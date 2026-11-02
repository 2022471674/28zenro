# -*- coding: utf-8 -*-
"""全局代理池（迁移自 fir-proxy 的核心逻辑：fetcher + checker + rotator）。

从多个**免费代理源**并发拉取 HTTP / SOCKS4 / SOCKS5 代理，逐个验证可用性
（TCP 预检 + 实际请求转发 + 假代理否定测试），维护一个线程安全的代理池供
全部 Web 工具共享。Web 工具经 :func:`make_session` / :func:`apply_proxy`
拿到带代理的 ``requests.Session``，实现「配置一次、全局生效」。

设计要点
--------
1. **纯标准库 + requests/PySocks**：拉取与验证走 ``requests``，SOCKS 代理经
   PySocks（``socks5://`` 方案），HTTP 代理走 requests 原生 ``http://``。
2. **轮换取用**：``get_proxy`` 按游标轮换取下一个可用代理，多线程下每个
   线程 / 每次调用分散到不同出口；代理故障立即剔除。
3. **假代理防护**：验证时先连保留地址 ``192.0.2.1`` 做否定测试，「不管目标
   是什么都回成功」的假代理会被判死。
4. **使用前检测**：:func:`check_available` 供工具启动前确认池内有可用代理。

本模块只做「配置进、会话 / 代理出」的纯逻辑，不导入任何 UI 模块。
"""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import requests
from requests.packages import urllib3

urllib3.disable_warnings()

# --------------------------------------------------------------------------- #
# 免费代理源（已验证可用，返回一行一个 ip:port 的纯文本）
# --------------------------------------------------------------------------- #
#: 免费代理源：协议 -> [(名称, URL), ...]
FREE_SOURCES: dict[str, list[tuple[str, str]]] = {
    "http": [
        ("TheSpeedX-http",
         "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt"),
        ("proxifly-http",
         "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt"),
    ],
    "socks4": [
        ("monosans-socks4",
         "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt"),
    ],
    "socks5": [
        ("TheSpeedX-socks5",
         "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt"),
        ("openproxylist-socks5",
         "https://openproxylist.xyz/socks5.txt"),
    ],
}

#: 所有源的扁平列表（名称 -> (协议, URL)），供配置界面展示
ALL_SOURCES: dict[str, tuple[str, str]] = {
    name: (proto, url)
    for proto, items in FREE_SOURCES.items()
    for name, url in items
}

#: 验证代理用的参照目标（逐个尝试，第一个成功即算可用）
CHECK_URLS = (
    "http://httpbin.org/ip",
    "https://www.baidu.com",
    "http://www.baidu.com",
)

#: 否定测试用的保留地址（RFC 5737 TEST-NET-1，保证不可路由）
NEGATIVE_URL = "http://192.0.2.1/"
NEGATIVE_TIMEOUT = 4.0

#: 默认配置
DEFAULT_ENABLED = False
DEFAULT_PROTOCOL = "http"
DEFAULT_TIMEOUT = 8.0
DEFAULT_THREADS = 64
DEFAULT_MAX_PROXIES = 200
DEFAULT_CHECK_TIMEOUT = 6.0

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

LogFn = Callable[[str], None]


class ProxyPoolError(ValueError):
    """代理池配置 / 拉取 / 验证失败时抛出的统一异常。"""


# --------------------------------------------------------------------------- #
# 单个代理
# --------------------------------------------------------------------------- #
@dataclass
class ProxyEntry:
    """池内的一条代理。``protocol`` 取 ``http`` / ``socks4`` / ``socks5``。"""

    host: str
    port: int
    protocol: str = "http"
    latency: float = 0.0
    failures: int = 0
    dead: bool = False
    verified: bool | None = None  # None=未测，True=可信，False=假代理/不可用
    fake: bool = False  # True=「全通」假代理（否定测试未通过）

    @property
    def address(self) -> str:
        return f"{self.host}:{self.port}"

    @property
    def key(self) -> str:
        return f"{self.protocol}://{self.host}:{self.port}"

    def requests_proxies(self) -> dict[str, str]:
        """转成 requests 的 ``proxies`` 字典。"""
        url = self.key
        return {"http": url, "https": url}

    def to_dict(self) -> dict[str, Any]:
        return {
            "proxy": self.address,
            "protocol": self.protocol,
            "latency": round(self.latency * 1000, 1),
            "dead": self.dead,
            "verified": self.verified,
        }


def parse_proxy(line: str, protocol: str = "http") -> ProxyEntry | None:
    """解析一行代理（``ip:port``，兼容 ``http://ip:port`` 前缀）。

    行内带协议前缀时以行内协议为准，覆盖 ``protocol`` 默认值。
    """
    text = str(line or "").strip().lstrip("\ufeff")
    if not text or text.startswith("#"):
        return None
    text = text.split("#", 1)[0].strip()
    lowered = text.lower()
    for scheme, proto in (("http://", "http"), ("https://", "http"),
                          ("socks5://", "socks5"), ("socks4://", "socks4"),
                          ("socks://", "socks5")):
        if lowered.startswith(scheme):
            text = text[len(scheme):]
            protocol = proto
            break
    if not text or ":" not in text:
        return None
    host, _, port_s = text.rpartition(":")
    host = host.strip().strip("[]")
    if not host or not port_s.strip().isdigit():
        return None
    port = int(port_s)
    if not (0 < port < 65536):
        return None
    if protocol == "socks":
        protocol = "socks5"
    return ProxyEntry(host=host, port=port, protocol=protocol)


# --------------------------------------------------------------------------- #
# 拉取（迁移 fetcher 核心）
# --------------------------------------------------------------------------- #
def fetch_source(url: str, timeout: float = DEFAULT_TIMEOUT,
                 protocol: str = "http") -> list[ProxyEntry]:
    """从单个免费源拉取代理列表，返回解析后的 :class:`ProxyEntry` 列表。"""
    response = requests.get(
        url, timeout=timeout,
        headers={"User-Agent": USER_AGENT},
        verify=False,
    )
    response.raise_for_status()
    entries: list[ProxyEntry] = []
    seen: set[str] = set()
    for line in response.text.splitlines():
        entry = parse_proxy(line, protocol)
        if entry is None or entry.address in seen:
            continue
        seen.add(entry.address)
        entries.append(entry)
    return entries


def fetch_all(protocols: tuple[str, ...] = ("http", "socks5"),
              sources: list[str] | None = None,
              timeout: float = DEFAULT_TIMEOUT,
              max_proxies: int = DEFAULT_MAX_PROXIES,
              log: LogFn | None = None,
              stop: threading.Event | None = None,
              ) -> dict[str, list[ProxyEntry]]:
    """从免费源拉取代理，返回 ``{协议: [ProxyEntry, ...]}``。

    ``sources`` 指定源名称（:data:`ALL_SOURCES` 的键），空则用协议对应的全部内置源。
    """
    emit = log or (lambda _m: None)
    result: dict[str, list[ProxyEntry]] = {p: [] for p in protocols}
    seen: set[str] = set()

    for protocol in protocols:
        candidates = [(n, u) for n, u in FREE_SOURCES.get(protocol, [])
                      if not sources or n in sources]
        if not candidates:
            continue
        for name, url in candidates:
            if stop is not None and stop.is_set():
                break
            try:
                entries = fetch_source(url, timeout, protocol)
            except requests.RequestException as exc:
                emit(f"[代理] {name} 拉取失败：{exc}")
                continue
            added = 0
            for entry in entries:
                if entry.address in seen:
                    continue
                seen.add(entry.address)
                result[protocol].append(entry)
                added += 1
                if sum(len(v) for v in result.values()) >= max_proxies:
                    break
            emit(f"[代理] {name}：拉到 {len(entries)} 条，去重后新增 {added} 条")
            if sum(len(v) for v in result.values()) >= max_proxies:
                break
        if sum(len(v) for v in result.values()) >= max_proxies:
            break

    # 按上限截断，避免验证阶段耗时过长
    total = 0
    for proto in result:
        remaining = max_proxies - total
        if remaining <= 0:
            result[proto] = []
            continue
        if len(result[proto]) > remaining:
            result[proto] = result[proto][:remaining]
        total += len(result[proto])

    total = sum(len(v) for v in result.values())
    emit(f"[代理] 拉取完成：共 {total} 条（去重后，上限 {max_proxies}）")
    return result


# --------------------------------------------------------------------------- #
# 验证（迁移 checker 核心，简化）
# --------------------------------------------------------------------------- #
def verify_proxy(entry: ProxyEntry,
                 timeout: float = DEFAULT_CHECK_TIMEOUT) -> bool:
    """验证单个代理是否真的可用（TCP 预检 + 转发测试 + 假代理否定测试）。

    返回 ``True`` 表示可用；结果写入 ``entry.verified`` / ``entry.latency`` /
    ``entry.dead``。
    """
    if entry.dead:
        return False

    # 1. TCP 预检（快）：代理端口通不通
    try:
        with socket.create_connection((entry.host, entry.port), timeout=1.5):
            pass
    except OSError:
        entry.dead = True
        entry.verified = False
        return False

    # 2. 否定测试：连保留地址必须失败，否则是「全通」假代理
    try:
        session = requests.Session()
        session.proxies.update(entry.requests_proxies())
        session.trust_env = False
        neg = session.get(NEGATIVE_URL, timeout=min(timeout, NEGATIVE_TIMEOUT),
                          verify=False, allow_redirects=False)
        if neg.status_code < 400:
            entry.dead = True
            entry.verified = False
            entry.fake = True
            return False
    except requests.RequestException:
        pass  # 连不上保留地址 = 真在转发，继续
    finally:
        try:
            session.close()
        except Exception:  # noqa: BLE001
            pass

    # 3. 转发测试：通过代理请求真实目标
    for url in CHECK_URLS:
        try:
            session = requests.Session()
            session.proxies.update(entry.requests_proxies())
            session.trust_env = False
            started = time.time()
            response = session.get(url, timeout=timeout, verify=False,
                                   allow_redirects=True)
            if response.status_code < 400:
                entry.latency = time.time() - started
                entry.verified = True
                entry.failures = 0
                return True
        except requests.RequestException:
            continue
        finally:
            try:
                session.close()
            except Exception:  # noqa: BLE001
                pass
        if entry.verified:
            break

    entry.dead = True
    entry.verified = False
    return False


def verify_all(entries: list[ProxyEntry],
               threads: int = DEFAULT_THREADS,
               timeout: float = DEFAULT_CHECK_TIMEOUT,
               log: LogFn | None = None,
               stop: threading.Event | None = None,
               ) -> list[ProxyEntry]:
    """并发验证代理列表，返回通过验证的代理（按延迟升序）。"""
    emit = log or (lambda _m: None)
    if not entries:
        return []

    from concurrent.futures import ThreadPoolExecutor, as_completed

    alive: list[ProxyEntry] = []
    lock = threading.Lock()
    done = 0
    total = len(entries)

    def _work(entry: ProxyEntry) -> bool:
        nonlocal done
        if stop is not None and stop.is_set():
            return False
        ok = verify_proxy(entry, timeout)
        with lock:
            done += 1
        return ok

    workers = max(1, min(int(threads), total))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_work, e) for e in entries]
        for future in as_completed(futures):
            if stop is not None and stop.is_set():
                for f in futures:
                    f.cancel()
                break
            try:
                if future.result():
                    pass
            except Exception:  # noqa: BLE001  单条验证异常不影响整体
                pass

    for entry in entries:
        if entry.verified and not entry.dead:
            alive.append(entry)

    alive.sort(key=lambda e: e.latency)
    emit(f"[代理] 验证完成：{total} 条中可用 {len(alive)} 条")
    return alive


# --------------------------------------------------------------------------- #
# 代理池（迁移 rotator 核心）
# --------------------------------------------------------------------------- #
class ProxyPool:
    """线程安全的代理池：轮换取用、故障剔除、可动态装载。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._items: list[ProxyEntry] = []
        self._cursor = 0

    def add(self, entry: ProxyEntry) -> bool:
        with self._lock:
            if any(e.key == entry.key for e in self._items):
                return False
            self._items.append(entry)
            return True

    def extend(self, entries) -> int:
        added = 0
        with self._lock:
            keys = {e.key for e in self._items}
            for entry in entries:
                if entry.key in keys or entry.dead:
                    continue
                keys.add(entry.key)
                self._items.append(entry)
                added += 1
        return added

    def clear(self) -> None:
        with self._lock:
            self._items.clear()
            self._cursor = 0

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)

    @property
    def items(self) -> list[ProxyEntry]:
        with self._lock:
            return list(self._items)

    def alive_count(self) -> int:
        with self._lock:
            return sum(1 for e in self._items if not e.dead)

    def next(self) -> ProxyEntry | None:
        """按游标轮换取下一个可用代理。"""
        with self._lock:
            total = len(self._items)
            if not total:
                return None
            for _ in range(total):
                entry = self._items[self._cursor % total]
                self._cursor = (self._cursor + 1) % total
                if entry.dead:
                    continue
                return entry
            return None

    def report_ok(self, entry: ProxyEntry, latency: float = 0.0) -> None:
        with self._lock:
            entry.failures = 0
            if latency:
                entry.latency = latency if not entry.latency else (
                    entry.latency * 0.7 + latency * 0.3)

    def report_failure(self, entry: ProxyEntry, force: bool = False) -> bool:
        """报告一次故障；``force=True`` 立即判死。返回是否已判死。"""
        should_save = False
        with self._lock:
            entry.failures += 1
            if force or entry.failures >= 2:
                entry.dead = True
            should_save = entry.dead
        if should_save:
            # 代理失效后立即持久化当前存活列表，避免缓存里残留死代理
            _save_cache()
        return should_save

    def stats(self) -> dict[str, Any]:
        with self._lock:
            total = len(self._items)
            dead = sum(1 for e in self._items if e.dead)
            return {"total": total, "alive": total - dead, "dead": dead}


# --------------------------------------------------------------------------- #
# 全局单例与配置
# --------------------------------------------------------------------------- #
_POOL = ProxyPool()

#: 池空时自动填充的互斥锁与冷却时间，避免多线程并发重复拉取免费源
_fetch_lock = threading.Lock()
_last_fetch_attempt = 0.0
_FETCH_COOLDOWN = 30.0

_config: dict[str, Any] = {
    "enabled": DEFAULT_ENABLED,
    "protocol": DEFAULT_PROTOCOL,
    "sources": [],
    "manual": "",
    "timeout": DEFAULT_CHECK_TIMEOUT,
    "threads": DEFAULT_THREADS,
    "max_proxies": DEFAULT_MAX_PROXIES,
    #: 按工具的「走代理」开关：{tool_id: bool}。仅记录被显式关闭（False）的工具，
    #: 未登记的工具默认 True（听从全局代理）。后续新增的 Web 工具无需额外配置，
    #: 默认即走全局代理。
    "tool_proxy": {},
}

#: 手动代理（从配置解析后缓存在这里，避免每次请求都解析）
_manual_entries: list[ProxyEntry] = []

#: 已验证代理持久化回调（由应用层注入，如写入 store），签名 ``(list[str]) -> None``
_on_cache_save: Callable[[list[str]], None] | None = None


def set_cache_saver(fn: Callable[[list[str]], None] | None) -> None:
    """注入「已验证代理」的持久化回调（应用层负责写入 config.json）。"""
    global _on_cache_save
    _on_cache_save = fn


def _serialize_alive() -> list[str]:
    """把池内可用代理序列化成 ``协议://host:port`` 字符串列表。"""
    return [e.key for e in _POOL.items if not e.dead and e.verified]


def _restore_cache(keys: list[str]) -> None:
    """把持久化的已验证代理恢复到池里（信任上次的验证结果，不重新验证）。"""
    for key in keys or []:
        entry = parse_proxy(key, "http")
        if entry is None:
            continue
        entry.verified = True
        entry.dead = False
        _POOL.add(entry)


def _save_cache() -> None:
    """若注册了持久化回调，把当前可用代理序列化后交给回调保存。"""
    if _on_cache_save is None:
        return
    try:
        _on_cache_save(_serialize_alive())
    except Exception:  # noqa: BLE001  持久化失败不影响代理池运行
        pass


def load_config(cfg: dict | None) -> None:
    """从 store 的 ``proxy_pool`` 节加载配置到全局单例。

    若配置里带 ``cache``（上次验证过的可用代理），则恢复进池，避免重复拉取；
    直到这些代理全部失效（被判死）才会在下次使用时重新拉取免费源。
    """
    if not isinstance(cfg, dict):
        cfg = {}
    _config["enabled"] = bool(cfg.get("enabled", DEFAULT_ENABLED))
    protocol = str(cfg.get("protocol", DEFAULT_PROTOCOL) or DEFAULT_PROTOCOL)
    if protocol not in ("http", "socks4", "socks5"):
        protocol = DEFAULT_PROTOCOL
    _config["protocol"] = protocol
    _config["sources"] = list(cfg.get("sources") or [])
    _config["manual"] = str(cfg.get("manual") or "")
    _config["timeout"] = float(cfg.get("timeout", DEFAULT_CHECK_TIMEOUT)
                               or DEFAULT_CHECK_TIMEOUT)
    _config["threads"] = int(cfg.get("threads", DEFAULT_THREADS) or DEFAULT_THREADS)
    _config["max_proxies"] = int(cfg.get("max_proxies", DEFAULT_MAX_PROXIES)
                                 or DEFAULT_MAX_PROXIES)
    # 按工具代理开关：仅接受 dict，且只保留值为 False 的项（未登记默认 True）
    raw_tool_proxy = cfg.get("tool_proxy")
    _config["tool_proxy"] = (
        {k: bool(v) for k, v in raw_tool_proxy.items() if not bool(v)}
        if isinstance(raw_tool_proxy, dict) else {}
    )
    _reload_manual()
    # 恢复上次验证过的可用代理（仅当池为空时，避免重复叠加）
    if _POOL.alive_count() == 0:
        _restore_cache(list(cfg.get("cache") or []))


def _reload_manual() -> None:
    global _manual_entries
    _manual_entries = []
    for line in str(_config.get("manual") or "").splitlines():
        entry = parse_proxy(line, _config["protocol"])
        if entry is not None:
            _manual_entries.append(entry)


def config() -> dict[str, Any]:
    """返回当前配置的副本。"""
    return dict(_config)


def is_enabled() -> bool:
    return bool(_config.get("enabled"))


def should_use_proxy(tool_id: str | None = None) -> bool:
    """判断某个工具是否应走全局代理。

    - ``tool_id`` 为 None（未指定工具）→ 默认 True（听从全局代理）；
    - ``tool_id`` 在 ``tool_proxy`` 里显式配置为 False → 返回 False（该工具直连，
      即使全局代理已启用）；
    - 其余 → True（听从全局代理）。

    这是「后续新增工具默认走代理（true）」的落地点：新工具未在配置里登记，
    自然返回 True。
    """
    if not tool_id:
        return True
    return _config.get("tool_proxy", {}).get(tool_id, True)


def set_tool_proxy(tool_id: str, enabled: bool) -> None:
    """设置某个工具的「走代理」开关（``enabled=False`` 表示该工具直连）。"""
    overrides = _config.setdefault("tool_proxy", {})
    if enabled:
        overrides.pop(tool_id, None)
    else:
        overrides[tool_id] = False


def tool_proxy_overrides() -> dict[str, bool]:
    """返回当前按工具代理开关（仅含被关闭的工具）。"""
    return dict(_config.get("tool_proxy", {}))


def pool() -> ProxyPool:
    return _POOL


def _prefer_protocols() -> tuple[str, ...]:
    """按配置协议决定拉取 / 使用哪些协议的代理。"""
    proto = _config["protocol"]
    order = {"http": ("http", "socks5", "socks4"),
             "socks5": ("socks5", "http", "socks4"),
             "socks4": ("socks4", "socks5", "http")}
    return tuple(order.get(proto, ("http", "socks5", "socks4")))


def get_proxy() -> ProxyEntry | None:
    """取下一个可用代理；池空时若配置了手动代理则回退到手动代理。"""
    entry = _POOL.next()
    if entry is None and _manual_entries:
        with _POOL._lock:
            entry = _manual_entries[_POOL._cursor % len(_manual_entries)]
            _POOL._cursor = (_POOL._cursor + 1) % len(_manual_entries)
    return entry


def _ensure_pool_ready(timeout: float = 30.0) -> bool:
    """使用前检测：池内无可用代理时，自动拉取免费源并验证（带冷却）。

    多线程并发时只有一个线程真正去拉取，其余线程直接返回失败（回退直连），
    避免「几十个线程同时拉免费源」把网络打满。
    """
    global _last_fetch_attempt
    if _POOL.alive_count() > 0:
        return True
    now = time.time()
    if now - _last_fetch_attempt < _FETCH_COOLDOWN:
        return False
    if not _fetch_lock.acquire(blocking=False):
        return False
    try:
        # 拿到锁后再确认一次（可能别的线程刚填充完）
        if _POOL.alive_count() > 0:
            return True
        _last_fetch_attempt = time.time()
        result = fetch_and_verify(log=None)
        return result.get("alive", 0) > 0
    except Exception:  # noqa: BLE001  自动填充失败不该影响主流程
        return False
    finally:
        _fetch_lock.release()


def get_proxies() -> dict[str, str] | None:
    """返回 requests 可直接使用的 ``proxies`` 字典；无可用代理返回 None。

    启用代理但池空且无手动代理时，会尝试自动拉取免费源一次（带冷却）。
    """
    entry = get_proxy()
    if entry is None:
        # 池空且无手动代理兜底时，尝试自动填充免费源
        if _ensure_pool_ready():
            entry = get_proxy()
    return entry.requests_proxies() if entry else None


def make_session(tool_id: str | None = None) -> requests.Session:
    """创建一个 ``requests.Session``，若启用了代理池则自动绑定代理。

    Web 工具统一用这个工厂创建会话，即可「配置一次、全局走代理」。
    未启用代理时返回 ``trust_env=False`` 的直连会话（沿用各工具原有行为）。

    ``tool_id`` 为工具标识（如 ``web_fuzz`` / ``dir_scan``）：若该工具在
    设置里被关闭了「走代理」，则即使全局代理已启用也返回直连会话。
    传 ``None``（未指定）时默认听从全局代理。

    启用全局代理但池内无可用代理（自动拉取也失败 / 冷却中）时抛
    :class:`ProxyPoolError` 而不是静默返回直连会话 —— 宁可让本次任务
    失败，也不把用户本机 IP 暴露给目标。
    """
    session = requests.Session()
    session.trust_env = False
    if should_use_proxy(tool_id) and is_enabled():
        proxies = get_proxies()
        if proxies:
            session.proxies.update(proxies)
        else:
            raise ProxyPoolError(
                "全局代理已启用，但代理池内没有可用代理（自动拉取失败或处于"
                "冷却期）。为避免直连暴露本机 IP，本次任务已中止；请在设置里"
                "重新获取代理、填写手动代理，或暂时关闭全局代理。")
    return session


def apply_proxy(session: requests.Session, tool_id: str | None = None) -> None:
    """给已有会话绑定当前代理（启用且该工具未被豁免时）。

    与 :func:`make_session` 一致：启用代理但无可用代理时抛
    :class:`ProxyPoolError`，绝不静默放行直连。
    """
    if should_use_proxy(tool_id) and is_enabled():
        proxies = get_proxies()
        if proxies:
            session.proxies.update(proxies)
            session.trust_env = False
        else:
            raise ProxyPoolError(
                "全局代理已启用，但代理池内没有可用代理；已阻止本次直连请求"
                "以避免暴露本机 IP。请重新获取代理或暂时关闭全局代理。")


# --------------------------------------------------------------------------- #
# 拉取 + 验证（settings 的「获取并检测」入口）
# --------------------------------------------------------------------------- #
def fetch_and_verify(log: LogFn | None = None,
                     stop: threading.Event | None = None,
                     protocols: tuple[str, ...] | None = None,
                     ) -> dict[str, Any]:
    """从免费源拉取并验证代理，结果装载进全局池。

    返回 ``{"fetched", "alive", "total", "fake"}``。
    """
    emit = log or (lambda _m: None)
    if stop is not None and stop.is_set():
        return {"fetched": 0, "alive": 0, "total": 0, "fake": 0}

    protos = protocols or _prefer_protocols()
    fetched = fetch_all(protos, sources=_config["sources"],
                        timeout=_config["timeout"],
                        max_proxies=_config["max_proxies"],
                        log=emit, stop=stop)
    flat = [e for lst in fetched.values() for e in lst]
    if _manual_entries:
        flat = _manual_entries + flat

    alive = verify_all(flat, threads=_config["threads"],
                       timeout=_config["timeout"], log=emit, stop=stop)
    _POOL.clear()
    _POOL.extend(alive)
    fake = sum(1 for e in flat if e.fake)

    result = {
        "fetched": len(flat),
        "alive": _POOL.alive_count(),
        "total": _POOL.stats()["total"],
        "fake": fake,
    }
    emit(f"[代理] 就绪：池内 {result['alive']} 个可用代理"
         + (f"，剔除假代理 {fake} 个" if fake else ""))
    # 立即持久化：把可用代理存进 config.json，下次启动直接恢复、无需重复拉取
    _save_cache()
    return result


def check_available(log: LogFn | None = None,
                    stop: threading.Event | None = None,
                    ) -> bool:
    """使用前检测：确认池内有可用代理。

    池空时会先尝试从免费源拉取并验证一次；仍无可用代理返回 ``False``。
    """
    emit = log or (lambda _m: None)
    if _POOL.alive_count() > 0:
        return True
    emit("[代理] 池内暂无可用代理，尝试从免费源拉取并验证…")
    try:
        result = fetch_and_verify(log=emit, stop=stop)
    except Exception as exc:  # noqa: BLE001
        emit(f"[代理] 拉取验证失败：{exc}")
        return False
    return result.get("alive", 0) > 0


def proxy_status() -> dict[str, Any]:
    """返回当前代理池状态（供界面展示）。"""
    stats = _POOL.stats()
    return {
        "enabled": is_enabled(),
        "protocol": _config["protocol"],
        **stats,
        "sample": [e.to_dict() for e in _POOL.items[:5]],
    }


def to_port_scan_pool():
    """把全局代理池转成 ``lib.port_scan.ProxyPool``（端口爆破用）。

    端口爆破走原生 socket 协议（SOCKS5 CONNECT / HTTP CONNECT），与 requests
    无关；这里把池内可用代理映射成 ``port_scan.Proxy`` 供其轮换。
    优先用已验证的池内代理，池空时回退到手动代理；都没有返回 None。
    """
    from lib import port_scan

    entries = [e for e in _POOL.items if not e.dead]
    if not entries and _manual_entries:
        entries = list(_manual_entries)
    if not entries:
        return None
    proxies = [
        port_scan.Proxy(
            scheme="http" if e.protocol in ("http", "https") else e.protocol,
            host=e.host,
            port=e.port,
        )
        for e in entries
    ]
    return port_scan.ProxyPool(proxies)


# --------------------------------------------------------------------------- #
# 自检：``python -m lib.proxy_pool``
# --------------------------------------------------------------------------- #
def _selftest() -> int:
    ok = True

    # 1. 解析
    cases = [
        ("1.2.3.4:8080", ("1.2.3.4", 8080, "http")),
        ("http://5.6.7.8:3128", ("5.6.7.8", 3128, "http")),
        ("socks5://9.9.9.9:1080", ("9.9.9.9", 1080, "socks5")),
        ("[::1]:8080", ("::1", 8080, "http")),
        ("", None),
        ("not-a-proxy", None),
    ]
    for line, expect in cases:
        entry = parse_proxy(line, "http")
        got = (entry.host, entry.port, entry.protocol) if entry else None
        if got != expect:
            print(f"[FAIL] 解析 {line!r} -> {got}，期望 {expect}")
            ok = False
    print("[OK] 代理解析")

    # 2. 池轮换 / 剔除
    pool = ProxyPool()
    pool.extend([ProxyEntry("1.1.1.1", 1), ProxyEntry("2.2.2.2", 2)])
    a = pool.next()
    b = pool.next()
    if a is None or b is None or a.address == b.address:
        print("[FAIL] 池未轮换")
        ok = False
    pool.report_failure(a, force=True)
    if not a.dead or pool.alive_count() != 1:
        print("[FAIL] 判死失败")
        ok = False
    print("[OK] 池轮换 / 判死")

    # 3. 假代理识别：起一个「无脑回 200」的本地 HTTP 代理
    import http.server

    class _FakeHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a) -> None:
            return

    fake_srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _FakeHandler)
    fake_port = fake_srv.server_address[1]
    threading.Thread(target=fake_srv.serve_forever, daemon=True).start()
    try:
        fake = ProxyEntry("127.0.0.1", fake_port, "http")
        # 假代理对任何目标都回 200 → 否定测试必须判死
        if verify_proxy(fake, 4.0) is not False:
            print("[FAIL] 假代理未被判死")
            ok = False
        if not fake.dead:
            print("[FAIL] 假代理未标记 dead")
            ok = False
        print("[OK] 假代理识别（保留地址否定测试）")
    finally:
        fake_srv.shutdown()

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(_selftest())
