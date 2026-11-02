# -*- coding: utf-8 -*-
"""端口爆破（支持代理池轮换，检测到封禁 / 代理失效立即更换代理）。

设计要点
--------
1. **纯标准库**：只用 ``socket`` 手写 SOCKS5 / HTTP CONNECT，不引入 PySocks，
   保证 PyInstaller 单文件打包不额外带二进制依赖。
2. **代理即探针**：端口是否开放本质上就是「能不能建立 TCP 连接」，而 SOCKS5 的
   CONNECT 命令与 HTTP 代理的 ``CONNECT host:port`` 正好就是一次建连请求。
   因此不需要发任何业务数据，探完即关，对目标几乎无痕。
3. **封禁即换**：每个端口的每次尝试都从代理池取**下一个**代理；代理本身连不上
   （refused / timeout / 协议异常）立刻判故障并换；目标对当前出口超时（疑似封禁）
   也会换一个出口重试。连续被封多次的代理会被降权，不再优先使用。

对外主要接口
------------
- ``Proxy`` / ``ProxyPool``：代理与代理池
- ``parse_proxy_line`` / ``load_proxy_file``：解析 ``socks5://h:p`` / ``h:p`` 等写法
- ``probe``：单次探测（返回 ``ProbeResult``）
- ``scan``：多线程扫描，带回调与结果落盘
- ``load_port_dict`` / ``parse_ports``：端口字典与手动端口表达式
"""
from __future__ import annotations

import csv
import ipaddress
import re
import socket
import struct
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Sequence

# --------------------------------------------------------------------------- #
# 常量
# --------------------------------------------------------------------------- #

#: 内置端口字典目录（相对项目根）
DICT_SUBDIR = ("dict", "Ports")

DEFAULT_THREADS = 24
DEFAULT_TIMEOUT = 6.0
#: 单个端口最多尝试几次（每次换一个代理）
DEFAULT_RETRIES = 3
#: 代理连续故障多少次判死
DEAD_AFTER = 2
#: 代理连续「疑似封禁」多少次后降权
BLOCK_AFTER = 3
MAX_PORTS = 65536

#: fir-proxy 默认监听（见其 modules/server.py）
LOCAL_PROXY_HTTP = "http://127.0.0.1:1801"
LOCAL_PROXY_SOCKS = "socks5://127.0.0.1:1800"

#: 端口状态
STATE_OPEN = "open"
STATE_CLOSED = "closed"
STATE_FILTERED = "filtered"
STATE_ERROR = "error"

STATE_LABELS = {
    STATE_OPEN: "开放",
    STATE_CLOSED: "关闭",
    STATE_FILTERED: "过滤/超时",
    STATE_ERROR: "错误",
}

#: 这些返回码代表「代理本身有问题」，必须换代理重试
PROXY_FAULTS = {
    "proxy_refused",
    "proxy_timeout",
    "proxy_bad",
    "proxy_auth",
    "proxy_io",
    "proxy_reset",
    "proxy_unreachable",
    "proxy_untrusted",
    "proxy_dead",
}

#: SOCKS5 应答码 → 内部返回码
_SOCKS5_CODES = {
    0: STATE_OPEN,
    1: "general_fail",
    2: "not_allowed",
    3: "net_unreach",
    4: "host_unreach",
    5: STATE_CLOSED,
    6: "ttl_expired",
    7: "cmd_unsupported",
    8: "atyp_unsupported",
}


# --------------------------------------------------------------------------- #
# 代理
# --------------------------------------------------------------------------- #

@dataclass
class Proxy:
    """一个上游代理。``scheme`` 取 ``socks5`` / ``socks4`` / ``http``。"""

    scheme: str
    host: str
    port: int
    username: str = ""
    password: str = ""
    ok: int = 0
    fail: int = 0
    blocked: int = 0
    latency: float = 0.0
    dead: bool = False
    #: 否定测试结果：None=未测，True=真在转发，False=「全通」假代理
    verified: bool | None = None
    #: 否定测试原因：fake（全通）/ unreachable（连不上）/ ok
    verify_reason: str = ""

    @property
    def key(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"

    @property
    def auth(self) -> bool:
        return bool(self.username)

    def __str__(self) -> str:  # pragma: no cover - 仅调试
        return self.key

    def to_dict(self) -> dict:
        return {
            "proxy": self.key,
            "ok": self.ok,
            "fail": self.fail,
            "blocked": self.blocked,
            "latency": round(self.latency, 3),
            "dead": self.dead,
            "verified": self.verified,
        }


_SCHEME_ALIASES = {
    "socks5": "socks5",
    "socks5h": "socks5",
    "socks": "socks5",
    "s5": "socks5",
    "socks4": "socks4",
    "s4": "socks4",
    "http": "http",
    "https": "http",
    "http-proxy": "http",
}

_LINE_RE = re.compile(
    r"^(?:(?P<scheme>[A-Za-z0-9_\-]+)://)?"
    r"(?:(?P<user>[^:@/\s]+):(?P<pwd>[^@/\s]*)@)?"
    r"(?P<host>[^:/\s,;]+)"
    r"[:,\s]+(?P<port>\d{1,5})\s*$"
)


def parse_proxy_line(line: str, default_scheme: str = "socks5") -> Proxy | None:
    """解析一行代理，支持 ``socks5://h:p`` / ``http://u:p@h:p`` / ``h:p`` / ``h p``。

    无法识别时返回 ``None``（不抛异常，便于直接喂整份脏文件）。
    """
    if not line:
        return None
    text = line.strip().lstrip("\ufeff")
    if not text or text.startswith("#") or text.startswith("//"):
        return None
    # 去掉行尾注释（"1.2.3.4:1080 # 备注"）
    for sep in (" #", "\t#"):
        if sep in text:
            text = text.split(sep, 1)[0].strip()
    m = _LINE_RE.match(text)
    if not m:
        return None
    scheme = _SCHEME_ALIASES.get((m.group("scheme") or default_scheme).lower())
    if not scheme:
        return None
    host = m.group("host").strip("[]")
    try:
        port = int(m.group("port"))
    except (TypeError, ValueError):
        return None
    if not (0 < port < 65536) or not host:
        return None
    return Proxy(
        scheme=scheme,
        host=host,
        port=port,
        username=m.group("user") or "",
        password=m.group("pwd") or "",
    )


def load_proxy_file(path: str | Path, default_scheme: str = "socks5") -> list[Proxy]:
    """读取代理列表文件（一行一个），自动去重。"""
    p = Path(path)
    raw = p.read_text(encoding="utf-8", errors="ignore")
    out: list[Proxy] = []
    seen: set[str] = set()
    for line in raw.splitlines():
        proxy = parse_proxy_line(line, default_scheme)
        if proxy is None or proxy.key in seen:
            continue
        seen.add(proxy.key)
        out.append(proxy)
    return out


class ProxyPool:
    """线程安全的代理池：轮换取用、故障剔除、封禁降权。"""

    def __init__(
        self,
        proxies: Iterable[Proxy] | None = None,
        dead_after: int = DEAD_AFTER,
        block_after: int = BLOCK_AFTER,
    ) -> None:
        self._lock = threading.RLock()
        self._items: list[Proxy] = []
        self._cursor = 0
        self.dead_after = max(1, int(dead_after))
        self.block_after = max(1, int(block_after))
        if proxies:
            self.extend(proxies)

    # -- 装载 --------------------------------------------------------------
    def add(self, proxy: Proxy) -> bool:
        with self._lock:
            if any(p.key == proxy.key for p in self._items):
                return False
            self._items.append(proxy)
            return True

    def extend(self, proxies: Iterable[Proxy]) -> int:
        added = 0
        with self._lock:
            keys = {p.key for p in self._items}
            for proxy in proxies:
                if proxy.key in keys:
                    continue
                keys.add(proxy.key)
                self._items.append(proxy)
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
    def items(self) -> list[Proxy]:
        with self._lock:
            return list(self._items)

    # -- 取用 / 反馈 -------------------------------------------------------
    def next(self, exclude: set[str] | None = None) -> Proxy | None:
        """按游标取下一个可用代理；``exclude`` 里的 key 本次跳过。"""
        with self._lock:
            total = len(self._items)
            if not total:
                return None
            skip = exclude or set()
            for _ in range(total):
                proxy = self._items[self._cursor % total]
                self._cursor = (self._cursor + 1) % total
                if proxy.dead or proxy.key in skip:
                    continue
                return proxy
            return None

    def report_ok(self, proxy: Proxy, latency: float = 0.0) -> None:
        with self._lock:
            proxy.ok += 1
            proxy.fail = 0
            proxy.blocked = 0
            if latency:
                proxy.latency = latency if not proxy.latency else (
                    proxy.latency * 0.7 + latency * 0.3
                )

    def report_fault(self, proxy: Proxy, force: bool = False) -> bool:
        """代理本身故障（连不上 / 协议异常）。返回是否已判死。

        ``force=True`` 时立即判死（健康检查用：一次探测就该定论）。
        """
        with self._lock:
            proxy.fail += 1
            if force or proxy.fail >= self.dead_after:
                proxy.dead = True
            return proxy.dead

    def report_blocked(self, proxy: Proxy) -> bool:
        """目标对当前出口超时 / 拒绝，疑似封禁。返回是否已降权。"""
        with self._lock:
            proxy.blocked += 1
            if proxy.blocked >= self.block_after:
                proxy.dead = True
            return proxy.dead

    def alive(self) -> list[Proxy]:
        with self._lock:
            return [p for p in self._items if not p.dead]

    def stats(self) -> dict:
        with self._lock:
            total = len(self._items)
            dead = sum(1 for p in self._items if p.dead)
            ok = sum(1 for p in self._items if p.ok > 0 and not p.dead)
            return {"total": total, "dead": dead, "alive": total - dead, "worked": ok}

    # -- 健康检查 ----------------------------------------------------------
    def verify_all(
        self,
        threads: int = 64,
        timeout: float = 4.0,
        limit: int = 0,
        log: Callable[[str], None] | None = None,
        stop: threading.Event | None = None,
    ) -> dict:
        """并发对池内代理做否定测试，剔除「全通」假代理。

        返回 ``{"tested", "trusted", "fake"}``。
        """
        with self._lock:
            targets = [p for p in self._items if p.verified is None and not p.dead]
        if limit > 0:
            targets = targets[:limit]
        if not targets:
            return {"tested": 0, "trusted": 0, "fake": 0}

        lock = threading.Lock()
        trusted = 0

        def _work(proxy: Proxy) -> None:
            nonlocal trusted
            if stop is not None and stop.is_set():
                return
            if verify_proxy(proxy, timeout):
                with lock:
                    trusted += 1

        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=max(1, min(threads, len(targets)))) as pool:
            list(pool.map(_work, targets))

        fake = len(targets) - trusted
        if log:
            log(f"代理可信度检查：{len(targets)} 个中可信 {trusted} 个，假代理 {fake} 个")
        return {"tested": len(targets), "trusted": trusted, "fake": fake}

    def health_check(
        self,
        dst_host: str = "www.baidu.com",
        dst_port: int = 443,
        threads: int = 64,
        timeout: float = 4.0,
        limit: int = 0,
        check_honest: bool = True,
        log: Callable[[str], None] | None = None,
        stop: threading.Event | None = None,
    ) -> dict:
        """并发验证代理是否真能连到目标，剔掉死代理与假代理。

        ``check_honest`` 为 True 时先做否定测试（见 :func:`verify_proxy`），
        避免「全通」代理把所有端口都报成开放。``limit`` > 0 时只测前
        ``limit`` 个（池子大时避免等太久）。
        """
        with self._lock:
            targets = [p for p in self._items if not p.dead]
        if limit > 0:
            targets = targets[:limit]
        total = len(targets)
        if not total:
            return {"tested": 0, "ok": 0, "dead": 0, "fake": 0}

        if check_honest:
            self.verify_all(threads=threads, timeout=timeout, log=log, stop=stop)
            with self._lock:
                targets = [p for p in targets if not p.dead]
            total = len(targets)
            if not total:
                if log:
                    log("所有代理都未通过可信度检查，请更换代理源")
                return {"tested": 0, "ok": 0, "dead": 0, "fake": 0}

        done = 0
        ok = 0
        lock = threading.Lock()

        def _work(proxy: Proxy) -> bool:
            nonlocal done, ok
            if stop is not None and stop.is_set():
                return False
            result = probe(proxy, dst_host, dst_port, timeout)
            # 注意：PROXY_FAULTS 是 code 集合，不是 state（state 只有 open/closed/
            # filtered/error），这里必须比 code，否则所有代理都会被判成可用。
            good = result.code not in PROXY_FAULTS
            with lock:
                done += 1
                if good:
                    ok += 1
                    self.report_ok(proxy, result.ms / 1000.0)
                else:
                    self.report_fault(proxy, force=True)
            return good

        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=max(1, min(threads, total))) as pool:
            list(pool.map(_work, targets))

        fake = sum(1 for p in self._items if p.verified is False)
        if log:
            log(f"代理检查完成：{total} 个中可用 {ok} 个（假代理 {fake} 个）")
        return {"tested": total, "ok": ok, "dead": total - ok, "fake": fake}


# --------------------------------------------------------------------------- #
# 探测
# --------------------------------------------------------------------------- #

@dataclass
class ProbeResult:
    """单次探测结果。``code`` 是原始返回码，``state`` 是归一化状态。"""

    port: int
    state: str
    code: str = ""
    ms: int = 0
    proxy: str = ""
    service: str = ""

    @property
    def label(self) -> str:
        return STATE_LABELS.get(self.state, self.state)

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "service": self.service,
            "state": self.state,
            "label": self.label,
            "code": self.code,
            "ms": self.ms,
            "proxy": self.proxy,
        }


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    buf = b""
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf += chunk
    return buf


def socks5_probe(proxy: Proxy, host: str, port: int, timeout: float) -> tuple[str, int]:
    """通过 SOCKS5 代理 CONNECT 目标，返回 ``(code, 耗时ms)``。

    返回码区分两类：``proxy_*`` 表示代理本身有问题（要换代理）；
    ``target_timeout`` 表示代理正常但目标没回应（端口过滤）。
    """
    t0 = time.time()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    connected = False
    try:
        sock.connect((proxy.host, proxy.port))
        connected = True
        if proxy.auth:
            sock.sendall(b"\x05\x02\x00\x02")
        else:
            sock.sendall(b"\x05\x01\x00")
        head = _recv_exact(sock, 2)
        if head[0] != 5:
            return "proxy_bad", int((time.time() - t0) * 1000)
        method = head[1]
        if method == 0x02:
            user = proxy.username.encode()
            pwd = proxy.password.encode()
            sock.sendall(bytes([1, len(user)]) + user + bytes([len(pwd)]) + pwd)
            if _recv_exact(sock, 2)[1] != 0:
                return "proxy_auth", int((time.time() - t0) * 1000)
        elif method != 0x00:
            return "proxy_auth", int((time.time() - t0) * 1000)

        if _is_ip(host):
            ip = ipaddress.ip_address(host)
            atyp = b"\x01" if ip.version == 4 else b"\x04"
            addr = ip.packed
        else:
            raw = host.encode("idna")
            atyp = b"\x03"
            addr = bytes([len(raw)]) + raw
        sock.sendall(b"\x05\x01\x00" + atyp + addr + struct.pack("!H", port))

        head = _recv_exact(sock, 4)
        if head[0] != 5:
            return "proxy_bad", int((time.time() - t0) * 1000)
        code = _SOCKS5_CODES.get(head[1], f"code{head[1]}")
        return code, int((time.time() - t0) * 1000)
    except socket.timeout:
        return ("target_timeout" if connected else "proxy_timeout"), int((time.time() - t0) * 1000)
    except ConnectionRefusedError:
        return "proxy_refused", int((time.time() - t0) * 1000)
    except ConnectionResetError:
        return ("target_timeout" if connected else "proxy_reset"), int((time.time() - t0) * 1000)
    except (ConnectionError, struct.error):
        return ("target_timeout" if connected else "proxy_bad"), int((time.time() - t0) * 1000)
    except OSError:
        return ("target_timeout" if connected else "proxy_io"), int((time.time() - t0) * 1000)
    finally:
        try:
            sock.close()
        except OSError:
            pass


def http_probe(proxy: Proxy, host: str, port: int, timeout: float) -> tuple[str, int]:
    """通过 HTTP 代理的 ``CONNECT`` 建隧道，返回 ``(code, 耗时ms)``。

    fir-proxy 的本地 HTTP 口（1801）上游失败时统一回 502，因此 502 也按
    「代理有问题」处理，交给上层换代理重试。
    """
    t0 = time.time()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    connected = False
    try:
        sock.connect((proxy.host, proxy.port))
        connected = True
        target = f"{host}:{port}"
        req = (
            f"CONNECT {target} HTTP/1.1\r\n"
            f"Host: {target}\r\n"
            "Proxy-Connection: keep-alive\r\n"
        )
        if proxy.auth:
            import base64

            token = base64.b64encode(
                f"{proxy.username}:{proxy.password}".encode()
            ).decode()
            req += f"Proxy-Authorization: Basic {token}\r\n"
        sock.sendall((req + "\r\n").encode())

        raw = b""
        while b"\r\n\r\n" not in raw:
            chunk = sock.recv(1024)
            if not chunk:
                break
            raw += chunk
            if len(raw) > 8192:
                break
        ms = int((time.time() - t0) * 1000)
        if not raw:
            return "proxy_bad", ms
        first = raw.split(b"\r\n", 1)[0].decode("latin-1", "ignore")
        parts = first.split()
        status = 0
        if len(parts) >= 2 and parts[1].isdigit():
            status = int(parts[1])
        if status == 200:
            return STATE_OPEN, ms
        if status in (502, 503, 504):
            # 上游代理连不上目标（fir-proxy 就是这么回的），换一个上游再试
            return "proxy_bad", ms
        if status == 407:
            return "proxy_auth", ms
        if status == 403:
            return "not_allowed", ms
        if status == 0:
            return "proxy_bad", ms
        return STATE_CLOSED, ms
    except socket.timeout:
        return ("target_timeout" if connected else "proxy_timeout"), int((time.time() - t0) * 1000)
    except ConnectionRefusedError:
        return "proxy_refused", int((time.time() - t0) * 1000)
    except ConnectionResetError:
        return ("target_timeout" if connected else "proxy_reset"), int((time.time() - t0) * 1000)
    except OSError:
        return ("target_timeout" if connected else "proxy_io"), int((time.time() - t0) * 1000)
    finally:
        try:
            sock.close()
        except OSError:
            pass


def direct_probe(host: str, port: int, timeout: float) -> tuple[str, int]:
    """不走代理的直连探测（对照用）。"""
    t0 = time.time()
    try:
        sock = socket.create_connection((host, port), timeout)
        ms = int((time.time() - t0) * 1000)
        sock.close()
        return STATE_OPEN, ms
    except ConnectionRefusedError:
        return STATE_CLOSED, int((time.time() - t0) * 1000)
    except socket.timeout:
        return "target_timeout", int((time.time() - t0) * 1000)
    except OSError as exc:
        name = exc.__class__.__name__
        if "unreachable" in str(exc).lower() or name == "OSError":
            return "net_unreach", int((time.time() - t0) * 1000)
        return "target_error", int((time.time() - t0) * 1000)


#: 否定测试用的保留地址（RFC 5737 TEST-NET-1，保证不可路由）。
#: 真代理连它必然失败；「全通」假代理（不管目标是什么都回成功）会在这里露馅。
NEGATIVE_HOST = "192.0.2.1"
NEGATIVE_PORT = 9


def verify_proxy(proxy: Proxy, timeout: float = 4.0) -> bool:
    """否定测试：确认代理真的在转发，而不是无脑回「连接成功」。

    返回 ``True`` 表示可信；``False`` 表示假代理或本身不可用。
    结果会写进 ``proxy.verified`` 缓存，同一代理只测一次。
    """
    if proxy.verified is not None:
        return proxy.verified
    if proxy.scheme == "http":
        code, _ = http_probe(proxy, NEGATIVE_HOST, NEGATIVE_PORT, timeout)
    else:
        code, _ = socks5_probe(proxy, NEGATIVE_HOST, NEGATIVE_PORT, timeout)
    if code == STATE_OPEN:
        # 保留地址都「能连上」→ 假代理，结果不可信
        proxy.verified = False
        proxy.verify_reason = "fake"
        proxy.dead = True
        return False
    if code == "proxy_bad" and proxy.scheme == "http":
        # HTTP 代理（如 fir-proxy 的 1801）上游连不上时统一回 502。它至少
        # 诚实报告了失败，不是「全通」假代理 —— 判为可信，别误杀。
        proxy.verified = True
        proxy.verify_reason = "ok"
        return True
    if code in PROXY_FAULTS:
        proxy.verified = False
        proxy.verify_reason = "unreachable"
        proxy.dead = True
        return False
    proxy.verified = True
    proxy.verify_reason = "ok"
    return True


def probe(proxy: Proxy | None, host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> ProbeResult:
    """对 ``host:port`` 做一次探测（``proxy`` 为 None 时直连）。"""
    if proxy is None:
        code, ms = direct_probe(host, port, timeout)
        via = "direct"
    elif proxy.scheme == "http":
        code, ms = http_probe(proxy, host, port, timeout)
        via = proxy.key
    else:
        code, ms = socks5_probe(proxy, host, port, timeout)
        via = proxy.key

    if code in PROXY_FAULTS:
        state = STATE_ERROR
    elif code == STATE_OPEN:
        state = STATE_OPEN
    elif code in (STATE_CLOSED, "not_allowed"):
        state = STATE_CLOSED
    else:
        state = STATE_FILTERED
    return ProbeResult(port=port, state=state, code=code, ms=ms, proxy=via)


def _probe_with_failover(
    pool: ProxyPool | None,
    host: str,
    port: int,
    timeout: float,
    retries: int,
    stop: threading.Event | None,
    counter: dict | None = None,
) -> ProbeResult | None:
    """带代理故障转移的单端口探测：失败 / 疑似封禁都立刻换下一个代理。"""
    if pool is None:
        return probe(None, host, port, timeout)

    tried: set[str] = set()
    last: ProbeResult | None = None
    for _ in range(max(1, retries + 1)):
        if stop is not None and stop.is_set():
            return None
        proxy = pool.next(exclude=tried)
        if proxy is None and tried:
            # 池子里能用的代理都被本次试过了（本地 fir-proxy 只有 1 个入口就是
            # 这种情况）。清空已试集合再来一轮 —— 上游出口由 fir-proxy 自己轮换，
            # 同一个本地端口重试是有意义的。
            tried.clear()
            proxy = pool.next()
        if proxy is None:
            if last is None:
                last = ProbeResult(port=port, state=STATE_ERROR, code="no_proxy")
            break
        tried.add(proxy.key)

        # 首次使用前做否定测试：假代理会把任何端口都报成开放，必须挡掉
        if proxy.verified is None and not verify_proxy(proxy, min(timeout, 5.0)):
            if counter is not None:
                key = "untrusted" if proxy.verify_reason == "fake" else "unreachable"
                counter[key] = counter.get(key, 0) + 1
            code = "proxy_untrusted" if proxy.verify_reason == "fake" else "proxy_dead"
            last = ProbeResult(port=port, state=STATE_ERROR, code=code, proxy=proxy.key)
            continue

        result = probe(proxy, host, port, timeout)

        if result.code in PROXY_FAULTS:
            pool.report_fault(proxy)
            last = result
            if counter is not None:
                counter["rotations"] = counter.get("rotations", 0) + 1
            continue

        if result.state == STATE_FILTERED:
            # 目标对当前出口超时 → 疑似封禁，换一个出口再试
            pool.report_blocked(proxy)
            last = result
            if counter is not None:
                counter["rotations"] = counter.get("rotations", 0) + 1
            continue

        pool.report_ok(proxy, result.ms / 1000.0)
        return result

    if last is None:
        last = ProbeResult(port=port, state=STATE_ERROR, code="no_proxy")
    return last


# --------------------------------------------------------------------------- #
# 端口字典 / 端口表达式
# --------------------------------------------------------------------------- #

_PORT_RANGE_RE = re.compile(r"^\s*(\d{1,5})\s*-\s*(\d{1,5})\s*$")


def parse_ports(text: str, limit: int = MAX_PORTS) -> list[int]:
    """解析端口表达式，支持 ``80``、``80,443``、``1-1024``、空格 / 换行分隔。"""
    ports: list[int] = []
    seen: set[int] = set()
    for token in re.split(r"[,;\s]+", text or ""):
        token = token.strip()
        if not token or token.startswith("#"):
            continue
        m = _PORT_RANGE_RE.match(token)
        if m:
            start, end = int(m.group(1)), int(m.group(2))
            if start > end:
                start, end = end, start
            for p in range(max(1, start), min(65535, end) + 1):
                if p not in seen:
                    seen.add(p)
                    ports.append(p)
                    if len(ports) >= limit:
                        return ports
            continue
        if token.isdigit():
            p = int(token)
            if 0 < p < 65536 and p not in seen:
                seen.add(p)
                ports.append(p)
                if len(ports) >= limit:
                    return ports
    return ports


def parse_port_line(line: str) -> tuple[int, str] | None:
    """解析字典中的一行，返回 ``(端口, 服务名)``。"""
    text = (line or "").strip().lstrip("\ufeff")
    if not text or text.startswith("#") or text.startswith("//"):
        return None
    for sep in (" #", "\t#"):
        if sep in text:
            text = text.split(sep, 1)[0].strip()
    m = re.match(r"^(\d{1,5})\s*(?:[,\s:|\t]+(.*))?$", text)
    if not m:
        return None
    port = int(m.group(1))
    if not (0 < port < 65536):
        return None
    service = (m.group(2) or "").strip()
    # 去掉说明括号，保留服务名
    if service:
        service = service.split("(")[0].strip()
    return port, service


def load_port_dict(path: str | Path) -> dict[int, str]:
    """读取单个端口字典文件，返回 ``{端口: 服务名}``。"""
    p = Path(path)
    out: dict[int, str] = {}
    raw = p.read_text(encoding="utf-8", errors="ignore")
    for line in raw.splitlines():
        parsed = parse_port_line(line)
        if parsed is None:
            continue
        port, service = parsed
        if port not in out or (service and not out[port]):
            out[port] = service
    return out


def default_dict_dir() -> Path:
    """内置端口字典目录（兼容 PyInstaller 冻结后的打包数据根）。"""
    from lib.runtime_paths import resource

    return resource(*DICT_SUBDIR)


def list_dict_files(directory: str | Path | None = None) -> list[Path]:
    """列出字典目录下的可用字典文件。"""
    root = Path(directory) if directory else default_dict_dir()
    if not root.is_dir():
        return []
    skip = {".md", ".py", ".json", ".pyc", ".png", ".jpg", ".zip", ".rar", ".7z"}
    return sorted(
        (p for p in root.iterdir() if p.is_file() and p.suffix.lower() not in skip),
        key=lambda p: p.name,
    )


def load_all_dicts(directory: str | Path | None = None) -> dict[int, str]:
    """合并目录下全部字典文件（去重，后出现的非空服务名优先）。"""
    merged: dict[int, str] = {}
    for path in list_dict_files(directory):
        for port, service in load_port_dict(path).items():
            if port not in merged or (service and not merged[port]):
                merged[port] = service
    return merged


# --------------------------------------------------------------------------- #
# 扫描
# --------------------------------------------------------------------------- #

@dataclass
class ScanStats:
    total: int = 0
    done: int = 0
    open: int = 0
    closed: int = 0
    filtered: int = 0
    error: int = 0
    rotations: int = 0
    started: float = field(default_factory=time.time)

    @property
    def elapsed(self) -> float:
        return max(0.0, time.time() - self.started)


def scan(
    host: str,
    ports: Sequence[int],
    pool: ProxyPool | None = None,
    threads: int = DEFAULT_THREADS,
    timeout: float = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
    service_map: dict[int, str] | None = None,
    log: Callable[[str], None] | None = None,
    on_hit: Callable[[ProbeResult], None] | None = None,
    on_progress: Callable[[ScanStats], None] | None = None,
    stop: threading.Event | None = None,
    out_dir: str | Path | None = None,
    verify_proxies: bool = True,
) -> dict:
    """多线程端口扫描。

    - ``pool`` 为 None 时直连；否则每个端口的每次尝试都从池里取下一个代理，
      代理故障或目标超时都会立刻换代理（「封禁即换」）。
    - ``verify_proxies`` 为 True 时，扫描前先对未验证的代理做否定测试，
      避免「全通」假代理把所有端口都报成开放。
    - 只把 ``open`` 的结果通过 ``on_hit`` 抛出；其余只计数，避免界面刷屏。
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    stop = stop or threading.Event()
    service_map = service_map or {}
    targets = [p for p in ports if 0 < p < 65536]
    stats = ScanStats(total=len(targets))
    hits: list[ProbeResult] = []
    hit_lock = threading.Lock()
    counter: dict = {"rotations": 0}
    progress_lock = threading.Lock()
    last_emit = [0.0]

    def _emit(force: bool = False) -> None:
        if on_progress is None:
            return
        now = time.time()
        with progress_lock:
            if not force and now - last_emit[0] < 0.2:
                return
            last_emit[0] = now
        stats.rotations = counter.get("rotations", 0)
        on_progress(stats)

    if log:
        mode = "直连" if pool is None else f"代理池（{len(pool)} 个，失败即换）"
        log(f"开始扫描 {host}，{len(targets)} 个端口，{threads} 线程，模式：{mode}")

    # 扫描前先把「全通」假代理剔掉，否则整份结果都不可信
    if pool is not None and verify_proxies:
        pending = [p for p in pool.items if p.verified is None and not p.dead]
        if pending:
            if log:
                log(f"先做代理可信度检查（{len(pending)} 个，用保留地址验证是否真转发）…")
            pool.verify_all(
                threads=max(8, min(threads * 4, 128)),
                timeout=min(timeout, 4.0),
                log=log,
                stop=stop,
            )
            alive = len(pool.alive())
            if log:
                log(f"可信代理剩余 {alive} 个")
            if alive == 0:
                if log:
                    log("没有可信代理可用，已中止（换一批代理源或改用直连）")
                stats.total = len(targets)
                return {
                    "host": host,
                    "total": len(targets),
                    "done": 0,
                    "open": 0,
                    "closed": 0,
                    "filtered": 0,
                    "error": 0,
                    "rotations": 0,
                    "untrusted": counter.get("untrusted", 0),
                    "elapsed": 0.0,
                    "hits": [],
                    "aborted": "no_trusted_proxy",
                    "proxy_stats": pool.stats() if pool is not None else None,
                }

    def _work(port: int) -> ProbeResult | None:
        result = _probe_with_failover(pool, host, port, timeout, retries, stop, counter)
        if result is None:
            return None
        result.service = service_map.get(port, "")
        with progress_lock:
            stats.done += 1
            if result.state == STATE_OPEN:
                stats.open += 1
            elif result.state == STATE_CLOSED:
                stats.closed += 1
            elif result.state == STATE_FILTERED:
                stats.filtered += 1
            else:
                stats.error += 1
        if result.state == STATE_OPEN:
            with hit_lock:
                hits.append(result)
            if on_hit is not None:
                on_hit(result)
        _emit()
        return result

    try:
        with ThreadPoolExecutor(max_workers=max(1, min(threads, max(1, len(targets))))) as executor:
            futures = [executor.submit(_work, port) for port in targets]
            for future in as_completed(futures):
                if stop.is_set():
                    for f in futures:
                        f.cancel()
                    break
                try:
                    future.result()
                except Exception as exc:  # 单端口异常不影响整体
                    if log:
                        log(f"[!] 探测异常：{exc}")
    finally:
        stats.rotations = counter.get("rotations", 0)
        _emit(force=True)

    hits.sort(key=lambda r: r.port)
    if log:
        log(
            f"扫描结束：开放 {stats.open} / 关闭 {stats.closed} / "
            f"过滤 {stats.filtered} / 错误 {stats.error}，"
            f"换代理 {stats.rotations} 次，耗时 {stats.elapsed:.1f}s"
        )
        # 大量超时通常意味着目标把当前出口整段封了，或者做了全端口过滤
        if stats.done >= 20 and stats.filtered / max(1, stats.done) >= 0.8:
            log(
                "提示：超时占比超过 80%，目标可能已封禁当前出口或做了全端口过滤，"
                "建议换一批代理源再试。"
            )

    result = {
        "host": host,
        "total": stats.total,
        "done": stats.done,
        "open": stats.open,
        "closed": stats.closed,
        "filtered": stats.filtered,
        "error": stats.error,
        "rotations": stats.rotations,
        "untrusted": counter.get("untrusted", 0),
        "elapsed": round(stats.elapsed, 2),
        "hits": [h.to_dict() for h in hits],
        "proxy_stats": pool.stats() if pool is not None else None,
    }

    if out_dir:
        result["files"] = _dump(host, hits, out_dir)
        if log:
            log(f"结果已保存到 {Path(out_dir)}")
    return result


def _dump(host: str, hits: list[ProbeResult], out_dir: str | Path) -> dict:
    """把开放端口写到 ``<out_dir>/<host>/open_ports.{csv,txt}``。"""
    safe = re.sub(r"[^0-9A-Za-z._-]", "_", host) or "target"
    root = Path(out_dir) / safe
    root.mkdir(parents=True, exist_ok=True)
    files: dict[str, str] = {}

    csv_path = root / "open_ports.csv"
    with csv_path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["端口", "服务", "状态", "延迟ms", "代理"])
        for hit in hits:
            writer.writerow([hit.port, hit.service, hit.label, hit.ms, hit.proxy])
    files["csv"] = str(csv_path)

    txt_path = root / "open_ports.txt"
    txt_path.write_text(
        "\n".join(
            f"{h.port}\t{h.service or '-'}\t{h.ms}ms\t{h.proxy}" for h in hits
        ) + ("\n" if hits else ""),
        encoding="utf-8",
    )
    files["txt"] = str(txt_path)
    return files


# --------------------------------------------------------------------------- #
# 自检
# --------------------------------------------------------------------------- #

def _selftest() -> int:
    """``python -m lib.port_scan`` 自检（不需要外网）。"""
    ok = True

    # 1. 代理行解析
    cases = [
        ("socks5://1.2.3.4:1080", ("socks5", "1.2.3.4", 1080)),
        ("http://5.6.7.8:8080", ("http", "5.6.7.8", 8080)),
        ("9.9.9.9:3128", ("socks5", "9.9.9.9", 3128)),
        ("10.0.0.1 8888", ("socks5", "10.0.0.1", 8888)),
        ("socks5://user:pwd@1.1.1.1:1080", ("socks5", "1.1.1.1", 1080)),
        ("# 注释", None),
        ("", None),
        ("not-a-proxy", None),
    ]
    for line, expect in cases:
        proxy = parse_proxy_line(line)
        got = (proxy.scheme, proxy.host, proxy.port) if proxy else None
        if got != expect:
            print(f"[FAIL] 代理解析 {line!r} -> {got}，期望 {expect}")
            ok = False
    print(f"[OK] 代理行解析 {len(cases)} 条")

    # 2. 端口表达式
    if parse_ports("80,443,1-5") != [80, 443, 1, 2, 3, 4, 5]:
        print("[FAIL] parse_ports 组合解析")
        ok = False
    if parse_ports("0,70000,abc,8080") != [8080]:
        print("[FAIL] parse_ports 非法值过滤")
        ok = False
    print("[OK] 端口表达式解析")

    # 3. 端口字典
    d = load_port_dict(default_dict_dir() / "常见端口.txt")
    if d.get(80) != "http" or d.get(3306) != "mysql":
        print(f"[FAIL] 端口字典解析：80={d.get(80)} 3306={d.get(3306)}")
        ok = False
    merged = load_all_dicts()
    if len(merged) < 100:
        print(f"[FAIL] 合并字典只有 {len(merged)} 条")
        ok = False
    print(f"[OK] 端口字典：常见 {len(d)} 条，合并 {len(merged)} 条")

    # 4. 代理池轮换与剔除
    pool = ProxyPool([Proxy("socks5", "1.1.1.1", 1), Proxy("socks5", "2.2.2.2", 2)])
    a = pool.next()
    b = pool.next()
    if a is None or b is None or a.key == b.key:
        print("[FAIL] 代理池未轮换")
        ok = False
    pool.report_fault(a)
    pool.report_fault(a)
    if not a.dead:
        print("[FAIL] 连续故障未判死")
        ok = False
    if pool.next(exclude={b.key}) is not None:
        print("[FAIL] exclude 未生效")
        ok = False
    print("[OK] 代理池轮换 / 判死 / 排除")

    # 5. 真实探测：本机起一个临时监听端口，走直连必须判 open
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(32)
    live_port = srv.getsockname()[1]
    accepted: list[socket.socket] = []
    accept_stop = threading.Event()

    def _accept_loop() -> None:
        while not accept_stop.is_set():
            try:
                conn, _ = srv.accept()
                accepted.append(conn)
            except OSError:
                break

    threading.Thread(target=_accept_loop, daemon=True).start()
    try:
        # 5. 直连探测
        res = probe(None, "127.0.0.1", live_port, 3)
        if res.state != STATE_OPEN:
            print(f"[FAIL] 直连探测本机监听端口 -> {res.state}/{res.code}")
            ok = False
        # Windows 上连 127.0.0.1 的关闭端口可能直接超时而非 RST，
        # 因此只要求「不判成开放」
        closed = probe(None, "127.0.0.1", 1, 2)
        if closed.state == STATE_OPEN:
            print("[FAIL] 直连探测已关闭端口误判为开放")
            ok = False
        print(f"[OK] 直连探测：开放端口 {live_port} -> {res.state}，关闭端口 -> {closed.state}")

        # 6. 扫描 + 落盘（直连）
        import tempfile

        tmp = Path(tempfile.mkdtemp(prefix="portscan_"))
        hits: list[ProbeResult] = []
        result = scan(
            "127.0.0.1",
            [live_port, 1, 2],
            pool=None,
            threads=4,
            timeout=2,
            log=print,
            on_hit=hits.append,
            out_dir=tmp,
        )
        if result["open"] != 1 or len(hits) != 1:
            print(f"[FAIL] 扫描统计：open={result['open']} hits={len(hits)}")
            ok = False
        if not Path(result.get("files", {}).get("csv", "")).is_file():
            print("[FAIL] 结果未落盘")
            ok = False
        print(f"[OK] 扫描直连：{result['total']} 个端口，开放 {result['open']}，已落盘")

        # 7. 代理全部故障：必须判成 error，绝不能误报开放
        bad_pool = ProxyPool([Proxy("socks5", "127.0.0.1", 1), Proxy("socks5", "127.0.0.1", 2)])
        failover = _probe_with_failover(bad_pool, "127.0.0.1", live_port, 1.0, 2, None, {})
        if failover is None or failover.state != STATE_ERROR:
            print(f"[FAIL] 代理全故障时应判 error，实际 {failover.state if failover else None}"
                  f"/{failover.code if failover else ''}")
            ok = False
        if failover is not None and failover.proxy == "direct":
            print("[FAIL] 代理故障时不应退回直连")
            ok = False
        print(f"[OK] 代理全部故障 -> {failover.state}/{failover.code}（不会误判开放）")

        # 8. 疑似封禁连续累计后降权
        blocker = Proxy("socks5", "3.3.3.3", 1080)
        bpool = ProxyPool([blocker], block_after=3)
        for _ in range(2):
            bpool.report_blocked(blocker)
        if blocker.dead:
            print("[FAIL] 未达阈值就降权")
            ok = False
        bpool.report_blocked(blocker)
        if not blocker.dead:
            print("[FAIL] 连续疑似封禁未降权")
            ok = False
        print("[OK] 连续疑似封禁后代理降权")
    finally:
        accept_stop.set()
        for conn in accepted:
            try:
                conn.close()
            except OSError:
                pass
        srv.close()

    # 9. 假代理识别：起一个「无脑回连接成功」的 SOCKS5，必须被判为不可信
    fake_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    fake_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    fake_srv.bind(("127.0.0.1", 0))
    fake_srv.listen(16)
    fake_port = fake_srv.getsockname()[1]
    fake_stop = threading.Event()

    def _fake_handle(conn: socket.socket) -> None:
        try:
            conn.settimeout(3)
            conn.recv(4)
            conn.sendall(b"\x05\x00")
            conn.recv(512)
            # 不管目标是哪都回「成功」
            conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            time.sleep(0.2)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _fake_loop() -> None:
        while not fake_stop.is_set():
            try:
                conn, _ = fake_srv.accept()
            except OSError:
                break
            threading.Thread(target=_fake_handle, args=(conn,), daemon=True).start()

    threading.Thread(target=_fake_loop, daemon=True).start()
    try:
        fake = Proxy("socks5", "127.0.0.1", fake_port)
        # 假代理对任意端口都回 open —— 这正是要防的坑
        loose = probe(fake, "www.example.com", 12345, 3)
        if loose.state != STATE_OPEN:
            print(f"[FAIL] 假代理应误报 open，实际 {loose.state}/{loose.code}")
            ok = False
        if verify_proxy(fake, 3) is not False:
            print("[FAIL] 否定测试未能识别假代理")
            ok = False
        if not fake.dead:
            print("[FAIL] 假代理未被判死")
            ok = False
        print("[OK] 假代理识别：任意端口误报 open，否定测试判死")
    finally:
        fake_stop.set()
        fake_srv.close()

    # 10. 扫描遇到假代理时必须中止，而不是吐出一堆假开放
    fake2 = Proxy("socks5", "127.0.0.1", fake_port)
    fp = ProxyPool([fake2])
    res2 = scan("www.example.com", [80, 443], pool=fp, threads=2, timeout=2,
                retries=1, log=None)
    if res2.get("aborted") != "no_trusted_proxy" or res2["open"] != 0:
        print(f"[FAIL] 假代理应中止扫描，实际 open={res2['open']} aborted={res2.get('aborted')}")
        ok = False
    print("[OK] 全是假代理时扫描中止，不产出假结果")

    # 11. 真 SOCKS5 转发代理：必须能正确区分开放 / 关闭
    mini_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mini_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mini_srv.bind(("127.0.0.1", 0))
    mini_srv.listen(16)
    mini_port = mini_srv.getsockname()[1]
    mini_stop = threading.Event()

    def _mini_handle(conn: socket.socket) -> None:
        try:
            conn.settimeout(3)
            head = conn.recv(2)
            if len(head) < 2:
                return
            conn.recv(head[1])
            conn.sendall(b"\x05\x00")
            req = _recv_exact(conn, 4)
            atyp = req[3]
            if atyp == 1:
                addr = socket.inet_ntoa(_recv_exact(conn, 4))
            elif atyp == 3:
                length = _recv_exact(conn, 1)[0]
                addr = _recv_exact(conn, length).decode()
            else:
                conn.sendall(b"\x05\x08\x00\x01" + b"\x00" * 6)
                return
            dst_port = struct.unpack("!H", _recv_exact(conn, 2))[0]
            try:
                remote = socket.create_connection((addr, dst_port), 3)
            except OSError:
                conn.sendall(b"\x05\x05\x00\x01" + b"\x00" * 6)  # connection refused
                return
            conn.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
            remote.close()
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _mini_loop() -> None:
        while not mini_stop.is_set():
            try:
                conn, _ = mini_srv.accept()
            except OSError:
                break
            threading.Thread(target=_mini_handle, args=(conn,), daemon=True).start()

    threading.Thread(target=_mini_loop, daemon=True).start()
    target_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    target_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    target_srv.bind(("127.0.0.1", 0))
    target_srv.listen(16)
    open_port = target_srv.getsockname()[1]
    target_stop = threading.Event()

    def _target_loop() -> None:
        while not target_stop.is_set():
            try:
                conn, _ = target_srv.accept()
                conn.close()
            except OSError:
                break

    threading.Thread(target=_target_loop, daemon=True).start()
    try:
        good_proxy = Proxy("socks5", "127.0.0.1", mini_port)
        if not verify_proxy(good_proxy, 3):
            print("[FAIL] 真代理未通过否定测试")
            ok = False
        hit = probe(good_proxy, "127.0.0.1", open_port, 3)
        miss = probe(good_proxy, "127.0.0.1", 1, 3)
        if hit.state != STATE_OPEN or miss.state == STATE_OPEN:
            print(f"[FAIL] 真代理判定错误：开放口={hit.state} 关闭口={miss.state}")
            ok = False
        gpool = ProxyPool([good_proxy])
        gres = scan("127.0.0.1", [open_port, 1], pool=gpool, threads=2, timeout=3,
                    retries=1, log=None)
        if gres["open"] != 1 or gres["hits"][0]["port"] != open_port:
            print(f"[FAIL] 真代理扫描结果错误：open={gres['open']} hits={gres['hits']}")
            ok = False
        print(f"[OK] 真 SOCKS5 代理：开放口 {open_port} -> open，关闭口 -> {miss.state}，扫描命中 1 个")
    finally:
        mini_stop.set()
        target_stop.set()
        mini_srv.close()
        target_srv.close()

    # 12. 本地 HTTP 代理（fir-proxy 形态）：502 不能被误判成假代理
    http_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    http_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    http_srv.bind(("127.0.0.1", 0))
    http_srv.listen(16)
    http_port = http_srv.getsockname()[1]
    http_stop = threading.Event()

    def _http_handle(conn: socket.socket) -> None:
        try:
            conn.settimeout(3)
            raw = b""
            while b"\r\n\r\n" not in raw:
                chunk = conn.recv(1024)
                if not chunk:
                    return
                raw += chunk
            first = raw.split(b"\r\n", 1)[0].decode("latin-1")
            parts = first.split()
            target = parts[1] if len(parts) > 1 else ""
            host, _, port_s = target.rpartition(":")
            try:
                remote = socket.create_connection((host, int(port_s)), 3)
            except (OSError, ValueError):
                conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                return
            conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            remote.close()
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _http_loop() -> None:
        while not http_stop.is_set():
            try:
                conn, _ = http_srv.accept()
            except OSError:
                break
            threading.Thread(target=_http_handle, args=(conn,), daemon=True).start()

    threading.Thread(target=_http_loop, daemon=True).start()
    tgt2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tgt2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tgt2.bind(("127.0.0.1", 0))
    tgt2.listen(16)
    live2 = tgt2.getsockname()[1]
    tgt2_stop = threading.Event()

    def _tgt2_loop() -> None:
        while not tgt2_stop.is_set():
            try:
                conn, _ = tgt2.accept()
                conn.close()
            except OSError:
                break

    threading.Thread(target=_tgt2_loop, daemon=True).start()
    try:
        http_proxy = Proxy("http", "127.0.0.1", http_port)
        if not verify_proxy(http_proxy, 3):
            print("[FAIL] HTTP 代理（上游失败回 502）被误判为不可信")
            ok = False
        hres = probe(http_proxy, "127.0.0.1", live2, 3)
        if hres.state != STATE_OPEN:
            print(f"[FAIL] HTTP 代理探测开放端口 -> {hres.state}/{hres.code}")
            ok = False
        print(f"[OK] HTTP 代理（fir-proxy 形态）：502 不误杀，开放口 -> {hres.state}")
    finally:
        http_stop.set()
        tgt2_stop.set()
        http_srv.close()
        tgt2.close()

    print("\n自检结果：", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(_selftest())
