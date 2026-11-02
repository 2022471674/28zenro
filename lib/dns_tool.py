# -*- coding: utf-8 -*-
"""DNS 工具纯逻辑模块：单域名 DNS 解析 + 字典子域名爆破。

提供两个独立能力，供「DNS 解析」与「字典子域名爆破」两个 Web 子工具使用，
同时被 :mod:`lib.web_fuzz` 复用（遵循 Web Fuzz 统一入口约定）：

1. **单域名 DNS 解析**：查询 A（IPv4）/ AAAA（IPv6）/ CNAME（别名）三类记录，
   用 ``Resolve-DnsName`` 与 ``nslookup`` 两条系统路径交叉校准，另用 Python
   ``socket.getaddrinfo`` 兜底（可走全局代理池 SOCKS5 做远程 DNS）。
2. **字典子域名爆破**：读取子域名字典（默认 ``dict/Contents/subdomain.dict``，
   支持自定义路径），逐个拼 ``词条.主域名`` 做 DNS A 查询，带速率限制与
   独立代理开关。

设计约定
--------
- 与 Web Fuzz 其它工具一致：DNS 解析的「代理」仅对 SOCKS5 生效（远程 DNS），
  ``Resolve-DnsName`` / ``nslookup`` 走系统本地 DNS 作为校准基线。
- 本模块只做纯逻辑，不导入任何 UI 模块；结果由 :func:`resolve_dns` /
  :func:`brute_subdomains` 返回结构化 dict / list。
- 全程支持 ``stop`` 事件与逐行日志回调。

本模块只做「域名进、记录出」的纯逻辑。
"""

from __future__ import annotations

import re
import socket
import subprocess
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Any, Callable

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
#: 默认子域名字典（相对项目根 / 打包数据根）
SUBDOMAIN_DICT = ("dict", "Contents", "subdomain.dict")

#: 子域名爆破默认速率限制：相邻两次 DNS 查询的最小间隔（秒）
DEFAULT_INTERVAL = 0.3
#: 单个 DNS 命令（Resolve-DnsName / nslookup）的超时（秒）
COMMAND_TIMEOUT = 8
#: 子域名爆破单轮最大查询条数（防止字典过大把流程拖死）
MAX_SUBDOMAINS = 2000

#: 支持的记录类型：类型名 -> 展示名
RECORD_TYPES: tuple[tuple[str, str], ...] = (
    ("A", "A（IPv4）"),
    ("AAAA", "AAAA（IPv6）"),
    ("CNAME", "CNAME（别名）"),
)

LogFn = Callable[[str], None]


class DnsToolError(ValueError):
    """DNS 工具参数 / 解析失败时抛出的统一异常。"""


# ---------------------------------------------------------------------------
# 域名 / 字典规范化
# ---------------------------------------------------------------------------
def normalize_domain(raw: str) -> str:
    """把 ``https://example.com/xx`` 之类整理成纯域名（去协议 / 路径 / 端口）。

    IP 原样返回（IPv6 带方括号会去掉）。无法解析时抛 :class:`DnsToolError`。
    """
    text = str(raw or "").strip().replace("：", ":")
    if not text:
        raise DnsToolError("请填写要解析的域名，如 example.com")
    lowered = text.lower()
    for scheme in ("https://", "http://"):
        if lowered.startswith(scheme):
            text = text[len(scheme):]
    text = text.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].strip()
    # 去掉端口（仅当单冒号且尾部是纯数字，避免误伤 IPv6）
    if text.count(":") == 1:
        head, tail = text.rsplit(":", 1)
        if tail.isdigit():
            text = head
    # IPv6 方括号
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    text = text.strip().strip(".")
    if not text:
        raise DnsToolError("域名格式不正确，示例：example.com")
    return text


def default_subdomain_dict() -> Path:
    """默认子域名字典：源码运行取项目根 ``dict/Contents/subdomain.dict``，
    打包后取打包数据根（_internal）。"""
    from lib.runtime_paths import resource

    return resource(*SUBDOMAIN_DICT)


def load_subdomain_words(dict_path: str | Path | None = None,
                         log: LogFn | None = None) -> list[str]:
    """读取子域名字典，返回规范化后的词条（去空行 / 注释 / 去重）。

    子域名标签只保留小写字母 / 数字 / 连字符；超过 :data:`MAX_SUBDOMAINS`
    时截断并提示。
    """
    emit = log or (lambda _m: None)
    path = Path(dict_path) if dict_path else default_subdomain_dict()
    if not path.is_file():
        raise DnsToolError(f"子域名字典不存在：{path}")
    raw = path.read_bytes()
    text = ""
    for encoding in ("utf-8-sig", "utf-8", "gbk", "latin-1"):
        try:
            text = raw.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    seen: set[str] = set()
    words: list[str] = []
    for line in text.splitlines():
        word = str(line or "").replace("\ufeff", "").strip()
        if not word or word.startswith("#") or word.startswith("//"):
            continue
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?", word):
            continue
        if word not in seen:
            seen.add(word)
            words.append(word)
    if len(words) > MAX_SUBDOMAINS:
        emit(f"[字典] {len(words)} 条超过上限 {MAX_SUBDOMAINS}，只取前 "
             f"{MAX_SUBDOMAINS} 条")
        words = words[:MAX_SUBDOMAINS]
    return words


# ---------------------------------------------------------------------------
# DNS 命令执行
# ---------------------------------------------------------------------------
def _run_command(args: list[str], timeout: float) -> tuple[str, str]:
    """运行一个系统 DNS 命令，返回 ``(stdout, stderr)``；失败返回空串。"""
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
        return proc.stdout or "", proc.stderr or ""
    except (OSError, subprocess.TimeoutExpired):
        return "", ""


def _is_windows() -> bool:
    import platform
    return platform.system() == "Windows"


#: 允许进入系统 DNS 命令（Resolve-DnsName / nslookup）的域名白名单：
#: 仅字母 / 数字 / 点 / 连字符 / 下划线（合法域名一定能通过）
_SAFE_HOST_RE = re.compile(r"[A-Za-z0-9._\-]{1,253}")


def _command_host_ok(host: str) -> bool:
    """host 是否能安全拼进系统命令。含引号 / 分号 / ``$`` 等特殊字符的输入
    一律不进命令（防命令注入），由 :func:`_resolve_socket` 的 getaddrinfo 兜底。"""
    return bool(_SAFE_HOST_RE.fullmatch(host))


def _resolve_dnsname(host: str, rtype: str, timeout: float) -> list[str]:
    """用 ``Resolve-DnsName`` 查询指定类型记录，返回结果列表。

    Windows 上走 PowerShell；非 Windows 回退到 ``nslookup -type=<rtype>``。
    返回的是「值」列表（A/AAAA 为 IP，CNAME 为别名）。解析失败返回空列表。
    """
    if not _command_host_ok(host):
        return []
    try:
        if _is_windows():
            out, _ = _run_command(
                ["powershell", "-NoProfile", "-Command",
                 f"Resolve-DnsName -Name '{host}' -Type {rtype} "
                 f"-ErrorAction SilentlyContinue | "
                 f"Select-Object -ExpandProperty "
                 f"{'IPAddress' if rtype in ('A', 'AAAA') else 'NameHost'}"],
                timeout)
        else:
            out, _ = _run_command(["nslookup", f"-type={rtype}", host], timeout)
    except Exception:  # noqa: BLE001  命令缺失等异常不影响其它查询
        return []
    return _extract_values(out, rtype)


def _resolve_nslookup(host: str, rtype: str, timeout: float) -> list[str]:
    """用 ``nslookup`` 查询指定类型记录，返回结果列表（跨平台）。"""
    if not _command_host_ok(host):
        return []
    out, _ = _run_command(["nslookup", f"-type={rtype}", host], timeout)
    return _extract_values(out, rtype)


def _extract_values(out: str, rtype: str) -> list[str]:
    """从命令输出里提取该记录类型的「值」。

    - A：IPv4 地址；
    - AAAA：IPv6 地址（``Addresses:`` 之后的答案，排除 DNS 服务器自身地址）；
    - CNAME：别名（``canonical name =`` / ``alias =`` 之后的值）。
    """
    values: list[str] = []

    # nslookup 的「Server: / Address:」（单数）是 DNS 服务器自身信息，
    # 真正的答案在「Addresses:」（复数）之后；Resolve-DnsName 则直接给 IP。
    # 统一策略：若输出里存在「Addresses:」，只从其位置往后取答案。
    m_addr = re.search(r"(?i)addresses\s*:", out)
    if m_addr is not None:
        out = out[m_addr.end():]

    if rtype == "AAAA":
        for m in re.finditer(
                r"(?i)\b[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,7}\b", out):
            value = m.group(0)
            # 排除链路本地地址（本机网卡 / DNS 服务器自身的 fe80::）
            if (":" in value and not value.lower().startswith("fe80:")
                    and value not in values):
                values.append(value)
        return values
    if rtype == "CNAME":
        # 别名：canonical name = xxx 或 alias = xxx
        for m in re.finditer(r"(?i)(?:canonical name|alias(?:es)?)\s*=\s*(\S+)",
                             out):
            value = m.group(1).rstrip(".")
            if value and value not in values:
                values.append(value)
        return values
    # A 记录：IPv4
    for m in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", out):
        ip = m.group(0)
        if ip.split(".")[0] != "0" and ip not in values:
            values.append(ip)
    return values


def _resolve_socket(host: str, rtype: str, use_proxy: bool,
                    timeout: float) -> list[str]:
    """用 Python ``socket.getaddrinfo`` 解析，返回结果列表。

    ``use_proxy=True`` 且代理池里有 SOCKS5 代理时，先通过 SOCKS5 RESOLVE
    扩展命令在代理侧做远程 DNS；代理不支持或失败时回退系统本地解析。
    注意：绝不替换全局 ``socket.socket`` —— ``getaddrinfo`` 走 C 层解析器，
    monkeypatch 对它本来就无效，只会污染整个进程的其它网络请求。

    A 用 AF_INET，AAAA 用 AF_INET6；CNAME 通过 getaddrinfo 拿不到，返回空。
    """
    if rtype == "CNAME":
        return []
    if use_proxy:
        remote = _resolve_via_socks5(host, timeout)
        if remote:
            return remote
    family = socket.AF_INET if rtype == "A" else socket.AF_INET6
    values: list[str] = []
    try:
        infos = socket.getaddrinfo(host, None, family, socket.SOCK_STREAM)
    except OSError:
        return []
    for info in infos:
        value = info[4][0]
        if value and value not in values:
            values.append(value)
    return values


def _resolve_via_socks5(host: str, timeout: float) -> list[str] | None:
    """从代理池取 SOCKS5 代理做远程 DNS；无可用代理或失败返回 None。"""
    try:
        from lib import proxy_pool
        entry = proxy_pool.get_proxy()
    except Exception:  # noqa: BLE001  代理池异常不影响本地解析
        return None
    if entry is None or entry.protocol != "socks5":
        return None
    try:
        return _socks5_resolve(host, entry, timeout)
    except (OSError, ValueError, UnicodeEncodeError):
        return None


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    """从 socket 精确读取 ``size`` 字节；对端中断抛 :class:`OSError`。"""
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise OSError("代理连接中断")
        data += chunk
    return data


def _socks5_resolve(host: str, entry: Any, timeout: float) -> list[str]:
    """SOCKS5 RESOLVE 扩展（命令码 0xF0，Tor / dante / shadowsocks 等支持）：
    让代理在它那一侧解析域名，返回代理解析出的地址（通常 1 条）。

    代理要求认证、不支持该扩展或连接失败时抛 :class:`OSError`，
    由调用方回退本地解析。
    """
    name = host.encode("ascii", "strict")
    if not name or len(name) > 255:
        raise OSError("域名长度超出 SOCKS5 协议限制")
    with socket.create_connection((entry.host, entry.port),
                                  timeout=max(1.0, float(timeout))) as sock:
        sock.settimeout(max(1.0, float(timeout)))
        # 握手：只声明「无认证」方法
        sock.sendall(b"\x05\x01\x00")
        method = _recv_exact(sock, 2)
        if method[0] != 5 or method[1] != 0:
            raise OSError("SOCKS5 代理要求认证，无法用于远程解析")
        # RESOLVE 请求：VER=5 CMD=0xF0 RSV=0 ATYP=0x03（域名）
        sock.sendall(b"\x05\xf0\x00\x03" + bytes([len(name)]) + name)
        head = _recv_exact(sock, 4)
        if head[1] != 0:
            raise OSError(f"SOCKS5 代理不支持远程解析（REP={head[1]}）")
        atyp = head[3]
        if atyp == 0x01:
            return [socket.inet_ntop(socket.AF_INET, _recv_exact(sock, 4))]
        if atyp == 0x04:
            return [socket.inet_ntop(socket.AF_INET6, _recv_exact(sock, 16))]
        if atyp == 0x03:
            size = _recv_exact(sock, 1)[0]
            return [_recv_exact(sock, size).decode("ascii", "replace").rstrip(".")]
        raise OSError(f"SOCKS5 应答含未知地址类型 {atyp}")


# ---------------------------------------------------------------------------
# 单域名 DNS 解析（A / AAAA / CNAME）
# ---------------------------------------------------------------------------
def resolve_record(host: str, rtype: str, use_proxy: bool,
                   timeout: float) -> dict[str, Any]:
    """查询 ``host`` 的单条记录类型，返回 ``{"type", "values", "note"}``。

    用 ``Resolve-DnsName`` 与 ``nslookup`` 交叉校准（另加 socket 兜底），
    结果不一致时 ``note`` 标注「解析不一致」。
    """
    dnsname = _resolve_dnsname(host, rtype, timeout)
    nslookup = _resolve_nslookup(host, rtype, timeout)
    socket_vals = _resolve_socket(host, rtype, use_proxy, timeout)

    merged: list[str] = []
    for v in dnsname + nslookup + socket_vals:
        if v and v not in merged:
            merged.append(v)

    note = ""
    non_empty = [s for s in (dnsname, nslookup, socket_vals) if s]
    if len(non_empty) >= 2:
        ref = set(non_empty[0])
        for other in non_empty[1:]:
            if set(other) != ref:
                note = "解析不一致"
                break
    return {"type": rtype, "values": merged, "note": note}


def resolve_dns(host: str, use_proxy: bool = False,
                timeout: float = COMMAND_TIMEOUT) -> dict[str, Any]:
    """对单个域名做 DNS 解析，返回结构化结果。

    返回 ``{"host", "records": [{"type", "values", "note"}, ...]}``，
    ``records`` 按 A / AAAA / CNAME 顺序，仅包含有值的记录。
    """
    target = normalize_domain(host)
    records: list[dict[str, Any]] = []
    for rtype, _label in RECORD_TYPES:
        rec = resolve_record(target, rtype, use_proxy, timeout)
        if rec["values"]:
            records.append(rec)
    return {"host": target, "records": records}


# ---------------------------------------------------------------------------
# 字典子域名爆破（DNS A 查询）
# ---------------------------------------------------------------------------
def brute_subdomains(
    base_domain: str,
    dict_path: str | Path | None = None,
    interval: float = DEFAULT_INTERVAL,
    use_proxy: bool = False,
    timeout: float = COMMAND_TIMEOUT,
    log: LogFn | None = None,
    found: Callable[[dict[str, Any]], None] | None = None,
    stop: threading.Event | None = None,
) -> tuple[list[dict[str, Any]], str]:
    """字典子域名爆破：逐个拼 ``词条.主域名`` 做 DNS A 查询。

    返回 ``(结果列表, 说明)``，每条 ``{"subdomain", "ips", "note"}``。
    速率限制通过 ``interval``（相邻两次最小间隔，秒，0 表示不限）控制，
    支持 ``stop`` 中断。

    ``found`` 为命中回调：每发现一个子域名立即回调（供界面增量填表，
    避免长时间爆破过程中表格一直为空），回调参数为单条结果 dict。
    """
    emit = log or (lambda _m: None)
    domain = normalize_domain(base_domain)
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", domain) or ":" in domain:
        return [], "目标是 IP，无法爆破子域名"
    try:
        words = load_subdomain_words(dict_path, log=emit)
    except DnsToolError as exc:
        return [], str(exc)
    if not words:
        return [], "子域名字典为空"

    interval = max(0.0, float(interval))
    emit(f"[子域名] 字典 {len(words)} 条，主域名 {domain}，"
         f"间隔 {interval:g}s"
         + ("，走 SOCKS5 代理" if use_proxy else "，直连系统 DNS"))

    results: list[dict[str, Any]] = []
    last_query = 0.0
    for word in words:
        if stop is not None and stop.is_set():
            break
        if interval > 0:
            wait = (last_query + interval) - time.time()
            while wait > 0:
                if stop is not None and stop.is_set():
                    break
                time.sleep(min(0.1, wait))
                wait = (last_query + interval) - time.time()
            if stop is not None and stop.is_set():
                break
        host = f"{word}.{domain}"
        last_query = time.time()
        try:
            rec = resolve_record(host, "A", use_proxy, timeout)
        except Exception as exc:  # noqa: BLE001  单条解析异常不影响整体
            emit(f"[子域名] {host} 解析异常：{exc}")
            continue
        if rec["values"]:
            item = {
                "subdomain": host,
                "ips": rec["values"],
                "note": rec["note"],
            }
            results.append(item)
            emit(f"[子域名] {host} -> {', '.join(rec['values'])}"
                 + (f"（{rec['note']}）" if rec["note"] else ""))
            if found is not None:
                found(dict(item))

    note = "已手动停止" if (stop is not None and stop.is_set()) else ""
    return results, note


__all__ = [
    "SUBDOMAIN_DICT",
    "DEFAULT_INTERVAL",
    "COMMAND_TIMEOUT",
    "MAX_SUBDOMAINS",
    "RECORD_TYPES",
    "DnsToolError",
    "normalize_domain",
    "default_subdomain_dict",
    "load_subdomain_words",
    "resolve_record",
    "resolve_dns",
    "brute_subdomains",
]
