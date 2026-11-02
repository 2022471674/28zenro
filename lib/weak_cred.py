# -*- coding: utf-8 -*-
"""通用弱口令检测（Redis / SSH / FTP / 常用服务）。

与 :mod:`lib.mysql_brute`（MySQL 弱口令）互补，覆盖 Web / 内网授权测试里
同样高频的几类服务。本模块同样**手写最简协议**，避免引入 paramiko 等重依赖
（PyInstaller 单文件打包友好）：

- **Redis**：发送 ``AUTH password``（未设密码时直接 ``PING``），回 ``+PONG``
  即命中；``-NOAUTH`` / ``-ERR`` 语义区分「密码错」与「需认证」。
- **FTP**：连接后读 220 欢迎码，发 ``USER`` / ``PASS``，230 → 登录成功，
  530 → 凭据错误。
- **SSH**：**仅做 banner 指纹识别**（连接后读取 ``SSH-2.0-xxx`` 版本串，
  不发认证），不做爆破 —— 爆破 SSH 需完整密钥交换，手写成本高且易被误判，
  这里只给出「服务存在 + 版本」的被动探测结果。

设计约定
--------
- 目标分类沿用 :mod:`lib.mysql_brute` 的合规边界：内网可爆破，公网 / 域名
  仅被动指纹（``classify_target``）。
- 本模块只做纯逻辑，不导入任何 UI 模块；全程支持 ``stop`` 与逐行日志。
"""

from __future__ import annotations

import socket
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Sequence

from lib.mysql_brute import (
    TARGET_INTRANET,
    TARGET_INTERNET,
    TARGET_HOSTNAME,
    classify_target,
)

DEFAULT_TIMEOUT = 6.0
DEFAULT_THREADS = 8

LogFn = Callable[[str], None]

#: 服务类型常量
SVC_REDIS = "redis"
SVC_FTP = "ftp"
SVC_SSH = "ssh"

SVC_LABELS = {
    SVC_REDIS: "Redis",
    SVC_FTP: "FTP",
    SVC_SSH: "SSH",
}

#: 各服务默认端口
DEFAULT_PORTS = {
    SVC_REDIS: 6379,
    SVC_FTP: 21,
    SVC_SSH: 22,
}

#: 结果状态
STATE_OK = "ok"
STATE_DENIED = "denied"
STATE_ERROR = "error"

STATE_LABELS = {
    STATE_OK: "成功",
    STATE_DENIED: "拒绝",
    STATE_ERROR: "错误",
}


class WeakCredError(ValueError):
    """弱口令检测参数错误时抛出的统一异常。"""


@dataclass
class AuthResult:
    """单次认证尝试的结果。"""

    service: str = ""
    host: str = ""
    port: int = 0
    user: str = ""
    password: str = ""
    state: str = STATE_ERROR
    code: str = ""
    message: str = ""
    banner: str = ""
    ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "service": self.service,
            "host": self.host,
            "port": self.port,
            "user": self.user,
            "password": self.password,
            "state": self.state,
            "code": self.code,
            "message": self.message,
            "banner": self.banner,
            "ms": self.ms,
        }


# ---------------------------------------------------------------------------
# 单次认证：Redis / FTP / SSH（banner）
# ---------------------------------------------------------------------------
def _connect(host: str, port: int, timeout: float) -> socket.socket:
    sock = socket.create_connection((host, port), timeout)
    sock.settimeout(timeout)
    return sock


def _recv_until(sock: socket.socket, marker: bytes, cap: int = 8192) -> bytes:
    """读取直到出现 marker 或超时 / 到上限。"""
    buf = b""
    try:
        while marker not in buf and len(buf) < cap:
            chunk = sock.recv(256)
            if not chunk:
                break
            buf += chunk
    except OSError:
        pass
    return buf


def try_redis(host: str, port: int, password: str,
              timeout: float = DEFAULT_TIMEOUT) -> AuthResult:
    """对 Redis 做一次认证 / 探测，返回 AuthResult。"""
    result = AuthResult(service=SVC_REDIS, host=host, port=port, password=password)
    import time

    t0 = time.time()
    try:
        sock = _connect(host, port, timeout)
        if password:
            sock.sendall(f"AUTH {password}\r\n".encode())
            resp = _recv_until(sock, b"\r\n")
            text = resp.decode("utf-8", "ignore").strip()
            if text.startswith("+PONG") or text.startswith("+OK"):
                result.state = STATE_OK
                result.message = "认证成功"
            elif text.startswith("-ERR invalid password") or "-WRONGPASS" in text:
                result.state = STATE_DENIED
                result.message = "密码错误"
            elif text.startswith("-NOAUTH"):
                result.state = STATE_DENIED
                result.message = "需要认证（密码错误或未授权）"
            elif "-ERR" in text and "without any password" in text:
                result.state = STATE_OK
                result.message = "未设密码（无需 AUTH）"
            else:
                result.state = STATE_ERROR
                result.message = text or "无响应"
        else:
            sock.sendall(b"PING\r\n")
            resp = _recv_until(sock, b"\r\n")
            text = resp.decode("utf-8", "ignore").strip()
            if text.startswith("+PONG"):
                result.state = STATE_OK
                result.message = "未设密码，可直接连接"
            elif text.startswith("-NOAUTH"):
                result.state = STATE_DENIED
                result.message = "需要密码认证"
            else:
                result.state = STATE_ERROR
                result.message = text or "无响应"
        sock.close()
    except (OSError, socket.timeout) as exc:
        result.state = STATE_ERROR
        result.message = f"连接失败：{exc}"
    result.ms = int((time.time() - t0) * 1000)
    return result


def try_ftp(host: str, port: int, user: str, password: str,
            timeout: float = DEFAULT_TIMEOUT) -> AuthResult:
    """对 FTP 做一次登录尝试，返回 AuthResult。"""
    result = AuthResult(service=SVC_FTP, host=host, port=port,
                        user=user, password=password)
    import time

    t0 = time.time()
    try:
        sock = _connect(host, port, timeout)
        welcome = _recv_until(sock, b"\r\n")
        result.banner = welcome.decode("utf-8", "ignore").strip()[:200]
        if not welcome.startswith(b"220"):
            result.state = STATE_ERROR
            result.message = "非 FTP 服务或连接被拒"
            sock.close()
            result.ms = int((time.time() - t0) * 1000)
            return result

        sock.sendall(f"USER {user}\r\n".encode())
        user_resp = _recv_until(sock, b"\r\n").decode("utf-8", "ignore").strip()
        sock.sendall(f"PASS {password}\r\n".encode())
        pass_resp = _recv_until(sock, b"\r\n").decode("utf-8", "ignore").strip()
        sock.close()

        if pass_resp.startswith("230"):
            result.state = STATE_OK
            result.message = "登录成功"
        elif pass_resp.startswith(("530", "430")):
            result.state = STATE_DENIED
            result.message = "凭据错误"
        elif pass_resp.startswith("331"):
            result.state = STATE_DENIED
            result.message = "需要额外认证"
        else:
            result.state = STATE_ERROR
            result.message = pass_resp or user_resp
    except (OSError, socket.timeout) as exc:
        result.state = STATE_ERROR
        result.message = f"连接失败：{exc}"
    result.ms = int((time.time() - t0) * 1000)
    return result


def try_ssh(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> AuthResult:
    """对 SSH 做被动 banner 指纹（不发认证，仅读版本串）。"""
    result = AuthResult(service=SVC_SSH, host=host, port=port)
    import time

    t0 = time.time()
    try:
        sock = _connect(host, port, timeout)
        banner = _recv_until(sock, b"\n")
        sock.close()
        result.banner = banner.decode("utf-8", "ignore").strip()[:200]
        if result.banner.startswith("SSH-"):
            result.state = STATE_OK
            result.message = f"SSH 服务：{result.banner}"
        else:
            result.state = STATE_ERROR
            result.message = f"非 SSH 服务：{result.banner or '无响应'}"
    except (OSError, socket.timeout) as exc:
        result.state = STATE_ERROR
        result.message = f"连接失败：{exc}"
    result.ms = int((time.time() - t0) * 1000)
    return result


#: 服务 -> 单次认证函数
_AUTH_FN = {
    SVC_REDIS: try_redis,
    SVC_FTP: try_ftp,
    SVC_SSH: try_ssh,
}


def probe(host: str, service: str, port: int | None = None,
          timeout: float = DEFAULT_TIMEOUT) -> AuthResult:
    """对目标做一次被动探测（Redis PING / FTP 220 / SSH banner）。"""
    svc = service if service in SVC_LABELS else SVC_SSH
    port = port or DEFAULT_PORTS[svc]
    if svc == SVC_SSH:
        return try_ssh(host, port, timeout)
    if svc == SVC_FTP:
        return try_ftp(host, port, "anonymous", "", timeout)
    return try_redis(host, port, "", timeout)


# ---------------------------------------------------------------------------
# 字典
# ---------------------------------------------------------------------------
#: 常用默认密码（供 Redis / FTP 爆破，比 rockyou 小得多，命中率足够日常授权测试）
DEFAULT_PASSWORDS = (
    "", "root", "toor", "admin", "password", "123456", "12345678", "123456789",
    "1234567890", "123123", "1234", "111111", "000000", "admin123", "admin888",
    "root123", "qwerty", "abc123", "letmein", "redis", "password123",
    "P@ssw0rd", "passw0rd", "1q2w3e4r", "test", "guest", "oracle", "iloveyou",
)

#: 常见默认用户名（FTP 等）
DEFAULT_USERS = (
    "root", "admin", "administrator", "ftp", "anonymous", "user", "test",
    "guest", "oracle", "web", "www", "ftpuser",
)


def parse_list(text: str) -> list[str]:
    """解析手输的逗号 / 换行分隔列表。"""
    out: list[str] = []
    seen: set[str] = set()
    for token in (text or "").replace("\n", ",").replace("，", ",").split(","):
        token = token.strip()
        if not token or token in seen:
            continue
        seen.add(token)
        out.append(token)
    return out


@dataclass
class BruteStats:
    """爆破统计。"""

    total: int = 0
    done: int = 0
    hits: int = 0
    errors: int = 0
    started: float = field(default_factory=lambda: __import__("time").time())

    @property
    def elapsed(self) -> float:
        import time

        return max(0.0, time.time() - self.started)

    @property
    def speed(self) -> float:
        return self.done / self.elapsed if self.elapsed > 0 else 0.0


def brute(
    host: str,
    service: str,
    users: Sequence[str],
    passwords: Sequence[str],
    port: int | None = None,
    threads: int = DEFAULT_THREADS,
    timeout: float = DEFAULT_TIMEOUT,
    log: LogFn | None = None,
    on_hit: Callable[[dict[str, Any]], None] | None = None,
    stop: threading.Event | None = None,
) -> dict[str, Any]:
    """对目标做弱口令爆破（Redis / FTP），返回结构化汇总。

    参数
    ----
    host      目标 IP / 域名。
    service   服务类型：``redis`` / ``ftp``（``ssh`` 仅探测，不做爆破）。
    users     用户名列表（FTP 用；Redis 忽略）。
    passwords 密码列表。
    port      端口（缺省用服务默认端口）。
    threads   并发线程数。
    timeout   单次尝试超时（秒）。
    log       逐行日志回调。
    on_hit    每命中一组凭据立即回调（参数为单条结果 dict）。
    stop      置位后尽快停止。

    返回
    ----
    ``{"service","host","port","target","done","total","hits":[dict],...}``，
    ``hits`` 只保留 ``state == ok`` 的凭据。
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    emit = log or (lambda _m: None)
    stop = stop or threading.Event()
    svc = service if service in SVC_LABELS else SVC_REDIS
    port = port or DEFAULT_PORTS[svc]
    users = list(users) if users else list(DEFAULT_USERS)
    passwords = list(passwords) if passwords else list(DEFAULT_PASSWORDS)

    # 合规边界：公网 / 域名只做被动指纹，不做爆破
    target_kind = classify_target(host)
    if svc in (SVC_REDIS, SVC_FTP) and target_kind in (TARGET_INTERNET, TARGET_HOSTNAME):
        emit("[合规] 目标为公网 / 域名，仅做被动指纹，不进行爆破。")
        stats = {"done": 1, "total": 1, "hits": 0, "errors": 0}
        hits: list[dict[str, Any]] = []
        p = probe(host, svc, port, timeout)
        return {
            "service": svc, "host": host, "port": port,
            "target_kind": target_kind, "done": 1, "total": 1,
            "hits": hits, "probe": p.to_dict(), "stats": stats,
        }

    if svc == SVC_SSH:
        emit("[说明] SSH 仅做被动 banner 指纹，不爆破。")
        p = probe(host, svc, port, timeout)
        return {
            "service": svc, "host": host, "port": port,
            "target_kind": target_kind, "done": 1, "total": 1,
            "hits": [], "probe": p.to_dict(),
            "stats": {"done": 1, "total": 1, "hits": 0, "errors": 0},
        }

    # 组合尝试列表：Redis 无用户名，FTP 用 users × passwords
    if svc == SVC_REDIS:
        combos = [(None, pwd) for pwd in passwords]
    else:
        combos = [(u, pwd) for u in users for pwd in passwords]

    stats = {"done": 0, "total": len(combos), "hits": 0, "errors": 0}
    hits = []
    lock = threading.Lock()
    emit(f"[开始] {SVC_LABELS[svc]} {host}:{port}，共 {len(combos)} 组，{threads} 线程")

    def work(combo: tuple) -> dict[str, Any] | None:
        user, pwd = combo
        if stop.is_set():
            return None
        if svc == SVC_REDIS:
            r = try_redis(host, port, pwd, timeout)
        else:
            r = try_ftp(host, port, user or "", pwd, timeout)
        with lock:
            stats["done"] += 1
            if r.state == STATE_OK:
                stats["hits"] += 1
                hits.append(r.to_dict())
            elif r.state == STATE_ERROR:
                stats["errors"] += 1
        if r.state == STATE_OK and on_hit:
            on_hit(r.to_dict())
        return r.to_dict()

    with ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
        futures = [pool.submit(work, c) for c in combos]
        for _ in as_completed(futures):
            if stop.is_set():
                break

    emit(f"[完成] 命中 {stats['hits']} 组，错误 {stats['errors']} 次，"
         f"共试 {stats['done']}/{stats['total']} 组")
    return {
        "service": svc, "host": host, "port": port,
        "target_kind": target_kind, "done": stats["done"],
        "total": stats["total"], "hits": hits, "stats": stats,
    }


__all__ = [
    "DEFAULT_TIMEOUT",
    "DEFAULT_THREADS",
    "SVC_REDIS",
    "SVC_FTP",
    "SVC_SSH",
    "SVC_LABELS",
    "DEFAULT_PORTS",
    "STATE_OK",
    "STATE_DENIED",
    "STATE_ERROR",
    "WeakCredError",
    "AuthResult",
    "BruteStats",
    "DEFAULT_PASSWORDS",
    "DEFAULT_USERS",
    "parse_list",
    "try_redis",
    "try_ftp",
    "try_ssh",
    "probe",
    "brute",
]
