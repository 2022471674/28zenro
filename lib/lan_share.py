# -*- coding: utf-8 -*-
"""局域网文件共享：本机起 HTTP 服务，别人输 4 位密码进频道传文件。

设计要点
--------
- 服务端：``ShareServer`` 绑定 ``0.0.0.0:port``，用 ``ThreadingHTTPServer``
  跑一个极简的「频道」站点。每个频道一个 4 位数字密码，密码即房间口令；
  每次加入都要重新输密码，服务端签发一次性会话 token（浏览器走 Cookie，
  桌面客户端走 ``token`` 查询参数 / ``X-Token`` 头）。
- 浏览器端：``/`` 是登录页（选频道 + 输密码），``/ch`` 是频道页
  （文件表 + 上传，列表轮询自动刷新），``/f?name=`` 下载。
- 桌面端：``client_*`` 系列函数用 ``urllib`` 直连对端，支持流式上传 /
  下载并回报进度，方便界面挂进度条。
- 安全：文件名一律 ``sanitize_filename`` 清洗（杜绝路径穿越），密码用
  ``secrets.compare_digest`` 比较，同一 IP 连续输错 5 次锁定 5 分钟，
  会话 2 小时过期。

本模块不依赖任何 UI 库，界面层只负责调用与展示。
"""

from __future__ import annotations

import html
import json
import re
import secrets
import shutil
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
MAX_UPLOAD_BYTES = 4 * 1024 ** 3     # 单次上传体积上限（4 GB）
_FORM_LIMIT = 512 * 1024 * 1024      # 浏览器表单上传内存上限
SESSION_TTL = 2 * 3600.0             # 会话有效期
FAIL_WINDOW = 600.0                  # 密码错误统计窗口
FAIL_LIMIT = 5                       # 窗口内允许的错误次数
FAIL_LOCKOUT = 300.0                 # 超限后的锁定时长
COOKIE_NAME = "cn_share_token"
_CHUNK = 256 * 1024


class LanShareError(Exception):
    """局域网传输统一异常，由界面层捕获并展示。"""


class PasswordError(LanShareError):
    """频道名不存在或密码错误。"""


class LockedError(LanShareError):
    """密码错误次数过多，暂时锁定。"""


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------
def generate_password() -> str:
    """生成 4 位纯数字密码（含前导 0），如 ``0731``。"""
    return f"{secrets.randbelow(10000):04d}"


def lan_ips() -> list[str]:
    """枚举本机局域网 IPv4 地址（主网卡优先）；全失败时返回 127.0.0.1。"""
    ips: list[str] = []

    def add(ip: str) -> None:
        ip = (ip or "").strip()
        if not ip or ip.startswith("127.") or ip in ips:
            return
        ips.append(ip)

    # 连一个外部地址（不发包）拿到默认出口网卡地址
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect(("8.8.8.8", 80))
            add(probe.getsockname()[0])
        finally:
            probe.close()
    except OSError:
        pass

    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            add(info[4][0])
    except OSError:
        pass

    return ips or ["127.0.0.1"]


def sanitize_filename(name: str, default: str = "未命名文件") -> str:
    """取纯文件名并替换 Windows 非法字符，杜绝路径穿越。"""
    text = str(name or "").replace("\\", "/").split("/")[-1].strip()
    text = re.sub(r'[<>:"|?*\x00-\x1f]', "_", text).strip(" .")
    if not text:
        text = default
    if len(text) > 120:
        stem, dot, ext = text.rpartition(".")
        if dot and len(ext) <= 10:
            text = stem[:110] + "." + ext
        else:
            text = text[:120]
    return text


def format_size(size: int) -> str:
    """字节数格式化为可读大小（B / KB / MB / GB / TB）。"""
    value = float(max(0, int(size or 0)))
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            if unit == "B":
                return f"{int(value)} B"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def pretty_time(ts: float) -> str:
    """时间戳转 ``月-日 时:分`` 展示。"""
    try:
        return time.strftime("%m-%d %H:%M", time.localtime(ts))
    except (OverflowError, OSError, ValueError):
        return "-"


def _file_suffix(name: str) -> tuple[str, str]:
    """拆出 ``(主干, 扩展名含点)``；无扩展名 / 隐藏文件按整体为主干。"""
    stem, dot, ext = name.rpartition(".")
    if not stem or not dot:
        return name, ""
    return stem, "." + ext


def dedupe_name(directory, name: str) -> str:
    """目录内重名文件追加 `` (2)``、`` (3)`` …"""
    base = Path(directory)
    if not (base / name).exists():
        return name
    stem, ext = _file_suffix(name)
    for index in range(2, 10000):
        candidate = f"{stem} ({index}){ext}"
        if not (base / candidate).exists():
            return candidate
    return f"{stem} ({secrets.token_hex(3)}){ext}"


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------
@dataclass
class FileInfo:
    """频道内一个已登记文件。"""

    name: str
    path: Path
    size: int
    ts: float
    sender: str = "未知"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "size": self.size,
            "size_text": format_size(self.size),
            "ts": self.ts,
            "time": pretty_time(self.ts),
            "sender": self.sender,
        }


@dataclass
class Channel:
    """一个共享频道：4 位密码 + 所属目录 + 文件登记。"""

    name: str
    password: str
    directory: Path
    files: dict[str, FileInfo] = field(default_factory=dict)


@dataclass
class Session:
    """一次成功的加入会话（token -> 频道 + 来源）。"""

    token: str
    channel: str
    ip: str
    joined: float
    last_seen: float

    def to_dict(self) -> dict:
        return {
            "token": self.token,
            "channel": self.channel,
            "ip": self.ip,
            "joined": self.joined,
        }


class ShareState:
    """服务端可变状态：频道表、会话表、密码尝试记录（全部持锁访问）。"""

    def __init__(self, root) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.channels: dict[str, Channel] = {}
        self.sessions: dict[str, Session] = {}
        self._fails: dict[str, list[float]] = {}
        self._locked_until: dict[str, float] = {}

    # -- 频道 -------------------------------------------------------------
    def new_channel(self, name: str = "", password: str | None = None) -> Channel:
        """新建频道（自动去重频道名与密码），已运行时也可调用。"""
        with self._lock:
            channel_name = str(name or "").strip() or self._free_channel_name_locked()
            if channel_name in self.channels:
                raise LanShareError(f"频道「{channel_name}」已存在")
            if len(channel_name) > 40:
                raise LanShareError("频道名不能超过 40 个字符")

            if password is not None and str(password) != "":
                text = str(password).strip()
                if not re.fullmatch(r"\d{4}", text):
                    raise LanShareError("密码必须为 4 位数字")
                if any(c.password == text for c in self.channels.values()):
                    raise LanShareError(f"密码 {text} 已被其他频道占用")
                pwd = text
            else:
                pwd = self._unique_password_locked()

            directory = self._channel_dir_locked(channel_name)
            directory.mkdir(parents=True, exist_ok=True)
            channel = Channel(name=channel_name, password=pwd, directory=directory)
            self.channels[channel_name] = channel
            return channel

    def _free_channel_name_locked(self) -> str:
        for index in range(1, 10000):
            candidate = "频道" if index == 1 else f"频道 {index}"
            if candidate not in self.channels:
                return candidate
        return f"频道 {secrets.token_hex(2)}"

    def _unique_password_locked(self) -> str:
        used = {c.password for c in self.channels.values()}
        for _ in range(2000):
            pwd = generate_password()
            if pwd not in used:
                return pwd
        raise LanShareError("可用密码已耗尽，请先删除部分频道")

    def _channel_dir_locked(self, channel_name: str) -> Path:
        """为频道分配落盘目录 ``root/<安全后的频道名>``。

        目录名即磁盘上的频道标识（重启重扫按它还原频道名）；若现役频道
        已占用该目录名则换号，只与孤儿目录同名时复用。
        """
        base = sanitize_filename(channel_name, "频道")
        used = {c.directory.name for c in self.channels.values()}
        candidate = base
        index = 2
        while candidate in used:
            candidate = f"{base} ({index})"
            index += 1
        return self.root / candidate

    def channel_names(self) -> list[str]:
        with self._lock:
            return sorted(self.channels)

    def channel(self, name: str) -> Channel:
        """按名取频道；不存在抛 :class:`LanShareError`。"""
        with self._lock:
            channel = self.channels.get(str(name or "").strip())
            if channel is None:
                raise LanShareError("频道已不存在，请重新获取频道列表")
            return channel

    def drop_channel(self, name: str) -> None:
        """删除频道：会话全部失效；连同落盘目录一起删除。"""
        with self._lock:
            channel = self.channels.pop(str(name or "").strip(), None)
            if channel is None:
                raise LanShareError("频道不存在")
            for token in [t for t, s in self.sessions.items() if s.channel == channel.name]:
                self.sessions.pop(token, None)
            directory = channel.directory
        shutil.rmtree(directory, ignore_errors=True)

    def regenerate_password(self, name: str) -> str:
        """重新生成某频道的 4 位密码（旧会员不受影响，新加入需新密码）。"""
        with self._lock:
            channel = self.channels.get(str(name or "").strip())
            if channel is None:
                raise LanShareError("频道不存在")
            used = {c.password for c in self.channels.values() if c is not channel}
            for _ in range(2000):
                pwd = generate_password()
                if pwd not in used:
                    channel.password = pwd
                    return pwd
            raise LanShareError("可用密码已耗尽")

    def overview(self) -> list[dict]:
        """给界面的频道概览：名称 / 密码 / 在线成员数 / 文件数。"""
        with self._lock:
            result = []
            for channel in self.channels.values():
                members = sum(1 for s in self.sessions.values()
                              if s.channel == channel.name)
                result.append({
                    "name": channel.name,
                    "password": channel.password,
                    "members": members,
                    "files": len(channel.files),
                    "directory": str(channel.directory),
                })
            return sorted(result, key=lambda c: c["name"])

    # -- 文件 -------------------------------------------------------------
    def files_of(self, name: str) -> list[dict]:
        """某频道的文件清单（按上传时间倒序），统一样式给界面 / API。"""
        with self._lock:
            channel = self.channels.get(str(name or "").strip())
            if channel is None:
                raise LanShareError("频道已不存在，请重新获取频道列表")
            items = [info.to_dict() for info in channel.files.values()]
        return sorted(items, key=lambda i: i["ts"], reverse=True)

    def members_of(self, name: str) -> list[dict]:
        """某频道现役会话（按加入时间升序）。"""
        with self._lock:
            return self._members_locked(name)

    def _members_locked(self, name: str) -> list[dict]:
        now = time.time()
        rows = [s.to_dict() for s in self.sessions.values()
                if s.channel == name and now - s.last_seen < SESSION_TTL]
        return sorted(rows, key=lambda s: s["joined"])

    def add_file_bytes(self, channel_name: str, filename: str, data: bytes,
                       sender: str = "未知") -> FileInfo:
        """把内存中的字节登记为新文件并写入频道目录。"""
        name = sanitize_filename(filename)
        with self._lock:
            channel = self.channel(channel_name)
            final = dedupe_name(channel.directory, name)
            path = channel.directory / final
            info = FileInfo(name=final, path=path, size=len(data),
                            ts=time.time(), sender=sender or "未知")
            channel.files[final] = info
        try:
            path.write_bytes(data)
        except OSError as exc:
            with self._lock:
                channel.files.pop(final, None)
            raise LanShareError(f"写入频道目录失败：{exc}") from exc
        return info

    def add_file_path(self, channel_name: str, src, sender: str = "未知",
                      report=None) -> FileInfo:
        """把本机文件复制进频道目录（流式复制，不占满内存）。"""
        source = Path(src)
        if not source.is_file():
            raise LanShareError(f"待发送文件不存在：{source}")
        total = source.stat().st_size
        name = sanitize_filename(source.name)
        with self._lock:
            channel = self.channel(channel_name)
            final = dedupe_name(channel.directory, name)
            path = channel.directory / final
            info = FileInfo(name=final, path=path, size=total,
                            ts=time.time(), sender=sender or "未知")
            channel.files[final] = info

        done = 0
        try:
            with open(source, "rb") as fin, open(path, "wb") as fout:
                while True:
                    chunk = fin.read(_CHUNK)
                    if not chunk:
                        break
                    fout.write(chunk)
                    done += len(chunk)
                    if report is not None:
                        report(done, total)
        except OSError as exc:
            with self._lock:
                channel.files.pop(final, None)
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
            raise LanShareError(f"复制文件失败：{exc}") from exc
        return info

    def adopt_temp(self, channel_name: str, filename: str, temp_path,
                   sender: str = "未知") -> FileInfo:
        """把已落盘的临时文件改名登记进频道（服务端流式上传用）。"""
        temp = Path(temp_path)
        name = sanitize_filename(filename)
        with self._lock:
            channel = self.channel(channel_name)
            final = dedupe_name(channel.directory, name)
            target = channel.directory / final
            info = FileInfo(name=final, path=target, size=temp.stat().st_size,
                            ts=time.time(), sender=sender or "未知")
            channel.files[final] = info
        try:
            temp.replace(target)
        except OSError as exc:
            with self._lock:
                channel.files.pop(final, None)
            try:
                temp.unlink(missing_ok=True)
            except OSError:
                pass
            raise LanShareError(f"写入频道目录失败：{exc}") from exc
        return info

    def file_of(self, channel_name: str, filename: str) -> FileInfo | None:
        """按 (频道, 文件名) 取登记文件；不存在返回 None。"""
        with self._lock:
            channel = self.channels.get(str(channel_name or "").strip())
            if channel is None:
                return None
            return channel.files.get(str(filename or ""))

    def remove_file(self, channel_name: str, filename: str) -> None:
        """从频道移除一个文件并删除磁盘上的实体（宿主界面用）。"""
        with self._lock:
            channel = self.channels.get(str(channel_name or "").strip())
            if channel is None:
                raise LanShareError("频道不存在")
            info = channel.files.get(str(filename or ""))
            if info is None:
                raise LanShareError("文件不存在")
        try:
            info.path.unlink(missing_ok=True)
        except OSError as exc:
            raise LanShareError(f"删除文件失败（可能正在被下载）：{exc}") from exc
        with self._lock:
            channel.files.pop(info.name, None)

    # -- 会话 -------------------------------------------------------------
    def try_join(self, channel_name: str, password: str, ip: str) -> Session:
        """校验「频道 + 密码」，成功创建会话；失败抛对应异常并记录。"""
        self.sweep()
        ip = str(ip or "未知").replace("::ffff:", "")
        now = time.time()
        name = str(channel_name or "").strip()
        pwd = str(password or "").strip()

        with self._lock:
            self._throttle_locked(now, ip)

            if not name:
                # 单频道场景允许不选频道：直接落到唯一频道
                if len(self.channels) == 1:
                    name = next(iter(self.channels))
                elif not self.channels:
                    raise PasswordError("服务端还没有创建频道")
                else:
                    raise PasswordError("请先选择频道：" + " / ".join(sorted(self.channels)))

            channel = self.channels.get(name)
            if channel is None:
                self._fail_locked(now, ip)
                raise PasswordError("频道不存在或密码错误")

            if not pwd:
                raise PasswordError("请输入 4 位频道密码")
            if not secrets.compare_digest(channel.password, pwd):
                left = self._fail_locked(now, ip)
                if left <= 0:
                    raise LockedError(
                        f"密码错误次数过多，已锁定约 {int(FAIL_LOCKOUT / 60)} 分钟")
                raise PasswordError(f"密码错误，还可尝试 {left} 次")

            self._fails.pop(ip, None)
            self._locked_until.pop(ip, None)
            # 同一来源重复加入同一频道时，旧会话直接作废，避免在线人数虚高
            for old_token in [t for t, s in self.sessions.items()
                              if s.ip == ip and s.channel == channel.name]:
                self.sessions.pop(old_token, None)
            token = secrets.token_urlsafe(24)
            session = Session(token=token, channel=channel.name, ip=ip,
                              joined=now, last_seen=now)
            self.sessions[token] = session
            return session

    def _throttle_locked(self, now: float, ip: str) -> None:
        until = self._locked_until.get(ip, 0.0)
        if until > now:
            raise LockedError(
                f"密码错误次数过多，请 {max(1, int((until - now) / 60) + 1)} 分钟后再试")

    def _fail_locked(self, now: float, ip: str) -> int:
        """记录一次失败并返回剩余可尝试次数（<=0 表示已锁定）。"""
        stamps = [t for t in self._fails.get(ip, []) if now - t < FAIL_WINDOW]
        stamps.append(now)
        self._fails[ip] = stamps
        if len(stamps) >= FAIL_LIMIT:
            self._locked_until[ip] = now + FAIL_LOCKOUT
            self._fails[ip] = []
            return 0
        return FAIL_LIMIT - len(stamps)

    def session_by_token(self, token: str) -> Session | None:
        """取会话；顺带刷新 ``last_seen``。过期 / 无效返回 None。"""
        token = str(token or "").strip()
        if not token:
            return None
        now = time.time()
        with self._lock:
            session = self.sessions.get(token)
            if session is None:
                return None
            if now - session.last_seen > SESSION_TTL:
                self.sessions.pop(token, None)
                return None
            session.last_seen = now
            return session

    def leave(self, token: str) -> None:
        """主动退出会话。"""
        with self._lock:
            self.sessions.pop(str(token or "").strip(), None)

    def sweep(self) -> None:
        """惰性清理：过期会话与超窗的失败记录。"""
        now = time.time()
        with self._lock:
            for token in [t for t, s in self.sessions.items()
                          if now - s.last_seen > SESSION_TTL]:
                self.sessions.pop(token, None)
            for ip in [k for k, stamps in self._fails.items()
                       if not stamps or now - stamps[-1] > FAIL_WINDOW]:
                self._fails.pop(ip, None)
            for ip in [k for k, until in self._locked_until.items() if until <= now]:
                self._locked_until.pop(ip, None)

    # -- 重启还原 ---------------------------------------------------------
    def load_from_disk(self, sender: str = "本机") -> int:
        """按 root 下的频道目录重建频道表（密码重新生成），返回频道数。"""
        try:
            directories = [p for p in self.root.iterdir() if p.is_dir()]
        except OSError:
            return 0
        count = 0
        for directory in sorted(directories):
            if directory.name.startswith("."):
                continue
            with self._lock:
                self._create_existing_locked(directory.name, sender)
            count += 1
        return count

    def _create_existing_locked(self, directory_name: str, sender: str) -> None:
        name = directory_name
        index = 2
        while name in self.channels:
            name = f"{directory_name} ({index})"
            index += 1
        channel = Channel(name=name, password=self._unique_password_locked(),
                          directory=self.root / directory_name)
        for path in sorted(channel.directory.iterdir()):
            if not path.is_file() or path.name.startswith("."):
                continue
            try:
                stat = path.stat()
            except OSError:
                continue
            channel.files[path.name] = FileInfo(
                name=path.name, path=path, size=stat.st_size,
                ts=stat.st_mtime, sender=sender)
        self.channels[name] = channel


# ---------------------------------------------------------------------------
# 浏览器页面
# ---------------------------------------------------------------------------
def _parse_multipart(content_type: str, body: bytes) -> list[tuple[str, bytes]]:
    """极简 multipart 解析，返回 ``[(文件名, 内容), ...]``（跳过非文件字段）。"""
    match = re.search(r'boundary="?([^";]+)"?', content_type or "")
    if not match:
        raise LanShareError("请求缺少 multipart boundary")
    boundary = ("--" + match.group(1)).encode("latin-1")

    files: list[tuple[str, bytes]] = []
    for chunk in body.split(boundary):
        if not chunk or chunk in (b"--", b"--\r\n", b"\r\n"):
            continue
        chunk = chunk.lstrip(b"\r\n")
        if chunk.endswith(b"--\r\n"):
            chunk = chunk[:-4]
        elif chunk.endswith(b"--"):
            chunk = chunk[:-2]
        if chunk.endswith(b"\r\n"):
            chunk = chunk[:-2]
        head, sep, data = chunk.partition(b"\r\n\r\n")
        if not sep:
            continue
        header_text = head.decode("latin-1", "replace")
        found = re.search(r'filename="([^"]*)"', header_text)
        if not found:
            continue
        raw = found.group(1)
        if not raw:
            continue
        name = raw
        for codec in ("utf-8", "gbk"):
            try:
                name = raw.encode("latin-1").decode(codec)
                break
            except UnicodeError:
                continue
        files.append((name, data))
    return files


_PAGE_CSS = """
:root{--bg:#f6f8fa;--card:#ffffff;--border:#d0d7de;--text:#1f2328;
--muted:#59636e;--accent:#0969da;--danger:#d1242f;--ok:#1a7f37;--soft:#eaeef2}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--card:#161b22;
--border:#30363d;--text:#e6edf3;--muted:#8b949e;--accent:#58a6ff;
--danger:#f85149;--ok:#3fb950;--soft:#21262d}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.65 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif}
.wrap{max-width:760px;margin:0 auto;padding:28px 18px 48px}
h1{font-size:22px;margin:0 0 4px}
h2{font-size:15px;margin:0 0 12px;color:var(--muted);font-weight:600}
.sub{color:var(--muted);font-size:13px;margin:0 0 16px}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;
padding:18px;margin-bottom:16px}
label{display:block;font-size:13px;color:var(--muted);margin:12px 0 6px}
input[type=text],input[type=password],select{width:100%;padding:9px 11px;
border:1px solid var(--border);border-radius:6px;background:var(--bg);
color:var(--text);font-size:15px}
input[type=file]{width:100%;padding:8px 0;color:var(--muted)}
button{padding:9px 16px;border-radius:6px;border:1px solid var(--accent);
background:var(--accent);color:#fff;font-size:14px;font-weight:600;cursor:pointer}
button:disabled{opacity:.55;cursor:default}
button.ghost{background:transparent;color:var(--text);border-color:var(--border);
font-weight:400}
table{width:100%;border-collapse:collapse;font-size:14px}
th{text-align:left;font-weight:600;color:var(--muted);font-size:12px;
border-bottom:1px solid var(--border);padding:6px 8px}
td{padding:8px;border-bottom:1px solid var(--border);vertical-align:top}
tr:last-child td{border-bottom:0}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
.err{background:rgba(209,36,47,.1);border:1px solid var(--danger);color:var(--danger);
padding:10px 12px;border-radius:6px;font-size:13px;margin-bottom:14px}
.ok{color:var(--ok);font-size:13px}
.empty{color:var(--muted);font-size:13px;margin:6px 0}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:12px}
.bar{height:5px;background:var(--soft);border-radius:3px;overflow:hidden;margin-top:10px}
.bar>i{display:block;height:100%;width:0;background:var(--accent);
transition:width .2s}
.name{word-break:break-all}
"""

# 频道页脚本：拦截表单提交改为流式上传（带进度），并轮询刷新文件表。
_PAGE_JS = """
(function(){
  var form=document.getElementById('upform');
  var picker=document.getElementById('picker');
  var tip=document.getElementById('uptip');
  var bar=document.getElementById('bar');
  var btn=document.getElementById('upbtn');
  if(form&&picker){
    form.addEventListener('submit',function(ev){
      if(!window.XMLHttpRequest||!picker.files||!picker.files.length)return;
      ev.preventDefault();
      var files=Array.prototype.slice.call(picker.files);
      btn.disabled=true;
      var idx=0;
      function next(){
        if(idx>=files.length){
          tip.textContent='全部上传完成';
          bar.style.width='100%';
          btn.disabled=false;
          picker.value='';
          refresh();
          setTimeout(function(){bar.style.width='0';tip.textContent='';},1200);
          return;
        }
        var f=files[idx];
        var xhr=new XMLHttpRequest();
        xhr.open('POST','/api/upload?token='+encodeURIComponent(window.SHARE_TOKEN),true);
        xhr.setRequestHeader('X-Filename',encodeURIComponent(f.name));
        xhr.setRequestHeader('Content-Type','application/octet-stream');
        xhr.upload.onprogress=function(e){
          if(!e.lengthComputable)return;
          var base=idx/files.length;
          var part=(e.loaded/e.total)/files.length;
          bar.style.width=Math.round((base+part)*100)+'%';
          tip.textContent='正在上传 '+f.name+'（'+(idx+1)+'/'+files.length+'）';
        };
        xhr.onload=function(){
          if(xhr.status!==200){
            var msg='上传失败：HTTP '+xhr.status;
            try{msg=JSON.parse(xhr.responseText).error||msg;}catch(_){}
            tip.textContent=msg;btn.disabled=false;return;
          }
          idx++;next();
        };
        xhr.onerror=function(){tip.textContent='上传失败：网络错误';btn.disabled=false;};
        xhr.send(f);
      }
      next();
    });
  }
  function refresh(){
    fetch('/update',{cache:'no-store'}).then(function(r){return r.json();})
      .then(function(data){
        if(!data||!data.ok)return;
        var host=document.getElementById('updatable');
        var members=document.getElementById('members');
        if(host&&data.html!==undefined)host.innerHTML=data.html;
        if(members&&data.members!==undefined)members.textContent=data.members;
      }).catch(function(){});
  }
  setInterval(refresh,4000);
})();
"""


def _page(title: str, body: str) -> str:
    """外壳：统一的 head / 样式。"""
    return (
        "<!doctype html><html lang='zh'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{html.escape(title)}</title><style>{_PAGE_CSS}</style></head>"
        f"<body>{body}</body></html>"
    )


def _page_login(service_name: str, channel_names: list[str], error: str = "") -> str:
    """浏览器登录页：选频道 + 4 位密码。"""
    if channel_names:
        options = "".join(
            f"<option value='{html.escape(n, quote=True)}'>{html.escape(n)}</option>"
            for n in channel_names)
        select = f"<select name='channel'>{options}</select>"
    else:
        select = "<select disabled><option>（暂无频道）</option></select>"

    notice = ""
    if error:
        notice = f"<div class='err'>服务方提示：{html.escape(error)}</div>"

    body = f"""
<div class='wrap'>
  <div class='card'>
    <h1>{html.escape(service_name)}</h1>
    <p class='sub'>选择频道并输入 4 位密码即可加入（同一局域网内可用）</p>
    {notice}
    <form action='/join' method='post'>
      <label>频道</label>{select}
      <label>4 位密码</label>
      <input type='password' name='password' inputmode='numeric' maxlength='4'
             pattern='\\d{{4}}' placeholder='····' required autocomplete='off'>
      <div class='row'><button type='submit'>加入频道</button></div>
    </form>
  </div>
  <p class='sub'>密码由共享方在 28zenro 的「局域网传输」页提供，每次加入都需重新输入。</p>
</div>
"""
    return _page(f"{service_name} · 加入频道", body)


def _files_payload(channel: Channel, member_count: int) -> str:
    """成员数 + 文件表 HTML：频道页首屏与 /update 轮询片段共用。"""
    if channel.files:
        rows = []
        for info in sorted(channel.files.values(), key=lambda f: f.ts, reverse=True):
            quote = urllib.parse.quote(info.name)
            rows.append(
                "<tr>"
                f"<td class='name'>{html.escape(info.name)}</td>"
                f"<td style='white-space:nowrap'>{format_size(info.size)}</td>"
                f"<td>{html.escape(info.sender)}</td>"
                f"<td style='white-space:nowrap'>{pretty_time(info.ts)}</td>"
                f"<td><a href='/f?name={quote}'>下载</a></td>"
                "</tr>")
        table = ("<table><tr><th>文件</th><th>大小</th><th>来自</th>"
                 "<th>时间</th><th></th></tr>" + "".join(rows) + "</table>")
    else:
        table = "<p class='empty'>频道里还没有文件，用下方表单上传第一个。</p>"

    members = ("（还没有人加入）" if member_count <= 0
               else f"已加入 {member_count} 人")
    return f"{table}<p class='sub'>{members}</p>"


def _page_channel(service_name: str, channel: Channel, member_count: int,
                  token: str) -> str:
    """浏览器频道页：文件列表 + 上传表单（列表每 4 秒自动刷新）。"""
    body = f"""
<div class='wrap'>
  <div class='card'>
    <h1>{html.escape(channel.name)}</h1>
    <p class='sub'>{html.escape(service_name)} ·
      <span id='members'>{member_count}</span> 人在线 ·
      <a href='/leave'>切换频道</a></p>
    <div id='updatable'>{_files_payload(channel, member_count)}</div>
  </div>
  <div class='card'>
    <h2>上传文件到该频道</h2>
    <form id='upform' action='/upload' method='post'
          enctype='multipart/form-data'>
      <input type='file' name='file' id='picker' multiple required>
      <div class='row'>
        <button type='submit' id='upbtn'>上传到该频道</button>
        <span class='sub' id='uptip'></span>
      </div>
    </form>
    <div class='bar'><i id='bar'></i></div>
  </div>
  <p class='sub'>提示：页面开着就会自动刷新文件列表，别人上传的文件几秒内出现。</p>
</div>
<script>window.SHARE_TOKEN={json.dumps(token)};</script>
<script>{_PAGE_JS}</script>
"""
    return _page(f"{channel.name} · {service_name}", body)


# ---------------------------------------------------------------------------
# HTTP 服务
# ---------------------------------------------------------------------------
class _ShareHTTPServer(ThreadingHTTPServer):
    """在标准 HTTP 载体上挂一个 ``share`` 引用，指回 :class:`ShareServer`。"""

    daemon_threads = True
    allow_reuse_address = True
    share = None  # type: ignore[assignment]


class ShareRequestHandler(BaseHTTPRequestHandler):
    """ShareServer 的请求路由。全部状态经 ``self.server``（ShareServer）。"""

    server_version = "28zenro-LanShare/1.0"
    protocol_version = "HTTP/1.0"

    # -- 基础 -------------------------------------------------------------
    @property
    def share(self) -> "ShareServer":
        return self.server.share  # type: ignore[attr-defined]

    @property
    def state(self) -> ShareState:
        return self.share.state

    def log_message(self, fmt: str, *args) -> None:  # noqa: D102
        # 默认 stderr 输出对 GUI 不友好，改为静默（重要事件走 on_event）
        return

    def client_ip(self) -> str:
        ip = self.client_address[0] if self.client_address else "未知"
        return str(ip).replace("::ffff:", "")

    def _query(self) -> dict:
        parsed = urllib.parse.urlparse(self.path)
        return {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}

    def _path_only(self) -> str:
        path = urllib.parse.urlparse(self.path).path
        return path.rstrip("/") or "/"

    def _read_body(self, limit: int) -> bytes:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0:
            return b""
        if length > limit:
            raise LanShareError(f"请求体过大（上限 {format_size(limit)}）")
        chunks = []
        remaining = length
        while remaining > 0:
            chunk = self.rfile.read(min(_CHUNK, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _cookie_token(self) -> str:
        raw = self.headers.get("Cookie") or ""
        for part in raw.split(";"):
            key, _, value = part.strip().partition("=")
            if key == COOKIE_NAME:
                return value.strip()
        return ""

    def _api_token(self) -> str:
        """API 请求取会话（查询参数 / X-Token 头优先，兼容 Cookie）。"""
        token = (self._query().get("token")
                 or self.headers.get("X-Token")
                 or self._cookie_token())
        return str(token or "").strip()

    # -- 响应 -------------------------------------------------------------
    def _send(self, code: int, content_type: str, body: bytes,
              extra: dict | None = None) -> None:
        try:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _send_json(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send(status, "application/json; charset=utf-8", body)

    def _send_html(self, text: str, status: int = 200,
                   extra: dict | None = None) -> None:
        self._send(status, "text/html; charset=utf-8",
                   text.encode("utf-8"), extra)

    def _redirect(self, location: str, extra: dict | None = None) -> None:
        headers = {"Location": location}
        headers.update(extra or {})
        self._send(302, "text/html; charset=utf-8",
                   f"<a href='{html.escape(location)}'>跳转</a>".encode("utf-8"),
                   headers)

    def _client_error_page(self, message: str, status: int = 400) -> None:
        body = (f"<div class='wrap'><div class='card'><h1>无法继续</h1>"
                f"<div class='err'>{html.escape(message)}</div>"
                f"<p class='sub'><a href='/'>返回登录页</a></p></div></div>")
        self._send_html(_page("无法继续", body), status)

    # -- 下载 -------------------------------------------------------------
    def _download(self) -> None:
        """按 (会话频道, 文件名) 流式回送文件（浏览器 / API 同源逻辑）。"""
        token = self._api_token()
        session = self.state.session_by_token(token)
        if session is None:
            if self._path_only().startswith("/api/"):
                self._send_json(
                    {"ok": False, "error": "会话已失效，请重新输入密码加入",
                     "code": "session_invalid"}, 401)
            else:
                self._redirect("/?msg=" + urllib.parse.quote("请先输入密码加入频道"))
            return

        name = self._query().get("name", "")
        info = self.state.file_of(session.channel, name)
        if info is None:
            if self._path_only().startswith("/api/"):
                self._send_json({"ok": False, "error": "文件不存在或已被移除"}, 404)
            else:
                self._client_error_page("文件不存在或已被移除", 404)
            return

        try:
            size = info.path.stat().st_size
            handle = open(info.path, "rb")
        except OSError:
            self._send_json({"ok": False, "error": "文件在磁盘上已缺失"}, 410)
            return

        quoted = urllib.parse.quote(info.name)
        ascii_name = re.sub(r"[^\x20-\x7e]", "_", info.name).replace('"', "_")
        disposition = (f"attachment; filename=\"{ascii_name}\"; "
                       f"filename*=UTF-8''{quoted}")
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(size))
            self.send_header("Content-Disposition", disposition)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            with handle:
                while True:
                    chunk = handle.read(_CHUNK)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            try:
                handle.close()
            except OSError:
                pass
        self.share.notify("downloaded", channel=session.channel,
                          name=info.name, ip=session.ip)

    # -- GET --------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802  Qt/BaseHTTPRequestHandler 命名
        path = self._path_only()
        try:
            if path in ("/", "/index.html"):
                self._get_index()
            elif path == "/ch":
                self._get_channel_page()
            elif path == "/update":
                self._get_update()
            elif path == "/leave":
                # 频道页里「切换频道」是普通链接（GET），与 POST /leave 同义
                self._do_leave()
            elif path == "/f":
                self._download()
            elif path == "/favicon.ico":
                self._send(204, "image/x-icon", b"")
            elif path == "/api/ping":
                self._get_ping()
            elif path == "/api/files":
                self._get_files()
            elif path == "/api/download":
                self._download()
            else:
                self._client_error_page("接口不存在", 404)
        except LanShareError as exc:
            self._send_json({"ok": False, "error": str(exc)}, 400)
        except Exception as exc:  # noqa: BLE001  服务端兜底，避免线程崩掉
            self._send_json({"ok": False, "error": f"服务器内部错误：{exc}"}, 500)

    def _get_index(self) -> None:
        session = self.state.session_by_token(self._cookie_token())
        if session is not None:
            self._redirect("/ch")
            return
        message = self._query().get("msg", "")
        self._send_html(_page_login(
            self.share.service_name, self.state.channel_names(), message))

    def _get_channel_page(self) -> None:
        session = self.state.session_by_token(self._cookie_token())
        if session is None:
            self._redirect("/?msg=" + urllib.parse.quote("请先输入密码加入频道"))
            return
        try:
            channel = self.state.channel(session.channel)
        except LanShareError:
            self._redirect("/?msg=" + urllib.parse.quote("频道已被移除，请重新加入"))
            return
        members = len(self.state.members_of(channel.name))
        self._send_html(_page_channel(
            self.share.service_name, channel, members, session.token))

    def _get_update(self) -> None:
        """浏览器频道页的轮询片段：只回「成员数 + 文件表」一小段。"""
        session = self.state.session_by_token(self._api_token())
        if session is None:
            self._send_json({"ok": False, "error": "会话已失效"}, 401)
            return
        try:
            channel = self.state.channel(session.channel)
        except LanShareError as exc:
            self._send_json({"ok": False, "error": str(exc)}, 404)
            return
        members = len(self.state.members_of(channel.name))
        self._send_json({"ok": True, "members": members,
                         "html": _files_payload(channel, members)})

    def _get_ping(self) -> None:
        self._send_json({"ok": True, "name": self.share.service_name,
                         "channels": self.state.channel_names()})

    def _get_files(self) -> None:
        session = self.state.session_by_token(self._api_token())
        if session is None:
            self._send_json({"ok": False, "error": "会话已失效，请重新输入密码加入",
                             "code": "session_invalid"}, 401)
            return
        files = self.state.files_of(session.channel)
        self._send_json({"ok": True, "channel": session.channel,
                         "members": len(self.state.members_of(session.channel)),
                         "files": files})

    # -- POST -------------------------------------------------------------
    def do_POST(self) -> None:  # noqa: N802
        path = self._path_only()
        try:
            if path == "/join":
                self._post_join()
            elif path == "/leave":
                self._post_leave()
            elif path == "/upload":
                self._post_upload_browser()
            elif path == "/api/join":
                self._post_api_join()
            elif path == "/api/upload":
                self._post_upload_api()
            elif path == "/api/leave":
                self._post_api_leave()
            else:
                self._send_json({"ok": False, "error": "接口不存在"}, 404)
        except LockedError as exc:
            self._send_json({"ok": False, "error": str(exc), "code": "locked"}, 429)
        except PasswordError as exc:
            self._send_json({"ok": False, "error": str(exc),
                             "code": "password_wrong"}, 403)
        except LanShareError as exc:
            self._send_json({"ok": False, "error": str(exc)}, 400)
        except Exception as exc:  # noqa: BLE001
            self._send_json({"ok": False, "error": f"服务器内部错误：{exc}"}, 500)

    def _post_join(self) -> None:
        raw = self._read_body(_FORM_LIMIT).decode("utf-8", "replace")
        form = {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}
        channel = (form.get("channel") or "").strip()
        password = (form.get("password") or "").strip()
        try:
            session = self.state.try_join(channel, password, self.client_ip())
        except LanShareError as exc:
            self._send_html(_page_login(
                self.share.service_name, self.state.channel_names(), str(exc)),
                403)
            return
        cookie = (f"{COOKIE_NAME}={session.token}; Path=/; "
                  f"Max-Age={int(SESSION_TTL)}; HttpOnly; SameSite=Lax")
        self._redirect("/ch", {"Set-Cookie": cookie})
        self.share.notify("join_ok", channel=session.channel, ip=session.ip)

    def _post_leave(self) -> None:
        self._do_leave()

    def _do_leave(self) -> None:
        """退出频道：作废会话并清掉 Cookie（GET / POST 共用）。"""
        token = self._cookie_token()
        session = self.state.session_by_token(token)
        if session is not None:
            self.state.leave(token)
            self.share.notify("leave", channel=session.channel, ip=session.ip)
        self._redirect("/", {"Set-Cookie": f"{COOKIE_NAME}=; Path=/; Max-Age=0"})

    def _post_upload_browser(self) -> None:
        session = self.state.session_by_token(self._cookie_token())
        if session is None:
            self._redirect("/?msg=" + urllib.parse.quote("请先输入密码加入频道"))
            return
        body = self._read_body(min(MAX_UPLOAD_BYTES, _FORM_LIMIT))
        files = _parse_multipart(self.headers.get("Content-Type", ""), body)
        if not files:
            self._client_error_page("没有接收到文件", 400)
            return
        names = []
        size = 0
        for filename, data in files:
            info = self.state.add_file_bytes(
                session.channel, filename, data, sender=session.ip)
            names.append(info.name)
            size += info.size
        self.share.notify("upload_ok", channel=session.channel, files=names,
                          sender=session.ip, size=size)
        self._redirect("/ch")

    def _post_api_join(self) -> None:
        raw = self._read_body(64 * 1024)
        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
        except (UnicodeError, json.JSONDecodeError):
            raise LanShareError("请求体不是合法 JSON")
        if not isinstance(payload, dict):
            raise LanShareError("请求体不是合法 JSON")
        session = self.state.try_join(
            str(payload.get("channel") or ""),
            str(payload.get("password") or ""),
            self.client_ip(),
        )
        members = len(self.state.members_of(session.channel))
        self._send_json({"ok": True, "token": session.token,
                         "channel": session.channel, "members": members,
                         "name": self.share.service_name})
        self.share.notify("join_ok", channel=session.channel, ip=session.ip)

    def _post_upload_api(self) -> None:
        session = self.state.session_by_token(self._api_token())
        if session is None:
            self._send_json({"ok": False, "error": "会话已失效，请重新输入密码加入",
                             "code": "session_invalid"}, 401)
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0:
            self._send_json({"ok": False, "error": "没有接收到文件"}, 400)
            return
        if length > self.share.max_upload:
            self._send_json({"ok": False, "error":
                             f"文件过大（上限 {format_size(self.share.max_upload)}）"},
                            413)
            return

        raw_name = self.headers.get("X-Filename") or "未命名文件"
        try:
            filename = urllib.parse.unquote(raw_name)
        except UnicodeError:
            filename = raw_name

        channel = self.state.channel(session.channel)
        temp = channel.directory / f".upload-{secrets.token_hex(8)}.part"
        remaining = length
        try:
            with open(temp, "wb") as handle:
                while remaining > 0:
                    chunk = self.rfile.read(min(_CHUNK, remaining))
                    if not chunk:
                        break
                    handle.write(chunk)
                    remaining -= len(chunk)
            if remaining > 0:
                raise LanShareError("连接中断，文件未传完")
            info = self.state.adopt_temp(
                session.channel, filename, temp, sender=session.ip)
        except OSError as exc:
            temp.unlink(missing_ok=True)
            raise LanShareError(f"接收文件失败：{exc}") from exc
        except LanShareError:
            temp.unlink(missing_ok=True)
            raise

        self._send_json({"ok": True, "file": info.to_dict()})
        self.share.notify("upload_ok", channel=session.channel,
                          files=[info.name], sender=session.ip,
                          size=info.size)

    def _post_api_leave(self) -> None:
        token = self._api_token()
        session = self.state.session_by_token(token)
        if session is not None:
            self.state.leave(token)
            self.share.notify("leave", channel=session.channel, ip=session.ip)
        self._send_json({"ok": True})


class ShareServer:
    """局域网共享服务：绑定端口起 ``ThreadingHTTPServer`` 后台线程。"""

    def __init__(self, service_name: str = "28zenro 共享", port: int = 0,
                 root=None, on_event=None, max_upload: int = MAX_UPLOAD_BYTES) -> None:
        self.service_name = str(service_name or "").strip() or "28zenro 共享"
        self._want_port = int(port or 0)
        self.state = ShareState(Path(root) if root else Path("output") / "lan_share")
        self.max_upload = int(max_upload)
        self._on_event = on_event
        self._httpd: _ShareHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._actual_port = 0

    # -- 状态 -------------------------------------------------------------
    @property
    def running(self) -> bool:
        return self._httpd is not None and self._thread is not None \
            and self._thread.is_alive()

    @property
    def port(self) -> int:
        return self._actual_port

    @property
    def addresses(self) -> list[str]:
        """本机可用的访问地址（每个网卡一条）。"""
        port = self._actual_port
        if not port:
            return []
        return [f"http://{ip}:{port}" for ip in lan_ips()]

    # -- 生命周期 ---------------------------------------------------------
    def start(self, on_event=None) -> int:
        """开机：重扫频道目录、绑定端口、启动后台线程（端到端同步完成）。"""
        if self.running:
            raise LanShareError("服务已经在运行")
        if on_event is not None:
            self._on_event = on_event
        self.state.load_from_disk()

        try:
            httpd = _ShareHTTPServer(("0.0.0.0", self._want_port),
                                     ShareRequestHandler)
        except OSError as exc:
            raise LanShareError(f"端口绑定失败：{exc}") from exc
        httpd.share = self
        self._httpd = httpd
        self._actual_port = httpd.server_address[1]
        self._thread = threading.Thread(
            target=self._serve, name="lan-share-server", daemon=True)
        self._thread.start()
        self.notify("started", port=self._actual_port,
                    addresses=self.addresses)
        return self._actual_port

    def _serve(self) -> None:
        httpd = self._httpd
        if httpd is None:
            return
        try:
            httpd.serve_forever(poll_interval=0.2)
        except Exception as exc:  # noqa: BLE001  线程兜底
            self.notify("error", message=f"服务线程异常退出：{exc}")
        finally:
            self.notify("closed")

    def stop(self) -> None:
        """停下服务并释放端口（界面线程调用安全；幂等）。"""
        httpd, thread = self._httpd, self._thread
        self._httpd = None
        self._thread = None
        self._actual_port = 0
        if httpd is not None:
            try:
                httpd.shutdown()
            except Exception:  # noqa: BLE001
                pass
            try:
                httpd.server_close()
            except Exception:  # noqa: BLE001
                pass
        if thread is not None and thread.is_alive():
            thread.join(timeout=1.5)

    def notify(self, event_type: str, **payload) -> None:
        """把事件吐给界面层；回调异常不应影响服务线程。"""
        callback = self._on_event
        if callback is None:
            return
        event = {"type": event_type}
        event.update(payload)
        try:
            callback(event)
        except Exception:  # noqa: BLE001
            pass


# ---------------------------------------------------------------------------
# 桌面客户端（urllib）
# ---------------------------------------------------------------------------
def normalize_base(host: str) -> str:
    """把 ``192.168.1.5:8517`` 之类的输入标准化成 ``http://...`` 地址。"""
    text = str(host or "").strip().replace("：", ":")
    if not text:
        raise LanShareError("请填写服务器地址（如 192.168.1.5:8517）")
    if "://" not in text:
        text = "http://" + text
    parsed = urllib.parse.urlparse(text)
    if not parsed.hostname:
        raise LanShareError("地址格式不正确，示例：192.168.1.5:8517")
    base = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path.rstrip("/")
    if path and path != "/":
        base += path
    return base


def _http_open(url: str, data=None, headers: dict | None = None,
               timeout: float = 15.0):
    """urllib 的薄封装：HTTPError 也拿响应体，其他异常归一化。"""
    request = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        return urllib.request.urlopen(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        return exc
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        raise LanShareError(f"连接失败：{reason}") from exc
    except OSError as exc:
        raise LanShareError(f"连接失败：{exc}") from exc


def _http_bytes(url: str, data=None, headers: dict | None = None,
                timeout: float = 15.0) -> tuple[int, bytes]:
    """请求并读取响应体；不使用 ``with``，因为错误响应可能是 HTTPError。"""
    response = _http_open(url, data=data, headers=headers, timeout=timeout)
    try:
        return int(response.status), response.read()
    finally:
        try:
            response.close()
        except Exception:  # noqa: BLE001
            pass


def _http_json(url: str, data=None, headers: dict | None = None,
               timeout: float = 15.0) -> dict:
    status, body = _http_bytes(url, data=data, headers=headers, timeout=timeout)
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise LanShareError("服务器响应异常") from exc
    if not isinstance(payload, dict):
        raise LanShareError("服务器响应异常")
    if status >= 400 or not payload.get("ok", True):
        raise LanShareError(str(payload.get("error") or f"请求失败（HTTP {status}）"))
    return payload


def client_channels(host: str, timeout: float = 5.0) -> dict:
    """取服务信息与频道名列表：``{"name": ..., "channels": [...]}``。"""
    base = normalize_base(host)
    payload = _http_json(f"{base}/api/ping", timeout=timeout)
    return {"base": base,
            "name": str(payload.get("name") or "局域网共享"),
            "channels": list(payload.get("channels") or [])}


def client_join(host: str, channel: str, password: str,
                timeout: float = 10.0) -> dict:
    """加入频道：校验 4 位密码，成功返回 token 与频道名。

    频道为空时服务端取唯一频道（单频道场景直接点「加入」即可）。
    """
    base = normalize_base(host)
    payload = _http_json(
        f"{base}/api/join",
        data=json.dumps({"channel": str(channel or "").strip(),
                         "password": str(password or "").strip()},
                        ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json; charset=utf-8"},
        timeout=timeout,
    )
    return {"base": base,
            "token": str(payload.get("token") or ""),
            "channel": str(payload.get("channel") or ""),
            "members": int(payload.get("members") or 0),
            "name": str(payload.get("name") or "")}


def client_files(base: str, token: str, timeout: float = 15.0) -> list[dict]:
    """拉会话频道的文件清单（按上传时间倒序）。"""
    query = urllib.parse.quote(str(token or ""))
    payload = _http_json(f"{normalize_base(base)}/api/files?token={query}",
                         timeout=timeout)
    return list(payload.get("files") or [])


class _ProgressReader:
    """把文件读操作变成带进度回调的数据源（urllib 直接收 data 流）。

    回调按时间节流（默认 150ms 一次 + 传完必报一次）：urllib 每次只读 8KB，
    大文件若逐块回调会把界面信号队列打满，反而拖慢传输。
    """

    def __init__(self, path: Path, report=None) -> None:
        self._handle = open(path, "rb")
        self._total = path.stat().st_size
        self._done = 0
        self._report = report
        self._last = 0.0

    def read(self, size: int = -1) -> bytes:
        chunk = self._handle.read(size)
        if chunk:
            self._done += len(chunk)
            now = time.monotonic()
            if self._report is not None and (
                    self._done >= self._total or now - self._last >= 0.15):
                self._last = now
                self._report(self._done, self._total)
        return chunk

    def close(self) -> None:
        try:
            self._handle.close()
        except OSError:
            pass


def client_upload(base: str, token: str, path, report=None,
                  timeout: float = 3600.0) -> dict:
    """上传本机文件到已加入的频道（直读文件流，进度经 report(done,total)）。"""
    source = Path(path)
    if not source.is_file():
        raise LanShareError(f"待上传文件不存在：{source}")
    total = source.stat().st_size
    reader = _ProgressReader(source, report)
    query = urllib.parse.quote(str(token or ""))
    headers = {
        "Content-Type": "application/octet-stream",
        "Content-Length": str(total),
        "X-Filename": urllib.parse.quote(source.name),
    }
    try:
        status, body = _http_bytes(
            f"{normalize_base(base)}/api/upload?token={query}",
            data=reader, headers=headers, timeout=timeout)
    finally:
        reader.close()
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise LanShareError(f"上传失败（HTTP {status}）") from None
    if status >= 400 or not payload.get("ok"):
        raise LanShareError(str(payload.get("error") or f"上传失败（HTTP {status}）"))
    return dict(payload.get("file") or {})


def _unique_dest(dest_dir: Path, name: str) -> Path:
    """下载落盘路径：重名时追加 `` (2)``。"""
    target = dest_dir / name
    if not target.exists():
        return target
    stem, ext = _file_suffix(name)
    for index in range(2, 10000):
        candidate = dest_dir / f"{stem} ({index}){ext}"
        if not candidate.exists():
            return candidate
    return dest_dir / f"{stem} ({secrets.token_hex(3)}){ext}"


def client_download(base: str, token: str, filename: str, dest_dir,
                    report=None, timeout: float = 3600.0) -> str:
    """下载频道内指定文件到目录（重名自动追加序号），返回本地路径。"""
    directory = Path(dest_dir)
    directory.mkdir(parents=True, exist_ok=True)
    query = urllib.parse.quote(str(token or ""))
    name = urllib.parse.quote(str(filename or ""))
    url = f"{normalize_base(base)}/api/download?token={query}&name={name}"
    response = _http_open(url, timeout=timeout)
    status = int(response.status)
    if status >= 400:
        body = response.read()
        response.close()
        message = f"下载失败（HTTP {status}）"
        try:
            payload = json.loads(body.decode("utf-8"))
            message = str(payload.get("error") or message)
        except (UnicodeError, json.JSONDecodeError):
            pass
        raise LanShareError(message)

    total = int(response.headers.get("Content-Length") or 0)
    target = _unique_dest(directory, sanitize_filename(filename))
    done = 0
    try:
        with open(target, "wb") as handle:
            while True:
                chunk = response.read(_CHUNK)
                if not chunk:
                    break
                handle.write(chunk)
                done += len(chunk)
                if report is not None:
                    report(done, total or done)
    except OSError as exc:
        target.unlink(missing_ok=True)
        raise LanShareError(f"保存文件失败：{exc}") from exc
    finally:
        try:
            response.close()
        except Exception:  # noqa: BLE001
            pass
    return str(target)


def client_leave(base: str, token: str, timeout: float = 5.0) -> None:
    """通知服务端立即作废会话（可选动作；不调用也会被 TTL 清理）。"""
    query = urllib.parse.quote(str(token or ""))
    try:
        _http_bytes(f"{normalize_base(base)}/api/leave?token={query}",
                    data=b"", timeout=timeout)
    except LanShareError:
        pass


# ---------------------------------------------------------------------------
# 自检：``python -m lib.lan_share`` 起一个临时服务跑通「建频道 -> 加入 ->
# 上传 -> 下载 -> 退出」全链路（仅监听 127.0.0.1）。
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        server = ShareServer("自检服务", port=0, root=tmp)
        port = server.start()
        channel = server.state.new_channel("测试频道")
        print(f"服务已启动 http://127.0.0.1:{port} 频道={channel.name} "
              f"密码={channel.password}")

        info = client_channels(f"127.0.0.1:{port}")
        assert info["channels"] == ["测试频道"], info

        try:
            client_join(f"127.0.0.1:{port}", "测试频道", "0000")
        except LanShareError as exc:
            print(f"错误密码被拒绝（预期）：{exc}")
        else:
            raise AssertionError("错误密码竟然通过了")

        joined = client_join(f"127.0.0.1:{port}", "测试频道", channel.password)
        assert joined["channel"] == "测试频道"

        sample = Path(tmp) / "sample.txt"
        sample.write_text("hello lan share", encoding="utf-8")
        uploaded = client_upload(joined["base"], joined["token"], sample)
        print(f"上传成功：{uploaded}")

        files = client_files(joined["base"], joined["token"])
        assert files and files[0]["name"] == "sample.txt", files

        out_dir = Path(tmp) / "down"
        saved = client_download(joined["base"], joined["token"],
                                "sample.txt", out_dir)
        assert Path(saved).read_text(encoding="utf-8") == "hello lan share"

        client_leave(joined["base"], joined["token"])
        server.stop()
        print("自检通过：建频道 / 密码校验 / 上传 / 下载 / 退出 全部正常")
