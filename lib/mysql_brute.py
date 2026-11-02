# -*- coding: utf-8 -*-
"""MySQL 用户名 / 密码爆破（纯标准库实现 MySQL 客户端认证协议）。

为什么手写协议
--------------
项目用 PyInstaller 打包单文件，``pymysql`` / ``mysql-connector`` 会带额外依赖；
而爆破只需要「握手 + 认证」这一段协议，比完整驱动小得多，用 ``socket`` 手写即可。

支持的认证插件
--------------
- ``mysql_native_password``（MySQL 5.x 默认）：``SHA1(pwd) XOR SHA1(salt + SHA1(SHA1(pwd)))``
- ``caching_sha2_password``（MySQL 8.0 默认）：快速认证走
  ``SHA256(pwd) XOR SHA256(SHA256(SHA256(pwd)) + salt)``；
  服务器要求完整认证时，向服务器索要 RSA 公钥，用 PKCS#1 v1.5 加密
  ``password + "\\0" XOR salt`` 回传（纯 Python 实现 DER 解析 + 模幂）
- 其它插件（``sha256_password`` / ``mysql_clear_password``）按明文或 SHA256 兜底

错误码语义（决定要不要继续试）
------------------------------
- ``1045`` Access denied → 凭据错误，继续下一个
- ``1129`` / ``1130`` 主机被拒 / 被锁 → 立即中止（再试只会加深封禁）
- ``1203`` / ``1040`` 连接数超限 → 降并发重试
- ``1049`` 未知库 → 认证其实成功了（说明账号密码对）
"""
from __future__ import annotations

import hashlib
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

DEFAULT_PORT = 3306
DEFAULT_THREADS = 8
DEFAULT_TIMEOUT = 6.0

# --------------------------------------------------------------------------- #
# 目标分类（合规：内网可爆破，公网/域名仅指纹）
# --------------------------------------------------------------------------- #
TARGET_INTRANET = "intranet"    # 内网：RFC1918 私有 / 回环 / 链路本地，可完整爆破
TARGET_INTERNET = "internet"    # 公网 IP：仅允许被动指纹判断
TARGET_HOSTNAME = "hostname"    # 域名：仅允许被动指纹判断

TARGET_LABELS = {
    TARGET_INTRANET: "内网",
    TARGET_INTERNET: "公网 IP",
    TARGET_HOSTNAME: "域名",
}


def classify_target(host: str) -> str:
    """判断目标是内网 IP、公网 IP 还是域名（标准库 ipaddress）。

    - 能解析成 IP 且属于私有 / 回环 / 链路本地 → 内网；
    - 能解析成 IP 但不属于内网 → 公网 IP；
    - 无法解析成 IP（域名）→ 域名（按公网对待，仅指纹）。
    """
    text = str(host or "").strip()
    if not text:
        return TARGET_HOSTNAME
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return TARGET_HOSTNAME
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified:
        return TARGET_INTRANET
    return TARGET_INTERNET
#: 连续多少次「连不上」就中止（目标挂了或把本机封了）
MAX_CONSECUTIVE_ERRORS = 15
MAX_INPUT = 200_000

#: 内置字典目录（相对项目根）
DICT_SUBDIR = ("dict", "3306")
DEFAULT_PASSWORD_DICT = "常用密码.dict"
DEFAULT_USER_DICT = "常见用户名.dict"

# -- 客户端能力标志 ---------------------------------------------------------
CLIENT_LONG_PASSWORD = 0x00000001
CLIENT_FOUND_ROWS = 0x00000002
CLIENT_LONG_FLAG = 0x00000004
CLIENT_CONNECT_WITH_DB = 0x00000008
CLIENT_PROTOCOL_41 = 0x00000200
CLIENT_TRANSACTIONS = 0x00002000
CLIENT_SECURE_CONNECTION = 0x00008000
CLIENT_MULTI_RESULTS = 0x00020000
CLIENT_PLUGIN_AUTH = 0x00080000

DEFAULT_CHARSET = 33  # utf8_general_ci

# -- 结果状态 ---------------------------------------------------------------
STATE_OK = "ok"              # 认证成功
STATE_DENIED = "denied"      # 凭据错误
STATE_LOCKED = "locked"      # 主机被锁 / 被拒，必须停
STATE_BUSY = "busy"          # 连接数超限，可重试
STATE_ERROR = "error"        # 网络 / 协议错误

STATE_LABELS = {
    STATE_OK: "成功",
    STATE_DENIED: "拒绝",
    STATE_LOCKED: "被封禁",
    STATE_BUSY: "连接超限",
    STATE_ERROR: "错误",
}

#: 认证失败但需要立刻停止的错误码
_LOCK_CODES = {1129, 1130, 1203, 1040}
#: 认证成功但服务器报的「非致命」错误码（说明账号密码其实对了）
_OK_CODES = {1049}


@dataclass
class AuthResult:
    """一次登录尝试的结果。"""

    user: str
    password: str
    state: str
    code: int = 0
    message: str = ""
    plugin: str = ""
    ms: int = 0
    host: str = ""

    @property
    def label(self) -> str:
        return STATE_LABELS.get(self.state, self.state)

    @property
    def ok(self) -> bool:
        return self.state == STATE_OK

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "user": self.user,
            "password": self.password,
            "state": self.state,
            "label": self.label,
            "code": self.code,
            "message": self.message,
            "plugin": self.plugin,
            "ms": self.ms,
        }


# --------------------------------------------------------------------------- #
# 包读写
# --------------------------------------------------------------------------- #

def _recv_exact(sock: socket.socket, count: int) -> bytes:
    buf = b""
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise ConnectionError("服务器关闭了连接")
        buf += chunk
    return buf


def read_packet(sock: socket.socket) -> tuple[int, bytes]:
    """读一个 MySQL 包，返回 ``(序号, 负载)``。"""
    header = _recv_exact(sock, 4)
    length = header[0] | (header[1] << 8) | (header[2] << 16)
    seq = header[3]
    if length == 0:
        return seq, b""
    if length > 16 * 1024 * 1024:
        raise ValueError(f"包长度异常：{length}")
    return seq, _recv_exact(sock, length)


def write_packet(sock: socket.socket, seq: int, payload: bytes) -> None:
    """写一个 MySQL 包。"""
    length = len(payload)
    header = bytes((length & 0xFF, (length >> 8) & 0xFF, (length >> 16) & 0xFF, seq & 0xFF))
    sock.sendall(header + payload)


def _read_nul(data: bytes, pos: int) -> tuple[str, int]:
    end = data.find(b"\x00", pos)
    if end < 0:
        end = len(data)
    return data[pos:end].decode("utf-8", "ignore"), end + 1


@dataclass
class ServerGreeting:
    """服务器握手包解析结果。"""

    version: str = ""
    thread_id: int = 0
    salt: bytes = b""
    capabilities: int = 0
    charset: int = 0
    status: int = 0
    plugin: str = "mysql_native_password"

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "plugin": self.plugin,
            "capabilities": self.capabilities,
            "charset": self.charset,
        }


def parse_greeting(payload: bytes) -> ServerGreeting:
    """解析 initial handshake 包。"""
    if not payload:
        raise ValueError("空握手包")
    if payload[0] == 0xFF:
        raise ValueError(_parse_error(payload)[1] or "服务器拒绝连接")
    if payload[0] != 10:
        raise ValueError(f"不支持的协议版本 {payload[0]}")

    pos = 1
    version, pos = _read_nul(payload, pos)
    thread_id = struct.unpack("<I", payload[pos:pos + 4])[0]
    pos += 4
    salt1 = payload[pos:pos + 8]
    pos += 8
    pos += 1  # filler
    caps_low = struct.unpack("<H", payload[pos:pos + 2])[0] if len(payload) >= pos + 2 else 0
    pos += 2

    greeting = ServerGreeting(version=version, thread_id=thread_id, salt=salt1)
    if len(payload) <= pos:
        greeting.capabilities = caps_low
        greeting.salt = salt1
        return greeting

    charset = payload[pos]
    pos += 1
    status = struct.unpack("<H", payload[pos:pos + 2])[0]
    pos += 2
    caps_high = struct.unpack("<H", payload[pos:pos + 2])[0]
    pos += 2
    capabilities = caps_low | (caps_high << 16)
    auth_len = payload[pos] if len(payload) > pos else 0
    pos += 1
    pos += 10  # reserved

    salt2 = b""
    if capabilities & CLIENT_SECURE_CONNECTION and len(payload) > pos:
        take = max(13, auth_len - 8)
        salt2 = payload[pos:pos + take]
        pos += take
    salt = (salt1 + salt2)[:20]

    plugin = ""
    if capabilities & CLIENT_PLUGIN_AUTH and len(payload) > pos:
        plugin, _ = _read_nul(payload, pos)

    greeting.salt = salt
    greeting.capabilities = capabilities
    greeting.charset = charset
    greeting.status = status
    greeting.plugin = plugin or "mysql_native_password"
    return greeting


def _parse_error(payload: bytes) -> tuple[int, str]:
    """解析 ERR 包，返回 ``(错误码, 消息)``。"""
    if len(payload) < 3:
        return 0, ""
    code = struct.unpack("<H", payload[1:3])[0]
    pos = 3
    if len(payload) > pos and payload[pos:pos + 1] == b"#":
        pos += 6  # '#' + 5 位 SQLSTATE
    message = payload[pos:].decode("utf-8", "ignore").strip()
    return code, message


# --------------------------------------------------------------------------- #
# 认证算法
# --------------------------------------------------------------------------- #

def scramble_native(password: str, salt: bytes) -> bytes:
    """``mysql_native_password``：SHA1(pwd) XOR SHA1(salt + SHA1(SHA1(pwd)))。"""
    if not password:
        return b""
    stage1 = hashlib.sha1(password.encode()).digest()
    stage2 = hashlib.sha1(stage1).digest()
    stage3 = hashlib.sha1(salt + stage2).digest()
    return bytes(a ^ b for a, b in zip(stage1, stage3))


def scramble_sha2(password: str, salt: bytes) -> bytes:
    """``caching_sha2_password`` 快速认证。"""
    if not password:
        return b""
    stage1 = hashlib.sha256(password.encode()).digest()
    stage2 = hashlib.sha256(stage1).digest()
    stage3 = hashlib.sha256(stage2 + salt).digest()
    return bytes(a ^ b for a, b in zip(stage1, stage3))


def scramble_sha256(password: str, salt: bytes) -> bytes:
    """``sha256_password`` 的明文 XOR salt 形式（需要 RSA 时另处理）。"""
    if not password:
        return b""
    raw = password.encode() + b"\x00"
    return bytes(a ^ b for a, b in zip(raw, salt * (len(raw) // len(salt) + 1)))


def _xor_password(password: str, salt: bytes) -> bytes:
    raw = password.encode() + b"\x00"
    stream = (salt * (len(raw) // max(1, len(salt)) + 1))[: len(raw)]
    return bytes(a ^ b for a, b in zip(raw, stream))


# -- 最小 DER 解析 + RSA PKCS#1 v1.5 ---------------------------------------

def _der_read(data: bytes, pos: int) -> tuple[int, bytes, int]:
    """读一个 DER TLV，返回 ``(tag, 内容, 新位置)``。"""
    if pos + 2 > len(data):
        raise ValueError("DER 数据不完整")
    tag = data[pos]
    pos += 1
    length = data[pos]
    pos += 1
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or pos + count > len(data):
            raise ValueError("DER 长度非法")
        length = int.from_bytes(data[pos:pos + count], "big")
        pos += count
    if pos + length > len(data):
        raise ValueError("DER 内容越界")
    return tag, data[pos:pos + length], pos + length


def parse_rsa_public_key(pem: bytes) -> tuple[int, int]:
    """从 PEM（SubjectPublicKeyInfo）里取出 ``(n, e)``。"""
    text = pem.decode("ascii", "ignore")
    match = re.search(
        r"-----BEGIN PUBLIC KEY-----(.+?)-----END PUBLIC KEY-----", text, re.S
    )
    if not match:
        raise ValueError("不是 PEM 公钥")
    import base64

    der = base64.b64decode("".join(match.group(1).split()))

    # SubjectPublicKeyInfo ::= SEQUENCE { algorithm SEQUENCE, subjectPublicKey BIT STRING }
    tag, body, _ = _der_read(der, 0)
    if tag != 0x30:
        raise ValueError("公钥结构异常")
    tag, _algo, pos = _der_read(body, 0)
    tag, bits, _ = _der_read(body, pos)
    if tag != 0x03 or not bits:
        raise ValueError("公钥 BIT STRING 异常")
    inner = bits[1:]  # 去掉 unused-bits 字节
    tag, seq, _ = _der_read(inner, 0)
    if tag != 0x30:
        raise ValueError("RSAPublicKey 结构异常")
    tag, n_bytes, pos = _der_read(seq, 0)
    tag, e_bytes, _ = _der_read(seq, pos)
    return int.from_bytes(n_bytes, "big"), int.from_bytes(e_bytes, "big")


def rsa_encrypt_pkcs1(pem: bytes, message: bytes) -> bytes:
    """用 PEM 公钥做 PKCS#1 v1.5 加密（纯 Python 模幂）。"""
    import os

    n, e = parse_rsa_public_key(pem)
    k = (n.bit_length() + 7) // 8
    if len(message) > k - 11:
        raise ValueError("明文过长，无法用该公钥加密")
    padding = bytearray()
    while len(padding) < k - 3 - len(message):
        byte = os.urandom(1)
        if byte != b"\x00":
            padding += byte
    block = b"\x00\x02" + bytes(padding) + b"\x00" + message
    cipher = pow(int.from_bytes(block, "big"), e, n)
    return cipher.to_bytes(k, "big")


# -- 自检用的密钥生成 / 解码（不进产品路径） --------------------------------

def _is_prime(num: int, rounds: int = 24) -> bool:
    import random as _random

    if num < 2:
        return False
    for small in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if num % small == 0:
            return num == small
    d, s = num - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = _random.randrange(2, num - 1)
        x = pow(a, d, num)
        if x in (1, num - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, num)
            if x == num - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits: int) -> int:
    import random as _random

    while True:
        cand = _random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_prime(cand):
            return cand


def _der(tag: int, body: bytes) -> bytes:
    return bytes([tag, len(body)]) + body


def _der_int(value: int) -> bytes:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if raw[0] & 0x80:  # DER 正整数需要前导 0 表示符号
        raw = b"\x00" + raw
    return _der(0x02, raw)


def _make_public_pem(n: int, e: int) -> bytes:
    """把 ``(n, e)`` 编成 MySQL 那种 SubjectPublicKeyInfo PEM。"""
    from base64 import b64encode

    rsa_pub = _der(0x30, _der_int(n) + _der_int(e))
    spki = _der(
        0x30,
        _der(0x30, _der(0x06, bytes.fromhex("2a864886f70d010101")) + b"\x05\x00")
        + _der(0x03, b"\x00" + rsa_pub),
    )
    body = "\n".join(
        b64encode(spki).decode()[i:i + 64]
        for i in range(0, len(b64encode(spki)), 64)
    )
    return f"-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----\n".encode()


def rsa_decrypt_pkcs1(n: int, d: int, cipher: bytes) -> bytes:
    """PKCS#1 v1.5 解密（自检用，验证客户端加密结果）。"""
    k = (n.bit_length() + 7) // 8
    plain = pow(int.from_bytes(cipher, "big"), d, n).to_bytes(k, "big")
    if not plain.startswith(b"\x00\x02"):
        raise ValueError("填充头不对")
    end = plain.find(b"\x00", 2)
    if end < 0:
        raise ValueError("缺少分隔符")
    return plain[end + 1:]


# --------------------------------------------------------------------------- #
# 单次登录
# --------------------------------------------------------------------------- #

def _auth_response(plugin: str, password: str, salt: bytes) -> bytes:
    plugin = (plugin or "").lower()
    if plugin == "mysql_native_password":
        return scramble_native(password, salt)
    if plugin == "caching_sha2_password":
        return scramble_sha2(password, salt)
    if plugin == "sha256_password":
        return scramble_sha256(password, salt)
    if plugin == "mysql_clear_password":
        return password.encode() + b"\x00"
    # 未知插件按 native 兜底（多数兼容）
    return scramble_native(password, salt)


def try_login(
    host: str,
    port: int,
    user: str,
    password: str,
    timeout: float = DEFAULT_TIMEOUT,
    probe_only: bool = False,
) -> AuthResult:
    """尝试一次登录。

    ``probe_only=True`` 时只握手不发认证，用来确认目标是不是 MySQL。
    """
    t0 = time.time()
    sock: socket.socket | None = None
    result = AuthResult(user=user, password=password, state=STATE_ERROR, host=f"{host}:{port}")
    try:
        sock = socket.create_connection((host, port), timeout)
        sock.settimeout(timeout)
        seq, payload = read_packet(sock)
        greeting = parse_greeting(payload)
        result.plugin = greeting.plugin
        if probe_only:
            result.state = STATE_OK
            result.message = f"MySQL {greeting.version}（{greeting.plugin}）"
            return result

        caps = (
            CLIENT_LONG_PASSWORD
            | CLIENT_LONG_FLAG
            | CLIENT_PROTOCOL_41
            | CLIENT_TRANSACTIONS
            | CLIENT_SECURE_CONNECTION
            | CLIENT_MULTI_RESULTS
            | CLIENT_PLUGIN_AUTH
        )
        auth = _auth_response(greeting.plugin, password, greeting.salt)
        body = struct.pack("<IIB", caps, 16 * 1024 * 1024, DEFAULT_CHARSET)
        body += b"\x00" * 23
        body += user.encode() + b"\x00"
        body += bytes([len(auth)]) + auth
        body += greeting.plugin.encode() + b"\x00"
        write_packet(sock, seq + 1, body)

        # 认证阶段可能要来回几次
        seq, payload = read_packet(sock)
        for _ in range(4):
            if not payload:
                result.state = STATE_ERROR
                result.message = "服务器返回空包"
                return result
            head = payload[0]

            if head == 0x00:  # OK
                result.state = STATE_OK
                result.message = "登录成功"
                return result

            if head == 0xFF:  # ERR
                code, message = _parse_error(payload)
                result.code = code
                result.message = message
                if code in _OK_CODES:
                    # 账号密码对，只是库/权限有额外提示
                    result.state = STATE_OK
                elif code in _LOCK_CODES:
                    result.state = STATE_LOCKED
                elif code == 1045:
                    result.state = STATE_DENIED
                else:
                    result.state = STATE_DENIED
                return result

            if head == 0xFE:  # Auth Switch Request
                plugin, pos = _read_nul(payload, 1)
                salt = payload[pos:pos + 20]
                plugin = plugin or greeting.plugin
                result.plugin = plugin
                auth = _auth_response(plugin, password, salt)
                if plugin.lower() == "mysql_clear_password":
                    write_packet(sock, seq + 1, password.encode() + b"\x00")
                else:
                    write_packet(sock, seq + 1, auth)
                seq, payload = read_packet(sock)
                continue

            if head == 0x01:  # Auth More Data
                data = payload[1:]
                if data[:1] == b"\x03":  # caching_sha2 fast auth success
                    seq, payload = read_packet(sock)
                    continue
                if data[:1] == b"\x04":  # 需要完整认证
                    write_packet(sock, seq + 1, b"\x02")  # 请求公钥
                    seq, payload = read_packet(sock)
                    if payload[:1] == b"\x01":
                        pem = payload[1:]
                        secret = _xor_password(password, greeting.salt)
                        try:
                            encrypted = rsa_encrypt_pkcs1(pem, secret)
                        except (ValueError, OSError) as exc:
                            result.state = STATE_ERROR
                            result.message = f"RSA 加密失败：{exc}"
                            return result
                        write_packet(sock, seq + 1, encrypted)
                        seq, payload = read_packet(sock)
                        continue
                    result.state = STATE_ERROR
                    result.message = "服务器未返回公钥"
                    return result
                # 其它 Auth More Data：直接把当前密码按 sha256 回一次
                write_packet(sock, seq + 1, scramble_sha256(password, greeting.salt))
                seq, payload = read_packet(sock)
                continue

            result.state = STATE_ERROR
            result.message = f"未知响应类型 0x{head:02x}"
            return result

        result.state = STATE_ERROR
        result.message = "认证交互次数过多"
        return result
    except socket.timeout:
        result.state = STATE_ERROR
        result.message = "连接超时"
        return result
    except ConnectionRefusedError:
        result.state = STATE_ERROR
        result.message = "端口未开放"
        return result
    except (ConnectionError, OSError) as exc:
        result.state = STATE_ERROR
        result.message = f"网络错误：{exc}"
        return result
    except ValueError as exc:
        result.state = STATE_ERROR
        result.message = f"协议错误：{exc}"
        return result
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        result.ms = int((time.time() - t0) * 1000)


def probe(host: str, port: int = DEFAULT_PORT, timeout: float = DEFAULT_TIMEOUT) -> AuthResult:
    """只握手，确认目标是不是 MySQL 并取版本 / 认证插件。"""
    return try_login(host, port, "", "", timeout, probe_only=True)


# --------------------------------------------------------------------------- #
# 纯被动 banner 指纹（公网 / 域名目标使用，不发送任何认证数据）
# --------------------------------------------------------------------------- #
def banner_grab(host: str, port: int = DEFAULT_PORT,
                timeout: float = DEFAULT_TIMEOUT) -> dict:
    """纯被动读取 MySQL 服务端握手包，仅做服务指纹识别。

    与 :func:`try_login` 的 ``probe_only`` 不同，这里**只 recv 一次握手包**
    后立即断开，不发送任何字节（连认证请求都不发），是等价于
    ``nmap -sV -p 3306`` 的合规被动探测。

    返回 ``{reachable, error, banner}``，``banner`` 为解析出的指纹 dict。
    """
    result: dict = {"reachable": False, "error": "", "banner": {}}
    sock: socket.socket | None = None
    try:
        sock = socket.create_connection((host, port), timeout)
        sock.settimeout(timeout)
        result["reachable"] = True
        # 关键：只被动接收服务端主动下发的握手包，不发送任何字节
        seq, payload = read_packet(sock)
        greeting = parse_greeting(payload)
        result["banner"] = {
            "version": greeting.version,
            "plugin": greeting.plugin,
            "thread_id": greeting.thread_id,
            "protocol": 10,
        }
    except socket.timeout:
        result["error"] = "连接超时（端口可能被防火墙过滤或服务未响应）"
    except ConnectionRefusedError:
        result["error"] = "连接被拒绝（端口未开放或被 ACL 限制）"
    except (ValueError, ConnectionError, OSError) as exc:
        result["error"] = f"无法识别服务：{exc}"
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return result


# --------------------------------------------------------------------------- #
# 核心脚本完整性校验（防篡改，MD5）
# --------------------------------------------------------------------------- #
def core_md5() -> str:
    """返回本核心脚本文件的 MD5（用于界面展示，检测是否被篡改）。"""
    path = Path(__file__)
    try:
        data = path.read_bytes()
    except OSError:
        return ""
    return hashlib.md5(data).hexdigest()


# --------------------------------------------------------------------------- #
# 字典
# --------------------------------------------------------------------------- #

def default_dict_dir() -> Path:
    """内置字典目录（兼容 PyInstaller 冻结后的打包数据根）。"""
    from lib.runtime_paths import resource

    return resource(*DICT_SUBDIR)


def load_lines(path: str | Path, limit: int = MAX_INPUT) -> list[str]:
    """读取一行一个的字典（去 BOM / 空行 / 注释，保序去重）。"""
    p = Path(path)
    out: list[str] = []
    seen: set[str] = set()
    for raw in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        text = raw.strip().lstrip("\ufeff")
        if not text or text.startswith("#") or text.startswith("//"):
            continue
        if text in seen:
            continue
        seen.add(text)
        out.append(text)
        if len(out) >= limit:
            break
    return out


def parse_list(text: str) -> list[str]:
    """解析手输的逗号 / 换行分隔列表。"""
    out: list[str] = []
    seen: set[str] = set()
    for token in re.split(r"[,;\r\n\t]+", text or ""):
        token = token.strip()
        if not token or token in seen:
            continue
        seen.add(token)
        out.append(token)
    return out


def default_users() -> list[str]:
    path = default_dict_dir() / DEFAULT_USER_DICT
    if path.is_file():
        return load_lines(path)
    return ["root", "admin", "test"]


def default_passwords() -> list[str]:
    path = default_dict_dir() / DEFAULT_PASSWORD_DICT
    if path.is_file():
        return load_lines(path)
    return ["", "root", "123456", "password"]


# --------------------------------------------------------------------------- #
# 爆破
# --------------------------------------------------------------------------- #

@dataclass
class BruteStats:
    total: int = 0
    done: int = 0
    denied: int = 0
    errors: int = 0
    started: float = field(default_factory=time.time)

    @property
    def elapsed(self) -> float:
        return max(0.0, time.time() - self.started)

    @property
    def speed(self) -> float:
        elapsed = self.elapsed
        return self.done / elapsed if elapsed > 0 else 0.0


def brute(
    host: str,
    port: int,
    users: Sequence[str],
    passwords: Sequence[str],
    threads: int = DEFAULT_THREADS,
    timeout: float = DEFAULT_TIMEOUT,
    stop: threading.Event | None = None,
    log: Callable[[str], None] | None = None,
    on_hit: Callable[[AuthResult], None] | None = None,
    on_progress: Callable[[BruteStats], None] | None = None,
    max_attempts: int = 0,
    out_dir: str | Path | None = None,
) -> dict:
    """按「用户 × 密码」组合爆破。

    - 找到一组可用凭据后**不会**自动停止（可能还有别的账号），但会记下来；
    - 遇到 ``1129 / 1130 / 1203 / 1040``（主机被锁 / 连接超限）立即中止；
    - 连续 ``MAX_CONSECUTIVE_ERRORS`` 次网络错误也中止，避免空跑。
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    stop = stop or threading.Event()
    combos = [(u, p) for u in users for p in passwords]
    if max_attempts > 0:
        combos = combos[:max_attempts]

    stats = BruteStats(total=len(combos))
    hits: list[AuthResult] = []
    lock = threading.Lock()
    abort = threading.Event()
    consecutive_errors = [0]
    last_emit = [0.0]

    def _emit(force: bool = False) -> None:
        if on_progress is None:
            return
        now = time.time()
        with lock:
            if not force and now - last_emit[0] < 0.25:
                return
            last_emit[0] = now
        on_progress(stats)

    if log:
        log(
            f"开始爆破 {host}:{port}，用户名 {len(users)} 个 × 密码 {len(passwords)} 个 "
            f"= {len(combos)} 次尝试，{threads} 线程"
        )

    def _work(combo: tuple[str, str]) -> AuthResult | None:
        if stop.is_set() or abort.is_set():
            return None
        user, password = combo
        result = try_login(host, port, user, password, timeout)
        with lock:
            stats.done += 1
            if result.state == STATE_OK:
                hits.append(result)
                consecutive_errors[0] = 0
            elif result.state == STATE_DENIED:
                stats.denied += 1
                consecutive_errors[0] = 0
            elif result.state == STATE_ERROR:
                stats.errors += 1
                consecutive_errors[0] += 1
            else:
                stats.errors += 1
                consecutive_errors[0] = 0

        if result.state == STATE_OK:
            if log:
                log(f"[+] 命中 {user}:{password}（{result.plugin}，{result.ms}ms）")
            if on_hit is not None:
                on_hit(result)
        elif result.state == STATE_LOCKED:
            abort.set()
            if log:
                log(f"[!] 服务器拒绝继续尝试（{result.code} {result.message}），已中止")
        elif result.state == STATE_ERROR and consecutive_errors[0] >= MAX_CONSECUTIVE_ERRORS:
            abort.set()
            if log:
                log(f"[!] 连续 {MAX_CONSECUTIVE_ERRORS} 次连接失败，已中止：{result.message}")
        _emit()
        return result

    try:
        with ThreadPoolExecutor(max_workers=max(1, min(threads, max(1, len(combos))))) as executor:
            futures = [executor.submit(_work, combo) for combo in combos]
            for future in as_completed(futures):
                if stop.is_set() or abort.is_set():
                    for f in futures:
                        f.cancel()
                    break
                try:
                    future.result()
                except Exception as exc:  # noqa: BLE001
                    if log:
                        log(f"[!] 尝试异常：{exc}")
    finally:
        _emit(force=True)

    if log:
        log(
            f"爆破结束：{stats.done}/{stats.total} 次，命中 {len(hits)} 组，"
            f"失败 {stats.denied}，错误 {stats.errors}，"
            f"耗时 {stats.elapsed:.1f}s（{stats.speed:.1f} 次/秒）"
        )

    result = {
        "host": host,
        "port": port,
        "total": stats.total,
        "done": stats.done,
        "denied": stats.denied,
        "errors": stats.errors,
        "hits": [h.to_dict() for h in hits],
        "elapsed": round(stats.elapsed, 2),
        "speed": round(stats.speed, 2),
        "aborted": abort.is_set(),
    }
    if out_dir and hits:
        result["files"] = _dump(host, port, hits, out_dir)
        if log:
            log(f"凭据已保存到 {Path(out_dir)}")
    return result


def _dump(host: str, port: int, hits: list[AuthResult], out_dir: str | Path) -> dict:
    import csv

    safe = re.sub(r"[^0-9A-Za-z._-]", "_", host) or "target"
    root = Path(out_dir) / f"{safe}_{port}"
    root.mkdir(parents=True, exist_ok=True)

    csv_path = root / "mysql_creds.csv"
    with csv_path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["主机", "端口", "用户名", "密码", "认证插件", "耗时ms"])
        for hit in hits:
            writer.writerow([host, port, hit.user, hit.password, hit.plugin, hit.ms])

    txt_path = root / "mysql_creds.txt"
    txt_path.write_text(
        "\n".join(f"{h.user}:{h.password}" for h in hits) + "\n", encoding="utf-8"
    )
    return {"csv": str(csv_path), "txt": str(txt_path)}


# --------------------------------------------------------------------------- #
# 自检
# --------------------------------------------------------------------------- #

class _FakeMySQLServer:
    """自检用的最小 MySQL 服务端：只为验证客户端握手与两种认证算法。

    ``accounts`` 是 ``{user: password}``，认证通过回 OK，否则回 1045。
    ``full_auth=True`` 时强制走 ``caching_sha2_password`` 的完整认证（RSA），
    用来覆盖 MySQL 8.0 默认路径。
    """

    def __init__(
        self,
        accounts: dict[str, str],
        plugin: str = "mysql_native_password",
        full_auth: bool = False,
    ):
        self.accounts = accounts
        self.plugin = plugin
        self.full_auth = full_auth
        self.salt = b"12345678abcdefghijkl"[:20]
        self.port = 0
        self._n = self._d = 0
        self._pem = b""
        if full_auth:
            p, q = _gen_prime(128), _gen_prime(128)
            self._n = p * q
            e = 65537
            self._d = pow(e, -1, (p - 1) * (q - 1))
            self._pem = _make_public_pem(self._n, e)
        self._stop = threading.Event()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def start(self) -> "_FakeMySQLServer":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(5)
            greeting = (
                b"\x0a"
                + b"8.0.36-fake\x00"
                + struct.pack("<I", 1)
                + self.salt[:8]
                + b"\x00"
                + struct.pack("<H", 0xFFFF)
                + bytes([33])
                + struct.pack("<H", 2)
                + struct.pack("<H", 0xFFFF)
                + bytes([21])
                + b"\x00" * 10
                + self.salt[8:20]
                + b"\x00"
                + self.plugin.encode()
                + b"\x00"
            )
            write_packet(conn, 0, greeting)
            seq, payload = read_packet(conn)

            caps = struct.unpack("<I", payload[:4])[0]
            pos = 32
            user, pos = _read_nul(payload, pos)
            auth_len = payload[pos]
            pos += 1
            auth = payload[pos:pos + auth_len]
            pos += auth_len
            plugin = ""
            if caps & CLIENT_PLUGIN_AUTH and pos < len(payload):
                plugin, _ = _read_nul(payload, pos)

            password = self.accounts.get(user)

            # caching_sha2_password 完整认证：要求客户端用 RSA 公钥加密明文密码
            if self.full_auth and (plugin or self.plugin).lower() == "caching_sha2_password":
                write_packet(conn, seq + 1, b"\x01\x04")
                seq2, request = read_packet(conn)
                if request[:1] != b"\x02":
                    return
                write_packet(conn, seq2 + 1, b"\x01" + self._pem)
                seq3, encrypted = read_packet(conn)
                try:
                    secret = rsa_decrypt_pkcs1(self._n, self._d, encrypted)
                    stream = (self.salt * (len(secret) // len(self.salt) + 1))[: len(secret)]
                    plain = bytes(a ^ b for a, b in zip(secret, stream))
                    got = plain.rstrip(b"\x00").decode("utf-8", "ignore")
                except (ValueError, OSError):
                    got = None
                if password is not None and got == password:
                    write_packet(conn, seq3 + 1, b"\x00\x00\x00\x02\x00\x00\x00")
                else:
                    write_packet(
                        conn, seq3 + 1,
                        b"\xff" + struct.pack("<H", 1045) + b"#28000Access denied",
                    )
                return

            expect = (
                _auth_response(plugin or self.plugin, password, self.salt)
                if password is not None
                else b""
            )
            if password is not None and auth == expect:
                write_packet(conn, seq + 1, b"\x00\x00\x00\x02\x00\x00\x00")
            else:
                msg = b"#28000Access denied for user"
                write_packet(conn, seq + 1, b"\xff" + struct.pack("<H", 1045) + msg)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


def _selftest() -> int:
    """``python -m lib.mysql_brute`` 自检（不需要真实 MySQL）。"""
    ok = True

    # 1. 两种认证算法的标准向量（与官方文档一致的手算校验）
    salt = bytes.fromhex("1a2b3c4d5e6f708192a3b4c5")
    native = scramble_native("pass", salt)
    expect = bytes(
        a ^ b
        for a, b in zip(
            hashlib.sha1(b"pass").digest(),
            hashlib.sha1(salt + hashlib.sha1(hashlib.sha1(b"pass").digest()).digest()).digest(),
        )
    )
    if native != expect:
        print("[FAIL] mysql_native_password 算法")
        ok = False
    if scramble_native("", salt) != b"":
        print("[FAIL] 空密码应返回空")
        ok = False
    if len(scramble_sha2("pass", salt)) != 32:
        print("[FAIL] caching_sha2 长度应为 32")
        ok = False
    print("[OK] 认证算法（native 20 字节 / sha2 32 字节 / 空密码）")

    # 2. 握手包解析
    payload = (
        b"\x0a" + b"5.7.44\x00" + struct.pack("<I", 7) + b"abcdefgh\x00"
        + struct.pack("<H", 0xFFFF) + bytes([33]) + struct.pack("<H", 2)
        + struct.pack("<H", 0xFFFF) + bytes([21]) + b"\x00" * 10
        + b"ijklmnopqrst\x00" + b"mysql_native_password\x00"
    )
    g = parse_greeting(payload)
    if g.version != "5.7.44" or g.plugin != "mysql_native_password" or len(g.salt) != 20:
        print(f"[FAIL] 握手解析：{g.to_dict()} salt={g.salt!r}")
        ok = False
    print(f"[OK] 握手解析：{g.version} / {g.plugin} / salt {len(g.salt)} 字节")

    # 3. RSA 公钥解析 + PKCS#1 加密（现场生成一对小密钥，验证能私钥还原）
    p = _gen_prime(128)
    q = _gen_prime(128)
    e = 65537
    n = p * q
    d = pow(e, -1, (p - 1) * (q - 1))
    pem = _make_public_pem(n, e)
    try:
        parsed_n, parsed_e = parse_rsa_public_key(pem)
        if (parsed_n, parsed_e) != (n, e):
            print(f"[FAIL] RSA 公钥解析：位数 {parsed_n.bit_length()}/{parsed_e} 不符")
            ok = False
        cipher = rsa_encrypt_pkcs1(pem, b"hi")
        k = (n.bit_length() + 7) // 8
        if len(cipher) != k:
            print(f"[FAIL] 密文长度 {len(cipher)} != {k}")
            ok = False
        if rsa_decrypt_pkcs1(n, d, cipher) != b"hi":
            print("[FAIL] PKCS#1 v1.5 解密结果不符")
            ok = False
        print(f"[OK] RSA 公钥 DER 解析 + PKCS#1 v1.5 加解密（{n.bit_length()} 位）")
    except Exception as exc:  # noqa: BLE001
        print(f"[FAIL] RSA 流程异常：{exc}")
        ok = False

    # 4. 假 MySQL 服务端：正确凭据成功、错误凭据 1045
    for plugin in ("mysql_native_password", "caching_sha2_password"):
        server = _FakeMySQLServer({"root": "toor", "app": ""}, plugin).start()
        try:
            good = try_login("127.0.0.1", server.port, "root", "toor", 3)
            bad = try_login("127.0.0.1", server.port, "root", "wrong", 3)
            empty = try_login("127.0.0.1", server.port, "app", "", 3)
            if good.state != STATE_OK:
                print(f"[FAIL] {plugin} 正确凭据 -> {good.state}/{good.code} {good.message}")
                ok = False
            if bad.state != STATE_DENIED or bad.code != 1045:
                print(f"[FAIL] {plugin} 错误凭据 -> {bad.state}/{bad.code}")
                ok = False
            if empty.state != STATE_OK:
                print(f"[FAIL] {plugin} 空密码账号 -> {empty.state}/{empty.code}")
                ok = False
            print(f"[OK] {plugin}：正确 {good.ms}ms / 错误 1045 / 空密码可登录")
        finally:
            server.stop()

    # 5. 探针
    server = _FakeMySQLServer({"root": "toor"}).start()
    try:
        info = probe("127.0.0.1", server.port, 3)
        if info.state != STATE_OK or "8.0.36" not in info.message:
            print(f"[FAIL] 探针 -> {info.state} {info.message}")
            ok = False
        print(f"[OK] 探针：{info.message}")
    finally:
        server.stop()

    # 6. 爆破主流程（含落盘）
    import tempfile

    server = _FakeMySQLServer({"root": "toor", "admin": "admin123"}).start()
    try:
        hits: list[AuthResult] = []
        tmp = Path(tempfile.mkdtemp(prefix="mysql_"))
        result = brute(
            "127.0.0.1", server.port,
            ["root", "admin", "nobody"],
            ["", "123456", "toor", "admin123"],
            threads=4, timeout=3, log=print,
            on_hit=hits.append, out_dir=tmp,
        )
        found = {(h["user"], h["password"]) for h in result["hits"]}
        if found != {("root", "toor"), ("admin", "admin123")}:
            print(f"[FAIL] 爆破命中不对：{found}")
            ok = False
        if not Path(result.get("files", {}).get("csv", "")).is_file():
            print("[FAIL] 凭据未落盘")
            ok = False
        print(f"[OK] 爆破：{result['done']}/{result['total']} 次，命中 {len(found)} 组，已落盘")
    finally:
        server.stop()

    # 7. caching_sha2_password 完整认证（MySQL 8.0 默认路径，需要 RSA 公钥交换）
    server = _FakeMySQLServer(
        {"root": "S3cret!Pass"}, "caching_sha2_password", full_auth=True
    ).start()
    try:
        good = try_login("127.0.0.1", server.port, "root", "S3cret!Pass", 5)
        bad = try_login("127.0.0.1", server.port, "root", "S3cret!Pas", 5)
        if good.state != STATE_OK:
            print(f"[FAIL] 完整认证正确凭据 -> {good.state}/{good.code} {good.message}")
            ok = False
        if bad.state != STATE_DENIED:
            print(f"[FAIL] 完整认证错误凭据 -> {bad.state}/{bad.code}")
            ok = False
        print(f"[OK] caching_sha2 完整认证（RSA 交换）：正确 {good.ms}ms / 错误 1045")
    finally:
        server.stop()

    # 8. 字典
    users = default_users()
    pwd_path = default_dict_dir() / DEFAULT_PASSWORD_DICT
    pwds = default_passwords() if pwd_path.is_file() else []
    if len(users) < 10:
        print(f"[FAIL] 内置用户名只有 {len(users)} 个")
        ok = False
    if pwd_path.is_file() and len(pwds) < 1000:
        print(f"[FAIL] 内置密码字典只有 {len(pwds)} 条")
        ok = False
    print(f"[OK] 内置字典：用户名 {len(users)} 个，密码 {len(pwds)} 条")

    print("\n自检结果：", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(_selftest())
