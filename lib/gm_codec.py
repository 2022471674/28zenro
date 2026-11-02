# -*- coding: utf-8 -*-
"""国密算法纯 Python 实现（SM3 / SM4 / SM2）。

**不引入任何第三方依赖**：项目用 PyInstaller 打包单文件，纯 Python 实现
（标准库 ``struct`` / ``os`` 即可）可以避免 ``gmssl`` / ``Cryptodome`` 之类
的二进制依赖在打包与跨平台分发时带来的麻烦。

对外接口
--------
- SM3 摘要：:func:`sm3_hash` / :func:`sm3_hex`；KDF 派生：:func:`sm3_kdf`
- SM4 分组密码：:func:`sm4_ecb_encrypt` / :func:`sm4_ecb_decrypt` /
  :func:`sm4_cbc_encrypt` / :func:`sm4_cbc_decrypt`（均支持 PKCS7 填充）
- SM2 椭圆曲线：:func:`sm2_generate_keypair` / :func:`sm2_encrypt` /
  :func:`sm2_decrypt` / :func:`sm2_sign` / :func:`sm2_verify`
- 输入解析辅助：:func:`parse_hex`（十六进制字符串 -> bytes）

所有算法均以官方测试向量自测通过（见文件末尾 ``__main__`` 自检块）。
"""

from __future__ import annotations

import os
import struct


class GmError(ValueError):
    """国密工具统一异常：输入非法 / 解密或验签失败等。"""


# ---------------------------------------------------------------------------
# 通用小工具
# ---------------------------------------------------------------------------
def _rotl(x: int, n: int) -> int:
    """32 位循环左移。"""
    n %= 32
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _to_bytes(data) -> bytes:
    """把 str / bytes / bytearray 统一成 bytes（str 按 UTF-8 编码）。"""
    if isinstance(data, bytes):
        return data
    if isinstance(data, bytearray):
        return bytes(data)
    return str(data).encode("utf-8")


def parse_hex(text: str) -> bytes:
    """把十六进制字符串解析为 bytes。

    容忍空白、``0x`` 前缀与 ``:`` / ``-`` 分隔符；奇数长度自动左补 0。
    """
    s = "".join(str(text).split()).replace(":", "").replace("-", "")
    if s.lower().startswith("0x"):
        s = s[2:]
    if not s:
        raise GmError("十六进制内容为空")
    if len(s) % 2:
        s = "0" + s
    try:
        return bytes.fromhex(s)
    except ValueError as exc:  # noqa: PERF203
        raise GmError("不是合法的十六进制字符串（含非十六进制字符）") from exc


# ===========================================================================
# SM3 密码杂凑算法（GM/T 0004-2012）
# ===========================================================================
_SM3_IV = (
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
)


def _sm3_p0(x: int) -> int:
    return x ^ _rotl(x, 9) ^ _rotl(x, 17)


def _sm3_p1(x: int) -> int:
    return x ^ _rotl(x, 15) ^ _rotl(x, 23)


def _sm3_ff(x: int, y: int, z: int, j: int) -> int:
    if j < 16:
        return x ^ y ^ z
    return (x & y) | (x & z) | (y & z)


def _sm3_gg(x: int, y: int, z: int, j: int) -> int:
    if j < 16:
        return x ^ y ^ z
    return (x & y) | ((~x & 0xFFFFFFFF) & z)


def _sm3_cf(v: list, block: bytes) -> list:
    """压缩函数 CF：把 512 位消息块并入 256 位状态。"""
    w = list(struct.unpack(">16I", block))
    for j in range(16, 68):
        w.append(
            _sm3_p1(w[j - 16] ^ w[j - 9] ^ _rotl(w[j - 3], 15))
            ^ _rotl(w[j - 13], 7)
            ^ w[j - 6]
        )
    w1 = [w[j] ^ w[j + 4] for j in range(64)]

    a, b, c, d, e, f, g, h = v
    for j in range(64):
        t_j = 0x79CC4519 if j < 16 else 0x7A879D8A
        ss1 = _rotl((_rotl(a, 12) + e + _rotl(t_j, j)) & 0xFFFFFFFF, 7)
        ss2 = ss1 ^ _rotl(a, 12)
        tt1 = (_sm3_ff(a, b, c, j) + d + ss2 + w1[j]) & 0xFFFFFFFF
        tt2 = (_sm3_gg(e, f, g, j) + h + ss1 + w[j]) & 0xFFFFFFFF
        d = c
        c = _rotl(b, 9)
        b = a
        a = tt1
        h = g
        g = _rotl(f, 19)
        f = e
        e = _sm3_p0(tt2)

    return [a ^ v[0], b ^ v[1], c ^ v[2], d ^ v[3],
            e ^ v[4], f ^ v[5], g ^ v[6], h ^ v[7]]


def sm3_hash(data) -> bytes:
    """计算 SM3 摘要，返回 32 字节。"""
    msg = bytearray(_to_bytes(data))
    bit_len = len(msg) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0x00)
    msg += struct.pack(">Q", bit_len)

    v = list(_SM3_IV)
    for i in range(0, len(msg), 64):
        v = _sm3_cf(v, bytes(msg[i:i + 64]))
    return struct.pack(">8I", *v)


def sm3_hex(data) -> str:
    """计算 SM3 摘要，返回 64 位十六进制小写字符串。"""
    return sm3_hash(data).hex()


def sm3_kdf(z: bytes, klen: int) -> bytes:
    """基于 SM3 的密钥派生函数 KDF(Z, klen)，返回 klen 字节。"""
    if klen <= 0:
        return b""
    out = bytearray()
    ct = 1
    while len(out) < klen:
        out += sm3_hash(z + struct.pack(">I", ct))
        ct += 1
    return bytes(out[:klen])


# ===========================================================================
# SM4 分组密码算法（GM/T 0002-2012）
# ===========================================================================
_SM4_SBOX = (
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
)

_SM4_FK = (0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC)

_SM4_CK = (
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
    0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
    0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
    0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
    0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
    0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
    0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279,
)

_SM4_BLOCK = 16


def _sm4_sub_word(x: int) -> int:
    """S 盒逐字节代换（t 算法中的 τ 变换）。"""
    return struct.unpack(">I", bytes(_SM4_SBOX[b] for b in struct.pack(">I", x)))[0]


def _sm4_t(x: int) -> int:
    """轮函数 T（τ 代换 + L 线性变换，用于加解密轮）。"""
    y = _sm4_sub_word(x)
    return y ^ _rotl(y, 2) ^ _rotl(y, 10) ^ _rotl(y, 18) ^ _rotl(y, 24)


def _sm4_t_key(x: int) -> int:
    """密钥扩展轮 T'（τ 代换 + L' 线性变换）。"""
    y = _sm4_sub_word(x)
    return y ^ _rotl(y, 13) ^ _rotl(y, 23)


def _sm4_key_schedule(key: bytes) -> list:
    """密钥扩展，返回 32 个轮密钥。"""
    mk = list(struct.unpack(">4I", key))
    k = [mk[i] ^ _SM4_FK[i] for i in range(4)]
    rk = []
    for i in range(32):
        k.append(k[i] ^ _sm4_t_key(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ _SM4_CK[i]))
        rk.append(k[i + 4])
    return rk


def _sm4_crypt_block(block: bytes, rk: list) -> bytes:
    """单分组加解密（轮密钥顺序决定方向，解密传逆序 rk）。"""
    x = list(struct.unpack(">4I", block))
    for i in range(32):
        x.append(x[i] ^ _sm4_t(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk[i]))
    return struct.pack(">4I", x[35], x[34], x[33], x[32])


def _check_key(key: bytes) -> None:
    if len(key) != 16:
        raise GmError(f"SM4 密钥必须为 16 字节，当前 {len(key)} 字节")


def _check_iv(iv: bytes) -> None:
    if len(iv) != 16:
        raise GmError(f"SM4 初始向量 IV 必须为 16 字节，当前 {len(iv)} 字节")


def _pkcs7_pad(data: bytes) -> bytes:
    n = _SM4_BLOCK - len(data) % _SM4_BLOCK
    return data + bytes([n]) * n


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data or len(data) % _SM4_BLOCK:
        raise GmError("密文长度不是 16 字节的整数倍")
    n = data[-1]
    if n < 1 or n > _SM4_BLOCK or data[-n:] != bytes([n]) * n:
        raise GmError("PKCS7 去填充失败（密钥 / 模式可能不正确）")
    return data[:-n]


def _sm4_prepare(data: bytes, padding: bool) -> bytes:
    if padding:
        return _pkcs7_pad(data)
    if len(data) % _SM4_BLOCK:
        raise GmError("已关闭填充：数据长度必须是 16 字节的整数倍")
    return data


def sm4_ecb_encrypt(data, key, padding: bool = True) -> bytes:
    """SM4-ECB 加密。``key`` 为 16 字节。"""
    data, key = _to_bytes(data), _to_bytes(key)
    _check_key(key)
    data = _sm4_prepare(data, padding)
    rk = _sm4_key_schedule(key)
    return b"".join(_sm4_crypt_block(data[i:i + 16], rk)
                    for i in range(0, len(data), 16))


def sm4_ecb_decrypt(data, key, padding: bool = True) -> bytes:
    """SM4-ECB 解密。``key`` 为 16 字节。"""
    data, key = _to_bytes(data), _to_bytes(key)
    _check_key(key)
    if len(data) % _SM4_BLOCK:
        raise GmError("密文长度必须是 16 字节的整数倍")
    rk = _sm4_key_schedule(key)[::-1]
    out = b"".join(_sm4_crypt_block(data[i:i + 16], rk)
                   for i in range(0, len(data), 16))
    return _pkcs7_unpad(out) if padding else out


def sm4_cbc_encrypt(data, key, iv, padding: bool = True) -> bytes:
    """SM4-CBC 加密。``key`` / ``iv`` 均为 16 字节。"""
    data, key, iv = _to_bytes(data), _to_bytes(key), _to_bytes(iv)
    _check_key(key)
    _check_iv(iv)
    data = _sm4_prepare(data, padding)
    rk = _sm4_key_schedule(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), _SM4_BLOCK):
        block = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
        enc = _sm4_crypt_block(block, rk)
        out += enc
        prev = enc
    return bytes(out)


def sm4_cbc_decrypt(data, key, iv, padding: bool = True) -> bytes:
    """SM4-CBC 解密。``key`` / ``iv`` 均为 16 字节。"""
    data, key, iv = _to_bytes(data), _to_bytes(key), _to_bytes(iv)
    _check_key(key)
    _check_iv(iv)
    if len(data) % _SM4_BLOCK:
        raise GmError("密文长度必须是 16 字节的整数倍")
    rk = _sm4_key_schedule(key)[::-1]
    out = bytearray()
    prev = iv
    for i in range(0, len(data), _SM4_BLOCK):
        blk = data[i:i + 16]
        dec = _sm4_crypt_block(blk, rk)
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = blk
    return _pkcs7_unpad(bytes(out)) if padding else bytes(out)


# ===========================================================================
# SM2 椭圆曲线公钥密码算法（GM/T 0003-2012）
# ===========================================================================
_SM2_P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
_SM2_A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
_SM2_B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
_SM2_N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
_SM2_GX = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
_SM2_GY = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
_SM2_G = (_SM2_GX, _SM2_GY)

#: SM2 签名默认用户标识（GM/T 0003 推荐值）
DEFAULT_USER_ID = b"1234567812345678"

#: 密文排列顺序：C1C3C2（新标准，默认）/ C1C2C3（旧标准）
MODE_C1C3C2 = "C1C3C2"
MODE_C1C2C3 = "C1C2C3"


def _pt_add(p1, p2):
    """椭圆曲线点加（仿射坐标，``None`` 表示无穷远点）。"""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % _SM2_P == 0:
            return None
        lam = (3 * x1 * x1 + _SM2_A) * pow(2 * y1, _SM2_P - 2, _SM2_P) % _SM2_P
    else:
        lam = (y2 - y1) * pow(x2 - x1, _SM2_P - 2, _SM2_P) % _SM2_P
    x3 = (lam * lam - x1 - x2) % _SM2_P
    y3 = (lam * (x1 - x3) - y1) % _SM2_P
    return (x3, y3)


def _pt_mul(k: int, point):
    """椭圆曲线标量乘 ``k * point``（双倍-点加）。"""
    k %= _SM2_N
    result = None
    addend = point
    while k:
        if k & 1:
            result = _pt_add(result, addend)
        addend = _pt_add(addend, addend)
        k >>= 1
    return result


def _parse_pubkey(public_key):
    """把公钥解析为坐标元组。

    兼容三种输入：``(x, y)`` 坐标元组（幂等）、十六进制串（可带 ``04`` 前缀）。
    """
    if isinstance(public_key, (tuple, list)) and len(public_key) == 2:
        x, y = int(public_key[0]), int(public_key[1])
        if (y * y - (x * x * x + _SM2_A * x + _SM2_B)) % _SM2_P != 0:
            raise GmError("SM2 公钥不在指定曲线上（坐标非法）")
        return (x, y)

    pk = "".join(str(public_key).split()).replace(":", "").replace("-", "")
    if pk.lower().startswith("04") and len(pk) == 130:
        pk = pk[2:]
    if len(pk) != 128:
        raise GmError("SM2 公钥应为 128 位十六进制（x||y，可带 04 前缀）")
    try:
        x = int(pk[:64], 16)
        y = int(pk[64:], 16)
    except ValueError as exc:
        raise GmError(f"SM2 公钥不是合法十六进制：{exc}") from exc
    if (y * y - (x * x * x + _SM2_A * x + _SM2_B)) % _SM2_P != 0:
        raise GmError("SM2 公钥不在指定曲线上（坐标非法）")
    return (x, y)


def _parse_privkey(private_key: str) -> int:
    pk = "".join(str(private_key).split())
    try:
        d = int(pk, 16)
    except ValueError as exc:
        raise GmError(f"SM2 私钥不是合法十六进制：{exc}") from exc
    if not 1 <= d < _SM2_N:
        raise GmError("SM2 私钥取值范围应为 [1, n-1]")
    return d


def _fmt_point(point) -> str:
    return "%064x%064x" % (point[0], point[1])


def sm2_generate_keypair() -> tuple:
    """生成 SM2 密钥对，返回 ``(私钥 hex, 公钥 hex)``（均 64 / 128 位十六进制）。"""
    d = int.from_bytes(os.urandom(32), "big") % (_SM2_N - 1) + 1
    pub = _pt_mul(d, _SM2_G)
    return "%064x" % d, _fmt_point(pub)


def sm2_public_from_private(private_key: str) -> str:
    """由私钥推导公钥（128 位十六进制）。"""
    return _fmt_point(_pt_mul(_parse_privkey(private_key), _SM2_G))


def sm2_encrypt(data, public_key: str, mode: str = MODE_C1C3C2) -> bytes:
    """SM2 加密，返回 ``04 || C1 || C3 || C2``（或 C1C2C3）字节串。"""
    data = _to_bytes(data)
    pub = _parse_pubkey(public_key)
    c1c2c3 = str(mode).upper() == MODE_C1C2C3
    while True:
        k = int.from_bytes(os.urandom(32), "big") % (_SM2_N - 1) + 1
        c1 = _pt_mul(k, _SM2_G)
        p2 = _pt_mul(k, pub)
        if p2 is None:
            continue
        x2b = p2[0].to_bytes(32, "big")
        y2b = p2[1].to_bytes(32, "big")
        t = sm3_kdf(x2b + y2b, len(data))
        if data and not any(t):  # t 全零则重新选取随机数
            continue
        c2 = bytes(a ^ b for a, b in zip(data, t))
        c3 = sm3_hash(x2b + data + y2b)
        c1b = _fmt_point(c1)
        body = (c1b + c2.hex() + c3.hex()) if c1c2c3 else (c1b + c3.hex() + c2.hex())
        return b"\x04" + bytes.fromhex(body)


def sm2_decrypt(data, private_key: str, mode: str = MODE_C1C3C2) -> bytes:
    """SM2 解密（兼容带 / 不带 ``04`` 前缀的密文）。"""
    raw = _to_bytes(data)
    if raw[:1] == b"\x04" and len(raw) >= 1 + 64 + 32:
        raw = raw[1:]
    if len(raw) < 64 + 32:
        raise GmError("SM2 密文长度不足（至少 96 字节）")
    c1 = (int.from_bytes(raw[0:32], "big"), int.from_bytes(raw[32:64], "big"))
    rest = raw[64:]
    if str(mode).upper() == MODE_C1C2C3:
        c2, c3 = rest[:-32], rest[-32:]
    else:
        c3, c2 = rest[:32], rest[32:]

    d = _parse_privkey(private_key)
    p2 = _pt_mul(d, c1)
    if p2 is None:
        raise GmError("SM2 解密失败：密钥与密文不匹配")
    x2b = p2[0].to_bytes(32, "big")
    y2b = p2[1].to_bytes(32, "big")
    t = sm3_kdf(x2b + y2b, len(c2))
    m = bytes(a ^ b for a, b in zip(c2, t))
    if sm3_hash(x2b + m + y2b) != c3:
        raise GmError("SM2 解密校验失败（C3 不匹配，密钥 / 模式可能不正确）")
    return m


def _sm2_za(public_key, user_id: bytes = DEFAULT_USER_ID) -> bytes:
    """计算用户标识杂凑值 ZA。"""
    pub = _parse_pubkey(public_key)
    entl = struct.pack(">H", (len(user_id) * 8) & 0xFFFF)
    data = (
        entl + user_id
        + _SM2_A.to_bytes(32, "big") + _SM2_B.to_bytes(32, "big")
        + _SM2_GX.to_bytes(32, "big") + _SM2_GY.to_bytes(32, "big")
        + pub[0].to_bytes(32, "big") + pub[1].to_bytes(32, "big")
    )
    return sm3_hash(data)


def _sm2_digest(data: bytes, public_key,
                user_id: bytes = DEFAULT_USER_ID) -> bytes:
    """待签名 / 验签的消息摘要 e = SM3(ZA || M)。"""
    return sm3_hash(_sm2_za(public_key, user_id) + data)


def sm2_sign(data, private_key: str, public_key: str = "",
             user_id: bytes = DEFAULT_USER_ID) -> str:
    """SM2 签名（SM3 摘要），返回 ``r || s``（128 位十六进制）。

    ``public_key`` 省略时由私钥推导。
    """
    data = _to_bytes(data)
    d = _parse_privkey(private_key)
    pub = public_key or _fmt_point(_pt_mul(d, _SM2_G))
    e = int.from_bytes(_sm2_digest(data, pub, user_id), "big")
    d1 = pow(d + 1, _SM2_N - 2, _SM2_N)
    while True:
        k = int.from_bytes(os.urandom(32), "big") % (_SM2_N - 1) + 1
        p1 = _pt_mul(k, _SM2_G)
        r = (e + p1[0]) % _SM2_N
        if r == 0 or (r + k) % _SM2_N == 0:
            continue
        s = d1 * (k - r * d) % _SM2_N
        if s == 0:
            continue
        return "%064x%064x" % (r, s)


def sm2_verify(data, signature: str, public_key: str,
               user_id: bytes = DEFAULT_USER_ID) -> bool:
    """SM2 验签，签名格式为 ``r || s``（128 位十六进制）。"""
    data = _to_bytes(data)
    sig = "".join(str(signature).split()).replace(":", "").replace("-", "")
    if len(sig) != 128:
        raise GmError("SM2 签名应为 128 位十六进制（r||s）")
    try:
        r = int(sig[:64], 16)
        s = int(sig[64:], 16)
    except ValueError as exc:
        raise GmError(f"SM2 签名不是合法十六进制：{exc}") from exc
    if not (1 <= r < _SM2_N and 1 <= s < _SM2_N):
        return False

    pub = _parse_pubkey(public_key)
    e = int.from_bytes(_sm2_digest(data, pub, user_id), "big")
    t = (r + s) % _SM2_N
    if t == 0:
        return False
    p1 = _pt_add(_pt_mul(s, _SM2_G), _pt_mul(t, pub))
    if p1 is None:
        return False
    return r == (e + p1[0]) % _SM2_N


# ---------------------------------------------------------------------------
# 自检：官方测试向量（直接运行本模块时执行）
# ---------------------------------------------------------------------------
def _self_test() -> None:
    # -- SM3：GM/T 0004-2012 附录 A --
    assert sm3_hex("abc") == \
        "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
    assert sm3_hex("abcd" * 16) == \
        "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"

    # -- SM4：GM/T 0002-2012 附录 A.1（单分组 ECB）--
    key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    pt = bytes.fromhex("0123456789abcdeffedcba9876543210")
    ct = sm4_ecb_encrypt(pt, key, padding=False)
    assert ct.hex() == "681edf34d206965e86b3e94f536e4246", ct.hex()
    assert sm4_ecb_decrypt(ct, key, padding=False) == pt

    # -- SM4 加解密往返（PKCS7 + CBC）--
    msg = b"28zenro national crypto self test"
    assert sm4_ecb_decrypt(sm4_ecb_encrypt(msg, key), key) == msg
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    assert sm4_cbc_decrypt(sm4_cbc_encrypt(msg, key, iv), key, iv) == msg

    # -- SM2：GM/T 0003.5-2012 附录 A.2 签名示例（固定 k）--
    # 私钥 d、公钥 P、ZA、e 与标准一致；用标准给出的 k 计算 r / s 应完全吻合。
    d = "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8"
    pub = sm2_public_from_private(d)
    assert pub.upper() == (
        "09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020"
        "CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13")
    assert _sm2_za(pub).hex().upper() == (
        "B2E14C5C79C6DF5B85F4FE7ED8DB7A262B9DA7E07CCB0EA9F4747B8CCDA8A4F3")
    m = b"message digest"
    assert _sm2_digest(m, pub).hex().upper() == (
        "F0B43E94BA45ACCAACE692ED534382EB17E6AB5A19CE7B31F4486FDFC0D28640")
    k = 0x59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21
    e = int.from_bytes(_sm2_digest(m, pub), "big")
    di = pow(int(d, 16) + 1, _SM2_N - 2, _SM2_N)
    r = (e + _pt_mul(k, _SM2_G)[0]) % _SM2_N
    s = di * (k - r * int(d, 16)) % _SM2_N
    assert "%064x%064x" % (r, s) == (
        "f5a03b0648d2c4630eeac513e1bb81a15944da3827d5b74143ac7eaceee720b3"
        "b1b6aa29df212fd8763182bc0d421ca1bb9038fd1f7f42d4840b69c485bbc1aa")

    # -- SM2 随机签名 / 验签 + 加解密往返 --
    sig = sm2_sign(m, d)
    assert sm2_verify(m, sig, pub)
    assert not sm2_verify(m + b"\x00", sig, pub)

    ct2 = sm2_encrypt(msg, pub)
    assert sm2_decrypt(ct2, d) == msg
    ct3 = sm2_encrypt(msg, pub, mode=MODE_C1C2C3)
    assert sm2_decrypt(ct3, d, mode=MODE_C1C2C3) == msg
    assert sm2_decrypt(ct2[1:], d) == msg  # 兼容无 04 前缀密文

    print("gm_codec 自检通过：SM3 / SM4 / SM2 全部测试向量匹配。")


if __name__ == "__main__":
    _self_test()
