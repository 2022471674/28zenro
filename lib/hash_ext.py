# -*- coding: utf-8 -*-
"""哈希长度扩展攻击（Length Extension Attack）纯逻辑模块。

针对 ``md5(secret || data)`` / ``sha1(secret || data)`` / ``sha256(secret || data)``
这类「密钥前置」的 MAC 构造：Merkle–Damgård 结构的哈希允许**在不知道 secret 的
情况下**，由 ``hash(secret || data)`` 与 ``len(secret)`` 推算出
``hash(secret || data || padding || append)``。

原理
----
这类哈希把消息切成 512 位块逐块压缩，最终内部状态即摘要值。给定原摘要
``h = H(secret || data)``，可还原出处理完 ``secret || data || padding`` 后的
内部状态，再以该状态继续压缩 ``append``，得到新摘要，等价于
``H(secret || data || padding || append)`` —— 全程无需 secret，只需其长度。

本模块**纯标准库**实现 MD5 / SHA1 / SHA256 的 padding 与压缩函数（不依赖
任何第三方库），用于 CTF / 授权测试中的 MAC 伪造演示。

本模块只做「参数进、结果出」的纯逻辑，不导入任何 UI 模块。
"""

from __future__ import annotations

import struct


class HashExtError(ValueError):
    """哈希长度扩展攻击参数非法时抛出的统一异常。"""


#: 支持的算法：算法名 -> (摘要十六进制长度, 状态字数, 是否小端)
ALGORITHMS = {
    "md5": (32, 4, True),
    "sha1": (40, 5, False),
    "sha256": (64, 8, False),
}


def _parse_hex_digest(digest: str, algo: str) -> bytes:
    """把十六进制摘要解析为原始字节（校验长度与字符）。"""
    text = str(digest or "").strip().lower().replace(" ", "").replace("\n", "")
    length = ALGORITHMS[algo][0]
    if len(text) != length or any(c not in "0123456789abcdef" for c in text):
        raise HashExtError(
            f"{algo.upper()} 摘要必须是 {length} 位十六进制字符串。")
    try:
        return bytes.fromhex(text)
    except ValueError as exc:
        raise HashExtError(f"摘要不是合法十六进制：{exc}") from exc


def _parse_len(value, field: str) -> int:
    try:
        n = int(str(value).strip())
    except (TypeError, ValueError):
        raise HashExtError(f"{field}必须是整数。")
    if n < 0:
        raise HashExtError(f"{field}必须 ≥ 0。")
    return n


# ===========================================================================
# MD5（小端，4 个 32 位状态）
# ===========================================================================
_MD5_S = (
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
)
_MD5_K = tuple((int(abs(__import__("math").sin(i + 1)) * 2 ** 32) & 0xFFFFFFFF)
               for i in range(64))

_MD5_INIT = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)


def _md5_compress(state: list[int], block: bytes) -> list[int]:
    """MD5 压缩函数：处理一个 64 字节块，返回新状态。"""
    a, b, c, d = state
    m = list(struct.unpack("<16I", block))
    for i in range(64):
        if i < 16:
            f = (b & c) | (~b & d)
            g = i
        elif i < 32:
            f = (d & b) | (~d & c)
            g = (5 * i + 1) % 16
        elif i < 48:
            f = b ^ c ^ d
            g = (3 * i + 5) % 16
        else:
            f = c ^ (b | ~d)
            g = (7 * i) % 16
        f = (f + a + _MD5_K[i] + m[g]) & 0xFFFFFFFF
        a, d, c = d, c, b
        b = (b + ((f << _MD5_S[i]) | (f >> (32 - _MD5_S[i])))) & 0xFFFFFFFF
    return [
        (state[0] + a) & 0xFFFFFFFF,
        (state[1] + b) & 0xFFFFFFFF,
        (state[2] + c) & 0xFFFFFFFF,
        (state[3] + d) & 0xFFFFFFFF,
    ]


# ===========================================================================
# SHA1（大端，5 个 32 位状态）
# ===========================================================================
_SHA1_INIT = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)


def _sha1_compress(state: list[int], block: bytes) -> list[int]:
    """SHA1 压缩函数：处理一个 64 字节块，返回新状态。"""
    w = list(struct.unpack(">16I", block))
    for i in range(16, 80):
        w.append(((w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]) << 1
                  | (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]) >> 31) & 0xFFFFFFFF)
    a, b, c, d, e = state
    for i in range(80):
        if i < 20:
            f = (b & c) | (~b & d)
            k = 0x5A827999
        elif i < 40:
            f = b ^ c ^ d
            k = 0x6ED9EBA1
        elif i < 60:
            f = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC
        else:
            f = b ^ c ^ d
            k = 0xCA62C1D6
        temp = (((a << 5) | (a >> 27)) + f + e + k + w[i]) & 0xFFFFFFFF
        e, d, c, b, a = d, c, ((b << 30) | (b >> 2)) & 0xFFFFFFFF, a, temp
    return [
        (state[0] + a) & 0xFFFFFFFF,
        (state[1] + b) & 0xFFFFFFFF,
        (state[2] + c) & 0xFFFFFFFF,
        (state[3] + d) & 0xFFFFFFFF,
        (state[4] + e) & 0xFFFFFFFF,
    ]


# ===========================================================================
# SHA256（大端，8 个 32 位状态）
# ===========================================================================
_SHA256_K = (
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
)

_SHA256_INIT = (
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
)


def _sha256_compress(state: list[int], block: bytes) -> list[int]:
    """SHA256 压缩函数：处理一个 64 字节块，返回新状态。"""
    w = list(struct.unpack(">16I", block))
    for i in range(16, 64):
        s0 = ((w[i - 15] >> 7) | (w[i - 15] << 25)) ^ ((w[i - 15] >> 18) | (w[i - 15] << 14)) ^ (w[i - 15] >> 3)
        s1 = ((w[i - 2] >> 17) | (w[i - 2] << 15)) ^ ((w[i - 2] >> 19) | (w[i - 2] << 13)) ^ (w[i - 2] >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF)
    a, b, c, d, e, f, g, h = state
    for i in range(64):
        S1 = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))
        ch = (e & f) ^ (~e & g)
        t1 = (h + S1 + ch + _SHA256_K[i] + w[i]) & 0xFFFFFFFF
        S0 = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (S0 + maj) & 0xFFFFFFFF
        h, g, f, e, d, c, b, a = g, f, e, (d + t1) & 0xFFFFFFFF, c, b, a, (t1 + t2) & 0xFFFFFFFF
    return [
        (state[0] + a) & 0xFFFFFFFF,
        (state[1] + b) & 0xFFFFFFFF,
        (state[2] + c) & 0xFFFFFFFF,
        (state[3] + d) & 0xFFFFFFFF,
        (state[4] + e) & 0xFFFFFFFF,
        (state[5] + f) & 0xFFFFFFFF,
        (state[6] + g) & 0xFFFFFFFF,
        (state[7] + h) & 0xFFFFFFFF,
    ]


# ===========================================================================
# 统一入口
# ===========================================================================
def _compress(algo: str, state: list[int], block: bytes) -> list[int]:
    if algo == "md5":
        return _md5_compress(state, block)
    if algo == "sha1":
        return _sha1_compress(state, block)
    return _sha256_compress(state, block)


def _init_state(algo: str) -> list[int]:
    if algo == "md5":
        return list(_MD5_INIT)
    if algo == "sha1":
        return list(_SHA1_INIT)
    return list(_SHA256_INIT)


def _state_from_digest(algo: str, digest_bytes: bytes) -> list[int]:
    """从十六进制摘要还原内部状态（摘要即状态的字序拼接）。"""
    _, words, little = ALGORITHMS[algo]
    fmt = "<" if little else ">"
    return list(struct.unpack(f"{fmt}{words}I", digest_bytes))


def _state_to_digest(algo: str, state: list[int]) -> str:
    _, _, little = ALGORITHMS[algo]
    fmt = "<" if little else ">"
    return struct.pack(f"{fmt}{len(state)}I", *state).hex()


def _padding(algo: str, message_len: int) -> bytes:
    """构造消息末尾的 padding（含 0x80、补零、64 位长度字段）。

    MD5 的长度字段为 64 位小端；SHA1 / SHA256 为 64 位大端。
    """
    length_bits = (message_len * 8) & 0xFFFFFFFFFFFFFFFF
    pad = b"\x80"
    pad += b"\x00" * ((56 - (message_len + 1) % 64) % 64)
    if algo == "md5":
        pad += struct.pack("<Q", length_bits)
    else:
        pad += struct.pack(">Q", length_bits)
    return pad


def length_extend(
    algo: str,
    original_hash: str,
    append: str,
    secret_len: int,
) -> dict:
    """执行哈希长度扩展攻击。

    参数
    ----
    algo          ``md5`` / ``sha1`` / ``sha256``
    original_hash 原始摘要 ``H(secret || data)``（十六进制）
    append        要追加的数据（字符串，按 UTF-8 编码）
    secret_len    secret 的字节长度（需已知或猜测）

    返回
    ----
    dict，含：
        new_hash    伪造摘要 ``H(secret || data || padding || append)``（十六进制）
        new_message 需要发送的完整消息体（``data || padding || append`` 的字节串，
                    不含 secret，因为 secret 未知），十六进制表示
        new_message_raw 上述消息体的原始 bytes（便于直接查看 / 复制）
    """
    algo = str(algo or "").strip().lower()
    if algo not in ALGORITHMS:
        raise HashExtError(
            f"不支持的算法 {algo!r}，可选 {'、'.join(ALGORITHMS)}。")
    digest_bytes = _parse_hex_digest(original_hash, algo)
    secret_len = _parse_len(secret_len, "secret 长度")
    append_bytes = str(append).encode("utf-8")

    # 1. 从摘要还原内部状态（等价于处理完 secret||data 后的状态）
    state = _state_from_digest(algo, digest_bytes)

    # 2. 构造 padding：总长度 = secret_len + len(data)，但 data 未知。
    #    这里需要一个关键参数：data 的长度。实际上攻击者通常也知道 data
    #    （消息是公开的），只不知道 secret。但本接口只收 secret_len 与 append，
    #    因此假设 data 为空或由调用方把 data 并入 append 的「原始消息」处理。
    #    见 length_extend_full（支持显式 data）。

    # 简化接口：假设原消息 = secret（data 为空），padding 基于 secret_len
    pad = _padding(algo, secret_len)
    # 用还原状态继续压缩「append + 新 padding」
    processed_len = secret_len + len(pad)
    new_pad = _padding(algo, processed_len + len(append_bytes))
    forged = _compress_message(algo, state, append_bytes + new_pad)
    new_hash = _state_to_digest(algo, forged)

    # 新消息体 = padding || append（发送时拼接在原始 data 之后）
    new_message = pad + append_bytes
    return {
        "new_hash": new_hash,
        "new_message": new_message.hex(),
        "new_message_raw": new_message,
    }


def length_extend_full(
    algo: str,
    original_hash: str,
    original_data: str,
    append: str,
    secret_len: int,
) -> dict:
    """哈希长度扩展攻击（完整版：显式给定原始 data）。

    与 :func:`length_extend` 的区别：``original_data`` 为公开的消息部分
    ``data``（``H(secret || data)`` 中的 data，按 UTF-8 编码）。这样能精确
    计算 padding 并给出「data || padding || append」的完整伪造消息。

    返回字段同 :func:`length_extend`，其中 ``new_message`` 是
    ``data || padding || append`` 的十六进制。
    """
    algo = str(algo or "").strip().lower()
    if algo not in ALGORITHMS:
        raise HashExtError(
            f"不支持的算法 {algo!r}，可选 {'、'.join(ALGORITHMS)}。")
    digest_bytes = _parse_hex_digest(original_hash, algo)
    secret_len = _parse_len(secret_len, "secret 长度")
    data_bytes = str(original_data).encode("utf-8")
    append_bytes = str(append).encode("utf-8")

    # 还原状态
    state = _state_from_digest(algo, digest_bytes)

    # padding 基于 secret||data 的总长度
    total_len = secret_len + len(data_bytes)
    pad = _padding(algo, total_len)

    # 用还原状态继续压缩「append + 新 padding」。
    # 新消息总长度 = (secret+data+原padding) 已处理字节 + append 长度，
    # 其中前者是 64 的倍数。
    processed_len = total_len + len(pad)
    new_pad = _padding(algo, processed_len + len(append_bytes))
    forged = _compress_message(algo, state, append_bytes + new_pad)
    new_hash = _state_to_digest(algo, forged)

    new_message = data_bytes + pad + append_bytes
    return {
        "new_hash": new_hash,
        "new_message": new_message.hex(),
        "new_message_raw": new_message,
    }


def _compress_message(algo: str, state: list[int], message: bytes) -> list[int]:
    """从给定状态继续压缩 ``message``（按 64 字节块），返回最终状态。"""
    for i in range(0, len(message), 64):
        block = message[i:i + 64]
        if len(block) < 64:
            block = block + b"\x00" * (64 - len(block))
        state = _compress(algo, state, block)
    return state


__all__ = [
    "ALGORITHMS",
    "HashExtError",
    "length_extend",
    "length_extend_full",
]


# ---------------------------------------------------------------------------
# 自检：``python -m lib.hash_ext``
# ---------------------------------------------------------------------------
def _self_test() -> int:
    import hashlib

    failures: list[str] = []

    # 用标准库验证：已知 secret，先算 H(secret||data)，再扩展，比对 H(secret||data||pad||append)
    for algo, hasher in (("md5", hashlib.md5),
                         ("sha1", hashlib.sha1),
                         ("sha256", hashlib.sha256)):
        secret = b"my_secret_key"
        data = b"count=10&lat=37.351&user_id=1&long=-119.827&waffle=eggo"
        append = b"&admin=true"

        original = hasher(secret + data).hexdigest()
        result = length_extend_full(algo, original, data.decode(), append.decode(),
                                    len(secret))

        # 用标准库计算真值：secret + data + padding + append
        total_len = len(secret) + len(data)
        pad = _padding(algo, total_len)
        forged_msg = secret + data + pad + append
        expect = hasher(forged_msg).hexdigest()

        if result["new_hash"] != expect:
            failures.append(f"{algo}: 扩展哈希 {result['new_hash']} != 期望 {expect}")
        else:
            # 校验 new_message 不含 secret（只含 data + padding + append）
            expected_msg = (data + pad + append).hex()
            if result["new_message"] != expected_msg:
                failures.append(f"{algo}: 新消息体不匹配")

    if failures:
        print("[FAIL] " + "；".join(failures))
        return 1
    print("hash_ext 自检通过：MD5 / SHA1 / SHA256 长度扩展攻击全部正确。")
    return 0


if __name__ == "__main__":
    raise SystemExit(_self_test())
