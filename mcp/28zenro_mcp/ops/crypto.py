# -*- coding: utf-8 -*-
"""cn_crypto —— 哈希 / 国密 / RSA / JWT / 密码识别工具组。

覆盖 ``lib.hash_codec`` / ``lib.hash_ext`` / ``lib.gm_codec`` /
``lib.rsa_attack`` / ``lib.jwt_codec`` / ``lib.cipher_fuzz``。全部为本地计算。

二进制参数约定
--------------
- 形如 ``key`` / ``iv`` / ``z`` / ``signing_input`` 的参数类型为 ``hex``：
  传十六进制串（可带空格、``0x``、``\\x`` 前缀），服务端自动转 bytes；
- 形如 ``data`` 的明文参数按 UTF-8 文本处理；需要传原始字节时把
  ``data_hex`` 设为 true，此时 ``data`` 按十六进制解析。
"""

from __future__ import annotations

from typing import Any

from lib import cipher_fuzz, gm_codec, hash_codec, hash_ext, jwt_codec, rsa_attack
from lib.jwt_codec import ALL_ALGORITHMS, HS_ALGORITHMS

from ..contract import (Ctx, Group, anyp, arr, custom_op, flag, hexb, make_op,
                        num, obj, txt)
from ..contract import parse_hex

_HASH_EXT_ALGOS = ("md5", "sha1", "sha256")
_SM2_MODES = ("C1C3C2", "C1C2C3")
_JWT_ALGOS = tuple(ALL_ALGORITHMS)
_HS_ALGOS = tuple(HS_ALGORITHMS)


# ---------------------------------------------------------------------------
# 国密：需要 data / key / iv 的字节级转换
# ---------------------------------------------------------------------------
def _gm_payload(a: dict[str, Any]) -> Any:
    """数据侧输入：data_hex=true 时按十六进制解析，否则按 UTF-8 文本。"""
    return parse_hex(a["data"], field="data") if a.get("data_hex") else a["data"]


def _gm_digest(fn):
    def handler(a: dict[str, Any], ctx: Ctx) -> Any:
        return fn(_gm_payload(a))
    return handler


def _gm_sm3_kdf(a: dict[str, Any], ctx: Ctx) -> Any:
    return gm_codec.sm3_kdf(parse_hex(a["z"], field="z"), a["klen"])


def _gm_sm4(fn, needs_iv: bool = False):
    def handler(a: dict[str, Any], ctx: Ctx) -> Any:
        data = _gm_payload(a)
        key = parse_hex(a["key"], field="key")
        if needs_iv:
            return fn(data, key, parse_hex(a["iv"], field="iv"),
                      padding=a["padding"])
        return fn(data, key, padding=a["padding"])
    return handler


def _gm_sm2_encrypt(a: dict[str, Any], ctx: Ctx) -> Any:
    return gm_codec.sm2_encrypt(_gm_payload(a), a["public_key"], mode=a["mode"])


def _gm_sm2_decrypt(a: dict[str, Any], ctx: Ctx) -> Any:
    return gm_codec.sm2_decrypt(parse_hex(a["data"], field="data"),
                                a["private_key"], mode=a["mode"])


def _gm_sm2_sign(a: dict[str, Any], ctx: Ctx) -> Any:
    return gm_codec.sm2_sign(_gm_payload(a), a["private_key"],
                             public_key=a["public_key"],
                             user_id=a["user_id"].encode("utf-8"))


def _gm_sm2_verify(a: dict[str, Any], ctx: Ctx) -> Any:
    return gm_codec.sm2_verify(_gm_payload(a), a["signature"], a["public_key"],
                               user_id=a["user_id"].encode("utf-8"))


# ---------------------------------------------------------------------------
# 列表型数学参数（crt / hastad）
# ---------------------------------------------------------------------------
def _to_int_list(values: list[str]) -> list[int]:
    return [rsa_attack.parse_int(value) for value in values]


def _rsa_crt(a: dict[str, Any], ctx: Ctx) -> Any:
    return rsa_attack.crt(_to_int_list(a["remainders"]), _to_int_list(a["moduli"]))


def _rsa_hastad(a: dict[str, Any], ctx: Ctx) -> Any:
    return rsa_attack.attack_hastad(_to_int_list(a["ciphertexts"]),
                                    _to_int_list(a["exponents"]), a["n"])


def _jwt_sign(a: dict[str, Any], ctx: Ctx) -> Any:
    return jwt_codec.sign(a["algorithm"], parse_hex(a["signing_input"],
                                                    field="signing_input"),
                          a["key"])


OPS = [
    # ---------------------------------------------------------------- 哈希
    make_op(hash_codec.md5_hex, "计算 MD5 摘要（32 位小写十六进制）。",
            [txt("data", required=True, desc="待摘要文本")], returns="str：MD5 十六进制",
            example={"data": "flag"}),
    make_op(hash_codec.sha1_hex, "计算 SHA-1 摘要（40 位小写十六进制）。",
            [txt("data", required=True, desc="待摘要文本")], returns="str：SHA-1 十六进制"),
    make_op(hash_codec.sha256_hex, "计算 SHA-256 摘要（64 位小写十六进制）。",
            [txt("data", required=True, desc="待摘要文本")], returns="str：SHA-256 十六进制"),
    make_op(hash_codec.sha512_hex, "计算 SHA-512 摘要（128 位小写十六进制）。",
            [txt("data", required=True, desc="待摘要文本")], returns="str：SHA-512 十六进制"),
    make_op(hash_codec.sha3_256_hex, "计算 SHA3-256 摘要（64 位小写十六进制）。",
            [txt("data", required=True, desc="待摘要文本")], returns="str：SHA3-256 十六进制"),
    make_op(hash_codec.hash_by_name, "按算法名计算摘要（md5 / sha1 / sha256 / sha512 / sha3_256）。",
            [txt("name", required=True, desc="算法名"),
             txt("data", required=True, desc="待摘要文本")],
            returns="str：摘要十六进制"),

    # -------------------------------------------------------- 哈希长度扩展
    make_op(hash_ext.length_extend,
            "哈希长度扩展攻击：已知原始摘要与 secret 长度，构造 ``append`` 之后的有效摘要。",
            [txt("algo", required=True, desc="算法", choices=_HASH_EXT_ALGOS),
             txt("original_hash", required=True, desc="原始摘要（十六进制）"),
             txt("append", required=True, desc="追加内容（原始 ASCII，不做 URL 编码）"),
             num("secret_len", required=True, desc="未知 secret 的字节长度",
                 minimum=0)],
            returns="dict：{digest, payload, padding, secret_len, algo}",
            risk="safe", notes="payload 为可直接拼进请求的伪造后缀片段。"),
    make_op(hash_ext.length_extend_full,
            "哈希长度扩展（完整版）：显式给出原始 data，自动计算 padding 并返回伪造 payload。",
            [txt("algo", required=True, desc="算法", choices=_HASH_EXT_ALGOS),
             txt("original_hash", required=True, desc="原始摘要（十六进制）"),
             txt("original_data", required=True, desc="原始消息（不含 secret 部分）"),
             txt("append", required=True, desc="追加内容"),
             num("secret_len", required=True, desc="未知 secret 的字节长度", minimum=0)],
            returns="dict：{digest, payload, padding, secret_len, algo}"),

    # ---------------------------------------------------------------- 国密
    custom_op("sm3_hash", _gm_digest(gm_codec.sm3_hash),
              "计算 SM3 摘要（输出 bytes：hex + length + text）。",
              [txt("data", required=True, desc="待摘要文本或十六进制字节"),
               flag("data_hex", default=False, desc="data 是否为十六进制字节串")],
              returns="dict：{hex, length, text, is_text}", risk="safe",
              module="lib.gm_codec"),
    custom_op("sm3_hex", _gm_digest(gm_codec.sm3_hex),
              "计算 SM3 摘要，返回 64 位小写十六进制。",
              [txt("data", required=True, desc="待摘要文本或十六进制字节"),
               flag("data_hex", default=False, desc="data 是否为十六进制字节串")],
              returns="str：SM3 十六进制", risk="safe", module="lib.gm_codec",
              example={"data": "abc"}),
    custom_op("sm3_kdf", _gm_sm3_kdf,
              "基于 SM3 的密钥派生函数 KDF(Z, klen)。",
              [hexb("z", required=True, desc="共享秘密 Z 的十六进制"),
               num("klen", required=True, desc="输出字节数", minimum=1)],
              returns="dict：{hex, length, text, is_text}", risk="safe",
              module="lib.gm_codec"),
    make_op(gm_codec.parse_hex, "把十六进制文本解析为 bytes。",
            [txt("text", required=True, desc="十六进制文本")],
            returns="dict：{hex, length, text, is_text}"),
    custom_op("sm4_ecb_encrypt", _gm_sm4(gm_codec.sm4_ecb_encrypt),
              "SM4-ECB 加密（key 必须 16 字节）。",
              [txt("data", required=True, desc="明文文本或十六进制字节"),
               flag("data_hex", default=False, desc="data 是否为十六进制字节串"),
               hexb("key", required=True, desc="16 字节密钥的十六进制（32 位）"),
               flag("padding", default=True, desc="是否使用 PKCS#7 填充")],
              returns="dict：{hex, length, text, is_text}", risk="safe",
              module="lib.gm_codec"),
    custom_op("sm4_ecb_decrypt", _gm_sm4(gm_codec.sm4_ecb_decrypt),
              "SM4-ECB 解密（密文按十六进制传入）。",
              [txt("data", required=True, desc="密文的十六进制"),
               flag("data_hex", default=True, desc="按十六进制解析 data（密文默认 true）"),
               hexb("key", required=True, desc="16 字节密钥的十六进制（32 位）"),
               flag("padding", default=True, desc="是否使用 PKCS#7 填充")],
              returns="dict：{hex, length, text, is_text}", risk="safe",
              module="lib.gm_codec"),
    custom_op("sm4_cbc_encrypt", _gm_sm4(gm_codec.sm4_cbc_encrypt, needs_iv=True),
              "SM4-CBC 加密（key / iv 均 16 字节）。",
              [txt("data", required=True, desc="明文文本或十六进制字节"),
               flag("data_hex", default=False, desc="data 是否为十六进制字节串"),
               hexb("key", required=True, desc="16 字节密钥的十六进制"),
               hexb("iv", required=True, desc="16 字节 IV 的十六进制"),
               flag("padding", default=True, desc="是否使用 PKCS#7 填充")],
              returns="dict：{hex, length, text, is_text}", risk="safe",
              module="lib.gm_codec"),
    custom_op("sm4_cbc_decrypt", _gm_sm4(gm_codec.sm4_cbc_decrypt, needs_iv=True),
              "SM4-CBC 解密。",
              [txt("data", required=True, desc="密文的十六进制"),
               flag("data_hex", default=True, desc="按十六进制解析 data（密文默认 true）"),
               hexb("key", required=True, desc="16 字节密钥的十六进制"),
               hexb("iv", required=True, desc="16 字节 IV 的十六进制"),
               flag("padding", default=True, desc="是否使用 PKCS#7 填充")],
              returns="dict：{hex, length, text, is_text}", risk="safe",
              module="lib.gm_codec"),
    make_op(gm_codec.sm2_generate_keypair, "生成 SM2 密钥对。", [],
            returns="dict：{private_key, public_key}（均为十六进制）",
            unpack=("private_key", "public_key")),
    make_op(gm_codec.sm2_public_from_private, "由 SM2 私钥推导公钥。",
            [txt("private_key", required=True, desc="64 位十六进制私钥")],
            returns="str：128 位十六进制公钥"),
    custom_op("sm2_encrypt", _gm_sm2_encrypt,
              "SM2 公钥加密（输出 C1C3C2 或 C1C2C3）。",
              [txt("data", required=True, desc="明文文本或十六进制字节"),
               flag("data_hex", default=False, desc="data 是否为十六进制字节串"),
               txt("public_key", required=True, desc="公钥十六进制（04|X|Y 或 X|Y）"),
               txt("mode", default="C1C3C2", desc="密文排列方式", choices=_SM2_MODES)],
              returns="dict：{hex, length, text, is_text}", risk="safe",
              module="lib.gm_codec"),
    custom_op("sm2_decrypt", _gm_sm2_decrypt,
              "SM2 私钥解密（密文十六进制，兼容带 / 不带 04 前缀）。",
              [txt("data", required=True, desc="密文的十六进制"),
               txt("private_key", required=True, desc="私钥十六进制"),
               txt("mode", default="C1C3C2", desc="密文排列方式", choices=_SM2_MODES)],
              returns="dict：{hex, length, text, is_text}", risk="safe",
              module="lib.gm_codec"),
    custom_op("sm2_sign", _gm_sm2_sign,
              "SM2 签名（SM3 摘要），返回 r||s 的 128 位十六进制。",
              [txt("data", required=True, desc="待签数据文本或十六进制"),
               flag("data_hex", default=False, desc="data 是否为十六进制字节串"),
               txt("private_key", required=True, desc="私钥十六进制"),
               txt("public_key", desc="公钥十六进制；留空则用默认公钥计算 ZA"),
               txt("user_id", default="1234567812345678", desc="SM2 用户标识（UTF-8）")],
              returns="str：签名（r||s）", risk="safe", module="lib.gm_codec"),
    custom_op("sm2_verify", _gm_sm2_verify, "SM2 验签。",
              [txt("data", required=True, desc="原始数据文本或十六进制"),
               flag("data_hex", default=False, desc="data 是否为十六进制字节串"),
               txt("signature", required=True, desc="签名（r||s 的 128 位十六进制）"),
               txt("public_key", required=True, desc="公钥十六进制"),
               txt("user_id", default="1234567812345678", desc="SM2 用户标识（UTF-8）")],
              returns="bool：验签结果", risk="safe", module="lib.gm_codec"),

    # ---------------------------------------------------------------- RSA
    make_op(rsa_attack.parse_int, "解析整数：支持十进制与 0x 十六进制字符串。",
            [anyp("value", required=True, desc="数字或数字字符串")],
            returns="int：解析结果"),
    make_op(rsa_attack.gcd, "最大公约数。",
            [num("a", required=True, desc="整数 a"), num("b", required=True, desc="整数 b")],
            returns="int：gcd(a, b)"),
    make_op(rsa_attack.lcm, "最小公倍数。",
            [num("a", required=True, desc="整数 a"), num("b", required=True, desc="整数 b")],
            returns="int：lcm(a, b)"),
    make_op(rsa_attack.extended_gcd, "扩展欧几里得：a*x + b*y = gcd(a, b)。",
            [num("a", required=True, desc="整数 a"), num("b", required=True, desc="整数 b")],
            returns="dict：{g, x, y}", unpack=("g", "x", "y")),
    make_op(rsa_attack.modinv, "模逆元 a⁻¹ mod m（不存在时报错）。",
            [num("a", required=True, desc="底数"), num("m", required=True, desc="模数")],
            returns="int：逆元"),
    make_op(rsa_attack.powmod, "快速幂取模 base^exp mod m。",
            [num("base", required=True, desc="底数"), num("exp", required=True, desc="指数"),
             num("mod", required=True, desc="模数")], returns="int：结果"),
    make_op(rsa_attack.euler_phi, "欧拉函数 φ(n)（试除分解，n 不要过大）。",
            [num("n", required=True, desc="正整数")], returns="int：φ(n)",
            risk="long", notes="对超大 n 会较慢；大数请先 factor。"),
    make_op(rsa_attack.integer_nth_root, "整数 k 次方根（向下取整）。",
            [num("n", required=True, desc="被开方数"),
             num("k", required=True, desc="次数", minimum=1)],
            returns="int：根"),
    make_op(rsa_attack.is_perfect_power, "判断 n 是否为某整数的 k 次幂。",
            [num("n", required=True, desc="整数"),
             num("k", required=True, desc="次数", minimum=1)],
            returns="bool：是否完全 k 次幂"),
    make_op(rsa_attack.is_prime, "确定性素性判定（Miller-Rabin）。",
            [num("n", required=True, desc="待判定整数")], returns="bool：是否素数"),
    make_op(rsa_attack.next_prime, "大于等于 n 的最小素数。",
            [num("n", required=True, desc="起点")], returns="int：素数"),
    make_op(rsa_attack.factor_trial, "试除法分解（只试除到 limit）。",
            [num("n", required=True, desc="待分解整数"),
             num("limit", default=1000000, desc="试除上限", minimum=1)],
            returns="list[int]：质因子（含重数）", risk="long"),
    make_op(rsa_attack.factor_fermat, "Fermat 分解（p、q 接近时有效，失败返回 null）。",
            [num("n", required=True, desc="待分解整数")],
            returns="dict：{p, q} 或 null", unpack=("p", "q"), risk="long"),
    make_op(rsa_attack.factor_prho, "Pollard's rho（Brent）分解，返回升序质因子。",
            [num("n", required=True, desc="待分解整数")],
            returns="list[int]：质因子", risk="long"),
    make_op(rsa_attack.factor_pm1, "Pollard's p-1 分解（p-1 为小素数幂积时有效）。",
            [num("n", required=True, desc="待分解整数"),
             num("bound", default=100000, desc="光滑界", minimum=1)],
            returns="int|null：找到的因子", risk="long"),
    make_op(rsa_attack.factor, "综合分解：试除 → Fermat → rho → p-1。",
            [num("n", required=True, desc="待分解整数"),
             flag("use_fermat", default=True, desc="启用 Fermat"),
             flag("use_prho", default=True, desc="启用 Pollard's rho"),
             flag("use_pm1", default=True, desc="启用 Pollard's p-1")],
            returns="list[int]：质因子（升序）", risk="long"),
    make_op(rsa_attack.rsa_recover_d, "由 p、q、e 恢复私钥 d。",
            [num("p", required=True, desc="素数 p"), num("q", required=True, desc="素数 q"),
             num("e", required=True, desc="公钥指数 e")],
            returns="int：私钥 d"),
    make_op(rsa_attack.rsa_private_key, "由 p、q、e 生成 PKCS#1 PEM 私钥。",
            [num("p", required=True, desc="素数 p"), num("q", required=True, desc="素数 q"),
             num("e", required=True, desc="公钥指数 e")],
            returns="str：PEM 私钥文本"),
    make_op(rsa_attack.rsa_recover_pq_from_ed, "由 n、e、d 反推 p、q。",
            [num("n", required=True, desc="模数 n"), num("e", required=True, desc="公钥指数"),
             num("d", required=True, desc="私钥指数")],
            returns="dict：{p, q}", unpack=("p", "q")),
    make_op(rsa_attack.attack_common_modulus, "共模攻击：同一 m、同一 n、不同 e 得到 c1 / c2。",
            [num("c1", required=True, desc="密文 c1"), num("c2", required=True, desc="密文 c2"),
             num("e1", required=True, desc="指数 e1"), num("e2", required=True, desc="指数 e2"),
             num("n", required=True, desc="公共模数 n")],
            returns="int：明文 m（配合 int_to_text 还原）", risk="safe"),
    make_op(rsa_attack.attack_low_exponent,
            "低加密指数攻击：c = m^e 且 m^e < n（无模约简）时直接开 e 次方。",
            [num("c", required=True, desc="密文 c"), num("e", required=True, desc="指数 e"),
             num("n", required=True, desc="模数 n")], returns="int：明文 m"),
    make_op(rsa_attack.attack_wiener, "Wiener 攻击：d 较小时用连分数恢复 d（失败返回 null）。",
            [num("n", required=True, desc="模数 n"), num("e", required=True, desc="指数 e")],
            returns="int|null：私钥 d"),
    custom_op("attack_hastad", _rsa_hastad,
              "Håstad 广播攻击：同一 m、相同 e、不同 n 的密文列表。",
              [arr("ciphertexts", required=True, desc="密文列表（十进制或 0x 十六进制）"),
               arr("exponents", required=True, desc="指数列表（通常每个都是 3）"),
               num("n", required=True, desc="模数 n")],
              returns="int：明文 m", risk="safe", module="lib.rsa_attack"),
    make_op(rsa_attack.int_to_bytes, "整数 -> 最小长度大端字节串。",
            [num("n", required=True, desc="非负整数")],
            returns="dict：{hex, length, text, is_text}"),
    make_op(rsa_attack.int_to_text, "整数 -> UTF-8 文本（失败回退十六进制）。",
            [num("n", required=True, desc="非负整数")], returns="str：文本"),
    make_op(rsa_attack.text_to_int, "文本 -> 整数（UTF-8 大端）。",
            [txt("text", required=True, desc="文本")], returns="int：整数"),
    custom_op("crt", _rsa_crt,
              "中国剩余定理：解 x ≡ r_i (mod m_i)，返回最小非负解。",
              [arr("remainders", required=True, desc="余数列表"),
               arr("moduli", required=True, desc="模数列表（两两互素）")],
              returns="int：最小非负解", risk="safe", module="lib.rsa_attack"),

    # ---------------------------------------------------------------- JWT
    make_op(jwt_codec.parse, "解析 JWT（不校验签名），返回 header / payload / 原始分段。",
            [txt("token", required=True, desc="JWT 字符串")],
            returns=("dict：{header, payload, signature(hex), header_raw, payload_raw, "
                     "signature_raw, algorithm, extra}")),
    make_op(jwt_codec.verify, "校验 JWT 签名。",
            [txt("token", required=True, desc="JWT 字符串"),
             txt("key", default="", desc="HMAC 密钥或 PEM 公钥")],
            returns="bool：是否通过校验"),
    make_op(jwt_codec.create, "创建并签名 JWT。",
            [obj("header", required=True, desc="header 对象，如 {\"alg\":\"HS256\",\"typ\":\"JWT\"}"),
             obj("payload", required=True, desc="payload 对象"),
             txt("key", default=None, desc="签名密钥；alg=none 时留空"),
             txt("algorithm", default="HS256", desc="签名算法", choices=_JWT_ALGOS)],
            returns="str：JWT 字符串"),
    make_op(jwt_codec.resign, "重签 JWT：保留 header / payload，可换算法或密钥。",
            [txt("token", required=True, desc="原 JWT"),
             txt("key", default=None, desc="新密钥；留空沿用空密钥"),
             txt("algorithm", default=None, desc="新算法；留空沿用原算法",
                 choices=_JWT_ALGOS)],
            returns="str：新 JWT"),
    custom_op("sign", _jwt_sign, "对任意 signing_input 按算法签名（底层能力）。",
              [txt("algorithm", required=True, desc="签名算法", choices=_JWT_ALGOS),
               hexb("signing_input", required=True, desc="待签字节的十六进制"),
               txt("key", default="", desc="密钥 / PEM")],
              returns="dict：{hex, length, text, is_text}", risk="safe",
              module="lib.jwt_codec"),
    make_op(jwt_codec.hs_bruteforce,
            "HS256 弱密钥爆破：遍历候选密钥，用 HMAC 验签找出正确密钥。",
            [txt("token", required=True, desc="JWT 字符串"),
             arr("candidates", required=True, desc="候选密钥列表")],
            returns="str|null：命中的密钥", risk="long"),
    make_op(jwt_codec.alg_confusion_rs_to_hs,
            "算法混淆攻击：用 RSA 公钥 PEM 伪造 HS256 令牌。",
            [obj("payload", required=True, desc="payload 对象"),
             txt("public_key_pem", required=True, desc="RSA 公钥 PEM 文本"),
             txt("hs_alg", default="HS256", desc="HMAC 算法", choices=_HS_ALGOS)],
            returns="str：伪造的 JWT"),
    make_op(jwt_codec.inject_header, "注入 header 字段（kid / jku 等）并重签。",
            [txt("token", required=True, desc="原 JWT"),
             obj("extra_header", required=True, desc="要注入的 header 字段"),
             txt("key", default=None, desc="签名密钥；留空沿用空密钥"),
             txt("algorithm", default=None, desc="新算法；留空沿用原算法",
                 choices=_JWT_ALGOS)],
            returns="str：新 JWT"),
    make_op(jwt_codec.now_timestamp, "当前 Unix 秒（填 iat / exp 用）。", [],
            returns="int：Unix 时间戳"),
    make_op(jwt_codec.b64url_encode, "Base64URL 编码（输入十六进制字节）。",
            [hexb("data", required=True, desc="原始字节的十六进制")],
            returns="str：Base64URL 字符串"),
    make_op(jwt_codec.b64url_decode, "Base64URL 解码（输出 bytes）。",
            [txt("text", required=True, desc="Base64URL 字符串")],
            returns="dict：{hex, length, text, is_text}"),
    make_op(jwt_codec.pretty, "把对象美化为缩进 JSON（中文不转义）。",
            [anyp("obj", required=True, desc="任意 JSON 值")], returns="str：美化 JSON"),
    make_op(jwt_codec.coerce_claim_value, "把字符串声明值转成合适的 JSON 类型。",
            [txt("text", required=True, desc="声明值文本")], returns="任意：转换后的值"),

    # ---------------------------------------------------------- 密码识别 Fuzz
    make_op(cipher_fuzz.run,
            "把 lib 里所有可解密方法跑一遍，按「可读性」降序返回候选明文。",
            [txt("text", required=True, desc="待识别密文"),
             txt("key", desc="需要密钥的方法（如凯撒）使用的密钥 / 位移"),
             num("offset", default=None, desc="ROT 类方法的固定位移；留空自动遍历",
                 minimum=-64, maximum=64),
             arr("targets", default=(), desc="限定只跑指定方法名（留空跑全部）"),
             flag("dedupe", default=True, desc="结果去重")],
            returns="dict：{hits: [{method, text, score}], tried, ...}",
            risk="long", notes="对超长密文会自动截断分析；结果按得分排序。"),
    make_op(cipher_fuzz.readability, "给一段输出打「像不像明文」的分（0~1）。",
            [txt("text", required=True, desc="待评分文本")], returns="float：0~1"),
]


GROUP = Group(
    name="cn_crypto",
    title="哈希 / 国密(SM) / RSA / JWT / 密码识别",
    summary=("MD5/SHA/SHA3 摘要与哈希长度扩展；SM3/SM4/SM2 全套国密；"
             "RSA 分解与常见攻击（共模、低指数、Wiener、Håstad、CRT）；"
             "JWT 解析/签发/弱密钥爆破/算法混淆；密文自动识别 Fuzz。"),
    ops=OPS,
    guide=("字节级参数（key / iv / z / signing_input）用十六进制传；明文参数按 UTF-8，"
           "需要原始字节时加 data_hex=true。大整数直接传十进制或 0x 前缀，"
           "返回的大整数是 JSON number（可能很长）。"),
)
