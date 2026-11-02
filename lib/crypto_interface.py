# -*- coding: utf-8 -*-
"""HTTP 请求器的「密码学循环接口」。

CTF 里最耗时间的一步是：拿到明文 / 单词 → 用某算法加密 / 编码 → 塞进接口
参数 → 看响应。本模块把项目里**全部能正向计算**的加密 / 编码工具收成一组
「载荷生成器」（:class:`CryptoOp`），供请求器的循环模式一键把明文列表变成
密文载荷列表：

    http_requester 的循环模式 ──► 密码学接口 ──► lib 里的 enc 函数
         载荷列表  ◄──────────── 变换函数 ◄────

设计约定（与 ``app/registry.py`` 的 ``ToolSpec`` 保持同源，避免两处维护）：

- 只收录**有正向函数**（``ToolSpec.enc``）的工具；纯解码类（URL 解码、
  ASCII 反解）与需要异步任务的（哈希爆破）不收录；
- 工具自己的参数（凯撒位移、Base85 变体…）在这里声明，值由调用方给定，
  缺省取登记表里的默认值；
- 某个载荷算失败（如非法字符、key 长度不对）时不中断整批循环，把错误
  记进 :class:`CryptoResult.errors` 并原样保留输入，便于对照。

本模块不导入任何 UI 模块，也不自行发起网络请求。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Sequence

from lib import char_codec, hash_codec, rot_codec, string_codec
from lib import base_codec

# ---------------------------------------------------------------------------
# 登记表用到的常量（不依赖 app 包，避免 lib -> app 的反向依赖）
# ---------------------------------------------------------------------------
PTYPE_INT = "int"
PTYPE_STR = "str"
PTYPE_SELECT = "select"

#: Base85 / Base91 之类的变体选项
BASE85_VARIANTS: tuple[tuple[str, str], ...] = (
    ("b85", "b85（Python base64.b85，CTF 常见）"),
    ("a85", "ascii85（Adobe / PDF）"),
    ("z85", "z85（ZeroMQ）"),
)


class CryptoParamError(ValueError):
    """密码学接口参数不合法。"""


# ---------------------------------------------------------------------------
# 契约
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class CryptoParam:
    """载荷生成器的一个参数声明（界面据此渲染控件）。"""

    key: str
    label: str = ""
    ptype: str = PTYPE_STR
    default: Any = ""
    minimum: int | None = None
    maximum: int | None = None
    choices: tuple[tuple[str, str], ...] = ()
    hint: str = ""

    @property
    def effective_label(self) -> str:
        return self.label or self.key

    def coerce(self, raw: Any) -> Any:
        """按 ptype 把外部输入转成函数实参。"""
        if self.ptype == PTYPE_INT:
            try:
                value = int(str(raw).strip() if not isinstance(raw, int) else raw)
            except (TypeError, ValueError) as exc:
                raise CryptoParamError(
                    f"参数 {self.effective_label} 需要整数，收到 {raw!r}") from exc
            if self.minimum is not None and value < self.minimum:
                raise CryptoParamError(
                    f"参数 {self.effective_label} 不能小于 {self.minimum}")
            if self.maximum is not None and value > self.maximum:
                raise CryptoParamError(
                    f"参数 {self.effective_label} 不能大于 {self.maximum}")
            return value
        if self.ptype == PTYPE_SELECT and self.choices:
            allowed = {value for value, _label in self.choices}
            text = str(raw)
            if text not in allowed:
                raise CryptoParamError(
                    f"参数 {self.effective_label} 取值 {text!r} 非法"
                    f"（可选 {', '.join(sorted(allowed))}）")
            return text
        return "" if raw is None else str(raw)

    @property
    def default_value(self) -> Any:
        """未显式给值时的实参。"""
        if self.ptype == PTYPE_INT and self.default == "":
            return 0
        return self.default


@dataclass(frozen=True)
class CryptoOp:
    """一个「明文 → 密文」的载荷生成器。"""

    op_id: str
    label: str
    group: str
    fn: Callable[..., Any]
    params: tuple[CryptoParam, ...] = ()
    #: 输出形态：``text`` 文本 / ``hex`` 十六进制 / ``bytes`` 原始字节
    output: str = "text"
    desc: str = ""

    def run(self, data: str, values: dict[str, Any] | None = None) -> str:
        """执行一次变换，返回字符串载荷。"""
        args: dict[str, Any] = {}
        given = values or {}
        for param in self.params:
            raw = given.get(param.key, param.default_value)
            args[param.key] = param.coerce(raw)
        try:
            result = self.fn(data, **args)
        except CryptoParamError:
            raise
        except Exception as exc:  # noqa: BLE001 - lib 异常统一转人话
            raise CryptoParamError(f"{type(exc).__name__}: {exc}") from exc
        return _to_text(result)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.op_id,
            "label": self.label,
            "group": self.group,
            "output": self.output,
            "description": self.desc,
            "params": [
                {
                    "key": param.key,
                    "label": param.effective_label,
                    "type": param.ptype,
                    "default": param.default,
                    "minimum": param.minimum,
                    "maximum": param.maximum,
                    "choices": [list(item) for item in param.choices],
                    "hint": param.hint,
                }
                for param in self.params
            ],
        }


def _to_text(result: Any) -> str:
    """把 lib 返回值统一成字符串载荷（bytes 转十六进制）。"""
    if isinstance(result, str):
        return result
    if isinstance(result, (bytes, bytearray)):
        return bytes(result).hex()
    return str(result)


# ---------------------------------------------------------------------------
# Base 系列：把 enc 函数批量登记成生成器
# ---------------------------------------------------------------------------
def _base_ops() -> list[CryptoOp]:
    simple = (
        ("base64", "Base64 编码", base_codec.base64_encrypt),
        ("base64url", "URLSafe Base64 编码", base_codec.base64_urlsafe_encrypt),
        ("base32", "Base32 编码", base_codec.base32_encrypt),
        ("base16", "Base16（HEX）编码", base_codec.base16_encrypt),
        ("base58", "Base58 编码", base_codec.base58_encrypt),
        ("base62", "Base62 编码", base_codec.base62_encrypt),
        ("base91", "Base91 编码", base_codec.base91_encrypt),
        ("base92", "Base92 编码", base_codec.base92_encrypt),
        ("uuencode", "UUencode 编码", base_codec.uuencode_encrypt),
        ("xxencode", "XXencode 编码", base_codec.xxencode_encrypt),
    )
    ops = [CryptoOp(op_id=f"crypto.{key}", label=label, group="Base 编码",
                    fn=fn, desc=f"{label}（lib.base_codec）")
           for key, label, fn in simple]
    ops.append(CryptoOp(
        op_id="crypto.base85", label="Base85 编码", group="Base 编码",
        fn=base_codec.base85_encrypt,
        params=(CryptoParam("variant", "变体", PTYPE_SELECT, "b85",
                            choices=BASE85_VARIANTS,
                            hint="b85 / ascii85 / z85"),),
        desc="Base85 编码，可选 b85 / ascii85 / z85 变体（lib.base_codec）"))
    return ops


# ---------------------------------------------------------------------------
# 哈希
# ---------------------------------------------------------------------------
def _hash_ops() -> list[CryptoOp]:
    return [
        CryptoOp(op_id="hash.md5", label="MD5（hex）", group="哈希",
                 fn=hash_codec.md5_hex, desc="32 位小写十六进制摘要"),
        CryptoOp(op_id="hash.sha1", label="SHA1（hex）", group="哈希",
                 fn=hash_codec.sha1_hex, desc="40 位十六进制摘要"),
        CryptoOp(op_id="hash.sha256", label="SHA256（hex）", group="哈希",
                 fn=hash_codec.sha256_hex, desc="64 位十六进制摘要"),
        CryptoOp(op_id="hash.sha512", label="SHA512（hex）", group="哈希",
                 fn=hash_codec.sha512_hex, desc="128 位十六进制摘要"),
        CryptoOp(op_id="hash.sha3_256", label="SHA3-256（hex）", group="哈希",
                 fn=hash_codec.sha3_256_hex, desc="64 位十六进制摘要"),
    ]


# ---------------------------------------------------------------------------
# 古典密码 / 字符串变换
# ---------------------------------------------------------------------------
def _classic_ops() -> list[CryptoOp]:
    return [
        CryptoOp(op_id="classic.caesar", label="凯撒密码（位移）", group="古典 / 移位",
                 fn=char_codec.caesar_encrypt,
                 params=(CryptoParam("shift", "位移量", PTYPE_INT, 3,
                                     minimum=0, maximum=25),),
                 desc="字母表整体位移，0-25"),
        CryptoOp(op_id="classic.rot13", label="ROT13", group="古典 / 移位",
                 fn=rot_codec.rot13_encrypt, desc="字母 13 位移位"),
        CryptoOp(op_id="classic.rot47", label="ROT47", group="古典 / 移位",
                 fn=rot_codec.rot47_encrypt, desc="可打印 ASCII 47 位移位"),
        CryptoOp(op_id="classic.rot_n", label="ROT-N（任意位移）", group="古典 / 移位",
                 fn=rot_codec.rot_n,
                 params=(CryptoParam("shift", "位移量", PTYPE_INT, 13,
                                     minimum=0, maximum=94),),
                 desc="通用 ROT 移位"),
        CryptoOp(op_id="classic.pigpen", label="猪圈密码", group="古典 / 移位",
                 fn=char_codec.pigpen_encrypt, desc="猪圈符号替换"),
        CryptoOp(op_id="str.url_encode", label="URL 编码（保留英文数字）",
                 group="字符串", fn=string_codec.url_encode,
                 desc="对非字母数字字符做百分号编码"),
        CryptoOp(op_id="str.url_encode_full", label="URL 全编码（含英文）",
                 group="字符串", fn=string_codec.url_encode_full,
                 desc="对全部字符做百分号编码"),
        CryptoOp(op_id="str.ascii", label="字符串转 ASCII（十进制码点）",
                 group="字符串", fn=string_codec.str_to_ascii,
                 desc="每个字符转十进制码点"),
        CryptoOp(op_id="str.lower", label="转小写", group="字符串",
                 fn=string_codec.to_lower, desc="全部字母转小写"),
        CryptoOp(op_id="str.upper", label="转大写", group="字符串",
                 fn=string_codec.to_upper, desc="全部字母转大写"),
        CryptoOp(op_id="str.quoted_printable", label="Quoted-printable 编码",
                 group="字符串", fn=string_codec.quoted_printable_encode,
                 desc="QP 编码"),
        CryptoOp(op_id="str.html_entity", label="HTML 实体编码", group="字符串",
                 fn=string_codec.html_entity_encode, desc="&amp; 这类实体转义"),
        CryptoOp(op_id="str.unicode_escape", label="Unicode 转义编码",
                 group="字符串", fn=string_codec.unicode_escape_encode,
                 desc="\\uXXXX 形式"),
    ]


# ---------------------------------------------------------------------------
# 国密（SM3 / SM4 / SM2）
# ---------------------------------------------------------------------------
def _gm_ops() -> list[CryptoOp]:
    try:
        from lib import gm_codec
    except Exception:  # noqa: BLE001 - 可选依赖缺失时整组跳过
        return []

    def _hex_encode(enc: bytes) -> str:
        return bytes(enc).hex()

    return [
        CryptoOp(op_id="gm.sm3", label="SM3 摘要（hex）", group="国密",
                 fn=g_sm3, desc="国密 SM3 哈希，64 位十六进制", output="hex"),
        CryptoOp(op_id="gm.sm4_ecb", label="SM4 ECB 加密（hex）", group="国密",
                 fn=g_sm4_ecb, output="hex",
                 params=(CryptoParam("key", "16 字节密钥", PTYPE_STR, "",
                                     hint="32 位 hex 或 16 字符"),
                         CryptoParam("padding", "PKCS7 填充", PTYPE_SELECT, "1",
                                     choices=(("1", "开启"), ("0", "关闭")))),
                 desc="国密 SM4 ECB，输出十六进制"),
        CryptoOp(op_id="gm.sm4_cbc", label="SM4 CBC 加密（hex）", group="国密",
                 fn=g_sm4_cbc, output="hex",
                 params=(CryptoParam("key", "16 字节密钥", PTYPE_STR, ""),
                         CryptoParam("iv", "16 字节 IV", PTYPE_STR, ""),
                         CryptoParam("padding", "PKCS7 填充", PTYPE_SELECT, "1",
                                     choices=(("1", "开启"), ("0", "关闭")))),
                 desc="国密 SM4 CBC，输出十六进制"),
    ]


def g_sm3(data: str) -> str:
    from lib import gm_codec
    return gm_codec.sm3_hex(data)


def _key_bytes(text: str, field: str) -> bytes:
    """把密钥 / IV 文本转 16 字节（32 位 hex 或 16 字符）。"""
    raw = str(text or "")
    if not raw:
        raise CryptoParamError(f"缺少 {field}（需要 32 位 hex 或 16 个字符）")
    if len(raw) == 32:
        try:
            return bytes.fromhex(raw)
        except ValueError:
            pass
    data = raw.encode("utf-8")
    if len(data) != 16:
        raise CryptoParamError(f"{field} 长度必须是 16 字节（当前 {len(data)}）")
    return data


def g_sm4_ecb(data: str, key: str = "", padding: str = "1") -> str:
    from lib import gm_codec
    used = _key_bytes(key, "密钥")
    return bytes(gm_codec.sm4_ecb_encrypt(data.encode("utf-8"), used,
                                          padding=padding == "1")).hex()


def g_sm4_cbc(data: str, key: str = "", iv: str = "", padding: str = "1") -> str:
    from lib import gm_codec
    used = _key_bytes(key, "密钥")
    used_iv = _key_bytes(iv, "IV")
    return bytes(gm_codec.sm4_cbc_encrypt(data.encode("utf-8"), used, used_iv,
                                          padding=padding == "1")).hex()


# ---------------------------------------------------------------------------
# 登记表
# ---------------------------------------------------------------------------
def _build() -> list[CryptoOp]:
    ops: list[CryptoOp] = []
    for builder in (_base_ops, _hash_ops, _classic_ops, _gm_ops):
        try:
            ops.extend(builder())
        except Exception:  # noqa: BLE001 - 某一组坏掉不影响其它组
            continue
    return ops


#: 全部载荷生成器（顺序即界面展示顺序）
CRYPTO_OPS: tuple[CryptoOp, ...] = tuple(_build())

_BY_ID: dict[str, CryptoOp] = {op.op_id: op for op in CRYPTO_OPS}


def list_ops() -> list[dict[str, Any]]:
    """列出全部密码学载荷生成器（供界面下拉框与 MCP 使用）。"""
    return [op.to_dict() for op in CRYPTO_OPS]


def get_op(op_id: str) -> CryptoOp:
    """按 id 取生成器；不存在抛 :class:`CryptoParamError`。"""
    key = str(op_id or "").strip()
    op = _BY_ID.get(key)
    if op is None:
        # 容忍省略前缀（"base64" → "crypto.base64"）
        for prefix in ("crypto.", "hash.", "classic.", "str.", "gm."):
            op = _BY_ID.get(prefix + key)
            if op is not None:
                break
    if op is None:
        raise CryptoParamError(
            f"未知密码学生成器：{op_id!r}（可用：{', '.join(sorted(_BY_ID))}）")
    return op


def groups() -> list[str]:
    """生成器按组名去重（保持登记顺序），供界面分组展示。"""
    seen: list[str] = []
    for op in CRYPTO_OPS:
        if op.group not in seen:
            seen.append(op.group)
    return seen


# ---------------------------------------------------------------------------
# 批量变换（循环模式的密码学接口）
# ---------------------------------------------------------------------------
@dataclass
class CryptoResult:
    """一批载荷的变换结果。"""

    op_id: str = ""
    label: str = ""
    inputs: list[str] = field(default_factory=list)
    outputs: list[str] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)

    @property
    def ok_count(self) -> int:
        return len(self.outputs)

    def to_dict(self) -> dict[str, Any]:
        return {
            "op": self.op_id,
            "label": self.label,
            "count": len(self.inputs),
            "ok": len(self.outputs),
            "outputs": list(self.outputs),
            "errors": list(self.errors),
        }


def transform(
    inputs: Sequence[str],
    op_id: str,
    values: dict[str, Any] | None = None,
    *,
    on_error: str = "keep",
) -> CryptoResult:
    """把一批明文逐个用 ``op_id`` 变换成载荷。

    ``on_error``：``keep`` 保留原文（便于对照） / ``hex`` 转十六进制 /
    ``skip`` 跳过该项。失败项一律记进 ``errors``，不中断整批。
    """
    op = get_op(op_id)
    result = CryptoResult(op_id=op.op_id, label=op.label,
                          inputs=[str(item) for item in inputs])
    for item in result.inputs:
        try:
            result.outputs.append(op.run(item, values))
        except CryptoParamError as exc:
            result.errors.append({"input": item, "error": str(exc)})
            if on_error == "hex":
                result.outputs.append(item.encode("utf-8").hex())
            elif on_error == "keep":
                result.outputs.append(item)
    return result


def transform_text(text: str, op_id: str,
                   values: dict[str, Any] | None = None,
                   *, on_error: str = "keep") -> str:
    """把多行文本（每行一个明文）批量变换，返回同样行数的载荷文本。"""
    items = [line for line in
             str(text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
             if line.strip() != ""]
    return "\n".join(transform(items, op_id, values, on_error=on_error).outputs)


__all__ = [
    "PTYPE_INT", "PTYPE_STR", "PTYPE_SELECT", "BASE85_VARIANTS",
    "CryptoParamError", "CryptoParam", "CryptoOp", "CryptoResult",
    "CRYPTO_OPS", "list_ops", "get_op", "groups", "transform", "transform_text",
]
