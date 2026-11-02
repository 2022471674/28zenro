# -*- coding: utf-8 -*-
"""字符串工具收拢后的「密码 Fuzz」参与声明。

URL / ASCII / 实体编码三类工具收拢成独立页面后，不再是注册表里带 ``dec`` 的
``KIND_TWO_WAY`` 工具（那类靠 ``dec`` 自动参与 Fuzz）。为保证「密码 Fuzz」仍能
一次性尝试这些解码方向，这里提供三个自定义 ``fuzz`` 函数：

    fn(ctx: FuzzContext) -> [(标签, 结果), ...]

对输入密文依次尝试对应的解码器，成功则产出 ``(算法名, 明文)``，失败静默跳过。

本模块只做纯逻辑，不导入任何 UI 模块。
"""

from __future__ import annotations

from lib import string_codec


def fuzz_url(ctx) -> list[tuple[str, str]]:
    """URL 编码工具的自定义 Fuzz：尝试 URL 解码。"""
    text = str(getattr(ctx, "text", "") or "")
    try:
        out = string_codec.url_decode(text)
    except Exception:  # noqa: BLE001  解不开是常态
        return []
    if out and out.strip() and out != text:
        return [("URL 解码", out)]
    return []


def fuzz_ascii(ctx) -> list[tuple[str, str]]:
    """ASCII 转换工具的自定义 Fuzz：尝试 ASCII 码点还原字符串。"""
    text = str(getattr(ctx, "text", "") or "")
    try:
        out = string_codec.ascii_to_str(text)
    except Exception:  # noqa: BLE001
        return []
    if out and out.strip() and out != text:
        return [("ASCII 转字符串", out)]
    return []


def fuzz_entity(ctx) -> list[tuple[str, str]]:
    """实体编码工具的自定义 Fuzz：依次尝试各解码方向。

    覆盖 HTML 实体 / Unicode 转义 / Quoted-printable / GBK·UTF-16（反向）四个
    解码器；任一失败静默跳过，不影响其它。
    """
    text = str(getattr(ctx, "text", "") or "")
    decoders = (
        ("HTML 实体解码", string_codec.html_entity_decode),
        ("Unicode 转义解码", string_codec.unicode_escape_decode),
        ("Quoted-printable 解码", string_codec.quoted_printable_decode),
        ("UTF-16 转 GBK", string_codec.utf16_to_gbk),
    )
    pairs: list[tuple[str, str]] = []
    for label, dec in decoders:
        try:
            out = dec(text)
        except Exception:  # noqa: BLE001
            continue
        if out and out.strip() and out != text:
            pairs.append((label, out))
    return pairs


__all__ = ["fuzz_url", "fuzz_ascii", "fuzz_entity"]
