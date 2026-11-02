# -*- coding: utf-8 -*-
"""baseX 工具的「密码 Fuzz」参与声明。

baseX 把 11 个 Base 系列解码器收拢到一个工具，不再是独立注册的
``KIND_TWO_WAY`` 工具（那类工具靠 ``dec`` 自动参与 Fuzz）。为保证「密码 Fuzz」
仍能一次性解出 Base 系列密文，这里显式提供一个自定义 ``fuzz`` 函数：

    fn(ctx: FuzzContext) -> [(标签, 结果), ...]

对输入密文依次尝试全部 Base 解码器，成功则产出 ``(算法名, 明文)``，失败静默
跳过（单个解码器失败不影响其它，也不影响整轮 Fuzz）。Base85 额外尝试
``b85`` 与 ``a85`` 两种变体。

本模块只做纯逻辑，不导入任何 UI 模块。
"""

from __future__ import annotations

from typing import Any

from lib import base_codec


#: (算法名, 解码函数, 是否带 variant 参数)
_DECODERS: tuple[tuple[str, Any, bool], ...] = (
    ("Base64", base_codec.base64_decrypt, False),
    ("URLSafe Base64", base_codec.base64_urlsafe_decrypt, False),
    ("Base32", base_codec.base32_decrypt, False),
    ("Base16", base_codec.base16_decrypt, False),
    ("Base58", base_codec.base58_decrypt, False),
    ("Base62", base_codec.base62_decrypt, False),
    ("Base85", base_codec.base85_decrypt, True),
    ("Base91", base_codec.base91_decrypt, False),
    ("Base92", base_codec.base92_decrypt, False),
    ("UUencode", base_codec.uuencode_decrypt, False),
    ("XXencode", base_codec.xxencode_decrypt, False),
)


def fuzz_basex(ctx) -> list[tuple[str, str]]:
    """baseX 的自定义 Fuzz：遍历全部 Base 解码器，返回 ``[(标签, 结果), ...]``。

    参数 ``ctx`` 为 :class:`lib.cipher_fuzz.FuzzContext`，本函数只用其中的
    ``ctx.text``。任一解码器抛异常（非法字符 / 长度不符 / 还原非 UTF-8）都
    静默跳过，绝不让单个算法拖垮整轮 Fuzz。
    """
    text = str(getattr(ctx, "text", "") or "")
    pairs: list[tuple[str, str]] = []
    for name, dec, has_variant in _DECODERS:
        if has_variant:
            for variant, variant_label in (("b85", "b85"), ("a85", "a85")):
                try:
                    out = dec(text, variant)
                except Exception:  # noqa: BLE001  单解码器失败静默跳过
                    continue
                if out and out.strip():
                    pairs.append((f"{name}({variant_label})", out))
        else:
            try:
                out = dec(text)
            except Exception:  # noqa: BLE001
                continue
            if out and out.strip():
                pairs.append((name, out))
    return pairs


__all__ = ["fuzz_basex"]
