# -*- coding: utf-8 -*-
"""进制转换纯逻辑模块（2 ~ 16 进制互转）。

本模块只做「字符串进、字符串出」的纯计算：不导入 tkinter 等任何 UI 模块，
也不拼接界面文案；失败时统一抛 :class:`CodecError`（``ValueError`` 子类），
由界面层的 ``CryptoApp._run_codec`` 捕获后加 ``[前缀]`` 展示。

对外接口：
    convert(data, from_base, to_base)     任意 2~16 进制互转（核心）
    make_converter(from_base, to_base)    生成 ``f(data) -> str`` 转换器，
                                          供菜单批量注册 ``action_*`` 使用
    bin_to_oct / oct_to_bin / ...         2 / 8 / 10 / 16 两两定向转换的
                                          12 个便捷函数，菜单直接引用

输入容忍度（都按 CTF 常见写法处理）：
    - 允许首尾空白、内部空格 / 下划线 / 冒号 / 连字符等分隔符（如 ``1010 1100``）；
    - 允许正负号；
    - 允许 ``0b`` / ``0o`` / ``0x`` 前缀，但**仅当它与所选源进制一致时才剥离**，
      避免把 16 进制的 ``0B1``（＝十进制 177）误判成 2 进制前缀；
    - 字母大小写均可。

输出约定：
    - 大于 10 的进制用大写字母（与 ``base_codec.base16_encrypt`` 保持一致），
      可通过 ``convert(..., upper=False)`` 切换为小写；
    - 不带 ``0b`` / ``0x`` 之类前缀。
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# 一、常量与统一异常
# ---------------------------------------------------------------------------
MIN_BASE = 2
MAX_BASE = 16

#: 进制位表：base=N 时只允许前 N 个字符
_DIGITS = "0123456789ABCDEF"

#: 可剥离的进制前缀 -> 对应进制
_PREFIXES = {"0B": 2, "0O": 8, "0X": 16}

#: 被视为分隔符、解析前会被直接剔除的字符
_SEPARATORS = " \t\r\n_:-"


class CodecError(ValueError):
    """进制转换失败时抛出的统一异常，便于界面层统一捕获并展示提示。"""


# ---------------------------------------------------------------------------
# 二、内部工具
# ---------------------------------------------------------------------------
def _check_base(value, name: str) -> int:
    """校验进制取值必须是 2~16 的整数。"""
    if isinstance(value, bool) or not isinstance(value, int):
        raise CodecError(
            f"进制转换失败：{name}必须是整数，当前类型为 {type(value).__name__}。"
        )
    if not MIN_BASE <= value <= MAX_BASE:
        raise CodecError(
            f"进制转换失败：{name}必须在 {MIN_BASE}~{MAX_BASE} 之间，当前为 {value}。"
        )
    return value


def _split_sign(data: str, action: str) -> tuple[int, str]:
    """校验输入类型并拆出符号位，返回 ``(sign, 剩余内容)``，sign 取 1 或 -1。"""
    if not isinstance(data, str):
        raise CodecError(
            f"{action}失败：输入必须是字符串，当前类型为 {type(data).__name__}。"
        )
    text = data.strip()
    if not text:
        raise CodecError(f"{action}失败：输入内容为空，请先填写待处理的数据。")

    sign = 1
    if text[0] in "+-":
        sign = -1 if text[0] == "-" else 1
        text = text[1:]
    return sign, text


def _parse(data: str, from_base: int, action: str) -> tuple[int, str]:
    """把输入整理成可直接交给 ``int(x, base)`` 的纯数字串。

    返回 ``(sign, digits)``；digits 已去除分隔符、统一大写、剥离匹配的进制前缀，
    并已确认每一位都合法。
    """
    sign, text = _split_sign(data, action)

    # 去掉分隔符并统一大写，使 A-F 与 a-f 等价
    text = "".join(ch for ch in text if ch not in _SEPARATORS).upper()

    # 前缀仅在与源进制一致时剥离；不一致时保留原样，交给按位校验判断
    if len(text) > 2:
        prefix = text[:2]
        if _PREFIXES.get(prefix) == from_base:
            text = text[2:]

    if not text:
        raise CodecError(f"{action}失败：去掉符号与前缀后内容为空，请检查输入。")

    allowed = _DIGITS[:from_base]
    invalid = sorted({ch for ch in text if ch not in allowed})
    if invalid:
        hint = ""
        guessed = _PREFIXES.get(text[:2])
        if guessed is not None and guessed != from_base:
            hint = (
                f"；输入以“{text[:2]}”开头，看起来是 {guessed} 进制写法，"
                "请确认源进制是否选错"
            )
        raise CodecError(
            f"{action}失败：输入含不属于 {from_base} 进制的字符 "
            f"{''.join(invalid)}。{from_base} 进制只允许 "
            f"{allowed[0]}-{allowed[-1]}（字母大小写均可）{hint}。"
        )

    return sign, text


def _to_digits(value: int, base: int, upper: bool = True) -> str:
    """把非负整数转成目标进制的字符串（不含符号、不含前缀）。"""
    if value == 0:
        return "0"
    alphabet = _DIGITS if upper else _DIGITS.lower()
    out = []
    while value:
        value, remainder = divmod(value, base)
        out.append(alphabet[remainder])
    return "".join(reversed(out))


# ---------------------------------------------------------------------------
# 三、核心接口
# ---------------------------------------------------------------------------
def convert(data: str, from_base: int, to_base: int, upper: bool = True) -> str:
    """把 ``data`` 从 ``from_base`` 进制转成 ``to_base`` 进制字符串。

    参数:
        data:      待转换的字符串，如 ``"1010"``、``"0x1A"``、``"-FF"``
        from_base: 源进制，2~16
        to_base:   目标进制，2~16
        upper:     大于 10 的进制是否用大写字母输出，默认 ``True``

    返回:
        转换后的字符串；负数保留 ``-`` 号，不带进制前缀。

    异常:
        CodecError: 进制越界、输入非字符串 / 为空 / 含非法字符时抛出。
    """
    from_base = _check_base(from_base, "源进制")
    to_base = _check_base(to_base, "目标进制")
    action = f"{from_base} 进制转 {to_base} 进制"

    sign, digits = _parse(data, from_base, action)
    value = int(digits, from_base)
    text = _to_digits(value, to_base, upper)
    return f"-{text}" if sign < 0 and value != 0 else text


def make_converter(from_base: int, to_base: int):
    """生成一个 ``f(data: str) -> str`` 的转换器，供菜单批量注册回调。

    用法::

        dec_to_hex = make_converter(10, 16)   # 之后直接 dec_to_hex("255")
    """
    from_base = _check_base(from_base, "源进制")
    to_base = _check_base(to_base, "目标进制")

    def converter(data: str) -> str:
        return convert(data, from_base, to_base)

    # 便于调试与菜单自检时识别该转换器的方向
    converter.from_base = from_base
    converter.to_base = to_base
    converter.__name__ = f"base{from_base}_to_base{to_base}"
    converter.__doc__ = f"{from_base} 进制转 {to_base} 进制。"
    return converter


# ---------------------------------------------------------------------------
# 四、常用进制定向转换
# ---------------------------------------------------------------------------
# 2 / 8 / 10 / 16 两两互转，共 12 个方向；签名统一为 f(data: str) -> str，
# 供菜单 action_* 直接引用（与 rot_codec / base_codec 的纯函数形态一致）。
def bin_to_oct(data: str) -> str:
    """2 进制转 8 进制。"""
    return convert(data, 2, 8)


def bin_to_dec(data: str) -> str:
    """2 进制转 10 进制。"""
    return convert(data, 2, 10)


def bin_to_hex(data: str) -> str:
    """2 进制转 16 进制。"""
    return convert(data, 2, 16)


def oct_to_bin(data: str) -> str:
    """8 进制转 2 进制。"""
    return convert(data, 8, 2)


def oct_to_dec(data: str) -> str:
    """8 进制转 10 进制。"""
    return convert(data, 8, 10)


def oct_to_hex(data: str) -> str:
    """8 进制转 16 进制。"""
    return convert(data, 8, 16)


def dec_to_bin(data: str) -> str:
    """10 进制转 2 进制。"""
    return convert(data, 10, 2)


def dec_to_oct(data: str) -> str:
    """10 进制转 8 进制。"""
    return convert(data, 10, 8)


def dec_to_hex(data: str) -> str:
    """10 进制转 16 进制。"""
    return convert(data, 10, 16)


def hex_to_bin(data: str) -> str:
    """16 进制转 2 进制。"""
    return convert(data, 16, 2)


def hex_to_oct(data: str) -> str:
    """16 进制转 8 进制。"""
    return convert(data, 16, 8)


def hex_to_dec(data: str) -> str:
    """16 进制转 10 进制。"""
    return convert(data, 16, 10)
