# -*- coding: utf-8 -*-
"""字符加解密纯逻辑模块（凯撒 / 猪圈密码）。

本模块只做「字符串进、字符串出」的纯计算：不导入 tkinter 等任何 UI 模块，
失败时统一抛 :class:`CodecError`（``ValueError`` 子类），由界面层的
``CryptoApp._run_codec`` 捕获后加 ``[前缀]`` 展示。

对外接口：
    caesar_encrypt(data, shift)   凯撒加密（A-Z / a-z 循环移位，非字母保留）
    caesar_decrypt(data, shift)   凯撒解密（同加密的反向移位）
    pigpen_encrypt(data)          猪圈加密（字母 -> 猪圈符号）
    pigpen_decrypt(data)          猪圈解密（猪圈符号 -> 字母）

说明：
    凯撒复用 :mod:`lib.rot_codec` 的 ``rot_n``（英文字母循环移位），避免重复实现；
    猪圈密码没有标准 Unicode 编码，本模块用 APL 符号区 U+2340~U+2359 的 26 个
    连续字符作为 A-Z 的符号表，编码 / 解码严格互逆；非字母字符一律原样保留。
"""

from __future__ import annotations

from . import rot_codec

_ALPHABET_LOWER = "abcdefghijklmnopqrstuvwxyz"
_ALPHABET_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

#: 猪圈密码符号表：A-Z 依次对应 U+2340 起的 26 个 APL 符号字符
_PIGPEN_SYMBOLS = "".join(chr(0x2340 + i) for i in range(26))
#: 符号 -> 大写字母 的逆映射（解码用）
_PIGPEN_REVERSE = {
    symbol: _ALPHABET_UPPER[index] for index, symbol in enumerate(_PIGPEN_SYMBOLS)
}


class CodecError(ValueError):
    """字符加解密失败时抛出的统一异常，便于界面层统一捕获并展示提示。"""


def _check_input(data, action: str) -> str:
    """校验输入必须是字符串且非空，返回去首尾空白后的内容。"""
    if not isinstance(data, str):
        raise CodecError(
            f"{action}失败：输入必须是字符串，当前类型为 {type(data).__name__}。"
        )
    text = data.strip()
    if not text:
        raise CodecError(f"{action}失败：输入内容为空，请先填写待处理的数据。")
    return text


def caesar_encrypt(data: str, shift: int) -> str:
    """凯撒加密：A-Z / a-z 各自循环右移 shift 位，非字母字符原样保留。"""
    text = _check_input(data, "凯撒加密")
    return rot_codec.rot_n(text, shift)


def caesar_decrypt(data: str, shift: int) -> str:
    """凯撒解密：对加密结果反向移位 shift 位还原原文。"""
    text = _check_input(data, "凯撒解密")
    return rot_codec.rot_n(text, -shift)


def pigpen_encrypt(data: str) -> str:
    """猪圈加密：英文字母（大小写均可）替换为猪圈符号，其余字符原样保留。"""
    text = _check_input(data, "猪圈加密")
    out = []
    for ch in text:
        if ch in _ALPHABET_LOWER:
            out.append(_PIGPEN_SYMBOLS[_ALPHABET_LOWER.index(ch)])
        elif ch in _ALPHABET_UPPER:
            out.append(_PIGPEN_SYMBOLS[_ALPHABET_UPPER.index(ch)])
        else:
            out.append(ch)
    return "".join(out)


def pigpen_decrypt(data: str) -> str:
    """猪圈解密：猪圈符号还原为对应大写字母，其余字符原样保留。"""
    text = _check_input(data, "猪圈解密")
    return "".join(_PIGPEN_REVERSE.get(ch, ch) for ch in text)
