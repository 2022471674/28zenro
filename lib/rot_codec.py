from __future__ import annotations

import codecs


_ALPHABET_LOWER = "abcdefghijklmnopqrstuvwxyz"
_ALPHABET_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

_ROT47_START = 33
_ROT47_END = 126
_ROT47_RANGE = _ROT47_END - _ROT47_START + 1  # 94
_ROT47_SHIFT = 47



class CodecError(ValueError):
    """ROT 系列编解码失败时抛出的统一异常，便于界面层统一捕获并弹出提示。"""

def _check_input(data: str, action: str) -> str:
    if not isinstance(data, str):
        raise CodecError(
            f"{action}失败：输入必须是字符串，当前类型为 {type(data).__name__}。"
        )
    text = data.strip()
    if not text:
        raise CodecError(f"{action}失败：输入内容为空，请先填写待处理的数据。")
    return text


def rot13_encrypt(data: str) -> str:
    text = _check_input(data, "ROT13 编码")
    try:
        return codecs.encode(text, "rot_13")
    except (UnicodeEncodeError, UnicodeDecodeError) as exc:
        raise CodecError(f"ROT13 编码失败：{exc}") from exc


def rot13_decrypt(data: str) -> str:
    return rot13_encrypt(data)



def _rot47_char(ch: str) -> str:
    code = ord(ch)
    if _ROT47_START <= code <= _ROT47_END:
        return chr(_ROT47_START + (code - _ROT47_START + _ROT47_SHIFT) % _ROT47_RANGE)
    return ch


def rot47_encrypt(data: str) -> str:
    text = _check_input(data, "ROT47 编码")
    try:
        return "".join(_rot47_char(ch) for ch in text)
    except (ValueError, UnicodeError) as exc:
        raise CodecError(f"ROT47 编码失败：{exc}") from exc


def rot47_decrypt(data: str) -> str:
    return rot47_encrypt(data)



def rot_n(data: str, shift: int) -> str:
    if not isinstance(shift, int) or isinstance(shift, bool):
        raise CodecError(
            f"ROT-N 失败：位移量 shift 必须是整数，当前类型为 {type(shift).__name__}。"
        )
    text = _check_input(data, "ROT-N")

    shift %= 26
    result = []
    for ch in text:
        if ch in _ALPHABET_LOWER:
            result.append(_ALPHABET_LOWER[(_ALPHABET_LOWER.index(ch) + shift) % 26])
        elif ch in _ALPHABET_UPPER:
            result.append(_ALPHABET_UPPER[(_ALPHABET_UPPER.index(ch) + shift) % 26])
        else:
            result.append(ch)
    return "".join(result)