# -*- coding: utf-8 -*-
from __future__ import annotations

from app.registry import CATEGORY_STRING, ParamSpec, tool

_LEET = str.maketrans({
    "a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7", "l": "1",
    "A": "4", "E": "3", "I": "1", "O": "0", "S": "5", "T": "7", "L": "1",
})


@tool(
    "leet_speak",
    name="Leet 变换",
    category=CATEGORY_STRING,
    description="把文本转成 leet（1337）风格，可反向还原",
    params=(ParamSpec(
        "decode", "反向还原", ptype="bool", default=False, order=0,
    ),),
)
def leet_speak(data: str, decode: bool = False) -> str:
    """encode 时把常见字母替换成 leet 数字，decode 时用反向表还原。"""
    text = str(data)
    if decode:
        reverse = {v: k for k, v in _LEET.items() if isinstance(k, str)}
        table = str.maketrans({v: k for k, v in reverse.items()})
        return text.translate(table)
    return text.translate(_LEET)
