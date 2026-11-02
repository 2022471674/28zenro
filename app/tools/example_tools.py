# -*- coding: utf-8 -*-
"""示例：用 ``@tool`` 装饰器注册的字符串工具（演示自动发现 + 参数 schema）。

本模块放在 ``app/tools/`` 下，启动时被自动导入；``@tool`` 装饰器把下面的函数
登记成两个工具，界面据此自动生成输入控件与执行按钮，无需改动 registry 的
集中式清单。

- ``str_reverse``：字符串逆序（带「是否反转大小写」布尔参数）；
- ``str_repeat``：字符串重复拼接（带「重复次数」整数参数与「分隔符」文本参数）。

这两个函数本身仍是普通 lib 函数，可被直接调用，也可参与密码 Fuzz（见
``fuzzable``）。
"""

from __future__ import annotations

from app.registry import CATEGORY_STRING, KIND_ONE_WAY, KIND_TWO_WAY, ParamSpec, tool


@tool(
    "str_reverse",
    name="字符串逆序",
    category=CATEGORY_STRING,
    kind=KIND_ONE_WAY,
    description="反转字符串顺序，可选同时反转字母大小写",
    params=(ParamSpec(
        "swap_case", "反转大小写", ptype="bool", default=False, order=0,
    ),),
)
def str_reverse(data: str, swap_case: bool = False) -> str:
    """把输入字符串逆序，``swap_case=True`` 时再反转每个字母的大小写。"""
    text = str(data)[::-1]
    if swap_case:
        text = text.swapcase()
    return text


@tool(
    "str_repeat",
    name="字符串重复",
    category=CATEGORY_STRING,
    kind=KIND_ONE_WAY,
    description="把字符串重复 N 次，可用分隔符连接",
    params=(
        ParamSpec("count", "重复次数", ptype="int", default=2,
                  minimum=1, maximum=100, order=0),
        ParamSpec("sep", "分隔符", ptype="str", default="", order=1,
                  hint="留空表示直接拼接"),
    ),
)
def str_repeat(data: str, count: int = 2, sep: str = "") -> str:
    """把 ``data`` 重复 ``count`` 次，用 ``sep`` 连接。"""
    return str(sep).join([str(data)] * int(count))
