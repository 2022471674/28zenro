# -*- coding: utf-8 -*-
"""op 声明聚合：每个 ``GROUP`` 对应一个 MCP 工具（``cn_*``）。

新增工具组的步骤
----------------
1. 在本目录新建 ``xxx.py``，用 :func:`~28zenro_mcp.contract.make_op` /
   :func:`~28zenro_mcp.contract.custom_op` 声明 op，导出 ``GROUP``；
2. 把模块名加进 :data:`_MODULES`；
3. 跑 ``python mcp/server.py --selftest``（契约审计 + 冒烟用例），
   再用 ``python mcp/server.py --gen-docs`` 重新生成 CONTRACT.md。

这里按模块**逐个容错导入**：某个工具组因为可选依赖缺失（如没装 Pillow）
初始化失败时，只丢掉该组并记入 :data:`IMPORT_ERRORS`，其余工具照常可用。
"""

from __future__ import annotations

import importlib
from typing import Iterable

from ..contract import Group

#: 工具组模块（顺序即工具列表顺序；help 必须最前）。
_MODULES: tuple[str, ...] = (
    "help",
    "codec",
    "data",
    "crypto",
    "image",
    "web",
    "requester",
    "scan",
    "attack",
    "llm",
    "misc",
)

GROUPS: list[Group] = []
#: 模块名 -> 导入失败原因（正常情况下为空）。
IMPORT_ERRORS: dict[str, str] = {}

for _name in _MODULES:
    try:
        _module = importlib.import_module(f".{_name}", __name__)
    except Exception as exc:  # noqa: BLE001 - 可选依赖缺失时降级
        IMPORT_ERRORS[_name] = f"{type(exc).__name__}: {exc}"
        continue
    _group = getattr(_module, "GROUP", None)
    if isinstance(_group, Group):
        GROUPS.append(_group)
    else:  # pragma: no cover - 声明错误
        IMPORT_ERRORS[_name] = "模块没有导出 GROUP"

del _name

# 第三方插件封装层（mcp/plugins/）：整层失败只丢插件组，不影响内置工具
try:
    from ..pluginkit import GROUPS as _PLUGIN_GROUPS
    from ..pluginkit import IMPORT_ERRORS as _PLUGIN_ERRORS
except Exception as exc:  # noqa: BLE001
    IMPORT_ERRORS["plugins"] = f"{type(exc).__name__}: {exc}"
else:
    GROUPS.extend(_PLUGIN_GROUPS)
    IMPORT_ERRORS.update({f"plugins.{key}": value
                          for key, value in _PLUGIN_ERRORS.items()})


def groups() -> list[Group]:
    """按注册顺序返回全部工具组。"""
    return list(GROUPS)


def total_ops(groups_: Iterable[Group] | None = None) -> int:
    return sum(len(group.ops) for group in (groups_ or GROUPS))
