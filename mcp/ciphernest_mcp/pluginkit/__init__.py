# -*- coding: utf-8 -*-
"""插件封装层：把 ``mcp/plugins/`` 下的第三方工具接成 MCP 工具组。

对应关系
--------
============  ==========================  ================================
工具组        插件                        封装程度
============  ==========================  ================================
cn_plugin     全部插件                    通用：发现 / 体检 / 受控直调
cn_sqlmap     sqlmap                     语义化 op + 输出解析 + 输出目录
cn_trufflehog TruffleHog                  NDJSON → 结构化 findings
cn_oneforall  OneForAll                   跑收集 + 解析 results/ 导出
cn_flaskcookie Flask Session Cookie Mgr   decode/encode（Flask 3.x 原生回退）
cn_filesensor FileSensor                  扫描 + 命中 URL 解析
============  ==========================  ================================

新增插件有两条路：
1. 只放文件 → 用 ``cn_plugin(op="run")`` 直调（无需改代码）；
2. 想要语义化 op → 在本目录加一个 ``<插件>.py`` 导出 ``GROUP``，
   并把模块名加进 :data:`_MODULES`。
"""

from __future__ import annotations

import importlib

from ..contract import Group

_MODULES: tuple[str, ...] = (
    "generic",
    "sqlmap",
    "trufflehog",
    "oneforall",
    "flaskcookie",
    "filesensor",
)

GROUPS: list[Group] = []
#: 模块名 -> 导入失败原因（正常情况下为空）。
IMPORT_ERRORS: dict[str, str] = {}

for _name in _MODULES:
    try:
        _module = importlib.import_module(f".{_name}", __name__)
    except Exception as exc:  # noqa: BLE001 - 单个插件组坏了不影响其他组
        IMPORT_ERRORS[_name] = f"{type(exc).__name__}: {exc}"
        continue
    _group = getattr(_module, "GROUP", None)
    if isinstance(_group, Group):
        GROUPS.append(_group)
    else:  # pragma: no cover - 声明错误
        IMPORT_ERRORS[_name] = "模块没有导出 GROUP"

del _name


def groups() -> list[Group]:
    return list(GROUPS)


def discovered_plugins() -> dict:
    """给 ``cn_help`` / 自检用：当前发现的插件清单。"""
    from .runtime import MANIFEST_ERRORS, PLUGINS, PLUGINS_ROOT
    return {
        "root": str(PLUGINS_ROOT),
        "plugins": {key: plugin.to_dict() for key, plugin in PLUGINS.items()},
        "manifest_errors": dict(MANIFEST_ERRORS),
    }
