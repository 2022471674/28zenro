# -*- coding: utf-8 -*-
"""应用程序数据根目录定位（源码 / PyInstaller 6 onedir / onefile 统一）。

PyInstaller 6 的 onedir 布局把 datas 与运行时全放进 ``<exe 目录>/_internal``，
但 ``sys._MEIPASS``（以及据此生成的纯模块 ``__file__``）却指向 **exe 顶层**——
直接用 ``_MEIPASS`` 拼字典 / 图片路径会一首错位（打包版字典加载失败、
插件目录找不到）。本模块给出唯一正确答案：

- dev：项目根（``lib/`` 的上级）；
- frozen onedir（6.x）：``<exe>/_internal``；旧版 onedir / onefile：
  ```` ``sys._MEIPASS`` `` ``（onefile 为解压临时目录）。

所有需要读「打进包里的静态数据」的地方（dict / lib/img / mcp/plugins /
static）一律走 :func:`data_root`，不要再各自手拼 ``_MEIPASS``。
"""

from __future__ import annotations

import sys
from pathlib import Path


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def data_root() -> Path:
    """返回打包数据根目录（字典 / 图片 / 插件等 datas 的所在父目录）。"""
    if not getattr(sys, "frozen", False):
        return _project_root()
    exe_dir = Path(sys.executable).resolve().parent
    internal = exe_dir / "_internal"
    if internal.is_dir():
        # PyInstaller 6.x onedir：datas 在 _internal
        return internal
    bundle = getattr(sys, "_MEIPASS", None)
    if bundle:
        return Path(bundle)
    return exe_dir


def resource(*parts: str) -> Path:
    """data_root() 下的相对资源路径（不检查存在性）。"""
    return data_root().joinpath(*parts)


def find_resource(*candidates: str) -> Path | None:
    """在 data_root() 下按候选顺序找第一个存在的资源；都不在返回 None。

    candidates 元素允许带子目录，如 ``("static/favicon.ico", "static/favicon_256.ico")``。
    """
    root = data_root()
    for item in candidates:
        path = root.joinpath(*item.split("/"))
        if path.is_file():
            return path
    return None
