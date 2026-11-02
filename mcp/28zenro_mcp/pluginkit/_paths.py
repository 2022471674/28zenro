# -*- coding: utf-8 -*-
"""插件侧的路径解析（与 ``ops._helpers`` 同样的规则，但独立实现避免包循环）。

相对路径一律基于项目根 ``CTFcrypto/``，与宿主进程 CWD 无关。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..bootstrap import PROJECT_ROOT
from ..envelope import ToolError


def resolve_path(raw: Any, *, field: str = "path", must_exist: bool = False) -> Path:
    text = str(raw or "").strip()
    if not text:
        raise ToolError("missing_param", f"缺少必填参数 {field}（文件路径）", field=field)
    path = Path(text).expanduser()
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    try:
        path = path.resolve()
    except OSError:  # pragma: no cover - 极端路径
        path = Path(path)
    if must_exist and not path.exists():
        raise ToolError("io", f"{field} 指向的路径不存在：{path}", field=field)
    return path


def rel(path: Path | str) -> str:
    try:
        return str(Path(path).resolve().relative_to(PROJECT_ROOT))
    except (ValueError, OSError):
        return str(path)
