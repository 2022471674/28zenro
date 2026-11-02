# -*- coding: utf-8 -*-
"""``python -m 28zenro_mcp`` 入口（等价于 ``python mcp/server.py``）。

在 ``mcp/`` 目录下执行::

    python -m 28zenro_mcp --selftest

注意：项目里的 ``mcp/`` 目录**故意不放 ``__init__.py``**，这样 ``import mcp``
仍然解析到已安装的 MCP SDK，不会互相遮蔽；真正的 Python 包是 ``28zenro_mcp``。
"""

from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
