#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""28zenro MCP 服务器入口（stdio / HTTP）。

基于项目 ``lib/`` 的全部纯逻辑能力，按「一个工具组一个 MCP 工具」暴露：

    cn_<group>(op="<操作名>", params={...}) -> 统一信封

用法
----
::

    python mcp/server.py                 # stdio（宿主以子进程拉起，最常用）
    python mcp/server.py --http          # streamable-http，默认 127.0.0.1:8000/mcp
    python mcp/server.py --http --port 9000 --host 0.0.0.0
    python mcp/server.py --list          # 打印全部工具与 op
    python mcp/server.py --show base64_encrypt
    python mcp/server.py --audit         # 契约 vs lib 签名审计
    python mcp/server.py --selftest      # 审计 + 冒烟用例（CI 用）
    python mcp/server.py --gen-docs      # 重新生成 mcp/CONTRACT.md
    python mcp/server.py --export mcp/docs/ops.json

宿主配置示例见 ``mcp/mcp.json``；完整方法契约见 ``mcp/CONTRACT.md``。

为什么 ``mcp/`` 目录里没有 ``__init__.py``
------------------------------------------
PyPI 上的 MCP SDK 这个包本身就叫 ``mcp``。如果本目录也做成 ``mcp`` 包，
`import mcp.server.fastmcp` 就会命中本地目录而不是 SDK。因此这里保持目录
（而非包），真正的实现放在 ``mcp/28zenro_mcp/`` 里。
"""

from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent           # .../CTFcrypto/mcp
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from 28zenro_mcp.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
