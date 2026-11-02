# -*- coding: utf-8 -*-
"""MCP 服务进程入口（PyInstaller 打包专用，dev 也可直接 ``python`` 运行）。

为什么需要单独一个入口
----------------------
GUI（main.py）冻结后 ``sys.executable`` 是 ``28zenro.exe`` 本身，
不能再拿它 ``<exe> mcp/server.py --http`` 去跑 Python 脚本 —— 那样等于
再开一个 GUI 实例（表现：任务栏冒出第二个程序，QtWebEngine 缓存目录
互相抢，报 ``Unable to move the cache: 拒绝访问``），MCP 服务永远起不来。

因此打包配置（``28zenro_onedir.spec``）用本文件生成独立小进程
``28zenroMcp.exe``（不含 Qt，启动快），``lib/mcp_server_control.py``
在冻结态直接拉它：

::

    28zenroMcp.exe --http --host 127.0.0.1 --port 8000
    28zenroMcp.exe --selftest          # 打包自检（审计 + 冒烟）

开发态仍然走 ``python mcp/server.py ...``，行为不变（两者最终都进
``28zenro_mcp.cli.main``）。
"""

from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent


def main() -> int:
    """把 ``mcp`` 目录挂进 ``sys.path`` 后转交 ``28zenro_mcp.cli``。"""
    if str(_HERE) not in sys.path:
        sys.path.insert(0, str(_HERE))
    from 28zenro_mcp.cli import main as cli_main  # 延迟导入：打包时由 Analysis 收集

    return int(cli_main())


if __name__ == "__main__":
    raise SystemExit(main())
