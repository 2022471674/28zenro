# -*- coding: utf-8 -*-
"""28zenro_mcp —— 28zenro 的 MCP (Model Context Protocol) 服务端实现。

本包把项目 ``lib/`` 下的全部纯逻辑函数包装成 MCP 工具，向 Agent 宿主
（Claude Desktop / Cursor / Cherry Studio / 自研客户端）暴露。

目录
----
``bootstrap``   路径注入、配置读取、代理池装载、stderr 日志
``envelope``    统一返回信封、序列化、参数脱敏
``contract``    参数契约（Param/Op/Group）、校验、分发、审计
``ops/*``       各工具组的 op 声明（唯一事实来源）
``app``         FastMCP 组装（工具注册 + 资源）
``docgen``      CONTRACT.md / ops.json 生成

设计原则
--------
1. 单一事实来源：每个 op 的参数就写在 ``ops/*`` 的声明里，文档由它生成；
2. 只在需要时适配：默认直接把 op 转发到同名 lib 函数（模块/函数由声明给出），
   只有返回元组、线程轮询、配置注入等少数场景写自定义 handler；
3. 可审计：``contract.audit()`` 用 ``inspect.signature`` 对照真实函数签名，
   发现「声明了不存在的参数」或「漏声明必填参数」等问题。
"""

from __future__ import annotations

__version__ = "1.0.0"
__all__ = ["__version__"]
