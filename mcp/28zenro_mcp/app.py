# -*- coding: utf-8 -*-
"""FastMCP 组装：工具注册 + 资源。

每个工具组的签名完全一致，这是本服务的核心约定::

    cn_<group>(op: str, params: dict | None = None) -> dict   # 统一返回信封

这样宿主只需要理解一种调用形态；具体能力用 ``cn_help`` 发现。
"""

from __future__ import annotations

import json
from typing import Any

from mcp.server.fastmcp import FastMCP

from . import __version__
from .bootstrap import log, settings
from .contract import Ctx, Group, run_op
from .ops import GROUPS

INSTRUCTIONS = """\
28zenro 密码学 / 安全工具集（Python，本地执行）。

调用形态（所有工具一致）：
    cn_<group>(op="<操作名>", params={...})

推荐流程：
1. cn_help(op="list")                      → 全部工具与 op 名单
2. cn_help(op="help", params={"op": "…"})  → 该 op 的参数表 / 返回 / 示例
3. 调用目标工具
4. 结果统一是 {"ok": bool, "tool", "op", "data"|"error", "meta"}

工具组：
- cn_help    发现 / 契约 / 自检
- cn_codec   编解码 / 进制 / ROT / 深奥语言
- cn_data    JSON / 文件↔十六进制 / 文本对比去重
- cn_crypto  哈希 / 国密 SM / RSA / JWT / 密文识别
- cn_image   图片 Base64 / LSB 隐写 / 可见水印
- cn_web     Web Fuzz / JSFinder / 指纹 / 收录 / DNS
- cn_scan    目录 / 端口 / 参数 / 泄露 / 多地 Ping
- cn_attack  SSTI / MySQL / 微信凭证 / ZIP / 哈希爆破
- cn_llm     对话 / 向量 / OCR / 翻译（OpenAI 兼容）
- cn_misc    番茄钟 / 代理池 / 局域网共享客户端

注意：
- 主动探测与爆破类 op 仅可用于已授权目标；
- 长任务都有参数上限（如 max_seconds / max_links / limit），先小范围试探；
- 进度日志写 stderr，不会污染协议通道。
"""


def _make_tool(group: Group):
    """生成一个工具函数：签名固定为 (op, params)，返回统一信封。"""

    def tool(op: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        ctx = Ctx(settings=settings(), prefix=f"{group.name}/{op} ")
        return run_op(group, op, params, ctx)

    tool.__name__ = group.name
    tool.__qualname__ = group.name
    tool.__doc__ = group.tool_description()
    return tool


def build_app(host: str = "127.0.0.1", port: int = 8000,
              debug: bool = False, track_sessions: bool = False) -> FastMCP:
    """构建 FastMCP 应用（工具 + 资源）。

    工具注册支持按组禁用：配置键 ``mcp_server.disabled_groups``（与 GUI /
    CLI 共享的 config.json）里列出的 ``cn_*`` 组不注册。``cn_help`` 是
    宿主的发现 / 契约入口**永远注册**——名单里即使写了它也会被忽略，
    否则其余工具组对 Agent 完全不可见。

    ``track_sessions=True``（HTTP 模式）时，额外挂一层轻量 ASGI 中间件记录
    活跃连接的来源（IP / UA / session_id），并注册 ``/__sessions`` 只读状态
    路由供 GUI 轮询；同时给 ``cn_help`` 加 ``sessions`` op。stdio 模式不启用。
    """
    app = FastMCP(
        "28zenro",
        instructions=INSTRUCTIONS,
        host=host,
        port=port,
        debug=debug,
        log_level="ERROR" if not debug else "DEBUG",
    )
    from .bootstrap import ALWAYS_ON_GROUPS
    disabled = {str(name) for name in
                (settings().section("mcp_server").get("disabled_groups") or [])}
    skipped: list[str] = []
    registered_ops = 0
    for group in GROUPS:
        if group.name in disabled and group.name not in ALWAYS_ON_GROUPS:
            skipped.append(group.name)
            log(f"跳过工具组 {group.name}（已在配置中禁用）")
            continue
        app.add_tool(
            _make_tool(group),
            name=group.name,
            title=group.title,
            description=group.tool_description(),
            structured_output=False,
        )
        registered_ops += len(group.ops)
    _register_resources(app)
    if track_sessions:
        from .session_tracker import SessionTrackingMiddleware, mount
        mount(app)  # 注册 /__sessions 只读状态路由
        # 包裹 streamable_http_app：让 FastMCP 构造出的 Starlette app 在
        # 返回前套上连接追踪中间件（捕获 IP / UA / session-id）。
        _original = app.streamable_http_app

        def _wrapped_streamable_http_app():
            inner = _original()
            return SessionTrackingMiddleware(inner)

        app.streamable_http_app = _wrapped_streamable_http_app  # type: ignore[method-assign]
    log(f"已注册 {len(GROUPS) - len(skipped)} 个工具 / {registered_ops} 个 op"
        + (f"；已禁用 {len(skipped)} 组（{'、'.join(skipped)}）"
           if skipped else ""))
    return app


def _register_resources(app: FastMCP) -> None:
    """把契约与用法作为 MCP 资源暴露，宿主可直接读取。"""

    @app.resource("28zenro://contract",
                  name="28zenro-contract",
                  title="28zenro 方法契约",
                  description="全部工具与 op 的机器可读契约（JSON）",
                  mime_type="application/json")
    def _contract_resource() -> str:
        from .ops import GROUPS as groups
        payload = {
            "server": "28zenro-mcp",
            "version": __version__,
            "tools": [group.schema() for group in groups],
        }
        return json.dumps(payload, ensure_ascii=False, indent=2)

    @app.resource("28zenro://guide",
                  name="28zenro-guide",
                  title="28zenro 调用指南",
                  description="调用约定与推荐流程（Markdown）",
                  mime_type="text/markdown")
    def _guide_resource() -> str:
        from .docgen import render_guide
        return render_guide()
