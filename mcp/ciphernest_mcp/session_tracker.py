# -*- coding: utf-8 -*-
"""HTTP 模式下的「活跃连接」追踪（进程内共享，不依赖 SDK 私有字段）。

背景
----
MCP SDK 的 ``StreamableHTTPSessionManager`` 内部虽然维护了活跃会话，但都是
私有字段、且不记录客户端来源（IP / User-Agent / 连接时间），也没有对外 API。
本模块用一层**自建的轻量 ASGI 中间件**在 HTTP 层记录这些信息，并暴露：

- :func:`snapshot`  —— 当前活跃连接的结构化快照（供 ``cn_help`` 的 sessions op）；
- :func:`mount`     —— 把 ``/__sessions`` 只读状态路由注册到 FastMCP 上（供 GUI 轮询）。

约定
----
- 仅 HTTP（streamable-http）模式有意义；stdio 模式没有「连接」概念，返回空列表；
- 来源信息在 ASGI ``scope`` 里捕获，属于**尽力而为**：本地回环显示 127.0.0.1，
  User-Agent 可能为空（取决于宿主 SDK 是否设置）；
- 记录只保留最近活跃时间，会话关闭（进程内无显式关闭回调时）按超时淘汰，
  避免无限增长。
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any

#: 会话无活动多久后视为过期（秒）。MCP SDK 默认不设 idle timeout，
#: 这里给一个保守的兜底，防止崩溃/断连的会话永久残留。
_IDLE_TTL = 300.0

#: 最多保留的会话记录数。
_MAX_SESSIONS = 256


@dataclass
class _Session:
    session_id: str
    client: str
    user_agent: str
    created: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)


#: 进程内共享注册表：session_id -> _Session（线程安全）。
_lock = threading.Lock()
_sessions: dict[str, _Session] = {}


def _now() -> float:
    return time.time()


def record(session_id: str | None, client: str, user_agent: str) -> None:
    """记录 / 更新一个会话的最近活跃时间。

    由 ASGI 中间件在每个 HTTP 请求上调用；``session_id`` 为 ``None`` 时
    （例如首次 initialize 尚未分配会话 ID）跳过，不影响统计。
    """
    if not session_id:
        return
    with _lock:
        existing = _sessions.get(session_id)
        if existing is None:
            if len(_sessions) >= _MAX_SESSIONS:
                _prune_locked()
            _sessions[session_id] = _Session(
                session_id=session_id, client=client, user_agent=user_agent)
        else:
            existing.last_seen = _now()
            if client and existing.client == "unknown":
                existing.client = client
            if user_agent and not existing.user_agent:
                existing.user_agent = user_agent


def _prune_locked() -> None:
    """淘汰已过期的会话（调用方需已持有 ``_lock``）。"""
    cutoff = _now() - _IDLE_TTL
    for sid in [sid for sid, s in _sessions.items() if s.last_seen < cutoff]:
        _sessions.pop(sid, None)


def snapshot() -> dict[str, Any]:
    """返回当前活跃连接的结构化快照。

    返回::

        {"transport": "streamable-http", "count": N,
         "sessions": [{"session_id", "client", "user_agent",
                       "created", "last_seen", "idle_seconds"}]}
    """
    with _lock:
        _prune_locked()
        items = []
        for s in _sessions.values():
            items.append({
                "session_id": s.session_id,
                "client": s.client,
                "user_agent": s.user_agent,
                "created": round(s.created, 3),
                "last_seen": round(s.last_seen, 3),
                "idle_seconds": round(_now() - s.last_seen, 2),
            })
        items.sort(key=lambda x: x["last_seen"], reverse=True)
        return {
            "transport": "streamable-http",
            "count": len(items),
            "sessions": items,
        }


# ---------------------------------------------------------------------------
# ASGI 中间件：在 HTTP 层捕获 client / UA / session-id
# ---------------------------------------------------------------------------
def _client_from_scope(scope: dict) -> str:
    client = scope.get("client") or scope.get("remote_addr")
    if isinstance(client, (tuple, list)) and client:
        host = client[0]
        port = client[1] if len(client) > 1 else None
        return f"{host}:{port}" if port else str(host)
    return str(client) if client else "unknown"


def _ua_from_scope(scope: dict) -> str:
    headers = scope.get("headers") or []
    for name, value in headers:
        if name.lower() == b"user-agent":
            try:
                return value.decode("utf-8", "replace")
            except Exception:  # pragma: no cover
                return ""
    return ""


def _session_id_from_scope(scope: dict) -> str | None:
    """从请求头里读取 ``mcp-session-id``（可能不存在）。"""
    headers = scope.get("headers") or []
    for name, value in headers:
        if name.lower() == b"mcp-session-id":
            try:
                return value.decode("ascii", "replace")
            except Exception:  # pragma: no cover
                return None
    return None


class SessionTrackingMiddleware:
    """轻量 ASGI 中间件：记录每个请求的来源与会话，其余原样透传。"""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        client = _client_from_scope(scope)
        user_agent = _ua_from_scope(scope)
        record(_session_id_from_scope(scope), client, user_agent)
        # 响应里也可能带 mcp-session-id（首次 initialize 时分配），包一层 send 捕获。
        async def _send(message) -> None:
            if message.get("type") == "http.response.start":
                for name, value in message.get("headers", []):
                    if name.lower() == b"mcp-session-id":
                        try:
                            record(value.decode("ascii", "replace"), client, user_agent)
                        except Exception:  # pragma: no cover
                            pass
                        break
            await send(message)

        await self.app(scope, receive, _send)


def mount(app) -> None:
    """把 ``/__sessions`` 只读状态路由注册到 FastMCP 实例上（供 GUI 轮询）。

    依赖 ``fastmcp.custom_route``，路由不要求鉴权（仅本地管理用途）。
    只在 HTTP 模式下由 ``cli.py`` 调用；stdio 模式无需也不会调用。
    """
    try:
        from starlette.responses import JSONResponse
    except ImportError:  # pragma: no cover - 无 starlette 时（理论上不会）降级
        return

    @app.custom_route("/__sessions", methods=["GET"])
    async def _sessions_route(request):  # noqa: ANN001
        return JSONResponse(snapshot())
