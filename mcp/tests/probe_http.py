# -*- coding: utf-8 -*-
"""HTTP 端点探针：验证 streamable-http 服务是否可用。

    python mcp/tests/probe_http.py                 # 默认 http://127.0.0.1:8000/mcp
    python mcp/tests/probe_http.py --port 8765
    python mcp/tests/probe_http.py --url http://127.0.0.1:8000/mcp

成功输出三行（initialize / tools/list / tools/call），退出码 0；
失败给出明确原因（拒绝连接 = 服务没以 --http 模式启动），退出码 1。

纯标准库实现，不依赖 mcp SDK，便于在任何环境里排查。
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from typing import Any

PROTOCOL_VERSION = "2025-06-18"


def _post(url: str, payload: dict[str, Any],
          session: str | None = None, timeout: float = 15.0) -> tuple[str, Any]:
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if session:
        headers["Mcp-Session-Id"] = session
    request = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers=headers, method="POST")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", "replace"), response.headers


def _sse_json(body: str) -> Any:
    """从 SSE 响应里取出第一条 data 帧并解析成 JSON。"""
    for line in body.splitlines():
        if line.startswith("data:"):
            return json.loads(line[5:].strip())
    return json.loads(body)


def probe(url: str) -> int:
    print(f"→ 探测 {url}")
    try:
        body, headers = _post(url, {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                       "clientInfo": {"name": "28zenro-probe", "version": "1.0"}},
        })
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        print(f"[FAIL] 连不上：{reason}")
        print("       服务是否以 HTTP 模式启动？应为 "
              "`python mcp/server.py --http`（不是 `python mcp/server.py`）")
        return 1
    except urllib.error.HTTPError as exc:
        print(f"[FAIL] HTTP {exc.code}：{exc.read().decode('utf-8', 'replace')[:300]}")
        return 1

    info = (_sse_json(body).get("result") or {})
    server = info.get("serverInfo") or {}
    session = headers.get("mcp-session-id")
    print(f"[ok] initialize：serverName={server.get('name')} "
          f"version={server.get('version')} protocol={info.get('protocolVersion')} "
          f"session={session}")

    try:
        _post(url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, session)
        body, _ = _post(url, {"jsonrpc": "2.0", "id": 2, "method": "tools/list",
                              "params": {}}, session)
        tools = (_sse_json(body).get("result") or {}).get("tools") or []
        print(f"[ok] tools/list：{len(tools)} 个工具 → "
              f"{', '.join(tool['name'] for tool in tools)}")

        body, _ = _post(url, {
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "cn_help",
                       "arguments": {"op": "version", "params": {}}},
        }, session)
        result = _sse_json(body).get("result") or {}
        content = result.get("content") or []
        payload = json.loads(content[0]["text"]) if content else {}
        if not payload.get("ok"):
            print(f"[FAIL] tools/call 返回异常：{payload}")
            return 1
        data = payload["data"]
        print(f"[ok] tools/call：cn_help/version → {data['tool_count']} 个工具 / "
              f"{data['op_count']} 个 op，python {data['python']}")
    except urllib.error.URLError as exc:
        print(f"[FAIL] 握手后请求失败：{getattr(exc, 'reason', exc)}")
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"[FAIL] 响应解析失败：{type(exc).__name__}: {exc}")
        return 1

    print("\n端点正常，可以用这个 URL 在宿主里添加连接。")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="28zenro MCP HTTP 端点探针")
    parser.add_argument("--url", default="", help="完整 MCP URL（优先于 --host/--port）")
    parser.add_argument("--host", default="127.0.0.1", help="监听地址（默认 127.0.0.1）")
    parser.add_argument("--port", type=int, default=8000, help="端口（默认 8000）")
    args = parser.parse_args(argv)
    url = args.url or f"http://{args.host}:{args.port}/mcp"
    return probe(url)


if __name__ == "__main__":
    raise SystemExit(main())
