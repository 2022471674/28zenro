# -*- coding: utf-8 -*-
"""端到端测试：真的以子进程启动 MCP 服务器，走 stdio JSON-RPC 握手。

覆盖：initialize / tools/list / tools/call（成功 + 失败）/ resources/list。

    python -m unittest mcp.tests.test_stdio -v
    # 或
    python mcp/tests/test_stdio.py
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import threading
import unittest
from pathlib import Path
from typing import Any

_MCP_DIR = Path(__file__).resolve().parent.parent
_PROJECT_ROOT = _MCP_DIR.parent
if str(_MCP_DIR) not in sys.path:
    sys.path.insert(0, str(_MCP_DIR))

SERVER = _MCP_DIR / "server.py"
PROTOCOL_VERSION = "2025-06-18"


class StdioClient:
    """极简 MCP stdio 客户端：一行一个 JSON-RPC 消息。"""

    def __init__(self) -> None:
        env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
        self.proc = subprocess.Popen(
            [sys.executable, str(SERVER)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=str(_PROJECT_ROOT), env=env, text=True, encoding="utf-8",
            bufsize=1,
        )
        self._messages: queue.Queue[dict[str, Any] | None] = queue.Queue()
        self._stderr: list[str] = []
        threading.Thread(target=self._read_stdout, daemon=True).start()
        threading.Thread(target=self._read_stderr, daemon=True).start()

    # -- 后台读取 ----------------------------------------------------------
    def _read_stdout(self) -> None:
        assert self.proc.stdout is not None
        try:
            for line in self.proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    self._messages.put(json.loads(line))
                except json.JSONDecodeError:
                    self._messages.put({"raw": line})
        finally:
            self._messages.put(None)

    def _read_stderr(self) -> None:
        assert self.proc.stderr is not None
        for line in self.proc.stderr:
            self._stderr.append(line.rstrip())

    # -- 协议 --------------------------------------------------------------
    def send(self, payload: dict[str, Any]) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
        self.proc.stdin.flush()

    def recv(self, timeout: float = 30.0) -> dict[str, Any]:
        message = self._messages.get(timeout=timeout)
        if message is None:
            raise AssertionError(f"服务器关闭了 stdout；stderr:\n{self.stderr()}")
        return message

    def request(self, request_id: int, method: str,
                params: dict[str, Any] | None = None,
                timeout: float = 30.0) -> dict[str, Any]:
        self.send({"jsonrpc": "2.0", "id": request_id, "method": method,
                   "params": params or {}})
        while True:
            message = self.recv(timeout)
            if message.get("id") == request_id:
                return message
            if message.get("id") is None:
                continue  # 通知 / 服务端日志帧
            raise AssertionError(f"收到意外响应：{message}")

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        self.send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def stderr(self) -> str:
        return "\n".join(self._stderr)

    def close(self) -> None:
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)


def _tool_text(response: dict[str, Any]) -> dict[str, Any]:
    """从 tools/call 响应里取出业务 JSON。"""
    result = response.get("result") or {}
    content = result.get("content") or []
    assert content, f"响应没有 content：{response}"
    text = content[0].get("text", "")
    return json.loads(text)


class TestStdioServer(unittest.TestCase):
    client: StdioClient

    @classmethod
    def setUpClass(cls) -> None:
        cls.client = StdioClient()
        init = cls.client.request(1, "initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "28zenro-selftest", "version": "1.0"},
        })
        cls.init_result = init.get("result") or {}
        cls.client.notify("notifications/initialized")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.client.close()

    def test_initialize(self) -> None:
        server_info = self.init_result.get("serverInfo") or {}
        self.assertEqual(server_info.get("name"), "28zenro")
        self.assertIn("protocolVersion", self.init_result)
        self.assertIn("tools", (self.init_result.get("capabilities") or {}))

    def test_tools_list(self) -> None:
        response = self.client.request(2, "tools/list")
        tools = (response.get("result") or {}).get("tools") or []
        names = {tool["name"] for tool in tools}
        self.assertGreaterEqual(len(tools), 16)
        for expected in ("cn_help", "cn_codec", "cn_crypto", "cn_web",
                         "cn_scan", "cn_attack", "cn_llm", "cn_misc",
                         "cn_image", "cn_data", "cn_plugin", "cn_sqlmap",
                         "cn_trufflehog", "cn_oneforall", "cn_flaskcookie",
                         "cn_filesensor"):
            self.assertIn(expected, names)
        codec = next(tool for tool in tools if tool["name"] == "cn_codec")
        schema = codec["inputSchema"]
        self.assertEqual(set(schema["properties"]), {"op", "params"})
        self.assertIn("op", schema["required"])
        self.assertTrue(codec.get("description"))

    def test_tools_call_success(self) -> None:
        response = self.client.request(3, "tools/call", {
            "name": "cn_codec",
            "arguments": {"op": "base64_encrypt", "params": {"data": "flag"}},
        })
        payload = _tool_text(response)
        self.assertTrue(payload["ok"], payload)
        self.assertEqual(payload["data"], "ZmxhZw==")
        self.assertEqual(payload["meta"]["module"], "lib.base_codec")

    def test_tools_call_error(self) -> None:
        response = self.client.request(4, "tools/call", {
            "name": "cn_codec",
            "arguments": {"op": "base64_decrypt", "params": {"data": "ZmxhZ"}},
        })
        payload = _tool_text(response)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"]["code"], "lib_error")

    def test_tools_call_unknown_op(self) -> None:
        response = self.client.request(5, "tools/call", {
            "name": "cn_help",
            "arguments": {"op": "help", "params": {"op": "base64_encrypt"}},
        })
        payload = _tool_text(response)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["data"]["name"], "base64_encrypt")

    def test_resources_list(self) -> None:
        response = self.client.request(6, "resources/list")
        resources = (response.get("result") or {}).get("resources") or []
        uris = {resource["uri"] for resource in resources}
        self.assertIn("28zenro://contract", uris)
        self.assertIn("28zenro://guide", uris)


if __name__ == "__main__":
    unittest.main(verbosity=2)
