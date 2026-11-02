# -*- coding: utf-8 -*-
"""第三方插件封装层测试：发现、适配器、安全约束、原生回退。

    python -m unittest discover -s mcp/tests -v
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

_MCP_DIR = Path(__file__).resolve().parent.parent
if str(_MCP_DIR) not in sys.path:
    sys.path.insert(0, str(_MCP_DIR))

from 28zenro_mcp.bootstrap import Settings  # noqa: E402
from 28zenro_mcp.contract import Ctx, run_op  # noqa: E402
from 28zenro_mcp.envelope import ToolError  # noqa: E402
from 28zenro_mcp.ops import GROUPS  # noqa: E402
from 28zenro_mcp.pluginkit.runtime import (PLUGINS, get_plugin,  # noqa: E402
                                              run_plugin)

INDEX = {group.name: group for group in GROUPS}
CTX = Ctx(settings=Settings())


def call(tool: str, op: str, params=None) -> dict:
    return run_op(INDEX[tool], op, params or {}, CTX)


class TestDiscovery(unittest.TestCase):
    def test_expected_plugins_found(self) -> None:
        for key in ("trufflehog", "sqlmap", "oneforall", "flaskcookie",
                    "filesensor"):
            self.assertIn(key, PLUGINS, f"未发现插件 {key}")
            self.assertTrue(PLUGINS[key].available,
                            f"插件 {key} 入口不存在：{PLUGINS[key].entry}")

    def test_plugin_groups_registered(self) -> None:
        for name in ("cn_plugin", "cn_sqlmap", "cn_trufflehog", "cn_oneforall",
                     "cn_flaskcookie", "cn_filesensor"):
            self.assertIn(name, INDEX)
            self.assertTrue(INDEX[name].ops, f"{name} 没有 op")

    def test_plugin_metadata(self) -> None:
        sqlmap = PLUGINS["sqlmap"]
        self.assertEqual(sqlmap.kind, "python")
        self.assertEqual(sqlmap.entry.name, "sqlmap.py")
        self.assertTrue(sqlmap.cwd.is_dir())
        trufflehog = PLUGINS["trufflehog"]
        self.assertEqual(trufflehog.kind, "binary")

    def test_list_op(self) -> None:
        payload = call("cn_plugin", "list")
        self.assertTrue(payload["ok"])
        data = payload["data"]
        self.assertEqual(data["count"], len(PLUGINS))
        self.assertEqual(data["missing"], [])
        keys = {item["key"] for item in data["plugins"]}
        self.assertIn("sqlmap", keys)


class TestSafety(unittest.TestCase):
    def test_no_shell_interpolation(self) -> None:
        """参数是数组逐个透传，含空格/元字符的单个参数不会被拆开。"""
        plugin = get_plugin("trufflehog")
        argv = plugin.command(["a b", "$(whoami)", "; rm -rf /"])
        self.assertEqual(argv[-3:], ["a b", "$(whoami)", "; rm -rf /"])
        self.assertIsInstance(argv, list)

    def test_string_args_rejected(self) -> None:
        plugin = get_plugin("trufflehog")
        with self.assertRaises(ToolError):
            run_plugin(plugin, "filesystem /tmp --json")  # type: ignore[arg-type]

    def test_nul_rejected(self) -> None:
        plugin = get_plugin("trufflehog")
        with self.assertRaises(ToolError):
            run_plugin(plugin, ["a\x00b"], timeout=5)

    def test_unknown_plugin(self) -> None:
        payload = call("cn_plugin", "run", {"plugin": "../evil", "args": ["x"]})
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"]["code"], "invalid_param")
        self.assertIn("hint", payload["error"])

    def test_missing_plugin_param(self) -> None:
        payload = call("cn_plugin", "info", {})
        self.assertEqual(payload["error"]["code"], "missing_param")

    def test_stdin_isolated_by_default(self) -> None:
        """默认 DEVNULL：sqlmap 会读 stdin 等回车，不能让它吃到父进程输入。"""
        payload = call("cn_plugin", "run",
                       {"plugin": "sqlmap", "args": ["--version"],
                        "max_seconds": 120})
        self.assertTrue(payload["ok"], payload)
        self.assertIsNotNone(payload["data"]["returncode"])


class TestAdapters(unittest.TestCase):
    def test_trufflehog_version(self) -> None:
        payload = call("cn_trufflehog", "version")
        self.assertTrue(payload["ok"])
        self.assertIn("trufflehog", payload["data"]["version"])

    def test_sqlmap_version_and_tamper(self) -> None:
        version = call("cn_sqlmap", "version")
        self.assertTrue(version["ok"])
        self.assertRegex(version["data"]["version"], r"\d+\.\d+\.\d+")
        tampers = call("cn_sqlmap", "tamper_list", {"keyword": "between"})
        self.assertTrue(tampers["ok"])
        self.assertIn("between", tampers["data"]["scripts"])

    def test_oneforall_version(self) -> None:
        payload = call("cn_oneforall", "version")
        self.assertTrue(payload["ok"])
        self.assertRegex(payload["data"]["version"], r"\d+\.\d+\.\d+")

    def test_filesensor_version(self) -> None:
        payload = call("cn_filesensor", "version")
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["data"]["version"], "0.2")

    def test_flaskcookie_roundtrip(self) -> None:
        structure = {"user": "admin", "role": "admin"}
        encoded = call("cn_flaskcookie", "encode",
                       {"secret": "dev-secret", "structure": structure})
        self.assertTrue(encoded["ok"], encoded)
        cookie = encoded["data"]["cookie"]
        self.assertTrue(cookie)
        decoded = call("cn_flaskcookie", "decode",
                       {"secret": "dev-secret", "cookie": cookie})
        self.assertTrue(decoded["ok"], decoded)
        self.assertEqual(decoded["data"]["value"], structure)

    def test_flaskcookie_decode_rejects_bad_secret(self) -> None:
        encoded = call("cn_flaskcookie", "encode",
                       {"secret": "right", "structure": {"a": 1}})
        cookie = encoded["data"]["cookie"]
        payload = call("cn_flaskcookie", "decode",
                       {"secret": "wrong", "cookie": cookie})
        self.assertFalse(payload["ok"])
        self.assertIn(payload["error"]["code"], ("lib_error", "plugin_exit"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
