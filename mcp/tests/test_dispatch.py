# -*- coding: utf-8 -*-
"""分发测试：信封、参数校验、宽松转换、脱敏、路径约定、序列化。

    python -m unittest discover -s mcp/tests -v
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

_MCP_DIR = Path(__file__).resolve().parent.parent
if str(_MCP_DIR) not in sys.path:
    sys.path.insert(0, str(_MCP_DIR))

from ciphernest_mcp.bootstrap import PROJECT_ROOT, Settings  # noqa: E402
from ciphernest_mcp.contract import Ctx, Param, run_op  # noqa: E402
from ciphernest_mcp.envelope import to_jsonable  # noqa: E402
from ciphernest_mcp.ops import GROUPS  # noqa: E402

INDEX = {group.name: group for group in GROUPS}
CTX = Ctx(settings=Settings())


def call(tool: str, op: str, params=None) -> dict:
    group = INDEX[tool]
    return run_op(group, op, params or {}, CTX)


class TestEnvelope(unittest.TestCase):
    def test_success_shape(self) -> None:
        payload = call("cn_codec", "base64_encrypt", {"data": "flag"})
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["tool"], "cn_codec")
        self.assertEqual(payload["op"], "base64_encrypt")
        self.assertEqual(payload["data"], "ZmxhZw==")
        meta = payload["meta"]
        self.assertEqual(meta["module"], "lib.base_codec")
        self.assertEqual(meta["risk"], "safe")
        self.assertIn("elapsed_ms", meta)
        self.assertEqual(meta["params"], {"data": "flag"})

    def test_error_shape(self) -> None:
        payload = call("cn_codec", "base64_encrypt", {"nope": 1})
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"]["code"], "invalid_param")
        self.assertEqual(payload["error"]["field"], "nope")
        self.assertIn("data", payload["error"]["hint"])

    def test_invalid_op_lists_available(self) -> None:
        payload = call("cn_codec", "definitely_not_here")
        self.assertEqual(payload["error"]["code"], "invalid_op")
        self.assertIn("base64_encrypt", payload["error"]["hint"])

    def test_lib_error_classified(self) -> None:
        payload = call("cn_codec", "base64_decrypt", {"data": "ZmxhZ"})
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"]["code"], "lib_error")
        self.assertTrue(payload["error"]["message"])


class TestCoercion(unittest.TestCase):
    def test_int_from_string(self) -> None:
        payload = call("cn_codec", "caesar_encrypt", {"data": "flag", "shift": "3"})
        self.assertEqual(payload["data"], "iodj")

    def test_int_from_hex_string(self) -> None:
        payload = call("cn_crypto", "rsa_recover_d", {"p": "0x3d", "q": "0x35", "e": 17})
        self.assertTrue(payload["ok"])

    def test_bool_from_string(self) -> None:
        payload = call("cn_codec", "convert",
                       {"data": "ff", "from_base": 16, "to_base": 16,
                        "upper": "false"})
        self.assertEqual(payload["data"], "ff")

    def test_list_from_string(self) -> None:
        payload = call("cn_scan", "parse_ports", {"text": "80, 443\n8000"})
        self.assertEqual(payload["data"], [80, 443, 8000])

    def test_hex_param(self) -> None:
        payload = call("cn_crypto", "sm4_ecb_encrypt",
                       {"data": "flag", "key": "0123 4567 89ab cdef fedc ba98 7654 3210"})
        self.assertTrue(payload["ok"], payload)
        self.assertIn("hex", payload["data"])

    def test_choices_rejected(self) -> None:
        payload = call("cn_codec", "base85_encrypt", {"data": "flag", "variant": "x"})
        self.assertEqual(payload["error"]["code"], "range_error")

    def test_range_rejected(self) -> None:
        payload = call("cn_scan", "parse_ports", {"text": "80", "limit": 0})
        self.assertEqual(payload["error"]["code"], "range_error")

    def test_param_defaults(self) -> None:
        self.assertFalse(Param("x", "int", False).has_default())
        self.assertTrue(Param("x", "int", False, 0).has_default())
        self.assertEqual(Param("x", "int", False, 0).effective_default(), 0)


class TestMasking(unittest.TestCase):
    def test_secret_keys_masked(self) -> None:
        from ciphernest_mcp.envelope import mask_params
        masked = mask_params({
            "password": "hunter2", "user": "root", "api_key": "sk-xxx",
            "token": "abc", "cookie": "sid=1", "private_key": "deadbeef",
            "data": "flag", "key": "0123",
        })
        self.assertEqual(masked["password"], "***")
        self.assertEqual(masked["api_key"], "***")
        self.assertEqual(masked["token"], "***")
        self.assertEqual(masked["cookie"], "***")
        self.assertEqual(masked["private_key"], "***")
        self.assertEqual(masked["key"], "***")
        self.assertEqual(masked["user"], "root")
        self.assertEqual(masked["data"], "flag")

    def test_meta_params_masked_in_envelope(self) -> None:
        from ciphernest_mcp.envelope import envelope_ok
        payload = envelope_ok("cn_demo", "op", "ok", module="lib.demo",
                              params={"password": "p", "text": "t"})
        self.assertEqual(payload["meta"]["params"]["password"], "***")
        self.assertEqual(payload["meta"]["params"]["text"], "t")


class TestSerialization(unittest.TestCase):
    def test_bytes_payload(self) -> None:
        payload = to_jsonable(b"flag")
        self.assertEqual(payload["hex"], "666c6167")
        self.assertEqual(payload["text"], "flag")
        self.assertTrue(payload["is_text"])

    def test_binary_bytes_payload(self) -> None:
        payload = to_jsonable(b"\xff\xfe")
        self.assertFalse(payload["is_text"])
        self.assertIsNone(payload["text"])

    def test_path_and_dataclass(self) -> None:
        import dataclasses

        @dataclasses.dataclass
        class Inner:
            value: int

        @dataclasses.dataclass
        class Outer:
            path: Path
            inner: Inner
            items: tuple = (1, 2)

        payload = to_jsonable(Outer(PROJECT_ROOT, Inner(3)))
        self.assertIsInstance(payload["path"], str)
        self.assertEqual(payload["inner"], {"value": 3})
        self.assertEqual(payload["items"], [1, 2])

    def test_unpack_tuple(self) -> None:
        payload = call("cn_data", "loads_json", {"data": '{"a":1,"a":2}'})
        self.assertEqual(payload["data"]["duplicate_keys"], ["a"])


class TestPaths(unittest.TestCase):
    def test_relative_path_is_project_root_based(self) -> None:
        payload = call("cn_data", "file_to_hex", {"path": "main.py", "limit": 4})
        self.assertTrue(payload["ok"], payload)
        self.assertTrue(payload["data"]["path"].startswith(str(PROJECT_ROOT)))
        self.assertGreater(payload["data"]["size"], 4)
        self.assertTrue(payload["data"]["truncated"])
        self.assertLessEqual(len(payload["data"]["hex"]), 8)

    def test_missing_file_is_io_error(self) -> None:
        payload = call("cn_data", "file_to_hex", {"path": "no/such/file.bin"})
        self.assertEqual(payload["error"]["code"], "io")


class TestHelpTool(unittest.TestCase):
    def test_list(self) -> None:
        payload = call("cn_help", "list")
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["data"]["tool_count"], len(GROUPS))

    def test_help_by_op(self) -> None:
        payload = call("cn_help", "help", {"op": "sm4_ecb_encrypt"})
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["data"]["tool"], "cn_crypto")
        params = {item["name"] for item in payload["data"]["params"]}
        self.assertIn("key", params)

    def test_help_unknown_op(self) -> None:
        payload = call("cn_help", "help", {"op": "nope"})
        self.assertEqual(payload["error"]["code"], "invalid_op")

    def test_audit_clean(self) -> None:
        payload = call("cn_help", "audit")
        self.assertTrue(payload["data"]["ok"])

    def test_export(self) -> None:
        payload = call("cn_help", "export")
        self.assertEqual(len(payload["data"]["tools"]), len(GROUPS))


class TestStatefulMisc(unittest.TestCase):
    def test_pomodoro_cycle(self) -> None:
        status = call("cn_misc", "pomodoro_start", {"work_minutes": 1})
        self.assertTrue(status["data"]["running"])
        paused = call("cn_misc", "pomodoro_pause")
        self.assertTrue(paused["data"]["paused"])
        resumed = call("cn_misc", "pomodoro_resume")
        self.assertFalse(resumed["data"]["paused"])
        reset = call("cn_misc", "pomodoro_reset")
        self.assertTrue(reset["data"]["idle"])

    def test_proxy_status(self) -> None:
        payload = call("cn_misc", "proxy_status")
        self.assertTrue(payload["ok"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
