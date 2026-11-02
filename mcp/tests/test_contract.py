# -*- coding: utf-8 -*-
"""契约测试：op 声明与 lib 真实签名一致、命名唯一、文档字段完整。

    python -m unittest discover -s mcp/tests -v
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

_MCP_DIR = Path(__file__).resolve().parent.parent
if str(_MCP_DIR) not in sys.path:
    sys.path.insert(0, str(_MCP_DIR))

from ciphernest_mcp.contract import RISKS, TYPES, audit  # noqa: E402
from ciphernest_mcp.ops import GROUPS, IMPORT_ERRORS, total_ops  # noqa: E402


class TestGroupShape(unittest.TestCase):
    def test_no_import_errors(self) -> None:
        self.assertEqual(IMPORT_ERRORS, {}, "有工具组导入失败")

    def test_group_names(self) -> None:
        names = [group.name for group in GROUPS]
        self.assertEqual(len(names), len(set(names)), "工具名重复")
        for name in names:
            self.assertTrue(name.startswith("cn_"), name)
        expected = {"cn_help", "cn_codec", "cn_data", "cn_crypto", "cn_image",
                    "cn_web", "cn_requester", "cn_scan", "cn_attack", "cn_llm",
                    "cn_misc"}
        expected |= {"cn_plugin", "cn_sqlmap", "cn_trufflehog", "cn_oneforall",
                     "cn_flaskcookie", "cn_filesensor"}
        self.assertEqual(set(names), expected)

    def test_op_counts(self) -> None:
        self.assertGreaterEqual(len(GROUPS), 16)
        self.assertGreaterEqual(total_ops(), 270, "op 覆盖过少")

    def test_every_op_documented(self) -> None:
        for group in GROUPS:
            for spec in group.ops:
                self.assertTrue(spec.summary, f"{group.name}/{spec.name} 缺 summary")
                self.assertTrue(spec.returns, f"{group.name}/{spec.name} 缺 returns")
                self.assertIn(spec.risk, RISKS)
                self.assertTrue(spec.module, f"{group.name}/{spec.name} 缺 module")
                for param in spec.params:
                    self.assertIn(param.type, TYPES)
                    if not param.required:
                        self.assertTrue(param.has_default(),
                                        f"{group.name}/{spec.name}.{param.name} "
                                        "既非必填又没有默认值")
                    self.assertTrue(param.desc,
                                    f"{group.name}/{spec.name}.{param.name} 缺说明")


class TestAudit(unittest.TestCase):
    def test_contract_matches_lib_signatures(self) -> None:
        issues = audit(GROUPS)
        self.assertEqual(issues, [], json.dumps(issues, ensure_ascii=False, indent=2))


class TestSchema(unittest.TestCase):
    def test_schema_is_json_serializable(self) -> None:
        for group in GROUPS:
            payload = group.schema()
            text = json.dumps(payload, ensure_ascii=False)
            self.assertIn(group.name, text)

    def test_tool_description_sane(self) -> None:
        for group in GROUPS:
            description = group.tool_description()
            self.assertLessEqual(len(description), 3300)
            self.assertIn(group.name, description)
            for spec in group.ops:
                self.assertIn(spec.name, description)


if __name__ == "__main__":
    unittest.main(verbosity=2)
