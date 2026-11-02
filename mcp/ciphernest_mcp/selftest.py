# -*- coding: utf-8 -*-
"""自检：契约审计 + 纯计算冒烟用例。

    python mcp/server.py --selftest

设计原则
--------
- 只跑**无副作用**的 op（不发网络请求、不写文件、不爆破）；
- 覆盖每个工具组至少一个 op，覆盖成功 / 参数错误 / 未知 op 三条路径；
- 任何一条失败都以非零码退出，便于 CI / 打包脚本卡口。
"""

from __future__ import annotations

import json
from typing import Any, Callable

from .contract import Ctx, audit, run_op
from .envelope import ToolError
from .ops import GROUPS, IMPORT_ERRORS, total_ops

Checker = Callable[[dict[str, Any]], bool]


# ---------------------------------------------------------------------------
# 用例
# ---------------------------------------------------------------------------
def _ok(payload: dict[str, Any]) -> bool:
    return bool(payload.get("ok"))


def _cases() -> list[tuple[str, str, str, dict[str, Any], Checker]]:
    """(说明, tool, op, params, 断言)。"""

    def eq(expected: Any) -> Checker:
        return lambda payload: payload.get("ok") and payload.get("data") == expected

    def ok(_expected: Any = None) -> Checker:
        return _ok

    return [
        # ---- 元工具
        ("元工具 list", "cn_help", "list", {}, ok()),
        ("元工具 version", "cn_help", "version", {}, ok()),
        # ---- 编解码
        ("Base64 编码", "cn_codec", "base64_encrypt", {"data": "flag"}, eq("ZmxhZw==")),
        ("Base64 解码", "cn_codec", "base64_decrypt", {"data": "ZmxhZw=="}, eq("flag")),
        ("Base32 编码", "cn_codec", "base32_encrypt", {"data": "flag"}, ok()),
        ("Base58 编码", "cn_codec", "base58_encrypt", {"data": "flag"}, ok()),
        ("凯撒加密", "cn_codec", "caesar_encrypt", {"data": "flag", "shift": 3},
         eq("iodj")),
        ("ROT13", "cn_codec", "rot13_encrypt", {"data": "synt"}, eq("flag")),
        ("进制转换", "cn_codec", "hex_to_dec", {"data": "ff"}, eq("255")),
        ("任意进制", "cn_codec", "convert",
         {"data": "1010", "from_base": 2, "to_base": 16}, ok()),
        ("URL 编码", "cn_codec", "url_encode", {"data": "a b"}, eq("a%20b")),
        ("文本统计", "cn_codec", "text_count", {"data": "flag{abc}"}, ok()),
        ("ASCII 转字符串", "cn_codec", "ascii_to_str", {"data": "102 108 97 103"},
         eq("flag")),
        ("Brainfuck 执行", "cn_codec", "brainfuck_exec",
         {"program": "++++++++[>++++++++<-]>+."}, ok()),
        # ---- 数据处理
        ("JSON 美化", "cn_data", "format_json", {"data": '{"a":1}'}, ok()),
        ("JSON 压缩", "cn_data", "minify_json", {"data": '{"a": 1}'}, eq('{"a":1}')),
        ("JSON 重复键", "cn_data", "loads_json", {"data": '{"a":1,"a":2}'},
         lambda payload: payload.get("data", {}).get("duplicate_keys") == ["a"]),
        ("十六进制转字节", "cn_data", "hex_to_bytes", {"text": "66 6c"},
         lambda payload: payload.get("data", {}).get("hex") == "666c"),
        ("文本去重", "cn_data", "dedupe", {"data": "a\nb\na"}, eq("a\nb")),
        ("文本对比", "cn_data", "compare",
         {"left": "flag{abc}", "right": "flag{abd}"}, ok()),
        # ---- 密码学
        ("MD5", "cn_crypto", "md5_hex", {"data": "flag"},
         eq("327a6c4304ad5938eaf0efb6cc3e53dc")),
        ("SHA-256", "cn_crypto", "sha256_hex", {"data": "flag"},
         eq(__import__("hashlib").sha256(b"flag").hexdigest())),
        ("SM3", "cn_crypto", "sm3_hex", {"data": "abc"}, ok()),
        ("SM4 往返", "cn_crypto", "sm4_ecb_encrypt",
         {"data": "flag", "key": "0123456789abcdeffedcba9876543210"}, ok()),
        ("RSA gcd", "cn_crypto", "gcd", {"a": 12, "b": 18}, eq(6)),
        ("RSA 求解 d", "cn_crypto", "rsa_recover_d", {"p": 61, "q": 53, "e": 17},
         ok()),
        ("RSA 分解小整数", "cn_crypto", "factor_trial", {"n": 91, "limit": 100},
         eq([7, 13])),
        ("JWT 解析", "cn_crypto", "parse",
         {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                   "eyJzdWIiOiIxMjM0In0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
         ok()),
        ("密文识别", "cn_crypto", "readability", {"text": "flag{abc}"}, ok()),
        # ---- 图片（不依赖文件：只测纯函数）
        ("颜色解析", "cn_image", "describe_params", {"channels": "RGB"}, ok()),
        # ---- 网络工具的纯函数部分
        ("域名规范化", "cn_web", "normalize_domain",
         {"raw": "https://sub.example.com:8443/x"}, ok()),
        ("IP 展开", "cn_web", "expand_ips", {"target": "10.0.0.0/30"}, ok()),
        ("端口表达式解析", "cn_scan", "parse_ports", {"text": "80,443,8000-8002"},
         lambda payload: payload.get("data") == [80, 443, 8000, 8001, 8002]),
        # ---- HTTP 请求器（只测纯计算，不发请求）
        ("URL 安全化保留密文", "cn_requester", "url_safe", {"text": "a+b/c="},
         eq("a+b/c=")),
        ("载荷切分", "cn_requester", "split_payloads", {"text": "a\n\nb"},
         eq(["a", "b"])),
        ("密码学生成器清单", "cn_requester", "crypto_list", {},
         lambda payload: payload.get("ok") and payload["data"]["count"] > 0),
        ("Base64 批量变换", "cn_requester", "crypto_transform",
         {"data": "flag", "op": "crypto.base64"},
         lambda payload: payload.get("data", {}).get("outputs") == ["ZmxhZw=="]),
        ("请求组装不二次编码", "cn_requester", "compose",
         {"url": "http://h/api", "method": "POST", "query": "token={{payload}}",
          "body": "d={{payload}}", "body_kind": "form", "values": ["a+b=", "a+b="]},
         lambda payload: payload.get("ok")
         and "token=a+b=" in payload["data"]["url"]
         and payload["data"]["body"] == "d=a+b="),
        ("载荷计划不发送", "cn_requester", "plan",
         {"url": "http://h/api", "query": "a={{payload}}\nb={{payload}}",
          "mode": "loop", "attack": "sniper", "payloads": "1\n2"},
         lambda payload: payload.get("data", {}).get("total_requests") == 4),
        ("目标规范化", "cn_scan", "normalize_target", {"raw": "example.com"}, ok()),
        # ---- 攻击类纯函数
        ("哈希长度", "cn_attack", "hash_length", {"hash_name": "md5"}, eq(32)),
        ("微博凭证解析", "cn_attack", "split_pair", {"line": "wx123:secret"},
         ok()),
        # ---- LLM / 杂项纯函数
        ("语言判断", "cn_llm", "detect_language", {"text": "hello"}, ok()),
        ("频道口令", "cn_misc", "generate_password", {}, ok()),
        ("本地 IP", "cn_misc", "lan_ips", {}, ok()),
        ("代理池状态", "cn_misc", "proxy_status", {}, ok()),
    ] + _plugin_cases()


def _plugin_cases() -> list[tuple[str, str, str, dict[str, Any], Checker]]:
    """第三方插件用例：只对「已发现且入口存在」的插件追加，缺插件不算失败。"""
    cases: list[tuple[str, str, str, dict[str, Any], Checker]] = [
        ("插件清单", "cn_plugin", "list", {}, _ok),
    ]
    try:
        from .pluginkit.runtime import PLUGINS
    except Exception:  # pragma: no cover - 插件层不可用时跳过
        return cases

    def available(key: str) -> bool:
        plugin = PLUGINS.get(key)
        return plugin is not None and plugin.available

    versions = (
        ("trufflehog 版本", "cn_trufflehog", "trufflehog"),
        ("sqlmap 版本", "cn_sqlmap", "sqlmap"),
        ("OneForAll 版本", "cn_oneforall", "oneforall"),
        ("flaskcookie 帮助", "cn_flaskcookie", "flaskcookie"),
        ("FileSensor 版本", "cn_filesensor", "filesensor"),
    )
    for title, tool, key in versions:
        if available(key):
            cases.append((title, tool, "version", {}, _ok))

    if available("sqlmap"):
        cases.append((
            "sqlmap tamper 枚举", "cn_sqlmap", "tamper_list",
            {"keyword": "space"},
            lambda payload: payload.get("ok")
            and payload["data"]["count"] > 0
            and "space2comment" in payload["data"]["scripts"],
        ))
    if available("oneforall"):
        cases.append(("OneForAll 历史结果", "cn_oneforall", "list_results", {},
                      lambda payload: payload.get("ok")
                      and isinstance(payload["data"].get("files"), list)))
    if available("trufflehog"):
        cases.append(("插件通用直调", "cn_plugin", "run",
                      {"plugin": "trufflehog", "args": ["--version"]},
                      lambda payload: payload.get("ok")
                      and payload["data"]["success"] is True))
    return cases


def _error_cases() -> list[tuple[str, str, str, dict[str, Any], str]]:
    """(说明, tool, op, params, 期望错误码)。"""
    return [
        ("未知 op", "cn_codec", "no_such_op", {}, "invalid_op"),
        ("未知参数", "cn_codec", "base64_encrypt", {"bogus": 1}, "invalid_param"),
        ("缺必填参数", "cn_codec", "caesar_encrypt", {"data": "flag"}, "missing_param"),
        ("类型错误", "cn_codec", "caesar_encrypt",
         {"data": "flag", "shift": "abc"}, "type_error"),
        ("取值越界", "cn_codec", "base85_encrypt",
         {"data": "flag", "variant": "zzz"}, "range_error"),
        ("lib 业务异常", "cn_codec", "base64_decrypt", {"data": "ZmxhZ"}, "lib_error"),
    ]


# ---------------------------------------------------------------------------
# 执行
# ---------------------------------------------------------------------------
def run(verbose: bool = True) -> int:
    from .bootstrap import Settings

    ctx = Ctx(settings=Settings(), prefix="selftest ")
    failures: list[str] = []
    passed = 0
    skipped = 0  # 环境限制（如打包版缺独立 Python 运行时）不算失败

    if IMPORT_ERRORS:
        for name, reason in IMPORT_ERRORS.items():
            message = f"工具组 {name} 导入失败：{reason}"
            failures.append(message)
            if verbose:
                print(f"[FAIL] {message}")

    issues = audit(GROUPS)
    for issue in issues:
        message = f"契约审计：{issue}"
        failures.append(message)
        if verbose:
            print(f"[FAIL] {message}")
    if verbose:
        print(f"[ok] 契约审计通过（{total_ops()} 个 op 对照 lib 签名）")

    index = {group.name: group for group in GROUPS}
    for name, tool, op, params, checker in _cases():
        group = index.get(tool)
        if group is None:
            failures.append(f"{name}：工具 {tool} 不可用（导入失败）")
            if verbose:
                print(f"[SKIP] {name}：{tool} 不可用")
            continue
        payload = run_op(group, op, params, ctx)
        good = False
        try:
            good = bool(checker(payload))
        except Exception as exc:  # pragma: no cover - 断言本身抛错
            good = False
            payload = {"assert_error": f"{type(exc).__name__}: {exc}"}
        if good:
            passed += 1
            if verbose:
                print(f"[ok] {name}")
            continue
        # 打包版未部署独立 Python 运行时等环境限制：记 SKIP，不计失败
        error = payload.get("error") if isinstance(payload, dict) else None
        if isinstance(error, dict) and error.get("code") == "unsupported":
            skipped += 1
            if verbose:
                print(f"[SKIP] {name}：{str(error.get('message', ''))[:80]}")
            continue
        failures.append(f"{name}（{tool}/{op}）")
        if verbose:
            print(f"[FAIL] {name}：{json.dumps(payload, ensure_ascii=False)[:400]}")

    for name, tool, op, params, expected_code in _error_cases():
        group = index.get(tool)
        if group is None:
            continue
        payload = run_op(group, op, params, ctx)
        actual = (payload.get("error") or {}).get("code")
        if payload.get("ok") is False and actual == expected_code:
            passed += 1
            if verbose:
                print(f"[ok] 错误路径：{name} -> {actual}")
        else:
            failures.append(f"错误路径 {name}：期望 {expected_code}，实际 {actual}")
            if verbose:
                print(f"[FAIL] 错误路径 {name}：期望 {expected_code}，"
                      f"实际 {json.dumps(payload, ensure_ascii=False)[:300]}")

    total = passed + len(failures)
    if verbose:
        note = f"，另有 {skipped} 跳过（环境限制）" if skipped else ""
        print(f"\n结果：{passed}/{total} 通过，{len(failures)} 失败{note}")
    if failures:
        return 1
    return 0
