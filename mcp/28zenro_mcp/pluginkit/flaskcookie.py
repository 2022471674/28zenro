# -*- coding: utf-8 -*-
"""cn_flaskcookie —— Flask Session Cookie Manager 二次封装。

上游脚本 ``flask_session_cookie_manager3.py`` 依赖 Flask 内部的 ``MockApp``，
在 **Flask 3.x** 上会抛 ``'MockApp' object has no attribute 'config'``（encode /
带 secret 的 decode 都不可用）。因此适配器：

1. 先按原样调用插件 CLI（保留插件行为）；
2. 一旦 CLI 返回 ``[Decoding error]`` / ``[Encoding error]``，自动回退到
   用 ``itsdangerous`` 复刻 Flask 的签名方案：

   ``URLSafeTimedSerializer(secret, salt="cookie-session",
   serializer=TaggedJSONSerializer(),
   signer_kwargs={"key_derivation": "hmac", "digest_method": sha1})``

返回里用 ``source`` 标明结果来自 ``plugin`` 还是 ``native``，便于排查。
"""

from __future__ import annotations

import ast
import json
from hashlib import sha1
from typing import Any

from ..contract import (Ctx, Group, anyp, custom_op, num, txt)
from ..envelope import ToolError
from .runtime import (first_line, get_plugin, plugin_result, run_plugin)

_KEY = "flaskcookie"
_TOOL = "cn_flaskcookie"


# ---------------------------------------------------------------------------
# 原生实现（Flask 3.x 兼容回退）
# ---------------------------------------------------------------------------
def _serializer(secret: str):
    try:
        from flask.json.tag import TaggedJSONSerializer
        from itsdangerous import URLSafeTimedSerializer
    except ImportError as exc:  # pragma: no cover - 依赖缺失
        raise ToolError(
            "unsupported",
            f"原生回退需要 flask + itsdangerous：{exc}",
            hint="pip install flask itsdangerous",
        ) from exc
    return URLSafeTimedSerializer(
        secret_key=secret,
        salt="cookie-session",
        serializer=TaggedJSONSerializer(),
        signer_kwargs={"key_derivation": "hmac", "digest_method": sha1},
    )


def _native_decode(cookie: str, secret: str) -> Any:
    serializer = _serializer(secret)
    try:
        return serializer.loads(cookie)
    except Exception as exc:  # noqa: BLE001 - itsdangerous 的异常类型较多
        raise ToolError(
            "lib_error",
            f"原生解码失败：{type(exc).__name__}: {exc}",
            hint="检查 secret 是否正确、cookie 是否完整（含两段签名字符串）",
        ) from exc


def _native_encode(secret: str, structure: Any) -> str:
    serializer = _serializer(secret)
    payload = _coerce_structure(structure)
    try:
        return serializer.dumps(payload)
    except Exception as exc:  # noqa: BLE001
        raise ToolError("lib_error", f"原生编码失败：{type(exc).__name__}: {exc}") from exc


def _coerce_structure(structure: Any) -> Any:
    """把外部传入的 session 结构转成 dict（支持 dict / JSON / Python 字面量）。"""
    if isinstance(structure, dict):
        return structure
    text = str(structure or "").strip()
    if not text:
        raise ToolError("missing_param", "缺少必填参数 structure（session 内容）",
                        field="structure")
    for loader in (json.loads, ast.literal_eval):
        try:
            value = loader(text)
        except (ValueError, SyntaxError):
            continue
        if isinstance(value, dict):
            return value
    raise ToolError("invalid_param",
                    "structure 必须是对象，或可解析成对象的 JSON / Python 字面量",
                    field="structure",
                    hint='例：{"structure": "{\\"user\\": \\"admin\\"}"}')


def _parse_cli_value(text: str) -> Any | None:
    """解析插件输出（可能是 b'...' / {'a': 1} / 纯文本）。"""
    raw = text.strip()
    if not raw:
        return None
    try:
        value = ast.literal_eval(raw)
    except (ValueError, SyntaxError):
        return raw
    if isinstance(value, bytes):
        decoded = value.decode("utf-8", "replace")
        try:
            return ast.literal_eval(decoded)
        except (ValueError, SyntaxError):
            return decoded
    return value


# ---------------------------------------------------------------------------
# handlers
# ---------------------------------------------------------------------------
def _version(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    plugin = get_plugin(_KEY)
    run = run_plugin(plugin, ["-h"], timeout=60)
    return plugin_result(run, plugin, {
        "version": first_line(run.stdout) or first_line(run.stderr),
        "homepage": plugin.homepage,
    })


def _decode(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    plugin = get_plugin(_KEY)
    cookie = str(a["cookie"] or "").strip()
    secret = str(a["secret"] or "")
    args = ["decode", "-c", cookie]
    if secret:
        args += ["-s", secret]
    run = run_plugin(plugin, args, timeout=a["max_seconds"])
    text = run.stdout.strip()
    payload: dict[str, Any] = {"args": args, "cookie": cookie,
                               "secret_used": bool(secret)}
    if "[Decoding error]" in text and secret:
        value = _native_decode(cookie, secret)
        payload.update({"source": "native", "value": value,
                        "note": "插件 CLI 与 Flask 3.x 不兼容，已用 itsdangerous 原生实现回退"})
        payload["raw"] = json.dumps(value, ensure_ascii=False, default=str)
        payload["success"] = True
        payload["returncode"] = run.returncode
        payload["duration_ms"] = round(run.duration_ms, 1)
        payload["timed_out"] = run.timed_out
        payload["stdout_tail"] = text[-400:]
        payload["stderr_tail"] = run.stderr.strip()[-400:]
        return payload
    value = _parse_cli_value(text)
    payload.update({"source": "plugin", "value": value, "raw": text})
    return plugin_result(run, plugin, payload)


def _encode(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    plugin = get_plugin(_KEY)
    secret = str(a["secret"] or "").strip()
    if not secret:
        raise ToolError("missing_param", "encode 必须提供 secret", field="secret")
    structure = a["structure"]
    structure_text = (json.dumps(structure, ensure_ascii=False)
                      if isinstance(structure, dict) else str(structure))
    args = ["encode", "-s", secret, "-t", structure_text]
    run = run_plugin(plugin, args, timeout=a["max_seconds"])
    text = run.stdout.strip()
    payload: dict[str, Any] = {"args": ["encode", "-s", "***", "-t", structure_text]}
    if "[Encoding error]" in text or run.returncode != 0:
        cookie = _native_encode(secret, structure)
        payload.update({"source": "native", "cookie": cookie,
                        "note": "插件 CLI 与 Flask 3.x 不兼容，已用 itsdangerous 原生实现回退"})
        payload["success"] = True
        payload["returncode"] = run.returncode
        payload["duration_ms"] = round(run.duration_ms, 1)
        payload["timed_out"] = run.timed_out
        payload["stdout_tail"] = text[-400:]
        payload["stderr_tail"] = run.stderr.strip()[-400:]
        return payload
    cookie = first_line(text)
    payload.update({"source": "plugin", "cookie": cookie})
    return plugin_result(run, plugin, payload)


OPS = [
    custom_op("version", _version, "查看插件的帮助 / 版本信息。", [],
              returns="dict：{success, version, stdout_tail}", risk="safe",
              module="plugins/flask-session-cookie-manager"),
    custom_op("decode", _decode,
              "解码 Flask session cookie；给了 secret 会验签并解出真实结构。",
              [txt("cookie", required=True, desc="session cookie 值（含签名段）"),
               txt("secret", desc="Flask SECRET_KEY；留空则只解 base64 部分（不验签）"),
               num("max_seconds", default=60, desc="最长运行秒数", minimum=2,
                   maximum=300)],
              returns="dict：{success, source, value, raw, cookie, secret_used}",
              risk="safe", module="plugins/flask-session-cookie-manager",
              notes="Flask 3.x 下插件 CLI 会报错，此时自动回退到 itsdangerous 原生实现"
                    "（source=native）。"),
    custom_op("encode", _encode,
              "用 SECRET_KEY 签一个 Flask session cookie（伪造 / 测试用）。",
              [txt("secret", required=True, desc="Flask SECRET_KEY"),
               anyp("structure", required=True,
                    desc="session 内容：对象，或 JSON / Python 字面量字符串"),
               num("max_seconds", default=60, desc="最长运行秒数", minimum=2,
                   maximum=300)],
              returns="dict：{success, source, cookie}", risk="safe",
              module="plugins/flask-session-cookie-manager",
              notes="签名算法与 Flask 3.x 一致（URLSafeTimedSerializer + "
                    "TaggedJSONSerializer + hmac/sha1）；只用于已授权测试。"),
]


GROUP = Group(
    name=_TOOL,
    title="Flask Session Cookie：解码 / 签发",
    summary=("Flask session cookie 的编解码封装：可只解 base64，也可用 SECRET_KEY "
             "验签解出结构、或签出新的 cookie。插件在 Flask 3.x 下失效时自动原生回退。"),
    ops=OPS,
    guide=("decode 不给 secret 只看载荷；给 secret 才会验签。encode 需要 SECRET_KEY，"
           "输出可直接当 Cookie 头用。"),
)
