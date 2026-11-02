# -*- coding: utf-8 -*-
"""统一返回信封与序列化。

所有工具（无论成功失败）都返回同一套信封，便于 Agent 稳定解析：

成功::

    {
      "ok": true,
      "tool": "cn_codec",
      "op": "base64_encrypt",
      "data": "ZmxhZw==",
      "meta": {
        "module": "lib.base_codec",
        "risk": "safe",
        "elapsed_ms": 0.42,
        "params": {"data": "flag"},
        "warnings": []
      }
    }

失败::

    {
      "ok": false,
      "tool": "cn_codec",
      "op": "base64_encrypt",
      "error": {
        "code": "missing_param",
        "message": "缺少必填参数 data",
        "field": "data",
        "hint": "cn_help(op=\"help\", params={\"op\": \"base64_encrypt\"}) 查看完整参数表"
      },
      "meta": {...}
    }

错误码
------
``invalid_op`` 未知 op ｜ ``invalid_param`` 未知/非法参数 ｜ ``missing_param`` 缺必填
``type_error`` 类型不符 ｜ ``range_error`` 越界 ｜ ``lib_error`` lib 抛出的业务异常
``timeout`` 超时 ｜ ``network`` 网络错误 ｜ ``io`` 文件/系统错误 ｜
``unsupported`` 环境不支持 ｜ ``internal`` 未预期异常
"""

from __future__ import annotations

import dataclasses
import json
import math
import re
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# 错误码
# ---------------------------------------------------------------------------
CODES = {
    "invalid_op", "invalid_param", "missing_param", "type_error", "range_error",
    "lib_error", "timeout", "network", "io", "unsupported", "internal",
}

#: 序列化结果的安全上限：超过后只回传摘要，避免撑爆宿主上下文。
MAX_JSON_CHARS = 400_000
#: 截断时保留的预览长度。
PREVIEW_CHARS = 4_000


class ToolError(Exception):
    """带错误码的可控异常：由参数校验 / handler 主动抛出。"""

    def __init__(self, code: str, message: str, *,
                 field: str | None = None, hint: str | None = None,
                 detail: Any = None) -> None:
        super().__init__(message)
        self.code = code if code in CODES else "internal"
        self.message = message
        self.field = field
        self.hint = hint
        self.detail = detail

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.field:
            payload["field"] = self.field
        if self.hint:
            payload["hint"] = self.hint
        if self.detail is not None:
            payload["detail"] = to_jsonable(self.detail)
        return payload


# ---------------------------------------------------------------------------
# 序列化
# ---------------------------------------------------------------------------
def _bytes_payload(value: bytes) -> dict[str, Any]:
    """bytes 统一表达：hex + 长度 + （可能的）UTF-8 文本。"""
    raw = bytes(value)
    try:
        text = raw.decode("utf-8")
        is_text = True
    except UnicodeDecodeError:
        text = None
        is_text = False
    return {"hex": raw.hex(), "length": len(raw), "text": text,
            "is_text": is_text}


def to_jsonable(value: Any, _depth: int = 0) -> Any:
    """把任意返回值压成可 JSON 序列化的结构。

    规则见 CONTRACT.md「结果序列化」：
    ``bytes`` → ``{hex, length, text, is_text}``；``Path`` → 字符串；
    ``dataclass`` → 优先 ``to_dict()``，否则按字段展开；``tuple`` → 数组；
    ``set`` → 排序后数组；非有限浮点 → 字符串。
    """
    if _depth > 12:  # 防御性：避免异常对象图导致递归失控
        return "<max-depth>"
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return _bytes_payload(bytes(value))
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            out[key if isinstance(key, str) else str(key)] = to_jsonable(item, _depth + 1)
        return out
    if isinstance(value, (list, tuple, set, frozenset)):
        items = list(value)
        if isinstance(value, (set, frozenset)):
            items.sort(key=lambda item: repr(item))
        return [to_jsonable(item, _depth + 1) for item in items]
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        try:
            return to_jsonable(to_dict(), _depth + 1)
        except Exception:  # pragma: no cover - 对象自身 to_dict 出错时降级
            pass
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        try:
            return {
                f.name: to_jsonable(getattr(value, f.name), _depth + 1)
                for f in dataclasses.fields(value)
            }
        except Exception:  # pragma: no cover
            pass
    text = repr(value)
    return text if len(text) <= 2000 else text[:2000] + "…"


def json_size(value: Any) -> int:
    """估算序列化长度（字符数），用于大纲保护。"""
    try:
        return len(json.dumps(value, ensure_ascii=False, default=str))
    except Exception:  # pragma: no cover
        return 0


def guard_size(data: Any) -> tuple[Any, dict[str, Any]]:
    """超过 :data:`MAX_JSON_CHARS` 时返回摘要 + 预览，并给出 meta 说明。"""
    size = json_size(data)
    if size <= MAX_JSON_CHARS:
        return data, {}
    try:
        text = json.dumps(data, ensure_ascii=False, default=str)
    except Exception:  # pragma: no cover
        text = repr(data)
    summary = {
        "truncated": True,
        "chars": len(text),
        "limit": MAX_JSON_CHARS,
        "preview": text[:PREVIEW_CHARS],
        "note": ("结果超过安全上限，仅回传预览；请缩小范围（更小的字典 / 更多过滤参数）"
                 "或改用 lib 工具分步获取。"),
    }
    return summary, {"truncated": True, "chars": len(text)}


# ---------------------------------------------------------------------------
# 脱敏
# ---------------------------------------------------------------------------
_SECRET_KEY = re.compile(
    r"(?i)^(?:.*_)?(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|apikey|"
    r"authorization|cookie|private[_-]?key|priv|salt|credential|key)$"
)


def mask_params(params: dict[str, Any]) -> dict[str, Any]:
    """回显参数时对敏感键（密码 / 密钥 / 令牌 / Cookie）做脱敏。"""
    masked: dict[str, Any] = {}
    for key, value in params.items():
        if _SECRET_KEY.match(str(key)):
            masked[key] = "***" if value not in (None, "") else value
        else:
            masked[key] = to_jsonable(value)
    return masked


# ---------------------------------------------------------------------------
# 信封构造
# ---------------------------------------------------------------------------
def envelope_ok(tool: str, op: str, data: Any, *,
                module: str = "", risk: str = "safe",
                elapsed_ms: float = 0.0, params: dict[str, Any] | None = None,
                warnings: list[str] | None = None,
                extra_meta: dict[str, Any] | None = None) -> dict[str, Any]:
    payload, guard_meta = guard_size(data)
    meta: dict[str, Any] = {
        "module": module,
        "risk": risk,
        "elapsed_ms": round(elapsed_ms, 3),
        "params": mask_params(params or {}),
    }
    if warnings:
        meta["warnings"] = list(warnings)
    meta.update(guard_meta)
    if extra_meta:
        meta.update(to_jsonable(extra_meta))
    return {"ok": True, "tool": tool, "op": op, "data": payload, "meta": meta}


def envelope_fail(tool: str, op: str, error: ToolError | Exception, *,
                  module: str = "", risk: str = "safe",
                  elapsed_ms: float = 0.0,
                  params: dict[str, Any] | None = None) -> dict[str, Any]:
    if isinstance(error, ToolError):
        payload = error.to_dict()
    else:
        payload = classify_exception(error)
    meta: dict[str, Any] = {
        "module": module,
        "risk": risk,
        "elapsed_ms": round(elapsed_ms, 3),
        "params": mask_params(params or {}),
    }
    return {"ok": False, "tool": tool, "op": op, "error": payload, "meta": meta}


# ---------------------------------------------------------------------------
# 异常 → 错误码
# ---------------------------------------------------------------------------
_NETWORK_HINTS = (
    "connectionerror", "timeout", "readtimeout", "connecttimeout", "gaierror",
    "herror", "urlerror", "sslerror", "proxyerror", "socks", "connection",
)
_TIMEOUT_HINTS = ("timeout", "timed out", "超时")


def classify_exception(exc: BaseException) -> dict[str, Any]:
    """把任意异常映射到统一错误码，保留原始类型名便于排查。"""
    name = type(exc).__name__
    text = str(exc)
    lowered = f"{name} {text}".lower()
    module = type(exc).__module__ or ""

    if isinstance(exc, ToolError):
        return exc.to_dict()
    if any(hint in lowered for hint in _TIMEOUT_HINTS):
        code = "timeout"
    elif isinstance(exc, (FileNotFoundError, PermissionError, IsADirectoryError,
                          NotADirectoryError, OSError)):
        code = "io"
    elif any(hint in lowered for hint in _NETWORK_HINTS) or module.startswith(
            ("socket", "ssl", "urllib3", "requests")):
        code = "network"
    elif isinstance(exc, (TypeError, AttributeError, KeyError)):
        code = "type_error"
    elif isinstance(exc, (ValueError, ArithmeticError)):
        code = "lib_error"
    else:
        code = "internal"

    detail: dict[str, Any] = {"exception": name}
    if module:
        detail["module"] = module
    return {"code": code, "message": text or name, "detail": detail}
