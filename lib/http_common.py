# -*- coding: utf-8 -*-
"""Web 工具共享的 HTTP 辅助函数（异常描述 / 响应体解码）。

``web_fuzz`` 与 ``http_requester`` 各自实现的 ``describe_error`` / ``_decode``
语义完全一致，收敛到这里，避免重复维护。后续新增 Web 工具也应复用本模块，
不要各自再写一份「异常 → 人话」映射或「响应体 → 文本」解码。

注意：URL 归一化（``normalize_url`` / ``normalize_target`` / ``normalize_domain``）
各模块语义有差异（补协议 / 剥协议 / 去尾斜杠 / 去端口…），**不在此收敛**，
由各模块保留自己的实现。
"""

from __future__ import annotations

import re
from typing import Any

import requests

#: ``charset=xxx`` 提取（响应体解码用）
_CHARSET_RE = re.compile(r"charset=([\w-]+)", re.IGNORECASE)


def describe_error(exc: Exception) -> str:
    """把 requests 异常压成一句人话。"""
    text = str(exc)
    if isinstance(exc, requests.exceptions.ConnectTimeout):
        return "连接超时"
    if isinstance(exc, requests.exceptions.ReadTimeout):
        return "读取超时"
    if isinstance(exc, requests.exceptions.SSLError):
        return "TLS 握手失败"
    if isinstance(exc, requests.exceptions.TooManyRedirects):
        return "重定向次数过多"
    if ("NewConnectionError" in text or "Connection refused" in text
            or "积极拒绝" in text or "Connection aborted" in text
            or "远程主机强迫关闭" in text or "10061" in text):
        return "目标拒绝连接（端口未开放或被防火墙拦截）"
    if ("Name or service not known" in text or "getaddrinfo failed" in text
            or "NameResolutionError" in text or "Failed to resolve" in text):
        return "域名解析失败"
    if "InvalidURL" in type(exc).__name__ or "Invalid URL" in text:
        return "URL 非法（检查是否含空格 / 不可见字符）"
    return f"{type(exc).__name__}: {text}"[:200]


def decode_body(raw: bytes, encoding: str | None = None, mime: str = "") -> str:
    """按响应头编码解码正文，失败退回 utf-8 / gb18030。

    优先级：``mime`` 里的 ``charset=`` → 显式 ``encoding`` → utf-8 → gb18030；
    全部失败时按 ``utf-8`` 以 ``replace`` 兜底（永不抛 UnicodeDecodeError）。
    """
    candidates: list[str] = []
    match = _CHARSET_RE.search(mime or "")
    if match:
        candidates.append(match.group(1))
    if encoding:
        candidates.append(encoding)
    candidates += ["utf-8", "gb18030"]
    seen: set[str] = set()
    for name in candidates:
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        try:
            return raw.decode(name, "strict")
        except (LookupError, UnicodeDecodeError):
            continue
    return raw.decode("utf-8", "replace")


__all__ = ["describe_error", "decode_body"]
