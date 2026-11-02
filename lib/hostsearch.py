# -*- coding: utf-8 -*-
"""域名解析历史（hostsearch）纯逻辑模块。

通过 ``hackertarget`` 的 hostsearch 接口查询一个域名**历史上被收录过**的
子域名与对应 IP：``GET https://api.hackertarget.com/hostsearch/?q=<域名>``，
返回纯文本，每行 ``子域名,IP``。

与 :mod:`lib.dns_tool`（主动 DNS A / AAAA / CNAME 解析）不同，本模块是
**被动**信息收集：查询第三方平台的历史收录记录，能发现主动 DNS 爆破难以
命中的历史子域名。

代理约定（与其它 Web 工具一致）：请求统一经 :mod:`lib.proxy_pool` 的
``make_session()`` 创建 —— 启用全局代理池时自动走轮换代理，未启用时
``trust_env=False`` 直连。

本模块只做「域名进、结构化结果出」的纯逻辑，不导入任何 UI 模块。
"""

from __future__ import annotations

import threading
import urllib.parse
from typing import Any, Callable

import requests
from requests.packages import urllib3

urllib3.disable_warnings()

#: hostsearch 历史收录查询 API
HOSTSEARCH_URL = "https://api.hackertarget.com/hostsearch/?q={domain}"

#: 单次请求默认超时（秒）
DEFAULT_TIMEOUT = 8

#: 结果上限
MAX_ITEMS = 2000

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

LogFn = Callable[[str], None]


class HostsearchError(ValueError):
    """历史收录查询参数 / 连接失败时抛出的统一异常。"""


def normalize_domain(raw: str) -> str:
    """把 ``https://sub.example.com/xx`` 整理成「不带 http/https 的域名」。

    去掉协议头、路径、查询串与端口；IP 原样返回（IPv6 去方括号）。
    无法解析时抛 :class:`HostsearchError`。
    """
    text = str(raw or "").strip().replace("：", ":")
    if not text:
        raise HostsearchError("请填写要查询的域名，如 example.com")
    lowered = text.lower()
    for scheme in ("https://", "http://"):
        if lowered.startswith(scheme):
            text = text[len(scheme):]
    text = text.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].strip()
    # 去掉端口（仅当单冒号且尾部是纯数字，避免误伤 IPv6）
    if text.count(":") == 1:
        head, tail = text.rsplit(":", 1)
        if tail.isdigit():
            text = head
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    text = text.strip().strip(".")
    if not text:
        raise HostsearchError("域名格式不正确，示例：example.com")
    return text


def _session() -> requests.Session:
    """创建走全局代理池的请求会话（Web 工具统一入口）。"""
    from lib import proxy_pool

    session = proxy_pool.make_session("hostsearch")
    session.headers.update({"User-Agent": USER_AGENT, "Connection": "close"})
    return session


def query_hostsearch(
    domain: str,
    timeout: float = DEFAULT_TIMEOUT,
    log: LogFn | None = None,
    stop: threading.Event | None = None,
) -> dict[str, Any]:
    """查询一个域名的历史收录记录，返回结构化结果。

    返回 ``{"domain", "records": [{"subdomain", "ip"}, ...], "note"}``。
    ``records`` 为按行去重后的子域名 / IP 列表；无记录或查询失败时
    ``records`` 为空，``note`` 给出说明。
    """
    emit = log or (lambda _m: None)
    target = normalize_domain(domain)
    emit(f"[收录] 查询历史收录：{target}")

    url = HOSTSEARCH_URL.format(domain=urllib.parse.quote(target, safe=""))
    if stop is not None and stop.is_set():
        return {"domain": target, "records": [], "note": "已手动停止"}

    try:
        session = _session()
    except Exception as exc:  # noqa: BLE001  会话创建失败给出说明
        return {"domain": target, "records": [], "note": f"无法创建请求会话：{exc}"}

    try:
        response = session.get(url, timeout=timeout, verify=False,
                               allow_redirects=True, stream=True)
        if response.status_code >= 400:
            return {"domain": target, "records": [],
                    "note": f"查询失败（HTTP {response.status_code}）"}
        text = response.text
    except requests.RequestException as exc:
        return {"domain": target, "records": [], "note": f"查询失败：{exc}"}
    finally:
        session.close()

    if not text.strip():
        return {"domain": target, "records": [], "note": "无历史收录记录"}

    lowered = text.strip().lower()
    if any(hint in lowered for hint in ("api count exceeded", "error invalid",
                                        "no records")):
        return {"domain": target, "records": [],
                "note": f"历史收录查询返回：{text.strip()[:120]}"}

    records: list[dict[str, str]] = []
    seen: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split(",")]
        if not parts or not parts[0]:
            continue
        subdomain = parts[0]
        ip = parts[1] if len(parts) > 1 else ""
        key = f"{subdomain}\0{ip}"
        if key in seen:
            continue
        seen.add(key)
        records.append({"subdomain": subdomain, "ip": ip})
        if len(records) >= MAX_ITEMS:
            break

    emit(f"[收录] {len(records)} 条记录")
    return {"domain": target, "records": records, "note": ""}


__all__ = [
    "HOSTSEARCH_URL",
    "DEFAULT_TIMEOUT",
    "HostsearchError",
    "normalize_domain",
    "query_hostsearch",
]
