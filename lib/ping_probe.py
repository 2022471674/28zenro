# -*- coding: utf-8 -*-
"""多地 Ping 纯逻辑模块（apihz.cn 免费 API 封装）。

通过「接口盒子（apihz.cn）」的免费多地 Ping 接口，在全球 / 国内多个节点对目标
主机发起 ICMP Ping 检测，一次请求同步返回全部节点的延迟与解析 IP：
- run_ping    提交检测并解析节点结果，返回 :class:`PingReport`

接口文档示例（公共 ID / KEY，共享每分钟频次，接口本身免费）：
``https://cn.apihz.cn/api/wangzhan/pingplus.php?id=10022374&key=qwertyuiopasdfghjkzxcvbn&dy=0&host=<域名>``

本模块同时预留 ``base_url`` / ``api_id`` / ``api_key`` / ``dy`` / 自定义 Header
这些可配置项，便于替换为其它兼容服务或经网关中转。

本模块只做「主机进、结果列表出」的网络处理，不导入任何 UI 模块。
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urlencode

from .llm_codec import parse_headers  # noqa: F401  供界面层复用

#: 默认服务地址（apihz.cn 免费多地 Ping 接口，公共示例 ID / KEY）
DEFAULT_BASE_URL = "https://cn.apihz.cn/api/wangzhan/pingplus.php"
#: 默认用户 ID（接口盒子公共示例 ID）
DEFAULT_API_ID = "10022374"
#: 默认通讯密钥（接口盒子公共示例 KEY）
DEFAULT_API_KEY = "qwertyuiopasdfghjkzxcvbn"
#: 默认附加参数 dy
DEFAULT_DY = "0"
#: 默认请求超时（秒）
DEFAULT_TIMEOUT = 30

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

ProgressFn = Callable[[str], None]


class PingProbeError(ValueError):
    """多地 Ping 处理失败时抛出的统一异常，由界面层统一捕获并展示。"""


@dataclass
class PingReport:
    """一次多地 Ping 检测的汇总结果。"""

    host: str
    nodes: list[dict] = field(default_factory=list)
    #: 检测失败原因（成功时为空字符串）
    error: str = ""


def _normalize_host(host: str) -> str:
    """去掉协议头 / 路径 / 端口，只保留主机名或 IP。"""
    text = str(host or "").strip()
    lowered = text.lower()
    for scheme in ("https://", "http://"):
        if lowered.startswith(scheme):
            text = text[len(scheme):]
    text = text.split("/", 1)[0].split("?", 1)[0].strip()
    # 去掉纯数字端口（IPv6 含多个冒号，不处理）
    if text.count(":") == 1:
        head, tail = text.rsplit(":", 1)
        if tail.isdigit():
            text = head
    return text.strip()


def build_headers(extra: dict[str, str] | None = None) -> dict[str, str]:
    """组合请求头：默认带 UA，``extra``（用户自定义 Header）最后合并、优先级最高。"""
    headers = {"User-Agent": USER_AGENT}
    if extra:
        headers.update(extra)
    return headers


def _safe_url(url: str) -> str:
    """去掉 query（其中含 key 等敏感参数），仅用于拼错误信息。"""
    return str(url or "").split("?", 1)[0]


def _request_json(url: str, timeout: float, headers: dict[str, str]) -> dict:
    """发一次 GET 请求并解析 JSON；失败统一抛 :class:`PingProbeError`。"""
    request = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        raise PingProbeError(
            f"服务返回 HTTP {exc.code}（{_safe_url(url)}），请确认 API 配置无误。"
        ) from exc
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, TimeoutError):
            raise PingProbeError(f"请求超时（{timeout} 秒）。") from exc
        raise PingProbeError(
            f"无法连接服务（{_safe_url(url)}），请确认 API 地址可达。") from exc
    except TimeoutError as exc:
        raise PingProbeError(f"请求超时（{timeout} 秒）。") from exc
    except (ConnectionError, OSError) as exc:
        # 服务端偶发断连 / 网络抖动统一兜底
        raise PingProbeError(
            f"网络连接中断（{_safe_url(url)}）：{exc}") from exc

    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        raise PingProbeError("服务返回内容不是合法的 JSON。") from exc


def _parse_node(item) -> dict:
    """把 apihz 返回的单节点数据解析成一行结构化数据。"""
    if not isinstance(item, dict):
        return {}
    region = str(item.get("jdxlmsg") or "").strip()
    parts = region.split("-")
    country = parts[0] if parts else ""
    city = parts[1] if len(parts) > 1 else ""
    line = "-".join(parts[2:]) if len(parts) > 2 else ""

    code = item.get("code")
    raw_time = item.get("totime")
    try:
        delay = float(raw_time) if raw_time not in (None, "") else None
    except (TypeError, ValueError):
        delay = None

    return {
        "region": region,
        "country": country,
        "city": city,
        "line": line,
        "ip": str(item.get("toip") or ""),
        "delay": delay,
        "status": "正常" if code == 200 else f"失败({code})",
    }


def run_ping(
    host: str,
    base_url: str = DEFAULT_BASE_URL,
    api_id: str = DEFAULT_API_ID,
    api_key: str = DEFAULT_API_KEY,
    dy: str = DEFAULT_DY,
    extra_headers: dict[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    progress: ProgressFn | None = None,
    stop=None,
) -> PingReport:
    """执行多地 Ping 检测，返回 :class:`PingReport`。

    ``stop`` 为 ``threading.Event``，置位后在发请求前提前结束。
    失败抛 :class:`PingProbeError`。
    """
    target = _normalize_host(host)
    if not target:
        raise PingProbeError("请填写要检测的主机（域名或 IP）。")
    if stop is not None and stop.is_set():
        return PingReport(host=target)

    base = str(base_url or DEFAULT_BASE_URL).strip()
    params = {
        "id": str(api_id or DEFAULT_API_ID),
        "key": str(api_key or DEFAULT_API_KEY),
        "dy": str(dy or DEFAULT_DY),
        "host": target,
    }
    sep = "&" if "?" in base else "?"
    url = f"{base}{sep}{urlencode(params)}"

    if progress:
        progress(f"正在请求多地 Ping 节点（{target}）…")
    body = _request_json(url, timeout, build_headers(extra_headers))

    if body.get("code") != 200:
        raise PingProbeError(
            str(body.get("msg") or f"接口返回错误 code={body.get('code')}"))
    datas = body.get("datas") or []
    if not datas:
        raise PingProbeError("接口未返回任何节点数据。")

    report = PingReport(host=target)
    for item in datas:
        node = _parse_node(item)
        if node:
            report.nodes.append(node)
    if progress:
        progress(f"检测完成：共 {len(report.nodes)} 个节点返回结果。")
    return report


def parse_hosts_file(text: str) -> list[str]:
    """把批量文件内容解析成主机列表：一行一个，跳过空行与 ``#`` 注释。

    每行去掉首尾空白；以 ``#`` 开头的行视为注释忽略。返回去重后的主机列表
    （保持原顺序，空列表时抛 :class:`PingProbeError`）。
    """
    hosts: list[str] = []
    seen: set[str] = set()
    for line in str(text or "").splitlines():
        host = line.strip()
        if not host or host.startswith("#"):
            continue
        # 去掉行内注释（# 之后的内容）
        if "#" in host:
            host = host.split("#", 1)[0].strip()
        if not host:
            continue
        normalized = _normalize_host(host)
        if normalized and normalized not in seen:
            seen.add(normalized)
            hosts.append(normalized)
    if not hosts:
        raise PingProbeError("批量文件中没有有效的主机（每行一个，空行 / # 注释会被忽略）。")
    return hosts


def run_ping_batch(
    hosts,
    base_url: str = DEFAULT_BASE_URL,
    api_id: str = DEFAULT_API_ID,
    api_key: str = DEFAULT_API_KEY,
    dy: str = DEFAULT_DY,
    extra_headers: dict[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    progress: ProgressFn | None = None,
    stop=None,
) -> list[PingReport]:
    """批量多地 Ping：顺序检测多个主机，返回 :class:`PingReport` 列表。

    ``hosts`` 为主机列表（字符串序列）；逐个顺序调用 :func:`run_ping`，单个
    主机失败不中断整体，而是记录到该主机的 ``report.error``（``nodes`` 为空）。
    ``stop`` 置位后不再检测后续主机。
    """
    reports: list[PingReport] = []
    total = len(hosts)
    for index, host in enumerate(hosts, start=1):
        if stop is not None and stop.is_set():
            break
        if progress:
            progress(f"[{index}/{total}] 正在检测 {host} …")
        try:
            report = run_ping(
                host,
                base_url=base_url, api_id=api_id, api_key=api_key, dy=dy,
                extra_headers=extra_headers, timeout=timeout,
                progress=progress, stop=stop,
            )
        except PingProbeError as exc:
            report = PingReport(host=_normalize_host(host), error=str(exc))
        reports.append(report)
    return reports
