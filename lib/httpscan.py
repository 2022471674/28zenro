# -*- coding: utf-8 -*-
"""httpscan 网段 Web 主机发现纯逻辑模块（移植自 httpscan.py）。

以爬虫方式探测指定 CIDR 网段内存活的 Web 主机（相对端口扫描更不易被防火墙拦截），
返回 IP、HTTP 状态码、Web 容器版本（Server 头）与网页标题：

- expand_ips      展开 CIDR / 单个 IP 为待测 IP 列表（标准库 ipaddress）
- scan_ip         探测单个 IP，返回结构化结果 dict（失败返回 None）
- run             多线程扫描入口，返回结果列表，进度经 ``progress`` 回调

相对原脚本的改动：
- 原脚本是 Python 2（``Queue`` / ``except Exception,e``），移植到 Python 3；
- 网段展开改用标准库 ``ipaddress``，去掉 ``IPy`` 依赖；
- 去掉 ``print`` 与日志文件写入，进度经 ``progress`` 回调、结果经 ``found`` 回调
  吐给界面层，由界面层统一展示 / 保存；
- 增加可停止开关（``stop``），界面可随时中止扫描；
- 增加可选 https 探测（原脚本只发 http 请求）；
- 失败抛 :class:`HttpScanError`，由界面层统一展示。

本模块只做「CIDR 进、结果列表出」的网络处理，不导入任何 UI 模块。
"""

from __future__ import annotations

import ipaddress
import queue
import re
import threading
from collections.abc import Callable
from typing import Any

import requests
from requests.packages import urllib3

urllib3.disable_warnings()  # https 探测常见自签名证书，统一静默告警

#: 默认请求超时（秒）
DEFAULT_TIMEOUT = 5
#: 默认线程数
DEFAULT_THREADS = 10
#: 标题截断长度
TITLE_MAX = 60
#: 单次扫描允许展开的最大地址数（约一个 /16；更大的网段必须拆分，
#: 否则 `0.0.0.0/0` 这类输入会在展开阶段耗尽内存 / 长时间假死）
MAX_ADDRESSES = 65536

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/44.0.2403.125 Safari/537.36"
)
HEADERS = {"User-Agent": USER_AGENT, "Connection": "close"}

_PROGRESS_EVERY = 20  # 每探测多少个 IP 汇报一次进度（最后一个必报）

ProgressFn = Callable[[str], None]
FoundFn = Callable[[dict[str, Any]], None]

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


class HttpScanError(ValueError):
    """httpscan 处理失败时抛出的统一异常，由界面层统一捕获并展示。"""


# ---------------------------------------------------------------------------
# 一、网段展开
# ---------------------------------------------------------------------------
def expand_ips(target: str) -> list[str]:
    """把 CIDR（如 ``192.168.1.0/24``）或单个 IP 展开成待测 IP 列表。

    目标无法解析时抛 :class:`HttpScanError`。
    """
    text = str(target or "").strip()
    if not text:
        raise HttpScanError("请填写要扫描的目标，如 192.168.1.0/24 或单个 IP")
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        raise HttpScanError(f"无法解析目标：{text}（示例：192.168.1.0/24 或 192.168.1.5）")
    if network.num_addresses > MAX_ADDRESSES:
        raise HttpScanError(
            f"目标网段过大：{text}（含 {network.num_addresses} 个地址，"
            f"上限 {MAX_ADDRESSES}，约一个 /16）。请拆分成更小的网段分别扫描")
    hosts = [str(ip) for ip in network.hosts()]
    if not hosts:  # /31、/32 等边界情况
        hosts = [str(network.network_address)]
    return hosts


# ---------------------------------------------------------------------------
# 二、单 IP 探测
# ---------------------------------------------------------------------------
def scan_ip(
    ip: str,
    timeout: int = DEFAULT_TIMEOUT,
    https: bool = False,
) -> dict[str, Any] | None:
    """探测单个 IP 上的 Web 服务，返回结构化结果；无 Web 服务返回 None。

    ``https=True`` 时先试 ``https://`` 再试 ``http://``（证书校验关闭）。
    """
    schemes = ("https", "http") if https else ("http",)
    from lib import proxy_pool
    session = proxy_pool.make_session("httpscan")
    try:
        for scheme in schemes:
            try:
                raw = session.get(
                    f"{scheme}://{ip}",
                    headers=HEADERS,
                    timeout=timeout,
                    verify=False,
                    allow_redirects=True,
                )
            except requests.RequestException:
                continue
            return _build_result(ip, raw)
    finally:
        session.close()
    return None


def _build_result(ip: str, raw: requests.Response) -> dict[str, Any]:
    """从响应中整理结果 dict。"""
    match = _TITLE_RE.search(raw.text or "")
    title = ""
    if match:
        title = re.sub(r"\s+", " ", match.group(1)).strip()[:TITLE_MAX]
    return {
        "ip": ip,
        "status": raw.status_code,
        "server": raw.headers.get("Server", "")[:40],
        "title": title or "-",
        "url": raw.url,
    }


# ---------------------------------------------------------------------------
# 三、多线程扫描
# ---------------------------------------------------------------------------
def run(
    target: str,
    threads: int = DEFAULT_THREADS,
    timeout: int = DEFAULT_TIMEOUT,
    https: bool = False,
    progress: ProgressFn | None = None,
    found: FoundFn | None = None,
    stop: threading.Event | None = None,
) -> list[dict[str, Any]]:
    """多线程扫描网段，返回存活主机结果列表。

    - ``progress``：周期性进度文案（已探测 / 总数、已发现数）；
    - ``found``：每发现一台主机立即回调（供界面增量展示）；
    - ``stop``：置位后工作线程在取下一个 IP 前退出，用于中止扫描。
    """
    ips = expand_ips(target)
    total = len(ips)
    jobs: queue.Queue[str] = queue.Queue()
    for ip in ips:
        jobs.put(ip)

    lock = threading.Lock()
    results: list[dict[str, Any]] = []
    done_count = 0

    def worker() -> None:
        nonlocal done_count
        while not (stop is not None and stop.is_set()):
            try:
                ip = jobs.get_nowait()
            except queue.Empty:
                return
            item = scan_ip(ip, timeout=timeout, https=https)
            with lock:
                done_count += 1
                if item is not None:
                    results.append(item)
                if progress is not None and (
                    done_count % _PROGRESS_EVERY == 0 or done_count == total
                ):
                    progress(
                        f"已探测 {done_count}/{total}，发现 {len(results)} 台存活主机")
            if item is not None and found is not None:
                found(dict(item))

    worker_count = max(1, min(int(threads), total))
    workers = [
        threading.Thread(target=worker, daemon=True, name=f"httpscan-{i}")
        for i in range(worker_count)
    ]
    for t in workers:
        t.start()
    for t in workers:
        t.join()

    if stop is not None and stop.is_set():
        raise HttpScanError("扫描已中止")
    return results
