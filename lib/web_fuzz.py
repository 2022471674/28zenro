# -*- coding: utf-8 -*-
"""Web Fuzz（Web 信息收集）：给定一个 URL，尽可能多地扒出页面与主机的信息。

与「密码 Fuzz」（把密文丢给所有算法）不同，Web Fuzz 的「Fuzz」指：对着一个
URL 把所有能拿到的信息都抓一遍 —— 响应头、状态码、容器指纹、页面标题、meta、
技术栈、链接、表单、脚本、注释、邮箱 / 手机号、IP、子域名、安全响应头、
robots.txt / sitemap.xml、Cookie、跳转链，最后合并成一份结构化报告。

设计约定
--------
1. **代理池约定（Web 工具必须遵守）**：所有 HTTP 请求统一经
   :func:`_session` 拿 ``proxy_pool.make_session()`` 创建会话 —— 启用全局
   代理池时自动走轮换代理，未启用时 ``trust_env=False`` 直连。内置浏览器是
   唯一例外，它不经过这里。
   **后续新增的 Web 工具都必须沿用同一约定**，不要自己 ``requests.get`` 或
   新建不走代理池的会话，否则「配置一次、全局生效」会失效。
2. **只做「URL 进、结构化结果出」**，不导入任何 UI 模块；结果由
   :func:`run` 返回 dict，由页面层负责展示 / 合并输出到 txt。
3. 全程支持 ``stop`` 事件，任意一步失败不影响其余步骤，最终都给出汇总。

本模块只做纯逻辑，不导入任何 UI 模块。
"""

from __future__ import annotations

import re
import threading
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import requests
from requests.packages import urllib3

urllib3.disable_warnings()  # 目标站常见自签名证书，统一静默告警

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
DEFAULT_TIMEOUT = 8
#: 抓取正文 / 页面文本的最大读取字节数（够拿标题 / meta / 链接 / 注释）
READ_LIMIT = 1024 * 1024
#: 单项列表结果最多保留多少条，避免超长页面把报告撑爆
MAX_ITEMS = 2000

#: 子域名爆破默认速率限制：相邻两次 DNS 查询的最小间隔（秒）
DNS_DEFAULT_INTERVAL = 0.3

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
HEADERS = {"User-Agent": USER_AGENT, "Connection": "close"}

LogFn = Callable[[str], None]

#: 值得单独拎出来提示的安全相关响应头
SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "x-xss-protection": "X-XSS-Protection",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "feature-policy": "Feature-Policy",
    "access-control-allow-origin": "CORS-Allow-Origin",
    "set-cookie": "Set-Cookie",
}

#: 常见技术栈指纹：响应头关键词 -> 技术名
_TECH_PATTERNS: tuple[tuple[str, str], ...] = (
    ("x-powered-by", "X-Powered-By"),
    ("server", "Server"),
    ("x-aspnet-version", "ASP.NET"),
    ("x-aspnetmvc-version", "ASP.NET MVC"),
    ("x-generator", "Generator"),
    ("x-drupal-cache", "Drupal"),
    ("x-varnish", "Varnish"),
    ("cf-ray", "Cloudflare"),
    ("x-served-by", "Served-By"),
)

_TECH_BODY: tuple[tuple[str, str], ...] = (
    (r"wp-content", "WordPress"),
    (r"wp-includes", "WordPress"),
    (r"__VIEWSTATE", "ASP.NET WebForms"),
    (r"jquery", "jQuery"),
    (r"react(-dom)?", "React"),
    (r"vue\.js|@vue", "Vue.js"),
    (r"angular", "Angular"),
    (r"laravel", "Laravel"),
    (r"thinkphp", "ThinkPHP"),
    (r"springframework|org\.springframework", "Spring"),
    (r"struts", "Struts"),
    (r"django", "Django"),
    (r"flask", "Flask"),
    (r"phpMyAdmin", "phpMyAdmin"),
    (r"nacos", "Nacos"),
    (r"swagger|openapi", "Swagger/OpenAPI"),
    (r"bootstrap", "Bootstrap"),
)

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_PHONE_RE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_META_RE = re.compile(
    r"<meta[^>]+(?:name|property|http-equiv)=[\"']([^\"']+)[\"'][^>]*"
    r"content=[\"']([^\"']*)[\"']", re.I)
_META_RE_ALT = re.compile(
    r"<meta[^>]+content=[\"']([^\"']*)[\"'][^>]*"
    r"(?:name|property|http-equiv)=[\"']([^\"']+)[\"']", re.I)
_LINK_RE = re.compile(r"<a[^>]+href=[\"']([^\"']+)[\"']", re.I)
_SCRIPT_RE = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.I)
_FORM_BLOCK_RE = re.compile(r"<form[^>]*>.*?</form\s*>", re.I | re.S)
_FORM_TAG_RE = re.compile(r"<form[^>]*>", re.I)
_INPUT_RE = re.compile(r"<input[^>]+name=[\"']([^\"']+)[\"']", re.I)


class WebFuzzError(ValueError):
    """Web Fuzz 参数 / 连接失败时抛出的统一异常。"""


class WebFuzzConnectionError(WebFuzzError):
    """目标连不上（DNS / 拒绝连接 / 超时），与「没有抓到某项信息」区分开。"""


@dataclass
class WebFuzzResult:
    """一次 Web Fuzz 的汇总结果。"""

    target: str
    final_url: str = ""
    status: int = 0
    elapsed: float = 0.0
    stopped: bool = False
    #: 主页请求失败时的错误说明（连不上 / 超时等）；空串表示成功抓到主页
    error: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    security: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    title: str = ""
    meta: dict[str, str] = field(default_factory=dict)
    technologies: list[str] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)
    comments: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    phones: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    redirect_chain: list[str] = field(default_factory=list)
    robots: list[str] = field(default_factory=list)
    sitemap: list[str] = field(default_factory=list)
    sitemap_note: str = ""
    #: 历史收录查询结果（hostsearch）：[(子域名, IP), ...]
    hostsearch: list[dict[str, str]] = field(default_factory=list)
    hostsearch_note: str = ""
    #: 字典子域名爆破结果：[{"subdomain", "ips", "note"}, ...]
    dns_brute: list[dict[str, Any]] = field(default_factory=list)
    dns_brute_note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "final_url": self.final_url,
            "status": self.status,
            "elapsed": round(self.elapsed, 1),
            "stopped": self.stopped,
            "error": self.error,
            "headers": dict(self.headers),
            "security": dict(self.security),
            "cookies": dict(self.cookies),
            "title": self.title,
            "meta": dict(self.meta),
            "technologies": list(self.technologies),
            "links": list(self.links),
            "scripts": list(self.scripts),
            "forms": list(self.forms),
            "comments": list(self.comments),
            "emails": list(self.emails),
            "phones": list(self.phones),
            "ips": list(self.ips),
            "subdomains": list(self.subdomains),
            "redirect_chain": list(self.redirect_chain),
            "robots": list(self.robots),
            "sitemap": list(self.sitemap),
            "sitemap_note": self.sitemap_note,
            "hostsearch": list(self.hostsearch),
            "hostsearch_note": self.hostsearch_note,
            "dns_brute": list(self.dns_brute),
            "dns_brute_note": self.dns_brute_note,
        }


# ---------------------------------------------------------------------------
# 会话（代理池约定）
# ---------------------------------------------------------------------------
def _session() -> requests.Session:
    """创建走全局代理池的请求会话（Web 工具统一入口）。

    启用代理池时自动绑定轮换代理，未启用时 ``trust_env=False`` 直连目标。
    **后续新增的 Web 工具都必须复用本约定**，不要绕过 :mod:`lib.proxy_pool`。
    """
    from lib import proxy_pool

    session = proxy_pool.make_session("web_fuzz")
    session.headers.update(HEADERS)
    return session


def _describe_error(exc: Exception) -> str:
    """把 requests 异常压成一句人话（复用 :mod:`lib.http_common`）。"""
    from lib.http_common import describe_error

    return describe_error(exc)


def _normalize_url(raw: str) -> str:
    """补协议头、去首尾空白、校验 netloc。"""
    text = str(raw or "").strip().replace("：", ":")
    if not text:
        raise WebFuzzError("请填写目标 URL，如 https://example.com")
    if "://" not in text:
        text = "http://" + text
    parsed = urllib.parse.urlparse(text)
    if not parsed.hostname:
        raise WebFuzzError("目标格式不正确，示例：https://example.com 或 example.com")
    return text


def _last_dot_domain(netloc: str) -> str:
    """取主域名（netloc 最后两级，如 www.a.example.com -> example.com）。"""
    parts = netloc.split(".")
    if len(parts) > 2:
        return ".".join(parts[-2:])
    return netloc


def _absolute(base: str, ref: str) -> str:
    """把相对链接补全为绝对 URL。"""
    if not ref:
        return ""
    ref = ref.strip()
    if ref.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
        return ""
    return urllib.parse.urljoin(base, ref)


# ---------------------------------------------------------------------------
# 抓取与解析
# ---------------------------------------------------------------------------
def _fetch(session: requests.Session, url: str, timeout: float,
           stop: threading.Event | None) -> requests.Response:
    """请求一个地址，返回响应；失败抛 WebFuzzConnectionError。"""
    if stop is not None and stop.is_set():
        raise WebFuzzConnectionError("已手动停止")
    try:
        return session.get(url, timeout=timeout, verify=False,
                           allow_redirects=True, stream=True)
    except requests.RequestException as exc:
        raise WebFuzzConnectionError(_describe_error(exc)) from exc


def _read_body(response: requests.Response, stop: threading.Event | None) -> bytes:
    """读取响应正文（上限 READ_LIMIT），返回 bytes。"""
    body = b""
    try:
        for chunk in response.iter_content(64 * 1024):
            if stop is not None and stop.is_set():
                break
            body += chunk
            if len(body) >= READ_LIMIT:
                break
    finally:
        response.close()
    return body


def _decode(body: bytes) -> str:
    """把 bytes 尽力解码成文本（复用 :mod:`lib.http_common.decode_body`）。"""
    from lib.http_common import decode_body

    return decode_body(body)


def _extract_technologies(headers: dict[str, str], text: str) -> list[str]:
    """从响应头与正文里识别技术栈指纹，去重返回。"""
    found: list[str] = []
    seen: set[str] = set()
    lowered_headers = {k.lower(): v for k, v in headers.items()}
    for key, name in _TECH_PATTERNS:
        value = lowered_headers.get(key, "")
        if value and name not in seen:
            seen.add(name)
            found.append(f"{name}: {str(value)[:60]}")
    for pattern, name in _TECH_BODY:
        if name in seen:
            continue
        if re.search(pattern, text, re.I):
            seen.add(name)
            found.append(name)
    return found


def _parse_one_form(form_tag: str, region: str, base: str) -> dict[str, Any]:
    """从 form 开始标签 + 待搜索区域（整个 form 块）解析出一个表单描述。"""
    action_m = re.search(r"action=[\"']([^\"']*)[\"']", form_tag, re.I)
    method_m = re.search(r"method=[\"']([^\"']*)[\"']", form_tag, re.I)
    inputs = _INPUT_RE.findall(region)
    return {
        "action": _absolute(base, action_m.group(1)) if action_m else base,
        "method": (method_m.group(1) if method_m else "GET").upper(),
        "inputs": inputs[:50],
    }


def _parse_forms(text: str, base: str) -> list[dict[str, Any]]:
    """解析页面里的 form：action / method / input 名。

    在整个 ``<form>...</form>`` 区间内找 input（input 是表单子元素，
    不在 form 开始标签里）；对没写 ``</form>`` 的残缺 HTML，从 form 标签处
    取到下一个 ``<form`` 或文末做兜底。
    """
    forms: list[dict[str, Any]] = []
    covered: list[tuple[int, int]] = []
    for block in _FORM_BLOCK_RE.finditer(text):
        covered.append((block.start(), block.end()))
        forms.append(_parse_one_form(
            _FORM_TAG_RE.search(block.group(0)).group(0), block.group(0), base))
    # 兜底：未闭合的 form（块正则要求有 </form> 才命中）
    for tag in _FORM_TAG_RE.finditer(text):
        if any(start <= tag.start() < end for start, end in covered):
            continue
        nxt = _FORM_TAG_RE.search(text, tag.end())
        region = text[tag.start():nxt.start() if nxt else len(text)]
        forms.append(_parse_one_form(tag.group(0), region, base))
    return forms


def _collect_sitemap(session: requests.Session, base: str, timeout: float,
                     stop: threading.Event | None) -> tuple[list[str], str]:
    """拉取 sitemap.xml，返回 (URL 列表, 说明)。"""
    url = _absolute(base, "/sitemap.xml")
    try:
        response = _fetch(session, url, timeout, stop)
    except WebFuzzConnectionError:
        return [], ""
    if response.status_code >= 400:
        response.close()
        return [], ""
    body = _decode(_read_body(response, stop))
    urls = re.findall(r"<loc[^>]*>(.*?)</loc>", body, re.I)
    return urls[:MAX_ITEMS], ""


def _collect_robots(session: requests.Session, base: str, timeout: float,
                    stop: threading.Event | None) -> list[str]:
    """拉取 robots.txt，返回逐行内容。"""
    url = _absolute(base, "/robots.txt")
    try:
        response = _fetch(session, url, timeout, stop)
    except WebFuzzConnectionError:
        return []
    if response.status_code >= 400:
        response.close()
        return []
    text = _decode(_read_body(response, stop))
    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    return lines[:MAX_ITEMS]


# ---------------------------------------------------------------------------
# 历史收录查询（hackertarget hostsearch）
# ---------------------------------------------------------------------------
def _extract_registerable_domain(netloc: str) -> str:
    """从 netloc 取「可注册域名」：去掉端口，保留主域名（不强行剥子域）。

    目标输入可能是 ``sub.example.com`` 或 ``example.com``，历史收录查询需要
    一个「不带 http/https 的域名」。这里返回去掉协议与端口、去掉首尾空白后的
    netloc；若 netloc 是 IP 则原样返回（此时历史收录无意义，调用方会跳过）。
    """
    host = (netloc or "").strip()
    if not host:
        return ""
    # 去掉 IPv6 方括号与端口
    if host.startswith("["):
        host = host.split("]", 1)[0][1:]
    else:
        host = host.split(":", 1)[0]
    return host


def _query_hostsearch(domain: str, timeout: float,
                      stop: threading.Event | None) -> tuple[list[dict[str, str]], str]:
    """调用 hackertarget hostsearch 查询历史收录的子域名与对应 IP。

    返回 ``(结果列表, 说明)``。底层逻辑复用 :mod:`lib.hostsearch`（与独立的
    「域名解析历史」子工具共享同一实现）。
    """
    from lib import hostsearch

    try:
        result = hostsearch.query_hostsearch(domain, timeout=timeout, stop=stop)
    except hostsearch.HostsearchError as exc:
        return [], str(exc)
    return result.get("records", []), result.get("note", "")


# ---------------------------------------------------------------------------
# 字典子域名爆破（DNS A 查询：Resolve-DnsName + nslookup 校准）
# 底层逻辑统一复用 :mod:`lib.dns_tool`，此处仅做 Web Fuzz 结果适配。
# ---------------------------------------------------------------------------
def _collect_subdomain_brute(
        base_domain: str,
        dict_path: str | Path | None,
        interval: float,
        use_proxy: bool,
        timeout: float,
        log: LogFn | None,
        stop: threading.Event | None,
) -> tuple[list[dict[str, Any]], str]:
    """字典子域名爆破：逐个拼 ``词条.主域名`` 做 DNS A 查询（委托 dns_tool）。

    返回 ``(结果列表, 说明)``。速率限制通过 ``interval``（秒，0 表示不限）
    控制，查询支持 ``stop`` 中断。
    """
    from lib import dns_tool

    try:
        results, note = dns_tool.brute_subdomains(
            base_domain,
            dict_path=dict_path,
            interval=interval,
            use_proxy=use_proxy,
            timeout=timeout,
            log=log,
            stop=stop,
        )
    except dns_tool.DnsToolError as exc:
        return [], str(exc)
    return results, note


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def run(
    target: str,
    timeout: float = DEFAULT_TIMEOUT,
    with_robots: bool = False,
    with_sitemap: bool = False,
    with_hostsearch: bool = False,
    with_subdomain_brute: bool = False,
    subdomain_dict: str | Path | None = None,
    subdomain_interval: float = DNS_DEFAULT_INTERVAL,
    subdomain_use_proxy: bool = False,
    log: LogFn | None = None,
    stop: threading.Event | None = None,
) -> dict[str, Any]:
    """对 ``target`` 做一次 Web Fuzz，返回结构化汇总 dict。

    参数
    ----
    target              目标 URL（可省略协议头）
    timeout             单次请求超时（秒）
    with_robots         是否顺带抓 robots.txt
    with_sitemap        是否顺带抓 sitemap.xml
    with_hostsearch     是否查询历史收录（hackertarget hostsearch）
    with_subdomain_brute 是否用字典爆破子域名（DNS A 查询）
    subdomain_dict      子域名字典路径，默认 ``dict/Contents/subdomain.dict``
    subdomain_interval  子域名爆破相邻两次查询最小间隔（秒），0 表示不限
    subdomain_use_proxy 子域名爆破是否走全局代理池 SOCKS5 代理做远程 DNS
    log                 逐行日志回调
    stop                置位后尽快停止，已完成的步骤仍会汇总
    """
    import time

    emit = log or (lambda _msg: None)
    started = time.time()
    base = _normalize_url(target)
    result = WebFuzzResult(target=base)

    emit(f"[目标] {base}")
    session = _session()
    try:
        # -- 1. 主页面 ------------------------------------------------------
        emit("[请求] 正在抓取主页…")
        response = _fetch(session, base, timeout, stop)
        result.status = response.status_code
        result.final_url = response.url
        result.headers = dict(response.headers)
        result.cookies = dict(response.cookies)
        result.redirect_chain = [r.url for r in response.history if r.url]
        for name in SECURITY_HEADERS:
            value = response.headers.get(name)
            if value:
                result.security[name] = value
        emit(f"[响应] {result.status} {result.final_url}")

        body = _read_body(response, stop)
        text = _decode(body)
        emit(f"[正文] {len(body)} 字节")

        title_m = _TITLE_RE.search(text)
        if title_m:
            result.title = re.sub(r"\s+", " ", title_m.group(1)).strip()[:200]

        for name, value in _META_RE.findall(text):
            result.meta[name] = value
        for value, name in _META_RE_ALT.findall(text):
            result.meta.setdefault(name, value)

        result.technologies = _extract_technologies(result.headers, text)

        links = [_absolute(base, m) for m in _LINK_RE.findall(text)]
        result.links = [u for u in dict.fromkeys(links) if u][:MAX_ITEMS]
        scripts = [_absolute(base, m) for m in _SCRIPT_RE.findall(text)]
        result.scripts = [u for u in dict.fromkeys(scripts) if u][:MAX_ITEMS]
        result.forms = _parse_forms(text, base)
        comments = [re.sub(r"\s+", " ", c).strip() for c in _COMMENT_RE.findall(text)]
        result.comments = [c for c in dict.fromkeys(comments) if c][:MAX_ITEMS]

        result.emails = list(dict.fromkeys(_EMAIL_RE.findall(text)))[:MAX_ITEMS]
        result.phones = list(dict.fromkeys(_PHONE_RE.findall(text)))[:MAX_ITEMS]

        main_domain = _last_dot_domain(urllib.parse.urlparse(base).hostname or "")
        subs: list[str] = []
        for url in result.links + result.scripts:
            netloc = urllib.parse.urlparse(url).netloc
            if netloc and main_domain and main_domain in netloc and netloc not in subs:
                subs.append(netloc)
        result.subdomains = subs

        ips = [ip for ip in dict.fromkeys(_IP_RE.findall(text))
               if ip.split(".")[0] != "0" and not ip.startswith("255")]
        result.ips = ips[:MAX_ITEMS]

        emit(f"[解析] 标题 {len(result.title)} 字、meta {len(result.meta)} 项、"
             f"链接 {len(result.links)}、脚本 {len(result.scripts)}、"
             f"表单 {len(result.forms)}、邮箱 {len(result.emails)}、"
             f"子域 {len(result.subdomains)}")

        # -- 2. robots.txt -------------------------------------------------
        if with_robots and stop is not None and stop.is_set():
            with_robots = False
        if with_robots:
            emit("[请求] 抓取 robots.txt…")
            result.robots = _collect_robots(session, base, timeout, stop)
            emit(f"[robots] {len(result.robots)} 行")

        # -- 3. sitemap.xml -------------------------------------------------
        if with_sitemap and stop is not None and stop.is_set():
            with_sitemap = False
        if with_sitemap:
            emit("[请求] 抓取 sitemap.xml…")
            result.sitemap, result.sitemap_note = _collect_sitemap(
                session, base, timeout, stop)
            emit(f"[sitemap] {len(result.sitemap)} 条 URL")

        # -- 4. 历史收录查询（hostsearch） ----------------------------------
        if with_hostsearch and stop is not None and stop.is_set():
            with_hostsearch = False
        if with_hostsearch:
            domain = _extract_registerable_domain(
                urllib.parse.urlparse(base).netloc)
            if domain and not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", domain):
                emit(f"[收录] 查询历史收录：{domain}")
                result.hostsearch, result.hostsearch_note = _query_hostsearch(
                    domain, timeout, stop)
                emit(f"[收录] {len(result.hostsearch)} 条记录"
                     + (f"（{result.hostsearch_note}）"
                        if result.hostsearch_note else ""))
            else:
                result.hostsearch_note = "目标是 IP，跳过历史收录查询"

        # -- 5. 字典子域名爆破（DNS A 查询） ---------------------------------
        if with_subdomain_brute and stop is not None and stop.is_set():
            with_subdomain_brute = False
        if with_subdomain_brute:
            domain = _extract_registerable_domain(
                urllib.parse.urlparse(base).netloc)
            result.dns_brute, result.dns_brute_note = _collect_subdomain_brute(
                domain,
                dict_path=subdomain_dict,
                interval=subdomain_interval,
                use_proxy=subdomain_use_proxy,
                timeout=timeout,
                log=emit,
                stop=stop,
            )
            emit(f"[子域名] 爆破完成，命中 {len(result.dns_brute)} 条"
                 + (f"（{result.dns_brute_note}）"
                    if result.dns_brute_note else ""))
    except WebFuzzConnectionError as exc:
        # 主页连不上时不再向上抛异常，而是返回带 error 说明的汇总，
        # 与「任意一步失败不影响其余步骤，最终都给出汇总」的约定一致。
        result.error = str(exc)
        emit(f"[错误] {exc}")
    finally:
        session.close()

    result.elapsed = time.time() - started
    result.stopped = bool(stop is not None and stop.is_set())
    emit(f"[完成] 耗时 {result.elapsed:.1f}s")
    return result.to_dict()


def to_text(result: dict[str, Any]) -> str:
    """把 :func:`run` 的结果 dict 渲染成一份合并的纯文本报告（供落盘 txt）。

    页面层可直接把返回值写进 ``.txt``；这里集中排版，保证「合并输出」格式一致。
    """
    from datetime import datetime

    lines: list[str] = []
    add = lines.append

    add("# Web Fuzz 报告")
    add(f"# 目标: {result.get('target', '')}")
    add(f"# 最终 URL: {result.get('final_url', '')}")
    add(f"# 状态码: {result.get('status', 0)}")
    add(f"# 时间: {datetime.now():%Y-%m-%d %H:%M:%S}")
    add(f"# 耗时: {result.get('elapsed', 0)}s"
        + ("（已手动停止）" if result.get("stopped") else ""))

    def section(title: str) -> None:
        add("")
        add(f"=== {title} ===")

    def kv_items(mapping: dict | None) -> None:
        items = mapping or {}
        if not items:
            add("  （无）")
            return
        for key, value in items.items():
            add(f"  {key}: {value}")

    def list_items(items: list | None) -> None:
        items = items or []
        if not items:
            add("  （无）")
            return
        for item in items:
            add(f"  {item}")

    if result.get("title"):
        section("页面标题")
        add(f"  {result['title']}")

    section("响应头")
    kv_items(result.get("headers"))

    if result.get("security"):
        section("安全响应头")
        kv_items(result.get("security"))

    if result.get("cookies"):
        section("Cookie")
        kv_items(result.get("cookies"))

    if result.get("redirect_chain"):
        section("跳转链")
        list_items(result.get("redirect_chain"))

    if result.get("technologies"):
        section("技术栈指纹")
        list_items(result.get("technologies"))

    if result.get("meta"):
        section("Meta 标签")
        kv_items(result.get("meta"))

    section("链接（同页 <a>）")
    list_items(result.get("links"))

    section("脚本（<script src>）")
    list_items(result.get("scripts"))

    section("表单")
    forms = result.get("forms") or []
    if not forms:
        add("  （无）")
    for form in forms:
        add(f"  [{form.get('method', 'GET')}] {form.get('action', '')}")
        for name in form.get("inputs") or []:
            add(f"      - {name}")

    section("HTML 注释")
    list_items(result.get("comments"))

    section("邮箱")
    list_items(result.get("emails"))

    section("手机号")
    list_items(result.get("phones"))

    section("IP 地址")
    list_items(result.get("ips"))

    section("子域名")
    list_items(result.get("subdomains"))

    section("robots.txt")
    list_items(result.get("robots"))

    section("sitemap.xml")
    if result.get("sitemap_note"):
        add(f"  {result['sitemap_note']}")
    list_items(result.get("sitemap"))

    section("历史收录查询（hostsearch）")
    if result.get("hostsearch_note"):
        add(f"  {result['hostsearch_note']}")
    hostsearch = result.get("hostsearch") or []
    if not hostsearch:
        add("  （无）")
    for item in hostsearch:
        add(f"  {item.get('subdomain', '')}  ->  {item.get('ip', '')}")

    section("字典子域名爆破（DNS A 查询）")
    if result.get("dns_brute_note"):
        add(f"  {result['dns_brute_note']}")
    dns_brute = result.get("dns_brute") or []
    if not dns_brute:
        add("  （无）")
    for item in dns_brute:
        note = f"  [注意] {item['note']}" if item.get("note") else ""
        add(f"  {item.get('subdomain', '')}  ->  {', '.join(item.get('ips') or [])}"
            + note)

    add("")
    add("# 生成于 28zenro Web Fuzz")
    return "\n".join(lines)


__all__ = [
    "DEFAULT_TIMEOUT",
    "DNS_DEFAULT_INTERVAL",
    "WebFuzzError",
    "WebFuzzConnectionError",
    "WebFuzzResult",
    "run",
    "to_text",
]
