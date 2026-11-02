# -*- coding: utf-8 -*-
"""JSFinder 网页 JS 链接收集纯逻辑模块（移植自 JSFinder.py）。

来源：整合并使用开源作品 JSFinder（https://github.com/Threezh1/JSFinder），
在此致谢原作者。

从指定页面及其 ``<script>`` 中提取 URL 与子域名：
- extract_URL      LinkFinder 正则，从 JS / HTML 文本提取链接
- process_url      相对链接补全为绝对 URL
- find_subdomain   从 URL 列表提取主域名下的子域名
- find_by_url      抓取页面 + 内嵌 / 外链 JS，提取同主域 URL
- find_by_url_deep 深度模式：跟进页面上的 ``<a>`` 链接递归收集
- run              组合入口，返回 ``(URL 列表, 子域名列表)``

相对原脚本的改动：
- 去掉 ``print`` 与 ``argparse``，进度经 ``progress`` 回调吐给界面层；
- 原脚本超时固定 3 秒，这里可配置（默认 5 秒）；
- 深度模式限制最大跟进链接数（默认 50），避免页面链接过多时无限爬取；
- 失败抛 :class:`JSFinderError`，由界面层统一展示。

本模块只做「URL 进、列表出」的网络与文本处理，不导入任何 UI 模块。
"""

from __future__ import annotations

import re
from collections.abc import Callable
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from requests.packages import urllib3

urllib3.disable_warnings()  # 目标站常见自签名证书，统一静默告警

#: 默认请求超时（秒）
DEFAULT_TIMEOUT = 5
#: 深度模式默认最大跟进链接数（0 表示不限）
DEFAULT_MAX_LINKS = 50

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

#: 直接丢弃的链接前缀
BLACK_URL = ("javascript:",)

ProgressFn = Callable[[str], None]


class JSFinderError(ValueError):
    """JSFinder 处理失败时抛出的统一异常，由界面层统一捕获并展示。"""


# ---------------------------------------------------------------------------
# 一、链接提取与补全
# ---------------------------------------------------------------------------
# 正则来自 https://github.com/GerbenJavado/LinkFinder（与原脚本一致）
_URL_PATTERN = re.compile(
    r"""
      (?:"|')                               # Start newline delimiter
      (
        ((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
        [^"'/]{1,}\.                        # Match a domainname (any character + dot)
        [a-zA-Z]{2,}[^"']{0,})              # The domainextension and/or path
        |
        ((?:/|\.\./|\./)                    # Start with /,../,./
        [^"'><,;| *()(%%$^/\\\[\]]          # Next character can't be...
        [^"'><,;|()]{1,})                   # Rest of the characters can't be
        |
        ([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
        [a-zA-Z0-9_\-/]{1,}                 # Resource name
        \.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
        (?:[\?|/][^"|']{0,}|))              # ? mark with parameters
        |
        ([a-zA-Z0-9_\-]{1,}                 # filename
        \.(?:php|asp|aspx|jsp|json|
             action|html|js|txt|xml)             # . + extension
        (?:\?[^"|']{0,}|))                  # ? mark with parameters
      )
      (?:"|')                               # End newline delimiter
    """,
    re.VERBOSE,
)


# 接口（API endpoint）正则：专门匹配 JS 里的接口路径，区别于上面的 URL 正则。
# 覆盖常见的接口写法：/api/xxx、/xxx/yyy、/xxx.do、/xxx.php、带 query 的路径等。
_API_PATTERN = re.compile(
    r"""
    (?:"|')                                   # 起始引号
    (
        (?:https?://[^"' ]{1,})?              # 可选完整域名前缀
        /[a-zA-Z0-9_\-\.]{1,}                 # 以 / 开头的路径首段
        (?:/[a-zA-Z0-9_\-\.%]{1,}){0,}        # 后续路径段
        (?:\?[^"' ]{0,})?                     # 可选 query
    )
    (?:"|')                                   # 结束引号
    """,
    re.VERBOSE,
)

#: 明显不是接口的路径片段（静态资源 / 占位符）
_API_EXCLUDE = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                ".ico", ".woff", ".woff2", ".ttf", ".map", ".html", ".htm")


def extract_url(js_text: str) -> list[str]:
    """从 JS / HTML 文本中提取链接（保留出现顺序，去重）。"""
    result: list[str] = []
    for match in _URL_PATTERN.finditer(str(js_text)):
        item = match.group().strip('"').strip("'")
        if item not in result:
            result.append(item)
    return result


def extract_api(js_text: str) -> list[str]:
    """从 JS 文本中提取 API 接口路径（保留出现顺序，去重）。

    相对 LinkFinder 的 URL 正则，本函数更聚焦「接口端点」：以 ``/`` 开头的
    路径、可带 query，过滤静态资源与占位符，适合「覆盖 JS 文件查询」模式。
    """
    result: list[str] = []
    for match in _API_PATTERN.finditer(str(js_text)):
        item = match.group(1).strip()
        if not item:
            continue
        # 过滤明显是静态资源 / 纯路径片段过短的
        lower = item.lower()
        if any(lower.endswith(ext) for ext in _API_EXCLUDE):
            continue
        if len(item) < 3:
            continue
        if item not in result:
            result.append(item)
    return result


def process_url(base_url: str, re_url: str) -> str:
    """把相对链接补全为绝对 URL（补全规则与原脚本一致）。"""
    if re_url[0:2] == "//":
        return urlparse(base_url).scheme + ":" + re_url
    if re_url[0:4] == "http":
        return re_url
    if re_url.startswith(BLACK_URL):
        return base_url
    parsed = urlparse(base_url)
    if re_url[0:1] == "/":
        return parsed.scheme + "://" + parsed.netloc + re_url
    if re_url[0:1] == ".":
        if re_url[0:2] == "..":
            return parsed.scheme + "://" + parsed.netloc + re_url[2:]
        return parsed.scheme + "://" + parsed.netloc + re_url[1:]
    return parsed.scheme + "://" + parsed.netloc + "/" + re_url


def _last_dot_domain(netloc: str) -> str:
    """取主域名（netloc 最后两级，如 www.a.example.com -> example.com）。"""
    positions = [m.start() for m in re.finditer(r"\.", netloc)]
    if len(positions) > 1:
        return netloc[positions[-2] + 1:]
    return netloc


def find_subdomain(urls: list[str], main_url: str) -> list[str]:
    """从 URL 列表中提取主域名下的全部子域名（去重，保持出现顺序）。"""
    main_domain = _last_dot_domain(urlparse(main_url).netloc)
    subdomains: list[str] = []
    for url in urls:
        subdomain = urlparse(url).netloc
        if not subdomain.strip():
            continue
        if main_domain in subdomain and subdomain not in subdomains:
            subdomains.append(subdomain)
    return subdomains


# ---------------------------------------------------------------------------
# 二、网络请求
# ---------------------------------------------------------------------------
def fetch(url: str, cookie: str = "", timeout: int = DEFAULT_TIMEOUT,
          session: requests.Session | None = None) -> str | None:
    """抓取页面文本；失败（连接错误 / 超时）返回 None。

    ``session`` 传入时复用该会话（连接池 + 统一代理），调用方负责关闭；
    不传时临时建一个、用完即关（兼容单次调用的 MCP / 页面路径）。
    """
    headers = {"User-Agent": USER_AGENT, "Cookie": cookie or ""}
    own = session is None
    if own:
        session = _session()
    try:
        # 走全局代理池（未启用代理时等价于直连，trust_env=False）
        raw = session.get(url, headers=headers, timeout=timeout, verify=False)
    except requests.RequestException:
        return None
    finally:
        if own:
            session.close()
    return raw.content.decode("utf-8", "ignore")


def _session() -> requests.Session:
    """创建请求会话，接入全局代理池。"""
    from lib import proxy_pool
    return proxy_pool.make_session("jsfinder")


# ---------------------------------------------------------------------------
# 三、收集
# ---------------------------------------------------------------------------
def _collect_scripts(
    url: str,
    cookie: str = "",
    timeout: int = DEFAULT_TIMEOUT,
    session: requests.Session | None = None,
) -> dict[str, str] | None:
    """抓取页面与其全部 script（内嵌 + 外链），返回 ``{脚本URL: 内容}``。

    页面无法访问返回 None。内嵌脚本以目标页 URL 为键。供 URL 收集与
    接口收集两种模式共用。
    """
    html_raw = fetch(url, cookie=cookie, timeout=timeout, session=session)
    if html_raw is None:
        return None

    html = BeautifulSoup(html_raw, "html.parser")
    script_array: dict[str, str] = {}
    inline_temp = ""
    for script in html.findAll("script"):
        src = script.get("src")
        if src is None:
            inline_temp += script.get_text() + "\n"
        else:
            purl = process_url(url, src)
            script_array[purl] = fetch(purl, cookie=cookie, timeout=timeout,
                                       session=session) or ""
    script_array[url] = inline_temp
    return script_array


def find_by_url(
    url: str,
    cookie: str = "",
    timeout: int = DEFAULT_TIMEOUT,
    session: requests.Session | None = None,
) -> list[str] | None:
    """抓取页面与其全部 script（内嵌 + 外链），提取同主域 URL。

    页面无法访问返回 None；页面可达但没有链接返回空列表。
    """
    script_array = _collect_scripts(url, cookie=cookie, timeout=timeout,
                                    session=session)
    if script_array is None:
        return None

    main_domain = _last_dot_domain(urlparse(url).netloc)
    result: list[str] = []
    for script_url, content in script_array.items():
        if not content:
            continue
        for temp_url in extract_url(content):
            absolute = process_url(script_url, temp_url)
            subdomain = urlparse(absolute).netloc
            if (main_domain in subdomain or not subdomain.strip()) \
                    and absolute not in result:
                result.append(absolute)
    return result


def find_api_by_url(
    url: str,
    cookie: str = "",
    timeout: int = DEFAULT_TIMEOUT,
    session: requests.Session | None = None,
) -> list[str] | None:
    """「覆盖 JS 文件查询」：抓取页面与其全部 JS，从中提取 API 接口路径。

    返回相对接口路径（如 ``/api/user/list``）列表，保留出现顺序并去重。
    页面无法访问返回 None；页面可达但没有接口返回空列表。
    """
    script_array = _collect_scripts(url, cookie=cookie, timeout=timeout,
                                    session=session)
    if script_array is None:
        return None

    result: list[str] = []
    for script_url, content in script_array.items():
        if not content:
            continue
        for api in extract_api(content):
            # 保留相对路径；若匹配到完整 URL，截取 path+query 部分统一为相对
            if api.startswith(("http://", "https://")):
                parsed = urlparse(api)
                api = (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")
            if api and api not in result:
                result.append(api)
    return result


def find_by_url_deep(
    url: str,
    cookie: str = "",
    timeout: int = DEFAULT_TIMEOUT,
    max_links: int = DEFAULT_MAX_LINKS,
    progress: ProgressFn | None = None,
    session: requests.Session | None = None,
) -> list[str] | None:
    """深度模式：跟进页面上的 ``<a>`` 链接，对每个链接递归执行普通收集。

    ``max_links`` 限制最大跟进链接数（0 不限），避免链接过多时无限爬取。
    """
    html_raw = fetch(url, cookie=cookie, timeout=timeout, session=session)
    if html_raw is None:
        return None

    html = BeautifulSoup(html_raw, "html.parser")
    links: list[str] = []
    for tag in html.findAll("a"):
        src = tag.get("href")
        if not src:
            continue
        link = process_url(url, src)
        if link not in links:
            links.append(link)
    if max_links > 0:
        links = links[:max_links]
    if not links:
        return None

    if progress:
        progress(f"页面共发现 {len(links)} 个链接，开始递归收集…")

    urls: list[str] = []
    remaining = len(links)
    for link in links:
        temp_urls = find_by_url(link, cookie=cookie, timeout=timeout,
                                session=session)
        if temp_urls:
            for temp_url in temp_urls:
                if temp_url not in urls:
                    urls.append(temp_url)
        if progress:
            progress(f"剩余 {remaining} 个链接 | 当前累计 {len(urls)} 条 URL")
        remaining -= 1
    return urls


# ---------------------------------------------------------------------------
# 四、组合入口
# ---------------------------------------------------------------------------
def _normalize_url(url: str) -> str:
    """补全协议头并去除首尾空白。"""
    text = str(url or "").strip()
    if text and "://" not in text:
        text = "http://" + text
    return text


def run(
    url: str,
    cookie: str = "",
    deep: bool = False,
    timeout: int = DEFAULT_TIMEOUT,
    max_links: int = DEFAULT_MAX_LINKS,
    endpoint: bool = False,
    progress: ProgressFn | None = None,
) -> tuple[list[str], list[str]]:
    """执行收集，返回 ``(URL 列表, 子域名列表)``；失败抛 :class:`JSFinderError`。

    ``endpoint=True`` 进入「覆盖 JS 文件查询」模式：抓取页面与其全部 JS，
    用接口正则提取 API 接口路径（结果放入第一个列表，子域名列表为空）。
    """
    target = _normalize_url(url)
    if not urlparse(target).netloc:
        raise JSFinderError("请填写形如 https://example.com 的有效 URL")

    # 整次收集共用一个会话（连接复用 + 统一代理出口），结束即关
    session = _session()
    try:
        if endpoint:
            apis = find_api_by_url(target, cookie=cookie, timeout=timeout,
                                   session=session)
            if apis is None:
                raise JSFinderError(f"无法访问 {target}（连接失败或超时）")
            if not apis:
                raise JSFinderError(f"{target} 的 JS 中未提取到接口路径")
            return apis, []

        if deep:
            urls = find_by_url_deep(target, cookie=cookie, timeout=timeout,
                                    max_links=max_links, progress=progress,
                                    session=session)
        else:
            urls = find_by_url(target, cookie=cookie, timeout=timeout,
                               session=session)

        if urls is None:
            raise JSFinderError(f"无法访问 {target}（连接失败或超时）")
        if not urls:
            raise JSFinderError(f"{target} 页面中未提取到同主域链接")

        subdomains = find_subdomain(urls, target)
        return urls, subdomains
    finally:
        session.close()
