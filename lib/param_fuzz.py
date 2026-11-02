# -*- coding: utf-8 -*-
"""参数爆破（整合 Arjun 的核心逻辑）。

给定一个 URL，自动发现该端点接受的 HTTP 参数名（query string / 表单 / JSON /
XML 体）。这是把 Arjun（https://github.com/s0md3v/Arjun）的参数爆破引擎迁移进来：

1. **稳定性探测**：对目标发若干次带随机参数名的请求，比较响应，把「每次都变」
   的因素（状态码 / 响应头 / 正文 / 行数 / 重定向 / 参数名反射 / 值反射）逐项
   排除，得到一组「稳定不变」的基线（``define`` / ``compare`` 逻辑）。
2. **启发式预提取**：从首个响应里抠出 ``<input>/<textarea>`` 的 name/id、JS 里的
   变量名 / 对象键、错误提示里的字段名，插到字典最前面优先测试（``heuristic``）。
3. **分块爆破**：把字典参数按 chunk 切成若干组，每组一次性塞进请求，比较响应与
   基线的差异；有差异的块再二分收敛到单个参数，最后逐个 ``verify`` 确认
   （``bruter`` / ``narrower`` / ``confirm`` 逻辑）。
4. **请求方法**：GET / POST / JSON / XML 四种；JSON 与 XML 可配合 ``include``
   固定负载（``$arjun$`` 占位符替换成爆破的键值对）。

相对原版 Arjun 的改动（与项目其余 Web 工具保持一致）：

- 全部请求统一经 :func:`_session` 走全局代理池（``proxy_pool.make_session``），
  不再用 ``requests.get/post`` 直连；这是本工程 Web 工具的铁律。
- 去掉命令行 / 颜色 / ``sys.exit`` / 全局 ``mem.var`` 状态机；改为 :func:`run`
  一个入口，参数显式传入，结果以结构化 dict 返回，:func:`to_text` 排版落盘。
- 去掉 ``ratelimit`` / ``dicttoxml`` 等第三方依赖：速率限制用原生 ``threading``
  节流实现，XML 用标准库 ``xml.etree`` 序列化。
- 去掉被动源（wayback / commoncrawl / otx）在线拉取（外网依赖且易被限速），
  保留启发式本地提取；字典从项目 ``dict/arjun/`` 目录按名加载。
- 支持 ``stop`` 事件：置位后不再发起新请求，在途请求尽快收尾。

本模块只做「URL 进、参数名出」的纯逻辑，不导入任何 UI 模块。
"""

from __future__ import annotations

import random
import re
import threading
import time
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import requests
from requests.packages import urllib3

urllib3.disable_warnings()

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
DEFAULT_TIMEOUT = 15
DEFAULT_THREADS = 5
DEFAULT_CHUNKS = 250
DEFAULT_DELAY = 0.0
DEFAULT_RATE_LIMIT = 0  # 0 = 不限速
DEFAULT_WORDLIST = "small"

#: 字典目录：项目 dict/arjun/ 下按名加载 small/medium/large
DICT_DIR = Path(__file__).resolve().parent.parent / "dict" / "arjun"

#: 支持的方法
METHODS = ("GET", "POST", "JSON", "XML")

#: 内建字典文件名映射
BUILTIN_DICTS = {
    "small": "small.txt",
    "medium": "medium.txt",
    "large": "large.txt",
}

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "close",
}

LogFn = Callable[[str], None]


class ParamFuzzError(ValueError):
    """参数爆破参数 / 连接失败时抛出的统一异常。"""


class ParamFuzzConnectionError(ParamFuzzError):
    """目标连不上（DNS / 拒绝连接 / 超时），与「没爆破出参数」区分开。"""


# ---------------------------------------------------------------------------
# 结果
# ---------------------------------------------------------------------------
@dataclass
class ParamFuzzResult:
    """一次参数爆破的汇总结果。"""

    target: str
    method: str = "GET"
    wordlist: str = ""
    elapsed: float = 0.0
    stopped: bool = False
    skipped: bool = False
    skip_reason: str = ""
    heuristic_params: list[str] = field(default_factory=list)
    found_params: list[str] = field(default_factory=list)
    reasons: dict[str, str] = field(default_factory=dict)
    total_requests: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "method": self.method,
            "wordlist": self.wordlist,
            "elapsed": round(self.elapsed, 1),
            "stopped": self.stopped,
            "skipped": self.skipped,
            "skip_reason": self.skip_reason,
            "heuristic_params": list(self.heuristic_params),
            "found_params": list(self.found_params),
            "reasons": dict(self.reasons),
            "total_requests": self.total_requests,
        }


# ---------------------------------------------------------------------------
# 会话（代理池约定）
# ---------------------------------------------------------------------------
def _session() -> requests.Session:
    """创建走全局代理池的请求会话（Web 工具统一入口）。"""
    from lib import proxy_pool

    session = proxy_pool.make_session("param_fuzz")
    session.headers.update(HEADERS)
    return session


def _describe_error(exc: Exception) -> str:
    """把 requests 异常压成一句人话。"""
    text = str(exc)
    if isinstance(exc, requests.exceptions.ConnectTimeout):
        return "连接超时"
    if isinstance(exc, requests.exceptions.ReadTimeout):
        return "读取超时"
    if isinstance(exc, requests.exceptions.SSLError):
        return "TLS 握手失败"
    if ("NewConnectionError" in text or "Connection refused" in text
            or "积极拒绝" in text or "Connection aborted" in text):
        return "目标拒绝连接（端口未开放或被防火墙拦截）"
    if ("Name or service not known" in text or "getaddrinfo failed" in text
            or "NameResolutionError" in text):
        return "域名解析失败"
    return text[:120]


def _normalize_url(raw: str) -> str:
    """补协议头、去首尾空白、校验 netloc。"""
    text = str(raw or "").strip().replace("：", ":")
    if not text:
        raise ParamFuzzError("请填写目标 URL，如 https://example.com")
    if "://" not in text:
        text = "http://" + text
    parsed = urllib.parse.urlparse(text)
    if not parsed.hostname:
        raise ParamFuzzError("目标格式不正确，示例：https://example.com 或 example.com")
    return text


# ---------------------------------------------------------------------------
# 工具函数（迁移自 Arjun 的 utils / anomaly 逻辑）
# ---------------------------------------------------------------------------
def _random_str(n: int) -> str:
    """生成一个纯数字随机串（Arjun 用数字串，避免被 WAF 拦截）。"""
    return "".join(str(random.choice(range(10))) for _ in range(n))


def _populate(words: list[str]) -> dict[str, str]:
    """把参数名列表映射成「参数名 -> 6 位数字值」（Arjun 的 populate）。"""
    return {name: "1" * (6 - len(str(i))) + str(i) for i, name in enumerate(words)}


def _slicer(dic: dict, n: int = 2) -> list[dict]:
    """把一个 dict 均匀切成 n 份（Arjun 的 slicer）。"""
    listed = list(dic.items())
    k, m = divmod(len(dic), n)
    return [
        dict(listed[i * k + min(i, m):(i + 1) * k + min(i + 1, m)])
        for i in range(n)
    ]


def _remove_tags(html: str) -> str:
    """去掉 HTML 标签，返回纯文本（Arjun 的 remove_tags）。"""
    return re.sub(r"(?s)<.*?>", "", html)


def _diff_map(body_1: str, body_2: str) -> list[str]:
    """返回两段多行文本里相同的行（Arjun 的 diff_map）。"""
    sig: list[str] = []
    lines_1, lines_2 = body_1.split("\n"), body_2.split("\n")
    for line_1, line_2 in zip(lines_1, lines_2):
        if line_1 == line_2:
            sig.append(line_1)
    return sig


def _dict_to_xml(obj: dict) -> str:
    """把 dict 序列化成无根 XML 片段（Arjun 用 dicttoxml root=False）。"""
    parts: list[str] = []
    for key, value in obj.items():
        text = str(value)
        parts.append(f"<{key}>{_xml_escape(text)}</{key}>")
    return "".join(parts)


def _xml_escape(text: str) -> str:
    """XML 文本转义。"""
    return (text.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;").replace("'", "&apos;"))


def _parse_headers(text: str) -> dict[str, str]:
    """解析「每行一个 Key: Value」的自定义请求头。"""
    result: dict[str, str] = {}
    for line in str(text or "").replace("\\n", "\n").splitlines():
        line = line.strip()
        if not line:
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        if key:
            result[key] = value.strip()
    return result


# ---------------------------------------------------------------------------
# 字典加载
# ---------------------------------------------------------------------------
def load_wordlist(source: str) -> list[str]:
    """按名加载字典，返回去重后的参数名列表。

    ``source`` 取 ``small`` / ``medium`` / ``large``（映射到 dict/arjun/ 内建
    文件），或一个存在的文件路径。失败抛 :class:`ParamFuzzError`。
    """
    name = str(source or "").strip()
    if name in BUILTIN_DICTS:
        path = DICT_DIR / BUILTIN_DICTS[name]
    else:
        path = Path(name)
    if not path.is_file():
        raise ParamFuzzError(
            f"字典不存在：{name}（可用 small / medium / large，或指定文件路径）")
    try:
        words: list[str] = []
        seen: set[str] = set()
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                word = line.rstrip("\r\n").strip()
                if not word or word in seen:
                    continue
                seen.add(word)
                words.append(word)
        return words
    except OSError as exc:
        raise ParamFuzzError(f"读取字典失败：{exc}") from exc


def _load_special() -> dict[str, str]:
    """加载 special.json（特殊参数 -> 固定值，用于最后 verify）。"""
    path = DICT_DIR / "special.json"
    try:
        import json
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


# ---------------------------------------------------------------------------
# 启发式预提取（迁移自 Arjun 的 heuristic 插件）
# ---------------------------------------------------------------------------
_RE_WORDS = re.compile(r"[A-Za-z][A-Za-z0-9_]*")
_RE_NOT_JUNK = re.compile(r"^[A-Za-z0-9_]+$")
_RE_INPUTS = re.compile(
    r"(?i)<(?:input|textarea)[^>]+?(?:id|name)=[\"']?([^\"'\s>]+)")
_RE_EMPTY_VARS = re.compile(
    r"(?:[;\n]|\bvar|\blet)(\w+)\s*=\s*(?:['\"`]{1,2}|true|false|null)")
_RE_MAP_KEYS = re.compile(r"['\"](\w+?)['\"]\s*:\s*['\"`]")


def _extract_js(text: str) -> list[str]:
    """从正文里抠出 <script> 块。"""
    scripts: list[str] = []
    for part in re.split(r"(?i)<script[> ]", text):
        actual = re.split(r"(?i)</script>", part, maxsplit=1)
        if len(actual) > 1:
            scripts.append(actual[0])
    return scripts


def _heuristic(response: requests.Response, wordlist: list[str]) -> list[str]:
    """从首个响应里启发式提取参数名，并插到字典最前面。"""
    words_exist = False
    potential: list[str] = []
    content_type = response.headers.get("content-type", "")
    body = response.text
    if content_type.startswith(("application/json", "text/plain")):
        if len(body) < 200 and any(k in body.lower() for k in
                                   ("required", "missing", "not found", "requires")):
            words_exist = True
            potential += _RE_WORDS.findall(body)
    potential += _RE_INPUTS.findall(body)
    for script in _extract_js(body):
        potential += _RE_EMPTY_VARS.findall(script)
        potential += _RE_MAP_KEYS.findall(script)

    found: list[str] = []
    seen: set[str] = set()
    for word in potential:
        if _RE_NOT_JUNK.match(word) and word not in seen:
            seen.add(word)
            found.append(word)
            # 启发式命中的参数优先测试：移到字典最前（Arjun 原逻辑）
            if word in wordlist:
                wordlist.remove(word)
            wordlist.insert(0, word)
    return found


# ---------------------------------------------------------------------------
# 异常检测（迁移自 Arjun 的 anomaly 模块）
# ---------------------------------------------------------------------------
def _define(response_1: requests.Response, response_2: requests.Response,
            param: str, value: str, wordlist: list[str]) -> dict[str, Any]:
    """对比两个响应，建立「稳定因素」基线。"""
    factors: dict[str, Any] = {
        "same_code": None,
        "same_body": None,
        "same_plaintext": None,
        "lines_num": None,
        "lines_diff": None,
        "same_headers": None,
        "same_redirect": None,
        "param_missing": None,
        "value_missing": None,
    }
    body_1, body_2 = response_1.text, response_2.text
    if response_1.status_code == response_2.status_code:
        factors["same_code"] = response_1.status_code
    h1, h2 = list(response_1.headers.keys()), list(response_2.headers.keys())
    h1.sort()
    h2.sort()
    if h1 == h2:
        factors["same_headers"] = h1
    # Arjun 默认 allow_redirects=False，用 Location 头判断重定向
    if response_1.headers.get("Location", "") == response_2.headers.get("Location", ""):
        factors["same_redirect"] = urllib.parse.urlparse(
            response_1.headers.get("Location", "")).path
    else:
        factors["same_redirect"] = ""
    if response_1.text == response_2.text:
        factors["same_body"] = response_1.text
    elif response_1.text.count("\n") == response_2.text.count("\n"):
        factors["lines_num"] = response_1.text.count("\n")
    elif _remove_tags(body_1) == _remove_tags(body_2):
        factors["same_plaintext"] = _remove_tags(body_1)
    elif body_1 and body_2:
        factors["lines_diff"] = _diff_map(body_1, body_2)
    if param not in response_2.text:
        factors["param_missing"] = [w for w in wordlist if w in response_2.text]
    if value not in response_2.text:
        factors["value_missing"] = True
    return factors


def _compare(response: requests.Response, factors: dict[str, Any],
             params: dict[str, str]) -> tuple[str, Any, str]:
    """把一个响应与基线对比，返回 (异常类型, 参数 dict, 异常因素名)。

    第二个返回值是传入的 ``params`` dict 本身（Arjun 原逻辑），这样「引起异常
    的参数组」能被继续二分切分，直到收敛到单个参数。
    """
    if response == "" or isinstance(response, str):
        return ("", [], "")
    these_headers = list(response.headers.keys())
    these_headers.sort()
    if factors["same_code"] is not None and response.status_code != factors["same_code"]:
        return ("http code", params, "same_code")
    if factors["same_headers"] is not None and these_headers != factors["same_headers"]:
        return ("http headers", params, "same_headers")
    if (factors["same_redirect"] is not None
            and urllib.parse.urlparse(response.headers.get("Location", "")).path
            != factors["same_redirect"]):
        return ("redirection", params, "same_redirect")
    if factors["same_body"] is not None and response.text != factors["same_body"]:
        return ("body length", params, "same_body")
    if factors["lines_num"] is not None and response.text.count("\n") != factors["lines_num"]:
        return ("number of lines", params, "lines_num")
    if factors["same_plaintext"] is not None and _remove_tags(response.text) != factors["same_plaintext"]:
        return ("text length", params, "same_plaintext")
    if factors["lines_diff"] is not None:
        for line in factors["lines_diff"]:
            if line not in response.text:
                return ("lines", params, "lines_diff")
    if factors["param_missing"] is not None:
        for param in params.keys():
            if len(param) < 5:
                continue
            if param not in factors["param_missing"] and re.search(
                    r"[\'\"\s]%s[\'\"\s]" % re.escape(param), response.text):
                return ("param name reflection", params, "param_missing")
    if factors["value_missing"] is not None:
        for value in params.values():
            if not isinstance(value, str) or len(value) != 6:
                continue
            if value in response.text and re.search(
                    r"[\'\"\s]%s[\'\"\s]" % re.escape(value), response.text):
                return ("param value reflection", params, "value_missing")
    return ("", [], "")


# ---------------------------------------------------------------------------
# 请求（迁移自 Arjun 的 requester / error_handler）
# ---------------------------------------------------------------------------
class _Throttle:
    """线程安全限速器（取代 ratelimit 库）。"""

    def __init__(self, rate_limit: float, delay: float) -> None:
        self._rate = rate_limit
        self._delay = delay
        self._lock = threading.Lock()
        self._next_allowed = 0.0

    def wait(self) -> None:
        if self._delay > 0:
            time.sleep(self._delay)
        if self._rate and self._rate > 0:
            interval = 1.0 / self._rate
            with self._lock:
                now = time.time()
                if now < self._next_allowed:
                    time.sleep(self._next_allowed - now)
                    now = time.time()
                self._next_allowed = now + interval


class _Runner:
    """封装单目标爆破的请求上下文与计数。"""

    def __init__(self, session: requests.Session, request: dict,
                 timeout: float, throttle: _Throttle,
                 stop: threading.Event | None, counter: list[int]) -> None:
        self.session = session
        self.request = request
        self.timeout = timeout
        self.throttle = throttle
        self.stop = stop
        self.counter = counter  # [total_requests]
        self.bad_req_count = 0
        self.healthy_url = False
        self.kill = False

    def requester(self, payload: dict | None = None) -> Any:
        """发一次请求，返回 Response 或错误字符串。"""
        if self.kill or (self.stop is not None and self.stop.is_set()):
            return "killed"
        self.throttle.wait()
        payload = dict(payload or {})
        include = self.request.get("include") or {}
        if include:
            payload.update(include)

        url = self.request["url"]
        method = self.request["method"]
        headers = dict(self.request["headers"])
        # JSON/XML 的 $arjun$ 模板必须用原始字符串；include 字段已被解析成
        # dict，str(dict) 是 Python repr 而不是合法 JSON/XML
        include_raw = str(self.request.get("include_raw") or "")
        try:
            if method == "GET":
                response = self.session.get(url, params=payload, headers=headers,
                                            verify=False, allow_redirects=False,
                                            timeout=self.timeout)
            elif method == "JSON":
                headers["Content-Type"] = "application/json"
                if "$arjun$" in include_raw:
                    body = _render_include_template(
                        include_raw,
                        __import__("json").dumps(payload, ensure_ascii=False))
                    response = self.session.post(url, data=body, headers=headers,
                                                 verify=False, allow_redirects=False,
                                                 timeout=self.timeout)
                else:
                    response = self.session.post(url, json=payload, headers=headers,
                                                 verify=False, allow_redirects=False,
                                                 timeout=self.timeout)
            elif method == "XML":
                headers["Content-Type"] = "application/xml"
                if "$arjun$" in include_raw:
                    body = _render_include_template(include_raw,
                                                    _dict_to_xml(payload))
                else:
                    body = _dict_to_xml(payload)
                response = self.session.post(url, data=body, headers=headers,
                                             verify=False, allow_redirects=False,
                                             timeout=self.timeout)
            else:  # POST
                response = self.session.post(url, data=payload, headers=headers,
                                             verify=False, allow_redirects=False,
                                             timeout=self.timeout)
            self.counter[0] += 1
            return response
        except requests.RequestException as exc:
            return _describe_error(exc)

    def error_handler(self, response: Any, factors: dict[str, Any]) -> str:
        """决定下一步：ok / retry / kill。"""
        if isinstance(response, requests.Response) and response.status_code in (400, 413, 418, 429, 503):
            if not self.healthy_url:
                return "ok"
            if response.status_code == 503:
                self.kill = True
                return "kill"
            if response.status_code in (429, 418):
                return "kill"
            if factors.get("same_code") != response.status_code:
                self.bad_req_count += 1
                if self.bad_req_count > 20:
                    self.kill = True
                    return "kill"
            else:
                return "ok"
        else:
            if isinstance(response, str):
                if "Timeout" in response or "超时" in response:
                    if self.timeout > 20:
                        self.kill = True
                        return "kill"
                    self.timeout += 5
                    return "retry"
                if "refused" in response or "拒绝" in response:
                    return "kill"
                return "kill"
        return "ok"

    def bruter(self, factors: dict[str, Any], params: dict[str, str],
               mode: str = "bruteforce") -> Any:
        """对一组参数做异常检测，返回 (异常类型, 参数列表) 或列表。"""
        if self.kill or (self.stop is not None and self.stop.is_set()):
            return []
        response = self.requester(params)
        conclusion = self.error_handler(response, factors)
        if conclusion == "retry":
            return self.bruter(factors, params, mode=mode)
        if conclusion == "kill":
            self.kill = True
            return []
        result = _compare(response, factors, params)
        if mode == "verify":
            return result[0]
        return result[1]


# ---------------------------------------------------------------------------
# 单目标爆破主流程（迁移自 Arjun 的 initialize + narrower）
# ---------------------------------------------------------------------------
def _scan_target(session: requests.Session, request: dict, wordlist: list[str],
                 timeout: float, threads: int, chunks: int, throttle: _Throttle,
                 log: LogFn, stop: threading.Event | None,
                 counter: list[int]) -> ParamFuzzResult:
    """对单个 request 对象做参数爆破，返回结果。"""
    url = request["url"]
    emit = log or (lambda _m: None)
    result = ParamFuzzResult(target=url, method=request["method"])
    if not url.startswith("http"):
        result.skipped = True
        result.skip_reason = f"{url} 不是有效 URL"
        return result

    runner = _Runner(session, request, timeout, throttle, stop, counter)

    # 稳定性探测：连发两次带随机参数名的请求，确认目标稳定
    fuzz = "z" + _random_str(6)
    probe_1 = runner.requester({fuzz[:-1]: fuzz[::-1][:-1]})
    if not isinstance(probe_1, requests.Response):
        result.skipped = True
        result.skip_reason = f"目标连接失败：{probe_1}"
        return result
    runner.healthy_url = probe_1.status_code not in (400, 413, 418, 429, 503)
    if not runner.healthy_url:
        emit(f"[警告] 目标返回 HTTP {probe_1.status_code}，可能影响爆破结果")
    probe_2 = runner.requester({fuzz[:-1]: fuzz[::-1][:-1]})
    if not isinstance(probe_2, requests.Response):
        result.skipped = True
        result.skip_reason = "目标稳定性探测失败"
        return result

    # 启发式预提取（在建立基线前先抠出响应里的参数）
    found = _heuristic(probe_1, wordlist)
    if found:
        result.heuristic_params = list(found)
        emit(f"[启发式] 从响应提取 {len(found)} 个参数：{', '.join(found[:20])}"
             + ("…" if len(found) > 20 else ""))

    # 建立稳定因素基线
    factors = _define(probe_1, probe_2, fuzz, fuzz[::-1], wordlist)

    # 第三发确认：把「每次变」的因素从基线里剔除
    zzuf = "z" + _random_str(6)
    probe_3 = runner.requester({zzuf[:-1]: zzuf[::-1][:-1]})
    if isinstance(probe_3, requests.Response):
        while True:
            reason = _compare(probe_3, factors, {zzuf[:-1]: zzuf[::-1][:-1]})[2]
            if not reason:
                break
            factors[reason] = None

    # 分块爆破
    populated = _populate(wordlist)
    populated.update(_load_special())
    if len(wordlist) < chunks:
        chunks = max(1, int(len(wordlist) / 2))
    param_groups = _slicer(populated, int(len(wordlist) / chunks))
    prev_count = len(param_groups)
    last_params: list[dict] = []

    emit(f"[爆破] 共 {len(wordlist)} 个参数，分 {len(param_groups)} 组，"
         f"每组最多 {chunks} 个")
    round_no = 0
    while True:
        if runner.kill or (stop is not None and stop.is_set()):
            break
        round_no += 1
        param_groups = _narrow(runner, factors, param_groups, threads, stop)
        if runner.kill:
            break
        if len(param_groups) >= prev_count * 2:
            # 组数翻倍 = 上一轮几乎每个组都异常（页面每次返回不同内容），
            # 说明目标页面本身不稳定，无法可靠爆破。
            # 注：Arjun 原版用 ``> prev_count``，在「小字典 + 大 chunk」时
            # 会因命中参数较多而误判，这里放宽为「翻倍」以兼顾正确性与鲁棒性。
            emit("[警告] 页面每次请求返回不同内容，无法可靠爆破，已跳过")
            result.skipped = True
            result.skip_reason = "页面响应不稳定（每次内容不同）"
            return result
        # 收敛：单键的组挪进 last_params，多键的组继续二分
        narrowed: list[dict] = []
        for group in param_groups:
            if len(group) == 1:
                last_params.append(group)
            else:
                narrowed.append(group)
        param_groups = narrowed
        prev_count = len(param_groups)
        emit(f"[收敛] 第 {round_no} 轮：剩余 {len(param_groups)} 组待细分，"
             f"已确认 {len(last_params)} 个候选")
        if not param_groups:
            break

    # verify：逐个确认候选参数
    confirmed: list[str] = []
    for param in last_params:
        if stop is not None and stop.is_set():
            result.stopped = True
            break
        reason = runner.bruter(factors, param, mode="verify")
        if reason:
            name = list(param.keys())[0]
            confirmed.append(name)
            result.reasons[name] = reason
            emit(f"[命中] {name}（依据：{reason}）")

    result.found_params = confirmed
    result.stopped = bool(stop is not None and stop.is_set()) or runner.kill
    result.total_requests = counter[0]
    return result


def _narrow(runner: _Runner, factors: dict[str, Any], param_groups: list[dict],
            threads: int, stop: threading.Event | None) -> list[dict]:
    """并发爆破一组参数块，把引起异常的块二分切分后返回（迁移自 narrower）。"""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    anomalous: list[dict] = []
    if not param_groups:
        return anomalous
    workers = max(1, min(int(threads), len(param_groups)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(runner.bruter, factors, g) for g in param_groups]
        for future in as_completed(futures):
            if runner.kill or (stop is not None and stop.is_set()):
                for f in futures:
                    f.cancel()
                break
            try:
                res = future.result()
            except Exception:  # noqa: BLE001
                res = []
            if res:
                # res 是引起异常的参数 dict，二分切分以收敛（Arjun 原逻辑）
                anomalous.extend(_slicer(res))
    return anomalous


# ---------------------------------------------------------------------------
# 统一入口
# ---------------------------------------------------------------------------
def run(
    target: str,
    method: str = "GET",
    wordlist: str = DEFAULT_WORDLIST,
    include: str = "",
    headers: str = "",
    timeout: float = DEFAULT_TIMEOUT,
    threads: int = DEFAULT_THREADS,
    chunks: int = DEFAULT_CHUNKS,
    delay: float = DEFAULT_DELAY,
    rate_limit: int = DEFAULT_RATE_LIMIT,
    log: LogFn | None = None,
    stop: threading.Event | None = None,
) -> dict[str, Any]:
    """对 ``target`` 做一次 HTTP 参数爆破，返回结构化 dict。

    参数
    ----
    target      目标 URL（可省略协议头）
    method      请求方法：GET / POST / JSON / XML
    wordlist    字典名（small / medium / large）或文件路径
    include     每发请求固定携带的负载（GET/POST 用 query/表单串；
                JSON/XML 可用 ``$arjun$`` 占位符嵌入爆破键值对）
    headers     自定义请求头（每行一个 ``Key: Value``）
    timeout     单次请求超时（秒）
    threads     并发线程数
    chunks      每组参数数量（chunk size）
    delay       每次请求间隔（秒）
    rate_limit  每秒最大请求数（0 = 不限速）
    log         逐行日志回调
    stop        置位后停止
    """
    import time as _time

    emit = log or (lambda _m: None)
    started = _time.time()
    base = _normalize_url(target)
    method = str(method or "GET").upper()
    if method not in METHODS:
        raise ParamFuzzError(f"不支持的请求方法：{method}（可选 {', '.join(METHODS)}）")

    words = load_wordlist(wordlist)
    emit(f"[目标] {base}")
    emit(f"[方法] {method}")
    emit(f"[字典] {wordlist}（{len(words)} 个参数）")

    # 组装 request 对象
    req_headers = dict(HEADERS)
    req_headers.update(_parse_headers(headers))
    request: dict[str, Any] = {
        "url": base,
        "method": method,
        "headers": req_headers,
        "include": _parse_include(include),
        # 原始 include 文本：$arjun$ 模板在 _parse_include 里会解析失败（占位符
        # 不是合法 JSON），必须保留原文供 JSON/XML 请求体渲染
        "include_raw": str(include or "").strip(),
    }

    session = _session()
    counter = [0]
    throttle = _Throttle(rate_limit, delay)
    try:
        result = _scan_target(session, request, words, timeout, threads, chunks,
                              throttle, emit, stop, counter)
    finally:
        session.close()

    result.wordlist = wordlist
    result.elapsed = _time.time() - started
    result.stopped = result.stopped or bool(stop is not None and stop.is_set())
    if result.skipped:
        emit(f"[跳过] {result.skip_reason}")
    elif result.found_params:
        emit(f"[完成] 命中 {len(result.found_params)} 个参数："
             f"{', '.join(result.found_params)}")
    else:
        emit("[完成] 未发现参数")
    emit(f"[统计] 共 {result.total_requests} 次请求，耗时 {result.elapsed:.1f}s")
    return result.to_dict()


def _parse_include(include: str) -> dict[str, str]:
    """解析 include 负载：JSON 对象或 query 串。"""
    text = str(include or "").strip()
    if not text:
        return {}
    if text.startswith("{"):
        import json
        try:
            data = json.loads(text.replace("'", '"'))
            return data if isinstance(data, dict) else {}
        except json.JSONDecodeError:
            return {}
    # query 串
    params: dict[str, str] = {}
    for part in text.split("?")[-1].split("&"):
        if "=" in part:
            key, _, value = part.partition("=")
            params[key] = value
        elif part:
            params[part] = ""
    return params


def _render_include_template(raw: str, chunk: str) -> str:
    """把 include 模板里的 ``$arjun$`` 占位符替换成爆破键值对的序列化文本。

    ``chunk`` 是当前这组候选参数的 JSON / XML 序列化结果。占位符两种写法：

    - ``"$arjun$"``（带引号，作为 JSON 值）：整体替换成完整序列化结果，
      如 ``{"data": "$arjun$"}`` → ``{"data": {"user": "x"}}``；
    - 裸 ``$arjun$``（内联成员）：替换成去外层花括号的对象体，
      如 ``{"a":1,$arjun$}`` → ``{"a":1,"user":"x"}``（空对象时连同多余
      逗号一起移除）。XML 模板按裸占位符整段嵌入。
    """
    if '"$arjun$"' in raw:
        return raw.replace('"$arjun$"', chunk)
    if "'$arjun$'" in raw:
        return raw.replace("'$arjun$'", chunk)
    if chunk.startswith("{") and chunk.endswith("}"):
        inner = chunk[1:-1].strip()
    else:
        inner = chunk
    if inner:
        return raw.replace("$arjun$", inner)
    return re.sub(r",?\s*\$arjun\$", "", raw)


def to_text(result: dict[str, Any]) -> str:
    """把 :func:`run` 的结果 dict 渲染成纯文本报告（供落盘 txt）。"""
    from datetime import datetime

    lines: list[str] = []
    add = lines.append
    add("# 参数爆破报告")
    add(f"# 目标: {result.get('target', '')}")
    add(f"# 方法: {result.get('method', '')}")
    add(f"# 字典: {result.get('wordlist', '')}")
    add(f"# 时间: {datetime.now():%Y-%m-%d %H:%M:%S}")
    add(f"# 耗时: {result.get('elapsed', 0)}s"
        + ("（已手动停止）" if result.get("stopped") else ""))
    add(f"# 请求数: {result.get('total_requests', 0)}")

    if result.get("skipped"):
        add("")
        add(f"=== 跳过 ===")
        add(f"  {result.get('skip_reason', '')}")
        return "\n".join(lines)

    heuristic = result.get("heuristic_params") or []
    if heuristic:
        add("")
        add(f"=== 启发式提取参数（{len(heuristic)}） ===")
        for name in heuristic:
            add(f"  {name}")

    found = result.get("found_params") or []
    reasons = result.get("reasons") or {}
    add("")
    add(f"=== 命中参数（{len(found)}） ===")
    if not found:
        add("  （无）")
    for name in found:
        reason = reasons.get(name, "")
        add(f"  {name}" + (f"  —— 依据：{reason}" if reason else ""))

    add("")
    add("# 生成于 28zenro 参数爆破")
    return "\n".join(lines)


__all__ = [
    "DEFAULT_TIMEOUT",
    "DEFAULT_THREADS",
    "DEFAULT_CHUNKS",
    "DEFAULT_DELAY",
    "DEFAULT_RATE_LIMIT",
    "DEFAULT_WORDLIST",
    "METHODS",
    "BUILTIN_DICTS",
    "ParamFuzzError",
    "ParamFuzzConnectionError",
    "ParamFuzzResult",
    "load_wordlist",
    "run",
    "to_text",
]
