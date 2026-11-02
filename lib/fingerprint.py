# -*- coding: utf-8 -*-
"""指纹探测（Web 应用 / 服务指纹识别）纯逻辑模块。

本模块实现与社区指纹识别工具 ``observer_ward``（侦查守卫）兼容的指纹规则匹配引擎：
读取 ``FingerprintHub`` 风格的 YAML 指纹规则（``id`` / ``info`` / ``http`` / ``matchers`` /
``extractors``），对目标 URL 发起 HTTP 探针请求，按规则里的关键词（word）、正则（regex）、
favicon 哈希（mmh3 / md5）逐条匹配，返回命中的组件名、厂商、产品、版本与匹配证据。

设计约定（与 :mod:`lib.web_fuzz` 一致）
--------------------------------------
1. **代理池约定**：所有 HTTP 请求统一经 :func:`proxy_pool.make_session` 创建会话
   （``tool_id="fingerprint"``），启用全局代理池时自动走轮换代理，未启用时直连。
2. **只做「URL + 规则集进、结构化结果出」**，不导入任何 UI 模块。
3. 全程支持 ``stop`` 事件，可随时中止；单个规则失败不影响其余规则。

规则格式（observer_ward / FingerprintHub）
------------------------------------------
本模块只实现 fingerprint 探测常用的子集：``http`` 探针（method / path / headers）与
三类匹配器（``word`` / ``regex`` / ``favicon``），以及正则 ``extractors`` 提取版本等字段。
不支持 ``tcp`` 服务指纹探针（那是端口扫描 / 服务识别的范畴，不在「Web 指纹探测」内）。

本模块只做纯逻辑，不导入任何 UI 模块。
"""

from __future__ import annotations

import hashlib
import re
import threading
import urllib.parse
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests
import yaml
from requests.packages import urllib3

urllib3.disable_warnings()  # 目标站常见自签名证书，统一静默告警

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
DEFAULT_TIMEOUT = 8
#: 单次请求读取正文上限（字节），够拿标题 / meta / 关键词
READ_LIMIT = 2 * 1024 * 1024
#: 单个结果里证据文本的最大长度
EVIDENCE_MAX = 200

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
HEADERS = {"User-Agent": USER_AGENT, "Connection": "close"}

#: 内置指纹规则目录（相对项目根）：FingerprintHub 风格的 YAML 文件
BUILTIN_RULES_DIR = "dict/fingerprints"

LogFn = Callable[[str], None]


class FingerprintError(ValueError):
    """指纹探测参数 / 连接失败时抛出的统一异常。"""


class FingerprintConnectionError(FingerprintError):
    """目标连不上（DNS / 拒绝连接 / 超时），与「没有匹配到指纹」区分开。"""


@dataclass
class FingerprintMatch:
    """一条命中指纹的规则结果。"""

    id: str
    name: str
    vendor: str = ""
    product: str = ""
    version: str = ""
    info: str = ""
    tags: list[str] = field(default_factory=list)
    #: 命中的证据（关键词 / 正则命中片段），用于界面回显与人工复核
    evidence: str = ""
    #: 匹配器类型（word / regex / favicon）
    match_type: str = ""
    #: 命中探针的最终 URL
    url: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "vendor": self.vendor,
            "product": self.product,
            "version": self.version,
            "info": self.info,
            "tags": list(self.tags),
            "evidence": self.evidence,
            "match_type": self.match_type,
            "url": self.url,
        }


# ---------------------------------------------------------------------------
# 规则加载
# ---------------------------------------------------------------------------
def rules_dir() -> Path:
    """内置指纹规则目录的绝对路径（源码 / 冻结态均可用）。"""
    import sys

    from lib.runtime_paths import resource

    return resource(BUILTIN_RULES_DIR)


def load_rules(
    directories: Iterable[str | Path] | None = None,
) -> list[dict[str, Any]]:
    """加载目录（或单个 YAML 文件路径）里的全部指纹规则。

    ``directories`` 缺省时只读内置 ``dict/fingerprints``；传入后可扩展用户自定义
    目录 / 文件（用于界面「加载自定义规则」）。规则按加载顺序返回，坏的 YAML 跳过并
    计入 ``load_errors``（不抛异常，保证其它规则可用）。
    """
    errors: list[str] = []
    rules: list[dict[str, Any]] = []
    paths: list[Path] = []

    sources = list(directories) if directories else [rules_dir()]
    for src in sources:
        p = Path(src)
        if not p.exists():
            errors.append(f"路径不存在：{p}")
            continue
        if p.is_file():
            paths.append(p)
        else:
            paths.extend(sorted(p.glob("*.yaml")) + sorted(p.glob("*.yml")))

    for path in paths:
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            errors.append(f"读取规则失败 {path.name}：{exc}")
            continue
        if isinstance(data, dict):
            rules.append(data)
        elif isinstance(data, list):
            rules.extend(item for item in data if isinstance(item, dict))
        else:
            errors.append(f"规则格式不支持：{path.name}")

    # 把加载错误挂到返回值上（借一个哨兵键，调用方用 get 取回，不污染规则本身）
    if errors:
        rules.append({"_load_errors": errors})
    return rules


# ---------------------------------------------------------------------------
# favicon 哈希
# ---------------------------------------------------------------------------
def mmh3_hash(data: bytes) -> str:
    """计算 bytes 的 mmh3 32 位哈希（与 observer_ward / shodan 的 favicon 哈希一致）。"""
    import mmh3

    return str(mmh3.hash(data) & 0xFFFFFFFF)


def md5_hash(data: bytes) -> str:
    """计算 bytes 的 md5 十六进制摘要。"""
    return hashlib.md5(data).hexdigest()  # noqa: S324  favicon 哈希非安全用途


def favicon_hashes(data: bytes) -> dict[str, str]:
    """返回 favicon 内容的 ``{"mmh3": …, "md5": …}`` 双哈希。"""
    return {"mmh3": mmh3_hash(data), "md5": md5_hash(data)}


# ---------------------------------------------------------------------------
# 会话（代理池约定）
# ---------------------------------------------------------------------------
def _session() -> requests.Session:
    """创建走全局代理池的请求会话（Web 工具统一入口）。"""
    from lib import proxy_pool

    session = proxy_pool.make_session("fingerprint")
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
        raise FingerprintError("请填写目标 URL，如 https://example.com")
    if "://" not in text:
        text = "http://" + text
    parsed = urllib.parse.urlparse(text)
    if not parsed.hostname:
        raise FingerprintError("目标格式不正确，示例：https://example.com 或 example.com")
    return text


# ---------------------------------------------------------------------------
# 规则匹配核心
# ---------------------------------------------------------------------------
def _match_word(
    words: list[str],
    part: str,
    headers: dict[str, str],
    body: str,
    case_insensitive: bool,
) -> tuple[bool, str]:
    """关键词匹配：``part`` 为 ``header`` 时在 ``Header: Value`` 文本里找，否则在 body 找。"""
    haystack = ""
    if part == "header":
        haystack = "\n".join(f"{k}: {v}" for k, v in headers.items())
    else:
        haystack = body
    if case_insensitive:
        haystack = haystack.lower()
    for word in words:
        needle = str(word)
        if case_insensitive:
            needle = needle.lower()
        idx = haystack.find(needle)
        if idx >= 0:
            start = max(0, idx - 20)
            snippet = haystack[idx:idx + len(needle) + 60].replace("\n", " ")
            return True, snippet[:EVIDENCE_MAX]
    return False, ""


def _match_regex(
    patterns: list[str],
    part: str,
    headers: dict[str, str],
    body: str,
) -> tuple[bool, str, dict[str, str], list[str]]:
    """正则匹配：返回 (命中, 证据片段, 命名组 dict, 全部捕获组 list)。"""
    haystack = "\n".join(f"{k}: {v}" for k, v in headers.items()) if part == "header" else body
    for pattern in patterns:
        try:
            m = re.search(pattern, haystack, re.I | re.S)
        except re.error:
            continue
        if m:
            snippet = re.sub(r"\s+", " ", m.group(0))[:EVIDENCE_MAX]
            named = {k: v for k, v in m.groupdict().items() if v is not None}
            return True, snippet, named, list(m.groups())
    return False, "", {}, []


def _resolve_favicon(
    session: requests.Session,
    base: str,
    html: str,
    timeout: float,
    stop: threading.Event | None,
) -> dict[str, str]:
    """从主页 HTML 提取 favicon 链接并下载计算双哈希，失败返回空 dict。"""
    hrefs: list[str] = []
    icon_re = re.compile(
        r"<link[^>]+rel=[\"'](?:shortcut\s+)?icon[\"'][^>]*"
        r"href=[\"']([^\"']+)[\"']", re.I)
    icon_re_alt = re.compile(
        r"<link[^>]+href=[\"']([^\"']+)[\"'][^>]*"
        r"rel=[\"'](?:shortcut\s+)?icon[\"']", re.I)
    hrefs = icon_re.findall(html) or icon_re_alt.findall(html)
    if not hrefs:
        hrefs = ["/favicon.ico"]
    seen: set[str] = set()
    for href in hrefs:
        if stop is not None and stop.is_set():
            break
        url = urllib.parse.urljoin(base, href)
        if url in seen:
            continue
        seen.add(url)
        try:
            resp = session.get(url, timeout=timeout, verify=False, stream=True)
        except requests.RequestException:
            continue
        if resp.status_code >= 400:
            resp.close()
            continue
        data = b""
        try:
            for chunk in resp.iter_content(64 * 1024):
                if stop is not None and stop.is_set():
                    break
                data += chunk
                if len(data) >= 512 * 1024:
                    break
        finally:
            resp.close()
        if data:
            return favicon_hashes(data)
    return {}


def _apply_extractors(
    rule: dict[str, Any],
    matcher_groups: dict[str, str],
    matcher_numbered: list[str],
    haystack: str,
    extractors: list[dict[str, Any]],
) -> dict[str, str]:
    """应用提取器，返回提取到的字段（version / info / product / vendor 等）。

    语义与 observer_ward 对齐：
    - ``extractors`` 里的正则会对响应（``haystack``）重新匹配，其捕获组按顺序
      映射为 ``$1`` / ``$2`` …；命名组映射为 ``$name``；
    - ``info.metadata`` 里的 ``version`` / ``info`` / ``product`` 等字段若含
      ``$1`` / ``$2`` / ``$name`` 占位符，会被替换为对应捕获值；
    - 若没有提取器，则退回到匹配器（matcher 正则）自身捕获的组做替换。
    """
    out: dict[str, str] = {}
    info_meta = rule.get("info", {}) or {}
    metadata = info_meta.get("metadata", {}) or {}

    # 收集所有可用的替换组：提取器组优先，其次匹配器组
    named: dict[str, str] = dict(matcher_groups)
    numbered: list[str] = list(matcher_numbered)

    for extractor in extractors:
        if not isinstance(extractor, dict):
            continue
        name = extractor.get("name") or ""
        if not name:
            continue
        if extractor.get("type") != "regex":
            continue  # json 提取器需要 jsonpath，暂不支持
        regexes = extractor.get("regex") or []
        if not regexes:
            continue
        try:
            m = re.search(str(regexes[0]), haystack, re.I | re.S)
        except re.error:
            continue
        if not m:
            continue
        # 提取器命中后：其组成为新的替换来源（覆盖匹配器组）
        named = {k: v for k, v in m.groupdict().items() if v is not None}
        numbered = list(m.groups())
        out[name] = (numbered[0] if numbered and numbered[0] is not None
                     else (named.get(name) or ""))

    def sub(text: str) -> str:
        result = str(text)
        for key, value in named.items():
            result = result.replace("$" + key, str(value))
        for i, value in enumerate(numbered, start=1):
            if value is not None:
                result = result.replace(f"${i}", str(value))
        return result

    # 优先 metadata 里的标准字段（version / info / product / vendor）
    for key in ("version", "info", "product", "vendor"):
        if key in metadata and key not in out:
            out[key] = sub(str(metadata[key]))
    return out


# ---------------------------------------------------------------------------
# 规则匹配核心
# ---------------------------------------------------------------------------
def _match_rule(
    rule: dict[str, Any],
    base: str,
    headers: dict[str, str],
    body: str,
    favicon: dict[str, str],
    url: str,
    session: requests.Session,
    timeout: float,
    stop: threading.Event | None,
) -> FingerprintMatch | None:
    """对单条规则做匹配，命中返回 FingerprintMatch，否则 None。"""

    info_meta = (rule.get("info", {}) or {}).get("metadata", {}) or {}
    match_id = str(rule.get("id") or "")
    match_name = str((rule.get("info", {}) or {}).get("name") or match_id or "未知")
    vendor = str(info_meta.get("vendor") or "")
    product = str(info_meta.get("product") or "")

    # 收集该规则全部探针下的 matchers
    probes = rule.get("http") or rule.get("probe") or []
    if isinstance(probes, dict):
        probes = [probes]

    for probe in probes:
        if stop is not None and stop.is_set():
            return None
        if not isinstance(probe, dict):
            continue
        matchers = probe.get("matchers") or []
        if not matchers:
            continue
        # 该探针的请求路径：默认 '/'；若指定了 path 且非首页，需额外发请求
        paths = probe.get("path") or ["/"]
        if not isinstance(paths, (list, tuple)):
            paths = [str(paths)]

        probe_headers = dict(headers)
        probe_body = body
        probe_url = url
        probe_favicon = favicon
        # 若探针指定了非 '/' 路径，额外请求一次（替换 body / headers）
        extra_paths = [p for p in paths if p not in ("", "/")]
        if extra_paths:
            extra_url = urllib.parse.urljoin(base, extra_paths[0])
            try:
                resp = session.get(extra_url, timeout=timeout, verify=False)
                probe_url = resp.url
                probe_headers = dict(resp.headers)
                probe_body = resp.text
            except requests.RequestException:
                continue

        # 供提取器正则重新匹配的响应文本（响应头 + 正文）
        probe_haystack = ("\n".join(f"{k}: {v}" for k, v in probe_headers.items())
                          + "\n\n" + probe_body)
        # 提取器可能在探针下，也可能在规则顶层，二者都兼容
        probe_extractors = (probe.get("extractors") or rule.get("extractors") or [])

        for matcher in matchers:
            if not isinstance(matcher, dict):
                continue
            mtype = matcher.get("type") or "word"
            negative = bool(matcher.get("negative", False))
            condition = (matcher.get("condition") or "or").lower()

            if mtype == "favicon":
                hashes = matcher.get("hash") or []
                for h in hashes:
                    h = str(h).strip()
                    if h in (favicon.get("mmh3", ""), favicon.get("md5", "")):
                        return _build_match(
                            match_id, match_name, vendor, product, info_meta,
                            "favicon", f"favicon hash {h}", probe_url, rule,
                            haystack=probe_haystack, extractors=probe_extractors)
                continue

            if mtype == "regex":
                patterns = matcher.get("regex") or []
                part = matcher.get("part") or "body"
                ok, snippet, groups, numbered = _match_regex(
                    patterns, part, probe_headers, probe_body)
                if negative:
                    ok = not ok
                if ok:
                    return _build_match(
                        match_id, match_name, vendor, product, info_meta,
                        "regex", snippet, probe_url, rule,
                        groups=groups, numbered=numbered,
                        haystack=probe_haystack, extractors=probe_extractors)
                continue

            # word 匹配（默认）
            words = matcher.get("words") or []
            if not words:
                continue
            part = matcher.get("part") or "body"
            case_insensitive = bool(matcher.get("case-insensitive", False))
            if condition == "and":
                ok_all = True
                for word in words:
                    one, _ = _match_word(
                        [word], part, probe_headers, probe_body, case_insensitive)
                    if not one:
                        ok_all = False
                        break
                if (not negative and ok_all) or (negative and not ok_all):
                    return _build_match(
                        match_id, match_name, vendor, product, info_meta,
                        "word", " AND ".join(str(w) for w in words)[:EVIDENCE_MAX],
                        probe_url, rule, haystack=probe_haystack,
                        extractors=probe_extractors)
            else:
                ok, snippet = _match_word(
                    words, part, probe_headers, probe_body, case_insensitive)
                if negative:
                    ok = not ok
                if ok:
                    return _build_match(
                        match_id, match_name, vendor, product, info_meta,
                        "word", snippet, probe_url, rule,
                        haystack=probe_haystack, extractors=probe_extractors)

    return None


def _build_match(
    match_id: str,
    match_name: str,
    vendor: str,
    product: str,
    metadata: dict[str, Any],
    match_type: str,
    evidence: str,
    url: str,
    rule: dict[str, Any],
    groups: dict[str, str] | None = None,
    numbered: list[str] | None = None,
    haystack: str = "",
    extractors: list[dict[str, Any]] | None = None,
) -> FingerprintMatch:
    """组装 FingerprintMatch，应用提取器填充 version / info。

    ``haystack`` 为 ``Header: Value`` 拼接后的响应文本（含响应头与正文），
    供提取器正则重新匹配以提取版本号等字段。``extractors`` 为该探针（或规则）
    下声明的提取器列表。
    """
    info_meta = (rule.get("info", {}) or {})
    tags = str(info_meta.get("tags") or "").split(",")
    tags = [t.strip() for t in tags if t.strip()]

    extracted = _apply_extractors(
        rule, groups or {}, numbered or [], haystack, extractors or [])

    match = FingerprintMatch(
        id=match_id,
        name=match_name,
        vendor=vendor,
        product=product,
        version=extracted.get("version", ""),
        info=extracted.get("info", ""),
        tags=tags,
        evidence=evidence,
        match_type=match_type,
        url=url,
    )
    # 提取器没给出版本时，回退 metadata 里的静态 version
    if not match.version:
        match.version = str(metadata.get("version") or "")
    if not match.info:
        match.info = str(metadata.get("info") or "")
    return match


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def run(
    target: str,
    timeout: float = DEFAULT_TIMEOUT,
    rules: list[dict[str, Any]] | None = None,
    log: LogFn | None = None,
    stop: threading.Event | None = None,
) -> dict[str, Any]:
    """对 ``target`` 做指纹探测，返回结构化结果 dict。

    参数
    ----
    target    目标 URL（可省略协议头）
    timeout   单次请求超时（秒）
    rules     指纹规则列表；缺省时自动加载内置 ``dict/fingerprints``
    log       逐行日志回调
    stop      置位后尽快停止，已匹配到的结果仍会返回
    """
    import time

    emit = log or (lambda _msg: None)
    started = time.time()
    base = _normalize_url(target)

    if rules is None:
        rules = load_rules()
    load_errors: list[str] = []
    clean_rules: list[dict[str, Any]] = []
    for rule in rules:
        if isinstance(rule, dict) and "_load_errors" in rule:
            load_errors.extend(rule["_load_errors"])
        elif isinstance(rule, dict):
            clean_rules.append(rule)

    emit(f"[目标] {base}")
    emit(f"[规则] 加载 {len(clean_rules)} 条指纹规则"
         + (f"，{len(load_errors)} 条加载失败" if load_errors else ""))

    session = _session()
    matches: list[FingerprintMatch] = []
    response: requests.Response | None = None
    try:
        emit("[请求] 抓取主页…")
        try:
            response = session.get(base, timeout=timeout, verify=False,
                                   allow_redirects=True, stream=True)
        except requests.RequestException as exc:
            raise FingerprintConnectionError(_describe_error(exc)) from exc

        final_url = response.url
        status = response.status_code
        headers = dict(response.headers)

        body_bytes = b""
        try:
            for chunk in response.iter_content(64 * 1024):
                if stop is not None and stop.is_set():
                    break
                body_bytes += chunk
                if len(body_bytes) >= READ_LIMIT:
                    break
        finally:
            response.close()

        body = _decode(body_bytes)
        emit(f"[响应] {status} {final_url}，正文 {len(body_bytes)} 字节")

        favicon = _resolve_favicon(session, base, body, timeout, stop)
        if favicon:
            emit(f"[favicon] mmh3={favicon['mmh3']} md5={favicon['md5']}")
        else:
            emit("[favicon] 未获取到 favicon（不影响关键词 / 正则匹配）")

        for i, rule in enumerate(clean_rules, start=1):
            if stop is not None and stop.is_set():
                break
            if i % 500 == 0:
                emit(f"[匹配] 已评估 {i}/{len(clean_rules)} 条规则")
            match = _match_rule(
                rule, base, headers, body, favicon, final_url,
                session, timeout, stop)
            if match is not None:
                matches.append(match)
                emit(f"[命中] {match.name}"
                     + (f" (version {match.version})" if match.version else "")
                     + f" — {match.match_type}")
    finally:
        session.close()

    result = {
        "target": base,
        "final_url": final_url,
        "status": status,
        "elapsed": round(time.time() - started, 1),
        "stopped": bool(stop is not None and stop.is_set()),
        "matches": [m.to_dict() for m in matches],
        "rules_loaded": len(clean_rules),
        "load_errors": load_errors,
    }
    emit(f"[完成] 命中 {len(matches)} 个指纹，耗时 {result['elapsed']}s")
    return result


def _decode(body: bytes) -> str:
    """把 bytes 尽力解码成文本。"""
    for encoding in ("utf-8", "gbk", "latin-1"):
        try:
            return body.decode(encoding)
        except UnicodeDecodeError:
            continue
    return body.decode("utf-8", "ignore")


# ---------------------------------------------------------------------------
# 文本报告
# ---------------------------------------------------------------------------
def to_text(result: dict[str, Any]) -> str:
    """把 :func:`run` 的结果 dict 渲染成纯文本报告（供界面展示 / 落盘）。"""
    from datetime import datetime

    lines: list[str] = []
    add = lines.append

    add("# 指纹探测报告")
    add(f"# 目标: {result.get('target', '')}")
    add(f"# 最终 URL: {result.get('final_url', '')}")
    add(f"# 状态码: {result.get('status', 0)}")
    add(f"# 时间: {datetime.now():%Y-%m-%d %H:%M:%S}")
    add(f"# 规则库: 加载 {result.get('rules_loaded', 0)} 条")
    add(f"# 命中: {len(result.get('matches') or [])} 个指纹，"
        f"耗时 {result.get('elapsed', 0)}s"
        + ("（已手动停止）" if result.get("stopped") else ""))
    add("")

    matches = result.get("matches") or []
    if not matches:
        add("（未匹配到已知指纹，可尝试加载更全的自定义规则库）")
    for i, m in enumerate(matches, start=1):
        add(f"--- 指纹 {i} ---")
        add(f"  名称: {m.get('name', '')}")
        if m.get("product") and m.get("product") != m.get("name"):
            add(f"  产品: {m.get('product', '')}")
        if m.get("vendor"):
            add(f"  厂商: {m.get('vendor', '')}")
        if m.get("version"):
            add(f"  版本: {m.get('version', '')}")
        if m.get("info"):
            add(f"  信息: {m.get('info', '')}")
        if m.get("tags"):
            add(f"  标签: {', '.join(m.get('tags') or [])}")
        add(f"  匹配: {m.get('match_type', '')}"
            + (f"（证据: {m.get('evidence', '')}）" if m.get("evidence") else ""))
        add("")

    if result.get("load_errors"):
        add("--- 规则加载告警 ---")
        for err in result["load_errors"]:
            add(f"  {err}")

    add("# 生成于 28zenro 指纹探测")
    return "\n".join(lines)


__all__ = [
    "DEFAULT_TIMEOUT",
    "BUILTIN_RULES_DIR",
    "FingerprintError",
    "FingerprintConnectionError",
    "FingerprintMatch",
    "rules_dir",
    "load_rules",
    "mmh3_hash",
    "md5_hash",
    "favicon_hashes",
    "run",
    "to_text",
]
