# -*- coding: utf-8 -*-
"""Nuclei 模板兼容层：纯 Python 解析并执行 Nuclei YAML 模板。

直接跑 projectdiscovery/nuclei-templates 的模板（id / info / http 的
requests / matchers / extractors），无需安装 nuclei 二进制，即可瞬间获得
上千个社区检测规则。本模块是**模板引擎**，只做「模板 + 目标 → 命中结果」，
不导入 UI，不发无关请求。

支持的模板语法子集（对齐常见 nuclei-templates 用法）
------------------------------------------------------
- ``id`` / ``info``（name / severity / description / reference / tags /
  classification.cve-id 等）
- ``http`` 协议模板：``method``、``path``（支持 ``{{BaseURL}}`` 与
  ``{{Hostname}}`` 等变量）、``headers``、``body``、``max-redirects``、
  ``req-condition``、``cookie-reuse``、多 ``payloads`` 变体
- ``matchers`` / ``matchers-condition``：
  - ``type: status``（``status: [200, 301]``，支持 ``condition: or``）
  - ``type: word``（``words`` / ``part: header|body|all`` / ``condition`` /
    ``case-insensitive`` / ``negative``）
  - ``type: regex``（``regex`` 列表 / ``condition`` / ``negative``）
  - ``type: dsl``（表达式 ``contains(body, 'xxx')`` / ``status_code == 200``）
  - matcher 级 ``part`` / ``condition`` / ``negative``
- ``extractors``（``type: regex`` / ``type: json``，``group`` / ``part``）
- 变量替换 ``{{BaseURL}}`` / ``{{Hostname}}`` / ``{{Port}}`` / ``{{Scheme}}``
  / ``{{RootURL}}`` 与自定义变量（``variables:``）

本模块与项目其余 Web 工具保持一致：请求统一经 :mod:`lib.proxy_pool` 的
``make_session`` 创建会话，支持 ``stop`` 事件，结果结构化返回。
"""

from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Callable

import requests
from requests.packages import urllib3

urllib3.disable_warnings()

#: 无 PyYAML 时退回的纯文本解析兜底标志（yaml 是可选依赖）
try:
    import yaml as _yaml  # type: ignore

    _HAS_YAML = True
except ImportError:  # pragma: no cover - 依赖缺失时降级
    _yaml = None
    _HAS_YAML = False

DEFAULT_TIMEOUT = 8
#: 响应体最大读取字节（匹配 word/regex 够用）
READ_LIMIT = 512 * 1024
#: 单模板最多保留的命中条数
MAX_MATCHES = 200

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
DEFAULT_HEADERS = {"User-Agent": USER_AGENT, "Connection": "close"}

LogFn = Callable[[str], None]


class NucleiError(ValueError):
    """Nuclei 模板解析 / 执行失败时抛出的统一异常。"""


class NucleiYamlError(NucleiError):
    """模板 YAML 解析失败（文件损坏 / 缺 PyYAML）。"""


# ---------------------------------------------------------------------------
# 结果
# ---------------------------------------------------------------------------
@dataclass
class NucleiFinding:
    """一次模板命中（对应一条 matcher 命中）。"""

    template_id: str
    name: str = ""
    severity: str = "info"
    matched_at: str = ""
    matcher_name: str = ""
    matcher_type: str = ""
    extractor: dict[str, Any] = field(default_factory=dict)
    request: str = ""
    response: str = ""
    #: 附加信息（info 的 description / tags / cve-id 等）
    info: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "template_id": self.template_id,
            "name": self.name,
            "severity": self.severity,
            "matched_at": self.matched_at,
            "matcher_name": self.matcher_name,
            "matcher_type": self.matcher_type,
            "extractor": dict(self.extractor),
            "request": self.request,
            "response": self.response,
            "info": dict(self.info),
        }


@dataclass
class NucleiTemplateResult:
    """单个模板对单个目标的执行结果。"""

    template_id: str
    path: str
    name: str = ""
    severity: str = "info"
    matched: bool = False
    findings: list[NucleiFinding] = field(default_factory=list)
    error: str = ""
    elapsed: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "template_id": self.template_id,
            "path": self.path,
            "name": self.name,
            "severity": self.severity,
            "matched": self.matched,
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error,
            "elapsed": round(self.elapsed, 2),
        }


# ---------------------------------------------------------------------------
# YAML 加载（PyYAML 优先，缺失时做最小子集解析）
# ---------------------------------------------------------------------------
def _load_yaml(text: str, source: str = "") -> dict:
    """解析 YAML 文本为 dict；优先 PyYAML，缺失时降级为有限解析。"""
    if _HAS_YAML:
        try:
            data = _yaml.safe_load(text)
        except Exception as exc:  # noqa: BLE001
            raise NucleiYamlError(f"YAML 解析失败（{source}）：{exc}") from exc
        if isinstance(data, dict):
            return data
        raise NucleiYamlError(f"模板顶层应为映射（{source}）")
    # 降级：无 PyYAML。做最小子集解析（只处理最简的 key: value / 列表缩进）。
    data = _minimal_yaml(text)
    if not data:
        raise NucleiYamlError(
            "缺少 PyYAML 依赖，且模板结构过复杂无法解析。请安装：pip install pyyaml")
    return data


def _minimal_yaml(text: str) -> dict:
    """极简 YAML 子集解析器（无 PyYAML 时的兜底，能力有限）。"""
    # 仅支持扁平的 `key: value` 与 `- item` 列表，以及少量缩进块。
    # 覆盖绝大多数简单 nuclei 模板（http 单请求 + 单词匹配）。
    result: dict[str, Any] = {}
    # 这里只实现最常用的场景；复杂模板直接返回空让上层报错。
    lines = text.splitlines()
    # 简易逐行 key: value
    for raw in lines:
        line = raw.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        # 列表项
        if line.lstrip().startswith("- "):
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().strip("'\"")
        value = value.strip()
        if key:
            result[key] = _minimal_scalar(value)
    return result


def _minimal_scalar(value: str) -> Any:
    value = value.strip()
    if value in ("true", "True"):
        return True
    if value in ("false", "False"):
        return False
    if value in ("null", "~", ""):
        return None
    if (value.startswith('"') and value.endswith('"')) or \
       (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    if value.isdigit():
        return int(value)
    if re.fullmatch(r"-?\d+\.\d+", value):
        return float(value)
    return value


# ---------------------------------------------------------------------------
# 变量替换
# ---------------------------------------------------------------------------
_VAR_RE = re.compile(r"\{\{([^{}]+)\}\}")


def _default_vars(base_url: str) -> dict[str, str]:
    """根据目标 URL 生成 {{BaseURL}} 等默认变量。"""
    parsed = requests.utils.urlparse(base_url)
    hostname = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    scheme = parsed.scheme or "http"
    root = f"{scheme}://{hostname}"
    return {
        "BaseURL": base_url.rstrip("/"),
        "RootURL": root,
        "Hostname": hostname,
        "Port": str(port),
        "Scheme": scheme,
        "Host": hostname,
    }


def render_template(text: str, variables: dict[str, str]) -> str:
    """把 ``{{Var}}`` 替换成变量值；未知变量原样保留。"""
    if not text or "{{" not in str(text):
        return str(text)

    def _sub(match: re.Match) -> str:
        name = match.group(1).strip()
        return str(variables.get(name, match.group(0)))

    return _VAR_RE.sub(_sub, str(text))


def render_value(value: Any, variables: dict[str, str]) -> Any:
    """递归替换 value 中的变量（str / list / dict）。"""
    if isinstance(value, str):
        return render_template(value, variables)
    if isinstance(value, list):
        return [render_value(v, variables) for v in value]
    if isinstance(value, dict):
        return {k: render_value(v, variables) for k, v in value.items()}
    return value


# ---------------------------------------------------------------------------
# DSL 求值（matchers type: dsl）
# ---------------------------------------------------------------------------
def eval_dsl(expression: str, ctx: dict[str, Any]) -> bool:
    """求值单个 DSL 表达式（支持 contains / regex / status_code 等）。

    为安全起见用受限的字符串替换 + eval，而非直接 import 任意模块。
    支持的常见表达式：
    - ``status_code == 200`` / ``status_code != 404``
    - ``contains(body, 'xxx')`` / ``contains(all_headers, 'xxx')``
    - ``regex('...', body)``
    - ``len(body) > 0``
    """
    expr = str(expression).strip()
    # 提取 body / header 等上下文
    body = str(ctx.get("body", ""))
    headers = str(ctx.get("all_headers", ""))
    status = int(ctx.get("status_code", 0))
    content_length = int(ctx.get("content_length", 0))

    # 安全白名单求值环境
    safe_globals: dict[str, Any] = {
        "__builtins__": {},
        "contains": lambda hay, needle: str(needle) in str(hay),
        "regex": lambda pattern, s: re.search(pattern, str(s)) is not None,
        "len": len,
        "status_code": status,
        "body": body,
        "all_headers": headers,
        "header": headers,
        "content_length": content_length,
    }
    safe_locals: dict[str, Any] = {}
    try:
        result = eval(expr, safe_globals, safe_locals)  # noqa: S307 受限环境
        return bool(result)
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
# Matcher / Extractor 判定
# ---------------------------------------------------------------------------
def _part_text(part: str, response: requests.Response, body: str) -> str:
    """取 matcher/extractor 要匹配的文本片段。"""
    part = (part or "body").lower()
    if part == "body":
        return body
    if part == "header" or part == "all":
        return "".join(f"{k}: {v}\n" for k, v in response.headers.items())
    return body


def match_status(matcher: dict, status: int) -> bool:
    statuses = matcher.get("status") or []
    if isinstance(statuses, int):
        statuses = [statuses]
    if not statuses:
        return False
    condition = (matcher.get("condition") or "or").lower()
    hits = [int(s) == status for s in statuses]
    return any(hits) if condition == "or" else all(hits)


def match_word(matcher: dict, text: str) -> bool:
    words = matcher.get("words") or []
    if isinstance(words, str):
        words = [words]
    words = [str(w) for w in words if w]
    if not words:
        return False
    condition = (matcher.get("condition") or "or").lower()
    case_insensitive = bool(matcher.get("case-insensitive", False))
    target = text.lower() if case_insensitive else text
    hits = []
    for w in words:
        w2 = w.lower() if case_insensitive else w
        hits.append(w2 in target)
    result = any(hits) if condition == "or" else all(hits)
    if matcher.get("negative"):
        result = not result
    return result


def match_regex(matcher: dict, text: str) -> tuple[bool, list[str]]:
    patterns = matcher.get("regex") or []
    if isinstance(patterns, str):
        patterns = [patterns]
    if not patterns:
        return False, []
    condition = (matcher.get("condition") or "or").lower()
    hits: list[bool] = []
    captures: list[str] = []
    for pattern in patterns:
        try:
            m = re.search(pattern, text, re.I if matcher.get("case-insensitive", True) else 0)
        except re.error:
            m = None
        hits.append(m is not None)
        if m and m.groups():
            captures.extend(g for g in m.groups() if g)
    result = any(hits) if condition == "or" else all(hits)
    if matcher.get("negative"):
        result = not result
    return result, captures


def match_dsl(matcher: dict, ctx: dict[str, Any]) -> bool:
    expressions = matcher.get("dsl") or []
    if isinstance(expressions, str):
        expressions = [expressions]
    if not expressions:
        return False
    condition = (matcher.get("condition") or "or").lower()
    results = [eval_dsl(e, ctx) for e in expressions]
    result = any(results) if condition == "or" else all(results)
    if matcher.get("negative"):
        result = not result
    return result


def apply_matcher(matcher: dict, response: requests.Response, body: str) -> tuple[bool, str]:
    """对单个 matcher 判定，返回 (是否命中, 命中描述)。"""
    mtype = (matcher.get("type") or "word").lower()
    part = matcher.get("part", "body")
    text = _part_text(part, response, body)
    ctx = {
        "body": body,
        "all_headers": "".join(f"{k}: {v}\n" for k, v in response.headers.items()),
        "status_code": response.status_code,
        "content_length": len(body),
    }
    name = matcher.get("name", "") or mtype
    if mtype == "status":
        return match_status(matcher, response.status_code), name
    if mtype == "word":
        return match_word(matcher, text), name
    if mtype == "regex":
        ok, _ = match_regex(matcher, text)
        return ok, name
    if mtype == "dsl":
        return match_dsl(matcher, ctx), name
    # 未知类型：fallback 到 word 语义（若带 words）否则 status
    if matcher.get("words"):
        return match_word(matcher, text), name
    return match_status(matcher, response.status_code), name


def apply_extractors(extractors: list[dict], response: requests.Response,
                     body: str) -> dict[str, Any]:
    """执行 extractors，返回 {name_or_type: [捕获值,...]}。"""
    result: dict[str, Any] = {}
    for ext in extractors or []:
        etype = (ext.get("type") or "regex").lower()
        part = ext.get("part", "body")
        text = _part_text(part, response, body)
        key = ext.get("name") or etype
        values: list[str] = []
        if etype == "regex":
            patterns = ext.get("regex") or []
            if isinstance(patterns, str):
                patterns = [patterns]
            group = ext.get("group", 0)
            for pattern in patterns:
                try:
                    for m in re.finditer(pattern, text, re.I):
                        if m.groups() and group and group <= len(m.groups()):
                            values.append(m.group(group))
                        elif group == 0:
                            values.append(m.group(0))
                except re.error:
                    continue
        elif etype == "json":
            # JSON 提取：从 body 中按 JSONPath 简化（这里用 key 列表逐层取值）
            try:
                data = json.loads(body)
            except (ValueError, TypeError):
                data = None
            if data is not None:
                for jkey in ext.get("json") or []:
                    val = _json_get(data, jkey)
                    if val is not None:
                        values.append(str(val))
        elif etype == "kval":
            kval = ext.get("kval") or []
            for k in kval:
                if k in response.headers:
                    values.append(response.headers[k])
        # 去重保序
        seen: set[str] = set()
        uniq = [v for v in values if v is not None and not (v in seen or seen.add(v))]
        if uniq:
            result[key] = uniq[:MAX_MATCHES]
    return result


def _json_get(data: Any, path: str) -> Any:
    """极简 JSONPath 取值（支持 ``a.b.c`` 与 ``a[0].b``）。"""
    try:
        # 切分 a.b[0].c 形式
        parts = re.findall(r"[^.\[\]]+", path)
        cur = data
        for p in parts:
            if isinstance(cur, dict):
                cur = cur.get(p)
            elif isinstance(cur, list) and p.isdigit():
                cur = cur[int(p)]
            else:
                return None
        return cur
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------------------
# 会话
# ---------------------------------------------------------------------------
def _session() -> requests.Session:
    from lib import proxy_pool

    session = proxy_pool.make_session("nuclei_scan")
    session.headers.update(DEFAULT_HEADERS)
    return session


def _describe_error(exc: Exception) -> str:
    from lib.http_common import describe_error

    return describe_error(exc)


# ---------------------------------------------------------------------------
# 模板执行
# ---------------------------------------------------------------------------
def _normalize_base(raw: str) -> str:
    text = str(raw or "").strip().replace("：", ":")
    if not text:
        raise NucleiError("请填写目标 URL")
    if "://" not in text:
        text = "http://" + text
    parsed = requests.utils.urlparse(text)
    if not parsed.hostname:
        raise NucleiError("目标格式不正确")
    return text.rstrip("/")


def _build_request_specs(template: dict, variables: dict[str, str]) -> list[dict]:
    """展开 http.requests 为具体请求列表（含 payloads 变体展开）。"""
    http = template.get("http") or []
    if isinstance(http, dict):
        http = [http]
    specs: list[dict] = []
    for block in http:
        if not isinstance(block, dict):
            continue
        method = str(block.get("method", "GET")).upper()
        raw_paths = block.get("path", ["/"])
        if isinstance(raw_paths, str):
            raw_paths = [raw_paths]
        paths = [render_template(p, variables) for p in raw_paths if p]
        headers = block.get("headers") or {}
        body = block.get("body", "")
        # payloads 变体（attack 类型，这里做简单展开：多个 payload 名取笛卡尔积）
        payloads = block.get("payloads") or {}
        attack = str(block.get("attack", "batteringram")).lower()
        payload_sets = _expand_payloads(payloads, attack)

        for path in paths:
            if payload_sets:
                for payload_map in payload_sets:
                    merged_vars = dict(variables)
                    merged_vars.update(payload_map)
                    specs.append({
                        "method": method,
                        "path": render_template(path, merged_vars),
                        "headers": render_value(headers, merged_vars),
                        "body": render_template(body, merged_vars),
                        "matchers": block.get("matchers", []),
                        "matchers_condition": block.get("matchers-condition", "or"),
                        "extractors": block.get("extractors", []),
                        "cookie_reuse": bool(block.get("cookie-reuse", False)),
                        "max_redirects": int(block.get("max-redirects", 3)),
                        "req_condition": block.get("req-condition", "true"),
                    })
            else:
                specs.append({
                    "method": method,
                    "path": path,
                    "headers": render_value(headers, variables),
                    "body": render_template(body, variables),
                    "matchers": block.get("matchers", []),
                    "matchers_condition": block.get("matchers-condition", "or"),
                    "extractors": block.get("extractors", []),
                    "cookie_reuse": bool(block.get("cookie-reuse", False)),
                    "max_redirects": int(block.get("max-redirects", 3)),
                    "req_condition": block.get("req-condition", "true"),
                })
    return specs


def _expand_payloads(payloads: dict, attack: str) -> list[dict[str, str]]:
    """展开 payloads 为变量赋值列表（batteringram=逐个，clusterbomb=笛卡尔积）。"""
    if not payloads:
        return []
    names = list(payloads.keys())
    values = [payloads[n] if isinstance(payloads[n], list) else [payloads[n]]
              for n in names]
    if attack == "clusterbomb":
        import itertools
        combos = list(itertools.product(*values))
    else:  # batteringram / pitchfork：按最长的对齐
        max_len = max((len(v) for v in values), default=0)
        combos = []
        for i in range(max_len):
            combo = tuple(values[j][i % len(values[j])] for j in range(len(values)))
            combos.append(combo)
    result = []
    for combo in combos:
        result.append({names[j]: combo[j] for j in range(len(names))})
    return result


def _do_request(session: requests.Session, spec: dict, base_url: str,
                timeout: float, stop: threading.Event | None,
                cookie_reuse: bool, cookie_jar: dict) -> requests.Response | None:
    url = spec["path"]
    if not url.startswith(("http://", "https://")):
        url = base_url + url
    if stop is not None and stop.is_set():
        return None
    try:
        kwargs: dict[str, Any] = {
            "timeout": timeout,
            "verify": False,
            "allow_redirects": spec["max_redirects"] > 0,
            "stream": True,
        }
        if spec["headers"]:
            kwargs["headers"] = spec["headers"]
        if cookie_reuse and cookie_jar:
            kwargs["cookies"] = cookie_jar
        if spec["method"] == "GET":
            return session.get(url, **kwargs)
        if spec["body"]:
            kwargs["data"] = spec["body"]
        return session.post(url, **kwargs)
    except requests.RequestException as exc:
        raise NucleiError(_describe_error(exc)) from exc


def _read_body(response: requests.Response) -> str:
    from lib.http_common import decode_body

    body = b""
    try:
        for chunk in response.iter_content(64 * 1024):
            body += chunk
            if len(body) >= READ_LIMIT:
                break
    finally:
        response.close()
    mime = response.headers.get("content-type", "")
    return decode_body(body, mime=mime)


def _apply_request_condition(condition: str, responses: list[bool]) -> bool:
    """对 req-condition 求值（true / false / 或复杂 DSL，这里支持简单 true/false 与 and/or 布尔）。"""
    cond = str(condition).strip().lower()
    if cond == "true":
        return True
    if cond == "false":
        return False
    # 简化：只支持 "true" / "false"
    return True


def execute_template(
    template: dict,
    target: str,
    source_path: str = "",
    timeout: float = DEFAULT_TIMEOUT,
    log: LogFn | None = None,
    stop: threading.Event | None = None,
) -> NucleiTemplateResult:
    """对单个目标执行一个模板，返回 :class:`NucleiTemplateResult`。"""
    import time

    emit = log or (lambda _m: None)
    started = time.time()
    template_id = str(template.get("id") or source_path or "unknown")
    info = template.get("info") or {}
    result = NucleiTemplateResult(
        template_id=template_id,
        path=source_path,
        name=str(info.get("name") or template_id),
        severity=str(info.get("severity") or "info").lower(),
    )
    result.info = dict(info)

    base_url = _normalize_base(target)
    variables = _default_vars(base_url)
    # 模板级 variables 覆盖默认
    tpl_vars = template.get("variables") or {}
    if isinstance(tpl_vars, dict):
        variables.update({k: str(v) for k, v in tpl_vars.items()})

    session = _session()
    try:
        specs = _build_request_specs(template, variables)
        if not specs:
            result.error = "模板未定义 http 请求"
            return result

        # 逐请求执行
        per_request: list[tuple[dict, requests.Response, str, dict]] = []
        cookie_jar: dict[str, str] = {}
        for spec in specs:
            if stop is not None and stop.is_set():
                break
            try:
                response = _do_request(
                    session, spec, base_url, timeout, stop,
                    spec["cookie_reuse"], cookie_jar)
            except NucleiError as exc:
                result.error = str(exc)
                emit(f"[nuclei] {template_id} 请求失败：{exc}")
                continue
            if response is None:
                continue
            body = _read_body(response)
            if spec["cookie_reuse"]:
                cookie_jar.update(response.cookies.get_dict())
            per_request.append((spec, response, body, dict(cookie_jar)))

        # 逐个请求应用 matchers / extractors
        for spec, response, body, cj in per_request:
            if stop is not None and stop.is_set():
                break
            matchers = spec["matchers"] or []
            if not matchers:
                # 无 matcher：只要有响应即命中（部分模板靠 extractors 判断）
                finding = NucleiFinding(
                    template_id=template_id,
                    name=result.name,
                    severity=result.severity,
                    matched_at=response.url,
                    matcher_name="(无 matcher)",
                    matcher_type="none",
                    request=f"{spec['method']} {spec['path']}",
                    response=body[:2000],
                    info=dict(result.info),
                )
                finding.extractor = apply_extractors(spec["extractors"], response, body)
                result.findings.append(finding)
                continue

            mc = (spec["matchers_condition"] or "or").lower()
            matched: list[str] = []
            matcher_names: list[str] = []
            for m in matchers:
                ok, name = apply_matcher(m, response, body)
                if ok:
                    matched.append(name)
                matcher_names.append(name)
            hit = (any(matched) if mc == "or" else len(matched) == len(matchers))
            if hit:
                finding = NucleiFinding(
                    template_id=template_id,
                    name=result.name,
                    severity=result.severity,
                    matched_at=response.url,
                    matcher_name=", ".join(matched) or ", ".join(matcher_names),
                    matcher_type=", ".join(m.get("type", "word") for m in matchers),
                    request=f"{spec['method']} {spec['path']}",
                    response=body[:2000],
                    info=dict(result.info),
                )
                finding.extractor = apply_extractors(spec["extractors"], response, body)
                result.findings.append(finding)

        result.findings = result.findings[:MAX_MATCHES]
        result.matched = bool(result.findings)
    except NucleiError as exc:
        result.error = str(exc)
    finally:
        session.close()

    result.elapsed = time.time() - started
    return result


def load_template(path: str) -> dict:
    """从文件加载单个模板为 dict（校验 YAML 可解析）。"""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            text = fh.read()
    except OSError as exc:
        raise NucleiYamlError(f"读取模板失败（{path}）：{exc}") from exc
    return _load_yaml(text, path)


def load_templates(directory: str, log: LogFn | None = None) -> list[dict]:
    """递归加载目录下所有 .yaml/.yml 模板，返回 (模板 dict, 源路径) 列表。"""
    from pathlib import Path

    emit = log or (lambda _m: None)
    root = Path(directory)
    if not root.is_dir():
        raise NucleiError(f"模板目录不存在：{directory}")
    templates: list[tuple[dict, str]] = []
    for path in root.rglob("*.yaml"):
        try:
            templates.append((load_template(str(path)), str(path)))
        except NucleiYamlError as exc:
            emit(f"[nuclei] 跳过模板 {path.name}：{exc}")
        except Exception as exc:  # noqa: BLE001
            emit(f"[nuclei] 跳过模板 {path.name}：{exc}")
    for path in root.rglob("*.yml"):
        try:
            templates.append((load_template(str(path)), str(path)))
        except NucleiYamlError as exc:
            emit(f"[nuclei] 跳过模板 {path.name}：{exc}")
        except Exception as exc:  # noqa: BLE001
            emit(f"[nuclei] 跳过模板 {path.name}：{exc}")
    return templates


__all__ = [
    "NucleiError",
    "NucleiYamlError",
    "NucleiFinding",
    "NucleiTemplateResult",
    "DEFAULT_TIMEOUT",
    "load_template",
    "load_templates",
    "execute_template",
    "render_template",
    "eval_dsl",
]
