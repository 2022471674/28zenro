# -*- coding: utf-8 -*-
"""HTTP 请求器（类 Burp Repeater / Intruder；不抓包，只发请求）。

面向 CTF 密码学题：接口参数常常是加密后的密文（Base64 / HEX / 哈希 …），
需要「换一个密文就发一次请求」看响应差异。本模块把这件事拆成两层：

1. **请求构造**：方法 / URL / 查询参数 / 请求头 / 请求体（表单、JSON、原始文本）
   都能逐条自定义；重复键也算不同参数（``a=1&a=2`` 是两条）。
2. **载荷注入**（其余部分不变，只换载荷位置）：

   - **常量模式**（:data:`MODE_CONST`）：原样发一次，``{{payload}}`` 换成给定值。
   - **循环模式**（:data:`MODE_LOOP`）：多位置同时替换，按四种攻击类型组合
     （语义对齐 Burp Intruder）：

     ===============  =========================================  ==================
     攻击类型          组合方式                                    请求总数
     ===============  =========================================  ==================
     ``sniper``       每个位置轮流注入，其它位置取默认值          位置数 × 载荷数
     ``batteringram`` 所有位置注入同一个载荷值                     载荷数
     ``pitchfork``    各位置按各自列表并行推进，短的耗尽即停        最短列表长度
     ``clusterbomb``  各位置列表取笛卡尔积                        各列表长度之积
     ===============  =========================================  ==================

**关于「URL 有时会被编码」**（本模块最关键的实现细节）：请求行 / 请求头 /
请求体全部由本模块**自己拼装**，再交给 ``requests`` 原样发送。若走
``requests`` 的 ``params=dict`` / ``data=dict`` / ``json=dict``，它会**再编码
一遍**——已经 Base64 / URL 编码过的密文会被二次转义（``+`` → ``%2B``、
``=`` → ``%3D``），服务器解出来就是错的。因此：

- 载荷位置上的值**按字面原样送达**，绝不被再编码；
- 非占位符部分（如手写的 ``a b``）只做最小限度 URL 安全化：空格、非 ASCII、
  ``"`` ``<`` ``>`` ``\\`` ``^`` ``|`` ``{`` ``}`` 与反引号、控制字符会编码；
  ``% + = & / : ? @ ; , $ ! ' ( ) * [ ] ~ - . _`` 等 URL 合法字符一律保留，
  不会破坏已编码的字符串。

于是「复制 Burp 里的报文直接贴进来发」也能得到同样的字节。

实现上先在模板里把占位符换成唯一记号，再做最小安全化，最后把载荷原样换回
记号位置——这样「该编码的编码、不该动的绝不动」是结构性保证，而不是靠拼字符串
时的小心。

请求统一走全局代理池（:func:`lib.proxy_pool.make_session`），与项目其它 Web
工具保持一致。本模块只做纯逻辑，不导入任何 UI 模块。
"""

from __future__ import annotations

import itertools
import json
import re
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Sequence

import requests
from requests.packages import urllib3

urllib3.disable_warnings()

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
#: 载荷模式：常量（发一次） / 循环（批量攻击）
MODE_CONST = "const"
MODE_LOOP = "loop"
MODES: tuple[str, ...] = (MODE_CONST, MODE_LOOP)

MODE_LABELS: dict[str, str] = {
    MODE_CONST: "常量模式（只发一次）",
    MODE_LOOP: "循环模式（批量 Attack）",
}

#: 攻击类型（语义对齐 Burp Intruder）
ATTACK_SNIPER = "sniper"
ATTACK_BATTERINGRAM = "batteringram"
ATTACK_PITCHFORK = "pitchfork"
ATTACK_CLUSTERBOMB = "clusterbomb"
ATTACKS: tuple[str, ...] = (
    ATTACK_SNIPER, ATTACK_BATTERINGRAM, ATTACK_PITCHFORK, ATTACK_CLUSTERBOMB,
)

ATTACK_LABELS: dict[str, str] = {
    ATTACK_SNIPER: "Sniper 狙击手：逐位置轮流注入，其余取默认值",
    ATTACK_BATTERINGRAM: "Battering ram 攻城锤：所有位置同一个值",
    ATTACK_PITCHFORK: "Pitchfork 草叉：各位置各自列表并行推进",
    ATTACK_CLUSTERBOMB: "Cluster bomb 集束炸弹：各位置列表笛卡尔积",
}

ATTACK_HINTS: dict[str, str] = {
    ATTACK_SNIPER: "适合「只有一处密文在变」：每个位置各跑一遍全部载荷。",
    ATTACK_BATTERINGRAM: "适合同一密钥 / 同一密文要同时填进多处（如签名 + 参数）。",
    ATTACK_PITCHFORK: "适合成对数据（user1+pass1、user2+pass2），按行对齐。",
    ATTACK_CLUSTERBOMB: "组合穷举；请求数 = 各位置载荷数相乘，注意规模。",
}

#: 下拉框用的短标签（完整说明见 :data:`ATTACK_LABELS`），窄窗口下不会把行撑开
ATTACK_SHORT_LABELS: dict[str, str] = {
    ATTACK_SNIPER: "Sniper 狙击手",
    ATTACK_BATTERINGRAM: "Battering ram 攻城锤",
    ATTACK_PITCHFORK: "Pitchfork 草叉",
    ATTACK_CLUSTERBOMB: "Cluster bomb 集束",
}

#: 请求方法（也允许自由填写任意方法）
METHODS: tuple[str, ...] = (
    "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT",
)

#: 请求体形态
BODY_NONE = "none"      # 不带请求体
BODY_FORM = "form"      # application/x-www-form-urlencoded
BODY_JSON = "json"      # application/json
BODY_TEXT = "text"      # 原始文本，Content-Type 由自定义头决定
BODY_KINDS: tuple[str, ...] = (BODY_NONE, BODY_FORM, BODY_JSON, BODY_TEXT)

BODY_LABELS: dict[str, str] = {
    BODY_NONE: "无请求体",
    BODY_FORM: "表单 x-www-form-urlencoded",
    BODY_JSON: "JSON",
    BODY_TEXT: "原始文本",
}

#: 载荷位置（固定次序，决定注入顺序与展示顺序）
LOC_QUERY = "query"
LOC_HEADER = "header"
LOC_BODY = "body"
LOC_URL = "url"
LOCATIONS: tuple[str, ...] = (LOC_QUERY, LOC_HEADER, LOC_BODY, LOC_URL)

LOCATION_LABELS: dict[str, str] = {
    LOC_QUERY: "查询参数",
    LOC_HEADER: "请求头",
    LOC_BODY: "请求体",
    LOC_URL: "URL 内",
}

#: 隐式位置在「按位置给载荷」时使用的统一键
IMPLICIT_KEY = "(隐式)"

DEFAULT_TIMEOUT = 15.0
DEFAULT_DELAY = 0.0
DEFAULT_RATE = 0.0
DEFAULT_WORKERS = 1
DEFAULT_REDIRECTS = False   # 与 Burp 一致：默认不跟随重定向
DEFAULT_VERIFY_TLS = False  # CTF 自签证书很常见

#: 响应正文预览上限（字节）
MAX_PREVIEW = 64 * 1024

#: URL 最小安全化要编码的字符（其余可打印 ASCII 原样保留）
_URL_UNSAFE_CHARS = frozenset('\t\n\r "<>\\^`{|}')

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

LogFn = Callable[[str], None]

#: 占位符 ``{{payload}}``（容忍 ``{{ payload }}`` 这种带空格写法）
PLACEHOLDER_RE = re.compile(r"\{\{\s*payload\s*\}\}", re.IGNORECASE)

#: 模板里的载荷记号。用私用区字符包裹「位置下标」，几乎不可能与用户输入冲突：
#: ``_MARK(i)`` 表示第 i 个载荷位置，组装完再一次性换成该位置的载荷值。
_MARK_PREFIX = "\uE000"
_MARK_SUFFIX = "\uE001"


def _mark(index: int) -> str:
    """第 ``index`` 个载荷位置的记号。"""
    return f"{_MARK_PREFIX}{index}{_MARK_SUFFIX}"


_MARK_RE = re.compile(r"\uE000(\d+)\uE001")


def _mark_marks(text: str, start: int = 0) -> tuple[str, int]:
    """把文本里的 ``{{payload}}`` 依次换成记号，返回 ``(新文本, 下一个下标)``。"""
    counter = [start]

    def _sub(_match: "re.Match[str]") -> str:
        mark = _mark(counter[0])
        counter[0] += 1
        return mark

    return PLACEHOLDER_RE.sub(_sub, text), counter[0]

#: 「载荷位置键」：显式占位符第 n 个统一存到 ``KEY_ALL``，隐式位置用位置名。
KEY_ALL = "(全部占位符)"

#: ``charset=xxx`` 提取（响应体解码用）
_CHARSET_RE = re.compile(r"charset=([\w-]+)", re.IGNORECASE)


class HttpRequesterError(ValueError):
    """请求器参数 / 连接失败时抛出的统一异常。"""


# ---------------------------------------------------------------------------
# 键值条目与载荷位置
# ---------------------------------------------------------------------------
@dataclass
class Entry:
    """一条可编辑的键值对（查询参数 / 请求头 / 表单字段）。

    ``name`` 为空且位于「原始文本」请求体时，表示整行正文。
    """

    name: str = ""
    value: str = ""
    enabled: bool = True


@dataclass
class Slot:
    """一个载荷位置（Burp 里被 § 标记的片段）。"""

    location: str
    label: str
    #: 在所属位置条目列表里的下标（URL 内的占位符统一为 -1）
    entry_index: int = -1
    #: 该条目里第几个占位符（0 起）；隐式载荷点为 0
    nth: int = 0
    #: 隐式载荷点：整个值都替换（请求里没写占位符时）
    implicit: bool = False
    header: str = ""
    name: str = ""
    #: 默认值：占位符留空后的文本 / 隐式位置为空串
    default: str = ""

    @property
    def key(self) -> str:
        """按位置给载荷时用的键：显式占位符全部共用一个键。"""
        return KEY_ALL if not self.implicit else self.location

    @property
    def slot_key(self) -> str:
        """唯一的「单个载荷位置」键，供界面为每个位置单独指定载荷。"""
        if self.implicit:
            return self.location
        return f"{self.location}:{self.entry_index}:{self.nth}"

    def describe(self) -> str:
        where = LOCATION_LABELS.get(self.location, self.location)
        return f"[{where}] {self.label}"


# ---------------------------------------------------------------------------
# 结果
# ---------------------------------------------------------------------------
@dataclass
class ResponseRecord:
    """一次请求的完整结果。"""

    index: int = 0
    payloads: list[str] = field(default_factory=list)
    url: str = ""
    method: str = ""
    status: int = 0
    reason: str = ""
    elapsed_ms: float = 0.0
    length: int = 0
    mime: str = ""
    #: 实际发出的报文（含拼好的 URL / 头 / 体），便于核对有没有被再编码
    request_dump: str = ""
    response_headers: list[tuple[str, str]] = field(default_factory=list)
    preview: str = ""
    truncated: bool = False
    error: str = ""
    #: 与上一行响应相比的差异标记（界面高亮用）
    changed: dict[str, bool] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.error

    def to_dict(self) -> dict[str, Any]:
        """转 dict。

        包含 ``request_dump`` / ``response_headers`` / ``preview`` —— 界面把它
        送进显示窗口后要靠这几项渲染「响应详情」，缺了详情页就是空的。
        """
        return {
            "index": self.index,
            "payloads": list(self.payloads),
            "method": self.method,
            "url": self.url,
            "status": self.status,
            "reason": self.reason,
            "elapsed_ms": round(self.elapsed_ms, 1),
            "length": self.length,
            "mime": self.mime,
            "error": self.error,
            "changed": dict(self.changed),
            "request_dump": self.request_dump,
            "response_headers": [list(item) for item in self.response_headers],
            "preview": self.preview,
            "truncated": self.truncated,
        }


@dataclass
class AttackPlan:
    """载荷展开计划（只算不发）：供界面预览总共会发多少次请求。"""

    mode: str = MODE_CONST
    attack: str = ATTACK_SNIPER
    slots: list[Slot] = field(default_factory=list)
    payloads: list[str] = field(default_factory=list)
    #: 每个位置实际生效的载荷列表（与 ``slots`` 一一对应）
    per_slot: list[list[str]] = field(default_factory=list)
    total: int = 0
    warning: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "attack": self.attack,
            "slots": [slot.describe() for slot in self.slots],
            "slot_count": len(self.slots),
            "payload_count": len(self.payloads),
            "per_slot_counts": [len(items) for items in self.per_slot],
            "total_requests": self.total,
            "warning": self.warning,
        }


@dataclass
class AttackResult:
    """请求器一次运行的汇总结果。"""

    mode: str = MODE_CONST
    attack: str = ATTACK_SNIPER
    total: int = 0
    done: int = 0
    stopped: bool = False
    elapsed: float = 0.0
    records: list[ResponseRecord] = field(default_factory=list)
    plan: dict[str, Any] = field(default_factory=dict)
    warning: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "attack": self.attack,
            "total": self.total,
            "done": self.done,
            "stopped": self.stopped,
            "elapsed": round(self.elapsed, 1),
            "warning": self.warning,
            "plan": dict(self.plan),
            "responses": [record.to_dict() for record in self.records],
        }


# ---------------------------------------------------------------------------
# 基础工具
# ---------------------------------------------------------------------------
def parse_kv(text: str) -> list[tuple[str, str]]:
    """解析 ``a=1&b=2&flag`` → ``[("a","1"),("b","2"),("flag","")]``（重复键保留）。"""
    pairs: list[tuple[str, str]] = []
    for part in str(text or "").split("&"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            name, _, value = part.partition("=")
            pairs.append((name.strip(), value))
        else:
            pairs.append((part, ""))
    return pairs


def build_kv(pairs: Iterable[tuple[str, str]]) -> str:
    """把键值对拼回 ``a=1&b=2``（值按字面保留）。"""
    return "&".join(f"{name}={value}" if value != "" else name for name, value in pairs)


def parse_headers(text: str) -> list[tuple[str, str]]:
    """解析「每行一个 ``Key: Value``」，保留顺序与重复头。"""
    pairs: list[tuple[str, str]] = []
    for line in str(text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if ":" not in line:
            pairs.append((line.strip(), ""))
            continue
        name, _, value = line.partition(":")
        name = name.strip()
        if name:
            pairs.append((name, value.strip()))
    return pairs


def build_headers(pairs: Iterable[tuple[str, str]]) -> str:
    return "\n".join(f"{name}: {value}" for name, value in pairs)


def split_payloads(text: str) -> list[str]:
    """载荷列表：每行一个，空行忽略；不 trim（保留以空格开头的载荷）。"""
    return [line for line in
            str(text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
            if line.strip() != ""]


def has_placeholder(text: str) -> bool:
    return bool(PLACEHOLDER_RE.search(str(text or "")))


def count_placeholders(text: str) -> int:
    return len(PLACEHOLDER_RE.findall(str(text or "")))


def replace_placeholder(text: str, value: str) -> str:
    """把文本里全部 ``{{payload}}`` 换成 ``value``。"""
    return PLACEHOLDER_RE.sub(lambda _m: value, str(text or ""))


def normalize_url(raw: str, *, scheme: str = "http") -> str:
    """补协议头（缺省 ``http``）、去首尾空白、校验 host。不做任何重编码。"""
    text = str(raw or "").strip().replace("：", ":")
    if not text:
        raise HttpRequesterError("请填写目标 URL，如 https://example.com/api")
    if "://" not in text:
        text = f"{scheme}://{text}"
    parsed = urllib.parse.urlparse(text)
    if not parsed.hostname:
        raise HttpRequesterError("目标 URL 格式不正确，示例：https://example.com/api")
    return text


def url_safe(text: str) -> str:
    """只做最小必要的 URL 安全化，尽量保留已编码字符串原样。

    编码：空格 / 非 ASCII / ``"`` ``<`` ``>`` ``\\`` ``^`` ``|`` ``{`` ``}``
    反引号 / 控制字符。
    保留：``% + = & / : ? @ ; , $ ! ' ( ) * [ ] ~ - . _`` —— 这样
    ``aGVsbG8+=`` 这类密文不会被二次转义成 ``%2B%3D``。

    载荷记号（私用区字符）必须原样穿过，否则占位符会被百分号化而失效。
    """
    out: list[str] = []
    for ch in str(text or ""):
        if ch in (_MARK_PREFIX, _MARK_SUFFIX):   # 载荷记号字符一律保留
            out.append(ch)
        elif ch in _URL_UNSAFE_CHARS or ord(ch) < 0x20 or ord(ch) > 0x7E:
            out.extend(f"%{byte:02X}" for byte in ch.encode("utf-8", "surrogatepass"))
        else:
            out.append(ch)
    return "".join(out)


def describe_error(exc: Exception) -> str:
    """把 requests 异常压成一句人话（复用 :mod:`lib.http_common`）。"""
    from lib.http_common import describe_error as _describe_error

    return _describe_error(exc)


def make_session() -> requests.Session:
    """创建走全局代理池的请求会话（项目 Web 工具的统一入口）。"""
    from lib import proxy_pool

    return proxy_pool.make_session("http_requester")


# ---------------------------------------------------------------------------
# 请求规格
# ---------------------------------------------------------------------------
@dataclass
class RequestSpec:
    """一次请求的完整定义。"""

    method: str = "GET"
    url: str = ""
    query: list[Entry] = field(default_factory=list)
    headers: list[Entry] = field(default_factory=list)
    body_kind: str = BODY_NONE
    body_entries: list[Entry] = field(default_factory=list)
    timeout: float = DEFAULT_TIMEOUT
    redirects: bool = DEFAULT_REDIRECTS
    verify: bool = DEFAULT_VERIFY_TLS
    scheme: str = "http"

    # -- 便捷视图 ----------------------------------------------------------
    @property
    def active_query(self) -> list[Entry]:
        return [entry for entry in self.query if entry.enabled]

    @property
    def active_headers(self) -> list[Entry]:
        return [entry for entry in self.headers if entry.enabled]

    @property
    def active_body(self) -> list[Entry]:
        if self.body_kind == BODY_NONE:
            return []
        return [entry for entry in self.body_entries if entry.enabled]

    # -- 从 dict / 字符串构造（MCP、CLI 等非界面调用方） -------------------
    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> "RequestSpec":
        """用纯 dict 描述请求。

        ``query`` / ``body`` 可给 ``"a=1&b=2"`` 字符串或 ``{k: v}`` dict；
        ``headers`` 可给 ``"Key: Value\\nKey2: v2"`` 或 dict。
        dict 里同名键只能出现一次；要重复键（``a=1&a=2``）请用字符串写法。
        """
        def _pairs(raw: Any, parser: Callable[[str], list[tuple[str, str]]]
                   ) -> list[Entry]:
            if raw is None or raw == "":
                return []
            if isinstance(raw, dict):
                return [Entry(str(k), "" if v is None else str(v))
                        for k, v in raw.items()]
            if isinstance(raw, (list, tuple)):
                out: list[Entry] = []
                for item in raw:
                    if isinstance(item, dict):
                        out.append(Entry(
                            str(item.get("name", "")),
                            "" if item.get("value") is None else str(item["value"]),
                            bool(item.get("enabled", True))))
                    elif isinstance(item, (list, tuple)) and len(item) == 2:
                        out.append(Entry(str(item[0]), str(item[1])))
                    else:
                        out.extend(Entry(n, v) for n, v in parser(str(item)))
                return out
            return [Entry(n, v) for n, v in parser(str(raw))]

        body_raw = data.get("body")
        kind = str(data.get("body_kind") or "").strip().lower()
        if not kind:
            if body_raw in (None, ""):
                kind = BODY_NONE
            elif isinstance(body_raw, (dict, list)):
                kind = BODY_JSON
            else:
                kind = BODY_FORM
        if kind not in BODY_KINDS:
            raise HttpRequesterError(
                f"未知请求体类型：{kind}（可选 {', '.join(BODY_KINDS)}）")

        body_entries: list[Entry]
        if kind == BODY_TEXT:
            body_entries = [Entry("", "" if body_raw is None else str(body_raw))]
        elif kind == BODY_JSON and isinstance(body_raw, (dict, list)):
            # dict/list 用一行 JSON 表示：值里写 {{payload}} 同样生效
            body_entries = [Entry("", json.dumps(body_raw, ensure_ascii=False))]
        elif kind in (BODY_FORM, BODY_JSON):
            body_entries = _pairs(body_raw, parse_kv)
        else:
            body_entries = []

        return cls(
            method=(str(data.get("method") or "GET").upper().strip() or "GET"),
            url=str(data.get("url") or ""),
            query=_pairs(data.get("query"), parse_kv),
            headers=_pairs(data.get("headers"), parse_headers),
            body_kind=kind,
            body_entries=body_entries,
            timeout=float(data.get("timeout") or DEFAULT_TIMEOUT),
            redirects=bool(data.get("redirects", DEFAULT_REDIRECTS)),
            verify=bool(data.get("verify", DEFAULT_VERIFY_TLS)),
            scheme=str(data.get("scheme") or "http"),
        )

    # -- 载荷位置枚举 ------------------------------------------------------
    def slots(self) -> list[Slot]:
        """枚举全部载荷位置。次序：查询参数 → 请求头 → 请求体 → URL 内。

        规则（与 Burp 的 § 标记等价）：

        1. 请求里**存在** ``{{payload}}`` → 只有被标记的片段是载荷位置；
           同一字段写多个占位符就是多个独立位置；默认值 = 占位符留空后的文本。
        2. 请求里**没有**任何 ``{{payload}}`` → 循环模式下把所有启用的
           查询参数 / 请求头 / 表单字段的值各当作一个隐式载荷位置（整个值替换），
           省得手写占位符。
        """
        explicit = self._slots(explicit=True)
        return explicit if explicit else self._slots(explicit=False)

    def _slots(self, *, explicit: bool) -> list[Slot]:
        slots: list[Slot] = []
        for location, entries in self._slot_entries():
            for index, entry in enumerate(entries):
                if not entry.enabled:
                    continue
                for field_name, text in (("name", entry.name), ("value", entry.value)):
                    if location == LOC_URL and field_name == "name":
                        continue          # URL 虚拟条目只按整串处理
                    slots.extend(self._field_slots(location, entry, index,
                                                   field_name, text, explicit))
        return slots

    def _field_slots(self, location: str, entry: Entry, index: int,
                     field_name: str, text: str, explicit: bool) -> list[Slot]:
        if explicit:
            total = count_placeholders(text)
            if not total:
                return []
            return [Slot(location=location,
                         label=self._slot_label(location, entry, field_name, nth),
                         entry_index=index, nth=nth, implicit=False,
                         header=entry.name if field_name == "value" else "",
                         name=entry.name,
                         default=replace_placeholder(text, ""))
                    for nth in range(total)]
        if field_name == "name":
            return []                   # 隐式位置只认「值」
        if location == LOC_BODY and entry.name == "" and self.body_kind == BODY_TEXT:
            return []                   # 原始文本没有键名，无法隐式定位
        return [Slot(location=location,
                     label=self._slot_label(location, entry, field_name, 0),
                     entry_index=index, nth=0, implicit=True,
                     header=entry.name, name=entry.name, default="")]

    def _slot_entries(self) -> list[tuple[str, list[Entry]]]:
        """承载载荷位置的位置列表（URL 内有占位符时附一条虚拟条目）。"""
        out: list[tuple[str, list[Entry]]] = [
            (LOC_QUERY, list(self.query)),
            (LOC_HEADER, list(self.headers)),
            (LOC_BODY, list(self.active_body)),
        ]
        url_text = self.base_url()
        if has_placeholder(url_text):
            out.append((LOC_URL, [Entry("url", url_text)]))
        return out

    def _slot_label(self, location: str, entry: Entry, field_name: str,
                    nth: int) -> str:
        if location == LOC_BODY and entry.name == "" and self.body_kind == BODY_TEXT:
            base = "正文"
        else:
            base = entry.name or ("(空头名)" if location == LOC_HEADER else "(空参数名)")
        if field_name == "name":
            base += "[名]"
        if nth:
            base += f"#{nth + 1}"
        return base

    # -- 报文拼装 ----------------------------------------------------------
    def base_url(self) -> str:
        """规范化后的 URL（保留 URL 里自带的 query）。"""
        return normalize_url(self.url, scheme=self.scheme)

    def split_url(self) -> tuple[str, str, str]:
        """拆 ``(前缀, query, fragment)``，不做重编码。

        ``前缀`` 含 scheme / host / path，因此路径里的 ``{{payload}}`` 能被替换。
        """
        text = self.base_url()
        fragment = ""
        if "#" in text:
            text, _, fragment = text.partition("#")
        prefix, _, query = text.partition("?")
        return prefix, query, fragment

    def has_placeholder(self) -> bool:
        """请求里是否有任一处写了 ``{{payload}}``。"""
        if has_placeholder(self.url):
            return True
        for entries in (self.query, self.headers, self.body_entries):
            for entry in entries:
                if has_placeholder(entry.name) or has_placeholder(entry.value):
                    return True
        return False


# ---------------------------------------------------------------------------
# 报文组装（核心：该编码的编码，载荷绝不动）
# ---------------------------------------------------------------------------
def _render_entries(entries: list[Entry], mode: str,
                    implicit_values: dict[str, str],
                    location: str, counter: list[int]) -> list[tuple[str, str]]:
    """把条目渲染成 ``[(name, value)]``；占位符换成**按位置编号**的记号。"""
    out: list[tuple[str, str]] = []
    for index, entry in enumerate(entries):
        if not entry.enabled:
            continue
        name, counter[0] = _mark_marks(entry.name, counter[0])
        value, counter[0] = _mark_marks(entry.value, counter[0])
        if mode == "implicit":
            value = implicit_values.get(f"{location}:{index}", value)
        out.append((name, value))
    return out


def _fill_marks(text: str, values: Sequence[str]) -> str:
    """把文本里的载荷记号换成对应位置的载荷值（缺值按空串）。"""
    def _sub(match: "re.Match[str]") -> str:
        index = int(match.group(1))
        return str(values[index]) if 0 <= index < len(values) else ""

    return _MARK_RE.sub(_sub, text)


def _has_mark(text: str) -> bool:
    return bool(_MARK_RE.search(text))


def compose(spec: RequestSpec, values: Sequence[str] = ()) -> dict[str, Any]:
    """把请求规格 + 一次载荷值组装成最终报文。

    返回 ``{"method", "url", "headers", "body", "query", "request_dump"}``。
    载荷按字面进入报文；非载荷的裸文本部分做最小 URL 安全化。

    位置编号顺序与 :meth:`RequestSpec.slots` 严格一致
    （查询参数 → 请求头 → 请求体 → URL 内），因此两次 ``slots()`` 调用的
    下标天然对齐，``values[i]`` 就是第 i 个载荷位置的取值。
    """
    explicit = spec.has_placeholder()
    mode = "explicit" if explicit else "implicit"
    slots = spec.slots()
    implicit_values: dict[str, str] = {}
    if not explicit:
        for i, slot in enumerate(slots):
            if i < len(values):
                implicit_values[f"{slot.location}:{slot.entry_index}"] = str(values[i])

    prefix, url_query, fragment = spec.split_url()
    # 计数顺序必须与 slots() 一致：query → header → body → url
    counter = [0]
    query_pairs = _render_entries(spec.query, mode, implicit_values, LOC_QUERY,
                                  counter)
    header_pairs = _render_entries(spec.headers, mode, implicit_values, LOC_HEADER,
                                   counter)
    body_pairs = _render_entries(spec.body_entries, mode, implicit_values, LOC_BODY,
                                 counter)
    prefix, counter[0] = _mark_marks(prefix, counter[0])
    url_query, counter[0] = _mark_marks(url_query, counter[0])

    # ---- URL：前缀 / 原生 query / 面板 query 三段分别安全化 ----
    pieces: list[str] = []
    if url_query:
        pieces.append(url_safe(url_query))
    for name, value in query_pairs:
        if name == "" and value == "":
            continue
        rendered_name = url_safe(name)
        if value != "":
            pieces.append(f"{rendered_name}={url_safe(value)}")
        else:
            pieces.append(rendered_name)
    final_query = "&".join(pieces)
    url = url_safe(prefix)
    if final_query:
        url += "?" + final_query
    if fragment:
        url += "#" + url_safe(fragment)

    # ---- 请求体 ----
    body_text = ""
    if spec.body_kind == BODY_FORM:
        form: list[str] = []
        for name, value in body_pairs:
            if name == "" and value == "":
                continue
            rendered_name = url_safe(name)
            form.append(f"{rendered_name}={url_safe(value)}" if value != ""
                        else rendered_name)
        body_text = "&".join(form)
    elif spec.body_kind == BODY_JSON:
        if body_pairs and any(not name for name, _v in body_pairs):
            # 整行 JSON：按原样发送（已编码的密文不会被再处理）
            body_text = "\n".join(value for _n, value in body_pairs)
        elif any(_has_mark(value) or _has_mark(name) for name, value in body_pairs):
            # 键值对 + 占位符：拼 JSON 时保持值原样，不额外转义载荷
            members: list[str] = []
            for name, value in body_pairs:
                members.append(f'"{name}":"{value}"')
            body_text = "{" + ",".join(members) + "}"
        else:
            body_text = json.dumps({name: value for name, value in body_pairs},
                                   ensure_ascii=False)
    elif spec.body_kind == BODY_TEXT:
        body_text = "\n".join(value for _n, value in body_pairs)

    # ---- 最后一律把载荷记号换成字面载荷 ----
    url = _fill_marks(url, values)
    body_text = _fill_marks(body_text, values)
    header_list = [(_fill_marks(name, values), _fill_marks(value, values))
                   for name, value in header_pairs]

    return {
        "method": spec.method,
        "url": url,
        "headers": header_list,
        "body": body_text,
        "query": final_query,
        "request_dump": _dump_request(spec.method, url, header_list, body_text),
    }


def _dump_request(method: str, url: str, headers: list[tuple[str, str]],
                  body: str) -> str:
    """把要发的报文渲染成 Burp 风格的可读文本（供界面核对）。"""
    parsed = urllib.parse.urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    lines = [f"{method} {path} HTTP/1.1", f"Host: {parsed.netloc}"]
    for name, value in headers:
        if name.lower() == "host":
            continue
        lines.append(f"{name}: {value}")
    lines.append("")
    if body:
        lines.append(body)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 载荷展开（四种攻击类型）
# ---------------------------------------------------------------------------
def plan(
    spec: RequestSpec,
    *,
    mode: str = MODE_LOOP,
    attack: str = ATTACK_SNIPER,
    payloads: Sequence[str] = (),
    per_slot: Sequence[Sequence[str]] | None = None,
    per_location: dict[str, Sequence[str]] | None = None,
) -> AttackPlan:
    """计算「这次会发哪些请求」，不产生任何网络请求。

    ``payloads`` 是所有位置共用的载荷；``per_slot`` 按位置下标给各自列表，
    ``per_location`` 按位置键（``query`` / ``header`` / ``body`` / ``url`` /
    ``(隐式)``）给列表；两者都优先于 ``payloads``。
    """
    mode = str(mode or MODE_LOOP).strip().lower()
    if mode not in MODES:
        raise HttpRequesterError(f"未知载荷模式：{mode}（可选 {', '.join(MODES)}）")
    attack = str(attack or ATTACK_SNIPER).strip().lower()
    if attack not in ATTACKS:
        raise HttpRequesterError(f"未知攻击类型：{attack}（可选 {', '.join(ATTACKS)}）")

    slots = spec.slots() if mode == MODE_LOOP else []
    shared = [str(item) for item in (payloads or [])]
    arrays: list[list[str]] = []
    for i, slot in enumerate(slots):
        own: list[str] = []
        if per_slot is not None and i < len(per_slot):
            own = [str(x) for x in per_slot[i]]
        if not own and per_location:
            # 依次尝试：单个位置键 → 位置名 → 隐式统一键
            for key in (slot.slot_key, slot.location, slot.key):
                found = per_location.get(key)
                if found:
                    own = [str(x) for x in found]
                    break
        arrays.append(own or list(shared))

    result = AttackPlan(mode=mode, attack=attack, slots=slots,
                        payloads=shared, per_slot=arrays)
    if mode == MODE_CONST:
        result.total = 1
        return result
    if not slots:
        result.warning = ("没有发现载荷位置：可在参数值里写 {{payload}} 标记，"
                          "或启用参数后直接循环。")
        return result

    if attack == ATTACK_SNIPER:
        if not shared:
            result.warning = "Sniper 需要通用载荷列表。"
            return result
        result.total = len(slots) * len(shared)
    elif attack == ATTACK_BATTERINGRAM:
        if not shared:
            result.warning = "Battering ram 需要通用载荷列表。"
            return result
        result.total = len(shared)
    elif attack == ATTACK_PITCHFORK:
        lengths = [len(items) for items in arrays]
        if not arrays or not all(lengths):
            result.warning = "Pitchfork 需要每个位置都有载荷。"
            return result
        result.total = min(lengths)
        if len(set(lengths)) > 1:
            result.warning = (f"各位置载荷数不一致（{lengths}），按最短的 "
                              f"{result.total} 次推进。")
    else:  # clusterbomb
        if not all(arrays):
            result.warning = "Cluster bomb 需要每个位置都有载荷。"
            return result
        result.total = 1
        for items in arrays:
            result.total *= len(items)
    return result


def combinations(plan_obj: AttackPlan) -> list[list[str]]:
    """把计划展开成「每次请求各位置的载荷值」列表。"""
    if plan_obj.mode == MODE_CONST or not plan_obj.slots:
        return []
    slots, shared, arrays = plan_obj.slots, plan_obj.payloads, plan_obj.per_slot
    if plan_obj.attack == ATTACK_SNIPER:
        return [[p if j == i else slot.default for j, slot in enumerate(slots)]
                for i in range(len(slots)) for p in shared]
    if plan_obj.attack == ATTACK_BATTERINGRAM:
        return [[p for _ in slots] for p in shared]
    if plan_obj.attack == ATTACK_PITCHFORK:
        if not all(arrays):
            return []
        return [list(combo) for combo in zip(*arrays)]
    if not all(arrays):
        return []
    return [list(combo) for combo in itertools.product(*arrays)]


# ---------------------------------------------------------------------------
# 发送
# ---------------------------------------------------------------------------
class _Throttle:
    """线程安全限速器（固定间隔 + 每秒上限）。"""

    def __init__(self, delay: float = 0.0, rate: float = 0.0) -> None:
        self.delay = max(0.0, float(delay or 0))
        self.rate = max(0.0, float(rate or 0))
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self) -> None:
        if self.delay > 0:
            time.sleep(self.delay)
        if self.rate > 0:
            interval = 1.0 / self.rate
            with self._lock:
                now = time.time()
                if now < self._next:
                    time.sleep(self._next - now)
                    now = time.time()
                self._next = now + interval


def _coalesce_headers(pairs: Sequence[tuple[str, str]]) -> list[tuple[str, str]]:
    """把重复的同名请求头合并成一行（保持首次出现顺序，值一个不丢）。

    requests 的 headers 走大小写不敏感字典，同名头多行会被静默去重只剩
    最后一个（也发不出去 list 形式的重复头）。按 RFC 9110 §5.2 合并：
    Cookie 用 ``"; "`` 连接（RFC 6265），其余头用 ``", "`` 连接，这样
    重复的 ``Cookie`` / ``X-Forwarded-For`` 等值全部保留在请求里。
    """
    order: list[tuple[str, str]] = []
    index: dict[str, int] = {}
    for name, value in pairs:
        key = name.lower()
        if key in index:
            i = index[key]
            prev_name, prev_value = order[i]
            sep = "; " if key == "cookie" else ", "
            order[i] = (prev_name, f"{prev_value}{sep}{value}")
        else:
            index[key] = len(order)
            order.append((name, str(value)))
    return order


def send(session: requests.Session, spec: RequestSpec, values: Sequence[str] = (),
         *, index: int = 0, payloads: Sequence[str] = (),
         throttle: _Throttle | None = None) -> ResponseRecord:
    """发一次请求；异常吞进 ``record.error``（不向上抛）。"""
    if throttle is not None:
        throttle.wait()
    try:
        payload = compose(spec, values)
    except HttpRequesterError as exc:
        return ResponseRecord(index=index, payloads=[str(v) for v in payloads],
                              method=spec.method, url=spec.url, error=str(exc))

    record = ResponseRecord(index=index, payloads=[str(v) for v in payloads],
                            url=payload["url"], method=spec.method)
    header_pairs = _coalesce_headers(payload["headers"])
    headers = dict(header_pairs)
    lower = {name.lower() for name in headers}
    # 只在用户没指定 Content-Type 时补默认值（绝不覆盖自定义头）
    if spec.body_kind == BODY_FORM and "content-type" not in lower:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if spec.body_kind == BODY_JSON and "content-type" not in lower:
        headers["Content-Type"] = "application/json"
    if spec.body_kind == BODY_TEXT and "content-type" not in lower:
        headers["Content-Type"] = "text/plain; charset=utf-8"
    # 报文 dump 用合并后的头重新渲染，保证「所见即所发」
    record.request_dump = _dump_request(spec.method, payload["url"],
                                        header_pairs, payload["body"] or "")

    body = payload["body"] or None
    started = time.perf_counter()
    try:
        response = session.request(
            spec.method,
            payload["url"],
            headers=headers,
            data=body.encode("utf-8") if isinstance(body, str) else body,
            timeout=spec.timeout,
            allow_redirects=spec.redirects,
            verify=spec.verify,
        )
    except Exception as exc:  # noqa: BLE001 - 任何网络异常都不外泄
        record.elapsed_ms = (time.perf_counter() - started) * 1000
        record.error = describe_error(exc)
        return record

    record.elapsed_ms = (time.perf_counter() - started) * 1000
    record.status = response.status_code
    record.reason = response.reason or ""
    record.mime = response.headers.get("Content-Type", "")
    record.response_headers = list(response.headers.items())
    raw = response.content or b""
    record.length = len(raw)
    text = _decode(raw[:MAX_PREVIEW], response.encoding, record.mime)
    record.truncated = len(raw) > MAX_PREVIEW
    record.preview = text
    return record


def _decode(raw: bytes, encoding: str | None, mime: str) -> str:
    """按响应头编码解码正文（复用 :mod:`lib.http_common.decode_body`）。"""
    from lib.http_common import decode_body

    return decode_body(raw, encoding, mime)


def mark_changes(records: list[ResponseRecord]) -> None:
    """给每行标记「状态码 / 长度 / 正文」相对上一行是否变化（差异高亮用）。"""
    previous: ResponseRecord | None = None
    for record in records:
        if previous is None:
            record.changed = {"status": False, "length": False, "body": False}
        else:
            record.changed = {
                "status": record.status != previous.status,
                "length": record.length != previous.length,
                "body": record.preview != previous.preview,
            }
        previous = record


def _emit_record(emit: LogFn, record: ResponseRecord) -> None:
    payload = " | ".join(record.payloads) if record.payloads else "-"
    if record.error:
        emit(f"[{record.index}] {payload} → 失败：{record.error}")
    else:
        emit(f"[{record.index}] {payload} → {record.status} {record.reason} "
             f"({record.length} bytes, {record.elapsed_ms:.0f}ms)")


def run(
    target: str | RequestSpec,
    *,
    method: str = "GET",
    query: Any = None,
    headers: Any = None,
    body: Any = None,
    body_kind: str = "",
    mode: str = MODE_CONST,
    attack: str = ATTACK_SNIPER,
    payloads: Sequence[str] | str = (),
    per_slot: Sequence[Sequence[str]] | None = None,
    per_location: dict[str, Sequence[str]] | None = None,
    const_value: str = "",
    timeout: float = DEFAULT_TIMEOUT,
    delay: float = DEFAULT_DELAY,
    rate: float = DEFAULT_RATE,
    workers: int = DEFAULT_WORKERS,
    redirects: bool = DEFAULT_REDIRECTS,
    verify: bool = DEFAULT_VERIFY_TLS,
    scheme: str = "http",
    log: LogFn | None = None,
    stop: threading.Event | None = None,
    on_result: Callable[[ResponseRecord], None] | None = None,
) -> dict[str, Any]:
    """请求器统一入口：返回可直接 JSON 序列化的结构化 dict。

    参数
    ----
    target        URL 字符串，或已构造好的 :class:`RequestSpec`
    query/headers/body  见 :meth:`RequestSpec.from_mapping`
    mode         ``const``（发一次） / ``loop``（批量）
    attack       ``sniper`` / ``batteringram`` / ``pitchfork`` / ``clusterbomb``
    payloads     通用载荷列表（字符串按行切分）
    per_location 按位置键给各自的载荷列表（pitchfork / clusterbomb 用）
    const_value  常量模式下替换 ``{{payload}}`` 的值
    workers      并发数（>1 时并发发送，结果仍按原始顺序返回）
    log / stop   逐行日志与中止开关
    on_result    每完成一行回调（界面增量刷新用）
    """
    emit = log or (lambda _m: None)
    started = time.time()

    if isinstance(target, RequestSpec):
        spec = target
    else:
        spec = RequestSpec.from_mapping({
            "method": method, "url": target, "query": query,
            "headers": headers, "body": body, "body_kind": body_kind,
            "redirects": redirects, "verify": verify, "scheme": scheme,
        })
    spec.timeout = float(timeout or DEFAULT_TIMEOUT)
    spec.redirects = bool(redirects)
    spec.verify = bool(verify)

    items = (split_payloads(payloads) if isinstance(payloads, str)
             else [str(item) for item in (payloads or [])])

    plan_obj = plan(spec, mode=mode, attack=attack, payloads=items,
                    per_slot=per_slot, per_location=per_location)
    emit(f"[目标] {spec.method} {spec.url}")
    emit(f"[模式] {plan_obj.mode}"
         + (f" / {plan_obj.attack}" if plan_obj.mode == MODE_LOOP else "")
         + f"，计划 {plan_obj.total} 次请求")
    if plan_obj.warning:
        emit(f"[提示] {plan_obj.warning}")
    for slot in plan_obj.slots:
        emit(f"[位置] {slot.describe()}")

    result = AttackResult(mode=plan_obj.mode, attack=plan_obj.attack,
                          total=plan_obj.total, plan=plan_obj.to_dict(),
                          warning=plan_obj.warning)
    session = make_session()
    throttle = _Throttle(delay, rate)
    records: list[ResponseRecord] = []

    try:
        if plan_obj.mode == MODE_CONST or plan_obj.total <= 0:
            # 常量模式：所有 {{payload}} 都填同一个值，所以按位置个数重复
            if spec.has_placeholder():
                slot_count = max(1, len(spec.slots()))
                values = [str(const_value)] * slot_count
            else:
                values = []
            record = send(session, spec, values, index=1, payloads=values,
                          throttle=throttle)
            records.append(record)
            result.total = 1
            _emit_record(emit, record)
            if on_result is not None:
                on_result(record)
        else:
            combos = combinations(plan_obj)
            batch = max(1, min(int(workers or 1), 32))
            if batch == 1:
                for i, combo in enumerate(combos, start=1):
                    if stop is not None and stop.is_set():
                        result.stopped = True
                        break
                    record = send(session, spec, combo, index=i, payloads=combo,
                                  throttle=throttle)
                    records.append(record)
                    _emit_record(emit, record)
                    if on_result is not None:
                        on_result(record)
            else:
                from concurrent.futures import ThreadPoolExecutor
                collected: dict[int, ResponseRecord] = {}
                with ThreadPoolExecutor(max_workers=batch) as pool:
                    futures = {
                        pool.submit(send, session, spec, combo, index=i,
                                    payloads=combo, throttle=throttle): i
                        for i, combo in enumerate(combos, start=1)}
                    for future, index in list(futures.items()):
                        if stop is not None and stop.is_set():
                            result.stopped = True
                            for pending in futures:
                                pending.cancel()
                            break
                        try:
                            collected[index] = future.result()
                        except Exception as exc:  # noqa: BLE001
                            collected[index] = ResponseRecord(
                                index=index, payloads=list(combos[index - 1]),
                                error=f"{type(exc).__name__}: {exc}")
                        if on_result is not None and index in collected:
                            on_result(collected[index])
                records = [collected[key] for key in sorted(collected)]
                for record in records:
                    _emit_record(emit, record)
    finally:
        session.close()

    mark_changes(records)
    result.records = records
    result.done = len(records)
    result.stopped = result.stopped or bool(stop is not None and stop.is_set())
    result.elapsed = time.time() - started
    emit(f"[完成] {result.done}/{result.total} 次请求，耗时 {result.elapsed:.1f}s"
         + ("（已手动停止）" if result.stopped else ""))
    return result.to_dict()


# ---------------------------------------------------------------------------
# 报告
# ---------------------------------------------------------------------------
def to_text(result: dict[str, Any]) -> str:
    """把 :func:`run` 的结果渲染成纯文本报告（落盘用）。"""
    from datetime import datetime

    lines: list[str] = []
    add = lines.append
    plan_info = result.get("plan") or {}
    add("# HTTP 请求器结果")
    add(f"# 模式: {result.get('mode', '')}"
        + (f" / {result.get('attack', '')}"
           if result.get("mode") == MODE_LOOP else ""))
    add(f"# 时间: {datetime.now():%Y-%m-%d %H:%M:%S}")
    add(f"# 请求: {result.get('done', 0)}/{result.get('total', 0)}"
        + ("（已手动停止）" if result.get("stopped") else ""))
    add(f"# 耗时: {result.get('elapsed', 0)}s")
    slots = plan_info.get("slots") or []
    if slots:
        add(f"# 载荷位置: {'；'.join(slots)}")
    add("")
    for record in result.get("responses") or []:
        payload = " | ".join(record.get("payloads") or []) or "-"
        add(f"=== [{record.get('index')}] {payload} ===")
        if record.get("error"):
            add(f"  请求失败：{record['error']}")
        else:
            add(f"  {record.get('method')} {record.get('url')}")
            add(f"  -> {record.get('status')} {record.get('reason')}  "
                f"{record.get('length')} bytes  {record.get('elapsed_ms')} ms")
        add("")
    add("# 生成于 28zenro HTTP 请求器")
    return "\n".join(lines)


__all__ = [
    "MODE_CONST", "MODE_LOOP", "MODES", "MODE_LABELS",
    "ATTACK_SNIPER", "ATTACK_BATTERINGRAM", "ATTACK_PITCHFORK", "ATTACK_CLUSTERBOMB",
    "ATTACKS", "ATTACK_LABELS", "ATTACK_HINTS", "METHODS", "BODY_KINDS",
    "BODY_LABELS", "LOCATIONS", "LOCATION_LABELS", "IMPLICIT_KEY", "KEY_ALL",
    "DEFAULT_TIMEOUT", "DEFAULT_DELAY", "DEFAULT_RATE", "DEFAULT_WORKERS",
    "DEFAULT_REDIRECTS", "DEFAULT_VERIFY_TLS",
    "HttpRequesterError", "Entry", "Slot", "RequestSpec", "ResponseRecord",
    "AttackPlan", "AttackResult",
    "parse_kv", "build_kv", "parse_headers", "build_headers", "split_payloads",
    "has_placeholder", "count_placeholders", "replace_placeholder", "normalize_url",
    "url_safe", "describe_error", "make_session", "compose", "plan", "combinations",
    "send", "mark_changes", "run", "to_text",
]
