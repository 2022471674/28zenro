# -*- coding: utf-8 -*-
"""密码 Fuzz：给定一段密文（可带已知 key / 偏移量），把所有能解密的工具跑一遍。

CTF 里最常见的一幕：拿到一串东西，不知道是 Base64、凯撒还是别的，
只能一个个工具试。本模块把它收敛成「输入密文 → 出候选明文列表」，
结果按**可读性**排序，真明文一般直接浮到最前面。

新增密码工具必须遵守的约定
--------------------------
1. **双向工具**（``ToolSpec`` 里声明了 ``dec``）**自动参与**，不需要任何额外配置；
2. **单向解码器**（只有 ``enc``，如 URL 解码 / ASCII 转字符串）注册时写
   ``fuzz=fuzz_decoder(函数)`` 即可参与；
3. **需要 key / 多算法 / 多步**的工具，注册时写 ``fuzz=自己的函数``：
   签名 ``fn(ctx: FuzzContext) -> list[tuple[标签, 结果]]``，``ctx.key`` 是用户填的
   已知 key，``ctx.offset`` 是已知偏移量（可能为 None）；
4. **不想参与**（哈希、文本统计、格式化等）保持默认即可 —— 没有 ``dec`` 的单向
   工具本来就不会被收录；确需排除某个双向工具时写 ``fuzzable=False``。

``registry.fuzz_targets()`` 按上述规则挑出参与工具，页面直接拿它跑，
所以「后续加入的密码工具自动进入 Fuzz」是约定本身的副作用，而不是手工维护的清单。

本模块只做「文本进、候选列表出」，不导入任何 UI 模块。
"""

from __future__ import annotations

import itertools
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Sequence

#: 参数名命中这些关键字时，优先使用用户填的偏移量（而不是遍历）
OFFSET_KEYS = ("shift", "offset", "rot", "step", "n")
#: 参数名命中这些关键字时，使用用户填的已知 key
KEY_KEYS = ("key", "password", "passphrase", "secret", "k")
#: 单个整型参数最多遍历多少个取值（防止误配一个巨大 range 把界面卡死）
MAX_SWEEP = 64
#: 单次 Fuzz 最多保留多少条候选
MAX_HITS = 4000
#: 输入长度上限（纯 Python 实现，超长文本会让 26 次凯撒都很慢）
MAX_INPUT = 200_000
#: 判定「可读」的阈值（只看可读结果时用）
READABLE_THRESHOLD = 0.78

LogFn = Callable[[str], None]


class CipherFuzzError(ValueError):
    """Fuzz 参数问题时抛出的统一异常，由界面层捕获展示。"""


@dataclass
class FuzzContext:
    """一次 Fuzz 的输入上下文，传给自定义 ``fuzz`` 函数。"""

    text: str
    key: str = ""
    offset: int | None = None


@dataclass
class FuzzHit:
    """一条候选解密结果。"""

    tool_id: str
    tool: str
    label: str
    output: str
    score: float = 0.0

    @property
    def readable(self) -> bool:
        return self.score >= READABLE_THRESHOLD

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_id": self.tool_id,
            "tool": self.tool,
            "label": self.label,
            "output": self.output,
            "score": round(self.score, 3),
            "readable": self.readable,
        }


@dataclass
class FuzzResult:
    """一次 Fuzz 的汇总。"""

    total_tools: int = 0
    tried_tools: int = 0
    hits: list[FuzzHit] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_tools": self.total_tools,
            "tried_tools": self.tried_tools,
            "hits": [hit.to_dict() for hit in self.hits],
            "skipped": list(self.skipped),
        }


# ---------------------------------------------------------------------------
# 可读性打分
# ---------------------------------------------------------------------------
#: 常见于正常文本的符号（出现不算「乱码」）
_TEXT_PUNCT = set(" \t\r\n.,:;!?'\"()[]{}<>/\\-_=+*&^%$#@~`|，。！？；：、“”‘’（）【】《》…—·")
#: 英文里出现频率最高的 15 个字母：命中率高说明像人话
_COMMON_LETTERS = set("etaoinshrdlucmfw")


def readability(text: str) -> float:
    """给一段输出打「像不像明文」的分（0~1，越高越像）。

    单看「可打印字符占比」是不够的 —— ROT47 之后的乱码、Base64 残片全是可打印
    字符，会和真明文并列满分。这里改成几项加权：

    - 可打印占比（基础分）；
    - 字母 + 汉字占比（明文以字母/汉字为主）；
    - 空格占比（英文靠空格断词）；
    - 高频字母占比（`etaoin…`，随机串命中率明显偏低）；
    - 符号密度、控制字符 / 替换字符重罚；
    - 汉字占比高时额外加分。

    目的只有一个：让凯撒 26 个候选里那句人话排到最前面。
    """
    sample = str(text or "")[:4000]
    if not sample:
        return 0.0
    total = len(sample)
    printable = bad = letters = spaces = digits = cjk = common = 0
    for char in sample:
        if char == "\ufffd" or (not char.isprintable() and char not in "\r\n\t"):
            bad += 1
            continue
        printable += 1
        if char.isspace():
            spaces += 1
            continue
        if char.isdigit():
            digits += 1
            continue
        if "\u4e00" <= char <= "\u9fff":
            cjk += 1
            letters += 1
            continue
        if char.isalpha():
            letters += 1
            if char.lower() in _COMMON_LETTERS:
                common += 1

    base = printable / total
    alpha = letters / total
    space_ratio = spaces / total
    symbols = max(0, printable - letters - spaces - digits)
    symbol_ratio = symbols / total
    common_ratio = common / letters if letters else 0.0

    score = (0.45 * base
             + 0.30 * alpha
             + 0.15 * min(space_ratio * 4, 1.0)
             + 0.10 * common_ratio * min(alpha * 2, 1.0))
    score -= 0.5 * symbol_ratio
    score -= 2.0 * (bad / total)
    if cjk / total >= 0.3:
        score += 0.12
    return max(0.0, min(1.0, score))


# ---------------------------------------------------------------------------
# 工具调用
# ---------------------------------------------------------------------------
def fuzz_decoder(func: Callable[[str], str]) -> Callable[[FuzzContext], list[tuple[str, str]]]:
    """单向解码器的标准 Fuzz 包装：只调用一次，失败就跳过。

    用法（注册表里）：``fuzz=fuzz_decoder(string_codec.url_decode)``。
    """

    def runner(ctx: FuzzContext) -> list[tuple[str, str]]:
        try:
            result = func(ctx.text)
        except Exception:  # noqa: BLE001  解不开是常态，不该打断整轮 Fuzz
            return []
        if isinstance(result, str) and result.strip() and result != ctx.text:
            return [("默认", result)]
        return []

    return runner


def _param_values(spec, ctx: FuzzContext) -> list[Any]:
    """按参数声明给出要尝试的取值列表。"""
    default = spec.default
    if isinstance(default, bool):
        return [True, False]
    if getattr(spec, "choices", ()):
        return [value for value, _text in spec.choices]
    if isinstance(default, str):
        # 字符串参数只可能是 key 类，用用户填的；没填就空串试一次
        return [ctx.key] if ctx.key else [""]

    low = spec.minimum if spec.minimum is not None else 0
    high = spec.maximum if spec.maximum is not None else 25
    key = str(getattr(spec, "key", "")).lower()
    if key in OFFSET_KEYS and ctx.offset is not None:
        return [ctx.offset]
    if key in KEY_KEYS and ctx.key:
        return [ctx.key]
    high = min(high, low + MAX_SWEEP - 1)
    return list(range(low, high + 1))


def _call(func: Callable, text: str, kwargs: dict) -> str | None:
    """调用一次解密函数，失败 / 无信息量时返回 None。"""
    try:
        result = func(text, **kwargs)
    except Exception:  # noqa: BLE001  单个算法失败不影响其他算法
        return None
    if not isinstance(result, str):
        return None
    if not result.strip() or result == text:
        return None
    return result


def _auto_hits(tool, ctx: FuzzContext) -> list[tuple[str, str]]:
    """按 ToolSpec 的 dec/enc + params 自动推导一轮候选。"""
    func = tool.dec or tool.enc
    if func is None:
        return []
    params = tuple(getattr(tool, "params", ()) or ())
    if not params:
        result = _call(func, ctx.text, {})
        return [("默认", result)] if result is not None else []

    keys = [spec.key for spec in params]
    grids = [_param_values(spec, ctx) for spec in params]
    hits: list[tuple[str, str]] = []
    for combo in itertools.product(*grids):
        if len(hits) >= MAX_HITS:
            break
        kwargs = dict(zip(keys, combo))
        label = "，".join(f"{key}={value}" for key, value in kwargs.items())
        result = _call(func, ctx.text, kwargs)
        if result is not None:
            hits.append((label, result))
    return hits


def _tool_pairs(tool, ctx: FuzzContext, log: LogFn) -> list[tuple[str, str]]:
    """取一个工具产出的 ``[(标签, 结果), …]``。"""
    custom = getattr(tool, "fuzz", None)
    if custom is not None:
        try:
            pairs = custom(ctx) or []
        except Exception as exc:  # noqa: BLE001  自定义 fuzz 出错不该拖垮整轮
            log(f"[跳过] {tool.name}：{exc}")
            return []
        cleaned: list[tuple[str, str]] = []
        for item in pairs:
            if isinstance(item, tuple) and len(item) == 2:
                label, output = item
                if isinstance(output, str) and output.strip():
                    cleaned.append((str(label), output))
        return cleaned
    return _auto_hits(tool, ctx)


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def run(
    text: str,
    key: str = "",
    offset: int | None = None,
    targets: Sequence = (),
    log: LogFn | None = None,
    stop: threading.Event | None = None,
    dedupe: bool = True,
) -> dict[str, Any]:
    """把所有可解密工具跑一遍，返回按可读性降序的候选列表。

    参数
    ----
    text     密文（必填）
    key      已知密钥（没有就留空）
    offset   已知偏移量（``None`` 表示让带位移参数的工具自己遍历）
    targets  参与的工具声明（页面传 ``registry.fuzz_targets()``）
    log      逐行日志回调
    stop     置位后不再尝试后续工具
    dedupe   相同输出只保留可读性最高的一条
    """
    emit = log or (lambda _msg: None)
    raw = str(text or "")
    if not raw.strip():
        raise CipherFuzzError("请先输入要尝试的密文")
    if len(raw) > MAX_INPUT:
        raise CipherFuzzError(f"密文太长（{len(raw)} 字符），请截断到 {MAX_INPUT} 字符以内")

    context = FuzzContext(text=raw, key=str(key or "").strip(), offset=offset)
    tools = [tool for tool in targets if tool is not None]
    result = FuzzResult(total_tools=len(tools))

    emit(f"[输入] {len(raw)} 字符"
         + (f"，已知 key（{len(context.key)} 字符）" if context.key else "")
         + (f"，偏移量 {context.offset}" if context.offset is not None else "，偏移量自动遍历"))

    seen: dict[str, FuzzHit] = {}
    for tool in tools:
        if stop is not None and stop.is_set():
            result.skipped.append("已手动停止")
            break
        pairs = _tool_pairs(tool, context, emit)
        if not pairs:
            result.skipped.append(tool.name)
            continue
        result.tried_tools += 1
        for label, output in pairs:
            score = readability(output)
            hit = FuzzHit(tool_id=tool.id, tool=tool.name, label=label,
                          output=output, score=score)
            if dedupe:
                old = seen.get(output)
                if old is not None:
                    if score > old.score:
                        seen[output] = hit
                    continue
            seen[output] = hit
            if len(seen) >= MAX_HITS:
                break
        emit(f"[尝试] {tool.name}：{len(pairs)} 条")

    hits = sorted(seen.values(), key=lambda item: item.score, reverse=True)
    result.hits = hits
    readable = sum(1 for hit in hits if hit.readable)
    emit(f"[完成] {result.tried_tools}/{result.total_tools} 个工具产出 "
         f"{len(hits)} 条候选，其中可读 {readable} 条")
    return result.to_dict()


# ---------------------------------------------------------------------------
# 自检：``python -m lib.cipher_fuzz``
# ---------------------------------------------------------------------------
def _self_test() -> int:
    """用注册表里的真实工具跑一遍，验证约定与排序是否生效。"""
    from app import registry

    failures: list[str] = []

    targets = registry.fuzz_targets()
    ids = {tool.id for tool in targets}
    for expect in ("caesar", "basex", "rot13", "url_codec"):
        if expect not in ids:
            failures.append(f"约定失效，未收录：{expect}")
    for banned in ("md5", "sha256", "text_dedup", "json_tool", "cipher_fuzz"):
        if banned in ids:
            failures.append(f"不该参与：{banned}")

    # 凯撒：ROT13 密文应能被「凯撒 shift=13」还原，且排在前面
    result = run("Uryyb Jbeyq", targets=targets)
    top = result["hits"][:5]
    if not any(hit["tool"] == "凯撒密码" for hit in top):
        failures.append("凯撒候选没有排进前 5")
    if not any(hit["output"] == "Hello World" for hit in result["hits"]):
        failures.append("没有还原出 Hello World")

    # 已知偏移量：只应产出 shift=13 这一条凯撒结果
    # （关掉去重，否则 "Hello World" 会被先注册的 ROT13 抢走）
    result = run("Uryyb Jbeyq", offset=13, targets=targets, dedupe=False)
    caesar = [hit for hit in result["hits"] if hit["tool"] == "凯撒密码"]
    if len(caesar) != 1 or caesar[0]["output"] != "Hello World":
        failures.append(f"已知偏移量未生效：{caesar[:3]}")

    # Base64
    result = run("SGVsbG8gV29ybGQ=", targets=targets)
    if not any(hit["output"] == "Hello World" for hit in result["hits"]):
        failures.append("Base64 未解出")

    # 空输入应报错
    try:
        run("   ", targets=targets)
    except CipherFuzzError:
        pass
    else:
        failures.append("空输入没有报错")

    if failures:
        print("[FAIL] " + "；".join(failures))
        return 1
    print(f"[OK] 收录 {len(targets)} 个工具；凯撒 / Base64 / 偏移量 / 空输入 全部通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(_self_test())
