# -*- coding: utf-8 -*-
"""文本去重与去重统计纯逻辑模块（行 / 词 / 字符三种粒度）。

本模块只做「字符串进、字符串出」的纯计算：不导入 PySide6 等任何 UI 模块。
:func:`dedupe` 返回处理后的文本；:func:`dedupe_stats` 返回多行统计报告，
其中分区标题与统计标签由调用方通过 ``labels`` 传入（与
``lib.string_codec.text_count`` 同一套约定，文案统一来自 ``app.registry``）。

切分口径（``unit``）：
    line  按换行符 ``\\n`` 切分，行内空白与行尾 ``\\r`` 原样保留（不改写原文）
    word  按空白切出的词（输出用单个空格重新拼接）
    char  非空白字符（输出直接相连，原空白不参与去重）

去重规则：同一单元视为重复时**保留首次出现**的内容（``ignore_case`` 开启时按
小写判定，但输出仍是首次出现的原始写法）。

对外接口：
    dedupe(data, unit, order, ignore_case)            -> 去重（可排序）后的文本
    dedupe_stats(data, unit, ignore_case, labels)     -> 多行统计报告
"""

from __future__ import annotations

import re
from collections.abc import Mapping

# ---------------------------------------------------------------------------
# 一、常量与异常
# ---------------------------------------------------------------------------
UNIT_LINE = "line"
UNIT_WORD = "word"
UNIT_CHAR = "char"
#: 可用粒度（顺序即界面下拉的展示顺序）
UNITS: tuple[str, ...] = (UNIT_LINE, UNIT_WORD, UNIT_CHAR)

ORDER_KEEP = "keep"
ORDER_ASC = "asc"
ORDER_DESC = "desc"
#: 可用排序方式（顺序即界面下拉的展示顺序）
ORDERS: tuple[str, ...] = (ORDER_KEEP, ORDER_ASC, ORDER_DESC)

#: 统计报告最多列出的重复单元条数（超出部分汇总成一行提示）
MAX_DETAIL = 100

#: 报告的标签键，前 5 项即报告主体的输出顺序（文案由界面层传入）
STAT_LABEL_KEYS = (
    "total", "unique", "extra", "kinds", "rate", "detail", "none", "empty",
    "times", "cap",
)

_WORD = re.compile(r"\S+")


class DedupError(ValueError):
    """文本去重 / 统计失败时抛出的统一异常，界面层统一捕获并展示提示。"""


# ---------------------------------------------------------------------------
# 二、内部工具
# ---------------------------------------------------------------------------
def _check_input(data, action: str) -> str:
    """校验输入必须是字符串（保留首尾空白，不改写原文）。"""
    if not isinstance(data, str):
        raise DedupError(
            f"{action}失败：输入必须是字符串，当前类型为 {type(data).__name__}。"
        )
    if not data.strip():
        raise DedupError(f"{action}失败：输入内容为空，请先填写待处理的数据。")
    return data


def _check_choice(value, allowed: tuple[str, ...], action: str, what: str) -> str:
    if value not in allowed:
        raise DedupError(
            f"{action}失败：未知的{what}「{value}」，可选值为 {' / '.join(allowed)}。"
        )
    return value


def _label(labels, key: str) -> str:
    """从界面层传入的标签映射里取文案；缺失说明配置漏项，直接报错。"""
    if not isinstance(labels, Mapping) or key not in labels:
        raise DedupError(f"缺少界面文案配置：labels 中未提供 {key!r}。")
    return str(labels[key])


def split_units(text: str, unit: str) -> list[str]:
    """把文本按粒度切成单元列表（拼接见 :data:`JOINERS`）。

    Raises:
        DedupError: 粒度非法。
    """
    if unit == UNIT_LINE:
        return text.split("\n")
    if unit == UNIT_WORD:
        return _WORD.findall(text)
    if unit == UNIT_CHAR:
        return [char for char in text if not char.isspace()]
    raise DedupError(
        f"未知的粒度「{unit}」，可选粒度为 {' / '.join(UNITS)}。"
    )


#: 各粒度重新拼接时的分隔符（行原样、词空格、字符直连）
JOINERS = {UNIT_LINE: "\n", UNIT_WORD: " ", UNIT_CHAR: ""}


# ---------------------------------------------------------------------------
# 三、去重（可排序）
# ---------------------------------------------------------------------------
def dedupe(data: str, unit: str = UNIT_LINE, order: str = ORDER_KEEP,
           ignore_case: bool = False) -> str:
    """文本去重排序：去掉重复单元，可按需升序 / 降序排列。

    Args:
        data:         待处理文本（原样保留，不做任何改写）
        unit:         粒度：``line`` 行 / ``word`` 词 / ``char`` 字符
        order:        ``keep`` 保持首次出现顺序 / ``asc`` 升序 / ``desc`` 降序
        ignore_case:  判重与排序时忽略大小写（输出仍是首次出现的原始写法）

    Returns:
        去重后的文本；行粒度用 ``\\n`` 拼接、词粒度用空格、字符粒度直接相连。

    Raises:
        DedupError: 输入非字符串 / 为空、粒度或排序方式非法。
    """
    action = "文本去重排序"
    text = _check_input(data, action)
    _check_choice(unit, UNITS, action, "粒度")
    _check_choice(order, ORDERS, action, "排序方式")

    seen: set[str] = set()
    kept: list[str] = []
    for item in split_units(text, unit):
        key = item.lower() if ignore_case else item
        if key in seen:
            continue
        seen.add(key)
        kept.append(item)

    if order != ORDER_KEEP:
        sort_key = (lambda s: s.lower()) if ignore_case else (lambda s: s)
        # 稳定排序：判定相等的单元保持首次出现的先后
        kept.sort(key=sort_key, reverse=(order == ORDER_DESC))
    return JOINERS[unit].join(kept)


# ---------------------------------------------------------------------------
# 四、去重统计
# ---------------------------------------------------------------------------
def _format_detail(display: str, count: int, labels) -> str:
    """一行明细：``[3次] 内容``；空行用中性占位符，避免看起来像缺内容。"""
    body = display if display.strip() else _label(labels, "empty")
    return f"[{count}{_label(labels, 'times')}] {body}"


def dedupe_stats(data: str, unit: str = UNIT_LINE, ignore_case: bool = False,
                 labels=None) -> str:
    """文本去重统计：返回多行报告，不改写原文。

    统计口径：
        total   原始单元数（按粒度切分后的总个数）
        unique  去重后单元数（判重可忽略大小写）
        extra   重复出现次数 = total - unique（多出来的那些出现）
        kinds   出现 2 次及以上的单元种类数
        rate    重复率 = extra / total * 100（保留一位小数）
        detail  重复单元明细，按出现次数降序，至多列出 :data:`MAX_DETAIL` 条

    Raises:
        DedupError: 输入非字符串 / 为空、粒度非法、``labels`` 缺少标签。
    """
    action = "文本去重统计"
    text = _check_input(data, action)
    _check_choice(unit, UNITS, action, "粒度")

    total = 0
    counts: dict[str, list] = {}  # key -> [首次出现的原文, 出现次数]
    for item in split_units(text, unit):
        total += 1
        key = item.lower() if ignore_case else item
        entry = counts.get(key)
        if entry is None:
            counts[key] = [item, 1]
        else:
            entry[1] += 1

    unique = len(counts)
    extra = total - unique
    repeated = [entry for entry in counts.values() if entry[1] > 1]
    # 按出现次数降序，同次数保持首次出现顺序（sort 稳定）
    repeated.sort(key=lambda entry: entry[1], reverse=True)

    body = {
        "total": total,
        "unique": unique,
        "extra": extra,
        "kinds": len(repeated),
        "rate": (extra / total * 100) if total else 0.0,
    }
    lines = [
        f"{_label(labels, key)}: "
        + (f"{body[key]:.1f}%" if key == "rate" else str(body[key]))
        for key in STAT_LABEL_KEYS[:5]
    ]
    lines.append("")
    lines.append(f"---- {_label(labels, 'detail')} ----")
    if not repeated:
        lines.append(_label(labels, "none"))
    else:
        for display, count in repeated[:MAX_DETAIL]:
            lines.append(_format_detail(display, count, labels))
        if len(repeated) > MAX_DETAIL:
            lines.append(_label(labels, "cap").format(
                count=len(repeated), shown=MAX_DETAIL))
    return "\n".join(lines)
