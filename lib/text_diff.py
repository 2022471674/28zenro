# -*- coding: utf-8 -*-
"""文本对比纯逻辑模块（字符 / 单词 / 行三种粒度）。

本模块只做「两段文本进、结构化差异出」的纯计算：不导入 PySide6 等任何 UI
模块，也不拼接界面文案——结论、统计、高亮配色全部由界面层依据
:class:`DiffResult` 的字段渲染；失败时抛 :class:`DiffError`
（``ValueError`` 子类），由界面层加 ``[前缀]`` 展示。

对外接口：
    compare(left, right, mode, ignore_case, ignore_space)  -> DiffResult

对比粒度（``mode``）：
    char  逐字符（默认，适合短文本 / 密文 / 标志位）
    word  按空白切分的词（空白本身也是一个比较单元）
    line  按行（换行符不参与比较，适合整篇文档）

比较口径（可选开关，只影响「匹配哪些单元」，原文一律原样返回用于高亮）：
    ignore_case   忽略大小写
    ignore_space  忽略空白字符（字符 / 单词粒度直接跳过空白单元，
                  行粒度则剔除行内的空白后再比较）

差异表示（Segment.kind）：
    same   两侧一致（不高亮）
    left   仅左侧有（左侧标红 = 删除）
    right  仅右侧有（右侧标绿 = 新增）
    both   两侧都不同（两侧标黄 = 替换）
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# 一、常量与异常
# ---------------------------------------------------------------------------
MODE_CHAR = "char"
MODE_WORD = "word"
MODE_LINE = "line"
#: 可用对比粒度（顺序即界面下拉的展示顺序）
UNIT_MODES: tuple[str, ...] = (MODE_CHAR, MODE_WORD, MODE_LINE)

SEG_SAME = "same"
SEG_LEFT = "left"
SEG_RIGHT = "right"
SEG_BOTH = "both"

#: 单侧文本长度上限（字符数）：超过则拒绝对比，避免超长输入把界面卡死
MAX_TEXT_LENGTH = 200_000
#: 单元数超过该规模时开启 difflib 的 popular-junk 启发式，牺牲少量精度换速度
_AUTOJUNK_AT = 20_000

#: 单词 / 空白切分（两种单元交替出现，拼回原文无损）
_SPLIT_WORDS = re.compile(r"\s+|\S+")
#: 行粒度忽略空白时剔除的行内空白
_STRIP_SPACE = re.compile(r"\s+")


class DiffError(ValueError):
    """文本对比失败时抛出的统一异常，界面层统一捕获并展示提示。"""


# ---------------------------------------------------------------------------
# 二、结果数据结构
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Segment:
    """一段连续文本及其在对比中的身份。

    text  原文切片（忽略空白 / 大小写时也保留原始写法，供高亮原样展示）
    kind  :data:`SEG_SAME` / :data:`SEG_LEFT` / :data:`SEG_RIGHT` / :data:`SEG_BOTH`
    """

    text: str
    kind: str


@dataclass(frozen=True)
class DiffResult:
    """一次文本对比的完整结果。

    left / right     两侧按顺序拼接即为各自原文的分段视图（不丢字符）
    equal            结论：True = 一致，False = 不一致
    similarity       相似度百分比（0.0 ~ 100.0，保留一位小数）
    blocks           差异处数（连续的差异单元合并算一处）
    removed          仅左侧有的单元数（删除，含替换块的左半）
    added            仅右侧有的单元数（新增，含替换块的右半）
    replaced         整体替换的块数
    mode             本次使用的对比粒度
    left_length / right_length  两侧原始字符数
    """

    left: tuple[Segment, ...]
    right: tuple[Segment, ...]
    equal: bool
    similarity: float
    blocks: int
    removed: int
    added: int
    replaced: int
    mode: str
    left_length: int
    right_length: int


# ---------------------------------------------------------------------------
# 三、输入校验与分词
# ---------------------------------------------------------------------------
def _check_text(text, side: str) -> str:
    """校验一侧输入必须是字符串且不超长，原样返回（保留首尾空白）。"""
    if not isinstance(text, str):
        raise DiffError(
            f"文本对比失败：{side}必须是字符串，当前类型为 {type(text).__name__}。"
        )
    if len(text) > MAX_TEXT_LENGTH:
        raise DiffError(
            f"文本对比失败：{side}长度 {len(text)} 超过单侧上限 "
            f"{MAX_TEXT_LENGTH} 字符，请拆分后分段对比。"
        )
    return text


def _check_mode(mode: str) -> str:
    if mode not in UNIT_MODES:
        raise DiffError(
            f"文本对比失败：未知的对比粒度「{mode}」，"
            f"可选粒度为 {' / '.join(UNIT_MODES)}。"
        )
    return mode


def _tokenize(text: str, mode: str, ignore_case: bool,
              ignore_space: bool) -> tuple[list[str], list[tuple[int, int]]]:
    """把原文切成参与匹配的单元。

    返回 ``(keys, spans)``：``keys`` 是归一化后用于匹配的单元串，
    ``spans`` 与之一一对应，记录该单元在原文中的 ``[start, end)`` 区间。
    被忽略的单元（如 ignore_space 下的空白）不进 ``keys``，
    其原文区间由 :func:`_side_segments` 的边界补齐规则兜底，保证不丢字符。
    """
    raw: list[tuple[int, int]] = []
    if mode == MODE_LINE:
        pos = 0
        for piece in text.splitlines(keepends=True):
            raw.append((pos, pos + len(piece)))
            pos += len(piece)
    elif mode == MODE_WORD:
        raw = [(m.start(), m.end()) for m in _SPLIT_WORDS.finditer(text)]
    else:
        raw = [(index, index + 1) for index in range(len(text))]

    keys: list[str] = []
    spans: list[tuple[int, int]] = []
    for start, end in raw:
        token = text[start:end]
        if mode == MODE_LINE:
            key = _STRIP_SPACE.sub("", token) if ignore_space else token
        else:
            if ignore_space and not token.strip():
                continue  # 空白单元：按「忽略空白」口径跳过
            key = token
        if ignore_case:
            key = key.lower()
        keys.append(key)
        spans.append((start, end))
    return keys, spans


def _side_segments(text: str, spans: list[tuple[int, int]],
                   opcodes: list[tuple], side: str) -> tuple[Segment, ...]:
    """按 difflib 的 opcodes 生成某一侧的分段视图。

    ``side`` 为 ``"left"`` 取 opcodes 的 ``i`` 区间，``"right"`` 取 ``j`` 区间。
    规则：
    - 该侧没有文本的区间（对侧插入 / 删除）直接跳过，不留空片段；
    - 相邻片段之间被忽略的空白归并到前一片段；
    - 首片段起点拉到 0、末片段终点拉到 ``len(text)``——两端的空白同样不丢。
    """
    segs: list[list] = []  # [start, end, kind]
    for tag, i1, i2, j1, j2 in opcodes:
        start_idx, end_idx = (i1, i2) if side == "left" else (j1, j2)
        if end_idx <= start_idx:
            continue  # 本侧该处无文本
        if tag == "equal":
            kind = SEG_SAME
        elif tag == "replace":
            kind = SEG_BOTH
        else:
            kind = SEG_LEFT if side == "left" else SEG_RIGHT
        segs.append([spans[start_idx][0], spans[end_idx - 1][1], kind])

    for index in range(len(segs) - 1):
        if segs[index][1] < segs[index + 1][0]:
            segs[index][1] = segs[index + 1][0]  # 段间被忽略的空白并入前段
    if not segs:
        # 整侧被忽略（如只有空白且 ignore_space）：作为对侧的新增 / 删除整体呈现
        if text:
            kind = SEG_LEFT if side == "left" else SEG_RIGHT
            segs.append([0, len(text), kind])
    else:
        segs[0][0] = 0
        segs[-1][1] = len(text)
    return tuple(Segment(text[start:end], kind) for start, end, kind in segs)


# ---------------------------------------------------------------------------
# 四、主流程
# ---------------------------------------------------------------------------
def compare(left: str, right: str, mode: str = MODE_CHAR,
            ignore_case: bool = False,
            ignore_space: bool = False) -> DiffResult:
    """对比两段文本，返回结构化差异结果。

    Args:
        left:          文本 A（原文原样保留，首尾空白参与对比）
        right:         文本 B
        mode:          对比粒度，``char`` / ``word`` / ``line`` 之一
        ignore_case:   忽略大小写
        ignore_space:  忽略空白字符

    Returns:
        :class:`DiffResult`：``equal`` 即「一致 / 不一致」结论，
        ``left`` / ``right`` 为可直接高亮渲染的分段序列。

    Raises:
        DiffError: 输入不是字符串、粒度非法或单侧文本超长。
    """
    left = _check_text(left, "文本A")
    right = _check_text(right, "文本B")
    mode = _check_mode(mode)

    left_keys, left_spans = _tokenize(left, mode, ignore_case, ignore_space)
    right_keys, right_spans = _tokenize(right, mode, ignore_case, ignore_space)

    matcher = difflib.SequenceMatcher(
        None, left_keys, right_keys,
        autojunk=max(len(left_keys), len(right_keys)) > _AUTOJUNK_AT,
    )
    opcodes = matcher.get_opcodes()

    blocks = 0
    in_diff = False
    removed = added = replaced = 0
    for tag, i1, i2, j1, j2 in opcodes:
        if tag == "equal":
            in_diff = False
            continue
        if not in_diff:
            blocks += 1
            in_diff = True
        if tag in ("delete", "replace"):
            removed += i2 - i1
        if tag in ("insert", "replace"):
            added += j2 - j1
        if tag == "replace":
            replaced += 1

    if not left_spans and not right_spans:
        # 两侧按当前口径都没有可比单元（全空白且忽略空白 / 两段空文本）
        return DiffResult(
            left=(Segment(left, SEG_SAME),),
            right=(Segment(right, SEG_SAME),),
            equal=True, similarity=100.0, blocks=0,
            removed=0, added=0, replaced=0, mode=mode,
            left_length=len(left), right_length=len(right),
        )

    return DiffResult(
        left=_side_segments(left, left_spans, opcodes, "left"),
        right=_side_segments(right, right_spans, opcodes, "right"),
        equal=blocks == 0,
        similarity=round(matcher.ratio() * 100, 1),
        blocks=blocks,
        removed=removed,
        added=added,
        replaced=replaced,
        mode=mode,
        left_length=len(left),
        right_length=len(right),
    )
