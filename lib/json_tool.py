# -*- coding: utf-8 -*-
"""JSON 解析 / 格式化 / 结构报告 / 构建纯逻辑模块。

本模块只做「字符串进、字符串出」的纯计算：不导入 PySide6 等任何 UI 模块，
界面文案（类型名、占位提示、报告标题）作为模块常量随本文件一起提供，
界面层直接引用（与 ``lib.jwt_codec`` 的 ``CLAIM_DESCRIPTIONS`` 同一约定）。

对外接口：
    loads_json(data)                       -> (解析结果, 重复键名列表)
    format_json(data, indent)              -> 美化后的 JSON 文本
    minify_json(data)                      -> 压缩后的单行 JSON
    analyze_json(data, limit)              -> 结构报告（类型 / 层级 / 值路径）
    build_json(root, entries, indent)      -> 由「键 / 类型 / 值」行构建 JSON
    rows_from_json(data)                   -> (根类型, 行列表) 供构建页导入

输入容忍度：
    - 三个入口都接受首尾空白（JSON 本身允许），空输入报错；
    - 解析错误给出 JSON 标准的「第 N 行第 M 列」定位；
    - 拒绝 ``NaN`` / ``Infinity``（不是合法 JSON），拒绝非有限数值；
    - 重复键不阻断解析，但会在结构报告里列出（生成对象时后者覆盖前者）。
"""

from __future__ import annotations

import json
import math
import re

# ---------------------------------------------------------------------------
# 一、常量与异常
# ---------------------------------------------------------------------------
#: 构建器的根节点类型
ROOT_OBJECT = "object"
ROOT_ARRAY = "array"
ROOT_TYPES: tuple[str, ...] = (ROOT_OBJECT, ROOT_ARRAY)

#: 单元格值类型（构建器下拉）
TYPE_STRING = "string"
TYPE_NUMBER = "number"
TYPE_BOOLEAN = "boolean"
TYPE_NULL = "null"
TYPE_RAW = "raw"
VALUE_TYPES: tuple[str, ...] = (
    TYPE_STRING, TYPE_NUMBER, TYPE_BOOLEAN, TYPE_NULL, TYPE_RAW,
)

#: 值类型 -> 下拉显示名
VALUE_TYPE_LABELS: tuple[tuple[str, str], ...] = (
    (TYPE_STRING, "字符串"),
    (TYPE_NUMBER, "数字"),
    (TYPE_BOOLEAN, "布尔"),
    (TYPE_NULL, "空值"),
    (TYPE_RAW, "JSON 原文"),
)

#: 值类型 -> 输入框占位提示（随类型切换）
VALUE_PLACEHOLDERS: dict[str, str] = {
    TYPE_STRING: "文本值，原样写入（可为空字符串）",
    TYPE_NUMBER: "123、-4、1.5",
    TYPE_BOOLEAN: "true / false（也接受 1 / 0）",
    TYPE_NULL: "任意内容都会被忽略，生成 null",
    TYPE_RAW: '{"a": 1} 或 [1, 2]，会作为子对象 / 子数组插入',
}

#: 结构报告的标题文案
REPORT_TYPE = "类型"
REPORT_KEYS = "键数量"
REPORT_ITEMS = "元素数量"
REPORT_DEPTH = "最大深度"
REPORT_DUP = "重复键"
REPORT_PATHS = "值路径"
REPORT_ROOT = "（根）"
REPORT_MORE = "...（路径共 {count} 条，仅列出前 {shown} 条）"

_INT_RE = re.compile(r"[+-]?\d+")


class JsonToolError(ValueError):
    """JSON 处理失败时抛出的统一异常，界面层统一捕获并展示提示。"""


# ---------------------------------------------------------------------------
# 二、解析
# ---------------------------------------------------------------------------
def _check_input(data, action: str) -> str:
    if not isinstance(data, str):
        raise JsonToolError(
            f"{action}失败：输入必须是字符串，当前类型为 {type(data).__name__}。"
        )
    if not data.strip():
        raise JsonToolError(f"{action}失败：输入内容为空，请先粘贴 JSON 文本。")
    return data


def _check_finite(obj) -> None:
    """拒绝 ``NaN`` / ``Infinity``（标准 JSON 不允许，dumps 会输出非法字面量）。"""
    stack = [obj]
    while stack:
        item = stack.pop()
        if isinstance(item, float) and not math.isfinite(item):
            raise JsonToolError(
                "JSON 处理失败：文本里含 NaN / Infinity 等非有限数值，"
                "它不是合法 JSON。"
            )
        elif isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)


def loads_json(data: str) -> tuple[object, list[str]]:
    """解析 JSON 文本，返回 ``(解析结果, 重复键名列表)``。

    Raises:
        JsonToolError: 输入非字符串 / 为空、语法错误（带行列定位）、
            含 NaN / Infinity。
    """
    action = "JSON 解析"
    text = _check_input(data, action)

    dup_keys: list[str] = []

    def _pairs_hook(pairs):
        seen: set[str] = set()
        dups: set[str] = set()
        for key, _value in pairs:
            if key in seen:
                dups.add(key)
            seen.add(key)
        for key in dups:
            if key not in dup_keys:
                dup_keys.append(key)
        return dict(pairs)

    try:
        obj = json.loads(text, object_pairs_hook=_pairs_hook)
    except json.JSONDecodeError as exc:
        raise JsonToolError(
            f"{action}失败：{exc.msg}（第 {exc.lineno} 行第 {exc.colno} 列）。"
        ) from exc
    except RecursionError as exc:
        raise JsonToolError(f"{action}失败：嵌套层级过深，无法解析。") from exc

    _check_finite(obj)
    return obj, dup_keys


# ---------------------------------------------------------------------------
# 三、格式化 / 压缩
# ---------------------------------------------------------------------------
def _dumps(obj, **kwargs) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False, allow_nan=False, **kwargs)
    except (ValueError, TypeError) as exc:  # pragma: no cover  前置检查已拦截
        raise JsonToolError(f"JSON 处理失败：{exc}") from exc


def format_json(data: str, indent: int = 2) -> str:
    """JSON 美化：缩进输出（中文原样保留，不转 ``\\uXXXX``）。"""
    obj, _ = loads_json(data)
    return _dumps(obj, indent=max(0, int(indent)))


def minify_json(data: str) -> str:
    """JSON 压缩：去掉所有非必要空白，输出单行。"""
    obj, _ = loads_json(data)
    return _dumps(obj, separators=(",", ":"))


# ---------------------------------------------------------------------------
# 四、结构报告
# ---------------------------------------------------------------------------
def _type_desc(value) -> str:
    """值的中文类型描述（数组附元素个数，对象附键个数）。"""
    if value is None:
        return "空值"
    if isinstance(value, bool):
        return "布尔"
    if isinstance(value, (int, float)):
        return "数字"
    if isinstance(value, str):
        return "字符串"
    if isinstance(value, dict):
        return f"对象（{len(value)} 个键）"
    if isinstance(value, list):
        return f"数组（{len(value)} 个元素）"
    return type(value).__name__  # pragma: no cover  json 只产出以上类型


def _depth(value) -> int:
    """最大嵌套层数：标量为 0，容器为 1 + 子节点最大层数。"""
    if isinstance(value, dict):
        return 1 + max((_depth(item) for item in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((_depth(item) for item in value), default=0)
    return 0


def _walk(value, prefix: str, out: list[tuple[str, str]]) -> None:
    """前序遍历出 ``(值路径, 类型描述)``，路径顺序即阅读顺序。"""
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            out.append((path, _type_desc(child)))
            _walk(child, path, out)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            path = f"{prefix}[{index}]"
            out.append((path, _type_desc(child)))
            _walk(child, path, out)


def analyze_json(data: str, limit: int = 500) -> str:
    """JSON 结构报告：类型 / 规模 / 最大深度 / 重复键 / 逐条值路径。

    Args:
        data:   待解析的 JSON 文本
        limit:  值路径最多列出的条数（超出部分汇总成一行提示）

    Raises:
        JsonToolError: 解析失败（同 :func:`loads_json`）。
    """
    obj, dup_keys = loads_json(data)

    lines = [f"{REPORT_TYPE}: {_type_desc(obj)}"]
    if isinstance(obj, dict):
        lines.append(f"{REPORT_KEYS}: {len(obj)}")
    elif isinstance(obj, list):
        lines.append(f"{REPORT_ITEMS}: {len(obj)}")
    lines.append(f"{REPORT_DEPTH}: {_depth(obj)}")
    if dup_keys:
        lines.append(f"{REPORT_DUP}: {'、'.join(dup_keys)}")

    paths: list[tuple[str, str]] = []
    lines.append("")
    lines.append(f"---- {REPORT_PATHS} ----")
    lines.append(f"{REPORT_ROOT}    {_type_desc(obj)}")
    _walk(obj, "", paths)
    cap = max(1, int(limit))
    for path, desc in paths[:cap]:
        lines.append(f"{path}    {desc}")
    if len(paths) > cap:
        lines.append(REPORT_MORE.format(count=len(paths), shown=cap))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 五、构建
# ---------------------------------------------------------------------------
def _convert(type_: str, text, where: str):
    """按声明类型把输入文本转成 Python 值。"""
    raw = text if isinstance(text, str) else str(text)
    if type_ == TYPE_NULL:
        return None
    if type_ == TYPE_STRING:
        return raw
    if type_ == TYPE_NUMBER:
        body = raw.strip()
        if not body:
            raise JsonToolError(f"JSON 构建失败：{where}声明为数字，但值为空。")
        if _INT_RE.fullmatch(body):
            return int(body)
        try:
            number = float(body)
        except ValueError as exc:
            raise JsonToolError(
                f"JSON 构建失败：{where}的值「{raw}」不是合法数字。"
            ) from exc
        if not math.isfinite(number):
            raise JsonToolError(
                f"JSON 构建失败：{where}的值「{raw}」不是有限数值。"
            )
        return number
    if type_ == TYPE_BOOLEAN:
        body = raw.strip().lower()
        if body in ("true", "1"):
            return True
        if body in ("false", "0"):
            return False
        raise JsonToolError(
            f"JSON 构建失败：{where}的值「{raw}」应为 true 或 false。"
        )
    if type_ == TYPE_RAW:
        if not raw.strip():
            raise JsonToolError(f"JSON 构建失败：{where}声明为 JSON 原文，但值为空。")
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise JsonToolError(
                f"JSON 构建失败：{where}的 JSON 原文有误：{exc.msg}"
                f"（第 {exc.lineno} 行第 {exc.colno} 列）。"
            ) from exc
    raise JsonToolError(f"JSON 构建失败：未知的值类型「{type_}」。")


def build_json(root: str, entries, indent: int = 2) -> str:
    """把「键 / 类型 / 值」行构建为 JSON 文本。

    Args:
        root:     ``object``（用键名列）或 ``array``（忽略键名列）
        entries:  ``(键名, 值类型, 值文本)`` 序列，顺序即输出顺序
        indent:   输出缩进空格数

    Raises:
        JsonToolError: 根类型非法、对象缺键名 / 键重复、某行值不符合声明类型。
    """
    items = list(entries)
    if root == ROOT_OBJECT:
        built: dict = {}
        for index, (key, type_, value) in enumerate(items, 1):
            name = str(key or "").strip()
            if not name:
                raise JsonToolError(
                    f"JSON 构建失败：第 {index} 行缺少键名，对象的每个值都需要键名。"
                )
            if name in built:
                raise JsonToolError(
                    f"JSON 构建失败：键「{name}」重复出现，生成对象时会互相覆盖。"
                )
            built[name] = _convert(type_, value, f"键「{name}」")
        target: object = built
    elif root == ROOT_ARRAY:
        target = [
            _convert(type_, value, f"第 {index} 行")
            for index, (_key, type_, value) in enumerate(items, 1)
        ]
    else:
        raise JsonToolError(
            f"JSON 构建失败：未知的根类型「{root}」，"
            f"可选值为 {' / '.join(ROOT_TYPES)}。"
        )
    return _dumps(target, indent=max(0, int(indent)))


def _type_of(value) -> str:
    """按值反推构建器可用的类型键（布尔先于数字判断，``bool`` 是 ``int`` 子类）。"""
    if value is None:
        return TYPE_NULL
    if isinstance(value, bool):
        return TYPE_BOOLEAN
    if isinstance(value, (int, float)):
        return TYPE_NUMBER
    if isinstance(value, str):
        return TYPE_STRING
    return TYPE_RAW  # dict / list


def _render(value) -> str:
    """把值渲染回构建器可编辑的文本。"""
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, float):
        return repr(value)
    return str(value)


def rows_from_json(data: str) -> tuple[str, list[tuple[str, str, str]]]:
    """把 JSON 文本转成 ``(根类型, [(键名, 值类型, 值文本), ...])``，供构建页导入。

    根节点必须是对象或数组；嵌套的对象 / 数组作为 ``raw`` 类型整段带入。

    Raises:
        JsonToolError: 解析失败，或根节点是标量。
    """
    obj, _ = loads_json(data)
    if isinstance(obj, dict):
        return ROOT_OBJECT, [
            (str(key), _type_of(value), _render(value))
            for key, value in obj.items()
        ]
    if isinstance(obj, list):
        return ROOT_ARRAY, [
            ("", _type_of(value), _render(value)) for value in obj
        ]
    raise JsonToolError(
        "导入构建器失败：根节点必须是对象或数组，"
        f"当前是{_type_desc(obj)}，无法用行编辑表达。"
    )
