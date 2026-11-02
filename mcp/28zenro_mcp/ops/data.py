# -*- coding: utf-8 -*-
"""cn_data —— 数据处理工具组。

覆盖 ``lib.json_tool`` / ``lib.file_hex_codec`` / ``lib.text_diff`` /
``lib.text_dedup``：JSON 美化与结构分析、文件 ↔ 十六进制互转、文本对比与去重。

路径约定：所有 ``path`` / ``out_path`` 参数，**相对路径基于项目根**
（``D:/Code/pythonCode/CTFcrypto``），不用宿主进程的 CWD。
"""

from __future__ import annotations

from typing import Any

from lib import file_hex_codec, json_tool, text_dedup, text_diff

from ..contract import (Ctx, Group, arr, flag, make_op, num, obj, txt,
                        custom_op, anyp)
from ..envelope import to_jsonable
from ._helpers import rel, resolve_output, resolve_path

_DEDUP_UNITS = ("line", "word", "char")
_DEDUP_ORDERS = ("keep", "asc", "desc")
_DIFF_MODES = ("char", "word", "line")


# ---------------------------------------------------------------------------
# 自定义 handler：路径解析 + 结果整形
# ---------------------------------------------------------------------------
def _file_to_hex(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    path = resolve_path(a["path"], must_exist=True)
    text, size, truncated = file_hex_codec.file_to_hex(
        path, separator=a["separator"], prefix=a["prefix"],
        uppercase=a["uppercase"], bytes_per_line=a["bytes_per_line"],
        limit=a["limit"])
    return {"path": str(path), "rel": rel(path), "size": size,
            "hex": text, "truncated": truncated}


def _write_hex_file(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    src = resolve_path(a["path"], must_exist=True)
    out = resolve_output(a["out_path"], src.with_suffix(src.suffix + ".hex"))
    written, size, lines = file_hex_codec.write_hex_file(
        src, out, separator=a["separator"], prefix=a["prefix"],
        uppercase=a["uppercase"], bytes_per_line=a["bytes_per_line"])
    return {"src": str(src), "out": str(written), "out_rel": rel(written),
            "size": size, "lines": lines}


def _hex_to_file(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    out = resolve_output(a["out_path"], "output/decoded.bin")
    written, size = file_hex_codec.hex_to_file(
        a["text"], out, separator=a["separator"])
    return {"out": str(written), "out_rel": rel(written), "size": size}


def _hex_file_to_file(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    src = resolve_path(a["src_path"], must_exist=True)
    out = resolve_output(a["out_path"], src.with_suffix(".bin"))
    written, size = file_hex_codec.hex_file_to_file(
        src, out, separator=a["separator"])
    return {"src": str(src), "out": str(written), "out_rel": rel(written),
            "size": size}


def _compare(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    result = text_diff.compare(
        a["left"], a["right"], mode=a["mode"],
        ignore_case=a["ignore_case"], ignore_space=a["ignore_space"])
    return to_jsonable(result)


OPS = [
    # ------------------------------------------------------------------ JSON
    make_op(json_tool.format_json, "JSON 美化：按 indent 缩进，中文原样保留（不转 \\uXXXX）。",
            [txt("data", required=True, desc="JSON 文本"),
             num("indent", default=2, desc="缩进空格数", minimum=0, maximum=8)],
            returns="str：格式化后的 JSON", example={"data": "{\"a\":1}"}),
    make_op(json_tool.minify_json, "JSON 压缩：去掉全部非必要空白，输出单行。",
            [txt("data", required=True, desc="JSON 文本")], returns="str：单行 JSON"),
    make_op(json_tool.analyze_json,
            "JSON 结构报告：根类型 / 规模 / 最大深度 / 重复键 / 逐条值路径。",
            [txt("data", required=True, desc="JSON 文本"),
             num("limit", default=500, desc="值路径最多列出多少条", minimum=1)],
            returns="str：纯文本结构报告"),
    make_op(json_tool.loads_json, "解析 JSON 并检出重复键。",
            [txt("data", required=True, desc="JSON 文本")],
            returns="dict：{value: 解析结果, duplicate_keys: [重复键名]}",
            unpack=("value", "duplicate_keys")),
    make_op(json_tool.rows_from_json,
            "把 JSON 摊平成 ``(根类型, [[键名, 值类型, 值文本], …])``，便于表格化。",
            [txt("data", required=True, desc="JSON 文本")],
            returns="dict：{root_type, rows}",
            unpack=("root_type", "rows")),
    make_op(json_tool.build_json,
            "按行构建 JSON：entries 为 ``[[键, 类型, 值文本], …]``。",
            [txt("root", default="object", desc="根类型：object / array",
                 choices=("object", "array")),
             anyp("entries", required=True,
                  desc="[[键名, 值类型, 值文本], …]；类型支持 str/int/float/bool/null/object/array"),
             num("indent", default=2, desc="缩进空格数", minimum=0, maximum=8)],
            returns="str：构建出的 JSON 文本"),

    # -------------------------------------------------------- 文件 ↔ 十六进制
    make_op(file_hex_codec.bytes_to_hex,
            "字节串（十六进制输入） -> 十六进制文本，可加分隔符 / 前缀 / 每行字节数。",
            [txt("data", required=True, desc="字节串的十六进制表示"),
             txt("separator", desc="字节间分隔符，如空格或 ``\\n``"),
             txt("prefix", desc="每个字节的前缀，如 ``0x``"),
             flag("uppercase", default=True, desc="输出大写十六进制"),
             num("bytes_per_line", default=0, desc="每行字节数，0 表示不换行",
                 minimum=0)],
            returns="str：十六进制文本", example={"data": "666c6167", "separator": " "}),
    make_op(file_hex_codec.hex_to_bytes,
            "十六进制文本 -> 字节串（输出 hex / length / text）。",
            [txt("text", required=True, desc="十六进制文本，可含 0x / \\x 前缀与分隔符"),
             txt("separator", default=None, desc="自定义分隔符（默认自动识别）")],
            returns="dict：{hex, length, text, is_text}"),
    make_op(file_hex_codec.unescape,
            "把 ``\\n`` / ``\\r`` / ``\\t`` / ``\\0`` / ``\\\\`` 转义还原为真实字符。",
            [txt("text", required=True, desc="含转义序列的文本")],
            returns="str：还原后的文本"),
    custom_op("file_to_hex", _file_to_hex,
              "读取文件并渲染为十六进制文本（流式，内存占用与文件大小无关）。",
              [txt("path", required=True, desc="源文件路径（相对路径基于项目根）"),
               txt("separator", desc="字节间分隔符"),
               txt("prefix", desc="每个字节的前缀"),
               flag("uppercase", default=True, desc="输出大写十六进制"),
               num("bytes_per_line", default=0, desc="每行字节数，0 表示不换行",
                   minimum=0),
               num("limit", default=None, desc="最多读取的字节数（默认全读）",
                   minimum=1)],
              returns="dict：{path, rel, size, hex, truncated}", risk="read",
              module="lib.file_hex_codec"),
    custom_op("write_hex_file", _write_hex_file,
              "把文件转成十六进制文本文件（流式写出）。",
              [txt("path", required=True, desc="源文件路径"),
               txt("out_path", desc="输出文件路径；留空则同在源文件旁加 .hex 后缀"),
               txt("separator", desc="字节间分隔符"),
               txt("prefix", desc="每个字节的前缀"),
               flag("uppercase", default=True, desc="输出大写十六进制"),
               num("bytes_per_line", default=0, desc="每行字节数，0 表示不换行",
                   minimum=0)],
              returns="dict：{src, out, out_rel, size, lines}", risk="write",
              module="lib.file_hex_codec"),
    custom_op("hex_to_file", _hex_to_file,
              "把十六进制文本解码并写出为二进制文件。",
              [txt("text", required=True, desc="十六进制文本"),
               txt("out_path", desc="输出文件路径；留空写入 output/decoded.bin"),
               txt("separator", default=None, desc="自定义分隔符（默认自动识别）")],
              returns="dict：{out, out_rel, size}", risk="write",
              module="lib.file_hex_codec"),
    custom_op("hex_file_to_file", _hex_file_to_file,
              "把十六进制文本文件解码为二进制文件（等价 ``xxd -r -p``）。",
              [txt("src_path", required=True, desc="十六进制文本文件路径"),
               txt("out_path", desc="输出二进制文件路径；留空则在源文件旁加 .bin"),
               txt("separator", default=None, desc="自定义分隔符（默认自动识别）")],
              returns="dict：{src, out, out_rel, size}", risk="write",
              module="lib.file_hex_codec"),

    # ---------------------------------------------------------------- 文本对比
    custom_op("compare", _compare,
              "文本差异对比：返回两侧分段（equal / removed / added / replaced）、"
              "相似度与增删改统计。",
              [txt("left", required=True, desc="文本 A"),
               txt("right", required=True, desc="文本 B"),
               txt("mode", default="char", desc="对比粒度", choices=_DIFF_MODES),
               flag("ignore_case", default=False, desc="忽略大小写"),
               flag("ignore_space", default=False, desc="忽略空白字符")],
              returns=("dict：{equal, similarity, blocks, removed, added, replaced, "
                       "mode, left_length, right_length, left[], right[]}"),
              risk="safe", module="lib.text_diff",
              example={"left": "flag{abc}", "right": "flag{abd}", "mode": "char"}),

    # ---------------------------------------------------------------- 文本去重
    make_op(text_dedup.dedupe,
            "文本去重：按行 / 词 / 字符去重，可保持原序或升序 / 降序排列。",
            [txt("data", required=True, desc="原始文本"),
             txt("unit", default="line", desc="去重粒度", choices=_DEDUP_UNITS),
             txt("order", default="keep", desc="输出顺序：keep / asc / desc",
                 choices=_DEDUP_ORDERS),
             flag("ignore_case", default=False, desc="大小写不敏感比较")],
            returns="str：去重后的文本"),
    make_op(text_dedup.dedupe_stats,
            "文本去重统计：返回总单元数 / 去重后数量等报告，不改写原文。",
            [txt("data", required=True, desc="原始文本"),
             txt("unit", default="line", desc="统计粒度", choices=_DEDUP_UNITS),
             flag("ignore_case", default=False, desc="大小写不敏感比较"),
             obj("labels", default=None,
                 desc="统计标签映射（键为 total/unique/duplicate 等，缺省用内置中文标签）")],
            returns="str：多行统计报告"),
    make_op(text_dedup.split_units,
            "把文本按指定粒度切成单元列表（只切分，不去重）。",
            [txt("text", required=True, desc="原始文本"),
             txt("unit", default="line", desc="切分粒度", choices=_DEDUP_UNITS)],
            returns="list[str]：单元列表"),
]


GROUP = Group(
    name="cn_data",
    title="数据处理：JSON / 十六进制文件 / 文本对比去重",
    summary=("JSON 美化·压缩·结构分析·摊平·构建；文件↔十六进制互转（流式）；"
             "文本差异对比（字符/词/行粒度）；文本去重与统计。"),
    ops=OPS,
    guide=("路径类 op 的相对路径基于项目根，不依赖宿主进程 CWD；"
           "写文件的 op 风险等级为 write，会在 meta.risk 里标明。"),
)
