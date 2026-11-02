# -*- coding: utf-8 -*-
"""cn_codec —— 编解码工具组。

覆盖 ``lib.base_codec`` / ``lib.char_codec`` / ``lib.rot_codec`` /
``lib.number_base_codec`` / ``lib.string_codec`` / ``lib.esolang``。
全部为纯计算（不联网、不读写业务文件），``risk=safe``。
"""

from __future__ import annotations

from typing import Any

from lib import (base_codec, char_codec, esolang, number_base_codec,
                 rot_codec, string_codec)

from ..contract import Group, flag, make_op, num, obj, txt

_BASE85 = ("b85", "a85")

#: ``string_codec.text_count`` 需要完整的标签映射，这里给一套中文默认值。
_COUNT_LABELS = {
    "total": "总字符数",
    "no_space": "不含空白字符数",
    "words": "单词数",
    "letters": "字母数",
    "digits": "数字数",
    "cjk": "汉字数",
    "lines": "行数",
}


def _data(desc: str) -> Any:
    return txt("data", required=True, desc=desc)


OPS = [
    # ------------------------------------------------------------------ Base
    make_op(base_codec.base16_encrypt, "Base16（十六进制）编码：文本 -> 十六进制大写字符串。",
            [_data("待编码文本")], returns="str：Base16 大写字符串", example={"data": "flag"}),
    make_op(base_codec.base16_decrypt, "Base16（十六进制）解码：十六进制字符串 -> 文本。",
            [_data("Base16 字符串（大小写均可）")], returns="str：解码后的文本"),
    make_op(base_codec.base32_encrypt, "Base32 编码：文本 -> Base32 字符串。",
            [_data("待编码文本")], returns="str：Base32 字符串", example={"data": "flag"}),
    make_op(base_codec.base32_decrypt, "Base32 解码：Base32 字符串 -> 文本。",
            [_data("Base32 字符串")], returns="str：解码后的文本"),
    make_op(base_codec.base64_encrypt, "Base64 编码：文本 -> Base64 字符串。",
            [_data("待编码文本")], returns="str：Base64 字符串", example={"data": "flag"}),
    make_op(base_codec.base64_decrypt, "Base64 解码：Base64 字符串 -> 文本。",
            [_data("Base64 字符串")], returns="str：解码后的文本", example={"data": "ZmxhZw=="}),
    make_op(base_codec.base64_urlsafe_encrypt,
            "Base64 URL 安全编码：``+`` / ``/`` 换成 ``-`` / ``_``，常用于 URL 与 JWT。",
            [_data("待编码文本")], returns="str：URL 安全 Base64 字符串"),
    make_op(base_codec.base64_urlsafe_decrypt, "Base64 URL 安全解码。",
            [_data("URL 安全 Base64 字符串")], returns="str：解码后的文本"),
    make_op(base_codec.base85_encrypt, "Base85 编码（variant：b85 = RFC1924/Git，a85 = Adobe Ascii85）。",
            [_data("待编码文本"), txt("variant", default="b85", desc="Base85 变体", choices=_BASE85)],
            returns="str：Base85 字符串"),
    make_op(base_codec.base85_decrypt, "Base85 解码（variant：b85 / a85）。",
            [_data("Base85 字符串"), txt("variant", default="b85", desc="Base85 变体", choices=_BASE85)],
            returns="str：解码后的文本"),
    make_op(base_codec.base58_encrypt, "Base58 编码（Bitcoin 字母表，去掉了 0OIl）。",
            [_data("待编码文本")], returns="str：Base58 字符串"),
    make_op(base_codec.base58_decrypt, "Base58 解码（Bitcoin 字母表）。",
            [_data("Base58 字符串")], returns="str：解码后的文本"),
    make_op(base_codec.base62_encrypt, "Base62 编码（0-9A-Za-z）。",
            [_data("待编码文本")], returns="str：Base62 字符串"),
    make_op(base_codec.base62_decrypt, "Base62 解码（0-9A-Za-z）。",
            [_data("Base62 字符串")], returns="str：解码后的文本"),
    make_op(base_codec.base91_encrypt, "Base91 编码（basE91 标准字母表）。",
            [_data("待编码文本")], returns="str：Base91 字符串"),
    make_op(base_codec.base91_decrypt, "Base91 解码（basE91 标准字母表）。",
            [_data("Base91 字符串")], returns="str：解码后的文本"),
    make_op(base_codec.base92_encrypt, "Base92 编码（92 个可打印 ASCII 字符）。",
            [_data("待编码文本")], returns="str：Base92 字符串"),
    make_op(base_codec.base92_decrypt, "Base92 解码（92 个可打印 ASCII 字符）。",
            [_data("Base92 字符串")], returns="str：解码后的文本"),
    make_op(base_codec.uuencode_encrypt, "UUencode 编码（输出含 begin / end 包裹）。",
            [_data("待编码文本")], returns="str：uuencode 文本"),
    make_op(base_codec.uuencode_decrypt, "UUencode 解码。",
            [_data("uuencode 文本")], returns="str：解码后的文本"),
    make_op(base_codec.xxencode_encrypt, "XXencode 编码（字母表 ``+ - 0-9 A-Z a-z``）。",
            [_data("待编码文本")], returns="str：xxencode 文本"),
    make_op(base_codec.xxencode_decrypt, "XXencode 解码。",
            [_data("xxencode 文本")], returns="str：解码后的文本"),

    # -------------------------------------------------------- 字符 / 经典密码
    make_op(char_codec.caesar_encrypt, "凯撒加密：字母表右移 shift 位，非字母原样保留。",
            [_data("明文"), num("shift", required=True, desc="右移位数（可为负）")],
            returns="str：密文", example={"data": "flag", "shift": 3}),
    make_op(char_codec.caesar_decrypt, "凯撒解密：对密文反向移位 shift 位。",
            [_data("密文"), num("shift", required=True, desc="加密时使用的位移")],
            returns="str：明文"),
    make_op(char_codec.pigpen_encrypt, "猪圈密码加密：英文字母替换为猪圈符号，其余字符原样。",
            [_data("明文")], returns="str：猪圈符号密文"),
    make_op(char_codec.pigpen_decrypt, "猪圈密码解密：猪圈符号还原为大写字母。",
            [_data("猪圈符号密文")], returns="str：明文"),

    # ------------------------------------------------------------------ ROT
    make_op(rot_codec.rot13_encrypt, "ROT13：字母位移 13 位（自逆）。",
            [_data("文本")], returns="str：ROT13 结果", example={"data": "synt"}),
    make_op(rot_codec.rot13_decrypt, "ROT13 解密（与加密相同）。",
            [_data("文本")], returns="str：ROT13 结果"),
    make_op(rot_codec.rot47_encrypt, "ROT47：可打印 ASCII（33~126）位移 47 位（自逆）。",
            [_data("文本")], returns="str：ROT47 结果"),
    make_op(rot_codec.rot47_decrypt, "ROT47 解密（与加密相同）。",
            [_data("文本")], returns="str：ROT47 结果"),
    make_op(rot_codec.rot_n, "ROT-N：字母表位移任意位数（自逆，位移 26 的倍数还原原文）。",
            [_data("文本"), num("shift", required=True, desc="位移位数")],
            returns="str：ROT-N 结果"),

    # ---------------------------------------------------------------- 进制
    make_op(number_base_codec.convert, "任意进制互转（2~16 进制，可自定义大小写）。",
            [_data("待转换数值文本"), num("from_base", required=True, desc="源进制（2~16）",
                                          minimum=2, maximum=16),
             num("to_base", required=True, desc="目标进制（2~16）", minimum=2, maximum=16),
             flag("upper", default=True, desc="true=输出大写字母，false=小写")],
            returns="str：目标进制字符串",
            example={"data": "ff", "from_base": 16, "to_base": 10}),
    make_op(number_base_codec.bin_to_oct, "2 进制 -> 8 进制。", [_data("二进制字符串")],
            returns="str：八进制字符串"),
    make_op(number_base_codec.bin_to_dec, "2 进制 -> 10 进制。", [_data("二进制字符串")],
            returns="str：十进制字符串"),
    make_op(number_base_codec.bin_to_hex, "2 进制 -> 16 进制。", [_data("二进制字符串")],
            returns="str：十六进制字符串"),
    make_op(number_base_codec.oct_to_bin, "8 进制 -> 2 进制。", [_data("八进制字符串")],
            returns="str：二进制字符串"),
    make_op(number_base_codec.oct_to_dec, "8 进制 -> 10 进制。", [_data("八进制字符串")],
            returns="str：十进制字符串"),
    make_op(number_base_codec.oct_to_hex, "8 进制 -> 16 进制。", [_data("八进制字符串")],
            returns="str：十六进制字符串"),
    make_op(number_base_codec.dec_to_bin, "10 进制 -> 2 进制。", [_data("十进制字符串")],
            returns="str：二进制字符串"),
    make_op(number_base_codec.dec_to_oct, "10 进制 -> 8 进制。", [_data("十进制字符串")],
            returns="str：八进制字符串"),
    make_op(number_base_codec.dec_to_hex, "10 进制 -> 16 进制。", [_data("十进制字符串")],
            returns="str：十六进制字符串"),
    make_op(number_base_codec.hex_to_bin, "16 进制 -> 2 进制。", [_data("十六进制字符串")],
            returns="str：二进制字符串"),
    make_op(number_base_codec.hex_to_oct, "16 进制 -> 8 进制。", [_data("十六进制字符串")],
            returns="str：八进制字符串"),
    make_op(number_base_codec.hex_to_dec, "16 进制 -> 10 进制。", [_data("十六进制字符串")],
            returns="str：十进制字符串"),

    # ---------------------------------------------------------- 字符串编码
    make_op(string_codec.url_encode, "URL 编码：非 ``A-Za-z0-9_.-~`` 字符按 UTF-8 百分号转义。",
            [_data("待编码文本")], returns="str：URL 编码结果"),
    make_op(string_codec.url_decode, "URL 解码：``%XX`` 还原为 UTF-8 文本。",
            [_data("URL 编码文本")], returns="str：解码结果"),
    make_op(string_codec.url_encode_full, "URL 全编码：每个 UTF-8 字节都写成 ``%XX``。",
            [_data("待编码文本")], returns="str：全编码结果"),
    make_op(string_codec.str_to_ascii, "字符串转 ASCII 码：逐字符十进制码点，空格分隔。",
            [_data("文本")], returns="str：码点序列", example={"data": "flag"}),
    make_op(string_codec.ascii_to_str, "ASCII 码转字符串：接受十进制或 ``0x`` 十六进制码点。",
            [_data("码点序列，如 ``102 108 97 103``")], returns="str：还原文本"),
    make_op(string_codec.to_lower, "大写转小写（Unicode 规则，保留空白与换行）。",
            [_data("文本")], returns="str：小写文本"),
    make_op(string_codec.to_upper, "小写转大写（Unicode 规则，保留空白与换行）。",
            [_data("文本")], returns="str：大写文本"),
    make_op(string_codec.text_count, "文本字数统计：总字符 / 不含空白 / 单词 / 字母 / 数字 / 汉字 / 行数。",
            [_data("待统计文本"),
             obj("labels", default=dict(_COUNT_LABELS),
                 desc="标签映射，键固定为 total/no_space/words/letters/digits/cjk/lines")],
            returns="str：多行统计报告（``标签: 数值``）"),
    make_op(string_codec.quoted_printable_encode, "Quoted-printable 编码（``=XX`` 转义，行宽 ≤ 76）。",
            [_data("待编码文本")], returns="str：QP 文本"),
    make_op(string_codec.quoted_printable_decode, "Quoted-printable 解码。",
            [_data("QP 文本")], returns="str：还原文本"),
    make_op(string_codec.html_entity_encode,
            "HTML 实体编码：``< > & \"`` 与全部非 ASCII 字符转实体。",
            [_data("待编码文本")], returns="str：实体文本"),
    make_op(string_codec.html_entity_decode,
            "HTML 实体解码：命名实体与数字实体（``&#20013;`` / ``&#x4e2d;``）均支持。",
            [_data("实体文本")], returns="str：还原文本"),
    make_op(string_codec.unicode_escape_encode,
            "Unicode 转义编码：非 ASCII 写成 ``\\uXXXX`` / ``\\UXXXXXXXX``。",
            [_data("待编码文本")], returns="str：转义文本"),
    make_op(string_codec.unicode_escape_decode,
            "Unicode 转义解码：``\\uXXXX`` / ``\\UXXXXXXXX`` 还原。",
            [_data("转义文本")], returns="str：还原文本"),
    make_op(string_codec.gbk_to_utf16,
            "编码转换 GBK -> UTF-16LE：输入 GBK 字节的十六进制串，输出 UTF-16LE 字节的十六进制串。",
            [_data("GBK 字节的十六进制串")], returns="str：UTF-16LE 十六进制串"),
    make_op(string_codec.utf16_to_gbk,
            "编码转换 UTF-16LE -> GBK：输入 UTF-16LE 字节的十六进制串，输出 GBK 字节的十六进制串。",
            [_data("UTF-16LE 字节的十六进制串")], returns="str：GBK 十六进制串"),

    # ------------------------------------------------------------- 深奥语言
    make_op(esolang.brainfuck_exec, "执行 Brainfuck 程序，返回标准输出。",
            [txt("program", required=True, desc="Brainfuck 源码"),
             txt("input_text", desc="程序的标准输入（对应 ``,`` 指令）")],
            returns="str：程序输出", risk="safe",
            notes="有指令步数上限保护；死循环会被截断。"),
    make_op(esolang.ook_to_brainfuck, "Ook! 程序 -> Brainfuck 程序（纯翻译不执行）。",
            [txt("program", required=True, desc="Ook! 源码")],
            returns="str：等价 Brainfuck 源码"),
    make_op(esolang.ook_exec, "执行 Ook! 程序（先翻译为 Brainfuck）。",
            [txt("program", required=True, desc="Ook! 源码"),
             txt("input_text", desc="标准输入")], returns="str：程序输出"),
    make_op(esolang.jother_to_brainfuck, "jother 程序 -> Brainfuck 程序（纯翻译不执行）。",
            [txt("program", required=True, desc="jother 源码")],
            returns="str：等价 Brainfuck 源码"),
    make_op(esolang.jother_exec, "执行 jother 程序（提取 Brainfuck 指令后执行）。",
            [txt("program", required=True, desc="jother 源码"),
             txt("input_text", desc="标准输入")], returns="str：程序输出"),
    make_op(esolang.jsfuck_encode, "JS 代码 -> JSFuck（仅 ``[]()!+`` 六种字符）。",
            [txt("js_code", required=True, desc="待编码 JS 代码")],
            returns="str：JSFuck 代码"),
    make_op(esolang.jsfuck_decode, "JSFuck -> JS 代码（需要系统 ``node`` 可执行）。",
            [txt("jsfuck_code", required=True, desc="JSFuck 代码")],
            returns="str：还原的 JS 代码",
            notes="依赖宿主环境中的 node；缺失时报 unsupported。"),
]


GROUP = Group(
    name="cn_codec",
    title="编解码 / 进制 / 深奥语言",
    summary=("文本与编码互转：Base16/32/64/58/62/85/91/92、UUencode、XXencode、"
             "凯撒与猪圈、ROT13/47/N、任意进制互转、URL / QP / HTML / Unicode 转义、"
             "ASCII 码点、编码转换、Brainfuck / Ook! / jother / JSFuck。"),
    ops=OPS,
    guide=("全部为纯计算 op，无副作用。解码类 op 输入非法时返回 ok=false，"
           "错误码为 lib_error，message 里带原因。"),
)
