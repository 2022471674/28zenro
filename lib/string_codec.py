# -*- coding: utf-8 -*-
"""字符串编码工具纯逻辑模块（URL / ASCII / 大小写 / 字数统计）。

本模块只做「字符串进、字符串出」的纯计算：不导入 tkinter 等任何 UI 模块，
也不拼接界面文案——需要分区标题、统计标签的地方由调用方通过 ``labels``
传入，文案统一来自 ``.env``；失败时统一抛 :class:`CodecError`
（``ValueError`` 子类），由界面层的 ``CryptoApp._run_codec`` 捕获后加
``[前缀]`` 展示。

对外接口：
    url_encode(data)                   URL 编码（UTF-8 百分号转义，空格 -> %20）
    url_decode(data)                   URL 解码（校验 %XX 转义完整性与 UTF-8）
    str_to_ascii(data)                 字符串 -> 十进制码点，空格分隔
    ascii_to_str(data)                 十进制 / 0x 十六进制码点 -> 字符串
    to_lower(data) / to_upper(data)    大小写互转
    text_count(data, labels)           文本字数统计（多行报告）

输入容忍度：
    - URL / ASCII 入口先去除首尾空白，便于直接粘贴带换行的内容；
    - 大小写互转与字数统计保留原文（含首尾空白与换行），避免改变统计口径。
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from urllib.parse import quote, unquote

# ---------------------------------------------------------------------------
# 一、统一异常与文案标签键
# ---------------------------------------------------------------------------
#: 文本字数统计的标签键，元组顺序即报告的输出顺序（文案由界面层传入）
COUNT_LABEL_KEYS = ("total", "no_space", "words", "letters", "digits", "cjk", "lines")


class CodecError(ValueError):
    """字符串编码工具处理失败时抛出的统一异常，便于界面层统一捕获并展示提示。"""


# ---------------------------------------------------------------------------
# 二、内部工具
# ---------------------------------------------------------------------------
def _check_input(data, action: str, strip: bool = True) -> str:
    """校验输入必须是字符串且非空，返回（可选去首尾空白后的）内容。"""
    if not isinstance(data, str):
        raise CodecError(
            f"{action}失败：输入必须是字符串，当前类型为 {type(data).__name__}。"
        )
    text = data.strip() if strip else data
    if not text.strip():
        raise CodecError(f"{action}失败：输入内容为空，请先填写待处理的数据。")
    return text


def _label(labels, key: str) -> str:
    """从界面层传入的标签映射里取文案；缺失说明配置漏项，直接报错。"""
    if not isinstance(labels, Mapping) or key not in labels:
        raise CodecError(f"缺少界面文案配置：labels 中未提供 {key!r}。")
    return str(labels[key])


#: 不完整的百分号转义：% 后面不是两位十六进制
_BAD_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")
#: ASCII 码串的分隔符：空白 / 中英文逗号 / 分号 / 竖线
_CODE_SEPARATORS = re.compile(r"[\s,，;；|]+")
#: 十进制码点 / 0x 前缀十六进制码点
_DECIMAL_CODE = re.compile(r"[0-9]+")
_HEX_CODE = re.compile(r"0[xX][0-9A-Fa-f]+")
#: 单词 / 字母 / 数字 / 中日韩汉字
_WORD = re.compile(r"[A-Za-z0-9_]+")
_LETTER = re.compile(r"[A-Za-z]")
_DIGIT = re.compile(r"[0-9]")
_CJK = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff]")


# ---------------------------------------------------------------------------
# 三、URL 编码 / 解码
# ---------------------------------------------------------------------------
def url_encode(data: str) -> str:
    """URL 编码：除 ``A-Za-z0-9_.-~`` 外的字符一律按 UTF-8 百分号转义。"""
    text = _check_input(data, "URL 编码")
    try:
        return quote(text, safe="", encoding="utf-8", errors="strict")
    except (UnicodeEncodeError, UnicodeDecodeError) as exc:
        raise CodecError(f"URL 编码失败：{exc}") from exc


def url_decode(data: str) -> str:
    """URL 解码：先校验 ``%XX`` 转义是否完整，再按 UTF-8 还原文本。"""
    text = _check_input(data, "URL 解码")

    bad = _BAD_PERCENT.search(text)
    if bad:
        fragment = text[bad.start(): bad.start() + 3]
        raise CodecError(
            f"URL 解码失败：存在不完整的百分号转义「{fragment}」，"
            "% 后必须紧跟两位十六进制数（如 %20 表示空格）。"
        )

    try:
        return unquote(text, encoding="utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise CodecError(
            f"URL 解码失败：百分号转义还原出的字节不是合法的 UTF-8 文本（{exc}）。"
        ) from exc


def url_encode_full(data: str) -> str:
    """URL 全编码（含英文）：UTF-8 字节流里的每个字节都写成 ``%XX``。

    与 :func:`url_encode` 的区别：``url_encode`` 保留 ``A-Za-z0-9_.-~``，
    本函数连英文字母与数字也一并转义（如 ``hello`` -> ``%68%65%6C%6C%6F``），
    常用于 CTF 里需要把整段内容（包括英文）都百分号转义的场景。
    """
    text = _check_input(data, "URL 全编码")
    try:
        raw = text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CodecError(f"URL 全编码失败：{exc}") from exc
    return "".join(f"%{byte:02X}" for byte in raw)


# ---------------------------------------------------------------------------
# 四、字符串 <-> ASCII 码
# ---------------------------------------------------------------------------
def str_to_ascii(data: str) -> str:
    """字符串转 ASCII 码：逐字符输出十进制码点，用空格分隔。

    非 ASCII 字符（如中文）按 Unicode 码点输出（如「中」-> 20013）。
    """
    text = _check_input(data, "字符串转 ASCII")
    return " ".join(str(ord(char)) for char in text)


def ascii_to_str(data: str) -> str:
    """ASCII 码转字符串：接受十进制（``72 101``）或 ``0x`` 前缀十六进制（``0x48``）。

    多个码点之间可用空格、中英文逗号、分号或竖线分隔。
    """
    text = _check_input(data, "ASCII 转字符串")
    tokens = [token for token in _CODE_SEPARATORS.split(text) if token]
    if not tokens:
        raise CodecError(
            "ASCII 转字符串失败：未解析出任何数字，请用空格、逗号或分号分隔多个码点。"
        )

    chars = []
    for token in tokens:
        if _DECIMAL_CODE.fullmatch(token):
            code = int(token, 10)
        elif _HEX_CODE.fullmatch(token):
            code = int(token, 16)
        else:
            raise CodecError(
                f"ASCII 转字符串失败：无法识别的码点「{token}」，"
                "仅支持十进制整数（如 65）或 0x 前缀十六进制（如 0x41），"
                "多个码点请用空格、逗号或分号分隔。"
            )
        if not 0 <= code <= 0x10FFFF or 0xD800 <= code <= 0xDFFF:
            raise CodecError(
                f"ASCII 转字符串失败：码点 {code} 超出合法范围，"
                "可用范围为 0~1114111（其中 55296~57343 为代理区，不能单独使用）。"
            )
        chars.append(chr(code))
    return "".join(chars)


# ---------------------------------------------------------------------------
# 五、大小写互转
# ---------------------------------------------------------------------------
def to_lower(data: str) -> str:
    """大写转小写：按 Unicode 大小写规则整篇转换，保留原文空白与换行。"""
    return _check_input(data, "大写转小写", strip=False).lower()


def to_upper(data: str) -> str:
    """小写转大写：按 Unicode 大小写规则整篇转换，保留原文空白与换行。"""
    return _check_input(data, "小写转大写", strip=False).upper()


# ---------------------------------------------------------------------------
# 六、文本字数统计
# ---------------------------------------------------------------------------
def text_count(data: str, labels) -> str:
    """文本字数统计：返回多行报告，每行形如「标签: 数值」。

    统计口径：
        total     总字符数（含空白与换行）
        no_space  不含空白字符的字符数
        words     单词数（连续英文字母 / 数字 / 下划线算一个词）
        letters   英文字母个数（A-Z / a-z）
        digits    阿拉伯数字个数（0-9）
        cjk       中日韩汉字个数
        lines     行数（按换行符切分）
    """
    text = _check_input(data, "文本字数统计", strip=False)
    stats = {
        "total": len(text),
        "no_space": sum(1 for char in text if not char.isspace()),
        "words": len(_WORD.findall(text)),
        "letters": len(_LETTER.findall(text)),
        "digits": len(_DIGIT.findall(text)),
        "cjk": len(_CJK.findall(text)),
        "lines": len(text.splitlines()),
    }
    return "\n".join(f"{_label(labels, key)}: {stats[key]}" for key in COUNT_LABEL_KEYS)


# ---------------------------------------------------------------------------
# 七、Quoted-printable
# ---------------------------------------------------------------------------
def quoted_printable_encode(data: str) -> str:
    """Quoted-printable 编码：非 ASCII / 特殊字符按 ``=XX`` 转义，行宽 ≤ 76。"""
    import quopri
    text = _check_input(data, "Quoted-printable 编码", strip=False)
    try:
        return quopri.encodestring(
            text.encode("utf-8"), quotetabs=False, header=False).decode("ascii")
    except (UnicodeEncodeError, UnicodeDecodeError) as exc:
        raise CodecError(f"Quoted-printable 编码失败：{exc}") from exc


def quoted_printable_decode(data: str) -> str:
    """Quoted-printable 解码：把 ``=XX`` 转义还原为 UTF-8 文本。"""
    import quopri
    text = _check_input(data, "Quoted-printable 解码", strip=False)
    try:
        raw = quopri.decodestring(text.encode("ascii", errors="surrogateescape"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise CodecError(f"Quoted-printable 解码失败：{exc}") from exc
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CodecError(f"Quoted-printable 解码失败：还原字节不是合法 UTF-8（{exc}）。") from exc


# ---------------------------------------------------------------------------
# 八、HTML 实体
# ---------------------------------------------------------------------------
def html_entity_encode(data: str) -> str:
    """HTML 实体编码：把 ``<`` / ``>`` / ``&`` / ``\"`` 与全部非 ASCII 字符转成实体。

    非 ASCII 字符使用十进制码点实体（``&#20013;``），ASCII 特殊字符用命名实体。
    """
    import html
    text = _check_input(data, "HTML 实体编码", strip=False)
    out = []
    for char in text:
        if char == "<":
            out.append("&lt;")
        elif char == ">":
            out.append("&gt;")
        elif char == "&":
            out.append("&amp;")
        elif char == '"':
            out.append("&quot;")
        elif ord(char) > 126:
            out.append(f"&#{ord(char)};")
        else:
            out.append(char)
    return "".join(out)


def html_entity_decode(data: str) -> str:
    """HTML 实体解码：把命名实体（``&lt;``）与数字实体（``&#20013;`` / ``&#x4e2d;``）还原。"""
    import html
    text = _check_input(data, "HTML 实体解码", strip=False)
    return html.unescape(text)


# ---------------------------------------------------------------------------
# 九、Unicode 转义（\\uXXXX）
# ---------------------------------------------------------------------------
def unicode_escape_encode(data: str) -> str:
    """Unicode 转义编码：非 ASCII 字符写成 ``\\uXXXX``（或 ``\\UXXXXXXXX``）。"""
    text = _check_input(data, "Unicode 转义编码", strip=False)
    out = []
    for char in text:
        code = ord(char)
        if code < 128:
            out.append(char)
        elif code <= 0xFFFF:
            out.append(f"\\u{code:04x}")
        else:
            out.append(f"\\U{code:08x}")
    return "".join(out)


def unicode_escape_decode(data: str) -> str:
    """Unicode 转义解码：把 ``\\uXXXX`` / ``\\UXXXXXXXX`` 还原为文本。"""
    text = _check_input(data, "Unicode 转义解码", strip=False)
    # 用 codecs 的 unicode_escape 解码，但需先按 UTF-8 取字节避免中文被误转
    try:
        raw = text.encode("utf-8").decode("unicode_escape")
    except UnicodeDecodeError as exc:
        raise CodecError(f"Unicode 转义解码失败：{exc}") from exc
    # unicode_escape 会把中文按 latin-1 逐个字节转义，需再按 UTF-8 还原
    try:
        return raw.encode("latin-1").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return raw


# ---------------------------------------------------------------------------
# 十、GBK · UTF-16 互转（十六进制字节串）
# ---------------------------------------------------------------------------
def _hex_to_bytes(text: str, action: str) -> bytes:
    """把十六进制字符串（可带空格 / 0x 前缀 / 换行）解析为字节。"""
    cleaned = text.replace(" ", "").replace("\n", "").replace("\r", "")
    cleaned = cleaned.replace("\t", "").replace("0x", "").replace("0X", "")
    cleaned = cleaned.replace("-", "").replace(":", "")
    if not cleaned:
        raise CodecError(f"{action}失败：去掉分隔符后内容为空。")
    if len(cleaned) % 2 != 0:
        raise CodecError(f"{action}失败：十六进制字符个数为奇数，请检查输入。")
    invalid = sorted({c for c in cleaned if c not in "0123456789abcdefABCDEF"})
    if invalid:
        raise CodecError(f"{action}失败：含非十六进制字符 {''.join(invalid)}。")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise CodecError(f"{action}失败：{exc}") from exc


def _bytes_to_hex(raw: bytes) -> str:
    return raw.hex()


def gbk_to_utf16(data: str) -> str:
    """GBK -> UTF-16：输入 GBK 编码字节的十六进制串，输出 UTF-16-LE 字节的十六进制串。"""
    raw = _hex_to_bytes(data, "GBK 转 UTF-16")
    try:
        text = raw.decode("gbk")
    except UnicodeDecodeError as exc:
        raise CodecError(f"GBK 转 UTF-16 失败：字节不是合法 GBK（{exc}）。") from exc
    return _bytes_to_hex(text.encode("utf-16-le"))


def utf16_to_gbk(data: str) -> str:
    """UTF-16 -> GBK：输入 UTF-16-LE 字节的十六进制串，输出 GBK 编码字节的十六进制串。"""
    raw = _hex_to_bytes(data, "UTF-16 转 GBK")
    try:
        text = raw.decode("utf-16-le")
    except UnicodeDecodeError as exc:
        raise CodecError(f"UTF-16 转 GBK 失败：字节不是合法 UTF-16-LE（{exc}）。") from exc
    try:
        return _bytes_to_hex(text.encode("gbk"))
    except UnicodeEncodeError as exc:
        raise CodecError(f"UTF-16 转 GBK 失败：字符无法用 GBK 表示（{exc}）。") from exc
