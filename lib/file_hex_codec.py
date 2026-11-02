# -*- coding: utf-8 -*-
"""文件 <-> 十六进制文本互转（纯逻辑，无 UI 依赖）。

CTF 中经常要把二进制文件转成十六进制文本（贴进文档 / 脚本 / 题解），
或把十六进制文本还原成文件（等价 ``xxd -r``）。本模块把这两件事收敛为
纯函数，界面层只负责收集参数与展示结果。

对外接口
--------
- :func:`bytes_to_hex`      字节 -> 十六进制文本（自定义分隔符 / 前缀 / 大小写 / 每行字节数）
- :func:`hex_to_bytes`      十六进制文本 -> 字节（分隔符可自动识别或自定义）
- :func:`file_to_hex`       文件 -> 十六进制文本（可只取前 N 字节做预览）
- :func:`write_hex_file`    文件 -> 十六进制文本文件（分块流式，适合大文件）
- :func:`hex_to_file`       十六进制文本 -> 文件
- :func:`hex_file_to_file`  十六进制文本文件 -> 文件（分块流式，等价 ``xxd -r -p``）
- :func:`unescape`          把 ``\\n`` / ``\\t`` 之类写法还原为真实字符

约定
----
``separator`` / ``prefix`` 都接受「转义写法」：传 ``"\\n"`` 表示换行、
``"\\t"`` 表示制表符、``"\\\\"`` 表示一个反斜杠；``"0x"`` 与 ``"\\x"``
按字面使用。解码时 ``separator`` 传 ``None`` 或空串表示**自动识别**
（忽略空白与 ``: - , ; _ | .`` 等常见分隔符），传非空字符串则只剥离该
分隔符（空白始终忽略）。

分隔符 / 前缀若只由十六进制字符组成（如 ``"ab"``），会与数据本身混淆导致
无法还原，因此一律拒绝并给出提示。
"""

from __future__ import annotations

import binascii
import os
import tempfile
from pathlib import Path


class FileHexError(ValueError):
    """文件 / 十六进制互转失败时抛出的统一异常，便于界面层统一捕获展示。"""


# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
#: 自动模式（``separator=None``）下额外忽略的常见分隔符字符
AUTO_SEPARATOR_CHARS = frozenset(":-,;_|.")
#: 任何模式下都忽略的空白字符
WHITESPACE_CHARS = frozenset(" \t\r\n\v\f")
#: 十六进制数字字符
HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
#: 任何模式下都当作「每字节前缀」剥掉的写法（``\x`` 指字面反斜杠 + x）
PREFIX_TOKENS = ("0x", "0X", "\\x", "\\X")
#: 允许用作分隔符 / 前缀的特例：本身由十六进制字符组成的固定写法
TOKEN_WHITELIST = frozenset(PREFIX_TOKENS)
#: 预览上限（256 KiB 数据约 512K 个十六进制字符，界面展示足够且不卡）
PREVIEW_BYTES = 256 * 1024
#: 流式读写的分块大小（4 MiB）
CHUNK_SIZE = 4 * 1024 * 1024
#: 流式解析时保留的原始尾部长度，避免把跨块的分隔符 / 前缀切断
RAW_TAIL = 16

#: 支持的转义写法（其余 ``\x`` 组合原样保留，如 ``\x`` 前缀）
_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", "0": "\0", "\\": "\\"}


# ---------------------------------------------------------------------------
# 一、辅助
# ---------------------------------------------------------------------------
def unescape(text: str) -> str:
    """把 ``\\n`` / ``\\r`` / ``\\t`` / ``\\0`` / ``\\\\`` 还原为真实字符。

    未知转义（如 ``\\x``）原样保留，这样 ``"\\x"`` 仍可作为「每字节前缀」使用。
    """
    if not isinstance(text, str):
        raise FileHexError("分隔符 / 前缀必须是字符串。")
    out: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text) and text[index + 1] in _ESCAPES:
            out.append(_ESCAPES[text[index + 1]])
            index += 2
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _check_token(token: str, label: str) -> str:
    """拒绝「只由十六进制字符组成」的分隔符 / 前缀，避免解码歧义。"""
    if token and token not in TOKEN_WHITELIST and any(c in HEX_DIGITS for c in token):
        raise FileHexError(
            f"{label} {token!r} 含十六进制字符（0-9 / A-F），会与数据本身混淆而"
            "无法还原；请改用空格、冒号、短横线、逗号等字符。"
        )
    return token


def _invalid_chars(text: str) -> str:
    """返回文本中所有非法十六进制字符（去重排序后的字符串）。"""
    return "".join(sorted({char for char in text if char not in HEX_DIGITS}))


def _check_digits(text: str, action: str, odd_ok: bool = False) -> None:
    """校验文本只含十六进制字符；``odd_ok=False`` 时还要求字符个数为偶数。"""
    invalid = _invalid_chars(text)
    if invalid:
        raise FileHexError(
            f"{action}失败：包含非十六进制字符 {invalid}。十六进制只允许 "
            "0-9、A-F（大小写均可）；若这些字符是分隔符，请在「分隔符」中声明。"
        )
    if not odd_ok and len(text) % 2:
        raise FileHexError(
            f"{action}失败：十六进制字符个数为奇数（{len(text)}），"
            "每个字节需要两位字符，请检查是否漏字符或多写了分隔符。"
        )


def _clean_hex(text: str, variants: tuple[str, ...] | None) -> str:
    """按分隔符规则剥离分隔符 / 前缀 / 空白，得到纯十六进制字符。

    ``variants`` 是分隔符的匹配变体（原始写法 + 转义还原后的真实字符），
    ``None`` 或空元组表示「自动识别」模式。
    """
    for token in variants or ():
        text = text.replace(token, "")
    for token in PREFIX_TOKENS:
        text = text.replace(token, "")
    drop = (AUTO_SEPARATOR_CHARS | WHITESPACE_CHARS) if not variants \
        else WHITESPACE_CHARS
    return "".join(char for char in text if char not in drop)


def _resolve_separator(separator: str | None, action: str) -> tuple[str, ...] | None:
    """把界面传入的分隔符转义写法还原，返回可匹配的变体元组。

    - ``None`` 或空串 -> ``None``，表示「自动识别」；
    - 其余 -> ``(原始写法, 转义还原后的字符)``：用户填 ``\\n`` 时，既能匹配
      文本里真实的换行，也能匹配字面写的 ``\\n``，避免「转义过了头」的坑。

    分隔符只由十六进制字符组成时（如 ``"ab"``）会与数据混淆，一律拒绝。
    """
    if separator is None:
        return None
    unescaped = _check_token(unescape(separator), "分隔符")
    if not unescaped:
        return None
    raw = _check_token(separator, "分隔符")
    # 去重且保持顺序：raw 与 unescaped 相同时只留一个
    return tuple(dict.fromkeys((raw, unescaped)))


# ---------------------------------------------------------------------------
# 二、字节 <-> 十六进制文本
# ---------------------------------------------------------------------------
def bytes_to_hex(data: bytes | bytearray,
                 separator: str = "",
                 prefix: str = "",
                 uppercase: bool = True,
                 bytes_per_line: int = 0) -> str:
    """把字节串渲染为十六进制文本。

    separator      字节之间的分隔符（转义写法，默认无）
    prefix         每个字节前的前缀，如 ``"0x"`` / ``"\\x"`` / ``"%"``
    uppercase      十六进制字母是否大写
    bytes_per_line 每行字节数，``0`` 表示不按行分组
    """
    sep = _check_token(unescape(separator), "分隔符")
    pre = _check_token(unescape(prefix), "前缀")
    if bytes_per_line < 0:
        raise FileHexError("每行字节数不能为负数。")
    if not data:
        return ""

    if bytes_per_line:
        rows = [data[start:start + bytes_per_line]
                for start in range(0, len(data), bytes_per_line)]
    else:
        rows = [bytes(data)]

    lines: list[str] = []
    for row in rows:
        digits = bytes(row).hex()
        if uppercase:
            digits = digits.upper()
        lines.append(sep.join(
            pre + digits[i:i + 2] for i in range(0, len(digits), 2)))
    return "\n".join(lines)


def hex_to_bytes(text: str, separator: str | None = None) -> bytes:
    """把十六进制文本还原为字节；非法输入抛 :class:`FileHexError`。

    ``separator=None``（默认）自动识别常见分隔符；传字符串则只剥离该分隔符。
    """
    if not isinstance(text, str):
        raise FileHexError("十六进制输入必须是字符串。")
    sep = _resolve_separator(separator, "十六进制转字节")
    cleaned = _clean_hex(text, sep)
    if not cleaned:
        raise FileHexError("十六进制内容为空，请先输入待转换的数据。")
    _check_digits(cleaned, "十六进制转字节")
    try:
        return binascii.unhexlify(cleaned)
    except (binascii.Error, ValueError) as exc:  # pragma: no cover  兜底
        raise FileHexError(f"十六进制转字节失败：{exc}") from exc


# ---------------------------------------------------------------------------
# 三、文件 <-> 十六进制
# ---------------------------------------------------------------------------
def file_to_hex(path: str | Path,
                separator: str = "",
                prefix: str = "",
                uppercase: bool = True,
                bytes_per_line: int = 0,
                limit: int | None = None) -> tuple[str, int, bool]:
    """读取文件并渲染为十六进制文本。

    返回 ``(文本, 文件总字节数, 是否被 limit 截断)``；``limit`` 用于只取
    前若干字节做界面预览，完整转换请用 :func:`write_hex_file`。
    """
    src = Path(path)
    if not src.is_file():
        raise FileHexError(f"文件不存在：{src}")
    size = src.stat().st_size
    with open(src, "rb") as fh:
        data = fh.read() if limit is None else fh.read(int(limit))
    text = bytes_to_hex(data, separator=separator, prefix=prefix,
                        uppercase=uppercase, bytes_per_line=bytes_per_line)
    truncated = limit is not None and size > len(data)
    return text, size, truncated


def write_hex_file(path: str | Path,
                   out_path: str | Path,
                   separator: str = "",
                   prefix: str = "",
                   uppercase: bool = True,
                   bytes_per_line: int = 0) -> tuple[Path, int, int]:
    """把文件转成十六进制文本文件（分块流式，内存占用与文件大小无关）。

    返回 ``(输出路径, 输入字节数, 输出字符数)``。
    """
    src = Path(path)
    if not src.is_file():
        raise FileHexError(f"文件不存在：{src}")
    sep = _check_token(unescape(separator), "分隔符")
    pre = _check_token(unescape(prefix), "前缀")
    if bytes_per_line < 0:
        raise FileHexError("每行字节数不能为负数。")

    # 按行分组时，块大小取「每行字节数」的整数倍，保证每块都是完整行
    block = CHUNK_SIZE
    if bytes_per_line:
        block = bytes_per_line * max(1, CHUNK_SIZE // bytes_per_line)
    # 块与块之间的连接符：有行结构用换行，否则用分隔符本身
    line_based = bytes_per_line > 0 or "\n" in sep
    joiner = "\n" if line_based else sep

    dst = Path(out_path)
    dst.parent.mkdir(parents=True, exist_ok=True)
    total = 0
    chars = 0
    first = True
    with open(src, "rb") as fin, open(dst, "w", encoding="utf-8", newline="") as fout:
        while True:
            data = fin.read(block)
            if not data:
                break
            text = bytes_to_hex(data, separator=sep, prefix=pre,
                                uppercase=uppercase, bytes_per_line=bytes_per_line)
            if not first and joiner:
                fout.write(joiner)
            fout.write(text)
            total += len(data)
            chars += len(text) + (len(joiner) if not first else 0)
            first = False
    return dst, total, chars


def hex_to_file(text: str,
                out_path: str | Path,
                separator: str | None = None) -> tuple[Path, int]:
    """把十六进制文本解码并写出为文件，返回 ``(输出路径, 字节数)``。"""
    data = hex_to_bytes(text, separator=separator)
    dst = Path(out_path)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(data)
    return dst, len(data)


def hex_file_to_file(src_path: str | Path,
                     out_path: str | Path,
                     separator: str | None = None) -> tuple[Path, int]:
    """把十六进制文本文件解码为二进制文件（分块流式，等价 ``xxd -r -p``）。

    先写同目录临时文件，全部解析成功后再原子替换目标文件；中途出错会删除
    临时文件，不会留下半截结果。返回 ``(输出路径, 字节数)``。
    """
    src = Path(src_path)
    if not src.is_file():
        raise FileHexError(f"文件不存在：{src}")
    sep = _resolve_separator(separator, "十六进制文件转字节")
    dst = Path(out_path)
    dst.parent.mkdir(parents=True, exist_ok=True)

    #: 每块保留的原始尾部长度：至少要能容下「最长分隔符 / 0x 前缀」，
    #: 否则跨块边界的分隔符会被切断，多出的字符变成非法十六进制字符
    tail_len = max(RAW_TAIL, max((len(v) for v in sep or ()), default=0) + 2)

    total = 0
    pending = ""   # 跨块残留的半个字节（奇数个字符）

    def _flush(fout, text: str) -> int:
        """把一段原始文本清洗、校验并写入；返回本次写入的字节数。"""
        nonlocal pending
        cleaned = pending + _clean_hex(text, sep)
        _check_digits(cleaned, "十六进制文件转字节", odd_ok=True)
        if len(cleaned) % 2:
            pending, cleaned = cleaned[-1], cleaned[:-1]
        else:
            pending = ""
        if cleaned:
            fout.write(binascii.unhexlify(cleaned))
            return len(cleaned) // 2
        return 0

    with open(src, "r", encoding="utf-8-sig") as fin:
        fd, tmp = tempfile.mkstemp(
            dir=str(dst.parent), prefix=".hex-", suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as fout:
                tail = ""
                while True:
                    raw = fin.read(CHUNK_SIZE)
                    if not raw:
                        break
                    buffer = tail + raw
                    if len(buffer) > tail_len:
                        buffer, tail = buffer[:-tail_len], buffer[-tail_len:]
                    else:
                        buffer, tail = "", buffer
                    total += _flush(fout, buffer)

                # 收尾：处理保留的尾部与残留的半个字节
                total += _flush(fout, tail)
                if pending:
                    raise FileHexError(
                        "十六进制文件转字节失败：十六进制字符个数为奇数，"
                        "每个字节需要两位字符，请检查文件末尾是否被截断。"
                    )
                if total == 0:
                    raise FileHexError("文件中没有解析到有效的十六进制数据。")
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        try:
            os.replace(tmp, dst)
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    return dst, total


# ---------------------------------------------------------------------------
# 四、自检（``python lib/file_hex_codec.py``）
# ---------------------------------------------------------------------------
def _self_test() -> None:
    """官方风格自检：格式渲染、分隔符解析、文件往返全部对齐。"""
    # -- 渲染 --
    assert bytes_to_hex(b"AB") == "4142"
    assert bytes_to_hex(b"AB", separator=":") == "41:42"
    assert bytes_to_hex(b"AB", separator=", ", prefix="0x") == "0x41, 0x42"
    assert bytes_to_hex(b"\xab\xcd", uppercase=False) == "abcd"
    assert bytes_to_hex(b"\xab\xcd") == "ABCD"
    assert bytes_to_hex(b"", separator=":") == ""
    assert bytes_to_hex(bytes(range(20)), separator=" ", bytes_per_line=16) == (
        "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n"
        "10 11 12 13"
    )
    assert bytes_to_hex(b"AB", separator="\\n") == "41\n42"
    assert bytes_to_hex(b"AB", separator="\\t") == "41\t42"

    # -- 转义 --
    assert unescape("\\n") == "\n"
    assert unescape("\\t") == "\t"
    assert unescape("\\\\") == "\\"
    assert unescape("\\x") == "\\x"      # 未知转义原样保留
    assert unescape(":") == ":"

    # -- 解析：自动识别 --
    assert hex_to_bytes("41 42") == b"AB"
    assert hex_to_bytes("41:42") == b"AB"
    assert hex_to_bytes("41-42") == b"AB"
    assert hex_to_bytes("41,42") == b"AB"
    assert hex_to_bytes("0x41,0x42") == b"AB"
    assert hex_to_bytes("\\x41\\x42") == b"AB"
    assert hex_to_bytes("41\n42\n") == b"AB"
    assert hex_to_bytes("  4142  ") == b"AB"

    # -- 解析：自定义分隔符（空串等同「自动识别」） --
    assert hex_to_bytes("41:42", separator=":") == b"AB"
    assert hex_to_bytes("41 | 42", separator=" | ") == b"AB"
    assert hex_to_bytes("41:42", separator="") == b"AB"
    assert hex_to_bytes("41_42", separator="_") == b"AB"
    assert hex_to_bytes("41\\n42", separator="\\n") == b"AB"

    # -- 解析：异常 --
    for bad, kwargs in (
        ("", {}),
        ("   ", {}),
        ("414", {}),                 # 奇数长度
        ("41 4", {}),                # 奇数长度
        ("41zz", {}),                # 非法字符
        ("41-42", {"separator": ":"}),  # 声明了分隔符 : 却混入 -
    ):
        try:
            hex_to_bytes(bad, **kwargs)
        except FileHexError:
            pass
        else:  # pragma: no cover
            raise AssertionError(f"应当报错：{bad!r} {kwargs!r}")

    try:
        hex_to_bytes("4142", separator="ab")   # 分隔符含十六进制字符
    except FileHexError:
        pass
    else:  # pragma: no cover
        raise AssertionError("分隔符含十六进制字符时应当报错")

    try:
        bytes_to_hex(b"AB", separator="41")
    except FileHexError:
        pass
    else:  # pragma: no cover
        raise AssertionError("渲染时非法分隔符应当报错")

    # -- 文件往返 --
    tmpdir = Path(tempfile.mkdtemp(prefix="filehex-selftest-"))
    try:
        blob = os.urandom(3000) + bytes(range(256))
        src = tmpdir / "sample.bin"
        src.write_bytes(blob)

        # 内存往返：小写 + 空格分隔 + 前缀
        text, size, truncated = file_to_hex(
            src, separator=" ", prefix="0x", uppercase=False)
        assert size == len(blob) and not truncated
        assert hex_to_bytes(text) == blob
        assert hex_to_bytes(text, separator=" ") == blob

        # 预览截断
        preview, size, truncated = file_to_hex(src, limit=1024)
        assert size == len(blob) and truncated and len(preview) == 1024 * 2
        assert hex_to_bytes(preview) == blob[:1024]

        # 流式写出 / 流式读回：每行 16 字节 + 冒号分隔
        hex_path, total, chars = write_hex_file(
            src, tmpdir / "sample.hex", separator=":", bytes_per_line=16)
        assert total == len(blob) and chars > 0
        back, count = hex_file_to_file(hex_path, tmpdir / "roundtrip.bin")
        assert count == len(blob) and back.read_bytes() == blob

        # 流式：无分隔符（``xxd -p`` 风格）
        plain = tmpdir / "plain.hex"
        write_hex_file(src, plain)
        assert plain.read_text(encoding="utf-8") == blob.hex().upper()
        assert hex_file_to_file(plain, tmpdir / "plain.bin")[1] == len(blob)

        # 流式：换行分隔（每字节一行）
        lines = tmpdir / "lines.hex"
        write_hex_file(src, lines, separator="\\n")
        assert hex_file_to_file(lines, tmpdir / "lines.bin")[1] == len(blob)
        assert (tmpdir / "lines.bin").read_bytes() == blob

        # 文本 -> 文件
        out, count = hex_to_file(blob.hex(), tmpdir / "text.bin")
        assert count == len(blob) and out.read_bytes() == blob

        # 空文件
        empty = tmpdir / "empty.bin"
        empty.write_bytes(b"")
        assert file_to_hex(empty) == ("", 0, False)

        # 非法十六进制文件：不留下半截输出
        bad = tmpdir / "bad.hex"
        bad.write_text("4142zz", encoding="utf-8")
        target = tmpdir / "bad.bin"
        try:
            hex_file_to_file(bad, target)
        except FileHexError:
            pass
        else:  # pragma: no cover
            raise AssertionError("非法十六进制文件应当报错")
        assert not target.exists(), "失败时不应留下输出文件"
        assert not list(tmpdir.glob(".hex-*.tmp")), "失败时应清理临时文件"
    finally:
        for item in tmpdir.rglob("*"):
            if item.is_file():
                item.unlink()
        tmpdir.rmdir()

    print("file_hex_codec 自检通过：渲染 / 解析 / 文件往返全部匹配。")


if __name__ == "__main__":
    _self_test()
