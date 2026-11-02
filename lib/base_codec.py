from __future__ import annotations

import base64
import binascii


# ===========================================================================
# BaseX 系列
# ===========================================================================
class CodecError(ValueError):
    """编码/解码失败时抛出的统一异常，便于界面层统一捕获并弹出提示。"""


def _check_input(data: str, action: str) -> str:
    """校验输入必须是字符串，并返回去首尾空白后的内容。"""
    if not isinstance(data, str):
        raise CodecError(
            f"{action}失败：输入必须是字符串，当前类型为 {type(data).__name__}。"
        )
    text = data.strip()
    if not text:
        raise CodecError(f"{action}失败：输入内容为空，请先填写待处理的数据。")
    return text


def _to_text(raw: bytes) -> str:
    """把解码得到的字节流还原为文本，并给出可读的解码失败提示。"""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CodecError(
            f"解码失败：还原出的字节不是合法的 UTF-8 文本（{exc}）。"
            "请确认输入是否为该编码格式，或原始内容是否包含二进制数据。"
        ) from exc



def base16_encrypt(data: str) -> str:
    text = _check_input(data, "Base16 编码")
    try:
        return binascii.hexlify(text.encode("utf-8")).decode("ascii").upper()
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise CodecError(f"Base16 编码失败：{exc}") from exc


def base16_decrypt(data: str) -> str:
    text = _check_input(data, "Base16 解码")

    normalized = text
    if normalized[:2].lower() == "0x":
        normalized = normalized[2:]
    normalized = normalized.replace(" ", "").replace("\t", "")
    normalized = normalized.replace("\n", "").replace("\r", "")
    normalized = normalized.replace("-", "").replace(":", "")

    if not normalized:
        raise CodecError("Base16 解码失败：去掉分隔符后内容为空，请检查输入。")

    if len(normalized) % 2 != 0:
        raise CodecError(
            f"Base16 解码失败：十六进制字符个数为奇数（{len(normalized)}），"
            "每个字节需要两位十六进制字符，请检查是否遗漏字符。"
        )

    invalid = sorted({c for c in normalized if c not in "0123456789abcdefABCDEF"})
    if invalid:
        raise CodecError(
            "Base16 解码失败：输入包含非十六进制字符 "
            f"{''.join(invalid)}。十六进制只允许 0-9、A-F（大小写均可）。"
        )

    try:
        raw = binascii.unhexlify(normalized.encode("ascii"))
    except (binascii.Error, ValueError) as exc:
        raise CodecError(f"Base16 解码失败：{exc}") from exc

    return _to_text(raw)


def base32_encrypt(data: str) -> str:
    """Base32 编码：文本 -> Base32 字符串。"""
    text = _check_input(data, "Base32 编码")
    try:
        return base64.b32encode(text.encode("utf-8")).decode()
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise CodecError(f"Base32 编码失败：{exc}") from exc


def base32_decrypt(data: str) -> str:
    """Base32 解码：Base32 字符串 -> 文本；非法输入抛 ``CodecError``。"""
    text = _check_input(data, "Base32 解码")
    # Base32 长度须为 8 的倍数，自动补齐缺失的 '=' 填充
    padded = text.upper() + "=" * (-len(text) % 8)
    try:
        raw = base64.b32decode(padded.encode())
    except (binascii.Error, ValueError) as exc:
        raise CodecError(
            f"Base32 解码失败：输入不是合法的 Base32 字符串（{exc}）。"
            "Base32 只允许 A-Z 与 2-7，请检查是否含空格、换行或非法字符。"
        ) from exc
    return _to_text(raw)


def base64_encrypt(data: str) -> str:
    """Base64 编码：文本 -> Base64 字符串。"""
    text = _check_input(data, "Base64 编码")
    try:
        return base64.b64encode(text.encode("utf-8")).decode()
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise CodecError(f"Base64 编码失败：{exc}") from exc


def base64_decrypt(data: str) -> str:
    """Base64 解码：Base64 字符串 -> 文本；非法输入抛 ``CodecError``。"""
    text = _check_input(data, "Base64 解码")
    # 自动补齐缺失的 '=' 填充，容忍常见的复制粘贴截断
    padded = text + "=" * (-len(text) % 4)
    try:
        raw = base64.b64decode(padded.encode())
    except (binascii.Error, ValueError) as exc:
        raise CodecError(
            f"Base64 解码失败：输入不是合法的 Base64 字符串（{exc}）。"
            "请检查长度是否为 4 的倍数、是否包含非法字符。"
        ) from exc
    return _to_text(raw)



def base64_urlsafe_encrypt(data: str) -> str:
    """Base64 URL 安全编码：把 ``+`` / ``/`` 替换为 ``-`` / ``_``，常用于 URL 与 JWT。"""
    text = _check_input(data, "Base64 URL-safe 编码")
    try:
        return base64.urlsafe_b64encode(text.encode("utf-8")).decode()
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise CodecError(f"Base64 URL-safe 编码失败：{exc}") from exc


def base64_urlsafe_decrypt(data: str) -> str:
    """Base64 URL 安全解码；非法输入抛 ``CodecError``。"""
    text = _check_input(data, "Base64 URL-safe 解码")
    padded = text + "=" * (-len(text) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode())
    except (binascii.Error, ValueError) as exc:
        raise CodecError(
            f"Base64 URL-safe 解码失败：输入不是合法的 URL-safe Base64 字符串（{exc}）。"
            "该变体只允许 A-Z、a-z、0-9、'-' 与 '_'。"
        ) from exc
    return _to_text(raw)


# ===========================================================================
# 一、Base58 / Base85 / Base91
# ===========================================================================
# 标准库只覆盖 Base16 / Base32 / Base64 / Base85 中的部分变体，Base58 与 Base91
# 需按各自的字母表自行实现。统一约定：
#   编码 = 文本按 UTF-8 取字节后编码为字符串；解码 = 还原字节后按 UTF-8 还原文本。
# 与前面几个 Base 系保持一致：空输入 / 非法字符都抛 ``CodecError``。
# ===========================================================================
#: Base58（Bitcoin）字母表：去掉了容易混淆的 0、O、I、l
_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
#: Base91（basE91）字母表：91 个可打印字符
_BASE91_ALPHABET = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    "!#$%&()*+,./:;<=>?@[]^_`{|}~\""
)
#: Base85 常用变体：键 -> (编码函数, 解码函数, 说明)
_BASE85_VARIANTS = {
    "b85": (base64.b85encode, base64.b85decode, "RFC 1924 / Git"),
    "a85": (base64.a85encode, base64.a85decode, "Adobe Ascii85"),
}


def _strip_whitespace(text: str) -> str:
    """去掉输入中的全部空白字符（长串编码复制后常夹带换行与空格）。"""
    return "".join(text.split())


def _base85_pair(variant: str, action: str) -> tuple:
    """取 Base85 变体对应的（编码, 解码）函数，变体名非法时抛 ``CodecError``。"""
    pair = _BASE85_VARIANTS.get(variant)
    if pair is None:
        raise CodecError(
            f"{action}失败：不支持的 Base85 变体 {variant!r}，"
            f"可选 {'、'.join(_BASE85_VARIANTS)}。"
        )
    return pair[0], pair[1]


def base85_encrypt(data: str, variant: str = "b85") -> str:
    """Base85 编码：文本 -> Base85 字符串。

    variant:
        ``"b85"``（默认）—— RFC 1924 / Git 风格，与标准库 ``base64.b85encode`` 一致；
        ``"a85"`` —— Adobe Ascii85，常出现在 PDF / PostScript 数据流中。
    """
    text = _check_input(data, "Base85 编码")
    encoder, _ = _base85_pair(variant, "Base85 编码")
    try:
        return encoder(text.encode("utf-8")).decode("ascii")
    except (UnicodeEncodeError, ValueError) as exc:
        raise CodecError(f"Base85 编码失败：{exc}") from exc


def base85_decrypt(data: str, variant: str = "b85") -> str:
    """Base85 解码：Base85 字符串 -> 文本；非法输入抛 ``CodecError``。

    ``variant`` 含义同 :func:`base85_encrypt`；``"a85"`` 时额外容忍 Adobe
    文档里常见的 ``<~ ... ~>`` 包裹写法。
    """
    text = _strip_whitespace(_check_input(data, "Base85 解码"))
    _, decoder = _base85_pair(variant, "Base85 解码")
    if variant == "a85":
        text = text.removeprefix("<~").removesuffix("~>")
    if not text:
        raise CodecError("Base85 解码失败：去掉空白字符后内容为空，请检查输入。")
    try:
        raw = decoder(text.encode("ascii"))
    except (UnicodeEncodeError, UnicodeDecodeError, ValueError, binascii.Error) as exc:
        raise CodecError(
            f"Base85 解码失败：输入不是合法的 Base85（{variant}）字符串（{exc}）。"
            "Base85 每 5 个字符为一组，请检查是否截断或混入了非法字符。"
        ) from exc
    return _to_text(raw)


def base58_encrypt(data: str) -> str:
    """Base58 编码（Bitcoin 字母表）：文本 -> Base58 字符串。"""
    text = _check_input(data, "Base58 编码")
    raw = text.encode("utf-8")
    # 前导零字节按 Base58 约定逐个映射为字符 '1'，其余按大整数做进制转换
    leading_zeros = len(raw) - len(raw.lstrip(b"\x00"))
    number = int.from_bytes(raw, "big")
    chars: list[str] = []
    while number:
        number, remainder = divmod(number, 58)
        chars.append(_BASE58_ALPHABET[remainder])
    return "1" * leading_zeros + "".join(reversed(chars))


def base58_decrypt(data: str) -> str:
    """Base58 解码（Bitcoin 字母表）；非法输入抛 ``CodecError``。"""
    text = _strip_whitespace(_check_input(data, "Base58 解码"))
    if not text:
        raise CodecError("Base58 解码失败：去掉空白字符后内容为空，请检查输入。")

    index = {char: value for value, char in enumerate(_BASE58_ALPHABET)}
    invalid = sorted({char for char in text if char not in index})
    if invalid:
        raise CodecError(
            "Base58 解码失败：输入包含非 Base58 字符 "
            f"{''.join(invalid)}。Base58 不含数字 0、大写 O、大写 I 与小写 l，"
            "请确认是否把其中某个字符认错。"
        )

    leading_ones = len(text) - len(text.lstrip("1"))
    number = 0
    for char in text:
        number = number * 58 + index[char]
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
    return _to_text(b"\x00" * leading_ones + raw)


def base91_encrypt(data: str) -> str:
    """Base91 编码（basE91 标准字母表）：文本 -> Base91 字符串。"""
    text = _check_input(data, "Base91 编码")
    raw = text.encode("utf-8")

    out: list[str] = []
    buffer = 0
    bits = 0
    for byte in raw:
        buffer |= byte << bits
        bits += 8
        # 积累到 14 位才输出一组：值 > 88 时用 13 位拆两个字符，否则用 14 位拆两个字符
        if bits > 13:
            value = buffer & 8191
            if value > 88:
                buffer >>= 13
                bits -= 13
            else:
                value = buffer & 16383
                buffer >>= 14
                bits -= 14
            out.append(_BASE91_ALPHABET[value % 91])
            out.append(_BASE91_ALPHABET[value // 91])

    # 收尾：不足一组时补 1~2 个字符
    if bits:
        out.append(_BASE91_ALPHABET[buffer % 91])
        if bits > 7 or buffer > 90:
            out.append(_BASE91_ALPHABET[buffer // 91])
    return "".join(out)


def base91_decrypt(data: str) -> str:
    """Base91 解码（basE91 标准字母表）；非法输入抛 ``CodecError``。"""
    text = _strip_whitespace(_check_input(data, "Base91 解码"))
    if not text:
        raise CodecError("Base91 解码失败：去掉空白字符后内容为空，请检查输入。")

    index = {char: value for value, char in enumerate(_BASE91_ALPHABET)}
    invalid = sorted({char for char in text if char not in index})
    if invalid:
        raise CodecError(
            "Base91 解码失败：输入包含非 Base91 字符 "
            f"{''.join(invalid)}。Base91 只允许 A-Z、a-z、0-9 与 26 个符号字符。"
        )

    out = bytearray()
    buffer = 0
    bits = 0
    value = -1
    for char in text:
        digit = index[char]
        if value < 0:
            # 一组两个字符：先攒下第一个（低位），等第二个字符到达后再合并
            value = digit
            continue
        value += digit * 91
        buffer |= value << bits
        bits += 13 if (value & 8191) > 88 else 14
        while bits > 7:
            out.append(buffer & 0xFF)
            buffer >>= 8
            bits -= 8
        value = -1

    # 收尾：还剩单个字符时补出最后 1 个字节
    if value >= 0:
        out.append((buffer | value << bits) & 0xFF)
    return _to_text(bytes(out))


# ===========================================================================
# 二、Base62 / Base92
# ===========================================================================
#: Base62 字母表：0-9 + A-Z + a-z（常见短链接 / 通用 Base62 变体）
_BASE62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
#: Base92 字母表：除反斜杠、单双引号外的 92 个可打印 ASCII 字符（避免转义麻烦）
_BASE92_ALPHABET = (
    "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
)


def base62_encrypt(data: str) -> str:
    """Base62 编码：文本 -> Base62 字符串（0-9、A-Z、a-z）。"""
    text = _check_input(data, "Base62 编码")
    raw = text.encode("utf-8")
    number = int.from_bytes(raw, "big")
    if number == 0:
        return _BASE62_ALPHABET[0]
    chars: list[str] = []
    while number:
        number, remainder = divmod(number, 62)
        chars.append(_BASE62_ALPHABET[remainder])
    return "".join(reversed(chars))


def base62_decrypt(data: str) -> str:
    """Base62 解码：Base62 字符串 -> 文本；非法输入抛 ``CodecError``。"""
    text = _strip_whitespace(_check_input(data, "Base62 解码"))
    if not text:
        raise CodecError("Base62 解码失败：去掉空白字符后内容为空，请检查输入。")
    index = {char: value for value, char in enumerate(_BASE62_ALPHABET)}
    invalid = sorted({char for char in text if char not in index})
    if invalid:
        raise CodecError(
            f"Base62 解码失败：输入包含非 Base62 字符 {''.join(invalid)}。"
            "Base62 只允许 0-9、A-Z、a-z。"
        )
    number = 0
    for char in text:
        number = number * 62 + index[char]
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
    return _to_text(raw)


def base92_encrypt(data: str) -> str:
    """Base92 编码：文本 -> Base92 字符串（92 个可打印 ASCII 字符）。"""
    text = _check_input(data, "Base92 编码")
    raw = text.encode("utf-8")
    number = int.from_bytes(raw, "big")
    if number == 0:
        return _BASE92_ALPHABET[0]
    chars: list[str] = []
    while number:
        number, remainder = divmod(number, 92)
        chars.append(_BASE92_ALPHABET[remainder])
    return "".join(reversed(chars))


def base92_decrypt(data: str) -> str:
    """Base92 解码：Base92 字符串 -> 文本；非法输入抛 ``CodecError``。"""
    text = _strip_whitespace(_check_input(data, "Base92 解码"))
    if not text:
        raise CodecError("Base92 解码失败：去掉空白字符后内容为空，请检查输入。")
    index = {char: value for value, char in enumerate(_BASE92_ALPHABET)}
    invalid = sorted({char for char in text if char not in index})
    if invalid:
        raise CodecError(
            f"Base92 解码失败：输入包含非 Base92 字符 {''.join(invalid)}。"
        )
    number = 0
    for char in text:
        number = number * 92 + index[char]
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
    return _to_text(raw)


# ===========================================================================
# 三、UUencode / XXencode
# ===========================================================================
def uuencode_encrypt(data: str) -> str:
    """UUencode 编码：文本 -> uuencode 字符串（含 ``begin`` / ``end`` 包裹）。"""
    text = _check_input(data, "UUencode 编码")
    raw = text.encode("utf-8")

    def _enc(body: bytes) -> str:
        lines: list[str] = []
        for i in range(0, len(body), 45):
            chunk = body[i:i + 45]
            # 每行：首字符为长度字符（0~45 -> 空格 + 长度），后跟编码数据
            line = chr(len(chunk) + 32)
            for j in range(0, len(chunk), 3):
                triple = chunk[j:j + 3].ljust(3, b"\x00")
                b0, b1, b2 = triple[0], triple[1], triple[2]
                line += chr((b0 >> 2) + 32)
                line += chr(((b0 & 0x03) << 4 | (b1 >> 4)) + 32)
                line += chr(((b1 & 0x0F) << 2 | (b2 >> 6)) + 32)
                line += chr((b2 & 0x3F) + 32)
            lines.append(line)
        return "\n".join(lines)

    body = _enc(raw)
    return f"begin 644 data\n{body}\n`\nend\n"


def uuencode_decrypt(data: str) -> str:
    """UUencode 解码：uuencode 字符串 -> 文本；非法输入抛 ``CodecError``。"""
    text = _check_input(data, "UUencode 解码")
    lines = [line for line in text.splitlines()
             if line.strip() and not line.strip().startswith(("begin", "end", "===="))]
    out = bytearray()
    for line in lines:
        line = line.rstrip("\r\n")
        if not line:
            continue
        length = (ord(line[0]) - 32) & 0x3F
        payload = line[1:]
        if length == 0:
            continue
        group = bytearray()
        values = [ord(char) - 32 for char in payload]
        for i in range(0, len(values), 4):
            quad = values[i:i + 4]
            while len(quad) < 4:
                quad.append(0)
            b0 = (quad[0] << 2) | (quad[1] >> 4)
            b1 = ((quad[1] & 0x0F) << 4) | (quad[2] >> 2)
            b2 = ((quad[2] & 0x03) << 6) | quad[3]
            group.extend((b0, b1, b2))
        out.extend(group[:length])
    return _to_text(bytes(out))


_XX_ALPHABET = "+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def xxencode_encrypt(data: str) -> str:
    """XXencode 编码：文本 -> xxencode 字符串（``+ - 0-9 A-Z a-z``）。"""
    text = _check_input(data, "XXencode 编码")
    raw = text.encode("utf-8")

    def _xx_enc(body: bytes) -> str:
        lines: list[str] = []
        for i in range(0, len(body), 45):
            chunk = body[i:i + 45]
            # 每行：首字符为长度字符（用字母表下标表示长度），后跟编码数据
            line = _XX_ALPHABET[len(chunk)]
            for j in range(0, len(chunk), 3):
                triple = chunk[j:j + 3].ljust(3, b"\x00")
                b0, b1, b2 = triple[0], triple[1], triple[2]
                line += _XX_ALPHABET[b0 >> 2]
                line += _XX_ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)]
                line += _XX_ALPHABET[((b1 & 0x0F) << 2) | (b2 >> 6)]
                line += _XX_ALPHABET[b2 & 0x3F]
            lines.append(line)
        return "\n".join(lines)

    return f"begin 644 data\n{_xx_enc(raw)}\n+\nend\n"


def xxencode_decrypt(data: str) -> str:
    """XXencode 解码：xxencode 字符串 -> 文本；非法输入抛 ``CodecError``。"""
    text = _check_input(data, "XXencode 解码")
    index = {char: value for value, char in enumerate(_XX_ALPHABET)}
    lines = [line for line in text.splitlines()
             if line.strip() and not line.strip().startswith(("begin", "end", "===="))]
    out = bytearray()
    for line in lines:
        line = line.rstrip("\r\n")
        if not line or line[0] not in index:
            continue
        length = index[line[0]]
        if length == 0:
            continue
        payload = line[1:]
        invalid = [char for char in payload if char not in index]
        if invalid:
            raise CodecError(
                f"XXencode 解码失败：输入包含非 xxencode 字符 {''.join(sorted(set(invalid)))}。"
            )
        values = [index[char] for char in payload]
        group = bytearray()
        for i in range(0, len(values), 4):
            quad = values[i:i + 4]
            while len(quad) < 4:
                quad.append(0)
            group.extend((
                (quad[0] << 2) | (quad[1] >> 4),
                ((quad[1] & 0x0F) << 4) | (quad[2] >> 2),
                ((quad[2] & 0x03) << 6) | quad[3],
            ))
        out.extend(group[:length])
    return _to_text(bytes(out))