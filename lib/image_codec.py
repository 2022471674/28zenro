# -*- coding: utf-8 -*-
"""图片编解码纯逻辑模块（图片文件 <-> Base64 文本）。

本模块只做「路径 / 文本进、文本 / 路径出」的纯计算，不导入任何 UI 模块。

对外接口：
    image_to_base64(path, data_uri)   图片字节 -> Base64 文本（可选 Data URI 前缀）
    decode_base64_image(text)         Base64 文本 -> (图片字节, 建议扩展名)
    base64_to_image(text, out_path)   Base64 文本 -> 写出图片文件，返回最终路径
"""

from __future__ import annotations

import base64
import binascii
import mimetypes
import re
from pathlib import Path


class ImageCodecError(ValueError):
    """图片编解码失败时抛出的统一异常，便于界面层统一捕获并展示提示。"""


#: Data URI 形式：``data:image/png;base64,<payload>``（mime 允许缺省）
_DATA_URI_RE = re.compile(
    r"^data:(?P<mime>[^;,]*)?;base64,(?P<data>.*)$",
    re.IGNORECASE | re.DOTALL,
)

#: mime -> 扩展名（用于带 Data URI 前缀时决定输出扩展名）
_MIME_EXT = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/jpg": ".jpg",
    "image/gif": ".gif",
    "image/bmp": ".bmp",
    "image/webp": ".webp",
    "image/tiff": ".tiff",
    "image/svg+xml": ".svg",
}

#: 常见图片格式魔数 -> 扩展名（无 Data URI 前缀时按字节嗅探）
_MAGIC_EXT = (
    (b"\x89PNG\r\n\x1a\n", ".png"),
    (b"\xff\xd8\xff", ".jpg"),
    (b"GIF87a", ".gif"),
    (b"GIF89a", ".gif"),
    (b"BM", ".bmp"),
    (b"\x00\x00\x01\x00", ".ico"),
)

#: URL-safe 字母表 -> 标准字母表（用于回退解码）
_URLSAFE_TO_STD = str.maketrans("-_", "+/")

#: ftyp box 中标识 HEIF / AVIF 家族的品牌名
_FTYP_BRANDS = {
    b"heic": ".heic",
    b"heix": ".heic",
    b"hevc": ".heic",
    b"mif1": ".heic",
    b"avif": ".avif",
}


def image_to_base64(image_path: str | Path, data_uri: bool = False) -> str:
    """把图片文件内容编码为 Base64 文本，返回编码结果。

    ``data_uri=True`` 时按 ``data:<mime>;base64,`` 前缀输出，
    可直接用于 ``<img src>`` / CSS ``url()``；mime 由扩展名推断，
    无法推断时按 ``image/png`` 处理。
    """
    path = Path(image_path)
    if not path.is_file():
        raise ImageCodecError(f"图片不存在: {path}")
    encoded = base64.b64encode(path.read_bytes()).decode("ascii")
    if data_uri:
        mime = mimetypes.guess_type(path.name)[0] or "image/png"
        return f"data:{mime};base64,{encoded}"
    return encoded


def _sniff_ext(data: bytes) -> str | None:
    """按字节魔数嗅探图片扩展名，无法识别返回 None。"""
    for magic, ext in _MAGIC_EXT:
        if data.startswith(magic):
            return ext
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return ".webp"
    if data[:4] in (b"II*\x00", b"MM\x00*"):
        return ".tiff"
    # ISO-BMFF 容器：偏移 4 处为 ``ftyp``，其后 4 字节为品牌名
    if data[4:8] == b"ftyp":
        return _FTYP_BRANDS.get(data[8:12])
    return None


def decode_base64_image(text: str) -> tuple[bytes, str]:
    """把 Base64 文本解码为图片字节，返回 ``(字节, 建议扩展名)``。

    兼容几种常见输入：
    - Data URI：``data:image/png;base64,iVBOR...``（扩展名优先按 mime 取）；
    - 纯 Base64：文本中的换行 / 空格会被忽略，扩展名按字节魔数嗅探；
    - 标准与 URL-safe 两种 Base64 字母表、缺失的 ``=`` 补位都会被容忍；
    - 以上都判不出类型时，扩展名回退 ``.png``。

    内容为空或解码失败时抛 :class:`ImageCodecError`。
    """
    raw = (text or "").strip()
    if not raw:
        raise ImageCodecError("Base64 内容为空")

    ext: str | None = None
    match = _DATA_URI_RE.match(raw)
    if match:
        mime = (match.group("mime") or "").strip().lower()
        ext = _MIME_EXT.get(mime)
        raw = match.group("data")

    # Base64 常被折行，去掉所有空白字符再解码
    payload = re.sub(r"\s+", "", raw)
    if not payload:
        raise ImageCodecError("Base64 内容为空")

    # 补齐缺失的 = 补位（长度须为 4 的倍数）
    remainder = len(payload) % 4
    if remainder:
        payload += "=" * (4 - remainder)

    try:
        data = base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError):
        # 回退：容忍 URL-safe 字母表（- _ 代替 + /），仍严格校验非法字符
        try:
            translated = payload.translate(_URLSAFE_TO_STD)
            data = base64.b64decode(translated, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ImageCodecError(f"Base64 解码失败：{exc}") from exc

    if not data:
        raise ImageCodecError("Base64 解码结果为空")

    if ext is None:
        ext = _sniff_ext(data) or ".png"
    return data, ext


def base64_to_image(text: str, out_path: str | Path) -> Path:
    """把 Base64 文本解码并写出为图片文件，返回最终写入路径。

    ``out_path`` 未带扩展名时，按图片实际类型自动补全（Data URI 的 mime
    优先，其次字节魔数，最后回退 ``.png``）。
    """
    data, ext = decode_base64_image(text)
    path = Path(out_path)
    if not path.suffix:
        path = path.with_suffix(ext)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path
