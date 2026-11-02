# -*- coding: utf-8 -*-
"""图片水印纯逻辑模块（可见水印添加 + 路径辅助）。

可见水印部分移植自 ``D:\\安全测试\\WebServiceScan\\水印\\Visible_Mark_Create.py``：
在图片上叠加半透明文字（支持四角定位与整图平铺），相对原脚本的改动：
- 原脚本失败时 ``print`` + ``exit(1)``，本模块改为抛出异常，由界面层展示；
- 输出路径按需创建父目录，重名文件经 :func:`unique_path` 自动加后缀不覆盖。

LSB 隐写部分已迁移至 :mod:`lib.lsb`（全参数嵌入 / 提取 + 参数自动探测），
本模块不再提供 LSB 函数。

本模块只做「路径 / 参数进、路径 / 文本出」的图像处理，不导入任何 UI 模块。

对外接口：
    app_root()                          应用根目录（源码为项目根，打包为 exe 目录）
    resolve_output_dir(raw, root)       解析输出目录（默认 output，相对根目录）
    unique_path(path)                   重名文件自动追加 _1 / _2 后缀
    parse_color(text)                   'R,G,B,A' 字符串 -> 四元组
    add_visible_watermark(...)          添加可见水印，返回输出路径
"""

from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

#: 可支持的水印位置（键）与显示顺序
POSITIONS: tuple[str, ...] = (
    "top-left", "top-right", "bottom-left", "bottom-right", "tile",
)

#: 位置键 -> 中文名（界面下拉展示用）
POSITION_NAMES: dict[str, str] = {
    "top-left": "左上",
    "top-right": "右上",
    "bottom-left": "左下",
    "bottom-right": "右下",
    "tile": "平铺",
}

#: 默认输出目录（相对应用根目录）
DEFAULT_OUTPUT_DIR = "output"


class WatermarkError(ValueError):
    """水印处理失败时抛出的统一异常，便于界面层统一捕获并展示提示。"""


# ---------------------------------------------------------------------------
# 路径辅助
# ---------------------------------------------------------------------------
def app_root() -> Path:
    """应用根目录：打包后取 exe 所在目录，源码运行取项目根目录（main.py 同级）。"""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def resolve_output_dir(raw: str | None = None, root: Path | None = None) -> Path:
    """解析输出目录：相对路径基于应用根目录，返回绝对路径并按需创建。

    ``raw`` 为空 / 纯空白时回退默认值 ``output``。
    """
    text = str(raw or "").strip() or DEFAULT_OUTPUT_DIR
    base = root or app_root()
    path = Path(text)
    if not path.is_absolute():
        path = base / path
    path = path.resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path


def out_path(filename: str, raw: str | None = None, root: Path | None = None) -> Path:
    """在输出目录下拼出完整文件路径（不检查是否已存在）。"""
    return resolve_output_dir(raw, root) / filename


def unique_path(path: str | Path) -> Path:
    """重名文件自动追加 ``_1``、``_2`` … 后缀，避免覆盖已有文件。"""
    target = Path(path)
    if not target.exists():
        return target
    stem, ext = target.stem, target.suffix
    n = 1
    while target.with_name(f"{stem}_{n}{ext}").exists():
        n += 1
    return target.with_name(f"{stem}_{n}{ext}")


# ---------------------------------------------------------------------------
# 一、可见水印
# ---------------------------------------------------------------------------
def parse_color(text: str) -> tuple[int, int, int, int]:
    """解析 ``'R,G,B,A'`` 形式的颜色字符串（各分量 0-255）。"""
    try:
        color = tuple(int(v) for v in str(text).split(","))
    except ValueError:
        raise WatermarkError("颜色需为 4 个 0-255 的整数（RGBA），如 255,255,255,128")
    if len(color) != 4 or any(c < 0 or c > 255 for c in color):
        raise WatermarkError("颜色需为 4 个 0-255 的整数（RGBA），如 255,255,255,128")
    return color  # type: ignore[return-value]


def add_visible_watermark(
    carrier_path: str | Path,
    watermark_text: str,
    output_path: str | Path,
    position: str = "bottom-right",
    font_size: int = 30,
    color: tuple[int, int, int, int] = (255, 255, 255, 128),
    font_path: str | Path | None = None,
) -> str:
    """在载体图片上叠加可见水印文字，返回输出文件路径。

    ``position`` 取 :data:`POSITIONS` 之一；``color`` 为 RGBA，
    末位为透明度（0-255）；``font_path`` 不存在或加载失败时回退默认字体。
    """
    carrier = Path(carrier_path)
    if not carrier.is_file():
        raise WatermarkError(f"载体图片不存在: {carrier}")
    if not str(watermark_text or "").strip():
        raise WatermarkError("水印文字不能为空")
    if position not in POSITIONS:
        raise WatermarkError(f"不支持的位置: {position}")
    if not isinstance(color, (tuple, list)) or len(color) != 4:
        color = parse_color(str(color))

    target = Path(output_path)
    if target.parent:
        target.parent.mkdir(parents=True, exist_ok=True)

    with Image.open(carrier) as src:
        base = src.convert("RGBA")

    watermark = Image.new("RGBA", base.size, (255, 255, 255, 0))
    draw = ImageDraw.Draw(watermark)

    try:
        if font_path and Path(font_path).is_file():
            font = ImageFont.truetype(str(font_path), font_size)
        else:
            font = ImageFont.load_default()
    except OSError:  # 字体损坏时回退默认字体
        font = ImageFont.load_default()

    bbox = draw.textbbox((0, 0), watermark_text, font=font)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]

    width, height = base.size
    padding = 20

    if position == "tile":
        for ty in range(0, height, text_height + padding):
            for tx in range(0, width, text_width + padding):
                draw.text((tx, ty), watermark_text, font=font, fill=color)
    else:
        if position == "top-left":
            x, y = padding, padding
        elif position == "top-right":
            x, y = width - text_width - padding, padding
        elif position == "bottom-left":
            x, y = padding, height - text_height - padding
        else:  # bottom-right
            x, y = width - text_width - padding, height - text_height - padding
        draw.text((x, y), watermark_text, font=font, fill=color)

    combined = Image.alpha_composite(base, watermark)
    if target.suffix.lower() in (".jpg", ".jpeg"):
        combined = combined.convert("RGB")
    combined.save(target)
    return str(target)
