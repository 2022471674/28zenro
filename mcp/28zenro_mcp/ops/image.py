# -*- coding: utf-8 -*-
"""cn_image —— 图片工具组。

覆盖 ``lib.image_codec``（图片 ↔ Base64）、``lib.lsb``（LSB 隐写嵌入 / 提取 /
参数盲猜）、``lib.watermark``（可见水印）。

路径约定：``carrier_path`` / ``out_path`` 等相对路径基于项目根；留空的输出路径
按配置 ``watermark.output_dir`` 或 ``output/`` 落地。
"""

from __future__ import annotations

from typing import Any

from lib import image_codec, lsb, watermark

from ..contract import (Ctx, Group, arr, custom_op, flag, make_op, num, txt)
from ..envelope import to_jsonable
from ._helpers import rel, resolve_output, resolve_output_dir, resolve_path, section

_CHANNELS = "RGB / RGBA / R / G / B / A / RB / GB 等通道组合"
_ORDERS = ("column", "row")
_FRAMINGS = ("marker", "length")
_FRAMINGS_EXTRACT = ("marker", "length", "auto")
_POSITIONS = tuple(watermark.POSITIONS)


def _img_to_b64(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    path = resolve_path(a["image_path"], field="image_path", must_exist=True)
    text = image_codec.image_to_base64(path, data_uri=a["data_uri"])
    return {"path": str(path), "rel": rel(path), "size": path.stat().st_size,
            "base64": text, "chars": len(text)}


def _b64_to_img(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    data, ext = image_codec.decode_base64_image(a["text"])
    out = resolve_output(a["out_path"], f"output/image{ext}")
    written = image_codec.base64_to_image(a["text"], out)
    return {"out": str(written), "out_rel": rel(written), "size": len(data),
            "extension": ext}


def _capacity(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    path = resolve_path(a["carrier_path"], field="carrier_path", must_exist=True)
    bits = lsb.capacity(path, channels=a["channels"])
    return {"path": str(path), "bits": bits, "bytes": bits // 8,
            "chars_hint": bits // 8, "channels": a["channels"]}


def _capacity_text(a: dict[str, Any], ctx: Ctx) -> str:
    path = resolve_path(a["carrier_path"], field="carrier_path", must_exist=True)
    return lsb.capacity_text(path, channels=a["channels"])


def _embed(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    carrier = resolve_path(a["carrier_path"], field="carrier_path", must_exist=True)
    secret = lsb.read_secret(a["secret"])
    if not secret:
        raise ValueError("secret 为空：既不是存在的文件路径，也没有文本内容")
    out = resolve_output(a["output_path"],
                         resolve_output_dir("", "output") / f"{carrier.stem}_stego{carrier.suffix}")
    written = lsb.embed(carrier, secret, out, channels=a["channels"], bit=a["bit"],
                        offset=a["offset"], order=a["order"],
                        framing=a["framing"])
    return {"carrier": str(carrier), "out": str(written), "out_rel": rel(written),
            "secret_chars": len(str(secret)), "channels": a["channels"],
            "bit": a["bit"], "offset": a["offset"], "order": a["order"],
            "framing": a["framing"]}


def _extract(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    stego = resolve_path(a["stego_path"], field="stego_path", must_exist=True)
    out = None
    if a["output_path"]:
        out = resolve_output(a["output_path"], "output/extracted.txt")
    text = lsb.extract(stego, out, channels=a["channels"], bit=a["bit"],
                       offset=a["offset"], order=a["order"],
                       framing=a["framing"])
    payload: dict[str, Any] = {"stego": str(stego), "text": text,
                               "chars": len(text or "")}
    if out is not None:
        payload["out"] = str(out)
        payload["out_rel"] = rel(out)
    return payload


def _detect(a: dict[str, Any], ctx: Ctx) -> Any:
    stego = resolve_path(a["stego_path"], field="stego_path", must_exist=True)
    result = lsb.detect_params(
        stego,
        channels_presets=tuple(a["channels_presets"] or ()),
        bits=[int(item) for item in (a["bits"] or [])],
        offsets=[int(item) for item in (a["offsets"] or [])],
        orders=tuple(a["orders"] or ()),
        framings=tuple(a["framings"] or ()),
        limit=a["limit"], min_score=a["min_score"])
    return to_jsonable(result)


def _add_watermark(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    carrier = resolve_path(a["carrier_path"], field="carrier_path", must_exist=True)
    color = watermark.parse_color(a["color"]) if isinstance(a["color"], str) else tuple(a["color"])
    default = resolve_output_dir(section("watermark").get("output_dir") or "output",
                                "output")
    out = resolve_output(a["output_path"],
                         default / f"{carrier.stem}_wm{carrier.suffix}")
    written = watermark.add_visible_watermark(
        carrier, a["watermark_text"], out, position=a["position"],
        font_size=a["font_size"], color=color,
        font_path=a["font_path"] or None)
    return {"carrier": str(carrier), "out": str(written), "out_rel": rel(written),
            "position": a["position"], "font_size": a["font_size"],
            "color": color}


def _out_dir(a: dict[str, Any], ctx: Ctx) -> str:
    return str(watermark.resolve_output_dir(a["raw"] or None))


def _out_path(a: dict[str, Any], ctx: Ctx) -> str:
    return str(watermark.out_path(a["filename"], a["raw"] or None))


OPS = [
    # ------------------------------------------------------------ 图片 Base64
    custom_op("image_to_base64", _img_to_b64,
              "把图片文件编码为 Base64 文本（可选 data URI 前缀）。",
              [txt("image_path", required=True, desc="图片路径（相对项目根或绝对）"),
               flag("data_uri", default=False, desc="是否加 ``data:image/...;base64,`` 前缀")],
              returns="dict：{path, rel, size, base64, chars}", risk="read",
              module="lib.image_codec"),
    make_op(image_codec.decode_base64_image, "把 Base64 文本解码为图片字节，返回建议扩展名。",
            [txt("text", required=True, desc="Base64 文本（可含 data URI 前缀）")],
            returns="dict：{image: {hex,length,text}, extension}",
            unpack=("image", "extension")),
    custom_op("base64_to_image", _b64_to_img,
              "把 Base64 文本解码并写出为图片文件。",
              [txt("text", required=True, desc="Base64 文本"),
               txt("out_path", desc="输出路径；留空写入 output/image.<ext>")],
              returns="dict：{out, out_rel, size, extension}", risk="write",
              module="lib.image_codec"),

    # ------------------------------------------------------------------- LSB
    custom_op("capacity", _capacity,
              "计算载体图片可写入的隐写位数（按通道）。",
              [txt("carrier_path", required=True, desc="载体图片路径"),
               txt("channels", default="RGB", desc=_CHANNELS)],
              returns="dict：{path, bits, bytes, chars_hint, channels}", risk="read",
              module="lib.lsb"),
    custom_op("capacity_text", _capacity_text,
              "用人类可读文本描述载体容量。",
              [txt("carrier_path", required=True, desc="载体图片路径"),
               txt("channels", default="RGB", desc=_CHANNELS)],
              returns="str：容量说明", risk="read", module="lib.lsb"),
    custom_op("embed", _embed,
              "LSB 隐写：把秘密信息写入载体图片（secret 既可以是文本，也可以是文本文件路径）。",
              [txt("carrier_path", required=True, desc="载体图片路径"),
               txt("secret", required=True,
                   desc="秘密文本；若该字符串是存在的文件路径则读文件内容"),
               txt("output_path", desc="输出图片路径；留空写入 output/<名字>_stego.<原后缀>"),
               txt("channels", default="RGB", desc=_CHANNELS),
               num("bit", default=0, desc="使用字节的第几位（0 = LSB）", minimum=0, maximum=7),
               num("offset", default=0, desc="起始位偏移", minimum=0),
               txt("order", default="column", desc="扫描顺序", choices=_ORDERS),
               txt("framing", default="marker", desc="帧格式：marker（末尾 FF）/ length（长度头）",
                   choices=_FRAMINGS)],
              returns="dict：{carrier, out, out_rel, secret_chars, channels, bit, offset, order, framing}",
              risk="write", module="lib.lsb"),
    custom_op("extract", _extract,
              "LSB 隐写提取（可选同时写入文本文件）。",
              [txt("stego_path", required=True, desc="隐写图片路径"),
               txt("output_path", desc="提取结果另存的文本路径；留空只返回文本"),
               txt("channels", default="RGB", desc=_CHANNELS),
               num("bit", default=0, desc="使用字节的第几位", minimum=0, maximum=7),
               num("offset", default=0, desc="起始位偏移", minimum=0),
               txt("order", default="column", desc="扫描顺序", choices=_ORDERS),
               txt("framing", default="auto", desc="帧格式：auto / marker / length",
                   choices=_FRAMINGS_EXTRACT)],
              returns="dict：{stego, text, chars[, out, out_rel]}", risk="read",
              module="lib.lsb"),
    custom_op("detect_params", _detect,
              "LSB 参数盲猜：遍历通道 / 位 / 偏移 / 顺序 / 帧格式组合，按得分排序返回候选。",
              [txt("stego_path", required=True, desc="可疑图片路径"),
               arr("channels_presets", default=("RGB", "RGBA", "R", "G", "B", "A", "RB", "GB"),
                   desc="候选通道组合"),
               arr("bits", default=(0, 1, 2, 3, 4, 5, 6, 7), desc="候选位下标"),
               arr("offsets", default=(0, 1, 2, 4, 8, 16, 32, 64, 128, 256),
                   desc="候选起始偏移"),
               arr("orders", default=("column", "row"), desc="候选扫描顺序"),
               arr("framings", default=("length", "marker"), desc="候选帧格式"),
               num("limit", default=8, desc="最多返回候选数", minimum=1),
               num("min_score", default=4.0, desc="最低得分阈值")],
              returns="list[dict]：候选参数与提取片段", risk="long",
              module="lib.lsb"),
    make_op(lsb.describe_params, "把 LSB 参数渲染成一句可读描述。",
            [txt("channels", default="RGB", desc=_CHANNELS),
             num("bit", default=0, desc="位下标", minimum=0, maximum=7),
             num("offset", default=0, desc="起始偏移", minimum=0),
             txt("order", default="column", desc="扫描顺序", choices=_ORDERS),
             txt("framing", default="marker", desc="帧格式", choices=_FRAMINGS)],
            returns="str：参数描述"),
    make_op(lsb.read_secret, "读取秘密输入：若为存在的文件路径则返回文件文本，否则原样返回。",
            [txt("secret_input", required=True, desc="秘密文本或文件路径")],
            returns="str：秘密文本", risk="read"),

    # ----------------------------------------------------------------- 水印
    custom_op("add_visible_watermark", _add_watermark,
              "在图片上叠加可见文字水印（可平铺）。",
              [txt("carrier_path", required=True, desc="载体图片路径"),
               txt("watermark_text", required=True, desc="水印文字"),
               txt("output_path", desc="输出路径；留空写入配置的输出目录"),
               txt("position", default="bottom-right", desc="水印位置", choices=_POSITIONS),
               num("font_size", default=30, desc="字号（像素）", minimum=6, maximum=400),
               txt("color", default="255,255,255,128",
                   desc="RGBA 颜色，形如 ``255,255,255,128``（末位透明度 0-255）"),
               txt("font_path", desc="自定义字体文件路径；留空用内置字体")],
              returns="dict：{carrier, out, out_rel, position, font_size, color}",
              risk="write", module="lib.watermark"),
    make_op(watermark.parse_color, "解析 ``R,G,B,A`` 颜色字符串。",
            [txt("text", required=True, desc="形如 ``255,255,255,128``")],
            returns="dict：{r, g, b, a}", unpack=("r", "g", "b", "a")),
    custom_op("resolve_output_dir", _out_dir,
              "解析水印输出目录（相对路径基于项目根，返回绝对路径）。",
              [txt("raw", desc="用户填写的目录；留空用配置默认值")],
              returns="str：绝对目录路径", risk="safe", module="lib.watermark"),
    custom_op("out_path", _out_path,
              "在输出目录下拼出完整文件路径。",
              [txt("filename", required=True, desc="文件名"),
               txt("raw", desc="自定义输出目录；留空用配置默认值")],
              returns="str：绝对文件路径", risk="safe", module="lib.watermark"),
]


GROUP = Group(
    name="cn_image",
    title="图片：Base64 / LSB 隐写 / 可见水印",
    summary=("图片 ↔ Base64；LSB 隐写容量计算、嵌入、提取、参数盲猜；"
             "可见文字水印（含平铺）。依赖 Pillow。"),
    ops=OPS,
    guide=("图片类 op 需要 Pillow；缺失时报 unsupported 并提示安装。"
           "相对路径基于项目根；写文件的 op 风险等级为 write。"),
)
