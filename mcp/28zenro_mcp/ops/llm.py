# -*- coding: utf-8 -*-
"""cn_llm —— 大模型接口工具组（OpenAI 兼容）。

覆盖 ``lib.llm_codec``（models / chat / embeddings / OCR）与
``lib.translate_codec``（中英互译）。

配置约定
--------
``base_url`` / ``model`` / ``api_key`` / ``timeout`` / 自定义请求头默认全部取自
``config.json`` 的 ``llm`` 节（与 GUI 设置共享）。调用时传参可临时覆盖，
不改配置文件。
"""

from __future__ import annotations

from typing import Any

from lib import llm_codec, translate_codec

from ..contract import (Ctx, Group, anyp, custom_op, flt, make_op, num, obj,
                        txt)
from ..envelope import ToolError
from ._helpers import llm_defaults, resolve_path


def _conf() -> dict[str, Any]:
    return llm_defaults()


def _need_base_url(value: str, conf: dict[str, Any]) -> str:
    base_url = str(value or conf.get("base_url") or "").strip()
    if not base_url:
        raise ToolError(
            "missing_param",
            "缺少 base_url：请求里没传，config.json 的 llm.base_url 也是空的",
            field="base_url",
            hint="在 params 里传 base_url，或先在 GUI 设置里配置大模型服务地址",
        )
    return base_url


def _timeout(value: float, conf: dict[str, Any]) -> float:
    return float(value) if value and value > 0 else float(conf.get("timeout") or 120)


def _headers(text: str) -> dict[str, str] | None:
    return llm_codec.parse_headers(str(text or "")) or None


def _list_models(a: dict[str, Any], ctx: Ctx) -> Any:
    conf = _conf()
    return llm_codec.list_models(
        _need_base_url(a["base_url"], conf), timeout=_timeout(a["timeout"], conf),
        api_key=a["api_key"] or conf.get("api_key") or None,
        extra_headers=_headers(a["headers"]))


def _chat(a: dict[str, Any], ctx: Ctx) -> Any:
    conf = _conf()
    model = str(a["model"] or conf.get("model") or "").strip()
    if not model:
        raise ToolError("missing_param", "缺少 model（请求未传且配置 llm.model 为空）",
                        field="model")
    return llm_codec.chat(
        _need_base_url(a["base_url"], conf), model, a["messages"],
        timeout=_timeout(a["timeout"], conf),
        api_key=a["api_key"] or conf.get("api_key") or None,
        extra_headers=_headers(a["headers"]), temperature=a["temperature"])


def _embed(a: dict[str, Any], ctx: Ctx) -> Any:
    conf = _conf()
    model = str(a["model"] or conf.get("embedding_model") or "").strip()
    if not model:
        raise ToolError("missing_param", "缺少 model（请求未传且配置 llm.embedding_model 为空）",
                        field="model")
    return llm_codec.embed(
        _need_base_url(a["base_url"], conf), model, a["text"],
        timeout=_timeout(a["timeout"], conf),
        api_key=a["api_key"] or conf.get("api_key") or None,
        extra_headers=_headers(a["headers"]))


def _ocr(a: dict[str, Any], ctx: Ctx) -> Any:
    conf = _conf()
    model = str(a["model"] or conf.get("ocr_model") or conf.get("multimodal_model")
                or "").strip()
    if not model:
        raise ToolError("missing_param",
                        "缺少 model（请求未传且配置 llm.ocr_model / multimodal_model 为空）",
                        field="model")
    image = resolve_path(a["image_path"], field="image_path", must_exist=True)
    return llm_codec.ocr_image(
        _need_base_url(a["base_url"], conf), model, image,
        prompt=a["prompt"], timeout=_timeout(a["timeout"], conf),
        api_key=a["api_key"] or conf.get("api_key") or None,
        extra_headers=_headers(a["headers"]))


def _translate(a: dict[str, Any], ctx: Ctx) -> Any:
    conf = _conf()
    model = str(a["model"] or conf.get("model") or "").strip()
    if not model:
        raise ToolError("missing_param", "缺少 model（请求未传且配置 llm.model 为空）",
                        field="model")
    return translate_codec.translate(
        a["data"], _need_base_url(a["base_url"], conf), model,
        timeout=_timeout(a["timeout"], conf),
        api_key=a["api_key"] or conf.get("api_key") or None,
        system_prompt_zh=a["system_prompt_zh"] or conf.get("system_prompt_zh") or None,
        system_prompt_en=a["system_prompt_en"] or conf.get("system_prompt_en") or None,
        headers=_headers(a["headers"]))


OPS = [
    custom_op("list_models", _list_models,
              "调用 ``GET /models`` 获取服务端可用模型 id 列表（OpenAI 兼容）。",
              [txt("base_url", desc="服务地址，如 ``http://localhost:11434/v1``；留空用配置"),
               flt("timeout", default=0.0, desc="超时秒数；0 表示用配置值", minimum=0),
               txt("api_key", desc="API Key；留空用配置"),
               txt("headers", desc="自定义请求头，多行 ``Key: Value``")],
              returns="list[str]：模型 id 列表", risk="network",
              module="lib.llm_codec"),
    custom_op("chat", _chat, "调 ``POST /chat/completions`` 做一次对话补全。",
              [txt("base_url", desc="服务地址；留空用配置"),
               txt("model", desc="模型名；留空用配置 llm.model"),
               anyp("messages", required=True,
                    desc="消息数组，如 [{\"role\":\"user\",\"content\":\"hi\"}]"),
               flt("timeout", default=0.0, desc="超时秒数；0 表示用配置值", minimum=0),
               txt("api_key", desc="API Key；留空用配置"),
               txt("headers", desc="自定义请求头，多行 ``Key: Value``"),
               flt("temperature", default=0.0, desc="采样温度", minimum=0, maximum=2)],
              returns="str：模型回复文本", risk="network", module="lib.llm_codec"),
    custom_op("embed", _embed, "调 ``POST /embeddings`` 计算文本向量。",
              [txt("base_url", desc="服务地址；留空用配置"),
               txt("model", desc="嵌入模型名；留空用配置 llm.embedding_model"),
               txt("text", required=True, desc="待嵌入文本"),
               flt("timeout", default=0.0, desc="超时秒数；0 表示用配置值", minimum=0),
               txt("api_key", desc="API Key；留空用配置"),
               txt("headers", desc="自定义请求头，多行 ``Key: Value``")],
              returns="list[float]：向量", risk="network", module="lib.llm_codec"),
    custom_op("ocr_image", _ocr, "多模态 OCR：把图片交给视觉模型识别文字。",
              [txt("base_url", desc="服务地址；留空用配置"),
               txt("model", desc="OCR / 多模态模型名；留空用配置"),
               txt("image_path", required=True, desc="图片路径（相对项目根或绝对）"),
               txt("prompt", desc="识别提示词；留空用内置提示"),
               flt("timeout", default=0.0, desc="超时秒数；0 表示用配置值", minimum=0),
               txt("api_key", desc="API Key；留空用配置"),
               txt("headers", desc="自定义请求头，多行 ``Key: Value``")],
              returns="str：识别出的文本", risk="network", module="lib.llm_codec"),
    custom_op("translate", _translate, "中英互译（自动判断方向，走 OpenAI 兼容接口）。",
              [txt("data", required=True, desc="待翻译文本"),
               txt("base_url", desc="服务地址；留空用配置"),
               txt("model", desc="对话模型名；留空用配置 llm.model"),
               flt("timeout", default=0.0, desc="超时秒数；0 表示用配置值", minimum=0),
               txt("api_key", desc="API Key；留空用配置"),
               txt("system_prompt_zh", desc="英译中时的系统提示词；留空用配置"),
               txt("system_prompt_en", desc="中译英时的系统提示词；留空用配置"),
               txt("headers", desc="自定义请求头，多行 ``Key: Value``")],
              returns="str：译文", risk="network", module="lib.translate_codec"),
    make_op(translate_codec.detect_language, "判断文本语言（zh / en / other）。",
            [txt("text", required=True, desc="文本")],
            returns="str：语言标识", risk="safe"),
    make_op(translate_codec.target_language, "判断译文目标语言：中文输入译英，其余译中。",
            [txt("text", required=True, desc="文本")],
            returns="str：目标语言标识", risk="safe"),
]


GROUP = Group(
    name="cn_llm",
    title="大模型：对话 / 向量 / OCR / 翻译",
    summary=("OpenAI 兼容接口：模型列表、对话补全、文本向量、图片 OCR；中英互译。"
             "地址与模型默认读 config.json 的 llm 节。"),
    ops=OPS,
    guide=("base_url / model / api_key 留空即用配置值；请求里传值只对本次调用生效，"
           "不会写回配置文件。"),
)
