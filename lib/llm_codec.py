# -*- coding: utf-8 -*-
"""大模型接口纯逻辑模块（OpenAI 兼容格式）。

统一提供 OpenAI 兼容格式的最小原语，供翻译等上层逻辑与设置页复用：
- parse_headers   把「每行一个 Header（``Key: Value``）」文本解析成 dict
- build_headers   组合 API Key 与自定义 Header
- list_models     ``GET {base_url}/models``，返回可用模型 id 列表
- chat            ``POST {base_url}/chat/completions``，返回回复文本
- embed           ``POST {base_url}/embeddings``，返回向量

兼容 OpenAI 官方与各类 OpenAI 兼容服务（Ollama ``/v1``、vLLM、One-API、
New-API 等），只要服务暴露标准的 ``/models``、``/chat/completions``、
``/embeddings`` 端点即可。失败统一抛 :class:`LLMError`，由界面层统一展示。

本模块只做「配置进、文本 / 列表出」的网络处理，不导入任何 UI 模块。
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path


class LLMError(ValueError):
    """模型接口失败时抛出的统一异常，由界面层统一捕获并展示。"""


# ---------------------------------------------------------------------------
# 请求头
# ---------------------------------------------------------------------------
def parse_headers(text: str) -> dict[str, str]:
    """把「每行一个 Header（``Key: Value``）」的文本解析成请求头 dict。

    空行与 ``#`` 开头的注释行会被忽略；无冒号的行跳过。
    """
    headers: dict[str, str] = {}
    for line in str(text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition(":")
        if sep and key.strip():
            headers[key.strip()] = value.strip()
    return headers


def build_headers(
    api_key: str | None = None,
    extra: dict[str, str] | None = None,
) -> dict[str, str]:
    """组合请求头：默认带 ``Content-Type``，有 Key 时补 ``Authorization``。

    ``extra``（用户自定义 Header）最后合并，优先级最高，可覆盖默认值。
    """
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    if extra:
        headers.update(extra)
    return headers


# ---------------------------------------------------------------------------
# HTTP 核心
# ---------------------------------------------------------------------------
def _request_json(
    url: str,
    payload: dict | None,
    timeout: float,
    headers: dict[str, str],
) -> dict:
    """发一次请求并解析 JSON；``payload`` 为 None 时走 GET，否则 POST。

    失败统一抛 :class:`LLMError`。
    """
    data = None
    method = None
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        method = "POST"
    request = urllib.request.Request(
        url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        raise LLMError(
            f"模型服务返回 HTTP {exc.code}（{url}），请确认地址 / Key / 模型无误。"
        ) from exc
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, TimeoutError):
            raise LLMError(f"请求模型服务超时（{timeout} 秒）。") from exc
        raise LLMError(
            f"无法连接模型服务（{url}），请确认服务地址可达。") from exc
    except TimeoutError as exc:
        raise LLMError(f"请求模型服务超时（{timeout} 秒）。") from exc

    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        raise LLMError("模型服务返回内容不是合法的 JSON。") from exc


def _endpoint(base_url: str, path: str) -> str:
    return str(base_url or "").rstrip("/") + path


# ---------------------------------------------------------------------------
# 对外原语
# ---------------------------------------------------------------------------
def list_models(
    base_url: str,
    timeout: float = 15.0,
    api_key: str | None = None,
    extra_headers: dict[str, str] | None = None,
) -> list[str]:
    """``GET /models`` 拉取可用模型 id 列表（OpenAI 格式）。"""
    if not base_url:
        raise LLMError("未配置模型服务地址。")
    body = _request_json(
        _endpoint(base_url, "/models"), None, timeout,
        build_headers(api_key, extra_headers))
    models: list[str] = []
    for item in body.get("data") or []:
        if isinstance(item, dict) and item.get("id"):
            models.append(str(item["id"]))
    if not models:
        # 少数兼容服务返回 Ollama 原生的 models[].name 结构
        for item in body.get("models") or []:
            if isinstance(item, dict) and item.get("name"):
                models.append(str(item["name"]))
    return models


def chat(
    base_url: str,
    model: str,
    messages: list[dict],
    timeout: float = 120.0,
    api_key: str | None = None,
    extra_headers: dict[str, str] | None = None,
    temperature: float = 0.0,
) -> str:
    """``POST /chat/completions``，返回首条回复的文本内容。"""
    if not base_url:
        raise LLMError("未配置模型服务地址。")
    if not model:
        raise LLMError("未配置模型名称。")
    payload = {
        "model": model,
        "messages": messages,
        "stream": False,
        "temperature": temperature,
    }
    body = _request_json(
        _endpoint(base_url, "/chat/completions"), payload, timeout,
        build_headers(api_key, extra_headers))
    for choice in body.get("choices") or []:
        if isinstance(choice, dict):
            content = (choice.get("message") or {}).get("content")
            if content:
                return str(content)
    return ""


def embed(
    base_url: str,
    model: str,
    text: str,
    timeout: float = 60.0,
    api_key: str | None = None,
    extra_headers: dict[str, str] | None = None,
) -> list[float]:
    """``POST /embeddings``，返回首条输入的向量。"""
    if not base_url:
        raise LLMError("未配置模型服务地址。")
    if not model:
        raise LLMError("未配置嵌入模型名称。")
    payload = {"model": model, "input": text}
    body = _request_json(
        _endpoint(base_url, "/embeddings"), payload, timeout,
        build_headers(api_key, extra_headers))
    for item in body.get("data") or []:
        if isinstance(item, dict) and item.get("embedding") is not None:
            return [float(x) for x in item["embedding"]]
    raise LLMError("模型服务未返回嵌入向量。")


DEFAULT_OCR_PROMPT = "请提取图片中的全部文字，保持原有排版，只输出文字内容。"


def ocr_image(
    base_url: str,
    model: str,
    image_path: str | Path,
    prompt: str = "",
    timeout: float = 120.0,
    api_key: str | None = None,
    extra_headers: dict[str, str] | None = None,
) -> str:
    """OCR 图片文字识别：走 OpenAI 兼容多模态 ``/chat/completions``。

    图片按 Data URI（``data:image/...;base64,``）作为 ``image_url`` 内容随
    ``user`` 消息发送，返回模型识别出的文字。``model`` 须为支持视觉的 OCR /
    多模态模型（在「设置 → 模型服务」里配置 OCR 模型）。
    """
    if not base_url:
        raise LLMError("未配置模型服务地址。")
    if not model:
        raise LLMError("未配置 OCR 模型，请先到「设置 → 模型服务」选择 OCR 模型。")
    # 复用图片编码能力，保证 mime 推断与 Base64 工具一致
    from . import image_codec

    data_uri = image_codec.image_to_base64(image_path, data_uri=True)
    messages = [
        {
            "role": "user",
            "content": [
                {"type": "text", "text": prompt or DEFAULT_OCR_PROMPT},
                {"type": "image_url", "image_url": {"url": data_uri}},
            ],
        }
    ]
    return chat(
        base_url, model, messages,
        timeout=timeout, api_key=api_key, extra_headers=extra_headers,
    )
