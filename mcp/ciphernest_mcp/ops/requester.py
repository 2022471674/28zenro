# -*- coding: utf-8 -*-
"""cn_requester —— HTTP 请求器（类 Burp Repeater / Intruder，不抓包）。

与 GUI 的「HTTP 请求器」页同源：``lib.http_requester`` 负责构造与发送，
``lib.crypto_interface`` 负责把明文批量加密成载荷。Agent 可直接用本工具：

- ``send``：发一次请求（常量模式，``{{payload}}`` 用 ``payload`` 替换）；
- ``loop``：循环模式，四种攻击类型（sniper / batteringram / pitchfork /
  clusterbomb），载荷可当场用密码学接口生成；
- ``crypto_list`` / ``crypto_transform``：查看 / 调用密码学载荷生成器；
- ``plan``：只算不发，先看会打多少次请求。

编码约定（重要）：请求报文由 lib 自行拼装，**载荷按字面发送**，
已经 Base64 / URL 编码的密文不会被二次转义。

合规：本工具只发请求、不抓包；主动探测仅可用于已授权目标。
"""

from __future__ import annotations

from typing import Any

from lib import crypto_interface, http_requester

from ..contract import (Ctx, Group, anyp, arr, custom_op, flag, flt, make_op,
                        num, obj, txt)
from ..envelope import ToolError, to_jsonable

_LOCATION_CHOICES_HINT = ("载荷位置：query / header / body / url；"
                          "亦可用单位置键（如 query:0:0）精确指定")


def _spec_from(a: dict[str, Any]) -> http_requester.RequestSpec:
    """把 op 参数收成 RequestSpec。

    给了 ``spec`` 时以它为基础，再用**显式传入**的顶层键覆盖
    （顶层键带默认值 '' 表示「没传」，不能拿来覆盖 spec 里的内容）。
    """
    if a.get("spec"):
        data = dict(a["spec"])
        for key in ("url", "method", "query", "headers", "body", "body_kind",
                    "scheme"):
            value = a.get(key)
            if value not in (None, "", "GET", "http"):
                data[key] = value
        return http_requester.RequestSpec.from_mapping(data)
    return http_requester.RequestSpec.from_mapping({
        "url": a.get("url") or "",
        "method": a.get("method") or "GET",
        "query": a.get("query"),
        "headers": a.get("headers"),
        "body": a.get("body"),
        "body_kind": a.get("body_kind") or "",
        "scheme": a.get("scheme") or "http",
    })


def _per_location(raw: Any) -> dict[str, list[str]] | None:
    """``per_location`` 入参：``{位置键: "每行一个" | [载荷…]}``。"""
    if not raw:
        return None
    if not isinstance(raw, dict):
        raise ToolError("type_error",
                        "per_location 需要对象：{位置键: 载荷文本或数组}",
                        field="per_location")
    out: dict[str, list[str]] = {}
    for key, value in raw.items():
        if isinstance(value, str):
            out[str(key)] = http_requester.split_payloads(value)
        elif isinstance(value, (list, tuple)):
            out[str(key)] = [str(item) for item in value]
        else:
            raise ToolError("type_error",
                            f"per_location[{key}] 需要字符串或数组",
                            field="per_location")
    return out


def _run_options(a: dict[str, Any]) -> dict[str, Any]:
    """run() 的通用参数。"""
    return {
        "timeout": float(a.get("timeout") or http_requester.DEFAULT_TIMEOUT),
        "redirects": bool(a.get("redirects", http_requester.DEFAULT_REDIRECTS)),
        "verify": bool(a.get("verify", http_requester.DEFAULT_VERIFY_TLS)),
        "workers": int(a.get("workers") or 1),
        "delay": float(a.get("delay") or 0.0),
    }


# ---------------------------------------------------------------------------
# 载荷准备：可先用密码学接口把明文变成密文
# ---------------------------------------------------------------------------
def _payloads(a: dict[str, Any], ctx: Ctx) -> list[str]:
    items = http_requester.split_payloads(a.get("payloads") or "")
    op_id = str(a.get("crypto") or "").strip()
    if op_id and items:
        values = a.get("crypto_params") or None
        result = crypto_interface.transform(items, op_id, values)
        for error in result.errors[:5]:
            ctx.warn(f"载荷 {error['input']!r} 变换失败：{error['error']}")
        ctx.log(f"已用「{result.label}」把 {len(items)} 个明文变换成载荷")
        return result.outputs
    return items


# ---------------------------------------------------------------------------
# op 实现
# ---------------------------------------------------------------------------
def _send(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    spec = _spec_from(a)
    spec.timeout = float(a.get("timeout") or http_requester.DEFAULT_TIMEOUT)
    spec.redirects = bool(a.get("redirects", http_requester.DEFAULT_REDIRECTS))
    spec.verify = bool(a.get("verify", http_requester.DEFAULT_VERIFY_TLS))
    payload = a.get("payload")
    # 常量值填进每个载荷位置（与 GUI 的常量模式一致）
    values = ([str(payload)] * len(spec.slots())
              if payload is not None and spec.has_placeholder() else [])
    session = http_requester.make_session()
    try:
        record = http_requester.send(session, spec, values, index=1,
                                     payloads=values)
    finally:
        session.close()
    return record.to_dict() | {"request_dump": record.request_dump}


def _loop_or_send(a: dict[str, Any], ctx: Ctx, mode: str) -> dict[str, Any]:
    spec = _spec_from(a)
    if not str(spec.url or "").strip():
        raise ToolError("missing_param", "缺少目标 url", field="url")
    items = _payloads(a, ctx)
    return http_requester.run(
        spec,
        mode=mode,
        attack=a.get("attack") or http_requester.ATTACK_SNIPER,
        payloads=items,
        per_location=_per_location(a.get("per_location")),
        const_value=str(a.get("payload") or ""),
        log=ctx.log,
        stop=ctx.stop,
        **_run_options(a),
    )


def _plan(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    spec = _spec_from(a)
    items = _payloads(a, ctx)
    plan_obj = http_requester.plan(
        spec,
        mode=a.get("mode") or http_requester.MODE_LOOP,
        attack=a.get("attack") or http_requester.ATTACK_SNIPER,
        payloads=items,
        per_location=_per_location(a.get("per_location")),
    )
    payload = plan_obj.to_dict()
    # 附上前若干次请求的最终 URL，便于核对有没有被二次编码
    combos = http_requester.combinations(plan_obj)[:5]
    payload["sample_requests"] = [
        {"values": combo, "url": http_requester.compose(spec, combo)["url"],
         "body": http_requester.compose(spec, combo)["body"]}
        for combo in combos]
    return payload


def _compose(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    spec = _spec_from(a)
    values = [str(item) for item in (a.get("values") or [])]
    payload = http_requester.compose(spec, values)
    return {key: to_jsonable(value) for key, value in payload.items()}


def _crypto_transform(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    items = http_requester.split_payloads(a.get("data") or "")
    result = crypto_interface.transform(items, a.get("op"),
                                        a.get("params") or None)
    payload = result.to_dict()
    payload["text"] = "\n".join(result.outputs)
    return payload


WEB_SPEC_PARAMS = [
    txt("url", desc="目标 URL（可含 {{payload}}）"),
    txt("method", default="GET", desc="请求方法，任意字符串（GET/POST/PUT…）"),
    anyp("query", desc='查询参数：``"a=1&b=2"`` 字符串或 {"a": "1"} 对象'),
    anyp("headers", desc='请求头：``"X-A: 1\\nX-B: 2"`` 字符串或 {"X-A": "1"}'),
    anyp("body", desc='请求体：字符串 / 对象 / [{name,value}] 列表'),
    txt("body_kind", desc="请求体类型", choices=http_requester.BODY_KINDS),
    txt("scheme", default="http", desc="URL 缺协议头时补的协议", choices=("http", "https")),
    obj("spec", desc="或直接给完整请求对象（键同上述 url/method/query/headers/body）"),
]

NET_OPTS = [
    flt("timeout", default=http_requester.DEFAULT_TIMEOUT, desc="单次请求超时（秒）",
        minimum=1, maximum=300),
    flag("redirects", default=http_requester.DEFAULT_REDIRECTS, desc="是否跟随重定向"),
    flag("verify", default=http_requester.DEFAULT_VERIFY_TLS, desc="是否校验证书"),
    num("workers", default=1, desc="并发数（循环模式）", minimum=1, maximum=32),
    flt("delay", default=0.0, desc="每次请求间隔（秒）", minimum=0, maximum=60),
]

OPS = [
    custom_op(
        "send", lambda a, ctx: _loop_or_send(a, ctx, http_requester.MODE_CONST),
        "常量模式：发一次请求，把 {{payload}} 全部换成 payload 的值。",
        params=WEB_SPEC_PARAMS + NET_OPTS + [
            txt("payload", desc="常量值，替换请求里所有 {{payload}}"),
        ],
        returns="dict：{mode, total, done, responses: [{index, status, length, url, ...}]}",
        risk="network", module="lib.http_requester",
        example={"url": "https://example.com/api", "method": "POST",
                 "query": {"token": "{{payload}}"},
                 "body": "data={{payload}}", "body_kind": "form",
                 "payload": "aGVsbG8+"},
        notes="载荷按字面发送，不会被二次 URL 编码。",
    ),
    custom_op(
        "loop", lambda a, ctx: _loop_or_send(a, ctx, http_requester.MODE_LOOP),
        "循环模式：按攻击类型批量替换载荷位置后逐个发请求。",
        params=WEB_SPEC_PARAMS + NET_OPTS + [
            txt("attack", default=http_requester.ATTACK_SNIPER,
                desc="攻击类型", choices=http_requester.ATTACKS),
            txt("payloads", desc="通用载荷列表（每行一个）"),
            obj("per_location", desc="按位置给载荷：{位置键: '每行一个' 或 [载荷…]}"),
            txt("crypto", desc="先用该密码学生成器变换 payloads（见 crypto_list）"),
            obj("crypto_params", desc="密码学生成器的参数，如 {\"key\": \"…\"}"),
        ],
        returns="dict：{mode, attack, total, done, responses: [{payloads, status, ...}]}",
        risk="intrusive", module="lib.http_requester",
        example={"url": "https://example.com/api", "method": "POST",
                 "body": "cipher={{payload}}", "body_kind": "form",
                 "attack": "sniper", "payloads": "flag\nadmin",
                 "crypto": "crypto.base64"},
        notes=(_LOCATION_CHOICES_HINT + "。主动批量请求请只用于已授权目标；"
               "建议先用 plan 看总量。"),
    ),
    custom_op("plan", _plan, "只计算不发送：返回载荷位置、总请求数与样例报文 URL。",
              params=WEB_SPEC_PARAMS + [
                  txt("mode", default=http_requester.MODE_LOOP, desc="模式",
                      choices=http_requester.MODES),
                  txt("attack", default=http_requester.ATTACK_SNIPER, desc="攻击类型",
                      choices=http_requester.ATTACKS),
                  txt("payloads", desc="通用载荷列表（每行一个）"),
                  obj("per_location", desc="按位置给载荷"),
                  txt("crypto", desc="先用该密码学生成器变换 payloads"),
                  obj("crypto_params", desc="密码学生成器参数"),
              ],
              returns="dict：{slots, total_requests, sample_requests, warning}",
              risk="safe", module="lib.http_requester"),
    custom_op("compose", _compose,
              "只组装报文不发送：返回最终 URL / 请求头 / 请求体 / Burp 风格报文。",
              params=WEB_SPEC_PARAMS + [
                  arr("values", desc="按载荷位置顺序给出的载荷值列表"),
              ],
              returns="dict：{method, url, headers, body, query, request_dump}",
              risk="safe", module="lib.http_requester",
              notes="最适合用来确认「已编码的密文有没有被再编码」。"),
    custom_op("crypto_list", lambda a, ctx: {
        "count": len(crypto_interface.CRYPTO_OPS),
        "groups": crypto_interface.groups(),
        "ops": crypto_interface.list_ops(),
    }, "列出全部密码学载荷生成器（可用于 loop 的 crypto 参数）。",
              [], returns="dict：{count, groups, ops: [...]}", risk="safe",
              module="lib.crypto_interface"),
    custom_op("crypto_transform", _crypto_transform,
              "用密码学生成器把多行明文批量变换成载荷。",
              [txt("data", required=True, desc="明文，每行一个"),
               txt("op", required=True, desc="生成器 id，如 crypto.base64"),
               obj("params", desc="生成器参数，如 {\"shift\": 3}")],
              returns="dict：{op, label, count, outputs, text, errors}",
              risk="safe", module="lib.crypto_interface",
              example={"data": "flag\nhello", "op": "crypto.base64"}),
    make_op(http_requester.url_safe, "最小 URL 安全化：只编码空格 / 非 ASCII / 保留 % + = 等。",
            [txt("text", required=True, desc="原文")],
            returns="str：安全化后的文本", risk="safe"),
    make_op(http_requester.split_payloads, "把多行文本切成载荷列表（忽略空行）。",
            [txt("text", required=True, desc="多行文本")],
            returns="list[str]：载荷列表", risk="safe"),
    make_op(http_requester.to_text, "把 loop / send 的结果渲染成纯文本报告。",
            [anyp("result", required=True, desc="loop / send 的返回 dict")],
            returns="str：文本报告", risk="safe"),
]


GROUP = Group(
    name="cn_requester",
    title="HTTP 请求器：常量 / 循环（Burp 风格）+ 密码学载荷",
    summary=("自定义 URL / 方法 / 查询参数 / 请求头 / 请求体的 HTTP 请求发送器"
             "（不抓包）。常量模式发一次；循环模式按 Sniper / Battering ram / "
             "Pitchfork / Cluster bomb 批量替换载荷位置，载荷可用密码学接口批量生成。"),
    ops=OPS,
    guide=("载荷位置写 {{payload}}；载荷按字面发送，不会被二次 URL 编码。"
           "先 plan 看总量，再用 loop 发送；只对已授权目标使用。"
           "crypto_list 可查全部密码学载荷生成器。"),
)
