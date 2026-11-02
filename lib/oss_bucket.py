# -*- coding: utf-8 -*-
"""对象存储桶探测（OSS Bucket）：检测阿里云 OSS / 腾讯 COS / AWS S3 桶的越权访问。

CTF 与授权测试中，对象存储桶常因配置不当被公开读取，或可枚举对象列表。
本模块对给定的一组桶名（或主域名自动派生候选桶名）逐个探测：

- **公开读检测**：匿名 GET 桶 / 对象，命中 200 且内容非权限错误 → 公开可读；
- **可枚举检测**：对桶发 ListObjects / GetBucket 类匿名请求，命中可解析对象
  列表 → 桶开启了列举权限（``ListBucket`` 类权限）；
- **存在性检测**：即使不可读，也能通过状态码 / 错误体区分「桶存在但拒绝」
  与「桶不存在」，帮助判断目标是否用了某厂商的对象存储。

设计约定（与其它 Web 工具一致）
----------------------------
- 所有 HTTP 请求统一经 :func:`_session` 拿 ``proxy_pool.make_session()`` 创建
  会话 —— 启用全局代理池时自动走轮换代理，未启用时 ``trust_env=False`` 直连。
- 本模块只做「桶名进、结构化结果出」的纯逻辑，不导入任何 UI 模块。
- 全程支持 ``stop`` 事件与逐行日志回调。

本模块只做纯逻辑。
"""

from __future__ import annotations

import threading
from typing import Any, Callable

import requests
from requests.packages import urllib3

urllib3.disable_warnings()

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
DEFAULT_TIMEOUT = 8
MAX_BUCKETS = 200

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

LogFn = Callable[[str], None]


class OssBucketError(ValueError):
    """OSS 桶探测参数错误时抛出的统一异常。"""


# ---------------------------------------------------------------------------
# 厂商探针模板
# ---------------------------------------------------------------------------
#: 每种厂商的探测端点模板：(桶名) -> URL 列表，以及「桶不存在」的判定关键词。
#: ``list_url``  匿名列举对象列表的端点（命中 → 可枚举）
#: ``bucket_url`` 匿名读取桶根的对象端点（命中 → 公开可读 / 桶存在）
_PROVIDERS: tuple[dict[str, Any], ...] = (
    {
        "id": "aliyun",
        "name": "阿里云 OSS",
        "bucket_url": "https://{bucket}.oss-cn-hangzhou.aliyuncs.com/",
        "list_url": "https://{bucket}.oss-cn-hangzhou.aliyuncs.com/?list-type=2&max-keys=5",
        "not_exist_markers": ("nosuchbucket", "nosuchkey"),
        "denied_markers": ("accessdenied", "invalidaccesskeyid",
                           "signaturedoesnotmatch"),
    },
    {
        "id": "tencent",
        "name": "腾讯云 COS",
        "bucket_url": "https://{bucket}.cos.ap-guangzhou.myqcloud.com/",
        "list_url": "https://{bucket}.cos.ap-guangzhou.myqcloud.com/?prefix=&max-keys=5",
        "not_exist_markers": ("nosuchbucket",),
        "denied_markers": ("accessdenied",),
    },
    {
        "id": "aws",
        "name": "AWS S3",
        "bucket_url": "https://{bucket}.s3.amazonaws.com/",
        "list_url": "https://{bucket}.s3.amazonaws.com/?list-type=2&max-keys=5",
        "not_exist_markers": ("nosuchbucket",),
        "denied_markers": ("accessdenied",),
    },
)


def _session() -> requests.Session:
    """创建走全局代理池的请求会话（Web 工具统一入口）。"""
    from lib import proxy_pool

    session = proxy_pool.make_session("oss_bucket")
    session.headers.update({"User-Agent": USER_AGENT, "Connection": "close"})
    return session


def normalize_bucket_name(raw: str) -> str:
    """把输入整理成合法桶名（小写、仅字母数字连字符、去首尾空白）。"""
    text = str(raw or "").strip().lower()
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/", 1)[0].strip()
    text = "".join(ch for ch in text if ch.isalnum() or ch == "-")
    text = text.strip("-")
    if not text:
        raise OssBucketError("桶名格式不正确，示例：my-bucket")
    return text


def derive_bucket_names(domain: str, extra: str = "") -> list[str]:
    """从主域名派生候选桶名（用于「一键全链路」与被动探测）。

    常见命名习惯：``域名主体``、``域名主体-oss``、``域名主体-backup``、
    ``www-域名主体`` 等。``extra`` 可追加用户自定义桶名（逗号 / 换行分隔）。
    """
    from lib import dns_tool

    base = dns_tool.normalize_domain(domain)
    parts = [p for p in base.split(".") if p and p != "www"]
    body = parts[0] if parts else base
    candidates: list[str] = []
    seen: set[str] = set()
    for name in (
        body,
        f"{body}-oss",
        f"{body}-backup",
        f"{body}-static",
        f"{body}-img",
        f"{body}-file",
        f"www-{body}",
    ):
        if name not in seen:
            seen.add(name)
            candidates.append(name)
    for token in (extra or "").replace("\n", ",").replace("，", ",").split(","):
        token = token.strip()
        if not token:
            continue
        try:
            name = normalize_bucket_name(token)
        except OssBucketError:
            continue
        if name not in seen:
            seen.add(name)
            candidates.append(name)
    return candidates[:MAX_BUCKETS]


def _try_list(session: requests.Session, provider: dict[str, Any],
              bucket: str, timeout: float, result: dict[str, Any]) -> None:
    """尝试匿名列举对象列表，命中则标记可枚举。"""
    url = provider["list_url"].format(bucket=bucket)
    try:
        response = session.get(url, timeout=timeout, verify=False,
                               allow_redirects=True, stream=True)
        status = response.status_code
        body = response.content[:64 * 1024]
        response.close()
    except requests.RequestException:
        return
    text = body.decode("utf-8", "ignore")
    if status == 200 and ("<key>" in text.lower() or "<contents>" in text.lower()):
        result["listable"] = True
        result["note"] = "可匿名列举对象列表（ListBucket 权限）"
    elif result["public_read"]:
        result["note"] = "公开可读"


def _probe_one(session: requests.Session, provider: dict[str, Any],
               bucket: str, timeout: float) -> dict[str, Any]:
    """探测单个桶在单个厂商下的访问状态。"""
    result: dict[str, Any] = {
        "bucket": bucket,
        "provider": provider["name"],
        "provider_id": provider["id"],
        "exists": False,
        "public_read": False,
        "listable": False,
        "status": 0,
        "note": "",
    }
    url = provider["bucket_url"].format(bucket=bucket)
    try:
        response = session.get(url, timeout=timeout, verify=False,
                               allow_redirects=True, stream=True)
        result["status"] = response.status_code
        body = response.content[:64 * 1024]
        response.close()
    except requests.RequestException as exc:
        result["note"] = f"连接失败：{exc}"
        return result

    text = body.decode("utf-8", "ignore").lower()
    if result["status"] == 200:
        result["exists"] = True
        result["public_read"] = True
    elif result["status"] in (301, 302, 307, 308):
        result["exists"] = True
        result["note"] = "存在（重定向）"
        return result
    elif any(m in text for m in provider["not_exist_markers"]):
        result["note"] = "桶不存在"
        return result
    elif result["status"] == 403:
        result["exists"] = True
        result["note"] = "桶存在但拒绝匿名访问"
        return result
    elif result["status"] == 404:
        result["note"] = "桶不存在（404）"
        return result

    if result["exists"]:
        _try_list(session, provider, bucket, timeout, result)
    return result


def run(
    buckets: str | list[str],
    domain: str = "",
    timeout: float = DEFAULT_TIMEOUT,
    log: LogFn | None = None,
    stop: threading.Event | None = None,
) -> dict[str, Any]:
    """对一组桶名做多厂商越权探测，返回结构化汇总。

    参数
    ----
    buckets  桶名列表（逗号 / 换行分隔的字符串，或 list[str]）；
             为空时配合 ``domain`` 自动派生候选桶名。
    domain   主域名（可选，用于自动派生候选桶名）。
    timeout  单次请求超时（秒）。
    log      逐行日志回调。
    stop     置位后尽快停止。

    返回
    ----
    ``{"buckets": [...], "hits": [...], "summary": {...}}``，
    每条 ``{"bucket","provider","provider_id","exists","public_read",
    "listable","status","note"}``；``hits`` 只保留存在 / 可读 / 可枚举的桶。
    """
    emit = log or (lambda _m: None)

    if isinstance(buckets, str):
        names: list[str] = []
        if domain:
            names = derive_bucket_names(domain, extra=buckets)
        else:
            for token in buckets.replace("\n", ",").replace("，", ",").split(","):
                token = token.strip()
                if not token:
                    continue
                try:
                    names.append(normalize_bucket_name(token))
                except OssBucketError as exc:
                    emit(f"[跳过] {token}：{exc}")
    else:
        names = [normalize_bucket_name(b) for b in (buckets or []) if b]

    names = list(dict.fromkeys(names))[:MAX_BUCKETS]
    if not names:
        raise OssBucketError("请填写要探测的桶名，或提供主域名以自动派生候选桶名")

    emit(f"[目标] 共 {len(names)} 个桶名 × {len(_PROVIDERS)} 个厂商")
    session = _session()
    results: list[dict[str, Any]] = []
    for bucket in names:
        if stop is not None and stop.is_set():
            emit("[中止] 已停止探测")
            break
        for provider in _PROVIDERS:
            if stop is not None and stop.is_set():
                break
            item = _probe_one(session, provider, bucket, timeout)
            results.append(item)
            if item["exists"]:
                emit(f"[命中] {bucket} @ {provider['name']}：{item['note'] or '存在'}")
            else:
                emit(f"[未命中] {bucket} @ {provider['name']}：{item['note'] or '不存在'}")
    session.close()

    hits = [r for r in results if r["exists"]]
    summary = {
        "total": len(results),
        "exists": len(hits),
        "public_read": sum(1 for r in hits if r["public_read"]),
        "listable": sum(1 for r in hits if r["listable"]),
    }
    return {"buckets": results, "hits": hits, "summary": summary}


__all__ = [
    "DEFAULT_TIMEOUT",
    "OssBucketError",
    "normalize_bucket_name",
    "derive_bucket_names",
    "run",
]
