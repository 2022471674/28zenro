# -*- coding: utf-8 -*-
"""微信公众号 appid / appsecret 校验纯逻辑模块。

调用微信公众平台「获取 access_token」接口校验一组 appid 与 appsecret 是否有效：

    GET https://api.weixin.qq.com/cgi-bin/token
        ?grant_type=client_credential&appid={appid}&secret={secret}

接口约定：
- 凭证有效：返回 ``access_token`` 与 ``expires_in``（7200 秒），errmsg 缺省；
- 凭证无效：返回错误码 ``errcode`` 与错误描述 ``errmsg``（如 40013 invalid appid、
  40125 invalid appsecret）。

本模块只做「appid / appsecret 进、校验结果出」的网络处理，不导入任何 UI 模块。
支持单组校验（:func:`check_credential`）与批量校验（:func:`check_many`，
逐条顺序请求，进度经回调回报）。失败统一抛 :class:`WechatCheckError`。
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from urllib.parse import urlencode

#: 微信公众平台获取 access_token 接口
TOKEN_URL = "https://api.weixin.qq.com/cgi-bin/token"
#: 默认请求超时（秒）
DEFAULT_TIMEOUT = 15

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

ProgressFn = Callable[[str], None]


class WechatCheckError(ValueError):
    """微信凭证校验失败（网络 / 解析层）时抛出的统一异常。"""


@dataclass
class CheckResult:
    """一次凭证校验的结果。

    valid        凭证是否有效（接口返回 access_token 即视为有效）
    appid        参与校验的 appid
    access_token 有效时返回的 access_token（无效为 ""）
    expires_in   有效时返回的有效期（秒），无效为 0
    errcode      无效时微信返回的错误码（有效为 0）
    errmsg       无效时微信返回的错误描述（有效为 ""）
    raw          接口返回的原始 JSON dict
    """

    appid: str
    valid: bool
    access_token: str = ""
    expires_in: int = 0
    errcode: int = 0
    errmsg: str = ""
    raw: dict = field(default_factory=dict)


def _clean(value: str) -> str:
    """去除首尾空白；appid / secret 里若带引号也一并剥掉。"""
    return str(value or "").strip().strip("'\"")


def _safe_url(url: str) -> str:
    """去掉 query（其中含 secret 等敏感参数），仅用于拼错误信息。"""
    return str(url or "").split("?", 1)[0]


def _request_json(url: str, timeout: float) -> dict:
    """发一次 GET 请求并解析 JSON；失败统一抛 :class:`WechatCheckError`。"""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        raise WechatCheckError(
            f"微信接口返回 HTTP {exc.code}（{_safe_url(url)}）。"
        ) from exc
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, TimeoutError):
            raise WechatCheckError(f"请求微信接口超时（{timeout} 秒）。") from exc
        raise WechatCheckError(
            f"无法连接微信接口（{_safe_url(url)}），请确认网络可达。") from exc
    except TimeoutError as exc:
        raise WechatCheckError(f"请求微信接口超时（{timeout} 秒）。") from exc
    except (ConnectionError, OSError) as exc:
        raise WechatCheckError(
            f"网络连接中断（{_safe_url(url)}）：{exc}") from exc

    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        raise WechatCheckError("微信接口返回内容不是合法的 JSON。") from exc


def _parse(appid: str, body: dict) -> CheckResult:
    """把接口返回的 JSON 解析成 :class:`CheckResult`。

    有效时返回 access_token（errcode 缺省）；无效时返回 errcode / errmsg。
    少数情况下接口可能返回非 dict（如网关报错页），此时按无效处理并保留原始文本。
    """
    if not isinstance(body, dict):
        return CheckResult(
            appid=appid, valid=False, errmsg=str(body)[:200], raw={})

    token = body.get("access_token")
    if token:
        try:
            expires = int(body.get("expires_in") or 0)
        except (TypeError, ValueError):
            expires = 0
        return CheckResult(
            appid=appid, valid=True, access_token=str(token),
            expires_in=expires, raw=body)

    try:
        errcode = int(body.get("errcode") or 0)
    except (TypeError, ValueError):
        errcode = 0
    return CheckResult(
        appid=appid, valid=False, errcode=errcode,
        errmsg=str(body.get("errmsg") or ""), raw=body)


def check_credential(
    appid: str,
    secret: str,
    timeout: float = DEFAULT_TIMEOUT,
    base_url: str = TOKEN_URL,
) -> CheckResult:
    """校验一组 appid / appsecret 是否有效，返回 :class:`CheckResult`。

    网络 / 解析层失败抛 :class:`WechatCheckError`；凭证无效不抛异常，
    而是以 ``valid=False`` + errcode / errmsg 表达（属于正常业务返回）。
    """
    appid = _clean(appid)
    secret = _clean(secret)
    if not appid:
        raise WechatCheckError("请填写 AppID。")
    if not secret:
        raise WechatCheckError("请填写 AppSecret。")

    params = {
        "grant_type": "client_credential",
        "appid": appid,
        "secret": secret,
    }
    base = str(base_url or TOKEN_URL).strip()
    sep = "&" if "?" in base else "?"
    url = f"{base}{sep}{urlencode(params)}"
    body = _request_json(url, timeout)
    return _parse(appid, body)


def parse_inputs(text: str) -> list[tuple[str, str]]:
    """把批量输入文本解析成 ``(appid, secret)`` 列表。

    支持三种行格式（可混用，空行与 ``#`` 注释行忽略）：

    - ``appid secret``（空白分隔，secret 紧随其后）
    - ``appid:secret`` / ``appid：secret``（全角 / 半角冒号）
    - ``appid,secret``（逗号分隔）
    """
    pairs: list[tuple[str, str]] = []
    for raw_line in str(text or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        appid, secret = split_pair(line)
        appid = _clean(appid)
        secret = _clean(secret)
        if appid:
            pairs.append((appid, secret))
    return pairs


def split_pair(line: str) -> tuple[str, str]:
    """把一行解析成 ``(appid, secret)``，按冒号 > 逗号 > 空白分隔的优先级。"""
    line = str(line or "").strip()
    # 全角冒号统一为半角
    line = line.replace("：", ":").replace("，", ",")
    for sep in (":", ","):
        if sep in line:
            left, _, right = line.partition(sep)
            return left.strip(), right.strip()
    parts = line.split()
    if len(parts) >= 2:
        return parts[0], parts[1]
    return line, ""


def check_many(
    pairs: Iterable[tuple[str, str]],
    timeout: float = DEFAULT_TIMEOUT,
    base_url: str = TOKEN_URL,
    progress: ProgressFn | None = None,
    stop=None,
) -> list[CheckResult]:
    """批量校验多组凭证，逐条顺序请求，返回结果列表。

    单条网络异常时记录一条 ``valid=False`` 的结果（errmsg 带上原因）继续下一条，
    而不是中断整批；``stop`` 为 ``threading.Event``，置位后提前结束。
    """
    results: list[CheckResult] = []
    total = 0
    for appid, secret in pairs:
        if stop is not None and stop.is_set():
            break
        total += 1
        try:
            result = check_credential(appid, secret, timeout, base_url)
        except WechatCheckError as exc:
            result = CheckResult(appid=appid, valid=False, errmsg=str(exc))
        results.append(result)
        if progress:
            progress(f"已校验 {total} 条（{appid}）："
                     f"{'有效' if result.valid else '无效'}")
    return results
