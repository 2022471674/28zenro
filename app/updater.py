# -*- coding: utf-8 -*-
"""28zenro 更新检查器：从 GitHub 拉取 version.json 并做语义化版本判断。

版本源约定（GitHub 仓库根目录或 Release 资产的 ``version.json``）：

.. code-block:: json

    {
      "latest": "1.0.2",          // 最新稳定版（语义化版本号，可带 v 前缀）
      "min_supported": "1.0.0",   // 最低支持升级的版本；低于它必须走全量重装
      "assets": {
        "full":   { "url": "https://.../28zenro-1.0.2.zip", "sha256": "...", "size": 12345678 },
        "patch":  { "url": "https://.../patch-1.0.1-1.0.2.zip", "sha256": "...", "size": 1234, "from": "1.0.1" }
      },
      "notes": "修复 xxx；新增 yyy",
      "published_at": "2026-11-03T12:00:00Z"
    }

本模块只负责「判断」，不负责「下载 / 安装」——真正替换文件由独立的
安装器（28zenroInstaller）完成，避免「程序覆盖正在运行的 exe」这一经典死结。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

#: 版本清单默认地址（GitHub 仓库根目录，主分支）
DEFAULT_MANIFEST_URL = (
    "https://raw.githubusercontent.com/2022471674/28zenro/main/version.json"
)
#: 请求超时（秒）
_TIMEOUT = 8

#: 语义化版本三段式：可选 v 前缀，允许缺省的补丁位（1.2 -> 1.2.0）
_VERSION_RE = re.compile(
    r"^[vV]?(\d+)(?:\.(\d+))?(?:\.(\d+))?"
    r"(?:[-.]([0-9A-Za-z.-]+))?$"
)


def parse_version(text: str) -> tuple[int, int, int]:
    """把 ``1.2`` / ``v1.2.3`` / ``1.0.1-beta`` 解析成 ``(主, 次, 补丁)``。

    无法解析时返回 ``(0, 0, 0)``（视为「最旧」，永不触发更新）。
    预发布 / 构建元数据（``-beta``、``+sha``）不参与比较，仅提取三段数字。
    """
    m = _VERSION_RE.match(str(text).strip())
    if not m:
        return (0, 0, 0)
    major = int(m.group(1))
    minor = int(m.group(2) or 0)
    patch = int(m.group(3) or 0)
    return (major, minor, patch)


def is_newer(remote: str, current: str) -> bool:
    """远端版本是否严格高于当前版本（语义化比较）。"""
    return parse_version(remote) > parse_version(current)


@dataclass
class UpdateInfo:
    """一次更新检查的完整结论。"""

    current: str
    latest: str = ""
    has_update: bool = False
    #: 当前版本是否已低于「最低支持升级」版本（此时只能全量重装）
    needs_full: bool = False
    notes: str = ""
    published_at: str = ""
    download_url: str = ""
    download_sha256: str = ""
    download_size: int = 0
    error: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.error


def _pick_asset(raw: dict, current: str) -> tuple[str, str, int, bool]:
    """从 version.json 里挑出适合当前版本的下载资产。

    返回 ``(url, sha256, size, needs_full)``。优先增量补丁（patch.from
    恰好等于当前版本），否则回退全量包；都没有则返回空串。
    """
    assets = raw.get("assets") or {}
    if not isinstance(assets, dict):
        return "", "", 0, False

    patch = assets.get("patch")
    if isinstance(patch, dict) and str(patch.get("from", "")).strip() == current:
        return (
            str(patch.get("url", "")),
            str(patch.get("sha256", "")),
            int(patch.get("size", 0) or 0),
            False,
        )

    full = assets.get("full")
    if isinstance(full, dict):
        return (
            str(full.get("url", "")),
            str(full.get("sha256", "")),
            int(full.get("size", 0) or 0),
            True,
        )

    return "", "", 0, False


def evaluate(raw: dict, current: str) -> UpdateInfo:
    """把已解析的 version.json 与当前版本比对，产出 :class:`UpdateInfo`。

    纯函数，不涉及网络，便于单元测试。
    """
    info = UpdateInfo(current=current, raw=raw)
    if not isinstance(raw, dict):
        info.error = "version.json 结构无效（应为 JSON 对象）"
        return info

    latest = str(raw.get("latest", "")).strip()
    info.latest = latest
    info.notes = str(raw.get("notes", ""))
    info.published_at = str(raw.get("published_at", ""))

    if not latest:
        info.error = "version.json 缺少 latest 字段"
        return info
    if not is_newer(latest, current):
        # 已是最新（或远端不高于本地），无需更新
        info.has_update = False
        return info

    info.has_update = True
    url, sha256, size, needs_full = _pick_asset(raw, current)
    info.download_url = url
    info.download_sha256 = sha256
    info.download_size = size
    info.needs_full = needs_full

    min_supported = str(raw.get("min_supported", "")).strip()
    if min_supported and parse_version(current) < parse_version(min_supported):
        info.needs_full = True

    if not url:
        info.error = f"检测到新版本 {latest}，但 version.json 未提供可用的下载地址"
    return info


def check(current: str, manifest_url: str = DEFAULT_MANIFEST_URL,
          timeout: float = _TIMEOUT) -> UpdateInfo:
    """联网拉取 version.json 并判断是否需要更新。

    网络失败 / 解析失败不会抛异常，而是把原因写进 ``UpdateInfo.error``，
    调用方据此给出「无法检查更新」的提示。
    """
    try:
        import requests
    except ImportError:  # 理论上不会发生（requirements 已含 requests）
        return UpdateInfo(current=current, error="缺少 requests 依赖，无法联网检查")

    try:
        resp = requests.get(manifest_url, timeout=timeout)
        resp.raise_for_status()
        raw = resp.json()
    except Exception as exc:  # noqa: BLE001  网络异常种类多，统一降级为提示
        return UpdateInfo(current=current, error=f"检查更新失败：{exc}")

    return evaluate(raw, current)
