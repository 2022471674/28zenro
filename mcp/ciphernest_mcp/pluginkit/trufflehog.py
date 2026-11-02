# -*- coding: utf-8 -*-
"""cn_trufflehog —— TruffleHog 二次封装工具组。

TruffleHog（``mcp/plugins/trufflehog/trufflehog.exe``）是 Go 的密钥泄露扫描器：

- **结果**：``--json`` 时以 NDJSON 逐行写 **stdout**（字段 ``DetectorName`` /
  ``Verified`` / ``Raw`` / ``SourceMetadata``）；
- **日志**：写 stderr，不能当结果解析；
- **更新器**：默认会联网自更新，自更新失败会直接退出，所以**必须**带
  ``--no-update``；
- **退出码**：不加 ``--fail`` 时，扫到密钥也返回 0。

适配器把 NDJSON 解析成结构化的 ``findings``，并统计 detector / 是否已验证。
"""

from __future__ import annotations

from typing import Any

from ..contract import (Ctx, Group, arr, custom_op, flag, num, txt)
from ..envelope import ToolError
from ._paths import resolve_path
from .runtime import (first_line, get_plugin, parse_ndjson, plugin_result,
                      run_plugin)

_KEY = "trufflehog"
_TOOL = "cn_trufflehog"


def _args(a: dict[str, Any], source: list[str]) -> list[str]:
    args = list(source) + ["--json", "--no-update"]
    if not a["verify"]:
        args.append("--no-verification")
    if a["concurrency"]:
        args.append(f"--concurrency={a['concurrency']}")
    results = str(a["results"] or "").strip()
    if results:
        args.append(f"--results={results}")
    if a["extra_args"]:
        args += list(a["extra_args"])
    return args


def _location(finding: dict[str, Any]) -> dict[str, Any] | None:
    meta = finding.get("SourceMetadata")
    data = (meta or {}).get("Data") if isinstance(meta, dict) else None
    if not isinstance(data, dict):
        return None
    for kind, detail in data.items():
        if not isinstance(detail, dict):
            continue
        location: dict[str, Any] = {"source": kind}
        for key in ("file", "line", "commit", "repository", "link", "email",
                    "image", "bucket", "key"):
            if key in detail:
                location[key] = detail[key]
        return location
    return None


def _parse_findings(stdout: str, limit: int) -> tuple[list[dict[str, Any]], int]:
    items = [item for item in parse_ndjson(stdout) if "DetectorName" in item]
    findings: list[dict[str, Any]] = []
    for item in items[:limit]:
        raw = str(item.get("Raw") or "")
        findings.append({
            "detector": item.get("DetectorName"),
            "verified": bool(item.get("Verified")),
            "decoder": item.get("DecoderName"),
            "raw": raw[:400],
            "raw_length": len(raw),
            "location": _location(item),
        })
    return findings, len(items)


def _run_op(a: dict[str, Any], source: list[str]) -> dict[str, Any]:
    plugin = get_plugin(_KEY)
    args = _args(a, source)
    run = run_plugin(plugin, args, timeout=a["max_seconds"])
    findings, total = _parse_findings(run.stdout, a["max_findings"])
    detectors = sorted({str(item["detector"]) for item in findings})
    verified = sum(1 for item in findings if item["verified"])
    payload = plugin_result(run, plugin, {
        "args": args,
        "findings_count": total,
        "verified_count": verified,
        "detectors": detectors,
        "findings": findings,
        "findings_truncated": total > len(findings),
        "source": source[0] if source else None,
    })
    return payload


def _version(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    plugin = get_plugin(_KEY)
    run = run_plugin(plugin, ["--version"], timeout=60)
    return plugin_result(run, plugin, {"version": first_line(run.stdout)})


def _scan_git(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    return _run_op(a, ["git", a["url"]])


def _scan_filesystem(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    path = resolve_path(a["path"], field="path", must_exist=True)
    return _run_op(a, ["filesystem", str(path)])


def _scan_docker(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    return _run_op(a, ["docker", a["image"]])


_COMMON = [
    flag("verify", default=False,
         desc="是否在线验证密钥（联网、更慢；默认关闭，只做离线识别）"),
    num("concurrency", default=None, desc="并发 chunk 数（留空用工具默认）",
        minimum=1, maximum=64),
    txt("results", default="verified,unverified,unknown",
        desc="结果过滤：verified / unverified / unknown 逗号组合"),
    num("max_findings", default=50, desc="最多返回多少条命中（影响上下文体积）",
        minimum=1, maximum=500),
    num("max_seconds", default=300, desc="最长运行秒数", minimum=5, maximum=3600),
    arr("extra_args", default=None, desc="追加原生参数（高级用法）"),
]


OPS = [
    custom_op("version", _version, "查看 TruffleHog 版本。", [],
              returns="dict：{success, version}", risk="safe",
              module="plugins/trufflehog"),
    custom_op("scan_git", _scan_git,
              "扫描 Git 仓库 / 远程地址中的密钥（trufflehog git）。",
              [txt("url", required=True,
                   desc="仓库地址，如 https://github.com/owner/repo 或本地路径"),
               *_COMMON],
              returns="dict：{success, findings_count, verified_count, detectors, "
                      "findings: [{detector, verified, raw, location}]}",
              risk="network", module="plugins/trufflehog",
              notes="默认离线识别（不验证）；需要验证可信度时传 verify=true。"),
    custom_op("scan_filesystem", _scan_filesystem,
              "扫描本地目录中的密钥 / 凭证（trufflehog filesystem）。",
              [txt("path", required=True,
                   desc="目录或文件路径（相对项目根或绝对）"),
               *_COMMON],
              returns="dict：{success, findings_count, detectors, findings}",
              risk="read", module="plugins/trufflehog",
              notes="纯本地扫描，适合先跑了 cn_scan/leak_scan 拿到源码后检查凭证。"),
    custom_op("scan_docker", _scan_docker,
              "扫描本地 Docker 镜像层中的密钥（trufflehog docker）。",
              [txt("image", required=True, desc="镜像名，如 nginx:latest"), *_COMMON],
              returns="dict：{success, findings_count, detectors, findings}",
              risk="network", module="plugins/trufflehog"),
]


GROUP = Group(
    name=_TOOL,
    title="TruffleHog：密钥 / 凭证泄露扫描",
    summary=("TruffleHog 二次封装：扫描 Git 仓库、本地目录、Docker 镜像中的密钥与凭证，"
             "NDJSON 结果已解析为结构化 findings（detector / verified / 位置）。"),
    ops=OPS,
    guide=("默认离线识别（--no-verification）更快；verify=true 会联网向各平台验证密钥真伪。"
           "只对已授权仓库 / 目录做扫描。"),
)
