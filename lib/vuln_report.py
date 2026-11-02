# -*- coding: utf-8 -*-
"""统一漏洞扫描报告模型与渲染（JSON / 纯文本 / Markdown）。

漏洞扫描编排器（:mod:`lib.vuln_scan`）与 Nuclei 模板引擎（
:mod:`lib.nuclei_engine`）的结果都收敛到 :class:`VulnReport`，再由本模块
渲染成统一的 JSON / txt / Markdown 三种格式。这样无论命中来自内置检测器
还是 Nuclei 模板，报告结构、严重级别、字段含义都保持一致。

本模块只做「结构化结果 → 文本」的纯渲染，不导入 UI、不发请求。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

#: 严重级别排序权重（升序 = 越不严重越靠前）
SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
SEVERITY_LABELS = {
    "info": "信息",
    "low": "低危",
    "medium": "中危",
    "high": "高危",
    "critical": "严重",
}


@dataclass
class VulnItem:
    """一条漏洞 / 发现（来自任一检测器或 Nuclei 模板）。"""

    name: str = ""
    severity: str = "info"
    #: 来源：内置检测器名 或 nuclei 模板 id
    source: str = ""
    #: 命中 URL / 位置
    target: str = ""
    #: 一句话描述
    description: str = ""
    #: 证据 / 匹配详情
    evidence: str = ""
    #: 参考链接（CVE / 文档）
    reference: list[str] = field(default_factory=list)
    #: 附加结构化字段（提取器结果、matcher 类型等）
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "severity": self.severity,
            "source": self.source,
            "target": self.target,
            "description": self.description,
            "evidence": self.evidence,
            "reference": list(self.reference),
            "extra": dict(self.extra),
        }

    @property
    def severity_label(self) -> str:
        return SEVERITY_LABELS.get(self.severity, self.severity)

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 0)


@dataclass
class VulnReport:
    """一次扫描的汇总报告。"""

    target: str = ""
    started_at: str = ""
    elapsed: float = 0.0
    stopped: bool = False
    items: list[VulnItem] = field(default_factory=list)
    #: 扫描统计：{模板/检测器数, 请求数, ...}
    stats: dict[str, Any] = field(default_factory=dict)
    #: 各严重级别计数
    severity_counts: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "elapsed": round(self.elapsed, 1),
            "stopped": self.stopped,
            "stats": dict(self.stats),
            "severity_counts": dict(self.severity_counts),
            "items": [i.to_dict() for i in self.items],
        }

    def sort_by_severity(self) -> None:
        """按严重级别降序（严重在前），同级按来源/名称稳定排序。"""
        self.items.sort(key=lambda i: (-i.severity_rank, i.source, i.name))


def _count_severities(items: list[VulnItem]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        counts[item.severity] = counts.get(item.severity, 0) + 1
    # 按固定顺序输出
    ordered = {}
    for sev in ("critical", "high", "medium", "low", "info"):
        if sev in counts:
            ordered[sev] = counts[sev]
    for sev, n in counts.items():
        if sev not in ordered:
            ordered[sev] = n
    return ordered


def build_report(target: str, items: list[VulnItem], *,
                 started_at: str = "", elapsed: float = 0.0,
                 stopped: bool = False,
                 stats: dict[str, Any] | None = None) -> VulnReport:
    """构造 :class:`VulnReport` 并自动统计严重级别、排序。"""
    report = VulnReport(
        target=target,
        started_at=started_at,
        elapsed=elapsed,
        stopped=stopped,
        items=list(items),
        stats=dict(stats or {}),
    )
    report.severity_counts = _count_severities(report.items)
    report.sort_by_severity()
    return report


# ---------------------------------------------------------------------------
# 渲染
# ---------------------------------------------------------------------------
def to_json(report: VulnReport) -> str:
    """渲染为结构化 JSON（机器可读，含全部字段）。"""
    return json.dumps(report.to_dict(), ensure_ascii=False, indent=2)


def to_text(report: VulnReport) -> str:
    """渲染为纯文本报告（复用项目现有 ``#`` / ``===`` 风格）。"""
    lines: list[str] = []
    add = lines.append

    add("# 漏洞扫描报告")
    add(f"# 目标: {report.target}")
    if report.started_at:
        add(f"# 开始时间: {report.started_at}")
    add(f"# 耗时: {report.elapsed:.1f}s"
        + ("（已手动停止）" if report.stopped else ""))
    add(f"# 命中总数: {len(report.items)}")
    if report.severity_counts:
        add("# 严重级别: " + "，".join(
            f"{SEVERITY_LABELS.get(k, k)} {v}" for k, v in report.severity_counts.items()))
    stats = report.stats or {}
    if stats:
        add("# 扫描统计: " + "，".join(f"{k}={v}" for k, v in stats.items()))

    if not report.items:
        add("")
        add("（未发现漏洞 / 无命中）")
        return "\n".join(lines)

    for idx, item in enumerate(report.items, 1):
        add("")
        add(f"=== [{idx}] {item.severity_label} — {item.name or '(未命名)'} ===")
        add(f"  严重级别: {item.severity}")
        if item.source:
            add(f"  来源: {item.source}")
        if item.target:
            add(f"  位置: {item.target}")
        if item.description:
            add(f"  描述: {item.description}")
        if item.evidence:
            add(f"  证据: {item.evidence}")
        if item.reference:
            add("  参考:")
            for ref in item.reference:
                add(f"    - {ref}")
        if item.extra:
            add("  详情:")
            for k, v in item.extra.items():
                add(f"    {k}: {v}")

    add("")
    add("# 生成于 28zenro 漏洞扫描编排器")
    return "\n".join(lines)


def to_markdown(report: VulnReport) -> str:
    """渲染为 Markdown 报告（便于贴到文档 / ticket）。"""
    lines: list[str] = []
    add = lines.append

    add("# 漏洞扫描报告")
    add("")
    add(f"- **目标**: `{report.target}`")
    if report.started_at:
        add(f"- **开始时间**: {report.started_at}")
    add(f"- **耗时**: {report.elapsed:.1f}s"
        + ("（已手动停止）" if report.stopped else ""))
    add(f"- **命中总数**: {len(report.items)}")
    if report.severity_counts:
        add("- **严重级别**: " + "，".join(
            f"{SEVERITY_LABELS.get(k, k)} {v}" for k, v in report.severity_counts.items()))
    stats = report.stats or {}
    if stats:
        add("- **扫描统计**: " + "，".join(f"{k}={v}" for k, v in stats.items()))
    add("")

    if not report.items:
        add("> 未发现漏洞 / 无命中。")
        add("")
        return "\n".join(lines)

    # 汇总表
    add("## 汇总")
    add("")
    add("| # | 严重级别 | 名称 | 来源 | 位置 |")
    add("|---|----------|------|------|------|")
    for idx, item in enumerate(report.items, 1):
        sev = item.severity_label
        name = (item.name or "未命名").replace("|", "\\|")
        source = item.source.replace("|", "\\|")
        target = item.target.replace("|", "\\|")
        add(f"| {idx} | {sev} | {name} | {source} | {target} |")
    add("")

    # 明细
    add("## 明细")
    add("")
    for idx, item in enumerate(report.items, 1):
        add(f"### {idx}. [{item.severity_label}] {item.name or '(未命名)'}")
        add("")
        add(f"- **严重级别**: `{item.severity}`")
        if item.source:
            add(f"- **来源**: `{item.source}`")
        if item.target:
            add(f"- **位置**: `{item.target}`")
        if item.description:
            add(f"- **描述**: {item.description}")
        if item.evidence:
            add(f"- **证据**: `{item.evidence}`")
        if item.reference:
            add("- **参考**:")
            for ref in item.reference:
                add(f"  - {ref}")
        if item.extra:
            add("- **详情**:")
            for k, v in item.extra.items():
                add(f"  - `{k}`: {v}")
        add("")

    add("---")
    add("")
    add("*生成于 28zenro 漏洞扫描编排器*")
    return "\n".join(lines)


def render(report: VulnReport, fmt: str = "json") -> str:
    """按格式渲染报告；``fmt`` 取 ``json`` / ``txt`` / ``markdown``。"""
    if fmt == "txt" or fmt == "text":
        return to_text(report)
    if fmt == "markdown" or fmt == "md":
        return to_markdown(report)
    return to_json(report)


__all__ = [
    "VulnItem",
    "VulnReport",
    "build_report",
    "to_json",
    "to_text",
    "to_markdown",
    "render",
    "SEVERITY_LABELS",
    "SEVERITY_ORDER",
]
