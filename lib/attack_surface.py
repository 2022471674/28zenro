# -*- coding: utf-8 -*-
"""攻击面测绘（一键全链路）：把现有 Web 原子工具编排成一条 pipeline。

对单个目标（域名或 URL）按固定顺序跑一遍攻击面测绘，输出合并汇总：

    子域名爆破 → 端口爆破 → 指纹探测 → WAF 识别 → 目录爆破 →
    源码泄露 → 参数爆破 → OSS 桶探测

每一步复用 :mod:`lib` 里已有的纯函数（``dns_tool`` / ``port_scan`` /
``fingerprint`` / ``waf_detect`` / ``dir_scan`` / ``leak_scan`` /
``param_fuzz`` / ``oss_bucket``），**不重复实现算法**，只负责：

1. 按依赖顺序调度（子域名 / 端口先出「资产清单」，指纹 / WAF / 目录 / 泄露 /
   参数 / 桶再针对性地探）；
2. 统一日志、``stop`` 中断、单步失败不影响后续步骤；
3. 汇总成一份结构化报告 + 文本报告。

设计约定
--------
- 本模块只做纯逻辑，不导入 UI；所有网络请求由各原子模块自己走
  ``proxy_pool.make_session()``（遵守 Web 工具统一代理约定）。
- 每一步都有独立开关（``with_*``），默认**不跑重资源步骤**（端口 / 目录 /
  源码泄露），避免误伤目标；子域名 / 指纹 / WAF / 参数 / OSS 默认开启。
- 全程支持 ``stop`` 事件与逐行日志。

本模块只做「目标进、报告出」的纯逻辑。
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any, Callable

LogFn = Callable[[str], None]


class AttackSurfaceError(ValueError):
    """攻击面测绘参数错误时抛出的统一异常。"""


# ---------------------------------------------------------------------------
# 步骤定义（顺序即执行顺序）
# ---------------------------------------------------------------------------
#: 每一步的 (step_id, 展示名, 默认是否开启, 是否重资源)
STEPS: tuple[tuple[str, str, bool, bool], ...] = (
    ("subdomain", "子域名爆破", True, True),
    ("port", "端口爆破", False, True),
    ("fingerprint", "指纹探测", True, False),
    ("waf", "WAF 识别", True, False),
    ("dir", "目录爆破", False, True),
    ("leak", "源码泄露", False, True),
    ("param", "参数爆破", True, False),
    ("oss", "OSS 桶探测", True, False),
)

#: 默认端口扫描范围（常见 Web 端口）
DEFAULT_PORTS = (
    80, 443, 8080, 8443, 8000, 8001, 8888, 3000, 5000, 7001, 9090, 9200, 2375,
)


def _normalize_domain(target: str) -> str:
    """从目标提取主域名（去协议 / 路径 / 端口）。"""
    from lib import dns_tool

    return dns_tool.normalize_domain(target)


def _normalize_url(target: str) -> str:
    """把目标补成完整 URL。"""
    from lib.waf_detect import normalize_url

    return normalize_url(target)


def _emit_step(emit: LogFn, name: str, ok: bool, note: str = "") -> None:
    emit(f"===== [步骤] {name} {'完成' if ok else '失败'}"
         + (f"：{note}" if note else "") + " =====")


def run(
    target: str,
    timeout: float = 8,
    with_subdomain: bool = True,
    with_port: bool = False,
    with_fingerprint: bool = True,
    with_waf: bool = True,
    with_dir: bool = False,
    with_leak: bool = False,
    with_param: bool = True,
    with_oss: bool = True,
    subdomain_dict: str | Path | None = None,
    subdomain_interval: float = 0.3,
    ports: str = "",
    threads: int = 16,
    log: LogFn | None = None,
    stop: threading.Event | None = None,
) -> dict[str, Any]:
    """对 ``target`` 做一次完整攻击面测绘，返回结构化汇总。"""
    emit = log or (lambda _m: None)
    stop = stop or threading.Event()
    started = time.time()

    domain = _normalize_domain(target)
    base_url = _normalize_url(target)
    emit(f"[目标] {domain}（{base_url}）")

    report: dict[str, Any] = {
        "target": domain, "url": base_url, "steps": [],
        "summary": {}, "elapsed": 0.0,
    }
    summary: dict[str, Any] = {}

    def _add_step(step_id: str, name: str, ok: bool, note: str,
                  result: Any) -> None:
        report["steps"].append({
            "id": step_id, "name": name, "ok": ok, "note": note, "result": result,
        })

    # -- 1. 子域名爆破 -------------------------------------------------------
    if with_subdomain and not stop.is_set():
        emit("[1/8] 子域名爆破…")
        try:
            from lib import dns_tool
            subs, note = dns_tool.brute_subdomains(
                domain, dict_path=subdomain_dict, interval=subdomain_interval,
                timeout=timeout, log=emit, stop=stop)
            summary["subdomains"] = len(subs)
            _add_step("subdomain", "子域名爆破", True, note, subs)
            _emit_step(emit, "子域名爆破", True, f"发现 {len(subs)} 个")
        except Exception as exc:  # noqa: BLE001
            summary["subdomains"] = 0
            _add_step("subdomain", "子域名爆破", False, str(exc), [])
            _emit_step(emit, "子域名爆破", False, str(exc))

    # -- 2. 端口爆破 ---------------------------------------------------------
    if with_port and not stop.is_set():
        emit("[2/8] 端口爆破…")
        try:
            from lib import port_scan
            port_list = port_scan.parse_ports(ports) if ports.strip() \
                else list(DEFAULT_PORTS)
            pr = port_scan.scan(
                domain, port_list, threads=threads, timeout=timeout,
                log=emit, stop=stop)
            hits = pr.get("hits", [])
            summary["ports"] = len(hits)
            _add_step("port", "端口爆破", True, f"开放 {len(hits)} 个", hits)
            _emit_step(emit, "端口爆破", True, f"开放 {len(hits)} 个")
        except Exception as exc:  # noqa: BLE001
            summary["ports"] = 0
            _add_step("port", "端口爆破", False, str(exc), [])
            _emit_step(emit, "端口爆破", False, str(exc))

    # -- 3. 指纹探测 ---------------------------------------------------------
    if with_fingerprint and not stop.is_set():
        emit("[3/8] 指纹探测…")
        try:
            from lib import fingerprint
            fr = fingerprint.run(base_url, timeout=timeout, log=emit, stop=stop)
            matches = fr.get("matches", [])
            summary["fingerprints"] = len(matches)
            _add_step("fingerprint", "指纹探测", True, "", matches)
            _emit_step(emit, "指纹探测", True, f"命中 {len(matches)} 条")
        except Exception as exc:  # noqa: BLE001
            summary["fingerprints"] = 0
            _add_step("fingerprint", "指纹探测", False, str(exc), [])
            _emit_step(emit, "指纹探测", False, str(exc))

    # -- 4. WAF 识别 ---------------------------------------------------------
    if with_waf and not stop.is_set():
        emit("[4/8] WAF 识别…")
        try:
            from lib import waf_detect
            wr = waf_detect.run(base_url, timeout=timeout, log=emit, stop=stop)
            matches = wr.get("matches", [])
            summary["waf"] = matches
            _add_step("waf", "WAF 识别", True,
                      "有 WAF" if wr.get("blocked") else "无 WAF", wr)
            _emit_step(emit, "WAF 识别", True,
                       f"命中 {len(matches)} 个" if matches else "未发现")
        except Exception as exc:  # noqa: BLE001
            summary["waf"] = []
            _add_step("waf", "WAF 识别", False, str(exc), [])
            _emit_step(emit, "WAF 识别", False, str(exc))

    # -- 5. 目录爆破 ---------------------------------------------------------
    if with_dir and not stop.is_set():
        emit("[5/8] 目录爆破…")
        try:
            from lib import dir_scan
            dr = dir_scan.scan(
                base_url, threads=threads, timeout=timeout,
                log=emit, stop=stop)
            hits = dr.get("hits", [])
            summary["dirs"] = len(hits)
            _add_step("dir", "目录爆破", True, f"命中 {len(hits)} 条", hits)
            _emit_step(emit, "目录爆破", True, f"命中 {len(hits)} 条")
        except Exception as exc:  # noqa: BLE001
            summary["dirs"] = 0
            _add_step("dir", "目录爆破", False, str(exc), [])
            _emit_step(emit, "目录爆破", False, str(exc))

    # -- 6. 源码泄露 ---------------------------------------------------------
    if with_leak and not stop.is_set():
        emit("[6/8] 源码泄露…")
        try:
            from lib import leak_scan
            import tempfile
            out_dir = Path(tempfile.mkdtemp(prefix="attack_surface_leak_"))
            results = leak_scan.run(
                base_url, out_dir, threads=threads, timeout=timeout,
                log=emit, stop=stop)
            found = [r for r in results if r.get("found")]
            summary["leaks"] = len(found)
            _add_step("leak", "源码泄露", True, f"命中 {len(found)} 条", found)
            _emit_step(emit, "源码泄露", True, f"命中 {len(found)} 条")
        except Exception as exc:  # noqa: BLE001
            summary["leaks"] = 0
            _add_step("leak", "源码泄露", False, str(exc), [])
            _emit_step(emit, "源码泄露", False, str(exc))

    # -- 7. 参数爆破 ---------------------------------------------------------
    if with_param and not stop.is_set():
        emit("[7/8] 参数爆破…")
        try:
            from lib import param_fuzz
            pr = param_fuzz.run(base_url, timeout=timeout, log=emit, stop=stop)
            found = pr.get("found_params", [])
            summary["params"] = len(found)
            _add_step("param", "参数爆破", True, f"发现 {len(found)} 个", found)
            _emit_step(emit, "参数爆破", True, f"发现 {len(found)} 个")
        except Exception as exc:  # noqa: BLE001
            summary["params"] = 0
            _add_step("param", "参数爆破", False, str(exc), [])
            _emit_step(emit, "参数爆破", False, str(exc))

    # -- 8. OSS 桶探测 -------------------------------------------------------
    if with_oss and not stop.is_set():
        emit("[8/8] OSS 桶探测…")
        try:
            from lib import oss_bucket
            or_ = oss_bucket.run("", domain=domain, timeout=timeout,
                                 log=emit, stop=stop)
            hits = or_.get("hits", [])
            summary["oss"] = len(hits)
            _add_step("oss", "OSS 桶探测", True, f"命中 {len(hits)} 个", hits)
            _emit_step(emit, "OSS 桶探测", True, f"命中 {len(hits)} 个")
        except Exception as exc:  # noqa: BLE001
            summary["oss"] = 0
            _add_step("oss", "OSS 桶探测", False, str(exc), [])
            _emit_step(emit, "OSS 桶探测", False, str(exc))

    report["summary"] = summary
    report["elapsed"] = round(time.time() - started, 2)
    report["stopped"] = stop.is_set()
    emit(f"[完成] 攻击面测绘结束，耗时 {report['elapsed']}s"
         + ("（已手动停止）" if stop.is_set() else ""))
    return report


def to_text(report: dict[str, Any]) -> str:
    """把攻击面测绘报告渲染成文本。"""
    lines: list[str] = []
    lines.append(f"# 攻击面测绘报告：{report.get('target', '')}")
    lines.append(f"# 目标 URL: {report.get('url', '')}")
    lines.append(f"# 耗时: {report.get('elapsed', 0)}s"
                 + ("（已停止）" if report.get("stopped") else ""))
    lines.append("")

    summary = report.get("summary", {})
    if summary:
        lines.append("=== 汇总 ===")
        for key, label in (
            ("subdomains", "子域名"), ("ports", "开放端口"),
            ("fingerprints", "指纹"), ("waf", "WAF"),
            ("dirs", "目录"), ("leaks", "源码泄露"),
            ("params", "参数"), ("oss", "OSS 桶"),
        ):
            value = summary.get(key)
            if isinstance(value, list):
                lines.append(f"  {label}: {len(value)}")
            else:
                lines.append(f"  {label}: {value}")
        lines.append("")

    for step in report.get("steps", []):
        mark = "✓" if step.get("ok") else "✗"
        lines.append(f"=== [{mark}] {step.get('name')} ===")
        if step.get("note"):
            lines.append(f"  {step['note']}")
        result = step.get("result")
        if isinstance(result, list):
            for item in result:
                lines.append(f"  - {item}")
        elif isinstance(result, dict) and step.get("id") == "waf":
            for m in result.get("matches", []):
                lines.append(f"  - {m.get('name')}")
        lines.append("")

    lines.append("# 生成于 cipherNest 攻击面测绘")
    return "\n".join(lines)


__all__ = [
    "STEPS",
    "DEFAULT_PORTS",
    "AttackSurfaceError",
    "run",
    "to_text",
]
