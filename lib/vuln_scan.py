# -*- coding: utf-8 -*-
"""漏洞扫描编排器：把内置检测器 + Nuclei 模板统一编排执行，输出统一报告。

这是「Web Fuzz 进化」的核心：以往 web_fuzz / dir_scan / leak_scan / ssti /
sql_inject / param_fuzz 各自为战，各出各的报告；本模块把它们（以及新的
Nuclei 模板兼容层）编排成一条扫描流水线，最终收敛为 :class:`lib.vuln_report.VulnReport`，
统一输出 JSON / txt / Markdown 三种格式。

编排模型
--------
- **检测器（detector）**：一个可调用单元，签名 ``detector(ctx) -> list[VulnItem]``。
  ``ctx`` 是 :class:`ScanContext`（含目标 / 会话 / 超时 / stop / log）。
  内置检测器：安全响应头检查（缺失 HSTS / CSP 等）；Nuclei 模板作为一类
  「模板检测器」批量接入。
- **模板来源**：内置精选模板（``dict/nuclei-templates/``）+ 用户指定本地目录
  + 从 GitHub 拉取官方 nuclei-templates（可选）。
- **报告**：所有命中统一成 :class:`VulnItem`，由 :class:`lib.vuln_report` 渲染。

本模块只做「目标 + 配置 → 统一报告」，不导入 UI，请求统一走
:mod:`lib.proxy_pool` 的 ``make_session``（tool_id="vuln_scan"）。
"""

from __future__ import annotations

import threading
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import requests
from requests.packages import urllib3

urllib3.disable_warnings()

from lib import nuclei_engine
from lib.vuln_report import VulnItem, VulnReport, build_report

DEFAULT_TIMEOUT = 8
DEFAULT_CONCURRENCY = 10
#: 内置精选 Nuclei 模板目录（相对项目根）
BUILTIN_TEMPLATES_DIR = "dict/nuclei-templates"
#: 官方 nuclei-templates 仓库
NUCLEI_TEMPLATES_REPO = "https://github.com/projectdiscovery/nuclei-templates"
#: 官方仓库 zip 下载地址（codeload）
NUCLEI_TEMPLATES_ZIP = (
    "https://codeload.github.com/projectdiscovery/nuclei-templates/zip/refs/heads/main")

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

LogFn = Callable[[str], None]


class VulnScanError(ValueError):
    """漏洞扫描编排器参数 / 连接失败时抛出的统一异常。"""


@dataclass
class ScanContext:
    """一次扫描的共享上下文。"""

    target: str
    base_url: str
    timeout: float = DEFAULT_TIMEOUT
    concurrency: int = DEFAULT_CONCURRENCY
    session: requests.Session | None = None
    stop: threading.Event | None = None
    log: LogFn | None = None
    #: 附加数据（检测器间共享）
    data: dict[str, Any] = field(default_factory=dict)

    def emit(self, message: str) -> None:
        if self.log is not None:
            self.log(message)


# ---------------------------------------------------------------------------
# 内置检测器：安全响应头检查
# ---------------------------------------------------------------------------
SECURITY_HEADER_CHECKS: tuple[tuple[str, str, str], ...] = (
    # (响应头名, 显示名, 严重级别)
    ("strict-transport-security", "HSTS（强制 HTTPS）", "medium"),
    ("content-security-policy", "CSP（内容安全策略）", "medium"),
    ("x-content-type-options", "X-Content-Type-Options（禁 MIME 嗅探）", "low"),
    ("x-frame-options", "X-Frame-Options（防点击劫持）", "low"),
    ("x-xss-protection", "X-XSS-Protection（XSS 过滤）", "low"),
    ("referrer-policy", "Referrer-Policy", "info"),
    ("permissions-policy", "Permissions-Policy", "info"),
)


def security_headers_detector(ctx: ScanContext) -> list[VulnItem]:
    """检测缺失的安全响应头（每个缺失头一条 info/low/medium）。"""
    ctx.emit("[检测] 安全响应头检查…")
    session = ctx.session
    if session is None:
        from lib import proxy_pool
        session = proxy_pool.make_session("vuln_scan")
        session.headers.update({"User-Agent": USER_AGENT, "Connection": "close"})
    try:
        response = session.get(ctx.base_url, timeout=ctx.timeout,
                               verify=False, allow_redirects=True)
    except requests.RequestException as exc:
        ctx.emit(f"[检测] 安全响应头检查失败：{exc}")
        return []
    headers = {k.lower(): v for k, v in response.headers.items()}
    items: list[VulnItem] = []
    for header, label, severity in SECURITY_HEADER_CHECKS:
        if header in headers:
            continue
        items.append(VulnItem(
            name=f"缺少安全响应头：{label}",
            severity=severity,
            source="security_headers",
            target=ctx.base_url,
            description=f"响应中未设置 {header} 头，建议补上以增强防护。",
            evidence=f"缺失 {header}",
        ))
    ctx.emit(f"[检测] 安全响应头检查完成：{len(items)} 个缺失项")
    return items


# ---------------------------------------------------------------------------
# Nuclei 模板检测器
# ---------------------------------------------------------------------------
def _template_to_item(result: nuclei_engine.NucleiTemplateResult,
                      target: str) -> list[VulnItem]:
    """把一个 Nuclei 模板执行结果转成 VulnItem 列表。"""
    items: list[VulnItem] = []
    for finding in result.findings:
        extra: dict[str, Any] = {}
        if finding.extractor:
            extra["extractor"] = finding.extractor
        if finding.info:
            # 提取 tags / cve-id 等
            for key in ("tags", "classification", "cve-id"):
                if key in finding.info:
                    extra[key] = finding.info[key]
        reference: list[str] = []
        ref = finding.info.get("reference") or []
        if isinstance(ref, str):
            ref = [ref]
        reference = list(ref)
        items.append(VulnItem(
            name=finding.name or finding.template_id,
            severity=finding.severity,
            source=f"nuclei:{finding.template_id}",
            target=finding.matched_at or target,
            description=str(finding.info.get("description") or ""),
            evidence=finding.response[:500] if finding.response else "",
            reference=reference,
            extra=extra,
        ))
    return items


def run_nuclei_templates(
    templates: list[tuple[dict, str]],
    target: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    concurrency: int = DEFAULT_CONCURRENCY,
    log: LogFn | None = None,
    stop: threading.Event | None = None,
) -> tuple[list[VulnItem], dict[str, Any]]:
    """并发执行一批 Nuclei 模板，返回 (VulnItem 列表, 统计 dict)。"""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    emit = log or (lambda _m: None)
    items: list[VulnItem] = []
    stats: dict[str, Any] = {
        "templates_total": len(templates),
        "templates_matched": 0,
        "templates_error": 0,
        "requests": 0,
    }
    if not templates:
        return items, stats

    base_url = target.rstrip("/")
    lock = threading.Lock()

    def _work(tpl_and_path: tuple[dict, str]) -> list[VulnItem]:
        tpl, path = tpl_and_path
        if stop is not None and stop.is_set():
            return []
        try:
            result = nuclei_engine.execute_template(
                tpl, base_url, source_path=path, timeout=timeout,
                log=emit, stop=stop)
        except nuclei_engine.NucleiError as exc:
            emit(f"[nuclei] {tpl.get('id', path)} 执行失败：{exc}")
            with lock:
                stats["templates_error"] += 1
            return []
        with lock:
            stats["requests"] += 1
            if result.matched:
                stats["templates_matched"] += 1
            if result.error:
                stats["templates_error"] += 1
        if result.matched:
            emit(f"[nuclei] 命中 {result.template_id}（{result.severity}）")
            return _template_to_item(result, base_url)
        return []

    workers = max(1, min(int(concurrency), len(templates)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_work, tp) for tp in templates]
        for future in as_completed(futures):
            if stop is not None and stop.is_set():
                for f in futures:
                    f.cancel()
                break
            try:
                items.extend(future.result())
            except Exception:  # noqa: BLE001
                pass
    return items, stats


# ---------------------------------------------------------------------------
# 模板加载辅助
# ---------------------------------------------------------------------------
def builtin_template_dir() -> Path:
    """内置精选模板目录（绝对路径）。"""
    return Path(__file__).resolve().parent.parent / BUILTIN_TEMPLATES_DIR


def load_all_templates(
    extra_dirs: list[str] | None = None,
    log: LogFn | None = None,
) -> list[tuple[dict, str]]:
    """加载内置模板 + 用户指定目录里的全部模板（去重按 id）。"""
    emit = log or (lambda _m: None)
    templates: list[tuple[dict, str]] = []
    seen_ids: set[str] = set()

    def _add(tpl: dict, path: str) -> None:
        tid = str(tpl.get("id") or path)
        if tid in seen_ids:
            return
        seen_ids.add(tid)
        templates.append((tpl, path))

    builtin = builtin_template_dir()
    if builtin.is_dir():
        for tpl, path in nuclei_engine.load_templates(str(builtin), log=emit):
            _add(tpl, path)
    for directory in extra_dirs or []:
        directory = str(directory or "").strip()
        if not directory:
            continue
        try:
            for tpl, path in nuclei_engine.load_templates(directory, log=emit):
                _add(tpl, path)
        except nuclei_engine.NucleiError as exc:
            emit(f"[模板] 加载目录失败（{directory}）：{exc}")
    emit(f"[模板] 共加载 {len(templates)} 个模板")
    return templates


def download_official_templates(
    dest_dir: str,
    log: LogFn | None = None,
    stop: threading.Event | None = None,
) -> str:
    """从 GitHub 下载官方 nuclei-templates 到 ``dest_dir``，返回解压后的目录。

    返回模板根目录路径（用于后续 load_templates）。下载失败抛
    :class:`VulnScanError`。
    """
    import io
    import shutil
    import zipfile

    emit = log or (lambda _m: None)
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    emit(f"[模板] 正在下载官方 nuclei-templates…（体积较大，请耐心等待）")
    try:
        response = requests.get(
            NUCLEI_TEMPLATES_ZIP, timeout=120, stream=True,
            headers={"User-Agent": USER_AGENT}, verify=False)
        response.raise_for_status()
    except requests.RequestException as exc:
        raise VulnScanError(f"下载官方模板失败：{exc}") from exc

    total = 0
    buf = io.BytesIO()
    for chunk in response.iter_content(1024 * 256):
        if stop is not None and stop.is_set():
            emit("[模板] 下载已中止")
            return ""
        buf.write(chunk)
        total += len(chunk)
    emit(f"[模板] 下载完成：{total / 1024 / 1024:.1f} MB，正在解压…")

    buf.seek(0)
    try:
        with zipfile.ZipFile(buf) as zf:
            # 官方 zip 顶层是 nuclei-templates-main/
            names = zf.namelist()
            top = ""
            for name in names:
                if "/" in name:
                    top = name.split("/", 1)[0]
                    break
            zf.extractall(str(dest))
    except (zipfile.BadZipFile, OSError) as exc:
        raise VulnScanError(f"解压官方模板失败：{exc}") from exc

    root = dest / top if top else dest
    emit(f"[模板] 官方模板已就绪：{root}")
    return str(root)


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------
def run(
    target: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    concurrency: int = DEFAULT_CONCURRENCY,
    with_security_headers: bool = True,
    nuclei_dirs: list[str] | None = None,
    nuclei_enabled: bool = True,
    log: LogFn | None = None,
    stop: threading.Event | None = None,
) -> VulnReport:
    """执行一次漏洞扫描编排，返回统一 :class:`VulnReport`。

    参数
    ----
    target              目标 URL（可省略协议头）
    timeout             单次请求超时（秒）
    concurrency         Nuclei 模板并发度
    with_security_headers  是否运行安全响应头检测器
    nuclei_dirs         额外 Nuclei 模板目录（除内置目录外）
    nuclei_enabled      是否运行 Nuclei 模板
    log                 逐行日志回调
    stop                置位后尽快停止
    """
    import time
    from datetime import datetime

    emit = log or (lambda _m: None)
    started = time.time()
    started_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 归一化目标
    text = str(target or "").strip().replace("：", ":")
    if not text:
        raise VulnScanError("请填写目标 URL，如 https://example.com")
    if "://" not in text:
        text = "http://" + text
    parsed = urllib.parse.urlparse(text)
    if not parsed.hostname:
        raise VulnScanError("目标格式不正确，示例：https://example.com")
    base_url = text.rstrip("/")

    emit(f"[目标] {base_url}")
    from lib import proxy_pool
    session = proxy_pool.make_session("vuln_scan")
    session.headers.update({"User-Agent": USER_AGENT, "Connection": "close"})

    ctx = ScanContext(
        target=target,
        base_url=base_url,
        timeout=timeout,
        concurrency=concurrency,
        session=session,
        stop=stop,
        log=emit,
    )

    all_items: list[VulnItem] = []
    stats: dict[str, Any] = {}

    try:
        # -- 1. 安全响应头检测器 ------------------------------------------
        if with_security_headers and not (stop is not None and stop.is_set()):
            all_items.extend(security_headers_detector(ctx))
            stats["security_headers"] = "on" if with_security_headers else "off"

        # -- 2. Nuclei 模板 -------------------------------------------------
        if nuclei_enabled and not (stop is not None and stop.is_set()):
            emit("[模板] 加载 Nuclei 模板…")
            templates = load_all_templates(nuclei_dirs, log=emit)
            if templates:
                emit(f"[模板] 开始执行 {len(templates)} 个模板…")
                nuc_items, nuc_stats = run_nuclei_templates(
                    templates, base_url, timeout=timeout,
                    concurrency=concurrency, log=emit, stop=stop)
                all_items.extend(nuc_items)
                stats.update(nuc_stats)
            else:
                emit("[模板] 无可用模板，跳过 Nuclei 扫描")
                stats["templates_total"] = 0
    finally:
        try:
            session.close()
        except Exception:  # noqa: BLE001
            pass

    report = build_report(
        target=base_url,
        items=all_items,
        started_at=started_at,
        elapsed=time.time() - started,
        stopped=bool(stop is not None and stop.is_set()),
        stats=stats,
    )
    emit(f"[完成] 扫描结束：命中 {len(all_items)} 条，耗时 {report.elapsed:.1f}s")
    return report


__all__ = [
    "DEFAULT_TIMEOUT",
    "DEFAULT_CONCURRENCY",
    "VulnScanError",
    "ScanContext",
    "security_headers_detector",
    "run_nuclei_templates",
    "load_all_templates",
    "download_official_templates",
    "builtin_template_dir",
    "run",
]
