# -*- coding: utf-8 -*-
"""漏洞扫描编排器页：内置检测器 + Nuclei 模板统一编排，输出统一报告。

页面只负责「收集参数 + 结果展示 + 落盘」，全部逻辑在 :mod:`lib.vuln_scan`
与 :mod:`lib.nuclei_engine`。命中结果统一为 :class:`lib.vuln_report.VulnReport`，
支持 JSON / txt / Markdown 三种导出。网络请求在后台线程执行（:class:`FuzzWorker`），
界面不阻塞；所有请求走全局代理池。
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from app.widgets.fuzz_worker import FuzzWorker
from app.widgets.no_wheel import NoWheelMixin, NoWheelSpinBox
from lib import vuln_scan, vuln_report
from lib.watermark import resolve_output_dir


class _VulnScanWorker(FuzzWorker):
    """后台执行漏洞扫描编排。"""

    error_prefix = "扫描失败"

    def __init__(self, target: str, timeout: int, concurrency: int,
                 with_security_headers: bool, nuclei_enabled: bool,
                 nuclei_dirs: list[str], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._target = target
        self._timeout = timeout
        self._concurrency = concurrency
        self._with_security_headers = with_security_headers
        self._nuclei_enabled = nuclei_enabled
        self._nuclei_dirs = nuclei_dirs

    def task(self) -> vuln_report.VulnReport:
        return vuln_scan.run(
            self._target,
            timeout=self._timeout,
            concurrency=self._concurrency,
            with_security_headers=self._with_security_headers,
            nuclei_enabled=self._nuclei_enabled,
            nuclei_dirs=self._nuclei_dirs,
            log=self.log.emit,
            stop=self._event,
        )


class VulnScanPage(QWidget):
    """漏洞扫描编排器页。"""

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._worker: _VulnScanWorker | None = None
        self._report: vuln_report.VulnReport | None = None
        self._build_ui()
        self._restore_config()

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        outer.addWidget(scroll)

        container = QWidget()
        scroll.setWidget(container)
        layout = QVBoxLayout(container)
        layout.setContentsMargins(36, 28, 36, 28)
        layout.setSpacing(10)

        form = QHBoxLayout()
        form.setSpacing(10)
        form.addWidget(QLabel("目标 URL"))
        self.url_edit = QLineEdit()
        self.url_edit.setPlaceholderText(
            "https://example.com（可省略协议头，如 example.com）")
        self.url_edit.returnPressed.connect(self._start)
        form.addWidget(self.url_edit, 1)
        layout.addLayout(form)

        opts = QHBoxLayout()
        opts.setSpacing(16)
        self.timeout_spin = NoWheelSpinBox()
        self.timeout_spin.setRange(1, 60)
        self.timeout_spin.setValue(vuln_scan.DEFAULT_TIMEOUT)
        self.timeout_spin.setSuffix(" 秒")
        opts.addWidget(QLabel("超时"))
        opts.addWidget(self.timeout_spin)

        self.concurrency_spin = NoWheelSpinBox()
        self.concurrency_spin.setRange(1, 100)
        self.concurrency_spin.setValue(vuln_scan.DEFAULT_CONCURRENCY)
        opts.addWidget(QLabel("并发"))
        opts.addWidget(self.concurrency_spin)
        opts.addStretch(1)
        layout.addLayout(opts)

        # -- 检测器开关 ----------------------------------------------------
        detector_opts = QHBoxLayout()
        detector_opts.setSpacing(16)
        self.security_headers_check = QCheckBox("安全响应头检查")
        self.security_headers_check.setChecked(True)
        self.security_headers_check.setToolTip(
            "检测缺失 HSTS / CSP / X-Frame-Options 等安全响应头。")
        detector_opts.addWidget(self.security_headers_check)

        self.nuclei_check = QCheckBox("Nuclei 模板扫描")
        self.nuclei_check.setChecked(True)
        self.nuclei_check.setToolTip(
            "运行内置精选模板 + 用户指定目录的 Nuclei YAML 模板。")
        detector_opts.addWidget(self.nuclei_check)
        detector_opts.addStretch(1)
        layout.addLayout(detector_opts)

        # -- 模板目录 ------------------------------------------------------
        tmpl_opts = QHBoxLayout()
        tmpl_opts.setSpacing(10)
        tmpl_opts.addWidget(QLabel("模板目录"))
        self.tmpl_dir_edit = QLineEdit()
        self.tmpl_dir_edit.setPlaceholderText(
            "可选：额外的 Nuclei 模板目录（含 .yaml 文件）")
        tmpl_opts.addWidget(self.tmpl_dir_edit, 1)
        browse_btn = QPushButton("浏览")
        browse_btn.setObjectName("ghbtn")
        browse_btn.clicked.connect(self._browse_dir)
        tmpl_opts.addWidget(browse_btn)
        download_btn = QPushButton("下载官方模板")
        download_btn.setObjectName("ghbtn")
        download_btn.setToolTip(
            "从 GitHub 下载官方 projectdiscovery/nuclei-templates 仓库（体积较大）")
        download_btn.clicked.connect(self._download_official)
        tmpl_opts.addWidget(download_btn)
        layout.addLayout(tmpl_opts)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        self.run_btn = QPushButton("开始扫描")
        self.run_btn.setObjectName("ghbtn-primary")
        self.run_btn.clicked.connect(self._start)
        buttons.addWidget(self.run_btn)

        self.stop_btn = QPushButton("停止")
        self.stop_btn.setObjectName("ghbtn")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop)
        buttons.addWidget(self.stop_btn)

        self.save_btn = QPushButton("导出报告")
        self.save_btn.setObjectName("ghbtn")
        self.save_btn.setEnabled(False)
        self.save_btn.clicked.connect(self._save)
        buttons.addWidget(self.save_btn)

        open_btn = QPushButton("打开输出目录")
        open_btn.setObjectName("ghbtn")
        open_btn.clicked.connect(self._open_output)
        buttons.addWidget(open_btn)

        clear_btn = QPushButton("清空")
        clear_btn.setObjectName("ghbtn")
        clear_btn.clicked.connect(self._clear)
        buttons.addWidget(clear_btn)
        buttons.addStretch(1)
        layout.addLayout(buttons)

        self.report_label = QLabel("扫描报告")
        self.report_label.setObjectName("section")
        layout.addWidget(self.report_label)

        self.report_view = QPlainTextEdit()
        self.report_view.setObjectName("io")
        self.report_view.setReadOnly(True)
        self.report_view.setPlaceholderText(
            "点击「开始扫描」后，这里会显示统一漏洞报告（默认纯文本视图）…")
        self.report_view.setMinimumHeight(320)
        layout.addWidget(self.report_view, 1)

        self.log_label = QLabel("扫描日志")
        self.log_label.setObjectName("section")
        layout.addWidget(self.log_label)

        self.log_view = QPlainTextEdit()
        self.log_view.setObjectName("io")
        self.log_view.setReadOnly(True)
        self.log_view.setMinimumHeight(90)
        self.log_view.setMaximumHeight(150)
        self.log_view.setMaximumBlockCount(3000)
        layout.addWidget(self.log_view)

        self.status_label = QLabel("")
        self.status_label.setObjectName("status-info")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

    # ------------------------------------------------------------------ 配置
    def _restore_config(self) -> None:
        cfg = self.store.get("vuln_scan", default={}) or {}
        try:
            self.timeout_spin.setValue(int(cfg.get("timeout")
                                           or vuln_scan.DEFAULT_TIMEOUT))
        except (TypeError, ValueError):
            self.timeout_spin.setValue(vuln_scan.DEFAULT_TIMEOUT)
        try:
            self.concurrency_spin.setValue(int(cfg.get("concurrency")
                                               or vuln_scan.DEFAULT_CONCURRENCY))
        except (TypeError, ValueError):
            self.concurrency_spin.setValue(vuln_scan.DEFAULT_CONCURRENCY)
        self.security_headers_check.setChecked(bool(cfg.get("security_headers", True)))
        self.nuclei_check.setChecked(bool(cfg.get("nuclei", True)))
        self.tmpl_dir_edit.setText(str(cfg.get("tmpl_dir", "") or ""))

    def _save_config(self) -> None:
        self.store.setv(int(self.timeout_spin.value()), "vuln_scan", "timeout")
        self.store.setv(int(self.concurrency_spin.value()), "vuln_scan", "concurrency")
        self.store.setv(bool(self.security_headers_check.isChecked()),
                        "vuln_scan", "security_headers")
        self.store.setv(bool(self.nuclei_check.isChecked()), "vuln_scan", "nuclei")
        self.store.setv(self.tmpl_dir_edit.text().strip(), "vuln_scan", "tmpl_dir")
        self.store.save()

    @property
    def _output_root(self) -> Path:
        cfg = self.store.get("watermark", default={}) or {}
        return resolve_output_dir(cfg.get("output_dir"))

    # ------------------------------------------------------------------ 操作
    def _start(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._set_status(False, "扫描正在进行中，请先停止。")
            return
        target = self.url_edit.text().strip()
        if not target:
            self._set_status(False, "请填写目标 URL，如 https://example.com。")
            return

        self._save_config()
        self._report = None
        self.report_view.clear()
        self.log_view.clear()
        self.save_btn.setEnabled(False)
        self.run_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self._set_status(True, "正在扫描…")

        nuclei_dirs = []
        tmpl_dir = self.tmpl_dir_edit.text().strip()
        if tmpl_dir:
            nuclei_dirs.append(tmpl_dir)

        old = self._worker
        worker = _VulnScanWorker(
            target,
            int(self.timeout_spin.value()),
            int(self.concurrency_spin.value()),
            self.security_headers_check.isChecked(),
            self.nuclei_check.isChecked(),
            nuclei_dirs,
            self,
        )
        worker.log.connect(self._append_log)
        worker.done_ok.connect(self._on_done)
        worker.done_err.connect(self._on_error)
        self._worker = worker
        if old is not None:
            old.deleteLater()
        worker.start()

    def _stop(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._worker.stop()
            self._set_status(True, "正在停止…（等待在途请求结束）")

    def _clear(self) -> None:
        self.url_edit.clear()
        self.report_view.clear()
        self.log_view.clear()
        self._report = None
        self.save_btn.setEnabled(False)
        self._set_status(True, "")

    def _browse_dir(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "选择 Nuclei 模板目录")
        if path:
            self.tmpl_dir_edit.setText(path)

    def _download_official(self) -> None:
        # 官方模板体积大，放到后台线程下载，避免卡界面
        dest = str(builtin_template_dir() / "official")
        self._set_status(True, "正在下载官方模板…（后台进行，可继续等待）")
        # 简化：同步下载放在 worker 里太重，这里用一个轻量线程
        import threading

        def _dl() -> None:
            try:
                root = vuln_scan.download_official_templates(dest, log=self._append_log)
                if root:
                    self._append_log(f"[模板] 官方模板已下载到：{root}")
                    self.tmpl_dir_edit.setText(root)
                    self._set_status(True, f"官方模板已下载：{root}")
                else:
                    self._set_status(False, "官方模板下载被中止")
            except vuln_scan.VulnScanError as exc:
                self._set_status(False, str(exc))

        threading.Thread(target=_dl, daemon=True).start()

    def _on_done(self, report: vuln_report.VulnReport) -> None:
        self._reset_buttons()
        self._report = report
        self.report_view.setPlainText(vuln_report.to_text(report))
        self.save_btn.setEnabled(True)
        counts = "，".join(
            f"{vuln_report.SEVERITY_LABELS.get(k, k)} {v}"
            for k, v in report.severity_counts.items())
        msg = (f"扫描{'已停止' if report.stopped else '完成'}："
               f"命中 {len(report.items)} 条"
               + (f"（{counts}）" if counts else "")
               + "。可点「导出报告」落盘。")
        self._set_status(not report.stopped, msg)

    def _on_error(self, message: str) -> None:
        self._reset_buttons()
        self._set_status(False, message)

    def _reset_buttons(self) -> None:
        self.run_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def _save(self) -> None:
        if self._report is None:
            self._set_status(False, "还没有可导出的报告，请先开始扫描。")
            return
        target = self.url_edit.text().strip()
        if "://" not in target:
            target = "http://" + target
        host = urlparse(target).netloc.replace(":", "_") or "vulnscan"
        out_dir = self._output_root
        default = str(out_dir / f"{host}_vulnscan")
        path, _ = QFileDialog.getSaveFileName(
            self, "导出漏洞扫描报告", default, "JSON (*.json);;文本 (*.txt);;Markdown (*.md)")
        if not path:
            return
        # 根据扩展名决定格式
        ext = Path(path).suffix.lower()
        fmt = "json" if ext == ".json" else ("markdown" if ext == ".md" else "txt")
        try:
            Path(path).write_text(vuln_report.render(self._report, fmt), encoding="utf-8")
        except OSError as exc:
            self._set_status(False, f"保存失败：{exc}")
            return
        self._set_status(True, f"已导出：{path}")

    def _open_output(self) -> None:
        path = self._output_root
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            self._set_status(False, f"无法打开目录：{exc}")
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    # ------------------------------------------------------------------ 输出
    def _append_log(self, message: str) -> None:
        self.log_view.appendPlainText(message)
        bar = self.log_view.verticalScrollBar()
        bar.setValue(bar.maximum())

    def _set_status(self, ok: bool, text: str) -> None:
        self.status_label.setText(text)
        self.status_label.setObjectName("status-ok" if ok else "status-err")
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)

    # ------------------------------------------------------------------ 生命周期
    def shutdown(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._worker.stop()
            self._worker.wait(1500)


def builtin_template_dir() -> Path:
    """供页面引用的内置模板目录（转发 lib.vuln_scan）。"""
    return vuln_scan.builtin_template_dir()
