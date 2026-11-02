# -*- coding: utf-8 -*-
"""Web Fuzz 页：输入一个 URL，把页面与主机的信息一次性抓全。

页面只负责「收集参数 + 结果展示 + 落盘」，全部网络逻辑在
:mod:`lib.web_fuzz`。结果分区展示（概览 / 响应头 / 链接 / 表单 / 敏感信息…），
并提供「合并导出 txt」按钮：把整个报告合并成一份 `.txt` 落到输出目录。

网络请求在后台线程执行，界面不阻塞；所有请求都走全局代理池（内置浏览器除外）。
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QCheckBox,
    QDoubleSpinBox,
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
from lib import web_fuzz
from lib.watermark import resolve_output_dir


class _NoWheelDoubleSpinBox(NoWheelMixin, QDoubleSpinBox):
    """滚过时不改值的小数输入框（用于子域名爆破速率限制间隔）。"""


class _WebFuzzWorker(FuzzWorker):
    """后台执行 Web Fuzz。"""

    error_prefix = "收集失败"

    def __init__(self, target: str, timeout: int, with_robots: bool,
                 with_sitemap: bool, with_hostsearch: bool,
                 with_subdomain_brute: bool, subdomain_interval: float,
                 subdomain_use_proxy: bool, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._target = target
        self._timeout = timeout
        self._with_robots = with_robots
        self._with_sitemap = with_sitemap
        self._with_hostsearch = with_hostsearch
        self._with_subdomain_brute = with_subdomain_brute
        self._subdomain_interval = subdomain_interval
        self._subdomain_use_proxy = subdomain_use_proxy

    def task(self) -> dict:
        return web_fuzz.run(
            self._target,
            timeout=self._timeout,
            with_robots=self._with_robots,
            with_sitemap=self._with_sitemap,
            with_hostsearch=self._with_hostsearch,
            with_subdomain_brute=self._with_subdomain_brute,
            subdomain_interval=self._subdomain_interval,
            subdomain_use_proxy=self._subdomain_use_proxy,
            log=self.log.emit,
            stop=self._event,
        )


class WebFuzzPage(QWidget):
    """Web Fuzz（Web 信息收集）页。"""

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._worker: _WebFuzzWorker | None = None
        self._result: dict | None = None
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
        self.timeout_spin.setValue(web_fuzz.DEFAULT_TIMEOUT)
        self.timeout_spin.setSuffix(" 秒")
        opts.addWidget(QLabel("超时"))
        opts.addWidget(self.timeout_spin)

        self.robots_check = QCheckBox("抓 robots.txt")
        self.robots_check.setChecked(False)
        opts.addWidget(self.robots_check)

        self.sitemap_check = QCheckBox("抓 sitemap.xml")
        self.sitemap_check.setChecked(False)
        opts.addWidget(self.sitemap_check)
        opts.addStretch(1)
        layout.addLayout(opts)

        # -- 历史收录查询 + 字典子域名爆破选项 ------------------------------
        sub_opts = QHBoxLayout()
        sub_opts.setSpacing(16)
        self.hostsearch_check = QCheckBox("历史收录查询（hostsearch）")
        self.hostsearch_check.setChecked(False)
        self.hostsearch_check.setToolTip(
            "经 hackertarget hostsearch 查询该域名历史被收录过的子域名与对应 IP；\n"
            "请求走全局代理池统一入口。")
        sub_opts.addWidget(self.hostsearch_check)

        self.subdomain_check = QCheckBox("字典子域名爆破（DNS A 查询）")
        self.subdomain_check.setChecked(False)
        self.subdomain_check.setToolTip(
            "用 dict/Contents/subdomain.dict 逐个子域名做 DNS A 查询，\n"
            "Resolve-DnsName 与 nslookup 交叉校准。")
        sub_opts.addWidget(self.subdomain_check)

        self.subdomain_interval_spin = _NoWheelDoubleSpinBox()
        self.subdomain_interval_spin.setRange(0.0, 10.0)
        self.subdomain_interval_spin.setDecimals(2)
        self.subdomain_interval_spin.setSingleStep(0.1)
        self.subdomain_interval_spin.setValue(web_fuzz.DNS_DEFAULT_INTERVAL)
        self.subdomain_interval_spin.setSuffix(" 秒")
        self.subdomain_interval_spin.setToolTip("相邻两次 DNS 查询的最小间隔（速率限制），0 表示不限")
        sub_opts.addWidget(QLabel("间隔"))
        sub_opts.addWidget(self.subdomain_interval_spin)

        self.subdomain_proxy_check = QCheckBox("走代理")
        self.subdomain_proxy_check.setChecked(False)
        self.subdomain_proxy_check.setToolTip(
            "开启后子域名爆破的 DNS 解析走全局代理池里的 SOCKS5 代理（远程 DNS）；\n"
            "关闭则用系统本地 DNS。仅影响字典爆破步骤。")
        sub_opts.addWidget(self.subdomain_proxy_check)
        sub_opts.addStretch(1)
        layout.addLayout(sub_opts)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        self.run_btn = QPushButton("开始收集")
        self.run_btn.setObjectName("ghbtn-primary")
        self.run_btn.clicked.connect(self._start)
        buttons.addWidget(self.run_btn)

        self.stop_btn = QPushButton("停止")
        self.stop_btn.setObjectName("ghbtn")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop)
        buttons.addWidget(self.stop_btn)

        self.save_btn = QPushButton("合并导出 txt")
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

        self.report_label = QLabel("报告")
        self.report_label.setObjectName("section")
        layout.addWidget(self.report_label)

        self.report_view = QPlainTextEdit()
        self.report_view.setObjectName("io")
        self.report_view.setReadOnly(True)
        self.report_view.setPlaceholderText(
            "点击「开始收集」后，这里会显示合并后的信息报告…")
        self.report_view.setMinimumHeight(320)
        layout.addWidget(self.report_view, 1)

        self.log_label = QLabel("收集日志")
        self.log_label.setObjectName("section")
        layout.addWidget(self.log_label)

        self.log_view = QPlainTextEdit()
        self.log_view.setObjectName("io")
        self.log_view.setReadOnly(True)
        self.log_view.setMinimumHeight(90)
        self.log_view.setMaximumHeight(150)
        self.log_view.setMaximumBlockCount(2000)
        layout.addWidget(self.log_view)

        self.status_label = QLabel("")
        self.status_label.setObjectName("status-info")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

    # ------------------------------------------------------------------ 配置
    def _restore_config(self) -> None:
        cfg = self.store.get("web_fuzz", default={}) or {}
        try:
            self.timeout_spin.setValue(int(cfg.get("timeout")
                                           or web_fuzz.DEFAULT_TIMEOUT))
        except (TypeError, ValueError):
            self.timeout_spin.setValue(web_fuzz.DEFAULT_TIMEOUT)
        self.robots_check.setChecked(bool(cfg.get("robots", False)))
        self.sitemap_check.setChecked(bool(cfg.get("sitemap", False)))
        self.hostsearch_check.setChecked(bool(cfg.get("hostsearch", False)))
        self.subdomain_check.setChecked(bool(cfg.get("subdomain_brute", False)))
        try:
            self.subdomain_interval_spin.setValue(
                float(cfg.get("subdomain_interval")
                      or web_fuzz.DNS_DEFAULT_INTERVAL))
        except (TypeError, ValueError):
            self.subdomain_interval_spin.setValue(web_fuzz.DNS_DEFAULT_INTERVAL)
        self.subdomain_proxy_check.setChecked(
            bool(cfg.get("subdomain_use_proxy", False)))

    def _save_config(self) -> None:
        self.store.setv(int(self.timeout_spin.value()), "web_fuzz", "timeout")
        self.store.setv(bool(self.robots_check.isChecked()), "web_fuzz", "robots")
        self.store.setv(bool(self.sitemap_check.isChecked()), "web_fuzz", "sitemap")
        self.store.setv(bool(self.hostsearch_check.isChecked()),
                        "web_fuzz", "hostsearch")
        self.store.setv(bool(self.subdomain_check.isChecked()),
                        "web_fuzz", "subdomain_brute")
        self.store.setv(float(self.subdomain_interval_spin.value()),
                        "web_fuzz", "subdomain_interval")
        self.store.setv(bool(self.subdomain_proxy_check.isChecked()),
                        "web_fuzz", "subdomain_use_proxy")
        self.store.save()

    @property
    def _output_root(self) -> Path:
        cfg = self.store.get("watermark", default={}) or {}
        return resolve_output_dir(cfg.get("output_dir"))

    # ------------------------------------------------------------------ 操作
    def _start(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._set_status(False, "收集正在进行中，请先停止。")
            return
        target = self.url_edit.text().strip()
        if not target:
            self._set_status(False, "请填写目标 URL，如 https://example.com。")
            return

        self._save_config()
        self._result = None
        self.report_view.clear()
        self.log_view.clear()
        self.save_btn.setEnabled(False)
        self.run_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self._set_status(True, "正在收集…")

        old = self._worker
        worker = _WebFuzzWorker(
            target,
            int(self.timeout_spin.value()),
            self.robots_check.isChecked(),
            self.sitemap_check.isChecked(),
            self.hostsearch_check.isChecked(),
            self.subdomain_check.isChecked(),
            float(self.subdomain_interval_spin.value()),
            self.subdomain_proxy_check.isChecked(),
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
        self._result = None
        self.save_btn.setEnabled(False)
        self._set_status(True, "")

    def _on_done(self, result: dict) -> None:
        self._reset_buttons()
        self._result = result
        text = web_fuzz.to_text(result)
        self.report_view.setPlainText(text)
        self.save_btn.setEnabled(True)
        status = int(result.get("status") or 0)
        counts = (f"链接 {len(result.get('links') or [])}、"
                  f"脚本 {len(result.get('scripts') or [])}、"
                  f"邮箱 {len(result.get('emails') or [])}、"
                  f"子域 {len(result.get('subdomains') or [])}")
        if result.get("hostsearch"):
            counts += f"、收录 {len(result['hostsearch'])}"
        if result.get("dns_brute"):
            counts += f"、爆破命中 {len(result['dns_brute'])}"
        msg = (f"收集{'已停止' if result.get('stopped') else '完成'}："
               f"状态码 {status}，{counts}。可点「合并导出 txt」落盘。")
        self._set_status(not result.get("stopped"), msg)

    def _on_error(self, message: str) -> None:
        self._reset_buttons()
        self._set_status(False, message)

    def _reset_buttons(self) -> None:
        self.run_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def _save(self) -> None:
        if self._result is None:
            self._set_status(False, "还没有可导出的结果，请先开始收集。")
            return
        target = self.url_edit.text().strip()
        if "://" not in target:
            target = "http://" + target
        host = urlparse(target).netloc.replace(":", "_") or "webfuzz"
        out_dir = self._output_root
        default = str(out_dir / f"{host}_webfuzz.txt")
        path, _ = QFileDialog.getSaveFileName(
            self, "合并导出 Web Fuzz 报告", default, "文本文件 (*.txt)")
        if not path:
            return
        try:
            Path(path).write_text(web_fuzz.to_text(self._result), encoding="utf-8")
        except OSError as exc:
            self._set_status(False, f"保存失败：{exc}")
            return
        self._set_status(True, f"已合并导出：{path}")

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
        """退出前请求停止 Web Fuzz 线程（closeEvent 调用）。"""
        if self._worker is not None and self._worker.isRunning():
            self._worker.stop()
            self._worker.wait(1500)
