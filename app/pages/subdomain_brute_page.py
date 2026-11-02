# -*- coding: utf-8 -*-
"""字典子域名爆破页：用子域名字典逐个拼主域名做 DNS A 查询。

默认读取 ``dict/Contents/subdomain.dict``，也支持选择自定义字典文件；逐个
拼接 ``词条.主域名`` 后用 :mod:`lib.dns_tool.brute_subdomains` 做 DNS A 查询
（Resolve-DnsName 与 nslookup 交叉校准），带速率限制与独立代理开关。命中的
子域名按行增量填入表格。

查询在后台线程执行，界面不阻塞；支持停止。
"""

from __future__ import annotations

import threading
from pathlib import Path

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QDoubleSpinBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)
from qfluentwidgets import TableWidget

from app.widgets.no_wheel import NoWheelMixin
from lib import dns_tool


class _NoWheelDoubleSpinBox(NoWheelMixin, QDoubleSpinBox):
    """滚过时不改值的小数输入框（用于速率限制间隔）。"""


class _BruteWorker(QThread):
    """后台执行字典子域名爆破，命中 / 日志 / 结果经信号回传主线程。"""

    log = Signal(str)
    hit = Signal(dict)
    done_ok = Signal(list)
    done_err = Signal(str)

    def __init__(self, domain: str, dict_path: str | None, interval: float,
                 use_proxy: bool, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._domain = domain
        self._dict_path = dict_path
        self._interval = interval
        self._use_proxy = use_proxy
        self._event = threading.Event()

    def stop(self) -> None:
        """请求中止：不再派发新子域名，在途查询尽快收尾。"""
        self._event.set()

    def run(self) -> None:  # noqa: D102  线程入口
        try:
            results, note = dns_tool.brute_subdomains(
                self._domain,
                dict_path=self._dict_path,
                interval=self._interval,
                use_proxy=self._use_proxy,
                log=self.log.emit,
                found=self.hit.emit,
                stop=self._event,
            )
        except dns_tool.DnsToolError as exc:
            self.done_err.emit(str(exc))
            return
        except Exception as exc:  # noqa: BLE001  后台线程兜底
            self.done_err.emit(f"爆破失败：{exc}")
            return
        self.done_ok.emit(results)


class SubdomainBrutePage(QWidget):
    """字典子域名爆破页：DNS A 查询发现子域名。"""

    COLUMNS = ("子域名", "IP", "备注")

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._worker: _BruteWorker | None = None
        self._rows: list[dict] = []
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
        form.addWidget(QLabel("主域名"))
        self.domain_edit = QLineEdit()
        self.domain_edit.setPlaceholderText("example.com（不带协议前缀）")
        self.domain_edit.returnPressed.connect(self._start)
        form.addWidget(self.domain_edit, 1)
        layout.addLayout(form)

        opts = QHBoxLayout()
        opts.setSpacing(16)
        self.interval_spin = _NoWheelDoubleSpinBox()
        self.interval_spin.setRange(0.0, 10.0)
        self.interval_spin.setDecimals(2)
        self.interval_spin.setSingleStep(0.1)
        self.interval_spin.setValue(dns_tool.DEFAULT_INTERVAL)
        self.interval_spin.setSuffix(" 秒")
        self.interval_spin.setToolTip(
            "相邻两次 DNS 查询的最小间隔（速率限制），0 表示不限")
        opts.addWidget(QLabel("间隔"))
        opts.addWidget(self.interval_spin)

        self.proxy_check = QCheckBox("走代理")
        self.proxy_check.setChecked(False)
        self.proxy_check.setToolTip(
            "开启后 DNS 解析经全局代理池的 SOCKS5 代理做远程 DNS；关闭则系统本地 DNS。")
        opts.addWidget(self.proxy_check)
        opts.addStretch(1)
        layout.addLayout(opts)

        # 字典选择行
        dict_row = QHBoxLayout()
        dict_row.setSpacing(10)
        dict_row.addWidget(QLabel("字典"))
        self.dict_edit = QLineEdit()
        self.dict_edit.setReadOnly(True)
        self.dict_edit.setPlaceholderText(
            f"默认：{dns_tool.default_subdomain_dict()}")
        dict_row.addWidget(self.dict_edit, 1)
        self.pick_btn = QPushButton("选择字典…")
        self.pick_btn.setObjectName("ghbtn")
        self.pick_btn.clicked.connect(self._pick_dict)
        dict_row.addWidget(self.pick_btn)
        self.reset_btn = QPushButton("恢复默认")
        self.reset_btn.setObjectName("ghbtn")
        self.reset_btn.clicked.connect(self._reset_dict)
        dict_row.addWidget(self.reset_btn)
        layout.addLayout(dict_row)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        self.run_btn = QPushButton("开始爆破")
        self.run_btn.setObjectName("ghbtn-primary")
        self.run_btn.clicked.connect(self._start)
        buttons.addWidget(self.run_btn)

        self.stop_btn = QPushButton("停止")
        self.stop_btn.setObjectName("ghbtn")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop)
        buttons.addWidget(self.stop_btn)

        clear_btn = QPushButton("清空结果")
        clear_btn.setObjectName("ghbtn")
        clear_btn.clicked.connect(self._clear)
        buttons.addWidget(clear_btn)
        buttons.addStretch(1)
        layout.addLayout(buttons)

        self.table = TableWidget(self)
        self.table.setColumnCount(len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels(self.COLUMNS)
        self.table.setEditTriggers(TableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(TableWidget.SelectRows)
        self.table.verticalHeader().hide()
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        header.resizeSection(2, 140)
        layout.addWidget(self.table, stretch=1)

        self.log_label = QLabel("爆破日志")
        self.log_label.setObjectName("section")
        layout.addWidget(self.log_label)

        self.log_view = QPlainTextEdit()
        self.log_view.setObjectName("io")
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(2000)
        self.log_view.setMinimumHeight(80)
        self.log_view.setMaximumHeight(140)
        layout.addWidget(self.log_view)

        self.status_label = QLabel("")
        self.status_label.setObjectName("status-info")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

    # ------------------------------------------------------------------ 配置
    def _restore_config(self) -> None:
        cfg = self.store.get("subdomain_brute", default={}) or {}
        try:
            self.interval_spin.setValue(
                float(cfg.get("interval") or dns_tool.DEFAULT_INTERVAL))
        except (TypeError, ValueError):
            self.interval_spin.setValue(dns_tool.DEFAULT_INTERVAL)
        self.proxy_check.setChecked(bool(cfg.get("use_proxy", False)))
        dict_path = str(cfg.get("dict_path") or "")
        self.dict_edit.setText(dict_path)

    def _save_config(self) -> None:
        self.store.setv(float(self.interval_spin.value()),
                        "subdomain_brute", "interval")
        self.store.setv(bool(self.proxy_check.isChecked()),
                        "subdomain_brute", "use_proxy")
        self.store.setv(self.dict_edit.text().strip(),
                        "subdomain_brute", "dict_path")
        self.store.save()

    # ------------------------------------------------------------------ 字典
    def _pick_dict(self) -> None:
        start = self.dict_edit.text().strip() or str(dns_tool.default_subdomain_dict())
        path, _ = QFileDialog.getOpenFileName(
            self, "选择子域名字典", start, "字典文件 (*.dict *.txt);;所有文件 (*)")
        if path:
            self.dict_edit.setText(path)

    def _reset_dict(self) -> None:
        self.dict_edit.clear()

    # ------------------------------------------------------------------ 操作
    def _start(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._set_status(False, "爆破正在进行中，请先停止。")
            return
        domain = self.domain_edit.text().strip()
        if not domain:
            self._set_status(False, "请填写主域名，如 example.com。")
            return

        self._save_config()
        self._clear(keep_status=True)
        self.run_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self._set_status(True, "正在爆破…")

        dict_path = self.dict_edit.text().strip() or None
        old = self._worker
        worker = _BruteWorker(
            domain,
            dict_path,
            float(self.interval_spin.value()),
            self.proxy_check.isChecked(),
            self,
        )
        worker.log.connect(self._append_log)
        worker.hit.connect(self._add_row)
        worker.done_ok.connect(self._on_done)
        worker.done_err.connect(self._on_error)
        self._worker = worker
        if old is not None:
            old.deleteLater()
        worker.start()

    def _stop(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._worker.stop()
            self._set_status(True, "正在停止…（等待在途查询结束）")

    def _clear(self, keep_status: bool = False) -> None:
        self.table.setRowCount(0)
        self._rows.clear()
        self.log_view.clear()
        if not keep_status:
            self._set_status(True, "")

    def _on_done(self, results: list) -> None:
        self._reset_buttons()
        self._set_status(True, f"爆破完成：命中 {len(self._rows)} 条子域名。")

    def _on_error(self, message: str) -> None:
        self._reset_buttons()
        self._set_status(False, message)

    def _reset_buttons(self) -> None:
        self.run_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def _add_row(self, item: dict) -> None:
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, QTableWidgetItem(str(item.get("subdomain", ""))))
        self.table.setItem(row, 1, QTableWidgetItem(
            ", ".join(item.get("ips") or [])))
        self.table.setItem(row, 2, QTableWidgetItem(str(item.get("note", ""))))
        self._rows.append(item)

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
        """退出前请求停止爆破线程（closeEvent 调用）。"""
        if self._worker is not None and self._worker.isRunning():
            self._worker.stop()
            self._worker.wait(1500)
