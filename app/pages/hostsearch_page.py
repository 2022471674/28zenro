# -*- coding: utf-8 -*-
"""域名解析历史页：查询域名历史上被收录过的子域名与对应 IP。

输入一个域名（可带 http/https 前缀与端口，会自动规范化），调用 hackertarget
hostsearch 接口被动查询历史收录记录，结果按「子域名 + IP」表格展示。

与「DNS 解析」（主动 A/AAAA/CNAME 查询）和「字典子域名爆破」（主动 DNS A
查询）互补 —— 本页是被动信息收集，能发现主动爆破难以命中的历史子域名。

请求走全局代理池统一入口，后台线程执行，界面不阻塞。
"""

from __future__ import annotations

import threading

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)
from qfluentwidgets import TableWidget

from app.widgets.fuzz_worker import FuzzWorker
from lib import hostsearch


class _HostsearchWorker(FuzzWorker):
    """后台执行历史收录查询。"""

    error_prefix = "查询失败"

    def __init__(self, domain: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._domain = domain

    def task(self) -> dict:
        return hostsearch.query_hostsearch(
            self._domain, log=self.log.emit, stop=self._event)


class HostsearchPage(QWidget):
    """域名解析历史页：历史收录子域名 + IP 查询。"""

    COLUMNS = ("子域名", "IP")

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._worker: _HostsearchWorker | None = None
        self._build_ui()

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
        form.addWidget(QLabel("域名"))
        self.domain_edit = QLineEdit()
        self.domain_edit.setPlaceholderText(
            "example.com（可带 http/https 前缀与端口，会自动规范化）")
        self.domain_edit.returnPressed.connect(self._start)
        form.addWidget(self.domain_edit, 1)
        layout.addLayout(form)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        self.run_btn = QPushButton("查询历史收录")
        self.run_btn.setObjectName("ghbtn-primary")
        self.run_btn.clicked.connect(self._start)
        buttons.addWidget(self.run_btn)

        self.stop_btn = QPushButton("停止")
        self.stop_btn.setObjectName("ghbtn")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop)
        buttons.addWidget(self.stop_btn)

        clear_btn = QPushButton("清空")
        clear_btn.setObjectName("ghbtn")
        clear_btn.clicked.connect(self._clear)
        buttons.addWidget(clear_btn)

        copy_btn = QPushButton("复制结果")
        copy_btn.setObjectName("ghbtn")
        copy_btn.clicked.connect(self._copy)
        buttons.addWidget(copy_btn)
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
        layout.addWidget(self.table, stretch=1)

        self.status_label = QLabel("")
        self.status_label.setObjectName("status-info")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

    # ------------------------------------------------------------------ 操作
    def _start(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._set_status(False, "查询正在进行中，请先停止。")
            return
        domain = self.domain_edit.text().strip()
        if not domain:
            self._set_status(False, "请填写要查询的域名，如 example.com。")
            return

        self._clear(keep_status=True)
        self.run_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self._set_status(True, "正在查询历史收录…")

        old = self._worker
        worker = _HostsearchWorker(domain, self)
        worker.log.connect(lambda _m: None)
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

    def _clear(self, keep_status: bool = False) -> None:
        self.table.setRowCount(0)
        if not keep_status:
            self._set_status(True, "")

    def _on_done(self, result: dict) -> None:
        self._reset_buttons()
        records = result.get("records") or []
        for item in records:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(str(item.get("subdomain", ""))))
            self.table.setItem(row, 1, QTableWidgetItem(str(item.get("ip", ""))))
        note = result.get("note", "")
        if note:
            self._set_status(False, note)
        else:
            self._set_status(True, f"查询完成：历史收录 {len(records)} 条子域名。")

    def _on_error(self, message: str) -> None:
        self._reset_buttons()
        self._set_status(False, message)

    def _reset_buttons(self) -> None:
        self.run_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def _copy(self) -> None:
        rows = self.table.rowCount()
        if rows == 0:
            self._set_status(False, "还没有可复制的结果，请先查询。")
            return
        lines = ["\t".join(self.COLUMNS)]
        for row in range(rows):
            sub = self.table.item(row, 0).text() if self.table.item(row, 0) else ""
            ip = self.table.item(row, 1).text() if self.table.item(row, 1) else ""
            lines.append(f"{sub}\t{ip}")
        QApplication.clipboard().setText("\n".join(lines))
        self._set_status(True, f"已复制 {rows} 条结果到剪贴板。")

    # ------------------------------------------------------------------ 输出
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
