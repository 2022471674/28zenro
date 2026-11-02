# -*- coding: utf-8 -*-
"""OSS 桶探测页：检测阿里云 OSS / 腾讯 COS / AWS S3 桶的越权访问。

可手动填桶名列表，或填主域名自动派生候选桶名，逐个对三家厂商探测
「公开读 / 可列举 / 桶存在」状态。后台线程执行，界面不阻塞。
"""

from __future__ import annotations

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
from lib import oss_bucket


class _OssWorker(FuzzWorker):
    """后台执行 OSS 桶探测。"""

    error_prefix = "探测失败"

    def __init__(self, buckets: str, domain: str,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._buckets = buckets
        self._domain = domain

    def task(self) -> dict:
        return oss_bucket.run(
            self._buckets, domain=self._domain,
            log=self.log.emit, stop=self._event)


class OssPage(QWidget):
    """OSS 桶探测页。"""

    COLUMNS = ("桶名", "厂商", "状态", "可公开读", "可列举", "说明")

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._worker: _OssWorker | None = None
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
        form.addWidget(QLabel("桶名"))
        self.bucket_edit = QLineEdit()
        self.bucket_edit.setPlaceholderText(
            "my-bucket, another-bucket（逗号分隔，留空则用主域名派生）")
        form.addWidget(self.bucket_edit, 1)
        layout.addLayout(form)

        form2 = QHBoxLayout()
        form2.setSpacing(10)
        form2.addWidget(QLabel("主域名"))
        self.domain_edit = QLineEdit()
        self.domain_edit.setPlaceholderText(
            "example.com（可选，用于自动派生候选桶名）")
        form2.addWidget(self.domain_edit, 1)
        layout.addLayout(form2)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        self.run_btn = QPushButton("开始探测")
        self.run_btn.setObjectName("ghbtn-primary")
        self.run_btn.clicked.connect(self._start)
        buttons.addWidget(self.run_btn)
        self.stop_btn = QPushButton("停止")
        self.stop_btn.setObjectName("ghbtn")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop)
        buttons.addWidget(self.stop_btn)
        self.clear_btn = QPushButton("清空")
        self.clear_btn.setObjectName("ghbtn")
        self.clear_btn.clicked.connect(self._clear)
        buttons.addWidget(self.clear_btn)
        self.copy_btn = QPushButton("复制结果")
        self.copy_btn.setObjectName("ghbtn")
        self.copy_btn.clicked.connect(self._copy)
        buttons.addWidget(self.copy_btn)
        buttons.addStretch(1)
        layout.addLayout(buttons)

        self.table = TableWidget(self)
        self.table.setColumnCount(len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels(self.COLUMNS)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table, stretch=1)

        self.status_label = QLabel("")
        self.status_label.setObjectName("status-info")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

    # ------------------------------------------------------------------ 操作
    def _start(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._set_status(False, "探测正在进行中，请先停止。")
            return
        buckets = self.bucket_edit.text().strip()
        domain = self.domain_edit.text().strip()
        if not buckets and not domain:
            self._set_status(False, "请填写桶名或主域名（至少一项）。")
            return

        self._clear(keep_status=True)
        self.run_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self._set_status(True, "正在探测 OSS 桶…")

        worker = _OssWorker(buckets, domain, self)
        worker.done_ok.connect(self._on_done)
        worker.done_err.connect(self._on_error)
        self._worker = worker
        worker.start()

    def _stop(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._worker.stop()
            self._set_status(True, "正在停止…")

    def _clear(self, keep_status: bool = False) -> None:
        self.table.setRowCount(0)
        if not keep_status:
            self._set_status(True, "")

    def _on_done(self, result: dict) -> None:
        self._reset_buttons()
        hits = result.get("hits") or []
        summary = result.get("summary") or {}
        for item in hits:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(str(item.get("bucket", ""))))
            self.table.setItem(row, 1, QTableWidgetItem(str(item.get("provider", ""))))
            self.table.setItem(row, 2, QTableWidgetItem(str(item.get("status", ""))))
            self.table.setItem(row, 3, QTableWidgetItem(
                "是" if item.get("public_read") else "否"))
            self.table.setItem(row, 4, QTableWidgetItem(
                "是" if item.get("listable") else "否"))
            self.table.setItem(row, 5, QTableWidgetItem(str(item.get("note", ""))))
        public = summary.get("public_read", 0)
        listable = summary.get("listable", 0)
        self._set_status(True, f"探测完成：命中 {len(hits)} 个桶"
                               f"（公开读 {public}，可列举 {listable}）。")

    def _on_error(self, message: str) -> None:
        self._reset_buttons()
        self._set_status(False, message)

    def _reset_buttons(self) -> None:
        self.run_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def _copy(self) -> None:
        rows = self.table.rowCount()
        if rows == 0:
            self._set_status(False, "还没有可复制的结果，请先探测。")
            return
        lines = ["\t".join(self.COLUMNS)]
        for row in range(rows):
            cells = []
            for col in range(len(self.COLUMNS)):
                item = self.table.item(row, col)
                cells.append(item.text() if item else "")
            lines.append("\t".join(cells))
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