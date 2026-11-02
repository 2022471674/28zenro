# -*- coding: utf-8 -*-
"""WAF 识别页：识别常见 Web 应用防火墙并给出绕过建议。

输入目标 URL，对比正常请求与攻击载荷请求的响应差异，结合内置 WAF 指纹
（Cloudflare / 宝塔 / 安全狗 / ModSecurity / D 盾 / 云锁 / 阿里云盾 / 创宇盾等）
识别厂商，命中后附带常见绕过建议。后台线程执行，界面不阻塞。
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
from lib import waf_detect


class _WafWorker(FuzzWorker):
    """后台执行 WAF 识别。"""

    error_prefix = "识别失败"

    def __init__(self, target: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._target = target

    def task(self) -> dict:
        return waf_detect.run(
            self._target, log=self.log.emit, stop=self._event)


class WafPage(QWidget):
    """WAF 识别页。"""

    COLUMNS = ("WAF / 厂商", "绕过建议")

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._worker: _WafWorker | None = None
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
        form.addWidget(QLabel("目标"))
        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText("https://example.com（可省略协议头）")
        self.target_edit.returnPressed.connect(self._start)
        form.addWidget(self.target_edit, 1)
        layout.addLayout(form)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        self.run_btn = QPushButton("开始识别")
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
        self.table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table, stretch=1)

        self.status_label = QLabel("")
        self.status_label.setObjectName("status-info")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

    # ------------------------------------------------------------------ 操作
    def _start(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._set_status(False, "识别正在进行中，请先停止。")
            return
        target = self.target_edit.text().strip()
        if not target:
            self._set_status(False, "请填写目标 URL，如 https://example.com。")
            return

        self._clear(keep_status=True)
        self.run_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self._set_status(True, "正在识别 WAF…")

        worker = _WafWorker(target, self)
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
        matches = result.get("matches") or []
        for m in matches:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(str(m.get("name", ""))))
            self.table.setItem(row, 1, QTableWidgetItem(
                "；".join(m.get("bypass", []))))
        if matches:
            self._set_status(True, f"识别完成：命中 {len(matches)} 个 WAF 指纹。")
        else:
            self._set_status(True, "识别完成：未发现已知 WAF 指纹。")

    def _on_error(self, message: str) -> None:
        self._reset_buttons()
        self._set_status(False, message)

    def _reset_buttons(self) -> None:
        self.run_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def _copy(self) -> None:
        rows = self.table.rowCount()
        if rows == 0:
            self._set_status(False, "还没有可复制的结果，请先识别。")
            return
        lines = ["\t".join(self.COLUMNS)]
        for row in range(rows):
            name = self.table.item(row, 0).text() if self.table.item(row, 0) else ""
            bypass = self.table.item(row, 1).text() if self.table.item(row, 1) else ""
            lines.append(f"{name}\t{bypass}")
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