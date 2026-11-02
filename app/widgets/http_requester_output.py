# -*- coding: utf-8 -*-
"""HTTP 请求器的「显示窗口」（配置窗口之外的独立窗口）。

分工
----
- **配置窗口**（``app/pages/http_requester_page.py``）：方法 / URL / 参数 /
  请求头 / 请求体 / 载荷 / 模式 / 发送 —— 只放「发什么」。
- **显示窗口**（本文件）：结果表 / 响应详情 / 实发报文 / 日志 / 请求预览
  —— 只放「发了之后得到什么」。

这样小屏（14/16 英寸）上配置窗口能保持紧凑不挤压，结果与正文也能铺开来看；
两个窗口可以并排、可以各自放到第二块屏，关掉显示窗口不影响继续发请求。

实现要点
--------
- 用 ``Qt.Tool`` 窗口类型：不占任务栏、始终浮在主窗之上，但**不模态**
  （配置窗口可以继续编辑、继续发）。
- 自身带 QSS，不受主窗口样式表限制（否则 QTableWidget / QPlainTextEdit
  的配色对不上）。
- 对外只暴露很少的方法：``append_record`` / ``set_summary`` / ``append_log`` /
  ``show_request`` / ``records`` —— 配置窗口不需要知道内部结构。
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from lib import http_requester as hr


class OutputWindow(QWidget):
    """请求器的结果 / 响应 / 报文 / 日志显示窗口。"""

    #: 窗口被关闭（配置窗口据此更新按钮状态）
    closed = Signal()

    COL_NO, COL_PAYLOAD, COL_STATUS, COL_LENGTH, COL_TIME = range(5)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent, Qt.WindowType.Tool
                         | Qt.WindowType.WindowCloseButtonHint)
        self.setWindowTitle("HTTP 请求器 · 结果")
        self.setMinimumSize(720, 480)
        self.resize(1060, 720)
        self._records: list[dict] = []
        self._mode = ""
        self._attack = ""
        self._headers: list[str] = ["#", "载荷", "状态", "长度", "耗时"]
        self._build()

    # ================================================================ 构建
    def _build(self) -> None:
        self.setObjectName("outputWindow")
        self.setAutoFillBackground(True)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(14, 12, 14, 12)
        outer.setSpacing(8)

        head = QHBoxLayout()
        head.setSpacing(8)
        title = QLabel("运行结果")
        title.setObjectName("title")
        head.addWidget(title)
        self.summary_label = QLabel("")
        self.summary_label.setObjectName("caption")
        self.summary_label.setWordWrap(True)
        head.addWidget(self.summary_label, 1)
        outer.addLayout(head)

        split = QSplitter(Qt.Orientation.Vertical)
        split.setChildrenCollapsible(False)

        # ---- 结果表 ----
        self.result_table = QTableWidget(0, 5)
        self.result_table.setHorizontalHeaderLabels(self._headers)
        self.result_table.verticalHeader().setVisible(False)
        self.result_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)
        self.result_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers)
        header = self.result_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(self.COL_PAYLOAD,
                                    QHeaderView.ResizeMode.Stretch)
        self.result_table.setColumnWidth(self.COL_NO, 56)
        self.result_table.setColumnWidth(self.COL_STATUS, 90)
        self.result_table.setColumnWidth(self.COL_LENGTH, 100)
        self.result_table.setColumnWidth(self.COL_TIME, 90)
        self.result_table.verticalHeader().setDefaultSectionSize(28)
        self.result_table.cellDoubleClicked.connect(self._open_record)
        split.addWidget(self.result_table)

        # ---- 详情 / 预览 / 日志 ----
        self.tabs = QTabWidget()
        self.detail_view = QPlainTextEdit()
        self.detail_view.setObjectName("io")
        self.detail_view.setReadOnly(True)
        self.detail_view.setPlaceholderText(
            "双击上方任意一行，查看实发报文 / 响应头 / 响应正文。")
        self.tabs.addTab(self.detail_view, "响应详情")

        self.request_view = QPlainTextEdit()
        self.request_view.setObjectName("io")
        self.request_view.setReadOnly(True)
        self.request_view.setPlaceholderText(
            "配置窗口里点「预览报文」后，这里显示将要发出的报文"
            "（可逐字核对已编码的密文有没有被再转义）。")
        self.tabs.addTab(self.request_view, "请求预览")

        self.log_view = QPlainTextEdit()
        self.log_view.setObjectName("io")
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(5000)
        self.log_view.setPlaceholderText("请求日志…")
        self.tabs.addTab(self.log_view, "日志")
        split.addWidget(self.tabs)
        split.setSizes([420, 300])
        outer.addWidget(split, 1)

        # ---- 底部按钮 ----
        bottom = QHBoxLayout()
        bottom.setSpacing(8)
        export_btn = QPushButton("导出结果…")
        export_btn.setObjectName("ghbtn")
        export_btn.clicked.connect(self.export)
        bottom.addWidget(export_btn)
        copy_btn = QPushButton("复制载荷")
        copy_btn.setObjectName("ghbtn")
        copy_btn.clicked.connect(self._copy_payloads)
        bottom.addWidget(copy_btn)
        copy_detail = QPushButton("复制详情")
        copy_detail.setObjectName("ghbtn")
        copy_detail.clicked.connect(self._copy_detail)
        bottom.addWidget(copy_detail)
        clear_btn = QPushButton("清空")
        clear_btn.setObjectName("ghbtn")
        clear_btn.clicked.connect(self.clear)
        bottom.addWidget(clear_btn)
        bottom.addStretch(1)
        self.count_label = QLabel("")
        self.count_label.setObjectName("caption")
        bottom.addWidget(self.count_label)
        outer.addLayout(bottom)

        self._apply_style()

    def _apply_style(self) -> None:
        """自带一套简洁深色样式（Tool 窗口不继承主窗 QSS）。"""
        self.setStyleSheet("""
            QWidget#outputWindow { background: #161b22; }
            QLabel#title { color: #e6edf3; font-size: 15px; font-weight: 600; }
            QLabel#caption { color: #8b949e; font-size: 12px; }
            QTableWidget {
                background: #0d1117; color: #e6edf3; gridline-color: #30363d;
                border: 1px solid #30363d; border-radius: 6px;
                selection-background-color: #1f6feb; selection-color: #ffffff;
            }
            QHeaderView::section {
                background: #161b22; color: #8b949e; border: none;
                border-bottom: 1px solid #30363d; padding: 6px 4px;
            }
            QPlainTextEdit#io {
                background: #0d1117; color: #e6edf3;
                border: 1px solid #30363d; border-radius: 6px; padding: 6px;
                font-family: Consolas, "Cascadia Mono", monospace;
                font-size: 12px;
            }
            QTabBar::tab { color: #8b949e; padding: 6px 14px; }
            QTabBar::tab:selected { color: #e6edf3; border-bottom: 2px solid #1f6feb; }
            QPushButton#ghbtn {
                background: #21262d; color: #c9d1d9;
                border: 1px solid #30363d; border-radius: 6px; padding: 6px 12px;
            }
            QPushButton#ghbtn:hover { background: #30363d; }
            QSplitter::handle { background: #30363d; height: 3px; }
        """)

    # ================================================================ 数据
    @property
    def records(self) -> list[dict]:
        return self._records

    def clear(self) -> None:
        self._records = []
        self.result_table.setRowCount(0)
        self.detail_view.clear()
        self.request_view.clear()
        self._refresh_count()

    def append_log(self, message: str) -> None:
        self.log_view.appendPlainText(message)
        bar = self.log_view.verticalScrollBar()
        bar.setValue(bar.maximum())

    def show_request(self, dump: str) -> None:
        """显示将要发出的报文，并切到该标签页。"""
        self.request_view.setPlainText(dump)
        self.tabs.setCurrentWidget(self.request_view)

    def set_summary(self, text: str) -> None:
        self.summary_label.setText(text)

    def append_record(self, record: dict) -> None:
        self._records.append(record)
        row = self.result_table.rowCount()
        self.result_table.insertRow(row)
        self.result_table.setItem(row, self.COL_NO,
                                  QTableWidgetItem(str(record.get("index"))))
        self.result_table.setItem(
            row, self.COL_PAYLOAD,
            QTableWidgetItem(" | ".join(record.get("payloads") or []) or "—"))
        if record.get("error"):
            item = QTableWidgetItem("失败")
            self.result_table.setItem(row, self.COL_STATUS, item)
            self.result_table.setItem(
                row, self.COL_LENGTH, QTableWidgetItem(record.get("error", "")[:60]))
            self.result_table.setItem(row, self.COL_TIME, QTableWidgetItem("—"))
            for col in range(5):
                cell = self.result_table.item(row, col)
                if cell is not None:
                    cell.setForeground(QBrush(QColor("#f85149")))
                    cell.setToolTip(record.get("error", ""))
        else:
            status_item = QTableWidgetItem(str(record.get("status")))
            self.result_table.setItem(row, self.COL_STATUS, status_item)
            self.result_table.setItem(
                row, self.COL_LENGTH,
                QTableWidgetItem(str(record.get("length"))))
            self.result_table.setItem(
                row, self.COL_TIME,
                QTableWidgetItem(f"{record.get('elapsed_ms', 0):.0f}ms"))
            changed = record.get("changed") or {}
            if changed.get("status"):
                status_item.setForeground(QBrush(QColor("#e3b341")))
            elif changed.get("length") or changed.get("body"):
                status_item.setForeground(QBrush(QColor("#3fb950")))
        self._refresh_count()
        bar = self.result_table.verticalScrollBar()
        bar.setValue(bar.maximum())

    def _refresh_count(self) -> None:
        if not self._records:
            self.count_label.setText("")
            return
        ok = sum(1 for r in self._records if not r.get("error"))
        self.count_label.setText(
            f"共 {len(self._records)} 条 · 成功 {ok} · "
            f"失败 {len(self._records) - ok}")

    # ================================================================ 详情
    def _open_record(self, row: int, _column: int) -> None:
        if not (0 <= row < len(self._records)):
            return
        record = self._records[row]
        lines: list[str] = []
        add = lines.append
        payload = " | ".join(record.get("payloads") or []) or "—"
        add(f"# 第 {record.get('index')} 条    载荷：{payload}")
        add("")
        if record.get("error"):
            add(f"请求失败：{record['error']}")
        else:
            add(f"{record.get('method')} {record.get('url')}")
            add(f"状态：{record.get('status')} {record.get('reason')}    "
                f"长度：{record.get('length')} bytes    "
                f"耗时：{record.get('elapsed_ms')} ms")
        add("")
        add("=" * 24 + " 实发报文 " + "=" * 24)
        add(record.get("request_dump") or "")
        add("")
        add("=" * 24 + " 响应头 " + "=" * 26)
        add("\n".join(f"{k}: {v}"
                      for k, v in (record.get("response_headers") or [])))
        add("")
        add("=" * 24 + " 响应正文 " + "=" * 24)
        add(record.get("preview") or "")
        self.detail_view.setPlainText("\n".join(lines))
        self.tabs.setCurrentWidget(self.detail_view)

    # ================================================================ 导出
    def export(self) -> None:
        if not self._records:
            self.count_label.setText("还没有结果可导出")
            return
        result = {
            "mode": self._mode,
            "attack": self._attack,
            "total": len(self._records),
            "done": len(self._records),
            "responses": self._records,
        }
        default = str(Path.cwd()
                      / f"requester_{datetime.now():%Y%m%d_%H%M%S}.txt")
        path, _ = QFileDialog.getSaveFileName(
            self, "导出请求器结果", default, "文本文件 (*.txt)")
        if not path:
            return
        parts = [hr.to_text(result), "", "=" * 60, "逐条详情", "=" * 60]
        for record in self._records:
            parts.append(f"\n--- #{record.get('index')} "
                         f"{' | '.join(record.get('payloads') or [])} ---")
            parts.append(record.get("request_dump") or "")
            parts.append("")
            parts.append(record.get("preview") or record.get("error") or "")
        try:
            Path(path).write_text("\n".join(parts), encoding="utf-8")
        except OSError as exc:
            self.count_label.setText(f"保存失败：{exc}")
            return
        self.count_label.setText(f"已导出：{path}")

    def _copy_payloads(self) -> None:
        if not self._records:
            return
        lines = ["\t".join(r.get("payloads") or []) for r in self._records]
        QApplication.clipboard().setText("\n".join(lines))
        self.count_label.setText(f"已复制 {len(lines)} 行载荷")

    def _copy_detail(self) -> None:
        QApplication.clipboard().setText(self.detail_view.toPlainText())
        self.count_label.setText("已复制详情")

    # ================================================================ 上下文
    def set_run_context(self, mode: str, attack: str) -> None:
        """记录本轮的模式 / 攻击类型（导出报告抬头用）。"""
        self._mode, self._attack = mode, attack

    def closeEvent(self, event) -> None:  # noqa: N802
        self.closed.emit()
        super().closeEvent(event)


__all__ = ["OutputWindow"]
