# -*- coding: utf-8 -*-
"""运行日志页：侧边栏常驻入口，显示软件全局运行日志。

数据来自 :mod:`app.runtime_log` 中枢（线程安全环形缓冲 + Qt 信号广播）：
页面首次构建时回放历史缓冲，之后经 ``appended`` 信号实时追加。日志上限
:data:`runtime_log.CAPACITY` 条，控件 ``maximumBlockCount`` 与缓冲对齐，
永不无限增长。

功能：级别过滤（全部 / INFO / WARN / ERROR）、自动跟随滚动开关、
清空 / 复制全部 / 导出为 txt。
"""

from __future__ import annotations

import time

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app import runtime_log

#: 级别优先级（用于过滤：所选级别及以上都显示）
_LEVEL_ORDER = {"INFO": 0, "WARN": 1, "ERROR": 2}


def _line_level(line: str) -> str:
    """从格式化日志行里取级别（``HH:MM:SS [LVxx] …``）。"""
    if "[WARN" in line:
        return "WARN"
    if "[ERRO" in line:
        return "ERROR"
    return "INFO"


class RuntimeLogPage(QWidget):
    """运行日志页。"""

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._build()
        # 回放历史 + 订阅增量（信号跨线程自动排队，回调只在主线程执行）
        for line in runtime_log.hub().lines():
            self._append(line)
        runtime_log.hub().appended.connect(self._append)
        self._refresh_count()

    # ------------------------------------------------------------------ UI
    def _build(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 14, 8, 8)
        layout.setSpacing(10)

        title = QLabel("运行日志")
        title.setObjectName("title")
        layout.addWidget(title)

        caption = QLabel(
            "记录软件运行事件（启动 / 主题 / 工具启停 / 后台任务结果）。"
            "各工具扫描的逐行日志仍在工具页内，不在此重复。")
        caption.setObjectName("caption")
        caption.setWordWrap(True)
        layout.addWidget(caption)

        bar = QHBoxLayout()
        bar.setSpacing(8)

        bar.addWidget(QLabel("级别"))
        self.level_box = QComboBox()
        self.level_box.addItems(("全部", "INFO", "WARN", "ERROR"))
        self.level_box.currentTextChanged.connect(self._refilter)
        bar.addWidget(self.level_box)

        self.follow_check = QCheckBox("自动跟随滚动")
        self.follow_check.setChecked(True)
        bar.addWidget(self.follow_check)

        self.clear_btn = QPushButton("清空")
        self.clear_btn.setObjectName("ghbtn")
        self.clear_btn.clicked.connect(self._clear)
        bar.addWidget(self.clear_btn)

        self.copy_btn = QPushButton("复制全部")
        self.copy_btn.setObjectName("ghbtn")
        self.copy_btn.clicked.connect(self._copy_all)
        bar.addWidget(self.copy_btn)

        self.export_btn = QPushButton("导出 txt")
        self.export_btn.setObjectName("ghbtn")
        self.export_btn.clicked.connect(self._export)
        bar.addWidget(self.export_btn)

        bar.addStretch(1)
        self.count_label = QLabel("")
        self.count_label.setObjectName("caption")
        bar.addWidget(self.count_label)
        layout.addLayout(bar)

        self.log_view = QPlainTextEdit()
        self.log_view.setObjectName("io")
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(runtime_log.CAPACITY)
        font = QFont("Consolas")
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.log_view.setFont(font)
        layout.addWidget(self.log_view, stretch=1)

    # ------------------------------------------------------------------ 数据
    def _append(self, line: str) -> None:
        """收到一条日志（历史回放或实时信号）。"""
        if not self._visible(line):
            self._refresh_count()
            return
        bar = self.log_view.verticalScrollBar()
        at_bottom = bar.value() >= bar.maximum() - 2
        self.log_view.appendPlainText(line)
        if self.follow_check.isChecked() and at_bottom:
            bar.setValue(bar.maximum())
        self._refresh_count()

    def _visible(self, line: str) -> bool:
        current = self.level_box.currentText()
        if current == "全部":
            return True
        return _LEVEL_ORDER.get(_line_level(line), 0) >= _LEVEL_ORDER.get(current, 0)

    def _refilter(self, _text: str) -> None:
        """级别切换：从缓冲快照重建视图。"""
        self.log_view.clear()
        for line in runtime_log.hub().lines():
            if self._visible(line):
                self.log_view.appendPlainText(line)
        bar = self.log_view.verticalScrollBar()
        bar.setValue(bar.maximum())
        self._refresh_count()

    def _refresh_count(self) -> None:
        self.count_label.setText(f"共 {len(runtime_log.hub().lines())} 条")

    # ------------------------------------------------------------------ 操作
    def _clear(self) -> None:
        runtime_log.hub().clear()
        self.log_view.clear()
        self._refresh_count()

    def _copy_all(self) -> None:
        from PySide6.QtWidgets import QApplication
        QApplication.clipboard().setText(
            "\n".join(runtime_log.hub().lines()))

    def _export(self) -> None:
        default = time.strftime("runtime_log_%Y%m%d_%H%M%S.txt")
        path, _ = QFileDialog.getSaveFileName(
            self, "导出运行日志", default, "文本文件 (*.txt)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(runtime_log.hub().lines()))
        except OSError:
            return

    # ------------------------------------------------------------------ 主题
    def set_theme(self, palette) -> None:
        self.theme = palette
