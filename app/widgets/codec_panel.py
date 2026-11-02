# -*- coding: utf-8 -*-
"""通用输入 / 输出面板。

主工具页、翻译页共用：上方「输入」多行文本 + 按钮行（清空 / 粘贴），
下方「输出」只读多行文本 + 复制 / 用作输入按钮。执行逻辑由持有方注入
（``run`` 回调），本组件只负责文本流转与剪贴板。

对外信号：
    input_changed(bool)  输入框是否有内容（供持有方联动执行按钮可用性）
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QTextCursor
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class CodecPanel(QFrame):
    """输入 / 输出双区面板。"""

    #: 输入框内容由空 -> 非空或反之时发出，参数为「当前是否有内容」
    input_changed = Signal(bool)

    def __init__(self, theme, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.setObjectName("card")
        self._build()

    def _build(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(8)
        t = self.theme

        # -- 输入区 --
        layout.addWidget(self._section_label("输入"))
        self.input_edit = QPlainTextEdit()
        self.input_edit.setObjectName("io")
        self.input_edit.setPlaceholderText(t.UI_PLACEHOLDER_INPUT)
        self.input_edit.setMinimumHeight(120)
        self.input_edit.textChanged.connect(self._emit_input_changed)
        layout.addWidget(self.input_edit, stretch=1)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        clear_btn = QPushButton(t.UI_BTN_CLEAR)
        clear_btn.setObjectName("ghbtn")
        clear_btn.clicked.connect(self.clear_all)
        paste_btn = QPushButton(t.UI_BTN_PASTE)
        paste_btn.setObjectName("ghbtn")
        paste_btn.clicked.connect(self.paste_input)
        btn_row.addWidget(clear_btn)
        btn_row.addWidget(paste_btn)
        btn_row.addStretch(1)
        layout.addLayout(btn_row)

        # -- 输出区 --
        layout.addWidget(self._section_label("输出"))
        self.output_edit = QPlainTextEdit()
        self.output_edit.setObjectName("io")
        self.output_edit.setReadOnly(True)
        self.output_edit.setPlaceholderText(t.UI_PLACEHOLDER_OUTPUT)
        self.output_edit.setMinimumHeight(120)
        layout.addWidget(self.output_edit, stretch=1)

        bottom = QHBoxLayout()
        bottom.setSpacing(8)
        bottom.addStretch(1)
        use_btn = QPushButton(t.UI_BTN_USE_AS_INPUT)
        use_btn.setObjectName("ghbtn")
        use_btn.setToolTip("把输出内容替换到输入框，便于连续解码 / 链式处理")
        use_btn.clicked.connect(self.use_output_as_input)
        self.use_as_input_btn = use_btn
        bottom.addWidget(use_btn)
        copy_btn = QPushButton(t.UI_BTN_COPY)
        copy_btn.setObjectName("ghbtn")
        copy_btn.clicked.connect(self.copy_output)
        bottom.addWidget(copy_btn)
        layout.addLayout(bottom)

    def _section_label(self, text: str) -> QLabel:
        label = QLabel(text)
        label.setObjectName("section")
        return label

    # -- 文本访问 -----------------------------------------------------------
    def get_input(self) -> str:
        return self.input_edit.toPlainText()

    def set_input(self, text: str) -> None:
        self.input_edit.setPlainText(text)

    def set_output(self, text: str) -> None:
        self.output_edit.setPlainText(text)

    def append_output(self, text: str) -> None:
        self.output_edit.appendPlainText(text)

    def has_input(self) -> bool:
        """输入框是否有非空白内容。"""
        return bool(self.input_edit.toPlainText().strip())

    def clear_all(self) -> None:
        self.input_edit.clear()
        self.output_edit.clear()

    # -- 剪贴板 / 链式处理 ---------------------------------------------------
    def paste_input(self) -> None:
        """把剪贴板文本追加到输入框；无文本时不做任何操作。"""
        text = QApplication.clipboard().text()
        if text:
            self.input_edit.moveCursor(QTextCursor.MoveOperation.End)
            self.input_edit.insertPlainText(text)

    def copy_output(self) -> None:
        text = self.output_edit.toPlainText()
        if text:
            QApplication.clipboard().setText(text)

    def use_output_as_input(self) -> None:
        """把输出内容搬回输入框（输出为空时不动），用于连续解码。"""
        text = self.output_edit.toPlainText()
        if not text:
            return
        self.input_edit.setPlainText(text)
        self.input_edit.moveCursor(QTextCursor.MoveOperation.End)

    def _emit_input_changed(self) -> None:
        self.input_changed.emit(self.has_input())
