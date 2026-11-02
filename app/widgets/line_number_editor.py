# -*- coding: utf-8 -*-
"""带行号的代码编辑器（``QPlainTextEdit`` + 行号栏）。

供 Payload 编译器使用：左侧绘制行号栏，随滚动 / 折叠 / 块数变化同步刷新。
行号栏宽度按行号位数自适应（>= 100 行自动加宽）。
"""

from __future__ import annotations

from PySide6.QtCore import QRect, QSize, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QTextFormat
from PySide6.QtWidgets import QPlainTextEdit, QTextEdit, QWidget


class _LineNumberArea(QWidget):
    """行号栏：与编辑器同步绘制。"""

    def __init__(self, editor: "LineNumberEditor") -> None:
        super().__init__(editor)
        self._editor = editor

    def sizeHint(self) -> QSize:  # noqa: N802
        return QSize(self._editor.line_number_area_width(), 0)

    def paintEvent(self, event) -> None:  # noqa: N802
        self._editor.paint_line_numbers(event)


class LineNumberEditor(QPlainTextEdit):
    """带行号栏的多行代码编辑器。"""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._line_number_area = _LineNumberArea(self)
        self._line_color = QColor("#8899aa")

        self.blockCountChanged.connect(self._update_area_width)
        self.updateRequest.connect(self._update_area_rect)
        self.cursorPositionChanged.connect(self._highlight_current_line)

        self._update_area_width(0)
        self._highlight_current_line()

    # ------------------------------------------------------------ 行号栏几何
    def line_number_area_width(self) -> int:
        digits = max(2, len(str(self.blockCount())))
        return 12 + self.fontMetrics().horizontalAdvance("9") * digits

    def _update_area_width(self, _count: int) -> None:
        self.setViewportMargins(self.line_number_area_width(), 0, 0, 0)

    def _update_area_rect(self, rect: QRect, dy: int) -> None:
        if dy:
            self._line_number_area.scroll(0, dy)
        else:
            self._line_number_area.update(
                0, rect.y(), self._line_number_area.width(), rect.height())
        if rect.contains(self.viewport().rect()):
            self._update_area_width(0)

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        cr = self.contentsRect()
        self._line_number_area.setGeometry(
            QRect(cr.left(), cr.top(),
                  self.line_number_area_width(), cr.height()))

    # ------------------------------------------------------------ 绘制
    def paint_line_numbers(self, event) -> None:
        painter = QPainter(self._line_number_area)
        painter.fillRect(event.rect(), self._line_number_area.palette().base())

        block = self.firstVisibleBlock()
        block_number = block.blockNumber()
        top = round(self.blockBoundingGeometry(block).translated(
            self.contentOffset()).top())
        bottom = top + round(self.blockBoundingRect(block).height())

        while block.isValid() and top <= event.rect().bottom():
            if block.isVisible() and bottom >= event.rect().top():
                number = str(block_number + 1)
                painter.setPen(self._line_color)
                painter.setFont(self.font())
                painter.drawText(
                    0, top, self._line_number_area.width() - 6,
                    self.fontMetrics().height(),
                    Qt.AlignmentFlag.AlignRight, number)
            block = block.next()
            top = bottom
            bottom = top + round(self.blockBoundingRect(block).height())
            block_number += 1

    def _highlight_current_line(self) -> None:
        selections: list = []
        if not self.isReadOnly():
            selection = QTextEdit.ExtraSelection()
            selection.format.setBackground(QColor("#00000014"))
            selection.format.setProperty(
                QTextFormat.Property.FullWidthSelection, True)
            selection.cursor = self.textCursor()
            selection.cursor.clearSelection()
            selections.append(selection)
        self.setExtraSelections(selections)

    # ------------------------------------------------------------ 公开 API
    def set_theme_colors(self, line_color: str) -> None:
        """换主题时同步行号颜色。"""
        self._line_color = QColor(line_color)
        self._line_number_area.update()
