# -*- coding: utf-8 -*-
"""可换行的水平布局（窄窗口下的控件防重叠）。

``QHBoxLayout`` 在小窗口里会把子控件一路压到最小尺寸以下、最后互相压叠。
:class:`WrapRow` 在宽度不够时把控件挪到下一行，控件永远保持自己的最小尺寸，
因此窗口再窄也只会变高、不会重叠。

每个控件可以声明自己的「优先级」：优先级高的先占当前位置，放不下时才换行；
``stretch=True`` 的控件（如 URL 输入框）吃掉行内剩余空间。
"""

from __future__ import annotations

from typing import Iterable

from PySide6.QtCore import QPoint, QRect, QSize, Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLayout,
    QSizePolicy,
    QWidget,
    QWidgetItem,
)


class WrapRow(QWidget):
    """自动换行的一行控件。"""

    def __init__(self, *, spacing: int = 8, row_spacing: int = 6,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._spacing = spacing
        self._row_spacing = row_spacing
        self._items: list[tuple[QWidget, bool]] = []
        self.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Minimum)

    # ------------------------------------------------------------------ API
    def add(self, widget: QWidget, *, stretch: bool = False) -> QWidget:
        """追加一个控件；``stretch=True`` 表示吃掉行内剩余宽度。"""
        widget.setParent(self)
        self._items.append((widget, stretch))
        return widget

    def add_label(self, text: str, *, stretch: bool = False):
        from PySide6.QtWidgets import QLabel

        label = QLabel(text)
        return self.add(label, stretch=stretch)

    def widget_count(self) -> int:
        return len(self._items)

    # ------------------------------------------------------------- 布局计算
    def _measure(self) -> tuple[list[list[tuple[QWidget, bool]]], int]:
        """按当前宽度把控件分行，返回 (行列表, 所需总高度)。"""
        # 尚未完成布局（宽度为 0）时按「单行」计算，避免把高度算成 0
        width = self.width() if self.width() > 0 else 10 ** 6
        rows: list[list[tuple[QWidget, bool]]] = [[]]
        used = 0
        height = 0
        for widget, stretch in self._items:
            # 用 isHidden() 而不是 isVisible()：父控件还没显示（或整页在后台页签）
            # 时 isVisible() 一律为 False，会把高度算成 0，控件就整行不绘制。
            if widget.isHidden():
                continue
            hint = widget.sizeHint().width()
            min_w = widget.minimumSizeHint().width()
            need = max(min_w, hint)
            gap = self._spacing if rows[-1] else 0
            if rows[-1] and used + gap + need > width:
                height += self._row_height(rows[-1]) + self._row_spacing
                rows.append([])
                gap = 0
            rows[-1].append((widget, stretch))
            used += gap + need
        if rows and rows[-1]:
            height += self._row_height(rows[-1])
        return rows, height

    @staticmethod
    def _row_height(row: list[tuple[QWidget, bool]]) -> int:
        """一行的高度 = 该行所有控件的「最小尺寸」与「建议尺寸」的较大值。

        必须取 ``minimumHeight``：``sizeHint`` 在窄行里可能被压到十几像素，
        照它排就会把输入框压成一条缝（下拉框 / 数字框尤其明显）。
        """
        return max(
            (max(widget.sizeHint().height(), widget.minimumHeight(),
                 widget.minimumSizeHint().height())
             for widget, _stretch in row),
            default=0,
        )

    def _do_layout(self) -> None:
        rows, _ = self._measure()
        width = max(0, self.width())
        y = 0
        for row in rows:
            if not row:
                continue
            row_h = self._row_height(row)
            # 弹性控件先吃剩余，其余按 sizeHint 排布
            fixed = sum(widget.sizeHint().width() for widget, stretch in row
                        if not stretch)
            stretchy = [entry for entry in row if entry[1]]
            gaps = self._spacing * (len(row) - 1)
            spare = max(0, width - fixed - gaps)
            x = 0
            for index, (widget, stretch) in enumerate(row):
                if index:
                    x += self._spacing
                if stretch:
                    share = spare // max(1, len(stretchy))
                    w = max(widget.minimumSizeHint().width(), share)
                else:
                    w = min(widget.sizeHint().width(),
                            max(widget.minimumSizeHint().width(),
                                width - x))
                widget.setGeometry(QRect(QPoint(x, y), QSize(w, row_h)))
                x += w
            y += row_h + self._row_spacing

    # ------------------------------------------------------------ Qt 钩子
    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self._do_layout()

    def showEvent(self, event) -> None:  # noqa: N802
        super().showEvent(event)
        self._do_layout()

    def sizeHint(self) -> QSize:  # noqa: N802
        """宽度 = 单行排布所需宽度；高度 = 按**当前**宽度折行后的高度。

        高度必须按真实宽度算：布局会按 sizeHint 宽度分配空间，若这里给的是
        「单行」高度，窄窗口下换行后的子控件就会溢出本控件、压到下一行上。
        宽度上限取「最宽子控件」和「可用宽度」的较大者，换取布局在窄窗口下
        愿意把本控件压窄（从而真的折行）。
        """
        rows, height = self._measure()
        single_line = 0
        for row in rows:
            single_line = max(single_line, sum(w.sizeHint().width() for w, _s in row)
                              + self._spacing * max(0, len(row) - 1))
        widest = self.minimumSizeHint().width()
        width = max(widest, min(single_line, max(self.width(), widest)))
        min_h = self.minimumSizeHint().height()
        return QSize(width, max(height, min_h))

    def minimumSizeHint(self) -> QSize:  # noqa: N802
        """最小尺寸：宽度 = 最宽的单控件，高度 = **单行**高度。

        高度绝不能返回 0：布局会把它当成「这一行可以不占地方」，控件就整行
        不绘制（URL / 方法那行曾因此消失）。换行后更高的情形由 ``sizeHint``
        与 :meth:`heightForWidth` 表达。
        注意用 ``isHidden()`` 而不是 ``isVisible()``——父控件未显示时后者恒为
        False，会把所有子控件当成不存在。
        """
        shown = [w for w, _s in self._items if not w.isHidden()]
        if not shown:
            return QSize(0, 0)
        widths = [max(w.minimumSizeHint().width(), w.sizeHint().width())
                  for w in shown]
        row_h = max((max(w.minimumSizeHint().height(),
                         w.minimumHeight(),
                         min(w.sizeHint().height(), 40))
                     for w in shown), default=0)
        return QSize(max(widths), row_h)

    def hasHeightForWidth(self) -> bool:  # noqa: N802
        return True

    def sizePolicy(self) -> QSizePolicy:  # noqa: N802
        policy = super().sizePolicy()
        policy.setHeightForWidth(True)
        policy.setVerticalPolicy(QSizePolicy.Policy.Minimum)
        return policy

    def heightForWidth(self, width: int) -> int:  # noqa: N802
        old = self.width()
        try:
            self.resize(max(0, width), self.height())
            return self._measure()[1]
        finally:
            self.resize(old, self.height())


__all__ = ["WrapRow"]
