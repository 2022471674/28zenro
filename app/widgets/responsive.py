# -*- coding: utf-8 -*-
"""小屏适配辅助：让长表单在 14/16 英寸笔记本上不被压扁。

问题背景
--------
``QVBoxLayout`` 在垂直空间不够时会把输入框一路压到 ``minimumSizeHint``
以下（实测 1366×768 上输入框只剩 12px 高），看起来就是「UI 挤压变形」。
根因是页面把「目标 + 一串请求配置 + 结果表 + payload」硬塞进一列，而且
输入框没有高度下限。

三个修复件
----------
:class:`ScrollColumn`
    表单竖向堆叠放进 ``QScrollArea``：空间够时铺满（不出现滚动条），空间
    不够时**变高并滚动**，而不是把控件压扁。

:class:`AdaptiveForm`
    按当前可用宽度，在「左标签 + 右控件」与「标签在上、控件在下」之间自动
    切换，窄屏下输入框不会被标签挤成一条缝。

:func:`guard_min_heights`
    给页面里的一行控件设置「不低于某高度」的下限，兜住滚动区之外的按钮等。
"""

from __future__ import annotations

from typing import Iterable

from PySide6.QtCore import QSize, Qt
from PySide6.QtWidgets import (
    QComboBox,
    QFormLayout,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

#: 一行输入框 / 下拉框 / 按钮的健康高度下限（再小就会被压成一条缝）
MIN_CONTROL_HEIGHT = 30

#: 表单切到「标签在上」模式的可用宽度阈值
NARROW_WIDTH = 560

#: 滚动区想要的舒服高度上限（超出就滚动）
COMFORT_HEIGHT = 520


class ScrollColumn(QScrollArea):
    """竖向堆叠、空间不足时滚动的容器。

    用法::

        scroll = ScrollColumn()
        form = scroll.form()          # 自适应表单
        form.addRow("目标 URL", line_edit)
        layout.addWidget(scroll, 1)
    """

    def __init__(self, parent: QWidget | None = None, *,
                 spacing: int = 8) -> None:
        super().__init__(parent)
        self.setWidgetResizable(True)
        self.setFrameShape(QScrollArea.Shape.NoFrame)
        # 横向不给滚动条（宽度由外层布局负责），纵向放不下才出现
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setSizePolicy(QSizePolicy.Policy.Preferred,
                           QSizePolicy.Policy.Expanding)

        self.body = QWidget()
        self.body.setObjectName("scrollBody")
        self._layout = QVBoxLayout(self.body)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(spacing)
        self.setWidget(self.body)
        self._form: AdaptiveForm | None = None

    # ------------------------------------------------------------------ API
    def add_widget(self, widget: QWidget, stretch: int = 0) -> QWidget:
        self._layout.addWidget(widget, stretch)
        return widget

    def add_layout(self, layout) -> None:
        self._layout.addLayout(layout)

    def add_stretch(self) -> None:
        self._layout.addStretch(1)

    def form(self) -> "AdaptiveForm":
        """滚动区顶部的自适应表单（只创建一次）。

        ``QFormLayout`` 必须有自己的宿主控件（不能直接塞进已有布局的 body），
        因此单独包一层 ``QWidget`` 再放进 body 的布局里。
        """
        if self._form is None:
            host = QWidget(self.body)
            host.setObjectName("formHost")
            self._form = AdaptiveForm(host)
            self._layout.addWidget(host)
        return self._form

    def body_layout(self) -> QVBoxLayout:
        return self._layout

    # ------------------------------------------------------------ 尺寸策略
    def sizeHint(self) -> QSize:  # noqa: N802
        body = self.body.sizeHint()
        return QSize(body.width() + 16, min(body.height(), COMFORT_HEIGHT))

    def minimumSizeHint(self) -> QSize:  # noqa: N802
        """纵向只要求「两行控件」的高度：放不下就滚动，绝不把外层窗口撑大。

        宽度仍要给足（横向不滚动），否则内容会被压扁或裁掉。
        高度故意给得很小：小屏（14/16 英寸）上页面才有空间把各部分都摆下，
        剩下的内容通过滚动条访问。
        """
        return QSize(self.body.minimumSizeHint().width(),
                     MIN_CONTROL_HEIGHT * 2)


class AdaptiveForm(QFormLayout):
    """宽度友好型表单：窄了就把标签挪到控件上方。

    宽屏 ``目标 URL  [__________]`` ／ 窄屏两行 ``目标 URL`` + ``[______]``。
    """

    def __init__(self, parent: QWidget | None = None, *,
                 threshold: int = NARROW_WIDTH) -> None:
        super().__init__(parent)
        self._threshold = threshold
        self._stacked = False
        self._ready = False
        self.setHorizontalSpacing(16)
        self.setVerticalSpacing(8)
        self.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)
        self._apply_mode(False)

    # ------------------------------------------------------------ 内部
    @staticmethod
    def _host_width(layout: QFormLayout) -> int:
        parent = layout.parentWidget()
        if parent is not None and parent.width() > 0:
            return parent.width()
        return 10 ** 6

    def _apply_mode(self, stacked: bool) -> None:
        """切换排布模式；模式没变就什么都不做（避免反复 invalidate）。"""
        if stacked == self._stacked and self._ready:
            return
        self._ready = True
        self._stacked = stacked
        if stacked:
            self.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapAllRows)
            self.setLabelAlignment(Qt.AlignmentFlag.AlignLeft
                                   | Qt.AlignmentFlag.AlignVCenter)
        else:
            self.setRowWrapPolicy(QFormLayout.RowWrapPolicy.DontWrapRows)
            self.setLabelAlignment(Qt.AlignmentFlag.AlignRight
                                   | Qt.AlignmentFlag.AlignVCenter)
        self.invalidate()

    # ------------------------------------------------------------ Qt 钩子
    def setGeometry(self, rect) -> None:  # noqa: N802
        self._apply_mode(rect.width() < self._threshold)
        super().setGeometry(rect)


def guard_min_heights(root: QWidget, *,
                      kinds: Iterable[type] = (QLineEdit, QPushButton,
                                               QComboBox, QSpinBox),
                      height: int = MIN_CONTROL_HEIGHT) -> None:
    """把 ``root`` 下的一行控件最小高度抬到 ``height``，防止被压成一条缝。"""
    kinds = tuple(kinds)
    for widget in root.findChildren(QWidget):
        if isinstance(widget, kinds) and widget.minimumHeight() < height:
            widget.setMinimumHeight(height)


def apply_adaptive_layout(page: QWidget) -> None:
    """让页面内所有 :class:`AdaptiveForm` 按当前宽度重排（resize 时调用）。"""
    for form in page.findChildren(AdaptiveForm):
        form._apply_mode(form._host_width(form) < form._threshold)


__all__ = [
    "MIN_CONTROL_HEIGHT", "NARROW_WIDTH", "COMFORT_HEIGHT", "ScrollColumn",
    "AdaptiveForm", "guard_min_heights", "apply_adaptive_layout",
]
