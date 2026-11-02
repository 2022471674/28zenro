# -*- coding: utf-8 -*-
"""滚轮不改值的输入控件。

Qt 默认让 ``QSpinBox`` / ``QComboBox`` 响应滚轮（滚一下值 ±1）。在滚动
设置页时，鼠标只要划过这些控件就会误改参数。这里提供忽略滚轮事件的子类：
滚轮事件被标记为「不接受」后会继续冒泡给父级滚动区，于是页面照常滚动、
控件值保持不变。

只忽略「滚轮改值」，不影响点击、键盘输入、下拉选择等正常交互；下拉列表
弹出后，列表自身的滚动由弹出层接收，也不受影响。
"""

from __future__ import annotations

from PySide6.QtWidgets import QComboBox, QSpinBox


class NoWheelMixin:
    """把滚轮事件标记为不接受，使其冒泡给父级滚动区。"""

    def wheelEvent(self, event) -> None:  # noqa: N802  Qt 命名约定
        event.ignore()


class NoWheelSpinBox(NoWheelMixin, QSpinBox):
    """滚过时不改值的数字输入框。"""


class NoWheelComboBox(NoWheelMixin, QComboBox):
    """滚过时不改值的下拉框。"""
