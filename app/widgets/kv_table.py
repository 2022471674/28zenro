# -*- coding: utf-8 -*-
"""可编辑的键值对表格（请求头 / 查询参数 / 表单字段共用）。

每行 = 一个参数：``[启用] 名称 | 值``。支持：

- 末尾的空白行自动补一行，边打字边「自动加行」；
- 删除选中行 / 清空；
- 保留重复键与顺序（``a=1&a=2`` 是两行，不是覆盖）；
- ``checkable=False`` 时用于「键名固定」的表格（如 Bulk 编辑器）。

表格只负责编辑，序列化成 :class:`lib.http_requester.Entry` 由调用方完成。
"""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QHBoxLayout,
    QHeaderView,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from lib.http_requester import Entry


class KVTable(QWidget):
    """键值对编辑表格。"""

    #: 内容变化（用于刷新「载荷位置」预览）
    changed = Signal()

    NAME_ROLE = "name"
    VALUE_ROLE = "value"

    def __init__(self, theme, *, headers: tuple[str, str] = ("名称", "值"),
                 name_placeholder: str = "name",
                 value_placeholder: str = "value",
                 checkable: bool = True,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self._name_head, self._value_head = headers
        self._name_ph = name_placeholder
        self._value_ph = value_placeholder
        self._checkable = checkable
        self._building = False
        self._build()
        self.set_entries([])

    # ------------------------------------------------------------------ UI
    def _build(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        self.table = QTableWidget(0, 3 if self._checkable else 2)
        heads = (["启用"] if self._checkable else []) + [self._name_head,
                                                         self._value_head]
        self.table.setHorizontalHeaderLabels(heads)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(
            QAbstractItemView.EditTrigger.DoubleClicked
            | QAbstractItemView.EditTrigger.SelectedClicked
            | QAbstractItemView.EditTrigger.EditKeyPressed
            | QAbstractItemView.EditTrigger.AnyKeyPressed)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        start = 0
        if self._checkable:
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
            self.table.setColumnWidth(0, 40)
            start = 1
        header.setSectionResizeMode(start + 1, QHeaderView.ResizeMode.Stretch)
        self.table.setColumnWidth(start, 120)
        self.table.verticalHeader().setDefaultSectionSize(30)
        self.table.itemChanged.connect(self._on_item_changed)
        layout.addWidget(self.table, 1)

        row = QHBoxLayout()
        row.setSpacing(8)
        add_btn = QPushButton("添加一行")
        add_btn.setObjectName("ghbtn")
        add_btn.clicked.connect(self.add_row)
        row.addWidget(add_btn)
        del_btn = QPushButton("删除选中")
        del_btn.setObjectName("ghbtn")
        del_btn.clicked.connect(self.remove_selected)
        row.addWidget(del_btn)
        clear_btn = QPushButton("清空")
        clear_btn.setObjectName("ghbtn")
        clear_btn.clicked.connect(lambda: self.set_entries([]))
        row.addWidget(clear_btn)
        if self._checkable:
            check_all = QPushButton("全启用/全禁用")
            check_all.setObjectName("ghbtn")
            check_all.clicked.connect(self.toggle_all)
            row.addWidget(check_all)
        row.addStretch(1)
        self.hint_label = None
        layout.addLayout(row)

    # -------------------------------------------------------------- 列结构
    @property
    def _name_col(self) -> int:
        return 1 if self._checkable else 0

    @property
    def _value_col(self) -> int:
        return 2 if self._checkable else 1

    def _new_row(self, name: str = "", value: str = "", enabled: bool = True,
                 *, placeholder: bool = False) -> int:
        row = self.table.rowCount()
        self.table.insertRow(row)
        if self._checkable:
            box = QCheckBox()
            box.setChecked(enabled)
            holder = QWidget()
            inner = QHBoxLayout(holder)
            inner.setContentsMargins(12, 0, 0, 0)
            inner.addWidget(box)
            inner.addStretch(1)
            self.table.setCellWidget(row, 0, holder)
        item_name = QTableWidgetItem(name)
        item_value = QTableWidgetItem(value)
        if placeholder:
            item_name.setForeground(self._placeholder_brush())
            item_value.setForeground(self._placeholder_brush())
            item_name.setToolTip(self._name_ph)
            item_value.setToolTip(self._value_ph)
        self.table.setItem(row, self._name_col, item_name)
        self.table.setItem(row, self._value_col, item_value)
        return row

    def _placeholder_brush(self):
        try:
            color = self.theme.text_secondary
        except AttributeError:
            color = None
        from PySide6.QtGui import QBrush, QColor
        if color is None:
            return QBrush(QColor("#8b949e"))
        return QBrush(QColor(str(color)))

    # -------------------------------------------------------------- 数据
    def set_entries(self, entries: list[Entry]) -> None:
        """载入条目（不含「空白补位行」）。"""
        self._building = True
        try:
            self.table.setRowCount(0)
            for entry in entries:
                self._new_row(entry.name, entry.value, entry.enabled)
            self._ensure_blank()
        finally:
            self._building = False
        self.changed.emit()

    def entries(self, *, include_blank: bool = False) -> list[Entry]:
        """读出条目；默认丢掉完全空白的行。"""
        out: list[Entry] = []
        for row in range(self.table.rowCount()):
            name_item = self.table.item(row, self._name_col)
            value_item = self.table.item(row, self._value_col)
            name = name_item.text() if name_item else ""
            value = value_item.text() if value_item else ""
            if not include_blank and not name and not value:
                continue
            out.append(Entry(name, value, self._is_enabled(row)))
        return out

    def _is_enabled(self, row: int) -> bool:
        if not self._checkable:
            return True
        holder = self.table.cellWidget(row, 0)
        if holder is None:
            return True
        box = holder.findChild(QCheckBox)
        return box.isChecked() if box is not None else True

    # -------------------------------------------------------------- 编辑
    def add_row(self) -> None:
        row = self._new_row()
        self.table.setCurrentCell(row, self._name_col)
        self.table.editItem(self.table.item(row, self._name_col))
        self._notify()

    def remove_selected(self) -> None:
        rows = sorted({index.row() for index in self.table.selectedIndexes()},
                      reverse=True)
        if not rows:
            return
        self._building = True
        try:
            for row in rows:
                self.table.removeRow(row)
            self._ensure_blank()
        finally:
            self._building = False
        self._notify()

    def toggle_all(self) -> None:
        if not self._checkable:
            return
        target = not all(self._is_enabled(row) for row in range(self.table.rowCount()))
        self._building = True
        try:
            for row in range(self.table.rowCount()):
                holder = self.table.cellWidget(row, 0)
                if holder is None:
                    continue
                box = holder.findChild(QCheckBox)
                if box is not None:
                    box.setChecked(target)
        finally:
            self._building = False
        self._notify()

    def _ensure_blank(self) -> None:
        """保证最后一行是空的，方便直接往下敲。"""
        rows = self.table.rowCount()
        if rows == 0:
            self._new_row()
            return
        name_item = self.table.item(rows - 1, self._name_col)
        value_item = self.table.item(rows - 1, self._value_col)
        name = name_item.text() if name_item else ""
        value = value_item.text() if value_item else ""
        if name or value:
            self._new_row()

    def _on_item_changed(self, item: QTableWidgetItem) -> None:
        if self._building:
            return
        self._building = True
        try:
            self._ensure_blank()
        finally:
            self._building = False
        self._notify()

    def _notify(self) -> None:
        self.changed.emit()

    # ---------------------------------------------------------------- 主题
    def set_theme(self, palette) -> None:
        self.theme = palette


__all__ = ["KVTable"]
