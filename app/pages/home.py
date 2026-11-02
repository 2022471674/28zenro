# -*- coding: utf-8 -*-
"""首页：按分类展示全部启用工具的卡片网格。

卡片点击跳转到对应页面（编解码类落到通用工具页并预选该工具）。
设置页关闭某工具后，``refresh()`` 重建网格，被关工具即时消失。
"""

from __future__ import annotations

from functools import partial

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QGridLayout,
    QLabel,
    QLineEdit,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from app import registry


class _ToolCard(QWidget):
    """单个工具卡片：名称 + 描述，点击发出 open_tool 信号。"""

    clicked = Signal(str)

    def __init__(self, theme, tool: registry.ToolSpec, parent=None) -> None:
        super().__init__(parent)
        self.tool_id = tool.id
        self.setObjectName("toolcard")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(88)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(4)

        name = QLabel(tool.name)
        name.setStyleSheet("font-size: 14px; font-weight: 600;")
        layout.addWidget(name)

        desc = QLabel(tool.description or tool.category_label)
        desc.setObjectName("caption")
        desc.setWordWrap(True)
        layout.addWidget(desc)
        layout.addStretch(1)

    def mousePressEvent(self, event) -> None:  # noqa: N802  Qt 命名约定
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self.tool_id)
        super().mousePressEvent(event)


class HomePage(QWidget):
    """首页工具网格。"""

    #: 点击工具卡片：tool_id -> None
    open_tool = Signal(str)

    def __init__(self, theme, store, parent=None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._build()

    def _build(self) -> None:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

        container = QWidget()
        self._container_layout = QVBoxLayout(container)
        self._container_layout.setContentsMargins(24, 20, 24, 20)
        self._container_layout.setSpacing(16)
        scroll.setWidget(container)

        headline = QLabel(self.theme.UI_HEADLINE)
        headline.setObjectName("title")
        subtitle = QLabel("Hello World CTF 编解码与密码学工具箱")
        subtitle.setObjectName("subtitle")
        self._container_layout.addWidget(headline)
        self._container_layout.addWidget(subtitle)
        self._container_layout.addSpacing(4)

        # 全局搜索框：输入即过滤，回车跳转第一个命中，Esc 清空
        self.search_edit = QLineEdit()
        self.search_edit.setObjectName("searchbox")
        self.search_edit.setPlaceholderText(
            "搜索工具（名称 / 描述 / 关键词），回车打开第一个结果，Esc 清空…")
        self.search_edit.setClearButtonEnabled(True)
        self.search_edit.textChanged.connect(self._on_search_changed)
        self.search_edit.returnPressed.connect(self._on_search_submit)
        self._container_layout.addWidget(self.search_edit)
        self._container_layout.addSpacing(4)

        self._grid_host = QWidget()
        self._container_layout.addWidget(self._grid_host)
        self._container_layout.addStretch(1)

        self.refresh()

    # ------------------------------------------------------------- 搜索
    def _on_search_changed(self, text: str) -> None:
        """搜索框内容变化：重建网格（带查询时显示过滤结果）。"""
        self.refresh()

    def _on_search_submit(self) -> None:
        """回车：若有命中则直接打开第一个工具。"""
        query = self.search_edit.text().strip()
        hits = registry.search_tools(query)
        if hits:
            self.open_tool.emit(hits[0].id)

    def keyPressEvent(self, event) -> None:  # noqa: N802
        """Esc 清空搜索框并恢复全量网格；Ctrl+F 聚焦搜索框。"""
        if event.key() == Qt.Key.Key_Escape and self.search_edit.text():
            self.search_edit.clear()
            return
        if event.key() == Qt.Key.Key_F and \
                event.modifiers() & Qt.KeyboardModifier.ControlModifier:
            self.search_edit.setFocus()
            self.search_edit.selectAll()
            return
        super().keyPressEvent(event)

    def refresh(self) -> None:
        """按当前启用状态（与搜索词）重建工具网格。"""
        # 清空旧网格
        old = self._grid_host
        self._grid_host = QWidget()
        index = self._container_layout.indexOf(old)
        self._container_layout.insertWidget(index, self._grid_host)
        old.deleteLater()

        grid_host = self._grid_host
        main_layout = QVBoxLayout(grid_host)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(16)

        query = self.search_edit.text().strip() if hasattr(self, "search_edit") else ""
        columns = 3

        if query:
            # 搜索模式：直接铺命中结果，不按分类分块
            hits = registry.search_tools(query)
            if not hits:
                empty = QLabel("没有匹配的工具，换个关键词试试。")
                empty.setObjectName("caption")
                main_layout.addWidget(empty)
            else:
                grid = QGridLayout()
                grid.setSpacing(10)
                for i, tool in enumerate(hits):
                    card = _ToolCard(self.theme, tool)
                    card.clicked.connect(partial(self.open_tool.emit))
                    grid.addWidget(card, i // columns, i % columns)
                for col in range(columns):
                    grid.setColumnStretch(col, 1)
                main_layout.addLayout(grid)
            return

        # 浏览模式：按分类分块展示
        for category, label in registry.CATEGORIES:
            tools = list(registry.tools_of_category(category))
            if not tools:
                continue

            cat_label = QLabel(label)
            cat_label.setObjectName("section")
            main_layout.addWidget(cat_label)

            grid = QGridLayout()
            grid.setSpacing(10)
            for i, tool in enumerate(tools):
                card = _ToolCard(self.theme, tool)
                card.clicked.connect(partial(self.open_tool.emit))
                grid.addWidget(card, i // columns, i % columns)
            for col in range(columns):
                grid.setColumnStretch(col, 1)
            main_layout.addLayout(grid)
            main_layout.addSpacing(4)
