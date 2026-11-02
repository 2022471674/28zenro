# -*- coding: utf-8 -*-
"""JSON 工具页（独立页面，挂在「字符串工具」分类下）。

两个子标签覆盖 JSON 的读与写，纯逻辑全部委托 ``lib.json_tool``
（本页不含任何解析 / 序列化代码）：

- 解析 / 格式化：粘贴 JSON → 校验 + 美化 / 压缩 / 结构报告（类型、键数、
  最大深度、重复键、逐条值路径），语法错误给「第 N 行第 M 列」定位；
- 构建器：选根节点（对象 / 数组）后逐行编辑「键名 / 类型 / 值」，一键生成
  JSON；嵌套对象 / 数组用「JSON 原文」类型整段插入，也可从解析标签一键导入。
"""

from __future__ import annotations

from functools import partial

from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from app.widgets.no_wheel import NoWheelComboBox
from lib import json_tool


def _make_status_label() -> QLabel:
    label = QLabel("")
    label.setObjectName("status-info")
    label.setWordWrap(True)
    return label


def _set_status(label: QLabel, ok: bool | None, text: str) -> None:
    """统一的状态行渲染：``None`` 灰色中性、``True`` 绿色成功、``False`` 红色失败。"""
    label.setObjectName(
        "status-info" if ok is None else ("status-ok" if ok else "status-err"))
    label.setText(text)
    label.style().unpolish(label)
    label.style().polish(label)


def _make_io_area(readonly: bool = False, min_height: int = 90) -> QPlainTextEdit:
    area = QPlainTextEdit()
    area.setObjectName("io")
    area.setReadOnly(readonly)
    area.setMinimumHeight(min_height)
    return area


def _copy(text: str) -> None:
    if text:
        QApplication.clipboard().setText(text)


class JsonRowsEditor(QWidget):
    """「键名 / 类型 / 值」行编辑器（构建标签用）。

    根节点为数组时键名列禁用（值仍按行顺序生成元素）；
    值输入框的占位提示随所选类型切换。
    """

    #: (键名输入框, 类型下拉, 值输入框, 删除按钮, 行布局)
    _Row = tuple[QLineEdit, NoWheelComboBox, QLineEdit, QPushButton, QHBoxLayout]

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._rows: list[JsonRowsEditor._Row] = []
        self._key_enabled = True

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(6)

        bar = QHBoxLayout()
        bar.setSpacing(6)
        add_btn = QPushButton("＋ 添加一行")
        add_btn.setObjectName("ghbtn")
        add_btn.clicked.connect(lambda: self.add_row())
        bar.addWidget(add_btn)
        bar.addStretch(1)
        outer.addLayout(bar)

        self._rows_host = QWidget()
        self._rows_layout = QVBoxLayout(self._rows_host)
        self._rows_layout.setContentsMargins(0, 0, 0, 0)
        self._rows_layout.setSpacing(4)
        outer.addWidget(self._rows_host)

    # -------------------------------------------------------------- 行操作
    def add_row(self, key: str = "", type_: str = json_tool.TYPE_STRING,
                value: str = "") -> QLineEdit:
        """追加一行键值，返回值输入框（便于调用方聚焦）。"""
        row = QHBoxLayout()
        row.setSpacing(6)

        key_edit = QLineEdit(key)
        key_edit.setPlaceholderText(self._key_placeholder())
        key_edit.setEnabled(self._key_enabled)

        type_box = NoWheelComboBox()
        for value_type, text in json_tool.VALUE_TYPE_LABELS:
            type_box.addItem(text, value_type)
        for index in range(type_box.count()):
            if type_box.itemData(index) == type_:
                type_box.setCurrentIndex(index)
                break

        value_edit = QLineEdit(value)
        value_edit.setPlaceholderText(
            json_tool.VALUE_PLACEHOLDERS.get(type_, ""))

        remove_btn = QPushButton("−")
        remove_btn.setObjectName("ghbtn")
        remove_btn.setFixedWidth(28)
        remove_btn.setToolTip("删除本行")

        entry = (key_edit, type_box, value_edit, remove_btn, row)
        remove_btn.clicked.connect(partial(self._remove_row, entry))
        # 切换类型时同步值输入框的占位提示（用默认参数绑定行内控件）
        type_box.currentIndexChanged.connect(
            partial(self._on_type_changed, type_box, value_edit))

        row.addWidget(key_edit, 2)
        row.addWidget(type_box)
        row.addWidget(value_edit, 3)
        row.addWidget(remove_btn)
        self._rows_layout.addLayout(row)
        self._rows.append(entry)
        return value_edit

    def _on_type_changed(self, type_box: NoWheelComboBox,
                         value_edit: QLineEdit, _index: int = 0) -> None:
        value_edit.setPlaceholderText(
            json_tool.VALUE_PLACEHOLDERS.get(type_box.currentData(), ""))

    def _remove_row(self, entry) -> None:
        key_edit, type_box, value_edit, remove_btn, row = entry
        self._rows_layout.removeItem(row)
        for widget in (key_edit, type_box, value_edit, remove_btn):
            widget.deleteLater()
        self._rows = [item for item in self._rows if item is not entry]

    def clear(self) -> None:
        for entry in list(self._rows):
            self._remove_row(entry)

    def row_count(self) -> int:
        """当前键值行数（含键名为空的行）。"""
        return len(self._rows)

    def set_rows(self, rows) -> None:
        """整体替换行内容（导入解析结果时用）。"""
        self.clear()
        for key, type_, value in rows:
            self.add_row(key, type_, value)

    def set_key_enabled(self, enabled: bool) -> None:
        """根节点在对象 / 数组间切换：数组模式下键名列禁用并说明原因。"""
        self._key_enabled = enabled
        for key_edit, _box, _value, _btn, _row in self._rows:
            key_edit.setEnabled(enabled)
            key_edit.setPlaceholderText(self._key_placeholder())

    def _key_placeholder(self) -> str:
        return "键名" if self._key_enabled else "（数组模式：键名列不参与生成）"

    # -------------------------------------------------------------- 读写
    def entries(self) -> list[tuple[str, str, str]]:
        """收集当前所有行，返回 ``(键名, 值类型, 值文本)``，顺序即显示顺序。"""
        return [
            (key_edit.text(), type_box.currentData(), value_edit.text())
            for key_edit, type_box, value_edit, _btn, _row in self._rows
        ]


class JsonPage(QWidget):
    """JSON 独立工具页：解析 / 格式化、构建器两个标签。"""

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._build()

    # ------------------------------------------------------------------ UI
    def _build(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(10)

        self.tabs = QTabWidget()
        self.parse_tab = self._build_parse_tab()
        self.build_tab = self._build_build_tab()
        self.tabs.addTab(self.parse_tab, "解析 / 格式化")
        self.tabs.addTab(self.build_tab, "构建器")
        layout.addWidget(self.tabs, stretch=1)

    # ---- Tab 1：解析 / 格式化 ---------------------------------------------
    def _build_parse_tab(self) -> QWidget:
        tab = QWidget()
        body = QHBoxLayout(tab)
        body.setContentsMargins(8, 14, 8, 8)
        body.setSpacing(16)

        # -- 左栏：输入 + 缩进 + 操作 --
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(8)
        left.setFixedWidth(420)

        left_layout.addWidget(self._section("JSON 文本"))
        self.parse_input = _make_io_area(min_height=140)
        self.parse_input.setPlaceholderText(
            "在此粘贴 JSON…\n对象 / 数组 / 标量均可，容忍首尾空白")
        left_layout.addWidget(self.parse_input)

        indent_row = QHBoxLayout()
        indent_row.setSpacing(8)
        indent_row.addWidget(self._section("缩进"))
        self.parse_indent = NoWheelComboBox()
        self.parse_indent.addItem("2 空格", 2)
        self.parse_indent.addItem("4 空格", 4)
        self.parse_indent.setMinimumWidth(160)
        indent_row.addWidget(self.parse_indent)
        indent_row.addStretch(1)
        left_layout.addLayout(indent_row)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        format_btn = QPushButton("格式化")
        format_btn.setObjectName("ghbtn-primary")
        format_btn.clicked.connect(self._do_format)
        minify_btn = QPushButton("压缩")
        minify_btn.setObjectName("ghbtn")
        minify_btn.clicked.connect(self._do_minify)
        analyze_btn = QPushButton("结构报告")
        analyze_btn.setObjectName("ghbtn")
        analyze_btn.clicked.connect(self._do_analyze)
        clear_btn = QPushButton("清空")
        clear_btn.setObjectName("ghbtn")
        clear_btn.clicked.connect(
            lambda: (self.parse_input.clear(), self.parse_out.clear(),
                     _set_status(self.parse_status, None, "")))
        buttons.addWidget(format_btn)
        buttons.addWidget(minify_btn)
        buttons.addWidget(analyze_btn)
        buttons.addWidget(clear_btn)
        buttons.addStretch(1)
        left_layout.addLayout(buttons)

        self.parse_status = _make_status_label()
        left_layout.addWidget(self.parse_status)
        left_layout.addStretch(1)
        body.addWidget(left)

        # -- 右栏：输出 --
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(8)

        right_layout.addWidget(self._section("输出"))
        self.parse_out = _make_io_area(readonly=True, min_height=160)
        self.parse_out.setPlaceholderText(
            "格式化 / 压缩结果或结构报告在此显示…")
        right_layout.addWidget(self.parse_out)

        out_btns = QHBoxLayout()
        out_btns.setSpacing(8)
        to_build = QPushButton("↓ 导入到构建器")
        to_build.setObjectName("ghbtn")
        to_build.setToolTip(
            "把当前输入的 JSON 拆成「键 / 类型 / 值」行，带入构建标签继续编辑")
        to_build.clicked.connect(self._import_to_build)
        copy_btn = QPushButton("复制结果")
        copy_btn.setObjectName("ghbtn")
        copy_btn.clicked.connect(lambda: _copy(self.parse_out.toPlainText()))
        out_btns.addWidget(to_build)
        out_btns.addStretch(1)
        out_btns.addWidget(copy_btn)
        right_layout.addLayout(out_btns)

        body.addWidget(right, stretch=1)
        return tab

    # ---- Tab 2：构建器 ------------------------------------------------------
    def _build_build_tab(self) -> QWidget:
        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(8, 14, 8, 8)
        layout.setSpacing(8)

        root_row = QHBoxLayout()
        root_row.setSpacing(8)
        root_row.addWidget(self._section("根节点"))
        self.build_root = NoWheelComboBox()
        self.build_root.addItem("对象（键 / 值）", json_tool.ROOT_OBJECT)
        self.build_root.addItem("数组（仅值）", json_tool.ROOT_ARRAY)
        self.build_root.setMinimumWidth(240)
        self.build_root.currentIndexChanged.connect(self._on_root_changed)
        root_row.addWidget(self.build_root)
        root_row.addStretch(1)
        layout.addLayout(root_row)

        layout.addWidget(self._section(
            "键 / 值行（嵌套结构选「JSON 原文」类型，整段粘贴子对象 / 子数组）"))
        self.build_rows = JsonRowsEditor()
        layout.addWidget(self.build_rows)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        build_btn = QPushButton("生成 JSON")
        build_btn.setObjectName("ghbtn-primary")
        build_btn.clicked.connect(self._do_build)
        import_btn = QPushButton("从解析标签导入")
        import_btn.setObjectName("ghbtn")
        import_btn.setToolTip("读取「解析 / 格式化」标签里输入的 JSON，拆成行继续编辑")
        import_btn.clicked.connect(self._import_to_build)
        clear_btn = QPushButton("清空行")
        clear_btn.setObjectName("ghbtn")
        clear_btn.clicked.connect(
            lambda: (self.build_rows.clear(), self.build_out.clear(),
                     _set_status(self.build_status, None, "")))
        copy_btn = QPushButton("复制结果")
        copy_btn.setObjectName("ghbtn")
        copy_btn.clicked.connect(lambda: _copy(self.build_out.toPlainText()))
        buttons.addWidget(build_btn)
        buttons.addWidget(import_btn)
        buttons.addWidget(clear_btn)
        buttons.addStretch(1)
        buttons.addWidget(copy_btn)
        layout.addLayout(buttons)

        layout.addWidget(self._section("生成结果（缩进 2 空格）"))
        self.build_out = _make_io_area(readonly=True, min_height=120)
        self.build_out.setPlaceholderText("点击「生成 JSON」后在此显示结果…")
        layout.addWidget(self.build_out)

        self.build_status = _make_status_label()
        layout.addWidget(self.build_status)
        layout.addStretch(1)

        return self._wrap_scroll(inner)

    # -------------------------------------------------------------- 小部件
    @staticmethod
    def _section(text: str) -> QLabel:
        label = QLabel(text)
        label.setObjectName("section")
        return label

    @staticmethod
    def _wrap_scroll(inner: QWidget) -> QScrollArea:
        """构建标签行数较多，套滚动区保证小窗口下不挤压。"""
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setWidget(inner)
        return scroll

    def _on_root_changed(self, _index: int = 0) -> None:
        self.build_rows.set_key_enabled(
            self.build_root.currentData() == json_tool.ROOT_OBJECT)

    # --------------------------------------------------------- Tab 1：解析
    def _do_format(self) -> None:
        source = self.parse_input.toPlainText()
        try:
            result = json_tool.format_json(
                source, indent=int(self.parse_indent.currentData()))
        except json_tool.JsonToolError as exc:
            self.parse_out.clear()
            _set_status(self.parse_status, False, str(exc))
            return
        self.parse_out.setPlainText(result)
        _set_status(self.parse_status, True,
                    f"格式化完成：输出 {len(result)} 个字符，中文原样保留。")

    def _do_minify(self) -> None:
        source = self.parse_input.toPlainText()
        try:
            result = json_tool.minify_json(source)
        except json_tool.JsonToolError as exc:
            self.parse_out.clear()
            _set_status(self.parse_status, False, str(exc))
            return
        self.parse_out.setPlainText(result)
        _set_status(self.parse_status, True,
                    f"压缩完成：{len(source)} → {len(result)} 个字符。")

    def _do_analyze(self) -> None:
        source = self.parse_input.toPlainText()
        try:
            result = json_tool.analyze_json(source)
        except json_tool.JsonToolError as exc:
            self.parse_out.clear()
            _set_status(self.parse_status, False, str(exc))
            return
        self.parse_out.setPlainText(result)
        _set_status(self.parse_status, True,
                    "结构报告已生成：值路径逐条列出类型与元素数。")

    def _import_to_build(self) -> None:
        """把解析标签里的输入拆成行，带入构建标签继续编辑。"""
        source = self.parse_input.toPlainText()
        try:
            root, rows = json_tool.rows_from_json(source)
        except json_tool.JsonToolError as exc:
            _set_status(self.parse_status, False, str(exc))
            return
        # 先切根节点（触发键名列启用 / 禁用），再填行
        self.build_root.setCurrentIndex(
            0 if root == json_tool.ROOT_OBJECT else 1)
        self.build_rows.set_rows(rows)
        self.build_out.clear()
        root_label = "对象" if root == json_tool.ROOT_OBJECT else "数组"
        _set_status(self.build_status, None,
                    f"已从解析标签导入：{root_label}，共 {len(rows)} 行，"
                    "编辑后点「生成 JSON」。")
        self.tabs.setCurrentWidget(self.build_tab)

    # -------------------------------------------------------- Tab 2：构建
    def _do_build(self) -> None:
        entries = self.build_rows.entries()
        try:
            result = json_tool.build_json(
                self.build_root.currentData(), entries)
        except json_tool.JsonToolError as exc:
            self.build_out.clear()
            _set_status(self.build_status, False, str(exc))
            return
        self.build_out.setPlainText(result)
        root_label = "对象" if self.build_root.currentData() == json_tool.ROOT_OBJECT \
            else "数组"
        _set_status(self.build_status, True,
                    f"构建完成：{root_label}，{len(entries)} 个值，"
                    f"共 {len(result)} 个字符。")

    def shutdown(self) -> None:
        """应用退出时调用：本页无后台线程，保留接口与其他页面对齐。"""
