# -*- coding: utf-8 -*-
"""单一工具页：由 :class:`app.registry.ToolSpec` 驱动渲染。

侧边栏改为「大类手风琴 + 子工具子列表」后，每个子工具都是侧边栏上的一个
独立条目，主区直接切换为该工具对应的页面控件，因此不再需要页面内部用
chips 切换工具。本文件只保留「一个工具」的完整界面：

- 参数行：ToolSpec.params 声明的额外输入（如凯撒位移量），无声明时不显示；
  控件按声明自动推断：``choices`` 下拉框 / ``bool`` 复选框 / 其余数字框；
- 执行按钮：two-way 给「加密 / 解密」两个按钮，one-way 给一个；
- 主体区按工具形态：
  - 通用输入 / 输出面板（:class:`app.widgets.codec_panel.CodecPanel`）；
  - ``kind == KIND_DIFF``（文本对比器）换成
    :class:`app.widgets.diff_panel.DiffPanel`（左右对照 + 差异高亮）。

自带独立页面的工具（``KIND_PAGE`` / ``KIND_EMBEDDED``，如国密、JWT、MD5
爆破）不经过本类，由 ``main_window`` 直接构造对应页面控件并挂到侧边栏。
新增算法只需在 registry 追加一条 ToolSpec，本文件零改动。
"""

from __future__ import annotations

from functools import partial

from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app import registry
from app.widgets.codec_panel import CodecPanel
from app.widgets.diff_panel import DiffPanel
from app.widgets.no_wheel import (
    NoWheelComboBox,
    NoWheelMixin,
    NoWheelSpinBox,
)


class NoWheelDoubleSpinBox(NoWheelMixin, QDoubleSpinBox):
    """滚过时不改值的小数数字框。"""


class ToolPanel(QWidget):
    """注册表驱动的单个工具界面（一个工具一个控件）。"""

    def __init__(self, theme, tool: registry.ToolSpec,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._theme = theme
        #: 本控件承载的工具
        self.tool = tool
        #: 当前工具的参数控件（QSpinBox / QComboBox / QCheckBox，见 registry.ParamSpec）
        self._param_inputs: dict[str, QWidget] = {}
        #: 当前工具的执行按钮（空输入时置灰）
        self._action_buttons: list[QPushButton] = []

        self.panel: CodecPanel | None = None
        self.diff_panel: DiffPanel | None = None

        self._build()

    # -------------------------------------------------------------- 主题
    @property
    def theme(self):
        return self._theme

    @theme.setter
    def theme(self, palette) -> None:
        self.set_theme(palette)

    def set_theme(self, palette) -> None:
        """换主题时把新调色板下发到本页持有的面板。"""
        self._theme = palette
        if self.panel is not None:
            self.panel.theme = palette
        if self.diff_panel is not None:
            self.diff_panel.set_theme(palette)

    # ------------------------------------------------------------------ UI
    def _build(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)

        # -- 参数行（按需显示） --
        self.params_row = QHBoxLayout()
        self.params_row.setSpacing(12)
        layout.addLayout(self.params_row)

        # -- 执行按钮行 --
        self.actions_row = QHBoxLayout()
        self.actions_row.setSpacing(8)
        layout.addLayout(self.actions_row)

        if self.tool.kind == registry.KIND_DIFF:
            self.diff_panel = DiffPanel(self._theme)
            layout.addWidget(self.diff_panel, stretch=1)
        else:
            self.panel = CodecPanel(self._theme)
            self.panel.input_changed.connect(self._sync_action_buttons)
            layout.addWidget(self.panel, stretch=1)
            self._build_params(self.tool)
            self._build_actions(self.tool)

    @staticmethod
    def _clear_layout(layout) -> None:
        """清空布局，并立即把子控件移出控件层级。"""
        while layout.count():
            item = layout.takeAt(0)
            if item is None:
                break
            widget = item if isinstance(item, QWidget) else item.widget()
            if widget is not None:
                widget.hide()
                widget.setParent(None)
                widget.deleteLater()

    def _clear_params(self) -> None:
        self._clear_layout(self.params_row)
        self._param_inputs.clear()

    def _clear_actions(self) -> None:
        self._clear_layout(self.actions_row)
        self._action_buttons.clear()

    def _build_params(self, tool: registry.ToolSpec) -> None:
        """按 ParamSpec 的 ptype（缺省时自动推断）渲染参数控件。"""
        self._clear_params()
        for spec in sorted(tool.params, key=lambda p: p.order):
            ptype = spec.effective_ptype
            if ptype == registry.PTYPE_SELECT:
                self._add_select(spec)
            elif ptype == registry.PTYPE_BOOL:
                self._add_bool(spec)
            elif ptype == registry.PTYPE_INT:
                self._add_spin(spec, float_type=False)
            elif ptype == registry.PTYPE_FLOAT:
                self._add_spin(spec, float_type=True)
            elif ptype == registry.PTYPE_FILE:
                self._add_file(spec)
            elif ptype == registry.PTYPE_TEXT:
                self._add_text(spec)
            else:  # PTYPE_STR
                self._add_str(spec)
        self.params_row.addStretch(1)

    def _add_label(self, spec: registry.ParamSpec) -> QLabel:
        label = QLabel(spec.effective_label)
        label.setObjectName("section")
        return label

    def _add_select(self, spec: registry.ParamSpec) -> None:
        self.params_row.addWidget(self._add_label(spec))
        box = NoWheelComboBox()
        for value, text in spec.choice_pairs:
            box.addItem(text, value)
        for index in range(box.count()):
            if box.itemData(index) == spec.default:
                box.setCurrentIndex(index)
                break
        box.setFixedWidth(130)
        self.params_row.addWidget(box)
        self._param_inputs[spec.key] = box

    def _add_bool(self, spec: registry.ParamSpec) -> None:
        box = QCheckBox(spec.effective_label)
        box.setChecked(bool(spec.default))
        if spec.hint:
            box.setToolTip(spec.hint)
        self.params_row.addWidget(box)
        self._param_inputs[spec.key] = box

    def _add_spin(self, spec: registry.ParamSpec, float_type: bool) -> None:
        self.params_row.addWidget(self._add_label(spec))
        if float_type:
            spin = NoWheelDoubleSpinBox()
            spin.setDecimals(2)
            spin.setSingleStep(0.1)
            minimum = spec.minimum if spec.minimum is not None else 0.0
            maximum = spec.maximum if spec.maximum is not None else 999999.0
            spin.setRange(float(minimum), float(maximum))
            spin.setValue(float(spec.default or 0.0))
        else:
            spin = NoWheelSpinBox()
            spin.setMinimum(int(spec.minimum) if spec.minimum is not None else 0)
            spin.setMaximum(int(spec.maximum) if spec.maximum is not None else 999999)
            spin.setValue(int(spec.default or 0))
        spin.setFixedWidth(110)
        if spec.hint:
            spin.setToolTip(spec.hint)
        self.params_row.addWidget(spin)
        self._param_inputs[spec.key] = spin

    def _add_str(self, spec: registry.ParamSpec) -> None:
        self.params_row.addWidget(self._add_label(spec))
        edit = QLineEdit()
        edit.setText("" if spec.default is None else str(spec.default))
        if spec.hint:
            edit.setPlaceholderText(spec.hint)
        edit.setFixedWidth(180)
        self.params_row.addWidget(edit)
        self._param_inputs[spec.key] = edit

    def _add_file(self, spec: registry.ParamSpec) -> None:
        self.params_row.addWidget(self._add_label(spec))
        edit = QLineEdit()
        edit.setText("" if spec.default is None else str(spec.default))
        edit.setReadOnly(True)
        if spec.hint:
            edit.setPlaceholderText(spec.hint)
        edit.setFixedWidth(200)
        self.params_row.addWidget(edit)
        browse = QPushButton("浏览…")
        browse.setObjectName("ghbtn")
        browse.clicked.connect(lambda: self._pick_file(edit))
        self.params_row.addWidget(browse)
        self._param_inputs[spec.key] = edit

    def _pick_file(self, edit: QLineEdit) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "选择文件", edit.text().strip() or "", "所有文件 (*)")
        if path:
            edit.setText(path)

    def _add_text(self, spec: registry.ParamSpec) -> None:
        label = self._add_label(spec)
        self.params_row.addWidget(label)
        text = QTextEdit()
        text.setPlainText("" if spec.default is None else str(spec.default))
        if spec.hint:
            text.setPlaceholderText(spec.hint)
        text.setFixedHeight(56)
        self.params_row.addWidget(text)
        self._param_inputs[spec.key] = text

    def _build_actions(self, tool: registry.ToolSpec) -> None:
        self._clear_actions()
        if tool.kind == registry.KIND_TWO_WAY and tool.dec is not None:
            enc_btn = QPushButton(f"{tool.name}加密")
            enc_btn.setObjectName("ghbtn-primary")
            enc_btn.clicked.connect(partial(self._run, True))
            dec_btn = QPushButton(f"{tool.name}解密")
            dec_btn.setObjectName("ghbtn")
            dec_btn.clicked.connect(partial(self._run, False))
            self.actions_row.addWidget(enc_btn)
            self.actions_row.addWidget(dec_btn)
            self._action_buttons = [enc_btn, dec_btn]
        else:
            run_btn = QPushButton(f"执行 {tool.name}")
            run_btn.setObjectName("ghbtn-primary")
            run_btn.clicked.connect(partial(self._run, True))
            self.actions_row.addWidget(run_btn)
            self._action_buttons = [run_btn]
        self.actions_row.addStretch(1)
        self._sync_action_buttons(self.panel.has_input())

    def _sync_action_buttons(self, has_input: bool) -> None:
        """空输入时置灰执行按钮，避免点了没反应或先报错后回滚的闪烁。"""
        for btn in self._action_buttons:
            btn.setEnabled(has_input)

    # ------------------------------------------------------------- 执行
    def _gather_params(self) -> dict:
        """把当前参数控件的取值收成 lib 函数的关键字参数。"""
        params: dict = {}
        for key, widget in self._param_inputs.items():
            if isinstance(widget, (QSpinBox, QDoubleSpinBox)):
                params[key] = widget.value()
            elif isinstance(widget, QCheckBox):
                params[key] = widget.isChecked()
            elif isinstance(widget, QComboBox):
                params[key] = widget.currentData()
            elif isinstance(widget, QTextEdit):
                params[key] = widget.toPlainText()
            elif isinstance(widget, QLineEdit):
                params[key] = widget.text()
        return params

    def _run(self, encrypt: bool) -> None:
        tool = self.tool
        func = tool.enc if encrypt else tool.dec
        if func is None or self.panel is None:
            return

        if not self.panel.has_input():
            self.panel.set_output(
                f"[{tool.failure or tool.name}失败] {self._theme.UI_EMPTY_INPUT}"
            )
            return

        data = self.panel.get_input()
        try:
            if tool.params:
                result = func(data, **self._gather_params())
            else:
                result = func(data)
        except NotImplementedError as exc:
            self.panel.set_output(str(exc))
            return
        except Exception as exc:  # noqa: BLE001  界面兜底：任何异常不崩窗
            prefix = tool.failure or tool.name
            self.panel.set_output(f"[{prefix}失败] {exc}")
            return

        self.panel.set_output(result)
