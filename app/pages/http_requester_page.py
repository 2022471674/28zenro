# -*- coding: utf-8 -*-
"""HTTP 请求器「配置窗口」页（类 Burp Repeater / Intruder，不抓包）。

页面结构（按「从上到下就是发请求的思考顺序」排列，每段都有标题）::

    ① 请求行        方法 + URL            ← 必填，最显眼
    ② 发送与网络    发送/停止/结果窗口 + 超时/并发/延时/重定向/证书
    ③ 请求内容      查询参数 | 请求头 | 请求体
    ④ 载荷与攻击    模式/攻击类型 + 载荷位置 | 载荷/密码学接口
    ⑤ 日志

**方法 / URL 永远可见**：这一行不受下方内容挤压，且下方有一行实时回显
「将发送：GET https://…」，保证「你看到的方法」就是「真正发出去的方法」。

结果、响应详情、实发报文、请求预览在独立窗口
(:class:`app.widgets.http_requester_output.OutputWindow`)，发送时自动打开。

编码约定：请求报文由 ``lib.http_requester`` 自己拼装，载荷按字面发送，
已 Base64 / URL 编码的密文不会被二次转义。
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.widgets.http_requester_output import OutputWindow
from app.widgets.http_requester_worker import HttpRequesterWorker
from app.widgets.kv_table import KVTable
from app.widgets.no_wheel import NoWheelComboBox, NoWheelSpinBox
from app.widgets.responsive import ScrollColumn, guard_min_heights
from lib import crypto_interface, http_requester as hr


def _section(text: str) -> QLabel:
    """分区标题（深色下也清晰）。"""
    label = QLabel(text)
    label.setObjectName("section")
    return label


#: 请求头表格的默认合法内容（首次使用 / 未保存过请求头时预置）。
#: User-Agent 取自 ``lib.http_requester.USER_AGENT``，与 requests 实际发送一致。
def _default_headers() -> list[hr.Entry]:
    return [
        hr.Entry("User-Agent", hr.USER_AGENT, True),
        hr.Entry("Accept", "*/*", True),
        hr.Entry("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8", True),
        hr.Entry("Connection", "close", True),
    ]


class HttpRequesterPage(QWidget):
    """HTTP 请求器（配置窗口）。"""

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._worker: HttpRequesterWorker | None = None
        self._window: OutputWindow | None = None
        self._refreshing = False
        self._last_result: dict | None = None
        self._crypto_ops: list[crypto_interface.CryptoOp] = []
        self._crypto_param_widgets: dict[str, QWidget] = {}
        self._build_ui()
        self._load_crypto_ops()
        self._restore_config()
        self._wire_slots()
        self._refresh_plan()
        self._refresh_target_line()

    # ================================================================ 构建
    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(26, 16, 26, 14)
        outer.setSpacing(10)

        # ================= ① 请求行（必填，永远在最上面）===============
        outer.addWidget(_section("① 请求行（必填）"))
        # 第一排：方法 + URL（最核心，永远是完整一行）
        line_row = QHBoxLayout()
        line_row.setSpacing(8)
        line_row.addWidget(QLabel("方法"))
        self.method_combo = NoWheelComboBox()
        self.method_combo.addItems(hr.METHODS)
        self.method_combo.setFixedWidth(108)
        self.method_combo.setToolTip("选择请求方法")
        line_row.addWidget(self.method_combo)
        line_row.addWidget(QLabel("URL"))
        self.url_edit = QLineEdit()
        self.url_edit.setPlaceholderText(
            "https://example.com/api?token={{payload}}（可省略 http://）")
        self.url_edit.setMinimumWidth(220)
        self.url_edit.returnPressed.connect(self._send)
        line_row.addWidget(self.url_edit, 1)
        outer.addLayout(line_row)

        # 第二排：操作按钮（不和输入框抢宽度）
        action_row = QHBoxLayout()
        action_row.setSpacing(8)
        self.send_btn = QPushButton("发送")
        self.send_btn.setObjectName("ghbtn-primary")
        self.send_btn.setMinimumWidth(88)
        self.send_btn.clicked.connect(self._send)
        action_row.addWidget(self.send_btn)
        self.stop_btn = QPushButton("停止")
        self.stop_btn.setObjectName("ghbtn")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop)
        action_row.addWidget(self.stop_btn)
        self.window_btn = QPushButton("结果窗口")
        self.window_btn.setObjectName("ghbtn")
        self.window_btn.setToolTip("打开 / 聚焦独立的结果显示窗口")
        self.window_btn.clicked.connect(lambda: self.show_window(force=True))
        action_row.addWidget(self.window_btn)
        action_row.addStretch(1)
        outer.addLayout(action_row)

        # 实时回显：方法 + URL，避免「看到的方法」和「发送的方法」不一致
        self.target_label = QLabel("")
        self.target_label.setObjectName("status-info")
        self.target_label.setWordWrap(True)
        self.target_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        outer.addWidget(self.target_label)

        # ================= ② 网络选项 ================================
        opts = QHBoxLayout()
        opts.setSpacing(10)
        opts.addWidget(QLabel("超时"))
        self.timeout_spin = NoWheelSpinBox()
        self.timeout_spin.setRange(1, 300)
        self.timeout_spin.setValue(int(hr.DEFAULT_TIMEOUT))
        self.timeout_spin.setSuffix(" 秒")
        opts.addWidget(self.timeout_spin)
        opts.addWidget(QLabel("并发"))
        self.workers_spin = NoWheelSpinBox()
        self.workers_spin.setRange(1, 32)
        self.workers_spin.setValue(hr.DEFAULT_WORKERS)
        self.workers_spin.setToolTip("循环模式的并发数；1 表示顺序发送")
        opts.addWidget(self.workers_spin)
        opts.addWidget(QLabel("延时"))
        self.delay_spin = NoWheelSpinBox()
        self.delay_spin.setRange(0, 60)
        self.delay_spin.setValue(int(hr.DEFAULT_DELAY))
        self.delay_spin.setSuffix(" 秒")
        self.delay_spin.setToolTip("每次请求之间的固定间隔")
        opts.addWidget(self.delay_spin)
        self.redirect_check = QCheckBox("跟随重定向")
        self.redirect_check.setChecked(hr.DEFAULT_REDIRECTS)
        opts.addWidget(self.redirect_check)
        self.verify_check = QCheckBox("校验证书")
        self.verify_check.setChecked(hr.DEFAULT_VERIFY_TLS)
        opts.addWidget(self.verify_check)
        opts.addStretch(1)
        outer.addLayout(opts)

        # ================= ③ 请求内容 ================================
        outer.addWidget(_section("② 请求内容"))
        self.request_tabs = QTabWidget()
        self.request_tabs.addTab(self._build_query_tab(), "查询参数")
        self.request_tabs.addTab(self._build_header_tab(), "请求头")
        self.request_tabs.addTab(self._build_body_tab(), "请求体")
        self.request_tabs.setMinimumHeight(72)
        self.request_scroll = ScrollColumn()
        self.request_scroll.add_widget(self.request_tabs, 1)
        outer.addWidget(self.request_scroll, 2)

        # ================= ④ 载荷与攻击 ==============================
        outer.addWidget(_section("③ 载荷与攻击"))
        self.payload_box = self._build_payload_box()
        self.payload_scroll = ScrollColumn()
        self.payload_scroll.add_widget(self.payload_box)
        outer.addWidget(self.payload_scroll, 3)

        # ================= ⑤ 日志 ====================================
        log_head = QHBoxLayout()
        log_head.setSpacing(8)
        log_head.addWidget(_section("④ 日志"))
        self.preview_btn = QPushButton("预览报文")
        self.preview_btn.setObjectName("ghbtn")
        self.preview_btn.setToolTip("把将要发出的报文送到结果窗口逐字核对")
        self.preview_btn.clicked.connect(self._preview_request)
        log_head.addWidget(self.preview_btn)
        clear_log_btn = QPushButton("清空日志")
        clear_log_btn.setObjectName("ghbtn")
        clear_log_btn.clicked.connect(lambda: self.log_view.clear())
        log_head.addWidget(clear_log_btn)
        log_head.addStretch(1)
        outer.addLayout(log_head)

        self.log_view = QPlainTextEdit()
        self.log_view.setObjectName("io")
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(2000)
        self.log_view.setMinimumHeight(48)
        self.log_view.setPlaceholderText("请求日志（结果窗口的「日志」页也有）…")
        outer.addWidget(self.log_view, 1)

        self.status_label = QLabel("")
        self.status_label.setObjectName("status-info")
        self.status_label.setWordWrap(True)
        outer.addWidget(self.status_label)

        for label in self.findChildren(QLabel):
            if not label.wordWrap() and len(label.text()) > 16:
                label.setWordWrap(True)
            label.setMinimumWidth(1)
        guard_min_heights(self)

    # ------------------------------------------------------ 请求内容三页
    def _build_query_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 6, 0, 0)
        self.query_table = KVTable(self.theme, headers=("参数名", "值"),
                                   name_placeholder="key",
                                   value_placeholder="value 或 {{payload}}")
        layout.addWidget(self.query_table)
        return page

    def _build_header_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 6, 0, 0)
        self.header_table = KVTable(self.theme, headers=("请求头", "值"),
                                    name_placeholder="X-Token",
                                    value_placeholder="value 或 {{payload}}")
        layout.addWidget(self.header_table)
        hint = QLabel("不填 Cookie / User-Agent 时按 requests 默认发送；"
                      "自定义 Content-Type 优先于「请求体」自动补的默认值。")
        hint.setObjectName("caption")
        hint.setWordWrap(True)
        layout.addWidget(hint)
        return page

    def _build_body_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 6, 0, 0)
        layout.setSpacing(6)
        kind_row = QHBoxLayout()
        kind_row.setSpacing(8)
        kind_row.addWidget(QLabel("类型"))
        self.body_kind_combo = NoWheelComboBox()
        for kind in hr.BODY_KINDS:
            self.body_kind_combo.addItem(hr.BODY_LABELS.get(kind, kind), kind)
        kind_row.addWidget(self.body_kind_combo)
        kind_row.addStretch(1)
        layout.addLayout(kind_row)
        self.body_table = KVTable(self.theme, headers=("字段名", "值"),
                                  name_placeholder="field",
                                  value_placeholder="value 或 {{payload}}")
        layout.addWidget(self.body_table, 1)
        self.body_raw = QPlainTextEdit()
        self.body_raw.setObjectName("io")
        self.body_raw.setPlaceholderText('原始请求体，例如 {"sign":"{{payload}}"}')
        self.body_raw.setMinimumHeight(80)
        layout.addWidget(self.body_raw, 1)
        hint = QLabel("表单：字段名+值拼成 a=1&b=2；JSON：拼成对象；"
                      "「原始文本」可自己写整段 JSON。")
        hint.setObjectName("caption")
        hint.setWordWrap(True)
        layout.addWidget(hint)
        return page

    # ------------------------------------------------------ 载荷与攻击
    def _build_payload_box(self) -> QWidget:
        box = QWidget()
        layout = QVBoxLayout(box)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        mode_row = QHBoxLayout()
        mode_row.setSpacing(10)
        mode_row.addWidget(QLabel("模式"))
        self.mode_combo = NoWheelComboBox()
        for mode in hr.MODES:
            self.mode_combo.addItem(hr.MODE_LABELS[mode], mode)
        self.mode_combo.setSizeAdjustPolicy(
            QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        self.mode_combo.setMinimumContentsLength(8)
        mode_row.addWidget(self.mode_combo)
        mode_row.addWidget(QLabel("攻击类型"))
        self.attack_combo = NoWheelComboBox()
        for attack in hr.ATTACKS:
            self.attack_combo.addItem(hr.ATTACK_SHORT_LABELS.get(attack, attack),
                                      attack)
            self.attack_combo.setItemData(
                self.attack_combo.count() - 1,
                hr.ATTACK_LABELS.get(attack, ""), Qt.ItemDataRole.ToolTipRole)
        self.attack_combo.setSizeAdjustPolicy(
            QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
        self.attack_combo.setMinimumContentsLength(12)
        mode_row.addWidget(self.attack_combo)
        self.plan_label = QLabel("")
        self.plan_label.setObjectName("caption")
        self.plan_label.setWordWrap(True)
        mode_row.addWidget(self.plan_label, 1)
        layout.addLayout(mode_row)

        self.const_row = QHBoxLayout()
        self.const_row.setSpacing(8)
        self.const_label = QLabel("常量值")
        self.const_row.addWidget(self.const_label)
        self.const_value_edit = QLineEdit()
        self.const_value_edit.setPlaceholderText(
            "常量模式下用它替换所有 {{payload}}")
        self.const_value_edit.setMinimumWidth(180)
        self.const_value_edit.textChanged.connect(self._refresh_preview)
        self.const_value_edit.returnPressed.connect(self._send)
        self.const_row.addWidget(self.const_value_edit, 1)
        layout.addLayout(self.const_row)

        self.payload_tabs = QTabWidget()

        slot_page = QWidget()
        s_layout = QVBoxLayout(slot_page)
        s_layout.setContentsMargins(0, 6, 0, 0)
        self.slot_table = QTableWidget(0, 3)
        self.slot_table.setHorizontalHeaderLabels(
            ["载荷位置", "默认值", "本位置载荷（每行一个，留空用通用列表）"])
        self.slot_table.verticalHeader().setVisible(False)
        head = self.slot_table.horizontalHeader()
        head.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        head.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.slot_table.setColumnWidth(0, 155)
        self.slot_table.setColumnWidth(1, 105)
        self.slot_table.verticalHeader().setDefaultSectionSize(26)
        s_layout.addWidget(self.slot_table, 1)
        slot_hint = QLabel("位置来自请求里写的 {{payload}}；一处都没写时，每个启用"
                           "的参数 / 请求头 / 表单字段各算一个位置。")
        slot_hint.setObjectName("caption")
        slot_hint.setWordWrap(True)
        s_layout.addWidget(slot_hint)
        self.payload_tabs.addTab(slot_page, "载荷位置")

        list_page = QWidget()
        l_layout = QHBoxLayout(list_page)
        l_layout.setContentsMargins(0, 6, 0, 0)
        l_layout.setSpacing(12)

        left = QVBoxLayout()
        left.setSpacing(4)
        left.addWidget(QLabel("载荷列表（每行一个）"))
        self.payload_edit = QPlainTextEdit()
        self.payload_edit.setObjectName("io")
        self.payload_edit.setPlaceholderText("flag\nadmin")
        self.payload_edit.textChanged.connect(self._on_payloads_changed)
        left.addWidget(self.payload_edit, 1)
        load_row = QHBoxLayout()
        load_row.setSpacing(6)
        load_btn = QPushButton("从文件载入")
        load_btn.setObjectName("ghbtn")
        load_btn.clicked.connect(self._load_payload_file)
        load_row.addWidget(load_btn)
        self.payload_count_label = QLabel("")
        self.payload_count_label.setObjectName("caption")
        load_row.addWidget(self.payload_count_label)
        load_row.addStretch(1)
        left.addLayout(load_row)
        l_layout.addLayout(left, 1)

        right = QVBoxLayout()
        right.setSpacing(4)
        right.addWidget(QLabel("密码学接口（明文 → 密文载荷）"))
        self.crypto_combo = NoWheelComboBox()
        self.crypto_combo.currentIndexChanged.connect(self._on_crypto_changed)
        right.addWidget(self.crypto_combo)
        self.crypto_param_box = QWidget()
        self.crypto_form = QFormLayout(self.crypto_param_box)
        self.crypto_form.setContentsMargins(0, 0, 0, 0)
        self.crypto_form.setVerticalSpacing(4)
        right.addWidget(self.crypto_param_box)
        apply_row = QHBoxLayout()
        apply_row.setSpacing(6)
        apply_btn = QPushButton("应用变换")
        apply_btn.setObjectName("ghbtn-primary")
        apply_btn.clicked.connect(lambda: self._apply_crypto(replace=True))
        apply_row.addWidget(apply_btn)
        prev_btn = QPushButton("仅预览")
        prev_btn.setObjectName("ghbtn")
        prev_btn.clicked.connect(lambda: self._apply_crypto(replace=False))
        apply_row.addWidget(prev_btn)
        apply_row.addStretch(1)
        right.addLayout(apply_row)
        right.addStretch(1)
        l_layout.addLayout(right, 1)
        self.payload_tabs.addTab(list_page, "载荷 / 密码学")

        self.payload_tabs.setMinimumHeight(96)
        layout.addWidget(self.payload_tabs, 1)
        return box

    # ================================================================ 载荷
    def _load_crypto_ops(self) -> None:
        self._crypto_ops = list(crypto_interface.CRYPTO_OPS)
        self.crypto_combo.blockSignals(True)
        self.crypto_combo.clear()
        self.crypto_combo.addItem("（不使用变换）", "")
        for op in self._crypto_ops:
            self.crypto_combo.addItem(f"{op.group} · {op.label}", op.op_id)
        self.crypto_combo.blockSignals(False)
        self._on_crypto_changed()

    def _on_crypto_changed(self) -> None:
        op_id = self.crypto_combo.currentData() or ""
        while self.crypto_form.rowCount():
            self.crypto_form.removeRow(0)
        self._crypto_param_widgets.clear()
        op = next((item for item in self._crypto_ops if item.op_id == op_id), None)
        if op is None:
            return
        for param in op.params:
            widget = self._make_crypto_param_widget(param)
            self._crypto_param_widgets[param.key] = widget
            self.crypto_form.addRow(param.effective_label, widget)

    def _make_crypto_param_widget(self, param) -> QWidget:
        if param.ptype == crypto_interface.PTYPE_SELECT and param.choices:
            combo = NoWheelComboBox()
            for value, label in param.choices:
                combo.addItem(label, value)
            for i in range(combo.count()):
                if str(combo.itemData(i)) == str(param.default):
                    combo.setCurrentIndex(i)
                    break
            return combo
        if param.ptype == crypto_interface.PTYPE_INT:
            spin = NoWheelSpinBox()
            low = int(param.minimum) if param.minimum is not None else -10 ** 9
            high = int(param.maximum) if param.maximum is not None else 10 ** 9
            spin.setRange(low, high)
            spin.setValue(int(param.default or 0))
            return spin
        edit = QLineEdit()
        edit.setText("" if param.default is None else str(param.default))
        edit.setPlaceholderText(param.hint or "")
        return edit

    def _crypto_values(self) -> dict:
        values: dict = {}
        for key, widget in self._crypto_param_widgets.items():
            if isinstance(widget, QComboBox):
                values[key] = widget.currentData()
            elif isinstance(widget, QSpinBox):
                values[key] = widget.value()
            elif isinstance(widget, QLineEdit):
                values[key] = widget.text()
        return values

    def _apply_crypto(self, *, replace: bool) -> None:
        op_id = self.crypto_combo.currentData() or ""
        if not op_id:
            self._set_status(False, "先选一个密码学算法。")
            return
        plain = hr.split_payloads(self.payload_edit.toPlainText())
        if not plain:
            self._set_status(False, "载荷列表是空的，先填几行明文。")
            return
        result = crypto_interface.transform(plain, op_id, self._crypto_values())
        if result.errors:
            first = result.errors[0]
            self._append_log(f"[密码学接口] {len(result.errors)} 行失败，例如 "
                             f"{first['input']!r}：{first['error']}")
        self.payload_edit.setPlainText("\n".join(result.outputs))
        if not replace:
            self.payload_edit.setReadOnly(True)
        self._set_status(True, f"已用「{result.label}」变换 {result.ok_count} 行载荷"
                               + (f"（{len(result.errors)} 行失败）"
                                  if result.errors else "。"))

    def _on_payloads_changed(self) -> None:
        self.payload_edit.setReadOnly(False)
        self._refresh_plan()

    def _load_payload_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "载入载荷文件", str(Path.cwd()), "文本文件 (*.txt);;所有文件 (*)")
        if not path:
            return
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            self._set_status(False, f"读取失败：{exc}")
            return
        self.payload_edit.setPlainText(text)
        self._set_status(True, f"已载入 {path}")

    # ================================================================ 表单
    def _wire_slots(self) -> None:
        for table in (self.query_table, self.header_table):
            table.changed.connect(self._refresh_plan)
        self.body_table.changed.connect(self._refresh_plan)
        self.body_raw.textChanged.connect(self._refresh_plan)
        self.body_kind_combo.currentIndexChanged.connect(self._on_body_kind_changed)
        self.url_edit.textChanged.connect(self._refresh_plan)
        self.url_edit.textChanged.connect(self._refresh_target_line)
        # 方法变化也要立刻回显（可编辑下拉：currentTextChanged 覆盖打字场景）
        self.method_combo.currentTextChanged.connect(self._refresh_target_line)
        self.method_combo.currentIndexChanged.connect(self._refresh_target_line)
        self.payload_edit.textChanged.connect(self._refresh_plan)
        self.mode_combo.currentIndexChanged.connect(self._on_mode_changed)
        self.attack_combo.currentIndexChanged.connect(self._on_mode_changed)
        self._on_body_kind_changed()
        self._on_mode_changed()

    def method(self) -> str:
        """当前请求方法（统一大写；空则退回 GET）。

        界面显示与真正发送都走这里，避免「看到 GET、发出去 POST」。
        """
        text = self.method_combo.currentText().strip().upper()
        return text or "GET"

    def _refresh_target_line(self) -> None:
        """实时回显「将发送：方法 URL」，让用户随时确认。"""
        if not hasattr(self, "target_label"):
            return
        method = self.method()
        url = self.url_edit.text().strip() or "（未填写 URL）"
        self.target_label.setText(f"将发送：{method}  {url}")

    def _on_body_kind_changed(self) -> None:
        is_text = self.body_kind_combo.currentData() == hr.BODY_TEXT
        self.body_table.setVisible(not is_text)
        self.body_raw.setVisible(is_text)
        self._refresh_plan()

    def _on_mode_changed(self) -> None:
        looping = self.mode_combo.currentData() == hr.MODE_LOOP
        self.attack_combo.setEnabled(looping)
        self.const_label.setVisible(not looping)
        self.const_value_edit.setVisible(not looping)
        self.payload_tabs.setTabEnabled(0, looping)
        self._refresh_plan()

    # ================================================================ 组装
    def _body_kind(self) -> str:
        return self.body_kind_combo.currentData() or hr.BODY_NONE

    def build_spec(self) -> hr.RequestSpec:
        """把当前界面状态收成 :class:`RequestSpec`。"""
        kind = self._body_kind()
        body_entries = ([] if kind in (hr.BODY_NONE, hr.BODY_TEXT)
                        else self.body_table.entries())
        if kind == hr.BODY_TEXT:
            body_entries = [hr.Entry("", self.body_raw.toPlainText())]
        scheme = ("https" if self.url_edit.text().strip().lower()
                  .startswith("https") else "http")
        return hr.RequestSpec(
            method=self.method(),
            url=self.url_edit.text().strip(),
            query=self.query_table.entries(),
            headers=self.header_table.entries(),
            body_kind=kind,
            body_entries=body_entries,
            timeout=float(self.timeout_spin.value()),
            redirects=self.redirect_check.isChecked(),
            verify=self.verify_check.isChecked(),
            scheme=scheme,
        )

    def _per_location_payloads(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for row in range(self.slot_table.rowCount()):
            key_item = self.slot_table.item(row, 0)
            value_item = self.slot_table.item(row, 2)
            if key_item is None or value_item is None:
                continue
            key = key_item.data(Qt.ItemDataRole.UserRole)
            lines = hr.split_payloads(value_item.text())
            if key and lines:
                out[str(key)] = lines
        return out

    def _refresh_plan(self) -> None:
        """带重入保护：刷新预览读表格可能再次触发本函数。"""
        if not hasattr(self, "plan_label") or self._refreshing:
            return
        self._refreshing = True
        try:
            self._refresh_plan_inner()
        finally:
            self._refreshing = False

    def _refresh_plan_inner(self) -> None:
        try:
            spec = self.build_spec()
            mode = self.mode_combo.currentData()
            attack = self.attack_combo.currentData()
            payloads = hr.split_payloads(self.payload_edit.toPlainText())
            plan_obj = hr.plan(spec, mode=mode, attack=attack, payloads=payloads,
                               per_location=self._per_location_payloads())
            if not plan_obj.slots and spec.has_placeholder():
                plan_obj.slots = hr.plan(spec, mode=hr.MODE_LOOP, attack=attack,
                                         payloads=payloads).slots
        except Exception as exc:  # noqa: BLE001 - URL 还没填好时不算错误
            self.plan_label.setText(str(exc))
            return
        self._render_slots(plan_obj)
        if plan_obj.mode == hr.MODE_CONST:
            self.plan_label.setText("常量模式：发 1 次")
        elif plan_obj.total:
            self.plan_label.setText(f"共 {plan_obj.total} 次请求"
                                    f"（{len(plan_obj.slots)} 个载荷位置）")
        else:
            self.plan_label.setText(plan_obj.warning or "没有可发送的请求")

    def _render_slots(self, plan_obj: hr.AttackPlan) -> None:
        """刷新「载荷位置」表格，保留用户已填的各位置载荷。"""
        existing = self._per_location_payloads()
        if not plan_obj.slots:
            if self.slot_table.rowCount():
                self.slot_table.setRowCount(0)
            return
        signature = [slot.slot_key for slot in plan_obj.slots]
        current = [self.slot_table.item(row, 0).data(Qt.ItemDataRole.UserRole)
                   if self.slot_table.item(row, 0) else None
                   for row in range(self.slot_table.rowCount())]
        if current == signature:
            for row, slot in enumerate(plan_obj.slots):
                cell = self.slot_table.item(row, 1)
                if cell is not None and cell.text() != slot.default:
                    cell.setText(slot.default)
            return
        self.slot_table.setRowCount(0)
        for slot in plan_obj.slots:
            row = self.slot_table.rowCount()
            self.slot_table.insertRow(row)
            item = QTableWidgetItem(slot.describe())
            item.setData(Qt.ItemDataRole.UserRole, slot.slot_key)
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.slot_table.setItem(row, 0, item)
            default_item = QTableWidgetItem(slot.default)
            default_item.setFlags(default_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.slot_table.setItem(row, 1, default_item)
            own = "\n".join(existing.get(slot.slot_key, []))
            self.slot_table.setItem(row, 2, QTableWidgetItem(own))

    # ================================================================ 显示窗口
    def show_window(self, *, force: bool = False) -> OutputWindow:
        """打开（或聚焦）结果显示窗口。"""
        win = self._window
        if win is None:
            win = OutputWindow(self.window())
            win.closed.connect(self._on_window_closed)
            self._window = win
        if force or not win.isVisible():
            win.show()
            win.raise_()
            win.activateWindow()
        elif not win.isActiveWindow():
            win.raise_()
        return win

    def _on_window_closed(self) -> None:
        self._window = None

    def _preview_request(self) -> None:
        try:
            spec = self.build_spec()
            mode = self.mode_combo.currentData()
            if mode == hr.MODE_CONST:
                values = ([self.const_value_edit.text()] * max(1, len(spec.slots()))
                          if spec.has_placeholder() else [])
            else:
                payloads = hr.split_payloads(self.payload_edit.toPlainText())
                plan_obj = hr.plan(spec, mode=mode,
                                   attack=self.attack_combo.currentData(),
                                   payloads=payloads,
                                   per_location=self._per_location_payloads())
                combos = hr.combinations(plan_obj)
                values = combos[0] if combos else []
            dump = hr.compose(spec, values)["request_dump"]
        except Exception as exc:  # noqa: BLE001
            self._set_status(False, f"无法生成预览：{exc}")
            return
        self.show_window(force=True).show_request(dump)
        self._set_status(True, "已把将要发出的报文送到结果窗口「请求预览」。")

    def _refresh_preview(self) -> None:
        """常量值变动时，若结果窗口开着就顺手刷新报文预览。"""
        if self._window is not None and self._window.isVisible():
            self._preview_request()

    # ================================================================ 发送
    def _send(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._set_status(False, "上一轮还没结束，请先停止。")
            return
        spec = self.build_spec()
        if not spec.url.strip():
            self._set_status(False, "请先填写目标 URL。")
            return
        mode = self.mode_combo.currentData()
        payloads = hr.split_payloads(self.payload_edit.toPlainText())
        per_location = self._per_location_payloads()
        if mode == hr.MODE_LOOP:
            plan_obj = hr.plan(spec, mode=mode,
                               attack=self.attack_combo.currentData(),
                               payloads=payloads, per_location=per_location)
            if plan_obj.total == 0:
                self._set_status(False, plan_obj.warning or "没有可发送的请求。")
                return

        # 把规范化后的方法写回控件：所见即所发（方法一定在下拉列表里）
        method_index = self.method_combo.findText(spec.method)
        if method_index >= 0:
            self.method_combo.setCurrentIndex(method_index)
        self._refresh_target_line()

        self._save_config()
        win = self.show_window(force=True)
        win.clear()
        win.set_run_context(mode, self.attack_combo.currentData())
        win.set_summary(f"{spec.method} {spec.url}")
        self.log_view.clear()
        self._set_status(True, f"正在发送（{spec.method}）…")
        self.send_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

        options = {
            "mode": mode,
            "attack": self.attack_combo.currentData(),
            "payloads": payloads,
            "per_location": per_location,
            "const_value": self.const_value_edit.text(),
            "timeout": float(self.timeout_spin.value()),
            "workers": int(self.workers_spin.value()),
            "delay": float(self.delay_spin.value()),
            "redirects": self.redirect_check.isChecked(),
            "verify": self.verify_check.isChecked(),
            "scheme": spec.scheme,
        }
        worker = HttpRequesterWorker(spec, options, self)
        worker.log.connect(self._append_log)
        worker.row_done.connect(win.append_record)
        worker.done_ok.connect(self._on_done)
        worker.done_err.connect(self._on_error)
        old = self._worker
        self._worker = worker
        if old is not None:
            old.deleteLater()
        worker.start()

    def _stop(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._worker.stop()
            self._set_status(True, "正在停止…（等待在途请求结束）")

    def _on_done(self, result: dict) -> None:
        self._reset_buttons()
        self._last_result = result
        if result.get("mode") == hr.MODE_CONST:
            records = result.get("responses") or []
            win = self._window
            if records and win is not None and not win.records:
                win.append_record(records[0])
            if records and not records[0].get("error"):
                rec = records[0]
                self._set_status(True, f"{rec.get('status')} {rec.get('reason')} · "
                                       f"{rec.get('length')} bytes · "
                                       f"{rec.get('elapsed_ms')} ms")
            elif records:
                self._set_status(False, f"请求失败：{records[0].get('error')}")
        else:
            self._set_status(
                True, f"完成 {result.get('done')}/{result.get('total')} 次请求"
                + ("（已停止）" if result.get("stopped") else ""))
        if self._window is not None:
            self._window.set_summary(
                f"{self.method()} · 完成 {result.get('done')}/"
                f"{result.get('total')} · {result.get('elapsed', 0)}s")

    def _on_error(self, message: str) -> None:
        self._reset_buttons()
        self._set_status(False, message)

    def _reset_buttons(self) -> None:
        self.send_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    # ================================================================ 配置
    def _restore_config(self) -> None:
        cfg = self.store.get("http_requester", default={}) or {}
        try:
            self.timeout_spin.setValue(int(cfg.get("timeout") or hr.DEFAULT_TIMEOUT))
        except (TypeError, ValueError):
            pass
        try:
            self.workers_spin.setValue(int(cfg.get("workers") or hr.DEFAULT_WORKERS))
        except (TypeError, ValueError):
            pass
        for combo, key, default in ((self.mode_combo, "mode", hr.MODE_CONST),
                                    (self.attack_combo, "attack", hr.ATTACK_SNIPER)):
            value = cfg.get(key) or default
            for i in range(combo.count()):
                if combo.itemData(i) == value:
                    combo.setCurrentIndex(i)
                    break
        # 方法：只认上次**成功发送**的方法；没有（或已不在列表）就默认 GET
        saved_method = str(cfg.get("method") or "GET").strip().upper() or "GET"
        method_index = self.method_combo.findText(saved_method)
        self.method_combo.setCurrentIndex(method_index if method_index >= 0 else 0)
        saved = cfg.get("last_request") or {}
        if isinstance(saved, dict) and saved:
            try:
                spec = hr.RequestSpec.from_mapping(saved)
            except hr.HttpRequesterError:
                spec = None
            if spec is not None:
                self.url_edit.setText(spec.url)
                self.query_table.set_entries(spec.query)
                self.header_table.set_entries(spec.headers)
                for i in range(self.body_kind_combo.count()):
                    if self.body_kind_combo.itemData(i) == spec.body_kind:
                        self.body_kind_combo.setCurrentIndex(i)
                        break
                if spec.body_kind == hr.BODY_TEXT:
                    self.body_raw.setPlainText(
                        "\n".join(entry.value for entry in spec.body_entries))
                else:
                    self.body_table.set_entries(spec.body_entries)
                self._on_body_kind_changed()
        else:
            # 首次使用（或从未保存过请求）：预置合法默认请求头
            self.header_table.set_entries(_default_headers())
        self.const_value_edit.setText(str(cfg.get("const_value") or ""))
        self.payload_edit.setPlainText(str(cfg.get("payload_text") or ""))

    def _save_config(self) -> None:
        spec = self.build_spec()
        self.store.setv(int(self.timeout_spin.value()), "http_requester", "timeout")
        self.store.setv(int(self.workers_spin.value()), "http_requester", "workers")
        self.store.setv(self.mode_combo.currentData(), "http_requester", "mode")
        self.store.setv(self.attack_combo.currentData(), "http_requester", "attack")
        self.store.setv(spec.method, "http_requester", "method")
        self.store.setv(self.const_value_edit.text(), "http_requester", "const_value")
        self.store.setv(self.payload_edit.toPlainText(),
                        "http_requester", "payload_text")
        self.store.setv({
            "method": spec.method,
            "url": spec.url,
            "query": [{"name": e.name, "value": e.value, "enabled": e.enabled}
                      for e in spec.query],
            "headers": [{"name": e.name, "value": e.value, "enabled": e.enabled}
                        for e in spec.headers],
            "body_kind": spec.body_kind,
            "body": [{"name": e.name, "value": e.value, "enabled": e.enabled}
                     for e in spec.body_entries],
        }, "http_requester", "last_request")
        self.store.save()

    # ================================================================ 其它
    def _append_log(self, message: str) -> None:
        self.log_view.appendPlainText(message)
        bar = self.log_view.verticalScrollBar()
        bar.setValue(bar.maximum())
        if self._window is not None:
            self._window.append_log(message)

    def _set_status(self, ok: bool, text: str) -> None:
        self.status_label.setText(text)
        self.status_label.setObjectName("status-ok" if ok else "status-err")
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)

    def set_theme(self, palette) -> None:
        self.theme = palette
        for table in (self.query_table, self.header_table, self.body_table):
            table.set_theme(palette)

    def shutdown(self) -> None:
        """退出前停线程并关掉结果窗口。"""
        if self._worker is not None and self._worker.isRunning():
            self._worker.stop()
            self._worker.wait(2000)
        if self._window is not None:
            self._window.close()
            self._window = None


__all__ = ["HttpRequesterPage"]
