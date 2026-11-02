# -*- coding: utf-8 -*-
"""JWT 工具页（独立页面，取代原「字符串工具」里的 JWT 解析 chips）。

三个子标签覆盖 JWT 完整生命周期，纯逻辑全部委托 ``lib.jwt_codec``
（HS / RS / ES / none 全算法，本页不含任何算法代码）：

- 解析 / 校验：拆出 Header / Payload / Signature；填入密钥后可校验签名真伪；
- 创建：选算法 + 自定义密钥，逐行编辑 iss / sub / exp 等声明，一键生成令牌；
- 修改 / 重签：载入已有令牌 → 增删改声明 → 按原算法（或指定算法）重新签名。

声明值做智能类型识别：``true`` / ``false`` -> 布尔、纯数字（如 ``exp`` 时间戳）
-> 整数、``{...}`` / ``[...]`` -> JSON，其余按字符串保留。
"""

from __future__ import annotations

import json
import threading
from functools import partial

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
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
from lib import jwt_codec


class _BruteWorker(QThread):
    """后台执行 HS256 弱密钥爆破，日志 / 结果经信号回传。"""

    log = Signal(str)
    done_ok = Signal(object)  # 命中密钥 str 或 None
    done_err = Signal(str)

    def __init__(self, token: str, candidates: list[str], parent=None) -> None:
        super().__init__(parent)
        self._token = token
        self._candidates = candidates
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:  # noqa: D102
        try:
            found = jwt_codec.hs_bruteforce(
                self._token, self._candidates, log=self.log.emit, stop=self._stop)
        except jwt_codec.JwtError as exc:
            self.done_err.emit(str(exc))
            return
        self.done_ok.emit(found)


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


class _ClaimsEditor(QWidget):
    """逐行的「声明名 / 值」编辑器（创建与修改标签共用）。

    顶部一排标准声明（iss / sub / aud / exp / iat / nbf / jti）快捷按钮：
    点击即追加一行（已存在则聚焦该行），时间类声明自动预填当前 / 过期时间戳。
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        #: [(key_edit, value_edit, remove_btn, row_layout), ...]
        self._rows: list[tuple[QLineEdit, QLineEdit, QPushButton, QHBoxLayout]] = []

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(6)

        bar = QHBoxLayout()
        bar.setSpacing(6)
        for claim in jwt_codec.STANDARD_CLAIMS:
            chip = QPushButton(claim)
            chip.setObjectName("chip")
            chip.setToolTip(jwt_codec.CLAIM_DESCRIPTIONS.get(claim, claim))
            chip.clicked.connect(partial(self._quick_add, claim))
            bar.addWidget(chip)
        bar.addStretch(1)
        add_btn = QPushButton("＋ 添加声明")
        add_btn.setObjectName("ghbtn")
        add_btn.clicked.connect(lambda: self.add_row())
        bar.addWidget(add_btn)
        outer.addLayout(bar)

        self._rows_host = QWidget()
        self._rows_layout = QVBoxLayout(self._rows_host)
        self._rows_layout.setContentsMargins(0, 0, 0, 0)
        self._rows_layout.setSpacing(4)
        outer.addWidget(self._rows_host)

    # -------------------------------------------------------------- 行操作
    def add_row(self, key: str = "", value: str = "") -> QLineEdit:
        """追加一行声明，返回值输入框（便于调用方聚焦）。"""
        row = QHBoxLayout()
        row.setSpacing(6)

        key_edit = QLineEdit(key)
        key_edit.setPlaceholderText("声明名（如 iss / role）")
        value_edit = QLineEdit(value)
        value_edit.setPlaceholderText("值：true/false、数字、JSON 自动识别为对应类型")

        remove_btn = QPushButton("−")
        remove_btn.setObjectName("ghbtn")
        remove_btn.setFixedWidth(28)
        remove_btn.setToolTip("删除本行")

        entry = (key_edit, value_edit, remove_btn, row)
        remove_btn.clicked.connect(partial(self._remove_row, entry))

        row.addWidget(key_edit, 1)
        row.addWidget(value_edit, 2)
        row.addWidget(remove_btn)
        self._rows_layout.addLayout(row)
        self._rows.append(entry)
        return value_edit

    def _remove_row(self, entry) -> None:
        key_edit, value_edit, remove_btn, row = entry
        self._rows_layout.removeItem(row)
        for widget in (key_edit, value_edit, remove_btn):
            widget.deleteLater()
        self._rows = [item for item in self._rows if item is not entry]

    def clear(self) -> None:
        for entry in list(self._rows):
            self._remove_row(entry)

    def rows_count(self) -> int:
        """当前声明行数（含声明名为空的行）。"""
        return len(self._rows)

    # -------------------------------------------------------------- 读写
    def claims(self) -> dict:
        """收集当前所有非空声明名的行为 dict，值经智能类型识别。"""
        out: dict = {}
        for key_edit, value_edit, _btn, _row in self._rows:
            key = key_edit.text().strip()
            if key:
                out[key] = jwt_codec.coerce_claim_value(value_edit.text())
        return out

    def set_claims(self, data: dict) -> None:
        self.clear()
        for key, value in (data or {}).items():
            self.add_row(str(key), self._render_value(value))

    @staticmethod
    def _render_value(value) -> str:
        """把 JSON 值渲染回可编辑文本（布尔不带引号、对象保持紧凑 JSON）。"""
        if isinstance(value, bool):
            return "true" if value else "false"
        if value is None:
            return "null"
        if isinstance(value, (dict, list)):
            return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        return str(value)

    # -------------------------------------------------------------- 快捷
    def _quick_add(self, claim: str) -> None:
        for key_edit, value_edit, _btn, _row in self._rows:
            if key_edit.text().strip() == claim:
                value_edit.setFocus()
                return
        preset = self._timestamp_preset(claim)
        edit = self.add_row(claim, preset)
        edit.setFocus()
        edit.selectAll()

    @staticmethod
    def _timestamp_preset(claim: str) -> str:
        """时间类声明预填：``iat`` / ``nbf`` 当前时间，``exp`` 一小时后。"""
        now = jwt_codec.now_timestamp()
        return {"iat": str(now), "nbf": str(now), "exp": str(now + 3600)}.get(claim, "")


class JwtPage(QWidget):
    """JWT 独立工具页：解析 / 校验、创建、修改重签三个标签。"""

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._brute_worker: _BruteWorker | None = None
        self._last_candidates: list[str] = []
        self._build()

    # ------------------------------------------------------------------ UI
    def _build(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(10)

        self.tabs = QTabWidget()
        self.parse_tab = self._build_parse_tab()
        self.create_tab = self._build_create_tab()
        self.edit_tab = self._build_edit_tab()
        self.attack_tab = self._build_attack_tab()
        self.tabs.addTab(self.parse_tab, "解析 / 校验")
        self.tabs.addTab(self.create_tab, "创建")
        self.tabs.addTab(self.edit_tab, "修改 / 重签")
        self.tabs.addTab(self.attack_tab, "攻击")
        layout.addWidget(self.tabs, stretch=1)

    # ---- Tab 1：解析 / 校验 ----------------------------------------------
    def _build_parse_tab(self) -> QWidget:
        tab = QWidget()
        body = QHBoxLayout(tab)
        body.setContentsMargins(8, 14, 8, 8)
        body.setSpacing(16)

        # -- 左栏：令牌 + 密钥 + 操作 --
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(8)
        left.setFixedWidth(400)

        left_layout.addWidget(self._section("JWT 令牌"))
        self.parse_token = _make_io_area(min_height=100)
        self.parse_token.setPlaceholderText(
            "在此粘贴 JWT（可带 Bearer 前缀）…\nheader.payload.signature")
        left_layout.addWidget(self.parse_token)

        left_layout.addWidget(self._section("密钥（校验签名用，可选）"))
        self.parse_key = _make_io_area(min_height=80)
        self.parse_key.setPlaceholderText(
            "HS*：HMAC 字符串密钥；RS* / ES*：PEM 公钥（或私钥）；none：留空")
        left_layout.addWidget(self.parse_key)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        parse_btn = QPushButton("解析令牌")
        parse_btn.setObjectName("ghbtn-primary")
        parse_btn.clicked.connect(self._do_parse)
        verify_btn = QPushButton("校验签名")
        verify_btn.setObjectName("ghbtn")
        verify_btn.clicked.connect(self._do_verify)
        clear_btn = QPushButton("清空")
        clear_btn.setObjectName("ghbtn")
        clear_btn.clicked.connect(
            lambda: (self.parse_token.clear(), self.parse_key.clear(),
                     self.parse_header_out.clear(), self.parse_payload_out.clear(),
                     self.parse_sig_out.clear(), self.parse_desc.clear()),
        )
        buttons.addWidget(parse_btn)
        buttons.addWidget(verify_btn)
        buttons.addWidget(clear_btn)
        buttons.addStretch(1)
        left_layout.addLayout(buttons)

        self.parse_status = _make_status_label()
        left_layout.addWidget(self.parse_status)
        left_layout.addStretch(1)
        body.addWidget(left)

        # -- 右栏：三段解析结果 --
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(8)

        right_layout.addWidget(self._section("Header"))
        self.parse_header_out = _make_io_area(readonly=True, min_height=90)
        right_layout.addWidget(self.parse_header_out, stretch=1)

        right_layout.addWidget(self._section("Payload"))
        self.parse_payload_out = _make_io_area(readonly=True, min_height=90)
        right_layout.addWidget(self.parse_payload_out, stretch=1)

        self.parse_desc = QLabel("")
        self.parse_desc.setObjectName("caption")
        self.parse_desc.setWordWrap(True)
        right_layout.addWidget(self.parse_desc)

        right_layout.addWidget(self._section("Signature（Base64URL 原文）"))
        self.parse_sig_out = _make_io_area(readonly=True, min_height=50)
        right_layout.addWidget(self.parse_sig_out)

        out_btns = QHBoxLayout()
        out_btns.setSpacing(8)
        to_modify = QPushButton("↑ 转到「修改 / 重签」")
        to_modify.setObjectName("ghbtn")
        to_modify.setToolTip("把当前令牌与密钥带到修改标签，载入后即可编辑声明重签")
        to_modify.clicked.connect(self._send_to_modify)
        copy_header = QPushButton("复制 Header")
        copy_header.setObjectName("ghbtn")
        copy_header.clicked.connect(
            lambda: _copy(self.parse_header_out.toPlainText()))
        copy_payload = QPushButton("复制 Payload")
        copy_payload.setObjectName("ghbtn")
        copy_payload.clicked.connect(
            lambda: _copy(self.parse_payload_out.toPlainText()))
        out_btns.addWidget(to_modify)
        out_btns.addStretch(1)
        out_btns.addWidget(copy_header)
        out_btns.addWidget(copy_payload)
        right_layout.addLayout(out_btns)

        body.addWidget(right, stretch=1)
        return tab

    # ---- Tab 2：创建 ------------------------------------------------------
    def _build_create_tab(self) -> QWidget:
        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(8, 14, 8, 8)
        layout.setSpacing(8)

        alg_row = QHBoxLayout()
        alg_row.setSpacing(8)
        alg_row.addWidget(self._section("签名算法"))
        self.create_alg = NoWheelComboBox()
        for alg in jwt_codec.ALL_ALGORITHMS:
            self.create_alg.addItem(jwt_codec.ALGORITHM_LABELS.get(alg, alg), alg)
        self.create_alg.setMinimumWidth(320)
        alg_row.addWidget(self.create_alg)
        alg_row.addStretch(1)
        layout.addLayout(alg_row)

        layout.addWidget(self._section("密钥"))
        self.create_key = _make_io_area(min_height=70)
        self.create_key.setPlaceholderText(
            "HS256 / HS384 / HS512：任意字符串密钥；RS* / ES*：PEM 私钥；none：留空")
        layout.addWidget(self.create_key)

        layout.addWidget(self._section("Header 声明（alg 由上方算法决定，此处置空即可）"))
        self.create_header = _ClaimsEditor()
        self.create_header.set_claims({"typ": "JWT"})
        layout.addWidget(self.create_header)

        layout.addWidget(self._section("Payload 声明（iss / sub / exp 等）"))
        self.create_payload = _ClaimsEditor()
        self._fill_create_template()
        layout.addWidget(self.create_payload)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        create_btn = QPushButton("创建令牌")
        create_btn.setObjectName("ghbtn-primary")
        create_btn.clicked.connect(self._do_create)
        template_btn = QPushButton("填入标准声明模板")
        template_btn.setObjectName("ghbtn")
        template_btn.setToolTip("重置为 iss / sub / aud / iat / exp 模板（时间自动填当前值）")
        template_btn.clicked.connect(self._fill_create_template)
        clear_btn = QPushButton("清空声明")
        clear_btn.setObjectName("ghbtn")
        clear_btn.clicked.connect(
            lambda: (self.create_header.clear(), self.create_payload.clear()))
        copy_btn = QPushButton("复制令牌")
        copy_btn.setObjectName("ghbtn")
        copy_btn.clicked.connect(lambda: _copy(self.create_token_out.toPlainText()))
        buttons.addWidget(create_btn)
        buttons.addWidget(template_btn)
        buttons.addWidget(clear_btn)
        buttons.addStretch(1)
        buttons.addWidget(copy_btn)
        layout.addLayout(buttons)

        layout.addWidget(self._section("生成结果"))
        self.create_token_out = _make_io_area(readonly=True, min_height=80)
        self.create_token_out.setPlaceholderText("点击「创建令牌」后在此显示结果…")
        layout.addWidget(self.create_token_out)

        self.create_status = _make_status_label()
        layout.addWidget(self.create_status)
        layout.addStretch(1)

        return self._wrap_scroll(inner)

    # ---- Tab 3：修改 / 重签 ----------------------------------------------
    def _build_edit_tab(self) -> QWidget:
        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(8, 14, 8, 8)
        layout.setSpacing(8)

        layout.addWidget(self._section("待修改的 JWT 令牌"))
        self.edit_token = _make_io_area(min_height=80)
        self.edit_token.setPlaceholderText("粘贴要修改的 JWT，点击下方「载入令牌」…")
        layout.addWidget(self.edit_token)

        load_row = QHBoxLayout()
        load_row.setSpacing(8)
        load_btn = QPushButton("载入令牌")
        load_btn.setObjectName("ghbtn-primary")
        load_btn.clicked.connect(self._do_load)
        load_row.addWidget(load_btn)
        load_row.addStretch(1)
        layout.addLayout(load_row)

        alg_row = QHBoxLayout()
        alg_row.setSpacing(8)
        alg_row.addWidget(self._section("重签算法"))
        self.edit_alg = NoWheelComboBox()
        self.edit_alg.addItem("沿用原令牌算法", None)
        for alg in jwt_codec.ALL_ALGORITHMS:
            self.edit_alg.addItem(jwt_codec.ALGORITHM_LABELS.get(alg, alg), alg)
        self.edit_alg.setMinimumWidth(320)
        alg_row.addWidget(self.edit_alg)
        alg_row.addStretch(1)
        layout.addLayout(alg_row)

        layout.addWidget(self._section("密钥（重签签名用）"))
        self.edit_key = _make_io_area(min_height=70)
        self.edit_key.setPlaceholderText(
            "HS*：新 HMAC 字符串密钥；RS* / ES*：PEM 私钥；none：留空")
        layout.addWidget(self.edit_key)

        layout.addWidget(self._section("Header 声明（载入后可编辑）"))
        self.edit_header = _ClaimsEditor()
        layout.addWidget(self.edit_header)

        layout.addWidget(self._section("Payload 声明（载入后可增删改，如 role -> admin）"))
        self.edit_payload = _ClaimsEditor()
        layout.addWidget(self.edit_payload)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        resign_btn = QPushButton("修改并重签")
        resign_btn.setObjectName("ghbtn-primary")
        resign_btn.clicked.connect(self._do_resign)
        copy_btn = QPushButton("复制新令牌")
        copy_btn.setObjectName("ghbtn")
        copy_btn.clicked.connect(lambda: _copy(self.edit_token_out.toPlainText()))
        buttons.addWidget(resign_btn)
        buttons.addWidget(copy_btn)
        buttons.addStretch(1)
        layout.addLayout(buttons)

        layout.addWidget(self._section("新令牌"))
        self.edit_token_out = _make_io_area(readonly=True, min_height=80)
        self.edit_token_out.setPlaceholderText("修改声明后点击「修改并重签」在此显示结果…")
        layout.addWidget(self.edit_token_out)

        self.edit_status = _make_status_label()
        layout.addWidget(self.edit_status)
        layout.addStretch(1)

        return self._wrap_scroll(inner)

    # ---- Tab 4：攻击 ------------------------------------------------------
    def _build_attack_tab(self) -> QWidget:
        tab = QWidget()
        body = QHBoxLayout(tab)
        body.setContentsMargins(8, 14, 8, 8)
        body.setSpacing(16)

        # -- 左栏：三个攻击的输入区（参照「解析 / 校验」标签的左栏） --
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(10)
        left.setFixedWidth(460)

        # 攻击一：HS256 弱密钥爆破
        left_layout.addWidget(self._section("HS256 弱密钥爆破"))
        left_layout.addWidget(self._section("目标 JWT 令牌"))
        self.atk_token = _make_io_area(min_height=56)
        self.atk_token.setPlaceholderText("粘贴 HS256/HS384/HS512 令牌…")
        left_layout.addWidget(self.atk_token)

        left_layout.addWidget(self._section("候选密钥（每行一个，可选）"))
        self.atk_candidates = _make_io_area(min_height=66)
        self.atk_candidates.setPlaceholderText(
            "secret\nadmin\npassword\n123456\n…")
        left_layout.addWidget(self.atk_candidates)

        dict_row = QHBoxLayout()
        dict_row.setSpacing(8)
        choose_dict = QPushButton("选择字典文件…")
        choose_dict.setObjectName("ghbtn")
        choose_dict.clicked.connect(self._choose_dict)
        dict_row.addWidget(choose_dict)
        self.atk_dict_path = QLineEdit()
        self.atk_dict_path.setReadOnly(True)
        self.atk_dict_path.setPlaceholderText("可选字典，如 dict/3306/常用密码.dict")
        dict_row.addWidget(self.atk_dict_path, stretch=1)
        left_layout.addLayout(dict_row)

        self.atk_brute_btn = QPushButton("开始爆破")
        self.atk_brute_btn.setObjectName("ghbtn-primary")
        self.atk_brute_btn.clicked.connect(self._do_brute)
        self.atk_stop_btn = QPushButton("停止")
        self.atk_stop_btn.setObjectName("ghbtn")
        self.atk_stop_btn.setEnabled(False)
        self.atk_stop_btn.clicked.connect(self._stop_brute)
        btn1 = QHBoxLayout()
        btn1.addWidget(self.atk_brute_btn)
        btn1.addWidget(self.atk_stop_btn)
        btn1.addStretch(1)
        left_layout.addLayout(btn1)

        # 攻击二：RS256→HS256 混淆
        left_layout.addWidget(self._section("RS256→HS256 算法混淆"))
        left_layout.addWidget(self._section("要伪造的 Payload（JSON）"))
        self.atk_confusion_payload = _make_io_area(min_height=56)
        self.atk_confusion_payload.setPlainText('{"role": "admin"}')
        left_layout.addWidget(self.atk_confusion_payload)

        left_layout.addWidget(self._section("RSA 公钥 PEM（会被当作 HMAC 密钥）"))
        self.atk_confusion_pub = _make_io_area(min_height=76)
        self.atk_confusion_pub.setPlaceholderText(
            "-----BEGIN PUBLIC KEY-----\n…\n-----END PUBLIC KEY-----")
        left_layout.addWidget(self.atk_confusion_pub)

        confusion_row = QHBoxLayout()
        confusion_row.setSpacing(8)
        self.atk_confusion_alg = NoWheelComboBox()
        for alg in ("HS256", "HS384", "HS512"):
            self.atk_confusion_alg.addItem(alg, alg)
        self.atk_confusion_alg.setFixedWidth(120)
        confusion_row.addWidget(QLabel("伪造算法"))
        confusion_row.addWidget(self.atk_confusion_alg)
        self.atk_confusion_btn = QPushButton("生成混淆令牌")
        self.atk_confusion_btn.setObjectName("ghbtn")
        self.atk_confusion_btn.clicked.connect(self._do_confusion)
        confusion_row.addWidget(self.atk_confusion_btn)
        confusion_row.addStretch(1)
        left_layout.addLayout(confusion_row)

        # 攻击三：kid / jku 注入
        left_layout.addWidget(self._section("kid / jku 注入"))
        left_layout.addWidget(self._section("原令牌（保留其 Payload）"))
        self.atk_inject_token = _make_io_area(min_height=56)
        self.atk_inject_token.setPlaceholderText("粘贴要注入的 JWT…")
        left_layout.addWidget(self.atk_inject_token)

        inject_fields = QHBoxLayout()
        inject_fields.setSpacing(8)
        inject_fields.addWidget(QLabel("kid"))
        self.atk_kid = QLineEdit()
        self.atk_kid.setPlaceholderText("密钥标识，如 attacker")
        inject_fields.addWidget(self.atk_kid, stretch=1)
        inject_fields.addWidget(QLabel("jku"))
        self.atk_jku = QLineEdit()
        self.atk_jku.setPlaceholderText("JWK Set URL，如 https://evil.com/jwks.json")
        inject_fields.addWidget(self.atk_jku, stretch=1)
        left_layout.addLayout(inject_fields)

        left_layout.addWidget(self._section("重签密钥（HS*：字符串；RS*/ES*：PEM）"))
        self.atk_inject_key = _make_io_area(min_height=48)
        self.atk_inject_key.setPlaceholderText("重签签名用的密钥…")
        left_layout.addWidget(self.atk_inject_key)

        self.atk_inject_btn = QPushButton("注入并重签")
        self.atk_inject_btn.setObjectName("ghbtn")
        self.atk_inject_btn.clicked.connect(self._do_inject)
        btn3 = QHBoxLayout()
        btn3.addWidget(self.atk_inject_btn)
        btn3.addStretch(1)
        left_layout.addLayout(btn3)

        self.atk_status = _make_status_label()
        left_layout.addWidget(self.atk_status)
        left_layout.addStretch(1)

        # 左栏内容多，套滚动区
        left_scroll = QScrollArea()
        left_scroll.setWidgetResizable(True)
        left_scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        left_scroll.setFixedWidth(480)
        left_scroll.setWidget(left)
        body.addWidget(left_scroll)

        # -- 右栏：攻击结果（参照「解析 / 校验」标签的右栏，置顶显眼） --
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(8)

        right_layout.addWidget(self._section("攻击结果"))
        self.atk_output = _make_io_area(readonly=True, min_height=200)
        self.atk_output.setPlaceholderText(
            "攻击结果会显示在这里：爆破命中的密钥与已尝试（Fuzz 过）的密钥、"
            "混淆 / 注入生成的令牌…")
        right_layout.addWidget(self.atk_output, stretch=1)

        out_btns = QHBoxLayout()
        out_btns.setSpacing(8)
        copy_btn = QPushButton("复制结果")
        copy_btn.setObjectName("ghbtn")
        copy_btn.clicked.connect(lambda: _copy(self.atk_output.toPlainText()))
        clear_out_btn = QPushButton("清空结果")
        clear_out_btn.setObjectName("ghbtn")
        clear_out_btn.clicked.connect(self.atk_output.clear)
        out_btns.addStretch(1)
        out_btns.addWidget(copy_btn)
        out_btns.addWidget(clear_out_btn)
        right_layout.addLayout(out_btns)

        body.addWidget(right, stretch=1)
        return tab

    # --------------------------------------------------------- Tab 4：攻击执行
    def _choose_dict(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "选择字典文件", "", "字典文件 (*.dict *.txt);;所有文件 (*)")
        if path:
            self.atk_dict_path.setText(path)

    def _gather_candidates(self) -> list[str]:
        """汇总候选密钥：候选输入框 + 字典文件（如已选）。"""
        candidates = [line.strip() for line in self.atk_candidates.toPlainText().splitlines()
                      if line.strip()]
        dict_path = self.atk_dict_path.text().strip()
        if dict_path:
            try:
                with open(dict_path, "r", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        word = line.strip()
                        if word and word not in candidates:
                            candidates.append(word)
            except OSError as exc:
                raise jwt_codec.JwtError(f"字典文件读取失败：{exc}")
        return candidates

    def _do_brute(self) -> None:
        if self._brute_worker is not None and self._brute_worker.isRunning():
            return
        token = self.atk_token.toPlainText().strip()
        if not token:
            _set_status(self.atk_status, False, "请先粘贴目标 JWT 令牌。")
            return
        try:
            candidates = self._gather_candidates()
        except jwt_codec.JwtError as exc:
            _set_status(self.atk_status, False, str(exc))
            return
        if not candidates:
            _set_status(self.atk_status, False,
                        "请提供候选密钥（输入框或字典文件）。")
            return

        self._last_candidates = candidates
        self.atk_brute_btn.setEnabled(False)
        self.atk_stop_btn.setEnabled(True)
        self.atk_output.clear()
        self.atk_output.appendPlainText(
            f"目标令牌：{token}\n候选密钥共 {len(candidates)} 个，开始爆破…\n")
        _set_status(self.atk_status, None, f"开始爆破（{len(candidates)} 个候选）…")

        self._brute_worker = _BruteWorker(token, candidates, self)
        self._brute_worker.log.connect(
            lambda m: self.atk_output.appendPlainText(m))
        self._brute_worker.done_ok.connect(self._on_brute_done)
        self._brute_worker.done_err.connect(self._on_brute_err)
        self._brute_worker.finished.connect(self._on_brute_finished)
        self._brute_worker.start()

    def _stop_brute(self) -> None:
        if self._brute_worker is not None and self._brute_worker.isRunning():
            self._brute_worker.stop()

    def _on_brute_done(self, found) -> None:
        candidates = getattr(self, "_last_candidates", [])
        if found is None:
            self.atk_output.appendPlainText(
                f"\n爆破结束：已尝试全部 {len(candidates)} 个密钥，未找到匹配。")
            self._append_tried_keys(candidates)
            _set_status(self.atk_status, False,
                        f"爆破结束：未命中（共 {len(candidates)} 个候选）。")
        else:
            # 命中的密钥在 candidates 中的位置（含该密钥本身）
            tried = candidates[:candidates.index(found) + 1] if found in candidates else [found]
            self.atk_output.appendPlainText(f"\n命中密钥：{found}")
            self._append_tried_keys(tried)
            _set_status(self.atk_status, True,
                        f"爆破成功：密钥 = {found}（共尝试 {len(tried)} 个）。")

    def _append_tried_keys(self, keys: list[str]) -> None:
        """把尝试过的密钥列表追加到结果区（超过 500 个截断）。"""
        if not keys:
            return
        self.atk_output.appendPlainText("\n—— 已尝试（Fuzz 过）的密钥 ——")
        shown = keys[:500]
        self.atk_output.appendPlainText("\n".join(shown))
        if len(keys) > 500:
            self.atk_output.appendPlainText(
                f"…（共 {len(keys)} 个，仅显示前 500 个）")

    def _on_brute_err(self, message: str) -> None:
        _set_status(self.atk_status, False, f"爆破失败：{message}")

    def _on_brute_finished(self) -> None:
        self.atk_brute_btn.setEnabled(True)
        self.atk_stop_btn.setEnabled(False)
        self._brute_worker.deleteLater()
        self._brute_worker = None

    def _do_confusion(self) -> None:
        payload_text = self.atk_confusion_payload.toPlainText().strip()
        pub = self.atk_confusion_pub.toPlainText().strip()
        hs_alg = self.atk_confusion_alg.currentData()
        if not payload_text:
            _set_status(self.atk_status, False, "请填写要伪造的 Payload JSON。")
            return
        try:
            payload = json.loads(payload_text)
            if not isinstance(payload, dict):
                raise ValueError("Payload 应为 JSON 对象")
        except (json.JSONDecodeError, ValueError) as exc:
            _set_status(self.atk_status, False, f"Payload 不是合法 JSON 对象：{exc}")
            return
        try:
            token = jwt_codec.alg_confusion_rs_to_hs(payload, pub, hs_alg)
        except jwt_codec.JwtError as exc:
            _set_status(self.atk_status, False, f"混淆失败：{exc}")
            return
        self.atk_output.setPlainText(token)
        _set_status(self.atk_status, True,
                    f"已生成 RS→HS 混淆令牌（alg={hs_alg}，密钥=公钥 PEM）。")

    def _do_inject(self) -> None:
        token = self.atk_inject_token.toPlainText().strip()
        kid = self.atk_kid.text().strip()
        jku = self.atk_jku.text().strip()
        key = self.atk_inject_key.toPlainText().strip()
        if not token:
            _set_status(self.atk_status, False, "请粘贴要注入的原令牌。")
            return
        if not kid and not jku:
            _set_status(self.atk_status, False, "请至少填写 kid 或 jku 之一。")
            return
        extra = {}
        if kid:
            extra["kid"] = kid
        if jku:
            extra["jku"] = jku
        try:
            new_token = jwt_codec.inject_header(token, extra, key or None, None)
        except jwt_codec.JwtError as exc:
            _set_status(self.atk_status, False, f"注入失败：{exc}")
            return
        self.atk_output.setPlainText(new_token)
        _set_status(self.atk_status, True,
                    f"已注入 {', '.join(extra)} 并重签。")

    # -------------------------------------------------------------- 小部件
    @staticmethod
    def _section(text: str) -> QLabel:
        label = QLabel(text)
        label.setObjectName("section")
        return label

    @staticmethod
    def _wrap_scroll(inner: QWidget) -> QScrollArea:
        """创建 / 修改标签内容较多，套滚动区保证小窗口下不挤压。"""
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setWidget(inner)
        return scroll

    def _fill_create_template(self) -> None:
        now = jwt_codec.now_timestamp()
        self.create_payload.set_claims({
            "iss": "example-issuer",
            "sub": "user",
            "aud": "example-audience",
            "iat": now,
            "exp": now + 3600,
        })

    # --------------------------------------------------------- Tab 1：解析
    def _do_parse(self) -> None:
        token = self.parse_token.toPlainText().strip()
        if not token:
            _set_status(self.parse_status, False, "请先粘贴要解析的 JWT 令牌。")
            return
        try:
            info = jwt_codec.parse(token)
        except jwt_codec.JwtError as exc:
            _set_status(self.parse_status, False, f"解析失败：{exc}")
            return

        self.parse_header_out.setPlainText(jwt_codec.pretty(info.header))
        self.parse_payload_out.setPlainText(jwt_codec.pretty(info.payload))
        if info.has_signature:
            self.parse_sig_out.setPlainText(
                f"{info.signature_raw}\n原始签名 {len(info.signature)} 字节")
        else:
            self.parse_sig_out.setPlainText("（空——该令牌未携带签名）")

        # 已识别声明的中文说明（header + payload 里命中的注册声明）
        hints = [f"{k}：{jwt_codec.CLAIM_DESCRIPTIONS[k]}"
                 for k in list(info.header) + list(info.payload)
                 if k in jwt_codec.CLAIM_DESCRIPTIONS]
        self.parse_desc.setText("；".join(hints))

        _set_status(self.parse_status, True,
                    f"解析成功：算法 {info.algorithm or '未标注'}，"
                    f"签名段 {len(info.signature)} 字节。"
                    "填入密钥后可点「校验签名」。")

    def _do_verify(self) -> None:
        token = self.parse_token.toPlainText().strip()
        if not token:
            _set_status(self.parse_status, False, "请先粘贴要校验的 JWT 令牌。")
            return
        try:
            ok = jwt_codec.verify(token, self.parse_key.toPlainText().strip())
        except jwt_codec.JwtError as exc:
            _set_status(self.parse_status, False, f"校验失败：{exc}")
            return
        if ok:
            _set_status(self.parse_status, True, "签名校验通过：签名与密钥匹配。")
        else:
            _set_status(self.parse_status, False,
                        "签名校验不通过：签名与密钥不匹配（或令牌内容被篡改）。")

    def _send_to_modify(self) -> None:
        token = self.parse_token.toPlainText().strip()
        if not token:
            _set_status(self.parse_status, False,
                        "当前没有令牌可转交，请先在本标签解析一个 JWT。")
            return
        self.edit_token.setPlainText(token)
        self.edit_key.setPlainText(self.parse_key.toPlainText())
        self.tabs.setCurrentWidget(self.edit_tab)
        self._do_load()

    # --------------------------------------------------------- Tab 2：创建
    def _do_create(self) -> None:
        alg = self.create_alg.currentData()
        key = self.create_key.toPlainText().strip()
        try:
            token = jwt_codec.create(
                self.create_header.claims(), self.create_payload.claims(),
                key or None, alg)
        except jwt_codec.JwtError as exc:
            _set_status(self.create_status, False, f"创建失败：{exc}")
            return
        self.create_token_out.setPlainText(token)
        _set_status(self.create_status, True,
                    f"已创建令牌（算法 {alg}）。可到「解析 / 校验」标签验证，"
                    "或复制后使用。")

    # ------------------------------------------------------ Tab 3：修改
    def _do_load(self) -> None:
        token = self.edit_token.toPlainText().strip()
        if not token:
            _set_status(self.edit_status, False, "请先粘贴要修改的 JWT 令牌。")
            return
        try:
            info = jwt_codec.parse(token)
        except jwt_codec.JwtError as exc:
            _set_status(self.edit_status, False, f"载入失败：{exc}")
            return
        self.edit_header.set_claims(info.header)
        self.edit_payload.set_claims(info.payload)
        # 「沿用原令牌算法」提示当前将沿用哪个算法
        self.edit_alg.setItemText(0, f"沿用原令牌算法（{info.algorithm or '未标注'}）")
        self.edit_alg.setCurrentIndex(0)
        _set_status(self.edit_status, None,
                    f"已载入：算法 {info.algorithm or '未标注'}，"
                    f"Payload 共 {len(info.payload)} 个声明。修改后点「修改并重签」。")

    def _do_resign(self) -> None:
        header = self.edit_header.claims()
        payload = self.edit_payload.claims()
        override = self.edit_alg.currentData()
        target = override or str(header.get("alg", "") or "HS256")
        key = self.edit_key.toPlainText().strip()
        try:
            token = jwt_codec.create(header, payload, key or None, target)
        except jwt_codec.JwtError as exc:
            _set_status(self.edit_status, False, f"重签失败：{exc}")
            return
        self.edit_token_out.setPlainText(token)
        _set_status(self.edit_status, True,
                    f"已按 {target} 重新签名。填入正确密钥后到「解析 / 校验」"
                    "标签可验证通过。")

    def shutdown(self) -> None:
        """应用退出时调用：停止后台爆破线程。"""
        if self._brute_worker is not None and self._brute_worker.isRunning():
            self._brute_worker.stop()
            self._brute_worker.wait(2000)
