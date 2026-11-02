# -*- coding: utf-8 -*-
"""国密工具页（独立页面）：SM3 摘要 / SM4 对称加解密 / SM2 公钥密码。

三个子标签覆盖国密算法的常见 CTF 用法，算法全部委托 ``lib.gm_codec``
（纯 Python 实现，无第三方依赖），本页不含任何密码学代码：

- SM3 摘要：文本或十六进制输入，输出 64 位十六进制摘要；
- SM4 加解密：ECB / CBC 两种模式，密钥与 IV 支持 Hex / UTF-8 两种录入方式，
  可选 PKCS7 填充，输入 / 输出均可在「文本」与「十六进制」间切换；
- SM2：一键生成密钥对（或由私钥推导公钥），支持加密 / 解密（C1C3C2 与
  C1C2C3 两种密文排列）与签名 / 验签（SM3 摘要，可自定义用户标识 ID）。

耗时的椭圆曲线运算放后台线程执行，避免大输入时界面卡顿。
"""

from __future__ import annotations

import os

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
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
from lib import gm_codec

#: 密钥 / 输入内容的录入格式选项（值 -> 显示名）
FMT_CHOICES = (("text", "文本（UTF-8）"), ("hex", "十六进制"))

#: SM2 密文排列顺序选项
SM2_MODE_CHOICES = (
    (gm_codec.MODE_C1C3C2, "C1C3C2（新标准）"),
    (gm_codec.MODE_C1C2C3, "C1C2C3（旧标准）"),
)


class _GmWorker(QThread):
    """后台执行一次国密运算，结果经 ``done`` 信号回传（payload / 错误文案）。"""

    #: (结果字符串, 错误文案)；二者必有其一为空
    done = Signal(object, str)

    def __init__(self, fn, parent=None) -> None:
        super().__init__(parent)
        self._fn = fn

    def run(self) -> None:  # noqa: D102  线程体
        try:
            result = self._fn()
        except Exception as exc:  # noqa: BLE001  统一转信号给界面
            self.done.emit(None, str(exc))
        else:
            self.done.emit(result, "")


def _make_io_area(readonly: bool = False, min_height: int = 96) -> QPlainTextEdit:
    area = QPlainTextEdit()
    area.setObjectName("io")
    area.setReadOnly(readonly)
    area.setMinimumHeight(min_height)
    return area


def _copy(text: str) -> None:
    if text:
        QApplication.clipboard().setText(text)


class GmPage(QWidget):
    """国密工具页：SM3 / SM4 / SM2 三个子标签。"""

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        #: 正在运行的后台任务（允许并发，结束后移除）
        self._workers: set = set()
        self._build()

    # ------------------------------------------------------------------ UI
    def _build(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(10)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_sm3_tab(), "SM3 摘要")
        self.tabs.addTab(self._build_sm4_tab(), "SM4 加解密")
        self.tabs.addTab(self._build_sm2_tab(), "SM2 公钥密码")
        layout.addWidget(self.tabs, stretch=1)

    # ---- Tab 1：SM3 -------------------------------------------------------
    def _build_sm3_tab(self) -> QWidget:
        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(8, 14, 8, 8)
        layout.setSpacing(8)

        fmt_row = QHBoxLayout()
        fmt_row.setSpacing(8)
        fmt_row.addWidget(self._section("输入格式"))
        self.sm3_in_fmt = NoWheelComboBox()
        for value, text in FMT_CHOICES:
            self.sm3_in_fmt.addItem(text, value)
        self.sm3_in_fmt.setFixedWidth(160)
        fmt_row.addWidget(self.sm3_in_fmt)
        fmt_row.addStretch(1)
        layout.addLayout(fmt_row)

        layout.addWidget(self._section("待计算内容"))
        self.sm3_input = _make_io_area(min_height=140)
        self.sm3_input.setPlaceholderText("输入要计算 SM3 摘要的文本，或十六进制数据…")
        layout.addWidget(self.sm3_input, stretch=1)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        run_btn = QPushButton("计算 SM3 摘要")
        run_btn.setObjectName("ghbtn-primary")
        run_btn.clicked.connect(self._do_sm3)
        clear_btn = QPushButton("清空")
        clear_btn.setObjectName("ghbtn")
        clear_btn.clicked.connect(
            lambda: (self.sm3_input.clear(), self.sm3_output.clear(),
                     _set_status(self.sm3_status, None, "")))
        copy_btn = QPushButton("复制摘要")
        copy_btn.setObjectName("ghbtn")
        copy_btn.clicked.connect(lambda: _copy(self.sm3_output.toPlainText()))
        buttons.addWidget(run_btn)
        buttons.addWidget(clear_btn)
        buttons.addStretch(1)
        buttons.addWidget(copy_btn)
        layout.addLayout(buttons)

        layout.addWidget(self._section("SM3 摘要（64 位十六进制）"))
        self.sm3_output = _make_io_area(readonly=True, min_height=64)
        layout.addWidget(self.sm3_output)

        self.sm3_status = _make_status_label()
        layout.addWidget(self.sm3_status)
        return self._wrap_scroll(inner)

    # ---- Tab 2：SM4 -------------------------------------------------------
    def _build_sm4_tab(self) -> QWidget:
        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(8, 14, 8, 8)
        layout.setSpacing(8)

        # -- 密钥 --
        key_row = QHBoxLayout()
        key_row.setSpacing(8)
        key_row.addWidget(self._section("密钥（16 字节）"))
        self.sm4_key = QLineEdit()
        self.sm4_key.setPlaceholderText("32 位十六进制，或 16 个 UTF-8 字符")
        key_row.addWidget(self.sm4_key, stretch=1)
        self.sm4_key_fmt = NoWheelComboBox()
        for value, text in FMT_CHOICES:
            self.sm4_key_fmt.addItem(text, value)
        self.sm4_key_fmt.setFixedWidth(150)
        key_row.addWidget(self.sm4_key_fmt)
        gen_key_btn = QPushButton("随机密钥")
        gen_key_btn.setObjectName("ghbtn")
        gen_key_btn.setToolTip("生成 16 字节随机密钥（以十六进制填入）")
        gen_key_btn.clicked.connect(self._gen_sm4_key)
        key_row.addWidget(gen_key_btn)
        layout.addLayout(key_row)

        # -- 模式 / IV / 填充 --
        opt_row = QHBoxLayout()
        opt_row.setSpacing(8)
        opt_row.addWidget(self._section("模式"))
        self.sm4_mode = NoWheelComboBox()
        self.sm4_mode.addItem("ECB", "ECB")
        self.sm4_mode.addItem("CBC", "CBC")
        self.sm4_mode.setFixedWidth(100)
        self.sm4_mode.currentIndexChanged.connect(self._sync_sm4_iv)
        opt_row.addWidget(self.sm4_mode)

        opt_row.addWidget(self._section("IV（CBC 用，16 字节）"))
        self.sm4_iv = QLineEdit()
        self.sm4_iv.setPlaceholderText("32 位十六进制，或 16 个 UTF-8 字符")
        opt_row.addWidget(self.sm4_iv, stretch=1)

        self.sm4_padding = QCheckBox("PKCS7 填充")
        self.sm4_padding.setChecked(True)
        opt_row.addWidget(self.sm4_padding)
        layout.addLayout(opt_row)

        # -- 输入 / 输出格式 --
        fmt_row = QHBoxLayout()
        fmt_row.setSpacing(8)
        fmt_row.addWidget(self._section("输入格式"))
        self.sm4_in_fmt = NoWheelComboBox()
        for value, text in FMT_CHOICES:
            self.sm4_in_fmt.addItem(text, value)
        self.sm4_in_fmt.setFixedWidth(160)
        fmt_row.addWidget(self.sm4_in_fmt)

        fmt_row.addWidget(self._section("输出格式"))
        self.sm4_out_fmt = NoWheelComboBox()
        for value, text in FMT_CHOICES:
            self.sm4_out_fmt.addItem(text, value)
        self.sm4_out_fmt.setCurrentIndex(1)  # 默认十六进制
        self.sm4_out_fmt.setFixedWidth(160)
        fmt_row.addWidget(self.sm4_out_fmt)
        fmt_row.addStretch(1)
        layout.addLayout(fmt_row)

        layout.addWidget(self._section("输入"))
        self.sm4_input = _make_io_area(min_height=110)
        self.sm4_input.setPlaceholderText("待加密的明文，或待解密的密文…")
        layout.addWidget(self.sm4_input, stretch=1)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        enc_btn = QPushButton("SM4 加密")
        enc_btn.setObjectName("ghbtn-primary")
        enc_btn.clicked.connect(lambda: self._do_sm4(True))
        dec_btn = QPushButton("SM4 解密")
        dec_btn.setObjectName("ghbtn")
        dec_btn.clicked.connect(lambda: self._do_sm4(False))
        clear_btn = QPushButton("清空")
        clear_btn.setObjectName("ghbtn")
        clear_btn.clicked.connect(
            lambda: (self.sm4_input.clear(), self.sm4_output.clear(),
                     _set_status(self.sm4_status, None, "")))
        copy_btn = QPushButton("复制结果")
        copy_btn.setObjectName("ghbtn")
        copy_btn.clicked.connect(lambda: _copy(self.sm4_output.toPlainText()))
        buttons.addWidget(enc_btn)
        buttons.addWidget(dec_btn)
        buttons.addWidget(clear_btn)
        buttons.addStretch(1)
        buttons.addWidget(copy_btn)
        layout.addLayout(buttons)

        layout.addWidget(self._section("输出"))
        self.sm4_output = _make_io_area(readonly=True, min_height=110)
        layout.addWidget(self.sm4_output, stretch=1)

        self.sm4_status = _make_status_label()
        layout.addWidget(self.sm4_status)
        self._sync_sm4_iv()
        return self._wrap_scroll(inner)

    # ---- Tab 3：SM2 -------------------------------------------------------
    def _build_sm2_tab(self) -> QWidget:
        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(8, 14, 8, 8)
        layout.setSpacing(8)

        # -- 密钥对 --
        key_head = QHBoxLayout()
        key_head.setSpacing(8)
        key_head.addWidget(self._section("SM2 密钥对"))
        key_head.addStretch(1)
        gen_btn = QPushButton("生成密钥对")
        gen_btn.setObjectName("ghbtn-primary")
        gen_btn.clicked.connect(self._gen_sm2_keypair)
        derive_btn = QPushButton("由私钥推导公钥")
        derive_btn.setObjectName("ghbtn")
        derive_btn.setToolTip("根据私钥重新计算公钥，校验两者是否匹配")
        derive_btn.clicked.connect(self._derive_sm2_pub)
        key_head.addWidget(gen_btn)
        key_head.addWidget(derive_btn)
        layout.addLayout(key_head)

        priv_row = QHBoxLayout()
        priv_row.setSpacing(8)
        priv_row.addWidget(self._section("私钥"))
        self.sm2_priv = QLineEdit()
        self.sm2_priv.setPlaceholderText("64 位十六进制私钥")
        priv_row.addWidget(self.sm2_priv, stretch=1)
        layout.addLayout(priv_row)

        pub_row = QHBoxLayout()
        pub_row.setSpacing(8)
        pub_row.addWidget(self._section("公钥"))
        self.sm2_pub = QLineEdit()
        self.sm2_pub.setPlaceholderText("128 位十六进制公钥（x||y，可带 04 前缀）")
        pub_row.addWidget(self.sm2_pub, stretch=1)
        layout.addLayout(pub_row)

        # -- 选项：密文模式 / 用户标识 --
        opt_row = QHBoxLayout()
        opt_row.setSpacing(8)
        opt_row.addWidget(self._section("密文排列"))
        self.sm2_mode = NoWheelComboBox()
        for value, text in SM2_MODE_CHOICES:
            self.sm2_mode.addItem(text, value)
        self.sm2_mode.setFixedWidth(190)
        opt_row.addWidget(self.sm2_mode)

        opt_row.addWidget(self._section("用户标识 ID（签名用）"))
        self.sm2_user_id = QLineEdit(gm_codec.DEFAULT_USER_ID.decode("ascii"))
        self.sm2_user_id.setPlaceholderText("默认 1234567812345678")
        opt_row.addWidget(self.sm2_user_id, stretch=1)
        layout.addLayout(opt_row)

        # -- 消息 / 密文（签名）--
        layout.addWidget(self._section("消息 / 明文（加密、签名、验签的输入）"))
        self.sm2_message = _make_io_area(min_height=90)
        self.sm2_message.setPlaceholderText("要加密或签名的消息…")
        layout.addWidget(self.sm2_message, stretch=1)

        layout.addWidget(self._section("密文 / 签名（解密、验签的输入；加密、签名的输出）"))
        self.sm2_blob = _make_io_area(min_height=90)
        self.sm2_blob.setPlaceholderText("十六进制密文，或 128 位十六进制签名…")
        layout.addWidget(self.sm2_blob, stretch=1)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        enc_btn = QPushButton("加密")
        enc_btn.setObjectName("ghbtn-primary")
        enc_btn.clicked.connect(lambda: self._do_sm2("encrypt"))
        dec_btn = QPushButton("解密")
        dec_btn.setObjectName("ghbtn")
        dec_btn.clicked.connect(lambda: self._do_sm2("decrypt"))
        sign_btn = QPushButton("签名")
        sign_btn.setObjectName("ghbtn")
        sign_btn.clicked.connect(lambda: self._do_sm2("sign"))
        verify_btn = QPushButton("验签")
        verify_btn.setObjectName("ghbtn")
        verify_btn.clicked.connect(lambda: self._do_sm2("verify"))
        clear_btn = QPushButton("清空")
        clear_btn.setObjectName("ghbtn")
        clear_btn.clicked.connect(
            lambda: (self.sm2_message.clear(), self.sm2_blob.clear(),
                     _set_status(self.sm2_status, None, "")))
        buttons.addWidget(enc_btn)
        buttons.addWidget(dec_btn)
        buttons.addWidget(sign_btn)
        buttons.addWidget(verify_btn)
        buttons.addWidget(clear_btn)
        buttons.addStretch(1)
        layout.addLayout(buttons)

        self.sm2_status = _make_status_label()
        layout.addWidget(self.sm2_status)
        return self._wrap_scroll(inner)

    # -------------------------------------------------------------- 小部件
    @staticmethod
    def _section(text: str) -> QLabel:
        label = QLabel(text)
        label.setObjectName("section")
        return label

    @staticmethod
    def _wrap_scroll(inner: QWidget) -> QScrollArea:
        """内容较多，套滚动区保证小窗口下不被挤压。"""
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setWidget(inner)
        return scroll

    def _sync_sm4_iv(self) -> None:
        """ECB 模式不需要 IV，禁用 IV 输入框。"""
        is_cbc = self.sm4_mode.currentData() == "CBC"
        self.sm4_iv.setEnabled(is_cbc)
        self.sm4_iv.setPlaceholderText(
            "32 位十六进制，或 16 个 UTF-8 字符"
            if is_cbc else "ECB 模式无需 IV")

    # ------------------------------------------------------------ 输入解析
    @staticmethod
    def _text_to_bytes(text: str, fmt: str) -> bytes:
        if fmt == "hex":
            return gm_codec.parse_hex(text)
        return text.encode("utf-8")

    @staticmethod
    def _bytes_to_text(data: bytes, fmt: str) -> str:
        if fmt == "hex":
            return data.hex()
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return data.hex()

    # -------------------------------------------------------------- 后台执行
    def _run_async(self, fn, on_ok) -> None:
        """在后台线程执行 ``fn``，完成后调用 ``on_ok(payload, err)``。

        允许并发：每个操作各起一个线程并登记到 ``self._workers``，结束后移除。
        这样即便上一个操作尚未结束，新点击也不会被静默丢弃（各自读写独立的
        输入快照，结果以最后写入者为准）。
        """
        worker = _GmWorker(fn, self)
        worker.done.connect(
            lambda payload, err: self._on_worker_done(payload, err, on_ok))
        worker.finished.connect(lambda w=worker: self._on_worker_finished(w))
        self._workers.add(worker)
        worker.start()

    def _on_worker_done(self, payload, err: str, on_ok) -> None:
        if err:
            on_ok(None, err)
        else:
            on_ok(payload, "")

    def _on_worker_finished(self, worker: _GmWorker) -> None:
        self._workers.discard(worker)
        worker.deleteLater()

    # ------------------------------------------------------------ SM3 执行
    def _do_sm3(self) -> None:
        text = self.sm3_input.toPlainText()
        if not text:
            _set_status(self.sm3_status, False, "请先输入要计算摘要的内容。")
            return
        fmt = self.sm3_in_fmt.currentData()

        def task():
            data = self._text_to_bytes(text, fmt)
            return gm_codec.sm3_hex(data), len(data)

        def done(payload, err):
            if err:
                _set_status(self.sm3_status, False, f"SM3 计算失败：{err}")
                return
            digest, size = payload
            self.sm3_output.setPlainText(digest)
            _set_status(self.sm3_status, True,
                        f"SM3 摘要计算完成（输入 {size} 字节，输出 32 字节）。")

        _set_status(self.sm3_status, None, "正在计算 SM3 摘要…")
        self._run_async(task, done)

    # ------------------------------------------------------------ SM4 执行
    def _gen_sm4_key(self) -> None:
        self.sm4_key_fmt.setCurrentIndex(
            [v for v, _ in FMT_CHOICES].index("hex"))
        self.sm4_key.setText(os.urandom(16).hex())
        _set_status(self.sm4_status, None, "已生成 16 字节随机密钥（十六进制）。")

    def _do_sm4(self, encrypt: bool) -> None:
        text = self.sm4_input.toPlainText()
        if not text:
            _set_status(self.sm4_status, False, "请先输入待处理的内容。")
            return
        key_fmt = self.sm4_key_fmt.currentData()
        in_fmt = self.sm4_in_fmt.currentData()
        out_fmt = self.sm4_out_fmt.currentData()
        mode = self.sm4_mode.currentData()
        padding = self.sm4_padding.isChecked()
        key_text = self.sm4_key.text()
        iv_text = self.sm4_iv.text()

        def task():
            key = self._text_to_bytes(key_text, key_fmt)
            data = self._text_to_bytes(text, in_fmt)
            if encrypt:
                if mode == "CBC":
                    iv = self._text_to_bytes(iv_text, key_fmt)
                    return gm_codec.sm4_cbc_encrypt(data, key, iv, padding)
                return gm_codec.sm4_ecb_encrypt(data, key, padding)
            if mode == "CBC":
                iv = self._text_to_bytes(iv_text, key_fmt)
                return gm_codec.sm4_cbc_decrypt(data, key, iv, padding)
            return gm_codec.sm4_ecb_decrypt(data, key, padding)

        def done(payload, err):
            if err:
                _set_status(self.sm4_status, False,
                            f"SM4 {'加密' if encrypt else '解密'}失败：{err}")
                return
            out = self._bytes_to_text(payload, out_fmt)
            self.sm4_output.setPlainText(out)
            _set_status(self.sm4_status, True,
                        f"SM4-{mode} {'加密' if encrypt else '解密'}完成"
                        f"（输出 {len(payload)} 字节）。")

        _set_status(self.sm4_status, None,
                    f"正在执行 SM4-{mode} {'加密' if encrypt else '解密'}…")
        self._run_async(task, done)

    # ------------------------------------------------------------ SM2 执行
    def _gen_sm2_keypair(self) -> None:
        priv, pub = gm_codec.sm2_generate_keypair()
        self.sm2_priv.setText(priv)
        self.sm2_pub.setText(pub)
        _set_status(self.sm2_status, None, "已生成新的 SM2 密钥对。")

    def _derive_sm2_pub(self) -> None:
        priv = self.sm2_priv.text().strip()
        if not priv:
            _set_status(self.sm2_status, False, "请先填写私钥。")
            return
        try:
            pub = gm_codec.sm2_public_from_private(priv)
        except gm_codec.GmError as exc:
            _set_status(self.sm2_status, False, f"推导失败：{exc}")
            return
        self.sm2_pub.setText(pub)
        _set_status(self.sm2_status, True, "已由私钥推导出公钥。")

    def _do_sm2(self, action: str) -> None:
        priv = self.sm2_priv.text().strip()
        pub = self.sm2_pub.text().strip()
        mode = self.sm2_mode.currentData()
        user_id = self.sm2_user_id.text().encode("utf-8") or gm_codec.DEFAULT_USER_ID
        message = self.sm2_message.toPlainText()
        blob = self.sm2_blob.toPlainText().strip()

        if action == "encrypt":
            if not pub or not message:
                _set_status(self.sm2_status, False, "加密需要公钥与消息。")
                return
        elif action == "decrypt":
            if not priv or not blob:
                _set_status(self.sm2_status, False, "解密需要私钥与密文。")
                return
        elif action == "sign":
            if not priv or not message:
                _set_status(self.sm2_status, False, "签名需要私钥与消息。")
                return
        else:  # verify
            if not pub or not message or not blob:
                _set_status(self.sm2_status, False, "验签需要公钥、消息与签名。")
                return

        def task():
            if action == "encrypt":
                return "blob", gm_codec.sm2_encrypt(
                    message.encode("utf-8"), pub, mode).hex()
            if action == "decrypt":
                return "message", gm_codec.sm2_decrypt(
                    gm_codec.parse_hex(blob), priv, mode).decode("utf-8", "replace")
            if action == "sign":
                return "blob", gm_codec.sm2_sign(
                    message.encode("utf-8"), priv, pub, user_id)
            return "verify", gm_codec.sm2_verify(
                message.encode("utf-8"), blob, pub, user_id)

        def done(payload, err):
            if err:
                _set_status(self.sm2_status, False, f"SM2 操作失败：{err}")
                return
            target, value = payload
            if target == "verify":
                if value:
                    _set_status(self.sm2_status, True, "验签通过：签名有效。")
                else:
                    _set_status(self.sm2_status, False,
                                "验签不通过：签名无效或消息被篡改。")
            elif target == "blob":
                self.sm2_blob.setPlainText(value)
                _set_status(self.sm2_status, True,
                            f"SM2 {'加密' if action == 'encrypt' else '签名'}完成。")
            else:  # message：解密结果写回消息框
                self.sm2_message.setPlainText(value)
                _set_status(self.sm2_status, True, "SM2 解密完成。")

        _set_status(self.sm2_status, None, "正在执行 SM2 运算…")
        self._run_async(task, done)

    # ------------------------------------------------------------ 生命周期
    def shutdown(self) -> None:
        """应用退出时调用：等待后台线程收尾。"""
        for worker in list(self._workers):
            if worker.isRunning():
                worker.wait(3000)


# ---------------------------------------------------------------------------
# 状态行辅助（与 jwt_page 保持一致的三态样式）
# ---------------------------------------------------------------------------
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
