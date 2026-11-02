# -*- coding: utf-8 -*-
"""baseX 工具页：把全部 Base 系列编解码收拢到一个工具，标签页切换。

覆盖 Base64 / URLSafe Base64 / Base32 / Base16 / Base58 / Base62 / Base85 /
Base91 / Base92 / UUencode / XXencode 共 11 个子工具，算法全部委托
``lib.base_codec``（纯 Python 实现，无第三方依赖），本页不含任何编解码代码。

每个子标签复用 :class:`app.widgets.codec_panel.CodecPanel`（输入 / 输出双区 +
复制 / 用作输入 / 粘贴），加「编码」「解码」两个按钮；Base85 额外提供
变体下拉（RFC 1924 b85 / Adobe Ascii85 a85）。

设计约定
--------
- 原 11 个独立的 base 工具（``base64`` / ``base32`` …）已从注册表移除，
  统一由本页承载；「密码 Fuzz」通过 ``ToolSpec.fuzz`` 显式声明参与
  （见 :func:`lib.basex_fuzz.fuzz_basex`），保证一键 Fuzz 仍能解出 Base 系列密文。
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from app.widgets.codec_panel import CodecPanel
from app.widgets.no_wheel import NoWheelComboBox
from lib import base_codec


#: Base 子工具定义：(子标签名, 编码函数, 解码函数, 是否带 variant 参数)
#: variant 参数仅 Base85 需要（b85 / a85 两种变体）。
_BASE_TOOLS: tuple[tuple[str, callable, callable, bool], ...] = (
    ("Base64", base_codec.base64_encrypt, base_codec.base64_decrypt, False),
    ("URLSafe Base64", base_codec.base64_urlsafe_encrypt,
     base_codec.base64_urlsafe_decrypt, False),
    ("Base32", base_codec.base32_encrypt, base_codec.base32_decrypt, False),
    ("Base16", base_codec.base16_encrypt, base_codec.base16_decrypt, False),
    ("Base58", base_codec.base58_encrypt, base_codec.base58_decrypt, False),
    ("Base62", base_codec.base62_encrypt, base_codec.base62_decrypt, False),
    ("Base85", base_codec.base85_encrypt, base_codec.base85_decrypt, True),
    ("Base91", base_codec.base91_encrypt, base_codec.base91_decrypt, False),
    ("Base92", base_codec.base92_encrypt, base_codec.base92_decrypt, False),
    ("UUencode", base_codec.uuencode_encrypt, base_codec.uuencode_decrypt, False),
    ("XXencode", base_codec.xxencode_encrypt, base_codec.xxencode_decrypt, False),
)

#: Base85 变体选项
_B85_VARIANTS = (("b85", "RFC 1924 / Git"), ("a85", "Adobe Ascii85"))


class _BaseSubPanel(QWidget):
    """单个 Base 子工具面板：CodecPanel + 编码/解码按钮（Base85 带变体下拉）。"""

    def __init__(self, theme, name: str, enc, dec, has_variant: bool,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._enc = enc
        self._dec = dec
        self._has_variant = has_variant
        self._build(theme)

    def _build(self, theme) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 12, 8, 8)
        layout.setSpacing(10)

        # -- 操作按钮行（含 Base85 变体下拉） --
        actions = QHBoxLayout()
        actions.setSpacing(8)
        self.enc_btn = QPushButton("编码")
        self.enc_btn.setObjectName("ghbtn-primary")
        self.enc_btn.clicked.connect(self._do_enc)
        actions.addWidget(self.enc_btn)
        self.dec_btn = QPushButton("解码")
        self.dec_btn.setObjectName("ghbtn")
        self.dec_btn.clicked.connect(self._do_dec)
        actions.addWidget(self.dec_btn)

        if self._has_variant:
            actions.addSpacing(8)
            actions.addWidget(QLabel("Base85 变体"))
            self.variant_combo = NoWheelComboBox()
            for value, text in _B85_VARIANTS:
                self.variant_combo.addItem(text, value)
            self.variant_combo.setFixedWidth(180)
            actions.addWidget(self.variant_combo)
        actions.addStretch(1)
        layout.addLayout(actions)

        # -- 输入 / 输出面板 --
        self.panel = CodecPanel(theme)
        layout.addWidget(self.panel, stretch=1)

        self._status = QLabel("")
        self._status.setObjectName("status-info")
        self._status.setWordWrap(True)
        layout.addWidget(self._status)

    # ------------------------------------------------------------------ 操作
    def _run(self, fn, action: str) -> None:
        data = self.panel.get_input()
        if not data.strip():
            self._set_status(False, f"请先在输入框填写要{action}的内容。")
            return
        try:
            if self._has_variant:
                variant = self.variant_combo.currentData()
                result = fn(data, variant)
            else:
                result = fn(data)
        except Exception as exc:  # noqa: BLE001  界面兜底
            self._set_status(False, f"{action}失败：{exc}")
            return
        self.panel.set_output(result)
        self._set_status(True, f"{action}完成。")

    def _do_enc(self) -> None:
        self._run(self._enc, "编码")

    def _do_dec(self) -> None:
        self._run(self._dec, "解码")

    def _set_status(self, ok: bool, text: str) -> None:
        self._status.setText(text)
        self._status.setObjectName("status-ok" if ok else "status-err")
        self._status.style().unpolish(self._status)
        self._status.style().polish(self._status)


class BasexPage(QWidget):
    """baseX 工具页：全部 Base 系列编解码，标签页切换。"""

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._sub_panels: list[_BaseSubPanel] = []
        self._build()

    # ------------------------------------------------------------------ UI
    def _build(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(10)

        self.tabs = QTabWidget()
        for name, enc, dec, has_variant in _BASE_TOOLS:
            panel = _BaseSubPanel(self.theme, name, enc, dec, has_variant)
            self._sub_panels.append(panel)
            self.tabs.addTab(panel, name)
        layout.addWidget(self.tabs, stretch=1)

    # ------------------------------------------------------------------ 主题
    def set_theme(self, palette) -> None:
        self.theme = palette
        for panel in self._sub_panels:
            panel.panel.theme = palette

    # ------------------------------------------------------------------ 生命周期
    def shutdown(self) -> None:
        """baseX 无后台线程，退出前无需额外清理。"""
