# -*- coding: utf-8 -*-
"""实体编码工具页：把双向字符串编码工具收拢到一个工具，标签页切换。

覆盖 HTML 实体 / Unicode 转义 / Quoted-printable / GBK·UTF-16 互转共 4 个
子工具，算法全部委托 ``lib.string_codec``，本页不含任何编解码代码。

每个子标签复用 :class:`app.widgets.codec_panel.CodecPanel`，加「编码」「解码」
两个按钮（这 4 个工具都是双向的）。

设计约定
--------
- 原 4 个独立的双向字符串工具（``html_entity`` / ``unicode_escape`` /
  ``quoted_printable`` / ``gbk_utf16``）已从注册表移除，统一由本页承载；
- 这些工具原为 ``KIND_TWO_WAY``（靠 ``dec`` 自动参与「密码 Fuzz」），收拢后
  通过 ``ToolSpec.fuzz`` 显式声明参与（见 :func:`lib.string_fuzz.fuzz_entity`），
  保证一键 Fuzz 仍能尝试这些解码方向。
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
from lib import string_codec


#: 实体编码子工具定义：(子标签名, 编码函数, 解码函数)
_ENTITY_TOOLS: tuple[tuple[str, callable, callable], ...] = (
    ("HTML 实体", string_codec.html_entity_encode,
     string_codec.html_entity_decode),
    ("Unicode 转义", string_codec.unicode_escape_encode,
     string_codec.unicode_escape_decode),
    ("Quoted-printable", string_codec.quoted_printable_encode,
     string_codec.quoted_printable_decode),
    ("GBK·UTF-16", string_codec.gbk_to_utf16, string_codec.utf16_to_gbk),
)


class _EntitySubPanel(QWidget):
    """单个实体编码子工具面板：CodecPanel + 编码/解码按钮。"""

    def __init__(self, theme, name: str, enc, dec,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._enc = enc
        self._dec = dec
        self._build(theme)

    def _build(self, theme) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 12, 8, 8)
        layout.setSpacing(10)

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
        actions.addStretch(1)
        layout.addLayout(actions)

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


class EntityCodecPage(QWidget):
    """实体编码工具页：HTML 实体 / Unicode 转义 / QP / GBK·UTF-16，标签页切换。"""

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._sub_panels: list[_EntitySubPanel] = []
        self._build()

    # ------------------------------------------------------------------ UI
    def _build(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(10)

        self.tabs = QTabWidget()
        for name, enc, dec in _ENTITY_TOOLS:
            panel = _EntitySubPanel(self.theme, name, enc, dec)
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
        """实体编码工具无后台线程，退出前无需额外清理。"""
