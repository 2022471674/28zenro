# -*- coding: utf-8 -*-
"""ASCII 转换工具页：把字符串 <-> ASCII 码两个工具收拢到一个工具，标签页切换。

覆盖字符串转 ASCII（十进制码点）与 ASCII 转字符串（十进制 / 0x 十六进制）
共 2 个子工具，算法全部委托 ``lib.string_codec``，本页不含任何编解码代码。

设计约定
--------
- 原 2 个独立的 ASCII 工具（``str_to_ascii`` / ``ascii_to_str``）已从注册表
  移除，统一由本页承载；
- 「密码 Fuzz」通过 ``ToolSpec.fuzz`` 显式声明参与（见
  :func:`lib.string_fuzz.fuzz_ascii`），保证一键 Fuzz 仍能把 ASCII 码点还原成文本。
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


#: ASCII 子工具定义：(子标签名, 执行函数, 动作名)
_ASCII_TOOLS: tuple[tuple[str, callable, str], ...] = (
    ("字符串转 ASCII", string_codec.str_to_ascii, "转换"),
    ("ASCII 转字符串", string_codec.ascii_to_str, "转换"),
)


class _AsciiSubPanel(QWidget):
    """单个 ASCII 子工具面板：CodecPanel + 执行按钮。"""

    def __init__(self, theme, name: str, func, action: str,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._func = func
        self._action = action
        self._build(theme)

    def _build(self, theme) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 12, 8, 8)
        layout.setSpacing(10)

        actions = QHBoxLayout()
        actions.setSpacing(8)
        self.run_btn = QPushButton(self._action)
        self.run_btn.setObjectName("ghbtn-primary")
        self.run_btn.clicked.connect(self._do_run)
        actions.addWidget(self.run_btn)
        actions.addStretch(1)
        layout.addLayout(actions)

        self.panel = CodecPanel(theme)
        layout.addWidget(self.panel, stretch=1)

        self._status = QLabel("")
        self._status.setObjectName("status-info")
        self._status.setWordWrap(True)
        layout.addWidget(self._status)

    # ------------------------------------------------------------------ 操作
    def _do_run(self) -> None:
        data = self.panel.get_input()
        if not data.strip():
            self._set_status(False, "请先在输入框填写要处理的内容。")
            return
        try:
            result = self._func(data)
        except Exception as exc:  # noqa: BLE001  界面兜底
            self._set_status(False, f"转换失败：{exc}")
            return
        self.panel.set_output(result)
        self._set_status(True, "转换完成。")

    def _set_status(self, ok: bool, text: str) -> None:
        self._status.setText(text)
        self._status.setObjectName("status-ok" if ok else "status-err")
        self._status.style().unpolish(self._status)
        self._status.style().polish(self._status)


class AsciiCodecPage(QWidget):
    """ASCII 转换工具页：字符串 <-> ASCII 码，标签页切换。"""

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._sub_panels: list[_AsciiSubPanel] = []
        self._build()

    # ------------------------------------------------------------------ UI
    def _build(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(10)

        self.tabs = QTabWidget()
        for name, func, action in _ASCII_TOOLS:
            panel = _AsciiSubPanel(self.theme, name, func, action)
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
        """ASCII 工具无后台线程，退出前无需额外清理。"""
