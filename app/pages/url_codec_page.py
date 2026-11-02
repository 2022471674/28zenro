# -*- coding: utf-8 -*-
"""URL 编码工具页：把 URL 相关的三个字符串工具收拢到一个工具，标签页切换。

覆盖 URL 编码 / URL 全编码（含英文）/ URL 解码共 3 个子工具，算法全部委托
``lib.string_codec``（标准库 urllib），本页不含任何编解码代码。

每个子标签复用 :class:`app.widgets.codec_panel.CodecPanel`（输入 / 输出双区 +
复制 / 用作输入 / 粘贴），加「执行」按钮；URL 编码与 URL 全编码为编码方向，
URL 解码为解码方向（单向），故每个子标签只有一个执行按钮。

设计约定
--------
- 原 3 个独立的 URL 字符串工具（``url_encode`` / ``url_encode_full`` /
  ``url_decode``）已从注册表移除，统一由本页承载；
- 「密码 Fuzz」通过 ``ToolSpec.fuzz`` 显式声明参与（见
  :func:`lib.url_fuzz.fuzz_url`），保证一键 Fuzz 仍能解出 URL 编码密文。
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


#: URL 子工具定义：(子标签名, 执行函数, 动作名)
_URL_TOOLS: tuple[tuple[str, callable, str], ...] = (
    ("URL 编码", string_codec.url_encode, "编码"),
    ("URL 全编码", string_codec.url_encode_full, "编码"),
    ("URL 解码", string_codec.url_decode, "解码"),
)


class _UrlSubPanel(QWidget):
    """单个 URL 子工具面板：CodecPanel + 执行按钮。"""

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

        # -- 操作按钮行 --
        actions = QHBoxLayout()
        actions.setSpacing(8)
        self.run_btn = QPushButton(self._action)
        self.run_btn.setObjectName("ghbtn-primary")
        self.run_btn.clicked.connect(self._do_run)
        actions.addWidget(self.run_btn)
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
    def _do_run(self) -> None:
        data = self.panel.get_input()
        if not data.strip():
            self._set_status(False, "请先在输入框填写要处理的内容。")
            return
        try:
            result = self._func(data)
        except Exception as exc:  # noqa: BLE001  界面兜底
            self._set_status(False, f"{self._action}失败：{exc}")
            return
        self.panel.set_output(result)
        self._set_status(True, f"{self._action}完成。")

    def _set_status(self, ok: bool, text: str) -> None:
        self._status.setText(text)
        self._status.setObjectName("status-ok" if ok else "status-err")
        self._status.style().unpolish(self._status)
        self._status.style().polish(self._status)


class UrlCodecPage(QWidget):
    """URL 编码工具页：URL 编码 / 全编码 / 解码，标签页切换。"""

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._sub_panels: list[_UrlSubPanel] = []
        self._build()

    # ------------------------------------------------------------------ UI
    def _build(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(10)

        self.tabs = QTabWidget()
        for name, func, action in _URL_TOOLS:
            panel = _UrlSubPanel(self.theme, name, func, action)
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
        """URL 工具无后台线程，退出前无需额外清理。"""
