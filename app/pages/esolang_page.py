# -*- coding: utf-8 -*-
"""esolang 工具页：把 esolang 相关的执行器收拢到一个工具，标签页切换。

覆盖 Brainfuck / Ook! / jother 执行器与 JSFuck 编码 / 解码共 5 个子工具，
算法全部委托 ``lib.esolang``，本页不含任何解释器代码。

每个子标签复用 :class:`app.widgets.codec_panel.CodecPanel`（输入 / 输出双区 +
复制 / 用作输入 / 粘贴），加「执行」/「编码」/「解码」按钮（单按钮，见下表）。

设计约定
--------
- 原 5 个独立的 esolang 工具（``brainfuck`` / ``ook`` / ``jother`` /
  ``jsfuck_encode`` / ``jsfuck_decode``）已从注册表移除，统一由本页承载；
- esolang 均为单向（执行 / 编码），原就不参与「密码 Fuzz」，收拢后亦无影响。
"""

from __future__ import annotations

from functools import partial

from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from app.widgets.codec_panel import CodecPanel
from lib import esolang


#: esolang 子工具定义：(子标签名, 执行函数, 按钮文案)
_ESO_TOOLS: tuple[tuple[str, callable, str], ...] = (
    ("Brainfuck", partial(esolang.brainfuck_exec, input_text=""), "执行"),
    ("Ook!", partial(esolang.ook_exec, input_text=""), "执行"),
    ("jother", partial(esolang.jother_exec, input_text=""), "执行"),
    ("JSFuck 编码", esolang.jsfuck_encode, "编码"),
    ("JSFuck 解码", esolang.jsfuck_decode, "解码"),
)


class _EsoSubPanel(QWidget):
    """单个 esolang 子工具面板：CodecPanel + 执行/编码/解码按钮。"""

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
            self._set_status(False, f"{self._action}失败：{exc}")
            return
        self.panel.set_output(result)
        self._set_status(True, f"{self._action}完成。")

    def _set_status(self, ok: bool, text: str) -> None:
        self._status.setText(text)
        self._status.setObjectName("status-ok" if ok else "status-err")
        self._status.style().unpolish(self._status)
        self._status.style().polish(self._status)


class EsolangPage(QWidget):
    """esolang 工具页：Brainfuck / Ook / jother / JSFuck，标签页切换。"""

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._sub_panels: list[_EsoSubPanel] = []
        self._build()

    # ------------------------------------------------------------------ UI
    def _build(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(10)

        self.tabs = QTabWidget()
        for name, func, action in _ESO_TOOLS:
            panel = _EsoSubPanel(self.theme, name, func, action)
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
        """esolang 无后台线程，退出前无需额外清理。"""
