# -*- coding: utf-8 -*-
"""哈希工具页：把全部单向哈希计算收拢到一个工具，标签页切换。

覆盖 MD5 / SHA1 / SHA256 / SHA512 / SHA3-256 共 5 个单向摘要算法，算法全部
委托 ``lib.hash_codec``（标准库 hashlib），本页不含任何哈希实现代码。

每个子标签复用 :class:`app.widgets.codec_panel.CodecPanel`（输入 / 输出双区 +
复制 / 用作输入 / 粘贴），加「计算」按钮，输出十六进制小写摘要。

设计约定
--------
- 原 5 个独立的哈希工具（``md5`` / ``sha1`` / ``sha256`` / ``sha512`` /
  ``sha3_256``）已从注册表移除，统一由本页承载；
- 哈希是**单向**不可逆的，本就不参与「密码 Fuzz」，收拢后无 Fuzz 影响；
- 「哈希爆破」（md5_crash 等）与「哈希长度扩展攻击」（hash_ext）保持独立，
  不受本次收拢影响。
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
from lib import hash_codec


#: 哈希子工具定义：(子标签名, 摘要函数)
_HASH_TOOLS: tuple[tuple[str, callable], ...] = (
    ("MD5", hash_codec.md5_hex),
    ("SHA1", hash_codec.sha1_hex),
    ("SHA256", hash_codec.sha256_hex),
    ("SHA512", hash_codec.sha512_hex),
    ("SHA3-256", hash_codec.sha3_256_hex),
)


class _HashSubPanel(QWidget):
    """单个哈希子工具面板：CodecPanel + 计算按钮。"""

    def __init__(self, theme, name: str, func, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._func = func
        self._build(theme)

    def _build(self, theme) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 12, 8, 8)
        layout.setSpacing(10)

        # -- 操作按钮行 --
        actions = QHBoxLayout()
        actions.setSpacing(8)
        self.run_btn = QPushButton("计算")
        self.run_btn.setObjectName("ghbtn-primary")
        self.run_btn.clicked.connect(self._do_calc)
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
    def _do_calc(self) -> None:
        data = self.panel.get_input()
        if not data.strip():
            self._set_status(False, "请先在输入框填写要计算摘要的内容。")
            return
        try:
            result = self._func(data)
        except Exception as exc:  # noqa: BLE001  界面兜底
            self._set_status(False, f"计算失败：{exc}")
            return
        self.panel.set_output(result)
        self._set_status(True, f"计算完成，{len(result)} 位十六进制摘要。")

    def _set_status(self, ok: bool, text: str) -> None:
        self._status.setText(text)
        self._status.setObjectName("status-ok" if ok else "status-err")
        self._status.style().unpolish(self._status)
        self._status.style().polish(self._status)


class HashPage(QWidget):
    """哈希工具页：全部单向哈希计算，标签页切换。"""

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._sub_panels: list[_HashSubPanel] = []
        self._build()

    # ------------------------------------------------------------------ UI
    def _build(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(10)

        self.tabs = QTabWidget()
        for name, func in _HASH_TOOLS:
            panel = _HashSubPanel(self.theme, name, func)
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
        """哈希工具无后台线程，退出前无需额外清理。"""
