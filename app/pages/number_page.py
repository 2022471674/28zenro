# -*- coding: utf-8 -*-
"""进制互转页。

用「源进制 / 目标进制」两个下拉（2 / 8 / 10 / 16）取代旧版 12 个菜单项，
逻辑层复用 ``lib.number_base_codec.convert``。
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from app.widgets.codec_panel import CodecPanel
from app.widgets.no_wheel import NoWheelComboBox
from lib import number_base_codec

BASES = (("2", "二进制"), ("8", "八进制"), ("10", "十进制"), ("16", "十六进制"))


class NumberBasePage(QWidget):
    """2 / 8 / 10 / 16 进制两两互转页。"""

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._build()

    def _build(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)

        selectors = QHBoxLayout()
        selectors.setSpacing(12)

        from_label = QLabel("源进制")
        from_label.setObjectName("section")
        self.from_box = NoWheelComboBox()
        for value, label in BASES:
            self.from_box.addItem(f"{label}（{value}）", int(value))
        self.from_box.setCurrentIndex(0)

        to_label = QLabel("目标进制")
        to_label.setObjectName("section")
        self.to_box = NoWheelComboBox()
        for value, label in BASES:
            self.to_box.addItem(f"{label}（{value}）", int(value))
        self.to_box.setCurrentIndex(2)

        convert_btn = QPushButton("转换 →")
        convert_btn.setObjectName("ghbtn-primary")
        convert_btn.clicked.connect(self._convert)

        selectors.addWidget(from_label)
        selectors.addWidget(self.from_box)
        selectors.addSpacing(8)
        selectors.addWidget(to_label)
        selectors.addWidget(self.to_box)
        selectors.addSpacing(8)
        selectors.addWidget(convert_btn)
        selectors.addStretch(1)
        layout.addLayout(selectors)

        self.panel = CodecPanel(self.theme)
        layout.addWidget(self.panel, stretch=1)

    def _convert(self) -> None:
        data = self.panel.get_input()
        if not data:
            return
        src = self.from_box.currentData()
        dst = self.to_box.currentData()
        try:
            result = number_base_codec.convert(data, src, dst)
        except Exception as exc:  # noqa: BLE001  界面兜底
            self.panel.set_output(f"[进制互转失败] {exc}")
            return
        self.panel.set_output(result)
