# -*- coding: utf-8 -*-
"""时间戳转换页（时间戳 ↔ 日期时间互转）。

纯逻辑全部委托 ``lib.time_codec``（精度识别 / 解析 / 转换），本页不含算法：

- **时间戳 -> 日期时间**：输入整数时间戳，自动按秒 / 毫秒 / 微秒 / 纳秒
  识别精度，输出本地时间与 UTC 时间。
- **日期时间 -> 时间戳**：输入日期时间字符串，选择目标精度（秒 / 毫秒 /
  微秒 / 纳秒），输出对应时间戳。
- 附带「当前时间」一键填充，方便快速取当前时间戳。

界面分两个子标签（QTabWidget），与其它页面一致的滚动区 + 状态标签范式。
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QFormLayout,
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

from lib import time_codec
from lib.time_codec import TimeCodecError


def _make_status_label() -> QLabel:
    label = QLabel("")
    label.setObjectName("status-info")
    label.setWordWrap(True)
    return label


def _set_status(label: QLabel, ok: bool | None, text: str) -> None:
    label.setObjectName(
        "status-info" if ok is None else ("status-ok" if ok else "status-err"))
    label.setText(text)
    label.style().unpolish(label)
    label.style().polish(label)


class TimeCodecPage(QWidget):
    """时间戳转换页。"""

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._build()

    # ------------------------------------------------------------------ UI
    def _build(self) -> None:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)

        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_ts_to_dt_tab(), "时间戳 → 日期时间")
        self.tabs.addTab(self._build_dt_to_ts_tab(), "日期时间 → 时间戳")
        layout.addWidget(self.tabs, stretch=1)

        scroll.setWidget(inner)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

    # ---- Tab 1: 时间戳 -> 日期时间 -------------------------------------
    def _build_ts_to_dt_tab(self) -> QWidget:
        tab = QWidget()
        form = QFormLayout(tab)
        form.setContentsMargins(8, 14, 8, 8)
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(10)

        self.ts_input = QLineEdit()
        self.ts_input.setPlaceholderText("输入整数时间戳，如 1700000000 / 1700000000000")
        form.addRow("时间戳", self.ts_input)

        self.ts_unit = QComboBox()
        self.ts_unit.addItem("自动识别", "")
        for key, name in (
            (time_codec.UNIT_SECOND, "秒"),
            (time_codec.UNIT_MILLISECOND, "毫秒"),
            (time_codec.UNIT_MICROSECOND, "微秒"),
            (time_codec.UNIT_NANOSECOND, "纳秒"),
        ):
            self.ts_unit.addItem(name, key)
        form.addRow("精度", self.ts_unit)

        self.ts_convert_btn = QPushButton("转换")
        self.ts_convert_btn.setObjectName("ghbtn-primary")
        self.ts_convert_btn.clicked.connect(self._on_ts_convert)
        self.ts_now_btn = QPushButton("填入当前时间戳")
        self.ts_now_btn.setObjectName("ghbtn")
        self.ts_now_btn.clicked.connect(self._on_ts_now)
        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        btn_row.addWidget(self.ts_convert_btn)
        btn_row.addWidget(self.ts_now_btn)
        btn_row.addStretch(1)
        form.addRow("", btn_row)

        self.ts_output = QPlainTextEdit()
        self.ts_output.setObjectName("io")
        self.ts_output.setReadOnly(True)
        self.ts_output.setPlaceholderText("转换结果…")
        self.ts_output.setMinimumHeight(160)
        form.addRow("结果", self.ts_output)

        self.ts_status = _make_status_label()
        form.addRow("", self.ts_status)
        return tab

    # ---- Tab 2: 日期时间 -> 时间戳 -------------------------------------
    def _build_dt_to_ts_tab(self) -> QWidget:
        tab = QWidget()
        form = QFormLayout(tab)
        form.setContentsMargins(8, 14, 8, 8)
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(10)

        self.dt_input = QLineEdit()
        self.dt_input.setPlaceholderText(
            "如 2026-01-01 12:00:00 / 2026/01/01 12:00:00 / 2026-01-01T12:00:00")
        form.addRow("日期时间", self.dt_input)

        self.dt_unit = QComboBox()
        for key, name in (
            (time_codec.UNIT_SECOND, "秒"),
            (time_codec.UNIT_MILLISECOND, "毫秒"),
            (time_codec.UNIT_MICROSECOND, "微秒"),
            (time_codec.UNIT_NANOSECOND, "纳秒"),
        ):
            self.dt_unit.addItem(name, key)
        form.addRow("目标精度", self.dt_unit)

        self.dt_convert_btn = QPushButton("转换")
        self.dt_convert_btn.setObjectName("ghbtn-primary")
        self.dt_convert_btn.clicked.connect(self._on_dt_convert)
        self.dt_now_btn = QPushButton("填入当前时间")
        self.dt_now_btn.setObjectName("ghbtn")
        self.dt_now_btn.clicked.connect(self._on_dt_now)
        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        btn_row.addWidget(self.dt_convert_btn)
        btn_row.addWidget(self.dt_now_btn)
        btn_row.addStretch(1)
        form.addRow("", btn_row)

        self.dt_output = QPlainTextEdit()
        self.dt_output.setObjectName("io")
        self.dt_output.setReadOnly(True)
        self.dt_output.setPlaceholderText("转换结果…")
        self.dt_output.setMinimumHeight(160)
        form.addRow("结果", self.dt_output)

        self.dt_status = _make_status_label()
        form.addRow("", self.dt_status)
        return tab

    # -------------------------------------------------------------- 逻辑
    def _on_ts_convert(self) -> None:
        text = self.ts_input.text().strip()
        if not text:
            _set_status(self.ts_status, False, "请输入时间戳。")
            return
        try:
            ts = int(text)
        except ValueError:
            _set_status(self.ts_status, False, "时间戳必须是整数。")
            return
        unit = self.ts_unit.currentData() or None
        try:
            r = time_codec.ts_to_datetime(ts, unit)
        except TimeCodecError as exc:
            _set_status(self.ts_status, False, str(exc))
            return
        self.ts_output.setPlainText(
            f"精度：{r['unit_name']}\n"
            f"本地时间：{r['local']}（{r['weekday']}）\n"
            f"UTC 时间：{r['utc']}\n"
            f"秒级值：{r['seconds']}\n"
            f"ISO 本地：{r['iso_local']}\n"
            f"ISO UTC：{r['iso_utc']}"
        )
        _set_status(self.ts_status, True, "转换成功。")

    def _on_ts_now(self) -> None:
        r = time_codec.now_timestamp()
        self.ts_input.setText(str(r["ts"]))
        _set_status(self.ts_status, None,
                    f"已填入当前 {r['unit_name']} 级时间戳：{r['ts']}")

    def _on_dt_convert(self) -> None:
        text = self.dt_input.text().strip()
        if not text:
            _set_status(self.dt_status, False, "请输入日期时间。")
            return
        unit = self.dt_unit.currentData() or time_codec.UNIT_SECOND
        try:
            r = time_codec.datetime_to_ts(text, unit)
        except TimeCodecError as exc:
            _set_status(self.dt_status, False, str(exc))
            return
        self.dt_output.setPlainText(
            f"精度：{r['unit_name']}\n"
            f"时间戳：{r['ts']}\n"
            f"本地时间：{r['local']}\n"
            f"UTC 时间：{r['utc']}"
        )
        _set_status(self.dt_status, True, "转换成功。")

    def _on_dt_now(self) -> None:
        r = time_codec.now_timestamp()
        self.dt_input.setText(r["local"])
        _set_status(self.dt_status, None,
                    f"已填入当前本地时间：{r['local']}")

    # -------------------------------------------------------------- 收尾
    def shutdown(self) -> None:
        """页面无后台线程 / 计时器，无需清理（占位以对齐其它页面）。"""
