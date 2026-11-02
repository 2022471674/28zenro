# -*- coding: utf-8 -*-
"""番茄时钟页（Pomodoro）。

计时状态机在 ``lib.pomodoro``（纯逻辑、无 UI），本页用 QTimer 每 250ms
驱动一次 :meth:`~lib.pomodoro.Pomodoro.tick` 并刷新倒计时；阶段结束时弹
Windows 系统通知（``QSystemTrayIcon.showMessage``）。

专注 / 短休息 / 长休息的时长与「每 N 个专注后长休息」可在本页调整，
保存写回 config.json；计时中改参数会对当前阶段重新起算。

界面：倒计时放在一块卡片面板里，字号随页面高度自适应（见
:meth:`PomodoroPage._refresh_time_style`）；配色按阶段切换
（未开始 / 暂停为正文色，专注为主色，休息为成功绿）。
"""

from __future__ import annotations

import math

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QCheckBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QSystemTrayIcon,
    QVBoxLayout,
    QWidget,
)
from qfluentwidgets import FluentIcon, ProgressBar

from app.widgets.no_wheel import NoWheelSpinBox
from lib import pomodoro

TICK_MS = 250


class PomodoroPage(QWidget):
    """番茄时钟页：专注 / 休息循环计时，阶段结束弹系统通知。"""

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store

        cfg = self.store.get("pomodoro", default={}) or {}
        self.pomo = pomodoro.Pomodoro(pomodoro.PomodoroConfig(
            work_minutes=int(cfg.get("work_minutes", 25) or 25),
            short_rest_minutes=int(cfg.get("short_rest_minutes", 5) or 5),
            long_rest_minutes=int(cfg.get("long_rest_minutes", 15) or 15),
            long_every=int(cfg.get("long_every", 4) or 4),
        ))
        self._auto_next = bool(cfg.get("auto_next", True))
        self._notify = bool(cfg.get("notify", True))

        #: 系统托盘图标（延迟创建；持有引用避免被 GC 导致通知失效）
        self._tray: QSystemTrayIcon | None = None

        self._timer = QTimer(self)
        self._timer.setInterval(TICK_MS)
        self._timer.timeout.connect(self._on_tick)

        self._build()
        self._render()
        self._refresh_time_style()

    # ------------------------------------------------------------------ UI
    def _build(self) -> None:
        # 与其他页面一致：内容放进滚动区，倒计时放大后也不会把底部控件挤出窗口
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)
        scroll.setWidget(container)

        # 倒计时卡片：阶段名 + 超大倒计时 + 进度条，整体作为一块面板呈现
        card = QWidget()
        card.setObjectName("card")
        card_lay = QVBoxLayout(card)
        card_lay.setContentsMargins(20, 22, 20, 22)
        card_lay.setSpacing(10)

        self.phase_label = QLabel("未开始")
        self.phase_label.setObjectName("pomodoroPhase")
        self.phase_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        card_lay.addWidget(self.phase_label)

        self.time_label = QLabel("25:00")
        self.time_label.setObjectName("pomodoroTime")
        self.time_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        card_lay.addWidget(self.time_label)

        self.bar = ProgressBar()
        self.bar.setRange(0, 1000)
        self.bar.setValue(0)
        card_lay.addWidget(self.bar)

        layout.addWidget(card)

        self.stats_label = QLabel("")
        self.stats_label.setObjectName("caption")
        self.stats_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.stats_label)

        # 控制按钮
        controls = QHBoxLayout()
        controls.setSpacing(8)
        self.start_btn = QPushButton("开始")
        self.start_btn.setObjectName("ghbtn-primary")
        self.start_btn.clicked.connect(self._on_start_clicked)
        self.skip_btn = QPushButton("跳过本轮")
        self.skip_btn.setObjectName("ghbtn")
        self.skip_btn.clicked.connect(self._on_skip)
        self.reset_btn = QPushButton("重置")
        self.reset_btn.setObjectName("ghbtn")
        self.reset_btn.clicked.connect(self._on_reset)
        controls.addStretch(1)
        controls.addWidget(self.start_btn)
        controls.addWidget(self.skip_btn)
        controls.addWidget(self.reset_btn)
        controls.addStretch(1)
        layout.addLayout(controls)

        # 参数设置
        cfg = self.store.get("pomodoro", default={}) or {}
        form = QFormLayout()
        form.setHorizontalSpacing(12)
        form.setVerticalSpacing(8)

        self.work_spin = self._make_spin(
            int(cfg.get("work_minutes", 25) or 25), 1, 180)
        form.addRow("专注时长（分钟）", self.work_spin)
        self.short_spin = self._make_spin(
            int(cfg.get("short_rest_minutes", 5) or 5), 1, 180)
        form.addRow("短休息（分钟）", self.short_spin)
        self.long_spin = self._make_spin(
            int(cfg.get("long_rest_minutes", 15) or 15), 1, 180)
        form.addRow("长休息（分钟）", self.long_spin)
        self.every_spin = self._make_spin(
            int(cfg.get("long_every", 4) or 4), 1, 12)
        form.addRow("每 N 个专注后长休息", self.every_spin)

        self.auto_check = QCheckBox("阶段结束后自动进入下一段")
        self.auto_check.setChecked(self._auto_next)
        form.addRow("", self.auto_check)
        self.notify_check = QCheckBox("阶段结束时弹出系统通知")
        self.notify_check.setChecked(self._notify)
        form.addRow("", self.notify_check)
        layout.addLayout(form)

        actions = QHBoxLayout()
        actions.setSpacing(8)
        save_btn = QPushButton("保存参数")
        save_btn.setObjectName("ghbtn-primary")
        save_btn.clicked.connect(self._save_cfg)
        actions.addWidget(save_btn)
        actions.addStretch(1)
        layout.addLayout(actions)

        self.status_label = QLabel("")
        self.status_label.setObjectName("status-info")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)
        layout.addStretch(1)

    @staticmethod
    def _make_spin(value: int, lo: int, hi: int) -> QSpinBox:
        spin = NoWheelSpinBox()
        spin.setRange(lo, hi)
        spin.setValue(value)
        spin.setSuffix(" 分钟" if hi == 180 else "")
        return spin

    #: 倒计时字号区间与随页面高度的缩放系数（避免过小看不清 / 过大溢出）
    _TIME_FONT_MIN = 56
    _TIME_FONT_MAX = 132
    _TIME_FONT_RATIO = 0.17

    def _time_font_size(self) -> int:
        """按页面可用高度算倒计时字号，夹在合理区间内。"""
        return int(min(
            self._TIME_FONT_MAX,
            max(self._TIME_FONT_MIN, self.height() * self._TIME_FONT_RATIO),
        ))

    def _refresh_time_style(self) -> None:
        """刷新倒计时样式（自适应字号 + 阶段配色）。

        注意：应用级 QSS 里的 ``QWidget { font-size: ... }`` 优先级高于
        ``QWidget.setFont()``，只 setFont 会被覆盖掉（旧版 64pt 就因此从未
        生效）。所以字号 / 字族 / 颜色一律写在控件自身的样式表里；
        QSS 不支持 ``letter-spacing``，字距再用字体属性补上。
        """
        from PySide6.QtGui import QFont

        if not hasattr(self, "time_label"):
            return
        size = self._time_font_size()
        color = getattr(self, "_time_color", self.theme.text)
        family = self.theme.font_mono_family
        key = (size, family, color)
        if key == getattr(self, "_time_style_key", None):
            return
        self._time_style_key = key

        self.time_label.setStyleSheet(
            f"color: {color};"
            f'font-family: "{family}", monospace;'
            f"font-size: {size}px;"
            "font-weight: bold;"
        )
        font = self.time_label.font()
        font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, size * 0.06)
        self.time_label.setFont(font)

    def _set_time_color(self, color: str) -> None:
        """更新倒计时配色（仅在颜色变化时重建样式表）。"""
        if getattr(self, "_time_color", None) == color:
            return
        self._time_color = color
        self._refresh_time_style()

    def resizeEvent(self, event) -> None:  # noqa: N802  Qt 命名约定
        super().resizeEvent(event)
        self._refresh_time_style()

    def showEvent(self, event) -> None:  # noqa: N802  Qt 命名约定
        super().showEvent(event)
        # 切回本页时重算字号（覆盖窗口缩放 / 主题字体变化两种情况）
        self._refresh_time_style()

    # -------------------------------------------------------------- 渲染
    def _render(self) -> None:
        p = self.pomo
        remaining = p.remaining()
        secs = int(math.ceil(remaining)) if p.running else int(p.total())
        self.time_label.setText(f"{secs // 60:02d}:{secs % 60:02d}")

        if not p.running:
            self.phase_label.setText("未开始")
            self._set_time_color(self.theme.text)
        elif p.paused:
            self.phase_label.setText(f"{p.phase_name}（已暂停）")
            self._set_time_color(self.theme.text_muted)
        else:
            self.phase_label.setText(p.phase_name)
            color = (self.theme.success
                     if p.phase != pomodoro.PHASE_WORK else self.theme.accent)
            self._set_time_color(color)

        self.bar.setValue(int(round(p.progress() * 1000)))
        self.start_btn.setText("继续" if p.paused else
                               ("暂停" if p.running else "开始"))

        nxt = p.next_phase()
        nxt_name = pomodoro.PHASE_NAMES.get(nxt, nxt)
        self.stats_label.setText(
            f"已完成 {p.completed} 个番茄 · 本轮第 {p.round_done}/{p.config.long_every} 个"
            f" · 接下来：{nxt_name}"
        )

    # -------------------------------------------------------------- 事件
    def _on_tick(self) -> None:
        finished = self.pomo.tick()
        self._render()
        if finished is None:
            return
        self._announce(finished)

    def _announce(self, finished: str) -> None:
        """阶段结束：状态栏提示 + 系统通知（可关）。"""
        if finished == pomodoro.PHASE_WORK:
            nxt = self.pomo.next_phase()
            nxt_name = pomodoro.PHASE_NAMES.get(nxt, nxt)
            msg = f"专注结束，进入{nxt_name}。已完成 {self.pomo.completed} 个番茄。"
        else:
            msg = "休息结束，开始下一个专注。"
        self._set_status(msg, ok=True)

        if not self._auto_next:
            # 关掉自动继续：停在下一段开头等用户点「开始」
            self.pomo.pause()
            self._render()

        if self._notify:
            self._notify_system(msg)

    def _notify_system(self, message: str) -> None:
        """弹 Windows 系统通知；托盘不可用时静默降级。"""
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        if self._tray is None:
            self._tray = QSystemTrayIcon(self)
            try:
                self._tray.setIcon(QIcon(FluentIcon.STOP_WATCH.path()))
            except Exception:  # noqa: BLE001  图标取不到不影响通知
                pass
            self._tray.show()
        self._tray.showMessage(
            "番茄时钟", message,
            QSystemTrayIcon.MessageIcon.Information, 5000)

    def _on_start_clicked(self) -> None:
        p = self.pomo
        if p.paused:
            p.resume()
            self._timer.start()
        elif p.running:
            p.pause()
        else:
            p.start()
            self._timer.start()
        self._set_status("")
        self._render()

    def _on_skip(self) -> None:
        if not self.pomo.running:
            self._set_status("尚未开始，无法跳过。", ok=False)
            return
        finished = self.pomo.skip()
        if finished is not None:
            self._announce(finished)
        self._render()

    def _on_reset(self) -> None:
        self._timer.stop()
        self.pomo.reset()
        self._set_status("已重置。")
        self._render()

    def _save_cfg(self) -> None:
        cfg = pomodoro.PomodoroConfig(
            work_minutes=self.work_spin.value(),
            short_rest_minutes=self.short_spin.value(),
            long_rest_minutes=self.long_spin.value(),
            long_every=self.every_spin.value(),
        )
        try:
            cfg.validate()
        except pomodoro.PomodoroError as exc:
            self._set_status(str(exc), ok=False)
            return
        self._auto_next = self.auto_check.isChecked()
        self._notify = self.notify_check.isChecked()
        self.store.setv(cfg.work_minutes, "pomodoro", "work_minutes")
        self.store.setv(cfg.short_rest_minutes, "pomodoro", "short_rest_minutes")
        self.store.setv(cfg.long_rest_minutes, "pomodoro", "long_rest_minutes")
        self.store.setv(cfg.long_every, "pomodoro", "long_every")
        self.store.setv(self._auto_next, "pomodoro", "auto_next")
        self.store.setv(self._notify, "pomodoro", "notify")
        self.store.save()
        self.pomo.reconfigure(cfg)
        self._set_status("已保存参数。", ok=True)
        self._render()

    def _set_status(self, text: str, ok: bool = True) -> None:
        self.status_label.setObjectName("status-ok" if ok else "status-err")
        self.status_label.setStyleSheet("")
        self.status_label.setText(text)

    # -------------------------------------------------------------- 收尾
    def shutdown(self) -> None:
        """停止计时并移除托盘图标（主窗口 closeEvent 调用）。"""
        self._timer.stop()
        if self._tray is not None:
            self._tray.hide()
            self._tray = None
