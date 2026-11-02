# -*- coding: utf-8 -*-
"""键盘输入模拟页（原 Tkinter 独立窗口迁移而来）。

逻辑层 ``lib.key_simulator.KeySimulator`` 不变：后台线程注入按键；
本页用 QTimer 做倒计时与进度轮询（替代 Tk 的 ``after``），并保留
反作弊进程检测拦截逻辑。
"""

from __future__ import annotations

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from lib import key_simulator
from lib.key_simulator import LETTERS, KeySimulator

COUNTDOWN_TICK_MS = 1000
PROGRESS_TICK_MS = 100


class KeySimPage(QWidget):
    """键盘输入模拟页：配置内容 / 速率 / 时长后注入当前焦点窗口。"""

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store

        self.simulator = KeySimulator()
        self._countdown = 0
        self._pending_plan = None
        self._launched = False
        self._rate_text = ""

        self._countdown_timer = QTimer(self)
        self._countdown_timer.setInterval(COUNTDOWN_TICK_MS)
        self._countdown_timer.timeout.connect(self._tick)

        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(PROGRESS_TICK_MS)
        self._poll_timer.timeout.connect(self._poll)

        self._build()

    # ------------------------------------------------------------------ UI
    def _build(self) -> None:
        cfg = self.store.get("key_sim", default={}) or {}
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)

        form = QFormLayout()
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(10)

        self.keys_edit = QLineEdit(LETTERS)
        self.keys_edit.setPlaceholderText("要模拟输入的按键内容，{ENTER} 这类特殊键名可用")
        form.addRow("模拟按键内容", self.keys_edit)

        self.rate_edit = QLineEdit(str(cfg.get("rate", 20)))
        self.rate_edit.setPlaceholderText("次/秒")
        form.addRow("输入速率（次/秒）", self.rate_edit)

        self.duration_edit = QLineEdit(str(cfg.get("duration", 10)))
        self.duration_edit.setPlaceholderText("秒")
        form.addRow("持续时间（秒）", self.duration_edit)

        layout.addLayout(form)

        hint = QLabel(self.theme.UI_KEY_SIM_HINT)
        hint.setObjectName("caption")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        self.status_label = QLabel(self.theme.UI_KEY_SIM_IDLE)
        self.status_label.setObjectName("status-info")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        self.start_btn = QPushButton(self.theme.UI_KEY_SIM_BTN_START)
        self.start_btn.setObjectName("ghbtn-primary")
        self.start_btn.clicked.connect(self.on_start)
        self.stop_btn = QPushButton(self.theme.UI_KEY_SIM_BTN_STOP)
        self.stop_btn.setObjectName("ghbtn-danger")
        self.stop_btn.clicked.connect(self.on_stop)
        buttons.addWidget(self.start_btn)
        buttons.addWidget(self.stop_btn)
        buttons.addStretch(1)
        layout.addLayout(buttons)
        layout.addStretch(1)

    # ------------------------------------------------------------- 交互
    def on_start(self) -> None:
        """校验参数 -> 倒计时 -> 启动注入线程。"""
        if self._countdown_timer.isActive() or self.simulator.running:
            return
        try:
            plan = key_simulator.build_plan(
                self.keys_edit.text(), self.rate_edit.text(), self.duration_edit.text()
            )
        except ValueError as exc:
            self._show_failure(exc)
            return

        self._rate_text = f"{plan.rate:g}"
        self._launched = False
        self._start_countdown(plan)

    def on_stop(self) -> None:
        self._countdown_timer.stop()
        self.simulator.stop()
        if not self.simulator.running:
            pressed = self.simulator.pressed if self._launched else 0
            self.status_label.setText(
                self.theme.UI_KEY_SIM_STOPPED.format(pressed=pressed)
            )

    # ------------------------------------------------- 倒计时与进度轮询
    def _start_countdown(self, plan) -> None:
        cfg = self.store.get("key_sim", default={}) or {}
        delay = max(0, int(cfg.get("delay", 3) or 0))
        if delay <= 0:
            self._launch(plan)
            return
        self._countdown = delay
        self._pending_plan = plan
        self._tick()

    def _tick(self) -> None:
        if self._countdown <= 0:
            self._countdown_timer.stop()
            self._launch(self._pending_plan)
            return
        self.status_label.setText(
            self.theme.UI_KEY_SIM_READY.format(
                seconds=self._countdown, count=self._pending_plan.total
            )
        )
        self._countdown -= 1
        if not self._countdown_timer.isActive():
            self._countdown_timer.start()

    def _detect_protected(self) -> str | None:
        cfg = self.store.get("key_sim", default={}) or {}
        try:
            names = key_simulator.parse_protected_processes(
                cfg.get("protected_processes", "")
            )
            return key_simulator.find_protected_process(names)
        except OSError:
            return None

    def _launch(self, plan) -> None:
        self._countdown_timer.stop()
        protected = self._detect_protected()
        if protected:
            self.status_label.setText(
                self.theme.UI_KEY_SIM_PROTECTED.format(process=protected)
            )
            return
        try:
            self.simulator.start(
                self.keys_edit.text(), self.rate_edit.text(), self.duration_edit.text()
            )
        except (ValueError, OSError) as exc:
            self._show_failure(exc)
            return
        self._launched = True
        self.status_label.setText(
            self.theme.UI_KEY_SIM_RUNNING.format(
                pressed=0, total=plan.total, rate=self._rate_text
            )
        )
        self._poll_timer.start()

    def _poll(self) -> None:
        pressed, total = self.simulator.progress()
        if self.simulator.running:
            self.status_label.setText(
                self.theme.UI_KEY_SIM_RUNNING.format(
                    pressed=pressed, total=total, rate=self._rate_text
                )
            )
            return
        self._poll_timer.stop()
        if self.simulator.error:
            self._show_failure(self.simulator.error)
        elif self.simulator.stopped:
            self.status_label.setText(
                self.theme.UI_KEY_SIM_STOPPED.format(pressed=pressed)
            )
        else:
            self.status_label.setText(
                self.theme.UI_KEY_SIM_DONE.format(pressed=pressed)
            )

    def _show_failure(self, reason) -> None:
        prefix = self.theme.ALGO_KEY_SIMULATE + self.theme.UI_SUFFIX_FAILED
        self.status_label.setText(f"{prefix}：{reason}")

    def shutdown(self) -> None:
        """应用退出时调用：停掉注入线程，避免继续往其它窗口打字。"""
        self._countdown_timer.stop()
        self._poll_timer.stop()
        self.simulator.stop(wait=True)
