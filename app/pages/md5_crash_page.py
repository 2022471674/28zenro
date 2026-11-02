# -*- coding: utf-8 -*-
"""MD5 爆破页（原 Tkinter 独立窗口迁移而来）。

逻辑层 ``lib.md5_crash.Md5Cracker`` 不变：枚举 / 验证进程 + 控制线程；
本页用 QTimer 每 200ms 轮询日志队列（替代 Tk 的 ``after``），支持
枚举爆破（纯数字 / 纯字母 / 混合）与字典爆破（候选输入池 + 字典文件）。
"""

from __future__ import annotations

import os
import time

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (
    QButtonGroup,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QRadioButton,
    QVBoxLayout,
    QWidget,
)

from app.widgets.no_wheel import NoWheelSpinBox
from lib import md5_crash

POLL_TICK_MS = 200


class Md5CrashPage(QWidget):
    """哈希爆破页：配置参数后后台爆破，日志区实时展示进度。

    ``hash_name`` 为哈希算法（``md5`` / ``sha1`` / ``sha256`` / ``sha512`` /
    ``sha3_256``），默认 ``md5``。SHA1 / SHA256 复用同一套枚举 / 字典 /
    多进程框架（见 :mod:`lib.md5_crash`），仅目标哈希长度与算法名不同。
    """

    def __init__(self, theme, store, hash_name: str = "md5",
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self.hash_name = str(hash_name or "md5").strip().lower()
        self._display = md5_crash.hash_display_name(self.hash_name)
        self._hex_len = md5_crash.hash_length(self.hash_name)

        self.cracker = md5_crash.Md5Cracker()
        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(POLL_TICK_MS)
        self._poll_timer.timeout.connect(self._poll)
        #: 当前选择的字典路径（空串 = 尚未选择）
        self._dict_path = ""

        self._build()

    # ------------------------------------------------------------- 文案
    @property
    def _hash_label(self) -> str:
        """目标哈希输入框标签（含算法名与长度）。"""
        return f"{self._display} 值（{self._hex_len} 位十六进制）"

    @property
    def _hash_placeholder(self) -> str:
        return f"{self._hex_len} 位十六进制 {self._display} 值"

    @property
    def _hash_idle(self) -> str:
        return f"就绪：填写 {self._display} 与参数后点击「开始」。"

    # ------------------------------------------------------------------ UI
    def _build(self) -> None:
        cfg = self.store.get("md5_crash", default={}) or {}

        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 20, 24, 20)
        outer.setSpacing(12)

        body = QHBoxLayout()
        body.setSpacing(16)
        outer.addLayout(body, stretch=1)

        # ---- 左栏：参数区 ----
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(10)
        left.setFixedWidth(420)

        form = QFormLayout()
        form.setHorizontalSpacing(12)
        form.setVerticalSpacing(8)

        self.md5_edit = QLineEdit()
        self.md5_edit.setPlaceholderText(self._hash_placeholder)
        form.addRow(self._hash_label, self.md5_edit)

        # 长度用 SpinBox 收：范围与 lib 侧一致，min/max 互相约束
        self.min_len_edit = NoWheelSpinBox()
        self.min_len_edit.setRange(1, md5_crash.MAX_LEN_LIMIT)
        self.min_len_edit.setValue(int(cfg.get("min_len", 8) or 8))
        self.max_len_edit = NoWheelSpinBox()
        self.max_len_edit.setRange(1, md5_crash.MAX_LEN_LIMIT)
        self.max_len_edit.setValue(int(cfg.get("max_len", 18) or 18))
        self.min_len_edit.valueChanged.connect(self._sync_len_range)
        self.max_len_edit.valueChanged.connect(self._sync_len_range)
        len_row = QHBoxLayout()
        len_row.setSpacing(8)
        len_row.addWidget(self.min_len_edit)
        len_row.addWidget(self.max_len_edit)
        form.addRow("最小 / 最大长度", len_row)

        self.worker_edit = NoWheelSpinBox()
        self.worker_edit.setRange(1, md5_crash.MAX_COUNT_LIMIT)
        self.worker_edit.setValue(int(cfg.get("worker_num", 8) or 8))
        self.thread_edit = NoWheelSpinBox()
        self.thread_edit.setRange(1, md5_crash.MAX_COUNT_LIMIT)
        self.thread_edit.setValue(int(cfg.get("thread_num", 8) or 8))
        proc_row = QHBoxLayout()
        proc_row.setSpacing(8)
        proc_row.addWidget(self.worker_edit)
        proc_row.addWidget(self.thread_edit)
        form.addRow("进程数 / 线程数", proc_row)

        self._sync_len_range()

        # -- 预测词（前缀/后缀） --
        self.prefix_edit = QLineEdit()
        self.prefix_edit.setPlaceholderText(self.theme.UI_MD5_CRASH_PREFIX_PLACEHOLDER)
        form.addRow(self.theme.UI_MD5_CRASH_LABEL_PREFIX, self.prefix_edit)

        self.suffix_edit = QLineEdit()
        self.suffix_edit.setPlaceholderText(self.theme.UI_MD5_CRASH_SUFFIX_PLACEHOLDER)
        form.addRow(self.theme.UI_MD5_CRASH_LABEL_SUFFIX, self.suffix_edit)

        left_layout.addLayout(form)

        # -- 爆破模式（单选组） --
        mode_label = QLabel(self.theme.UI_MD5_CRASH_LABEL_MODE)
        mode_label.setObjectName("section")
        left_layout.addWidget(mode_label)

        mode_row = QHBoxLayout()
        mode_row.setSpacing(16)
        self._mode_group = QButtonGroup(self)
        self._mode_buttons: dict[str, QRadioButton] = {}
        default_mode = cfg.get("mode", "mixed")
        for mode, text in (
            ("digits", self.theme.UI_MD5_CRASH_MODE_DIGITS),
            ("letters", self.theme.UI_MD5_CRASH_MODE_LETTERS),
            ("mixed", self.theme.UI_MD5_CRASH_MODE_MIXED),
            ("dict", self.theme.UI_MD5_CRASH_MODE_DICT),
        ):
            radio = QRadioButton(text)
            self._mode_group.addButton(radio)
            self._mode_buttons[mode] = radio
            mode_row.addWidget(radio)
            if mode == default_mode:
                radio.setChecked(True)
        mode_row.addStretch(1)
        left_layout.addLayout(mode_row)

        # -- 字典爆破区（默认隐藏） --
        self.dict_widget = QWidget()
        dict_layout = QVBoxLayout(self.dict_widget)
        dict_layout.setContentsMargins(0, 0, 0, 0)
        dict_layout.setSpacing(8)

        dict_btns = QHBoxLayout()
        dict_btns.setSpacing(8)
        choose_btn = QPushButton(self.theme.UI_MD5_CRASH_BTN_DICT_CHOOSE)
        choose_btn.setObjectName("ghbtn")
        choose_btn.clicked.connect(self.on_choose_dict)
        default_btn = QPushButton(self.theme.UI_MD5_CRASH_BTN_DICT_DEFAULT)
        default_btn.setObjectName("ghbtn")
        default_btn.clicked.connect(self.on_use_default_dict)
        dict_btns.addWidget(choose_btn)
        dict_btns.addWidget(default_btn)
        dict_btns.addStretch(1)
        dict_layout.addLayout(dict_btns)

        cand_label = QLabel(self.theme.UI_MD5_CRASH_LABEL_DICT_CANDIDATES)
        cand_label.setObjectName("section")
        dict_layout.addWidget(cand_label)
        self.candidates_edit = QPlainTextEdit()
        self.candidates_edit.setObjectName("io")
        self.candidates_edit.setPlaceholderText("每行一个候选词，非空时优先于字典尝试")
        self.candidates_edit.setMinimumHeight(80)
        dict_layout.addWidget(self.candidates_edit)

        self.dict_widget.setVisible(default_mode == "dict")
        left_layout.addWidget(self.dict_widget)

        # 预测词输入框只在非字典模式下显示
        self.prefix_edit.setVisible(default_mode != "dict")
        self.suffix_edit.setVisible(default_mode != "dict")
        # 通过 form layout 的 label 行也隐藏
        for i in range(form.rowCount()):
            label = form.labelForField(self.prefix_edit) if i == form.rowCount() - 2 else None
            if label:
                label.setVisible(default_mode != "dict")
            label = form.labelForField(self.suffix_edit) if i == form.rowCount() - 1 else None
            if label:
                label.setVisible(default_mode != "dict")

        self._mode_group.buttonClicked.connect(self._on_mode_changed)

        hint = QLabel(self.theme.UI_MD5_CRASH_HINT)
        hint.setObjectName("caption")
        hint.setWordWrap(True)
        left_layout.addWidget(hint)

        self.status_label = QLabel(self._hash_idle)
        self.status_label.setObjectName("status-info")
        self.status_label.setWordWrap(True)
        left_layout.addWidget(self.status_label)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        self.start_btn = QPushButton(self.theme.UI_MD5_CRASH_BTN_START)
        self.start_btn.setObjectName("ghbtn-primary")
        self.start_btn.clicked.connect(self.on_start)
        self.stop_btn = QPushButton(self.theme.UI_MD5_CRASH_BTN_STOP)
        self.stop_btn.setObjectName("ghbtn-danger")
        self.stop_btn.clicked.connect(self.on_stop)
        self.stop_btn.setEnabled(False)
        buttons.addWidget(self.start_btn)
        buttons.addWidget(self.stop_btn)
        buttons.addStretch(1)
        left_layout.addLayout(buttons)
        left_layout.addStretch(1)

        body.addWidget(left)

        # ---- 右栏：日志区 ----
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(8)
        log_label = QLabel(self.theme.UI_MD5_CRASH_LABEL_LOG)
        log_label.setObjectName("section")
        right_layout.addWidget(log_label)
        self.log_area = QPlainTextEdit()
        self.log_area.setMaximumBlockCount(2000)  # 日志环形上限：防长扫描内存膨胀
        self.log_area.setObjectName("io")
        self.log_area.setReadOnly(True)
        right_layout.addWidget(self.log_area, stretch=1)

        body.addWidget(right, stretch=1)

    # ------------------------------------------------------------- 模式
    def _current_mode(self) -> str:
        for mode, radio in self._mode_buttons.items():
            if radio.isChecked():
                return mode
        return "mixed"

    def _on_mode_changed(self) -> None:
        is_dict = self._current_mode() == "dict"
        self.dict_widget.setVisible(is_dict)
        self.prefix_edit.setVisible(not is_dict)
        self.suffix_edit.setVisible(not is_dict)
        # 同步隐藏 form layout 中的标签
        form = self.prefix_edit.parent().layout().itemAt(0).layout()
        for i in range(form.rowCount()):
            label = form.labelForField(self.prefix_edit)
            if label:
                label.setVisible(not is_dict)
            label = form.labelForField(self.suffix_edit)
            if label:
                label.setVisible(not is_dict)

    def _sync_len_range(self) -> None:
        """约束最小长度 ≤ 最大长度，避免运行到一半才报错。"""
        low = self.min_len_edit.value()
        high = self.max_len_edit.value()
        if low > high:
            self.max_len_edit.setValue(low)

    # ------------------------------------------------------------- 字典
    def _count_dict_entries(self, files) -> int:
        """统计字典文件的总候选行数（跳过空行），用于状态行展示。"""
        total = 0
        for path in files:
            try:
                total += sum(1 for _ in md5_crash.iter_dict_words(path))
            except OSError:
                continue
        return total

    def _report_dict_ready(self, files, label: str) -> None:
        """统一的字典就绪提示：文件名 / 文件数与总条目数。"""
        count = self._count_dict_entries(files)
        self._set_status(
            self.theme.UI_MD5_CRASH_DICT_SELECTED.format(
                count=len(files), entries=count, name=label
            )
        )

    def on_choose_dict(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, self.theme.UI_MD5_CRASH_BTN_DICT_CHOOSE, "",
            "字典文件 (*.txt *.dict);;所有文件 (*.*)",
        )
        if not path:
            return
        try:
            files = md5_crash.parse_dict_path(path)
        except ValueError as exc:
            prefix = self.theme.ALGO_MD5_CRASH + self.theme.UI_SUFFIX_FAILED
            self._set_status(f"{prefix}：{exc}")
            return
        self._dict_path = os.path.abspath(path)
        self._report_dict_ready(files, os.path.basename(path))

    def on_use_default_dict(self) -> None:
        try:
            files = md5_crash.parse_dict_path(md5_crash.DEFAULT_DICT_DIR)
        except ValueError as exc:
            prefix = self.theme.ALGO_MD5_CRASH + self.theme.UI_SUFFIX_FAILED
            self._set_status(f"{prefix}：{exc}")
            return
        self._dict_path = md5_crash.DEFAULT_DICT_DIR
        self._report_dict_ready(files, "默认字典")

    # ------------------------------------------------------------- 交互
    def on_start(self) -> None:
        if self.cracker.running:
            return
        mode = self._current_mode()
        try:
            if mode == "dict":
                if not self._dict_path:
                    self.on_use_default_dict()
                    if not self._dict_path:
                        return  # 默认字典加载失败，状态行已提示
                candidates = [
                    line.strip()
                    for line in self.candidates_edit.toPlainText().splitlines()
                    if line.strip()
                ]
                self.cracker.start(
                    self.md5_edit.text(), None, None,
                    self.worker_edit.text(), self.thread_edit.text(),
                    charset=None, dict_path=self._dict_path,
                    candidates=candidates, hash_name=self.hash_name,
                )
            else:
                self.cracker.start(
                    self.md5_edit.text(),
                    self.min_len_edit.text(), self.max_len_edit.text(),
                    self.worker_edit.text(), self.thread_edit.text(),
                    charset=mode,
                    prefix=self.prefix_edit.text(),
                    suffix=self.suffix_edit.text(),
                    hash_name=self.hash_name,
                )
        except ValueError as exc:
            self._show_failure(exc)
            return

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self._set_status(self.theme.UI_MD5_CRASH_RUNNING)
        self.log_area.appendPlainText("")
        self._drain_logs()
        self._poll_timer.start()

    def on_stop(self) -> None:
        if not self.cracker.running:
            return
        self.cracker.stop()

    # --------------------------------------------------------- 日志轮询
    def _append_log(self, line: str) -> None:
        self.log_area.appendPlainText(line)

    def _format_log(self, kind: str, *payload) -> str:
        if kind == "info":
            return str(payload[0])
        if kind == "progress":
            return self.theme.UI_MD5_CRASH_LOG_PROGRESS.format(
                count=payload[1], text=payload[2]
            )
        if kind == "found":
            return f"命中明文：{payload[0]}"
        if kind == "done":
            return str(payload[0])
        return ""

    def _drain_logs(self) -> None:
        for log in self.cracker.poll_logs():
            line = self._format_log(*log)
            if line:
                self._append_log(line)

    def _set_status(self, text: str) -> None:
        self.status_label.setText(text)

    def _poll(self) -> None:
        self._drain_logs()
        if self.cracker.running:
            return
        self._poll_timer.stop()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

        status = self.cracker.status
        if status == md5_crash.STATUS_FOUND:
            self._append_log("")
            self._set_status(
                self.theme.UI_MD5_CRASH_FOUND.format(
                    plain=self.cracker.result,
                    cost=time.monotonic() - self.cracker.started_at,
                )
            )
        elif status == md5_crash.STATUS_STOPPED:
            self._set_status(self.theme.UI_MD5_CRASH_STOPPED)
        elif status == md5_crash.STATUS_ERROR:
            self._set_status(
                self.theme.ALGO_MD5_CRASH + self.theme.UI_SUFFIX_FAILED
                + f"：{self.cracker.error}"
            )
        else:
            self._set_status(self.theme.UI_MD5_CRASH_DONE)

    def _show_failure(self, reason) -> None:
        prefix = self.theme.ALGO_MD5_CRASH + self.theme.UI_SUFFIX_FAILED
        self._set_status(f"{prefix}：{reason}")

    def shutdown(self) -> None:
        """应用退出时调用：停止爆破，避免残留进程占用 CPU。"""
        self._poll_timer.stop()
        self.cracker.stop(wait=True, timeout=1.0)
