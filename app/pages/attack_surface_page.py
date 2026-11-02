# -*- coding: utf-8 -*-
"""攻击面测绘页：一键全链路编排现有 Web 原子工具。

对单个目标按固定顺序跑一遍：子域名爆破 → 端口爆破 → 指纹探测 → WAF 识别 →
目录爆破 → 源码泄露 → 参数爆破 → OSS 桶探测，逐步汇总成报告。

每个步骤有独立开关（重资源步骤默认关闭），全程后台线程执行、可停止，结果
分「步骤结果表 + 汇总状态」展示，并可导出文本报告。
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)
from qfluentwidgets import TableWidget

from app.widgets.fuzz_worker import FuzzWorker
from lib import attack_surface


class _AttackSurfaceWorker(FuzzWorker):
    """后台执行攻击面测绘 pipeline。"""

    error_prefix = "测绘失败"

    def __init__(self, target: str, flags: dict, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._target = target
        self._flags = flags

    def task(self) -> dict:
        return attack_surface.run(
            self._target,
            log=self.log.emit,
            stop=self._event,
            **self._flags,
        )


class AttackSurfacePage(QWidget):
    """攻击面测绘页。"""

    COLUMNS = ("步骤", "结果", "说明")

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._worker: _AttackSurfaceWorker | None = None
        self._result: dict | None = None
        self._step_checks: dict[str, QCheckBox] = {}
        self._build_ui()

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        outer.addWidget(scroll)

        container = QWidget()
        scroll.setWidget(container)
        layout = QVBoxLayout(container)
        layout.setContentsMargins(36, 28, 36, 28)
        layout.setSpacing(10)

        form = QHBoxLayout()
        form.setSpacing(10)
        form.addWidget(QLabel("目标"))
        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText(
            "example.com 或 https://example.com")
        self.target_edit.returnPressed.connect(self._start)
        form.addWidget(self.target_edit, 1)
        layout.addLayout(form)

        # 步骤开关
        checks = QHBoxLayout()
        checks.setSpacing(12)
        for step_id, name, default, _heavy in attack_surface.STEPS:
            box = QCheckBox(name)
            box.setChecked(default)
            self._step_checks[step_id] = box
            checks.addWidget(box)
        checks.addStretch(1)
        layout.addLayout(checks)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        self.run_btn = QPushButton("开始测绘")
        self.run_btn.setObjectName("ghbtn-primary")
        self.run_btn.clicked.connect(self._start)
        buttons.addWidget(self.run_btn)
        self.stop_btn = QPushButton("停止")
        self.stop_btn.setObjectName("ghbtn")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop)
        buttons.addWidget(self.stop_btn)
        self.clear_btn = QPushButton("清空")
        self.clear_btn.setObjectName("ghbtn")
        self.clear_btn.clicked.connect(self._clear)
        buttons.addWidget(self.clear_btn)
        self.copy_btn = QPushButton("复制报告")
        self.copy_btn.setObjectName("ghbtn")
        self.copy_btn.clicked.connect(self._copy)
        buttons.addWidget(self.copy_btn)
        buttons.addStretch(1)
        layout.addLayout(buttons)

        self.table = TableWidget(self)
        self.table.setColumnCount(len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels(self.COLUMNS)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table, stretch=1)

        self.status_label = QLabel("")
        self.status_label.setObjectName("status-info")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

    # ------------------------------------------------------------------ 操作
    def _start(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._set_status(False, "测绘正在进行中，请先停止。")
            return
        target = self.target_edit.text().strip()
        if not target:
            self._set_status(False, "请填写目标，如 example.com。")
            return

        flags = {
            "with_subdomain": self._step_checks["subdomain"].isChecked(),
            "with_port": self._step_checks["port"].isChecked(),
            "with_fingerprint": self._step_checks["fingerprint"].isChecked(),
            "with_waf": self._step_checks["waf"].isChecked(),
            "with_dir": self._step_checks["dir"].isChecked(),
            "with_leak": self._step_checks["leak"].isChecked(),
            "with_param": self._step_checks["param"].isChecked(),
            "with_oss": self._step_checks["oss"].isChecked(),
        }

        self._clear(keep_status=True)
        self.run_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self._set_status(True, "正在测绘攻击面…")

        worker = _AttackSurfaceWorker(target, flags, self)
        worker.done_ok.connect(self._on_done)
        worker.done_err.connect(self._on_error)
        self._worker = worker
        worker.start()

    def _stop(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._worker.stop()
            self._set_status(True, "正在停止…")

    def _clear(self, keep_status: bool = False) -> None:
        self.table.setRowCount(0)
        self._result = None
        if not keep_status:
            self._set_status(True, "")

    def _on_done(self, result: dict) -> None:
        self._reset_buttons()
        self._result = result
        for step in result.get("steps", []):
            row = self.table.rowCount()
            self.table.insertRow(row)
            name = step.get("name", "")
            ok = step.get("ok")
            mark = "✓" if ok else "✗"
            self.table.setItem(row, 0, QTableWidgetItem(f"{mark} {name}"))
            self.table.setItem(row, 1, QTableWidgetItem(step.get("note", "")))
            self.table.setItem(row, 2, QTableWidgetItem(
                self._summarize(step.get("result"))))
        self._set_status(True, f"测绘完成，耗时 {result.get('elapsed', 0)}s。")

    def _summarize(self, result) -> str:
        """把单个步骤的结果压成一行摘要。"""
        if isinstance(result, list):
            return f"{len(result)} 条"
        if isinstance(result, dict):
            # WAF 步骤结果
            if "matches" in result:
                names = [m.get("name") for m in result.get("matches", [])]
                return "、".join(names) if names else "未发现"
        return ""

    def _on_error(self, message: str) -> None:
        self._reset_buttons()
        self._set_status(False, message)

    def _reset_buttons(self) -> None:
        self.run_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def _copy(self) -> None:
        if self._result is None:
            self._set_status(False, "还没有可复制的报告，请先测绘。")
            return
        QApplication.clipboard().setText(attack_surface.to_text(self._result))
        self._set_status(True, "报告已复制到剪贴板。")

    # ------------------------------------------------------------------ 输出
    def _set_status(self, ok: bool, text: str) -> None:
        self.status_label.setText(text)
        self.status_label.setObjectName("status-ok" if ok else "status-err")
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)

    # ------------------------------------------------------------------ 生命周期
    def shutdown(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._worker.stop()
            self._worker.wait(1500)