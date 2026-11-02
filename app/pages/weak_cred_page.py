# -*- coding: utf-8 -*-
"""通用弱口令检测页（Redis / FTP / SSH banner）。

合规设计（与 MySQL 弱口令一致）：内网目标可爆破，公网 / 域名仅做被动指纹。
服务选择：
- Redis：爆破密码（含空密码检测）；
- FTP：用户名 × 密码爆破；
- SSH：仅被动 banner 指纹（不爆破）。

后台线程执行，界面不阻塞。
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFormLayout,
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
from app.widgets.no_wheel import NoWheelSpinBox
from lib import weak_cred


class _WeakCredWorker(FuzzWorker):
    """后台执行弱口令检测。"""

    error_prefix = "检测失败"

    def __init__(self, host: str, service: str, port: int,
                 users: list[str], passwords: list[str],
                 threads: int, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._host = host
        self._service = service
        self._port = port
        self._users = users
        self._passwords = passwords
        self._threads = threads

    def task(self) -> dict:
        return weak_cred.brute(
            self._host, self._service, self._users, self._passwords,
            port=self._port, threads=self._threads,
            log=self.log.emit, stop=self._event)


class WeakCredPage(QWidget):
    """通用弱口令检测页。"""

    COLUMNS = ("服务", "用户名", "密码", "状态", "说明")

    SERVICES = (
        (weak_cred.SVC_REDIS, "Redis"),
        (weak_cred.SVC_FTP, "FTP"),
        (weak_cred.SVC_SSH, "SSH（仅 banner 指纹）"),
    )

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._worker: _WeakCredWorker | None = None
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

        form = QFormLayout()
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(10)

        self.service_combo = QComboBox()
        for value, label in self.SERVICES:
            self.service_combo.addItem(label, value)
        self.service_combo.currentIndexChanged.connect(self._on_service_changed)
        form.addRow("服务类型", self.service_combo)

        self.host_edit = QLineEdit()
        self.host_edit.setPlaceholderText("目标 IP / 域名，如 127.0.0.1")
        form.addRow("目标", self.host_edit)

        self.port_spin = NoWheelSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(weak_cred.DEFAULT_PORTS[weak_cred.SVC_REDIS])
        form.addRow("端口", self.port_spin)

        self.user_edit = QLineEdit()
        self.user_edit.setPlaceholderText("FTP 用户名（逗号分隔，Redis 忽略）")
        form.addRow("用户名", self.user_edit)

        self.pwd_edit = QLineEdit()
        self.pwd_edit.setPlaceholderText(
            "密码（逗号分隔，留空用内置常用弱口令）")
        form.addRow("密码", self.pwd_edit)

        self.threads_spin = NoWheelSpinBox()
        self.threads_spin.setRange(1, 64)
        self.threads_spin.setValue(weak_cred.DEFAULT_THREADS)
        form.addRow("线程数", self.threads_spin)

        layout.addLayout(form)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        self.run_btn = QPushButton("开始检测")
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
        self.copy_btn = QPushButton("复制结果")
        self.copy_btn.setObjectName("ghbtn")
        self.copy_btn.clicked.connect(self._copy)
        buttons.addWidget(self.copy_btn)
        buttons.addStretch(1)
        layout.addLayout(buttons)

        self.table = TableWidget(self)
        self.table.setColumnCount(len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels(self.COLUMNS)
        header = self.table.horizontalHeader()
        for i in range(len(self.COLUMNS) - 1):
            header.setSectionResizeMode(i, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(len(self.COLUMNS) - 1,
                                    QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table, stretch=1)

        self.status_label = QLabel("")
        self.status_label.setObjectName("status-info")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

    def _on_service_changed(self) -> None:
        service = self.service_combo.currentData()
        self.port_spin.setValue(weak_cred.DEFAULT_PORTS.get(service, 0))
        self.user_edit.setEnabled(service == weak_cred.SVC_FTP)

    # ------------------------------------------------------------------ 操作
    def _start(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._set_status(False, "检测正在进行中，请先停止。")
            return
        host = self.host_edit.text().strip()
        if not host:
            self._set_status(False, "请填写目标 IP / 域名。")
            return
        service = self.service_combo.currentData()
        port = self.port_spin.value()
        users = weak_cred.parse_list(self.user_edit.text()) \
            if service == weak_cred.SVC_FTP else []
        passwords = weak_cred.parse_list(self.pwd_edit.text()) \
            or list(weak_cred.DEFAULT_PASSWORDS)
        threads = self.threads_spin.value()

        self._clear(keep_status=True)
        self.run_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self._set_status(True, "正在检测弱口令…（仅限授权内网目标）")

        worker = _WeakCredWorker(host, service, port, users, passwords,
                                 threads, self)
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
        if not keep_status:
            self._set_status(True, "")

    def _on_done(self, result: dict) -> None:
        self._reset_buttons()
        service = result.get("service", "")
        hits = result.get("hits") or []
        probe = result.get("probe")
        # SSH / 公网目标走 probe 分支：展示 banner
        if probe and not hits:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(
                weak_cred.SVC_LABELS.get(service, service)))
            self.table.setItem(row, 1, QTableWidgetItem(""))
            self.table.setItem(row, 2, QTableWidgetItem(""))
            self.table.setItem(row, 3, QTableWidgetItem(str(probe.get("state", ""))))
            self.table.setItem(row, 4, QTableWidgetItem(
                str(probe.get("message", "") or probe.get("banner", ""))))
            self._set_status(True, f"探测完成：{probe.get('message', '')}")
            return
        for item in hits:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(
                weak_cred.SVC_LABELS.get(service, service)))
            self.table.setItem(row, 1, QTableWidgetItem(str(item.get("user", ""))))
            self.table.setItem(row, 2, QTableWidgetItem(str(item.get("password", ""))))
            self.table.setItem(row, 3, QTableWidgetItem(
                weak_cred.STATE_LABELS.get(item.get("state"), item.get("state", ""))))
            self.table.setItem(row, 4, QTableWidgetItem(str(item.get("message", ""))))
        self._set_status(True, f"检测完成：命中 {len(hits)} 组弱口令。")

    def _on_error(self, message: str) -> None:
        self._reset_buttons()
        self._set_status(False, message)

    def _reset_buttons(self) -> None:
        self.run_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def _copy(self) -> None:
        rows = self.table.rowCount()
        if rows == 0:
            self._set_status(False, "还没有可复制的结果，请先检测。")
            return
        lines = ["\t".join(self.COLUMNS)]
        for row in range(rows):
            cells = []
            for col in range(len(self.COLUMNS)):
                item = self.table.item(row, col)
                cells.append(item.text() if item else "")
            lines.append("\t".join(cells))
        QApplication.clipboard().setText("\n".join(lines))
        self._set_status(True, f"已复制 {rows} 条结果到剪贴板。")

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