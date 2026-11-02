# -*- coding: utf-8 -*-
"""主机探针页（``httpscan.py`` 整合迁移，原名 httpscan）。

输入 CIDR 网段、单个 IP 或域名（如 ``192.168.1.0/24``、``example.com``，多个目标
可用空格 / 逗号分隔混填），以爬虫方式多线程探测存活 Web 主机，表格增量展示
目标 / 解析 IP / 状态码 / Web 容器 / 标题 / 最终 URL：
- 可配置线程数（默认 10）与请求超时（默认 5 秒）；
- 可选 https 探测（默认关闭，保持原脚本的 http 行为）；
- 双击结果行可查看该主机的原始 HTTP 响应头（状态行 + 逐行头字段）；
- 可随时中止扫描；结果可复制或保存为 csv 文件（含响应头列）。

网络请求放后台线程执行，发现主机经信号增量回传，不阻塞界面。
"""

from __future__ import annotations

import csv
import re
import threading
from datetime import datetime

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)
from qfluentwidgets import TableWidget

from app.widgets.no_wheel import NoWheelSpinBox
from lib import httpscan, watermark


class _ScanWorker(QThread):
    """后台执行多目标扫描，进度 / 单机结果 / 总结果经信号回传主线程。"""

    progress = Signal(str)
    found = Signal(dict)
    done_ok = Signal(list)
    done_err = Signal(str)

    def __init__(self, target: str, threads: int, timeout: int,
                 https: bool, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._target = target
        self._threads = threads
        self._timeout = timeout
        self._https = https
        self._stop = threading.Event()

    def stop(self) -> None:
        """置位停止开关，工作线程在取下一个目标前退出。"""
        self._stop.set()

    def run(self) -> None:  # noqa: D102  线程入口
        try:
            results = httpscan.run(
                self._target,
                threads=self._threads,
                timeout=self._timeout,
                https=self._https,
                progress=self.progress.emit,
                found=self.found.emit,
                stop=self._stop,
            )
        except Exception as exc:  # noqa: BLE001  后台线程兜底
            self.done_err.emit(str(exc))
            return
        self.done_ok.emit(results)


class HttpScanPage(QWidget):
    """主机探针页：CIDR 网段 / IP / 域名 Web 主机发现（原名 httpscan）。"""

    #: 表格列顺序
    COLUMNS = ("目标", "IP", "状态码", "Web容器", "标题", "URL")
    #: 结果 dict 中与 ``COLUMNS`` 一一对应的键
    KEYS = ("target", "ip", "status", "server", "title", "url")

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._worker: _ScanWorker | None = None
        self._rows: list[dict] = []
        self._build_ui()

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(36, 28, 36, 28)
        layout.setSpacing(10)

        form = QFormLayout()
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(10)

        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText(
            "目标网段 / IP / 域名，如 192.168.1.0/24、192.168.1.5 或 example.com，"
            "多个目标用空格或逗号分隔")
        form.addRow("目标", self.target_edit)

        opts = QHBoxLayout()
        opts.setSpacing(16)
        self.threads_spin = NoWheelSpinBox()
        self.threads_spin.setRange(1, 200)
        self.threads_spin.setValue(httpscan.DEFAULT_THREADS)
        opts.addWidget(QLabel("线程数"))
        opts.addWidget(self.threads_spin)
        self.timeout_spin = NoWheelSpinBox()
        self.timeout_spin.setRange(1, 60)
        self.timeout_spin.setValue(httpscan.DEFAULT_TIMEOUT)
        self.timeout_spin.setSuffix(" 秒")
        opts.addWidget(QLabel("超时"))
        opts.addWidget(self.timeout_spin)
        self.https_check = QCheckBox("https 探测（证书校验关闭）")
        self.https_check.setToolTip(
            "目标未自带协议前缀时先试 https 再试 http；\n"
            "目标自带 http:// 或 https:// 前缀时以前缀为准。")
        opts.addWidget(self.https_check)
        opts.addStretch(1)
        form.addRow("", opts)
        layout.addLayout(form)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        self.run_btn = QPushButton("开始扫描")
        self.run_btn.setObjectName("ghbtn-primary")
        self.run_btn.clicked.connect(self._start)
        buttons.addWidget(self.run_btn)
        self.stop_btn = QPushButton("停止")
        self.stop_btn.setObjectName("ghbtn")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop)
        buttons.addWidget(self.stop_btn)
        clear_btn = QPushButton("清空结果")
        clear_btn.setObjectName("ghbtn")
        clear_btn.clicked.connect(self._clear)
        buttons.addWidget(clear_btn)
        copy_btn = QPushButton("复制结果")
        copy_btn.setObjectName("ghbtn")
        copy_btn.clicked.connect(self._copy)
        buttons.addWidget(copy_btn)
        save_btn = QPushButton("保存结果…")
        save_btn.setObjectName("ghbtn")
        save_btn.clicked.connect(self._save)
        buttons.addWidget(save_btn)
        buttons.addStretch(1)
        layout.addLayout(buttons)

        self.table = TableWidget(self)
        self.table.setColumnCount(len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels(self.COLUMNS)
        self.table.setEditTriggers(TableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(TableWidget.SelectRows)
        self.table.verticalHeader().hide()
        self.table.itemDoubleClicked.connect(self._show_headers)
        header = self.table.horizontalHeader()
        for col, mode in enumerate(
                (QHeaderView.ResizeMode.Fixed,
                 QHeaderView.ResizeMode.Fixed,
                 QHeaderView.ResizeMode.Fixed,
                 QHeaderView.ResizeMode.Fixed,
                 QHeaderView.ResizeMode.Stretch,
                 QHeaderView.ResizeMode.Stretch)):
            header.setSectionResizeMode(col, mode)
        header.resizeSection(0, 180)
        header.resizeSection(1, 130)
        header.resizeSection(2, 70)
        header.resizeSection(3, 190)
        layout.addWidget(self.table, stretch=1)

        hint = QLabel("双击任意一行可查看该主机的原始 HTTP 响应头。")
        hint.setObjectName("caption")
        layout.addWidget(hint)

        self.status_label = QLabel("")
        self.status_label.setObjectName("status-info")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

    # -------------------------------------------------------------- 运行
    def _start(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._set_status(False, "扫描正在进行中，请先停止。")
            return
        target = self.target_edit.text().strip()
        if not target:
            self._set_status(
                False, "请先填写目标，如 192.168.1.0/24、192.168.1.5 或 example.com。")
            return

        self._clear(keep_status=True)
        worker = _ScanWorker(
            target,
            self.threads_spin.value(),
            self.timeout_spin.value(),
            self.https_check.isChecked(),
            self,
        )
        worker.progress.connect(lambda msg: self._set_status(True, msg))
        worker.found.connect(self._add_row)
        worker.done_ok.connect(self._on_ok)
        worker.done_err.connect(self._on_err)
        self._worker = worker
        self.run_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        worker.start()
        self._set_status(True, "扫描已开始…")

    def _stop(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._worker.stop()
            self._set_status(True, "正在停止…（等待当前请求结束）")

    def _on_err(self, message: str) -> None:
        self._reset_buttons()
        self._set_status(False, message)

    def _on_ok(self, results: list) -> None:
        self._reset_buttons()
        self._set_status(
            True, f"扫描完成：发现 {len(results)} 台存活主机，共探测 "
                  f"{self._rows_total()} 条记录。")

    def _reset_buttons(self) -> None:
        self.run_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def _rows_total(self) -> int:
        return self.table.rowCount()

    # -------------------------------------------------------------- 表格
    def _add_row(self, item: dict) -> None:
        row = self.table.rowCount()
        self.table.insertRow(row)
        for col, key in enumerate(self.KEYS):
            self.table.setItem(row, col, QTableWidgetItem(str(item.get(key, ""))))
        self._rows.append(item)

    def _show_headers(self, item: QTableWidgetItem) -> None:
        """双击结果行：弹窗展示该主机的原始 HTTP 响应头。"""
        row = item.row()
        if not (0 <= row < len(self._rows)):
            return
        data = self._rows[row]
        headers = str(data.get("headers", "")).strip()
        if not headers:
            self._set_status(False, "该主机没有可展示的响应头。")
            return
        dlg = QDialog(self.window())
        dlg.setWindowTitle(f"HTTP 响应头 — {data.get('target', '')}")
        dlg.resize(680, 480)
        box = QVBoxLayout(dlg)
        box.setContentsMargins(16, 16, 16, 16)
        box.setSpacing(10)
        info = QLabel(
            f"状态码：{data.get('status', '')}    最终 URL：{data.get('url', '')}")
        info.setObjectName("caption")
        info.setWordWrap(True)
        box.addWidget(info)
        edit = QPlainTextEdit(dlg)
        edit.setObjectName("io")
        edit.setReadOnly(True)
        edit.setPlainText(headers)
        box.addWidget(edit, stretch=1)
        btn_row = QHBoxLayout()
        btn_row.addStretch(1)
        copy_btn = QPushButton("复制响应头")
        copy_btn.setObjectName("ghbtn")
        copy_btn.clicked.connect(
            lambda: QApplication.clipboard().setText(headers))
        btn_row.addWidget(copy_btn)
        close_btn = QPushButton("关闭")
        close_btn.setObjectName("ghbtn")
        close_btn.clicked.connect(dlg.accept)
        btn_row.addWidget(close_btn)
        box.addLayout(btn_row)
        dlg.exec()

    def _clear(self, keep_status: bool = False) -> None:
        self.table.setRowCount(0)
        self._rows.clear()
        if not keep_status:
            self._set_status(True, "结果已清空。")

    # -------------------------------------------------------------- 导出
    def _copy(self) -> None:
        if not self._rows:
            self._set_status(False, "还没有可复制的结果，请先开始扫描。")
            return
        lines = ["\t".join(self.COLUMNS)]
        for item in self._rows:
            lines.append("\t".join(
                str(item.get(key, "")).replace("\t", " ").replace("\n", " ")
                for key in self.KEYS))
        QApplication.clipboard().setText("\n".join(lines))
        self._set_status(True, f"已复制 {len(self._rows)} 条结果到剪贴板。")

    def _save(self) -> None:
        if not self._rows:
            self._set_status(False, "还没有可保存的结果，请先开始扫描。")
            return
        target = self.target_edit.text().strip().replace("/", "_").replace("\\", "_")
        target = re.sub(r"[\s,;]+", "_", target)[:40]  # 多目标输入时保证文件名可用
        cfg = self.store.get("watermark", default={}) or {}
        out_dir = watermark.resolve_output_dir(cfg.get("output_dir"))
        default = str(out_dir / f"httpscan_{target or 'result'}_"
                                f"{datetime.now():%Y%m%d_%H%M%S}.csv")
        path, _ = QFileDialog.getSaveFileName(
            self, "保存扫描结果", default, "CSV 文件 (*.csv)")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as fp:
                writer = csv.writer(fp)
                writer.writerow([*self.COLUMNS, "响应头"])
                for item in self._rows:
                    writer.writerow(
                        [str(item.get(key, "")) for key in self.KEYS]
                        + [str(item.get("headers", ""))])
        except OSError as exc:
            self._set_status(False, f"保存失败：{exc}")
            return
        self._set_status(True, f"已保存 {len(self._rows)} 条结果：{path}")

    # -------------------------------------------------------------- 杂项
    def _set_status(self, ok: bool, text: str) -> None:
        self.status_label.setText(text)
        self.status_label.setObjectName("status-err" if not ok else "status-info")
        self.style().unpolish(self.status_label)
        self.style().polish(self.status_label)

    def shutdown(self) -> None:
        """退出前请求停止扫描线程（closeEvent 调用）。"""
        if self._worker is not None and self._worker.isRunning():
            self._worker.stop()
