# -*- coding: utf-8 -*-
from __future__ import annotations

import csv
import threading
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)
from qfluentwidgets import TableWidget

from app.widgets.no_wheel import NoWheelSpinBox
from lib import ping_probe, watermark


class _PingWorker(QThread):
    """后台执行多地 Ping 检测（支持单目标 / 批量），进度与结果经信号回传。"""

    progress = Signal(str)
    done_ok = Signal(object)   # 单目标: PingReport；批量: list[PingReport]
    done_err = Signal(str)

    def __init__(self, hosts: list[str], cfg: dict, parent=None) -> None:
        super().__init__(parent)
        self._hosts = hosts
        self._cfg = cfg
        self._stop = threading.Event()

    def stop(self) -> None:
        """置位停止开关，工作线程在发下一个请求前退出。"""
        self._stop.set()

    def run(self) -> None:  # noqa: D102  线程入口
        try:
            if len(self._hosts) == 1:
                report = ping_probe.run_ping(
                    self._hosts[0],
                    base_url=self._cfg["base_url"],
                    api_id=self._cfg["api_id"],
                    api_key=self._cfg["api_key"],
                    dy=self._cfg["dy"],
                    extra_headers=self._cfg["headers"],
                    timeout=self._cfg["timeout"],
                    progress=self.progress.emit,
                    stop=self._stop,
                )
            else:
                report = ping_probe.run_ping_batch(
                    self._hosts,
                    base_url=self._cfg["base_url"],
                    api_id=self._cfg["api_id"],
                    api_key=self._cfg["api_key"],
                    dy=self._cfg["dy"],
                    extra_headers=self._cfg["headers"],
                    timeout=self._cfg["timeout"],
                    progress=self.progress.emit,
                    stop=self._stop,
                )
        except Exception as exc:  # noqa: BLE001  后台线程兜底
            self.done_err.emit(str(exc))
            return
        self.done_ok.emit(report)


class PingPage(QWidget):
    """多地 Ping 页：全球 / 国内多节点 ICMP 延迟检测。"""

    #: 表格列顺序（「目标」列用于批量模式区分不同主机）
    COLUMNS = ("目标", "节点地区", "解析 IP", "延迟(ms)", "线路", "状态")

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._worker: _PingWorker | None = None
        self._rows: list[dict] = []
        #: 批量检测的文件路径（空串 = 未选择，单目标模式）
        self._batch_path = ""
        self._build_ui()
        self._load_api_config()

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(36, 28, 36, 28)
        layout.setSpacing(10)

        form = QFormLayout()
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(10)

        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText("目标主机，如 example.com 或 1.1.1.1")
        form.addRow("目标", self.target_edit)

        batch_row = QHBoxLayout()
        batch_row.setSpacing(8)
        self.batch_btn = QPushButton("批量检测…")
        self.batch_btn.setObjectName("ghbtn")
        self.batch_btn.setToolTip("选择文件批量检测，文件内一行一个主机（默认格式）")
        self.batch_btn.clicked.connect(self._choose_batch_file)
        batch_row.addWidget(self.batch_btn)
        self.batch_path_edit = QLineEdit()
        self.batch_path_edit.setReadOnly(True)
        self.batch_path_edit.setPlaceholderText("未选择批量文件（一行一个主机）")
        batch_row.addWidget(self.batch_path_edit, stretch=1)
        self.batch_clear_btn = QPushButton("清除批量")
        self.batch_clear_btn.setObjectName("ghbtn")
        self.batch_clear_btn.clicked.connect(self._clear_batch)
        batch_row.addWidget(self.batch_clear_btn)
        form.addRow("批量模式", batch_row)

        opts = QHBoxLayout()
        opts.setSpacing(16)
        self.timeout_spin = NoWheelSpinBox()
        self.timeout_spin.setRange(5, 120)
        self.timeout_spin.setValue(ping_probe.DEFAULT_TIMEOUT)
        self.timeout_spin.setSuffix(" 秒")
        opts.addWidget(QLabel("超时"))
        opts.addWidget(self.timeout_spin)
        opts.addStretch(1)
        form.addRow("", opts)
        layout.addLayout(form)

        # -- API 设置折叠区（预留可编辑接口） --
        api_row = QHBoxLayout()
        self.api_toggle_btn = QPushButton("API 设置 ▸")
        self.api_toggle_btn.setObjectName("ghbtn")
        self.api_toggle_btn.setCheckable(True)
        self.api_toggle_btn.clicked.connect(self._toggle_api)
        api_row.addWidget(self.api_toggle_btn)
        api_row.addStretch(1)
        layout.addLayout(api_row)

        self.api_box = QWidget()
        api_layout = QVBoxLayout(self.api_box)
        api_layout.setContentsMargins(0, 0, 0, 0)
        api_layout.setSpacing(8)

        api_hint = QLabel(
            "默认使用接口盒子公共示例 ID / KEY（免费，共享每分钟频次）。如需独享频次，"
            "请到 www.apihz.cn 注册获取自己的 ID 与 KEY 后填入；也可经网关中转或"
            "更换兼容服务（地址、dy 参数、自定义 Header）。")
        api_hint.setObjectName("caption")
        api_hint.setWordWrap(True)
        api_layout.addWidget(api_hint)

        api_form = QFormLayout()
        api_form.setHorizontalSpacing(12)
        api_form.setVerticalSpacing(8)
        self.api_base_edit = QLineEdit()
        self.api_base_edit.setPlaceholderText(ping_probe.DEFAULT_BASE_URL)
        api_form.addRow("API 地址", self.api_base_edit)
        self.api_id_edit = QLineEdit()
        self.api_id_edit.setPlaceholderText(ping_probe.DEFAULT_API_ID)
        api_form.addRow("用户 ID", self.api_id_edit)
        self.api_key_edit = QLineEdit()
        self.api_key_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.api_key_edit.setPlaceholderText(ping_probe.DEFAULT_API_KEY)
        api_form.addRow("通讯密钥", self.api_key_edit)
        self.dy_edit = QLineEdit()
        self.dy_edit.setPlaceholderText(ping_probe.DEFAULT_DY)
        api_form.addRow("dy 参数", self.dy_edit)
        api_layout.addLayout(api_form)

        api_layout.addWidget(QLabel("自定义 Header（可选，每行一个 Key: Value）"))
        self.headers_edit = QTextEdit()
        self.headers_edit.setObjectName("io")
        self.headers_edit.setFixedHeight(56)
        self.headers_edit.setPlaceholderText("X-Custom-Header: value")
        api_layout.addWidget(self.headers_edit)

        api_save = QHBoxLayout()
        api_save.setSpacing(8)
        save_api_btn = QPushButton("保存 API 配置")
        save_api_btn.setObjectName("ghbtn-primary")
        save_api_btn.clicked.connect(self._save_api_config)
        api_save.addWidget(save_api_btn)
        api_save.addStretch(1)
        api_layout.addLayout(api_save)

        self.api_box.hide()
        layout.addWidget(self.api_box)

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
        header = self.table.horizontalHeader()
        for col, mode in enumerate(
                (QHeaderView.ResizeMode.Fixed,       # 目标
                 QHeaderView.ResizeMode.Stretch,     # 节点地区
                 QHeaderView.ResizeMode.Fixed,       # 解析 IP
                 QHeaderView.ResizeMode.Fixed,       # 延迟
                 QHeaderView.ResizeMode.Fixed,       # 线路
                 QHeaderView.ResizeMode.Fixed)):     # 状态
            header.setSectionResizeMode(col, mode)
        for col, width in ((0, 160), (2, 130), (3, 90), (4, 130), (5, 90)):
            header.resizeSection(col, width)
        layout.addWidget(self.table, stretch=1)

        self.status_label = QLabel("")
        self.status_label.setObjectName("status-info")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

    # ----------------------------------------------------------- API 配置
    def _toggle_api(self, checked: bool) -> None:
        self.api_box.setVisible(bool(checked))
        self.api_toggle_btn.setText("API 设置 ▾" if checked else "API 设置 ▸")

    def _choose_batch_file(self) -> None:
        """选择批量检测文件（一行一个主机）。"""
        path, _ = QFileDialog.getOpenFileName(
            self, "选择批量检测文件", "",
            "文本文件 (*.txt *.list);;所有文件 (*)")
        if not path:
            return
        self._batch_path = path
        self.batch_path_edit.setText(path)
        self._set_status(True, f"已选择批量文件：{path}（一行一个主机）")

    def _clear_batch(self) -> None:
        """清除批量文件，回到单目标模式。"""
        self._batch_path = ""
        self.batch_path_edit.clear()
        self._set_status(True, "已清除批量文件，回到单目标模式。")

    def _load_api_config(self) -> None:
        """把 store 中已保存的 API 配置回填到编辑框。"""
        raw = self.store.get("ping_probe", default={}) or {}
        self.api_base_edit.setText(str(raw.get("base_url", "") or ""))
        self.api_id_edit.setText(str(raw.get("api_id", "") or ""))
        self.api_key_edit.setText(str(raw.get("api_key", "") or ""))
        self.dy_edit.setText(str(raw.get("dy", "") or ""))
        self.headers_edit.setPlainText(str(raw.get("headers", "") or ""))

    def _save_api_config(self) -> None:
        """把 API 设置区当前值保存到 store（持久化）。"""
        self.store.setv(self.api_base_edit.text().strip(), "ping_probe", "base_url")
        self.store.setv(self.api_id_edit.text().strip(), "ping_probe", "api_id")
        self.store.setv(self.api_key_edit.text().strip(), "ping_probe", "api_key")
        self.store.setv(self.dy_edit.text().strip(), "ping_probe", "dy")
        self.store.setv(self.headers_edit.toPlainText(), "ping_probe", "headers")
        try:
            self.store.save()
        except OSError as exc:
            self._set_status(False, f"保存失败：{exc}")
            return
        self._set_status(True, "已保存 API 配置。")

    # -------------------------------------------------------------- 运行
    def _start(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._set_status(False, "检测正在进行中，请先停止。")
            return

        # 决定检测目标：批量模式（已选文件）或单目标模式
        if self._batch_path:
            try:
                with open(self._batch_path, "r", encoding="utf-8",
                          errors="replace") as fh:
                    hosts = ping_probe.parse_hosts_file(fh.read())
            except (OSError, ping_probe.PingProbeError) as exc:
                self._set_status(False, f"批量文件读取失败：{exc}")
                return
        else:
            host = self.target_edit.text().strip()
            if not host:
                self._set_status(False, "请先填写目标主机，或选择批量文件。")
                return
            hosts = [host]

        # 直接读取 API 设置区当前值（改了立即生效），保存按钮仅用于持久化
        cfg = {
            "base_url": self.api_base_edit.text().strip()
                        or ping_probe.DEFAULT_BASE_URL,
            "api_id": self.api_id_edit.text().strip()
                      or ping_probe.DEFAULT_API_ID,
            "api_key": self.api_key_edit.text().strip()
                       or ping_probe.DEFAULT_API_KEY,
            "dy": self.dy_edit.text().strip() or ping_probe.DEFAULT_DY,
            "headers": ping_probe.parse_headers(self.headers_edit.toPlainText()),
            "timeout": self.timeout_spin.value(),
        }

        self._clear(keep_status=True)
        worker = _PingWorker(hosts, cfg, self)
        worker.progress.connect(lambda msg: self._set_status(True, msg))
        worker.done_ok.connect(self._on_ok)
        worker.done_err.connect(self._on_err)
        self._worker = worker
        self.run_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        worker.start()
        if len(hosts) == 1:
            self._set_status(True, "正在请求多地 Ping…")
        else:
            self._set_status(True, f"正在批量检测 {len(hosts)} 个主机…")

    def _stop(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._worker.stop()
            self._set_status(True, "正在停止…（等待当前请求结束）")

    def _on_err(self, message: str) -> None:
        self._reset_buttons()
        self._set_status(False, message)

    def _on_ok(self, result) -> None:
        self._reset_buttons()
        # 单目标返回 PingReport，批量返回 list[PingReport]
        if isinstance(result, list):
            for report in result:
                self._render(report)
            ok_count = sum(1 for r in result if not r.error)
            self._set_status(
                True, f"批量检测完成：{len(result)} 个主机，"
                      f"成功 {ok_count} 个。")
        else:
            self._render(result)
            if result.error:
                self._set_status(False, f"检测失败：{result.error}")
            else:
                self._set_status(
                    True, f"检测完成：共 {len(result.nodes)} 个节点返回结果。")

    def _reset_buttons(self) -> None:
        self.run_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    # -------------------------------------------------------------- 表格
    def _row_values(self, node: dict) -> list[str]:
        region = node.get("region", "")
        if not region:
            region = " ".join(
                x for x in (node.get("country", ""), node.get("city", "")) if x)
        return [
            str(node.get("host", "")),
            region,
            str(node.get("ip", "")),
            self._fmt_ms(node.get("delay")),
            str(node.get("line", "")),
            str(node.get("status", "")),
        ]

    @staticmethod
    def _fmt_ms(value) -> str:
        return "-" if value is None else str(value)

    def _render(self, report) -> None:
        """把一次检测的节点渲染进表格（批量时多次调用，累加不覆盖）。"""
        if not report.nodes:
            # 无节点（失败或无结果）：仍插入一行占位，展示目标与失败原因
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(str(report.host)))
            if getattr(report, "error", ""):
                self.table.setItem(row, 1, QTableWidgetItem(f"失败：{report.error}"))
            self._rows.append({"host": str(report.host), "region": "",
                               "ip": "", "delay": None, "line": "",
                               "status": getattr(report, "error", "")})
            return
        for node in report.nodes:
            node_with_host = dict(node)
            node_with_host["host"] = str(report.host)
            row = self.table.rowCount()
            self.table.insertRow(row)
            values = self._row_values(node_with_host)
            for col, val in enumerate(values):
                self.table.setItem(row, col, QTableWidgetItem(val))
            self._rows.append(node_with_host)

    def _clear(self, keep_status: bool = False) -> None:
        self.table.setRowCount(0)
        self._rows.clear()
        if not keep_status:
            self._set_status(True, "结果已清空。")

    # -------------------------------------------------------------- 导出
    def _copy(self) -> None:
        if not self._rows:
            self._set_status(False, "还没有可复制的结果，请先开始检测。")
            return
        lines = ["\t".join(self.COLUMNS)]
        for node in self._rows:
            lines.append("\t".join(self._row_values(node)))
        QApplication.clipboard().setText("\n".join(lines))
        self._set_status(True, f"已复制 {len(self._rows)} 条结果到剪贴板。")

    def _save(self) -> None:
        if not self._rows:
            self._set_status(False, "还没有可保存的结果，请先开始检测。")
            return
        target = self.target_edit.text().strip().replace("/", "_").replace("\\", "_")
        cfg = self.store.get("watermark", default={}) or {}
        out_dir = watermark.resolve_output_dir(cfg.get("output_dir"))
        default = str(out_dir / f"ping_{target or 'result'}_"
                                f"{datetime.now():%Y%m%d_%H%M%S}.csv")
        path, _ = QFileDialog.getSaveFileName(
            self, "保存检测结果", default, "CSV 文件 (*.csv)")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as fp:
                writer = csv.writer(fp)
                writer.writerow(self.COLUMNS)
                for node in self._rows:
                    writer.writerow(self._row_values(node))
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
        """退出前请求停止检测线程（closeEvent 调用）。"""
        if self._worker is not None and self._worker.isRunning():
            self._worker.stop()
