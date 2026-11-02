# -*- coding: utf-8 -*-
"""微信公众号 AppID / AppSecret 校验页。

对一组或多组 appid 与 appsecret 调用微信公众平台「获取 access_token」接口，
判断凭证是否有效：有效则回显 access_token 与有效期，无效则回显错误码与原因。

- 单组校验：在「AppID / AppSecret」两个输入框填入后点「校验」；
- 批量校验：在「批量输入」区按行填入 ``appid secret``（支持冒号 / 逗号分隔），
  逐条顺序请求，结果汇总到表格，可复制 / 导出 CSV。

网络请求放后台线程执行，进度经信号回传主线程，不阻塞界面。
"""

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
from lib import wechat_check, watermark


class _WechatWorker(QThread):
    """后台执行微信凭证校验，进度与结果经信号回传主线程。"""

    progress = Signal(str)
    done_ok = Signal(object)   # list[wechat_check.CheckResult]
    done_err = Signal(str)

    def __init__(self, pairs, timeout: int, parent=None) -> None:
        super().__init__(parent)
        self._pairs = pairs
        self._timeout = timeout
        self._stop = threading.Event()

    def stop(self) -> None:
        """置位停止开关，工作线程在下一条请求前退出。"""
        self._stop.set()

    def run(self) -> None:  # noqa: D102  线程入口
        try:
            results = wechat_check.check_many(
                self._pairs,
                timeout=self._timeout,
                progress=self.progress.emit,
                stop=self._stop,
            )
        except Exception as exc:  # noqa: BLE001  后台线程兜底
            self.done_err.emit(str(exc))
            return
        self.done_ok.emit(results)


class WechatPage(QWidget):
    """微信公众号 AppID / AppSecret 校验页。"""

    COLUMNS = ("AppID", "状态", "AccessToken", "有效期(秒)", "错误码", "错误信息")

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._worker: _WechatWorker | None = None
        self._rows: list[dict] = []
        self._build_ui()
        self._load_config()

    def _load_config(self) -> None:
        """把 store 中保存的超时配置回填到数字框。"""
        cfg = self.store.get("wechat_check", default={}) or {}
        try:
            timeout = int(cfg.get("timeout", wechat_check.DEFAULT_TIMEOUT))
        except (TypeError, ValueError):
            timeout = wechat_check.DEFAULT_TIMEOUT
        self.timeout_spin.setValue(timeout)

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(36, 28, 36, 28)
        layout.setSpacing(10)

        form = QFormLayout()
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(10)

        self.appid_edit = QLineEdit()
        self.appid_edit.setPlaceholderText("公众号 AppID，如 wx1234567890abcdef")
        form.addRow("AppID", self.appid_edit)

        self.secret_edit = QLineEdit()
        self.secret_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.secret_edit.setPlaceholderText("公众号 AppSecret")
        form.addRow("AppSecret", self.secret_edit)

        opts = QHBoxLayout()
        opts.setSpacing(16)
        self.timeout_spin = NoWheelSpinBox()
        self.timeout_spin.setRange(3, 120)
        self.timeout_spin.setValue(wechat_check.DEFAULT_TIMEOUT)
        self.timeout_spin.setSuffix(" 秒")
        opts.addWidget(QLabel("超时"))
        opts.addWidget(self.timeout_spin)
        opts.addStretch(1)
        form.addRow("", opts)
        layout.addLayout(form)

        layout.addWidget(QLabel("批量输入（可选，每行一组 appid secret）"))
        self.batch_edit = QTextEdit()
        self.batch_edit.setObjectName("io")
        self.batch_edit.setFixedHeight(96)
        self.batch_edit.setPlaceholderText(
            "wx1234567890abcdef secretxxxxxxxx\n"
            "wx2233445566778899:secretxxxxxxxx\n"
            "wxaaaaaaaaaaaaaaaa,secretxxxxxxxx")
        layout.addWidget(self.batch_edit)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        self.run_btn = QPushButton("开始校验")
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
        for col in range(len(self.COLUMNS)):
            header.setSectionResizeMode(col, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header.resizeSection(0, 190)
        layout.addWidget(self.table, stretch=1)

        self.status_label = QLabel("")
        self.status_label.setObjectName("status-info")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

    # -------------------------------------------------------------- 运行
    def _start(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._set_status(False, "校验正在进行中，请先停止。")
            return

        pairs = []
        single = (
            self.appid_edit.text().strip(),
            self.secret_edit.text().strip(),
        )
        if single[0] or single[1]:
            pairs.append(single)
        pairs.extend(wechat_check.parse_inputs(self.batch_edit.toPlainText()))

        if not pairs:
            self._set_status(False, "请填写 AppID / AppSecret，或在批量区输入凭证。")
            return

        self._clear(keep_status=True)
        worker = _WechatWorker(pairs, self.timeout_spin.value(), self)
        worker.progress.connect(lambda msg: self._set_status(True, msg))
        worker.done_ok.connect(self._on_ok)
        worker.done_err.connect(self._on_err)
        self._worker = worker
        self.run_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        worker.start()
        self._set_status(True, f"正在校验 {len(pairs)} 组凭证…")

    def _stop(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._worker.stop()
            self._set_status(True, "正在停止…（等待当前请求结束）")

    def _on_err(self, message: str) -> None:
        self._reset_buttons()
        self._set_status(False, message)

    def _on_ok(self, results) -> None:
        self._reset_buttons()
        for result in results:
            self._append_row(result)
        valid = sum(1 for r in results if r.valid)
        self._set_status(
            True, f"校验完成：共 {len(results)} 组，有效 {valid} 组。")

    def _reset_buttons(self) -> None:
        self.run_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    # -------------------------------------------------------------- 表格
    def _append_row(self, result: wechat_check.CheckResult) -> None:
        if result.valid:
            values = [
                result.appid, "有效", result.access_token,
                str(result.expires_in), "", "",
            ]
        else:
            values = [
                result.appid, "无效", "",
                "", str(result.errcode or ""), result.errmsg,
            ]
        row = self.table.rowCount()
        self.table.insertRow(row)
        for col, val in enumerate(values):
            self.table.setItem(row, col, QTableWidgetItem(val))
        self._rows.append({
            "appid": result.appid,
            "valid": result.valid,
            "access_token": result.access_token,
            "expires_in": result.expires_in,
            "errcode": result.errcode,
            "errmsg": result.errmsg,
        })

    def _clear(self, keep_status: bool = False) -> None:
        self.table.setRowCount(0)
        self._rows.clear()
        if not keep_status:
            self._set_status(True, "结果已清空。")

    # -------------------------------------------------------------- 导出
    def _row_values(self, item: dict) -> list[str]:
        if item["valid"]:
            return [
                item["appid"], "有效", item["access_token"],
                str(item["expires_in"]), "", "",
            ]
        return [
            item["appid"], "无效", "", "",
            str(item["errcode"] or ""), item["errmsg"],
        ]

    def _copy(self) -> None:
        if not self._rows:
            self._set_status(False, "还没有可复制的结果，请先开始校验。")
            return
        lines = ["\t".join(self.COLUMNS)]
        for item in self._rows:
            lines.append("\t".join(self._row_values(item)))
        QApplication.clipboard().setText("\n".join(lines))
        self._set_status(True, f"已复制 {len(self._rows)} 条结果到剪贴板。")

    def _save(self) -> None:
        if not self._rows:
            self._set_status(False, "还没有可保存的结果，请先开始校验。")
            return
        cfg = self.store.get("watermark", default={}) or {}
        out_dir = watermark.resolve_output_dir(cfg.get("output_dir"))
        default = str(out_dir / f"wechat_{datetime.now():%Y%m%d_%H%M%S}.csv")
        path, _ = QFileDialog.getSaveFileName(
            self, "保存校验结果", default, "CSV 文件 (*.csv)")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as fp:
                writer = csv.writer(fp)
                writer.writerow(self.COLUMNS)
                for item in self._rows:
                    writer.writerow(self._row_values(item))
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
        """退出前请求停止校验线程（closeEvent 调用）。"""
        if self._worker is not None and self._worker.isRunning():
            self._worker.stop()
