# -*- coding: utf-8 -*-
"""SSTI 子类枚举 & RCE 可达性检测页。

遍历目标模板引擎 ``object.__subclasses__()`` 的每个子类，检查其
``__init__.__globals__`` 中是否含 ``os`` / ``system`` / ``popen`` / ``eval`` /
``__builtins__``，命中即认为该子类提供 RCE 路径，输出索引、类名、命中键，
并给出利用 payload。

仅限授权靶场 / 渗透测试环境使用，请勿用于未授权目标。

网络请求放后台线程执行，进度经信号回传主线程，不阻塞界面。
"""

from __future__ import annotations

import threading

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
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

from app.widgets.no_wheel import NoWheelComboBox, NoWheelSpinBox
from app.widgets.responsive import ScrollColumn, guard_min_heights
from lib import ssti_finder


class _SSTIWorker(QThread):
    """后台执行 SSTI 检测，进度 / 结果 / 结束经信号回传主线程。"""

    progress = Signal(str)
    done_ok = Signal(object)   # ssti_finder.SSTIReport
    done_err = Signal(str)

    def __init__(self, cfg: dict, parent=None) -> None:
        super().__init__(parent)
        self._cfg = cfg
        self._stop = threading.Event()

    def stop(self) -> None:
        """请求中止：当前阶段结束后提前退出。"""
        self._stop.set()

    def run(self) -> None:  # noqa: D102  线程入口
        try:
            report = ssti_finder.run(
                self._cfg["url"],
                self._cfg["param"],
                method=self._cfg["method"],
                data=self._cfg["data"],
                cookie=self._cfg["cookie"],
                headers=self._cfg["headers"],
                proxy=self._cfg["proxy"],
                prefix=self._cfg["prefix"],
                timeout=self._cfg["timeout"],
                enum_all=self._cfg["enum_all"],
                progress=self.progress.emit,
                stop=self._stop,
            )
        except ssti_finder.SSTIFinderError as exc:
            self.done_err.emit(str(exc))
            return
        except Exception as exc:  # noqa: BLE001  后台线程兜底
            self.done_err.emit(f"检测失败：{exc}")
            return
        self.done_ok.emit(report)


class SstiPage(QWidget):
    """SSTI 子类枚举 & RCE 可达性检测页。"""

    COLUMNS = ("索引", "子类名", "命中键")

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._worker: _SSTIWorker | None = None
        self._hits: list[ssti_finder.RceHit] = []
        self._prefix = ssti_finder.DEFAULT_PREFIX
        self._build_ui()

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(36, 28, 36, 28)
        layout.setSpacing(10)

        # -- 目标与请求配置（放进滚动区：小屏下变高滚动，而不是压扁输入框）--
        self.config_scroll = ScrollColumn()
        form = self.config_scroll.form()

        self.url_edit = QLineEdit()
        self.url_edit.setPlaceholderText("目标 URL，如 http://10.0.0.5:5000/")
        form.addRow("目标 URL", self.url_edit)

        self.param_edit = QLineEdit()
        self.param_edit.setPlaceholderText("注入参数名，如 name / q / page")
        form.addRow("注入参数", self.param_edit)

        method_row = QHBoxLayout()
        method_row.setSpacing(12)
        self.method_combo = NoWheelComboBox()
        self.method_combo.addItem("GET", "GET")
        self.method_combo.addItem("POST", "POST")
        method_row.addWidget(self.method_combo)
        self.enum_check = QCheckBox("额外枚举全部子类")
        self.enum_check.setChecked(True)
        method_row.addWidget(self.enum_check)
        self.timeout_spin = NoWheelSpinBox()
        self.timeout_spin.setRange(3, 120)
        self.timeout_spin.setValue(ssti_finder.DEFAULT_TIMEOUT)
        self.timeout_spin.setSuffix(" 秒")
        method_row.addWidget(QLabel("超时"))
        method_row.addWidget(self.timeout_spin)
        method_row.addStretch(1)
        form.addRow("请求方式", method_row)

        self.data_edit = QLineEdit()
        self.data_edit.setPlaceholderText("附加参数，形如 page=1&size=10")
        form.addRow("附加参数", self.data_edit)

        self.cookie_edit = QLineEdit()
        self.cookie_edit.setPlaceholderText("Cookie，如 session=abc123")
        form.addRow("Cookie", self.cookie_edit)

        self.proxy_edit = QLineEdit()
        self.proxy_edit.setPlaceholderText("代理，如 http://127.0.0.1:8080")
        form.addRow("代理", self.proxy_edit)

        self.prefix_edit = QLineEdit()
        self.prefix_edit.setPlaceholderText(ssti_finder.DEFAULT_PREFIX)
        form.addRow("Object 前缀", self.prefix_edit)


        self.headers_edit = QPlainTextEdit()
        self.headers_edit.setObjectName("io")
        self.headers_edit.setMinimumHeight(56)
        self.headers_edit.setPlaceholderText("X-Custom-Header: value")
        self.headers_edit_label = QLabel("自定义请求头（可选，每行一个 Key: Value）")
        self.config_scroll.add_widget(self.headers_edit_label)
        self.config_scroll.add_widget(self.headers_edit)
        layout.addWidget(self.config_scroll, 1)

        # -- 操作按钮 --
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
        copy_btn = QPushButton("复制 Payload")
        copy_btn.setObjectName("ghbtn")
        copy_btn.clicked.connect(self._copy_payload)
        buttons.addWidget(copy_btn)
        buttons.addStretch(1)
        layout.addLayout(buttons)

        # -- 结果表格（RCE 命中子类） --
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
        header.resizeSection(0, 70)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        header.resizeSection(2, 180)
        layout.addWidget(self.table, stretch=1)

        # -- 利用 payload 输出 --
        layout.addWidget(QLabel("利用 Payload（把 id 换成需要的命令）"))
        self.payload_edit = QPlainTextEdit()
        self.payload_edit.setObjectName("io")
        self.payload_edit.setReadOnly(True)
        self.payload_edit.setMinimumHeight(90)
        self.payload_edit.setPlaceholderText("检测到 RCE 子类后，此处显示利用 payload。")
        layout.addWidget(self.payload_edit)

        self.status_label = QLabel("")
        self.status_label.setObjectName("status-info")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        guard_min_heights(self)

    # -------------------------------------------------------------- 运行
    def _gather_cfg(self) -> dict:
        return {
            "url": self.url_edit.text().strip(),
            "param": self.param_edit.text().strip(),
            "method": self.method_combo.currentData(),
            "data": self.data_edit.text().strip(),
            "cookie": self.cookie_edit.text().strip(),
            "headers": self.headers_edit.toPlainText(),
            "proxy": self.proxy_edit.text().strip(),
            "prefix": self.prefix_edit.text().strip()
                      or ssti_finder.DEFAULT_PREFIX,
            "timeout": self.timeout_spin.value(),
            "enum_all": self.enum_check.isChecked(),
        }

    def _start(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._set_status(False, "检测正在进行中，请先停止。")
            return
        cfg = self._gather_cfg()
        if not cfg["url"]:
            self._set_status(False, "请先填写目标 URL。")
            return
        if not cfg["param"]:
            self._set_status(False, "请先填写注入参数名。")
            return

        self._prefix = cfg["prefix"]
        self._clear(keep_status=True)
        worker = _SSTIWorker(cfg, self)
        worker.progress.connect(lambda msg: self._set_status(True, msg))
        worker.done_ok.connect(self._on_ok)
        worker.done_err.connect(self._on_err)
        self._worker = worker
        self.run_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        worker.start()
        self._set_status(True, "正在探测模板执行点…")

    def _stop(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._worker.stop()
            self._set_status(True, "正在停止…（等待当前请求结束）")

    def _on_err(self, message: str) -> None:
        self._reset_buttons()
        self._set_status(False, message)

    def _on_ok(self, report) -> None:
        self._reset_buttons()
        self._render(report)
        probe_txt = "可用" if report.probe_ok else "未确认"
        n_hits = len(report.hits)
        n_subs = len(report.subclasses)
        msg = f"检测完成：模板执行点 {probe_txt}；"
        if n_subs:
            msg += f"共 {n_subs} 个子类；"
        msg += f"发现 {n_hits} 个具备 RCE 能力的子类。"
        if not report.probe_ok:
            msg += "（探活未命中，请检查参数名 / 请求方式 / 前缀）"
        self._set_status(n_hits > 0, msg)

    def _reset_buttons(self) -> None:
        self.run_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    # -------------------------------------------------------------- 渲染
    def _render(self, report) -> None:
        self.table.setRowCount(0)
        self._hits = []
        self.payload_edit.clear()

        lines = []
        for hit in sorted(report.hits, key=lambda h: h.index):
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(str(hit.index)))
            self.table.setItem(row, 1, QTableWidgetItem(hit.name))
            self.table.setItem(row, 2, QTableWidgetItem(",".join(hit.keys)))
            self._hits.append(hit)

            lines.append(f"# [{hit.index}] {hit.name}  (命中: {','.join(hit.keys)})")
            for tip in ssti_finder.build_rce_payload(
                    self._prefix, hit.index, hit.keys):
                lines.append("  " + tip)
            lines.append("")

        if not report.hits:
            lines.append(
                "# 未发现具备 os/eval RCE 能力的子类。\n"
                "# 提示：可勾选「额外枚举全部子类」查看全部子类，人工翻找；\n"
                "# 或尝试更换 Object 前缀指向 object 类的其它路径。")

        self.payload_edit.setPlainText("\n".join(lines))

        # 额外展示全部子类（若枚举了）
        if report.subclasses:
            subs_lines = ["# 全部子类（索引: 类名）"]
            for idx in sorted(report.subclasses):
                subs_lines.append(f"[{idx:3d}] {report.subclasses[idx]}")
            self.payload_edit.setPlainText(
                self.payload_edit.toPlainText()
                + "\n\n" + "\n".join(subs_lines))

    def _clear(self, keep_status: bool = False) -> None:
        self.table.setRowCount(0)
        self._hits = []
        self.payload_edit.clear()
        if not keep_status:
            self._set_status(True, "结果已清空。")

    # -------------------------------------------------------------- 导出
    def _copy_payload(self) -> None:
        text = self.payload_edit.toPlainText().strip()
        if not text:
            self._set_status(False, "还没有可复制的 payload，请先开始检测。")
            return
        QApplication.clipboard().setText(text)
        self._set_status(True, "已复制 payload 到剪贴板。")

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
