# -*- coding: utf-8 -*-
"""源码泄露页：输入一个域名，自动检测 .git / .svn / .DS_Store 与
敏感文件（vim .swp、.bak、.env 等）四类泄露。

整合原 ``GitHack`` / ``SvnHack`` / ``Python-dsstore`` 三个脚本，并补充
敏感文件静态探测（见 :mod:`lib.leak_scan`）：

- 用户只填域名或带目录的域名（``example.com`` / ``example.com/upload``），
  不用自己拼 ``/.git/`` 之类的尾巴，泄露类型由 :mod:`lib.leak_scan` 处理；
- 四类检测可分别勾选；git / svn 命中后源码还原到 ``output/leak/<host>/<类型>/``；
- 逐行日志实时追加，结果表按类型增量填行；可随时停止；
- 所有类型都没命中时，提示用户改走 **「目录扫描」独立工具** 继续目录爆破
  （原内嵌区域已抽成独立页面，字典 / 线程 / 请求头均可在那里配置）。

网络与解压都在后台线程（``_LeakWorker``）里跑，界面不阻塞。
"""

from __future__ import annotations

import threading
from pathlib import Path

from PySide6.QtCore import Qt, QThread, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)
from qfluentwidgets import TableWidget

from app.widgets.no_wheel import NoWheelSpinBox
from lib import leak_scan
from lib.watermark import resolve_output_dir



class _LeakWorker(QThread):
    """后台执行多类泄露检测，日志 / 结果 / 结束经信号回传主线程。"""

    log = Signal(str)
    result = Signal(dict)
    done_ok = Signal(list)
    done_err = Signal(str)

    def __init__(self, target: str, out_dir: str, kinds: list[str],
                 threads: int, timeout: int, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._target = target
        self._out_dir = out_dir
        self._kinds = kinds
        self._threads = threads
        self._timeout = timeout
        self._event = threading.Event()

    def stop(self) -> None:
        """请求中止：不再开始新的尾路径，已开始的尽快收尾。"""
        self._event.set()

    def run(self) -> None:  # noqa: D102  线程入口
        try:
            results = leak_scan.run(
                self._target,
                self._out_dir,
                kinds=self._kinds,
                threads=self._threads,
                timeout=self._timeout,
                log=self.log.emit,
                result=self.result.emit,
                stop=self._event,
            )
        except leak_scan.LeakError as exc:
            self.done_err.emit(str(exc))
            return
        except Exception as exc:  # noqa: BLE001  后台线程兜底
            self.done_err.emit(f"检测失败：{exc}")
            return
        self.done_ok.emit(results)


class LeakScanPage(QWidget):
    """源码泄露检测页（Web 信息收集分类）。"""

    COLUMNS = ("检测项", "状态", "文件数", "说明")

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._worker: _LeakWorker | None = None
        self._build_ui()
        self._apply_styles()
        self._restore_config()

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

        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText(
            "example.com 或 example.com/upload（不用自己拼 .git/ 之类的后缀）")
        self.target_edit.returnPressed.connect(self._start)
        form.addRow("目标", self.target_edit)

        kinds_row = QHBoxLayout()
        kinds_row.setSpacing(16)
        self.git_check = QCheckBox("Git（/.git/）")
        self.svn_check = QCheckBox("SVN（/.svn/）")
        self.ds_check = QCheckBox(".DS_Store")
        self.files_check = QCheckBox("敏感文件（.swp/.bak/.env 等）")
        for box in (self.git_check, self.svn_check, self.ds_check,
                    self.files_check):
            box.setChecked(True)
            kinds_row.addWidget(box)
        kinds_row.addStretch(1)
        form.addRow("检测项", kinds_row)

        opts = QHBoxLayout()
        opts.setSpacing(16)
        self.threads_spin = NoWheelSpinBox()
        self.threads_spin.setRange(1, 32)
        self.threads_spin.setValue(leak_scan.DEFAULT_THREADS)
        opts.addWidget(QLabel("线程数"))
        opts.addWidget(self.threads_spin)

        self.timeout_spin = NoWheelSpinBox()
        self.timeout_spin.setRange(1, 60)
        self.timeout_spin.setValue(leak_scan.DEFAULT_TIMEOUT)
        self.timeout_spin.setSuffix(" 秒")
        opts.addWidget(QLabel("超时"))
        opts.addWidget(self.timeout_spin)
        opts.addStretch(1)
        form.addRow("", opts)

        out_row = QHBoxLayout()
        out_row.setSpacing(8)
        self.out_edit = QLineEdit()
        self.out_edit.setPlaceholderText("输出目录（相对路径基于程序目录）")
        out_row.addWidget(self.out_edit, 1)
        browse_btn = QPushButton("浏览…")
        browse_btn.setObjectName("ghbtn")
        browse_btn.clicked.connect(self._browse_output)
        out_row.addWidget(browse_btn)
        form.addRow("输出目录", out_row)
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

        open_btn = QPushButton("打开输出目录")
        open_btn.setObjectName("ghbtn")
        open_btn.clicked.connect(self._open_output)
        buttons.addWidget(open_btn)

        clear_btn = QPushButton("清空日志")
        clear_btn.setObjectName("ghbtn")
        clear_btn.clicked.connect(self._clear_log)
        buttons.addWidget(clear_btn)
        buttons.addStretch(1)
        layout.addLayout(buttons)

        self.table = TableWidget(self)
        self.table.setColumnCount(len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels(list(self.COLUMNS))
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.verticalHeader().hide()
        self.table.setMinimumHeight(120)
        self.table.setMaximumHeight(180)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header.resizeSection(0, 160)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        header.resizeSection(1, 80)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        header.resizeSection(2, 80)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table)

        log_label = QLabel("检测日志")
        log_label.setObjectName("section")
        layout.addWidget(log_label)

        self.log_view = QPlainTextEdit()
        self.log_view.setObjectName("io")
        self.log_view.setReadOnly(True)
        self.log_view.setMinimumHeight(220)
        self.log_view.setMaximumBlockCount(8000)
        layout.addWidget(self.log_view, 1)

        self.status_label = QLabel("")
        self.status_label.setObjectName("status-info")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

    def _apply_styles(self) -> None:
        p = self.theme
        sheet = (
            "QTableWidget {"
            f" background: transparent; border: 1px solid {p.border};"
            " border-radius: 6px; }"
            "QTableWidget::item { padding: 4px 6px; }"
            f"QTableWidget::item:selected {{ background: {p.accent};"
            f" color: {p.accent_fg}; }}"
            "QHeaderView::section { background: transparent; border: 0;"
            f" border-bottom: 1px solid {p.border}; padding: 4px 6px;"
            f" color: {p.text_muted}; font-family: \"{p.font_ui_family}\"; }}"
        )
        self.table.setStyleSheet(sheet)

    def set_theme(self, theme) -> None:
        """换主题时下发调色板。"""
        self.theme = theme
        self._apply_styles()

    # ------------------------------------------------------------------ 配置
    def _restore_config(self) -> None:
        cfg = self.store.get("leak_scan", default={}) or {}
        self.out_edit.setText(str(cfg.get("output_dir") or "output/leak"))
        try:
            self.threads_spin.setValue(int(cfg.get("threads") or
                                           leak_scan.DEFAULT_THREADS))
        except (TypeError, ValueError):
            self.threads_spin.setValue(leak_scan.DEFAULT_THREADS)
        try:
            self.timeout_spin.setValue(int(cfg.get("timeout") or
                                           leak_scan.DEFAULT_TIMEOUT))
        except (TypeError, ValueError):
            self.timeout_spin.setValue(leak_scan.DEFAULT_TIMEOUT)

    def _save_config(self) -> None:
        self.store.setv(self.out_edit.text().strip() or "output/leak",
                        "leak_scan", "output_dir")
        self.store.setv(int(self.threads_spin.value()), "leak_scan", "threads")
        self.store.setv(int(self.timeout_spin.value()), "leak_scan", "timeout")
        self.store.save()

    @property
    def _output_root(self) -> Path:
        return resolve_output_dir(self.out_edit.text().strip() or "output/leak")

    # ------------------------------------------------------------------ 操作
    def _browse_output(self) -> None:
        directory = QFileDialog.getExistingDirectory(
            self, "选择输出目录", str(self._output_root))
        if directory:
            self.out_edit.setText(directory)

    def _open_output(self) -> None:
        path = self._output_root
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            self._set_status(False, f"无法打开目录：{exc}")
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def _clear_log(self) -> None:
        self.log_view.clear()

    def _selected_kinds(self) -> list[str]:
        kinds = []
        if self.git_check.isChecked():
            kinds.append(leak_scan.KIND_GIT)
        if self.svn_check.isChecked():
            kinds.append(leak_scan.KIND_SVN)
        if self.ds_check.isChecked():
            kinds.append(leak_scan.KIND_DS)
        if self.files_check.isChecked():
            kinds.append(leak_scan.KIND_FILES)
        return kinds

    def _start(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._set_status(False, "检测正在进行中，请先停止。")
            return
        target = self.target_edit.text().strip()
        if not target:
            self._set_status(False, "请填写目标域名，如 example.com。")
            return
        kinds = self._selected_kinds()
        if not kinds:
            self._set_status(False, "请至少勾选一种检测项。")
            return

        self.table.setRowCount(0)
        self.log_view.clear()
        self._save_config()
        self._set_status(True, "开始检测…")

        old = self._worker
        worker = _LeakWorker(target, str(self._output_root), kinds,
                             self.threads_spin.value(),
                             self.timeout_spin.value(), self)
        worker.log.connect(self._append_log)
        worker.result.connect(self._add_result)
        worker.done_ok.connect(self._on_done)
        worker.done_err.connect(self._on_error)
        self._worker = worker
        if old is not None:
            old.deleteLater()
        self.run_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        worker.start()

    def _stop(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._worker.stop()
            self._set_status(True, "正在停止…（等待当前文件结束）")

    def _on_done(self, results: list) -> None:
        self._reset_buttons()
        found = [item for item in results if item.get("found")]
        errors = [item for item in results if item.get("error")]
        files = sum(int(item.get("files") or 0) for item in found)
        if not results:
            self._set_status(False, "检测已停止，未完成任何一项。")
            return
        if errors and not found:
            self._set_status(
                False, f"检测失败：{errors[0].get('summary', '无法连接目标')}")
            return
        if not found:
            self._set_status(
                True, f"检测完成：{len(results)} 项均未发现源码泄露，"
                      "可到「目录扫描」工具继续对目标做字典爆破。")
            return
        names = "、".join(item["label"] for item in found)
        self._set_status(
            True, f"检测完成：命中 {len(found)} 项（{names}），"
                  f"共还原 / 解析 {files} 个文件，已保存到 {self._output_root}。")

    def _on_error(self, message: str) -> None:
        self._reset_buttons()
        self._set_status(False, message)

    def _reset_buttons(self) -> None:
        self.run_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    # ------------------------------------------------------------------ 输出
    def _append_log(self, message: str) -> None:
        self.log_view.appendPlainText(message)
        bar = self.log_view.verticalScrollBar()
        bar.setValue(bar.maximum())

    def _add_result(self, item: dict) -> None:
        row = self.table.rowCount()
        self.table.insertRow(row)
        found = bool(item.get("found"))
        error = bool(item.get("error"))
        status = "失败" if error else ("已发现" if found else "未发现")
        cells = (item.get("label", ""), status,
                 str(item.get("files", 0)), item.get("summary", ""))
        for col, text in enumerate(cells):
            cell = QTableWidgetItem(str(text))
            if col in (1, 2):
                cell.setTextAlignment(Qt.AlignmentFlag.AlignHCenter
                                      | Qt.AlignmentFlag.AlignVCenter)
            if error:
                cell.setForeground(QColor(self.theme.danger))
            elif found and col == 1:
                cell.setForeground(QColor(self.theme.success))
            cell.setToolTip(str(item.get("url", "")))
            self.table.setItem(row, col, cell)

    def _set_status(self, ok: bool, text: str) -> None:
        self.status_label.setText(text)
        self.status_label.setObjectName("status-ok" if ok else "status-err")
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)

    # ------------------------------------------------------------------ 生命周期
    def shutdown(self) -> None:
        """退出前请求停止检测 / 爆破线程（closeEvent 调用）。"""
        if self._worker is not None and self._worker.isRunning():
            self._worker.stop()
            self._worker.wait(1500)

