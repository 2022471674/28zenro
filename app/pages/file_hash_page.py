# -*- coding: utf-8 -*-
"""文件哈希分析页。

纯逻辑全部委托 ``lib.file_hash``（流式计算多种摘要 / CRC32），本页不含
算法代码：

- 选择文件后，一键计算 MD5 / SHA1 / SHA256 / SHA512 / SHA3-256 / CRC32，
  结果逐行列出，可一键复制单个或全部摘要。
- 大文件走流式读取（分块），内存占用与文件大小无关；多算法在一次读取
  中并行计算，避免重复读盘。
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import (
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from lib import file_hash
from lib.file_hash import FileHashError

ALL_FILTER = "所有文件 (*)"


class _HashWorker(QThread):
    """后台执行文件哈希计算，结果经信号返回主线程（大文件不卡 UI）。"""

    done_ok = Signal(str)
    done_err = Signal(str)

    def __init__(self, fn, parent=None) -> None:
        super().__init__(parent)
        self._fn = fn

    def run(self) -> None:  # noqa: D102
        try:
            result = self._fn()
        except Exception as exc:  # noqa: BLE001
            self.done_err.emit(str(exc))
        else:
            self.done_ok.emit(str(result))


def _make_status_label() -> QLabel:
    label = QLabel("")
    label.setObjectName("status-info")
    label.setWordWrap(True)
    return label


def _set_status(label: QLabel, ok: bool | None, text: str) -> None:
    label.setObjectName(
        "status-info" if ok is None else ("status-ok" if ok else "status-err"))
    label.setText(text)
    label.style().unpolish(label)
    label.style().polish(label)


class FileHashPage(QWidget):
    """文件哈希分析页。"""

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._worker: _HashWorker | None = None
        self._last_results: dict[str, str] = {}
        self._build()

    # ------------------------------------------------------------------ UI
    def _build(self) -> None:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)

        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)

        form = QFormLayout()
        form.setContentsMargins(0, 0, 0, 0)
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(10)

        # 文件选择
        self.f_path = QLineEdit()
        self.f_path.setPlaceholderText("选择要计算哈希的文件…")
        browse = QPushButton("浏览…")
        browse.setObjectName("ghbtn")
        browse.clicked.connect(self._pick_file)
        box = QWidget()
        row = QHBoxLayout(box)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(6)
        row.addWidget(self.f_path, stretch=1)
        row.addWidget(browse)
        form.addRow("文件", box)

        # 操作按钮
        self.calc_btn = QPushButton("计算哈希")
        self.calc_btn.setObjectName("ghbtn-primary")
        self.calc_btn.clicked.connect(self._run_calc)
        self.copy_all_btn = QPushButton("复制全部")
        self.copy_all_btn.setObjectName("ghbtn")
        self.copy_all_btn.clicked.connect(self._copy_all)
        self.clear_btn = QPushButton("清空")
        self.clear_btn.setObjectName("ghbtn")
        self.clear_btn.clicked.connect(self._clear)
        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        btn_row.addWidget(self.calc_btn)
        btn_row.addWidget(self.copy_all_btn)
        btn_row.addWidget(self.clear_btn)
        btn_row.addStretch(1)
        form.addRow("", btn_row)

        layout.addLayout(form)

        # 结果展示
        self.output = QPlainTextEdit()
        self.output.setObjectName("io")
        self.output.setReadOnly(True)
        self.output.setPlaceholderText("选择文件并点「计算哈希」后在此显示…")
        self.output.setMinimumHeight(260)
        layout.addWidget(self.output, stretch=1)

        self.status = _make_status_label()
        layout.addWidget(self.status)

        scroll.setWidget(inner)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

    # -------------------------------------------------------------- 控件
    def _pick_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "选择文件", "", ALL_FILTER)
        if path:
            self.f_path.setText(path)
            _set_status(self.status, None, "")

    # -------------------------------------------------------------- 逻辑
    def _run_calc(self) -> None:
        path = self.f_path.text().strip()
        if not path:
            _set_status(self.status, False, "请先选择文件。")
            return
        if not Path(path).is_file():
            _set_status(self.status, False, f"文件不存在：{path}")
            return

        _set_status(self.status, True, "正在计算哈希…")

        def work() -> str:
            results = file_hash.hash_file_all(path)
            info = file_hash.file_info(path)
            lines = [f"文件：{info['name']}"]
            lines.append(f"大小：{info['size']:,} 字节")
            lines.append("")
            for algo, display in file_hash.ALGORITHMS.values() or []:
                pass
            # 按固定顺序输出（与 ALGORITHMS 定义顺序一致）
            for algo, (_, display) in file_hash.ALGORITHMS.items():
                lines.append(f"{display}: {results[algo]}")
            self._last_results = results
            return "\n".join(lines)

        self._start_worker(work, self.status)

    def _start_worker(self, fn, err_label: QLabel) -> None:
        if self._worker is not None and self._worker.isRunning():
            _set_status(err_label, False, "上一个任务还在处理中，请稍候。")
            return
        self._worker = _HashWorker(fn, self)
        self._worker.done_ok.connect(
            lambda msg: (self.output.setPlainText(msg),
                         _set_status(err_label, True, "计算完成。")))
        self._worker.done_err.connect(
            lambda msg: _set_status(err_label, False, msg))
        self._worker.start()

    def _copy_all(self) -> None:
        text = self.output.toPlainText()
        if not text.strip():
            _set_status(self.status, False, "没有可复制的结果。")
            return
        from PySide6.QtWidgets import QApplication
        QApplication.clipboard().setText(text)
        _set_status(self.status, True, "已复制全部结果到剪贴板。")

    def _clear(self) -> None:
        self.output.clear()
        self._last_results = {}
        _set_status(self.status, None, "")

    # -------------------------------------------------------------- 收尾
    def shutdown(self) -> None:
        """停止后台线程（如有），避免退出时崩溃。"""
        if self._worker is not None and self._worker.isRunning():
            self._worker.wait(2000)
