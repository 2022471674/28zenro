# -*- coding: utf-8 -*-
"""密码 Fuzz 页：输入密文（可带已知 key / 偏移量），把所有能解密的工具跑一遍。

CTF 里拿到一串看不懂的东西时，不用再一个个工具点过去：把密文粘进来，
工具按注册表里的「Fuzz 约定」（见 :mod:`lib.cipher_fuzz`）自动收录所有
可解密的算法，逐条尝试，结果按**可读性**排序，真明文一般就在最上面。

- 偏移量留空 → 带位移参数的工具（如凯撒）自动遍历 0~25；
- 偏移量填了 → 只试这个偏移量；
- key 填了 → 留给需要密钥的算法（后续新增的 AES / 维吉尼亚等）；
- 可勾「只看可读结果」过滤乱码，双击结果行复制。

耗时算法在后台线程里跑，界面不阻塞。
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
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

from app import registry
from app.widgets.fuzz_worker import FuzzWorker
from lib import cipher_fuzz

#: 表格最多渲染多少行（候选可能上千条，全部塞进表里会卡）
MAX_ROWS = 500


class _FuzzWorker(FuzzWorker):
    """后台跑一轮密码 Fuzz。"""

    error_prefix = "尝试失败"

    def __init__(self, text: str, key: str, offset: int | None,
                 targets: tuple, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._text = text
        self._key = key
        self._offset = offset
        self._targets = targets

    def task(self) -> dict:
        return cipher_fuzz.run(
            self._text,
            key=self._key,
            offset=self._offset,
            targets=self._targets,
            log=self.log.emit,
            stop=self._event,
        )


class CipherFuzzPage(QWidget):
    """密码 Fuzz（密码学入口下的独立页面）。"""

    COLUMNS = ("算法", "参数", "结果", "可读性")

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._worker: _FuzzWorker | None = None
        self._hits: list[dict] = []
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

        input_label = QLabel("密文")
        input_label.setObjectName("section")
        layout.addWidget(input_label)

        self.input_edit = QPlainTextEdit()
        self.input_edit.setObjectName("io")
        self.input_edit.setPlaceholderText(
            "粘贴要尝试的内容，例如 Uryyb Jbeyq / SGVsbG8gV29ybGQ= / %E4%BD%A0%E5%A5%BD …")
        self.input_edit.setMinimumHeight(92)
        self.input_edit.setMaximumHeight(170)
        layout.addWidget(self.input_edit)

        params = QHBoxLayout()
        params.setSpacing(10)
        params.addWidget(QLabel("已知 key"))
        self.key_edit = QLineEdit()
        self.key_edit.setPlaceholderText("可留空；用于 AES / 维吉尼亚等需要密钥的算法")
        params.addWidget(self.key_edit, 2)

        params.addSpacing(8)
        params.addWidget(QLabel("偏移量"))
        self.offset_edit = QLineEdit()
        self.offset_edit.setPlaceholderText("留空=遍历 0~25")
        self.offset_edit.setMaximumWidth(130)
        params.addWidget(self.offset_edit)
        layout.addLayout(params)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        self.run_btn = QPushButton("开始尝试")
        self.run_btn.setObjectName("ghbtn-primary")
        self.run_btn.clicked.connect(self._start)
        buttons.addWidget(self.run_btn)

        self.stop_btn = QPushButton("停止")
        self.stop_btn.setObjectName("ghbtn")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop)
        buttons.addWidget(self.stop_btn)

        self.only_readable = QCheckBox("只看可读结果")
        self.only_readable.setChecked(True)
        self.only_readable.stateChanged.connect(self._on_filter_changed)
        buttons.addWidget(self.only_readable)

        clear_btn = QPushButton("清空")
        clear_btn.setObjectName("ghbtn")
        clear_btn.clicked.connect(self._clear)
        buttons.addWidget(clear_btn)

        copy_btn = QPushButton("复制选中结果")
        copy_btn.setObjectName("ghbtn")
        copy_btn.clicked.connect(self._copy_selected)
        buttons.addWidget(copy_btn)
        buttons.addStretch(1)
        layout.addLayout(buttons)

        self.table = TableWidget(self)
        self.table.setColumnCount(len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels(list(self.COLUMNS))
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.verticalHeader().hide()
        self.table.setMinimumHeight(220)
        self.table.cellDoubleClicked.connect(self._copy_row)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header.resizeSection(0, 130)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        header.resizeSection(1, 150)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        header.resizeSection(3, 80)
        layout.addWidget(self.table, 1)

        self.log_label = QLabel("尝试日志")
        self.log_label.setObjectName("section")
        layout.addWidget(self.log_label)

        self.log_view = QPlainTextEdit()
        self.log_view.setObjectName("io")
        self.log_view.setReadOnly(True)
        self.log_view.setMinimumHeight(96)
        self.log_view.setMaximumHeight(150)
        self.log_view.setMaximumBlockCount(2000)
        layout.addWidget(self.log_view)

        self.status_label = QLabel("")
        self.status_label.setObjectName("status-info")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

    def _apply_styles(self) -> None:
        p = self.theme
        self.table.setStyleSheet(
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

    def set_theme(self, theme) -> None:
        """换主题时下发调色板。"""
        self.theme = theme
        self._apply_styles()
        self._fill_table()

    # ------------------------------------------------------------------ 配置
    def _restore_config(self) -> None:
        cfg = self.store.get("cipher_fuzz", default={}) or {}
        self.only_readable.setChecked(bool(cfg.get("only_readable", True)))

    def _save_config(self) -> None:
        self.store.setv(bool(self.only_readable.isChecked()),
                        "cipher_fuzz", "only_readable")
        self.store.save()

    def _disabled_fuzz_tools(self) -> set[str]:
        """读取设置页「一键 Fuzz」里被用户取消勾选的密码工具 id 集合。"""
        cfg = self.store.get("fuzz_config", default={}) or {}
        disabled = cfg.get("crypto_disabled") or []
        return set(disabled) if isinstance(disabled, list) else set()

    # ------------------------------------------------------------------ 操作
    def _parse_offset(self) -> tuple[int | None, bool]:
        """解析偏移量输入，返回 ``(值, 是否合法)``。空输入视为自动。"""
        text = self.offset_edit.text().strip()
        if not text:
            return None, True
        try:
            return int(text), True
        except ValueError:
            return None, False

    def _start(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._set_status(False, "正在尝试中，请稍候或先停止。")
            return
        text = self.input_edit.toPlainText()
        if not text.strip():
            self._set_status(False, "请先粘贴要尝试的密文。")
            return
        offset, valid = self._parse_offset()
        if not valid:
            self._set_status(False, "偏移量需要填整数，或留空让工具自动遍历。")
            return

        self._save_config()
        self._hits = []
        self.table.setRowCount(0)
        self.log_view.clear()
        self.run_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self._set_status(True, "正在尝试所有可解密算法…")

        targets = registry.fuzz_targets(exclude=self._disabled_fuzz_tools())
        old = self._worker
        worker = _FuzzWorker(text, self.key_edit.text(), offset, targets, self)
        worker.log.connect(self._append_log)
        worker.done_ok.connect(self._on_done)
        worker.done_err.connect(self._on_error)
        self._worker = worker
        if old is not None:
            old.deleteLater()
        worker.start()

    def _stop(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._worker.stop()
            self._set_status(True, "正在停止…")

    def _clear(self) -> None:
        self.input_edit.clear()
        self.log_view.clear()
        self.table.setRowCount(0)
        self._hits = []
        self._set_status(True, "")

    def _on_done(self, result: dict) -> None:
        self._reset_buttons()
        self._hits = list(result.get("hits") or [])
        shown, total = self._fill_table()
        tried = int(result.get("tried_tools") or 0)
        total_tools = int(result.get("total_tools") or 0)
        readable = sum(1 for hit in self._hits if hit.get("readable"))
        if not self._hits:
            self._set_status(
                False, f"已尝试 {tried}/{total_tools} 个算法，都没有得到有效结果。"
                       "可检查密文是否完整，或填上已知的 key / 偏移量再试。")
            return
        text = (f"尝试完成：{tried}/{total_tools} 个算法产出 {len(self._hits)} 条候选，"
                f"其中可读 {readable} 条")
        if shown < total:
            text += f"，当前显示 {shown} 条"
        if total > MAX_ROWS:
            text += f"（表格最多渲染 {MAX_ROWS} 行）"
        self._set_status(True, text + "。双击结果行可复制。")

    def _on_filter_changed(self, _state: int) -> None:
        if not self._hits:
            return
        self._save_config()
        shown, total = self._fill_table()
        if shown < total:
            self._set_status(True, f"共 {total} 条候选，当前显示 {shown} 条可读结果"
                                   "（取消勾选可查看全部）。")
        else:
            self._set_status(True, f"共 {total} 条候选，已全部显示。")

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

    def _fill_table(self) -> tuple[int, int]:
        """按当前过滤条件重填表格（可读性已由 lib 排好序）。

        返回 ``(显示行数, 候选总数)``。
        """
        only_readable = self.only_readable.isChecked()
        rows = [hit for hit in self._hits if hit.get("readable") or not only_readable]
        self.table.setRowCount(0)
        for hit in rows[:MAX_ROWS]:
            row = self.table.rowCount()
            self.table.insertRow(row)
            score = float(hit.get("score") or 0)
            cells = (hit.get("tool", ""), hit.get("label", ""),
                     hit.get("output", ""), f"{score:.2f}")
            for col, text in enumerate(cells):
                cell = QTableWidgetItem(str(text))
                if col == 3:
                    cell.setTextAlignment(Qt.AlignmentFlag.AlignHCenter
                                          | Qt.AlignmentFlag.AlignVCenter)
                if hit.get("readable"):
                    cell.setForeground(QColor(self.theme.success))
                cell.setToolTip(str(hit.get("output", ""))[:600])
                self.table.setItem(row, col, cell)
        return min(len(rows), MAX_ROWS), len(self._hits)

    def _copy_row(self, row: int, _column: int) -> None:
        cell = self.table.item(row, 2)
        if cell is not None:
            QGuiApplication.clipboard().setText(cell.text())

    def _copy_selected(self) -> None:
        rows = sorted({index.row() for index in self.table.selectedIndexes()})
        if not rows:
            self._set_status(False, "请先在结果表里选中要复制的行。")
            return
        texts = []
        for row in rows:
            cell = self.table.item(row, 2)
            if cell is not None:
                texts.append(cell.text())
        if texts:
            QGuiApplication.clipboard().setText("\n".join(texts))
            self._set_status(True, f"已复制 {len(texts)} 条结果到剪贴板。")

    def _set_status(self, ok: bool, text: str) -> None:
        self.status_label.setText(text)
        self.status_label.setObjectName("status-ok" if ok else "status-err")
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)

    # ------------------------------------------------------------------ 生命周期
    def shutdown(self) -> None:
        """退出前请求停止 Fuzz 线程（closeEvent 调用）。"""
        if self._worker is not None and self._worker.isRunning():
            self._worker.stop()
            self._worker.wait(1500)
