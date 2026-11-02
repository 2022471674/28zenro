# -*- coding: utf-8 -*-
"""目录扫描独立页：字典目录逐条探测目标隐藏路径（dirsearch 风格）。

由源码泄露页里内嵌的「目录爆破」区域抽出成独立工具：

- 字典：默认读 ``dict/Contents`` 下全部字典文件（合并去重后缓存），
  可换任意目录；
- 并发：线程数 / 超时 / 相邻请求最小间隔（默认 30s，防 WAF）可调；
- 请求头：默认头来自 ``dict/Contents/http_headers.json``（用户可直接改
  这个文件换全局默认）， 页内编辑框可逐项覆盖（每行 ``Key: Value``），
  改动持久化到配置；点「恢复默认」拉回文件当前值；
- 命中：双击结果行用浏览器打开对应地址，或点「打开结果目录」看 CSV。

网络都在后台线程（``_DirScanWorker``）里跑，界面不阻塞。
"""

from __future__ import annotations

import threading

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QColor, QDesktopServices
from PySide6.QtCore import QUrl
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)
from qfluentwidgets import TableWidget

from app.widgets.no_wheel import NoWheelSpinBox
from lib import dir_scan
from lib.watermark import resolve_output_dir


class _DirScanWorker(QThread):
    """后台执行目录爆破，日志 / 命中 / 进度 / 结束经信号回传主线程。"""

    log = Signal(str)
    hit = Signal(dict)
    progress = Signal(int, int)
    done_ok = Signal(dict)
    done_err = Signal(str)

    def __init__(self, target: str, out_dir: str, words: list[str],
                 threads: int, timeout: int, interval: float, headers: str,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._target = target
        self._out_dir = out_dir
        self._words = words
        self._threads = threads
        self._timeout = timeout
        self._interval = interval
        self._headers = headers
        self._event = threading.Event()

    def stop(self) -> None:
        """请求中止：不再派发新任务，在途请求尽快收尾。"""
        self._event.set()

    def run(self) -> None:  # noqa: D102  线程入口
        try:
            result = dir_scan.scan(
                self._target,
                out_dir=self._out_dir,
                words=self._words,
                threads=self._threads,
                timeout=self._timeout,
                interval=self._interval,
                headers=self._headers,
                log=self.log.emit,
                on_hit=self.hit.emit,
                on_progress=self.progress.emit,
                stop=self._event,
            )
        except dir_scan.DirScanError as exc:
            self.done_err.emit(str(exc))
            return
        except Exception as exc:  # noqa: BLE001  后台线程兜底
            self.done_err.emit(f"目录扫描失败：{exc}")
            return
        self.done_ok.emit(result)


def _headers_text() -> str:
    """把当前默认请求头（含 dict/Contents/http_headers.json 覆盖）排成文本。"""
    headers = dir_scan.load_default_headers()
    keys = sorted(headers, key=lambda k: (k != "User-Agent", k.lower()))
    return "\n".join(f"{key}: {headers[key]}" for key in keys)


class DirScanPage(QWidget):
    """目录扫描页（Web 信息收集分类）。"""

    COLUMNS = ("状态", "长度", "路径", "标题")

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._worker: _DirScanWorker | None = None
        self._dict_words: list[str] | None = None
        self._dict_files = 0
        self._build()
        self._restore_config()
        self._refresh_dict_info(verbose=False)

    # ------------------------------------------------------------------ 界面
    def _build(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 14, 8, 8)
        layout.setSpacing(10)

        form_row = QHBoxLayout()
        form_row.setSpacing(8)
        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText(
            "example.com 或 example.com/upload（扫描某个子目录）")
        self.target_edit.returnPressed.connect(self._start)
        form_row.addWidget(self.target_edit, 1)
        layout.addLayout(form_row)

        dict_row = QHBoxLayout()
        dict_row.setSpacing(8)
        dict_row.addWidget(QLabel("字典目录"))
        self.dict_edit = QLineEdit()
        self.dict_edit.setPlaceholderText(
            "目录下所有字典文件会被一并读取（内置 dict/Contents）")
        self.dict_edit.textChanged.connect(self._on_dict_dir_changed)
        dict_row.addWidget(self.dict_edit, 1)
        dict_browse = QPushButton("浏览…")
        dict_browse.setObjectName("ghbtn")
        dict_browse.clicked.connect(self._browse_dict)
        dict_row.addWidget(dict_browse)
        dict_reload = QPushButton("重新加载")
        dict_reload.setObjectName("ghbtn")
        dict_reload.clicked.connect(lambda: self._refresh_dict_info(verbose=True))
        dict_row.addWidget(dict_reload)
        layout.addLayout(dict_row)

        self.dict_info = QLabel("字典：未加载")
        self.dict_info.setObjectName("caption")
        layout.addWidget(self.dict_info)

        opts = QHBoxLayout()
        opts.setSpacing(16)
        self.threads_spin = NoWheelSpinBox()
        self.threads_spin.setRange(1, 64)
        self.threads_spin.setValue(dir_scan.DEFAULT_THREADS)
        opts.addWidget(QLabel("线程数"))
        opts.addWidget(self.threads_spin)

        self.timeout_spin = NoWheelSpinBox()
        self.timeout_spin.setRange(1, 60)
        self.timeout_spin.setValue(dir_scan.DEFAULT_TIMEOUT)
        self.timeout_spin.setSuffix(" 秒")
        opts.addWidget(QLabel("超时"))
        opts.addWidget(self.timeout_spin)

        self.interval_spin = NoWheelSpinBox()
        self.interval_spin.setRange(0, 3600)
        self.interval_spin.setValue(int(dir_scan.DEFAULT_INTERVAL))
        self.interval_spin.setSuffix(" 秒")
        self.interval_spin.setToolTip(
            "相邻两次探测请求的最小间隔，默认 30 秒，可降低触发 WAF / 限速的概率；"
            "设为 0 表示不限间隔。")
        opts.addWidget(QLabel("请求间隔"))
        opts.addWidget(self.interval_spin)
        opts.addStretch(1)

        self.run_btn = QPushButton("开始扫描")
        self.run_btn.setObjectName("ghbtn-primary")
        self.run_btn.clicked.connect(self._start)
        opts.addWidget(self.run_btn)

        self.stop_btn = QPushButton("停止")
        self.stop_btn.setObjectName("ghbtn")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop)
        opts.addWidget(self.stop_btn)

        open_btn = QPushButton("打开结果目录")
        open_btn.setObjectName("ghbtn")
        open_btn.clicked.connect(self._open_output)
        opts.addWidget(open_btn)
        layout.addLayout(opts)

        out_row = QHBoxLayout()
        out_row.setSpacing(8)
        out_row.addWidget(QLabel("输出目录"))
        self.out_edit = QLineEdit()
        self.out_edit.setPlaceholderText("输出目录（相对路径基于程序目录）")
        out_row.addWidget(self.out_edit, 1)
        browse_btn = QPushButton("浏览…")
        browse_btn.setObjectName("ghbtn")
        browse_btn.clicked.connect(self._browse_output)
        out_row.addWidget(browse_btn)
        layout.addLayout(out_row)

        # 请求头（可折叠）：默认值来自 dict/Contents/http_headers.json，
        # 页内逐行覆盖，持久化到配置 —— 两层自定义接口。
        headers_row = QHBoxLayout()
        headers_row.setSpacing(8)
        self.headers_toggle = QPushButton("请求头 ▸")
        self.headers_toggle.setObjectName("ghbtn")
        self.headers_toggle.setCheckable(True)
        self.headers_toggle.clicked.connect(self._toggle_headers)
        headers_row.addWidget(self.headers_toggle)
        self.default_headers_btn = QPushButton("恢复默认")
        self.default_headers_btn.setObjectName("ghbtn")
        self.default_headers_btn.setToolTip(
            "把编辑框恢复成 dict/Contents/http_headers.json 当前的内容；"
            "改过该文件后按此重新拉取。")
        self.default_headers_btn.clicked.connect(self._reset_headers)
        headers_row.addWidget(self.default_headers_btn)
        self.headers_hint = QLabel(
            "默认已带一组伪造的真实客户端请求头（Chrome UA / Accept / Sec-Fetch 等），"
            "实际默认值可在 dict/Contents/http_headers.json 里改；"
            "此处逐行「Key: Value」覆盖。")
        self.headers_hint.setObjectName("caption")
        self.headers_hint.setWordWrap(True)
        headers_row.addWidget(self.headers_hint, 1)
        layout.addLayout(headers_row)

        self.headers_edit = QTextEdit()
        self.headers_edit.setObjectName("io")
        self.headers_edit.setFixedHeight(120)
        self.headers_edit.setPlaceholderText(
            "User-Agent: Mozilla/5.0 …\nX-Custom-Header: value")
        self.headers_edit.hide()
        layout.addWidget(self.headers_edit)

        self.table = TableWidget(self)
        self.table.setColumnCount(len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels(list(self.COLUMNS))
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.verticalHeader().hide()
        self.table.setMinimumHeight(160)
        self.table.cellDoubleClicked.connect(self._open_hit)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header.resizeSection(0, 70)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        header.resizeSection(1, 90)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table, 1)

        log_label = QLabel("扫描日志")
        log_label.setObjectName("section")
        layout.addWidget(log_label)

        self.log_view = QPlainTextEdit()
        self.log_view.setObjectName("io")
        self.log_view.setReadOnly(True)
        self.log_view.setMinimumHeight(140)
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
        cfg = self.store.get("dir_scan", default={}) or {}
        self.out_edit.setText(str(cfg.get("output_dir") or "output/dir_scan"))
        self.dict_edit.setText(str(cfg.get("dict_dir") or dir_scan.default_dict_dir()))
        try:
            self.threads_spin.setValue(int(cfg.get("threads") or
                                           dir_scan.DEFAULT_THREADS))
        except (TypeError, ValueError):
            self.threads_spin.setValue(dir_scan.DEFAULT_THREADS)
        try:
            self.timeout_spin.setValue(int(cfg.get("timeout") or
                                           dir_scan.DEFAULT_TIMEOUT))
        except (TypeError, ValueError):
            self.timeout_spin.setValue(dir_scan.DEFAULT_TIMEOUT)
        try:
            interval = cfg.get("interval")
            self.interval_spin.setValue(
                int(interval) if interval is not None
                else int(dir_scan.DEFAULT_INTERVAL))
        except (TypeError, ValueError):
            self.interval_spin.setValue(int(dir_scan.DEFAULT_INTERVAL))
        saved = str(cfg.get("headers") or "")
        self.headers_edit.setPlainText(saved if saved else _headers_text())

    def _save_config(self) -> None:
        self.store.setv(self.out_edit.text().strip() or "output/dir_scan",
                        "dir_scan", "output_dir")
        self.store.setv(self.dict_edit.text().strip(), "dir_scan", "dict_dir")
        self.store.setv(int(self.threads_spin.value()), "dir_scan", "threads")
        self.store.setv(int(self.timeout_spin.value()), "dir_scan", "timeout")
        self.store.setv(int(self.interval_spin.value()), "dir_scan", "interval")
        self.store.setv(self.headers_edit.toPlainText(), "dir_scan", "headers")
        self.store.save()

    @property
    def _output_root(self):
        return resolve_output_dir(self.out_edit.text().strip() or "output/dir_scan")

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

    def _on_dict_dir_changed(self, _text: str) -> None:
        """字典目录一改就丢缓存，下次扫描 / 重新加载时再读。"""
        self._dict_words = None
        self._dict_files = 0
        self.dict_info.setText("字典：目录已变更，点「重新加载」或直接开始扫描")

    def _browse_dict(self) -> None:
        start = self.dict_edit.text().strip() or str(dir_scan.default_dict_dir())
        directory = QFileDialog.getExistingDirectory(self, "选择字典目录", start)
        if directory:
            self.dict_edit.setText(directory)

    def _refresh_dict_info(self, verbose: bool = True) -> bool:
        """读取字典目录下全部字典文件，缓存合并后的词表并刷新提示。"""
        directory = (self.dict_edit.text().strip()
                     or str(dir_scan.default_dict_dir()))
        try:
            words, details = dir_scan.load_words(
                directory, log=self._append_log if verbose else None)
        except (dir_scan.DirScanError, OSError) as exc:
            self._dict_words = None
            self._dict_files = 0
            self.dict_info.setText(f"字典：加载失败 —— {exc}")
            if verbose:
                self._append_log(f"[字典] 加载失败：{exc}")
            return False
        self._dict_words = words
        self._dict_files = len(details)
        self.dict_info.setText(
            f"字典：{self._dict_files} 个文件，去重后 {len(words)} 条路径（已缓存）")
        return True

    # ------------------------------------------------------------------ 请求头
    def _toggle_headers(self, checked: bool) -> None:
        """展开 / 收起自定义请求头编辑框。"""
        self.headers_edit.setVisible(bool(checked))
        self.headers_toggle.setText("请求头 ▾" if checked else "请求头 ▸")

    def _reset_headers(self) -> None:
        """把编辑框恢复成当前默认请求头（dict/Contents/http_headers.json）。"""
        dir_scan.reset_default_headers_cache()
        self.headers_edit.setPlainText(_headers_text())
        self._set_status(True, "请求头已恢复为默认值"
                               "（dict/Contents/http_headers.json 当前内容）。")

    # ------------------------------------------------------------------ 运行
    def _start(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._set_status(False, "扫描正在进行中，请先停止。")
            return
        target = self.target_edit.text().strip()
        if not target:
            self._set_status(False, "请填写目标域名，如 example.com。")
            return
        if self._dict_words is None and not self._refresh_dict_info(verbose=True):
            self._set_status(False, "字典加载失败，请检查字典目录。")
            return
        if not self._dict_words:
            self._set_status(False, "字典里没有可用的路径，请换一份字典。")
            return

        self.table.setRowCount(0)
        self._save_config()
        self.run_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self._set_status(
            True, f"开始扫描：{len(self._dict_words)} 条路径，"
                  f"线程 {self.threads_spin.value()}，"
                  f"请求间隔 {self.interval_spin.value()} 秒…")

        old = self._worker
        worker = _DirScanWorker(target, str(self._output_root),
                                list(self._dict_words),
                                int(self.threads_spin.value()),
                                int(self.timeout_spin.value()),
                                float(self.interval_spin.value()),
                                self.headers_edit.toPlainText(), self)
        worker.log.connect(self._append_log)
        worker.hit.connect(self._add_hit)
        worker.progress.connect(self._on_progress)
        worker.done_ok.connect(self._on_done)
        worker.done_err.connect(self._on_error)
        self._worker = worker
        if old is not None:
            old.deleteLater()
        worker.start()

    def _stop(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._worker.stop()
            self._set_status(True, "正在停止…（等待在途请求结束）")

    def _on_progress(self, done: int, total: int) -> None:
        if total <= 0:
            return
        percent = done * 100 // total
        self._set_status(
            True, f"扫描中… {done}/{total}（{percent}%），"
                  f"已命中 {self.table.rowCount()} 条")

    def _on_done(self, result: dict) -> None:
        self.run_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        hits = len(result.get("hits") or [])
        tested = int(result.get("tested") or 0)
        total = int(result.get("total") or 0)
        elapsed = result.get("elapsed") or 0
        extra: list[str] = []
        if result.get("filtered"):
            extra.append(f"软 404 过滤 {result['filtered']} 条")
        if result.get("errors"):
            extra.append(f"失败 {result['errors']} 次")
        if result.get("stopped"):
            extra.append("已手动停止")
        text = (f"扫描{'已停止' if result.get('stopped') else '完成'}："
                f"测试 {tested}/{total} 条，命中 {hits} 条，耗时 {elapsed}s")
        if extra:
            text += f"（{'；'.join(extra)}）"
        if result.get("output"):
            text += f"，结果已保存到 {result['output']}"
        self._set_status(True, text)
        if not hits and not result.get("stopped"):
            self._set_status(
                True, text + "。可换更大的字典，或检查目标是否对任意路径都返回 200。")

    def _on_error(self, message: str) -> None:
        self.run_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self._set_status(False, message)

    # ------------------------------------------------------------------ 结果
    def _open_hit(self, row: int, _column: int) -> None:
        """双击结果行：用默认浏览器打开命中的地址。"""
        cell = self.table.item(row, 2)
        url = cell.data(Qt.ItemDataRole.UserRole) if cell is not None else ""
        if url:
            QDesktopServices.openUrl(QUrl(str(url)))

    def _add_hit(self, item: dict) -> None:
        row = self.table.rowCount()
        self.table.insertRow(row)
        status = int(item.get("status") or 0)
        word = str(item.get("word") or "")
        title = str(item.get("title") or "")
        if item.get("listing"):
            title = f"[目录列表] {title}".strip()
        cells = (str(status), str(item.get("length") or 0), f"/{word}", title)
        for col, text in enumerate(cells):
            cell = QTableWidgetItem(text)
            if col in (0, 1):
                cell.setTextAlignment(Qt.AlignmentFlag.AlignHCenter
                                      | Qt.AlignmentFlag.AlignVCenter)
            if col == 0:
                if 200 <= status < 300:
                    cell.setForeground(QColor(self.theme.success))
                elif 300 <= status < 400:
                    cell.setForeground(QColor(self.theme.accent))
                else:
                    cell.setForeground(QColor(self.theme.warning))
            tip = str(item.get("url") or "")
            if item.get("redirect"):
                tip += f"\n跳转：{item['redirect']}"
            cell.setToolTip(tip)
            if col == 2:
                cell.setData(Qt.ItemDataRole.UserRole, str(item.get("url") or ""))
            self.table.setItem(row, col, cell)
        bar = self.table.verticalScrollBar()
        bar.setValue(bar.maximum())

    def _append_log(self, message: str) -> None:
        self.log_view.appendPlainText(message)
        bar = self.log_view.verticalScrollBar()
        bar.setValue(bar.maximum())

    def _set_status(self, ok: bool, text: str) -> None:
        self.status_label.setText(text)
        self.status_label.setObjectName("status-ok" if ok else "status-err")
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)

    # ------------------------------------------------------------------ 生命周期
    def shutdown(self) -> None:
        """退出前请求停止扫描线程（closeEvent 调用）。"""
        if self._worker is not None and self._worker.isRunning():
            self._worker.stop()
            self._worker.wait(1500)

