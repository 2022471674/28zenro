# -*- coding: utf-8 -*-
"""参数爆破页（整合 Arjun 的核心逻辑）。

输入一个 URL，自动发现该端点接受的 HTTP 参数名（query string / 表单 / JSON /
XML 体）。核心逻辑在 :mod:`lib.param_fuzz`：

- 稳定性探测 + 异常检测基线（对比「每次变」的因素并剔除）；
- 启发式预提取（从响应抠出 input/textarea 的 name/id、JS 变量名与对象键）；
- 分块爆破 + 二分收敛 + 逐个 verify。

可选请求方法 GET / POST / JSON / XML，可指定字典（small / medium / large 或
文件路径），可配置线程数、超时、延时、chunk 大小、自定义请求头与固定负载
（``include``，JSON/XML 用 ``$arjun$`` 占位符嵌入爆破键值对）。

网络请求在后台线程执行，日志 / 结果经信号回传主线程，不阻塞界面；所有请求
统一走全局代理池。
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.widgets.fuzz_worker import FuzzWorker
from app.widgets.no_wheel import NoWheelSpinBox
from lib import param_fuzz, watermark


class _ParamFuzzWorker(FuzzWorker):
    """后台执行参数爆破。"""

    error_prefix = "爆破失败"

    def __init__(self, target: str, method: str, wordlist: str, include: str,
                 headers: str, timeout: float, threads: int, chunks: int,
                 delay: float, rate_limit: int,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._target = target
        self._method = method
        self._wordlist = wordlist
        self._include = include
        self._headers = headers
        self._timeout = timeout
        self._threads = threads
        self._chunks = chunks
        self._delay = delay
        self._rate_limit = rate_limit

    def task(self) -> dict:
        return param_fuzz.run(
            self._target,
            method=self._method,
            wordlist=self._wordlist,
            include=self._include,
            headers=self._headers,
            timeout=self._timeout,
            threads=self._threads,
            chunks=self._chunks,
            delay=self._delay,
            rate_limit=self._rate_limit,
            log=self.log.emit,
            stop=self._event,
        )


class ParamFuzzPage(QWidget):
    """参数爆破页（整合 Arjun）。"""

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._worker: _ParamFuzzWorker | None = None
        self._result: dict | None = None
        self._build_ui()
        self._restore_config()

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
            "https://example.com（可省略协议头，如 example.com/search）")
        self.target_edit.returnPressed.connect(self._start)
        form.addRow("目标 URL", self.target_edit)

        opts = QHBoxLayout()
        opts.setSpacing(16)

        self.method_combo = QComboBox()
        for method in param_fuzz.METHODS:
            self.method_combo.addItem(method, method)
        opts.addWidget(QLabel("方法"))
        opts.addWidget(self.method_combo)

        self.wordlist_combo = QComboBox()
        for key, label in (("small", "small（约 800）"),
                           ("medium", "medium（约 1.1 万）"),
                           ("large", "large（约 2.6 万）")):
            self.wordlist_combo.addItem(label, key)
        opts.addWidget(QLabel("字典"))
        opts.addWidget(self.wordlist_combo)
        opts.addStretch(1)
        form.addRow("", opts)

        opts2 = QHBoxLayout()
        opts2.setSpacing(16)
        self.timeout_spin = NoWheelSpinBox()
        self.timeout_spin.setRange(1, 60)
        self.timeout_spin.setValue(param_fuzz.DEFAULT_TIMEOUT)
        self.timeout_spin.setSuffix(" 秒")
        opts2.addWidget(QLabel("超时"))
        opts2.addWidget(self.timeout_spin)

        self.threads_spin = NoWheelSpinBox()
        self.threads_spin.setRange(1, 50)
        self.threads_spin.setValue(param_fuzz.DEFAULT_THREADS)
        opts2.addWidget(QLabel("线程"))
        opts2.addWidget(self.threads_spin)

        self.chunks_spin = NoWheelSpinBox()
        self.chunks_spin.setRange(10, 1000)
        self.chunks_spin.setValue(param_fuzz.DEFAULT_CHUNKS)
        opts2.addWidget(QLabel("每组参数"))
        opts2.addWidget(self.chunks_spin)
        opts2.addStretch(1)
        form.addRow("", opts2)

        opts3 = QHBoxLayout()
        opts3.setSpacing(16)
        self.delay_spin = NoWheelSpinBox()
        self.delay_spin.setRange(0, 60)
        self.delay_spin.setValue(int(param_fuzz.DEFAULT_DELAY))
        self.delay_spin.setSuffix(" 秒")
        opts3.addWidget(QLabel("延时"))
        opts3.addWidget(self.delay_spin)

        self.rate_spin = NoWheelSpinBox()
        self.rate_spin.setRange(0, 9999)
        self.rate_spin.setValue(param_fuzz.DEFAULT_RATE_LIMIT)
        self.rate_spin.setToolTip("每秒最大请求数，0 表示不限速")
        opts3.addWidget(QLabel("限速/秒"))
        opts3.addWidget(self.rate_spin)
        opts3.addStretch(1)
        form.addRow("", opts3)

        layout.addLayout(form)

        # -- 高级选项折叠区 --
        adv_row = QHBoxLayout()
        self.adv_toggle_btn = QPushButton("高级选项 ▸")
        self.adv_toggle_btn.setObjectName("ghbtn")
        self.adv_toggle_btn.setCheckable(True)
        self.adv_toggle_btn.clicked.connect(self._toggle_adv)
        adv_row.addWidget(self.adv_toggle_btn)
        adv_row.addStretch(1)
        layout.addLayout(adv_row)

        self.adv_box = QWidget()
        adv_layout = QVBoxLayout(self.adv_box)
        adv_layout.setContentsMargins(0, 0, 0, 0)
        adv_layout.setSpacing(8)

        adv_hint = QLabel(
            "自定义字典：可填文件路径覆盖上方的 small/medium/large；固定负载"
            "（include）在每次请求中追加——GET/POST 用 query/表单串（如 a=1&b=2），"
            "JSON/XML 用 JSON 对象或含 $arjun$ 占位符的模板；自定义请求头每行一个"
            "「Key: Value」。")
        adv_hint.setObjectName("caption")
        adv_hint.setWordWrap(True)
        adv_layout.addWidget(adv_hint)

        adv_form = QFormLayout()
        adv_form.setHorizontalSpacing(12)
        adv_form.setVerticalSpacing(8)
        self.wordlist_edit = QLineEdit()
        self.wordlist_edit.setPlaceholderText("留空使用上方内建字典，或填文件路径")
        adv_form.addRow("自定义字典", self.wordlist_edit)
        self.include_edit = QLineEdit()
        self.include_edit.setPlaceholderText('如 a=1&b=2 或 {"key":"value"}')
        adv_form.addRow("固定负载 include", self.include_edit)
        adv_layout.addLayout(adv_form)

        adv_layout.addWidget(QLabel("自定义请求头（每行一个 Key: Value）"))
        self.headers_edit = QTextEdit()
        self.headers_edit.setObjectName("io")
        self.headers_edit.setFixedHeight(56)
        self.headers_edit.setPlaceholderText("X-Custom-Header: value")
        adv_layout.addWidget(self.headers_edit)

        self.adv_box.hide()
        layout.addWidget(self.adv_box)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        self.run_btn = QPushButton("开始爆破")
        self.run_btn.setObjectName("ghbtn-primary")
        self.run_btn.clicked.connect(self._start)
        buttons.addWidget(self.run_btn)
        self.stop_btn = QPushButton("停止")
        self.stop_btn.setObjectName("ghbtn")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop)
        buttons.addWidget(self.stop_btn)
        self.save_btn = QPushButton("导出报告…")
        self.save_btn.setObjectName("ghbtn")
        self.save_btn.setEnabled(False)
        self.save_btn.clicked.connect(self._save)
        buttons.addWidget(self.save_btn)
        copy_btn = QPushButton("复制结果")
        copy_btn.setObjectName("ghbtn")
        copy_btn.clicked.connect(self._copy)
        buttons.addWidget(copy_btn)
        clear_btn = QPushButton("清空")
        clear_btn.setObjectName("ghbtn")
        clear_btn.clicked.connect(self._clear)
        buttons.addWidget(clear_btn)
        buttons.addStretch(1)
        layout.addLayout(buttons)

        self.report_label = QLabel("报告")
        self.report_label.setObjectName("section")
        layout.addWidget(self.report_label)

        self.report_view = QPlainTextEdit()
        self.report_view.setObjectName("io")
        self.report_view.setReadOnly(True)
        self.report_view.setPlaceholderText(
            "点击「开始爆破」后，这里会显示命中的参数…")
        self.report_view.setMinimumHeight(280)
        layout.addWidget(self.report_view, 1)

        self.log_label = QLabel("爆破日志")
        self.log_label.setObjectName("section")
        layout.addWidget(self.log_label)

        self.log_view = QPlainTextEdit()
        self.log_view.setObjectName("io")
        self.log_view.setReadOnly(True)
        self.log_view.setMinimumHeight(80)
        self.log_view.setMaximumHeight(140)
        self.log_view.setMaximumBlockCount(2000)
        layout.addWidget(self.log_view)

        self.status_label = QLabel("")
        self.status_label.setObjectName("status-info")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

    # ------------------------------------------------------------------ 配置
    def _restore_config(self) -> None:
        cfg = self.store.get("param_fuzz", default={}) or {}
        try:
            self.timeout_spin.setValue(int(cfg.get("timeout")
                                           or param_fuzz.DEFAULT_TIMEOUT))
        except (TypeError, ValueError):
            self.timeout_spin.setValue(param_fuzz.DEFAULT_TIMEOUT)
        try:
            self.threads_spin.setValue(int(cfg.get("threads")
                                          or param_fuzz.DEFAULT_THREADS))
        except (TypeError, ValueError):
            self.threads_spin.setValue(param_fuzz.DEFAULT_THREADS)
        try:
            self.chunks_spin.setValue(int(cfg.get("chunks")
                                          or param_fuzz.DEFAULT_CHUNKS))
        except (TypeError, ValueError):
            self.chunks_spin.setValue(param_fuzz.DEFAULT_CHUNKS)
        try:
            self.rate_spin.setValue(int(cfg.get("rate_limit")
                                        or param_fuzz.DEFAULT_RATE_LIMIT))
        except (TypeError, ValueError):
            self.rate_spin.setValue(param_fuzz.DEFAULT_RATE_LIMIT)
        method = str(cfg.get("method") or "GET").upper()
        for i in range(self.method_combo.count()):
            if self.method_combo.itemData(i) == method:
                self.method_combo.setCurrentIndex(i)
                break
        wl = str(cfg.get("wordlist") or param_fuzz.DEFAULT_WORDLIST)
        for i in range(self.wordlist_combo.count()):
            if self.wordlist_combo.itemData(i) == wl:
                self.wordlist_combo.setCurrentIndex(i)
                break

    def _save_config(self) -> None:
        self.store.setv(self.method_combo.currentData(), "param_fuzz", "method")
        self.store.setv(self.wordlist_combo.currentData(), "param_fuzz", "wordlist")
        self.store.setv(int(self.timeout_spin.value()), "param_fuzz", "timeout")
        self.store.setv(int(self.threads_spin.value()), "param_fuzz", "threads")
        self.store.setv(int(self.chunks_spin.value()), "param_fuzz", "chunks")
        self.store.setv(int(self.rate_spin.value()), "param_fuzz", "rate_limit")
        self.store.save()

    @property
    def _output_root(self) -> Path:
        cfg = self.store.get("watermark", default={}) or {}
        return watermark.resolve_output_dir(cfg.get("output_dir"))

    # ------------------------------------------------------------------ 操作
    def _toggle_adv(self, checked: bool) -> None:
        self.adv_box.setVisible(bool(checked))
        self.adv_toggle_btn.setText("高级选项 ▾" if checked else "高级选项 ▸")

    def _start(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._set_status(False, "爆破正在进行中，请先停止。")
            return
        target = self.target_edit.text().strip()
        if not target:
            self._set_status(False, "请填写目标 URL，如 https://example.com。")
            return

        self._save_config()
        self._result = None
        self.report_view.clear()
        self.log_view.clear()
        self.save_btn.setEnabled(False)
        self.run_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self._set_status(True, "正在爆破…")

        wordlist = self.wordlist_edit.text().strip() or self.wordlist_combo.currentData()

        old = self._worker
        worker = _ParamFuzzWorker(
            target,
            self.method_combo.currentData(),
            wordlist,
            self.include_edit.text(),
            self.headers_edit.toPlainText(),
            float(self.timeout_spin.value()),
            int(self.threads_spin.value()),
            int(self.chunks_spin.value()),
            float(self.delay_spin.value()),
            int(self.rate_spin.value()),
            self,
        )
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
            self._set_status(True, "正在停止…（等待在途请求结束）")

    def _clear(self) -> None:
        self.report_view.clear()
        self.log_view.clear()
        self._result = None
        self.save_btn.setEnabled(False)
        self._set_status(True, "")

    def _on_done(self, result: dict) -> None:
        self._reset_buttons()
        self._result = result
        self.report_view.setPlainText(param_fuzz.to_text(result))
        self.save_btn.setEnabled(True)
        if result.get("skipped"):
            self._set_status(False, f"已跳过：{result.get('skip_reason', '')}")
            return
        found = result.get("found_params") or []
        if result.get("stopped"):
            self._set_status(True, f"已停止：命中 {len(found)} 个参数。")
        else:
            self._set_status(True, f"爆破完成：命中 {len(found)} 个参数。")

    def _on_error(self, message: str) -> None:
        self._reset_buttons()
        self._set_status(False, message)

    def _reset_buttons(self) -> None:
        self.run_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def _save(self) -> None:
        if self._result is None:
            self._set_status(False, "还没有可导出的结果，请先开始爆破。")
            return
        target = self.target_edit.text().strip()
        if "://" not in target:
            target = "http://" + target
        host = urlparse(target).netloc.replace(":", "_") or "paramfuzz"
        out_dir = self._output_root
        default = str(out_dir / f"{host}_paramfuzz.txt")
        path, _ = QFileDialog.getSaveFileName(
            self, "导出参数爆破报告", default, "文本文件 (*.txt)")
        if not path:
            return
        try:
            Path(path).write_text(param_fuzz.to_text(self._result), encoding="utf-8")
        except OSError as exc:
            self._set_status(False, f"保存失败：{exc}")
            return
        self._set_status(True, f"已导出：{path}")

    def _copy(self) -> None:
        if self._result is None:
            self._set_status(False, "还没有可复制的结果，请先开始爆破。")
            return
        found = self._result.get("found_params") or []
        if not found:
            self._set_status(False, "没有命中参数，无可复制内容。")
            return
        QApplication.clipboard().setText("\n".join(found))
        self._set_status(True, f"已复制 {len(found)} 个参数到剪贴板。")

    # ------------------------------------------------------------------ 输出
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
        """退出前请求停止爆破线程（closeEvent 调用）。"""
        if self._worker is not None and self._worker.isRunning():
            self._worker.stop()
            self._worker.wait(1500)
