# -*- coding: utf-8 -*-
"""指纹探测页（observer_ward 风格 Web 应用 / 服务指纹识别）。

输入目标 URL，用 ``lib.fingerprint`` 的规则匹配引擎（兼容 observer_ward /
FingerprintHub 的 YAML 指纹规则）对目标做指纹探测：关键词 / 正则 / favicon
（mmh3 + md5）三类匹配器，返回命中的组件名、厂商、产品、版本与匹配证据。

- 默认加载内置 ``dict/fingerprints`` 规则库；
- 可「加载规则目录」扩充自定义规则；
- 表格列出命中的指纹（名称 / 产品 / 厂商 / 版本 / 匹配类型 / 证据），
  可复制 / 保存为 CSV；
- 网络请求走全局代理池，后台线程执行，支持随时中止。
"""

from __future__ import annotations

import csv
import re
from datetime import datetime
from pathlib import Path

from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
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

from app.widgets.fuzz_worker import FuzzWorker
from app.widgets.no_wheel import NoWheelSpinBox
from lib import fingerprint
from lib.watermark import resolve_output_dir


class _FingerprintWorker(FuzzWorker):
    """后台执行指纹探测。"""

    error_prefix = "探测失败"

    def __init__(self, target: str, timeout: int,
                 rules: list[dict] | None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._target = target
        self._timeout = timeout
        self._rules = rules

    def task(self) -> dict:
        return fingerprint.run(
            self._target,
            timeout=self._timeout,
            rules=self._rules,
            log=self.log.emit,
            stop=self._event,
        )


class FingerprintPage(QWidget):
    """指纹探测页：observer_ward 风格 Web 指纹识别。"""

    #: 表格列顺序
    COLUMNS = ("组件", "产品", "厂商", "版本", "匹配", "证据")
    #: 结果 dict 中与 ``COLUMNS`` 一一对应的键
    KEYS = ("name", "product", "vendor", "version", "match_type", "evidence")

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._worker: _FingerprintWorker | None = None
        self._result: dict | None = None
        self._rules: list[dict] | None = None
        self._build_ui()
        self._restore_config()

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(36, 28, 36, 28)
        layout.setSpacing(10)

        form = QHBoxLayout()
        form.setSpacing(10)
        form.addWidget(QLabel("目标 URL"))
        self.url_edit = QLineEdit()
        self.url_edit.setPlaceholderText(
            "https://example.com（可省略协议头，如 example.com）")
        self.url_edit.returnPressed.connect(self._start)
        form.addWidget(self.url_edit, 1)
        layout.addLayout(form)

        opts = QHBoxLayout()
        opts.setSpacing(16)
        self.timeout_spin = NoWheelSpinBox()
        self.timeout_spin.setRange(1, 60)
        self.timeout_spin.setValue(fingerprint.DEFAULT_TIMEOUT)
        self.timeout_spin.setSuffix(" 秒")
        opts.addWidget(QLabel("超时"))
        opts.addWidget(self.timeout_spin)
        self.rules_dir_label = QLabel("规则库：内置（dict/fingerprints）")
        self.rules_dir_label.setObjectName("caption")
        opts.addWidget(self.rules_dir_label)
        opts.addStretch(1)
        layout.addLayout(opts)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        self.run_btn = QPushButton("开始探测")
        self.run_btn.setObjectName("ghbtn-primary")
        self.run_btn.clicked.connect(self._start)
        buttons.addWidget(self.run_btn)

        self.stop_btn = QPushButton("停止")
        self.stop_btn.setObjectName("ghbtn")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop)
        buttons.addWidget(self.stop_btn)

        self.load_btn = QPushButton("加载规则目录…")
        self.load_btn.setObjectName("ghbtn")
        self.load_btn.clicked.connect(self._load_rules_dir)
        buttons.addWidget(self.load_btn)

        self.reload_btn = QPushButton("还原内置规则")
        self.reload_btn.setObjectName("ghbtn")
        self.reload_btn.clicked.connect(self._reset_rules)
        buttons.addWidget(self.reload_btn)

        self.copy_btn = QPushButton("复制结果")
        self.copy_btn.setObjectName("ghbtn")
        self.copy_btn.setEnabled(False)
        self.copy_btn.clicked.connect(self._copy)
        buttons.addWidget(self.copy_btn)

        self.save_btn = QPushButton("保存结果…")
        self.save_btn.setObjectName("ghbtn")
        self.save_btn.setEnabled(False)
        self.save_btn.clicked.connect(self._save)
        buttons.addWidget(self.save_btn)
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
                (QHeaderView.ResizeMode.ResizeToContents,
                 QHeaderView.ResizeMode.ResizeToContents,
                 QHeaderView.ResizeMode.ResizeToContents,
                 QHeaderView.ResizeMode.ResizeToContents,
                 QHeaderView.ResizeMode.ResizeToContents,
                 QHeaderView.ResizeMode.Stretch)):
            header.setSectionResizeMode(col, mode)
        layout.addWidget(self.table, stretch=1)

        self.log_label = QLabel("探测日志")
        self.log_label.setObjectName("section")
        layout.addWidget(self.log_label)

        self.log_view = QPlainTextEdit()
        self.log_view.setObjectName("io")
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(2000)
        self.log_view.setMaximumHeight(120)
        layout.addWidget(self.log_view)

        self.status_label = QLabel("")
        self.status_label.setObjectName("status-info")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

    # ------------------------------------------------------------------ 配置
    def _restore_config(self) -> None:
        cfg = self.store.get("fingerprint", default={}) or {}
        try:
            self.timeout_spin.setValue(
                int(cfg.get("timeout") or fingerprint.DEFAULT_TIMEOUT))
        except (TypeError, ValueError):
            self.timeout_spin.setValue(fingerprint.DEFAULT_TIMEOUT)
        rules_dir = cfg.get("rules_dir") or ""
        if rules_dir:
            self._load_rules_from(str(rules_dir))

    def _save_config(self) -> None:
        self.store.setv(int(self.timeout_spin.value()), "fingerprint", "timeout")
        self.store.setv(self._rules_dir_cfg or "", "fingerprint", "rules_dir")
        self.store.save()

    # ------------------------------------------------------------------ 规则
    @property
    def _rules_dir_cfg(self) -> str:
        cfg = self.store.get("fingerprint", default={}) or {}
        return str(cfg.get("rules_dir") or "")

    def _load_rules_from(self, directory: str) -> None:
        """从指定目录加载规则（失败时回退内置并提示）。"""
        rules = fingerprint.load_rules([directory])
        errors = [r["_load_errors"] for r in rules if isinstance(r, dict) and "_load_errors" in r]
        errors = [e for sub in errors for e in sub]
        clean = [r for r in rules if isinstance(r, dict) and "_load_errors" not in r]
        if not clean and errors:
            self._rules = None
            self.rules_dir_label.setText("规则库：内置（dict/fingerprints）")
            self._set_status(False, "自定义规则加载失败：" + errors[0])
            return
        self._rules = clean
        self.rules_dir_label.setText(f"规则库：自定义（{directory}，{len(clean)} 条）")
        self._set_status(True, f"已加载自定义规则 {len(clean)} 条" + (
            f"，{len(errors)} 条加载失败" if errors else ""))

    def _load_rules_dir(self) -> None:
        directory = QFileDialog.getExistingDirectory(self, "选择指纹规则目录")
        if not directory:
            return
        self._load_rules_from(directory)

    def _reset_rules(self) -> None:
        self._rules = None
        self.store.setv("", "fingerprint", "rules_dir")
        self.store.save()
        self.rules_dir_label.setText("规则库：内置（dict/fingerprints）")
        self._set_status(True, "已还原为内置规则库。")

    # ------------------------------------------------------------------ 运行
    def _start(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._set_status(False, "探测正在进行中，请先停止。")
            return
        target = self.url_edit.text().strip()
        if not target:
            self._set_status(False, "请填写目标 URL，如 https://example.com。")
            return

        self._save_config()
        self._result = None
        self.table.setRowCount(0)
        self.log_view.clear()
        self.copy_btn.setEnabled(False)
        self.save_btn.setEnabled(False)
        self.run_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self._set_status(True, "正在探测…")

        old = self._worker
        worker = _FingerprintWorker(
            target, int(self.timeout_spin.value()), self._rules, self)
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

    def _on_done(self, result: dict) -> None:
        self._reset_buttons()
        self._result = result
        matches = result.get("matches") or []
        for item in matches:
            self._add_row(item)
        self.copy_btn.setEnabled(bool(matches))
        self.save_btn.setEnabled(bool(matches))
        msg = (f"探测{'已停止' if result.get('stopped') else '完成'}："
               f"加载规则 {result.get('rules_loaded', 0)} 条，"
               f"命中 {len(matches)} 个指纹，耗时 {result.get('elapsed', 0)}s。")
        if result.get("load_errors"):
            msg += f"（{len(result['load_errors'])} 条规则加载失败）"
        self._set_status(not result.get("stopped"), msg)

    def _on_error(self, message: str) -> None:
        self._reset_buttons()
        self._set_status(False, message)

    def _reset_buttons(self) -> None:
        self.run_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def _add_row(self, item: dict) -> None:
        row = self.table.rowCount()
        self.table.insertRow(row)
        for col, key in enumerate(self.KEYS):
            self.table.setItem(row, col, QTableWidgetItem(str(item.get(key, ""))))

    # ------------------------------------------------------------------ 导出
    def _copy(self) -> None:
        matches = (self._result or {}).get("matches") or []
        if not matches:
            self._set_status(False, "还没有可复制的结果，请先开始探测。")
            return
        lines = ["\t".join(self.COLUMNS)]
        for item in matches:
            lines.append("\t".join(
                str(item.get(key, "")).replace("\t", " ").replace("\n", " ")
                for key in self.KEYS))
        QApplication.clipboard().setText("\n".join(lines))
        self._set_status(True, f"已复制 {len(matches)} 条结果到剪贴板。")

    def _save(self) -> None:
        if self._result is None:
            self._set_status(False, "还没有可保存的结果，请先开始探测。")
            return
        matches = self._result.get("matches") or []
        if not matches:
            self._set_status(False, "没有命中指纹，无需保存。")
            return
        target = self.url_edit.text().strip()
        if "://" not in target:
            target = "http://" + target
        host = re.sub(r"[^\w.-]", "_", target)[:40] or "result"
        cfg = self.store.get("watermark", default={}) or {}
        out_dir = resolve_output_dir(cfg.get("output_dir"))
        default = str(out_dir / f"fingerprint_{host}_"
                                f"{datetime.now():%Y%m%d_%H%M%S}.csv")
        path, _ = QFileDialog.getSaveFileName(
            self, "保存指纹探测结果", default, "CSV 文件 (*.csv)")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as fp:
                writer = csv.writer(fp)
                writer.writerow(self.COLUMNS)
                for item in matches:
                    writer.writerow([str(item.get(key, "")) for key in self.KEYS])
        except OSError as exc:
            self._set_status(False, f"保存失败：{exc}")
            return
        self._set_status(True, f"已保存 {len(matches)} 条结果：{path}")

    # ------------------------------------------------------------------ 杂项
    def _append_log(self, message: str) -> None:
        self.log_view.appendPlainText(message)
        bar = self.log_view.verticalScrollBar()
        bar.setValue(bar.maximum())

    def _set_status(self, ok: bool, text: str) -> None:
        self.status_label.setText(text)
        self.status_label.setObjectName("status-err" if not ok else "status-info")
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)

    def shutdown(self) -> None:
        """退出前请求停止探测线程（closeEvent 调用）。"""
        if self._worker is not None and self._worker.isRunning():
            self._worker.stop()
            self._worker.wait(1500)
