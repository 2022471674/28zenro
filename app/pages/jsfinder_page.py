# -*- coding: utf-8 -*-
"""JSFinder 页（``JSFinder.py`` 整合迁移）。

输入目标 URL（可选 Cookie），抓取页面与其全部 ``<script>``，
用 LinkFinder 正则提取同主域 URL 与子域名：
- 普通模式：只分析目标页面及其内嵌 / 外链 JS；
- 深度模式：跟进页面上的 ``<a>`` 链接递归收集（最多 50 个链接，带进度）。

结果可复制到剪贴板或保存为 txt 文件；网络请求放后台线程执行，不阻塞界面。
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSplitter,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.widgets.no_wheel import NoWheelSpinBox
from lib import jsfinder, watermark


class _FinderWorker(QThread):
    """后台执行 JSFinder 收集，进度与结果经信号回传主线程。"""

    progress = Signal(str)
    done_ok = Signal(list, list)   # URL 列表、子域名列表（接口模式下子域名为空）
    done_err = Signal(str)

    def __init__(self, url: str, cookie: str, deep: bool,
                 timeout: int, endpoint: bool,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._url = url
        self._cookie = cookie
        self._deep = deep
        self._timeout = timeout
        self._endpoint = endpoint

    def run(self) -> None:  # noqa: D102  线程入口
        try:
            urls, subs = jsfinder.run(
                self._url,
                cookie=self._cookie,
                deep=self._deep,
                timeout=self._timeout,
                endpoint=self._endpoint,
                progress=self.progress.emit,
            )
        except Exception as exc:  # noqa: BLE001  后台线程兜底
            self.done_err.emit(str(exc))
            return
        self.done_ok.emit(urls, subs)


class JsFinderPage(QWidget):
    """JSFinder 页：URL / 子域名收集。"""

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._worker: _FinderWorker | None = None
        self._urls: list[str] = []
        self._subs: list[str] = []
        self._build_ui()

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(36, 28, 36, 28)
        layout.setSpacing(10)

        form = QFormLayout()
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(10)

        self.url_edit = QLineEdit()
        self.url_edit.setPlaceholderText("目标网址，如 https://example.com（可省略协议头）")
        form.addRow("目标 URL", self.url_edit)

        self.cookie_edit = QLineEdit()
        self.cookie_edit.setPlaceholderText("可选：登录态 Cookie，用于访问需鉴权的页面")
        form.addRow("Cookie", self.cookie_edit)

        opts = QHBoxLayout()
        opts.setSpacing(16)
        self.timeout_spin = NoWheelSpinBox()
        self.timeout_spin.setRange(1, 60)
        self.timeout_spin.setValue(jsfinder.DEFAULT_TIMEOUT)
        self.timeout_spin.setSuffix(" 秒")
        opts.addWidget(QLabel("超时"))
        opts.addWidget(self.timeout_spin)
        self.deep_check = QCheckBox("深度模式（跟进页面链接递归收集）")
        opts.addWidget(self.deep_check)
        self.endpoint_check = QCheckBox("覆盖 JS 文件查询（提取接口路径）")
        opts.addWidget(self.endpoint_check)
        opts.addStretch(1)
        form.addRow("", opts)
        layout.addLayout(form)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        run_btn = QPushButton("开始收集")
        run_btn.setObjectName("ghbtn-primary")
        run_btn.clicked.connect(self._run_finder)
        buttons.addWidget(run_btn)
        copy_url_btn = QPushButton("复制 URL")
        copy_url_btn.setObjectName("ghbtn")
        copy_url_btn.clicked.connect(
            lambda: self._copy(self.url_text, self._urls, "URL"))
        buttons.addWidget(copy_url_btn)
        copy_sub_btn = QPushButton("复制子域名")
        copy_sub_btn.setObjectName("ghbtn")
        copy_sub_btn.clicked.connect(
            lambda: self._copy(self.sub_text, self._subs, "子域名"))
        buttons.addWidget(copy_sub_btn)
        save_btn = QPushButton("保存结果…")
        save_btn.setObjectName("ghbtn")
        save_btn.clicked.connect(self._save)
        buttons.addWidget(save_btn)
        buttons.addStretch(1)
        layout.addLayout(buttons)

        splitter = QSplitter()
        splitter.setOrientation(Qt.Vertical)
        splitter.setChildrenCollapsible(False)

        url_box = QWidget()
        url_layout = QVBoxLayout(url_box)
        url_layout.setContentsMargins(0, 0, 0, 0)
        url_layout.setSpacing(6)
        self.url_label = QLabel("URL 列表")
        self.url_label.setObjectName("caption")
        url_layout.addWidget(self.url_label)
        self.url_text = QTextEdit()
        self.url_text.setObjectName("io")
        self.url_text.setReadOnly(True)
        self.url_text.setPlaceholderText("点击「开始收集」后在此显示提取到的 URL…")
        url_layout.addWidget(self.url_text)
        splitter.addWidget(url_box)

        sub_box = QWidget()
        sub_layout = QVBoxLayout(sub_box)
        sub_layout.setContentsMargins(0, 0, 0, 0)
        sub_layout.setSpacing(6)
        self.sub_label = QLabel("子域名列表")
        self.sub_label.setObjectName("caption")
        sub_layout.addWidget(self.sub_label)
        self.sub_text = QTextEdit()
        self.sub_text.setObjectName("io")
        self.sub_text.setReadOnly(True)
        self.sub_text.setPlaceholderText("主域名下的子域名会显示在这里…")
        sub_layout.addWidget(self.sub_text)
        splitter.addWidget(sub_box)

        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        layout.addWidget(splitter, stretch=1)

        self.status_label = QLabel("")
        self.status_label.setObjectName("status-info")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

    # -------------------------------------------------------------- 运行
    def _run_finder(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._set_status(False, "上一个任务还在进行中，请稍候。")
            return
        url = self.url_edit.text().strip()
        if not url:
            self._set_status(False, "请先填写目标 URL。")
            return

        worker = _FinderWorker(
            url,
            self.cookie_edit.text().strip(),
            self.deep_check.isChecked(),
            self.timeout_spin.value(),
            self.endpoint_check.isChecked(),
            self,
        )
        worker.progress.connect(
            lambda msg: self._set_status(True, msg))
        worker.done_ok.connect(self._on_ok)
        worker.done_err.connect(self._on_err)
        self._worker = worker
        worker.start()
        if self.endpoint_check.isChecked():
            self._set_status(True, "正在覆盖 JS 文件查询接口…")
        else:
            self._set_status(True, "正在收集…")

    def _on_err(self, message: str) -> None:
        self._set_status(False, message)

    def _on_ok(self, urls: list, subs: list) -> None:
        self._urls = list(urls)
        self._subs = list(subs)
        self.url_text.setPlainText("\n".join(self._urls))
        self.sub_text.setPlainText("\n".join(self._subs))
        if self.endpoint_check.isChecked():
            self.url_label.setText(f"接口列表（{len(self._urls)} 条）")
            self.sub_label.setText("子域名列表（接口模式下不提取）")
            self._set_status(True, "接口查询完成。")
        else:
            self.url_label.setText(f"URL 列表（{len(self._urls)} 条）")
            self.sub_label.setText(f"子域名列表（{len(self._subs)} 条）")
            self._set_status(True, "收集完成。")

    # -------------------------------------------------------------- 操作
    def _copy(self, text_edit: QTextEdit, items: list, kind: str) -> None:
        if not items:
            self._set_status(False, f"还没有可复制的{kind}，请先开始收集。")
            return
        QApplication.clipboard().setText("\n".join(items))
        self._set_status(True, f"已复制 {len(items)} 条{kind}到剪贴板。")

    def _save(self) -> None:
        if not self._urls and not self._subs:
            self._set_status(False, "还没有可保存的结果，请先开始收集。")
            return
        target = self.url_edit.text().strip()
        if "://" not in target:
            target = "http://" + target
        host = urlparse(target).netloc.replace(":", "_") or "jsfinder"
        cfg = self.store.get("watermark", default={}) or {}
        out_dir = watermark.resolve_output_dir(cfg.get("output_dir"))
        default = str(out_dir / f"{host}_jsfinder.txt")
        path, _ = QFileDialog.getSaveFileName(
            self, "保存收集结果", default, "文本文件 (*.txt)")
        if not path:
            return
        lines = [
            "# JSFinder 收集结果",
            f"# 目标: {self.url_edit.text().strip()}",
            f"# 时间: {datetime.now():%Y-%m-%d %H:%M:%S}",
            "",
            f"=== URL（{len(self._urls)} 条）===",
            *self._urls,
            "",
            f"=== 子域名（{len(self._subs)} 条）===",
            *self._subs,
            "",
        ]
        try:
            Path(path).write_text("\n".join(lines), encoding="utf-8")
        except OSError as exc:
            self._set_status(False, f"保存失败：{exc}")
            return
        self._set_status(True, f"已保存：{path}")

    def _set_status(self, ok: bool, text: str) -> None:
        self.status_label.setText(text)
        self.status_label.setObjectName("status-err" if ok is False else "status-info")
        self.style().unpolish(self.status_label)
        self.style().polish(self.status_label)
