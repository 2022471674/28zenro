# -*- coding: utf-8 -*-
"""DNS 解析页：对单个域名解析 A / AAAA / CNAME 三类记录。

输入一个域名（可带 http/https 前缀与端口，会自动规范化），后台调用
:mod:`lib.dns_tool.resolve_dns` 用 ``Resolve-DnsName`` 与 ``nslookup`` 交叉
校准（另加 socket 兜底，可走全局代理池 SOCKS5 做远程 DNS），结果按记录类型
分区展示。

网络 / 系统命令在后台线程执行，界面不阻塞；支持停止。
"""

from __future__ import annotations

import threading

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from lib import dns_tool


class _DnsWorker(QThread):
    """后台执行 DNS 解析，日志 / 结果 / 错误经信号回传主线程。"""

    log = Signal(str)
    done_ok = Signal(dict)
    done_err = Signal(str)

    def __init__(self, host: str, use_proxy: bool,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._host = host
        self._use_proxy = use_proxy
        self._event = threading.Event()

    def stop(self) -> None:
        """请求中止：不再开始新的解析，在途查询尽快收尾。"""
        self._event.set()

    def run(self) -> None:  # noqa: D102  线程入口
        try:
            if self._event.is_set():
                self.done_err.emit("已停止。")
                return
            result = dns_tool.resolve_dns(self._host, use_proxy=self._use_proxy)
        except dns_tool.DnsToolError as exc:
            self.done_err.emit(str(exc))
            return
        except Exception as exc:  # noqa: BLE001  后台线程兜底
            self.done_err.emit(f"解析失败：{exc}")
            return
        self.done_ok.emit(result)


class DnsPage(QWidget):
    """DNS 解析页：A / AAAA / CNAME 三类记录查询。"""

    #: 记录类型显示名映射
    _TYPE_LABELS = {"A": "A（IPv4）", "AAAA": "AAAA（IPv6）", "CNAME": "CNAME（别名）"}

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._worker: _DnsWorker | None = None
        self._build_ui()
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

        form = QHBoxLayout()
        form.setSpacing(10)
        form.addWidget(QLabel("域名"))
        self.host_edit = QLineEdit()
        self.host_edit.setPlaceholderText(
            "example.com（可带 http/https 前缀与端口，会自动规范化）")
        self.host_edit.returnPressed.connect(self._start)
        form.addWidget(self.host_edit, 1)
        layout.addLayout(form)

        opts = QHBoxLayout()
        opts.setSpacing(16)
        self.proxy_check = QCheckBox("走代理（SOCKS5 远程 DNS）")
        self.proxy_check.setChecked(False)
        self.proxy_check.setToolTip(
            "开启后解析经全局代理池的 SOCKS5 代理做远程 DNS；关闭则系统本地 DNS。")
        opts.addWidget(self.proxy_check)
        opts.addStretch(1)
        layout.addLayout(opts)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        self.run_btn = QPushButton("开始解析")
        self.run_btn.setObjectName("ghbtn-primary")
        self.run_btn.clicked.connect(self._start)
        buttons.addWidget(self.run_btn)

        self.stop_btn = QPushButton("停止")
        self.stop_btn.setObjectName("ghbtn")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop)
        buttons.addWidget(self.stop_btn)

        clear_btn = QPushButton("清空")
        clear_btn.setObjectName("ghbtn")
        clear_btn.clicked.connect(self._clear)
        buttons.addWidget(clear_btn)
        buttons.addStretch(1)
        layout.addLayout(buttons)

        self.result_label = QLabel("解析结果")
        self.result_label.setObjectName("section")
        layout.addWidget(self.result_label)

        self.result_view = QPlainTextEdit()
        self.result_view.setObjectName("io")
        self.result_view.setReadOnly(True)
        self.result_view.setPlaceholderText(
            "点击「开始解析」后，这里会显示 A / AAAA / CNAME 记录…")
        self.result_view.setMinimumHeight(280)
        layout.addWidget(self.result_view, 1)

        self.status_label = QLabel("")
        self.status_label.setObjectName("status-info")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

    # ------------------------------------------------------------------ 配置
    def _restore_config(self) -> None:
        cfg = self.store.get("dns_tool", default={}) or {}
        self.proxy_check.setChecked(bool(cfg.get("use_proxy", False)))

    def _save_config(self) -> None:
        self.store.setv(bool(self.proxy_check.isChecked()), "dns_tool", "use_proxy")
        self.store.save()

    # ------------------------------------------------------------------ 操作
    def _start(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._set_status(False, "解析正在进行中，请先停止。")
            return
        host = self.host_edit.text().strip()
        if not host:
            self._set_status(False, "请填写要解析的域名，如 example.com。")
            return

        self._save_config()
        self.result_view.clear()
        self.run_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self._set_status(True, "正在解析…")

        old = self._worker
        worker = _DnsWorker(host, self.proxy_check.isChecked(), self)
        worker.done_ok.connect(self._on_done)
        worker.done_err.connect(self._on_error)
        self._worker = worker
        if old is not None:
            old.deleteLater()
        worker.start()

    def _stop(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._worker.stop()
            self._set_status(True, "正在停止…（等待在途查询结束）")

    def _clear(self) -> None:
        self.host_edit.clear()
        self.result_view.clear()
        self._set_status(True, "")

    def _on_done(self, result: dict) -> None:
        self._reset_buttons()
        lines: list[str] = []
        lines.append(f"主机: {result.get('host', '')}")
        records = result.get("records") or []
        if not records:
            lines.append("")
            lines.append("（未解析到任何记录）")
        for rec in records:
            rtype = rec.get("type", "")
            label = self._TYPE_LABELS.get(rtype, rtype)
            values = rec.get("values") or []
            note = rec.get("note", "")
            lines.append("")
            lines.append(f"=== {label} ===" + (f"  [注意] {note}" if note else ""))
            for value in values:
                lines.append(f"  {value}")
        self.result_view.setPlainText("\n".join(lines))
        count = len(records)
        self._set_status(True, f"解析完成：{count} 类记录。")

    def _on_error(self, message: str) -> None:
        self._reset_buttons()
        self._set_status(False, message)

    def _reset_buttons(self) -> None:
        self.run_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    # ------------------------------------------------------------------ 输出
    def _set_status(self, ok: bool, text: str) -> None:
        self.status_label.setText(text)
        self.status_label.setObjectName("status-ok" if ok else "status-err")
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)

    # ------------------------------------------------------------------ 生命周期
    def shutdown(self) -> None:
        """退出前请求停止 DNS 解析线程（closeEvent 调用）。"""
        if self._worker is not None and self._worker.isRunning():
            self._worker.stop()
            self._worker.wait(1500)
