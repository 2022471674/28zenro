# -*- coding: utf-8 -*-
"""端口爆破页：通过代理池扫描目标端口，检测到封禁 / 代理失效立即换代理。

三种代理来源：

- **全局代理池**（默认）：复用设置页「Web 工具代理池」拉取并验证过的免费代理，
  每个端口从池里轮换取代理，封禁即换；使用前先检测池内是否有可用代理；
- **代理列表文件**：一行一个（``socks5://host:port`` / ``http://host:port`` /
  ``host:port``），本工具自己轮换，封禁即换下一个；
- **直连**：不走代理，用于对照。

端口来源支持内置字典（``dict/Ports``）、自定义字典文件、手动端口表达式
（``1-1024,3306,6379``）。网络与代理验证都在后台线程里跑，界面不阻塞。
"""

from __future__ import annotations

import threading
from pathlib import Path

from PySide6.QtCore import Qt, QThread, QTimer, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
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

from app.widgets.no_wheel import NoWheelComboBox, NoWheelSpinBox
from lib import port_scan, proxy_pool
from lib.watermark import resolve_output_dir

PROXY_MODES = (
    ("global", "全局代理池（设置页配置）"),
    ("file", "代理列表文件"),
    ("direct", "直连（不走代理）"),
)

PORT_SOURCES = (
    ("builtin", "内置字典（dict/Ports）"),
    ("file", "自定义字典文件"),
    ("manual", "手动范围"),
)

#: 代理健康检查用的公网参照（不依赖用户目标，避免目标封禁导致误判）
CHECK_HOST = "www.baidu.com"
CHECK_PORT = 443


class _PortWorker(QThread):
    """后台执行端口扫描，命中 / 进度 / 日志经信号回传主线程。"""

    log = Signal(str)
    hit = Signal(dict)
    progress = Signal(int, int)
    done_ok = Signal(dict)
    done_err = Signal(str)

    def __init__(self, host: str, ports: list[int], pool, service_map: dict,
                 threads: int, timeout: float, retries: int, out_dir: str,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._host = host
        self._ports = ports
        self._pool = pool
        self._service_map = service_map
        self._threads = threads
        self._timeout = timeout
        self._retries = retries
        self._out_dir = out_dir
        self._event = threading.Event()

    def stop(self) -> None:
        """请求中止：不再派发新端口，在途探测尽快收尾。"""
        self._event.set()

    def run(self) -> None:  # noqa: D102  线程入口
        try:
            result = port_scan.scan(
                self._host,
                self._ports,
                pool=self._pool,
                threads=self._threads,
                timeout=self._timeout,
                retries=self._retries,
                service_map=self._service_map,
                log=self.log.emit,
                on_hit=lambda item: self.hit.emit(item.to_dict()),
                on_progress=lambda st: self.progress.emit(st.done, st.total),
                stop=self._event,
                out_dir=self._out_dir,
            )
        except Exception as exc:  # noqa: BLE001  后台线程兜底
            self.done_err.emit(f"扫描失败：{exc}")
            return
        self.done_ok.emit(result)


class _CheckWorker(QThread):
    """后台验证代理池是否可用（含假代理识别）。"""

    log = Signal(str)
    done_ok = Signal(dict)
    done_err = Signal(str)

    def __init__(self, pool, dst_host: str, dst_port: int, threads: int,
                 timeout: float, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._pool = pool
        self._dst_host = dst_host
        self._dst_port = dst_port
        self._threads = threads
        self._timeout = timeout
        self._event = threading.Event()

    def stop(self) -> None:
        self._event.set()

    def run(self) -> None:  # noqa: D102  线程入口
        try:
            stats = self._pool.health_check(
                self._dst_host,
                self._dst_port,
                threads=self._threads,
                timeout=self._timeout,
                log=self.log.emit,
                stop=self._event,
            )
        except Exception as exc:  # noqa: BLE001
            self.done_err.emit(f"代理检查失败：{exc}")
            return
        self.done_ok.emit(stats)


class PortPage(QWidget):
    """端口爆破页面。"""

    COLUMNS = ("端口", "服务", "状态", "延迟", "代理")

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._worker: _PortWorker | None = None
        self._check_worker: _CheckWorker | None = None
        self._dict_files: list[Path] = []
        self._build_ui()
        self._apply_styles()
        self._restore_config()
        self._reload_dict_list()
        self._on_source_changed()
        self._on_mode_changed()

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
        self.form = form

        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText("目标 IP 或域名，例如 192.168.1.10 / example.com")
        self.target_edit.returnPressed.connect(self._start)
        form.addRow("目标", self.target_edit)

        # -- 端口来源 ------------------------------------------------------
        self.source_combo = NoWheelComboBox()
        for key, label in PORT_SOURCES:
            self.source_combo.addItem(label, key)
        self.source_combo.currentIndexChanged.connect(self._on_source_changed)
        form.addRow("端口来源", self.source_combo)

        dict_row = QHBoxLayout()
        dict_row.setSpacing(8)
        self.dict_combo = NoWheelComboBox()
        self.dict_combo.currentIndexChanged.connect(self._on_dict_changed)
        dict_row.addWidget(self.dict_combo, 1)
        reload_btn = QPushButton("重新加载")
        reload_btn.setObjectName("ghbtn")
        reload_btn.clicked.connect(self._reload_dict_list)
        dict_row.addWidget(reload_btn)
        self.dict_row = dict_row
        form.addRow("内置字典", dict_row)

        file_row = QHBoxLayout()
        file_row.setSpacing(8)
        self.dict_file_edit = QLineEdit()
        self.dict_file_edit.setPlaceholderText("自定义端口字典（一行一个：端口 或 端口 服务名）")
        file_row.addWidget(self.dict_file_edit, 1)
        dict_browse = QPushButton("浏览…")
        dict_browse.setObjectName("ghbtn")
        dict_browse.clicked.connect(self._browse_dict_file)
        file_row.addWidget(dict_browse)
        self.dict_file_row = file_row
        form.addRow("字典文件", file_row)

        self.manual_edit = QLineEdit()
        self.manual_edit.setPlaceholderText("例如 1-1024,3306,6379,27017（逗号 / 空格分隔）")
        form.addRow("端口范围", self.manual_edit)

        self.ports_hint = QLabel("")
        self.ports_hint.setObjectName("caption")
        self.ports_hint.setWordWrap(True)
        form.addRow("", self.ports_hint)

        # -- 代理 ----------------------------------------------------------
        self.mode_combo = NoWheelComboBox()
        for key, label in PROXY_MODES:
            self.mode_combo.addItem(label, key)
        self.mode_combo.currentIndexChanged.connect(self._on_mode_changed)
        form.addRow("代理方式", self.mode_combo)

        proxy_row = QHBoxLayout()
        proxy_row.setSpacing(8)
        self.proxy_edit = QLineEdit()
        self.proxy_edit.setPlaceholderText("代理列表文件（socks5://h:p / http://h:p / h:p，一行一个）")
        # 手输路径也要刷新「已载入 N 个代理」提示，400ms 防抖避免每敲一个键就读文件
        self._proxy_timer = QTimer(self)
        self._proxy_timer.setSingleShot(True)
        self._proxy_timer.setInterval(400)
        self._proxy_timer.timeout.connect(self._on_mode_changed)
        self.proxy_edit.textChanged.connect(lambda _t: self._proxy_timer.start())
        proxy_row.addWidget(self.proxy_edit, 1)
        proxy_browse = QPushButton("浏览…")
        proxy_browse.setObjectName("ghbtn")
        proxy_browse.clicked.connect(self._browse_proxy_file)
        proxy_row.addWidget(proxy_browse)
        self.proxy_row = proxy_row
        form.addRow("代理文件", proxy_row)

        self.proxy_hint = QLabel("")
        self.proxy_hint.setObjectName("caption")
        self.proxy_hint.setWordWrap(True)
        form.addRow("", self.proxy_hint)

        opts = QHBoxLayout()
        opts.setSpacing(16)
        self.threads_spin = NoWheelSpinBox()
        self.threads_spin.setRange(1, 200)
        self.threads_spin.setValue(port_scan.DEFAULT_THREADS)
        opts.addWidget(QLabel("线程数"))
        opts.addWidget(self.threads_spin)

        self.timeout_spin = NoWheelSpinBox()
        self.timeout_spin.setRange(1, 60)
        self.timeout_spin.setValue(int(port_scan.DEFAULT_TIMEOUT))
        self.timeout_spin.setSuffix(" 秒")
        opts.addWidget(QLabel("超时"))
        opts.addWidget(self.timeout_spin)

        self.retries_spin = NoWheelSpinBox()
        self.retries_spin.setRange(0, 10)
        self.retries_spin.setValue(port_scan.DEFAULT_RETRIES)
        opts.addWidget(QLabel("换代理重试"))
        opts.addWidget(self.retries_spin)
        opts.addStretch(1)
        form.addRow("", opts)

        out_row = QHBoxLayout()
        out_row.setSpacing(8)
        self.out_edit = QLineEdit()
        self.out_edit.setPlaceholderText("输出目录（相对路径基于程序目录）")
        out_row.addWidget(self.out_edit, 1)
        out_browse = QPushButton("浏览…")
        out_browse.setObjectName("ghbtn")
        out_browse.clicked.connect(self._browse_output)
        out_row.addWidget(out_browse)
        form.addRow("输出目录", out_row)
        layout.addLayout(form)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        self.run_btn = QPushButton("开始扫描")
        self.run_btn.setObjectName("ghbtn-primary")
        self.run_btn.clicked.connect(self._start)
        buttons.addWidget(self.run_btn)

        self.stop_btn = QPushButton("停止")
        self.stop_btn.setObjectName("ghbtn")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop)
        buttons.addWidget(self.stop_btn)

        self.check_btn = QPushButton("测试代理")
        self.check_btn.setObjectName("ghbtn")
        self.check_btn.clicked.connect(self._check_proxy)
        buttons.addWidget(self.check_btn)

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
        self.table.setMinimumHeight(200)
        self.table.cellDoubleClicked.connect(self._copy_row)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header.resizeSection(0, 80)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        header.resizeSection(1, 150)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        header.resizeSection(2, 100)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        header.resizeSection(3, 90)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table, 1)

        log_label = QLabel("扫描日志")
        log_label.setObjectName("section")
        layout.addWidget(log_label)

        self.log_view = QPlainTextEdit()
        self.log_view.setObjectName("io")
        self.log_view.setReadOnly(True)
        self.log_view.setMinimumHeight(100)
        self.log_view.setMaximumHeight(160)
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
        """主题切换时刷新表格配色（其余控件走全局 QSS）。"""
        self.theme = theme
        self._apply_styles()

    # -------------------------------------------------------------- 配置
    def _restore_config(self) -> None:
        cfg = self.store.get("port_scan") or {}
        self.target_edit.setText(cfg.get("target", ""))
        self._select_data(self.source_combo, cfg.get("port_source", "builtin"))
        # 旧版曾提供「本地 fir-proxy（1800/1801）」选项，现已移除（fir-proxy 已
        # 内嵌为全局代理池），旧值 local_http / local_socks 统一迁移为 global。
        proxy_mode = cfg.get("proxy_mode", "global")
        if proxy_mode in ("local_http", "local_socks"):
            proxy_mode = "global"
        self._select_data(self.mode_combo, proxy_mode)
        self.dict_file_edit.setText(cfg.get("dict_file", ""))
        self.manual_edit.setText(cfg.get("ports_text", ""))
        self.proxy_edit.setText(cfg.get("proxy_file", ""))
        self.threads_spin.setValue(int(cfg.get("threads", port_scan.DEFAULT_THREADS)))
        self.timeout_spin.setValue(int(cfg.get("timeout", int(port_scan.DEFAULT_TIMEOUT))))
        self.retries_spin.setValue(int(cfg.get("retries", port_scan.DEFAULT_RETRIES)))
        self.out_edit.setText(cfg.get("out_dir", "output/portscan"))
        self._want_dict = cfg.get("dict_name", "")

    def _save_config(self) -> None:
        self.store.set({
            "target": self.target_edit.text().strip(),
            "port_source": self.source_combo.currentData(),
            "proxy_mode": self.mode_combo.currentData(),
            "dict_name": self.dict_combo.currentText(),
            "dict_file": self.dict_file_edit.text().strip(),
            "ports_text": self.manual_edit.text().strip(),
            "proxy_file": self.proxy_edit.text().strip(),
            "threads": self.threads_spin.value(),
            "timeout": self.timeout_spin.value(),
            "retries": self.retries_spin.value(),
            "out_dir": self.out_edit.text().strip() or "output/portscan",
        }, "port_scan")
        self.store.save()

    @staticmethod
    def _select_data(combo, value: str) -> None:
        for i in range(combo.count()):
            if combo.itemData(i) == value:
                combo.setCurrentIndex(i)
                return

    # ---------------------------------------------------------- 字典 / 代理
    def _reload_dict_list(self) -> None:
        self._dict_files = port_scan.list_dict_files()
        current = getattr(self, "_want_dict", "") or self.dict_combo.currentText()
        self.dict_combo.blockSignals(True)
        self.dict_combo.clear()
        for path in self._dict_files:
            self.dict_combo.addItem(path.name, str(path))
        self.dict_combo.blockSignals(False)
        if self.dict_combo.count() == 0:
            self._set_hint(self.ports_hint, "未找到内置字典，请检查 dict/Ports 目录", warn=True)
            return
        target = 0
        for i in range(self.dict_combo.count()):
            if self.dict_combo.itemText(i) == current:
                target = i
                break
        self.dict_combo.setCurrentIndex(target)
        self._on_dict_changed()

    def _on_dict_changed(self) -> None:
        path = self.dict_combo.currentData()
        if not path:
            return
        try:
            mapping = port_scan.load_port_dict(path)
        except OSError as exc:
            self._set_hint(self.ports_hint, f"字典读取失败：{exc}", warn=True)
            return
        sample = "、".join(str(p) for p in list(mapping)[:6])
        self._set_hint(
            self.ports_hint,
            f"当前字典 {Path(path).name}：{len(mapping)} 个端口（{sample}…）",
        )

    def _on_source_changed(self) -> None:
        source = self.source_combo.currentData()
        self._set_row_visible(self.dict_row, source == "builtin")
        self._set_row_visible(self.dict_file_row, source == "file")
        self._set_row_visible(self.manual_edit, source == "manual")
        if source != "builtin":
            self._set_hint(self.ports_hint, "")
        else:
            self._on_dict_changed()

    def _on_mode_changed(self) -> None:
        mode = self.mode_combo.currentData()
        self._set_row_visible(self.proxy_row, mode == "file")
        if mode == "global":
            status = proxy_pool.proxy_status()
            if status["enabled"]:
                self._set_hint(
                    self.proxy_hint,
                    f"使用全局代理池：池内 {status['total']} 个，可用 {status['alive']} 个。"
                    "池空时可到设置页「Web 工具代理池」点「获取并检测代理」。",
                    warn=status["alive"] == 0,
                )
            else:
                self._set_hint(
                    self.proxy_hint,
                    "全局代理池未启用。请到设置页「Web 工具代理池」勾选启用并获取代理，"
                    "或改用「代理列表文件 / 直连」。",
                    warn=True,
                )
        elif mode == "file":
            count = 0
            text = self.proxy_edit.text().strip()
            if text and Path(text).is_file():
                try:
                    count = len(port_scan.load_proxy_file(text))
                except OSError:
                    count = 0
            self._set_hint(
                self.proxy_hint,
                f"已载入 {count} 个代理（封禁即换下一个）" if count
                else "选择代理列表文件后，扫描前会自动做可信度检查并剔除死代理 / 假代理",
                warn=not count and bool(text),
            )
        else:
            self._set_hint(self.proxy_hint, "直连模式不走代理，目标封禁后无法换 IP，仅作对照。")

    def _set_row_visible(self, widget, visible: bool) -> None:
        """表单行显隐：优先用 ``QFormLayout.setRowVisible``（连左侧标签一起收起）。"""
        try:
            self.form.setRowVisible(widget, visible)
        except (AttributeError, TypeError):
            if hasattr(widget, "setVisible"):
                widget.setVisible(visible)
            else:
                for i in range(widget.count()):
                    item = widget.itemAt(i)
                    child = item.widget() if item is not None else None
                    if child is not None:
                        child.setVisible(visible)

    def _set_hint(self, label: QLabel, text: str, warn: bool = False) -> None:
        """提示行：有内容才占位，空文本时把整行收起，避免留下空白。"""
        label.setText(text)
        label.setObjectName("status-warn" if warn else "caption")
        label.style().unpolish(label)
        label.style().polish(label)
        self._set_row_visible(label, bool(text))

    def _browse_dict_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "选择端口字典", "", "字典文件 (*.txt *.dict);;所有文件 (*)")
        if path:
            self.dict_file_edit.setText(path)
            self._save_config()

    def _browse_proxy_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "选择代理列表", "", "文本文件 (*.txt *.json);;所有文件 (*)")
        if path:
            self.proxy_edit.setText(path)
            self._on_mode_changed()
            self._save_config()

    def _browse_output(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "选择输出目录", self.out_edit.text() or "")
        if path:
            self.out_edit.setText(path)
            self._save_config()

    def _open_output(self) -> None:
        try:
            path = resolve_output_dir(self.out_edit.text())
        except OSError as exc:
            self._set_status(False, f"输出目录不可用：{exc}")
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    # -------------------------------------------------------------- 扫描
    def _collect_ports(self) -> tuple[list[int], dict[int, str], str]:
        """按当前来源解析端口，返回 ``(端口列表, 端口→服务名, 错误信息)``。"""
        source = self.source_combo.currentData()
        if source == "builtin":
            path = self.dict_combo.currentData()
            if not path:
                return [], {}, "没有可用的内置字典"
            mapping = port_scan.load_port_dict(path)
            return sorted(mapping), mapping, ""
        if source == "file":
            text = self.dict_file_edit.text().strip()
            if not text or not Path(text).is_file():
                return [], {}, "自定义字典文件不存在"
            mapping = port_scan.load_port_dict(text)
            return sorted(mapping), mapping, ""
        ports = port_scan.parse_ports(self.manual_edit.text())
        if not ports:
            return [], {}, "端口范围为空或格式不对（示例：1-1024,3306）"
        return ports, {}, ""

    def _build_pool(self):
        """按当前代理方式构造代理池；直连返回 None。"""
        mode = self.mode_combo.currentData()
        if mode == "direct":
            return None
        if mode == "global":
            # 使用前检测：确保全局代理池内有可用代理；池空时提示去设置页获取，
            # 不在主线程阻塞拉取免费源（拉取+验证耗时较长）。
            if not proxy_pool.is_enabled():
                raise ValueError(
                    "全局代理池未启用，请到设置页「Web 工具代理池」勾选启用并获取代理。")
            pool = proxy_pool.to_port_scan_pool()
            if pool is None:
                raise ValueError(
                    "全局代理池内没有可用代理，请到设置页「Web 工具代理池」点"
                    "「获取并检测代理」，或改用代理列表文件 / 直连。")
            return pool
        # 代理列表文件
        text = self.proxy_edit.text().strip()
        if not text or not Path(text).is_file():
            raise ValueError("代理文件不存在")
        proxies = port_scan.load_proxy_file(text)
        if not proxies:
            raise ValueError("代理文件里没有解析出可用代理")
        return port_scan.ProxyPool(proxies)

    def _start(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            return
        host = self.target_edit.text().strip()
        if not host:
            self._set_status(False, "请先填写目标 IP 或域名")
            return
        host = host.split("://", 1)[-1].split("/", 1)[0].strip()
        ports, service_map, err = self._collect_ports()
        if err:
            self._set_status(False, err)
            return
        if not ports:
            self._set_status(False, "没有可扫描的端口")
            return
        try:
            pool = self._build_pool()
        except (OSError, ValueError) as exc:
            self._set_status(False, f"代理配置有误：{exc}")
            return

        self._save_config()
        self.table.setRowCount(0)
        self.log_view.clear()
        self._open_count = 0
        self._append_log(
            f"目标 {host}，端口 {len(ports)} 个，代理方式：{self.mode_combo.currentText()}"
        )

        out_dir = str(resolve_output_dir(self.out_edit.text()))
        worker = _PortWorker(
            host, ports, pool, service_map,
            self.threads_spin.value(), float(self.timeout_spin.value()),
            self.retries_spin.value(), out_dir, self,
        )
        worker.log.connect(self._append_log)
        worker.hit.connect(self._add_hit)
        worker.progress.connect(self._on_progress)
        worker.done_ok.connect(self._on_done)
        worker.done_err.connect(self._on_error)
        worker.finished.connect(self._reset_buttons)
        self._worker = worker
        self.run_btn.setEnabled(False)
        self.check_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self._set_status(True, "扫描中…")
        worker.start()

    def _stop(self) -> None:
        if self._worker is not None:
            self._worker.stop()
            self._set_status(True, "正在停止…")
        if self._check_worker is not None:
            self._check_worker.stop()

    def _on_progress(self, done: int, total: int) -> None:
        if total <= 0:
            return
        percent = done * 100.0 / total
        self._set_status(True, f"已探测 {done}/{total}（{percent:.0f}%），开放 {self._open_count} 个")

    def _on_done(self, result: dict) -> None:
        if result.get("aborted") == "no_trusted_proxy":
            self._set_status(
                False,
                "代理池里没有可信代理（全部连不上或都是「全通」假代理），"
                "已中止。请换一批代理源，或临时改用直连。",
            )
            return
        parts = [
            f"开放 {result['open']} 个",
            f"关闭 {result['closed']}",
            f"过滤 {result['filtered']}",
        ]
        if result.get("error"):
            parts.append(f"代理失败 {result['error']}")
        if result.get("rotations"):
            parts.append(f"换代理 {result['rotations']} 次")
        parts.append(f"耗时 {result['elapsed']:.1f}s")
        text = "扫描完成：" + "，".join(parts)
        if result.get("files", {}).get("csv"):
            text += f"。结果：{result['files']['csv']}"
        self._set_status(result["open"] > 0, text)
        self._append_log(text)

    def _on_error(self, message: str) -> None:
        self._set_status(False, message)
        self._append_log(message)

    def _reset_buttons(self) -> None:
        self.run_btn.setEnabled(True)
        self.check_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self._worker = None

    # ---------------------------------------------------------- 代理测试
    def _check_proxy(self) -> None:
        if self._check_worker is not None and self._check_worker.isRunning():
            return
        try:
            pool = self._build_pool()
        except (OSError, ValueError) as exc:
            self._set_status(False, f"代理配置有误：{exc}")
            return
        if pool is None:
            self._set_status(True, "当前是直连模式，无需测试代理")
            return
        self._append_log(f"开始测试代理（参照目标 {CHECK_HOST}:{CHECK_PORT}）…")
        worker = _CheckWorker(pool, CHECK_HOST, CHECK_PORT,
                              min(128, max(8, self.threads_spin.value() * 4)),
                              min(6.0, float(self.timeout_spin.value())), self)
        worker.log.connect(self._append_log)
        worker.done_ok.connect(self._on_check_done)
        worker.done_err.connect(self._on_error)
        worker.finished.connect(lambda: setattr(self, "_check_worker", None))
        self._check_worker = worker
        self.check_btn.setEnabled(False)
        self._set_status(True, "正在测试代理…")
        worker.start()

    def _on_check_done(self, stats: dict) -> None:
        self.check_btn.setEnabled(True)
        ok = stats.get("ok", 0)
        fake = stats.get("fake", 0)
        text = f"代理测试完成：{stats.get('tested', 0)} 个中可用 {ok} 个"
        if fake:
            text += f"，剔除「全通」假代理 {fake} 个"
        self._set_status(ok > 0, text)
        self._append_log(text)

    # -------------------------------------------------------------- 结果
    def _add_hit(self, item: dict) -> None:
        p = self.theme
        row = self.table.rowCount()
        self.table.insertRow(row)
        values = (
            str(item.get("port", "")),
            item.get("service", "") or "-",
            item.get("label", ""),
            f"{item.get('ms', 0)} ms",
            item.get("proxy", ""),
        )
        for col, text in enumerate(values):
            cell = QTableWidgetItem(text)
            if col in (0, 3):
                cell.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if col in (0, 2):
                cell.setForeground(QColor(p.success))
            elif col == 4:
                cell.setForeground(QColor(p.text_muted))
            self.table.setItem(row, col, cell)
        self._open_count = getattr(self, "_open_count", 0) + 1
        self.table.scrollToBottom()

    def _copy_row(self, row: int, _column: int) -> None:
        port_item = self.table.item(row, 0)
        if port_item is None:
            return
        host = self.target_edit.text().strip().split("://", 1)[-1].split("/", 1)[0]
        text = f"{host}:{port_item.text()}"
        QApplication.clipboard().setText(text)
        self._set_status(True, f"已复制 {text}")

    def _clear_log(self) -> None:
        self.log_view.clear()

    def _append_log(self, message: str) -> None:
        self.log_view.appendPlainText(message)
        bar = self.log_view.verticalScrollBar()
        bar.setValue(bar.maximum())

    def _set_status(self, ok: bool, text: str) -> None:
        self.status_label.setText(text)
        self.status_label.setObjectName("status-ok" if ok else "status-err")
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)

    # -------------------------------------------------------------- 收尾
    def shutdown(self) -> None:
        """窗口关闭时中止后台线程。"""
        for worker in (self._worker, self._check_worker):
            if worker is not None:
                worker.stop()
                worker.wait(1500)
