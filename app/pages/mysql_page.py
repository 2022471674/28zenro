# -*- coding: utf-8 -*-
"""MySQL 弱口令审计页。

合规设计：目标分两类处理——
- **内网 IP**（RFC1918 私有 / 回环 / 链路本地）：可完整进行用户名 / 密码弱口令爆破；
- **公网 IP / 域名**：仅做纯被动指纹识别（只读取服务端握手包，不发送任何认证数据），
  不进行爆破。

进入该功能时先弹出**强制性免责声明**，确认授权后才允许操作。页面同时展示核心
脚本文件的 MD5，用于识别脚本逻辑是否被篡改。

协议实现在 :mod:`lib.mysql_brute`（纯标准库），支持 ``mysql_native_password``
与 MySQL 8.0 默认的 ``caching_sha2_password``（含 RSA 完整认证）。
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
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)
from qfluentwidgets import TableWidget

from app.widgets.no_wheel import NoWheelComboBox, NoWheelSpinBox
from lib import mysql_brute
from lib.watermark import resolve_output_dir

USER_SOURCES = (
    ("builtin", "内置字典（dict/3306）"),
    ("file", "自定义文件"),
    ("manual", "手动输入"),
)

PASSWORD_SOURCES = (
    ("builtin", "内置字典（dict/3306）"),
    ("file", "自定义文件"),
    ("manual", "手动输入"),
)

#: 免责声明文案
DISCLAIMER_TEXT = (
    "本工具仅供授权的内网安全测试，请勿用于公网未授权目标。\n"
    "点击确认代表您已获得合法授权。"
)

#: 核心脚本（lib/mysql_brute.py）的**开发者定死** MD5 基准值。
#: 启动时读取脚本实际 MD5 与之对比，不一致说明脚本被篡改，页面标红警示。
#: 修改脚本后必须由开发者同步更新此常量。
EXPECTED_CORE_MD5 = "09280fb68a6d46ffa4650f4b6413a1f5"


class _BruteWorker(QThread):
    """后台执行爆破，命中 / 进度 / 日志经信号回传主线程。"""

    log = Signal(str)
    hit = Signal(dict)
    progress = Signal(int, int)
    done_ok = Signal(dict)
    done_err = Signal(str)

    def __init__(self, host: str, port: int, users: list[str], passwords: list[str],
                 threads: int, timeout: float, max_attempts: int, out_dir: str,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._host = host
        self._port = port
        self._users = users
        self._passwords = passwords
        self._threads = threads
        self._timeout = timeout
        self._max_attempts = max_attempts
        self._out_dir = out_dir
        self._event = threading.Event()

    def stop(self) -> None:
        """请求中止：不再派发新尝试，在途请求尽快收尾。"""
        self._event.set()

    def run(self) -> None:  # noqa: D102  线程入口
        try:
            result = mysql_brute.brute(
                self._host,
                self._port,
                self._users,
                self._passwords,
                threads=self._threads,
                timeout=self._timeout,
                stop=self._event,
                log=self.log.emit,
                on_hit=lambda r: self.hit.emit(r.to_dict()),
                on_progress=lambda st: self.progress.emit(st.done, st.total),
                max_attempts=self._max_attempts,
                out_dir=self._out_dir,
            )
        except Exception as exc:  # noqa: BLE001  后台线程兜底
            self.done_err.emit(f"爆破失败：{exc}")
            return
        self.done_ok.emit(result)


class _ProbeWorker(QThread):
    """后台纯被动指纹识别（只读取握手包，不发送任何认证数据）。"""

    done_ok = Signal(dict)
    done_err = Signal(str)

    def __init__(self, host: str, port: int, timeout: float,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._host = host
        self._port = port
        self._timeout = timeout

    def run(self) -> None:  # noqa: D102  线程入口
        try:
            result = mysql_brute.banner_grab(self._host, self._port, self._timeout)
        except Exception as exc:  # noqa: BLE001
            self.done_err.emit(f"指纹识别失败：{exc}")
            return
        self.done_ok.emit(result)


class MysqlPage(QWidget):
    """MySQL 弱口令审计页面。"""

    COLUMNS = ("用户名", "密码", "状态", "认证插件", "耗时")

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._worker: _BruteWorker | None = None
        self._probe_worker: _ProbeWorker | None = None
        self._user_files: list[Path] = []
        self._pwd_files: list[Path] = []
        self._build_ui()
        self._apply_styles()
        self._restore_config()
        self._reload_dicts()
        self._on_source_changed()
        self._refresh_count()

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

        # 核心脚本 MD5（防篡改校验：开发者定死基准值，启动时对比实际值）
        self.md5_label = QLabel("")
        self.md5_label.setObjectName("caption")
        self.md5_label.setWordWrap(True)
        self.md5_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self.md5_label)
        self._verify_core_md5()

        form = QFormLayout()
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(10)
        self.form = form

        target_row = QHBoxLayout()
        target_row.setSpacing(8)
        self.host_edit = QLineEdit()
        self.host_edit.setPlaceholderText("目标 IP 或域名，例如 192.168.1.10")
        self.host_edit.returnPressed.connect(self._start)
        target_row.addWidget(self.host_edit, 3)
        target_row.addWidget(QLabel("端口"))
        self.port_spin = NoWheelSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(mysql_brute.DEFAULT_PORT)
        target_row.addWidget(self.port_spin)
        target_row.addStretch(1)
        form.addRow("目标", target_row)

        # -- 用户名 --------------------------------------------------------
        self.user_source = NoWheelComboBox()
        for key, label in USER_SOURCES:
            self.user_source.addItem(label, key)
        self.user_source.currentIndexChanged.connect(self._on_source_changed)
        form.addRow("用户名来源", self.user_source)

        user_dict_row = QHBoxLayout()
        user_dict_row.setSpacing(8)
        self.user_combo = NoWheelComboBox()
        self.user_combo.currentIndexChanged.connect(self._on_user_dict_changed)
        user_dict_row.addWidget(self.user_combo, 1)
        user_reload = QPushButton("重新加载")
        user_reload.setObjectName("ghbtn")
        user_reload.clicked.connect(self._reload_dicts)
        user_dict_row.addWidget(user_reload)
        self.user_dict_row = user_dict_row
        form.addRow("内置用户", user_dict_row)

        user_file_row = QHBoxLayout()
        user_file_row.setSpacing(8)
        self.user_file_edit = QLineEdit()
        self.user_file_edit.setPlaceholderText("用户名字典（一行一个）")
        self.user_file_edit.textChanged.connect(lambda _t: self._refresh_count())
        user_file_row.addWidget(self.user_file_edit, 1)
        user_browse = QPushButton("浏览…")
        user_browse.setObjectName("ghbtn")
        user_browse.clicked.connect(lambda: self._browse_file(self.user_file_edit, "选择用户名字典"))
        user_file_row.addWidget(user_browse)
        self.user_file_row = user_file_row
        form.addRow("用户名文件", user_file_row)

        self.user_manual = QLineEdit()
        self.user_manual.setPlaceholderText("多个用户名用逗号分隔，例如 root,admin,test")
        self.user_manual.textChanged.connect(lambda _t: self._refresh_count())
        form.addRow("手动用户名", self.user_manual)

        # -- 密码 ----------------------------------------------------------
        self.pwd_source = NoWheelComboBox()
        for key, label in PASSWORD_SOURCES:
            self.pwd_source.addItem(label, key)
        self.pwd_source.currentIndexChanged.connect(self._on_source_changed)
        form.addRow("密码来源", self.pwd_source)

        pwd_dict_row = QHBoxLayout()
        pwd_dict_row.setSpacing(8)
        self.pwd_combo = NoWheelComboBox()
        self.pwd_combo.currentIndexChanged.connect(self._on_pwd_dict_changed)
        pwd_dict_row.addWidget(self.pwd_combo, 1)
        pwd_reload = QPushButton("重新加载")
        pwd_reload.setObjectName("ghbtn")
        pwd_reload.clicked.connect(self._reload_dicts)
        pwd_dict_row.addWidget(pwd_reload)
        self.pwd_dict_row = pwd_dict_row
        form.addRow("内置密码", pwd_dict_row)

        pwd_file_row = QHBoxLayout()
        pwd_file_row.setSpacing(8)
        self.pwd_file_edit = QLineEdit()
        self.pwd_file_edit.setPlaceholderText("密码字典（一行一个）")
        self.pwd_file_edit.textChanged.connect(lambda _t: self._refresh_count())
        pwd_file_row.addWidget(self.pwd_file_edit, 1)
        pwd_browse = QPushButton("浏览…")
        pwd_browse.setObjectName("ghbtn")
        pwd_browse.clicked.connect(lambda: self._browse_file(self.pwd_file_edit, "选择密码字典"))
        pwd_file_row.addWidget(pwd_browse)
        self.pwd_file_row = pwd_file_row
        form.addRow("密码文件", pwd_file_row)

        self.pwd_manual = QLineEdit()
        self.pwd_manual.setPlaceholderText("多个密码用逗号分隔；留空表示只试空密码")
        self.pwd_manual.textChanged.connect(lambda _t: self._refresh_count())
        form.addRow("手动密码", self.pwd_manual)

        self.count_hint = QLabel("")
        self.count_hint.setObjectName("caption")
        self.count_hint.setWordWrap(True)
        form.addRow("", self.count_hint)

        # -- 参数 ----------------------------------------------------------
        opts = QHBoxLayout()
        opts.setSpacing(16)
        self.threads_spin = NoWheelSpinBox()
        self.threads_spin.setRange(1, 64)
        self.threads_spin.setValue(mysql_brute.DEFAULT_THREADS)
        opts.addWidget(QLabel("线程数"))
        opts.addWidget(self.threads_spin)

        self.timeout_spin = NoWheelSpinBox()
        self.timeout_spin.setRange(1, 60)
        self.timeout_spin.setValue(int(mysql_brute.DEFAULT_TIMEOUT))
        self.timeout_spin.setSuffix(" 秒")
        opts.addWidget(QLabel("超时"))
        opts.addWidget(self.timeout_spin)

        self.limit_spin = NoWheelSpinBox()
        self.limit_spin.setRange(0, 5_000_000)
        self.limit_spin.setSingleStep(1000)
        self.limit_spin.setValue(0)
        self.limit_spin.setSpecialValueText("不限")
        opts.addWidget(QLabel("尝试上限"))
        opts.addWidget(self.limit_spin)
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
        self.run_btn = QPushButton("开始审计")
        self.run_btn.setObjectName("ghbtn-primary")
        self.run_btn.clicked.connect(self._start)
        buttons.addWidget(self.run_btn)

        self.stop_btn = QPushButton("停止")
        self.stop_btn.setObjectName("ghbtn")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop)
        buttons.addWidget(self.stop_btn)

        self.probe_btn = QPushButton("指纹识别")
        self.probe_btn.setObjectName("ghbtn")
        self.probe_btn.clicked.connect(self._probe)
        buttons.addWidget(self.probe_btn)

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
        header.resizeSection(0, 150)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        header.resizeSection(1, 200)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        header.resizeSection(2, 90)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        header.resizeSection(3, 190)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table, 1)

        log_label = QLabel("审计日志")
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
        cfg = self.store.get("mysql_brute") or {}
        self.host_edit.setText(cfg.get("host", ""))
        self.port_spin.setValue(int(cfg.get("port", mysql_brute.DEFAULT_PORT)))
        self._select_data(self.user_source, cfg.get("user_source", "builtin"))
        self._select_data(self.pwd_source, cfg.get("pwd_source", "builtin"))
        self.user_file_edit.setText(cfg.get("user_file", ""))
        self.pwd_file_edit.setText(cfg.get("pwd_file", ""))
        self.user_manual.setText(cfg.get("user_manual", "root"))
        self.pwd_manual.setText(cfg.get("pwd_manual", ""))
        self.threads_spin.setValue(int(cfg.get("threads", mysql_brute.DEFAULT_THREADS)))
        self.timeout_spin.setValue(int(cfg.get("timeout", int(mysql_brute.DEFAULT_TIMEOUT))))
        self.limit_spin.setValue(int(cfg.get("limit", 0)))
        self.out_edit.setText(cfg.get("out_dir", "output/mysql"))
        self._want_user_dict = cfg.get("user_dict", mysql_brute.DEFAULT_USER_DICT)
        self._want_pwd_dict = cfg.get("pwd_dict", mysql_brute.DEFAULT_PASSWORD_DICT)

    def _save_config(self) -> None:
        self.store.set({
            "host": self.host_edit.text().strip(),
            "port": self.port_spin.value(),
            "user_source": self.user_source.currentData(),
            "pwd_source": self.pwd_source.currentData(),
            "user_dict": self.user_combo.currentText(),
            "pwd_dict": self.pwd_combo.currentText(),
            "user_file": self.user_file_edit.text().strip(),
            "pwd_file": self.pwd_file_edit.text().strip(),
            "user_manual": self.user_manual.text().strip(),
            "pwd_manual": self.pwd_manual.text().strip(),
            "threads": self.threads_spin.value(),
            "timeout": self.timeout_spin.value(),
            "limit": self.limit_spin.value(),
            "out_dir": self.out_edit.text().strip() or "output/mysql",
        }, "mysql_brute")
        self.store.save()

    @staticmethod
    def _select_data(combo, value: str) -> None:
        for i in range(combo.count()):
            if combo.itemData(i) == value:
                combo.setCurrentIndex(i)
                return

    # -------------------------------------------------------------- 字典
    def _reload_dicts(self) -> None:
        root = mysql_brute.default_dict_dir()
        self._user_files = []
        self._pwd_files = []
        if root.is_dir():
            for path in sorted(root.iterdir()):
                if not path.is_file() or path.suffix.lower() in {".md", ".py", ".json"}:
                    continue
                if "用户" in path.name or "user" in path.name.lower():
                    self._user_files.append(path)
                else:
                    self._pwd_files.append(path)

        self._fill_combo(self.user_combo, self._user_files, self._want_user_dict)
        self._fill_combo(self.pwd_combo, self._pwd_files, self._want_pwd_dict)
        self._on_user_dict_changed()
        self._on_pwd_dict_changed()

    @staticmethod
    def _fill_combo(combo, files: list[Path], want: str) -> None:
        combo.blockSignals(True)
        combo.clear()
        for path in files:
            combo.addItem(path.name, str(path))
        combo.blockSignals(False)
        if combo.count() == 0:
            return
        target = 0
        for i in range(combo.count()):
            if combo.itemText(i) == want:
                target = i
                break
        combo.setCurrentIndex(target)

    def _on_user_dict_changed(self) -> None:
        path = self.user_combo.currentData()
        if path:
            try:
                count = len(mysql_brute.load_lines(path))
            except OSError:
                count = 0
            self.user_combo.setToolTip(f"{count} 个用户名")
        self._refresh_count()

    def _on_pwd_dict_changed(self) -> None:
        path = self.pwd_combo.currentData()
        if path:
            try:
                count = len(mysql_brute.load_lines(path))
            except OSError:
                count = 0
            self.pwd_combo.setToolTip(f"{count} 条密码")
        self._refresh_count()

    def _on_source_changed(self) -> None:
        user_src = self.user_source.currentData()
        self._set_row_visible(self.user_dict_row, user_src == "builtin")
        self._set_row_visible(self.user_file_row, user_src == "file")
        self._set_row_visible(self.user_manual, user_src == "manual")

        pwd_src = self.pwd_source.currentData()
        self._set_row_visible(self.pwd_dict_row, pwd_src == "builtin")
        self._set_row_visible(self.pwd_file_row, pwd_src == "file")
        self._set_row_visible(self.pwd_manual, pwd_src == "manual")
        self._refresh_count()

    def _set_row_visible(self, widget, visible: bool) -> None:
        """表单行显隐：优先用 ``QFormLayout.setRowVisible``（连左侧标签一起收起）。"""
        try:
            self.form.setRowVisible(widget, visible)
        except (AttributeError, TypeError):
            if hasattr(widget, "setVisible"):
                widget.setVisible(visible)

    def _collect_users(self) -> tuple[list[str], str]:
        source = self.user_source.currentData()
        if source == "builtin":
            path = self.user_combo.currentData()
            if not path:
                return [], "没有可用的内置用户名字典"
            return mysql_brute.load_lines(path), ""
        if source == "file":
            text = self.user_file_edit.text().strip()
            if not text or not Path(text).is_file():
                return [], "用户名文件不存在"
            return mysql_brute.load_lines(text), ""
        users = mysql_brute.parse_list(self.user_manual.text())
        return users, "" if users else "请填写至少一个用户名"

    def _collect_passwords(self) -> tuple[list[str], str]:
        source = self.pwd_source.currentData()
        if source == "builtin":
            path = self.pwd_combo.currentData()
            if not path:
                return [], "没有可用的内置密码字典"
            return mysql_brute.load_lines(path), ""
        if source == "file":
            text = self.pwd_file_edit.text().strip()
            if not text or not Path(text).is_file():
                return [], "密码文件不存在"
            return mysql_brute.load_lines(text), ""
        text = self.pwd_manual.text().strip()
        if not text:
            return [""], ""  # 留空 = 只试空密码
        return mysql_brute.parse_list(text), ""

    def _refresh_count(self) -> None:
        """实时估算尝试次数，次数过多时给出提示。"""
        users, uerr = self._collect_users()
        pwds, perr = self._collect_passwords()
        if uerr or perr:
            self._set_hint(self.count_hint, uerr or perr, warn=True)
            return
        total = len(users) * len(pwds)
        limit = self.limit_spin.value()
        shown = min(total, limit) if limit else total
        text = f"共 {len(users)} 个用户名 × {len(pwds)} 条密码 = {total:,} 次尝试"
        if limit and limit < total:
            text += f"（受上限限制实际跑 {shown:,} 次）"
        warn = shown > 200_000
        if warn:
            text += "。次数偏多，建议先用小字典或设置尝试上限。"
        self._set_hint(self.count_hint, text, warn=warn)

    def _set_hint(self, label: QLabel, text: str, warn: bool = False) -> None:
        label.setText(text)
        label.setObjectName("status-warn" if warn else "caption")
        label.style().unpolish(label)
        label.style().polish(label)
        self._set_row_visible(label, bool(text))

    def _browse_file(self, target: QLineEdit, title: str) -> None:
        path, _ = QFileDialog.getOpenFileName(self, title, "", "字典文件 (*.txt *.dict);;所有文件 (*)")
        if path:
            target.setText(path)
            self._refresh_count()

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

    # -------------------------------------------------------------- 爆破
    def _target(self) -> tuple[str, int]:
        host = self.host_edit.text().strip()
        host = host.split("://", 1)[-1].split("/", 1)[0]
        if ":" in host and host.count(":") == 1:
            host = host.split(":", 1)[0]
        return host, self.port_spin.value()

    def _verify_core_md5(self) -> None:
        """校验核心脚本 MD5 是否与开发者定死的基准值一致。

        一致 → 正常灰色显示；不一致 → 标红，提示脚本可能被篡改。
        """
        actual = mysql_brute.core_md5()
        if actual == EXPECTED_CORE_MD5:
            self.md5_label.setText(
                f"核心脚本 MD5：{EXPECTED_CORE_MD5}（校验一致）")
            self.md5_label.setObjectName("caption")
        else:
            self.md5_label.setText(
                f"核心脚本 MD5：{actual or '读取失败'}（与基准 "
                f"{EXPECTED_CORE_MD5} 不一致，脚本可能被篡改！）\n"
                "请遵循《网络安全法》及平台安全渗透守则，勿使用被篡改的脚本。")
            self.md5_label.setObjectName("status-err")
        self.md5_label.style().unpolish(self.md5_label)
        self.md5_label.style().polish(self.md5_label)

    def _show_disclaimer(self) -> bool:
        """弹强制免责声明，返回是否确认授权。"""
        box = QMessageBox(self)
        box.setWindowTitle("免责声明")
        box.setIcon(QMessageBox.Icon.Warning)
        box.setText(DISCLAIMER_TEXT)
        box.setStandardButtons(
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.No)
        confirm = box.addButton("我已获得授权并同意", QMessageBox.ButtonRole.AcceptRole)
        box.setDefaultButton(confirm)
        box.exec()
        return box.clickedButton() is confirm

    def _start(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            return
        # 核心脚本完整性校验：MD5 被篡改则直接阻止操作
        if mysql_brute.core_md5() != EXPECTED_CORE_MD5:
            self._set_status(
                False, "核心脚本 MD5 校验不一致，脚本可能被篡改，已阻止操作。"
                       "请遵循网络安全法，恢复原版脚本后再使用。")
            return
        # 强制免责声明
        if not self._show_disclaimer():
            self._set_status(False, "未确认授权，操作已取消。")
            return

        host, port = self._target()
        if not host:
            self._set_status(False, "请先填写目标 IP 或域名")
            return

        # 目标分类：内网可爆破，公网/域名仅指纹
        kind = mysql_brute.classify_target(host)
        self._append_log(
            f"目标 {host}:{port} 分类：{mysql_brute.TARGET_LABELS.get(kind, kind)}")

        if kind != mysql_brute.TARGET_INTRANET:
            self._append_log(
                "该目标为公网 IP / 域名，仅做纯被动指纹识别（不发送任何认证数据）。")
            self._fingerprint(host, port)
            return

        # 内网目标：完整弱口令爆破
        users, uerr = self._collect_users()
        if uerr:
            self._set_status(False, uerr)
            return
        pwds, perr = self._collect_passwords()
        if perr:
            self._set_status(False, perr)
            return

        self._save_config()
        self.table.setRowCount(0)
        self.log_view.clear()
        self._hit_count = 0
        out_dir = str(resolve_output_dir(self.out_edit.text()))

        worker = _BruteWorker(
            host, port, users, pwds,
            self.threads_spin.value(), float(self.timeout_spin.value()),
            self.limit_spin.value(), out_dir, self,
        )
        worker.log.connect(self._append_log)
        worker.hit.connect(self._add_hit)
        worker.progress.connect(self._on_progress)
        worker.done_ok.connect(self._on_done)
        worker.done_err.connect(self._on_error)
        worker.finished.connect(self._reset_buttons)
        self._worker = worker
        self.run_btn.setEnabled(False)
        self.probe_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self._set_status(True, "弱口令审计中…")
        worker.start()

    def _stop(self) -> None:
        if self._worker is not None:
            self._worker.stop()
            self._set_status(True, "正在停止…")

    def _on_progress(self, done: int, total: int) -> None:
        if total <= 0:
            return
        self._set_status(
            True,
            f"已尝试 {done}/{total}（{done * 100.0 / total:.1f}%），命中 {self._hit_count} 组",
        )

    def _on_done(self, result: dict) -> None:
        parts = [
            f"尝试 {result['done']}/{result['total']}",
            f"命中 {len(result['hits'])} 组",
        ]
        if result.get("denied"):
            parts.append(f"拒绝 {result['denied']}")
        if result.get("errors"):
            parts.append(f"错误 {result['errors']}")
        parts.append(f"耗时 {result['elapsed']:.1f}s（{result['speed']:.1f} 次/秒）")
        text = "弱口令审计完成：" + "，".join(parts)
        if result.get("aborted"):
            text += "。已被服务器拒绝继续尝试（可能触发了连接限制），建议降低线程数后再试"
        if result.get("files", {}).get("csv"):
            text += f"。凭据：{result['files']['csv']}"
        self._set_status(bool(result["hits"]), text)
        self._append_log(text)

    def _on_error(self, message: str) -> None:
        self._set_status(False, message)
        self._append_log(message)

    def _reset_buttons(self) -> None:
        self.run_btn.setEnabled(True)
        self.probe_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self._worker = None

    # -------------------------------------------------------------- 指纹
    def _fingerprint(self, host: str, port: int) -> None:
        """公网 / 域名目标：纯被动指纹识别。"""
        if self._probe_worker is not None and self._probe_worker.isRunning():
            return
        self._append_log(f"对 {host}:{port} 执行纯被动指纹识别…")
        worker = _ProbeWorker(host, port, float(self.timeout_spin.value()), self)
        worker.done_ok.connect(self._on_fingerprint_done)
        worker.done_err.connect(self._on_error)
        worker.finished.connect(lambda: setattr(self, "_probe_worker", None))
        self._probe_worker = worker
        self.probe_btn.setEnabled(False)
        self._set_status(True, "正在进行纯被动指纹识别…")
        worker.start()

    def _on_fingerprint_done(self, result: dict) -> None:
        self.probe_btn.setEnabled(True)
        if not result.get("reachable"):
            self._set_status(False, f"端口不可达：{result.get('error')}")
            self._append_log(f"[-] 端口不可达：{result.get('error')}")
            self._append_log("    结论：端口未对外暴露或已被防火墙 / ACL 限制。")
            return
        banner = result.get("banner") or {}
        if not banner:
            self._set_status(False, f"端口开放但无法识别：{result.get('error')}")
            self._append_log(f"[?] 端口开放但未识别到 MySQL 指纹：{result.get('error')}")
            return
        ver = banner.get("version", "")
        plugin = banner.get("plugin", "")
        self._append_log("[+] 端口开放，成功读取服务端握手包（纯被动，未发送任何认证数据）：")
        self._append_log(f"    服务器版本 : {ver}")
        self._append_log(f"    认证插件   : {plugin or '(未解析到)'}")
        self._append_log(f"    连接 ID    : {banner.get('thread_id')}")
        if ver and plugin:
            text = (f"指纹识别完成：MySQL {ver}（{plugin}）。"
                    "该目标为公网/域名，仅做被动识别，未进行任何爆破。")
            self._set_status(True, text)
        else:
            self._set_status(True, "端口开放但 banner 解析不完整，请人工复核。")

    def _probe(self) -> None:
        """「指纹识别」按钮：对当前目标执行纯被动指纹识别。"""
        if self._probe_worker is not None and self._probe_worker.isRunning():
            return
        # 核心脚本完整性校验：MD5 被篡改则直接阻止操作
        if mysql_brute.core_md5() != EXPECTED_CORE_MD5:
            self._set_status(
                False, "核心脚本 MD5 校验不一致，脚本可能被篡改，已阻止操作。"
                       "请遵循网络安全法，恢复原版脚本后再使用。")
            return
        host, port = self._target()
        if not host:
            self._set_status(False, "请先填写目标 IP 或域名")
            return
        self._append_log(f"对 {host}:{port} 执行纯被动指纹识别…")
        worker = _ProbeWorker(host, port, float(self.timeout_spin.value()), self)
        worker.done_ok.connect(self._on_fingerprint_done)
        worker.done_err.connect(self._on_error)
        worker.finished.connect(lambda: setattr(self, "_probe_worker", None))
        self._probe_worker = worker
        self.probe_btn.setEnabled(False)
        self._set_status(True, "正在识别指纹…")
        worker.start()

    # -------------------------------------------------------------- 结果
    def _add_hit(self, item: dict) -> None:
        p = self.theme
        row = self.table.rowCount()
        self.table.insertRow(row)
        values = (
            item.get("user", ""),
            item.get("password", "") or "(空)",
            item.get("label", ""),
            item.get("plugin", ""),
            f"{item.get('ms', 0)} ms",
        )
        for col, text in enumerate(values):
            cell = QTableWidgetItem(text)
            if col in (2, 4):
                cell.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            cell.setForeground(QColor(p.success))
            self.table.setItem(row, col, cell)
        self._hit_count = getattr(self, "_hit_count", 0) + 1
        self.table.scrollToBottom()

    def _copy_row(self, row: int, _column: int) -> None:
        user = self.table.item(row, 0)
        pwd = self.table.item(row, 1)
        if user is None or pwd is None:
            return
        host, port = self._target()
        text = f"{host}:{port} {user.text()}:{pwd.text()}"
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
        for worker in (self._worker, self._probe_worker):
            if worker is not None:
                worker.stop()
                worker.wait(1500)
