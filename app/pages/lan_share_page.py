# -*- coding: utf-8 -*-
"""局域网传输页：本机开启 HTTP 共享服务，也可以加入他人的频道。

两种角色在同一个页面里：
- **服务端**：点「开启服务」即在 ``0.0.0.0`` 上起一个 HTTP 服务，自动建一个
  频道并生成 4 位数字密码；同网段的手机 / 电脑用浏览器打开页面地址，选频道
  + 输密码就能上传 / 下载文件。可以再建多个频道，每个频道一套密码。
- **客户端**：填对方的 ``IP:端口``，拉取频道列表，选中频道并输入它的 4 位
  密码加入；加入后能看文件列表、上传、下载，退出后会话立即作废。

服务端线程只碰 ``lib.lan_share`` 的状态对象（自带锁），界面刷新经
``_EventBridge`` 信号回到主线程；客户端请求与文件复制全部在 ``_RpcWorker``
后台线程里跑，进度经信号回传，不卡界面。
"""

from __future__ import annotations

import re
import time
from pathlib import Path

from PySide6.QtCore import QObject, Qt, QThread, QTimer, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QIcon, QRegularExpressionValidator
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSystemTrayIcon,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)
from qfluentwidgets import FluentIcon, TableWidget

from app.widgets.no_wheel import NoWheelComboBox, NoWheelSpinBox
from lib import lan_share
from lib.watermark import resolve_output_dir


class _EventBridge(QObject):
    """把服务端线程的事件转到主线程（UI 只在主线程刷新的接缝）。"""

    event = Signal(dict)


class _RpcWorker(QThread):
    """后台跑一次客户端 HTTP 操作 / 文件复制。

    ``fn(report)`` 的结果对象经 ``done_ok`` 回传；``progress`` 定期吐
    ``(已传字节, 总字节)``；异常统一走 ``done_err``（文案即 LanShareError）。
    """

    progress = Signal(int, int)
    done_ok = Signal(object)
    done_err = Signal(str)

    def __init__(self, fn, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._fn = fn

    def run(self) -> None:  # noqa: D102  线程入口
        try:
            result = self._fn(self.progress.emit)
        except lan_share.LanShareError as exc:
            self.done_err.emit(str(exc))
            return
        except Exception as exc:  # noqa: BLE001  后台线程兜底
            self.done_err.emit(f"操作失败：{exc}")
            return
        self.done_ok.emit(result)


class LanSharePage(QWidget):
    """局域网传输页：本机作为服务端，也可以作为客户端加入他人频道。"""

    #: 服务端事件轮询间隔（毫秒）
    HEARTBEAT_MS = 5000

    CHANNEL_COLUMNS = ("频道", "密码", "在线", "文件")
    FILE_COLUMNS = ("文件", "大小", "来自", "时间")

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self.server: lan_share.ShareServer | None = None
        self._bridge = _EventBridge(self)
        self._bridge.event.connect(self._on_server_event)
        self._workers: set[_RpcWorker] = set()
        self._session: dict | None = None
        self._filling = False
        self._poll_busy = False
        self._last_progress = 0.0
        self._tray: QSystemTrayIcon | None = None

        self._timer = QTimer(self)
        self._timer.setInterval(self.HEARTBEAT_MS)
        self._timer.timeout.connect(self._heartbeat)

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
        layout.setSpacing(12)

        layout.addWidget(self._build_server_card())
        layout.addWidget(self._build_host_card())
        layout.addWidget(self._build_client_card())

        self.status_label = QLabel("服务未开启。")
        self.status_label.setObjectName("status-info")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)
        layout.addStretch(1)

    def _card(self, title_text: str) -> tuple[QFrame, QVBoxLayout]:
        card = QFrame()
        card.setObjectName("card")
        box = QVBoxLayout(card)
        box.setContentsMargins(16, 14, 16, 14)
        box.setSpacing(8)
        label = QLabel(title_text)
        label.setObjectName("section")
        box.addWidget(label)
        return card, box

    # -- 服务端卡片 -------------------------------------------------------
    def _build_server_card(self) -> QFrame:
        card, box = self._card("本机服务")

        row = QHBoxLayout()
        row.setSpacing(8)
        row.addWidget(QLabel("服务名称"))
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("浏览器登录页与服务信息里显示的名称")
        self.name_edit.setMaximumWidth(220)
        row.addWidget(self.name_edit)

        row.addWidget(QLabel("端口"))
        self.port_spin = NoWheelSpinBox()
        self.port_spin.setRange(0, 65535)
        self.port_spin.setSpecialValueText("自动")
        self.port_spin.setMaximumWidth(110)
        self.port_spin.setToolTip("0 表示自动选一个空闲端口；开启后回显实际端口")
        row.addWidget(self.port_spin)

        self.start_btn = QPushButton("开启服务")
        self.start_btn.setObjectName("ghbtn-primary")
        self.start_btn.clicked.connect(self._toggle_server)
        row.addWidget(self.start_btn)

        self.notify_check = QCheckBox("收到新文件时弹系统通知")
        row.addWidget(self.notify_check)
        row.addStretch(1)
        box.addLayout(row)

        addr_row = QHBoxLayout()
        addr_row.setSpacing(8)
        self.addr_label = QLabel("服务未开启。开启后这里会显示局域网访问地址。")
        self.addr_label.setWordWrap(True)
        self.addr_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        addr_row.addWidget(self.addr_label, 1)

        self.copy_addr_btn = QPushButton("复制地址")
        self.copy_addr_btn.setObjectName("ghbtn")
        self.copy_addr_btn.clicked.connect(self._copy_addresses)
        addr_row.addWidget(self.copy_addr_btn)

        self.open_dir_btn = QPushButton("打开存储目录")
        self.open_dir_btn.setObjectName("ghbtn")
        self.open_dir_btn.clicked.connect(self._open_storage)
        addr_row.addWidget(self.open_dir_btn)
        box.addLayout(addr_row)

        self.addr_hint = QLabel("把上面的地址和频道密码发给同网段的人即可。")
        self.addr_hint.setObjectName("caption")
        self.addr_hint.setVisible(False)
        box.addWidget(self.addr_hint)
        return card

    # -- 本机频道 ---------------------------------------------------------
    def _build_host_card(self) -> QFrame:
        card, box = self._card("本机频道")

        self.channels_table = self._make_table(self.CHANNEL_COLUMNS,
                                               multi=False)
        self.channels_table.itemSelectionChanged.connect(
            self._on_channel_selected)
        box.addWidget(self.channels_table)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        for text, handler, primary in (
            ("新建频道", self._new_channel, True),
            ("复制密码", self._copy_channel_password, False),
            ("重置密码", self._reset_channel_password, False),
            ("发送文件到此频道", self._send_files_to_channel, False),
            ("删除频道", self._delete_channel, False),
        ):
            btn = QPushButton(text)
            btn.setObjectName("ghbtn-primary" if primary else "ghbtn")
            btn.clicked.connect(handler)
            buttons.addWidget(btn)
            if text == "发送文件到此频道":
                self.send_files_btn = btn
        buttons.addStretch(1)
        box.addLayout(buttons)

        tip = QLabel("频道内文件（选中频道后显示，每 5 秒自动刷新）：")
        tip.setObjectName("caption")
        box.addWidget(tip)

        self.host_files_table = self._make_table(self.FILE_COLUMNS)
        box.addWidget(self.host_files_table)

        files_row = QHBoxLayout()
        files_row.setSpacing(8)
        del_btn = QPushButton("删除所选文件")
        del_btn.setObjectName("ghbtn-danger")
        del_btn.clicked.connect(self._delete_host_files)
        files_row.addWidget(del_btn)
        files_row.addStretch(1)
        box.addLayout(files_row)
        return card

    # -- 客户端卡片 -------------------------------------------------------
    def _build_client_card(self) -> QFrame:
        card, box = self._card("加入他人频道")

        grid = QGridLayout()
        grid.setHorizontalSpacing(8)
        grid.setVerticalSpacing(8)

        grid.addWidget(QLabel("服务器地址"), 0, 0)
        self.addr_edit = QLineEdit()
        self.addr_edit.setPlaceholderText("服务器地址，如 192.168.1.5:8517")
        self.addr_edit.returnPressed.connect(self._discover)
        grid.addWidget(self.addr_edit, 0, 1, 1, 2)

        self.discover_btn = QPushButton("拉取频道")
        self.discover_btn.setObjectName("ghbtn")
        self.discover_btn.clicked.connect(self._discover)
        grid.addWidget(self.discover_btn, 0, 3)

        grid.addWidget(QLabel("频道"), 1, 0)
        self.channel_combo = NoWheelComboBox()
        self.channel_combo.setEditable(True)
        self.channel_combo.setMinimumWidth(180)
        self.channel_combo.lineEdit().setPlaceholderText("选择频道（或直接输入频道名）")
        grid.addWidget(self.channel_combo, 1, 1)

        grid.addWidget(QLabel("密码"), 1, 2)
        self.password_edit = QLineEdit()
        self.password_edit.setPlaceholderText("4 位密码")
        self.password_edit.setMaxLength(4)
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_edit.setValidator(
            QRegularExpressionValidator(r"\d{0,4}", self))
        self.password_edit.returnPressed.connect(self._join)
        self.password_edit.setMaximumWidth(110)
        grid.addWidget(self.password_edit, 1, 3)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        self.join_btn = QPushButton("加入频道")
        self.join_btn.setObjectName("ghbtn-primary")
        self.join_btn.clicked.connect(self._join)
        buttons.addWidget(self.join_btn)

        self.leave_btn = QPushButton("退出频道")
        self.leave_btn.setObjectName("ghbtn")
        self.leave_btn.clicked.connect(self._leave)
        self.leave_btn.setEnabled(False)
        buttons.addWidget(self.leave_btn)

        self.refresh_btn = QPushButton("刷新列表")
        self.refresh_btn.setObjectName("ghbtn")
        self.refresh_btn.clicked.connect(lambda: self._load_client_files(False))
        self.refresh_btn.setEnabled(False)
        buttons.addWidget(self.refresh_btn)

        self.upload_btn = QPushButton("上传文件…")
        self.upload_btn.setObjectName("ghbtn")
        self.upload_btn.clicked.connect(self._upload_files)
        self.upload_btn.setEnabled(False)
        buttons.addWidget(self.upload_btn)

        self.download_btn = QPushButton("下载并保存…")
        self.download_btn.setObjectName("ghbtn")
        self.download_btn.clicked.connect(self._download_files)
        self.download_btn.setEnabled(False)
        buttons.addWidget(self.download_btn)
        buttons.addStretch(1)
        box.addLayout(grid)
        box.addLayout(buttons)

        self.client_label = QLabel("未加入频道")
        self.client_label.setObjectName("caption")
        self.client_label.setWordWrap(True)
        box.addWidget(self.client_label)

        self.client_files_table = self._make_table(self.FILE_COLUMNS)
        box.addWidget(self.client_files_table)
        return card

    def _make_table(self, columns: tuple[str, ...],
                    multi: bool = True) -> TableWidget:
        """频道 / 文件表通用构造：整行选中、不可编辑、首列伸缩。

        ``multi=False`` 用于频道表（一次只操作一个频道），文件表则可多选
        批量下载 / 删除。
        """
        table = TableWidget(self)
        table.setColumnCount(len(columns))
        table.setHorizontalHeaderLabels(list(columns))
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(
            QAbstractItemView.SelectionMode.ExtendedSelection if multi
            else QAbstractItemView.SelectionMode.SingleSelection)
        table.setAlternatingRowColors(False)
        table.verticalHeader().hide()
        table.setMinimumHeight(96)
        table.setMaximumHeight(132)
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for col in range(1, len(columns)):
            header.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        return table

    # ------------------------------------------------------------------ 样式
    def _apply_styles(self) -> None:
        p = self.theme
        table_qss = (
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
        for table in (self.channels_table, self.host_files_table,
                      self.client_files_table):
            table.setStyleSheet(table_qss)
        self.addr_label.setStyleSheet(
            f'color: {p.accent}; font-family: "{p.font_mono_family}", monospace;')

    def set_theme(self, theme) -> None:
        """换主题时下发调色板（兼容 ToolPage 的 set_theme 调用入口）。"""
        self.theme = theme
        self._apply_styles()

    def apply_theme(self, theme) -> None:
        """ToolPage 主题下发入口：直接复用 :meth:`set_theme`。"""
        self.set_theme(theme)

    # ------------------------------------------------------------------ 配置
    def _restore_config(self) -> None:
        cfg = self.store.get("lan_share", default={}) or {}
        self.name_edit.setText(str(cfg.get("service_name") or "28zenro 共享"))
        try:
            self.port_spin.setValue(int(cfg.get("port") or 0))
        except (TypeError, ValueError):
            self.port_spin.setValue(0)
        self.notify_check.setChecked(bool(cfg.get("notify", True)))

    def _save_config(self) -> None:
        """把服务名 / 端口 / 通知开关写回 config.json。"""
        self.store.setv(self.name_edit.text().strip() or "28zenro 共享",
                        "lan_share", "service_name")
        self.store.setv(int(self.port_spin.value()), "lan_share", "port")
        self.store.setv(self.notify_check.isChecked(), "lan_share", "notify")
        self.store.save()

    @property
    def _storage_root(self) -> Path:
        cfg = self.store.get("watermark", default={}) or {}
        return resolve_output_dir(cfg.get("output_dir")) / "lan_share"

    # ------------------------------------------------------------------ 状态
    def _set_status(self, ok: bool, text: str) -> None:
        """状态栏：True 绿 / False 红，样式经由 objectName 切换。"""
        self.status_label.setText(text)
        self.status_label.setObjectName("status-ok" if ok else "status-err")
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)

    def _set_info(self, text: str) -> None:
        self.status_label.setText(text)
        self.status_label.setObjectName("status-info")
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)

    # ------------------------------------------------------------------ 服务端
    def _toggle_server(self) -> None:
        """开启 / 关闭本机 HTTP 共享服务。"""
        if self.server is not None and self.server.running:
            self._stop_server()
            return

        server = lan_share.ShareServer(
            service_name=self.name_edit.text().strip() or "28zenro 共享",
            port=int(self.port_spin.value()),
            root=self._storage_root,
            on_event=self._bridge.event.emit,
        )
        try:
            port = server.start()
        except lan_share.LanShareError as exc:
            self._set_status(
                False, f"开启服务失败：{exc}。请检查端口是否被占用，"
                       "或把端口设为「自动」再试。")
            return

        self.server = server
        self._save_config()

        # 首次开启自动建一个频道并生成 4 位密码；重启则沿用磁盘上的频道，
        # 但密码每次启动都会重新生成（避免旧密码长期有效）。
        created: dict | None = None
        if not server.state.channel_names():
            try:
                channel = server.state.new_channel()
                created = {"name": channel.name, "password": channel.password}
            except lan_share.LanShareError as exc:
                self._set_status(False, f"创建频道失败：{exc}")
        else:
            overview = server.state.overview()
            if overview:
                created = overview[0]

        # 回显实际端口并落盘，下次启动沿用同一端口（端口被占时再改回「自动」）
        self.port_spin.setValue(port)
        self._save_config()
        self.start_btn.setText("关闭服务")
        self.start_btn.setObjectName("ghbtn-danger")
        self.start_btn.style().unpolish(self.start_btn)
        self.start_btn.style().polish(self.start_btn)
        self.addr_label.setText(
            "访问地址：\n" + "\n".join(server.addresses))
        self.addr_hint.setVisible(True)
        self._refresh_channels()
        self._timer.start()

        if created is not None:
            self._set_status(
                True,
                f"服务已开启，端口 {port}。频道「{created['name']}」的密码是 "
                f"{created['password']}，把这个密码发给要加入的人。")
        else:
            self._set_status(True, f"服务已开启，端口 {port}。")

    def _stop_server(self) -> None:
        if self.server is not None:
            self.server.stop()
        self.server = None
        self._timer.stop()
        self.start_btn.setText("开启服务")
        self.start_btn.setObjectName("ghbtn-primary")
        self.start_btn.style().unpolish(self.start_btn)
        self.start_btn.style().polish(self.start_btn)
        self.addr_label.setText("服务未开启。开启后这里会显示局域网访问地址。")
        self.addr_hint.setVisible(False)
        self.channels_table.setRowCount(0)
        self.host_files_table.setRowCount(0)
        self._set_info("服务已停止。")

    def _copy_addresses(self) -> None:
        if self.server is None or not self.server.running:
            self._set_status(False, "请先点击「开启服务」。")
            return
        QApplication.clipboard().setText("\n".join(self.server.addresses))
        self._set_status(True, "已复制全部局域网访问地址。")

    def _open_storage(self) -> None:
        path = self._storage_root
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            self._set_status(False, f"无法打开目录：{exc}")
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    # -- 频道表 -----------------------------------------------------------
    def _refresh_channels(self) -> None:
        """频道表重建：只在本机服务运行时显示（member 数随事件 / 定时器）。"""
        if self.server is None or not self.server.running:
            return
        overview = self.server.state.overview()
        selected = self._selected_channel_name()
        self._filling = True
        try:
            self.channels_table.setRowCount(0)
            for row, item in enumerate(overview):
                self.channels_table.insertRow(row)
                cells = (item["name"], item["password"],
                         str(item["members"]), str(item["files"]))
                for col, text in enumerate(cells):
                    cell = QTableWidgetItem(text)
                    if col >= 2:
                        cell.setTextAlignment(
                            Qt.AlignmentFlag.AlignHCenter
                            | Qt.AlignmentFlag.AlignVCenter)
                    if col == 1:
                        cell.setToolTip("该频道的 4 位加入密码")
                    self.channels_table.setItem(row, col, cell)
                if selected and item["name"] == selected:
                    self.channels_table.selectRow(row)
        finally:
            self._filling = False

    def _selected_channel_name(self) -> str:
        """表格当前选中行第一列（频道名）；无选中返回空串。"""
        if self._filling:
            return ""
        rows = {index.row() for index in self.channels_table.selectedIndexes()}
        if not rows:
            return ""
        item = self.channels_table.item(min(rows), 0)
        return item.text() if item is not None else ""

    def _selected_channel_password(self) -> str:
        rows = {index.row() for index in self.channels_table.selectedIndexes()}
        if not rows:
            return ""
        item = self.channels_table.item(min(rows), 1)
        return item.text() if item is not None else ""

    def _on_channel_selected(self) -> None:
        if self._filling:
            return
        name = self._selected_channel_name()
        self._load_host_files(name)

    def _load_host_files(self, channel_name: str) -> None:
        """宿主侧所选频道的文件表：事件 / 5 秒心跳都会刷。"""
        if self.server is None or not self.server.running:
            return
        self.host_files_table.setRowCount(0)
        if not channel_name:
            return
        try:
            files = self.server.state.files_of(channel_name)
        except lan_share.LanShareError:
            return
        self._fill_files_table(self.host_files_table, files)

    @classmethod
    def _fill_files_table(cls, table: TableWidget, files: list[dict]) -> None:
        """把文件清单渲染进表格，并按文件名还原原有选中行。

        5 秒心跳会重建表格，若不复原选中，用户正在挑的「要删除 / 要下载」
        的文件会被静默清掉。
        """
        selected = set(cls._selected_file_names(table))
        table.setRowCount(0)
        for row, info in enumerate(files):
            table.insertRow(row)
            for col, key in enumerate(("name", "size_text", "sender", "time")):
                cell = QTableWidgetItem(str(info.get(key, "")))
                if col == 0:
                    cell.setData(Qt.ItemDataRole.UserRole, info.get("name", ""))
                table.setItem(row, col, cell)
        if selected:
            for row in range(table.rowCount()):
                item = table.item(row, 0)
                if item is not None and item.text() in selected:
                    table.selectRow(row)

    # -- 频道操作 ---------------------------------------------------------
    def _new_channel(self) -> None:
        if self.server is None or not self.server.running:
            self._set_status(False, "请先点击「开启服务」。")
            return
        name, ok = QInputDialog.getText(
            self, "新建频道", "频道名称（留空自动起名）：")
        if not ok:
            return
        try:
            channel = self.server.state.new_channel(name.strip())
        except lan_share.LanShareError as exc:
            self._set_status(False, f"新建频道失败：{exc}")
            return
        self._refresh_channels()
        self._set_status(
            True, f"已创建频道「{channel.name}」，密码 {channel.password}。")

    def _copy_channel_password(self) -> None:
        password = self._selected_channel_password()
        if not password:
            self._set_status(False, "请先在频道表里选中一个频道。")
            return
        QApplication.clipboard().setText(password)
        name = self._selected_channel_name()
        self._set_status(True, f"已复制「{name}」的密码 {password}。")

    def _reset_channel_password(self) -> None:
        name = self._selected_channel_name()
        if self.server is None or not name:
            self._set_status(False, "请先在频道表里选中一个频道。")
            return
        try:
            password = self.server.state.regenerate_password(name)
        except lan_share.LanShareError as exc:
            self._set_status(False, f"重置密码失败：{exc}")
            return
        self._refresh_channels()
        self._set_status(True, f"「{name}」的新密码是 {password}（旧密码立即作废）。")

    def _delete_channel(self) -> None:
        name = self._selected_channel_name()
        if self.server is None or not name:
            self._set_status(False, "请先在频道表里选中一个频道。")
            return
        answer = QMessageBox.question(
            self, "删除频道",
            f"确认删除频道「{name}」？\n\n频道内的会话会立即失效，"
            "该频道目录与其中的文件也会一并删除。")
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            self.server.state.drop_channel(name)
        except lan_share.LanShareError as exc:
            self._set_status(False, f"删除频道失败：{exc}")
            return
        self._refresh_channels()
        self.host_files_table.setRowCount(0)
        self._set_status(True, f"已删除频道「{name}」。")

    def _send_files_to_channel(self) -> None:
        """本机发送文件：流式复制进频道目录（worker 里执行，带总体进度）。"""
        name = self._selected_channel_name()
        if self.server is None or not name:
            self._set_status(False, "请先在频道表里选中一个频道。")
            return
        paths, _ = QFileDialog.getOpenFileNames(self, "选择要发送的文件")
        if not paths:
            return

        total = 0
        sizes: dict[str, int] = {}
        for path in paths:
            try:
                sizes[path] = Path(path).stat().st_size
                total += sizes[path]
            except OSError as exc:
                self._set_status(False, f"读取文件信息失败：{exc}")
                return

        state = self.server.state

        def job(report):
            done_before = 0
            sent = []
            for path in paths:
                size = sizes[path]

                def on_progress(done, _total, base=done_before):
                    report(base + done, total)

                info = state.add_file_path(name, path, sender="本机",
                                           report=on_progress)
                sent.append(info.name)
                done_before += size
            return sent

        self._run_async(
            job,
            lambda names: self._after_send(names, name),
            self.start_btn, self.send_files_btn,
        )

    def _after_send(self, names: list, channel_name: str) -> None:
        self._refresh_channels()
        self._load_host_files(channel_name)
        self._set_status(
            True, f"已发送 {len(names)} 个文件到「{channel_name}」："
                  + "、".join(names))

    def _delete_host_files(self) -> None:
        """宿主删除频道内文件：登记与磁盘一并删，选多个可批量。"""
        name = self._selected_channel_name()
        if self.server is None or not name:
            self._set_status(False, "请先在频道表里选中一个频道。")
            return
        names = self._selected_file_names(self.host_files_table)
        if not names:
            self._set_status(False, "请先在文件列表里选中要删除的文件。")
            return
        answer = QMessageBox.question(
            self, "删除文件",
            f"确认把「{name}」里选中的 {len(names)} 个文件从频道和磁盘一并删除？")
        if answer != QMessageBox.StandardButton.Yes:
            return
        failed = []
        for filename in names:
            try:
                self.server.state.remove_file(name, filename)
            except lan_share.LanShareError:
                failed.append(filename)
        self._refresh_channels()
        self._load_host_files(name)
        if failed:
            self._set_status(
                False, f"部分文件删除失败：{'、'.join(failed)}")
        else:
            self._set_status(True, f"已从「{name}」删除 {len(names)} 个文件。")

    @staticmethod
    def _selected_file_names(table: TableWidget) -> list[str]:
        """表格当前选中行第一列的文件名（按行号升序去重）。"""
        rows = sorted({index.row() for index in table.selectedIndexes()})
        names = []
        for row in rows:
            item = table.item(row, 0)
            if item is not None and item.text() not in names:
                names.append(item.text())
        return names

    # ------------------------------------------------------------------ 事件
    def _on_server_event(self, event: dict) -> None:
        """服务端事件（可能在服务线程发出，bridge 已转回主线程）。"""
        kind = event.get("type")
        if kind == "closed":
            return
        if kind == "join_ok":
            self._set_info(
                f"[加入] {event.get('ip', '?')} 进入了频道「{event.get('channel', '')}」")
        elif kind == "leave":
            self._set_info(
                f"[退出] {event.get('ip', '?')} 离开了「{event.get('channel', '')}」")
        elif kind == "upload_ok":
            files = event.get("files") or []
            self._set_info(
                f"[上传] {event.get('sender', '?')} 把 {'、'.join(files)} "
                f"发到「{event.get('channel', '')}」")
            if self.notify_check.isChecked():
                self._notify_system(
                    f"{event.get('sender', '?')} 向「{event.get('channel', '')}」"
                    f"发送了 {'、'.join(files)}")
        elif kind == "downloaded":
            self._set_info(
                f"[下载] {event.get('ip', '?')} 取走了「{event.get('channel', '')}」"
                f"的 {event.get('name', '')}")
        elif kind == "error":
            self._set_status(False, event.get("message", "服务异常"))

        if kind in ("join_ok", "leave", "upload_ok", "downloaded"):
            self._refresh_channels()
            name = self._selected_channel_name()
            if name:
                self._load_host_files(name)

    def _notify_system(self, message: str) -> None:
        """系统通知：没有可用图标时不弹（避免 Qt「No Icon set」警告）。"""
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        if self._tray is None:
            self._tray = QSystemTrayIcon(self)
            icon = QIcon(FluentIcon.WIFI.path())
            if icon.isNull():
                return
            self._tray.setIcon(icon)
            self._tray.show()
        self._tray.showMessage("局域网传输", message,
                               QSystemTrayIcon.MessageIcon.Information, 4000)

    # ------------------------------------------------------------------ 心跳
    def _heartbeat(self) -> None:
        """5 秒心跳：宿主频道表与所选频道文件表各刷一遍。"""
        if self.server is not None and self.server.running:
            name = self._selected_channel_name()
            self._refresh_channels()
            if name:
                self._load_host_files(name)
        if self._session is not None:
            self._poll_client_files()

    # ------------------------------------------------------------------ 客户端
    def _discover(self) -> None:
        """拉取对方服务的服务名与频道名列表（无需密码）。"""
        host = self.addr_edit.text().strip()
        if not host:
            self._set_status(False, "请填写服务器地址，如 192.168.1.5:8517。")
            return

        def job(report):
            return lan_share.client_channels(host)

        def done(info):
            self.channel_combo.clear()
            self.channel_combo.addItems(info["channels"])
            self.client_label.setText(
                f"服务「{info['name']}」共 {len(info['channels'])} 个频道，"
                "选择频道并输入密码后加入。")
            self._set_status(True, f"拉取成功：服务「{info['name']}」，"
                                   f"{len(info['channels'])} 个频道。")

        self._run_async(job, done, self.discover_btn)

    def _join(self) -> None:
        """输密码加入：成功后拉一次文件列表（无需重复输入密码直到过期）。"""
        host = self.addr_edit.text().strip()
        channel = self.channel_combo.currentText().strip()
        password = self.password_edit.text().strip()
        if not host:
            self._set_status(False, "请填写服务器地址，如 192.168.1.5:8517。")
            return
        if not password:
            self._set_status(False, "请输入 4 位频道密码。")
            return
        if not re.fullmatch(r"\d{4}", password):
            self._set_status(False, "密码必须是 4 位数字。")
            return

        def job(report):
            joined = lan_share.client_join(host, channel, password)
            files = lan_share.client_files(joined["base"], joined["token"])
            return joined, files

        def done(result):
            joined, files = result
            self._session = {
                "base": joined["base"],
                "token": joined["token"],
                "channel": joined["channel"],
            }
            self.password_edit.clear()
            self.client_label.setText(
                f"已加入「{joined['channel']}」（{joined['members']} 人在线）")
            self._fill_files_table(self.client_files_table, files)
            self._set_client_joined(True)
            self._set_status(True, f"加入成功：频道「{joined['channel']}」，"
                                   f"{len(files)} 个文件。")

        self._run_async(job, done, self.join_btn, self.discover_btn)

    def _set_client_joined(self, joined: bool) -> None:
        """客户端按钮随「是否已加入」翻转。"""
        if not joined:
            self.client_files_table.setRowCount(0)
            self.client_label.setText("未加入频道")
        self._sync_client_buttons()

    def _sync_client_buttons(self) -> None:
        """按当前会话状态同步客户端按钮的可用性。"""
        joined = self._session is not None
        for btn in (self.refresh_btn, self.upload_btn, self.download_btn,
                    self.leave_btn):
            btn.setEnabled(joined)
        self.join_btn.setEnabled(True)

    @staticmethod
    def _session_lost(message: str) -> bool:
        """判断错误文案是否意味着当前会话已作废（需要重新输密码）。"""
        return any(key in message for key in
                   ("会话已失效", "重新输入密码", "频道已不存在", "频道已被移除"))

    def _load_client_files(self, silent: bool) -> None:
        """拉取会话频道文件清单（后台线程）。"""
        session = self._session
        if session is None:
            self._set_status(False, "请先输入密码加入频道。")
            return

        def job(report):
            return lan_share.client_files(session["base"], session["token"])

        def done(files):
            self._fill_files_table(self.client_files_table, files)
            if not silent:
                self._set_status(True, f"文件列表已刷新（{len(files)} 个）。")

        def failed(message: str) -> None:
            if self._session_lost(message):
                self._session = None
                self._set_client_joined(False)
            self._set_status(False, message)

        self._run_async(job, done, on_err=failed)

    def _poll_client_files(self) -> None:
        """静默轮询当前频道的文件列表：对端发文件 3 秒内自动出现。

        与「刷新列表」共用 _ok 回调但不动状态栏文案；一次轮询没回来就跳过
        本次心跳（_poll_busy 防重入）。
        """
        if self._poll_busy or self._session is None:
            return
        session = self._session
        self._poll_busy = True

        def job(report):
            return lan_share.client_files(session["base"], session["token"],
                                          timeout=6.0)

        def done(files):
            self._poll_busy = False
            self._fill_files_table(self.client_files_table, files)

        def failed(message: str) -> None:
            self._poll_busy = False
            if self._session_lost(message):
                self._session = None
                self._set_client_joined(False)
                self._set_status(False, "与服务器失去联系，请重新加入频道。")

        self._run_async(job, done, on_err=failed)

    def _upload_files(self) -> None:
        """把本机文件上传到当前会话频道。"""
        session = self._session
        if session is None:
            self._set_status(False, "请先输入密码加入频道。")
            return
        paths, _ = QFileDialog.getOpenFileNames(self, "选择要上传的文件")
        if not paths:
            return

        def job(report):
            uploaded = []
            for path in paths:
                info = lan_share.client_upload(
                    session["base"], session["token"], path, report=report)
                uploaded.append(info.get("name", Path(path).name))
            return uploaded

        def done(names):
            self._set_status(
                True, f"已上传 {len(names)} 个文件到当前频道。")
            self._load_client_files(True)

        self._run_async(job, done, self.upload_btn, self.download_btn)

    def _download_files(self) -> None:
        """下载：保存所选文件到目录（可多选；重名自动追加序号）。"""
        session = self._session
        if session is None:
            self._set_status(False, "请先输入密码加入频道。")
            return
        names = self._selected_file_names(self.client_files_table)
        if not names:
            self._set_status(False, "请先在列表里选中要下载的文件。")
            return
        cfg = self.store.get("watermark", default={}) or {}
        default_dir = str(resolve_output_dir(cfg.get("output_dir")))
        directory = QFileDialog.getExistingDirectory(
            self, "选择保存位置", default_dir)
        if not directory:
            return

        def job(report):
            saved = []
            for filename in names:
                path = lan_share.client_download(
                    session["base"], session["token"], filename, directory,
                    report=report)
                saved.append(path)
            return saved

        def done(saved):
            self._set_status(
                True, f"已保存 {len(saved)} 个文件到 {directory}。")

        self._run_async(job, done, self.download_btn, self.upload_btn)

    def _leave(self) -> None:
        """主动退出：服务端立刻作废会话，下次加入需要再次输密码。"""
        session = self._session
        self._session = None
        self._set_client_joined(False)
        if session is None:
            return
        self._set_info("已退出频道（会话作废）。")
        self._run_async(
            lambda report: lan_share.client_leave(
                session["base"], session["token"]),
            None,
        )

    # ------------------------------------------------------------------ 任务
    def _run_async(self, fn, on_ok, *buttons, on_err=None) -> None:
        """启动一个后台任务；关联按钮在任务完成前禁用。"""
        worker = _RpcWorker(fn, self)
        enabled = [btn for btn in buttons if hasattr(btn, "setEnabled")]
        for btn in enabled:
            btn.setEnabled(False)
        worker.progress.connect(self._on_progress)

        def finish() -> None:
            self._workers.discard(worker)
            for btn in enabled:
                btn.setEnabled(True)
            self._sync_client_buttons()
            worker.deleteLater()

        def ok(result) -> None:
            finish()
            if on_ok is not None:
                on_ok(result)

        def err(message: str) -> None:
            finish()
            if on_err is not None:
                on_err(message)
            else:
                self._set_status(False, message)

        worker.done_ok.connect(ok)
        worker.done_err.connect(err)
        worker.finished.connect(lambda: self._workers.discard(worker))
        self._workers.add(worker)
        worker.start()

    def _on_progress(self, done: int, total: int) -> None:
        """后台传输进度：状态栏实时刷新（节流到 ~10 次/秒）。"""
        if total <= 0:
            return
        now = time.monotonic()
        percent = min(100, int(done * 100 / total))
        if percent < 100 and now - self._last_progress < 0.1:
            return
        self._last_progress = now
        self._set_info(
            f"传输中：{lan_share.format_size(done)} / "
            f"{lan_share.format_size(total)}（{percent}%）")

    # ------------------------------------------------------------------ 生命周期
    def shutdown(self) -> None:
        """停服务、等后台线程退出（应用退出时调用）。"""
        self._timer.stop()
        if self.server is not None:
            self.server.stop()
            self.server = None
        if self._session is not None:
            session = self._session
            self._session = None
            lan_share.client_leave(session["base"], session["token"], timeout=1.0)
        for worker in list(self._workers):
            if worker.isRunning():
                worker.wait(1500)
        self._workers.clear()
        self._save_config()
