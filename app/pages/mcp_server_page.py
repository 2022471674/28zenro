# -*- coding: utf-8 -*-
"""MCP 服务状态管理页。

管理 28zenro 的 MCP HTTP（streamable-http）长驻服务：
- 配置监听地址 / 端口（持久化到 store 的 ``mcp_server`` 节）；
- 启动 / 停止 / 重启服务进程（``python mcp/server.py --http``）；
- 实时状态检测（端口是否监听 + 进程是否存活）；
- 实时日志（子进程 stdout / stderr 追加到日志框）；
- 「工具注册」展示全部 ``cn_*`` 工具组与 op 明细，并支持按组启用 / 禁用
  （写入 ``mcp_server.disabled_groups``，服务重启后生效）。

stdio 模式由宿主以子进程方式拉起，不在本页管理范围内。
"""

from __future__ import annotations

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QPushButton,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.widgets.no_wheel import NoWheelSpinBox
from lib import mcp_server_control as msc

#: op 风险等级在表格里的显示文案
_RISK_LABELS = {
    "safe": "safe 纯计算",
    "read": "read 读文件",
    "write": "write 写文件",
    "network": "network 网络",
    "intrusive": "intrusive 主动探测",
    "long": "long 耗时",
}


class McpServerPage(QWidget):
    """MCP HTTP 服务控制面板 + 配置文件预览 / 修改。"""

    #: 子进程后台线程 → 主线程的日志回传信号（线程安全，避免跨线程操作 GUI）
    _log_signal = Signal(str)

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._registry: dict | None = None      # 工具注册表摘要（工具注册页）
        self._building_registry = False          # 列表重建期间抑制勾选信号
        self._manager = msc.current_manager()
        # 后台线程日志统一经信号回主线程再写控件
        self._log_signal.connect(self._append_log)
        self._build()

        # 状态刷新定时器（1.5s 轮询一次）
        self._poll = QTimer(self)
        self._poll.setInterval(1500)
        self._poll.timeout.connect(self._refresh_status)
        self._poll.start()

    # -------------------------------------------------------------- 主题
    def set_theme(self, palette) -> None:
        self.theme = palette

    # ------------------------------------------------------------------ UI
    def _build(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_control_tab(), "服务控制")
        self.tabs.addTab(self._build_tools_tab(), "工具注册")
        self.tabs.addTab(self._build_config_tab(), "配置文件")
        layout.addWidget(self.tabs, stretch=1)

        self._update_endpoint()
        self._refresh_status()
        self._load_config()

    # -- 标签页 1：服务控制 -------------------------------------------------
    def _build_control_tab(self) -> QWidget:
        host = QWidget()
        layout = QVBoxLayout(host)
        layout.setContentsMargins(8, 14, 8, 8)
        layout.setSpacing(12)

        # -- 配置区 --
        cfg = self.store.get("mcp_server", default={}) or {}
        form = QFormLayout()
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(10)

        self.host_edit = QLineEdit(str(cfg.get("host", msc.DEFAULT_HOST)))
        form.addRow("监听地址", self.host_edit)

        self.port_spin = NoWheelSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(int(cfg.get("port", msc.DEFAULT_PORT)))
        form.addRow("监听端口", self.port_spin)

        self.endpoint_label = QLabel("")
        self.endpoint_label.setObjectName("caption")
        form.addRow("端点", self.endpoint_label)
        layout.addLayout(form)

        # -- 控制按钮 --
        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        self.start_btn = QPushButton("启动")
        self.start_btn.setObjectName("ghbtn-primary")
        self.start_btn.clicked.connect(self._start)
        self.stop_btn = QPushButton("停止")
        self.stop_btn.setObjectName("ghbtn-danger")
        self.stop_btn.clicked.connect(self._stop)
        self.restart_btn = QPushButton("重启")
        self.restart_btn.setObjectName("ghbtn")
        self.restart_btn.clicked.connect(self._restart)
        self.refresh_btn = QPushButton("刷新状态")
        self.refresh_btn.setObjectName("ghbtn")
        self.refresh_btn.clicked.connect(self._refresh_status)
        buttons.addWidget(self.start_btn)
        buttons.addWidget(self.stop_btn)
        buttons.addWidget(self.restart_btn)
        buttons.addWidget(self.refresh_btn)
        buttons.addStretch(1)
        layout.addLayout(buttons)

        # -- 状态 --
        self.status_label = QLabel("就绪。")
        self.status_label.setObjectName("status-info")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        # -- 活跃连接 --
        sessions_label = QLabel("活跃连接")
        sessions_label.setObjectName("section")
        layout.addWidget(sessions_label)
        self.sessions_summary = QLabel("服务未启动，暂无连接信息。")
        self.sessions_summary.setObjectName("caption")
        self.sessions_summary.setWordWrap(True)
        layout.addWidget(self.sessions_summary)
        self.sessions_table = QTableWidget(0, 4)
        self.sessions_table.setHorizontalHeaderLabels(
            ("session_id", "来源", "User-Agent", "最近活跃"))
        self.sessions_table.verticalHeader().setVisible(False)
        self.sessions_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)
        self.sessions_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers)
        sheader = self.sessions_table.horizontalHeader()
        sheader.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.sessions_table.setColumnWidth(0, 240)
        self.sessions_table.setColumnWidth(1, 150)
        self.sessions_table.setColumnWidth(2, 240)
        sheader.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.sessions_table.verticalHeader().setDefaultSectionSize(24)
        layout.addWidget(self.sessions_table, 1)

        # -- 日志 --
        log_label = QLabel("服务日志")
        log_label.setObjectName("section")
        layout.addWidget(log_label)
        self.log_view = QPlainTextEdit()
        self.log_view.setObjectName("io")
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(5000)
        layout.addWidget(self.log_view, stretch=2)
        return host

    # ------------------------------------------------------------- 工具注册
    def _build_tools_tab(self) -> QWidget:
        """「工具注册」：展示 MCP 全部 ``cn_*`` 工具组与其 op，按组启停。"""
        host = QWidget()
        layout = QVBoxLayout(host)
        layout.setContentsMargins(8, 14, 8, 8)
        layout.setSpacing(10)

        # -- 汇总 + 刷新 --
        top = QHBoxLayout()
        top.setSpacing(8)
        self.registry_summary = QLabel("工具注册表加载中…")
        self.registry_summary.setObjectName("caption")
        self.registry_summary.setWordWrap(True)
        top.addWidget(self.registry_summary, 1)
        reload_btn = QPushButton("重新加载")
        reload_btn.setObjectName("ghbtn")
        reload_btn.clicked.connect(self._reload_registry)
        top.addWidget(reload_btn)
        layout.addLayout(top)

        # -- 左：工具组列表；右：选中组的 op 表 --
        left_label = QLabel("工具组（勾选 = 注册，取消 = 禁用；cn_help 固定注册）")
        left_label.setObjectName("section")
        self.group_list = QListWidget()
        self.group_list.setSelectionMode(
            QListWidget.SelectionMode.SingleSelection)
        self._building_registry = False
        self.group_list.itemChanged.connect(self._on_group_item_changed)
        self.group_list.currentItemChanged.connect(
            lambda _c, _p: self._show_group_ops())

        right_label = QLabel("工具组 op 明细")
        right_label.setObjectName("section")
        self.group_title = QLabel("")
        self.group_title.setObjectName("title")
        self.group_summary = QLabel("")
        self.group_summary.setObjectName("caption")
        self.group_summary.setWordWrap(True)
        self.ops_table = QTableWidget(0, 4)
        self.ops_table.setHorizontalHeaderLabels(
            ("op", "风险", "返回", "说明"))
        self.ops_table.verticalHeader().setVisible(False)
        self.ops_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)
        self.ops_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers)
        header = self.ops_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.ops_table.setColumnWidth(0, 220)
        self.ops_table.setColumnWidth(1, 130)
        self.ops_table.setColumnWidth(2, 260)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.ops_table.verticalHeader().setDefaultSectionSize(26)

        body = QHBoxLayout()
        body.setSpacing(12)
        left_col = QVBoxLayout()
        left_col.setSpacing(6)
        left_col.addWidget(left_label)
        left_col.addWidget(self.group_list, 1)
        right_col = QVBoxLayout()
        right_col.setSpacing(6)
        right_col.addWidget(right_label)
        right_col.addWidget(self.group_title)
        right_col.addWidget(self.group_summary)
        right_col.addWidget(self.ops_table, 1)
        body.addLayout(left_col, 2)
        body.addLayout(right_col, 3)
        layout.addLayout(body, 1)

        # -- 保存 --
        actions = QHBoxLayout()
        actions.setSpacing(8)
        save_btn = QPushButton("保存注册配置")
        save_btn.setObjectName("ghbtn-primary")
        save_btn.clicked.connect(self._save_registry)
        actions.addWidget(save_btn)
        actions.addStretch(1)
        layout.addLayout(actions)

        self.tools_status_label = QLabel("")
        self.tools_status_label.setObjectName("status-info")
        self.tools_status_label.setWordWrap(True)
        layout.addWidget(self.tools_status_label)

        self._reload_registry()
        return host

    # -- 注册表加载 / 展示 -------------------------------------------------
    def _reload_registry(self) -> None:
        """加载（或重载）工具注册表并同步到列表与保存状态。"""
        try:
            summary = msc.registry_summary()
        except Exception as exc:  # noqa: BLE001  mcp/ 子项目缺失时降级
            self.registry_summary.setText(
                f"工具注册表加载失败：{type(exc).__name__}: {exc}"
                "　—— 请确认 mcp/ 目录存在后点「重新加载」。")
            self.registry_summary.setObjectName("status-err")
            self.registry_summary.style().unpolish(self.registry_summary)
            self.registry_summary.style().polish(self.registry_summary)
            return

        self._registry = summary
        groups = summary.get("groups") or []
        disabled = set(msc.load_disabled_groups(self.store))

        self._building_registry = True
        try:
            self.group_list.clear()
            for group in groups:
                name = group["name"]
                item = QListWidgetItem(
                    f"{name}　·　{group['op_count']} op　{group['title']}")
                item.setData(Qt.ItemDataRole.UserRole, name)
                flags = item.flags()
                if name in msc.ALWAYS_ON_GROUPS:
                    item.setText(
                        f"{name}　·　{group['op_count']} op　"
                        f"{group['title']}（固定注册）")
                    item.setFlags(flags & ~Qt.ItemFlag.ItemIsUserCheckable)
                else:
                    item.setCheckState(
                        Qt.CheckState.Unchecked if name in disabled
                        else Qt.CheckState.Checked)
                    item.setFlags(flags | Qt.ItemFlag.ItemIsUserCheckable)
                item.setToolTip(group.get("summary", ""))
                self.group_list.addItem(item)
        finally:
            self._building_registry = False

        import_errors = summary.get("import_errors")
        extra = ""
        if import_errors:
            extra += f"　·　{len(import_errors)} 个模块加载失败"
        self.registry_summary.setText(
            f"{len(groups)} 个工具组 / {summary.get('total_ops', 0)} 个 op，"
            f"当前禁用 {len(disabled)} 组{extra}"
            f"　——　保存后需重启 MCP 服务生效。")
        self.registry_summary.setObjectName("caption")
        self.registry_summary.style().unpolish(self.registry_summary)
        self.registry_summary.style().polish(self.registry_summary)

        self.group_list.setCurrentRow(0)
        self._show_group_ops()

    def _on_group_item_changed(self, item: QListWidgetItem) -> None:
        """勾选变化：锁定 ``cn_help`` 并同步汇总行禁用计数。"""
        if self._building_registry:
            return
        name = item.data(Qt.ItemDataRole.UserRole)
        if name in msc.ALWAYS_ON_GROUPS:
            self.tools_status_label.setText(
                "cn_help 是宿主的工具发现入口，固定注册，不可禁用。")
        registry = getattr(self, "_registry", None) or {}
        disabled = self._current_disabled()
        self.registry_summary.setText(
            f"{self.group_list.count()} 个工具组 / "
            f"{registry.get('total_ops', 0)} 个 op，"
            f"未保存的禁用名单为 {len(disabled)} 组　——　"
            "记得点「保存注册配置」生效。")

    def _current_disabled(self) -> list[str]:
        """按当前勾选状态收集被禁用（未勾选）的工具组名。"""
        out: list[str] = []
        for i in range(self.group_list.count()):
            item = self.group_list.item(i)
            if item is None:
                continue
            name = item.data(Qt.ItemDataRole.UserRole)
            if name in msc.ALWAYS_ON_GROUPS:
                continue
            if item.checkState() != Qt.CheckState.Checked:
                out.append(name)
        return out

    def _is_checked_row(self, row: int) -> bool:
        """该行是否视为已注册（固定注册组恒为真；其余看勾选态）。"""
        item = self.group_list.item(row)
        if item is None:
            return False
        if item.data(Qt.ItemDataRole.UserRole) in msc.ALWAYS_ON_GROUPS:
            return True
        return item.checkState() == Qt.CheckState.Checked

    def _selected_group(self) -> dict | None:
        """当前选中工具组的注册表条目（保存在 item UserRole 里）。"""
        item = self.group_list.currentItem()
        if item is None:
            return None
        name = item.data(Qt.ItemDataRole.UserRole)
        for group in getattr(self, "_registry", {}).get("groups", []):
            if group["name"] == name:
                return group
        return None

    def _show_group_ops(self) -> None:
        """把选中工具组的 op 明细填进表格。"""
        group = self._selected_group()
        if group is None:
            self.group_title.setText("")
            self.group_summary.setText("")
            self.ops_table.setRowCount(0)
            return
        self.group_title.setText(
            f"{group['name']}　{group.get('title', '')}")
        risks = "、".join(_RISK_LABELS.get(r, r) for r in group.get("risks", []))
        self.group_summary.setText(
            f"{group.get('summary', '')}\n风险等级：{risks}")
        self.ops_table.setRowCount(0)
        for op in group.get("ops", []):
            row = self.ops_table.rowCount()
            self.ops_table.insertRow(row)
            self.ops_table.setItem(
                row, 0, QTableWidgetItem(op["name"]))
            self.ops_table.setItem(
                row, 1, QTableWidgetItem(_RISK_LABELS.get(op["risk"], op["risk"])))
            self.ops_table.setItem(
                row, 2, QTableWidgetItem(op.get("returns", "")))
            summary_item = QTableWidgetItem(op.get("summary", ""))
            summary_item.setToolTip(op.get("summary", ""))
            self.ops_table.setItem(row, 3, summary_item)

    def _save_registry(self) -> None:
        """把禁用名单写入共享配置并提示重启服务生效。"""
        disabled = [self.group_list.item(i).data(Qt.ItemDataRole.UserRole)
                    for i in range(self.group_list.count())
                    if not self._is_checked_row(i)]
        try:
            msc.save_disabled_groups(self.store, disabled)
        except OSError as exc:
            self.tools_status_label.setText(f"保存失败：{exc}")
            return
        total = self.group_list.count()
        self.tools_status_label.setText(
            f"已保存：注册 {total - len(disabled)} 组 / 禁用 {len(disabled)} 组"
            f"（禁用：{'、'.join(disabled) if disabled else '无'}）。"
            "服务运行中时请到「服务控制」重启生效。")
        # 同步汇总行的禁用计数
        self.registry_summary.setText(
            f"{total} 个工具组 / {(self._registry or {}).get('total_ops', 0)} 个 op，"
            f"当前禁用 {len(disabled)} 组　——　保存后需重启 MCP 服务生效。")

    # -- 标签页 3：配置文件 -------------------------------------------------
    def _build_config_tab(self) -> QWidget:
        host = QWidget()
        layout = QVBoxLayout(host)
        layout.setContentsMargins(8, 14, 8, 8)
        layout.setSpacing(10)

        self.config_path_label = QLabel("")
        self.config_path_label.setObjectName("caption")
        self.config_path_label.setWordWrap(True)
        self.config_path_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self.config_path_label)

        self.config_edit = QPlainTextEdit()
        self.config_edit.setObjectName("io")
        self.config_edit.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        layout.addWidget(self.config_edit, stretch=1)

        self.config_status = QLabel("")
        self.config_status.setObjectName("status-info")
        self.config_status.setWordWrap(True)
        layout.addWidget(self.config_status)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        reload_btn = QPushButton("重新读取")
        reload_btn.setObjectName("ghbtn")
        reload_btn.clicked.connect(self._load_config)
        save_btn = QPushButton("保存")
        save_btn.setObjectName("ghbtn-primary")
        save_btn.clicked.connect(self._save_config_file)
        buttons.addWidget(reload_btn)
        buttons.addWidget(save_btn)
        buttons.addStretch(1)
        layout.addLayout(buttons)
        return host

    # ------------------------------------------------------------- 配置文件
    def _load_config(self) -> None:
        path = msc.config_path()
        self.config_path_label.setText(f"配置文件：{path}")
        self.config_edit.setPlainText(msc.read_config())

    def _save_config_file(self) -> None:
        text = self.config_edit.toPlainText()
        err = msc.validate_config(text)
        if err is not None:
            self._set_config_status(False, err)
            return
        try:
            msc.write_config(text)
        except OSError as exc:
            self._set_config_status(False, f"保存失败：{exc}")
            return
        self._set_config_status(True, "已保存到 mcp/mcp.json。")

    def _set_config_status(self, ok: bool, text: str) -> None:
        self.config_status.setText(text)
        self.config_status.setObjectName("status-ok" if ok else "status-err")
        self.config_status.style().unpolish(self.config_status)
        self.config_status.style().polish(self.config_status)

    # ------------------------------------------------------------- 状态
    def _host(self) -> str:
        return self.host_edit.text().strip() or msc.DEFAULT_HOST

    def _port(self) -> int:
        return int(self.port_spin.value())

    def _update_endpoint(self) -> None:
        self.endpoint_label.setText(f"http://{self._host()}:{self._port()}/mcp")

    def _save_config(self) -> None:
        self.store.setv(self._host(), "mcp_server", "host")
        self.store.setv(self._port(), "mcp_server", "port")
        self.store.save()

    def _refresh_status(self) -> None:
        host, port = self._host(), self._port()
        listening = msc.port_open(host, port)
        managed = self._manager.running
        pid = self._manager.pid

        if listening and managed:
            text = f"运行中　·　监听 http://{host}:{port}/mcp　·　PID {pid}"
            obj = "status-ok"
        elif listening and not managed:
            text = f"监听中（由外部进程管理，非本界面启动）　·　http://{host}:{port}/mcp"
            obj = "status-warn"
        elif managed and not listening:
            text = f"进程存活但尚未监听　·　PID {pid}　·　正在启动…"
            obj = "status-info"
        else:
            text = "已停止"
            obj = "status-info"

        self.status_label.setText(text)
        self.status_label.setObjectName(obj)
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)

        self.start_btn.setEnabled(not listening)
        self.stop_btn.setEnabled(managed)
        self.restart_btn.setEnabled(managed)

        self._refresh_sessions(listening)

    def _refresh_sessions(self, listening: bool) -> None:
        """刷新「活跃连接」面板（仅 HTTP 模式；stdio / 未监听时显示提示）。"""
        host, port = self._host(), self._port()
        if not listening:
            self.sessions_summary.setText("服务未启动，暂无连接信息。")
            self.sessions_table.setRowCount(0)
            return

        data = msc.fetch_sessions(host, port)
        if data is None:
            self.sessions_summary.setText(
                "无法获取连接信息（服务可能为旧版本，不支持 /__sessions 端点）。")
            self.sessions_table.setRowCount(0)
            return

        sessions = data.get("sessions", [])
        count = data.get("count", len(sessions))
        transport = data.get("transport", "?")
        self.sessions_summary.setText(
            f"当前 {count} 个活跃连接（transport: {transport}）。")
        self.sessions_table.setRowCount(len(sessions))
        for row, s in enumerate(sessions):
            sid = str(s.get("session_id", ""))
            client = str(s.get("client", ""))
            ua = str(s.get("user_agent", ""))
            last = s.get("last_seen")
            try:
                import datetime
                t = datetime.datetime.fromtimestamp(float(last))
                seen = t.strftime("%H:%M:%S")
            except (TypeError, ValueError, OSError):
                seen = "—"
            for col, val in enumerate((sid, client, ua, seen)):
                item = QTableWidgetItem(val)
                if col == 0:
                    item.setToolTip(sid)
                elif col == 2:
                    item.setToolTip(ua)
                self.sessions_table.setItem(row, col, item)

    def _append_log(self, line: str) -> None:
        self.log_view.appendPlainText(line)
        bar = self.log_view.verticalScrollBar()
        bar.setValue(bar.maximum())

    def _emit_log(self, line: str) -> None:
        """线程安全日志入口：后台线程调用此方法，实际写控件经信号回主线程。"""
        self._log_signal.emit(line)

    # ------------------------------------------------------------- 控制
    def _start(self) -> None:
        self._save_config()
        self._update_endpoint()
        host, port = self._host(), self._port()
        self._append_log(f">>> 启动 MCP HTTP 服务（{host}:{port}）")
        ok = self._manager.start(host, port, on_output=self._emit_log)
        if not ok:
            self._refresh_status()
            return
        self._refresh_status()

    def _stop(self) -> None:
        self._append_log(">>> 停止 MCP HTTP 服务")
        self._manager.stop()
        self._refresh_status()

    def _restart(self) -> None:
        self._append_log(">>> 重启 MCP HTTP 服务")
        self._stop()
        self._start()

    # ------------------------------------------------------------- 生命周期
    def shutdown(self) -> None:
        """退出时停止由本界面拉起的服务进程。"""
        self._poll.stop()
        self._manager.stop()
