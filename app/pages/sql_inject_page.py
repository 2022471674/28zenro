# -*- coding: utf-8 -*-
"""SQL 注入 Payload 生成器页（参考 sqlmap 生成逻辑）。

技术（布尔盲注 / 报错 / 时间盲注 / UNION / 堆叠）× 闭合边界 × DBMS ×
tamper 绕过链组合生成 payload，支持 level 过滤、true/false 对照对展示、
向量（[QUERY]/[INFERENCE] 已替换）与 txt 导出。

纯本地计算，无网络请求。仅限授权靶场 / 渗透测试环境使用。
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFileDialog,
    QGridLayout,
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

from app.widgets.no_wheel import NoWheelComboBox, NoWheelSpinBox
from app.widgets.responsive import ScrollColumn, guard_min_heights
from lib import sql_inject


class SqlInjectPage(QWidget):
    """SQL 注入 Payload 生成器页。"""

    COLUMNS = ("技术", "DBMS", "标题", "Lv", "Payload")
    #: tamper 复选框排版：每行几个
    _TAMPER_PER_ROW = 5

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._report: sql_inject.GenerateReport | None = None
        self._items: list[sql_inject.PayloadItem] = []      # 全部结果
        self._shown: list[sql_inject.PayloadItem] = []      # 过滤后表格里的
        self._build_ui()

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(36, 28, 36, 28)
        layout.setSpacing(10)

        # -- 生成配置（滚动区：统一网格，标签列 + 控件列两两成对垂直对齐）----
        self.config_scroll = ScrollColumn()
        grid = QGridLayout()
        grid.setVerticalSpacing(8)
        grid.setHorizontalSpacing(12)
        grid.setColumnStretch(1, 1)
        grid.setColumnStretch(3, 1)

        def _label(text: str) -> QLabel:
            lab = QLabel(text)
            lab.setAlignment(Qt.AlignmentFlag.AlignRight
                             | Qt.AlignmentFlag.AlignVCenter)
            return lab

        row = 0
        # 注入技术：5 个复选框等宽列均匀铺满整行
        self.tech_checks: dict[str, QCheckBox] = {}
        tech_grid = QGridLayout()
        tech_grid.setHorizontalSpacing(8)
        for idx, (key, label) in enumerate(sql_inject.TECHNIQUES):
            check = QCheckBox(label)
            check.setChecked(True)
            self.tech_checks[key] = check
            tech_grid.addWidget(check, 0, idx)
            tech_grid.setColumnStretch(idx, 1)
        grid.addWidget(_label("注入技术"), row, 0)
        grid.addLayout(tech_grid, row, 1, 1, 3)
        row += 1

        self.dbms_combo = NoWheelComboBox()
        for value, label in sql_inject.DBMS_CHOICES:
            self.dbms_combo.addItem(label, value)
        self.closure_combo = NoWheelComboBox()
        for value, label in sql_inject.CLOSURE_CHOICES:
            self.closure_combo.addItem(label, value)
        grid.addWidget(_label("数据库"), row, 0)
        grid.addWidget(self.dbms_combo, row, 1)
        grid.addWidget(_label("闭合边界"), row, 2)
        grid.addWidget(self.closure_combo, row, 3)
        row += 1

        self.where_combo = NoWheelComboBox()
        for value, label in sql_inject.WHERE_CHOICES:
            self.where_combo.addItem(label, value)
        self.level_spin = NoWheelSpinBox()
        self.level_spin.setRange(1, 5)
        self.level_spin.setValue(3)
        self.level_spin.setToolTip("sqlmap level：1 最常用（<100 请求），"
                                   "5 罕见（>1000 请求）；只生成 level ≤ 此值的条目")
        grid.addWidget(_label("拼接方式"), row, 0)
        grid.addWidget(self.where_combo, row, 1)
        grid.addWidget(_label("Level ≤"), row, 2)
        grid.addWidget(self.level_spin, row, 3)
        row += 1

        self.orig_edit = QLineEdit()
        self.orig_edit.setText("1")
        self.orig_edit.setPlaceholderText("注入点的原始参数值，如 1 / admin")
        self.sleep_spin = NoWheelSpinBox()
        self.sleep_spin.setRange(1, 30)
        self.sleep_spin.setValue(sql_inject.DEFAULT_SLEEP)
        self.sleep_spin.setSuffix(" 秒")
        grid.addWidget(_label("原参数值"), row, 0)
        grid.addWidget(self.orig_edit, row, 1)
        grid.addWidget(_label("延时（秒）"), row, 2)
        grid.addWidget(self.sleep_spin, row, 3)
        row += 1

        self.query_edit = QLineEdit()
        self.query_edit.setText(sql_inject.DEFAULT_QUERY)
        self.query_edit.setPlaceholderText(
            "利用向量中 [QUERY] 的替换内容，如 SELECT @@version / "
            "SELECT version() / SELECT table_name FROM information_schema.tables")
        grid.addWidget(_label("取数查询"), row, 0)
        grid.addWidget(self.query_edit, row, 1, 1, 3)
        row += 1

        self.union_fill_combo = NoWheelComboBox()
        for value, label in sql_inject.UNION_FILL_CHOICES:
            self.union_fill_combo.addItem(label, value)
        self.col_start_spin = NoWheelSpinBox()
        self.col_start_spin.setRange(1, 30)
        self.col_start_spin.setValue(1)
        self.col_stop_spin = NoWheelSpinBox()
        self.col_stop_spin.setRange(1, 30)
        self.col_stop_spin.setValue(10)
        col_range = QHBoxLayout()
        col_range.setContentsMargins(0, 0, 0, 0)
        col_range.setSpacing(6)
        col_range.addWidget(self.col_start_spin)
        col_range.addWidget(QLabel("至"))
        col_range.addWidget(self.col_stop_spin)
        col_range.addStretch(1)
        grid.addWidget(_label("UNION 填充"), row, 0)
        grid.addWidget(self.union_fill_combo, row, 1)
        grid.addWidget(_label("列数范围"), row, 2)
        grid.addLayout(col_range, row, 3)
        row += 1

        self.limit_spin = NoWheelSpinBox()
        self.limit_spin.setRange(0, 2000)
        self.limit_spin.setValue(sql_inject.DEFAULT_LIMIT)
        self.limit_spin.setSuffix(" 条")
        self.limit_spin.setSpecialValueText("不限")
        self.orderby_check = QCheckBox("ORDER BY 探测列数")
        self.orderby_check.setChecked(True)
        grid.addWidget(_label("条数上限"), row, 0)
        grid.addWidget(self.limit_spin, row, 1)
        grid.addWidget(_label("列数探测"), row, 2)
        grid.addWidget(self.orderby_check, row, 3)
        row += 1

        # tamper 复选框：等宽列均匀分布（附说明 tooltip）
        tamper_grid = QGridLayout()
        tamper_grid.setHorizontalSpacing(8)
        self.tamper_checks: dict[str, QCheckBox] = {}
        for idx, tamper in enumerate(sql_inject.TAMPERS):
            check = QCheckBox(tamper.key)
            check.setToolTip(tamper.desc)
            self.tamper_checks[tamper.key] = check
            tamper_grid.addWidget(check, idx // self._TAMPER_PER_ROW,
                                  idx % self._TAMPER_PER_ROW)
        for col in range(self._TAMPER_PER_ROW):
            tamper_grid.setColumnStretch(col, 1)
        grid.addWidget(_label("tamper 链"), row, 0)
        grid.addLayout(tamper_grid, row, 1, 1, 3)

        self.config_scroll.add_layout(grid)
        layout.addWidget(self.config_scroll, 2)

        # -- 操作按钮 --------------------------------------------------------
        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        self.run_btn = QPushButton("生成 Payload")
        self.run_btn.setObjectName("ghbtn-primary")
        self.run_btn.clicked.connect(self._generate)
        buttons.addWidget(self.run_btn)
        clear_btn = QPushButton("清空")
        clear_btn.setObjectName("ghbtn")
        clear_btn.clicked.connect(self._clear)
        buttons.addWidget(clear_btn)
        copy_sel_btn = QPushButton("复制选中")
        copy_sel_btn.setObjectName("ghbtn")
        copy_sel_btn.clicked.connect(self._copy_selected)
        buttons.addWidget(copy_sel_btn)
        copy_all_btn = QPushButton("复制全部")
        copy_all_btn.setObjectName("ghbtn")
        copy_all_btn.clicked.connect(self._copy_all)
        buttons.addWidget(copy_all_btn)
        export_btn = QPushButton("导出 txt")
        export_btn.setObjectName("ghbtn")
        export_btn.clicked.connect(self._export)
        buttons.addWidget(export_btn)
        buttons.addStretch(1)
        layout.addLayout(buttons)

        # -- 结果表格 --------------------------------------------------------
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("过滤结果（标题 / DBMS / payload 关键字）")
        self.filter_edit.textChanged.connect(self._render_table)
        layout.addWidget(self.filter_edit)

        self.table = TableWidget(self)
        self.table.setColumnCount(len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels(self.COLUMNS)
        self.table.setEditTriggers(TableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(TableWidget.SelectRows)
        self.table.verticalHeader().hide()
        header = self.table.horizontalHeader()
        for col in range(len(self.COLUMNS)):
            header.setSectionResizeMode(col, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header.resizeSection(0, 84)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        header.resizeSection(1, 120)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        header.resizeSection(3, 40)
        self.table.currentCellChanged.connect(
            lambda *_: self._show_detail())
        self.table.cellDoubleClicked.connect(self._copy_row)
        layout.addWidget(self.table, stretch=3)

        # -- 选中条目详情 ----------------------------------------------------
        layout.addWidget(QLabel("选中条目详情（payload / 利用向量 / 说明）"))
        self.detail_edit = QPlainTextEdit()
        self.detail_edit.setObjectName("io")
        self.detail_edit.setReadOnly(True)
        self.detail_edit.setMinimumHeight(96)
        self.detail_edit.setPlaceholderText("选中表格中的一行查看详情；双击行复制该 payload。")
        layout.addWidget(self.detail_edit, stretch=1)

        self.status_label = QLabel("")
        self.status_label.setObjectName("status-info")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        guard_min_heights(self)

    # -------------------------------------------------------------- 生成
    def _gather_cfg(self) -> dict:
        techniques = tuple(
            key for key, check in self.tech_checks.items() if check.isChecked())
        tampers = tuple(
            key for key, check in self.tamper_checks.items() if check.isChecked())
        return {
            "techniques": techniques,
            "dbms": self.dbms_combo.currentData(),
            "closure": self.closure_combo.currentData(),
            "where_mode": self.where_combo.currentData(),
            "max_level": self.level_spin.value(),
            "orig_value": self.orig_edit.text().strip(),
            "sleep_time": self.sleep_spin.value(),
            "query": self.query_edit.text().strip() or sql_inject.DEFAULT_QUERY,
            "tampers": tampers,
            "union_fill": self.union_fill_combo.currentData(),
            "union_col_start": self.col_start_spin.value(),
            "union_col_stop": self.col_stop_spin.value(),
            "union_order_by": self.orderby_check.isChecked(),
            "limit": self.limit_spin.value(),
        }

    def _generate(self) -> None:
        cfg = self._gather_cfg()
        if not cfg["techniques"]:
            self._set_status(False, "请至少勾选一种注入技术。")
            return
        try:
            report = sql_inject.generate(**cfg)
        except Exception as exc:  # noqa: BLE001  纯计算兜底
            self._set_status(False, f"生成失败：{exc}")
            return
        self._report = report
        self._items = report.items
        self._render_table()
        summary = "、".join(f"{k} {v} 条" for k, v in report.counts.items())
        note = f"；tamper 链：{' -> '.join(report.tamper_keys)}" \
            if report.tamper_keys else ""
        self._set_status(True, f"共生成 {report.total} 条（{summary}）{note}")

    # -------------------------------------------------------------- 渲染
    def _render_table(self) -> None:
        keyword = self.filter_edit.text().strip().lower()
        self.table.setRowCount(0)
        self._shown = []
        for item in self._items:
            hay = " ".join((item.title, item.dbms, item.payload,
                            item.technique_label)).lower()
            if keyword and keyword not in hay:
                continue
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(item.technique_label))
            self.table.setItem(row, 1, QTableWidgetItem(item.dbms or "通用"))
            self.table.setItem(row, 2, QTableWidgetItem(item.title))
            self.table.setItem(row, 3, QTableWidgetItem(str(item.level)))
            self.table.setItem(row, 4, QTableWidgetItem(item.payload))
            self._shown.append(item)
        if self._shown:
            self.table.selectRow(0)

    def _show_detail(self) -> None:
        row = self.table.currentRow()
        if row < 0 or row >= len(self._shown):
            return
        item = self._shown[row]
        lines = [
            f"[{item.technique_label}][{item.dbms or '通用'}] {item.title}",
            f"level {item.level} / risk {item.risk} / 闭合：{item.closure_label}",
            "",
            item.payload,
        ]
        if item.vector:
            lines += ["", f"利用向量：{item.vector}"]
        if item.note:
            lines += ["", f"说明：{item.note}"]
        self.detail_edit.setPlainText("\n".join(lines))

    def _clear(self) -> None:
        self._report = None
        self._items = []
        self._shown = []
        self.table.setRowCount(0)
        self.detail_edit.clear()
        self.filter_edit.clear()
        self._set_status(True, "结果已清空。")

    # -------------------------------------------------------------- 导出
    def _copy_selected(self) -> None:
        row = self.table.currentRow()
        if row < 0 or row >= len(self._shown):
            self._set_status(False, "请先在表格中选中一行。")
            return
        QApplication.clipboard().setText(self._shown[row].payload)
        self._set_status(True, "已复制选中 payload 到剪贴板。")

    def _copy_row(self, row: int, _col: int) -> None:
        if 0 <= row < len(self._shown):
            QApplication.clipboard().setText(self._shown[row].payload)
            self._set_status(True, "已复制该行 payload 到剪贴板。")

    def _copy_all(self) -> None:
        if not self._items:
            self._set_status(False, "还没有结果，请先生成。")
            return
        QApplication.clipboard().setText(
            sql_inject.format_items_text(self._items, self._report))
        self._set_status(True, f"已复制全部 {len(self._items)} 条到剪贴板。")

    def _export(self) -> None:
        if not self._items:
            self._set_status(False, "还没有结果，请先生成。")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "导出 SQL 注入 payload", "sql_payloads.txt",
            "文本文件 (*.txt);;所有文件 (*)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(sql_inject.format_items_text(self._items, self._report))
        except OSError as exc:
            self._set_status(False, f"导出失败：{exc}")
            return
        self._set_status(True, f"已导出 {len(self._items)} 条到 {path}")

    # -------------------------------------------------------------- 杂项
    def _set_status(self, ok: bool, text: str) -> None:
        self.status_label.setText(text)
        self.status_label.setObjectName("status-err" if not ok else "status-info")
        self.style().unpolish(self.status_label)
        self.style().polish(self.status_label)
