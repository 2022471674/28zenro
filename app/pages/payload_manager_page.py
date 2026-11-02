# -*- coding: utf-8 -*-
"""Payload 编译器页（Java / PHP / Python）。

布局：
- 顶部语言分类 chips（Java / PHP / Python）；
- 中部 payload 卡片网格（每次生成一个 payload 即一张卡片，右上角标注语言，
  卡片含标题 + 作用介绍，点击进入编辑视图）；
- 底部「新建 Payload」按钮；
- 编辑视图：名称、语言、备注、带行号的大代码框，以及保存 / 编译 / 运行；
- 编译 / 运行日志在独立弹窗中显示。

解释器路径在「设置页 → Payload 编译器」统一配置，本页不再各自维护。
数据经 SQLite 持久化，编译 / 运行在后台线程执行。
"""

from __future__ import annotations

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from lib import payload_manager as pm
from app.widgets.line_number_editor import LineNumberEditor


# ---------------------------------------------------------------------------
# 卡片
# ---------------------------------------------------------------------------
class _PayloadCard(QWidget):
    """单张 payload 卡片：右上角语言标签 + 标题 + 介绍。"""

    clicked = Signal(int)

    def __init__(self, payload_id: int, name: str, language: str,
                 note: str, theme, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.payload_id = payload_id
        self.setObjectName("toolcard")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(120)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(6)

        # 顶行：标题 + 右上角语言标签
        top = QHBoxLayout()
        top.setSpacing(8)
        title = QLabel(name)
        title.setStyleSheet("font-size: 14px; font-weight: 600;")
        title.setWordWrap(True)
        top.addWidget(title, stretch=1)

        lang_badge = QLabel(pm.LANGUAGE_NAMES.get(language, language))
        lang_badge.setObjectName("chip")
        lang_badge.setStyleSheet(
            f"background-color: {theme.accent}; color: {theme.accent_fg};"
            " border-radius: 10px; padding: 2px 10px; font-size: 11px;"
            " font-weight: 600;")
        top.addWidget(lang_badge, 0, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(top)

        # 介绍
        desc = QLabel(note or "（无备注）")
        desc.setObjectName("caption")
        desc.setWordWrap(True)
        layout.addWidget(desc)
        layout.addStretch(1)

    def mousePressEvent(self, event) -> None:  # noqa: N802  Qt 命名约定
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self.payload_id)
        super().mousePressEvent(event)


# ---------------------------------------------------------------------------
# 后台编译 / 运行线程
# ---------------------------------------------------------------------------
class _BuildWorker(QThread):
    """后台编译 / 运行线程。"""

    finished = Signal(str, dict)  # action, result

    def __init__(self, action: str, language: str, source: str,
                 tools: dict[str, str], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._action = action
        self._language = language
        self._source = source
        self._tools = tools

    def run(self) -> None:  # noqa: D102  线程体
        try:
            if self._action == "compile":
                result = pm.compile_source(
                    self._language, self._source, self._tools)
            else:
                result = pm.run_source(
                    self._language, self._source, self._tools)
        except Exception as exc:  # noqa: BLE001  线程内异常统一转信号
            result = {"ok": False, "returncode": -1,
                      "output": str(exc), "command": "", "artifact": ""}
        self.finished.emit(self._action, result)


# ---------------------------------------------------------------------------
# 日志弹窗
# ---------------------------------------------------------------------------
class _LogDialog(QDialog):
    """编译 / 运行日志的独立弹窗。"""

    def __init__(self, action: str, output: str, ok: bool,
                 artifact: str = "", command: str = "",
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"{action} 日志")
        self.resize(680, 460)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(10)

        status = QLabel("成功" if ok else "失败")
        status.setObjectName("status-ok" if ok else "status-err")
        status.setStyleSheet("font-size: 15px; font-weight: 600;")
        layout.addWidget(status)

        if command:
            cmd_label = QLabel(f"命令：{command}")
            cmd_label.setObjectName("caption")
            cmd_label.setWordWrap(True)
            cmd_label.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse)
            layout.addWidget(cmd_label)

        if artifact:
            art_label = QLabel(f"产物：{artifact}")
            art_label.setObjectName("caption")
            art_label.setWordWrap(True)
            art_label.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse)
            layout.addWidget(art_label)

        log = QPlainTextEdit()
        log.setObjectName("io")
        log.setReadOnly(True)
        log.setPlainText(output or "（无输出）")
        layout.addWidget(log, stretch=1)

        close_btn = QPushButton("关闭")
        close_btn.setObjectName("ghbtn-primary")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn, 0, Qt.AlignmentFlag.AlignRight)


# ---------------------------------------------------------------------------
# 页面
# ---------------------------------------------------------------------------
class PayloadManagerPage(QWidget):
    """Payload 编译器：卡片网格 + 语言分类 + 编辑器 + 弹窗日志。"""

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._db = pm.PayloadStore()
        self._worker: _BuildWorker | None = None
        self._current_id: int | None = None
        self._active_language: str = "java"
        self._build()

    # -------------------------------------------------------------- 主题
    def set_theme(self, palette) -> None:
        self.theme = palette

    # ------------------------------------------------------------------ UI
    def _build(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)

        # 顶部：语言分类 chips + 新建按钮
        top = QHBoxLayout()
        top.setSpacing(8)
        self._lang_buttons: dict[str, QPushButton] = {}
        for lang in pm.LANGUAGES:
            btn = QPushButton(pm.LANGUAGE_NAMES[lang])
            btn.setObjectName("chip")
            btn.setCheckable(True)
            btn.clicked.connect(
                lambda _c=False, l=lang: self._on_language(l))
            top.addWidget(btn)
            self._lang_buttons[lang] = btn
        top.addStretch(1)
        new_btn = QPushButton("新建 Payload")
        new_btn.setObjectName("ghbtn-primary")
        new_btn.clicked.connect(self._new_payload)
        top.addWidget(new_btn)
        layout.addLayout(top)

        # 主体：QStackedWidget 在「卡片网格」与「编辑器」间切换
        self.stack = QStackedWidget()
        self.stack.addWidget(self._build_grid_view())   # index 0
        self.stack.addWidget(self._build_editor_view())  # index 1
        layout.addWidget(self.stack, stretch=1)

        self._sync_lang_checks()
        self._reload_cards()

    # -- 网格视图 ----------------------------------------------------------
    def _build_grid_view(self) -> QWidget:
        host = QWidget()
        outer = QVBoxLayout(host)
        outer.setContentsMargins(0, 0, 0, 0)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        outer.addWidget(self.scroll)

        self.grid_container = QWidget()
        self.grid_layout = QVBoxLayout(self.grid_container)
        self.grid_layout.setContentsMargins(0, 0, 0, 0)
        self.grid_layout.setSpacing(16)
        self.scroll.setWidget(self.grid_container)
        return host

    def _build_editor_view(self) -> QWidget:
        host = QWidget()
        box = QVBoxLayout(host)
        box.setContentsMargins(0, 0, 0, 0)
        box.setSpacing(10)

        # 返回 + 标题
        head = QHBoxLayout()
        head.setSpacing(8)
        back_btn = QPushButton("← 返回")
        back_btn.setObjectName("ghbtn")
        back_btn.clicked.connect(self._back_to_grid)
        head.addWidget(back_btn)
        self.editor_title = QLabel("新建 Payload")
        self.editor_title.setObjectName("title")
        head.addWidget(self.editor_title)
        head.addStretch(1)
        box.addLayout(head)

        # 名称 + 语言 + 备注
        meta = QHBoxLayout()
        meta.setSpacing(8)
        meta.addWidget(QLabel("名称"))
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("payload 名称，如 ReverseShell")
        meta.addWidget(self.name_edit, stretch=1)
        meta.addWidget(QLabel("语言"))
        self.lang_combo = QComboBox()
        for lang in pm.LANGUAGES:
            self.lang_combo.addItem(pm.LANGUAGE_NAMES[lang], lang)
        meta.addWidget(self.lang_combo)
        box.addLayout(meta)

        note_row = QHBoxLayout()
        note_row.setSpacing(8)
        note_row.addWidget(QLabel("备注"))
        self.note_edit = QLineEdit()
        self.note_edit.setPlaceholderText("介绍这个 payload 的作用")
        note_row.addWidget(self.note_edit, stretch=1)
        box.addLayout(note_row)

        # 代码框（带行号）
        code_label = QLabel("代码")
        code_label.setObjectName("section")
        box.addWidget(code_label)
        self.code_edit = LineNumberEditor()
        self.code_edit.setObjectName("io")
        self.code_edit.setPlaceholderText("在此粘贴 payload 源码…")
        self.code_edit.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        box.addWidget(self.code_edit, stretch=1)

        # 操作按钮
        actions = QHBoxLayout()
        actions.setSpacing(8)
        self.save_btn = QPushButton("保存")
        self.save_btn.setObjectName("ghbtn-primary")
        self.save_btn.clicked.connect(self._save)
        self.compile_btn = QPushButton("编译")
        self.compile_btn.setObjectName("ghbtn")
        self.compile_btn.clicked.connect(lambda: self._do_build("compile"))
        self.run_btn = QPushButton("运行")
        self.run_btn.setObjectName("ghbtn")
        self.run_btn.clicked.connect(lambda: self._do_build("run"))
        self.delete_btn = QPushButton("删除")
        self.delete_btn.setObjectName("ghbtn-danger")
        self.delete_btn.clicked.connect(self._delete_payload)
        actions.addWidget(self.save_btn)
        actions.addWidget(self.compile_btn)
        actions.addWidget(self.run_btn)
        actions.addWidget(self.delete_btn)
        actions.addStretch(1)
        box.addLayout(actions)

        self.status_label = QLabel("")
        self.status_label.setObjectName("status-info")
        self.status_label.setWordWrap(True)
        box.addWidget(self.status_label)
        return host

    # ------------------------------------------------------------- 语言分类
    def _sync_lang_checks(self) -> None:
        for lang, btn in self._lang_buttons.items():
            btn.setChecked(lang == self._active_language)

    def _on_language(self, language: str) -> None:
        self._active_language = language
        self._sync_lang_checks()
        self._reload_cards()

    # ------------------------------------------------------------- 卡片
    @staticmethod
    def _clear_layout(layout) -> None:
        """递归清空布局并真正销毁其中的控件与子布局。"""
        while layout.count():
            item = layout.takeAt(0)
            if item is None:
                break
            widget = item.widget()
            child_layout = item.layout()
            if widget is not None:
                widget.setParent(None)
                widget.deleteLater()
            elif child_layout is not None:
                PayloadManagerPage._clear_layout(child_layout)

    def _reload_cards(self) -> None:
        # 彻底清理旧卡片，避免切换语言时残留
        self._clear_layout(self.grid_layout)

        records = self._db.list_payloads(self._active_language)
        if not records:
            empty = QLabel("该语言下暂无 payload，点击右上角「新建 Payload」开始。")
            empty.setObjectName("caption")
            empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.grid_layout.addWidget(empty)
            self.grid_layout.addStretch(1)
            return

        grid = QGridLayout()
        grid.setSpacing(12)
        columns = 3
        for i, rec in enumerate(records):
            card = _PayloadCard(rec.id, rec.name, rec.language, rec.note,
                                self.theme)
            card.clicked.connect(self._open_payload)
            grid.addWidget(card, i // columns, i % columns)
        for col in range(columns):
            grid.setColumnStretch(col, 1)
        self.grid_layout.addLayout(grid)
        self.grid_layout.addStretch(1)

    def _open_payload(self, payload_id: int) -> None:
        rec = self._db.get_payload(payload_id)
        if rec is None:
            return
        self._current_id = rec.id
        self.name_edit.setText(rec.name)
        self.note_edit.setText(rec.note)
        index = self.lang_combo.findData(rec.language)
        if index >= 0:
            self.lang_combo.setCurrentIndex(index)
        self.code_edit.setPlainText(rec.code)
        self.editor_title.setText(rec.name)
        self.status_label.setText("")
        self.stack.setCurrentIndex(1)

    # ------------------------------------------------------------- 操作
    def _new_payload(self) -> None:
        self._current_id = None
        self.name_edit.setText("Untitled")
        self.note_edit.clear()
        index = self.lang_combo.findData(self._active_language)
        if index >= 0:
            self.lang_combo.setCurrentIndex(index)
        self.code_edit.clear()
        self.editor_title.setText("新建 Payload")
        self.status_label.setText("")
        self.stack.setCurrentIndex(1)
        self.name_edit.setFocus()

    def _back_to_grid(self) -> None:
        self.stack.setCurrentIndex(0)
        self._reload_cards()

    def _save(self) -> None:
        name = self.name_edit.text().strip() or "Untitled"
        language = self.lang_combo.currentData()
        code = self.code_edit.toPlainText()
        note = self.note_edit.text().strip()
        self._current_id = self._db.upsert_payload(
            name, language, code, note, self._current_id)
        self.editor_title.setText(name)
        self._set_status(True, f"已保存：{name}")

    def _delete_payload(self) -> None:
        if self._current_id is None:
            return
        self._db.delete_payload(self._current_id)
        self._current_id = None
        self._back_to_grid()

    def _current_tools(self) -> dict[str, str]:
        """从 store 的 payload_compiler 配置节取当前语言的解释器路径。"""
        cfg = self.store.get("payload_compiler", default={}) or {}
        by_lang = pm.tools_from_config(cfg)
        return by_lang.get(self.lang_combo.currentData(), {})

    def _do_build(self, action: str) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._set_status(False, "上一个任务仍在执行，请稍候。")
            return
        language = self.lang_combo.currentData()
        source = self.code_edit.toPlainText()
        if not source.strip():
            self._set_status(False, "代码为空，请先填写 payload 源码。")
            return
        tools = self._current_tools()
        self.compile_btn.setEnabled(False)
        self.run_btn.setEnabled(False)
        verb = "编译" if action == "compile" else "运行"
        self._set_status(True, f"正在{verb}…")

        worker = _BuildWorker(action, language, source, tools, self)
        worker.finished.connect(self._on_build_done)
        self._worker = worker
        worker.start()

    def _on_build_done(self, action: str, result: dict) -> None:
        self.compile_btn.setEnabled(True)
        self.run_btn.setEnabled(True)
        ok = bool(result.get("ok"))
        output = result.get("output", "")
        artifact = result.get("artifact", "")
        command = result.get("command", "")

        # 落一条历史
        self._db.add_history(
            self._current_id, self.lang_combo.currentData(), action,
            ok, output, artifact, command)

        if ok:
            verb = "编译" if action == "compile" else "运行"
            self._set_status(True, f"{verb}成功。")
        else:
            self._set_status(False, f"{'编译' if action == 'compile' else '运行'}失败。")

        # 独立弹窗显示日志
        dialog = _LogDialog("编译" if action == "compile" else "运行",
                            output, ok, artifact, command, self)
        dialog.exec()

    def _set_status(self, ok: bool, text: str) -> None:
        self.status_label.setText(text)
        self.status_label.setObjectName(
            "status-ok" if ok else "status-err")
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)

    # ------------------------------------------------------------- 生命周期
    def shutdown(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._worker.wait(2000)
        self._db.close()
