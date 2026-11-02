# -*- coding: utf-8 -*-
"""文本对比面板：两段文本左右对照，差异高亮 + 一致 / 不一致结论。

结构：
    - 输入区   文本A / 文本B 两个多行文本框（``#io`` 样式，与通用面板一致）；
    - 控制区   开始对比 / 交换 A·B / 清空 + 对比粒度（字符 / 单词 / 行）
               + 忽略大小写 / 忽略空白字符 两个口径开关；
    - 统计行   两侧字符数（caption）；
    - 结论行   「一致 / 不一致」结论（status-ok / status-err / status-info）；
    - 结果区   两侧对照的只读高亮视图：
               红 = 仅左侧有（删除）、绿 = 仅右侧有（新增）、黄 = 两侧都不同（替换）。

输入变化后 350ms 防抖自动对比，「开始对比」可立即执行。计算本身走
:mod:`lib.text_diff` 纯逻辑，本类只负责采集输入、渲染高亮与结论。
"""

from __future__ import annotations

from PySide6.QtCore import QTimer
from PySide6.QtGui import QColor, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (
    QCheckBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.widgets.no_wheel import NoWheelComboBox
from lib import text_diff

#: 粒度 -> 统计文案里的单元名（字符 / 单词 / 行）
UNIT_LABELS = {"char": "字符", "word": "单词", "line": "行"}

#: 高亮底色在调色板里的来源（与 pane 无关，两侧共用一张映射表）
_SEG_COLORS = {
    text_diff.SEG_LEFT: "danger",    # 删除：红
    text_diff.SEG_RIGHT: "success",  # 新增：绿
    text_diff.SEG_BOTH: "warning",   # 替换：黄
}


def _mix(base: str, over: str, ratio: float) -> QColor:
    """把 ``over`` 按 ``ratio`` 混进 ``base``，得到不刺眼的高亮底色。"""
    a, b = QColor(base), QColor(over)
    return QColor(
        round(a.red() + (b.red() - a.red()) * ratio),
        round(a.green() + (b.green() - a.green()) * ratio),
        round(a.blue() + (b.blue() - a.blue()) * ratio),
    )


class DiffPanel(QFrame):
    """文本对比面板（由「字符串工具 → 文本对比器」chips 挂载）。"""

    def __init__(self, theme, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.setObjectName("card")
        #: 最近一次成功对比的结果（换主题后据此重绘高亮）
        self._last: text_diff.DiffResult | None = None
        self._build()
        self._reset()

    # ------------------------------------------------------------------ UI
    def _build(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(8)

        # -- 输入区：文本A / 文本B --
        inputs = QHBoxLayout()
        inputs.setSpacing(12)
        inputs.addWidget(self._text_column(
            "文本A", "left_edit", "在此粘贴待对比的文本 A…", editable=True),
            stretch=1)
        inputs.addWidget(self._text_column(
            "文本B", "right_edit", "在此粘贴待对比的文本 B…", editable=True),
            stretch=1)
        layout.addLayout(inputs)

        # -- 控制区 --
        controls = QHBoxLayout()
        controls.setSpacing(8)

        run_btn = QPushButton("开始对比")
        run_btn.setObjectName("ghbtn-primary")
        run_btn.clicked.connect(self._run_now)
        controls.addWidget(run_btn)

        swap_btn = QPushButton("交换 A / B")
        swap_btn.setObjectName("ghbtn")
        swap_btn.setToolTip("左右两栏内容互换后重新对比")
        swap_btn.clicked.connect(self._swap)
        controls.addWidget(swap_btn)

        clear_btn = QPushButton("清空")
        clear_btn.setObjectName("ghbtn")
        clear_btn.clicked.connect(self.clear)
        controls.addWidget(clear_btn)

        controls.addSpacing(8)
        mode_label = QLabel("对比粒度")
        mode_label.setObjectName("section")
        controls.addWidget(mode_label)

        self.mode_box = NoWheelComboBox()
        for key, label in (
            ("char", "字符级"), ("word", "单词级"), ("line", "行级"),
        ):
            self.mode_box.addItem(label, key)
        self.mode_box.setToolTip("字符级逐字比对，行级按整行比对")
        controls.addWidget(self.mode_box)

        self.ignore_case = QCheckBox("忽略大小写")
        self.ignore_space = QCheckBox("忽略空白字符")
        controls.addSpacing(8)
        controls.addWidget(self.ignore_case)
        controls.addWidget(self.ignore_space)
        controls.addStretch(1)
        layout.addLayout(controls)

        # -- 统计行 --
        self.stats = QLabel("")
        self.stats.setObjectName("caption")
        layout.addWidget(self.stats)

        # -- 结论行 --
        self.conclusion = QLabel("")
        self.conclusion.setObjectName("status-info")
        self.conclusion.setWordWrap(True)
        layout.addWidget(self.conclusion)

        # -- 结果区：两侧对照高亮 --
        legend = QLabel("高亮：红 = 仅左侧有（删除）　绿 = 仅右侧有（新增）　"
                        "黄 = 两侧不同（替换）")
        legend.setObjectName("section")
        layout.addWidget(legend)

        outputs = QHBoxLayout()
        outputs.setSpacing(12)
        outputs.addWidget(self._text_column(
            "差异结果 · 文本A", "left_out",
            "点击「开始对比」后在此查看高亮差异…", editable=False), stretch=1)
        outputs.addWidget(self._text_column(
            "差异结果 · 文本B", "right_out",
            "点击「开始对比」后在此查看高亮差异…", editable=False), stretch=1)
        layout.addLayout(outputs)

        # -- 交互：输入变化防抖自动对比 --
        self._debounce = QTimer(self)
        self._debounce.setSingleShot(True)
        self._debounce.setInterval(350)
        self._debounce.timeout.connect(self._compare)
        for edit in (self.left_edit, self.right_edit):
            edit.textChanged.connect(self._on_text_changed)
        self.mode_box.currentIndexChanged.connect(self._schedule)
        for box in (self.ignore_case, self.ignore_space):
            box.toggled.connect(self._schedule)

    def _text_column(self, title: str, attr: str, placeholder: str,
                     editable: bool) -> QWidget:
        """一列：分区标题 + 文本框，结果挂在 ``self.<attr>`` 上。

        editable = True  输入框（``QPlainTextEdit``）；
        editable = False 只读高亮视图（``QTextEdit``）。
        """
        column = QWidget()
        box = QVBoxLayout(column)
        box.setContentsMargins(0, 0, 0, 0)
        box.setSpacing(6)

        label = QLabel(title)
        label.setObjectName("section")
        box.addWidget(label)

        if editable:
            edit: QPlainTextEdit | QTextEdit = QPlainTextEdit()
            edit.setPlaceholderText(placeholder)
            edit.setMinimumHeight(110)
        else:
            edit = QTextEdit()
            edit.setReadOnly(True)
            edit.setPlaceholderText(placeholder)
            edit.setMinimumHeight(110)
        edit.setObjectName("io")
        setattr(self, attr, edit)
        box.addWidget(edit, stretch=1)
        return column

    # ------------------------------------------------------------- 主题切换
    def set_theme(self, theme) -> None:
        """换主题：更新调色板并按新配色重绘最近一次的高亮。"""
        self.theme = theme
        if self._last is not None:
            self._render(self._last)

    # ------------------------------------------------------------- 交互入口
    def _on_text_changed(self) -> None:
        self._update_stats()
        self._schedule()

    def _schedule(self, *_args) -> None:
        self._debounce.start()

    def _run_now(self) -> None:
        self._debounce.stop()
        self._compare()

    def _swap(self) -> None:
        left, right = self.left_edit.toPlainText(), self.right_edit.toPlainText()
        self.left_edit.setPlainText(right)
        self.right_edit.setPlainText(left)
        self._run_now()

    def clear(self) -> None:
        """清空两侧输入、高亮结果与结论。"""
        self.left_edit.clear()
        self.right_edit.clear()
        self._reset()

    # ------------------------------------------------------------- 对比流程
    def _current_options(self) -> tuple[str, bool, bool]:
        return (
            str(self.mode_box.currentData()),
            self.ignore_case.isChecked(),
            self.ignore_space.isChecked(),
        )

    def _update_stats(self) -> None:
        left, right = self.left_edit.toPlainText(), self.right_edit.toPlainText()
        self.stats.setText(f"文本A {len(left)} 个字符　·　文本B {len(right)} 个字符")

    def _reset(self) -> None:
        self._last = None
        self.left_out.clear()
        self.right_out.clear()
        self._set_status(None, "就绪：在上方分别粘贴两段文本，"
                               "差异会自动高亮并给出一致 / 不一致结论。")
        self._update_stats()

    def _compare(self) -> None:
        left, right = self.left_edit.toPlainText(), self.right_edit.toPlainText()
        if not left.strip() and not right.strip():
            self._reset()
            return

        mode, ignore_case, ignore_space = self._current_options()
        try:
            result = text_diff.compare(
                left, right, mode,
                ignore_case=ignore_case, ignore_space=ignore_space,
            )
        except text_diff.DiffError as exc:
            self._last = None
            self._set_status(False, str(exc))
            return
        except Exception as exc:  # noqa: BLE001  界面兜底：任何异常不崩窗
            self._last = None
            self._set_status(False, f"对比失败：{exc}")
            return
        self._last = result
        self._render(result)

    # ------------------------------------------------------------- 渲染
    def _render(self, result: text_diff.DiffResult) -> None:
        _, ignore_case, ignore_space = self._current_options()
        note = self._option_note(ignore_case, ignore_space)
        unit = UNIT_LABELS.get(result.mode, "字符")
        self._update_stats()

        if result.equal:
            self._set_status(
                True,
                f"一致：两段文本完全相同（共 {result.left_length} 个字符），"
                f"未发现任何差异{note}。",
            )
        else:
            self._set_status(
                False,
                f"不一致：共 {result.blocks} 处差异"
                f"（删除 {result.removed} 个{unit}、新增 {result.added} 个{unit}、"
                f"替换 {result.replaced} 处），相似度 {result.similarity:.1f}%{note}。",
            )

        colors = {
            kind: _mix(self.theme.surface, getattr(self.theme, token), 0.32)
            for kind, token in _SEG_COLORS.items()
        }
        self._render_pane(self.left_out, result.left, colors)
        self._render_pane(self.right_out, result.right, colors)

    @staticmethod
    def _option_note(ignore_case: bool, ignore_space: bool) -> str:
        options = []
        if ignore_case:
            options.append("忽略大小写")
        if ignore_space:
            options.append("忽略空白字符")
        return f"（口径：{'、'.join(options)}）" if options else ""

    @staticmethod
    def _render_pane(pane: QTextEdit, segments, colors: dict) -> None:
        """把分段序列写进只读视图：差异段上底色，一致段保持原样。"""
        pane.clear()
        cursor = pane.textCursor()
        cursor.beginEditBlock()
        for segment in segments:
            if not segment.text:
                continue
            fmt = QTextCharFormat()
            color = colors.get(segment.kind)
            if color is not None:
                fmt.setBackground(color)
            cursor.setCharFormat(fmt)
            cursor.insertText(segment.text)
        cursor.endEditBlock()
        pane.moveCursor(QTextCursor.MoveOperation.Start)

    def _set_status(self, ok: bool | None, text: str) -> None:
        """状态行渲染：``None`` 灰色中性、``True`` 绿色一致、``False`` 红色不一致。"""
        label = self.conclusion
        label.setObjectName(
            "status-info" if ok is None else ("status-ok" if ok else "status-err"))
        label.setText(text)
        label.style().unpolish(label)
        label.style().polish(label)
