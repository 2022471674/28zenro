# -*- coding: utf-8 -*-
"""文件与 Hex 互转页。

两个子标签覆盖文件 ↔ 十六进制的完整互转，纯逻辑全部委托
``lib.file_hex_codec``（渲染 / 解析 / 文件流式读写），本页不含算法代码：

- **文件转 Hex**：选择文件 → 可设分隔符 / 前缀 / 大小写 / 每行字节数，
  一键转换为十六进制文本。输出区为**三栏可编辑的 hex 编辑器视图**
  （地址偏移量 | 十六进制数据区 | ASCII 预览区），可直接在 Hex 或 ASCII
  栏编辑数据，另一栏实时联动；支持把编辑后的数据导出为二进制文件。
- **Hex 转文件**：粘贴或导入十六进制文本 → 还原为二进制文件并保存。
  分隔符可自动识别或自定义。

大文件走流式读写（``write_hex_file`` / ``hex_file_to_file``），
内存占用与文件大小无关；界面预览截取前 256 KiB 渲染。
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QThread, QTimer, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)
from PySide6.QtGui import QFont, QTextCursor

from app.widgets.no_wheel import NoWheelSpinBox
from lib import file_hex_codec
from lib.file_hex_codec import FileHexError

#: 预览上限（超过此字节数只渲染前 N 字节，避免界面卡顿）
PREVIEW_LIMIT = file_hex_codec.PREVIEW_BYTES

#: hex 编辑器视图每行字节数（固定 16，经典 hex dump 格式）
BYTES_PER_LINE = 16

#: 文件过滤器
ALL_FILTER = "所有文件 (*)"
HEX_TEXT_FILTER = "十六进制文本 (*.hex *.txt);;所有文件 (*)"

#: 同步防抖延迟（毫秒）
SYNC_DELAY_MS = 300


# ---------------------------------------------------------------------------
# hex 编辑器风格的三栏 dump 格式化（地址 | hex | ASCII）
# ---------------------------------------------------------------------------
def format_hex_dump(data: bytes,
                    uppercase: bool = True) -> str:
    """把字节数据渲染为 hex 编辑器风格的三栏文本。

    每行格式::

        00000000  48 65 6C 6C 6F 20 57 6F  72 6C 64 21 0A 00 00 00  Hello World!.....

    - 第一栏：8 位十六进制地址偏移量
    - 第二栏：每行 16 字节的十六进制数据，中间 8 字节处加额外空格
    - 第三栏：ASCII 预览，不可打印字符用 ``.`` 代替
    """
    if not data:
        return ""
    addr_width = 8
    hex_digits = "0123456789ABCDEF" if uppercase else "0123456789abcdef"
    lines: list[str] = []
    for start in range(0, len(data), BYTES_PER_LINE):
        chunk = data[start:start + BYTES_PER_LINE]
        addr = f"{start:0{addr_width}X}"
        hex_parts: list[str] = []
        for i in range(BYTES_PER_LINE):
            if i < len(chunk):
                b = chunk[i]
                hex_parts.append(hex_digits[b >> 4] + hex_digits[b & 0xF])
            else:
                hex_parts.append("  ")
            if i == 7:
                hex_parts.append(" ")
        hex_col = " ".join(hex_parts)
        ascii_parts: list[str] = []
        for b in chunk:
            ascii_parts.append(chr(b) if 0x20 <= b < 0x7F else ".")
        ascii_col = "".join(ascii_parts)
        lines.append(f"{addr}  {hex_col}  {ascii_col}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 各栏的单独格式化
# ---------------------------------------------------------------------------
def _format_addr_column(data_len: int, width: int = 8) -> str:
    """生成地址偏移量列文本。"""
    if data_len == 0:
        return ""
    last = ((data_len - 1) // BYTES_PER_LINE) * BYTES_PER_LINE
    lines = [f"{i:0{width}X}" for i in range(0, data_len, BYTES_PER_LINE)]
    if last not in range(0, data_len, BYTES_PER_LINE):
        lines.append(f"{last:0{width}X}")
    return "\n".join(lines)


def _format_hex_column(data: bytes, uppercase: bool = True) -> str:
    """生成十六进制数据列文本（空格分隔，每行 16 字节，中间分组）。"""
    if not data:
        return ""
    hex_digits = "0123456789ABCDEF" if uppercase else "0123456789abcdef"
    lines: list[str] = []
    for start in range(0, len(data), BYTES_PER_LINE):
        chunk = data[start:start + BYTES_PER_LINE]
        parts: list[str] = []
        for i in range(BYTES_PER_LINE):
            if i < len(chunk):
                b = chunk[i]
                parts.append(hex_digits[b >> 4] + hex_digits[b & 0xF])
            else:
                parts.append("  ")
            if i == 7:
                parts.append(" ")
        lines.append(" ".join(parts))
    return "\n".join(lines)


def _format_ascii_column(data: bytes) -> str:
    """生成 ASCII 预览列文本（不可打印字符用 ``.`` 代替）。"""
    if not data:
        return ""
    lines: list[str] = []
    for start in range(0, len(data), BYTES_PER_LINE):
        chunk = data[start:start + BYTES_PER_LINE]
        parts = [chr(b) if 0x20 <= b < 0x7F else "." for b in chunk]
        lines.append("".join(parts))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 后台工作线程
# ---------------------------------------------------------------------------
class _HexWorker(QThread):
    """后台执行一次性文件 ↔ Hex 转换，结果经信号返回主线程。"""

    done_ok = Signal(str)
    done_err = Signal(str)

    def __init__(self, fn, parent=None) -> None:
        super().__init__(parent)
        self._fn = fn

    def run(self) -> None:  # noqa: D102
        try:
            result = self._fn()
        except Exception as exc:  # noqa: BLE001
            self.done_err.emit(str(exc))
        else:
            self.done_ok.emit(str(result))


# ---------------------------------------------------------------------------
# 辅助：状态标签
# ---------------------------------------------------------------------------
def _make_status_label() -> QLabel:
    label = QLabel("")
    label.setObjectName("status-info")
    label.setWordWrap(True)
    return label


def _set_status(label: QLabel, ok: bool | None, text: str) -> None:
    """``None`` 灰色中性、``True`` 绿色成功、``False`` 红色失败。"""
    label.setObjectName(
        "status-info" if ok is None else ("status-ok" if ok else "status-err"))
    label.setText(text)
    label.style().unpolish(label)
    label.style().polish(label)


def _make_mono_font(theme) -> QFont:
    """构造等宽字体，保证三栏对齐。"""
    family = (theme.font_mono_family
              if hasattr(theme, "font_mono_family") else "Consolas")
    font = QFont(family)
    font.setStyleHint(QFont.StyleHint.Monospace)
    return font


# ---------------------------------------------------------------------------
# 三栏可编辑的 hex 编辑器视图
# ---------------------------------------------------------------------------
class _HexEditorView(QWidget):
    """三栏可编辑的 hex 编辑器视图：地址偏移量 | 十六进制数据 | ASCII 预览。

    - **地址偏移量栏**：只读，自动按 16 字节/行生成偏移地址。
    - **十六进制数据栏**：可编辑，用户可直接修改 hex 值；停止输入后
      自动解析并同步到 ASCII 栏与地址栏。
    - **ASCII 预览栏**：可编辑，用户可直接修改文本；停止输入后自动
      转换为字节并同步到 Hex 栏与地址栏。

    三栏共享垂直滚动条（任一栏滚动时其余两栏同步），且均不换行
    （``NoWrap``），保证行对齐。

    同步使用 ``QTimer`` 防抖（300 ms），避免逐键解析导致的光标跳动
    与性能问题。解析失败（hex 非法）时跳过本次同步，等用户修正后
    下次自动重试。
    """

    #: 数据被用户编辑后发出（供持有方启用「导出」按钮等）
    data_edited = Signal()

    def __init__(self, theme, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self._data = b""               # 源数据（字节）
        self._uppercase = True         # hex 大小写
        self._syncing = False          # 同步中标志，防止反馈环
        self._last_edited = None       # "hex" / "ascii" / None
        self._build()
        self._sync_timer = QTimer(self)
        self._sync_timer.setSingleShot(True)
        self._sync_timer.setInterval(SYNC_DELAY_MS)
        self._sync_timer.timeout.connect(self._do_sync)

    # ------------------------------------------------------------------ UI
    def _build(self) -> None:
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)

        mono = _make_mono_font(self.theme)

        # ---- 栏 1：地址偏移量（只读） ----
        self.addr_edit = QPlainTextEdit()
        self.addr_edit.setObjectName("io")
        self.addr_edit.setReadOnly(True)
        self.addr_edit.setFixedWidth(150)
        self.addr_edit.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.addr_edit.setFont(mono)
        self.addr_edit.setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.addr_edit.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        # ---- 栏 2：十六进制数据（可编辑） ----
        self.hex_edit = QPlainTextEdit()
        self.hex_edit.setObjectName("io")
        self.hex_edit.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.hex_edit.setFont(mono)
        self.hex_edit.setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.hex_edit.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.hex_edit.setPlaceholderText(
            "选择文件并点「转换为 Hex」后在此显示…\n"
            "可直接编辑 hex 值，ASCII 栏自动联动。")

        # ---- 栏 3：ASCII 预览（可编辑） ----
        self.ascii_edit = QPlainTextEdit()
        self.ascii_edit.setObjectName("io")
        self.ascii_edit.setFixedWidth(280)
        self.ascii_edit.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.ascii_edit.setFont(mono)
        self.ascii_edit.setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.ascii_edit.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.ascii_edit.setPlaceholderText(
            "ASCII 预览…\n可直接编辑，hex 栏自动联动。")

        layout.addWidget(self.addr_edit)
        layout.addWidget(self.hex_edit, stretch=1)
        layout.addWidget(self.ascii_edit)

        # ---- 信号 ----
        self.hex_edit.textChanged.connect(self._on_hex_changed)
        self.ascii_edit.textChanged.connect(self._on_ascii_changed)

        # 滚动同步：以 ASCII 栏（有滚动条的那栏）为主，其余跟随
        self._scroll_source = None
        for edit in (self.addr_edit, self.hex_edit, self.ascii_edit):
            edit.verticalScrollBar().valueChanged.connect(
                lambda v, src=edit: self._on_scroll(src, v))

    # ------------------------------------------------------------------ 数据
    def set_data(self, data: bytes, uppercase: bool = True) -> None:
        """设置数据并刷新三栏（外部载入文件时调用）。"""
        self._syncing = True
        self._data = bytes(data)
        self._uppercase = uppercase
        self._render_all()
        self._syncing = False
        self._last_edited = None

    def get_data(self) -> bytes:
        """获取当前编辑后的字节（从 hex 栏解析）。"""
        if self._last_edited == "ascii":
            return self._ascii_to_bytes()
        return self._hex_to_bytes()

    def get_hex_text(self, separator: str = "", prefix: str = "",
                     uppercase: bool = True,
                     bytes_per_line: int = 0) -> str:
        """把当前数据渲染为纯十六进制文本（供复制 / 导出）。"""
        return file_hex_codec.bytes_to_hex(
            self.get_data(), separator=separator, prefix=prefix,
            uppercase=uppercase, bytes_per_line=bytes_per_line)

    def clear(self) -> None:
        """清空三栏。"""
        self._syncing = True
        self._data = b""
        self.addr_edit.clear()
        self.hex_edit.clear()
        self.ascii_edit.clear()
        self._syncing = False
        self._last_edited = None

    def is_empty(self) -> bool:
        return not self.hex_edit.toPlainText().strip()

    # ------------------------------------------------------------------ 渲染
    def _render_all(self) -> None:
        """根据 ``self._data`` 刷新三栏文本。"""
        self.addr_edit.setPlainText(_format_addr_column(len(self._data)))
        self.hex_edit.setPlainText(
            _format_hex_column(self._data, self._uppercase))
        self.ascii_edit.setPlainText(_format_ascii_column(self._data))

    def _render_addr(self) -> None:
        """只刷新地址栏。"""
        self.addr_edit.setPlainText(_format_addr_column(len(self._data)))

    # ------------------------------------------------------------------ 同步
    def _on_hex_changed(self) -> None:
        if self._syncing:
            return
        self._last_edited = "hex"
        self._sync_timer.start()

    def _on_ascii_changed(self) -> None:
        if self._syncing:
            return
        self._last_edited = "ascii"
        self._sync_timer.start()

    def _do_sync(self) -> None:
        """防抖定时器触发：把最后编辑的栏解析为字节，刷新其余两栏。"""
        if self._last_edited is None or self._syncing:
            return
        if self._last_edited == "hex":
            data = self._hex_to_bytes()
            if data is None:
                return  # 解析失败（用户还在输入中间态），跳过
            self._data = data
            # 刷新 ASCII + 地址栏（不动 hex 栏本身，保留用户光标）
            self._syncing = True
            self.ascii_edit.setPlainText(_format_ascii_column(data))
            self._render_addr()
            self._syncing = False
        elif self._last_edited == "ascii":
            data = self._ascii_to_bytes()
            if data is None:
                return
            self._data = data
            self._syncing = True
            self.hex_edit.setPlainText(
                _format_hex_column(data, self._uppercase))
            self._render_addr()
            self._syncing = False
        self.data_edited.emit()

    def _hex_to_bytes(self) -> bytes | None:
        """从 hex 栏文本解析为字节；失败返回 ``None``（不抛异常）。"""
        text = self.hex_edit.toPlainText()
        if not text.strip():
            return b""
        try:
            return file_hex_codec.hex_to_bytes(text, separator=None)
        except FileHexError:
            return None

    def _ascii_to_bytes(self) -> bytes | None:
        """从 ASCII 栏文本转换为字节（latin-1 编码，每字符 1 字节）。

        空行被忽略，换行不产生字节；不可打印的 ``.`` 还原为 ``0x2E``。
        """
        text = self.ascii_edit.toPlainText()
        if not text:
            return b""
        lines = text.split("\n")
        result = bytearray()
        for line in lines:
            result.extend(line.encode("latin-1", errors="replace"))
        return bytes(result)

    # ------------------------------------------------------------------ 滚动
    def _on_scroll(self, source: QPlainTextEdit, value: int) -> None:
        """同步三栏的垂直滚动位置。"""
        if self._syncing:
            return
        self._syncing = True
        for edit in (self.addr_edit, self.hex_edit, self.ascii_edit):
            if edit is not source:
                bar = edit.verticalScrollBar()
                bar.setValue(value)
        self._syncing = False


# ---------------------------------------------------------------------------
# 主页面
# ---------------------------------------------------------------------------
class FileHexPage(QWidget):
    """文件与 Hex 互转页。"""

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._worker: _HexWorker | None = None
        self._build()

    # ------------------------------------------------------------------ UI
    def _build(self) -> None:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)

        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(12)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_file_to_hex_tab(), "文件转 Hex")
        self.tabs.addTab(self._build_hex_to_file_tab(), "Hex 转文件")
        layout.addWidget(self.tabs, stretch=1)

        scroll.setWidget(inner)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

    # ---- Tab 1: 文件转 Hex ------------------------------------------------
    def _build_file_to_hex_tab(self) -> QWidget:
        tab = QWidget()
        form = QFormLayout(tab)
        form.setContentsMargins(8, 14, 8, 8)
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(10)

        # 文件选择
        self.f_path = QLineEdit()
        self.f_path.setPlaceholderText("选择要转换的文件…")
        form.addRow("文件", self._with_browse(self.f_path, self._pick_file))

        # 分隔符
        self.f_sep = QLineEdit()
        self.f_sep.setPlaceholderText("留空=无分隔符；支持 \\n \\t 等")
        form.addRow("分隔符", self.f_sep)

        # 前缀
        self.f_prefix = QLineEdit()
        self.f_prefix.setPlaceholderText("每字节前缀，如 0x / \\x / %（可选）")
        form.addRow("前缀", self.f_prefix)

        # 大小写 + 每行字节数
        self.f_upper = QCheckBox("十六进制字母大写")
        self.f_upper.setChecked(True)
        self.f_bpl = NoWheelSpinBox()
        self.f_bpl.setRange(0, 256)
        self.f_bpl.setValue(BYTES_PER_LINE)
        self.f_bpl.setSuffix(" 字节/行（0=不分组）")
        opts = QHBoxLayout()
        opts.setSpacing(12)
        opts.addWidget(self.f_upper)
        opts.addWidget(self.f_bpl)
        opts.addStretch(1)
        form.addRow("格式", opts)

        # 操作按钮
        self.f_convert_btn = QPushButton("转换为 Hex")
        self.f_convert_btn.setObjectName("ghbtn-primary")
        self.f_convert_btn.clicked.connect(self._run_convert)
        self.f_export_btn = QPushButton("导出 Hex 文本文件")
        self.f_export_btn.setObjectName("ghbtn")
        self.f_export_btn.clicked.connect(self._run_export)
        self.f_save_btn = QPushButton("导出编辑数据为文件…")
        self.f_save_btn.setObjectName("ghbtn")
        self.f_save_btn.setEnabled(False)
        self.f_save_btn.clicked.connect(self._save_edited)
        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        btn_row.addWidget(self.f_convert_btn)
        btn_row.addWidget(self.f_export_btn)
        btn_row.addWidget(self.f_save_btn)
        btn_row.addStretch(1)
        form.addRow("", btn_row)

        # 三栏可编辑 hex 编辑器视图
        header_row = QHBoxLayout()
        header_row.setContentsMargins(0, 0, 0, 0)
        header_row.setSpacing(2)
        h_addr = QLabel("地址偏移量")
        h_addr.setObjectName("caption")
        h_addr.setFixedWidth(150)
        h_hex = QLabel("十六进制数据区（可编辑）")
        h_hex.setObjectName("caption")
        h_ascii = QLabel("ASCII 预览（可编辑）")
        h_ascii.setObjectName("caption")
        h_ascii.setFixedWidth(280)
        header_row.addWidget(h_addr)
        header_row.addWidget(h_hex, stretch=1)
        header_row.addWidget(h_ascii)
        form.addRow("", header_row)

        self.f_editor = _HexEditorView(self.theme)
        self.f_editor.setMinimumHeight(300)
        self.f_editor.data_edited.connect(
            lambda: self.f_save_btn.setEnabled(not self.f_editor.is_empty()))
        form.addRow("", self.f_editor)

        # 复制 / 清空
        copy_btn = QPushButton("复制 Hex 文本")
        copy_btn.setObjectName("ghbtn")
        copy_btn.clicked.connect(self._copy_output)
        clear_btn = QPushButton("清空")
        clear_btn.setObjectName("ghbtn")
        clear_btn.clicked.connect(self._clear_output)
        bottom = QHBoxLayout()
        bottom.setSpacing(8)
        bottom.addWidget(copy_btn)
        bottom.addWidget(clear_btn)
        bottom.addStretch(1)
        form.addRow("", bottom)

        self.f_status = _make_status_label()
        form.addRow("", self.f_status)

        return tab

    # ---- Tab 2: Hex 转文件 ------------------------------------------------
    def _build_hex_to_file_tab(self) -> QWidget:
        tab = QWidget()
        form = QFormLayout(tab)
        form.setContentsMargins(8, 14, 8, 8)
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(10)

        self.h_sep = QLineEdit()
        self.h_sep.setPlaceholderText("留空=自动识别（空格/冒号/逗号/换行等）")
        form.addRow("分隔符", self.h_sep)

        self.h_input = QPlainTextEdit()
        self.h_input.setObjectName("io")
        self.h_input.setPlaceholderText(
            "在此粘贴十六进制文本…\n"
            "支持自动识别分隔符（空格、冒号、短横线、逗号、换行等）；\n"
            "也可在上方指定自定义分隔符。")
        self.h_input.setMinimumHeight(160)
        form.addRow("Hex 输入", self.h_input)

        self.h_import_btn = QPushButton("从 Hex 文件导入…")
        self.h_import_btn.setObjectName("ghbtn")
        self.h_import_btn.clicked.connect(self._import_hex_file)
        import_row = QHBoxLayout()
        import_row.setSpacing(8)
        import_row.addWidget(self.h_import_btn)
        import_row.addStretch(1)
        form.addRow("", import_row)

        self.h_convert_btn = QPushButton("转为文件并保存…")
        self.h_convert_btn.setObjectName("ghbtn-primary")
        self.h_convert_btn.clicked.connect(self._run_hex_to_file)
        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        btn_row.addWidget(self.h_convert_btn)
        btn_row.addStretch(1)
        form.addRow("", btn_row)

        self.h_status = _make_status_label()
        form.addRow("", self.h_status)

        return tab

    # -------------------------------------------------------------- 控件工具
    def _with_browse(self, edit: QLineEdit, picker) -> QWidget:
        box = QWidget()
        row = QHBoxLayout(box)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(6)
        row.addWidget(edit, stretch=1)
        btn = QPushButton("浏览…")
        btn.setObjectName("ghbtn")
        btn.clicked.connect(lambda: picker())
        row.addWidget(btn)
        return box

    def _pick_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "选择文件", "", ALL_FILTER)
        if path:
            self.f_path.setText(path)
            _set_status(self.f_status, None, "")

    def _import_hex_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "选择十六进制文本文件", "", HEX_TEXT_FILTER)
        if not path:
            return
        try:
            text = Path(path).read_text(encoding="utf-8-sig")
        except OSError as exc:
            _set_status(self.h_status, False, f"读取文件失败：{exc}")
            return
        self.h_input.setPlainText(text)
        _set_status(self.h_status, True, f"已导入：{path}")

    # -------------------------------------------------------------- Tab 1 逻辑
    def _collect_params(self) -> dict:
        return {
            "separator": self.f_sep.text(),
            "prefix": self.f_prefix.text(),
            "uppercase": self.f_upper.isChecked(),
            "bytes_per_line": self.f_bpl.value(),
        }

    def _run_convert(self) -> None:
        """读取文件并填充三栏可编辑 hex 编辑器视图。"""
        path = self.f_path.text().strip()
        if not path:
            _set_status(self.f_status, False, "请先选择文件。")
            return
        src = Path(path)
        if not src.is_file():
            _set_status(self.f_status, False, f"文件不存在：{path}")
            return

        uppercase = self.f_upper.isChecked()
        try:
            with open(src, "rb") as fh:
                preview_data = fh.read(PREVIEW_LIMIT)
            size = src.stat().st_size
            truncated = size > len(preview_data)
        except OSError as exc:
            _set_status(self.f_status, False, str(exc))
            return

        self.f_editor.set_data(preview_data, uppercase=uppercase)
        if truncated:
            _set_status(self.f_status, True,
                        f"文件共 {size:,} 字节，已载入前 "
                        f"{len(preview_data):,} 字节到编辑器。"
                        "完整导出请用「导出 Hex 文本文件」。")
        else:
            _set_status(self.f_status, True,
                        f"文件大小 {size:,} 字节，已载入编辑器，可直接编辑。")
        self.f_save_btn.setEnabled(True)

    def _run_export(self) -> None:
        """把文件流式转成 hex 文本文件（``write_hex_file``）。"""
        path = self.f_path.text().strip()
        if not path:
            _set_status(self.f_status, False, "请先选择文件。")
            return
        if not Path(path).is_file():
            _set_status(self.f_status, False, f"文件不存在：{path}")
            return

        out_path, _ = QFileDialog.getSaveFileName(
            self, "导出 Hex 文本文件",
            str(Path(path).with_suffix(".hex")),
            HEX_TEXT_FILTER)
        if not out_path:
            return

        params = self._collect_params()
        _set_status(self.f_status, True, "正在导出…")

        def work() -> str:
            out, total, chars = file_hex_codec.write_hex_file(
                path, out_path, **params)
            return (f"已导出：{out}\n"
                    f"输入 {total:,} 字节 → 输出 {chars:,} 字符")

        self._start_worker(work, lambda msg: _set_status(
            self.f_status, True, msg), self.f_status, "正在导出…")

    def _save_edited(self) -> None:
        """把编辑器中编辑后的数据导出为二进制文件。"""
        if self.f_editor.is_empty():
            _set_status(self.f_status, False, "编辑器为空，没有可导出的数据。")
            return
        data = self.f_editor.get_data()
        if data is None:
            _set_status(self.f_status, False,
                        "十六进制数据格式不正确，无法导出。")
            return

        out_path, _ = QFileDialog.getSaveFileName(
            self, "保存编辑后的文件", "", ALL_FILTER)
        if not out_path:
            return
        try:
            Path(out_path).write_bytes(data)
        except OSError as exc:
            _set_status(self.f_status, False, f"保存失败：{exc}")
            return
        _set_status(self.f_status, True,
                    f"已保存 {len(data):,} 字节到：{out_path}")

    def _copy_output(self) -> None:
        """把编辑器中的纯十六进制文本复制到剪贴板。"""
        if self.f_editor.is_empty():
            _set_status(self.f_status, False, "编辑器为空。")
            return
        params = self._collect_params()
        text = self.f_editor.get_hex_text(**params)
        if not text:
            _set_status(self.f_status, False, "数据格式不正确。")
            return
        from PySide6.QtWidgets import QApplication
        QApplication.clipboard().setText(text)
        _set_status(self.f_status, True, "已复制纯十六进制文本到剪贴板。")

    def _clear_output(self) -> None:
        self.f_editor.clear()
        self.f_save_btn.setEnabled(False)
        _set_status(self.f_status, None, "")

    # -------------------------------------------------------------- Tab 2 逻辑
    def _run_hex_to_file(self) -> None:
        """把十六进制文本还原为文件并保存。"""
        text = self.h_input.toPlainText()
        if not text.strip():
            _set_status(self.h_status, False, "请先输入十六进制文本。")
            return

        out_path, _ = QFileDialog.getSaveFileName(
            self, "保存文件", "", ALL_FILTER)
        if not out_path:
            return

        separator = self.h_sep.text().strip() or None
        _set_status(self.h_status, True, "正在转换…")

        def work() -> str:
            out, count = file_hex_codec.hex_to_file(text, out_path,
                                                     separator=separator)
            return f"已保存：{out}（{count:,} 字节）"

        self._start_worker(work, lambda msg: _set_status(
            self.h_status, True, msg), self.h_status, "正在转换…")

    # -------------------------------------------------------------- 线程管理
    def _start_worker(self, fn, on_ok, err_label: QLabel,
                      busy_text: str) -> None:
        if self._worker is not None and self._worker.isRunning():
            _set_status(err_label, False, "上一个任务还在处理中，请稍候。")
            return
        _set_status(err_label, True, busy_text)
        self._worker = _HexWorker(fn, self)
        self._worker.done_ok.connect(on_ok)
        self._worker.done_err.connect(
            lambda msg: _set_status(err_label, False, msg))
        self._worker.start()

    def shutdown(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._worker.wait(2000)
