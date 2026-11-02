# -*- coding: utf-8 -*-
"""压缩包工具页（移植自 Hx0 战队 ZipCracker）。

三个子标签：
- 伪加密修复：识别 ZIP 通用标志位被置 1 的「伪加密」包，一键清除标志位生成
  修复副本；真加密包会明确提示需要密码而不是硬改。
- CRC32 碰撞：对未加密的小文件（≤6 字节），用条目记录的 CRC32 反撞明文，
  无需密码。可自动扫描包内小文件，也可手动指定 CRC 与长度。
- 字典爆破：内置常用字典 + 0~N 位纯数字字典，也可选自定义字典（如项目自带
  ``dict/rockyou.txt.gz``）。后台线程跑，可随时停止；命中后可直接解密提取。

输出位置统一走「设置 → 压缩包工具」（默认应用根目录下 ``output`` 文件夹）。
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QThread, QTimer, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.widgets.no_wheel import NoWheelComboBox, NoWheelSpinBox
from lib import watermark, zip_cracker
from lib.zip_cracker import ZipCracker

ZIP_FILTER = "ZIP 压缩包 (*.zip);;所有文件 (*)"
DICT_FILTER = "字典文件 (*.txt *.dict *.gz);;所有文件 (*)"

#: 爆破进度轮询间隔（毫秒）
POLL_MS = 200


class _ZipWorker(QThread):
    """后台执行一个一次性任务（修复 / CRC 碰撞），结果经信号返回。"""

    done_ok = Signal(str)
    done_err = Signal(str)

    def __init__(self, fn, parent=None) -> None:
        super().__init__(parent)
        self._fn = fn

    def run(self) -> None:  # noqa: D102  线程体
        try:
            result = self._fn()
        except Exception as exc:  # noqa: BLE001  统一转信号给界面
            self.done_err.emit(str(exc))
        else:
            self.done_ok.emit(result)


class ZipCrackPage(QWidget):
    """压缩包工具页：伪加密修复 / CRC32 碰撞 / 字典爆破。"""

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._worker: _ZipWorker | None = None
        #: 字典爆破主控（后台线程 + 日志队列）
        self.cracker = ZipCracker()
        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(POLL_MS)
        self._poll_timer.timeout.connect(self._poll)
        self._build()

    # ------------------------------------------------------------------ UI
    def _build(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(10)

        self.outdir_label = QLabel("")
        self.outdir_label.setObjectName("caption")
        self.outdir_label.setWordWrap(True)
        layout.addWidget(self.outdir_label)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_fix_tab(), "伪加密修复")
        self.tabs.addTab(self._build_crc_tab(), "CRC32 碰撞")
        self.tabs.addTab(self._build_crack_tab(), "字典爆破")
        layout.addWidget(self.tabs, stretch=1)

    # ---- Tab 1：伪加密修复 -------------------------------------------------
    def _build_fix_tab(self) -> QWidget:
        tab = QWidget()
        form = QFormLayout(tab)
        form.setContentsMargins(8, 14, 8, 8)
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(10)

        self.f_zip = QLineEdit()
        self.f_zip.setPlaceholderText("选择要检测的 ZIP 压缩包…")
        form.addRow("压缩包", self._with_browse(
            self.f_zip, self._pick_zip, ZIP_FILTER))

        self.f_detect_btn = QPushButton("检测加密类型")
        self.f_detect_btn.setObjectName("ghbtn")
        self.f_detect_btn.clicked.connect(self._run_detect)
        row = QHBoxLayout()
        row.setSpacing(8)
        row.addWidget(self.f_detect_btn)
        row.addStretch(1)
        form.addRow("", row)

        self.f_result = QLabel("尚未检测。")
        self.f_result.setObjectName("caption")
        self.f_result.setWordWrap(True)
        form.addRow("检测结果", self.f_result)

        self.f_fix_btn = QPushButton("清除伪加密标志并另存")
        self.f_fix_btn.setObjectName("ghbtn-primary")
        self.f_fix_btn.clicked.connect(self._run_fix)
        row2 = QHBoxLayout()
        row2.setSpacing(8)
        row2.addWidget(self.f_fix_btn)
        row2.addStretch(1)
        form.addRow("", row2)

        self.f_status = QLabel("")
        self.f_status.setObjectName("status-info")
        self.f_status.setWordWrap(True)
        form.addRow("", self.f_status)
        return tab

    # ---- Tab 2：CRC32 碰撞 -------------------------------------------------
    def _build_crc_tab(self) -> QWidget:
        tab = QWidget()
        form = QFormLayout(tab)
        form.setContentsMargins(8, 14, 8, 8)
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(10)

        self.c_zip = QLineEdit()
        self.c_zip.setPlaceholderText("选择含小文件的 ZIP 压缩包…")
        form.addRow("压缩包", self._with_browse(
            self.c_zip, self._pick_zip, ZIP_FILTER))

        self.c_scan_btn = QPushButton("扫描小文件候选")
        self.c_scan_btn.setObjectName("ghbtn")
        self.c_scan_btn.clicked.connect(self._run_scan)
        row = QHBoxLayout()
        row.setSpacing(8)
        row.addWidget(self.c_scan_btn)
        row.addStretch(1)
        form.addRow("", row)

        self.c_candidates = QLabel("尚未扫描。")
        self.c_candidates.setObjectName("caption")
        self.c_candidates.setWordWrap(True)
        form.addRow("小文件候选", self.c_candidates)

        # 手动指定 CRC 与长度
        self.c_crc = QLineEdit()
        self.c_crc.setPlaceholderText("条目记录的 CRC32（十六进制或十进制）")
        self.c_size = NoWheelSpinBox()
        self.c_size.setRange(1, zip_cracker.CRC_SMALL_FILE_MAX)
        self.c_size.setValue(4)
        manual = QHBoxLayout()
        manual.setSpacing(8)
        manual.addWidget(self.c_crc, stretch=1)
        manual.addWidget(QLabel("长度"))
        manual.addWidget(self.c_size)
        form.addRow("手动 CRC", manual)

        self.c_alpha = NoWheelComboBox()
        for key, label in zip_cracker.ALPHABET_PRESETS:
            self.c_alpha.addItem(label, key)
        default_alpha = (self.store.get("zip_crack", "alphabet", default="lower")
                         or "lower")
        idx = self.c_alpha.findData(default_alpha)
        self.c_alpha.setCurrentIndex(idx if idx >= 0 else 1)
        form.addRow("字符集", self.c_alpha)

        self.c_run_btn = QPushButton("开始碰撞")
        self.c_run_btn.setObjectName("ghbtn-primary")
        self.c_run_btn.clicked.connect(self._run_crc)
        row2 = QHBoxLayout()
        row2.setSpacing(8)
        row2.addWidget(self.c_run_btn)
        row2.addStretch(1)
        form.addRow("", row2)

        self.c_output = QTextEdit()
        self.c_output.setReadOnly(True)
        self.c_output.setObjectName("mono")
        self.c_output.setPlaceholderText("碰撞结果会显示在这里…")
        form.addRow("明文", self.c_output)

        self.c_status = QLabel("")
        self.c_status.setObjectName("status-info")
        self.c_status.setWordWrap(True)
        form.addRow("", self.c_status)

        copy_btn = QPushButton("复制明文")
        copy_btn.setObjectName("ghbtn")
        copy_btn.clicked.connect(
            lambda: self._copy_to_clipboard(self.c_output.toPlainText()))
        row3 = QHBoxLayout()
        row3.setSpacing(8)
        row3.addWidget(copy_btn)
        row3.addStretch(1)
        form.addRow("", row3)
        return tab

    # ---- Tab 3：字典爆破 ---------------------------------------------------
    def _build_crack_tab(self) -> QWidget:
        tab = QWidget()
        form = QFormLayout(tab)
        form.setContentsMargins(8, 14, 8, 8)
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(10)

        self.k_zip = QLineEdit()
        self.k_zip.setPlaceholderText("选择真加密的 ZIP 压缩包…")
        form.addRow("压缩包", self._with_browse(
            self.k_zip, self._pick_zip, ZIP_FILTER))

        cfg = self.store.get("zip_crack", default={}) or {}
        self.k_builtin = QCheckBox("叠加内置常用密码字典（6009 条）")
        self.k_builtin.setChecked(bool(cfg.get("use_builtin_dict", True)))
        form.addRow("", self.k_builtin)

        self.k_numeric = NoWheelSpinBox()
        self.k_numeric.setRange(0, zip_cracker.MAX_NUMERIC_LEN)
        self.k_numeric.setValue(int(cfg.get("max_numeric_len", 6) or 6))
        self.k_numeric.setSuffix(" 位（0=不叠加）")
        form.addRow("纯数字字典", self.k_numeric)

        self.k_dict = QLineEdit()
        self.k_dict.setPlaceholderText("可选：自定义字典文件（留空则只用内置/数字）")
        form.addRow("自定义字典", self._with_browse(
            self.k_dict, self._pick_dict, DICT_FILTER))

        self.k_start_btn = QPushButton("开始爆破")
        self.k_start_btn.setObjectName("ghbtn-primary")
        self.k_start_btn.clicked.connect(self._start_crack)
        self.k_stop_btn = QPushButton("停止")
        self.k_stop_btn.setObjectName("ghbtn")
        self.k_stop_btn.setEnabled(False)
        self.k_stop_btn.clicked.connect(self._stop_crack)
        row = QHBoxLayout()
        row.setSpacing(8)
        row.addWidget(self.k_start_btn)
        row.addWidget(self.k_stop_btn)
        row.addStretch(1)
        form.addRow("", row)

        # QPlainTextEdit 而非 QTextEdit：流式爆破日志需要 maximumBlockCount
        # 环形上限（QTextEdit 没有该 API），大字典爆破不会无限吃内存
        self.k_log = QPlainTextEdit()
        self.k_log.setReadOnly(True)
        self.k_log.setObjectName("mono")
        self.k_log.setMaximumBlockCount(2000)
        self.k_log.setPlaceholderText("爆破日志会显示在这里…")
        form.addRow("日志", self.k_log)

        self.k_status = QLabel("")
        self.k_status.setObjectName("status-info")
        self.k_status.setWordWrap(True)
        form.addRow("", self.k_status)

        self.k_extract_btn = QPushButton("用命中密码解密提取")
        self.k_extract_btn.setObjectName("ghbtn")
        self.k_extract_btn.setEnabled(False)
        self.k_extract_btn.clicked.connect(self._run_extract)
        row2 = QHBoxLayout()
        row2.setSpacing(8)
        row2.addWidget(self.k_extract_btn)
        row2.addStretch(1)
        form.addRow("", row2)
        return tab

    # -------------------------------------------------------------- 控件工具
    def _with_browse(self, edit: QLineEdit, picker, file_filter: str) -> QWidget:
        """输入框 + 浏览按钮的组合控件。"""
        box = QWidget()
        row = QHBoxLayout(box)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(6)
        row.addWidget(edit, stretch=1)
        btn = QPushButton("浏览…")
        btn.setObjectName("ghbtn")
        btn.clicked.connect(lambda: picker(edit, file_filter))
        row.addWidget(btn)
        return box

    def _pick_zip(self, edit: QLineEdit, file_filter: str) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "选择压缩包", "", file_filter)
        if path:
            edit.setText(path)
            self._set_status(self.f_status, True, "")

    def _pick_dict(self, edit: QLineEdit, file_filter: str) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "选择字典文件", "", file_filter)
        if path:
            edit.setText(path)

    def _output_dir(self) -> Path:
        cfg = self.store.get("zip_crack", default={}) or {}
        return watermark.resolve_output_dir(cfg.get("output_dir"))

    def _set_status(self, label: QLabel, ok: bool, text: str) -> None:
        label.setObjectName("status-ok" if ok else "status-err")
        label.setStyleSheet("")  # 触发 objectName 重新应用样式
        label.setText(text)

    def _append(self, area: QPlainTextEdit, line: str) -> None:
        area.appendPlainText(line)
        bar = area.verticalScrollBar()
        bar.setValue(bar.maximum())

    def _copy_to_clipboard(self, text: str) -> None:
        if text.strip():
            from PySide6.QtWidgets import QApplication
            QApplication.clipboard().setText(text.strip())
            self._set_status(self.c_status, True, "已复制到剪贴板。")

    def _busy(self) -> bool:
        return self._worker is not None and self._worker.isRunning()

    def _start_worker(self, fn, on_ok, err_label: QLabel, busy_text: str) -> None:
        """启动后台一次性任务；``on_ok`` 为成功回调（接收结果字符串）。"""
        if self._busy() or self.cracker.running:
            self._set_status(err_label, False, "上一个任务还在处理中，请稍候。")
            return
        self._set_status(err_label, True, busy_text)
        self._worker = _ZipWorker(fn, self)
        self._worker.done_ok.connect(on_ok)
        self._worker.done_err.connect(
            lambda msg: self._set_status(err_label, False, msg))
        self._worker.start()

    # -------------------------------------------------------------- Tab 1
    def _run_detect(self) -> None:
        path = self.f_zip.text().strip()
        if not path:
            self._set_status(self.f_status, False, "请先选择压缩包。")
            return
        try:
            zip_cracker.check_zip_path(path)
        except zip_cracker.ZipCrackerError as exc:
            self._set_status(self.f_status, False, str(exc))
            return

        def work() -> str:
            entries = zip_cracker.list_entries(path)
            encrypted = any(e["encrypted"] for e in entries)
            if not encrypted:
                return "未加密：可以直接解压，无需修复或爆破。"
            if zip_cracker.is_fake_encrypted(path):
                return "伪加密：仅标志位被置 1，数据并未真正加密。可一键修复。"
            return "真加密：数据确实被加密，需要密码才能解压（可尝试「字典爆破」）。"

        self._start_worker(work, lambda text: self._on_detected(text),
                            self.f_status, "正在检测…")

    def _on_detected(self, text: str) -> None:
        self.f_result.setText(text)
        ok = "伪加密" in text
        self._set_status(self.f_status, ok, "检测完成。")

    def _run_fix(self) -> None:
        path = self.f_zip.text().strip()
        if not path:
            self._set_status(self.f_status, False, "请先选择压缩包。")
            return
        # 修复副本落到应用输出目录，重名自动改名
        try:
            out_name = watermark.unique_path(
                self._output_dir() / f"{Path(path).stem}_fixed.zip")
        except OSError as exc:
            self._set_status(self.f_status, False, f"输出目录不可用：{exc}")
            return

        def work() -> str:
            target = zip_cracker.fix_fake_encrypted(path, out_path=str(out_name))
            return f"已生成修复副本：{target}"

        self._start_worker(work, lambda text: self._set_status(
            self.f_status, True, text), self.f_status, "正在修复…")

    # -------------------------------------------------------------- Tab 2
    def _run_scan(self) -> None:
        path = self.c_zip.text().strip()
        if not path:
            self._set_status(self.c_status, False, "请先选择压缩包。")
            return
        try:
            cands = zip_cracker.small_crc_candidates(path)
        except zip_cracker.ZipCrackerError as exc:
            self._set_status(self.c_status, False, str(exc))
            return
        if not cands:
            self.c_candidates.setText("没有适合 CRC32 碰撞的条目"
                                     "（需要未加密、且大小 ≤ 6 字节的文件）。")
            return
        lines = []
        for e in cands:
            lines.append(f"{e['name']}  大小 {e['size']} 字节  "
                         f"CRC 0x{e['crc']:08x}")
        self.c_candidates.setText("\n".join(lines))
        self._set_status(self.c_status, True, f"找到 {len(cands)} 个小文件候选。")

    def _run_crc(self) -> None:
        raw_crc = self.c_crc.text().strip()
        if not raw_crc:
            self._set_status(self.c_status, False, "请填写 CRC32 值。")
            return
        crc = self._parse_crc(raw_crc)
        if crc is None:
            self._set_status(self.c_status, False,
                             "CRC32 值格式不正确（支持十进制或 0x 十六进制）。")
            return
        size = self.c_size.value()
        alpha_key = self.c_alpha.currentData()

        self.c_output.clear()

        def work() -> str:
            got = zip_cracker.crc32_crack(crc, size, alphabet=alpha_key)
            return got if got is not None else ""

        self._start_worker(work, lambda text: self._on_crc_done(text),
                            self.c_status, "正在碰撞…")

    @staticmethod
    def _parse_crc(text: str) -> int | None:
        """解析 CRC32 值：支持十进制或 ``0x`` 十六进制；非法返回 ``None``。"""
        try:
            if text.lower().startswith("0x"):
                return int(text, 16) & 0xFFFFFFFF
            return int(text) & 0xFFFFFFFF
        except ValueError:
            return None

    def _on_crc_done(self, text: str) -> None:
        if text:
            self.c_output.setPlainText(text)
            self._set_status(self.c_status, True, "碰撞成功，已还原明文。")
        else:
            self._set_status(self.c_status, False,
                             "穷举完毕未命中，请换更贴近的字符集或确认长度。")

    # -------------------------------------------------------------- Tab 3
    def _start_crack(self) -> None:
        path = self.k_zip.text().strip()
        if not path:
            self._set_status(self.k_status, False, "请先选择压缩包。")
            return
        dict_path = self.k_dict.text().strip() or None
        use_builtin = self.k_builtin.isChecked()
        numeric_len = self.k_numeric.value()
        if not dict_path and not use_builtin and numeric_len == 0:
            self._set_status(self.k_status, False,
                             "请至少选择一种爆破来源（内置字典 / 纯数字 / 自定义字典）。")
            return
        try:
            self.cracker.start(path, dict_path=dict_path,
                               use_builtin=use_builtin,
                               max_numeric_len=numeric_len)
        except zip_cracker.ZipCrackerError as exc:
            self._set_status(self.k_status, False, str(exc))
            return
        self.k_log.clear()
        self.k_extract_btn.setEnabled(False)
        self.k_start_btn.setEnabled(False)
        self.k_stop_btn.setEnabled(True)
        self._set_status(self.k_status, True, "爆破中…")
        self._poll_timer.start()

    def _stop_crack(self) -> None:
        self.cracker.stop()

    def _drain_logs(self) -> None:
        for kind, *payload in self.cracker.poll_logs():
            if kind == "info":
                self._append(self.k_log, payload[0])
            elif kind == "progress":
                self._append(self.k_log, f"…已尝试 {payload[0]} 个，"
                                         f"时速 {payload[1]} 个/秒")
            elif kind == "found":
                self._set_status(self.k_status, True,
                                 f"命中密码：{payload[0]}")
                self.k_extract_btn.setEnabled(True)
            elif kind == "done":
                self._append(self.k_log, payload[0])

    def _poll(self) -> None:
        self._drain_logs()
        if self.cracker.running:
            return
        self._poll_timer.stop()
        self.k_stop_btn.setEnabled(False)
        self.k_start_btn.setEnabled(True)
        if self.cracker.status == zip_cracker.STATUS_FOUND:
            self._set_status(self.k_status, True,
                             f"命中密码：{self.cracker.result}")
            self.k_extract_btn.setEnabled(True)
        elif self.cracker.status == zip_cracker.STATUS_STOPPED:
            self._set_status(self.k_status, False, "已停止爆破。")
        elif self.cracker.status == zip_cracker.STATUS_ERROR:
            self._set_status(self.k_status, False,
                             f"爆破失败：{self.cracker.error}")
        else:
            self._set_status(self.k_status, False,
                             "字典已穷举完毕，未命中密码。")

    def _run_extract(self) -> None:
        path = self.k_zip.text().strip()
        password = self.cracker.result
        if not path or not password:
            self._set_status(self.k_status, False, "没有可用的密码，请先爆破。")
            return

        def work() -> str:
            out_dir = watermark.unique_path(
                self._output_dir() / f"{Path(path).stem}_extracted")
            got = zip_cracker.extract(path, out_dir=str(out_dir),
                                      password=password)
            return f"已解密提取 {len(got)} 个文件到：{out_dir}"

        self._start_worker(work, lambda text: self._set_status(
            self.k_status, True, text), self.k_status, "正在解密提取…")

    # -------------------------------------------------------------- 生命周期
    def showEvent(self, event) -> None:  # noqa: N802  Qt 命名约定
        """每次显示时刷新输出目录提示（设置页改完切回来即可见）。"""
        super().showEvent(event)
        try:
            resolved = self._output_dir()
            self.outdir_label.setText(
                f"输出位置：{resolved}（可在「设置 → 压缩包工具」中修改）")
        except OSError as exc:
            self.outdir_label.setText(f"输出位置不可用：{exc}")

    def shutdown(self) -> None:
        """应用退出时调用：停止爆破，避免残留线程占用 CPU。"""
        self._poll_timer.stop()
        self.cracker.stop(wait=True, timeout=1.0)
        if self._worker is not None and self._worker.isRunning():
            self._worker.wait(1000)
