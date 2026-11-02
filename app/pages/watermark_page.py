# -*- coding: utf-8 -*-
"""图片工具页（``Visible_Mark_Create.py`` / ``source_mark_create.py`` 整合迁移）。

六个子标签：
- 添加可见水印：载体图片 + 水印文字 + 位置 / 字号 / RGBA 颜色 / 字体，叠加输出；
- 隐写嵌入：把秘密信息写入图片 LSB 通道（输出强制 PNG，JPEG 压缩会破坏数据）；
- 提取水印文字：从隐写图片读回水印 / 秘密信息，可同时保存到输出目录；
- 图片转 Base64：图片文件编码为 Base64 文本（可选 Data URI 前缀），
  可复制或保存为 .txt；
- Base64 转图片：把 Base64 文本（支持 Data URI 前缀 / 折行）解码还原为图片，
  扩展名按实际类型自动补全，保存到输出目录；
- OCR 文字识别：调用「设置 → 模型服务」里配置的 OCR 模型（OpenAI 兼容
  多模态接口）识别图片文字，可复制或保存为 .txt。

输出位置统一走「设置 → 图片工具」（默认应用根目录下 ``output`` 文件夹），
本页顶部实时显示当前解析后的目录；图像处理放后台线程执行，不阻塞界面。
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.widgets.no_wheel import NoWheelComboBox, NoWheelSpinBox
from lib import image_codec, llm_codec, lsb, watermark

IMAGE_FILTER = "图片文件 (*.png *.jpg *.jpeg *.bmp *.gif *.webp);;所有文件 (*)"
FONT_FILTER = "字体文件 (*.ttf *.otf *.ttc);;所有文件 (*)"


class _WatermarkWorker(QThread):
    """后台执行一个水印任务，结果经信号返回（成功带路径 / 文本，失败带原因）。"""

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


class WatermarkPage(QWidget):
    """图片工具页：可见水印 / LSB 隐写 / 提取水印 / 图片转 Base64 / Base64 转图片 / OCR 文字识别。"""

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._worker: _WatermarkWorker | None = None
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
        self.tabs.addTab(self._build_visible_tab(), "添加可见水印")
        self.tabs.addTab(self._build_embed_tab(), "隐写嵌入")
        self.tabs.addTab(self._build_extract_tab(), "提取水印文字")
        self.tabs.addTab(self._build_base64_tab(), "图片转 Base64")
        self.tabs.addTab(self._build_decode_tab(), "Base64 转图片")
        self.tabs.addTab(self._build_ocr_tab(), "OCR 文字识别")
        layout.addWidget(self.tabs, stretch=1)

    # ---- Tab 1：添加可见水印 ---------------------------------------------
    def _build_visible_tab(self) -> QWidget:
        tab = QWidget()
        form = QFormLayout(tab)
        form.setContentsMargins(8, 14, 8, 8)
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(10)

        self.v_carrier = QLineEdit()
        self.v_carrier.setPlaceholderText("选择要添加水印的载体图片…")
        form.addRow("载体图片", self._with_browse(
            self.v_carrier, self._pick_carrier, IMAGE_FILTER))

        self.v_text = QLineEdit()
        self.v_text.setPlaceholderText("要显示在图片上的水印文字")
        form.addRow("水印文字", self.v_text)

        self.v_pos = NoWheelComboBox()
        for key in watermark.POSITIONS:
            self.v_pos.addItem(f"{watermark.POSITION_NAMES[key]}（{key}）", key)
        self.v_pos.setCurrentIndex(watermark.POSITIONS.index("bottom-right"))
        form.addRow("位置", self.v_pos)

        self.v_size = NoWheelSpinBox()
        self.v_size.setRange(8, 300)
        self.v_size.setValue(30)
        self.v_size.setSuffix(" px")
        form.addRow("字号", self.v_size)

        self.v_color = QLineEdit("255,255,255,128")
        self.v_color.setPlaceholderText("R,G,B,A（0-255，末位为透明度）")
        form.addRow("颜色 RGBA", self.v_color)

        self.v_font = QLineEdit()
        self.v_font.setPlaceholderText("可选：ttf / otf 字体文件，留空用内置默认字体")
        form.addRow("字体文件", self._with_browse(
            self.v_font, self._pick_font, FONT_FILTER))

        self.v_outname = QLineEdit()
        self.v_outname.setPlaceholderText("留空自动生成，如 photo_wm.png")
        form.addRow("输出文件名", self.v_outname)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        run_btn = QPushButton("生成水印")
        run_btn.setObjectName("ghbtn-primary")
        run_btn.clicked.connect(self._run_visible)
        buttons.addWidget(run_btn)
        buttons.addStretch(1)
        form.addRow("", buttons)

        self.v_status = QLabel("")
        self.v_status.setObjectName("status-info")
        self.v_status.setWordWrap(True)
        form.addRow("", self.v_status)
        return tab

    # ---- Tab 2：LSB 隐写嵌入（全参数） -----------------------------------
    def _build_embed_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(8, 14, 8, 8)
        layout.setSpacing(10)

        form = QFormLayout()
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(10)

        self.e_carrier = QLineEdit()
        self.e_carrier.setPlaceholderText("选择载体图片（建议纯色 / 无损的 PNG）")
        self.e_carrier.textChanged.connect(self._refresh_embed_capacity)
        form.addRow("载体图片", self._with_browse(
            self.e_carrier, self._pick_carrier, IMAGE_FILTER))

        # 嵌入位置参数（通道 / 位平面 / 偏移 / 顺序 / 封装）
        self.e_channels = NoWheelComboBox()
        for key in lsb.CHANNEL_PRESETS:
            self.e_channels.addItem(lsb.CHANNEL_NAMES.get(key, key), key)
        form.addRow("通道", self.e_channels)

        self.e_bit = NoWheelSpinBox()
        self.e_bit.setRange(0, 7)
        self.e_bit.setValue(0)
        form.addRow("位平面", self.e_bit)

        self.e_offset = NoWheelSpinBox()
        self.e_offset.setRange(0, 10_000_000)
        self.e_offset.setValue(0)
        form.addRow("起始偏移", self.e_offset)

        self.e_order = NoWheelComboBox()
        for key in lsb.ORDERS:
            self.e_order.addItem(lsb.ORDER_NAMES.get(key, key), key)
        form.addRow("扫描顺序", self.e_order)

        self.e_framing = NoWheelComboBox()
        for key in lsb.FRAMINGS:
            self.e_framing.addItem(lsb.FRAMING_NAMES.get(key, key), key)
        self.e_framing.setCurrentIndex(lsb.FRAMINGS.index("length"))
        form.addRow("载荷封装", self.e_framing)

        self.e_capacity = QLabel("")
        self.e_capacity.setObjectName("caption")
        self.e_capacity.setWordWrap(True)
        form.addRow("容量", self.e_capacity)

        self.e_outname = QLineEdit()
        self.e_outname.setPlaceholderText("留空自动生成，强制输出 PNG")
        form.addRow("输出文件名", self.e_outname)
        layout.addLayout(form)

        layout.addWidget(QLabel("秘密信息"))
        self.e_secret = QTextEdit()
        self.e_secret.setObjectName("io")
        self.e_secret.setPlaceholderText("直接填写文本；也可填写文件路径（执行时读取文件内容）")
        layout.addWidget(self.e_secret, stretch=1)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        embed_btn = QPushButton("嵌入信息")
        embed_btn.setObjectName("ghbtn-primary")
        embed_btn.clicked.connect(self._run_embed)
        buttons.addWidget(embed_btn)
        buttons.addStretch(1)
        layout.addLayout(buttons)

        self.e_status = QLabel("提示：JPEG 压缩会破坏 LSB 数据，输出已强制为 PNG。")
        self.e_status.setObjectName("status-info")
        self.e_status.setWordWrap(True)
        layout.addWidget(self.e_status)
        return tab

    # ---- Tab 3：LSB 提取 / 参数自动探测 ----------------------------------
    def _build_extract_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(8, 14, 8, 8)
        layout.setSpacing(10)

        form = QFormLayout()
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(10)

        self.x_stego = QLineEdit()
        self.x_stego.setPlaceholderText("选择含隐写数据的图片…")
        form.addRow("隐写图片", self._with_browse(
            self.x_stego, self._pick_carrier, IMAGE_FILTER))

        # 提取参数（与嵌入对应；封装含 auto 自动判断）
        self.x_channels = NoWheelComboBox()
        for key in lsb.CHANNEL_PRESETS:
            self.x_channels.addItem(lsb.CHANNEL_NAMES.get(key, key), key)
        form.addRow("通道", self.x_channels)

        self.x_bit = NoWheelSpinBox()
        self.x_bit.setRange(0, 7)
        self.x_bit.setValue(0)
        form.addRow("位平面", self.x_bit)

        self.x_offset = NoWheelSpinBox()
        self.x_offset.setRange(0, 10_000_000)
        self.x_offset.setValue(0)
        form.addRow("起始偏移", self.x_offset)

        self.x_order = NoWheelComboBox()
        for key in lsb.ORDERS:
            self.x_order.addItem(lsb.ORDER_NAMES.get(key, key), key)
        form.addRow("扫描顺序", self.x_order)

        self.x_framing = NoWheelComboBox()
        self.x_framing.addItem("自动判断（marker / length）", "auto")
        for key in lsb.FRAMINGS:
            self.x_framing.addItem(lsb.FRAMING_NAMES.get(key, key), key)
        form.addRow("载荷封装", self.x_framing)

        self.x_save = QCheckBox("提取后同时保存到输出目录")
        self.x_save.setChecked(True)
        form.addRow("", self.x_save)

        self.x_outname = QLineEdit()
        self.x_outname.setPlaceholderText("留空自动生成，如 photo_extracted.txt")
        form.addRow("保存文件名", self.x_outname)
        layout.addLayout(form)

        layout.addWidget(QLabel("提取结果"))
        self.x_result = QTextEdit()
        self.x_result.setObjectName("io")
        self.x_result.setReadOnly(True)
        layout.addWidget(self.x_result, stretch=1)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        extract_btn = QPushButton("按当前参数提取")
        extract_btn.setObjectName("ghbtn-primary")
        extract_btn.clicked.connect(self._run_extract)
        detect_btn = QPushButton("自动探测参数")
        detect_btn.setObjectName("ghbtn")
        detect_btn.clicked.connect(self._run_detect)
        buttons.addWidget(extract_btn)
        buttons.addWidget(detect_btn)
        buttons.addStretch(1)
        layout.addLayout(buttons)

        self.x_status = QLabel("")
        self.x_status.setObjectName("status-info")
        self.x_status.setWordWrap(True)
        layout.addWidget(self.x_status)
        return tab

    # ---- Tab 4：图片转 Base64 ---------------------------------------------
    def _build_base64_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(8, 14, 8, 8)
        layout.setSpacing(10)

        form = QFormLayout()
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(10)

        self.b_image = QLineEdit()
        self.b_image.setPlaceholderText("选择要编码的图片文件…")
        form.addRow("图片文件", self._with_browse(
            self.b_image, self._pick_carrier, IMAGE_FILTER))

        self.b_data_uri = QCheckBox("输出 Data URI 格式（带 data:image/...;base64, 前缀）")
        self.b_data_uri.setChecked(True)
        form.addRow("", self.b_data_uri)
        layout.addLayout(form)

        layout.addWidget(QLabel("Base64 结果"))
        self.b_result = QTextEdit()
        self.b_result.setObjectName("io")
        self.b_result.setReadOnly(True)
        self.b_result.setPlaceholderText("点击「生成 Base64」后在此显示结果…")
        layout.addWidget(self.b_result, stretch=1)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        gen_btn = QPushButton("生成 Base64")
        gen_btn.setObjectName("ghbtn-primary")
        gen_btn.clicked.connect(self._run_base64)
        copy_btn = QPushButton("复制结果")
        copy_btn.setObjectName("ghbtn")
        copy_btn.clicked.connect(self._copy_base64)
        save_btn = QPushButton("保存到输出目录")
        save_btn.setObjectName("ghbtn")
        save_btn.clicked.connect(self._save_base64)
        buttons.addWidget(gen_btn)
        buttons.addWidget(copy_btn)
        buttons.addWidget(save_btn)
        buttons.addStretch(1)
        layout.addLayout(buttons)

        self.b_status = QLabel("")
        self.b_status.setObjectName("status-info")
        self.b_status.setWordWrap(True)
        layout.addWidget(self.b_status)
        return tab

    # ---- Tab 5：Base64 转图片 ---------------------------------------------
    def _build_decode_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(8, 14, 8, 8)
        layout.setSpacing(10)

        form = QFormLayout()
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(10)
        self.d_outname = QLineEdit()
        self.d_outname.setPlaceholderText("留空自动生成，扩展名按图片类型自动补全")
        form.addRow("输出文件名", self.d_outname)
        layout.addLayout(form)

        layout.addWidget(QLabel("Base64 文本（支持 data:image/...;base64, 前缀与换行）"))
        self.d_input = QTextEdit()
        self.d_input.setObjectName("io")
        self.d_input.setPlaceholderText("在此粘贴 Base64 文本…")
        layout.addWidget(self.d_input, stretch=1)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        decode_btn = QPushButton("解码并保存图片")
        decode_btn.setObjectName("ghbtn-primary")
        decode_btn.clicked.connect(self._run_decode)
        load_btn = QPushButton("从文本文件读取…")
        load_btn.setObjectName("ghbtn")
        load_btn.clicked.connect(self._load_base64_file)
        paste_btn = QPushButton("粘贴剪贴板")
        paste_btn.setObjectName("ghbtn")
        paste_btn.clicked.connect(self._paste_base64)
        clear_btn = QPushButton("清空")
        clear_btn.setObjectName("ghbtn")
        clear_btn.clicked.connect(self.d_input.clear)
        buttons.addWidget(decode_btn)
        buttons.addWidget(load_btn)
        buttons.addWidget(paste_btn)
        buttons.addWidget(clear_btn)
        buttons.addStretch(1)
        layout.addLayout(buttons)

        self.d_status = QLabel("")
        self.d_status.setObjectName("status-info")
        self.d_status.setWordWrap(True)
        layout.addWidget(self.d_status)
        return tab

    # ---- Tab 6：OCR 图片文字识别 ------------------------------------------
    def _build_ocr_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(8, 14, 8, 8)
        layout.setSpacing(10)

        form = QFormLayout()
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(10)

        self.o_image = QLineEdit()
        self.o_image.setPlaceholderText("选择要识别文字的图片…")
        form.addRow("图片文件", self._with_browse(
            self.o_image, self._pick_carrier, IMAGE_FILTER))

        self.o_prompt = QLineEdit(llm_codec.DEFAULT_OCR_PROMPT)
        self.o_prompt.setPlaceholderText("识别指令，留空用内置默认值")
        form.addRow("识别指令", self.o_prompt)
        layout.addLayout(form)

        self.o_cfg_hint = QLabel("")
        self.o_cfg_hint.setObjectName("caption")
        self.o_cfg_hint.setWordWrap(True)
        layout.addWidget(self.o_cfg_hint)

        layout.addWidget(QLabel("识别结果"))
        self.o_result = QTextEdit()
        self.o_result.setObjectName("io")
        self.o_result.setReadOnly(True)
        self.o_result.setPlaceholderText("点击「识别文字」后在此显示结果…")
        layout.addWidget(self.o_result, stretch=1)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        ocr_btn = QPushButton("识别文字")
        ocr_btn.setObjectName("ghbtn-primary")
        ocr_btn.clicked.connect(self._run_ocr)
        copy_btn = QPushButton("复制结果")
        copy_btn.setObjectName("ghbtn")
        copy_btn.clicked.connect(self._copy_ocr)
        save_btn = QPushButton("保存到输出目录")
        save_btn.setObjectName("ghbtn")
        save_btn.clicked.connect(self._save_ocr)
        buttons.addWidget(ocr_btn)
        buttons.addWidget(copy_btn)
        buttons.addWidget(save_btn)
        buttons.addStretch(1)
        layout.addLayout(buttons)

        self.o_status = QLabel("")
        self.o_status.setObjectName("status-info")
        self.o_status.setWordWrap(True)
        layout.addWidget(self.o_status)
        return tab

    # -------------------------------------------------------------- 辅助
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

    def _pick_carrier(self, edit: QLineEdit, file_filter: str) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "选择图片", "", file_filter)
        if path:
            edit.setText(path)

    def _pick_font(self, edit: QLineEdit, file_filter: str) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "选择字体文件", "", file_filter)
        if path:
            edit.setText(path)

    def _output_dir(self) -> Path:
        cfg = self.store.get("watermark", default={}) or {}
        return watermark.resolve_output_dir(cfg.get("output_dir"))

    def _named_out(self, name: str, default_name: str) -> Path:
        """把文件名落到输出目录（补扩展名 + 重名自动改名）。"""
        text = (name or "").strip() or default_name
        if not Path(text).suffix:
            text += ".png"
        return watermark.unique_path(self._output_dir() / text)

    def _auto_name(self, carrier: str, suffix: str, default_ext: str) -> str:
        stem = Path(carrier.strip()).stem or "output"
        ext = Path(carrier.strip()).suffix or default_ext
        return f"{stem}{suffix}{ext}"

    def _set_status(self, label: QLabel, ok: bool, text: str) -> None:
        label.setObjectName("status-ok" if ok else "status-err")
        label.setStyleSheet("")  # 触发 objectName 重新应用样式
        label.setText(text)

    def _busy(self) -> bool:
        if self._worker is not None and self._worker.isRunning():
            return True
        return False

    def _start(self, fn, on_ok, err_label: QLabel, busy_text: str) -> None:
        """启动后台任务；``on_ok`` 为成功回调（接收结果字符串）。"""
        if self._busy():
            self._set_status(err_label, False, "上一个任务还在处理中，请稍候。")
            return
        self._set_status(err_label, True, busy_text)
        self._worker = _WatermarkWorker(fn, self)
        self._worker.done_ok.connect(on_ok)
        self._worker.done_err.connect(
            lambda msg: self._set_status(err_label, False, msg))
        self._worker.start()

    def showEvent(self, event) -> None:  # noqa: N802  Qt 命名约定
        """每次显示时刷新输出目录与 OCR 模型提示（设置页改完切回来即可见）。"""
        super().showEvent(event)
        try:
            resolved = self._output_dir()
            self.outdir_label.setText(f"输出位置：{resolved}（可在「设置 → 图片工具」中修改）")
        except OSError as exc:
            self.outdir_label.setText(f"输出位置不可用：{exc}")
        self._refresh_ocr_cfg_hint()

    # ------------------------------------------------------------ Tab 1
    def _run_visible(self) -> None:
        carrier = self.v_carrier.text().strip()
        text = self.v_text.text().strip()
        if not carrier:
            self._set_status(self.v_status, False, "请先选择载体图片。")
            return
        if not text:
            self._set_status(self.v_status, False, "请填写水印文字。")
            return

        try:
            color = watermark.parse_color(self.v_color.text())
        except watermark.WatermarkError as exc:
            self._set_status(self.v_status, False, str(exc))
            return

        out = self._named_out(
            self.v_outname.text(),
            self._auto_name(carrier, "_wm", Path(carrier).suffix or ".png"),
        )
        position = self.v_pos.currentData()
        font_size = self.v_size.value()
        font_path = self.v_font.text().strip() or None

        self._start(
            lambda: watermark.add_visible_watermark(
                carrier, text, out,
                position=position, font_size=font_size,
                color=color, font_path=font_path,
            ),
            lambda path: self._set_status(
                self.v_status, True, f"可见水印已生成：{path}"),
            self.v_status,
            "正在生成可见水印…",
        )

    # ------------------------------------------------------------ Tab 2
    def _refresh_embed_capacity(self) -> None:
        """载体图片变化时实时刷新可写容量提示。"""
        carrier = self.e_carrier.text().strip()
        if not carrier:
            self.e_capacity.setText("")
            return
        channels = self.e_channels.currentData()
        try:
            self.e_capacity.setText(f"可写 {lsb.capacity_text(carrier, channels)}")
        except Exception:  # noqa: BLE001  文件可能暂不可读
            self.e_capacity.setText("（容量未知）")

    def _run_embed(self) -> None:
        carrier = self.e_carrier.text().strip()
        secret = self.e_secret.toPlainText().strip()
        if not carrier:
            self._set_status(self.e_status, False, "请先选择载体图片。")
            return
        if not secret:
            self._set_status(self.e_status, False, "请填写秘密信息。")
            return

        channels = self.e_channels.currentData()
        bit = self.e_bit.value()
        offset = self.e_offset.value()
        order = self.e_order.currentData()
        framing = self.e_framing.currentData()

        # JPEG 压缩会破坏 LSB 数据，输出扩展名强制改为 PNG
        name = (self.e_outname.text().strip()
                or self._auto_name(carrier, "_stego", ".png"))
        out = self._named_out(str(Path(name).with_suffix(".png")),
                              "output_stego.png")

        self._start(
            lambda: lsb.embed(
                carrier, lsb.read_secret(secret), out,
                channels=channels, bit=bit, offset=offset,
                order=order, framing=framing,
            ),
            lambda path: self._set_status(
                self.e_status, True, f"信息已写入：{path}"),
            self.e_status,
            "正在嵌入信息…",
        )

    # ------------------------------------------------------------ Tab 3
    def _gather_extract_params(self) -> tuple:
        """收集提取标签页的当前参数。"""
        return (
            self.x_channels.currentData(),
            self.x_bit.value(),
            self.x_offset.value(),
            self.x_order.currentData(),
            self.x_framing.currentData(),
        )

    def _run_extract(self) -> None:
        stego = self.x_stego.text().strip()
        if not stego:
            self._set_status(self.x_status, False, "请先选择隐写图片。")
            return

        channels, bit, offset, order, framing = self._gather_extract_params()

        out = None
        if self.x_save.isChecked():
            default = self._auto_name(stego, "_extracted", ".txt")
            out = self._named_out(self.x_outname.text(),
                                  Path(default).stem + ".txt")

        # 结果经 ``文本 \x00 保存路径`` 拼接跨线程传递（信号只带一个 str）
        def job_str() -> str:
            text = lsb.extract(
                stego, out, channels=channels, bit=bit, offset=offset,
                order=order, framing=framing,
            )
            return f"{text}\x00{out if out else ''}"

        def done_str(payload: str) -> None:
            text, saved = payload.split("\x00", 1)
            self.x_result.setPlainText(text if text else "（未提取到内容）")
            tail = f"，已保存到 {saved}" if saved else ""
            params = lsb.describe_params(channels, bit, offset, order, framing)
            self._set_status(
                self.x_status, True,
                f"提取完成（{params}）{tail}。")

        self._start(job_str, done_str, self.x_status, "正在提取…")

    def _run_detect(self) -> None:
        """对未知参数的隐写图片爆破参数组合，展示候选并回填最佳参数。"""
        stego = self.x_stego.text().strip()
        if not stego:
            self._set_status(self.x_status, False, "请先选择隐写图片。")
            return

        def job() -> str:
            cands = lsb.detect_params(stego)
            if not cands:
                return ""
            # 候选列表序列化为多行文本（\x00 分隔字段避免换行歧义）
            lines = []
            for c in cands:
                lines.append(
                    f"{c['score']:.2f}\x00{c['channels']}\x00{c['bit']}"
                    f"\x00{c['offset']}\x00{c['order']}\x00{c['framing']}"
                    f"\x00{c['bytes']}\x00{c['text']}"
                )
            return "\x01".join(lines)

        def done(payload: str) -> None:
            if not payload:
                self.x_result.setPlainText("（未找到可信的隐写参数）")
                self._set_status(
                    self.x_status, True, "自动探测完成，未找到可信候选。")
                return

            blocks = payload.split("\x01")
            candidates = []
            for b in blocks:
                parts = b.split("\x00")
                if len(parts) != 8:
                    continue
                candidates.append({
                    "score": float(parts[0]),
                    "channels": parts[1],
                    "bit": int(parts[2]),
                    "offset": int(parts[3]),
                    "order": parts[4],
                    "framing": parts[5],
                    "bytes": int(parts[6]),
                    "text": parts[7],
                })

            # 展示候选列表
            report = []
            for i, c in enumerate(candidates, 1):
                report.append(
                    f"[{i}] {c['score']:.2f} 分 · {lsb.describe_params(c['channels'], c['bit'], c['offset'], c['order'], c['framing'])}\n"
                    f"    内容预览：{c['text'][:120]}")
            self.x_result.setPlainText("\n\n".join(report))

            # 回填最佳参数到面板
            top = candidates[0]
            self.x_channels.setCurrentIndex(
                max(0, self.x_channels.findData(top["channels"])))
            self.x_bit.setValue(top["bit"])
            self.x_offset.setValue(top["offset"])
            self.x_order.setCurrentIndex(
                max(0, self.x_order.findData(top["order"])))
            self.x_framing.setCurrentIndex(
                max(0, self.x_framing.findData(top["framing"])))

            self._set_status(
                self.x_status, True,
                f"自动探测完成：找到 {len(candidates)} 个候选，"
                f"已回填最佳参数（{top['score']:.2f} 分）。")

        self._start(job, done, self.x_status, "正在自动探测参数…")

    # ------------------------------------------------------------ Tab 4
    def _run_base64(self) -> None:
        image = self.b_image.text().strip()
        if not image:
            self._set_status(self.b_status, False, "请先选择图片文件。")
            return
        data_uri = self.b_data_uri.isChecked()

        def job() -> str:
            return image_codec.image_to_base64(image, data_uri=data_uri)

        def done(text: str) -> None:
            self.b_result.setPlainText(text)
            size = Path(image).stat().st_size
            self._set_status(
                self.b_status, True,
                f"编码完成：原图 {size / 1024:.1f} KB，Base64 共 {len(text):,} 字符。")

        self._start(job, done, self.b_status, "正在编码…")

    def _copy_base64(self) -> None:
        text = self.b_result.toPlainText().strip()
        if not text:
            self._set_status(self.b_status, False, "还没有可复制的内容，请先生成 Base64。")
            return
        QApplication.clipboard().setText(text)
        self._set_status(self.b_status, True, f"已复制 {len(text):,} 个字符到剪贴板。")

    def _save_base64(self) -> None:
        text = self.b_result.toPlainText().strip()
        if not text:
            self._set_status(self.b_status, False, "还没有可保存的内容，请先生成 Base64。")
            return
        image = self.b_image.text().strip()
        default = Path(image).stem + "_base64.txt" if image else "image_base64.txt"
        out = self._named_out("", default)
        try:
            out.write_text(text, encoding="utf-8")
        except OSError as exc:
            self._set_status(self.b_status, False, f"保存失败：{exc}")
            return
        self._set_status(self.b_status, True, f"已保存：{out}")

    # ------------------------------------------------------------ Tab 5
    def _load_base64_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "选择 Base64 文本文件", "",
            "文本文件 (*.txt);;所有文件 (*)")
        if not path:
            return
        try:
            text = Path(path).read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            self._set_status(self.d_status, False, f"读取失败：{exc}")
            return
        self.d_input.setPlainText(text.strip())
        self._set_status(self.d_status, True, f"已载入：{path}（{len(text):,} 字符）。")

    def _paste_base64(self) -> None:
        text = QApplication.clipboard().text().strip()
        if not text:
            self._set_status(self.d_status, False, "剪贴板为空。")
            return
        self.d_input.setPlainText(text)
        self._set_status(self.d_status, True, f"已粘贴 {len(text):,} 个字符。")

    def _run_decode(self) -> None:
        text = self.d_input.toPlainText().strip()
        if not text:
            self._set_status(self.d_status, False, "请先粘贴或载入 Base64 文本。")
            return
        # 在 GUI 线程先取好文件名，避免在工作线程里访问控件
        name = self.d_outname.text().strip()

        def job() -> str:
            # 先解码拿到建议扩展名，再落到输出目录（缺扩展名按类型补全 + 重名自动改名）
            data, ext = image_codec.decode_base64_image(text)
            fname = name or "decoded_image"
            if not Path(fname).suffix:
                fname += ext
            out = watermark.unique_path(self._output_dir() / fname)
            out.write_bytes(data)
            return str(out)

        def done(saved: str) -> None:
            size = Path(saved).stat().st_size
            self._set_status(
                self.d_status, True,
                f"解码完成：已保存 {saved}（{size / 1024:.1f} KB）。")

        self._start(job, done, self.d_status, "正在解码 Base64…")

    # ------------------------------------------------------------ Tab 6
    def _refresh_ocr_cfg_hint(self) -> None:
        """按当前 store 的 llm 配置刷新 OCR 分组顶部的提示文案。"""
        llm = self.store.get("llm", default={}) or {}
        base_url = str(llm.get("base_url", "")).strip()
        model = str(llm.get("ocr_model", "")).strip()
        if base_url and model:
            self.o_cfg_hint.setText(
                f"使用 OCR 模型：{model} @ {base_url}（可在「设置 → 模型服务」中修改）")
        elif not base_url:
            self.o_cfg_hint.setText(
                "未配置模型服务地址，请先到「设置 → 模型服务」填写并保存。")
        else:
            self.o_cfg_hint.setText(
                "未配置 OCR 模型，请先到「设置 → 模型服务」选择 OCR 模型并保存。")

    def _run_ocr(self) -> None:
        image = self.o_image.text().strip()
        if not image:
            self._set_status(self.o_status, False, "请先选择图片文件。")
            return
        llm = self.store.get("llm", default={}) or {}
        base_url = str(llm.get("base_url", "")).strip()
        model = str(llm.get("ocr_model", "")).strip()
        if not base_url:
            self._set_status(
                self.o_status, False,
                "未配置模型服务地址，请先到「设置 → 模型服务」填写并保存。")
            return
        if not model:
            self._set_status(
                self.o_status, False,
                "未配置 OCR 模型，请先到「设置 → 模型服务」选择 OCR 模型并保存。")
            return
        prompt = self.o_prompt.text().strip()
        timeout = int(llm.get("timeout", 120) or 120)
        api_key = str(llm.get("api_key", "")).strip() or None
        headers = llm_codec.parse_headers(str(llm.get("headers", "")))

        def job() -> str:
            return llm_codec.ocr_image(
                base_url, model, image,
                prompt=prompt, timeout=timeout,
                api_key=api_key, extra_headers=headers,
            )

        def done(text: str) -> None:
            stripped = (text or "").strip()
            self.o_result.setPlainText(stripped or "（未识别到文字）")
            if stripped:
                self._set_status(
                    self.o_status, True,
                    f"识别完成：共 {len(stripped)} 个字符。")
            else:
                self._set_status(self.o_status, True, "识别完成，但未返回文字内容。")

        self._start(job, done, self.o_status, "正在识别图片文字…")

    def _copy_ocr(self) -> None:
        text = self.o_result.toPlainText().strip()
        if not text:
            self._set_status(self.o_status, False, "还没有可复制的内容，请先识别文字。")
            return
        QApplication.clipboard().setText(text)
        self._set_status(self.o_status, True, f"已复制 {len(text):,} 个字符到剪贴板。")

    def _save_ocr(self) -> None:
        text = self.o_result.toPlainText().strip()
        if not text:
            self._set_status(self.o_status, False, "还没有可保存的内容，请先识别文字。")
            return
        image = self.o_image.text().strip()
        default = Path(image).stem + "_ocr.txt" if image else "ocr_result.txt"
        out = self._named_out("", default)
        try:
            out.write_text(text, encoding="utf-8")
        except OSError as exc:
            self._set_status(self.o_status, False, f"保存失败：{exc}")
            return
        self._set_status(self.o_status, True, f"已保存：{out}")
