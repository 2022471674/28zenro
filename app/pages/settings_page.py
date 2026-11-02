# -*- coding: utf-8 -*-
"""设置页。

三个分区：
- 外观：明 / 暗主题切换（GitHub Primer 双主题），即时生效并落盘；
- 模型服务（OpenAI 兼容）：地址 / API Key / 对话·嵌入·OCR·多模态模型 /
  超时 / 自定义 Header / 翻译提示词，可一键获取可用模型列表；
- 图片工具：输出位置（默认应用根目录下 output 文件夹，可自定义）。
- 压缩包工具：输出位置（修复副本 / 解密提取的落盘目录，可自定义）。

界面层不直接拼配置键，全部经 ``store`` 读写。
项目介绍见侧边栏「关于」页。
"""

from __future__ import annotations

import threading
from pathlib import Path

from PySide6.QtCore import Qt, QThread, QTimer, Signal
from PySide6.QtGui import QColor, QFontDatabase
from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QColorDialog,
    QComboBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLayout,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QStackedWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from qfluentwidgets import FlowLayout

from app import registry
from app import theme as theme_module
from app.widgets.no_wheel import NoWheelComboBox, NoWheelSpinBox
from lib import llm_codec, proxy_pool, watermark


#: 走全局代理池、可配置「按工具代理开关」的 Web 工具清单：(tool_id, 显示名)。
#: 后续新增的 Web 工具若走 ``proxy_pool.make_session()``，在此登记即可出现在
#: 设置页开关里；未登记的仍默认走全局代理（见 proxy_pool.should_use_proxy）。
_PROXY_TOOLS = (
    ("web_fuzz", "Web Fuzz"),
    ("hostsearch", "域名解析历史"),
    ("dir_scan", "目录爆破"),
    ("leak_scan", "源码泄露"),
    ("httpscan", "主机探针"),
    ("param_fuzz", "参数爆破"),
    ("ssti_finder", "SSTI 子类枚举"),
    ("jsfinder", "JSFinder"),
    ("fingerprint", "指纹探测"),
    ("waf_detect", "WAF 识别"),
    ("oss_bucket", "OSS 桶探测"),
    ("attack_surface", "攻击面测绘"),
    ("quick_access", "快捷访问图标"),
)


class _ModelsWorker(QThread):
    """后台拉取可用模型：请求 OpenAI 兼容 ``/models``，结果经信号返回。"""

    done_ok = Signal(list)   # 模型 id 列表
    done_err = Signal(str)

    def __init__(self, base_url: str, timeout: int, api_key: str,
                 headers: dict, parent=None) -> None:
        super().__init__(parent)
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.api_key = api_key
        self.headers = headers

    def run(self) -> None:  # noqa: D102  线程体
        try:
            models = llm_codec.list_models(
                self.base_url,
                timeout=float(self.timeout),
                api_key=self.api_key or None,
                extra_headers=self.headers or None,
            )
        except Exception as exc:  # noqa: BLE001  统一转信号
            self.done_err.emit(str(exc))
            return
        self.done_ok.emit(models)


class _ProxyFetchWorker(QThread):
    """后台从免费源拉取并验证代理（不阻塞设置页）。"""

    done_ok = Signal(dict)
    done_err = Signal(str)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:  # noqa: D102  线程体
        try:
            result = proxy_pool.fetch_and_verify(
                log=lambda _m: None, stop=self._stop)
        except Exception as exc:  # noqa: BLE001
            self.done_err.emit(f"拉取验证失败：{exc}")
            return
        self.done_ok.emit(result)


class FuzzToolsDialog(QDialog):
    """「Fuzz 工具选择」居中弹窗。

    内部是一个卡片（``#card``），标题「Fuzz 工具选择」，主体为 Tag 标签
    网格（一行 4 个）选择参与「一键 Fuzz」的密码学工具；「Web Fuzz 步骤
    开关」属于进阶设置，默认折叠在「高级设置 ▼」里，点击才展开。
    """

    def __init__(self, theme, store, parent=None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._fuzz_tool_checks: dict[str, QPushButton] = {}
        self._web_step_checks: dict[str, tuple[str, QPushButton]] = {}
        self.setWindowTitle("Fuzz 工具选择")
        self.setModal(True)
        self._build()

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        card = QWidget()
        card.setObjectName("card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(12)

        # 标题行：标题 + 右侧「高级设置 ▼」
        title_row = QHBoxLayout()
        title_row.setSpacing(8)
        title = QLabel("Fuzz 工具选择")
        title.setObjectName("title")
        title_row.addWidget(title)
        title_row.addStretch(1)
        self.adv_btn = QPushButton("高级设置 ▼")
        self.adv_btn.setObjectName("ghbtn")
        self.adv_btn.setCheckable(True)
        self.adv_btn.clicked.connect(self._toggle_advanced)
        title_row.addWidget(self.adv_btn)
        layout.addLayout(title_row)

        hint = QLabel(
            "点击标签切换是否参与一键 Fuzz：选中（蓝底）= 参与；"
            "取消（灰边）= 排除。")
        hint.setObjectName("caption")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        # -- 密码学：Tag 标签（网格布局，一行 4 个） --
        layout.addWidget(self._section_label("密码学一键 Fuzz 工具"))
        fuzz_cfg = self.store.get("fuzz_config", default={}) or {}
        disabled = set(fuzz_cfg.get("crypto_disabled") or [])
        crypto_grid = QGridLayout()
        crypto_grid.setSpacing(8)
        crypto_grid.setContentsMargins(0, 0, 0, 0)
        tools = registry.fuzzable_tools()
        for i, tool in enumerate(tools):
            tag = QPushButton(tool.name)
            tag.setObjectName("tag")
            tag.setCheckable(True)
            tag.setChecked(tool.id not in disabled)
            tag.setCursor(Qt.CursorShape.PointingHandCursor)
            tag.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
            tag.setToolTip(
                f"{tool.category_label} · {tool.description}" if tool.description
                else tool.category_label)
            self._fuzz_tool_checks[tool.id] = tag
            crypto_grid.addWidget(tag, i // 4, i % 4)
        # 第 5 列用 stretch 吸收多余宽度，让前 4 列标签紧凑靠左，不平均拉宽
        crypto_grid.setColumnStretch(4, 1)
        crypto_widget = QWidget()
        crypto_widget.setLayout(crypto_grid)
        layout.addWidget(crypto_widget)

        # -- 高级设置（默认折叠）：Web Fuzz 步骤开关 --
        self.advanced_box = QWidget()
        adv_layout = QVBoxLayout(self.advanced_box)
        adv_layout.setContentsMargins(0, 0, 0, 0)
        adv_layout.setSpacing(8)
        adv_layout.addWidget(self._section_label("Web Fuzz 步骤开关"))
        web_cfg = self.store.get("web_fuzz", default={}) or {}
        web_grid = QGridLayout()
        web_grid.setSpacing(8)
        web_grid.setContentsMargins(0, 0, 0, 0)
        web_steps = (("robots", "抓 robots.txt"),
                     ("sitemap", "抓 sitemap.xml"),
                     ("hostsearch", "历史收录查询"),
                     ("subdomain_brute", "字典子域名爆破"))
        for i, (key, label) in enumerate(web_steps):
            tag = QPushButton(label)
            tag.setObjectName("tag")
            tag.setCheckable(True)
            tag.setChecked(bool(web_cfg.get(key, False)))
            tag.setCursor(Qt.CursorShape.PointingHandCursor)
            tag.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
            self._web_step_checks[key] = (label, tag)
            web_grid.addWidget(tag, i // 4, i % 4)
        web_grid.setColumnStretch(4, 1)
        web_widget = QWidget()
        web_widget.setLayout(web_grid)
        adv_layout.addWidget(web_widget)
        layout.addWidget(self.advanced_box)
        self.advanced_box.setVisible(False)

        # 按钮行：保存 / 全选 / 关闭
        actions = QHBoxLayout()
        actions.setSpacing(8)
        save_btn = QPushButton("保存 Fuzz 配置")
        save_btn.setObjectName("ghbtn-primary")
        save_btn.clicked.connect(self._save)
        actions.addWidget(save_btn)
        all_btn = QPushButton("全选")
        all_btn.setObjectName("ghbtn")
        all_btn.clicked.connect(self._select_all)
        actions.addWidget(all_btn)
        actions.addStretch(1)
        close_btn = QPushButton("关闭")
        close_btn.setObjectName("ghbtn")
        close_btn.clicked.connect(self.accept)
        actions.addWidget(close_btn)
        layout.addLayout(actions)

        self.status_label = QLabel("")
        self.status_label.setObjectName("caption")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        root.addWidget(card)
        # 用 SetFixedSize 布局约束：窗口严格锁定为内容的 sizeHint 尺寸，
        # 从机制上杜绝 exec() 被拉伸成全屏；展开/折叠「高级设置」时布局会
        # 重新计算 sizeHint，窗口自动跟着内容伸缩，无需手动 adjustSize。
        root.setSizeConstraint(QLayout.SizeConstraint.SetFixedSize)

    def _section_label(self, text: str) -> QLabel:
        label = QLabel(text)
        label.setObjectName("section")
        return label

    def _toggle_advanced(self) -> None:
        expanded = self.adv_btn.isChecked()
        self.advanced_box.setVisible(expanded)
        self.adv_btn.setText("高级设置 ▲" if expanded else "高级设置 ▼")

    def _select_all(self) -> None:
        for tag in self._fuzz_tool_checks.values():
            tag.setChecked(True)

    def _save(self) -> None:
        disabled = [tid for tid, tag in self._fuzz_tool_checks.items()
                    if not tag.isChecked()]
        self.store.setv(disabled, "fuzz_config", "crypto_disabled")
        for key, (_label, tag) in self._web_step_checks.items():
            self.store.setv(bool(tag.isChecked()), "web_fuzz", key)
        try:
            self.store.save()
        except OSError as exc:
            self.status_label.setText(f"保存失败：{exc}")
            return
        self.status_label.setText(
            f"已保存。密码学一键 Fuzz 排除 {len(disabled)} 个工具；"
            f"Web Fuzz 步骤开关已更新。")


class SettingsPage(QWidget):
    """设置页：外观 / 工具管理 / 模型配置。"""

    #: 主题切换回调：mode -> None（由 main_window 接管应用）
    theme_changed = Signal(str)

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._models_worker: _ModelsWorker | None = None
        self._proxy_worker: _ProxyFetchWorker | None = None

        self._theme_apply_timer = QTimer(self)
        self._theme_apply_timer.setSingleShot(True)
        self._theme_apply_timer.setInterval(250)
        self._theme_apply_timer.timeout.connect(self._apply_theme_now)

        self._build()

    def _build(self) -> None:
        # 左导航 + 右内容
        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # 左侧导航
        self.nav_panel = QWidget()
        self.nav_panel.setObjectName("nav")
        self.nav_panel.setFixedWidth(180)
        nav_layout = QVBoxLayout(self.nav_panel)
        nav_layout.setContentsMargins(12, 16, 12, 16)
        nav_layout.setSpacing(4)

        self._nav_buttons: dict[str, QPushButton] = {}
        self._nav_group: list[tuple[str, str]] = [
            ("appearance", "外观"),
            ("theme", "主题"),
            ("model", "模型服务"),
            ("fuzz", "Fuzz 工具"),
            ("proxy", "代理池"),
            ("tools", "工具输出"),
            ("payload", "Payload 编译器"),
        ]
        for key, label in self._nav_group:
            btn = QPushButton(label)
            btn.setObjectName("nav-item")
            btn.setCheckable(True)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda _c=False, k=key: self._switch_nav(k))
            nav_layout.addWidget(btn)
            self._nav_buttons[key] = btn
        nav_layout.addStretch(1)

        self._reset_btn = QPushButton("恢复默认设置")
        self._reset_btn.setObjectName("ghbtn-danger")
        self._reset_btn.clicked.connect(self._reset_defaults)
        nav_layout.addWidget(self._reset_btn)
        root.addWidget(self.nav_panel)

        # 右侧内容：stack 直接贴在右栏。每个分区各自包一层 QScrollArea
        # （分区过高时独立滚动），而不是用一个外层滚动区包整叠 stack ——
        # 后者会让 QStackedWidget 取「最高分区」的 sizeHint 当整叠高度
        # （QStackedLayout 的固有行为，含隐藏页），较矮的分区会被垂直
        # 摊开：内容悬在中部、控件之间出现大段空白。
        self.stack = QStackedWidget()
        self.stack.setSizePolicy(QSizePolicy.Policy.Expanding,
                                 QSizePolicy.Policy.Expanding)
        root.addWidget(self.stack, 1)

        # 左导航顺序与本处注册顺序必须一一对应（_switch_nav 按索引切换）
        # 外观
        self.stack.addWidget(self._wrap_scroll(
            self._section_page(self._build_appearance())))
        # 主题（颜色 + 字体）
        self.stack.addWidget(self._wrap_scroll(self._section_page(
            self._section_title("自定义主题 · 颜色"),
            self._build_custom_colors(),
            self._section_title("自定义主题 · 字体与窗口"),
            self._build_custom_fonts(),
        )))
        # 模型服务
        self.stack.addWidget(self._wrap_scroll(self._section_page(
            self._section_title("模型服务（OpenAI 兼容格式）"),
            self._build_model(),
        )))
        # Fuzz 工具（入口卡片 + 按钮 → 弹出居中对话框）
        self.stack.addWidget(self._wrap_scroll(self._section_page(
            self._section_title("Fuzz 工具选择"),
            self._build_fuzz_entry(),
        )))
        # 代理池
        self.stack.addWidget(self._wrap_scroll(self._section_page(
            self._section_title("Web 工具代理池"),
            self._build_proxy_pool(),
        )))
        # 工具输出
        self.stack.addWidget(self._wrap_scroll(self._section_page(
            self._section_title("图片工具"),
            self._build_watermark(),
            self._section_title("压缩包工具"),
            self._build_zip_crack(),
        )))
        # Payload 编译器
        self.stack.addWidget(self._wrap_scroll(self._section_page(
            self._section_title("Payload 编译器"),
            self._build_payload_compiler(),
        )))

        self._switch_nav("appearance")

    def _section_page(self, *widgets: QWidget) -> QWidget:
        """把若干标题 / 卡片组成一个分区页。

        末尾固定加一个 ``addStretch(1)``：页高会取「分区内容高度与视口
        高度的较大者」，矮分区（如外观）被拉高时多出的空间全部沉到页尾，
        而不是被 QVBoxLayout 摊到各控件项之间把内容顶到页面中部。
        """
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)
        for widget in widgets:
            layout.addWidget(widget)
        layout.addStretch(1)
        return page

    @staticmethod
    def _wrap_scroll(page: QWidget) -> QScrollArea:
        """给分区页包一个可调大小的无边框专属滚动区。"""
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setWidget(page)
        return scroll

    def _switch_nav(self, key: str) -> None:
        """切换左侧导航高亮 + 右侧内容。"""
        for nav_key, btn in self._nav_buttons.items():
            btn.setChecked(nav_key == key)
        index = dict((k, i) for i, (k, _l) in enumerate(self._nav_group))[key]
        self.stack.setCurrentIndex(index)

    # ----------------------------------------------------------- 小部件
    def _section_title(self, text: str) -> QLabel:
        label = QLabel(text)
        label.setObjectName("title")
        return label

    def _card(self) -> QWidget:
        card = QWidget()
        card.setObjectName("card")
        return card

    def _section_label(self, text: str) -> QLabel:
        label = QLabel(text)
        label.setObjectName("section")
        return label

    # ----------------------------------------------------------- 外观
    def _build_appearance(self) -> QWidget:
        card = self._card()
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(10)

        row = QHBoxLayout()
        row.setSpacing(12)

        self._theme_group = QButtonGroup(self)
        light_btn = QRadioButton("Light")
        dark_btn = QRadioButton("Dark")
        self._theme_group.addButton(light_btn)
        self._theme_group.addButton(dark_btn)
        mode = self.store.get("theme_mode", default="light")
        light_btn.setChecked(mode != theme_module.THEME_DARK)
        dark_btn.setChecked(mode == theme_module.THEME_DARK)
        light_btn.toggled.connect(self._on_theme_toggled)
        dark_btn.toggled.connect(self._on_theme_toggled)

        row.addWidget(QLabel("主题"))
        row.addWidget(light_btn)
        row.addWidget(dark_btn)
        row.addStretch(1)
        layout.addLayout(row)

        self.resizable_check = QCheckBox("窗口可调整大小（重启后生效）")
        self.resizable_check.setChecked(
            bool(self.store.get("window_resizable", default=True)))
        self.resizable_check.toggled.connect(self._on_resizable_toggled)
        layout.addWidget(self.resizable_check)
        return card

    def _on_theme_toggled(self, checked: bool) -> None:
        if not checked:
            return
        mode = (theme_module.THEME_DARK
                if self._theme_group.checkedButton().text() == "Dark"
                else theme_module.THEME_LIGHT)
        self.store.setv(mode, "theme_mode")
        self.store.save()
        self.theme_changed.emit(mode)
        # 颜色编辑器切换为该模式自己的配色
        self._refresh_color_rows()

    def _current_mode(self) -> str:
        checked = self._theme_group.checkedButton()
        return (theme_module.THEME_DARK
                if checked is not None and checked.text() == "Dark"
                else theme_module.THEME_LIGHT)

    def _refresh_color_rows(self) -> None:
        """把颜色编辑器同步为当前模式的配色（覆盖值或预设）。"""
        mode = self._current_mode()
        base = theme_module.palette_for(mode)
        bucket = theme_module.custom_color_bucket(
            self.store.get("custom_colors", default={}), mode)
        for key, (swatch, edit) in self._color_rows.items():
            value = (theme_module.normalize_color(bucket.get(key))
                     or getattr(base, key))
            edit.blockSignals(True)
            edit.setText(value)
            edit.blockSignals(False)
            swatch.setStyleSheet(
                f"background-color: {value}; border-radius: 4px;")

    def _on_resizable_toggled(self, checked: bool) -> None:
        self.store.setv(bool(checked), "window_resizable")
        self.store.save()

    # ------------------------------------------------------- 自定义主题
    def _build_custom_colors(self) -> QWidget:
        """颜色编辑器：按分组列出全部颜色令牌，色块 + 十六进制双通道编辑。"""
        card = self._card()
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(10)

        hint = QLabel(
            "点击色块弹出取色器，或直接填写 #RRGGBB。"
            "明 / 暗主题各自独立记录一套配色，切换上方「主题」即可分别调整；"
            "修改即时生效并保存，未修改的元素继续使用对应主题的预设颜色。"
        )
        hint.setObjectName("caption")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        self._color_rows: dict[str, tuple[QPushButton, QLineEdit]] = {}
        groups: dict[str, list[tuple[str, str]]] = {}
        for key, group, label in theme_module.COLOR_TOKENS:
            groups.setdefault(group, []).append((key, label))

        for group, items in groups.items():
            layout.addWidget(self._section_label(f"{group}"))
            form = QFormLayout()
            form.setHorizontalSpacing(12)
            form.setVerticalSpacing(8)
            for key, label in items:
                form.addRow(label, self._make_color_row(key, "#808080"))
            layout.addLayout(form)
        self._refresh_color_rows()

        actions = QHBoxLayout()
        actions.setSpacing(8)
        reset_btn = QPushButton("恢复预设颜色")
        reset_btn.setObjectName("ghbtn")
        reset_btn.clicked.connect(self._reset_custom_colors)
        actions.addWidget(reset_btn)
        actions.addStretch(1)
        layout.addLayout(actions)
        return card

    def _make_color_row(self, key: str, value: str) -> QWidget:
        row = QWidget()
        box = QHBoxLayout(row)
        box.setContentsMargins(0, 0, 0, 0)
        box.setSpacing(8)

        swatch = QPushButton()
        swatch.setFixedSize(46, 24)
        swatch.setCursor(Qt.CursorShape.PointingHandCursor)
        swatch.setStyleSheet(f"background-color: {value}; border-radius: 4px;")
        swatch.clicked.connect(lambda _=False, k=key: self._pick_color(k))

        edit = QLineEdit(value)
        edit.setMaximumWidth(120)
        edit.setPlaceholderText("#RRGGBB")
        edit.textChanged.connect(lambda _t, k=key: self._on_color_edited(k))

        box.addWidget(swatch)
        box.addWidget(edit)
        box.addStretch(1)
        self._color_rows[key] = (swatch, edit)
        return row

    def _pick_color(self, key: str) -> None:
        swatch, edit = self._color_rows[key]
        initial = theme_module.normalize_color(edit.text()) or "#808080"
        color = QColorDialog.getColor(QColor(initial), self, "选择颜色")
        if color.isValid():
            edit.blockSignals(True)
            edit.setText(color.name())
            edit.blockSignals(False)
            swatch.setStyleSheet(f"background-color: {color.name()}; border-radius: 4px;")
            self._schedule_theme_apply()

    def _on_color_edited(self, key: str) -> None:
        swatch, edit = self._color_rows[key]
        color = theme_module.normalize_color(edit.text())
        if color:
            swatch.setStyleSheet(f"background-color: {color}; border-radius: 4px;")
            self._schedule_theme_apply()

    def _reset_custom_colors(self) -> None:
        """恢复当前模式的配色为预设（另一种模式的配色保持不变）。"""
        mode = self._current_mode()
        raw = self.store.get("custom_colors", default={}) or {}
        light_b = dict(raw.get("light")) if isinstance(raw.get("light"), dict) else {}
        dark_b = dict(raw.get("dark")) if isinstance(raw.get("dark"), dict) else {}
        if mode == theme_module.THEME_DARK:
            dark_b = {}
        else:
            light_b = {}
        self.store.setv({"light": light_b, "dark": dark_b}, "custom_colors")
        self.store.save()
        self._refresh_color_rows()
        self.theme_changed.emit(self.store.get("theme_mode", default="light"))

    def _build_custom_fonts(self) -> QWidget:
        """字体与窗口编辑器：字体族（下拉 + 可输入）与字号（px）。"""
        card = self._card()
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(10)

        hint = QLabel("字体可从下拉中选择系统已安装字体，也可直接输入名称；字号单位为像素。")
        hint.setObjectName("caption")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        self._font_family_edits: dict[str, QComboBox] = {}
        self._font_size_spins: dict[str, QSpinBox] = {}
        custom_fonts = self.store.get("custom_fonts", default={}) or {}
        if not isinstance(custom_fonts, dict):
            custom_fonts = {}
        base = theme_module.palette_for(self.store.get("theme_mode", default="light"))

        form = QFormLayout()
        form.setHorizontalSpacing(12)
        form.setVerticalSpacing(8)
        families = sorted(set(QFontDatabase.families()))
        for key, label, kind in theme_module.FONT_TOKENS:
            preset = getattr(base, key)
            current = custom_fonts.get(key, preset)
            if kind == "family":
                combo = NoWheelComboBox()
                combo.setEditable(True)
                combo.addItems(families[:400])
                combo.setCurrentText(str(current))
                combo.currentTextChanged.connect(
                    lambda _t, k=key: self._schedule_theme_apply())
                self._font_family_edits[key] = combo
                form.addRow(label, combo)
            else:
                spin = NoWheelSpinBox()
                spin.setRange(8, 48)
                spin.setValue(int(current))
                spin.setSuffix(" px")
                spin.valueChanged.connect(
                    lambda _v, k=key: self._schedule_theme_apply())
                self._font_size_spins[key] = spin
                form.addRow(label, spin)
        layout.addLayout(form)

        actions = QHBoxLayout()
        actions.setSpacing(8)
        reset_btn = QPushButton("恢复预设字体")
        reset_btn.setObjectName("ghbtn")
        reset_btn.clicked.connect(self._reset_custom_fonts)
        actions.addWidget(reset_btn)
        actions.addStretch(1)
        layout.addLayout(actions)
        return card

    def _reset_custom_fonts(self) -> None:
        self.store.setv({}, "custom_fonts")
        self.store.save()
        base = theme_module.palette_for(self.store.get("theme_mode", default="light"))
        for key, combo in self._font_family_edits.items():
            combo.blockSignals(True)
            combo.setCurrentText(str(getattr(base, key)))
            combo.blockSignals(False)
        for key, spin in self._font_size_spins.items():
            spin.blockSignals(True)
            spin.setValue(int(getattr(base, key)))
            spin.blockSignals(False)
        self.theme_changed.emit(self.store.get("theme_mode", default="light"))

    def _schedule_theme_apply(self) -> None:
        """防抖：250ms 内的连续修改只落盘 / 生效一次。"""
        self._theme_apply_timer.start(250)

    def _apply_theme_now(self) -> None:
        mode = self._current_mode()
        colors = {}
        for key, (_swatch, edit) in self._color_rows.items():
            color = theme_module.normalize_color(edit.text())
            if color:
                colors[key] = color

        # 分模式存储：只覆盖当前正在编辑的模式，另一种模式保持原样
        raw = self.store.get("custom_colors", default={}) or {}
        light_b = dict(raw.get("light")) if isinstance(raw.get("light"), dict) else {}
        dark_b = dict(raw.get("dark")) if isinstance(raw.get("dark"), dict) else {}
        if mode == theme_module.THEME_DARK:
            dark_b = colors
        else:
            light_b = colors
        self.store.setv({"light": light_b, "dark": dark_b}, "custom_colors")

        fonts: dict = {}
        for key, combo in self._font_family_edits.items():
            text = combo.currentText().strip()
            if text:
                fonts[key] = text
        for key, spin in self._font_size_spins.items():
            fonts[key] = int(spin.value())

        self.store.setv(fonts, "custom_fonts")
        self.store.save()
        self.theme_changed.emit(mode)

    # ------------------------------------------------------- 恢复默认
    def _reset_defaults(self) -> None:
        """把全部配置恢复为内置默认值（二次确认后落盘并同步界面）。"""
        answer = QMessageBox.question(
            self,
            "恢复默认设置",
            "将把主题、模型服务配置与各工具默认参数全部恢复为内置默认值，"
            "当前设置不可撤销。确定继续？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return

        self.store.reset()
        self.refresh_from_store()
        self.theme_changed.emit(self.store.get("theme_mode", default="light"))
        self.model_status.setText("已恢复默认模型配置。")

    def refresh_from_store(self) -> None:
        """把所有界面控件同步为 store 中的当前值（重置后调用）。"""
        mode = self.store.get("theme_mode", default="light")
        buttons = self._theme_group.buttons()
        if len(buttons) >= 2:
            dark = mode == theme_module.THEME_DARK
            buttons[0].blockSignals(True)
            buttons[1].blockSignals(True)
            buttons[0].setChecked(not dark)
            buttons[1].setChecked(dark)
            buttons[0].blockSignals(False)
            buttons[1].blockSignals(False)

        self.resizable_check.blockSignals(True)
        self.resizable_check.setChecked(
            bool(self.store.get("window_resizable", default=True)))
        self.resizable_check.blockSignals(False)

        base = theme_module.palette_for(mode)
        self._refresh_color_rows()

        custom_fonts = self.store.get("custom_fonts", default={}) or {}
        if not isinstance(custom_fonts, dict):
            custom_fonts = {}
        for key, combo in self._font_family_edits.items():
            combo.blockSignals(True)
            combo.setCurrentText(str(custom_fonts.get(key, getattr(base, key))))
            combo.blockSignals(False)
        for key, spin in self._font_size_spins.items():
            spin.blockSignals(True)
            spin.setValue(int(custom_fonts.get(key, getattr(base, key))))
            spin.blockSignals(False)

        llm = self.store.get("llm", default={}) or {}
        self.base_url_edit.setText(str(llm.get("base_url", "")))
        self.api_key_edit.setText(str(llm.get("api_key", "")))
        self.timeout_spin.setValue(int(llm.get("timeout", 120) or 120))
        for combo, key in (
            (self.model_combo, "model"),
            (self.embedding_combo, "embedding_model"),
            (self.ocr_combo, "ocr_model"),
            (self.multimodal_combo, "multimodal_model"),
        ):
            combo.blockSignals(True)
            combo.setCurrentText(str(llm.get(key, "")))
            combo.blockSignals(False)
        self.headers_edit.setPlainText(str(llm.get("headers", "")))
        self.prompt_zh_edit.setPlainText(str(llm.get("system_prompt_zh", "")))
        self.prompt_en_edit.setPlainText(str(llm.get("system_prompt_en", "")))

        wm = self.store.get("watermark", default={}) or {}
        self.wm_outdir_edit.setText(str(wm.get("output_dir", "")))
        self._update_wm_preview()

        # 代理池配置回填
        proxy_cfg = self.store.get("proxy_pool", default={}) or {}
        self.proxy_enabled_check.blockSignals(True)
        self.proxy_enabled_check.setChecked(bool(proxy_cfg.get("enabled", False)))
        self.proxy_enabled_check.blockSignals(False)
        self._select_data(self.proxy_protocol_combo, proxy_cfg.get("protocol", "http"))
        self.proxy_timeout_spin.setValue(int(proxy_cfg.get("timeout", 6) or 6))
        self.proxy_threads_spin.setValue(int(proxy_cfg.get("threads", 64) or 64))
        self.proxy_max_spin.setValue(int(proxy_cfg.get("max_proxies", 200) or 200))
        enabled_sources = set(proxy_cfg.get("sources") or [])
        for name, check in self._proxy_source_checks.items():
            check.blockSignals(True)
            check.setChecked(name in enabled_sources)
            check.blockSignals(False)
        self.proxy_manual_edit.setPlainText(str(proxy_cfg.get("manual", "") or ""))
        # 按工具代理开关回填
        if hasattr(self, "_proxy_tool_checks"):
            tool_proxy_cfg = proxy_cfg.get("tool_proxy")
            tool_proxy_cfg = tool_proxy_cfg if isinstance(tool_proxy_cfg, dict) else {}
            for tool_id, check in self._proxy_tool_checks.items():
                check.blockSignals(True)
                check.setChecked(bool(tool_proxy_cfg.get(tool_id, True)))
                check.blockSignals(False)
        self._on_proxy_enabled(bool(proxy_cfg.get("enabled", False)))

    # ------------------------------------------------------- 模型配置
    def _build_model(self) -> QWidget:
        card = self._card()
        layout = QVBoxLayout(card)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(9)

        llm = self.store.get("llm", default={}) or {}

        hint = QLabel(
            "兼容 OpenAI 格式的服务（OpenAI / DeepSeek / Ollama /v1 / vLLM / "
            "One-API 等中转网关）。填写地址与 Key 后点「获取可用模型」可自动拉取"
            "模型列表并填入下方各模型下拉框。")
        hint.setObjectName("caption")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        form = QFormLayout()
        form.setHorizontalSpacing(12)
        form.setVerticalSpacing(8)

        addr_row = QHBoxLayout()
        addr_row.setSpacing(8)
        self.base_url_edit = QLineEdit(str(llm.get("base_url", "")))
        self.base_url_edit.setPlaceholderText("https://api.openai.com/v1")
        addr_row.addWidget(self.base_url_edit, stretch=1)
        self.fetch_btn = QPushButton("获取可用模型")
        self.fetch_btn.setObjectName("ghbtn")
        self.fetch_btn.clicked.connect(self._fetch_models)
        addr_row.addWidget(self.fetch_btn)
        form.addRow("服务地址", addr_row)

        self.api_key_edit = QLineEdit(str(llm.get("api_key", "")))
        self.api_key_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.api_key_edit.setPlaceholderText("sk-…（本地服务可留空）")
        form.addRow("API Key（可选）", self.api_key_edit)

        # 四类模型：对话（翻译）/ 嵌入 / OCR / 多模态
        self.model_combo = self._make_model_combo(str(llm.get("model", "")))
        form.addRow("对话模型（翻译）", self.model_combo)
        self.embedding_combo = self._make_model_combo(
            str(llm.get("embedding_model", "")))
        form.addRow("嵌入模型", self.embedding_combo)
        self.ocr_combo = self._make_model_combo(str(llm.get("ocr_model", "")))
        form.addRow("OCR 模型", self.ocr_combo)
        self.multimodal_combo = self._make_model_combo(
            str(llm.get("multimodal_model", "")))
        form.addRow("多模态模型（看图）", self.multimodal_combo)

        self.timeout_spin = NoWheelSpinBox()
        self.timeout_spin.setRange(1, 3600)
        self.timeout_spin.setValue(int(llm.get("timeout", 120) or 120))
        self.timeout_spin.setSuffix(" 秒")
        form.addRow("请求超时", self.timeout_spin)

        layout.addLayout(form)

        # 高级设置（默认折叠）：自定义 Header + 中英文提示词
        self.adv_header_btn = QPushButton("高级设置 ▼")
        self.adv_header_btn.setObjectName("ghbtn")
        self.adv_header_btn.setCheckable(True)
        self.adv_header_btn.clicked.connect(self._toggle_advanced)
        adv_row = QHBoxLayout()
        adv_row.addStretch(1)
        adv_row.addWidget(self.adv_header_btn)
        layout.addLayout(adv_row)

        self.advanced_box = QWidget()
        adv_layout = QVBoxLayout(self.advanced_box)
        adv_layout.setContentsMargins(0, 0, 0, 0)
        adv_layout.setSpacing(8)

        # 自定义 Header（每行一个 Key: Value）
        adv_layout.addWidget(QLabel("自定义 Header（可选，每行一个 Key: Value）"))
        self.headers_edit = QTextEdit()
        self.headers_edit.setObjectName("io")
        self.headers_edit.setPlainText(str(llm.get("headers", "")))
        self.headers_edit.setPlaceholderText(
            "X-Custom-Header: value\nAnother-Header: value")
        self.headers_edit.setFixedHeight(54)
        adv_layout.addWidget(self.headers_edit)

        adv_layout.addWidget(QLabel("中文方向提示词（留空用内置默认值）"))
        self.prompt_zh_edit = QTextEdit()
        self.prompt_zh_edit.setObjectName("io")
        self.prompt_zh_edit.setPlainText(str(llm.get("system_prompt_zh", "")))
        self.prompt_zh_edit.setFixedHeight(64)
        adv_layout.addWidget(self.prompt_zh_edit)

        adv_layout.addWidget(QLabel("英文方向提示词（留空用内置默认值）"))
        self.prompt_en_edit = QTextEdit()
        self.prompt_en_edit.setObjectName("io")
        self.prompt_en_edit.setPlainText(str(llm.get("system_prompt_en", "")))
        self.prompt_en_edit.setFixedHeight(64)
        adv_layout.addWidget(self.prompt_en_edit)

        layout.addWidget(self.advanced_box)
        self.advanced_box.setVisible(False)

        actions = QHBoxLayout()
        actions.setSpacing(8)
        save_btn = QPushButton("保存模型配置")
        save_btn.setObjectName("ghbtn-primary")
        save_btn.clicked.connect(self._save_model)
        actions.addWidget(save_btn)
        actions.addStretch(1)
        layout.addLayout(actions)

        self.model_status = QLabel("")
        self.model_status.setObjectName("caption")
        self.model_status.setWordWrap(True)
        layout.addWidget(self.model_status)
        return card

    def _make_model_combo(self, value: str) -> QComboBox:
        """可编辑下拉：既能手填模型名，也能用「获取可用模型」填充候选。"""
        combo = NoWheelComboBox()
        combo.setEditable(True)
        combo.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        combo.setCurrentText(value)
        combo.setMinimumWidth(260)
        return combo

    def _fetch_models(self) -> None:
        if self._models_worker is not None and self._models_worker.isRunning():
            return
        base_url = self.base_url_edit.text().strip()
        if not base_url:
            self.model_status.setText("请先填写服务地址。")
            return
        self.fetch_btn.setEnabled(False)
        self.model_status.setText("正在获取可用模型…")
        self._models_worker = _ModelsWorker(
            base_url,
            self.timeout_spin.value(),
            self.api_key_edit.text().strip(),
            llm_codec.parse_headers(self.headers_edit.toPlainText()),
            self,
        )
        self._models_worker.done_ok.connect(self._on_models_ok)
        self._models_worker.done_err.connect(self._on_models_err)
        self._models_worker.start()

    def _on_models_ok(self, models: list) -> None:
        self.fetch_btn.setEnabled(True)
        if not models:
            self.model_status.setText("服务可达，但未返回任何模型。")
            return
        for combo in (self.model_combo, self.embedding_combo,
                      self.ocr_combo, self.multimodal_combo):
            current = combo.currentText().strip()
            combo.blockSignals(True)
            combo.clear()
            combo.addItems(models)
            # 保留已填值；原本为空则保持为空（下拉里可选），不自动选首项——
            # 拉取到的是全部模型，首项未必是嵌入 / OCR / 多模态模型
            combo.setCurrentText(current)
            combo.blockSignals(False)
        shown = ", ".join(models[:6])
        if len(models) > 6:
            shown += f" …（共 {len(models)} 个）"
        self.model_status.setText(
            f"获取到 {len(models)} 个模型：{shown}（已填入各模型下拉框）")

    def _on_models_err(self, reason: str) -> None:
        self.fetch_btn.setEnabled(True)
        self.model_status.setText(f"获取模型失败：{reason}")

    def _toggle_advanced(self) -> None:
        """展开 / 折叠「高级设置」（自定义 Header + 提示词）。"""
        expanded = self.adv_header_btn.isChecked()
        self.advanced_box.setVisible(expanded)
        self.adv_header_btn.setText("高级设置 ▲" if expanded else "高级设置 ▼")

    def _save_model(self) -> None:
        self.store.setv(self.base_url_edit.text().strip(), "llm", "base_url")
        self.store.setv(self.api_key_edit.text().strip(), "llm", "api_key")
        self.store.setv(self.timeout_spin.value(), "llm", "timeout")
        self.store.setv(self.model_combo.currentText().strip(), "llm", "model")
        self.store.setv(self.embedding_combo.currentText().strip(),
                        "llm", "embedding_model")
        self.store.setv(self.ocr_combo.currentText().strip(), "llm", "ocr_model")
        self.store.setv(self.multimodal_combo.currentText().strip(),
                        "llm", "multimodal_model")
        self.store.setv(self.headers_edit.toPlainText(), "llm", "headers")
        self.store.setv(self.prompt_zh_edit.toPlainText(),
                        "llm", "system_prompt_zh")
        self.store.setv(self.prompt_en_edit.toPlainText(),
                        "llm", "system_prompt_en")
        self.store.save()
        self.model_status.setText("已保存模型配置。")

    # ------------------------------------------------------- 一键 Fuzz 配置
    def _build_fuzz_entry(self) -> QWidget:
        """Fuzz 工具选择的入口卡片：说明 + 「打开 Fuzz 工具选择」按钮。

        点击按钮弹出居中的 :class:`FuzzToolsDialog`，真正的 Tag 网格选择在
        弹窗内完成；配置读写仍落在 ``fuzz_config`` / ``web_fuzz`` 节，与
        Web Fuzz 页面共享同一配置。
        """
        card = self._card()
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(10)

        hint = QLabel(
            "选择哪些密码学工具参与「一键 Fuzz」，以及 Web Fuzz 的内部步骤开关。"
            "点击下方按钮，在弹出的「Fuzz 工具选择」卡片里用标签勾选（选中=蓝底）。")
        hint.setObjectName("caption")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        row = QHBoxLayout()
        row.setSpacing(8)
        open_btn = QPushButton("打开 Fuzz 工具选择…")
        open_btn.setObjectName("ghbtn-primary")
        open_btn.clicked.connect(self._open_fuzz_dialog)
        row.addWidget(open_btn)
        row.addStretch(1)
        layout.addLayout(row)

        return card

    def _open_fuzz_dialog(self) -> None:
        """弹出居中的「Fuzz 工具选择」对话框（模态）。"""
        dialog = FuzzToolsDialog(self.theme, self.store, self)
        dialog.exec()

    # ------------------------------------------------------- Web 工具代理池
    def _build_proxy_pool(self) -> QWidget:
        """Web 工具全局代理池配置：启用开关 / 协议 / 免费源 / 手动代理 / 检测。"""
        card = self._card()
        layout = QVBoxLayout(card)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(9)

        cfg = self.store.get("proxy_pool", default={}) or {}

        hint = QLabel(
            "启用后，JSFinder / 主机探针 / 源码泄露 / 目录爆破 / 多地 Ping 等 Web 工具"
            "的请求会统一经代理池转发。代理从免费源拉取并验证，使用前会先检测是否可用。"
            "免费代理源不稳定属正常现象，若验证结果偏少可稍后重试。")
        hint.setObjectName("caption")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        form = QFormLayout()
        form.setHorizontalSpacing(12)
        form.setVerticalSpacing(8)

        self.proxy_enabled_check = QCheckBox("启用 Web 工具代理池")
        self.proxy_enabled_check.setChecked(bool(cfg.get("enabled", False)))
        self.proxy_enabled_check.toggled.connect(self._on_proxy_enabled)
        form.addRow("", self.proxy_enabled_check)

        self.proxy_protocol_combo = NoWheelComboBox()
        for key, label in (("http", "HTTP 代理"),
                           ("socks5", "SOCKS5 代理"),
                           ("socks4", "SOCKS4 代理")):
            self.proxy_protocol_combo.addItem(label, key)
        self._select_data(self.proxy_protocol_combo, cfg.get("protocol", "http"))
        form.addRow("优先协议", self.proxy_protocol_combo)

        opts = QHBoxLayout()
        opts.setSpacing(12)
        self.proxy_timeout_spin = NoWheelSpinBox()
        self.proxy_timeout_spin.setRange(3, 30)
        self.proxy_timeout_spin.setValue(int(cfg.get("timeout", 6) or 6))
        self.proxy_timeout_spin.setSuffix(" 秒")
        opts.addWidget(QLabel("验证超时"))
        opts.addWidget(self.proxy_timeout_spin)
        self.proxy_threads_spin = NoWheelSpinBox()
        self.proxy_threads_spin.setRange(8, 256)
        self.proxy_threads_spin.setValue(int(cfg.get("threads", 64) or 64))
        opts.addWidget(QLabel("验证线程"))
        opts.addWidget(self.proxy_threads_spin)
        self.proxy_max_spin = NoWheelSpinBox()
        self.proxy_max_spin.setRange(20, 1000)
        self.proxy_max_spin.setValue(int(cfg.get("max_proxies", 200) or 200))
        opts.addWidget(QLabel("拉取上限"))
        opts.addWidget(self.proxy_max_spin)
        opts.addStretch(1)
        form.addRow("", opts)
        layout.addLayout(form)

        layout.addWidget(self._section_label("免费代理源（勾选启用的源）"))
        self._proxy_source_checks: dict[str, QCheckBox] = {}
        source_flow = FlowLayout(needAni=False)
        source_flow.setContentsMargins(0, 0, 0, 0)
        source_flow.setHorizontalSpacing(8)
        source_flow.setVerticalSpacing(6)
        enabled_sources = set(cfg.get("sources") or [])
        for name in proxy_pool.ALL_SOURCES:
            check = QCheckBox(name)
            check.setChecked(name in enabled_sources)
            self._proxy_source_checks[name] = check
            source_flow.addWidget(check)
        source_widget = QWidget()
        source_widget.setLayout(source_flow)
        layout.addWidget(source_widget)

        layout.addWidget(QLabel("手动代理（可选，每行一个 ip:port，可带协议前缀）"))
        self.proxy_manual_edit = QTextEdit()
        self.proxy_manual_edit.setObjectName("io")
        self.proxy_manual_edit.setPlainText(str(cfg.get("manual", "") or ""))
        self.proxy_manual_edit.setPlaceholderText(
            "1.2.3.4:8080\nsocks5://5.6.7.8:1080")
        self.proxy_manual_edit.setFixedHeight(64)
        layout.addWidget(self.proxy_manual_edit)

        # -- 按工具代理开关（默认全部勾选 = 听从全局代理） --
        layout.addWidget(self._section_label(
            "按工具代理开关（取消勾选 = 该工具直连，不跟随全局代理）"))
        tool_hint = QLabel(
            "默认全部勾选（听从全局代理）。取消勾选的工具即使全局代理已启用，"
            "也会直连目标。后续新增的 Web 工具默认走代理，无需额外配置。")
        tool_hint.setObjectName("caption")
        tool_hint.setWordWrap(True)
        layout.addWidget(tool_hint)

        self._proxy_tool_checks: dict[str, QCheckBox] = {}
        tool_proxy_cfg = cfg.get("tool_proxy") if isinstance(cfg, dict) else None
        tool_proxy_cfg = tool_proxy_cfg if isinstance(tool_proxy_cfg, dict) else {}
        tool_flow = FlowLayout(needAni=False)
        tool_flow.setContentsMargins(0, 0, 0, 0)
        tool_flow.setHorizontalSpacing(8)
        tool_flow.setVerticalSpacing(6)
        for tool_id, label in _PROXY_TOOLS:
            check = QCheckBox(label)
            check.setChecked(bool(tool_proxy_cfg.get(tool_id, True)))
            check.setToolTip(f"工具 id：{tool_id}")
            self._proxy_tool_checks[tool_id] = check
            tool_flow.addWidget(check)
        tool_widget = QWidget()
        tool_widget.setLayout(tool_flow)
        layout.addWidget(tool_widget)

        actions = QHBoxLayout()
        actions.setSpacing(8)
        save_btn = QPushButton("保存代理配置")
        save_btn.setObjectName("ghbtn")
        save_btn.clicked.connect(self._save_proxy_pool)
        actions.addWidget(save_btn)
        fetch_btn = QPushButton("获取并检测代理")
        fetch_btn.setObjectName("ghbtn-primary")
        fetch_btn.clicked.connect(self._fetch_proxies)
        actions.addWidget(fetch_btn)
        check_btn = QPushButton("检测现有代理")
        check_btn.setObjectName("ghbtn")
        check_btn.clicked.connect(self._check_proxies)
        actions.addWidget(check_btn)
        actions.addStretch(1)
        layout.addLayout(actions)

        self.proxy_status_label = QLabel("")
        self.proxy_status_label.setObjectName("caption")
        self.proxy_status_label.setWordWrap(True)
        layout.addWidget(self.proxy_status_label)

        self._on_proxy_enabled(bool(cfg.get("enabled", False)))
        return card

    def _on_proxy_enabled(self, checked: bool) -> None:
        for w in (self.proxy_protocol_combo, self.proxy_timeout_spin,
                  self.proxy_threads_spin, self.proxy_max_spin,
                  self.proxy_manual_edit):
            w.setEnabled(checked)
        for check in self._proxy_source_checks.values():
            check.setEnabled(checked)
        # 按工具代理开关：仅当全局代理启用时才有意义
        for check in self._proxy_tool_checks.values():
            check.setEnabled(checked)

    @staticmethod
    def _select_data(combo, value) -> None:
        for i in range(combo.count()):
            if combo.itemData(i) == value:
                combo.setCurrentIndex(i)
                return

    def _collect_proxy_cfg(self) -> dict:
        return {
            "enabled": self.proxy_enabled_check.isChecked(),
            "protocol": self.proxy_protocol_combo.currentData(),
            "sources": [name for name, check in self._proxy_source_checks.items()
                        if check.isChecked()],
            "manual": self.proxy_manual_edit.toPlainText(),
            "timeout": float(self.proxy_timeout_spin.value()),
            "threads": self.proxy_threads_spin.value(),
            "max_proxies": self.proxy_max_spin.value(),
            # 按工具代理开关：仅记录被取消勾选（直连）的工具
            "tool_proxy": {tool_id: False for tool_id, check in
                           self._proxy_tool_checks.items() if not check.isChecked()},
        }

    def _save_proxy_pool(self) -> None:
        cfg = self._collect_proxy_cfg()
        # 保留已有的已验证代理缓存（cache 由代理池拉取/失效时自动写回）
        existing = self.store.get("proxy_pool", default={}) or {}
        cache = existing.get("cache") if isinstance(existing, dict) else []
        cfg["cache"] = list(cache) if isinstance(cache, list) else []
        self.store.set(cfg, "proxy_pool")
        try:
            self.store.save()
        except OSError as exc:
            self.proxy_status_label.setText(f"保存失败：{exc}")
            return
        proxy_pool.load_config(cfg)
        status = proxy_pool.proxy_status()
        self.proxy_status_label.setText(
            f"已保存。当前池：{status['total']} 个，可用 {status['alive']} 个。"
            f"（{'已启用，Web 工具将走代理' if cfg['enabled'] else '未启用，Web 工具直连'}）")

    def _fetch_proxies(self) -> None:
        """保存配置后从免费源拉取并验证代理。"""
        self._save_proxy_pool()
        if not self.proxy_enabled_check.isChecked():
            self.proxy_status_label.setText("请先勾选「启用 Web 工具代理池」再获取代理。")
            return
        self.proxy_status_label.setText("正在从免费源拉取并验证代理…")
        worker = _ProxyFetchWorker()
        worker.done_ok.connect(self._on_proxy_fetched)
        worker.done_err.connect(lambda m: self.proxy_status_label.setText(m))
        self._proxy_worker = worker
        worker.start()

    def _check_proxies(self) -> None:
        """检测池内现有代理是否可用（不重新拉取）。"""
        proxy_pool.load_config(self._collect_proxy_cfg())
        status = proxy_pool.proxy_status()
        if status["total"] == 0:
            self.proxy_status_label.setText("池内没有代理，请先「获取并检测代理」。")
            return
        self.proxy_status_label.setText(
            f"当前池：共 {status['total']} 个，可用 {status['alive']} 个，"
            f"已死 {status['dead']} 个。")

    def _on_proxy_fetched(self, result: dict) -> None:
        self.proxy_status_label.setText(
            f"完成：拉取 {result.get('fetched', 0)} 条，验证可用 {result.get('alive', 0)} 个"
            + (f"，剔除假代理 {result.get('fake', 0)} 个"
               if result.get('fake') else "") + "。")

    # ------------------------------------------------------- 水印输出位置
    def _build_watermark(self) -> QWidget:
        card = self._card()
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(10)

        form = QHBoxLayout()
        form.setSpacing(8)
        form.addWidget(QLabel("输出位置"))

        wm = self.store.get("watermark", default={}) or {}
        self.wm_outdir_edit = QLineEdit(str(wm.get("output_dir", "")))
        self.wm_outdir_edit.setPlaceholderText(watermark.DEFAULT_OUTPUT_DIR)
        form.addWidget(self.wm_outdir_edit, stretch=1)

        browse_btn = QPushButton("浏览…")
        browse_btn.setObjectName("ghbtn")
        browse_btn.clicked.connect(self._browse_wm_outdir)
        form.addWidget(browse_btn)

        save_btn = QPushButton("保存")
        save_btn.setObjectName("ghbtn-primary")
        save_btn.clicked.connect(self._save_wm_outdir)
        form.addWidget(save_btn)
        layout.addLayout(form)

        self.wm_outdir_preview = QLabel("")
        self.wm_outdir_preview.setObjectName("caption")
        self.wm_outdir_preview.setWordWrap(True)
        layout.addWidget(self.wm_outdir_preview)
        self.wm_outdir_edit.textChanged.connect(self._update_wm_preview)
        return card

    def _browse_wm_outdir(self) -> None:
        initial = self._wm_outdir_absolute() or str(watermark.app_root())
        path = QFileDialog.getExistingDirectory(self, "选择输出目录", initial)
        if path:
            self.wm_outdir_edit.setText(path)

    def _wm_outdir_absolute(self) -> str:
        raw = self.wm_outdir_edit.text().strip()
        if not raw:
            return str(watermark.app_root() / watermark.DEFAULT_OUTPUT_DIR)
        path = Path(raw)
        return str(path if path.is_absolute() else watermark.app_root() / path)

    def _update_wm_preview(self) -> None:
        raw = self.wm_outdir_edit.text().strip()
        if not raw:
            text = f"（留空使用默认值）实际路径：{self._wm_outdir_absolute()}"
        else:
            text = f"实际路径：{self._wm_outdir_absolute()}"
        self.wm_outdir_preview.setText(text)

    def _save_wm_outdir(self) -> None:
        raw = self.wm_outdir_edit.text().strip() or watermark.DEFAULT_OUTPUT_DIR
        self.store.setv(raw, "watermark", "output_dir")
        try:
            self.store.save()
            resolved = watermark.resolve_output_dir(raw)
        except OSError as exc:
            QMessageBox.warning(self, "保存失败", f"输出目录不可用：{exc}")
            return
        self.wm_outdir_preview.setText(f"已保存。实际路径：{resolved}")

    # ----------------------------------------------------------- 压缩包工具
    def _build_zip_crack(self) -> QWidget:
        card = self._card()
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(10)

        form = QHBoxLayout()
        form.setSpacing(8)
        form.addWidget(QLabel("输出位置"))

        zc_cfg = self.store.get("zip_crack", default={}) or {}
        self.zc_outdir_edit = QLineEdit(str(zc_cfg.get("output_dir", "")))
        self.zc_outdir_edit.setPlaceholderText(watermark.DEFAULT_OUTPUT_DIR)
        form.addWidget(self.zc_outdir_edit, stretch=1)

        browse_btn = QPushButton("浏览…")
        browse_btn.setObjectName("ghbtn")
        browse_btn.clicked.connect(self._browse_zc_outdir)
        form.addWidget(browse_btn)

        save_btn = QPushButton("保存")
        save_btn.setObjectName("ghbtn-primary")
        save_btn.clicked.connect(self._save_zc_outdir)
        form.addWidget(save_btn)
        layout.addLayout(form)

        self.zc_outdir_preview = QLabel("")
        self.zc_outdir_preview.setObjectName("caption")
        self.zc_outdir_preview.setWordWrap(True)
        layout.addWidget(self.zc_outdir_preview)
        self.zc_outdir_edit.textChanged.connect(self._update_zc_preview)
        return card

    def _browse_zc_outdir(self) -> None:
        initial = self._zc_outdir_absolute() or str(watermark.app_root())
        path = QFileDialog.getExistingDirectory(self, "选择输出目录", initial)
        if path:
            self.zc_outdir_edit.setText(path)

    def _zc_outdir_absolute(self) -> str:
        raw = self.zc_outdir_edit.text().strip()
        if not raw:
            return str(watermark.app_root() / watermark.DEFAULT_OUTPUT_DIR)
        path = Path(raw)
        return str(path if path.is_absolute() else watermark.app_root() / path)

    def _update_zc_preview(self) -> None:
        raw = self.zc_outdir_edit.text().strip()
        if not raw:
            text = f"（留空使用默认值）实际路径：{self._zc_outdir_absolute()}"
        else:
            text = f"实际路径：{self._zc_outdir_absolute()}"
        self.zc_outdir_preview.setText(text)

    def _save_zc_outdir(self) -> None:
        raw = self.zc_outdir_edit.text().strip() or watermark.DEFAULT_OUTPUT_DIR
        self.store.setv(raw, "zip_crack", "output_dir")
        try:
            self.store.save()
            resolved = watermark.resolve_output_dir(raw)
        except OSError as exc:
            QMessageBox.warning(self, "保存失败", f"输出目录不可用：{exc}")
            return
        self.zc_outdir_preview.setText(f"已保存。实际路径：{resolved}")

    # ----------------------------------------------------------- Payload 编译器
    def _build_payload_compiler(self) -> QWidget:
        card = self._card()
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(10)

        layout.addWidget(self._caption_note(
            "配置 Payload 编译器各语言的解释器 / 编译器路径；留空则自动探测 "
            "系统 PATH 中的命令（javac / java / php / python）。"))

        cfg = self.store.get("payload_compiler", default={}) or {}
        self._pc_edits: dict[str, QLineEdit] = {}
        fields = (
            ("java_compiler", "Java 编译器（javac）"),
            ("java_runner", "Java 运行器（java）"),
            ("php_path", "PHP 解释器（php）"),
            ("python_path", "Python 解释器（python）"),
        )
        for key, label in fields:
            row = QHBoxLayout()
            row.setSpacing(8)
            row.addWidget(QLabel(label))
            edit = QLineEdit(str(cfg.get(key, "")))
            edit.setPlaceholderText("留空自动探测")
            row.addWidget(edit, stretch=1)
            browse = QPushButton("浏览…")
            browse.setObjectName("ghbtn")
            browse.clicked.connect(
                lambda _c=False, e=edit: self._browse_pc_path(e))
            row.addWidget(browse)
            layout.addLayout(row)
            self._pc_edits[key] = edit

        save_btn = QPushButton("保存")
        save_btn.setObjectName("ghbtn-primary")
        save_btn.clicked.connect(self._save_payload_compiler)
        layout.addWidget(save_btn, 0, Qt.AlignmentFlag.AlignRight)
        return card

    def _caption_note(self, text: str) -> QLabel:
        label = QLabel(text)
        label.setObjectName("caption")
        label.setWordWrap(True)
        return label

    def _browse_pc_path(self, edit: QLineEdit) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "选择解释器 / 编译器", edit.text().strip() or "", "所有文件 (*)")
        if path:
            edit.setText(path)

    def _save_payload_compiler(self) -> None:
        values = {key: edit.text().strip()
                  for key, edit in self._pc_edits.items()}
        self.store.setv(values, "payload_compiler")
        self.store.save()
        QMessageBox.information(self, "已保存", "Payload 编译器解释器配置已保存。")

    # ----------------------------------------------------------- 收尾
    def shutdown(self) -> None:
        for worker in (self._proxy_worker, self._models_worker):
            if worker is not None and worker.isRunning():
                if hasattr(worker, "stop"):
                    worker.stop()
                worker.wait(2000)
