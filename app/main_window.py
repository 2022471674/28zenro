# -*- coding: utf-8 -*-
from __future__ import annotations

from functools import partial

from PySide6.QtGui import QCursor
from PySide6.QtWidgets import QApplication, QVBoxLayout, QWidget

from qfluentwidgets import (
    FluentIcon,
    FluentWindow,
    NavigationAvatarWidget,
    NavigationItemPosition,
    NavigationTreeWidget,
)

from app import registry
from app import runtime_log
from app import theme as theme_module
from app.pages.about_page import AVATAR_PATH, AboutPage
from app.pages.home import HomePage
from app.pages.runtime_log_page import RuntimeLogPage
from app.pages.settings_page import SettingsPage
from app.widgets.tool_page import ToolPanel


#: 分类 -> 侧边栏子工具图标（子列表条目用一个统一的小图标）
_CATEGORY_ICONS = {
    registry.CATEGORY_FUZZ: FluentIcon.SEARCH,
    registry.CATEGORY_CRYPTO: FluentIcon.CODE,
    registry.CATEGORY_HASH: FluentIcon.DICTIONARY,
    registry.CATEGORY_GM: FluentIcon.CERTIFICATE,
    registry.CATEGORY_NUMBER: FluentIcon.UNIT,
    registry.CATEGORY_STRING: FluentIcon.FONT,
    registry.CATEGORY_CHAR: FluentIcon.EDIT,
    registry.CATEGORY_JWT: FluentIcon.TAG,
    registry.CATEGORY_TRANSLATE: FluentIcon.LANGUAGE,
    registry.CATEGORY_WEB: FluentIcon.GLOBE,
    registry.CATEGORY_TOOLS: FluentIcon.APPLICATION,
    registry.CATEGORY_EFFICIENCY: FluentIcon.STOP_WATCH,
    registry.CATEGORY_TRANSFER: FluentIcon.SHARE,
    registry.CATEGORY_PAYLOAD: FluentIcon.CODE,
    registry.CATEGORY_MCP: FluentIcon.ROBOT,
    registry.CATEGORY_FUN: FluentIcon.PHOTO,
}


class _LazyToolHost(QWidget):
    """惰性工具页宿主：首次显示（showEvent）时才实例化真实页面。

    启动时只为每个工具建一个空壳控件（省掉 ~36 个页面的构造时间与
    常驻内存），用户第一次切到该工具时再调用工厂构建真页面并填进来。
    工厂闭包引用 :class:`MainWindow` 的当前 ``theme``，保证构建时用的
    是最新调色板；未构建期间收到的主题切换会在构建后由工厂自然生效。
    """

    def __init__(self, factory, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._factory = factory
        self._inner: QWidget | None = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

    def ensure_built(self) -> QWidget | None:
        """构建真实页面（幂等）；返回内部控件（尚未构建过则先构建）。"""
        if self._inner is None:
            self._inner = self._factory()
            self.layout().addWidget(self._inner)
        return self._inner

    def showEvent(self, event) -> None:  # noqa: N802  Qt 命名约定
        self.ensure_built()
        super().showEvent(event)

    # ------- 以下三个转发让 MainWindow 无感知地继续遍历 _tool_widgets -------
    def set_theme(self, palette) -> None:
        if self._inner is not None:
            apply = getattr(self._inner, "set_theme", None)
            if callable(apply):
                apply(palette)
            elif hasattr(self._inner, "theme"):
                self._inner.theme = palette

    def shutdown(self) -> None:
        if self._inner is not None:
            stop = getattr(self._inner, "shutdown", None)
            if callable(stop):
                stop()


class MainWindow(FluentWindow):
    """应用主窗：单窗口 + 侧边栏手风琴，每个子工具都是侧边栏上的独立条目。"""

    def __init__(self, theme, store) -> None:
        super().__init__()
        self.theme = theme
        self.store = store

        #: tool_id -> 承载控件（独立页面、通用面板或惰性宿主）
        self._tool_widgets: dict[str, object] = {}
        #: hub -> 侧边栏手风琴父节点
        self._hub_parents: dict[str, NavigationTreeWidget] = {}

        # 不设置窗口标题文字（标题栏不显示 cipherNest 商标），
        # 仅保留窗口图标与左上角头像卡片。
        self.setWindowTitle("")
        theme_module.apply_window_background(self, theme)
        self._apply_window_geometry()

        self._build_pages()
        self._build_navigation()

        self.settings_page.theme_changed.connect(self._on_theme_changed)
        self.home_page.open_tool.connect(self._open_tool)

        runtime_log.install_logging_bridge()
        runtime_log.info("程序启动完成")

    # 14/16 英寸笔记本常见可用高度只有 728~768px，最小高度必须留够余量，
    # 否则窗口比屏幕还大、底部控件被任务栏压住。
    _MIN_W = 900
    _MIN_H = 560
    _DEF_W = 1200
    _DEF_H = 800
    _SCREEN_MARGIN = 24
    _SMALL_SCREEN_W = 1440
    _SMALL_SCREEN_H = 900

    def _target_screen(self):
        screen = QApplication.screenAt(QCursor.pos())
        if screen is None:
            screen = QApplication.primaryScreen()
        return screen

    def _apply_window_geometry(self) -> None:
        screen = self._target_screen()
        want_w = int(self.store.get("window_width", default=self._DEF_W)
                     or self._DEF_W)
        want_h = int(self.store.get("window_height", default=self._DEF_H)
                     or self._DEF_H)
        min_w, min_h = self._MIN_W, self._MIN_H

        if screen is not None:
            avail = screen.availableGeometry()
            max_w = max(480, avail.width() - self._SCREEN_MARGIN)
            max_h = max(360, avail.height() - self._SCREEN_MARGIN)
            min_w = min(min_w, max_w)
            min_h = min(min_h, max_h)
            want_w = min(want_w, max_w)
            want_h = min(want_h, max_h)
            if avail.width() <= self._SMALL_SCREEN_W or avail.height() <= self._SMALL_SCREEN_H:
                want_w, want_h = avail.width(), avail.height()

        self.setMinimumSize(min_w, min_h)
        self.resize(want_w, want_h)

        if screen is not None:
            avail = screen.availableGeometry()
            x = avail.x() + max(0, (avail.width() - want_w) // 2)
            y = avail.y() + max(0, (avail.height() - want_h) // 2)
            self.move(x, y)

        if not bool(self.store.get("window_resizable", default=True)):
            self.setFixedSize(want_w, want_h)

    # ------------------------------------------------------------- 页面装配
    def _register(self, tool_id: str, widget) -> None:
        """登记一个工具控件并给唯一 objectName（供侧边栏 routeKey 使用）。"""
        widget.setObjectName(f"tool_{tool_id}")
        self._tool_widgets[tool_id] = widget

    def _build_pages(self) -> None:
        s = self.store

        self.home_page = HomePage(self.theme, s)
        self.home_page.setObjectName("homePage")

        self.about_page = AboutPage(self.theme, s)
        self.about_page.setObjectName("aboutPage")
        self.settings_page = SettingsPage(self.theme, s)
        self.settings_page.setObjectName("settingsPage")
        self.runtime_log_page = RuntimeLogPage(self.theme, s)
        self.runtime_log_page.setObjectName("runtimeLogPage")

        # 登记全部工具控件：注册成「惰性宿主」—— 首次进入该工具时才
        # import + 实例化页面类（或 ToolPanel 通用面板）。启动只建空壳，
        # 首屏时间和常驻内存不再随工具数量线性增长。
        for tool in registry.REGISTRY:
            if tool.page:
                def page_factory(tool_ref=tool, kwargs=dict(tool.page_kwargs)):
                    page_cls = registry._resolve_page_ref(tool_ref.page)
                    return page_cls(self.theme, s, **kwargs)
                host_factory = page_factory
            elif tool.kind in (registry.KIND_ONE_WAY, registry.KIND_TWO_WAY,
                               registry.KIND_DIFF):
                def panel_factory(tool_ref=tool):
                    return ToolPanel(self.theme, tool_ref)
                host_factory = panel_factory
            else:
                continue
            self._register(tool.id, _LazyToolHost(host_factory, self))

    # ------------------------------------------------------------- 导航
    def _build_navigation(self) -> None:
        nav = self.navigationInterface
        nav.setExpandWidth(220)

        # 侧边栏默认展开、不折叠：隐藏汉堡（折叠）按钮与返回按钮，
        # 并禁用折叠能力，避免用户误触导致导航收起。
        nav.setMenuButtonVisible(False)
        nav.setReturnButtonVisible(False)
        nav.setCollapsible(False)

        # 侧边栏顶部 header：头像 + 昵称占位卡片，撑出与首个列表项的视觉间距
        nav.addWidget(
            "authorHeader",
            NavigationAvatarWidget("28.7", str(AVATAR_PATH)),
            onClick=lambda: self.switchTo(self.about_page),
        )

        scroll = NavigationItemPosition.SCROLL

        # 首页（固定在顶部，不随工具区滚动）
        self.addSubInterface(self.home_page, FluentIcon.HOME, "首页")

        # 快捷访问：独立侧边栏入口（不在手风琴里，点开就是链接收藏页）
        quick_widget = self._tool_widgets.get("quick_access")
        if quick_widget is not None:
            self.addSubInterface(
                quick_widget, FluentIcon.LINK, "快捷访问", position=scroll)

        # 工具大类：手风琴父节点（不可选中，点击只展开 / 收起子列表）
        hub_icons = {
            registry.HUB_CRYPTO: FluentIcon.CERTIFICATE,
            registry.HUB_WEB: FluentIcon.GLOBE,
            registry.HUB_MISC: FluentIcon.APPLICATION,
            registry.HUB_PAYLOAD: FluentIcon.CODE,
            registry.HUB_MCP: FluentIcon.ROBOT,
            registry.HUB_ENTER: FluentIcon.PHOTO,
        }
        for hub, label in registry.HUBS:
            parent = nav.addItem(
                f"hub-{hub}", hub_icons[hub], label,
                selectable=False, position=scroll,
            )
            parent.clicked.connect(partial(self._on_hub_clicked, hub))
            self._hub_parents[hub] = parent

            # 子工具：每个都是侧边栏上的独立条目，主区直接切换到对应控件
            for tool in registry.tools_of_hub(hub):
                widget = self._tool_widgets.get(tool.id)
                if widget is None:
                    continue
                icon = _CATEGORY_ICONS.get(
                    tool.category, FluentIcon.APPLICATION)
                self.addSubInterface(
                    widget, icon, tool.name,
                    position=scroll, parent=f"hub-{hub}",
                )

        # 运行日志 / 关于 / 设置固定在最底部（设置在最末）
        self.addSubInterface(
            self.runtime_log_page, FluentIcon.HISTORY, "运行日志",
            position=NavigationItemPosition.BOTTOM,
        )
        self.addSubInterface(
            self.about_page, FluentIcon.INFO, "关于",
            position=NavigationItemPosition.BOTTOM,
        )
        self.addSubInterface(
            self.settings_page, FluentIcon.SETTING, "设置",
            position=NavigationItemPosition.BOTTOM,
        )

    # ----------------------------------------------------------- 手风琴互斥
    def _set_active_hub(self, hub: str | None) -> None:
        """展开 ``hub`` 并收起其它手风琴（``None`` 表示全部收起）。

        供程序化跳转（首页卡片 / 关于页链接）使用。
        """
        for key, parent in self._hub_parents.items():
            parent.setExpanded(key == hub, ani=True)

    def _on_hub_clicked(self, hub: str, _triggered=False) -> None:
        """点击手风琴头部：仅收起其它手风琴。

        被点击的手风琴自身展开 / 收起由 qfluentwidgets 的
        ``NavigationTreeWidget._onClicked`` 在发出 ``clicked`` 之前已经
        完成，这里不能再重复切换它，否则会互相抵消；只负责互斥地收起兄弟节点。
        """
        for key, parent in self._hub_parents.items():
            if key != hub:
                parent.setExpanded(False, ani=True)

    # ----------------------------------------------------------- 信号处理
    def _on_theme_changed(self, mode: str) -> None:
        app = QApplication.instance()
        if app is not None:
            from qfluentwidgets import Theme, setTheme
            setTheme(Theme.DARK if mode == theme_module.THEME_DARK else Theme.LIGHT)
            palette = theme_module.apply_theme(
                app, mode, theme_module.overrides_from_store(self.store, mode))
        else:
            palette = theme_module.palette_from_store(self.store, mode)
        self.theme = palette
        theme_module.apply_window_background(self, palette)

        for widget in (self.home_page, self.about_page, self.settings_page,
                       self.runtime_log_page, *self._tool_widgets.values()):
            if hasattr(widget, "set_theme"):
                widget.set_theme(palette)
            elif hasattr(widget, "theme"):
                widget.theme = palette
        runtime_log.info(f"主题切换为 {mode}")

    def _open_tool(self, tool_id: str) -> None:
        """首页卡片 / 关于页链接跳转：定位到手风琴并切到对应工具。"""
        tool = registry.get_tool(tool_id)
        widget = self._tool_widgets.get(tool_id)
        if tool is None or widget is None:
            return
        self._set_active_hub(tool.hub_key)
        self.switchTo(widget)

    # ----------------------------------------------------------- 生命周期
    def closeEvent(self, event) -> None:  # noqa: N802  Qt 命名约定
        runtime_log.info("程序退出")
        self.store.setv(self.width(), "window_width")
        self.store.setv(self.height(), "window_height")
        self.store.save()
        for widget in self._tool_widgets.values():
            shutdown = getattr(widget, "shutdown", None)
            if callable(shutdown):
                shutdown()
        self.settings_page.shutdown()
        super().closeEvent(event)
