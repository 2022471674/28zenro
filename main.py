# -*- coding: utf-8 -*-
"""cipherNest 入口：PySide6 + QFluentWidgets 单窗体应用。

启动流程：
1. 创建 ``QApplication``；
2. ``SettingsStore`` 加载用户配置（不存在则用内置默认值）；
3. ``apply_theme`` 应用 GitHub 明 / 暗主题（QSS + QPalette），
   QFluentWidgets 自身同步 ``setTheme``；
4. ``MainWindow`` 装配首页与全部工具页，进入事件循环。
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from PySide6.QtCore import QTimer  # noqa: E402
from PySide6.QtGui import QIcon  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from qfluentwidgets import Theme, setTheme  # noqa: E402

from app import theme as theme_module  # noqa: E402
from app.main_window import MainWindow  # noqa: E402
from app.store import SettingsStore  # noqa: E402


def _icon_path() -> Path | None:
    """窗口图标路径：开发态取项目 ``static``，冻结态取打包数据根。

    打包脚本只生成带尺寸后缀的 ico（``favicon_256.ico`` 为多分辨率合集，
    窗口 / 任务栏 / Alt+Tab 各取合适尺寸），候选链按优先级依次回退；
    都不存在时返回 ``None``（main 里跳过 setWindowIcon，不报错）。
    """
    from lib.runtime_paths import find_resource

    return find_resource("static/favicon.ico", "static/favicon_256.ico",
                         "static/favicon_128.ico")


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("cipherNest")
    app.setOrganizationName("cipherNest")

    # 任务栏 / Alt+Tab / 窗口标题栏图标：exe 内嵌图标只作用于资源管理器层，
    # Qt 窗口必须显式 setWindowIcon，否则任务栏显示空白图标。
    icon_file = _icon_path()
    if icon_file is not None and icon_file.is_file():
        app.setWindowIcon(QIcon(str(icon_file)))

    store = SettingsStore()
    mode = store.get("theme_mode", default="light")
    # 先应用 QFluentWidgets 主题（会向各控件写入 QSS），再用应用级 QSS 覆盖
    setTheme(Theme.DARK if mode == theme_module.THEME_DARK else Theme.LIGHT)
    theme_module.apply_theme(app, mode)

    # 加载全局代理池配置（Web 工具统一走代理的前提）
    from lib import proxy_pool  # noqa: E402
    proxy_pool.load_config(store.get("proxy_pool", default={}))
    # 注入「已验证代理」持久化回调：代理获取/失效后立即写回 config.json
    def _save_proxy_cache(keys) -> None:
        store.set(list(keys), "proxy_pool", "cache")
        store.save()
    proxy_pool.set_cache_saver(_save_proxy_cache)

    window = MainWindow(theme_module.palette_from_store(store, mode), store)

    # 启动动画：圆形头像 + 「28.7」+ 随机言语，主窗就绪后淡出
    from app.splash import SplashScreen  # noqa: E402
    palette = theme_module.palette_from_store(store, mode)
    splash = SplashScreen(palette)
    splash.show_centered()

    def _finish() -> None:
        # 淡出动画结束后：关闭 splash、显示主窗、释放 splash（内部统一处理）
        splash.fade_out_and_close(window.show)

    # 给主窗一个首帧渲染的间隙（让 splash 先稳稳显示），再淡出并显示主窗
    QTimer.singleShot(900, _finish)

    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
