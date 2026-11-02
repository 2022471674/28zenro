# -*- coding: utf-8 -*-
"""工具模块目录：用 ``@tool`` 装饰器注册的工具模块放这里。

本目录下的每个 ``.py``（非下划线开头）会在应用启动时被 :func:`app.registry.discover_tools`
自动导入，模块内的 :func:`app.registry.tool` 装饰器会顺带把工具登记进注册表，
无需在 registry 的集中式清单里手动追加。

约定：
- 文件名即模块名，工具 id 建议与模块内函数名 / 显式 id 保持一致；
- 工具逻辑本身应是纯函数（数据进、结果出），不 import 任何 UI 模块；
- 需要额外输入参数时用 :class:`app.registry.ParamSpec` 声明，界面自动渲染。
"""
