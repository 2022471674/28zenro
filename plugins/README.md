# -*- coding: utf-8 -*-
"""插件目录：第三方工具模块放这里，应用启动时自动发现。

把单个 ``.py`` 文件丢进本目录（或 ``app/tools/``），文件内用
``@tool`` 装饰器注册工具，即可被识别并出现在对应分类里，无需修改主仓库代码。

- 文件名即模块名（非 ``_`` 开头）；
- 用 ``from app.registry import tool, CATEGORY_*, ParamSpec`` 声明工具；
- 工具函数应为纯函数（数据进、结果出），不 import UI 模块。

示例见 ``hello_plugin.py``。
"""
