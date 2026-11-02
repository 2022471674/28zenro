# -*- mode: python ; coding: utf-8 -*-
# cipherNest v2 文件夹模式打包配置：输出 dist/cipherNest/ 目录，
# 启动快、无需解压，适合本地分发。
# 运行：python -m PyInstaller cipherNest_onedir.spec --noconfirm
#
# 目录里有两个 exe：
# - cipherNest.exe     —— GUI 主程序（main.py，console=False）；
# - cipherNestMcp.exe  —— MCP 服务子进程（mcp/mcp_server_entry.py，
#   console=True）。GUI 在冻结态用 sys.executable 拼
#   ``<exe> mcp/server.py`` 是不可行的（只会再开一个 GUI 实例，
#   QtWebEngine 缓存互相冲突），必须有独立的服务程序。
#   两个 exe 共享同一个 ``_internal``（_MEIPASS），字典 / lib/img /
#   mcp/plugins 数据只需在 GUI 端打一份；MCP 端没有 Qt。

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[('static', 'static'), ('dict', 'dict'), ('lib/img', 'lib/img')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # 本项目只依赖 PySide6 / qfluentwidgets / requests / bs4 / pillow / cryptography，
    # 系统 Python 环境里还装了大量无关包，这里显式排除，避免 PyInstaller 顺着
    # 第三方 hook 把无关依赖打进包（体积膨胀 + 无谓的启动扫描）。
    excludes=[
        # GUI 冗余：本应用基于 PySide6
        'tkinter', 'PyQt4', 'PyQt5', 'PyQt6', 'wx', 'gtk',
        # 数值/科学计算（Pillow 的可选依赖，不需要）
        'numpy', 'scipy', 'pandas', 'matplotlib',
        # 重量级 ML / 数据栈（环境里存在但项目从不 import）
        'torch', 'tensorflow', 'keras', 'jax', 'sklearn',
        # 开发/调试/文档工具链
        'IPython', 'jedi', 'setuptools', 'pip', 'wheel',
        'pytest', 'unittest2', 'sphinx', 'black', 'mypy', 'flake8',
        # 其他常见误拉
        'notebook', 'tornado', 'uvloop',
        # bs4 的可选解析器（代码里固定用 html.parser）+ 网络栈冗余
        'lxml', 'html5lib', 'chardet', 'h2', 'hyperframe', 'hpack',
    ],
    noarchive=False,
    optimize=1,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='cipherNest',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['static/favicon_256.ico'],
)

# --------------------------------------------------------------------------
# MCP 服务子进程：入口 mcp/mcp_server_entry.py（无 Qt、命令行参数直接透传）
# --------------------------------------------------------------------------
am = Analysis(
    ['mcp/mcp_server_entry.py'],
    pathex=['mcp'],
    binaries=[],
    # 精简版默认**不带** mcp/plugins（OneForAll 173MB + trufflehog 169MB 等
    # 第三方工具，缺席时相关 op 报错但主功能无损）。带插件的分支版用
    # cipherNest_onedir_full.spec（仅多这一条 datas）；
    # 手工恢复：把源码 mcp/plugins 拷到 <包>/_internal/mcp/plugins。
    datas=[],
    # ops / pluginkit 的子模块都是 importlib.import_module 动态加载的，
    # 静态分析跟不到，必须显式携带；ciphernest_mcp 顶层也要点名（wrapper
    # 里是函数内延迟导入）。
    hiddenimports=[
        'ciphernest_mcp',
        'ciphernest_mcp.bootstrap', 'ciphernest_mcp.cli',
        'ciphernest_mcp.contract', 'ciphernest_mcp.docgen',
        'ciphernest_mcp.envelope', 'ciphernest_mcp.selftest',
        'ciphernest_mcp.ops',
        'ciphernest_mcp.ops.help', 'ciphernest_mcp.ops.codec',
        'ciphernest_mcp.ops.data', 'ciphernest_mcp.ops.crypto',
        'ciphernest_mcp.ops.image', 'ciphernest_mcp.ops.web',
        'ciphernest_mcp.ops.requester', 'ciphernest_mcp.ops.scan',
        'ciphernest_mcp.ops.attack', 'ciphernest_mcp.ops.llm',
        'ciphernest_mcp.ops.misc', 'ciphernest_mcp.ops._helpers',
        'ciphernest_mcp.pluginkit',
        'ciphernest_mcp.pluginkit._paths', 'ciphernest_mcp.pluginkit.runtime',
        'ciphernest_mcp.pluginkit.generic', 'ciphernest_mcp.pluginkit.sqlmap',
        'ciphernest_mcp.pluginkit.trufflehog',
        'ciphernest_mcp.pluginkit.oneforall',
        'ciphernest_mcp.pluginkit.flaskcookie',
        'ciphernest_mcp.pluginkit.filesensor',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # MCP 子进程绝不引入 GUI 栈（分析期被误跟进去时兜底）
        'PySide6', 'PyQt5', 'tkinter',
        # 本项目运行链实证不使用（bs4 / PIL / uvicorn 等的条件 import 被
        # 静态扫到而误拉），与 GUI 端同一张黑名单：
        'numpy', 'numpy.libs', 'scipy', 'pandas', 'matplotlib',
        'torch', 'tensorflow', 'keras', 'jax', 'sklearn',
        'IPython', 'jedi', 'setuptools', 'pip', 'wheel',
        'pytest', 'unittest2', 'sphinx', 'black', 'mypy', 'flake8',
        'notebook', 'tornado', 'uvloop',
        'lxml', 'html5lib', 'chardet', 'h2', 'hyperframe', 'hpack',
        'boto3', 'botocore', 's3transfer', 'jmespath', 'grpc',
    ],
    noarchive=False,
    optimize=1,
)
pyzm = PYZ(am.pure)

exem = EXE(
    pyzm,
    am.scripts,
    [],
    exclude_binaries=True,
    name='cipherNestMcp',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    # console=True：stdout/stderr 走管道回传 GUI 日志区；GUI 侧 Popen 用
    # CREATE_NO_WINDOW 拉起，不会弹出黑窗。它同时方便手工执行
    # ``cipherNestMcp.exe --selftest`` 做打包自检。
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['static/favicon_256.ico'],
)

coll = COLLECT(
    exe,
    exem,
    a.binaries,
    a.datas,
    am.binaries,
    am.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='cipherNest',
)
