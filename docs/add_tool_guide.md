# cipherNest 新增工具/方法完整流程

> 以「原神随机壁纸」为实例。项目已完成「插槽化」改造：新增任何工具（纯函数型
> 或页面型）都**只需写一个文件**，无需改主仓库代码。本文档分「页面型工具」和
> 「纯函数型工具」两条路径，最后附可选的 CLI/MCP 扩展与验证清单。

---

## 一、整体架构

一个功能从底层到界面是三层串联，**只依赖下层，互不反向依赖**：

```
lib/xxx.py               ← 纯函数层（真正的"方法"逻辑，禁止 import 任何 UI 库）
   │
   ├─→ app/registry.py    @tool 装饰器 / ToolSpec 登记 → 自动发现
   ├─→ app/main_window.py 遍历 REGISTRY 自动实例化页面 → 侧边栏/首页显示
   ├─→ cli.py             @_register("id") → 命令行子命令（可选）
   └─→ mcp_server.py      @mcp.tool()     → MCP 工具（可选，给 Agent 调用）
```

**关键设计：插槽机制**

`app/registry.py` 里有一套「自动发现」机制：`discover_tools()` 会扫描
`app/tools/` 与 `plugins/` 目录下所有非 `_` 开头的 `.py` 文件，导入时
`@tool(...)` 装饰器自动把工具登记进注册表。`main_window.py` 遍历注册表
自动实例化控件。因此：

> **加工具 = 加一个文件，重启即生效。不碰 registry 清单、不碰 main_window。**

---

## 二、页面型工具（完整实例：原神随机壁纸）

页面型工具（`KIND_PAGE` / `KIND_EMBEDDED`）需要写一个 `QWidget` 页面类，
并用 `@tool(..., page="模块:类名")` 挂载。**一个文件搞定**，页面类和注册
声明放一起（推荐放 `app/tools/` 或 `plugins/`）。

### 完整示例：`plugins/gensh_wallpaper.py`

```python
# -*- coding: utf-8 -*-
"""原神随机壁纸页：进入即自动拉取一张，右侧展示，可换一张 / 保存。"""
from __future__ import annotations

import requests

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import QLabel, QPushButton, QVBoxLayout, QWidget

from app.registry import CATEGORY_FUN, KIND_PAGE, tool

URI = "https://v2.xxapi.cn/api/ys?return=json"


def _download_wallpaper() -> bytes:
    """请求接口拿到图片直链，再下载图片字节。"""
    rep = requests.get(URI, timeout=10)
    rep.raise_for_status()
    url = rep.json().get("data", "")
    if not url:
        raise RuntimeError("接口未返回图片地址")
    return requests.get(url, timeout=10).content


class _Worker(QThread):
    done_ok = Signal(bytes)
    done_err = Signal(str)

    def run(self) -> None:
        try:
            data = _download_wallpaper()
        except Exception as exc:  # noqa: BLE001
            self.done_err.emit(str(exc))
            return
        self.done_ok.emit(data)


class GenshWallpaperPage(QWidget):
    def __init__(self, theme, store, parent=None):
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._worker = None
        self._build_ui()
        self._fetch()  # 进入页面立即获取

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        self.reload_btn = QPushButton("换一张")
        self.reload_btn.clicked.connect(self._fetch)
        layout.addWidget(self.reload_btn)
        self.image_label = QLabel("正在获取壁纸…")
        self.image_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.image_label, stretch=1)

    def _fetch(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            return
        self._worker = _Worker(self)
        self._worker.done_ok.connect(self._on_ok)
        self._worker.done_err.connect(lambda m: self.image_label.setText(f"失败：{m}"))
        self._worker.start()

    def _on_ok(self, data: bytes) -> None:
        pixmap = QPixmap()
        if pixmap.loadFromData(data):
            self._pixmap = pixmap
            self.image_label.setPixmap(pixmap.scaled(
                self.image_label.size(),
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation))

    def shutdown(self) -> None:  # 退出时停止后台线程
        if self._worker is not None and self._worker.isRunning():
            self._worker.wait(1500)


# 注册声明：page 用 "模块路径:类名" 字符串（懒加载，规避循环导入）
@tool(
    "gens_wallpaper", name="原神壁纸", category=CATEGORY_FUN,
    kind=KIND_PAGE,
    page="plugins.gensh_wallpaper:GenshWallpaperPage",
    description="随机获取一张原神壁纸（xxapi 免费接口）",
)
def _register() -> None:
    """仅作挂载声明，函数体可为空（装饰器已登记元数据）。"""
    pass
```

### 页面类必须遵守的约定

1. **签名固定**：`__init__(self, theme, store, parent=None)`；
2. **网络请求跑 `QThread`**，用信号回传结果，不阻塞界面；
3. **进入即执行**：需要自动拉取就在 `__init__` 末尾调用触发方法；
4. **提供 `shutdown()`**：退出时停止后台线程（`main_window.closeEvent` 会统一调用）；
5. **`page=` 用字符串** `"模块路径:类名"`，不要直接传类对象（避免 `registry ↔ pages` 循环导入）。

### 需要 `page_kwargs` 的情况（复用同一页面类）

同一个页面类被多个工具复用、且需要不同参数时（如 md5/sha1/sha256 爆破共用
`Md5CrashPage`，只是 `hash_name` 不同），用 `page_kwargs` 传参：

```python
@tool(
    "md5_crash", name="MD5 爆破", category=CATEGORY_HASH,
    kind=KIND_EMBEDDED,
    page="app.pages.md5_crash_page:Md5CrashPage",
    page_kwargs={"hash_name": "md5"},
)
def _register() -> None:
    pass
```

`main_window` 会以 `PageCls(theme, store, **page_kwargs)` 实例化。

---

## 三、纯函数型工具（更简单）

纯函数型（`KIND_ONE_WAY` / `KIND_TWO_WAY` / `KIND_DIFF`）不需要写页面类，
`main_window` 会用通用 `ToolPanel` 自动生成界面。只需一个 `@tool` 装饰器：

```python
# plugins/my_codec.py
from app.registry import CATEGORY_STRING, KIND_TWO_WAY, ParamSpec, tool


def my_encode(data: str, shift: int = 3) -> str:
    return "".join(chr((ord(c) + shift) % 0x110000) for c in data)


def my_decode(data: str, shift: int = 3) -> str:
    return "".join(chr((ord(c) - shift) % 0x110000) for c in data)


@tool(
    "my_codec", name="我的编码", category=CATEGORY_STRING,
    kind=KIND_TWO_WAY, enc=my_encode, dec=my_decode,
    params=(ParamSpec("shift", "位移量", ptype="int", default=3),),
)
def _register() -> None:
    pass
```

`@tool` 装饰器返回原函数，所以函数体可为空；`enc` / `dec` 直接引用纯函数。
界面按 `params` 里的 `ParamSpec` 自动生成输入控件。

**kind 取值说明**：

| kind | 含义 | 是否需写页面类 |
|---|---|---|
| `KIND_PAGE` | 独立复杂页面 | 是（`page=` 指定） |
| `KIND_EMBEDDED` | 内嵌子工具（如爆破） | 是（`page=` 指定，不占侧边栏顶层） |
| `KIND_ONE_WAY` / `KIND_TWO_WAY` | 简单编解码 | 否，通用 `ToolPanel` 自动生成 |
| `KIND_DIFF` | 文本对比 | 否 |

---

## 四、新增分类（仅当需要新的大类时）

若工具需要一个新的大类（如「娱乐」），需在 `app/registry.py` 改 **4 处**，
且 **key 一律用英文**，中文只出现在显示名里：

```python
# 1. 分类常量
CATEGORY_FUN = "fun"              # 娱乐

# 2. 侧边栏入口
HUB_ENTER = "enter"
HUBS = (..., (HUB_ENTER, "娱乐"))  # 显示名用中文

# 3. 分类→入口映射
HUB_OF_CATEGORY = {..., CATEGORY_FUN: HUB_ENTER}

# 4. 分类显示名
CATEGORIES = (..., (CATEGORY_FUN, "娱乐"))
```

> ⚠️ 新增 hub 后，**必须同步改 `app/main_window.py`** 里的 `hub_icons` 和
> `_CATEGORY_ICONS` 两个字典，否则报 `KeyError: '<hub>'`。
> （这是唯一一处仍需改 main_window 的地方——分类/hub 属全局导航骨架，不在插槽范围内。）

---

## 五、可选扩展：CLI / MCP

页面工具若也要命令行 / MCP 入口，额外加两处（可选，非必须）。

### CLI 子命令（`cli.py`）

```python
@_register("gens_wallpaper")
def _cmd_gens_wallpaper(parser: argparse.ArgumentParser):
    from lib import gensh_wallpapper

    def run(args, store):
        return {"url": gensh_wallpapper.get_wallpaper_url()}

    return run, None
```

`build_parser()` 会遍历 `_WEB_COMMANDS` 自动生成子命令，无需改主流程。

### MCP 工具（`mcp_server.py`）

```python
@mcp.tool()
def gens_wallpaper(timeout: float = 10.0) -> dict:
    """获取一张原神随机壁纸图片直链 URL。"""
    from lib import gensh_wallpapper
    return {"url": gensh_wallpapper.get_wallpaper_url(timeout=timeout)}
```

---

## 六、验证清单

新增后按顺序验证：

```bash
# 1. registry 能识别到新工具
python -c "import app.registry as r; print([t.id for t in r.REGISTRY])"

# 2. 页面模块能正常导入（页面型）
python -c "from plugins.gensh_wallpaper import GenshWallpaperPage"

# 3. 全部改动文件语法编译通过
python -m py_compile plugins/gensh_wallpaper.py

# 4. 启动 GUI 手动确认
python main.py
```

---

## 七、避坑要点

1. **lib 模块底部不要直接调用函数** —— 导入即执行，无网络时整个程序崩。
2. **lib 函数要有 return**，类型注解别写成 `->json`（应为 `->dict` / `->str`）。
3. **分类 key 用英文**，中文只出现在 `CATEGORIES` / `HUBS` 的显示名里。
4. **新增 hub 必须同步补 `main_window.py` 的 `hub_icons`**，否则 `KeyError`。
5. **`page=` 用字符串 `"模块:类名"`**，不要传类对象（避免循环导入）。
6. **页面类签名 `(theme, store, parent=None)`**，额外参数走 `page_kwargs`。
7. **页面类要提供 `shutdown()`**，`closeEvent` 会统一遍历调用。
8. **图片展示用 QPixmap + resizeEvent 缩放**，保持宽高比、随窗口缩放。
9. **`@tool` 装饰器返回原函数**，注册声明函数体可为空（`pass`）。
