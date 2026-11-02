# -*- coding: utf-8 -*-
"""快捷访问页：自定义链接分组，图标 + 标题网格，点击用系统浏览器打开。

功能
----
- **分组管理**：新建 / 重命名 / 删除分组；
- **链接管理**：直接添加（未分组）或放进指定分组，支持编辑、删除、复制链接；
- **网站图标**：新增链接后自动抓取 favicon，也可以手动刷新；
- **自定义图标**：从本地选择任意 Qt 支持的图片（png / jpg / gif / ico /
  webp / svg / bmp / tif …），自动复制到应用数据目录做缓存；
- **持久化**：全部数据写入 ``config.json`` 的 ``quick_access`` 节。

界面按分组分块，每个链接是一个固定尺寸卡片：上方图标、下方标题，点击卡片
调用 ``QDesktopServices.openUrl`` 在系统默认浏览器打开。
"""

from __future__ import annotations

import uuid
from pathlib import Path

from PySide6.QtCore import Qt, QThread, QUrl, Signal
from PySide6.QtGui import (
    QColor,
    QDesktopServices,
    QFont,
    QImageReader,
    QPainter,
    QPainterPath,
    QPixmap,
)
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)
from qfluentwidgets import FlowLayout

from lib import favicon_fetch

#: 链接卡片尺寸（图标 + 标题）
TILE_WIDTH = 112
TILE_HEIGHT = 108
ICON_SIZE = 48
#: 同时抓取图标的线程数上限（避免一次刷新全部时瞬间开几十个线程）
MAX_ICON_WORKERS = 3


def _new_id() -> str:
    """生成短随机 id（配置里只用于定位，不要求可读）。"""
    return uuid.uuid4().hex[:12]


# ---------------------------------------------------------------------------
# 图标绘制
# ---------------------------------------------------------------------------
def _load_pixmap(path: str) -> QPixmap:
    """从本地路径加载图片；不存在 / 无法解码时返回空 QPixmap。"""
    if not path:
        return QPixmap()
    file = Path(path)
    if not file.is_file():
        return QPixmap()
    pixmap = QPixmap(str(file))
    if not pixmap.isNull():
        return pixmap

    # 某些格式（如 svgz）QPixmap 构造失败时，再用 QImageReader 兜底
    reader = QImageReader(str(file))
    reader.setAutoTransform(True)
    image = reader.read()
    return QPixmap.fromImage(image) if not image.isNull() else QPixmap()


def _rounded_pixmap(source: QPixmap, size: int, radius: int = 10) -> QPixmap:
    """把源图等比缩放并裁成圆角，保证不同尺寸的图标视觉一致。"""
    canvas = QPixmap(size, size)
    canvas.fill(Qt.GlobalColor.transparent)

    painter = QPainter(canvas)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform, True)
    clip = QPainterPath()
    clip.addRoundedRect(0, 0, size, size, radius, radius)
    painter.setClipPath(clip)

    scaled = source.scaled(
        size, size,
        Qt.AspectRatioMode.KeepAspectRatio,
        Qt.TransformationMode.SmoothTransformation,
    )
    x = (size - scaled.width()) // 2
    y = (size - scaled.height()) // 2
    painter.drawPixmap(x, y, scaled)
    painter.end()
    return canvas


def _placeholder_pixmap(text: str, theme, size: int = ICON_SIZE) -> QPixmap:
    """没有图标时，用标题首字生成一张带底色的占位图。"""
    canvas = QPixmap(size, size)
    canvas.fill(Qt.GlobalColor.transparent)

    painter = QPainter(canvas)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    painter.setBrush(QColor(theme.accent))
    painter.setPen(Qt.PenStyle.NoPen)
    painter.drawRoundedRect(0, 0, size, size, 10, 10)

    char = (text or "?").strip()[:1] or "?"
    font = QFont(theme.font_ui_family)
    font.setPixelSize(max(12, int(size * 0.42)))
    font.setBold(True)
    painter.setFont(font)
    painter.setPen(QColor(theme.accent_fg))
    painter.drawText(canvas.rect(), Qt.AlignmentFlag.AlignCenter, char.upper())
    painter.end()
    return canvas


def _link_pixmap(icon_path: str, theme, title: str,
                 size: int = ICON_SIZE) -> QPixmap:
    """按「本地图标 -> 首字占位图」的顺序取链接图标。"""
    source = _load_pixmap(icon_path)
    if source.isNull():
        return _placeholder_pixmap(title, theme, size)
    return _rounded_pixmap(source, size)


# ---------------------------------------------------------------------------
# 后台抓取 favicon
# ---------------------------------------------------------------------------
class _FaviconWorker(QThread):
    """在后台抓取单个链接的网站图标并落盘。"""

    done_ok = Signal(str, str, str, str)   # group_id, link_id, icon_path, title
    done_err = Signal(str, str, str, str)  # group_id, link_id, message, title

    def __init__(self, url: str, icon_dir: str, group_id: str,
                 link_id: str, title: str, parent=None) -> None:
        super().__init__(parent)
        self.url = url
        self.icon_dir = icon_dir
        self.group_id = group_id
        self.link_id = link_id
        self.title = title

    def run(self) -> None:  # noqa: D102  线程入口
        try:
            path = favicon_fetch.fetch_and_save_icon(
                self.url, self.icon_dir,
                log=lambda message: None,
            )
        except Exception as exc:  # noqa: BLE001  后台线程统一转信号
            self.done_err.emit(self.group_id, self.link_id, str(exc), self.title)
            return
        self.done_ok.emit(self.group_id, self.link_id, path, self.title)


# ---------------------------------------------------------------------------
# 链接卡片
# ---------------------------------------------------------------------------
class _LinkTile(QWidget):
    """单个链接卡片：图标在上、标题在下，点击打开链接。"""

    open_requested = Signal(str, str)
    edit_requested = Signal(str, str)
    delete_requested = Signal(str, str)
    refresh_requested = Signal(str, str)

    def __init__(self, theme, group_id: str, link: dict, parent=None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.group_id = group_id
        self.link = link
        self.setObjectName("linkcard")
        self.setFixedSize(TILE_WIDTH, TILE_HEIGHT)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 12, 8, 8)
        layout.setSpacing(6)

        self.icon_label = QLabel()
        self.icon_label.setFixedSize(ICON_SIZE, ICON_SIZE)
        self.icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.icon_label.setAttribute(
            Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        layout.addWidget(self.icon_label, 0, Qt.AlignmentFlag.AlignHCenter)

        self.title_label = QLabel()
        self.title_label.setObjectName("linktitle")
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.title_label.setFixedHeight(18)
        self.title_label.setAttribute(
            Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        layout.addWidget(self.title_label)

        self.apply_link(link)

    # ------------------------------------------------------------------ 数据
    def apply_link(self, link: dict) -> None:
        """更新卡片展示（标题 / 图标 / 提示）。"""
        self.link = link
        title = str(link.get("title") or favicon_fetch.host_of(
            str(link.get("url", ""))) or "未命名")
        url = str(link.get("url", ""))

        metrics = self.title_label.fontMetrics()
        self.title_label.setText(metrics.elidedText(
            title, Qt.TextElideMode.ElideRight, TILE_WIDTH - 20))
        self.title_label.setToolTip(f"{title}\n{url}")
        self.setToolTip(f"{title}\n{url}")
        self.set_icon(str(link.get("icon", "")))

    def set_icon(self, icon_path: str) -> None:
        title = str(self.link.get("title") or self.link.get("url") or "")
        self.icon_label.setPixmap(
            _link_pixmap(icon_path, self.theme, title, ICON_SIZE))

    # ------------------------------------------------------------------ 交互
    def mousePressEvent(self, event) -> None:  # noqa: N802  Qt 命名约定
        if event.button() == Qt.MouseButton.LeftButton:
            self.open_requested.emit(self.group_id, str(self.link.get("id", "")))
        super().mousePressEvent(event)

    def contextMenuEvent(self, event) -> None:  # noqa: N802  Qt 命名约定
        link_id = str(self.link.get("id", ""))
        menu = QMenu(self)
        open_action = menu.addAction("打开链接")
        edit_action = menu.addAction("编辑")
        refresh_action = menu.addAction("重新获取图标")
        copy_action = menu.addAction("复制链接")
        menu.addSeparator()
        delete_action = menu.addAction("删除")

        chosen = menu.exec(event.globalPos())
        if chosen is open_action:
            self.open_requested.emit(self.group_id, link_id)
        elif chosen is edit_action:
            self.edit_requested.emit(self.group_id, link_id)
        elif chosen is refresh_action:
            self.refresh_requested.emit(self.group_id, link_id)
        elif chosen is copy_action:
            QApplication.clipboard().setText(str(self.link.get("url", "")))
        elif chosen is delete_action:
            self.delete_requested.emit(self.group_id, link_id)


# ---------------------------------------------------------------------------
# 添加 / 编辑链接对话框
# ---------------------------------------------------------------------------
def _image_filter() -> str:
    exts = " ".join(f"*{ext}" for ext in favicon_fetch.IMAGE_EXTENSIONS)
    return f"图片文件 ({exts});;所有文件 (*)"


class _LinkDialog(QDialog):
    """添加或编辑一条快捷链接。"""

    def __init__(self, theme, groups: list[dict], icon_dir: str,
                 link: dict | None = None, default_group_id: str = "",
                 parent=None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.groups = groups
        self.icon_dir = icon_dir
        self.default_group_id = default_group_id
        self.link = dict(link) if link else {}
        self._icon_path = str(self.link.get("icon", ""))
        self._custom_source = ""
        self._icon_changed = False
        self._result: dict | None = None

        self.setWindowTitle("编辑快捷链接" if link else "添加快捷链接")
        self.setModal(True)
        self.resize(520, 300)
        self._build()
        self._fill()

    # ------------------------------------------------------------------ UI
    def _build(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(22, 18, 22, 16)
        outer.setSpacing(12)

        title = QLabel("编辑快捷链接" if self.link else "添加快捷链接")
        title.setObjectName("title")
        outer.addWidget(title)

        caption = QLabel("点击图标时用系统默认浏览器打开对应网址。")
        caption.setObjectName("caption")
        outer.addWidget(caption)

        form = QFormLayout()
        form.setHorizontalSpacing(16)
        form.setVerticalSpacing(10)

        self.url_edit = QLineEdit()
        self.url_edit.setPlaceholderText("https://example.com")
        form.addRow("链接", self.url_edit)

        self.title_edit = QLineEdit()
        self.title_edit.setPlaceholderText("留空则使用网站域名")
        form.addRow("标题", self.title_edit)

        self.group_combo = QComboBox()
        self.group_combo.addItem("未分组（直接显示在页面上）", "")
        for group in self.groups:
            self.group_combo.addItem(
                str(group.get("name", "未命名分组")), str(group.get("id", "")))
        form.addRow("分组", self.group_combo)

        icon_row = QHBoxLayout()
        icon_row.setSpacing(12)
        self.icon_label = QLabel()
        self.icon_label.setFixedSize(64, 64)
        self.icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.icon_label.setStyleSheet(
            "border: 1px dashed #888; border-radius: 10px;")
        icon_row.addWidget(self.icon_label)

        icon_buttons = QVBoxLayout()
        icon_buttons.setSpacing(6)
        pick_btn = QPushButton("选择本地图片…")
        pick_btn.setObjectName("ghbtn")
        pick_btn.clicked.connect(self._pick_icon)
        clear_btn = QPushButton("清除图标")
        clear_btn.setObjectName("ghbtn")
        clear_btn.clicked.connect(self._clear_icon)
        icon_buttons.addWidget(pick_btn)
        icon_buttons.addWidget(clear_btn)
        icon_buttons.addStretch(1)
        icon_row.addLayout(icon_buttons)
        icon_row.addStretch(1)
        form.addRow("图标", icon_row)

        self.auto_check = QCheckBox("保存后自动获取网站图标")
        self.auto_check.setChecked(True)
        form.addRow("", self.auto_check)
        outer.addLayout(form)

        # 输入 URL / 标题时实时刷新占位图（只连接一次，避免重复触发）
        self.url_edit.textChanged.connect(self._refresh_preview)
        self.title_edit.textChanged.connect(self._refresh_preview)

        hint = QLabel(
            "支持 png / jpg / gif / ico / webp / svg / bmp / tif 等所有"
            " Qt 可读取的图片格式；自定义图标会复制到应用数据目录。")
        hint.setObjectName("caption")
        hint.setWordWrap(True)
        outer.addWidget(hint)

        outer.addStretch(1)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        buttons.addStretch(1)
        cancel_btn = QPushButton("取消")
        cancel_btn.setObjectName("ghbtn")
        cancel_btn.clicked.connect(self.reject)
        save_btn = QPushButton("保存")
        save_btn.setObjectName("ghbtn-primary")
        save_btn.clicked.connect(self._on_save)
        buttons.addWidget(cancel_btn)
        buttons.addWidget(save_btn)
        outer.addLayout(buttons)

    def _fill(self) -> None:
        """把编辑对象 / 默认分组回填到控件。"""
        if self.link:
            self.url_edit.setText(str(self.link.get("url", "")))
            self.title_edit.setText(str(self.link.get("title", "")))
            index = self.group_combo.findData(str(self.link.get("group_id", "")))
            if index >= 0:
                self.group_combo.setCurrentIndex(index)
        else:
            index = self.group_combo.findData(self.default_group_id)
            if index >= 0:
                self.group_combo.setCurrentIndex(index)
        self._refresh_preview()
        self._refresh_auto_check()

    def _refresh_preview(self) -> None:
        title = self.title_edit.text().strip() or favicon_fetch.host_of(
            self.url_edit.text().strip())
        self.icon_label.setPixmap(
            _link_pixmap(self._icon_path, self.theme, title, 64))

    def _refresh_auto_check(self) -> None:
        has_icon = bool(self._icon_path)
        self.auto_check.setEnabled(not has_icon)
        if has_icon:
            self.auto_check.setChecked(False)
        elif not self._icon_changed:
            self.auto_check.setChecked(True)

    # ------------------------------------------------------------- 图标选择
    def _pick_icon(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "选择图标", "", _image_filter())
        if not path:
            return
        pixmap = _load_pixmap(path)
        if pixmap.isNull():
            QMessageBox.warning(
                self, "无法读取图片",
                "选中的文件不是受支持的图片，请换一个文件。\n"
                "支持 png / jpg / gif / ico / webp / svg / bmp / tif 等格式。")
            return
        self._icon_path = path
        self._custom_source = path
        self._icon_changed = True
        self._refresh_preview()
        self._refresh_auto_check()

    def _clear_icon(self) -> None:
        self._icon_path = ""
        self._custom_source = ""
        self._icon_changed = True
        self.auto_check.setChecked(True)
        self._refresh_preview()
        self._refresh_auto_check()

    # ----------------------------------------------------------------- 保存
    def _on_save(self) -> None:
        try:
            url = favicon_fetch.normalize_url(self.url_edit.text())
        except favicon_fetch.FaviconError as exc:
            QMessageBox.warning(self, "链接无效", str(exc))
            return

        title = self.title_edit.text().strip()
        if not title:
            title = favicon_fetch.host_of(url) or url

        icon = self._icon_path
        if self._custom_source:
            try:
                icon = favicon_fetch.copy_icon_file(
                    self._custom_source, self.icon_dir)
            except favicon_fetch.FaviconError as exc:
                QMessageBox.warning(self, "图标保存失败", str(exc))
                return

        auto_fetch = (
            self.auto_check.isEnabled() and self.auto_check.isChecked()
            and not icon
        )
        self._result = {
            "url": url,
            "title": title,
            "group_id": str(self.group_combo.currentData() or ""),
            "icon": icon,
            "auto_fetch": auto_fetch,
        }
        self.accept()

    def values(self) -> dict:
        """保存后的字段（只在 ``exec()`` 返回 Accepted 后使用）。"""
        return self._result or {}


# ---------------------------------------------------------------------------
# 页面
# ---------------------------------------------------------------------------
class QuickAccessPage(QWidget):
    """快捷访问页：分组 + 图标网格的链接收藏夹。"""

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._data = self._load_data()
        #: (group_id, link_id) -> 正在运行的抓取线程
        self._workers: dict[tuple[str, str], _FaviconWorker] = {}
        #: 待抓取队列：(group_id, link_id, url, title)
        self._queue: list[tuple[str, str, str, str]] = []
        #: (group_id, link_id) -> 卡片控件（用于单个图标抓取完成后局部刷新）
        self._tiles: dict[tuple[str, str], _LinkTile] = {}
        self._build_ui()
        self.refresh()

    # ------------------------------------------------------------- 数据读写
    def _load_data(self) -> dict:
        raw = self.store.get("quick_access", default={}) or {}
        if not isinstance(raw, dict):
            raw = {}

        groups: list[dict] = []
        used: set[str] = set()
        for item in raw.get("groups") or []:
            if not isinstance(item, dict):
                continue
            group_id = str(item.get("id") or _new_id())
            while group_id in used:
                group_id = _new_id()
            used.add(group_id)
            groups.append({
                "id": group_id,
                "name": str(item.get("name") or "未命名分组"),
                "links": self._normalize_links(item.get("links")),
            })

        return {
            "groups": groups,
            "links": self._normalize_links(raw.get("links")),
            "icon_dir": str(raw.get("icon_dir") or ""),
        }

    @staticmethod
    def _normalize_links(raw_links) -> list[dict]:
        links: list[dict] = []
        used: set[str] = set()
        for item in raw_links or []:
            if not isinstance(item, dict):
                continue
            url = str(item.get("url") or "").strip()
            if not url:
                continue
            link_id = str(item.get("id") or _new_id())
            while link_id in used:
                link_id = _new_id()
            used.add(link_id)
            links.append({
                "id": link_id,
                "title": str(item.get("title") or ""),
                "url": url,
                "icon": str(item.get("icon") or ""),
            })
        return links

    def _save_data(self) -> None:
        self.store.setv(self._data, "quick_access")
        self.store.save()

    def _icon_dir(self) -> Path:
        """图标缓存目录：默认放在 config.json 同级的 quick_access_icons。"""
        raw = str(self._data.get("icon_dir") or "").strip()
        base = Path(raw) if raw else self.store.path.parent / "quick_access_icons"
        if not base.is_absolute():
            base = self.store.path.parent / base
        base.mkdir(parents=True, exist_ok=True)
        return base

    def _all_links(self):
        """遍历全部链接：``(group_id, link)``，未分组链接的 group_id 为空串。"""
        for link in self._data.get("links", []):
            yield "", link
        for group in self._data.get("groups", []):
            group_id = str(group.get("id", ""))
            for link in group.get("links", []):
                yield group_id, link

    def _find_group(self, group_id: str) -> dict | None:
        for group in self._data.get("groups", []):
            if str(group.get("id", "")) == group_id:
                return group
        return None

    def _find_link(self, group_id: str, link_id: str) -> dict | None:
        for current_group, link in self._all_links():
            if current_group == group_id and str(link.get("id", "")) == link_id:
                return link
        return None

    def _find_link_anywhere(self, link_id: str) -> tuple[str | None, dict | None]:
        """按 id 在全部分组里找链接（链接被移动分组后仍能定位）。"""
        for group_id, link in self._all_links():
            if str(link.get("id", "")) == link_id:
                return group_id, link
        return None, None

    def _links_of_group(self, group_id: str) -> list[dict]:
        if not group_id:
            return self._data.setdefault("links", [])
        group = self._find_group(group_id)
        return group.setdefault("links", []) if group is not None else []

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        header = QWidget()
        header_layout = QVBoxLayout(header)
        header_layout.setContentsMargins(32, 22, 32, 10)
        header_layout.setSpacing(8)

        title_row = QHBoxLayout()
        title_row.setSpacing(8)
        title = QLabel("快捷访问")
        title.setObjectName("title")
        title_row.addWidget(title)
        title_row.addStretch(1)

        self.refresh_icons_btn = QPushButton("刷新缺失图标")
        self.refresh_icons_btn.setObjectName("ghbtn")
        self.refresh_icons_btn.setToolTip("为还没有图标的链接重新抓取网站图标")
        self.refresh_icons_btn.clicked.connect(self._refresh_missing_icons)
        title_row.addWidget(self.refresh_icons_btn)

        add_group_btn = QPushButton("添加分组")
        add_group_btn.setObjectName("ghbtn")
        add_group_btn.clicked.connect(self._add_group)
        title_row.addWidget(add_group_btn)

        add_link_btn = QPushButton("添加链接")
        add_link_btn.setObjectName("ghbtn-primary")
        add_link_btn.clicked.connect(lambda: self._add_link(""))
        title_row.addWidget(add_link_btn)
        header_layout.addLayout(title_row)

        subtitle = QLabel(
            "把常用站点固定在这里，点击图标用系统默认浏览器打开；"
            "支持自定义分组与本地图标。")
        subtitle.setObjectName("subtitle")
        header_layout.addWidget(subtitle)

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("搜索链接（标题 / 网址）…")
        self.search_edit.setClearButtonEnabled(True)
        self.search_edit.textChanged.connect(self.refresh)
        header_layout.addWidget(self.search_edit)

        outer.addWidget(header)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        outer.addWidget(self.scroll, stretch=1)

        self.status_label = QLabel("")
        self.status_label.setObjectName("status-info")
        self.status_label.setWordWrap(True)
        self.status_label.setContentsMargins(32, 4, 32, 10)
        outer.addWidget(self.status_label)

    # -------------------------------------------------------------- 刷新渲染
    def refresh(self, *_args) -> None:
        """按搜索词重建分组与链接网格。"""
        self._tiles.clear()
        query = self.search_edit.text().strip().lower() if hasattr(
            self, "search_edit") else ""

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(32, 8, 32, 24)
        layout.setSpacing(20)

        has_any = bool(self._data.get("links")) or bool(
            self._data.get("groups"))
        matched = 0

        # 未分组链接：直接定义在页面上的链接
        direct_links = list(self._data.get("links", []))
        direct_links = self._filter_links(direct_links, query)
        if direct_links:
            matched += len(direct_links)
            self._add_section(layout, "", "未分组", direct_links)

        for group in self._data.get("groups", []):
            group_id = str(group.get("id", ""))
            name = str(group.get("name", "未命名分组"))
            links = list(group.get("links", []))
            group_matched = bool(query) and query in name.lower()
            visible = links if group_matched else self._filter_links(links, query)
            if query and not group_matched and not visible:
                continue
            matched += len(visible)
            self._add_section(layout, group_id, name, visible)

        if not has_any:
            layout.addStretch(1)
            layout.addWidget(self._empty_widget())
            layout.addStretch(1)
        elif query and matched == 0:
            empty = QLabel("没有匹配的链接，换个关键词试试。")
            empty.setObjectName("caption")
            layout.addWidget(empty)
            layout.addStretch(1)
        else:
            layout.addStretch(1)

        self.scroll.setWidget(container)

    @staticmethod
    def _filter_links(links: list[dict], query: str) -> list[dict]:
        if not query:
            return links
        result = []
        for link in links:
            haystack = (
                str(link.get("title", "")) + " " + str(link.get("url", ""))
            ).lower()
            if query in haystack:
                result.append(link)
        return result

    def _empty_widget(self) -> QWidget:
        card = QWidget()
        layout = QVBoxLayout(card)
        layout.setContentsMargins(0, 40, 0, 40)
        layout.setSpacing(8)

        heading = QLabel("还没有快捷链接")
        heading.setObjectName("title")
        heading.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(heading)

        hint = QLabel("点击右上角「添加链接」，把常用站点固定在这里。")
        hint.setObjectName("caption")
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(hint)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        buttons.addStretch(1)
        add_group = QPushButton("新建分组")
        add_group.setObjectName("ghbtn")
        add_group.clicked.connect(self._add_group)
        add_link = QPushButton("添加第一个链接")
        add_link.setObjectName("ghbtn-primary")
        add_link.clicked.connect(lambda: self._add_link(""))
        buttons.addWidget(add_group)
        buttons.addWidget(add_link)
        buttons.addStretch(1)
        layout.addLayout(buttons)
        return card

    def _add_section(self, parent_layout: QVBoxLayout, group_id: str,
                     name: str, links: list[dict]) -> None:
        section = QWidget()
        layout = QVBoxLayout(section)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        header = QHBoxLayout()
        header.setSpacing(8)

        group_label = QLabel(name)
        group_label.setObjectName("groupTitle")
        header.addWidget(group_label)

        count = QLabel(f"{len(links)} 个链接")
        count.setObjectName("caption")
        header.addWidget(count)
        header.addStretch(1)

        add_btn = QPushButton("＋ 添加链接")
        add_btn.setObjectName("ghbtn")
        add_btn.clicked.connect(lambda: self._add_link(group_id))
        header.addWidget(add_btn)

        if group_id:
            menu_btn = QPushButton("⋯")
            menu_btn.setObjectName("ghbtn")
            menu_btn.setFixedWidth(42)
            menu_btn.setToolTip("分组操作")
            menu_btn.clicked.connect(
                lambda: self._show_group_menu(group_id, menu_btn))
            header.addWidget(menu_btn)

        layout.addLayout(header)

        if links:
            host = QWidget()
            flow = FlowLayout(host, needAni=False)
            flow.setContentsMargins(0, 0, 0, 0)
            flow.setHorizontalSpacing(8)
            flow.setVerticalSpacing(8)
            for link in links:
                tile = _LinkTile(self.theme, group_id, link)
                tile.open_requested.connect(self._open_link)
                tile.edit_requested.connect(self._edit_link)
                tile.delete_requested.connect(self._delete_link)
                tile.refresh_requested.connect(self._refresh_link_icon)
                flow.addWidget(tile)
                self._tiles[(group_id, str(link.get("id", "")))] = tile
            layout.addWidget(host)
        else:
            empty = QLabel("这个分组还是空的，点击「＋ 添加链接」放一个进去。")
            empty.setObjectName("caption")
            layout.addWidget(empty)

        parent_layout.addWidget(section)

    # -------------------------------------------------------------- 分组操作
    def _add_group(self) -> None:
        name, ok = QInputDialog.getText(
            self, "新建分组", "分组名称：", text="")
        name = name.strip()
        if not ok or not name:
            return
        self._data.setdefault("groups", []).append({
            "id": _new_id(),
            "name": name,
            "links": [],
        })
        self._save_data()
        self.refresh()
        self._set_status(True, f"已创建分组「{name}」。")

    def _rename_group(self, group_id: str) -> None:
        group = self._find_group(group_id)
        if group is None:
            return
        name, ok = QInputDialog.getText(
            self, "重命名分组", "分组名称：", text=str(group.get("name", "")))
        name = name.strip()
        if not ok or not name:
            return
        group["name"] = name
        self._save_data()
        self.refresh()
        self._set_status(True, f"分组已重命名为「{name}」。")

    def _delete_group(self, group_id: str) -> None:
        group = self._find_group(group_id)
        if group is None:
            return
        name = str(group.get("name", "未命名分组"))
        count = len(group.get("links", []))
        answer = QMessageBox.question(
            self, "删除分组",
            f"确定删除分组「{name}」吗？\n组内 {count} 个链接也会一并删除。",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return

        old_icons = [str(link.get("icon", "")) for link in group.get("links", [])]
        self._data["groups"] = [
            item for item in self._data.get("groups", [])
            if str(item.get("id", "")) != group_id
        ]
        self._save_data()
        for icon in old_icons:
            self._discard_icon(icon)
        self.refresh()
        self._set_status(True, f"已删除分组「{name}」。")

    def _show_group_menu(self, group_id: str, anchor: QWidget) -> None:
        menu = QMenu(self)
        rename_action = menu.addAction("重命名分组")
        refresh_action = menu.addAction("刷新组内缺失图标")
        menu.addSeparator()
        delete_action = menu.addAction("删除分组")
        chosen = menu.exec(anchor.mapToGlobal(anchor.rect().bottomLeft()))
        if chosen is rename_action:
            self._rename_group(group_id)
        elif chosen is refresh_action:
            self._refresh_group_icons(group_id)
        elif chosen is delete_action:
            self._delete_group(group_id)

    # -------------------------------------------------------------- 链接操作
    def _add_link(self, default_group_id: str) -> None:
        try:
            icon_dir = str(self._icon_dir())
        except OSError as exc:
            QMessageBox.warning(self, "图标目录不可用", str(exc))
            return
        dialog = _LinkDialog(
            self.theme, self._data.get("groups", []), icon_dir,
            default_group_id=default_group_id, parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        values = dialog.values()
        group_id = values.get("group_id", "")
        if group_id and self._find_group(group_id) is None:
            group_id = ""
        link = {
            "id": _new_id(),
            "title": values.get("title", ""),
            "url": values.get("url", ""),
            "icon": values.get("icon", ""),
        }
        self._links_of_group(group_id).append(link)
        self._save_data()
        self.refresh()
        self._set_status(True, f"已添加「{link['title']}」。")

        if values.get("auto_fetch"):
            self._queue_icon_fetch(group_id, link["id"], link["url"], link["title"])

    def _edit_link(self, group_id: str, link_id: str) -> None:
        link = self._find_link(group_id, link_id)
        if link is None:
            return
        payload = dict(link)
        payload["group_id"] = group_id
        try:
            icon_dir = str(self._icon_dir())
        except OSError as exc:
            QMessageBox.warning(self, "图标目录不可用", str(exc))
            return
        dialog = _LinkDialog(
            self.theme, self._data.get("groups", []), icon_dir,
            link=payload, parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        values = dialog.values()
        new_group_id = values.get("group_id", "")
        if new_group_id and self._find_group(new_group_id) is None:
            new_group_id = ""

        old_icon = str(link.get("icon", ""))
        old_links = self._links_of_group(group_id)
        for index, item in enumerate(old_links):
            if str(item.get("id", "")) == link_id:
                old_links.pop(index)
                break
        link.update({
            "title": values.get("title", ""),
            "url": values.get("url", ""),
            "icon": values.get("icon", ""),
        })
        self._links_of_group(new_group_id).append(link)
        self._save_data()
        if old_icon and old_icon != link["icon"]:
            self._discard_icon(old_icon)
        self.refresh()
        self._set_status(True, f"已更新「{link['title']}」。")

        if values.get("auto_fetch"):
            self._queue_icon_fetch(
                new_group_id, link["id"], link["url"], link["title"])

    def _delete_link(self, group_id: str, link_id: str) -> None:
        link = self._find_link(group_id, link_id)
        if link is None:
            return
        answer = QMessageBox.question(
            self, "删除链接",
            f"确定删除「{link.get('title') or link.get('url')}」吗？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return

        icon = str(link.get("icon", ""))
        links = self._links_of_group(group_id)
        links[:] = [
            item for item in links if str(item.get("id", "")) != link_id
        ]
        self._save_data()
        self._discard_icon(icon)
        self.refresh()
        self._set_status(True, "链接已删除。")

    def _open_link(self, group_id: str, link_id: str) -> None:
        link = self._find_link(group_id, link_id)
        if link is None:
            return
        try:
            url = favicon_fetch.normalize_url(str(link.get("url", "")))
        except favicon_fetch.FaviconError as exc:
            self._set_status(False, str(exc))
            return
        if not QDesktopServices.openUrl(QUrl(url)):
            self._set_status(False, f"无法打开链接：{url}")
            return
        self._set_status(True, f"已在浏览器打开：{url}")

    # -------------------------------------------------------------- 图标抓取
    def _queue_icon_fetch(self, group_id: str, link_id: str,
                          url: str, title: str) -> None:
        key = (group_id, link_id)
        if key in self._workers:
            return
        if any(item[0] == key[0] and item[1] == key[1] for item in self._queue):
            return
        self._queue.append((group_id, link_id, url, title))
        self._pump_icon_queue()

    def _pump_icon_queue(self) -> None:
        while self._queue and len(self._workers) < MAX_ICON_WORKERS:
            group_id, link_id, url, title = self._queue.pop(0)
            key = (group_id, link_id)
            try:
                icon_dir = str(self._icon_dir())
            except OSError as exc:
                self._queue.clear()
                self._set_status(False, f"图标目录不可用：{exc}")
                return
            worker = _FaviconWorker(
                url, icon_dir, group_id, link_id, title, self)
            worker.done_ok.connect(self._on_icon_ok)
            worker.done_err.connect(self._on_icon_err)
            worker.finished.connect(
                lambda group_id=group_id, link_id=link_id: self._on_icon_done(
                    (group_id, link_id)))
            self._workers[key] = worker
            worker.start()

    def _on_icon_done(self, key: tuple[str, str]) -> None:
        worker = self._workers.pop(key, None)
        if worker is not None:
            worker.deleteLater()
        self._pump_icon_queue()

    def _on_icon_ok(self, group_id: str, link_id: str,
                    icon_path: str, title: str) -> None:
        current_group, link = self._find_link_anywhere(link_id)
        if link is None:
            self._discard_icon(icon_path)
            return
        old_icon = str(link.get("icon", ""))
        link["icon"] = icon_path
        self._save_data()
        if old_icon and old_icon != icon_path:
            self._discard_icon(old_icon)

        tile = self._tiles.get((str(current_group or ""), link_id))
        if tile is None:
            for (_group, tile_id), candidate in self._tiles.items():
                if tile_id == link_id:
                    tile = candidate
                    break
        if tile is not None:
            tile.set_icon(icon_path)
        self._set_status(True, f"已自动获取「{title}」的网站图标。")

    def _on_icon_err(self, group_id: str, link_id: str,
                     message: str, title: str) -> None:
        self._set_status(
            False, f"「{title}」图标获取失败：{message}（可右键手动重试）")

    def _refresh_link_icon(self, group_id: str, link_id: str) -> None:
        link = self._find_link(group_id, link_id)
        if link is None:
            return
        # 保留旧图标直到新图标抓取成功，失败时不会把已有图标弄丢
        self._set_status(True, f"正在重新获取「{link.get('title') or link['url']}」的图标…")
        self._queue_icon_fetch(
            group_id, link_id, str(link.get("url", "")),
            str(link.get("title") or link.get("url", "")))

    def _refresh_missing_icons(self) -> None:
        queued = 0
        for group_id, link in self._all_links():
            icon = str(link.get("icon", ""))
            if icon and Path(icon).is_file():
                continue
            self._queue_icon_fetch(
                group_id, str(link.get("id", "")), str(link.get("url", "")),
                str(link.get("title") or link.get("url", "")))
            queued += 1
        if queued:
            self._set_status(True, f"已加入 {queued} 个图标抓取任务…")
        else:
            self._set_status(True, "所有链接都已经有图标了。")

    def _refresh_group_icons(self, group_id: str) -> None:
        queued = 0
        for link in self._links_of_group(group_id):
            icon = str(link.get("icon", ""))
            if icon and Path(icon).is_file():
                continue
            self._queue_icon_fetch(
                group_id, str(link.get("id", "")), str(link.get("url", "")),
                str(link.get("title") or link.get("url", "")))
            queued += 1
        if queued:
            self._set_status(True, f"已加入 {queued} 个图标抓取任务…")
        else:
            self._set_status(True, "这个分组里的链接都已经有图标了。")

    # ---------------------------------------------------------- 图标文件清理
    def _icon_in_cache(self, path: str) -> bool:
        if not path:
            return False
        try:
            file = Path(path).resolve()
            return file.is_relative_to(self._icon_dir().resolve())
        except (OSError, ValueError):
            return False

    def _discard_icon(self, path: str) -> None:
        """删除缓存目录里不再被任何链接引用的图标文件。"""
        if not path or not self._icon_in_cache(path):
            return
        target = Path(path).resolve()
        for _group_id, link in self._all_links():
            icon = str(link.get("icon", ""))
            if not icon:
                continue
            try:
                if Path(icon).resolve() == target:
                    return
            except OSError:
                continue
        try:
            target.unlink()
        except OSError:
            pass

    # ------------------------------------------------------------------ 杂项
    def _set_status(self, ok: bool | None, text: str) -> None:
        self.status_label.setText(text)
        self.status_label.setObjectName(
            "status-info" if ok is None else ("status-ok" if ok else "status-err"))
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)

    def set_theme(self, palette) -> None:
        self.theme = palette
        self.refresh()

    def shutdown(self) -> None:
        """退出前结束后台图标线程，避免 Qt 销毁运行中的 QThread。"""
        self._queue.clear()
        for worker in list(self._workers.values()):
            if not worker.isRunning():
                continue
            if not worker.wait(2000):
                # 网络请求无法从外部中断，退出时只能强制结束线程
                worker.terminate()
                worker.wait(500)
        self._workers.clear()
