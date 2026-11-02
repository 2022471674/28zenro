# -*- coding: utf-8 -*-
"""原神随机壁纸页：进入即自动拉取一张壁纸，右侧展示，可一键换一张。"""

from __future__ import annotations

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from lib import gensh_wallpapper


class _WallpaperWorker(QThread):
    """后台下载壁纸字节，成功回传 bytes，失败回传错误文案。"""

    done_ok = Signal(bytes)
    done_err = Signal(str)

    def run(self) -> None:  # noqa: D102  线程体
        try:
            data = gensh_wallpapper.download_wallpaper()
        except Exception as exc:  # noqa: BLE001  统一转信号
            self.done_err.emit(str(exc))
            return
        self.done_ok.emit(data)


class GenshWallpaperPage(QWidget):
    """原神随机壁纸页：进入自动获取，右侧显示，支持换一张。"""

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._worker: _WallpaperWorker | None = None
        self._build_ui()
        self._fetch()  # 进入页面立即获取

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # 顶部工具条
        bar = QHBoxLayout()
        bar.setContentsMargins(36, 20, 36, 12)
        bar.setSpacing(8)

        title = QLabel("原神随机壁纸")
        title.setObjectName("title")
        bar.addWidget(title)
        bar.addStretch(1)

        self.reload_btn = QPushButton("换一张")
        self.reload_btn.setObjectName("ghbtn-primary")
        self.reload_btn.clicked.connect(self._fetch)
        bar.addWidget(self.reload_btn)

        self.save_btn = QPushButton("保存图片")
        self.save_btn.setObjectName("ghbtn")
        self.save_btn.setEnabled(False)
        self.save_btn.clicked.connect(self._save)
        bar.addWidget(self.save_btn)
        outer.addLayout(bar)

        # 右侧图片展示区（居中缩放显示）
        stage = QWidget()
        stage_layout = QVBoxLayout(stage)
        stage_layout.setContentsMargins(36, 0, 36, 24)
        stage_layout.setSpacing(10)

        self.image_label = QLabel()
        self.image_label.setObjectName("wallpaper-image")
        self.image_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.image_label.setMinimumSize(480, 360)
        self.image_label.setWordWrap(False)
        self.image_label.setText("正在获取壁纸…")
        stage_layout.addWidget(self.image_label, stretch=1)

        self.status_label = QLabel("")
        self.status_label.setObjectName("status-info")
        self.status_label.setWordWrap(True)
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        stage_layout.addWidget(self.status_label)

        outer.addWidget(stage, stretch=1)

    # -------------------------------------------------------------- 获取
    def _fetch(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            return
        self.reload_btn.setEnabled(False)
        self.save_btn.setEnabled(False)
        self._set_status(True, "正在获取壁纸…")

        old = self._worker
        worker = _WallpaperWorker(self)
        worker.done_ok.connect(self._on_ok)
        worker.done_err.connect(self._on_err)
        self._worker = worker
        if old is not None:
            old.deleteLater()
        worker.start()

    def _on_ok(self, data: bytes) -> None:
        self._worker = None
        self.reload_btn.setEnabled(True)
        pixmap = QPixmap()
        if not pixmap.loadFromData(data):
            self._set_status(False, "图片数据解析失败")
            return
        self._pixmap = pixmap
        self._render_pixmap()
        self.save_btn.setEnabled(True)
        self._set_status(True, "已获取一张壁纸")

    def _on_err(self, message: str) -> None:
        self._worker = None
        self.reload_btn.setEnabled(True)
        self._set_status(False, f"获取失败：{message}")

    # -------------------------------------------------------------- 展示
    def _render_pixmap(self) -> None:
        if not hasattr(self, "_pixmap"):
            return
        avail = self.image_label.size()
        scaled = self._pixmap.scaled(
            avail, Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation)
        self.image_label.setPixmap(scaled)

    def resizeEvent(self, event) -> None:  # noqa: N802  Qt 钩子
        super().resizeEvent(event)
        self._render_pixmap()

    # -------------------------------------------------------------- 保存
    def _save(self) -> None:
        if not hasattr(self, "_pixmap") or self._pixmap.isNull():
            self._set_status(False, "还没有可保存的壁纸")
            return
        from PySide6.QtWidgets import QFileDialog

        path, _ = QFileDialog.getSaveFileName(
            self, "保存壁纸", "genshin_wallpaper.jpg",
            "图片文件 (*.jpg *.jpeg *.png);;所有文件 (*)")
        if not path:
            return
        if self._pixmap.save(path):
            self._set_status(True, f"已保存：{path}")
        else:
            self._set_status(False, "保存失败，请检查路径或格式")

    # -------------------------------------------------------------- 输出
    def _set_status(self, ok: bool, text: str) -> None:
        self.status_label.setText(text)
        self.status_label.setObjectName("status-err" if not ok else "status-info")
        self.status_label.style().unpolish(self.status_label)
        self.status_label.style().polish(self.status_label)

    def shutdown(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            self._worker.wait(1500)
