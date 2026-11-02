# -*- coding: utf-8 -*-
from __future__ import annotations

import random

from PySide6.QtCore import (
    QEasingCurve,
    QPropertyAnimation,
    Qt,
    QTimer,
)
from PySide6.QtWidgets import (
    QGraphicsOpacityEffect,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from app.pages.about_page import AVATAR_PATH, circular_pixmap

#: 启动时随机滚动的一句话（CTF / 密码学主题）
SPLASH_QUOTES: tuple[str, ...] = (
    "正在破译启动序列…",
    "加载密码学工具箱…",
    "召唤 Base64 大军…",
    "转动 ROT13 齿轮…",
    "预热哈希计算器…",
    "校准凯撒密码盘…",
    "拼接猪圈符号…",
    "解析 JWT 声明…",
    "监听 0.0.0.0:4444…",
    "碰撞 MD5 中，请稍候…",
    "枚举排列组合…",
    "解密中，稍安勿躁…",
    "Loading flags…",
    "nc -lvnp 就绪…",
    "扫描开放端口…",
    "还原 .git 泄露…",
)

#: 卡片圆角（与主题 BTN_RADIUS 视觉一致）
CARD_RADIUS = 12
#: 头像尺寸（像素）
AVATAR_SIZE = 88
#: 卡片宽度
CARD_WIDTH = 260


class SplashScreen(QWidget):
    """启动动画窗口：无边框、透明、置顶、居中。"""

    def __init__(self, theme, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self._build()

    # ------------------------------------------------------------------ UI
    def _build(self) -> None:
        self.setWindowFlags(
            Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.SplashScreen
            | Qt.WindowType.WindowStaysOnTopHint
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

        # 外层透明容器：让卡片居中，四周留透明边距用于圆角阴影感
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setAlignment(Qt.AlignmentFlag.AlignCenter)

        card = QWidget()
        card.setObjectName("splashCard")
        card.setFixedWidth(CARD_WIDTH)
        card.setStyleSheet(
            f"QWidget#splashCard {{"
            f" background-color: {self.theme.surface};"
            f" border: 1px solid {self.theme.border};"
            f" border-radius: {CARD_RADIUS}px;"
            f" }}"
        )
        outer.addWidget(card, 0, Qt.AlignmentFlag.AlignCenter)

        box = QVBoxLayout(card)
        box.setContentsMargins(24, 26, 24, 22)
        box.setSpacing(10)
        box.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # 圆形头像（素材缺失时自动隐藏，不影响整体）
        self.avatar = QLabel()
        pixmap = circular_pixmap(AVATAR_PATH, AVATAR_SIZE)
        if pixmap is not None:
            self.avatar.setPixmap(pixmap)
            self.avatar.setFixedSize(AVATAR_SIZE, AVATAR_SIZE)
            self.avatar.setAlignment(Qt.AlignmentFlag.AlignCenter)
        else:
            self.avatar.hide()
        box.addWidget(self.avatar, 0, Qt.AlignmentFlag.AlignCenter)

        # 名称
        name = QLabel("28.7")
        name.setAlignment(Qt.AlignmentFlag.AlignCenter)
        name.setStyleSheet(
            f"color: {self.theme.text};"
            f" font-size: 24px; font-weight: 700;"
            f" font-family: \"{self.theme.font_title_family}\", \"微软雅黑\";"
        )
        box.addWidget(name)

        # 随机言语
        self.quote = QLabel(random.choice(SPLASH_QUOTES))
        self.quote.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.quote.setWordWrap(True)
        self.quote.setStyleSheet(
            f"color: {self.theme.text_muted};"
            f" font-size: {self.theme.font_caption_size}px;"
            f" font-family: \"{self.theme.font_ui_family}\", \"微软雅黑\";"
        )
        box.addWidget(self.quote)

        # 固定窗口高度，配合卡片宽度形成居中的小卡片
        self.adjustSize()

        # 淡入动画：整体透明度 0 -> 1
        self._effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self._effect)
        self._anim = QPropertyAnimation(self._effect, b"opacity", self)
        self._anim.setDuration(320)
        self._anim.setStartValue(0.0)
        self._anim.setEndValue(1.0)
        self._anim.setEasingCurve(QEasingCurve.Type.OutCubic)

    def show_centered(self) -> None:
        """居中到主屏可用区域并启动淡入。"""
        screen = self.screen()
        if screen is None:
            from PySide6.QtWidgets import QApplication
            screen = QApplication.primaryScreen()
        if screen is not None:
            geo = screen.availableGeometry()
            self.adjustSize()
            x = geo.x() + (geo.width() - self.width()) // 2
            y = geo.y() + (geo.height() - self.height()) // 2
            self.move(x, y)
        self.show()
        self._anim.start()

    def fade_out_and_close(self, on_done=None) -> None:
        """淡出后关闭窗口；``on_done`` 在关闭后回调（可选）。

        淡出动画完成前不删除自身，动画结束后统一「关闭 → 回调 → 释放」，
        避免过早 ``deleteLater`` 把动画对象连带销毁、回调永不触发。
        """
        anim = QPropertyAnimation(self._effect, b"opacity", self)
        anim.setDuration(180)
        anim.setStartValue(1.0)
        anim.setEndValue(0.0)
        anim.setEasingCurve(QEasingCurve.Type.InCubic)

        def _on_finished() -> None:
            self.close()
            if on_done is not None:
                on_done()
            self.deleteLater()

        anim.finished.connect(_on_finished)
        anim.start()
        # 动画对象需在期间存活，挂到 self 上防止被 GC
        self._fade_out_anim = anim
