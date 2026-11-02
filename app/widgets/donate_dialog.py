# -*- coding: utf-8 -*-
"""打赏弹窗：微信 / 支付宝收款二维码 + 标语。

设计
----
- 全屏（覆盖父窗）无边框弹窗，四周为半透明遮罩，点击遮罩（空白处）即关闭；
- 按 ``Esc`` 也可关闭；
- 中心卡片内并排展示「微信」与「支付宝」两张收款码，图片缺失时降级为文字；
- 二维码素材取自 ``static/qcor``（开发态项目根，冻结态 data_root 下），
  已在打包 spec 的 ``datas`` 中随包分发。
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from lib.runtime_paths import resource


#: 打赏标语
SLOGAN = "如果觉得还不错，打赏一下吧，愿上帝保佑你，阿门"
#: 微信收款码路径
WECHAT_QR = resource("static", "qcor", "wechar.JPG")
#: 支付宝收款码路径
ALIPAY_QR = resource("static", "qcor", "alipay.JPG")
#: 二维码展示尺寸（像素）
QR_SIZE = 220


def _qr_label(path: Path, title: str, subtitle: str) -> QWidget:
    """生成「标题 + 二维码 + 副标题」竖排小组件。"""
    box = QWidget()
    layout = QVBoxLayout(box)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(8)

    name = QLabel(title)
    name.setObjectName("section")
    name.setAlignment(Qt.AlignmentFlag.AlignHCenter)
    layout.addWidget(name)

    pm = QPixmap(str(path))
    if pm.isNull():
        placeholder = QLabel(subtitle)
        placeholder.setObjectName("caption")
        placeholder.setWordWrap(True)
        placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(placeholder)
    else:
        img = QLabel()
        img.setPixmap(pm.scaled(
            QR_SIZE, QR_SIZE,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation))
        img.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(img)

    caption = QLabel(subtitle)
    caption.setObjectName("caption")
    caption.setAlignment(Qt.AlignmentFlag.AlignHCenter)
    layout.addWidget(caption)
    return box


class DonateDialog(QDialog):
    """全屏遮罩式打赏弹窗（模态），点空白或按 Esc 关闭。"""

    def __init__(self, theme, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.setObjectName("donateOverlay")
        self.setWindowFlags(
            Qt.WindowType.Dialog
            | Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setModal(True)
        self._build()

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 24, 24, 24)

        # 居中：卡片放在水平居中 + 垂直居中的位置
        card = QWidget()
        card.setObjectName("card")
        card.setCursor(Qt.CursorShape.ArrowCursor)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(16)

        title = QLabel("打赏支持")
        title.setObjectName("title")
        title.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        layout.addWidget(title)

        slogan = QLabel(SLOGAN)
        slogan.setObjectName("caption")
        slogan.setWordWrap(True)
        slogan.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        layout.addWidget(slogan)

        # 两张二维码并排
        qr_row = QHBoxLayout()
        qr_row.setSpacing(32)
        qr_row.addWidget(_qr_label(WECHAT_QR, "微信", "微信扫一扫赞赏"))
        qr_row.addWidget(_qr_label(ALIPAY_QR, "支付宝", "支付宝扫一扫赞赏"))
        layout.addLayout(qr_row)

        hint = QLabel("点击空白处或按 Esc 关闭")
        hint.setObjectName("caption")
        hint.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        layout.addWidget(hint)

        # 水平 + 垂直都居中
        hbox = QHBoxLayout()
        hbox.addStretch(1)
        hbox.addWidget(card)
        hbox.addStretch(1)
        vbox = QVBoxLayout()
        vbox.addStretch(1)
        vbox.addLayout(hbox)
        vbox.addStretch(1)
        root.addLayout(vbox)

    # ------------------------------------------------------- 遮罩与事件
    def showEvent(self, event) -> None:  # noqa: N802  Qt 命名约定
        super().showEvent(event)
        # 铺满父窗（若有）或主屏可用区域，形成覆盖遮罩
        if self.parentWidget() is not None:
            self.setGeometry(self.parentWidget().rect())
        else:
            from PySide6.QtWidgets import QApplication
            screen = QApplication.primaryScreen()
            if screen is not None:
                self.setGeometry(screen.availableGeometry())

    def mousePressEvent(self, event) -> None:  # noqa: N802  Qt 命名约定
        # 点击任何空白（非卡片）区域都关闭；卡片上的子控件会先消费事件，
        # 因此能走到这里的只有遮罩空白处。
        self.close()
        super().mousePressEvent(event)

    def keyPressEvent(self, event) -> None:  # noqa: N802  Qt 命名约定
        if event.key() == Qt.Key.Key_Escape:
            self.close()
            return
        super().keyPressEvent(event)

    def paintEvent(self, event) -> None:  # noqa: N802  Qt 命名约定
        # 半透明黑色遮罩（背景），让底层窗口微微透出、点击空白区视觉可辨。
        from PySide6.QtGui import QColor, QPainter
        painter = QPainter(self)
        painter.fillRect(self.rect(), QColor(0, 0, 0, 120))
        painter.end()
        super().paintEvent(event)
