# -*- coding: utf-8 -*-
"""关于页：作者 / 项目介绍 / 公众号引导 / 开源协议与仓库 / 功能一览 / 免责声明。

顶部为居中的「头像 + 28.7」作者横幅；图片素材取自项目 ``lib/img`` 目录
（PyInstaller 冻结环境回退到 ``sys.打包数据根``，spec 已把 ``lib/img`` 打入
datas）。素材缺失时自动降级为纯文字，不影响页面可用性。
"""

from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtCore import Qt, QRectF, QUrl
from PySide6.QtGui import QDesktopServices, QPainter, QPainterPath, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

#: 开源仓库地址（关于页展示与复制用）
REPO_URL = "https://github.com/2022471674/cipherNest"
#: 开源协议展示名（LICENSE 文件即 Apache-2.0 全文）
LICENSE_NAME = "Apache License 2.0"
#: 公众号搜索关键词（微信搜一搜）
WX_KEYWORD = "28.7Blog"
#: 整合使用的开源项目（名称 -> (项目地址, 用途说明)）
CREDIT_PROJECTS: dict[str, tuple[str, str]] = {
    "GitHack": (
        "https://github.com/lijiejie/GitHack",
        "「源码泄露」：解析 ``.git/index`` 按 sha1 拉 objects 并 zlib 解压，"
        "还原工程源码（scan_git 移植自本项目）",
    ),
    "SvnHack": (
        "https://github.com/shengqi158/svnhack",
        "「源码泄露」：还原泄露的 SVN 仓库，支持 1.6（entries）与 "
        "1.7+（wc.db），scan_svn 移植自本项目",
    ),
    "Python-dsstore": (
        "https://github.com/gehaxelt/Python-dsstore",
        "「源码泄露」：解析 ``.DS_Store`` 抽取目录下的全部文件名"
        "（相当于免费目录爆破），结构与本项目同源",
    ),
    "JSFinder": (
        "https://github.com/Threezh1/JSFinder",
        "「JS 信息收集」：从页面与脚本中提取 URL / 子域名"
        "（lib/jsfinder.py 移植，深度模式并发化）",
    ),
}
#: 作者联系方式（QQ 邮箱）
CONTACT_QQ_EMAIL = "2022471677@qq.com"
#: 作者联系方式（谷歌邮箱）
CONTACT_GMAIL_EMAIL = "lujin2404@gmail.com"


def _asset_dir() -> Path:
    """图片素材目录：开发态为项目 ``lib/img``，冻结态回退到打包数据根。"""
    from lib.runtime_paths import resource

    return resource("lib", "img")


_ASSET_DIR = _asset_dir()
#: 作者头像（侧边栏 header 顶部占位卡片用）
AVATAR_PATH = _ASSET_DIR / "author_avatar.JPG"
#: 微信搜一搜宣传横幅：白色版适配亮色主题，标准色版适配暗色主题
QR_BANNER_LIGHT = _ASSET_DIR / "扫码_搜索联合传播样式-白色版.png"
QR_BANNER_DARK = _ASSET_DIR / "扫码_搜索联合传播样式-标准色版.png"


def circular_pixmap(source: Path | str, size: int) -> QPixmap | None:
    """把图片居中裁切为圆形头像；文件缺失或无法加载时返回 ``None``。

    供启动画面（``app.splash``）与其它需要圆形头像的组件复用。
    """
    pm = QPixmap(str(source))
    if pm.isNull():
        return None
    side = min(pm.width(), pm.height())
    pm = pm.copy((pm.width() - side) // 2, (pm.height() - side) // 2,
                 side, side).scaled(
        size, size, Qt.AspectRatioMode.KeepAspectRatio,
        Qt.TransformationMode.SmoothTransformation)

    out = QPixmap(size, size)
    out.fill(Qt.GlobalColor.transparent)
    painter = QPainter(out)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    path = QPainterPath()
    path.addEllipse(QRectF(0, 0, size, size))
    painter.setClipPath(path)
    painter.drawPixmap(0, 0, pm)
    painter.end()
    return out


def _copy(text: str) -> None:
    if text:
        QApplication.clipboard().setText(text)


class AboutPage(QWidget):
    """关于页：作者横幅 + 项目介绍 + 公众号 + 协议 / 仓库 + 功能 + 免责。"""

    def __init__(self, theme, store, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.store = store
        self._build()

    # ------------------------------------------------------------------ UI
    def _build(self) -> None:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)
        scroll.setWidget(container)

        layout.addWidget(self._build_intro())
        layout.addWidget(self._build_wechat())
        layout.addWidget(self._build_license())
        layout.addWidget(self._build_credits())
        layout.addWidget(self._build_contact())
        layout.addWidget(self._build_disclaimer())
        layout.addWidget(self._build_tech())
        layout.addStretch(1)

    # ------------------------------------------------------------- 小部件
    def _card(self) -> QWidget:
        card = QWidget()
        card.setObjectName("card")
        return card

    @staticmethod
    def _heading(text: str, color: str | None = None) -> QLabel:
        label = QLabel(text)
        label.setStyleSheet(
            "font-size: 14px; font-weight: 600;"
            + (f" color: {color};" if color else ""))
        return label

    @staticmethod
    def _caption(text: str) -> QLabel:
        label = QLabel(text)
        label.setObjectName("caption")
        label.setWordWrap(True)
        return label

    def _btn(self, text: str, on_click, primary: bool = False) -> QPushButton:
        btn = QPushButton(text)
        btn.setObjectName("ghbtn-primary" if primary else "ghbtn")
        btn.clicked.connect(on_click)
        return btn

    # ----------------------------------------------------------- 作者横幅
    # （已移除：原顶部「头像 + 28.7 + 简介 + 版本/协议」横幅与版权声明重叠，
    #   现已删除，直接以「关于项目」卡片开头。）

    # --------------------------------------------------------------- 关于
    def _build_intro(self) -> QWidget:
        card = self._card()
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(6)

        layout.addWidget(self._heading("关于项目"))
        layout.addWidget(self._caption(
            "cipherNest 是面向 CTF 比赛与日常安全测试的 Hello World 编解码 / "
            "密码学工具箱，把密码 Fuzz / Base / ROT / 哈希 / 进制 / 字符串处理 / "
            "凯撒猪圈 / JWT / 智能翻译 / 键盘模拟 / MD5 爆破 / 图片工具 / "
            "压缩包分析 / 主机探针 / 源码泄露与目录爆破 / 端口爆破 / MySQL 爆破 / 局域网传输等常用工具整合进一个单窗体应用，"
            "开箱即用。"
        ))
        layout.addWidget(self._caption(
            "项目持续迭代中，功能建议与问题反馈欢迎通过开源仓库的 "
            "Issue 提出，或关注公众号获取更新通知与使用教程。"
        ))
        layout.addWidget(self._caption(
            "遇到 Bug 或有新想法？欢迎到仓库提交 Issue —— "
            "报告问题时请附上复现步骤、版本号与系统环境，"
            "提出功能建议时请说明使用场景，你的反馈会帮助工具做得更好。"
        ))
        issue_url = REPO_URL.rstrip("/") + "/issues"
        issue = QLabel(f'<a href="{issue_url}">提交 Issue →</a>')
        issue.setObjectName("caption")
        issue.setOpenExternalLinks(True)
        issue.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextBrowserInteraction)
        layout.addWidget(issue)
        return card

    # ----------------------------------------------------------- 公众号
    def _build_wechat(self) -> QWidget:
        card = self._card()
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(8)

        layout.addWidget(self._heading("关注公众号"))

        banner_path = (QR_BANNER_DARK if self.theme.mode == "dark"
                       else QR_BANNER_LIGHT)
        banner = QPixmap(str(banner_path))
        if not banner.isNull():
            label = QLabel()
            label.setPixmap(banner.scaled(
                440, 146, Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation))
            label.setFixedWidth(440)
            layout.addWidget(label)
        else:
            layout.addWidget(self._caption(
                "（宣传图缺失）微信搜一搜「28.7Blog」即可找到公众号。"))

        layout.addWidget(self._caption(
            f"微信搜索「{WX_KEYWORD}」或扫描上方二维码，关注公众号获取"
            "更新通知、CTF 题解与工具使用教程。"))

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        buttons.addWidget(self._btn(
            "复制公众号名称", lambda: _copy(WX_KEYWORD)))
        buttons.addWidget(self._btn(
            "打开宣传图", lambda: QDesktopServices.openUrl(
                QUrl.fromLocalFile(str(banner_path)))))
        buttons.addStretch(1)
        layout.addLayout(buttons)
        return card

    # ------------------------------------------------------- 协议与仓库
    def _build_license(self) -> QWidget:
        card = self._card()
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(6)

        layout.addWidget(self._heading("开源协议"))
        layout.addWidget(self._caption(
            f"本项目代码基于 {LICENSE_NAME} 保护：你可以自由地使用、修改、"
            "分发本软件（含商业用途），但需保留版权与许可证声明；"
            "专利授权与免责声明条款详见项目根目录 LICENSE 文件。"
        ))
        layout.addWidget(self._caption(
            "版权归属作者「28.7」。作者标识（28.7）与作者头像"
            "（lib/img/author_avatar.JPG）以 CC BY 4.0 许可发布，"
            "任何二次创作 / 衍生作品的开发者都必须保留并显著展示「28.7」标识，"
            "并一并携带该头像标识，详情见项目根目录 NOTICE 文件。"
        ))

        layout.addWidget(self._heading("开源仓库"))
        repo = QLabel(REPO_URL)
        repo.setObjectName("caption")
        repo.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(repo)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        buttons.addWidget(self._btn(
            "复制仓库地址", lambda: _copy(REPO_URL)))
        buttons.addWidget(self._btn(
            "打开仓库页面", lambda: QDesktopServices.openUrl(QUrl(REPO_URL))))
        buttons.addStretch(1)
        layout.addLayout(buttons)

        layout.addWidget(self._caption(
            "欢迎 Star 支持、提交 Issue 参与反馈，或 PR 一起完善工具箱。"))
        return card

    # ------------------------------------------------------- 开源项目致谢
    def _build_credits(self) -> QWidget:
        card = self._card()
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(6)

        layout.addWidget(self._heading("开源项目致谢"))
        layout.addWidget(self._caption(
            "本工具整合并使用了以下开源作品，在此向原作者致以诚挚感谢"
            "（点击仓库名可直接打开项目主页）："
        ))
        for name, (url, usage) in CREDIT_PROJECTS.items():
            # 用途说明（普通文本）
            layout.addWidget(self._caption(f"{name} —— {usage}"))
            # 仓库地址（可点击打开 / 可复制）
            link = QLabel(f'<a href="{url}">{url}</a>')
            link.setObjectName("caption")
            link.setOpenExternalLinks(True)
            link.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextBrowserInteraction)
            layout.addWidget(link)
        layout.addWidget(self._caption(
            "感谢以上作者的无私开源，让这些思路得以沉淀进本工具箱。"))
        return card

    # ------------------------------------------------------------- 联系
    def _build_contact(self) -> QWidget:
        card = self._card()
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(6)

        layout.addWidget(self._heading("联系方式"))
        layout.addWidget(self._caption(
            "任何问题与建议，欢迎通过以下邮箱联系作者："
        ))
        qq = QLabel(f"QQ 邮箱：{CONTACT_QQ_EMAIL}")
        qq.setObjectName("caption")
        qq.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(qq)
        gmail = QLabel(f"谷歌邮箱：{CONTACT_GMAIL_EMAIL}")
        gmail.setObjectName("caption")
        gmail.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(gmail)
        return card

    # ------------------------------------------------------------- 免责
    def _build_disclaimer(self) -> QWidget:
        card = self._card()
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(6)

        layout.addWidget(self._heading("免责声明", self.theme.warning))
        layout.addWidget(self._caption(
            "• 本工具面向 CTF 竞赛、授权安全测试与教学研究，请勿用于"
            "未授权的攻击行为；"
        ))
        layout.addWidget(self._caption(
            "• MD5 爆破、键盘模拟、压缩包密码爆破、主机探针、隐写分析等"
            "属于敏感能力，请在合法授权范围内使用；"
        ))
        layout.addWidget(self._caption(
            "• 因不当使用本软件造成的任何直接或间接损失与法律责任，"
            "均由使用者自行承担，作者概不负责；"
        ))
        layout.addWidget(self._caption(
            "• 作者不对任何非法使用本工具的行为承担任何责任；"
        ))
        layout.addWidget(self._caption(
            "• 本软件按「现状」提供，不附带任何明示或暗示的担保。"
            "使用即表示你已阅读并同意本声明，以及根目录 NOTICE 文件中的全部条款。"
        ))
        return card

    # ------------------------------------------------------------- 技术
    def _build_tech(self) -> QWidget:
        card = self._card()
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(6)

        layout.addWidget(self._heading("技术信息"))
        layout.addWidget(self._caption(
            "界面：PySide6 + QFluentWidgets　·　主题：GitHub Primer 明 / 暗双主题"))
        layout.addWidget(self._caption(
            f"运行环境：Python {sys.version.split()[0]}"))
        config_path = self._caption(f"配置文件：{self.store.path}")
        layout.addWidget(config_path)
        return card
