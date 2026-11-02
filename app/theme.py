# -*- coding: utf-8 -*-
from __future__ import annotations

import re
from dataclasses import dataclass

from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication

THEME_LIGHT = "light"
THEME_DARK = "dark"

# ---------------------------------------------------------------------------
# 按钮尺寸令牌：所有按钮（普通 / 主 / 危险 / chips）共用同一套圆角与内边距，
# 避免各处硬编码魔法数字导致视觉不统一。
# ---------------------------------------------------------------------------
BTN_RADIUS = 6          # 矩形按钮圆角
BTN_PAD_V = 5           # 上下内边距
BTN_PAD_H = 12          # 左右内边距
BTN_MIN_HEIGHT = 22     # 最小高度（保证密集文字按钮不塌陷）
CHIP_RADIUS = 13        # 胶囊 chips 圆角（≈ 高度一半）
CHIP_PAD_V = 4
CHIP_PAD_H = 12


@dataclass(frozen=True)
class GitHubPalette:
    """一组语义色，供 QSS 与代码绘色共同引用。

    类属性（非 dataclass 字段）为界面文案常量：旧版这些文案来自 .env ->
    config -> theme 三层转发，重构后直接挂在调色板对象上，界面层只需持有
    一个 theme 引用即可同时取到颜色与文案。
    """

    mode: str
    bg: str              # 窗口底色
    surface: str         # 卡片 / 面板底色
    surface_alt: str     # 输入框底色
    surface_out: str     # 标签页内容区底色
    border: str          # 边框 / 分隔线
    text: str            # 正文
    text_muted: str      # 次要文字
    accent: str          # 主色（链接蓝 / 强调）
    accent_hover: str    # 主色悬停
    accent_deep: str     # 主色加深（输入框聚焦边框等）
    accent_fg: str       # 主色上的文字
    accent_pink: str     # 点缀色：首页卡片悬停边框
    accent_rose: str     # 点缀色：滚动条悬停
    accent_sand: str     # 点缀色：标签页悬停下划线
    success: str         # 成功绿
    danger: str          # 危险红
    warning: str         # 警告黄
    btn_hover: str       # 中性按钮悬停底色
    btn_press: str       # 中性按钮按下底色
    mono_bg: str         # 等宽文本区底色

    # ------------------------------------------------------------------
    # 字体令牌（可在设置中自定义，size 单位为 px）
    # ------------------------------------------------------------------
    font_ui_family: str = "Microsoft YaHei UI"
    font_ui_size: int = 13
    font_caption_size: int = 12
    font_title_family: str = "Microsoft YaHei UI"
    font_title_size: int = 20
    font_mono_family: str = "Consolas"
    font_mono_size: int = 13

    # ------------------------------------------------------------------
    # 界面文案（与颜色无关，挂在调色板上供界面层统一从 theme 取）
    # ------------------------------------------------------------------
    UI_TITLE = "28zenro"
    UI_HEADLINE = "28zenro"
    UI_AUTH = "28.7"
    UI_BTN_CLEAR = "清空内容"
    UI_BTN_PASTE = "粘贴剪贴板"
    UI_BTN_COPY = "复制"
    UI_BTN_USE_AS_INPUT = "↑ 用作输入"
    UI_EMPTY_INPUT = "请输入待处理内容。"
    UI_PLACEHOLDER_INPUT = "在此粘贴待处理内容…"
    UI_PLACEHOLDER_OUTPUT = "执行后在此显示结果…"
    UI_SUFFIX_FAILED = "失败"
    UI_TRANSLATING = "翻译中，请稍候…"
    UI_TRANSLATE_FAILED = "翻译失败"
    # 键盘模拟
    ALGO_KEY_SIMULATE = "模拟输入"
    UI_KEY_SIM_BTN_START = "开始"
    UI_KEY_SIM_BTN_STOP = "停止"
    UI_KEY_SIM_HINT = ("提示：点击「开始」后请在倒计时内切换到目标窗口，"
                       "按键会注入当前获得焦点的窗口；{ENTER} 这类特殊键名同样可用。")
    UI_KEY_SIM_IDLE = "就绪：填写内容与参数后点击「开始」。"
    UI_KEY_SIM_READY = "将于 {seconds} 秒后开始（共 {count} 次按键），请切换到目标窗口…"
    UI_KEY_SIM_RUNNING = "模拟中：{pressed} / {total} 次（{rate} 次/秒）"
    UI_KEY_SIM_DONE = "模拟完成：共输入 {pressed} 次按键。"
    UI_KEY_SIM_STOPPED = "已停止：共输入 {pressed} 次按键。"
    UI_KEY_SIM_PROTECTED = ("检测到前台窗口是受反作弊保护的进程「{process}」："
                            "它会拦截 SendInput 合成输入，模拟不会生效，已跳过本次注入。")
    # MD5 爆破
    ALGO_MD5_CRASH = "md5_Crash"
    UI_MD5_CRASH_LABEL_MD5 = "MD5 值（32 位十六进制）"
    UI_MD5_CRASH_LABEL_MODE = "爆破模式"
    UI_MD5_CRASH_MODE_DIGITS = "纯数字"
    UI_MD5_CRASH_MODE_LETTERS = "纯字母"
    UI_MD5_CRASH_MODE_MIXED = "混合（默认）"
    UI_MD5_CRASH_MODE_DICT = "字典爆破"
    UI_MD5_CRASH_BTN_DICT_CHOOSE = "选择字典文件…"
    UI_MD5_CRASH_BTN_DICT_DEFAULT = "使用默认字典"
    UI_MD5_CRASH_LABEL_DICT_CANDIDATES = "候选输入池"
    UI_MD5_CRASH_DICT_SELECTED = "字典已就绪：{name}（{count} 个文件，共 {entries} 条候选）"
    UI_MD5_CRASH_HINT = ("提示：纯数字模式从 0 开始递增到指定长度；纯字母为大小写字母排列；"
                         "混合模式在字母数字与 . , ; * @ # 中排列。"
                         "长度越长枚举量越大，建议先用小长度测试。"
                          "已知原文开头/结尾可填预测前缀/后缀，自动拼接枚举剩余部分。")
    UI_MD5_CRASH_LABEL_LOG = "爆破日志"
    UI_MD5_CRASH_BTN_START = "开始"
    UI_MD5_CRASH_BTN_STOP = "停止"
    UI_MD5_CRASH_IDLE = "就绪：填写 MD5 与参数后点击「开始」。"
    UI_MD5_CRASH_RUNNING = "爆破进行中…点击「停止」可中止。"
    UI_MD5_CRASH_FOUND = "爆破成功：明文为「{plain}」，耗时 {cost:.1f} 秒。"
    UI_MD5_CRASH_STOPPED = "已停止：本次爆破未完成。"
    UI_MD5_CRASH_DONE = "爆破结束：未找到匹配明文。"
    UI_MD5_CRASH_LOG_PROGRESS = "已尝试 {count} 次，当前候选：{text}"
    UI_MD5_CRASH_LABEL_PREFIX = "预测前缀（已知原文开头）"
    UI_MD5_CRASH_LABEL_SUFFIX = "预测后缀（已知原文结尾）"
    UI_MD5_CRASH_PREFIX_PLACEHOLDER = "例如：abc（可选）"
    UI_MD5_CRASH_SUFFIX_PLACEHOLDER = "例如：123（可选）"
    UI_MD5_CRASH_PRED_INVALID = "预测词长度不能超过最大长度"
    UI_MD5_CRASH_PRED_TOO_LONG = "预测词总长 {pred_len} 位，最大长度仅 {max_len} 位，无法枚举剩余部分"


LIGHT = GitHubPalette(
    mode=THEME_LIGHT,
    bg="#ffffff",
    surface="#f6f8fa",
    surface_alt="#ffffff",
    surface_out="#f3f4f6",
    border="#d0d7de",
    text="#1f2328",
    text_muted="#59636e",
    accent="#0969da",
    accent_hover="#0860c4",
    accent_deep="#054291",
    accent_fg="#ffffff",
    accent_pink="#0969da",
    accent_rose="#59636e",
    accent_sand="#d0d7de",
    success="#1a7f37",
    danger="#d1242f",
    warning="#9a6700",
    btn_hover="#f3f4f6",
    btn_press="#eaeef2",
    mono_bg="#f6f8fa",
)

DARK = GitHubPalette(
    mode=THEME_DARK,
    bg="#151517",
    surface="#232324",
    surface_alt="#2c2c2e",
    surface_out="#1b1b1d",
    border="#333338",
    text="#e6edf3",
    text_muted="#8b949e",
    accent="#4176e6",
    accent_hover="#5a8af0",
    accent_deep="#3358c4",
    accent_fg="#ffffff",
    accent_pink="#4176e6",
    accent_rose="#8b949e",
    accent_sand="#333338",
    success="#3fb950",
    danger="#f85149",
    warning="#d29922",
    btn_hover="#2c2c2e",
    btn_press="#333338",
    mono_bg="#232324",
)


# ---------------------------------------------------------------------------
# 可自定义令牌表：设置页据此渲染编辑器，新增令牌只需在此登记
# ---------------------------------------------------------------------------
#: 颜色令牌：(键, 分组, 标签)。键即 GitHubPalette 字段名。
COLOR_TOKENS: tuple[tuple[str, str, str], ...] = (
    ("accent", "主色系", "主色（按钮 / 链接 / 选中）"),
    ("accent_hover", "主色系", "主色悬停"),
    ("accent_deep", "主色系", "主色加深（聚焦边框）"),
    ("accent_fg", "主色系", "主色上的文字"),
    ("accent_pink", "主色系", "点缀 · 卡片悬停边框"),
    ("accent_rose", "主色系", "点缀 · 滚动条悬停"),
    ("accent_sand", "主色系", "点缀 · 标签页悬停"),
    ("bg", "中性色", "窗口背景"),
    ("surface", "中性色", "卡片 / 面板"),
    ("surface_alt", "中性色", "输入框背景"),
    ("surface_out", "中性色", "标签页内容区背景"),
    ("border", "中性色", "边框 / 分隔线"),
    ("text", "中性色", "正文文字"),
    ("text_muted", "中性色", "次要文字"),
    ("btn_hover", "中性色", "按钮悬停"),
    ("btn_press", "中性色", "按钮按下"),
    ("mono_bg", "中性色", "等宽文本区底色"),
    ("success", "状态色", "成功"),
    ("danger", "状态色", "危险"),
    ("warning", "状态色", "警告"),
)

#: 字体令牌：(键, 标签, 类型)。类型 "family" 为字体名，"size" 为 px 字号。
FONT_TOKENS: tuple[tuple[str, str, str], ...] = (
    ("font_ui_family", "界面字体", "family"),
    ("font_ui_size", "正文字号（px）", "size"),
    ("font_caption_size", "辅助文字字号（px）", "size"),
    ("font_title_family", "标题字体", "family"),
    ("font_title_size", "标题字号（px）", "size"),
    ("font_mono_family", "等宽字体", "family"),
    ("font_mono_size", "等宽字号（px）", "size"),
)

_HEX_RE = re.compile(r"^#?[0-9a-fA-F]{6}$")


def normalize_color(value) -> str | None:
    """校验并规范化 ``#RRGGBB`` 颜色字符串；非法返回 None。"""
    text = str(value or "").strip()
    if not _HEX_RE.match(text):
        return None
    if not text.startswith("#"):
        text = "#" + text
    return text.lower()


def palette_for(mode: str, overrides: dict | None = None) -> GitHubPalette:
    """按模式名取调色板并应用用户自定义覆盖，未知值回退 Light。

    ``overrides`` 为 ``{令牌键: 值}``（来自设置页），非法颜色 / 未知键
    自动忽略，回退到预设值。
    """
    base = DARK if mode == THEME_DARK else LIGHT
    if not overrides:
        return base

    from dataclasses import fields, replace

    valid = {f.name for f in fields(GitHubPalette)}
    merged: dict = {}
    for key, value in overrides.items():
        if key not in valid:
            continue
        if key.startswith("font_"):
            if key.endswith("_family"):
                text = str(value or "").strip()
                if text:
                    merged[key] = text
            else:
                try:
                    size = int(value)
                except (TypeError, ValueError):
                    continue
                if 8 <= size <= 48:
                    merged[key] = size
        else:
            color = normalize_color(value)
            if color:
                merged[key] = color
    return replace(base, **merged) if merged else base


def custom_color_bucket(colors, mode: str) -> dict:
    """从 ``custom_colors`` 配置节点取指定模式（light / dark）的配色覆盖。

    新格式按 ``{"light": {...}, "dark": {...}}`` 分模式存储，两种模式各自
    独立记录一套配色；旧版扁平格式（直接 ``{令牌: 颜色}``）视为明暗共用，
    两种模式都返回，保证旧配置不丢数据。
    """
    if not isinstance(colors, dict):
        return {}
    legacy = {k: v for k, v in colors.items() if k not in ("light", "dark")}
    merged = dict(legacy)
    bucket = colors.get(mode)
    if isinstance(bucket, dict):
        merged.update(bucket)
    return merged


def overrides_from_store(store, mode: str) -> dict:
    """从用户配置读取自定义覆盖：颜色按 ``mode`` 取对应模式，字体明暗共用。"""
    overrides = custom_color_bucket(store.get("custom_colors", default={}), mode)
    fonts = store.get("custom_fonts", default={}) or {}
    if isinstance(fonts, dict):
        overrides.update(fonts)
    return overrides


def palette_from_store(store, mode: str) -> GitHubPalette:
    """从用户配置读取自定义颜色 / 字体并合并出当前调色板。"""
    return palette_for(mode, overrides_from_store(store, mode))


def build_qss(p: GitHubPalette) -> str:
    """把调色板渲染成全局 QSS。

    说明：
    - QFluentWidgets 自身控件跟随 ``setTheme`` 走明暗，这里主要覆盖
      自定义容器 / 文本区 / 按钮等需要 GitHub 观感的部分；
    - 选择器尽量用类名，避免逐控件 setProperty 带来的维护成本。
    """
    # 明暗模式统一应用输入框样式：background: transparent 让所有输入框
    # 无底色，与卡片 / 面板背景自然融合，避免 QFluentWidgets 原生暗色背景
    # 与自定义控件之间出现色差。
    text_area_qss = f"""
    QPlainTextEdit#io, QTextEdit#io {{
        background: transparent;
        color: {p.text};
        border: 1px solid {p.border};
        border-radius: 4px;
        padding: 8px 10px;
        selection-background-color: {p.accent};
        selection-color: {p.accent_fg};
        font-family: "{p.font_mono_family}", "Consolas", "Courier New", monospace;
        font-size: {p.font_mono_size}px;
    }}
    QPlainTextEdit#io:focus, QTextEdit#io:focus {{
        border: 1px solid {p.accent};
    }}
"""

    line_edit_qss = f"""
    QLineEdit, QComboBox, QSpinBox {{
        background: transparent;
        color: {p.text};
        border: 1px solid {p.border};
        border-radius: 4px;
        padding: 4px 8px;
        min-height: 22px;
        selection-background-color: {p.accent};
        selection-color: {p.accent_fg};
    }}
    QLineEdit:focus, QComboBox:focus, QSpinBox:focus {{
        border: 1px solid {p.accent_deep};
    }}
    QComboBox::drop-down {{
        border: none;
        width: 22px;
    }}
    QComboBox QAbstractItemView {{
        background: {p.surface};
        color: {p.text};
        border: 1px solid {p.border};
        selection-background-color: {p.accent};
        selection-color: {p.accent_fg};
    }}
"""

    return f"""
    QWidget {{
        background: transparent;
        color: {p.text};
        font-family: "{p.font_ui_family}", "微软雅黑", "Segoe UI", sans-serif;
        font-size: {p.font_ui_size}px;
    }}

    /* ---------- 卡片 ---------- */
    Frame#card, QWidget#card {{
        background-color: {p.surface};
        border: 1px solid {p.border};
        border-radius: 6px;
    }}

    /* ---------- 分隔线 ---------- */
    QWidget#divider {{
        background-color: {p.border};
        max-height: 1px;
        min-height: 1px;
    }}
    QWidget#dividerV {{
        background-color: {p.border};
        max-width: 1px;
        min-width: 1px;
    }}

    /* ---------- 标签 ---------- */
    QLabel#title {{
        font-family: "{p.font_title_family}", "微软雅黑", "Segoe UI", sans-serif;
        font-size: {p.font_title_size}px;
        font-weight: 700;
        color: {p.text};
    }}
    QLabel#subtitle, QLabel#caption {{
        color: {p.text_muted};
        font-size: {p.font_caption_size}px;
    }}
    QLabel#section {{
        color: {p.text_muted};
        font-size: {p.font_caption_size}px;
        font-weight: 600;
    }}
    /* 番茄时钟：倒计时卡片内的阶段名（比普通 caption 略醒目） */
    QLabel#pomodoroPhase {{
        color: {p.text_muted};
        font-size: {p.font_caption_size + 1}px;
        font-weight: 600;
    }}

    /* ---------- 标签页内容区 ---------- */
    QTabWidget::pane {{
        background-color: {p.surface_out};
        border: 1px solid {p.border};
        border-radius: 6px;
        top: -1px;
    }}
    QTabBar::tab {{
        background: transparent;
        color: {p.text_muted};
        padding: 5px 14px;
        margin-right: 2px;
        border-bottom: 2px solid transparent;
    }}
    QTabBar::tab:selected {{
        color: {p.text};
        font-weight: 600;
        border-bottom: 2px solid {p.accent};
    }}
    QTabBar::tab:hover:!selected {{
        color: {p.text};
        border-bottom: 2px solid {p.accent_sand};
    }}

    /* ---------- 文本区（明暗模式统一应用 transparent 背景） ---------- */
    {text_area_qss}

    /* ---------- 按钮公共基座 ----------
       QFluentWidgets 的 PushButton 自带一层背景 / 圆角绘制，若 QSS 只改
       background-color 而不接管前景色、边框与文字对齐，两层绘制会叠加，
       表现为「文字旁边多出一块异色」（密集文字按钮上尤其明显）。
       这里对四种按钮统一补全 color / border / radius / padding / 对齐，
       并用 background-clip: padding 切断 Fluent 默认绘制层的干扰。 */
    QPushButton#ghbtn, QPushButton#ghbtn-primary,
    QPushButton#ghbtn-danger, QPushButton#chip {{
        border-radius: {BTN_RADIUS}px;
        padding: {BTN_PAD_V}px {BTN_PAD_H}px;
        min-height: {BTN_MIN_HEIGHT}px;
        text-align: center;
        background-clip: padding;
        background-repeat: no-repeat;
    }}

    /* ---------- 中性按钮（类 GitHub button） ---------- */
    QPushButton#ghbtn {{
        background-color: {p.surface};
        color: {p.text};
        border: 1px solid {p.border};
    }}
    QPushButton#ghbtn:hover {{ background-color: {p.btn_hover}; }}
    QPushButton#ghbtn:pressed {{ background-color: {p.btn_press}; }}
    QPushButton#ghbtn:disabled {{
        color: {p.text_muted};
        border-color: {p.border};
        background-color: {p.bg};
    }}

    /* ---------- 主按钮（accent 填充） ---------- */
    QPushButton#ghbtn-primary {{
        background-color: {p.accent};
        color: {p.accent_fg};
        border: 1px solid {p.accent};
        font-weight: 600;
    }}
    QPushButton#ghbtn-primary:hover {{
        background-color: {p.accent_hover};
        border-color: {p.accent_hover};
    }}
    QPushButton#ghbtn-primary:pressed {{
        background-color: {p.accent};
        border-color: {p.accent};
    }}
    QPushButton#ghbtn-primary:disabled {{
        background-color: {p.border};
        border-color: {p.border};
        color: {p.text_muted};
    }}

    /* ---------- 危险按钮 ---------- */
    QPushButton#ghbtn-danger {{
        background-color: {p.surface};
        color: {p.danger};
        border: 1px solid {p.border};
    }}
    QPushButton#ghbtn-danger:hover {{
        background-color: {p.danger};
        color: #ffffff;
        border-color: {p.danger};
    }}
    QPushButton#ghbtn-danger:pressed {{
        background-color: {p.danger};
        color: #ffffff;
        border-color: {p.danger};
    }}
    QPushButton#ghbtn-danger:disabled {{
        background-color: {p.bg};
        color: {p.text_muted};
        border-color: {p.border};
    }}

    /* ---------- 状态文字 ---------- */
    QLabel#status-ok {{ color: {p.success}; }}
    QLabel#status-err {{ color: {p.danger}; }}
    QLabel#status-warn {{ color: {p.warning}; }}
    QLabel#status-info {{ color: {p.text_muted}; }}

    /* ---------- 工具选择 chips（胶囊，覆盖基座圆角） ---------- */
    QPushButton#chip {{
        background-color: {p.bg};
        color: {p.text};
        border: 1px solid {p.border};
        border-radius: {CHIP_RADIUS}px;
        padding: {CHIP_PAD_V}px {CHIP_PAD_H}px;
        font-weight: 400;
    }}
    QPushButton#chip:hover {{ background-color: {p.btn_hover}; }}
    QPushButton#chip:pressed {{ background-color: {p.btn_press}; }}
    QPushButton#chip:checked {{
        background-color: {p.accent};
        color: {p.accent_fg};
        border: 1px solid {p.accent};
        font-weight: 600;
    }}
    QPushButton#chip:checked:hover {{
        background-color: {p.accent_hover};
        border-color: {p.accent_hover};
    }}

    /* ---------- 一级 chips：分类（描边式，视觉权重低于工具 chips） ---------- */
    QPushButton#chip-group {{
        background: transparent;
        color: {p.text_muted};
        border: 1px solid transparent;
        border-radius: 6px;
        padding: 3px 10px;
        font-weight: 500;
    }}
    QPushButton#chip-group:hover {{
        color: {p.text};
        background-color: {p.btn_hover};
    }}
    QPushButton#chip-group:pressed {{ background-color: {p.btn_press}; }}
    QPushButton#chip-group:checked {{
        color: {p.accent};
        border: 1px solid {p.accent};
        font-weight: 600;
    }}
    QPushButton#chip-group:checked:hover {{ background: transparent; }}

    /* ---------- 设置页 Tag 标签（淘宝筛选式：灰边框 ↔ 蓝底） ---------- */
    QPushButton#tag {{
        background: transparent;
        color: {p.text};
        border: 1px solid {p.border};
        border-radius: 14px;
        padding: 4px 14px;
        font-weight: 400;
    }}
    QPushButton#tag:hover {{
        border-color: {p.accent};
        color: {p.accent};
    }}
    QPushButton#tag:checked {{
        background-color: {p.accent};
        color: {p.accent_fg};
        border: 1px solid {p.accent};
        font-weight: 600;
    }}
    QPushButton#tag:checked:hover {{
        background-color: {p.accent_hover};
        border-color: {p.accent_hover};
    }}

    /* ---------- 设置页左侧导航条目 ---------- */
    QPushButton#nav-item {{
        background: transparent;
        color: {p.text};
        border: none;
        border-radius: 6px;
        padding: 8px 12px;
        text-align: left;
        font-weight: 400;
    }}
    QPushButton#nav-item:hover {{ background-color: {p.btn_hover}; }}
    QPushButton#nav-item:checked {{
        background-color: {p.accent};
        color: {p.accent_fg};
        font-weight: 600;
    }}

    /* ---------- 首页工具卡片 ---------- */
    QWidget#toolcard {{
        background-color: {p.surface};
        border: 1px solid {p.border};
        border-radius: 6px;
    }}
    QWidget#toolcard:hover {{
        border: 1px solid {p.accent_pink};
    }}

    /* ---------- 快捷访问：链接卡片 / 分组标题 ---------- */
    QWidget#linkcard {{
        background-color: transparent;
        border: 1px solid transparent;
        border-radius: 8px;
    }}
    QWidget#linkcard:hover {{
        background-color: {p.surface};
        border: 1px solid {p.accent_pink};
    }}
    QLabel#linktitle {{
        color: {p.text};
        font-size: {p.font_caption_size}px;
        font-weight: 500;
    }}
    QLabel#groupTitle {{
        color: {p.text};
        font-size: 14px;
        font-weight: 600;
    }}

    /* ---------- 侧边栏（NavigationInterface 容器） ---------- */
    QWidget#nav {{
        background-color: {p.surface};
        border-right: 1px solid {p.border};
    }}

    /* ---------- 滚动条 ---------- */
    QScrollArea {{ border: none; background: transparent; }}
    QScrollBar:vertical {{
        background: transparent;
        width: 10px;
        margin: 0;
    }}
    QScrollBar::handle:vertical {{
        background: {p.border};
        border-radius: 5px;
        min-height: 30px;
    }}
    QScrollBar::handle:vertical:hover {{ background: {p.accent_rose}; }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
        height: 0;
    }}
    QScrollBar:horizontal {{
        background: transparent;
        height: 10px;
        margin: 0;
    }}
    QScrollBar::handle:horizontal {{
        background: {p.border};
        border-radius: 5px;
        min-width: 30px;
    }}
    QScrollBar::handle:horizontal:hover {{
        background: {p.accent_rose};
    }}
    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
        width: 0;
    }}

    /* ---------- 输入框 / 下拉 / 自旋（明暗模式统一应用 transparent 背景） ---------- */
    {line_edit_qss}

    /* ---------- 单选 / 复选 ---------- */
    QRadioButton, QCheckBox {{
        color: {p.text};
        spacing: 6px;
    }}
    QRadioButton::indicator, QCheckBox::indicator {{
        width: 15px;
        height: 15px;
        border: 1px solid {p.border};
        border-radius: 3px;
        background: transparent;
    }}
    QRadioButton::indicator {{ border-radius: 8px; }}
    QRadioButton::indicator:checked {{
        background: {p.accent};
        border: 4px solid {p.accent};
    }}
    QCheckBox::indicator:checked {{
        background: {p.accent};
        border: 1px solid {p.accent};
    }}

    /* ---------- 提示气泡 ---------- */
    QToolTip {{
        background-color: {p.surface};
        color: {p.text};
        border: 1px solid {p.border};
        padding: 4px 8px;
    }}
    """


def apply_qpalette(app: QApplication, p: GitHubPalette) -> None:
    """同步 QApplication 级 QPalette，覆盖原生弹窗 / 对话框等杂项控件。"""
    qp = QPalette()
    qp.setColor(QPalette.ColorRole.Window, QColor(p.bg))
    qp.setColor(QPalette.ColorRole.WindowText, QColor(p.text))
    qp.setColor(QPalette.ColorRole.Base, QColor(p.surface_alt))
    qp.setColor(QPalette.ColorRole.AlternateBase, QColor(p.surface))
    qp.setColor(QPalette.ColorRole.Text, QColor(p.text))
    qp.setColor(QPalette.ColorRole.Button, QColor(p.surface))
    qp.setColor(QPalette.ColorRole.ButtonText, QColor(p.text))
    qp.setColor(QPalette.ColorRole.Highlight, QColor(p.accent))
    qp.setColor(QPalette.ColorRole.HighlightedText, QColor(p.accent_fg))
    qp.setColor(QPalette.ColorRole.ToolTipBase, QColor(p.surface))
    qp.setColor(QPalette.ColorRole.ToolTipText, QColor(p.text))
    qp.setColor(QPalette.ColorRole.PlaceholderText, QColor(p.text_muted))
    app.setPalette(qp)


def apply_theme(app: QApplication, mode: str,
                overrides: dict | None = None) -> GitHubPalette:
    """应用明暗主题到 QApplication，返回当前调色板供界面取色。

    ``overrides`` 为用户自定义颜色 / 字体覆盖（键为令牌名），
    会与对应明暗预设合并后渲染 QSS。

    QFluentWidgets 的 setTheme 由调用方在 main_window 内另行调用
    （它负责 Fluent 控件自身的换肤），本函数负责全局 QSS 与 QPalette。
    """
    p = palette_for(mode, overrides)
    apply_qpalette(app, p)
    app.setStyleSheet(build_qss(p))
    return p


def apply_window_background(window, p: GitHubPalette) -> None:
    if hasattr(window, "setMicaEffectEnabled"):
        window.setMicaEffectEnabled(False)
    if hasattr(window, "setCustomBackgroundColor"):
        window.setCustomBackgroundColor(QColor(p.bg), QColor(p.bg))
    # setCustomBackgroundColor 走 120ms 背景色动画，这里再直接落一次色，
    # 确保首帧渲染即为主题底色，不闪黑。
    if hasattr(window, "setBackgroundColor"):
        window.setBackgroundColor(QColor(p.bg))
