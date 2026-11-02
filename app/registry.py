# -*- coding: utf-8 -*-
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

# lib.text_dedup 在模块级被下面的 DEDUP_* 常量引用（lib 不反向依赖 app，无循环）。
from lib import text_dedup
from lib import gensh_wallpapper
from lib.basex_fuzz import fuzz_basex

# ---------------------------------------------------------------------------
# 分类常量
# ---------------------------------------------------------------------------
CATEGORY_CRYPTO = "crypto"        # Base / ROT 加解密
CATEGORY_FUZZ = "fuzz"            # 密码 Fuzz（把密文丢给所有能解密的工具试一遍）
CATEGORY_HASH = "hash"            # 哈希
CATEGORY_GM = "gm"                # 国密（SM2 / SM3 / SM4）
CATEGORY_NUMBER = "number"        # 进制互转
CATEGORY_STRING = "string"        # 字符串编码工具
CATEGORY_CHAR = "char"            # 字符加解密（凯撒 / 猪圈）
CATEGORY_TRANSLATE = "translate"  # 翻译
CATEGORY_WEB = "web"              # Web 信息收集
CATEGORY_EFFICIENCY = "efficiency"  # 效率工具（番茄时钟）
CATEGORY_TRANSFER = "transfer"    # 局域网传输（HTTP 共享 / 加入频道）
CATEGORY_TOOLS = "tools"          # 独立工具（键盘模拟 / 图片 / 压缩包）
CATEGORY_JWT = "jwt"              # JWT（解析 / 校验 / 创建）
CATEGORY_PAYLOAD = "payload"      # Payload 管理器（Java / PHP / Python）
CATEGORY_MCP = "mcp"              # MCP 服务状态管理
CATEGORY_FUN = "fun"              # 娱乐
CATEGORY_QUICK = "quick_access"   # 快捷访问（自定义链接 / 分组）

# ---------------------------------------------------------------------------
# 侧边栏入口（hub）：侧边栏只渲染这几个，入口内部用 chips 切换工具
# ---------------------------------------------------------------------------
HUB_CRYPTO = "crypto"
HUB_WEB = "web"
HUB_MISC = "misc"
HUB_PAYLOAD = "payload"
HUB_MCP = "mcp"
HUB_ENTER = "enter"
#: 快捷访问是侧边栏的独立入口（不在 HUBS 手风琴里，由主窗单独挂载）
HUB_QUICK = "quick"

#: 入口展示顺序与显示名（侧边栏顺序）
HUBS: tuple[tuple[str, str], ...] = (
    (HUB_CRYPTO, "密码学"),
    (HUB_WEB, "Web 安全"),
    (HUB_MISC, "Misc"),
    (HUB_PAYLOAD, "Payload"),
    (HUB_MCP, "MCP"),
    (HUB_ENTER, "娱乐")
)

#: 分类 → 默认入口。个别工具可在 ToolSpec.hub 里覆盖。
HUB_OF_CATEGORY: dict[str, str] = {
    CATEGORY_FUZZ: HUB_CRYPTO,
    CATEGORY_CRYPTO: HUB_CRYPTO,
    CATEGORY_STRING: HUB_CRYPTO,
    CATEGORY_CHAR: HUB_CRYPTO,
    CATEGORY_JWT: HUB_CRYPTO,
    CATEGORY_NUMBER: HUB_CRYPTO,
    CATEGORY_HASH: HUB_CRYPTO,
    CATEGORY_GM: HUB_CRYPTO,
    CATEGORY_WEB: HUB_WEB,
    CATEGORY_TRANSLATE: HUB_MISC,
    CATEGORY_TOOLS: HUB_MISC,
    CATEGORY_EFFICIENCY: HUB_MISC,
    CATEGORY_TRANSFER: HUB_MISC,
    CATEGORY_PAYLOAD: HUB_PAYLOAD,
    CATEGORY_MCP: HUB_MCP,
    CATEGORY_FUN: HUB_ENTER,
    CATEGORY_QUICK: HUB_QUICK,
}

#: 分类展示顺序与显示名（首页网格区块用）
CATEGORIES: tuple[tuple[str, str], ...] = (
    (CATEGORY_QUICK, "快捷访问"),
    (CATEGORY_FUZZ, "Fuzz"),
    (CATEGORY_CRYPTO, "编解码"),
    (CATEGORY_HASH, "哈希"),
    (CATEGORY_GM, "国密"),
    (CATEGORY_NUMBER, "进制互转"),
    (CATEGORY_STRING, "字符串工具"),
    (CATEGORY_CHAR, "字符加解密"),
    (CATEGORY_JWT, "JWT"),
    (CATEGORY_TRANSLATE, "翻译"),
    (CATEGORY_WEB, "Web信息收集"),
    (CATEGORY_EFFICIENCY, "效率工具"),
    (CATEGORY_TRANSFER, "局域网传输"),
    (CATEGORY_TOOLS, "工具箱"),
    (CATEGORY_PAYLOAD, "Payload"),
    (CATEGORY_FUN, "娱乐"),
    (CATEGORY_MCP, "MCP 服务"),
)

KIND_ONE_WAY = "one-way"
KIND_TWO_WAY = "two-way"
KIND_DIFF = "diff"
KIND_PAGE = "page"
KIND_EMBEDDED = "embedded"


# ---------------------------------------------------------------------------
# 字符串工具的共享配置（选项与文案集中在这里，lib 只做纯逻辑）
# ---------------------------------------------------------------------------

#: 文本去重的粒度选项（顺序即下拉展示顺序）
DEDUP_UNIT_CHOICES: tuple[tuple[str, str], ...] = (
    (text_dedup.UNIT_LINE, "行"),
    (text_dedup.UNIT_WORD, "词"),
    (text_dedup.UNIT_CHAR, "字符"),
)

#: 文本去重的排序方式选项
DEDUP_ORDER_CHOICES: tuple[tuple[str, str], ...] = (
    (text_dedup.ORDER_KEEP, "保持原序"),
    (text_dedup.ORDER_ASC, "升序"),
    (text_dedup.ORDER_DESC, "降序"),
)

#: 去重统计报告的标签（文案在此维护，``lib.text_dedup`` 只负责排版与统计）
DEDUP_STAT_LABELS: dict[str, str] = {
    "total": "原始单元数",
    "unique": "去重后单元数",
    "extra": "重复出现次数",
    "kinds": "重复单元种类",
    "rate": "重复率",
    "detail": "重复单元明细（按出现次数降序）",
    "none": "（无重复单元）",
    "empty": "（空行）",
    "times": "次",
    "cap": "...（重复单元共 {count} 种，仅列出前 {shown} 种）",
}


#: 参数类型常量（ParamSpec.ptype 取值，决定界面渲染哪种控件）
PTYPE_INT = "int"        # 整数数字框
PTYPE_FLOAT = "float"    # 小数数字框
PTYPE_STR = "str"        # 单行文本
PTYPE_BOOL = "bool"      # 复选框
PTYPE_SELECT = "select"  # 下拉框（需配 choices）
PTYPE_FILE = "file"      # 文件选择（只读行 + 浏览按钮）
PTYPE_TEXT = "text"      # 多行文本


@dataclass(frozen=True)
class ParamSpec:
    """工具执行前需要收集的额外参数声明（UI 同源 schema）。

    字段
    ----
    key       参数键名（执行时以关键字传给 lib 函数）
    label     界面标签（缺省用 key）
    ptype     控件类型：:data:`PTYPE_INT` / :data:`PTYPE_FLOAT` /
              :data:`PTYPE_STR` / :data:`PTYPE_BOOL` / :data:`PTYPE_SELECT` /
              :data:`PTYPE_FILE` / :data:`PTYPE_TEXT`。缺省时按 default /
              choices 自动推断（兼容旧写法）。
    default   默认值
    minimum / maximum  数值范围（int / float 用）
    choices   下拉选项，两种写法都接受：
              ``((值, 显示名), ...)``（旧）或 ``["a", "b"]``（新，值与显示名同）
    required  是否必填（str / file / text 用，暂仅提示语义）
    hint      输入框占位提示（placeholder）
    order     排序权重（升序，缺省 0；UI 按此排序渲染）

    界面控件按 ptype（或自动推断）渲染，见 ``ToolPanel._build_params``。
    新工具优先显式声明 ``ptype``，旧工具省略 ptype 也照常工作。
    """

    key: str
    label: str = ""
    default: Any = None
    ptype: str = ""
    minimum: float | None = None
    maximum: float | None = None
    choices: tuple | list | None = None
    required: bool = False
    hint: str = ""
    order: int = 0

    @property
    def effective_label(self) -> str:
        """标签：显式 label 优先，否则退回 key。"""
        return self.label or self.key

    @property
    def effective_ptype(self) -> str:
        """实际控件类型：显式 ptype 优先，否则按 default / choices 推断。"""
        if self.ptype:
            return self.ptype
        if self.choices:
            return PTYPE_SELECT
        if isinstance(self.default, bool):
            return PTYPE_BOOL
        if isinstance(self.default, float):
            return PTYPE_FLOAT
        if isinstance(self.default, int):
            return PTYPE_INT
        return PTYPE_STR

    @property
    def choice_pairs(self) -> tuple[tuple[Any, str], ...]:
        """把 choices 统一成 ``((值, 显示名), ...)`` 形式。"""
        if not self.choices:
            return ()
        pairs: list[tuple[Any, str]] = []
        for item in self.choices:
            if isinstance(item, (tuple, list)) and len(item) == 2:
                pairs.append((item[0], str(item[1])))
            else:
                pairs.append((item, str(item)))
        return tuple(pairs)


@dataclass(frozen=True)
class ToolSpec:
    id: str
    name: str
    category: str
    kind: str = KIND_TWO_WAY
    enc: Callable | None = None
    dec: Callable | None = None
    failure: str | None = None
    params: tuple[ParamSpec, ...] = field(default_factory=tuple)
    description: str = ""
    hub: str = ""
    #: 自定义「密码 Fuzz」调用：``fn(ctx: FuzzContext) -> [(标签, 结果), …]``。
    #: 需要 key / 多算法 / 多步的工具用它声明；单向解码器可用
    #: :func:`lib.cipher_fuzz.fuzz_decoder` 包装。
    fuzz: Callable | None = None
    #: 是否参与「密码 Fuzz」。双向工具（有 ``dec``）默认参与，
    #: 置 False 可显式排除（哈希 / 文本统计这类本来就没有 ``dec``，不用管）。
    fuzzable: bool = True
    #: 页面工具（KIND_PAGE / KIND_EMBEDDED）的页面类引用。两种写法：
    #: - 字符串 ``"app.pages.xxx:ClassName"``（模块:类），懒加载，规避循环导入；
    #: - 类对象（可调用），直接实例化。
    #: 非页面工具留空。实例化时以 ``(theme, store, **page_kwargs)`` 调用。
    page: Any = ""
    #: 实例化页面类时的额外关键字参数（如 Md5CrashPage 的 hash_name）。
    page_kwargs: dict = field(default_factory=dict)
    #: 搜索关键词 / 别名（空格分隔），参与全局搜索匹配；向后兼容，默认空。
    keywords: str = ""

    @property
    def one_way(self) -> bool:
        return self.kind == KIND_TWO_WAY and self.dec is None

    @property
    def fuzz_participates(self) -> bool:
        """是否被「密码 Fuzz」收录。

        约定：显式声明了 ``fuzz`` 的一律参与；否则双向工具（有 ``dec``）
        在 ``fuzzable`` 为真时参与。单向工具默认不参与，需要它参与就写
        ``fuzz=fuzz_decoder(...)``。
        """
        if self.fuzz is not None:
            return True
        return bool(self.fuzzable) and self.dec is not None

    @property
    def hub_key(self) -> str:
        """所属侧边栏入口：显式声明优先，否则按分类默认归属。"""
        return self.hub or HUB_OF_CATEGORY.get(self.category, HUB_MISC)

    @property
    def category_label(self) -> str:
        return category_label(self.category)


def _resolve_page_ref(ref) -> Any:
    """把 ``page`` 引用解析成可实例化的类。

    支持字符串 ``"module.path:ClassName"``（懒加载，规避 app.pages ↔ registry
    循环导入）与类对象两种形式；空值返回 None。
    """
    if ref is None or ref == "":
        return None
    if isinstance(ref, str):
        import importlib

        module_path, _, attr = ref.partition(":")
        if not attr:
            raise ValueError(f"page 引用格式应为 'module.path:ClassName'，收到 {ref!r}")
        module = importlib.import_module(module_path)
        return getattr(module, attr)
    return ref


def category_label(category: str) -> str:
    """取分类的显示名（未知分类原样返回）。"""
    for key, label in CATEGORIES:
        if key == category:
            return label
    return category


# ---------------------------------------------------------------------------
# 注册表构建：导入 lib 纯函数后集中登记
# ---------------------------------------------------------------------------
def _build_registry() -> tuple[ToolSpec, ...]:
    from lib import (
        char_codec,
        rot_codec,
        string_codec,
    )
    tools: list[ToolSpec] = []

    # -- 快捷访问（独立侧边栏入口：自定义分组 + 图标网格，点击开浏览器） ----
    tools.append(ToolSpec(
        id="quick_access", name="快捷访问", category=CATEGORY_QUICK,
        kind=KIND_PAGE, hub=HUB_QUICK,
        description="自定义链接分组，图标 + 标题网格，自动抓取网站图标，"
                    "点击用系统浏览器打开",
        page="app.pages.quick_access_page:QuickAccessPage",
    ))

    # -- 密码 Fuzz（独立页面：密文丢进去，所有能解密的工具各跑一遍） --------
    tools.append(ToolSpec(
        id="cipher_fuzz", name="密码 Fuzz", category=CATEGORY_FUZZ,
        kind=KIND_PAGE,
        description="密文 + key + 偏移量，一次跑完全部解密算法",
        page="app.pages.fuzz_page:CipherFuzzPage",
    ))

    # -- ROT 加解密（双向） --------------------------------------------------
    for tool_id, name, enc, dec in (
        ("rot13", "ROT13", rot_codec.rot13_encrypt, rot_codec.rot13_decrypt),
        ("rot47", "ROT47", rot_codec.rot47_encrypt, rot_codec.rot47_decrypt),
    ):
        tools.append(ToolSpec(
            id=tool_id, name=name, category=CATEGORY_CRYPTO,
            kind=KIND_TWO_WAY, enc=enc, dec=dec, failure=name,
        ))

    # -- baseX：全部 Base 系列编解码收拢到一个工具（标签页切换） -------------
    # 原 11 个独立 base 工具（base64/base32/...）已合并至此；「密码 Fuzz」通过
    # fuzz=fuzz_basex 显式声明参与（遍历全部 Base 解码器）。
    tools.append(ToolSpec(
        id="basex", name="baseX 工具", category=CATEGORY_CRYPTO,
        kind=KIND_PAGE,
        description="Base64 / URLSafe / Base32 / Base16 / Base58 / Base62 / "
                    "Base85 / Base91 / Base92 / UUencode / XXencode 一键编解码",
        page="app.pages.basex_page:BasexPage",
        fuzz=fuzz_basex,
    ))

    # -- 哈希工具：5 个单向摘要收拢到一个工具（标签页切换） ------------------
    # 原 5 个独立哈希工具（md5/sha1/sha256/sha512/sha3_256）已合并至此。
    tools.append(ToolSpec(
        id="hash_tool", name="哈希工具", category=CATEGORY_HASH,
        kind=KIND_PAGE,
        description="MD5 / SHA1 / SHA256 / SHA512 / SHA3-256 一键计算摘要",
        page="app.pages.hash_page:HashPage",
    ))

    # MD5 爆破：自带独立页面，但内嵌在「哈希」工具页里作为子工具，不占侧边栏
    tools.append(ToolSpec(
        id="md5_crash", name="MD5 爆破", category=CATEGORY_HASH,
        kind=KIND_EMBEDDED, description="排列枚举 / 字典爆破 32 位 MD5 明文",
        page="app.pages.md5_crash_page:Md5CrashPage",
        page_kwargs={"hash_name": "md5"},
    ))
    # SHA1 / SHA256 爆破：复用 md5_crash 的枚举 / 字典 / 多进程框架
    tools.append(ToolSpec(
        id="sha1_crash", name="SHA1 爆破", category=CATEGORY_HASH,
        kind=KIND_EMBEDDED, description="排列枚举 / 字典爆破 40 位 SHA1 明文",
        page="app.pages.md5_crash_page:Md5CrashPage",
        page_kwargs={"hash_name": "sha1"},
    ))
    tools.append(ToolSpec(
        id="sha256_crash", name="SHA256 爆破", category=CATEGORY_HASH,
        kind=KIND_EMBEDDED, description="排列枚举 / 字典爆破 64 位 SHA256 明文",
        page="app.pages.md5_crash_page:Md5CrashPage",
        page_kwargs={"hash_name": "sha256"},
    ))
    # 哈希长度扩展攻击：独立页面（md5/sha1/sha256 的 padding 克隆 + MAC 伪造）
    tools.append(ToolSpec(
        id="hash_ext", name="哈希长度扩展攻击", category=CATEGORY_HASH,
        kind=KIND_PAGE,
        description="md5/sha1/sha256(secret||data) MAC 伪造（长度扩展攻击，纯 Python）",
        page="app.pages.hash_ext_page:HashExtPage",
    ))

    # -- 国密（独立页面：SM3 摘要 / SM4 对称加解密 / SM2 公钥密码）----------
    tools.append(ToolSpec(
        id="gm", name="国密工具", category=CATEGORY_GM,
        kind=KIND_PAGE,
        description="SM3 摘要 / SM4 对称加解密 / SM2 公钥加解密与签名验签",
        page="app.pages.gm_page:GmPage",
    ))

    # -- RSA / 大整数攻击（独立页面：分解 / 恢复 / 常见攻击 / 基础运算）-----
    tools.append(ToolSpec(
        id="rsa_attack", name="RSA 攻击", category=CATEGORY_CRYPTO,
        kind=KIND_PAGE,
        description="大整数分解 / RSA 私钥恢复 / 常见攻击（共模、低指数、Wiener、广播）/ 基础运算",
        page="app.pages.rsa_page:RsaPage",
    ))

    # -- 进制互转（独立页面：from/to 下拉取代 12 个菜单项） ----------------
    tools.append(ToolSpec(
        id="number_base", name="进制互转", category=CATEGORY_NUMBER,
        kind=KIND_PAGE, description="2 / 8 / 10 / 16 进制两两互转",
        page="app.pages.number_page:NumberBasePage",
    ))

    # -- 字符串编码工具：同类收拢到独立页面（标签页切换） ------------------
    # 原独立工具（url_encode / url_decode / str_to_ascii / html_entity /
    # quoted_printable / unicode_escape / gbk_utf16 / brainfuck / jsfuck …）
    # 已按「同类型」收拢为 4 个页面工具，见下。解码方向经
    # lib.string_fuzz 显式声明参与「密码 Fuzz」，保证一键 Fuzz 不受影响。
    from lib import string_fuzz

    # URL 编码 / 全编码 / 解码 -> 一个「URL 编码工具」
    tools.append(ToolSpec(
        id="url_codec", name="URL 编码工具", category=CATEGORY_STRING,
        kind=KIND_PAGE,
        description="URL 编码 / URL 全编码（含英文）/ URL 解码，标签页切换",
        page="app.pages.url_codec_page:UrlCodecPage",
        fuzz=string_fuzz.fuzz_url,
    ))

    # 字符串转 ASCII / ASCII 转字符串 -> 一个「ASCII 转换工具」
    tools.append(ToolSpec(
        id="ascii_codec", name="ASCII 转换工具", category=CATEGORY_STRING,
        kind=KIND_PAGE,
        description="字符串转 ASCII（十进制码点）/ ASCII 转字符串（十进制 / 0x），标签页切换",
        page="app.pages.ascii_codec_page:AsciiCodecPage",
        fuzz=string_fuzz.fuzz_ascii,
    ))

    # HTML 实体 / Unicode 转义 / QP / GBK·UTF-16 -> 一个「实体编码工具」
    tools.append(ToolSpec(
        id="entity_codec", name="实体编码工具", category=CATEGORY_STRING,
        kind=KIND_PAGE,
        description="HTML 实体 / Unicode 转义 / Quoted-printable / GBK·UTF-16 互转，标签页切换",
        page="app.pages.entity_codec_page:EntityCodecPage",
        fuzz=string_fuzz.fuzz_entity,
    ))

    # Brainfuck / Ook / jother / JSFuck -> 一个「esolang 工具」
    tools.append(ToolSpec(
        id="esolang", name="esolang 工具", category=CATEGORY_STRING,
        kind=KIND_PAGE,
        description="Brainfuck / Ook! / jother 执行器 + JSFuck 编码 / 解码，标签页切换",
        page="app.pages.esolang_page:EsolangPage",
    ))

    # 大小写互转（双向文本变换，保留为独立条目）
    for tool_id, name, enc, dec in (
        ("to_lower", "大写转小写", string_codec.to_lower, None),
        ("to_upper", "小写转大写", string_codec.to_upper, None),
    ):
        tools.append(ToolSpec(
            id=tool_id, name=name, category=CATEGORY_STRING,
            kind=KIND_ONE_WAY, enc=enc, failure=name,
        ))

    # 文本字数统计（独立单向工具）
    from functools import partial
    count_labels = {
        "total": "总字符数", "no_space": "不含空白字符", "words": "单词数",
        "letters": "字母数", "digits": "数字个数", "cjk": "中文字符数",
        "lines": "行数",
    }
    tools.append(ToolSpec(
        id="text_count", name="文本字数统计", category=CATEGORY_STRING,
        kind=KIND_ONE_WAY, enc=partial(string_codec.text_count, labels=count_labels),
        failure="文本字数统计",
    ))

    # -- 文本对比器（diff 形态：工具页切换为左右对照的差异面板） ----------
    tools.append(ToolSpec(
        id="text_diff", name="文本对比器", category=CATEGORY_STRING,
        kind=KIND_DIFF,
        description="对比两段文本的差异并高亮，给出一致 / 不一致结论",
    ))

    # -- 文本去重 / 统计（单向，参数走下拉框与复选框） -------------------
    tools.append(ToolSpec(
        id="text_dedup", name="文本去重排序", category=CATEGORY_STRING,
        kind=KIND_ONE_WAY, enc=text_dedup.dedupe, failure="文本去重排序",
        description="按行 / 词 / 字符去重，可保持原序或升序、降序排列",
        params=(
            ParamSpec("unit", "粒度", text_dedup.UNIT_LINE,
                      choices=DEDUP_UNIT_CHOICES),
            ParamSpec("order", "排序", text_dedup.ORDER_KEEP,
                      choices=DEDUP_ORDER_CHOICES),
            ParamSpec("ignore_case", "忽略大小写", False),
        ),
    ))
    tools.append(ToolSpec(
        id="text_dedup_stats", name="去重统计", category=CATEGORY_STRING,
        kind=KIND_ONE_WAY,
        enc=partial(text_dedup.dedupe_stats, labels=DEDUP_STAT_LABELS),
        failure="去重统计",
        description="统计原始 / 去重后单元数、重复率，并列出重复单元明细",
        params=(
            ParamSpec("unit", "粒度", text_dedup.UNIT_LINE,
                      choices=DEDUP_UNIT_CHOICES),
            ParamSpec("ignore_case", "忽略大小写", False),
        ),
    ))

    # -- JSON 工具（独立页面：解析 / 格式化 + 行编辑构建器） -------------
    tools.append(ToolSpec(
        id="json_tool", name="JSON 工具", category=CATEGORY_STRING,
        kind=KIND_PAGE, hub=HUB_CRYPTO,
        description="解析 / 格式化 / 压缩 / 结构报告，键值行编辑构建 JSON",
        page="app.pages.json_page:JsonPage",
    ))

    # -- 字符加解密 --------------------------------------------------------
    tools.append(ToolSpec(
        id="caesar", name="凯撒密码", category=CATEGORY_CHAR,
        kind=KIND_TWO_WAY, enc=char_codec.caesar_encrypt, dec=char_codec.caesar_decrypt,
        failure="凯撒密码",
        params=(ParamSpec("shift", "位移量（0-25）", 3, 0, 25),),
    ))
    tools.append(ToolSpec(
        id="pigpen", name="猪圈密码", category=CATEGORY_CHAR,
        kind=KIND_TWO_WAY, enc=char_codec.pigpen_encrypt, dec=char_codec.pigpen_decrypt,
        failure="猪圈密码",
    ))

    # -- 翻译 / 独立工具（页面形态） ---------------------------------------
    tools.append(ToolSpec(
        id="translate", name="智能翻译", category=CATEGORY_TRANSLATE,
        kind=KIND_PAGE, description="中英自动互译（OpenAI 兼容模型）",
        page="app.pages.translate_page:TranslatePage",
    ))
    tools.append(ToolSpec(
        id="key_simulate", name="键盘输入模拟", category=CATEGORY_TOOLS,
        kind=KIND_PAGE, description="按速率与时长模拟物理键盘按键",
        page="app.pages.key_sim_page:KeySimPage",
    ))
    tools.append(ToolSpec(
        id="watermark", name="图片工具", category=CATEGORY_TOOLS,
        kind=KIND_PAGE, description="可见水印 / LSB 隐写 / 图片转 Base64 / OCR 文字识别",
        page="app.pages.watermark_page:WatermarkPage",
    ))
    tools.append(ToolSpec(
        id="zip_crack", name="压缩包工具", category=CATEGORY_TOOLS,
        kind=KIND_PAGE, description="ZIP 伪加密识别修复 / CRC32 碰撞 / 字典密码爆破",
        page="app.pages.zip_page:ZipCrackPage",
    ))
    tools.append(ToolSpec(
        id="file_hex", name="文件 Hex 互转", category=CATEGORY_TOOLS,
        kind=KIND_PAGE,
        description="文件 ↔ 十六进制互转，自定义分隔符 / 前缀，hex 编辑器风格三栏视图",
        page="app.pages.file_hex_page:FileHexPage",
    ))
    tools.append(ToolSpec(
        id="time_codec", name="时间戳转换", category=CATEGORY_TOOLS,
        kind=KIND_PAGE,
        description="时间戳 ↔ 日期时间互转，秒/毫秒/微秒/纳秒自动识别，本地/UTC 双时区",
        page="app.pages.time_codec_page:TimeCodecPage",
    ))
    tools.append(ToolSpec(
        id="file_hash", name="文件哈希分析", category=CATEGORY_TOOLS,
        kind=KIND_PAGE,
        description="文件 MD5/SHA1/SHA256/SHA512/SHA3-256/CRC32 一键计算，大文件流式读取",
        page="app.pages.file_hash_page:FileHashPage",
    ))
    # 思维导图（Mermaid 渲染 + SVG / PNG 导出）
    tools.append(ToolSpec(
        id="mindmap", name="思维导图", category=CATEGORY_TOOLS,
        kind=KIND_PAGE,
        description="输入 Mermaid 语法实时渲染思维导图，支持导出 SVG / PNG",
        page="app.pages.mindmap_page:MindMapPage",
        keywords="mermaid 思维导图 mindmap 流程图 导出 svg png",
    ))
    # Markdown 编辑（渲染 + HTML / PDF / Word 导出）
    tools.append(ToolSpec(
        id="markdown", name="Markdown 编辑", category=CATEGORY_TOOLS,
        kind=KIND_PAGE,
        description="编辑 Markdown 源码实时渲染，支持导出 HTML / PDF / Word",
        page="app.pages.markdown_page:MarkdownPage",
        keywords="markdown 编辑 预览 导出 html pdf word doc",
    ))
    tools.append(ToolSpec(
        id="jwt_tool", name="JWT 工具", category=CATEGORY_JWT,
        kind=KIND_PAGE,
        description="解析 / 校验 / 创建 / 修改重签，自定义密钥与 iss 等声明",
        page="app.pages.jwt_page:JwtPage",
    ))
    tools.append(ToolSpec(
        id="jsfinder", name="JSFinder", category=CATEGORY_WEB,
        kind=KIND_PAGE, description="从页面与其 JS 中提取 URL 与子域名",
        page="app.pages.jsfinder_page:JsFinderPage",
    ))
    tools.append(ToolSpec(
        id="web_fuzz", name="Web Fuzz", category=CATEGORY_WEB,
        kind=KIND_PAGE,
        description="URL 一次抓全页面 / 主机信息（响应头、技术栈、链接、邮箱、子域…）合并导出 txt",
        page="app.pages.web_fuzz_page:WebFuzzPage",
    ))
    tools.append(ToolSpec(
        id="fingerprint", name="指纹探测", category=CATEGORY_WEB,
        kind=KIND_PAGE,
        description="observer_ward 风格指纹识别：关键词 / 正则 / favicon（mmh3+md5）匹配，识别组件 / 厂商 / 版本",
        page="app.pages.fingerprint_page:FingerprintPage",
    ))
    tools.append(ToolSpec(
        id="dns_tool", name="DNS 解析", category=CATEGORY_WEB,
        kind=KIND_PAGE,
        description="解析域名的 A / AAAA / CNAME 记录（Resolve-DnsName 与 nslookup 交叉校准）",
        page="app.pages.dns_page:DnsPage",
    ))
    tools.append(ToolSpec(
        id="hostsearch", name="域名解析历史", category=CATEGORY_WEB,
        kind=KIND_PAGE,
        description="hackertarget 历史收录查询：域名历史被收录过的子域名与对应 IP（被动收集）",
        page="app.pages.hostsearch_page:HostsearchPage",
    ))
    tools.append(ToolSpec(
        id="subdomain_brute", name="字典子域名爆破", category=CATEGORY_WEB,
        kind=KIND_PAGE,
        description="字典逐个拼主域名做 DNS A 查询，发现子域名与 IP（速率限制 + 代理开关）",
        page="app.pages.subdomain_brute_page:SubdomainBrutePage",
    ))
    tools.append(ToolSpec(
        id="param_fuzz", name="参数爆破", category=CATEGORY_WEB,
        kind=KIND_PAGE,
        description="自动发现 URL 接受的 HTTP 参数名（GET/POST/JSON/XML，整合 Arjun 引擎）",
        page="app.pages.param_fuzz_page:ParamFuzzPage",
    ))
    # HTTP 请求器（类 Burp Repeater/Intruder，不抓包：自己构造并发送请求）
    tools.append(ToolSpec(
        id="http_requester", name="HTTP 请求器", category=CATEGORY_WEB,
        kind=KIND_PAGE,
        description="参数 / 请求头 / 请求体自定义，{{payload}} 标记 + 常量 / 循环"
                    "（Sniper 等 4 种攻击类型），密码学接口批量加密载荷",
        page="app.pages.http_requester_page:HttpRequesterPage",
    ))
    tools.append(ToolSpec(
        id="httpscan", name="主机探针", category=CATEGORY_WEB,
        kind=KIND_PAGE, description="CIDR 网段 Web 主机发现（状态码 / 容器 / 标题）",
        page="app.pages.httpscan_page:HttpScanPage",
    ))
    tools.append(ToolSpec(
        id="leak_scan", name="源码泄露", category=CATEGORY_WEB,
        kind=KIND_PAGE,
        description="域名自动检测 /.git/、/.svn/、/.DS_Store 与敏感文件清单"
                    "（vim .swp / .bak / .env 等），并可还原源码；未命中可转目录扫描",
        page="app.pages.leak_page:LeakScanPage",
    ))
    tools.append(ToolSpec(
        id="dir_scan", name="目录扫描", category=CATEGORY_WEB,
        kind=KIND_PAGE,
        description="字典目录逐条探测隐藏路径：软 404 过滤、限速防 WAF、"
                    "请求头可用 dict/Contents/http_headers.json 自定义",
        page="app.pages.dir_scan_page:DirScanPage",
    ))
    tools.append(ToolSpec(
        id="port_scan", name="端口爆破", category=CATEGORY_WEB,
        kind=KIND_PAGE,
        description="走代理池扫端口，封禁即换代理；内置端口字典",
        page="app.pages.port_page:PortPage",
    ))
    tools.append(ToolSpec(
        id="mysql_brute", name="MySQL 弱口令审计", category=CATEGORY_WEB,
        kind=KIND_PAGE,
        description="内网弱口令爆破 + 公网/域名纯被动指纹识别（合规授权）",
        page="app.pages.mysql_page:MysqlPage",
    ))
    tools.append(ToolSpec(
        id="ping_probe", name="多地 Ping", category=CATEGORY_WEB,
        kind=KIND_PAGE,
        description="多节点 ICMP Ping 延迟检测（接口盒子免费 API，可自定义 ID / KEY / Header）",
        page="app.pages.ping_page:PingPage",
    ))
    tools.append(ToolSpec(
        id="wechat_check", name="微信凭证校验", category=CATEGORY_WEB,
        kind=KIND_PAGE,
        description="校验公众号 AppID / AppSecret 是否有效（单组 / 批量）",
        page="app.pages.wechat_page:WechatPage",
    ))
    tools.append(ToolSpec(
        id="ssti_finder", name="SSTI 子类枚举", category=CATEGORY_WEB,
        kind=KIND_PAGE,
        description="枚举 object 子类并检测 os/eval RCE 可达性，给出利用 payload",
        page="app.pages.ssti_page:SstiPage",
    ))
    tools.append(ToolSpec(
        id="sql_inject", name="SQL 注入 Payload", category=CATEGORY_WEB,
        kind=KIND_PAGE,
        description="参考 sqlmap 生成逻辑：布尔/报错/时间盲注、UNION、堆叠 "
                    "payload，多 DBMS 闭合边界 × tamper 绕过链",
        page="app.pages.sql_inject_page:SqlInjectPage",
    ))
    tools.append(ToolSpec(
        id="attack_surface", name="攻击面测绘", category=CATEGORY_WEB,
        kind=KIND_PAGE,
        description="一键全链路编排：子域名→端口→指纹→WAF→目录→源码泄露→"
                    "参数→OSS 桶，逐步汇总成报告",
        page="app.pages.attack_surface_page:AttackSurfacePage",
    ))
    tools.append(ToolSpec(
        id="vuln_scan", name="漏洞扫描编排器", category=CATEGORY_WEB,
        kind=KIND_PAGE,
        description="内置检测器（安全响应头等）+ Nuclei 模板兼容层统一编排，"
                    "直接跑 Nuclei YAML 模板（内置精选 + 可下载官方库），"
                    "输出统一 JSON / txt / Markdown 报告",
        page="app.pages.vuln_scan_page:VulnScanPage",
    ))
    tools.append(ToolSpec(
        id="waf_detect", name="WAF 识别", category=CATEGORY_WEB,
        kind=KIND_PAGE,
        description="识别 Cloudflare / 宝塔 / 安全狗 / ModSecurity 等 WAF，"
                    "并给出绕过建议",
        page="app.pages.waf_page:WafPage",
    ))
    tools.append(ToolSpec(
        id="oss_bucket", name="OSS 桶探测", category=CATEGORY_WEB,
        kind=KIND_PAGE,
        description="检测阿里云 OSS / 腾讯 COS / AWS S3 桶的公开读与可列举越权",
        page="app.pages.oss_page:OssPage",
    ))
    tools.append(ToolSpec(
        id="weak_cred", name="弱口令检测", category=CATEGORY_WEB,
        kind=KIND_PAGE,
        description="Redis / FTP 弱口令爆破 + SSH banner 指纹（内网爆破、"
                    "公网仅指纹，合规授权）",
        page="app.pages.weak_cred_page:WeakCredPage",
    ))
    tools.append(ToolSpec(
        id="pomodoro", name="番茄时钟", category=CATEGORY_EFFICIENCY,
        kind=KIND_PAGE, description="专注 / 休息循环计时，阶段结束系统通知",
        page="app.pages.pomodoro_page:PomodoroPage",
    ))

    # -- 局域网传输（本机开 HTTP 服务 / 输 4 位密码加入他人频道） ----------
    tools.append(ToolSpec(
        id="lan_share", name="局域网传输", category=CATEGORY_TRANSFER,
        kind=KIND_PAGE,
        description="本机开 HTTP 共享，4 位密码进频道；也能加入他人的频道互传文件",
        page="app.pages.lan_share_page:LanSharePage",
    ))

    # -- Payload 管理器（Java / PHP / Python 编译与运行，SQLite 记录） -----
    tools.append(ToolSpec(
        id="payload_manager", name="Payload 管理器", category=CATEGORY_PAYLOAD,
        kind=KIND_PAGE,
        description="Java / PHP / Python payload 的存储、编译与运行，"
                    "自定义解释器位置，SQLite 记录历史",
        page="app.pages.payload_manager_page:PayloadManagerPage",
    ))

    # -- MCP 服务状态管理（HTTP streamable-http 长驻进程的启停与日志） ------
    tools.append(ToolSpec(
        id="mcp_server", name="MCP 服务", category=CATEGORY_MCP,
        kind=KIND_PAGE,
        description="管理 cipherNest MCP HTTP 服务：启动 / 停止 / 重启、"
                    "状态检测与实时日志",
        page="app.pages.mcp_server_page:McpServerPage",
    ))

    tools.append(ToolSpec(
        id="gens_wallpaper", name="原神壁纸", category=CATEGORY_FUN,
        kind=KIND_PAGE,
        description="随机获取一张原神壁纸，API 提供者 https://xxapi.cn/doc/ys",
        page="app.pages.gensh_wallpaper_page:GenshWallpaperPage",
    ))

    return tuple(tools)


# ---------------------------------------------------------------------------
# @tool 装饰器 + 自动发现 + 插件目录（增量机制，与集中式清单并存）
# ---------------------------------------------------------------------------
#: 装饰器 / 插件注册进来的工具（id -> ToolSpec），与 ``_build_registry`` 的内置
#: 清单合并成最终的 :data:`REGISTRY`。内置清单优先，重复 id 以内置为准。
_TOOL_REGISTRY: dict[str, ToolSpec] = {}


def register(spec_or_fn, **kwargs) -> ToolSpec:
    """注册一个工具到装饰器注册表，返回 :class:`ToolSpec`。

    两种用法：

    - ``register(spec)``：直接给一个已构造好的 :class:`ToolSpec`；
    - ``register(fn, **kwargs)``：给一个函数 + 元数据，内部构造 ToolSpec
      （供 :func:`tool` 装饰器内部调用，也便于第三方插件手动注册）。
    """
    if isinstance(spec_or_fn, ToolSpec):
        spec = spec_or_fn
    elif callable(spec_or_fn):
        spec = ToolSpec(
            id=kwargs.get("id") or spec_or_fn.__name__,
            name=kwargs.get("name") or spec_or_fn.__name__.replace("_", " "),
            category=kwargs.get("category", CATEGORY_TOOLS),
            kind=kwargs.get("kind", KIND_ONE_WAY),
            enc=spec_or_fn if kwargs.get("kind", KIND_ONE_WAY) in
                 (KIND_ONE_WAY, KIND_TWO_WAY) else None,
            dec=kwargs.get("dec"),
            failure=kwargs.get("failure") or spec_or_fn.__name__.replace("_", " "),
            params=tuple(kwargs.get("params") or ()),
            description=kwargs.get("description", ""),
            hub=kwargs.get("hub", ""),
            fuzz=kwargs.get("fuzz"),
            fuzzable=kwargs.get("fuzzable", True),
            page=kwargs.get("page", ""),
            page_kwargs=dict(kwargs.get("page_kwargs") or {}),
        )
    else:
        raise TypeError("register() 需要一个 ToolSpec 或可调用对象")

    _TOOL_REGISTRY[spec.id] = spec
    return spec


def tool(id=None, *, name=None, category=None, kind=KIND_ONE_WAY,
         dec=None, failure=None, params=(), description="", hub="",
         fuzz=None, fuzzable=True, page="", page_kwargs=None):
    """工具注册装饰器：把被装饰的 lib 函数注册为一个工具。

    用法示例（放在 ``app/tools/`` 或 ``plugins/`` 里的模块顶部）：:

        from app.registry import tool, CATEGORY_CRYPTO, ParamSpec

        @tool("rot_shift", name="ROT 位移", category=CATEGORY_CRYPTO,
              kind="two-way", dec=rot_dec, params=(ParamSpec("n", ptype="int"),))
        def rot_enc(data, n=13):
            ...

    装饰器只负责登记元数据，不改动函数本身（返回原函数），因此该函数仍可被
    当作普通 lib 函数直接调用。``kind`` 为 ``two-way`` 且给了 ``dec`` 时
    自动具备加密/解密两个按钮；否则按 ``one-way`` 只给一个执行按钮。
    """
    def deco(fn):
        register(
            fn,
            id=id,
            name=name,
            category=category,
            kind=kind,
            dec=dec,
            failure=failure,
            params=params,
            description=description,
            hub=hub,
            fuzz=fuzz,
            fuzzable=fuzzable,
            page=page,
            page_kwargs=page_kwargs,
        )
        return fn
    return deco


def _plugin_dirs() -> list[Path]:
    """返回需要扫描的插件 / 工具目录（项目内 plugins/ 与 app/tools/）。"""
    root = Path(__file__).resolve().parent.parent  # 项目根
    return [root / "app" / "tools", root / "plugins"]


def discover_tools(log=None) -> dict[str, ToolSpec]:
    """扫描 ``app/tools/`` 与 ``plugins/``，导入其中定义的工具模块。

    每个 ``.py`` 文件被 import 时，其内部的 :func:`tool` 装饰器会自动把工具
    登记进 :data:`_TOOL_REGISTRY`。已登记的工具不会重复导入。

    返回本次新登记的工具（id -> ToolSpec）；``log`` 可选，用于打印发现过程。
    """
    emit = log or (lambda _m: None)
    discovered: dict[str, ToolSpec] = {}
    before = set(_TOOL_REGISTRY)

    for directory in _plugin_dirs():
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("*.py")):
            if path.name.startswith("_"):
                continue
            module_name = path.stem
            try:
                _import_plugin_module(directory, module_name)
            except Exception as exc:  # noqa: BLE001  单个插件失败不影响其它
                emit(f"[插件] 加载失败 {path.name}：{exc}")

    for tool_id, spec in _TOOL_REGISTRY.items():
        if tool_id not in before:
            discovered[tool_id] = spec
    return discovered


def _import_plugin_module(directory: Path, module_name: str) -> None:
    """用 importlib 导入插件目录下的单个模块（支持重复扫描不报错）。"""
    import importlib.util
    import sys

    # 用目录名做命名空间前缀，避免 app/tools 与 plugins 下同名模块冲突
    namespace = f"_ctfcrypto_plugins.{directory.name}"
    full_name = f"{namespace}.{module_name}"
    if full_name in sys.modules:
        return
    path = directory / f"{module_name}.py"
    spec = importlib.util.spec_from_file_location(full_name, path)
    if spec is None or spec.loader is None:
        return
    module = importlib.util.module_from_spec(spec)
    sys.modules[full_name] = module
    spec.loader.exec_module(module)


def extra_tools() -> tuple[ToolSpec, ...]:
    """装饰器 / 插件注册进来的额外工具（按注册顺序）。"""
    return tuple(_TOOL_REGISTRY.values())


#: 全量注册表（模块导入时构建一次）：内置清单 + 装饰器/插件发现的额外工具
def _collect_all_tools() -> tuple[ToolSpec, ...]:
    builtin = _build_registry()
    discover_tools()
    builtin_ids = {t.id for t in builtin}
    extras = [spec for spec in _TOOL_REGISTRY.values() if spec.id not in builtin_ids]
    return builtin + tuple(extras)


REGISTRY: tuple[ToolSpec, ...] = _collect_all_tools()

#: id -> ToolSpec 索引
_BY_ID: dict[str, ToolSpec] = {tool.id: tool for tool in REGISTRY}


def get_tool(tool_id: str) -> ToolSpec | None:
    """按 id 取工具声明；不存在返回 None。

    优先查启动时固化的内置索引 ``_BY_ID``，兜底查装饰器注册表
    ``_TOOL_REGISTRY``（覆盖运行时动态 ``register`` 进来的插件）。
    """
    return _BY_ID.get(tool_id) or _TOOL_REGISTRY.get(tool_id)


def tools_of_category(category: str) -> tuple[ToolSpec, ...]:
    """取某分类下的全部工具，保持注册顺序。"""
    return tuple(tool for tool in REGISTRY if tool.category == category)


def tools_of_hub(hub: str) -> tuple[ToolSpec, ...]:
    """取某个侧边栏入口下的全部工具（含独立页面），保持注册顺序。

    顺序沿用注册表顺序：同一分类的工具天然连在一起，被 ``hub`` 覆盖归属的
    个别工具（JSON / JWT）落在其注册位置，因此 JWT 会排在密码学入口末尾。
    """
    return tuple(tool for tool in REGISTRY if tool.hub_key == hub)


def search_tools(query: str) -> tuple[ToolSpec, ...]:
    """全局搜索：按工具名 / 描述 / 分类名 / 关键词模糊匹配。

    匹配忽略大小写，空查询返回空。供首页搜索框与未来命令行式跳转复用。
    """
    query = (query or "").strip().lower()
    if not query:
        return ()
    hits: list[ToolSpec] = []
    for tool in REGISTRY:
        haystack = " ".join([
            tool.id.lower(),
            tool.name.lower(),
            tool.description.lower(),
            tool.category_label.lower(),
            tool.keywords.lower(),
        ])
        if query in haystack:
            hits.append(tool)
    return tuple(hits)


def fuzz_targets(exclude: set[str] | frozenset[str] | None = None) -> tuple[ToolSpec, ...]:
    """参与「密码 Fuzz」的工具，保持注册顺序。

    判定规则见 :attr:`ToolSpec.fuzz_participates`：新增的**双向**密码工具
    （声明了 ``dec``）会自动出现在这里，不需要手工维护清单 —— 这就是
    「后续加入的密码工具也必须遵循此约定」的落地点。

    ``exclude`` 为要排除的工具 id 集合（来自设置页「一键 Fuzz」的用户配置），
    被排除的工具不参与本轮 Fuzz。
    """
    excluded = exclude or frozenset()
    return tuple(
        tool for tool in REGISTRY
        if tool.fuzz_participates and tool.id not in excluded)


def fuzzable_tools() -> tuple[ToolSpec, ...]:
    """
    所有**可参与**密码 Fuzz 的工具（供设置页列出开关）。
    """
    return tuple(tool for tool in REGISTRY if tool.fuzz_participates)

