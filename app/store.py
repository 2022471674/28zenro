# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

APP_NAME = "cipherNest"

#: 全量默认配置。新键一律先登记在这里，保证旧配置文件缺键时可回退。
DEFAULTS: dict = {
    # 外观：light / dark
    "theme_mode": "light",
    # 用户自定义主题覆盖：颜色按明 / 暗分别存储（两套独立配色），
    # 键为 theme.COLOR_TOKENS / FONT_TOKENS 中的令牌名，缺失键回退预设值
    "custom_colors": {"light": {}, "dark": {}},
    "custom_fonts": {},
    # 主窗口是否可调整大小
    "window_resizable": True,
    # 主窗口尺寸（像素）
    "window_width": 1200,
    "window_height": 800,
    # 快捷访问：自定义链接分组 / 未分组链接 / 图标缓存目录（空 = 默认位置）
    "quick_access": {
        "groups": [],
        "links": [],
        "icon_dir": "",
    },
    # 大模型服务（OpenAI 兼容格式：/models、/chat/completions、/embeddings）
    # 兼容 Ollama（/v1）、vLLM、One-API、New-API、各类中转站等
    "llm": {
        "base_url": "http://localhost:11434/v1",
        "api_key": "",
        "timeout": 120,
        # 自定义请求头：每行一个 "Key: Value"，可覆盖默认头（如网关鉴权）
        "headers": "",
        # 对话模型（翻译用）
        "model": "",
        # 嵌入模型
        "embedding_model": "",
        # OCR 模型
        "ocr_model": "",
        # 工具多模态模型（看图 / 识图类任务）
        "multimodal_model": "",
        "system_prompt_zh": "",
        "system_prompt_en": "",
    },
    # 键盘模拟默认参数
    "key_sim": {
        "rate": 20,
        "duration": 10,
        "delay": 3,
        "protected_processes": (
            "YuanShen.exe, GenshinImpact.exe, StarRail.exe, "
            "ZenlessZoneZero.exe, BH3.exe, Client-Win64-Shipping.exe"
        ),
    },
    # MD5 爆破默认参数
    "md5_crash": {
        "min_len": 8,
        "max_len": 18,
        "worker_num": 8,
        "thread_num": 8,
        "mode": "mixed",
    },
    # 图片工具：输出目录（相对路径基于应用根目录，也可填绝对路径）
    "watermark": {
        "output_dir": "output",
    },
    # 番茄时钟默认参数（分钟；long_every = 每 N 个专注后长休息）
    "pomodoro": {
        "work_minutes": 25,
        "short_rest_minutes": 5,
        "long_rest_minutes": 15,
        "long_every": 4,
        "auto_next": True,
        "notify": True,
    },
    # 压缩包工具默认参数（输出目录 / 爆破选项）
    "zip_crack": {
        "output_dir": "output",
        "use_builtin_dict": True,
        "max_numeric_len": 6,
        "alphabet": "lower",
    },
    # 局域网传输：服务名 / 监听端口（0 = 自动，开启后回写实际端口）/ 系统通知
    "lan_share": {
        "service_name": "cipherNest 共享",
        "port": 0,
        "notify": True,
    },
    # 源码泄露：输出目录 / 并发线程 / 请求超时
    "leak_scan": {
        "output_dir": "output/leak",
        "threads": 8,
        "timeout": 8,
        "dict_dir": "",
        "dir_threads": 16,
        "dir_timeout": 6,
        "dir_interval": 30,
        "dir_headers": "",
    },
    "cipher_fuzz": {
        "only_readable": True,
    },
    # 端口爆破：端口来源 / 代理方式 / 并发与超时
    "port_scan": {
        "port_source": "builtin",
        "dict_name": "常见端口.txt",
        "dict_file": "",
        "ports_text": "",
        "proxy_mode": "global",
        "proxy_file": "",
        "threads": 24,
        "timeout": 6,
        "retries": 3,
        "out_dir": "output/portscan",
    },
    # MySQL 爆破：目标 / 字典来源 / 并发与上限
    "mysql_brute": {
        "port": 3306,
        "user_source": "builtin",
        "pwd_source": "builtin",
        "user_dict": "常见用户名.dict",
        "pwd_dict": "常用密码.dict",
        "user_manual": "root",
        "pwd_manual": "",
        "threads": 8,
        "timeout": 6,
        "limit": 0,
        "out_dir": "output/mysql",
    },
    # 多地 Ping：服务地址 / 用户 ID / 通讯密钥 / dy 参数 / 自定义 Header
    # （默认接口盒子 apihz.cn 免费 API，公共示例 ID / KEY 共享频次）
    "ping_probe": {
        "base_url": "https://cn.apihz.cn/api/wangzhan/pingplus.php",
        "api_id": "10022374",
        "api_key": "qwertyuiopasdfghjkzxcvbn",
        "dy": "0",
        "headers": "",
    },
    # 微信公众号凭证校验：请求超时（秒）
    "wechat_check": {
        "timeout": 15,
    },
    # SSTI 子类枚举：请求超时（秒）
    "ssti_finder": {
        "timeout": 15,
    },
    # Web Fuzz：请求超时 / 是否顺带抓 robots.txt 与 sitemap.xml /
    # 历史收录查询 / 字典子域名爆破（间隔 + 是否走代理）
    "web_fuzz": {
        "timeout": 8,
        # 各收集步骤「接入 Fuzz」开关：默认全部 false（关闭），
        # 需在设置里手动开启对应步骤才会被 Web Fuzz 收集。
        "robots": False,
        "sitemap": False,
        "hostsearch": False,
        "subdomain_brute": False,
        "subdomain_interval": 0.3,
        "subdomain_use_proxy": False,
    },
    # DNS 解析：是否走代理（SOCKS5 远程 DNS）
    "dns_tool": {
        "use_proxy": False,
    },
    # 字典子域名爆破：速率限制间隔 / 是否走代理 / 自定义字典路径
    "subdomain_brute": {
        "interval": 0.3,
        "use_proxy": False,
        "dict_path": "",
    },
    # 参数爆破：请求方法 / 字典 / 超时 / 线程 / 每组参数 / 限速
    "param_fuzz": {
        "method": "GET",
        "wordlist": "small",
        "timeout": 15,
        "threads": 5,
        "chunks": 250,
        "rate_limit": 0,
    },
    # 全局代理池：是否启用 / 优先协议 / 启用源 / 手动代理 / 验证参数
    # cache 存「上次验证通过的可用代理」（协议://host:port），启动时恢复，
    # 直到这些代理失效才重新拉取免费源
    "proxy_pool": {
        "enabled": False,
        "protocol": "http",
        "sources": ["TheSpeedX-http", "proxifly-http", "TheSpeedX-socks5",
                    "openproxylist-socks5", "monosans-socks4"],
        "manual": "",
        "timeout": 6.0,
        "threads": 64,
        "max_proxies": 200,
        "cache": [],
    },
    # 一键 Fuzz 可配置性：
    # crypto_disabled：密码学一键 Fuzz 中被排除（不参与）的工具 id 列表。
    # （web Fuzz 的步骤开关复用「web_fuzz」节里的 robots / sitemap /
    #   hostsearch / subdomain_brute，不在此重复。）
    "fuzz_config": {
        "crypto_disabled": [],
    },
    # Payload 编译器：各语言解释器 / 编译器路径（留空自动探测 PATH）。
    # java 用 javac 编译 + java 运行；php / python 编译运行共用同一解释器。
    "payload_compiler": {
        "java_compiler": "",
        "java_runner": "",
        "php_path": "",
        "python_path": "",
    },
    # MCP 服务（HTTP streamable-http 模式）：由 GUI 内的状态管理页拉起/停止。
    "mcp_server": {
        "host": "127.0.0.1",
        "port": 8000,
        # 按组禁用的 MCP 工具组名（cn_help 恒注册，写了也会被忽略）；
        # 服务端 build_app 注册时过滤，工具注册页可编辑。
        "disabled_groups": [],
    },
    # 目录扫描（独立页）：字典目录 / 并发 / 限速 / 自定义请求头。
    "dir_scan": {
        "dict_dir": "",            # 空 = 内置 dict/Contents
        "output_dir": "output/dir_scan",
        "threads": 16,
        "timeout": 6,
        "interval": 30,            # 相邻请求最小间隔（秒），防 WAF
        "headers": "",             # 页内编辑框的完整请求头文本
    },
}


def _config_dir() -> Path:
    """用户数据目录：Windows 用 %APPDATA%，其余平台用 ~/.config。"""
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(base) / APP_NAME
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / APP_NAME


def _deep_merge(base: dict, override: dict) -> dict:
    """递归合并：override 覆盖 base，嵌套字典逐键合并，返回新 dict。"""
    merged = dict(base)
    for key, value in override.items():
        current = merged.get(key)
        if isinstance(current, dict) and isinstance(value, dict):
            merged[key] = _deep_merge(current, value)
        else:
            merged[key] = value
    return merged


class SettingsStore:
    """config.json 的读写封装。"""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or (_config_dir() / "config.json")
        self._data: dict = {}
        self.load()

    # -- 读 ---------------------------------------------------------------
    def load(self) -> None:
        """从磁盘加载并与默认值深合并；文件缺失 / 损坏时按默认值起步。"""
        loaded: dict = {}
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            if not isinstance(loaded, dict):
                loaded = {}
        except (OSError, json.JSONDecodeError):
            loaded = {}
        self._migrate_legacy(loaded)
        self._data = _deep_merge(DEFAULTS, loaded)

    @staticmethod
    def _migrate_legacy(loaded: dict) -> None:
        """就地迁移旧版配置：``ollama`` 节 -> ``llm`` 节（OpenAI 兼容格式）。

        旧版把 Ollama 地址存成 ``http://localhost:11434``（走 /api/chat），
        迁移时补上 ``/v1``（OpenAI 兼容端点前缀），并把对话模型挪到 ``model``。
        已有 ``llm`` 节则跳过，不覆盖新配置。
        """
        legacy = loaded.get("ollama")
        if not isinstance(legacy, dict) or isinstance(loaded.get("llm"), dict):
            return
        migrated: dict = {}
        base_url = str(legacy.get("base_url", "")).strip().rstrip("/")
        if base_url and not base_url.endswith("/v1"):
            base_url += "/v1"
        migrated["base_url"] = base_url
        migrated["model"] = str(legacy.get("model", "")).strip()
        migrated["api_key"] = str(legacy.get("api_key", "")).strip()
        migrated["timeout"] = legacy.get("timeout", 120)
        migrated["system_prompt_zh"] = legacy.get("system_prompt_zh", "")
        migrated["system_prompt_en"] = legacy.get("system_prompt_en", "")
        loaded["llm"] = migrated

    def get(self, *keys, default=None):
        """按路径取值：``get("llm", "model")``。任一层缺失返回 default。"""
        node = self._data
        for key in keys:
            if not isinstance(node, dict) or key not in node:
                return default
            node = node[key]
        return node

    # -- 写 ---------------------------------------------------------------
    def set(self, value, *keys) -> None:
        """按路径写值：``set("llm", "model", value=...)`` 前先 setv。"""
        self.setv(value, *keys)

    def setv(self, value, *keys) -> None:
        if not keys:
            raise ValueError("至少需要一个键名")
        node = self._data
        for key in keys[:-1]:
            child = node.get(key)
            if not isinstance(child, dict):
                child = {}
                node[key] = child
            node = child
        node[keys[-1]] = value

    def save(self) -> None:
        """原子落盘：先写同目录临时文件，再 os.replace 替换。"""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(
            dir=str(self.path.parent), prefix=".config-", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self._data, fh, ensure_ascii=False, indent=2)
            os.replace(tmp, self.path)
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    # -- 重置 ---------------------------------------------------------------
    def reset(self) -> None:
        """丢弃全部用户改动，恢复内置默认值并落盘。"""
        self._data = _deep_merge(DEFAULTS, {})
        self.save()
