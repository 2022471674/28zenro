# -*- coding: utf-8 -*-
"""启动引导：路径注入 / 配置读取 / 代理池装载 / stderr 日志。

约定
----
- 本服务**只读**配置：使用 :class:`app.store.SettingsStore` 读取
  ``%APPDATA%/cipherNest/config.json``（与 GUI / CLI 共享），从不写回；
- 配置缺失或 ``app`` 包不可用时自动降级为内置默认值，工具仍可用；
- 一切日志写 stderr。stdio 传输下 stdout 专用于 MCP 协议帧，绝不能污染。
"""

from __future__ import annotations

import sys
import threading
from pathlib import Path
from typing import Any, Callable

# ---------------------------------------------------------------------------
# 路径：mcp/ 与项目根（lib / app 所在目录）
# ---------------------------------------------------------------------------
if getattr(sys, "frozen", False):
    # PyInstaller 6 onedir：datas 在 <exe>/_internal，但纯模块 __file__
    # 基于 exe 顶层 —— 插件目录 / 相对路径解析都要以数据根为准。
    from lib.runtime_paths import data_root

    PROJECT_ROOT = data_root()
    MCP_ROOT = PROJECT_ROOT / "mcp"    # 数据位置：_internal/mcp（代码本身在 PYZ 里）
else:
    MCP_ROOT = Path(__file__).resolve().parent.parent        # .../CTFcrypto/mcp
    PROJECT_ROOT = MCP_ROOT.parent                           # .../CTFcrypto


def ensure_paths() -> None:
    """把项目根与 mcp 目录加入 ``sys.path``，保证任意 CWD 下都能 import。"""
    for path in (str(PROJECT_ROOT), str(MCP_ROOT)):
        if path not in sys.path:
            sys.path.insert(0, path)


ensure_paths()


# ---------------------------------------------------------------------------
# 日志（stderr）
# ---------------------------------------------------------------------------
def log(message: str) -> None:
    """统一的进度日志出口：stderr + 前缀，绝不写 stdout。"""
    try:
        print(f"[ciphernest] {message}", file=sys.stderr, flush=True)
    except Exception:  # pragma: no cover - 极端情况下日志失败不影响工具
        pass


# ---------------------------------------------------------------------------
# 配置（只读）
# ---------------------------------------------------------------------------
#: 无论 ``mcp_server.disabled_groups`` 里写了什么都必须注册的工具组：
#: ``cn_help`` 是宿主的发现 / 契约入口，禁掉等于整套工具不可见。
#: 与 ``lib.mcp_server_control.ALWAYS_ON_GROUPS`` 保持一致（UI 侧同锁）。
ALWAYS_ON_GROUPS: tuple[str, ...] = ("cn_help",)

#: ``app.store`` 不可用时的最小回退（只保留工具用得到的键）。
_FALLBACK: dict[str, Any] = {
    "llm": {
        "base_url": "http://localhost:11434/v1",
        "api_key": "",
        "timeout": 120,
        "headers": "",
        "model": "",
        "embedding_model": "",
        "ocr_model": "",
        "multimodal_model": "",
        "system_prompt_zh": "",
        "system_prompt_en": "",
    },
    "proxy_pool": {
        "enabled": False,
        "protocol": "http",
        "manual": "",
        "timeout": 6.0,
        "threads": 64,
        "max_proxies": 200,
        "cache": [],
    },
    "pomodoro": {
        "work_minutes": 25,
        "short_rest_minutes": 5,
        "long_rest_minutes": 15,
        "long_every": 4,
        "auto_next": True,
        "notify": True,
    },
    "watermark": {"output_dir": "output"},
    "zip_crack": {"output_dir": "output", "use_builtin_dict": True,
                  "max_numeric_len": 6, "alphabet": "lower"},
    "md5_crash": {"min_len": 8, "max_len": 18, "worker_num": 8,
                  "thread_num": 8, "mode": "mixed"},
    "leak_scan": {"output_dir": "output/leak", "threads": 8, "timeout": 8},
    "port_scan": {"threads": 24, "timeout": 6, "retries": 3,
                  "out_dir": "output/portscan"},
    "param_fuzz": {"method": "GET", "wordlist": "small", "timeout": 15,
                   "threads": 5, "chunks": 250, "rate_limit": 0},
    "web_fuzz": {"timeout": 8, "robots": False, "sitemap": False,
                 "hostsearch": False, "subdomain_brute": False,
                 "subdomain_interval": 0.3, "subdomain_use_proxy": False},
    "dns_tool": {"use_proxy": False},
    "subdomain_brute": {"interval": 0.3, "use_proxy": False, "dict_path": ""},
    "ping_probe": {
        "base_url": "https://cn.apihz.cn/api/wangzhan/pingplus.php",
        "api_id": "10022374",
        "api_key": "qwertyuiopasdfghjklzxcvbn",
        "dy": "0",
        "headers": "",
    },
    "wechat_check": {"timeout": 15},
    "ssti_finder": {"timeout": 15},
    "mysql_brute": {"port": 3306, "threads": 8, "timeout": 6, "limit": 0,
                    "out_dir": "output/mysql"},
}


def _deep_merge(base: dict, override: dict) -> dict:
    merged = dict(base)
    for key, value in override.items():
        current = merged.get(key)
        if isinstance(current, dict) and isinstance(value, dict):
            merged[key] = _deep_merge(current, value)
        else:
            merged[key] = value
    return merged


class Settings:
    """只读配置访问器：``settings.get("llm", "model", default="")``。"""

    def __init__(self, store: Any | None = None) -> None:
        self._store = store
        self._data: dict[str, Any] | None = None

    # -- 装载 --------------------------------------------------------------
    def load(self) -> "Settings":
        if self._data is not None:
            return self
        if self._store is None:
            try:
                from app.store import SettingsStore  # 与 GUI/CLI 共用配置
                self._store = SettingsStore(None)
                log(f"配置已加载：{self._store.path}")
            except Exception as exc:  # pragma: no cover - 取决于运行环境
                log(f"配置不可用（{type(exc).__name__}: {exc}），使用内置默认值")
                self._store = None
        self._data = _FALLBACK
        return self

    def _raw(self) -> dict[str, Any]:
        self.load()
        if self._store is not None:
            try:
                return _deep_merge(_FALLBACK, dict(self._store._data))  # noqa: SLF001
            except Exception:  # pragma: no cover
                pass
        return dict(_FALLBACK)

    # -- 读取 --------------------------------------------------------------
    def get(self, *keys: str, default: Any = None) -> Any:
        node: Any = self._raw()
        for key in keys:
            if not isinstance(node, dict) or key not in node:
                return default
            node = node[key]
        return node

    def section(self, name: str) -> dict[str, Any]:
        value = self.get(name, default={})
        return dict(value) if isinstance(value, dict) else {}

    # -- 常用快捷 ----------------------------------------------------------
    def llm(self) -> dict[str, Any]:
        return self.section("llm")

    @property
    def project_root(self) -> Path:
        return PROJECT_ROOT

    @property
    def mcp_root(self) -> Path:
        return MCP_ROOT


_settings = Settings()


def settings() -> Settings:
    """进程级只读配置单例。"""
    return _settings.load()


# ---------------------------------------------------------------------------
# 代理池（全局，供 Web 系工具复用）
# ---------------------------------------------------------------------------
_proxy_lock = threading.Lock()
_proxy_ready = False


def init_proxy_pool() -> None:
    """把配置里的 ``proxy_pool`` 节装载到 ``lib.proxy_pool`` 全局单例。

    幂等；失败只记日志，不影响不依赖代理的工具。
    """
    global _proxy_ready
    with _proxy_lock:
        if _proxy_ready:
            return
        try:
            from lib import proxy_pool
            proxy_pool.load_config(settings().section("proxy_pool"))
            _proxy_ready = True
            if proxy_pool.is_enabled():
                log("全局代理池已启用")
        except Exception as exc:  # pragma: no cover
            log(f"代理池装载失败（{type(exc).__name__}: {exc}），网络工具将直连")


def proxy_enabled() -> bool:
    """全局代理池是否启用（读配置，不触发网络）。"""
    try:
        return bool(settings().get("proxy_pool", "enabled", default=False))
    except Exception:  # pragma: no cover
        return False


def stderr_logger(prefix: str = "") -> Callable[[str], None]:
    """生成一个写 stderr 的日志回调，供 lib 工具的 ``log=`` 参数使用。"""

    def _emit(message: str) -> None:
        log(f"{prefix}{message}")

    return _emit
