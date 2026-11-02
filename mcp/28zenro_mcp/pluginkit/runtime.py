# -*- coding: utf-8 -*-
"""第三方插件运行时：发现 + 受控子进程调用 + 输出整形。

插件目录：``mcp/plugins/``（用户放第三方工具的地方）。两类插件：

- ``binary``：直接可执行文件（如 ``trufflehog/trufflehog.exe``）；
- ``python``：入口是 ``.py`` 脚本，用当前解释器 + ``cwd=插件目录`` 启动
  （很多工具依赖自身目录下的模块，必须这样跑）。

统一约定
--------
1. **永不经过 shell**：命令是 ``list[str]``，参数逐个透传，天然免疫命令注入；
2. **stdin 必须隔离**：stdio 模式下本服务的 stdin 是 MCP 协议通道，
   插件若去读 stdin 会吞协议帧。因此默认 ``stdin=DEVNULL``，
   只有显式传 ``stdin_text`` 时才给管道；
3. **超时必杀**：``timeout`` 到点由 ``subprocess`` 终止进程；
4. **输出设上限**：超长输出保留「头部 + 尾部」，标记 ``output_truncated``；
5. **返回结构化结果**：``success/returncode/duration_ms/stdout_tail/stderr_tail``
   固定字段，适配器再补充解析出来的业务字段。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from ..bootstrap import PROJECT_ROOT
from ..envelope import ToolError

#: 插件根目录（mcp/plugins）。
PLUGINS_ROOT = PROJECT_ROOT / "mcp" / "plugins"


# ---------------------------------------------------------------------------
# 独立 Python 运行时（python 型插件在打包版里的运行前提）
# ---------------------------------------------------------------------------
def python_runtime() -> tuple[bool, str | None, str]:
    """探测可运行 Python 型插件的解释器。

    返回 ``(可用?, 解释器路径或 None, 来源说明)``：

    - dev：直接用当前解释器；
    - frozen：按优先级 ``28ZENRO_PYTHON`` 环境变量 →
      ``<exe 目录>/runtime/python/python.exe`` → ``<exe 目录>/runtime/python.exe``。
      主包默认不内置解释器（精简 1GB+ 瘦身的决定），带插件分支包 + 用户
      事后部署嵌入式 Python（如 python-3.12 embeddable）即可启用 sqlmap /
      OneForAll / FileSensor 等 python 型插件，`cn_plugin(op="doctor")`
      会实时探测并给出安装路径。
    """
    if not getattr(sys, "frozen", False):
        return True, sys.executable, "dev: 当前解释器（源码运行）"
    env = str(os.environ.get("28ZENRO_PYTHON", "") or "").strip()
    if env and Path(env).is_file():
        return True, env, "环境变量 28ZENRO_PYTHON"
    exe_dir = Path(sys.executable).resolve().parent
    candidates = (
        exe_dir / "runtime" / "python" / "python.exe",
        exe_dir / "runtime" / "python.exe",
    )
    for candidate in candidates:
        if candidate.is_file():
            return True, str(candidate), f"内置运行时：{candidate}"
    return False, None, "frozen: 未部署独立 Python 运行时"

#: 单次调用允许的最大输出字符数（超出则头尾截断）。
MAX_OUTPUT_CHARS = 300_000
#: 返回给 Agent 的 stdout/stderr 各自最多保留的行数。
TAIL_LINES = 120


# ---------------------------------------------------------------------------
# 插件描述
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Plugin:
    """一个已发现的第三方插件。"""

    key: str                 # 稳定标识，MCP 调用里用这个
    name: str                # 展示名
    kind: str                # "python" | "binary"
    entry: Path              # 入口脚本 / 可执行文件
    cwd: Path                # 工作目录
    version_cmd: tuple[str, ...] = ()   # 版本探测参数（不含入口）
    homepage: str = ""
    notes: str = ""
    ops: tuple[str, ...] = field(default=())   # 已适配的 op 名

    @property
    def available(self) -> bool:
        return self.entry.is_file()

    def command(self, args: Iterable[str]) -> list[str]:
        """拼出完整命令行（python 插件用当前解释器 / 打包版独立运行时）。"""
        if self.kind == "python":
            if getattr(sys, "frozen", False):
                # 冻结态：GUI 主程序是 windowed exe，sys.executable 跑 .py
                # 插件只会再开一个 GUI 实例。必须用部署好的独立 Python 运行时。
                py_ok, py_path, py_source = python_runtime()
                if not py_ok:
                    raise ToolError(
                        "unsupported",
                        f"打包版缺少独立 Python 运行时，无法运行插件 {self.name}",
                        field="plugin",
                        hint="把嵌入式 Python（python-3.12 embeddable）解压到 "
                             "程序目录 runtime\\python\\（保证其 python.exe 可用），"
                             "或设置环境变量 28ZENRO_PYTHON；"
                             "现状详情见 cn_plugin(op=\"doctor\")",
                    )
                return [py_path, str(self.entry)] + [str(arg) for arg in args]
            return ([sys.executable, str(self.entry)]
                    + [str(arg) for arg in args])
        return [str(self.entry)] + [str(arg) for arg in args]

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "name": self.name,
            "kind": self.kind,
            "entry": str(self.entry),
            "entry_rel": _rel(self.entry),
            "cwd": str(self.cwd),
            "available": self.available,
            "version_cmd": list(self.version_cmd),
            "homepage": self.homepage,
            "notes": self.notes,
            "ops": list(self.ops),
        }


def _rel(path: Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(PROJECT_ROOT))
    except (ValueError, OSError):
        return str(path)


# ---------------------------------------------------------------------------
# 发现
# ---------------------------------------------------------------------------
#: 内置适配的插件（按目录名 + 入口文件名定位，允许小幅改名）。
_SPECS: tuple[dict[str, Any], ...] = (
    {
        "key": "trufflehog",
        "name": "TruffleHog",
        "kind": "binary",
        "dirs": ("trufflehog",),
        "entries": ("trufflehog.exe", "trufflehog"),
        "version_cmd": ("--version",),
        "homepage": "https://github.com/trufflesecurity/trufflehog",
        "notes": "密钥/凭证泄露扫描器；结果以 NDJSON 输出到 stdout，日志在 stderr。",
        "ops": ("version", "scan_git", "scan_filesystem", "scan_docker"),
    },
    {
        "key": "sqlmap",
        "name": "sqlmap",
        "kind": "python",
        "dirs": ("sqlmap-master", "sqlmap"),
        "entries": ("sqlmap.py",),
        "version_cmd": ("--version",),
        "homepage": "https://github.com/sqlmapproject/sqlmap",
        "notes": "SQL 注入检测；内部会读 stdin 等待回车，必须隔离 stdin（已处理）。",
        "ops": ("version", "scan", "dbs", "tables", "columns", "dump",
                "tamper_list"),
    },
    {
        "key": "oneforall",
        "name": "OneForAll",
        "kind": "python",
        "dirs": ("OneForAll", "oneforall"),
        "entries": ("oneforall.py",),
        "version_cmd": ("version",),
        "homepage": "https://github.com/shmilylty/OneForAll",
        "notes": "子域名收集；结果导出到插件目录 results/ 下（csv / json）。",
        "ops": ("version", "check", "run", "list_results"),
    },
    {
        "key": "flaskcookie",
        "name": "Flask Session Cookie Manager",
        "kind": "python",
        "dirs": ("flask-session-cookie-manager-master",
                 "flask-session-cookie-manager"),
        "entries": ("flask_session_cookie_manager3.py",
                    "flask_session_cookie_manager2.py"),
        "version_cmd": ("-h",),
        "homepage": "https://github.com/noraj/flask-session-cookie-manager",
        "notes": "Flask session cookie 编解码；上游脚本与 Flask 3.x 不兼容，"
                 "适配器在 CLI 报错时自动回退到 itsdangerous 原生实现。",
        "ops": ("version", "decode", "encode"),
    },
    {
        "key": "filesensor",
        "name": "FileSensor",
        "kind": "python",
        "dirs": ("FileSensor", "filesensor"),
        "entries": ("filesensor.py",),
        "version_cmd": ("-h",),
        "homepage": "https://github.com/Xyntax/FileSensor",
        "notes": "基于 Scrapy 的敏感文件探测（备份 / swp / 源码泄露等）。",
        "ops": ("version", "scan"),
    },
)

#: 清单文件（可选）：``plugins/<任意目录>/plugin.json``，用于接入新工具。
MANIFEST_NAME = "plugin.json"


def _find_entry(directory: Path, names: Iterable[str]) -> Path | None:
    for name in names:
        candidate = directory / name
        if candidate.is_file():
            return candidate
    return None


def _from_spec(spec: dict[str, Any]) -> Plugin | None:
    directory = None
    for name in spec["dirs"]:
        candidate = PLUGINS_ROOT / name
        if candidate.is_dir():
            directory = candidate
            break
    if directory is None:
        return None
    entry = _find_entry(directory, spec["entries"])
    if entry is None:
        return None
    return Plugin(
        key=spec["key"], name=spec["name"], kind=spec["kind"], entry=entry,
        cwd=directory, version_cmd=tuple(spec["version_cmd"]),
        homepage=spec["homepage"], notes=spec["notes"], ops=tuple(spec["ops"]),
    )


def _from_manifest(path: Path) -> Plugin | None:
    """从 ``plugin.json`` 读取一个插件（第三方自助接入）。"""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        MANIFEST_ERRORS[str(path)] = f"{type(exc).__name__}: {exc}"
        return None
    if not isinstance(data, dict):
        MANIFEST_ERRORS[str(path)] = "清单顶层必须是对象"
        return None
    key = str(data.get("key") or path.parent.name).strip()
    directory = path.parent
    entry_name = str(data.get("entry") or "").strip()
    entry = (directory / entry_name) if entry_name else None
    if not key or entry is None or not Path(entry).is_file():
        MANIFEST_ERRORS[str(path)] = "缺少 key / entry，或 entry 文件不存在"
        return None
    kind = str(data.get("kind") or "python").strip().lower()
    if kind not in ("python", "binary"):
        MANIFEST_ERRORS[str(path)] = f"不支持的 kind：{kind}"
        return None
    return Plugin(
        key=key,
        name=str(data.get("name") or key),
        kind=kind,
        entry=Path(entry),
        cwd=directory,
        version_cmd=tuple(str(item) for item in (data.get("version_cmd") or [])),
        homepage=str(data.get("homepage") or ""),
        notes=str(data.get("notes") or ""),
        ops=tuple(str(item) for item in (data.get("ops") or [])),
    )


MANIFEST_ERRORS: dict[str, str] = {}


def discover() -> dict[str, Plugin]:
    """扫描插件目录，返回 ``{key: Plugin}``（进程内缓存）。"""
    found: dict[str, Plugin] = {}
    for spec in _SPECS:
        plugin = _from_spec(spec)
        if plugin is not None:
            found[plugin.key] = plugin
    if PLUGINS_ROOT.is_dir():
        for manifest in sorted(PLUGINS_ROOT.glob(f"*/{MANIFEST_NAME}")):
            plugin = _from_manifest(manifest)
            if plugin is not None and plugin.key not in found:
                found[plugin.key] = plugin
    return found


PLUGINS: dict[str, Plugin] = discover()


def get_plugin(key: Any) -> Plugin:
    """按 key 取插件；不存在或不可用时报错（错误码 invalid_param / unsupported）。"""
    name = str(key or "").strip()
    if not name:
        raise ToolError("missing_param", "缺少必填参数 plugin",
                        field="plugin",
                        hint=f"可用插件：{', '.join(sorted(PLUGINS)) or '（未发现）'}")
    plugin = PLUGINS.get(name)
    if plugin is None:
        raise ToolError("invalid_param", f"未知插件：{name}",
                        field="plugin",
                        hint=f"可用插件：{', '.join(sorted(PLUGINS)) or '（未发现）'}")
    if not plugin.available:
        raise ToolError("unsupported",
                        f"插件 {name} 的入口文件不存在：{plugin.entry}",
                        field="plugin",
                        hint="检查 mcp/plugins/ 下的文件是否完整")
    return plugin


# ---------------------------------------------------------------------------
# 子进程执行
# ---------------------------------------------------------------------------
@dataclass
class RunResult:
    """一次插件调用的原始结果。"""

    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration_ms: float
    timed_out: bool = False
    output_truncated: bool = False


def _decode(raw: bytes | None) -> str:
    if not raw:
        return ""
    return raw.decode("utf-8", "replace")


def _truncate(text: str, limit: int = MAX_OUTPUT_CHARS) -> tuple[str, bool]:
    """超长时保留头 60% + 尾 40%，中间打标记。"""
    if len(text) <= limit:
        return text, False
    head = int(limit * 0.6)
    tail = limit - head
    return (text[:head] + f"\n…（输出已截断，共 {len(text)} 字符）…\n"
            + text[-tail:]), True


def _clean_args(args: Any) -> list[str]:
    if args is None:
        return []
    if isinstance(args, (str, bytes)):
        raise ToolError("type_error", "args 必须是字符串数组（不接受整条命令字符串）",
                        field="args",
                        hint='例：{"args": ["git", "https://example.com/repo", "--json"]}')
    if not isinstance(args, (list, tuple)):
        raise ToolError("type_error", f"args 必须是数组，收到 {type(args).__name__}",
                        field="args")
    cleaned: list[str] = []
    for item in args:
        text = str(item)
        if "\x00" in text:
            raise ToolError("invalid_param", "args 里不允许出现 NUL 字符", field="args")
        if len(text) > 4096:
            raise ToolError("range_error", "单个参数过长（>4096）", field="args")
        cleaned.append(text)
    if len(cleaned) > 200:
        raise ToolError("range_error", "参数个数过多（>200）", field="args")
    return cleaned


def run_plugin(plugin: Plugin, args: Iterable[str], *,
               timeout: float = 300.0,
               stdin_text: str | None = None,
               cwd: str | Path | None = None,
               env_extra: dict[str, str] | None = None,
               max_output: int = MAX_OUTPUT_CHARS) -> RunResult:
    """运行插件命令（不经过 shell），返回 :class:`RunResult`。"""
    argv = plugin.command(_clean_args(args))
    workdir = Path(cwd) if cwd else plugin.cwd
    if not Path(workdir).is_dir():
        raise ToolError("io", f"工作目录不存在：{workdir}", field="cwd")

    env = dict(os.environ)
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.setdefault("PYTHONUTF8", "1")
    if env_extra:
        env.update({str(k): str(v) for k, v in env_extra.items()})

    kwargs: dict[str, Any] = {
        "cwd": str(workdir),
        "env": env,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "timeout": max(0.5, float(timeout)),
    }
    if stdin_text is None:
        # 关键：stdio 模式下父进程 stdin 是 MCP 协议通道，绝不能透传给插件
        kwargs["stdin"] = subprocess.DEVNULL
    else:
        kwargs["stdin"] = subprocess.PIPE
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)

    started = time.monotonic()
    timed_out = False
    try:
        proc = subprocess.run(argv, input=(stdin_text or "").encode("utf-8")
                              if stdin_text is not None else None, **kwargs)
        stdout, stderr = proc.stdout, proc.stderr
        returncode = proc.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout, stderr = exc.stdout, exc.stderr
        returncode = -9
    except FileNotFoundError as exc:
        raise ToolError("unsupported", f"无法启动插件：{exc}", field="plugin") from exc
    except OSError as exc:
        raise ToolError("io", f"启动插件失败：{exc}", field="plugin") from exc
    duration_ms = (time.monotonic() - started) * 1000

    text_out, cut_out = _truncate(_decode(stdout), max_output)
    text_err, cut_err = _truncate(_decode(stderr), max_output)
    return RunResult(command=argv, returncode=returncode, stdout=text_out,
                     stderr=text_err, duration_ms=duration_ms,
                     timed_out=timed_out,
                     output_truncated=cut_out or cut_err)


# ---------------------------------------------------------------------------
# 结果整形
# ---------------------------------------------------------------------------
def tail(text: str, lines: int = TAIL_LINES) -> str:
    if not text:
        return ""
    parts = text.rstrip().splitlines()
    return "\n".join(parts[-lines:])


def plugin_result(run: RunResult, plugin: Plugin,
                  extras: dict[str, Any] | None = None) -> dict[str, Any]:
    """把 :class:`RunResult` 变成对 Agent 友好的结构。"""
    success = (not run.timed_out) and run.returncode == 0
    payload: dict[str, Any] = {
        "success": success,
        "plugin": plugin.key,
        "command": run.command,
        "returncode": run.returncode,
        "duration_ms": round(run.duration_ms, 1),
        "timed_out": run.timed_out,
        "output_truncated": run.output_truncated,
        "stdout_tail": tail(run.stdout),
        "stderr_tail": tail(run.stderr),
    }
    if not success:
        payload["error"] = {
            "code": "timeout" if run.timed_out else "plugin_exit",
            "message": ("插件执行超时" if run.timed_out
                        else f"插件返回非零退出码 {run.returncode}"),
            "hint": "看 stderr_tail / stdout_tail 定位；必要时加大 max_seconds 或检查参数",
        }
    if extras:
        payload.update(extras)
    return payload


def parse_ndjson(text: str) -> list[dict[str, Any]]:
    """解析按行分隔的 JSON（trufflehog 的 ``--json`` 输出）。"""
    items: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            items.append(value)
    return items


def first_line(text: str) -> str:
    for line in text.splitlines():
        if line.strip():
            return line.strip()
    return ""


def summarize_duration(ms: float) -> str:
    return f"{ms / 1000:.1f}s" if ms >= 1000 else f"{ms:.0f}ms"
