# -*- coding: utf-8 -*-
"""MCP HTTP 服务的进程管理与状态检测（纯逻辑，不依赖 UI）。

28zenro 的 MCP 服务器 ``mcp/server.py`` 支持 stdio 与 streamable-http 两种
传输。stdio 模式由宿主（Claude Desktop / Cursor 等）以子进程方式拉起，GUI
无法也不应接管；本模块管理的是 **HTTP 长驻服务进程**：

- 用 ``subprocess.Popen`` 拉起 MCP 服务子进程（dev 为
  ``python mcp/server.py --http ...``；打包后为同目录的
  ``28zenroMcp.exe --http ...``）；
- 提供优雅停止（先 terminate，超时再 kill）；
- 通过探测 ``host:port`` 是否监听判断「运行中」状态（与是否由本 GUI 启动无关，
  因此也能识别外部手动启动的服务）。

本模块不导入任何 UI 模块，进程输出以回调形式暴露给界面层。
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

#: 默认监听地址与端口（与 mcp/start_http.cmd 保持一致）
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000

#: 启动后等待服务就绪的最长时间（秒）
_READY_TIMEOUT = 10.0

#: 停止进程的优雅等待（秒），超时后强制 kill
_TERM_GRACE = 3.0


def project_root() -> Path:
    """项目根目录（源码运行时为 ``mcp/`` 的上级，打包后为 exe 目录）。"""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def server_script() -> Path:
    """MCP 服务器入口脚本路径：``<root>/mcp/server.py``（仅 dev 模式使用）。"""
    return project_root() / "mcp" / "server.py"


#: 打包后随主程序一起分发的 MCP 服务子进程名
MCP_WORKER_EXE = "28zenroMcp.exe"


def _launch_head() -> list[str]:
    """拼出 MCP 服务启动命令的前半段（后半段为 ``--http --host --port``）。

    - dev：``python mcp/server.py``；
    - 冻结：``28zenroMcp.exe``（同目录专用子程序）。冻结态不能再用
      ``sys.executable + server.py`` —— exe 会把所有参数当 GUI 启动，
      导致再开一个实例抢 QtWebEngine 缓存、MCP 服务永远起不来。
    """
    if getattr(sys, "frozen", False):
        worker = Path(sys.executable).resolve().parent / MCP_WORKER_EXE
        if worker.is_file():
            return [str(worker)]
        # 老版本包没带 MCP 子程序：返回占位（start() 里给出友好错误）
        return ["__missing_worker__"]
    return [sys.executable or "python", str(server_script())]


def config_path() -> Path:
    """宿主连接配置文件路径：``<root>/mcp/mcp.json``。

    这是给 Claude Desktop / Cursor 等宿主配置 stdio 连接用的 mcpServers 片段，
    与 HTTP 服务的 host/port 配置（store 的 ``mcp_server`` 节）相互独立。
    """
    return project_root() / "mcp" / "mcp.json"


def read_config() -> str:
    """读取 mcp.json 文本；文件不存在时返回空字符串。"""
    path = config_path()
    if not path.is_file():
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def write_config(text: str) -> None:
    """把文本写回 mcp.json（父目录不存在时先创建）。"""
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def validate_config(text: str) -> str | None:
    """校验 mcp.json 文本是否为合法 JSON；合法返回 None，否则返回错误信息。"""
    import json
    try:
        json.loads(text)
    except json.JSONDecodeError as exc:
        return f"JSON 解析失败（第 {exc.lineno} 行第 {exc.colno} 列）：{exc.msg}"
    except Exception as exc:  # noqa: BLE001
        return f"校验失败：{exc}"
    return None


def port_open(host: str, port: int, timeout: float = 0.6) -> bool:
    """探测 ``host:port`` 是否有进程在监听（TCP connect）。"""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# 工具注册表：展示 / 按组禁用（配置键 ``mcp_server.disabled_groups``）
# ---------------------------------------------------------------------------
#: 永远注册、不允许禁用的工具组：``cn_help`` 是宿主的发现/契约入口，禁掉它
#: 之后其它工具组对 Agent 不可见，等于整套 MCP 失效。
ALWAYS_ON_GROUPS: tuple[str, ...] = ("cn_help",)


def registry_summary() -> dict:
    """读取 MCP 工具注册表摘要（供 UI 展示）。

    直接导入 ``mcp/28zenro_mcp/ops`` 的 :data:`GROUPS`（合同层不依赖
    MCP SDK，与 GUI 依赖无冲突），返回::

        {"groups": [{"name", "title", "summary", "op_count",
                     "ops": [{"name", "risk", "returns", "summary"}]}],
         "import_errors": {模块名: 失败原因}}

    某工具组因可选依赖缺失（如 Pillow）导入失败时只是从 ``groups``
    中缺席并记录在 ``import_errors``，与服务器运行时行为一致。
    """
    mcp_dir = project_root() / "mcp"
    root = project_root()
    for path in (str(root), str(mcp_dir)):
        if path not in sys.path:
            sys.path.insert(0, path)
    from 28zenro_mcp.ops import GROUPS, IMPORT_ERRORS  # noqa: E402

    groups: list[dict] = []
    for group in GROUPS:
        groups.append({
            "name": group.name,
            "title": group.title,
            "summary": group.summary,
            "op_count": len(group.ops),
            "risks": group.risks(),
            "ops": [{
                "name": spec.name,
                "risk": spec.risk,
                "returns": spec.returns,
                "summary": spec.summary,
            } for spec in group.ops],
        })
    return {
        "groups": groups,
        "import_errors": dict(IMPORT_ERRORS),
        "total_ops": sum(len(g["ops"]) for g in groups),
    }


def load_disabled_groups(store) -> list[str]:
    """读取被禁用的工具组名单（``store['mcp_server']['disabled_groups']``）。"""
    cfg = store.get("mcp_server", default={}) or {}
    disabled = cfg.get("disabled_groups") or []
    return [str(name) for name in disabled if isinstance(name, str)]


def save_disabled_groups(store, names) -> None:
    """保存禁用名单并落盘（存储键 ``mcp_server.disabled_groups``）。"""
    clean = sorted({str(name) for name in names if isinstance(name, str)})
    store.setv(clean, "mcp_server", "disabled_groups")
    store.save()


def apply_disabled_groups(group_names: list[str], disabled: list[str]) -> list[str]:
    """按禁用名单过滤出实际注册的工具组名（``cn_help`` 恒在）。"""
    blocked = {str(name) for name in disabled}
    protect = set(ALWAYS_ON_GROUPS)
    return [name for name in group_names if name not in blocked or name in protect]


class McpServerProcess:
    """一个 MCP HTTP 服务子进程的句柄：启动 / 停止 / 状态 / 输出回调。"""

    def __init__(self) -> None:
        self._proc: subprocess.Popen | None = None
        self._host = DEFAULT_HOST
        self._port = DEFAULT_PORT

    # ------------------------------------------------------------ 状态
    @property
    def running(self) -> bool:
        """本句柄拉起的进程是否仍在运行。"""
        return self._proc is not None and self._proc.poll() is None

    @property
    def pid(self) -> int | None:
        return self._proc.pid if self._proc is not None else None

    def is_listening(self) -> bool:
        """``host:port`` 是否在监听（不区分是否由本句柄启动）。"""
        return port_open(self._host, self._port)

    # ------------------------------------------------------------ 启动
    def start(self, host: str, port: int,
              on_output: Callable[[str], None] | None = None) -> bool:
        """启动 HTTP 服务。已在运行则先停止旧进程。

        返回是否启动成功（进程成功拉起并存活即视为成功；服务完全就绪由
        界面层用 ``is_listening`` 轮询确认）。
        """
        self._host = host
        self._port = port
        self.stop()

        head = _launch_head()
        if head == ["__missing_worker__"]:
            worker = Path(sys.executable).resolve().parent / MCP_WORKER_EXE
            if on_output:
                on_output(f"[错误] 打包版缺少 MCP 服务程序：{worker}\n"
                          "[错误] 请使用最新版发布包（含 28zenroMcp.exe）。")
            return False
        cmd = head + ["--http", "--host", str(host), "--port", str(port)]

        def _reader() -> None:
            # 在后台线程里读 stdout/stderr，避免缓冲区写满阻塞子进程
            import threading
            assert self._proc is not None

            def _pump(stream, prefix: str) -> None:
                try:
                    for line in iter(stream.readline, ""):
                        if on_output:
                            on_output(f"{prefix}{line.rstrip()}")
                except Exception:  # noqa: BLE001  读取失败忽略
                    pass

            threading.Thread(
                target=_pump, args=(self._proc.stdout, ""), daemon=True).start()
            threading.Thread(
                target=_pump, args=(self._proc.stderr, ""), daemon=True).start()

        try:
            kwargs: dict[str, Any] = {}
            if os.name == "nt":
                # MCP 子程序是 console 型（日志走管道），不能让它弹黑窗；
                # CREATE_NO_WINDOW 下 stdout/stderr 管道照常工作。
                kwargs["creationflags"] = getattr(
                    subprocess, "CREATE_NO_WINDOW", 0)
            self._proc = subprocess.Popen(
                cmd,
                cwd=str(project_root()),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                **kwargs,
            )
        except OSError as exc:
            self._proc = None
            if on_output:
                on_output(f"[错误] 启动失败：{exc}")
            return False

        _reader()
        if on_output:
            on_output(f"[启动] {' '.join(cmd)}")
        return True

    # ------------------------------------------------------------ 停止
    def stop(self) -> None:
        """优雅停止：先 terminate，超时后 kill。"""
        proc = self._proc
        self._proc = None
        if proc is None:
            return
        if proc.poll() is not None:
            return
        try:
            proc.terminate()
        except OSError:
            pass
        try:
            proc.wait(timeout=_TERM_GRACE)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except OSError:
                pass
            try:
                proc.wait(timeout=1.0)
            except Exception:  # noqa: BLE001
                pass


# ---------------------------------------------------------------------------
# 便捷函数（供界面层直接使用，内部维护一个全局单例句柄）
# ---------------------------------------------------------------------------
_manager = McpServerProcess()


def current_manager() -> McpServerProcess:
    """返回进程内共享的 MCP 服务句柄单例。"""
    return _manager


def probe_status(host: str, port: int) -> dict:
    """探测 MCP HTTP 服务状态，返回结构化结果。"""
    listening = port_open(host, port)
    return {
        "listening": listening,
        "host": host,
        "port": port,
        "managed": _manager.running,
        "pid": _manager.pid,
        "script": str(server_script()),
    }


def fetch_sessions(host: str, port: int, timeout: float = 1.0) -> dict | None:
    """查询 HTTP 服务的活跃连接列表（``/__sessions`` 端点）。

    返回结构化快照；服务未监听 / 端点不存在 / 超时 / 非 JSON 时返回 ``None``。
    """
    import json
    import urllib.request

    url = f"http://{host}:{port}/__sessions"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data
    except Exception:  # noqa: BLE001  网络/解析失败统一降级
        return None
