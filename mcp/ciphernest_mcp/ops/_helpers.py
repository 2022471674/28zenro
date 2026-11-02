# -*- coding: utf-8 -*-
"""op 实现共用的辅助函数：路径解析、配置默认值、线程任务轮询。"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Callable

from ..bootstrap import PROJECT_ROOT, Settings, log, settings
from ..envelope import ToolError


# ---------------------------------------------------------------------------
# 路径约定：相对路径一律基于**项目根**（CTFcrypto/），而不是宿主进程的 CWD
# ---------------------------------------------------------------------------
def resolve_path(raw: Any, *, field: str = "path", must_exist: bool = False) -> Path:
    """把用户给的路径规范成绝对路径（相对路径基于项目根）。"""
    text = str(raw or "").strip()
    if not text:
        raise ToolError("missing_param", f"缺少必填参数 {field}（文件路径）", field=field)
    path = Path(text).expanduser()
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    try:
        path = path.resolve()
    except OSError:  # pragma: no cover - Windows 极端路径
        path = Path(path)
    if must_exist and not path.exists():
        raise ToolError("io", f"{field} 指向的文件不存在：{path}", field=field)
    return path


def resolve_output(raw: Any, default: str | Path, *,
                   field: str = "out_path") -> Path:
    """解析输出路径：留空则回落到 ``default``（相对项目根）。"""
    text = str(raw or "").strip()
    if not text:
        path = Path(default)
        if not path.is_absolute():
            path = PROJECT_ROOT / path
        return path
    return resolve_path(text, field=field)


def resolve_output_dir(raw: Any, default: str | Path, *,
                       field: str = "out_dir") -> Path:
    """解析输出目录（不创建，由 lib 侧按需创建）。"""
    return resolve_output(raw, default, field=field)


def default_dict_dir() -> Path:
    """内置字典目录 ``dict/Contents``（目录爆破 / 子域名）。"""
    return PROJECT_ROOT / "dict" / "Contents"


def rel(path: Path) -> str:
    """把绝对路径尽量表示为相对项目根的短路径（仅用于展示）。"""
    try:
        return str(Path(path).resolve().relative_to(PROJECT_ROOT))
    except (ValueError, OSError):
        return str(path)


# ---------------------------------------------------------------------------
# 配置默认值
# ---------------------------------------------------------------------------
def llm_defaults() -> dict[str, Any]:
    """大模型相关默认值：全部来自 ``config.json`` 的 ``llm`` 节。"""
    conf = settings().llm()
    return {
        "base_url": str(conf.get("base_url") or "").strip(),
        "api_key": str(conf.get("api_key") or ""),
        "timeout": float(conf.get("timeout") or 120),
        "headers": str(conf.get("headers") or ""),
        "model": str(conf.get("model") or ""),
        "embedding_model": str(conf.get("embedding_model") or ""),
        "ocr_model": str(conf.get("ocr_model") or ""),
        "multimodal_model": str(conf.get("multimodal_model") or ""),
        "system_prompt_zh": str(conf.get("system_prompt_zh") or ""),
        "system_prompt_en": str(conf.get("system_prompt_en") or ""),
    }


def section(name: str) -> dict[str, Any]:
    return settings().section(name)


# ---------------------------------------------------------------------------
# 线程型任务轮询（md5 / zip 爆破复用）
# ---------------------------------------------------------------------------
def poll_until_done(job: Any, *, max_seconds: float,
                    log_fn: Callable[[str], None],
                    events: list[tuple] | None = None) -> bool:
    """轮询 ``job.running`` 直到结束或超时；返回是否在时限内结束。"""
    deadline = time.monotonic() + max(0.1, float(max_seconds))
    while getattr(job, "running", False) and time.monotonic() < deadline:
        if events is not None:
            events.extend(job.poll_logs())
        time.sleep(0.08)
    if events is not None:
        events.extend(job.poll_logs())
    finished = not getattr(job, "running", False)
    if not finished:
        log_fn(f"达到时间上限 {max_seconds}s，正在停止任务…")
        try:
            job.stop(wait=True, timeout=5.0)
        except Exception as exc:  # pragma: no cover
            log(f"停止任务失败：{type(exc).__name__}: {exc}")
        if events is not None:
            events.extend(job.poll_logs())
    return finished


def job_result(job: Any, events: list[tuple], *, finished: bool,
               kind: str = "crack") -> dict[str, Any]:
    """把线程型任务整理成统一结果 dict。"""
    status = str(getattr(job, "status", "") or "")
    if not finished and status != "found":
        status = status or "timeout"
    payload: dict[str, Any] = {
        "status": status or ("found" if getattr(job, "result", None) else "done"),
        "result": getattr(job, "result", None),
        "error": getattr(job, "error", None),
        "finished": finished,
        "events": [list(event) for event in events][-200:],
        "kind": kind,
    }
    return payload
