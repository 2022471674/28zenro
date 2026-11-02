# -*- coding: utf-8 -*-
"""cn_help —— 元工具：发现 / 契约查询 / 自检。

Agent 的推荐用法
----------------
1. ``cn_help(op="list")``：拿到全部工具与 op 名称（体积小）；
2. ``cn_help(op="help", params={"op": "base64_encrypt"})``：拿到该 op 的完整参数表；
3. 真正调用目标工具；
4. ``cn_help(op="audit")``：怀疑契约漂移时自检。
"""

from __future__ import annotations

import platform
import sys
from typing import Any

from ..contract import Ctx, Group, audit, custom_op, flag, txt
from ..envelope import to_jsonable

_TOOL = "cn_help"


def _groups() -> list[Group]:
    from . import GROUPS  # 延迟导入，避免包初始化期的循环依赖
    return GROUPS


def _build_index() -> dict[str, Group]:
    return {group.name: group for group in _groups()}


def _list(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    detail = bool(a["with_params"])
    tools = []
    for group in _groups():
        item: dict[str, Any] = {
            "tool": group.name,
            "title": group.title,
            "summary": group.summary,
            "op_count": len(group.ops),
            "risks": group.risks(),
            "ops": group.op_names(),
        }
        if detail:
            item["op_specs"] = [spec.schema() for spec in group.ops]
        tools.append(item)
    return {"tool_count": len(tools),
            "op_count": sum(item["op_count"] for item in tools),
            "tools": tools}


def _help(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    op_name = str(a["op"] or "").strip()
    tool_name = str(a["tool"] or "").strip()
    index = _build_index()
    if op_name:
        from ..contract import find_op
        group, spec = find_op(_groups(), op_name)
        if spec is None or group is None:
            from ..envelope import ToolError
            raise ToolError(
                "invalid_op", f"未知 op：{op_name}",
                hint="用 cn_help(op=\"list\") 查看全部工具与 op；"
                     "也可用 cn_help(op=\"list\", params={\"with_params\": true}) 拉全量契约")
        payload = spec.schema()
        payload["op"] = spec.name
        payload["tool"] = group.name
        payload["tool_title"] = group.title
        payload["call"] = {
            "tool": group.name,
            "op": spec.name,
            "params_example": spec.example or {},
        }
        return payload
    if tool_name:
        group = index.get(tool_name) or index.get(f"cn_{tool_name}")
        if group is None:
            from ..envelope import ToolError
            raise ToolError("invalid_op", f"未知工具：{tool_name}",
                            hint=f"可用工具：{', '.join(index)}")
        return group.schema()
    return {
        "hint": "按 tool 或 op 查询：params={\"op\": \"base64_encrypt\"} / "
                "{\"tool\": \"cn_codec\"}；不传则返回全部工具摘要",
        "tools": [
            {"tool": group.name, "title": group.title,
             "op_count": len(group.ops), "summary": group.summary}
            for group in _groups()
        ],
    }


def _audit(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    issues = audit(_groups())
    return {
        "ok": not issues,
        "issue_count": len(issues),
        "issues": issues,
        "checked_ops": sum(len(group.ops) for group in _groups()),
        "note": ("审计规则：op 声明的参数必须存在于 lib 函数签名；"
                 "lib 的必填参数必须在契约里声明；log/progress/stop 由分发器注入。"),
    }


def _version(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    from .. import __version__
    from ..bootstrap import PROJECT_ROOT, settings
    try:
        import mcp as mcp_sdk
        sdk_version = getattr(mcp_sdk, "__version__", "unknown")
    except Exception:  # pragma: no cover
        sdk_version = "unavailable"
    lib_modules = []
    try:
        from pathlib import Path
        lib_dir = Path(PROJECT_ROOT) / "lib"
        lib_modules = sorted(path.stem for path in lib_dir.glob("*.py")
                             if path.stem != "__init__")
    except Exception:  # pragma: no cover
        pass
    store = getattr(settings(), "_store", None)
    plugins: dict[str, Any] = {}
    try:
        from ..pluginkit import discovered_plugins
        plugins = discovered_plugins()
    except Exception:  # pragma: no cover - 插件层不可用时忽略
        pass
    return {
        "server": "28zenro-mcp",
        "version": __version__,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "mcp_sdk": sdk_version,
        "project_root": str(PROJECT_ROOT),
        "config_path": str(getattr(store, "path", "") or "") or None,
        "tool_count": len(_groups()),
        "op_count": sum(len(group.ops) for group in _groups()),
        "lib_modules": lib_modules,
        "plugin_count": len(plugins.get("plugins") or {}),
        "plugins": {
            key: {"available": item.get("available"),
                  "kind": item.get("kind"),
                  "entry_rel": item.get("entry_rel")}
            for key, item in (plugins.get("plugins") or {}).items()
        },
        "manifest_errors": plugins.get("manifest_errors") or {},
    }


def _export(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    return {
        "server": "28zenro-mcp",
        "conventions": {
            "call": "<tool>(op=\"<op>\", params={...})",
            "envelope": {"ok": True, "tool": "…", "op": "…", "data": "…",
                         "meta": {"module": "…", "risk": "…",
                                  "elapsed_ms": 0.0, "params": {}}},
            "error_envelope": {"ok": False, "tool": "…", "op": "…",
                               "error": {"code": "…", "message": "…"}},
            "param_types": ["str", "int", "float", "bool", "list", "dict", "hex", "any"],
            "risks": ["safe", "read", "write", "network", "intrusive", "long"],
            "path_rule": "相对路径基于项目根 CTFcrypto/",
            "secret_masking": "meta.params 中 password/secret/token/key/cookie 等键做脱敏",
        },
        "tools": [group.schema() for group in _groups()],
    }


def _sessions(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    """返回当前活跃连接快照（仅 HTTP 模式有意义）。"""
    try:
        from ..session_tracker import snapshot
    except Exception:  # pragma: no cover - 模块缺失时降级
        return {"transport": "unknown", "count": 0, "sessions": [],
                "note": "连接追踪不可用（可能为 stdio 模式）。"}
    return snapshot()


OPS = [
    custom_op("list", _list, "列出全部工具与 op 名称（工具发现入口）。",
              [flag("with_params", default=False,
                    desc="是否连同每个 op 的完整参数表一起返回（体积大）")],
              returns="dict：{tool_count, op_count, tools: [{tool, title, summary, ops}]}",
              risk="safe", module=_TOOL),
    custom_op("help", _help, "查询某个 op 的完整参数表（推荐按 op 名查）。",
              [txt("op", desc="op 名称，如 ``base64_encrypt``"),
               txt("tool", desc="工具名，如 ``cn_codec``（与 op 二选一）")],
              returns="dict：op 契约（参数表 / 返回 / 风险 / 示例）或工具 schema",
              risk="safe", module=_TOOL),
    custom_op("audit", _audit, "契约审计：核对声明的参数与 lib 真实函数签名是否一致。",
              [], returns="dict：{ok, issue_count, issues, checked_ops}",
              risk="safe", module=_TOOL),
    custom_op("version", _version, "返回服务版本、运行环境、lib 模块清单与统计。",
              [], returns="dict：版本与环境信息", risk="safe", module=_TOOL),
    custom_op("export", _export,
              "导出完整契约（机器可读 JSON），可用于自动生成客户端代码或文档。",
              [], returns="dict：{server, conventions, tools: [...]}",
              risk="safe", module=_TOOL),
    custom_op("sessions", _sessions,
              "查询当前活跃连接（HTTP 模式）：返回连接数、session_id、来源 IP、"
              "User-Agent、创建/最近活跃时间。stdio 模式返回空列表。",
              [], returns="dict：{transport, count, sessions: [...]}",
              risk="safe", module=_TOOL),
]


GROUP = Group(
    name="cn_help",
    title="元工具：发现 / 契约 / 自检",
    summary=("工具发现与契约查询：list（全部工具与 op）、help（单个 op 的参数表）、"
             "audit（契约与 lib 签名一致性自检）、version、export（全量契约 JSON）、"
             "sessions（活跃连接查询）。"),
    ops=OPS,
    guide="任何不确定 op 名或参数时，先调 cn_help(op=\"list\")，再 cn_help(op=\"help\")。",
)
