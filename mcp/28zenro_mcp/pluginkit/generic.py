# -*- coding: utf-8 -*-
"""cn_plugin —— 插件通用工具组（发现 / 信息 / 环境检测 / 体检 / 受控直调）。

所有第三方插件共用这一个入口；针对具体插件的「二次封装」是独立的工具组
（``cn_sqlmap`` / ``cn_trufflehog`` / ``cn_oneforall`` / ``cn_flaskcookie`` /
``cn_filesensor``），它们的 op 更语义化、返回值已经解析成结构。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import sys

from ..contract import (Ctx, Group, arr, custom_op, flag, num, txt)
from ..envelope import ToolError
from .runtime import (MANIFEST_ERRORS, PLUGINS, PLUGINS_ROOT, get_plugin,
                      plugin_result, run_plugin, first_line, parse_ndjson,
                      python_runtime)

_TOOL = "cn_plugin"


def _list(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    detailed = bool(a["with_ops"])
    items = []
    for key in sorted(PLUGINS):
        plugin = PLUGINS[key]
        item = plugin.to_dict()
        if not detailed:
            item.pop("version_cmd", None)
            item.pop("cwd", None)
        items.append(item)
    return {
        "count": len(items),
        "plugins_root": str(PLUGINS_ROOT),
        "available": [item["key"] for item in items if item["available"]],
        "missing": [item["key"] for item in items if not item["available"]],
        "plugins": items,
        "manifest_errors": dict(MANIFEST_ERRORS),
        "hint": "具体插件有专用工具组（cn_sqlmap / cn_trufflehog / "
                "cn_oneforall / cn_flaskcookie / cn_filesensor）；"
                "其他插件用 cn_plugin(op=\"run\") 直调。",
    }


def _info(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    plugin = get_plugin(a["plugin"])
    payload = plugin.to_dict()
    payload["version_cmd_hint"] = plugin.command(plugin.version_cmd)
    payload["dedicated_tool"] = f"cn_{plugin.key}" if plugin.ops else None
    return payload


def _check(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    key = str(a["plugin"] or "").strip()
    keys = [key] if key else sorted(PLUGINS)
    results = []
    for item in keys:
        plugin = PLUGINS.get(item)
        if plugin is None:
            results.append({"plugin": item, "ok": False,
                            "error": f"未知插件：{item}"})
            continue
        if not plugin.available:
            results.append({"plugin": item, "ok": False,
                            "error": f"入口不存在：{plugin.entry}"})
            continue
        args = list(plugin.version_cmd) or ["-h"]
        try:
            run = run_plugin(plugin, args, timeout=60)
        except ToolError as exc:
            # 冻结态缺独立解释器等环境问题：只降级这一项，不影响其他插件
            results.append({"plugin": item, "ok": False,
                            "error": str(exc.message), "hint": exc.hint})
            continue
        results.append({
            "plugin": item,
            "ok": run.returncode == 0 and not run.timed_out,
            "command": run.command,
            "returncode": run.returncode,
            "duration_ms": round(run.duration_ms, 1),
            "version_line": first_line(run.stdout) or first_line(run.stderr),
            "stdout_tail": run.stdout.strip()[-400:],
            "stderr_tail": run.stderr.strip()[-400:],
        })
    return {"count": len(results), "ok": all(item["ok"] for item in results),
            "results": results}


def _doctor(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    """环境检测：打包版 / dev 下插件体系的可用性与修复指引。"""
    from ..ops import IMPORT_ERRORS as _OPS_ERRORS  # 延迟导入避免环

    frozen = bool(getattr(sys, "frozen", False))
    py_ok, py_path, py_source = python_runtime()
    plugin_items = []
    for key in sorted(PLUGINS):
        plugin = PLUGINS[key]
        item = plugin.to_dict()
        item.pop("cwd", None)
        item.pop("version_cmd", None)
        if plugin.kind == "python":
            item["frozen_runnable"] = (py_ok if frozen else True)
            item["needs_python_runtime"] = bool(frozen)
        else:
            item["frozen_runnable"] = True
            item["needs_python_runtime"] = False
        plugin_items.append(item)
    plugins_missing = sorted(
        {"sqlmap", "trufflehog", "oneforall", "flaskcookie", "filesensor"}
        - set(PLUGINS))
    install_hint = []
    if not PLUGINS_ROOT.is_dir():
        install_hint.append(
            f"插件目录不存在：{PLUGINS_ROOT}")
        if frozen:
            install_hint.append(
                "精简版默认不带插件 —— 使用带插件的完整分支包（"
                "28zenro_onedir_full.spec 构建版）；"
                "或把源码 mcp/plugins 整个拷到上面这个路径即可恢复")
    if frozen and not py_ok:
        install_hint.append(
            "Python 型插件（sqlmap / OneForAll / FileSensor / "
            "flaskcookie）需要独立解释器：把 python-3.12 embeddable 解压"
            "到 <exe 目录>/runtime/python/（其 python.exe 必须存在），"
            "或设置环境变量 28ZENRO_PYTHON 后重试 cn_plugin(op=\"check\")")
    return {
        "mode": "frozen(打包)" if frozen else "dev(源码)",
        "python_runtime": {
            "ok": py_ok,
            "path": py_path,
            "source": py_source,
        },
        "plugins_root": str(PLUGINS_ROOT),
        "plugins_root_exists": PLUGINS_ROOT.is_dir(),
        "available": [key for key in sorted(PLUGINS)
                      if PLUGINS[key].available],
        "missing": plugins_missing,
        "plugins": plugin_items,
        "manifest_errors": dict(MANIFEST_ERRORS),
        "module_import_errors": {k: v
                                 for k, v in dict(_OPS_ERRORS).items()
                                 if k.startswith("plugins")},
        "verdict": (
            "插件体系可用"
            if (PLUGINS and not plugins_missing and py_ok)
            else ("插件可用但部分功能受限"
                  if PLUGINS and (plugins_missing or not py_ok)
                  else "本包未集成插件（精简版）")),
        "install": install_hint,
    }


def _run(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    plugin = get_plugin(a["plugin"])
    cwd = None
    if a["cwd"]:
        raw = Path(str(a["cwd"]))
        cwd = raw if raw.is_absolute() else (plugin.cwd / raw)
        if not Path(cwd).is_dir():
            raise ToolError("io", f"cwd 不存在：{cwd}", field="cwd")
    run = run_plugin(plugin, a["args"], timeout=a["max_seconds"],
                     stdin_text=a["stdin"] or None, cwd=cwd)
    payload = plugin_result(run, plugin)
    payload["json_lines"] = len(parse_ndjson(run.stdout))
    return payload


OPS = [
    custom_op("list", _list,
              "列出 mcp/plugins 下发现的所有第三方插件（名称 / 类型 / 入口 / 可用性 / 已适配 op）。",
              [flag("with_ops", default=True,
                    desc="是否包含为每个插件适配的 op 列表与详细元数据")],
              returns="dict：{count, available, missing, plugins: [...], manifest_errors}",
              risk="safe", module=_TOOL),
    custom_op("info", _info, "查看单个插件的详细信息与推荐调用方式。",
              [txt("plugin", required=True, desc="插件 key，如 trufflehog / sqlmap")],
              returns="dict：插件元数据 + version_cmd + 专用工具组",
              risk="safe", module=_TOOL),
    custom_op("check", _check,
              "插件体检：逐个跑版本探测命令，确认可执行、打印版本行。plugin 留空检查全部。",
              [txt("plugin", desc="只检查指定插件；留空检查全部")],
              returns="dict：{ok, results: [{plugin, ok, returncode, version_line}]}",
              risk="safe", module=_TOOL,
              notes="慢工具（sqlmap 首次启动约 1~3s）会给每个插件 60s 上限。"),
    custom_op("doctor", _doctor,
              "环境检测：当前运行模式（dev / 打包）下插件体系可用性 —— 插件清单、"
              "独立 Python 运行时是否部署、插件目录位置与缺失补装指引。",
              [],
              returns="dict：{mode, python_runtime, plugins_root, available, missing, "
                      "plugins, verdict, install: [...]}",
              risk="safe", module=_TOOL,
              notes="不执行任何插件命令（纯静态检测）；运行体检请用 op=\"check\"。"
                    "打包精简版默认不带插件：verdict 会给出补装方法。"),
    custom_op("run", _run,
              "受控直调插件：参数以数组透传（绝不经过 shell），stdin 默认隔离。",
              [txt("plugin", required=True, desc="插件 key"),
               arr("args", required=True,
                   desc="参数数组，如 [\"filesystem\", \"D:/tmp\", \"--json\"]；"
                        "也接受按空白/换行分隔的字符串"),
               num("max_seconds", default=300, desc="最长运行秒数", minimum=1,
                   maximum=3600),
               txt("stdin", desc="写入插件 stdin 的文本；留空则接 DEVNULL（防止吞掉 MCP 协议帧）"),
               txt("cwd", desc="工作目录；相对路径基于插件目录，默认插件目录")],
              returns="dict：{success, command, returncode, duration_ms, stdout_tail, "
                      "stderr_tail, timed_out, json_lines}",
              risk="intrusive", module=_TOOL,
              notes="直调不做参数语义校验，适合已适配插件之外的新工具；"
                    "仅可用于已授权目标。"),
]


GROUP = Group(
    name="cn_plugin",
    title="第三方插件：发现 / 体检 / 环境检测 / 受控直调",
    summary=("统一管理 mcp/plugins 下的第三方工具：列出已发现插件、查看详情、"
             "跑版本体检、检测运行环境（打包版独立解释器等），"
             "以及以「参数数组 + 隔离 stdin + 超时上限」的方式受控直调。"),
    ops=OPS,
    guide=("插件调用永不经过 shell；stdin 默认 DEVNULL（stdio 模式下父进程 stdin 是 "
           "MCP 协议通道）。专用适配工具组：cn_sqlmap / cn_trufflehog / "
           "cn_oneforall / cn_flaskcookie / cn_filesensor。"),
)
