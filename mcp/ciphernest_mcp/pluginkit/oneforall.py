# -*- coding: utf-8 -*-
"""cn_oneforall —— OneForAll 二次封装工具组。

OneForAll（``mcp/plugins/OneForAll/oneforall.py``）是子域名收集器，CLI 由
``fire`` 驱动：

    python oneforall.py --target example.com [--alive=False] ... run
    python oneforall.py version
    python oneforall.py check

结果导出到插件目录 ``results/<域名>.<fmt>``（csv / json）。适配器在 ``run``
结束后自动定位导出文件并解析成结构化子域名列表。
"""

from __future__ import annotations

import csv
import json
import re
import time
from pathlib import Path
from typing import Any

from ..contract import (Ctx, Group, arr, custom_op, flag, num, txt)
from ..envelope import ToolError
from .runtime import first_line, get_plugin, plugin_result, run_plugin
from ._paths import rel

_KEY = "oneforall"
_TOOL = "cn_oneforall"
_VERSION_RE = re.compile(r"v(\d+\.\d+\.\d+)")
_FORMATS = ("csv", "json")


def _results_dir() -> Path:
    return get_plugin(_KEY).cwd / "results"


def _newest_result(target: str, fmt: str) -> Path | None:
    """在 results/ 里找最新的、名字里带目标域名的结果文件。"""
    directory = _results_dir()
    if not directory.is_dir():
        return None
    main = target.lower()
    for prefix in ("http://", "https://", "www."):
        main = main.replace(prefix, "")
    main = main.split("/")[0]
    candidates = [path for path in directory.glob(f"*.{fmt}") if path.is_file()]
    preferred = [path for path in candidates if main in path.stem.lower()]
    pool = preferred or candidates
    if not pool:
        return None
    return max(pool, key=lambda path: path.stat().st_mtime)


def _read_rows(path: Path, limit: int) -> tuple[list[dict[str, Any]], int]:
    if path.suffix.lower() == ".json":
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        rows = data if isinstance(data, list) else [data]
        return [dict(item) for item in rows[:limit] if isinstance(item, dict)], len(rows)
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            if len(rows) >= limit:
                break
            rows.append(dict(row))
        total = len(rows)
        for _ in reader:  # 统计真实总数
            total += 1
    return rows, total


def _version(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    plugin = get_plugin(_KEY)
    run = run_plugin(plugin, ["version"], timeout=120)
    match = _VERSION_RE.search(run.stdout) or _VERSION_RE.search(run.stderr)
    return plugin_result(run, plugin, {
        "version": match.group(1) if match else first_line(run.stdout),
        "banner_tail": run.stdout.strip()[-300:],
    })


def _check(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    plugin = get_plugin(_KEY)
    run = run_plugin(plugin, ["check"], timeout=180)
    return plugin_result(run, plugin, {
        "note": "check 会联网比对最新版本；离线环境失败属正常。",
    })


def _run(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    target = str(a["target"] or "").strip()
    if not target:
        raise ToolError("missing_param", "缺少必填参数 target（域名）", field="target")
    plugin = get_plugin(_KEY)
    args: list[str] = ["--target", target]
    for name in ("alive", "brute", "dns", "req"):
        value = a[name]
        if value is not None:
            args.append(f"--{name}={str(bool(value)).lower()}")
    if a["port"]:
        args += ["--port", a["port"]]
    if a["fmt"] and a["fmt"] != "csv":
        args += ["--fmt", a["fmt"]]
    if a["takeover"]:
        args.append("--takeover=True")
    if a["extra_args"]:
        args += list(a["extra_args"])
    args.append("run")

    run = run_plugin(plugin, args, timeout=a["max_seconds"])
    extras: dict[str, Any] = {"args": args, "target": target}
    result_path = _newest_result(target, a["fmt"] or "csv")
    if result_path is not None:
        extras["result_file"] = str(result_path)
        extras["result_file_rel"] = rel(result_path)
        try:
            rows, total = _read_rows(result_path, a["max_rows"])
            extras["subdomain_count"] = total
            extras["subdomains"] = rows
            extras["subdomains_truncated"] = total > len(rows)
        except (OSError, json.JSONDecodeError, csv.Error) as exc:
            extras["parse_error"] = f"{type(exc).__name__}: {exc}"
    else:
        extras["result_file"] = None
        extras["note"] = (f"未在 {_results_dir()} 找到本次结果文件；"
                          "看 stdout_tail 里的导出路径日志")
    return plugin_result(run, plugin, extras)


def _list_results(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    plugin = get_plugin(_KEY)
    directory = _results_dir()
    if not directory.is_dir():
        return {"plugin": _KEY, "results_dir": str(directory), "count": 0,
                "files": []}
    files = []
    for path in sorted(directory.iterdir()):
        if not path.is_file():
            continue
        stat = path.stat()
        files.append({
            "name": path.name,
            "rel": rel(path),
            "size": stat.st_size,
            "modified": time.strftime("%Y-%m-%d %H:%M:%S",
                                      time.localtime(stat.st_mtime)),
        })
    files.sort(key=lambda item: item["modified"], reverse=True)
    return {"plugin": _KEY, "results_dir": str(directory),
            "count": len(files), "files": files[:100]}


OPS = [
    custom_op("version", _version, "查看 OneForAll 版本。", [],
              returns="dict：{success, version, banner_tail}", risk="safe",
              module="plugins/OneForAll"),
    custom_op("check", _check, "联网检查 OneForAll 是否有新版本（离线会失败）。",
              [], returns="dict：{success, stdout_tail}", risk="network",
              module="plugins/OneForAll"),
    custom_op("run", _run,
              "执行子域名收集（oneforall.py --target <域名> ... run），"
              "结束后自动解析 results/ 下的导出文件。",
              [txt("target", required=True, desc="目标域名，如 example.com"),
               flag("alive", default=None,
                    desc="只保留存活子域名；留空用工具默认（不传该参数）"),
               flag("brute", default=None,
                    desc="是否启用爆破；留空用工具默认。建议先关掉再按需开"),
               flag("dns", default=None, desc="是否做 DNS 解析；留空用工具默认"),
               flag("req", default=None, desc="是否做 HTTP 探活；留空用工具默认"),
               txt("port", default="", desc="端口探测规模：small / medium / large；留空不探测"),
               txt("fmt", default="csv", desc="导出格式", choices=_FORMATS),
               flag("takeover", default=False, desc="是否做子域名接管检测"),
               num("max_rows", default=100, desc="最多返回多少条子域名记录",
                   minimum=1, maximum=1000),
               num("max_seconds", default=900, desc="最长运行秒数", minimum=10,
                   maximum=7200),
               arr("extra_args", default=None, desc="追加原生参数（高级用法）")],
              returns="dict：{success, subdomain_count, subdomains: [...], "
                      "result_file_rel, stdout_tail}",
              risk="intrusive", module="plugins/OneForAll",
              notes="完整收集可能跑很久（默认 15 分钟上限）；先关 brute 再开，"
                    "结果文件在插件目录 results/ 下。"),
    custom_op("list_results", _list_results,
              "列出 OneForAll 历史导出文件（本地，不联网）。",
              [], returns="dict：{count, results_dir, files: [...]}", risk="read",
              module="plugins/OneForAll"),
]


GROUP = Group(
    name=_TOOL,
    title="OneForAll：子域名收集",
    summary=("OneForAll 二次封装：跑子域名收集并自动解析导出结果（csv/json），"
             "支持存活/爆破/DNS/HTTP/端口/接管等开关，也能列历史结果。"),
    ops=OPS,
    guide=("默认带 15 分钟上限；爆破（brute=true）很慢，建议先关。"
           "结果落在 plugins/OneForAll/results/，run 会把记录解析成 subdomains。"),
)
