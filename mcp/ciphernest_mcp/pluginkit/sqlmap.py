# -*- coding: utf-8 -*-
"""cn_sqlmap —— sqlmap 二次封装工具组。

把 ``mcp/plugins/sqlmap-master/sqlmap.py`` 的常用动作封装成语义化 op：
``scan``（注入探测）、``dbs`` / ``tables`` / ``columns`` / ``dump``（逐级取数）、
``tamper_list``（本地枚举 tamper 脚本）、``version``。

约定
----
- 一律带 ``--batch --disable-coloring``，避免交互式提问卡住；
- 每次调用都落到独立输出目录 ``output/sqlmap/<slug>-<时间>/``，便于回看日志；
- 返回里除 ``stdout_tail`` 外，还解析出 ``vulnerable / dbms / payload / databases /
  tables`` 等结构字段；``success`` 依据进程退出码；
- 插件必须读 stdin 时也不会吞掉 MCP 协议帧（runtime 已隔离 stdin）。
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any

from ..bootstrap import PROJECT_ROOT
from ..contract import (Ctx, Group, arr, custom_op, flag, flt, num, txt)
from .runtime import (RunResult, get_plugin, plugin_result, run_plugin,
                      first_line)

_KEY = "sqlmap"
_TOOL = "cn_sqlmap"
_TECHNIQUES = ("B", "E", "U", "S", "T", "Q")

_MARKER_DATABASES = re.compile(r"available databases \[\d+\]:")
_MARKER_DATABASE = re.compile(r"^Database:\s*(.+)$")


# ---------------------------------------------------------------------------
# 参数拼装
# ---------------------------------------------------------------------------
def _output_dir(slug: str) -> Path:
    safe = re.sub(r"[^0-9A-Za-z._-]+", "_", slug).strip("_")[:60] or "target"
    stamp = time.strftime("%Y%m%d-%H%M%S")
    return PROJECT_ROOT / "output" / "sqlmap" / f"{safe}-{stamp}"


def _common(a: dict[str, Any], out_dir: Path) -> list[str]:
    args = ["-u", a["url"], "--batch", "--disable-coloring",
            "--output-dir", str(out_dir)]
    if a["level"] is not None:
        args += ["--level", str(a["level"])]
    if a["risk"] is not None:
        args += ["--risk", str(a["risk"])]
    if a["dbms"]:
        args += ["--dbms", a["dbms"]]
    if a["technique"]:
        args += ["--technique", a["technique"].upper()]
    if a["tamper"]:
        args += ["--tamper", a["tamper"]]
    if a["threads"] is not None:
        args += ["--threads", str(a["threads"])]
    if a["http_timeout"] is not None:
        args += ["--timeout", str(a["http_timeout"])]
    if a["retries"] is not None:
        args += ["--retries", str(a["retries"])]
    if a["delay"]:
        args += ["--delay", str(a["delay"])]
    if a["data"]:
        args += ["--data", a["data"]]
    if a["cookie"]:
        args += ["--cookie", a["cookie"]]
    if a["headers"]:
        args += ["--headers", a["headers"]]
    if a["proxy"]:
        args += ["--proxy", a["proxy"]]
    if a["random_agent"]:
        args.append("--random-agent")
    if a["flush_session"]:
        args.append("--flush-session")
    if a["parse_errors"]:
        args.append("--parse-errors")
    if a["extra_args"]:
        args += list(a["extra_args"])
    return args


# ---------------------------------------------------------------------------
# 输出解析
# ---------------------------------------------------------------------------
def _items_after(text: str, marker: re.Pattern[str]) -> list[str]:
    """取 marker 之后连续的 ``[*] item`` 行。"""
    lines = text.splitlines()
    start = None
    for index, line in enumerate(lines):
        if marker.search(line):
            start = index + 1
    if start is None:
        return []
    items: list[str] = []
    for line in lines[start:]:
        stripped = line.strip()
        if stripped.startswith("[*]"):
            items.append(stripped[3:].strip())
            continue
        if not stripped:
            continue
        break
    return items


def _analyze(text: str) -> dict[str, Any]:
    info: dict[str, Any] = {}
    dbms = re.search(r"back-end DBMS:\s*(.+)", text)
    if dbms:
        info["dbms"] = dbms.group(1).strip()
    payloads = re.findall(r"Payload:\s*(.+)", text)
    if payloads:
        info["payload"] = payloads[-1].strip()[:300]
    critical = re.findall(r"\[CRITICAL\]\s*(.+)", text)
    if critical:
        info["critical"] = critical[-1].strip()[:300]
    lowered = text.lower()
    if "is vulnerable" in lowered or "appears to be injectable" in lowered:
        info["vulnerable"] = True
    elif ("does not seem to be injectable" in lowered
          or "not injectable" in lowered
          or "all tested parameters do not appear to be injectable" in lowered):
        info["vulnerable"] = False
    databases = _items_after(text, _MARKER_DATABASES)
    if databases:
        info["databases"] = databases
    current_db = None
    for line in text.splitlines():
        match = _MARKER_DATABASE.match(line.strip())
        if match:
            current_db = match.group(1).strip()
    tables = [item for item in _items_after(text, _MARKER_DATABASE)]
    if tables:
        info["tables"] = tables
    if current_db:
        info["database"] = current_db
    return info


def _invoke(a: dict[str, Any], args: list[str], *,
            out_dir: Path) -> dict[str, Any]:
    plugin = get_plugin(_KEY)
    run: RunResult = run_plugin(plugin, args, timeout=a["max_seconds"])
    extras: dict[str, Any] = {
        "args": args,
        "output_dir": str(out_dir),
        "output_dir_rel": _rel(out_dir),
    }
    if args == ["--version"]:
        extras["version"] = first_line(run.stdout)
    info = _analyze(run.stdout)
    extras.update(info)
    payload = plugin_result(run, plugin, extras)
    # sqlmap 对「连不上目标」等致命问题仍返回 0，需要按 [CRITICAL] 纠正 success
    if info.get("critical"):
        payload["success"] = False
        payload["error"] = {"code": "plugin_critical",
                            "message": info["critical"],
                            "hint": "检查 URL 可达性 / 代理 / 目标是否存活"}
    return payload


def _rel(path: Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(PROJECT_ROOT))
    except (ValueError, OSError):
        return str(path)


def _slug(url: str) -> str:
    return re.sub(r"^[a-z]+://", "", url, flags=re.I).split("/")[0]


# ---------------------------------------------------------------------------
# handlers
# ---------------------------------------------------------------------------
def _version(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    plugin = get_plugin(_KEY)
    run = run_plugin(plugin, ["--version"], timeout=120)
    # sqlmap 的 --version 会附带更新提示与「Press Enter」噪声，这里只留版本行
    clean = [line for line in run.stdout.splitlines()
             if line.strip() and "Press Enter" not in line
             and "[ERROR]" not in line]
    return plugin_result(run, plugin, {
        "version": clean[0].strip() if clean else first_line(run.stdout),
        "banner_tail": "\n".join(clean[-3:]),
    })


def _scan(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    out_dir = _output_dir(_slug(a["url"]))
    args = _common(a, out_dir)
    payload = _invoke(a, args, out_dir=out_dir)
    payload.setdefault("vulnerable", None)
    return payload


def _dbs(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    out_dir = _output_dir(_slug(a["url"]))
    args = _common(a, out_dir) + ["--dbs"]
    return _invoke(a, args, out_dir=out_dir)


def _tables(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    if not a["db"]:
        from ..envelope import ToolError
        raise ToolError("missing_param", "枚举表必须提供 db", field="db")
    out_dir = _output_dir(_slug(a["url"]))
    args = _common(a, out_dir) + ["-D", a["db"], "--tables"]
    return _invoke(a, args, out_dir=out_dir)


def _columns(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    from ..envelope import ToolError
    if not a["db"] or not a["table"]:
        raise ToolError("missing_param", "枚举列必须同时提供 db 与 table", field="table")
    out_dir = _output_dir(_slug(a["url"]))
    args = _common(a, out_dir) + ["-D", a["db"], "-T", a["table"], "--columns"]
    return _invoke(a, args, out_dir=out_dir)


def _dump(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    from ..envelope import ToolError
    if not a["db"]:
        raise ToolError("missing_param", "dump 至少需要 db；表级 dump 再给 table",
                        field="db")
    fmt = str(a["dump_format"] or "csv").strip().upper()
    if fmt not in ("CSV", "HTML", "SQLITE"):
        raise ToolError("range_error", f"不支持的导出格式：{fmt}（CSV / HTML / SQLITE）",
                        field="dump_format")
    out_dir = _output_dir(_slug(a["url"]))
    args = _common(a, out_dir) + ["-D", a["db"]]
    if a["table"]:
        args += ["-T", a["table"]]
    if a["columns"]:
        args += ["-C", a["columns"]]
    if fmt != "CSV":
        args += ["--dump-format", fmt]
    args.append("--dump")
    payload = _invoke(a, args, out_dir=out_dir)
    payload["csv_files"] = _csv_files(out_dir)
    return payload


def _csv_files(out_dir: Path) -> list[str]:
    try:
        return [ _rel(path) for path in sorted(out_dir.glob("*.csv"))
                 if path.is_file() ]
    except OSError:
        return []


def _tamper_list(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    plugin = get_plugin(_KEY)
    directory = plugin.cwd / "tamper"
    if not directory.is_dir():
        from ..envelope import ToolError
        raise ToolError("unsupported", f"tamper 目录不存在：{directory}",
                        hint="确认 sqlmap 插件目录完整")
    scripts = sorted(path.stem for path in directory.glob("*.py")
                     if path.stem != "__init__")
    keyword = str(a["keyword"] or "").strip().lower()
    if keyword:
        scripts = [name for name in scripts if keyword in name.lower()]
    return {"count": len(scripts), "tamper_dir": str(directory),
            "scripts": scripts,
            "usage": "--tamper 参数支持逗号分隔多个，如 "
                     "space2comment,between"}


OPS = [
    custom_op("version", _version, "查看 sqlmap 版本。", [],
              returns="dict：{success, version, banner_tail}", risk="safe",
              module="plugins/sqlmap-master"),
    custom_op("scan", _scan,
              "SQL 注入探测（等价 sqlmap -u URL --batch）：默认只做检测，不取数据。",
              [txt("url", required=True, desc="目标 URL（含参数才可能注入）"),
               num("level", default=None, desc="探测等级 1~5（越大越全也越慢）",
                   minimum=1, maximum=5),
               num("risk", default=None, desc="风险等级 1~3（3 会尝试 OR 型 payload）",
                   minimum=1, maximum=3),
               txt("dbms", desc="指定后端数据库（mysql / mssql / postgresql / oracle …）"),
               txt("technique", desc="注入技术：B/E/U/S/T/Q 可组合，如 BEU",
                   choices=_TECHNIQUES),
               txt("tamper", desc="tamper 脚本（逗号分隔），先用 tamper_list 查名字"),
               num("threads", default=None, desc="并发线程 1~10", minimum=1, maximum=10),
               num("http_timeout", default=None, desc="单请求超时（秒）", minimum=1),
               num("retries", default=None, desc="请求重试次数", minimum=0),
               flt("delay", default=0.0, desc="每次请求间隔（秒）", minimum=0),
               txt("data", desc="POST 数据（如 ``id=1&name=x``）"),
               txt("cookie", desc="Cookie 头"),
               txt("headers", desc="额外请求头，多个用换行分隔"),
               txt("proxy", desc="代理地址，如 socks5://127.0.0.1:1080"),
               flag("random_agent", default=False, desc="随机 User-Agent"),
               flag("flush_session", default=False, desc="清空历史会话后重扫"),
               flag("parse_errors", default=False, desc="解析并显示 DBMS 报错"),
               arr("extra_args", default=None, desc="追加原生参数（高级用法）"),
               num("max_seconds", default=300, desc="最长运行秒数", minimum=5,
                   maximum=3600)],
              returns="dict：{success, vulnerable, dbms, payload, stdout_tail, "
                      "output_dir, returncode}",
              risk="intrusive", module="plugins/sqlmap-master",
              notes="仅可用于已授权目标；默认只检测，取数请用 dbs/tables/columns/dump。"),
    custom_op("dbs", _dbs, "枚举数据库名（sqlmap --dbs）。",
              [txt("url", required=True, desc="目标 URL"),
               num("level", default=None, desc="探测等级 1~5", minimum=1, maximum=5),
               num("risk", default=None, desc="风险等级 1~3", minimum=1, maximum=3),
               txt("dbms", desc="指定后端数据库"), txt("tamper", desc="tamper 脚本"),
               txt("cookie", desc="Cookie 头"), txt("data", desc="POST 数据"),
               txt("proxy", desc="代理地址"),
               arr("extra_args", default=None, desc="追加原生参数"),
               num("max_seconds", default=300, desc="最长运行秒数", minimum=5,
                   maximum=3600)],
              returns="dict：{success, databases: [...], stdout_tail, output_dir}",
              risk="intrusive", module="plugins/sqlmap-master"),
    custom_op("tables", _tables, "枚举指定库的表（sqlmap -D db --tables）。",
              [txt("url", required=True, desc="目标 URL"),
               txt("db", required=True, desc="数据库名"),
               num("level", default=None, desc="探测等级 1~5", minimum=1, maximum=5),
               num("risk", default=None, desc="风险等级 1~3", minimum=1, maximum=3),
               txt("tamper", desc="tamper 脚本"), txt("cookie", desc="Cookie 头"),
               txt("proxy", desc="代理地址"),
               arr("extra_args", default=None, desc="追加原生参数"),
               num("max_seconds", default=300, desc="最长运行秒数", minimum=5,
                   maximum=3600)],
              returns="dict：{success, database, tables: [...], stdout_tail, output_dir}",
              risk="intrusive", module="plugins/sqlmap-master"),
    custom_op("columns", _columns, "枚举指定表的列（sqlmap -D db -T table --columns）。",
              [txt("url", required=True, desc="目标 URL"),
               txt("db", required=True, desc="数据库名"),
               txt("table", required=True, desc="表名"),
               num("level", default=None, desc="探测等级 1~5", minimum=1, maximum=5),
               num("risk", default=None, desc="风险等级 1~3", minimum=1, maximum=3),
               txt("tamper", desc="tamper 脚本"), txt("cookie", desc="Cookie 头"),
               txt("proxy", desc="代理地址"),
               arr("extra_args", default=None, desc="追加原生参数"),
               num("max_seconds", default=300, desc="最长运行秒数", minimum=5,
                   maximum=3600)],
              returns="dict：{success, database, tables/columns, stdout_tail, output_dir}",
              risk="intrusive", module="plugins/sqlmap-master"),
    custom_op("dump", _dump, "导出数据（sqlmap --dump）；表级需给 table，列级再给 columns。",
              [txt("url", required=True, desc="目标 URL"),
               txt("db", required=True, desc="数据库名"),
               txt("table", desc="表名（留空导整库）"),
               txt("columns", desc="列名，逗号分隔（留空导整表）"),
               txt("dump_format", default="csv", desc="导出格式（sqlmap 默认 CSV）"),
               txt("tamper", desc="tamper 脚本"), txt("cookie", desc="Cookie 头"),
               txt("proxy", desc="代理地址"),
               arr("extra_args", default=None, desc="追加原生参数"),
               num("max_seconds", default=600, desc="最长运行秒数", minimum=5,
                   maximum=3600)],
              returns="dict：{success, stdout_tail, csv_files, output_dir}",
              risk="intrusive", module="plugins/sqlmap-master",
              notes="导出的 CSV 落在 output_dir 内，csv_files 列出相对路径。"),
    custom_op("tamper_list", _tamper_list,
              "枚举 sqlmap 自带 tamper 脚本（本地文件，不联网、不启动 sqlmap）。",
              [txt("keyword", desc="按名字过滤（小写子串匹配）")],
              returns="dict：{count, scripts, tamper_dir, usage}", risk="read",
              module="plugins/sqlmap-master"),
]


GROUP = Group(
    name=_TOOL,
    title="sqlmap：SQL 注入检测与取数",
    summary=("sqlmap 二次封装：注入探测（scan）、逐级取数（dbs / tables / columns / "
             "dump）、tamper 脚本枚举、版本查询。每次调用独立输出目录，结果自动解析。"),
    ops=OPS,
    guide=("默认只做检测不取数；先用 scan 确认可注入，再逐级 dbs → tables → columns → dump。"
           "导出文件落在 output/sqlmap/<目标>-<时间>/。仅用于已授权目标。"),
)
