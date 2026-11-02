# -*- coding: utf-8 -*-
"""cn_scan —— 扫描 / 爆破 / 探活工具组。

覆盖 ``lib.dir_scan``（目录爆破）、``lib.port_scan``（端口扫描）、
``lib.param_fuzz``（参数 Fuzz）、``lib.leak_scan``（源码泄露检测）、
``lib.ping_probe``（多地 Ping）。

全部为**主动探测**类能力：请只对已授权目标使用。长任务建议先用小字典 / 小端口
范围试探，再放大参数。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from lib import dir_scan, leak_scan, param_fuzz, ping_probe, port_scan

from ..bootstrap import PROJECT_ROOT, init_proxy_pool
from ..contract import (Ctx, Group, arr, custom_op, flag, flt, make_op, num,
                        obj, txt)
from ..envelope import ToolError, to_jsonable
from ._helpers import rel, resolve_output_dir, section

_PARAM_METHODS = ("GET", "POST", "JSON", "XML")
_LEAK_KINDS = ("git", "svn", "ds_store", "files")

#: 内置端口字典文件名（``dict/Ports`` 下）。
_PORT_DICT_HINTS = ("常见端口.txt", "全端口1-1024.txt", "高危端口.txt")


# ---------------------------------------------------------------------------
# 端口解析：表达式 / 内置字典名 / 字典文件路径
# ---------------------------------------------------------------------------
def _ports_dir() -> Path:
    return PROJECT_ROOT / "dict" / "Ports"


def _resolve_ports(raw: Any) -> list[int]:
    text = str(raw or "").strip()
    if not text:
        raise ToolError("missing_param", "缺少必填参数 ports（端口表达式或字典名）",
                        field="ports")
    lowered = text.lower()
    if lowered in ("all", "全端口", "1-65535"):
        return list(range(1, 65536))
    candidates = [Path(text), _ports_dir() / text]
    if not Path(text).suffix:
        candidates.append(_ports_dir() / f"{text}.txt")
    for candidate in candidates:
        path = candidate if candidate.is_absolute() else PROJECT_ROOT / candidate
        if path.is_file():
            return sorted(port_scan.load_port_dict(path))
    if Path(text).suffix.lower() in (".txt", ".dict"):
        raise ToolError("io", f"端口字典文件不存在：{text}（查找目录 {_ports_dir()}）",
                        field="ports")
    ports = port_scan.parse_ports(text)
    if not ports:
        raise ToolError("invalid_param", f"ports 未解析出任何端口：{text!r}",
                        field="ports")
    return ports


# ---------------------------------------------------------------------------
# 自定义 handler
# ---------------------------------------------------------------------------
def _port_scan(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    ports = _resolve_ports(a["ports"])
    pool = None
    if a["use_proxy"]:
        init_proxy_pool()
        try:
            from lib import proxy_pool
            pool = proxy_pool.to_port_scan_pool()
        except Exception as exc:  # pragma: no cover - 池不可用时回退直连
            ctx.warn(f"代理池不可用，回退直连：{exc}")
            pool = None
    service_map = port_scan.load_all_dicts() if a["service_names"] else None
    out_dir = None
    if a["out_dir"]:
        out_dir = resolve_output_dir(
            a["out_dir"], section("port_scan").get("out_dir") or "output/portscan")
    result = port_scan.scan(
        a["host"], ports, pool=pool, threads=a["threads"], timeout=a["timeout"],
        retries=a["retries"], service_map=service_map, log=ctx.log,
        stop=ctx.stop, out_dir=out_dir, verify_proxies=a["verify_proxies"])
    payload = to_jsonable(result)
    if isinstance(payload, dict):
        payload.setdefault("ports_total", len(ports))
        payload.setdefault("proxy", bool(pool))
    return payload


def _leak_scan(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    out_dir = resolve_output_dir(
        a["out_dir"], section("leak_scan").get("output_dir") or "output/leak")
    kinds = list(a["kinds"]) if a["kinds"] else None
    results = leak_scan.run(a["target"], out_dir, kinds=kinds,
                            threads=a["threads"], timeout=a["timeout"],
                            log=ctx.log, stop=ctx.stop)
    return {"target": a["target"], "out_dir": str(out_dir), "count": len(results),
            "results": to_jsonable(results)}


def _parse_headers(text: str) -> dict[str, str] | None:
    pairs: dict[str, str] = {}
    for line in str(text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, _, value = line.partition(":")
        pairs[key.strip()] = value.strip()
    return pairs or None


def _ping_conf() -> dict[str, Any]:
    return section("ping_probe")


def _ping(a: dict[str, Any], ctx: Ctx) -> Any:
    conf = _ping_conf()
    report = ping_probe.run_ping(
        a["host"],
        base_url=a["base_url"] or conf.get("base_url") or "",
        api_id=a["api_id"] or conf.get("api_id") or "",
        api_key=a["api_key"] or conf.get("api_key") or "",
        dy=a["dy"] or conf.get("dy") or "0",
        extra_headers=_parse_headers(a["headers"]),
        timeout=a["timeout"], progress=ctx.log, stop=ctx.stop)
    return to_jsonable(report)


def _ping_batch(a: dict[str, Any], ctx: Ctx) -> Any:
    conf = _ping_conf()
    reports = ping_probe.run_ping_batch(
        a["hosts"],
        base_url=a["base_url"] or conf.get("base_url") or "",
        api_id=a["api_id"] or conf.get("api_id") or "",
        api_key=a["api_key"] or conf.get("api_key") or "",
        dy=a["dy"] or conf.get("dy") or "0",
        extra_headers=_parse_headers(a["headers"]),
        timeout=a["timeout"], progress=ctx.log, stop=ctx.stop)
    return to_jsonable(reports)


OPS = [
    # ------------------------------------------------------------ 目录爆破
    make_op(dir_scan.scan,
            "目录爆破：按字典逐条探测目标路径（合并 ``dict/Contents`` 全部字典）。",
            [txt("target", required=True, desc="目标 URL"),
             txt("out_dir", default=None, desc="结果输出目录；留空不落盘"),
             txt("dict_dir", default=None, desc="字典目录；留空用 ``dict/Contents``"),
             arr("words", default=None, desc="自定义词条列表（给了就不再读字典）"),
             num("threads", default=16, desc="并发线程数", minimum=1, maximum=200),
             flt("timeout", default=6.0, desc="单请求超时（秒）", minimum=1),
             flt("interval", default=30.0, desc="每轮之间的间隔（秒）", minimum=0),
             txt("headers", desc="自定义请求头，多行 ``Key: Value``")],
            returns="dict：{target, hits: [{url, status, length, ...}], requests, elapsed, ...}",
            risk="intrusive", notes="耗时工具；建议先用小字典 + 短超时试探。"),
    make_op(dir_scan.list_dict_files, "列出字典目录下的全部字典文件。",
            [txt("dict_dir", default=None, desc="字典目录；留空用 ``dict/Contents``")],
            returns="list[str]：字典文件路径", risk="read"),
    make_op(dir_scan.load_words, "读取字典目录下全部字典，合并去重。",
            [txt("dict_dir", default=None, desc="字典目录；留空用内置目录"),
             arr("files", default=None, desc="只读指定文件列表")],
            returns="dict：{words, files: [[文件名, 词条数], …]}",
            unpack=("words", "files"), risk="read"),
    make_op(dir_scan.default_dict_dir, "返回内置目录字典的绝对路径。", [],
            returns="str：字典目录路径", risk="safe"),

    # ------------------------------------------------------------ 端口扫描
    custom_op("port_scan", _port_scan,
              "端口扫描：端口来源支持表达式（``80,443,1-1024``）、内置字典名"
              "（``常见端口.txt`` / ``全端口1-1024.txt`` / ``高危端口.txt``）或字典文件路径。",
              [txt("host", required=True, desc="目标主机（IP 或域名）"),
               txt("ports", default="常见端口.txt",
                   desc="端口表达式 / 字典名 / 字典路径；all 表示 1-65535"),
               num("threads", default=24, desc="并发线程数", minimum=1, maximum=256),
               flt("timeout", default=6.0, desc="单端口超时（秒）", minimum=0.5),
               num("retries", default=3, desc="失败重试次数", minimum=1, maximum=10),
               flag("use_proxy", default=False, desc="是否轮换全局代理池"),
               flag("service_names", default=True, desc="是否用字典补充服务名"),
               flag("verify_proxies", default=True, desc="扫描前先验证代理可用性"),
               txt("out_dir", default=None, desc="结果输出目录；留空不落盘")],
              returns="dict：{host, open: [{port, service, banner, ms}], ...}",
              risk="intrusive", module="lib.port_scan"),
    make_op(port_scan.parse_ports, "解析端口表达式（``80`` / ``80,443`` / ``1-1024`` / 空格换行分隔）。",
            [txt("text", required=True, desc="端口表达式"),
             num("limit", default=65536, desc="最多返回多少个端口", minimum=1)],
            returns="list[int]：端口列表", risk="safe"),
    make_op(port_scan.load_all_dicts, "合并端口字典目录下全部字典为 ``{端口: 服务名}``。",
            [txt("directory", default=None, desc="字典目录；留空用内置 ``dict/Ports``")],
            returns="dict：{端口: 服务名}", risk="read"),

    # ------------------------------------------------------------ 参数 Fuzz
    make_op(param_fuzz.run,
            "参数发现：对目标接口做参数爆破（GET / POST / JSON / XML）。",
            [txt("target", required=True, desc="目标 URL"),
             txt("method", default="GET", desc="请求方法", choices=_PARAM_METHODS),
             txt("wordlist", default="small", desc="字典名（small / medium / large）或文件路径"),
             txt("include", desc="每次请求固定携带的负载；JSON/XML 可用 ``$arjun$`` 占位"),
             txt("headers", desc="自定义请求头，多行 ``Key: Value``"),
             flt("timeout", default=15.0, desc="单请求超时（秒）", minimum=1),
             num("threads", default=5, desc="并发线程数", minimum=1, maximum=50),
             num("chunks", default=250, desc="每组参数数量", minimum=1),
             flt("delay", default=0.0, desc="每次请求间隔（秒）", minimum=0),
             num("rate_limit", default=0, desc="每秒最大请求数（0 = 不限速）", minimum=0)],
            returns="dict：{target, method, found_params, total_requests, elapsed, ...}",
            risk="intrusive"),
    make_op(param_fuzz.to_text, "把参数 Fuzz 结果渲染为纯文本报告。",
            [obj("result", required=True, desc="param_fuzz.run 的返回 dict")],
            returns="str：文本报告", risk="safe"),

    # ------------------------------------------------------- 源码泄露检测
    custom_op("leak_scan", _leak_scan,
              "源码泄露检测：探测 ``.git`` / ``.svn`` / ``.DS_Store`` 是否可访问并"
              "尝试还原；另一类 ``files`` 按静态清单并发探测敏感文件（vim "
              "``.swp`` / ``~`` / ``.bak`` 备份、``.env``、``.hg`` / ``.bzr``、"
              "整站打包、SQL 转储、Actuator / Druid 等），只报告不还原。",
              [txt("target", required=True, desc="目标域名或 URL"),
               arr("kinds", default=None,
                   desc="检测类型子集（git / svn / ds_store / files），留空全查"),
               num("threads", default=8, desc="并发线程数", minimum=1, maximum=100),
               flt("timeout", default=8.0, desc="请求超时（秒）", minimum=1),
               txt("out_dir", default=None, desc="输出目录；留空用配置 output/leak")],
              returns="dict：{target, out_dir, count, results: [...]}", risk="intrusive",
              module="lib.leak_scan"),
    make_op(leak_scan.normalize_target, "规范化目标：缺协议自动补 ``http://``。",
            [txt("raw", required=True, desc="域名或 URL")],
            returns="str：规范化后的 URL", risk="safe"),

    # ------------------------------------------------------------ 多地 Ping
    custom_op("ping", _ping,
              "多地 Ping：通过接口盒子 API 从多节点探测延迟与解析结果。",
              [txt("host", required=True, desc="目标域名或 IP"),
               txt("base_url", desc="API 地址；留空用配置值"),
               txt("api_id", desc="API 用户 ID；留空用配置值"),
               txt("api_key", desc="API 通讯密钥；留空用配置值"),
               txt("dy", desc="dy 参数（0 = 默认线路）"),
               txt("headers", desc="自定义请求头，多行 ``Key: Value``"),
               flt("timeout", default=30.0, desc="请求超时（秒）", minimum=1)],
              returns="dict：{host, nodes: [{node, ip, ms, ...}], error}",
              risk="network", module="lib.ping_probe"),
    custom_op("ping_batch", _ping_batch, "批量多地 Ping（顺序执行）。",
              [arr("hosts", required=True, desc="目标列表"),
               txt("base_url", desc="API 地址；留空用配置值"),
               txt("api_id", desc="API 用户 ID；留空用配置值"),
               txt("api_key", desc="API 通讯密钥；留空用配置值"),
               txt("dy", desc="dy 参数"),
               txt("headers", desc="自定义请求头，多行 ``Key: Value``"),
               flt("timeout", default=30.0, desc="单目标超时（秒）", minimum=1)],
              returns="list[dict]：每个目标的 Ping 报告", risk="network",
              module="lib.ping_probe"),
]


GROUP = Group(
    name="cn_scan",
    title="扫描：目录 / 端口 / 参数 / 泄露 / 多地 Ping",
    summary=("目录爆破；端口扫描（表达式 / 字典 / 代理轮换）；参数发现 Fuzz；"
             ".git/.svn/.DS_Store 源码泄露检测；多地 Ping 探活。"),
    ops=OPS,
    guide=("全部为主动探测能力，仅用于已授权目标。耗时 op 请先小范围试探："
           "目录爆破用小字典、端口扫描用常见端口、参数 Fuzz 用 small 字典。"),
)
