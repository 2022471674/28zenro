# -*- coding: utf-8 -*-
"""28zenro 命令行调度入口。

把桌面端工具以命令行方式拉起来跑、返回结果，用于脚本化、批量处理与 CI 集成。

与 GUI 的关系
-------------
- 只依赖纯逻辑层：``lib.*``（纯函数）+ ``app.registry`` / ``app.store``
  （均无 Qt 依赖），因此未安装 PySide6 的机器也能运行本入口；
- 启动时复用 :class:`app.store.SettingsStore` 读取 ``config.json``（含全局
  代理池配置与各 Web 工具的默认参数），保证 CLI 与 GUI 行为一致；
- Web 工具统一走 ``lib.proxy_pool``，与 GUI 共用「全局代理池」。

用法
----
    python cli.py list                          # 列出全部工具
    python cli.py webfuzz https://example.com   # Web Fuzz
    python cli.py dns example.com               # DNS 解析
    python cli.py ... --json                    # 结构化输出（供脚本/Agent）
    python cli.py ... --config <path>           # 指定 config.json（默认用户目录）

约定
----
- 子命令名与 ``app.registry.ToolSpec.id`` 一一对应，未来可自动化生成；
- 默认输出人类可读文本，加 ``--json`` 输出统一结构 ``{ok, tool, result|error}``；
- 业务失败（各 lib 的 ``*Error`` 异常）打印到 stderr 并返回非零退出码。
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path

# 保证 `python cli.py` 与 `python -m cli` 都能找到项目根下的 lib / app 包。
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ---------------------------------------------------------------------------
# 输出与配置
# ---------------------------------------------------------------------------
def _reconfigure_stdio() -> None:
    """强制 stdout/stderr 走 UTF-8，规避 Windows GBK 控制台中文乱码 / 崩溃。"""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def _load_config(path: str | None):
    """加载 SettingsStore 并应用全局代理池配置。

    返回 ``(store, proxy_cfg)``；无配置文件时用内置默认值，不报错。
    """
    from app.store import SettingsStore
    from lib import proxy_pool

    store = SettingsStore(Path(path) if path else None)
    proxy_cfg = store.get("proxy_pool", default={})
    proxy_pool.load_config(proxy_cfg)
    return store, proxy_cfg


# ---------------------------------------------------------------------------
# 通用输出辅助
# ---------------------------------------------------------------------------
def _emit_text(text: str) -> None:
    print(text)


def _emit_result(args, tool_id: str, result, *, text_fn=None):
    """统一输出：``--json`` 输出结构化结果，否则输出人类可读文本。

    ``result`` 为工具返回值（dict / list / dataclass / 基本类型）；
    ``text_fn`` 为可选的人类可读渲染函数（缺省时回退 ``to_text`` 或 repr）。
    """
    if getattr(args, "json", False):
        data = _to_serializable(result)
        payload = {"ok": True, "tool": tool_id, "result": data}
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return

    if text_fn is not None:
        text = text_fn(result)
    else:
        text = _render_text(result)
    _emit_text(text)


def _emit_error(args, tool_id: str, exc: Exception) -> int:
    """统一错误输出；返回退出码。"""
    msg = str(exc) or exc.__class__.__name__
    if getattr(args, "json", False):
        print(json.dumps(
            {"ok": False, "tool": tool_id, "error": msg},
            ensure_ascii=False, indent=2))
    else:
        print(f"[错误] {msg}", file=sys.stderr)
    return 1


def _to_serializable(value):
    """把结果递归转成可 JSON 序列化的纯数据（dataclass → dict）。"""
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {k: _to_serializable(v)
                for k, v in dataclasses.asdict(value).items()}
    if isinstance(value, dict):
        return {str(k): _to_serializable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_serializable(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _render_text(value, indent: int = 0) -> str:
    """兜底人类可读渲染：dict/list 排版，dataclass 转 dict。"""
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        value = dataclasses.asdict(value)
    if isinstance(value, dict):
        lines = []
        for k, v in value.items():
            if isinstance(v, (dict, list)) or dataclasses.is_dataclass(v):
                lines.append(" " * indent + f"{k}:")
                lines.append(_render_text(v, indent + 2))
            else:
                lines.append(" " * indent + f"{k}: {v}")
        return "\n".join(lines)
    if isinstance(value, (list, tuple)):
        lines = []
        for item in value:
            if isinstance(item, (dict, list)) or dataclasses.is_dataclass(item):
                lines.append(_render_text(item, indent))
            else:
                lines.append(" " * indent + f"- {item}")
        return "\n".join(lines)
    return " " * indent + str(value)


def _log_printer() -> callable:
    """把逐行日志直接打印到 stderr，避免污染 stdout 的结构化结果。"""
    def emit(msg: str) -> None:
        print(msg, file=sys.stderr)
    return emit


# ---------------------------------------------------------------------------
# 子命令：list
# ---------------------------------------------------------------------------
def cmd_list(args) -> int:
    from app import registry

    if args.json:
        rows = []
        for tool in registry.REGISTRY:
            rows.append({
                "id": tool.id,
                "name": tool.name,
                "category": tool.category,
                "category_label": tool.category_label,
                "kind": tool.kind,
                "cli": _tool_cli_name(tool.id),
                "description": tool.description,
            })
        print(json.dumps({"ok": True, "tool": "list", "result": rows},
                         ensure_ascii=False, indent=2))
        return 0

    # 表格化输出
    lines = []
    lines.append(f"{'命令':<16} {'名称':<14} {'分类':<12} 说明")
    lines.append("-" * 80)
    for tool in registry.REGISTRY:
        cli_name = _tool_cli_name(tool.id)
        note = "" if cli_name else "（仅 GUI）"
        lines.append(f"{cli_name or tool.id:<16} "
                     f"{tool.name:<14} {tool.category_label:<12} "
                     f"{tool.description}{note}")
    _emit_text("\n".join(lines))
    return 0


# ---------------------------------------------------------------------------
# Web 工具子命令注册表：id -> (函数, 参数解析器)
# ---------------------------------------------------------------------------
# 每个条目是 ``(tool_id, build_parser_func, run_func)``。
# build_parser 在子 parser 上追加参数；run_func 接收 args，返回结果。
_WEB_COMMANDS: dict[str, dict] = {}


def _register(tool_id: str):
    """装饰器：登记一个 Web 工具子命令的构建与执行函数。"""
    def deco(fn):
        _WEB_COMMANDS[tool_id] = fn
        return fn
    return deco


def _tool_cli_name(tool_id: str) -> str:
    """返回该工具 id 是否有对应 CLI 子命令（没有则返回空串）。"""
    return tool_id if tool_id in _WEB_COMMANDS else ""


# ---------------------------------------------------------------------------
# 各 Web 工具子命令实现
# ---------------------------------------------------------------------------
@_register("webfuzz")
def _cmd_webfuzz(parser: argparse.ArgumentParser):
    from lib import web_fuzz

    parser.add_argument("url", help="目标 URL（可省略协议头）")
    parser.add_argument("--timeout", type=float, default=web_fuzz.DEFAULT_TIMEOUT)
    parser.add_argument("--robots", action="store_true", help="顺带抓 robots.txt")
    parser.add_argument("--sitemap", action="store_true", help="顺带抓 sitemap.xml")
    parser.add_argument("--hostsearch", action="store_true",
                        help="查询历史收录（hackertarget）")
    parser.add_argument("--subdomain", action="store_true",
                        help="字典爆破子域名")
    parser.add_argument("--subdomain-dict", default=None, help="子域名字典路径")
    parser.add_argument("--subdomain-interval", type=float,
                        default=web_fuzz.DNS_DEFAULT_INTERVAL)
    parser.add_argument("--subdomain-proxy", action="store_true")

    def run(args, store):
        from lib import web_fuzz as wf
        return wf.run(
            args.url,
            timeout=args.timeout,
            with_robots=args.robots,
            with_sitemap=args.sitemap,
            with_hostsearch=args.hostsearch,
            with_subdomain_brute=args.subdomain,
            subdomain_dict=args.subdomain_dict,
            subdomain_interval=args.subdomain_interval,
            subdomain_use_proxy=args.subdomain_proxy,
            log=_log_printer(),
        )

    return run, web_fuzz.to_text


@_register("jsfinder")
def _cmd_jsfinder(parser: argparse.ArgumentParser):
    from lib import jsfinder

    parser.add_argument("url")
    parser.add_argument("--cookie", default="")
    parser.add_argument("--deep", action="store_true")
    parser.add_argument("--endpoint", action="store_true",
                        help="覆盖 JS 文件查询：提取 JS 里的 API 接口路径")
    parser.add_argument("--timeout", type=int, default=jsfinder.DEFAULT_TIMEOUT)
    parser.add_argument("--max-links", type=int, default=jsfinder.DEFAULT_MAX_LINKS)

    def run(args, store):
        from lib import jsfinder as jf
        urls, subdomains = jf.run(
            args.url, cookie=args.cookie, deep=args.deep,
            endpoint=args.endpoint,
            timeout=args.timeout, max_links=args.max_links,
            progress=_log_printer())
        return {"urls": urls, "subdomains": subdomains}

    return run, None


@_register("fingerprint")
def _cmd_fingerprint(parser: argparse.ArgumentParser):
    from lib import fingerprint

    parser.add_argument("url")
    parser.add_argument("--timeout", type=float, default=fingerprint.DEFAULT_TIMEOUT)
    parser.add_argument("--rules-dir", default=None, help="指纹规则目录（缺省用内置）")

    def run(args, store):
        from lib import fingerprint as fp
        rules = None
        if args.rules_dir:
            rules = fp.load_rules([args.rules_dir])
        return fp.run(args.url, timeout=args.timeout, rules=rules,
                      log=_log_printer())

    return run, fingerprint.to_text


@_register("dns")
def _cmd_dns(parser: argparse.ArgumentParser):
    from lib import dns_tool

    parser.add_argument("host")
    parser.add_argument("--proxy", action="store_true", help="走全局代理池 SOCKS5 远程 DNS")

    def run(args, store):
        from lib import dns_tool as dt
        return dt.resolve_dns(args.host, use_proxy=args.proxy)

    return run, None


@_register("subdomain")
def _cmd_subdomain(parser: argparse.ArgumentParser):
    from lib import dns_tool

    parser.add_argument("domain")
    parser.add_argument("--dict", dest="dict_path", default=None)
    parser.add_argument("--interval", type=float, default=dns_tool.DEFAULT_INTERVAL)
    parser.add_argument("--proxy", action="store_true")

    def run(args, store):
        from lib import dns_tool as dt
        results, note = dt.brute_subdomains(
            args.domain, dict_path=args.dict_path, interval=args.interval,
            use_proxy=args.proxy, log=_log_printer())
        return {"results": results, "note": note}

    return run, None


@_register("hostsearch")
def _cmd_hostsearch(parser: argparse.ArgumentParser):
    parser.add_argument("domain")

    def run(args, store):
        from lib import hostsearch
        return hostsearch.query_hostsearch(args.domain, log=_log_printer())

    return run, None


@_register("httpscan")
def _cmd_httpscan(parser: argparse.ArgumentParser):
    from lib import httpscan

    parser.add_argument("cidr", help="CIDR 网段或单个 IP")
    parser.add_argument("--threads", type=int, default=httpscan.DEFAULT_THREADS)
    parser.add_argument("--timeout", type=int, default=httpscan.DEFAULT_TIMEOUT)
    parser.add_argument("--https", action="store_true")

    def run(args, store):
        from lib import httpscan as hs
        return hs.run(args.cidr, threads=args.threads, timeout=args.timeout,
                      https=args.https, progress=_log_printer(),
                      found=lambda item: _log_printer()(f"[发现] {item.get('ip')}"))

    return run, None


@_register("dirscan")
def _cmd_dirscan(parser: argparse.ArgumentParser):
    from lib import dir_scan

    parser.add_argument("url")
    parser.add_argument("--dict-dir", default=None)
    parser.add_argument("--threads", type=int, default=dir_scan.DEFAULT_THREADS)
    parser.add_argument("--timeout", type=float, default=dir_scan.DEFAULT_TIMEOUT)
    parser.add_argument("--interval", type=float, default=dir_scan.DEFAULT_INTERVAL)
    parser.add_argument("--headers", default="")
    parser.add_argument("--out-dir", default=None)

    def run(args, store):
        from lib import dir_scan as ds
        return ds.scan(
            args.url, out_dir=args.out_dir, dict_dir=args.dict_dir,
            threads=args.threads, timeout=args.timeout, interval=args.interval,
            headers=args.headers, log=_log_printer(),
            on_hit=lambda h: _log_printer()(
                f"[命中] {h.get('status')}  {h.get('url')}"))

    return run, None


@_register("leakscan")
def _cmd_leakscan(parser: argparse.ArgumentParser):
    from lib import leak_scan

    parser.add_argument("domain")
    parser.add_argument("--kinds", nargs="*", default=None,
                        help="要检测的类型：git / svn / ds_store / files"
                             "（缺省全查）")
    parser.add_argument("--threads", type=int, default=leak_scan.DEFAULT_THREADS)
    parser.add_argument("--timeout", type=float, default=leak_scan.DEFAULT_TIMEOUT)
    parser.add_argument("--out-dir", default="output/leak")

    def run(args, store):
        from lib import leak_scan as ls
        return ls.run(args.domain, out_dir=args.out_dir, kinds=args.kinds,
                      threads=args.threads, timeout=args.timeout,
                      log=_log_printer())

    return run, None


@_register("paramfuzz")
def _cmd_paramfuzz(parser: argparse.ArgumentParser):
    from lib import param_fuzz

    parser.add_argument("url")
    parser.add_argument("--method", default="GET", choices=("GET", "POST", "JSON", "XML"))
    parser.add_argument("--wordlist", default=param_fuzz.DEFAULT_WORDLIST)
    parser.add_argument("--include", default="")
    parser.add_argument("--headers", default="")
    parser.add_argument("--timeout", type=float, default=param_fuzz.DEFAULT_TIMEOUT)
    parser.add_argument("--threads", type=int, default=param_fuzz.DEFAULT_THREADS)
    parser.add_argument("--chunks", type=int, default=param_fuzz.DEFAULT_CHUNKS)
    parser.add_argument("--delay", type=float, default=param_fuzz.DEFAULT_DELAY)
    parser.add_argument("--rate-limit", type=int, default=param_fuzz.DEFAULT_RATE_LIMIT)

    def run(args, store):
        from lib import param_fuzz as pf
        return pf.run(
            args.url, method=args.method, wordlist=args.wordlist,
            include=args.include, headers=args.headers, timeout=args.timeout,
            threads=args.threads, chunks=args.chunks, delay=args.delay,
            rate_limit=args.rate_limit, log=_log_printer())

    return run, param_fuzz.to_text


@_register("portscan")
def _cmd_portscan(parser: argparse.ArgumentParser):
    from lib import port_scan

    parser.add_argument("host")
    parser.add_argument("--ports", default="常见端口.txt",
                        help="端口来源：字典文件名 / 自定义文件 / 范围 1-1024,3306")
    parser.add_argument("--threads", type=int, default=port_scan.DEFAULT_THREADS)
    parser.add_argument("--timeout", type=float, default=port_scan.DEFAULT_TIMEOUT)
    parser.add_argument("--retries", type=int, default=port_scan.DEFAULT_RETRIES)
    parser.add_argument("--no-proxy", action="store_true", help="直连，不走代理池")
    parser.add_argument("--out-dir", default=None)

    def run(args, store):
        from lib import port_scan as ps

        # 解析端口来源
        ports = _resolve_ports(args.ports)

        pool = None
        if not args.no_proxy:
            pool = _build_proxy_pool()
            if pool is not None and len(pool) == 0:
                pool = None  # 池空则回退直连

        return ps.scan(
            args.host, ports, pool=pool, threads=args.threads,
            timeout=args.timeout, retries=args.retries,
            log=_log_printer(), on_hit=lambda r: _log_printer()(f"[开放] {r.label()}"),
            out_dir=args.out_dir)

    return run, None


@_register("ssti")
def _cmd_ssti(parser: argparse.ArgumentParser):
    from lib import ssti_finder

    parser.add_argument("url")
    parser.add_argument("param", help="注入参数名")
    parser.add_argument("--method", default="GET")
    parser.add_argument("--data", default="")
    parser.add_argument("--cookie", default="")
    parser.add_argument("--headers", default="")
    parser.add_argument("--proxy", default="")
    parser.add_argument("--prefix", default=ssti_finder.DEFAULT_PREFIX)
    parser.add_argument("--timeout", type=float, default=ssti_finder.DEFAULT_TIMEOUT)
    parser.add_argument("--enum-all", action="store_true")

    def run(args, store):
        from lib import ssti_finder as sf
        report = sf.run(
            args.url, args.param, method=args.method, data=args.data,
            cookie=args.cookie, headers=args.headers, proxy=args.proxy,
            prefix=args.prefix, timeout=args.timeout, enum_all=args.enum_all,
            progress=_log_printer())
        return report

    return run, None


@_register("wechat")
def _cmd_wechat(parser: argparse.ArgumentParser):
    parser.add_argument("pairs", nargs="+",
                        help="每组 AppID AppSecret（空格分隔），可多组")
    parser.add_argument("--timeout", type=float, default=15.0)

    def run(args, store):
        from lib import wechat_check as wc
        pairs = []
        # 每两个参数一组：appid secret
        it = iter(args.pairs)
        for appid in it:
            secret = next(it, "")
            pairs.append((appid, secret))
        return wc.check_many(pairs, timeout=args.timeout,
                             progress=_log_printer())

    return run, None


@_register("ping")
def _cmd_ping(parser: argparse.ArgumentParser):
    from lib import ping_probe

    parser.add_argument("host")
    parser.add_argument("--base-url", default=ping_probe.DEFAULT_BASE_URL)
    parser.add_argument("--api-id", default=ping_probe.DEFAULT_API_ID)
    parser.add_argument("--api-key", default=ping_probe.DEFAULT_API_KEY)
    parser.add_argument("--dy", default=ping_probe.DEFAULT_DY)
    parser.add_argument("--timeout", type=float, default=ping_probe.DEFAULT_TIMEOUT)
    parser.add_argument("--headers", default="")

    def run(args, store):
        from lib import ping_probe as pp
        extra = {}
        if args.headers:
            for line in args.headers.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    extra[k.strip()] = v.strip()
        return pp.run_ping(
            args.host, base_url=args.base_url, api_id=args.api_id,
            api_key=args.api_key, dy=args.dy, extra_headers=extra,
            timeout=args.timeout, progress=_log_printer())

    return run, None


# ---------------------------------------------------------------------------
# 端口解析 / 代理池辅助
# ---------------------------------------------------------------------------
def _resolve_ports(source: str) -> list[int]:
    """把 ``--ports`` 解析成端口列表：字典文件 / 范围 / 逗号分隔。"""
    from lib import port_scan as ps

    # 范围或逗号分隔
    if any(ch in source for ch in ",-\n") or source.isdigit():
        try:
            return ps.parse_ports(source)
        except Exception:
            pass

    # 字典文件：先在 dict/Ports 下找，再按路径找
    cand = ps.default_dict_dir() / source
    if cand.is_file():
        return list(ps.load_port_dict(cand).keys())

    path = Path(source)
    if path.is_file():
        return list(ps.load_port_dict(path).keys())

    # 回退：全部内置字典合并
    return list(ps.load_all_dicts().keys())


def _build_proxy_pool():
    """把全局代理池转成 port_scan 可用的 ProxyPool。

    未启用代理或池空时返回 None（表示直连），复用 ``proxy_pool`` 现成转换。
    """
    from lib import proxy_pool

    if not proxy_pool.is_enabled():
        return None
    return proxy_pool.to_port_scan_pool()


# ---------------------------------------------------------------------------
# 参数解析
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cli.py",
        description="28zenro 命令行调度入口",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--json", action="store_true",
                        help="输出结构化 JSON（供脚本 / Agent 消费）")
    parser.add_argument("--config", default=None,
                        help="config.json 路径（缺省用用户数据目录）")

    sub = parser.add_subparsers(dest="command", metavar="<命令>")

    # list
    p_list = sub.add_parser("list", help="列出全部工具")
    p_list.set_defaults(handler=cmd_list)

    # Web 工具
    for tool_id, build in _WEB_COMMANDS.items():
        p = sub.add_parser(tool_id, help=_describe(tool_id))
        run_fn, text_fn = build(p)
        p.set_defaults(_run_fn=run_fn, _text_fn=text_fn, _tool_id=tool_id)

    return parser


def _describe(tool_id: str) -> str:
    """取工具说明文案（优先 registry，其次内置映射）。"""
    try:
        from app import registry
        tool = registry.get_tool(tool_id)
        if tool is not None and tool.description:
            return tool.description
    except Exception:
        pass
    return ""


def main(argv: list[str] | None = None) -> int:
    _reconfigure_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "command", None):
        parser.print_help()
        return 1

    store, _ = _load_config(args.config)

    try:
        if args.command == "list":
            return cmd_list(args)
        result = args._run_fn(args, store)
        _emit_result(args, args._tool_id, result, text_fn=args._text_fn)
        return 0
    except KeyboardInterrupt:
        print("\n[中止] 用户中断", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001  统一错误出口
        return _emit_error(args, getattr(args, "_tool_id", args.command), exc)


if __name__ == "__main__":
    raise SystemExit(main())
