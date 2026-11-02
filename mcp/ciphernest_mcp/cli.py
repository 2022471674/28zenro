# -*- coding: utf-8 -*-
"""命令行入口实现（被 ``mcp/server.py`` 与 ``python -m ciphernest_mcp`` 共用）。

只读命令直接打印到 stdout；服务模式下 stdout 交给 MCP stdio 传输，
本模块的进度日志一律走 stderr（``bootstrap.log``）。
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .bootstrap import init_proxy_pool, log, settings
from .contract import audit, find_op
from .ops import GROUPS, IMPORT_ERRORS, total_ops

EPILOG = """\
示例：
  python mcp/server.py                       # stdio
  python mcp/server.py --http --port 9000    # streamable-http
  python mcp/server.py --list                # 工具与 op 清单
  python mcp/server.py --show base64_encrypt # 单个 op 契约
  python mcp/server.py --selftest            # 自检
  python mcp/server.py --gen-docs            # 生成 mcp/CONTRACT.md
"""


def _safe_stdio() -> None:
    """把 CLI 的 stdout/stderr 切到 UTF-8，避免 Windows GBK 控制台打印中文崩掉。

    只影响文本层；MCP stdio 传输会自己包装 ``sys.stdout.buffer``，不受影响。
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # pragma: no cover - 非 TextIOWrapper 时跳过
            pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ciphernest-mcp",
        description="cipherNest MCP 服务器（基于项目 lib/ 的全部方法）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EPILOG,
    )
    parser.add_argument("--transport", choices=("stdio", "sse", "streamable-http"),
                        default="stdio", help="传输方式（默认 stdio）")
    parser.add_argument("--http", action="store_true",
                        help="等价于 --transport streamable-http")
    parser.add_argument("--host", default="127.0.0.1", help="HTTP 监听地址")
    parser.add_argument("--port", type=int, default=8000, help="HTTP 监听端口")
    parser.add_argument("--debug", action="store_true", help="打开 DEBUG 日志")

    parser.add_argument("--list", action="store_true", help="打印工具与 op 清单后退出")
    parser.add_argument("--json", action="store_true", help="配合 --list 输出 JSON")
    parser.add_argument("--show", metavar="OP", help="打印单个 op 的契约后退出")
    parser.add_argument("--audit", action="store_true", help="契约审计后退出")
    parser.add_argument("--selftest", action="store_true", help="自检（审计 + 冒烟）后退出")
    parser.add_argument("--gen-docs", nargs="?", const="CONTRACT.md", metavar="PATH",
                        help="生成 CONTRACT.md（默认 mcp/CONTRACT.md）")
    parser.add_argument("--export", nargs="?", const="mcp/docs/ops.json", metavar="PATH",
                        help="导出机器可读契约 JSON（默认 mcp/docs/ops.json）")
    parser.add_argument("--version", action="store_true", help="打印版本后退出")
    return parser


# ---------------------------------------------------------------------------
# 只读命令
# ---------------------------------------------------------------------------
def cmd_list(as_json: bool) -> int:
    if as_json:
        payload = {
            "version": __version__,
            "tool_count": len(GROUPS),
            "op_count": total_ops(),
            "tools": [
                {
                    "tool": group.name,
                    "title": group.title,
                    "op_count": len(group.ops),
                    "risks": group.risks(),
                    "ops": group.op_names(),
                }
                for group in GROUPS
            ],
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0
    print(f"cipherNest MCP v{__version__}：{len(GROUPS)} 个工具 / {total_ops()} 个 op")
    for group in GROUPS:
        print(f"\n{group.name}  ({group.title}) — {len(group.ops)} ops")
        print(f"  {group.summary}")
        for spec in group.ops:
            print(f"    - {spec.name}({spec.signature_text()})  [{spec.risk}]")
    if IMPORT_ERRORS:
        print("\n导入失败的组：")
        for name, reason in IMPORT_ERRORS.items():
            print(f"    - {name}: {reason}")
    return 0


def cmd_show(op_name: str) -> int:
    group, spec = find_op(GROUPS, op_name)
    if spec is None or group is None:
        print(f"未知 op：{op_name}", file=sys.stderr)
        return 2
    payload = spec.schema()
    payload["op"] = spec.name
    payload["tool"] = group.name
    payload["tool_title"] = group.title
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def cmd_audit() -> int:
    issues = audit(GROUPS)
    print(f"对照 {total_ops()} 个 op 的 lib 签名，发现问题 {len(issues)} 个")
    for issue in issues:
        print("  -", json.dumps(issue, ensure_ascii=False))
    return 1 if issues else 0


def cmd_selftest() -> int:
    from . import selftest
    return selftest.run(verbose=True)


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    _safe_stdio()
    args = build_parser().parse_args(argv)

    if args.version:
        print(f"ciphernest-mcp {__version__}")
        return 0
    if args.list:
        return cmd_list(args.json)
    if args.show:
        return cmd_show(args.show)
    if args.audit:
        return cmd_audit()
    if args.selftest:
        return cmd_selftest()
    if args.gen_docs:
        from .docgen import write_contract
        target = write_contract(GROUPS, args.gen_docs)
        print(f"已生成契约文档：{target}")
        return 0
    if args.export:
        from .docgen import export_json
        target = export_json(GROUPS, args.export)
        print(f"已导出契约 JSON：{target}")
        return 0

    # 正常服务模式
    init_proxy_pool()
    settings().load()
    if IMPORT_ERRORS:
        for name, reason in IMPORT_ERRORS.items():
            log(f"[warn] 工具组 {name} 不可用：{reason}")

    transport = "streamable-http" if args.http else args.transport
    from .app import build_app
    # HTTP（streamable-http）模式启用「活跃连接」追踪；stdio 模式无连接概念。
    app = build_app(host=args.host, port=args.port, debug=args.debug,
                    track_sessions=(transport == "streamable-http"))

    if transport == "stdio":
        log(f"以 stdio 启动（{len(GROUPS)} 个工具 / {total_ops()} 个 op）")
        log("提示：stdio 模式不监听任何端口；若要用 HTTP 连接器，"
            "请改用 `python mcp/server.py --http`（或 start_http.cmd）")
    else:
        path = "/mcp" if transport == "streamable-http" else "/sse"
        log(f"以 {transport} 启动：http://{args.host}:{args.port}{path}")
    app.run(transport=transport)
    return 0
