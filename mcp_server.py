# -*- coding: utf-8 -*-
"""28zenro MCP Server。

把 lib/ 里的 Web 信息收集工具以 MCP (Model Context Protocol) tool 形式
暴露给 Agent 宿主（Claude Desktop / Cursor 等），与 ``cli.py`` 共用同一层
纯函数与 ``config.json`` 代理池配置。

与 CLI 的关系
-------------
- 底层完全复用 ``lib.*`` 纯函数，行为与 ``python cli.py <tool> --json`` 一致；
- 配置同样走 :class:`app.store.SettingsStore`，启动时加载全局代理池；
- CLI 面向 shell 脚本，本入口面向工具调用型 Agent，二者互不依赖。

运行方式
--------
    python mcp_server.py          # stdio 传输（宿主以子进程方式拉起）

宿主配置示例（Claude Desktop / Cursor 的 mcp.json）::
    {
      "mcpServers": {
        "28zenro": {
          "command": "python",
          "args": ["D:/Code/pythonCode/CTFcrypto/mcp_server.py"]
        }
      }
    }

约定
----
- 所有 tool 返回 JSON 可序列化的 dict / list（dataclass 已 asdict）；
- 进度日志一律写 stderr，不污染 stdio 协议通道；
- 参数与 ``cli.py`` 子命令一一对应，方便两边文档互查。
"""

from __future__ import annotations

import dataclasses
import sys
from pathlib import Path

# 保证以任意工作目录启动都能找到项目根下的 lib / app 包。
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# 初始化：加载配置 + 全局代理池（与 cli.py 的 _load_config 一致）
# ---------------------------------------------------------------------------
def _bootstrap() -> None:
    from app.store import SettingsStore
    from lib import proxy_pool

    store = SettingsStore(None)
    proxy_pool.load_config(store.get("proxy_pool", default={}))


def _log(msg: str) -> None:
    """进度日志走 stderr，不污染 stdio 协议。"""
    print(msg, file=sys.stderr)


def _plain(value):
    """dataclass → dict，保证返回值可 JSON 序列化。"""
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return dataclasses.asdict(value)
    return value


_bootstrap()

mcp = FastMCP(
    "28zenro",
    instructions=(
        "28zenro Web 安全工具集：信息收集 / 子域名 / 指纹 / 目录与参数爆破 / "
        "端口扫描 / 源码泄露 / SSTI。所有工具返回结构化 JSON。"
        "慢工具（dirscan/portscan/paramfuzz）建议先用默认参数小范围试探。"
    ),
)


# ---------------------------------------------------------------------------
# 信息收集
# ---------------------------------------------------------------------------
@mcp.tool()
def webfuzz(url: str, timeout: float = 8.0, robots: bool = False,
            sitemap: bool = False, hostsearch: bool = False,
            subdomain: bool = False) -> dict:
    """Web Fuzz 一站式信息收集：状态码/响应头/安全头/Cookie/标题/meta/
    技术栈/链接/脚本/表单/注释/邮箱/手机号/IP。可选附带 robots.txt、
    sitemap.xml、域名历史收录、子域名字典爆破。"""
    from lib import web_fuzz
    return _plain(web_fuzz.run(
        url, timeout=timeout, with_robots=robots, with_sitemap=sitemap,
        with_hostsearch=hostsearch, with_subdomain_brute=subdomain,
        log=_log))


@mcp.tool()
def jsfinder(url: str, cookie: str = "", deep: bool = False,
             endpoint: bool = False, timeout: int = 5,
             max_links: int = 50) -> dict:
    """从目标页面及其 JS 文件中提取 URL 与子域名。
    deep=True 时递归跟进同域 JS（更慢更全）。
    endpoint=True 时进入「覆盖 JS 文件查询」：提取 JS 里的 API 接口路径。"""
    from lib import jsfinder
    urls, subdomains = jsfinder.run(
        url, cookie=cookie, deep=deep, endpoint=endpoint,
        timeout=timeout, max_links=max_links, progress=_log)
    return {"urls": urls, "subdomains": subdomains}


@mcp.tool()
def fingerprint(url: str, timeout: float = 8.0,
                rules_dir: str = "") -> dict:
    """Web 指纹识别（observer_ward 风格）：识别目标站点使用的
    产品/组件/厂商/版本。rules_dir 缺省用内置规则。"""
    from lib import fingerprint
    rules = fingerprint.load_rules([rules_dir]) if rules_dir else None
    return _plain(fingerprint.run(url, timeout=timeout, rules=rules, log=_log))


@mcp.tool()
def dns_resolve(host: str, use_proxy: bool = False) -> dict:
    """DNS 解析：返回 A / AAAA / CNAME 等记录。use_proxy=True 时
    走全局代理池的 SOCKS5 远程 DNS。"""
    from lib import dns_tool
    return dns_tool.resolve_dns(host, use_proxy=use_proxy)


@mcp.tool()
def subdomain_brute(domain: str, dict_path: str = "",
                    interval: float = 0.3, use_proxy: bool = False) -> dict:
    """子域名字典爆破。dict_path 缺省用内置字典；interval 为查询间隔秒数。"""
    from lib import dns_tool
    results, note = dns_tool.brute_subdomains(
        domain, dict_path=dict_path or None, interval=interval,
        use_proxy=use_proxy, log=_log)
    return {"results": results, "note": note}


@mcp.tool()
def hostsearch(domain: str) -> dict:
    """查询域名历史收录（hackertarget）：返回历史子域名与 IP 记录。"""
    from lib import hostsearch
    return hostsearch.query_hostsearch(domain, log=_log)


# ---------------------------------------------------------------------------
# 扫描 / 爆破
# ---------------------------------------------------------------------------
@mcp.tool()
def httpscan(cidr: str, threads: int = 10, timeout: int = 5,
             https: bool = False) -> list:
    """CIDR 网段 Web 主机探针：存活主机的状态码/Server/标题/最终 URL。
    例：cidr="192.168.1.0/24"。"""
    from lib import httpscan
    return httpscan.run(cidr, threads=threads, timeout=timeout,
                        https=https, progress=_log)


@mcp.tool()
def dirscan(url: str, dict_dir: str = "", threads: int = 16,
            timeout: float = 6.0, interval: float = 30.0,
            headers: str = "", out_dir: str = "") -> dict:
    """目录爆破：基于字典探测目标隐藏路径。interval 为每轮间隔秒数。
    headers 支持多行 "Key: Value" 格式。耗时工具，建议小字典先试。"""
    from lib import dir_scan
    return _plain(dir_scan.scan(
        url, out_dir=out_dir or None, dict_dir=dict_dir or None,
        threads=threads, timeout=timeout, interval=interval,
        headers=headers, log=_log))


@mcp.tool()
def leakscan(domain: str, kinds: list[str] | None = None,
             threads: int = 8, timeout: float = 8.0,
             out_dir: str = "output/leak") -> list:
    """源码泄露检测：探测 .git / .svn / .DS_Store 等敏感文件是否可访问。
    kinds 可选 ["git", "svn", "ds_store"]，缺省全查。"""
    from lib import leak_scan
    return leak_scan.run(domain, out_dir=out_dir, kinds=kinds,
                         threads=threads, timeout=timeout, log=_log)


@mcp.tool()
def paramfuzz(url: str, method: str = "GET", wordlist: str = "small",
              include: str = "", headers: str = "", timeout: float = 8.0,
              threads: int = 10, delay: float = 0.0) -> dict:
    """参数 Fuzz：发现目标接口的隐藏参数（GET/POST/JSON/XML）。
    wordlist 可用 small / big 或自定义文件路径。耗时工具。"""
    from lib import param_fuzz
    return param_fuzz.run(
        url, method=method, wordlist=wordlist, include=include,
        headers=headers, timeout=timeout, threads=threads,
        delay=delay, log=_log)


@mcp.tool()
def portscan(host: str, ports: str = "常见端口.txt", threads: int = 24,
             timeout: float = 6.0, retries: int = 3,
             no_proxy: bool = False) -> dict:
    """端口扫描。ports 支持：内置字典文件名 / 自定义文件路径 /
    范围表达式（如 "1-1024,3306"）。默认走全局代理池，no_proxy=True 直连。"""
    from lib import port_scan
    from cli import _resolve_ports, _build_proxy_pool  # 复用 CLI 的解析逻辑

    port_list = _resolve_ports(ports)
    pool = None if no_proxy else _build_proxy_pool()
    return port_scan.scan(
        host, port_list, pool=pool, threads=threads, timeout=timeout,
        retries=retries, log=_log)


# ---------------------------------------------------------------------------
# 漏洞探测
# ---------------------------------------------------------------------------
@mcp.tool()
def ssti(url: str, param: str, method: str = "GET", data: str = "",
         cookie: str = "", headers: str = "", prefix: str = "",
         timeout: float = 15.0, enum_all: bool = False) -> dict:
    """SSTI 模板注入探测：对指定参数注入探测载荷，枚举可 RCE 的
    模板子类。param 为注入参数名；enum_all=True 枚举全部子类（更慢）。"""
    from lib import ssti_finder
    kwargs = {}
    if prefix:
        kwargs["prefix"] = prefix
    return _plain(ssti_finder.run(
        url, param, method=method, data=data, cookie=cookie,
        headers=headers, timeout=timeout, enum_all=enum_all,
        progress=_log, **kwargs))


# ---------------------------------------------------------------------------
# 凭证 / 其他
# ---------------------------------------------------------------------------
@mcp.tool()
def wechat_check(appid: str, secret: str, timeout: float = 15.0) -> dict:
    """微信公众号 AppID/AppSecret 凭证有效性校验：返回是否有效、
    access_token、errcode/errmsg。"""
    from lib import wechat_check
    return _plain(wechat_check.check_credential(appid, secret, timeout=timeout))


@mcp.tool()
def ping_multi(host: str, timeout: float = 15.0) -> dict:
    """多地 Ping：通过 API 从多个节点探测目标延迟与解析结果。"""
    from lib import ping_probe
    return _plain(ping_probe.run_ping(host, timeout=timeout, progress=_log))


@mcp.tool()
def mysql_probe(host: str, port: int = 3306, timeout: float = 6.0) -> dict:
    """MySQL 被动指纹探测（不爆破）：识别 3306 端口是否为 MySQL、
    版本信息与认证方式。仅限授权测试。"""
    from lib import mysql_brute
    return _plain(mysql_brute.probe(host, port=port, timeout=timeout))


if __name__ == "__main__":
    mcp.run()  # stdio 传输：宿主以子进程方式拉起，通过 stdin/stdout 通信