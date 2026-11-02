# -*- coding: utf-8 -*-
"""cn_web —— Web 信息收集工具组。

覆盖 ``lib.web_fuzz``（一站式 Fuzz）、``lib.jsfinder``、``lib.fingerprint``、
``lib.hostsearch``、``lib.httpscan``、``lib.dns_tool``。

网络约定
--------
- 所有 op 默认走配置里的全局代理池（``proxy_pool.enabled``）；未启用则直连；
- 只有明确写着「直连」的 op 才强制绕过代理；
- 主动探测类 op（子域名爆破 / 网段扫描）风险等级为 ``network`` / ``intrusive``，
  仅可用于已授权目标。
"""

from __future__ import annotations

from typing import Any

from lib import dns_tool, fingerprint, hostsearch, httpscan, jsfinder, web_fuzz

from ..contract import (Ctx, Group, arr, custom_op, flag, flt, hexb, make_op,
                        num, anyp, txt)
from ..envelope import to_jsonable

_RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA")


def _brute_subdomains(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    results, note = dns_tool.brute_subdomains(
        a["base_domain"], dict_path=a["dict_path"] or None,
        interval=a["interval"], use_proxy=a["use_proxy"], timeout=a["timeout"],
        log=ctx.log, stop=ctx.stop)
    return {"base_domain": a["base_domain"], "count": len(results),
            "results": to_jsonable(results), "note": note}


def _fingerprint_to_text(a: dict[str, Any], ctx: Ctx) -> str:
    return fingerprint.to_text(a["result"])


OPS = [
    # ------------------------------------------------------------ Web Fuzz
    make_op(web_fuzz.run, name="web_fuzz",
            summary="一站式 Web 信息收集：状态码 / 响应头 / 安全头 / Cookie / 标题 / meta / "
            "技术栈 / 链接 / 脚本 / 表单 / 注释 / 邮箱 / 手机号 / IP，可选附带 "
            "robots.txt、sitemap.xml、历史收录、子域名字典爆破。",
            params=[txt("target", required=True, desc="目标 URL 或域名"),
             flt("timeout", default=8.0, desc="单次请求超时（秒）", minimum=1, maximum=120),
             flag("with_robots", default=False, desc="顺带抓 robots.txt"),
             flag("with_sitemap", default=False, desc="顺带抓 sitemap.xml"),
             flag("with_hostsearch", default=False, desc="顺带查历史收录"),
             flag("with_subdomain_brute", default=False, desc="顺带做子域名字典爆破（慢）"),
             txt("subdomain_dict", default=None, desc="子域名字典路径；留空用内置字典"),
             flt("subdomain_interval", default=0.3, desc="子域名查询间隔（秒）",
                 minimum=0, maximum=10),
             flag("subdomain_use_proxy", default=False, desc="子域名查询是否走代理")],
            returns="dict：{target, status, headers, security, cookies, title, meta, tech, links, scripts, forms, comments, emails, phones, ips, ...}",
            risk="network", example={"target": "https://example.com"}),
    make_op(web_fuzz.to_text, "把 Web Fuzz 结果渲染为纯文本报告。",
            [anyp("result", required=True, desc="web_fuzz.run 的返回 dict")],
            returns="str：文本报告"),

    # -------------------------------------------------------------- JSFinder
    make_op(jsfinder.extract_url, "从 JS / HTML 文本中提取链接（保序去重）。",
            [txt("js_text", required=True, desc="JS 或 HTML 文本")],
            returns="list[str]：提取到的链接", risk="safe"),
    make_op(jsfinder.process_url, "把相对链接补全为绝对 URL。",
            [txt("base_url", required=True, desc="基准 URL"),
             txt("re_url", required=True, desc="待补全的链接")],
            returns="str：绝对 URL", risk="safe"),
    make_op(jsfinder.find_subdomain, "从 URL 列表里提取主域名下的全部子域名。",
            [arr("urls", required=True, desc="URL 列表"),
             txt("main_url", required=True, desc="主 URL")],
            returns="list[str]：子域名（保序去重）", risk="safe"),
    make_op(jsfinder.find_by_url, "抓取页面与全部 script（内嵌 + 外链）提取同域链接。",
            [txt("url", required=True, desc="目标页面 URL"),
             txt("cookie", desc="Cookie 头"), num("timeout", default=5, desc="请求超时（秒）", minimum=1)],
            returns="list[str]|null：链接列表", risk="network"),
    make_op(jsfinder.find_by_url_deep, "深度模式：跟进页面 ``<a>`` 链接递归收集。",
            [txt("url", required=True, desc="目标页面 URL"),
             txt("cookie", desc="Cookie 头"), num("timeout", default=5, desc="请求超时（秒）", minimum=1),
             num("max_links", default=50, desc="最多跟进的链接数", minimum=1, maximum=500)],
            returns="list[str]|null：链接列表", risk="network"),
    make_op(jsfinder.run, name="jsfinder",
            summary="JSFinder 主入口：返回 URL 列表与子域名列表。",
            params=[txt("url", required=True, desc="目标页面 URL"),
             txt("cookie", desc="Cookie 头"),
             flag("deep", default=False, desc="深度模式（跟进链接，更慢更全）"),
             num("timeout", default=5, desc="请求超时（秒）", minimum=1),
             num("max_links", default=50, desc="深度模式最多跟进链接数", minimum=1)],
            returns="dict：{urls, subdomains}", unpack=("urls", "subdomains"),
            risk="network"),

    # ------------------------------------------------------------ 指纹识别
    make_op(fingerprint.run, name="fingerprint",
            summary="Web 指纹识别（observer_ward 风格）：识别产品 / 组件 / 厂商 / 版本。",
            params=[txt("target", required=True, desc="目标 URL"),
             flt("timeout", default=8.0, desc="请求超时（秒）", minimum=1),
             anyp("rules", default=None,
                  desc="自定义规则列表；留空用 ``dict/fingerprints`` 内置规则")],
            returns="dict：{target, matches: [{name, product, version, ...}], ...}",
            risk="network"),
    custom_op("fingerprint_to_text", _fingerprint_to_text,
              "把指纹识别结果渲染为纯文本报告。",
              [anyp("result", required=True, desc="fingerprint.run 的返回 dict")],
              returns="str：文本报告", risk="safe", module="lib.fingerprint"),
    make_op(fingerprint.load_rules, "加载指纹规则目录（或单个 YAML 文件）。",
            [arr("directories", default=None, desc="规则目录 / 文件列表；留空用内置目录")],
            returns="list[dict]：规则列表", risk="read"),
    make_op(fingerprint.favicon_hashes, "计算 favicon 的 mmh3 与 md5 双哈希（与 shodan 一致）。",
            [hexb("data", required=True, desc="favicon 原始字节的十六进制")],
            returns="dict：{mmh3, md5}"),

    # ------------------------------------------------------------ 历史收录
    make_op(hostsearch.query_hostsearch, "查询域名历史收录（hackertarget）。",
            [txt("domain", required=True, desc="域名（可带协议前缀）"),
             flt("timeout", default=8.0, desc="请求超时（秒）", minimum=1)],
            returns="dict：{domain, subdomains, ips, ...}", risk="network"),
    make_op(hostsearch.normalize_domain, "规范化域名：去掉协议 / 路径 / 端口。",
            [txt("raw", required=True, desc="原始域名或 URL")],
            returns="str：纯域名", risk="safe"),

    # ------------------------------------------------------------ 网段扫描
    make_op(httpscan.expand_ips, "把 CIDR（如 192.168.1.0/24）或单个 IP 展开为 IP 列表。",
            [txt("target", required=True, desc="CIDR 或 IP")],
            returns="list[str]：IP 列表", risk="safe"),
    make_op(httpscan.scan_ip, "探测单个 IP 上的 Web 服务（无 Web 服务返回 null）。",
            [txt("ip", required=True, desc="目标 IP"),
             num("timeout", default=5, desc="超时（秒）", minimum=1),
             flag("https", default=False, desc="是否走 https")],
            returns="dict|null：{ip, url, status, server, title}", risk="network"),
    make_op(httpscan.run, name="httpscan",
            summary="多线程扫描网段，返回存活 Web 主机列表。",
            params=[txt("target", required=True, desc="CIDR 或 IP"),
             num("threads", default=10, desc="并发线程数", minimum=1, maximum=200),
             num("timeout", default=5, desc="单主机超时（秒）", minimum=1),
             flag("https", default=False, desc="是否走 https")],
            returns="list[dict]：存活主机结果", risk="intrusive",
            notes="网段扫描请只用于已授权目标。"),

    # ---------------------------------------------------------------- DNS
    make_op(dns_tool.resolve_dns, "DNS 解析：返回 A / AAAA / CNAME / MX / TXT / NS 等记录。",
            [txt("host", required=True, desc="域名"),
             flag("use_proxy", default=False, desc="是否走 SOCKS5 代理做远程 DNS"),
             flt("timeout", default=8.0, desc="查询超时（秒）", minimum=1)],
            returns="dict：{host, records: [{type, values, note}], ...}", risk="network"),
    make_op(dns_tool.resolve_record, "查询单条 DNS 记录类型。",
            [txt("host", required=True, desc="域名"),
             txt("rtype", required=True, desc="记录类型", choices=_RECORD_TYPES),
             flag("use_proxy", default=False, desc="是否走 SOCKS5 代理"),
             flt("timeout", default=8.0, desc="查询超时（秒）", minimum=1)],
            returns="dict：{type, values, note}", risk="network"),
    custom_op("brute_subdomains", _brute_subdomains,
              "子域名字典爆破：逐个拼 ``词条.主域名`` 做 DNS A 查询。",
              [txt("base_domain", required=True, desc="主域名"),
               txt("dict_path", default=None, desc="子域名字典路径；留空用内置字典"),
               flt("interval", default=0.3, desc="每次查询间隔（秒）", minimum=0, maximum=10),
               flag("use_proxy", default=False, desc="是否走代理"),
               flt("timeout", default=8.0, desc="单次查询超时（秒）", minimum=1)],
              returns="dict：{base_domain, count, results, note}", risk="intrusive",
              module="lib.dns_tool",
              notes="字典较大时耗时较长；建议先用小字典试探。"),
    make_op(dns_tool.load_subdomain_words, "读取子域名字典（去空行 / 注释 / 去重）。",
            [txt("dict_path", default=None, desc="字典路径；留空用内置字典")],
            returns="list[str]：词条列表", risk="read"),
    make_op(dns_tool.normalize_domain, name="dns_normalize_domain",
            summary="规范化域名：去协议 / 路径 / 端口（DNS 模块版本）。",
            params=[txt("raw", required=True, desc="原始域名或 URL")],
            returns="str：纯域名", risk="safe"),
]


GROUP = Group(
    name="cn_web",
    title="Web 信息收集：Fuzz / JSFinder / 指纹 / 收录 / 网段 / DNS",
    summary=("一站式 Web Fuzz；JS 链接与子域名提取；observer_ward 风格指纹识别；"
             "历史收录查询；CIDR 网段 Web 主机发现；DNS 记录解析与子域名爆破。"),
    ops=OPS,
    guide=("网络类 op 默认复用 config.json 的全局代理池；只对已授权目标使用。"
           "长任务（brute_subdomains / httpscan）建议先用小范围参数试探。"),
)
