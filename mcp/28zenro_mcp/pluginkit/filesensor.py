# -*- coding: utf-8 -*-
"""cn_filesensor —— FileSensor 二次封装工具组。

FileSensor（``mcp/plugins/FileSensor/filesensor.py``）是基于 Scrapy 的动态敏感
文件探测工具：先爬取页面，再按爬到的路径生成敏感文件探测向量
（``.swp`` / ``.bak`` / ``~`` / 备份文件等）。

CLI：

    python filesensor.py URL [--404 REGEX] [-o]

- ``--404 REGEX``：用正则把「返回 200 的自定义 404 页面」过滤掉；
- ``-o``：结果另存到插件目录 ``output/``。

输出格式（解析依据）：结尾固定打印 ``Crawled Page: N`` /
``Sensitive File Found: N``，随后逐行列出命中 URL，``-o`` 时再打印
``Results saved in <路径>``。
"""

from __future__ import annotations

import re
from typing import Any

from ..contract import (Ctx, Group, custom_op, flag, num, txt)
from .runtime import (first_line, get_plugin, plugin_result, run_plugin)

_KEY = "filesensor"
_TOOL = "cn_filesensor"

_VERSION_RE = re.compile(r"FileSensor\s+ver\s*([\d.]+)", re.I)
_CRAWLED_RE = re.compile(r"Crawled Page:\s*(\d+)")
_FOUND_RE = re.compile(r"Sensitive File Found:\s*(\d+)")
_SAVED_RE = re.compile(r"Results saved in\s+(.+)")
_LINE_URL_RE = re.compile(r"^https?://\S+$")


def _version(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    plugin = get_plugin(_KEY)
    run = run_plugin(plugin, ["-h"], timeout=60)
    match = _VERSION_RE.search(run.stdout)
    return plugin_result(run, plugin, {
        "version": match.group(1) if match else first_line(run.stdout),
        "homepage": plugin.homepage,
    })


def _scan(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    plugin = get_plugin(_KEY)
    args = [a["url"]]
    if a["filter_404"]:
        args += ["--404", a["filter_404"]]
    if a["save_output"]:
        args.append("-o")

    run = run_plugin(plugin, args, timeout=a["max_seconds"])
    stdout = run.stdout
    crawled = _CRAWLED_RE.search(stdout)
    found = _FOUND_RE.search(stdout)
    saved = _SAVED_RE.search(stdout)

    hits: list[str] = []
    collecting = False
    for line in stdout.splitlines():
        stripped = line.strip()
        if _FOUND_RE.search(stripped):
            collecting = True
            continue
        if collecting:
            if stripped.startswith("Results saved in"):
                break
            if stripped and _LINE_URL_RE.match(stripped):
                hits.append(stripped)

    return plugin_result(run, plugin, {
        "args": args,
        "url": a["url"],
        "crawled_pages": int(crawled.group(1)) if crawled else None,
        "sensitive_found": int(found.group(1)) if found else len(hits),
        "hits": hits[:200],
        "hits_truncated": len(hits) > 200,
        "saved_file": saved.group(1).strip() if saved else None,
    })


OPS = [
    custom_op("version", _version, "查看 FileSensor 版本（解析帮助横幅）。", [],
              returns="dict：{success, version}", risk="safe",
              module="plugins/FileSensor"),
    custom_op("scan", _scan,
              "对目标站点做敏感文件探测（爬取 + 向量扫描），返回命中 URL 列表。",
              [txt("url", required=True, desc="目标 URL，如 https://example.com/"),
               txt("filter_404",
                   desc="用于识别「返回 200 的假 404 页面」的正则，如 ``404 File not Found``"),
               flag("save_output", default=False,
                    desc="是否把结果另存到插件目录 output/"),
               num("max_seconds", default=600, desc="最长运行秒数", minimum=10,
                   maximum=3600)],
              returns="dict：{success, crawled_pages, sensitive_found, hits: [...], "
                      "saved_file}",
              risk="intrusive", module="plugins/FileSensor",
              notes="基于 Scrapy 爬虫，站点大时会跑很久；先用默认参数小范围试探。"),
]


GROUP = Group(
    name=_TOOL,
    title="FileSensor：敏感文件探测",
    summary=("FileSensor 二次封装：爬目标站点并按爬取结果生成敏感文件探测向量"
             "（备份 / swp / 源码泄露等），结果解析成命中 URL 列表。"),
    ops=OPS,
    guide=("站点有自定义 404 页面时务必传 filter_404 正则，否则会大量误报。"
           "仅用于已授权目标。"),
)
