# -*- coding: utf-8 -*-
"""cn_attack —— 漏洞探测 / 凭证爆破 / 压缩包 / 哈希爆破工具组。

覆盖 ``lib.ssti_finder``、``lib.mysql_brute``、``lib.wechat_check``、
``lib.zip_cracker``、``lib.md5_crash``。

线程型任务（压缩包爆破 / 哈希爆破）统一用「同步等待 + 时间上限」模型：
``max_seconds`` 到达后停止任务并返回当前状态，避免 MCP 调用无限挂起。
"""

from __future__ import annotations

import time
from typing import Any

from lib import md5_crash, mysql_brute, ssti_finder, wechat_check, zip_cracker

from ..contract import (Ctx, Group, anyp, arr, custom_op, flag, flt, make_op,
                        num, obj, txt)
from ..envelope import ToolError, to_jsonable
from ._helpers import (job_result, poll_until_done, rel, resolve_output,
                       resolve_output_dir, resolve_path, section)

_SSTI_METHODS = ("GET", "POST")


# ---------------------------------------------------------------------------
# 压缩包
# ---------------------------------------------------------------------------
def _zip_path(a: dict[str, Any]) -> Any:
    return resolve_path(a["zip_path"], field="zip_path", must_exist=True)


def _zip_list(a: dict[str, Any], ctx: Ctx) -> Any:
    return to_jsonable(zip_cracker.list_entries(_zip_path(a)))


def _zip_is_encrypted(a: dict[str, Any], ctx: Ctx) -> Any:
    return zip_cracker.is_encrypted(_zip_path(a))


def _zip_is_fake(a: dict[str, Any], ctx: Ctx) -> Any:
    return zip_cracker.is_fake_encrypted(_zip_path(a))


def _zip_fix_fake(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    src = _zip_path(a)
    out = resolve_output(a["out_path"], src.with_name(src.stem + "_fixed.zip"))
    written = zip_cracker.fix_fake_encrypted(src, out)
    return {"src": str(src), "out": str(written), "out_rel": rel(written)}


def _zip_extract(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    src = _zip_path(a)
    out_dir = resolve_output_dir(
        a["out_dir"], section("zip_crack").get("output_dir") or "output",
        field="out_dir") / src.stem
    names = zip_cracker.extract(src, out_dir=out_dir,
                                password=a["password"] or None)
    return {"zip": str(src), "out_dir": str(out_dir), "out_rel": rel(out_dir),
            "count": len(names), "files": to_jsonable(names)}


def _zip_small_crc(a: dict[str, Any], ctx: Ctx) -> Any:
    return to_jsonable(zip_cracker.small_crc_candidates(_zip_path(a),
                                                        max_size=a["max_size"]))


def _zip_crack(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    src = _zip_path(a)
    dict_path = None
    if a["dict_path"]:
        dict_path = str(resolve_path(a["dict_path"], field="dict_path",
                                     must_exist=True))
    job = zip_cracker.ZipCracker()
    job.start(src, dict_path=dict_path, use_builtin=a["use_builtin"],
              max_numeric_len=a["max_numeric_len"],
              custom_first=a["custom_first"])
    events: list[tuple] = []
    finished = poll_until_done(job, max_seconds=a["max_seconds"],
                              log_fn=ctx.log, events=events)
    payload = job_result(job, events, finished=finished, kind="zip")
    payload["zip"] = str(src)
    tried = getattr(job, "tried", None)
    if isinstance(tried, int):
        payload["tried"] = tried
    return payload


# ---------------------------------------------------------------------------
# 哈希爆破
# ---------------------------------------------------------------------------
def _md5_crack(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    dict_path = None
    if a["dict_path"]:
        dict_path = str(resolve_path(a["dict_path"], field="dict_path",
                                     must_exist=True))
    candidates = list(a["candidates"]) if a["candidates"] else []
    min_len, max_len = a["min_len"], a["max_len"]
    if dict_path is None and not candidates and (min_len is None or max_len is None):
        raise ToolError(
            "missing_param",
            "枚举模式必须给 min_len 与 max_len；或者改传 dict_path / candidates",
            field="min_len")
    job = md5_crash.Md5Cracker()
    job.start(a["hash_value"], min_len, max_len, a["worker_num"],
              a["thread_num"], charset=a["charset"] or None,
              dict_path=dict_path, candidates=candidates or None,
              prefix=a["prefix"], suffix=a["suffix"],
              hash_name=a["hash_name"])
    events: list[tuple] = []
    finished = poll_until_done(job, max_seconds=a["max_seconds"],
                              log_fn=ctx.log, events=events)
    payload = job_result(job, events, finished=finished, kind="hash")
    payload["hash_name"] = a["hash_name"]
    payload["hash"] = a["hash_value"]
    return payload


# ---------------------------------------------------------------------------
# 微信凭证
# ---------------------------------------------------------------------------
def _wechat_many(a: dict[str, Any], ctx: Ctx) -> Any:
    raw = a["pairs"]
    if isinstance(raw, str):
        pairs = wechat_check.parse_inputs(raw)
    else:
        pairs = [(str(item[0]), str(item[1])) for item in raw]
    results = wechat_check.check_many(
        pairs, timeout=a["timeout"], base_url=a["base_url"],
        progress=ctx.log, stop=ctx.stop)
    return to_jsonable(results)


OPS = [
    # --------------------------------------------------------------- SSTI
    make_op(ssti_finder.run,
            "SSTI 模板注入探测：注入探测载荷，枚举可 RCE 的模板子类。",
            [txt("url", required=True, desc="目标 URL"),
             txt("param", required=True, desc="注入参数名"),
             txt("method", default="GET", desc="请求方法", choices=_SSTI_METHODS),
             txt("data", desc="POST body"),
             txt("cookie", desc="Cookie 头"),
             txt("headers", desc="自定义请求头，多行 ``Key: Value``"),
             txt("proxy", desc="单次请求使用的代理（留空走全局代理池）"),
             txt("prefix", default="().__class__.__bases__[0]",
                 desc="注入前缀（payload 起始对象）"),
             flt("timeout", default=15.0, desc="单请求超时（秒）", minimum=1),
             flag("enum_all", default=False, desc="枚举全部子类（更慢更全）")],
            returns="dict：{url, param, vulnerable, prefix, subclasses, rce_hits, ...}",
            risk="intrusive"),

    # ------------------------------------------------------------ MySQL
    make_op(mysql_brute.probe,
            "MySQL 被动指纹：确认目标是否为 MySQL 并读取版本 / 认证方式（不爆破）。",
            [txt("host", required=True, desc="目标主机"),
             num("port", default=3306, desc="端口", minimum=1, maximum=65535),
             flt("timeout", default=6.0, desc="超时（秒）", minimum=1)],
            returns="dict：{user, password, state, code, message, plugin, ms, host}",
            risk="network"),
    make_op(mysql_brute.banner_grab, "抓取 MySQL 服务端 banner 与握手信息。",
            [txt("host", required=True, desc="目标主机"),
             num("port", default=3306, desc="端口", minimum=1, maximum=65535),
             flt("timeout", default=6.0, desc="超时（秒）", minimum=1)],
            returns="dict：{version, plugin, salt, capability, ...}", risk="network"),
    make_op(mysql_brute.try_login, "用一组用户名密码尝试登录。",
            [txt("host", required=True, desc="目标主机"),
             num("port", default=3306, desc="端口", minimum=1, maximum=65535),
             txt("user", required=True, desc="用户名"),
             txt("password", default="", desc="密码"),
             flt("timeout", default=6.0, desc="超时（秒）", minimum=1),
             flag("probe_only", default=False, desc="只探测不真正登录")],
            returns="dict：{user, state, code, message, plugin, ms}", risk="intrusive"),
    make_op(mysql_brute.brute,
            "MySQL 用户名×密码组合爆破（线程池 + 上限）。",
            [txt("host", required=True, desc="目标主机"),
             num("port", default=3306, desc="端口", minimum=1, maximum=65535),
             arr("users", required=True, desc="用户名列表"),
             arr("passwords", required=True, desc="密码列表"),
             num("threads", default=8, desc="并发线程数", minimum=1, maximum=64),
             flt("timeout", default=6.0, desc="单次超时（秒）", minimum=1),
             num("max_attempts", default=0, desc="最大尝试次数（0 = 不限）", minimum=0),
             txt("out_dir", default=None, desc="结果输出目录；留空不落盘")],
            returns="dict：{host, attempts, hits: [...], ...}", risk="intrusive"),
    make_op(mysql_brute.classify_target, "判断目标是 IP 还是域名（用于选字典策略）。",
            [txt("host", required=True, desc="目标主机")],
            returns="str：'ip' / 'domain'", risk="safe"),
    make_op(mysql_brute.default_users, "内置默认用户名列表。", [],
            returns="list[str]：用户名", risk="safe"),
    make_op(mysql_brute.default_passwords, "内置默认密码列表。", [],
            returns="list[str]：密码", risk="safe"),
    make_op(mysql_brute.load_lines, "读取一行一个的字典文件（去 BOM / 去注释 / 去重）。",
            [txt("path", required=True, desc="字典文件路径"),
             num("limit", default=200000, desc="最多读取行数", minimum=1)],
            returns="list[str]：词条", risk="read"),

    # ------------------------------------------------------- 微信公众号凭证
    make_op(wechat_check.check_credential,
            "校验一组微信公众号 AppID / AppSecret 是否有效（返回 access_token）。",
            [txt("appid", required=True, desc="AppID"),
             txt("secret", required=True, desc="AppSecret"),
             flt("timeout", default=15.0, desc="超时（秒）", minimum=1),
             txt("base_url", default="https://api.weixin.qq.com/cgi-bin/token",
                 desc="校验接口地址")],
            returns=("dict：{appid, valid, access_token, expires_in, errcode, "
                     "errmsg, raw}"), risk="network"),
    custom_op("wechat_check_many", _wechat_many,
              "批量校验多组微信公众号凭证（逐条顺序请求）。",
              [anyp("pairs", required=True,
                    desc="[[appid, secret], …] 列表，或 ``appid:secret`` 多行文本"),
               flt("timeout", default=15.0, desc="单组超时（秒）", minimum=1),
               txt("base_url", default="https://api.weixin.qq.com/cgi-bin/token",
                   desc="校验接口地址")],
              returns="list[dict]：每组凭证的校验结果", risk="network",
              module="lib.wechat_check"),
    make_op(wechat_check.parse_inputs, "把批量输入文本解析成 (appid, secret) 列表。",
            [txt("text", required=True, desc="多行 ``appid:secret`` 文本")],
            returns="list[list[str]]：凭证对", risk="safe"),
    make_op(wechat_check.split_pair, "把一行解析成 (appid, secret)。",
            [txt("line", required=True, desc="一行凭证文本")],
            returns="dict：{appid, secret}", unpack=("appid", "secret"),
            risk="safe"),

    # ------------------------------------------------------------ 压缩包
    custom_op("zip_list_entries", _zip_list, "列出压缩包条目（名称 / 大小 / CRC / 是否加密）。",
              [txt("zip_path", required=True, desc="压缩包路径（相对项目根或绝对）")],
              returns="list[dict]：{name, size, crc, encrypted, is_dir}",
              risk="read", module="lib.zip_cracker"),
    custom_op("zip_is_encrypted", _zip_is_encrypted, "压缩包是否有条目被标记加密（含伪加密）。",
              [txt("zip_path", required=True, desc="压缩包路径")],
              returns="bool：是否需要密码", risk="read", module="lib.zip_cracker"),
    custom_op("zip_is_fake_encrypted", _zip_is_fake, "判定是否为伪加密（标志位标记但数据未加密）。",
              [txt("zip_path", required=True, desc="压缩包路径")],
              returns="bool：是否伪加密", risk="read", module="lib.zip_cracker"),
    custom_op("zip_fix_fake_encrypted", _zip_fix_fake,
              "修复伪加密：清除加密标志位后另存为新压缩包。",
              [txt("zip_path", required=True, desc="压缩包路径"),
               txt("out_path", desc="输出路径；留空写 ``<名字>_fixed.zip``")],
              returns="dict：{src, out, out_rel}", risk="write",
              module="lib.zip_cracker"),
    custom_op("zip_extract", _zip_extract, "解压压缩包（可带密码）。",
              [txt("zip_path", required=True, desc="压缩包路径"),
               txt("out_dir", desc="输出目录；留空写 ``output/<包名>/``"),
               txt("password", default=None, desc="解压密码（无密码留空）")],
              returns="dict：{zip, out_dir, out_rel, count, files}",
              risk="write", module="lib.zip_cracker"),
    custom_op("zip_small_crc_candidates", _zip_small_crc,
              "列出适合 CRC32 碰撞的条目（未加密、非目录、大小 ≤ max_size）。",
              [txt("zip_path", required=True, desc="压缩包路径"),
               num("max_size", default=6, desc="明文最大长度", minimum=1, maximum=32)],
              returns="list[dict]：候选条目", risk="read", module="lib.zip_cracker"),
    make_op(zip_cracker.crc32_crack,
            "CRC32 碰撞：已知 CRC 与明文长度，按字符集还原明文。",
            [num("crc", required=True, desc="目标 CRC32（十进制）"),
             num("size", required=True, desc="明文长度", minimum=1, maximum=12),
             txt("alphabet", default="0123456789",
                 desc="字符集，或预设名 digits / lower / alpha / printable")],
            returns="str|null：命中的明文", risk="long",
            notes="组合数随 size 指数增长；size > 8 时可能很慢。"),
    custom_op("zip_crack", _zip_crack,
              "压缩包密码爆破：内置字典 + 纯数字枚举，找到密码立即返回。",
              [txt("zip_path", required=True, desc="压缩包路径"),
               txt("dict_path", default=None, desc="自定义字典路径；留空用内置字典"),
               flag("use_builtin", default=True, desc="是否叠加内置字典"),
               num("max_numeric_len", default=6, desc="纯数字密码最大位数",
                   minimum=0, maximum=12),
               flag("custom_first", default=True, desc="是否优先用自定义字典"),
               flt("max_seconds", default=600.0, desc="最长运行秒数（到点停止）",
                   minimum=1, maximum=3600)],
              returns="dict：{status, result, error, finished, events, zip, tried}",
              risk="long", module="lib.zip_cracker"),
    make_op(zip_cracker.builtin_dict_path, "内置压缩包密码字典的绝对路径。", [],
            returns="str：字典路径", risk="safe"),

    # --------------------------------------------------------- 哈希爆破
    custom_op("md5_crack", _md5_crack,
              "哈希爆破：枚举模式（长度 + 字符集）、字典模式、候选列表模式三种。",
              [txt("hash_value", required=True, desc="目标哈希值（十六进制）"),
               num("min_len", default=None, desc="枚举最小长度（枚举模式必填）",
                   minimum=0, maximum=64),
               num("max_len", default=None, desc="枚举最大长度（枚举模式必填）",
                   minimum=0, maximum=64),
               num("worker_num", default=8, desc="工作进程数", minimum=1, maximum=64),
               num("thread_num", default=8, desc="每进程线程数", minimum=1, maximum=64),
               txt("charset", default=None,
                   desc="字符集或预设名 digits / letters / mixed；留空用 mixed"),
               txt("dict_path", default=None, desc="字典路径或字典目录"),
               arr("candidates", default=None, desc="候选词列表（优先于字典）"),
               txt("prefix", desc="已知明文前缀"),
               txt("suffix", desc="已知明文后缀"),
               txt("hash_name", default="md5", desc="哈希算法",
                   choices=("md5", "sha1", "sha256", "sha512", "sha3_256")),
               flt("max_seconds", default=600.0, desc="最长运行秒数（到点停止）",
                   minimum=1, maximum=7200)],
              returns="dict：{status, result, error, finished, events, hash_name, hash}",
              risk="long", module="lib.md5_crash",
              notes="worker_num × thread_num 会放大 CPU 占用，注意宿主负载。"),
    make_op(md5_crash.hash_length, "返回指定哈希算法的十六进制摘要长度。",
            [txt("hash_name", default="md5", desc="哈希算法名")],
            returns="int：摘要长度", risk="safe"),
]


GROUP = Group(
    name="cn_attack",
    title="攻击：SSTI / MySQL / 微信凭证 / 压缩包 / 哈希爆破",
    summary=("SSTI 模板注入探测；MySQL 指纹与登录爆破；微信公众号凭证校验；"
             "ZIP 伪加密修复 / 解压 / CRC32 碰撞 / 密码爆破；"
             "MD5 等哈希爆破（枚举 / 字典 / 候选）。"),
    ops=OPS,
    guide=("爆破类 op 会消耗大量 CPU / 网络，默认都带时间上限（max_seconds）；"
           "仅可用于已授权目标。线程型任务在达到上限时会自动停止并返回当前状态。"),
)
