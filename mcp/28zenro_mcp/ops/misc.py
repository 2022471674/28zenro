# -*- coding: utf-8 -*-
"""cn_misc —— 番茄钟 / 代理池 / 局域网共享客户端。

覆盖 ``lib.pomodoro``、``lib.proxy_pool``、``lib.lan_share`` 的**客户端**函数。

刻意不暴露的能力（在 CONTRACT.md「未暴露方法」一节说明原因）
- ``lib.key_simulator``：向当前焦点窗口注入键盘事件，属于桌面交互，不适合远程调用；
- ``lib.lan_share`` 的 ``ShareServer`` / ``ShareState``：需要在本进程托管 HTTP
  服务与文件目录，属于本地服务生命周期，应由 GUI 管理；这里只提供客户端能力；
- 各工具的 ``main()`` / 纯 UI 辅助函数。
"""

from __future__ import annotations

from typing import Any

from lib import lan_share, pomodoro, proxy_pool

from ..bootstrap import init_proxy_pool
from ..contract import (Ctx, Group, arr, custom_op, flt, make_op, num, obj,
                        txt)
from ..envelope import to_jsonable
from ._helpers import rel, resolve_output, resolve_path, section

_POMO: dict[str, Any] = {"instance": None}


# ---------------------------------------------------------------------------
# 番茄钟：进程级单例状态机
# ---------------------------------------------------------------------------
def _pomodoro() -> pomodoro.Pomodoro:
    if _POMO["instance"] is None:
        conf = section("pomodoro")
        config = pomodoro.PomodoroConfig(
            work_minutes=int(conf.get("work_minutes") or 25),
            short_rest_minutes=int(conf.get("short_rest_minutes") or 5),
            long_rest_minutes=int(conf.get("long_rest_minutes") or 15),
            long_every=int(conf.get("long_every") or 4))
        _POMO["instance"] = pomodoro.Pomodoro(config)
    return _POMO["instance"]


def _pomo_status(p: pomodoro.Pomodoro) -> dict[str, Any]:
    return {
        "phase": p.phase,
        "phase_name": p.phase_name,
        "running": p.running,
        "paused": p.paused,
        "idle": p.idle,
        "remaining_seconds": round(p.remaining(), 1),
        "total_seconds": round(p.total(), 1),
        "progress": round(p.progress(), 4),
        "completed": p.completed,
        "round_done": p.round_done,
        "next_phase": p.next_phase(),
    }


def _pomo_start(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    p = _pomodoro()
    if a["work_minutes"]:
        p.reconfigure(pomodoro.PomodoroConfig(
            work_minutes=int(a["work_minutes"]),
            short_rest_minutes=int(a["short_rest_minutes"] or 5),
            long_rest_minutes=int(a["long_rest_minutes"] or 15),
            long_every=int(a["long_every"] or 4)))
    p.start()
    return _pomo_status(p)


def _pomo_simple(action: str):
    def handler(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
        p = _pomodoro()
        getattr(p, action)()
        return _pomo_status(p)
    return handler


def _pomo_skip(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    p = _pomodoro()
    finished = p.skip()
    status = _pomo_status(p)
    status["skipped_phase"] = finished
    return status


def _pomo_status_op(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    return _pomo_status(_pomodoro())


# ---------------------------------------------------------------------------
# 代理池
# ---------------------------------------------------------------------------
def _proxy_fetch(a: dict[str, Any], ctx: Ctx) -> Any:
    init_proxy_pool()
    protocols = tuple(a["protocols"]) if a["protocols"] else None
    return to_jsonable(proxy_pool.fetch_and_verify(
        log=ctx.log, stop=ctx.stop, protocols=protocols))


def _proxy_get(a: dict[str, Any], ctx: Ctx) -> Any:
    init_proxy_pool()
    entry = proxy_pool.get_proxy()
    return to_jsonable(entry.to_dict()) if entry is not None else None


# ---------------------------------------------------------------------------
# 局域网共享（客户端）
# ---------------------------------------------------------------------------
def _lan_upload(a: dict[str, Any], ctx: Ctx) -> Any:
    path = resolve_path(a["path"], field="path", must_exist=True)
    return to_jsonable(lan_share.client_upload(
        a["base"], a["token"], path, timeout=a["timeout"]))


def _lan_download(a: dict[str, Any], ctx: Ctx) -> dict[str, Any]:
    dest = resolve_output(a["dest_dir"], "output/lanshare", field="dest_dir")
    written = lan_share.client_download(
        a["base"], a["token"], a["filename"], dest, timeout=a["timeout"])
    return {"out": str(written), "out_rel": rel(resolve_path(written, must_exist=True))}


OPS = [
    # ------------------------------------------------------------- 番茄钟
    custom_op("pomodoro_start", _pomo_start,
              "开始一轮番茄钟（可临时覆盖专注 / 休息时长）。",
              [num("work_minutes", default=None, desc="专注分钟数；留空用配置值",
                   minimum=1, maximum=180),
               num("short_rest_minutes", default=None, desc="短休息分钟数", minimum=1),
               num("long_rest_minutes", default=None, desc="长休息分钟数", minimum=1),
               num("long_every", default=None, desc="每 N 个专注后长休息", minimum=1)],
              returns="dict：当前阶段 / 剩余 / 进度 / 完成数", risk="safe",
              module="lib.pomodoro"),
    custom_op("pomodoro_pause", _pomo_simple("pause"), "暂停番茄钟。",
              [], returns="dict：当前状态", risk="safe", module="lib.pomodoro"),
    custom_op("pomodoro_resume", _pomo_simple("resume"), "继续番茄钟。",
              [], returns="dict：当前状态", risk="safe", module="lib.pomodoro"),
    custom_op("pomodoro_reset", _pomo_simple("reset"), "重置番茄钟（回到第一个专注阶段）。",
              [], returns="dict：当前状态", risk="safe", module="lib.pomodoro"),
    custom_op("pomodoro_skip", _pomo_skip, "跳过当前阶段，进入下一阶段。",
              [], returns="dict：当前状态 + skipped_phase", risk="safe",
              module="lib.pomodoro"),
    custom_op("pomodoro_status", _pomo_status_op, "查询番茄钟当前状态。",
              [], returns="dict：阶段 / 剩余秒数 / 进度 / 完成数 / 下一阶段",
              risk="safe", module="lib.pomodoro"),

    # ------------------------------------------------------------- 代理池
    make_op(proxy_pool.proxy_status, "返回全局代理池状态（启用 / 池内数量 / 统计）。", [],
            returns="dict：代理池状态", risk="safe"),
    custom_op("proxy_get", _proxy_get, "从池中取下一个可用代理（不含手动兜底）。",
              [], returns="dict|null：{protocol, host, port, ...}", risk="safe",
              module="lib.proxy_pool"),
    custom_op("proxy_fetch_and_verify", _proxy_fetch,
              "从免费源拉取代理并验证，结果装载进全局池（耗时 + 联网）。",
              [arr("protocols", default=None, desc="限定协议（http / socks5）；留空用配置")],
              returns="dict：拉取 / 验证统计", risk="network",
              module="lib.proxy_pool"),
    make_op(proxy_pool.check_available, "使用前检测：确认池内有可用代理（必要时触发拉取）。",
            [], returns="bool：是否有可用代理", risk="network"),
    make_op(proxy_pool.is_enabled, "全局代理池是否启用。", [],
            returns="bool：是否启用", risk="safe"),
    make_op(proxy_pool.should_use_proxy, "判断某个工具是否应走全局代理。",
            [txt("tool_id", default=None, desc="工具 id；留空表示默认策略")],
            returns="bool：是否走代理", risk="safe"),
    make_op(proxy_pool.config, "返回当前代理池配置副本。", [],
            returns="dict：配置", risk="safe"),

    # ------------------------------------------------- 局域网共享（客户端）
    make_op(lan_share.normalize_base, "规范化共享服务地址（``ip:port`` -> ``http://ip:port``）。",
            [txt("host", required=True, desc="主机，如 ``192.168.1.5:8517``")],
            returns="str：规范化地址", risk="safe"),
    make_op(lan_share.generate_password, "生成 4 位数字频道口令。", [],
            returns="str：口令", risk="safe"),
    make_op(lan_share.lan_ips, "枚举本机局域网 IPv4 地址。", [],
            returns="list[str]：IP 列表", risk="safe"),
    make_op(lan_share.client_channels, "获取共享服务的频道列表。",
            [txt("host", required=True, desc="共享服务地址（ip:port）"),
             flt("timeout", default=5.0, desc="超时（秒）", minimum=1)],
            returns="dict：{name, channels: [...]}", risk="network"),
    make_op(lan_share.client_join, "加入频道（校验 4 位口令，成功返回 token）。",
            [txt("host", required=True, desc="共享服务地址"),
             txt("channel", required=True, desc="频道名"),
             txt("password", required=True, desc="4 位频道口令"),
             flt("timeout", default=10.0, desc="超时（秒）", minimum=1)],
            returns="dict：{token, channel, ...}", risk="network"),
    make_op(lan_share.client_files, "获取频道内文件清单（按上传时间倒序）。",
            [txt("base", required=True, desc="服务地址"),
             txt("token", required=True, desc="join 得到的 token"),
             flt("timeout", default=15.0, desc="超时（秒）", minimum=1)],
            returns="list[dict]：文件清单", risk="network"),
    custom_op("client_upload", _lan_upload, "上传本地文件到频道。",
              [txt("base", required=True, desc="服务地址"),
               txt("token", required=True, desc="join 得到的 token"),
               txt("path", required=True, desc="本地文件路径（相对项目根或绝对）"),
               flt("timeout", default=3600.0, desc="超时（秒）", minimum=1)],
              returns="dict：上传结果", risk="network", module="lib.lan_share"),
    custom_op("client_download", _lan_download, "从频道下载文件到本地目录（自动改名防覆盖）。",
              [txt("base", required=True, desc="服务地址"),
               txt("token", required=True, desc="join 得到的 token"),
               txt("filename", required=True, desc="频道内文件名"),
               txt("dest_dir", desc="本地目标目录；留空写 output/lanshare"),
               flt("timeout", default=3600.0, desc="超时（秒）", minimum=1)],
              returns="dict：{out, out_rel}", risk="write", module="lib.lan_share"),
    make_op(lan_share.client_leave, "离开频道（释放会话）。",
            [txt("base", required=True, desc="服务地址"),
             txt("token", required=True, desc="join 得到的 token"),
             flt("timeout", default=5.0, desc="超时（秒）", minimum=1)],
            returns="null：无返回内容", risk="network"),
]


GROUP = Group(
    name="cn_misc",
    title="杂项：番茄钟 / 代理池 / 局域网共享客户端",
    summary=("番茄钟状态机（开始 / 暂停 / 继续 / 跳过 / 重置 / 查询）；"
             "全局代理池状态与拉取验证；局域网文件共享的客户端能力。"),
    ops=OPS,
    guide=("番茄钟是**进程级单例**，多次调用共享同一个状态机。"
           "共享服务端（ShareServer）不在本服务里托管，只提供客户端调用。"
           "键盘模拟（key_simulator）属于桌面交互能力，未暴露。"),
)
