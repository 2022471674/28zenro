# -*- coding: utf-8 -*-
"""时间戳转换纯逻辑模块。

只做「输入进出」的纯计算，不导入任何 UI 模块：

- 时间戳 -> 日期时间：按秒 / 毫秒 / 微秒 / 纳秒自动识别时间戳精度，
  转成可读的本地时间与 UTC 时间字符串。
- 日期时间 -> 时间戳：把日期时间字符串解析后转成秒 / 毫秒 / 微秒 /
  纳秒时间戳。

精度识别规则：根据数字的位数 / 量级判断（见 :func:`detect_unit`）。
"""

from __future__ import annotations

import datetime as _dt
import time as _time


class TimeCodecError(ValueError):
    """时间戳非法时抛出，由界面层统一捕获并展示。"""


#: 精度单位常量
UNIT_SECOND = "second"
UNIT_MILLISECOND = "millisecond"
UNIT_MICROSECOND = "microsecond"
UNIT_NANOSECOND = "nanosecond"

#: 单位 -> 显示名
UNIT_NAMES = {
    UNIT_SECOND: "秒",
    UNIT_MILLISECOND: "毫秒",
    UNIT_MICROSECOND: "微秒",
    UNIT_NANOSECOND: "纳秒",
}

#: 单位 -> 换算到秒的系数
_UNIT_FACTOR = {
    UNIT_SECOND: 1.0,
    UNIT_MILLISECOND: 1e3,
    UNIT_MICROSECOND: 1e6,
    UNIT_NANOSECOND: 1e9,
}


def detect_unit(ts: int) -> str:
    """根据时间戳的位数自动识别精度单位。

    规则（按十进制位数判断，正负时间戳都适用）：

    - 10 位（约 1e9 ~ 1e10）     -> 秒（如 1700000000）
    - 13 位（约 1e12 ~ 1e13）     -> 毫秒（如 1700000000000）
    - 16 位（约 1e15 ~ 1e16）     -> 微秒（如 1700000000000000）
    - 19 位（约 1e18 ~ 1e19）     -> 纳秒

    中间位数的（11/12/14/15/17/18 位）按就近原则归入相邻档位；
    10 位以下按秒处理，19 位以上按纳秒处理。
    """
    if not isinstance(ts, int):
        raise TimeCodecError("时间戳必须是整数。")
    if ts == 0:
        return UNIT_SECOND
    digits = len(str(abs(ts)))
    if digits <= 10:
        return UNIT_SECOND
    if digits <= 13:
        return UNIT_MILLISECOND
    if digits <= 16:
        return UNIT_MICROSECOND
    return UNIT_NANOSECOND


def _ts_to_seconds(ts: int, unit: str) -> float:
    """把时间戳按单位换算成秒（浮点）。"""
    factor = _UNIT_FACTOR.get(unit)
    if factor is None:
        raise TimeCodecError(f"未知精度单位：{unit}")
    return float(ts) / factor


def _format_dt(dt: _dt.datetime) -> str:
    """格式化为 ``YYYY-MM-DD HH:MM:SS``。"""
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def ts_to_datetime(ts: int, unit: str | None = None) -> dict:
    """把时间戳转成日期时间（本地 + UTC）。

    返回 dict：``unit``（实际单位）、``local``、``utc``、``seconds``、
    ``iso_local``、``iso_utc``。
    """
    if not isinstance(ts, int):
        raise TimeCodecError("时间戳必须是整数。")
    unit = unit or detect_unit(ts)
    secs = _ts_to_seconds(ts, unit)

    # 本地时间（含时区）与 UTC 时间
    local = _dt.datetime.fromtimestamp(secs)
    utc = _dt.datetime.fromtimestamp(secs, tz=_dt.timezone.utc)

    return {
        "unit": unit,
        "unit_name": UNIT_NAMES.get(unit, unit),
        "seconds": secs,
        "local": _format_dt(local),
        "utc": _format_dt(utc),
        "iso_local": local.isoformat(),
        "iso_utc": utc.replace(tzinfo=_dt.timezone.utc).isoformat(),
        "weekday": local.strftime("%A"),
    }


def datetime_to_ts(text: str, unit: str = UNIT_SECOND) -> dict:
    """把日期时间字符串转成时间戳。

    支持多种常见格式：``YYYY-MM-DD HH:MM:SS``、``YYYY/MM/DD HH:MM:SS``、
    ISO 8601（``YYYY-MM-DDTHH:MM:SS`` 及其带时区变体）、
    ``YYYY-MM-DD``（视为当天 00:00:00）。返回 dict：``unit``、``ts``、
    ``local``、``utc``。
    """
    text = (text or "").strip()
    if not text:
        raise TimeCodecError("日期时间不能为空。")

    dt = _parse_datetime(text)
    secs = dt.timestamp()  # 本地时区 -> 秒
    factor = _UNIT_FACTOR.get(unit)
    if factor is None:
        raise TimeCodecError(f"未知精度单位：{unit}")

    ts = int(round(secs * factor))
    return {
        "unit": unit,
        "unit_name": UNIT_NAMES.get(unit, unit),
        "ts": ts,
        "local": _format_dt(dt),
        "utc": _format_dt(dt.astimezone(_dt.timezone.utc)),
    }


def _parse_datetime(text: str) -> _dt.datetime:
    """解析常见日期时间字符串为本地时区 aware datetime。"""
    # 依次尝试多种格式
    formats = (
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y/%m/%d %H:%M",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%d",
        "%Y/%m/%d",
    )
    for fmt in formats:
        try:
            dt = _dt.datetime.strptime(text, fmt)
            # 无时区信息视为本地时区
            if dt.tzinfo is None:
                return dt.astimezone()  # 附加本地时区
            return dt
        except ValueError:
            continue

    # ISO 8601 带时区（如 2026-01-01T12:00:00+08:00 / Z）
    iso_text = text.replace("Z", "+00:00")
    try:
        dt = _dt.datetime.fromisoformat(iso_text)
        if dt.tzinfo is None:
            dt = dt.astimezone()
        return dt
    except ValueError:
        pass

    raise TimeCodecError(
        f"无法解析日期时间：{text!r}。支持格式如 "
        "「2026-01-01 12:00:00」「2026/01/01 12:00:00」"
        "「2026-01-01T12:00:00」等。"
    )


def now_timestamp(unit: str = UNIT_SECOND) -> dict:
    """取当前时间的时间戳与日期时间。"""
    secs = _time.time()
    factor = _UNIT_FACTOR.get(unit)
    if factor is None:
        raise TimeCodecError(f"未知精度单位：{unit}")
    ts = int(secs * factor)
    return {
        "unit": unit,
        "unit_name": UNIT_NAMES.get(unit, unit),
        "ts": ts,
        "local": _format_dt(_dt.datetime.fromtimestamp(secs)),
        "utc": _format_dt(_dt.datetime.fromtimestamp(secs, tz=_dt.timezone.utc)),
    }
