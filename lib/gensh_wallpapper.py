# -*- coding: utf-8 -*-
"""原神随机壁纸（xxapi 免费接口）。

接口返回形如::

    {"code": 200, "msg": "获取成功", "data": "https://images.xxapi.cn/images/ys/image_xxx.jpg"}

图片直链在 ``data`` 字段，页面拿到后自行下载展示。
"""

from __future__ import annotations

import requests

URI = "https://v2.xxapi.cn/api/ys?return=json"
DEFAULT_TIMEOUT = 10.0


def get_wallpaper_url(timeout: float = DEFAULT_TIMEOUT) -> str:
    """请求原神随机壁纸接口，返回图片直链 URL。"""
    rep = requests.get(url=URI, timeout=timeout)
    rep.raise_for_status()
    data = rep.json()
    return data.get("data", "") or ""


def download_wallpaper(timeout: float = DEFAULT_TIMEOUT) -> bytes:
    """请求随机壁纸接口并下载图片字节，返回原始图片数据。"""
    url = get_wallpaper_url(timeout=timeout)
    if not url:
        raise RuntimeError("接口未返回图片地址")
    rep = requests.get(url=url, timeout=timeout)
    rep.raise_for_status()
    return rep.content
