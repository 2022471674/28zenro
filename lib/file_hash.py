# -*- coding: utf-8 -*-
"""文件哈希分析纯逻辑模块。

只做「文件进出哈希」的纯计算，不导入任何 UI 模块。流式读取大文件，
支持多种摘要算法与 CRC32，便于界面层一键计算并展示。

命名约定沿用项目规范：哈希函数以 ``_hex`` 结尾（返回十六进制摘要字符串）。
"""

from __future__ import annotations

import hashlib
import zlib
from pathlib import Path


class FileHashError(ValueError):
    """文件读取或参数非法时抛出，由界面层统一捕获并展示。"""


#: 支持的摘要算法：算法名 -> (hashlib 名称, 显示名)
ALGORITHMS: dict[str, tuple[str, str]] = {
    "md5": ("md5", "MD5"),
    "sha1": ("sha1", "SHA1"),
    "sha256": ("sha256", "SHA256"),
    "sha512": ("sha512", "SHA512"),
    "sha3_256": ("sha3_256", "SHA3-256"),
    "crc32": ("", "CRC32"),
}

#: 分块读取大小（流式，内存占用与文件大小无关）
_CHUNK = 1024 * 1024


def _hasher_for(algo: str):
    """取某个算法的 hashlib 构造器；CRC32 返回 None（单独处理）。"""
    name, _ = ALGORITHMS.get(algo, ("", ""))
    if not name:
        return None
    return getattr(hashlib, name)


def hash_file(path: str, algo: str) -> str:
    """计算单个文件的某一种哈希，返回十六进制摘要字符串（小写）。

    CRC32 返回 8 位十六进制；其余返回对应算法的小写 hexdigest。
    """
    if algo not in ALGORITHMS:
        raise FileHashError(f"不支持的哈希算法：{algo}")
    src = Path(path)
    if not src.is_file():
        raise FileHashError(f"文件不存在：{path}")

    if algo == "crc32":
        return crc32_file(path)

    hasher = _hasher_for(algo)()
    with open(src, "rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def crc32_file(path: str) -> str:
    """计算文件的 CRC32（返回 8 位十六进制，小写）。"""
    src = Path(path)
    if not src.is_file():
        raise FileHashError(f"文件不存在：{path}")
    crc = 0
    with open(src, "rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            crc = zlib.crc32(chunk, crc)
    return f"{crc & 0xFFFFFFFF:08x}"


def hash_file_all(path: str, algos: tuple[str, ...] | None = None) -> dict:
    """一次性计算文件的多种哈希，返回 ``{算法名: 摘要字符串}``。

    ``algos`` 缺省时计算全部支持算法。读取一次文件即可完成所有算法，
    避免大文件重复读取。
    """
    src = Path(path)
    if not src.is_file():
        raise FileHashError(f"文件不存在：{path}")
    algos = tuple(algos) if algos else tuple(ALGORITHMS.keys())
    for a in algos:
        if a not in ALGORITHMS:
            raise FileHashError(f"不支持的哈希算法：{a}")

    # CRC32 与其他 hashlib 算法分开维护
    hashers: dict[str, object] = {}
    crc = 0
    include_crc = "crc32" in algos
    for a in algos:
        if a == "crc32":
            continue
        hashers[a] = _hasher_for(a)()

    with open(src, "rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            for h in hashers.values():
                h.update(chunk)
            if include_crc:
                crc = zlib.crc32(chunk, crc)

    result: dict[str, str] = {}
    for a in algos:
        if a == "crc32":
            result[a] = f"{crc & 0xFFFFFFFF:08x}"
        else:
            result[a] = hashers[a].hexdigest()
    return result


def file_info(path: str) -> dict:
    """返回文件基本信息：大小、修改时间等（供界面展示）。"""
    src = Path(path)
    if not src.is_file():
        raise FileHashError(f"文件不存在：{path}")
    st = src.stat()
    return {
        "path": str(src),
        "name": src.name,
        "size": st.st_size,
    }
