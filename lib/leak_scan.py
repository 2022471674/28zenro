# -*- coding: utf-8 -*-
"""
源码泄露检测（整合 GitHack / SvnHack / Python-dsstore 三个工具）。

来源与致谢（感谢原作者的开源精神）：

- GitHack        https://github.com/lijiejie/GitHack
- SvnHack        https://github.com/shengqi158/svnhack
- Python-dsstore https://github.com/gehaxelt/Python-dsstore
"""

from __future__ import annotations

import binascii
import queue
import re
import sqlite3
import struct
import tempfile
import threading
import urllib.parse
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import requests
from requests.packages import urllib3

urllib3.disable_warnings()

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
KIND_GIT = "git"
KIND_SVN = "svn"
KIND_DS = "ds_store"
KIND_FILES = "files"

#: 各类尾路径（顺序即界面上的展示顺序；``KIND_FILES`` 用整站静态路径清单，
#: 这个 ``/`` 只是给界面上显示「目标根目录」用的占位）
SUFFIXES: dict[str, str] = {
    KIND_GIT: "/.git/",
    KIND_SVN: "/.svn/",
    KIND_DS: "/.DS_Store",
    KIND_FILES: "/",
}

KIND_LABELS: dict[str, str] = {
    KIND_GIT: "Git 泄露（.git/）",
    KIND_SVN: "SVN 泄露（.svn/）",
    KIND_DS: ".DS_Store 泄露",
    KIND_FILES: "敏感文件（vim .swp / .bak / .env 等）",
}

DEFAULT_THREADS = 8
DEFAULT_TIMEOUT = 8
MAX_FILES = 3000                      # 单次还原文件数上限
MAX_BYTES = 512 * 1024 * 1024         # 单次还原总体积上限

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
HEADERS = {"User-Agent": USER_AGENT, "Connection": "close"}

LogFn = Callable[[str], None]
ResultFn = Callable[[dict[str, Any]], None]


class LeakError(ValueError):
    """源码泄露检测失败时抛出的统一异常，由界面层捕获并展示。"""


class LeakConnectionError(LeakError):
    """目标连不上（DNS / 拒绝连接 / 超时），与「文件不存在」区分开。"""


@dataclass
class LeakResult:
    """一条尾路径的检测结论。"""

    kind: str
    url: str
    found: bool = False
    files: int = 0
    missing: int = 0
    summary: str = ""
    directory: str = ""
    error: bool = False
    names: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "label": KIND_LABELS.get(self.kind, self.kind),
            "url": self.url,
            "found": self.found,
            "files": self.files,
            "missing": self.missing,
            "summary": self.summary,
            "directory": self.directory,
            "error": self.error,
            "names": list(self.names),
        }


# ---------------------------------------------------------------------------
# 目标与文件工具
# ---------------------------------------------------------------------------
def normalize_target(raw: str) -> str:
    """把 ``example.com/upload`` 之类整理成 ``http://example.com/upload``。

    去掉末尾斜杠与查询串，缺协议时补 ``http://``。
    """
    text = str(raw or "").strip().replace("：", ":")
    if not text:
        raise LeakError("请填写目标域名，如 example.com 或 example.com/upload")
    if "://" not in text:
        text = "http://" + text
    parsed = urllib.parse.urlparse(text)
    if not parsed.hostname:
        raise LeakError("目标格式不正确，示例：example.com 或 example.com/upload")
    path = parsed.path.rstrip("/")
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def _host_dir(base: str) -> str:
    """输出目录名：``host_port``，避免不同端口互相覆盖。"""
    netloc = urllib.parse.urlparse(base).netloc or "target"
    return re.sub(r'[<>:"|?*\\/]', "_", netloc)


def _safe_join(root: Path, name: str) -> Path | None:
    """把仓库内相对路径拼到输出目录，越界（``..`` / 绝对路径）返回 None。"""
    text = str(name or "").replace("\\", "/").strip()
    if not text or text.startswith("/") or ".." in text.split("/"):
        return None
    if re.match(r"^[A-Za-z]:", text):
        return None
    target = (root / text).resolve()
    try:
        target.relative_to(root.resolve())
    except ValueError:
        return None
    return target


def _session() -> requests.Session:
    """新建会话，接入全局代理池。

    未启用代理时 ``trust_env = False``：忽略系统 HTTP_PROXY / HTTPS_PROXY。
    扫描器要直连目标，走系统代理时内网 / 回环目标会被代理直接 502（很多人
    的机器上常开 Clash 之类的全局代理，这是最容易踩的坑）。启用代理池后
    由 :mod:`lib.proxy_pool` 注入轮换代理。
    """
    from lib import proxy_pool

    session = proxy_pool.make_session("leak_scan")
    session.headers.update(HEADERS)
    return session


def _fetch(session: requests.Session, url: str, timeout: float,
           limit: int = 0) -> bytes | None:
    """GET 一个地址，404/403 返回 None，其他错误抛 :class:`LeakError`。"""
    try:
        response = session.get(url, timeout=timeout, verify=False,
                               allow_redirects=True, stream=bool(limit))
    except requests.exceptions.ConnectTimeout as exc:
        raise LeakConnectionError("连接失败：连接超时") from exc
    except requests.exceptions.ReadTimeout as exc:
        raise LeakConnectionError("连接失败：读取超时") from exc
    except requests.exceptions.SSLError as exc:
        raise LeakConnectionError("连接失败：TLS 握手失败") from exc
    except requests.RequestException as exc:
        text = str(exc)
        if ("NewConnectionError" in text or "Connection refused" in text
                or "积极拒绝" in text or "Connection aborted" in text):
            text = "目标拒绝连接（端口未开放或被防火墙拦截）"
        elif ("Name or service not known" in text
                or "getaddrinfo failed" in text or "NameResolutionError" in text):
            text = "域名解析失败"
        raise LeakConnectionError(f"连接失败：{text[:120]}") from exc
    try:
        if response.status_code in (401, 403, 404, 410):
            return None
        if response.status_code >= 400:
            return None
        if limit:
            chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_content(64 * 1024):
                chunks.append(chunk)
                total += len(chunk)
                if total > limit:
                    raise LeakError("文件超过大小上限，已跳过")
            return b"".join(chunks)
        return response.content
    finally:
        response.close()


# ---------------------------------------------------------------------------
# 一、Git 泄露
# ---------------------------------------------------------------------------
def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    """读 git 的变长整数（offset encoding），返回 (值, 新位置)。"""
    if pos >= len(data):
        raise LeakError("索引文件被截断")
    byte = data[pos]
    pos += 1
    value = byte & 0x7F
    while byte & 0x80:
        if pos >= len(data):
            raise LeakError("索引文件被截断")
        value += 1
        byte = data[pos]
        pos += 1
        value = (value << 7) + (byte & 0x7F)
    return value, pos


def parse_git_index(data: bytes) -> list[dict[str, str]]:
    """解析 ``.git/index``（DIRC，版本 2 / 3 / 4），返回 ``[{sha1, name}]``。

    格式参考 ``Documentation/technical/index-format.txt``。版本 4 用「前缀压缩」
    存路径（先给要截掉的字节数，再给后缀），且不做 8 字节对齐填充。
    """
    if len(data) < 12 or data[:4] != b"DIRC":
        raise LeakError("返回内容不是 Git 索引文件（缺少 DIRC 标记）")
    version, count = struct.unpack_from(">II", data, 4)
    if version not in (2, 3, 4):
        raise LeakError(f"暂不支持 Git 索引版本 {version}（仅支持 2 / 3 / 4）")

    entries: list[dict[str, str]] = []
    pos = 12
    prev_name = ""
    for _ in range(count):
        start = pos
        if start + 62 > len(data):
            break
        sha1 = binascii.hexlify(data[start + 40:start + 60]).decode("ascii")
        flags = struct.unpack_from(">H", data, start + 60)[0]
        namelen = flags & 0x0FFF
        extended = bool(flags & 0x4000)
        pos = start + 62
        if extended and version == 3:
            pos += 2

        if version == 4:
            strip, pos = _read_varint(data, pos)
            end = data.find(b"\x00", pos)
            if end < 0:
                break
            suffix = data[pos:end].decode("utf-8", "replace")
            pos = end + 1
            keep = max(0, len(prev_name) - strip)
            name = (prev_name[:keep] + suffix).strip()
            prev_name = name
        else:
            if namelen < 0x0FFF:
                raw_name = data[pos:pos + namelen]
                pos += namelen
            else:
                end = data.find(b"\x00", pos)
                if end < 0:
                    break
                raw_name = data[pos:end]
                pos = end
            entry_len = pos - start
            pos += (8 - (entry_len % 8)) or 8
            name = raw_name.decode("utf-8", "replace").strip()

        if name:
            entries.append({"sha1": sha1, "name": name})
    return entries


def _strip_git_blob(data: bytes) -> bytes:
    """去掉 git 对象头 ``blob <size>\\x00``（原脚本的正则在 bytes 上无效）。"""
    head = data.find(b"\x00", 0, 64)
    if head != -1 and data[:head].startswith(b"blob "):
        return data[head + 1:]
    return data


def scan_git(base: str, root: Path, timeout: float, threads: int,
             log: LogFn, stop: threading.Event | None = None) -> LeakResult:
    """拉取 ``.git/`` 还原源码。"""
    url = f"{base}{SUFFIXES[KIND_GIT]}"
    result = LeakResult(kind=KIND_GIT, url=url, directory=str(root))
    session = _session()
    try:
        log("[Git] 读取 .git/index …")
        try:
            index = _fetch(session, f"{url}index", timeout)
        except LeakConnectionError:
            raise
        except LeakError as exc:
            result.summary = f"读取 index 失败：{exc}"
            log(f"[Git] {result.summary}")
            return result
        if not index:
            result.summary = "未发现 .git/index（不存在或无权限）"
            log(f"[Git] {result.summary}")
            return result

        try:
            entries = parse_git_index(index)
        except LeakError as exc:
            result.summary = str(exc)
            log(f"[Git] {result.summary}")
            return result

        result.found = True
        root.mkdir(parents=True, exist_ok=True)
        (root / "index").write_bytes(index)
        log(f"[Git] index 解析成功：{len(entries)} 个文件条目")

        jobs: queue.Queue[dict[str, str]] = queue.Queue()
        for entry in entries:
            jobs.put(entry)

        lock = threading.Lock()
        written = 0
        missing = 0
        total_bytes = 0
        stopped = False

        def worker() -> None:
            nonlocal written, missing, total_bytes, stopped
            while True:
                if stop is not None and stop.is_set():
                    stopped = True
                    return
                try:
                    entry = jobs.get_nowait()
                except queue.Empty:
                    return
                sha1, name = entry["sha1"], entry["name"]
                target = _safe_join(root, name)
                if target is None:
                    with lock:
                        missing += 1
                    log(f"[Git] 跳过可疑路径：{name}")
                    continue
                object_url = f"{url}objects/{sha1[:2]}/{sha1[2:]}"
                try:
                    raw = _fetch(session, object_url, timeout, limit=16 * 1024 * 1024)
                except LeakError as exc:
                    with lock:
                        missing += 1
                    log(f"[Git] {name} 下载失败：{exc}")
                    continue
                if not raw:
                    with lock:
                        missing += 1
                    continue
                try:
                    payload = _strip_git_blob(zlib.decompress(raw))
                except zlib.error:
                    payload = _strip_git_blob(raw)
                with lock:
                    if written >= MAX_FILES or total_bytes + len(payload) > MAX_BYTES:
                        stopped = True
                        return
                    written += 1
                    total_bytes += len(payload)
                try:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(payload)
                except OSError as exc:
                    with lock:
                        written -= 1
                    log(f"[Git] 写入失败 {name}：{exc}")
                    continue
                log(f"[Git] [OK] {name}（{len(payload)} B）")

        count = max(1, min(int(threads), len(entries), 16))
        workers = [threading.Thread(target=worker, daemon=True,
                                    name=f"leak-git-{i}") for i in range(count)]
        for thread in workers:
            thread.start()
        for thread in workers:
            thread.join()

        result.files = written
        result.missing = missing
        result.names = sorted(
            str(p.relative_to(root)).replace("\\", "/")
            for p in root.rglob("*") if p.is_file())
        if stopped:
            result.summary = (f"已还原 {written} 个文件（触发上限 {MAX_FILES} 个 / "
                              f"{MAX_BYTES // 1024 // 1024} MB 后停止）")
        else:
            result.summary = f"已还原 {written} 个文件" + (
                f"，{missing} 个对象缺失（可能未泄露完整）" if missing else "")
        log(f"[Git] {result.summary} → {root}")
        return result
    finally:
        session.close()


# ---------------------------------------------------------------------------
# 二、SVN 泄露
# ---------------------------------------------------------------------------
_SVN_DIR_RE = re.compile(r"\n(.*?)\ndir")
_SVN_FILE_RE = re.compile(r"\n(.*?)\nfile")


def _svn_entries_parse(text: str) -> tuple[list[str], list[str]]:
    """解析 SVN 1.6 的 ``entries`` 文件，返回 (子目录, 文件名)。"""
    dirs = [d.strip() for d in _SVN_DIR_RE.findall(text) if d.strip()]
    files = [f.strip() for f in _SVN_FILE_RE.findall(text) if f.strip()]
    return dirs, files


def _svn_modern_files(db_bytes: bytes) -> list[tuple[str, str]]:
    """解析 SVN 1.7+ 的 ``wc.db``，返回 ``[(相对路径, pristine sha1)]``。"""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as handle:
        handle.write(db_bytes)
        path = handle.name
    rows: list[tuple[str, str]] = []
    try:
        con = sqlite3.connect(path)
        try:
            cursor = con.execute(
                "SELECT local_relpath, checksum FROM NODES "
                "WHERE kind = 'file' AND checksum IS NOT NULL")
            for relpath, checksum in cursor.fetchall():
                text = str(checksum or "")
                if text.startswith("$sha1$"):
                    rows.append((str(relpath), text[6:]))
        finally:
            con.close()
    except sqlite3.Error as exc:
        raise LeakError(f"wc.db 解析失败：{exc}") from exc
    finally:
        try:
            Path(path).unlink(missing_ok=True)
        except OSError:
            pass
    return rows


def scan_svn(base: str, root: Path, timeout: float, threads: int,
             log: LogFn, stop: threading.Event | None = None) -> LeakResult:
    """拉取 ``.svn/`` 还原源码（兼容 1.6 entries 与 1.7+ wc.db）。"""
    url = f"{base}{SUFFIXES[KIND_SVN]}"
    result = LeakResult(kind=KIND_SVN, url=url, directory=str(root))
    session = _session()
    try:
        log("[SVN] 探测 .svn/entries 与 .svn/wc.db …")
        entries_text = ""
        try:
            raw = _fetch(session, f"{url}entries", timeout, limit=8 * 1024 * 1024)
            if raw:
                entries_text = raw.decode("utf-8", "replace")
        except LeakConnectionError:
            raise
        except LeakError:
            entries_text = ""

        db_bytes = b""
        try:
            db_bytes = _fetch(session, f"{url}wc.db", timeout,
                              limit=64 * 1024 * 1024) or b""
        except LeakConnectionError:
            raise
        except LeakError:
            db_bytes = b""

        if not entries_text and not db_bytes:
            result.summary = "未发现 .svn/entries 或 .svn/wc.db（不存在或无权限）"
            log(f"[SVN] {result.summary}")
            return result

        result.found = True
        root.mkdir(parents=True, exist_ok=True)
        written = 0
        missing = 0
        names: list[str] = []

        # -- 1.7+：wc.db 里的 checksum 直接对应 pristine 文件 -----------------
        if db_bytes:
            log(f"[SVN] 发现 wc.db（{len(db_bytes)} B），按 1.7+ 格式还原 …")
            try:
                rows = _svn_modern_files(db_bytes)
            except LeakError as exc:
                log(f"[SVN] {exc}")
                rows = []
            (root / "wc.db").write_bytes(db_bytes)
            for relpath, sha1 in rows:
                if stop is not None and stop.is_set():
                    break
                if written >= MAX_FILES:
                    break
                target = _safe_join(root, relpath)
                if target is None:
                    continue
                pristine = f"{url}pristine/{sha1[:2]}/{sha1[2:]}.svn-base"
                try:
                    payload = _fetch(session, pristine, timeout,
                                     limit=16 * 1024 * 1024)
                except LeakError:
                    payload = None
                if not payload:
                    missing += 1
                    continue
                try:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(payload)
                except OSError as exc:
                    log(f"[SVN] 写入失败 {relpath}：{exc}")
                    continue
                written += 1
                names.append(relpath)
                log(f"[SVN] [OK] {relpath}（{len(payload)} B）")

        # -- 1.6：entries 递归，优先取 text-base 里的原始源码 ----------------
        if entries_text and not db_bytes:
            log("[SVN] 按 1.6 entries 递归拉取 …")
            pending: queue.Queue[str] = queue.Queue()
            pending.put("")
            visited: set[str] = set()
            while not pending.empty():
                if stop is not None and stop.is_set():
                    break
                if written >= MAX_FILES:
                    break
                prefix = pending.get()
                if prefix in visited:
                    continue
                visited.add(prefix)
                if len(visited) > 400:
                    log("[SVN] 目录数超过 400，停止递归")
                    break
                entries_url = (f"{base}/{prefix}/.svn/entries" if prefix
                               else f"{url}entries")
                try:
                    text = entries_text if not prefix else (
                        _fetch(session, entries_url, timeout,
                               limit=8 * 1024 * 1024) or b"").decode("utf-8", "replace")
                except LeakError:
                    continue
                if not text:
                    continue
                dirs, files = _svn_entries_parse(text)
                for sub in dirs:
                    child = f"{prefix}/{sub}" if prefix else sub
                    if _safe_join(root, child) is not None:
                        pending.put(child)
                for name in files:
                    if written >= MAX_FILES:
                        break
                    relpath = f"{prefix}/{name}" if prefix else name
                    target = _safe_join(root, relpath)
                    if target is None:
                        continue
                    base_dir = f"{base}/{prefix}" if prefix else base
                    payload = None
                    for candidate in (
                        f"{base_dir}/.svn/text-base/{name}.svn-base",
                        f"{base}/{relpath}",
                    ):
                        try:
                            payload = _fetch(session, candidate, timeout,
                                             limit=16 * 1024 * 1024)
                        except LeakError:
                            payload = None
                        if payload:
                            break
                    if not payload:
                        missing += 1
                        continue
                    try:
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(payload)
                    except OSError as exc:
                        log(f"[SVN] 写入失败 {relpath}：{exc}")
                        continue
                    written += 1
                    names.append(relpath)
                    log(f"[SVN] [OK] {relpath}（{len(payload)} B）")

        result.files = written
        result.missing = missing
        result.names = names
        mode = "1.7+（wc.db）" if db_bytes else "1.6（entries）"
        result.summary = f"{mode}：已还原 {written} 个文件" + (
            f"，{missing} 个文件缺失" if missing else "")
        log(f"[SVN] {result.summary} → {root}")
        return result
    finally:
        session.close()


# ---------------------------------------------------------------------------
# 三、.DS_Store 泄露
# ---------------------------------------------------------------------------
class _ParsingError(Exception):
    """DS_Store 结构解析失败。"""


class _DataBlock:
    """DS_Store 里的一个数据块（对应原始 dsstore.DataBlock）。"""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def read(self, length: int, offset: int | None = None) -> bytes:
        start = self.pos if offset is None else offset
        if start < 0 or start + length > len(self.data):
            raise _ParsingError("读取越界")
        if offset is None:
            self.pos += length
        return self.data[start:start + length]

    def skip(self, length: int) -> None:
        self.pos += length

    def read_filename(self) -> str:
        """读出一个文件名（UTF-16BE，长度前缀），并跳到下一条记录。"""
        (length,) = struct.unpack(">I", self.read(4))
        if length > 4096:
            raise _ParsingError("文件名长度异常")
        name = self.read(2 * length).decode("utf-16be", "replace")
        self.read(4)                     # structure id（未使用）
        structure = self.read(4).decode("latin-1")

        skips = {
            "bool": 1, "type": 4, "long": 4, "shor": 4, "fwsw": 4,
            "fwvh": 4, "icvt": 4, "lsvt": 4, "vSrn": 4, "vstl": 4,
            "comp": 8, "dutc": 8, "icgo": 8, "icsp": 8, "logS": 8,
            "lg1S": 8, "lssp": 8, "modD": 8, "moDD": 8, "phyS": 8,
            "ph1S": 8, "BKGD": 12, "ICVO": 1, "LSVO": 1, "dscl": 1,
            "Iloc": 16, "fwi0": 16, "dilc": 32, "lsvo": 76,
        }
        if structure == "blob":
            (blen,) = struct.unpack(">I", self.read(4))
            skip = blen
        elif structure in ("ustr", "cmmt", "extn", "GRP0"):
            (blen,) = struct.unpack(">I", self.read(4))
            skip = 2 * blen
        elif structure in skips:
            skip = skips[structure]
        else:
            # 未知类型：按原始实现的「voodoo」重试一次
            self.skip(-8)
            name += self.read(2).decode("utf-16be", "replace")
            self.read(8)
            skip = 1
        self.skip(skip)
        return name


class _DSStore:
    """解析 ``.DS_Store``，取出目录下出现过的文件名。"""

    def __init__(self, data: bytes) -> None:
        if len(data) < 36:
            raise _ParsingError("文件太短，不是 .DS_Store")
        if data[:4] != b"\x00\x00\x00\x01" or data[4:8] != b"Bud1":
            raise _ParsingError("缺少 Bud1 标记，不是 .DS_Store")
        self.data = data
        root = _DataBlock(data)
        root.read(8)
        offset, size, offset2 = struct.unpack(">III", root.read(12))
        if offset != offset2 or offset + size > len(data):
            raise _ParsingError("头信息不完整")
        root.read(16)
        self.root = _DataBlock(root.read(size, offset + 4))
        self._read_offsets()
        self.toc = self._read_toc()
        self._read_freelist()

    def _read_offsets(self) -> None:
        block = self.root
        (count,) = struct.unpack(">I", block.read(4))
        block.read(4)
        offsets = []
        for _ in range(count):
            (address,) = struct.unpack(">I", block.read(4))
            if address:
                offsets.append(address)
        section_end = (count // 256 + 1) * 256 * 4 - count * 4
        block.skip(max(0, section_end))
        self.offsets = offsets

    def _read_toc(self) -> dict[str, int]:
        block = self.root
        (count,) = struct.unpack(">I", block.read(4))
        toc: dict[str, int] = {}
        for _ in range(count):
            (name_len,) = struct.unpack(">b", block.read(1))
            if name_len <= 0:
                continue
            name = block.read(name_len).decode("latin-1")
            (block_id,) = struct.unpack(">I", block.read(4))
            toc[name] = block_id
        return toc

    def _read_freelist(self) -> None:
        block = self.root
        for _ in range(32):
            (count,) = struct.unpack(">I", block.read(4))
            block.skip(4 * count)

    def _block(self, block_id: int) -> _DataBlock:
        if block_id >= len(self.offsets):
            raise _ParsingError("块编号越界")
        address = self.offsets[block_id]
        offset = (address >> 5) << 5
        size = 1 << (address & 0x1F)
        return _DataBlock(self.data[offset + 4:offset + 4 + size])

    def names(self) -> list[str]:
        """从 DSDB 根块开始遍历，返回全部文件名。"""
        if "DSDB" not in self.toc:
            raise _ParsingError("缺少 DSDB 目录块")
        root = self._block(self.toc["DSDB"])
        (root_id,) = struct.unpack(">I", root.read(4))
        root.read(16)
        found: list[str] = []
        self._traverse(root_id, found, depth=0)
        # 去重并保持出现顺序
        seen: set[str] = set()
        result = []
        for name in found:
            text = name.strip()
            if text and text not in seen:
                seen.add(text)
                result.append(text)
        return result

    def _traverse(self, block_id: int, out: list[str], depth: int) -> None:
        if depth > 64 or len(out) > 20000:
            return
        node = self._block(block_id)
        (next_pointer,) = struct.unpack(">I", node.read(4))
        (count,) = struct.unpack(">I", node.read(4))
        if count > 10000:
            raise _ParsingError("记录数异常")
        if next_pointer > 0:
            for _ in range(count):
                (child,) = struct.unpack(">I", node.read(4))
                self._traverse(child, out, depth + 1)
                out.append(node.read_filename())
            self._traverse(next_pointer, out, depth + 1)
        else:
            for _ in range(count):
                out.append(node.read_filename())


def scan_ds_store(base: str, root: Path, timeout: float, threads: int,
                  log: LogFn, stop: threading.Event | None = None) -> LeakResult:
    """拉取 ``/.DS_Store`` 并解析出目录里的文件名。"""
    url = f"{base}{SUFFIXES[KIND_DS]}"
    result = LeakResult(kind=KIND_DS, url=url, directory=str(root))
    session = _session()
    try:
        log("[DS_Store] 请求 /.DS_Store …")
        try:
            data = _fetch(session, url, timeout, limit=8 * 1024 * 1024)
        except LeakConnectionError:
            raise
        except LeakError as exc:
            result.summary = f"读取失败：{exc}"
            log(f"[DS_Store] {result.summary}")
            return result
        if not data:
            result.summary = "未发现 .DS_Store（不存在或无权限）"
            log(f"[DS_Store] {result.summary}")
            return result

        result.found = True
        root.mkdir(parents=True, exist_ok=True)
        (root / ".DS_Store").write_bytes(data)
        try:
            names = _DSStore(data).names()
        except (_ParsingError, struct.error, ValueError) as exc:
            result.summary = f"已下载但解析失败：{exc}"
            log(f"[DS_Store] {result.summary}")
            return result

        listing = root / "_ds_store_list.txt"
        listing.write_text("\n".join(names) + ("\n" if names else ""),
                           encoding="utf-8")
        result.files = len(names)
        result.names = names
        result.summary = f"解析出 {len(names)} 个文件名（已存为 _ds_store_list.txt）"
        for name in names[:200]:
            log(f"[DS_Store] {name}")
        if len(names) > 200:
            log(f"[DS_Store] …… 共 {len(names)} 条，完整清单见 {listing}")
        log(f"[DS_Store] {result.summary} → {root}")
        return result
    finally:
        session.close()


# ---------------------------------------------------------------------------
# 四、敏感文件 / 编辑器临时文件泄露（vim .swp 等）
# ---------------------------------------------------------------------------
#: 软 404 探针：基本不存在的随机路径，用来取「404 页面」的样貌做基线。
_SOFT404_TOKEN = ".cn-leak-probe-0000000000000000"

#: 打包类文件扩展名 -> 文件头魔数；命中这类路径时额外校验文件头，
#: 避免把「自定义 404 / 空页」误报成整站备份包。
_ARCHIVE_MAGIC: tuple[tuple[str, bytes], ...] = (
    (".zip", b"PK\x03\x04"),
    (".war", b"PK\x03\x04"),
    (".jar", b"PK\x03\x04"),
    (".rar", b"Rar!\x1a\x07"),
    (".7z", b"7z\xbc\xaf\x27\x1c"),
    (".tar.gz", b"\x1f\x8b"),
    (".tgz", b"\x1f\x8b"),
)

#: 静态探测清单：相对站点根目录的路径（不含开头斜杠）。分组覆盖：
#: **编辑器临时文件**（vim 交换 ``.{name}.swp`` / ``.swo``、行内备份
#: ``{name}~``、``.bak`` / ``.old`` / ``.save``）、**VCS 残留**
#: （``.hg`` / ``.bzr`` / ``CVS``）、**敏感配置**（``.env`` / commit
#: 文件 / IDE 配置）、**整站打包**、**SQL 转储**、**调试端点**
#: （phpinfo / Apache server-status / Spring Actuator / Druid 等）。
SCAN_PATHS: tuple[str, ...] = (
    # -- 编辑器临时文件 / 备份（vim 交换文件、~、.bak） --
    ".index.php.swp", ".index.php.swo",
    ".index.html.swp", ".index.html.swo",
    ".index.jsp.swp", ".index.asp.swp",
    ".config.php.swp", ".database.php.swp",
    "index.php~", "index.html~", "index.jsp~",
    "index.asp~", "index.aspx~", "web.config~",
    "index.php.swp",
    "index.php.bak", "index.php.old", "index.php.save",
    "config.php.bak", "db.php.bak", "database.php.bak",
    "common.inc.bak",
    "index.html.bak", "web.config.bak", "web.config.old",
    ".htaccess~", ".htaccess.bak", ".htaccess.old",
    # -- VCS 残留（git / svn 之外的三家） --
    ".hg/hgrc", ".hg/store/fncache", ".hg/store/00changelog.i",
    ".bzr/README", ".bzr/branch-format",
    "CVS/Root", "CVS/Entries",
    # -- 环境变量与工程配置 --
    ".env", ".env.bak", ".env.local", ".env.production", ".env.development",
    "application.yml", "application.properties",
    "web.config", "WEB-INF/web.xml",
    ".gitignore", "phpunit.xml.dist",
    "composer.json", "composer.lock", "package.json", "yarn.lock",
    "npm-debug.log",
    ".vscode/settings.json", ".idea/workspace.xml",
    # -- Windows 目录元数据（当前路径只测根目录） --
    "Thumbs.db", "desktop.ini",
    # -- 整站打包备份 --
    "www.zip", "www.tar.gz", "www.rar", "www.7z",
    "web.zip", "web.tar.gz", "web.rar", "web.7z",
    "web.war", "ROOT.war",
    "site.zip", "source.zip", "backup.zip", "backup.tar.gz", "backup.rar",
    # -- SQL 转储 --
    "database.sql", "db.sql", "backup.sql", "dump.sql", "data.sql",
    # -- 命令历史 / 调试端点 --
    ".bash_history", ".mysql_history",
    "phpinfo.php", "info.php",
    "server-status", "server-info",
    "actuator", "actuator/heapdump", "actuator/env",
    "druid/index.html",
    "swagger-ui.html", "swagger-ui/index.html",
)


def _archive_magic(path: str) -> bytes | None:
    """该路径若是打包类文件，返回期望的文件头魔数；否则返回 ``None``。"""
    lower = str(path).lower()
    for suffix, magic in _ARCHIVE_MAGIC:
        if lower.endswith(suffix):
            return magic
    return None


def scan_files(base: str, root: Path, timeout: float, threads: int,
               log: LogFn, stop: threading.Event | None = None) -> LeakResult:
    """按 :data:`SCAN_PATHS` 静态清单并发探测敏感文件（只报告，不还原）。

    三重降噪，避免自定义 404 页把结果撑爆：
    1. 每个目标先请求一个基本不存在的随机路径取「软 404」基线，正文
       哈希相同的直接判为不存在；
    2. 打包类路径（``.zip`` / ``.rar`` / ``.tar.gz`` 等）额外校验文件头
       魔数，内容不符按缓存页 / 伪装页处理；
    3. ``401`` / ``403`` / ``404`` / ``410`` 与其它 4xx 都不记命中
       （:func:`_fetch` 里统一处理）。
    """
    url = f"{base}{SUFFIXES[KIND_FILES]}"
    result = LeakResult(kind=KIND_FILES, url=url, directory=str(root))
    session = _session()
    try:
        # -- 1. 软 404 基线 --------------------------------------------------
        log("[Sensitive] 采集 404 基线 …")
        try:
            baseline = _fetch(session, f"{base}/{_SOFT404_TOKEN}", timeout,
                              limit=512 * 1024)
        except LeakConnectionError:
            raise
        except LeakError as exc:
            result.summary = f"基线探测失败：{exc}"
            log(f"[Sensitive] {result.summary}")
            return result

        # -- 2. 并发探测 ----------------------------------------------------
        jobs: queue.Queue[str] = queue.Queue()
        for path in SCAN_PATHS:
            jobs.put(path)

        lock = threading.Lock()
        hits: list[tuple[str, int, str]] = []
        soft404 = 0
        stopped = False

        def worker() -> None:
            nonlocal soft404, stopped
            while True:
                if stop is not None and stop.is_set():
                    stopped = True
                    return
                try:
                    path = jobs.get_nowait()
                except queue.Empty:
                    return
                target = f"{base}/{path}"
                try:
                    data = _fetch(session, target, timeout, limit=32 * 1024)
                except LeakConnectionError as exc:
                    # 目标整体连不上：交给外层统一报告
                    with lock:
                        result.found = False
                        result.summary = str(exc)
                        result.error = True
                    return
                except LeakError as exc:
                    with lock:
                        soft404 += 1
                    log(f"[Sensitive] {path} 响应异常：{exc}")
                    continue
                if not data:
                    continue        # 明确 4xx：不算命中也不算软 404
                if baseline and data == baseline:
                    with lock:
                        soft404 += 1
                    continue        # 与 404 页面同正文：软 404
                magic = _archive_magic(path)
                if magic and not data.startswith(magic):
                    with lock:
                        soft404 += 1
                    log(f"[Sensitive] {path} 内容与扩展名不符，"
                        "疑似伪装页（或缓存的路由响应），已忽略")
                    continue
                note = f"{len(data)} 字节" + (
                    "" if not magic else "（文件头校验通过）")
                with lock:
                    hits.append((path, len(data), note))
                log(f"[Sensitive] 命中 {path}：{note}")

        scan_threads = max(1, int(threads))
        workers = [threading.Thread(target=worker, daemon=True,
                                    name=f"leakfiles-{i}")
                   for i in range(scan_threads)]
        for one in workers:
            one.start()
        for one in workers:
            one.join()

        # -- 3. 汇总 --------------------------------------------------------
        if result.error:
            log(f"[Sensitive] {result.summary}")
            return result
        if stopped:
            result.summary = "已手动停止"
            return result
        with lock:
            result.found = bool(hits)
            result.files = len(hits)
            result.missing = max(0, len(SCAN_PATHS) - len(hits) - soft404)
            result.names = [path for path, _size, _note in hits]
            if hits:
                root.mkdir(parents=True, exist_ok=True)
                listing = root / "_files_hits.txt"
                lines = [f"{path} | {size} 字节 | {note}"
                         for path, size, note in hits]
                listing.write_text(
                    f"# base: {base}\n# hits: {len(hits)}\n"
                    + "\n".join(lines) + "\n", encoding="utf-8")
                result.summary = (
                    f"命中 {len(hits)} 个敏感文件（清单已存为 _files_hits.txt）")
            else:
                result.summary = (
                    f"清单 {len(SCAN_PATHS)} 条无一命中（软 404 / 异常 {soft404} 条）")
            for path, size, note in hits[:200]:
                log(f"[Sensitive] {path} | {size} 字节 | {note}")
            if len(hits) > 200:
                log(f"[Sensitive] …… 共 {len(hits)} 条，完整清单见 {listing}")
            log(f"[Sensitive] {result.summary} → {root / 'files'}")
        return result
    finally:
        session.close()


# ---------------------------------------------------------------------------
# 五、统一入口
# ---------------------------------------------------------------------------
_SCANNERS = {
    KIND_GIT: scan_git,
    KIND_SVN: scan_svn,
    KIND_DS: scan_ds_store,
    KIND_FILES: scan_files,
}


def run(
    target: str,
    out_dir: str | Path,
    kinds: list[str] | tuple[str, ...] | None = None,
    threads: int = DEFAULT_THREADS,
    timeout: float = DEFAULT_TIMEOUT,
    log: LogFn | None = None,
    result: ResultFn | None = None,
    stop: threading.Event | None = None,
) -> list[dict[str, Any]]:
    """按类检测泄露尾路径，返回每条的结果 dict 列表。

    - ``target``：域名或带目录的域名，缺协议自动补 ``http://``；
    - ``kinds``：要检测的类型（git / svn / ds_store / files，默认全查）；
    - ``log``：逐行日志回调（界面直接追加到日志框）；
    - ``result``：每完成一条立即回调（界面增量填表）；
    - ``stop``：置位后不再开始新的类型，已开始的会尽快结束。
    """
    base = normalize_target(target)
    host_dir = _host_dir(base)
    root = Path(out_dir) / host_dir
    selected = [k for k in (kinds or list(SUFFIXES)) if k in _SCANNERS]
    if not selected:
        raise LeakError("请至少选择一种检测类型")

    emit = log or (lambda _msg: None)
    emit(f"[目标] {base}")
    emit(f"[输出] {root}")

    results: list[dict[str, Any]] = []
    for index, kind in enumerate(selected):
        if stop is not None and stop.is_set():
            emit("[中止] 已停止检测")
            break
        emit(f"===== {KIND_LABELS[kind]}：{base}{SUFFIXES[kind]} =====")
        try:
            item = _SCANNERS[kind](base, root / kind, timeout, threads, emit, stop)
        except LeakConnectionError as exc:
            # 连不上就没必要再试另外两条尾路径了：同一个错误填满剩余项
            emit(f"[错误] {exc}")
            for rest in selected[index:]:
                payload = LeakResult(
                    kind=rest, url=f"{base}{SUFFIXES[rest]}",
                    summary=str(exc), error=True,
                    directory=str(root / rest)).to_dict()
                results.append(payload)
                if result is not None:
                    result(payload)
            break
        except LeakError as exc:
            item = LeakResult(kind=kind, url=f"{base}{SUFFIXES[kind]}",
                              summary=str(exc), directory=str(root / kind))
            emit(f"[错误] {exc}")
        except Exception as exc:  # noqa: BLE001  单个类型失败不影响其他类型
            item = LeakResult(kind=kind, url=f"{base}{SUFFIXES[kind]}",
                              summary=f"检测异常：{exc}", directory=str(root / kind))
            emit(f"[错误] {exc}")
        payload = item.to_dict()
        results.append(payload)
        if result is not None:
            result(payload)

    found = sum(1 for item in results if item["found"])
    emit(f"[完成] {len(results)} 项检测，命中 {found} 项")
    return results
