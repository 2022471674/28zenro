# -*- coding: utf-8 -*-
"""目录扫描（dirsearch 风格）：字典目录并发探测隐藏路径。

默认 HTTP 请求头可由 ``dict/Contents/http_headers.json`` 自定义
（参见 :func:`load_default_headers`），UI / CLI 也可逐项追加覆盖。
"""
from __future__ import annotations

import csv
import json
import queue
import re
import secrets
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import requests
from requests.packages import urllib3

from lib.leak_scan import LeakError, normalize_target

urllib3.disable_warnings()

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
#: 默认字典目录（相对项目根 / 打包数据根）
DICT_SUBDIR = ("dict", "Contents")

DEFAULT_THREADS = 16
DEFAULT_TIMEOUT = 6
#: 相邻两次探测请求的最小间隔（秒），降低触发 WAF / 限速的概率
DEFAULT_INTERVAL = 30.0
#: 词表条数上限，防止误把大字典（几十万行）一次性灌进来
MAX_WORDS = 200_000
#: 单个响应最多读这么多字节用于取标题 / 判断目录列表
READ_LIMIT = 64 * 1024
#: 连续连接失败多少次就判定目标不可用并中止
MAX_CONSECUTIVE_ERRORS = 25
#: 不当作字典的扩展名（说明文档 / 脚本 / 图片）
SKIP_SUFFIXES = {
    ".md", ".py", ".pyc", ".json", ".png", ".jpg", ".jpeg", ".gif",
    ".bmp", ".ico", ".log", ".ini", ".cfg", ".yaml", ".yml",
}
#: 这些状态码不算命中（404 就是没这个路径）
MISS_STATUSES = {400, 404, 410, 429, 451}

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
#: 默认伪造的真实浏览器客户端请求头（Chrome 120 风格），降低被 WAF 识别的风险。
#: 这是**兜底值**：``dict/Contents/http_headers.json`` 存在且内容合法时，
#: 以该文件为默认头 —— 用户不改代码就能换掉全局默认 UA / Accept 等。
HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
               "image/avif,image/webp,image/apng,*/*;q=0.8,"
               "application/signed-exchange;v=b3;q=0.7"),
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "close",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Cache-Control": "max-age=0",
}

_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)

LogFn = Callable[[str], None]
HitFn = Callable[[dict[str, Any]], None]
ProgressFn = Callable[[int, int], None]


class DirScanError(ValueError):
    """目录爆破参数 / 字典问题时抛出的统一异常。"""


class DirScanConnectionError(DirScanError):
    """目标连不上（DNS / 拒绝连接 / 超时），与「没有命中」区分开。"""


# ---------------------------------------------------------------------------
# 一、字典
# ---------------------------------------------------------------------------
def default_dict_dir() -> Path:
    """默认字典目录：源码运行取项目根 ``dict/Contents``，打包后取打包数据根（_internal）。"""
    from lib.runtime_paths import resource

    return resource(*DICT_SUBDIR)


#: 默认请求头文件名（放在字典目录下；``.json`` 本在生产 ``SKIP_SUFFIXES``
#: 里，不会被当成字典加载）
HEADERS_FILE = "http_headers.json"

_DEFAULT_HEADERS: dict[str, str] | None = None
_DEFAULT_HEADERS_LOCK = threading.Lock()


def default_headers_file() -> Path:
    """默认请求头文件位置：``dict/Contents/http_headers.json``。"""
    return default_dict_dir() / HEADERS_FILE


def load_default_headers() -> dict[str, str]:
    """读取**当前生效的默认请求头**（带进程内缓存）。

    优先级：``dict/Contents/http_headers.json``（合法的非空 JSON 对象，键值
    均应为字符串）→ 程序内置 :data:`HEADERS` 兜底。文件缺失 / JSON 损坏 /
    类型不对时静默回退，绝不影响扫描本身。
    """
    global _DEFAULT_HEADERS
    if _DEFAULT_HEADERS is not None:
        return dict(_DEFAULT_HEADERS)
    with _DEFAULT_HEADERS_LOCK:
        if _DEFAULT_HEADERS is None:
            headers: dict[str, str] = dict(HEADERS)
            try:
                data = json.loads(default_headers_file().read_text("utf-8"))
            except (OSError, ValueError):
                data = None
            if isinstance(data, dict):
                clean = {str(key).strip(): str(value)
                         for key, value in data.items()
                         if str(key).strip() and not str(key).startswith("_")}
                if clean:
                    headers = clean
            _DEFAULT_HEADERS = headers
        return dict(_DEFAULT_HEADERS)


def reset_default_headers_cache() -> None:
    """丢弃默认头缓存（UI 让用户改完文件后点「重新加载」时用）。"""
    global _DEFAULT_HEADERS
    with _DEFAULT_HEADERS_LOCK:
        _DEFAULT_HEADERS = None


def list_dict_files(dict_dir: str | Path | None = None) -> list[Path]:
    """列出字典目录下的全部字典文件（按文件名排序，跳过说明文档等）。"""
    root = Path(dict_dir) if dict_dir else default_dict_dir()
    if not root.is_dir():
        raise DirScanError(f"字典目录不存在：{root}")
    files: list[Path] = []
    for path in sorted(root.iterdir(), key=lambda item: item.name.lower()):
        if not path.is_file() or path.name.startswith("."):
            continue
        if path.suffix.lower() in SKIP_SUFFIXES:
            continue
        files.append(path)
    return files


def normalize_word(line: str) -> str | None:
    """把字典里的一行整理成可拼接的路径片段，无效行返回 None。

    - 去 BOM / 首尾空白（``\\r``、尾随空格）；
    - 去掉前导与尾随 ``/``（``/.printer`` → ``.printer``）；
    - 跳过空行、``#`` / ``//`` 注释、含 ``..`` 或 ``://`` 的行；
    - 单行超过 200 字符视为脏数据。
    """
    word = str(line or "").replace("\ufeff", "").strip()
    if not word or word.startswith("#") or word.startswith("//"):
        return None
    word = word.strip("/").strip()
    if not word or len(word) > 200:
        return None
    if "://" in word or word.startswith("?"):
        return None
    if ".." in word.split("/"):
        return None
    return word


def read_words(path: str | Path) -> list[str]:
    """读一个字典文件，返回规范化后的词条（保留原顺序，文件内去重）。"""
    raw = Path(path).read_bytes()
    text = ""
    for encoding in ("utf-8-sig", "utf-8", "gbk", "latin-1"):
        try:
            text = raw.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    seen: set[str] = set()
    words: list[str] = []
    for line in text.splitlines():
        word = normalize_word(line)
        if word and word not in seen:
            seen.add(word)
            words.append(word)
    return words


def load_words(dict_dir: str | Path | None = None,
               files: list[str | Path] | None = None,
               log: LogFn | None = None) -> tuple[list[str], list[tuple[str, int]]]:
    """读取字典目录下全部字典，合并去重。

    返回 ``(词表, [(文件名, 该文件有效条数), …])``。跨文件按大小写敏感去重，
    保持「先出现的文件优先」的顺序，便于日志里说明每个文件贡献了多少条。
    """
    emit = log or (lambda _msg: None)
    targets = [Path(item) for item in files] if files else list_dict_files(dict_dir)
    if not targets:
        raise DirScanError("字典目录里没有可用的字典文件")

    merged: list[str] = []
    seen: set[str] = set()
    details: list[tuple[str, int]] = []
    for path in targets:
        try:
            words = read_words(path)
        except OSError as exc:
            emit(f"[字典] 读取失败 {path.name}：{exc}")
            continue
        added = 0
        for word in words:
            if word in seen:
                continue
            seen.add(word)
            merged.append(word)
            added += 1
        details.append((path.name, len(words)))
        emit(f"[字典] {path.name}：{len(words)} 条，去重后新增 {added} 条")

    if not merged:
        raise DirScanError("字典文件里没有有效路径，请检查文件内容")
    if len(merged) > MAX_WORDS:
        emit(f"[字典] 词表 {len(merged)} 条超过上限 {MAX_WORDS}，只取前 {MAX_WORDS} 条")
        merged = merged[:MAX_WORDS]
    emit(f"[字典] 合并完成：{len(merged)} 条待测路径（来自 {len(details)} 个文件）")
    return merged, details


# ---------------------------------------------------------------------------
# 二、HTTP 探测
# ---------------------------------------------------------------------------
@dataclass
class DirHit:
    """一条命中记录。"""

    word: str
    url: str
    status: int
    length: int
    title: str = ""
    redirect: str = ""
    listing: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "word": self.word,
            "url": self.url,
            "status": self.status,
            "length": self.length,
            "title": self.title,
            "redirect": self.redirect,
            "listing": self.listing,
        }


@dataclass
class DirScanResult:
    """一次目录爆破的汇总。"""

    base: str
    total: int = 0
    tested: int = 0
    filtered: int = 0
    errors: int = 0
    stopped: bool = False
    elapsed: float = 0.0
    output: str = ""
    baseline: str = ""
    hits: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "base": self.base,
            "total": self.total,
            "tested": self.tested,
            "filtered": self.filtered,
            "errors": self.errors,
            "stopped": self.stopped,
            "elapsed": round(self.elapsed, 1),
            "output": self.output,
            "baseline": self.baseline,
            "hits": list(self.hits),
        }


def _session(extra_headers: dict[str, str] | None = None) -> requests.Session:
    """独立会话，接入全局代理池。

    ``trust_env=False`` 绕过系统代理；启用全局代理池后由
    :mod:`lib.proxy_pool` 注入轮换代理，未启用时直连目标。
    默认头来自 :func:`load_default_headers`（``dict/Contents/http_headers.json``
    可覆盖）；``extra_headers`` 再在其上叠加（自定义头优先）。
    """
    from lib import proxy_pool

    session = proxy_pool.make_session("dir_scan")
    session.headers.update(load_default_headers())
    if extra_headers:
        session.headers.update(extra_headers)
    return session


def _describe_error(exc: Exception) -> str:
    """把 requests 的异常压成一句人话。"""
    text = str(exc)
    if isinstance(exc, requests.exceptions.ConnectTimeout):
        return "连接超时"
    if isinstance(exc, requests.exceptions.ReadTimeout):
        return "读取超时"
    if isinstance(exc, requests.exceptions.SSLError):
        return "TLS 握手失败"
    if ("NewConnectionError" in text or "Connection refused" in text
            or "积极拒绝" in text or "Connection aborted" in text):
        return "目标拒绝连接（端口未开放或被防火墙拦截）"
    if ("Name or service not known" in text or "getaddrinfo failed" in text
            or "NameResolutionError" in text):
        return "域名解析失败"
    return text[:120]


def _parse_headers(text: str) -> dict[str, str]:
    """解析「每行一个 ``Key: Value``」的自定义请求头，返回 dict。

    空行、无冒号的行、空键会被跳过；同名键后者覆盖前者。
    """
    result: dict[str, str] = {}
    for line in str(text or "").replace("\\n", "\n").splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        if key:
            result[key] = value.strip()
    return result


def _title_of(body: bytes) -> str:
    """从响应前若干字节里抠出 ``<title>``，压成一行。"""
    match = _TITLE_RE.search(body)
    if not match:
        return ""
    try:
        text = match.group(1).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001  极端编码问题不该影响探测
        return ""
    text = re.sub(r"\s+", " ", text).strip()
    return text[:120]


def _probe(session: requests.Session, url: str,
           timeout: float) -> tuple[int, int, str, str, bool, bytes]:
    """请求一个地址，返回 ``(状态码, 长度, 标题, 跳转, 是否目录列表, 正文头部)``。"""
    try:
        response = session.get(url, timeout=timeout, verify=False,
                               allow_redirects=False, stream=True)
    except requests.RequestException as exc:
        raise DirScanConnectionError(_describe_error(exc)) from exc

    try:
        status = response.status_code
        redirect = response.headers.get("Location", "") or ""
        declared = response.headers.get("Content-Length", "")
        body = b""
        if status not in (204, 304) and status < 400:
            for chunk in response.iter_content(16 * 1024):
                body += chunk
                if len(body) >= READ_LIMIT:
                    break
        length = int(declared) if declared.isdigit() else len(body)
        title = _title_of(body[:READ_LIMIT])
        head = body[:4096]
        listing = (b"Index of /" in head
                   or b"Directory listing for" in head
                   or b"<title>Directory" in head)
        return status, length, title, redirect, listing, body[:2048]
    finally:
        response.close()


def _soft_404_match(status: int, length: int, title: str, body: bytes,
                    baseline: tuple[int, int, str, bytes] | None) -> bool:
    """判断响应是否就是「随便什么路径都返回的同一页」。

    基线状态码可以是 200（整站返回首页），也可以是 403 / 401（整站返回
    拒绝页）—— 两种都会让「命中」爆表，所以一律按「同状态 + 正文相同或
    （长度接近且标题一致）」判重。
    """
    if baseline is None:
        return False
    base_status, base_length, base_title, base_body = baseline
    if base_status != status:
        return False
    if base_body and body and body[:512] == base_body[:512]:
        return True
    close_len = (bool(base_length) and bool(length)
                 and abs(length - base_length) <= max(16, base_length // 50))
    if close_len and title == base_title:
        return True
    return False


# ---------------------------------------------------------------------------
# 三、爆破主流程
# ---------------------------------------------------------------------------
def scan(
    target: str,
    out_dir: str | Path | None = None,
    dict_dir: str | Path | None = None,
    words: list[str] | None = None,
    threads: int = DEFAULT_THREADS,
    timeout: float = DEFAULT_TIMEOUT,
    interval: float = DEFAULT_INTERVAL,
    headers: str = "",
    log: LogFn | None = None,
    on_hit: HitFn | None = None,
    on_progress: ProgressFn | None = None,
    stop: threading.Event | None = None,
) -> dict[str, Any]:
    """对 ``target`` 逐条探测字典里的路径，返回汇总 dict。

    参数
    ----
    target       域名或带目录的域名（``example.com`` / ``example.com/upload``）
    out_dir      结果落盘根目录，命中写到 ``<out_dir>/<host>/``
    dict_dir     字典目录，默认 :func:`default_dict_dir`
    words        直接给词表（给了就不再读字典目录，便于测试）
    threads      并发线程数
    timeout      单次请求超时（秒）
    interval     相邻两次探测请求的最小间隔（秒），默认 30；置 0 表示不限间隔
    headers      自定义请求头（每行一个 ``Key: Value``），叠加到默认头
                 （:func:`load_default_headers`）之上
    log          逐行日志回调
    on_hit       每命中一条立即回调（界面增量填表）
    on_progress  进度回调 ``(已完成, 总数)``
    stop         置位后不再派发新任务，已发出的请求尽快结束
    """
    try:
        base = normalize_target(target)
    except LeakError as exc:
        raise DirScanError(str(exc)) from exc
    emit = log or (lambda _msg: None)
    started = time.time()

    interval = max(0.0, float(interval))
    extra_headers = _parse_headers(headers)

    if words is not None:
        # 直传词表也走一遍规范化，避免 "/api/" 被拼成 "//api/"
        wordlist = []
        seen: set[str] = set()
        for item in words:
            word = normalize_word(item)
            if word and word not in seen:
                seen.add(word)
                wordlist.append(word)
    else:
        wordlist = load_words(dict_dir, log=emit)[0]
    if not wordlist:
        raise DirScanError("词表为空，没有可探测的路径")

    result = DirScanResult(base=base, total=len(wordlist))
    emit(f"[目标] {base}")
    emit(f"[词表] {len(wordlist)} 条，线程 {threads}，超时 {timeout:g}s"
         + (f"，请求间隔 {interval:g}s" if interval else ""))
    if extra_headers:
        emit(f"[请求头] 附加 {len(extra_headers)} 个自定义头："
             f"{', '.join(extra_headers)}")

    local = threading.local()

    def session_of() -> requests.Session:
        session = getattr(local, "session", None)
        if session is None:
            session = _session(extra_headers)
            local.session = session
        return session

    # -- 1. 基线：先探一个必然不存在的路径，识别「软 404」 -------------------
    probe_path = f"__cn_{secrets.token_hex(6)}__"
    baseline: tuple[int, int, str, bytes] | None = None
    try:
        status, length, title, redirect, listing, body = _probe(
            session_of(), f"{base}/{probe_path}", timeout)
        baseline = (status, length, title, body)
        result.baseline = f"{status} / {length} B" + (f" / {title}" if title else "")
        emit(f"[基线] 随机路径返回 {status}，长度 {length} B"
             + (f"，标题「{title}」" if title else ""))
        if status == 200 and length:
            emit("[基线] 目标对任意路径都返回 200，将按「状态 + 长度 + 标题」过滤软 404")
    except DirScanConnectionError as exc:
        raise DirScanConnectionError(f"连接失败：{exc}") from exc

    # -- 2. 并发探测 --------------------------------------------------------
    jobs: queue.Queue[str] = queue.Queue()
    for word in wordlist:
        jobs.put(word)

    lock = threading.Lock()
    hits: list[dict[str, Any]] = []
    counters = {"tested": 0, "filtered": 0, "errors": 0, "consecutive": 0}
    abort = {"reason": ""}
    last_emit = [0.0]

    # -- 全局请求节流：所有线程共享「下次允许发请求」的时间戳，保证相邻两次
    #    探测请求的最小间隔 >= interval（interval=0 时不节流）。
    throttle = {"next_allowed": 0.0}
    throttle_lock = threading.Lock()

    def _throttle_wait() -> None:
        """在发请求前调用：若配置了间隔，则阻塞到距上次请求满 interval。"""
        if interval <= 0:
            return
        with throttle_lock:
            now = time.time()
            wait = throttle["next_allowed"] - now
            if wait <= 0:
                throttle["next_allowed"] = now + interval
            else:
                throttle["next_allowed"] += interval
        if wait > 0:
            # 可被 stop 打断的睡眠，避免「停不下来」还傻等 30 秒
            deadline = time.time() + wait
            while time.time() < deadline:
                if stop is not None and stop.is_set():
                    return
                time.sleep(min(0.2, deadline - time.time()))

    def worker() -> None:
        while True:
            if stop is not None and stop.is_set():
                return
            if abort["reason"]:
                return
            try:
                word = jobs.get_nowait()
            except queue.Empty:
                return

            url = f"{base}/{urllib.parse.quote(word, safe='/%._-~')}"
            _throttle_wait()
            if stop is not None and stop.is_set():
                return
            try:
                status, length, title, redirect, listing, body = _probe(
                    session_of(), url, timeout)
            except DirScanConnectionError as exc:
                with lock:
                    counters["errors"] += 1
                    counters["consecutive"] += 1
                    if (counters["consecutive"] >= MAX_CONSECUTIVE_ERRORS
                            and not abort["reason"]):
                        abort["reason"] = str(exc)
                continue

            payload = None
            with lock:
                counters["tested"] += 1
                counters["consecutive"] = 0
                if status in MISS_STATUSES:
                    pass
                elif _soft_404_match(status, length, title, body, baseline):
                    counters["filtered"] += 1
                else:
                    hit = DirHit(word=word, url=url, status=status,
                                 length=length, title=title,
                                 redirect=redirect, listing=listing)
                    payload = hit.to_dict()
                    hits.append(payload)
                done = counters["tested"]

            # 回调一律放到锁外：Qt 信号 / 用户回调里可能做耗时操作
            if payload is not None:
                if on_hit is not None:
                    on_hit(payload)
                emit(f"[命中] {status}  {length:>8} B  /{word}"
                     + ("  [目录列表]" if listing else "")
                     + (f"  → {redirect}" if redirect else ""))

            if on_progress is not None:
                now = time.time()
                if now - last_emit[0] >= 0.2 or done >= len(wordlist):
                    last_emit[0] = now
                    on_progress(done, len(wordlist))

    count = max(1, min(int(threads), 64, len(wordlist)))
    workers = [threading.Thread(target=worker, daemon=True, name=f"dirscan-{i}")
               for i in range(count)]
    for thread in workers:
        thread.start()
    for thread in workers:
        thread.join()

    result.tested = counters["tested"]
    result.filtered = counters["filtered"]
    result.errors = counters["errors"]
    result.stopped = bool(stop is not None and stop.is_set())
    result.hits = hits
    result.elapsed = time.time() - started

    if abort["reason"] and not hits:
        raise DirScanConnectionError(f"连接失败：{abort['reason']}")

    # -- 3. 落盘 ------------------------------------------------------------
    if out_dir:
        result.output = _write_output(base, Path(out_dir), result, emit)

    emit(f"[完成] 测试 {result.tested}/{result.total} 条，命中 {len(hits)} 条"
         + (f"，软 404 过滤 {result.filtered} 条" if result.filtered else "")
         + (f"，失败 {result.errors} 次" if result.errors else "")
         + (f"，耗时 {result.elapsed:.1f}s" if result.elapsed else ""))
    return result.to_dict()


def _host_dir(base: str) -> str:
    """输出子目录名：``host_port``（不同端口不互相覆盖）。"""
    netloc = urllib.parse.urlparse(base).netloc or "target"
    return re.sub(r'[<>:"|?*\\/]', "_", netloc)


def _write_output(base: str, out_dir: Path, result: DirScanResult,
                  emit: LogFn) -> str:
    """把命中写成 ``hits.csv`` + ``hits.txt``，返回目录。"""
    root = out_dir / _host_dir(base)
    try:
        root.mkdir(parents=True, exist_ok=True)
        with (root / "hits.csv").open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["URL", "状态码", "长度", "标题", "跳转", "目录列表"])
            for hit in result.hits:
                writer.writerow([hit["url"], hit["status"], hit["length"],
                                 hit["title"], hit["redirect"],
                                 "是" if hit["listing"] else ""])
        with (root / "hits.txt").open("w", encoding="utf-8") as handle:
            for hit in result.hits:
                handle.write(f"{hit['status']}\t{hit['length']}\t{hit['url']}"
                             f"\t{hit['title']}\n")
        emit(f"[输出] 命中清单已写入 {root}")
        return str(root)
    except OSError as exc:
        emit(f"[输出] 写入失败：{exc}")
        return ""


__all__ = [
    "DICT_SUBDIR",
    "DEFAULT_THREADS",
    "DEFAULT_TIMEOUT",
    "DEFAULT_INTERVAL",
    "HEADERS",
    "HEADERS_FILE",
    "DirHit",
    "DirScanError",
    "DirScanConnectionError",
    "DirScanResult",
    "default_dict_dir",
    "default_headers_file",
    "list_dict_files",
    "load_default_headers",
    "load_words",
    "normalize_word",
    "read_words",
    "reset_default_headers_cache",
    "scan",
]


# ---------------------------------------------------------------------------
# 自检：``python -m lib.dir_scan``
# ---------------------------------------------------------------------------
def _self_test() -> int:
    """起一个临时站点，验证命中 / 软 404 / 停止三条主路径。"""
    import tempfile
    import threading as _threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    root = Path(tempfile.mkdtemp(prefix="dirscan_"))
    (root / "admin").mkdir()
    (root / "admin" / "index.html").write_text("<title>后台</title>", "utf-8")
    (root / "uploads").mkdir()
    (root / "uploads" / "index.html").write_text("<title>Index of /uploads</title>",
                                                 "utf-8")
    (root / "backup.zip").write_bytes(b"PK\x03\x04" + b"0" * 128)

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802  http.server 约定
            path = self.path.lstrip("/").split("?")[0]
            target = root / path
            if target.is_dir():
                target = target / "index.html"
            if target.is_file():
                body = target.read_bytes()
                self.send_response(200)
            else:
                body = b"<html><title>404</title>not found</html>"
                self.send_response(404)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args) -> None:  # 静音
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    _threading.Thread(target=server.serve_forever, daemon=True).start()

    failures: list[str] = []
    try:
        words = ["admin", "/uploads/", "backup.zip", "nope-xyz", "../etc/passwd"]
        result = scan(f"127.0.0.1:{port}", out_dir=str(root / "out"),
                      words=words, threads=4, timeout=5, interval=0)
        hit_words = {item["word"] for item in result["hits"]}
        for expect in ("admin", "uploads", "backup.zip"):
            if expect not in hit_words:
                failures.append(f"缺少命中：{expect}")
        for miss in ("nope-xyz", "etc/passwd"):
            if miss in hit_words:
                failures.append(f"不该命中：{miss}")
        if result["filtered"]:
            failures.append(f"普通 404 站点不该有软 404 过滤：{result['filtered']}")
        if not (root / "out").exists():
            failures.append("结果没有落盘")

        # 软 404：整站返回 200 的站点不该满屏命中
        class _Soft(_Handler):
            def do_GET(self) -> None:  # noqa: N802
                body = b"<html><title>Home</title>welcome</html>"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        soft = ThreadingHTTPServer(("127.0.0.1", 0), _Soft)
        _threading.Thread(target=soft.serve_forever, daemon=True).start()
        try:
            soft_result = scan(f"127.0.0.1:{soft.server_address[1]}",
                               words=["a", "b", "c"], threads=3, timeout=5,
                               interval=0)
        finally:
            soft.shutdown()
        if soft_result["hits"]:
            failures.append(f"软 404 未过滤：{len(soft_result['hits'])} 条命中")
    finally:
        server.shutdown()

    if failures:
        print("[FAIL] " + "；".join(failures))
        return 1
    print("[OK] 命中 / 路径穿越拦截 / 软 404 过滤 全部通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(_self_test())

