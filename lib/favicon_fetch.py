# -*- coding: utf-8 -*-
"""网站图标（favicon）抓取与本地缓存。

本模块只做纯逻辑，不依赖 Qt，供「快捷访问」页在后台线程里调用：

1. 抓取目标页面 HTML，解析 ``<link rel="icon">`` / ``apple-touch-icon``；
2. 回退到站点根目录 ``/favicon.ico``、``/apple-touch-icon.png``；
3. 再回退到 Google / DuckDuckGo 等公共 favicon 服务；
4. 校验响应确实是图片（按魔数或 Content-Type），落盘到本地图标缓存目录。

网络请求统一走 :func:`lib.proxy_pool.make_session`，与其它 Web 工具共用
全局代理池；当全局代理启用但池内无可用代理时会抛
:class:`lib.proxy_pool.ProxyPoolError`，由页面层提示用户。
"""

from __future__ import annotations

import base64
import hashlib
import re
import shutil
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests

from lib import proxy_pool

#: 单次请求超时（秒）
DEFAULT_TIMEOUT = 8
#: 图标文件大小上限（2 MB），避免有些站点把整张图 / HTML 当 favicon 返回
MAX_ICON_BYTES = 2 * 1024 * 1024
#: 解析页面时最多读取的 HTML 字节数
MAX_HTML_BYTES = 512 * 1024

#: 公共 favicon 兜底服务（{host} 会被替换成域名）
THIRD_PARTY_SOURCES: tuple[str, ...] = (
    "https://www.google.com/s2/favicons?domain={host}&sz=128",
    "https://icons.duckduckgo.com/ip3/{host}.ico",
    "https://api.faviconkit.com/{host}/128",
)
#: 公共服务的连接通常比目标站点慢，单独用更短的超时避免拖太久
THIRD_PARTY_TIMEOUT = 3.5

#: 允许落盘 / 作为自定义图标导入的扩展名（Qt 能读的常见图片格式）
IMAGE_EXTENSIONS: tuple[str, ...] = (
    ".bmp", ".cur", ".gif", ".ico", ".jfif", ".jpeg", ".jpg", ".pbm",
    ".pgm", ".png", ".ppm", ".svg", ".svgz", ".tga", ".tif", ".tiff",
    ".wbmp", ".webp", ".xbm", ".xpm",
)

_CTYPE_EXT = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/jpg": ".jpg",
    "image/gif": ".gif",
    "image/x-icon": ".ico",
    "image/vnd.microsoft.icon": ".ico",
    "image/bmp": ".bmp",
    "image/webp": ".webp",
    "image/svg+xml": ".svg",
    "image/tiff": ".tif",
}

_DATA_URI_RE = re.compile(r"^data:(image/[\w.+-]+)(;base64)?,(.*)$", re.S | re.I)


class FaviconError(ValueError):
    """抓取 / 保存网站图标失败时抛出的统一异常。"""


# ---------------------------------------------------------------------------
# URL / 图片格式工具
# ---------------------------------------------------------------------------
def normalize_url(url: str) -> str:
    """补全协议并校验 URL；非法时抛 :class:`FaviconError`。"""
    text = str(url or "").strip()
    if not text:
        raise FaviconError("链接为空")
    if "://" not in text:
        text = "https://" + text
    parsed = urlparse(text)
    if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc:
        raise FaviconError("链接格式不正确，需以 http:// 或 https:// 开头")
    return text


def host_of(url: str) -> str:
    """取 URL 的主机名（不含端口），失败返回空串。"""
    try:
        return (urlparse(normalize_url(url)).hostname or "").lower()
    except FaviconError:
        return ""


def sniff_extension(data: bytes, content_type: str = "") -> str:
    """按图片魔数（优先）或 Content-Type 推断扩展名；无法识别返回空串。"""
    if not data:
        return ""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if data.startswith(b"\x00\x00\x01\x00"):
        return ".ico"
    if data.startswith(b"\x00\x00\x02\x00"):
        return ".cur"
    if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        return ".gif"
    if data.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    if data[:2] == b"BM":
        return ".bmp"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return ".webp"
    if data.startswith(b"II*\x00") or data.startswith(b"MM\x00*"):
        return ".tif"

    head = data[:2048].lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if head.startswith(b"<svg") or b"<svg" in head[:1024]:
        return ".svg"

    ctype = (content_type or "").split(";", 1)[0].strip().lower()
    return _CTYPE_EXT.get(ctype, "")


def is_image_bytes(data: bytes, content_type: str = "") -> bool:
    """判断字节是否是受支持的图片（避免把 HTML 404 页当图标缓存）。"""
    return bool(data) and len(data) <= MAX_ICON_BYTES and bool(
        sniff_extension(data, content_type))


def _icon_digest(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()[:16]


def _safe_extension(ext: str) -> str:
    ext = str(ext or "").lower().strip()
    if not ext.startswith("."):
        ext = "." + ext
    return ext if ext in IMAGE_EXTENSIONS else ""


# ---------------------------------------------------------------------------
# HTML 解析
# ---------------------------------------------------------------------------
class _IconLinkParser(HTMLParser):
    """收集页面里的图标链接，按「质量」排序后返回。"""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.icons: list[tuple[int, str]] = []

    def handle_starttag(self, tag, attrs) -> None:  # noqa: N802  Qt/HTML 约定
        if tag.lower() != "link":
            return
        attr = {str(k).lower(): str(v or "") for k, v in attrs}
        rel = attr.get("rel", "").lower()
        link_type = attr.get("type", "").lower()
        tokens = rel.split()
        if not any("icon" in token for token in tokens) and \
                not link_type.startswith("image/"):
            return
        href = attr.get("href", "").strip()
        if not href:
            return

        # 数字越小优先级越高：apple-touch-icon 通常尺寸更大、更清晰
        if "apple-touch-icon" in rel:
            priority = 0
        elif "mask-icon" in rel:
            priority = 3
        elif "shortcut" in rel:
            priority = 2
        else:
            priority = 1

        # 有 sizes 属性时，尺寸越大越优先（同一优先级内靠前）
        sizes = attr.get("sizes", "")
        try:
            first = sizes.split()[0]
            width = int(first.split("x", 1)[0])
            if width >= 96:
                priority -= 1
        except (ValueError, IndexError):
            pass
        self.icons.append((priority, href))

    def sorted_hrefs(self) -> list[str]:
        return [href for _priority, href in sorted(self.icons, key=lambda x: x[0])]


def _page_icon_candidates(session: requests.Session, url: str,
                          timeout: float) -> list[str]:
    """请求页面并从 HTML 中提取图标 URL；失败返回空列表。"""
    try:
        resp = session.get(
            url, timeout=timeout, allow_redirects=True,
            headers={"User-Agent": proxy_pool.USER_AGENT})
    except requests.RequestException:
        return []
    if resp.status_code >= 400:
        return []

    ctype = resp.headers.get("Content-Type", "").lower()
    if ctype and "html" not in ctype and "xml" not in ctype:
        return []

    raw = resp.content[:MAX_HTML_BYTES]
    encoding = resp.encoding or "utf-8"
    try:
        html = raw.decode(encoding, errors="ignore")
    except LookupError:
        html = raw.decode("utf-8", errors="ignore")

    parser = _IconLinkParser()
    try:
        parser.feed(html)
    except Exception:  # noqa: BLE001  解析失败按「没有图标链接」处理
        return []

    base = resp.url or url
    candidates: list[str] = []
    for href in parser.sorted_hrefs():
        href = href.strip()
        if href.startswith("data:"):
            candidates.append(href)
        else:
            candidates.append(urljoin(base, href))
    return candidates


# ---------------------------------------------------------------------------
# 下载
# ---------------------------------------------------------------------------
def _decode_data_uri(uri: str) -> bytes | None:
    match = _DATA_URI_RE.match(uri)
    if not match:
        return None
    _ctype, is_base64, payload = match.groups()
    try:
        if is_base64:
            data = base64.b64decode(payload, validate=False)
        else:
            from urllib.parse import unquote_to_bytes
            data = unquote_to_bytes(payload)
    except (ValueError, TypeError):
        return None
    return data if is_image_bytes(data) else None


def _fetch_candidate(session: requests.Session, candidate: str,
                     timeout: float) -> bytes | None:
    """下载单个候选图标；不是图片 / 请求失败返回 None。"""
    if candidate.startswith("data:"):
        return _decode_data_uri(candidate)
    try:
        resp = session.get(
            candidate, timeout=timeout, allow_redirects=True,
            headers={"User-Agent": proxy_pool.USER_AGENT})
    except requests.RequestException:
        return None
    if resp.status_code >= 400:
        return None
    data = resp.content
    if not is_image_bytes(data, resp.headers.get("Content-Type", "")):
        return None
    return data


def fetch_favicon(url: str, timeout: float = DEFAULT_TIMEOUT,
                  session: requests.Session | None = None,
                  log=None) -> bytes:
    """抓取 ``url`` 对应网站的 favicon，返回图片字节。

    依次尝试：页面内声明的图标 → 根目录 favicon → apple-touch-icon →
    公共 favicon 服务。全部失败时抛 :class:`FaviconError`。
    """
    target = normalize_url(url)
    own_session = session is None
    if own_session:
        session = proxy_pool.make_session("quick_access")
    session.headers.setdefault("User-Agent", proxy_pool.USER_AGENT)

    try:
        parsed = urlparse(target)
        host = (parsed.hostname or "").lower()
        origin = f"{parsed.scheme}://{parsed.netloc}"

        candidates: list[tuple[str, float]] = [
            (item, timeout)
            for item in _page_icon_candidates(session, target, timeout)
        ]
        candidates.extend((
            (f"{origin}/favicon.ico", timeout),
            (f"{origin}/favicon.png", timeout),
            (f"{origin}/apple-touch-icon.png", timeout),
            (f"{origin}/apple-touch-icon-precomposed.png", timeout),
        ))
        if host:
            for template in THIRD_PARTY_SOURCES:
                candidates.append((
                    template.format(host=host),
                    min(timeout, THIRD_PARTY_TIMEOUT),
                ))

        seen: set[str] = set()
        for candidate, candidate_timeout in candidates:
            candidate = candidate.strip()
            if not candidate or candidate in seen:
                continue
            seen.add(candidate)
            if log:
                log(f"尝试获取图标：{candidate}")
            data = _fetch_candidate(session, candidate, candidate_timeout)
            if data:
                if log:
                    log(f"图标获取成功：{candidate}")
                return data
    finally:
        if own_session:
            session.close()

    raise FaviconError("没有找到可用的网站图标")


# ---------------------------------------------------------------------------
# 落盘
# ---------------------------------------------------------------------------
def save_icon_bytes(data: bytes, directory: str | Path) -> str:
    """把图标字节写入缓存目录（按内容去重），返回本地文件路径。"""
    if not is_image_bytes(data):
        raise FaviconError("下载到的内容不是有效图片")
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    ext = sniff_extension(data) or ".png"
    path = directory / f"favicon_{_icon_digest(data)}{ext}"
    if not path.exists():
        path.write_bytes(data)
    return str(path)


def copy_icon_file(source: str | Path, directory: str | Path) -> str:
    """把用户选择的本地图片复制进缓存目录，返回缓存文件路径。

    保留原扩展名（Qt 支持的图片类型都接受），无法识别扩展名时按内容探测；
    内容完全相同的图片会复用同一个缓存文件。
    """
    src = Path(source)
    if not src.is_file():
        raise FaviconError(f"图片文件不存在：{source}")
    try:
        data = src.read_bytes()
    except OSError as exc:
        raise FaviconError(f"读取图片失败：{exc}") from exc
    if not data:
        raise FaviconError("图片文件为空")

    ext = _safe_extension(src.suffix) or sniff_extension(data)
    if not ext:
        ext = src.suffix.lower() or ".png"

    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    dest = directory / f"custom_{_icon_digest(data)}{ext}"
    if not dest.exists():
        try:
            shutil.copyfile(src, dest)
        except OSError as exc:
            raise FaviconError(f"复制图片失败：{exc}") from exc
    return str(dest)


def fetch_and_save_icon(url: str, directory: str | Path,
                        timeout: float = DEFAULT_TIMEOUT,
                        log=None) -> str:
    """抓取 favicon 并落盘，返回本地路径（供后台线程直接调用）。"""
    data = fetch_favicon(url, timeout=timeout, log=log)
    return save_icon_bytes(data, directory)
