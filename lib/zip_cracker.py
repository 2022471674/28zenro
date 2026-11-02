# -*- coding: utf-8 -*-
"""ZIP 压缩包工具纯逻辑（移植自 Hx0 战队 ZipCracker）。

能力三块，全部无 UI 依赖、异常抛出而不 ``exit``：

- **伪加密识别与修复**：ZIP 的「通用标志位」第 0 位置 1 即标记为加密，但
  很多 CTF 题只是把该位置 1、数据并未真正加密（伪加密）。本模块能判定并在
  确属伪加密时清掉标志位生成修复副本（保留原压缩方式与元数据）。
- **CRC32 碰撞**：ZIP 条目记录的 CRC32 是**未压缩明文**的校验和。对 ≤6 字节
  的小文件，直接枚举字符集碰撞 CRC32 即可还原明文，无需密码。原版无搜索上限
  （6 字节 printable 为 10¹² 次），此处加组合数护栏与字符集预设，防止把机器
  拖死。
- **字典爆破**：内置常用密码字典 + 0~N 位纯数字字典，也可用用户自定义字典
  （如项目自带的 ``dict/rockyou.txt.gz``）。后台线程跑，进度走日志队列由界面层
  ``poll_logs()`` 取回。

对每个候选密码只做一次「打开首个加密条目读 1 字节」的校验，而不是原版的
``testzip()`` + ``extractall()``（后者会把整个包解出来，既慢又会污染磁盘）。

用法示例::

    cracker = ZipCracker()
    cracker.start("flag.zip", dict_path=None, max_numeric_len=6)
    while cracker.running:
        for log in cracker.poll_logs():
            print(log)
    print(cracker.status, cracker.result)
"""

from __future__ import annotations

import binascii
import itertools
import queue
import string
import threading
import time
import zipfile
from pathlib import Path

# ===========================================================================
# 一、常量
# ===========================================================================
#: ZIP 通用标志位里的「加密」位
_ENCRYPT_FLAG = 0x1

#: 内置密码字典文件名（位于项目 dict/ 目录）
BUILTIN_DICT_NAME = "zip_passwords.txt"

#: 字典读取编码回退顺序（沿用 md5_crash 的约定：utf-8 → latin-1 → GBK）
DICT_ENCODINGS = ("utf-8", "latin-1", "gbk")

#: 纯数字字典最大位数上限（防误填把内存撑爆；0~8 位约 1.1 亿条）
MAX_NUMERIC_LEN = 8

#: CRC32 碰撞的组合数护栏：超过则拒绝执行（提示换更小字符集或更短内容）
CRC_MAX_COMBINATIONS = 50_000_000

#: CRC32 碰撞可判定为「小文件」的最大字节数
CRC_SMALL_FILE_MAX = 6

#: CRC32 碰撞进度回传节流：每尝试这么多次才写一条日志
CRC_LOG_INTERVAL = 200_000

#: 密码爆破进度回传节流：每尝试这么多个密码才写一条日志
CRACK_LOG_INTERVAL = 500

#: 后台线程轮询密码 / 停止信号的间隔
_POLL_INTERVAL = 0.2

# 三种字符集预设（供 CRC32 碰撞选用）
ALPHABET_DIGITS = string.digits              # 0-9
ALPHABET_LOWER = string.ascii_lowercase      # a-z
ALPHABET_ALPHA = string.ascii_letters        # a-zA-Z
ALPHABET_PRINTABLE = string.printable        # 数字 + 字母 + 常见符号 + 空白

#: 字符集预设的界面显示名
ALPHABET_PRESETS = (
    ("digits", "数字 0-9"),
    ("lower", "小写字母 a-z"),
    ("alpha", "大小写字母"),
    ("printable", "可打印字符（含符号）"),
)
_ALPHABET_BY_KEY = {
    "digits": ALPHABET_DIGITS,
    "lower": ALPHABET_LOWER,
    "alpha": ALPHABET_ALPHA,
    "printable": ALPHABET_PRINTABLE,
}

#: 状态码（界面层据此展示终态）
STATUS_IDLE = "idle"
STATUS_RUNNING = "running"
STATUS_FOUND = "found"
STATUS_STOPPED = "stopped"
STATUS_DONE = "done"
STATUS_ERROR = "error"


class ZipCrackerError(ValueError):
    """压缩包工具的统一异常，界面层捕获后展示中文原因。"""


def _resolve_dict_dir() -> str:
    """内置字典目录：打包数据根（dev = 项目 dict/，冻结 = _internal/dict）。"""
    from lib.runtime_paths import resource

    return str(resource("dict"))


DICT_DIR = _resolve_dict_dir()


# ===========================================================================
# 二、路径与条目解析
# ===========================================================================
def check_zip_path(path, field: str = "压缩包") -> str:
    """校验路径存在且确为 ZIP，返回绝对路径字符串。"""
    import os

    text = str(path or "").strip().strip('"')
    if not text:
        raise ZipCrackerError(f"请选择{field}文件。")
    if not os.path.isfile(text):
        raise ZipCrackerError(f"{field}文件不存在：{text}")
    if not zipfile.is_zipfile(text):
        raise ZipCrackerError(f"该文件不是合法的 ZIP 压缩包：{text}")
    return os.path.abspath(text)


def list_entries(zip_path) -> list:
    """列出压缩包条目：``{name, size, crc, encrypted, is_dir}``。

    ``size`` 为未压缩大小，``crc`` 为未压缩数据的 CRC32（碰撞明文的依据）。
    """
    real = check_zip_path(zip_path)
    try:
        with zipfile.ZipFile(real) as zf:
            entries = []
            for info in zf.infolist():
                entries.append({
                    "name": info.filename,
                    "size": info.file_size,
                    "crc": info.CRC,
                    "encrypted": bool(info.flag_bits & _ENCRYPT_FLAG),
                    "is_dir": info.is_dir(),
                })
            return entries
    except zipfile.BadZipFile as exc:
        raise ZipCrackerError(f"压缩包损坏或格式异常：{exc}") from exc


def is_encrypted(zip_path) -> bool:
    """压缩包是否有任一条目被标记加密（含伪加密）。"""
    return any(e["encrypted"] for e in list_entries(zip_path))


def small_crc_candidates(zip_path, max_size: int = CRC_SMALL_FILE_MAX) -> list:
    """返回适合 CRC32 碰撞的条目（未加密、非目录、大小 ≤ ``max_size``）。"""
    return [
        e for e in list_entries(zip_path)
        if not e["encrypted"] and not e["is_dir"]
        and 0 < e["size"] <= max_size
    ]


# ===========================================================================
# 三、伪加密识别与修复
# ===========================================================================
def _clear_flags_in_place(zf: zipfile.ZipFile) -> list:
    """就地清除 ``zf`` 内所有条目的加密标志位，返回被改动的条目列表。

    ``infolist()`` 返回的是 ``filelist`` 里那批 ``ZipInfo`` 对象本身，就地改
    ``flag_bits`` 后，``read()`` / ``open()`` 便不再要求密码。这是原版
    ZipCracker 识别伪加密的核心技巧：数据若真被加密，解出来是乱码、CRC 会
    失败；若只是标志位被置 1（伪加密），解出来完全正常。
    """
    touched = []
    for info in zf.infolist():
        if info.flag_bits & _ENCRYPT_FLAG:
            info.flag_bits &= ~_ENCRYPT_FLAG
            touched.append(info)
    return touched


def _try_read_cleared(zf: zipfile.ZipFile, info: zipfile.ZipInfo):
    """就地清掉单个条目的加密标志后读出其数据。

    成功返回 ``bytes``；解压失败（真加密数据当 deflate 流必然解出乱码 / 报错）
    返回 ``None``。
    """
    import zlib

    original = info.flag_bits
    info.flag_bits &= ~_ENCRYPT_FLAG
    try:
        return zf.read(info.filename)
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError,
            OSError, ValueError, zlib.error, EOFError):
        return None
    finally:
        info.flag_bits = original


def is_fake_encrypted(zip_path) -> bool:
    """判定是否为**伪加密**：标志位标记了加密，但数据并未真正加密。

    判据：就地清掉加密标志位后能把每个加密条目完整读出，且解出内容的
    CRC32 与压缩包记录的 ``info.CRC`` 一致。真加密的包清位后解出的是乱码，
    CRC 对不上（或直接解压失败），据此判定为真加密。

    不能用「重建副本再 testzip」来判定——``writestr`` 会按读到的字节重算
    CRC，乱码也会自洽通过。
    """
    real = check_zip_path(zip_path)
    if not is_encrypted(real):
        return False
    try:
        with zipfile.ZipFile(real) as zf:
            encrypted = [i for i in zf.infolist() if i.flag_bits & _ENCRYPT_FLAG]
            for info in encrypted:
                payload = _try_read_cleared(zf, info)
                if payload is None:
                    return False
                if (binascii.crc32(payload) & 0xFFFFFFFF) != (info.CRC & 0xFFFFFFFF):
                    return False
            return True
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError):
        return False


def fix_fake_encrypted(zip_path, out_path=None) -> str:
    """修复伪加密：清除加密标志位后另存为新文件，返回新文件绝对路径。

    若压缩包并非伪加密（真加密 / 未加密），抛 :class:`ZipCrackerError`，不做
    任何写盘。``out_path`` 缺省为 ``原名_fixed.zip``，与原版的 ``fix_`` 前缀
    区分开以避免与源文件同名冲突。
    """
    import os

    real = check_zip_path(zip_path)
    if not is_encrypted(real):
        raise ZipCrackerError("该压缩包未标记加密，无需修复。")
    if not is_fake_encrypted(real):
        raise ZipCrackerError("该压缩包是真加密（需要密码），不是伪加密，无法直接修复。")

    if out_path:
        target = os.path.abspath(str(out_path))
    else:
        base, ext = os.path.splitext(real)
        target = f"{base}_fixed{ext or '.zip'}"

    os.makedirs(os.path.dirname(target) or ".", exist_ok=True)

    # 目标与源相同则退回加后缀，避免覆盖原包
    if os.path.abspath(target) == real:
        base, ext = os.path.splitext(real)
        target = f"{base}_fixed{ext or '.zip'}"

    with zipfile.ZipFile(real) as src:
        # 先就地清标志，否则 read() 会因 0x1 位直接抛「需要密码」
        _clear_flags_in_place(src)
        with zipfile.ZipFile(target, "w") as dst:
            for info in src.infolist():
                payload = src.read(info.filename)
                new_info = zipfile.ZipInfo(info.filename, date_time=info.date_time)
                new_info.compress_type = info.compress_type
                new_info.external_attr = info.external_attr
                new_info.internal_attr = info.internal_attr
                new_info.create_system = info.create_system
                new_info.flag_bits = info.flag_bits & ~_ENCRYPT_FLAG
                dst.writestr(new_info, payload)

    # 修复后自校验，确保产出的包真的可读
    with zipfile.ZipFile(target) as check:
        bad = check.testzip()
        if bad is not None:
            raise ZipCrackerError(f"修复后的压缩包校验失败（{bad}），可能不是伪加密。")
    return target


def extract(zip_path, out_dir=None, password=None) -> list:
    """解压压缩包，返回解出的文件名列表。

    ``password`` 为空串 / ``None`` 时按未加密处理。目标目录缺省为压缩包同级的
    ``<包名>_extracted``。会做路径穿越防护（拒绝 ``..`` 与绝对路径条目）。
    """
    import os

    real = check_zip_path(zip_path)
    if out_dir:
        target = os.path.abspath(str(out_dir))
    else:
        target = os.path.splitext(real)[0] + "_extracted"
    os.makedirs(target, exist_ok=True)

    pwd = str(password).encode("utf-8") if password else None
    extracted = []
    with zipfile.ZipFile(real) as zf:
        for info in zf.infolist():
            name = info.filename
            # 路径穿越防护：剔除绝对盘符与 .. 段
            safe = os.path.normpath(name).replace("\\", "/")
            if safe.startswith("/") or ".." in safe.split("/"):
                continue
            zf.extract(info, path=target, pwd=pwd)
            if not info.is_dir():
                extracted.append(name)
    return extracted


# ===========================================================================
# 四、CRC32 碰撞（还原小文件明文）
# ===========================================================================
def resolve_alphabet(value) -> str:
    """把预设键 / 字符串解析为实际字符集。"""
    if value in _ALPHABET_BY_KEY:
        return _ALPHABET_BY_KEY[value]
    text = str(value or "")
    if not text:
        raise ZipCrackerError("字符集不能为空。")
    return text


def combination_count(size: int, alphabet_len: int) -> int:
    """字符集长度 ``alphabet_len`` 下、明文长度 ``size`` 的组合总数。"""
    return alphabet_len ** size


def crc32_crack(crc: int, size: int, alphabet=ALPHABET_DIGITS,
                stop_event=None, log=None) -> str | None:
    """按 CRC32 碰撞还原长度为 ``size`` 的明文。

    ``crc`` 为 ZIP 条目记录的未压缩 CRC32，``alphabet`` 为字符集（字符串或
    预设键）。命中返回明文字符串；被 ``stop_event`` 中止或穷举完毕返回
    ``None``。组合数超过 :data:`CRC_MAX_COMBINATIONS` 直接抛
    :class:`ZipCrackerError`。

    ``log`` 为可选回调 ``log(tried: int) -> None``，用于回传进度。
    """
    if not isinstance(size, int) or size <= 0:
        raise ZipCrackerError("明文长度必须是正整数。")
    if size > CRC_SMALL_FILE_MAX:
        raise ZipCrackerError(
            f"CRC32 碰撞仅适用于 ≤{CRC_SMALL_FILE_MAX} 字节的小文件（当前 {size} 字节）。")

    chars = resolve_alphabet(alphabet)
    total = combination_count(size, len(chars))
    if total > CRC_MAX_COMBINATIONS:
        raise ZipCrackerError(
            f"搜索空间过大（{total:,} 种组合，上限 {CRC_MAX_COMBINATIONS:,}）。"
            f"请改用更小字符集或确认明文更短。")

    target = int(crc) & 0xFFFFFFFF
    tried = 0
    for combo in itertools.product(chars, repeat=size):
        tried += 1
        if log is not None and tried % CRC_LOG_INTERVAL == 0:
            log(tried)
        if stop_event is not None and stop_event.is_set():
            return None
        data = "".join(combo).encode("utf-8", errors="ignore")
        if binascii.crc32(data) & 0xFFFFFFFF == target:
            if log is not None:
                log(tried)
            return "".join(combo)
    if log is not None:
        log(tried)
    return None


# ===========================================================================
# 五、密码爆破（字典 + 纯数字）
# ===========================================================================
def iter_dict_words(path):
    """逐行读取字典候选词：去空白、跳过空行，编码自动回退。

    与 ``md5_crash.iter_dict_words`` 同约定：按二进制行迭代，选定编码后流式
    解码，不一次性载入大文件（``dict/rockyou.txt.gz.gz`` 解压后 140MB）。
    支持 gzip 压缩字典（``.gz`` 结尾），流式解压不占额外内存。
    """
    import gzip
    import os

    if not os.path.isfile(path):
        raise ZipCrackerError(f"字典文件不存在：{path}")
    opener = gzip.open if path.lower().endswith(".gz") else open
    chosen = None
    with opener(path, "rb") as fh:
        for raw in fh:
            if chosen is None:
                for enc in DICT_ENCODINGS:
                    try:
                        raw.decode(enc)
                        chosen = enc
                        break
                    except UnicodeDecodeError:
                        continue
                if chosen is None:
                    chosen = DICT_ENCODINGS[-1]
            try:
                line = raw.decode(chosen)
            except UnicodeDecodeError:
                line = raw.decode(chosen, errors="replace")
            word = line.strip()
            if word:
                yield word


def builtin_dict_path() -> str:
    """内置密码字典的绝对路径。"""
    import os

    return os.path.join(DICT_DIR, BUILTIN_DICT_NAME)


def numeric_passwords(max_len: int = 6):
    """生成 1~``max_len`` 位纯数字密码（惰性，不占内存）。

    与原版一致：从 1 位到 ``max_len`` 位，每位用 ``itertools.product`` 允许
    重复（``0`` → ``00`` → ``000`` …）。
    """
    if not isinstance(max_len, int) or not 1 <= max_len <= MAX_NUMERIC_LEN:
        raise ZipCrackerError(f"纯数字位数须为 1~{MAX_NUMERIC_LEN} 之间的整数。")
    for length in range(1, max_len + 1):
        for digits in itertools.product(string.digits, repeat=length):
            yield "".join(digits)


def _pick_test_entry(zip_path: str) -> str:
    """挑一个加密条目作为密码校验对象。

    优先选**最小**的加密文件（读得最少、最快）。全部未加密则抛异常——那说明
    无需爆破。AES 加密的包 Python 标准库无法解密，抛中文提示改用 7z / john。
    """
    with zipfile.ZipFile(zip_path) as zf:
        encrypted = [i for i in zf.infolist()
                     if i.flag_bits & _ENCRYPT_FLAG and not i.is_dir()]
        if not encrypted:
            raise ZipCrackerError("该压缩包没有任何加密条目，无需爆破密码。")
        encrypted.sort(key=lambda i: i.file_size)
        return encrypted[0].filename


def _verify_password(zf: zipfile.ZipFile, entry: str, password: str) -> bool:
    """校验单个密码：用它打开 ``entry`` 读 1 字节。

    密码错误时 ``zf.open`` 抛 ``RuntimeError``；CRC 对不上抛
    ``BadZipFile``；数据损坏抛 ``zlib.error``。任一异常都判定为密码错误。
    """
    import zlib

    try:
        with zf.open(entry, pwd=password.encode("utf-8")) as handle:
            handle.read(1)
        return True
    except (RuntimeError, zipfile.BadZipFile, zlib.error, ValueError, OSError):
        return False


class ZipCracker:
    """字典 / 纯数字密码爆破主控（后台线程 + 日志队列）。

    接口对齐 ``md5_crash.Md5Cracker``，界面层用法一致::

        cracker = ZipCracker()
        cracker.start("flag.zip", use_builtin=True, max_numeric_len=6)
        while cracker.running:
            for log in cracker.poll_logs():
                print(log)
        print(cracker.status, cracker.result)
    """

    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._log_queue: "queue.Queue" = queue.Queue()
        self.status = STATUS_IDLE
        self.result: str | None = None          # 命中的密码
        self.error: str | None = None           # 运行失败原因（中文）
        self.tried = 0                          # 已尝试的密码数
        self.started_at = 0.0                   # 开始时刻（monotonic）

    @property
    def running(self) -> bool:
        """后台线程是否仍在跑。"""
        return self._thread is not None and self._thread.is_alive()

    def start(self, zip_path, dict_path=None, use_builtin: bool = True,
              max_numeric_len: int = 6, custom_first: bool = True) -> None:
        """启动爆破。参数非法直接抛异常（同步），线程内部异常进 ``error``。

        ``dict_path``       用户自定义字典（文件或目录，可为 ``None``）
        ``use_builtin``     是否叠加内置常用字典
        ``max_numeric_len`` 叠加 0~N 位纯数字字典（0 表示不叠加）
        ``custom_first``    自定义字典是否排在内置字典之前（更快命中常见密码）
        """
        real = check_zip_path(zip_path)
        if self.running:
            raise ZipCrackerError("已有爆破任务在运行，请先停止。")

        # 同步做一次开销小的前置校验，让用户立刻拿到明确错误
        test_entry = _pick_test_entry(real)
        numeric_len = int(max_numeric_len) if max_numeric_len else 0
        if numeric_len < 0 or numeric_len > MAX_NUMERIC_LEN:
            raise ZipCrackerError(f"纯数字位数须为 0~{MAX_NUMERIC_LEN} 之间的整数。")

        self._stop_event.clear()
        self._drain_logs()
        self.status = STATUS_RUNNING
        self.result = None
        self.error = None
        self.tried = 0
        self.started_at = time.monotonic()
        self._thread = threading.Thread(
            target=self._run,
            args=(real, test_entry, dict_path, use_builtin, numeric_len,
                  custom_first),
            daemon=True,
        )
        self._thread.start()

    def stop(self, wait: bool = False, timeout: float = 3.0) -> None:
        """请求停止；``wait=True`` 时阻塞等待线程退出。"""
        self._stop_event.set()
        if wait and self._thread is not None:
            self._thread.join(timeout=timeout)

    def poll_logs(self) -> list:
        """取走当前累积的日志，每条为 ``(kind, *payload)``。

        ``kind`` ∈ ``info`` / ``progress`` / ``found`` / ``done``，界面层据此
        渲染不同行。
        """
        logs = []
        while True:
            try:
                logs.append(self._log_queue.get_nowait())
            except queue.Empty:
                return logs

    def _emit(self, kind: str, *payload) -> None:
        self._log_queue.put((kind, *payload))

    def _drain_logs(self) -> None:
        while True:
            try:
                self._log_queue.get_nowait()
            except queue.Empty:
                return

    def _run(self, zip_path, test_entry, dict_path, use_builtin,
             numeric_len, custom_first) -> None:
        """线程体：按序喂候选密码，命中即停。"""
        try:
            self._crack(zip_path, test_entry, dict_path, use_builtin,
                        numeric_len, custom_first)
        except ZipCrackerError as exc:
            self.error = str(exc)
            self.status = STATUS_ERROR
            self._emit("done", f"爆破异常终止：{self.error}")
        except Exception as exc:  # noqa: BLE001  兜底，避免线程静默死亡
            self.error = f"{exc.__class__.__name__}: {exc}"
            self.status = STATUS_ERROR
            self._emit("done", f"爆破异常终止：{self.error}")

    def _crack(self, zip_path, test_entry, dict_path, use_builtin,
               numeric_len, custom_first) -> None:
        sources = []
        # 字典来源：自定义 → 内置，可切换顺序
        custom = []
        if dict_path:
            import os

            if os.path.isdir(dict_path):
                files = sorted(
                    str(p) for p in Path(dict_path).iterdir()
                    if p.is_file() and p.suffix.lower() in (".txt", ".dict")
                )
            else:
                files = [str(dict_path)]
            custom = files
        builtin = [builtin_dict_path()] if use_builtin else []
        order = (custom + builtin) if custom_first else (builtin + custom)
        for path in order:
            sources.append(("dict", path))

        total_hint = 0
        if not sources and numeric_len == 0:
            raise ZipCrackerError("既没有可用字典，也没有启用纯数字爆破，请先选择其一。")

        for kind, path in sources:
            if self._stop_event.is_set():
                return
            self._emit("info", f"加载字典：{path}")
        if numeric_len:
            self._emit("info", f"叠加 0~{numeric_len} 位纯数字字典。")

        self._emit("info", f"开始爆破，校验条目：{test_entry}")

        start = time.monotonic()
        with zipfile.ZipFile(zip_path) as zf:
            hit = self._feed(sources, numeric_len, zf, test_entry, start)
        cost = time.monotonic() - self.started_at

        if hit is not None:
            self.result = hit
            self.status = STATUS_FOUND
            self._emit("found", hit)
            self._emit("done",
                       f"爆破成功：密码 = {hit}，共尝试 {self.tried} 个，"
                       f"耗时 {cost:.1f} 秒。")
        elif self._stop_event.is_set():
            self.status = STATUS_STOPPED
            self._emit("done",
                       f"已停止：共尝试 {self.tried} 个密码，耗时 {cost:.1f} 秒。")
        else:
            self.status = STATUS_DONE
            self._emit("done",
                       f"字典中的所有密码均已尝试完毕（{self.tried} 个），未命中。"
                       f"请换更大的字典，如 dict/rockyou.txt.gz。")

    def _feed(self, sources, numeric_len, zf, test_entry, start) -> str | None:
        """依次尝试各来源的密码，命中返回密码，否则 ``None``。"""
        for kind, path in sources:
            for word in iter_dict_words(path):
                if self._stop_event.is_set():
                    return None
                self.tried += 1
                if self.tried % CRACK_LOG_INTERVAL == 0:
                    self._emit_progress(start)
                if _verify_password(zf, test_entry, word):
                    return word
        if numeric_len and not self._stop_event.is_set():
            for word in numeric_passwords(numeric_len):
                if self._stop_event.is_set():
                    return None
                self.tried += 1
                if self.tried % CRACK_LOG_INTERVAL == 0:
                    self._emit_progress(start)
                if _verify_password(zf, test_entry, word):
                    return word
        return None

    def _emit_progress(self, start: float) -> None:
        elapsed = time.monotonic() - start
        rate = int(self.tried / elapsed) if elapsed > 0 else 0
        self._emit("progress", self.tried, rate)
