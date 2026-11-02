# -*- coding: utf-8 -*-
"""MD5 爆破：排列枚举 + 多进程 / 多线程。

分层说明
--------
本模块属于逻辑层，**不导入 tkinter 等任何 UI 模块**。它以「MD5 值 + 长度范围 +
进程 / 线程数」为输入，通过「枚举进程 + 验证进程」的多进程结构完成爆破：

- 枚举进程（enumerator）从长度队列取长度，用 :func:`itertools.permutations`
  枚举该长度下的全部候选（字母 / 数字 / 特殊符号），写入有界任务队列；
- 验证进程（worker）内再起多个验证线程，线程从任务队列取候选、计算 MD5 并与
  目标比对，命中后把明文写入结果队列并置停止事件；
- 主控（:class:`Md5Cracker`）负责建队列、起进程、收结果、响应停止请求，并把
  进度日志通过日志队列回传给界面层轮询展示。

设计要点（相对原脚本的修复）
------------------------------
- 所有被 ``multiprocessing.Process`` 调用的函数 / 类均为模块级定义，Windows
  spawn 模式下可直接按「模块路径 + 名称」pickle 查找，去掉原脚本依赖
  ``__main__`` 直跑才可运行的写法；
- 原脚本 ``do_task`` 中 ``while taskq.empty(): return`` 会在 worker 启动瞬间
  因队列为空而立即退出，导致所有 worker 提前退场。本模块改为「有界队列 +
  超时轮询 + 结束哨兵」：枚举进程消费完长度任务后退出，主控确认枚举结束后向
  任务队列投放与验证线程数等量的结束哨兵，验证线程收到哨兵（或停止事件）后
  退出，保证 worker 稳定工作到任务结束；
- 任务队列有界（默认 20000 项），枚举进程在队列满时阻塞重试，形成天然背压，
  避免把排列枚举结果无限塞入内存；
- 日志不直接 ``print``，而是写入日志队列，由界面层 ``poll_logs`` 取回展示；
- 命中或用户停止时置跨进程停止事件，枚举 / 验证双方都能在轮询间隔内退出，
  不会残留僵尸进程。

对外接口
--------
    ALL_LETTERS                候选字符表（字母 + 数字 + 特殊符号）
    STATUS_*                   状态码常量（idle / running / found / stopped /
                                done / error）
    parse_md5(value)           校验 MD5 值（32 位十六进制）
    parse_len(value, field)    校验长度参数（正整数、带上限）
    parse_count(value, field)  校验进程 / 线程数量参数（正整数、带上限）
    Md5Cracker                 主控：start / stop / poll_logs / running / status

命令行入口（可直接运行）::

    python -m lib.md5_crash e522214d32eabe3fda854da213c62d5f --min-len 3 --max-len 4
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import multiprocessing
import os
import queue
import sys
import threading
import time
from string import ascii_letters, digits

# ===========================================================================
# 一、常量与参数上限
# ===========================================================================
#: 候选字符表：大小写字母 + 数字 + 常见符号（沿用原脚本字符集）
ALL_LETTERS = ascii_letters + digits + ".,;*@#"

#: 三种内置模式对应的候选字符表（纯数字 / 纯字母 / 混合）
CHARSET_DIGITS = digits
CHARSET_LETTERS = ascii_letters
CHARSET_MIXED = ALL_LETTERS

#: 任务队列容量：满了枚举进程阻塞重试，防止内存无限增长
DEFAULT_TASKQ_SIZE = 20000
#: 队列 / 进程轮询间隔（秒）：越小对「停止」的响应越快
POLL_INTERVAL = 0.2
#: 进度日志节流：每尝试这么多次才回传一条进度日志
LOG_PROGRESS_INTERVAL = 2000
#: 进程 / 线程数量参数上限（防止误填把机器拖垮）
MAX_COUNT_LIMIT = 64
#: 枚举长度上限
MAX_LEN_LIMIT = 24
#: 结束哨兵（长度队列 / 任务队列通用，None 值）
_SENTINEL = None

#: 默认字典目录：项目根下的 dict 目录（任务约定的爆破字典存放处）；
#: PyInstaller 冻结环境下回退到打包数据根下的 dict（spec 已将其打入 datas）
def _default_dict_dir() -> str:
    from lib.runtime_paths import resource

    return str(resource("dict"))


DEFAULT_DICT_DIR = _default_dict_dir()
#: 字典文件读取编码回退顺序：优先 utf-8，失败依次回退 latin-1 / ANSI(GBK)
DICT_ENCODINGS = ("utf-8", "latin-1", "gbk")

#: 状态码（界面层据此展示终态）
STATUS_IDLE = "idle"
STATUS_RUNNING = "running"
STATUS_FOUND = "found"
STATUS_STOPPED = "stopped"
STATUS_DONE = "done"
STATUS_ERROR = "error"

#: 支持的哈希爆破算法：算法名 -> 十六进制摘要长度。
#: 新增算法只需在此登记，枚举 / 字典 / 多进程框架自动复用。
HASH_SPECS = {
    "md5": 32,
    "sha1": 40,
    "sha256": 64,
    "sha512": 128,
    "sha3_256": 64,
}

#: 默认哈希算法（保持历史行为：MD5 爆破）
DEFAULT_HASH_NAME = "md5"


def hash_length(hash_name: str) -> int:
    """返回指定哈希算法的十六进制摘要长度；未知算法抛 ``ValueError``。"""
    name = str(hash_name or DEFAULT_HASH_NAME).strip().lower()
    if name not in HASH_SPECS:
        raise ValueError(f"不支持的哈希算法：{hash_name}")
    return HASH_SPECS[name]


def hash_display_name(hash_name: str) -> str:
    """返回算法的显示名（用于日志 / 文案，如 ``md5`` -> ``MD5``）。"""
    return str(hash_name or DEFAULT_HASH_NAME).strip().upper()


# ===========================================================================
# 二、参数校验（字符串 / 参数进）
# ===========================================================================
def parse_md5(value) -> str:
    """校验 MD5 值，返回统一为小写的 32 位十六进制字符串（向后兼容别名）。"""
    return parse_hash(value, "md5")


def parse_hash(value, hash_name: str = DEFAULT_HASH_NAME) -> str:
    """校验哈希值，返回统一为小写的十六进制字符串。

    按 ``hash_name`` 对应的摘要长度校验（md5=32 / sha1=40 / sha256=64 等）。
    """
    name = str(hash_name or DEFAULT_HASH_NAME).strip().lower()
    length = hash_length(name)
    text = str(value or "").strip().lower()
    if len(text) != length or any(char not in "0123456789abcdef" for char in text):
        raise ValueError(
            f"{hash_display_name(name)} 值必须是 {length} 位十六进制字符串。")
    return text


def _parse_positive_int(value, field: str, upper: int) -> int:
    """把界面 / 命令行传入的值转成正整数，失败时抛中文 ``ValueError``。"""
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        raise ValueError(f"{field}必须是整数。")
    if number <= 0:
        raise ValueError(f"{field}必须大于 0。")
    if number > upper:
        raise ValueError(f"{field}过大（上限 {upper}）。")
    return number


def parse_len(value, field: str) -> int:
    """校验枚举长度参数（如最小 / 最大长度）。"""
    return _parse_positive_int(value, field, MAX_LEN_LIMIT)


def parse_count(value, field: str) -> int:
    """校验进程 / 线程数量参数。"""
    return _parse_positive_int(value, field, MAX_COUNT_LIMIT)


_CHARSET_ALIASES = {
    "digits": CHARSET_DIGITS,
    "letters": CHARSET_LETTERS,
    "mixed": CHARSET_MIXED,
}


def parse_charset(value, field: str = "字符集") -> str:
    """校验候选字符集。

    支持内置别名（``digits`` / ``letters`` / ``mixed``，对应纯数字 / 纯字母 /
    混合模式），也接受直接传入字符表（自动去重并保证非空）。
    """
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{field}不能为空。")
    if text in _CHARSET_ALIASES:
        return _CHARSET_ALIASES[text]
    chars = "".join(dict.fromkeys(text))
    if not chars:
        raise ValueError(f"{field}不能为空。")
    return chars


def parse_prediction(value, field: str = "预测词") -> str:
    """校验预测词（前缀/后缀）：返回去空后的字符串，空串表示不预测。"""
    text = str(value or "").strip()
    return text


def parse_candidates(value, field: str = "候选输入池") -> list:
    """规范化候选输入池：None / 空串 → ``[]``，其余按行拆分去空白。

    - 传入字符串：按行拆分（兼容界面多行输入框全文 / 候选文件内容），每行
      ``strip`` 后跳过空行；
    - 传入序列（如界面层预拆分的列表）：逐项 ``strip`` 去空。

    返回的列表作为**高优先级候选**：字典爆破模式下非空时先于字典文件逐词尝试，
    为空时直接尝试字典。
    """
    if value is None:
        return []
    lines = value.splitlines() if isinstance(value, str) else list(value)
    words = []
    for line in lines:
        word = str(line).strip()
        if word:
            words.append(word)
    return words


def parse_dict_path(value, field: str = "字典路径") -> list:
    """校验字典路径，返回待读取的字典文件绝对路径列表。

    - 传入**单个字典文件**：直接使用该文件；
    - 传入**目录**（如默认的 ``dict`` 目录）：扫描目录下全部普通文件依次尝试；
    - 路径不存在 / 目录为空时抛中文 ``ValueError``。
    """
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{field}不能为空。")
    if not os.path.exists(text):
        raise ValueError(f"{field}不存在：{text}")
    if os.path.isdir(text):
        files = [
            os.path.abspath(os.path.join(text, name))
            for name in sorted(os.listdir(text))
            if os.path.isfile(os.path.join(text, name))
        ]
        if not files:
            raise ValueError(f"{field}目录下没有可用字典文件：{text}")
        return files
    if os.path.isfile(text):
        return [os.path.abspath(text)]
    raise ValueError(f"{field}既不是文件也不是目录：{text}")


def iter_dict_words(path):
    """逐行读取字典文件候选词：去除行尾换行与空白，跳过空行。

    编码处理：优先 ``utf-8``；首行解码失败则依次回退 ``latin-1`` /
    ``gbk``（Windows ANSI）。选定编码后按行流式解码，不一次性载入大文件；
    个别行解码异常时用替换字符兜底，不影响整体读取与爆破。

    支持 gzip 压缩字典（``.gz`` 结尾），流式解压不占额外内存（对齐
    ``zip_cracker.iter_dict_words`` 的行为，便于复用 ``dict/rockyou.txt.gz``）。
    """
    import gzip
    import os

    if not os.path.isfile(path):
        raise ValueError(f"字典文件不存在：{path}")
    opener = gzip.open if path.lower().endswith(".gz") else open
    chosen = None
    with opener(path, "rb") as fh:
        for raw in fh:  # 二进制按行迭代，多字节序列不含换行字节，行切分安全
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


def _candidates_for(charset: str, length: int):
    """按字符集生成长度 ``length`` 的候选迭代器。

    纯数字模式（字符集恰为 ``digits``）使用笛卡尔积 ``product``：候选从
    ``0`` 开始按数值递增（``00…0`` → ``99…9``，允许数字重复，符合递增语义）；
    其余字符集沿用原脚本的排列枚举 ``permutations``（候选内字符不重复）。
    """
    if charset == CHARSET_DIGITS:
        return itertools.product(charset, repeat=length)
    return itertools.permutations(charset, length)


# ===========================================================================
# 三、验证线程（worker 进程内部使用）
# ===========================================================================
class Md5VerifyThread(threading.Thread):
    """单个验证线程：从任务队列取候选、验证 MD5、上报命中。

    退出条件（满足其一即退出）:
        1. 从任务队列取到结束哨兵 ``None``；
        2. 跨进程停止事件被置位（命中 / 用户停止）；
        3. 捕获到异常（记录到日志队列后退出）。
    """

    def __init__(self, name, taskq, resultq, logq, stop_event, md5_value,
                 hash_name=DEFAULT_HASH_NAME):
        super().__init__(name=name, daemon=True)
        self.taskq = taskq
        self.resultq = resultq
        self.logq = logq
        self.stop_event = stop_event
        self.md5_value = md5_value
        self.hash_name = str(hash_name or DEFAULT_HASH_NAME).strip().lower()
        self.attempts = 0

    def _emit_log(self, kind, *payload) -> None:
        """向日志队列写入一条日志；队列满或不可写时静默丢弃（不影响爆破）。"""
        try:
            self.logq.put((kind, *payload), timeout=0.1)
        except (queue.Full, OSError):
            pass

    def run(self) -> None:
        while not self.stop_event.is_set():
            try:
                text = self.taskq.get(timeout=POLL_INTERVAL)
            except queue.Empty:
                continue
            except OSError:
                # 底层管道异常（如其它进程被强杀），放弃本轮尝试
                self._emit_log("info", f"{self.name} 读取任务队列异常，线程退出。")
                return
            if text is None:  # 结束哨兵
                return
            if self.stop_event.is_set():
                return

            self.attempts += 1
            if self.attempts % LOG_PROGRESS_INTERVAL == 0:
                self._emit_log("progress", self.name, self.attempts, text)

            if hashlib.new(self.hash_name, text.encode("utf-8")).hexdigest() == self.md5_value:
                self._emit_log("found", text)
                try:
                    self.resultq.put(("found", text), timeout=0.1)
                except (queue.Full, OSError):
                    pass
                self.stop_event.set()
                return


# ===========================================================================
# 四、进程函数（模块级，可被 multiprocessing spawn pickle）
# ===========================================================================
def _enumerator_process(len_q, taskq, stop_event, charset, prefix="", suffix="") -> None:
    """枚举进程：消费长度任务，把该长度的全部候选写入任务队列。

    长度任务为整数；消费到结束哨兵 ``None``（长度任务已耗尽）后退出；
    停止事件置位时同样在轮询间隔内退出。

    ``prefix`` / ``suffix`` 为预测词（已知原文前缀/后缀），枚举的候选词会
    拼接为 ``prefix + candidate + suffix`` 后写入任务队列。

    退出前调用 ``cancel_join_thread``：Windows 上 multiprocessing.Queue 在
    进程退出清理时会等待本地 feeder 线程把积压数据发完，若消费端（worker）
    已退出，会因管道无对端而挂死，导致主控 join 不到枚举进程。
    """
    try:
        while not stop_event.is_set():
            try:
                length = len_q.get(timeout=POLL_INTERVAL)
            except queue.Empty:
                continue
            except OSError:
                return
            if length is None:  # 长度任务耗尽
                return

            for item in _candidates_for(charset, length):
                if stop_event.is_set():
                    return
                candidate = prefix + "".join(item) + suffix
                # 有界队列 + 超时重试：满了就阻塞等待，形成背压且不阻塞停止响应
                while not stop_event.is_set():
                    try:
                        taskq.put(candidate, timeout=POLL_INTERVAL)
                        break
                    except queue.Full:
                        continue
                    except OSError:
                        return
    finally:
        try:
            taskq.cancel_join_thread()
        except Exception:
            pass


def _worker_process(taskq, resultq, logq, stop_event, md5_value, thread_num,
                    hash_name=DEFAULT_HASH_NAME) -> None:
    """验证进程：内部再起 ``thread_num`` 个验证线程，全部退出后进程结束。"""
    try:
        threads = []
        for index in range(thread_num):
            name = f"W{os.getpid()}-T{index}"
            thread = Md5VerifyThread(
                name, taskq, resultq, logq, stop_event, md5_value, hash_name
            )
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join()
    finally:
        # 与枚举进程同理：退出前放弃等待 feeder 清理，避免挂死在进程退出
        for q in (taskq, resultq, logq):
            try:
                q.cancel_join_thread()
            except Exception:
                pass


def _dict_enumerator_process(files, taskq, logq, stop_event) -> None:
    """字典枚举进程：从分到的字典文件逐行读取候选词写入任务队列。

    与排列枚举进程行为一致：逐行去空白后写入有界任务队列（背压式阻塞），
    命中 / 停止时在轮询间隔内退出；退出前 ``cancel_join_thread``，保证
    Windows spawn 下进程干净退出、主控可正常 join。
    """
    try:
        for file_path in files:
            if stop_event.is_set():
                return
            count = 0
            for word in iter_dict_words(file_path):
                if stop_event.is_set():
                    return
                while not stop_event.is_set():
                    try:
                        taskq.put(word, timeout=POLL_INTERVAL)
                        break
                    except queue.Full:
                        continue
                    except OSError:
                        return
                count += 1
            try:
                logq.put(
                    ("info", f"字典候选词已处理 {count} 个。"),
                    timeout=0.1,
                )
            except (queue.Full, OSError):
                pass
    finally:
        for q in (taskq, logq):
            try:
                q.cancel_join_thread()
            except Exception:
                pass


# ===========================================================================
# 五、主控（界面层 / 命令行共用）
# ===========================================================================
class Md5Cracker:
    """MD5 爆破主控：建队列、起进程、收结果、响应停止。

    界面层用法::

        cracker = Md5Cracker()
        cracker.start(md5_value, min_len, max_len, worker_num, thread_num, charset)
        # 轮询：每隔 200ms 调一次 poll_logs() 刷新日志、检查 running 状态
        for log in cracker.poll_logs():
            ...
        cracker.stop()          # 用户点「停止」时调用
        cracker.status          # 终态：found / stopped / done / error
        cracker.result          # 命中明文（status == found 时有效）

    实例同时充当状态容器：控制线程与界面线程共享简单字段（队列引用、
    状态码、结果），跨进程通信全部走 ``multiprocessing`` 队列 / 事件。
    """

    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._stop_requested = threading.Event()  # 界面层主动停止请求
        self.log_queue = None                      # 日志队列（控制线程创建）
        self.status = STATUS_IDLE
        self.result: str | None = None             # 命中明文
        self.error: str | None = None              # 运行失败原因（中文）
        self.started_at = 0.0                      # 开始时刻（monotonic）

    # -- 状态 --------------------------------------------------------------
    @property
    def running(self) -> bool:
        """控制线程是否仍在工作。"""
        return self._thread is not None and self._thread.is_alive()

    # -- 控制 --------------------------------------------------------------
    def start(self, md5_value, min_len, max_len, worker_num, thread_num,
              charset=None, dict_path=None, candidates=None,
              prefix="", suffix="", hash_name=DEFAULT_HASH_NAME) -> None:
        """校验参数并在后台控制线程启动爆破。

        ``charset`` 为候选字符集：可传内置别名（``digits`` / ``letters`` /
        ``mixed``）或直接传字符表；不传默认 ``mixed``（混合模式）。

        ``dict_path`` 传入时进入**字典爆破模式**：可传单个字典文件路径或
        ``dict`` 目录（目录下全部字典文件依次尝试），此时忽略
        ``min_len`` / ``max_len`` / ``charset`` 参数。

        ``candidates`` 为**候选输入池**（多行字符串或字符串序列，逐词高优先级
        候选）：仅字典爆破模式生效，非空时先逐词尝试输入池、再继续字典文件，
        为空时直接尝试字典。字典模式下未传 ``dict_path`` 但传入非空
         ``candidates`` 时，自动加载默认字典目录（``DEFAULT_DICT_DIR``）。

        ``prefix`` / ``suffix`` 为**预测词**（已知原文前缀/后缀），仅枚举模式
        生效；枚举的候选词会拼接为 ``prefix + candidate + suffix``。

        ``hash_name`` 为目标哈希算法（``md5`` / ``sha1`` / ``sha256`` /
        ``sha512`` / ``sha3_256``），默认 ``md5``。SHA1 / SHA256 等算法复用
        同一套枚举 / 字典 / 多进程框架。

        异常:
            ValueError: 参数非法（由 ``parse_*`` 抛出）
        """
        if self.running:
            raise ValueError("上一次爆破尚未结束，请先停止。")

        hash_name = str(hash_name or DEFAULT_HASH_NAME).strip().lower()
        hash_length(hash_name)  # 校验算法合法性
        md5_value = parse_hash(md5_value, hash_name)
        worker_num = parse_count(worker_num, "进程数")
        thread_num = parse_count(thread_num, "线程数")
        candidates = parse_candidates(candidates)
        prefix = parse_prediction(prefix)
        suffix = parse_prediction(suffix)

        files = None
        if dict_path is not None:
            files = parse_dict_path(dict_path)
            min_len = max_len = charset = None
        elif candidates:
            # 默认字典必选：未显式指定字典路径但给出候选输入池时，自动加载 dict 目录
            files = parse_dict_path(DEFAULT_DICT_DIR)
            min_len = max_len = charset = None
        else:
            min_len = parse_len(min_len, "最小长度")
            max_len = parse_len(max_len, "最大长度")
            charset = parse_charset(charset) if charset is not None else CHARSET_MIXED
            if min_len > max_len:
                raise ValueError("最小长度不能大于最大长度。")
            # 预测词长度不能超过最大长度
            pred_len = len(prefix) + len(suffix)
            if pred_len > max_len:
                raise ValueError(
                    f"预测词总长 {pred_len} 位，最大长度仅 {max_len} 位，无法枚举剩余部分。"
                )

        self._stop_requested.clear()
        self.status = STATUS_RUNNING
        self.result = None
        self.error = None
        self.started_at = time.monotonic()
        self._thread = threading.Thread(
            target=self._controller,
            args=(md5_value, min_len, max_len, worker_num, thread_num, charset, files,
                  candidates, prefix, suffix, hash_name),
            name=f"{hash_name}-crash-controller",
            daemon=True,
        )
        self._thread.start()

    def stop(self, wait: bool = False, timeout: float = 3.0) -> None:
        """请求停止爆破；``wait=True`` 时等待控制线程退出（最多 ``timeout`` 秒）。"""
        self._stop_requested.set()
        if wait and self._thread is not None:
            self._thread.join(timeout)

    # -- 日志 --------------------------------------------------------------
    def poll_logs(self) -> list:
        """非阻塞取走日志队列中当前全部日志。

        日志条目为元组:
            ("info", message)                      直接显示的文本
            ("progress", name, count, text)        进度（界面层按模板格式化）
            ("found", plain)                       命中明文
            ("done", message)                      结束文本
        """
        logs = []
        logq = self.log_queue
        if logq is not None:
            while True:
                try:
                    logs.append(logq.get_nowait())
                except queue.Empty:
                    break
                except OSError:
                    break
        return logs

    # -- 控制线程体 ---------------------------------------------------------
    def _controller(self, md5_value, min_len, max_len, worker_num, thread_num,
                    charset, files, candidates, prefix="", suffix="",
                    hash_name=DEFAULT_HASH_NAME) -> None:
        try:
            if files is not None:
                self._run_dict_controller(md5_value, files, worker_num, thread_num,
                                          candidates, hash_name)
            else:
                self._run_controller(md5_value, min_len, max_len, worker_num, thread_num,
                                     charset, prefix, suffix, hash_name)
        except Exception as exc:  # noqa: BLE001  (控制线程异常需落到 error 字段)
            self.error = str(exc) or exc.__class__.__name__
            self.status = STATUS_ERROR
            if self.log_queue is not None:
                try:
                    self.log_queue.put(("done", f"爆破异常终止：{self.error}"), timeout=0.1)
                except (queue.Full, OSError):
                    pass

    def _run_controller(self, md5_value, min_len, max_len, worker_num, thread_num,
                        charset, prefix="", suffix="",
                        hash_name=DEFAULT_HASH_NAME) -> None:
        # 兼容 PyInstaller 打包：spawn 子进程的引导在此处兜底（普通源码运行无副作用）
        multiprocessing.freeze_support()
        display = hash_display_name(hash_name)

        # 进程分工：约一半进程做枚举，其余做验证，总数 ≈ worker_num
        enumerator_num = max(1, worker_num // 2)
        worker_proc_num = max(1, worker_num - enumerator_num)
        sentinel_num = worker_proc_num * thread_num

        ctx = multiprocessing.get_context("spawn")
        taskq = ctx.Queue(maxsize=DEFAULT_TASKQ_SIZE)
        resultq = ctx.Queue()
        len_q = ctx.Queue()
        logq = ctx.Queue()
        stop_event = ctx.Event()
        self.log_queue = logq

        try:
            logq.put((
                "info",
                f"{display} 爆破启动：目标={md5_value} 长度=[{min_len}, {max_len}] "
                f"进程={worker_proc_num}（枚举 {enumerator_num} + 验证 {worker_proc_num}）"
                f"线程/进程={thread_num} 字符集={len(charset)} 个字符"
                f"预测词：前缀={prefix or '无'} 后缀={suffix or '无'}",
            ), timeout=0.1)
        except (queue.Full, OSError):
            pass

        # 长度任务：闭区间 [min_len - pred_len, max_len - pred_len]，末尾放枚举进程数等量的哨兵
        pred_len = len(prefix) + len(suffix)
        enum_min = max(1, min_len - pred_len)
        enum_max = max_len - pred_len
        for length in range(enum_min, enum_max + 1):
            len_q.put(length)
        for _ in range(enumerator_num):
            len_q.put(_SENTINEL)

        enumerators = []
        workers = []
        try:
            for _ in range(enumerator_num):
                proc = ctx.Process(
                    target=_enumerator_process,
                    args=(len_q, taskq, stop_event, charset, prefix, suffix)
                )
                proc.start()
                enumerators.append(proc)
            for _ in range(worker_proc_num):
                proc = ctx.Process(
                    target=_worker_process,
                    args=(taskq, resultq, logq, stop_event, md5_value, thread_num,
                          hash_name),
                )
                proc.start()
                workers.append(proc)

            found = self._wait_outcome(resultq, enumerators)
            # 命中 / 用户停止：先置停止事件，让仍存活的进程在轮询间隔内退出
            if found is not None or self._stop_requested.is_set():
                stop_event.set()
            for proc in enumerators:
                proc.join()
            # 自然结束（枚举耗尽且未命中）：投放哨兵让验证线程优雅退出
            if found is None and not self._stop_requested.is_set():
                for _ in range(sentinel_num):
                    taskq.put(_SENTINEL)
            for proc in workers:
                proc.join()
        finally:
            # 兜底清理：确保停止事件已置位，防止残留进程空转
            stop_event.set()

        # 收尾：结果与状态
        if found is None:
            try:
                found = resultq.get_nowait()
            except queue.Empty:
                pass
            except OSError:
                found = None

        cost = time.monotonic() - self.started_at
        if found is not None:
            self.result = found[1]
            self.status = STATUS_FOUND
            logq.put(("done", f"爆破成功：明文 = {self.result}，耗时 {cost:.1f} 秒。"), timeout=0.1)
        elif self._stop_requested.is_set():
            self.status = STATUS_STOPPED
            logq.put(("done", f"已停止：本次爆破未完成，已耗时 {cost:.1f} 秒。"), timeout=0.1)
        else:
            self.status = STATUS_DONE
            logq.put(("done", f"爆破结束：长度 [{min_len}, {max_len}] 内未找到匹配明文，耗时 {cost:.1f} 秒。"), timeout=0.1)

    def _run_dict_controller(self, md5_value, files, worker_num, thread_num,
                             candidates, hash_name=DEFAULT_HASH_NAME) -> None:
        """字典爆破控制线程体：候选输入池 + 字典枚举进程 + 验证进程。

        - ``candidates``（候选输入池）非空时，先由主控线程逐词写入任务队列
          （背压式阻塞 + 轮询停止 / 命中），worker 优先消费，实现「先测输入池
          再测字典」的高优先级语义；为空时直接启动字典枚举进程。
        - 字典文件按枚举进程数**文件级分片**，各进程只读自己的分片，避免重复；
        - 命中 / 停止 / 自然耗尽三条结束路径与 ``_run_controller`` 完全相同，
          进程退出均依赖 ``cancel_join_thread`` 保证 Windows spawn 下干净退出。
        """
        # 兼容 PyInstaller 打包：spawn 子进程的引导在此处兜底（普通源码运行无副作用）
        multiprocessing.freeze_support()
        display = hash_display_name(hash_name)

        enumerator_num = max(1, worker_num // 2)
        worker_proc_num = max(1, worker_num - enumerator_num)
        sentinel_num = worker_proc_num * thread_num

        ctx = multiprocessing.get_context("spawn")
        taskq = ctx.Queue(maxsize=DEFAULT_TASKQ_SIZE)
        resultq = ctx.Queue()
        logq = ctx.Queue()
        stop_event = ctx.Event()
        self.log_queue = logq

        try:
            logq.put((
                "info",
                f"{display} 字典爆破启动：目标={md5_value} 字典文件数={len(files)} "
                f"候选输入池={len(candidates)} 词"
                f"进程={worker_proc_num}（枚举 {enumerator_num} + 验证 {worker_proc_num}）"
                f"线程/进程={thread_num}",
            ), timeout=0.1)
            if candidates:
                logq.put((
                    "info",
                    f"候选输入池非空：将优先尝试 {len(candidates)} 个候选词，再继续字典。",
                ), timeout=0.1)
        except (queue.Full, OSError):
            pass

        # 文件级分片：按枚举进程数均分，保证每个文件恰好被一个枚举进程读取
        file_chunks = [files[index::enumerator_num] for index in range(enumerator_num)]

        enumerators = []
        workers = []
        try:
            # 1) 先启动验证进程：输入池逐词写入需要消费者，否则有界队列会死锁
            for _ in range(worker_proc_num):
                proc = ctx.Process(
                    target=_worker_process,
                    args=(taskq, resultq, logq, stop_event, md5_value, thread_num,
                          hash_name),
                )
                proc.start()
                workers.append(proc)

            # 2) 候选输入池优先入队（高优先级候选；命中 / 停止时提前返回）
            pre_found = None
            if candidates:
                pre_found = self._feed_candidates(taskq, resultq, stop_event, candidates)

            # 3) 输入池未命中才启动字典枚举进程（命中后无需枚举，直接收尾）
            if pre_found is None:
                for chunk in file_chunks:
                    if not chunk:
                        continue
                    proc = ctx.Process(
                        target=_dict_enumerator_process,
                        args=(chunk, taskq, logq, stop_event),
                    )
                    proc.start()
                    enumerators.append(proc)

            if pre_found is not None:
                found = pre_found
            else:
                found = self._wait_outcome(resultq, enumerators)
            # 命中 / 用户停止：先置停止事件，让仍存活的进程在轮询间隔内退出
            if found is not None or self._stop_requested.is_set():
                stop_event.set()
            for proc in enumerators:
                proc.join()
            # 自然结束（字典耗尽且未命中）：投放哨兵让验证线程优雅退出
            if found is None and not self._stop_requested.is_set():
                for _ in range(sentinel_num):
                    taskq.put(_SENTINEL)
            for proc in workers:
                proc.join()
        finally:
            # 兜底清理：确保停止事件已置位，防止残留进程空转
            stop_event.set()

        # 收尾：结果与状态
        if found is None:
            try:
                found = resultq.get_nowait()
            except queue.Empty:
                pass
            except OSError:
                found = None

        cost = time.monotonic() - self.started_at
        if found is not None:
            self.result = found[1]
            self.status = STATUS_FOUND
            logq.put(("done", f"爆破成功：明文 = {self.result}，耗时 {cost:.1f} 秒。"), timeout=0.1)
        elif self._stop_requested.is_set():
            self.status = STATUS_STOPPED
            logq.put(("done", f"已停止：本次爆破未完成，已耗时 {cost:.1f} 秒。"), timeout=0.1)
        else:
            self.status = STATUS_DONE
            logq.put(("done", f"爆破结束：{len(files)} 个字典文件未找到匹配明文，耗时 {cost:.1f} 秒。"), timeout=0.1)

    def _feed_candidates(self, taskq, resultq, stop_event, candidates):
        """把候选输入池逐词写入任务队列（高优先级：先于字典入队）。

        有界队列满时阻塞重试（背压），每轮检查跨进程停止事件 / 主动停止请求；
        若 worker 已命中（结果队列出现 ``found``），立即返回命中结果并停止写入，
        避免为已命中的目标继续消耗输入池与字典。
        """
        for word in candidates:
            if stop_event.is_set() or self._stop_requested.is_set():
                break
            try:
                hit = resultq.get_nowait()
            except queue.Empty:
                hit = None
            except OSError:
                hit = None
            if hit is not None:
                return hit
            while not stop_event.is_set() and not self._stop_requested.is_set():
                try:
                    taskq.put(word, timeout=POLL_INTERVAL)
                    break
                except queue.Full:
                    continue
                except OSError:
                    return None
        try:
            hit = resultq.get_nowait()
        except queue.Empty:
            return None
        except OSError:
            return None
        return hit

    def _wait_outcome(self, resultq, enumerators):
        """轮询等待「命中 / 用户停止 / 枚举进程全部退出」三个结束条件之一。"""
        while not self._stop_requested.is_set():
            try:
                return resultq.get(timeout=POLL_INTERVAL)
            except queue.Empty:
                pass
            except OSError:
                return None
            if not any(proc.is_alive() for proc in enumerators):
                # 枚举进程全部退出：可能是自然耗尽或异常，结束等待
                return None
        return None


# ===========================================================================
# 六、命令行入口
# ===========================================================================
def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m lib.md5_crash",
        description="排列枚举 + 多进程 / 多线程爆破 32 位 MD5 的原始明文。",
    )
    parser.add_argument("md5", help="32 位十六进制 MD5 值")
    parser.add_argument(
        "--min-len", type=int, default=8,
        help="枚举最小长度（含端点），默认 8，上限 24。",
    )
    parser.add_argument(
        "--max-len", type=int, default=18,
        help="枚举最大长度（含端点），默认 18，上限 24。",
    )
    parser.add_argument(
        "--worker", type=int, default=8,
        help="总进程数（约一半枚举、一半验证），默认 8，上限 64。",
    )
    parser.add_argument(
        "--thread", type=int, default=8,
        help="每个验证进程内的线程数，默认 8，上限 64。",
    )
    parser.add_argument(
        "--charset", default="mixed",
        help="候选字符集：digits（纯数字）/ letters（纯字母）/ mixed（混合，默认）"
             "或直接传字符表。",
    )
    parser.add_argument(
        "--dict", default=None,
        help="字典文件或目录路径；传入后进入字典爆破模式（逐行读词比对，"
             "忽略长度 / 字符集参数，目录则扫描其下全部字典文件）。",
    )
    parser.add_argument(
        "--candidates-file", default=None,
        help="候选输入池文件（UTF-8，每行一个候选词）；与 --dict 搭配使用时，"
             "非空输入池会先于字典逐词尝试；单独传入时自动加载默认 dict 目录。",
    )
    return parser


def _cli_log_line(kind, *payload) -> str:
    """命令行场景的日志格式化（界面层请自行用 .env 模板格式化）。"""
    if kind == "info":
        return str(payload[0])
    if kind == "progress":
        return f"{payload[0]} 已尝试 {payload[1]} 次，当前候选：{payload[2]}"
    if kind == "found":
        return f"命中明文：{payload[0]}"
    if kind == "done":
        return str(payload[0])
    return ""


def main(argv=None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        md5_value = parse_md5(args.md5)
        worker_num = parse_count(args.worker, "进程数")
        thread_num = parse_count(args.thread, "线程数")
        dict_path = None
        candidates = None
        if args.candidates_file:
            with open(args.candidates_file, "r", encoding="utf-8") as fh:
                candidates = parse_candidates(fh.read())
        if args.dict:
            dict_path = parse_dict_path(args.dict)
        elif not candidates:
            min_len = parse_len(args.min_len, "最小长度")
            max_len = parse_len(args.max_len, "最大长度")
            charset = parse_charset(args.charset, "字符集")
            if min_len > max_len:
                raise ValueError("最小长度不能大于最大长度。")
    except ValueError as exc:
        print(f"MD5 爆破失败：{exc}", file=sys.stderr)
        return 1

    cracker = Md5Cracker()
    try:
        cracker.start(
            md5_value,
            args.min_len if dict_path is None and not candidates else None,
            args.max_len if dict_path is None and not candidates else None,
            worker_num,
            thread_num,
            charset=args.charset if dict_path is None and not candidates else None,
            dict_path=args.dict if args.dict else None,
            candidates=candidates,
        )
        while cracker.running:
            for log in cracker.poll_logs():
                print(_cli_log_line(*log), flush=True)
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        cracker.stop(wait=True)
        print("\n收到中断，正在停止爆破…", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"MD5 爆破失败：{exc}", file=sys.stderr)
        return 1

    for log in cracker.poll_logs():
        print(_cli_log_line(*log), flush=True)
    if cracker.status == STATUS_FOUND:
        print(f"爆破成功：明文 = {cracker.result}")
        return 0
    if cracker.status == STATUS_STOPPED:
        print("已停止：本次爆破未完成。")
        return 1
    if cracker.status == STATUS_ERROR:
        print(f"爆破异常终止：{cracker.error}", file=sys.stderr)
        return 1
    print("爆破结束：未找到匹配明文。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
