# -*- coding: utf-8 -*-
"""键盘输入模拟：按设定的速率与持续时间，向当前焦点窗口持续注入「物理级」按键。

分层说明
--------
本模块属于逻辑层，**不导入 tkinter 等任何 UI 模块**；但它与 ``lib`` 中
「字符串进、字符串出」的纯函数不同，会通过系统接口产生真实副作用：

    - 内容 / 参数非法      -> 抛中文 ``ValueError``（复用标准库异常，不自建异常层）
    - 平台不支持、注入失败 -> 抛中文 ``OSError``

物理按键级注入
--------------
所有按键事件都以「扫描码 + ``KEYEVENTF_SCANCODE``」下发（``wVk=0``、
``wScan=<扫描码>``），而不是只填虚拟键码 ``wVk``。模拟器 / 游戏等软件只认
真实键盘硬件上报的扫描码，这种下发方式与物理键盘一致，因此对它们同样有效。

注意：扫描码按美式布局（QWERTY）解析，最终落到什么字符由目标系统的键盘
布局决定 —— 这与真实物理键盘的行为完全一致。

对外接口
--------
    LETTERS                          小写 26 字母常量（默认模拟内容）
    NAMED_KEYS                       可用特殊键名（{ENTER} / {TAB} / {F1} ...）
    build_keys(text)                 文本 -> 按键序列（失败抛中文 ValueError）
    build_plan(text, rate, duration) 文本 + 参数 -> 本次模拟计划 Plan
    foreground_process_name()        当前前台窗口的进程名（非 Windows 抛中文 OSError）
    find_protected_process(names)    前台进程命中反作弊保护名单时返回其进程名
    KeySimulator                     后台线程执行器：start / stop / progress / wait

命令行入口（可直接运行）::

    python -m lib.key_simulator --text abc --rate 20 --duration 3
    python -m lib.key_simulator --text "{ENTER}" --dry-run
"""

from __future__ import annotations

import argparse
import ctypes
import math
import re
import sys
import threading
import time
from typing import NamedTuple

# ===========================================================================
# 一、常量与参数上限
# ===========================================================================
#: 小写英文字母表（26 个），也是默认要模拟输入的内容
LETTERS = "abcdefghijklmnopqrstuvwxyz"

#: 默认输入速率（次 / 秒）
DEFAULT_RATE = 20.0
#: 默认持续时间（秒）
DEFAULT_DURATION = 10.0

#: 速率上限（次 / 秒）：再快就会因为键过多而被系统丢弃
MAX_RATE = 500.0
#: 持续时间上限（秒）
MAX_DURATION = 3600.0

_IS_WINDOWS = sys.platform.startswith("win")

# ---------------------------------------------------------------------------
# 键盘扫描码表（USB HID / Set 1，美式 QWERTY 布局）
# ---------------------------------------------------------------------------
#: 修饰键一律使用左侧键的扫描码
_SCAN_SHIFT = 0x2A
_SCAN_CTRL = 0x1D
_SCAN_ALT = 0x38

#: 主键盘符号行：未按 Shift 的字符、按住 Shift 的字符、以及该行各键的 (虚拟键码, 扫描码)
_SYMBOL_ROWS = (
    (
        "`1234567890-=",
        "~!@#$%^&*()_+",
        (
            (0xC0, 0x29), (0x31, 0x02), (0x32, 0x03), (0x33, 0x04),
            (0x34, 0x05), (0x35, 0x06), (0x36, 0x07), (0x37, 0x08),
            (0x38, 0x09), (0x39, 0x0A), (0x30, 0x0B), (0xBD, 0x0C),
            (0xBB, 0x0D),
        ),
    ),
    (
        "[]\\;',./",
        "{}|:\"<>?",
        (
            (0xDB, 0x1A), (0xDD, 0x1B), (0xDC, 0x2B), (0xBA, 0x27),
            (0xDE, 0x28), (0xBC, 0x33), (0xBE, 0x34), (0xBF, 0x35),
        ),
    ),
    (" ", " ", ((0x20, 0x39),)),
)

#: 字母行的扫描码起点：a~z 按 QWERTY 三行排列
_LETTER_ROWS = (("qwertyuiop", 0x10), ("asdfghjkl", 0x1E), ("zxcvbnm", 0x2C))

#: 可用的特殊键名 -> (虚拟键码, 扫描码, 是否扩展键)
_NAMED_KEYS = {
    "ENTER": (0x0D, 0x1C, False),
    "TAB": (0x09, 0x0F, False),
    "ESC": (0x1B, 0x01, False),
    "SPACE": (0x20, 0x39, False),
    "BACKSPACE": (0x08, 0x0E, False),
    "INSERT": (0x2D, 0x52, True),
    "DELETE": (0x2E, 0x53, True),
    "HOME": (0x24, 0x47, True),
    "END": (0x23, 0x4F, True),
    "PGUP": (0x21, 0x49, True),
    "PGDN": (0x22, 0x51, True),
    "UP": (0x26, 0x48, True),
    "DOWN": (0x28, 0x50, True),
    "LEFT": (0x25, 0x4B, True),
    "RIGHT": (0x27, 0x4D, True),
}
for _index, _scan in enumerate(
    (0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x57, 0x58),
    start=1,
):
    _NAMED_KEYS[f"F{_index}"] = (0x70 + _index - 1, _scan, False)

#: 供界面提示 / 报错信息使用的键名清单（按字母序，便于查找）
NAMED_KEYS = tuple(sorted(_NAMED_KEYS))

#: 控制字符 -> 特殊键名（``VkKeyScan`` 类接口无法处理换行 / 制表符，需先行转换）
_CONTROL_CHARS = {
    "\n": "ENTER",
    "\r": "ENTER",
    "\t": "TAB",
    "\x1b": "ESC",
    "\b": "BACKSPACE",
    "\x7f": "DELETE",
}


def _char_key_table() -> dict:
    """构建「单个字符 -> (虚拟键码, 扫描码, 是否需要 Shift)」的完整表。"""
    table = {}
    for unshifted, shifted, keys in _SYMBOL_ROWS:
        for index, (vk, scan) in enumerate(keys):
            table[unshifted[index]] = (vk, scan, False)
            table[shifted[index]] = (vk, scan, True)
    for row, first_scan in _LETTER_ROWS:
        for offset, char in enumerate(row):
            table[char] = (ord(char.upper()), first_scan + offset, False)
            table[char.upper()] = (ord(char.upper()), first_scan + offset, True)
    return table


#: 可输入的字符表（ASCII 可见字符 + 空格）
_CHAR_KEYS = _char_key_table()


# ===========================================================================
# 二、数据结构
# ===========================================================================
class KeyAction(NamedTuple):
    """一次「按键」：实际下发的是扫描码，``vk`` 仅用于阅读与排查。"""

    label: str      # 展示用名称（字符本身，或 {ENTER} 这类键名）
    vk: int         # 虚拟键码（仅作记录，注入时以扫描码为准）
    scan: int       # 扫描码
    extended: bool  # 是否扩展键（方向键、Delete 等）
    shift: bool     # 是否需要同时按住 Shift
    ctrl: bool      # 是否需要同时按住 Ctrl


class Plan(NamedTuple):
    """一次模拟的执行计划（由 :func:`build_plan` 计算得出）。"""

    keys: tuple     # 按键序列（``KeyAction`` 元组，循环使用）
    total: int      # 总按键次数
    rate: float     # 速率（次 / 秒）
    interval: float # 相邻两次按键的间隔（秒）
    duration: float # 持续时间（秒）


# ===========================================================================
# 三、文本解析与参数校验
# ===========================================================================
def _char_action(char: str, position: int) -> KeyAction:
    """把单个字符转换为按键动作；不支持的字符抛中文 ``ValueError``。"""
    named = _CONTROL_CHARS.get(char)
    if named is not None:
        return _named_action(named)

    spec = _CHAR_KEYS.get(char)
    if spec is None:
        raise ValueError(
            f"第 {position} 个字符「{char}」无法模拟输入，"
            "目前支持 ASCII 可见字符、空格、换行与 {ENTER} 这类特殊键名。"
        )

    vk, scan, shift = spec
    return KeyAction(label=char, vk=vk, scan=scan, extended=False, shift=shift, ctrl=False)


def _named_action(name: str) -> KeyAction:
    """把 ``{ENTER}`` 这样的键名转换为按键动作。"""
    vk, scan, extended = _NAMED_KEYS[name]
    return KeyAction(
        label="{" + name + "}",
        vk=vk,
        scan=scan,
        extended=extended,
        shift=False,
        ctrl=False,
    )


def build_keys(text) -> tuple:
    """把待输入的文本解析为按键序列。

    支持的写法:

    - 任意 ASCII 可见字符（字母区分大小写，大写自动附带 Shift）；
    - 空格、``\\n`` / ``\\t``（分别等价于 {ENTER} / {TAB}）；
    - 特殊键名 ``{ENTER}`` / ``{TAB}`` / ``{ESC}`` / ``{BACKSPACE}`` /
      ``{DELETE}`` / ``{INSERT}`` / ``{HOME}`` / ``{END}`` / ``{PGUP}`` /
      ``{PGDN}`` / ``{UP}`` / ``{DOWN}`` / ``{LEFT}`` / ``{RIGHT}`` /
      ``{F1}`` ~ ``{F12}``（键名不区分大小写）；
    - 想输入字面量花括号时写成 ``{{`` 与 ``}}``。

    异常:
        ValueError: 文本为空、含不支持的字符、``{`` 未闭合或键名不存在。
    """
    if not isinstance(text, str):
        raise ValueError(f"仅支持字符串输入，当前类型为 {type(text).__name__}。")
    if not text:
        raise ValueError("模拟按键内容为空，请先填写要模拟的按键。")

    actions = []
    index = 0
    length = len(text)
    while index < length:
        char = text[index]

        # 花括号：{{ 与 }} 表示字面量，{NAME} 表示特殊键名
        if char == "{" and text[index + 1: index + 2] == "{":
            actions.append(_char_action("{", index + 1))
            index += 2
            continue
        if char == "}" and text[index + 1: index + 2] == "}":
            actions.append(_char_action("}", index + 1))
            index += 2
            continue
        if char == "{":
            end = text.find("}", index + 1)
            if end == -1:
                raise ValueError(
                    f"第 {index + 1} 个字符「{{」缺少配对的「}}」，"
                    "若要输入花括号本身请写成 {{ 或 }}。"
                )
            name = text[index + 1: end].strip().upper()
            if name not in _NAMED_KEYS:
                raise ValueError(
                    f"「{{{name}}}」不是可用的特殊键名，"
                    f"可用键名：{'、'.join(NAMED_KEYS)}。"
                )
            actions.append(_named_action(name))
            index = end + 1
            continue

        actions.append(_char_action(char, index + 1))
        index += 1

    return tuple(actions)


def _to_float(value, field: str) -> float:
    """把界面 / 命令行传入的值转成浮点数，失败时抛中文 ``ValueError``。"""
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"{field}必须是数字。")
    if not math.isfinite(number):
        raise ValueError(f"{field}不是有效的数字。")
    return number


def parse_rate(value) -> float:
    """校验输入速率（次 / 秒），返回浮点值。"""
    rate = _to_float(value, "输入速率")
    if rate <= 0:
        raise ValueError("输入速率必须大于 0（次/秒）。")
    if rate > MAX_RATE:
        raise ValueError(f"输入速率过大（上限 {MAX_RATE:g} 次/秒）。")
    return rate


def parse_duration(value) -> float:
    """校验持续时间（秒），返回浮点值。"""
    duration = _to_float(value, "持续时间")
    if duration <= 0:
        raise ValueError("持续时间必须大于 0 秒。")
    if duration > MAX_DURATION:
        raise ValueError(f"持续时间过长（上限 {MAX_DURATION:g} 秒）。")
    return duration


def build_plan(text, rate, duration) -> Plan:
    """解析内容与参数，得到本次模拟的执行计划。

    总按键次数 = 速率 × 持续时间（四舍五入，至少 1 次）；内容会在时间到之前
    循环重复输入。
    """
    keys = build_keys(text)
    rate = parse_rate(rate)
    duration = parse_duration(duration)

    total = max(1, int(round(rate * duration)))
    return Plan(
        keys=keys,
        total=total,
        rate=rate,
        interval=1.0 / rate,
        duration=duration,
    )


def describe_keys(keys) -> str:
    """把按键序列还原成便于阅读的一行文本（用于预览）。"""
    return "".join(action.label for action in keys)


# ===========================================================================
# 四、Win32 物理按键注入
# ===========================================================================
_KEYEVENTF_EXTENDEDKEY = 0x0001
_KEYEVENTF_KEYUP = 0x0002
_KEYEVENTF_SCANCODE = 0x0008
_INPUT_KEYBOARD = 1

_user32 = None

if _IS_WINDOWS:
    from ctypes import wintypes

    #: ULONG_PTR 随指针宽度取 64 / 32 位，保证 INPUT 结构体尺寸与系统一致
    _ULONG_PTR = (
        ctypes.c_ulonglong if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_ulong
    )

    class _KEYBDINPUT(ctypes.Structure):
        _fields_ = (
            ("wVk", wintypes.WORD),
            ("wScan", wintypes.WORD),
            ("dwFlags", wintypes.DWORD),
            ("time", wintypes.DWORD),
            ("dwExtraInfo", _ULONG_PTR),
        )

    class _MOUSEINPUT(ctypes.Structure):
        _fields_ = (
            ("dx", wintypes.LONG),
            ("dy", wintypes.LONG),
            ("mouseData", wintypes.DWORD),
            ("dwFlags", wintypes.DWORD),
            ("time", wintypes.DWORD),
            ("dwExtraInfo", _ULONG_PTR),
        )

    class _HARDWAREINPUT(ctypes.Structure):
        _fields_ = (
            ("uMsg", wintypes.DWORD),
            ("wParamL", wintypes.WORD),
            ("wParamH", wintypes.WORD),
        )

    class _INPUTUNION(ctypes.Union):
        _fields_ = (
            ("ki", _KEYBDINPUT),
            ("mi", _MOUSEINPUT),
            ("hi", _HARDWAREINPUT),
        )

    class _INPUT(ctypes.Structure):
        _anonymous_ = ("u",)
        _fields_ = (("type", wintypes.DWORD), ("u", _INPUTUNION))


def _require_windows() -> None:
    """真实按键注入仅 Windows 可用；其它平台给出中文提示。"""
    if not _IS_WINDOWS:
        raise OSError(
            "当前平台不支持真实按键注入（仅 Windows 提供 SendInput 接口），"
            "可先用 dry_run=True 预览将要输入的按键。"
        )
    global _user32
    if _user32 is None:
        _user32 = ctypes.windll.user32


def _send_events(events) -> None:
    """把一串 ``(扫描码, 是否扩展键, 是否抬起)`` 一次性下发给系统。"""
    _require_windows()

    inputs = (_INPUT * len(events))()
    for index, (scan, extended, key_up) in enumerate(events):
        flags = _KEYEVENTF_SCANCODE
        if extended:
            flags |= _KEYEVENTF_EXTENDEDKEY
        if key_up:
            flags |= _KEYEVENTF_KEYUP

        item = inputs[index]
        item.type = _INPUT_KEYBOARD
        item.ki.wVk = 0          # 关键：不使用虚拟键码
        item.ki.wScan = scan     # 关键：改用物理扫描码
        item.ki.dwFlags = flags
        item.ki.time = 0
        item.ki.dwExtraInfo = 0

    sent = _user32.SendInput(len(events), inputs, ctypes.sizeof(_INPUT))
    if sent != len(events):
        raise OSError(
            f"按键注入被系统拦截（SendInput 返回 {sent}/{len(events)}），"
            "目标窗口可能以管理员权限运行，请以同等权限启动本程序后重试。"
        )


def _action_events(action: KeyAction) -> list:
    """把一次按键展开为扫描码事件序列（修饰键按下 -> 主键 -> 修饰键抬起）。"""
    events = []
    if action.ctrl:
        events.append((_SCAN_CTRL, False, False))
    if action.shift:
        events.append((_SCAN_SHIFT, False, False))
    events.append((action.scan, action.extended, False))
    events.append((action.scan, action.extended, True))
    if action.shift:
        events.append((_SCAN_SHIFT, False, True))
    if action.ctrl:
        events.append((_SCAN_CTRL, False, True))
    return events


def press_key(action: KeyAction, dry_run: bool = False) -> None:
    """按下并释放一次按键（``dry_run=True`` 时只走流程、不产生任何按键）。"""
    if dry_run:
        return
    _send_events(_action_events(action))


# ===========================================================================
# 五、前台窗口进程检测（反作弊保护名单）
# ===========================================================================
#: 默认的受反作弊保护进程名单（.env 的 KEY_SIM_PROTECTED_PROCESSES 可扩充）
DEFAULT_PROTECTED_PROCESSES = (
    "YuanShen.exe",               # 原神（国服）
    "GenshinImpact.exe",          # 原神（国际服）
    "StarRail.exe",               # 崩坏：星穹铁道
    "ZenlessZoneZero.exe",        # 绝区零
    "BH3.exe",                    # 崩坏3
    "Client-Win64-Shipping.exe",  # 鸣潮等 UE 引擎游戏客户端
)

#: 名单分隔符：中英文逗号 / 分号 / 竖线 / 空白（.env 里一行写完或换行写均可）
_PROCESS_SEPARATOR_RE = re.compile(r"[,，;；|\s]+")

#: OpenProcess 的最小查询权限（足以读取进程映像名）
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

_kernel32 = None


def _process_key(name) -> str:
    """把进程名归一化为比较键：取路径末段、去引号空白、去 .exe、转小写。"""
    text = str(name or "").strip().strip('"').replace("\\", "/")
    text = text.rsplit("/", 1)[-1].strip()
    if text.lower().endswith(".exe"):
        text = text[:-4]
    return text.strip().lower()


def parse_protected_processes(value=None) -> tuple:
    """解析受反作弊保护的进程名单；空值时退回内置默认名单。

    参数:
        value: 名单文本（逗号 / 分号 / 换行分隔）或任意进程名序列
    返回:
        原始书写形式的进程名元组（去空、去重、保持顺序）
    """
    if value is None:
        items = []
    elif isinstance(value, str):
        items = _PROCESS_SEPARATOR_RE.split(value)
    else:
        items = [str(item) for item in value]

    names = []
    seen = set()
    for item in items:
        name = str(item or "").strip().strip('"')
        key = _process_key(name)
        if not key or key in seen:
            continue
        seen.add(key)
        names.append(name)
    return tuple(names) if names else DEFAULT_PROTECTED_PROCESSES


def _init_win32_api() -> None:
    """载入并声明检测所需的 Win32 接口签名（HWND / HANDLE 按指针宽度处理）。"""
    global _kernel32
    _require_windows()
    if _kernel32 is not None:
        return

    _kernel32 = ctypes.windll.kernel32
    _user32.GetForegroundWindow.restype = wintypes.HWND
    _user32.GetWindowThreadProcessId.argtypes = (
        wintypes.HWND,
        ctypes.POINTER(wintypes.DWORD),
    )
    _user32.GetWindowThreadProcessId.restype = wintypes.DWORD
    _kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    _kernel32.OpenProcess.restype = wintypes.HANDLE
    _kernel32.QueryFullProcessImageNameW.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    )
    _kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    _kernel32.CloseHandle.restype = wintypes.BOOL


def foreground_process_name() -> str | None:
    """返回当前前台窗口所属进程的可执行文件名（如 ``"YuanShen.exe"``）。

    非 Windows 平台抛中文 ``OSError``；拿不到窗口 / 进程或权限不足（例如前台
    是更高权限的进程）时返回 ``None``。
    """
    if not _IS_WINDOWS:
        raise OSError("当前平台无法获取前台窗口进程名（仅 Windows 提供相关接口）。")

    _init_win32_api()

    hwnd = _user32.GetForegroundWindow()
    if not hwnd:
        return None

    pid = wintypes.DWORD(0)
    _user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    if not pid.value:
        return None

    handle = _kernel32.OpenProcess(
        _PROCESS_QUERY_LIMITED_INFORMATION, False, pid.value
    )
    if not handle:
        return None
    try:
        size = wintypes.DWORD(260)
        buffer = ctypes.create_unicode_buffer(size.value)
        query = _kernel32.QueryFullProcessImageNameW
        if not query(handle, 0, buffer, ctypes.byref(size)):
            return None
        path = buffer.value
    finally:
        _kernel32.CloseHandle(handle)

    return path.replace("\\", "/").rsplit("/", 1)[-1] or None


def find_protected_process(protected, process_name=None) -> str | None:
    """前台进程命中受保护名单时返回其进程名，未命中返回 ``None``。

    参数:
        protected:    受保护进程名单（见 :func:`parse_protected_processes`）
        process_name: 待检测的进程名；默认取当前前台窗口进程
    """
    if process_name is None:
        process_name = foreground_process_name()
    key = _process_key(process_name)
    if not key:
        return None
    for name in parse_protected_processes(protected):
        if _process_key(name) == key:
            return str(process_name).replace("\\", "/").rsplit("/", 1)[-1]
    return None


# ===========================================================================
# 六、执行器
# ===========================================================================
class KeySimulator:
    """按计划在后台线程持续注入按键，支持随时停止。

    界面层只需 ``start`` -> 轮询 :meth:`progress` -> ``stop``：

        simulator = KeySimulator()
        simulator.start("abc", rate=20, duration=5)
        ...
        simulator.stop()

    实例同时充当状态容器，所有字段在注入线程内更新、在界面线程内读取，
    都是简单的整数 / 布尔值，无需额外加锁。
    """

    def __init__(self, dry_run: bool = False) -> None:
        self.dry_run = dry_run
        self.plan: Plan | None = None
        self.pressed = 0        # 已注入的按键次数
        self.total = 0          # 计划总次数
        self.stopped = False    # 是否被调用方主动停止
        self.error: str | None = None  # 运行期间的失败原因（中文）
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    # -- 状态 --------------------------------------------------------------
    @property
    def running(self) -> bool:
        """注入线程是否仍在工作。"""
        return self._thread is not None and self._thread.is_alive()

    def progress(self) -> tuple:
        """返回当前 ``(已注入次数, 计划总次数)``。"""
        return self.pressed, self.total

    # -- 控制 --------------------------------------------------------------
    def start(self, text, rate, duration) -> Plan:
        """校验内容与参数并立即在后台线程开始注入，返回执行计划。

        异常:
            ValueError: 内容 / 参数非法（由 :func:`build_plan` 抛出）
            OSError:    非 Windows 平台且未开启 ``dry_run``
        """
        if self.running:
            raise ValueError("上一次模拟尚未结束，请先停止再开始。")
        if not self.dry_run:
            # 提前校验平台，避免把错误留到线程里才发现
            _require_windows()

        plan = build_plan(text, rate, duration)
        self.plan = plan
        self.total = plan.total
        self.pressed = 0
        self.stopped = False
        self.error = None
        self._stop_event.clear()

        self._thread = threading.Thread(
            target=self._run, name="key-simulator", daemon=True
        )
        self._thread.start()
        return plan

    def stop(self, wait: bool = False, timeout: float = 2.0) -> None:
        """请求停止注入；``wait=True`` 时等待线程退出（最多 ``timeout`` 秒）。"""
        self._stop_event.set()
        if wait and self._thread is not None:
            self._thread.join(timeout)

    def wait(self, timeout: float | None = None) -> int:
        """等待注入结束，返回已注入的按键次数。"""
        if self._thread is not None:
            self._thread.join(timeout)
        return self.pressed

    # -- 线程体 ------------------------------------------------------------
    def _run(self) -> None:
        try:
            self._loop()
        except Exception as exc:  # noqa: BLE001  (线程内异常需落到 error 字段，不能外抛)
            self.error = str(exc) or exc.__class__.__name__

    def _loop(self) -> None:
        """按键主循环：按 ``interval`` 均匀下发，边下发边响应停止请求。"""
        keys = self.plan.keys
        count = len(keys)
        interval = self.plan.interval
        started = time.perf_counter()

        for index in range(self.plan.total):
            if self._stop_event.is_set():
                self.stopped = True
                return

            press_key(keys[index % count], dry_run=self.dry_run)
            self.pressed = index + 1

            # 以「本轮应结束的时刻」为准等待，避免累计漂移；分段等待以便及时停止
            deadline = started + (index + 1) * interval
            while True:
                remain = deadline - time.perf_counter()
                if remain <= 0:
                    break
                if self._stop_event.wait(min(remain, 0.05)):
                    self.stopped = True
                    return


# ===========================================================================
# 七、命令行入口
# ===========================================================================
def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m lib.key_simulator",
        description="按设定速率与持续时间，模拟物理键盘的连续按键输入。",
    )
    parser.add_argument(
        "--text", "-t",
        default=LETTERS,
        help="要模拟输入的按键内容，默认完整的 26 个小写字母；"
             f"特殊键写 {{{{ENTER}}}} 这种形式。",
    )
    parser.add_argument(
        "--rate", "-r",
        type=float,
        default=DEFAULT_RATE,
        help=f"输入速率（次/秒），默认 {DEFAULT_RATE:g}，上限 {MAX_RATE:g}。",
    )
    parser.add_argument(
        "--duration", "-d",
        type=float,
        default=DEFAULT_DURATION,
        help=f"持续时间（秒），默认 {DEFAULT_DURATION:g}，上限 {MAX_DURATION:g}。",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="开始注入前的等待秒数，便于切换到目标窗口，默认 0。",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="只校验内容与参数并打印执行计划，不真正注入按键。",
    )
    return parser


def main(argv=None) -> int:
    args = _build_parser().parse_args(argv)

    try:
        plan = build_plan(args.text, args.rate, args.duration)
        delay = float(args.delay)
        if delay < 0:
            raise ValueError("开始前的等待时间不能为负数。")
    except (TypeError, ValueError) as exc:
        print(f"按键模拟失败：{exc}", file=sys.stderr)
        return 1

    preview = describe_keys(plan.keys)
    print(
        f"按键内容：{preview}（{len(plan.keys)} 个按键）\n"
        f"执行计划：{plan.rate:g} 次/秒 × {plan.duration:g} 秒 = 共 {plan.total} 次按键"
    )

    if args.dry_run:
        print("[dry-run] 仅预览，未注入任何按键。")
        return 0

    simulator = KeySimulator()
    try:
        if delay > 0:
            print(f"将在 {delay:g} 秒后开始，请切换到目标窗口…")
            time.sleep(delay)
        simulator.start(args.text, plan.rate, plan.duration)
        while simulator.running:
            time.sleep(0.2)
    except KeyboardInterrupt:
        simulator.stop(wait=True)
        print(f"\n已中断：共注入 {simulator.pressed} 次按键。")
        return 1
    except (ValueError, OSError) as exc:
        print(f"按键模拟失败：{exc}", file=sys.stderr)
        return 1

    if simulator.error:
        print(f"按键模拟失败：{simulator.error}", file=sys.stderr)
        return 1
    if simulator.stopped:
        print(f"已停止：共注入 {simulator.pressed} 次按键。")
        return 0

    print(f"模拟完成：共注入 {simulator.pressed} 次按键。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
