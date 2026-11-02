# -*- coding: utf-8 -*-
"""全局运行日志中枢：跨线程收集软件运行事件，供侧边栏「运行日志」页展示。

设计
----
- 任何线程（主线程 / QThread / 裸 threading 线程）都可以直接调
  :func:`log`；写入线程安全的环形缓冲（最多 :data:`CAPACITY` 条），
  并通过 Qt 信号 ``appended`` 广播 —— 信号从工作线程 emit 时 Qt 自动
  排队投递到主线程订阅者，因此页面刷新永远是主线程安全的。
- 「运行日志」页不必常开：首次打开时用 :meth:`RuntimeLog.lines` 回放
  历史缓冲，之后的增量经 ``appended`` 信号实时追加。
- 记录的是**软件级**运行事件（启动 / 主题切换 / 工具启停 / 后台任务
  结果），不复制各工具页面自己的逐行扫描日志 —— 那些仍显示在工具页内。

本模块只依赖 PySide6 的 QtCore（QObject/Signal），不依赖任何页面。
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque

from PySide6.QtCore import QObject, Signal

#: 环形缓冲容量（与运行日志页的 maximumBlockCount 对齐）
CAPACITY = 2000


class RuntimeLog(QObject):
    """运行日志中枢：线程安全写入 + Qt 信号广播 + 环形缓冲。"""

    #: 新增一条日志（完整格式化行，含时间戳 / 级别）
    appended = Signal(str)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._lines: deque[str] = deque(maxlen=CAPACITY)
        self._lock = threading.Lock()

    # ------------------------------------------------------------- 写入
    def log(self, message: str, level: str = "INFO") -> None:
        """写一条运行日志；``level`` 取 INFO / WARN / ERROR。线程安全。"""
        line = "{} [{:<4}] {}".format(time.strftime("%H:%M:%S"), level, message)
        with self._lock:
            self._lines.append(line)
        # 从工作线程 emit 时 Qt 自动走 QueuedConnection，订阅者只在主线程收
        self.appended.emit(line)

    # ------------------------------------------------------------- 读取
    def lines(self) -> list[str]:
        """返回当前缓冲快照（ oldest → newest ）。"""
        with self._lock:
            return list(self._lines)

    def clear(self) -> None:
        with self._lock:
            self._lines.clear()


# ---------------------------------------------------------------------------
# 进程级单例（懒创建，首次使用时生成；主线程先触发则归主线程所有）
# ---------------------------------------------------------------------------
_HUB: RuntimeLog | None = None
_HUB_LOCK = threading.Lock()


def hub() -> RuntimeLog:
    """取全局运行日志中枢单例。"""
    global _HUB
    if _HUB is None:
        with _HUB_LOCK:
            if _HUB is None:
                _HUB = RuntimeLog()
    return _HUB


def log(message: str, level: str = "INFO") -> None:
    """模块级快捷入口：任何线程可直接调用。"""
    hub().log(message, level)


def info(message: str) -> None:
    hub().log(message, "INFO")


def warn(message: str) -> None:
    hub().log(message, "WARN")


def error(message: str) -> None:
    hub().log(message, "ERROR")


# ---------------------------------------------------------------------------
# 标准库 logging 桥接（lib 层未来改用 logging 时自动进入运行日志页）
# ---------------------------------------------------------------------------
class _QtLogHandler(logging.Handler):
    """把标准库 logging 记录转发到运行日志中枢。"""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            level = ("ERROR" if record.levelno >= logging.ERROR
                     else "WARN" if record.levelno >= logging.WARNING
                     else "INFO")
            hub().log(record.getMessage(), level)
        except Exception:  # noqa: BLE001  日志桥接绝不能影响业务
            pass


def install_logging_bridge(level: int = logging.INFO) -> None:
    """给 root logger 挂一个转发 handler（幂等，重复调用不叠加）。"""
    root = logging.getLogger()
    if any(isinstance(h, _QtLogHandler) for h in root.handlers):
        return
    handler = _QtLogHandler()
    handler.setLevel(level)
    root.addHandler(handler)
