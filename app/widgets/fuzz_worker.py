# -*- coding: utf-8 -*-
"""Fuzz 通用后台线程：密码 Fuzz / Web Fuzz / 参数爆破三个页面复用。

三个 Fuzz 页的 worker 结构完全一致：都是 ``QThread`` + ``log`` / ``done_ok`` /
``done_err`` 三个信号 + ``threading.Event`` 停止开关 + ``stop()`` 方法，run() 里
try/except 调用各自的 lib 层 ``run`` 函数，异常统一转 ``done_err``。本模块把这套
样板收敛成一个基类 :class:`FuzzWorker`，子类只需：

- 在 ``__init__`` 里保存参数（调用 ``super().__init__(parent)``）；
- 实现 :meth:`FuzzWorker.task`（返回结果，异常直接抛出即可）；
- 可选覆盖 :attr:`FuzzWorker.error_prefix`（其它异常的前缀文案，如「尝试失败」）。

这样三个页面不再各自复制 ``log`` / ``done_ok`` / ``done_err`` / ``stop`` /
``_event`` / ``run`` 的 try-except 样板，保持「轻量统一」—— 不强行统一输入模型
（密码 Fuzz 的输入是密文，Web Fuzz 的输入是 URL，语义不同，仍由各自子类持有）。
"""

from __future__ import annotations

import threading

from PySide6.QtCore import QThread, Signal


class FuzzWorker(QThread):
    """Fuzz 通用后台线程基类。

    信号
    ----
    log       逐行日志（str）
    done_ok   成功结果（任意对象，由页面按需解析）
    done_err  失败文案（str）

    子类约定
    --------
    - ``__init__`` 里 ``super().__init__(parent)`` 并保存参数；
    - 实现 :meth:`task`：执行 lib 层 run，返回结果，异常直接抛出；
    - 可选覆盖 :attr:`error_prefix`：非业务异常时的前缀（业务异常通常已是人话）。
    """

    log = Signal(str)
    done_ok = Signal(object)
    done_err = Signal(str)

    #: 其它异常（非 lib 层业务异常）时的前缀文案，子类覆盖。空串则不额外前缀。
    error_prefix: str = ""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._event = threading.Event()

    def stop(self) -> None:
        """请求中止：置位停止开关，在途步骤尽快收尾。"""
        self._event.set()

    def task(self):
        """执行具体 Fuzz 任务，返回结果；异常直接抛出（基类会转成 ``done_err``）。

        子类必须实现。返回 ``self._event`` 传给 lib 层 ``run`` 的 ``stop`` 参数。
        """
        raise NotImplementedError

    def run(self) -> None:  # noqa: D102  线程入口
        # 运行日志中枢记录任务启停（跨线程 emit 自动排队到主线程）。
        # 类名去下划线前缀 / Worker 后缀作为工具名，如 _WebFuzzWorker → WebFuzz
        from app import runtime_log
        name = self.__class__.__name__.lstrip("_").replace("Worker", "") or "Fuzz"
        runtime_log.info(f"「{name}」任务开始")
        try:
            result = self.task()
        except Exception as exc:  # noqa: BLE001  后台线程兜底：任何异常不崩线程
            prefix = f"{self.error_prefix}：" if self.error_prefix else ""
            runtime_log.error(f"「{name}」任务失败：{exc}")
            self.done_err.emit(f"{prefix}{exc}")
            return
        runtime_log.info(f"「{name}」任务完成")
        self.done_ok.emit(result)
