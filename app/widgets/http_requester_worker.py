# -*- coding: utf-8 -*-
"""HTTP 请求器后台线程。

请求器有两种运行方式：

- 单次发送：只跑一次 :func:`lib.http_requester.run`，结果一次回传；
- 循环模式：同样跑一次 ``run``，但把 ``on_result`` 接到信号上，**每完成一行
  就推一次**，界面表格边跑边填，不用等整批跑完。

两条路径共用 :class:`app.widgets.fuzz_worker.FuzzWorker` 的
``log`` / ``done_ok`` / ``done_err`` + ``stop()`` 样板，只多一个
``row_done`` 信号。
"""

from __future__ import annotations

from PySide6.QtCore import Signal

from app.widgets.fuzz_worker import FuzzWorker
from lib import http_requester


class HttpRequesterWorker(FuzzWorker):
    """在后台执行一次请求器任务。"""

    error_prefix = "请求失败"

    #: 每完成一行推一次（ResponseRecord 的 dict 形态）
    row_done = Signal(object)

    def __init__(self, spec: http_requester.RequestSpec, options: dict,
                 parent=None) -> None:
        super().__init__(parent)
        self._spec = spec
        self._options = dict(options)

    def task(self) -> dict:
        def _on_result(record) -> None:
            self.row_done.emit(record.to_dict())

        return http_requester.run(
            self._spec,
            log=self.log.emit,
            stop=self._event,
            on_result=_on_result,
            **self._options,
        )


__all__ = ["HttpRequesterWorker"]
