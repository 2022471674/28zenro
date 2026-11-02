# -*- coding: utf-8 -*-
"""番茄工作法（Pomodoro）纯逻辑模块。

只做「配置进、状态出」的计时状态机，不导入任何 UI 模块，也不自己起线程：
外部（界面层的 QTimer）每帧调用 :meth:`Pomodoro.tick` 驱动，本模块据此
判断阶段是否结束并自动切换到下一阶段。

阶段流转（``long_every`` 默认 4）::

    专注 -> 短休息 -> 专注 -> 短休息 -> 专注 -> 短休息 -> 专注 -> 长休息 -> …

计时基准用单调时钟 ``time.monotonic``，不受系统时间调整影响；时钟可通过
构造参数注入，便于测试（无需真的等待）。
"""

from __future__ import annotations

import time
from dataclasses import dataclass

# 阶段标识
PHASE_WORK = "work"            # 专注
PHASE_SHORT_REST = "short_rest"  # 短休息
PHASE_LONG_REST = "long_rest"    # 长休息

#: 阶段显示名（界面层可直接用，也可自行覆盖）
PHASE_NAMES = {
    PHASE_WORK: "专注",
    PHASE_SHORT_REST: "短休息",
    PHASE_LONG_REST: "长休息",
}


class PomodoroError(ValueError):
    """配置非法时抛出，由界面层统一捕获并展示。"""


@dataclass(frozen=True)
class PomodoroConfig:
    """番茄时钟参数。全部以分钟为单位，``long_every`` 为「几个番茄后长休息」。"""

    work_minutes: int = 25
    short_rest_minutes: int = 5
    long_rest_minutes: int = 15
    long_every: int = 4

    def validate(self) -> None:
        """校验参数范围；非法时抛 :class:`PomodoroError`。"""
        for name, value in (
            ("专注时长", self.work_minutes),
            ("短休息时长", self.short_rest_minutes),
            ("长休息时长", self.long_rest_minutes),
        ):
            if not isinstance(value, int) or not 1 <= value <= 180:
                raise PomodoroError(f"{name}须为 1~180 之间的整数分钟。")
        if not isinstance(self.long_every, int) or not 1 <= self.long_every <= 12:
            raise PomodoroError("长休息间隔须为 1~12 之间的整数。")

    def seconds_for(self, phase: str) -> float:
        """取某阶段的时长（秒）。"""
        if phase == PHASE_WORK:
            return self.work_minutes * 60.0
        if phase == PHASE_LONG_REST:
            return self.long_rest_minutes * 60.0
        if phase == PHASE_SHORT_REST:
            return self.short_rest_minutes * 60.0
        raise PomodoroError(f"未知阶段：{phase}")


class Pomodoro:
    """番茄时钟状态机。

    使用方式::

        p = Pomodoro(PomodoroConfig())
        p.start()                    # 开始第一个专注
        ...
        finished = p.tick()          # 每帧调用；阶段结束时返回阶段名并自动切换
        p.pause(); p.resume()        # 暂停 / 继续
        p.reset()                    # 清零回到第一个专注
    """

    def __init__(self, config: PomodoroConfig | None = None,
                 clock=None) -> None:
        self.config = config or PomodoroConfig()
        self.config.validate()
        #: 注入时钟，默认单调时钟；测试可传可控假时钟
        self._clock = clock or time.monotonic

        self._phase = PHASE_WORK
        self._running = False
        self._paused = False
        self._phase_end: float | None = None
        #: 暂停时锁存的剩余秒数
        self._paused_remaining = 0.0
        #: 累计完成的专注番茄数
        self.completed = 0
        #: 当前长休息周期内已完成的专注数（决定下一次是短休息还是长休息）
        self._round_done = 0

    # -------------------------------------------------------------- 状态
    @property
    def phase(self) -> str:
        """当前阶段标识。"""
        return self._phase

    @property
    def phase_name(self) -> str:
        """当前阶段中文名。"""
        return PHASE_NAMES.get(self._phase, self._phase)

    @property
    def running(self) -> bool:
        """是否处于计时中（含暂停）。"""
        return self._running

    @property
    def paused(self) -> bool:
        """是否处于暂停中。"""
        return self._running and self._paused

    @property
    def idle(self) -> bool:
        """是否处于未开始状态。"""
        return not self._running

    @property
    def round_done(self) -> int:
        """当前长休息周期内已完成的专注数。"""
        return self._round_done

    def remaining(self) -> float:
        """当前阶段剩余秒数（未开始返回 0）。"""
        if not self._running:
            return 0.0
        if self._paused:
            return max(0.0, self._paused_remaining)
        if self._phase_end is None:
            return 0.0
        return max(0.0, self._phase_end - self._clock())

    def total(self) -> float:
        """当前阶段总时长（秒）。"""
        return self.config.seconds_for(self._phase)

    def progress(self) -> float:
        """当前阶段已完成比例，取值 0~1。"""
        total = self.total()
        if total <= 0:
            return 0.0
        return min(1.0, max(0.0, (total - self.remaining()) / total))

    def next_phase(self) -> str:
        """预览下一个阶段（供界面提示「接下来：短休息 5 分钟」）。"""
        if self._phase != PHASE_WORK:
            return PHASE_WORK
        if self._round_done >= self.config.long_every:
            return PHASE_LONG_REST
        return PHASE_SHORT_REST

    # -------------------------------------------------------------- 控制
    def start(self) -> None:
        """开始计时：回到专注阶段并清零本轮计数（不清累计番茄数）。"""
        self._round_done = 0
        self._phase = PHASE_WORK
        self._running = True
        self._paused = False
        self._paused_remaining = 0.0
        self._phase_end = self._clock() + self.total()

    def pause(self) -> None:
        """暂停：锁存剩余秒数。未在计时或已暂停时调用无副作用。"""
        if not self._running or self._paused:
            return
        self._paused_remaining = self.remaining()
        self._paused = True
        self._phase_end = None

    def resume(self) -> None:
        """继续：从锁存的剩余秒数接着走。未暂停时调用无副作用。"""
        if not self._running or not self._paused:
            return
        self._paused = False
        self._phase_end = self._clock() + self._paused_remaining
        self._paused_remaining = 0.0

    def reset(self) -> None:
        """停止并清零：回到未开始状态，累计番茄数与本轮计数一并清零。"""
        self._phase = PHASE_WORK
        self._running = False
        self._paused = False
        self._phase_end = None
        self._paused_remaining = 0.0
        self.completed = 0
        self._round_done = 0

    def skip(self) -> str | None:
        """立即结束当前阶段并切到下一段（与阶段自然结束同效）。

        返回刚结束的阶段名；未在计时（含暂停）时返回 ``None`` 且无副作用。
        暂停中调用会先按「已到点」处理，切换后仍保持暂停，剩余时间置为
        新阶段满值，交由用户决定继续还是再跳。
        """
        if not self._running or self._paused:
            return None
        finished = self._phase
        if finished == PHASE_WORK:
            self.completed += 1
            self._round_done += 1
            upcoming = (PHASE_LONG_REST
                        if self._round_done >= self.config.long_every
                        else PHASE_SHORT_REST)
        else:
            upcoming = PHASE_WORK
            if finished == PHASE_LONG_REST:
                self._round_done = 0
        self._phase = upcoming
        self._phase_end = self._clock() + self.total()
        return finished

    def reconfigure(self, config: PomodoroConfig) -> None:
        """更换参数；计时中会用新时长重新起当前阶段。"""
        config.validate()
        self.config = config
        if self._running and not self._paused:
            self._phase_end = self._clock() + self.total()
        elif self._running and self._paused:
            self._paused_remaining = min(self._paused_remaining, self.total())

    # -------------------------------------------------------------- 驱动
    def tick(self) -> str | None:
        """推进一帧；若本帧内阶段结束则返回刚结束的阶段名并自动切换。

        暂停中或未开始时恒返回 ``None``。超时溢出的时间不带入下一阶段
        （下一阶段从当下重新起算），避免长时间挂机后一次性跳过多段。
        """
        if not self._running or self._paused or self._phase_end is None:
            return None
        now = self._clock()
        if now < self._phase_end:
            return None

        finished = self._phase
        if finished == PHASE_WORK:
            self.completed += 1
            self._round_done += 1
            upcoming = (PHASE_LONG_REST
                        if self._round_done >= self.config.long_every
                        else PHASE_SHORT_REST)
        else:
            upcoming = PHASE_WORK
            if finished == PHASE_LONG_REST:
                self._round_done = 0

        self._phase = upcoming
        self._phase_end = now + self.total()
        return finished
