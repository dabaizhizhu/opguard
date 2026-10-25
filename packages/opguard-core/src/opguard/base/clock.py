"""Time source. Tests inject a manual clock; production uses the wall clock."""

from __future__ import annotations

import time
from typing import Protocol


class Clock(Protocol):
    def now(self) -> float:
        """Unix seconds."""


class SystemClock:
    def now(self) -> float:
        return time.time()


class ManualClock:
    def __init__(self, start: float = 1_700_000_000.0) -> None:
        self._now = start

    def now(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds
