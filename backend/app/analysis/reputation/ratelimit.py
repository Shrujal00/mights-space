"""Sliding-window rate limiting.

VirusTotal's public tier allows four requests a minute and five hundred a day,
which is the binding constraint on how fast a sample can be enriched. Waiting
for the window is preferable to collecting 429s.

The clock and sleep function are injectable so tests never really sleep.
"""

from collections import deque
from typing import Callable
import time


class RateLimiter:
    def __init__(
        self,
        max_calls: int,
        per_seconds: float,
        now: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.max_calls = max_calls
        self.per_seconds = per_seconds
        self._now = now
        self._sleep = sleep
        self._calls: deque[float] = deque()

    def acquire(self) -> None:
        """Block until another call is allowed, then record it."""
        self._drop_expired()
        if len(self._calls) >= self.max_calls:
            wait = self.per_seconds - (self._now() - self._calls[0])
            if wait > 0:
                self._sleep(wait)
            self._drop_expired()
        self._calls.append(self._now())

    def _drop_expired(self) -> None:
        cutoff = self._now() - self.per_seconds
        while self._calls and self._calls[0] <= cutoff:
            self._calls.popleft()
