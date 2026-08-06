from app.analysis.reputation.ratelimit import RateLimiter


class FakeClock:
    """Injected so rate-limit tests never actually sleep."""

    def __init__(self):
        self.time = 0.0
        self.sleeps: list[float] = []

    def now(self) -> float:
        return self.time

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.time += seconds

    def advance(self, seconds: float) -> None:
        self.time += seconds


def make_limiter(clock, max_calls=4, per_seconds=60.0):
    return RateLimiter(
        max_calls=max_calls,
        per_seconds=per_seconds,
        now=clock.now,
        sleep=clock.sleep,
    )


def test_calls_within_the_limit_do_not_wait():
    clock = FakeClock()
    limiter = make_limiter(clock)

    for _ in range(4):
        limiter.acquire()

    assert clock.sleeps == []


def test_the_call_that_exceeds_the_limit_waits_for_the_window_to_clear():
    # VirusTotal's public tier allows 4 requests per minute; the fifth has to
    # wait rather than earn a 429.
    clock = FakeClock()
    limiter = make_limiter(clock)
    for _ in range(4):
        limiter.acquire()

    limiter.acquire()

    assert clock.sleeps == [60.0]


def test_no_wait_once_the_window_has_passed():
    clock = FakeClock()
    limiter = make_limiter(clock)
    for _ in range(4):
        limiter.acquire()

    clock.advance(61.0)
    limiter.acquire()

    assert clock.sleeps == []


def test_waits_only_the_remaining_time_in_the_window():
    clock = FakeClock()
    limiter = make_limiter(clock)
    for _ in range(4):
        limiter.acquire()
    clock.advance(45.0)

    limiter.acquire()

    assert clock.sleeps == [15.0]
