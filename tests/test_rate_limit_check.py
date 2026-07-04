from pipeline.rate_limit_check import (
    BAN_SECONDS,
    BAN_VIOLATION_THRESHOLD,
    MAX_MESSAGES_PER_WINDOW,
    RateLimiter,
    WINDOW_SECONDS,
)
from pipeline.message import parse_packet
from tests.helpers import build_packet


class FakeClock:
    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now


def _msg(ephem_id: bytes = b"\x02" * 16):
    return parse_packet(build_packet(ephem_id=ephem_id))


def test_messages_under_limit_pass():
    limiter = RateLimiter(clock=FakeClock())
    for _ in range(MAX_MESSAGES_PER_WINDOW):
        assert limiter.check(_msg()) is None


def test_message_over_limit_drops():
    limiter = RateLimiter(clock=FakeClock())
    for _ in range(MAX_MESSAGES_PER_WINDOW):
        limiter.check(_msg())
    reason = limiter.check(_msg())
    assert reason is not None
    assert "rate limit" in reason.lower()


def test_window_boundary_exactly_at_edge_still_counts():
    # Messages exactly WINDOW_SECONDS old are still inside the window.
    clock = FakeClock()
    limiter = RateLimiter(clock=clock)
    for _ in range(MAX_MESSAGES_PER_WINDOW):
        limiter.check(_msg())
    clock.now += WINDOW_SECONDS
    assert limiter.check(_msg()) is not None


def test_window_slides_after_boundary():
    clock = FakeClock()
    limiter = RateLimiter(clock=clock)
    for _ in range(MAX_MESSAGES_PER_WINDOW):
        limiter.check(_msg())
    clock.now += WINDOW_SECONDS + 0.01
    assert limiter.check(_msg()) is None


def test_limits_are_per_sender_identity():
    limiter = RateLimiter(clock=FakeClock())
    for _ in range(MAX_MESSAGES_PER_WINDOW):
        limiter.check(_msg(ephem_id=b"\x0a" * 16))
    # A different ephem_id has its own budget.
    assert limiter.check(_msg(ephem_id=b"\x0b" * 16)) is None


def test_ban_after_consecutive_violations():
    clock = FakeClock()
    limiter = RateLimiter(clock=clock)
    for _ in range(MAX_MESSAGES_PER_WINDOW):
        limiter.check(_msg())
    for _ in range(BAN_VIOLATION_THRESHOLD):
        reason = limiter.check(_msg())
        assert reason is not None
    assert "banned" in reason.lower()
    # Even after the window slides, the sender stays banned.
    clock.now += WINDOW_SECONDS + 1
    assert "banned" in limiter.check(_msg()).lower()


def test_ban_expires_after_ban_seconds():
    clock = FakeClock()
    limiter = RateLimiter(clock=clock)
    for _ in range(MAX_MESSAGES_PER_WINDOW + BAN_VIOLATION_THRESHOLD):
        limiter.check(_msg())
    clock.now += BAN_SECONDS + 0.01
    assert limiter.check(_msg()) is None


def test_successful_message_resets_violation_streak():
    clock = FakeClock()
    limiter = RateLimiter(clock=clock)
    for _ in range(MAX_MESSAGES_PER_WINDOW):
        limiter.check(_msg())
    # Two violations, then the window slides and a message passes.
    limiter.check(_msg())
    limiter.check(_msg())
    clock.now += WINDOW_SECONDS + 0.01
    assert limiter.check(_msg()) is None
    # Streak was reset: filling the window again yields a violation, not a ban.
    for _ in range(MAX_MESSAGES_PER_WINDOW - 1):
        limiter.check(_msg())
    reason = limiter.check(_msg())
    assert reason is not None
    assert "banned" not in reason.lower()
