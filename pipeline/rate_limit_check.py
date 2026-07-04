import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable

from .message import Message

# Technical Reference §2/§8.3: N messages per 10 s sliding window per ephemeral
# ID; ban the ephem_id for 60 s after 3 violations in a row. N = 10 was chosen
# during Phase 4 — see DECISIONS.md.
WINDOW_SECONDS = 10
MAX_MESSAGES_PER_WINDOW = 10
BAN_SECONDS = 60
BAN_VIOLATION_THRESHOLD = 3
# Housekeeping so per-sender state doesn't grow unbounded (see DECISIONS.md).
_IDLE_EXPIRY_SECONDS = 600
_PRUNE_INTERVAL_CHECKS = 1_000


@dataclass
class _SenderState:
    window: "deque[float]" = field(default_factory=deque)  # accepted-message times
    consecutive_violations: int = 0
    banned_until: float = 0.0
    last_seen: float = 0.0


class RateLimiter:
    """Step 5: sliding-window rate limit per sender.

    Keyed on ephem_id, not the long-term key, per the security model (§7.4):
    the ephemeral ID is what rotates on-air, so throttling it cannot be used
    to track a person across the event. Runs before signature verification so
    a flood attacker cannot force Ed25519 work before being throttled.
    """

    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._senders: dict[bytes, _SenderState] = {}
        self._checks = 0

    def check(self, msg: Message) -> str | None:
        now = self._clock()
        self._checks += 1
        if self._checks % _PRUNE_INTERVAL_CHECKS == 0:
            self._prune(now)

        state = self._senders.setdefault(msg.ephem_id, _SenderState())
        state.last_seen = now

        if now < state.banned_until:
            return "rate limit: sender is banned"

        while state.window and now - state.window[0] > WINDOW_SECONDS:
            state.window.popleft()

        if len(state.window) >= MAX_MESSAGES_PER_WINDOW:
            state.consecutive_violations += 1
            if state.consecutive_violations >= BAN_VIOLATION_THRESHOLD:
                state.banned_until = now + BAN_SECONDS
                state.consecutive_violations = 0
                return (
                    f"rate limit: {BAN_VIOLATION_THRESHOLD} violations in a row, "
                    f"sender banned for {BAN_SECONDS}s"
                )
            return (
                f"rate limit exceeded: > {MAX_MESSAGES_PER_WINDOW} messages "
                f"per {WINDOW_SECONDS}s window"
            )

        state.consecutive_violations = 0
        state.window.append(now)
        return None

    def _prune(self, now: float) -> None:
        stale = [
            ephem_id
            for ephem_id, state in self._senders.items()
            if now - state.last_seen > _IDLE_EXPIRY_SECONDS and now >= state.banned_until
        ]
        for ephem_id in stale:
            del self._senders[ephem_id]
