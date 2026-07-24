from dataclasses import dataclass
from enum import Enum
from typing import Optional

from routing.spray_and_wait import SprayBudgetTracker, split_copies

from .message import Message, parse_packet
from .size_check import check_size
from .ttl_check import check_ttl
from .timestamp_check import check_timestamp
from .dedup_check import DedupCache
from .rate_limit_check import RateLimiter
from .signature_check import check_signature
from .attestation_check import AttestationCache


class Outcome(Enum):
    DELIVER = "deliver"
    RELAY = "relay"
    DROP = "drop"


# ttl / spray_L byte offsets in the fixed header (docs/message-format.md §2).
# Both sit outside the signed region, so a relay may rewrite them.
_TTL_OFFSET = 68
_SPRAY_OFFSET = 69


@dataclass
class PipelineResult:
    outcome: Outcome
    drop_reason: Optional[str] = None
    message: Optional[Message] = None
    # The onward copy of an accepted packet: ttl decremented, spray_L
    # binary-split to the peer's share (Spray-and-Wait). None when the hop
    # budget or the copy budget is exhausted — deliver locally, spray no
    # further. A broadcast packet is both delivered AND forwarded, which the
    # single-valued outcome enum cannot express; hence a separate field.
    forward: Optional[bytes] = None


class RelayPipeline:
    """Ordered relay pipeline for MeshLink messages.

    Steps run cheapest-first: a flood attacker sending forged packets hits the
    rate-limit (step 5) before any Ed25519 work is done. Violating this order
    opens a CPU and battery exhaustion vector on mobile relays.

    Step 7 (attestation) enforces ticket-bound tokens when an
    AttestationCache is provided (Phase 5). Without one the step passes —
    the node runs open until an organiser key is provisioned.
    """

    def __init__(self, attestation: Optional[AttestationCache] = None) -> None:
        self._dedup = DedupCache()
        self._rate_limiter = RateLimiter()
        self._attestation = attestation
        self._spray_budget = SprayBudgetTracker()

    def process(self, raw: bytes) -> PipelineResult:
        # Step 1 — size (pre-parse, one comparison)
        if reason := check_size(raw):
            return PipelineResult(Outcome.DROP, reason)

        # Parse header; drop if structurally malformed (e.g. payload_len mismatch)
        try:
            msg = parse_packet(raw)
        except ValueError as exc:
            return PipelineResult(Outcome.DROP, f"malformed: {exc}")

        # Step 2 — TTL
        if reason := check_ttl(msg):
            return PipelineResult(Outcome.DROP, reason)

        # Step 3 — timestamp (replay prevention, before dedup state is written)
        if reason := check_timestamp(msg):
            return PipelineResult(Outcome.DROP, reason)

        # Step 4 — dedup (Bloom filter + LRU)
        if reason := self._dedup.check(msg):
            return PipelineResult(Outcome.DROP, reason)

        # Step 5 — rate limit (sliding window per ephem_id)
        if reason := self._rate_limiter.check(msg):
            return PipelineResult(Outcome.DROP, reason)

        # Step 6 — Ed25519 signature verification
        if reason := check_signature(msg):
            return PipelineResult(Outcome.DROP, reason)

        # Step 7 — attestation token (skipped when no organiser key configured)
        if self._attestation is not None:
            if reason := self._attestation.check(msg.sender_key):
                return PipelineResult(Outcome.DROP, reason)

        # Step 8 — deliver, and compute the onward Spray-and-Wait copy.
        # Budget contract first: a relay must never present a spray_L higher
        # than this device first observed for the msg_id (backstops dedup
        # eviction against budget inflation).
        if reason := self._spray_budget.check(msg.msg_id, msg.spray_l):
            return PipelineResult(Outcome.DROP, reason)
        return PipelineResult(
            Outcome.DELIVER, message=msg, forward=_onward_copy(raw, msg)
        )


def _onward_copy(raw: bytes, msg: Message) -> Optional[bytes]:
    """The packet to hand peers: ttl-1, spray_L = the peer's binary-split
    share. None once either budget is spent — the message enters the Wait
    phase (deliver only, no further spraying). Rewriting these two bytes is
    signature-safe: both sit outside signed_region."""
    next_ttl = msg.ttl - 1
    forward_l = split_copies(msg.spray_l).forward
    if next_ttl <= 0 or forward_l == 0:
        return None
    return (
        raw[:_TTL_OFFSET]
        + bytes([next_ttl, forward_l])
        + raw[_SPRAY_OFFSET + 1:]
    )
