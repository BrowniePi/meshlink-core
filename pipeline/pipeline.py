from dataclasses import dataclass
from enum import Enum
from typing import Optional

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


@dataclass
class PipelineResult:
    outcome: Outcome
    drop_reason: Optional[str] = None
    message: Optional[Message] = None


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

        # Step 8 — deliver or relay (stub: always deliver at Phase 0)
        return PipelineResult(Outcome.DELIVER, message=msg)
