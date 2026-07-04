"""Adversarial injection script: forged/replayed/stale/future/duplicate messages.

Constructs deliberately invalid messages and runs each against a relay node's
pipeline, confirming it is rejected at the correct, documented pipeline step
(identified by the drop reason), not just "rejected somewhere".

Expected rejection steps (Technical Reference §2/§8.3):
  forged signature   → step 6 (signature verify)
  replayed message   → step 4 (dedup — captured packet re-injected while fresh)
  stale timestamp    → step 3 (timestamp; also covers >5-min-old replays)
  future timestamp   → step 3 (timestamp)
  duplicate message  → step 4 (dedup)

Run standalone for demo/regression output:
    uv run python -m tests.adversarial.inject_attacks
Also collected by pytest (test_all_attacks_rejected).
"""
import sys
import time

from identity import build_signed_packet, generate_keypair
from pipeline.pipeline import Outcome, RelayPipeline

VICTIM = generate_keypair()  # honest sender whose traffic the attacker abuses
EPHEM_ID = b"\x0e" * 16


def _victim_packet(*, timestamp: int | None = None, payload: bytes = b"legit message") -> bytes:
    return build_signed_packet(
        VICTIM,
        ephem_id=EPHEM_ID,
        ttl=5,
        spray_l=8,
        zone_id=3,
        msg_type=1,
        payload=payload,
        timestamp=timestamp,
    )


def _expect_drop(node: RelayPipeline, raw: bytes, reason_substring: str, step: str) -> tuple[bool, str]:
    result = node.process(raw)
    if result.outcome != Outcome.DROP:
        return False, f"NOT dropped (outcome={result.outcome.value})"
    if reason_substring not in result.drop_reason.lower():
        return False, f"dropped at the wrong step: {result.drop_reason!r} (expected {step})"
    return True, f"rejected at {step}: {result.drop_reason!r}"


def attack_forged_signature(node: RelayPipeline) -> tuple[bool, str]:
    """Attacker tampers with a signed packet (equivalently: signs with a key
    that doesn't match the claimed sender_key)."""
    raw = bytearray(_victim_packet())
    raw[-64:] = b"\x99" * 64
    return _expect_drop(node, bytes(raw), "signature", "step 6 (signature verify)")


def attack_replayed_message(node: RelayPipeline) -> tuple[bool, str]:
    """Attacker captures a valid message the node already relayed and
    re-injects it within the freshness window."""
    raw = _victim_packet(payload=b"message to be replayed")
    first = node.process(raw)
    if first.outcome != Outcome.DELIVER:
        return False, f"setup failed: honest send was dropped ({first.drop_reason!r})"
    return _expect_drop(node, raw, "duplicate", "step 4 (dedup)")


def attack_stale_timestamp(node: RelayPipeline) -> tuple[bool, str]:
    """Replay of an old capture: validly signed but 6 minutes stale."""
    raw = _victim_packet(timestamp=int(time.time()) - 360)
    return _expect_drop(node, raw, "old", "step 3 (timestamp)")


def attack_future_timestamp(node: RelayPipeline) -> tuple[bool, str]:
    """Validly signed but timestamped 60 s in the future."""
    raw = _victim_packet(timestamp=int(time.time()) + 60)
    return _expect_drop(node, raw, "future", "step 3 (timestamp)")


def attack_duplicate_message(node: RelayPipeline) -> tuple[bool, str]:
    """The same packet delivered twice (e.g. two spray copies arriving)."""
    raw = _victim_packet(payload=b"sent exactly twice")
    node.process(raw)
    return _expect_drop(node, raw, "duplicate", "step 4 (dedup)")


ATTACKS = [
    ("forged signature", attack_forged_signature),
    ("replayed message", attack_replayed_message),
    ("stale timestamp", attack_stale_timestamp),
    ("future timestamp", attack_future_timestamp),
    ("duplicate message", attack_duplicate_message),
]


def run_all() -> list[tuple[str, bool, str]]:
    results = []
    for name, attack in ATTACKS:
        node = RelayPipeline()  # fresh node per attack: no cross-contamination
        # Control: an honest message must pass, so rejections below are real.
        control = node.process(_victim_packet(payload=f"control for {name}".encode()))
        if control.outcome != Outcome.DELIVER:
            results.append((name, False, f"control message was dropped: {control.drop_reason!r}"))
            continue
        ok, detail = attack(node)
        results.append((name, ok, detail))
    return results


def test_all_attacks_rejected():
    """Pytest entry point: every attack must be rejected at its expected step."""
    results = run_all()
    failures = [f"{name}: {detail}" for name, ok, detail in results if not ok]
    assert not failures, "\n".join(failures)


def main() -> int:
    results = run_all()
    print("MeshLink adversarial injection results")
    print("=" * 54)
    for name, ok, detail in results:
        print(f"[{'PASS' if ok else 'FAIL'}] {name:<20} {detail}")
    print("=" * 54)
    failed = sum(1 for _, ok, _ in results if not ok)
    print(f"{len(results) - failed}/{len(results)} attacks correctly rejected")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
