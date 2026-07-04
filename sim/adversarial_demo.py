"""Socket-based adversarial demo: a real 3-node mesh (sim.harness devices,
each its own SocketTransport + RelayPipeline) receiving forged/replayed/
stale/future/duplicate messages over genuine TCP connections from an
attacker that is not one of the mesh's registered neighbors.

This exercises the exact same live-node path as `sim.harness` — packets
travel over real sockets and are processed by a device's real RelayPipeline
in its own accept-thread — unlike tests/adversarial/inject_attacks.py, which
calls RelayPipeline.process() directly in-process. Confirms Phase 4's
"3-node mesh ... provably resistant to a forged or replayed message" demo
criterion holds for this repo's socket transport.

Run: uv run python -m sim.adversarial_demo
"""
import os
import sys
import time

from identity import generate_keypair
from sim import device as device_module
from sim.device import Device
from sim.packet import build_packet
from sim.topologies import line
from transport.socket_transport import SocketTransport

SETTLE_SECONDS = 0.3
ATTACKER_IDENTITY = generate_keypair()  # never a hardcoded/dummy key


def _build_mesh(n: int = 3) -> list[Device]:
    adjacency = line.build(n)
    devices = [Device(index=i, zone_id=0) for i in range(n)]
    for d in devices:
        d.start()
    for i, d in enumerate(devices):
        d.neighbors = [devices[j].address for j in adjacency[i]]
        for j in adjacency[i]:
            d.connect_to(devices[j].address)
    return devices


def _capture_events():
    """Patch sim.device's log_event so we can assert on outcomes while still
    printing the normal demo output."""
    events: list[tuple[str, int, dict]] = []
    original = device_module.log_event

    def capturing(event, index, **fields):
        events.append((event, index, fields))
        original(event, index, **fields)

    device_module.log_event = capturing
    return events, original


def _send_raw(attacker: SocketTransport, victim: Device, raw: bytes) -> None:
    attacker.send(victim.address, raw)
    time.sleep(SETTLE_SECONDS)


def _last_outcome_for(events, victim_index: int) -> tuple[str, str | None]:
    for event, index, fields in reversed(events):
        if index == victim_index and event in ("delivered", "dropped"):
            return event, fields.get("reason")
    return "none", None


def _victim_packet(*, timestamp: int | None = None, msg_id: bytes | None = None,
                    payload: bytes = b"attack payload") -> bytes:
    return build_packet(
        identity=ATTACKER_IDENTITY,
        msg_id=msg_id or os.urandom(16),
        ephem_id=b"\xee" * 16,
        timestamp=timestamp if timestamp is not None else int(time.time()),
        ttl=5,
        spray_l=1,
        zone_id=0xFFFF,
        msg_type=1,
        payload=payload,
    )


def main() -> int:
    devices = _build_mesh(3)
    events, _ = _capture_events()
    attacker = SocketTransport()
    attacker.start()
    victim = devices[1]  # middle node of the line topology
    attacker.connect_peer(victim.address)

    results = []

    # Control: an honest, validly signed message must be delivered.
    control_raw = _victim_packet(payload=b"control message")
    _send_raw(attacker, victim, control_raw)
    outcome, _ = _last_outcome_for(events, victim.index)
    results.append(("control (honest message)", outcome == "delivered", outcome))

    # Attack 1: forged signature.
    forged = bytearray(_victim_packet())
    forged[-64:] = b"\x99" * 64
    _send_raw(attacker, victim, bytes(forged))
    outcome, reason = _last_outcome_for(events, victim.index)
    ok = outcome == "dropped" and reason and "signature" in reason.lower()
    results.append(("forged signature -> step 6", ok, f"{outcome}: {reason}"))

    # Attack 2: replayed message (capture + immediate re-send while fresh).
    replay_raw = _victim_packet(payload=b"captured then replayed")
    _send_raw(attacker, victim, replay_raw)  # first delivery
    _send_raw(attacker, victim, replay_raw)  # attacker replays the capture
    outcome, reason = _last_outcome_for(events, victim.index)
    ok = outcome == "dropped" and reason and "duplicate" in reason.lower()
    results.append(("replayed message -> step 4 (dedup)", ok, f"{outcome}: {reason}"))

    # Attack 3: stale timestamp (6 minutes old).
    stale_raw = _victim_packet(timestamp=int(time.time()) - 360)
    _send_raw(attacker, victim, stale_raw)
    outcome, reason = _last_outcome_for(events, victim.index)
    ok = outcome == "dropped" and reason and "old" in reason.lower()
    results.append(("stale timestamp -> step 3", ok, f"{outcome}: {reason}"))

    # Attack 4: future timestamp (60s ahead).
    future_raw = _victim_packet(timestamp=int(time.time()) + 60)
    _send_raw(attacker, victim, future_raw)
    outcome, reason = _last_outcome_for(events, victim.index)
    ok = outcome == "dropped" and reason and "future" in reason.lower()
    results.append(("future timestamp -> step 3", ok, f"{outcome}: {reason}"))

    # Attack 5: duplicate message (same msg_id sent twice, e.g. two spray copies).
    dup_msg_id = os.urandom(16)
    dup_raw = _victim_packet(msg_id=dup_msg_id, payload=b"sent exactly twice")
    _send_raw(attacker, victim, dup_raw)
    _send_raw(attacker, victim, dup_raw)
    outcome, reason = _last_outcome_for(events, victim.index)
    ok = outcome == "dropped" and reason and "duplicate" in reason.lower()
    results.append(("duplicate message -> step 4 (dedup)", ok, f"{outcome}: {reason}"))

    attacker.stop()
    for d in devices:
        d.transport.stop()

    print()
    print("Socket-based adversarial demo results")
    print("=" * 60)
    failed = 0
    for name, ok, detail in results:
        print(f"[{'PASS' if ok else 'FAIL'}] {name:<38} {detail}")
        if not ok:
            failed += 1
    print("=" * 60)
    print(f"{len(results) - failed}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
