"""Demo: the same message (identical msg_id) sent twice from the same device
is delivered once — the second copy is silently dropped by dedup.

Uses Device.inject() directly (rather than the harness CLI) so both sends
can share one explicit msg_id; the CLI's --inject always mints a fresh
random msg_id per injection. zone_id=4 matches none of the 3 devices
(zones are i%4), so no device delivers/ACKs it — that keeps this demo
isolated to dedup behavior, not the ACK suppression feature.

Run: uv run python -m sim.demos.demo_dedup
"""
import time

from sim.harness import build_devices

MSG_ID = b"\xAB" * 16


def run() -> None:
    devices = build_devices(3, "line")

    devices[0].inject(payload=b"dedup-test", ttl=5, spray_l=8, zone_id=4, msg_id=MSG_ID)
    time.sleep(0.3)
    devices[0].inject(payload=b"dedup-test", ttl=5, spray_l=8, zone_id=4, msg_id=MSG_ID)

    time.sleep(1.0)
    for device in devices:
        device.transport.stop()


if __name__ == "__main__":
    run()
