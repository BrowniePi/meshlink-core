"""Demo: a Spray-and-Wait message (L=4) sprayed across multiple peers from a
hub, where the destination's ACK suppresses the copy it would otherwise have
forwarded onward.

Topology: device0 is a hub connected to peers 1/2/3 (the "multiple peers"
L=4 is sprayed across); device4 sits one hop past device1, which is the
message's intended destination (unique zone_id=99). When device1 delivers
the message it immediately sends an ACK and marks the msg_id as acked, so
its own would-be relay to device4 is suppressed instead of sent — even
though spray_l and ttl both still have budget left, proving the suppression
is ACK-driven, not exhaustion-driven. device4 ends up only ever seeing the
ACK, never the data payload.

Run: uv run python -m sim.demos.demo_spray_suppression
"""
import time

from sim.device import Device

ADJACENCY = {
    0: [1, 2, 3],
    1: [0, 4],
    2: [0],
    3: [0],
    4: [1],
}
TARGET_ZONE = 99


def build_devices() -> list[Device]:
    devices = [Device(index=i, zone_id=0) for i in range(5)]
    devices[1].zone_id = TARGET_ZONE

    for device in devices:
        device.start()

    for i, device in enumerate(devices):
        device.neighbors = [devices[j].address for j in ADJACENCY[i]]
        for j in ADJACENCY[i]:
            device.connect_to(devices[j].address)

    return devices


def run() -> None:
    devices = build_devices()

    devices[0].inject(
        payload=b"spray-test",
        ttl=6,
        spray_l=4,
        zone_id=TARGET_ZONE,
        msg_id=b"\xCD" * 16,
    )

    time.sleep(1.5)
    for device in devices:
        device.transport.stop()


if __name__ == "__main__":
    run()
