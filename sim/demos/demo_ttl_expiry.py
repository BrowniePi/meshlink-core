"""Demo: a message with ttl=2 sent across a 4-hop line topology dies before
reaching the far end.

zone_id=4 matches none of the 5 devices (zones are i%4, i.e. 0/1/2/3/0), so
no device ever delivers/ACKs it — this isolates the demo to pure TTL
behavior. ttl=2 allows exactly one relay hop (device0 -> device1); device1's
own relay attempt is blocked by the `ttl > 1` guard before a second hop ever
happens, so devices 2/3/4 never see the message.

Run: uv run python -m sim.demos.demo_ttl_expiry
"""
from sim.harness import main


def run() -> None:
    main([
        "--topology", "line",
        "--devices", "5",
        "--inject", "device=0,payload=ttltest,ttl=2,zone_id=4",
        "--wait", "1.0",
    ])


if __name__ == "__main__":
    run()
