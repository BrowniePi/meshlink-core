# Simulation harness

Spins up N simulated devices in one process, each its own `SocketTransport` +
`RelayPipeline`, wired into a configurable topology, and lets injected
messages propagate over real local TCP sockets. Threads, not multiprocessing
— `SocketTransport` already runs its accept-loop and per-connection handlers
on daemon threads, so this is genuinely realistic without IPC overhead.

Each device is assigned to one of 4 zones via `zone_id = device_index % 4`. A
device logs a message as "delivered" if the message's `zone_id` matches its
own zone or is the broadcast value `0xFFFF`.

## Running it

```
uv run python -m sim.harness --topology star --devices 4 \
    --inject device=0,payload=hello,zone_id=65535 --wait 1.0
```

- `--topology {line,star,mesh}` and `--devices N` are required.
- `--inject device=I,payload=TEXT[,ttl=T][,spray_l=L][,zone_id=Z][,delay=SECONDS]`
  is repeatable — pass it multiple times to fire several messages in one run,
  optionally at different devices and times (`delay` is seconds to wait after
  the previous injection before firing this one). Defaults: `ttl=5`,
  `spray_l=8`, `zone_id=65535` (broadcast), `delay=0`. Payload text must not
  contain commas (the spec is comma-separated `key=value` pairs).
- `--wait SECONDS` (default `2.0`) is the settle time after the last
  injection before the harness shuts everything down.

Example with two injections:

```
uv run python -m sim.harness --topology line --devices 5 \
    --inject device=0,payload=first \
    --inject device=4,payload=second,delay=0.5 \
    --wait 1.0
```

## Reading the output

Each line is `t=<ms since harness start> device=<index> event=<name> ...fields`:

- `injected` — a message was created at this device (the injection point).
- `received` — this device's transport received bytes from `from=<peer addr>`.
- `delivered` — the pipeline accepted the message and its `zone_id` matched
  this device's zone (or was broadcast).
- `relayed` — the device forwarded a re-spray of the message (`ttl`/`spray_l`
  decremented per Spray-and-Wait's `split_copies`) to `to=<peer addr>`.
- `dropped` — the pipeline rejected the message; `reason=<...>` explains why
  (most commonly `duplicate: msg_id already seen`, which is what stops a
  relayed message from ping-ponging back to a device that already saw it —
  `msg_id` never changes across hops, so each device's own dedup cache kills
  the loop).
- `ack_sent` — a device delivered a message and sent an ACK (msg_type 0x03,
  see `docs/message-format.md`) back to its neighbors.
- `ack_received` / `ack_relayed` — a device received an ACK or ACK_SUPPRESS
  and (while ttl budget remains) re-flooded it as ACK_SUPPRESS.
- `suppressed` — a device held an in-flight spray copy of a msg_id it has
  since learned was ACKed, and dropped it instead of relaying — this is how
  Spray-and-Wait stops flooding a message once it's known to be delivered,
  without waiting for ttl/spray_l to exhaust naturally.

## Demos

`sim/demos/` has one script per Phase 0 validation scenario (TTL expiry,
dedup, spray suppression via ACK). Run e.g. `uv run python -m
sim.demos.demo_spray_suppression`; each script's `.log` file alongside it is
a captured transcript from a prior run.

## Adding a new topology

Add `sim/topologies/<name>.py` exporting:

```python
def build(n: int) -> dict[int, list[int]]:
    """Return a symmetric adjacency dict: j in adj[i] iff i in adj[j]."""
```

then register it in `TOPOLOGIES` in `sim/harness.py`.

## Tests

This harness is a manual-verification rig, not a pytest target — verify by
running it and reading the log output. The existing unit test suite (pipeline
checks, transport, routing) still runs via `uv run pytest`.
