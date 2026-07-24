# meshlink-core
A pure implementation of the relay pipeline, message format, and Spray-and-Wait logic, running entirely as a simulated network — multiple processes on one laptop talking over local sockets standing in for BLE. No phones, no Pi, no radios at all.

## Relay pipeline

Every received message runs through an ordered sequence of checks before being delivered or forwarded. The order is not arbitrary — it is the primary defence against CPU and battery exhaustion attacks on mobile relay devices.

```
Step 1  size check        raw bytes outside [131, 460]      — one comparison, pre-parse
Step 2  TTL check         ttl == 0                          — one field read
Step 3  timestamp check   > 5 min old or > 30 s in future  — two comparisons, replay prevention
Step 4  dedup             msg_id already seen               — Bloom filter lookup
Step 5  rate limit        sender exceeds N/10 s             — sliding window counter  [stub]
Step 6  signature verify  Ed25519 invalid                   — libsodium, ~50 µs/Pi    [stub]
Step 7  attestation       no valid ticket token             — cached-token lookup
Step 8  deliver or relay  —
```

**Why this order matters:** Ed25519 verification (step 6) costs ~50 µs on a Pi 4 and ~2–5 ms on a mid-range phone. An attacker flooding the network with forged packets would force that cost on every relay device if signature verification ran early. By placing cheap structural checks (steps 1–4) and rate limiting (step 5) first, a flood is stopped before any cryptographic work is done. Steps marked `[stub]` always pass at Phase 0 and are replaced with real implementations in later phases (rate-limit in Phase 0, signature in Phase 4, attestation in Phase 5).

## Message types

The relay pipeline is content-agnostic, but `meshlink-core` also owns the
shared wire formats every consumer (`meshlink-app`, `meshlink-node`) reuses:

```
0x01 TEXT               plain relayed text
0x02 LOCATION           phone → node location beacon (single coordinate)
0x03 ACK / 0x04 ACK_SUPPRESS
0x05 ANNOUNCEMENT
0x06 ATTESTATION_PRESENT organiser JWT (node-terminated)
0x07 FRIEND_REQUEST     sealed to recipient, routed like a DM
0x08 FRIEND_ACCEPT      sealed to original requester; carries a capability token
0x09 FRIEND_DECLINE     minimal, signed; references the request msg_id
0x0A LOCATION_QUERY     requester → node; carries a capability token
0x0B LOCATION_RESPONSE  node → requester; sealed to requester, names its target
0x0C LOCATION_REVOKE    target → node/friend; signed by target
0x0D DIRECT_MESSAGE     friend → friend text, sealed to recipient
```

## Friendship, location & capability tokens

Beyond the pipeline, `meshlink-core` implements the offline-first friendship
and location-sharing protocol shared with the app and node:

- `friends/state.py` — the friendship state machine (request → accept /
  decline, token refresh, revoke) with the effects each transition emits.
- `friends/wire.py` — payload codecs for FRIEND_REQUEST / ACCEPT / DECLINE
  and DIRECT_MESSAGE. Each payload leads with an 8-byte `recipient_hint`
  (`BLAKE3(recipient Ed25519 pub)[0:8]`) so a recipient recognises its own
  mail without trial-decrypting; everything after it is sealed to the
  recipient's Curve25519 key (`crypto/sealed.py`).
- `capability/token.py` — phone-signed capability tokens (98-byte compact
  binary). A node serves a friend's last-known coordinate only against a
  token signed by the *target's* long-term Ed25519 key, so a compromised
  node can never fabricate consent.
- `location/wire.py` — the LOCATION beacon / QUERY / RESPONSE / REVOKE codecs.

Delivery uses Spray-and-Wait (`routing/spray_and_wait.py`): step 8 sprays a
message toward the destination zone, and a LOCATION_RESPONSE names its target
so the requesting node can route the reply back.

## Running tests

```
pip install pytest
pytest
```
