# Phase 4 Implementation Decisions (not specified in Notion)

Choices made during the Python (meshlink-core) implementation that the Notion
docs leave open. **The Dart port must make the same choices** so both
implementations are wire- and behaviour-compatible.

## Identity / keygen

- **Key type: Ed25519, not raw Curve25519.** Notion says "Curve25519 keypair"
  for identity but also requires Ed25519 signatures from "the keypair whose
  public half is `sender_key`" (message-format.md §3). These are only
  simultaneously satisfiable if the long-term keypair is an Ed25519
  (crypto_sign) keypair: its public key is birationally equivalent to a
  Curve25519 key and libsodium converts it (`crypto_sign_ed25519_pk_to_curve25519`)
  for X25519 DH when DM encryption arrives. So: **generate Ed25519; the wire
  `sender_key` is the 32-byte Ed25519 public key.** Dart: use a libsodium
  binding (e.g. `sodium_libs`), same construction.
- **Library: PyNaCl 1.6.2** (libsodium bindings) — vetted, maintained, the
  canonical libsodium binding for Python. Not hand-rolled.
- **Placeholder key store:** plaintext JSON file (`private_seed` + `public_key`
  as hex) created with `0600` permissions, generated exactly once
  (fails-closed on race via `O_EXCL`). This is explicitly temporary; secure
  storage (Keychain/Keystore) is the app-side Phase 4 task.

## Pipeline checks

- **Rate limit N = 10 messages per 10 s window** (confirmed with project owner
  2026-07-04). Notion gives the window (10 s) and the ban rule (60 s ban after
  3 violations in a row, Tech Ref §8.3) but never fixes N.
- **Rate-limit semantics:** over-limit messages are dropped and do NOT consume
  window budget; a message that passes resets the consecutive-violation
  streak; while banned, messages are dropped without touching the window; the
  streak restarts at zero after a ban expires. Boundary: a message exactly
  `WINDOW_SECONDS` old still counts inside the window (evict when age
  strictly > window).
- **Rate-limiter memory bound:** per-sender state is pruned opportunistically
  (every 1,000 checks, drop senders idle > 10 min and not banned) so the
  sender map can't grow unbounded at event scale.
- **Dedup Bloom/LRU wiring:** the Bloom filter answers membership (a ~1% false
  positive drops a valid message once — spec'd as acceptable); the LRU
  (OrderedDict msg_id → seen_at) is the source of truth for what is live.
  Because Bloom filters can't delete, the filter is **rebuilt from live LRU
  entries after 1,000 evictions accumulate** (threshold = 10% of capacity).
  The filter is sized `capacity + 2 × rebuild_threshold` so lingering evicted
  entries never overflow its hard capacity between rebuilds. Boundary: an
  entry exactly at the 10-min TTL is still a duplicate (evict when age
  strictly > TTL).
- **Bloom library (Python): pybloom-live 4.0.0** — named in the Tech Ref.
  Dart: any Bloom implementation with the same capacity/error-rate semantics
  works; the filter is device-local state, never on the wire, so
  implementations don't need to match bit-for-bit.
- **Clock injection:** `DedupCache` and `RateLimiter` take a `clock` callable
  (default `time.time`) so tests control time. Mirror this in Dart.

## Signing / verification

- **Signed region:** the Phase 4 task card says the signature "must cover
  msg_id + payload"; message-format.md §3 is more precise — the signature
  covers `bytes[0 : 75 + payload_len]` (the whole header including msg_id,
  plus payload). The spec's definition is implemented; the task wording is a
  summary of it, not a different scheme.
- **msg_id hashing: `blake3` PyPI package 1.x** (official Rust-backed
  binding). Dart: any BLAKE3 implementation; output must match byte-for-byte
  (`BLAKE3(sender_key ‖ timestamp_be4 ‖ msg_type_byte ‖ payload)[0:16]`).
- **No hardcoded test keypair anywhere:** the test helpers generate a fresh
  `TEST_IDENTITY` at import time and sign every built packet with it. Do the
  same in the Dart test suite — never commit key material, even test keys.
- **Pipeline does not verify msg_id derivation.** Recomputing the BLAKE3
  msg_id at relays is possible per spec ("any relay can recompute") but is not
  one of the 8 documented pipeline steps, so it is deliberately not checked.
