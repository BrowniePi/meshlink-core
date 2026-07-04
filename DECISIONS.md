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
