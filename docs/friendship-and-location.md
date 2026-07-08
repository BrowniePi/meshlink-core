# Friendship, Mutual Consent, and Node-Served Location — core additions

Phase 5 extension. Everything here is pure protocol logic (no I/O, no
platform code), consumed by `meshlink-node` (submodule) and ported to Dart in
`meshlink-app` (parity-tested).

## What was added

| Module | Purpose |
|---|---|
| `pipeline/message.py` `MessageType` | Formalises the msg_type enum; adds `FRIEND_REQUEST/ACCEPT/DECLINE` (0x07–0x09), `LOCATION_QUERY/RESPONSE/REVOKE` (0x0A–0x0C) and `DIRECT_MESSAGE` (0x0D). Existing values untouched; 0x06 (attestation presentation, allocated node/app-side) is recorded so nothing reclaims it. The 120 s phone→node location beacon reuses the existing `LOCATION` (0x02) type — no new beacon type. |
| `friends/state.py` | Pure friendship state machine: `NONE → REQUESTED/PENDING → FRIENDS → REVOKED`. Takes events, returns new state + side-effect descriptors. `location_sharing_enabled` is a separate per-friend flag — friendship never auto-shares location. |
| `friends/wire.py` | Payload codecs for the three friend message types, plus DIRECT_MESSAGE (0x0D): `hint ‖ seal(utf-8 text)`, text ≤ 265 bytes (321 − 8 hint − 48 seal overhead). DMs relay like TEXT but only the recipient can read them; sender authenticity is the envelope Ed25519 signature, and receiving phones drop DMs from anyone not a pinned FRIENDS-state peer — mutual consent gates messaging too. |
| `capability/token.py` | 98-byte compact-binary capability token: `version ‖ issuer_pubkey_id(8) ‖ grantee_pubkey_id(8) ‖ issued_at ‖ expires_at ‖ scope ‖ nonce(8) ‖ Ed25519 signature(64)`, signed by the **target's** long-term key. `verify()` is a pure function. Default expiry 24 h. |
| `location/wire.py` | Codecs for LOCATION_QUERY (the token itself), LOCATION_RESPONSE (single sealed coordinate), LOCATION_REVOKE (revocation key). |
| `crypto/sealed.py` | Anonymous sealed envelope to an X25519 key (ephemeral X25519 + ChaCha20-Poly1305-IETF, 48-byte overhead). libsodium's `crypto_box_seal` construction with the AEAD swapped so the pure-Dart port can match it byte-for-byte. |

## Security invariants upheld here

1. **The node never fabricates consent.** Access to a coordinate is gated on
   a token signed by the target's long-term Ed25519 key. A compromised node
   cannot forge that signature — `tests/test_capability_token.py::
   test_token_signed_by_non_target_fails` proves a token signed by any other
   key (including a node's own) verifies false.
2. **Stable identity never touches the BLE air interface.** Nothing in these
   modules emits anything into advertising; identities appear only inside
   the signed envelope over established connections, and friend payloads
   seal usernames/keys so even the backhaul sees only an 8-byte pubkey hash
   hint (§7.4 ephemeral-ID rotation is untouched).
3. **Latest-coordinate-only, from the wire format itself.** LOCATION_RESPONSE
   is a fixed 16-byte single-coordinate struct — no timestamp array, no
   history field, by construction (`test_location_response_carries_no_history_by_construction`).
   Storage-side enforcement lives in `meshlink-node/location/store.py`.
4. **Location responses are encrypted to the requester** via the sealed
   envelope — a passive backhaul sniffer harvests nothing.
5. **Consent is revocable and expiring.** Tokens carry `expires_at`
   (default 24 h); `(issuer, grantee, issued_at, nonce)` is the revocation
   key a LOCATION_REVOKE names.

## Decisions (in the spirit of DECISIONS.md — the Dart port must match)

- **Separate X25519 encryption keypair per account**, registered alongside
  the Ed25519 signing key. The app's pure-Dart crypto (package:cryptography)
  cannot do libsodium's Ed25519→Curve25519 conversion, so accounts carry
  both keys explicitly (that's why the backend `users` schema has
  `curve25519_pub` *and* `ed25519_pub`).
- **Sealed envelope = ephemeral X25519 + BLAKE3 KDF + ChaCha20-Poly1305-IETF,
  zero nonce** (key is single-use), 48-byte overhead. Not libsodium
  `crypto_box_seal` (XSalsa20 — unavailable in Dart).
- **Recipient hints**: the envelope has no destination field, so recipient-
  addressed payloads carry BLAKE3(recipient Ed25519 pub)[0:8] in plaintext.
  A hash of a public key, rotating nothing, revealing no username.
- **Simultaneous cross-request** (both sides send FRIEND_REQUEST): the
  inbound request moves the record to PENDING and the local user must still
  accept — there is no auto-accept path anywhere in the machine.
