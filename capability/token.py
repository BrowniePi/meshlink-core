"""Phone-signed capability tokens for node-served location.

Security invariant 1 — the node never fabricates consent. A node serves a
friend's last-known coordinate only when presented a token signed by the
*target's* long-term Ed25519 key ("target grants grantee the right to query
`scope` until `expires_at`"). A compromised node cannot grant itself or a
stranger access because it cannot forge that signature; it can only refuse
to enforce expiry/revocation for tokens that were already legitimately
issued (invariant 5 bounds that with short expiries).

Compact binary on-wire encoding (fixed field order, big-endian) — JSON would
not fit the §2 size bounds once embedded in FRIEND_ACCEPT alongside keys:

    version(1) ‖ issuer_pubkey_id(8) ‖ grantee_pubkey_id(8) ‖
    issued_at(4) ‖ expires_at(4) ‖ scope(1) ‖ nonce(8) ‖ signature(64)

TOKEN_SIZE = 98 bytes. `*_pubkey_id` is BLAKE3(ed25519_pub)[0:8] — the token
never carries full public keys; the verifier must already know the expected
target key (from the node's cached user directory), so a token alone names
nobody. `nonce` + (issuer, grantee, issued_at) form the revocation key the
node stores in its revocation set.
"""
import struct
import time
from dataclasses import dataclass

import blake3
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey
from nacl.utils import random as nacl_random

TOKEN_VERSION = 1
SCOPE_LOCATION = 0x01

_BODY_FORMAT = ">B8s8sIIB8s"
_BODY_SIZE = struct.calcsize(_BODY_FORMAT)  # 34
_SIGNATURE_SIZE = 64
TOKEN_SIZE = _BODY_SIZE + _SIGNATURE_SIZE   # 98

DEFAULT_EXPIRY_S = 24 * 3600  # short expiry bounds a leaked token's usefulness


def pubkey_id(ed25519_pub: bytes) -> bytes:
    """8-byte truncated BLAKE3 of a long-term Ed25519 public key."""
    if len(ed25519_pub) != 32:
        raise ValueError("ed25519 public key must be 32 bytes")
    return blake3.blake3(ed25519_pub).digest()[:8]


@dataclass(frozen=True)
class CapabilityToken:
    version: int
    issuer_pubkey_id: bytes    # 8 bytes — truncated hash of target Ed25519
    grantee_pubkey_id: bytes   # 8 bytes
    issued_at: int             # uint32 Unix seconds
    expires_at: int            # uint32 Unix seconds
    scope: int                 # bitflags: LOCATION = 0x01
    nonce: bytes               # 8 bytes
    signature: bytes           # 64 bytes, Ed25519 by the issuer (target)

    @property
    def raw(self) -> bytes:
        return self.body + self.signature

    @property
    def body(self) -> bytes:
        return struct.pack(
            _BODY_FORMAT,
            self.version,
            self.issuer_pubkey_id,
            self.grantee_pubkey_id,
            self.issued_at,
            self.expires_at,
            self.scope,
            self.nonce,
        )


def parse(raw: bytes) -> CapabilityToken:
    """Decode a token. Raises ValueError if structurally invalid."""
    if len(raw) != TOKEN_SIZE:
        raise ValueError(f"capability token must be {TOKEN_SIZE} bytes, got {len(raw)}")
    (version, issuer_id, grantee_id, issued_at,
     expires_at, scope, nonce) = struct.unpack(_BODY_FORMAT, raw[:_BODY_SIZE])
    return CapabilityToken(
        version=version,
        issuer_pubkey_id=issuer_id,
        grantee_pubkey_id=grantee_id,
        issued_at=issued_at,
        expires_at=expires_at,
        scope=scope,
        nonce=nonce,
        signature=raw[_BODY_SIZE:],
    )


def issue(
    issuer_signing_key: SigningKey,
    grantee_ed25519_pub: bytes,
    *,
    scope: int = SCOPE_LOCATION,
    issued_at: int | None = None,
    expiry_s: int = DEFAULT_EXPIRY_S,
    nonce: bytes | None = None,
) -> bytes:
    """Mint a token signed with the issuer's (the target's) long-term key.

    Only the person whose location is being shared can call this — the
    signing key never leaves their phone.
    """
    if issued_at is None:
        issued_at = int(time.time())
    if nonce is None:
        nonce = nacl_random(8)
    token = CapabilityToken(
        version=TOKEN_VERSION,
        issuer_pubkey_id=pubkey_id(bytes(issuer_signing_key.verify_key)),
        grantee_pubkey_id=pubkey_id(grantee_ed25519_pub),
        issued_at=issued_at,
        expires_at=issued_at + expiry_s,
        scope=scope,
        nonce=nonce,
        signature=b"",
    )
    signature = issuer_signing_key.sign(token.body).signature
    return token.body + signature


def verify(
    raw: bytes,
    expected_target_ed25519_pub: bytes,
    grantee_pubkey: bytes,
    now: int,
    *,
    scope: int = SCOPE_LOCATION,
) -> bool:
    """True iff the token is a currently valid grant from the expected target
    to this grantee for this scope. Pure function, no I/O.

    Checks, in order: structure, version, issuer binding (the token must hash
    -bind to the *expected* target key — a token from anyone else is not
    consent, invariant 1), grantee binding, scope bit, time window, and the
    Ed25519 signature by the target's long-term key.
    """
    try:
        token = parse(raw)
    except ValueError:
        return False
    if token.version != TOKEN_VERSION:
        return False
    if token.issuer_pubkey_id != pubkey_id(expected_target_ed25519_pub):
        return False
    if token.grantee_pubkey_id != pubkey_id(grantee_pubkey):
        return False
    if not token.scope & scope:
        return False
    if not token.issued_at <= now < token.expires_at:
        return False
    try:
        VerifyKey(expected_target_ed25519_pub).verify(token.body, token.signature)
    except BadSignatureError:
        return False
    return True


def revocation_key(token: CapabilityToken) -> tuple[bytes, bytes, int, bytes]:
    """The identity of a grant for the node's revocation set: a LOCATION_REVOKE
    naming these four fields invalidates exactly this token."""
    return (token.issuer_pubkey_id, token.grantee_pubkey_id,
            token.issued_at, token.nonce)
