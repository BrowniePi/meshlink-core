"""Payload codecs for FRIEND_REQUEST / FRIEND_ACCEPT / FRIEND_DECLINE.

The MeshLink envelope has no destination field (messages are zone-routed),
so every friend payload starts with an 8-byte plaintext `recipient_hint` —
BLAKE3(recipient Ed25519 pub)[0:8] — letting the recipient recognise its own
mail without anyone trial-decrypting. The hint names a *public key hash*,
never a username or a stable identifier absent from the directory, and it
rides inside the message envelope over established connections — nothing
here touches BLE advertising (invariant 2, Technical Reference §7.4).

Everything after the hint in REQUEST/ACCEPT is sealed to the recipient's
Curve25519 key (crypto/sealed.py): usernames and public keys of who is
befriending whom are not backhaul-sniffable. All payloads stay within the
§2 size bounds — asserted in tests/test_friend_wire.py.
"""
import struct
from dataclasses import dataclass

from capability.token import TOKEN_SIZE
from crypto.sealed import seal, unseal

RECIPIENT_HINT_SIZE = 8
MAX_USERNAME_BYTES = 32


@dataclass(frozen=True)
class FriendRequestPayload:
    """Requester username + long-term public keys, sealed to the recipient."""
    username: str
    curve25519_pub: bytes
    ed25519_pub: bytes


@dataclass(frozen=True)
class FriendAcceptPayload:
    """Acceptor username + public keys + optionally the initial capability
    token (present when the acceptor also enabled location at accept time)."""
    username: str
    curve25519_pub: bytes
    ed25519_pub: bytes
    capability_token: bytes | None = None


def _pack_identity(username: str, curve_pub: bytes, ed_pub: bytes) -> bytes:
    name = username.encode("utf-8")
    if not 1 <= len(name) <= MAX_USERNAME_BYTES:
        raise ValueError(f"username must be 1–{MAX_USERNAME_BYTES} UTF-8 bytes")
    if len(curve_pub) != 32 or len(ed_pub) != 32:
        raise ValueError("public keys must be 32 bytes")
    return struct.pack(">B", len(name)) + name + curve_pub + ed_pub


def _unpack_identity(data: bytes) -> tuple[str, bytes, bytes, bytes]:
    """Returns (username, curve_pub, ed_pub, remainder)."""
    if len(data) < 1:
        raise ValueError("identity block truncated")
    name_len = data[0]
    if not 1 <= name_len <= MAX_USERNAME_BYTES or len(data) < 1 + name_len + 64:
        raise ValueError("identity block malformed")
    name = data[1:1 + name_len].decode("utf-8")
    curve_pub = data[1 + name_len:1 + name_len + 32]
    ed_pub = data[1 + name_len + 32:1 + name_len + 64]
    return name, curve_pub, ed_pub, data[1 + name_len + 64:]


def encode_friend_request(
    payload: FriendRequestPayload,
    recipient_hint: bytes,
    recipient_curve25519_pub: bytes,
) -> bytes:
    body = _pack_identity(payload.username, payload.curve25519_pub, payload.ed25519_pub)
    return recipient_hint + seal(body, recipient_curve25519_pub)


def decode_friend_request(
    raw: bytes, recipient_curve25519_priv: bytes,
) -> FriendRequestPayload:
    body = unseal(raw[RECIPIENT_HINT_SIZE:], recipient_curve25519_priv)
    username, curve_pub, ed_pub, rest = _unpack_identity(body)
    if rest:
        raise ValueError("trailing bytes in FRIEND_REQUEST payload")
    return FriendRequestPayload(username, curve_pub, ed_pub)


def encode_friend_accept(
    payload: FriendAcceptPayload,
    recipient_hint: bytes,
    recipient_curve25519_pub: bytes,
) -> bytes:
    body = _pack_identity(payload.username, payload.curve25519_pub, payload.ed25519_pub)
    if payload.capability_token is None:
        body += struct.pack(">B", 0)
    else:
        if len(payload.capability_token) != TOKEN_SIZE:
            raise ValueError("capability token has wrong size")
        body += struct.pack(">B", 1) + payload.capability_token
    return recipient_hint + seal(body, recipient_curve25519_pub)


def decode_friend_accept(
    raw: bytes, recipient_curve25519_priv: bytes,
) -> FriendAcceptPayload:
    body = unseal(raw[RECIPIENT_HINT_SIZE:], recipient_curve25519_priv)
    username, curve_pub, ed_pub, rest = _unpack_identity(body)
    if len(rest) < 1:
        raise ValueError("FRIEND_ACCEPT payload truncated")
    has_token, rest = rest[0], rest[1:]
    token = None
    if has_token:
        if len(rest) != TOKEN_SIZE:
            raise ValueError("FRIEND_ACCEPT token block malformed")
        token = rest
    elif rest:
        raise ValueError("trailing bytes in FRIEND_ACCEPT payload")
    return FriendAcceptPayload(username, curve_pub, ed_pub, token)


def encode_friend_decline(request_msg_id: bytes, recipient_hint: bytes) -> bytes:
    """Minimal by design: no payload beyond the msg_id reference. Authenticity
    comes from the envelope's Ed25519 signature (pipeline step 6)."""
    if len(request_msg_id) != 16:
        raise ValueError("msg_id must be 16 bytes")
    return recipient_hint + request_msg_id


def decode_friend_decline(raw: bytes) -> bytes:
    """Returns the declined request's msg_id."""
    if len(raw) != RECIPIENT_HINT_SIZE + 16:
        raise ValueError("FRIEND_DECLINE payload malformed")
    return raw[RECIPIENT_HINT_SIZE:]


def recipient_hint_of(raw: bytes) -> bytes:
    """The plaintext hint prefix — how a phone recognises mail addressed to it."""
    if len(raw) < RECIPIENT_HINT_SIZE:
        raise ValueError("payload shorter than recipient hint")
    return raw[:RECIPIENT_HINT_SIZE]
