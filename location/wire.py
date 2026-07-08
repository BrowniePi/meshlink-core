"""Payload codecs for LOCATION_QUERY / LOCATION_RESPONSE / LOCATION_REVOKE.

LOCATION_QUERY is node-terminated: a requester asks the *node* for a
friend's last-known coordinate, presenting the capability token that friend
signed for them. The node never forwards the query to the target phone — the
whole point of the hybrid is that it works while the target is asleep.

LOCATION_RESPONSE is a single coordinate, sealed to the requester's
Curve25519 key (invariant 4 — a passive backhaul sniffer harvests nothing).
The plaintext struct is fixed-size by construction: one lat, one lon, one
age. There is no timestamp array, no history field, and no room to add one
without a version bump — the wire format itself enforces the
latest-coordinate-only retention invariant from the response side
(invariant 3). Coordinates use the same int32 microdegree encoding as the
LOCATION beacon (docs/message-format.md §4).

LOCATION_REVOKE carries the revocation key of a previously issued grant
(capability.token.revocation_key). Its authenticity comes from the envelope
signature: enforcement points must check the envelope sender is the token's
issuer before honouring it, else anyone could revoke anyone's grants.
"""
import struct
from dataclasses import dataclass

from capability.token import TOKEN_SIZE
from crypto.sealed import seal, unseal

REQUESTER_HINT_SIZE = 8

# lat(int32 microdeg) lon(int32 microdeg) accuracy_m(u16) beacon_age_s(u32) zone_id(u16)
_RESPONSE_FORMAT = ">iiHIH"
_RESPONSE_SIZE = struct.calcsize(_RESPONSE_FORMAT)  # 16

_REVOKE_FORMAT = ">8s8sI8s"
REVOKE_PAYLOAD_SIZE = struct.calcsize(_REVOKE_FORMAT)  # 28


@dataclass(frozen=True)
class LocationResponsePayload:
    lat_microdeg: int
    lon_microdeg: int
    accuracy_m: int
    beacon_age_s: int   # how stale the coordinate is — surfaced in the UI
    zone_id: int


@dataclass(frozen=True)
class LocationRevokePayload:
    """revocation key fields, mirroring capability.token.revocation_key."""
    issuer_pubkey_id: bytes
    grantee_pubkey_id: bytes
    issued_at: int
    nonce: bytes

    @property
    def revocation_key(self) -> tuple[bytes, bytes, int, bytes]:
        return (self.issuer_pubkey_id, self.grantee_pubkey_id,
                self.issued_at, self.nonce)


def encode_location_query(capability_token: bytes) -> bytes:
    """The query payload is exactly the token — the target is named by the
    token's issuer_pubkey_id and the requester by the envelope sender_key."""
    if len(capability_token) != TOKEN_SIZE:
        raise ValueError("capability token has wrong size")
    return capability_token


def decode_location_query(raw: bytes) -> bytes:
    if len(raw) != TOKEN_SIZE:
        raise ValueError("LOCATION_QUERY payload malformed")
    return raw


def encode_location_response(
    payload: LocationResponsePayload,
    requester_hint: bytes,
    requester_curve25519_pub: bytes,
) -> bytes:
    body = struct.pack(
        _RESPONSE_FORMAT,
        payload.lat_microdeg,
        payload.lon_microdeg,
        payload.accuracy_m,
        payload.beacon_age_s,
        payload.zone_id,
    )
    return requester_hint + seal(body, requester_curve25519_pub)


def decode_location_response(
    raw: bytes, requester_curve25519_priv: bytes,
) -> LocationResponsePayload:
    body = unseal(raw[REQUESTER_HINT_SIZE:], requester_curve25519_priv)
    if len(body) != _RESPONSE_SIZE:
        raise ValueError("LOCATION_RESPONSE payload malformed")
    lat, lon, accuracy_m, age_s, zone_id = struct.unpack(_RESPONSE_FORMAT, body)
    return LocationResponsePayload(lat, lon, accuracy_m, age_s, zone_id)


def encode_location_revoke(payload: LocationRevokePayload) -> bytes:
    return struct.pack(
        _REVOKE_FORMAT,
        payload.issuer_pubkey_id,
        payload.grantee_pubkey_id,
        payload.issued_at,
        payload.nonce,
    )


def decode_location_revoke(raw: bytes) -> LocationRevokePayload:
    if len(raw) != REVOKE_PAYLOAD_SIZE:
        raise ValueError("LOCATION_REVOKE payload malformed")
    issuer_id, grantee_id, issued_at, nonce = struct.unpack(_REVOKE_FORMAT, raw)
    return LocationRevokePayload(issuer_id, grantee_id, issued_at, nonce)
