"""Friend/location payload codecs: round-trips, recipient hints, and the §2
size-bound assertions — every new message type must serialise to a full
signed packet within [131, 460] bytes even at maximum field sizes."""
import dataclasses

import pytest
from nacl.signing import SigningKey

from capability.token import issue, pubkey_id
from crypto.sealed import generate_encryption_keypair
from friends.wire import (
    MAX_DM_TEXT_BYTES,
    MAX_USERNAME_BYTES,
    FriendAcceptPayload,
    FriendRequestPayload,
    decode_direct_message,
    decode_friend_accept,
    decode_friend_decline,
    decode_friend_request,
    encode_direct_message,
    encode_friend_accept,
    encode_friend_decline,
    encode_friend_request,
    recipient_hint_of,
)
from identity import generate_keypair
from location.wire import (
    LocationResponsePayload,
    LocationRevokePayload,
    decode_location_query,
    decode_location_response,
    decode_location_revoke,
    encode_location_query,
    encode_location_response,
    encode_location_revoke,
)
from pipeline.message import MAX_PACKET, MIN_PACKET, MessageType
from identity.signing import build_signed_packet

RECIP_PRIV, RECIP_PUB = generate_encryption_keypair()
SENDER_ED = SigningKey.generate()
HINT = b"\x11" * 8
MAX_NAME = "u" * MAX_USERNAME_BYTES

TOKEN = issue(SENDER_ED, b"\x22" * 32, issued_at=1_800_000_000)


def as_packet(msg_type: int, payload: bytes) -> bytes:
    return build_signed_packet(
        generate_keypair(),
        ephem_id=b"\x03" * 16,
        ttl=5,
        spray_l=1,
        zone_id=3,
        msg_type=msg_type,
        payload=payload,
    )


def assert_within_size_bounds(msg_type: int, payload: bytes):
    packet = as_packet(msg_type, payload)
    assert MIN_PACKET <= len(packet) <= MAX_PACKET, (
        f"msg_type {msg_type:#x}: {len(packet)}-byte packet outside "
        f"[{MIN_PACKET}, {MAX_PACKET}]"
    )


def test_friend_request_round_trip_and_size():
    payload = FriendRequestPayload(MAX_NAME, b"\x04" * 32, b"\x05" * 32)
    raw = encode_friend_request(payload, HINT, RECIP_PUB)
    assert recipient_hint_of(raw) == HINT
    assert decode_friend_request(raw, RECIP_PRIV) == payload
    assert_within_size_bounds(MessageType.FRIEND_REQUEST, raw)


def test_friend_accept_with_token_round_trip_and_size():
    """Worst case for the accept payload: max username + embedded token."""
    payload = FriendAcceptPayload(MAX_NAME, b"\x04" * 32, b"\x05" * 32, TOKEN)
    raw = encode_friend_accept(payload, HINT, RECIP_PUB)
    assert decode_friend_accept(raw, RECIP_PRIV) == payload
    assert_within_size_bounds(MessageType.FRIEND_ACCEPT, raw)


def test_friend_accept_without_token_round_trip():
    payload = FriendAcceptPayload("bo", b"\x04" * 32, b"\x05" * 32, None)
    raw = encode_friend_accept(payload, HINT, RECIP_PUB)
    assert decode_friend_accept(raw, RECIP_PRIV) == payload


def test_friend_decline_round_trip_and_size():
    raw = encode_friend_decline(b"\x0f" * 16, HINT)
    assert decode_friend_decline(raw) == b"\x0f" * 16
    assert recipient_hint_of(raw) == HINT
    assert_within_size_bounds(MessageType.FRIEND_DECLINE, raw)


def test_location_query_round_trip_and_size():
    raw = encode_location_query(TOKEN)
    assert decode_location_query(raw) == TOKEN
    assert_within_size_bounds(MessageType.LOCATION_QUERY, raw)


def test_location_response_round_trip_and_size():
    payload = LocationResponsePayload(
        lat_microdeg=51503298, lon_microdeg=-127144,
        accuracy_m=5, beacon_age_s=40, zone_id=3,
    )
    raw = encode_location_response(payload, HINT, RECIP_PUB)
    assert decode_location_response(raw, RECIP_PRIV) == payload
    assert_within_size_bounds(MessageType.LOCATION_RESPONSE, raw)


def test_location_response_carries_no_history_by_construction():
    """Core-side half of retention invariant 3: the response is a single
    coordinate with scalar fields only — no timestamp array, no track log,
    and no container field a history could hide in."""
    fields = dataclasses.fields(LocationResponsePayload)
    assert {f.name for f in fields} == {
        "lat_microdeg", "lon_microdeg", "accuracy_m", "beacon_age_s", "zone_id",
    }
    assert all(f.type in (int, "int") for f in fields)
    # And the wire form is fixed-size: hint + sealed(16-byte struct).
    payload = LocationResponsePayload(0, 0, 0, 0, 0)
    assert len(encode_location_response(payload, HINT, RECIP_PUB)) == 8 + 48 + 16


def test_location_revoke_round_trip_and_size():
    payload = LocationRevokePayload(
        pubkey_id(bytes(SENDER_ED.verify_key)), b"\x22" * 8, 1_800_000_000, b"\x0c" * 8,
    )
    raw = encode_location_revoke(payload)
    assert decode_location_revoke(raw) == payload
    assert payload.revocation_key == (payload.issuer_pubkey_id, b"\x22" * 8,
                                      1_800_000_000, b"\x0c" * 8)
    assert_within_size_bounds(MessageType.LOCATION_REVOKE, raw)


def test_direct_message_round_trip_and_size():
    """Worst case: a max-length DM must still fit the 460-byte packet cap."""
    text = "m" * MAX_DM_TEXT_BYTES
    raw = encode_direct_message(text, HINT, RECIP_PUB)
    assert recipient_hint_of(raw) == HINT
    assert decode_direct_message(raw, RECIP_PRIV) == text
    assert_within_size_bounds(MessageType.DIRECT_MESSAGE, raw)


def test_direct_message_utf8_and_bounds():
    raw = encode_direct_message("café ☕", HINT, RECIP_PUB)
    assert decode_direct_message(raw, RECIP_PRIV) == "café ☕"
    with pytest.raises(ValueError):
        encode_direct_message("", HINT, RECIP_PUB)
    with pytest.raises(ValueError):
        encode_direct_message("m" * (MAX_DM_TEXT_BYTES + 1), HINT, RECIP_PUB)


def test_direct_message_unreadable_by_relays():
    """A relay/node holding the raw payload learns the hint and nothing else:
    only the recipient's X25519 key opens the body."""
    other_priv, _ = generate_encryption_keypair()
    raw = encode_direct_message("meet at gate B", HINT, RECIP_PUB)
    assert b"meet at gate B" not in raw
    with pytest.raises(ValueError):
        decode_direct_message(raw, other_priv)


def test_wrong_recipient_cannot_decode():
    other_priv, _ = generate_encryption_keypair()
    raw = encode_friend_request(
        FriendRequestPayload("ada", b"\x04" * 32, b"\x05" * 32), HINT, RECIP_PUB,
    )
    with pytest.raises(ValueError):
        decode_friend_request(raw, other_priv)


def test_oversize_username_rejected():
    with pytest.raises(ValueError):
        encode_friend_request(
            FriendRequestPayload("u" * (MAX_USERNAME_BYTES + 1), b"\x04" * 32, b"\x05" * 32),
            HINT, RECIP_PUB,
        )
