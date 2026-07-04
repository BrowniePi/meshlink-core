"""Outgoing-message construction and Ed25519 signing (Phase 4).

Every outgoing message is signed with the device's long-term private key
before transmission. Per docs/message-format.md the signature covers the
signed region bytes[0 : 75 + payload_len] — every field except the signature
itself (which includes msg_id and payload). msg_id is content-addressable:
BLAKE3(sender_key ‖ timestamp_be4 ‖ msg_type_byte ‖ payload)[0:16].
"""
import struct
import time

import blake3

from pipeline.message import HEADER_FORMAT
from .keygen import DeviceIdentity


def compute_msg_id(sender_key: bytes, timestamp: int, msg_type: int, payload: bytes) -> bytes:
    material = sender_key + struct.pack(">I", timestamp) + struct.pack(">B", msg_type) + payload
    return blake3.blake3(material).digest()[:16]


def build_signed_packet(
    identity: DeviceIdentity,
    *,
    ephem_id: bytes,
    ttl: int,
    spray_l: int,
    zone_id: int,
    msg_type: int,
    payload: bytes,
    timestamp: int | None = None,
) -> bytes:
    """Build a complete wire packet: header + payload + Ed25519 signature."""
    if timestamp is None:
        timestamp = int(time.time())

    sender_key = identity.public_key
    msg_id = compute_msg_id(sender_key, timestamp, msg_type, payload)
    header = struct.pack(
        HEADER_FORMAT,
        msg_id, sender_key, ephem_id,
        timestamp, ttl, spray_l, zone_id, msg_type, len(payload),
    )
    signed_region = header + payload
    signature = identity.signing_key.sign(signed_region).signature
    return signed_region + signature
