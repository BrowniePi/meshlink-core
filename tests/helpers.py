"""Test helpers for constructing well-formed MeshLink packets.

Packets are signed with TEST_IDENTITY (a keypair generated fresh at import —
never hardcoded) so they pass the real Ed25519 signature check by default.
Pass an explicit `signature` or a mismatched `sender_key` to build invalid
packets.
"""
import struct
import time

from identity import generate_keypair

_HEADER_FORMAT = ">16s32s16sIBBHBH"

TEST_IDENTITY = generate_keypair()

DEFAULT_MSG_ID = b"\x00" * 16
DEFAULT_SENDER_KEY = TEST_IDENTITY.public_key
DEFAULT_EPHEM_ID = b"\x02" * 16
DEFAULT_PAYLOAD = b"hello"


def build_packet(
    *,
    msg_id: bytes = DEFAULT_MSG_ID,
    sender_key: bytes | None = None,
    ephem_id: bytes = DEFAULT_EPHEM_ID,
    timestamp: int | None = None,
    ttl: int = 5,
    spray_l: int = 8,
    zone_id: int = 3,
    msg_type: int = 1,
    payload: bytes = DEFAULT_PAYLOAD,
    signature: bytes | None = None,
    force_length: int | None = None,
) -> bytes:
    """Build a valid, signed packet. Use force_length to test size checks."""
    if timestamp is None:
        timestamp = int(time.time())
    if sender_key is None:
        sender_key = TEST_IDENTITY.public_key

    header = struct.pack(
        _HEADER_FORMAT,
        msg_id, sender_key, ephem_id,
        timestamp, ttl, spray_l, zone_id, msg_type, len(payload),
    )
    if signature is None:
        signature = TEST_IDENTITY.signing_key.sign(header + payload).signature
    packet = header + payload + signature

    if force_length is not None:
        if force_length < len(packet):
            packet = packet[:force_length]
        else:
            packet = packet + b"\x00" * (force_length - len(packet))

    return packet
