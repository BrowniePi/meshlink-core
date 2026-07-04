"""Minimal packet builder for the simulation harness.

Kept separate from tests/helpers.py so production-adjacent sim/ code doesn't
depend on the tests/ package.
"""
import struct

from identity import DeviceIdentity
from pipeline.message import HEADER_FORMAT, signed_region


def build_packet(
    *,
    identity: DeviceIdentity,
    msg_id: bytes,
    ephem_id: bytes,
    timestamp: int,
    ttl: int,
    spray_l: int,
    zone_id: int,
    msg_type: int,
    payload: bytes,
) -> bytes:
    """Serialize and sign a well-formed packet with the originating device's
    real Ed25519 identity. ttl/spray_l are excluded from the signed region
    (see pipeline.message.signed_region), so a relay re-serializing this
    packet with a decremented ttl or reduced spray_l — but an unchanged
    signature — still verifies at the next hop."""
    header = struct.pack(
        HEADER_FORMAT,
        msg_id, identity.public_key, ephem_id,
        timestamp, ttl, spray_l, zone_id, msg_type, len(payload),
    )
    unsigned_packet = header + payload
    signature = identity.signing_key.sign(
        signed_region(unsigned_packet, len(payload))
    ).signature
    return unsigned_packet + signature


def rewrite_ttl_and_spray(raw: bytes, *, ttl: int, spray_l: int) -> bytes:
    """Overwrite a relayed packet's hop-mutable ttl (offset 68) and spray_L
    (offset 69) bytes in place. Safe without re-signing because those two
    bytes are excluded from the Ed25519 signed region — the rest of the
    packet, including the original signature, is untouched."""
    patched = bytearray(raw)
    patched[68] = ttl
    patched[69] = spray_l
    return bytes(patched)
