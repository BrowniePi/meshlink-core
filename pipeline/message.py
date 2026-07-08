import struct
from dataclasses import dataclass
from enum import IntEnum


class MessageType(IntEnum):
    """msg_type enum from docs/message-format.md §4.

    Values are wire constants shared with meshlink-node and the meshlink-app
    Dart port (lib/core/message_factory.dart) — never renumber existing
    entries. 0x06 was allocated node/app-side in Phase 5 for attestation
    token presentation and is recorded here so nothing else claims it.
    """

    TEXT = 0x01
    LOCATION = 0x02              # phone → node location beacon (single coordinate)
    ACK = 0x03
    ACK_SUPPRESS = 0x04
    ANNOUNCEMENT = 0x05
    ATTESTATION_PRESENT = 0x06   # payload = organiser JWT (node-terminated)
    # Friendship + node-served location (Phase 5 extension):
    FRIEND_REQUEST = 0x07        # encrypted to recipient; routed like a DM
    FRIEND_ACCEPT = 0x08         # encrypted to original requester
    FRIEND_DECLINE = 0x09        # minimal, signed; references the request msg_id
    LOCATION_QUERY = 0x0A        # requester → node; carries a capability token;
                                 # node-terminated, never relayed to the target
    LOCATION_RESPONSE = 0x0B     # node → requester; encrypted to requester
    LOCATION_REVOKE = 0x0C       # target → node/friend; signed by target
    DIRECT_MESSAGE = 0x0D        # friend → friend text, encrypted to recipient;
                                 # relayed like TEXT, unreadable to relays/nodes

# Wire format constants from docs/message-format.md
HEADER_FORMAT = ">16s32s16sIBBHBH"
HEADER_SIZE = 75      # fixed header bytes before payload
SIGNATURE_SIZE = 64   # Ed25519 signature appended after payload
MIN_PACKET = 131      # pre-parse size floor (catches truncated headers)
MAX_PACKET = 460      # pre-parse size ceiling (75 header + 321 payload + 64 sig)

# ttl (offset 68) and spray_L (offset 69) are rewritten by every relay hop
# (Technical Reference §3), so they are excluded from the Ed25519 signed
# region — a relay decrementing ttl or splitting spray_L must not invalidate
# the originating sender's signature. See DECISIONS.md.
_TTL_SPRAY_OFFSET = 68
_TTL_SPRAY_SIZE = 2


def signed_region(raw: bytes, payload_len: int) -> bytes:
    """Bytes covered by the Ed25519 signature: the full header and payload
    except the two hop-mutable bytes (ttl, spray_L)."""
    return (
        raw[:_TTL_SPRAY_OFFSET]
        + raw[_TTL_SPRAY_OFFSET + _TTL_SPRAY_SIZE : HEADER_SIZE + payload_len]
    )


@dataclass
class Message:
    raw: bytes
    msg_id: bytes       # 16 bytes — content-addressable dedup key
    sender_key: bytes   # 32 bytes — Curve25519 long-term identity
    ephem_id: bytes     # 16 bytes — rotating on-air identifier
    timestamp: int      # uint32 — Unix seconds at creation
    ttl: int            # uint8  — remaining relay hop budget
    spray_l: int        # uint8  — Spray-and-Wait copy budget
    zone_id: int        # uint16 — destination zone (0xFFFF = broadcast)
    msg_type: int       # uint8  — message type enum
    payload_len: int    # uint16 — byte length of payload field
    payload: bytes      # variable, 0–321 bytes
    signature: bytes    # 64 bytes — Ed25519 over bytes[0 : 75 + payload_len]


def parse_packet(raw: bytes) -> Message:
    """Parse raw bytes into a Message. Raises ValueError if structurally invalid."""
    if len(raw) < HEADER_SIZE + SIGNATURE_SIZE:
        raise ValueError(f"packet too short to parse: {len(raw)} bytes")

    (msg_id, sender_key, ephem_id, timestamp, ttl, spray_l,
     zone_id, msg_type, payload_len) = struct.unpack_from(HEADER_FORMAT, raw)

    expected_len = HEADER_SIZE + payload_len + SIGNATURE_SIZE
    if len(raw) != expected_len:
        raise ValueError(
            f"packet length {len(raw)} != expected {expected_len} "
            f"(payload_len={payload_len})"
        )

    payload = raw[HEADER_SIZE:HEADER_SIZE + payload_len]
    signature = raw[HEADER_SIZE + payload_len:]

    return Message(
        raw=raw,
        msg_id=msg_id,
        sender_key=sender_key,
        ephem_id=ephem_id,
        timestamp=timestamp,
        ttl=ttl,
        spray_l=spray_l,
        zone_id=zone_id,
        msg_type=msg_type,
        payload_len=payload_len,
        payload=payload,
        signature=signature,
    )
