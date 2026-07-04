"""Tests for real Ed25519 signature verification (pipeline step 6)."""
from identity import build_signed_packet, generate_keypair
from pipeline.message import parse_packet
from pipeline.signature_check import check_signature
from tests.helpers import TEST_IDENTITY, build_packet


def test_validly_signed_message_passes():
    msg = parse_packet(build_packet())
    assert check_signature(msg) is None


def test_signing_module_output_passes():
    identity = generate_keypair()
    raw = build_signed_packet(
        identity,
        ephem_id=b"\x07" * 16,
        ttl=5,
        spray_l=8,
        zone_id=3,
        msg_type=1,
        payload=b"signed by the real thing",
    )
    msg = parse_packet(raw)
    assert msg.sender_key == identity.public_key
    assert check_signature(msg) is None


def test_forged_signature_rejected():
    msg = parse_packet(build_packet(signature=b"\x99" * 64))
    reason = check_signature(msg)
    assert reason is not None
    assert "signature" in reason.lower()


def test_corrupted_payload_rejected():
    raw = bytearray(build_packet(payload=b"original payload"))
    raw[80] ^= 0xFF  # flip a payload byte after signing
    msg = parse_packet(bytes(raw))
    assert check_signature(msg) is not None


def test_message_signed_by_different_keypair_than_claimed_rejected():
    # Signature is made by TEST_IDENTITY but the packet claims another sender.
    imposter_claim = generate_keypair().public_key
    msg = parse_packet(build_packet(sender_key=imposter_claim))
    assert check_signature(msg) is not None


def test_corrupted_header_field_rejected():
    raw = bytearray(build_packet())
    raw[70] ^= 0x01  # tamper with zone_id, inside the signed region
    msg = parse_packet(bytes(raw))
    assert check_signature(msg) is not None
