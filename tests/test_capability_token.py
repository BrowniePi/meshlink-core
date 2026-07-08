"""Capability token: round-trip, every rejection path, and the invariant that
possession of a valid token is the ONLY thing that grants access (invariant 1
— the node enforces consent, it never authors it; there is no code path that
verifies without the target's signature)."""
import pytest
from nacl.signing import SigningKey

from capability.token import (
    SCOPE_LOCATION,
    TOKEN_SIZE,
    issue,
    parse,
    pubkey_id,
    revocation_key,
    verify,
)

TARGET = SigningKey.generate()          # the person whose location is shared
GRANTEE = SigningKey.generate()         # the friend allowed to query it
TARGET_PUB = bytes(TARGET.verify_key)
GRANTEE_PUB = bytes(GRANTEE.verify_key)

NOW = 1_800_000_000


def make_token(**kwargs):
    defaults = dict(issued_at=NOW - 60, expiry_s=24 * 3600)
    defaults.update(kwargs)
    return issue(TARGET, GRANTEE_PUB, **defaults)


def test_round_trip_verifies():
    token = make_token()
    assert len(token) == TOKEN_SIZE == 98
    assert verify(token, TARGET_PUB, GRANTEE_PUB, NOW)


def test_parse_fields():
    token = parse(make_token(nonce=b"\x07" * 8))
    assert token.issuer_pubkey_id == pubkey_id(TARGET_PUB)
    assert token.grantee_pubkey_id == pubkey_id(GRANTEE_PUB)
    assert token.issued_at == NOW - 60
    assert token.expires_at == NOW - 60 + 24 * 3600
    assert token.scope == SCOPE_LOCATION
    assert token.nonce == b"\x07" * 8


@pytest.mark.parametrize("offset", range(0, 34))
def test_any_tampered_body_byte_fails(offset):
    token = bytearray(make_token())
    token[offset] ^= 0x01
    assert not verify(bytes(token), TARGET_PUB, GRANTEE_PUB, NOW)


def test_tampered_signature_fails():
    token = bytearray(make_token())
    token[-1] ^= 0x01
    assert not verify(bytes(token), TARGET_PUB, GRANTEE_PUB, NOW)


def test_expired_fails():
    token = make_token(issued_at=NOW - 7200, expiry_s=3600)
    assert not verify(token, TARGET_PUB, GRANTEE_PUB, NOW)
    # boundary: expires_at itself is already invalid (half-open window)
    token = make_token(issued_at=NOW - 3600, expiry_s=3600)
    assert not verify(token, TARGET_PUB, GRANTEE_PUB, NOW)


def test_not_yet_valid_fails():
    token = make_token(issued_at=NOW + 60)
    assert not verify(token, TARGET_PUB, GRANTEE_PUB, NOW)


def test_wrong_grantee_fails():
    stranger = SigningKey.generate()
    token = make_token()
    assert not verify(token, TARGET_PUB, bytes(stranger.verify_key), NOW)


def test_wrong_scope_bit_fails():
    token = make_token(scope=0x02)  # some future scope, not LOCATION
    assert not verify(token, TARGET_PUB, GRANTEE_PUB, NOW, scope=SCOPE_LOCATION)


def test_token_signed_by_non_target_fails():
    """The heart of invariant 1: a token signed by anyone but the target —
    including a node's own key — is not consent."""
    impostor = SigningKey.generate()  # e.g. a compromised node's key
    forged = issue(impostor, GRANTEE_PUB, issued_at=NOW - 60)
    assert not verify(forged, TARGET_PUB, GRANTEE_PUB, NOW)


def test_wrong_target_lookup_fails():
    """A valid token for target A must not unlock target B."""
    other_target = SigningKey.generate()
    token = make_token()
    assert not verify(token, bytes(other_target.verify_key), GRANTEE_PUB, NOW)


def test_truncated_or_padded_fails():
    token = make_token()
    assert not verify(token[:-1], TARGET_PUB, GRANTEE_PUB, NOW)
    assert not verify(token + b"\x00", TARGET_PUB, GRANTEE_PUB, NOW)


def test_revocation_key_is_stable_and_specific():
    token_bytes = make_token(nonce=b"\x0a" * 8)
    key = revocation_key(parse(token_bytes))
    assert key == (pubkey_id(TARGET_PUB), pubkey_id(GRANTEE_PUB), NOW - 60, b"\x0a" * 8)
    # a re-issued token (fresh nonce) has a different revocation key, so
    # revoking an old grant does not kill a deliberately re-issued one
    other = revocation_key(parse(make_token(nonce=b"\x0b" * 8)))
    assert key != other
