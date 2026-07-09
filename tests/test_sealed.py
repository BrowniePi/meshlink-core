"""Sealed envelope (crypto/sealed.py): round-trip, tamper and wrong-key
rejection, and the exact 48-byte overhead the size budgets depend on."""
import pytest

from crypto.sealed import SEAL_OVERHEAD, generate_encryption_keypair, seal, unseal


def test_round_trip():
    priv, pub = generate_encryption_keypair()
    plaintext = b"meet me at the south gate"
    sealed = seal(plaintext, pub)
    assert unseal(sealed, priv) == plaintext


def test_overhead_is_exactly_48_bytes():
    _, pub = generate_encryption_keypair()
    for size in (0, 1, 16, 321 - SEAL_OVERHEAD):
        assert len(seal(b"\x00" * size, pub)) == size + SEAL_OVERHEAD
    assert SEAL_OVERHEAD == 48


def test_fresh_ephemeral_per_call():
    _, pub = generate_encryption_keypair()
    assert seal(b"same", pub) != seal(b"same", pub)


def test_wrong_key_fails():
    _, pub = generate_encryption_keypair()
    other_priv, _ = generate_encryption_keypair()
    with pytest.raises(ValueError):
        unseal(seal(b"secret", pub), other_priv)


def test_tampered_ciphertext_fails():
    priv, pub = generate_encryption_keypair()
    sealed = bytearray(seal(b"secret", pub))
    sealed[-1] ^= 0x01
    with pytest.raises(ValueError):
        unseal(bytes(sealed), priv)


def test_tampered_ephemeral_pub_fails():
    priv, pub = generate_encryption_keypair()
    sealed = bytearray(seal(b"secret", pub))
    sealed[0] ^= 0x01
    with pytest.raises(ValueError):
        unseal(bytes(sealed), priv)


def test_too_short_fails():
    priv, _ = generate_encryption_keypair()
    with pytest.raises(ValueError):
        unseal(b"\x00" * (SEAL_OVERHEAD - 1), priv)
