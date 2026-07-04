"""Tests for identity/keygen.py (Phase 4 keypair generation)."""
from identity import generate_keypair, load_or_create_identity


def test_generated_keys_have_correct_length_and_format():
    identity = generate_keypair()
    assert len(identity.public_key) == 32
    assert len(identity.private_seed) == 32
    assert isinstance(identity.public_key, bytes)
    assert isinstance(identity.private_seed, bytes)


def test_generated_key_is_valid_curve25519_key():
    # The Ed25519 public key must convert cleanly to its Curve25519 (X25519)
    # equivalent — this is what future DM encryption (Noise_XX) will use.
    identity = generate_keypair()
    curve_pk = identity.signing_key.verify_key.to_curve25519_public_key()
    assert len(bytes(curve_pk)) == 32


def test_generated_key_signs_and_verifies():
    identity = generate_keypair()
    signed = identity.signing_key.sign(b"probe")
    assert identity.signing_key.verify_key.verify(signed) == b"probe"


def test_two_generations_produce_different_keypairs():
    a, b = generate_keypair(), generate_keypair()
    assert a.public_key != b.public_key
    assert a.private_seed != b.private_seed


def test_load_or_create_generates_exactly_once(tmp_path):
    store = tmp_path / "identity.json"
    first = load_or_create_identity(store)
    assert store.exists()
    second = load_or_create_identity(store)
    assert first.public_key == second.public_key
    assert first.private_seed == second.private_seed
