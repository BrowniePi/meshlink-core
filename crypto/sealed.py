"""Anonymous sealed envelopes to a Curve25519 (X25519) public key.

Used for payloads that must be readable only by one recipient — friend
requests/accepts and the node → requester LOCATION_RESPONSE (security
invariant 4: a passive backhaul sniffer harvests nothing). The construction
mirrors libsodium's crypto_box_seal but swaps XSalsa20 for the IETF
ChaCha20-Poly1305 AEAD so the meshlink-app Dart port (package:cryptography,
which has no XSalsa20) can produce byte-identical envelopes:

    ephemeral X25519 keypair (fresh per message)
    shared  = X25519(ephemeral_priv, recipient_pub)
    key     = BLAKE3(shared ‖ ephemeral_pub ‖ recipient_pub)[0:32]
    nonce   = 12 zero bytes  (safe: the key is unique per message because the
                              ephemeral keypair is never reused)
    wire    = ephemeral_pub(32) ‖ AEAD_ciphertext(plaintext ‖ tag(16))

Overhead is exactly SEAL_OVERHEAD = 48 bytes. The sender is anonymous at
this layer — authentication comes from the Ed25519 envelope signature on the
enclosing MeshLink packet (pipeline step 6), never re-implemented here.
"""
import blake3
from nacl.bindings import (
    crypto_aead_chacha20poly1305_ietf_decrypt,
    crypto_aead_chacha20poly1305_ietf_encrypt,
    crypto_scalarmult,
    crypto_scalarmult_base,
)
from nacl.utils import random as nacl_random

_EPHEMERAL_PUB_SIZE = 32
_TAG_SIZE = 16
_NONCE = b"\x00" * 12

SEAL_OVERHEAD = _EPHEMERAL_PUB_SIZE + _TAG_SIZE  # 48 bytes


def generate_encryption_keypair() -> tuple[bytes, bytes]:
    """Fresh X25519 keypair: (private, public). This is the account's
    long-term *encryption* identity, registered alongside the Ed25519 signing
    key at POST /account — kept distinct because the app's pure-Dart crypto
    cannot do libsodium's Ed25519→Curve25519 birational conversion."""
    priv = nacl_random(32)
    return priv, crypto_scalarmult_base(priv)


def _derive_key(shared: bytes, ephemeral_pub: bytes, recipient_pub: bytes) -> bytes:
    return blake3.blake3(shared + ephemeral_pub + recipient_pub).digest()[:32]


def seal(plaintext: bytes, recipient_curve25519_pub: bytes) -> bytes:
    """Encrypt plaintext so only the holder of the recipient's X25519 private
    key can read it. Fresh ephemeral keypair per call — never deterministic."""
    if len(recipient_curve25519_pub) != 32:
        raise ValueError("recipient public key must be 32 bytes")
    ephemeral_priv = nacl_random(32)
    ephemeral_pub = crypto_scalarmult_base(ephemeral_priv)
    shared = crypto_scalarmult(ephemeral_priv, recipient_curve25519_pub)
    key = _derive_key(shared, ephemeral_pub, recipient_curve25519_pub)
    ciphertext = crypto_aead_chacha20poly1305_ietf_encrypt(plaintext, b"", _NONCE, key)
    return ephemeral_pub + ciphertext


def unseal(sealed: bytes, recipient_curve25519_priv: bytes) -> bytes:
    """Decrypt a sealed envelope. Raises ValueError on any tampering or a
    wrong key — callers treat that as a silent drop, never an oracle."""
    if len(sealed) < SEAL_OVERHEAD:
        raise ValueError("sealed envelope too short")
    ephemeral_pub = sealed[:_EPHEMERAL_PUB_SIZE]
    ciphertext = sealed[_EPHEMERAL_PUB_SIZE:]
    recipient_pub = crypto_scalarmult_base(recipient_curve25519_priv)
    shared = crypto_scalarmult(recipient_curve25519_priv, ephemeral_pub)
    key = _derive_key(shared, ephemeral_pub, recipient_pub)
    try:
        return crypto_aead_chacha20poly1305_ietf_decrypt(ciphertext, b"", _NONCE, key)
    except Exception as exc:  # nacl.exceptions.CryptoError
        raise ValueError("sealed envelope failed to open") from exc
