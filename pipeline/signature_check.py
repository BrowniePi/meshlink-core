from nacl.exceptions import CryptoError
from nacl.signing import VerifyKey

from .message import Message, signed_region


def check_signature(msg: Message) -> str | None:
    """Step 6: verify the Ed25519 signature against the sender's public key.

    Verifies msg.signature over the signed region (header + payload, minus
    the hop-mutable ttl/spray_L bytes — see message.signed_region) using
    msg.sender_key (libsodium via PyNaCl). This is the most expensive
    per-packet operation (~50 µs on Pi 4, ~2–5 ms on a mid-range phone) — it
    runs last among the security checks precisely so cheap structural and
    rate-limit checks can short-circuit before it.
    """
    try:
        VerifyKey(msg.sender_key).verify(signed_region(msg.raw, msg.payload_len), msg.signature)
    except (CryptoError, ValueError):
        return "signature invalid: Ed25519 verification failed"
    return None
