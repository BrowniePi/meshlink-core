from nacl.exceptions import CryptoError
from nacl.signing import VerifyKey

from .message import HEADER_SIZE, Message


def check_signature(msg: Message) -> str | None:
    """Step 6: verify the Ed25519 signature against the sender's public key.

    Verifies msg.signature over the signed region raw[0 : 75 + payload_len]
    using msg.sender_key (libsodium via PyNaCl). This is the most expensive
    per-packet operation (~50 µs on Pi 4, ~2–5 ms on a mid-range phone) — it
    runs last among the security checks precisely so cheap structural and
    rate-limit checks can short-circuit before it.
    """
    signed_region = msg.raw[: HEADER_SIZE + msg.payload_len]
    try:
        VerifyKey(msg.sender_key).verify(signed_region, msg.signature)
    except (CryptoError, ValueError):
        return "signature invalid: Ed25519 verification failed"
    return None
