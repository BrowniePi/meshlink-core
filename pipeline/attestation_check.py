"""Step 7: ticket-bound attestation token validation (Phase 5).

meshlink-backend issues each ticket holder a compact JWT signed with the
organiser's Ed25519 key (alg EdDSA): claims `sub` (device sender_key, hex),
`eid` (event ID) and `exp` (Unix seconds). meshlink-core only *validates* — issuance lives in
meshlink-backend. Tokens reach the node out of band (gossip/provisioning, an
app-side concern) and are added to this local cache; the per-packet check is
then a dict lookup, keeping step 7 cheap. A Sybil attacker must buy one
ticket per identity.
"""
import base64
import json
import time

from nacl.exceptions import CryptoError
from nacl.signing import VerifyKey


def _b64url_decode(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


class AttestationCache:
    """Node-local cache of validated attestation tokens, keyed by sender_key.

    `organiser_key` (the organiser's 32-byte Ed25519 public key) and
    `event_id` are provisioned to the node at event setup; tokens minted for
    a different event are rejected.
    """

    def __init__(self, organiser_key: bytes, event_id: str) -> None:
        self._verify_key = VerifyKey(organiser_key)
        self._event_id = event_id
        self._expiry: dict[bytes, int] = {}  # sender_key -> exp (Unix seconds)

    def add_token(self, token: str) -> bytes:
        """Validate a token and cache its sender_key. Returns the sender_key.

        Raises ValueError if the token is malformed, not signed by the
        organiser key, for a different event, or already expired.
        """
        try:
            header_b64, payload_b64, sig_b64 = token.split(".")
            signed = f"{header_b64}.{payload_b64}".encode("ascii")
            self._verify_key.verify(signed, _b64url_decode(sig_b64))
            header = json.loads(_b64url_decode(header_b64))
            claims = json.loads(_b64url_decode(payload_b64))
            if header.get("alg") != "EdDSA":
                raise ValueError(f"unsupported alg: {header.get('alg')}")
            sender_key = bytes.fromhex(claims["sub"])
            event_id = claims["eid"]
            exp = int(claims["exp"])
        except (CryptoError, ValueError, KeyError, TypeError) as exc:
            raise ValueError(f"invalid attestation token: {exc}") from exc
        if len(sender_key) != 32:
            raise ValueError("invalid attestation token: sub is not a 32-byte key")
        if event_id != self._event_id:
            raise ValueError(f"invalid attestation token: wrong event ({event_id!r})")
        if exp <= int(time.time()):
            raise ValueError("invalid attestation token: expired")
        self._expiry[sender_key] = exp
        return sender_key

    def check(self, sender_key: bytes) -> str | None:
        """Step 7: drop unless sender_key holds an unexpired cached token."""
        exp = self._expiry.get(sender_key)
        if exp is None:
            return "attestation failed: no valid ticket-bound identity token"
        if exp <= int(time.time()):
            del self._expiry[sender_key]
            return "attestation failed: token expired"
        return None
