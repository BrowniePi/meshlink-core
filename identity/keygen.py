"""Long-term device identity keypair, generated once on first install.

Uses PyNaCl (libsodium bindings) — vetted crypto, never hand-rolled. The
keypair is generated as Ed25519 (libsodium crypto_sign): the public half is
the 32-byte `sender_key` in the message envelope and is birationally
equivalent to a Curve25519 key (libsodium crypto_sign_ed25519_pk_to_curve25519
converts it for X25519 DH when DM encryption arrives). See DECISIONS.md.

Storage here is a PLACEHOLDER: a plaintext JSON file with 0600 permissions.
Secure storage (iOS Keychain / Android Keystore) is wired on the app side in a
separate Phase 4 task; meshlink-core only defines the identity logic.
"""
import json
import os
from dataclasses import dataclass
from pathlib import Path

from nacl.signing import SigningKey


@dataclass(frozen=True)
class DeviceIdentity:
    """A device's long-term keypair. `public_key` is the wire `sender_key`."""

    signing_key: SigningKey

    @property
    def public_key(self) -> bytes:
        return bytes(self.signing_key.verify_key)

    @property
    def private_seed(self) -> bytes:
        return bytes(self.signing_key)


def generate_keypair() -> DeviceIdentity:
    """Generate a fresh Ed25519 keypair from the OS CSPRNG."""
    return DeviceIdentity(signing_key=SigningKey.generate())


def load_or_create_identity(path: str | Path) -> DeviceIdentity:
    """Return the device identity, generating and persisting it exactly once.

    First call on a device creates `path`; every later call loads the same
    keypair from it. `path` is the placeholder insecure store described in the
    module docstring.
    """
    path = Path(path)
    if path.exists():
        data = json.loads(path.read_text())
        return DeviceIdentity(signing_key=SigningKey(bytes.fromhex(data["private_seed"])))

    identity = generate_keypair()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(
            {
                "private_seed": identity.private_seed.hex(),
                "public_key": identity.public_key.hex(),
            },
            f,
        )
    return identity
