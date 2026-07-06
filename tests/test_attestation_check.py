"""Step 7: attestation token validation (Phase 5).

Tokens here are minted locally with a test organiser keypair, mirroring the
compact JWT format meshlink-backend issues: EdDSA over
base64url(header).base64url(claims), sub = device sender_key hex, exp = Unix
seconds.
"""
import base64
import json
import time

import pytest

from identity import generate_keypair
from pipeline import AttestationCache, Outcome, RelayPipeline

from .helpers import TEST_IDENTITY, build_packet

ORGANISER = generate_keypair()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def mint_token(
    sender_key: bytes,
    *,
    organiser=ORGANISER,
    exp: int | None = None,
    alg: str = "EdDSA",
) -> str:
    if exp is None:
        exp = int(time.time()) + 3600
    header = _b64url(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    claims = _b64url(json.dumps({"sub": sender_key.hex(), "exp": exp}).encode())
    signed = f"{header}.{claims}"
    signature = organiser.signing_key.sign(signed.encode("ascii")).signature
    return f"{signed}.{_b64url(signature)}"


def make_cache() -> AttestationCache:
    return AttestationCache(ORGANISER.public_key)


class TestAddToken:
    def test_valid_token_accepted(self):
        cache = make_cache()
        assert cache.add_token(mint_token(TEST_IDENTITY.public_key)) == TEST_IDENTITY.public_key

    def test_wrong_signer_rejected(self):
        token = mint_token(TEST_IDENTITY.public_key, organiser=generate_keypair())
        with pytest.raises(ValueError, match="invalid attestation token"):
            make_cache().add_token(token)

    def test_expired_token_rejected(self):
        token = mint_token(TEST_IDENTITY.public_key, exp=int(time.time()) - 1)
        with pytest.raises(ValueError, match="expired"):
            make_cache().add_token(token)

    def test_wrong_alg_rejected(self):
        token = mint_token(TEST_IDENTITY.public_key, alg="none")
        with pytest.raises(ValueError, match="invalid attestation token"):
            make_cache().add_token(token)

    def test_garbage_rejected(self):
        with pytest.raises(ValueError, match="invalid attestation token"):
            make_cache().add_token("not.a.token")


class TestCheck:
    def test_attested_sender_passes(self):
        cache = make_cache()
        cache.add_token(mint_token(TEST_IDENTITY.public_key))
        assert cache.check(TEST_IDENTITY.public_key) is None

    def test_unattested_sender_dropped(self):
        reason = make_cache().check(TEST_IDENTITY.public_key)
        assert reason == "attestation failed: no valid ticket-bound identity token"


class TestPipelineIntegration:
    def test_pipeline_without_cache_stays_open(self):
        result = RelayPipeline().process(build_packet())
        assert result.outcome == Outcome.DELIVER

    def test_pipeline_drops_unattested_sender(self):
        result = RelayPipeline(attestation=make_cache()).process(build_packet())
        assert result.outcome == Outcome.DROP
        assert "attestation failed" in result.drop_reason

    def test_pipeline_accepts_attested_sender(self):
        cache = make_cache()
        cache.add_token(mint_token(TEST_IDENTITY.public_key))
        result = RelayPipeline(attestation=cache).process(build_packet())
        assert result.outcome == Outcome.DELIVER
