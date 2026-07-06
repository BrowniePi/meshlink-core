"""Regression guard for relay pipeline check ordering (Technical Reference).

Spies on each check function to confirm the orchestrator calls them in the
documented order and never lets a later check run once an earlier one drops
the message.
"""
from pipeline import pipeline as pipeline_module
from pipeline.pipeline import RelayPipeline, Outcome
from tests.helpers import TEST_IDENTITY, build_packet
from tests.test_attestation_check import make_cache, mint_token


def _spy(monkeypatch, name, call_order):
    original = getattr(pipeline_module, name)

    def wrapper(*args, **kwargs):
        call_order.append(name)
        return original(*args, **kwargs)

    monkeypatch.setattr(pipeline_module, name, wrapper)


def _spy_method(monkeypatch, obj, label, call_order):
    original = obj.check

    def wrapper(*args, **kwargs):
        call_order.append(label)
        return original(*args, **kwargs)

    monkeypatch.setattr(obj, "check", wrapper)


def test_checks_run_in_documented_order(monkeypatch):
    call_order = []
    for name in ("check_size", "check_ttl", "check_timestamp", "check_signature"):
        _spy(monkeypatch, name, call_order)

    attestation = make_cache()
    attestation.add_token(mint_token(TEST_IDENTITY.public_key))
    pipeline = RelayPipeline(attestation=attestation)
    _spy_method(monkeypatch, pipeline._dedup, "check_dedup", call_order)
    _spy_method(monkeypatch, pipeline._rate_limiter, "check_rate_limit", call_order)
    _spy_method(monkeypatch, pipeline._attestation, "check_attestation", call_order)

    result = pipeline.process(build_packet())

    assert result.outcome == Outcome.DELIVER
    assert call_order == [
        "check_size",
        "check_ttl",
        "check_timestamp",
        "check_dedup",
        "check_rate_limit",
        "check_signature",
        "check_attestation",
    ]


def test_failing_size_check_short_circuits_ttl(monkeypatch):
    call_order = []
    _spy(monkeypatch, "check_ttl", call_order)

    pipeline = RelayPipeline()
    result = pipeline.process(build_packet(force_length=10))

    assert result.outcome == Outcome.DROP
    assert call_order == []


def test_failing_ttl_check_short_circuits_timestamp(monkeypatch):
    call_order = []
    _spy(monkeypatch, "check_timestamp", call_order)

    pipeline = RelayPipeline()
    result = pipeline.process(build_packet(ttl=0))

    assert result.outcome == Outcome.DROP
    assert call_order == []


def test_failing_dedup_check_short_circuits_rate_limit(monkeypatch):
    call_order = []

    pipeline = RelayPipeline()
    _spy_method(monkeypatch, pipeline._rate_limiter, "check_rate_limit", call_order)

    raw = build_packet()
    pipeline.process(raw)  # warm up dedup cache
    call_order.clear()
    result = pipeline.process(raw)

    assert result.outcome == Outcome.DROP
    assert call_order == []
