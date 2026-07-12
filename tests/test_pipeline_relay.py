"""Step 8 relay: the pipeline computes the onward Spray-and-Wait copy.

An accepted packet is delivered locally AND (budget permitting) yields a
`forward` packet with ttl-1 and spray_L binary-split to the peer's share.
The two rewritten bytes sit outside the signed region, so the onward copy
still carries a valid origin signature — asserted by re-processing it
through a second pipeline instance.
"""
import time

from pipeline.pipeline import RelayPipeline, Outcome
from pipeline.message import parse_packet
from tests.helpers import build_packet


def test_accepted_packet_yields_forward_copy():
    pipeline = RelayPipeline()
    result = pipeline.process(build_packet(ttl=5, spray_l=8))
    assert result.outcome == Outcome.DELIVER
    forwarded = parse_packet(result.forward)
    assert forwarded.ttl == 4
    assert forwarded.spray_l == 4  # peer gets floor(8/2)


def test_odd_spray_l_peer_gets_floor_half():
    pipeline = RelayPipeline()
    result = pipeline.process(build_packet(spray_l=5))
    assert parse_packet(result.forward).spray_l == 2


def test_forward_copy_signature_still_valid():
    # The onward copy must pass a fresh pipeline (fresh dedup) end-to-end:
    # rewriting ttl/spray_L is signature-safe by construction.
    first_hop = RelayPipeline()
    second_hop = RelayPipeline()
    result = first_hop.process(build_packet(ttl=5, spray_l=8))
    relayed = second_hop.process(result.forward)
    assert relayed.outcome == Outcome.DELIVER


def test_wait_phase_spray_l_one_stops_forwarding():
    pipeline = RelayPipeline()
    result = pipeline.process(build_packet(spray_l=1))
    assert result.outcome == Outcome.DELIVER  # still delivered locally
    assert result.forward is None


def test_ttl_one_stops_forwarding():
    # ttl=1 is processable here but the onward copy would arrive dead.
    pipeline = RelayPipeline()
    result = pipeline.process(build_packet(ttl=1, spray_l=8))
    assert result.outcome == Outcome.DELIVER
    assert result.forward is None


def test_payload_and_header_otherwise_untouched():
    pipeline = RelayPipeline()
    raw = build_packet(ttl=5, spray_l=8, zone_id=7, payload=b"onward")
    result = pipeline.process(raw)
    original = parse_packet(raw)
    forwarded = parse_packet(result.forward)
    assert forwarded.msg_id == original.msg_id
    assert forwarded.zone_id == 7
    assert forwarded.payload == b"onward"
    assert forwarded.signature == original.signature


def test_inflated_spray_l_resend_is_dropped():
    # Same msg_id re-presented with a higher L than first observed must be
    # rejected even if the dedup cache no longer remembers it. Simulate the
    # eviction by clearing dedup state between sightings.
    pipeline = RelayPipeline()
    low = build_packet(spray_l=2, timestamp=int(time.time()))
    high = low[:69] + bytes([16]) + low[70:]  # inflate spray_L in place
    assert pipeline.process(low).outcome == Outcome.DELIVER
    pipeline._dedup = type(pipeline._dedup)()
    result = pipeline.process(high)
    assert result.outcome == Outcome.DROP
    assert "inflated" in result.drop_reason.lower()
