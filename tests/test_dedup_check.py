import struct

from pipeline.dedup_check import CAPACITY, REBUILD_EVICTION_THRESHOLD, TTL_SECONDS, DedupCache
from pipeline.message import parse_packet
from tests.helpers import build_packet


class FakeClock:
    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now


def _msg(n: int):
    return parse_packet(build_packet(msg_id=struct.pack(">Q", n) * 2))


def test_first_message_passes():
    cache = DedupCache()
    msg = parse_packet(build_packet())
    assert cache.check(msg) is None


def test_duplicate_drops():
    cache = DedupCache()
    raw = build_packet()
    msg = parse_packet(raw)
    cache.check(msg)
    assert cache.check(msg) is not None


def test_different_msg_ids_both_pass():
    cache = DedupCache()
    msg1 = parse_packet(build_packet(msg_id=b"\x01" * 16))
    msg2 = parse_packet(build_packet(msg_id=b"\x02" * 16))
    assert cache.check(msg1) is None
    assert cache.check(msg2) is None


def test_drop_reason_mentions_duplicate():
    cache = DedupCache()
    msg = parse_packet(build_packet())
    cache.check(msg)
    reason = cache.check(msg)
    assert reason is not None
    assert "duplicate" in reason.lower()


def test_lru_evicts_past_capacity_and_bloom_rebuild_forgets_old_entries():
    clock = FakeClock()
    cache = DedupCache(clock=clock)
    cache.check(_msg(0))
    # Push msg 0 out of the LRU and past the rebuild threshold. A ~1% Bloom
    # false-positive rate means some unique inserts report "duplicate" — that
    # is spec'd behaviour, so results are not asserted per message here.
    # 2x the threshold in extra inserts guarantees >= one rebuild even though
    # ~1% of unique inserts are FP-dropped and never reach the LRU.
    total = CAPACITY + 2 * REBUILD_EVICTION_THRESHOLD
    passed = sum(cache.check(_msg(n)) is None for n in range(1, 1 + total))
    assert passed >= total * 0.95
    assert len(cache._lru) <= CAPACITY
    # A rebuild happened: total evictions exceeded the threshold but the
    # counter was reset below it.
    total_evictions = (passed + 1) - len(cache._lru)
    assert total_evictions > REBUILD_EVICTION_THRESHOLD
    assert cache._evictions_since_rebuild < REBUILD_EVICTION_THRESHOLD
    # After the rebuild, msg 0 is no longer remembered and passes again.
    assert cache.check(_msg(0)) is None


def test_entries_expire_after_ttl_once_rebuilt():
    clock = FakeClock()
    cache = DedupCache(clock=clock)
    old_ids = list(range(REBUILD_EVICTION_THRESHOLD))
    for n in old_ids:
        cache.check(_msg(n))
    # Within the TTL they are duplicates.
    assert cache.check(_msg(old_ids[0])) is not None
    # Past the TTL, one new insert evicts all expired entries and triggers a
    # rebuild, so the old ids pass again.
    clock.now += TTL_SECONDS + 1
    assert cache.check(_msg(10_000_000)) is None
    assert cache.check(_msg(old_ids[0])) is None


def test_entry_exactly_at_ttl_boundary_is_still_a_duplicate():
    clock = FakeClock()
    cache = DedupCache(clock=clock)
    cache.check(_msg(1))
    clock.now += TTL_SECONDS  # exactly at the boundary — not yet expired
    assert cache.check(_msg(1)) is not None
