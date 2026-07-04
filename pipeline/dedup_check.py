import time
from collections import OrderedDict
from typing import Callable

from pybloom_live import BloomFilter

from .message import Message

# Technical Reference §2: Bloom filter ~1% FPR, LRU capacity 10,000, TTL 10 min.
CAPACITY = 10_000
TTL_SECONDS = 600
FALSE_POSITIVE_RATE = 0.01
# Bloom filters cannot delete, so the filter is rebuilt from the live LRU
# entries once this many evictions accumulate. See DECISIONS.md.
REBUILD_EVICTION_THRESHOLD = 1_000


class DedupCache:
    """Step 4: drop messages whose msg_id has already been seen.

    The Bloom filter (pybloom-live) is the primary membership store — a ~1%
    false positive drops a valid message once, acceptable given Spray-and-Wait
    redundancy. The LRU cache (capacity 10,000, TTL 10 min) is the eviction
    layer: it tracks exactly which msg_ids are live so the Bloom filter can be
    rebuilt without the evicted ones.
    """

    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._lru: "OrderedDict[bytes, float]" = OrderedDict()  # msg_id -> seen_at
        self._bloom = self._new_bloom()
        self._evictions_since_rebuild = 0

    @staticmethod
    def _new_bloom() -> BloomFilter:
        # Headroom above CAPACITY: entries evicted from the LRU linger in the
        # filter until the next rebuild and must not overflow it. 2x the
        # rebuild threshold so the count never touches the filter's hard
        # capacity between rebuilds.
        return BloomFilter(
            capacity=CAPACITY + 2 * REBUILD_EVICTION_THRESHOLD,
            error_rate=FALSE_POSITIVE_RATE,
        )

    def check(self, msg: Message) -> str | None:
        if msg.msg_id in self._bloom:
            return "duplicate: msg_id already seen"
        now = self._clock()
        self._bloom.add(msg.msg_id)
        self._lru[msg.msg_id] = now
        self._evict(now)
        return None

    def _evict(self, now: float) -> None:
        while self._lru:
            oldest_id, seen_at = next(iter(self._lru.items()))
            if len(self._lru) > CAPACITY or now - seen_at > TTL_SECONDS:
                del self._lru[oldest_id]
                self._evictions_since_rebuild += 1
            else:
                break
        if self._evictions_since_rebuild >= REBUILD_EVICTION_THRESHOLD:
            self._bloom = self._new_bloom()
            for msg_id in self._lru:
                self._bloom.add(msg_id)
            self._evictions_since_rebuild = 0
