# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for shared duration-stable generation indexes."""

from datetime import UTC, datetime, timedelta
from time import perf_counter

import pytest

import evidenceforge.generation.indexes as indexes_module
from evidenceforge.generation.indexes import (
    CompactHandleStore,
    CompactIndexedStore,
    ExpiringIndex,
    GroupedTemporalIndex,
    IncrementalExactMap,
    IndexedEntityStore,
    PackedByteRowStore,
    PackedHandleExpiryIndex,
    PackedUniqueDigestMap,
    ReferenceLeaseIndex,
    SegmentedTemporalIndex,
    ShardedExpiringIndex,
    TemporalAllocationIndex,
)


def test_packed_byte_row_store_reuses_handles_and_releases_empty_arenas() -> None:
    """Inline and overflow rows remain exact while empty stores drop peak backing."""

    rows = PackedByteRowStore(inline_slot_bytes=8, chunk_slots=2)
    inline = rows.insert(b"small")
    overflow = rows.insert(b"this row exceeds the inline slot")

    assert bytes(rows.get_by_handle(inline)) == b"small"
    assert bytes(rows.get_by_handle(overflow)) == b"this row exceeds the inline slot"
    before = rows.metrics(estimate_bytes=True)
    before_values = rows.estimated_value_bytes
    assert before.live_entries == 2
    assert before.allocated_slots == 2
    assert rows.estimated_value_bytes > 0

    rows.delete(inline)
    with pytest.raises(KeyError):
        rows.get_by_handle(inline)
    assert rows.insert(b"again") == inline
    rows.delete(inline)
    rows.delete(overflow)

    after = rows.metrics(estimate_bytes=True)
    assert after.live_entries == 0
    assert after.allocated_slots == 0
    assert after.estimated_bytes > 0
    assert rows.estimated_value_bytes < before_values


def test_packed_unique_digest_map_probes_resizes_mutates_and_pops_exactly() -> None:
    """Packed route clusters remain exact through resize, mutation, and deletion."""

    routes = PackedUniqueDigestMap(b"ef-test-route")
    for ordinal, digest in enumerate(range(1, 1_000 * 8, 8)):
        routes.set_digest(digest, ordinal)
    routes["semantic-route"] = 50_000
    routes.set_digest(1, 60_000)

    assert len(routes) == 1_001
    assert routes.get_digest(1) == 60_000
    assert routes.get_digest(9) == 1
    assert routes.get("semantic-route") == 50_000
    assert routes.pop_digest(9) == 1
    assert routes.get_digest(9) is None
    assert routes.pop("semantic-route") == 50_000
    assert "semantic-route" not in routes
    metrics = routes.metrics(estimate_bytes=True)
    assert metrics.live_entries == 999
    assert metrics.high_water_mark == 1_001
    assert metrics.primary_map_backing_bytes > 0


def test_packed_unique_digest_map_releases_empty_peak_capacity_in_constant_work() -> None:
    """Forced empty compaction drops peak arrays without scanning old slots."""

    routes = PackedUniqueDigestMap(b"ef-test-empty")
    for ordinal in range(10_000):
        routes.set_digest(ordinal, ordinal)
    before = routes.metrics(estimate_bytes=True)
    for ordinal in range(10_000):
        assert routes.pop_digest(ordinal) == ordinal

    assert routes.compact_primary(max_entries=0, force=True) == 0
    after = routes.metrics(estimate_bytes=True)
    assert after.live_entries == 0
    assert after.primary_map_backing_bytes < before.primary_map_backing_bytes // 100


def test_compact_handle_store_reuses_external_route_handles_and_pages() -> None:
    """Handle-owned values avoid a duplicate primary map while retaining equality APIs."""

    store: CompactHandleStore[tuple[str, str]] = CompactHandleStore(
        owner=lambda item: item[0],
        affinity=lambda item: item,
    )
    first = store.insert(("alice", "web"))
    second = store.insert(("alice", "mail"))

    assert tuple(store.find_iter("owner", "alice")) == (
        ("alice", "web"),
        ("alice", "mail"),
    )
    page, cursor = store.find_handle_page("owner", "alice", limit=1)
    assert page == (first,)
    assert cursor == first
    assert store.find_handle_page("owner", "alice", after_handle=cursor, limit=1) == (
        (second,),
        None,
    )
    assert store.replace(first, ("bob", "web")) == ("alice", "web")
    assert store.count("owner", "alice") == 1
    assert store.count("owner", "bob") == 1
    assert store.delete(first) == ("bob", "web")
    assert store.insert(("carol", "web")) == first
    metrics = store.metrics(estimate_bytes=True)
    assert metrics.primary_map_entries == 0
    assert metrics.backing_entries == 2
    assert metrics.live_entries == 2
    assert metrics.estimated_bytes > 0


def test_incremental_exact_map_preserves_mutations_during_bounded_rotation() -> None:
    """Active/retired routing stays exact while each call moves only its budget."""

    routes: IncrementalExactMap[str, int] = IncrementalExactMap()
    for ordinal in range(5_000):
        routes[f"route-{ordinal}"] = ordinal

    assert routes.compact_primary(max_entries=10, force=True) == 10
    assert routes.metrics().primary_compaction_pending
    routes["route-0"] = 50_000
    del routes["route-1"]
    routes["route-new"] = 60_000

    while routes.metrics().primary_compaction_pending:
        assert routes.compact_primary(max_entries=127) <= 127

    assert len(routes) == 5_000
    assert routes["route-0"] == 50_000
    assert routes.get("route-1") is None
    assert routes["route-new"] == 60_000
    metrics = routes.metrics(estimate_bytes=True)
    assert metrics.primary_compaction_rotations == 1
    assert metrics.primary_compaction_work < 5_000
    assert metrics.primary_map_entries == len(routes)
    assert metrics.estimated_bytes > 0


def test_incremental_exact_map_drops_an_empty_retired_map_in_constant_work() -> None:
    """A deletion-only watermark releases peak dictionary capacity without a scan."""

    routes: IncrementalExactMap[int, int] = IncrementalExactMap()
    for ordinal in range(5_000):
        routes[ordinal] = ordinal
    for ordinal in range(5_000):
        del routes[ordinal]

    before = routes.metrics()
    assert before.primary_map_backing_bytes > 100_000
    assert routes.compact_primary(max_entries=0, force=True) == 0
    after = routes.metrics()
    assert not after.primary_compaction_pending
    assert after.primary_compaction_rotations == 1
    assert after.primary_map_backing_bytes < before.primary_map_backing_bytes // 100


def test_packed_handle_expiry_index_preserves_exact_update_and_boundary_semantics() -> None:
    """Primitive handle deadlines retain versioning and inclusive cutoff behavior."""

    index = PackedHandleExpiryIndex()
    index.set(7, 10.0)
    index.set(2, 10.0)
    index.set(7, 12.0)

    assert index.get(7) == 12.0
    assert index.get(2) == 10.0
    assert index.get(99) is None
    assert index.get(99, -1.0) == -1.0
    assert index.expire_before(10.0) == []
    assert index.expire_before(10.0, inclusive=True) == [(2, 10.0)]
    assert index.get(2) is None
    index.set(2, 14.0)
    assert index.get(2) == 14.0
    assert index.pop(2) == 14.0
    assert index.expire_before(12.0, inclusive=True) == [(7, 12.0)]
    assert len(index) == 0


def test_packed_handle_expiry_index_pages_due_handles_without_aba_leaks() -> None:
    """Bounded pages preserve deadline/handle order and current versions."""

    index = PackedHandleExpiryIndex()
    index.set(7, 10.0)
    index.set(2, 10.0)
    index.set(7, 20.0)
    index.set(3, 10.0)

    assert index.first_due_before(10.0) is None
    assert index.first_due_before(10.0, inclusive=True) == (2, 10.0)
    assert index.expire_before_page(10.0, inclusive=True, limit=1) == ((2, 10.0),)
    assert index.expire_before_page(10.0, inclusive=True, limit=1) == ((3, 10.0),)
    assert index.expire_before_page(10.0, inclusive=True, limit=1) == ()
    assert index.first_due_before(20.0, inclusive=True) == (7, 20.0)
    with pytest.raises(ValueError, match="positive"):
        index.expire_before_page(20.0, limit=0)


def test_packed_handle_expiry_index_rebuilds_stale_heap_with_bounded_slot_work() -> None:
    """A version-heavy heap scans no more than the explicit watermark budget."""

    index = PackedHandleExpiryIndex()
    for handle in range(5_000):
        index.set(handle, float(handle + 10))
        index.set(handle, float(handle + 20))
        index.set(handle, float(handle + 30))

    before = index.metrics(estimate_bytes=True)
    assert before.backing_entries == 15_000
    assert before.estimated_bytes < before.backing_entries * 32
    assert index.compact(max_slots=37) == 37
    assert index.metrics().compaction_pending
    index.set(0, 50_000.0)
    while index.metrics().compaction_pending:
        assert index.compact(max_slots=127) <= 127

    after = index.metrics()
    assert after.backing_entries <= after.live_entries + 1
    assert after.compaction_work == 5_000
    assert index.expire_before(40.0, inclusive=True)[0] == (1, 31.0)


def test_compact_indexed_store_uses_handles_and_streaming_secondary_indexes() -> None:
    """Compact indexes should replace records without duplicating semantic keys."""
    store: CompactIndexedStore[str, tuple[str, str]] = CompactIndexedStore(
        host=lambda item: item[0],
        owner=lambda item: item[1],
    )
    store["object-one"] = ("ws01", "alice")
    store["object-two"] = ("ws01", "bob")
    first_handle = store.handle_for("object-one")

    assert tuple(store.find_key_iter("host", "ws01")) == ("object-one", "object-two")
    assert store.count("host", "ws01") == 2
    assert store.find_one("owner", "alice") == ("ws01", "alice")
    assert store.get_by_handle(first_handle) == ("ws01", "alice")

    store["object-one"] = ("ws02", "alice")
    assert store.handle_for("object-one") == first_handle
    assert tuple(store.find_key_iter("host", "ws01")) == ("object-two",)
    assert tuple(store.find_key_iter("host", "ws02")) == ("object-one",)

    del store["object-one"]
    with pytest.raises(KeyError):
        store.get_by_handle(first_handle)
    store["object-three"] = ("ws03", "carol")
    assert store.handle_for("object-three") == first_handle
    assert store.metrics().live_entries == 2


def test_compact_indexed_store_rejects_unknown_secondary_index() -> None:
    """Misspelled lookup paths should fail before scanning primary storage."""
    store: CompactIndexedStore[str, tuple[str]] = CompactIndexedStore(host=lambda item: item[0])
    store["one"] = ("ws01",)

    with pytest.raises(KeyError, match="unknown compact index"):
        store.find_one("hostname", "ws01")


def test_compact_indexed_store_allocates_secondary_state_lazily() -> None:
    """Declaring indexes should not allocate per-index maps for an empty store."""
    store: CompactIndexedStore[str, tuple[str, str]] = CompactIndexedStore(
        host=lambda item: item[0],
        owner=lambda item: item[1],
    )

    assert store._indexes == {}
    assert store.metrics(estimate_bytes=True).secondary_buckets == 0
    assert store.find_one("host", "ws01") is None
    assert store._indexes == {}


def test_compact_indexed_store_pages_exact_bucket_without_live_iterators() -> None:
    """Bounded pages should resume in deterministic bucket insertion order."""
    store: CompactIndexedStore[str, tuple[str]] = CompactIndexedStore(host=lambda item: item[0])
    for ordinal in range(7):
        store[f"key-{ordinal}"] = ("ws01",)

    first, cursor = store.find_handle_page("host", "ws01", limit=3)
    second, cursor = store.find_handle_page("host", "ws01", after_handle=cursor, limit=3)
    third, cursor = store.find_handle_page("host", "ws01", after_handle=cursor, limit=3)

    assert first + second + third == tuple(range(7))
    assert cursor is None
    with pytest.raises(ValueError, match="positive"):
        store.find_handle_page("host", "ws01", limit=0)


def test_compact_indexed_store_extractor_failures_are_atomic() -> None:
    """An invalid new value must not partially mutate primary or secondary state."""

    def checked_host(item: tuple[str]) -> str:
        if item[0] == "raise":
            raise ValueError("invalid host")
        return item[0]

    store: CompactIndexedStore[str, tuple[str]] = CompactIndexedStore(host=checked_host)
    store["one"] = ("ws01",)

    with pytest.raises(ValueError, match="invalid host"):
        store["two"] = ("raise",)
    with pytest.raises(ValueError, match="invalid host"):
        store["one"] = ("raise",)

    assert tuple(store) == ("one",)
    assert store["one"] == ("ws01",)
    assert tuple(store.find_key_iter("host", "ws01")) == ("one",)


def test_compact_indexed_store_rotates_peak_primary_map_incrementally() -> None:
    store: CompactIndexedStore[int, tuple[str, int]] = CompactIndexedStore(
        owner=lambda item: item[0],
    )
    for ordinal in range(5_000):
        store[ordinal] = (f"owner-{ordinal}", ordinal)
    for ordinal in range(4_990):
        del store[ordinal]

    before = store.metrics()
    assert before.live_entries == 10
    assert before.primary_map_entries == 10
    assert before.primary_map_backing_bytes > 100_000

    assert store.compact_primary(max_slots=1_000) == 1_000
    during = store.metrics()
    assert during.primary_compaction_pending is True
    assert store[4_999] == ("owner-4999", 4_999)

    store[4_999] = ("updated", 9_999)
    del store[4_998]
    store[6_000] = ("new", 6_000)
    while store.metrics().primary_compaction_pending:
        assert store.compact_primary(max_slots=1_000) <= 1_000

    after = store.metrics()
    assert len(store) == 10
    assert after.primary_map_entries == len(store)
    assert after.primary_map_backing_bytes < before.primary_map_backing_bytes // 10
    assert after.primary_compaction_rotations == 1
    assert after.primary_compaction_work == 5_000
    assert store[4_999] == ("updated", 9_999)
    assert store[6_000] == ("new", 6_000)
    assert store.find_one("owner", "updated") == store[4_999]
    assert store.find_one("owner", "new") == store[6_000]


def test_compact_indexed_store_primary_rotation_is_explicitly_bounded() -> None:
    store: CompactIndexedStore[int, tuple[str, int]] = CompactIndexedStore()
    for ordinal in range(100):
        store[ordinal] = ("alice", ordinal)

    assert store.compact_primary(max_slots=10) == 0
    assert store.metrics().primary_compaction_pending is False
    assert store.compact_primary(max_slots=0, force=True) == 0
    assert store.metrics().primary_compaction_pending is True
    assert store.compact_primary(max_slots=10) == 10
    assert list(store) == list(range(10)) + list(range(10, 100))
    with pytest.raises(ValueError, match="max_slots"):
        store.compact_primary(max_slots=-1)


def test_compact_indexed_store_drops_empty_peak_map_without_slot_scan() -> None:
    store: CompactIndexedStore[int, int] = CompactIndexedStore()
    for ordinal in range(5_000):
        store[ordinal] = ordinal
    for ordinal in range(5_000):
        del store[ordinal]
    before_bytes = store.metrics().primary_map_backing_bytes

    assert store.compact_primary(max_slots=1, force=True) == 0

    after = store.metrics()
    assert after.primary_compaction_pending is False
    assert after.primary_compaction_rotations == 1
    assert after.primary_compaction_work == 0
    assert after.primary_map_backing_bytes < before_bytes // 100


def test_indexed_entity_store_preserves_primary_and_secondary_order() -> None:
    """Secondary lookup should match filtered primary insertion order."""
    store: IndexedEntityStore[str, dict[str, str]] = IndexedEntityStore(
        user=lambda item: item["user"],
        host=lambda item: item["host"],
    )
    store["one"] = {"user": "alice", "host": "ws01"}
    store["two"] = {"user": "bob", "host": "ws01"}
    store["three"] = {"user": "alice", "host": "ws02"}

    assert list(store) == ["one", "two", "three"]
    assert store.find("user", "alice") == [
        {"user": "alice", "host": "ws01"},
        {"user": "alice", "host": "ws02"},
    ]
    assert store.find_keys("host", "ws01") == ("one", "two")


def test_indexed_entity_store_refreshes_mutated_fields_and_rekeys() -> None:
    """Mutation and primary-key changes must not leave stale index entries."""
    store: IndexedEntityStore[str, dict[str, str]] = IndexedEntityStore(
        user=lambda item: item["user"],
    )
    value = {"user": "alice"}
    store["old"] = value
    value["user"] = "bob"
    store.refresh("old")

    assert store.find("user", "alice") == []
    assert store.find_keys("user", "bob") == ("old",)
    assert store.rekey("old", "new") is value
    assert store.find_keys("user", "bob") == ("new",)


def test_expiring_index_preserves_deadline_and_insertion_order() -> None:
    """Due entries should be returned by deadline with stable tie ordering."""
    index: ExpiringIndex[str, str] = ExpiringIndex()
    index.set("later", "later-value", 20.0)
    index.set("first-tie", "first-value", 10.0)
    index.set("second-tie", "second-value", 10.0)

    assert index.expire_before(10.0) == []
    assert index.expire_before(10.0, inclusive=True) == [
        ("first-tie", "first-value"),
        ("second-tie", "second-value"),
    ]
    assert index.get("later") == "later-value"


def test_expiring_index_pages_due_entries_without_materializing_the_remainder() -> None:
    """Each compatibility-independent expiry page obeys its explicit bound."""

    index: ExpiringIndex[str, str] = ExpiringIndex()
    index.set("later", "later", 20.0)
    index.set("first", "first", 10.0)
    index.set("second", "second", 10.0)

    assert index.expire_before_page(10.0, inclusive=True, limit=1) == (("first", "first"),)
    assert index.expire_before_page(10.0, inclusive=True, limit=1) == (("second", "second"),)
    assert index.expire_before_page(10.0, inclusive=True, limit=1) == ()
    assert index.get("later") == "later"
    with pytest.raises(ValueError, match="positive"):
        index.expire_before_page(20.0, limit=0)


def test_expiring_index_ignores_stale_deadlines_after_update() -> None:
    """Updating a deadline should make the old heap entry inert."""
    index: ExpiringIndex[str, str] = ExpiringIndex()
    index.set("key", "old", 10.0)
    index.set("key", "new", 30.0)

    assert index.expire_before(20.0, inclusive=True) == []
    assert index.get("key") == "new"
    assert index.expire_before(30.0, inclusive=True) == [("key", "new")]


def test_expiring_index_reinsert_same_deadline_rejects_stale_heap_aba() -> None:
    """A removed key's heap generation must never expire its replacement."""
    index: ExpiringIndex[str, str] = ExpiringIndex()
    index.set("key", "old", 10.0)
    index.set("keeper", "value", 10.0)
    assert index.pop("key") == "old"
    index.set("key", "new", 10.0)

    assert index.expire_before(10.0, inclusive=True) == [
        ("keeper", "value"),
        ("key", "new"),
    ]


def test_expiring_index_trims_earliest_deadlines_without_sorting_live_values() -> None:
    """Capacity eviction should retain the longest-lived entries in deadline order."""

    index: ExpiringIndex[str, str] = ExpiringIndex()
    index.set("late", "late-value", 40.0)
    index.set("early", "early-value", 10.0)
    index.set("updated", "stale-value", 5.0)
    index.set("updated", "updated-value", 30.0)

    assert index.trim_earliest(2) == [("early", "early-value")]
    assert list(index.items()) == [
        ("late", "late-value"),
        ("updated", "updated-value"),
    ]


def test_expiring_index_rejects_negative_capacity() -> None:
    """A nonsensical capacity must fail before changing retained state."""

    index: ExpiringIndex[str, str] = ExpiringIndex()
    index.set("one", "value", 1.0)

    with pytest.raises(ValueError, match="non-negative"):
        index.trim_earliest(-1)

    assert index.get("one") == "value"


@pytest.mark.parametrize("trim_kind", ["rank", "earliest"])
def test_expiring_index_capacity_rejects_smaller_than_protected_lane_neutrally(
    trim_kind: str,
) -> None:
    """Capacity validation cannot silently overrun or invoke a rank callback."""

    index: ExpiringIndex[str, str] = ExpiringIndex()
    index.set("protected-one", "protected-one", 10.0)
    index.set("protected-two", "protected-two", 20.0)
    index.set("ordinary", "ordinary", 30.0)
    index.protect("protected-one")
    index.protect("protected-two")
    before = (
        dict(index._items),
        dict(index._deadlines),
        dict(index._orders),
        dict(index._versions),
        list(index._heap),
        set(index._protected),
    )
    rank_calls = 0

    def rank(_key: str, _value: str) -> int:
        nonlocal rank_calls
        rank_calls += 1
        return 0

    with pytest.raises(ValueError, match="protected entries"):
        if trim_kind == "rank":
            index.trim(1, rank=rank)
        else:
            index.trim_earliest(1)
    assert rank_calls == 0
    assert (
        dict(index._items),
        dict(index._deadlines),
        dict(index._orders),
        dict(index._versions),
        list(index._heap),
        set(index._protected),
    ) == before

    if trim_kind == "rank":
        assert index.trim(2, rank=rank) == [("ordinary", "ordinary")]
        assert rank_calls == 1
    else:
        assert index.trim_earliest(2) == [("ordinary", "ordinary")]
    assert set(index) == {"protected-one", "protected-two"}


def test_expiring_index_protection_preserves_exact_order_update_and_capacity() -> None:
    """Protected keys keep their row/order while displacing ordinary cap victims."""

    index: ExpiringIndex[str, str] = ExpiringIndex()
    index.set("protected", "old", 10.0)
    index.set("first", "first", 10.0)
    index.set("second", "second", 10.0)

    assert index.protect("protected")
    assert not index.protect("protected")
    assert index.is_protected("protected")
    assert index.protected_count() == 1
    index.set("protected", "updated", 30.0)
    assert index.expire_before(10.0, inclusive=True) == [
        ("first", "first"),
        ("second", "second"),
    ]
    assert index.get("protected") == "updated"
    assert index.deadline("protected") == 30.0

    index.set("ordinary", "ordinary", 20.0)
    assert index.trim_earliest(1) == [("ordinary", "ordinary")]
    assert list(index.items()) == [("protected", "updated")]
    metrics = index.metrics(estimate_bytes=True)
    assert metrics.protected_entries == 1
    assert metrics.protected_high_water_mark == 1
    assert metrics.estimated_bytes > 0

    assert index.release("protected")
    assert index.expire_before(29.0, inclusive=True) == []
    assert index.expire_before(30.0, inclusive=True) == [("protected", "updated")]
    assert index.protected_count() == 0
    index.set("removed", "removed", 25.0)
    index.protect("removed")
    assert index.pop("removed") == "removed"
    assert index.protected_count() == 0
    index.set("replacement", "replacement", 30.0)
    index.protect("replacement")
    index.clear()
    assert not index
    assert index.protected_count() == 0


def test_expiring_index_release_is_ordered_and_lost_return_idempotent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Release allocates first, restores original tie order, and converges on retry."""

    index: ExpiringIndex[str, str] = ExpiringIndex()
    index.set("protected", "protected", 10.0)
    index.set("peer", "peer", 10.0)
    index.protect("protected")

    with monkeypatch.context() as release_fault:
        release_fault.setattr(
            indexes_module.heapq,
            "heappush",
            lambda _heap, _record: (_ for _ in ()).throw(RuntimeError("before release")),
        )
        with pytest.raises(RuntimeError, match="before release"):
            index.release("protected")
    assert index.is_protected("protected")
    assert index.expire_before(10.0, inclusive=True) == [("peer", "peer")]

    original_heappush = indexes_module.heapq.heappush
    for _attempt in range(3):
        with monkeypatch.context() as partial_release_fault:

            def append_then_raise(
                heap: list[tuple[float, int, int, str]],
                record: tuple[float, int, int, str],
            ) -> None:
                original_heappush(heap, record)
                raise RuntimeError("partial release push")

            partial_release_fault.setattr(
                indexes_module.heapq,
                "heappush",
                append_then_raise,
            )
            with pytest.raises(RuntimeError, match="partial release push"):
                index.release("protected")
        assert index.is_protected("protected")
        assert index.metrics().backing_entries == 1
        assert index.expire_before(10.0, inclusive=True) == []
        assert index.metrics().backing_entries == 0

    def release_then_lose_return() -> None:
        assert index.release("protected")
        raise RuntimeError("lost release return")

    with pytest.raises(RuntimeError, match="lost release return"):
        release_then_lose_return()
    assert not index.is_protected("protected")
    assert not index.release("protected")
    assert index.expire_before(10.0, inclusive=True) == [("protected", "protected")]


def test_expiring_index_release_restores_original_stable_tie_order() -> None:
    """A protected key returns to its original insertion order within a deadline tie."""

    index: ExpiringIndex[str, str] = ExpiringIndex()
    index.set("protected-first", "protected-first", 10.0)
    index.set("second", "second", 10.0)
    index.set("third", "third", 10.0)
    index.protect("protected-first")
    assert index.release("protected-first")

    assert index.expire_before(10.0, inclusive=True) == [
        ("protected-first", "protected-first"),
        ("second", "second"),
        ("third", "third"),
    ]


def test_expiring_index_protected_update_plateaus_at_100k_operations() -> None:
    """Protected updates do not append heap work on every clock or value change."""

    index: ExpiringIndex[str, int] = ExpiringIndex()
    index.set("protected", 0, 1.0)
    index.protect("protected")
    for ordinal in range(1, 100_001):
        index.set("protected", ordinal, float(ordinal + 1))

    before_clock = index.metrics()
    assert before_clock.live_entries == 1
    assert before_clock.protected_entries == 1
    assert before_clock.backing_entries == 1
    assert before_clock.stale_entries == 1
    for _ in range(100):
        assert index.expire_before(200_000.0, inclusive=True) == []
    after_clock = index.metrics()
    assert after_clock.backing_entries == 0
    assert after_clock.stale_entries == 0
    assert index.get("protected") == 100_000

    assert index.release("protected")
    released = index.metrics()
    assert released.backing_entries == 1
    assert released.protected_entries == 0
    assert index.expire_before(200_000.0, inclusive=True) == [("protected", 100_000)]


def test_expiring_index_reports_and_compacts_stale_backing_state() -> None:
    """Explicit watermarks should remove stale heap amplification."""
    index: ExpiringIndex[str, str] = ExpiringIndex()
    for deadline in range(10):
        index.set("key", f"value-{deadline}", float(deadline))

    before = index.metrics()
    assert before.live_entries == 1
    assert before.backing_entries == 10
    assert before.stale_entries == 9

    index.compact()
    assert index.metrics().backing_entries == 1


def test_expiring_index_rebuilds_stale_heap_in_bounded_dual_heap_pages() -> None:
    index: ExpiringIndex[int, int] = ExpiringIndex()
    for ordinal in range(20_000):
        index.set(ordinal % 100, ordinal, float(ordinal + 100))

    before = index.metrics()
    assert before.live_entries == 100
    assert before.backing_entries == 20_000
    assert index.compact(max_entries=257) == 257
    during = index.metrics()
    assert during.compaction_pending is True
    assert during.compaction_work == 257
    assert during.backing_entries <= before.backing_entries
    assert index.get(99) == 19_999

    index.set(99, 99_999, 99_999.0)
    index.pop(98)
    while index.metrics().compaction_pending:
        assert index.compact(max_entries=257) <= 257

    after = index.metrics()
    assert after.live_entries == 99
    assert after.backing_entries == after.live_entries
    assert after.stale_entries == 0
    assert index.get(99) == 99_999
    with pytest.raises(ValueError, match="max_entries"):
        index.compact(max_entries=-1)


@pytest.mark.slow
def test_expiring_index_million_entry_skew_compaction_page_is_bounded() -> None:
    index: ExpiringIndex[str, int] = ExpiringIndex()
    for ordinal in range(1_000_000):
        index.set("single-owner", ordinal, float(ordinal + 1))

    before = index.metrics()
    assert before.live_entries == 1
    assert before.backing_entries == 1_000_000
    started = perf_counter()
    assert index.compact(max_entries=4_096) == 4_096
    elapsed = perf_counter() - started

    after = index.metrics()
    assert elapsed < 2.0
    assert after.compaction_pending is True
    assert after.compaction_work == 4_096
    assert after.backing_entries == before.backing_entries - 4_096
    assert index.get("single-owner") == 999_999


def test_sharded_expiring_index_allocates_only_used_stable_shards() -> None:
    """Small workloads stay small while large owners use bounded heaps."""
    index: ShardedExpiringIndex[tuple[int, str], str] = ShardedExpiringIndex(
        shard_selector=lambda key: key[0],
        shard_count=8,
    )
    index.set((1, "one"), "first", 10.0)
    index.set((9, "two"), "second", 20.0)
    index.set((2, "three"), "third", 10.0)

    assert index.get((9, "two")) == "second"
    assert index.metrics().secondary_buckets == 2
    assert index.expire_before(10.0, inclusive=True) == [
        ((1, "one"), "first"),
        ((2, "three"), "third"),
    ]
    assert tuple(index) == ((9, "two"),)


def test_sharded_expiring_index_pages_across_shards_with_one_global_bound() -> None:
    """One page never materializes more than its limit across lazy shards."""

    index: ShardedExpiringIndex[tuple[int, str], str] = ShardedExpiringIndex(
        shard_selector=lambda key: key[0],
        shard_count=8,
    )
    index.set((2, "second"), "second", 10.0)
    index.set((1, "first"), "first", 10.0)
    index.set((3, "later"), "later", 20.0)

    assert index.expire_before_page(10.0, inclusive=True, limit=1) == (((1, "first"), "first"),)
    assert index.expire_before_page(10.0, inclusive=True, limit=1) == (((2, "second"), "second"),)
    assert index.expire_before_page(10.0, inclusive=True, limit=1) == ()
    assert index.get((3, "later")) == "later"


def test_grouped_temporal_index_filters_history_and_preserves_insertion_order() -> None:
    """Range lookup should skip expired history without changing result order."""
    start = datetime(2026, 1, 1, tzinfo=UTC)
    index: GroupedTemporalIndex[str, str] = GroupedTemporalIndex()
    index.add("later-inserted-first", "alice", start + timedelta(hours=3))
    index.add("earlier-inserted-second", "alice", start + timedelta(hours=2))
    index.add("other-user", "bob", start + timedelta(hours=4))

    assert index.keys_after("alice", start + timedelta(hours=1)) == (
        "later-inserted-first",
        "earlier-inserted-second",
    )
    assert index.keys_after("alice", start + timedelta(hours=2)) == ("later-inserted-first",)
    assert index.keys_at_or_before("alice", start + timedelta(hours=2)) == (
        "earlier-inserted-second",
    )


def test_grouped_temporal_index_replacement_leaves_old_record_stale() -> None:
    """Replacing and removing keys must not leak stale temporal records."""
    start = datetime(2026, 1, 1, tzinfo=UTC)
    index: GroupedTemporalIndex[str, str] = GroupedTemporalIndex()
    index.add("session", "alice", start + timedelta(hours=1))
    index.add("session", "alice", start + timedelta(hours=3))

    assert index.keys_after("alice", start + timedelta(hours=2)) == ("session",)
    assert index.keys_at_or_before("alice", start + timedelta(hours=2)) == ()
    index.remove("session")
    assert index.keys_after("alice", start) == ()


def test_grouped_temporal_index_compacts_large_stale_history() -> None:
    """Repeated replacements and removals should not retain unbounded stale records."""
    start = datetime(2026, 1, 1, tzinfo=UTC)
    index: GroupedTemporalIndex[str, str] = GroupedTemporalIndex()

    for offset in range(2_100):
        index.add("session", "alice", start + timedelta(seconds=offset))

    records = index._records["alice"]
    assert len(records) < 1_100
    assert index.keys_after("alice", start) == ("session",)

    index.remove("session")
    assert index.keys_after("alice", start) == ()


def test_segmented_temporal_index_bounds_out_of_order_blocks_and_streams_results() -> None:
    """A hot skewed group should use bounded blocks instead of list-wide inserts."""
    start = datetime(2026, 1, 1, tzinfo=UTC)
    index: SegmentedTemporalIndex[str] = SegmentedTemporalIndex()
    count = SegmentedTemporalIndex._BLOCK_SIZE * 5
    for offset in reversed(range(count)):
        index.add(offset, "alice", start + timedelta(seconds=offset))

    group = index._groups[index._group_ids["alice"]]
    assert max(len(block) for block in group.blocks) <= SegmentedTemporalIndex._BLOCK_SIZE * 2
    assert tuple(index.iter_after("alice", start + timedelta(seconds=count - 4))) == (
        count - 3,
        count - 2,
        count - 1,
    )
    assert tuple(index.iter_at_or_before("alice", start + timedelta(seconds=2))) == (
        0,
        1,
        2,
    )
    assert tuple(index.iter_after("alice", start, limit=2)) == (1, 2)


def test_segmented_temporal_index_promotes_and_demotes_inline_singletons() -> None:
    """Sparse groups should stay inline and return inline after packed churn."""
    start = datetime(2026, 1, 1, tzinfo=UTC)
    index: SegmentedTemporalIndex[str] = SegmentedTemporalIndex()
    index.add(0, "alice", start)
    group_id = index._group_ids["alice"]

    assert not hasattr(index._groups[group_id], "blocks")
    assert tuple(index.iter_at_or_before("alice", start)) == (0,)

    index.add(1, "alice", start + timedelta(seconds=1))
    assert hasattr(index._groups[group_id], "blocks")
    index.remove(1)
    assert index.compact(max_groups=1) == 1
    assert not hasattr(index._groups[group_id], "blocks")
    assert tuple(index.iter_at_or_before("alice", start)) == (0,)


def test_segmented_temporal_index_replaces_compacts_and_discards_history() -> None:
    """Versioned replacement and watermark discard keep only current records."""
    start = datetime(2026, 1, 1, tzinfo=UTC)
    index: SegmentedTemporalIndex[str] = SegmentedTemporalIndex()
    for offset in range(1_100):
        index.add(0, "alice", start + timedelta(seconds=offset))
    index.add(1, "alice", start + timedelta(hours=2))

    assert tuple(index.iter_after("alice", start + timedelta(minutes=10))) == (
        0,
        1,
    )
    assert index.metrics().stale_entries >= 1_099
    assert index.compact() == 1
    assert index.metrics().backing_entries == 2

    index.discard_before(start + timedelta(hours=1))
    assert tuple(index.iter_after("alice", start)) == (1,)
    assert len(index) == 1


def test_segmented_temporal_index_preserves_equal_time_order_across_blocks() -> None:
    """Equal timestamps spanning block boundaries must remain complete and stable."""
    event_time = datetime(2026, 1, 1, tzinfo=UTC)
    index: SegmentedTemporalIndex[str] = SegmentedTemporalIndex()
    count = SegmentedTemporalIndex._BLOCK_SIZE * 4 + 1
    for handle in range(count):
        index.add(handle, "alice", event_time)

    assert tuple(index.iter_at_or_before("alice", event_time)) == tuple(range(count))
    assert tuple(index.iter_at_or_before("alice", event_time + timedelta(seconds=1))) == tuple(
        range(count)
    )

    index.add(0, "alice", event_time)
    assert tuple(index.iter_at_or_before("alice", event_time)) == tuple(range(count))


def test_segmented_temporal_index_latest_predecessor_bounds_reuse_inspection() -> None:
    """Latest lookup should not walk retained reuse history."""

    start = datetime(2026, 1, 1, tzinfo=UTC)
    index: SegmentedTemporalIndex[str] = SegmentedTemporalIndex(track_lookup_candidates=True)
    count = 10_000
    for handle in range(count):
        index.add(handle, "alice", start + timedelta(seconds=handle))

    before = index.metrics().lookup_candidates_inspected
    assert index.latest_at_or_before("alice", start + timedelta(seconds=8_765)) == 8_765
    after = index.metrics().lookup_candidates_inspected

    assert after - before == 1
    assert index.latest_at_or_before("alice", start - timedelta(microseconds=1)) is None
    assert index.latest_at_or_before("missing", start) is None


def test_segmented_temporal_index_latest_predecessor_handles_equal_and_stale_records() -> None:
    """Equal timestamps and replacement tombstones should resolve deterministically."""

    start = datetime(2026, 1, 1, tzinfo=UTC)
    index: SegmentedTemporalIndex[str] = SegmentedTemporalIndex()
    for handle in range(4):
        index.add(handle, "alice", start)

    assert index.latest_at_or_before("alice", start) == 3
    index.add(3, "alice", start - timedelta(seconds=1))
    assert index.latest_at_or_before("alice", start) == 2

    singleton: SegmentedTemporalIndex[str] = SegmentedTemporalIndex()
    singleton.add(11, "bob", start)
    assert singleton.latest_at_or_before("bob", start) == 11


def test_segmented_temporal_index_bounds_compaction_inspection_with_cursor() -> None:
    """Bounded compaction should inspect no more than requested and resume later."""
    event_time = datetime(2026, 1, 1, tzinfo=UTC)
    index: SegmentedTemporalIndex[str] = SegmentedTemporalIndex()
    index.add(0, "clean", event_time)
    index.add(1, "stale", event_time)
    index.add(1, "stale", event_time + timedelta(seconds=1))

    before = index.metrics()
    assert index.compact(max_groups=0) == 0
    assert index.metrics() == before
    assert index.compact(max_groups=1) == 0
    assert index.compact(max_groups=1) == 1
    assert index.metrics().stale_entries == 0


def test_segmented_temporal_index_bounds_discard_and_reuses_empty_group_ids() -> None:
    """Watermark churn should plateau group metadata instead of retaining old keys."""
    start = datetime(2026, 1, 1, tzinfo=UTC)
    index: SegmentedTemporalIndex[str] = SegmentedTemporalIndex()
    group_count = 32
    for cycle in range(5):
        for handle in range(group_count):
            index.add(handle, f"cycle-{cycle}-group-{handle}", start)
        assert index.discard_before(start + timedelta(seconds=1), max_groups=16) == 16
        assert index.discard_before(start + timedelta(seconds=1), max_groups=16) == 16
        assert len(index) == 0
        assert index.metrics().secondary_buckets == 0
        assert len(index._groups) == group_count


def test_index_metrics_expose_opt_in_candidate_and_census_data() -> None:
    """Diagnostics should be available without forcing hot-path timing."""
    start = datetime(2026, 1, 1, tzinfo=UTC)
    index: SegmentedTemporalIndex[str] = SegmentedTemporalIndex(track_lookup_candidates=True)
    index.add(0, "alice", start)
    assert tuple(index.iter_at_or_before("alice", start)) == (0,)

    metrics = index.metrics(estimate_bytes=True)
    assert metrics.high_water_mark == 1
    assert metrics.lookup_candidates_inspected == 1
    assert metrics.estimated_bytes > 0
    assert metrics.backing_amplification == 1.0


def test_reference_lease_index_tracks_owner_and_expiry_without_scans() -> None:
    """Explicit leases should synchronize key, owner, and deadline indexes."""
    leases: ReferenceLeaseIndex[str, str] = ReferenceLeaseIndex()
    leases.acquire("process-1", "action-a", deadline=10.0)
    leases.acquire("process-1", "ground-truth", deadline=30.0)
    leases.acquire("process-2", "action-a", deadline=20.0)

    assert leases.leased_key_count == 2
    assert tuple(leases.owners("process-1")) == ("action-a", "ground-truth")
    assert tuple(leases.keys_for_owner("action-a")) == ("process-1", "process-2")
    assert leases.expire_before(10.0, inclusive=True) == (("process-1", "action-a"),)
    assert leases.is_leased("process-1")
    assert leases.release_owner("ground-truth") == ("process-1",)
    assert not leases.is_leased("process-1")
    assert leases.metrics().live_entries == 1


def test_reference_lease_index_caches_census_and_compacts_peak_maps() -> None:
    leases: ReferenceLeaseIndex[str, str] = ReferenceLeaseIndex()
    for ordinal in range(5_000):
        leases.acquire(
            f"process-{ordinal}",
            f"owner-{ordinal}",
            deadline=float(ordinal + 1),
        )
    for ordinal in range(5_000):
        assert leases.release(f"process-{ordinal}", f"owner-{ordinal}")

    before = leases.metrics()
    assert before.live_entries == 0
    assert before.secondary_buckets == 0
    assert before.primary_map_backing_bytes > 100_000
    assert leases.compact(max_primary_slots=1, force_primary=True) == 0

    after = leases.metrics()
    assert after.live_entries == 0
    assert after.primary_compaction_pending is False
    assert after.primary_compaction_rotations == 1
    assert after.primary_map_backing_bytes < before.primary_map_backing_bytes // 100
    assert after.compaction_pending is False


def test_temporal_allocation_index_matches_reference_queries() -> None:
    """Temporal bounds should remain exact for out-of-order allocations."""
    start = datetime(2026, 1, 1, tzinfo=UTC)
    records = [
        (start + timedelta(minutes=20), 400),
        (start + timedelta(minutes=5), 180),
        (start + timedelta(minutes=10), 275),
        (start + timedelta(minutes=10), 290),
    ]
    index = TemporalAllocationIndex()
    for event_time, value in records:
        index.add(event_time, value)

    for minute in (0, 5, 9, 10, 15, 20, 25):
        cutoff = start + timedelta(minutes=minute)
        prior = [value for event_time, value in records if event_time <= cutoff]
        future = [value for event_time, value in records if event_time > cutoff]
        assert index.max_value_at_or_before(cutoff) == (max(prior) if prior else None)
        assert index.min_value_after(cutoff) == (min(future) if future else None)


def test_temporal_allocation_index_tracks_owned_values_across_discard() -> None:
    """Logical allocation ownership must remain exact when the open window advances."""
    start = datetime(2026, 1, 1, tzinfo=UTC)
    index = TemporalAllocationIndex()
    index.add(start, 100)
    index.add(start + timedelta(minutes=1), 200)

    assert index.contains_value(100)
    assert index.contains_value(200)

    index.discard_before(start + timedelta(seconds=30))

    assert not index.contains_value(100)
    assert index.contains_value(200)


def test_temporal_allocation_index_prefix_summary_survives_splits() -> None:
    """Large histories and later out-of-order inserts keep exact tree summaries."""
    start = datetime(2026, 1, 1, tzinfo=UTC)
    index = TemporalAllocationIndex()
    records = [
        (start + timedelta(seconds=second), 10_000 + second)
        for second in range(TemporalAllocationIndex._BLOCK_SIZE * 3)
    ]
    for event_time, value in records:
        index.add(event_time, value)

    inserted = (start + timedelta(seconds=100, microseconds=500_000), 99_999)
    index.add(*inserted)

    before_insert = inserted[0] - timedelta(microseconds=1)
    after_insert = inserted[0] + timedelta(microseconds=1)
    assert index.max_value_at_or_before(before_insert) == 10_100
    assert index.max_value_at_or_before(after_insert) == inserted[1]
    assert index.min_value_after(before_insert) == 10_101
    assert index.first_record_after(before_insert) == inserted


def test_temporal_allocation_index_matches_elapsed_delta_reference() -> None:
    """Indexed elapsed-delta checks should equal the historical scan predicate."""
    start = datetime(2026, 1, 1, tzinfo=UTC)
    records = [
        (start + timedelta(seconds=0.125), 1_000),
        (start + timedelta(seconds=19.75), 1_127),
        (start + timedelta(seconds=61.5), 1_240),
    ]
    index = TemporalAllocationIndex()
    for event_time, value in records:
        index.add(event_time, value)

    for seconds in (1.0, 20.25, 65.75, 120.0):
        event_time = start + timedelta(seconds=seconds)
        for candidate in range(900, 1_401):
            expected = any(
                abs((event_time - allocated_time).total_seconds()) >= 1.0
                and abs(
                    abs(candidate - allocated_value)
                    - abs((event_time - allocated_time).total_seconds())
                )
                <= 1.0
                for allocated_time, allocated_value in records
            )
            assert (
                index.matches_elapsed_delta(
                    event_time,
                    candidate,
                    tolerance=1.0,
                )
                is expected
            )
