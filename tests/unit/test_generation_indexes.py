# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for shared duration-stable generation indexes."""

from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.generation.indexes import (
    ExpiringIndex,
    GroupedTemporalIndex,
    IndexedEntityStore,
    TemporalAllocationIndex,
)


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


def test_expiring_index_ignores_stale_deadlines_after_update() -> None:
    """Updating a deadline should make the old heap entry inert."""
    index: ExpiringIndex[str, str] = ExpiringIndex()
    index.set("key", "old", 10.0)
    index.set("key", "new", 30.0)

    assert index.expire_before(20.0, inclusive=True) == []
    assert index.get("key") == "new"
    assert index.expire_before(30.0, inclusive=True) == [("key", "new")]


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
