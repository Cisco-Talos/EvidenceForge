# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Failure-atomicity tests for the bounded process runtime cache owner."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier

import pytest

from evidenceforge.generation.indexes import CompactIndexedStore, PackedHandleExpiryIndex
from evidenceforge.generation.process_runtime_cache import BoundedRuntimeCache

_START = datetime(2024, 1, 1, tzinfo=UTC)


def _cache_owner_state(
    cache: BoundedRuntimeCache[str, str],
    key: str,
) -> tuple[object | None, float | None, int, int, int, int]:
    record = cache._record(key)
    deadline = None
    if record is not None:
        handle = cache._records.handle_for(key)
        deadline = cache._deadlines.get(handle)
    metrics = cache.metrics()
    return (
        record,
        deadline,
        metrics.live_entries,
        len(cache._deadlines),
        metrics.high_water_mark,
        cache.estimated_payload_bytes,
    )


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("fault_phase", ["before", "after_primary", "after_deadline"])
def test_bounded_cache_set_failure_restores_exact_owner_state_and_retries(
    monkeypatch: pytest.MonkeyPatch,
    existing: bool,
    fault_phase: str,
) -> None:
    cache: BoundedRuntimeCache[str, str] = BoundedRuntimeCache(
        default_deadline=lambda _value: _START + timedelta(days=1)
    )
    cache.set("stable", "stable-value", deadline=_START + timedelta(hours=6))
    if existing:
        cache.set("target", "old-value", deadline=_START + timedelta(hours=2))
    before = _cache_owner_state(cache, "target")
    original_primary_set = CompactIndexedStore.__setitem__
    original_deadline_set = PackedHandleExpiryIndex.set

    if fault_phase == "before":

        def fail_before_primary(
            _store: CompactIndexedStore[object, object],
            _key: object,
            _value: object,
        ) -> None:
            raise RuntimeError("injected failure before primary")

        monkeypatch.setattr(CompactIndexedStore, "__setitem__", fail_before_primary)
    elif fault_phase == "after_primary":

        def fail_after_primary(
            store: CompactIndexedStore[object, object],
            key: object,
            value: object,
        ) -> None:
            original_primary_set(store, key, value)
            raise RuntimeError("injected failure after primary")

        monkeypatch.setattr(CompactIndexedStore, "__setitem__", fail_after_primary)
    else:

        def fail_after_deadline(
            index: PackedHandleExpiryIndex,
            handle: int,
            deadline: float,
        ) -> None:
            original_deadline_set(index, handle, deadline)
            raise RuntimeError("injected failure after deadline")

        monkeypatch.setattr(PackedHandleExpiryIndex, "set", fail_after_deadline)

    with pytest.raises(RuntimeError, match=f"failure {fault_phase.replace('_', ' ')}"):
        cache.set("target", "new-value-with-different-size", deadline=_START + timedelta(hours=9))

    assert _cache_owner_state(cache, "target") == before
    first_due = cache._deadlines.first_due_before((_START + timedelta(hours=3)).timestamp())
    if existing:
        assert first_due == (
            cache._records.handle_for("target"),
            (_START + timedelta(hours=2)).timestamp(),
        )
    else:
        assert first_due is None

    monkeypatch.undo()
    cache.set("target", "new-value-with-different-size", deadline=_START + timedelta(hours=9))
    installed = cache._record("target")
    assert installed is not None
    assert installed.value == "new-value-with-different-size"
    assert cache._deadlines.get(cache._records.handle_for("target")) == pytest.approx(
        (_START + timedelta(hours=9)).timestamp()
    )
    expected_payload = (
        before[5]
        - (0 if before[0] is None else before[0].retained_bytes)
        + installed.retained_bytes
    )
    assert cache.estimated_payload_bytes == expected_payload
    assert cache.metrics().high_water_mark == 2


def test_bounded_cache_redeadline_failure_is_atomic_and_retryable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cache: BoundedRuntimeCache[str, str] = BoundedRuntimeCache(
        default_deadline=lambda _value: _START + timedelta(days=1)
    )
    cache.set("target", "stable-value", deadline=_START + timedelta(hours=2))
    before = _cache_owner_state(cache, "target")
    original_deadline_set = PackedHandleExpiryIndex.set

    def fail_after_deadline(
        index: PackedHandleExpiryIndex,
        handle: int,
        deadline: float,
    ) -> None:
        original_deadline_set(index, handle, deadline)
        raise RuntimeError("injected redeadline failure")

    monkeypatch.setattr(PackedHandleExpiryIndex, "set", fail_after_deadline)
    with pytest.raises(RuntimeError, match="redeadline failure"):
        cache.redeadline("target", deadline=_START + timedelta(hours=8))
    assert _cache_owner_state(cache, "target") == before

    monkeypatch.undo()
    assert cache.redeadline("target", deadline=_START + timedelta(hours=8))
    assert cache.raw_get("target") == "stable-value"
    assert cache._deadlines.get(cache._records.handle_for("target")) == pytest.approx(
        (_START + timedelta(hours=8)).timestamp()
    )
    assert cache.estimated_payload_bytes == before[5]
    assert cache.metrics().high_water_mark == before[4]


def test_bounded_cache_concurrent_set_and_redeadline_keep_indexes_and_counters_exact() -> None:
    cache: BoundedRuntimeCache[int, tuple[int, int]] = BoundedRuntimeCache(
        default_deadline=lambda _value: _START + timedelta(days=1)
    )
    worker_count = 8
    key_count = 32
    barrier = Barrier(worker_count)

    def mutate(worker: int) -> None:
        barrier.wait()
        for ordinal in range(256):
            key = ordinal % key_count
            cache.set(
                key,
                (worker, ordinal),
                deadline=_START + timedelta(hours=2, microseconds=worker),
            )
            if ordinal % 4 == 0:
                assert cache.redeadline(
                    key,
                    deadline=_START + timedelta(hours=3, microseconds=ordinal),
                )

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        tuple(executor.map(mutate, range(worker_count)))

    cache.advance_watermark(_START, limit=4_096)
    retained_bytes = 0
    for key in range(key_count):
        record = cache._record(key)
        assert record is not None
        retained_bytes += record.retained_bytes
        handle = cache._records.handle_for(key)
        assert cache._deadlines.get(handle) == pytest.approx(record.deadline_seconds)
    metrics = cache.metrics()
    assert metrics.live_entries == key_count
    assert len(cache._deadlines) == key_count
    assert metrics.high_water_mark == key_count
    assert metrics.backing_entries <= PackedHandleExpiryIndex._COMPACT_MIN_BACKING
    assert cache.estimated_payload_bytes == retained_bytes


def _failed_deadline_retention_census(failure_count: int) -> tuple[int, int, int, int, int]:
    cache: BoundedRuntimeCache[str, str] = BoundedRuntimeCache(
        default_deadline=lambda _value: _START + timedelta(days=1)
    )
    for ordinal in range(64):
        cache.set(
            f"key-{ordinal}",
            f"value-{ordinal}",
            deadline=_START + timedelta(hours=2),
        )
    before_payload = cache.estimated_payload_bytes
    before_high_water = cache.metrics().high_water_mark
    original_deadline_set = PackedHandleExpiryIndex.set

    def fail_after_deadline(
        index: PackedHandleExpiryIndex,
        handle: int,
        deadline: float,
    ) -> None:
        original_deadline_set(index, handle, deadline)
        raise RuntimeError("injected retained deadline failure")

    with pytest.MonkeyPatch.context() as patcher:
        patcher.setattr(PackedHandleExpiryIndex, "set", fail_after_deadline)
        for ordinal in range(failure_count):
            with pytest.raises(RuntimeError, match="retained deadline failure"):
                cache.redeadline(
                    f"key-{ordinal % 64}",
                    deadline=_START + timedelta(hours=3, microseconds=ordinal),
                )

    metrics = cache.metrics()
    return (
        metrics.live_entries,
        len(cache._deadlines),
        metrics.backing_entries,
        cache.estimated_payload_bytes - before_payload,
        metrics.high_water_mark - before_high_water,
    )


def test_bounded_cache_failed_install_retention_plateaus_from_seven_to_thirty_days() -> None:
    seven_day = _failed_deadline_retention_census(24 * 7)
    thirty_day = _failed_deadline_retention_census(24 * 30)

    assert seven_day[:2] == thirty_day[:2] == (64, 64)
    assert seven_day[2] <= seven_day[0] * 2
    assert thirty_day[2] <= thirty_day[0] * 2
    assert seven_day[3:] == thirty_day[3:] == (0, 0)
