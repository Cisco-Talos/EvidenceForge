"""Temporal logind allocation preserves previously published neighbour IDs."""

import random
from datetime import UTC, datetime, timedelta

from evidenceforge.generation.state_manager import StateManager


def test_logind_out_of_order_subsecond_insertions_keep_temporal_identity() -> None:
    state = StateManager()
    base = datetime(2026, 11, 2, 13, tzinfo=UTC)
    events = [base + timedelta(seconds=v) for v in (10, 0, 5, 2.5, 7.5, 5.5)]
    allocated = [
        (at, state.next_linux_logind_session_id("linux-host", random.Random(i), at))
        for i, at in enumerate(events)
    ]
    ids = [value for _at, value in sorted(allocated)]
    assert ids == sorted(ids)
    assert len(set(ids)) == len(ids)
    index = state._linux_logind_session_allocations["linux-host"]
    for at, value in allocated:
        assert index.max_value_at_or_before(at) == value


def test_logind_exhausted_out_of_order_interval_keeps_ids_unique() -> None:
    state = StateManager()
    base = datetime(2026, 11, 2, 13, tzinfo=UTC)
    event_times = [base + timedelta(seconds=value * 10) for value in range(8)]
    random.Random(0).shuffle(event_times)

    allocated = [
        state.next_linux_logind_session_id("linux-host", random.Random(index), event_time)
        for index, event_time in enumerate(event_times)
    ]

    assert len(set(allocated)) == len(event_times)
    index = state._linux_logind_session_allocations["linux-host"]
    assert all(
        index.max_value_at_or_before(event_time) == session_id
        for event_time, session_id in zip(event_times, allocated, strict=True)
    )


def test_logind_session_id_growth_tracks_allocations_not_elapsed_minutes() -> None:
    state = StateManager()
    base = datetime(2026, 11, 2, 13, tzinfo=UTC)
    event_times = [base + timedelta(hours=offset) for offset in (0, 2, 5, 9, 14, 20)]
    allocated = [
        (at, state.next_linux_logind_session_id("linux-host", random.Random(index), at))
        for index, at in enumerate(event_times)
    ]

    ordered_ids = [value for _at, value in sorted(allocated)]
    increments = [right - left for left, right in zip(ordered_ids, ordered_ids[1:], strict=False)]
    assert ordered_ids == sorted(ordered_ids)
    assert len(set(ordered_ids)) == len(ordered_ids)
    assert all(8 <= increment <= 80 for increment in increments)


def test_logind_allocation_does_not_advance_the_callers_rng_for_session_gaps() -> None:
    state = StateManager()
    at = datetime(2026, 11, 2, 13, tzinfo=UTC)
    rng = random.Random(91)
    expected_rng = random.Random(91)
    expected_rng.randint(20, 250)

    state.next_linux_logind_session_id("linux-host", rng, at)

    assert rng.getstate() == expected_rng.getstate()
