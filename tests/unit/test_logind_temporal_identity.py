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
