# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Scale and census contracts for bounded source-timing planner state."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from evidenceforge.generation.source_timing import SourceTimingPlanner
from evidenceforge.generation.timing import TimingRuntime

T0 = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)


def test_source_timing_public_probe_shapes_match_constant_time_census() -> None:
    """Public production shapes must populate every index without private inspection."""

    planner = SourceTimingPlanner(
        timing_runtime=TimingRuntime(reference_time=T0, namespace="source-census-shapes")
    )

    for ordinal, spec in enumerate(planner.index_family_specs):
        inserted = planner.load_probe_entry(spec.name, ordinal, T0)
        replaced = planner.load_probe_entry(spec.name, ordinal, T0)
        assert inserted.inserted is True
        assert inserted.replaced is False
        assert replaced.inserted is False
        assert replaced.replaced is True
        assert inserted.key == replaced.key
        assert inserted.deadline == replaced.deadline

    census = planner.census(estimate_bytes=True)

    assert tuple(index.name for index in census.indexes) == tuple(
        spec.name for spec in planner.index_family_specs
    )
    assert census.index_count == len(planner.index_family_specs)
    assert census.live_entries == census.index_count
    assert census.backing_entries >= census.live_entries
    assert census.high_water_entries == census.index_count
    assert census.estimated_index_bytes > 0
    assert census.estimated_total_bytes >= (
        census.estimated_index_bytes + census.runtime.estimated_bytes
    )


def test_source_timing_population_plateaus_after_public_watermark() -> None:
    """A production-shaped population must expire by bounded pages, not duration scans."""

    planner = SourceTimingPlanner(
        timing_runtime=TimingRuntime(reference_time=T0, namespace="source-census-plateau")
    )
    family_names = tuple(spec.name for spec in planner.index_family_specs)
    population = 16_000
    session_probe = None
    for ordinal in range(population):
        family = family_names[ordinal % len(family_names)]
        result = planner.load_probe_entry(
            family,
            ordinal,
            T0 + timedelta(microseconds=ordinal),
        )
        if family == "latest_session_start" and session_probe is None:
            session_probe = result

    before = planner.census(estimate_bytes=True)
    assert before.live_entries == population
    assert before.backing_entries >= population
    assert before.high_water_entries == population
    assert before.stale_entries == 0
    assert session_probe is not None
    family, lifecycle_id = session_probe.key
    assert planner.session_start_source_time(family, lifecycle_id) is not None
    assert planner.census().lookup_candidates_inspected == 1

    reclaimed = planner.advance_watermark(T0 + timedelta(hours=49))
    after = planner.census(estimate_bytes=True)

    assert reclaimed == population
    assert after.live_entries == 0
    assert after.backing_entries == 0
    assert after.stale_entries == 0
    assert after.high_water_entries == population
    assert after.expiry_work == population
    assert after.watermark == T0 + timedelta(hours=49)
    assert after.estimated_index_bytes < before.estimated_index_bytes
