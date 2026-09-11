# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Boundary tests for allocation-free endpoint-clock admission headroom."""

from datetime import UTC, datetime, timedelta

import pytest

import evidenceforge.generation.source_timing as source_timing_module
from evidenceforge.generation.activity.timing_profiles import EndpointClockTiming
from evidenceforge.generation.source_timing import SourceTimingPlanner
from evidenceforge.generation.timing import TimingRuntime

_REFERENCE = datetime(2024, 1, 15, 10, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    ("elapsed", "positive_microseconds", "negative_microseconds"),
    (
        (timedelta(seconds=1), 2_007, 1_003),
        (-timedelta(seconds=1), 2_003, 1_007),
    ),
)
def test_endpoint_clock_headroom_selects_extrema_on_both_sides_of_reference(
    monkeypatch: pytest.MonkeyPatch,
    elapsed: timedelta,
    positive_microseconds: int,
    negative_microseconds: int,
) -> None:
    """Drift extrema reverse when canonical time precedes the runtime epoch."""

    monkeypatch.setattr(
        source_timing_module,
        "endpoint_clock_timing",
        lambda _profile, _os: EndpointClockTiming(
            host_offset_min_ms=-1,
            host_offset_max_ms=2,
            host_drift_min_ppm=-3,
            host_drift_max_ppm=7,
        ),
    )
    planner = SourceTimingPlanner(
        timing_runtime=TimingRuntime(reference_time=_REFERENCE),
    )
    canonical_time = _REFERENCE + elapsed

    assert planner.endpoint_clock_positive_headroom(
        canonical_time,
        "windows",
    ) == timedelta(microseconds=positive_microseconds)
    assert planner.endpoint_clock_negative_headroom(
        canonical_time,
        "windows",
    ) == timedelta(microseconds=negative_microseconds)


def test_endpoint_clock_headroom_rounds_outward_and_clips_at_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sub-microsecond support is rounded outward and one-sided support stays zero."""

    timing = EndpointClockTiming(
        host_offset_min_ms=0,
        host_offset_max_ms=0,
        host_drift_min_ppm=-1,
        host_drift_max_ppm=1,
    )
    monkeypatch.setattr(
        source_timing_module,
        "endpoint_clock_timing",
        lambda _profile, _os: timing,
    )
    planner = SourceTimingPlanner(
        timing_runtime=TimingRuntime(reference_time=_REFERENCE),
    )
    canonical_time = _REFERENCE + timedelta(microseconds=1)

    assert planner.endpoint_clock_positive_headroom(
        canonical_time,
        "linux",
    ) == timedelta(microseconds=1)
    assert planner.endpoint_clock_negative_headroom(
        canonical_time,
        "linux",
    ) == timedelta(microseconds=1)

    one_sided = EndpointClockTiming(
        host_offset_min_ms=2,
        host_offset_max_ms=3,
        host_drift_min_ppm=0,
        host_drift_max_ppm=0,
    )
    monkeypatch.setattr(
        source_timing_module,
        "endpoint_clock_timing",
        lambda _profile, _os: one_sided,
    )
    assert planner.endpoint_clock_negative_headroom(_REFERENCE, "linux") == timedelta(0)


def test_endpoint_clock_headroom_is_allocation_free() -> None:
    """Admission queries do not create sampled host clocks or timing audit records."""

    runtime = TimingRuntime(reference_time=_REFERENCE)
    planner = SourceTimingPlanner(
        clock_profile_name="messy_collection",
        timing_runtime=runtime,
    )
    before = runtime.census(estimate_bytes=True)

    for os_category in ("windows", "linux"):
        planner.endpoint_clock_positive_headroom(
            _REFERENCE + timedelta(days=365),
            os_category,
        )
        planner.endpoint_clock_negative_headroom(
            _REFERENCE - timedelta(days=365),
            os_category,
        )

    assert runtime.census(estimate_bytes=True) == before


def test_endpoint_clock_headroom_is_zero_for_non_endpoint_operating_system() -> None:
    """Only supported endpoint OS families have a host-clock projection."""

    planner = SourceTimingPlanner(
        clock_profile_name="messy_collection",
        timing_runtime=TimingRuntime(reference_time=_REFERENCE),
    )

    assert planner.endpoint_clock_positive_headroom(_REFERENCE, "network") == timedelta(0)
    assert planner.endpoint_clock_negative_headroom(_REFERENCE, "network") == timedelta(0)
