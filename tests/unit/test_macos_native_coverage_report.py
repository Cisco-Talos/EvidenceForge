# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Ground truth explains authored aggregate births from retained canonical facts."""

from datetime import timedelta

import pytest

from evidenceforge.events.macos_native_coverage import (
    MacosNativeCoverage,
    MacosNativeHostCoverage,
    MacosProcessCoverageSummary,
)
from evidenceforge.generation.ground_truth import GroundTruthGenerator
from tests.unit.test_macos_installed_provisioning import _scenario


def test_authored_aggregate_coverage_is_derived_from_canonical_launch_annotation() -> None:
    minimal_scenario = _scenario()
    event = dict(
        type="process",
        time=minimal_scenario.time_window.start,
        actor="test_user",
        system="MAC-01",
        activity="Invented aggregate launch",
        storyline_cluster_id="launch",
        process_name="/bin/zsh",
        pid=123,
        native_process_model="aggregate_birth",
    )
    coverage = MacosNativeCoverage(
        hosts=(
            MacosNativeHostCoverage(
                hostname="MAC-01",
                source_profile="invented-profile",
                observations=(),
            ),
        )
    )
    generator = GroundTruthGenerator(minimal_scenario, [event], macos_native_coverage=coverage)
    first = generator.build_document()
    assert first == generator.build_document()
    host = first.macos_native_coverage.hosts[0]
    assert host.observations[0].phase == "aggregate_birth"
    assert host.observations[0].reason == "aggregate_birth_only"
    assert host.observations[0].count == 1
    assert host.authored_actions[0].storyline_cluster_id == "launch"
    assert first.events[0].attributes.native_process_model == "aggregate_birth"
    assert not coverage.hosts[0].observations


def test_unknown_launch_annotation_does_not_infer_aggregate_from_missing_native_rows() -> None:
    minimal_scenario = _scenario()
    event = dict(
        type="process",
        time=minimal_scenario.time_window.start,
        actor="test_user",
        system="MAC-01",
        activity="Unknown launch",
        process_name="/bin/zsh",
        pid=123,
    )
    coverage = MacosNativeCoverage(
        hosts=(
            MacosNativeHostCoverage(
                hostname="MAC-01",
                source_profile="invented-profile",
                observations=(),
            ),
        )
    )
    document = GroundTruthGenerator(
        minimal_scenario, [event], macos_native_coverage=coverage
    ).build_document()
    assert not document.macos_native_coverage.hosts[0].observations


@pytest.mark.parametrize("seconds,expected", [(-1, 0), (0, 1), (3600, 0)])
@pytest.mark.parametrize("microseconds", [0, 500000])
def test_aggregate_diagnostic_respects_independent_census_collection_window(
    seconds: int, expected: int, microseconds: int
) -> None:
    scenario = _scenario()
    scenario.time_window.duration = "1h"
    scenario.time_window.start += timedelta(microseconds=microseconds)
    start = scenario.time_window.start
    event = dict(
        type="process",
        time=start + timedelta(seconds=seconds),
        actor="test_user",
        system="MAC-01",
        activity="Invented aggregate launch",
        storyline_cluster_id="launch",
        process_name="/bin/zsh",
        pid=123,
        native_process_model="aggregate_birth",
    )
    census = MacosProcessCoverageSummary(
        window_start=start,
        window_end=start + timedelta(hours=1),
        expected_forks=0,
        expected_execs=expected,
        published_forks=0,
        published_execs=0,
        fork_identities_match=True,
        exec_identities_match=not expected,
        aggregate_births=expected,
        aggregate_examples=("/bin/zsh",) if expected else (),
        complete=not expected,
    )
    coverage = MacosNativeCoverage(
        scope="canonical_process_window",
        hosts=(
            MacosNativeHostCoverage(
                hostname="MAC-01",
                source_profile="invented-profile",
                observations=(),
                process_census=census,
            ),
        ),
    )
    result = GroundTruthGenerator(
        scenario, [event], macos_native_coverage=coverage
    ).build_document()
    assert (
        sum(item.count for item in result.macos_native_coverage.hosts[0].observations) == expected
    )
    assert len(result.events) == 1
    assert result.events[0].time == event["time"]
    assert result.events[0].emitted == bool(expected)
    if not expected:
        assert result.events[0].skipped_reason == "outside_collection_window"
