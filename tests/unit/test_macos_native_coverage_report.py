# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Ground truth explains authored aggregate births from retained canonical facts."""

from evidenceforge.events.macos_native_coverage import (
    MacosNativeCoverage,
    MacosNativeHostCoverage,
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
