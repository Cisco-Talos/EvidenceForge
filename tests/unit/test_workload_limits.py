# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for generation workload estimation without hard capacity rejection."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.generation.workload import WorkloadLimits, estimate_workload
from evidenceforge.models.scenario import (
    BeaconEventSpec,
    ProcessEventSpec,
    Scenario,
    StorylineEvent,
)
from evidenceforge.utils.files import load_yaml
from evidenceforge.validation import ScenarioValidator


def _minimal_scenario() -> Scenario:
    fixture = Path(__file__).parent.parent / "fixtures" / "scenarios" / "minimal.yaml"
    return Scenario(**load_yaml(fixture))


def _long_scenario() -> Scenario:
    scenario = _minimal_scenario()
    return scenario.model_copy(
        update={"time_window": scenario.time_window.model_copy(update={"duration": "32d"})}
    )


def test_engine_forecasts_unsupported_duration_without_rejecting(tmp_path: Path) -> None:
    """An authored long run is estimated and admitted without allocating output."""

    engine = GenerationEngine(_long_scenario(), tmp_path / "output")

    assert not (tmp_path / "output").exists()
    assert engine.workload_estimate.limit_violations
    assert engine.resource_forecast.memory.expected_bytes > 0


def test_engine_keeps_large_workload_keyword_as_compatibility_noop(tmp_path: Path) -> None:
    """Existing library callers may pass the old keyword without changing admission."""

    engine = GenerationEngine(
        _long_scenario(),
        tmp_path / "output",
        allow_large_workload=True,
    )

    assert engine.allow_large_workload is True
    assert engine.workload_estimate.limit_violations


def test_validator_does_not_report_static_workload_envelope_as_validation_issue() -> None:
    """Machine resource forecasts replace static workload validation errors."""
    scenario = _long_scenario()

    issues = ScenarioValidator(scenario).validate()
    compatibility_issues = ScenarioValidator(scenario, allow_large_workload=True).validate()

    assert not any(issue.field_path == "workload" for issue in issues)
    assert not any(issue.field_path == "workload" for issue in compatibility_issues)


def test_rendered_record_limit_uses_preallocation_estimate() -> None:
    """Rendered fan-out is bounded using integer estimates, not event allocation."""
    scenario = _minimal_scenario()
    estimate = estimate_workload(
        scenario,
        limits=WorkloadLimits(max_rendered_records=1),
    )

    assert estimate.rendered_records > 1
    assert any("rendered records" in violation for violation in estimate.limit_violations)


def test_periodic_rate_must_be_finite() -> None:
    """Infinite authored rates cannot reach workload arithmetic or generation loops."""

    with pytest.raises(ValidationError, match="rate must be finite"):
        BeaconEventSpec(dst_ip="198.51.100.10", rate=float("inf"), count=1)


def test_workload_estimate_counts_full_small_cidr_nmap_expansion() -> None:
    """A five-port /24 process command must reserve all 1,270 canonical probes."""

    base = _minimal_scenario()
    scenario = base.model_copy(
        update={
            "storyline": [
                StorylineEvent(
                    id="scan",
                    time="+10m",
                    actor="test_user",
                    system="TEST-01",
                    activity="Inventory scan",
                    events=[
                        ProcessEventSpec(
                            process_name="nmap",
                            command_line="nmap -sT -p 22,80,443,445,3306 10.10.2.0/24",
                        )
                    ],
                )
            ]
        }
    )

    estimate = estimate_workload(scenario)

    assert estimate.explicit_occurrences == 254 * 5
    assert estimate.canonical_occurrences >= estimate.explicit_occurrences * 8
    assert estimate.limit_violations == ()
