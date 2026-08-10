# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for generation workload estimation and explicit trusted overrides."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.generation.workload import WorkloadLimits, estimate_workload
from evidenceforge.models.exceptions import WorkloadLimitError
from evidenceforge.models.scenario import BeaconEventSpec, Scenario
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


def test_engine_rejects_unsupported_duration_before_generation(tmp_path: Path) -> None:
    """An authored long run fails before generator state or artifacts are allocated."""

    with pytest.raises(WorkloadLimitError, match="primary duration"):
        GenerationEngine(_long_scenario(), tmp_path / "output")

    assert not (tmp_path / "output").exists()


def test_engine_accepts_explicit_trusted_large_workload_override(tmp_path: Path) -> None:
    """The same reviewed workload can be admitted only through the explicit override."""

    engine = GenerationEngine(
        _long_scenario(),
        tmp_path / "output",
        allow_large_workload=True,
    )

    assert engine.allow_large_workload is True
    assert engine.workload_estimate.limit_violations


def test_validator_reports_error_or_override_info_for_same_workload() -> None:
    """CLI validation and runtime construction enforce one shared workload contract."""
    scenario = _long_scenario()

    rejected = ScenarioValidator(scenario).validate()
    accepted = ScenarioValidator(scenario, allow_large_workload=True).validate()

    assert any(issue.field_path == "workload" and issue.severity == "error" for issue in rejected)
    assert any(issue.field_path == "workload" and issue.severity == "info" for issue in accepted)


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
