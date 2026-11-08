"""Saved native coverage stays distinct from generic evaluation acceptance."""

from datetime import UTC, datetime

import pytest
from fastapi import HTTPException

from evidenceforge.evaluation.models import PillarScore, QualityReport
from evidenceforge.studio.service import _scorecard_macos_hosts


def test_scorecard_keeps_unknown_and_unmeasured_exit_outcomes_distinct() -> None:
    census = {
        "window_start": "2026-11-02T13:00:00Z",
        "window_end": "2026-11-02T14:00:00Z",
        "expected_forks": 3,
        "published_forks": 3,
        "expected_execs": 4,
        "published_execs": 4,
        "fork_identities_match": True,
        "exec_identities_match": True,
        "aggregate_births": 0,
        "aggregate_examples": [],
        "complete": True,
    }
    report = QualityReport(
        scenario_name="invented",
        evaluated_at=datetime(2026, 11, 6, tzinfo=UTC),
        acceptance_passed=True,
        pillars=[
            PillarScore(
                number=3,
                name="Causality",
                weight=0.2,
                supplementary={
                    "macos_native_coverage": {
                        "schema_version": 3,
                        "policy": "partial",
                        "hosts": [
                            {
                                "hostname": "MAC",
                                "source_profile": "invented-v11",
                                "observations": [],
                                "process_census": census
                                | {
                                    "expected_exits": 3,
                                    "observed_exits": 3,
                                    "known_exits": 2,
                                    "published_exits": 2,
                                    "exit_complete": False,
                                },
                            },
                            {
                                "hostname": "OLD",
                                "source_profile": "historical",
                                "observations": [],
                                "process_census": census,
                            },
                        ],
                    }
                },
            )
        ],
    )
    current, old = _scorecard_macos_hosts(report)
    assert current.policy == "partial" and current.census.complete
    assert current.census.observed_exits - current.census.known_exits == 1
    assert current.census.exit_complete is False
    assert old.census.known_exits is None and old.census.exit_complete is None
    assert report.acceptance_passed is True


def test_scorecard_without_native_coverage_has_no_fabricated_hosts() -> None:
    report = QualityReport(scenario_name="old", evaluated_at=datetime(2026, 11, 6, tzinfo=UTC))
    assert _scorecard_macos_hosts(report) == []
    report.pillars = [
        PillarScore(
            number=3,
            name="Causality",
            weight=0.2,
            supplementary={"macos_native_coverage": {"hosts": [{"hostname": "MAC"}]}},
        )
    ]
    with pytest.raises(HTTPException, match="invalid") as error:
        _scorecard_macos_hosts(report)
    assert error.value.status_code == 422
