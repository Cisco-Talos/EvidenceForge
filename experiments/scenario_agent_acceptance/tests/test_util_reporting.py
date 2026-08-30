"""Redaction, bounds, atomic writes, integrity, and baseline tests."""

import json
from datetime import datetime
from pathlib import Path

import pytest

from experiments.scenario_agent_acceptance.models import (
    AcceptanceReport,
    AggregateMetrics,
    InputDigests,
)
from experiments.scenario_agent_acceptance.reporting import (
    baseline_from_report,
    compare_baseline,
    load_verified_report,
    write_report,
)
from experiments.scenario_agent_acceptance.util import (
    MAX_TEXT_BYTES,
    atomic_write_json,
    redact_text,
)


def _report() -> AcceptanceReport:
    aggregate = AggregateMetrics(
        sessions=0,
        passes=0,
        failures=0,
        infrastructure_errors=0,
        first_complete_draft_successes=0,
        total_validation_passes_to_zero=0,
        median_validation_passes_to_zero=None,
        maximum_validation_passes_to_zero=None,
        total_introduced_warnings=0,
        total_unexpected_warnings=0,
        repair_regressions=0,
        strict_violations=0,
        duration_seconds=0,
    )
    return AcceptanceReport(
        run_id="test",
        created_at=datetime.now().astimezone(),
        suite="full",
        source_commit="a" * 40,
        source_dirty=False,
        inputs=InputDigests(
            suite="1",
            prompt="2",
            skill="3",
            model="4",
            provider_cli="5",
            evidenceforge_wheel="6",
            harness="7",
        ),
        sessions=[],
        aggregate=aggregate,
        report_digest="",
    )


def test_redaction_removes_credentials_and_bounds_output() -> None:
    value = "api_key=secret Authorization: Bearer abc.def " + "x" * (MAX_TEXT_BYTES + 100)

    redacted = redact_text(value)

    assert "secret" not in redacted
    assert "abc.def" not in redacted
    assert len(redacted.encode()) <= MAX_TEXT_BYTES


def test_atomic_write_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "link.json"
    link.symlink_to(target)

    with pytest.raises(ValueError, match="symlink"):
        atomic_write_json(link, {"changed": True})


def test_report_tampering_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    write_report(path, _report())
    assert load_verified_report(path).report_digest
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["source_dirty"] = True
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="digest mismatch"):
        load_verified_report(path)


def test_baseline_ratchets_regressions() -> None:
    report = _report()
    baseline = baseline_from_report(report)
    regressed = report.model_copy(
        update={
            "aggregate": report.aggregate.model_copy(
                update={"total_introduced_warnings": 1, "repair_regressions": 1}
            )
        }
    )

    assert compare_baseline(regressed, baseline) == [
        "introduced warning count increased",
        "repair regression count increased",
    ]
