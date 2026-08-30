"""Completeness, loop, warning-churn, and drift negative controls."""

from pathlib import Path

import yaml

from experiments.scenario_agent_acceptance.cases import (
    incomplete_requirements,
    load_cases,
    load_yaml_document,
)
from experiments.scenario_agent_acceptance.metrics import (
    aggregate_sessions,
    calculate_session_metrics,
    repair_drift,
)
from experiments.scenario_agent_acceptance.models import (
    AgentName,
    NormalizedEvent,
    SessionMetrics,
    SessionResult,
    SessionStatus,
    ValidationAttempt,
)


def test_infrastructure_metric_defaults_are_constructible() -> None:
    metrics = SessionMetrics(duration_seconds=0.5)

    assert metrics.tool_calls == 0
    assert metrics.strict_violations == []


def test_all_eight_full_cases_have_unique_contracts() -> None:
    cases = load_cases("full")

    assert len(cases) == 8
    assert len({case.id for case in cases}) == 8
    assert all(case.required_references for case in cases)
    assert all(case.required_schema_selectors for case in cases)
    assert all(case.requirements for case in cases)


def test_controlled_repair_oracle_distinguishes_incomplete_and_good() -> None:
    case = next(case for case in load_cases("full") if case.id == "controlled_repair")
    root = Path(__file__).resolve().parents[3]
    invalid = load_yaml_document(root / case.starting_fixture)
    valid = load_yaml_document(root / case.known_good_fixture)

    assert incomplete_requirements(invalid, case)
    assert incomplete_requirements(valid, case) == []


def test_every_case_oracle_accepts_known_good_and_rejects_empty_fixture() -> None:
    fixture = Path(__file__).resolve().parents[1] / "fixtures" / "oracle_documents.yaml"
    documents = yaml.safe_load(fixture.read_text(encoding="utf-8"))

    for case in load_cases("full"):
        assert incomplete_requirements(documents[case.id], case) == []
        assert incomplete_requirements({}, case)


def test_metric_negative_controls_detect_all_strict_failures() -> None:
    case = load_cases("smoke")[0]
    attempts = [
        ValidationAttempt(
            sequence=1,
            scenario_digest="same",
            complete=True,
            exit_code=2,
            error_keys=["old"],
            warning_keys=["warning.old"],
        ),
        ValidationAttempt(
            sequence=2,
            scenario_digest="same",
            complete=True,
            exit_code=2,
            error_keys=["old"],
            warning_keys=["warning.old"],
        ),
        ValidationAttempt(
            sequence=3,
            scenario_digest="new",
            complete=True,
            exit_code=2,
            error_keys=["new"],
            warning_keys=["warning.new"],
        ),
    ]

    metrics = calculate_session_metrics(
        case=case,
        attempts=attempts,
        events=[NormalizedEvent(sequence=0, kind="tool_call", tool="shell")],
        terminal_valid=False,
        terminal_composition_valid=False,
        used_references=set(),
        used_schema_selectors=set(),
        repair_drift_paths=["storyline.0.actor"],
        forbidden_commands=["generate scenario.yaml"],
        ambient_accesses=["/tmp/ambient.yaml"],
        duration_seconds=1.0,
        interview_turns=2,
        question_discipline_violations=1,
    )

    assert metrics.unchanged_validation_loops == 1
    assert metrics.newly_introduced_errors == ["new"]
    assert metrics.introduced_warnings == ["warning.new"]
    assert set(metrics.strict_violations) == {
        "terminal_invalid",
        "terminal_composition_invalid",
        "unchanged_validation_loop",
        "required_reference_skipped",
        "required_schema_skipped",
        "repair_drift",
        "forbidden_command",
        "ambient_context_access",
    }


def test_repeated_validation_of_valid_yaml_is_not_a_loop() -> None:
    case = load_cases("smoke")[0]
    attempts = [
        ValidationAttempt(
            sequence=sequence,
            scenario_digest="valid",
            complete=True,
            exit_code=0,
            error_keys=[],
            warning_keys=["expected.warning"],
        )
        for sequence in (1, 2)
    ]

    metrics = calculate_session_metrics(
        case=case,
        attempts=attempts,
        events=[],
        terminal_valid=True,
        terminal_composition_valid=None,
        used_references=set(case.required_references),
        used_schema_selectors=set(case.required_schema_selectors),
        repair_drift_paths=[],
        forbidden_commands=[],
        ambient_accesses=[],
        duration_seconds=1.0,
        interview_turns=0,
        question_discipline_violations=0,
    )

    assert metrics.unchanged_validation_loops == 0
    assert "unchanged_validation_loop" not in metrics.strict_violations


def test_repair_drift_allows_only_named_subtrees() -> None:
    before = {"environment": {"service_accounts": [{"name": "svc"}]}, "name": "same"}
    allowed_after = {"environment": {"service_accounts": ["svc"]}, "name": "same"}
    drifted_after = {"environment": {"service_accounts": ["svc"]}, "name": "changed"}

    assert repair_drift(before, allowed_after, ["environment.service_accounts"]) == []
    assert repair_drift(before, drifted_after, ["environment.service_accounts"]) == ["name"]


def test_aggregate_keeps_behavioral_dimensions_separate() -> None:
    case = load_cases("smoke")[0]
    metrics = calculate_session_metrics(
        case=case,
        attempts=[],
        events=[],
        terminal_valid=True,
        terminal_composition_valid=None,
        used_references=set(case.required_references),
        used_schema_selectors=set(case.required_schema_selectors),
        repair_drift_paths=[],
        forbidden_commands=[],
        ambient_accesses=[],
        duration_seconds=2.0,
        interview_turns=0,
        question_discipline_violations=0,
    )
    session = SessionResult(
        case_id=case.id,
        agent=AgentName.CODEX,
        provider_version="codex-cli 0.147.0",
        model="gpt-5.6-sol",
        effort="medium",
        status=SessionStatus.PASS,
        metrics=metrics,
        transcript_path="transcript.jsonl",
        trace_path="trace.jsonl",
        final_scenario_path="scenario.yaml",
    )

    aggregate = aggregate_sessions([session])

    assert aggregate.passes == 1
    assert aggregate.duration_seconds == 2.0
    assert not hasattr(aggregate, "quality_score")
