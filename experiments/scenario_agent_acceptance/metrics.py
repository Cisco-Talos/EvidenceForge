"""Offline completeness, drift, and metric calculations."""

from __future__ import annotations

import statistics
from collections import defaultdict
from typing import Any

from .models import (
    AggregateMetrics,
    CaseDefinition,
    NormalizedEvent,
    SessionMetrics,
    SessionResult,
    ValidationAttempt,
)


def diff_paths(before: Any, after: Any, prefix: str = "") -> set[str]:
    """Return stable dotted paths whose values differ."""

    if type(before) is not type(after):
        return {prefix or "$"}
    if isinstance(before, dict):
        paths: set[str] = set()
        for key in sorted(set(before) | set(after)):
            child = f"{prefix}.{key}" if prefix else str(key)
            if key not in before or key not in after:
                paths.add(child)
            else:
                paths.update(diff_paths(before[key], after[key], child))
        return paths
    if isinstance(before, list):
        paths = set()
        for index in range(max(len(before), len(after))):
            child = f"{prefix}.{index}" if prefix else str(index)
            if index >= len(before) or index >= len(after):
                paths.add(child)
            else:
                paths.update(diff_paths(before[index], after[index], child))
        return paths
    return set() if before == after else {prefix or "$"}


def repair_drift(before: Any, after: Any, allowed: list[str]) -> list[str]:
    """Find changed paths outside explicitly repairable subtrees."""

    return sorted(
        path
        for path in diff_paths(before, after)
        if not any(path == root or path.startswith(f"{root}.") for root in allowed)
    )


def _warning_metrics(
    attempts: list[ValidationAttempt], allowed: set[str]
) -> tuple[list[str], list[str], list[str], list[str]]:
    complete = [attempt for attempt in attempts if attempt.complete]
    if not complete:
        return [], [], [], []
    first = set(complete[0].warning_keys)
    final = set(complete[-1].warning_keys)
    introduced = sorted(final - first)
    removed = sorted(first - final)
    retained = sorted(first & final)
    unexpected = sorted(final - allowed)
    return introduced, removed, retained, unexpected


def calculate_session_metrics(
    *,
    case: CaseDefinition,
    attempts: list[ValidationAttempt],
    events: list[NormalizedEvent],
    terminal_valid: bool,
    terminal_composition_valid: bool | None,
    used_references: set[str],
    used_schema_selectors: set[str],
    repair_drift_paths: list[str],
    forbidden_commands: list[str],
    ambient_accesses: list[str],
    duration_seconds: float,
    interview_turns: int,
    question_discipline_violations: int,
) -> SessionMetrics:
    """Build the non-LLM session scorecard and strict invariant list."""

    complete = [attempt for attempt in attempts if attempt.complete]
    first_valid = bool(complete and not complete[0].error_keys)
    passes_to_zero: int | None = None
    for index, attempt in enumerate(complete, start=1):
        if not attempt.error_keys:
            passes_to_zero = index
            break
    loops = sum(
        1
        for previous, current in zip(attempts, attempts[1:], strict=False)
        if previous.scenario_digest
        and previous.error_keys
        and previous.scenario_digest == current.scenario_digest
        and previous.error_keys == current.error_keys
        and previous.warning_keys == current.warning_keys
    )
    error_first_seen: dict[str, int] = {}
    for index, attempt in enumerate(complete):
        for key in attempt.error_keys:
            error_first_seen.setdefault(key, index)
    new_errors = sorted(key for key, index in error_first_seen.items() if index > 0)
    introduced, removed, retained, unexpected = _warning_metrics(
        attempts, set(case.allowed_warning_codes)
    )
    missing_references = sorted(set(case.required_references) - used_references)
    missing_selectors = sorted(set(case.required_schema_selectors) - used_schema_selectors)
    violations: list[str] = []
    if not terminal_valid:
        violations.append("terminal_invalid")
    if terminal_composition_valid is False:
        violations.append("terminal_composition_invalid")
    if loops:
        violations.append("unchanged_validation_loop")
    if missing_references:
        violations.append("required_reference_skipped")
    if missing_selectors:
        violations.append("required_schema_skipped")
    if repair_drift_paths:
        violations.append("repair_drift")
    if forbidden_commands:
        violations.append("forbidden_command")
    if ambient_accesses:
        violations.append("ambient_context_access")
    usage: defaultdict[str, int | float] = defaultdict(int)
    for event in events:
        for key, value in event.usage.items():
            usage[key] += value
    return SessionMetrics(
        terminal_valid=terminal_valid,
        terminal_composition_valid=terminal_composition_valid,
        first_complete_draft_valid=first_valid,
        validation_passes_to_zero_errors=passes_to_zero,
        unchanged_validation_loops=loops,
        required_references_used=sorted(used_references & set(case.required_references)),
        missing_references=missing_references,
        required_schema_selectors_used=sorted(
            used_schema_selectors & set(case.required_schema_selectors)
        ),
        missing_schema_selectors=missing_selectors,
        introduced_warnings=introduced,
        removed_warnings=removed,
        retained_warnings=retained,
        unexpected_warnings=unexpected,
        newly_introduced_errors=new_errors,
        repair_drift_paths=repair_drift_paths,
        interview_turns=interview_turns,
        question_discipline_violations=question_discipline_violations,
        forbidden_commands=forbidden_commands,
        ambient_accesses=ambient_accesses,
        duration_seconds=duration_seconds,
        tool_calls=sum(event.kind == "tool_call" for event in events),
        provider_usage=dict(sorted(usage.items())),
        strict_violations=violations,
    )


def aggregate_sessions(sessions: list[SessionResult]) -> AggregateMetrics:
    """Aggregate behavior without creating a composite quality score."""

    pass_counts = [
        session.metrics.validation_passes_to_zero_errors
        for session in sessions
        if session.metrics.validation_passes_to_zero_errors is not None
    ]
    usage: defaultdict[str, int | float] = defaultdict(int)
    for session in sessions:
        for key, value in session.metrics.provider_usage.items():
            usage[key] += value
    return AggregateMetrics(
        sessions=len(sessions),
        passes=sum(session.status.value == "PASS" for session in sessions),
        failures=sum(session.status.value == "FAIL" for session in sessions),
        infrastructure_errors=sum(
            session.status.value == "INFRASTRUCTURE_ERROR" for session in sessions
        ),
        first_complete_draft_successes=sum(
            session.metrics.first_complete_draft_valid for session in sessions
        ),
        total_validation_passes_to_zero=sum(pass_counts),
        median_validation_passes_to_zero=(statistics.median(pass_counts) if pass_counts else None),
        maximum_validation_passes_to_zero=max(pass_counts, default=None),
        total_introduced_warnings=sum(
            len(session.metrics.introduced_warnings) for session in sessions
        ),
        total_unexpected_warnings=sum(
            len(session.metrics.unexpected_warnings) for session in sessions
        ),
        repair_regressions=sum(bool(session.metrics.repair_drift_paths) for session in sessions),
        strict_violations=sum(len(session.metrics.strict_violations) for session in sessions),
        duration_seconds=sum(session.metrics.duration_seconds for session in sessions),
        provider_usage=dict(sorted(usage.items())),
    )
