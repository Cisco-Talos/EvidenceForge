"""Pydantic contracts for the experimental scenario-agent harness."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

HARNESS_SCHEMA_VERSION = "1.0"


class StrictModel(BaseModel):
    """Base model that rejects silent contract drift."""

    model_config = ConfigDict(extra="forbid")


class AgentName(StrEnum):
    """Supported live authoring providers."""

    CODEX = "codex"
    CLAUDE = "claude"


class SessionStatus(StrEnum):
    """Terminal result of one case/agent session."""

    PASS = "PASS"
    FAIL = "FAIL"
    INFRASTRUCTURE_ERROR = "INFRASTRUCTURE_ERROR"


class OracleRequirement(StrictModel):
    """One deterministic completeness predicate."""

    id: str
    path: str
    predicate: Literal["exists", "equals", "contains", "min_items", "any_equals"]
    expected: Any = None


class CaseDefinition(StrictModel):
    """One controlled authoring or repair case."""

    case_schema_version: Literal["1.0"] = "1.0"
    id: str
    title: str
    suites: list[Literal["smoke", "full"]]
    mode: Literal["author", "repair"]
    prompt: str
    scenario_path: str = "scenario.yaml"
    starting_fixture: str | None = None
    known_good_fixture: str | None = None
    required_references: list[str] = Field(default_factory=list)
    required_schema_selectors: list[str] = Field(default_factory=list)
    requirements: list[OracleRequirement] = Field(default_factory=list)
    allowed_warning_codes: list[str] = Field(default_factory=list)
    allowed_repair_paths: list[str] = Field(default_factory=list)
    scripted_answers: list[str] = Field(default_factory=list)

    @field_validator("scenario_path", "starting_fixture", "known_good_fixture")
    @classmethod
    def relative_paths_only(cls, value: str | None) -> str | None:
        """Reject absolute and parent-traversing fixture paths."""

        if value is None:
            return value
        path = Path(value)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("case paths must remain relative to the experiment directory")
        return value


class NormalizedEvent(StrictModel):
    """Provider-independent transcript event."""

    sequence: int = Field(ge=0)
    kind: Literal["session", "message", "tool_call", "tool_result", "usage"]
    tool: str | None = None
    input: dict[str, Any] = Field(default_factory=dict)
    output: str | None = None
    session_id: str | None = None
    usage: dict[str, int | float] = Field(default_factory=dict)


class ValidationAttempt(StrictModel):
    """Normalized observation of one agent-requested validation."""

    sequence: int = Field(ge=0)
    scenario_digest: str | None = None
    complete: bool = False
    exit_code: int
    error_keys: list[str] = Field(default_factory=list)
    warning_keys: list[str] = Field(default_factory=list)


class SessionMetrics(StrictModel):
    """Deterministic scorecard for one session."""

    terminal_valid: bool = False
    terminal_composition_valid: bool | None = None
    first_complete_draft_valid: bool = False
    validation_passes_to_zero_errors: int | None = None
    unchanged_validation_loops: int = 0
    required_references_used: list[str] = Field(default_factory=list)
    missing_references: list[str] = Field(default_factory=list)
    required_schema_selectors_used: list[str] = Field(default_factory=list)
    missing_schema_selectors: list[str] = Field(default_factory=list)
    introduced_warnings: list[str] = Field(default_factory=list)
    removed_warnings: list[str] = Field(default_factory=list)
    retained_warnings: list[str] = Field(default_factory=list)
    unexpected_warnings: list[str] = Field(default_factory=list)
    newly_introduced_errors: list[str] = Field(default_factory=list)
    repair_drift_paths: list[str] = Field(default_factory=list)
    interview_turns: int = 0
    question_discipline_violations: int = 0
    forbidden_commands: list[str] = Field(default_factory=list)
    ambient_accesses: list[str] = Field(default_factory=list)
    duration_seconds: float = Field(ge=0)
    tool_calls: int = Field(default=0, ge=0)
    provider_usage: dict[str, int | float] = Field(default_factory=dict)
    strict_violations: list[str] = Field(default_factory=list)


class SessionResult(StrictModel):
    """Complete result for one case/agent execution."""

    case_id: str
    agent: AgentName
    provider_version: str
    model: str
    effort: str
    isolation: Literal["session-isolated"] = "session-isolated"
    status: SessionStatus
    metrics: SessionMetrics
    transcript_path: str
    transcript_digest: str | None = None
    trace_path: str
    trace_digest: str | None = None
    final_scenario_path: str
    final_scenario_digest: str | None = None
    infrastructure_error: str | None = None


class AggregateMetrics(StrictModel):
    """Aggregate regression signals stored in reports and baselines."""

    sessions: int
    passes: int
    failures: int
    infrastructure_errors: int
    first_complete_draft_successes: int
    total_validation_passes_to_zero: int
    median_validation_passes_to_zero: float | None
    maximum_validation_passes_to_zero: int | None
    total_introduced_warnings: int
    total_unexpected_warnings: int
    repair_regressions: int
    strict_violations: int
    duration_seconds: float
    provider_usage: dict[str, int | float] = Field(default_factory=dict)


class InputDigests(StrictModel):
    """Immutable identities for inputs that affect a run."""

    suite: str
    prompt: str
    skill: str
    model: str
    provider_cli: str
    evidenceforge_wheel: str
    harness: str


class AcceptanceReport(StrictModel):
    """Portable report; transcripts remain separate artifacts."""

    report_schema_version: Literal["1.0"] = "1.0"
    run_id: str
    created_at: datetime
    suite: Literal["smoke", "full"]
    isolation: Literal["session-isolated"] = "session-isolated"
    source_commit: str
    source_dirty: bool
    inputs: InputDigests
    sessions: list[SessionResult]
    aggregate: AggregateMetrics
    report_digest: str


class ExperimentalBaseline(StrictModel):
    """Compact aggregate-only experimental baseline."""

    baseline_schema_version: Literal["1.0"] = "1.0"
    created_at: datetime
    source_report_digest: str
    suite: Literal["smoke", "full"]
    inputs: InputDigests
    aggregate: AggregateMetrics
