"""Versioned deterministic facts retained independently of source collection."""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_serializer
from pydantic.functional_serializers import SerializerFunctionWrapHandler

GROUND_TRUTH_EVENTS_FILENAME = "GROUND_TRUTH_EVENTS.jsonl"


class GroundTruthRawExpectation(BaseModel):
    """A source-local raw receipt, separate from canonical occurrences."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal[1] = 1
    time: datetime
    format: str
    fields: dict[str, JsonValue]
    datetime_fields: list[str] = Field(default_factory=list)
    status: Literal["visible", "delayed", "dropped", "filtered", "out_of_window"]


class GroundTruthOutcome(BaseModel):
    """An operation result, independently of whether a source observed it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    result: Literal["completed", "prevented", "failed", "partial", "unknown"] = "completed"
    mechanism: str | None = None
    enforcing_entity: str | None = None
    operation: str | None = None
    stage: str | None = None
    reason: str | None = None


class GroundTruthObservation(BaseModel):
    """One exact source's observation or an explicit source-family absence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_instance: str
    source_host: str | None = None
    format: str
    status: Literal["observed", "not_observed"]
    reason: str | None = None
    observed_time: datetime | None = None
    identifiers: dict[str, str] = Field(default_factory=dict)


class GroundTruthCondition(BaseModel):
    """One independently inspectable stage of a source observation decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    stage: Literal[
        "deployment", "placement", "capability", "window", "loss", "source_filter", "export"
    ]
    state: Literal["eligible", "excluded", "unknown"]
    reason: str | None = None


class GroundTruthSourceExpectation(BaseModel):
    """Expected source evidence, never a claim that output was independently read."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    expectation_id: str
    source_instance: str
    source_host: str
    family: str
    format: str
    role: str
    phase: str
    connection_leg: str | None = None
    transaction_phase: str | None = None
    expected: Literal["present", "absent"]
    reason: str | None = None
    conditions: list[GroundTruthCondition] = Field(default_factory=list)
    identifiers: dict[str, str] = Field(default_factory=dict)
    requirements: list[dict[str, JsonValue]] = Field(default_factory=list)
    expected_time: datetime | None = None
    timing_tolerance_seconds: float = Field(default=2.0, ge=0, le=3600)
    provenance: dict[str, JsonValue] = Field(default_factory=dict)


class GroundTruthCoverageGap(BaseModel):
    """A missing source family/location without a fabricated source instance."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    family: str
    format: str
    location: str
    reason: Literal["source_not_deployed", "deployment_unknown", "source_not_configured"]
    restrictions: list[str] = Field(default_factory=list)


class GroundTruthExpectationContract(BaseModel):
    """Frozen run-level source policies used to verify source decisions."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal[1] = 1
    rules_version: Literal[1] = 1
    scenario_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    profile: str
    profile_settings: dict[str, JsonValue] = Field(default_factory=dict)
    sources: dict[str, dict[str, JsonValue]] = Field(default_factory=dict)
    source_rules: dict[str, JsonValue] = Field(default_factory=dict)


class GroundTruthExpectationSummary(BaseModel):
    """Configuration-sized source totals, distinct from evaluation matches."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    present: int = Field(default=0, ge=0)
    absent: int = Field(default=0, ge=0)
    coverage_gaps: int = Field(default=0, ge=0)
    by_source: dict[str, dict[str, int]] = Field(default_factory=dict)
    exclusion_reasons: dict[str, int] = Field(default_factory=dict)


class GroundTruthRelationship(BaseModel):
    """An execution-owned association, never a reverse-DNS inference."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: str
    facts: dict[str, JsonValue] = Field(default_factory=dict)


class GroundTruthSensorView(BaseModel):
    """One frozen sensor capture receipt, shared across its format expectations."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    sensor_identity: str
    profile: str
    path_role: str
    traffic: dict[str, JsonValue]
    files: list[dict[str, JsonValue]] = Field(default_factory=list)
    source_times: dict[str, datetime] = Field(default_factory=dict)
    visible_formats: list[str] = Field(default_factory=list)
    start_time: datetime | None = None
    close_time: datetime | None = None
    firewall_teardown_time: datetime | None = None
    firewall_teardown_observed: bool = False


class GroundTruthOccurrence(BaseModel):
    """One canonical occurrence plus separately accounted source observations."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1, 2] = 2
    occurrence_id: str
    action_id: str
    intent_id: str
    storyline_id: str
    section: Literal["storyline", "red_herring"]
    kind: str
    time: datetime
    facts: dict[str, JsonValue] = Field(default_factory=dict)
    outcome: GroundTruthOutcome = Field(default_factory=GroundTruthOutcome)
    observations: list[GroundTruthObservation] = Field(default_factory=list)
    source_expectations: list[GroundTruthSourceExpectation] = Field(default_factory=list)
    source_views: dict[str, GroundTruthSensorView] = Field(default_factory=dict)
    coverage_gaps: list[GroundTruthCoverageGap] = Field(default_factory=list)
    relationships: list[GroundTruthRelationship] = Field(default_factory=list)

    @model_serializer(mode="wrap")
    def serialize_occurrence(self, handler: SerializerFunctionWrapHandler) -> dict:
        """Retain legacy readers without exporting ambiguous observation claims in v2."""
        data = handler(self)
        if self.schema_version == 2:
            data.pop("observations", None)
        return data


class GroundTruthEventStream(BaseModel):
    """Integrity-bound detailed occurrence stream accompanying compact summaries."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1, 2] = 2
    path: Literal["GROUND_TRUTH_EVENTS.jsonl"] = GROUND_TRUTH_EVENTS_FILENAME
    count: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


def read_ground_truth_occurrences(
    root: Path,
    reference: GroundTruthEventStream,
) -> Iterator[GroundTruthOccurrence]:
    """Stream bounded validated records and verify the complete file binding."""
    path = root / reference.path
    if path.is_symlink() or not path.is_file():
        raise ValueError("Canonical ground-truth occurrence sidecar is missing or a symlink")
    digest = hashlib.sha256()
    count = 0
    previous: tuple[datetime, str] | None = None
    with path.open("rb") as stream:
        while data := stream.readline(1_048_577):
            if len(data) > 1_048_576:
                raise ValueError("Canonical ground-truth occurrence exceeds the record limit")
            digest.update(data)
            row = GroundTruthOccurrence.model_validate_json(data)
            if row.schema_version != reference.schema_version:
                raise ValueError("Canonical occurrence schema differs from its stream reference")
            key = (row.time, row.occurrence_id)
            if previous is not None and key <= previous:
                raise ValueError("Canonical ground-truth occurrences are duplicated or unordered")
            previous = key
            count += 1
            yield row
    if count != reference.count or digest.hexdigest() != reference.sha256:
        raise ValueError("Canonical ground-truth occurrence count or digest mismatch")
