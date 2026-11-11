"""Validate process timing against canonical identities and independent source anchors."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from itertools import chain
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from evidenceforge.evaluation.storage import bounded_map
from evidenceforge.events.ground_truth_occurrence import (
    GroundTruthOccurrence,
    GroundTruthSourceExpectation,
)
from evidenceforge.generation.activity.timing_profiles import load_timing_profiles

if TYPE_CHECKING:
    from evidenceforge.evaluation.ground_truth_agreement import _RecordIndex


class TimingAnchor(BaseModel):
    """One predecessor already admitted by the source timing owner."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    kind: Literal[
        "process_create",
        "preferred_create",
        "process_frontier",
        "parent_create",
        "previous_execution",
        "session_login",
    ]
    identity: str
    time: datetime
    logon_id: str | None = None

    @field_validator("time")
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        """Reject an ambiguous predecessor clock."""
        if value.tzinfo is None:
            raise ValueError("Timing dependencies require an aware timestamp")
        return value


class ProcessTimingReceipt(BaseModel):
    """Bounded timing witness retained without introducing another random decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal[1]
    phase: str
    object_id: str
    execution_id: str
    canonical_time: datetime
    native_time: datetime
    policy: str
    anchors: list[TimingAnchor] = Field(max_length=8)

    @field_validator("canonical_time", "native_time")
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        """Reject an ambiguous receipt clock."""
        if value.tzinfo is None:
            raise ValueError("Timing receipts require aware timestamps")
        return value


class TimingPoints:
    """Exact existence proofs retaining at most two distinct owners per clock/key."""

    def __init__(self) -> None:
        self.values = bounded_map()

    def add(self, key: tuple[str, str], at: datetime, occurrence_id: str) -> None:
        identity = (*key, at)
        previous = self.values.get(identity, ())
        if occurrence_id not in previous and len(previous) < 2:
            self.values[identity] = (*previous, occurrence_id)

    def has_other(self, key: tuple[str, str], at: datetime, occurrence_id: str) -> bool:
        return any(owner != occurrence_id for owner in self.values.get((*key, at), ()))


type CanonicalTimingPoints = TimingPoints | Mapping[tuple[str, str], Sequence[tuple[datetime, str]]]


def _canonical_anchor_exists(
    points: CanonicalTimingPoints,
    key: tuple[str, str],
    at: datetime,
    occurrence_id: str,
) -> bool:
    if isinstance(points, TimingPoints):
        return points.has_other(key, at, occurrence_id)
    return any(owner != occurrence_id and point == at for point, owner in points.get(key, ()))


def verify_process_timing(
    row: GroundTruthOccurrence,
    expectation: GroundTruthSourceExpectation,
    index: _RecordIndex,
    points: CanonicalTimingPoints,
) -> list[str]:
    """Verify identity, predecessor existence, acyclic ordering and policy bounds."""
    payload = expectation.provenance.get("timing")
    if not payload:
        return []  # Historical limits still apply; this does not excuse a long delay.
    try:
        receipt = ProcessTimingReceipt.model_validate(payload)
    except ValidationError:
        return ["invalid_process_timing_provenance"]
    process = row.facts.get("process") or {}
    actor = row.facts.get("actor_process") or {}
    transition = row.facts.get("process_transition") or {}
    policy = (
        "source.ecar_process_create"
        if row.kind in {"process_create", "system_process_create", "process_fork"}
        else "source.ecar_process_terminate"
        if row.kind == "process_terminate"
        else "source.ecar_dependent_after_process_create"
    )
    errors = []
    if (
        receipt.phase != row.kind
        or receipt.canonical_time != row.time
        or receipt.object_id != process.get("object_id")
        or receipt.execution_id != process.get("execution_id")
        or receipt.policy != policy
        or expectation.expected_time is None
        # Runtime-owned endpoint receipts name the final visible timestamp,
        # after observation delay and lifecycle constraints have been applied.
        or abs((expectation.expected_time - receipt.native_time).total_seconds()) > 0.000001
    ):
        errors.append("process_timing_identity_disagreement")
    rules = load_timing_profiles().get("relationships", {})
    maximum = float(rules.get(policy, {}).get("max_ms", 100)) / 1000 + 0.008
    upper = row.time.timestamp() + 2
    seen = set()
    for anchor in receipt.anchors:
        key = (anchor.kind, anchor.identity, anchor.time)
        if key in seen or anchor.time.tzinfo is None or anchor.time >= receipt.native_time:
            errors.append("invalid_timing_dependency_order")
            continue
        seen.add(key)
        expected_identity = (
            actor.get("object_id")
            if anchor.kind == "parent_create"
            else transition.get("previous_execution_id")
            if anchor.kind == "previous_execution"
            else (row.facts.get("lifecycle") or {}).get("parent_group_id")
            if anchor.kind == "session_login"
            else process.get("object_id")
        )
        if anchor.identity != expected_identity:
            errors.append("invalid_timing_dependency_identity")
            continue
        native_key = anchor.logon_id if anchor.kind == "session_login" else anchor.identity
        field = (
            "logon_id"
            if anchor.kind == "session_login"
            else "execution_id"
            if anchor.kind == "previous_execution"
            else "objectID"
        )
        if anchor.kind == "session_login" and anchor.logon_id != process.get("logon_id"):
            errors.append("invalid_timing_dependency_identity")
            continue
        point_kind = (
            "session"
            if anchor.kind == "session_login"
            else "exec"
            if anchor.kind == "previous_execution"
            else "frontier"
            if anchor.kind == "process_frontier"
            else "create"
        )
        canonical = _canonical_anchor_exists(
            points,
            (expectation.source_instance, point_kind + ":" + str(native_key)),
            anchor.time,
            row.occurrence_id,
        )
        records = index.identity_at(
            "ecar", index.host(expectation.source_host), field, str(native_key), anchor.time
        )
        if anchor.kind == "process_frontier":
            canonical |= _canonical_anchor_exists(
                points,
                (expectation.source_instance, "children:" + anchor.identity),
                anchor.time,
                row.occurrence_id,
            )
            records = chain(
                records,
                index.identity_at(
                    "ecar",
                    index.host(expectation.source_host),
                    "pid",
                    str(process.get("pid")),
                    anchor.time,
                ),
                (
                    record
                    for record in index.identity_at(
                        "ecar",
                        index.host(expectation.source_host),
                        "ppid",
                        str(process.get("pid")),
                        anchor.time,
                    )
                    if record.fields.get("object") == "PROCESS"
                    and record.fields.get("action") == "CREATE"
                ),
            )
        preferred = anchor.kind == "preferred_create" or (
            anchor.kind == "process_create"
            and row.kind in {"process_create", "process_fork", "system_process_create"}
        )
        if preferred:
            canonical = -2 <= (anchor.time - row.time).total_seconds() <= maximum
        observed = any(
            index.time(record) is not None
            and abs((index.time(record) - anchor.time).total_seconds()) < 0.001
            and (
                anchor.kind not in {"parent_create", "process_create"}
                or record.fields.get("action") == "CREATE"
            )
            and (anchor.kind != "session_login" or record.fields.get("action") == "LOGIN")
            for record in records
        )
        inherited_entity = False
        if anchor.kind == "parent_create" and actor.get("start_time"):
            entity_start = datetime.fromisoformat(str(actor["start_time"]))
            inherited_entity = (
                entity_start.tzinfo is not None
                and -2 <= (anchor.time - entity_start).total_seconds() <= 2
                and entity_start < row.time
            )
        if not canonical and not observed and not inherited_entity:
            errors.append("unverifiable_timing_dependency")
            continue
        extra = 0.0
        if row.kind == "process_terminate" and anchor.kind == "process_create":
            start = process.get("start_time")
            extra = (
                max(0, (row.time - datetime.fromisoformat(start)).total_seconds()) if start else 0
            )
        upper = max(upper, anchor.time.timestamp() + maximum + extra)
    if not row.time.timestamp() - 2 <= receipt.native_time.timestamp() <= upper:
        errors.append("unjustified_source_time")
    return sorted(set(errors))
