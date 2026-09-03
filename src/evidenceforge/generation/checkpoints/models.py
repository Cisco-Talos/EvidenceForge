"""Versioned inert models for incremental generation checkpoints."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

CHECKPOINT_SCHEMA_VERSION = "1.0"
SHA256_PATTERN = r"^[0-9a-f]{64}$"


class CheckpointCursor(BaseModel):
    """Exact resumable position after one completed simulated hour."""

    phase: Literal["warmup", "collection", "tail"]
    completed_simulated_hours: int = Field(ge=1)
    next_hour: str | None = None

    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="after")
    def validate_next_hour(self) -> CheckpointCursor:
        """Require another hour for active phases and none after collection."""

        if self.phase in {"warmup", "collection"} and self.next_hour is None:
            raise ValueError(f"{self.phase} checkpoints require next_hour")
        if self.phase == "tail" and self.next_hour is not None:
            raise ValueError("tail checkpoints cannot name a next hour")
        return self


class SegmentReference(BaseModel):
    """One immutable content-addressed participant or spool segment."""

    owner: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9_.-]+$")
    schema_version: str = Field(min_length=1, max_length=32)
    owner_ordinal: int = Field(ge=0)
    sha256: str = Field(pattern=SHA256_PATTERN)
    relative_path: str = Field(min_length=1)
    size: int = Field(ge=0)
    record_count: int = Field(ge=0)
    codec: Literal["stdlib-packed-v1"] = "stdlib-packed-v1"
    compression: Literal["none", "zlib-1"] = "none"

    model_config = ConfigDict(extra="forbid", frozen=True)


class ParticipantHead(BaseModel):
    """Bounded live state for one explicit checkpoint participant."""

    owner: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9_.-]+$")
    schema_version: str = Field(min_length=1, max_length=32)
    relative_path: str = Field(min_length=1)
    size: int = Field(ge=0)
    sha256: str = Field(pattern=SHA256_PATTERN)
    referenced_segments: tuple[str, ...] = ()

    model_config = ConfigDict(extra="forbid", frozen=True)


class CheckpointManifest(BaseModel):
    """Human-readable commit record written last for one recovery point."""

    kind: Literal["evidenceforge.incremental-generation-checkpoint"] = (
        "evidenceforge.incremental-generation-checkpoint"
    )
    schema_version: Literal["1.0"] = CHECKPOINT_SCHEMA_VERSION
    sequence: int = Field(ge=0)
    run_id: str = Field(min_length=1)
    run_fingerprint: str = Field(pattern=SHA256_PATTERN)
    checkpoint_hours: int = Field(gt=0)
    cursor: CheckpointCursor
    resolved_scenario_sha256: str = Field(pattern=SHA256_PATTERN)
    resolved_scenario_relative_path: str = Field(min_length=1)
    segments: tuple[SegmentReference, ...] = ()
    participant_heads: tuple[ParticipantHead, ...] = ()
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="forbid", frozen=True)

    @model_validator(mode="after")
    def validate_unique_owners_and_segments(self) -> CheckpointManifest:
        """Reject ambiguous heads, duplicate paths, and conflicting segment digests."""

        owners = [head.owner for head in self.participant_heads]
        if len(owners) != len(set(owners)):
            raise ValueError("checkpoint participant head owners must be unique")
        paths = [
            self.resolved_scenario_relative_path,
            *(segment.relative_path for segment in self.segments),
            *(head.relative_path for head in self.participant_heads),
        ]
        if len(paths) != len(set(paths)):
            raise ValueError("checkpoint object paths must be unique")
        by_digest: dict[str, SegmentReference] = {}
        owner_ordinals: dict[str, list[int]] = {}
        for segment in self.segments:
            previous = by_digest.setdefault(segment.sha256, segment)
            if previous != segment:
                raise ValueError("one segment digest cannot describe conflicting objects")
            owner_ordinals.setdefault(segment.owner, []).append(segment.owner_ordinal)
        for owner, ordinals in owner_ordinals.items():
            if len(ordinals) != len(set(ordinals)) or ordinals != sorted(ordinals):
                raise ValueError(f"checkpoint participant {owner!r} has invalid segment ordinals")
        known = set(by_digest)
        for head in self.participant_heads:
            missing = set(head.referenced_segments) - known
            if missing:
                raise ValueError(
                    f"participant {head.owner!r} references unknown segments: {sorted(missing)}"
                )
        return self


class CheckpointRecovery(BaseModel):
    """Validated recovery point selected from newest then previous."""

    checkpoint_directory: str
    manifest: CheckpointManifest
    used_fallback: bool = False
    warning: str | None = None

    model_config = ConfigDict(extra="forbid", frozen=True)


class CheckpointStoreMetrics(BaseModel):
    """Bounded work performed while publishing an incremental checkpoint."""

    emitter_quiesce_seconds: float = Field(default=0.0, ge=0.0)
    barrier_prepare_seconds: float = Field(default=0.0, ge=0.0)
    participant_prepare_seconds: float = Field(default=0.0, ge=0.0)
    participant_commit_seconds: float = Field(default=0.0, ge=0.0)
    new_segment_bytes: int = Field(default=0, ge=0)
    reused_segment_bytes: int = Field(default=0, ge=0)
    head_bytes: int = Field(default=0, ge=0)
    manifest_bytes: int = Field(default=0, ge=0)
    bytes_read: int = Field(default=0, ge=0)
    bytes_hashed: int = Field(default=0, ge=0)
    reused_segment_bytes_read: int = Field(default=0, ge=0)
    reused_segment_bytes_hashed: int = Field(default=0, ge=0)
    segment_encode_seconds: float = Field(default=0.0, ge=0.0)
    compression_seconds: float = Field(default=0.0, ge=0.0)
    hashing_seconds: float = Field(default=0.0, ge=0.0)
    segment_write_seconds: float = Field(default=0.0, ge=0.0)
    head_write_seconds: float = Field(default=0.0, ge=0.0)
    manifest_write_seconds: float = Field(default=0.0, ge=0.0)
    atomic_publish_seconds: float = Field(default=0.0, ge=0.0)
    index_publish_seconds: float = Field(default=0.0, ge=0.0)
    rotation_seconds: float = Field(default=0.0, ge=0.0)
    commit_seconds: float = Field(default=0.0, ge=0.0)
    foreground_pause_seconds: float = Field(default=0.0, ge=0.0)

    model_config = ConfigDict(extra="forbid")
