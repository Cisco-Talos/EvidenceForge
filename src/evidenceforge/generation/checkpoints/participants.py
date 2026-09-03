"""Explicit contracts for incremental checkpoint state owners."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable

from .store import HeadDraft, SegmentDraft

CheckpointStateDisposition = Literal[
    "bounded-live-head",
    "immutable-incremental-segments",
    "deterministically-rebuilt",
    "transient-empty-at-barrier",
]


@dataclass(frozen=True)
class OwnerStateField:
    """Structural classification for one mutable or rebuildable owner field."""

    name: str
    disposition: CheckpointStateDisposition


@dataclass(frozen=True)
class ParticipantSeal:
    """New immutable delta and bounded live head sealed at one barrier."""

    head: HeadDraft
    segments: tuple[SegmentDraft, ...] = ()


@runtime_checkable
class IncrementalCheckpointParticipant(Protocol):
    """One owner that persists without a generic object-graph fallback."""

    checkpoint_owner: str
    checkpoint_schema_version: str
    checkpoint_state_fields: tuple[OwnerStateField, ...]

    def prepare_checkpoint(self, sequence: int) -> ParticipantSeal:
        """Freeze an idempotent delta and bounded head without advancing its watermark."""

    def checkpoint_committed(self, sequence: int) -> None:
        """Advance the participant delta watermark after durable manifest publication."""

    def checkpoint_aborted(self, sequence: int) -> None:
        """Release a prepared seal while retaining every uncommitted mutation."""

    def restore_checkpoint(self, head: bytes, segments: tuple[bytes, ...]) -> None:
        """Restore semantic state and rebuild all derived runtime infrastructure."""
