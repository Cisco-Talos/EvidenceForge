"""Cadence coordinator for explicit incremental checkpoint participants."""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Callable, Iterable

from .cadence import CheckpointCadence
from .errors import CheckpointError
from .models import (
    CheckpointCursor,
    CheckpointManifest,
    CheckpointRecovery,
    CheckpointStoreMetrics,
    SegmentReference,
)
from .participants import IncrementalCheckpointParticipant, ParticipantSeal
from .store import IncrementalCheckpointStore

logger = logging.getLogger(__name__)


class IncrementalCheckpointController:
    """Publish cadence points from explicit transactional state owners."""

    def __init__(
        self,
        *,
        store: IncrementalCheckpointStore,
        fingerprint: str,
        checkpoint_hours: int,
        resolved_scenario: bytes,
        run_id: str | None = None,
        next_sequence: int = 0,
        inherited_segments: tuple[SegmentReference, ...] = (),
        progress: Callable[[dict[str, float | int | str]], None] | None = None,
    ) -> None:
        self.store = store
        self.fingerprint = fingerprint
        self.cadence = CheckpointCadence(checkpoint_hours)
        self.resolved_scenario = bytes(resolved_scenario)
        self.run_id = run_id or uuid.uuid4().hex
        self.next_sequence = next_sequence
        self.inherited_segments = inherited_segments
        self.progress = progress

    @classmethod
    def for_recovery(
        cls,
        *,
        store: IncrementalCheckpointStore,
        recovery: CheckpointRecovery,
        fingerprint: str,
        resolved_scenario: bytes,
        checkpoint_hours: int | None = None,
        progress: Callable[[dict[str, float | int | str]], None] | None = None,
    ) -> IncrementalCheckpointController:
        """Continue sequence and segment ownership from one validated recovery point."""

        interval = (
            recovery.manifest.checkpoint_hours if checkpoint_hours is None else checkpoint_hours
        )
        return cls(
            store=store,
            fingerprint=fingerprint,
            checkpoint_hours=interval,
            resolved_scenario=resolved_scenario,
            run_id=recovery.manifest.run_id,
            next_sequence=recovery.manifest.sequence + 1,
            inherited_segments=recovery.manifest.segments,
            progress=progress,
        )

    def is_due(self, completed_simulated_hours: int) -> bool:
        """Return whether the cadence schedules this completed-hour boundary."""

        return self.cadence.is_due(completed_simulated_hours)

    @staticmethod
    def _participants(
        participants: Iterable[IncrementalCheckpointParticipant],
    ) -> tuple[IncrementalCheckpointParticipant, ...]:
        ordered = tuple(sorted(participants, key=lambda item: item.checkpoint_owner))
        owners = [participant.checkpoint_owner for participant in ordered]
        if len(owners) != len(set(owners)):
            raise ValueError("incremental checkpoint participant owners must be unique")
        return ordered

    def commit(
        self,
        *,
        cursor: CheckpointCursor,
        participants: Iterable[IncrementalCheckpointParticipant],
    ) -> CheckpointManifest:
        """Prepare all owners and atomically publish one cadence recovery point."""

        if not self.is_due(cursor.completed_simulated_hours):
            raise ValueError("checkpoint cursor is not scheduled by the configured cadence")
        ordered = self._participants(participants)
        sequence = self.next_sequence
        prepared: list[tuple[IncrementalCheckpointParticipant, ParticipantSeal]] = []
        started = time.perf_counter()
        metrics = CheckpointStoreMetrics()
        try:
            for participant in ordered:
                seal = participant.prepare_checkpoint(sequence)
                if seal.head.owner != participant.checkpoint_owner:
                    raise ValueError(
                        f"checkpoint participant {participant.checkpoint_owner!r} returned "
                        f"head owner {seal.head.owner!r}"
                    )
                if any(segment.owner != participant.checkpoint_owner for segment in seal.segments):
                    raise ValueError(
                        f"checkpoint participant {participant.checkpoint_owner!r} returned a "
                        "foreign segment"
                    )
                prepared.append((participant, seal))
            manifest = self.store.commit(
                sequence=sequence,
                run_id=self.run_id,
                run_fingerprint=self.fingerprint,
                checkpoint_hours=self.cadence.hours,
                cursor=cursor,
                resolved_scenario=self.resolved_scenario,
                inherited_segments=self.inherited_segments,
                new_segments=tuple(segment for _, seal in prepared for segment in seal.segments),
                heads=tuple(seal.head for _, seal in prepared),
                metadata={
                    "participant_owners": [
                        participant.checkpoint_owner for participant, _ in prepared
                    ]
                },
                metrics=metrics,
            )
        except BaseException:
            for participant, _ in reversed(prepared):
                participant.checkpoint_aborted(sequence)
            raise
        for participant, _ in prepared:
            participant.checkpoint_committed(sequence)
        self.next_sequence += 1
        self.inherited_segments = manifest.segments
        total_seconds = time.perf_counter() - started
        progress_data: dict[str, float | int | str] = {
            "checkpoint_seconds": total_seconds,
            "completed_simulated_hours": cursor.completed_simulated_hours,
            "head_bytes": metrics.head_bytes,
            "new_segment_bytes": metrics.new_segment_bytes,
            "phase": cursor.phase,
            "reused_segment_bytes": metrics.reused_segment_bytes,
            "sequence": sequence,
        }
        logger.info("Committed incremental generation checkpoint %s: %s", sequence, progress_data)
        if self.progress is not None:
            self.progress(progress_data)
        return manifest

    def restore_participants(
        self,
        *,
        recovery: CheckpointRecovery,
        participants: Iterable[IncrementalCheckpointParticipant],
    ) -> None:
        """Hydrate explicit owners from bounded heads and their immutable segments."""

        ordered = self._participants(participants)
        expected = set(recovery.manifest.metadata.get("participant_owners", []))
        actual = {participant.checkpoint_owner for participant in ordered}
        if expected != actual:
            raise CheckpointError(
                "checkpoint participant set is incompatible: "
                f"stored={sorted(expected)}, runtime={sorted(actual)}"
            )
        for participant in ordered:
            references = sorted(
                (
                    reference
                    for reference in recovery.manifest.segments
                    if reference.owner == participant.checkpoint_owner
                ),
                key=lambda reference: reference.owner_ordinal,
            )
            participant.restore_checkpoint(
                self.store.read_head(recovery, participant.checkpoint_owner),
                tuple(self.store.read_segment(reference) for reference in references),
            )
