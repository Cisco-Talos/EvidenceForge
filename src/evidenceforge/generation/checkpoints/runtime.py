"""Cadence coordinator for explicit incremental checkpoint participants."""

from __future__ import annotations

import logging
import uuid
from collections.abc import Iterable

from .cadence import CheckpointCadence
from .control import (
    SuspensionRequest,
    clear_controller_record,
    mark_suspended,
    publish_controller_record,
    read_suspension_request,
)
from .errors import CheckpointError
from .models import (
    CheckpointCursor,
    CheckpointManifest,
    CheckpointRecovery,
    SegmentCatalogReference,
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
        inherited_catalogs: tuple[SegmentCatalogReference, ...] = (),
        run_options: dict[str, object] | None = None,
        fingerprint_components: dict[str, object] | None = None,
        last_committed_cursor: CheckpointCursor | None = None,
    ) -> None:
        self.store = store
        self.fingerprint = fingerprint
        self.cadence = CheckpointCadence(checkpoint_hours)
        self.resolved_scenario = bytes(resolved_scenario)
        self.run_id = run_id or uuid.uuid4().hex
        self.next_sequence = next_sequence
        self.inherited_catalogs = inherited_catalogs
        self.run_options = {} if run_options is None else dict(run_options)
        self.fingerprint_components = (
            {} if fingerprint_components is None else dict(fingerprint_components)
        )
        self.last_committed_cursor = last_committed_cursor
        self.resolved_scenario_reference = self.store.persist_resolved_scenario(
            self.resolved_scenario
        )
        if self.cadence.hours > 0:
            publish_controller_record(
                self.store,
                run_id=self.run_id,
                checkpoint_hours=self.cadence.hours,
            )
        else:
            clear_controller_record(self.store)

    @classmethod
    def for_recovery(
        cls,
        *,
        store: IncrementalCheckpointStore,
        recovery: CheckpointRecovery,
        fingerprint: str,
        resolved_scenario: bytes,
        checkpoint_hours: int | None = None,
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
            inherited_catalogs=recovery.manifest.segment_catalogs,
            run_options=dict(recovery.manifest.metadata.get("run_options", {})),
            fingerprint_components=dict(
                recovery.manifest.metadata.get("fingerprint_components", {})
            ),
            last_committed_cursor=recovery.manifest.cursor,
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

    @staticmethod
    def _restore_participants(
        participants: Iterable[IncrementalCheckpointParticipant],
    ) -> tuple[IncrementalCheckpointParticipant, ...]:
        """Order hydration by explicit dependency priority, then stable owner name."""

        ordered = tuple(
            sorted(
                participants,
                key=lambda item: (
                    getattr(item, "checkpoint_restore_priority", 100),
                    item.checkpoint_owner,
                ),
            )
        )
        owners = [participant.checkpoint_owner for participant in ordered]
        if len(owners) != len(set(owners)):
            raise ValueError("incremental checkpoint participant owners must be unique")
        return ordered

    def commit(
        self,
        *,
        cursor: CheckpointCursor,
        participants: Iterable[IncrementalCheckpointParticipant],
        require_cadence: bool = True,
    ) -> CheckpointManifest:
        """Prepare all owners and atomically publish one recovery point."""

        if require_cadence and not self.is_due(cursor.completed_simulated_hours):
            raise ValueError("checkpoint cursor is not scheduled by the configured cadence")
        if self.cadence.hours == 0:
            raise ValueError("checkpoint publication is disabled")
        ordered = self._participants(participants)
        sequence = self.next_sequence
        prepared: list[tuple[IncrementalCheckpointParticipant, ParticipantSeal]] = []
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
                resolved_scenario_reference=self.resolved_scenario_reference,
                inherited_catalogs=self.inherited_catalogs,
                new_segments=tuple(segment for _, seal in prepared for segment in seal.segments),
                heads=tuple(seal.head for _, seal in prepared),
                metadata={
                    "participant_owners": [
                        participant.checkpoint_owner for participant, _ in prepared
                    ],
                    "run_options": self.run_options,
                    "fingerprint_components": self.fingerprint_components,
                },
            )
            self.last_committed_cursor = manifest.cursor
        except BaseException:
            for participant, _ in reversed(prepared):
                participant.checkpoint_aborted(sequence)
            raise
        for participant, _ in prepared:
            participant.checkpoint_committed(sequence)
        self.next_sequence += 1
        self.inherited_catalogs = manifest.segment_catalogs
        logger.info(
            "Committed incremental generation checkpoint %s at simulated hour %s",
            sequence,
            cursor.completed_simulated_hours,
        )
        return manifest

    def pending_suspension_request(self) -> SuspensionRequest | None:
        """Return a cooperative request observed by this controller, if any."""

        return read_suspension_request(self.store)

    def commit_suspension(
        self,
        *,
        request: SuspensionRequest,
        cursor: CheckpointCursor,
        participants: Iterable[IncrementalCheckpointParticipant],
    ) -> CheckpointManifest:
        """Publish an explicit off-cadence recovery and acknowledge planned suspension."""

        manifest = self.commit(
            cursor=cursor,
            participants=participants,
            require_cadence=False,
        )
        mark_suspended(self.store, request=request, cursor=cursor)
        return manifest

    def restore_participants(
        self,
        *,
        recovery: CheckpointRecovery,
        participants: Iterable[IncrementalCheckpointParticipant],
    ) -> None:
        """Hydrate explicit owners from bounded heads and their immutable segments."""

        ordered = self._restore_participants(participants)
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
                    for reference in recovery.segments
                    if reference.owner == participant.checkpoint_owner
                ),
                key=lambda reference: reference.owner_ordinal,
            )
            participant.restore_checkpoint(
                self.store.read_head(recovery, participant.checkpoint_owner),
                tuple(self.store.read_segment(reference) for reference in references),
            )
