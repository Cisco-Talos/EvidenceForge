"""Cadence coordinator for explicit incremental checkpoint participants."""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable, Iterable
from typing import Literal

from .cadence import CheckpointCadence
from .control import (
    SuspensionRequest,
    clear_controller_record,
    mark_suspended,
    new_suspension_request,
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


def _build_identity(components: object) -> dict[str, object]:
    """Return the bounded build identity recorded in recovery provenance."""

    if type(components) is not dict:
        return {}
    return {
        key: components[key]
        for key in ("evidenceforge_version", "evidenceforge_build_sha256")
        if key in components
    }


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
        recovery_store: IncrementalCheckpointStore | None = None,
        compatibility_level: Literal["exact", "load-compatible"] = "exact",
        resume_provenance: dict[str, object] | None = None,
        migration_published: Callable[[], None] | None = None,
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
        self.recovery_store = store if recovery_store is None else recovery_store
        self.compatibility_level = compatibility_level
        self.resume_provenance = {} if resume_provenance is None else dict(resume_provenance)
        self._migration_published = migration_published
        self.migration_required = compatibility_level == "load-compatible"
        self.restore_diagnostics: dict[str, object] = {}
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
        fingerprint_components: dict[str, object] | None = None,
        compatibility_level: Literal["exact", "load-compatible"] = "exact",
        recovery_store: IncrementalCheckpointStore | None = None,
        resume_policy: Literal["exact", "compatible", "attempt"] = "compatible",
        behavior_change: str = "exact",
        behavior_change_ids: tuple[str, ...] = (),
        runtime_differences: dict[str, dict[str, object]] | None = None,
        confirmation_status: str = "not-required",
        migration_published: Callable[[], None] | None = None,
    ) -> IncrementalCheckpointController:
        """Continue sequence and segment ownership from one validated recovery point."""

        interval = (
            recovery.manifest.checkpoint_hours if checkpoint_hours is None else checkpoint_hours
        )
        stored_components = recovery.manifest.metadata.get("fingerprint_components", {})
        current_components = (
            stored_components if fingerprint_components is None else fingerprint_components
        )
        stored_provenance = recovery.manifest.metadata.get("resume_provenance", {})
        provenance = dict(stored_provenance) if type(stored_provenance) is dict else {}
        transitions = provenance.get("transitions", [])
        transition_rows = list(transitions) if type(transitions) is list else []
        omitted = provenance.get("omitted_transition_count", 0)
        omitted_count = omitted if type(omitted) is int and omitted >= 0 else 0
        migration_value = provenance.get("migration_count", 0)
        migration_count = migration_value if type(migration_value) is int else 0
        transition_rows.append(
            {
                "classification": compatibility_level,
                "accepted_policy": resume_policy,
                "behavior_change": behavior_change,
                "behavior_change_ids": list(behavior_change_ids),
                "confirmation_status": confirmation_status,
                "cursor": recovery.manifest.cursor.model_dump(mode="json"),
                "from_fingerprint": recovery.manifest.run_fingerprint,
                "originating_build": _build_identity(stored_components),
                "resuming_build": _build_identity(current_components),
                "runtime_differences": ({} if runtime_differences is None else runtime_differences),
                "to_fingerprint": fingerprint,
            }
        )
        if len(transition_rows) > 8:
            omitted_count += len(transition_rows) - 8
            transition_rows = transition_rows[-8:]
        provenance = {
            "origin_build": provenance.get("origin_build", _build_identity(stored_components)),
            "origin_fingerprint": provenance.get(
                "origin_fingerprint", recovery.manifest.run_fingerprint
            ),
            "current_build": _build_identity(current_components),
            "current_fingerprint": fingerprint,
            "migration_count": migration_count + (compatibility_level == "load-compatible"),
            "omitted_transition_count": omitted_count,
            "transitions": transition_rows,
        }
        return cls(
            store=store,
            fingerprint=fingerprint,
            checkpoint_hours=interval,
            resolved_scenario=resolved_scenario,
            run_id=recovery.manifest.run_id,
            next_sequence=recovery.manifest.sequence + 1,
            inherited_catalogs=recovery.manifest.segment_catalogs,
            run_options=dict(recovery.manifest.metadata.get("run_options", {})),
            fingerprint_components=(
                dict(stored_components)
                if fingerprint_components is None
                else fingerprint_components
            ),
            last_committed_cursor=recovery.manifest.cursor,
            recovery_store=recovery_store,
            compatibility_level=compatibility_level,
            resume_provenance=provenance,
            migration_published=migration_published,
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
        allow_disabled: bool = False,
    ) -> CheckpointManifest:
        """Prepare all owners and atomically publish one recovery point."""

        if require_cadence and not self.is_due(cursor.completed_simulated_hours):
            raise ValueError("checkpoint cursor is not scheduled by the configured cadence")
        if self.cadence.hours == 0 and not allow_disabled:
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
            metadata: dict[str, object] = {
                "participant_owners": [participant.checkpoint_owner for participant, _ in prepared],
                "run_options": self.run_options,
                "fingerprint_components": self.fingerprint_components,
            }
            if self.resume_provenance:
                metadata["resume_provenance"] = self.resume_provenance
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
                metadata=metadata,
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

    def commit_local_suspension(
        self,
        *,
        cursor: CheckpointCursor,
        participants: Iterable[IncrementalCheckpointParticipant],
    ) -> CheckpointManifest:
        """Publish and acknowledge an in-process graceful suspension request."""

        return self.commit_suspension(
            request=new_suspension_request(),
            cursor=cursor,
            participants=participants,
        )

    def acknowledge_local_suspension(self, cursor: CheckpointCursor) -> None:
        """Mark a just-published cadence point as an in-process suspension."""

        mark_suspended(self.store, request=new_suspension_request(), cursor=cursor)

    def commit_migration(
        self,
        *,
        participants: Iterable[IncrementalCheckpointParticipant],
    ) -> CheckpointManifest | None:
        """Restamp a successfully hydrated build-only recovery before generation."""

        if not self.migration_required:
            return None
        cursor = self.last_committed_cursor
        if cursor is None:
            raise CheckpointError("compatible checkpoint migration has no committed cursor")
        manifest = self.commit(
            cursor=cursor,
            participants=participants,
            require_cadence=False,
            allow_disabled=True,
        )
        self.migration_required = False
        if self._migration_published is not None:
            self._migration_published()
        return manifest

    def restore_participants(
        self,
        *,
        recovery: CheckpointRecovery,
        participants: Iterable[IncrementalCheckpointParticipant],
        progress: Callable[[int, int, str], None] | None = None,
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
        heads = {head.owner: head for head in recovery.manifest.participant_heads}
        total = len(ordered)
        for index, participant in enumerate(ordered, start=1):
            head = heads.get(participant.checkpoint_owner)
            if head is None:
                raise CheckpointError(
                    f"checkpoint has no head for participant {participant.checkpoint_owner!r}"
                )
            if head.schema_version != participant.checkpoint_schema_version:
                raise CheckpointError(
                    f"checkpoint participant {participant.checkpoint_owner!r} schema is "
                    f"{head.schema_version!r}; runtime requires "
                    f"{participant.checkpoint_schema_version!r}"
                )
            references = sorted(
                (
                    reference
                    for reference in recovery.segments
                    if reference.owner == participant.checkpoint_owner
                ),
                key=lambda reference: reference.owner_ordinal,
            )
            incompatible_segments = sorted(
                {
                    reference.schema_version
                    for reference in references
                    if reference.schema_version != participant.checkpoint_schema_version
                }
            )
            if incompatible_segments:
                raise CheckpointError(
                    f"checkpoint participant {participant.checkpoint_owner!r} segment schemas "
                    f"are incompatible: {incompatible_segments}"
                )
            participant.restore_checkpoint(
                self.recovery_store.read_head(recovery, participant.checkpoint_owner),
                tuple(self.recovery_store.read_segment(reference) for reference in references),
            )
            if progress is not None:
                progress(index, total, participant.checkpoint_owner)
            diagnostics = getattr(participant, "last_restore_diagnostics", None)
            if diagnostics is not None:
                self.restore_diagnostics[participant.checkpoint_owner] = diagnostics
                dangling = getattr(diagnostics, "dangling_process_parents", ())
                dangling_count = getattr(diagnostics, "dangling_process_parent_count", 0)
                if dangling_count:
                    logger.warning(
                        "Restored %s retained processes whose parents aged out; examples=%s",
                        dangling_count,
                        list(dangling[:8]),
                    )
