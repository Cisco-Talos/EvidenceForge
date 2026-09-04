"""Bounded checkpoint head for dispatcher observation-reporting state."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.observation import ObservationSummary

from .errors import CheckpointCorruptionError
from .packed import dumps, loads
from .participants import OwnerStateField, ParticipantSeal
from .store import HeadDraft

_SCHEMA_VERSION = "1"


class _DispatcherObservationHead(BaseModel):
    """Validated envelope for source-observation report aggregates."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str
    source_evidence_version: int = Field(ge=0)
    summaries: list[list[object]] = Field(default_factory=list)


class DispatcherObservationParticipant:
    """Persist cumulative observation summaries used by deterministic sidecars."""

    checkpoint_owner = "dispatcher-observation-reporting"
    checkpoint_restore_priority = 30
    checkpoint_schema_version = _SCHEMA_VERSION
    checkpoint_state_fields = (
        OwnerStateField("_source_evidence_status", "bounded-live-head"),
        OwnerStateField("_source_evidence_version", "bounded-live-head"),
        OwnerStateField("_source_evidence_lock", "deterministically-rebuilt"),
    )

    def __init__(self, dispatcher: EventDispatcher) -> None:
        self.dispatcher = dispatcher

    def prepare_checkpoint(self, sequence: int) -> ParticipantSeal:
        """Capture stable cumulative source-observation counters."""

        del sequence
        with self.dispatcher._source_evidence_lock:
            rows = [
                [
                    cluster_id,
                    source,
                    summary.visible,
                    summary.delayed,
                    summary.dropped,
                    summary.filtered,
                    summary.out_of_window,
                ]
                for cluster_id, source_summaries in sorted(
                    self.dispatcher._source_evidence_status.items()
                )
                for source, summary in sorted(source_summaries.items())
            ]
            document = _DispatcherObservationHead(
                schema_version=self.checkpoint_schema_version,
                source_evidence_version=self.dispatcher._source_evidence_version,
                summaries=rows,
            )
        return ParticipantSeal(
            head=HeadDraft(
                owner=self.checkpoint_owner,
                schema_version=self.checkpoint_schema_version,
                payload=dumps(document.model_dump(mode="python")),
            )
        )

    def checkpoint_committed(self, sequence: int) -> None:
        """The bounded head owns no delta watermark."""

        del sequence

    def checkpoint_aborted(self, sequence: int) -> None:
        """The bounded head owns no prepared publication state."""

        del sequence

    def restore_checkpoint(self, head: bytes, segments: tuple[bytes, ...]) -> None:
        """Restore observation counters into the fresh dispatcher."""

        if segments:
            raise CheckpointCorruptionError("dispatcher observation checkpoint cannot own segments")
        try:
            document = _DispatcherObservationHead.model_validate(loads(head))
        except (TypeError, ValueError, ValidationError) as error:
            raise CheckpointCorruptionError(
                "dispatcher observation checkpoint head is invalid"
            ) from error
        if document.schema_version != self.checkpoint_schema_version:
            raise CheckpointCorruptionError(
                "dispatcher observation checkpoint schema is unsupported"
            )
        restored: dict[str, dict[str, ObservationSummary]] = {}
        for row in document.summaries:
            if (
                type(row) is not list
                or len(row) != 7
                or type(row[0]) is not str
                or not row[0]
                or type(row[1]) is not str
                or not row[1]
                or any(type(count) is not int or count < 0 for count in row[2:])
            ):
                raise CheckpointCorruptionError(
                    "dispatcher observation checkpoint summary is invalid"
                )
            cluster = restored.setdefault(row[0], {})
            if row[1] in cluster:
                raise CheckpointCorruptionError(
                    "dispatcher observation checkpoint summary is duplicated"
                )
            cluster[row[1]] = ObservationSummary(
                visible=row[2],
                delayed=row[3],
                dropped=row[4],
                filtered=row[5],
                out_of_window=row[6],
            )
        with self.dispatcher._source_evidence_lock:
            self.dispatcher._source_evidence_status = restored
            self.dispatcher._source_evidence_version = document.source_evidence_version
