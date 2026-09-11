"""Incremental checkpoint head for network-visibility allocation state."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from evidenceforge.generation.network_visibility import NetworkVisibilityEngine

from .errors import CheckpointCorruptionError
from .packed import dumps, loads
from .participants import OwnerStateField, ParticipantSeal
from .store import HeadDraft

_SCHEMA_VERSION = "1"


class _NetworkVisibilityHead(BaseModel):
    """Validated envelope for dynamic PAT allocator cursors."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str
    pat_port_counters: list[list[object]] = Field(default_factory=list)


class NetworkVisibilityParticipant:
    """Persist dynamic allocation state while rebuilding static topology."""

    checkpoint_owner = "network-visibility"
    checkpoint_restore_priority = 20
    checkpoint_schema_version = _SCHEMA_VERSION
    checkpoint_state_fields = (
        OwnerStateField("_pat_port_counters", "bounded-live-head"),
        OwnerStateField("_enabled", "deterministically-rebuilt"),
        OwnerStateField("_ip_to_segments", "deterministically-rebuilt"),
        OwnerStateField("_public_cidrs", "deterministically-rebuilt"),
        OwnerStateField("_real_ip_to_vip", "deterministically-rebuilt"),
        OwnerStateField("_segment_networks", "deterministically-rebuilt"),
        OwnerStateField("_sensors", "deterministically-rebuilt"),
        OwnerStateField("_vip_to_real_ip", "deterministically-rebuilt"),
    )

    def __init__(self, visibility: NetworkVisibilityEngine) -> None:
        self.visibility = visibility

    def prepare_checkpoint(self, sequence: int) -> ParticipantSeal:
        """Capture the small set of per-firewall PAT allocation cursors."""

        del sequence
        rows = [
            [sensor, rule_index, port]
            for (sensor, rule_index), port in sorted(self.visibility._pat_port_counters.items())
        ]
        document = _NetworkVisibilityHead(
            schema_version=self.checkpoint_schema_version,
            pat_port_counters=rows,
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
        """Restore allocator cursors into the rebuilt topology."""

        if segments:
            raise CheckpointCorruptionError("network visibility checkpoint cannot own segments")
        try:
            document = _NetworkVisibilityHead.model_validate(loads(head))
        except (TypeError, ValueError, ValidationError) as error:
            raise CheckpointCorruptionError(
                "network visibility checkpoint head is invalid"
            ) from error
        if document.schema_version != self.checkpoint_schema_version:
            raise CheckpointCorruptionError("network visibility checkpoint schema is unsupported")
        restored: dict[tuple[str, int], int] = {}
        for row in document.pat_port_counters:
            if (
                type(row) is not list
                or len(row) != 3
                or type(row[0]) is not str
                or not row[0]
                or type(row[1]) is not int
                or row[1] < 0
                or type(row[2]) is not int
                or not 1024 <= row[2] <= 65535
            ):
                raise CheckpointCorruptionError("network visibility PAT row is invalid")
            key = (row[0], row[1])
            if key in restored:
                raise CheckpointCorruptionError(
                    "network visibility checkpoint has a duplicate PAT allocator"
                )
            restored[key] = row[2]
        if restored.keys() != self.visibility._pat_port_counters.keys():
            raise CheckpointCorruptionError(
                "network visibility checkpoint PAT topology does not match the scenario"
            )
        self.visibility._pat_port_counters = restored
