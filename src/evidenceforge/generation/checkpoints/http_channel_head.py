"""Bounded semantic checkpoint head for HTTP transport sidecars."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from evidenceforge.generation.http_channels import (
    HttpApplicationChannelManager,
    HttpChannelTransport,
)

from .errors import CheckpointCorruptionError
from .owner_inventory import (
    HTTP_CHANNEL_MANAGER_CHECKPOINT_FIELDS,
    HTTP_PACKED_TRANSPORT_STORE_CHECKPOINT_FIELDS,
    HTTP_TRANSPORT_SHARD_CHECKPOINT_FIELDS,
    assert_complete_owner_inventory,
    assert_transient_owner_state_empty,
)
from .packed import dumps, loads
from .participants import ParticipantSeal
from .state_values import decode_state_value, encode_state_value
from .store import HeadDraft

_SCHEMA_VERSION = "1"


class _HttpChannelHead(BaseModel):
    """Validated envelope for open HTTP transport views."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str
    owns_registry: bool
    reuse_guard: object
    operation_budget: int = Field(gt=0)
    watermark: object
    next_prepared_reservation_id: int = Field(gt=0)
    transports: list[list[object]] = Field(default_factory=list)


def _datetime(value: object, *, field_name: str) -> datetime:
    decoded = decode_state_value(value)
    if type(decoded) is not datetime or decoded.tzinfo is not UTC:
        raise CheckpointCorruptionError(
            f"HTTP checkpoint {field_name} must be an exact UTC datetime"
        )
    return decoded


def _capture_transports(manager: HttpApplicationChannelManager) -> list[list[object]]:
    rows: list[list[object]] = []
    for shard_id, shard in sorted(manager._shards.items()):
        if shard_id != shard.shard_id:
            raise RuntimeError("HTTP checkpoint shard route diverged")
        assert_complete_owner_inventory(
            shard,
            HTTP_TRANSPORT_SHARD_CHECKPOINT_FIELDS,
            owner_name=f"HttpTransportShard[{shard_id}]",
        )
        assert_complete_owner_inventory(
            shard.transports,
            HTTP_PACKED_TRANSPORT_STORE_CHECKPOINT_FIELDS,
            owner_name=f"PackedHttpTransportStore[{shard_id}]",
        )
        with shard.lock:
            active_handles = (
                handle for handle, active in enumerate(shard.transports._rows._active) if active
            )
            for handle in active_handles:
                transport = shard.transports._decode_uncached(handle)
                expiry = shard.transport_expiry.get(handle)
                snapshot = manager._registry.get(transport.channel_id)
                if (
                    expiry is None
                    or expiry != transport.reuse_deadline.timestamp()
                    or snapshot is None
                    or not snapshot.is_open
                    or snapshot.identity.owner_id == ""
                ):
                    raise RuntimeError("HTTP checkpoint sidecar authority diverged")
                rows.append(
                    [
                        snapshot.identity.owner_id,
                        transport.channel_id,
                        transport.affinity_digest,
                        transport.transport_id,
                        transport.zeek_uid,
                        transport.conn_id,
                        transport.src_port,
                        encode_state_value(transport.opened_at),
                        encode_state_value(transport.closes_at),
                        encode_state_value(transport.reuse_deadline),
                    ]
                )
    rows.sort(key=lambda row: row[1])
    return rows


def _restore_transport(manager: HttpApplicationChannelManager, row: object) -> None:
    if (
        type(row) is not list
        or len(row) != 10
        or any(type(row[index]) is not str or not row[index] for index in range(6))
        or type(row[6]) is not int
        or not 1 <= row[6] <= 65_535
    ):
        raise CheckpointCorruptionError("HTTP checkpoint transport row is invalid")
    owner_id, channel_id, affinity_digest, transport_id, zeek_uid, conn_id = row[:6]
    opened_at = _datetime(row[7], field_name="transport opening")
    closes_at = _datetime(row[8], field_name="transport closing")
    reuse_deadline = _datetime(row[9], field_name="transport reuse deadline")
    try:
        transport = HttpChannelTransport(
            channel_id=channel_id,
            affinity_digest=affinity_digest,
            transport_id=transport_id,
            zeek_uid=zeek_uid,
            conn_id=conn_id,
            src_port=row[6],
            opened_at=opened_at,
            closes_at=closes_at,
            reuse_deadline=reuse_deadline,
        )
    except (TypeError, ValueError) as error:
        raise CheckpointCorruptionError("HTTP checkpoint transport row is invalid") from error
    snapshot = manager._registry.get(channel_id)
    if (
        snapshot is None
        or not snapshot.is_open
        or snapshot.identity.protocol != "http"
        or snapshot.identity.owner_id != owner_id
        or snapshot.identity.affinity_digest != affinity_digest
        or snapshot.identity.binding.transport_id != transport_id
        or snapshot.identity.binding.opened_at != opened_at
        or snapshot.identity.binding.closes_at != closes_at
        or reuse_deadline <= manager._watermark
    ):
        raise CheckpointCorruptionError("HTTP checkpoint transport binding changed")
    shard = manager._shard(owner_id, create=True)
    assert shard is not None
    if shard.transports.get(channel_id) is not None:
        raise CheckpointCorruptionError("HTTP checkpoint transport is duplicated")
    handle = shard.transports.insert(transport)
    shard.transport_expiry.set(handle, reuse_deadline.timestamp())


class HttpApplicationChannelParticipant:
    """Persist open HTTP transport sidecars and rebuild their packed indexes."""

    checkpoint_owner = "http-channels"
    checkpoint_schema_version = _SCHEMA_VERSION
    checkpoint_state_fields = HTTP_CHANNEL_MANAGER_CHECKPOINT_FIELDS

    def __init__(self, manager: HttpApplicationChannelManager) -> None:
        self.manager = manager

    def prepare_checkpoint(self, sequence: int) -> ParticipantSeal:
        """Capture only open sidecars after rejecting prepared admissions."""

        del sequence
        assert_complete_owner_inventory(
            self.manager,
            self.checkpoint_state_fields,
            owner_name="HttpApplicationChannelManager",
        )
        with self.manager._watermark_lane, self.manager._gate.watermark():
            with self.manager._prepared_lock:
                assert_transient_owner_state_empty(
                    self.manager,
                    self.checkpoint_state_fields,
                    owner_name="HttpApplicationChannelManager",
                )
                with self.manager._directory_lock:
                    document = _HttpChannelHead(
                        schema_version=self.checkpoint_schema_version,
                        owns_registry=self.manager._owns_registry,
                        reuse_guard=encode_state_value(self.manager._reuse_guard),
                        operation_budget=self.manager._operation_budget,
                        watermark=encode_state_value(self.manager._watermark),
                        next_prepared_reservation_id=(self.manager._next_prepared_reservation_id),
                        transports=_capture_transports(self.manager),
                    )
        return ParticipantSeal(
            head=HeadDraft(
                owner=self.checkpoint_owner,
                schema_version=self.checkpoint_schema_version,
                payload=dumps(document.model_dump(mode="python")),
            )
        )

    def checkpoint_committed(self, sequence: int) -> None:
        """The bounded HTTP head owns no delta watermark."""

        del sequence

    def checkpoint_aborted(self, sequence: int) -> None:
        """The bounded HTTP head owns no prepared publication state."""

        del sequence

    def restore_checkpoint(self, head: bytes, segments: tuple[bytes, ...]) -> None:
        """Restore HTTP sidecars after the shared application registry."""

        if segments:
            raise CheckpointCorruptionError("HTTP checkpoint has unexpected segments")
        try:
            document = _HttpChannelHead.model_validate(loads(head))
        except (TypeError, ValueError, ValidationError) as error:
            raise CheckpointCorruptionError("HTTP checkpoint head is invalid") from error
        reuse_guard = decode_state_value(document.reuse_guard)
        watermark = _datetime(document.watermark, field_name="watermark")
        if (
            document.schema_version != self.checkpoint_schema_version
            or document.owns_registry != self.manager._owns_registry
            or type(reuse_guard) is not timedelta
            or reuse_guard != self.manager._reuse_guard
            or document.operation_budget != self.manager._operation_budget
            or not self.manager._registry.window_start
            <= watermark
            <= self.manager._registry._watermark
        ):
            raise CheckpointCorruptionError("HTTP checkpoint configuration changed")
        if self.manager._shards:
            raise ValueError("HTTP checkpoint hydration requires a fresh manager")
        self.manager._watermark = watermark
        self.manager._next_prepared_reservation_id = document.next_prepared_reservation_id
        for row in document.transports:
            _restore_transport(self.manager, row)


__all__ = ["HttpApplicationChannelParticipant"]
