"""Explicit bounded checkpoint head for the common application-channel registry."""

from __future__ import annotations

from datetime import datetime, timedelta

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from evidenceforge.events.application import (
    ApplicationChannelBudget,
    ApplicationChannelIdentity,
    ApplicationChannelSnapshot,
    ApplicationOperationReservation,
    ApplicationTransportBinding,
)
from evidenceforge.generation.application_channels import (
    ApplicationChannelRegistry,
    _ApplicationChannelShard,
    _operation_estimated_bytes,
    _snapshot_estimated_bytes,
    _used_id_estimated_bytes,
)
from evidenceforge.models.exceptions import StateError

from .errors import CheckpointCorruptionError
from .owner_inventory import (
    APPLICATION_CHANNEL_REGISTRY_CHECKPOINT_FIELDS,
    APPLICATION_CHANNEL_SHARD_CHECKPOINT_FIELDS,
    assert_complete_owner_inventory,
    assert_transient_owner_state_empty,
)
from .packed import dumps, loads
from .participants import ParticipantSeal
from .store import HeadDraft

_SCHEMA_VERSION = "1"


class _ApplicationChannelHead(BaseModel):
    """Validated envelope for channel, operation, and used-ID tables."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str
    watermark: str
    channels: list[list[object]] = Field(default_factory=list)
    operations: list[list[object]] = Field(default_factory=list)
    used_operation_ids: list[list[str]] = Field(default_factory=list)


def _time(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat()


def _decode_time(value: object, label: str, *, optional: bool = False) -> datetime | None:
    if value is None and optional:
        return None
    if type(value) is not str:
        raise CheckpointCorruptionError(f"application channel checkpoint {label} is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise CheckpointCorruptionError(
            f"application channel checkpoint {label} is invalid"
        ) from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise CheckpointCorruptionError(f"application channel checkpoint {label} lacks an offset")
    return parsed


def _row(value: object, width: int, label: str) -> list[object]:
    if type(value) is not list or len(value) != width:
        raise CheckpointCorruptionError(f"application channel checkpoint {label} is invalid")
    return value


def _encode_channel(snapshot: ApplicationChannelSnapshot) -> list[object]:
    identity = snapshot.identity
    return [
        identity.channel_id,
        identity.protocol,
        identity.owner_id,
        identity.affinity_digest,
        identity.binding.transport_id,
        _time(identity.binding.opened_at),
        _time(identity.binding.closes_at),
        _time(identity.opened_at),
        int(identity.idle_timeout.total_seconds() * 1_000_000),
        _time(identity.hard_deadline),
        identity.budget.initiator_bytes,
        identity.budget.responder_bytes,
        identity.budget.operations,
        _time(snapshot.last_activity_at),
        _time(snapshot.idle_deadline),
        snapshot.reserved_initiator_bytes,
        snapshot.reserved_responder_bytes,
        snapshot.reserved_operations,
        snapshot.completed_operations,
        snapshot.active_operations,
        _time(snapshot.closed_at),
        snapshot.close_reason,
    ]


def _decode_channel(value: object) -> ApplicationChannelSnapshot:
    fields = _row(value, 22, "channel row")
    if (
        any(type(fields[index]) is not str for index in (0, 1, 2, 3, 4, 21))
        or any(type(fields[index]) is not int for index in (8, 10, 11, 12))
        or any(type(fields[index]) is not int for index in range(15, 20))
    ):
        raise CheckpointCorruptionError("application channel checkpoint channel row is invalid")
    try:
        binding = ApplicationTransportBinding(
            transport_id=fields[4],
            opened_at=_decode_time(fields[5], "transport open"),  # type: ignore[arg-type]
            closes_at=_decode_time(fields[6], "transport close"),  # type: ignore[arg-type]
        )
        budget = ApplicationChannelBudget(
            initiator_bytes=fields[10],  # type: ignore[arg-type]
            responder_bytes=fields[11],  # type: ignore[arg-type]
            operations=fields[12],  # type: ignore[arg-type]
        )
        identity = ApplicationChannelIdentity(
            channel_id=fields[0],  # type: ignore[arg-type]
            protocol=fields[1],  # type: ignore[arg-type]
            owner_id=fields[2],  # type: ignore[arg-type]
            affinity_digest=fields[3],  # type: ignore[arg-type]
            binding=binding,
            opened_at=_decode_time(fields[7], "channel open"),  # type: ignore[arg-type]
            idle_timeout=timedelta(microseconds=fields[8]),  # type: ignore[arg-type]
            hard_deadline=_decode_time(fields[9], "hard deadline"),  # type: ignore[arg-type]
            budget=budget,
        )
        return ApplicationChannelSnapshot(
            identity=identity,
            last_activity_at=_decode_time(fields[13], "last activity"),  # type: ignore[arg-type]
            idle_deadline=_decode_time(fields[14], "idle deadline"),  # type: ignore[arg-type]
            reserved_initiator_bytes=fields[15],  # type: ignore[arg-type]
            reserved_responder_bytes=fields[16],  # type: ignore[arg-type]
            reserved_operations=fields[17],  # type: ignore[arg-type]
            completed_operations=fields[18],  # type: ignore[arg-type]
            active_operations=fields[19],  # type: ignore[arg-type]
            closed_at=_decode_time(fields[20], "channel close", optional=True),
            close_reason=fields[21],  # type: ignore[arg-type]
        )
    except (TypeError, ValueError) as error:
        raise CheckpointCorruptionError(
            "application channel checkpoint channel row is invalid"
        ) from error


def _encode_operation(operation: ApplicationOperationReservation) -> list[object]:
    return [
        operation.operation_id,
        operation.channel_id,
        operation.ordinal,
        _time(operation.started_at),
        _time(operation.ended_at),
        operation.initiator_bytes,
        operation.responder_bytes,
        operation.parent_operation_id,
    ]


def _decode_operation(value: object) -> ApplicationOperationReservation:
    fields = _row(value, 8, "operation row")
    if any(type(fields[index]) is not str for index in (0, 1, 3, 4, 7)) or any(
        type(fields[index]) is not int for index in (2, 5, 6)
    ):
        raise CheckpointCorruptionError("application channel checkpoint operation row is invalid")
    try:
        return ApplicationOperationReservation(
            operation_id=fields[0],  # type: ignore[arg-type]
            channel_id=fields[1],  # type: ignore[arg-type]
            ordinal=fields[2],  # type: ignore[arg-type]
            started_at=_decode_time(fields[3], "operation start"),  # type: ignore[arg-type]
            ended_at=_decode_time(fields[4], "operation end"),  # type: ignore[arg-type]
            initiator_bytes=fields[5],  # type: ignore[arg-type]
            responder_bytes=fields[6],  # type: ignore[arg-type]
            parent_operation_id=fields[7],  # type: ignore[arg-type]
        )
    except (TypeError, ValueError) as error:
        raise CheckpointCorruptionError(
            "application channel checkpoint operation row is invalid"
        ) from error


def _used_ids(shard: _ApplicationChannelShard, handle: int) -> tuple[str, ...]:
    operation_ids: list[str] = []
    single = shard.used_operation_ids._single_operation(handle)
    if single is not None:
        operation_ids.append(single)
    operation_ids.extend(
        shard.used_operation_ids.key_by_handle(row_handle)[1]
        for row_handle in shard.used_operation_ids._channels.iter_handles(handle)
    )
    return tuple(sorted(operation_ids))


class ApplicationChannelRegistryParticipant:
    """Persist active channels, retained tombstones, operations, and used IDs."""

    checkpoint_owner = "application-channels"
    checkpoint_restore_priority = 20
    checkpoint_schema_version = _SCHEMA_VERSION
    checkpoint_state_fields = APPLICATION_CHANNEL_REGISTRY_CHECKPOINT_FIELDS

    def __init__(self, registry: ApplicationChannelRegistry) -> None:
        self.registry = registry

    def prepare_checkpoint(self, sequence: int) -> ParticipantSeal:
        """Capture normalized semantic rows after all application mutations drain."""

        del sequence
        assert_transient_owner_state_empty(
            self.registry,
            self.checkpoint_state_fields,
            owner_name="ApplicationChannelRegistry",
        )
        channels: list[list[object]] = []
        operations: list[list[object]] = []
        used: list[list[str]] = []
        for shard_id, shard in sorted(self.registry._shards.items()):
            assert shard.shard_id == shard_id
            assert_complete_owner_inventory(
                shard,
                APPLICATION_CHANNEL_SHARD_CHECKPOINT_FIELDS,
                owner_name=f"ApplicationChannelShard[{shard_id}]",
            )
            with shard.lock:
                for handle, length in enumerate(shard.channels._identity_lengths):
                    if length == shard.channels._EMPTY_IDENTITY:
                        continue
                    snapshot = shard.channels.detached_by_handle(handle)
                    channels.append(_encode_channel(snapshot))
                    used.extend(
                        [snapshot.channel_id, operation_id]
                        for operation_id in _used_ids(shard, handle)
                    )
                operations.extend(
                    _encode_operation(operation) for _key, operation in shard.operations.items()
                )
        channels.sort(key=dumps)
        operations.sort(key=dumps)
        used.sort(key=dumps)
        head = _ApplicationChannelHead(
            schema_version=self.checkpoint_schema_version,
            watermark=self.registry._watermark.isoformat(),
            channels=channels,
            operations=operations,
            used_operation_ids=used,
        )
        return ParticipantSeal(
            head=HeadDraft(
                owner=self.checkpoint_owner,
                schema_version=self.checkpoint_schema_version,
                payload=dumps(head.model_dump(mode="python")),
            )
        )

    def checkpoint_committed(self, sequence: int) -> None:
        """The bounded head owns no delta watermark."""

        del sequence

    def checkpoint_aborted(self, sequence: int) -> None:
        """The bounded head owns no prepared publication state."""

        del sequence

    def _restore_channel(
        self, snapshot: ApplicationChannelSnapshot
    ) -> tuple[_ApplicationChannelShard, int]:
        registry = self.registry
        identity = snapshot.identity
        initial = registry.open_channel(identity)
        routed = registry._channel_route(identity.channel_id)
        if routed is None:
            raise CheckpointCorruptionError("restored application channel route is missing")
        _route, _shard_id, handle = routed
        shard = registry._owner_shard(registry._owner_shard_id(identity.owner_id), create=False)
        if shard is None:
            raise CheckpointCorruptionError("restored application channel shard is missing")
        with shard.lock:
            shard.channels.replace(handle, snapshot, known_prior=initial)
            shard.estimated_value_bytes += _snapshot_estimated_bytes(
                snapshot
            ) - _snapshot_estimated_bytes(initial)
            shard.mutation_version += 1
            registry._set_active_deadline(shard, handle, snapshot)
            if snapshot.closed_at is not None:
                shard.active_expiry.pop(handle, None)
                shard.closed_expiry.set(
                    handle,
                    (snapshot.closed_at + registry._closed_grace).timestamp(),
                )
                shard.open_channels -= 1
            if snapshot.active_operations:
                shard.operation_blocker_expiry.set(
                    handle,
                    registry._effective_deadline(snapshot).timestamp(),
                )
        return shard, handle

    def restore_checkpoint(self, head: bytes, segments: tuple[bytes, ...]) -> None:
        """Hydrate semantic rows into a fresh registry and rebuild packed indexes."""

        if segments:
            raise CheckpointCorruptionError(
                "application channel checkpoint has unexpected segments"
            )
        try:
            document = _ApplicationChannelHead.model_validate(loads(head))
        except (TypeError, ValueError, ValidationError) as error:
            raise CheckpointCorruptionError(
                "application channel checkpoint head is invalid"
            ) from error
        if document.schema_version != self.checkpoint_schema_version:
            raise CheckpointCorruptionError("application channel checkpoint schema is unsupported")
        assert_transient_owner_state_empty(
            self.registry,
            self.checkpoint_state_fields,
            owner_name="ApplicationChannelRegistry",
        )
        if self.registry._shards:
            raise CheckpointCorruptionError(
                "application channel checkpoint hydration requires a fresh registry"
            )
        watermark = _decode_time(document.watermark, "watermark")
        if (
            watermark is None
            or not self.registry._window_start <= watermark <= self.registry._window_end
        ):
            raise CheckpointCorruptionError(
                "application channel checkpoint watermark is outside the runtime window"
            )
        channels: dict[str, tuple[_ApplicationChannelShard, int]] = {}
        try:
            for encoded in document.channels:
                snapshot = _decode_channel(encoded)
                if snapshot.channel_id in channels:
                    raise CheckpointCorruptionError(
                        "application channel checkpoint duplicates a channel"
                    )
                channels[snapshot.channel_id] = self._restore_channel(snapshot)
            for encoded in document.used_operation_ids:
                channel_id, operation_id = _row(encoded, 2, "used operation row")
                if type(channel_id) is not str or type(operation_id) is not str:
                    raise CheckpointCorruptionError(
                        "application channel checkpoint used operation row is invalid"
                    )
                shard, handle = channels[channel_id]
                key = (handle, operation_id)
                shard.used_operation_ids[key] = handle
                shard.estimated_value_bytes += _used_id_estimated_bytes(key)
            for encoded in document.operations:
                operation = _decode_operation(encoded)
                shard, handle = channels[operation.channel_id]
                if (handle, operation.operation_id) not in shard.used_operation_ids:
                    raise CheckpointCorruptionError(
                        "application channel active operation lacks its used-ID marker"
                    )
                shard.operations[operation.operation_id] = operation
                shard.estimated_value_bytes += _operation_estimated_bytes(operation)
                route = self.registry._route_partition(
                    "operation", operation.operation_id, create=True
                )
                assert route is not None
                route.operations[operation.operation_id] = self.registry._pack_channel_locator(
                    shard.shard_id, handle
                )
            self.registry._watermark = watermark
        except (KeyError, StateError, TypeError, ValueError) as error:
            if isinstance(error, CheckpointCorruptionError):
                raise
            raise CheckpointCorruptionError(
                "application channel checkpoint semantic state is invalid"
            ) from error
