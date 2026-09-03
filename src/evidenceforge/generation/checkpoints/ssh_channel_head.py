"""Bounded packed checkpoint head for SSH sessions and active children."""

from __future__ import annotations

import struct
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from evidenceforge.events.application import (
    ApplicationChannelSnapshot,
    ApplicationOperationReservation,
)
from evidenceforge.generation.ssh_channels import (
    SshApplicationChannelManager,
    SshOperationLease,
    SshSessionView,
    _PackedOperation,
    _unpack_operation,
    _unpack_session,
)
from evidenceforge.models.exceptions import StateError

from .errors import CheckpointCorruptionError
from .owner_inventory import (
    SSH_CHANNEL_MANAGER_CHECKPOINT_FIELDS,
    SSH_OPERATION_ROUTE_CHECKPOINT_FIELDS,
    SSH_PACKED_OPERATION_STORE_CHECKPOINT_FIELDS,
    SSH_PACKED_SESSION_STORE_CHECKPOINT_FIELDS,
    SSH_SIDECAR_SHARD_CHECKPOINT_FIELDS,
    assert_complete_owner_inventory,
    assert_transient_owner_state_empty,
)
from .packed import dumps, loads
from .participants import ParticipantSeal
from .state_values import decode_state_value, encode_state_value
from .store import HeadDraft

_SCHEMA_VERSION = "1"


class _SshChannelHead(BaseModel):
    """Validated envelope for open SSH sessions and active operations."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str
    watermark: object
    next_prepared_reservation_id: int = Field(gt=0)
    sessions: list[bytes] = Field(default_factory=list)
    operations: list[bytes] = Field(default_factory=list)


def _datetime(value: object, *, field_name: str) -> datetime:
    decoded = decode_state_value(value)
    if type(decoded) is not datetime or decoded.tzinfo is not UTC:
        raise CheckpointCorruptionError(
            f"SSH checkpoint {field_name} must be an exact UTC datetime"
        )
    return decoded


def _decode_session(row: bytes) -> SshSessionView:
    try:
        return _unpack_session(row)
    except (
        IndexError,
        StateError,
        TypeError,
        UnicodeDecodeError,
        ValueError,
        struct.error,
    ) as error:
        raise CheckpointCorruptionError("SSH checkpoint session row is invalid") from error


def _decode_operation(row: bytes) -> _PackedOperation:
    try:
        return _unpack_operation(row)
    except (
        IndexError,
        StateError,
        TypeError,
        UnicodeDecodeError,
        ValueError,
        struct.error,
    ) as error:
        raise CheckpointCorruptionError("SSH checkpoint operation row is invalid") from error


def _application_operation(
    manager: SshApplicationChannelManager,
    operation_id: str,
) -> ApplicationOperationReservation | None:
    routed = manager._registry._operation_route(operation_id)
    if routed is None:
        return None
    _route, shard_id, _channel_handle = routed
    shard = manager._registry._owner_shard(shard_id, create=False)
    return None if shard is None else shard.operations.get(operation_id)


def _operation_matches_application(
    operation: _PackedOperation,
    reservation: ApplicationOperationReservation | None,
) -> bool:
    return reservation is not None and (
        operation.operation_id,
        operation.channel_id,
        operation.ordinal,
        operation.started_at,
        operation.ended_at,
        operation.initiator_bytes,
        operation.responder_bytes,
        operation.parent_operation_id,
    ) == (
        reservation.operation_id,
        reservation.channel_id,
        reservation.ordinal,
        reservation.started_at,
        reservation.ended_at,
        reservation.initiator_bytes,
        reservation.responder_bytes,
        reservation.parent_operation_id,
    )


def _validate_session_authority(
    manager: SshApplicationChannelManager,
    row: bytes,
) -> tuple[SshSessionView, ApplicationChannelSnapshot]:
    session = _decode_session(row)
    snapshot = manager._registry.get(session.channel_id)
    if (
        snapshot is None
        or not snapshot.is_open
        or snapshot.identity.protocol != "ssh"
        or snapshot.identity.owner_id != session.owner_id
        or snapshot.identity.affinity_digest != session.affinity.digest
        or snapshot.identity.binding.transport_id != session.transport.transport_id
        or snapshot.identity.binding.opened_at != session.transport.opened_at
        or snapshot.identity.binding.closes_at != session.transport.closes_at
        or snapshot.identity.opened_at != session.binding.ready_at
    ):
        raise CheckpointCorruptionError("SSH checkpoint session binding changed")
    return session, snapshot


def _capture_rows(manager: SshApplicationChannelManager) -> tuple[list[bytes], list[bytes]]:
    sessions: list[tuple[str, bytes]] = []
    operations: list[tuple[str, bytes]] = []
    for route in manager._operation_routes:
        if route is not None:
            assert_complete_owner_inventory(
                route,
                SSH_OPERATION_ROUTE_CHECKPOINT_FIELDS,
                owner_name=f"SshOperationRoute[{route.partition_id}]",
            )
    for shard_id, shard in sorted(manager._shards.items()):
        if shard_id != shard.shard_id:
            raise RuntimeError("SSH checkpoint shard route diverged")
        assert_complete_owner_inventory(
            shard,
            SSH_SIDECAR_SHARD_CHECKPOINT_FIELDS,
            owner_name=f"SshShard[{shard_id}]",
        )
        assert_complete_owner_inventory(
            shard.sessions,
            SSH_PACKED_SESSION_STORE_CHECKPOINT_FIELDS,
            owner_name=f"PackedSshSessionStore[{shard_id}]",
        )
        assert_complete_owner_inventory(
            shard.operations,
            SSH_PACKED_OPERATION_STORE_CHECKPOINT_FIELDS,
            owner_name=f"PackedSshOperationStore[{shard_id}]",
        )
        with shard.lock:
            for handle, active in enumerate(shard.sessions._rows._active):
                if not active:
                    continue
                row = bytes(shard.sessions._rows.get_by_handle(handle))
                session, snapshot = _validate_session_authority(manager, row)
                close_token = manager._registry.channel_close_token(session.channel_id)
                expected_expiry = min(
                    snapshot.idle_deadline,
                    snapshot.identity.hard_deadline,
                    snapshot.identity.binding.closes_at,
                ).timestamp()
                if (
                    close_token is None
                    or shard.sessions._close_locators[handle] != close_token.locator
                    or shard.sessions._close_generations[handle] != close_token.generation
                    or shard.expiry.get(handle) != expected_expiry
                ):
                    raise RuntimeError("SSH checkpoint session authority diverged")
                sessions.append((session.channel_id, row))
            for handle, active in enumerate(shard.operations._rows._active):
                if not active:
                    continue
                row = bytes(shard.operations._rows.get_by_handle(handle))
                operation = _decode_operation(row)
                routed = manager._operation_route_locator(operation.operation_id)
                if (
                    routed is None
                    or routed[1:] != (shard_id, handle)
                    or not _operation_matches_application(
                        operation,
                        _application_operation(manager, operation.operation_id),
                    )
                ):
                    raise RuntimeError("SSH checkpoint operation authority diverged")
                operations.append((operation.operation_id, row))
    sessions.sort(key=lambda item: item[0])
    operations.sort(key=lambda item: item[0])
    return [row for _identity, row in sessions], [row for _identity, row in operations]


def _restore_session(manager: SshApplicationChannelManager, row: bytes) -> SshSessionView:
    session, snapshot = _validate_session_authority(manager, row)
    if session.transport.closes_at <= manager._watermark:
        raise CheckpointCorruptionError("SSH checkpoint session precedes its watermark")
    shard = manager._shard(session.owner_id, create=True)
    assert shard is not None
    if shard.sessions.get(session.channel_id) is not None:
        raise CheckpointCorruptionError("SSH checkpoint session is duplicated")
    handle = shard.sessions.insert(session, packed_row=row)
    close_token = manager._registry.channel_close_token(session.channel_id)
    if close_token is None:
        raise CheckpointCorruptionError("SSH checkpoint session lost its close authority")
    shard.sessions.bind_close_token_by_handle(handle, close_token)
    shard.expiry.set(
        handle,
        min(
            snapshot.idle_deadline,
            snapshot.identity.hard_deadline,
            snapshot.identity.binding.closes_at,
        ).timestamp(),
    )
    shard.high_water_mark = max(shard.high_water_mark, len(shard.sessions))
    return session


def _restore_operation(
    manager: SshApplicationChannelManager,
    row: bytes,
    sessions: dict[str, SshSessionView],
) -> None:
    operation = _decode_operation(row)
    session = sessions.get(operation.channel_id)
    reservation = _application_operation(manager, operation.operation_id)
    if session is None or not _operation_matches_application(operation, reservation):
        raise CheckpointCorruptionError("SSH checkpoint operation binding changed")
    lease = SshOperationLease(
        operation_id=operation.operation_id,
        child_channel_id=operation.child_channel_id,
        channel_id=operation.channel_id,
        semantic_operation_id=operation.semantic_operation_id,
        parent_operation_id=operation.parent_operation_id,
        kind=operation.kind,
        ordinal=operation.ordinal,
        started_at=operation.started_at,
        ended_at=operation.ended_at,
        initiator_bytes=operation.initiator_bytes,
        responder_bytes=operation.responder_bytes,
        session=session,
    )
    shard = manager._shard(session.owner_id, create=False)
    operation_route = manager._operation_route(operation.operation_id, create=True)
    child_route = manager._operation_route(operation.child_channel_id, create=True)
    assert shard is not None and operation_route is not None and child_route is not None
    if (
        operation_route.operations.get(operation.operation_id) is not None
        or child_route.children.get(operation.child_channel_id) is not None
    ):
        raise CheckpointCorruptionError("SSH checkpoint operation is duplicated")
    handle = shard.operations.insert(lease)
    locator = manager._pack_locator(shard.shard_id, handle)
    operation_route.operations[operation.operation_id] = locator
    child_route.children[operation.child_channel_id] = locator
    shard.high_water_mark = max(shard.high_water_mark, len(shard.sessions) + len(shard.operations))


class SshApplicationChannelParticipant:
    """Persist open SSH sessions and active child operations as packed rows."""

    checkpoint_owner = "ssh-channels"
    checkpoint_schema_version = _SCHEMA_VERSION
    checkpoint_state_fields = SSH_CHANNEL_MANAGER_CHECKPOINT_FIELDS

    def __init__(self, manager: SshApplicationChannelManager) -> None:
        self.manager = manager

    def prepare_checkpoint(self, sequence: int) -> ParticipantSeal:
        """Capture bounded SSH rows after rejecting prepared admissions."""

        del sequence
        assert_complete_owner_inventory(
            self.manager,
            self.checkpoint_state_fields,
            owner_name="SshApplicationChannelManager",
        )
        with self.manager._watermark_lane, self.manager._gate.watermark():
            with self.manager._prepared_lock:
                assert_transient_owner_state_empty(
                    self.manager,
                    self.checkpoint_state_fields,
                    owner_name="SshApplicationChannelManager",
                )
                with self.manager._directory_lock:
                    sessions, operations = _capture_rows(self.manager)
                    document = _SshChannelHead(
                        schema_version=self.checkpoint_schema_version,
                        watermark=encode_state_value(self.manager._watermark),
                        next_prepared_reservation_id=self.manager._next_prepared_reservation_id,
                        sessions=sessions,
                        operations=operations,
                    )
        return ParticipantSeal(
            head=HeadDraft(
                owner=self.checkpoint_owner,
                schema_version=self.checkpoint_schema_version,
                payload=dumps(document.model_dump(mode="python")),
            )
        )

    def checkpoint_committed(self, sequence: int) -> None:
        """The bounded SSH head owns no incremental mutation tail."""

        del sequence

    def checkpoint_aborted(self, sequence: int) -> None:
        """The bounded SSH head owns no prepared publication state."""

        del sequence

    def restore_checkpoint(self, head: bytes, segments: tuple[bytes, ...]) -> None:
        """Restore SSH sidecars after the shared application registry."""

        if segments:
            raise CheckpointCorruptionError("SSH checkpoint has unexpected segments")
        try:
            document = _SshChannelHead.model_validate(loads(head))
        except (TypeError, ValueError, ValidationError) as error:
            raise CheckpointCorruptionError("SSH checkpoint head is invalid") from error
        watermark = _datetime(document.watermark, field_name="watermark")
        if (
            document.schema_version != self.checkpoint_schema_version
            or not self.manager._window_start <= watermark <= self.manager._registry._watermark
        ):
            raise CheckpointCorruptionError("SSH checkpoint configuration changed")
        if (
            self.manager._shards
            or any(route is not None for route in self.manager._operation_routes)
            or self.manager._session_hot_cache
        ):
            raise ValueError("SSH checkpoint hydration requires a fresh manager")
        self.manager._watermark = watermark
        self.manager._next_prepared_reservation_id = document.next_prepared_reservation_id
        sessions: dict[str, SshSessionView] = {}
        prior_channel_id = ""
        for row in document.sessions:
            session = _restore_session(self.manager, row)
            if session.channel_id <= prior_channel_id:
                raise CheckpointCorruptionError("SSH checkpoint sessions are not ordered")
            prior_channel_id = session.channel_id
            sessions[session.channel_id] = session
        prior_operation_id = ""
        for row in document.operations:
            operation = _decode_operation(row)
            if operation.operation_id <= prior_operation_id:
                raise CheckpointCorruptionError("SSH checkpoint operations are not ordered")
            prior_operation_id = operation.operation_id
            _restore_operation(self.manager, row, sessions)
        for route in self.manager._operation_routes:
            if route is not None:
                assert_complete_owner_inventory(
                    route,
                    SSH_OPERATION_ROUTE_CHECKPOINT_FIELDS,
                    owner_name=f"SshOperationRoute[{route.partition_id}]",
                )


__all__ = ["SshApplicationChannelParticipant"]
