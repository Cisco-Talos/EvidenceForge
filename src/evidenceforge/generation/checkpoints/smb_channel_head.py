"""Bounded semantic checkpoint head for reusable SMB channel sidecars."""

from __future__ import annotations

import struct

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from evidenceforge.events.application import ApplicationOperationReservation
from evidenceforge.events.network import NetworkSensorObservation, NetworkTransactionPlan
from evidenceforge.generation.smb_channels import (
    SmbApplicationChannelManager,
    SmbSessionView,
    _estimated_record_bytes,
    _pack_session_metadata_values,
    _SmbSessionRecord,
    _unpack_close_token,
    _unpack_handle,
    _unpack_network_plan,
    _unpack_tree,
)
from evidenceforge.models.exceptions import StateError

from .errors import CheckpointCorruptionError
from .owner_inventory import (
    SMB_CHANNEL_MANAGER_CHECKPOINT_FIELDS,
    SMB_SESSION_RECORD_CHECKPOINT_FIELDS,
    SMB_SESSION_STORE_CHECKPOINT_FIELDS,
    SMB_SIDECAR_SHARD_CHECKPOINT_FIELDS,
    assert_complete_owner_inventory,
    assert_transient_owner_state_empty,
)
from .packed import dumps, loads
from .participants import ParticipantSeal
from .state_values import decode_state_value, encode_state_value
from .store import HeadDraft

_SCHEMA_VERSION = "1"
_METADATA_WIDTH = 12
_ROW_WIDTH = 9


class _SmbChannelHead(BaseModel):
    """Validated envelope for open SMB session records."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str
    next_prepared_reservation_id: int = Field(gt=0)
    sessions: list[list[object]] = Field(default_factory=list)


def _application_operation(
    manager: SmbApplicationChannelManager,
    operation_id: str,
) -> ApplicationOperationReservation | None:
    routed = manager._registry._operation_route(operation_id)
    if routed is None:
        return None
    _route, shard_id, _channel_handle = routed
    shard = manager._registry._owner_shard(shard_id, create=False)
    return None if shard is None else shard.operations.get(operation_id)


def _decode_plan(payload: bytes) -> NetworkTransactionPlan:
    try:
        return _unpack_network_plan(payload)
    except (
        IndexError,
        StateError,
        TypeError,
        UnicodeDecodeError,
        ValueError,
        struct.error,
    ) as error:
        raise CheckpointCorruptionError("SMB checkpoint transport plan is invalid") from error


def _decode_observations(value: object) -> tuple[NetworkSensorObservation, ...]:
    decoded = decode_state_value(value)
    if type(decoded) is not list or any(
        type(item) is not NetworkSensorObservation for item in decoded
    ):
        raise CheckpointCorruptionError("SMB checkpoint sensor observations are invalid")
    return tuple(decoded)


def _semantic_metadata(session: SmbSessionView) -> list[object]:
    return [
        session.ground_truth_transport_uid,
        session.logon_id,
        session.auth_session_ref,
        session.principal,
        session.auth_protocol,
        session.account_scope,
        session.effective_uid,
        session.effective_gid,
        session.client_access,
        session.server_hostname,
        session.client_ip,
        session.lifecycle_group_id,
    ]


def _capture_record(
    manager: SmbApplicationChannelManager,
    channel_key: bytes,
    record: _SmbSessionRecord,
) -> list[object]:
    assert_complete_owner_inventory(
        record,
        SMB_SESSION_RECORD_CHECKPOINT_FIELDS,
        owner_name=f"SmbSessionRecord[{channel_key.hex()}]",
    )
    channel_id = manager._channel_id_from_key(channel_key)
    session = manager._session_view(channel_id, record)
    snapshot = manager._registry.get(channel_id)
    close_token = manager._registry.channel_close_token(channel_id)
    if (
        snapshot is None
        or not snapshot.is_open
        or snapshot.identity.protocol != "smb"
        or snapshot.identity.affinity_digest != record.affinity_key.hex()
        or snapshot.identity.binding.transport_id != session.transport_id
        or snapshot.identity.binding.opened_at != session.transport_plan.started_at
        or snapshot.identity.binding.closes_at != session.transport_plan.closed_at
        or close_token is None
        or _unpack_close_token(record) != close_token
    ):
        raise RuntimeError("SMB checkpoint session authority diverged")
    first_tree = record.first_tree
    additional_trees = (
        []
        if record.additional_trees is None
        else [[key, value] for key, value in sorted(record.additional_trees.items())]
    )
    first_handle = record.first_handle
    additional_handles = (
        []
        if record.additional_handles is None
        else [[key, value] for key, value in sorted(record.additional_handles.items())]
    )
    if record.tree_count != int(first_tree is not None) + len(additional_trees) or (
        record.handle_count != int(first_handle is not None) + len(additional_handles)
    ):
        raise RuntimeError("SMB checkpoint record counters diverged")
    return [
        channel_key,
        record.affinity_key,
        record.plan_payload,
        encode_state_value(list(record.sensor_observations)),
        _semantic_metadata(session),
        first_tree,
        additional_trees,
        first_handle,
        additional_handles,
    ]


def _capture_rows(manager: SmbApplicationChannelManager) -> list[list[object]]:
    rows: list[list[object]] = []
    for shard_id, shard in sorted(manager._shards.items()):
        if shard_id != shard.shard_id:
            raise RuntimeError("SMB checkpoint shard route diverged")
        assert_complete_owner_inventory(
            shard,
            SMB_SIDECAR_SHARD_CHECKPOINT_FIELDS,
            owner_name=f"SmbShard[{shard_id}]",
        )
        assert_complete_owner_inventory(
            shard.sessions,
            SMB_SESSION_STORE_CHECKPOINT_FIELDS,
            owner_name=f"SmbSessionStore[{shard_id}]",
        )
        with shard.lock:
            for channel_key, record in shard.sessions.items():
                row = _capture_record(manager, channel_key, record)
                snapshot = manager._registry.get(manager._channel_id_from_key(channel_key))
                assert snapshot is not None
                if manager._registry.owner_partition_id(snapshot.identity.owner_id) != shard_id:
                    raise RuntimeError("SMB checkpoint owner route diverged")
                handle = shard.sessions.handle_for(channel_key)
                expected_expiry = min(
                    snapshot.idle_deadline,
                    snapshot.identity.hard_deadline,
                    snapshot.identity.binding.closes_at,
                ).timestamp()
                if shard.expiry.get(handle) != expected_expiry:
                    raise RuntimeError("SMB checkpoint expiry authority diverged")
                rows.append(row)
    rows.sort(key=lambda row: row[0])
    return rows


def _validated_pairs(value: object, *, label: str) -> list[tuple[str, bytes]]:
    if type(value) is not list:
        raise CheckpointCorruptionError(f"SMB checkpoint {label} rows are invalid")
    pairs: list[tuple[str, bytes]] = []
    prior = ""
    for row in value:
        if (
            type(row) is not list
            or len(row) != 2
            or type(row[0]) is not str
            or not row[0]
            or type(row[1]) is not bytes
            or row[0] <= prior
        ):
            raise CheckpointCorruptionError(f"SMB checkpoint {label} rows are invalid")
        prior = row[0]
        pairs.append((row[0], row[1]))
    return pairs


def _validate_trees(
    manager: SmbApplicationChannelManager,
    session: SmbSessionView,
    first: bytes | None,
    additional: list[tuple[str, bytes]],
) -> set[str]:
    tree_ids: set[str] = set()
    values = ([] if first is None else [("", first)]) + additional
    for key, payload in values:
        try:
            share_ref, _connected_at = _unpack_tree(payload)
        except (
            IndexError,
            StateError,
            TypeError,
            UnicodeDecodeError,
            ValueError,
            struct.error,
        ) as error:
            raise CheckpointCorruptionError("SMB checkpoint tree row is invalid") from error
        if key and key != share_ref.casefold():
            raise CheckpointCorruptionError("SMB checkpoint tree route changed")
        tree_id = manager._tree_id(session.session_id, share_ref)
        if tree_id in tree_ids:
            raise CheckpointCorruptionError("SMB checkpoint tree is duplicated")
        tree_ids.add(tree_id)
    return tree_ids


def _validate_handles(
    manager: SmbApplicationChannelManager,
    session: SmbSessionView,
    tree_ids: set[str],
    first: bytes | None,
    additional: list[tuple[str, bytes]],
) -> int:
    handle_ids: set[str] = set()
    operation_counts: dict[str, int] = {}
    values = ([] if first is None else [("", first)]) + additional
    for key, payload in values:
        try:
            handle = _unpack_handle(payload, session.channel_id)
        except (
            IndexError,
            StateError,
            TypeError,
            UnicodeDecodeError,
            ValueError,
            struct.error,
        ) as error:
            raise CheckpointCorruptionError("SMB checkpoint handle row is invalid") from error
        operation = _application_operation(manager, handle.operation_id)
        if (
            (key and key != handle.handle_id)
            or handle.handle_id in handle_ids
            or handle.tree_id not in tree_ids
            or operation is None
            or operation.channel_id != session.channel_id
        ):
            raise CheckpointCorruptionError("SMB checkpoint handle binding changed")
        handle_ids.add(handle.handle_id)
        operation_counts[handle.operation_id] = operation_counts.get(handle.operation_id, 0) + 1
    return max(operation_counts.values(), default=0)


def _restore_record(manager: SmbApplicationChannelManager, row: object) -> bytes:
    if (
        type(row) is not list
        or len(row) != _ROW_WIDTH
        or type(row[0]) is not bytes
        or len(row[0]) != 16
        or type(row[1]) is not bytes
        or len(row[1]) != 32
        or type(row[2]) is not bytes
        or (row[5] is not None and type(row[5]) is not bytes)
        or (row[7] is not None and type(row[7]) is not bytes)
    ):
        raise CheckpointCorruptionError("SMB checkpoint session row is invalid")
    channel_key = row[0]
    channel_id = manager._channel_id_from_key(channel_key)
    plan = _decode_plan(row[2])
    observations = _decode_observations(row[3])
    metadata = row[4]
    if (
        type(metadata) is not list
        or len(metadata) != _METADATA_WIDTH
        or any(type(metadata[index]) is not str for index in range(6))
        or (metadata[6] is not None and type(metadata[6]) is not int)
        or (metadata[7] is not None and type(metadata[7]) is not int)
        or any(type(metadata[index]) is not str for index in range(8, 12))
    ):
        raise CheckpointCorruptionError("SMB checkpoint session metadata is invalid")
    snapshot = manager._registry.get(channel_id)
    close_token = manager._registry.channel_close_token(channel_id)
    if (
        snapshot is None
        or not snapshot.is_open
        or snapshot.identity.protocol != "smb"
        or snapshot.identity.affinity_digest != row[1].hex()
        or snapshot.identity.binding.transport_id != plan.stable_id
        or snapshot.identity.binding.opened_at != plan.started_at
        or snapshot.identity.binding.closes_at != plan.closed_at
        or close_token is None
    ):
        raise CheckpointCorruptionError("SMB checkpoint session binding changed")
    additional_trees = _validated_pairs(row[6], label="tree")
    additional_handles = _validated_pairs(row[8], label="handle")
    record = _SmbSessionRecord(
        affinity_key=row[1],
        plan_payload=row[2],
        metadata_payload=_pack_session_metadata_values(
            plan=plan,
            close_token=close_token,
            ground_truth_transport_uid=metadata[0],
            logon_id=metadata[1],
            auth_session_ref=metadata[2],
            principal=metadata[3],
            auth_protocol=metadata[4],
            account_scope=metadata[5],
            effective_uid=metadata[6],
            effective_gid=metadata[7],
            client_access=metadata[8],
            server_hostname=metadata[9],
            client_ip=metadata[10],
            lifecycle_group_id=metadata[11],
        ),
        sensor_observations=observations,
        first_tree=row[5],
        additional_trees=(dict(additional_trees) if additional_trees else None),
        first_handle=row[7],
        additional_handles=(dict(additional_handles) if additional_handles else None),
        tree_count=int(row[5] is not None) + len(additional_trees),
        handle_count=int(row[7] is not None) + len(additional_handles),
    )
    session = manager._session_view(channel_id, record)
    tree_ids = _validate_trees(manager, session, row[5], additional_trees)
    maximum_handles = _validate_handles(
        manager,
        session,
        tree_ids,
        row[7],
        additional_handles,
    )
    shard = manager._shard(snapshot.identity.owner_id, create=True)
    assert shard is not None
    if shard.sessions.get(channel_key) is not None:
        raise CheckpointCorruptionError("SMB checkpoint session is duplicated")
    shard.sessions[channel_key] = record
    handle = shard.sessions.handle_for(channel_key)
    shard.expiry.set(
        handle,
        min(
            snapshot.idle_deadline,
            snapshot.identity.hard_deadline,
            snapshot.identity.binding.closes_at,
        ).timestamp(),
    )
    shard.estimated_value_bytes += _estimated_record_bytes(record)
    shard.open_trees += record.tree_count
    shard.open_handles += record.handle_count
    shard.maximum_trees_per_session = max(shard.maximum_trees_per_session, record.tree_count)
    shard.maximum_handles_per_operation = max(
        shard.maximum_handles_per_operation,
        maximum_handles,
    )
    return channel_key


class SmbApplicationChannelParticipant:
    """Persist open SMB sessions, trees, and handles without runtime capabilities."""

    checkpoint_owner = "smb-channels"
    checkpoint_restore_priority = 30
    checkpoint_schema_version = _SCHEMA_VERSION
    checkpoint_state_fields = SMB_CHANNEL_MANAGER_CHECKPOINT_FIELDS

    def __init__(self, manager: SmbApplicationChannelManager) -> None:
        self.manager = manager

    def prepare_checkpoint(self, sequence: int) -> ParticipantSeal:
        """Capture only bounded open SMB sidecars."""

        del sequence
        assert_complete_owner_inventory(
            self.manager,
            self.checkpoint_state_fields,
            owner_name="SmbApplicationChannelManager",
        )
        with self.manager._watermark_lane, self.manager._gate.watermark():
            with self.manager._prepared_lock:
                assert_transient_owner_state_empty(
                    self.manager,
                    self.checkpoint_state_fields,
                    owner_name="SmbApplicationChannelManager",
                )
                with self.manager._directory_lock:
                    document = _SmbChannelHead(
                        schema_version=self.checkpoint_schema_version,
                        next_prepared_reservation_id=self.manager._next_prepared_reservation_id,
                        sessions=_capture_rows(self.manager),
                    )
        return ParticipantSeal(
            head=HeadDraft(
                owner=self.checkpoint_owner,
                schema_version=self.checkpoint_schema_version,
                payload=dumps(document.model_dump(mode="python")),
            )
        )

    def checkpoint_committed(self, sequence: int) -> None:
        """The bounded SMB head owns no incremental mutation tail."""

        del sequence

    def checkpoint_aborted(self, sequence: int) -> None:
        """The bounded SMB head owns no prepared publication state."""

        del sequence

    def restore_checkpoint(self, head: bytes, segments: tuple[bytes, ...]) -> None:
        """Restore SMB sidecars after the shared application registry."""

        if segments:
            raise CheckpointCorruptionError("SMB checkpoint has unexpected segments")
        try:
            document = _SmbChannelHead.model_validate(loads(head))
        except (TypeError, ValueError, ValidationError) as error:
            raise CheckpointCorruptionError("SMB checkpoint head is invalid") from error
        if document.schema_version != self.checkpoint_schema_version:
            raise CheckpointCorruptionError("SMB checkpoint schema changed")
        if self.manager._shards or self.manager._exact_route_cache:
            raise ValueError("SMB checkpoint hydration requires a fresh manager")
        self.manager._next_prepared_reservation_id = document.next_prepared_reservation_id
        prior = b""
        for row in document.sessions:
            channel_key = _restore_record(self.manager, row)
            if channel_key <= prior:
                raise CheckpointCorruptionError("SMB checkpoint sessions are not ordered")
            prior = channel_key


__all__ = ["SmbApplicationChannelParticipant"]
