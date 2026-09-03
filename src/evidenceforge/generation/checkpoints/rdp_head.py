"""Bounded semantic checkpoint head for reconnectable RDP sessions."""

from __future__ import annotations

from collections import defaultdict

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from evidenceforge.events.rdp import RdpRetentionLease, RdpSessionSnapshot, RdpSessionState
from evidenceforge.generation.rdp_sessions import (
    RdpReconnectStateManager,
    _acquire_stable_locks,
    _lease_estimated_bytes,
)

from .errors import CheckpointCorruptionError
from .owner_inventory import (
    RDP_AFFINITY_PARTITION_CHECKPOINT_FIELDS,
    RDP_MANAGER_CHECKPOINT_FIELDS,
    RDP_SHARD_CHECKPOINT_FIELDS,
    assert_complete_owner_inventory,
    assert_transient_owner_state_empty,
)
from .packed import dumps, loads
from .participants import ParticipantSeal
from .state_values import decode_state_value, encode_state_value
from .store import HeadDraft

_SCHEMA_VERSION = "1"


class _RdpHead(BaseModel):
    """Validated envelope around explicit session, operation, and lease rows."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str
    watermark: object
    sessions: list[object] = Field(default_factory=list)
    operations: list[list[object]] = Field(default_factory=list)
    leases: list[object] = Field(default_factory=list)
    shard_high_water: list[list[int]] = Field(default_factory=list)


def _live_leases(shard: object) -> list[RdpRetentionLease]:
    store = shard.leases
    result: list[RdpRetentionLease] = []
    for handle in range(len(store._slot_values)):
        try:
            result.append(store.get_by_handle(handle))
        except KeyError:
            continue
    return result


class RdpSessionManagerParticipant:
    """Persist live RDP semantics and rebuild all compact routing infrastructure."""

    checkpoint_owner = "rdp-session-manager"
    checkpoint_schema_version = _SCHEMA_VERSION
    checkpoint_state_fields = RDP_MANAGER_CHECKPOINT_FIELDS

    def __init__(self, manager: RdpReconnectStateManager) -> None:
        self.manager = manager

    def prepare_checkpoint(self, sequence: int) -> ParticipantSeal:
        """Capture bounded RDP sessions only after all admission capabilities drain."""

        del sequence
        assert_transient_owner_state_empty(
            self.manager,
            self.checkpoint_state_fields,
            owner_name="RdpReconnectStateManager",
        )
        with self.manager._directory_lock:
            shards = tuple(sorted(self.manager._shards.values(), key=lambda item: item.shard_id))
            routes = tuple(
                route for route in self.manager._affinity_partitions if route is not None
            )
        lock_entries = [self.manager._route_lock_entry(route) for route in routes]
        lock_entries.extend(self.manager._shard_lock_entry(shard) for shard in shards)
        with _acquire_stable_locks(lock_entries):
            sessions: list[object] = []
            operations: list[list[object]] = []
            leases: list[object] = []
            high_water: list[list[int]] = []
            for route in routes:
                assert_complete_owner_inventory(
                    route,
                    RDP_AFFINITY_PARTITION_CHECKPOINT_FIELDS,
                    owner_name="rdp-affinity-partition",
                )
            for shard in shards:
                assert_complete_owner_inventory(
                    shard,
                    RDP_SHARD_CHECKPOINT_FIELDS,
                    owner_name="rdp-session-shard",
                )
                high_water.append(
                    [shard.shard_id, shard.maximum_lease_bucket, shard.generation_high_water_mark]
                )
                logical_by_handle: dict[int, str] = {}
                for handle, active in enumerate(shard.sessions._active):
                    if not active:
                        continue
                    snapshot = shard.sessions.get_by_handle(handle)
                    logical_by_handle[handle] = snapshot.logical_session_id
                    sessions.append(encode_state_value(snapshot))
                for operation_id in sorted(shard.operations):
                    handle = shard.operations[operation_id]
                    logical_id = logical_by_handle.get(handle)
                    if logical_id is None:
                        raise RuntimeError("RDP operation retained a stale session handle")
                    operations.append([operation_id, logical_id])
                leases.extend(encode_state_value(lease) for lease in _live_leases(shard))
            document = _RdpHead(
                schema_version=self.checkpoint_schema_version,
                watermark=encode_state_value(self.manager._watermark),
                sessions=sessions,
                operations=operations,
                leases=leases,
                shard_high_water=high_water,
            )
        return ParticipantSeal(
            head=HeadDraft(
                owner=self.checkpoint_owner,
                schema_version=self.checkpoint_schema_version,
                payload=dumps(document.model_dump(mode="python")),
            )
        )

    def checkpoint_committed(self, sequence: int) -> None:
        """The bounded RDP head owns no delta watermark."""

        del sequence

    def checkpoint_aborted(self, sequence: int) -> None:
        """The bounded RDP head owns no pending publication state."""

        del sequence

    def restore_checkpoint(self, head: bytes, segments: tuple[bytes, ...]) -> None:
        """Restore sessions into fresh stores and reconnect application authority."""

        if segments:
            raise CheckpointCorruptionError("RDP checkpoint has unexpected segments")
        try:
            document = _RdpHead.model_validate(loads(head))
        except (TypeError, ValueError, ValidationError) as error:
            raise CheckpointCorruptionError("RDP checkpoint head is invalid") from error
        if document.schema_version != self.checkpoint_schema_version:
            raise CheckpointCorruptionError("RDP checkpoint schema is unsupported")
        watermark = decode_state_value(document.watermark)
        if type(watermark) is not type(self.manager._watermark):
            raise CheckpointCorruptionError("RDP checkpoint watermark is invalid")
        if self.manager._shards or any(self.manager._affinity_partitions):
            raise CheckpointCorruptionError("RDP checkpoint requires a fresh manager")

        handles: dict[str, tuple[object, int, RdpSessionSnapshot]] = {}
        for encoded in document.sessions:
            snapshot = decode_state_value(encoded)
            if type(snapshot) is not RdpSessionSnapshot or snapshot.logical_session_id in handles:
                raise CheckpointCorruptionError("RDP checkpoint session row is invalid")
            shard = self.manager._shard(snapshot.logical_session_id, create=True)
            affinity = self.manager._affinity_partition(snapshot.identity.affinity, create=True)
            assert shard is not None and affinity is not None
            handle = shard.sessions.insert(snapshot)
            logical_key = self.manager._logical_route_key(snapshot.logical_session_id)
            affinity_key = self.manager._affinity_route_key(snapshot.identity.affinity)
            if (
                shard.session_routes.get_digest(logical_key) is not None
                or affinity.routes.get_digest(affinity_key) is not None
            ):
                raise CheckpointCorruptionError("RDP checkpoint route is duplicated")
            shard.sessions.set_route_metadata(
                handle,
                logical_route_key=logical_key,
                affinity_route_key=affinity_key,
                affinity_partition_id=affinity.partition_id,
            )
            shard.session_routes.set_digest(logical_key, handle)
            affinity.routes.set_digest(
                affinity_key,
                self.manager._pack_locator(shard.shard_id, handle),
            )
            close_token = self.manager._application.channel_close_token(
                snapshot.generation.channel_id
            )
            if close_token is not None:
                shard.sessions.set_close_token(handle, close_token)
            elif snapshot.state is not RdpSessionState.LOGGED_OUT:
                raise CheckpointCorruptionError("RDP checkpoint lost its application channel")
            deadline = (
                snapshot.retention_deadline
                if snapshot.state is RdpSessionState.LOGGED_OUT
                else self.manager._effective_generation_deadline(snapshot)
            )
            if deadline is None:
                raise CheckpointCorruptionError("RDP checkpoint session deadline is invalid")
            shard.session_expiry.set(handle, deadline.timestamp())
            if snapshot.active_operations:
                shard.blocker_expiry.set(handle, deadline.timestamp())
            if snapshot.state is RdpSessionState.CONNECTED:
                shard.connected_sessions += 1
            elif snapshot.state is RdpSessionState.DISCONNECTED:
                shard.disconnected_sessions += 1
            else:
                shard.logged_out_sessions += 1
            handles[snapshot.logical_session_id] = (shard, handle, snapshot)

        operation_counts: defaultdict[str, int] = defaultdict(int)
        for row in document.operations:
            if (
                type(row) is not list
                or len(row) != 2
                or type(row[0]) is not str
                or not row[0]
                or type(row[1]) is not str
                or row[1] not in handles
            ):
                raise CheckpointCorruptionError("RDP checkpoint operation row is invalid")
            operation_id, logical_id = row
            shard, handle, _snapshot = handles[logical_id]
            if operation_id in shard.operations:
                raise CheckpointCorruptionError("RDP checkpoint operation is duplicated")
            shard.operations[operation_id] = handle
            shard.active_operations += 1
            operation_counts[logical_id] += 1

        lease_counts: defaultdict[str, int] = defaultdict(int)
        for encoded in document.leases:
            lease = decode_state_value(encoded)
            if type(lease) is not RdpRetentionLease or lease.logical_session_id not in handles:
                raise CheckpointCorruptionError("RDP checkpoint lease row is invalid")
            shard, _session_handle, _snapshot = handles[lease.logical_session_id]
            key = (lease.logical_session_id, lease.lease_id)
            if shard.lease_routes.get(key) is not None:
                raise CheckpointCorruptionError("RDP checkpoint lease is duplicated")
            lease_handle = shard.leases.insert(lease)
            shard.lease_routes[key] = lease_handle
            shard.lease_expiry.set(lease_handle, lease.retain_until.timestamp())
            shard.active_leases += 1
            shard.estimated_value_bytes += _lease_estimated_bytes(lease)
            lease_counts[lease.logical_session_id] += 1

        for logical_id, (_shard, _handle, snapshot) in handles.items():
            if (
                operation_counts[logical_id] != snapshot.active_operations
                or lease_counts[logical_id] != snapshot.active_leases
            ):
                raise CheckpointCorruptionError("RDP checkpoint relationship counts diverged")
        seen_shards: set[int] = set()
        for row in document.shard_high_water:
            if (
                type(row) is not list
                or len(row) != 3
                or any(type(value) is not int or value < 0 for value in row)
                or row[0] in seen_shards
                or row[0] >= self.manager._shard_count
            ):
                raise CheckpointCorruptionError("RDP checkpoint shard summary is invalid")
            seen_shards.add(row[0])
            shard = self.manager._shards.get(row[0])
            if shard is not None:
                shard.maximum_lease_bucket = max(row[1], shard.active_leases)
                shard.generation_high_water_mark = max(
                    row[2],
                    max(
                        (
                            snapshot.generation.ordinal + 1
                            for retained_shard, _handle, snapshot in handles.values()
                            if retained_shard is shard
                        ),
                        default=0,
                    ),
                )
        self.manager._watermark = watermark
