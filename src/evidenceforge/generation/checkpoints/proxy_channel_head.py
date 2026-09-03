"""Bounded semantic checkpoint head for explicit-proxy tunnel sidecars."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from evidenceforge.generation.proxy_channels import (
    ExplicitProxyChannelManager,
    ExplicitProxyTunnelIdentity,
)

from .errors import CheckpointCorruptionError
from .owner_inventory import (
    PROXY_CHANNEL_MANAGER_CHECKPOINT_FIELDS,
    PROXY_PACKED_TUNNEL_STORE_CHECKPOINT_FIELDS,
    PROXY_SIDECAR_SHARD_CHECKPOINT_FIELDS,
    assert_complete_owner_inventory,
    assert_transient_owner_state_empty,
)
from .packed import dumps, loads
from .participants import ParticipantSeal
from .state_values import decode_state_value, encode_state_value
from .store import HeadDraft

_SCHEMA_VERSION = "1"


class _ProxyChannelHead(BaseModel):
    """Validated envelope for open explicit-proxy tunnels."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str
    owns_registry: bool
    close_guard: object
    idle_timeout: object
    watermark: object
    next_admission_id: int = Field(gt=0)
    tunnels: list[list[object]] = Field(default_factory=list)


def _datetime(value: object, *, field_name: str) -> datetime:
    decoded = decode_state_value(value)
    if type(decoded) is not datetime or decoded.tzinfo is not UTC:
        raise CheckpointCorruptionError(
            f"explicit-proxy checkpoint {field_name} must be an exact UTC datetime"
        )
    return decoded


def _capture_tunnels(manager: ExplicitProxyChannelManager) -> list[list[object]]:
    rows: list[list[object]] = []
    for shard_id, shard in sorted(manager._shards.items()):
        if shard_id != shard.shard_id:
            raise RuntimeError("explicit-proxy checkpoint shard route diverged")
        assert_complete_owner_inventory(
            shard,
            PROXY_SIDECAR_SHARD_CHECKPOINT_FIELDS,
            owner_name=f"ProxySidecarShard[{shard_id}]",
        )
        assert_complete_owner_inventory(
            shard.tunnels,
            PROXY_PACKED_TUNNEL_STORE_CHECKPOINT_FIELDS,
            owner_name=f"PackedProxyTunnelStore[{shard_id}]",
        )
        with shard.lock:
            for handle, active in enumerate(shard.tunnels._rows._active):
                if not active:
                    continue
                tunnel = shard.tunnels._unpack(shard.tunnels._rows.get_by_handle(handle))
                expiry = shard.expiry.get(handle)
                snapshot = manager._registry.get(tunnel.channel_id)
                expected_expiry = (
                    min(tunnel.reuse_deadline, snapshot.idle_deadline).timestamp()
                    if snapshot is not None
                    else None
                )
                if (
                    expiry is None
                    or expiry != expected_expiry
                    or snapshot is None
                    or not snapshot.is_open
                    or not snapshot.identity.owner_id
                ):
                    raise RuntimeError("explicit-proxy checkpoint sidecar authority diverged")
                rows.append(
                    [
                        snapshot.identity.owner_id,
                        tunnel.channel_id,
                        tunnel.affinity_digest,
                        tunnel.client_transport_id,
                        tunnel.origin_transport_id,
                        tunnel.client_zeek_uid,
                        tunnel.origin_zeek_uid,
                        tunnel.tunnel_group_id,
                        tunnel.client_source_port,
                        tunnel.proxy_listener_port,
                        tunnel.origin_source_port,
                        tunnel.origin_destination_port,
                        encode_state_value(tunnel.opened_at),
                        encode_state_value(tunnel.closes_at),
                        encode_state_value(tunnel.reuse_deadline),
                        tunnel.planned_request_count,
                        tunnel.aggregate_request_wire_bytes,
                        tunnel.aggregate_response_wire_bytes,
                    ]
                )
    rows.sort(key=lambda row: row[1])
    return rows


def _restore_tunnel(manager: ExplicitProxyChannelManager, row: object) -> None:
    if (
        type(row) is not list
        or len(row) != 18
        or any(type(row[index]) is not str or not row[index] for index in range(8))
        or any(type(row[index]) is not int for index in range(8, 12))
        or any(type(row[index]) is not int or row[index] < 0 for index in range(15, 18))
    ):
        raise CheckpointCorruptionError("explicit-proxy checkpoint tunnel row is invalid")
    opened_at = _datetime(row[12], field_name="tunnel opening")
    closes_at = _datetime(row[13], field_name="tunnel closing")
    reuse_deadline = _datetime(row[14], field_name="tunnel reuse deadline")
    try:
        tunnel = ExplicitProxyTunnelIdentity(
            channel_id=row[1],
            affinity_digest=row[2],
            client_transport_id=row[3],
            origin_transport_id=row[4],
            client_zeek_uid=row[5],
            origin_zeek_uid=row[6],
            tunnel_group_id=row[7],
            client_source_port=row[8],
            proxy_listener_port=row[9],
            origin_source_port=row[10],
            origin_destination_port=row[11],
            opened_at=opened_at,
            closes_at=closes_at,
            reuse_deadline=reuse_deadline,
            planned_request_count=row[15],
            aggregate_request_wire_bytes=row[16],
            aggregate_response_wire_bytes=row[17],
        )
    except (TypeError, ValueError) as error:
        raise CheckpointCorruptionError(
            "explicit-proxy checkpoint tunnel row is invalid"
        ) from error
    owner_id = row[0]
    snapshot = manager._registry.get(tunnel.channel_id)
    if (
        snapshot is None
        or not snapshot.is_open
        or snapshot.identity.protocol != "explicit-proxy"
        or snapshot.identity.owner_id != owner_id
        or snapshot.identity.affinity_digest != tunnel.affinity_digest
        or snapshot.identity.binding.transport_id != tunnel.client_transport_id
        or snapshot.identity.binding.opened_at != tunnel.opened_at
        or snapshot.identity.binding.closes_at != tunnel.closes_at
        or tunnel.reuse_deadline <= manager._watermark
    ):
        raise CheckpointCorruptionError("explicit-proxy checkpoint tunnel binding changed")
    shard = manager._sidecar_shard(owner_id, create=True)
    assert shard is not None
    if (
        shard.tunnels.get(tunnel.channel_id) is not None
        or shard.tunnels.find_affinity(tunnel.affinity_digest) is not None
        or shard.tunnels.find_origin_transport(tunnel.origin_transport_id) is not None
    ):
        raise CheckpointCorruptionError("explicit-proxy checkpoint tunnel is duplicated")
    handle = shard.tunnels.insert(tunnel)
    shard.expiry.set(handle, min(tunnel.reuse_deadline, snapshot.idle_deadline).timestamp())


class ExplicitProxyChannelParticipant:
    """Persist open proxy tunnels and rebuild all packed sidecar routes."""

    checkpoint_owner = "proxy-channels"
    checkpoint_restore_priority = 30
    checkpoint_schema_version = _SCHEMA_VERSION
    checkpoint_state_fields = PROXY_CHANNEL_MANAGER_CHECKPOINT_FIELDS

    def __init__(self, manager: ExplicitProxyChannelManager) -> None:
        self.manager = manager

    def prepare_checkpoint(self, sequence: int) -> ParticipantSeal:
        """Capture only open tunnels after rejecting coupled admissions."""

        del sequence
        assert_complete_owner_inventory(
            self.manager,
            self.checkpoint_state_fields,
            owner_name="ExplicitProxyChannelManager",
        )
        with self.manager._gate.watermark(), self.manager._prepared_lock:
            assert_transient_owner_state_empty(
                self.manager,
                self.checkpoint_state_fields,
                owner_name="ExplicitProxyChannelManager",
            )
            with self.manager._directory_lock:
                document = _ProxyChannelHead(
                    schema_version=self.checkpoint_schema_version,
                    owns_registry=self.manager._owns_registry,
                    close_guard=encode_state_value(self.manager._close_guard),
                    idle_timeout=encode_state_value(self.manager._idle_timeout),
                    watermark=encode_state_value(self.manager._watermark),
                    next_admission_id=self.manager._next_admission_id,
                    tunnels=_capture_tunnels(self.manager),
                )
        return ParticipantSeal(
            head=HeadDraft(
                owner=self.checkpoint_owner,
                schema_version=self.checkpoint_schema_version,
                payload=dumps(document.model_dump(mode="python")),
            )
        )

    def checkpoint_committed(self, sequence: int) -> None:
        """The bounded proxy head owns no delta watermark."""

        del sequence

    def checkpoint_aborted(self, sequence: int) -> None:
        """The bounded proxy head owns no prepared publication state."""

        del sequence

    def restore_checkpoint(self, head: bytes, segments: tuple[bytes, ...]) -> None:
        """Restore proxy sidecars after the common registry is hydrated."""

        if segments:
            raise CheckpointCorruptionError("explicit-proxy checkpoint has unexpected segments")
        try:
            document = _ProxyChannelHead.model_validate(loads(head))
        except (TypeError, ValueError, ValidationError) as error:
            raise CheckpointCorruptionError("explicit-proxy checkpoint head is invalid") from error
        close_guard = decode_state_value(document.close_guard)
        idle_timeout = decode_state_value(document.idle_timeout)
        watermark = _datetime(document.watermark, field_name="watermark")
        if (
            document.schema_version != self.checkpoint_schema_version
            or document.owns_registry != self.manager._owns_registry
            or type(close_guard) is not timedelta
            or close_guard != self.manager._close_guard
            or type(idle_timeout) is not timedelta
            or idle_timeout != self.manager._idle_timeout
            or not self.manager._window_start <= watermark <= self.manager._registry._watermark
        ):
            raise CheckpointCorruptionError("explicit-proxy checkpoint configuration changed")
        if self.manager._shards:
            raise ValueError("explicit-proxy checkpoint hydration requires a fresh manager")
        self.manager._watermark = watermark
        self.manager._next_admission_id = document.next_admission_id
        for row in document.tunnels:
            _restore_tunnel(self.manager, row)


__all__ = ["ExplicitProxyChannelParticipant"]
