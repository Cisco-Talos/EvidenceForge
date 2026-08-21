# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Duration-stable application channels for explicit forward-proxy tunnels.

This manager owns only reusable application state. Network planning still owns
the two physical transports and rendering. A successful CONNECT setup is one
operation and later proxy-visible requests are compact child operations on the
same immutable transport identity. Completed operations collapse into counters;
payload bytes and rendered records are never retained.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import struct
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field, fields, replace
from datetime import UTC, datetime, timedelta
from threading import Condition, Lock, RLock
from typing import Literal

from evidenceforge.events.application import (
    ApplicationChannelBudget,
    ApplicationChannelCensus,
    ApplicationChannelIdentity,
    ApplicationChannelSnapshot,
    ApplicationOperationReservation,
    ApplicationTransportBinding,
)
from evidenceforge.generation.application_channels import (
    ApplicationChannelAdmissionReceipt,
    ApplicationChannelAdmissionResult,
    ApplicationChannelAdmissionToken,
    ApplicationChannelCloseToken,
    ApplicationChannelPreparedCommit,
    ApplicationChannelRegistry,
)
from evidenceforge.generation.indexes import (
    IndexMetrics,
    PackedByteRowStore,
    PackedHandleExpiryIndex,
    PackedUniqueDigestMap,
)
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.time import ensure_utc

ProxyChannelOutcome = Literal[
    "success",
    "denied",
    "authentication_required",
    "gateway_failure",
]

_DEFAULT_CLOSE_GUARD = timedelta(milliseconds=900)
_DEFAULT_CLOSED_GRACE = timedelta(seconds=30)
_DEFAULT_IDLE_TIMEOUT = timedelta(seconds=240)
_DEFAULT_SHARD_COUNT = 64
_SIDECAR_COMPACTION_WORK_PER_WATERMARK = 4_096
_REQUEST_GAP = timedelta(microseconds=1)
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_PROXY_TUNNEL_HEADER = struct.Struct("<4H3q8H")
_PROXY_TUNNEL_TEXT_FIELDS = 5
_PROXY_TUNNEL_INTEGER_FIELDS = 3
_PROXY_CHANNEL_PREFIX = "explicit-proxy-channel-"
_PROXY_CHANNEL_DIGEST_BYTES = 16
_PROXY_AFFINITY_DIGEST_BYTES = 32
_PROXY_MANAGER_KIND: Literal["explicit_proxy"] = "explicit_proxy"
_DECODED_CACHE_CAPACITY_PER_SHARD = 256
_EMPTY_PACKED_ROUTE_BYTES = 1_024
_ESTIMATED_PACKED_ROUTE_VALUE_BYTES = 128


def _required_text(value: str, field_name: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field_name} must not be empty")
    return normalized


def _port(value: int, field_name: str) -> int:
    if value <= 0 or value > 65_535:
        raise ValueError(f"{field_name} must be between 1 and 65535")
    return value


def _semantic_digest(namespace: str, values: tuple[str | int, ...]) -> str:
    """Return a stable collision-resistant digest for canonical primitive fields."""

    encoded = repr((namespace, *values)).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _canonical_hex_route_digest(
    value: str,
    *,
    prefix: str,
    hex_characters: int,
) -> int | None:
    """Return a packed route digest when a semantic ID already owns hex identity."""

    suffix = value.removeprefix(prefix)
    if not value.startswith(prefix) or len(suffix) != hex_characters:
        return None
    try:
        bytes.fromhex(suffix)
    except ValueError:
        return None
    return int(suffix[:16], 16)


def _normalized_hostname(value: str) -> str:
    normalized = _required_text(value, "origin_host").lower().rstrip(".")
    if not normalized:
        raise ValueError("origin_host must not contain only dots")
    return normalized


def _normalized_user_agent(value: str) -> str:
    return " ".join(value.casefold().split())


def _datetime_to_microseconds(value: datetime) -> int:
    delta = ensure_utc(value) - _EPOCH
    return ((delta.days * 86_400 + delta.seconds) * 1_000_000) + delta.microseconds


def _datetime_from_microseconds(value: int) -> datetime:
    return _EPOCH + timedelta(microseconds=value)


def _pack_unsigned(value: int) -> bytes:
    if value < 0:
        raise ValueError("Packed explicit-proxy integers must be non-negative")
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "little")


def _unpack_unsigned(value: bytes | memoryview) -> int:
    return int.from_bytes(value, "little")


def _validated_application_identity(
    *,
    channel_id: str,
    owner_id: str,
    affinity_digest: str,
    transport_id: str,
    opened_at: datetime,
    closes_at: datetime,
    idle_timeout: timedelta,
    initiator_bytes: int,
    responder_bytes: int,
    operations: int,
) -> ApplicationChannelIdentity:
    """Build a canonical common identity after proxy-boundary validation.

    ``open_tunnel`` has already normalized every string/time and checked the
    transport interval and non-negative budgets.  Building these frozen value
    objects directly avoids repeating four dataclass normalization passes for
    every retained tunnel; the common registry still enforces window,
    containment, uniqueness, affinity, and budget admission atomically.
    """

    binding = object.__new__(ApplicationTransportBinding)
    object.__setattr__(binding, "transport_id", transport_id)
    object.__setattr__(binding, "opened_at", opened_at)
    object.__setattr__(binding, "closes_at", closes_at)
    budget = object.__new__(ApplicationChannelBudget)
    object.__setattr__(budget, "initiator_bytes", initiator_bytes)
    object.__setattr__(budget, "responder_bytes", responder_bytes)
    object.__setattr__(budget, "operations", operations)
    identity = object.__new__(ApplicationChannelIdentity)
    object.__setattr__(identity, "channel_id", channel_id)
    object.__setattr__(identity, "protocol", "explicit-proxy")
    object.__setattr__(identity, "owner_id", owner_id)
    object.__setattr__(identity, "affinity_digest", affinity_digest)
    object.__setattr__(identity, "binding", binding)
    object.__setattr__(identity, "opened_at", opened_at)
    object.__setattr__(identity, "idle_timeout", idle_timeout)
    object.__setattr__(identity, "hard_deadline", closes_at)
    object.__setattr__(identity, "budget", budget)
    return identity


def _validated_completed_operation(
    *,
    operation_id: str,
    channel_id: str,
    ordinal: int,
    started_at: datetime,
    ended_at: datetime,
    initiator_bytes: int,
    responder_bytes: int,
) -> ApplicationOperationReservation:
    """Build a normalized immediate operation after proxy-boundary checks."""

    reservation = object.__new__(ApplicationOperationReservation)
    object.__setattr__(reservation, "operation_id", operation_id)
    object.__setattr__(reservation, "channel_id", channel_id)
    object.__setattr__(reservation, "ordinal", ordinal)
    object.__setattr__(reservation, "started_at", started_at)
    object.__setattr__(reservation, "ended_at", ended_at)
    object.__setattr__(reservation, "initiator_bytes", initiator_bytes)
    object.__setattr__(reservation, "responder_bytes", responder_bytes)
    object.__setattr__(reservation, "parent_operation_id", "")
    return reservation


@dataclass(frozen=True, slots=True)
class ExplicitProxyChannelAffinity:
    """Exact semantic reuse boundary for one client/proxy/origin relationship."""

    client_ip: str
    proxy_ip: str
    proxy_port: int
    origin_host: str
    origin_ip: str
    origin_port: int
    user_agent: str
    auth_identity: str
    policy_id: str

    def __post_init__(self) -> None:
        """Normalize case-insensitive fields while retaining every fence."""

        object.__setattr__(self, "client_ip", _required_text(self.client_ip, "client_ip"))
        object.__setattr__(self, "proxy_ip", _required_text(self.proxy_ip, "proxy_ip"))
        object.__setattr__(self, "proxy_port", _port(self.proxy_port, "proxy_port"))
        object.__setattr__(self, "origin_host", _normalized_hostname(self.origin_host))
        object.__setattr__(self, "origin_ip", _required_text(self.origin_ip, "origin_ip"))
        object.__setattr__(self, "origin_port", _port(self.origin_port, "origin_port"))
        object.__setattr__(self, "user_agent", _normalized_user_agent(self.user_agent))
        object.__setattr__(self, "auth_identity", self.auth_identity.strip())
        object.__setattr__(self, "policy_id", _required_text(self.policy_id, "policy_id"))

    @property
    def digest(self) -> str:
        """Return a stable digest containing every permitted reuse dimension."""

        return _semantic_digest(
            "explicit-proxy-affinity-v1",
            (
                self.client_ip,
                self.proxy_ip,
                self.proxy_port,
                self.origin_host,
                self.origin_ip,
                self.origin_port,
                self.user_agent,
                self.auth_identity,
                self.policy_id,
            ),
        )

    @property
    def owner_id(self) -> str:
        """Return the stable client/proxy ownership partition."""

        return f"explicit-proxy:{self.client_ip}:{self.proxy_ip}:{self.proxy_port}"


@dataclass(frozen=True, slots=True)
class ExplicitProxyTunnelIdentity:
    """Frozen identities and aggregate limits for one successful tunnel."""

    channel_id: str
    affinity_digest: str
    client_transport_id: str
    origin_transport_id: str
    client_zeek_uid: str
    origin_zeek_uid: str
    tunnel_group_id: str
    client_source_port: int
    proxy_listener_port: int
    origin_source_port: int
    origin_destination_port: int
    opened_at: datetime
    closes_at: datetime
    reuse_deadline: datetime
    planned_request_count: int
    aggregate_request_wire_bytes: int
    aggregate_response_wire_bytes: int

    def __post_init__(self) -> None:
        """Validate immutable wire identity and aggregate browser budgets."""

        for field_name in (
            "channel_id",
            "affinity_digest",
            "client_transport_id",
            "origin_transport_id",
            "client_zeek_uid",
            "origin_zeek_uid",
            "tunnel_group_id",
        ):
            object.__setattr__(
                self,
                field_name,
                _required_text(getattr(self, field_name), field_name),
            )
        for field_name in (
            "client_source_port",
            "proxy_listener_port",
            "origin_source_port",
            "origin_destination_port",
        ):
            object.__setattr__(self, field_name, _port(getattr(self, field_name), field_name))
        if self.planned_request_count < 0:
            raise ValueError("planned_request_count must be non-negative")
        if (
            min(
                self.aggregate_request_wire_bytes,
                self.aggregate_response_wire_bytes,
            )
            < 0
        ):
            raise ValueError("Explicit-proxy aggregate byte budgets must be non-negative")
        opened_at = ensure_utc(self.opened_at)
        closes_at = ensure_utc(self.closes_at)
        reuse_deadline = ensure_utc(self.reuse_deadline)
        if closes_at <= opened_at:
            raise ValueError("Explicit-proxy tunnel close must follow its open")
        if reuse_deadline < opened_at or reuse_deadline > closes_at:
            raise ValueError("Explicit-proxy reuse deadline must be inside its transport")
        object.__setattr__(self, "opened_at", opened_at)
        object.__setattr__(self, "closes_at", closes_at)
        object.__setattr__(self, "reuse_deadline", reuse_deadline)


@dataclass(frozen=True, slots=True)
class ExplicitProxyTunnelOpen:
    """Result of a successful setup, including a setup-only tunnel."""

    tunnel: ExplicitProxyTunnelIdentity
    setup_operation_id: str
    remaining_request_count: int
    remaining_request_wire_bytes: int
    remaining_response_wire_bytes: int


@dataclass(frozen=True, slots=True)
class ExplicitProxyRequestReuse:
    """Exact reusable tunnel identity returned for one accepted child request."""

    tunnel: ExplicitProxyTunnelIdentity
    operation_id: str
    ordinal: int
    canonical_request_time: datetime
    canonical_complete_time: datetime
    remaining_request_count: int
    remaining_request_wire_bytes: int
    remaining_response_wire_bytes: int

    def __post_init__(self) -> None:
        """Normalize returned times and preserve their ordering."""

        request_time = ensure_utc(self.canonical_request_time)
        complete_time = ensure_utc(self.canonical_complete_time)
        if complete_time < request_time:
            raise ValueError("Explicit-proxy request completion cannot precede its request")
        object.__setattr__(self, "canonical_request_time", request_time)
        object.__setattr__(self, "canonical_complete_time", complete_time)


@dataclass(frozen=True, slots=True)
class ExplicitProxyTerminalRequest:
    """Frozen terminal request and exact channel-retirement intent."""

    tunnel: ExplicitProxyTunnelIdentity
    operation_id: str
    ordinal: int
    outcome: Literal["denied", "authentication_required", "gateway_failure"]
    canonical_request_time: datetime
    canonical_complete_time: datetime
    close_at: datetime
    close_reason: str

    def __post_init__(self) -> None:
        """Normalize and validate the terminal request interval."""

        request_time = ensure_utc(self.canonical_request_time)
        complete_time = ensure_utc(self.canonical_complete_time)
        close_at = ensure_utc(self.close_at)
        if complete_time < request_time:
            raise ValueError("Explicit-proxy terminal completion cannot precede its request")
        if close_at < complete_time:
            raise ValueError("Explicit-proxy terminal close cannot precede its completion")
        if not self.close_reason.strip():
            raise ValueError("Explicit-proxy terminal request requires a close reason")
        object.__setattr__(self, "canonical_request_time", request_time)
        object.__setattr__(self, "canonical_complete_time", complete_time)
        object.__setattr__(self, "close_at", close_at)


ProxyAdmissionResult = (
    ExplicitProxyTunnelOpen | ExplicitProxyRequestReuse | ExplicitProxyTerminalRequest
)


@dataclass(frozen=True, slots=True)
class ExplicitProxyRequestSnapshot:
    """Authenticated immutable view used before a deferred request preparation."""

    manager_id: str
    affinity_digest: str
    requested_at: datetime
    tunnel: ExplicitProxyTunnelIdentity
    application_snapshot: ApplicationChannelSnapshot
    generation_token: ApplicationChannelCloseToken
    _manager_token: int = field(repr=False, default=0)
    _integrity_token: str = field(repr=False, default="")

    def __post_init__(self) -> None:
        """Normalize request time and require exact sidecar/common agreement."""

        object.__setattr__(self, "requested_at", ensure_utc(self.requested_at))
        if self.affinity_digest != self.tunnel.affinity_digest:
            raise ValueError("Explicit-proxy request snapshot changed affinity")
        if self.application_snapshot.channel_id != self.tunnel.channel_id:
            raise ValueError("Explicit-proxy request snapshot changed channel identity")

    @property
    def snapshot_token(self) -> str:
        """Return the opaque keyed proof over this exact current tunnel view."""

        return self._integrity_token


@dataclass(frozen=True, slots=True)
class ExplicitProxyAdmissionToken:
    """Opaque coupled reservation for common-channel and proxy-sidecar state."""

    kind: Literal["open", "request"]
    application_token: ApplicationChannelAdmissionToken = field(repr=False)
    result: ProxyAdmissionResult
    _manager_token: int = field(repr=False)
    _admission_id: int = field(repr=False)
    _owner_id: str = field(repr=False)
    _expected_tunnel: ExplicitProxyTunnelIdentity | None = field(repr=False)
    _replacement_channel_id: str = field(repr=False, default="")
    _reserved_channel_ids: tuple[str, ...] = field(repr=False, default=())
    _reserved_affinity_key: tuple[str, str] = field(repr=False, default=("", ""))
    _reserved_origin_transport_ids: tuple[str, ...] = field(repr=False, default=())
    _application_publication_token: str = field(repr=False, default="")
    _token_seal: bytes = field(repr=False, default=b"")

    @property
    def linearization_time(self) -> datetime:
        """Return the common canonical frontier fenced while this token is claimed."""

        return self.application_token.linearization_time

    @property
    def publication_token(self) -> str:
        """Return the opaque keyed capability binding for external coordinators."""

        return self._token_seal.hex()


def _proxy_admission_seal(
    authority_secret: bytes,
    token: ExplicitProxyAdmissionToken,
) -> bytes:
    """Return an integrity seal over the complete proxy capability payload."""

    payload = tuple(
        (item.name, getattr(token, item.name))
        for item in fields(token)
        if item.name != "_token_seal"
    )
    return hmac.new(authority_secret, repr(payload).encode("utf-8"), hashlib.sha256).digest()


def _prepared_proxy_admission_estimated_bytes(token: ExplicitProxyAdmissionToken) -> int:
    """Estimate proxy-owned prepared values without double-counting common state."""

    retained = sum(
        sys.getsizeof(value)
        for value in (
            token,
            token.result,
            token._reserved_channel_ids,
            token._reserved_affinity_key,
            token._reserved_origin_transport_ids,
            token._application_publication_token,
            token._token_seal,
        )
    )
    if isinstance(token.result, ExplicitProxyTunnelOpen):
        retained += _tunnel_estimated_bytes(token.result.tunnel)
    return retained


@dataclass(frozen=True, slots=True)
class _ExplicitProxyAdmissionCapability:
    """Manager-owned immutable locator and release metadata for one public token."""

    token_id: int
    admission_id: int
    manager_token: int
    owner_id: str
    reserved_channel_ids: tuple[str, ...]
    reserved_affinity_key: tuple[str, str]
    reserved_origin_transport_ids: tuple[str, ...]
    application_publication_token: str
    token_seal: bytes
    linearization_time: datetime
    estimated_bytes: int


@dataclass(frozen=True, slots=True)
class ExplicitProxyAdmissionReceipt:
    """Authenticated proof of one committed common and proxy admission."""

    manager_kind: Literal["explicit_proxy"]
    manager_id: str
    kind: Literal["open", "request"]
    publication_token: str
    application_receipt: ApplicationChannelAdmissionReceipt
    application_receipt_token: str
    channel_id: str
    operation_id: str
    current_transport_id: str
    prerequisite_transport_ids: tuple[str, ...]
    origin_affinity_digest: str
    sidecar_result: ProxyAdmissionResult
    sidecar_result_digest: str
    _manager_token: int = field(repr=False, default=0)
    _integrity_token: str = field(repr=False, default="")

    @property
    def receipt_token(self) -> str:
        """Return the opaque keyed proof over the exact committed result."""

        return self._integrity_token

    @property
    def common_receipt_token(self) -> str:
        """Return the nested common-registry proof for composite authorities."""

        return self.application_receipt_token

    @property
    def manager_instance_id(self) -> str:
        """Return the stable manager identity under its explicit public name."""

        return self.manager_id

    @property
    def result(self) -> ProxyAdmissionResult:
        """Return the exact frozen sidecar result for compatibility consumers."""

        return self.sidecar_result

    @property
    def physical_transport_ids(self) -> tuple[str, ...]:
        """Return client-to-proxy and proxy-to-origin transport identities."""

        return (*self.prerequisite_transport_ids, self.current_transport_id)

    @property
    def result_digest(self) -> str:
        """Return a stable digest of the exact frozen proxy result snapshot."""

        return self.sidecar_result_digest


def _proxy_admission_transport_legs(
    result: ProxyAdmissionResult,
) -> tuple[str, tuple[str, ...]]:
    """Return the exact transport owned by each proxy admission kind."""

    tunnel = result.tunnel
    if isinstance(result, ExplicitProxyTunnelOpen):
        return tunnel.origin_transport_id, (tunnel.client_transport_id,)
    return tunnel.client_transport_id, ()


def _proxy_admission_operation_id(result: ProxyAdmissionResult) -> str:
    """Return the common operation represented by one proxy sidecar result."""

    if isinstance(result, ExplicitProxyTunnelOpen):
        return result.setup_operation_id
    return result.operation_id


def explicit_proxy_sidecar_result_digest(result: ProxyAdmissionResult) -> str:
    """Return a stable digest of one exact frozen proxy sidecar result."""

    return hashlib.sha256(repr(("explicit-proxy-admission-result-v1", result)).encode()).hexdigest()


def _proxy_request_snapshot_integrity_token(
    authority_secret: bytes,
    snapshot: ExplicitProxyRequestSnapshot,
) -> str:
    """Authenticate one manager-issued immutable current-tunnel projection."""

    canonical = repr(
        (
            "explicit-proxy-request-snapshot-v1",
            snapshot.manager_id,
            snapshot.affinity_digest,
            snapshot.requested_at,
            snapshot.tunnel,
            snapshot.application_snapshot,
            snapshot.generation_token,
            snapshot._manager_token,
        )
    ).encode()
    return hmac.new(authority_secret, canonical, hashlib.sha256).hexdigest()


def _proxy_admission_receipt_integrity_token(
    authority_secret: bytes,
    receipt: ExplicitProxyAdmissionReceipt,
) -> str:
    """Authenticate the nested common receipt and exact sidecar result."""

    canonical = repr(
        (
            "explicit-proxy-admission-receipt-v3",
            receipt.manager_kind,
            receipt.manager_id,
            receipt.kind,
            receipt.publication_token,
            receipt.application_receipt,
            receipt.application_receipt_token,
            receipt.channel_id,
            receipt.operation_id,
            receipt.current_transport_id,
            receipt.prerequisite_transport_ids,
            receipt.origin_affinity_digest,
            receipt.sidecar_result,
            receipt.sidecar_result_digest,
            receipt._manager_token,
        )
    ).encode()
    return hmac.new(authority_secret, canonical, hashlib.sha256).hexdigest()


@dataclass(frozen=True, slots=True)
class ExplicitProxyAdmissionCommitResult:
    """Frozen proxy result plus authenticated coupled-publication proof."""

    result: ProxyAdmissionResult
    receipt: ExplicitProxyAdmissionReceipt


class ExplicitProxyPreparedCommit:
    """No-lock-body proxy commit capability for one claimed admission."""

    __slots__ = (
        "_active",
        "_application_commit",
        "_committed",
        "_manager",
        "_result",
        "_token",
    )

    def __init__(
        self,
        manager: ExplicitProxyChannelManager,
        token: ExplicitProxyAdmissionToken,
        application_commit: ApplicationChannelPreparedCommit,
    ) -> None:
        self._manager = manager
        self._token = token
        self._application_commit = application_commit
        self._active = True
        self._committed = False
        self._result: ExplicitProxyAdmissionCommitResult | None = None

    @property
    def committed(self) -> bool:
        """Return whether this exact claimed admission has committed."""

        return self._committed

    @property
    def result(self) -> ExplicitProxyAdmissionCommitResult | None:
        """Return the committed immutable proxy result, if any."""

        return self._result

    def commit_no_fail(self) -> ExplicitProxyAdmissionCommitResult:
        """Publish the already-validated common and proxy mutations once."""

        if not self._active:
            raise StateError("explicit-proxy prepared commit is no longer active")
        if self._committed:
            raise StateError("explicit-proxy admission was already committed")
        self._result = self._manager._commit_claimed_admission(
            self._token,
            self._application_commit,
        )
        self._committed = True
        return self._result

    def _close(self) -> None:
        self._active = False


@dataclass(frozen=True, slots=True)
class ExplicitProxyChannelCensus:
    """Low-cost retained-state and expiry amplification metrics."""

    open_tunnel_views: int
    tunnel_expiry_entries: int
    stale_tunnel_expiry_entries: int
    sidecar_shard_count: int
    max_sidecar_shard_load: int
    sidecar_allocated_slots: int
    sidecar_primary_map_bytes: int
    sidecar_primary_map_amplification: float
    sidecar_estimated_bytes: int
    sidecar_estimated_index_bytes: int
    decoded_cache_entries: int
    decoded_cache_capacity: int
    decoded_cache_estimated_bytes: int
    sidecar_lookup_candidates_inspected: int
    sidecar_compaction_pending: int
    sidecar_compaction_rotations: int
    sidecar_compaction_work: int
    sidecar_compaction_seconds: float
    prepared_admissions: int
    claimed_admissions: int
    reserved_channel_ids: int
    reserved_affinities: int
    reserved_origin_transport_ids: int
    estimated_prepared_bytes: int
    application: ApplicationChannelCensus


class _SidecarMutationGate:
    """Allow disjoint-owner work while giving watermarks exclusive admission."""

    def __init__(self) -> None:
        self._condition = Condition(Lock())
        self._readers = 0
        self._writer = False
        self._waiting_writers = 0

    @contextmanager
    def mutation(self) -> Iterator[None]:
        """Enter a concurrent sidecar operation lane."""

        with self._condition:
            while self._writer or self._waiting_writers:
                self._condition.wait()
            self._readers += 1
        try:
            yield
        finally:
            with self._condition:
                self._readers -= 1
                if self._readers == 0:
                    self._condition.notify_all()

    @contextmanager
    def watermark(self) -> Iterator[None]:
        """Enter the exclusive sidecar expiry/compaction lane."""

        with self._condition:
            self._waiting_writers += 1
            try:
                while self._writer or self._readers:
                    self._condition.wait()
                self._writer = True
            finally:
                self._waiting_writers -= 1
        try:
            yield
        finally:
            with self._condition:
                self._writer = False
                self._condition.notify_all()


def _tunnel_estimated_bytes(tunnel: ExplicitProxyTunnelIdentity) -> int:
    """Return a shallow, length-aware retained-byte estimate for one tunnel."""

    return sum(
        sys.getsizeof(value)
        for value in (
            tunnel,
            tunnel.channel_id,
            tunnel.affinity_digest,
            tunnel.client_transport_id,
            tunnel.origin_transport_id,
            tunnel.client_zeek_uid,
            tunnel.origin_zeek_uid,
            tunnel.tunnel_group_id,
            tunnel.opened_at,
            tunnel.closes_at,
            tunnel.reuse_deadline,
        )
    )


class _PackedProxyTunnelStore:
    """Packed open-only proxy rows with exact routes and bounded decoding."""

    def __init__(self) -> None:
        self._rows = PackedByteRowStore(inline_slot_bytes=256, chunk_slots=256)
        self._channel_routes = PackedUniqueDigestMap(b"ef-prx-channel")
        self._affinity_routes = PackedUniqueDigestMap(b"ef-prx-aff")
        self._origin_transport_routes = PackedUniqueDigestMap(b"ef-prx-origin")
        self._decoded: dict[int, ExplicitProxyTunnelIdentity] = {}
        self._decoded_bytes = 0
        self._lookup_candidates_inspected = 0
        self._compaction_rotations = 0

    def __len__(self) -> int:
        return len(self._rows)

    @staticmethod
    def _pack(tunnel: ExplicitProxyTunnelIdentity) -> bytes:
        channel_digest = tunnel.channel_id.removeprefix(_PROXY_CHANNEL_PREFIX)
        if (
            not tunnel.channel_id.startswith(_PROXY_CHANNEL_PREFIX)
            or len(channel_digest) != _PROXY_CHANNEL_DIGEST_BYTES * 2
        ):
            raise ValueError("Explicit-proxy packed channel ID has an invalid digest shape")
        if len(tunnel.affinity_digest) != _PROXY_AFFINITY_DIGEST_BYTES * 2:
            raise ValueError("Explicit-proxy packed affinity has an invalid digest shape")
        try:
            channel_key = bytes.fromhex(channel_digest)
            affinity_key = bytes.fromhex(tunnel.affinity_digest)
        except ValueError as exc:
            raise ValueError("Explicit-proxy packed digests must be hexadecimal") from exc
        text = tuple(
            value.encode("utf-8")
            for value in (
                tunnel.client_transport_id,
                tunnel.origin_transport_id,
                tunnel.client_zeek_uid,
                tunnel.origin_zeek_uid,
                tunnel.tunnel_group_id,
            )
        )
        integers = tuple(
            _pack_unsigned(value)
            for value in (
                tunnel.planned_request_count,
                tunnel.aggregate_request_wire_bytes,
                tunnel.aggregate_response_wire_bytes,
            )
        )
        lengths = tuple(len(value) for value in (*text, *integers))
        if any(length >= 1 << 16 for length in lengths):
            raise ValueError(
                "Explicit-proxy packed text and integer fields must be shorter than 65,536 bytes"
            )
        return (
            _PROXY_TUNNEL_HEADER.pack(
                tunnel.client_source_port,
                tunnel.proxy_listener_port,
                tunnel.origin_source_port,
                tunnel.origin_destination_port,
                _datetime_to_microseconds(tunnel.opened_at),
                _datetime_to_microseconds(tunnel.closes_at),
                _datetime_to_microseconds(tunnel.reuse_deadline),
                *lengths,
            )
            + channel_key
            + affinity_key
            + b"".join(text)
            + b"".join(integers)
        )

    @staticmethod
    def _unpack(row: bytes | memoryview) -> ExplicitProxyTunnelIdentity:
        values = _PROXY_TUNNEL_HEADER.unpack_from(row)
        ports = values[:4]
        times = values[4:7]
        lengths = values[7:]
        text_lengths = lengths[:_PROXY_TUNNEL_TEXT_FIELDS]
        integer_lengths = lengths[
            _PROXY_TUNNEL_TEXT_FIELDS : _PROXY_TUNNEL_TEXT_FIELDS + _PROXY_TUNNEL_INTEGER_FIELDS
        ]
        offset = _PROXY_TUNNEL_HEADER.size
        channel_key = bytes(row[offset : offset + _PROXY_CHANNEL_DIGEST_BYTES])
        offset += _PROXY_CHANNEL_DIGEST_BYTES
        affinity_key = bytes(row[offset : offset + _PROXY_AFFINITY_DIGEST_BYTES])
        offset += _PROXY_AFFINITY_DIGEST_BYTES
        text: list[str] = []
        for length in text_lengths:
            text.append(bytes(row[offset : offset + length]).decode("utf-8"))
            offset += length
        integers: list[int] = []
        for length in integer_lengths:
            integers.append(_unpack_unsigned(row[offset : offset + length]))
            offset += length

        tunnel = object.__new__(ExplicitProxyTunnelIdentity)
        object.__setattr__(
            tunnel,
            "channel_id",
            f"{_PROXY_CHANNEL_PREFIX}{channel_key.hex()}",
        )
        object.__setattr__(tunnel, "affinity_digest", affinity_key.hex())
        for name, value in zip(
            (
                "client_transport_id",
                "origin_transport_id",
                "client_zeek_uid",
                "origin_zeek_uid",
                "tunnel_group_id",
            ),
            text,
            strict=True,
        ):
            object.__setattr__(tunnel, name, value)
        for name, value in zip(
            (
                "client_source_port",
                "proxy_listener_port",
                "origin_source_port",
                "origin_destination_port",
            ),
            ports,
            strict=True,
        ):
            object.__setattr__(tunnel, name, value)
        for name, value in zip(
            ("opened_at", "closes_at", "reuse_deadline"),
            times,
            strict=True,
        ):
            object.__setattr__(tunnel, name, _datetime_from_microseconds(value))
        for name, value in zip(
            (
                "planned_request_count",
                "aggregate_request_wire_bytes",
                "aggregate_response_wire_bytes",
            ),
            integers,
            strict=True,
        ):
            object.__setattr__(tunnel, name, value)
        return tunnel

    def _decode(self, handle: int) -> ExplicitProxyTunnelIdentity:
        cached = self._decoded.get(handle)
        if cached is not None:
            return cached
        tunnel = self._unpack(self._rows.get_by_handle(handle))
        if len(self._decoded) >= _DECODED_CACHE_CAPACITY_PER_SHARD:
            oldest = next(iter(self._decoded))
            evicted = self._decoded.pop(oldest)
            self._decoded_bytes -= _tunnel_estimated_bytes(evicted)
        self._decoded[handle] = tunnel
        self._decoded_bytes += _tunnel_estimated_bytes(tunnel)
        return tunnel

    @staticmethod
    def _verify(value: str, expected: str, route_name: str) -> None:
        if value != expected:
            raise StateError(f"Explicit-proxy packed {route_name} digest collision")

    def _lookup(
        self,
        route: PackedUniqueDigestMap,
        key: str,
        *,
        digest: int,
        field_name: str,
        route_name: str,
        count_candidate: bool,
    ) -> ExplicitProxyTunnelIdentity | None:
        handle = route.get_digest(digest)
        if handle is None:
            return None
        tunnel = self._decode(handle)
        self._verify(getattr(tunnel, field_name), key, route_name)
        if count_candidate:
            self._lookup_candidates_inspected += 1
        return tunnel

    def get(self, channel_id: str) -> ExplicitProxyTunnelIdentity | None:
        digest = _canonical_hex_route_digest(
            channel_id,
            prefix=_PROXY_CHANNEL_PREFIX,
            hex_characters=_PROXY_CHANNEL_DIGEST_BYTES * 2,
        )
        return self._lookup(
            self._channel_routes,
            channel_id,
            digest=(self._channel_routes.digest(channel_id) if digest is None else digest),
            field_name="channel_id",
            route_name="channel route",
            count_candidate=True,
        )

    def find_affinity(self, affinity_digest: str) -> ExplicitProxyTunnelIdentity | None:
        digest = _canonical_hex_route_digest(
            affinity_digest,
            prefix="",
            hex_characters=_PROXY_AFFINITY_DIGEST_BYTES * 2,
        )
        return self._lookup(
            self._affinity_routes,
            affinity_digest,
            digest=(self._affinity_routes.digest(affinity_digest) if digest is None else digest),
            field_name="affinity_digest",
            route_name="affinity route",
            count_candidate=True,
        )

    def find_origin_transport(self, transport_id: str) -> ExplicitProxyTunnelIdentity | None:
        return self._lookup(
            self._origin_transport_routes,
            transport_id,
            digest=self._origin_transport_routes.digest(transport_id),
            field_name="origin_transport_id",
            route_name="origin transport route",
            count_candidate=True,
        )

    def peek(self, channel_id: str) -> ExplicitProxyTunnelIdentity | None:
        """Return an exact channel row without charging a caller lookup candidate."""

        digest = _canonical_hex_route_digest(
            channel_id,
            prefix=_PROXY_CHANNEL_PREFIX,
            hex_characters=_PROXY_CHANNEL_DIGEST_BYTES * 2,
        )
        return self._lookup(
            self._channel_routes,
            channel_id,
            digest=(self._channel_routes.digest(channel_id) if digest is None else digest),
            field_name="channel_id",
            route_name="channel route",
            count_candidate=False,
        )

    def peek_affinity(self, affinity_digest: str) -> ExplicitProxyTunnelIdentity | None:
        """Return one affinity row for internal validation without telemetry."""

        digest = _canonical_hex_route_digest(
            affinity_digest,
            prefix="",
            hex_characters=_PROXY_AFFINITY_DIGEST_BYTES * 2,
        )
        return self._lookup(
            self._affinity_routes,
            affinity_digest,
            digest=(self._affinity_routes.digest(affinity_digest) if digest is None else digest),
            field_name="affinity_digest",
            route_name="affinity route",
            count_candidate=False,
        )

    def peek_origin_transport(self, transport_id: str) -> ExplicitProxyTunnelIdentity | None:
        """Return one origin route for internal validation without telemetry."""

        return self._lookup(
            self._origin_transport_routes,
            transport_id,
            digest=self._origin_transport_routes.digest(transport_id),
            field_name="origin_transport_id",
            route_name="origin transport route",
            count_candidate=False,
        )

    def get_by_handle(self, handle: int) -> ExplicitProxyTunnelIdentity:
        return self._decode(handle)

    def handle_for(self, channel_id: str) -> int:
        digest = _canonical_hex_route_digest(
            channel_id,
            prefix=_PROXY_CHANNEL_PREFIX,
            hex_characters=_PROXY_CHANNEL_DIGEST_BYTES * 2,
        )
        handle = self._channel_routes.get_digest(
            self._channel_routes.digest(channel_id) if digest is None else digest
        )
        if handle is None:
            raise KeyError(channel_id)
        tunnel = self._decode(handle)
        self._verify(tunnel.channel_id, channel_id, "channel route")
        return handle

    def insert(self, tunnel: ExplicitProxyTunnelIdentity) -> int:
        channel_digest = _canonical_hex_route_digest(
            tunnel.channel_id,
            prefix=_PROXY_CHANNEL_PREFIX,
            hex_characters=_PROXY_CHANNEL_DIGEST_BYTES * 2,
        )
        affinity_digest = _canonical_hex_route_digest(
            tunnel.affinity_digest,
            prefix="",
            hex_characters=_PROXY_AFFINITY_DIGEST_BYTES * 2,
        )
        if channel_digest is None or affinity_digest is None:
            raise ValueError("Explicit-proxy packed routes require canonical hexadecimal IDs")
        route_values = tuple(
            (route, key, digest, field_name, route_name)
            for route, key, digest, field_name, route_name in (
                (
                    self._channel_routes,
                    tunnel.channel_id,
                    channel_digest,
                    "channel_id",
                    "channel route",
                ),
                (
                    self._affinity_routes,
                    tunnel.affinity_digest,
                    affinity_digest,
                    "affinity_digest",
                    "affinity route",
                ),
                (
                    self._origin_transport_routes,
                    tunnel.origin_transport_id,
                    self._origin_transport_routes.digest(tunnel.origin_transport_id),
                    "origin_transport_id",
                    "origin transport route",
                ),
            )
        )
        for route, key, digest, field_name, route_name in route_values:
            handle = route.get_digest(digest)
            if handle is None:
                continue
            retained = self._decode(handle)
            self._verify(getattr(retained, field_name), key, route_name)
            raise StateError(f"Duplicate explicit-proxy packed {route_name}")

        handle = self._rows.insert(self._pack(tunnel))
        for route, _key, digest, _field_name, _route_name in route_values:
            route.set_digest(digest, handle)
        return handle

    def delete(self, channel_id: str) -> ExplicitProxyTunnelIdentity | None:
        channel_digest = _canonical_hex_route_digest(
            channel_id,
            prefix=_PROXY_CHANNEL_PREFIX,
            hex_characters=_PROXY_CHANNEL_DIGEST_BYTES * 2,
        )
        handle = self._channel_routes.get_digest(
            self._channel_routes.digest(channel_id) if channel_digest is None else channel_digest
        )
        if handle is None:
            return None
        tunnel = self._decode(handle)
        self._verify(tunnel.channel_id, channel_id, "channel route")
        self._channel_routes.pop_digest(
            self._channel_routes.digest(channel_id) if channel_digest is None else channel_digest
        )
        affinity_digest = _canonical_hex_route_digest(
            tunnel.affinity_digest,
            prefix="",
            hex_characters=_PROXY_AFFINITY_DIGEST_BYTES * 2,
        )
        self._affinity_routes.pop_digest(
            self._affinity_routes.digest(tunnel.affinity_digest)
            if affinity_digest is None
            else affinity_digest
        )
        self._origin_transport_routes.pop(tunnel.origin_transport_id)
        reclaimed_arena = len(self) == 1
        self._rows.delete(handle)
        if reclaimed_arena:
            self._compaction_rotations += 1
        cached = self._decoded.pop(handle, None)
        if cached is not None:
            self._decoded_bytes -= _tunnel_estimated_bytes(cached)
        return tunnel

    @property
    def estimated_value_bytes(self) -> int:
        return self._rows.estimated_value_bytes + sys.getsizeof(self._decoded) + self._decoded_bytes

    @property
    def decoded_cache_entries(self) -> int:
        return len(self._decoded)

    @property
    def decoded_cache_estimated_bytes(self) -> int:
        return sys.getsizeof(self._decoded) + self._decoded_bytes

    def compact_primary(self, *, max_slots: int = 4_096, force: bool = False) -> int:
        if max_slots < 0:
            raise ValueError("Explicit-proxy packed compaction budget cannot be negative")
        for route in (
            self._channel_routes,
            self._affinity_routes,
            self._origin_transport_routes,
        ):
            before = route.metrics().primary_map_backing_bytes
            route.compact_primary(max_entries=max_slots, force=force)
            after = route.metrics().primary_map_backing_bytes
            if after < before:
                self._compaction_rotations += 1
        return 0

    def metrics(self, *, estimate_bytes: bool = False) -> IndexMetrics:
        rows = self._rows.metrics(estimate_bytes=estimate_bytes)
        routes = tuple(
            route.metrics(estimate_bytes=estimate_bytes)
            for route in (
                self._channel_routes,
                self._affinity_routes,
                self._origin_transport_routes,
            )
        )
        return IndexMetrics(
            live_entries=rows.live_entries,
            backing_entries=rows.backing_entries,
            stale_entries=rows.stale_entries,
            allocated_slots=rows.allocated_slots,
            high_water_mark=rows.high_water_mark,
            lookup_candidates_inspected=self._lookup_candidates_inspected,
            estimated_bytes=rows.estimated_bytes + sum(item.estimated_bytes for item in routes),
            primary_map_entries=sum(item.primary_map_entries for item in routes),
            primary_map_backing_bytes=sum(item.primary_map_backing_bytes for item in routes),
            primary_compaction_rotations=self._compaction_rotations,
        )


@dataclass(slots=True)
class _ProxySidecarShard:
    """Open-only protocol metadata for one stable owner partition."""

    shard_id: int
    lock: RLock = field(default_factory=RLock)
    tunnels: _PackedProxyTunnelStore = field(default_factory=_PackedProxyTunnelStore)
    expiry: PackedHandleExpiryIndex = field(default_factory=PackedHandleExpiryIndex)


class ExplicitProxyChannelManager:
    """Own bounded CONNECT setup and browser-request reuse state."""

    def __init__(
        self,
        *,
        window_start: datetime,
        window_end: datetime,
        registry: ApplicationChannelRegistry | None = None,
        allow_private_registry: bool = False,
        close_guard: timedelta = _DEFAULT_CLOSE_GUARD,
        closed_grace: timedelta = _DEFAULT_CLOSED_GRACE,
        idle_timeout: timedelta = _DEFAULT_IDLE_TIMEOUT,
        shard_count: int = _DEFAULT_SHARD_COUNT,
    ) -> None:
        """Create a manager backed by the engine-owned common registry.

        A private registry exists only for isolated compatibility callers that
        opt in with ``allow_private_registry=True``.
        """

        if close_guard < timedelta(0):
            raise ValueError("Explicit-proxy close_guard must be non-negative")
        if idle_timeout <= timedelta(0):
            raise ValueError("Explicit-proxy idle_timeout must be positive")
        if shard_count <= 0:
            raise ValueError("Explicit-proxy shard_count must be positive")
        self._window_start = ensure_utc(window_start)
        self._window_end = ensure_utc(window_end)
        if self._window_end < self._window_start:
            raise ValueError("Explicit-proxy window_end cannot precede window_start")
        self._close_guard = close_guard
        self._idle_timeout = idle_timeout
        if registry is None:
            if not allow_private_registry:
                raise ValueError(
                    "Explicit-proxy manager requires the shared ApplicationChannelRegistry; "
                    "isolated compatibility callers must set allow_private_registry=True"
                )
            registry = ApplicationChannelRegistry(
                window_start=self._window_start,
                window_end=self._window_end,
                closed_grace=closed_grace,
                max_reusable_per_affinity=1,
                shard_count=shard_count,
            )
            self._owns_registry = True
        else:
            if allow_private_registry:
                raise ValueError(
                    "allow_private_registry cannot be combined with an injected registry"
                )
            if (
                registry.window_start != self._window_start
                or registry.window_end != self._window_end
            ):
                raise ValueError(
                    "Explicit-proxy manager window must exactly match the shared "
                    "application registry"
                )
            if registry.shard_count != shard_count:
                raise ValueError(
                    "Explicit-proxy shard_count must match the shared application registry"
                )
            self._owns_registry = False
        self._shard_count = registry.shard_count
        self._registry = registry
        self._shards: dict[int, _ProxySidecarShard] = {}
        self._directory_lock = RLock()
        self._gate = _SidecarMutationGate()
        self._watermark = self._window_start
        self._prepared_lock = RLock()
        self._prepared_admissions: dict[int, ExplicitProxyAdmissionToken] = {}
        self._prepared_capabilities: dict[int, _ExplicitProxyAdmissionCapability] = {}
        self._claimed_admissions: set[int] = set()
        self._prepared_channel_ids: dict[str, int] = {}
        self._prepared_affinity_keys: dict[tuple[str, str], int] = {}
        self._prepared_origin_transport_ids: dict[str, int] = {}
        self._next_admission_id = 1
        self._admission_secret = secrets.token_bytes(32)
        self._manager_id = (
            "explicit-proxy-manager-"
            + hmac.new(
                self._admission_secret,
                b"explicit-proxy-manager-instance-v1",
                hashlib.sha256,
            ).hexdigest()[:32]
        )
        self._estimated_prepared_bytes = 0

    @property
    def application_registry(self) -> ApplicationChannelRegistry:
        """Return the injected common registry for identity/invariant checks."""

        return self._registry

    @property
    def manager_id(self) -> str:
        """Return the stable opaque identity of this manager instance."""

        return self._manager_id

    @property
    def manager_instance_id(self) -> str:
        """Return the stable manager identity for explicit composite proofs."""

        return self._manager_id

    def authenticates_admission_token(self, token: ExplicitProxyAdmissionToken) -> bool:
        """Return whether this manager and common registry own one intact token."""

        if not isinstance(token, ExplicitProxyAdmissionToken):
            return False
        with self._prepared_lock:
            try:
                self._active_admission_locked(token)
            except StateError:
                return False
        return self._registry.authenticates_admission_token(token.application_token)

    def authenticates_request_snapshot(self, snapshot: ExplicitProxyRequestSnapshot) -> bool:
        """Return whether this manager issued one intact current-tunnel snapshot."""

        if (
            not isinstance(snapshot, ExplicitProxyRequestSnapshot)
            or snapshot._manager_token != id(self)
            or not hmac.compare_digest(snapshot.manager_id, self._manager_id)
        ):
            return False
        expected = _proxy_request_snapshot_integrity_token(
            self._admission_secret,
            snapshot,
        )
        return hmac.compare_digest(snapshot._integrity_token, expected)

    def snapshot_request(
        self,
        affinity: ExplicitProxyChannelAffinity,
        *,
        requested_at: datetime,
    ) -> ExplicitProxyRequestSnapshot | None:
        """Return a signed nonmutating view of the exact reusable tunnel."""

        canonical_request = ensure_utc(requested_at)
        affinity_digest = affinity.digest
        with self._locked_sidecar_prepared(affinity.owner_id, create=False) as shard:
            if shard is None:
                return None
            tunnel = shard.tunnels.find_affinity(affinity_digest)
            if tunnel is None:
                return None
            self._reject_proxy_reservation_conflict_locked(
                channel_ids=(tunnel.channel_id,),
                affinity_key=(affinity.owner_id, affinity_digest),
                origin_transport_ids=(tunnel.origin_transport_id,),
            )
            application_snapshot = self._registry.find_reusable(
                affinity_digest=affinity_digest,
                owner_id=affinity.owner_id,
                at=canonical_request,
            )
            if application_snapshot is None:
                return None
            if application_snapshot.channel_id != tunnel.channel_id:
                raise StateError("Explicit-proxy affinity resolved to the wrong channel")
            generation_token = self._registry.channel_close_token(tunnel.channel_id)
            if generation_token is None:
                raise StateError("Explicit-proxy reusable tunnel has no exact generation token")
            snapshot = ExplicitProxyRequestSnapshot(
                manager_id=self._manager_id,
                affinity_digest=affinity_digest,
                requested_at=canonical_request,
                tunnel=tunnel,
                application_snapshot=application_snapshot,
                generation_token=generation_token,
                _manager_token=id(self),
            )
            return replace(
                snapshot,
                _integrity_token=_proxy_request_snapshot_integrity_token(
                    self._admission_secret,
                    snapshot,
                ),
            )

    def authenticates_admission_receipt(
        self,
        receipt: ExplicitProxyAdmissionReceipt,
    ) -> bool:
        """Return whether this manager issued an exact coupled-publication receipt."""

        if not isinstance(receipt, ExplicitProxyAdmissionReceipt):
            return False
        if not isinstance(
            receipt.sidecar_result,
            (
                ExplicitProxyTunnelOpen,
                ExplicitProxyRequestReuse,
                ExplicitProxyTerminalRequest,
            ),
        ) or not isinstance(receipt.application_receipt, ApplicationChannelAdmissionReceipt):
            return False
        if (
            receipt.manager_kind != _PROXY_MANAGER_KIND
            or not hmac.compare_digest(
                receipt.manager_id,
                self._manager_id,
            )
            or receipt._manager_token != id(self)
        ):
            return False
        if not self._registry.authenticates_admission_receipt(receipt.application_receipt):
            return False
        expected = _proxy_admission_receipt_integrity_token(
            self._admission_secret,
            receipt,
        )
        if not hmac.compare_digest(receipt._integrity_token, expected):
            return False
        result = receipt.sidecar_result
        expected_current, expected_prerequisites = _proxy_admission_transport_legs(result)
        application_receipt = receipt.application_receipt
        application_transport_id = application_receipt.snapshot.identity.binding.transport_id
        return (
            receipt.application_receipt_token == application_receipt.receipt_token
            and receipt.channel_id == application_receipt.channel_id
            and receipt.channel_id == result.tunnel.channel_id
            and receipt.operation_id == application_receipt.operation_id
            and receipt.operation_id == _proxy_admission_operation_id(result)
            and receipt.current_transport_id == expected_current
            and receipt.prerequisite_transport_ids == expected_prerequisites
            and (
                (
                    isinstance(result, ExplicitProxyTunnelOpen)
                    and expected_prerequisites == (application_transport_id,)
                )
                or (
                    isinstance(
                        result,
                        (ExplicitProxyRequestReuse, ExplicitProxyTerminalRequest),
                    )
                    and expected_current == application_transport_id
                    and not expected_prerequisites
                )
            )
            and (
                (
                    isinstance(result, ExplicitProxyTerminalRequest)
                    and application_receipt.snapshot.closed_at == result.close_at
                    and application_receipt.snapshot.close_reason == result.close_reason
                )
                or (
                    isinstance(result, ExplicitProxyTunnelOpen)
                    and not result.tunnel.planned_request_count
                    and application_receipt.kind == "open_completed_close"
                    and application_receipt.snapshot.closed_at
                    == application_receipt.snapshot.last_activity_at
                    and application_receipt.snapshot.close_reason == "setup-only"
                )
                or (
                    not isinstance(
                        result,
                        (ExplicitProxyTerminalRequest, ExplicitProxyTunnelOpen),
                    )
                    and application_receipt.snapshot.is_open
                )
                or (
                    isinstance(result, ExplicitProxyTunnelOpen)
                    and bool(result.tunnel.planned_request_count)
                    and application_receipt.kind == "open_completed"
                    and application_receipt.snapshot.is_open
                )
            )
            and receipt.origin_affinity_digest == result.tunnel.affinity_digest
            and receipt.sidecar_result_digest == explicit_proxy_sidecar_result_digest(result)
        )

    def _sidecar_shard(
        self,
        owner_id: str,
        *,
        create: bool,
    ) -> _ProxySidecarShard | None:
        shard_id = self._registry.owner_partition_id(owner_id)
        shard = self._shards.get(shard_id)
        if shard is not None or not create:
            return shard
        with self._directory_lock:
            shard = self._shards.get(shard_id)
            if shard is None:
                shard = _ProxySidecarShard(shard_id=shard_id)
                self._shards[shard_id] = shard
            return shard

    @contextmanager
    def _locked_sidecar(
        self,
        owner_id: str,
        *,
        create: bool,
    ) -> Iterator[_ProxySidecarShard | None]:
        """Yield one owner shard while preserving watermark exclusion."""

        with self._gate.mutation():
            shard = self._sidecar_shard(owner_id, create=create)
            if shard is None:
                yield None
                return
            with shard.lock:
                yield shard

    @contextmanager
    def _locked_sidecar_prepared(
        self,
        owner_id: str,
        *,
        create: bool,
    ) -> Iterator[_ProxySidecarShard | None]:
        """Lock one owner before the short global reservation metadata lane."""

        with self._gate.mutation():
            shard = self._sidecar_shard(owner_id, create=create)
            if shard is None:
                with self._prepared_lock:
                    yield None
                return
            with shard.lock, self._prepared_lock:
                yield shard

    @staticmethod
    def _channel_id(
        affinity_digest: str,
        *,
        client_transport_id: str,
        origin_transport_id: str,
        client_zeek_uid: str,
        origin_zeek_uid: str,
        client_source_port: int,
        origin_source_port: int,
        opened_at: datetime,
    ) -> str:
        digest = _semantic_digest(
            "explicit-proxy-channel-v1",
            (
                affinity_digest,
                client_transport_id,
                origin_transport_id,
                client_zeek_uid,
                origin_zeek_uid,
                client_source_port,
                origin_source_port,
                ensure_utc(opened_at).isoformat(),
            ),
        )
        return f"explicit-proxy-channel-{digest[:32]}"

    @staticmethod
    def _operation_id(channel_id: str, ordinal: int) -> str:
        if ordinal == 0 and channel_id.startswith(_PROXY_CHANNEL_PREFIX):
            channel_digest = channel_id.removeprefix(_PROXY_CHANNEL_PREFIX)
            if len(channel_digest) == _PROXY_CHANNEL_DIGEST_BYTES * 2:
                return f"explicit-proxy-operation-{channel_digest}"
        digest = _semantic_digest("explicit-proxy-operation-v1", (channel_id, ordinal))
        return f"explicit-proxy-operation-{digest[:32]}"

    def _active_admission_locked(
        self,
        token: ExplicitProxyAdmissionToken,
    ) -> _ExplicitProxyAdmissionCapability:
        """Return one exact active proxy token while the prepared lock is held."""

        capability = self._prepared_capabilities.get(id(token))
        if capability is None:
            if token._manager_token != id(self):
                raise StateError("explicit-proxy admission token belongs to another manager")
            raise StateError("explicit-proxy admission token is stale or already consumed")
        if capability.manager_token != id(self):
            raise StateError("explicit-proxy admission token belongs to another manager")
        active = self._prepared_admissions.get(capability.admission_id)
        if active is not token:
            raise StateError("explicit-proxy admission token is stale or already consumed")
        self._verify_admission_integrity(token)
        if not hmac.compare_digest(
            token._application_publication_token,
            capability.application_publication_token,
        ) or not hmac.compare_digest(token._token_seal, capability.token_seal):
            raise StateError("explicit-proxy admission token integrity validation failed")
        return capability

    def _verify_admission_integrity(self, token: ExplicitProxyAdmissionToken) -> None:
        """Reject retargeted proxy or nested common admission capabilities."""

        if not token._application_publication_token or not token._token_seal:
            raise StateError("explicit-proxy admission token is missing its integrity seal")
        if not hmac.compare_digest(
            token.application_token.publication_token,
            token._application_publication_token,
        ):
            raise StateError("explicit-proxy common admission token was modified")
        if not hmac.compare_digest(
            _proxy_admission_seal(self._admission_secret, token),
            token._token_seal,
        ):
            raise StateError("explicit-proxy admission token was modified")

    def _reject_proxy_reservation_conflict_locked(
        self,
        *,
        channel_ids: tuple[str, ...] = (),
        affinity_key: tuple[str, str] = ("", ""),
        origin_transport_ids: tuple[str, ...] = (),
    ) -> None:
        """Reject proxy identities already reserved by another prepared mutation."""

        for label, values, retained in (
            ("channel", channel_ids, self._prepared_channel_ids),
            ("origin transport", origin_transport_ids, self._prepared_origin_transport_ids),
        ):
            for value in values:
                if value and value in retained:
                    raise StateError(f"Explicit-proxy {label} {value!r} has a prepared admission")
        if affinity_key != ("", "") and affinity_key in self._prepared_affinity_keys:
            raise StateError(
                f"Explicit-proxy affinity {affinity_key[1]!r} has a prepared admission"
            )

    def _register_admission_locked(self, token: ExplicitProxyAdmissionToken) -> None:
        """Publish bounded proxy reservation metadata without canonical sidecar state."""

        self._reject_proxy_reservation_conflict_locked(
            channel_ids=token._reserved_channel_ids,
            affinity_key=token._reserved_affinity_key,
            origin_transport_ids=token._reserved_origin_transport_ids,
        )
        admission_id = token._admission_id
        estimated_bytes = _prepared_proxy_admission_estimated_bytes(token)
        capability = _ExplicitProxyAdmissionCapability(
            token_id=id(token),
            admission_id=admission_id,
            manager_token=id(self),
            owner_id=token._owner_id,
            reserved_channel_ids=token._reserved_channel_ids,
            reserved_affinity_key=token._reserved_affinity_key,
            reserved_origin_transport_ids=token._reserved_origin_transport_ids,
            application_publication_token=token._application_publication_token,
            token_seal=token._token_seal,
            linearization_time=token.linearization_time,
            estimated_bytes=estimated_bytes,
        )
        self._prepared_admissions[admission_id] = token
        self._prepared_capabilities[capability.token_id] = capability
        for channel_id in token._reserved_channel_ids:
            self._prepared_channel_ids[channel_id] = admission_id
        if token._reserved_affinity_key != ("", ""):
            self._prepared_affinity_keys[token._reserved_affinity_key] = admission_id
        for transport_id in token._reserved_origin_transport_ids:
            self._prepared_origin_transport_ids[transport_id] = admission_id
        self._estimated_prepared_bytes += estimated_bytes

    def _release_admission_locked(
        self,
        capability: _ExplicitProxyAdmissionCapability,
    ) -> None:
        """Release every proxy reservation marker for one exact token."""

        active = self._prepared_admissions.pop(capability.admission_id, None)
        retained = self._prepared_capabilities.pop(capability.token_id, None)
        if active is None or retained is not capability:
            return
        self._claimed_admissions.discard(capability.admission_id)
        for channel_id in capability.reserved_channel_ids:
            if self._prepared_channel_ids.get(channel_id) == capability.admission_id:
                self._prepared_channel_ids.pop(channel_id)
        if (
            capability.reserved_affinity_key != ("", "")
            and self._prepared_affinity_keys.get(capability.reserved_affinity_key)
            == capability.admission_id
        ):
            self._prepared_affinity_keys.pop(capability.reserved_affinity_key)
        for transport_id in capability.reserved_origin_transport_ids:
            if self._prepared_origin_transport_ids.get(transport_id) == capability.admission_id:
                self._prepared_origin_transport_ids.pop(transport_id)
        self._estimated_prepared_bytes -= capability.estimated_bytes

    def _new_admission_token(
        self,
        *,
        kind: Literal["open", "request"],
        application_token: ApplicationChannelAdmissionToken,
        result: ProxyAdmissionResult,
        owner_id: str,
        expected_tunnel: ExplicitProxyTunnelIdentity | None,
        replacement_channel_id: str = "",
        reserved_channel_ids: tuple[str, ...],
        reserved_affinity_key: tuple[str, str],
        reserved_origin_transport_ids: tuple[str, ...],
    ) -> ExplicitProxyAdmissionToken:
        """Create and register one sealed manager-local admission token."""

        if not self._registry.authenticates_admission_token(application_token):
            raise StateError("explicit-proxy common admission token is not authentic")
        admission_id = self._next_admission_id
        self._next_admission_id += 1
        token = ExplicitProxyAdmissionToken(
            kind=kind,
            application_token=application_token,
            result=result,
            _manager_token=id(self),
            _admission_id=admission_id,
            _owner_id=owner_id,
            _expected_tunnel=expected_tunnel,
            _replacement_channel_id=replacement_channel_id,
            _reserved_channel_ids=tuple(dict.fromkeys(reserved_channel_ids)),
            _reserved_affinity_key=reserved_affinity_key,
            _reserved_origin_transport_ids=tuple(dict.fromkeys(reserved_origin_transport_ids)),
            _application_publication_token=application_token.publication_token,
        )
        object.__setattr__(
            token,
            "_token_seal",
            _proxy_admission_seal(self._admission_secret, token),
        )
        self._register_admission_locked(token)
        return token

    def has_future_reuse_headroom(
        self,
        *,
        opened_at: datetime,
        closes_at: datetime,
        setup_completed_at: datetime,
    ) -> bool:
        """Return whether setup leaves strict manager-owned future-reuse headroom.

        This preflight is pure: it allocates no identities, takes no mutation
        locks, and publishes no prepared or canonical state.
        """

        canonical_open = ensure_utc(opened_at)
        canonical_close = ensure_utc(closes_at)
        setup_complete = ensure_utc(setup_completed_at)
        if canonical_close <= canonical_open:
            raise StateError("Explicit-proxy tunnel close must follow its open")
        if canonical_open < self._window_start or canonical_open >= self._window_end:
            raise StateError("Explicit-proxy tunnel open is outside the manager window")
        if canonical_close > self._window_end:
            raise StateError("Explicit-proxy tunnel close is outside the manager window")
        if not canonical_open <= setup_complete <= canonical_close:
            raise StateError("Explicit-proxy setup must be contained by its client transport")
        return setup_complete < canonical_close - self._close_guard

    def prepare_open_tunnel(
        self,
        affinity: ExplicitProxyChannelAffinity,
        *,
        client_transport_id: str,
        origin_transport_id: str,
        client_zeek_uid: str,
        origin_zeek_uid: str,
        tunnel_group_id: str,
        client_source_port: int,
        origin_source_port: int,
        opened_at: datetime,
        closes_at: datetime,
        setup_started_at: datetime,
        setup_completed_at: datetime,
        setup_request_wire_bytes: int,
        setup_response_wire_bytes: int,
        planned_request_count: int,
        aggregate_request_wire_bytes: int,
        aggregate_response_wire_bytes: int,
        setup_outcome: ProxyChannelOutcome = "success",
    ) -> ExplicitProxyAdmissionToken | None:
        """Prepare one CONNECT setup without publishing common or proxy state.

        Aggregate request bytes already include request bodies. The manager never
        adds upload sizes again when reserving a child, preventing the historical
        upload double count.
        """

        if setup_outcome not in {
            "success",
            "denied",
            "authentication_required",
            "gateway_failure",
        }:
            raise ValueError(f"Unknown explicit-proxy setup outcome {setup_outcome!r}")
        normalized_client_transport = _required_text(client_transport_id, "client_transport_id")
        normalized_origin_transport = _required_text(origin_transport_id, "origin_transport_id")
        normalized_client_uid = _required_text(client_zeek_uid, "client_zeek_uid")
        normalized_origin_uid = _required_text(origin_zeek_uid, "origin_zeek_uid")
        normalized_group = _required_text(tunnel_group_id, "tunnel_group_id")
        _port(client_source_port, "client_source_port")
        _port(origin_source_port, "origin_source_port")
        if planned_request_count < 0:
            raise ValueError("planned_request_count must be non-negative")
        if (
            min(
                setup_request_wire_bytes,
                setup_response_wire_bytes,
                aggregate_request_wire_bytes,
                aggregate_response_wire_bytes,
            )
            < 0
        ):
            raise ValueError("Explicit-proxy setup and aggregate bytes must be non-negative")
        if planned_request_count == 0 and (
            aggregate_request_wire_bytes or aggregate_response_wire_bytes
        ):
            raise ValueError("Setup-only proxy tunnels cannot reserve child byte budgets")
        canonical_open = ensure_utc(opened_at)
        canonical_close = ensure_utc(closes_at)
        setup_start = ensure_utc(setup_started_at)
        setup_complete = ensure_utc(setup_completed_at)
        if canonical_close <= canonical_open:
            raise StateError("Explicit-proxy tunnel close must follow its open")
        if canonical_open < self._window_start or canonical_open >= self._window_end:
            raise StateError("Explicit-proxy tunnel open is outside the manager window")
        if canonical_close > self._window_end:
            raise StateError("Explicit-proxy tunnel close is outside the manager window")
        if not canonical_open <= setup_start <= setup_complete <= canonical_close:
            raise StateError("Explicit-proxy setup must be contained by its client transport")
        if setup_outcome != "success":
            return None

        if planned_request_count and not self.has_future_reuse_headroom(
            opened_at=canonical_open,
            closes_at=canonical_close,
            setup_completed_at=setup_complete,
        ):
            return None
        reuse_deadline = canonical_close - self._close_guard

        affinity_digest = affinity.digest
        channel_id = self._channel_id(
            affinity_digest,
            client_transport_id=normalized_client_transport,
            origin_transport_id=normalized_origin_transport,
            client_zeek_uid=normalized_client_uid,
            origin_zeek_uid=normalized_origin_uid,
            client_source_port=client_source_port,
            origin_source_port=origin_source_port,
            opened_at=canonical_open,
        )
        tunnel = object.__new__(ExplicitProxyTunnelIdentity)
        for field_name, field_value in (
            ("channel_id", channel_id),
            ("affinity_digest", affinity_digest),
            ("client_transport_id", normalized_client_transport),
            ("origin_transport_id", normalized_origin_transport),
            ("client_zeek_uid", normalized_client_uid),
            ("origin_zeek_uid", normalized_origin_uid),
            ("tunnel_group_id", normalized_group),
            ("client_source_port", client_source_port),
            ("proxy_listener_port", affinity.proxy_port),
            ("origin_source_port", origin_source_port),
            ("origin_destination_port", affinity.origin_port),
            ("opened_at", canonical_open),
            ("closes_at", canonical_close),
            ("reuse_deadline", max(canonical_open, reuse_deadline)),
            ("planned_request_count", planned_request_count),
            ("aggregate_request_wire_bytes", aggregate_request_wire_bytes),
            ("aggregate_response_wire_bytes", aggregate_response_wire_bytes),
        ):
            object.__setattr__(tunnel, field_name, field_value)
        setup_operation_id = self._operation_id(channel_id, 0)
        with self._locked_sidecar_prepared(affinity.owner_id, create=False) as shard:
            if canonical_open < self._watermark:
                raise StateError("Explicit-proxy tunnel cannot open before the watermark")
            affinity_key = (affinity.owner_id, affinity_digest)
            self._reject_proxy_reservation_conflict_locked(
                channel_ids=(channel_id,),
                affinity_key=affinity_key,
                origin_transport_ids=(normalized_origin_transport,),
            )
            same_affinity: ExplicitProxyTunnelIdentity | None = None
            origin_collision: ExplicitProxyTunnelIdentity | None = None
            if shard is not None:
                same_affinity = shard.tunnels.find_affinity(affinity_digest)
                origin_collision = shard.tunnels.find_origin_transport(normalized_origin_transport)
            if origin_collision is not None:
                raise StateError(
                    "Explicit-proxy origin transport already belongs to channel "
                    f"{origin_collision.channel_id!r}"
                )
            if (
                same_affinity is not None
                and same_affinity.client_transport_id == normalized_client_transport
            ):
                raise StateError(
                    "Explicit-proxy client transport already belongs to another "
                    "application channel; transport already owns open channel or "
                    "retained channel"
                )

            replacement_channel_id = ""
            replacement_closed_at: datetime | None = None
            if same_affinity is not None:
                prior_snapshot = self._registry.get(same_affinity.channel_id)
                if prior_snapshot is None or not prior_snapshot.is_open:
                    raise StateError(
                        f"Explicit-proxy tunnel view {same_affinity.channel_id!r} is not open"
                    )
                effective_deadline = min(
                    prior_snapshot.idle_deadline,
                    prior_snapshot.identity.hard_deadline,
                    prior_snapshot.identity.binding.closes_at,
                )
                replacement_channel_id = same_affinity.channel_id
                replacement_closed_at = min(
                    effective_deadline,
                    max(
                        canonical_open,
                        prior_snapshot.identity.opened_at,
                        prior_snapshot.last_activity_at,
                    ),
                )

            identity = _validated_application_identity(
                channel_id=channel_id,
                owner_id=affinity.owner_id,
                affinity_digest=affinity_digest,
                transport_id=normalized_client_transport,
                opened_at=canonical_open,
                closes_at=canonical_close,
                idle_timeout=self._idle_timeout,
                initiator_bytes=(setup_request_wire_bytes + aggregate_request_wire_bytes),
                responder_bytes=(setup_response_wire_bytes + aggregate_response_wire_bytes),
                operations=planned_request_count + 1,
            )
            reservation = _validated_completed_operation(
                operation_id=setup_operation_id,
                channel_id=channel_id,
                ordinal=0,
                started_at=setup_start,
                ended_at=setup_complete,
                initiator_bytes=setup_request_wire_bytes,
                responder_bytes=setup_response_wire_bytes,
            )
            try:
                prepare_open = (
                    self._registry.prepare_open_channel_with_completed_operation
                    if planned_request_count
                    else self._registry.prepare_open_channel_with_completed_operation_and_close
                )
                close_options = (
                    {}
                    if planned_request_count
                    else {"closed_at": setup_complete, "reason": "setup-only"}
                )
                application_token = prepare_open(
                    identity,
                    reservation,
                    **close_options,
                    replacement_channel_id=replacement_channel_id,
                    replacement_closed_at=replacement_closed_at,
                    replacement_reason=("replaced" if replacement_channel_id else ""),
                )
            except StateError as exc:
                if "already owns open channel or retained channel" in str(exc):
                    raise StateError(
                        "Explicit-proxy client transport already belongs to another "
                        "application channel; transport already owns open channel or "
                        "retained channel"
                    ) from exc
                raise

            result = ExplicitProxyTunnelOpen(
                tunnel=tunnel,
                setup_operation_id=setup_operation_id,
                remaining_request_count=planned_request_count,
                remaining_request_wire_bytes=aggregate_request_wire_bytes,
                remaining_response_wire_bytes=aggregate_response_wire_bytes,
            )
            try:
                return self._new_admission_token(
                    kind="open",
                    application_token=application_token,
                    result=result,
                    owner_id=affinity.owner_id,
                    expected_tunnel=same_affinity,
                    replacement_channel_id=replacement_channel_id,
                    reserved_channel_ids=tuple(
                        candidate for candidate in (channel_id, replacement_channel_id) if candidate
                    ),
                    reserved_affinity_key=affinity_key,
                    reserved_origin_transport_ids=(normalized_origin_transport,),
                )
            except (StateError, ValueError):
                self._registry.cancel_prepared_admission(application_token)
                raise

    def _validate_sidecar_admission_locked(
        self,
        token: ExplicitProxyAdmissionToken,
    ) -> None:
        """Verify that proxy sidecar state still matches one reserved token."""

        shard = self._sidecar_shard(token._owner_id, create=False)
        expected = token._expected_tunnel
        if token.kind == "request":
            if shard is None or expected is None:
                raise StateError("prepared explicit-proxy request tunnel disappeared")
            retained = shard.tunnels.peek(expected.channel_id)
            if retained != expected:
                raise StateError("prepared explicit-proxy request tunnel changed")
            if isinstance(token.result, ExplicitProxyTerminalRequest):
                if (
                    token.application_token.kind != "completed_operation_close"
                    or token.application_token.channel_closed_at != token.result.close_at
                    or token.application_token.channel_close_reason != token.result.close_reason
                ):
                    raise StateError("prepared explicit-proxy terminal close preimage changed")
            elif token.application_token.kind != "completed_operation":
                raise StateError("non-terminal proxy request carries a terminal close")
            return

        result = token.result
        assert isinstance(result, ExplicitProxyTunnelOpen)
        expected_common_kind = (
            "open_completed" if result.tunnel.planned_request_count else "open_completed_close"
        )
        if token.application_token.kind != expected_common_kind:
            raise StateError("prepared explicit-proxy open changed its common close disposition")
        if not result.tunnel.planned_request_count and (
            token.application_token.channel_closed_at
            != token.application_token.reservation.ended_at
            or token.application_token.channel_close_reason != "setup-only"
        ):
            raise StateError("prepared explicit-proxy setup-only close preimage changed")
        retained_channel = None if shard is None else shard.tunnels.peek(result.tunnel.channel_id)
        if retained_channel is not None:
            raise StateError("prepared explicit-proxy channel identity became occupied")
        retained_origin = (
            None
            if shard is None
            else shard.tunnels.peek_origin_transport(result.tunnel.origin_transport_id)
        )
        if retained_origin is not None:
            raise StateError("prepared explicit-proxy origin transport became occupied")
        retained_affinity = (
            None if shard is None else shard.tunnels.peek_affinity(result.tunnel.affinity_digest)
        )
        if expected is None:
            if retained_affinity is not None:
                raise StateError("prepared explicit-proxy affinity became occupied")
            return
        if retained_affinity != expected:
            raise StateError("prepared replacement explicit-proxy tunnel changed")
        if token._replacement_channel_id != expected.channel_id:
            raise StateError("prepared replacement explicit-proxy identity was retargeted")

    def cancel_prepared_admission(self, token: ExplicitProxyAdmissionToken) -> bool:
        """Cancel one unclaimed proxy/common admission without publishing state."""

        with self._gate.mutation(), self._prepared_lock:
            capability = self._prepared_capabilities.get(id(token))
            if capability is None:
                if token._manager_token != id(self):
                    raise StateError("explicit-proxy admission token belongs to another manager")
                return False
            try:
                capability = self._active_admission_locked(token)
            except StateError:
                self._release_admission_locked(capability)
                self._registry.cancel_prepared_admission(token.application_token)
                raise
            if capability.admission_id in self._claimed_admissions:
                return False
            try:
                return self._registry.cancel_prepared_admission(token.application_token)
            finally:
                self._release_admission_locked(capability)

    def _claim_prepared_admission(self, token: ExplicitProxyAdmissionToken) -> None:
        """Revalidate and claim one proxy token in a short manager-only section."""

        with self._locked_sidecar_prepared(token._owner_id, create=False):
            capability = self._active_admission_locked(token)
            if not self._registry.authenticates_admission_token(token.application_token):
                self._release_admission_locked(capability)
                raise StateError("explicit-proxy common admission token is not authentic")
            if capability.admission_id in self._claimed_admissions:
                raise StateError("explicit-proxy admission token is already claimed")
            if capability.linearization_time < self._watermark:
                self._release_admission_locked(capability)
                raise StateError("explicit-proxy admission starts behind the canonical watermark")
            self._validate_sidecar_admission_locked(token)
            self._active_admission_locked(token)
            self._claimed_admissions.add(capability.admission_id)

    def _cancel_claimed_admission(self, token: ExplicitProxyAdmissionToken) -> None:
        """Release a proxy claim after its external transaction aborts."""

        with self._locked_sidecar_prepared(token._owner_id, create=False):
            capability = self._prepared_capabilities.get(id(token))
            if capability is None:
                return
            try:
                capability = self._active_admission_locked(token)
            except StateError:
                self._release_admission_locked(capability)
                return
            if capability.admission_id not in self._claimed_admissions:
                raise StateError("explicit-proxy admission token is not claimed")
            self._release_admission_locked(capability)

    @contextmanager
    def prepared_admission(
        self,
        token: ExplicitProxyAdmissionToken,
    ) -> Iterator[ExplicitProxyPreparedCommit]:
        """Claim common and proxy reservations while retaining no manager locks."""

        with self._gate.mutation(), self._prepared_lock:
            capability = self._prepared_capabilities.get(id(token))
            if capability is None:
                if token._manager_token != id(self):
                    raise StateError("explicit-proxy admission token belongs to another manager")
                raise StateError("explicit-proxy admission token is stale or already consumed")
            try:
                capability = self._active_admission_locked(token)
            except StateError:
                self._release_admission_locked(capability)
                self._registry.cancel_prepared_admission(token.application_token)
                raise
            if not self._registry.authenticates_admission_token(token.application_token):
                self._release_admission_locked(capability)
                self._registry.cancel_prepared_admission(token.application_token)
                raise StateError("explicit-proxy common admission token is not authentic")
        try:
            with self._registry.prepared_admission(token.application_token) as application_commit:
                self._claim_prepared_admission(token)
                transaction = ExplicitProxyPreparedCommit(self, token, application_commit)
                try:
                    yield transaction
                finally:
                    if not transaction.committed:
                        self._cancel_claimed_admission(token)
                    transaction._close()
        except StateError:
            with self._gate.mutation(), self._prepared_lock:
                capability = self._prepared_capabilities.get(id(token))
                if capability is not None:
                    self._release_admission_locked(capability)
            raise

    def _commit_proxy_sidecar_locked(
        self,
        token: ExplicitProxyAdmissionToken,
        application_result: ApplicationChannelAdmissionResult,
    ) -> None:
        """Apply only prevalidated packed sidecar primitives."""

        result = token.result
        shard = self._sidecar_shard(token._owner_id, create=True)
        assert shard is not None
        with shard.lock:
            if token.kind == "open":
                assert isinstance(result, ExplicitProxyTunnelOpen)
                if token._replacement_channel_id:
                    try:
                        replacement_handle = shard.tunnels.handle_for(token._replacement_channel_id)
                    except KeyError:
                        replacement_handle = None
                    shard.tunnels.delete(token._replacement_channel_id)
                    if replacement_handle is not None:
                        shard.expiry.pop(replacement_handle, None)
                if result.tunnel.planned_request_count:
                    tunnel_handle = shard.tunnels.insert(result.tunnel)
                    self._set_tunnel_expiry(
                        shard,
                        result.tunnel,
                        application_result.snapshot,
                        tunnel_handle=tunnel_handle,
                    )
                return

            if isinstance(result, ExplicitProxyTerminalRequest):
                try:
                    tunnel_handle = shard.tunnels.handle_for(result.tunnel.channel_id)
                except KeyError:
                    tunnel_handle = None
                shard.tunnels.delete(result.tunnel.channel_id)
                if tunnel_handle is not None:
                    shard.expiry.pop(tunnel_handle, None)
                return

            assert isinstance(result, ExplicitProxyRequestReuse)
            self._set_tunnel_expiry(shard, result.tunnel, application_result.snapshot)

    def _commit_claimed_admission(
        self,
        token: ExplicitProxyAdmissionToken,
        application_commit: ApplicationChannelPreparedCommit,
    ) -> ExplicitProxyAdmissionCommitResult:
        """Commit one fully claimed common/proxy admission with no external locks."""

        with self._locked_sidecar_prepared(token._owner_id, create=False):
            capability = self._active_admission_locked(token)
            if not self._registry.authenticates_admission_token(token.application_token):
                raise StateError("explicit-proxy common admission token is not authentic")
            if capability.admission_id not in self._claimed_admissions:
                raise StateError("explicit-proxy admission token is not claimed")
            self._validate_sidecar_admission_locked(token)
            self._active_admission_locked(token)

        application_result = application_commit.commit_no_fail()
        application_receipt = application_result.receipt
        if application_receipt is None or not self._registry.authenticates_admission_receipt(
            application_receipt
        ):
            raise StateError("prepared explicit-proxy common receipt is not authentic")
        result = token.result
        if token.kind == "open":
            assert isinstance(result, ExplicitProxyTunnelOpen)
            if application_result.snapshot.channel_id != result.tunnel.channel_id:
                raise StateError("prepared explicit-proxy common result changed identity")
            if not result.tunnel.planned_request_count:
                if (
                    token.application_token.kind != "open_completed_close"
                    or application_result.snapshot.closed_at
                    != token.application_token.reservation.ended_at
                    or application_result.snapshot.close_reason != "setup-only"
                    or application_result.close_token is not None
                ):
                    raise StateError("prepared explicit-proxy setup-only close changed result")
            elif token.application_token.kind != "open_completed":
                raise StateError("prepared explicit-proxy reusable open carries a terminal close")
        else:
            assert isinstance(result, (ExplicitProxyRequestReuse, ExplicitProxyTerminalRequest))
            if application_result.snapshot.channel_id != result.tunnel.channel_id:
                raise StateError("prepared explicit-proxy request changed channel identity")
            if isinstance(result, ExplicitProxyTerminalRequest):
                if (
                    application_result.snapshot.closed_at != result.close_at
                    or application_result.snapshot.close_reason != result.close_reason
                ):
                    raise StateError("prepared explicit-proxy terminal close changed result")

        with self._locked_sidecar_prepared(token._owner_id, create=True):
            capability = self._active_admission_locked(token)
            if capability.admission_id not in self._claimed_admissions:
                raise StateError("explicit-proxy admission token is not claimed")
            self._commit_proxy_sidecar_locked(token, application_result)
            self._release_admission_locked(capability)
        current_transport_id, prerequisite_transport_ids = _proxy_admission_transport_legs(result)
        receipt = ExplicitProxyAdmissionReceipt(
            manager_kind=_PROXY_MANAGER_KIND,
            manager_id=self._manager_id,
            kind=token.kind,
            publication_token=token.publication_token,
            application_receipt=application_receipt,
            application_receipt_token=application_receipt.receipt_token,
            channel_id=application_receipt.channel_id,
            operation_id=application_receipt.operation_id,
            current_transport_id=current_transport_id,
            prerequisite_transport_ids=prerequisite_transport_ids,
            origin_affinity_digest=result.tunnel.affinity_digest,
            sidecar_result=result,
            sidecar_result_digest=explicit_proxy_sidecar_result_digest(result),
            _manager_token=id(self),
        )
        receipt = replace(
            receipt,
            _integrity_token=_proxy_admission_receipt_integrity_token(
                self._admission_secret,
                receipt,
            ),
        )
        return ExplicitProxyAdmissionCommitResult(result=result, receipt=receipt)

    def open_tunnel(
        self,
        affinity: ExplicitProxyChannelAffinity,
        *,
        client_transport_id: str,
        origin_transport_id: str,
        client_zeek_uid: str,
        origin_zeek_uid: str,
        tunnel_group_id: str,
        client_source_port: int,
        origin_source_port: int,
        opened_at: datetime,
        closes_at: datetime,
        setup_started_at: datetime,
        setup_completed_at: datetime,
        setup_request_wire_bytes: int,
        setup_response_wire_bytes: int,
        planned_request_count: int,
        aggregate_request_wire_bytes: int,
        aggregate_response_wire_bytes: int,
        setup_outcome: ProxyChannelOutcome = "success",
    ) -> ExplicitProxyTunnelOpen | None:
        """Compatibility wrapper that prepares, claims, and commits one setup."""

        token = self.prepare_open_tunnel(
            affinity,
            client_transport_id=client_transport_id,
            origin_transport_id=origin_transport_id,
            client_zeek_uid=client_zeek_uid,
            origin_zeek_uid=origin_zeek_uid,
            tunnel_group_id=tunnel_group_id,
            client_source_port=client_source_port,
            origin_source_port=origin_source_port,
            opened_at=opened_at,
            closes_at=closes_at,
            setup_started_at=setup_started_at,
            setup_completed_at=setup_completed_at,
            setup_request_wire_bytes=setup_request_wire_bytes,
            setup_response_wire_bytes=setup_response_wire_bytes,
            planned_request_count=planned_request_count,
            aggregate_request_wire_bytes=aggregate_request_wire_bytes,
            aggregate_response_wire_bytes=aggregate_response_wire_bytes,
            setup_outcome=setup_outcome,
        )
        if token is None:
            return None
        with self.prepared_admission(token) as transaction:
            committed = transaction.commit_no_fail()
        result = committed.result
        assert isinstance(result, ExplicitProxyTunnelOpen)
        return result

    def _prepare_request_admission(
        self,
        affinity: ExplicitProxyChannelAffinity,
        *,
        requested_at: datetime,
        completed_at: datetime,
        request_wire_bytes: int,
        response_wire_bytes: int,
        upload_body_bytes: int = 0,
        outcome: ProxyChannelOutcome = "success",
        expected_channel_id: str = "",
        expected_client_transport_id: str = "",
        expected_origin_transport_id: str = "",
        expected_client_source_port: int | None = None,
        expected_snapshot: ExplicitProxyRequestSnapshot | None = None,
        retire_on_rejection: bool,
    ) -> ExplicitProxyAdmissionToken | None:
        """Prepare one exact child request or return ``None`` for a new path.

        ``request_wire_bytes`` is the complete client-to-proxy total and already
        contains ``upload_body_bytes``. The body size is an integrity fence only;
        it is deliberately not added to the directional reservation.
        """

        if min(request_wire_bytes, response_wire_bytes, upload_body_bytes) < 0:
            raise ValueError("Explicit-proxy request and upload bytes must be non-negative")
        if upload_body_bytes > request_wire_bytes:
            raise StateError("Upload body cannot exceed client-to-proxy request wire bytes")
        if outcome not in {
            "success",
            "denied",
            "authentication_required",
            "gateway_failure",
        }:
            raise ValueError(f"Unknown explicit-proxy request outcome {outcome!r}")
        canonical_request = ensure_utc(requested_at)
        canonical_complete = ensure_utc(completed_at)
        if canonical_complete < canonical_request:
            raise StateError("Explicit-proxy request completion cannot precede its request")
        affinity_digest = affinity.digest
        if expected_snapshot is not None:
            if not self.authenticates_request_snapshot(expected_snapshot):
                raise StateError("Explicit-proxy request has no authentic current-tunnel snapshot")
            if (
                expected_snapshot.affinity_digest != affinity_digest
                or expected_snapshot.requested_at != canonical_request
            ):
                raise StateError("Explicit-proxy request changed its current-tunnel snapshot")

        with self._locked_sidecar_prepared(affinity.owner_id, create=False) as shard:
            if shard is None:
                return None
            with shard.lock:
                tunnel = shard.tunnels.find_affinity(affinity_digest)
                if tunnel is None:
                    return None
                affinity_key = (affinity.owner_id, affinity_digest)
                self._reject_proxy_reservation_conflict_locked(
                    channel_ids=(tunnel.channel_id,),
                    affinity_key=affinity_key,
                    origin_transport_ids=(tunnel.origin_transport_id,),
                )
                self._check_expected_identity(
                    tunnel,
                    expected_channel_id=expected_channel_id,
                    expected_client_transport_id=expected_client_transport_id,
                    expected_origin_transport_id=expected_origin_transport_id,
                    expected_client_source_port=expected_client_source_port,
                )
                snapshot = self._registry.get(tunnel.channel_id)
                if snapshot is None or not snapshot.is_open:
                    raise StateError(
                        f"Explicit-proxy tunnel view {tunnel.channel_id!r} is not open"
                    )
                if expected_snapshot is not None:
                    current_generation = self._registry.channel_close_token(tunnel.channel_id)
                    if (
                        tunnel != expected_snapshot.tunnel
                        or snapshot != expected_snapshot.application_snapshot
                        or current_generation != expected_snapshot.generation_token
                    ):
                        raise StateError("Explicit-proxy current-tunnel snapshot is stale")
                if canonical_request < tunnel.opened_at:
                    raise StateError("Explicit-proxy child request cannot precede tunnel open")
                reusable = self._registry.find_reusable(
                    affinity_digest=affinity_digest,
                    owner_id=affinity.owner_id,
                    at=canonical_request,
                )
                if reusable is None:
                    effective_deadline = min(
                        tunnel.reuse_deadline,
                        snapshot.idle_deadline,
                        snapshot.identity.hard_deadline,
                        snapshot.identity.binding.closes_at,
                    )
                    if canonical_request >= effective_deadline:
                        if retire_on_rejection:
                            self._retire_locked(
                                shard,
                                tunnel.channel_id,
                                at=effective_deadline,
                                reason="reuse deadline",
                            )
                        return None
                    raise StateError(
                        f"Exact explicit-proxy channel {tunnel.channel_id!r} is not reusable"
                    )
                if reusable.channel_id != tunnel.channel_id:
                    raise StateError("Explicit-proxy affinity resolved to the wrong channel")
                snapshot = reusable
                duration = canonical_complete - canonical_request
                ordered_request = max(
                    canonical_request,
                    snapshot.last_activity_at + _REQUEST_GAP,
                )
                ordered_complete = ordered_request + duration
                effective_deadline = min(
                    tunnel.reuse_deadline,
                    snapshot.idle_deadline,
                    snapshot.identity.hard_deadline,
                    snapshot.identity.binding.closes_at,
                )
                if (
                    ordered_request >= effective_deadline
                    or ordered_complete > tunnel.reuse_deadline
                ):
                    if retire_on_rejection:
                        self._retire_locked(
                            shard,
                            tunnel.channel_id,
                            at=effective_deadline,
                            reason="reuse deadline",
                        )
                    return None

                budget = snapshot.identity.budget
                fits = (
                    snapshot.reserved_operations + 1 <= budget.operations
                    and snapshot.reserved_initiator_bytes + request_wire_bytes
                    <= budget.initiator_bytes
                    and snapshot.reserved_responder_bytes + response_wire_bytes
                    <= budget.responder_bytes
                )
                if not fits:
                    # Capacity overflow is a request for a replacement path,
                    # not authority to destroy the current one.  A later
                    # prepared open closes this exact tunnel only as part of
                    # its successful coupled commit.
                    return None

                ordinal = snapshot.reserved_operations
                operation_id = self._operation_id(tunnel.channel_id, ordinal)
                reservation = _validated_completed_operation(
                    operation_id=operation_id,
                    channel_id=tunnel.channel_id,
                    ordinal=ordinal,
                    started_at=ordered_request,
                    ended_at=ordered_complete,
                    initiator_bytes=request_wire_bytes,
                    responder_bytes=response_wire_bytes,
                )
                if outcome == "success":
                    application_token = self._registry.prepare_completed_operation(reservation)
                    result: ProxyAdmissionResult = ExplicitProxyRequestReuse(
                        tunnel=tunnel,
                        operation_id=operation_id,
                        ordinal=ordinal,
                        canonical_request_time=ordered_request,
                        canonical_complete_time=ordered_complete,
                        remaining_request_count=(
                            budget.operations - snapshot.reserved_operations - 1
                        ),
                        remaining_request_wire_bytes=(
                            budget.initiator_bytes
                            - snapshot.reserved_initiator_bytes
                            - request_wire_bytes
                        ),
                        remaining_response_wire_bytes=(
                            budget.responder_bytes
                            - snapshot.reserved_responder_bytes
                            - response_wire_bytes
                        ),
                    )
                else:
                    close_reason = f"terminal {outcome.replace('_', ' ')}"
                    application_token = self._registry.prepare_completed_operation_and_close(
                        reservation,
                        closed_at=ordered_complete,
                        reason=close_reason,
                    )
                    result = ExplicitProxyTerminalRequest(
                        tunnel=tunnel,
                        operation_id=operation_id,
                        ordinal=ordinal,
                        outcome=outcome,
                        canonical_request_time=ordered_request,
                        canonical_complete_time=ordered_complete,
                        close_at=ordered_complete,
                        close_reason=close_reason,
                    )
                try:
                    return self._new_admission_token(
                        kind="request",
                        application_token=application_token,
                        result=result,
                        owner_id=affinity.owner_id,
                        expected_tunnel=tunnel,
                        reserved_channel_ids=(tunnel.channel_id,),
                        reserved_affinity_key=affinity_key,
                        reserved_origin_transport_ids=(tunnel.origin_transport_id,),
                    )
                except (StateError, ValueError):
                    self._registry.cancel_prepared_admission(application_token)
                    raise

    def prepare_request(
        self,
        affinity: ExplicitProxyChannelAffinity,
        *,
        requested_at: datetime,
        completed_at: datetime,
        request_wire_bytes: int,
        response_wire_bytes: int,
        upload_body_bytes: int = 0,
        outcome: ProxyChannelOutcome = "success",
        expected_channel_id: str = "",
        expected_client_transport_id: str = "",
        expected_origin_transport_id: str = "",
        expected_client_source_port: int | None = None,
        expected_snapshot: ExplicitProxyRequestSnapshot | None = None,
    ) -> ExplicitProxyAdmissionToken | None:
        """Prepare a request without retiring or mutating its existing tunnel."""

        return self._prepare_request_admission(
            affinity,
            requested_at=requested_at,
            completed_at=completed_at,
            request_wire_bytes=request_wire_bytes,
            response_wire_bytes=response_wire_bytes,
            upload_body_bytes=upload_body_bytes,
            outcome=outcome,
            expected_channel_id=expected_channel_id,
            expected_client_transport_id=expected_client_transport_id,
            expected_origin_transport_id=expected_origin_transport_id,
            expected_client_source_port=expected_client_source_port,
            expected_snapshot=expected_snapshot,
            retire_on_rejection=False,
        )

    def reserve_request(
        self,
        affinity: ExplicitProxyChannelAffinity,
        *,
        requested_at: datetime,
        completed_at: datetime,
        request_wire_bytes: int,
        response_wire_bytes: int,
        upload_body_bytes: int = 0,
        outcome: ProxyChannelOutcome = "success",
        expected_channel_id: str = "",
        expected_client_transport_id: str = "",
        expected_origin_transport_id: str = "",
        expected_client_source_port: int | None = None,
    ) -> ExplicitProxyRequestReuse | None:
        """Compatibility wrapper that prepares, claims, and commits a child."""

        token = self._prepare_request_admission(
            affinity,
            requested_at=requested_at,
            completed_at=completed_at,
            request_wire_bytes=request_wire_bytes,
            response_wire_bytes=response_wire_bytes,
            upload_body_bytes=upload_body_bytes,
            outcome=outcome,
            expected_channel_id=expected_channel_id,
            expected_client_transport_id=expected_client_transport_id,
            expected_origin_transport_id=expected_origin_transport_id,
            expected_client_source_port=expected_client_source_port,
            expected_snapshot=None,
            retire_on_rejection=True,
        )
        if token is None:
            return None
        with self.prepared_admission(token) as transaction:
            committed = transaction.commit_no_fail()
        result = committed.result
        if isinstance(result, ExplicitProxyTerminalRequest):
            return None
        assert isinstance(result, ExplicitProxyRequestReuse)
        return result

    @staticmethod
    def _check_expected_identity(
        tunnel: ExplicitProxyTunnelIdentity,
        *,
        expected_channel_id: str,
        expected_client_transport_id: str,
        expected_origin_transport_id: str,
        expected_client_source_port: int | None,
    ) -> None:
        expected: tuple[tuple[str, object, object], ...] = (
            ("channel", expected_channel_id, tunnel.channel_id),
            (
                "client transport",
                expected_client_transport_id,
                tunnel.client_transport_id,
            ),
            (
                "origin transport",
                expected_origin_transport_id,
                tunnel.origin_transport_id,
            ),
            (
                "client source port",
                expected_client_source_port,
                tunnel.client_source_port,
            ),
        )
        for label, wanted, actual in expected:
            if wanted not in {"", None} and wanted != actual:
                raise StateError(
                    f"Explicit-proxy {label} identity mismatch: expected {wanted!r}, "
                    f"found {actual!r}"
                )

    def _set_tunnel_expiry(
        self,
        shard: _ProxySidecarShard,
        tunnel: ExplicitProxyTunnelIdentity,
        snapshot: ApplicationChannelSnapshot,
        *,
        tunnel_handle: int | None = None,
    ) -> None:
        deadline = min(tunnel.reuse_deadline, snapshot.idle_deadline).timestamp()
        handle = (
            shard.tunnels.handle_for(tunnel.channel_id) if tunnel_handle is None else tunnel_handle
        )
        shard.expiry.set(handle, deadline)

    def get_tunnel(self, channel_id: str) -> ExplicitProxyTunnelIdentity | None:
        """Return one open tunnel view by exact stable channel identity."""

        with self._gate.mutation():
            shard_id = self._registry.owner_partition_for_channel(channel_id)
            if shard_id is None:
                return None
            shard = self._shards.get(shard_id)
            if shard is None:
                return None
            with shard.lock:
                return shard.tunnels.get(channel_id)

    def close_tunnel(
        self,
        channel_id: str,
        *,
        closed_at: datetime,
        reason: str,
    ) -> bool:
        """Finalize one open tunnel idempotently and discard its sidecar."""

        with self._gate.mutation():
            shard_id = self._registry.owner_partition_for_channel(channel_id)
            if shard_id is None:
                return False
            shard = self._shards.get(shard_id)
            if shard is None:
                return False
            with shard.lock, self._prepared_lock:
                if channel_id in self._prepared_channel_ids:
                    raise StateError(
                        f"Explicit-proxy channel {channel_id!r} has a prepared admission"
                    )
                if shard.tunnels.get(channel_id) is None:
                    return False
                self._retire_locked(
                    shard,
                    channel_id,
                    at=ensure_utc(closed_at),
                    reason=reason,
                )
                return True

    def _retire_locked(
        self,
        shard: _ProxySidecarShard,
        channel_id: str,
        *,
        at: datetime,
        reason: str,
    ) -> None:
        snapshot = self._registry.get(channel_id)
        if snapshot is not None and snapshot.is_open:
            effective_deadline = min(
                snapshot.idle_deadline,
                snapshot.identity.hard_deadline,
                snapshot.identity.binding.closes_at,
            )
            close_time = min(
                effective_deadline,
                max(ensure_utc(at), snapshot.identity.opened_at, snapshot.last_activity_at),
            )
            self._registry.close_channel(
                channel_id,
                closed_at=close_time,
                reason=reason,
            )
        try:
            handle = shard.tunnels.handle_for(channel_id)
        except KeyError:
            return
        shard.tunnels.delete(channel_id)
        shard.expiry.pop(handle, None)

    @staticmethod
    def _compact_sidecars(
        shards: tuple[_ProxySidecarShard, ...],
        *,
        max_work: int,
    ) -> None:
        """Incrementally rotate sidecar primary maps within one global budget."""

        remaining = max_work
        for shard in shards:
            if remaining <= 0:
                break
            with shard.lock:
                before = shard.tunnels.metrics()
                force = not len(shard.tunnels) and (
                    before.primary_map_backing_bytes > _EMPTY_PACKED_ROUTE_BYTES
                )
                used = shard.tunnels.compact_primary(
                    max_slots=remaining,
                    force=force,
                )
                remaining -= used
                if remaining > 0:
                    remaining -= shard.expiry.compact(max_slots=remaining)

    def watermark(self, at: datetime) -> ExplicitProxyChannelCensus:
        """Drain due sidecars and, for a private fallback, the common registry."""

        canonical_time = ensure_utc(at)
        with self._gate.watermark():
            if canonical_time < self._watermark:
                raise StateError("Explicit-proxy watermarks must be monotonic")
            with self._prepared_lock:
                claimed_frontier = min(
                    (
                        capability.linearization_time
                        for capability in self._prepared_capabilities.values()
                        if capability.admission_id in self._claimed_admissions
                    ),
                    default=None,
                )
            if claimed_frontier is not None and canonical_time > claimed_frontier:
                raise StateError(
                    "Explicit-proxy watermark cannot advance past a claimed admission at "
                    f"{claimed_frontier.isoformat()}"
                )
            with self._directory_lock:
                shards = tuple(self._shards[index] for index in sorted(self._shards))
            cutoff = canonical_time.timestamp()
            for shard in shards:
                while True:
                    with shard.lock:
                        due = shard.expiry.expire_before_page(
                            cutoff,
                            inclusive=True,
                            limit=_SIDECAR_COMPACTION_WORK_PER_WATERMARK,
                        )
                        for handle, deadline in due:
                            try:
                                tunnel = shard.tunnels.get_by_handle(handle)
                            except KeyError:
                                continue
                            self._retire_locked(
                                shard,
                                tunnel.channel_id,
                                at=datetime.fromtimestamp(
                                    deadline,
                                    tz=canonical_time.tzinfo,
                                ),
                                reason="deadline",
                            )
                    if not due:
                        break
            self._compact_sidecars(
                shards,
                max_work=_SIDECAR_COMPACTION_WORK_PER_WATERMARK,
            )
            if self._owns_registry:
                self._registry.watermark(canonical_time)
            self._watermark = canonical_time
            return self._census_unfenced(shards)

    def census(self) -> ExplicitProxyChannelCensus:
        """Return bounded current-state and expiry-amplification metrics."""

        with self._gate.watermark():
            with self._directory_lock:
                shards = tuple(self._shards[index] for index in sorted(self._shards))
            return self._census_unfenced(shards)

    def _census_unfenced(
        self,
        shards: tuple[_ProxySidecarShard, ...],
    ) -> ExplicitProxyChannelCensus:
        with self._prepared_lock:
            prepared_admissions = len(self._prepared_admissions)
            claimed_admissions = len(self._claimed_admissions)
            reserved_channel_ids = len(self._prepared_channel_ids)
            reserved_affinities = len(self._prepared_affinity_keys)
            reserved_origin_transport_ids = len(self._prepared_origin_transport_ids)
            prepared_map_bytes = sum(
                sys.getsizeof(value)
                for value in (
                    self._prepared_admissions,
                    self._prepared_capabilities,
                    self._claimed_admissions,
                    self._prepared_channel_ids,
                    self._prepared_affinity_keys,
                    self._prepared_origin_transport_ids,
                )
            )
            estimated_prepared_bytes = self._estimated_prepared_bytes + prepared_map_bytes
        store_metrics = []
        expiry_metrics = []
        for shard in shards:
            with shard.lock:
                store_metrics.append(shard.tunnels.metrics(estimate_bytes=True))
                expiry_metrics.append(shard.expiry.metrics(estimate_bytes=True))
        sidecar_estimated_index_bytes = (
            sum(metric.estimated_bytes for metric in (*store_metrics, *expiry_metrics))
            + prepared_map_bytes
        )
        return ExplicitProxyChannelCensus(
            open_tunnel_views=sum(metric.live_entries for metric in store_metrics),
            tunnel_expiry_entries=sum(metric.backing_entries for metric in expiry_metrics),
            stale_tunnel_expiry_entries=sum(metric.stale_entries for metric in expiry_metrics),
            sidecar_shard_count=len(shards),
            max_sidecar_shard_load=max(
                (metric.live_entries for metric in store_metrics),
                default=0,
            ),
            sidecar_allocated_slots=sum(metric.allocated_slots for metric in store_metrics),
            sidecar_primary_map_bytes=sum(
                metric.primary_map_backing_bytes for metric in store_metrics
            ),
            sidecar_primary_map_amplification=(
                sum(metric.primary_map_backing_bytes for metric in store_metrics)
                / max(
                    1,
                    len(store_metrics) * _EMPTY_PACKED_ROUTE_BYTES
                    + sum(metric.live_entries for metric in store_metrics)
                    * _ESTIMATED_PACKED_ROUTE_VALUE_BYTES,
                )
            ),
            sidecar_estimated_bytes=(
                sys.getsizeof(self._shards)
                + sum(sys.getsizeof(shard) for shard in shards)
                + sum(shard.tunnels.estimated_value_bytes for shard in shards)
                + sidecar_estimated_index_bytes
                + self._estimated_prepared_bytes
            ),
            sidecar_estimated_index_bytes=sidecar_estimated_index_bytes,
            decoded_cache_entries=sum(shard.tunnels.decoded_cache_entries for shard in shards),
            decoded_cache_capacity=(len(shards) * _DECODED_CACHE_CAPACITY_PER_SHARD),
            decoded_cache_estimated_bytes=sum(
                shard.tunnels.decoded_cache_estimated_bytes for shard in shards
            ),
            sidecar_lookup_candidates_inspected=sum(
                metric.lookup_candidates_inspected for metric in store_metrics
            ),
            sidecar_compaction_pending=sum(
                metric.primary_compaction_pending for metric in store_metrics
            ),
            sidecar_compaction_rotations=sum(
                metric.primary_compaction_rotations for metric in store_metrics
            ),
            sidecar_compaction_work=sum(metric.primary_compaction_work for metric in store_metrics)
            + sum(metric.compaction_work for metric in expiry_metrics),
            sidecar_compaction_seconds=sum(
                metric.primary_compaction_seconds for metric in store_metrics
            )
            + sum(metric.compaction_seconds for metric in expiry_metrics),
            prepared_admissions=prepared_admissions,
            claimed_admissions=claimed_admissions,
            reserved_channel_ids=reserved_channel_ids,
            reserved_affinities=reserved_affinities,
            reserved_origin_transport_ids=reserved_origin_transport_ids,
            estimated_prepared_bytes=estimated_prepared_bytes,
            application=self._registry.census(),
        )

    def channel_snapshot(self, channel_id: str) -> ApplicationChannelSnapshot | None:
        """Return one frozen common-registry snapshot for tests and diagnostics."""

        with self._gate.mutation():
            return self._registry.get(channel_id)
