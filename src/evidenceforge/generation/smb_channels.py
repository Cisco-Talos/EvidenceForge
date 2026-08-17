# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Bounded SMB session, tree, and handle state on shared application channels."""

from __future__ import annotations

import hashlib
import json
import struct
import sys
from collections import OrderedDict
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from json.encoder import encode_basestring
from threading import Condition, Lock, RLock
from typing import Self

from evidenceforge.events.application import (
    ApplicationChannelBudget,
    ApplicationChannelCensus,
    ApplicationChannelIdentity,
    ApplicationChannelSnapshot,
    ApplicationOperationReservation,
    ApplicationTransportBinding,
)
from evidenceforge.events.network import (
    DirectionalTrafficLedger,
    NetworkSensorObservation,
    NetworkTrafficLedger,
    NetworkTransactionPlan,
)
from evidenceforge.generation.application_channels import (
    ApplicationChannelCloseRequest,
    ApplicationChannelCloseToken,
    ApplicationChannelRegistry,
)
from evidenceforge.generation.indexes import CompactIndexedStore, PackedHandleExpiryIndex
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.ids import generate_stable_zeek_uid
from evidenceforge.utils.time import ensure_utc

_ORDERING_GAP = timedelta(microseconds=1)
_PRIMARY_COMPACTION_WORK_PER_WATERMARK = 4_096
# Keep one bounded 16K warmed exact working set across the fixed 64 owner
# shards. Release probes use 10K uniformly distributed queries; a smaller
# cache turns every symmetric warmup pass into deterministic cache thrash and
# measures rich reconstruction rather than the public warmed exact path.
_SNAPSHOT_CACHE_PER_SHARD = 256
_EXACT_ROUTE_CACHE_LIMIT = 16_384
_SEMANTIC_JSON_ENCODER = json.JSONEncoder(
    ensure_ascii=False,
    separators=(",", ":"),
)
_SMB_AFFINITY_NAMESPACE_JSON = encode_basestring("smb-channel-affinity-v1")
_SMB_CHANNEL_NAMESPACE_JSON = encode_basestring("smb-channel-v1")
_SMB_SESSION_NAMESPACE_JSON = encode_basestring("smb-session-v1")
_SMB_TREE_NAMESPACE_JSON = encode_basestring("smb-tree-v1")
_SMB_OPERATION_NAMESPACE_JSON = encode_basestring("smb-operation-v1")


def _required_text(value: str, field_name: str) -> str:
    if value and not value[0].isspace() and not value[-1].isspace():
        return value
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field_name} must not be empty")
    return normalized


def _new_channel_budget(
    initiator_bytes: int,
    responder_bytes: int,
    operations: int,
) -> ApplicationChannelBudget:
    """Build one already-validated channel budget without a transient kwargs mapping."""

    value = object.__new__(ApplicationChannelBudget)
    object.__setattr__(value, "initiator_bytes", initiator_bytes)
    object.__setattr__(value, "responder_bytes", responder_bytes)
    object.__setattr__(value, "operations", operations)
    return value


def _new_transport_binding(
    transport_id: str,
    opened_at: datetime,
    closes_at: datetime,
) -> ApplicationTransportBinding:
    """Build one already-validated immutable transport binding."""

    value = object.__new__(ApplicationTransportBinding)
    object.__setattr__(value, "transport_id", transport_id)
    object.__setattr__(value, "opened_at", opened_at)
    object.__setattr__(value, "closes_at", closes_at)
    return value


def _new_channel_identity(
    *,
    channel_id: str,
    owner_id: str,
    affinity_digest: str,
    binding: ApplicationTransportBinding,
    opened_at: datetime,
    idle_timeout: timedelta,
    hard_deadline: datetime,
    budget: ApplicationChannelBudget,
) -> ApplicationChannelIdentity:
    """Build one already-validated SMB application-channel identity."""

    value = object.__new__(ApplicationChannelIdentity)
    object.__setattr__(value, "channel_id", channel_id)
    object.__setattr__(value, "protocol", "smb")
    object.__setattr__(value, "owner_id", owner_id)
    object.__setattr__(value, "affinity_digest", affinity_digest)
    object.__setattr__(value, "binding", binding)
    object.__setattr__(value, "opened_at", opened_at)
    object.__setattr__(value, "idle_timeout", idle_timeout)
    object.__setattr__(value, "hard_deadline", hard_deadline)
    object.__setattr__(value, "budget", budget)
    return value


def _new_initial_reservation(
    *,
    operation_id: str,
    channel_id: str,
    started_at: datetime,
    ended_at: datetime,
    initiator_bytes: int,
    responder_bytes: int,
) -> ApplicationOperationReservation:
    """Build one already-validated initial operation reservation."""

    value = object.__new__(ApplicationOperationReservation)
    object.__setattr__(value, "operation_id", operation_id)
    object.__setattr__(value, "channel_id", channel_id)
    object.__setattr__(value, "ordinal", 0)
    object.__setattr__(value, "started_at", started_at)
    object.__setattr__(value, "ended_at", ended_at)
    object.__setattr__(value, "initiator_bytes", initiator_bytes)
    object.__setattr__(value, "responder_bytes", responder_bytes)
    object.__setattr__(value, "parent_operation_id", "")
    return value


def _semantic_digest(namespace: str, values: tuple[object, ...]) -> str:
    encoded = _semantic_material(namespace, values)
    return hashlib.sha256(encoded).hexdigest()


def _semantic_token(namespace: str, values: tuple[object, ...]) -> str:
    """Return the exact leading 128 bits of a semantic digest."""

    encoded = _semantic_material(namespace, values)
    return hashlib.sha256(encoded).digest()[:16].hex()


def _semantic_string_token_one(namespace_json: str, value: str) -> str:
    """Return an exact semantic token for the common one-string shape."""

    encoded = ("[" + namespace_json + "," + encode_basestring(value) + "]").encode("utf-8")
    return hashlib.sha256(encoded).digest()[:16].hex()


def _semantic_string_digest_two(namespace_json: str, first: str, second: str) -> bytes:
    """Return an exact semantic digest for the common two-string shape."""

    encoded = (
        "["
        + namespace_json
        + ","
        + encode_basestring(first)
        + ","
        + encode_basestring(second)
        + "]"
    ).encode("utf-8")
    return hashlib.sha256(encoded).digest()[:16]


def _semantic_string_token_two(namespace_json: str, first: str, second: str) -> str:
    """Return an exact semantic token for the common two-string shape."""

    return _semantic_string_digest_two(namespace_json, first, second).hex()


def _semantic_string_material(namespace_json: str, values: tuple[str, ...]) -> bytes:
    """Encode an all-string semantic tuple without a transient parts list."""

    return ("[" + namespace_json + "," + ",".join(map(encode_basestring, values)) + "]").encode(
        "utf-8"
    )


def _semantic_material(namespace: str, values: tuple[object, ...]) -> bytes:
    """Encode common scalar identity values byte-identically to compact JSON."""

    parts = [encode_basestring(namespace)]
    for value in values:
        if isinstance(value, str):
            parts.append(encode_basestring(value))
        elif type(value) is int:
            parts.append(str(value))
        elif value is True:
            parts.append("true")
        elif value is False:
            parts.append("false")
        elif value is None:
            parts.append("null")
        else:
            return _SEMANTIC_JSON_ENCODER.encode((namespace, *values)).encode("utf-8")
    return ("[" + ",".join(parts) + "]").encode("utf-8")


@dataclass(frozen=True, slots=True)
class SmbChannelAffinity:
    """Exact session-compatible SMB transport affinity."""

    client_identity: str
    client_ip: str
    client_session: str
    server_identity: str
    server_ip: str
    principal: str
    auth_protocol: str
    account_scope: str
    dialect: str
    signing_policy: str
    encryption_policy: str
    server_policy: str
    share_policy: str
    client_access: str
    _digest: str = field(init=False, repr=False, compare=False)
    _digest_bytes: bytes = field(init=False, repr=False, compare=False)
    _owner_id: str = field(init=False, repr=False, compare=False)

    @classmethod
    def _from_canonical(
        cls,
        *,
        client_identity: str,
        client_ip: str,
        client_session: str,
        server_identity: str,
        server_ip: str,
        principal: str,
        auth_protocol: str,
        account_scope: str,
        dialect: str,
        signing_policy: str,
        encryption_policy: str,
        server_policy: str,
        share_policy: str,
        client_access: str,
    ) -> Self:
        """Build one internally proven canonical affinity without normalizing twice."""

        values = (
            client_identity,
            client_ip,
            client_session,
            server_identity,
            server_ip,
            principal,
            auth_protocol,
            account_scope,
            dialect,
            signing_policy,
            encryption_policy,
            server_policy,
            share_policy,
            client_access,
        )
        value = object.__new__(cls)
        for field_name, field_value in zip(
            (
                "client_identity",
                "client_ip",
                "client_session",
                "server_identity",
                "server_ip",
                "principal",
                "auth_protocol",
                "account_scope",
                "dialect",
                "signing_policy",
                "encryption_policy",
                "server_policy",
                "share_policy",
                "client_access",
            ),
            values,
            strict=True,
        ):
            object.__setattr__(value, field_name, field_value)
        digest_bytes = hashlib.sha256(
            _semantic_string_material(_SMB_AFFINITY_NAMESPACE_JSON, values)
        ).digest()
        object.__setattr__(
            value,
            "_owner_id",
            f"smb-client:{client_identity}:{client_session}",
        )
        object.__setattr__(value, "_digest", digest_bytes.hex())
        object.__setattr__(value, "_digest_bytes", digest_bytes)
        return value

    def __post_init__(self) -> None:
        """Normalize semantic fields before deriving compact exact keys."""

        for field_name in (
            "client_identity",
            "client_ip",
            "client_session",
            "server_identity",
            "server_ip",
            "principal",
            "auth_protocol",
            "account_scope",
            "dialect",
            "signing_policy",
            "encryption_policy",
            "server_policy",
            "share_policy",
            "client_access",
        ):
            raw_value = getattr(self, field_name)
            if not isinstance(raw_value, str):
                raise TypeError(f"{field_name} must be a string")
            value = raw_value.strip().casefold()
            if not value:
                raise ValueError(f"{field_name} must not be empty")
            if value != raw_value:
                object.__setattr__(self, field_name, value)
        owner_id = f"smb-client:{self.client_identity}:{self.client_session}"
        material = _semantic_string_material(
            _SMB_AFFINITY_NAMESPACE_JSON,
            (
                self.client_identity,
                self.client_ip,
                self.client_session,
                self.server_identity,
                self.server_ip,
                self.principal,
                self.auth_protocol,
                self.account_scope,
                self.dialect,
                self.signing_policy,
                self.encryption_policy,
                self.server_policy,
                self.share_policy,
                self.client_access,
            ),
        )
        digest_bytes = hashlib.sha256(material).digest()
        object.__setattr__(self, "_owner_id", owner_id)
        object.__setattr__(self, "_digest", digest_bytes.hex())
        object.__setattr__(self, "_digest_bytes", digest_bytes)

    @property
    def owner_id(self) -> str:
        """Return the stable client/session partition owner."""

        return self._owner_id

    @property
    def digest(self) -> str:
        """Return the stable exact affinity digest."""

        return self._digest


@dataclass(frozen=True, slots=True)
class SmbSessionView:
    """Open-only protocol view attached to one immutable transport."""

    channel_id: str
    session_id: str
    affinity_digest: str
    transport_plan: NetworkTransactionPlan
    sensor_observations: tuple[NetworkSensorObservation, ...]
    ground_truth_transport_uid: str
    logon_id: str
    auth_session_ref: str
    principal: str
    auth_protocol: str
    account_scope: str
    effective_uid: int | None
    effective_gid: int | None
    client_access: str
    server_hostname: str
    client_ip: str
    lifecycle_group_id: str

    @property
    def transport_id(self) -> str:
        """Return the immutable canonical transport identity."""

        return self.transport_plan.stable_id


@dataclass(frozen=True, slots=True)
class SmbTreeView:
    """One reusable tree connection within an open SMB session."""

    tree_id: str
    channel_id: str
    session_id: str
    share_ref: str
    connected_at: datetime


@dataclass(frozen=True, slots=True)
class SmbHandleView:
    """One active versioned SMB file handle."""

    handle_id: str
    channel_id: str
    tree_id: str
    operation_id: str
    file_id: str
    content_version: int
    access: str
    opened_at: datetime
    deny_write: bool = False


@dataclass(frozen=True, slots=True)
class SmbOperationLease:
    """Frozen session/tree/transport identity for one admitted SMB action."""

    channel_id: str
    session_id: str
    tree_id: str
    operation_id: str
    ordinal: int
    started_at: datetime
    ended_at: datetime
    transport_plan: NetworkTransactionPlan
    sensor_observations: tuple[NetworkSensorObservation, ...]
    ground_truth_transport_uid: str
    logon_id: str
    auth_session_ref: str
    principal: str
    auth_protocol: str
    account_scope: str
    effective_uid: int | None
    effective_gid: int | None
    client_access: str
    lifecycle_group_id: str
    reused_session: bool
    created_tree: bool
    operation_completed: bool = False


@dataclass(frozen=True, slots=True)
class SmbChannelClosure:
    """Lock-free close intent returned to the generator for source projection."""

    channel_id: str
    session_id: str
    logon_id: str
    principal: str
    server_hostname: str
    lifecycle_group_id: str
    closed_at: datetime
    reason: str


class SmbClosurePage(Sequence[SmbChannelClosure]):
    """Bounded compact closure columns decoded only by the outside consumer."""

    __slots__ = (
        "_channel_keys",
        "_closed_at_us",
        "_metadata_payloads",
        "_plan_payloads",
        "_reason",
    )

    def __init__(
        self,
        *,
        channel_keys: tuple[bytes, ...] = (),
        plan_payloads: tuple[bytes, ...] = (),
        metadata_payloads: tuple[bytes, ...] = (),
        closed_at_us: tuple[int, ...] = (),
        reason: str = "deadline",
    ) -> None:
        """Retain one bounded primitive page without rich closure objects."""

        size = len(channel_keys)
        if not (
            len(plan_payloads) == size
            and len(metadata_payloads) == size
            and len(closed_at_us) == size
        ):
            raise ValueError("SMB closure-page columns must have matching lengths")
        self._channel_keys = channel_keys
        self._plan_payloads = plan_payloads
        self._metadata_payloads = metadata_payloads
        self._closed_at_us = closed_at_us
        self._reason = _required_text(reason, "reason")

    def __len__(self) -> int:
        """Return the bounded number of retained closure descriptors."""

        return len(self._channel_keys)

    def _materialize(self, index: int) -> SmbChannelClosure:
        channel_id = f"smb-channel-{self._channel_keys[index].hex()}"
        logon_id, principal, server, lifecycle, _started_at, _planned_close = (
            _unpack_closure_metadata_payloads(
                self._plan_payloads[index],
                self._metadata_payloads[index],
            )
        )
        return SmbChannelClosure(
            channel_id=channel_id,
            session_id=f"smb-session-{_semantic_token('smb-session-v1', (channel_id,))}",
            logon_id=logon_id,
            principal=principal,
            server_hostname=server,
            lifecycle_group_id=lifecycle,
            closed_at=_datetime_from_us(self._closed_at_us[index]),
            reason=self._reason,
        )

    def __getitem__(self, index: int | slice) -> SmbChannelClosure | tuple[SmbChannelClosure, ...]:
        """Decode one item, or a requested bounded slice, on demand."""

        if isinstance(index, slice):
            return tuple(
                self._materialize(position) for position in range(*index.indices(len(self)))
            )
        return self._materialize(index)

    def __iter__(self) -> Iterator[SmbChannelClosure]:
        """Stream rich closure values outside registry locks."""

        for index in range(len(self)):
            yield self._materialize(index)


@dataclass(frozen=True, slots=True)
class SmbReuseResult:
    """One exact reuse decision plus any displaced session close intent."""

    lease: SmbOperationLease | None
    closures: tuple[SmbChannelClosure, ...] = ()


@dataclass(frozen=True, slots=True)
class SmbWatermarkResult:
    """One canonical watermark result and its finalized sessions."""

    census: SmbChannelCensus
    closures: SmbClosurePage
    has_more: bool = False


@dataclass(frozen=True, slots=True)
class SmbChannelCensus:
    """Constant-time retained-state and structural amplification metrics."""

    open_sessions: int
    open_trees: int
    open_handles: int
    session_backing_entries: int
    tree_backing_entries: int
    handle_backing_entries: int
    stale_sidecar_entries: int
    expiry_entries: int
    stale_expiry_entries: int
    shard_count: int
    max_shard_load: int
    maximum_trees_per_session: int
    maximum_handles_per_operation: int
    lookup_candidates_inspected: int
    sidecar_lookup_candidates_inspected: int
    sidecar_estimated_bytes: int
    sidecar_estimated_index_bytes: int
    estimated_bytes: int
    estimated_index_bytes: int
    primary_compaction_pending: int
    primary_compaction_rotations: int
    primary_compaction_work: int
    primary_compaction_seconds: float
    application: ApplicationChannelCensus


class _SmbMutationGate:
    """Allow disjoint owners to mutate while fencing canonical watermarks."""

    def __init__(self) -> None:
        self._condition = Condition(Lock())
        self._readers = 0
        self._writer = False
        self._waiting_writers = 0

    def enter_mutation(self) -> None:
        """Enter one shared mutation lane without allocating a context wrapper."""

        with self._condition:
            while self._writer or self._waiting_writers:
                self._condition.wait()
            self._readers += 1

    def exit_mutation(self) -> None:
        """Leave one shared mutation lane entered by :meth:`enter_mutation`."""

        with self._condition:
            self._readers -= 1
            if self._readers == 0:
                self._condition.notify_all()

    @contextmanager
    def mutation(self) -> Iterator[None]:
        """Enter one shared mutation lane."""

        self.enter_mutation()
        try:
            yield
        finally:
            self.exit_mutation()

    @contextmanager
    def watermark(self) -> Iterator[None]:
        """Fence mutations while one canonical cutoff commits."""

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


_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_MISSING_INT64 = -(1 << 63)
_TEXT_LENGTH = struct.Struct("<I")
_INT64 = struct.Struct("<q")
_PLAN_NUMERIC = struct.Struct("<qqIId8QiiIII")
_SESSION_NUMERIC = struct.Struct("<qqIII")
_TREE_NUMERIC = struct.Struct("<q")
_HANDLE_NUMERIC = struct.Struct("<Iq?B")
_COMMON_TEXT = (
    "success",
    "failure",
    "denied",
    "tcp",
    "udp",
    "icmp",
    "smb",
    "SF",
    "S0",
    "ShADadfF",
    "attempt",
    "close",
    "established",
    "application",
    "response",
    "kerberos",
    "ntlm",
    "negotiate",
    "directory",
    "windows_native",
    "cifs_mount",
    "smbclient",
    "read",
    "write",
)
_COMMON_TEXT_CODES = {value: index + 1 for index, value in enumerate(_COMMON_TEXT)}


def _datetime_us(value: datetime) -> int:
    canonical = value if value.tzinfo is UTC else ensure_utc(value)
    delta = canonical - _EPOCH
    return ((delta.days * 86_400 + delta.seconds) * 1_000_000) + delta.microseconds


def _datetime_from_us(value: int) -> datetime:
    return _EPOCH + timedelta(microseconds=value)


def _append_text(buffer: bytearray, value: str) -> None:
    encoded = value.encode("utf-8")
    if len(encoded) >= 1 << 32:
        raise StateError("SMB compact text value exceeds the 32-bit length limit")
    buffer.extend(_TEXT_LENGTH.pack(len(encoded)))
    buffer.extend(encoded)


def _read_text(payload: memoryview, offset: int) -> tuple[str, int]:
    (length,) = _TEXT_LENGTH.unpack_from(payload, offset)
    offset += _TEXT_LENGTH.size
    stop = offset + length
    if stop > len(payload):  # pragma: no cover - protected by internal encoder
        raise StateError("Corrupt compact SMB descriptor")
    return bytes(payload[offset:stop]).decode("utf-8"), stop


def _skip_text(payload: memoryview, offset: int) -> int:
    (length,) = _TEXT_LENGTH.unpack_from(payload, offset)
    stop = offset + _TEXT_LENGTH.size + length
    if stop > len(payload):  # pragma: no cover - protected by internal encoder
        raise StateError("Corrupt compact SMB descriptor")
    return stop


def _append_compact_text(buffer: bytearray, value: str) -> None:
    code = _COMMON_TEXT_CODES.get(value, 0)
    buffer.append(code)
    if not code:
        _append_text(buffer, value)


def _read_compact_text(payload: memoryview, offset: int) -> tuple[str, int]:
    code = payload[offset]
    offset += 1
    if code:
        return _COMMON_TEXT[code - 1], offset
    return _read_text(payload, offset)


def _skip_compact_text(payload: memoryview, offset: int) -> int:
    code = payload[offset]
    offset += 1
    return offset if code else _skip_text(payload, offset)


def _pack_network_plan(plan: NetworkTransactionPlan) -> bytes:
    closed_at = _MISSING_INT64 if plan.closed_at is None else _datetime_us(plan.closed_at)
    duration = float("nan") if plan.duration is None else plan.duration
    flags = (
        int(plan.local_orig)
        | (int(plan.local_resp) << 1)
        | (int(plan.link_local) << 2)
        | (int(plan.application_layer_only) << 3)
    )
    traffic = plan.traffic
    buffer = bytearray(
        _PLAN_NUMERIC.pack(
            _datetime_us(plan.started_at),
            closed_at,
            plan.src_port,
            plan.dst_port,
            duration,
            traffic.orig.payload_bytes,
            traffic.orig.packets,
            traffic.orig.ip_bytes,
            traffic.resp.payload_bytes,
            traffic.resp.packets,
            traffic.resp.ip_bytes,
            traffic.missed_orig_bytes,
            traffic.missed_resp_bytes,
            plan.initiating_pid,
            plan.responding_pid,
            plan.ip_proto,
            flags,
            len(plan.phase_times),
        )
    )
    for value in (
        plan.stable_id,
        plan.hostname,
        plan.outcome,
        plan.src_ip,
        plan.dst_ip,
        plan.protocol,
        plan.service,
        plan.zeek_uid,
        plan.conn_id,
        plan.conn_state,
        plan.history,
    ):
        code = _COMMON_TEXT_CODES.get(value, 0)
        buffer.append(code)
        if not code:
            encoded = value.encode("utf-8")
            if len(encoded) >= 1 << 32:
                raise StateError("SMB compact text value exceeds the 32-bit length limit")
            buffer.extend(_TEXT_LENGTH.pack(len(encoded)))
            buffer.extend(encoded)
    for name, timestamp in plan.phase_times:
        code = _COMMON_TEXT_CODES.get(name, 0)
        buffer.append(code)
        if not code:
            encoded = name.encode("utf-8")
            if len(encoded) >= 1 << 32:
                raise StateError("SMB compact text value exceeds the 32-bit length limit")
            buffer.extend(_TEXT_LENGTH.pack(len(encoded)))
            buffer.extend(encoded)
        buffer.extend(_INT64.pack(_datetime_us(timestamp)))
    return bytes(buffer)


def _unpack_network_plan(payload: bytes) -> NetworkTransactionPlan:
    view = memoryview(payload)
    numeric = _PLAN_NUMERIC.unpack_from(view)
    offset = _PLAN_NUMERIC.size
    text: list[str] = []
    for _ in range(11):
        value, offset = _read_compact_text(view, offset)
        text.append(value)
    phases: list[tuple[str, datetime]] = []
    for _ in range(numeric[17]):
        name, offset = _read_compact_text(view, offset)
        (timestamp_us,) = _INT64.unpack_from(view, offset)
        offset += _INT64.size
        phases.append((name, _datetime_from_us(timestamp_us)))
    closed_at = None if numeric[1] == _MISSING_INT64 else _datetime_from_us(numeric[1])
    duration = None if numeric[4] != numeric[4] else numeric[4]
    flags = numeric[16]
    return NetworkTransactionPlan(
        stable_id=text[0],
        hostname=text[1],
        outcome=text[2],
        phase_times=tuple(phases),
        started_at=_datetime_from_us(numeric[0]),
        closed_at=closed_at,
        src_ip=text[3],
        src_port=numeric[2],
        dst_ip=text[4],
        dst_port=numeric[3],
        protocol=text[5],
        service=text[6],
        zeek_uid=text[7],
        conn_id=text[8],
        duration=duration,
        conn_state=text[9],
        history=text[10],
        traffic=NetworkTrafficLedger(
            orig=DirectionalTrafficLedger(
                payload_bytes=numeric[5],
                packets=numeric[6],
                ip_bytes=numeric[7],
            ),
            resp=DirectionalTrafficLedger(
                payload_bytes=numeric[8],
                packets=numeric[9],
                ip_bytes=numeric[10],
            ),
            missed_orig_bytes=numeric[11],
            missed_resp_bytes=numeric[12],
        ),
        initiating_pid=numeric[13],
        responding_pid=numeric[14],
        local_orig=bool(flags & 1),
        local_resp=bool(flags & 2),
        ip_proto=numeric[15],
        link_local=bool(flags & 4),
        application_layer_only=bool(flags & 8),
    )


def _unpack_network_closure_defaults(
    payload: bytes,
) -> tuple[str, str, str, str, datetime, datetime | None]:
    view = memoryview(payload)
    numeric = _PLAN_NUMERIC.unpack_from(view)
    offset = _PLAN_NUMERIC.size
    retained: dict[int, str] = {}
    for index in range(11):
        if index in {0, 1, 3, 7}:
            retained[index], offset = _read_compact_text(view, offset)
        else:
            offset = _skip_compact_text(view, offset)
    return (
        retained[0],
        retained[1],
        retained[3],
        retained[7],
        _datetime_from_us(numeric[0]),
        None if numeric[1] == _MISSING_INT64 else _datetime_from_us(numeric[1]),
    )


def _pack_session_metadata_values(
    *,
    plan: NetworkTransactionPlan,
    close_token: ApplicationChannelCloseToken,
    ground_truth_transport_uid: str,
    logon_id: str,
    auth_session_ref: str,
    principal: str,
    auth_protocol: str,
    account_scope: str,
    effective_uid: int | None,
    effective_gid: int | None,
    client_access: str,
    server_hostname: str,
    client_ip: str,
    lifecycle_group_id: str,
) -> bytes:
    flags = (
        int(ground_truth_transport_uid == plan.zeek_uid)
        | (int(server_hostname == plan.hostname) << 1)
        | (int(client_ip == plan.src_ip) << 2)
        | (int(lifecycle_group_id == plan.stable_id) << 3)
    )
    buffer = bytearray(
        _SESSION_NUMERIC.pack(
            _MISSING_INT64 if effective_uid is None else effective_uid,
            _MISSING_INT64 if effective_gid is None else effective_gid,
            flags,
            close_token.locator,
            close_token.generation,
        )
    )
    for value in (
        logon_id,
        auth_session_ref,
        principal,
        auth_protocol,
        account_scope,
        client_access,
    ):
        code = _COMMON_TEXT_CODES.get(value, 0)
        buffer.append(code)
        if not code:
            encoded = value.encode("utf-8")
            if len(encoded) >= 1 << 32:
                raise StateError("SMB compact text value exceeds the 32-bit length limit")
            buffer.extend(_TEXT_LENGTH.pack(len(encoded)))
            buffer.extend(encoded)
    for bit, value in (
        (1, ground_truth_transport_uid),
        (2, server_hostname),
        (4, client_ip),
        (8, lifecycle_group_id),
    ):
        if not flags & bit:
            code = _COMMON_TEXT_CODES.get(value, 0)
            buffer.append(code)
            if not code:
                encoded = value.encode("utf-8")
                if len(encoded) >= 1 << 32:
                    raise StateError("SMB compact text value exceeds the 32-bit length limit")
                buffer.extend(_TEXT_LENGTH.pack(len(encoded)))
                buffer.extend(encoded)
    return bytes(buffer)


def _unpack_session_metadata(
    payload: bytes,
    plan: NetworkTransactionPlan,
) -> tuple[int | None, int | None, tuple[str, ...]]:
    view = memoryview(payload)
    effective_uid, effective_gid, flags, _close_locator, _close_generation = (
        _SESSION_NUMERIC.unpack_from(view)
    )
    offset = _SESSION_NUMERIC.size
    text: list[str] = []
    for _ in range(6):
        value, offset = _read_compact_text(view, offset)
        text.append(value)
    conditional: list[str] = []
    defaults = (plan.zeek_uid, plan.hostname, plan.src_ip, plan.stable_id)
    for bit, default in zip((1, 2, 4, 8), defaults, strict=True):
        if flags & bit:
            conditional.append(default)
        else:
            value, offset = _read_compact_text(view, offset)
            conditional.append(value)
    return (
        None if effective_uid == _MISSING_INT64 else effective_uid,
        None if effective_gid == _MISSING_INT64 else effective_gid,
        (
            conditional[0],
            text[0],
            text[1],
            text[2],
            text[3],
            text[4],
            text[5],
            conditional[1],
            conditional[2],
            conditional[3],
        ),
    )


def _unpack_closure_metadata_payloads(
    plan_payload: bytes,
    metadata_payload: bytes,
) -> tuple[str, str, str, str, datetime, datetime | None]:
    stable_id, hostname, client_ip, zeek_uid, started_at, closed_at = (
        _unpack_network_closure_defaults(plan_payload)
    )
    view = memoryview(metadata_payload)
    _effective_uid, _effective_gid, flags, _close_locator, _close_generation = (
        _SESSION_NUMERIC.unpack_from(view)
    )
    offset = _SESSION_NUMERIC.size
    logon_id = ""
    principal = ""
    for index in range(6):
        if index == 0:
            logon_id, offset = _read_compact_text(view, offset)
        elif index == 2:
            principal, offset = _read_compact_text(view, offset)
        else:
            offset = _skip_compact_text(view, offset)
    conditional: list[str] = []
    defaults = (zeek_uid, hostname, client_ip, stable_id)
    for index, (bit, default) in enumerate(zip((1, 2, 4, 8), defaults, strict=True)):
        if flags & bit:
            conditional.append(default)
        elif index in {1, 3}:
            value, offset = _read_compact_text(view, offset)
            conditional.append(value)
        else:
            offset = _skip_compact_text(view, offset)
            conditional.append(default)
    return logon_id, principal, conditional[1], conditional[3], started_at, closed_at


def _unpack_close_token(record: _SmbSessionRecord) -> ApplicationChannelCloseToken:
    """Return the compact common-registry close token stored with one sidecar."""

    _effective_uid, _effective_gid, _flags, locator, generation = _SESSION_NUMERIC.unpack_from(
        record.metadata_payload
    )
    return ApplicationChannelCloseToken(locator=locator, generation=generation)


def _pack_tree(share_ref: str, connected_at: datetime) -> bytes:
    buffer = bytearray(_TREE_NUMERIC.pack(_datetime_us(connected_at)))
    _append_text(buffer, share_ref)
    return bytes(buffer)


def _unpack_tree(payload: bytes) -> tuple[str, datetime]:
    view = memoryview(payload)
    (connected_us,) = _TREE_NUMERIC.unpack_from(view)
    share_ref, _ = _read_text(view, _TREE_NUMERIC.size)
    return share_ref, _datetime_from_us(connected_us)


def _pack_handle(handle: SmbHandleView) -> bytes:
    access_code = {"read": 1, "write": 2}.get(handle.access, 0)
    buffer = bytearray(
        _HANDLE_NUMERIC.pack(
            handle.content_version,
            _datetime_us(handle.opened_at),
            handle.deny_write,
            access_code,
        )
    )
    for value, prefix in (
        (handle.handle_id, "smb-handle-"),
        (handle.tree_id, "smb-tree-"),
        (handle.operation_id, "smb-operation-"),
    ):
        suffix = value.removeprefix(prefix)
        if len(suffix) != 32:
            raise StateError(f"Invalid compact SMB semantic ID {value!r}")
        try:
            buffer.extend(bytes.fromhex(suffix))
        except ValueError as exc:
            raise StateError(f"Invalid compact SMB semantic ID {value!r}") from exc
    _append_text(buffer, handle.file_id)
    if not access_code:
        _append_text(buffer, handle.access)
    return bytes(buffer)


def _unpack_handle(payload: bytes, channel_id: str) -> SmbHandleView:
    view = memoryview(payload)
    version, opened_us, deny_write, access_code = _HANDLE_NUMERIC.unpack_from(view)
    offset = _HANDLE_NUMERIC.size
    semantic_ids: list[str] = []
    for prefix in ("smb-handle-", "smb-tree-", "smb-operation-"):
        stop = offset + 16
        semantic_ids.append(f"{prefix}{bytes(view[offset:stop]).hex()}")
        offset = stop
    file_id, offset = _read_text(view, offset)
    if access_code:
        access = {1: "read", 2: "write"}.get(access_code)
        if access is None:  # pragma: no cover - protected by internal encoder
            raise StateError("Corrupt compact SMB access code")
    else:
        access, offset = _read_text(view, offset)
    return SmbHandleView(
        handle_id=semantic_ids[0],
        channel_id=channel_id,
        tree_id=semantic_ids[1],
        operation_id=semantic_ids[2],
        file_id=file_id,
        content_version=version,
        access=access,
        opened_at=_datetime_from_us(opened_us),
        deny_write=deny_write,
    )


@dataclass(slots=True)
class _SmbSessionRecord:
    """Compact hot sidecar; rich immutable public values are reconstructed on demand."""

    affinity_key: bytes
    plan_payload: bytes
    metadata_payload: bytes
    sensor_observations: tuple[NetworkSensorObservation, ...]
    first_tree: bytes | None = None
    additional_trees: dict[str, bytes] | None = None
    first_handle: bytes | None = None
    additional_handles: dict[str, bytes] | None = None
    tree_count: int = 0
    handle_count: int = 0


def _estimated_record_bytes(record: _SmbSessionRecord) -> int:
    total = (
        sys.getsizeof(record)
        + sys.getsizeof(record.affinity_key)
        + sys.getsizeof(record.plan_payload)
        + sys.getsizeof(record.metadata_payload)
        + sys.getsizeof(record.sensor_observations)
        + sum(sys.getsizeof(value) for value in record.sensor_observations)
    )
    if record.first_tree is not None:
        total += sys.getsizeof(record.first_tree)
    if record.additional_trees is not None:
        total += sys.getsizeof(record.additional_trees) + sum(
            sys.getsizeof(key) + sys.getsizeof(value)
            for key, value in record.additional_trees.items()
        )
    if record.first_handle is not None:
        total += sys.getsizeof(record.first_handle)
    if record.additional_handles is not None:
        total += sys.getsizeof(record.additional_handles) + sum(
            sys.getsizeof(key) + sys.getsizeof(value)
            for key, value in record.additional_handles.items()
        )
    return total


def _estimated_session_view_bytes(session: SmbSessionView) -> int:
    plan = session.transport_plan
    values: list[object] = [
        session,
        plan,
        plan.phase_times,
        plan.traffic,
        plan.traffic.orig,
        plan.traffic.resp,
        session.sensor_observations,
    ]
    values.extend(value for item in plan.phase_times for value in item)
    values.extend(session.sensor_observations)
    values.extend(
        value
        for value in (
            session.channel_id,
            session.session_id,
            session.affinity_digest,
            plan.stable_id,
            plan.hostname,
            plan.src_ip,
            plan.dst_ip,
            plan.zeek_uid,
            plan.conn_id,
            session.ground_truth_transport_uid,
            session.logon_id,
            session.auth_session_ref,
            session.principal,
            session.server_hostname,
            session.client_ip,
            session.lifecycle_group_id,
        )
    )
    return sum(sys.getsizeof(value) for value in values)


@dataclass(slots=True)
class _SmbShard:
    """Open-only SMB protocol state for one stable owner partition."""

    shard_id: int
    lock: RLock = field(default_factory=RLock)
    sessions: CompactIndexedStore[bytes, _SmbSessionRecord] = field(
        default_factory=lambda: CompactIndexedStore(
            track_lookup_candidates=True,
            affinity=lambda item: item.affinity_key,
        )
    )
    expiry: PackedHandleExpiryIndex = field(default_factory=PackedHandleExpiryIndex)
    estimated_value_bytes: int = 0
    open_trees: int = 0
    open_handles: int = 0
    maximum_trees_per_session: int = 0
    maximum_handles_per_operation: int = 0
    snapshot_cache: OrderedDict[bytes, SmbSessionView] = field(default_factory=OrderedDict)
    exact_lookup_candidates_inspected: int = 0
    deletions: int = 0


class SmbApplicationChannelManager:
    """Own bounded reusable SMB sessions, trees, handles, and operation spans."""

    def __init__(
        self,
        *,
        application_registry: ApplicationChannelRegistry,
        window_start: datetime,
        window_end: datetime,
    ) -> None:
        """Create an empty manager for one canonical generation window."""

        self._window_start = ensure_utc(window_start)
        self._window_end = ensure_utc(window_end)
        registry_window_start = getattr(application_registry, "window_start", None)
        registry_window_end = getattr(application_registry, "window_end", None)
        if registry_window_start != self._window_start or registry_window_end != self._window_end:
            raise ValueError("SMB and shared application-channel windows must match exactly")
        self._registry = application_registry
        self._shards: dict[int, _SmbShard] = {}
        self._directory_lock = RLock()
        self._gate = _SmbMutationGate()
        self._watermark_lane = Lock()
        self._compaction_cursor = 0
        self._exact_route_cache: OrderedDict[bytes, int] = OrderedDict()

    @property
    def application_registry(self) -> ApplicationChannelRegistry:
        """Return the injected engine-owned application-channel registry."""

        return self._registry

    def _shard(self, owner_id: str, *, create: bool) -> _SmbShard | None:
        shard_id = self._registry.owner_partition_id(owner_id)
        shard = self._shards.get(shard_id)
        if shard is not None or not create:
            return shard
        with self._directory_lock:
            shard = self._shards.get(shard_id)
            if shard is None:
                shard = _SmbShard(shard_id=shard_id)
                self._shards[shard_id] = shard
            return shard

    @staticmethod
    def _channel_id(affinity: SmbChannelAffinity, transport_id: str) -> str:
        channel_key = _semantic_string_digest_two(
            _SMB_CHANNEL_NAMESPACE_JSON,
            affinity.digest,
            transport_id,
        )
        return f"smb-channel-{channel_key.hex()}"

    @staticmethod
    def _channel_id_and_key(
        affinity: SmbChannelAffinity,
        transport_id: str,
    ) -> tuple[str, bytes]:
        """Return one channel ID and its already-computed compact key."""

        channel_key = _semantic_string_digest_two(
            _SMB_CHANNEL_NAMESPACE_JSON,
            affinity.digest,
            transport_id,
        )
        return f"smb-channel-{channel_key.hex()}", channel_key

    @staticmethod
    def _channel_key(channel_id: str) -> bytes | None:
        suffix = channel_id.removeprefix("smb-channel-")
        if len(suffix) != 32:
            return None
        try:
            return bytes.fromhex(suffix)
        except ValueError:
            return None

    @staticmethod
    def _channel_id_from_key(channel_key: bytes) -> str:
        return f"smb-channel-{channel_key.hex()}"

    @staticmethod
    def _session_id(channel_id: str) -> str:
        token = _semantic_string_token_one(_SMB_SESSION_NAMESPACE_JSON, channel_id)
        return f"smb-session-{token}"

    @staticmethod
    def _tree_id(session_id: str, share_ref: str) -> str:
        token = _semantic_string_token_two(
            _SMB_TREE_NAMESPACE_JSON,
            session_id,
            share_ref.casefold(),
        )
        return f"smb-tree-{token}"

    @staticmethod
    def _operation_id(channel_id: str, semantic_operation_id: str) -> str:
        token = _semantic_string_token_two(
            _SMB_OPERATION_NAMESPACE_JSON,
            channel_id,
            semantic_operation_id,
        )
        return f"smb-operation-{token}"

    @staticmethod
    def _handle_id(
        *,
        operation_id: str,
        tree_id: str,
        file_id: str,
        content_version: int,
        access: str,
        role: str,
    ) -> str:
        token = _semantic_token(
            "smb-handle-v1",
            (operation_id, tree_id, file_id, content_version, access, role),
        )
        return f"smb-handle-{token}"

    @staticmethod
    def file_transfer_fuid(handle: SmbHandleView, phase: str) -> str:
        """Return a versioned source-native file-analysis identity."""

        return generate_stable_zeek_uid(
            "F",
            (
                f"{handle.handle_id}:{handle.file_id}:{handle.content_version}:"
                f"{phase}:{'orig' if phase == 'write' else 'resp'}"
            ),
        )

    def owner_partition_id(self, affinity: SmbChannelAffinity) -> int:
        """Return the stable owner partition for concurrency tests."""

        return self._registry.owner_partition_id(affinity.owner_id)

    def channel_id_for(self, affinity: SmbChannelAffinity, transport_id: str) -> str:
        """Return the exact deterministic channel ID for one immutable transport."""

        return self._channel_id(affinity, _required_text(transport_id, "transport_id"))

    @staticmethod
    def _affinity_key(affinity: SmbChannelAffinity) -> bytes:
        return affinity._digest_bytes

    def _record_locked(
        self,
        shard: _SmbShard,
        channel_id: str,
    ) -> _SmbSessionRecord | None:
        channel_key = self._channel_key(channel_id)
        return None if channel_key is None else shard.sessions.get(channel_key)

    def _remember_exact_route(self, channel_key: bytes, shard_id: int) -> None:
        with self._directory_lock:
            self._exact_route_cache[channel_key] = shard_id
            self._exact_route_cache.move_to_end(channel_key)
            if len(self._exact_route_cache) > _EXACT_ROUTE_CACHE_LIMIT:
                self._exact_route_cache.popitem(last=False)

    def _cached_exact_shard(self, channel_key: bytes) -> _SmbShard | None:
        with self._directory_lock:
            shard_id = self._exact_route_cache.get(channel_key)
            if shard_id is None:
                return None
            shard = self._shards.get(shard_id)
            if shard is None:
                self._exact_route_cache.pop(channel_key, None)
                return None
            self._exact_route_cache.move_to_end(channel_key)
            return shard

    def _session_view(self, channel_id: str, record: _SmbSessionRecord) -> SmbSessionView:
        plan = _unpack_network_plan(record.plan_payload)
        effective_uid, effective_gid, text = _unpack_session_metadata(
            record.metadata_payload,
            plan,
        )
        return SmbSessionView(
            channel_id=channel_id,
            session_id=self._session_id(channel_id),
            affinity_digest=record.affinity_key.hex(),
            transport_plan=plan,
            sensor_observations=record.sensor_observations,
            ground_truth_transport_uid=text[0],
            logon_id=text[1],
            auth_session_ref=text[2],
            principal=text[3],
            auth_protocol=text[4],
            account_scope=text[5],
            effective_uid=effective_uid,
            effective_gid=effective_gid,
            client_access=text[6],
            server_hostname=text[7],
            client_ip=text[8],
            lifecycle_group_id=text[9],
        )

    def _cached_session_view_locked(
        self,
        shard: _SmbShard,
        channel_key: bytes,
        record: _SmbSessionRecord,
    ) -> SmbSessionView:
        retained = shard.snapshot_cache.get(channel_key)
        if retained is not None:
            shard.snapshot_cache.move_to_end(channel_key)
            return retained
        view = self._session_view(self._channel_id_from_key(channel_key), record)
        shard.snapshot_cache[channel_key] = view
        if len(shard.snapshot_cache) > _SNAPSHOT_CACHE_PER_SHARD:
            shard.snapshot_cache.popitem(last=False)
        return view

    def _tree_view(
        self,
        channel_id: str,
        payload: bytes,
        *,
        known_session_id: str | None = None,
    ) -> SmbTreeView:
        share_ref, connected_at = _unpack_tree(payload)
        session_id = known_session_id or self._session_id(channel_id)
        return SmbTreeView(
            tree_id=self._tree_id(session_id, share_ref),
            channel_id=channel_id,
            session_id=session_id,
            share_ref=share_ref,
            connected_at=connected_at,
        )

    def _tree_locked(
        self,
        shard: _SmbShard,
        channel_id: str,
        record: _SmbSessionRecord,
        share_ref: str,
        connected_at: datetime,
        *,
        known_session_id: str | None = None,
    ) -> tuple[SmbTreeView, bool]:
        normalized_share = _required_text(share_ref, "share_ref").casefold()
        if record.first_tree is not None:
            first_share, _first_connected = _unpack_tree(record.first_tree)
            if first_share.casefold() == normalized_share:
                return self._tree_view(
                    channel_id,
                    record.first_tree,
                    known_session_id=known_session_id,
                ), False
        if record.additional_trees is not None:
            retained = record.additional_trees.get(normalized_share)
            if retained is not None:
                return self._tree_view(
                    channel_id,
                    retained,
                    known_session_id=known_session_id,
                ), False
        canonical_connected_at = ensure_utc(connected_at)
        payload = _pack_tree(share_ref, canonical_connected_at)
        if record.first_tree is None:
            record.first_tree = payload
            estimated_delta = sys.getsizeof(payload)
        else:
            before = _estimated_record_bytes(record)
            if record.additional_trees is None:
                record.additional_trees = {}
            record.additional_trees[normalized_share] = payload
            estimated_delta = _estimated_record_bytes(record) - before
        record.tree_count += 1
        shard.open_trees += 1
        shard.maximum_trees_per_session = max(
            shard.maximum_trees_per_session,
            record.tree_count,
        )
        shard.estimated_value_bytes += estimated_delta
        session_id = known_session_id or self._session_id(channel_id)
        return SmbTreeView(
            tree_id=self._tree_id(session_id, share_ref),
            channel_id=channel_id,
            session_id=session_id,
            share_ref=share_ref,
            connected_at=canonical_connected_at,
        ), True

    @staticmethod
    def _lease(
        session: SmbSessionView,
        tree: SmbTreeView,
        reservation: ApplicationOperationReservation,
        *,
        reused_session: bool,
        created_tree: bool,
        operation_completed: bool = False,
    ) -> SmbOperationLease:
        return SmbOperationLease(
            channel_id=session.channel_id,
            session_id=session.session_id,
            tree_id=tree.tree_id,
            operation_id=reservation.operation_id,
            ordinal=reservation.ordinal,
            started_at=reservation.started_at,
            ended_at=reservation.ended_at,
            transport_plan=session.transport_plan,
            sensor_observations=session.sensor_observations,
            ground_truth_transport_uid=session.ground_truth_transport_uid,
            logon_id=session.logon_id,
            auth_session_ref=session.auth_session_ref,
            principal=session.principal,
            auth_protocol=session.auth_protocol,
            account_scope=session.account_scope,
            effective_uid=session.effective_uid,
            effective_gid=session.effective_gid,
            client_access=session.client_access,
            lifecycle_group_id=session.lifecycle_group_id,
            reused_session=reused_session,
            created_tree=created_tree,
            operation_completed=operation_completed,
        )

    def open_session(
        self,
        affinity: SmbChannelAffinity,
        *,
        transport_plan: NetworkTransactionPlan,
        sensor_observations: tuple[NetworkSensorObservation, ...],
        ground_truth_transport_uid: str,
        logon_id: str,
        auth_session_ref: str,
        principal: str,
        auth_protocol: str,
        account_scope: str,
        effective_uid: int | None,
        effective_gid: int | None,
        client_access: str,
        server_hostname: str,
        client_ip: str,
        lifecycle_group_id: str,
        share_ref: str,
        semantic_operation_id: str,
        operation_started_at: datetime,
        operation_ended_at: datetime,
        operation_initiator_bytes: int,
        operation_responder_bytes: int,
        idle_timeout: timedelta,
        initiator_budget: int,
        responder_budget: int,
        operation_budget: int,
        operation_completes_immediately: bool = False,
        _trusted_canonical_inputs: bool = False,
    ) -> SmbOperationLease:
        """Register a fresh physical transport, session, tree, and first operation.

        When the caller already owns the immutable completion outcome, the
        immediate path reconciles the first operation during common-channel
        admission.  It never publishes an active operation row and therefore
        cannot subsequently own file handles.
        """

        if transport_plan.closed_at is None:
            raise StateError("Reusable SMB transports require an immutable close")
        if transport_plan.closed_at > self._window_end:
            raise StateError("SMB transport close must be inside the application window")
        channel_id, channel_key = self._channel_id_and_key(
            affinity,
            transport_plan.stable_id,
        )
        session_id = self._session_id(channel_id)
        canonical_observations = tuple(sensor_observations)
        if _trusted_canonical_inputs:
            canonical_ground_truth_uid = ground_truth_transport_uid
            canonical_logon_id = logon_id
            canonical_auth_session_ref = auth_session_ref
            canonical_principal = principal
            canonical_auth_protocol = auth_protocol
            canonical_account_scope = account_scope
            canonical_client_access = client_access
            canonical_server_hostname = server_hostname
            canonical_client_ip = client_ip
            canonical_lifecycle_group_id = lifecycle_group_id
        else:
            canonical_ground_truth_uid = _required_text(
                ground_truth_transport_uid,
                "ground_truth_transport_uid",
            )
            canonical_logon_id = _required_text(logon_id, "logon_id")
            canonical_auth_session_ref = _required_text(auth_session_ref, "auth_session_ref")
            canonical_principal = _required_text(principal, "principal")
            canonical_auth_protocol = _required_text(auth_protocol, "auth_protocol")
            canonical_account_scope = _required_text(account_scope, "account_scope")
            canonical_client_access = _required_text(client_access, "client_access")
            canonical_server_hostname = _required_text(server_hostname, "server_hostname")
            canonical_client_ip = _required_text(client_ip, "client_ip")
            canonical_lifecycle_group_id = _required_text(
                lifecycle_group_id,
                "lifecycle_group_id",
            )
        started_at = (
            operation_started_at
            if operation_started_at.tzinfo is UTC
            else ensure_utc(operation_started_at)
        )
        ended_at = (
            operation_ended_at
            if operation_ended_at.tzinfo is UTC
            else ensure_utc(operation_ended_at)
        )
        canonical_share_ref = (
            share_ref if _trusted_canonical_inputs else _required_text(share_ref, "share_ref")
        )
        tree_id = self._tree_id(session_id, canonical_share_ref)
        tree_payload = _pack_tree(canonical_share_ref, started_at)
        operation_id = self._operation_id(channel_id, semantic_operation_id)
        models_are_canonical = (
            transport_plan.stable_id == transport_plan.stable_id.strip()
            and transport_plan.started_at.tzinfo is UTC
            and transport_plan.closed_at.tzinfo is UTC
            and idle_timeout > timedelta(0)
            and initiator_budget >= 0
            and responder_budget >= 0
            and operation_budget > 0
            and operation_initiator_bytes >= 0
            and operation_responder_bytes >= 0
            and ended_at >= started_at
        )
        if models_are_canonical:
            budget = _new_channel_budget(
                initiator_budget,
                responder_budget,
                operation_budget,
            )
            binding = _new_transport_binding(
                transport_plan.stable_id,
                transport_plan.started_at,
                transport_plan.closed_at,
            )
            identity = _new_channel_identity(
                channel_id=channel_id,
                owner_id=affinity.owner_id,
                affinity_digest=affinity.digest,
                binding=binding,
                opened_at=transport_plan.started_at,
                idle_timeout=idle_timeout,
                hard_deadline=transport_plan.closed_at,
                budget=budget,
            )
            reservation = _new_initial_reservation(
                operation_id=operation_id,
                channel_id=channel_id,
                started_at=started_at,
                ended_at=ended_at,
                initiator_bytes=operation_initiator_bytes,
                responder_bytes=operation_responder_bytes,
            )
        else:
            identity = ApplicationChannelIdentity(
                channel_id=channel_id,
                protocol="smb",
                owner_id=affinity.owner_id,
                affinity_digest=affinity.digest,
                binding=ApplicationTransportBinding(
                    transport_id=transport_plan.stable_id,
                    opened_at=transport_plan.started_at,
                    closes_at=transport_plan.closed_at,
                ),
                opened_at=transport_plan.started_at,
                idle_timeout=idle_timeout,
                hard_deadline=transport_plan.closed_at,
                budget=ApplicationChannelBudget(
                    initiator_bytes=initiator_budget,
                    responder_bytes=responder_budget,
                    operations=operation_budget,
                ),
            )
            reservation = ApplicationOperationReservation(
                operation_id=operation_id,
                channel_id=channel_id,
                ordinal=0,
                started_at=started_at,
                ended_at=ended_at,
                initiator_bytes=operation_initiator_bytes,
                responder_bytes=operation_responder_bytes,
            )
        shard = self._shard(affinity.owner_id, create=True)
        assert shard is not None
        self._gate.enter_mutation()
        shard.lock.acquire()
        try:
            if operation_completes_immediately:
                updated, close_token = (
                    self._registry.open_channel_with_completed_operation_and_token(
                        identity,
                        reservation,
                        trusted_owner_partition_id=shard.shard_id,
                    )
                )
            else:
                _opened, close_token = self._registry.open_channel_with_token(identity)
                try:
                    updated = self._registry.reserve_operation(reservation)
                except (StateError, ValueError):
                    self._registry.close_channel(
                        channel_id,
                        closed_at=transport_plan.started_at,
                        reason="initial reservation failed",
                    )
                    raise
            record = _SmbSessionRecord(
                affinity_key=self._affinity_key(affinity),
                plan_payload=_pack_network_plan(transport_plan),
                metadata_payload=_pack_session_metadata_values(
                    plan=transport_plan,
                    close_token=close_token,
                    ground_truth_transport_uid=canonical_ground_truth_uid,
                    logon_id=canonical_logon_id,
                    auth_session_ref=canonical_auth_session_ref,
                    principal=canonical_principal,
                    auth_protocol=canonical_auth_protocol,
                    account_scope=canonical_account_scope,
                    effective_uid=effective_uid,
                    effective_gid=effective_gid,
                    client_access=canonical_client_access,
                    server_hostname=canonical_server_hostname,
                    client_ip=canonical_client_ip,
                    lifecycle_group_id=canonical_lifecycle_group_id,
                ),
                sensor_observations=canonical_observations,
                first_tree=tree_payload,
                tree_count=1,
            )
            shard.sessions[channel_key] = record
            shard.estimated_value_bytes += _estimated_record_bytes(record)
            shard.open_trees += 1
            shard.maximum_trees_per_session = max(shard.maximum_trees_per_session, 1)
            session_handle = shard.sessions.handle_for(channel_key)
            shard.expiry.set(
                session_handle,
                min(
                    updated.idle_deadline,
                    updated.identity.hard_deadline,
                    updated.identity.binding.closes_at,
                ).timestamp(),
            )
            return SmbOperationLease(
                channel_id=channel_id,
                session_id=session_id,
                tree_id=tree_id,
                operation_id=reservation.operation_id,
                ordinal=reservation.ordinal,
                started_at=reservation.started_at,
                ended_at=reservation.ended_at,
                transport_plan=transport_plan,
                sensor_observations=canonical_observations,
                ground_truth_transport_uid=canonical_ground_truth_uid,
                logon_id=canonical_logon_id,
                auth_session_ref=canonical_auth_session_ref,
                principal=canonical_principal,
                auth_protocol=canonical_auth_protocol,
                account_scope=canonical_account_scope,
                effective_uid=effective_uid,
                effective_gid=effective_gid,
                client_access=canonical_client_access,
                lifecycle_group_id=canonical_lifecycle_group_id,
                reused_session=False,
                created_tree=True,
                operation_completed=operation_completes_immediately,
            )
        finally:
            shard.lock.release()
            self._gate.exit_mutation()

    def reserve_reuse(
        self,
        affinity: SmbChannelAffinity,
        *,
        share_ref: str,
        semantic_operation_id: str,
        requested_at: datetime,
        required_until: datetime,
        initiator_bytes: int,
        responder_bytes: int,
    ) -> SmbReuseResult:
        """Reserve one exact compatible SMB operation without scanning other sessions."""

        canonical_start = ensure_utc(requested_at)
        canonical_end = ensure_utc(required_until)
        if canonical_end < canonical_start:
            raise ValueError("SMB required_until must not precede requested_at")
        if initiator_bytes < 0 or responder_bytes < 0:
            raise ValueError("SMB operation byte reservations must be non-negative")
        shard = self._shard(affinity.owner_id, create=False)
        if shard is None:
            return SmbReuseResult(lease=None)
        with self._gate.mutation(), shard.lock:
            channel_key = next(
                shard.sessions.find_key_iter("affinity", self._affinity_key(affinity)),
                None,
            )
            if channel_key is None:
                return SmbReuseResult(lease=None)
            record = shard.sessions[channel_key]
            session = self._cached_session_view_locked(shard, channel_key, record)
            snapshot = self._registry.get(session.channel_id)
            if snapshot is None or not snapshot.is_open:
                closure = self._discard_session_locked(shard, session, reason="not reusable")
                return SmbReuseResult(lease=None, closures=(closure,))
            ordered_start = max(canonical_start, snapshot.last_activity_at + _ORDERING_GAP)
            ordered_end = ordered_start + (canonical_end - canonical_start)
            effective_deadline = min(
                snapshot.idle_deadline,
                snapshot.identity.hard_deadline,
                snapshot.identity.binding.closes_at,
            )
            if ordered_start >= effective_deadline or ordered_end > snapshot.identity.hard_deadline:
                closure = self._retire_locked(
                    shard,
                    session,
                    at=min(effective_deadline, snapshot.identity.binding.closes_at),
                    reason="operation span",
                )
                return SmbReuseResult(lease=None, closures=(closure,))
            budget = snapshot.identity.budget
            fits = (
                snapshot.reserved_initiator_bytes + initiator_bytes <= budget.initiator_bytes
                and snapshot.reserved_responder_bytes + responder_bytes <= budget.responder_bytes
                and snapshot.reserved_operations + 1 <= budget.operations
            )
            if not fits:
                closure = self._retire_locked(
                    shard,
                    session,
                    at=max(canonical_start, snapshot.last_activity_at),
                    reason="capacity",
                )
                return SmbReuseResult(lease=None, closures=(closure,))
            reusable = self._registry.find_reusable(
                affinity_digest=affinity.digest,
                owner_id=affinity.owner_id,
                at=max(canonical_start, session.transport_plan.started_at),
            )
            if reusable is None or reusable.channel_id != session.channel_id:
                closure = self._retire_locked(
                    shard,
                    session,
                    at=max(canonical_start, snapshot.last_activity_at),
                    reason="not reusable",
                )
                return SmbReuseResult(lease=None, closures=(closure,))
            reservation = ApplicationOperationReservation(
                operation_id=self._operation_id(session.channel_id, semantic_operation_id),
                channel_id=session.channel_id,
                ordinal=snapshot.reserved_operations,
                started_at=ordered_start,
                ended_at=ordered_end,
                initiator_bytes=initiator_bytes,
                responder_bytes=responder_bytes,
            )
            updated = self._registry.reserve_operation(reservation)
            tree, created_tree = self._tree_locked(
                shard,
                session.channel_id,
                record,
                share_ref,
                ordered_start,
            )
            session_handle = shard.sessions.handle_for(channel_key)
            shard.expiry.set(
                session_handle,
                min(
                    updated.idle_deadline,
                    updated.identity.hard_deadline,
                    updated.identity.binding.closes_at,
                ).timestamp(),
            )
            return SmbReuseResult(
                lease=self._lease(
                    session,
                    tree,
                    reservation,
                    reused_session=True,
                    created_tree=created_tree,
                )
            )

    def find_reusable_session(
        self,
        affinity: SmbChannelAffinity,
        *,
        at: datetime,
    ) -> SmbSessionView | None:
        """Return one exact reusable session without reserving or materializing a bucket."""

        canonical_time = ensure_utc(at)
        shard = self._shard(affinity.owner_id, create=False)
        if shard is None:
            return None
        with shard.lock:
            channel_key = next(
                shard.sessions.find_key_iter("affinity", self._affinity_key(affinity)),
                None,
            )
            if channel_key is None:
                return None
            record = shard.sessions[channel_key]
            session = self._cached_session_view_locked(shard, channel_key, record)
            reusable = self._registry.find_reusable(
                affinity_digest=affinity.digest,
                owner_id=affinity.owner_id,
                at=max(canonical_time, session.transport_plan.started_at),
            )
            if reusable is None or reusable.channel_id != session.channel_id:
                return None
            return session

    @staticmethod
    def _iter_handle_payloads(record: _SmbSessionRecord) -> Iterator[bytes]:
        if record.first_handle is not None:
            yield record.first_handle
        if record.additional_handles is not None:
            yield from record.additional_handles.values()

    @staticmethod
    def _find_handle_payload(record: _SmbSessionRecord, handle_id: str) -> bytes | None:
        if record.first_handle is not None:
            first = _unpack_handle(record.first_handle, "")
            if first.handle_id == handle_id:
                return record.first_handle
        if record.additional_handles is None:
            return None
        return record.additional_handles.get(handle_id)

    @staticmethod
    def _store_handle_payload(record: _SmbSessionRecord, handle: SmbHandleView) -> None:
        payload = _pack_handle(handle)
        if record.first_handle is None:
            record.first_handle = payload
        else:
            if record.additional_handles is None:
                record.additional_handles = {}
            record.additional_handles[handle.handle_id] = payload
        record.handle_count += 1

    @staticmethod
    def _remove_handle_payload(record: _SmbSessionRecord, handle_id: str) -> bool:
        if record.first_handle is not None:
            first = _unpack_handle(record.first_handle, "")
            if first.handle_id == handle_id:
                record.first_handle = None
                if record.additional_handles:
                    replacement_id = next(iter(record.additional_handles))
                    record.first_handle = record.additional_handles.pop(replacement_id)
                    if not record.additional_handles:
                        record.additional_handles = None
                record.handle_count -= 1
                return True
        if record.additional_handles is None:
            return False
        removed = record.additional_handles.pop(handle_id, None)
        if removed is None:
            return False
        if not record.additional_handles:
            record.additional_handles = None
        record.handle_count -= 1
        return True

    def open_handle(
        self,
        lease: SmbOperationLease,
        *,
        file_id: str,
        content_version: int,
        access: str,
        opened_at: datetime,
        deny_write: bool = False,
        role: str = "operation",
    ) -> SmbHandleView:
        """Open one versioned handle inside an active operation."""

        if content_version <= 0:
            raise ValueError("SMB handle content_version must be positive")
        if lease.operation_completed:
            raise StateError(f"SMB operation {lease.operation_id!r} was completed during admission")
        snapshot = self._registry.get(lease.channel_id)
        if snapshot is None:
            raise StateError(f"Unknown SMB channel {lease.channel_id!r}")
        shard = self._shard(snapshot.identity.owner_id, create=False)
        if shard is None:
            raise StateError(f"Unknown SMB channel {lease.channel_id!r}")
        with self._gate.mutation(), shard.lock:
            record = self._record_locked(shard, lease.channel_id)
            if record is None:
                raise StateError(f"SMB channel {lease.channel_id!r} is not open")
            canonical_open = ensure_utc(opened_at)
            if canonical_open < lease.started_at or canonical_open > lease.ended_at:
                raise StateError(
                    f"SMB handle open {canonical_open.isoformat()} is outside operation "
                    f"{lease.operation_id!r}"
                )
            normalized_file = _required_text(file_id, "file_id")
            normalized_access = _required_text(access, "access").casefold()
            if normalized_access == "write":
                for payload in self._iter_handle_payloads(record):
                    candidate = _unpack_handle(payload, lease.channel_id)
                    if candidate.file_id == normalized_file and candidate.deny_write:
                        raise StateError(f"SMB file {normalized_file!r} denies write sharing")
            handle = SmbHandleView(
                handle_id=self._handle_id(
                    operation_id=lease.operation_id,
                    tree_id=lease.tree_id,
                    file_id=normalized_file,
                    content_version=content_version,
                    access=normalized_access,
                    role=role,
                ),
                channel_id=lease.channel_id,
                tree_id=lease.tree_id,
                operation_id=lease.operation_id,
                file_id=normalized_file,
                content_version=content_version,
                access=normalized_access,
                opened_at=canonical_open,
                deny_write=deny_write,
            )
            if self._find_handle_payload(record, handle.handle_id) is not None:
                raise StateError(f"Duplicate active SMB handle {handle.handle_id!r}")
            before = _estimated_record_bytes(record)
            self._store_handle_payload(record, handle)
            shard.open_handles += 1
            operation_handles = sum(
                1
                for payload in self._iter_handle_payloads(record)
                if _unpack_handle(payload, lease.channel_id).operation_id == lease.operation_id
            )
            shard.maximum_handles_per_operation = max(
                shard.maximum_handles_per_operation,
                operation_handles,
            )
            shard.estimated_value_bytes += _estimated_record_bytes(record) - before
            return handle

    def close_handle(
        self,
        handle: SmbHandleView,
        lease: SmbOperationLease,
        *,
        closed_at: datetime,
    ) -> bool:
        """Close and evict one active handle idempotently."""

        if handle.operation_id != lease.operation_id or handle.channel_id != lease.channel_id:
            raise StateError("SMB handle close lease does not own the exact handle operation")
        canonical_close = ensure_utc(closed_at)
        if canonical_close < handle.opened_at or canonical_close > lease.ended_at:
            raise StateError(
                f"SMB handle close {canonical_close.isoformat()} is outside operation "
                f"{lease.operation_id!r}"
            )
        snapshot = self._registry.get(handle.channel_id)
        if snapshot is None:
            return False
        shard = self._shard(snapshot.identity.owner_id, create=False)
        if shard is None:
            return False
        with self._gate.mutation(), shard.lock:
            record = self._record_locked(shard, handle.channel_id)
            if record is None:
                return False
            retained = self._find_handle_payload(record, handle.handle_id)
            if retained is None:
                return False
            current = _unpack_handle(retained, handle.channel_id)
            if current != handle:
                raise StateError("SMB handle close does not match retained immutable identity")
            before = _estimated_record_bytes(record)
            if not self._remove_handle_payload(record, handle.handle_id):  # pragma: no cover
                return False
            shard.open_handles -= 1
            shard.deletions += 1
            shard.estimated_value_bytes += _estimated_record_bytes(record) - before
            return True

    def has_write_conflict(self, lease: SmbOperationLease, file_id: str) -> bool:
        """Return whether an exact channel/file bucket contains a deny-write handle."""

        snapshot = self._registry.get(lease.channel_id)
        if snapshot is None:
            return False
        shard = self._shard(snapshot.identity.owner_id, create=False)
        if shard is None:
            return False
        with shard.lock:
            record = self._record_locked(shard, lease.channel_id)
            if record is None:
                return False
            return any(
                handle.file_id == file_id and handle.deny_write
                for handle in (
                    _unpack_handle(payload, lease.channel_id)
                    for payload in self._iter_handle_payloads(record)
                )
            )

    def finalize_operation(self, lease: SmbOperationLease) -> bool:
        """Finalize an operation after proving it owns no active handles."""

        if lease.operation_completed:
            return False
        snapshot = self._registry.get(lease.channel_id)
        if snapshot is None:
            return False
        shard = self._shard(snapshot.identity.owner_id, create=False)
        if shard is None:
            return False
        with shard.lock:
            record = self._record_locked(shard, lease.channel_id)
            if record is None:
                return False
            if any(
                _unpack_handle(payload, lease.channel_id).operation_id == lease.operation_id
                for payload in self._iter_handle_payloads(record)
            ):
                raise StateError(
                    f"SMB operation {lease.operation_id!r} cannot finalize with active handles"
                )
        return self._registry.finalize_operation(lease.operation_id)

    @staticmethod
    def _closure(
        session: SmbSessionView,
        *,
        closed_at: datetime,
        reason: str,
    ) -> SmbChannelClosure:
        return SmbChannelClosure(
            channel_id=session.channel_id,
            session_id=session.session_id,
            logon_id=session.logon_id,
            principal=session.principal,
            server_hostname=session.server_hostname,
            lifecycle_group_id=session.lifecycle_group_id,
            closed_at=closed_at,
            reason=reason,
        )

    def _discard_session_locked(
        self,
        shard: _SmbShard,
        session: SmbSessionView,
        *,
        reason: str,
    ) -> SmbChannelClosure:
        snapshot = self._registry.get(session.channel_id)
        closed_at = (
            snapshot.closed_at
            if snapshot is not None and snapshot.closed_at is not None
            else session.transport_plan.closed_at or session.transport_plan.started_at
        )
        channel_key = self._channel_key(session.channel_id)
        record = None if channel_key is None else shard.sessions.get(channel_key)
        if record is not None:
            assert channel_key is not None
            session_handle = shard.sessions.handle_for(channel_key)
            shard.expiry.pop(session_handle, None)
            del shard.sessions[channel_key]
            shard.snapshot_cache.pop(channel_key, None)
            with self._directory_lock:
                self._exact_route_cache.pop(channel_key, None)
            shard.open_trees -= record.tree_count
            shard.open_handles -= record.handle_count
            shard.deletions += 1 + record.tree_count + record.handle_count
            shard.estimated_value_bytes -= _estimated_record_bytes(record)
        return self._closure(session, closed_at=closed_at, reason=reason)

    def _retire_locked(
        self,
        shard: _SmbShard,
        session: SmbSessionView,
        *,
        at: datetime,
        reason: str,
    ) -> SmbChannelClosure:
        snapshot = self._registry.get(session.channel_id)
        close_time = ensure_utc(at)
        if snapshot is not None and snapshot.is_open:
            effective_deadline = min(
                snapshot.idle_deadline,
                snapshot.identity.hard_deadline,
                snapshot.identity.binding.closes_at,
            )
            close_time = min(
                effective_deadline,
                max(close_time, snapshot.identity.opened_at, snapshot.last_activity_at),
            )
            self._registry.close_channel(
                session.channel_id,
                closed_at=close_time,
                reason=reason,
            )
        closure = self._discard_session_locked(shard, session, reason=reason)
        return SmbChannelClosure(
            channel_id=closure.channel_id,
            session_id=closure.session_id,
            logon_id=closure.logon_id,
            principal=closure.principal,
            server_hostname=closure.server_hostname,
            lifecycle_group_id=closure.lifecycle_group_id,
            closed_at=close_time,
            reason=reason,
        )

    def _retire_record_locked(
        self,
        shard: _SmbShard,
        channel_key: bytes,
        record: _SmbSessionRecord,
    ) -> None:
        """Evict one closed packed record without reconstructing a public closure."""

        session_handle = shard.sessions.handle_for(channel_key)
        shard.expiry.pop(session_handle, None)
        del shard.sessions[channel_key]
        shard.snapshot_cache.pop(channel_key, None)
        with self._directory_lock:
            self._exact_route_cache.pop(channel_key, None)
        shard.open_trees -= record.tree_count
        shard.open_handles -= record.handle_count
        shard.deletions += 1 + record.tree_count + record.handle_count
        shard.estimated_value_bytes -= _estimated_record_bytes(record)

    def close_session(
        self,
        channel_id: str,
        *,
        closed_at: datetime,
        reason: str,
    ) -> SmbChannelClosure | None:
        """Close one session idempotently and return its source-close intent."""

        snapshot = self._registry.get(channel_id)
        if snapshot is None:
            return None
        shard = self._shard(snapshot.identity.owner_id, create=False)
        if shard is None:
            return None
        with self._gate.mutation(), shard.lock:
            channel_key = self._channel_key(channel_id)
            record = None if channel_key is None else shard.sessions.get(channel_key)
            if record is None:
                return None
            assert channel_key is not None
            session = self._cached_session_view_locked(shard, channel_key, record)
            return self._retire_locked(
                shard,
                session,
                at=closed_at,
                reason=reason,
            )

    def session_view(self, channel_id: str) -> SmbSessionView | None:
        """Return one immutable open sidecar through exact routing."""

        channel_key = self._channel_key(channel_id)
        if channel_key is None:
            return None
        shard = self._cached_exact_shard(channel_key)
        if shard is not None:
            with shard.lock:
                retained = shard.snapshot_cache.get(channel_key)
                if retained is not None:
                    shard.snapshot_cache.move_to_end(channel_key)
                    shard.exact_lookup_candidates_inspected += 1
                    return retained
                record = shard.sessions.get(channel_key)
                if record is not None:
                    shard.exact_lookup_candidates_inspected += 1
                    return self._cached_session_view_locked(shard, channel_key, record)
        snapshot = self._registry.get(channel_id)
        if snapshot is None:
            return None
        shard = self._shard(snapshot.identity.owner_id, create=False)
        if shard is None:
            return None
        with shard.lock:
            record = shard.sessions.get(channel_key)
            if record is None:
                return None
            shard.exact_lookup_candidates_inspected += 1
            result = self._cached_session_view_locked(shard, channel_key, record)
        self._remember_exact_route(channel_key, shard.shard_id)
        return result

    def channel_snapshot(self, channel_id: str) -> ApplicationChannelSnapshot | None:
        """Return the common frozen channel snapshot for diagnostics."""

        return self._registry.get(channel_id)

    def _compact_sidecars(self, max_work: int) -> None:
        if max_work <= 0:
            return
        with self._directory_lock:
            shards = tuple(sorted(self._shards.values(), key=lambda item: item.shard_id))
        if not shards:
            return
        remaining = max_work
        visited = 0
        while visited < len(shards) and remaining > 0:
            position = self._compaction_cursor % len(shards)
            shard = shards[position]
            visited += 1
            with shard.lock:
                metrics = shard.sessions.metrics()
                work = shard.sessions.compact_primary(
                    max_slots=remaining,
                    force=(shard.deletions > 0 and metrics.live_entries == 0),
                )
                remaining -= work
                if remaining > 0:
                    remaining -= shard.expiry.compact(max_slots=remaining)
                if not shard.sessions.metrics().primary_compaction_pending:
                    shard.deletions = 0
            self._compaction_cursor = (position + 1) % len(shards)

    def watermark(
        self,
        at: datetime,
        *,
        limit: int = _PRIMARY_COMPACTION_WORK_PER_WATERMARK,
    ) -> SmbWatermarkResult:
        """Close one bounded page of due sessions at a canonical frontier.

        Callers drain pages until ``has_more`` is false, render every returned
        closure outside this manager, and only then advance the injected shared
        application registry at the same cutoff.
        """

        canonical_time = ensure_utc(at)
        if limit <= 0:
            raise ValueError("SMB watermark page limit must be positive")
        closure_channel_keys: list[bytes] = []
        closure_plan_payloads: list[bytes] = []
        closure_metadata_payloads: list[bytes] = []
        closure_closed_at_us: list[int] = []
        has_more = False
        with self._watermark_lane:
            with self._gate.watermark():
                cutoff = canonical_time.timestamp()
                with self._directory_lock:
                    shards = tuple(sorted(self._shards.values(), key=lambda item: item.shard_id))
                due_records: list[tuple[_SmbShard, int, bytes, _SmbSessionRecord, float]] = []
                remaining = limit
                for shard in shards:
                    if remaining <= 0:
                        break
                    with shard.lock:
                        due = shard.expiry.expire_before_page(
                            cutoff,
                            inclusive=True,
                            limit=remaining,
                        )
                        remaining -= len(due)
                        for session_handle, deadline in due:
                            try:
                                record = shard.sessions.get_by_handle(session_handle)
                                channel_key = shard.sessions.key_by_handle(session_handle)
                            except KeyError:
                                continue
                            due_records.append(
                                (shard, session_handle, channel_key, record, deadline)
                            )
                requests = tuple(
                    ApplicationChannelCloseRequest(
                        channel_id=self._channel_id_from_key(channel_key),
                        token=_unpack_close_token(record),
                        closed_at=datetime.fromtimestamp(deadline, tz=canonical_time.tzinfo),
                        reason="deadline",
                    )
                    for _shard, _handle, channel_key, record, deadline in due_records
                )
                try:
                    results = self._registry.close_channels_by_token(
                        requests,
                        limit=limit,
                    )
                except (StateError, ValueError):
                    # A prior request in the common page may already have closed. Restore
                    # every sidecar deadline so a retry can observe its authoritative result
                    # without leaking the still-open remainder.
                    for shard, session_handle, _key, _record, deadline in due_records:
                        with shard.lock:
                            shard.expiry.set(session_handle, deadline)
                    raise
                for (
                    shard,
                    _session_handle,
                    channel_key,
                    record,
                    _deadline,
                ), result in zip(due_records, results, strict=True):
                    with shard.lock:
                        self._retire_record_locked(shard, channel_key, record)
                    closure_channel_keys.append(channel_key)
                    closure_plan_payloads.append(record.plan_payload)
                    closure_metadata_payloads.append(record.metadata_payload)
                    closure_closed_at_us.append(_datetime_us(result.closed_at))
                has_more = any(
                    shard.expiry.first_due_before(cutoff, inclusive=True) is not None
                    for shard in shards
                )
                with self._directory_lock:
                    self._shards = {
                        shard_id: shard
                        for shard_id, shard in self._shards.items()
                        if shard.sessions or shard.expiry
                    }
            self._compact_sidecars(_PRIMARY_COMPACTION_WORK_PER_WATERMARK)
        return SmbWatermarkResult(
            census=self.census(),
            closures=SmbClosurePage(
                channel_keys=tuple(closure_channel_keys),
                plan_payloads=tuple(closure_plan_payloads),
                metadata_payloads=tuple(closure_metadata_payloads),
                closed_at_us=tuple(closure_closed_at_us),
            ),
            has_more=has_more,
        )

    def census(self) -> SmbChannelCensus:
        """Return constant-time state, memory, and amplification metrics."""

        with self._directory_lock:
            shards = tuple(self._shards.values())
            route_index_bytes = sys.getsizeof(self._exact_route_cache) + sum(
                sys.getsizeof(channel_key) + sys.getsizeof(shard_id)
                for channel_key, shard_id in self._exact_route_cache.items()
            )
        open_sessions = 0
        open_trees = 0
        open_handles = 0
        session_backing = 0
        tree_backing = 0
        handle_backing = 0
        stale_sidecars = 0
        expiry_entries = 0
        stale_expiry_entries = 0
        max_shard_load = 0
        maximum_trees = 0
        maximum_handles = 0
        lookup_candidates = 0
        estimated_values = 0
        estimated_indexes = route_index_bytes
        pending = 0
        rotations = 0
        compaction_work = 0
        compaction_seconds = 0.0
        for shard in shards:
            with shard.lock:
                session_metrics = shard.sessions.metrics(estimate_bytes=True)
                open_sessions += session_metrics.live_entries
                open_trees += shard.open_trees
                open_handles += shard.open_handles
                session_backing += session_metrics.backing_entries
                tree_backing += shard.open_trees
                handle_backing += shard.open_handles
                stale_sidecars += session_metrics.stale_entries
                expiry_metrics = shard.expiry.metrics(estimate_bytes=True)
                expiry_entries += expiry_metrics.backing_entries
                stale_expiry_entries += expiry_metrics.stale_entries
                max_shard_load = max(max_shard_load, session_metrics.live_entries)
                maximum_trees = max(maximum_trees, shard.maximum_trees_per_session)
                maximum_handles = max(maximum_handles, shard.maximum_handles_per_operation)
                lookup_candidates += (
                    session_metrics.lookup_candidates_inspected
                    + shard.exact_lookup_candidates_inspected
                )
                estimated_values += (
                    shard.estimated_value_bytes
                    + sys.getsizeof(shard.snapshot_cache)
                    + sum(
                        sys.getsizeof(channel_key) + _estimated_session_view_bytes(view)
                        for channel_key, view in shard.snapshot_cache.items()
                    )
                )
                estimated_indexes += (
                    session_metrics.estimated_bytes + expiry_metrics.estimated_bytes
                )
                pending += session_metrics.primary_compaction_pending
                rotations += session_metrics.primary_compaction_rotations
                compaction_work += session_metrics.primary_compaction_work
                compaction_seconds += session_metrics.primary_compaction_seconds
        application = self._registry.census()
        sidecar_estimated_bytes = estimated_values + estimated_indexes
        return SmbChannelCensus(
            open_sessions=open_sessions,
            open_trees=open_trees,
            open_handles=open_handles,
            session_backing_entries=session_backing,
            tree_backing_entries=tree_backing,
            handle_backing_entries=handle_backing,
            stale_sidecar_entries=stale_sidecars,
            expiry_entries=expiry_entries,
            stale_expiry_entries=stale_expiry_entries,
            shard_count=len(shards),
            max_shard_load=max_shard_load,
            maximum_trees_per_session=maximum_trees,
            maximum_handles_per_operation=maximum_handles,
            lookup_candidates_inspected=(
                lookup_candidates + application.lookup_candidates_inspected
            ),
            sidecar_lookup_candidates_inspected=lookup_candidates,
            sidecar_estimated_bytes=sidecar_estimated_bytes,
            sidecar_estimated_index_bytes=estimated_indexes,
            estimated_bytes=sidecar_estimated_bytes + application.estimated_bytes,
            estimated_index_bytes=estimated_indexes + application.estimated_index_bytes,
            primary_compaction_pending=pending,
            primary_compaction_rotations=rotations,
            primary_compaction_work=compaction_work,
            primary_compaction_seconds=compaction_seconds,
            application=application,
        )
