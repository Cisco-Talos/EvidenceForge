# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Bounded SMB session, tree, and handle state on shared application channels."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import struct
import sys
from collections import OrderedDict
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field, fields, replace
from datetime import UTC, datetime, timedelta
from json.encoder import encode_basestring
from threading import Condition, Lock, RLock
from typing import Literal, Self
from weakref import WeakValueDictionary

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
    FileSensorObservation,
    NatSensorObservation,
    NetworkSensorObservation,
    NetworkTrafficLedger,
    NetworkTransactionPlan,
    NetworkTuple,
)
from evidenceforge.generation.application_channels import (
    ApplicationChannelAdmissionReceipt,
    ApplicationChannelAdmissionResult,
    ApplicationChannelAdmissionToken,
    ApplicationChannelCloseRequest,
    ApplicationChannelCloseToken,
    ApplicationChannelPreparedCommit,
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
class SmbCompletedHandlePlan:
    """One file-handle lifetime completed inside a prepared SMB operation."""

    file_id: str
    content_version: int
    access: str
    opened_at: datetime
    closed_at: datetime
    deny_write: bool = False
    role: str = "operation"


@dataclass(frozen=True, slots=True)
class SmbCompletedOperationPlan:
    """One completed member of a prepared terminal SMB batch."""

    semantic_operation_id: str
    started_at: datetime
    ended_at: datetime
    initiator_bytes: int
    responder_bytes: int
    handles: tuple[SmbCompletedHandlePlan, ...] = ()


@dataclass(frozen=True, slots=True)
class SmbCompletedHandleView:
    """Canonical immutable identity for one handle born and closed in a batch."""

    handle_id: str
    channel_id: str
    tree_id: str
    operation_id: str
    file_id: str
    content_version: int
    access: str
    opened_at: datetime
    closed_at: datetime
    deny_write: bool
    role: str


@dataclass(frozen=True, slots=True)
class SmbCompletedOperationView:
    """Canonical immutable result for one completed batch operation."""

    operation_id: str
    ordinal: int
    started_at: datetime
    ended_at: datetime
    initiator_bytes: int
    responder_bytes: int
    handles: tuple[SmbCompletedHandleView, ...]


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
    _manager_id: str = field(default="", repr=False, compare=False)
    _integrity: str = field(default="", repr=False, compare=False)


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


@dataclass(frozen=True, slots=True)
class SmbClosedSessionBatch:
    """One terminal SMB session/tree and its completed operation members."""

    session: SmbSessionView
    tree: SmbTreeView
    operations: tuple[SmbCompletedOperationView, ...]
    closure: SmbChannelClosure


_SMB_ADMISSION_GRAPH_TYPES = frozenset(
    {
        SmbSessionView,
        SmbTreeView,
        SmbCompletedHandleView,
        SmbCompletedOperationView,
        SmbChannelClosure,
        SmbClosedSessionBatch,
        DirectionalTrafficLedger,
        NetworkTrafficLedger,
        NetworkTuple,
        NatSensorObservation,
        FileSensorObservation,
        NetworkSensorObservation,
        NetworkTransactionPlan,
    }
)
_SMB_ADMISSION_MAX_GRAPH_NODES = 65_536
_SMB_ADMISSION_MAX_SCALAR_BYTES = 16 * 1024 * 1024


def _append_smb_admission_scalar(buffer: bytearray, tag: bytes, payload: bytes) -> None:
    """Append one exactly typed length-framed scalar to an admission snapshot."""

    if len(payload) > _SMB_ADMISSION_MAX_SCALAR_BYTES:
        raise StateError("SMB admission scalar exceeds its exact byte bound")
    buffer.extend(tag)
    buffer.extend(len(payload).to_bytes(8, "big"))
    buffer.extend(payload)


def _smb_admission_graph_bytes(value: object) -> bytes:
    """Encode one bounded exact-type graph without invoking nested ``repr`` hooks."""

    buffer = bytearray()
    remaining_nodes = _SMB_ADMISSION_MAX_GRAPH_NODES

    def encode(item: object, *, depth: int) -> None:
        nonlocal remaining_nodes
        remaining_nodes -= 1
        if remaining_nodes < 0 or depth > 32:
            raise StateError("SMB admission graph exceeds its exact structural bound")
        item_type = type(item)
        if item is None:
            buffer.extend(b"n")
        elif item_type is bool:
            buffer.extend(b"b1" if item else b"b0")
        elif item_type is int:
            _append_smb_admission_scalar(buffer, b"i", str(item).encode("ascii"))
        elif item_type is float:
            _append_smb_admission_scalar(buffer, b"f", struct.pack("!d", item))
        elif item_type is str:
            _append_smb_admission_scalar(buffer, b"s", item.encode("utf-8"))
        elif item_type is bytes:
            _append_smb_admission_scalar(buffer, b"y", item)
        elif item_type is datetime:
            _append_smb_admission_scalar(
                buffer,
                b"d",
                item.isoformat(timespec="microseconds").encode("ascii"),
            )
        elif item_type is tuple:
            if len(item) > _SMB_ADMISSION_MAX_GRAPH_NODES:
                raise StateError("SMB admission tuple exceeds its exact member bound")
            buffer.extend(b"t")
            buffer.extend(len(item).to_bytes(8, "big"))
            for member in item:
                encode(member, depth=depth + 1)
        elif item_type is frozenset:
            if len(item) > 64 or any(type(member) is not str for member in item):
                raise StateError("SMB admission set has an invalid exact shape")
            encoded_members = tuple(sorted(member.encode("utf-8") for member in item))
            buffer.extend(b"r")
            buffer.extend(len(encoded_members).to_bytes(8, "big"))
            for member in encoded_members:
                _append_smb_admission_scalar(buffer, b"m", member)
        elif item_type in _SMB_ADMISSION_GRAPH_TYPES:
            _append_smb_admission_scalar(
                buffer,
                b"c",
                f"{item_type.__module__}.{item_type.__qualname__}".encode("ascii"),
            )
            declared_fields = fields(item_type)
            buffer.extend(len(declared_fields).to_bytes(8, "big"))
            for declared in declared_fields:
                _append_smb_admission_scalar(buffer, b"k", declared.name.encode("ascii"))
                encode(object.__getattribute__(item, declared.name), depth=depth + 1)
        else:
            raise StateError("SMB admission graph contains an unsupported or inexact nested type")
        if len(buffer) > _SMB_ADMISSION_MAX_SCALAR_BYTES:
            raise StateError("SMB admission graph exceeds its exact byte bound")

    encode(value, depth=0)
    return bytes(buffer)


def _smb_closed_session_batch_digest(result: SmbClosedSessionBatch) -> str:
    """Return a strict digest over one exact terminal SMB batch."""

    if (
        type(result) is not SmbClosedSessionBatch
        or type(result.operations) is not tuple
        or not 1 <= len(result.operations) <= 64
    ):
        raise StateError("SMB terminal sidecar result has an invalid exact shape")
    return hashlib.sha256(
        b"smb-channel-sidecar-result-v2\x00" + _smb_admission_graph_bytes(result)
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class SmbChannelAdmissionToken:
    """Opaque manager reservation for one terminal SMB/common-channel batch."""

    kind: Literal["fresh_completed_batch_close"]
    application_token: ApplicationChannelAdmissionToken = field(repr=False)
    result: SmbClosedSessionBatch
    _manager_token: int = field(repr=False, default=0)
    _reservation_id: int = field(repr=False, default=0)
    _integrity_token: str = field(repr=False, default="")

    @property
    def linearization_time(self) -> datetime:
        """Return the canonical frontier protected by the common capability."""

        return self.application_token.linearization_time

    @property
    def publication_token(self) -> str:
        """Return the stable opaque manager capability binding."""

        return self._integrity_token


def _smb_admission_integrity_token(
    authority_secret: bytes,
    token: SmbChannelAdmissionToken,
) -> str:
    """Return a compact owner-issued SMB capability label."""

    del authority_secret
    return hashlib.sha256(
        f"smb-admission:{token._manager_token}:{token._reservation_id}".encode()
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class _SmbAdmissionCapability:
    """Manager-owned immutable locator for one terminal SMB admission."""

    token_id: int
    reservation_id: int
    integrity_token: str
    application_token: ApplicationChannelAdmissionToken
    trusted_result: SmbClosedSessionBatch


def smb_channel_sidecar_result_digest(result: SmbClosedSessionBatch) -> str:
    """Return a stable digest over every terminal SMB session/member fact."""

    return _smb_closed_session_batch_digest(result)


@dataclass(frozen=True, slots=True, weakref_slot=True)
class SmbChannelAdmissionReceipt:
    """Authenticated proof of one committed SMB/common terminal batch."""

    manager_kind: Literal["smb"]
    manager_id: str
    kind: Literal["fresh_completed_batch_close"]
    publication_token: str
    application_receipt: ApplicationChannelAdmissionReceipt
    application_receipt_token: str
    channel_id: str
    operation_id: str
    operation_ids: tuple[str, ...]
    transport_id: str
    sidecar_result: SmbClosedSessionBatch
    sidecar_result_digest: str
    _manager_token: int = field(repr=False, default=0)
    _integrity_token: str = field(repr=False, default="")

    @property
    def receipt_token(self) -> str:
        """Return the keyed proof over the complete manager result."""

        return self._integrity_token


def _smb_admission_receipt_integrity_token(
    authority_secret: bytes,
    receipt: SmbChannelAdmissionReceipt,
) -> str:
    del authority_secret
    return hashlib.sha256(
        f"smb-receipt:{receipt._manager_token}:{receipt.publication_token}".encode()
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class SmbChannelAdmissionResult:
    """Frozen terminal SMB result plus common and manager proofs."""

    result: SmbClosedSessionBatch
    application: ApplicationChannelAdmissionResult
    receipt: SmbChannelAdmissionReceipt


class SmbChannelPreparedCommit:
    """No-lock-body capability for one terminal SMB/common-channel commit."""

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
        manager: SmbApplicationChannelManager,
        token: SmbChannelAdmissionToken,
        application_commit: ApplicationChannelPreparedCommit,
    ) -> None:
        self._manager = manager
        self._token = token
        self._application_commit = application_commit
        self._active = True
        self._committed = False
        self._result: SmbChannelAdmissionResult | None = None

    @property
    def committed(self) -> bool:
        """Return whether this exact manager claim has committed."""

        return self._committed

    @property
    def result(self) -> SmbChannelAdmissionResult | None:
        """Return the frozen terminal result after commit."""

        return self._result

    def commit_no_fail(self) -> SmbChannelAdmissionResult:
        """Publish or adopt the common terminal batch and seal its SMB proof."""

        if not self._active:
            raise StateError("SMB channel prepared commit is no longer active")
        if self._committed:
            raise StateError("SMB channel prepared admission was already committed")
        application_result = (
            self._application_commit.result
            if self._application_commit.committed
            else self._application_commit.commit_no_fail()
        )
        if application_result is None:  # pragma: no cover - guarded by committed contract
            raise AssertionError("SMB common admission retained no committed result")
        self._result = self._manager._issue_claimed_admission_result(
            self._token,
            application_result,
        )
        self._committed = True
        self._manager._release_committed_admission(self._token)
        return self._result

    def commit(self) -> SmbChannelAdmissionResult:
        """Compatibility alias for :meth:`commit_no_fail`."""

        return self.commit_no_fail()

    def _close(self) -> None:
        self._active = False


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
    prepared_admissions: int = 0
    claimed_admissions: int = 0
    estimated_prepared_bytes: int = 0


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
        self._manager_id = secrets.token_hex(16)
        self._lease_secret = secrets.token_bytes(32)
        self._shards: dict[int, _SmbShard] = {}
        self._directory_lock = RLock()
        self._gate = _SmbMutationGate()
        self._watermark_lane = Lock()
        self._compaction_cursor = 0
        self._exact_route_cache: OrderedDict[bytes, int] = OrderedDict()
        self._prepared_lock = RLock()
        self._admission_secret = secrets.token_bytes(32)
        self._next_prepared_reservation_id = 1
        self._prepared_admissions: dict[int, SmbChannelAdmissionToken] = {}
        self._prepared_capabilities: dict[int, _SmbAdmissionCapability] = {}
        self._admission_receipts: WeakValueDictionary[int, SmbChannelAdmissionReceipt] = (
            WeakValueDictionary()
        )
        self._claimed_admissions: set[int] = set()
        self._cancelling_admissions: set[int] = set()

    @property
    def application_registry(self) -> ApplicationChannelRegistry:
        """Return the injected engine-owned application-channel registry."""

        return self._registry

    @property
    def manager_id(self) -> str:
        """Return the stable opaque identity of this manager instance."""

        return self._manager_id

    def _active_prepared_admission_locked(
        self,
        token: SmbChannelAdmissionToken,
    ) -> _SmbAdmissionCapability:
        """Return the manager-owned capability for one intact exact token."""

        capability = self._prepared_capabilities.get(id(token))
        if capability is None:
            if token._manager_token != id(self):
                raise StateError("SMB channel admission token belongs to another manager")
            raise StateError("SMB channel admission token is stale or already consumed")
        if self._prepared_admissions.get(capability.reservation_id) is not token:
            raise StateError("SMB channel admission token is stale or already consumed")
        if token.application_token is not capability.application_token:
            raise StateError("SMB token no longer binds its exact common capability")
        if token.result is not capability.trusted_result:
            raise StateError("SMB token no longer binds its exact terminal sidecar")
        return capability

    def authenticates_admission_token(self, token: SmbChannelAdmissionToken) -> bool:
        """Return whether one intact manager/common terminal token remains active."""

        if type(token) is not SmbChannelAdmissionToken:
            return False
        with self._prepared_lock:
            try:
                capability = self._active_prepared_admission_locked(token)
            except StateError:
                return False
        return self._registry.authenticates_admission_token(capability.application_token)

    def authenticates_admission_receipt(self, receipt: SmbChannelAdmissionReceipt) -> bool:
        """Return whether this manager issued the exact terminal batch receipt."""

        return bool(
            self.authenticates_admission_receipt_proof(receipt)
            and self._registry.authenticates_admission_receipt(receipt.application_receipt)
        )

    def authenticates_admission_receipt_proof(
        self,
        receipt: SmbChannelAdmissionReceipt,
    ) -> bool:
        """Authenticate one issued manager/common proof after terminal acknowledgement."""

        if (
            type(receipt) is not SmbChannelAdmissionReceipt
            or self._admission_receipts.get(id(receipt)) is not receipt
        ):
            return False
        if not self._registry.authenticates_admission_receipt_proof(receipt.application_receipt):
            return False
        return True

    def authenticates_admission_result(self, result: object) -> bool:
        """Authenticate one exact SMB/common outer result and every identity link."""

        if type(result) is not SmbChannelAdmissionResult:
            return False
        receipt = result.receipt
        application = result.application
        return bool(
            type(receipt) is SmbChannelAdmissionReceipt
            and type(application) is ApplicationChannelAdmissionResult
            and result.result is receipt.sidecar_result
            and application.receipt is receipt.application_receipt
            and self.authenticates_admission_receipt(receipt)
            and self._registry.authenticates_admission_result(application)
        )

    def authenticates_admission_result_proof(self, result: object) -> bool:
        """Authenticate one intact outer result after its recovery owners are released."""

        if type(result) is not SmbChannelAdmissionResult:
            return False
        receipt = result.receipt
        application = result.application
        return bool(
            type(receipt) is SmbChannelAdmissionReceipt
            and type(application) is ApplicationChannelAdmissionResult
            and result.result is receipt.sidecar_result
            and application.receipt is receipt.application_receipt
            and self.authenticates_admission_receipt_proof(receipt)
            and self._registry.authenticates_admission_result_proof(application)
        )

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

    def _lease(
        self,
        session: SmbSessionView,
        tree: SmbTreeView,
        reservation: ApplicationOperationReservation,
        *,
        reused_session: bool,
        created_tree: bool,
        operation_completed: bool = False,
    ) -> SmbOperationLease:
        lease = SmbOperationLease(
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
            _manager_id=self._manager_id,
        )
        object.__setattr__(lease, "_integrity", self._lease_integrity(lease))
        return lease

    def _lease_integrity(self, lease: SmbOperationLease) -> str:
        """Bind one exact lease object to every immutable operation fact."""

        payload = repr(
            (
                "smb-operation-lease-v1",
                id(lease),
                lease._manager_id,
                lease.channel_id,
                lease.session_id,
                lease.tree_id,
                lease.operation_id,
                lease.ordinal,
                lease.started_at,
                lease.ended_at,
                lease.transport_plan,
                lease.sensor_observations,
                lease.ground_truth_transport_uid,
                lease.logon_id,
                lease.auth_session_ref,
                lease.principal,
                lease.auth_protocol,
                lease.account_scope,
                lease.effective_uid,
                lease.effective_gid,
                lease.client_access,
                lease.lifecycle_group_id,
                lease.reused_session,
                lease.created_tree,
                lease.operation_completed,
            )
        ).encode("utf-8")
        return hmac.new(self._lease_secret, payload, hashlib.sha256).hexdigest()

    def _authenticate_lease(self, lease: SmbOperationLease) -> None:
        """Reject copied, foreign, stale-shaped, or mutated lease carriers."""

        if (
            type(lease) is not SmbOperationLease
            or lease._manager_id != self._manager_id
            or type(lease._integrity) is not str
            or len(lease._integrity) != 64
            or not hmac.compare_digest(lease._integrity, self._lease_integrity(lease))
        ):
            raise StateError("SMB operation lease is copied, foreign, or tampered")

    def prepare_fresh_session_with_completed_operations_and_close(
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
        tree_connected_at: datetime,
        operations: tuple[SmbCompletedOperationPlan, ...],
        idle_timeout: timedelta,
        closed_at: datetime,
        reason: str = "logoff",
    ) -> SmbChannelAdmissionToken:
        """Prepare one 1..64-member SMB session that is born terminal at root commit."""

        if type(operations) is not tuple or not operations or len(operations) > 64:
            raise ValueError("Prepared SMB terminal batches require 1..64 operations")
        if any(type(item) is not SmbCompletedOperationPlan for item in operations):
            raise TypeError("Prepared SMB operations must be exact immutable models")
        if transport_plan.closed_at is None:
            raise StateError("Prepared SMB terminal batches require an immutable transport close")
        transport_open = ensure_utc(transport_plan.started_at)
        transport_close = ensure_utc(transport_plan.closed_at)
        canonical_tree_time = ensure_utc(tree_connected_at)
        canonical_close = ensure_utc(closed_at)
        if transport_close > self._window_end:
            raise StateError("SMB transport close must be inside the application window")
        if idle_timeout <= timedelta(0):
            raise ValueError("SMB idle_timeout must be positive")
        if not transport_open <= canonical_tree_time <= canonical_close <= transport_close:
            raise StateError("SMB tree/session terminal times must stay inside the transport")

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
        canonical_share_ref = _required_text(share_ref, "share_ref")
        canonical_reason = _required_text(reason, "reason")
        canonical_observations = tuple(sensor_observations)

        channel_id = self._channel_id(affinity, transport_plan.stable_id)
        session_id = self._session_id(channel_id)
        tree_id = self._tree_id(session_id, canonical_share_ref)
        operation_ids: set[str] = set()
        handle_ids: set[str] = set()
        handle_spans: dict[str, list[SmbCompletedHandleView]] = {}
        operation_views: list[SmbCompletedOperationView] = []
        reservations: list[ApplicationOperationReservation] = []
        previous_end = canonical_tree_time
        for ordinal, plan in enumerate(operations):
            semantic_operation_id = _required_text(
                plan.semantic_operation_id,
                "semantic_operation_id",
            )
            started_at = ensure_utc(plan.started_at)
            ended_at = ensure_utc(plan.ended_at)
            if started_at < previous_end or ended_at < started_at or ended_at > canonical_close:
                raise StateError("Prepared SMB operation spans must be ordered inside the session")
            if ordinal and started_at <= previous_end:
                raise StateError("Prepared SMB operation spans require a strict ordering gap")
            if plan.initiator_bytes < 0 or plan.responder_bytes < 0:
                raise ValueError("Prepared SMB operation bytes must be non-negative")
            if type(plan.handles) is not tuple or len(plan.handles) > 4:
                raise ValueError("Prepared SMB operations support at most four completed handles")
            operation_id = self._operation_id(channel_id, semantic_operation_id)
            if operation_id in operation_ids:
                raise StateError("Prepared SMB terminal batch repeats an operation identity")
            operation_ids.add(operation_id)
            completed_handles: list[SmbCompletedHandleView] = []
            for handle_plan in plan.handles:
                if type(handle_plan) is not SmbCompletedHandlePlan:
                    raise TypeError("Prepared SMB handles must be exact immutable models")
                file_id = _required_text(handle_plan.file_id, "file_id")
                access = _required_text(handle_plan.access, "access")
                role = _required_text(handle_plan.role, "role")
                opened_at = ensure_utc(handle_plan.opened_at)
                handle_closed_at = ensure_utc(handle_plan.closed_at)
                if handle_plan.content_version <= 0:
                    raise ValueError("Prepared SMB handle content_version must be positive")
                if not started_at <= opened_at <= handle_closed_at <= ended_at:
                    raise StateError("Prepared SMB handle lifetime must stay inside its operation")
                handle_id = self._handle_id(
                    operation_id=operation_id,
                    tree_id=tree_id,
                    file_id=file_id,
                    content_version=handle_plan.content_version,
                    access=access,
                    role=role,
                )
                if handle_id in handle_ids:
                    raise StateError("Prepared SMB terminal batch repeats a handle identity")
                handle_ids.add(handle_id)
                view = SmbCompletedHandleView(
                    handle_id=handle_id,
                    channel_id=channel_id,
                    tree_id=tree_id,
                    operation_id=operation_id,
                    file_id=file_id,
                    content_version=handle_plan.content_version,
                    access=access,
                    opened_at=opened_at,
                    closed_at=handle_closed_at,
                    deny_write=handle_plan.deny_write,
                    role=role,
                )
                for retained in handle_spans.get(file_id, ()):
                    overlaps = (
                        opened_at < retained.closed_at and retained.opened_at < handle_closed_at
                    )
                    write_conflict = "write" in {access, retained.access} and (
                        handle_plan.deny_write or retained.deny_write
                    )
                    if overlaps and write_conflict:
                        raise StateError("Prepared SMB handles violate deny-write sharing")
                handle_spans.setdefault(file_id, []).append(view)
                completed_handles.append(view)
            operation_views.append(
                SmbCompletedOperationView(
                    operation_id=operation_id,
                    ordinal=ordinal,
                    started_at=started_at,
                    ended_at=ended_at,
                    initiator_bytes=plan.initiator_bytes,
                    responder_bytes=plan.responder_bytes,
                    handles=tuple(completed_handles),
                )
            )
            reservations.append(
                ApplicationOperationReservation(
                    operation_id=operation_id,
                    channel_id=channel_id,
                    ordinal=ordinal,
                    started_at=started_at,
                    ended_at=ended_at,
                    initiator_bytes=plan.initiator_bytes,
                    responder_bytes=plan.responder_bytes,
                )
            )
            previous_end = ended_at

        initiator_bytes = sum(item.initiator_bytes for item in operation_views)
        responder_bytes = sum(item.responder_bytes for item in operation_views)
        if (
            initiator_bytes != transport_plan.traffic.orig.payload_bytes
            or responder_bytes != transport_plan.traffic.resp.payload_bytes
        ):
            raise StateError("Prepared SMB batch bytes must equal the canonical transport ledger")
        binding = ApplicationTransportBinding(
            transport_id=transport_plan.stable_id,
            opened_at=transport_open,
            closes_at=transport_close,
        )
        identity = ApplicationChannelIdentity(
            channel_id=channel_id,
            protocol="smb",
            owner_id=affinity.owner_id,
            affinity_digest=affinity.digest,
            binding=binding,
            opened_at=transport_open,
            idle_timeout=idle_timeout,
            hard_deadline=transport_close,
            budget=ApplicationChannelBudget(
                initiator_bytes=initiator_bytes,
                responder_bytes=responder_bytes,
                operations=len(operation_views),
            ),
        )
        session = SmbSessionView(
            channel_id=channel_id,
            session_id=session_id,
            affinity_digest=affinity.digest,
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
            server_hostname=canonical_server_hostname,
            client_ip=canonical_client_ip,
            lifecycle_group_id=canonical_lifecycle_group_id,
        )
        result = SmbClosedSessionBatch(
            session=session,
            tree=SmbTreeView(
                tree_id=tree_id,
                channel_id=channel_id,
                session_id=session_id,
                share_ref=canonical_share_ref,
                connected_at=canonical_tree_time,
            ),
            operations=tuple(operation_views),
            closure=SmbChannelClosure(
                channel_id=channel_id,
                session_id=session_id,
                logon_id=canonical_logon_id,
                principal=canonical_principal,
                server_hostname=canonical_server_hostname,
                lifecycle_group_id=canonical_lifecycle_group_id,
                closed_at=canonical_close,
                reason=canonical_reason,
            ),
        )
        application_token = self._registry.prepare_open_channel_with_completed_operations_and_close(
            identity,
            tuple(reservations),
            closed_at=canonical_close,
            reason=canonical_reason,
        )
        try:
            with self._prepared_lock:
                reservation_id = self._next_prepared_reservation_id
                self._next_prepared_reservation_id += 1
                token = SmbChannelAdmissionToken(
                    kind="fresh_completed_batch_close",
                    application_token=application_token,
                    result=result,
                    _manager_token=id(self),
                    _reservation_id=reservation_id,
                )
                token = replace(
                    token,
                    _integrity_token=_smb_admission_integrity_token(
                        self._admission_secret,
                        token,
                    ),
                )
                capability = _SmbAdmissionCapability(
                    token_id=id(token),
                    reservation_id=reservation_id,
                    integrity_token=token._integrity_token,
                    application_token=application_token,
                    trusted_result=result,
                )
                self._prepared_admissions[reservation_id] = token
                self._prepared_capabilities[id(token)] = capability
                return token
        except BaseException:
            self._registry.cancel_prepared_admission(application_token)
            raise

    def cancel_prepared_admission(self, token: SmbChannelAdmissionToken) -> bool:
        """Cancel one unclaimed SMB/common terminal reservation."""

        validation_error: StateError | None = None
        with self._prepared_lock:
            capability = self._prepared_capabilities.get(id(token))
            if capability is None:
                return False
            try:
                capability = self._active_prepared_admission_locked(token)
            except StateError as error:
                validation_error = error
            if capability.reservation_id in self._claimed_admissions:
                return False
            self._cancelling_admissions.add(capability.reservation_id)
        self._registry.cancel_prepared_admission(capability.application_token)
        if self._registry.authenticates_admission_token(capability.application_token):
            raise StateError("SMB cancellation did not retire its exact common reservation")
        with self._prepared_lock:
            retained = self._prepared_capabilities.get(capability.token_id)
            if retained is capability:
                self._release_prepared_capability_locked(capability)
            self._cancelling_admissions.discard(capability.reservation_id)
        if validation_error is not None:
            raise validation_error
        return True

    def _release_prepared_capability_locked(self, capability: _SmbAdmissionCapability) -> None:
        """Release one manager reservation using only its immutable locator."""

        self._claimed_admissions.discard(capability.reservation_id)
        self._cancelling_admissions.discard(capability.reservation_id)
        self._prepared_admissions.pop(capability.reservation_id, None)
        self._prepared_capabilities.pop(capability.token_id, None)
        if not self._prepared_admissions:
            self._prepared_admissions.clear()
            self._prepared_capabilities.clear()
            self._claimed_admissions.clear()
            self._cancelling_admissions.clear()

    def _claim_prepared_admission(self, token: SmbChannelAdmissionToken) -> _SmbAdmissionCapability:
        """Claim and revalidate one manager token without retaining locks."""

        with self._prepared_lock:
            capability = self._active_prepared_admission_locked(token)
            if capability.reservation_id in self._cancelling_admissions:
                raise StateError("SMB channel admission token is being cancelled")
            if capability.reservation_id in self._claimed_admissions:
                raise StateError("SMB channel admission token is already claimed")
            if not self._registry.authenticates_admission_token(capability.application_token):
                self._release_prepared_capability_locked(capability)
                raise StateError("SMB admission's common token failed authentication")
            self._claimed_admissions.add(capability.reservation_id)
            return capability

    @contextmanager
    def prepared_admission(
        self,
        token: SmbChannelAdmissionToken,
    ) -> Iterator[SmbChannelPreparedCommit]:
        """Claim SMB and common capabilities while retaining no manager locks."""

        capability = self._claim_prepared_admission(token)
        transaction: SmbChannelPreparedCommit | None = None
        try:
            with self._registry.prepared_admission(
                capability.application_token
            ) as application_commit:
                transaction = SmbChannelPreparedCommit(self, token, application_commit)
                try:
                    yield transaction
                finally:
                    transaction._close()
        finally:
            if transaction is None or not transaction.committed:
                self._cancel_claimed_admission(token)

    def _cancel_claimed_admission(self, token: SmbChannelAdmissionToken) -> None:
        """Release one manager claim after its outer transaction aborts."""

        with self._prepared_lock:
            capability = self._prepared_capabilities.get(id(token))
            if capability is None:
                return
            try:
                capability = self._active_prepared_admission_locked(token)
            except StateError:
                self._release_prepared_capability_locked(capability)
                return
            if capability.reservation_id not in self._claimed_admissions:
                raise StateError("SMB channel admission token is not claimed")
            self._release_prepared_capability_locked(capability)

    def _issue_claimed_admission_result(
        self,
        token: SmbChannelAdmissionToken,
        application_result: ApplicationChannelAdmissionResult,
    ) -> SmbChannelAdmissionResult:
        """Validate one committed common batch and issue its typed SMB proof."""

        with self._prepared_lock:
            capability = self._active_prepared_admission_locked(token)
            if capability.reservation_id not in self._claimed_admissions:
                raise StateError("SMB channel admission token is not claimed")
            common = application_result.receipt
            if common is None or not self._registry.authenticates_admission_result(
                application_result
            ):
                raise AssertionError("SMB common admission returned no authentic receipt")
            trusted = capability.trusted_result
            operation_ids = tuple(item.operation_id for item in trusted.operations)
            snapshot = application_result.snapshot
            assert common.kind == "open_completed_batch_close"
            assert common.publication_token == capability.application_token.publication_token
            assert common.operation_ids == operation_ids
            assert common.channel_id == trusted.session.channel_id
            assert common.close_token is None and application_result.close_token is None
            assert snapshot.closed_at == trusted.closure.closed_at
            assert snapshot.active_operations == 0
            assert snapshot.completed_operations == len(operation_ids)
            assert snapshot.reserved_operations == len(operation_ids)
            assert snapshot.reserved_initiator_bytes == sum(
                item.initiator_bytes for item in trusted.operations
            )
            assert snapshot.reserved_responder_bytes == sum(
                item.responder_bytes for item in trusted.operations
            )
            receipt = SmbChannelAdmissionReceipt(
                manager_kind="smb",
                manager_id=self._manager_id,
                kind="fresh_completed_batch_close",
                publication_token=capability.integrity_token,
                application_receipt=common,
                application_receipt_token=common.receipt_token,
                channel_id=common.channel_id,
                operation_id=common.operation_id,
                operation_ids=operation_ids,
                transport_id=snapshot.identity.binding.transport_id,
                sidecar_result=trusted,
                sidecar_result_digest=smb_channel_sidecar_result_digest(trusted),
                _manager_token=id(self),
            )
            receipt = replace(
                receipt,
                _integrity_token=_smb_admission_receipt_integrity_token(
                    self._admission_secret,
                    receipt,
                ),
            )
            self._admission_receipts[id(receipt)] = receipt
            return SmbChannelAdmissionResult(
                result=trusted,
                application=application_result,
                receipt=receipt,
            )

    def _release_committed_admission(self, token: SmbChannelAdmissionToken) -> None:
        """Release one manager claim after its immutable result is safely cached."""

        with self._prepared_lock:
            capability = self._prepared_capabilities.get(id(token))
            if capability is None:
                return
            self._release_prepared_capability_locked(capability)

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
            lease = SmbOperationLease(
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
                _manager_id=self._manager_id,
            )
            object.__setattr__(lease, "_integrity", self._lease_integrity(lease))
            return lease
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

        return self._reserve_reuse(
            affinity,
            exact_channel_id=None,
            share_ref=share_ref,
            semantic_operation_id=semantic_operation_id,
            requested_at=requested_at,
            required_until=required_until,
            initiator_bytes=initiator_bytes,
            responder_bytes=responder_bytes,
        )

    def reserve_channel_reuse(
        self,
        anchor_lease: SmbOperationLease,
        affinity: SmbChannelAffinity,
        *,
        share_ref: str,
        semantic_operation_id: str,
        requested_at: datetime,
        required_until: datetime,
        initiator_bytes: int,
        responder_bytes: int,
    ) -> SmbReuseResult:
        """Reserve reuse on the exact channel proven by an authenticated lease."""

        self._authenticate_lease(anchor_lease)
        return self._reserve_reuse(
            affinity,
            exact_channel_id=anchor_lease.channel_id,
            share_ref=share_ref,
            semantic_operation_id=semantic_operation_id,
            requested_at=requested_at,
            required_until=required_until,
            initiator_bytes=initiator_bytes,
            responder_bytes=responder_bytes,
        )

    def _reserve_reuse(
        self,
        affinity: SmbChannelAffinity,
        *,
        exact_channel_id: str | None,
        share_ref: str,
        semantic_operation_id: str,
        requested_at: datetime,
        required_until: datetime,
        initiator_bytes: int,
        responder_bytes: int,
    ) -> SmbReuseResult:
        """Reserve one compatible operation, optionally on one exact proven channel."""

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
            channel_key = (
                self._channel_key(exact_channel_id)
                if exact_channel_id is not None
                else next(
                    shard.sessions.find_key_iter("affinity", self._affinity_key(affinity)),
                    None,
                )
            )
            if channel_key is None:
                return SmbReuseResult(lease=None)
            record = shard.sessions.get(channel_key)
            if record is None:
                return SmbReuseResult(lease=None)
            if record.affinity_key != self._affinity_key(affinity):
                raise StateError("SMB exact-channel reuse changed its authenticated affinity")
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
            if exact_channel_id is None:
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

        self._authenticate_lease(lease)
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

        self._authenticate_lease(lease)
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

        self._authenticate_lease(lease)
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

        self._authenticate_lease(lease)
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

        with self._prepared_lock:
            prepared_admissions = len(self._prepared_admissions)
            claimed_admissions = len(self._claimed_admissions)
            estimated_prepared_bytes = (
                sys.getsizeof(self._prepared_admissions)
                + sys.getsizeof(self._prepared_capabilities)
                + sys.getsizeof(self._claimed_admissions)
                + sys.getsizeof(self._cancelling_admissions)
                + sum(
                    sys.getsizeof(key) + sys.getsizeof(value)
                    for key, value in self._prepared_admissions.items()
                )
                + sum(
                    sys.getsizeof(key) + sys.getsizeof(value)
                    for key, value in self._prepared_capabilities.items()
                )
            )
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
        sidecar_estimated_bytes = estimated_values + estimated_indexes + estimated_prepared_bytes
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
            prepared_admissions=prepared_admissions,
            claimed_admissions=claimed_admissions,
            estimated_prepared_bytes=estimated_prepared_bytes,
        )
