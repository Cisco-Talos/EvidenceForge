# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Bounded SSH child channels on the shared application-channel registry.

The SSH action bundle remains the owner of authentication, endpoint session
lifecycle, and source-native close evidence.  The canonical network connection
remains the owner of the TCP/22 interval and sensor identity.  This manager
only records the reusable application session and its active shell, exec,
SFTP, or SCP children.  Finalized children are removed immediately; rendered
records and transferred payloads are never retained here.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import struct
import sys
from array import array
from collections import OrderedDict
from collections.abc import Iterator
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from threading import Condition, Lock, RLock
from typing import Literal

from evidenceforge.events.application import (
    ApplicationChannelBudget,
    ApplicationChannelCensus,
    ApplicationChannelIdentity,
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
    ApplicationChannelRetirementProof,
)
from evidenceforge.generation.indexes import (
    IndexMetrics,
    PackedByteRowStore,
    PackedHandleExpiryIndex,
    PackedUniqueDigestMap,
)
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.time import ensure_utc

# Keep one bounded, owner-sharded hot working set large enough for the scale
# probe's 4,000-session random exact-lookup cohort.  At the shared registry's
# 32 shards this retains at most 4,096 reconstructed immutable views; packed
# rows remain the source of truth and cold fleet entries are never expanded.
_DEFAULT_DECODED_CACHE_PER_SHARD = 128
_DEFAULT_SESSION_HOT_CACHE = 16_384
_DEFAULT_COMPACTION_WORK = 4_096
_DEFAULT_WATERMARK_PAGE = 4_096
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_SESSION_STORED_TEXT_FIELDS = 16
_SESSION_COMPACT_HEADER = struct.Struct(f"<BB16sHH9q{_SESSION_STORED_TEXT_FIELDS}B")
_SESSION_WIDE_HEADER = struct.Struct(f"<BB16sHH9q{_SESSION_STORED_TEXT_FIELDS}H")
_OPERATION_TEXT_FIELDS = 5
_OPERATION_HEADER = struct.Struct(f"<BI2q2Q{_OPERATION_TEXT_FIELDS}H")
_SESSION_WIDE_LENGTHS = 1 << 7
_SESSION_CLIENT_SOURCE_REFERENCE = 1 << 0
_AUTH_METHOD_CODES = {
    "password": 1,
    "publickey": 2,
    "keyboard-interactive": 3,
    "gssapi-with-mic": 4,
}
_AUTH_CODE_METHODS = {code: value for value, code in _AUTH_METHOD_CODES.items()}

# A deferred SSH close can place PAM session-close evidence just under 2.5
# seconds after TCP close, then place the tuple-scoped sshd termination just
# under 5.2 seconds after PAM close.  Keep this as one public application
# contract so optional and authored admission use the same conservative bound.
SSH_CANONICAL_CLOSE_HEADROOM = timedelta(milliseconds=7_701)
SSH_EXCLUSIVE_OUTPUT_FENCE = timedelta(microseconds=1)
SSH_TRANSPORT_START_JITTER_HEADROOM = timedelta(seconds=1)


class SshSessionAdmissionError(StateError):
    """An optional SSH session cannot fit inside its engine-owned output window."""


def _required_text(value: str, field_name: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field_name} must not be empty")
    return normalized


def _canonical_utc(value: datetime) -> datetime:
    """Return already-canonical UTC values without a redundant conversion."""

    return value if value.tzinfo is UTC else ensure_utc(value)


def _datetime_us(value: datetime) -> int:
    delta = _canonical_utc(value) - _EPOCH
    return ((delta.days * 86_400 + delta.seconds) * 1_000_000) + delta.microseconds


def _datetime_from_us(value: int) -> datetime:
    return _EPOCH + timedelta(microseconds=value)


def _validated_application_identity(
    *,
    channel_id: str,
    owner_id: str,
    affinity_digest: str,
    transport: SshTransportPlan,
    opened_at: datetime,
    idle_timeout: timedelta,
    budget: ApplicationChannelBudget,
) -> ApplicationChannelIdentity:
    """Build common frozen values after the SSH boundary validated them.

    The manager has already normalized every identity/time, enforced TCP and
    lifecycle containment, and validated the budget. Constructing the frozen
    common values directly avoids repeating those dataclass normalization
    passes for every retained session. The shared registry still performs its
    own window, uniqueness, containment, affinity, and budget admission.
    """

    binding = object.__new__(ApplicationTransportBinding)
    object.__setattr__(binding, "transport_id", transport.transport_id)
    object.__setattr__(binding, "opened_at", transport.opened_at)
    object.__setattr__(binding, "closes_at", transport.closes_at)
    identity = object.__new__(ApplicationChannelIdentity)
    object.__setattr__(identity, "channel_id", channel_id)
    object.__setattr__(identity, "protocol", "ssh")
    object.__setattr__(identity, "owner_id", owner_id)
    object.__setattr__(identity, "affinity_digest", affinity_digest)
    object.__setattr__(identity, "binding", binding)
    object.__setattr__(identity, "opened_at", opened_at)
    object.__setattr__(identity, "idle_timeout", idle_timeout)
    object.__setattr__(identity, "hard_deadline", transport.closes_at)
    object.__setattr__(identity, "budget", budget)
    return identity


def _validated_application_budget(
    *,
    initiator_bytes: int,
    responder_bytes: int,
    operations: int,
) -> ApplicationChannelBudget:
    """Build one common budget after SSH boundary range checks."""

    budget = object.__new__(ApplicationChannelBudget)
    object.__setattr__(budget, "initiator_bytes", initiator_bytes)
    object.__setattr__(budget, "responder_bytes", responder_bytes)
    object.__setattr__(budget, "operations", operations)
    return budget


def _validated_completed_operation(
    *,
    operation_id: str,
    channel_id: str,
    started_at: datetime,
    ended_at: datetime,
    initiator_bytes: int,
    responder_bytes: int,
) -> ApplicationOperationReservation:
    """Build one normalized synchronous child after SSH boundary checks."""

    reservation = object.__new__(ApplicationOperationReservation)
    object.__setattr__(reservation, "operation_id", operation_id)
    object.__setattr__(reservation, "channel_id", channel_id)
    object.__setattr__(reservation, "ordinal", 0)
    object.__setattr__(reservation, "started_at", started_at)
    object.__setattr__(reservation, "ended_at", ended_at)
    object.__setattr__(reservation, "initiator_bytes", initiator_bytes)
    object.__setattr__(reservation, "responder_bytes", responder_bytes)
    object.__setattr__(reservation, "parent_operation_id", "")
    return reservation


def _encode_text_fields(
    values: tuple[str, ...],
    field_name: str,
) -> tuple[tuple[int, ...], bytes]:
    encoded = tuple(value.encode("utf-8") for value in values)
    lengths = tuple(len(value) for value in encoded)
    if any(length >= 1 << 16 for length in lengths):
        raise ValueError(f"SSH packed {field_name} fields must be shorter than 65,536 bytes")
    return lengths, b"".join(encoded)


def _decode_text_fields(
    row: bytes | memoryview,
    *,
    offset: int,
    lengths: tuple[int, ...],
) -> tuple[str, ...]:
    values: list[str] = []
    for length in lengths:
        end = offset + length
        values.append(bytes(row[offset:end]).decode("utf-8"))
        offset = end
    return tuple(values)


class SshOperationKind(StrEnum):
    """Supported SSH application-child families."""

    SHELL = "shell"
    EXEC = "exec"
    SFTP = "sftp"
    SCP = "scp"


_OPERATION_KIND_TO_CODE = {
    SshOperationKind.SHELL: 1,
    SshOperationKind.EXEC: 2,
    SshOperationKind.SFTP: 3,
    SshOperationKind.SCP: 4,
}
_OPERATION_CODE_TO_KIND = {value: key for key, value in _OPERATION_KIND_TO_CODE.items()}


@dataclass(frozen=True, slots=True)
class SshChannelAffinity:
    """Exact SSH client/session to server/session authentication affinity."""

    client_identity: str
    client_session_object_id: str
    server_identity: str
    server_session_object_id: str
    principal: str
    auth_method: str
    _owner_id: str = field(init=False, repr=False)
    _digest: str = field(init=False, repr=False)
    _digest_bytes: bytes = field(init=False, repr=False)

    def __post_init__(self) -> None:
        """Normalize identity fields and derive stable owner/affinity keys."""

        client_identity = _required_text(self.client_identity, "client_identity").casefold()
        client_session = _required_text(
            self.client_session_object_id,
            "client_session_object_id",
        )
        server_identity = _required_text(self.server_identity, "server_identity").casefold()
        server_session = _required_text(
            self.server_session_object_id,
            "server_session_object_id",
        )
        principal = _required_text(self.principal, "principal").casefold()
        auth_method = _required_text(self.auth_method, "auth_method").casefold()
        object.__setattr__(self, "client_identity", client_identity)
        object.__setattr__(self, "client_session_object_id", client_session)
        object.__setattr__(self, "server_identity", server_identity)
        object.__setattr__(self, "server_session_object_id", server_session)
        object.__setattr__(self, "principal", principal)
        object.__setattr__(self, "auth_method", auth_method)
        digest = hashlib.blake2b(digest_size=16, person=b"ef-ssh-aff-v2")
        for value in (client_identity, client_session):
            encoded = value.encode("utf-8")
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
        owner_digest = digest.copy().hexdigest()
        digest.update(b"\xff")
        for value in (server_identity, server_session, principal, auth_method):
            encoded = value.encode("utf-8")
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
        affinity_digest = digest.digest()
        object.__setattr__(self, "_owner_id", f"ssh-owner-{owner_digest[:32]}")
        object.__setattr__(self, "_digest", affinity_digest.hex())
        object.__setattr__(self, "_digest_bytes", affinity_digest)

    @property
    def owner_id(self) -> str:
        """Return the stable shared-registry owner partition identity."""

        return self._owner_id

    @property
    def digest(self) -> str:
        """Return the stable exact affinity digest."""

        return self._digest


@dataclass(frozen=True, slots=True)
class SshProcessHold:
    """Frozen process/session interval required by an SSH transport or child."""

    hostname: str
    pid: int
    process_object_id: str
    session_object_id: str
    principal: str
    started_at: datetime
    required_until: datetime

    def __post_init__(self) -> None:
        """Normalize the process instance and reject backward holds."""

        hostname = _required_text(self.hostname, "hostname").casefold()
        process_object_id = _required_text(self.process_object_id, "process_object_id")
        session_object_id = _required_text(self.session_object_id, "session_object_id")
        principal = _required_text(self.principal, "principal").casefold()
        if self.pid <= 0:
            raise ValueError("SSH process hold pid must be positive")
        started_at = _canonical_utc(self.started_at)
        required_until = _canonical_utc(self.required_until)
        if required_until < started_at:
            raise ValueError("SSH process hold required_until cannot precede process start")
        object.__setattr__(self, "hostname", hostname)
        object.__setattr__(self, "process_object_id", process_object_id)
        object.__setattr__(self, "session_object_id", session_object_id)
        object.__setattr__(self, "principal", principal)
        object.__setattr__(self, "started_at", started_at)
        object.__setattr__(self, "required_until", required_until)

    def contains(self, started_at: datetime, ended_at: datetime) -> bool:
        """Return whether this process instance contains a canonical child span."""

        return (
            self.started_at <= _canonical_utc(started_at)
            and _canonical_utc(ended_at) <= self.required_until
        )


@dataclass(frozen=True, slots=True)
class SshTransportPlan:
    """Immutable canonical TCP/22 binding and explicit process holds."""

    transport_id: str
    zeek_uid: str
    conn_id: str
    source_ip: str
    server_ip: str
    source_port: int
    server_port: int
    opened_at: datetime
    closes_at: datetime
    receiver_process: SshProcessHold
    source_process: SshProcessHold | None = None

    def __post_init__(self) -> None:
        """Normalize transport identity and enforce immutable hold containment."""

        for field_name in ("transport_id", "source_ip", "server_ip"):
            object.__setattr__(
                self,
                field_name,
                _required_text(getattr(self, field_name), field_name),
            )
        object.__setattr__(self, "zeek_uid", self.zeek_uid.strip())
        object.__setattr__(self, "conn_id", self.conn_id.strip())
        if not 0 < self.source_port <= 65_535 or not 0 < self.server_port <= 65_535:
            raise ValueError("SSH transport ports must be between 1 and 65,535")
        if self.server_port != 22:
            raise ValueError("SSH transport server_port must be 22")
        opened_at = _canonical_utc(self.opened_at)
        closes_at = _canonical_utc(self.closes_at)
        if closes_at <= opened_at:
            raise ValueError("SSH transport close must follow transport open")
        if self.source_process is not None and self.source_process.started_at > opened_at:
            raise ValueError("SSH source process hold starts after TCP open")
        if self.receiver_process.started_at >= closes_at:
            raise ValueError("SSH receiver process hold must start before TCP close")
        for hold in (self.source_process, self.receiver_process):
            if hold is not None and hold.required_until < closes_at:
                raise ValueError("SSH transport process hold ends before TCP close")
        object.__setattr__(self, "opened_at", opened_at)
        object.__setattr__(self, "closes_at", closes_at)


@dataclass(frozen=True, slots=True)
class SshSessionBinding:
    """Exact lifecycle/session object owned by the SSH action bundle."""

    hostname: str
    logon_id: str
    session_object_id: str
    lifecycle_group_id: str
    principal: str
    ready_at: datetime

    def __post_init__(self) -> None:
        """Normalize the exact session identity and canonical readiness time."""

        object.__setattr__(self, "hostname", _required_text(self.hostname, "hostname").casefold())
        object.__setattr__(self, "logon_id", _required_text(self.logon_id, "logon_id"))
        object.__setattr__(
            self,
            "session_object_id",
            _required_text(self.session_object_id, "session_object_id"),
        )
        object.__setattr__(
            self,
            "lifecycle_group_id",
            _required_text(self.lifecycle_group_id, "lifecycle_group_id"),
        )
        object.__setattr__(
            self,
            "principal",
            _required_text(self.principal, "principal").casefold(),
        )
        object.__setattr__(self, "ready_at", _canonical_utc(self.ready_at))


@dataclass(frozen=True, slots=True)
class SshSessionView:
    """Open-only SSH protocol view over one immutable transport."""

    channel_id: str
    ssh_session_id: str
    affinity: SshChannelAffinity
    transport: SshTransportPlan
    binding: SshSessionBinding

    @property
    def owner_id(self) -> str:
        """Return the shared application-channel owner identity."""

        return self.affinity.owner_id


@dataclass(frozen=True, slots=True)
class SshOperationLease:
    """Frozen active SSH child-channel reservation."""

    operation_id: str
    child_channel_id: str
    channel_id: str
    semantic_operation_id: str
    parent_operation_id: str
    kind: SshOperationKind
    ordinal: int
    started_at: datetime
    ended_at: datetime
    initiator_bytes: int
    responder_bytes: int
    session: SshSessionView


@dataclass(frozen=True, slots=True)
class SshChannelAdmissionToken:
    """Opaque reservation for one SSH session and synchronous first child."""

    kind: Literal["open_completed"]
    application_token: ApplicationChannelAdmissionToken = field(repr=False)
    session: SshSessionView
    operation: SshOperationLease
    _manager_token: int = field(repr=False, default=0)
    _reservation_id: int = field(repr=False, default=0)
    _owner_shard_id: int = field(repr=False, default=0)
    _reserved_channel_ids: tuple[str, ...] = field(repr=False, default=())
    _integrity_token: str = field(repr=False, default="")

    @property
    def linearization_time(self) -> datetime:
        """Return the canonical frontier protected while this token is claimed."""

        return self.application_token.linearization_time

    @property
    def publication_token(self) -> str:
        """Return the stable opaque manager capability binding."""

        return self._integrity_token


def _ssh_admission_integrity_token(
    authority_secret: bytes,
    token: SshChannelAdmissionToken,
) -> str:
    """Authenticate the nested common capability and exact SSH sidecar preimage."""

    canonical = repr(
        (
            "ssh-channel-admission-v1",
            token.kind,
            token.application_token.publication_token,
            token.session,
            token.operation,
            token._manager_token,
            token._reservation_id,
            token._owner_shard_id,
            token._reserved_channel_ids,
        )
    ).encode()
    return hmac.new(authority_secret, canonical, hashlib.sha256).hexdigest()


@dataclass(frozen=True, slots=True)
class _SshAdmissionCapability:
    """Manager-owned immutable locator and trusted SSH admission preimage."""

    token_id: int
    reservation_id: int
    integrity_token: str
    application_token: ApplicationChannelAdmissionToken
    trusted_token: SshChannelAdmissionToken
    owner_shard_id: int
    reserved_channel_ids: tuple[str, ...]
    packed_session: bytes
    channel_route_digest: int
    linearization_time: datetime


def ssh_channel_sidecar_result_digest(
    session: SshSessionView,
    operation: SshOperationLease,
) -> str:
    """Return a stable digest over one exact frozen SSH sidecar result."""

    semantic = (
        session.channel_id,
        session.ssh_session_id,
        session.affinity,
        session.transport,
        session.binding,
        operation.operation_id,
        operation.child_channel_id,
        operation.channel_id,
        operation.semantic_operation_id,
        operation.parent_operation_id,
        operation.kind,
        operation.ordinal,
        operation.started_at,
        operation.ended_at,
        operation.initiator_bytes,
        operation.responder_bytes,
        operation.session,
    )
    return hashlib.sha256(repr(("ssh-channel-sidecar-result-v1", semantic)).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class SshChannelAdmissionReceipt:
    """Authenticated proof of one committed SSH/common-channel admission."""

    manager_kind: Literal["ssh"]
    manager_id: str
    kind: Literal["open_completed"]
    publication_token: str
    application_receipt: ApplicationChannelAdmissionReceipt
    application_receipt_token: str
    channel_id: str
    ssh_session_id: str
    operation_id: str
    transport_ids: tuple[str, ...]
    session: SshSessionView
    operation: SshOperationLease
    sidecar_result_digest: str
    _manager_token: int = field(repr=False, default=0)
    _integrity_token: str = field(repr=False, default="")

    @property
    def receipt_token(self) -> str:
        """Return the opaque keyed proof over the complete manager result."""

        return self._integrity_token


def _ssh_admission_receipt_integrity_token(
    authority_secret: bytes,
    receipt: SshChannelAdmissionReceipt,
) -> str:
    """Authenticate exact manager, common receipt, and SSH result membership."""

    canonical = repr(
        (
            "ssh-channel-admission-receipt-v1",
            receipt.manager_kind,
            receipt.manager_id,
            receipt.kind,
            receipt.publication_token,
            receipt.application_receipt,
            receipt.application_receipt_token,
            receipt.channel_id,
            receipt.ssh_session_id,
            receipt.operation_id,
            receipt.transport_ids,
            receipt.session,
            receipt.operation,
            receipt.sidecar_result_digest,
            receipt._manager_token,
        )
    ).encode()
    return hmac.new(authority_secret, canonical, hashlib.sha256).hexdigest()


@dataclass(frozen=True, slots=True)
class SshChannelAdmissionResult:
    """Frozen SSH result plus authenticated common and manager proofs."""

    session: SshSessionView
    operation: SshOperationLease
    application: ApplicationChannelAdmissionResult
    receipt: SshChannelAdmissionReceipt


class SshChannelPreparedCommit:
    """No-lock-body capability for one final SSH/common-channel commit."""

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
        manager: SshApplicationChannelManager,
        token: SshChannelAdmissionToken,
        application_commit: ApplicationChannelPreparedCommit,
    ) -> None:
        self._manager = manager
        self._token = token
        self._application_commit = application_commit
        self._active = True
        self._committed = False
        self._result: SshChannelAdmissionResult | None = None

    @property
    def committed(self) -> bool:
        """Return whether this exact manager claim has committed."""

        return self._committed

    @property
    def result(self) -> SshChannelAdmissionResult | None:
        """Return the frozen SSH result after commit."""

        return self._result

    def commit_no_fail(self) -> SshChannelAdmissionResult:
        """Publish the fully claimed common admission and SSH sidecar mutation."""

        if not self._active:
            raise StateError("SSH channel prepared commit is no longer active")
        if self._committed:
            raise StateError("SSH channel prepared admission was already committed")
        self._result = self._manager._commit_claimed_admission(
            self._token,
            self._application_commit,
        )
        self._committed = True
        return self._result

    def commit(self) -> SshChannelAdmissionResult:
        """Compatibility alias for :meth:`commit_no_fail`."""

        return self.commit_no_fail()

    def _close(self) -> None:
        self._active = False


@dataclass(frozen=True, slots=True)
class SshChannelClosure:
    """Lock-free protocol close intent for SSH lifecycle orchestration."""

    channel_id: str
    ssh_session_id: str
    logon_id: str
    session_object_id: str
    lifecycle_group_id: str
    principal: str
    transport_id: str
    closed_at: datetime
    reason: str
    source_process: SshProcessHold | None
    receiver_process: SshProcessHold
    retirement_proof: ApplicationChannelRetirementProof


@dataclass(frozen=True, slots=True)
class SshWatermarkResult:
    """One bounded manager watermark page and its closure intents."""

    census: SshChannelCensus
    closures: tuple[SshChannelClosure, ...]
    has_more: bool = False


@dataclass(frozen=True, slots=True)
class SshChannelCensus:
    """Constant-time SSH sidecar and shared-registry structural metrics."""

    open_sessions: int
    active_operations: int
    session_backing_entries: int
    operation_backing_entries: int
    stale_sidecar_entries: int
    expiry_entries: int
    stale_expiry_entries: int
    shard_count: int
    max_shard_load: int
    high_water_mark: int
    lookup_candidates_inspected: int
    sidecar_lookup_candidates_inspected: int
    decoded_cache_entries: int
    decoded_cache_capacity: int
    decoded_cache_estimated_bytes: int
    sidecar_estimated_bytes: int
    sidecar_estimated_index_bytes: int
    estimated_bytes: int
    estimated_index_bytes: int
    primary_compaction_pending: int
    primary_compaction_work: int
    expiry_compaction_pending: int
    expiry_compaction_work: int
    watermark: datetime
    application: ApplicationChannelCensus


def _validate_session_contract(
    affinity: SshChannelAffinity,
    transport: SshTransportPlan,
    binding: SshSessionBinding,
) -> None:
    if affinity.server_identity != binding.hostname:
        raise StateError("SSH affinity server identity disagrees with the lifecycle session host")
    if affinity.server_session_object_id != binding.session_object_id:
        raise StateError("SSH affinity session object disagrees with the lifecycle session")
    if affinity.principal != binding.principal:
        raise StateError("SSH affinity principal disagrees with the lifecycle session")
    receiver = transport.receiver_process
    if receiver.hostname != binding.hostname:
        raise StateError("SSH receiver process belongs to another host")
    if receiver.session_object_id != binding.session_object_id:
        raise StateError("SSH receiver process is not bound to the SSH lifecycle session")
    if receiver.principal != binding.principal:
        raise StateError("SSH receiver process principal disagrees with the SSH session")
    if receiver.started_at > binding.ready_at:
        raise StateError("SSH receiver process starts after lifecycle session readiness")
    source = transport.source_process
    if source is not None:
        if source.hostname != affinity.client_identity:
            raise StateError("SSH source process belongs to another client host")
        if source.session_object_id != affinity.client_session_object_id:
            raise StateError("SSH source process is not bound to the affinity client session")
    if binding.ready_at < transport.opened_at or binding.ready_at >= transport.closes_at:
        raise StateError("SSH lifecycle session readiness must be inside the TCP transport")


def _pack_session(
    view: SshSessionView,
    *,
    channel_digest: bytes | None = None,
) -> bytes:
    affinity = view.affinity
    transport = view.transport
    binding = view.binding
    source = transport.source_process
    receiver = transport.receiver_process
    channel_prefix = "ssh-channel-"
    channel_suffix = view.channel_id.removeprefix(channel_prefix)
    if (
        not view.channel_id.startswith(channel_prefix)
        or len(channel_suffix) != 32
        or channel_suffix != channel_suffix.lower()
    ):
        raise StateError("SSH manager generated an invalid packed channel identity")
    if channel_digest is None:
        try:
            channel_digest = bytes.fromhex(channel_suffix)
        except ValueError as exc:  # pragma: no cover - internal ID invariant
            raise StateError("SSH manager generated an invalid packed channel digest") from exc
    flags = 0
    client_identity = affinity.client_identity
    if client_identity == transport.source_ip:
        flags |= _SESSION_CLIENT_SOURCE_REFERENCE
        client_identity = ""
    auth_code = _AUTH_METHOD_CODES.get(affinity.auth_method, 0)
    auth_method = "" if auth_code else affinity.auth_method
    texts = (
        transport.transport_id,
        transport.zeek_uid,
        transport.conn_id,
        transport.source_ip,
        transport.server_ip,
        binding.logon_id,
        binding.lifecycle_group_id,
        client_identity,
        affinity.client_session_object_id,
        affinity.server_identity,
        affinity.server_session_object_id,
        affinity.principal,
        auth_method,
        "" if source is None else source.process_object_id,
        "" if source is None else source.principal,
        receiver.process_object_id,
    )
    lengths, payload = _encode_text_fields(texts, "session")
    if all(length < 1 << 8 for length in lengths):
        header = _SESSION_COMPACT_HEADER
    else:
        flags |= _SESSION_WIDE_LENGTHS
        header = _SESSION_WIDE_HEADER
    return (
        header.pack(
            flags,
            auth_code,
            channel_digest,
            transport.source_port,
            transport.server_port,
            _datetime_us(transport.opened_at),
            _datetime_us(transport.closes_at),
            _datetime_us(binding.ready_at),
            0 if source is None else source.pid,
            0 if source is None else _datetime_us(source.started_at),
            0 if source is None else _datetime_us(source.required_until),
            receiver.pid,
            _datetime_us(receiver.started_at),
            _datetime_us(receiver.required_until),
            *lengths,
        )
        + payload
    )


def _unpack_session(row: bytes | memoryview) -> SshSessionView:
    flags = row[0]
    header = _SESSION_WIDE_HEADER if flags & _SESSION_WIDE_LENGTHS else _SESSION_COMPACT_HEADER
    values = header.unpack_from(row)
    auth_code = values[1]
    channel_id = f"ssh-channel-{values[2].hex()}"
    source_port, server_port = values[3:5]
    numeric = values[5:14]
    lengths = tuple(values[14 : 14 + _SESSION_STORED_TEXT_FIELDS])
    text = _decode_text_fields(row, offset=header.size, lengths=lengths)
    client_identity = text[3] if flags & _SESSION_CLIENT_SOURCE_REFERENCE else text[7]
    auth_method = _AUTH_CODE_METHODS.get(auth_code, text[12])
    affinity = SshChannelAffinity(
        client_identity=client_identity,
        client_session_object_id=text[8],
        server_identity=text[9],
        server_session_object_id=text[10],
        principal=text[11],
        auth_method=auth_method,
    )
    source = (
        None
        if numeric[3] == 0
        else SshProcessHold(
            hostname=affinity.client_identity,
            pid=numeric[3],
            process_object_id=text[13],
            session_object_id=affinity.client_session_object_id,
            principal=text[14],
            started_at=_datetime_from_us(numeric[4]),
            required_until=_datetime_from_us(numeric[5]),
        )
    )
    receiver = SshProcessHold(
        hostname=affinity.server_identity,
        pid=numeric[6],
        process_object_id=text[15],
        session_object_id=affinity.server_session_object_id,
        principal=affinity.principal,
        started_at=_datetime_from_us(numeric[7]),
        required_until=_datetime_from_us(numeric[8]),
    )
    transport = SshTransportPlan(
        transport_id=text[0],
        zeek_uid=text[1],
        conn_id=text[2],
        source_ip=text[3],
        server_ip=text[4],
        source_port=source_port,
        server_port=server_port,
        opened_at=_datetime_from_us(numeric[0]),
        closes_at=_datetime_from_us(numeric[1]),
        receiver_process=receiver,
        source_process=source,
    )
    binding = SshSessionBinding(
        hostname=affinity.server_identity,
        logon_id=text[5],
        session_object_id=affinity.server_session_object_id,
        lifecycle_group_id=text[6],
        principal=affinity.principal,
        ready_at=_datetime_from_us(numeric[2]),
    )
    return SshSessionView(
        channel_id=channel_id,
        ssh_session_id=channel_id.replace("ssh-channel-", "ssh-protocol-session-", 1),
        affinity=affinity,
        transport=transport,
        binding=binding,
    )


def _pack_operation(lease: SshOperationLease) -> bytes:
    texts = (
        lease.operation_id,
        lease.child_channel_id,
        lease.channel_id,
        lease.semantic_operation_id,
        lease.parent_operation_id,
    )
    lengths, payload = _encode_text_fields(texts, "operation")
    return (
        _OPERATION_HEADER.pack(
            _OPERATION_KIND_TO_CODE[lease.kind],
            lease.ordinal,
            _datetime_us(lease.started_at),
            _datetime_us(lease.ended_at),
            lease.initiator_bytes,
            lease.responder_bytes,
            *lengths,
        )
        + payload
    )


@dataclass(frozen=True, slots=True)
class _PackedOperation:
    operation_id: str
    child_channel_id: str
    channel_id: str
    semantic_operation_id: str
    parent_operation_id: str
    kind: SshOperationKind
    ordinal: int
    started_at: datetime
    ended_at: datetime
    initiator_bytes: int
    responder_bytes: int


def _unpack_operation(row: bytes | memoryview) -> _PackedOperation:
    values = _OPERATION_HEADER.unpack_from(row)
    kind_code, ordinal, started_us, ended_us, initiator_bytes, responder_bytes = values[:6]
    lengths = tuple(values[6 : 6 + _OPERATION_TEXT_FIELDS])
    text = _decode_text_fields(row, offset=_OPERATION_HEADER.size, lengths=lengths)
    try:
        kind = _OPERATION_CODE_TO_KIND[kind_code]
    except KeyError as exc:  # pragma: no cover - internal encoder invariant
        raise StateError(f"Corrupt packed SSH operation kind {kind_code}") from exc
    return _PackedOperation(
        operation_id=text[0],
        child_channel_id=text[1],
        channel_id=text[2],
        semantic_operation_id=text[3],
        parent_operation_id=text[4],
        kind=kind,
        ordinal=ordinal,
        started_at=_datetime_from_us(started_us),
        ended_at=_datetime_from_us(ended_us),
        initiator_bytes=initiator_bytes,
        responder_bytes=responder_bytes,
    )


class _PackedSshSessionStore:
    """Packed open-session rows with one exact collision-checked local route.

    The common registry already owns exact transport and affinity routes.  The
    SSH sidecar retains only channel-to-row resolution and verifies the rich
    affinity/transport after the common route selects its single candidate.
    """

    def __init__(self) -> None:
        # The channel digest, common auth methods, and duplicate client/source
        # identity are represented as compact primitives. A 456-byte slot
        # covers realistic fleet rows without an overflow object; arbitrary
        # long public values retain the exact one-row overflow fallback.
        self._rows = PackedByteRowStore(inline_slot_bytes=456, chunk_slots=256)
        self._channels = PackedUniqueDigestMap(b"ef-ssh-channel")
        self._close_locators = array("I")
        self._close_generations = array("I")
        self._handle_generations = array("I")
        self._generation_epoch = 1
        self._decoded: OrderedDict[int, SshSessionView] = OrderedDict()
        self._decoded_bytes = 0
        self.lookup_candidates_inspected = 0

    def __len__(self) -> int:
        return len(self._rows)

    @staticmethod
    def _channel_route_digest(channel_id: str) -> int | None:
        prefix = "ssh-channel-"
        if not channel_id.startswith(prefix):
            return None
        semantic = channel_id[len(prefix) :]
        if len(semantic) != 32:
            return None
        try:
            return int(semantic[:16], 16)
        except ValueError:
            return None

    @staticmethod
    def _estimated_view_bytes(view: SshSessionView) -> int:
        values: list[object] = [
            view,
            view.affinity,
            view.transport,
            view.binding,
            view.transport.receiver_process,
        ]
        if view.transport.source_process is not None:
            values.append(view.transport.source_process)
        values.extend(
            value
            for value in (
                view.channel_id,
                view.ssh_session_id,
                view.affinity.client_identity,
                view.affinity.client_session_object_id,
                view.affinity.server_identity,
                view.affinity.server_session_object_id,
                view.affinity.principal,
                view.affinity.auth_method,
                view.transport.transport_id,
                view.transport.zeek_uid,
                view.transport.conn_id,
                view.transport.source_ip,
                view.transport.server_ip,
                view.binding.logon_id,
                view.binding.lifecycle_group_id,
                view.transport.receiver_process.process_object_id,
                ""
                if view.transport.source_process is None
                else view.transport.source_process.process_object_id,
            )
        )
        return sum(sys.getsizeof(value) for value in values)

    def _decode(self, handle: int) -> SshSessionView:
        cached = self._decoded.get(handle)
        if cached is not None:
            self._decoded.move_to_end(handle)
            return cached
        view = _unpack_session(self._rows.get_by_handle(handle))
        if len(self._decoded) >= _DEFAULT_DECODED_CACHE_PER_SHARD:
            _old_handle, old = self._decoded.popitem(last=False)
            self._decoded_bytes -= self._estimated_view_bytes(old)
        self._decoded[handle] = view
        self._decoded_bytes += self._estimated_view_bytes(view)
        return view

    @staticmethod
    def _verify(actual: object, expected: object, route_name: str) -> None:
        if actual != expected:
            raise StateError(f"SSH packed {route_name} digest collision")

    def get(self, channel_id: str) -> SshSessionView | None:
        located = self.locate(channel_id)
        return None if located is None else located[0]

    def locate(self, channel_id: str) -> tuple[SshSessionView, int, int] | None:
        """Return one exact view with its compact ABA-safe row token."""

        digest = self._channel_route_digest(channel_id)
        if digest is None:
            return None
        handle = self._channels.get_digest(digest)
        if handle is None:
            return None
        self.lookup_candidates_inspected += 1
        view = self._decode(handle)
        self._verify(view.channel_id, channel_id, "channel route")
        return view, handle, self.generation(handle)

    def get_by_handle(self, handle: int) -> SshSessionView:
        self.lookup_candidates_inspected += 1
        return self._decode(handle)

    def handle_for(self, channel_id: str) -> int:
        digest = self._channel_route_digest(channel_id)
        handle = None if digest is None else self._channels.get_digest(digest)
        if handle is None:
            raise KeyError(channel_id)
        self._verify(self._decode(handle).channel_id, channel_id, "channel route")
        return handle

    def insert(
        self,
        view: SshSessionView,
        *,
        packed_row: bytes | None = None,
        channel_route_digest: int | None = None,
    ) -> int:
        route_digest = (
            self._channel_route_digest(view.channel_id)
            if channel_route_digest is None
            else channel_route_digest
        )
        assert route_digest is not None
        retained_channel = self._channels.get_digest(route_digest)
        if retained_channel is not None:
            retained = self._decode(retained_channel)
            self._verify(retained.channel_id, view.channel_id, "channel route")
            raise StateError(f"Duplicate SSH channel_id {view.channel_id!r}")
        handle = self._rows.insert(_pack_session(view) if packed_row is None else packed_row)
        while len(self._close_locators) <= handle:
            self._close_locators.append(0)
            self._close_generations.append(0)
            self._handle_generations.append(0)
        self._close_locators[handle] = 0
        self._close_generations[handle] = 0
        generation = self._handle_generations[handle] + 1
        if generation >= 1 << 32:  # pragma: no cover - impossible in a generation window
            raise OverflowError("SSH sidecar exhausted a compact handle generation")
        self._handle_generations[handle] = generation
        self._channels.set_digest(route_digest, handle)
        return handle

    def generation(self, handle: int) -> int:
        """Return one live row's epoch-fenced ABA generation."""

        self._rows.get_by_handle(handle)
        return (self._generation_epoch << 32) | self._handle_generations[handle]

    def matches_generation(self, handle: int, generation: int) -> bool:
        """Return whether a direct hot-cache locator still owns a live row."""

        try:
            retained = self.generation(handle)
        except KeyError:
            return False
        return retained == generation

    def bind_close_token(
        self,
        channel_id: str,
        token: ApplicationChannelCloseToken,
    ) -> None:
        """Bind the shared registry's compact ABA-safe close token."""

        handle = self.handle_for(channel_id)
        self._close_locators[handle] = token.locator
        self._close_generations[handle] = token.generation

    def bind_close_token_by_handle(
        self,
        handle: int,
        token: ApplicationChannelCloseToken,
    ) -> None:
        """Bind a token to the insertion handle without decoding its row."""

        self._rows.get_by_handle(handle)
        self._close_locators[handle] = token.locator
        self._close_generations[handle] = token.generation

    def close_token_by_handle(self, handle: int) -> ApplicationChannelCloseToken:
        """Return the compact shared close token for one retained sidecar."""

        self._rows.get_by_handle(handle)
        generation = self._close_generations[handle]
        if generation == 0:
            raise StateError("SSH sidecar has no shared application close token")
        return ApplicationChannelCloseToken(
            locator=self._close_locators[handle],
            generation=generation,
        )

    def delete(self, channel_id: str) -> SshSessionView | None:
        channel_digest = self._channel_route_digest(channel_id)
        handle = None if channel_digest is None else self._channels.get_digest(channel_digest)
        if handle is None:
            return None
        view = self._decode(handle)
        self._verify(view.channel_id, channel_id, "channel route")
        assert channel_digest is not None
        self._channels.pop_digest(channel_digest)
        self._rows.delete(handle)
        self._close_locators[handle] = 0
        self._close_generations[handle] = 0
        cached = self._decoded.pop(handle, None)
        if cached is not None:
            self._decoded_bytes -= self._estimated_view_bytes(cached)
        if not self._rows:
            self._close_locators = array("I")
            self._close_generations = array("I")
            self._handle_generations = array("I")
            self._generation_epoch += 1
        return view

    def compact(self) -> None:
        force = not self._rows
        self._channels.compact_primary(force=force)

    @property
    def decoded_entries(self) -> int:
        return len(self._decoded)

    @property
    def estimated_value_bytes(self) -> int:
        return self._rows.estimated_value_bytes + sys.getsizeof(self._decoded) + self._decoded_bytes

    def metrics(self) -> tuple[IndexMetrics, tuple[IndexMetrics, ...]]:
        token_metrics = IndexMetrics(
            live_entries=len(self._rows),
            backing_entries=len(self._close_locators),
            stale_entries=max(0, len(self._close_locators) - len(self._rows)),
            allocated_slots=len(self._close_locators),
            high_water_mark=len(self._close_locators),
            estimated_bytes=(
                sys.getsizeof(self._close_locators)
                + sys.getsizeof(self._close_generations)
                + sys.getsizeof(self._handle_generations)
            ),
        )
        return (
            self._rows.metrics(estimate_bytes=True),
            (
                self._channels.metrics(estimate_bytes=True),
                token_metrics,
            ),
        )


class _PackedSshOperationStore:
    """Packed active-child rows; completed children leave no sidecar history."""

    def __init__(self) -> None:
        self._rows = PackedByteRowStore(inline_slot_bytes=256, chunk_slots=256)
        self._decoded: OrderedDict[int, _PackedOperation] = OrderedDict()
        self._decoded_bytes = 0

    def __len__(self) -> int:
        return len(self._rows)

    @staticmethod
    def _estimated_operation_bytes(operation: _PackedOperation) -> int:
        return sum(
            sys.getsizeof(value)
            for value in (
                operation,
                operation.operation_id,
                operation.child_channel_id,
                operation.channel_id,
                operation.semantic_operation_id,
                operation.parent_operation_id,
            )
        )

    def _decode(self, handle: int) -> _PackedOperation:
        cached = self._decoded.get(handle)
        if cached is not None:
            self._decoded.move_to_end(handle)
            return cached
        operation = _unpack_operation(self._rows.get_by_handle(handle))
        if len(self._decoded) >= _DEFAULT_DECODED_CACHE_PER_SHARD:
            _old_handle, old = self._decoded.popitem(last=False)
            self._decoded_bytes -= self._estimated_operation_bytes(old)
        self._decoded[handle] = operation
        self._decoded_bytes += self._estimated_operation_bytes(operation)
        return operation

    def insert(self, lease: SshOperationLease) -> int:
        return self._rows.insert(_pack_operation(lease))

    def get_by_handle(self, handle: int) -> _PackedOperation:
        return self._decode(handle)

    def delete(self, handle: int) -> _PackedOperation:
        operation = self._decode(handle)
        self._rows.delete(handle)
        cached = self._decoded.pop(handle, None)
        if cached is not None:
            self._decoded_bytes -= self._estimated_operation_bytes(cached)
        return operation

    @property
    def decoded_entries(self) -> int:
        return len(self._decoded)

    @property
    def estimated_value_bytes(self) -> int:
        return self._rows.estimated_value_bytes + sys.getsizeof(self._decoded) + self._decoded_bytes

    def metrics(self) -> IndexMetrics:
        return self._rows.metrics(estimate_bytes=True)


class _MutationGate:
    """Allow disjoint owner mutations while giving watermarks exclusive admission."""

    def __init__(self) -> None:
        self._condition = Condition(Lock())
        self._readers = 0
        self._writer = False
        self._waiting_writers = 0

    @contextmanager
    def mutation(self) -> Iterator[None]:
        """Enter a non-exclusive mutation lane."""

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
        """Enter the exclusive canonical-watermark lane."""

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


@dataclass(frozen=True, slots=True)
class _SshSessionHotCacheEntry:
    """One exact direct locator into a stable owner shard."""

    shard_id: int
    handle: int
    generation: int
    view: SshSessionView


@dataclass(slots=True)
class _SshShard:
    """Open-only SSH protocol state for one stable shared owner partition."""

    shard_id: int
    lock: RLock = field(default_factory=RLock)
    sessions: _PackedSshSessionStore = field(default_factory=_PackedSshSessionStore)
    operations: _PackedSshOperationStore = field(default_factory=_PackedSshOperationStore)
    expiry: PackedHandleExpiryIndex = field(default_factory=PackedHandleExpiryIndex)
    high_water_mark: int = 0


@dataclass(slots=True)
class _OperationRoutePartition:
    """Lazy exact active-child routes into stable owner shards."""

    partition_id: int
    lock: RLock = field(default_factory=RLock)
    operations: PackedUniqueDigestMap = field(
        default_factory=lambda: PackedUniqueDigestMap(b"ef-ssh-op")
    )
    children: PackedUniqueDigestMap = field(
        default_factory=lambda: PackedUniqueDigestMap(b"ef-ssh-child")
    )
    lookup_candidates_inspected: int = 0


def _stable_partition(namespace: str, value: str, count: int) -> int:
    material = f"{namespace}\0{value}".encode()
    digest = hashlib.blake2b(material, digest_size=8).digest()
    return int.from_bytes(digest, "big") % count


@contextmanager
def _stable_locks(entries: list[tuple[tuple[int, int], RLock]]) -> Iterator[None]:
    unique: dict[int, tuple[tuple[int, int], RLock]] = {}
    for token, lock in entries:
        unique.setdefault(id(lock), (token, lock))
    ordered = sorted(unique.values(), key=lambda item: item[0])
    for _token, lock in ordered:
        lock.acquire()
    try:
        yield
    finally:
        for _token, lock in reversed(ordered):
            lock.release()


class SshApplicationChannelManager:
    """Own exact bounded SSH sessions and active child-channel operations."""

    def __init__(
        self,
        *,
        application_registry: ApplicationChannelRegistry,
        window_start: datetime,
        window_end: datetime,
    ) -> None:
        """Create an SSH manager over the engine-owned application registry."""

        self._window_start = _canonical_utc(window_start)
        self._window_end = _canonical_utc(window_end)
        if self._window_end < self._window_start:
            raise ValueError("SSH window_end cannot precede window_start")
        if (
            application_registry.window_start != self._window_start
            or application_registry.window_end != self._window_end
        ):
            raise ValueError("SSH and shared application-channel windows must match exactly")
        self._registry = application_registry
        self._shard_count = application_registry.shard_count
        self._shards: dict[int, _SshShard] = {}
        self._operation_routes: list[_OperationRoutePartition | None] = [None] * self._shard_count
        self._session_hot_cache: OrderedDict[str, _SshSessionHotCacheEntry] = OrderedDict()
        self._session_hot_cache_lock = RLock()
        self._session_hot_cache_bytes = 0
        self._session_hot_cache_candidates = 0
        self._directory_lock = RLock()
        self._gate = _MutationGate()
        self._watermark_lane = Lock()
        self._watermark = self._window_start
        self._prepared_lock = RLock()
        self._admission_secret = secrets.token_bytes(32)
        self._manager_id = f"ssh-manager-{secrets.token_hex(16)}"
        self._next_prepared_reservation_id = 1
        self._prepared_admissions: dict[int, SshChannelAdmissionToken] = {}
        self._prepared_capabilities: dict[int, _SshAdmissionCapability] = {}
        self._claimed_admissions: set[int] = set()
        self._prepared_channel_ids: dict[str, int] = {}

    @property
    def application_registry(self) -> ApplicationChannelRegistry:
        """Return the injected engine-owned common registry."""

        return self._registry

    @property
    def manager_id(self) -> str:
        """Return the stable opaque identity of this manager instance."""

        return self._manager_id

    def authenticates_admission_token(self, token: SshChannelAdmissionToken) -> bool:
        """Return whether one intact manager/common token pair remains active."""

        if not isinstance(token, SshChannelAdmissionToken):
            return False
        with self._prepared_lock:
            try:
                capability = self._active_prepared_admission_locked(token)
            except StateError:
                return False
        return self._registry.authenticates_admission_token(capability.application_token)

    def authenticates_admission_receipt(self, receipt: SshChannelAdmissionReceipt) -> bool:
        """Return whether this manager issued the exact coupled commit receipt."""

        if not isinstance(receipt, SshChannelAdmissionReceipt):
            return False
        if (
            receipt.manager_kind != "ssh"
            or receipt.manager_id != self._manager_id
            or receipt._manager_token != id(self)
            or not isinstance(receipt.application_receipt, ApplicationChannelAdmissionReceipt)
            or not isinstance(receipt.session, SshSessionView)
            or not isinstance(receipt.operation, SshOperationLease)
        ):
            return False
        if not self._registry.authenticates_admission_receipt(receipt.application_receipt):
            return False
        expected = _ssh_admission_receipt_integrity_token(self._admission_secret, receipt)
        if not hmac.compare_digest(receipt._integrity_token, expected):
            return False
        application = receipt.application_receipt
        return (
            receipt.application_receipt_token == application.receipt_token
            and receipt.channel_id == application.channel_id == receipt.session.channel_id
            and receipt.ssh_session_id == receipt.session.ssh_session_id
            and receipt.operation_id == application.operation_id == receipt.operation.operation_id
            and receipt.operation.channel_id == receipt.channel_id
            and receipt.operation.session == receipt.session
            and receipt.transport_ids
            == (application.snapshot.identity.binding.transport_id,)
            == (receipt.session.transport.transport_id,)
            and receipt.sidecar_result_digest
            == ssh_channel_sidecar_result_digest(receipt.session, receipt.operation)
        )

    @property
    def watermark_time(self) -> datetime:
        """Return the manager's committed canonical watermark."""

        return self._watermark

    def _shard(self, owner_id: str, *, create: bool) -> _SshShard | None:
        shard_id = self._registry.owner_partition_id(owner_id)
        shard = self._shards.get(shard_id)
        if shard is not None or not create:
            return shard
        with self._directory_lock:
            shard = self._shards.get(shard_id)
            if shard is None:
                shard = _SshShard(shard_id=shard_id)
                self._shards[shard_id] = shard
            return shard

    def owner_partition_id(self, affinity: SshChannelAffinity) -> int:
        """Return the stable shared owner partition for concurrency probes."""

        return self._registry.owner_partition_id(affinity.owner_id)

    def _operation_route(
        self,
        semantic_id: str,
        *,
        create: bool,
    ) -> _OperationRoutePartition | None:
        partition_id = _stable_partition("ssh-operation-route", semantic_id, self._shard_count)
        route = self._operation_routes[partition_id]
        if route is not None or not create:
            return route
        with self._directory_lock:
            route = self._operation_routes[partition_id]
            if route is None:
                route = _OperationRoutePartition(partition_id=partition_id)
                self._operation_routes[partition_id] = route
            return route

    @staticmethod
    def _route_lock(route: _OperationRoutePartition) -> tuple[tuple[int, int], RLock]:
        return (0, route.partition_id), route.lock

    @staticmethod
    def _shard_lock(shard: _SshShard) -> tuple[tuple[int, int], RLock]:
        return (1, shard.shard_id), shard.lock

    def _pack_locator(self, shard_id: int, handle: int) -> int:
        return handle * self._shard_count + shard_id

    def _unpack_locator(self, locator: int) -> tuple[int, int]:
        handle, shard_id = divmod(locator, self._shard_count)
        return shard_id, handle

    def _cache_session(
        self,
        *,
        shard_id: int,
        handle: int,
        generation: int,
        view: SshSessionView,
    ) -> None:
        entry = _SshSessionHotCacheEntry(
            shard_id=shard_id,
            handle=handle,
            generation=generation,
            view=view,
        )
        with self._session_hot_cache_lock:
            prior = self._session_hot_cache.pop(view.channel_id, None)
            if prior is not None:
                self._session_hot_cache_bytes -= self._estimated_hot_cache_entry(prior)
            self._session_hot_cache[view.channel_id] = entry
            self._session_hot_cache_bytes += self._estimated_hot_cache_entry(entry)
            self._session_hot_cache.move_to_end(view.channel_id)
            while len(self._session_hot_cache) > _DEFAULT_SESSION_HOT_CACHE:
                _channel_id, evicted = self._session_hot_cache.popitem(last=False)
                self._session_hot_cache_bytes -= self._estimated_hot_cache_entry(evicted)

    @staticmethod
    def _estimated_hot_cache_entry(entry: _SshSessionHotCacheEntry) -> int:
        return sys.getsizeof(entry) + _PackedSshSessionStore._estimated_view_bytes(entry.view)

    def _cached_session(self, channel_id: str) -> SshSessionView | None:
        with self._session_hot_cache_lock:
            entry = self._session_hot_cache.get(channel_id)
            if entry is None:
                return None
            self._session_hot_cache.move_to_end(channel_id)
        shard = self._shards.get(entry.shard_id)
        if shard is not None:
            with shard.lock:
                if shard.sessions.matches_generation(entry.handle, entry.generation):
                    with self._session_hot_cache_lock:
                        self._session_hot_cache_candidates += 1
                    return entry.view
        with self._session_hot_cache_lock:
            if self._session_hot_cache.get(channel_id) is entry:
                self._session_hot_cache.pop(channel_id, None)
                self._session_hot_cache_bytes -= self._estimated_hot_cache_entry(entry)
        return None

    def _evict_cached_session(self, channel_id: str) -> None:
        with self._session_hot_cache_lock:
            evicted = self._session_hot_cache.pop(channel_id, None)
            if evicted is not None:
                self._session_hot_cache_bytes -= self._estimated_hot_cache_entry(evicted)

    def _require_time(
        self,
        value: datetime,
        field_name: str,
        *,
        allow_end: bool = False,
    ) -> datetime:
        canonical = _canonical_utc(value)
        after_end = canonical > self._window_end or (
            canonical == self._window_end and not allow_end
        )
        if canonical < self._window_start or after_end:
            raise StateError(
                f"{field_name} {canonical.isoformat()} is outside the SSH window "
                f"[{self._window_start.isoformat()}, {self._window_end.isoformat()})"
            )
        return canonical

    @staticmethod
    def _channel_digest(affinity: SshChannelAffinity, transport_id: str) -> bytes:
        return hashlib.blake2b(
            affinity._digest_bytes + transport_id.encode("utf-8"),
            digest_size=16,
            person=b"ef-ssh-channel2",
        ).digest()

    @classmethod
    def _channel_id(cls, affinity: SshChannelAffinity, transport_id: str) -> str:
        return f"ssh-channel-{cls._channel_digest(affinity, transport_id).hex()}"

    @staticmethod
    def _session_id(channel_id: str, session_object_id: str) -> str:
        # The channel digest already includes the exact server session object
        # through its affinity. A source-specific prefix gives the protocol
        # session a distinct typed ID without hashing the same identity twice.
        del session_object_id
        return channel_id.replace("ssh-channel-", "ssh-protocol-session-", 1)

    @staticmethod
    def _child_channel_id(
        channel_id: str,
        semantic_operation_id: str,
        kind: SshOperationKind,
        *,
        channel_digest: bytes | None = None,
    ) -> str:
        digest = hashlib.blake2b(
            (
                bytes.fromhex(channel_id.removeprefix("ssh-channel-"))
                if channel_digest is None
                else channel_digest
            )
            + bytes((_OPERATION_KIND_TO_CODE[kind],))
            + semantic_operation_id.encode("utf-8"),
            digest_size=16,
            person=b"ef-ssh-child-v2",
        ).hexdigest()
        return f"ssh-child-channel-{digest}"

    @staticmethod
    def _operation_id(child_channel_id: str, semantic_operation_id: str) -> str:
        # The child-channel digest already commits to the semantic operation
        # ID. Preserve that digest with an operation-specific typed prefix.
        del semantic_operation_id
        return child_channel_id.replace("ssh-child-channel-", "ssh-operation-", 1)

    def _active_prepared_admission_locked(
        self,
        token: SshChannelAdmissionToken,
    ) -> _SshAdmissionCapability:
        """Return the manager-owned capability for one intact active token."""

        capability = self._prepared_capabilities.get(id(token))
        if capability is None:
            if token._manager_token != id(self):
                raise StateError("SSH channel admission token belongs to another manager")
            raise StateError("SSH channel admission token is stale or already consumed")
        active = self._prepared_admissions.get(capability.reservation_id)
        if active is not token:
            raise StateError("SSH channel admission token is stale or already consumed")
        if token.application_token is not capability.application_token:
            raise StateError(
                "SSH channel admission token no longer binds its exact common capability"
            )
        expected = _ssh_admission_integrity_token(self._admission_secret, token)
        if not hmac.compare_digest(token._integrity_token, capability.integrity_token) or not (
            hmac.compare_digest(expected, capability.integrity_token)
        ):
            raise StateError("SSH channel admission token integrity validation failed")
        return capability

    def _reject_prepared_channel_locked(self, channel_id: str) -> None:
        """Reject an SSH mutation crossing one reserved channel identity."""

        if channel_id in self._prepared_channel_ids:
            raise StateError(f"SSH channel identity {channel_id!r} has a prepared admission")

    def _register_prepared_admission_locked(
        self,
        token: SshChannelAdmissionToken,
        *,
        packed_session: bytes,
        channel_route_digest: int,
    ) -> None:
        """Retain reservation metadata and one trusted immutable SSH preimage."""

        expected = _ssh_admission_integrity_token(self._admission_secret, token)
        if not hmac.compare_digest(token._integrity_token, expected):
            raise StateError("SSH channel admission token integrity validation failed")
        for channel_id in token._reserved_channel_ids:
            self._reject_prepared_channel_locked(channel_id)
        capability = _SshAdmissionCapability(
            token_id=id(token),
            reservation_id=token._reservation_id,
            integrity_token=expected,
            application_token=token.application_token,
            trusted_token=deepcopy(token),
            owner_shard_id=token._owner_shard_id,
            reserved_channel_ids=token._reserved_channel_ids,
            packed_session=packed_session,
            channel_route_digest=channel_route_digest,
            linearization_time=token.linearization_time,
        )
        self._prepared_admissions[capability.reservation_id] = token
        self._prepared_capabilities[capability.token_id] = capability
        for channel_id in capability.reserved_channel_ids:
            self._prepared_channel_ids[channel_id] = capability.reservation_id

    def _release_prepared_capability_locked(
        self,
        capability: _SshAdmissionCapability,
    ) -> None:
        """Release SSH reservations using only manager-owned immutable keys."""

        active = self._prepared_admissions.pop(capability.reservation_id, None)
        retained = self._prepared_capabilities.pop(capability.token_id, None)
        if active is None or retained is not capability:
            return
        self._claimed_admissions.discard(capability.reservation_id)
        for channel_id in capability.reserved_channel_ids:
            if self._prepared_channel_ids.get(channel_id) == capability.reservation_id:
                self._prepared_channel_ids.pop(channel_id)
        if not self._prepared_admissions:
            self._prepared_admissions.clear()
            self._prepared_capabilities.clear()
            self._claimed_admissions.clear()
            self._prepared_channel_ids.clear()

    def _validate_prepared_sidecar_locked(
        self,
        capability: _SshAdmissionCapability,
    ) -> None:
        """Verify the exact SSH sidecar preimage without changing lookup state."""

        token = capability.trusted_token
        session = token.session
        if token.operation.session != session or token.operation.channel_id != session.channel_id:
            raise StateError("Prepared SSH operation no longer matches its exact session")
        if self._registry.owner_partition_id(session.owner_id) != capability.owner_shard_id:
            raise StateError("Prepared SSH owner partition changed before commit")
        shard = self._shards.get(capability.owner_shard_id)
        if shard is not None:
            with shard.lock:
                occupied = shard.sessions.get(session.channel_id)
            if occupied is not None:
                raise StateError("Prepared SSH channel identity became occupied")

    def channel_id_for(self, affinity: SshChannelAffinity, transport_id: str) -> str:
        """Return the deterministic channel ID for an immutable transport."""

        return self._channel_id(affinity, _required_text(transport_id, "transport_id"))

    def open_session(
        self,
        affinity: SshChannelAffinity,
        *,
        transport: SshTransportPlan,
        binding: SshSessionBinding,
        idle_timeout: timedelta,
        initiator_budget: int,
        responder_budget: int,
        operation_budget: int,
    ) -> SshSessionView:
        """Open one exact SSH session on a canonical TCP/22 transport."""

        _validate_session_contract(affinity, transport, binding)
        if idle_timeout <= timedelta(0):
            raise ValueError("SSH idle_timeout must be positive")
        self._require_time(transport.opened_at, "SSH transport opened_at")
        self._require_time(transport.closes_at, "SSH transport closes_at", allow_end=True)
        ready_at = self._require_time(binding.ready_at, "SSH session ready_at")
        if ready_at < self._watermark:
            raise StateError("SSH sessions cannot open before the current watermark")
        if initiator_budget < 0 or responder_budget < 0:
            raise ValueError("SSH channel byte budgets must be non-negative")
        if operation_budget <= 0:
            raise ValueError("SSH channel operation budget must be positive")
        budget = _validated_application_budget(
            initiator_bytes=initiator_budget,
            responder_bytes=responder_budget,
            operations=operation_budget,
        )
        channel_digest = self._channel_digest(affinity, transport.transport_id)
        channel_id = f"ssh-channel-{channel_digest.hex()}"
        view = SshSessionView(
            channel_id=channel_id,
            ssh_session_id=self._session_id(channel_id, binding.session_object_id),
            affinity=affinity,
            transport=transport,
            binding=binding,
        )
        packed_row = _pack_session(view, channel_digest=channel_digest)
        with self._gate.mutation():
            shard = self._shard(affinity.owner_id, create=True)
            assert shard is not None
            return self._open_session_locked(
                shard,
                view,
                ready_at=ready_at,
                idle_timeout=idle_timeout,
                budget=budget,
                packed_row=packed_row,
                channel_route_digest=int.from_bytes(channel_digest[:8], "big"),
            )

    def _open_session_locked(
        self,
        shard: _SshShard,
        view: SshSessionView,
        *,
        ready_at: datetime,
        idle_timeout: timedelta,
        budget: ApplicationChannelBudget,
        packed_row: bytes,
        channel_route_digest: int,
    ) -> SshSessionView:
        """Publish a validated session while its owner shard is locked."""

        affinity = view.affinity
        transport = view.transport
        channel_id = view.channel_id
        with shard.lock:
            if self._watermark > ready_at:
                raise StateError("SSH sessions cannot open before the current watermark")
            handle = shard.sessions.insert(
                view,
                packed_row=packed_row,
                channel_route_digest=channel_route_digest,
            )
            try:
                snapshot, close_token = self._registry.open_channel_with_token(
                    _validated_application_identity(
                        channel_id=channel_id,
                        owner_id=affinity.owner_id,
                        affinity_digest=affinity.digest,
                        transport=transport,
                        opened_at=ready_at,
                        idle_timeout=idle_timeout,
                        budget=budget,
                    )
                )
            except (StateError, ValueError):
                shard.sessions.delete(channel_id)
                raise
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
            return view

    def open_session_with_completed_operation(
        self,
        affinity: SshChannelAffinity,
        *,
        transport: SshTransportPlan,
        binding: SshSessionBinding,
        idle_timeout: timedelta,
        initiator_budget: int,
        responder_budget: int,
        operation_budget: int,
        kind: SshOperationKind,
        semantic_operation_id: str,
        started_at: datetime,
        ended_at: datetime,
        initiator_bytes: int = 0,
        responder_bytes: int = 0,
    ) -> tuple[SshSessionView, SshOperationLease]:
        """Compatibility wrapper that commits one prepared SSH admission."""

        token = self.prepare_open_session_with_completed_operation(
            affinity,
            transport=transport,
            binding=binding,
            idle_timeout=idle_timeout,
            initiator_budget=initiator_budget,
            responder_budget=responder_budget,
            operation_budget=operation_budget,
            kind=kind,
            semantic_operation_id=semantic_operation_id,
            started_at=started_at,
            ended_at=ended_at,
            initiator_bytes=initiator_bytes,
            responder_bytes=responder_bytes,
        )
        with self.prepared_admission(token) as prepared:
            admission = prepared.commit_no_fail()
        return admission.session, admission.operation

    def prepare_open_session_with_completed_operation(
        self,
        affinity: SshChannelAffinity,
        *,
        transport: SshTransportPlan,
        binding: SshSessionBinding,
        idle_timeout: timedelta,
        initiator_budget: int,
        responder_budget: int,
        operation_budget: int,
        kind: SshOperationKind,
        semantic_operation_id: str,
        started_at: datetime,
        ended_at: datetime,
        initiator_bytes: int = 0,
        responder_bytes: int = 0,
    ) -> SshChannelAdmissionToken:
        """Reserve one SSH session and synchronous first child without publishing.

        The completed child never enters either the SSH active-operation
        sidecar or the common registry's active-operation store. The common
        registry retains only its bounded used-ID marker and aggregate budget
        counters.
        """

        _validate_session_contract(affinity, transport, binding)
        if idle_timeout <= timedelta(0):
            raise ValueError("SSH idle_timeout must be positive")
        self._require_time(transport.opened_at, "SSH transport opened_at")
        self._require_time(transport.closes_at, "SSH transport closes_at", allow_end=True)
        ready_at = self._require_time(binding.ready_at, "SSH session ready_at")
        semantic_id = _required_text(semantic_operation_id, "semantic_operation_id")
        canonical_start = self._require_time(started_at, "SSH operation started_at")
        canonical_end = self._require_time(ended_at, "SSH operation ended_at", allow_end=True)
        if ready_at < self._watermark or canonical_start < self._watermark:
            raise StateError("SSH session and operation cannot precede the current watermark")
        if canonical_end < canonical_start:
            raise ValueError("SSH operation ended_at cannot precede started_at")
        if initiator_budget < 0 or responder_budget < 0:
            raise ValueError("SSH channel byte budgets must be non-negative")
        if operation_budget <= 0:
            raise ValueError("SSH channel operation budget must be positive")
        if initiator_bytes < 0 or responder_bytes < 0:
            raise ValueError("SSH operation byte reservations must be non-negative")
        if canonical_start < ready_at or canonical_end > transport.closes_at:
            raise StateError("SSH operation is outside its lifecycle session or TCP transport")
        source_hold = transport.source_process
        receiver_hold = transport.receiver_process
        if (
            source_hold is not None
            and not (
                source_hold.started_at <= canonical_start
                and canonical_end <= source_hold.required_until
            )
        ) or not (
            receiver_hold.started_at <= canonical_start
            and canonical_end <= receiver_hold.required_until
        ):
            raise StateError("SSH operation is outside a frozen process hold")
        budget = _validated_application_budget(
            initiator_bytes=initiator_budget,
            responder_bytes=responder_budget,
            operations=operation_budget,
        )
        channel_digest = self._channel_digest(affinity, transport.transport_id)
        channel_id = f"ssh-channel-{channel_digest.hex()}"
        session = SshSessionView(
            channel_id=channel_id,
            ssh_session_id=self._session_id(channel_id, binding.session_object_id),
            affinity=affinity,
            transport=transport,
            binding=binding,
        )
        child_channel_id = self._child_channel_id(
            channel_id,
            semantic_id,
            kind,
            channel_digest=channel_digest,
        )
        operation_id = self._operation_id(child_channel_id, semantic_id)
        lease = SshOperationLease(
            operation_id=operation_id,
            child_channel_id=child_channel_id,
            channel_id=channel_id,
            semantic_operation_id=semantic_id,
            parent_operation_id="",
            kind=kind,
            ordinal=0,
            started_at=canonical_start,
            ended_at=canonical_end,
            initiator_bytes=initiator_bytes,
            responder_bytes=responder_bytes,
            session=session,
        )
        identity = _validated_application_identity(
            channel_id=channel_id,
            owner_id=affinity.owner_id,
            affinity_digest=affinity.digest,
            transport=transport,
            opened_at=ready_at,
            idle_timeout=idle_timeout,
            budget=budget,
        )
        reservation = _validated_completed_operation(
            operation_id=operation_id,
            channel_id=channel_id,
            started_at=canonical_start,
            ended_at=canonical_end,
            initiator_bytes=initiator_bytes,
            responder_bytes=responder_bytes,
        )
        packed_row = _pack_session(session, channel_digest=channel_digest)
        channel_route_digest = int.from_bytes(channel_digest[:8], "big")
        owner_shard_id = self._registry.owner_partition_id(affinity.owner_id)
        with self._gate.mutation(), self._prepared_lock:
            if self._watermark > ready_at:
                raise StateError("SSH sessions cannot open before the current watermark")
            self._reject_prepared_channel_locked(channel_id)
            shard = self._shards.get(owner_shard_id)
            if shard is not None:
                with shard.lock:
                    if shard.sessions.get(channel_id) is not None:
                        raise StateError(f"Duplicate SSH channel_id {channel_id!r}")

        application_token = self._registry.prepare_open_channel_with_completed_operation(
            identity,
            reservation,
        )
        try:
            with self._gate.mutation(), self._prepared_lock:
                if self._watermark > ready_at:
                    raise StateError("SSH sessions cannot open before the current watermark")
                self._reject_prepared_channel_locked(channel_id)
                shard = self._shards.get(owner_shard_id)
                if shard is not None:
                    with shard.lock:
                        if shard.sessions.get(channel_id) is not None:
                            raise StateError("SSH sidecar changed during admission preparation")
                reservation_id = self._next_prepared_reservation_id
                self._next_prepared_reservation_id += 1
                token = SshChannelAdmissionToken(
                    kind="open_completed",
                    application_token=application_token,
                    session=session,
                    operation=lease,
                    _manager_token=id(self),
                    _reservation_id=reservation_id,
                    _owner_shard_id=owner_shard_id,
                    _reserved_channel_ids=(channel_id,),
                )
                token = replace(
                    token,
                    _integrity_token=_ssh_admission_integrity_token(
                        self._admission_secret,
                        token,
                    ),
                )
                self._register_prepared_admission_locked(
                    token,
                    packed_session=packed_row,
                    channel_route_digest=channel_route_digest,
                )
                return token
        except (StateError, ValueError):
            self._registry.cancel_prepared_admission(application_token)
            raise

    def cancel_prepared_admission(self, token: SshChannelAdmissionToken) -> bool:
        """Cancel one unclaimed SSH/common reservation without canonical mutation."""

        integrity_error: StateError | None = None
        with self._gate.mutation(), self._prepared_lock:
            capability = self._prepared_capabilities.get(id(token))
            if capability is None:
                return False
            try:
                capability = self._active_prepared_admission_locked(token)
            except StateError as error:
                integrity_error = error
                self._release_prepared_capability_locked(capability)
            else:
                if capability.reservation_id in self._claimed_admissions:
                    return False
                self._release_prepared_capability_locked(capability)
        common_error: StateError | None = None
        try:
            self._registry.cancel_prepared_admission(capability.application_token)
        except StateError as error:
            common_error = error
        if integrity_error is not None:
            raise integrity_error
        if common_error is not None:
            raise common_error
        return True

    def _claim_prepared_admission(
        self,
        token: SshChannelAdmissionToken,
    ) -> _SshAdmissionCapability:
        """Claim and revalidate one manager token without retaining SSH locks."""

        failure: StateError | None = None
        capability: _SshAdmissionCapability | None = None
        with self._gate.mutation(), self._prepared_lock:
            capability = self._prepared_capabilities.get(id(token))
            try:
                capability = self._active_prepared_admission_locked(token)
                if capability.reservation_id in self._claimed_admissions:
                    raise StateError("SSH channel admission token is already claimed")
                if capability.linearization_time < self._watermark:
                    raise StateError("SSH channel admission starts behind the canonical watermark")
                if not self._registry.authenticates_admission_token(capability.application_token):
                    raise StateError(
                        "SSH admission's common application token failed authentication"
                    )
                self._validate_prepared_sidecar_locked(capability)
                self._active_prepared_admission_locked(token)
            except StateError as error:
                failure = error
                if capability is not None:
                    self._release_prepared_capability_locked(capability)
            else:
                self._claimed_admissions.add(capability.reservation_id)
                return capability
        if capability is not None:
            try:
                self._registry.cancel_prepared_admission(capability.application_token)
            except StateError:
                pass
        assert failure is not None
        raise failure

    @contextmanager
    def prepared_admission(
        self,
        token: SshChannelAdmissionToken,
    ) -> Iterator[SshChannelPreparedCommit]:
        """Claim SSH and common tokens while retaining no locks across the body."""

        capability = self._claim_prepared_admission(token)
        transaction: SshChannelPreparedCommit | None = None
        try:
            with self._registry.prepared_admission(
                capability.application_token
            ) as application_commit:
                transaction = SshChannelPreparedCommit(
                    self,
                    token,
                    application_commit,
                )
                try:
                    yield transaction
                finally:
                    transaction._close()
        except BaseException:
            try:
                self._registry.cancel_prepared_admission(capability.application_token)
            except StateError:
                pass
            raise
        finally:
            if transaction is None or not transaction.committed:
                self._cancel_claimed_admission(token)

    def _cancel_claimed_admission(self, token: SshChannelAdmissionToken) -> None:
        """Release one manager claim after its external transaction aborts."""

        with self._gate.mutation(), self._prepared_lock:
            capability = self._prepared_capabilities.get(id(token))
            if capability is None:
                return
            try:
                self._active_prepared_admission_locked(token)
            except StateError:
                self._release_prepared_capability_locked(capability)
                return
            if capability.reservation_id not in self._claimed_admissions:
                raise StateError("SSH channel admission token is not claimed")
            self._release_prepared_capability_locked(capability)

    def _commit_claimed_admission(
        self,
        token: SshChannelAdmissionToken,
        application_commit: ApplicationChannelPreparedCommit,
    ) -> SshChannelAdmissionResult:
        """Commit one fully validated common admission, then its SSH sidecar."""

        with self._gate.mutation(), self._prepared_lock:
            capability = self._active_prepared_admission_locked(token)
            if capability.reservation_id not in self._claimed_admissions:
                raise StateError("SSH channel admission token is not claimed")
            if not self._registry.authenticates_admission_token(capability.application_token):
                raise StateError("SSH admission's common application token failed authentication")
            self._validate_prepared_sidecar_locked(capability)
            self._active_prepared_admission_locked(token)
            trusted_token = capability.trusted_token
            application_result = application_commit.commit_no_fail()
            application_receipt = application_result.receipt
            assert application_receipt is not None
            assert self._registry.authenticates_admission_receipt(application_receipt)
            assert (
                application_receipt.publication_token
                == trusted_token.application_token.publication_token
            )
            assert application_receipt.snapshot == application_result.snapshot
            assert application_receipt.close_token == application_result.close_token
            assert application_receipt.channel_id == trusted_token.session.channel_id
            assert application_receipt.operation_id == trusted_token.operation.operation_id
            close_token = application_result.close_token
            assert close_token is not None
            shard = self._shard(trusted_token.session.owner_id, create=True)
            assert shard is not None and shard.shard_id == capability.owner_shard_id
            with shard.lock:
                handle = shard.sessions.insert(
                    trusted_token.session,
                    packed_row=capability.packed_session,
                    channel_route_digest=capability.channel_route_digest,
                )
                shard.sessions.bind_close_token_by_handle(handle, close_token)
                snapshot = application_result.snapshot
                shard.expiry.set(
                    handle,
                    min(
                        snapshot.idle_deadline,
                        snapshot.identity.hard_deadline,
                        snapshot.identity.binding.closes_at,
                    ).timestamp(),
                )
                shard.high_water_mark = max(shard.high_water_mark, len(shard.sessions))
            receipt = SshChannelAdmissionReceipt(
                manager_kind="ssh",
                manager_id=self._manager_id,
                kind=trusted_token.kind,
                publication_token=capability.integrity_token,
                application_receipt=application_receipt,
                application_receipt_token=application_receipt.receipt_token,
                channel_id=application_receipt.channel_id,
                ssh_session_id=trusted_token.session.ssh_session_id,
                operation_id=application_receipt.operation_id,
                transport_ids=(application_receipt.snapshot.identity.binding.transport_id,),
                session=trusted_token.session,
                operation=trusted_token.operation,
                sidecar_result_digest=ssh_channel_sidecar_result_digest(
                    trusted_token.session,
                    trusted_token.operation,
                ),
                _manager_token=id(self),
            )
            receipt = replace(
                receipt,
                _integrity_token=_ssh_admission_receipt_integrity_token(
                    self._admission_secret,
                    receipt,
                ),
            )
            result = SshChannelAdmissionResult(
                session=trusted_token.session,
                operation=trusted_token.operation,
                application=application_result,
                receipt=receipt,
            )
            self._release_prepared_capability_locked(capability)
            return result

    def session_view(self, channel_id: str) -> SshSessionView | None:
        """Return one immutable open SSH sidecar through exact routing."""

        cached = self._cached_session(channel_id)
        if cached is not None:
            return cached
        shard_id = self._registry.owner_partition_for_channel(channel_id)
        if shard_id is None:
            return None
        shard = self._shards.get(shard_id)
        if shard is None:
            return None
        with shard.lock:
            located = shard.sessions.locate(channel_id)
            if located is None:
                return None
            view, handle, generation = located
            self._cache_session(
                shard_id=shard_id,
                handle=handle,
                generation=generation,
                view=view,
            )
            return view

    def find_by_transport(self, transport_id: str) -> SshSessionView | None:
        """Return the exact open SSH session bound to a canonical transport."""

        snapshot = self._registry.find_open_by_transport(transport_id)
        if snapshot is None or snapshot.identity.protocol != "ssh":
            return None
        shard = self._shard(snapshot.identity.owner_id, create=False)
        if shard is None:
            return None
        with shard.lock:
            session = shard.sessions.get(snapshot.channel_id)
            if session is None:
                return None
            if session.transport.transport_id != transport_id:
                raise StateError("SSH packed transport route digest collision")
            return session

    def find_reusable_session(
        self,
        affinity: SshChannelAffinity,
        *,
        at: datetime,
    ) -> SshSessionView | None:
        """Return one exact reusable SSH session after one candidate inspection."""

        canonical = self._require_time(at, "SSH reuse time")
        reusable = self._registry.find_reusable(
            affinity_digest=affinity.digest,
            owner_id=affinity.owner_id,
            at=canonical,
        )
        if reusable is None:
            return None
        shard = self._shard(affinity.owner_id, create=False)
        if shard is None:
            raise StateError("Reusable shared SSH channel has no owner sidecar shard")
        with shard.lock:
            session = shard.sessions.get(reusable.channel_id)
            if session is None:
                raise StateError("Reusable shared SSH channel has no protocol sidecar")
            if session.affinity != affinity:
                raise StateError("SSH packed affinity digest collision")
            return session

    @staticmethod
    def _same_session(actual: SshSessionView, expected: SshSessionView) -> bool:
        return actual == expected

    def reserve_operation(
        self,
        session: SshSessionView,
        *,
        kind: SshOperationKind,
        semantic_operation_id: str,
        started_at: datetime,
        ended_at: datetime,
        initiator_bytes: int = 0,
        responder_bytes: int = 0,
        parent_operation_id: str = "",
    ) -> SshOperationLease:
        """Reserve one exact contained SSH child channel and operation."""

        semantic_id = _required_text(semantic_operation_id, "semantic_operation_id")
        canonical_start = self._require_time(started_at, "SSH operation started_at")
        canonical_end = self._require_time(
            ended_at,
            "SSH operation ended_at",
            allow_end=True,
        )
        if canonical_end < canonical_start:
            raise ValueError("SSH operation ended_at cannot precede started_at")
        if initiator_bytes < 0 or responder_bytes < 0:
            raise ValueError("SSH operation byte reservations must be non-negative")
        if canonical_start < self._watermark:
            raise StateError("SSH operations cannot start before the current watermark")
        if (
            canonical_start < session.binding.ready_at
            or canonical_end > session.transport.closes_at
        ):
            raise StateError("SSH operation is outside its lifecycle session or TCP transport")
        source_hold = session.transport.source_process
        receiver_hold = session.transport.receiver_process
        if (
            source_hold is not None
            and not (
                source_hold.started_at <= canonical_start
                and canonical_end <= source_hold.required_until
            )
        ) or not (
            receiver_hold.started_at <= canonical_start
            and canonical_end <= receiver_hold.required_until
        ):
            raise StateError("SSH operation is outside a frozen process hold")
        child_channel_id = self._child_channel_id(session.channel_id, semantic_id, kind)
        operation_id = self._operation_id(child_channel_id, semantic_id)
        with self._gate.mutation():
            operation_route = self._operation_route(operation_id, create=True)
            child_route = self._operation_route(child_channel_id, create=True)
            shard = self._shard(session.owner_id, create=False)
            if shard is None or operation_route is None or child_route is None:
                raise StateError(f"Unknown SSH session {session.channel_id!r}")
            with _stable_locks(
                [
                    self._route_lock(operation_route),
                    self._route_lock(child_route),
                    self._shard_lock(shard),
                ]
            ):
                if canonical_start < self._watermark:
                    raise StateError("SSH operations cannot start before the current watermark")
                retained = shard.sessions.get(session.channel_id)
                if retained is None or not self._same_session(retained, session):
                    raise StateError("SSH operation session identity or transport binding is stale")
                if operation_route.operations.get(operation_id) is not None:
                    raise StateError(f"Duplicate active SSH operation_id {operation_id!r}")
                if child_route.children.get(child_channel_id) is not None:
                    raise StateError(f"Duplicate active SSH child_channel_id {child_channel_id!r}")
                snapshot = self._registry.get(session.channel_id)
                if snapshot is None or not snapshot.is_open:
                    raise StateError(f"SSH session {session.channel_id!r} is not open")
                if snapshot.identity.binding.transport_id != session.transport.transport_id:
                    raise StateError("SSH operation transport binding disagrees with the registry")
                prior_deadline = min(
                    snapshot.idle_deadline,
                    snapshot.identity.hard_deadline,
                    snapshot.identity.binding.closes_at,
                )
                ordinal = snapshot.reserved_operations
                lease = SshOperationLease(
                    operation_id=operation_id,
                    child_channel_id=child_channel_id,
                    channel_id=session.channel_id,
                    semantic_operation_id=semantic_id,
                    parent_operation_id=parent_operation_id.strip(),
                    kind=kind,
                    ordinal=ordinal,
                    started_at=canonical_start,
                    ended_at=canonical_end,
                    initiator_bytes=initiator_bytes,
                    responder_bytes=responder_bytes,
                    session=session,
                )
                handle = shard.operations.insert(lease)
                locator = self._pack_locator(shard.shard_id, handle)
                operation_route.operations[operation_id] = locator
                child_route.children[child_channel_id] = locator
                try:
                    updated = self._registry.reserve_operation(
                        ApplicationOperationReservation(
                            operation_id=operation_id,
                            channel_id=session.channel_id,
                            ordinal=ordinal,
                            started_at=canonical_start,
                            ended_at=canonical_end,
                            initiator_bytes=initiator_bytes,
                            responder_bytes=responder_bytes,
                            parent_operation_id=lease.parent_operation_id,
                        )
                    )
                except (StateError, ValueError):
                    operation_route.operations.pop(operation_id)
                    child_route.children.pop(child_channel_id)
                    shard.operations.delete(handle)
                    raise
                updated_deadline = min(
                    updated.idle_deadline,
                    updated.identity.hard_deadline,
                    updated.identity.binding.closes_at,
                )
                if updated_deadline != prior_deadline:
                    session_handle = shard.sessions.handle_for(session.channel_id)
                    shard.expiry.set(session_handle, updated_deadline.timestamp())
                shard.high_water_mark = max(
                    shard.high_water_mark,
                    len(shard.sessions) + len(shard.operations),
                )
                return lease

    def _operation_route_locator(
        self,
        operation_id: str,
    ) -> tuple[_OperationRoutePartition, int, int] | None:
        route = self._operation_route(operation_id, create=False)
        if route is None:
            return None
        with route.lock:
            locator = route.operations.get(operation_id)
            if locator is not None:
                route.lookup_candidates_inspected += 1
        if locator is None:
            return None
        shard_id, handle = self._unpack_locator(locator)
        return route, shard_id, handle

    def operation_lease(self, operation_id: str) -> SshOperationLease | None:
        """Return one exact active operation without retaining completed history."""

        routed = self._operation_route_locator(operation_id)
        if routed is None:
            return None
        route, shard_id, handle = routed
        shard = self._shards.get(shard_id)
        if shard is None:
            return None
        with _stable_locks([self._route_lock(route), self._shard_lock(shard)]):
            locator = self._pack_locator(shard_id, handle)
            if route.operations.get(operation_id) != locator:
                return None
            try:
                operation = shard.operations.get_by_handle(handle)
            except KeyError:
                return None
            if operation.operation_id != operation_id:
                raise StateError("SSH packed operation route digest collision")
            session = shard.sessions.get(operation.channel_id)
            if session is None:
                raise StateError("Active SSH operation lost its parent session")
            return SshOperationLease(
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

    def finalize_operation(self, operation_id: str) -> bool:
        """Finalize one active SSH child; repeated finalization is a no-op."""

        routed = self._operation_route_locator(operation_id)
        if routed is None:
            return False
        operation_route, shard_id, handle = routed
        shard = self._shards.get(shard_id)
        if shard is None:
            return False
        with (
            self._gate.mutation(),
            _stable_locks([self._route_lock(operation_route), self._shard_lock(shard)]),
        ):
            locator = self._pack_locator(shard_id, handle)
            if operation_route.operations.get(operation_id) != locator:
                return False
            try:
                operation = shard.operations.get_by_handle(handle)
            except KeyError:
                return False
            child_route = self._operation_route(operation.child_channel_id, create=False)
            if child_route is None:
                raise StateError("Active SSH operation lost its child-channel route")
        # Reacquire every route in stable order because the child route may be
        # distinct from the operation route.  No sidecar value escapes the lock.
        with (
            self._gate.mutation(),
            _stable_locks(
                [
                    self._route_lock(operation_route),
                    self._route_lock(child_route),
                    self._shard_lock(shard),
                ]
            ),
        ):
            locator = self._pack_locator(shard_id, handle)
            if operation_route.operations.get(operation_id) != locator:
                return False
            operation = shard.operations.get_by_handle(handle)
            if not self._registry.finalize_operation(operation_id):
                raise StateError("Active SSH sidecar operation is absent from the shared registry")
            operation_route.operations.pop(operation_id)
            if child_route.children.get(operation.child_channel_id) == locator:
                child_route.children.pop(operation.child_channel_id)
            shard.operations.delete(handle)
            return True

    @staticmethod
    def _closure(
        session: SshSessionView,
        *,
        closed_at: datetime,
        reason: str,
        retirement_proof: ApplicationChannelRetirementProof,
    ) -> SshChannelClosure:
        return SshChannelClosure(
            channel_id=session.channel_id,
            ssh_session_id=session.ssh_session_id,
            logon_id=session.binding.logon_id,
            session_object_id=session.binding.session_object_id,
            lifecycle_group_id=session.binding.lifecycle_group_id,
            principal=session.binding.principal,
            transport_id=session.transport.transport_id,
            closed_at=closed_at,
            reason=reason,
            source_process=session.transport.source_process,
            receiver_process=session.transport.receiver_process,
            retirement_proof=retirement_proof,
        )

    def _retire_locked(
        self,
        shard: _SshShard,
        session: SshSessionView,
        *,
        at: datetime,
        reason: str,
    ) -> SshChannelClosure:
        snapshot = self._registry.get(session.channel_id)
        close_time = _canonical_utc(at)
        retirement_proof: ApplicationChannelRetirementProof
        handle = shard.sessions.handle_for(session.channel_id)
        if snapshot is not None and snapshot.is_open:
            if snapshot.active_operations:
                raise StateError(
                    f"SSH channel {session.channel_id!r} cannot close with active operations"
                )
            effective_deadline = min(
                snapshot.idle_deadline,
                snapshot.identity.hard_deadline,
                snapshot.identity.binding.closes_at,
            )
            close_time = min(
                effective_deadline,
                max(close_time, snapshot.identity.opened_at, snapshot.last_activity_at),
            )
            close_result = self._registry.close_channel_by_token(
                session.channel_id,
                token=shard.sessions.close_token_by_handle(handle),
                closed_at=close_time,
                reason=reason,
                include_retirement_proof=True,
            )
            close_time = close_result.closed_at
            if close_result.retirement_proof is None:
                raise StateError("SSH channel close returned no retirement proof")
            retirement_proof = close_result.retirement_proof
        elif snapshot is not None and snapshot.closed_at is not None:
            close_time = snapshot.closed_at
            retirement_proof = self._registry.retirement_proof(session.channel_id)
        else:
            raise StateError("SSH sidecar lost its shared application retirement owner")
        shard.expiry.pop(handle, None)
        shard.sessions.delete(session.channel_id)
        self._evict_cached_session(session.channel_id)
        return self._closure(
            session,
            closed_at=close_time,
            reason=retirement_proof.snapshot.close_reason,
            retirement_proof=retirement_proof,
        )

    def close_session(
        self,
        channel_id: str,
        *,
        closed_at: datetime,
        reason: str,
    ) -> SshChannelClosure | None:
        """Close one SSH session idempotently and return a lock-free intent."""

        canonical = self._require_time(closed_at, "SSH session closed_at", allow_end=True)
        if canonical < self._watermark:
            raise StateError("SSH sessions cannot close before the current watermark")
        snapshot = self._registry.get(channel_id)
        if snapshot is None or snapshot.identity.protocol != "ssh":
            return None
        shard = self._shard(snapshot.identity.owner_id, create=False)
        if shard is None:
            return None
        with self._gate.mutation(), shard.lock:
            session = shard.sessions.get(channel_id)
            if session is None:
                return None
            return self._retire_locked(shard, session, at=canonical, reason=reason)

    def _compact_sidecars(self, max_work: int) -> None:
        if max_work <= 0:
            return
        with self._directory_lock:
            shards = tuple(self._shards.values())
            routes = tuple(route for route in self._operation_routes if route is not None)
        remaining = max_work
        for shard in sorted(shards, key=lambda item: item.shard_id):
            if remaining <= 0:
                break
            with shard.lock:
                shard.sessions.compact()
                remaining -= shard.expiry.compact(max_slots=remaining)
        for route in sorted(routes, key=lambda item: item.partition_id):
            if remaining <= 0:
                break
            with route.lock:
                force = not route.operations and not route.children
                route.operations.compact_primary(force=force)
                route.children.compact_primary(force=force)

    def _reclaim_empty(self) -> None:
        with self._directory_lock:
            self._shards = {
                shard_id: shard
                for shard_id, shard in self._shards.items()
                if shard.sessions or shard.operations or shard.expiry
            }
            for index, route in enumerate(self._operation_routes):
                if route is None:
                    continue
                with route.lock:
                    if not route.operations and not route.children:
                        self._operation_routes[index] = None

    def watermark(
        self,
        at: datetime,
        *,
        limit: int = _DEFAULT_WATERMARK_PAGE,
    ) -> SshWatermarkResult:
        """Close one bounded page; caller drains intents before shared watermark."""

        canonical = _canonical_utc(at)
        if canonical < self._watermark:
            raise StateError("SSH watermarks must be monotonic")
        if limit <= 0:
            raise ValueError("SSH watermark page limit must be positive")
        closures: list[SshChannelClosure] = []
        has_more = False
        with self._watermark_lane:
            with self._gate.watermark():
                with self._prepared_lock:
                    claimed_frontier = min(
                        (
                            capability.linearization_time
                            for capability in self._prepared_capabilities.values()
                            if capability.reservation_id in self._claimed_admissions
                        ),
                        default=None,
                    )
                if claimed_frontier is not None and canonical > claimed_frontier:
                    raise StateError(
                        "SSH watermark cannot advance past a claimed admission at "
                        f"{claimed_frontier.isoformat()}"
                    )
                with self._directory_lock:
                    shards = tuple(sorted(self._shards.values(), key=lambda item: item.shard_id))
                cutoff = canonical.timestamp()
                remaining = limit
                for shard in shards:
                    while remaining > 0:
                        with shard.lock:
                            due = shard.expiry.first_due_before(cutoff, inclusive=True)
                            if due is None:
                                break
                            handle, deadline = due
                            session = shard.sessions.get_by_handle(handle)
                            close_token = shard.sessions.close_token_by_handle(handle)
                            try:
                                close_result = self._registry.close_channel_by_token(
                                    session.channel_id,
                                    token=close_token,
                                    closed_at=datetime.fromtimestamp(deadline, tz=UTC),
                                    reason="deadline",
                                    include_retirement_proof=True,
                                )
                            except StateError as exc:
                                if "active operations" not in str(exc):
                                    raise
                                raise StateError(
                                    f"SSH watermark cannot close {session.channel_id!r} with "
                                    "active child operations"
                                ) from exc
                            shard.expiry.pop(handle, None)
                            shard.sessions.delete(session.channel_id)
                            self._evict_cached_session(session.channel_id)
                            retirement_proof = close_result.retirement_proof
                            if retirement_proof is None:
                                raise StateError("SSH watermark close returned no retirement proof")
                            closures.append(
                                self._closure(
                                    session,
                                    closed_at=close_result.closed_at,
                                    reason=retirement_proof.snapshot.close_reason,
                                    retirement_proof=retirement_proof,
                                )
                            )
                            remaining -= 1
                    if remaining <= 0:
                        break
                has_more = any(
                    shard.expiry.first_due_before(cutoff, inclusive=True) is not None
                    for shard in shards
                )
                self._watermark = canonical
            self._compact_sidecars(_DEFAULT_COMPACTION_WORK)
            with self._gate.watermark():
                self._reclaim_empty()
        return SshWatermarkResult(
            census=self.census(),
            closures=tuple(closures),
            has_more=has_more,
        )

    def census(self) -> SshChannelCensus:
        """Return bounded sidecar metrics plus the shared application census."""

        with self._directory_lock:
            shards = tuple(self._shards.values())
            routes = tuple(route for route in self._operation_routes if route is not None)
        with self._session_hot_cache_lock:
            hot_cache_entries = len(self._session_hot_cache)
            hot_cache_bytes = sys.getsizeof(self._session_hot_cache) + self._session_hot_cache_bytes
            hot_cache_candidates = self._session_hot_cache_candidates
        open_sessions = 0
        active_operations = 0
        session_backing = 0
        operation_backing = 0
        stale_sidecars = 0
        expiry_entries = 0
        stale_expiry = 0
        max_shard_load = 0
        high_water = 0
        sidecar_candidates = 0
        decoded_entries = 0
        estimated_values = 0
        estimated_indexes = 0
        primary_pending = 0
        primary_work = 0
        expiry_pending = 0
        expiry_work = 0
        for shard in shards:
            with shard.lock:
                session_rows, session_routes = shard.sessions.metrics()
                operation_rows = shard.operations.metrics()
                expiry = shard.expiry.metrics(estimate_bytes=True)
                open_sessions += session_rows.live_entries
                active_operations += operation_rows.live_entries
                session_backing += session_rows.backing_entries
                operation_backing += operation_rows.backing_entries
                stale_sidecars += session_rows.stale_entries + operation_rows.stale_entries
                expiry_entries += expiry.backing_entries
                stale_expiry += expiry.stale_entries
                max_shard_load = max(
                    max_shard_load,
                    session_rows.live_entries + operation_rows.live_entries,
                )
                high_water = max(high_water, shard.high_water_mark)
                sidecar_candidates += shard.sessions.lookup_candidates_inspected
                decoded_entries += shard.sessions.decoded_entries + shard.operations.decoded_entries
                estimated_values += (
                    shard.sessions.estimated_value_bytes + shard.operations.estimated_value_bytes
                )
                index_metrics = (session_rows, operation_rows, expiry, *session_routes)
                estimated_indexes += sum(metric.estimated_bytes for metric in index_metrics)
                primary_pending += sum(
                    metric.primary_compaction_pending for metric in session_routes
                )
                primary_work += sum(metric.primary_compaction_work for metric in session_routes)
                expiry_pending += expiry.compaction_pending
                expiry_work += expiry.compaction_work
        for route in routes:
            with route.lock:
                route_metrics = (
                    route.operations.metrics(estimate_bytes=True),
                    route.children.metrics(estimate_bytes=True),
                )
                estimated_indexes += sum(metric.estimated_bytes for metric in route_metrics)
                sidecar_candidates += route.lookup_candidates_inspected
                primary_pending += sum(
                    metric.primary_compaction_pending for metric in route_metrics
                )
                primary_work += sum(metric.primary_compaction_work for metric in route_metrics)
        application = self._registry.census()
        sidecar_bytes = (
            sys.getsizeof(self)
            + sys.getsizeof(self.__dict__)
            + sys.getsizeof(self._shards)
            + sys.getsizeof(self._operation_routes)
            + sum(sys.getsizeof(shard) for shard in shards)
            + sum(sys.getsizeof(route) for route in routes)
            + hot_cache_bytes
            + estimated_values
            + estimated_indexes
        )
        return SshChannelCensus(
            open_sessions=open_sessions,
            active_operations=active_operations,
            session_backing_entries=session_backing,
            operation_backing_entries=operation_backing,
            stale_sidecar_entries=stale_sidecars,
            expiry_entries=expiry_entries,
            stale_expiry_entries=stale_expiry,
            shard_count=len(shards),
            max_shard_load=max_shard_load,
            high_water_mark=high_water,
            lookup_candidates_inspected=(
                sidecar_candidates + hot_cache_candidates + application.lookup_candidates_inspected
            ),
            sidecar_lookup_candidates_inspected=sidecar_candidates + hot_cache_candidates,
            decoded_cache_entries=decoded_entries + hot_cache_entries,
            decoded_cache_capacity=(
                len(shards) * _DEFAULT_DECODED_CACHE_PER_SHARD + _DEFAULT_SESSION_HOT_CACHE
            ),
            decoded_cache_estimated_bytes=hot_cache_bytes,
            sidecar_estimated_bytes=sidecar_bytes,
            sidecar_estimated_index_bytes=estimated_indexes,
            estimated_bytes=sidecar_bytes + application.estimated_bytes,
            estimated_index_bytes=estimated_indexes + application.estimated_index_bytes,
            primary_compaction_pending=primary_pending,
            primary_compaction_work=primary_work,
            expiry_compaction_pending=expiry_pending,
            expiry_compaction_work=expiry_work,
            watermark=self._watermark,
            application=application,
        )
