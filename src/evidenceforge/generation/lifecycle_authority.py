# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Generator-facing orchestration for canonical lifecycle registry authority.

Lifecycle identity, holds, foreground ownership, singleton ownership, barriers,
and closure tickets remain in :class:`LifecycleRegistry`.  This adapter owns
only compact deadline queues for work that must be dispatched later by the
generator.  Queue payloads are removed while a shard lock is held and executed
by the caller after the lock is released.
"""

from __future__ import annotations

import heapq
import hmac
import random
import secrets
import struct
from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from threading import Condition, Lock, RLock, Thread, current_thread
from types import FunctionType, MemberDescriptorType
from typing import Any, Generic, Literal, Protocol, TypeVar, cast
from weakref import ReferenceType, ref

from evidenceforge.events.base import CanonicalOccurrence
from evidenceforge.events.identity import ProcessIdentity, SessionIdentity, ThreadIdentity
from evidenceforge.events.lifecycle import (
    LifecycleCloseBarrier,
    LifecycleEntityRef,
    LifecycleForegroundLease,
    LifecycleHold,
    LifecycleSingletonLease,
    LifecycleTransition,
    ProcessLifecycleIdentity,
    ServiceProcessBindingIdentity,
    SessionLifecycleIdentity,
)
from evidenceforge.generation.application_channels import (
    ApplicationChannelAdmissionReceipt,
    ApplicationChannelAdmissionResult,
    ApplicationChannelAdmissionToken,
    ApplicationChannelPreparedCommit,
    ApplicationChannelRegistry,
)
from evidenceforge.generation.cryptographic_material import (
    CryptographicMaterialPreparationReceipt,
)
from evidenceforge.generation.deferred_session_composition import (
    DeferredSessionComposition,
    DeferredSessionCompositionCoordinator,
)
from evidenceforge.generation.http_channels import (
    HttpApplicationChannelManager,
    HttpChannelAdmissionResult,
    HttpChannelAdmissionToken,
    HttpChannelPreparedCommit,
)
from evidenceforge.generation.indexes import CompactIndexedStore, PackedHandleExpiryIndex
from evidenceforge.generation.lifecycle_registry import (
    LifecycleActionCohortAdmissionToken,
    LifecycleActionCohortOperation,
    LifecycleActionCohortReceipt,
    LifecycleActionCohortRequest,
    LifecycleClosedTransportAdmissionToken,
    LifecycleClosedTransportPublicationReceipt,
    LifecycleClosedTransportStartMember,
    LifecycleLeaseConflictError,
    LifecycleProcessStartRequest,
    LifecycleRegistry,
    LifecycleServiceAdmissionToken,
    LifecycleServiceClosureAdmissionToken,
    LifecycleServiceProcessClosureReceipt,
    LifecycleServicePublicationReceipt,
    LifecycleServiceStagedProcessBindingMember,
    LifecycleSessionStartRequest,
    LifecycleSubjectClosureControl,
    PreparedLifecycleClosedTransportPublication,
    ProcessLifecycleSnapshot,
)
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.generation.network_runtime import (
    NetworkConnectionCommitResult,
    NetworkTransactionPreparationReceipt,
    NetworkTransactionPreparedCommit,
    NetworkTransactionRuntime,
    NetworkTransportLifecycleMode,
    PreparedNetworkTransactionRoot,
)
from evidenceforge.generation.proxy_channels import (
    ExplicitProxyAdmissionCommitResult,
    ExplicitProxyAdmissionToken,
    ExplicitProxyChannelManager,
    ExplicitProxyPreparedCommit,
)
from evidenceforge.generation.rdp_sessions import (
    RdpReconnectStateManager,
    RdpSessionAdmissionResult,
    RdpSessionAdmissionToken,
    RdpSessionPreparedCommit,
)
from evidenceforge.generation.smb_channels import (
    SmbApplicationChannelManager,
    SmbChannelAdmissionResult,
    SmbChannelAdmissionToken,
    SmbChannelPreparedCommit,
)
from evidenceforge.generation.source_timing import (
    SourceTimingPlanner,
    SourceTimingPreparation,
    SourceTimingPreparationReceipt,
    SourceTimingPreparationToken,
)
from evidenceforge.generation.ssh_channels import (
    SshApplicationChannelManager,
    SshChannelAdmissionResult,
    SshChannelAdmissionToken,
    SshChannelPreparedCommit,
)
from evidenceforge.generation.state_manager import (
    ActionCohortMaterializationPlan,
    ConnectionCompositeMaterializationPlan,
    ConnectionCompositeMaterializationResult,
    ConnectionExistingSessionLifecycleDisposition,
    ConnectionMaterializationMode,
    MaterializationBatchPlan,
    PhysicalTransportFingerprint,
    PreparedConnectionCompositeMaterialization,
    ProcessMaterializationPlan,
    ProcessTerminationMaterializationPlan,
    SessionMaterializationPlan,
    StateManager,
)
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import System
from evidenceforge.models.state import ActiveSession, RunningProcess
from evidenceforge.utils.rng import stable_uuid
from evidenceforge.utils.time import ensure_utc

ProcessInstanceKey = tuple[str, int, datetime | None]
StrictLifecycleKey = tuple[str, str]
_DEFAULT_SHARD_COUNT = 64
_DEFAULT_DUE_PAGE = 4_096
_MAX_ACTION_COHORT_OPERATIONS = 256
_DEFAULT_MATERIALIZATION_BATCH_TRANSACTION_CAPACITY = 64
_DEFAULT_MATERIALIZATION_BATCH_TRANSACTION_BYTE_CAPACITY = 16 * 1024 * 1024
_DEFAULT_PREPARED_NETWORK_RECEIPT_ISSUANCE_CAPACITY = 4096
_MAX_MATERIALIZATION_BATCH_TRANSACTION_BYTES = 4 * 1024 * 1024
_MAX_MATERIALIZATION_BATCH_PAYLOAD_NODES = 65_536
_MAX_MATERIALIZATION_BATCH_SCALAR_BYTES = 64 * 1024

_ApplicationAdmissionToken = (
    ApplicationChannelAdmissionToken
    | HttpChannelAdmissionToken
    | ExplicitProxyAdmissionToken
    | SmbChannelAdmissionToken
    | SshChannelAdmissionToken
    | RdpSessionAdmissionToken
)
_ApplicationAdmissionResult = (
    ApplicationChannelAdmissionResult
    | HttpChannelAdmissionResult
    | ExplicitProxyAdmissionCommitResult
    | SmbChannelAdmissionResult
    | SshChannelAdmissionResult
    | RdpSessionAdmissionResult
)
_ApplicationPreparedCommit = (
    ApplicationChannelPreparedCommit
    | HttpChannelPreparedCommit
    | ExplicitProxyPreparedCommit
    | SmbChannelPreparedCommit
    | SshChannelPreparedCommit
    | RdpSessionPreparedCommit
)


def _validate_materialization_batch_external_result(
    value: object,
) -> tuple[int, int]:
    """Validate and measure one deeply immutable bounded canonical payload."""

    nodes = 0
    retained_bytes = 0
    pending: list[tuple[object, int]] = [(value, 0)]
    while pending:
        member, depth = pending.pop()
        nodes += 1
        if nodes > _MAX_MATERIALIZATION_BATCH_PAYLOAD_NODES:
            raise StateError("Materialization-batch payload has too many retained members")
        if depth > 16:
            raise StateError("Materialization-batch external result nesting is too deep")
        if member is None:
            retained_bytes += 1
        elif type(member) is bool:
            retained_bytes += 1
        elif type(member) is int:
            retained_bytes += max(1, (member.bit_length() + 8) // 8)
        elif type(member) is str:
            scalar_bytes = len(member.encode("utf-8"))
            if scalar_bytes > _MAX_MATERIALIZATION_BATCH_SCALAR_BYTES:
                raise StateError("Materialization-batch string member is too large")
            retained_bytes += scalar_bytes
        elif type(member) is bytes:
            if len(member) > _MAX_MATERIALIZATION_BATCH_SCALAR_BYTES:
                raise StateError("Materialization-batch bytes member is too large")
            retained_bytes += len(member)
        elif type(member) is datetime:
            if member.tzinfo is not UTC:
                raise StateError(
                    "Materialization-batch external datetimes must use exact built-in UTC"
                )
            retained_bytes += 16
        elif type(member) is tuple:
            retained_bytes += 8 * len(member)
            if retained_bytes > _MAX_MATERIALIZATION_BATCH_TRANSACTION_BYTES:
                raise StateError("Materialization-batch payload exceeds its retained-byte limit")
            pending.extend((child, depth + 1) for child in member)
        else:
            raise StateError(
                "Materialization-batch external results require immutable canonical tuples"
            )
        if retained_bytes > _MAX_MATERIALIZATION_BATCH_TRANSACTION_BYTES:
            raise StateError("Materialization-batch payload exceeds its retained-byte limit")
    return nodes, retained_bytes


def _canonical_materialization_batch_payload_bytes(value: object) -> bytes:
    """Encode one validated inert payload without dispatching caller-defined code."""

    _validate_materialization_batch_external_result(value)

    def encode(member: object) -> bytes:
        if member is None:
            return b"n"
        if type(member) is bool:
            return b"b1" if member else b"b0"
        if type(member) is int:
            scalar = str(member).encode("ascii")
            return b"i" + str(len(scalar)).encode("ascii") + b":" + scalar
        if type(member) is str:
            scalar = member.encode("utf-8")
            return b"s" + str(len(scalar)).encode("ascii") + b":" + scalar
        if type(member) is bytes:
            return b"y" + str(len(member)).encode("ascii") + b":" + member
        if type(member) is datetime:
            scalar = member.isoformat(timespec="microseconds").encode("ascii")
            return b"d" + str(len(scalar)).encode("ascii") + b":" + scalar
        if type(member) is tuple:
            encoded_members = tuple(encode(child) for child in member)
            return (
                b"t"
                + str(len(encoded_members)).encode("ascii")
                + b":"
                + b"".join(
                    str(len(child)).encode("ascii") + b":" + child for child in encoded_members
                )
            )
        raise AssertionError("validated materialization payload changed during encoding")

    return encode(value)


def _materialization_batch_hmac(authority_secret: bytes, payload: tuple[object, ...]) -> str:
    """Authenticate one exact inert tuple without relying on object ``repr`` hooks."""

    return hmac.new(
        authority_secret,
        _canonical_materialization_batch_payload_bytes(payload),
        sha256,
    ).hexdigest()


def _thread_identity_payload(identity: ThreadIdentity | None) -> tuple[object, ...] | None:
    """Project one exact immutable thread identity into inert built-ins."""

    if identity is None:
        return None
    if type(identity) is not ThreadIdentity:
        raise StateError("Materialization-batch thread identity must have its exact type")
    return (
        "thread-identity-v1",
        identity.hostname,
        identity.process_object_id,
        identity.pid,
        identity.tid,
        identity.object_id,
        identity.started_at,
        identity.kind,
    )


def _process_identity_payload(identity: ProcessIdentity) -> tuple[object, ...]:
    """Project one exact immutable process identity into inert built-ins."""

    if type(identity) is not ProcessIdentity:
        raise StateError("Materialization-batch process identity must have its exact type")
    return (
        "process-identity-v1",
        identity.hostname,
        identity.object_id,
        identity.pid,
        identity.parent_pid,
        identity.image,
        identity.command_line,
        identity.principal,
        identity.logon_id,
        identity.started_at,
        identity.lifecycle_group_id,
        identity.parent_lifecycle_group_id,
        _thread_identity_payload(identity.primary_thread),
    )


def _session_identity_payload(identity: SessionIdentity | None) -> tuple[object, ...] | None:
    """Project one exact immutable session identity into inert built-ins."""

    if identity is None:
        return None
    if type(identity) is not SessionIdentity:
        raise StateError("Materialization-batch session identity must have its exact type")
    return (
        "session-identity-v1",
        identity.hostname,
        identity.object_id,
        identity.logon_id,
        identity.session_id,
        identity.principal,
        identity.session_kind,
        identity.started_at,
        identity.lifecycle_group_id,
        identity.logon_guid,
        identity.parent_lifecycle_group_id,
    )


@dataclass(frozen=True, slots=True)
class LifecycleMaterializationReceipt:
    """Authenticated proof that registry and StateManager published one start."""

    _kind: str
    _object_id: str
    _publication_token: str
    _prior_version: int
    _committed_version: int
    _integrity_token: str

    @classmethod
    def _issue(
        cls,
        *,
        authority_secret: bytes,
        kind: str,
        object_id: str,
        publication_token: str,
        prior_version: int,
        committed_version: int,
    ) -> LifecycleMaterializationReceipt:
        """Issue one authority-keyed receipt over every proof field."""

        values = (kind, object_id, publication_token, prior_version, committed_version)
        integrity_token = hmac.new(
            authority_secret,
            repr(values).encode(),
            sha256,
        ).hexdigest()
        return cls(*values, integrity_token)

    @property
    def kind(self) -> str:
        """Return the materialized lifecycle kind."""

        return self._kind

    @property
    def object_id(self) -> str:
        """Return the exact canonical object identity."""

        return self._object_id

    @property
    def prior_version(self) -> int:
        """Return the StateManager fence consumed by the plan."""

        return self._prior_version

    @property
    def committed_version(self) -> int:
        """Return the StateManager fence immediately after publication."""

        return self._committed_version

    def _has_valid_integrity(self, authority_secret: bytes) -> bool:
        values = (
            self._kind,
            self._object_id,
            self._publication_token,
            self._prior_version,
            self._committed_version,
        )
        expected = hmac.new(
            authority_secret,
            repr(values).encode(),
            sha256,
        ).hexdigest()
        return hmac.compare_digest(self._integrity_token, expected)


@dataclass(frozen=True, slots=True)
class LifecycleMaterializationBatchReceipt:
    """Authenticated proof of one all-or-none session/process start batch."""

    _publication_token: str
    _member_tokens: tuple[str, ...]
    _prior_version: int
    _committed_version: int
    _integrity_token: str

    @classmethod
    def _issue(
        cls,
        *,
        authority_secret: bytes,
        publication_token: str,
        member_tokens: tuple[str, ...],
        prior_version: int,
        committed_version: int,
    ) -> LifecycleMaterializationBatchReceipt:
        """Issue one authority-keyed receipt for the exact ordered batch."""

        values = (
            publication_token,
            member_tokens,
            prior_version,
            committed_version,
        )
        integrity_token = hmac.new(
            authority_secret,
            repr(values).encode(),
            sha256,
        ).hexdigest()
        return cls(*values, integrity_token)

    @property
    def prior_version(self) -> int:
        """Return the single StateManager fence consumed by the batch."""

        return self._prior_version

    @property
    def committed_version(self) -> int:
        """Return the StateManager fence after the one-step batch commit."""

        return self._committed_version

    def _has_valid_integrity(self, authority_secret: bytes) -> bool:
        values = (
            self._publication_token,
            self._member_tokens,
            self._prior_version,
            self._committed_version,
        )
        expected = hmac.new(
            authority_secret,
            repr(values).encode(),
            sha256,
        ).hexdigest()
        return hmac.compare_digest(self._integrity_token, expected)


@dataclass(frozen=True, slots=True)
class LifecycleMaterializationBatchTransaction:
    """Authority-issued exact locator for one retry-stable batch request."""

    _transaction_id: str
    _request_digest: str
    _generation: int
    _integrity_token: str = field(repr=False)

    @classmethod
    def _issue(
        cls,
        *,
        authority_secret: bytes,
        transaction_id: str,
        request_digest: str,
        generation: int,
    ) -> LifecycleMaterializationBatchTransaction:
        values: tuple[object, ...] = (
            "materialization-batch-transaction-v1",
            transaction_id,
            request_digest,
            generation,
        )
        token = _materialization_batch_hmac(authority_secret, values)
        return cls(transaction_id, request_digest, generation, token)

    @property
    def transaction_id(self) -> str:
        """Return the stable caller-selected transaction identity."""

        return self._transaction_id

    @property
    def request_digest(self) -> str:
        """Return the exact retry-stable request digest."""

        return self._request_digest

    def _has_valid_integrity(self, authority_secret: bytes) -> bool:
        values: tuple[object, ...] = (
            "materialization-batch-transaction-v1",
            self._transaction_id,
            self._request_digest,
            self._generation,
        )
        try:
            expected = _materialization_batch_hmac(authority_secret, values)
        except StateError:
            return False
        return type(self._integrity_token) is str and hmac.compare_digest(
            self._integrity_token,
            expected,
        )


@dataclass(frozen=True, slots=True)
class LifecycleMaterializationBatchPlanningAttempt:
    """Exact caller-held identity for one retry-stable planning-claim attempt."""

    _transaction_id: str
    _request_digest: str
    _transaction_generation: int
    _integrity_token: str = field(repr=False)

    @classmethod
    def _issue(
        cls,
        *,
        authority_secret: bytes,
        transaction: LifecycleMaterializationBatchTransaction,
    ) -> LifecycleMaterializationBatchPlanningAttempt:
        payload: tuple[object, ...] = (
            "materialization-batch-planning-attempt-v1",
            transaction.transaction_id,
            transaction.request_digest,
            transaction._generation,
        )
        return cls(
            transaction.transaction_id,
            transaction.request_digest,
            transaction._generation,
            _materialization_batch_hmac(authority_secret, payload),
        )

    def _has_valid_integrity(self, authority_secret: bytes) -> bool:
        payload: tuple[object, ...] = (
            "materialization-batch-planning-attempt-v1",
            self._transaction_id,
            self._request_digest,
            self._transaction_generation,
        )
        try:
            expected = _materialization_batch_hmac(authority_secret, payload)
        except StateError:
            return False
        return type(self._integrity_token) is str and hmac.compare_digest(
            self._integrity_token,
            expected,
        )


@dataclass(frozen=True, slots=True)
class LifecycleMaterializationBatchPlanningCapability:
    """Exact retained proof that one Thread owns retry-stable batch planning."""

    _transaction_id: str
    _request_digest: str
    _transaction_generation: int
    _integrity_token: str = field(repr=False)

    @classmethod
    def _issue(
        cls,
        *,
        authority_secret: bytes,
        transaction: LifecycleMaterializationBatchTransaction,
    ) -> LifecycleMaterializationBatchPlanningCapability:
        payload: tuple[object, ...] = (
            "materialization-batch-planning-capability-v1",
            transaction.transaction_id,
            transaction.request_digest,
            transaction._generation,
        )
        return cls(
            transaction.transaction_id,
            transaction.request_digest,
            transaction._generation,
            _materialization_batch_hmac(authority_secret, payload),
        )

    def _has_valid_integrity(self, authority_secret: bytes) -> bool:
        payload: tuple[object, ...] = (
            "materialization-batch-planning-capability-v1",
            self._transaction_id,
            self._request_digest,
            self._transaction_generation,
        )
        try:
            expected = _materialization_batch_hmac(authority_secret, payload)
        except StateError:
            return False
        return type(self._integrity_token) is str and hmac.compare_digest(
            self._integrity_token,
            expected,
        )


def _materialization_batch_receipt_payload(
    receipt: LifecycleMaterializationBatchReceipt,
) -> tuple[object, ...]:
    """Project one exact batch receipt without invoking its representation."""

    if type(receipt) is not LifecycleMaterializationBatchReceipt:
        raise StateError("Materialization-batch receipt must have its exact public type")
    return (
        "materialization-batch-receipt-v1",
        receipt._publication_token,
        receipt._member_tokens,
        receipt._prior_version,
        receipt._committed_version,
        receipt._integrity_token,
    )


def _materialization_batch_terminal_payload(
    *,
    transaction_id: str,
    request_digest: str,
    transaction_generation: int,
    plan_publication_token: str,
    session: SessionIdentity | None,
    processes: tuple[ProcessIdentity, ...],
    boot_times: tuple[tuple[str, datetime], ...],
    external_result: tuple[object, ...],
    terminal_at: datetime,
    receipt: LifecycleMaterializationBatchReceipt,
) -> tuple[object, ...]:
    """Project an exact terminal into deeply inert authenticated built-ins."""

    if type(processes) is not tuple:
        raise StateError("Materialization-batch processes must be an exact tuple")
    if type(boot_times) is not tuple:
        raise StateError("Materialization-batch boot times must be an exact tuple")
    canonical_boot_times: list[tuple[str, datetime]] = []
    for member in boot_times:
        if type(member) is not tuple or len(member) != 2:
            raise StateError("Materialization-batch boot-time members must be exact pairs")
        hostname, boot_time = member
        if type(hostname) is not str or type(boot_time) is not datetime:
            raise StateError("Materialization-batch boot-time members are malformed")
        canonical_boot_times.append((hostname, boot_time))
    payload: tuple[object, ...] = (
        "materialization-batch-terminal-v1",
        transaction_id,
        request_digest,
        transaction_generation,
        plan_publication_token,
        _session_identity_payload(session),
        tuple(_process_identity_payload(identity) for identity in processes),
        tuple(canonical_boot_times),
        external_result,
        terminal_at,
        _materialization_batch_receipt_payload(receipt),
    )
    _validate_materialization_batch_external_result(payload)
    return payload


@dataclass(frozen=True, slots=True)
class LifecycleMaterializationBatchTerminalResult:
    """Authenticated immutable result retained across a lost public return."""

    _transaction_id: str
    _request_digest: str
    _transaction_generation: int
    _plan_publication_token: str
    _session: SessionIdentity | None
    _processes: tuple[ProcessIdentity, ...]
    _boot_times: tuple[tuple[str, datetime], ...]
    _external_result: tuple[object, ...]
    _terminal_at: datetime
    _receipt: LifecycleMaterializationBatchReceipt
    _integrity_token: str = field(repr=False)

    @classmethod
    def _issue(
        cls,
        *,
        authority_secret: bytes,
        transaction: LifecycleMaterializationBatchTransaction,
        plan: MaterializationBatchPlan,
        external_result: tuple[object, ...],
        receipt: LifecycleMaterializationBatchReceipt,
    ) -> LifecycleMaterializationBatchTerminalResult:
        session = plan.session.identity if plan.session is not None else None
        processes = tuple(member.identity for member in plan.processes)
        values = _materialization_batch_terminal_payload(
            transaction_id=transaction.transaction_id,
            request_digest=transaction.request_digest,
            transaction_generation=transaction._generation,
            plan_publication_token=plan.publication_token,
            session=session,
            processes=processes,
            boot_times=plan.boot_times,
            external_result=external_result,
            terminal_at=plan.final_state_time,
            receipt=receipt,
        )
        token = _materialization_batch_hmac(authority_secret, values)
        return cls(
            transaction.transaction_id,
            transaction.request_digest,
            transaction._generation,
            plan.publication_token,
            session,
            processes,
            plan.boot_times,
            external_result,
            plan.final_state_time,
            receipt,
            token,
        )

    @property
    def transaction_id(self) -> str:
        """Return the retry-stable transaction identity."""

        return self._transaction_id

    @property
    def request_digest(self) -> str:
        """Return the exact request digest bound to this result."""

        return self._request_digest

    @property
    def session(self) -> SessionIdentity | None:
        """Return the exact committed session identity, when present."""

        return self._session

    @property
    def processes(self) -> tuple[ProcessIdentity, ...]:
        """Return exact committed process identities in batch order."""

        return self._processes

    @property
    def boot_times(self) -> tuple[tuple[str, datetime], ...]:
        """Return exact committed host boot times."""

        return self._boot_times

    @property
    def external_result(self) -> tuple[object, ...]:
        """Return the authenticated canonical external publication payload."""

        return self._external_result

    @property
    def terminal_at(self) -> datetime:
        """Return the canonical retention time for this terminal result."""

        return self._terminal_at

    @property
    def receipt(self) -> LifecycleMaterializationBatchReceipt:
        """Return the exact authenticated State/lifecycle commit receipt."""

        return self._receipt

    def _has_valid_integrity(self, authority_secret: bytes) -> bool:
        try:
            values = _materialization_batch_terminal_payload(
                transaction_id=self._transaction_id,
                request_digest=self._request_digest,
                transaction_generation=self._transaction_generation,
                plan_publication_token=self._plan_publication_token,
                session=self._session,
                processes=self._processes,
                boot_times=self._boot_times,
                external_result=self._external_result,
                terminal_at=self._terminal_at,
                receipt=self._receipt,
            )
            expected = _materialization_batch_hmac(authority_secret, values)
        except StateError:
            return False
        return type(self._integrity_token) is str and hmac.compare_digest(
            self._integrity_token,
            expected,
        )


@dataclass(frozen=True, slots=True)
class LifecycleProcessServiceCompositeReceipt:
    """Authority proof for one process start plus service/binding publication."""

    process_receipt: LifecycleMaterializationReceipt
    service_receipt: LifecycleServicePublicationReceipt
    _integrity_token: str

    @classmethod
    def _issue(
        cls,
        *,
        authority_secret: bytes,
        process_receipt: LifecycleMaterializationReceipt,
        service_receipt: LifecycleServicePublicationReceipt,
    ) -> LifecycleProcessServiceCompositeReceipt:
        """Issue an authority-keyed proof over both registry receipts."""

        integrity_token = hmac.new(
            authority_secret,
            repr(
                (
                    process_receipt,
                    service_receipt.publication_token,
                    service_receipt.plan_digest,
                    service_receipt.committed_digest,
                )
            ).encode(),
            sha256,
        ).hexdigest()
        return cls(process_receipt, service_receipt, integrity_token)

    def _has_valid_integrity(self, authority_secret: bytes) -> bool:
        expected = hmac.new(
            authority_secret,
            repr(
                (
                    self.process_receipt,
                    self.service_receipt.publication_token,
                    self.service_receipt.plan_digest,
                    self.service_receipt.committed_digest,
                )
            ).encode(),
            sha256,
        ).hexdigest()
        return hmac.compare_digest(self._integrity_token, expected)


@dataclass(frozen=True, slots=True)
class LifecycleProcessServiceCompositeResult:
    """Committed State process and authenticated cross-registry receipt."""

    process: RunningProcess
    receipt: LifecycleProcessServiceCompositeReceipt


@dataclass(frozen=True, slots=True)
class LifecycleProcessServiceClosureCompositeReceipt:
    """Authority proof for one State process and service-ownership closure."""

    process_receipt: LifecycleMaterializationReceipt
    service_receipt: LifecycleServiceProcessClosureReceipt
    _integrity_token: str

    @classmethod
    def _issue(
        cls,
        *,
        authority_secret: bytes,
        process_receipt: LifecycleMaterializationReceipt,
        service_receipt: LifecycleServiceProcessClosureReceipt,
    ) -> LifecycleProcessServiceClosureCompositeReceipt:
        """Issue one authority-keyed proof over both terminal receipts."""

        integrity_token = hmac.new(
            authority_secret,
            repr(
                (
                    "process-service-closure-v1",
                    process_receipt,
                    service_receipt.publication_token,
                    service_receipt.plan_digest,
                    service_receipt.committed_digest,
                )
            ).encode(),
            sha256,
        ).hexdigest()
        return cls(process_receipt, service_receipt, integrity_token)

    def _has_valid_integrity(self, authority_secret: bytes) -> bool:
        expected = hmac.new(
            authority_secret,
            repr(
                (
                    "process-service-closure-v1",
                    self.process_receipt,
                    self.service_receipt.publication_token,
                    self.service_receipt.plan_digest,
                    self.service_receipt.committed_digest,
                )
            ).encode(),
            sha256,
        ).hexdigest()
        return hmac.compare_digest(self._integrity_token, expected)


@dataclass(frozen=True, slots=True)
class LifecycleProcessServiceClosureCompositeResult:
    """Exact ended process identity and authenticated closure receipt."""

    process: ProcessIdentity
    receipt: LifecycleProcessServiceClosureCompositeReceipt


@dataclass(frozen=True, slots=True)
class ApplicationChannelCompositeProof:
    """Normalized authenticated proof from one engine-owned application manager."""

    manager_kind: Literal["protocol_neutral", "http", "explicit_proxy", "smb", "ssh", "rdp"]
    manager_id: str
    manager_receipt_token: str
    common_receipt_token: str
    channel_id: str
    operation_id: str
    current_transport_id: str
    prerequisite_transport_ids: tuple[str, ...]
    sidecar_result_digest: str

    def __post_init__(self) -> None:
        """Reject anonymous, cyclic, or duplicate transport authority."""

        if not all(
            (
                self.manager_id,
                self.manager_receipt_token,
                self.common_receipt_token,
                self.channel_id,
                self.operation_id,
                self.current_transport_id,
                self.sidecar_result_digest,
            )
        ):
            raise ValueError("Application composite proof requires complete signed identity")
        if self.current_transport_id in self.prerequisite_transport_ids:
            raise ValueError("Application composite current transport cannot be a prerequisite")
        if len(set(self.prerequisite_transport_ids)) != len(self.prerequisite_transport_ids):
            raise ValueError("Application composite repeats a prerequisite transport")


@dataclass(frozen=True, slots=True)
class ConnectionCompositePrerequisiteProof:
    """Compact authority-issued proof of one already committed prerequisite leg."""

    receipt_token: str
    receipt_digest: str
    physical_transport_id: str
    transaction_id: str
    conn_id: str
    zeek_uid: str


@dataclass(frozen=True, slots=True)
class LifecycleConnectionCompositeReceipt:
    """Authority-keyed proof of one State/lifecycle/application transaction."""

    _state_publication_token: str
    _prior_version: int
    _committed_version: int
    _transaction_id: str
    _physical_transport: PhysicalTransportFingerprint
    _materializes_connection: bool
    _lifecycle_receipt: LifecycleClosedTransportPublicationReceipt | None
    _application_proof: ApplicationChannelCompositeProof | None
    _prerequisite_proofs: tuple[ConnectionCompositePrerequisiteProof, ...]
    _integrity_token: str

    @classmethod
    def _issue(
        cls,
        *,
        authority_secret: bytes,
        state_publication_token: str,
        prior_version: int,
        committed_version: int,
        transaction_id: str,
        physical_transport: PhysicalTransportFingerprint,
        materializes_connection: bool,
        lifecycle_receipt: LifecycleClosedTransportPublicationReceipt | None,
        application_proof: ApplicationChannelCompositeProof | None,
        prerequisite_proofs: tuple[ConnectionCompositePrerequisiteProof, ...],
    ) -> LifecycleConnectionCompositeReceipt:
        """Issue one secret-bound proof over all normalized authority results."""

        values = (
            state_publication_token,
            prior_version,
            committed_version,
            transaction_id,
            physical_transport,
            materializes_connection,
            lifecycle_receipt,
            application_proof,
            prerequisite_proofs,
        )
        integrity_token = cls._integrity_for(
            authority_secret=authority_secret,
            values=values,
        )
        return cls(*values, integrity_token)

    @staticmethod
    def _integrity_for(
        *,
        authority_secret: bytes,
        values: tuple[object, ...],
    ) -> str:
        """Return the authority HMAC over exact normalized composite truth."""

        lifecycle_receipt = values[6]
        lifecycle_token = (
            lifecycle_receipt.publication_token
            if isinstance(lifecycle_receipt, LifecycleClosedTransportPublicationReceipt)
            else ""
        )
        canonical = (
            "lifecycle-connection-composite-v1",
            *values,
            lifecycle_token,
        )
        return hmac.new(
            authority_secret,
            repr(canonical).encode(),
            sha256,
        ).hexdigest()

    @property
    def prior_version(self) -> int:
        """Return the StateManager version consumed by this transaction."""

        return self._prior_version

    @property
    def committed_version(self) -> int:
        """Return the StateManager version after the one-step commit."""

        return self._committed_version

    @property
    def transaction_id(self) -> str:
        """Return this canonical transaction occurrence identity."""

        return self._transaction_id

    @property
    def physical_transport_id(self) -> str:
        """Return the exact physical transport owning this occurrence."""

        return self._physical_transport.transport_id

    @property
    def materializes_connection(self) -> bool:
        """Return whether this receipt created the physical State/lifecycle transport."""

        return self._materializes_connection

    @property
    def conn_id(self) -> str:
        """Return the exact canonical StateManager connection ID."""

        return self._physical_transport.conn_id

    @property
    def zeek_uid(self) -> str:
        """Return the exact physical transport Zeek UID."""

        return self._physical_transport.zeek_uid

    @property
    def lifecycle_publication_token(self) -> str:
        """Return the nested lifecycle proof when this transaction creates a transport."""

        receipt = self._lifecycle_receipt
        return "" if receipt is None else receipt.publication_token

    @property
    def application_proof(self) -> ApplicationChannelCompositeProof | None:
        """Return normalized application-manager proof, if this transaction has one."""

        return self._application_proof

    @property
    def prerequisite_proofs(self) -> tuple[ConnectionCompositePrerequisiteProof, ...]:
        """Return ordered already-committed transport prerequisites."""

        return self._prerequisite_proofs

    @property
    def start_plan_tokens(self) -> tuple[str, ...]:
        """Return ordered State start tokens committed by lifecycle authority."""

        receipt = self._lifecycle_receipt
        return () if receipt is None else receipt.start_plan_tokens

    @property
    def process_holds(self) -> tuple[LifecycleHold, ...]:
        """Return exact process holds committed with the physical transport."""

        receipt = self._lifecycle_receipt
        return () if receipt is None else receipt.process_holds

    @property
    def receipt_token(self) -> str:
        """Return the opaque authority proof used by dependent publications."""

        return self._integrity_token

    def _has_valid_integrity(self, authority_secret: bytes) -> bool:
        values = (
            self._state_publication_token,
            self._prior_version,
            self._committed_version,
            self._transaction_id,
            self._physical_transport,
            self._materializes_connection,
            self._lifecycle_receipt,
            self._application_proof,
            self._prerequisite_proofs,
        )
        expected = self._integrity_for(
            authority_secret=authority_secret,
            values=values,
        )
        return hmac.compare_digest(self._integrity_token, expected)


@dataclass(frozen=True, slots=True)
class LifecycleConnectionCompositeResult:
    """Exact committed rows plus their outer authority receipt."""

    state: ConnectionCompositeMaterializationResult
    lifecycle: LifecycleClosedTransportPublicationReceipt | None
    application: _ApplicationAdmissionResult | None
    receipt: LifecycleConnectionCompositeReceipt


_MAX_DETACHED_NETWORK_BINDING_TEXT_BYTES = 64 * 1024
_MAX_DETACHED_NETWORK_BINDING_PAYLOAD_BYTES = 1024 * 1024
_DETACHED_NETWORK_BINDING_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_DETACHED_NETWORK_BINDING_MIN_DATETIME_US = -62_135_596_800_000_000
_DETACHED_NETWORK_BINDING_MAX_DATETIME_US = 253_402_300_799_999_999


# A sealed capability stores one private Python handler beside inert structural
# contract data.  Security boundaries create their attester locally, validate
# the handler immediately before and after invocation, and never execute an
# externally reachable Python attester.  Replacing both the handler reference
# and its separate immutable contract (or rewriting the boundary method itself)
# is arbitrary in-process code execution and is outside the receipt-tampering
# model; every single handler/code/default/closure-cell mutation remains in
# scope and fails before the changed handler can run.
_DetachedNetworkSealedCapability = tuple[object, ...]


def _freeze_detached_network_sealed_capability(
    handler: Callable[[int, tuple[object, ...]], object],
) -> _DetachedNetworkSealedCapability:
    """Freeze inert function-state data for one closure-private handler."""

    frozen_getattribute = object.__getattribute__
    closure = frozen_getattribute(handler, "__closure__")
    if closure is None:
        closure_state: tuple[tuple[object, object], ...] = ()
        cell_type = type((lambda retained: lambda: retained)(None).__closure__[0])
    else:
        cell_type = type(closure[0])
        closure_state = tuple((cell, cell.cell_contents) for cell in closure)
    cell_contents_get = cell_type.cell_contents.__get__
    return (
        handler,
        frozen_getattribute(handler, "__code__"),
        frozen_getattribute(handler, "__defaults__"),
        frozen_getattribute(handler, "__kwdefaults__"),
        closure,
        closure_state,
        frozen_getattribute,
        FunctionType,
        cell_type,
        cell_contents_get,
    )


def _detached_network_binding_datetime_us(value: object, field_name: str) -> int:
    """Return one exact UTC datetime as a signed fixed-width microsecond scalar."""

    if type(value) is not datetime or value.tzinfo is not UTC:
        raise ValueError(f"{field_name} must be an exact UTC datetime")
    delta = value - _DETACHED_NETWORK_BINDING_EPOCH
    microseconds = ((delta.days * 86_400 + delta.seconds) * 1_000_000) + delta.microseconds
    if microseconds < -(1 << 63) or microseconds >= 1 << 63:
        raise ValueError(f"{field_name} exceeds the detached network-binding datetime bound")
    return microseconds


def _detached_network_binding_signed_datetime_us(value: object, field_name: str) -> int:
    """Validate one exact scalar in Python's UTC datetime range."""

    if type(value) is not int or not (
        _DETACHED_NETWORK_BINDING_MIN_DATETIME_US
        <= value
        <= _DETACHED_NETWORK_BINDING_MAX_DATETIME_US
    ):
        raise ValueError(f"{field_name} must be an exact representable UTC microsecond scalar")
    return value


def _detached_network_binding_datetime_from_us(value: object, field_name: str) -> datetime:
    """Reconstruct an exact UTC datetime from one validated scalar."""

    microseconds = _detached_network_binding_signed_datetime_us(value, field_name)
    return _DETACHED_NETWORK_BINDING_EPOCH + timedelta(microseconds=microseconds)


@dataclass(frozen=True, slots=True)
class LifecycleDetachedNetworkReceiptBinding:
    """Stateless scalar proof of one authenticated prepared-network receipt.

    The lifecycle authority retains no row for this value. A future protocol
    manager owns exact object identity, freshness, and lifetime. Byte-identical
    copies are intentionally equivalent at this value-proof boundary.
    """

    transaction_id: str
    state_publication_token: str
    runtime_publication_token: str
    materialization_mode: str
    lifecycle_mode: str
    physical_transport_id: str
    conn_id: str
    zeek_uid: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    started_at_us: int
    closed_at_us: int | None
    network_result_digest: str
    timing_binding_digest: str
    timing_receipt_digest: str
    runtime_receipt_digest: str
    connection_receipt_digest: str
    source_receipt_token: str
    _integrity_token: str = field(repr=False, default="")

    @property
    def tuple_key(self) -> tuple[str, int, str, int, str]:
        """Return the exact physical transport five-tuple."""

        return self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol

    @property
    def started_at(self) -> datetime:
        """Return the exact canonical transport start."""

        return _detached_network_binding_datetime_from_us(
            self.started_at_us,
            "binding.started_at_us",
        )

    @property
    def closed_at(self) -> datetime | None:
        """Return the exact canonical transport close, if finite."""

        if self.closed_at_us is None:
            return None
        return _detached_network_binding_datetime_from_us(
            self.closed_at_us,
            "binding.closed_at_us",
        )

    @property
    def proof_token(self) -> str:
        """Return the lifecycle authority's stateless value proof."""

        return self._integrity_token


_DETACHED_NETWORK_BINDING_FIELD_NAMES = (
    "transaction_id",
    "state_publication_token",
    "runtime_publication_token",
    "materialization_mode",
    "lifecycle_mode",
    "physical_transport_id",
    "conn_id",
    "zeek_uid",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "started_at_us",
    "closed_at_us",
    "network_result_digest",
    "timing_binding_digest",
    "timing_receipt_digest",
    "runtime_receipt_digest",
    "connection_receipt_digest",
    "source_receipt_token",
    "_integrity_token",
)
_DETACHED_NETWORK_BINDING_DESCRIPTORS = tuple(
    vars(LifecycleDetachedNetworkReceiptBinding)[field_name]
    for field_name in _DETACHED_NETWORK_BINDING_FIELD_NAMES
)
_DETACHED_NETWORK_BINDING_TRUSTED_NAMESPACE = tuple(
    vars(LifecycleDetachedNetworkReceiptBinding).items()
)
_DETACHED_NETWORK_BINDING_TRUSTED_METADATA = tuple(
    vars(LifecycleDetachedNetworkReceiptBinding)["__dataclass_fields__"].items()
)


def _freeze_detached_network_binding_boundary_capability() -> _DetachedNetworkSealedCapability:
    """Seal binding capture, framing, signing, allocation, and verification."""

    frozen_class = LifecycleDetachedNetworkReceiptBinding
    frozen_namespace = _DETACHED_NETWORK_BINDING_TRUSTED_NAMESPACE
    frozen_metadata = _DETACHED_NETWORK_BINDING_TRUSTED_METADATA
    frozen_descriptors = _DETACHED_NETWORK_BINDING_DESCRIPTORS
    frozen_field_count = len(_DETACHED_NETWORK_BINDING_FIELD_NAMES)
    frozen_text_limit = _MAX_DETACHED_NETWORK_BINDING_TEXT_BYTES
    frozen_payload_limit = _MAX_DETACHED_NETWORK_BINDING_PAYLOAD_BYTES
    frozen_min_datetime = _DETACHED_NETWORK_BINDING_MIN_DATETIME_US
    frozen_max_datetime = _DETACHED_NETWORK_BINDING_MAX_DATETIME_US
    frozen_prefix = b"lifecycle-detached-network-receipt-binding-v1\0"
    frozen_hex = "0123456789abcdef"
    frozen_physical_mode = "physical"
    frozen_application_mode = "application_child"
    frozen_network_mode = "network"
    frozen_deferred_mode = "deferred_session"
    frozen_bool_type = bool
    frozen_bytes_type = bytes
    frozen_bytearray_type = bytearray
    frozen_dict_type = dict
    frozen_function_type = FunctionType
    frozen_int_type = int
    frozen_mapping_type = type(vars(frozen_class))
    frozen_member_descriptor_type = MemberDescriptorType
    frozen_str_type = str
    frozen_tuple_type = tuple
    frozen_type = type
    frozen_len = len
    frozen_zip = zip
    frozen_object_getattribute = object.__getattribute__
    frozen_type_getattribute = type.__getattribute__
    frozen_mapping_get = frozen_mapping_type.get
    frozen_dict_get = dict.get
    frozen_member_get = MemberDescriptorType.__get__
    frozen_member_set = MemberDescriptorType.__set__
    frozen_object_new = object.__new__
    frozen_bytearray_extend = bytearray.extend
    frozen_bytes_from_buffer = bytes
    frozen_utf8_encode = str.encode
    frozen_int_to_bytes = int.to_bytes
    frozen_pack = struct.pack
    frozen_hmac_new = hmac._hashopenssl.hmac_new
    frozen_sha256 = sha256
    frozen_compare_digest = hmac.compare_digest
    frozen_hmac_type = frozen_type(frozen_hmac_new(b"", digestmod=frozen_sha256))
    frozen_hmac_hexdigest = frozen_hmac_type.hexdigest
    frozen_value_error = ValueError
    frozen_unicode_encode_error = UnicodeEncodeError
    frozen_sentinel = object()

    pending_functions: list[FunctionType] = []
    for _name, namespace_value in frozen_namespace:
        if type(namespace_value) is FunctionType:
            pending_functions.append(namespace_value)
        elif type(namespace_value) is property:
            for accessor in (
                namespace_value.fget,
                namespace_value.fset,
                namespace_value.fdel,
            ):
                if type(accessor) is FunctionType:
                    pending_functions.append(accessor)
    observed_functions: list[FunctionType] = []
    function_contracts: list[tuple[object, ...]] = []
    while pending_functions:
        trusted_function = pending_functions.pop()
        if any(retained is trusted_function for retained in observed_functions):
            continue
        observed_functions.append(trusted_function)
        closure = frozen_object_getattribute(trusted_function, "__closure__")
        closure_state = (
            () if closure is None else tuple((cell, cell.cell_contents) for cell in closure)
        )
        kwdefaults = frozen_object_getattribute(trusted_function, "__kwdefaults__")
        kwdefault_state = () if kwdefaults is None else tuple(kwdefaults.items())
        function_contracts.append(
            (
                trusted_function,
                frozen_object_getattribute(trusted_function, "__code__"),
                frozen_object_getattribute(trusted_function, "__defaults__"),
                kwdefaults,
                kwdefault_state,
                closure,
                closure_state,
            )
        )
        for _cell, captured in closure_state:
            if type(captured) is FunctionType:
                pending_functions.append(captured)
    frozen_function_contracts = tuple(function_contracts)

    annotations = vars(frozen_class)["__annotations__"]
    frozen_annotations = tuple(annotations.items())
    frozen_field_type = type(frozen_metadata[0][1])
    frozen_field_slots = tuple(frozen_field_type.__slots__)
    frozen_field_states = tuple(
        (
            trusted_field,
            tuple(
                (slot_name, frozen_object_getattribute(trusted_field, slot_name))
                for slot_name in frozen_field_slots
            ),
        )
        for _field_name, trusted_field in frozen_metadata
    )
    dataclass_params = vars(frozen_class)["__dataclass_params__"]
    frozen_params_type = type(dataclass_params)
    frozen_params_slots = tuple(frozen_params_type.__slots__)
    frozen_params_state = tuple(
        (
            slot_name,
            frozen_object_getattribute(dataclass_params, slot_name),
        )
        for slot_name in frozen_params_slots
    )

    def invoke(operation: int, arguments: tuple[object, ...]) -> object:
        def validates_function_contract(contract: tuple[object, ...]) -> bool:
            (
                trusted_function,
                expected_code,
                expected_defaults,
                expected_kwdefaults,
                expected_kwdefault_state,
                expected_closure,
                expected_closure_state,
            ) = contract
            if frozen_type(trusted_function) is not frozen_function_type:
                return False
            if (
                frozen_object_getattribute(trusted_function, "__code__") is not expected_code
                or frozen_object_getattribute(trusted_function, "__defaults__")
                is not expected_defaults
                or frozen_object_getattribute(trusted_function, "__kwdefaults__")
                is not expected_kwdefaults
                or frozen_object_getattribute(trusted_function, "__closure__")
                is not expected_closure
            ):
                return False
            if expected_kwdefaults is not None:
                if frozen_type(expected_kwdefaults) is not frozen_dict_type or frozen_len(
                    expected_kwdefaults
                ) != frozen_len(expected_kwdefault_state):
                    return False
                for name, expected in expected_kwdefault_state:
                    if frozen_dict_get(expected_kwdefaults, name, frozen_sentinel) is not expected:
                        return False
            if expected_closure is not None:
                if frozen_len(expected_closure) != frozen_len(expected_closure_state):
                    return False
                for observed, expected in frozen_zip(
                    expected_closure,
                    expected_closure_state,
                    strict=True,
                ):
                    expected_cell, expected_value = expected
                    if (
                        observed is not expected_cell
                        or observed.cell_contents is not expected_value
                    ):
                        return False
            return True

        def class_authenticates() -> bool:
            namespace = frozen_type_getattribute(frozen_class, "__dict__")
            if frozen_type(namespace) is not frozen_mapping_type or frozen_len(
                namespace
            ) != frozen_len(frozen_namespace):
                return False
            for name, trusted in frozen_namespace:
                if frozen_mapping_get(namespace, name, frozen_sentinel) is not trusted:
                    return False
            metadata = frozen_mapping_get(
                namespace,
                "__dataclass_fields__",
                frozen_sentinel,
            )
            if frozen_type(metadata) is not frozen_dict_type or frozen_len(metadata) != frozen_len(
                frozen_metadata
            ):
                return False
            for name, trusted in frozen_metadata:
                if frozen_dict_get(metadata, name, frozen_sentinel) is not trusted:
                    return False
            retained_annotations = frozen_mapping_get(
                namespace,
                "__annotations__",
                frozen_sentinel,
            )
            if frozen_type(retained_annotations) is not frozen_dict_type or frozen_len(
                retained_annotations
            ) != frozen_len(frozen_annotations):
                return False
            for name, trusted in frozen_annotations:
                if frozen_dict_get(retained_annotations, name, frozen_sentinel) is not trusted:
                    return False
            for trusted_field, expected_state in frozen_field_states:
                if frozen_type(trusted_field) is not frozen_field_type:
                    return False
                for slot_name, expected in expected_state:
                    if frozen_object_getattribute(trusted_field, slot_name) is not expected:
                        return False
            if frozen_type(dataclass_params) is not frozen_params_type:
                return False
            for slot_name, expected in frozen_params_state:
                if frozen_object_getattribute(dataclass_params, slot_name) is not expected:
                    return False
            for contract in frozen_function_contracts:
                if not validates_function_contract(contract):
                    return False
            return True

        def digest(value: object) -> str:
            if frozen_type(value) is not frozen_str_type or frozen_len(value) != 64:
                raise frozen_value_error("detached binding digest is malformed")
            for character in value:
                if character not in frozen_hex:
                    raise frozen_value_error("detached binding digest is malformed")
            return value

        def text(value: object) -> bytes:
            if (
                frozen_type(value) is not frozen_str_type
                or not value
                or frozen_len(value) > frozen_text_limit
            ):
                raise frozen_value_error("detached binding text is malformed")
            try:
                encoded = frozen_utf8_encode(value, "utf-8")
            except frozen_unicode_encode_error as error:
                raise frozen_value_error("detached binding text is not UTF-8") from error
            if (
                frozen_type(encoded) is not frozen_bytes_type
                or frozen_len(encoded) > frozen_text_limit
            ):
                raise frozen_value_error("detached binding text is malformed")
            return frozen_pack(">I", frozen_len(encoded)) + encoded

        def capture(binding: object) -> tuple[object, ...]:
            if frozen_type(binding) is not frozen_class or not class_authenticates():
                raise frozen_value_error("detached binding class is not authentic")
            captured: list[object] = []
            for descriptor in frozen_descriptors:
                if frozen_type(descriptor) is not frozen_member_descriptor_type:
                    raise frozen_value_error("detached binding descriptor is not authentic")
                captured.append(frozen_member_get(descriptor, binding, frozen_class))
            if not class_authenticates():
                raise frozen_value_error("detached binding class is not authentic")
            return frozen_tuple_type(captured)

        def payload(values: object) -> bytes:
            if (
                frozen_type(values) is not frozen_tuple_type
                or frozen_len(values) != frozen_field_count - 1
            ):
                raise frozen_value_error("detached binding field vector is malformed")
            (
                transaction_id,
                state_publication_token,
                runtime_publication_token,
                materialization_mode,
                lifecycle_mode,
                physical_transport_id,
                conn_id,
                zeek_uid,
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                protocol,
                started_at_us,
                closed_at_us,
                network_result_digest,
                timing_binding_digest,
                timing_receipt_digest,
                runtime_receipt_digest,
                connection_receipt_digest,
                source_receipt_token,
            ) = values
            digest(state_publication_token)
            digest(runtime_publication_token)
            digest(network_result_digest)
            digest(timing_binding_digest)
            digest(timing_receipt_digest)
            digest(runtime_receipt_digest)
            digest(connection_receipt_digest)
            digest(source_receipt_token)
            if frozen_type(materialization_mode) is not frozen_str_type or (
                materialization_mode != frozen_physical_mode
                and materialization_mode != frozen_application_mode
            ):
                raise frozen_value_error("detached binding materialization mode is malformed")
            if frozen_type(lifecycle_mode) is not frozen_str_type or (
                lifecycle_mode != frozen_network_mode
                and lifecycle_mode != frozen_deferred_mode
                and lifecycle_mode != frozen_application_mode
            ):
                raise frozen_value_error("detached binding lifecycle mode is malformed")
            retained = frozen_bytearray_type(frozen_prefix)
            for value in (
                transaction_id,
                state_publication_token,
                runtime_publication_token,
                materialization_mode,
                lifecycle_mode,
                physical_transport_id,
                conn_id,
                zeek_uid,
                src_ip,
                dst_ip,
                protocol,
            ):
                frozen_bytearray_extend(retained, text(value))
            for port in (src_port, dst_port):
                if frozen_type(port) is not frozen_int_type or not 0 <= port < 1 << 16:
                    raise frozen_value_error("detached binding port is malformed")
                frozen_bytearray_extend(retained, frozen_int_to_bytes(port, 2, "big"))
            if frozen_type(started_at_us) is not frozen_int_type or not (
                frozen_min_datetime <= started_at_us <= frozen_max_datetime
            ):
                raise frozen_value_error("detached binding start time is malformed")
            frozen_bytearray_extend(retained, frozen_pack(">q", started_at_us))
            if closed_at_us is None:
                frozen_bytearray_extend(retained, b"\0")
            else:
                if frozen_type(closed_at_us) is not frozen_int_type or not (
                    frozen_min_datetime <= closed_at_us <= frozen_max_datetime
                ):
                    raise frozen_value_error("detached binding close time is malformed")
                frozen_bytearray_extend(retained, b"\1")
                frozen_bytearray_extend(retained, frozen_pack(">q", closed_at_us))
            for value in (
                network_result_digest,
                timing_binding_digest,
                timing_receipt_digest,
                runtime_receipt_digest,
                connection_receipt_digest,
                source_receipt_token,
            ):
                frozen_bytearray_extend(retained, text(value))
            if frozen_len(retained) > frozen_payload_limit:
                raise frozen_value_error("detached binding payload exceeds its bound")
            return frozen_bytes_from_buffer(retained)

        def sign(secret: object, retained_payload: bytes) -> str:
            if frozen_type(secret) is not frozen_bytes_type or frozen_len(secret) != 32:
                raise frozen_value_error("detached binding secret is malformed")
            retained_hmac = frozen_hmac_new(secret, retained_payload, frozen_sha256)
            if frozen_type(retained_hmac) is not frozen_hmac_type:
                raise frozen_value_error("detached binding HMAC constructor is malformed")
            retained_digest = frozen_hmac_hexdigest(retained_hmac)
            if frozen_type(retained_digest) is not frozen_str_type:
                raise frozen_value_error("detached binding HMAC result is malformed")
            return digest(retained_digest)

        if (
            frozen_type(operation) is not frozen_int_type
            or frozen_type(arguments) is not frozen_tuple_type
        ):
            raise frozen_value_error("detached binding operation is malformed")
        if operation == 0:
            if frozen_len(arguments) != 2:
                raise frozen_value_error("detached binding signing request is malformed")
            values, secret = arguments
            if not class_authenticates():
                raise frozen_value_error("detached binding class is not authentic")
            proof = sign(secret, payload(values))
            if not class_authenticates():
                raise frozen_value_error("detached binding class is not authentic")
            return proof
        if operation == 1:
            if frozen_len(arguments) != 2:
                raise frozen_value_error("detached binding allocation request is malformed")
            values, proof = arguments
            payload(values)
            digest(proof)
            if not class_authenticates():
                raise frozen_value_error("detached binding class is not authentic")
            binding = frozen_object_new(frozen_class)
            field_values = (*values, proof)
            for descriptor, value in frozen_zip(
                frozen_descriptors,
                field_values,
                strict=True,
            ):
                frozen_member_set(descriptor, binding, value)
            if not class_authenticates():
                raise frozen_value_error("detached binding class is not authentic")
            return binding
        if operation == 2:
            if frozen_len(arguments) != 2:
                raise frozen_value_error("detached binding verification request is malformed")
            binding, secret = arguments
            captured = capture(binding)
            retained = digest(captured[-1])
            expected = sign(secret, payload(captured[:-1]))
            matches = frozen_compare_digest(retained, expected)
            if frozen_type(matches) is not frozen_bool_type or not class_authenticates():
                raise frozen_value_error("detached binding verification result is malformed")
            return matches
        if operation == 3:
            if frozen_len(arguments) != 3:
                raise frozen_value_error("detached binding result check is malformed")
            binding, values, proof = arguments
            payload(values)
            digest(proof)
            captured = capture(binding)
            payload(captured[:-1])
            digest(captured[-1])
            if frozen_len(captured) != frozen_field_count:
                return False
            expected = (*values, proof)
            for observed, retained in frozen_zip(captured, expected, strict=True):
                if frozen_type(observed) is not frozen_type(retained) or observed != retained:
                    return False
            return class_authenticates()
        raise frozen_value_error("detached binding operation is unknown")

    return _freeze_detached_network_sealed_capability(invoke)


_DETACHED_NETWORK_BINDING_BOUNDARY_CAPABILITY = (
    _freeze_detached_network_binding_boundary_capability()
)


def _freeze_detached_network_binding_boundary_methods(
    capability: _DetachedNetworkSealedCapability,
    issuance_record_type: type[object],
    issuance_claim_type: type[object],
    receipt_type: type[object],
    issuance_descriptors: tuple[MemberDescriptorType, ...],
) -> tuple[Callable[..., object], Callable[..., object], Callable[..., object]]:
    """Create non-injectable authority methods around one sealed capability.

    The trusted handler and its structural contract occupy distinct closure
    cells.  Single-cell mutation therefore fails before handler execution.
    Coordinated replacement of both cells, or rewriting these boundary methods,
    is arbitrary in-process code execution outside the receipt-tampering model.
    """

    (
        trusted_call,
        expected_function,
        expected_code,
        expected_defaults,
        expected_kwdefaults,
        expected_closure,
        expected_closure_state,
        frozen_getattribute,
        frozen_function_type,
        frozen_cell_type,
        frozen_cell_contents_get,
    ) = (capability[0], *capability)
    frozen_type = type
    frozen_len = len
    frozen_bool_type = bool
    frozen_str_type = str
    frozen_value_error = ValueError
    frozen_state_error = StateError
    frozen_rejected_errors = (
        AttributeError,
        OverflowError,
        TypeError,
        UnicodeError,
        ValueError,
    )
    frozen_assertion_error = AssertionError
    frozen_object_getattribute = object.__getattribute__
    frozen_dict_type = dict
    frozen_dict_get = dict.get
    frozen_bytes_type = bytes
    frozen_int_type = int
    frozen_tuple_type = tuple
    frozen_reference_type = ReferenceType
    frozen_reference_call = ReferenceType.__call__
    frozen_member_get = MemberDescriptorType.__get__
    frozen_lock_type = type(RLock())
    frozen_id = id
    frozen_zip = zip
    frozen_issuance_record_type = issuance_record_type
    frozen_issuance_claim_type = issuance_claim_type
    frozen_receipt_type = receipt_type
    frozen_issuance_descriptors = issuance_descriptors

    def construct(
        self: object,
        values: tuple[object, ...],
        proof: str,
    ) -> LifecycleDetachedNetworkReceiptBinding:
        def handler_authenticates() -> bool:
            if trusted_call is not expected_function or frozen_type(trusted_call) is not (
                frozen_function_type
            ):
                return False
            if (
                frozen_getattribute(trusted_call, "__code__") is not expected_code
                or frozen_getattribute(trusted_call, "__defaults__") is not expected_defaults
                or frozen_getattribute(trusted_call, "__kwdefaults__") is not expected_kwdefaults
                or frozen_getattribute(trusted_call, "__closure__") is not expected_closure
            ):
                return False
            if expected_closure is None:
                return not expected_closure_state
            if frozen_len(expected_closure) != frozen_len(expected_closure_state):
                return False
            for observed, expected in frozen_zip(
                expected_closure,
                expected_closure_state,
                strict=True,
            ):
                expected_cell, expected_value = expected
                if (
                    frozen_type(observed) is not frozen_cell_type
                    or observed is not expected_cell
                    or frozen_cell_contents_get(observed, frozen_cell_type) is not expected_value
                ):
                    return False
            return True

        def invoke(operation: int, arguments: tuple[object, ...]) -> object:
            if not handler_authenticates():
                raise frozen_value_error("detached binding capability is not authentic")
            try:
                result = trusted_call(operation, arguments)
            finally:
                if not handler_authenticates():
                    raise frozen_value_error("detached binding capability is not authentic")
            return result

        del self
        allocated = invoke(1, (values, proof))
        matches = invoke(3, (allocated, values, proof))
        if frozen_type(matches) is not frozen_bool_type or not matches:
            raise frozen_value_error("detached binding allocator returned a mismatched value")
        return allocated  # type: ignore[return-value]

    def issue(
        self: object,
        issuance_record: object,
        values: tuple[object, ...],
    ) -> LifecycleDetachedNetworkReceiptBinding:
        def issuance_authenticates() -> bool:
            if frozen_type(issuance_record) is not frozen_issuance_record_type:
                return False
            try:
                (
                    root,
                    generation,
                    receipt,
                    claim_ref,
                    detached_values,
                    canonical_committed,
                    terminal,
                ) = frozen_tuple_type(
                    frozen_member_get(
                        descriptor,
                        issuance_record,
                        frozen_issuance_record_type,
                    )
                    for descriptor in frozen_issuance_descriptors
                )
                instance_namespace = frozen_object_getattribute(self, "__dict__")
                if frozen_type(instance_namespace) is not frozen_dict_type:
                    return False
                issuance_lock = frozen_dict_get(
                    instance_namespace,
                    "_prepared_network_receipt_issuance_lock",
                )
                issuances = frozen_dict_get(
                    instance_namespace,
                    "_prepared_network_receipt_issuances",
                )
                generations = frozen_dict_get(
                    instance_namespace,
                    "_prepared_network_receipt_issuance_generations",
                )
                receipts = frozen_dict_get(
                    instance_namespace,
                    "_prepared_network_receipt_issuance_receipts",
                )
            except frozen_rejected_errors:
                return False
            if (
                frozen_type(generation) is not frozen_int_type
                or generation <= 0
                or frozen_type(receipt) is not frozen_receipt_type
                or frozen_type(claim_ref) is not frozen_reference_type
                or frozen_type(frozen_reference_call(claim_ref)) is not frozen_issuance_claim_type
                or detached_values is not values
                or canonical_committed is not True
                or terminal is not False
                or frozen_type(issuance_lock) is not frozen_lock_type
                or frozen_type(issuances) is not frozen_dict_type
                or frozen_type(generations) is not frozen_dict_type
                or frozen_type(receipts) is not frozen_dict_type
            ):
                return False
            root_id = frozen_id(root)
            key = (root_id, generation)
            with issuance_lock:
                return (
                    frozen_dict_get(issuances, key) is issuance_record
                    and frozen_dict_get(generations, root_id) == generation
                    and frozen_dict_get(receipts, frozen_id(receipt)) == key
                )

        def handler_authenticates() -> bool:
            if trusted_call is not expected_function or frozen_type(trusted_call) is not (
                frozen_function_type
            ):
                return False
            if (
                frozen_getattribute(trusted_call, "__code__") is not expected_code
                or frozen_getattribute(trusted_call, "__defaults__") is not expected_defaults
                or frozen_getattribute(trusted_call, "__kwdefaults__") is not expected_kwdefaults
                or frozen_getattribute(trusted_call, "__closure__") is not expected_closure
            ):
                return False
            if expected_closure is None:
                return not expected_closure_state
            if frozen_len(expected_closure) != frozen_len(expected_closure_state):
                return False
            for observed, expected in frozen_zip(
                expected_closure,
                expected_closure_state,
                strict=True,
            ):
                expected_cell, expected_value = expected
                if (
                    frozen_type(observed) is not frozen_cell_type
                    or observed is not expected_cell
                    or frozen_cell_contents_get(observed, frozen_cell_type) is not expected_value
                ):
                    return False
            return True

        def invoke(operation: int, arguments: tuple[object, ...]) -> object:
            if not handler_authenticates():
                raise frozen_state_error("Detached binding capability is not trusted")
            try:
                result = trusted_call(operation, arguments)
            finally:
                if not handler_authenticates():
                    raise frozen_state_error("Detached binding capability is not trusted")
            return result

        try:
            instance_namespace = frozen_object_getattribute(self, "__dict__")
            if frozen_type(instance_namespace) is not frozen_dict_type:
                raise frozen_state_error("Detached binding authority has no trusted namespace")
            secret = frozen_dict_get(instance_namespace, "_receipt_secret")
            if frozen_type(secret) is not frozen_bytes_type:
                raise frozen_state_error("Detached binding authority secret is malformed")
            if not issuance_authenticates():
                raise frozen_state_error(
                    "Detached binding requires an exact retained issuance authority"
                )
            proof = invoke(0, (values, secret))
            if frozen_type(proof) is not frozen_str_type:
                raise frozen_state_error("Detached binding proof has an invalid type")
            binding = invoke(1, (values, proof))
            matches_values = invoke(3, (binding, values, proof))
            authentic = invoke(2, (binding, secret))
            if not issuance_authenticates():
                raise frozen_state_error(
                    "Detached binding requires an exact retained issuance authority"
                )
        except frozen_rejected_errors as error:
            if frozen_type(error) is frozen_state_error:
                raise
            raise frozen_state_error("Detached binding issuance failed closed") from error
        if (
            frozen_type(matches_values) is not frozen_bool_type
            or not matches_values
            or frozen_type(authentic) is not frozen_bool_type
            or not authentic
        ):
            raise frozen_assertion_error("Detached prepared-network proof reconstruction failed")
        return binding  # type: ignore[return-value]

    def authenticates(self: object, binding: object) -> bool:
        def handler_authenticates() -> bool:
            if trusted_call is not expected_function or frozen_type(trusted_call) is not (
                frozen_function_type
            ):
                return False
            if (
                frozen_getattribute(trusted_call, "__code__") is not expected_code
                or frozen_getattribute(trusted_call, "__defaults__") is not expected_defaults
                or frozen_getattribute(trusted_call, "__kwdefaults__") is not expected_kwdefaults
                or frozen_getattribute(trusted_call, "__closure__") is not expected_closure
            ):
                return False
            if expected_closure is None:
                return not expected_closure_state
            if frozen_len(expected_closure) != frozen_len(expected_closure_state):
                return False
            for observed, expected in frozen_zip(
                expected_closure,
                expected_closure_state,
                strict=True,
            ):
                expected_cell, expected_value = expected
                if (
                    frozen_type(observed) is not frozen_cell_type
                    or observed is not expected_cell
                    or frozen_cell_contents_get(observed, frozen_cell_type) is not expected_value
                ):
                    return False
            return True

        def invoke(operation: int, arguments: tuple[object, ...]) -> object:
            if not handler_authenticates():
                raise frozen_value_error("detached binding capability is not authentic")
            try:
                result = trusted_call(operation, arguments)
            finally:
                if not handler_authenticates():
                    raise frozen_value_error("detached binding capability is not authentic")
            return result

        try:
            instance_namespace = frozen_object_getattribute(self, "__dict__")
            if frozen_type(instance_namespace) is not frozen_dict_type:
                return False
            secret = frozen_dict_get(instance_namespace, "_receipt_secret")
            if frozen_type(secret) is not frozen_bytes_type:
                return False
            authentic = invoke(2, (binding, secret))
        except frozen_rejected_errors:
            return False
        return frozen_type(authentic) is frozen_bool_type and authentic

    construct.__name__ = "_construct_detached_network_receipt_binding"
    construct.__qualname__ = (
        "GeneratorLifecycleAuthority._construct_detached_network_receipt_binding"
    )
    construct.__doc__ = "Construct one exact binding through the sealed allocator."
    issue.__name__ = "_issue_detached_network_receipt_binding_recoverably"
    issue.__qualname__ = (
        "GeneratorLifecycleAuthority._issue_detached_network_receipt_binding_recoverably"
    )
    issue.__doc__ = "Issue one stateless proof through the sealed binding boundary."
    authenticates.__name__ = "authenticates_detached_network_receipt_binding"
    authenticates.__qualname__ = (
        "GeneratorLifecycleAuthority.authenticates_detached_network_receipt_binding"
    )
    authenticates.__doc__ = (
        "Authenticate one stateless detached network-receipt value proof.\n\n"
        "Byte-identical copies are equivalent. Exact object identity, staleness, "
        "and lifetime belong to the manager capability that cross-binds this proof."
    )
    return construct, issue, authenticates


@dataclass(frozen=True, slots=True, weakref_slot=True)
class LifecyclePreparedNetworkReceipt:
    """Authenticated proof of one complete runtime/timing/network publication."""

    _runtime_publication_token: str
    _state_publication_token: str
    _transaction_id: str
    _materialization_mode: ConnectionMaterializationMode
    _lifecycle_mode: NetworkTransportLifecycleMode
    _physical_transport: PhysicalTransportFingerprint
    _result_digest: str
    _timing_binding_token: SourceTimingPreparationToken
    _connection_receipt: LifecycleConnectionCompositeReceipt
    _runtime_receipt: NetworkTransactionPreparationReceipt
    _timing_receipt: SourceTimingPreparationReceipt
    _integrity_token: str

    @classmethod
    def _issue(
        cls,
        *,
        authority_secret: bytes,
        runtime_publication_token: str,
        state_publication_token: str,
        transaction_id: str,
        materialization_mode: ConnectionMaterializationMode,
        lifecycle_mode: NetworkTransportLifecycleMode,
        physical_transport: PhysicalTransportFingerprint,
        result_digest: str,
        timing_binding_token: SourceTimingPreparationToken,
        connection_receipt: LifecycleConnectionCompositeReceipt,
        runtime_receipt: NetworkTransactionPreparationReceipt,
        timing_receipt: SourceTimingPreparationReceipt,
    ) -> LifecyclePreparedNetworkReceipt:
        """Issue one authority-keyed receipt over every nested commit proof."""

        values = (
            runtime_publication_token,
            state_publication_token,
            transaction_id,
            materialization_mode,
            lifecycle_mode,
            physical_transport,
            result_digest,
            timing_binding_token,
            connection_receipt,
            runtime_receipt,
            timing_receipt,
        )
        integrity_token = cls._integrity_for(
            authority_secret=authority_secret,
            values=values,
        )
        return cls(*values, integrity_token)

    @staticmethod
    def _integrity_for(
        *,
        authority_secret: bytes,
        values: tuple[object, ...],
    ) -> str:
        """Return the authority HMAC over exact nested network authority truth."""

        canonical = ("lifecycle-prepared-network-v1", *values)
        return hmac.new(
            authority_secret,
            repr(canonical).encode(),
            sha256,
        ).hexdigest()

    @property
    def prior_version(self) -> int:
        """Return the StateManager version consumed by this transaction."""

        return self._connection_receipt.prior_version

    @property
    def committed_version(self) -> int:
        """Return the StateManager version after this transaction committed."""

        return self._connection_receipt.committed_version

    @property
    def transaction_id(self) -> str:
        """Return the finalized network transaction identity."""

        return self._transaction_id

    @property
    def physical_transport_id(self) -> str:
        """Return the physical transport owning this occurrence."""

        return self._physical_transport.transport_id

    @property
    def materializes_connection(self) -> bool:
        """Return whether this receipt created the physical transport."""

        return self._connection_receipt.materializes_connection

    @property
    def connection_receipt(self) -> LifecycleConnectionCompositeReceipt:
        """Return the nested State/lifecycle/application proof."""

        return self._connection_receipt

    @property
    def runtime_receipt(self) -> NetworkTransactionPreparationReceipt:
        """Return the nested network-runtime and cryptographic proof."""

        return self._runtime_receipt

    @property
    def timing_receipt(self) -> SourceTimingPreparationReceipt:
        """Return the nested source-timing proof."""

        return self._timing_receipt

    @property
    def timing_binding_token(self) -> SourceTimingPreparationToken:
        """Return the exact source-timing preparation binding."""

        return self._timing_binding_token

    @property
    def receipt_token(self) -> str:
        """Return the opaque outer authority proof."""

        return self._integrity_token

    def _has_valid_integrity(self, authority_secret: bytes) -> bool:
        values = (
            self._runtime_publication_token,
            self._state_publication_token,
            self._transaction_id,
            self._materialization_mode,
            self._lifecycle_mode,
            self._physical_transport,
            self._result_digest,
            self._timing_binding_token,
            self._connection_receipt,
            self._runtime_receipt,
            self._timing_receipt,
        )
        expected = self._integrity_for(
            authority_secret=authority_secret,
            values=values,
        )
        return hmac.compare_digest(self._integrity_token, expected)


_PREPARED_NETWORK_RECEIPT_FIELD_NAMES = (
    "_runtime_publication_token",
    "_state_publication_token",
    "_transaction_id",
    "_materialization_mode",
    "_lifecycle_mode",
    "_physical_transport",
    "_result_digest",
    "_timing_binding_token",
    "_connection_receipt",
    "_runtime_receipt",
    "_timing_receipt",
    "_integrity_token",
)
_PREPARED_NETWORK_RECEIPT_DESCRIPTORS = tuple(
    vars(LifecyclePreparedNetworkReceipt)[field_name]
    for field_name in _PREPARED_NETWORK_RECEIPT_FIELD_NAMES
)


def _allocate_prepared_network_receipt_shell(
    values: tuple[object, ...] | None = None,
    *,
    _receipt_type: type[LifecyclePreparedNetworkReceipt] = LifecyclePreparedNetworkReceipt,
    _descriptors: tuple[MemberDescriptorType, ...] = _PREPARED_NETWORK_RECEIPT_DESCRIPTORS,
    _object_new: Callable[[type[object]], object] = object.__new__,
    _member_set: Callable[[object, object, object], None] = MemberDescriptorType.__set__,
) -> LifecyclePreparedNetworkReceipt:
    """Allocate one exact receipt shell without invoking live class behavior."""

    receipt = _object_new(_receipt_type)
    if values is not None:
        if type(values) is not tuple or len(values) != len(_descriptors):
            raise ValueError("Prepared-network receipt shell field vector is malformed")
        for descriptor, value in zip(_descriptors, values, strict=True):
            _member_set(descriptor, receipt, value)
    return cast(LifecyclePreparedNetworkReceipt, receipt)


@dataclass(frozen=True, slots=True)
class _PreparedNetworkReceiptAuthority:
    """Bounded exact-object authority for issuance-time detached scalar facts."""

    receipt_ref: ReferenceType[LifecyclePreparedNetworkReceipt]
    timing_authority: object
    timing_receipt_id: int
    generation: int
    detached_values: tuple[object, ...] | None = None
    detached_proof: str = ""
    committed: bool = False
    receipt_graph: _PreparedNetworkGraphSnapshot | None = None


_PREPARED_NETWORK_RECEIPT_AUTHORITY_FIELD_NAMES = (
    "receipt_ref",
    "timing_authority",
    "timing_receipt_id",
    "generation",
    "detached_values",
    "detached_proof",
    "committed",
    "receipt_graph",
)
_PREPARED_NETWORK_RECEIPT_AUTHORITY_DESCRIPTORS = tuple(
    vars(_PreparedNetworkReceiptAuthority)[field_name]
    for field_name in _PREPARED_NETWORK_RECEIPT_AUTHORITY_FIELD_NAMES
)


@dataclass(frozen=True, slots=True)
class LifecyclePreparedNetworkResult:
    """Exact committed connection, runtime, and source-timing results."""

    connection: LifecycleConnectionCompositeResult
    runtime: NetworkTransactionPreparationReceipt
    timing: SourceTimingPreparationReceipt
    receipt: LifecyclePreparedNetworkReceipt


_PREPARED_NETWORK_RESULT_FIELD_NAMES = (
    "connection",
    "runtime",
    "timing",
    "receipt",
)
_PREPARED_NETWORK_RESULT_DESCRIPTORS = tuple(
    vars(LifecyclePreparedNetworkResult)[field_name]
    for field_name in _PREPARED_NETWORK_RESULT_FIELD_NAMES
)

_MAX_PREPARED_NETWORK_AUTHORITY_GRAPH_NODES = 65_536
_MAX_PREPARED_NETWORK_AUTHORITY_GRAPH_TUPLE_MEMBERS = 65_536
_MAX_PREPARED_NETWORK_AUTHORITY_GRAPH_SCALAR_BYTES = 16 * 1024 * 1024
_PreparedNetworkGraphSnapshot = tuple[
    tuple[
        object | None,
        type[object],
        tuple[tuple[str, object], ...],
    ],
    ...,
]


def _capture_prepared_network_authoritative_graph(
    root: object,
    *,
    _fields: Callable[[type[object]], tuple[object, ...]] = fields,
    _is_dataclass: Callable[[object], bool] = is_dataclass,
    _object_getattribute: Callable[[object, str], object] = object.__getattribute__,
    _str_encode: Callable[[str, str], bytes] = str.encode,
) -> _PreparedNetworkGraphSnapshot:
    """Capture one bounded exact-object graph without retaining its public root twice."""

    pending: list[tuple[object, bool]] = [(root, True)]
    seen: set[int] = set()
    nodes: list[
        tuple[
            object | None,
            type[object],
            tuple[tuple[str, object], ...],
        ]
    ] = []
    charged_nodes = 0
    charged_scalar_bytes = 0
    while pending:
        value, is_root = pending.pop()
        value_type = type(value)
        if value is None or value_type in {bool, int, float, str, bytes}:
            charged_nodes += 1
            if value_type is str:
                charged_scalar_bytes += len(_str_encode(value, "utf-8"))
            elif value_type is bytes:
                charged_scalar_bytes += len(value)
            else:
                charged_scalar_bytes += 8
            if (
                charged_nodes > _MAX_PREPARED_NETWORK_AUTHORITY_GRAPH_NODES
                or charged_scalar_bytes > _MAX_PREPARED_NETWORK_AUTHORITY_GRAPH_SCALAR_BYTES
            ):
                raise StateError("Prepared-network authority graph exceeds its bound")
            continue

        identity = id(value)
        if identity in seen:
            if value is root:
                raise StateError("Prepared-network authority graph contains a root cycle")
            continue
        seen.add(identity)
        charged_nodes += 1
        if charged_nodes > _MAX_PREPARED_NETWORK_AUTHORITY_GRAPH_NODES:
            raise StateError("Prepared-network authority graph exceeds its node bound")

        if value_type is tuple:
            member_count = len(value)
            if member_count > _MAX_PREPARED_NETWORK_AUTHORITY_GRAPH_TUPLE_MEMBERS:
                raise StateError("Prepared-network authority graph tuple exceeds its bound")
            charged_nodes += member_count
            if charged_nodes > _MAX_PREPARED_NETWORK_AUTHORITY_GRAPH_NODES:
                raise StateError("Prepared-network authority graph exceeds its node bound")
            for member in value:
                pending.append((member, False))
            continue

        if not _is_dataclass(value_type):
            continue
        members = _fields(value_type)
        if type(members) is not tuple:
            raise StateError("Prepared-network authority graph metadata is malformed")
        if len(members) > _MAX_PREPARED_NETWORK_AUTHORITY_GRAPH_TUPLE_MEMBERS:
            raise StateError("Prepared-network authority object exceeds its field bound")
        captured_fields: list[tuple[str, object]] = []
        for member in members:
            field_name = _object_getattribute(member, "name")
            if type(field_name) is not str or not field_name:
                raise StateError("Prepared-network authority graph field is malformed")
            field_value = _object_getattribute(value, field_name)
            if field_value is root:
                raise StateError("Prepared-network authority graph contains a root cycle")
            captured_fields.append((field_name, field_value))
            pending.append((field_value, False))
        nodes.append(
            (
                None if is_root else value,
                value_type,
                tuple(captured_fields),
            )
        )
    if not nodes or nodes[0][0] is not None or nodes[0][1] is not type(root):
        raise StateError("Prepared-network authority graph has no exact dataclass root")
    return tuple(nodes)


def _prepared_network_authoritative_graph_matches(
    root: object,
    snapshot: object,
    *,
    _object_getattribute: Callable[[object, str], object] = object.__getattribute__,
) -> bool:
    """Compare one public graph to its neutral snapshot without invoking value callbacks."""

    if type(snapshot) is not tuple or not snapshot:
        return False
    scalar_types = {bool, int, float, str, bytes}
    for index, node in enumerate(snapshot):
        if type(node) is not tuple or len(node) != 3:
            return False
        retained, expected_type, expected_fields = node
        target = root if index == 0 else retained
        if (
            (index == 0 and retained is not None)
            or (index != 0 and retained is None)
            or type(expected_type) is not type
            or type(target) is not expected_type
            or type(expected_fields) is not tuple
        ):
            return False
        for expected_field in expected_fields:
            if type(expected_field) is not tuple or len(expected_field) != 2:
                return False
            field_name, expected = expected_field
            if type(field_name) is not str:
                return False
            try:
                actual = _object_getattribute(target, field_name)
            except AttributeError:
                return False
            expected_value_type = type(expected)
            if expected is None:
                if actual is not None:
                    return False
            elif expected_value_type in scalar_types:
                if type(actual) is not expected_value_type or actual != expected:
                    return False
            elif actual is not expected:
                return False
    return True


def _restore_prepared_network_authoritative_graph(
    root: object,
    snapshot: object,
    *,
    _object_setattr: Callable[[object, str, object], None] = object.__setattr__,
) -> bool:
    """Restore every exact field in one retained graph without reading caller values."""

    if type(snapshot) is not tuple or not snapshot:
        return False
    for index, node in enumerate(snapshot):
        if type(node) is not tuple or len(node) != 3:
            return False
        retained, expected_type, expected_fields = node
        target = root if index == 0 else retained
        if (
            (index == 0 and retained is not None)
            or (index != 0 and retained is None)
            or type(expected_type) is not type
            or type(target) is not expected_type
            or type(expected_fields) is not tuple
        ):
            return False
        for expected_field in expected_fields:
            if type(expected_field) is not tuple or len(expected_field) != 2:
                return False
            field_name, expected = expected_field
            if type(field_name) is not str:
                return False
            _object_setattr(target, field_name, expected)
    return _prepared_network_authoritative_graph_matches(root, snapshot)


def _allocate_prepared_network_result_shell(
    values: tuple[object, ...] | None = None,
    *,
    _result_type: type[LifecyclePreparedNetworkResult] = LifecyclePreparedNetworkResult,
    _descriptors: tuple[MemberDescriptorType, ...] = _PREPARED_NETWORK_RESULT_DESCRIPTORS,
    _object_new: Callable[[type[object]], object] = object.__new__,
    _member_set: Callable[[object, object, object], None] = MemberDescriptorType.__set__,
) -> LifecyclePreparedNetworkResult:
    """Allocate one exact result shell without invoking live class behavior."""

    result = _object_new(_result_type)
    if values is not None:
        if type(values) is not tuple or len(values) != len(_descriptors):
            raise ValueError("Prepared-network result shell field vector is malformed")
        for descriptor, value in zip(_descriptors, values, strict=True):
            _member_set(descriptor, result, value)
    return cast(LifecyclePreparedNetworkResult, result)


class _PreparedNetworkReceiptIssuanceClaim:
    """Ephemeral exact claim whose weak lifetime follows one materialization call."""

    __slots__ = ("__weakref__",)


@dataclass(slots=True)
class _PreparedNetworkReceiptIssuance:
    """Strong bounded carrier spanning canonical commit through result delivery."""

    root: PreparedNetworkTransactionRoot
    generation: int
    receipt: LifecyclePreparedNetworkReceipt
    result: LifecyclePreparedNetworkResult
    authority_record: _PreparedNetworkReceiptAuthority
    claim_ref: ReferenceType[_PreparedNetworkReceiptIssuanceClaim] | None
    authority_generation: int | None = None
    issuance_values: tuple[object, ...] | None = None
    result_values: tuple[object, ...] | None = None
    receipt_values: tuple[object, ...] | None = None
    detached_values: tuple[object, ...] | None = None
    detached_proof: str = ""
    root_graph: _PreparedNetworkGraphSnapshot | None = None
    result_graph: _PreparedNetworkGraphSnapshot | None = None
    receipt_graph: _PreparedNetworkGraphSnapshot | None = None
    durable_capture: object | None = None
    durable_capture_facts: tuple[object, ...] | None = None
    canonical_committed: bool = False
    terminal: bool = False


def _prepared_network_durable_capture_matches(
    root: object,
    receipt: object,
    capture: object,
    facts: object,
    *,
    _object_getattribute: Callable[[object, str], object] = object.__getattribute__,
    _capture_lock_type: type[object] = type(Lock()),
) -> bool:
    """Match one committed public capture to callback-free detached slot facts."""

    from evidenceforge.generation.actions.network_connection import (
        NetworkConnectionIdentityCapture,
        NetworkConnectionPublicationOutcome,
    )

    if (
        type(root) is not PreparedNetworkTransactionRoot
        or type(receipt) is not LifecyclePreparedNetworkReceipt
        or type(capture) is not NetworkConnectionIdentityCapture
        or type(facts) is not tuple
        or len(facts) != 10
    ):
        return False
    try:
        capture_lock = _object_getattribute(capture, "_lock")
        runtime_token = _object_getattribute(root, "runtime_token")
        transaction = _object_getattribute(root, "transaction")
        lifecycle_mode = _object_getattribute(runtime_token, "lifecycle_mode")
    except AttributeError:
        return False
    if type(capture_lock) is not _capture_lock_type:
        return False
    with capture_lock:
        captured = (
            _object_getattribute(capture, "_transaction"),
            _object_getattribute(capture, "_lifecycle_mode"),
            _object_getattribute(capture, "_prepared_root"),
            _object_getattribute(capture, "_source_timing_preparation"),
            _object_getattribute(capture, "_prepared_dispatch"),
            _object_getattribute(capture, "_persistent_smb_root_handoff"),
            _object_getattribute(capture, "_receipt"),
            _object_getattribute(capture, "_application_receipt"),
            _object_getattribute(capture, "_outcome"),
            _object_getattribute(capture, "_claim"),
        )
    for index, (supplied, expected) in enumerate(zip(captured, facts, strict=True)):
        if index == 1:
            if type(supplied) is not str or type(expected) is not str or supplied != expected:
                return False
        elif supplied is not expected:
            return False
    return (
        facts[0] is transaction
        and type(facts[1]) is str
        and type(lifecycle_mode) is str
        and facts[1] == lifecycle_mode
        and facts[2] is root
        and facts[4] is None
        and facts[6] is receipt
        and type(facts[8]) is NetworkConnectionPublicationOutcome
        and facts[9] is None
    )


_PREPARED_NETWORK_RECEIPT_ISSUANCE_SIGNER_FIELD_NAMES = (
    "root",
    "generation",
    "receipt",
    "claim_ref",
    "detached_values",
    "canonical_committed",
    "terminal",
)
_PREPARED_NETWORK_RECEIPT_ISSUANCE_SIGNER_DESCRIPTORS = tuple(
    vars(_PreparedNetworkReceiptIssuance)[field_name]
    for field_name in _PREPARED_NETWORK_RECEIPT_ISSUANCE_SIGNER_FIELD_NAMES
)
_DETACHED_NETWORK_BINDING_BOUNDARY_METHODS = _freeze_detached_network_binding_boundary_methods(
    _DETACHED_NETWORK_BINDING_BOUNDARY_CAPABILITY,
    _PreparedNetworkReceiptIssuance,
    _PreparedNetworkReceiptIssuanceClaim,
    LifecyclePreparedNetworkReceipt,
    _PREPARED_NETWORK_RECEIPT_ISSUANCE_SIGNER_DESCRIPTORS,
)


@dataclass(frozen=True, slots=True)
class DeferredSessionPublishedNetworkResult:
    """Committed deferred root plus its exact dispatcher source publication."""

    materialization: LifecyclePreparedNetworkResult
    publication: object


@dataclass(frozen=True, slots=True)
class _DeferredSessionPublicationPrecommit:
    """Exact dispatcher bridge owners revalidated at the canonical commit fence."""

    dispatcher: object
    precommit: object


@dataclass(frozen=True, slots=True)
class _DeferredSessionMaterializationShells:
    """Preallocated receipt/result identities finalized after canonical commit."""

    connection_receipt: LifecycleConnectionCompositeReceipt
    connection_result: LifecycleConnectionCompositeResult
    network_receipt: LifecyclePreparedNetworkReceipt
    network_result: LifecyclePreparedNetworkResult


@dataclass(slots=True)
class _DeferredSessionCanonicalProgress:
    """Authority-private terminal cursor spanning the canonical owner chain."""

    lifecycle_committed: bool = False
    state_committed: bool = False
    application_committed: bool = False
    runtime_committed: bool = False
    timing_committed: bool = False

    @property
    def any_owner_committed(self) -> bool:
        """Return whether precanonical cleanup is permanently forbidden."""

        return (
            self.lifecycle_committed
            or self.state_committed
            or self.application_committed
            or self.runtime_committed
            or self.timing_committed
        )


class _OrderedIntent(Protocol):
    @property
    def order_key(self) -> tuple[datetime, datetime, str, int]: ...


_IntentT = TypeVar("_IntentT", bound=_OrderedIntent)


class _StableIntentHeap(Generic[_IntentT]):
    """Version-tolerant full commit-order heap with bounded rebuilding."""

    _COMPACT_MIN_BACKING = 4_096
    _COMPACT_RATIO = 2

    def __init__(self) -> None:
        self._heap: list[tuple[datetime, datetime, str, int, int]] = []
        self._retired_heap: list[tuple[datetime, datetime, str, int, int]] | None = None
        self._compaction_cursor = 0

    @staticmethod
    def _entry(
        intent: _IntentT,
        handle: int,
    ) -> tuple[datetime, datetime, str, int, int]:
        return (*intent.order_key, handle)

    def push(self, handle: int, intent: _IntentT) -> None:
        heapq.heappush(self._heap, self._entry(intent, handle))

    @staticmethod
    def _valid_head(
        heap: list[tuple[datetime, datetime, str, int, int]],
        store: CompactIndexedStore[Any, _IntentT],
    ) -> tuple[datetime, datetime, str, int, int] | None:
        while heap:
            entry = heap[0]
            try:
                intent = store.get_by_handle(entry[4])
            except KeyError:
                heapq.heappop(heap)
                continue
            if entry[:4] != intent.order_key:
                heapq.heappop(heap)
                continue
            return entry
        return None

    def _head_with_heap(
        self,
        store: CompactIndexedStore[Any, _IntentT],
    ) -> (
        tuple[
            tuple[datetime, datetime, str, int, int],
            list[tuple[datetime, datetime, str, int, int]],
        ]
        | None
    ):
        active = self._valid_head(self._heap, store)
        retired_heap = self._retired_heap
        retired = self._valid_head(retired_heap, store) if retired_heap is not None else None
        if active is None:
            return None if retired is None or retired_heap is None else (retired, retired_heap)
        if retired is None or active <= retired:
            return active, self._heap
        assert retired_heap is not None
        return retired, retired_heap

    def first_due(
        self,
        store: CompactIndexedStore[Any, _IntentT],
        cutoff: datetime,
        *,
        inclusive: bool,
    ) -> tuple[tuple[datetime, datetime, str, int], int] | None:
        """Return the exact first due commit without removing it."""

        head = self._head_with_heap(store)
        if head is None:
            return None
        entry = head[0]
        if entry[0] > cutoff or (entry[0] == cutoff and not inclusive):
            return None
        return entry[:4], entry[4]

    def pop_expected(
        self,
        store: CompactIndexedStore[Any, _IntentT],
        expected: tuple[tuple[datetime, datetime, str, int], int],
    ) -> bool:
        """Pop only the still-current exact head selected by a global merge."""

        head = self._head_with_heap(store)
        if head is None or (head[0][:4], head[0][4]) != expected:
            return False
        heapq.heappop(head[1])
        return True

    def compact(
        self,
        store: CompactIndexedStore[Any, _IntentT],
        *,
        max_slots: int,
    ) -> int:
        """Rebuild at most ``max_slots`` handle positions after O(1) heap rotation."""

        if max_slots < 0:
            raise ValueError("Stable intent heap compaction max_slots must be non-negative")
        if not store:
            self._heap = []
            self._retired_heap = None
            self._compaction_cursor = 0
            return 0
        backing = self.backing_entries
        if self._retired_heap is None and backing > max(
            self._COMPACT_MIN_BACKING,
            len(store) * self._COMPACT_RATIO,
        ):
            self._retired_heap = self._heap
            self._heap = []
            self._compaction_cursor = 0
        if self._retired_heap is None or max_slots == 0:
            return 0
        allocated = store.metrics().allocated_slots
        stop = min(allocated, self._compaction_cursor + max_slots)
        for handle in range(self._compaction_cursor, stop):
            try:
                intent = store.get_by_handle(handle)
            except KeyError:
                continue
            self.push(handle, intent)
        work = stop - self._compaction_cursor
        self._compaction_cursor = stop
        if stop == allocated:
            self._retired_heap = None
            self._compaction_cursor = 0
        return work

    @property
    def backing_entries(self) -> int:
        """Return active plus retired versioned heap records."""

        return len(self._heap) + (0 if self._retired_heap is None else len(self._retired_heap))


@dataclass(frozen=True, slots=True)
class ProcessCloseIntent:
    """Frozen dispatch payload for one exact bounded process close."""

    system: System
    pid: int
    started_at: datetime | None
    process_object_id: str
    username: str
    process_name: str
    logon_id: str
    close_at: datetime
    action_id: str
    transition_ordinal: int = 0
    eligible_at: datetime | None = None

    def __post_init__(self) -> None:
        if self.pid <= 0 or not self.process_object_id or not self.action_id:
            raise ValueError("Process close intents require PID, process object, and action IDs")
        if self.transition_ordinal < 0:
            raise ValueError("Process close intent ordinal must be non-negative")
        if self.started_at is not None:
            object.__setattr__(self, "started_at", ensure_utc(self.started_at))
        close_at = ensure_utc(self.close_at)
        eligible_at = close_at if self.eligible_at is None else ensure_utc(self.eligible_at)
        if eligible_at < close_at:
            raise ValueError("Process close eligibility cannot precede its canonical close time")
        object.__setattr__(self, "close_at", close_at)
        object.__setattr__(self, "eligible_at", eligible_at)

    @property
    def key(self) -> ProcessInstanceKey:
        return (self.system.hostname, self.pid, self.started_at)

    @property
    def order_key(self) -> tuple[datetime, datetime, str, int]:
        assert self.eligible_at is not None
        return (self.eligible_at, self.close_at, self.action_id, self.transition_ordinal)


@dataclass(frozen=True, slots=True)
class DeferredLifecycleCloseIntent:
    """Frozen queue envelope for one action-owned deferred session close."""

    close_id: str
    hostname: str
    session_object_id: str
    close_at: datetime
    action_id: str
    payload: object
    transition_ordinal: int = 0

    def __post_init__(self) -> None:
        if not all((self.close_id, self.hostname, self.session_object_id, self.action_id)):
            raise ValueError("Deferred lifecycle closes require exact close/session/action IDs")
        if self.transition_ordinal < 0:
            raise ValueError("Deferred lifecycle close ordinal must be non-negative")
        object.__setattr__(self, "close_at", ensure_utc(self.close_at))

    @property
    def order_key(self) -> tuple[datetime, datetime, str, int]:
        return (self.close_at, self.close_at, self.action_id, self.transition_ordinal)


@dataclass(frozen=True, slots=True)
class GeneratorLifecycleAuthorityCensus:
    """Constant-time structural census of generator-local deadline queues."""

    process_close_intents: int
    deferred_session_closes: int
    strict_markers: int
    deadline_entries: int
    deadline_backing_entries: int
    allocated_shards: int
    shard_count: int
    maximum_shard_entries: int
    high_water_entries: int
    bootstrapped_sessions: int
    bootstrapped_processes: int
    watermark: datetime | None
    materialization_batch_transactions: int
    materialization_batch_transactions_pending: int
    materialization_batch_transactions_unacknowledged: int
    materialization_batch_transactions_acknowledged: int
    materialization_batch_transaction_capacity: int
    materialization_batch_transaction_high_water: int
    materialization_batch_transaction_retained_bytes: int
    materialization_batch_transaction_retained_bytes_high_water: int
    materialization_batch_transaction_byte_capacity: int


@dataclass(frozen=True, slots=True)
class ForegroundShellOwner:
    """Exact lifecycle identities for one interactive shell resource."""

    hostname: str
    principal: str
    session_object_id: str
    process_object_id: str

    @property
    def resource_key(self) -> tuple[str, str, str, str]:
        """Return the registry's normalized exact foreground key."""

        return (
            self.hostname.strip().casefold(),
            self.principal.strip().casefold(),
            self.session_object_id,
            self.process_object_id,
        )


@dataclass(frozen=True, slots=True)
class _StrictLifecycleMarker:
    key: StrictLifecycleKey
    retain_until: datetime


@dataclass(slots=True, weakref_slot=True)
class _LifecycleMaterializationBatchTransactionRecord:
    """Bounded authority-owned retry and terminal-result record."""

    transaction: LifecycleMaterializationBatchTransaction
    terminal_result: LifecycleMaterializationBatchTerminalResult | None = None
    claimed_thread: Thread | None = None
    planning_attempt: LifecycleMaterializationBatchPlanningAttempt | None = None
    planning_capability: LifecycleMaterializationBatchPlanningCapability | None = None
    planning_capability_consumed: bool = False
    retained_bytes: int = 0
    acknowledged: bool = False
    acknowledged_watermark: datetime | None = None


class _AuthorityShard:
    """Lazily allocated exact stores for one stable host shard."""

    def __init__(self) -> None:
        self.lock = RLock()
        self.process_closes: CompactIndexedStore[ProcessInstanceKey, ProcessCloseIntent] = (
            CompactIndexedStore()
        )
        self.process_close_deadlines = PackedHandleExpiryIndex()
        self.process_close_order: _StableIntentHeap[ProcessCloseIntent] = _StableIntentHeap()
        self.deferred_closes: CompactIndexedStore[str, DeferredLifecycleCloseIntent] = (
            CompactIndexedStore()
        )
        self.deferred_close_deadlines = PackedHandleExpiryIndex()
        self.deferred_close_order: _StableIntentHeap[DeferredLifecycleCloseIntent] = (
            _StableIntentHeap()
        )
        self.strict_markers: CompactIndexedStore[StrictLifecycleKey, _StrictLifecycleMarker] = (
            CompactIndexedStore()
        )
        self.strict_deadlines = PackedHandleExpiryIndex()
        self.high_water_entries = 0

    def record_high_water(self) -> None:
        self.high_water_entries = max(
            self.high_water_entries,
            len(self.process_closes) + len(self.deferred_closes) + len(self.strict_markers),
        )


class GeneratorLifecycleAuthority:
    """Strict lifecycle facade plus compact future-close scheduling."""

    def __init__(
        self,
        state_manager: StateManager,
        lifecycle_shadow: LifecycleShadow,
        *,
        shard_count: int = _DEFAULT_SHARD_COUNT,
        materialization_batch_transaction_capacity: int = (
            _DEFAULT_MATERIALIZATION_BATCH_TRANSACTION_CAPACITY
        ),
        materialization_batch_transaction_byte_capacity: int = (
            _DEFAULT_MATERIALIZATION_BATCH_TRANSACTION_BYTE_CAPACITY
        ),
        prepared_network_receipt_issuance_capacity: int = (
            _DEFAULT_PREPARED_NETWORK_RECEIPT_ISSUANCE_CAPACITY
        ),
    ) -> None:
        if shard_count <= 0:
            raise ValueError("Generator lifecycle shard_count must be positive")
        if (
            type(materialization_batch_transaction_capacity) is not int
            or materialization_batch_transaction_capacity <= 0
        ):
            raise ValueError(
                "Generator lifecycle materialization-batch transaction capacity "
                "must be a positive exact integer"
            )
        if (
            type(materialization_batch_transaction_byte_capacity) is not int
            or materialization_batch_transaction_byte_capacity <= 0
        ):
            raise ValueError(
                "Generator lifecycle materialization-batch byte capacity must be a positive "
                "exact integer"
            )
        if (
            type(prepared_network_receipt_issuance_capacity) is not int
            or prepared_network_receipt_issuance_capacity <= 0
        ):
            raise ValueError(
                "Generator lifecycle prepared-network issuance capacity must be a "
                "positive exact integer"
            )
        self._state_manager = state_manager
        self._shadow = lifecycle_shadow
        self._registry = lifecycle_shadow.registry
        self._shard_count = shard_count
        self._shards: list[_AuthorityShard | None] = [None] * shard_count
        self._shard_allocation_lock = Lock()
        self._bootstrap_lock = Lock()
        self._bootstrap_complete = False
        self._bootstrapped_sessions = 0
        self._bootstrapped_processes = 0
        self._watermark: datetime | None = None
        self._materialization_precommit_hook: Callable[[], None] | None = None
        self._receipt_secret = secrets.token_bytes(32)
        self._materialization_batch_transaction_lock = RLock()
        self._materialization_batch_transaction_condition = Condition(
            self._materialization_batch_transaction_lock
        )
        self._materialization_batch_transactions: dict[
            str, _LifecycleMaterializationBatchTransactionRecord
        ] = {}
        self._materialization_batch_transaction_generation = 0
        self._materialization_batch_transactions_pending = 0
        self._materialization_batch_transactions_unacknowledged = 0
        self._materialization_batch_transactions_acknowledged = 0
        self._materialization_batch_transaction_capacity = (
            materialization_batch_transaction_capacity
        )
        self._materialization_batch_transaction_high_water = 0
        self._materialization_batch_transaction_retained_bytes = 0
        self._materialization_batch_transaction_retained_bytes_high_water = 0
        self._materialization_batch_transaction_byte_capacity = (
            materialization_batch_transaction_byte_capacity
        )
        self._fixture_parent_backfill = False
        self._application_registry: ApplicationChannelRegistry | None = None
        self._http_channel_manager: HttpApplicationChannelManager | None = None
        self._explicit_proxy_manager: ExplicitProxyChannelManager | None = None
        self._smb_channel_manager: SmbApplicationChannelManager | None = None
        self._ssh_channel_manager: SshApplicationChannelManager | None = None
        self._rdp_session_manager: RdpReconnectStateManager | None = None
        self._network_runtime: NetworkTransactionRuntime | None = None
        self._source_timing_planner: SourceTimingPlanner | None = None
        self._prepared_network_receipt_authorities: dict[
            int,
            _PreparedNetworkReceiptAuthority,
        ] = {}
        self._prepared_network_receipt_generation = 0
        self._prepared_network_receipt_issuance_lock = RLock()
        self._prepared_network_receipt_issuances: dict[
            tuple[int, int],
            _PreparedNetworkReceiptIssuance,
        ] = {}
        self._prepared_network_receipt_issuance_generations: dict[int, int] = {}
        self._prepared_network_receipt_issuance_receipts: dict[
            int,
            tuple[int, int],
        ] = {}
        self._prepared_network_receipt_issuance_generation = 0
        self._prepared_network_receipt_issuance_capacity = (
            prepared_network_receipt_issuance_capacity
        )

    @property
    def registry(self) -> LifecycleRegistry:
        """Return the single engine-owned canonical lifecycle registry."""

        return self._registry

    @property
    def state_manager(self) -> StateManager:
        """Return the exact State owner committed by this authority."""

        return self._state_manager

    @property
    def lifecycle_shadow(self) -> LifecycleShadow:
        """Return the exact State/lifecycle projection adapter."""

        return self._shadow

    def reserve_materialization_batch_transaction(
        self,
        *,
        transaction_id: str,
        request_digest: str,
        request_payload: tuple[object, ...] = (),
        anticipated_terminal_payload: tuple[object, ...] | None = None,
    ) -> LifecycleMaterializationBatchTransaction:
        """Reserve or recover one bounded retry-stable batch transaction."""

        if type(transaction_id) is not str or not transaction_id.strip():
            raise StateError("Materialization-batch transaction ID must be a non-empty string")
        if len(transaction_id) > 256:
            raise StateError("Materialization-batch transaction ID is too long")
        if type(request_digest) is not str or not request_digest.strip():
            raise StateError("Materialization-batch request digest must be a non-empty string")
        if len(request_digest) > 256:
            raise StateError("Materialization-batch request digest is too long")
        if type(request_payload) is not tuple:
            raise StateError("Materialization-batch request payload must be an exact tuple")
        if (
            anticipated_terminal_payload is not None
            and type(anticipated_terminal_payload) is not tuple
        ):
            raise StateError(
                "Materialization-batch anticipated terminal payload must be an exact tuple"
            )
        _nodes, request_bytes = _validate_materialization_batch_external_result(request_payload)
        reserved_bytes = 256 + len(transaction_id.encode()) + len(request_digest.encode())
        reserved_bytes += request_bytes
        if anticipated_terminal_payload is not None:
            _validate_materialization_batch_external_result(anticipated_terminal_payload)
            anticipated_terminal_retained_bytes = 512 + len(
                _canonical_materialization_batch_payload_bytes(anticipated_terminal_payload)
            )
            if anticipated_terminal_retained_bytes > _MAX_MATERIALIZATION_BATCH_TRANSACTION_BYTES:
                raise StateError("Materialization-batch terminal exceeds its retained-byte limit")
            reserved_bytes = max(reserved_bytes, anticipated_terminal_retained_bytes)
        if reserved_bytes > _MAX_MATERIALIZATION_BATCH_TRANSACTION_BYTES:
            raise StateError("Materialization-batch request exceeds its retained-byte limit")
        with self._materialization_batch_transaction_lock:
            existing = self._materialization_batch_transactions.get(transaction_id)
            if existing is not None:
                if existing.transaction.request_digest != request_digest:
                    raise StateError(
                        "Materialization-batch transaction ID is already bound to another request"
                    )
                self._reserve_materialization_batch_transaction_bytes_locked(
                    existing,
                    reserved_bytes,
                )
                return existing.transaction
            if (
                len(self._materialization_batch_transactions)
                >= self._materialization_batch_transaction_capacity
            ):
                raise StateError(
                    "Materialization-batch transaction capacity is exhausted by retained records"
                )
            if (
                self._materialization_batch_transaction_retained_bytes + reserved_bytes
                > self._materialization_batch_transaction_byte_capacity
            ):
                raise StateError("Materialization-batch transaction byte capacity is exhausted")
            self._materialization_batch_transaction_generation += 1
            transaction = LifecycleMaterializationBatchTransaction._issue(
                authority_secret=self._receipt_secret,
                transaction_id=transaction_id,
                request_digest=request_digest,
                generation=self._materialization_batch_transaction_generation,
            )
            self._materialization_batch_transactions[transaction_id] = (
                _LifecycleMaterializationBatchTransactionRecord(
                    transaction=transaction,
                    retained_bytes=reserved_bytes,
                )
            )
            self._materialization_batch_transaction_retained_bytes += reserved_bytes
            self._materialization_batch_transaction_retained_bytes_high_water = max(
                self._materialization_batch_transaction_retained_bytes_high_water,
                self._materialization_batch_transaction_retained_bytes,
            )
            self._materialization_batch_transactions_pending += 1
            self._materialization_batch_transaction_high_water = max(
                self._materialization_batch_transaction_high_water,
                len(self._materialization_batch_transactions),
            )
            return transaction

    def _reserve_materialization_batch_transaction_bytes_locked(
        self,
        record: _LifecycleMaterializationBatchTransactionRecord,
        retained_bytes: int,
    ) -> None:
        """Reserve an exact larger byte charge before any canonical mutation."""

        if retained_bytes <= record.retained_bytes:
            return
        additional = retained_bytes - record.retained_bytes
        if (
            self._materialization_batch_transaction_retained_bytes + additional
            > self._materialization_batch_transaction_byte_capacity
        ):
            raise StateError("Materialization-batch transaction byte capacity is exhausted")
        record.retained_bytes = retained_bytes
        self._materialization_batch_transaction_retained_bytes += additional
        self._materialization_batch_transaction_retained_bytes_high_water = max(
            self._materialization_batch_transaction_retained_bytes_high_water,
            self._materialization_batch_transaction_retained_bytes,
        )

    @staticmethod
    def _materialization_batch_terminal_retained_bytes(
        transaction: LifecycleMaterializationBatchTransaction,
        plan: MaterializationBatchPlan,
        external_result: tuple[object, ...],
    ) -> int:
        """Measure the exact immutable terminal projection before State publication."""

        if type(plan) is not MaterializationBatchPlan:
            raise StateError("Materialization-batch plan must have its exact public type")
        member_count = len(plan.processes) + len(plan.boot_times) + int(plan.session is not None)
        if member_count > _MAX_MATERIALIZATION_BATCH_PAYLOAD_NODES:
            raise StateError("Materialization-batch terminal has too many retained members")
        projection: tuple[object, ...] = (
            "materialization-batch-terminal-size-v1",
            transaction.transaction_id,
            transaction.request_digest,
            transaction._generation,
            plan.publication_token,
            _session_identity_payload(plan.session.identity if plan.session is not None else None),
            tuple(_process_identity_payload(member.identity) for member in plan.processes),
            plan.boot_times,
            external_result,
            plan.final_state_time,
        )
        retained_bytes = 512 + len(_canonical_materialization_batch_payload_bytes(projection))
        if retained_bytes > _MAX_MATERIALIZATION_BATCH_TRANSACTION_BYTES:
            raise StateError("Materialization-batch terminal exceeds its retained-byte limit")
        return retained_bytes

    def _validate_materialization_batch_transaction(
        self,
        transaction: LifecycleMaterializationBatchTransaction,
    ) -> None:
        """Authenticate transaction structure before acquiring transaction locks."""

        if type(
            transaction
        ) is not LifecycleMaterializationBatchTransaction or not transaction._has_valid_integrity(
            self._receipt_secret
        ):
            raise StateError("Materialization-batch transaction failed authority authentication")

    def _materialization_batch_transaction_record_for_locked(
        self,
        transaction: LifecycleMaterializationBatchTransaction,
    ) -> _LifecycleMaterializationBatchTransactionRecord:
        """Resolve retained identity using only prevalidated inert fields."""

        record = self._materialization_batch_transactions.get(transaction.transaction_id)
        if record is None or record.transaction is not transaction:
            raise StateError("Materialization-batch transaction is not retained by this authority")
        return record

    def _validate_materialization_batch_planning_capability(
        self,
        transaction: LifecycleMaterializationBatchTransaction,
        capability: LifecycleMaterializationBatchPlanningCapability,
    ) -> None:
        """Authenticate one planning capability outside transaction locks."""

        if (
            type(capability) is not LifecycleMaterializationBatchPlanningCapability
            or not capability._has_valid_integrity(self._receipt_secret)
            or capability._transaction_id != transaction.transaction_id
            or capability._request_digest != transaction.request_digest
            or capability._transaction_generation != transaction._generation
        ):
            raise StateError("Materialization-batch planning capability failed authentication")

    def _validate_materialization_batch_planning_attempt(
        self,
        transaction: LifecycleMaterializationBatchTransaction,
        attempt: LifecycleMaterializationBatchPlanningAttempt,
    ) -> None:
        """Authenticate one caller-held planning attempt outside transaction locks."""

        if (
            type(attempt) is not LifecycleMaterializationBatchPlanningAttempt
            or not attempt._has_valid_integrity(self._receipt_secret)
            or attempt._transaction_id != transaction.transaction_id
            or attempt._request_digest != transaction.request_digest
            or attempt._transaction_generation != transaction._generation
        ):
            raise StateError("Materialization-batch planning attempt failed authentication")

    def authenticates_materialization_batch_terminal_result(
        self,
        transaction: LifecycleMaterializationBatchTransaction,
        result: object,
    ) -> bool:
        """Verify the exact retained result and reject copied/replayed objects."""

        if not self._materialization_batch_terminal_result_has_valid_integrity(
            transaction,
            result,
        ):
            return False
        with self._materialization_batch_transaction_lock:
            record = self._materialization_batch_transactions.get(transaction.transaction_id)
            return (
                record is not None
                and record.transaction is transaction
                and record.terminal_result is result
            )

    def _materialization_batch_terminal_result_has_valid_integrity(
        self,
        transaction: LifecycleMaterializationBatchTransaction,
        result: object,
    ) -> bool:
        """Verify terminal cryptography and generation without retained identity."""

        return (
            type(transaction) is LifecycleMaterializationBatchTransaction
            and transaction._has_valid_integrity(self._receipt_secret)
            and type(result) is LifecycleMaterializationBatchTerminalResult
            and result._has_valid_integrity(self._receipt_secret)
            and result.transaction_id == transaction.transaction_id
            and result.request_digest == transaction.request_digest
            and result._transaction_generation == transaction._generation
            and result.receipt._has_valid_integrity(self._receipt_secret)
            and result.receipt._publication_token == result._plan_publication_token
        )

    def validates_archived_materialization_batch_terminal_result(
        self,
        transaction: LifecycleMaterializationBatchTransaction,
        result: LifecycleMaterializationBatchTerminalResult,
    ) -> bool:
        """Verify an engine-retained terminal after acknowledged watermark pruning."""

        return self._materialization_batch_terminal_result_has_valid_integrity(
            transaction,
            result,
        )

    def _runtime_for_materialization_batch_terminal_result(
        self,
        transaction: LifecycleMaterializationBatchTransaction,
        result: LifecycleMaterializationBatchTerminalResult,
    ) -> tuple[ActiveSession | None, tuple[RunningProcess, ...]]:
        """Resolve exact live State/registry objects for one authentic terminal result."""

        if not self._materialization_batch_terminal_result_has_valid_integrity(
            transaction,
            result,
        ):
            raise StateError("Materialization-batch terminal result failed authentication")
        if self._state_manager.materialization_version < result.receipt.committed_version:
            raise StateError("Materialization-batch terminal result is ahead of canonical State")
        for hostname, boot_time in result.boot_times:
            if self._state_manager.get_boot_time(hostname) != boot_time:
                raise StateError(
                    "Materialization-batch terminal boot metadata no longer matches State"
                )
        session: ActiveSession | None = None
        if result.session is not None:
            identity = result.session
            session = self._state_manager.get_session(identity.logon_id)
            if (
                session is None
                or self._state_manager.get_session_identity(identity.logon_id) != identity
            ):
                raise StateError("Materialization-batch terminal session is absent from State")
            session_snapshot = self._registry.get_session(identity.object_id)
            if (
                session_snapshot is None
                or session_snapshot.closed_at is not None
                or session_snapshot.identity.object_id != identity.object_id
                or session_snapshot.identity.hostname != identity.hostname
                or session_snapshot.identity.logon_id != identity.logon_id
            ):
                raise StateError(
                    "Materialization-batch terminal session is absent from lifecycle registry"
                )
        processes: list[RunningProcess] = []
        for identity in result.processes:
            process = self._state_manager.get_process(identity.hostname, identity.pid)
            if (
                process is None
                or self._state_manager.get_process_identity(
                    identity.hostname,
                    identity.pid,
                )
                != identity
            ):
                raise StateError("Materialization-batch terminal process is absent from State")
            process_snapshot = self._registry.get_process(identity.object_id)
            if (
                process_snapshot is None
                or process_snapshot.closed_at is not None
                or process_snapshot.identity.object_id != identity.object_id
                or process_snapshot.identity.hostname != identity.hostname
                or process_snapshot.identity.pid != identity.pid
                or process_snapshot.identity.started_at != identity.started_at
            ):
                raise StateError(
                    "Materialization-batch terminal process is absent from lifecycle registry"
                )
            processes.append(process)
        return session, tuple(processes)

    def reconcile_materialization_batch_transaction(
        self,
        transaction: LifecycleMaterializationBatchTransaction,
    ) -> LifecycleMaterializationBatchTerminalResult | None:
        """Return and verify a committed result, or ``None`` while still pending."""

        self._validate_materialization_batch_transaction(transaction)
        with self._materialization_batch_transaction_lock:
            record = self._materialization_batch_transaction_record_for_locked(transaction)
            result = record.terminal_result
            if result is None:
                return None
        self._runtime_for_materialization_batch_terminal_result(transaction, result)
        with self._materialization_batch_transaction_lock:
            record = self._materialization_batch_transaction_record_for_locked(transaction)
            if record.terminal_result is not result:
                raise StateError("Materialization-batch terminal changed during reconciliation")
        return result

    def acknowledge_materialization_batch_transaction(
        self,
        transaction: LifecycleMaterializationBatchTransaction,
        result: LifecycleMaterializationBatchTerminalResult,
    ) -> None:
        """Acknowledge exact result delivery without weakening watermark retention."""

        if not self.acknowledge_materialization_batch_transaction_if_retained(
            transaction,
            result,
        ):
            raise StateError("Materialization-batch transaction is not retained by this authority")

    def acknowledge_materialization_batch_transaction_if_retained(
        self,
        transaction: LifecycleMaterializationBatchTransaction,
        result: LifecycleMaterializationBatchTerminalResult,
    ) -> bool:
        """Atomically acknowledge one retained terminal or return false after exact pruning."""

        if not self._materialization_batch_terminal_result_has_valid_integrity(
            transaction,
            result,
        ):
            raise StateError("Materialization-batch acknowledgement result is not canonical")
        with self._materialization_batch_transaction_lock:
            record = self._materialization_batch_transactions.get(transaction.transaction_id)
            if record is None:
                return False
            if record.transaction is not transaction:
                raise StateError(
                    "Materialization-batch transaction is not retained by this authority"
                )
            if record.terminal_result is None:
                raise StateError("Pending materialization-batch transaction cannot be acknowledged")
            if result is not record.terminal_result:
                raise StateError("Materialization-batch acknowledgement result is not canonical")
            if record.acknowledged:
                return True
            record.acknowledged = True
            record.acknowledged_watermark = self._watermark
            record.planning_attempt = None
            record.planning_capability = None
            record.planning_capability_consumed = False
            self._materialization_batch_transactions_unacknowledged -= 1
            self._materialization_batch_transactions_acknowledged += 1
            return True

    def cancel_materialization_batch_transaction(
        self,
        transaction: LifecycleMaterializationBatchTransaction,
    ) -> None:
        """Release one still-pending reservation; terminal records require acknowledgement."""

        self._validate_materialization_batch_transaction(transaction)
        with self._materialization_batch_transaction_lock:
            record = self._materialization_batch_transaction_record_for_locked(transaction)
            if record.terminal_result is not None:
                raise StateError("Terminal materialization-batch transaction cannot be cancelled")
            if record.claimed_thread is not None:
                raise StateError("Claimed materialization-batch transaction cannot be cancelled")
            self._materialization_batch_transactions.pop(transaction.transaction_id)
            self._materialization_batch_transaction_retained_bytes -= record.retained_bytes
            self._materialization_batch_transactions_pending -= 1

    def _prune_acknowledged_materialization_batch_transactions(self, cutoff: datetime) -> None:
        """Prune only acknowledged terminals at or behind the shared watermark."""

        with self._materialization_batch_transaction_lock:
            prunable: list[str] = []
            for transaction_id, record in self._materialization_batch_transactions.items():
                if not record.acknowledged or record.terminal_result is None:
                    continue
                if record.acknowledged_watermark is None:
                    record.acknowledged_watermark = cutoff
                    continue
                if record.acknowledged_watermark < cutoff:
                    prunable.append(transaction_id)
            for transaction_id in prunable:
                record = self._materialization_batch_transactions.pop(transaction_id)
                self._materialization_batch_transaction_retained_bytes -= record.retained_bytes
                self._materialization_batch_transactions_acknowledged -= 1

    def _claim_materialization_batch_transaction(
        self,
        transaction: LifecycleMaterializationBatchTransaction,
        planning_capability: LifecycleMaterializationBatchPlanningCapability | None,
    ) -> tuple[
        _LifecycleMaterializationBatchTransactionRecord,
        LifecycleMaterializationBatchTerminalResult | None,
    ]:
        """Claim one pending transaction or wait for its authentic terminal result."""

        self._validate_materialization_batch_transaction(transaction)
        if planning_capability is not None:
            self._validate_materialization_batch_planning_capability(
                transaction,
                planning_capability,
            )
        with self._materialization_batch_transaction_condition:
            record = self._materialization_batch_transaction_record_for_locked(transaction)
            if planning_capability is not None and (
                record.planning_capability is not planning_capability
                or record.claimed_thread is not current_thread()
            ):
                raise StateError("Materialization-batch planning capability is not owned here")
            while record.claimed_thread is not None and record.terminal_result is None:
                if record.claimed_thread is current_thread():
                    if (
                        planning_capability is not None
                        and record.planning_capability is planning_capability
                        and not record.planning_capability_consumed
                    ):
                        record.planning_capability_consumed = True
                        return record, None
                    raise StateError("Materialization-batch transaction is reentrantly claimed")
                self._materialization_batch_transaction_condition.wait()
                record = self._materialization_batch_transaction_record_for_locked(transaction)
            if record.terminal_result is not None:
                return record, record.terminal_result
            if planning_capability is not None:
                raise StateError("Materialization-batch planning capability is no longer active")
            record.claimed_thread = current_thread()
            return record, None

    def prepare_materialization_batch_transaction_planning_attempt(
        self,
        transaction: LifecycleMaterializationBatchTransaction,
    ) -> LifecycleMaterializationBatchPlanningAttempt:
        """Issue one inert attempt identity before entering the retained planning claim."""

        self._validate_materialization_batch_transaction(transaction)
        with self._materialization_batch_transaction_lock:
            self._materialization_batch_transaction_record_for_locked(transaction)
        return LifecycleMaterializationBatchPlanningAttempt._issue(
            authority_secret=self._receipt_secret,
            transaction=transaction,
        )

    def claim_materialization_batch_transaction_for_planning(
        self,
        transaction: LifecycleMaterializationBatchTransaction,
        *,
        attempt: LifecycleMaterializationBatchPlanningAttempt,
    ) -> (
        LifecycleMaterializationBatchPlanningCapability
        | LifecycleMaterializationBatchTerminalResult
    ):
        """Serialize exact retry-stable planning before any State capability is minted."""

        self._validate_materialization_batch_transaction(transaction)
        self._validate_materialization_batch_planning_attempt(transaction, attempt)
        capability = LifecycleMaterializationBatchPlanningCapability._issue(
            authority_secret=self._receipt_secret,
            transaction=transaction,
        )
        with self._materialization_batch_transaction_condition:
            record = self._materialization_batch_transaction_record_for_locked(transaction)
            while record.claimed_thread is not None and record.terminal_result is None:
                if record.claimed_thread is current_thread():
                    raise StateError("Materialization-batch planning is reentrantly claimed")
                self._materialization_batch_transaction_condition.wait()
                record = self._materialization_batch_transaction_record_for_locked(transaction)
            if record.terminal_result is not None:
                return record.terminal_result
            record.claimed_thread = current_thread()
            record.planning_attempt = attempt
            record.planning_capability = capability
            record.planning_capability_consumed = False
            return capability

    def reconcile_materialization_batch_transaction_planning_claim(
        self,
        transaction: LifecycleMaterializationBatchTransaction,
        *,
        attempt: LifecycleMaterializationBatchPlanningAttempt,
    ) -> LifecycleMaterializationBatchPlanningCapability | None:
        """Recover only this exact attempt's capability after a lost claim return."""

        self._validate_materialization_batch_transaction(transaction)
        self._validate_materialization_batch_planning_attempt(transaction, attempt)
        with self._materialization_batch_transaction_lock:
            record = self._materialization_batch_transaction_record_for_locked(transaction)
            if record.terminal_result is not None:
                return None
            if record.claimed_thread is None:
                return None
            if record.claimed_thread is not current_thread():
                raise StateError("Materialization-batch planning claim is owned by another Thread")
            if record.planning_attempt is not attempt:
                return None
            capability = record.planning_capability
            if capability is None or record.planning_capability_consumed:
                raise StateError("Materialization-batch transaction is past its planning claim")
            return capability

    def release_materialization_batch_transaction_planning_claim(
        self,
        transaction: LifecycleMaterializationBatchTransaction,
        capability: LifecycleMaterializationBatchPlanningCapability,
    ) -> None:
        """Release an exact planning claim after a neutral pre-materialization failure."""

        self._validate_materialization_batch_transaction(transaction)
        self._validate_materialization_batch_planning_capability(transaction, capability)
        with self._materialization_batch_transaction_condition:
            record = self._materialization_batch_transaction_record_for_locked(transaction)
            if record.terminal_result is not None:
                if record.planning_capability is not capability:
                    raise StateError("Materialization-batch planning claim is not owned here")
                record.planning_attempt = None
                record.planning_capability = None
                record.planning_capability_consumed = False
                return
            if (
                record.claimed_thread is None
                and record.planning_capability is capability
                and record.planning_capability_consumed
            ):
                record.planning_attempt = None
                record.planning_capability = None
                record.planning_capability_consumed = False
                return
            if (
                record.claimed_thread is not current_thread()
                or record.planning_capability is not capability
                or record.planning_capability_consumed
            ):
                raise StateError("Materialization-batch planning claim is not owned here")
            record.claimed_thread = None
            record.planning_attempt = None
            record.planning_capability = None
            record.planning_capability_consumed = False
            self._materialization_batch_transaction_condition.notify_all()

    def _release_materialization_batch_transaction_claim(
        self,
        record: _LifecycleMaterializationBatchTransactionRecord,
    ) -> None:
        """Release one nonterminal claim after a fully neutral failure."""

        with self._materialization_batch_transaction_condition:
            if record.terminal_result is None and record.claimed_thread is current_thread():
                record.claimed_thread = None
                self._materialization_batch_transaction_condition.notify_all()

    def _terminalize_materialization_batch_transaction_no_fail(
        self,
        record: _LifecycleMaterializationBatchTransactionRecord,
        result: LifecycleMaterializationBatchTerminalResult,
    ) -> None:
        """Publish one preauthenticated terminal under the retained State claim."""

        with self._materialization_batch_transaction_condition:
            if record.claimed_thread is not current_thread() or record.terminal_result is not None:
                raise StateError("Materialization-batch transaction lost terminal ownership")
            self._publish_materialization_batch_terminal_result_locked(record, result)

    def _publish_materialization_batch_terminal_result_locked(
        self,
        record: _LifecycleMaterializationBatchTransactionRecord,
        result: LifecycleMaterializationBatchTerminalResult,
    ) -> None:
        """Install one precomputed exact terminal using assignment-only writes."""

        record.terminal_result = result
        record.claimed_thread = None
        self._materialization_batch_transactions_pending -= 1
        self._materialization_batch_transactions_unacknowledged += 1
        self._materialization_batch_transaction_condition.notify_all()

    def _recover_materialization_batch_terminal_install_no_fail(
        self,
        record: _LifecycleMaterializationBatchTransactionRecord,
        result: LifecycleMaterializationBatchTerminalResult,
    ) -> None:
        """Converge a failed public terminal-install boundary on its exact result."""

        with self._materialization_batch_transaction_condition:
            if record.terminal_result is result:
                return
            if record.terminal_result is not None or record.claimed_thread is not current_thread():
                raise StateError("Materialization-batch terminal install changed during failure")
            self._publish_materialization_batch_terminal_result_locked(record, result)

    def validate_archived_materialization_batch_terminal_state(
        self,
        transaction: LifecycleMaterializationBatchTransaction,
        result: LifecycleMaterializationBatchTerminalResult,
    ) -> None:
        """Validate an engine-pinned terminal against exact State/lifecycle truth."""

        self._runtime_for_materialization_batch_terminal_result(transaction, result)

    def bind_application_channel_registry(
        self,
        registry: ApplicationChannelRegistry,
    ) -> None:
        """Bind the one engine-owned common application registry."""

        current = self._application_registry
        if current is not None and current is not registry:
            raise StateError("Lifecycle authority is already bound to another app registry")
        self._application_registry = registry

    def bind_http_channel_manager(self, manager: HttpApplicationChannelManager) -> None:
        """Bind the one engine-owned HTTP sidecar verifier."""

        self.bind_application_channel_registry(manager.application_registry)
        current = self._http_channel_manager
        if current is not None and current is not manager:
            raise StateError("Lifecycle authority is already bound to another HTTP manager")
        self._http_channel_manager = manager

    def bind_explicit_proxy_manager(self, manager: ExplicitProxyChannelManager) -> None:
        """Bind the one engine-owned explicit-proxy sidecar verifier."""

        self.bind_application_channel_registry(manager.application_registry)
        current = self._explicit_proxy_manager
        if current is not None and current is not manager:
            raise StateError("Lifecycle authority is already bound to another proxy manager")
        self._explicit_proxy_manager = manager

    def bind_smb_channel_manager(self, manager: SmbApplicationChannelManager) -> None:
        """Bind the one engine-owned SMB terminal-batch verifier."""

        if type(manager) is not SmbApplicationChannelManager:
            raise TypeError("Lifecycle authority requires a typed SMB channel manager")
        self.bind_application_channel_registry(manager.application_registry)
        current = self._smb_channel_manager
        if current is not None and current is not manager:
            raise StateError("Lifecycle authority is already bound to another SMB manager")
        self._smb_channel_manager = manager

    def bind_ssh_channel_manager(self, manager: SshApplicationChannelManager) -> None:
        """Bind the one engine-owned SSH sidecar verifier."""

        if type(manager) is not SshApplicationChannelManager:
            raise TypeError("Lifecycle authority requires a typed SSH channel manager")
        self.bind_application_channel_registry(manager.application_registry)
        current = self._ssh_channel_manager
        if current is not None and current is not manager:
            raise StateError("Lifecycle authority is already bound to another SSH manager")
        self._ssh_channel_manager = manager

    def bind_rdp_session_manager(self, manager: RdpReconnectStateManager) -> None:
        """Bind the one engine-owned RDP logical-session verifier."""

        if type(manager) is not RdpReconnectStateManager:
            raise TypeError("Lifecycle authority requires a typed RDP session manager")
        self.bind_application_channel_registry(manager.application_registry)
        current = self._rdp_session_manager
        if current is not None and current is not manager:
            raise StateError("Lifecycle authority is already bound to another RDP manager")
        self._rdp_session_manager = manager

    def bind_network_transaction_runtime(self, runtime: NetworkTransactionRuntime) -> None:
        """Bind the one runtime sharing this authority's StateManager."""

        if type(runtime) is not NetworkTransactionRuntime:
            raise TypeError("Lifecycle authority requires a typed network runtime")
        if runtime.state_manager is not self._state_manager:
            raise StateError("Lifecycle authority and network runtime must share StateManager")
        current = self._network_runtime
        if current is not None and current is not runtime:
            raise StateError("Lifecycle authority is already bound to another network runtime")
        self._network_runtime = runtime

    def bind_source_timing_planner(self, planner: SourceTimingPlanner) -> None:
        """Bind the one source-timing planner committed by prepared network roots."""

        if type(planner) is not SourceTimingPlanner:
            raise TypeError("Lifecycle authority requires a typed source timing planner")
        current = self._source_timing_planner
        if current is not None and current is not planner:
            raise StateError("Lifecycle authority is already bound to another timing planner")
        self._source_timing_planner = planner

    def authenticates_materialization_receipt(
        self,
        plan: SessionMaterializationPlan | ProcessMaterializationPlan | MaterializationBatchPlan,
        receipt: object,
    ) -> bool:
        """Verify an exact receipt issued by this authority after a committed start."""

        if not self._state_manager.authenticates_materialization_plan(plan):
            return False
        if (
            type(plan) is ProcessMaterializationPlan
            and type(receipt) is LifecyclePreparedNetworkReceipt
        ):
            if not self._authenticates_issued_prepared_network_receipt(receipt):
                return False
            connection_receipt = receipt.connection_receipt
            return (
                connection_receipt.materializes_connection
                and plan.expected_version == receipt.prior_version
                and receipt.committed_version == plan.expected_version + 1
                and plan.publication_token in connection_receipt.start_plan_tokens
            )
        if isinstance(receipt, LifecycleMaterializationReceipt):
            return (
                not isinstance(plan, MaterializationBatchPlan)
                and receipt._has_valid_integrity(self._receipt_secret)
                and receipt.object_id == plan.identity.object_id
                and receipt._publication_token == plan.publication_token
                and receipt.prior_version == plan.expected_version
                and receipt.committed_version == plan.expected_version + 1
            )
        if not isinstance(receipt, LifecycleMaterializationBatchReceipt):
            return False
        if not receipt._has_valid_integrity(self._receipt_secret):
            return False
        if receipt.prior_version != plan.expected_version:
            return False
        if receipt.committed_version != plan.expected_version + 1:
            return False
        if isinstance(plan, MaterializationBatchPlan):
            member_tokens = tuple(
                member.publication_token
                for member in (
                    *((plan.session,) if plan.session is not None else ()),
                    *plan.processes,
                )
            )
            return (
                receipt._publication_token == plan.publication_token
                and receipt._member_tokens == member_tokens
            )
        return plan.publication_token in receipt._member_tokens

    @staticmethod
    def _connection_batch_member_tokens(
        plan: ConnectionCompositeMaterializationPlan,
    ) -> tuple[str, ...]:
        """Return the exact State member order bound into lifecycle publication."""

        batch = plan.batch
        batch_tokens = (
            ()
            if batch is None
            else tuple(
                member.publication_token
                for member in (
                    *((batch.session,) if batch.session is not None else ()),
                    *batch.processes,
                )
            )
        )
        if (
            plan.existing_session_patch is not None
            and plan.existing_session_patch.lifecycle_disposition
            is ConnectionExistingSessionLifecycleDisposition.START
        ):
            return (plan.publication_token, *batch_tokens)
        return batch_tokens

    @staticmethod
    def _action_cohort_id(
        plan: ActionCohortMaterializationPlan,
        category: str,
        source_ordinal: int,
        object_id: str,
        role: str,
    ) -> str:
        """Derive one stable lifecycle member ID from authenticated State semantics."""

        return stable_uuid(
            "lifecycle-authority-action-cohort",
            plan.semantic_id,
            category,
            source_ordinal,
            object_id,
            role,
        )

    def _action_cohort_registered_session(
        self,
        identity: SessionIdentity,
    ) -> SessionIdentity:
        """Require one exact State session identity in this authority's registry."""

        snapshot = self._registry.get_session(identity.object_id)
        expected = self._shadow.project_session_start(identity)
        if snapshot is None or snapshot.identity != expected:
            raise StateError(
                "Action cohort session owner is not registered with exact lifecycle identity: "
                f"{identity.object_id}"
            )
        return identity

    def _action_cohort_live_session_for_process(
        self,
        identity: ProcessIdentity,
    ) -> SessionIdentity | None:
        """Resolve a process start's exact retained live session without backfill."""

        if not identity.logon_id:
            return None
        session = self._state_manager.get_session_identity(identity.logon_id)
        if session is None:
            return None
        if session.hostname != identity.hostname:
            raise StateError(
                f"Action cohort process {identity.object_id} uses a cross-host session"
            )
        snapshot = self._registry.session_for_logon_at(
            identity.hostname,
            identity.logon_id,
            identity.started_at,
        )
        expected = self._shadow.project_session_start(session)
        if snapshot is None or snapshot.identity != expected:
            raise StateError(
                "Action cohort process session is not registered with exact lifecycle identity: "
                f"{session.object_id}"
            )
        return session

    def _action_cohort_registered_process(
        self,
        identity: ProcessIdentity,
    ) -> ProcessIdentity:
        """Require one exact State process identity in this authority's registry."""

        snapshot = self._registry.get_process(identity.object_id)
        if snapshot is None:
            raise StateError(
                "Action cohort process owner is not registered in lifecycle authority: "
                f"{identity.object_id}"
            )
        parent_object_id = ""
        if identity.parent_pid != 0:
            parent = self._registry.process_for_pid_at(
                identity.hostname,
                identity.parent_pid,
                identity.started_at,
            )
            if parent is None and (identity.parent_pid != 4 or snapshot.identity.parent_object_id):
                raise StateError(
                    "Action cohort registered process has no exact lifecycle parent: "
                    f"{identity.object_id}"
                )
            # Narrow compatibility fixtures may model Windows PID 4 as a virtual
            # kernel parent with no lifecycle row. Production boot fleets materialize
            # it, in which case the exact at-start parent must agree below.
            if parent is not None:
                parent_object_id = parent.identity.object_id
        expected, _token, _membership = self._shadow.project_process_start(
            identity,
            integrity_level=snapshot.token.integrity_level,
            session=None,
            token_session_id=snapshot.token.session_id,
            session_logon_type=snapshot.token.logon_type,
            parent_object_id=parent_object_id,
        )
        if snapshot.identity != expected:
            raise StateError(
                "Action cohort process owner disagrees with exact State identity: "
                f"{identity.object_id}"
            )
        return identity

    def _action_cohort_live_parent(
        self,
        identity: ProcessIdentity,
    ) -> ProcessIdentity:
        """Resolve an exact State-backed lifecycle parent at the child's start."""

        if identity.parent_pid in {0, 4}:
            raise StateError(
                f"Action cohort process {identity.object_id} has no modeled lifecycle parent"
            )
        snapshot = self._registry.process_for_pid_at(
            identity.hostname,
            identity.parent_pid,
            identity.started_at,
        )
        if snapshot is None:
            raise StateError(
                "Action cohort process parent is not registered and live at child start: "
                f"{identity.hostname} PID={identity.parent_pid}"
            )
        parent = self._state_manager.get_process_identity_by_object_id(snapshot.identity.object_id)
        if (
            parent is None
            or parent.hostname != identity.hostname
            or parent.pid != identity.parent_pid
        ):
            raise StateError(
                "Action cohort lifecycle parent is not owned by the same StateManager: "
                f"{snapshot.identity.object_id}"
            )
        return self._action_cohort_registered_process(parent)

    def _action_cohort_request_from_authenticated_plan(
        self,
        plan: ActionCohortMaterializationPlan,
    ) -> LifecycleActionCohortRequest:
        """Project one HMAC-authenticated State plan without publishing either owner."""

        entries: list[tuple[datetime, int, int, LifecycleActionCohortOperation]] = []
        source_sequence = 0

        def append(
            canonical_time: datetime,
            tie_class: int,
            operation: LifecycleActionCohortOperation,
        ) -> None:
            nonlocal source_sequence
            entries.append((ensure_utc(canonical_time), tie_class, source_sequence, operation))
            source_sequence += 1

        staged_sessions: dict[tuple[str, str], SessionMaterializationPlan] = {}
        for ordinal, session_plan in enumerate(plan.sessions):
            identity = session_plan.identity
            staged_sessions[(identity.hostname, identity.logon_id)] = session_plan
            projected = self._shadow.project_session_start(identity)
            category = "session-start"
            append(
                identity.started_at,
                0,
                LifecycleSessionStartRequest(
                    identity=projected,
                    action_id=self._action_cohort_id(
                        plan,
                        category,
                        ordinal,
                        identity.object_id,
                        "action",
                    ),
                    transition_id=self._action_cohort_id(
                        plan,
                        category,
                        ordinal,
                        identity.object_id,
                        "transition",
                    ),
                ),
            )

        staged_processes: dict[tuple[str, int], ProcessMaterializationPlan] = {}
        for ordinal, process_plan in enumerate(plan.processes):
            identity = process_plan.identity
            parent_object_id = ""
            if identity.parent_pid not in {0, 4}:
                parent_plan = staged_processes.get((identity.hostname, identity.parent_pid))
                parent = (
                    parent_plan.identity
                    if parent_plan is not None
                    else self._action_cohort_live_parent(identity)
                )
                parent_object_id = parent.object_id

            staged_session = staged_sessions.get((identity.hostname, identity.logon_id))
            session = (
                staged_session.identity
                if staged_session is not None
                else self._action_cohort_live_session_for_process(identity)
            )
            session_logon_type = (
                staged_session.logon_type
                if staged_session is not None
                else process_plan.auth_logon_type
            )
            lifecycle_identity, token, membership = self._shadow.project_process_start(
                identity,
                integrity_level=process_plan.integrity_level,
                session=session,
                token_session_id=process_plan.auth_session_id,
                session_logon_type=session_logon_type,
                parent_object_id=parent_object_id,
            )
            category = "process-start"
            append(
                identity.started_at,
                1,
                LifecycleProcessStartRequest(
                    identity=lifecycle_identity,
                    token=token,
                    membership=membership,
                    action_id=self._action_cohort_id(
                        plan,
                        category,
                        ordinal,
                        identity.object_id,
                        "action",
                    ),
                    transition_id=self._action_cohort_id(
                        plan,
                        category,
                        ordinal,
                        identity.object_id,
                        "transition",
                    ),
                ),
            )
            parent_activity_time = process_plan._payload.parent_activity_time
            if parent_activity_time is not None:
                if not parent_object_id:
                    raise StateError(
                        "Action cohort process parent activity has no lifecycle parent"
                    )
                activity_category = "process-start-parent-activity"
                append(
                    parent_activity_time,
                    2,
                    LifecycleTransition(
                        transition_id=self._action_cohort_id(
                            plan,
                            activity_category,
                            ordinal,
                            parent_object_id,
                            "transition",
                        ),
                        subject=LifecycleEntityRef("process", parent_object_id),
                        kind="dependent",
                        canonical_time=parent_activity_time,
                        action_id=self._action_cohort_id(
                            plan,
                            activity_category,
                            ordinal,
                            parent_object_id,
                            "action",
                        ),
                        reason="State process-start parent activity",
                    ),
                )
            staged_processes[(identity.hostname, identity.pid)] = process_plan

        for ordinal, patch in enumerate(plan.session_metadata_patches):
            target = patch.target
            identity = target.identity if type(target) is SessionMaterializationPlan else target
            if type(target) is not SessionMaterializationPlan:
                self._action_cohort_registered_session(identity)
            transition_time = max(
                value
                for value in (
                    identity.started_at,
                    patch.after.source_ready_time,
                    patch.after.network_close_time,
                )
                if value is not None
            )
            category = "session-metadata"
            append(
                transition_time,
                2,
                LifecycleTransition(
                    transition_id=self._action_cohort_id(
                        plan,
                        category,
                        ordinal,
                        identity.object_id,
                        "transition",
                    ),
                    subject=LifecycleEntityRef("session", identity.object_id),
                    kind="dependent",
                    canonical_time=transition_time,
                    action_id=self._action_cohort_id(
                        plan,
                        category,
                        ordinal,
                        identity.object_id,
                        "action",
                    ),
                    reason="State session metadata transition",
                ),
            )

        for ordinal, patch in enumerate(plan.process_activity_patches):
            target = patch.target
            identity = target.identity if type(target) is ProcessMaterializationPlan else target
            if type(target) is not ProcessMaterializationPlan:
                self._action_cohort_registered_process(identity)
            category = "process-activity"
            append(
                patch.activity_time,
                2,
                LifecycleTransition(
                    transition_id=self._action_cohort_id(
                        plan,
                        category,
                        ordinal,
                        identity.object_id,
                        "transition",
                    ),
                    subject=LifecycleEntityRef("process", identity.object_id),
                    kind="dependent",
                    canonical_time=patch.activity_time,
                    action_id=self._action_cohort_id(
                        plan,
                        category,
                        ordinal,
                        identity.object_id,
                        "action",
                    ),
                    reason="State process activity transition",
                ),
            )

        for ordinal, patch in enumerate(plan.session_activity_patches):
            target = patch.target
            identity = target.identity if type(target) is SessionMaterializationPlan else target
            if type(target) is not SessionMaterializationPlan:
                self._action_cohort_registered_session(identity)
            category = "session-activity"
            append(
                patch.activity_time,
                2,
                LifecycleTransition(
                    transition_id=self._action_cohort_id(
                        plan,
                        category,
                        ordinal,
                        identity.object_id,
                        "transition",
                    ),
                    subject=LifecycleEntityRef("session", identity.object_id),
                    kind="dependent",
                    canonical_time=patch.activity_time,
                    action_id=self._action_cohort_id(
                        plan,
                        category,
                        ordinal,
                        identity.object_id,
                        "action",
                    ),
                    reason="State session activity transition",
                ),
            )

        for ordinal, termination in enumerate(plan.process_terminations):
            parent_activity = termination.parent_activity
            parent_activity_time: datetime | None = None
            parent_identity: ProcessIdentity | None = None
            if parent_activity is not None:
                target = parent_activity.target
                parent_identity = (
                    target.identity if type(target) is ProcessMaterializationPlan else target
                )
                if type(target) is not ProcessMaterializationPlan:
                    self._action_cohort_registered_process(parent_identity)
                parent_activity_time = parent_activity.activity_time
            elif type(termination.target) is ProcessTerminationMaterializationPlan:
                parent_activity_time = termination.target.parent_activity_time
                if parent_activity_time is not None:
                    parent_identity = self._action_cohort_live_parent(termination.identity)
            if parent_activity_time is not None and parent_identity is not None:
                category = "process-close-parent-activity"
                append(
                    parent_activity_time,
                    2,
                    LifecycleTransition(
                        transition_id=self._action_cohort_id(
                            plan,
                            category,
                            ordinal,
                            parent_identity.object_id,
                            "transition",
                        ),
                        subject=LifecycleEntityRef("process", parent_identity.object_id),
                        kind="dependent",
                        canonical_time=parent_activity_time,
                        action_id=self._action_cohort_id(
                            plan,
                            category,
                            ordinal,
                            parent_identity.object_id,
                            "action",
                        ),
                        reason="State process-close parent activity",
                    ),
                )

            identity = termination.identity
            if type(termination.target) is ProcessTerminationMaterializationPlan:
                self._action_cohort_registered_process(identity)
            category = "process-close"
            subject = LifecycleEntityRef("process", identity.object_id)
            append(
                termination.end_time,
                3,
                LifecycleSubjectClosureControl(
                    barrier=LifecycleCloseBarrier(
                        barrier_id=self._action_cohort_id(
                            plan,
                            category,
                            ordinal,
                            identity.object_id,
                            "barrier",
                        ),
                        subject=subject,
                        requested_at=termination.end_time,
                        authority="authoritative",
                        action_id=self._action_cohort_id(
                            plan,
                            category,
                            ordinal,
                            identity.object_id,
                            "action",
                        ),
                    ),
                    ticket_id=self._action_cohort_id(
                        plan,
                        category,
                        ordinal,
                        identity.object_id,
                        "ticket",
                    ),
                ),
            )

        for ordinal, terminalization in enumerate(plan.session_terminalizations):
            target = terminalization.target
            identity = target.identity if type(target) is SessionMaterializationPlan else target
            if type(target) is not SessionMaterializationPlan:
                self._action_cohort_registered_session(identity)
            category = "session-close"
            subject = LifecycleEntityRef("session", identity.object_id)
            append(
                terminalization.end_time,
                4,
                LifecycleSubjectClosureControl(
                    barrier=LifecycleCloseBarrier(
                        barrier_id=self._action_cohort_id(
                            plan,
                            category,
                            ordinal,
                            identity.object_id,
                            "barrier",
                        ),
                        subject=subject,
                        requested_at=terminalization.end_time,
                        authority="authoritative",
                        action_id=self._action_cohort_id(
                            plan,
                            category,
                            ordinal,
                            identity.object_id,
                            "action",
                        ),
                    ),
                    ticket_id=self._action_cohort_id(
                        plan,
                        category,
                        ordinal,
                        identity.object_id,
                        "ticket",
                    ),
                ),
            )

        operations = tuple(entry[3] for entry in sorted(entries, key=lambda entry: entry[:3]))
        if len(operations) > _MAX_ACTION_COHORT_OPERATIONS:
            raise StateError(
                "State action cohort projects too many lifecycle operations: "
                f"{len(operations)} > {_MAX_ACTION_COHORT_OPERATIONS}"
            )
        return LifecycleActionCohortRequest(
            state_publication_token=plan.publication_token,
            operations=operations,
        )

    def action_cohort_request(
        self,
        plan: ActionCohortMaterializationPlan,
    ) -> LifecycleActionCohortRequest:
        """Project an exact current State cohort into one ordered lifecycle request."""

        if not self._state_manager.authenticates_action_cohort_plan(plan):
            raise StateError("Action cohort State plan integrity validation failed")
        self._state_manager.validate_action_cohort_materialization(plan)
        return self._action_cohort_request_from_authenticated_plan(plan)

    def prepare_action_cohort(
        self,
        plan: ActionCohortMaterializationPlan,
    ) -> LifecycleActionCohortAdmissionToken:
        """Prepare lifecycle admission bound to one exact current State cohort."""

        return self._registry.prepare_action_cohort(self.action_cohort_request(plan))

    def authenticates_action_cohort_binding(
        self,
        plan: object,
        binding: object,
    ) -> bool:
        """Totally authenticate an active token or receipt against one State plan."""

        if not self._state_manager.authenticates_action_cohort_plan(plan):
            return False
        assert type(plan) is ActionCohortMaterializationPlan
        try:
            request = self._action_cohort_request_from_authenticated_plan(plan)
            if type(binding) is LifecycleActionCohortAdmissionToken:
                return self._registry.authenticates_action_cohort_admission_token(
                    binding,
                    request=request,
                    state_publication_token=plan.publication_token,
                )
            if type(binding) is LifecycleActionCohortReceipt:
                return self._registry.authenticates_action_cohort_receipt(
                    binding,
                    request=request,
                    state_publication_token=plan.publication_token,
                )
            return False
        except (
            AssertionError,
            AttributeError,
            LookupError,
            RecursionError,
            RuntimeError,
            StateError,
            TypeError,
            ValueError,
        ):
            return False

    def connection_composite_start_members(
        self,
        plan: ConnectionCompositeMaterializationPlan,
    ) -> tuple[LifecycleClosedTransportStartMember, ...]:
        """Project exact parent-ordered lifecycle starts without publishing state."""

        if not self._state_manager.authenticates_materialization_plan(plan):
            raise StateError("Connection composite plan integrity validation failed")
        batch = plan.batch
        if batch is None and plan.existing_session_patch is None:
            return ()
        session_plan = batch.session if batch is not None else None
        existing_session_patch = plan.existing_session_patch
        existing_session_starts = bool(
            existing_session_patch is not None
            and existing_session_patch.lifecycle_disposition
            is ConnectionExistingSessionLifecycleDisposition.START
        )
        staged_session = (
            session_plan.identity
            if session_plan is not None
            else existing_session_patch.after.identity
            if existing_session_starts and existing_session_patch is not None
            else None
        )
        members: list[LifecycleClosedTransportStartMember] = []
        if session_plan is not None:
            session_identity = self._shadow.project_session_start(session_plan.identity)
            members.append(
                LifecycleClosedTransportStartMember(
                    request=LifecycleSessionStartRequest(
                        identity=session_identity,
                        action_id=stable_uuid(
                            "lifecycle-authority-start-action",
                            "session",
                            session_identity.object_id,
                        ),
                        transition_id=stable_uuid(
                            "lifecycle-authority-start-transition",
                            "session",
                            session_identity.object_id,
                        ),
                    ),
                    publication_token=session_plan.publication_token,
                )
            )
        elif existing_session_starts:
            assert existing_session_patch is not None
            session_identity = self._shadow.project_session_start(
                existing_session_patch.after.identity
            )
            members.append(
                LifecycleClosedTransportStartMember(
                    request=LifecycleSessionStartRequest(
                        identity=session_identity,
                        action_id=stable_uuid(
                            "lifecycle-authority-start-action",
                            "existing-session",
                            session_identity.object_id,
                        ),
                        transition_id=stable_uuid(
                            "lifecycle-authority-start-transition",
                            "existing-session",
                            session_identity.object_id,
                        ),
                    ),
                    publication_token=plan.publication_token,
                )
            )

        staged_processes: dict[tuple[str, int], ProcessIdentity] = {}
        for process_plan in batch.processes if batch is not None else ():
            identity = process_plan.identity
            parent_object_id = ""
            if identity.parent_pid:
                staged_parent = staged_processes.get((identity.hostname, identity.parent_pid))
                if staged_parent is not None:
                    if process_plan.parent_identity != staged_parent:
                        raise StateError(
                            "Connection composite parent differs from authenticated process plan"
                        )
                    parent_object_id = staged_parent.object_id
                else:
                    parent = process_plan.parent_identity
                    if parent is None:
                        if identity.parent_pid != 4:
                            raise StateError(
                                "Connection composite has no exact lifecycle parent for "
                                f"{identity.object_id} PID={identity.parent_pid}"
                            )
                    else:
                        parent_snapshot = self._registry.get_process(parent.object_id)
                        if parent_snapshot is None or parent_snapshot.closed_at is not None:
                            raise StateError(
                                "Connection composite parent is not registered and live: "
                                f"{parent.object_id}"
                            )
                        parent_object_id = parent.object_id

            session = (
                staged_session
                if staged_session is not None and staged_session.logon_id == identity.logon_id
                else self._state_manager.get_session_identity(identity.logon_id)
                if identity.logon_id
                else None
            )
            if session is not None and session.hostname != identity.hostname:
                raise StateError(
                    f"Connection composite process {identity.object_id} uses cross-host session"
                )
            if session is not None and session is not staged_session:
                session_snapshot = self._registry.get_session(session.object_id)
                if session_snapshot is None or session_snapshot.closed_at is not None:
                    raise StateError(
                        "Connection composite session is not registered and live: "
                        f"{session.object_id}"
                    )
            session_logon_type = (
                session_plan.logon_type
                if session is staged_session and session_plan is not None
                else existing_session_patch.after.logon_type
                if session is staged_session and existing_session_patch is not None
                else self._state_manager.get_session_logon_type(identity.logon_id)
                if session is not None
                else None
            )
            lifecycle_identity, token, membership = self._shadow.project_process_start(
                identity,
                integrity_level=process_plan.integrity_level,
                session=session,
                token_session_id=process_plan.auth_session_id,
                session_logon_type=(
                    session_logon_type if session is not None else process_plan.auth_logon_type
                ),
                parent_object_id=parent_object_id,
            )
            members.append(
                LifecycleClosedTransportStartMember(
                    request=LifecycleProcessStartRequest(
                        identity=lifecycle_identity,
                        token=token,
                        membership=membership,
                        action_id=stable_uuid(
                            "lifecycle-authority-start-action",
                            "process",
                            identity.object_id,
                        ),
                        transition_id=stable_uuid(
                            "lifecycle-authority-start-transition",
                            "process",
                            identity.object_id,
                        ),
                    ),
                    publication_token=process_plan.publication_token,
                )
            )
            staged_processes[(identity.hostname, identity.pid)] = identity
        return tuple(members)

    @staticmethod
    def _validate_connection_holds(
        plan: ConnectionCompositeMaterializationPlan,
        holds: tuple[LifecycleHold, ...],
    ) -> None:
        """Require exact State activity frontiers for every lifecycle process hold."""

        process_patches = {patch.identity.object_id: patch for patch in plan.process_activity}
        if len(process_patches) != len(plan.process_activity):
            raise StateError("Connection composite repeats a process activity owner")
        hold_subjects = [hold.subject.object_id for hold in holds]
        if len(set(hold_subjects)) != len(hold_subjects):
            raise StateError("Connection composite repeats a process hold subject")
        if set(hold_subjects) != set(process_patches):
            raise StateError("Connection process activity and lifecycle holds disagree")
        session_patches = {patch.identity.logon_id: patch for patch in plan.session_activity}
        if len(session_patches) != len(plan.session_activity):
            raise StateError("Connection composite repeats a session activity owner")
        expected_session_ids = {
            patch.identity.logon_id for patch in process_patches.values() if patch.identity.logon_id
        }
        if set(session_patches) != expected_session_ids:
            raise StateError("Connection session activity and lifecycle holds disagree")
        for hold in holds:
            if hold.subject.kind != "process":
                raise StateError("Connection composite holds must target processes")
            process_patch = process_patches[hold.subject.object_id]
            if process_patch.activity_time != hold.hold_until:
                raise StateError("Connection process hold and State activity deadline disagree")
            logon_id = process_patch.identity.logon_id
            if not logon_id:
                continue
            session_patch = session_patches.get(logon_id)
            if session_patch is None or session_patch.activity_time != hold.hold_until:
                raise StateError(
                    "Connection process hold and owning-session activity deadline disagree"
                )

    @staticmethod
    def _lifecycle_transport_matches_fingerprint(
        fingerprint: PhysicalTransportFingerprint,
        lifecycle_receipt: LifecycleClosedTransportPublicationReceipt,
    ) -> bool:
        """Return whether lifecycle committed the exact State physical transport."""

        identity = lifecycle_receipt.transport.identity
        return (
            identity.transport_id == fingerprint.transport_id
            and identity.conn_id == fingerprint.conn_id
            and identity.zeek_uid == fingerprint.zeek_uid
            and identity.tuple_key == fingerprint.tuple_key
            and identity.opened_at == fingerprint.started_at
            and identity.close_deadline == fingerprint.closed_at
            and lifecycle_receipt.transport.closed_at == fingerprint.closed_at
        )

    def _validate_existing_lifecycle_transport(
        self,
        fingerprint: PhysicalTransportFingerprint,
    ) -> None:
        """Require an exact existing lifecycle transport for an application child."""

        snapshot = self._registry.transport_for_transport_id(fingerprint.transport_id)
        if snapshot is None:
            raise StateError(
                "Application child has no exact canonical lifecycle transport "
                f"{fingerprint.transport_id!r}"
            )
        identity = snapshot.identity
        if (
            identity.conn_id != fingerprint.conn_id
            or identity.zeek_uid != fingerprint.zeek_uid
            or identity.tuple_key != fingerprint.tuple_key
            or identity.opened_at != fingerprint.started_at
            or identity.close_deadline != fingerprint.closed_at
            or snapshot.closed_at != fingerprint.closed_at
        ):
            raise StateError("Application child lifecycle transport disagrees with State")

    def _common_application_token_identity(
        self,
        token: ApplicationChannelAdmissionToken,
    ) -> object:
        """Return the exact common channel identity protected by one active token."""

        registry = self._application_registry
        if registry is None or not registry.authenticates_admission_token(token):
            raise StateError("Connection composite has no authentic common application token")
        if token.identity is not None:
            return token.identity
        snapshot = registry.get(token.reservation.channel_id)
        if snapshot is None:
            raise StateError("Prepared common application operation has no exact channel")
        return snapshot.identity

    def _application_admission_transport_ids(
        self,
        token: _ApplicationAdmissionToken,
    ) -> tuple[str, tuple[str, ...]]:
        """Authenticate a bound manager token and return current/prerequisite legs."""

        if isinstance(token, HttpChannelAdmissionToken):
            manager = self._http_channel_manager
            if manager is None or not manager.authenticates_admission_token(token):
                raise StateError("Connection composite has no authentic HTTP admission token")
            identity = self._common_application_token_identity(token.application_token)
            return identity.binding.transport_id, ()
        if isinstance(token, ExplicitProxyAdmissionToken):
            manager = self._explicit_proxy_manager
            if manager is None or not manager.authenticates_admission_token(token):
                raise StateError("Connection composite has no authentic proxy admission token")
            self._common_application_token_identity(token.application_token)
            tunnel = token.result.tunnel
            if token.kind == "open":
                return tunnel.origin_transport_id, (tunnel.client_transport_id,)
            if token.kind == "request":
                return tunnel.client_transport_id, ()
            raise StateError(f"Unsupported explicit-proxy admission kind {token.kind!r}")
        if isinstance(token, SmbChannelAdmissionToken):
            manager = self._smb_channel_manager
            if manager is None or not manager.authenticates_admission_token(token):
                raise StateError("Connection composite has no authentic SMB admission token")
            identity = self._common_application_token_identity(token.application_token)
            if identity.protocol != "smb":
                raise StateError("SMB admission's common channel has another protocol")
            return identity.binding.transport_id, ()
        if isinstance(token, SshChannelAdmissionToken):
            manager = self._ssh_channel_manager
            if manager is None or not manager.authenticates_admission_token(token):
                raise StateError("Connection composite has no authentic SSH admission token")
            self._common_application_token_identity(token.application_token)
            return token.session.transport.transport_id, ()
        if isinstance(token, RdpSessionAdmissionToken):
            manager = self._rdp_session_manager
            if manager is None or not manager.authenticates_admission_token(token):
                raise StateError("Connection composite has no authentic RDP admission token")
            self._common_application_token_identity(token.application_token)
            return token.transport_ids[-1], ()
        identity = self._common_application_token_identity(token)
        if identity.protocol in {"http", "explicit-proxy", "smb", "ssh", "rdp"}:
            raise StateError(
                f"Protocol {identity.protocol!r} requires its engine-owned sidecar receipt"
            )
        return identity.binding.transport_id, ()

    @staticmethod
    def _prerequisite_proof_digest(
        receipt: LifecycleConnectionCompositeReceipt,
    ) -> str:
        """Return a stable digest over one already authority-authenticated receipt."""

        semantic = (
            receipt._state_publication_token,
            receipt.prior_version,
            receipt.committed_version,
            receipt.transaction_id,
            receipt._physical_transport,
            receipt.materializes_connection,
            receipt.lifecycle_publication_token,
            receipt.application_proof,
            receipt.prerequisite_proofs,
            receipt.receipt_token,
        )
        return sha256(repr(("connection-prerequisite-v1", semantic)).encode()).hexdigest()

    def _authenticates_issued_connection_receipt(
        self,
        receipt: object,
    ) -> bool:
        """Authenticate a prior authority receipt without relying on retained State rows."""

        if not isinstance(receipt, LifecycleConnectionCompositeReceipt):
            return False
        if not receipt._has_valid_integrity(self._receipt_secret):
            return False
        if receipt.committed_version != receipt.prior_version + 1:
            return False
        lifecycle_receipt = receipt._lifecycle_receipt
        if receipt.materializes_connection:
            if lifecycle_receipt is None:
                return False
            if not self._registry.authenticates_closed_transport_publication_receipt(
                lifecycle_receipt,
                request=lifecycle_receipt.request,
                start_plan_tokens=receipt.start_plan_tokens,
            ):
                return False
            if not self._lifecycle_transport_matches_fingerprint(
                receipt._physical_transport,
                lifecycle_receipt,
            ):
                return False
        elif lifecycle_receipt is not None:
            return False
        proof = receipt.application_proof
        if proof is None:
            return receipt.materializes_connection and not receipt.prerequisite_proofs
        if proof.current_transport_id != receipt.physical_transport_id:
            return False
        return proof.prerequisite_transport_ids == tuple(
            prerequisite.physical_transport_id for prerequisite in receipt.prerequisite_proofs
        )

    def _normalize_prerequisite_proofs(
        self,
        receipts: tuple[LifecycleConnectionCompositeReceipt, ...],
        expected_transport_ids: tuple[str, ...],
    ) -> tuple[ConnectionCompositePrerequisiteProof, ...]:
        """Authenticate exact prior authority receipts and freeze compact proof membership."""

        if len({id(receipt) for receipt in receipts}) != len(receipts):
            raise StateError("Connection composite repeats a prerequisite receipt")
        if tuple(receipt.physical_transport_id for receipt in receipts) != expected_transport_ids:
            raise StateError("Connection prerequisite receipts do not match manager transport legs")
        proofs: list[ConnectionCompositePrerequisiteProof] = []
        for receipt in receipts:
            if not self._authenticates_issued_connection_receipt(receipt):
                raise StateError("Connection composite prerequisite receipt is not authentic")
            if not receipt.materializes_connection:
                raise StateError("Connection composite prerequisite must own a physical transport")
            proofs.append(
                ConnectionCompositePrerequisiteProof(
                    receipt_token=receipt.receipt_token,
                    receipt_digest=self._prerequisite_proof_digest(receipt),
                    physical_transport_id=receipt.physical_transport_id,
                    transaction_id=receipt.transaction_id,
                    conn_id=receipt.conn_id,
                    zeek_uid=receipt.zeek_uid,
                )
            )
        return tuple(proofs)

    @staticmethod
    def _common_sidecar_result_digest(receipt: ApplicationChannelAdmissionReceipt) -> str:
        """Return stable protocol-neutral result membership for the outer proof."""

        semantic = (
            receipt.kind,
            receipt.channel_id,
            receipt.operation_id,
            receipt.operation_ids,
            receipt.snapshot,
            receipt.close_token,
            receipt.receipt_token,
        )
        return sha256(repr(("application-common-result-v1", semantic)).encode()).hexdigest()

    def _normalize_application_proof(
        self,
        token: _ApplicationAdmissionToken,
        result: _ApplicationAdmissionResult,
    ) -> ApplicationChannelCompositeProof:
        """Verify an engine-owned manager receipt, then discard its manager-specific carrier."""

        if isinstance(token, HttpChannelAdmissionToken):
            manager = self._http_channel_manager
            if manager is None or not isinstance(result, HttpChannelAdmissionResult):
                raise AssertionError("HTTP application commit returned an incompatible result")
            receipt = result.receipt
            if not manager.authenticates_admission_receipt(receipt):
                raise AssertionError("HTTP manager returned an unauthenticated receipt")
            return ApplicationChannelCompositeProof(
                manager_kind="http",
                manager_id=receipt.manager_id,
                manager_receipt_token=receipt.receipt_token,
                common_receipt_token=receipt.application_receipt_token,
                channel_id=receipt.channel_id,
                operation_id=receipt.operation_id,
                current_transport_id=receipt.transport_id,
                prerequisite_transport_ids=(),
                sidecar_result_digest=receipt.sidecar_result_digest,
            )
        if isinstance(token, ExplicitProxyAdmissionToken):
            manager = self._explicit_proxy_manager
            if manager is None or not isinstance(result, ExplicitProxyAdmissionCommitResult):
                raise AssertionError("Proxy application commit returned an incompatible result")
            receipt = result.receipt
            if not manager.authenticates_admission_receipt(receipt):
                raise AssertionError("Proxy manager returned an unauthenticated receipt")
            return ApplicationChannelCompositeProof(
                manager_kind="explicit_proxy",
                manager_id=receipt.manager_id,
                manager_receipt_token=receipt.receipt_token,
                common_receipt_token=receipt.application_receipt_token,
                channel_id=receipt.channel_id,
                operation_id=receipt.operation_id,
                current_transport_id=receipt.current_transport_id,
                prerequisite_transport_ids=receipt.prerequisite_transport_ids,
                sidecar_result_digest=receipt.sidecar_result_digest,
            )
        if isinstance(token, SmbChannelAdmissionToken):
            manager = self._smb_channel_manager
            if (
                manager is None
                or type(result) is not SmbChannelAdmissionResult
                or not manager.authenticates_admission_result(result)
            ):
                raise AssertionError("SMB application commit returned an incompatible result")
            receipt = result.receipt
            return ApplicationChannelCompositeProof(
                manager_kind="smb",
                manager_id=receipt.manager_id,
                manager_receipt_token=receipt.receipt_token,
                common_receipt_token=receipt.application_receipt_token,
                channel_id=receipt.channel_id,
                operation_id=receipt.operation_id,
                current_transport_id=receipt.transport_id,
                prerequisite_transport_ids=(),
                sidecar_result_digest=receipt.sidecar_result_digest,
            )
        if isinstance(token, SshChannelAdmissionToken):
            manager = self._ssh_channel_manager
            if manager is None or not isinstance(result, SshChannelAdmissionResult):
                raise AssertionError("SSH application commit returned an incompatible result")
            receipt = result.receipt
            if not manager.authenticates_admission_receipt(receipt):
                raise AssertionError("SSH manager returned an unauthenticated receipt")
            return ApplicationChannelCompositeProof(
                manager_kind="ssh",
                manager_id=receipt.manager_id,
                manager_receipt_token=receipt.receipt_token,
                common_receipt_token=receipt.application_receipt_token,
                channel_id=receipt.channel_id,
                operation_id=receipt.operation_id,
                current_transport_id=receipt.transport_ids[-1],
                prerequisite_transport_ids=(),
                sidecar_result_digest=receipt.sidecar_result_digest,
            )
        if isinstance(token, RdpSessionAdmissionToken):
            manager = self._rdp_session_manager
            if manager is None or not isinstance(result, RdpSessionAdmissionResult):
                raise AssertionError("RDP application commit returned an incompatible result")
            receipt = result.receipt
            if not manager.authenticates_admission_receipt(receipt):
                raise AssertionError("RDP manager returned an unauthenticated receipt")
            return ApplicationChannelCompositeProof(
                manager_kind="rdp",
                manager_id=receipt.manager_id,
                manager_receipt_token=receipt.receipt_token,
                common_receipt_token=receipt.application_receipt_token,
                channel_id=receipt.channel_id,
                operation_id=receipt.operation_id,
                current_transport_id=receipt.transport_ids[-1],
                prerequisite_transport_ids=(),
                sidecar_result_digest=receipt.sidecar_result_digest,
            )
        registry = self._application_registry
        if (
            registry is None
            or type(result) is not ApplicationChannelAdmissionResult
            or not registry.authenticates_admission_result(result)
        ):
            raise AssertionError("Common application commit returned an incompatible result")
        receipt = result.receipt
        if receipt is None:
            raise AssertionError("Common application registry returned no authentic receipt")
        return ApplicationChannelCompositeProof(
            manager_kind="protocol_neutral",
            manager_id="engine-application-registry",
            manager_receipt_token=receipt.receipt_token,
            common_receipt_token=receipt.receipt_token,
            channel_id=receipt.channel_id,
            operation_id=receipt.operation_id,
            current_transport_id=receipt.snapshot.identity.binding.transport_id,
            prerequisite_transport_ids=(),
            sidecar_result_digest=self._common_sidecar_result_digest(receipt),
        )

    @staticmethod
    def _transport_identity_matches_fingerprint(
        fingerprint: PhysicalTransportFingerprint,
        identity: object,
    ) -> bool:
        """Return whether one lifecycle transport identity matches all State fields."""

        return (
            identity.transport_id == fingerprint.transport_id
            and identity.conn_id == fingerprint.conn_id
            and identity.zeek_uid == fingerprint.zeek_uid
            and identity.tuple_key == fingerprint.tuple_key
            and identity.opened_at == fingerprint.started_at
            and identity.close_deadline == fingerprint.closed_at
        )

    def _validate_connection_composite_admissions(
        self,
        plan: ConnectionCompositeMaterializationPlan,
        lifecycle_token: LifecycleClosedTransportAdmissionToken | None,
        application_token: _ApplicationAdmissionToken | None,
        prerequisite_receipts: tuple[LifecycleConnectionCompositeReceipt, ...],
    ) -> tuple[
        tuple[LifecycleClosedTransportStartMember, ...],
        tuple[ConnectionCompositePrerequisiteProof, ...],
    ]:
        """Validate every cross-authority relationship without publishing rows."""

        if not self._state_manager.authenticates_materialization_plan(plan):
            raise StateError("Connection composite plan integrity validation failed")
        fingerprint = plan.physical_transport_fingerprint
        if fingerprint.closed_at is None:
            raise StateError("Lifecycle connection composite requires a closed transport")

        start_members: tuple[LifecycleClosedTransportStartMember, ...] = ()
        if plan.materializes_connection:
            if lifecycle_token is None:
                raise StateError("Physical connection composite requires lifecycle admission")
            start_members = self.connection_composite_start_members(plan)
            request = lifecycle_token.request
            if request.start_members != start_members:
                raise StateError("Lifecycle admission start members disagree with State batch")
            if not self._transport_identity_matches_fingerprint(
                fingerprint,
                request.identity,
            ):
                raise StateError("Lifecycle admission transport disagrees with State")
            self._validate_connection_holds(plan, request.process_holds)
            if not self._registry.authenticates_closed_transport_admission_token(
                lifecycle_token,
                request=request,
                start_plan_tokens=self._connection_batch_member_tokens(plan),
            ):
                raise StateError("Connection composite lifecycle admission is not authentic")
        else:
            if lifecycle_token is not None:
                raise StateError("Application child cannot create another lifecycle transport")
            if plan.batch is not None:
                raise StateError("Application child cannot materialize lifecycle start members")
            if plan.process_activity or plan.session_activity:
                raise StateError(
                    "Application child cannot add activity beyond its physical transport hold"
                )
            self._validate_existing_lifecycle_transport(fingerprint)

        if application_token is None:
            if not plan.materializes_connection:
                raise StateError("Application child requires an engine-owned manager admission")
            if prerequisite_receipts:
                raise StateError("Connection prerequisites require an application manager proof")
            return start_members, ()
        current_transport_id, prerequisite_transport_ids = (
            self._application_admission_transport_ids(application_token)
        )
        if current_transport_id != fingerprint.transport_id:
            raise StateError("Application manager admission targets another physical transport")
        prerequisite_proofs = self._normalize_prerequisite_proofs(
            prerequisite_receipts,
            prerequisite_transport_ids,
        )
        return start_members, prerequisite_proofs

    def _enter_application_admission(
        self,
        stack: ExitStack,
        token: _ApplicationAdmissionToken,
    ) -> _ApplicationPreparedCommit:
        """Claim one exact engine-owned manager capability without arbitrary callbacks."""

        if isinstance(token, HttpChannelAdmissionToken):
            manager = self._http_channel_manager
            if manager is None:
                raise StateError("Lifecycle authority has no bound HTTP manager")
            return stack.enter_context(manager.prepared_admission(token))
        if isinstance(token, ExplicitProxyAdmissionToken):
            manager = self._explicit_proxy_manager
            if manager is None:
                raise StateError("Lifecycle authority has no bound proxy manager")
            return stack.enter_context(manager.prepared_admission(token))
        if isinstance(token, SmbChannelAdmissionToken):
            manager = self._smb_channel_manager
            if manager is None:
                raise StateError("Lifecycle authority has no bound SMB manager")
            return stack.enter_context(manager.prepared_admission(token))
        if isinstance(token, SshChannelAdmissionToken):
            manager = self._ssh_channel_manager
            if manager is None:
                raise StateError("Lifecycle authority has no bound SSH manager")
            return stack.enter_context(manager.prepared_admission(token))
        if isinstance(token, RdpSessionAdmissionToken):
            manager = self._rdp_session_manager
            if manager is None:
                raise StateError("Lifecycle authority has no bound RDP manager")
            return stack.enter_context(manager.prepared_admission(token))
        registry = self._application_registry
        if registry is None:
            raise StateError("Lifecycle authority has no bound application registry")
        return stack.enter_context(registry.prepared_admission(token))

    def _discard_application_admission(
        self,
        token: _ApplicationAdmissionToken | None,
    ) -> None:
        """Best-effort release of one exact transferred manager capability."""

        try:
            if isinstance(token, HttpChannelAdmissionToken):
                manager = self._http_channel_manager
                if manager is not None:
                    manager.cancel_prepared_admission(token)
            elif isinstance(token, ExplicitProxyAdmissionToken):
                manager = self._explicit_proxy_manager
                if manager is not None:
                    manager.cancel_prepared_admission(token)
            elif isinstance(token, SmbChannelAdmissionToken):
                manager = self._smb_channel_manager
                if manager is not None:
                    manager.cancel_prepared_admission(token)
            elif isinstance(token, SshChannelAdmissionToken):
                manager = self._ssh_channel_manager
                if manager is not None:
                    manager.cancel_prepared_admission(token)
            elif isinstance(token, RdpSessionAdmissionToken):
                manager = self._rdp_session_manager
                if manager is not None:
                    manager.cancel_prepared_admission(token)
            elif isinstance(token, ApplicationChannelAdmissionToken):
                registry = self._application_registry
                if registry is not None:
                    registry.cancel_prepared_admission(token)
        except (StateError, ValueError):
            # Exact-object cancellation deliberately reports integrity drift after
            # releasing its retained preimage. Preserve the composite's primary error.
            pass

    def _discard_connection_composite_admissions(
        self,
        lifecycle_token: LifecycleClosedTransportAdmissionToken | None,
        application_token: _ApplicationAdmissionToken | None,
    ) -> None:
        """Release every uncommitted one-shot capability transferred by a caller."""

        self._discard_application_admission(application_token)
        if lifecycle_token is None:
            return
        try:
            self._registry.cancel_closed_transport_publication(lifecycle_token)
        except StateError:
            # The registry has already released an in-place-mutated exact token.
            pass

    @staticmethod
    def _commit_application_admission_no_fail(prepared: object) -> _ApplicationAdmissionResult:
        """Commit one already claimed typed application capability."""

        result = prepared.commit_no_fail()
        if not isinstance(
            result,
            (
                ApplicationChannelAdmissionResult,
                HttpChannelAdmissionResult,
                ExplicitProxyAdmissionCommitResult,
                SmbChannelAdmissionResult,
                SshChannelAdmissionResult,
                RdpSessionAdmissionResult,
            ),
        ):
            raise AssertionError("Application manager returned an incompatible commit result")
        return result

    @staticmethod
    def _commit_lifecycle_admission_recoverably(
        prepared: PreparedLifecycleClosedTransportPublication,
    ) -> LifecycleClosedTransportPublicationReceipt:
        """Commit or adopt one exact lifecycle owner across a lost return."""

        first_failure: BaseException | None = None
        for _attempt in range(2):
            try:
                receipt = prepared.commit_no_fail()
            except BaseException as failure:
                if first_failure is None:
                    first_failure = failure
                receipt = prepared.receipt if prepared.committed else None
                if type(receipt) is LifecycleClosedTransportPublicationReceipt:
                    return receipt
                continue
            if type(receipt) is not LifecycleClosedTransportPublicationReceipt:
                raise AssertionError("Lifecycle registry returned an incompatible receipt")
            return receipt
        assert first_failure is not None
        raise first_failure

    @staticmethod
    def _commit_state_composite_recoverably(
        prepared: PreparedConnectionCompositeMaterialization,
    ) -> ConnectionCompositeMaterializationResult:
        """Commit or adopt one exact State composite across a lost return."""

        first_failure: BaseException | None = None
        for _attempt in range(2):
            try:
                result = prepared.commit()
            except BaseException as failure:
                if first_failure is None:
                    first_failure = failure
                result = prepared._result if prepared.committed else None
                if type(result) is ConnectionCompositeMaterializationResult:
                    return result
                continue
            if type(result) is not ConnectionCompositeMaterializationResult:
                raise AssertionError("State manager returned an incompatible composite result")
            return result
        assert first_failure is not None
        raise first_failure

    @classmethod
    def _commit_application_admission_recoverably(
        cls,
        prepared: _ApplicationPreparedCommit,
    ) -> _ApplicationAdmissionResult:
        """Commit or adopt one exact application owner across a lost return."""

        first_failure: BaseException | None = None
        for _attempt in range(2):
            try:
                return cls._commit_application_admission_no_fail(prepared)
            except BaseException as failure:
                if first_failure is None:
                    first_failure = failure
                result = prepared.result if prepared.committed else None
                if isinstance(
                    result,
                    (
                        ApplicationChannelAdmissionResult,
                        HttpChannelAdmissionResult,
                        ExplicitProxyAdmissionCommitResult,
                        SmbChannelAdmissionResult,
                        SshChannelAdmissionResult,
                        RdpSessionAdmissionResult,
                    ),
                ):
                    return result
        assert first_failure is not None
        raise first_failure

    @staticmethod
    def _commit_runtime_recoverably(
        prepared: NetworkTransactionPreparedCommit,
    ) -> NetworkTransactionPreparationReceipt:
        """Commit or adopt one exact network-runtime owner across a lost return."""

        first_failure: BaseException | None = None
        for _attempt in range(2):
            try:
                receipt = prepared.commit_no_fail()
            except BaseException as failure:
                if first_failure is None:
                    first_failure = failure
                receipt = prepared.receipt if prepared.committed else None
                if type(receipt) is NetworkTransactionPreparationReceipt:
                    return receipt
                continue
            if type(receipt) is not NetworkTransactionPreparationReceipt:
                raise AssertionError("Network runtime returned an incompatible receipt")
            return receipt
        assert first_failure is not None
        raise first_failure

    @staticmethod
    def _commit_source_timing_recoverably(
        prepared: SourceTimingPreparation,
    ) -> SourceTimingPreparationReceipt:
        """Commit or adopt one exact source-timing owner across a lost return."""

        first_failure: BaseException | None = None
        for _attempt in range(2):
            try:
                receipt = prepared.commit_no_fail()
            except BaseException as failure:
                if first_failure is None:
                    first_failure = failure
                receipt = prepared.receipt if prepared.committed else None
                if type(receipt) is SourceTimingPreparationReceipt:
                    return receipt
                continue
            if type(receipt) is not SourceTimingPreparationReceipt:
                raise AssertionError("Source timing returned an incompatible receipt")
            return receipt
        assert first_failure is not None
        raise first_failure

    def _issue_connection_composite_receipt_recoverably(
        self,
        *,
        state_publication_token: str,
        prior_version: int,
        committed_version: int,
        transaction_id: str,
        physical_transport: PhysicalTransportFingerprint,
        materializes_connection: bool,
        lifecycle_receipt: LifecycleClosedTransportPublicationReceipt | None,
        application_proof: ApplicationChannelCompositeProof | None,
        prerequisite_proofs: tuple[ConnectionCompositePrerequisiteProof, ...],
    ) -> LifecycleConnectionCompositeReceipt:
        """Issue, or reconstruct, the pure outer proof after a lost constructor return."""

        values = (
            state_publication_token,
            prior_version,
            committed_version,
            transaction_id,
            physical_transport,
            materializes_connection,
            lifecycle_receipt,
            application_proof,
            prerequisite_proofs,
        )
        try:
            receipt = LifecycleConnectionCompositeReceipt._issue(
                authority_secret=self._receipt_secret,
                state_publication_token=state_publication_token,
                prior_version=prior_version,
                committed_version=committed_version,
                transaction_id=transaction_id,
                physical_transport=physical_transport,
                materializes_connection=materializes_connection,
                lifecycle_receipt=lifecycle_receipt,
                application_proof=application_proof,
                prerequisite_proofs=prerequisite_proofs,
            )
        except BaseException:
            receipt = LifecycleConnectionCompositeReceipt(
                *values,
                LifecycleConnectionCompositeReceipt._integrity_for(
                    authority_secret=self._receipt_secret,
                    values=values,
                ),
            )
        if type(
            receipt
        ) is not LifecycleConnectionCompositeReceipt or not receipt._has_valid_integrity(
            self._receipt_secret
        ):
            raise AssertionError(
                "Connection composite receipt reconstruction failed authentication"
            )
        return receipt

    def _claim_prepared_network_receipt_issuance(
        self,
        root: object,
    ) -> tuple[
        _PreparedNetworkReceiptIssuance | None,
        LifecyclePreparedNetworkResult | None,
        _PreparedNetworkReceiptIssuanceClaim | None,
    ]:
        """Claim a committed retry carrier before reading consumed caller capabilities."""

        if type(root) is not PreparedNetworkTransactionRoot:
            return None, None, None
        root_id = id(root)
        with self._prepared_network_receipt_issuance_lock:
            generation = self._prepared_network_receipt_issuance_generations.get(root_id)
            if generation is None:
                return None, None, None
            key = (root_id, generation)
            record = self._prepared_network_receipt_issuances.get(key)
            if (
                type(record) is not _PreparedNetworkReceiptIssuance
                or record.root is not root
                or record.generation != generation
            ):
                raise StateError("Prepared-network issuance carrier identity changed")
            if not record.canonical_committed or record.issuance_values is None:
                raise StateError("Prepared-network issuance carrier has no committed facts")
            retained_claim = None if record.claim_ref is None else record.claim_ref()
            if retained_claim is not None:
                raise StateError("Prepared-network issuance recovery is already claimed")
            claim = _PreparedNetworkReceiptIssuanceClaim()
            record.claim_ref = ref(claim)
            return record, None, claim

    def _reserve_prepared_network_receipt_issuance(
        self,
        root: PreparedNetworkTransactionRoot,
        receipt: LifecyclePreparedNetworkReceipt,
        result: LifecyclePreparedNetworkResult,
        authority_record: _PreparedNetworkReceiptAuthority,
        claim: _PreparedNetworkReceiptIssuanceClaim,
        root_graph: _PreparedNetworkGraphSnapshot,
    ) -> _PreparedNetworkReceiptIssuance:
        """Preallocate one strong hard-capped carrier before canonical mutation."""

        planner = self._source_timing_planner
        if (
            planner is None
            or type(root) is not PreparedNetworkTransactionRoot
            or type(receipt) is not LifecyclePreparedNetworkReceipt
            or type(result) is not LifecyclePreparedNetworkResult
            or type(authority_record) is not _PreparedNetworkReceiptAuthority
            or type(claim) is not _PreparedNetworkReceiptIssuanceClaim
            or type(root_graph) is not tuple
            or not root_graph
        ):
            raise StateError("Prepared-network issuance reservation is malformed")
        capacity = object.__getattribute__(
            self,
            "_prepared_network_receipt_issuance_capacity",
        )
        if type(capacity) is not int or capacity < 1:
            raise StateError("Prepared-network issuance capacity is malformed")
        root_id = id(root)
        receipt_id = id(receipt)
        with self._prepared_network_receipt_issuance_lock:
            if len(self._prepared_network_receipt_issuances) >= capacity:
                raise StateError("Prepared-network issuance carrier capacity is exhausted")
            if root_id in self._prepared_network_receipt_issuance_generations:
                raise StateError("Prepared-network root already has an issuance carrier")
            if receipt_id in self._prepared_network_receipt_issuance_receipts:
                raise StateError("Prepared-network receipt already has an issuance carrier")
            self._prepared_network_receipt_issuance_generation += 1
            generation = self._prepared_network_receipt_issuance_generation
            key = (root_id, generation)

            record = _PreparedNetworkReceiptIssuance(
                root=root,
                generation=generation,
                receipt=receipt,
                result=result,
                authority_record=authority_record,
                claim_ref=ref(claim),
                root_graph=root_graph,
            )
            self._prepared_network_receipt_issuances[key] = record
            self._prepared_network_receipt_issuance_generations[root_id] = generation
            self._prepared_network_receipt_issuance_receipts[receipt_id] = key
            return record

    def _discard_prepared_network_receipt_issuance(
        self,
        root: PreparedNetworkTransactionRoot,
        record: _PreparedNetworkReceiptIssuance,
    ) -> None:
        """Generation-CAS discard one still-reversible strong carrier."""

        root_id = id(root)
        generation = record.generation
        key = (root_id, generation)
        with self._prepared_network_receipt_issuance_lock:
            retained = self._prepared_network_receipt_issuances.get(key)
            if (
                retained is record
                and retained.root is root
                and not retained.terminal
                and not retained.canonical_committed
                and self._prepared_network_receipt_issuance_generations.get(root_id) == generation
                and self._prepared_network_receipt_issuance_receipts.get(id(record.receipt)) == key
            ):
                self._prepared_network_receipt_issuances.pop(key, None)
                self._prepared_network_receipt_issuance_generations.pop(root_id, None)
                self._prepared_network_receipt_issuance_receipts.pop(id(record.receipt), None)

    def _bind_prepared_network_durable_capture_for_ack(
        self,
        root: PreparedNetworkTransactionRoot,
        result: LifecyclePreparedNetworkResult,
        capture: object,
        facts: tuple[object, ...],
        *,
        expected_persistent_smb_root_handoff: object | None = None,
        _capture_matches: Callable[[object, object, object, object], bool] = (
            _prepared_network_durable_capture_matches
        ),
        _graph_matches: Callable[[object, object], bool] = (
            _prepared_network_authoritative_graph_matches
        ),
    ) -> None:
        """Bind one exact durable planner handoff into its terminal carrier."""

        if (
            type(root) is not PreparedNetworkTransactionRoot
            or type(result) is not LifecyclePreparedNetworkResult
            or type(facts) is not tuple
            or len(facts) != 10
            or facts[5] is not expected_persistent_smb_root_handoff
        ):
            raise StateError("Prepared-network durable capture binding is malformed")
        root_id = id(root)
        with self._prepared_network_receipt_issuance_lock:
            generation = self._prepared_network_receipt_issuance_generations.get(root_id)
            key = None if generation is None else (root_id, generation)
            record = None if key is None else self._prepared_network_receipt_issuances.get(key)
            if (
                type(record) is not _PreparedNetworkReceiptIssuance
                or record.root is not root
                or record.result is not result
                or record.generation != generation
                or not record.canonical_committed
                or not record.terminal
                or record.claim_ref is not None
                or self._prepared_network_receipt_issuance_receipts.get(id(record.receipt)) != key
                or type(record.root_graph) is not tuple
                or type(record.result_graph) is not tuple
                or type(record.receipt_graph) is not tuple
                or not _graph_matches(root, record.root_graph)
                or not _graph_matches(result, record.result_graph)
                or not _graph_matches(record.receipt, record.receipt_graph)
                or not _capture_matches(root, record.receipt, capture, facts)
            ):
                raise StateError("Prepared-network durable capture binding is not canonical")
            if record.durable_capture is None and record.durable_capture_facts is None:
                record.durable_capture = capture
                record.durable_capture_facts = facts
            elif record.durable_capture is not capture or record.durable_capture_facts is not facts:
                raise StateError("Prepared-network durable capture binding changed")

    def acknowledge_prepared_network_transaction(
        self,
        root: PreparedNetworkTransactionRoot,
        result: LifecyclePreparedNetworkResult,
        *,
        durable_capture: object | None = None,
        durable_capture_facts: tuple[object, ...] | None = None,
    ) -> None:
        """Acknowledge exact result delivery and release its strong retry carrier."""

        if not self.acknowledge_prepared_network_transaction_if_retained(
            root,
            result,
            durable_capture=durable_capture,
            durable_capture_facts=durable_capture_facts,
        ):
            raise StateError("Prepared-network issuance carrier is not retained")

    def acknowledge_prepared_network_transaction_if_retained(
        self,
        root: PreparedNetworkTransactionRoot,
        result: LifecyclePreparedNetworkResult,
        *,
        durable_capture: object | None = None,
        durable_capture_facts: tuple[object, ...] | None = None,
        _result_descriptors: tuple[MemberDescriptorType, ...] = (
            _PREPARED_NETWORK_RESULT_DESCRIPTORS
        ),
        _receipt_descriptors: tuple[MemberDescriptorType, ...] = (
            _PREPARED_NETWORK_RECEIPT_DESCRIPTORS
        ),
        _authority_descriptors: tuple[MemberDescriptorType, ...] = (
            _PREPARED_NETWORK_RECEIPT_AUTHORITY_DESCRIPTORS
        ),
        _member_get: Callable[[object, object, object], object] = MemberDescriptorType.__get__,
        _object_getattribute: Callable[[object, str], object] = object.__getattribute__,
        _object_new: Callable[[type[object]], object] = object.__new__,
        _weak_ref: Callable[..., ReferenceType[object]] = ref,
        _graph_matches: Callable[[object, object], bool] = (
            _prepared_network_authoritative_graph_matches
        ),
        _capture_matches: Callable[[object, object, object, object], bool] = (
            _prepared_network_durable_capture_matches
        ),
    ) -> bool:
        """Authenticate and generation-CAS release one exact terminal carrier."""

        if (
            type(root) is not PreparedNetworkTransactionRoot
            or type(result) is not LifecyclePreparedNetworkResult
        ):
            raise StateError("Prepared-network acknowledgement is malformed")
        planner = _object_getattribute(self, "_source_timing_planner")
        if planner is None:
            raise StateError("Prepared-network acknowledgement lost its timing authority")
        authority_lock = _object_getattribute(planner, "_preparation_authority_lock")
        timing_authorities = _object_getattribute(
            planner,
            "_committed_preparation_receipts",
        )
        receipt_authorities = _object_getattribute(
            self,
            "_prepared_network_receipt_authorities",
        )
        issuance_lock = _object_getattribute(
            self,
            "_prepared_network_receipt_issuance_lock",
        )
        issuances = _object_getattribute(self, "_prepared_network_receipt_issuances")
        generations = _object_getattribute(
            self,
            "_prepared_network_receipt_issuance_generations",
        )
        receipts = _object_getattribute(
            self,
            "_prepared_network_receipt_issuance_receipts",
        )
        root_id = id(root)
        with issuance_lock:
            generation = generations.get(root_id)
            if generation is None:
                return False
            key = (root_id, generation)
            record = issuances.get(key)
            if (
                type(record) is not _PreparedNetworkReceiptIssuance
                or record.root is not root
                or record.generation != generation
                or not record.terminal
                or record.result is not result
                or generations.get(root_id) != generation
                or receipts.get(id(record.receipt)) != key
            ):
                raise StateError("Prepared-network acknowledgement is not canonical")
            retained_claim = None if record.claim_ref is None else record.claim_ref()
            if retained_claim is not None:
                raise StateError("Prepared-network acknowledgement is not canonical")
            claim = cast(
                _PreparedNetworkReceiptIssuanceClaim,
                _object_new(_PreparedNetworkReceiptIssuanceClaim),
            )
            record.claim_ref = _weak_ref(claim)
            receipt = record.receipt
            authority_record = record.authority_record
            authority_generation = record.authority_generation
            issuance_values = record.issuance_values
            expected_result_values = record.result_values
            expected_receipt_values = record.receipt_values
            expected_detached_values = record.detached_values
            expected_detached_proof = record.detached_proof
            root_graph = record.root_graph
            result_graph = record.result_graph
            receipt_graph = record.receipt_graph
            retained_durable_capture = record.durable_capture
            retained_durable_capture_facts = record.durable_capture_facts

        def durable_capture_matches() -> bool:
            if retained_durable_capture is not None or retained_durable_capture_facts is not None:
                if (
                    retained_durable_capture is None
                    or type(retained_durable_capture_facts) is not tuple
                    or (
                        durable_capture is not None
                        and durable_capture is not retained_durable_capture
                    )
                    or (
                        durable_capture_facts is not None
                        and durable_capture_facts is not retained_durable_capture_facts
                    )
                ):
                    return False
                return _capture_matches(
                    root,
                    receipt,
                    retained_durable_capture,
                    retained_durable_capture_facts,
                )
            if durable_capture is None and durable_capture_facts is None:
                return True
            return _capture_matches(
                root,
                receipt,
                durable_capture,
                durable_capture_facts,
            )

        def release_claim() -> None:
            with issuance_lock:
                retained = issuances.get(key)
                if (
                    retained is record
                    and type(retained.claim_ref) is ReferenceType
                    and retained.claim_ref() is claim
                ):
                    retained.claim_ref = None

        try:
            if (
                type(receipt) is not LifecyclePreparedNetworkReceipt
                or type(authority_record) is not _PreparedNetworkReceiptAuthority
                or type(authority_generation) is not int
                or authority_generation <= 0
                or type(issuance_values) is not tuple
                or len(issuance_values) != 11
                or type(expected_result_values) is not tuple
                or len(expected_result_values) != len(_result_descriptors)
                or type(expected_receipt_values) is not tuple
                or len(expected_receipt_values) != len(_receipt_descriptors)
                or type(expected_detached_values) is not tuple
                or type(expected_detached_proof) is not str
                or not expected_detached_proof
                or type(root_graph) is not tuple
                or type(result_graph) is not tuple
                or type(receipt_graph) is not tuple
                or expected_result_values[3] is not receipt
                or issuance_values[10] is not expected_result_values[2]
                or not _graph_matches(root, root_graph)
                or not _graph_matches(result, result_graph)
                or not _graph_matches(receipt, receipt_graph)
                or not durable_capture_matches()
            ):
                raise StateError("Prepared-network acknowledgement is not canonical")

            actual_result_values = tuple(
                _member_get(
                    descriptor,
                    result,
                    LifecyclePreparedNetworkResult,
                )
                for descriptor in _result_descriptors
            )
            if any(
                supplied is not expected
                for supplied, expected in zip(
                    actual_result_values,
                    expected_result_values,
                    strict=True,
                )
            ):
                raise StateError("Prepared-network acknowledgement is not canonical")

            actual_receipt_values = tuple(
                _member_get(
                    descriptor,
                    receipt,
                    LifecyclePreparedNetworkReceipt,
                )
                for descriptor in _receipt_descriptors
            )
            identity_fields = (3, 5, 7, 8, 9, 10)
            for index, (supplied, expected) in enumerate(
                zip(actual_receipt_values, expected_receipt_values, strict=True)
            ):
                if index in identity_fields:
                    if supplied is not expected:
                        raise StateError("Prepared-network acknowledgement is not canonical")
                elif type(supplied) is not str or type(expected) is not str or supplied != expected:
                    raise StateError("Prepared-network acknowledgement is not canonical")

            with authority_lock:
                retained_authority = receipt_authorities.get(id(receipt))
                if (
                    retained_authority is not authority_record
                    or type(retained_authority) is not _PreparedNetworkReceiptAuthority
                ):
                    raise StateError("Prepared-network acknowledgement is not canonical")
                authority_values = tuple(
                    _member_get(
                        descriptor,
                        retained_authority,
                        _PreparedNetworkReceiptAuthority,
                    )
                    for descriptor in _authority_descriptors
                )
                (
                    retained_receipt_ref,
                    timing_authority,
                    timing_receipt_id,
                    retained_generation,
                    detached_values,
                    detached_proof,
                    committed,
                    retained_receipt_graph,
                ) = authority_values
                timing_receipt = issuance_values[10]
                if (
                    type(retained_receipt_ref) is not ReferenceType
                    or retained_receipt_ref() is not receipt
                    or retained_generation != authority_generation
                    or timing_receipt_id != id(timing_receipt)
                    or timing_authorities.get(timing_receipt_id) is not timing_authority
                    or timing_authority is None
                    or _object_getattribute(timing_authority, "receipt_ref")() is not timing_receipt
                    or _object_getattribute(timing_authority, "committed") is not True
                    or detached_values is not expected_detached_values
                    or detached_proof != expected_detached_proof
                    or committed is not True
                    or retained_receipt_graph is not receipt_graph
                ):
                    raise StateError("Prepared-network acknowledgement is not canonical")

                with issuance_lock:
                    retained = issuances.get(key)
                    if (
                        retained is not record
                        or retained.root is not root
                        or retained.generation != generation
                        or retained.receipt is not receipt
                        or retained.result is not result
                        or retained.authority_record is not retained_authority
                        or retained.authority_generation != authority_generation
                        or retained.issuance_values is not issuance_values
                        or retained.result_values is not expected_result_values
                        or retained.receipt_values is not expected_receipt_values
                        or retained.detached_values is not expected_detached_values
                        or retained.detached_proof != expected_detached_proof
                        or retained.root_graph is not root_graph
                        or retained.result_graph is not result_graph
                        or retained.receipt_graph is not receipt_graph
                        or retained.durable_capture is not retained_durable_capture
                        or retained.durable_capture_facts is not retained_durable_capture_facts
                        or not retained.canonical_committed
                        or not retained.terminal
                        or type(retained.claim_ref) is not ReferenceType
                        or retained.claim_ref() is not claim
                        or generations.get(root_id) != generation
                        or receipts.get(id(receipt)) != key
                    ):
                        raise StateError("Prepared-network acknowledgement is not canonical")
                    if (
                        not _graph_matches(root, root_graph)
                        or not _graph_matches(result, result_graph)
                        or not _graph_matches(receipt, receipt_graph)
                        or not durable_capture_matches()
                    ):
                        raise StateError("Prepared-network acknowledgement is not canonical")
                    for descriptor, expected in zip(
                        _result_descriptors,
                        expected_result_values,
                        strict=True,
                    ):
                        if (
                            _member_get(
                                descriptor,
                                result,
                                LifecyclePreparedNetworkResult,
                            )
                            is not expected
                        ):
                            raise StateError("Prepared-network acknowledgement is not canonical")
                    for index, (descriptor, expected) in enumerate(
                        zip(
                            _receipt_descriptors,
                            expected_receipt_values,
                            strict=True,
                        )
                    ):
                        supplied = _member_get(
                            descriptor,
                            receipt,
                            LifecyclePreparedNetworkReceipt,
                        )
                        if index in identity_fields:
                            exact = supplied is expected
                        else:
                            exact = (
                                type(supplied) is str
                                and type(expected) is str
                                and supplied == expected
                            )
                        if not exact:
                            raise StateError("Prepared-network acknowledgement is not canonical")
                    retained.claim_ref = None
                    removed_record = issuances.pop(key, None)
                    if removed_record is not record:
                        raise AssertionError(
                            "Prepared-network issuance changed during acknowledgement CAS"
                        )
                    if generations.pop(root_id, None) != generation:
                        raise AssertionError(
                            "Prepared-network issuance generation changed during CAS"
                        )
                    if receipts.pop(id(receipt), None) != key:
                        raise AssertionError(
                            "Prepared-network receipt generation changed during CAS"
                        )
            _ = removed_record
            return True
        except BaseException as error:
            release_claim()
            if type(error) is StateError:
                raise
            raise StateError("Prepared-network acknowledgement is not canonical") from error

    def _reserve_prepared_network_receipt_authority(
        self,
        receipt: LifecyclePreparedNetworkReceipt,
        timing_receipt: SourceTimingPreparationReceipt,
        authority_record: _PreparedNetworkReceiptAuthority,
        *,
        _authority_descriptors: tuple[MemberDescriptorType, ...] = (
            _PREPARED_NETWORK_RECEIPT_AUTHORITY_DESCRIPTORS
        ),
        _member_get: Callable[[object, object, object], object] = MemberDescriptorType.__get__,
        _member_set: Callable[[object, object, object], None] = MemberDescriptorType.__set__,
        _object_getattribute: Callable[[object, str], object] = object.__getattribute__,
        _weak_ref: Callable[..., ReferenceType[object]] = ref,
    ) -> int:
        """Install one preallocated weak sidecar using only primitive locked writes."""

        planner = _object_getattribute(self, "_source_timing_planner")
        if (
            planner is None
            or type(receipt) is not LifecyclePreparedNetworkReceipt
            or type(timing_receipt) is not SourceTimingPreparationReceipt
            or type(authority_record) is not _PreparedNetworkReceiptAuthority
        ):
            raise StateError("Prepared-network receipt authority reservation is malformed")
        for descriptor in _authority_descriptors:
            try:
                _member_get(descriptor, authority_record, _PreparedNetworkReceiptAuthority)
            except AttributeError:
                continue
            raise StateError("Prepared-network receipt authority shell is already initialized")
        authority_lock = _object_getattribute(planner, "_preparation_authority_lock")
        timing_authorities = _object_getattribute(
            planner,
            "_committed_preparation_receipts",
        )
        capacity = _object_getattribute(planner, "_preparation_authority_capacity")
        receipt_id = id(receipt)
        timing_receipt_id = id(timing_receipt)
        owner_ref = _weak_ref(self)
        with authority_lock:
            timing_authority = timing_authorities.get(timing_receipt_id)
            if (
                timing_authority is None
                or _object_getattribute(timing_authority, "receipt_ref")() is not timing_receipt
            ):
                raise StateError("Prepared-network timing receipt authority is not active")
            if len(self._prepared_network_receipt_authorities) >= capacity:
                raise StateError("Prepared-network receipt authority capacity is exhausted")
            if receipt_id in self._prepared_network_receipt_authorities:
                raise StateError("Prepared-network receipt identity is already retained")
            self._prepared_network_receipt_generation += 1
            generation = self._prepared_network_receipt_generation

        def remove_collected(
            receipt_ref: ReferenceType[LifecyclePreparedNetworkReceipt],
        ) -> None:
            owner = owner_ref()
            if owner is None:
                return
            retained_planner = _object_getattribute(owner, "_source_timing_planner")
            if retained_planner is None:
                return
            retained_lock = _object_getattribute(
                retained_planner,
                "_preparation_authority_lock",
            )
            removed: _PreparedNetworkReceiptAuthority | None = None
            retained: _PreparedNetworkReceiptAuthority | None = None
            with retained_lock:
                authorities = _object_getattribute(
                    owner,
                    "_prepared_network_receipt_authorities",
                )
                retained = authorities.get(receipt_id)
                if retained is authority_record:
                    retained_generation = _member_get(
                        _authority_descriptors[3],
                        retained,
                        _PreparedNetworkReceiptAuthority,
                    )
                    retained_receipt_ref = _member_get(
                        _authority_descriptors[0],
                        retained,
                        _PreparedNetworkReceiptAuthority,
                    )
                    if retained_generation == generation and retained_receipt_ref is receipt_ref:
                        removed = authorities.pop(receipt_id, None)
            # Keep the removed record alive until the authority lock is released.
            _ = retained, removed

        receipt_ref = _weak_ref(receipt, remove_collected)
        authority_values = (
            receipt_ref,
            timing_authority,
            timing_receipt_id,
            generation,
            None,
            "",
            False,
            None,
        )
        for descriptor, value in zip(
            _authority_descriptors,
            authority_values,
            strict=True,
        ):
            _member_set(descriptor, authority_record, value)

        with authority_lock:
            retained_timing_authority = timing_authorities.get(timing_receipt_id)
            if (
                retained_timing_authority is not timing_authority
                or _object_getattribute(timing_authority, "receipt_ref")() is not timing_receipt
                or len(self._prepared_network_receipt_authorities) >= capacity
                or receipt_id in self._prepared_network_receipt_authorities
            ):
                raise StateError("Prepared-network receipt authority reservation changed")
            self._prepared_network_receipt_authorities[receipt_id] = authority_record
        return generation

    def _discard_prepared_network_receipt_authority(
        self,
        receipt: LifecyclePreparedNetworkReceipt,
        generation: int,
        *,
        _authority_descriptors: tuple[MemberDescriptorType, ...] = (
            _PREPARED_NETWORK_RECEIPT_AUTHORITY_DESCRIPTORS
        ),
        _member_get: Callable[[object, object, object], object] = MemberDescriptorType.__get__,
    ) -> None:
        """Discard one unpublished receipt reservation after a reversible abort."""

        planner = self._source_timing_planner
        if planner is None:
            return
        authority_lock = object.__getattribute__(planner, "_preparation_authority_lock")
        receipt_id = id(receipt)
        retained: _PreparedNetworkReceiptAuthority | None = None
        removed: _PreparedNetworkReceiptAuthority | None = None
        with authority_lock:
            retained = self._prepared_network_receipt_authorities.get(receipt_id)
            if (
                retained is not None
                and _member_get(
                    _authority_descriptors[3],
                    retained,
                    _PreparedNetworkReceiptAuthority,
                )
                == generation
                and _member_get(
                    _authority_descriptors[6],
                    retained,
                    _PreparedNetworkReceiptAuthority,
                )
                is False
                and _member_get(
                    _authority_descriptors[0],
                    retained,
                    _PreparedNetworkReceiptAuthority,
                )()
                is receipt
            ):
                removed = self._prepared_network_receipt_authorities.pop(receipt_id, None)
        # Keep the removed record alive until the authority lock is released.
        _ = retained, removed

    def _commit_prepared_network_receipt_authority(
        self,
        receipt: LifecyclePreparedNetworkReceipt,
        timing_receipt: SourceTimingPreparationReceipt,
        generation: int,
        detached_values: tuple[object, ...],
        detached_proof: str,
        receipt_graph: _PreparedNetworkGraphSnapshot,
        *,
        _authority_descriptors: tuple[MemberDescriptorType, ...] = (
            _PREPARED_NETWORK_RECEIPT_AUTHORITY_DESCRIPTORS
        ),
        _member_get: Callable[[object, object, object], object] = MemberDescriptorType.__get__,
        _member_set: Callable[[object, object, object], None] = MemberDescriptorType.__set__,
    ) -> None:
        """Atomically seal issuance facts into one preallocated exact-object record."""

        planner = self._source_timing_planner
        if (
            planner is None
            or type(receipt) is not LifecyclePreparedNetworkReceipt
            or type(timing_receipt) is not SourceTimingPreparationReceipt
            or type(generation) is not int
            or type(detached_values) is not tuple
            or type(detached_proof) is not str
            or type(receipt_graph) is not tuple
            or not receipt_graph
        ):
            raise AssertionError("Prepared-network receipt authority lost its timing planner")
        authority_lock = object.__getattribute__(planner, "_preparation_authority_lock")
        timing_authorities = object.__getattribute__(
            planner,
            "_committed_preparation_receipts",
        )
        issuance_lock = object.__getattribute__(
            self,
            "_prepared_network_receipt_issuance_lock",
        )
        issuance_records = object.__getattribute__(
            self,
            "_prepared_network_receipt_issuances",
        )
        issuance_receipts = object.__getattribute__(
            self,
            "_prepared_network_receipt_issuance_receipts",
        )
        issuance_generations = object.__getattribute__(
            self,
            "_prepared_network_receipt_issuance_generations",
        )
        receipt_id = id(receipt)
        with authority_lock:
            retained = self._prepared_network_receipt_authorities.get(receipt_id)
            timing_authority = timing_authorities.get(id(timing_receipt))
            with issuance_lock:
                issuance_key = issuance_receipts.get(receipt_id)
                issuance = None if issuance_key is None else issuance_records.get(issuance_key)
                expected_issuance_values = None if issuance is None else issuance.issuance_values
                expected_detached_values = None if issuance is None else issuance.detached_values
                exact_detached_values = (
                    type(issuance) is _PreparedNetworkReceiptIssuance
                    and issuance.receipt is receipt
                    and type(issuance_key) is tuple
                    and len(issuance_key) == 2
                    and issuance_key[0] == id(issuance.root)
                    and issuance_key[1] == issuance.generation
                    and issuance_generations.get(issuance_key[0]) == issuance.generation
                    and issuance.authority_generation == generation
                    and type(issuance.claim_ref) is ReferenceType
                    and issuance.claim_ref() is not None
                    and type(expected_issuance_values) is tuple
                    and len(expected_issuance_values) == 11
                    and expected_issuance_values[10] is timing_receipt
                    and type(issuance.receipt_values) is tuple
                    and type(issuance.result_values) is tuple
                    and type(expected_detached_values) is tuple
                    and type(issuance.detached_proof) is str
                    and issuance.receipt_graph is receipt_graph
                    and len(detached_values) == len(expected_detached_values)
                )
                if exact_detached_values:
                    for supplied, expected in zip(
                        detached_values,
                        expected_detached_values,
                        strict=True,
                    ):
                        if expected is None:
                            if supplied is not None:
                                exact_detached_values = False
                                break
                            continue
                        expected_type = type(expected)
                        if expected_type is not str and expected_type is not int:
                            exact_detached_values = False
                            break
                        if type(supplied) is not expected_type:
                            exact_detached_values = False
                            break
                        if supplied != expected:
                            exact_detached_values = False
                            break
            if (
                retained is None
                or type(issuance) is not _PreparedNetworkReceiptIssuance
                or retained is not issuance.authority_record
                or _member_get(
                    _authority_descriptors[3],
                    retained,
                    _PreparedNetworkReceiptAuthority,
                )
                != generation
                or _member_get(
                    _authority_descriptors[6],
                    retained,
                    _PreparedNetworkReceiptAuthority,
                )
                is not False
                or _member_get(
                    _authority_descriptors[0],
                    retained,
                    _PreparedNetworkReceiptAuthority,
                )()
                is not receipt
                or _member_get(
                    _authority_descriptors[2],
                    retained,
                    _PreparedNetworkReceiptAuthority,
                )
                != id(timing_receipt)
                or _member_get(
                    _authority_descriptors[1],
                    retained,
                    _PreparedNetworkReceiptAuthority,
                )
                is not timing_authority
                or timing_authority is None
                or object.__getattribute__(timing_authority, "committed") is not True
                or object.__getattribute__(timing_authority, "receipt_ref")() is not timing_receipt
                or not exact_detached_values
                or detached_proof != issuance.detached_proof
                or receipt_graph is not issuance.receipt_graph
            ):
                raise AssertionError("Prepared-network receipt authority changed before seal")
            _member_set(
                _authority_descriptors[4],
                retained,
                expected_detached_values,
            )
            _member_set(
                _authority_descriptors[5],
                retained,
                issuance.detached_proof,
            )
            _member_set(_authority_descriptors[7], retained, issuance.receipt_graph)
            _member_set(_authority_descriptors[6], retained, True)

    def _issue_prepared_network_receipt_recoverably(
        self,
        issuance_record: _PreparedNetworkReceiptIssuance,
        *,
        runtime_publication_token: str,
        state_publication_token: str,
        transaction_id: str,
        materialization_mode: ConnectionMaterializationMode,
        lifecycle_mode: NetworkTransportLifecycleMode,
        physical_transport: PhysicalTransportFingerprint,
        result_digest: str,
        timing_binding_token: SourceTimingPreparationToken,
        connection_receipt: LifecycleConnectionCompositeReceipt,
        runtime_receipt: NetworkTransactionPreparationReceipt,
        timing_receipt: SourceTimingPreparationReceipt,
        receipt_shell: LifecyclePreparedNetworkReceipt,
        authority_generation: int,
        commit_prepared_network_receipt_authority: Callable[..., None],
        _receipt_type: type[LifecyclePreparedNetworkReceipt] = LifecyclePreparedNetworkReceipt,
        _receipt_descriptors: tuple[MemberDescriptorType, ...] = (
            _PREPARED_NETWORK_RECEIPT_DESCRIPTORS
        ),
        _member_set: Callable[[object, object, object], None] = MemberDescriptorType.__set__,
        _object_getattribute: Callable[[object, str], object] = object.__getattribute__,
        _dict_get: Callable[[dict[object, object], object], object] = dict.get,
        _integrity_for: Callable[..., str] = LifecyclePreparedNetworkReceipt._integrity_for,
        _datetime_us: Callable[[object, str], int] = _detached_network_binding_datetime_us,
        _sha256: Callable[..., object] = sha256,
        _bytes_fromhex: Callable[[str], bytes] = bytes.fromhex,
        _binding_issue: Callable[..., object] = _DETACHED_NETWORK_BINDING_BOUNDARY_METHODS[1],
    ) -> LifecyclePreparedNetworkReceipt:
        """Finalize one preallocated receipt and its issuance-time detached proof."""

        values = (
            runtime_publication_token,
            state_publication_token,
            transaction_id,
            materialization_mode,
            lifecycle_mode,
            physical_transport,
            result_digest,
            timing_binding_token,
            connection_receipt,
            runtime_receipt,
            timing_receipt,
        )
        if type(issuance_record) is not _PreparedNetworkReceiptIssuance:
            raise AssertionError("Prepared network receipt has no exact issuance authority")
        issuance_lock = _object_getattribute(
            self,
            "_prepared_network_receipt_issuance_lock",
        )
        issuances = _object_getattribute(self, "_prepared_network_receipt_issuances")
        generations = _object_getattribute(
            self,
            "_prepared_network_receipt_issuance_generations",
        )
        expected_values = issuance_record.issuance_values
        exact_values = type(expected_values) is tuple and len(expected_values) == len(values)
        if exact_values:
            identity_fields = {3, 5, 7, 8, 9, 10}
            for index, (supplied, expected) in enumerate(zip(values, expected_values, strict=True)):
                if index in identity_fields:
                    if supplied is not expected:
                        exact_values = False
                        break
                elif type(supplied) is not str or type(expected) is not str or supplied != expected:
                    exact_values = False
                    break
        root_id = id(issuance_record.root)
        with issuance_lock:
            retained = issuances.get((root_id, issuance_record.generation))
            if (
                retained is not issuance_record
                or retained.root is not issuance_record.root
                or retained.receipt is not receipt_shell
                and issuance_record.receipt_values is not None
                or not retained.canonical_committed
                or retained.issuance_values is not expected_values
                or generations.get(root_id) != retained.generation
                or not exact_values
            ):
                raise AssertionError("Prepared-network receipt authority changed before seal")
        authority_namespace = _object_getattribute(self, "__dict__")
        receipt_secret = (
            _dict_get(authority_namespace, "_receipt_secret")
            if type(authority_namespace) is dict
            else None
        )
        if (
            type(receipt_shell) is not _receipt_type
            or type(authority_generation) is not int
            or authority_generation <= 0
            or type(connection_receipt) is not LifecycleConnectionCompositeReceipt
            or type(runtime_receipt) is not NetworkTransactionPreparationReceipt
            or type(timing_receipt) is not SourceTimingPreparationReceipt
            or type(timing_binding_token) is not SourceTimingPreparationToken
            or type(physical_transport) is not PhysicalTransportFingerprint
            or type(receipt_secret) is not bytes
        ):
            raise AssertionError("Prepared network receipt finalization is malformed")
        integrity_token = _integrity_for(
            authority_secret=receipt_secret,
            values=values,
        )

        def exact_digest_token(value: object, field_name: str) -> str:
            if (
                type(value) is not str
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
            ):
                raise AssertionError(f"{field_name} is not an exact committed digest")
            return value

        def sealed_digest(domain: bytes, *tokens: object) -> str:
            digest = _sha256(domain)
            for index, token in enumerate(tokens):
                digest.update(
                    _bytes_fromhex(exact_digest_token(token, f"detached authority token {index}"))
                )
            result = digest.hexdigest()
            return exact_digest_token(result, "detached authority digest")

        transport_id = _object_getattribute(physical_transport, "transport_id")
        conn_id = _object_getattribute(physical_transport, "conn_id")
        zeek_uid = _object_getattribute(physical_transport, "zeek_uid")
        tuple_key = _object_getattribute(physical_transport, "tuple_key")
        started_at = _object_getattribute(physical_transport, "started_at")
        closed_at = _object_getattribute(physical_transport, "closed_at")
        if type(tuple_key) is not tuple or len(tuple_key) != 5:
            raise AssertionError("Prepared network physical tuple is malformed")
        src_ip, src_port, dst_ip, dst_port, protocol = tuple_key
        if materialization_mode is ConnectionMaterializationMode.PHYSICAL:
            detached_materialization_mode = "physical"
        elif materialization_mode is ConnectionMaterializationMode.APPLICATION_CHILD:
            detached_materialization_mode = "application_child"
        else:
            raise AssertionError("Prepared network materialization mode is malformed")
        if type(lifecycle_mode) is not str or lifecycle_mode not in {
            "network",
            "deferred_session",
            "application_child",
        }:
            raise AssertionError("Prepared network lifecycle mode is malformed")
        timing_integrity = _object_getattribute(timing_receipt, "_integrity")
        timing_binding_integrity = _object_getattribute(timing_binding_token, "_integrity")
        runtime_integrity = _object_getattribute(runtime_receipt, "_integrity_token")
        cryptographic_receipt = _object_getattribute(runtime_receipt, "cryptographic_receipt")
        if type(cryptographic_receipt) is not CryptographicMaterialPreparationReceipt:
            raise AssertionError("Prepared network cryptographic receipt is malformed")
        cryptographic_integrity = _object_getattribute(
            cryptographic_receipt,
            "_integrity_token",
        )
        connection_integrity = _object_getattribute(connection_receipt, "_integrity_token")
        detached_values = (
            transaction_id,
            state_publication_token,
            runtime_publication_token,
            detached_materialization_mode,
            lifecycle_mode,
            transport_id,
            conn_id,
            zeek_uid,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol,
            _datetime_us(
                started_at,
                "physical.started_at",
            ),
            (
                None
                if closed_at is None
                else _datetime_us(
                    closed_at,
                    "physical.closed_at",
                )
            ),
            exact_digest_token(result_digest, "prepared network result digest"),
            sealed_digest(
                b"lifecycle-detached-timing-binding-v1\0",
                timing_binding_integrity,
            ),
            sealed_digest(
                b"lifecycle-detached-timing-receipt-v1\0",
                timing_binding_integrity,
                timing_integrity,
            ),
            sealed_digest(
                b"lifecycle-detached-runtime-receipt-v1\0",
                cryptographic_integrity,
                runtime_integrity,
            ),
            sealed_digest(
                b"lifecycle-detached-connection-receipt-v1\0",
                connection_integrity,
            ),
            exact_digest_token(integrity_token, "prepared network receipt integrity"),
        )
        root_id = id(issuance_record.root)
        with issuance_lock:
            retained = issuances.get((root_id, issuance_record.generation))
            if (
                retained is not issuance_record
                or retained.claim_ref is None
                or retained.claim_ref() is None
                or retained.terminal
                or not retained.canonical_committed
                or generations.get(root_id) != retained.generation
            ):
                raise AssertionError("Prepared-network receipt authority changed before signing")
            canonical_detached_values = retained.detached_values
            if canonical_detached_values is None:
                retained.detached_values = detached_values
                canonical_detached_values = detached_values
            else:
                if type(canonical_detached_values) is not tuple or len(
                    canonical_detached_values
                ) != len(detached_values):
                    raise AssertionError("Prepared-network detached facts changed before signing")
                for supplied, expected in zip(
                    detached_values,
                    canonical_detached_values,
                    strict=True,
                ):
                    if type(expected) not in {str, int, type(None)}:
                        raise AssertionError(
                            "Prepared-network detached facts changed before signing"
                        )
                    if type(supplied) is not type(expected) or supplied != expected:
                        raise AssertionError(
                            "Prepared-network detached facts changed before signing"
                        )
                detached_values = canonical_detached_values
        detached_binding = _binding_issue(self, issuance_record, detached_values)
        detached_proof = _object_getattribute(detached_binding, "_integrity_token")
        if type(detached_proof) is not str:
            raise AssertionError("Prepared network detached proof is malformed")
        final_values = (*values, integrity_token)
        for descriptor, value in zip(_receipt_descriptors, final_values, strict=True):
            _member_set(descriptor, receipt_shell, value)
        commit_prepared_network_receipt_authority(
            receipt_shell,
            timing_receipt,
            authority_generation,
            detached_values,
            detached_proof,
        )
        return receipt_shell

    def _validate_deferred_session_publication_precommit(
        self,
        binding: _DeferredSessionPublicationPrecommit,
    ) -> None:
        """Reauthenticate the exact dispatcher carrier at the last reversible fence."""

        from evidenceforge.events.dispatcher import (
            DeferredSessionPublicationPrecommit,
            EventDispatcher,
        )

        dispatcher = binding.dispatcher
        precommit = binding.precommit
        if (
            type(dispatcher) is not EventDispatcher
            or type(precommit) is not DeferredSessionPublicationPrecommit
            or not dispatcher.authenticates_lifecycle_authority_owner(self)
            or not dispatcher.claim_deferred_session_publication_precommit(precommit)
        ):
            raise StateError(
                "Deferred-session exact bridge changed at the canonical precommit fence"
            )

    def _prepare_deferred_session_materialization_shells(
        self,
        root: PreparedNetworkTransactionRoot,
        source_timing_preparation: SourceTimingPreparation,
        prerequisite_proofs: tuple[ConnectionCompositePrerequisiteProof, ...],
        _allocate_network_receipt: Callable[
            [tuple[object, ...] | None],
            LifecyclePreparedNetworkReceipt,
        ] = _allocate_prepared_network_receipt_shell,
    ) -> _DeferredSessionMaterializationShells:
        """Allocate every public result identity before the canonical mutation fence."""

        plan = root.state_plan
        connection_receipt = LifecycleConnectionCompositeReceipt(
            plan.publication_token,
            plan.expected_version,
            plan.expected_version + 1,
            plan.transaction.stable_id,
            plan.physical_transport_fingerprint,
            plan.materializes_connection,
            None,
            None,
            prerequisite_proofs,
            "",
        )
        connection_result = LifecycleConnectionCompositeResult(
            state=cast("ConnectionCompositeMaterializationResult", None),
            lifecycle=None,
            application=None,
            receipt=connection_receipt,
        )
        network_receipt = _allocate_network_receipt(
            (
                root.runtime_token.publication_token,
                plan.publication_token,
                root.transaction.stable_id,
                plan.mode,
                root.runtime_token.lifecycle_mode,
                plan.physical_transport_fingerprint,
                self._prepared_network_result_digest(root.result),
                source_timing_preparation.binding_token,
                connection_receipt,
                cast("NetworkTransactionPreparationReceipt", None),
                cast("SourceTimingPreparationReceipt", None),
                "",
            )
        )
        object.__setattr__(
            network_receipt,
            "_integrity_token",
            self._deferred_session_materialization_receipt_shell_integrity(
                root,
                source_timing_preparation,
                network_receipt,
            ),
        )
        network_result = LifecyclePreparedNetworkResult(
            connection=connection_result,
            runtime=cast("NetworkTransactionPreparationReceipt", None),
            timing=cast("SourceTimingPreparationReceipt", None),
            receipt=network_receipt,
        )
        return _DeferredSessionMaterializationShells(
            connection_receipt=connection_receipt,
            connection_result=connection_result,
            network_receipt=network_receipt,
            network_result=network_result,
        )

    def _deferred_session_materialization_receipt_shell_integrity(
        self,
        root: PreparedNetworkTransactionRoot,
        source_timing_preparation: SourceTimingPreparation,
        receipt: LifecyclePreparedNetworkReceipt,
    ) -> str:
        """Sign one exact provisional result identity before canonical mutation."""

        payload = repr(
            (
                "lifecycle-deferred-session-materialization-shell-v1",
                id(receipt),
                id(receipt._connection_receipt),
                root.runtime_token.publication_token,
                root.state_plan.publication_token,
                root.transaction.stable_id,
                root.state_plan.mode,
                root.runtime_token.lifecycle_mode,
                root.state_plan.physical_transport_fingerprint,
                self._prepared_network_result_digest(root.result),
                id(source_timing_preparation.binding_token),
            )
        ).encode("utf-8")
        return hmac.new(self._receipt_secret, payload, sha256).hexdigest()

    def authenticates_deferred_session_materialization_receipt_shell(
        self,
        root: object,
        source_timing_preparation: object,
        receipt: object,
    ) -> bool:
        """Authenticate one exact blank deferred result identity before commit."""

        if (
            type(root) is not PreparedNetworkTransactionRoot
            or type(source_timing_preparation) is not SourceTimingPreparation
            or type(receipt) is not LifecyclePreparedNetworkReceipt
        ):
            return False
        try:
            connection = receipt._connection_receipt
            plan = root.state_plan
            fingerprint = plan.physical_transport_fingerprint
            if (
                type(connection) is not LifecycleConnectionCompositeReceipt
                or receipt._runtime_publication_token != root.runtime_token.publication_token
                or receipt._state_publication_token != plan.publication_token
                or receipt._transaction_id != root.transaction.stable_id
                or receipt._materialization_mode is not plan.mode
                or receipt._lifecycle_mode != root.runtime_token.lifecycle_mode
                or type(receipt._physical_transport) is not PhysicalTransportFingerprint
                or receipt._physical_transport != fingerprint
                or receipt._result_digest != self._prepared_network_result_digest(root.result)
                or receipt._timing_binding_token is not source_timing_preparation.binding_token
                or receipt._runtime_receipt is not None
                or receipt._timing_receipt is not None
                or type(receipt._integrity_token) is not str
                or len(receipt._integrity_token) != 64
                or connection._state_publication_token != plan.publication_token
                or type(connection._prior_version) is not int
                or connection._prior_version != plan.expected_version
                or type(connection._committed_version) is not int
                or connection._committed_version != plan.expected_version + 1
                or connection._transaction_id != root.transaction.stable_id
                or type(connection._physical_transport) is not PhysicalTransportFingerprint
                or connection._physical_transport != fingerprint
                or type(connection._materializes_connection) is not bool
                or connection._materializes_connection is not plan.materializes_connection
                or connection._lifecycle_receipt is not None
                or connection._application_proof is not None
                or type(connection._prerequisite_proofs) is not tuple
                or connection._prerequisite_proofs
                or connection._integrity_token != ""
            ):
                return False
            expected = self._deferred_session_materialization_receipt_shell_integrity(
                root,
                source_timing_preparation,
                receipt,
            )
            return hmac.compare_digest(receipt._integrity_token, expected)
        except (AttributeError, TypeError, ValueError):
            return False

    def materialize_connection_composite(
        self,
        plan: ConnectionCompositeMaterializationPlan,
        owner_rng: random.Random,
        *,
        lifecycle_token: LifecycleClosedTransportAdmissionToken | None = None,
        application_token: _ApplicationAdmissionToken | None = None,
        prerequisite_receipts: tuple[LifecycleConnectionCompositeReceipt, ...] = (),
        finalize_external_no_fail: Callable[[], None] | None = None,
        _deferred_session_publication_precommit: (
            _DeferredSessionPublicationPrecommit | None
        ) = None,
        _deferred_session_materialization_shells: (
            _DeferredSessionMaterializationShells | None
        ) = None,
        _deferred_session_canonical_progress: _DeferredSessionCanonicalProgress | None = None,
        _publish_external_result_no_fail: (
            Callable[[LifecycleConnectionCompositeResult], None] | None
        ) = None,
    ) -> LifecycleConnectionCompositeResult:
        """Atomically consume and publish State, lifecycle, and application admissions.

        Passing an admission token transfers its one-shot reservation to this
        authority. Every failure path releases still-uncommitted exact capabilities;
        committed prior receipts remain immutable proof inputs and are never consumed.
        ``finalize_external_no_fail`` runs last while every lower authority fence is
        retained and must contain only already-claimed, structurally no-fail commits.
        """

        canonical_committed = False
        try:
            start_members, prerequisite_proofs = self._validate_connection_composite_admissions(
                plan,
                lifecycle_token,
                application_token,
                prerequisite_receipts,
            )
            lifecycle_receipt: LifecycleClosedTransportPublicationReceipt | None = None
            application_result: _ApplicationAdmissionResult | None = None
            application_proof: ApplicationChannelCompositeProof | None = None
            with ExitStack() as stack:
                application_commit = (
                    self._enter_application_admission(stack, application_token)
                    if application_token is not None
                    else None
                )
                with self._state_manager.prepared_connection_composite_materialization(
                    plan,
                    owner_rng,
                ) as state_commit:
                    lifecycle_commit = (
                        stack.enter_context(
                            self._registry.claimed_closed_transport_publication(lifecycle_token)
                        )
                        if lifecycle_token is not None
                        else None
                    )
                    self._validate_connection_composite_admissions(
                        plan,
                        lifecycle_token,
                        application_token,
                        prerequisite_receipts,
                    )
                    hook = self._materialization_precommit_hook
                    if hook is not None:
                        hook()
                    self._state_manager.validate_connection_composite_materialization(
                        plan,
                        owner_rng,
                    )
                    final_start_members, final_prerequisite_proofs = (
                        self._validate_connection_composite_admissions(
                            plan,
                            lifecycle_token,
                            application_token,
                            prerequisite_receipts,
                        )
                    )
                    if (
                        final_start_members != start_members
                        or final_prerequisite_proofs != prerequisite_proofs
                    ):
                        raise StateError(
                            "Connection composite authority inputs changed during precommit"
                        )
                    if _deferred_session_publication_precommit is not None:
                        self._validate_deferred_session_publication_precommit(
                            _deferred_session_publication_precommit
                        )
                    if lifecycle_commit is not None:
                        try:
                            lifecycle_receipt = self._commit_lifecycle_admission_recoverably(
                                lifecycle_commit
                            )
                        finally:
                            if lifecycle_commit.committed:
                                canonical_committed = True
                                if _deferred_session_canonical_progress is not None:
                                    _deferred_session_canonical_progress.lifecycle_committed = True
                    try:
                        state_result = self._commit_state_composite_recoverably(state_commit)
                    finally:
                        if state_commit.committed:
                            canonical_committed = True
                            if _deferred_session_canonical_progress is not None:
                                _deferred_session_canonical_progress.state_committed = True
                    if application_commit is not None:
                        try:
                            application_result = self._commit_application_admission_recoverably(
                                application_commit
                            )
                        finally:
                            if application_commit.committed:
                                canonical_committed = True
                                if _deferred_session_canonical_progress is not None:
                                    _deferred_session_canonical_progress.application_committed = (
                                        True
                                    )
                    application_proof = (
                        self._normalize_application_proof(application_token, application_result)
                        if application_token is not None and application_result is not None
                        else None
                    )
                    if lifecycle_receipt is not None and not (
                        self._registry.authenticates_closed_transport_publication_receipt(
                            lifecycle_receipt,
                            request=lifecycle_receipt.request,
                            start_plan_tokens=self._connection_batch_member_tokens(plan),
                        )
                    ):
                        raise AssertionError(
                            "Lifecycle registry returned an unauthenticated receipt"
                        )
                    if application_proof is not None:
                        if application_proof.current_transport_id != plan.physical_transport_id:
                            raise AssertionError(
                                "Application manager committed another physical transport"
                            )
                        if application_proof.prerequisite_transport_ids != tuple(
                            proof.physical_transport_id for proof in prerequisite_proofs
                        ):
                            raise AssertionError(
                                "Application manager changed prerequisite transport legs"
                            )
                    if finalize_external_no_fail is not None:
                        finalize_external_no_fail()
        except BaseException as primary:
            if not canonical_committed and _deferred_session_publication_precommit is not None:
                try:
                    dispatcher = _deferred_session_publication_precommit.dispatcher
                    dispatcher.release_deferred_session_publication_precommit(
                        _deferred_session_publication_precommit.precommit
                    )
                except BaseException as cleanup_error:
                    primary.add_note(
                        f"Deferred-session precommit cleanup also failed: {cleanup_error!r}"
                    )
            if not canonical_committed:
                try:
                    self._discard_connection_composite_admissions(
                        lifecycle_token,
                        application_token,
                    )
                except BaseException as cleanup_error:
                    primary.add_note(
                        f"Connection-composite admission cleanup also failed: {cleanup_error!r}"
                    )
            raise

        issued_receipt = self._issue_connection_composite_receipt_recoverably(
            state_publication_token=plan.publication_token,
            prior_version=plan.expected_version,
            committed_version=plan.expected_version + 1,
            transaction_id=plan.transaction.stable_id,
            physical_transport=plan.physical_transport_fingerprint,
            materializes_connection=plan.materializes_connection,
            lifecycle_receipt=lifecycle_receipt,
            application_proof=application_proof,
            prerequisite_proofs=prerequisite_proofs,
        )
        if _deferred_session_materialization_shells is None:
            result = LifecycleConnectionCompositeResult(
                state=state_result,
                lifecycle=lifecycle_receipt,
                application=application_result,
                receipt=issued_receipt,
            )
        else:
            receipt = _deferred_session_materialization_shells.connection_receipt
            for field_name in (
                "_state_publication_token",
                "_prior_version",
                "_committed_version",
                "_transaction_id",
                "_physical_transport",
                "_materializes_connection",
                "_lifecycle_receipt",
                "_application_proof",
                "_prerequisite_proofs",
                "_integrity_token",
            ):
                object.__setattr__(receipt, field_name, getattr(issued_receipt, field_name))
            result = _deferred_session_materialization_shells.connection_result
            object.__setattr__(result, "state", state_result)
            object.__setattr__(result, "lifecycle", lifecycle_receipt)
            object.__setattr__(result, "application", application_result)
        if _publish_external_result_no_fail is not None:
            _publish_external_result_no_fail(result)
        return result

    @staticmethod
    def _prepared_network_result_digest(result: NetworkConnectionCommitResult) -> str:
        """Return the exact immutable commit-result digest bound into the outer receipt."""

        if type(result) is not NetworkConnectionCommitResult:
            raise StateError("Prepared network root has no exact commit result")
        return sha256(repr(("prepared-network-result-v1", result)).encode()).hexdigest()

    _construct_detached_network_receipt_binding = _DETACHED_NETWORK_BINDING_BOUNDARY_METHODS[0]
    authenticates_detached_network_receipt_binding = _DETACHED_NETWORK_BINDING_BOUNDARY_METHODS[2]

    def _authenticates_issued_prepared_network_receipt(
        self,
        receipt: object,
        *,
        _authority_descriptors: tuple[MemberDescriptorType, ...] = (
            _PREPARED_NETWORK_RECEIPT_AUTHORITY_DESCRIPTORS
        ),
        _member_get: Callable[[object, object, object], object] = MemberDescriptorType.__get__,
        _object_getattribute: Callable[[object, str], object] = object.__getattribute__,
        _graph_matches: Callable[[object, object], bool] = (
            _prepared_network_authoritative_graph_matches
        ),
        _lock_type: type[object] = type(RLock()),
    ) -> bool:
        """Authenticate one exact issued identity against its weak sealed sidecar."""

        if type(receipt) is not LifecyclePreparedNetworkReceipt:
            return False
        try:
            planner = _object_getattribute(self, "_source_timing_planner")
            receipt_authorities = _object_getattribute(
                self,
                "_prepared_network_receipt_authorities",
            )
            if planner is None or type(receipt_authorities) is not dict:
                return False
            authority_lock = _object_getattribute(planner, "_preparation_authority_lock")
            if type(authority_lock) is not _lock_type:
                return False
            timing_authorities = _object_getattribute(
                planner,
                "_committed_preparation_receipts",
            )
            if type(timing_authorities) is not dict:
                return False
            with authority_lock:
                retained = receipt_authorities.get(id(receipt))
                if type(retained) is not _PreparedNetworkReceiptAuthority:
                    return False
                values = tuple(
                    _member_get(
                        descriptor,
                        retained,
                        _PreparedNetworkReceiptAuthority,
                    )
                    for descriptor in _authority_descriptors
                )
                if len(values) != 8:
                    return False
                (
                    receipt_ref,
                    timing_authority,
                    timing_receipt_id,
                    generation,
                    detached_values,
                    detached_proof,
                    committed,
                    receipt_graph,
                ) = values
                receipt_graph_root = (
                    receipt_graph[0] if type(receipt_graph) is tuple and receipt_graph else None
                )
                if type(receipt_graph_root) is not tuple or len(receipt_graph_root) != 3:
                    return False
                retained_root, retained_root_type, retained_root_fields = receipt_graph_root
                if (
                    retained_root is not None
                    or retained_root_type is not LifecyclePreparedNetworkReceipt
                    or type(retained_root_fields) is not tuple
                    or len(retained_root_fields) != len(_PREPARED_NETWORK_RECEIPT_FIELD_NAMES)
                ):
                    return False
                timing_receipt_field = retained_root_fields[10]
                if (
                    type(timing_receipt_field) is not tuple
                    or len(timing_receipt_field) != 2
                    or timing_receipt_field[0] != "_timing_receipt"
                    or type(timing_receipt_field[1]) is not SourceTimingPreparationReceipt
                ):
                    return False
                expected_timing_receipt = timing_receipt_field[1]
                if (
                    type(receipt_ref) is not ReferenceType
                    or receipt_ref() is not receipt
                    or type(timing_receipt_id) is not int
                    or timing_receipt_id <= 0
                    or type(generation) is not int
                    or generation <= 0
                    or type(detached_values) is not tuple
                    or type(detached_proof) is not str
                    or not detached_proof
                    or committed is not True
                    or type(receipt_graph) is not tuple
                    or not receipt_graph
                    or timing_authorities.get(timing_receipt_id) is not timing_authority
                    or timing_authority is None
                    or _object_getattribute(timing_authority, "committed") is not True
                    or _object_getattribute(timing_authority, "receipt_ref")()
                    is not expected_timing_receipt
                ):
                    return False
            return _graph_matches(receipt, receipt_graph)
        except (AttributeError, LookupError, TypeError, ValueError):
            return False

    def _validate_prepared_network_transaction(
        self,
        root: PreparedNetworkTransactionRoot,
        source_timing_preparation: SourceTimingPreparation,
        lifecycle_token: LifecycleClosedTransportAdmissionToken | None,
        application_token: _ApplicationAdmissionToken | None,
        prerequisite_receipts: tuple[LifecyclePreparedNetworkReceipt, ...],
        *,
        allow_deferred_session: bool = False,
    ) -> tuple[LifecycleConnectionCompositeReceipt, ...]:
        """Validate every full prepared-network authority input before claiming locks."""

        runtime = self._network_runtime
        planner = self._source_timing_planner
        if runtime is None:
            raise StateError("Lifecycle authority has no bound network runtime")
        if planner is None:
            raise StateError("Lifecycle authority has no bound source timing planner")
        if type(root) is not PreparedNetworkTransactionRoot:
            raise StateError("Prepared network materialization requires an exact root")
        if not runtime.authenticates_preparation_root(root):
            raise StateError("Prepared network root failed runtime authentication")
        if root.runtime_token.lifecycle_mode == "deferred_session" and not allow_deferred_session:
            raise StateError("Deferred-session network roots require their session authority")
        if root.runtime_token.lifecycle_mode not in {
            "network",
            "deferred_session",
            "application_child",
        }:
            raise StateError("Prepared network root has an unsupported lifecycle mode")
        if root.state_plan.mode is ConnectionMaterializationMode.PHYSICAL:
            expected_modes = (
                {"network", "deferred_session"} if allow_deferred_session else {"network"}
            )
            if root.runtime_token.lifecycle_mode not in expected_modes:
                raise StateError("Physical prepared network root has incompatible lifecycle mode")
        elif root.state_plan.mode is ConnectionMaterializationMode.APPLICATION_CHILD:
            if root.runtime_token.lifecycle_mode != "application_child":
                raise StateError(
                    "Application-child prepared root requires application_child lifecycle mode"
                )
        else:
            raise StateError("Prepared network root has no explicit materialization mode")
        if (
            type(source_timing_preparation) is not SourceTimingPreparation
            or source_timing_preparation.owner is not planner
            or not source_timing_preparation.sealed
            or source_timing_preparation.committed
            or source_timing_preparation.receipt is not None
            or not planner.authenticates_preparation(source_timing_preparation)
        ):
            raise StateError(
                "Prepared network source timing capability is not authentic and sealed"
            )
        if type(prerequisite_receipts) is not tuple:
            raise StateError("Prepared network prerequisites require an exact receipt tuple")
        if len({id(receipt) for receipt in prerequisite_receipts}) != len(prerequisite_receipts):
            raise StateError("Prepared network root repeats a prerequisite receipt")
        connection_prerequisites: list[LifecycleConnectionCompositeReceipt] = []
        for receipt in prerequisite_receipts:
            if not self._authenticates_issued_prepared_network_receipt(receipt):
                raise StateError("Prepared network prerequisite receipt is not authentic")
            if not receipt.materializes_connection:
                raise StateError("Prepared network prerequisite must own a physical transport")
            connection_prerequisites.append(receipt.connection_receipt)
        normalized = tuple(connection_prerequisites)
        self._validate_connection_composite_admissions(
            root.state_plan,
            lifecycle_token,
            application_token,
            normalized,
        )
        return normalized

    def _discard_prepared_network_transaction(
        self,
        root: object,
        source_timing_preparation: object,
        lifecycle_token: LifecycleClosedTransportAdmissionToken | None,
        application_token: _ApplicationAdmissionToken | None,
    ) -> None:
        """Best-effort release of every uncommitted transferred root capability."""

        self._discard_connection_composite_admissions(lifecycle_token, application_token)
        runtime = self._network_runtime
        if runtime is not None and type(root) is PreparedNetworkTransactionRoot:
            try:
                runtime.cancel_preparation(root.runtime_token)
            except (AttributeError, StateError, TypeError, ValueError):
                pass
        planner = self._source_timing_planner
        if (
            planner is not None
            and type(source_timing_preparation) is SourceTimingPreparation
            and source_timing_preparation.owner is planner
            and not source_timing_preparation.committed
        ):
            try:
                source_timing_preparation.cancel()
            except StateError:
                pass

    def materialize_prepared_network_transaction(
        self,
        root: PreparedNetworkTransactionRoot,
        owner_rng: random.Random,
        *,
        source_timing_preparation: SourceTimingPreparation,
        lifecycle_token: LifecycleClosedTransportAdmissionToken | None = None,
        application_token: _ApplicationAdmissionToken | None = None,
        prerequisite_receipts: tuple[LifecyclePreparedNetworkReceipt, ...] = (),
    ) -> LifecyclePreparedNetworkResult:
        """Publish one ordinary prepared network root through its owning authorities."""

        return self._materialize_prepared_network_transaction(
            root,
            owner_rng,
            source_timing_preparation=source_timing_preparation,
            lifecycle_token=lifecycle_token,
            application_token=application_token,
            prerequisite_receipts=prerequisite_receipts,
            allow_deferred_session=False,
        )

    def materialize_prepared_deferred_session_transaction(
        self,
        composition: DeferredSessionComposition,
        coordinator: DeferredSessionCompositionCoordinator,
        owner_rng: random.Random,
    ) -> LifecyclePreparedNetworkResult:
        """Atomically publish one coordinator-authenticated deferred session root."""

        if type(coordinator) is not DeferredSessionCompositionCoordinator:
            raise StateError("Deferred session materialization requires its exact coordinator")
        if type(composition) is not DeferredSessionComposition or not coordinator.authenticates(
            composition
        ):
            raise StateError("Deferred session composition failed owner authentication")
        from evidenceforge.events.dispatcher import PreparedDispatchStateIntent

        if (
            getattr(composition.transport_dispatch, "_state_intent", None)
            is PreparedDispatchStateIntent.EXTERNAL_DEFERRED_TRANSPORT
        ):
            raise StateError(
                "Deferred-session exact dispatches require the prepared publication bridge"
            )
        return self._materialize_prepared_network_transaction(
            composition.prepared_root,
            owner_rng,
            source_timing_preparation=composition.source_timing_preparation,
            lifecycle_token=composition.lifecycle_token,
            application_token=composition.application_token,
            prerequisite_receipts=(),
            allow_deferred_session=True,
        )

    def materialize_prepared_deferred_session_publication(
        self,
        composition: DeferredSessionComposition,
        coordinator: DeferredSessionCompositionCoordinator,
        owner_rng: random.Random,
        *,
        dispatcher: object,
        publication_batch: object,
    ) -> DeferredSessionPublishedNetworkResult:
        """Commit and immediately transfer a deferred root into exact source recovery."""

        from evidenceforge.events.dispatcher import (
            EventDispatcher,
            PreparedDeferredSessionPublicationBatch,
        )

        if type(dispatcher) is not EventDispatcher:
            raise StateError("Deferred-session exact bridge requires its exact dispatcher")
        if type(publication_batch) is not PreparedDeferredSessionPublicationBatch:
            raise StateError("Deferred-session exact bridge requires its exact source batch")
        if not dispatcher.authenticates_lifecycle_authority_owner(self):
            raise StateError(
                "Deferred-session dispatcher belongs to a different lifecycle authority"
            )
        precommit_token = dispatcher.prepare_deferred_session_publication_precommit(
            publication_batch,
            composition=composition,
            coordinator=coordinator,
        )
        precommit = _DeferredSessionPublicationPrecommit(
            dispatcher=dispatcher,
            precommit=precommit_token,
        )
        materialization = self._materialize_prepared_network_transaction(
            composition.prepared_root,
            owner_rng,
            source_timing_preparation=composition.source_timing_preparation,
            lifecycle_token=composition.lifecycle_token,
            application_token=composition.application_token,
            prerequisite_receipts=(),
            allow_deferred_session=True,
            deferred_publication_precommit=precommit,
        )
        try:
            publication = dispatcher.publish_prepared_deferred_session_publication_batch(
                publication_batch,
                materialization_receipt=materialization.receipt,
            )
        except BaseException as failure:
            try:
                object.__setattr__(
                    failure,
                    "deferred_session_materialization",
                    materialization,
                )
                failure.add_note(
                    "Deferred-session canonical root committed; retry the retained "
                    "dispatcher publication batch with this materialization receipt"
                )
            except BaseException:
                pass
            raise
        return DeferredSessionPublishedNetworkResult(
            materialization=materialization,
            publication=publication,
        )

    def _materialize_prepared_network_transaction(
        self,
        root: PreparedNetworkTransactionRoot,
        owner_rng: random.Random,
        *,
        source_timing_preparation: SourceTimingPreparation,
        lifecycle_token: LifecycleClosedTransportAdmissionToken | None,
        application_token: _ApplicationAdmissionToken | None,
        prerequisite_receipts: tuple[LifecyclePreparedNetworkReceipt, ...],
        allow_deferred_session: bool,
        deferred_publication_precommit: _DeferredSessionPublicationPrecommit | None = None,
        _allocate_network_receipt: Callable[
            [tuple[object, ...] | None],
            LifecyclePreparedNetworkReceipt,
        ] = _allocate_prepared_network_receipt_shell,
        _allocate_network_result: Callable[
            [tuple[object, ...] | None],
            LifecyclePreparedNetworkResult,
        ] = _allocate_prepared_network_result_shell,
        _receipt_authority_type: type[_PreparedNetworkReceiptAuthority] = (
            _PreparedNetworkReceiptAuthority
        ),
        _result_descriptors: tuple[MemberDescriptorType, ...] = (
            _PREPARED_NETWORK_RESULT_DESCRIPTORS
        ),
        _receipt_descriptors: tuple[MemberDescriptorType, ...] = (
            _PREPARED_NETWORK_RECEIPT_DESCRIPTORS
        ),
        _authority_descriptors: tuple[MemberDescriptorType, ...] = (
            _PREPARED_NETWORK_RECEIPT_AUTHORITY_DESCRIPTORS
        ),
        _trusted_issue_prepared_network_receipt: Callable[..., object] = (
            _issue_prepared_network_receipt_recoverably
        ),
        _member_set: Callable[[object, object, object], None] = MemberDescriptorType.__set__,
        _member_get: Callable[[object, object, object], object] = MemberDescriptorType.__get__,
        _object_new: Callable[[type[object]], object] = object.__new__,
        _object_getattribute: Callable[[object, str], object] = object.__getattribute__,
        _capture_graph: Callable[[object], _PreparedNetworkGraphSnapshot] = (
            _capture_prepared_network_authoritative_graph
        ),
        _graph_matches: Callable[[object, object], bool] = (
            _prepared_network_authoritative_graph_matches
        ),
        _restore_graph: Callable[[object, object], bool] = (
            _restore_prepared_network_authoritative_graph
        ),
    ) -> LifecyclePreparedNetworkResult:
        """Atomically publish a sealed network root through every owning authority.

        Source timing is claimed first, followed by the network runtime, application
        manager, StateManager, and lifecycle registry. The no-fail tail commits in
        lifecycle, State, application, runtime/crypto, then source-timing order.
        Every failure releases all still-uncommitted transferred capabilities.
        """

        issue_prepared_network_receipt = _object_getattribute(
            self,
            "_issue_prepared_network_receipt_recoverably",
        )
        commit_prepared_network_receipt_authority = _object_getattribute(
            self,
            "_commit_prepared_network_receipt_authority",
        )
        prepared_issuance_lock = _object_getattribute(
            self,
            "_prepared_network_receipt_issuance_lock",
        )
        prepared_issuances = _object_getattribute(
            self,
            "_prepared_network_receipt_issuances",
        )
        prepared_issuance_generations = _object_getattribute(
            self,
            "_prepared_network_receipt_issuance_generations",
        )
        prepared_receipt_authorities = _object_getattribute(
            self,
            "_prepared_network_receipt_authorities",
        )
        (
            issuance_record,
            terminal_result,
            issuance_claim,
        ) = self._claim_prepared_network_receipt_issuance(root)
        if terminal_result is not None:
            return terminal_result

        runtime_receipt: NetworkTransactionPreparationReceipt | None = None
        expected_timing_receipt: SourceTimingPreparationReceipt | None = None
        timing_receipt: SourceTimingPreparationReceipt | None = None
        materialization_shells: _DeferredSessionMaterializationShells | None = None
        network_receipt_shell: LifecyclePreparedNetworkReceipt | None = None
        network_result_shell: LifecyclePreparedNetworkResult | None = None
        receipt_authority_shell: _PreparedNetworkReceiptAuthority | None = None
        receipt_authority_generation: int | None = None
        issuance_values: tuple[object, ...] | None = None
        canonical_progress = (
            _DeferredSessionCanonicalProgress()
            if deferred_publication_precommit is not None
            else None
        )
        if issuance_record is not None:
            network_receipt_shell = issuance_record.receipt
            network_result_shell = issuance_record.result
            receipt_authority_shell = issuance_record.authority_record
            receipt_authority_generation = issuance_record.authority_generation
            issuance_values = issuance_record.issuance_values
        else:
            try:
                connection_prerequisites = self._validate_prepared_network_transaction(
                    root,
                    source_timing_preparation,
                    lifecycle_token,
                    application_token,
                    prerequisite_receipts,
                    allow_deferred_session=allow_deferred_session,
                )
                prepared_issuance_prefix = (
                    root.runtime_token.publication_token,
                    root.state_plan.publication_token,
                    root.transaction.stable_id,
                    root.state_plan.mode,
                    root.runtime_token.lifecycle_mode,
                    root.state_plan.physical_transport_fingerprint,
                    self._prepared_network_result_digest(root.result),
                    source_timing_preparation.binding_token,
                )
                root_graph = _capture_graph(root)
                materialization_shells = self._prepare_deferred_session_materialization_shells(
                    root,
                    source_timing_preparation,
                    connection_prerequisites,
                    _allocate_network_receipt=_allocate_network_receipt,
                )
                network_receipt_shell = materialization_shells.network_receipt
                network_result_shell = materialization_shells.network_result
                receipt_authority_shell = cast(
                    _PreparedNetworkReceiptAuthority,
                    _object_new(_receipt_authority_type),
                )
                issuance_claim = _PreparedNetworkReceiptIssuanceClaim()
                issuance_record = self._reserve_prepared_network_receipt_issuance(
                    root,
                    network_receipt_shell,
                    network_result_shell,
                    receipt_authority_shell,
                    issuance_claim,
                    root_graph,
                )
                if deferred_publication_precommit is not None:
                    dispatcher = deferred_publication_precommit.dispatcher
                    dispatcher.bind_deferred_session_materialization_receipt_shell(
                        deferred_publication_precommit.precommit,
                        network_receipt_shell,
                    )
                runtime = self._network_runtime
                planner = self._source_timing_planner
                assert runtime is not None and planner is not None
                with source_timing_preparation.claimed_commit() as timing_commit:
                    expected_timing_receipt = timing_commit.expected_receipt
                    if not planner.authenticates_expected_preparation_receipt(
                        expected_timing_receipt,
                        preparation=timing_commit,
                    ):
                        raise StateError(
                            "Prepared network source timing receipt failed authentication"
                        )
                    prebound_issuance_values = (
                        *prepared_issuance_prefix,
                        materialization_shells.connection_receipt,
                        None,
                        expected_timing_receipt,
                    )
                    prebound_result_values = (
                        materialization_shells.connection_result,
                        None,
                        expected_timing_receipt,
                        network_receipt_shell,
                    )
                    root_id = id(root)
                    with prepared_issuance_lock:
                        retained = prepared_issuances.get((root_id, issuance_record.generation))
                        if (
                            retained is not issuance_record
                            or retained.root is not root
                            or retained.claim_ref is None
                            or retained.claim_ref() is not issuance_claim
                            or retained.terminal
                            or retained.canonical_committed
                            or retained.issuance_values is not None
                            or retained.result_values is not None
                            or prepared_issuance_generations.get(root_id) != retained.generation
                        ):
                            raise AssertionError(
                                "Prepared network issuance carrier changed before commit"
                            )
                        retained.issuance_values = prebound_issuance_values
                        retained.result_values = prebound_result_values
                    receipt_authority_generation = self._reserve_prepared_network_receipt_authority(
                        network_receipt_shell,
                        expected_timing_receipt,
                        receipt_authority_shell,
                    )
                    with runtime.claimed_preparation(root.runtime_token) as runtime_commit:
                        timing_commit.certify_composite_commit(expected_timing_receipt)

                        def _finalize_prepared_network_no_fail() -> None:
                            nonlocal runtime_receipt, timing_receipt
                            try:
                                runtime_receipt = self._commit_runtime_recoverably(runtime_commit)
                            finally:
                                if runtime_commit.committed and canonical_progress is not None:
                                    canonical_progress.runtime_committed = True
                            try:
                                timing_receipt = self._commit_source_timing_recoverably(
                                    timing_commit
                                )
                            finally:
                                if timing_commit.committed and canonical_progress is not None:
                                    canonical_progress.timing_committed = True

                        def _publish_prepared_connection_result_no_fail(
                            supplied_connection_result: LifecycleConnectionCompositeResult,
                        ) -> None:
                            nonlocal issuance_values
                            if (
                                supplied_connection_result
                                is not materialization_shells.connection_result
                                or runtime_receipt is None
                                or timing_receipt is None
                                or timing_receipt is not expected_timing_receipt
                            ):
                                raise AssertionError(
                                    "Prepared network connection result changed before publish"
                                )
                            connection_receipt = _object_getattribute(
                                supplied_connection_result,
                                "receipt",
                            )
                            if connection_receipt is not materialization_shells.connection_receipt:
                                raise AssertionError(
                                    "Prepared network connection receipt identity changed"
                                )
                            issuance_values = (
                                *prepared_issuance_prefix,
                                connection_receipt,
                                runtime_receipt,
                                timing_receipt,
                            )
                            result_values = (
                                supplied_connection_result,
                                runtime_receipt,
                                timing_receipt,
                                network_receipt_shell,
                            )
                            for descriptor, value in zip(
                                _result_descriptors,
                                result_values,
                                strict=True,
                            ):
                                _member_set(descriptor, network_result_shell, value)
                            root_id = id(root)
                            with prepared_issuance_lock:
                                retained = prepared_issuances.get(
                                    (root_id, issuance_record.generation)
                                )
                                if (
                                    retained is not issuance_record
                                    or retained.root is not root
                                    or retained.claim_ref is None
                                    or retained.claim_ref() is not issuance_claim
                                    or retained.terminal
                                    or retained.canonical_committed
                                    or retained.issuance_values is not prebound_issuance_values
                                    or retained.result_values is not prebound_result_values
                                    or prepared_issuance_generations.get(root_id)
                                    != retained.generation
                                ):
                                    raise AssertionError(
                                        "Prepared network issuance carrier changed at commit"
                                    )
                                retained.authority_generation = receipt_authority_generation
                                retained.issuance_values = issuance_values
                                retained.result_values = result_values
                                retained.canonical_committed = True

                        self.materialize_connection_composite(
                            root.state_plan,
                            owner_rng,
                            lifecycle_token=lifecycle_token,
                            application_token=application_token,
                            prerequisite_receipts=connection_prerequisites,
                            finalize_external_no_fail=_finalize_prepared_network_no_fail,
                            _deferred_session_publication_precommit=(
                                deferred_publication_precommit
                            ),
                            _deferred_session_materialization_shells=(materialization_shells),
                            _deferred_session_canonical_progress=canonical_progress,
                            _publish_external_result_no_fail=(
                                _publish_prepared_connection_result_no_fail
                            ),
                        )
            except BaseException:
                carrier_committed = (
                    issuance_record is not None and issuance_record.canonical_committed
                )
                if (
                    not carrier_committed
                    and network_receipt_shell is not None
                    and receipt_authority_generation is not None
                ):
                    self._discard_prepared_network_receipt_authority(
                        network_receipt_shell,
                        receipt_authority_generation,
                    )
                reversible = (
                    not carrier_committed
                    and not source_timing_preparation.committed
                    and not (
                        canonical_progress is not None and canonical_progress.any_owner_committed
                    )
                )
                if reversible:
                    if issuance_record is not None:
                        self._discard_prepared_network_receipt_issuance(root, issuance_record)
                    self._discard_prepared_network_transaction(
                        root,
                        source_timing_preparation,
                        lifecycle_token,
                        application_token,
                    )
                elif issuance_record is not None:
                    with prepared_issuance_lock:
                        issuance_record.claim_ref = None
                raise

            if (
                runtime_receipt is None
                or expected_timing_receipt is None
                or timing_receipt is not expected_timing_receipt
                or network_receipt_shell is None
                or network_result_shell is None
                or receipt_authority_generation is None
                or issuance_record is None
                or not issuance_record.canonical_committed
            ):
                raise AssertionError("Prepared network finalizer returned no complete carrier")
            issuance_values = issuance_record.issuance_values

        if (
            issuance_record is None
            or network_receipt_shell is None
            or network_result_shell is None
            or receipt_authority_generation is None
            or issuance_values is None
            or issuance_claim is None
        ):
            raise AssertionError("Prepared network issuance recovery has no committed facts")
        (
            runtime_publication_token,
            state_publication_token,
            transaction_id,
            materialization_mode,
            lifecycle_mode,
            physical_transport,
            result_digest,
            timing_binding_token,
            connection_receipt,
            runtime_receipt,
            timing_receipt,
        ) = issuance_values

        if issuance_record.receipt_values is None:
            scratch_receipt = _allocate_network_receipt(None)
            expected_detached_values: tuple[object, ...] | None = None
            expected_detached_proof: str | None = None

            def capture_expected_issuance_facts(
                captured_receipt: LifecyclePreparedNetworkReceipt,
                captured_timing_receipt: SourceTimingPreparationReceipt,
                captured_generation: int,
                captured_detached_values: tuple[object, ...],
                captured_detached_proof: str,
            ) -> None:
                nonlocal expected_detached_values, expected_detached_proof
                if (
                    captured_receipt is not scratch_receipt
                    or captured_timing_receipt is not timing_receipt
                    or captured_generation != receipt_authority_generation
                    or type(captured_detached_values) is not tuple
                    or type(captured_detached_proof) is not str
                ):
                    raise AssertionError("Prepared network expected issuance facts changed")
                expected_detached_values = captured_detached_values
                expected_detached_proof = captured_detached_proof

            expected_receipt = _trusted_issue_prepared_network_receipt(
                self,
                issuance_record,
                runtime_publication_token=runtime_publication_token,
                state_publication_token=state_publication_token,
                transaction_id=transaction_id,
                materialization_mode=materialization_mode,
                lifecycle_mode=lifecycle_mode,
                physical_transport=physical_transport,
                result_digest=result_digest,
                timing_binding_token=timing_binding_token,
                connection_receipt=connection_receipt,
                runtime_receipt=runtime_receipt,
                timing_receipt=timing_receipt,
                receipt_shell=scratch_receipt,
                authority_generation=receipt_authority_generation,
                commit_prepared_network_receipt_authority=(capture_expected_issuance_facts),
            )
            if (
                expected_receipt is not scratch_receipt
                or expected_detached_values is None
                or expected_detached_proof is None
            ):
                raise AssertionError("Prepared network expected issuance did not complete")
            expected_receipt_values = tuple(
                _member_get(descriptor, scratch_receipt, LifecyclePreparedNetworkReceipt)
                for descriptor in _receipt_descriptors
            )
            root_id = id(root)
            with prepared_issuance_lock:
                retained = prepared_issuances.get((root_id, issuance_record.generation))
                if (
                    retained is not issuance_record
                    or retained.root is not root
                    or retained.claim_ref is None
                    or retained.claim_ref() is not issuance_claim
                    or retained.terminal
                    or retained.issuance_values is not issuance_values
                    or retained.result_values is None
                    or retained.receipt_values is not None
                    or retained.detached_values is not expected_detached_values
                    or retained.detached_proof
                ):
                    raise AssertionError("Prepared network issuance facts changed before seal")
                retained.receipt_values = expected_receipt_values
                retained.detached_proof = expected_detached_proof

        expected_receipt_values = issuance_record.receipt_values
        expected_result_values = issuance_record.result_values
        expected_detached_values = issuance_record.detached_values
        expected_detached_proof = issuance_record.detached_proof
        if (
            type(expected_receipt_values) is not tuple
            or len(expected_receipt_values) != len(_receipt_descriptors)
            or type(expected_result_values) is not tuple
            or len(expected_result_values) != len(_result_descriptors)
            or type(expected_detached_values) is not tuple
            or type(expected_detached_proof) is not str
            or not expected_detached_proof
        ):
            raise AssertionError("Prepared network issuance carrier facts are malformed")
        planner = _object_getattribute(self, "_source_timing_planner")
        if planner is None:
            raise AssertionError("Prepared network issuance recovery lost its timing planner")

        authority_lock = _object_getattribute(planner, "_preparation_authority_lock")
        receipt_authorities = prepared_receipt_authorities
        timing_receipt_authorities = _object_getattribute(
            planner,
            "_committed_preparation_receipts",
        )

        def exact_detached_facts_match(actual: object) -> bool:
            if type(actual) is not tuple or len(actual) != len(expected_detached_values):
                return False
            for supplied, expected in zip(actual, expected_detached_values, strict=True):
                if expected is None:
                    if supplied is not None:
                        return False
                    continue
                expected_type = type(expected)
                if expected_type is not str and expected_type is not int:
                    return False
                if type(supplied) is not expected_type:
                    return False
                if supplied != expected:
                    return False
            return True

        def exact_receipt_values_match(actual: tuple[object, ...]) -> bool:
            if len(actual) != len(expected_receipt_values):
                return False
            identity_fields = {3, 5, 7, 8, 9, 10}
            for index, (supplied, expected) in enumerate(
                zip(actual, expected_receipt_values, strict=True)
            ):
                if index in identity_fields:
                    if supplied is not expected:
                        return False
                elif type(supplied) is not str or type(expected) is not str or supplied != expected:
                    return False
            return True

        def commit_authoritative_issuance_facts(
            supplied_receipt: LifecyclePreparedNetworkReceipt,
            supplied_timing_receipt: SourceTimingPreparationReceipt,
            supplied_generation: int,
            supplied_detached_values: tuple[object, ...],
            supplied_detached_proof: str,
        ) -> None:
            if (
                supplied_receipt is not network_receipt_shell
                or supplied_timing_receipt is not timing_receipt
                or type(supplied_generation) is not int
                or supplied_generation != receipt_authority_generation
                or not exact_detached_facts_match(supplied_detached_values)
                or type(supplied_detached_proof) is not str
                or supplied_detached_proof != expected_detached_proof
            ):
                raise AssertionError("Prepared-network receipt authority changed before seal")
            captured_receipt_graph = _capture_graph(supplied_receipt)
            captured_result_graph = _capture_graph(network_result_shell)
            root_id = id(root)
            with prepared_issuance_lock:
                retained = prepared_issuances.get((root_id, issuance_record.generation))
                if (
                    retained is not issuance_record
                    or retained.root is not root
                    or retained.receipt is not supplied_receipt
                    or retained.result is not network_result_shell
                    or not retained.canonical_committed
                    or retained.issuance_values is not issuance_values
                    or retained.receipt_values is not expected_receipt_values
                    or retained.detached_values is not expected_detached_values
                    or retained.detached_proof != expected_detached_proof
                    or type(retained.root_graph) is not tuple
                    or not _graph_matches(root, retained.root_graph)
                ):
                    raise AssertionError("Prepared-network retained graph changed before seal")
                if retained.receipt_graph is None and retained.result_graph is None:
                    retained.receipt_graph = captured_receipt_graph
                    retained.result_graph = captured_result_graph
                elif (
                    retained.receipt_graph is None
                    or retained.result_graph is None
                    or not _graph_matches(supplied_receipt, retained.receipt_graph)
                    or not _graph_matches(network_result_shell, retained.result_graph)
                ):
                    raise AssertionError("Prepared-network retained graph changed before seal")
            commit_prepared_network_receipt_authority(
                supplied_receipt,
                supplied_timing_receipt,
                supplied_generation,
                supplied_detached_values,
                supplied_detached_proof,
                issuance_record.receipt_graph,
            )

        def publish_terminal_if_sealed() -> bool:
            receipt_id = id(network_receipt_shell)

            def sealed_sidecar_values() -> tuple[object, ...] | None:
                retained_authority = receipt_authorities.get(receipt_id)
                if (
                    type(retained_authority) is not _PreparedNetworkReceiptAuthority
                    or retained_authority is not receipt_authority_shell
                ):
                    return None
                values = tuple(
                    _member_get(
                        descriptor,
                        retained_authority,
                        _PreparedNetworkReceiptAuthority,
                    )
                    for descriptor in _authority_descriptors
                )
                (
                    retained_receipt_ref,
                    retained_timing_authority,
                    retained_timing_receipt_id,
                    retained_generation,
                    retained_detached_values,
                    retained_detached_proof,
                    retained_committed,
                    retained_receipt_graph,
                ) = values
                if (
                    type(retained_receipt_ref) is not ReferenceType
                    or retained_receipt_ref() is not network_receipt_shell
                    or retained_generation != receipt_authority_generation
                    or retained_timing_receipt_id != id(timing_receipt)
                    or timing_receipt_authorities.get(retained_timing_receipt_id)
                    is not retained_timing_authority
                    or retained_timing_authority is None
                    or _object_getattribute(retained_timing_authority, "committed") is not True
                    or _object_getattribute(retained_timing_authority, "receipt_ref")()
                    is not timing_receipt
                    or retained_committed is not True
                    or not exact_detached_facts_match(retained_detached_values)
                    or retained_detached_values is not expected_detached_values
                    or type(retained_detached_proof) is not str
                    or retained_detached_proof != expected_detached_proof
                    or retained_receipt_graph is not issuance_record.receipt_graph
                ):
                    return None
                return values

            with authority_lock:
                initial_sidecar_values = sealed_sidecar_values()
            if initial_sidecar_values is None:
                return False

            if type(issuance_record.root_graph) is not tuple or not _graph_matches(
                root, issuance_record.root_graph
            ):
                raise StateError("Prepared network root changed before terminal retry")
            if (
                type(issuance_record.result_graph) is not tuple
                or type(issuance_record.receipt_graph) is not tuple
                or not _restore_graph(network_result_shell, issuance_record.result_graph)
                or not _graph_matches(network_receipt_shell, issuance_record.receipt_graph)
            ):
                raise AssertionError("Prepared network terminal graph could not be restored")

            with authority_lock:
                final_sidecar_values = sealed_sidecar_values()
                if final_sidecar_values is None:
                    return False
                if any(
                    final is not initial
                    for final, initial in zip(
                        final_sidecar_values,
                        initial_sidecar_values,
                        strict=True,
                    )
                ):
                    raise AssertionError("Prepared network sidecar changed during restoration")
                root_id = id(root)
                with prepared_issuance_lock:
                    retained_issuance = prepared_issuances.get(
                        (root_id, issuance_record.generation)
                    )
                    if (
                        retained_issuance is not issuance_record
                        or retained_issuance.root is not root
                        or retained_issuance.receipt is not network_receipt_shell
                        or retained_issuance.result is not network_result_shell
                        or retained_issuance.authority_record is not receipt_authority_shell
                        or retained_issuance.authority_generation != receipt_authority_generation
                        or retained_issuance.issuance_values is not issuance_values
                        or retained_issuance.result_values is not expected_result_values
                        or retained_issuance.receipt_values is not expected_receipt_values
                        or retained_issuance.detached_values is not expected_detached_values
                        or retained_issuance.detached_proof != expected_detached_proof
                        or retained_issuance.root_graph is not issuance_record.root_graph
                        or retained_issuance.result_graph is not issuance_record.result_graph
                        or retained_issuance.receipt_graph is not issuance_record.receipt_graph
                        or not retained_issuance.canonical_committed
                        or type(retained_issuance.claim_ref) is not ReferenceType
                        or retained_issuance.claim_ref() is not issuance_claim
                        or prepared_issuance_generations.get(root_id)
                        != retained_issuance.generation
                    ):
                        raise AssertionError(
                            "Prepared network terminal carrier changed before publish"
                        )
                    retained_issuance.terminal = True
                    retained_issuance.claim_ref = None
            return True

        if publish_terminal_if_sealed():
            return network_result_shell
        if type(issuance_record.root_graph) is not tuple or not _graph_matches(
            root, issuance_record.root_graph
        ):
            with prepared_issuance_lock:
                issuance_record.claim_ref = None
            raise StateError("Prepared network root changed before issuance retry")
        if issuance_record.result_graph is not None and not _restore_graph(
            network_result_shell,
            issuance_record.result_graph,
        ):
            with prepared_issuance_lock:
                issuance_record.claim_ref = None
            raise StateError("Prepared network retained graph could not be restored")
        try:
            issued_receipt = issue_prepared_network_receipt(
                issuance_record,
                runtime_publication_token=runtime_publication_token,
                state_publication_token=state_publication_token,
                transaction_id=transaction_id,
                materialization_mode=materialization_mode,
                lifecycle_mode=lifecycle_mode,
                physical_transport=physical_transport,
                result_digest=result_digest,
                timing_binding_token=timing_binding_token,
                connection_receipt=connection_receipt,
                runtime_receipt=runtime_receipt,
                timing_receipt=timing_receipt,
                receipt_shell=network_receipt_shell,
                authority_generation=receipt_authority_generation,
                commit_prepared_network_receipt_authority=(commit_authoritative_issuance_facts),
            )
        except BaseException:
            if not publish_terminal_if_sealed():
                with prepared_issuance_lock:
                    issuance_record.claim_ref = None
            raise
        if issued_receipt is not network_receipt_shell:
            publish_terminal_if_sealed()
            raise AssertionError("Prepared-session receipt shell identity changed")
        if not publish_terminal_if_sealed():
            with prepared_issuance_lock:
                issuance_record.claim_ref = None
            raise AssertionError("Prepared network receipt authority did not seal")
        return network_result_shell

    def authenticates_prepared_network_receipt(
        self,
        root: PreparedNetworkTransactionRoot,
        receipt: object,
    ) -> bool:
        """Authenticate a full committed receipt against its exact prepared root."""

        runtime = self._network_runtime
        if (
            runtime is None
            or type(root) is not PreparedNetworkTransactionRoot
            or type(receipt) is not LifecyclePreparedNetworkReceipt
            or not self._authenticates_issued_prepared_network_receipt(receipt)
        ):
            return False
        try:
            runtime_authentic = runtime.authenticates_preparation_receipt(
                receipt.runtime_receipt,
                token=root.runtime_token,
            )
            connection_authentic = self.authenticates_connection_composite_receipt(
                root.state_plan,
                receipt.connection_receipt,
            )
            if (
                not runtime_authentic
                or not connection_authentic
                or type(root.result) is not NetworkConnectionCommitResult
                or root.result.transaction != root.transaction
                or root.state_plan.transaction != root.transaction
                or root.result.lifecycle_mode != root.runtime_token.lifecycle_mode
                or receipt._runtime_publication_token != root.runtime_token.publication_token
                or receipt._state_publication_token != root.state_plan.publication_token
                or receipt._transaction_id != root.transaction.stable_id
                or receipt._materialization_mode is not root.state_plan.mode
                or receipt._lifecycle_mode != root.runtime_token.lifecycle_mode
                or receipt._physical_transport != root.state_plan.physical_transport_fingerprint
                or receipt._result_digest != self._prepared_network_result_digest(root.result)
            ):
                return False
            return self._authenticates_issued_prepared_network_receipt(receipt)
        except (
            AttributeError,
            LookupError,
            RecursionError,
            RuntimeError,
            StateError,
            TypeError,
            ValueError,
        ):
            return False

    def authenticates_connection_composite_receipt(
        self,
        plan: ConnectionCompositeMaterializationPlan,
        receipt: object,
    ) -> bool:
        """Authenticate one exact committed connection composite against its State plan."""

        if not self._state_manager.authenticates_materialization_plan(plan):
            return False
        if not self._authenticates_issued_connection_receipt(receipt):
            return False
        assert isinstance(receipt, LifecycleConnectionCompositeReceipt)
        if (
            receipt._state_publication_token != plan.publication_token
            or receipt.prior_version != plan.expected_version
            or receipt.committed_version != plan.expected_version + 1
            or receipt.transaction_id != plan.transaction.stable_id
            or receipt._physical_transport != plan.physical_transport_fingerprint
            or receipt.materializes_connection != plan.materializes_connection
        ):
            return False
        lifecycle_receipt = receipt._lifecycle_receipt
        if lifecycle_receipt is not None:
            if lifecycle_receipt.start_plan_tokens != self._connection_batch_member_tokens(plan):
                return False
            try:
                self._validate_connection_holds(plan, lifecycle_receipt.process_holds)
            except StateError:
                return False
        elif plan.materializes_connection or plan.batch is not None:
            return False
        if not plan.materializes_connection:
            try:
                self._validate_existing_lifecycle_transport(plan.physical_transport_fingerprint)
            except StateError:
                return False
        proof = receipt.application_proof
        if proof is None:
            return plan.materializes_connection and not receipt.prerequisite_proofs
        return (
            proof.current_transport_id == plan.physical_transport_id
            and proof.prerequisite_transport_ids
            == tuple(
                prerequisite.physical_transport_id for prerequisite in receipt.prerequisite_proofs
            )
        )

    def enable_fixture_parent_backfill(self) -> None:
        """Allow direct-test StateManager parents to enter authority on first use.

        Production never enables this compatibility boundary. Engine-owned starts
        must register parent-before-child through prepared materialization.
        """

        self._fixture_parent_backfill = True

    @staticmethod
    def _host_hash(hostname: str) -> int:
        digest = sha256(f"generator-lifecycle\0{hostname.casefold()}".encode()).digest()
        return int.from_bytes(digest[:8], "big")

    def _shard_id(self, hostname: str) -> int:
        return self._host_hash(hostname) % self._shard_count

    def _shard(self, hostname: str) -> _AuthorityShard:
        shard_id = self._shard_id(hostname)
        shard = self._shards[shard_id]
        if shard is not None:
            return shard
        with self._shard_allocation_lock:
            shard = self._shards[shard_id]
            if shard is None:
                shard = _AuthorityShard()
                self._shards[shard_id] = shard
            return shard

    def ensure_session(self, hostname: str, logon_id: str) -> SessionLifecycleIdentity:
        """Resolve and publish one exact StateManager session identity."""

        identity = self._state_manager.get_session_identity(logon_id)
        if identity is None or identity.hostname != hostname:
            raise StateError(f"No live session identity for {hostname} LogonID={logon_id}")
        return self._shadow.ensure_session(identity)

    def ensure_process(self, hostname: str, pid: int) -> ProcessLifecycleIdentity:
        """Resolve and publish one exact StateManager process identity and ancestry."""

        identity = self._state_manager.get_process_identity(hostname, pid)
        if identity is None:
            raise StateError(f"No live process identity for {hostname} PID={pid}")
        session = (
            self._state_manager.get_session_identity(identity.logon_id)
            if identity.logon_id
            else None
        )
        return self._shadow.ensure_process(identity, session=session)

    def materialize_session(
        self,
        plan: SessionMaterializationPlan,
        *,
        finalize_external_no_fail: Callable[[], None] | None = None,
    ) -> tuple[ActiveSession, LifecycleMaterializationReceipt]:
        """Atomically publish one planned session and any preclaimed external token.

        The optional callback must be the primitive no-fail commit of an already
        validated and lock-owning external publication. The caller acquires that
        owner before entry, preserving the global artifact -> StateManager ->
        LifecycleRegistry lock order. It runs last while the state and lifecycle
        transaction locks remain held.
        """

        identity = self._shadow.project_session_start(plan.identity)
        request = LifecycleSessionStartRequest(
            identity=identity,
            action_id=stable_uuid(
                "lifecycle-authority-start-action",
                "session",
                identity.object_id,
            ),
            transition_id=stable_uuid(
                "lifecycle-authority-start-transition",
                "session",
                identity.object_id,
            ),
        )
        with self._state_manager.materialization_guard(plan):
            self._state_manager.validate_session_materialization(plan)
            with self._registry.prepare_start_batch(sessions=(request,)) as ticket:
                hook = self._materialization_precommit_hook
                if hook is not None:
                    hook()
                ticket.commit()
                session = self._state_manager._commit_prevalidated_session_materialization(plan)
                if finalize_external_no_fail is not None:
                    finalize_external_no_fail()
        receipt = LifecycleMaterializationReceipt._issue(
            authority_secret=self._receipt_secret,
            kind="session",
            object_id=identity.object_id,
            publication_token=plan.publication_token,
            prior_version=plan.expected_version,
            committed_version=plan.expected_version + 1,
        )
        return session, receipt

    def materialize_batch(
        self,
        plan: MaterializationBatchPlan,
        *,
        finalize_external_no_fail: Callable[[], None] | None = None,
        transaction: LifecycleMaterializationBatchTransaction | None = None,
        external_result: tuple[object, ...] = (),
        planning_capability: LifecycleMaterializationBatchPlanningCapability | None = None,
    ) -> tuple[
        ActiveSession | None,
        tuple[RunningProcess, ...],
        LifecycleMaterializationBatchReceipt,
    ]:
        """Publish or reconcile one claimed all-or-none lifecycle start batch."""

        if type(external_result) is not tuple:
            raise StateError("Materialization-batch external result must be an exact tuple")
        _validate_materialization_batch_external_result(external_result)
        if transaction is not None and finalize_external_no_fail is not None:
            raise StateError(
                "Retry-stable materialization-batch transactions cannot run external callbacks"
            )
        if transaction is None and planning_capability is not None:
            raise StateError(
                "Materialization-batch planning capability requires a retained transaction"
            )
        if transaction is not None:
            self._validate_materialization_batch_transaction(transaction)
            if planning_capability is not None:
                self._validate_materialization_batch_planning_capability(
                    transaction,
                    planning_capability,
                )
            terminal_bytes = self._materialization_batch_terminal_retained_bytes(
                transaction,
                plan,
                external_result,
            )
            with self._materialization_batch_transaction_lock:
                transaction_record = self._materialization_batch_transaction_record_for_locked(
                    transaction
                )
                self._reserve_materialization_batch_transaction_bytes_locked(
                    transaction_record,
                    terminal_bytes,
                )
        if transaction is None:
            if external_result:
                raise StateError(
                    "Materialization-batch external result requires a retained transaction"
                )
            return self._materialize_batch_claimed(
                plan,
                finalize_external_no_fail=finalize_external_no_fail,
                transaction_record=None,
                external_result=external_result,
            )

        record, terminal_result = self._claim_materialization_batch_transaction(
            transaction,
            planning_capability,
        )
        if terminal_result is not None:
            if (
                terminal_result._plan_publication_token != plan.publication_token
                or terminal_result.external_result != external_result
            ):
                raise StateError(
                    "Materialization-batch transaction replay used another exact plan or result"
                )
            session, processes = self._runtime_for_materialization_batch_terminal_result(
                transaction,
                terminal_result,
            )
            return session, processes, terminal_result.receipt
        try:
            return self._materialize_batch_claimed(
                plan,
                finalize_external_no_fail=finalize_external_no_fail,
                transaction_record=record,
                external_result=external_result,
            )
        finally:
            self._release_materialization_batch_transaction_claim(record)

    def _materialize_batch_claimed(
        self,
        plan: MaterializationBatchPlan,
        *,
        finalize_external_no_fail: Callable[[], None] | None,
        transaction_record: _LifecycleMaterializationBatchTransactionRecord | None,
        external_result: tuple[object, ...],
    ) -> tuple[
        ActiveSession | None,
        tuple[RunningProcess, ...],
        LifecycleMaterializationBatchReceipt,
    ]:
        """Atomically publish one session and its parent-ordered process tree.

        All StateManager validation and lifecycle projection completes before the
        sorted registry start ticket is committed.  The primitive state commit then
        publishes every member and advances the StateManager fence exactly once.
        """

        if not self._state_manager.authenticates_materialization_plan(plan):
            raise StateError("Materialization batch plan integrity validation failed")

        session_plan = plan.session
        session_request: LifecycleSessionStartRequest | None = None
        staged_session: SessionIdentity | None = None
        if session_plan is not None:
            staged_session = session_plan.identity
            session_identity = self._shadow.project_session_start(staged_session)
            session_request = LifecycleSessionStartRequest(
                identity=session_identity,
                action_id=stable_uuid(
                    "lifecycle-authority-start-action",
                    "session",
                    session_identity.object_id,
                ),
                transition_id=stable_uuid(
                    "lifecycle-authority-start-transition",
                    "session",
                    session_identity.object_id,
                ),
            )

        staged_processes: dict[tuple[str, int], ProcessIdentity] = {}
        process_requests: list[LifecycleProcessStartRequest] = []
        for process_plan in plan.processes:
            identity = process_plan.identity
            parent_object_id = ""
            if identity.parent_pid:
                staged_parent = staged_processes.get((identity.hostname, identity.parent_pid))
                if staged_parent is not None:
                    if process_plan.parent_identity != staged_parent:
                        raise StateError(
                            "Lifecycle batch parent differs from authenticated process plan"
                        )
                    parent_object_id = staged_parent.object_id
                else:
                    parent = process_plan.parent_identity
                    if parent is None:
                        if identity.parent_pid != 4:
                            raise StateError(
                                "Lifecycle batch has no exact parent identity for "
                                f"{identity.object_id} PID={identity.parent_pid}"
                            )
                    else:
                        parent_snapshot = self._registry.get_process(parent.object_id)
                        if parent_snapshot is None and self._fixture_parent_backfill:
                            parent_session = (
                                self._state_manager.get_session_identity(parent.logon_id)
                                if parent.logon_id
                                else None
                            )
                            self._shadow.ensure_process(parent, session=parent_session)
                            parent_snapshot = self._registry.get_process(parent.object_id)
                        if parent_snapshot is None or parent_snapshot.closed_at is not None:
                            raise StateError(
                                "Lifecycle batch parent is not registered and live: "
                                f"{parent.object_id}"
                            )
                        parent_object_id = parent.object_id

            session = (
                staged_session
                if staged_session is not None and staged_session.logon_id == identity.logon_id
                else self._state_manager.get_session_identity(identity.logon_id)
                if identity.logon_id
                else None
            )
            if session is not None and session.hostname != identity.hostname:
                if self._fixture_parent_backfill:
                    session = None
                else:
                    raise StateError(
                        f"Lifecycle process {identity.object_id} cannot use a cross-host session"
                    )
            if session is not None and session is not staged_session:
                session_snapshot = self._registry.get_session(session.object_id)
                if session_snapshot is None and self._fixture_parent_backfill:
                    self._shadow.ensure_session(session)
                    session_snapshot = self._registry.get_session(session.object_id)
                if session_snapshot is None or session_snapshot.closed_at is not None:
                    raise StateError(
                        f"Lifecycle batch session is not registered and live: {session.object_id}"
                    )
            session_logon_type = (
                session_plan.logon_type
                if session is staged_session and session_plan is not None
                else self._state_manager.get_session_logon_type(identity.logon_id)
                if session is not None
                else None
            )
            lifecycle_identity, token, membership = self._shadow.project_process_start(
                identity,
                integrity_level=process_plan.integrity_level,
                session=session,
                token_session_id=process_plan.auth_session_id,
                session_logon_type=(
                    session_logon_type if session is not None else process_plan.auth_logon_type
                ),
                parent_object_id=parent_object_id,
            )
            process_requests.append(
                LifecycleProcessStartRequest(
                    identity=lifecycle_identity,
                    token=token,
                    membership=membership,
                    action_id=stable_uuid(
                        "lifecycle-authority-start-action",
                        "process",
                        identity.object_id,
                    ),
                    transition_id=stable_uuid(
                        "lifecycle-authority-start-transition",
                        "process",
                        identity.object_id,
                    ),
                )
            )
            staged_processes[(identity.hostname, identity.pid)] = identity

        hook = self._materialization_precommit_hook
        if hook is not None:
            hook()
        member_tokens = tuple(
            member.publication_token
            for member in (
                *((session_plan,) if session_plan is not None else ()),
                *plan.processes,
            )
        )
        receipt = LifecycleMaterializationBatchReceipt._issue(
            authority_secret=self._receipt_secret,
            publication_token=plan.publication_token,
            member_tokens=member_tokens,
            prior_version=plan.expected_version,
            committed_version=plan.expected_version + 1,
        )
        terminal_result: LifecycleMaterializationBatchTerminalResult | None = None
        if transaction_record is not None:
            if (
                transaction_record.claimed_thread is not current_thread()
                or transaction_record.terminal_result is not None
            ):
                raise StateError("Materialization-batch transaction lost its exact claim")
            terminal_result = LifecycleMaterializationBatchTerminalResult._issue(
                authority_secret=self._receipt_secret,
                transaction=transaction_record.transaction,
                plan=plan,
                external_result=external_result,
                receipt=receipt,
            )
            if not self._materialization_batch_terminal_result_has_valid_integrity(
                transaction_record.transaction,
                terminal_result,
            ):
                raise StateError("Materialization-batch terminal precomputation failed")

        session_requests = (session_request,) if session_request is not None else ()
        lost_boundary_error: BaseException | None = None
        with self._state_manager.prepared_materialization_batch(plan) as prepared:
            with self._registry.prepare_start_batch(
                sessions=session_requests,
                processes=tuple(process_requests),
            ) as ticket:
                try:
                    session, processes = prepared.apply_provisional()
                except BaseException as error:
                    if not prepared.provisionally_applied:
                        raise
                    lost_boundary_error = error
                try:
                    ticket.commit()
                except BaseException as error:
                    if not ticket.committed:
                        raise
                    if lost_boundary_error is None:
                        lost_boundary_error = error
                if transaction_record is not None:
                    assert terminal_result is not None
                    try:
                        self._terminalize_materialization_batch_transaction_no_fail(
                            transaction_record,
                            terminal_result,
                        )
                    except BaseException as error:
                        self._recover_materialization_batch_terminal_install_no_fail(
                            transaction_record,
                            terminal_result,
                        )
                        if lost_boundary_error is None:
                            lost_boundary_error = error
                session, processes = prepared.finalize_no_fail()
                if finalize_external_no_fail is not None:
                    finalize_external_no_fail()
        if lost_boundary_error is not None and transaction_record is not None:
            raise lost_boundary_error
        return session, processes, receipt

    def _process_start_request(
        self,
        plan: ProcessMaterializationPlan,
    ) -> LifecycleProcessStartRequest:
        """Project one exact lifecycle request without allocating State identity."""

        if not self._state_manager.authenticates_materialization_plan(plan):
            raise StateError("Process materialization plan integrity validation failed")

        identity = plan.identity
        parent_object_id = ""
        if identity.parent_pid:
            parent = plan.parent_identity
            if parent is None:
                if identity.parent_pid == 4:
                    # PID 4 is the Windows virtual kernel/System parent in narrow
                    # compatibility fixtures that do not materialize the boot tree.
                    # It is not a missing user process and owns no registry row.
                    parent = None
                else:
                    raise StateError(
                        "Lifecycle materialization has no exact parent identity for "
                        f"{identity.object_id} PID={identity.parent_pid}"
                    )
            if parent is not None:
                parent_snapshot = self._registry.get_process(parent.object_id)
                if parent_snapshot is None and self._fixture_parent_backfill:
                    parent_session = (
                        self._state_manager.get_session_identity(parent.logon_id)
                        if parent.logon_id
                        else None
                    )
                    self._shadow.ensure_process(parent, session=parent_session)
                    parent_snapshot = self._registry.get_process(parent.object_id)
                if parent_snapshot is None or parent_snapshot.closed_at is not None:
                    raise StateError(
                        "Lifecycle materialization parent is not registered and live: "
                        f"{parent.object_id}"
                    )
                parent_object_id = parent.object_id

        session = (
            self._state_manager.get_session_identity(identity.logon_id)
            if identity.logon_id
            else None
        )
        if session is not None and session.hostname != identity.hostname:
            if self._fixture_parent_backfill:
                session = None
            else:
                raise StateError(
                    f"Lifecycle process {identity.object_id} cannot use a cross-host session"
                )
        if session is not None:
            session_snapshot = self._registry.get_session(session.object_id)
            if session_snapshot is None and self._fixture_parent_backfill:
                self._shadow.ensure_session(session)
                session_snapshot = self._registry.get_session(session.object_id)
            if session_snapshot is None or session_snapshot.closed_at is not None:
                raise StateError(
                    "Lifecycle materialization session is not registered and live: "
                    f"{session.object_id}"
                )
        session_logon_type = (
            self._state_manager.get_session_logon_type(identity.logon_id)
            if session is not None
            else None
        )
        lifecycle_identity, token, membership = self._shadow.project_process_start(
            identity,
            integrity_level=plan.integrity_level,
            session=session,
            token_session_id=plan.auth_session_id,
            session_logon_type=(
                session_logon_type if session is not None else plan.auth_logon_type
            ),
            parent_object_id=parent_object_id,
        )
        return LifecycleProcessStartRequest(
            identity=lifecycle_identity,
            token=token,
            membership=membership,
            action_id=stable_uuid(
                "lifecycle-authority-start-action",
                "process",
                identity.object_id,
            ),
            transition_id=stable_uuid(
                "lifecycle-authority-start-transition",
                "process",
                identity.object_id,
            ),
        )

    def service_staged_process_binding_member(
        self,
        plan: ProcessMaterializationPlan,
        binding: ServiceProcessBindingIdentity,
    ) -> LifecycleServiceStagedProcessBindingMember:
        """Freeze the exact lifecycle/State proof for one staged service process."""

        if not self._state_manager.authenticates_materialization_plan(plan):
            raise StateError("Service process State plan integrity validation failed")
        if binding.process_object_id != plan.identity.object_id:
            raise StateError("Service binding targets another process materialization plan")
        return LifecycleServiceStagedProcessBindingMember(
            binding_id=binding.binding_id,
            process_start=self._process_start_request(plan),
            state_publication_token=plan.publication_token,
        )

    def _validate_process_service_admission(
        self,
        plan: ProcessMaterializationPlan,
        process_start: LifecycleProcessStartRequest,
        token: LifecycleServiceAdmissionToken,
    ) -> None:
        """Authenticate one exact staged process/service capability."""

        if not self._state_manager.authenticates_materialization_plan(plan):
            raise StateError("Service process State plan integrity validation failed")
        if not self._registry.authenticates_service_admission_token(token):
            raise StateError("Service publication admission is not authentic")
        request = token.request
        if request.identity.hostname != plan.identity.hostname:
            raise StateError("Service publication and staged process hosts do not match")
        members = request.staged_process_bindings
        if len(members) != 1:
            raise StateError("Process/service coordinator requires one staged process binding")
        member = members[0]
        if (
            member.process_start != process_start
            or member.state_publication_token != plan.publication_token
        ):
            raise StateError("Service publication staged process proof does not match State")
        binding = next(
            (item for item in request.process_bindings if item.binding_id == member.binding_id),
            None,
        )
        if binding is None or binding.process_object_id != plan.identity.object_id:
            raise StateError("Service publication does not bind the staged process")

    def _discard_service_admission(self, token: LifecycleServiceAdmissionToken) -> None:
        """Best-effort release of one exact transferred service capability."""

        try:
            self._registry.cancel_service_publication(token)
        except StateError:
            # Exact-object tamper cleanup releases its retained canonical preimage.
            pass

    def materialize_process_service_composite(
        self,
        plan: ProcessMaterializationPlan,
        service_token: LifecycleServiceAdmissionToken,
        *,
        finalize_external_no_fail: Callable[[], None] | None = None,
    ) -> LifecycleProcessServiceCompositeResult:
        """Atomically publish one staged process, service, and exact binding.

        Passing ``service_token`` transfers its one-shot reservation to this
        authority. Any rejection before primitive commit releases that exact
        capability without consuming foreign or copied tokens. The optional
        finalizer follows the same preclaimed, primitive-only contract as the
        ordinary process materialization boundary.
        """

        identity = plan.identity
        process_start = self._process_start_request(plan)
        try:
            self._validate_process_service_admission(plan, process_start, service_token)
            with self._registry.claimed_service_publication(service_token) as service_publication:
                with self._state_manager.materialization_guard(plan):
                    self._state_manager.validate_process_materialization(plan)
                    with self._registry.prepare_start_batch(
                        processes=(process_start,),
                        service_publication=service_publication,
                    ) as ticket:
                        hook = self._materialization_precommit_hook
                        if hook is not None:
                            hook()
                        self._state_manager.validate_process_materialization(plan)
                        self._validate_process_service_admission(
                            plan,
                            process_start,
                            service_token,
                        )
                        ticket.commit()
                        service_receipt = ticket.service_receipt
                        if service_receipt is None:
                            raise AssertionError(
                                "Composite lifecycle ticket returned no service receipt"
                            )
                        process = self._state_manager._commit_prevalidated_process_materialization(
                            plan
                        )
                        if finalize_external_no_fail is not None:
                            finalize_external_no_fail()
        except BaseException:
            self._discard_service_admission(service_token)
            raise

        process_receipt = LifecycleMaterializationReceipt._issue(
            authority_secret=self._receipt_secret,
            kind="process",
            object_id=identity.object_id,
            publication_token=plan.publication_token,
            prior_version=plan.expected_version,
            committed_version=plan.expected_version + 1,
        )
        receipt = LifecycleProcessServiceCompositeReceipt._issue(
            authority_secret=self._receipt_secret,
            process_receipt=process_receipt,
            service_receipt=service_receipt,
        )
        return LifecycleProcessServiceCompositeResult(process=process, receipt=receipt)

    def authenticates_process_service_composite_receipt(
        self,
        plan: ProcessMaterializationPlan,
        receipt: object,
    ) -> bool:
        """Verify one exact committed process/service authority receipt."""

        if not isinstance(receipt, LifecycleProcessServiceCompositeReceipt):
            return False
        if not receipt._has_valid_integrity(self._receipt_secret):
            return False
        if not self.authenticates_materialization_receipt(
            plan,
            receipt.process_receipt,
        ):
            return False
        service_receipt = receipt.service_receipt
        if not self._registry.authenticates_service_publication_receipt(service_receipt):
            return False
        members = service_receipt.request.staged_process_bindings
        if len(members) != 1:
            return False
        member = members[0]
        process_identity = member.process_start.identity
        return (
            member.state_publication_token == plan.publication_token
            and process_identity.object_id == plan.identity.object_id
            and process_identity.hostname == plan.identity.hostname
            and process_identity.pid == plan.identity.pid
            and process_identity.started_at == plan.identity.started_at
            and process_identity.image == plan.identity.image
            and service_receipt.start_plan_tokens == (plan.publication_token,)
            and tuple(item.identity for item in service_receipt.processes) == (process_identity,)
        )

    def _validate_process_service_closure_admission(
        self,
        plan: ProcessTerminationMaterializationPlan,
        token: LifecycleServiceClosureAdmissionToken,
    ) -> None:
        """Authenticate one exact binding-first process/service close capability."""

        if not self._state_manager.authenticates_process_termination_plan(plan):
            raise StateError("Service process termination State plan integrity validation failed")
        if not self._registry.authenticates_service_closure_admission_token(token):
            raise StateError("Service process closure admission is not authentic")
        request = token.request
        identity = plan.identity
        if len(request.process_closures) != 1:
            raise StateError("Process/service closure requires one exact process close")
        process_control = request.process_closures[0]
        if (
            process_control.barrier.subject.kind != "process"
            or process_control.barrier.subject.object_id != identity.object_id
            or process_control.barrier.requested_at != plan.end_time
        ):
            raise StateError("Service closure process control does not match the State plan")
        if not request.binding_closures or any(
            item.identity.process_object_id != identity.object_id or item.closed_at != plan.end_time
            for item in request.binding_closures
        ):
            raise StateError("Service closure must close every exact process binding at exit")
        if any(item.barrier.requested_at != plan.end_time for item in request.service_closures):
            raise StateError("Service terminalization must share the process exit frontier")

    def _discard_service_closure_admission(
        self,
        token: LifecycleServiceClosureAdmissionToken,
    ) -> None:
        """Best-effort release of one exact transferred service-close capability."""

        try:
            self._registry.cancel_service_process_closure(token)
        except StateError:
            # Exact-object tamper cleanup releases its retained canonical preimage.
            pass

    def materialize_process_service_closure_composite(
        self,
        plan: ProcessTerminationMaterializationPlan,
        service_token: LifecycleServiceClosureAdmissionToken,
        *,
        finalize_external_no_fail: Callable[[], None] | None = None,
    ) -> LifecycleProcessServiceClosureCompositeResult:
        """Atomically close service bindings/lifecycle and exact State process state.

        Passing ``service_token`` transfers its one-shot reservation to this
        authority. The registry capability is claimed without retaining registry
        locks, then the State guard establishes the global State-to-lifecycle lock
        order. After the final authentication sweep there is no caller callback or
        yield before the lifecycle and State primitive commits.
        """

        identity = plan.identity
        try:
            self._validate_process_service_closure_admission(plan, service_token)
            with self._registry.claimed_service_process_closure(service_token) as service_closure:
                with self._state_manager.process_termination_materialization_guard(plan):
                    hook = self._materialization_precommit_hook
                    if hook is not None:
                        hook()
                    self._state_manager.validate_process_termination_materialization(plan)
                    self._validate_process_service_closure_admission(plan, service_token)
                    service_receipt = service_closure.commit_no_fail()
                    ended = self._state_manager._commit_prevalidated_process_termination_materialization(
                        plan
                    )
                    if finalize_external_no_fail is not None:
                        finalize_external_no_fail()
        except BaseException:
            self._discard_service_closure_admission(service_token)
            raise

        process_receipt = LifecycleMaterializationReceipt._issue(
            authority_secret=self._receipt_secret,
            kind="process_termination",
            object_id=identity.object_id,
            publication_token=plan.publication_token,
            prior_version=plan.expected_version,
            committed_version=plan.expected_version + 1,
        )
        receipt = LifecycleProcessServiceClosureCompositeReceipt._issue(
            authority_secret=self._receipt_secret,
            process_receipt=process_receipt,
            service_receipt=service_receipt,
        )
        return LifecycleProcessServiceClosureCompositeResult(process=ended, receipt=receipt)

    def authenticates_process_service_closure_composite_receipt(
        self,
        plan: ProcessTerminationMaterializationPlan,
        receipt: object,
    ) -> bool:
        """Verify one exact committed State/lifecycle service closure receipt."""

        if not isinstance(receipt, LifecycleProcessServiceClosureCompositeReceipt):
            return False
        if not receipt._has_valid_integrity(self._receipt_secret):
            return False
        if not self._state_manager.authenticates_process_termination_plan(plan):
            return False
        process_receipt = receipt.process_receipt
        if (
            not process_receipt._has_valid_integrity(self._receipt_secret)
            or process_receipt.kind != "process_termination"
            or process_receipt.object_id != plan.identity.object_id
            or process_receipt._publication_token != plan.publication_token
            or process_receipt.prior_version != plan.expected_version
            or process_receipt.committed_version != plan.expected_version + 1
        ):
            return False
        service_receipt = receipt.service_receipt
        if not self._registry.authenticates_service_process_closure_receipt(service_receipt):
            return False
        request = service_receipt.request
        if len(request.process_closures) != 1 or len(service_receipt.processes) != 1:
            return False
        control = request.process_closures[0]
        lifecycle_process = service_receipt.processes[0]
        identity = plan.identity
        return (
            control.barrier.subject.kind == "process"
            and control.barrier.subject.object_id == identity.object_id
            and control.barrier.requested_at == plan.end_time
            and lifecycle_process.identity.object_id == identity.object_id
            and lifecycle_process.identity.hostname == identity.hostname
            and lifecycle_process.identity.pid == identity.pid
            and lifecycle_process.identity.started_at == identity.started_at
            and lifecycle_process.identity.image == identity.image
            and lifecycle_process.closed_at == plan.end_time
            and tuple(item.identity for item in service_receipt.bindings)
            == tuple(item.identity for item in request.binding_closures)
            and all(item.closed_at == plan.end_time for item in service_receipt.bindings)
        )

    def materialize_process(
        self,
        plan: ProcessMaterializationPlan,
        *,
        finalize_external_no_fail: Callable[[], None] | None = None,
    ) -> tuple[RunningProcess, LifecycleMaterializationReceipt]:
        """Atomically publish one planned process/thread and external token.

        ``finalize_external_no_fail`` has the same preclaimed, primitive-only
        contract and global lock ordering as :meth:`materialize_session`.
        """

        identity = plan.identity
        request = self._process_start_request(plan)
        with self._state_manager.materialization_guard(plan):
            self._state_manager.validate_process_materialization(plan)
            with self._registry.prepare_start_batch(processes=(request,)) as ticket:
                hook = self._materialization_precommit_hook
                if hook is not None:
                    hook()
                ticket.commit()
                process = self._state_manager._commit_prevalidated_process_materialization(plan)
                if finalize_external_no_fail is not None:
                    finalize_external_no_fail()
        receipt = LifecycleMaterializationReceipt._issue(
            authority_secret=self._receipt_secret,
            kind="process",
            object_id=identity.object_id,
            publication_token=plan.publication_token,
            prior_version=plan.expected_version,
            committed_version=plan.expected_version + 1,
        )
        return process, receipt

    def bootstrap_active_state(self) -> tuple[int, int]:
        """Publish compatibility-active identities once before the first watermark.

        Some boot and warmup paths predate dispatcher lifecycle publication.  They
        remain valid future hold owners, so the engine must publish them before the
        late-write fence passes their canonical starts.  This is a one-time boundary
        migration, not a recurring watermark scan.
        """

        with self._bootstrap_lock:
            if self._bootstrap_complete:
                return self._bootstrapped_sessions, self._bootstrapped_processes
            sessions = self._state_manager.list_active_sessions()
            for session in sessions:
                identity = self._state_manager.get_session_identity(session.logon_id)
                if identity is None:
                    raise StateError(
                        f"Active session {session.logon_id} has no canonical lifecycle identity"
                    )
                self._shadow.ensure_session(identity)
            processes = self._state_manager.list_running_processes()
            for process in processes:
                self.ensure_process(process.system, process.pid)
            self._bootstrapped_sessions = len(sessions)
            self._bootstrapped_processes = len(processes)
            self._bootstrap_complete = True
            return self._bootstrapped_sessions, self._bootstrapped_processes

    def foreground_owner(self, hostname: str, shell_pid: int) -> ForegroundShellOwner:
        """Resolve one live shell and its exact registry session/token ownership."""

        process = self.ensure_process(hostname, shell_pid)
        snapshot = self._registry.get_process(process.object_id)
        if snapshot is None or snapshot.closed_at is not None:
            raise StateError(f"No live lifecycle shell for {hostname} PID={shell_pid}")
        session_object_id = snapshot.membership.session_object_id
        if not session_object_id:
            raise StateError(
                f"Lifecycle foreground shell {process.object_id} has no session membership"
            )
        return ForegroundShellOwner(
            hostname=process.hostname,
            principal=snapshot.token.principal,
            session_object_id=session_object_id,
            process_object_id=process.object_id,
        )

    def foreground_lease_for_shell(
        self,
        hostname: str,
        shell_pid: int,
    ) -> LifecycleForegroundLease | None:
        """Return the exact group-level lease for one live shell resource."""

        owner = self.foreground_owner(hostname, shell_pid)
        return self._registry.foreground_lease_for(
            owner.hostname,
            owner.principal,
            owner.session_object_id,
            owner.process_object_id,
        )

    def release_foreground_process_lease(
        self,
        *,
        hostname: str,
        pid: int,
        released_at: datetime,
    ) -> LifecycleForegroundLease | None:
        """Release the exact foreground resource held by a closing shell process."""

        identity = self._state_manager.get_process_identity(hostname, pid)
        if identity is None:
            return None
        snapshot = self._registry.get_process(identity.object_id)
        if snapshot is None or not snapshot.membership.session_object_id:
            return None
        lease = self._registry.foreground_lease_for(
            identity.hostname,
            snapshot.token.principal,
            snapshot.membership.session_object_id,
            identity.object_id,
        )
        if lease is None:
            return None
        action_id = stable_uuid("generator-foreground-release-action", lease.lease_id)
        released = self._registry.release_foreground_lease(
            lease.lease_id,
            released_at=ensure_utc(released_at),
            action_id=action_id,
            transition_ordinal=lease.transition_ordinal + 1,
        )
        if not released:
            raise StateError(f"Foreground lease {lease.lease_id} disappeared before process close")
        return lease

    def remember_foreground_lease(
        self,
        *,
        hostname: str,
        shell_pid: int,
        acquired_at: datetime,
        lease_until: datetime,
        concurrency_group_id: str,
    ) -> LifecycleForegroundLease:
        """Acquire or renew the one immutable group-level shell foreground lease."""

        owner = self.foreground_owner(hostname, shell_pid)
        acquired = ensure_utc(acquired_at)
        deadline = ensure_utc(lease_until)
        if not concurrency_group_id:
            raise ValueError("Foreground lifecycle leases require a concurrency_group_id")
        existing = self._registry.foreground_lease_for(
            owner.hostname,
            owner.principal,
            owner.session_object_id,
            owner.process_object_id,
        )
        if existing is not None and existing.concurrency_group_id == concurrency_group_id:
            if deadline <= existing.lease_until:
                return existing
            renewed = self._registry.renew_foreground_lease(
                existing.lease_id,
                expected_lease_until=existing.lease_until,
                lease_until=deadline,
                canonical_time=max(acquired, existing.acquired_at),
                action_id=existing.action_id,
                concurrency_group_id=concurrency_group_id,
                transition_ordinal=existing.transition_ordinal + 1,
            )
            self.mark_strict(
                LifecycleEntityRef("session", owner.session_object_id),
                hostname=owner.hostname,
                retain_until=renewed.lease_until,
            )
            self.mark_strict(
                LifecycleEntityRef("process", owner.process_object_id),
                hostname=owner.hostname,
                retain_until=renewed.lease_until,
            )
            return renewed
        if existing is not None:
            acquired = max(acquired, existing.lease_until)
        action_id = stable_uuid(
            "generator-foreground-action",
            owner.hostname,
            owner.session_object_id,
            owner.process_object_id,
            concurrency_group_id,
            acquired.isoformat(),
        )
        lease = LifecycleForegroundLease(
            lease_id=stable_uuid("generator-foreground-lease", action_id),
            hostname=owner.hostname,
            principal=owner.principal,
            session_object_id=owner.session_object_id,
            process_object_id=owner.process_object_id,
            acquired_at=acquired,
            lease_until=max(acquired, deadline),
            action_id=action_id,
            concurrency_group_id=concurrency_group_id,
        )
        result = self._registry.acquire_foreground_lease(lease)
        self.mark_strict(
            LifecycleEntityRef("session", owner.session_object_id),
            hostname=owner.hostname,
            retain_until=result.lease_until,
        )
        self.mark_strict(
            LifecycleEntityRef("process", owner.process_object_id),
            hostname=owner.hostname,
            retain_until=result.lease_until,
        )
        return result

    def singleton_lease_id(
        self,
        key: tuple[str, str, str, str],
        start: datetime,
    ) -> str:
        """Return the stable exact identity for one pre-allocation singleton claim."""

        hostname, principal, logon_id, canonical_image = key
        session_identity = self._state_manager.get_session_identity(logon_id)
        if session_identity is None:
            raise StateError(f"No exact lifecycle session for singleton {hostname}/{logon_id}")
        return stable_uuid(
            "generator-singleton-lease",
            hostname,
            principal,
            session_identity.object_id,
            canonical_image,
            ensure_utc(start).isoformat(),
        )

    @staticmethod
    def _same_singleton_claim(
        current: LifecycleSingletonLease,
        requested: LifecycleSingletonLease,
    ) -> bool:
        """Return whether two values identify one immutable pre-allocation claim."""

        return (
            current.lease_id == requested.lease_id
            and current.hostname == requested.hostname
            and current.principal == requested.principal
            and current.session_object_id == requested.session_object_id
            and current.logon_id == requested.logon_id
            and current.canonical_image == requested.canonical_image
            and current.acquired_at == requested.acquired_at
            and current.action_id == requested.action_id
        )

    def claim_singleton_lease(
        self,
        key: tuple[str, str, str, str],
        start: datetime,
        provisional_end: datetime,
    ) -> LifecycleSingletonLease | None:
        """Claim a non-overlapping session singleton before PID allocation."""

        hostname, principal, logon_id, canonical_image = key
        acquired = ensure_utc(start)
        deadline = ensure_utc(provisional_end)
        ended_at = self._state_manager.get_session_end_time(logon_id)
        end_plan = self._state_manager.get_session_end_plan(logon_id)
        session_deadlines = [
            ensure_utc(candidate)
            for candidate in (
                ended_at,
                end_plan.canonical_end if end_plan is not None else None,
            )
            if candidate is not None
        ]
        if session_deadlines:
            deadline = min(deadline, *session_deadlines)
        if deadline <= acquired:
            # A singleton interval is half-open.  Reject an ended or zero-width
            # owner before publishing a session or allocating a PID.
            return None
        session_identity = self._state_manager.get_session_identity(logon_id)
        if session_identity is None or session_identity.hostname.casefold() != hostname.casefold():
            raise StateError(f"No exact lifecycle session for singleton {hostname}/{logon_id}")
        if session_identity.principal.casefold() != principal.casefold():
            raise StateError(
                f"Singleton principal {principal!r} disagrees with session "
                f"{session_identity.principal!r}"
            )
        session = self._shadow.ensure_session(session_identity)
        action_id = stable_uuid(
            "generator-singleton-action",
            hostname,
            session.object_id,
            canonical_image,
            acquired.isoformat(),
        )
        lease = LifecycleSingletonLease(
            lease_id=self.singleton_lease_id(key, acquired),
            hostname=hostname,
            principal=principal,
            session_object_id=session.object_id,
            logon_id=session.logon_id,
            canonical_image=canonical_image,
            process_object_id="",
            acquired_at=acquired,
            lease_until=deadline,
            action_id=action_id,
        )
        current = self._registry.singleton_lease(lease.lease_id)
        if current is not None:
            if not self._same_singleton_claim(current, lease):
                raise StateError(
                    "Generator singleton lease identity collides with a different immutable "
                    f"claim: lease_id={lease.lease_id} resource={lease.resource_key!r}"
                )
            # The exact claim is already active (and may already be bound or
            # renewed).  It owns this half-open interval, so a second caller
            # must not allocate another process for the same singleton.
            return None
        try:
            result = self._registry.acquire_singleton_lease(lease)
        except LifecycleLeaseConflictError:
            return None
        except StateError:
            # Same-resource workers can observe the claim between the exact
            # preflight read and the partition commit.  Treat only the fully
            # matching immutable claim as the same occupied singleton; every
            # other registry authority error remains actionable.
            raced = self._registry.singleton_lease(lease.lease_id)
            if raced is not None and self._same_singleton_claim(raced, lease):
                return None
            raise
        self.mark_strict(
            session.ref,
            hostname=hostname,
            retain_until=result.lease_until,
        )
        return result

    def bind_singleton_lease(
        self,
        key: tuple[str, str, str, str],
        start: datetime,
        *,
        pid: int,
    ) -> LifecycleSingletonLease:
        """Bind a pre-allocation singleton claim to its exact published process."""

        lease_id = self.singleton_lease_id(key, start)
        current = self._registry.singleton_lease(lease_id)
        if current is None:
            raise StateError(f"Unknown generator singleton lease {lease_id}")
        process = self.ensure_process(key[0], pid)
        result = self._registry.bind_singleton_lease(
            lease_id,
            process_object_id=process.object_id,
            canonical_time=max(ensure_utc(start), process.started_at),
            action_id=current.action_id,
            transition_ordinal=1,
        )
        self.mark_strict(
            process.ref,
            hostname=key[0],
            retain_until=result.lease_until,
        )
        return result

    def update_singleton_lease_end(
        self,
        key: tuple[str, str, str, str],
        start: datetime,
        end: datetime,
    ) -> LifecycleSingletonLease:
        """CAS-update one bound singleton's planned end without scanning intervals."""

        lease_id = self.singleton_lease_id(key, start)
        current = self._registry.singleton_lease(lease_id)
        if current is None:
            raise StateError(f"Unknown generator singleton lease {lease_id}")
        process_snapshot = (
            self._registry.get_process(current.process_object_id)
            if current.process_object_id
            else None
        )
        canonical_time = max(
            ensure_utc(start) + timedelta(microseconds=1),
            current.acquired_at,
            (
                process_snapshot.identity.started_at + timedelta(microseconds=1)
                if process_snapshot is not None
                else current.acquired_at
            ),
        )
        renewed = self._registry.renew_singleton_lease(
            lease_id,
            expected_lease_until=current.lease_until,
            lease_until=ensure_utc(end),
            canonical_time=canonical_time,
            action_id=current.action_id,
            transition_ordinal=max(2, current.transition_ordinal + 1),
        )
        self.mark_strict(
            LifecycleEntityRef("session", renewed.session_object_id),
            hostname=renewed.hostname,
            retain_until=renewed.lease_until,
        )
        if renewed.process_object_id:
            self.mark_strict(
                LifecycleEntityRef("process", renewed.process_object_id),
                hostname=renewed.hostname,
                retain_until=renewed.lease_until,
            )
        return renewed

    def release_singleton_process_lease(
        self,
        *,
        hostname: str,
        pid: int,
        released_at: datetime,
    ) -> LifecycleSingletonLease | None:
        """Release the exact singleton owner before committing its process close."""

        identity = self._state_manager.get_process_identity(hostname, pid)
        if identity is None:
            return None
        lease = self._registry.singleton_lease_for_process(identity.object_id)
        if lease is None:
            return None
        if lease.process_object_id != identity.object_id:
            raise StateError(
                f"Singleton lease {lease.lease_id} is not bound to process {identity.object_id}"
            )
        action_id = stable_uuid("generator-singleton-release-action", lease.lease_id)
        released = self._registry.release_singleton_lease(
            lease.lease_id,
            released_at=ensure_utc(released_at),
            action_id=action_id,
            transition_ordinal=lease.transition_ordinal + 1,
        )
        if not released:
            raise StateError(f"Singleton lease {lease.lease_id} disappeared before process close")
        return lease

    def add_process_hold(
        self,
        *,
        hostname: str,
        pid: int,
        acquired_at: datetime,
        hold_until: datetime,
        reason: str,
    ) -> LifecycleHold:
        """Append one exact typed process hold under stable action ownership."""

        acquired = ensure_utc(acquired_at)
        deadline = ensure_utc(hold_until)
        process = self.ensure_process(hostname, pid)
        action_id = stable_uuid(
            "generator-lifecycle-hold-action",
            process.object_id,
            reason,
            acquired.isoformat(),
            deadline.isoformat(),
        )
        hold = LifecycleHold(
            hold_id=stable_uuid("generator-lifecycle-hold", action_id),
            subject=process.ref,
            acquired_at=acquired,
            hold_until=deadline,
            action_id=action_id,
            reason=reason,
        )
        result = self._registry.add_hold(hold)
        self.mark_strict(
            process.ref,
            hostname=hostname,
            retain_until=deadline,
        )
        return result

    def process_hold_until(self, hostname: str, pid: int) -> datetime | None:
        """Return the latest exact typed hold for the live PID instance."""

        identity = self._state_manager.get_process_identity(hostname, pid)
        if identity is None:
            return None
        snapshot = self._registry.get_process(identity.object_id)
        return None if snapshot is None else snapshot.latest_hold_until

    def process_resource_lease_deadline(self, hostname: str, pid: int) -> datetime | None:
        """Return the exact cached foreground/singleton deadline for one live process."""

        identity = self._state_manager.get_process_identity(hostname, pid)
        if identity is None:
            return None
        return self._registry.resource_lease_deadline(
            LifecycleEntityRef("process", identity.object_id)
        )

    def session_member_close_deadline(self, hostname: str, logon_id: str) -> datetime | None:
        """Return the exact all-members-closed deadline for one live session."""

        session = self.ensure_session(hostname, logon_id)
        return self._registry.session_member_close_deadline(session.object_id)

    def live_session_member_process_page(
        self,
        hostname: str,
        logon_id: str,
        *,
        limit: int = _DEFAULT_DUE_PAGE,
    ) -> tuple[ProcessLifecycleSnapshot, ...]:
        """Return the first bounded indexed page of exact live session members."""

        session = self.ensure_session(hostname, logon_id)
        members, _cursor = self._registry.live_session_member_process_page(
            session.object_id,
            limit=limit,
        )
        return members

    def live_session_member_process_census(
        self,
        hostname: str,
        logon_id: str,
        *,
        limit: int = _DEFAULT_DUE_PAGE,
    ) -> tuple[ProcessLifecycleSnapshot, ...]:
        """Return one bounded complete indexed census of exact live session members."""

        if type(limit) is not int or limit <= 0 or limit > _DEFAULT_DUE_PAGE:
            raise ValueError(
                f"Lifecycle session-member census limit must be in [1, {_DEFAULT_DUE_PAGE}]"
            )
        session = self.ensure_session(hostname, logon_id)
        members: list[ProcessLifecycleSnapshot] = []
        cursor: int | None = None
        while True:
            remaining = limit - len(members)
            if remaining <= 0:
                raise StateError(
                    "Lifecycle session-member census exceeds its bounded page capacity: "
                    f"session={session.object_id} limit={limit}"
                )
            page, cursor = self._registry.live_session_member_process_page(
                session.object_id,
                after_handle=cursor,
                limit=min(remaining, _DEFAULT_DUE_PAGE),
            )
            members.extend(page)
            if cursor is None:
                return tuple(members)

    def live_child_process_page_for_object(
        self,
        process_object_id: str,
        *,
        limit: int = _DEFAULT_DUE_PAGE,
    ) -> tuple[ProcessLifecycleSnapshot, ...]:
        """Return one bounded indexed page of an exact process object's live children."""

        children, _cursor = self._registry.live_child_process_page(
            process_object_id,
            limit=limit,
        )
        return children

    def live_process_descendant_postorder(
        self,
        process_object_id: str,
        *,
        limit: int = _DEFAULT_DUE_PAGE,
    ) -> tuple[ProcessLifecycleSnapshot, ...]:
        """Return one bounded exact children-first process-descendant census."""

        if type(process_object_id) is not str or not process_object_id:
            raise ValueError("Lifecycle descendant census requires a process object ID")
        if type(limit) is not int or limit <= 0 or limit > _DEFAULT_DUE_PAGE:
            raise ValueError(
                f"Lifecycle descendant census limit must be in [1, {_DEFAULT_DUE_PAGE}]"
            )

        snapshots: dict[str, ProcessLifecycleSnapshot] = {}
        visiting: set[str] = set()
        completed: set[str] = set()
        postorder: list[ProcessLifecycleSnapshot] = []
        stack: list[tuple[str, bool]] = [(process_object_id, False)]
        while stack:
            object_id, expanded = stack.pop()
            if expanded:
                visiting.discard(object_id)
                completed.add(object_id)
                snapshot = snapshots.get(object_id)
                if snapshot is not None:
                    postorder.append(snapshot)
                continue
            if object_id in completed:
                continue
            if object_id in visiting:
                raise StateError(
                    f"Lifecycle descendant ancestry cycle detected at process {object_id}"
                )
            visiting.add(object_id)
            stack.append((object_id, True))

            children: list[ProcessLifecycleSnapshot] = []
            cursor: int | None = None
            while True:
                remaining = limit - len(snapshots) - len(children)
                page, cursor = self._registry.live_child_process_page(
                    object_id,
                    after_handle=cursor,
                    limit=max(1, min(remaining, _DEFAULT_DUE_PAGE)),
                )
                if remaining <= 0 and page:
                    raise StateError(
                        "Lifecycle descendant census exceeds its bounded page capacity: "
                        f"root={process_object_id} limit={limit}"
                    )
                children.extend(page)
                if cursor is None:
                    break
            for child in children:
                child_id = child.identity.object_id
                retained = snapshots.get(child_id)
                if retained is not None and retained != child:
                    raise StateError(
                        f"Lifecycle descendant process {child_id} changed during census"
                    )
                if child_id in completed or child_id in visiting or retained is not None:
                    raise StateError(
                        f"Lifecycle descendant process {child_id} has ambiguous ancestry"
                    )
                snapshots[child_id] = child
            for child in reversed(children):
                stack.append((child.identity.object_id, False))
        return tuple(postorder)

    def process_latest_closed_child_at_for_object(
        self,
        process_object_id: str,
    ) -> datetime | None:
        """Return one process's latest retained child close without requiring a drain."""

        if type(process_object_id) is not str or not process_object_id:
            raise ValueError("Lifecycle latest child close requires a process object ID")
        return self._registry.process_latest_closed_child_at(process_object_id)

    def session_latest_closed_member_at_for_object(
        self,
        session_object_id: str,
    ) -> datetime | None:
        """Return one session's latest retained member close without requiring a drain."""

        if type(session_object_id) is not str or not session_object_id:
            raise ValueError("Lifecycle latest member close requires a session object ID")
        return self._registry.session_latest_closed_member_at(session_object_id)

    def reconcile_prepared_process_close(
        self,
        snapshot: ProcessLifecycleSnapshot,
        *,
        session_close_at: datetime,
    ) -> bool:
        """Commit a previously prepared exact close after descendants drain."""

        ticket = snapshot.closure_ticket
        if ticket is None:
            return False
        terminal = ensure_utc(session_close_at)
        if ticket.effective_at >= terminal:
            raise StateError(
                "Prepared process close does not precede its owning session close: "
                f"process={snapshot.identity.object_id} "
                f"process_close={ticket.effective_at.isoformat()} "
                f"session_close={terminal.isoformat()}"
            )
        self._registry.close(ticket.ticket_id)
        return True

    def live_child_process_page(
        self,
        hostname: str,
        parent_pid: int,
        *,
        after_handle: int | None = None,
        limit: int = _DEFAULT_DUE_PAGE,
    ) -> tuple[tuple[ProcessLifecycleSnapshot, ...], int | None]:
        """Return one bounded exact page of the live parent's direct children."""

        parent = self.ensure_process(hostname, parent_pid)
        return self._registry.live_child_process_page(
            parent.object_id,
            after_handle=after_handle,
            limit=limit,
        )

    def process_child_close_deadline(self, hostname: str, parent_pid: int) -> datetime | None:
        """Return the exact latest child close once the parent's children are closed."""

        parent = self.ensure_process(hostname, parent_pid)
        return self._registry.process_child_close_deadline(parent.object_id)

    def schedule_process_close(self, intent: ProcessCloseIntent) -> None:
        """Insert or replace one exact process close intent in O(log n)."""

        if self._watermark is not None and intent.close_at <= self._watermark:
            raise StateError(
                f"Process close {intent.action_id} is at or behind lifecycle watermark"
            )
        shard = self._shard(intent.system.hostname)
        with shard.lock:
            shard.process_closes[intent.key] = intent
            handle = shard.process_closes.handle_for(intent.key)
            shard.process_close_deadlines.set(handle, intent.close_at.timestamp())
            shard.process_close_order.push(handle, intent)
            self._mark_strict_locked(
                shard,
                ("process", intent.process_object_id),
                intent.close_at,
            )
            shard.record_high_water()

    def schedule_bounded_process_close(
        self,
        *,
        system: System,
        pid: int,
        username: str,
        process_name: str,
        logon_id: str,
        close_at: datetime,
        eligible_at: datetime | None = None,
    ) -> ProcessCloseIntent:
        """Resolve and queue one exact live process close intent."""

        process = self.ensure_process(system.hostname, pid)
        action_id = stable_uuid(
            "generator-process-close-action",
            process.object_id,
        )
        intent = ProcessCloseIntent(
            system=system,
            pid=pid,
            started_at=process.started_at,
            process_object_id=process.object_id,
            username=username,
            process_name=process_name,
            logon_id=logon_id,
            close_at=close_at,
            action_id=action_id,
            eligible_at=eligible_at,
        )
        self.schedule_process_close(intent)
        return intent

    def process_close_intent(
        self,
        hostname: str,
        pid: int,
        started_at: datetime | None,
    ) -> ProcessCloseIntent | None:
        """Return one exact queued close without scanning PID history."""

        key = (hostname, pid, ensure_utc(started_at) if started_at is not None else None)
        shard = self._shards[self._shard_id(hostname)]
        if shard is None:
            return None
        with shard.lock:
            intent = shard.process_closes.get(key)
            if (
                intent is not None
                and self._watermark is not None
                and intent.close_at <= self._watermark
            ):
                return None
            return intent

    def discard_process_close(
        self,
        hostname: str,
        pid: int,
        started_at: datetime | None,
    ) -> ProcessCloseIntent | None:
        """Remove one exact close intent after another path closed the process."""

        key = (hostname, pid, ensure_utc(started_at) if started_at is not None else None)
        shard = self._shards[self._shard_id(hostname)]
        if shard is None:
            return None
        with shard.lock:
            intent = shard.process_closes.get(key)
            if intent is None:
                return None
            handle = shard.process_closes.handle_for(key)
            shard.process_close_deadlines.pop(handle, None)
            shard.process_closes.pop(key)
            return intent

    def pop_due_process_closes(
        self,
        cutoff: datetime,
        *,
        limit: int = _DEFAULT_DUE_PAGE,
    ) -> tuple[ProcessCloseIntent, ...]:
        """Pop one globally ordered bounded page of due process closes."""

        return self._pop_due_process_closes(ensure_utc(cutoff), limit=limit)

    def has_due_process_closes(self, cutoff: datetime) -> bool:
        """Return whether any process close is dispatch-eligible at ``cutoff``.

        The shard count is fixed at construction, so this is independent of the
        number of queued process lifecycles and never scans close records.
        """

        at = ensure_utc(cutoff)
        for shard in self._shards:
            if shard is None:
                continue
            with shard.lock:
                if (
                    shard.process_close_order.first_due(
                        shard.process_closes,
                        at,
                        inclusive=True,
                    )
                    is not None
                ):
                    return True
        return False

    def _has_canonical_process_close_at_or_before(self, cutoff: datetime) -> bool:
        """Return whether a canonical close deadline blocks watermark advancement."""

        deadline = ensure_utc(cutoff).timestamp()
        for shard in self._shards:
            if shard is None:
                continue
            with shard.lock:
                if (
                    shard.process_close_deadlines.first_due_before(
                        deadline,
                        inclusive=True,
                    )
                    is not None
                ):
                    return True
        return False

    def schedule_deferred_close(self, intent: DeferredLifecycleCloseIntent) -> None:
        """Queue one exact action-owned session close."""

        if self._watermark is not None and intent.close_at <= self._watermark:
            raise StateError(
                f"Deferred close {intent.close_id} is at or behind lifecycle watermark"
            )
        shard = self._shard(intent.hostname)
        with shard.lock:
            existing = shard.deferred_closes.get(intent.close_id)
            if existing is not None and existing != intent:
                raise StateError(f"Deferred lifecycle close ID {intent.close_id} is already in use")
            shard.deferred_closes[intent.close_id] = intent
            handle = shard.deferred_closes.handle_for(intent.close_id)
            shard.deferred_close_deadlines.set(handle, intent.close_at.timestamp())
            shard.deferred_close_order.push(handle, intent)
            self._mark_strict_locked(
                shard,
                ("session", intent.session_object_id),
                intent.close_at,
            )
            shard.record_high_water()

    @staticmethod
    def deferred_close_id(session_object_id: str, close_at: datetime) -> str:
        """Return the stable semantic key for one session-owned deferred close."""

        return stable_uuid(
            "generator-ssh-deferred-close",
            session_object_id,
            ensure_utc(close_at).isoformat(),
        )

    def deferred_close(
        self,
        *,
        hostname: str,
        close_id: str,
    ) -> DeferredLifecycleCloseIntent | None:
        """Peek one exact deferred close without consuming another due intent."""

        shard = self._shards[self._shard_id(hostname)]
        if shard is None:
            return None
        with shard.lock:
            return shard.deferred_closes.get(close_id)

    def take_deferred_close(
        self,
        *,
        hostname: str,
        close_id: str,
        expected: DeferredLifecycleCloseIntent,
    ) -> DeferredLifecycleCloseIntent:
        """CAS-remove one previously validated exact deferred close intent."""

        shard = self._shards[self._shard_id(hostname)]
        if shard is None:
            raise StateError(f"Unknown deferred lifecycle close {close_id}")
        with shard.lock:
            current = shard.deferred_closes.get(close_id)
            if current is not expected:
                raise StateError(
                    f"Deferred lifecycle close {close_id} changed during exact finalization"
                )
            handle = shard.deferred_closes.handle_for(close_id)
            shard.deferred_close_deadlines.pop(handle, None)
            shard.deferred_closes.pop(close_id)
            return current

    def pop_due_deferred_closes(
        self,
        cutoff: datetime,
        *,
        inclusive: bool = False,
        limit: int = _DEFAULT_DUE_PAGE,
    ) -> tuple[DeferredLifecycleCloseIntent, ...]:
        """Pop one globally ordered bounded page of due deferred closes."""

        return self._pop_due_deferred_closes(
            ensure_utc(cutoff),
            inclusive=inclusive,
            limit=limit,
        )

    def mark_strict(
        self,
        subject: LifecycleEntityRef,
        *,
        hostname: str,
        retain_until: datetime,
    ) -> None:
        """Mark one migrated subject for dispatch-time hard lifecycle gates."""

        shard = self._shard(hostname)
        with shard.lock:
            self._mark_strict_locked(
                shard,
                (subject.kind, subject.object_id),
                ensure_utc(retain_until),
            )
            shard.record_high_water()

    @staticmethod
    def _mark_strict_locked(
        shard: _AuthorityShard,
        key: StrictLifecycleKey,
        retain_until: datetime,
    ) -> None:
        current = shard.strict_markers.get(key)
        deadline = max(
            ensure_utc(retain_until),
            current.retain_until if current is not None else ensure_utc(retain_until),
        )
        shard.strict_markers[key] = _StrictLifecycleMarker(key, deadline)
        shard.strict_deadlines.set(shard.strict_markers.handle_for(key), deadline.timestamp())

    def is_strict(self, subject: LifecycleEntityRef, hostname: str) -> bool:
        """Return whether one exact migrated subject uses hard dispatch gates."""

        shard = self._shards[self._shard_id(hostname)]
        if shard is None:
            return False
        with shard.lock:
            marker = shard.strict_markers.get((subject.kind, subject.object_id))
            return marker is not None and (
                self._watermark is None or marker.retain_until > self._watermark
            )

    def event_is_strict(self, event: CanonicalOccurrence) -> bool:
        """Return whether a migrated event subject/session uses hard dispatch gates."""

        plan = event.identity_plan
        if plan is None:
            return False
        identities = (plan.subject, plan.session)
        for identity in identities:
            if isinstance(identity, ProcessIdentity) and self.is_strict(
                LifecycleEntityRef("process", identity.object_id),
                identity.hostname,
            ):
                return True
            if isinstance(identity, SessionIdentity) and self.is_strict(
                LifecycleEntityRef("session", identity.object_id),
                identity.hostname,
            ):
                return True
        return False

    def advance_watermark(self, cutoff: datetime) -> None:
        """Bound auxiliary queues without advancing the canonical registry twice."""

        at = ensure_utc(cutoff)
        if self._watermark is not None and at < self._watermark:
            raise StateError(
                f"Generator lifecycle watermark cannot move backward: "
                f"{at.isoformat()} < {self._watermark.isoformat()}"
            )
        if self._has_canonical_process_close_at_or_before(at):
            raise StateError(
                "Generator lifecycle watermark cannot discard due process closes; "
                "drain bounded close pages before advancing the retention frontier"
            )
        remaining = _DEFAULT_DUE_PAGE
        for shard in self._shards:
            if shard is None or remaining <= 0:
                continue
            with shard.lock:
                expired = shard.strict_deadlines.expire_before_page(
                    at.timestamp(),
                    inclusive=True,
                    limit=remaining,
                )
                remaining -= len(expired)
                for handle, _deadline in expired:
                    try:
                        key = shard.strict_markers.key_by_handle(handle)
                    except KeyError:
                        continue
                    shard.strict_markers.pop(key)
                stores = (
                    shard.process_closes,
                    shard.deferred_closes,
                    shard.strict_markers,
                )
                page = max(1, _DEFAULT_DUE_PAGE // len(stores))
                for store in stores:
                    store.compact_primary(max_slots=page, force=not store)
                shard.process_close_deadlines.compact(max_slots=page)
                shard.deferred_close_deadlines.compact(max_slots=page)
                shard.strict_deadlines.compact(max_slots=page)
                shard.process_close_order.compact(
                    shard.process_closes,
                    max_slots=page,
                )
                shard.deferred_close_order.compact(
                    shard.deferred_closes,
                    max_slots=page,
                )
        self._watermark = at
        self._prune_acknowledged_materialization_batch_transactions(at)

    def census(self) -> GeneratorLifecycleAuthorityCensus:
        """Return structural queue metrics without scanning stored entries."""

        process_closes = 0
        deferred_closes = 0
        strict_markers = 0
        deadline_entries = 0
        deadline_backing = 0
        allocated = 0
        maximum = 0
        high_water = 0
        for shard in self._shards:
            if shard is None:
                continue
            allocated += 1
            with shard.lock:
                process_closes += len(shard.process_closes)
                deferred_closes += len(shard.deferred_closes)
                strict_markers += len(shard.strict_markers)
                metrics = (
                    shard.process_close_deadlines.metrics(),
                    shard.deferred_close_deadlines.metrics(),
                    shard.strict_deadlines.metrics(),
                )
                deadline_entries += sum(metric.live_entries for metric in metrics)
                deadline_backing += sum(metric.backing_entries for metric in metrics) + (
                    shard.process_close_order.backing_entries
                    + shard.deferred_close_order.backing_entries
                )
                live = (
                    len(shard.process_closes)
                    + len(shard.deferred_closes)
                    + len(shard.strict_markers)
                )
                maximum = max(maximum, live)
                high_water += shard.high_water_entries
        with self._materialization_batch_transaction_lock:
            batch_transaction_census = (
                len(self._materialization_batch_transactions),
                self._materialization_batch_transactions_pending,
                self._materialization_batch_transactions_unacknowledged,
                self._materialization_batch_transactions_acknowledged,
                self._materialization_batch_transaction_capacity,
                self._materialization_batch_transaction_high_water,
                self._materialization_batch_transaction_retained_bytes,
                self._materialization_batch_transaction_retained_bytes_high_water,
                self._materialization_batch_transaction_byte_capacity,
            )
        return GeneratorLifecycleAuthorityCensus(
            process_close_intents=process_closes,
            deferred_session_closes=deferred_closes,
            strict_markers=strict_markers,
            deadline_entries=deadline_entries,
            deadline_backing_entries=deadline_backing,
            allocated_shards=allocated,
            shard_count=self._shard_count,
            maximum_shard_entries=maximum,
            high_water_entries=high_water,
            bootstrapped_sessions=self._bootstrapped_sessions,
            bootstrapped_processes=self._bootstrapped_processes,
            watermark=self._watermark,
            materialization_batch_transactions=batch_transaction_census[0],
            materialization_batch_transactions_pending=batch_transaction_census[1],
            materialization_batch_transactions_unacknowledged=batch_transaction_census[2],
            materialization_batch_transactions_acknowledged=batch_transaction_census[3],
            materialization_batch_transaction_capacity=batch_transaction_census[4],
            materialization_batch_transaction_high_water=batch_transaction_census[5],
            materialization_batch_transaction_retained_bytes=batch_transaction_census[6],
            materialization_batch_transaction_retained_bytes_high_water=(
                batch_transaction_census[7]
            ),
            materialization_batch_transaction_byte_capacity=batch_transaction_census[8],
        )

    def _pop_due_process_closes(
        self,
        cutoff: datetime,
        *,
        limit: int,
    ) -> tuple[ProcessCloseIntent, ...]:
        if limit <= 0:
            raise ValueError("Generator lifecycle due-page limit must be positive")
        heap: list[tuple[tuple[datetime, datetime, str, int], int, int]] = []
        for shard_id, shard in enumerate(self._shards):
            if shard is None:
                continue
            with shard.lock:
                head = shard.process_close_order.first_due(
                    shard.process_closes,
                    cutoff,
                    inclusive=True,
                )
                if head is None:
                    continue
                order_key, handle = head
                heapq.heappush(heap, (order_key, shard_id, handle))
        result: list[ProcessCloseIntent] = []
        while heap and len(result) < limit:
            order_key, shard_id, handle = heapq.heappop(heap)
            shard = self._shards[shard_id]
            assert shard is not None
            with shard.lock:
                expected = (order_key, handle)
                head = shard.process_close_order.first_due(
                    shard.process_closes,
                    cutoff,
                    inclusive=True,
                )
                if head != expected or not shard.process_close_order.pop_expected(
                    shard.process_closes,
                    expected,
                ):
                    if head is not None:
                        next_order, next_handle = head
                        heapq.heappush(heap, (next_order, shard_id, next_handle))
                    continue
                try:
                    key = shard.process_closes.key_by_handle(handle)
                    intent = shard.process_closes.get_by_handle(handle)
                except KeyError:
                    shard.process_close_deadlines.pop(handle, None)
                    continue
                shard.process_close_deadlines.pop(handle, None)
                shard.process_closes.pop(key)
                result.append(intent)
                next_head = shard.process_close_order.first_due(
                    shard.process_closes,
                    cutoff,
                    inclusive=True,
                )
                if next_head is not None:
                    next_order, next_handle = next_head
                    heapq.heappush(heap, (next_order, shard_id, next_handle))
        return tuple(result)

    def _pop_due_deferred_closes(
        self,
        cutoff: datetime,
        *,
        inclusive: bool,
        limit: int,
    ) -> tuple[DeferredLifecycleCloseIntent, ...]:
        if limit <= 0:
            raise ValueError("Generator lifecycle due-page limit must be positive")
        heap: list[tuple[tuple[datetime, datetime, str, int], int, int]] = []
        for shard_id, shard in enumerate(self._shards):
            if shard is None:
                continue
            with shard.lock:
                head = shard.deferred_close_order.first_due(
                    shard.deferred_closes,
                    cutoff,
                    inclusive=inclusive,
                )
                if head is None:
                    continue
                order_key, handle = head
                heapq.heappush(heap, (order_key, shard_id, handle))
        result: list[DeferredLifecycleCloseIntent] = []
        while heap and len(result) < limit:
            order_key, shard_id, handle = heapq.heappop(heap)
            shard = self._shards[shard_id]
            assert shard is not None
            with shard.lock:
                expected = (order_key, handle)
                head = shard.deferred_close_order.first_due(
                    shard.deferred_closes,
                    cutoff,
                    inclusive=inclusive,
                )
                if head != expected or not shard.deferred_close_order.pop_expected(
                    shard.deferred_closes,
                    expected,
                ):
                    if head is not None:
                        next_order, next_handle = head
                        heapq.heappush(heap, (next_order, shard_id, next_handle))
                    continue
                try:
                    key = shard.deferred_closes.key_by_handle(handle)
                    intent = shard.deferred_closes.get_by_handle(handle)
                except KeyError:
                    shard.deferred_close_deadlines.pop(handle, None)
                    continue
                shard.deferred_close_deadlines.pop(handle, None)
                shard.deferred_closes.pop(key)
                result.append(intent)
                next_head = shard.deferred_close_order.first_due(
                    shard.deferred_closes,
                    cutoff,
                    inclusive=inclusive,
                )
                if next_head is not None:
                    next_order, next_handle = next_head
                    heapq.heappush(heap, (next_order, shard_id, next_handle))
        return tuple(result)


# Install the public detach method only after the sealed binding allocator exists.
# Detachment never reopens the caller-visible receipt graph.  It resolves one
# exact weak issuance identity and copies the scalar facts sealed beside that
# identity at the canonical commit fence.
def _freeze_issued_prepared_network_detach_method(
    _record_descriptors: tuple[MemberDescriptorType, ...] = (
        _PREPARED_NETWORK_RECEIPT_AUTHORITY_DESCRIPTORS
    ),
    _binding_methods: tuple[Callable[..., object], Callable[..., object], Callable[..., object]] = (
        _DETACHED_NETWORK_BINDING_BOUNDARY_METHODS
    ),
) -> Callable[[GeneratorLifecycleAuthority, object], LifecycleDetachedNetworkReceiptBinding]:
    frozen_authority_type = GeneratorLifecycleAuthority
    frozen_receipt_type = LifecyclePreparedNetworkReceipt
    frozen_record_type = _PreparedNetworkReceiptAuthority
    frozen_record_descriptors = _record_descriptors
    frozen_record_field_count = len(_PREPARED_NETWORK_RECEIPT_AUTHORITY_FIELD_NAMES)
    frozen_binding_type = LifecycleDetachedNetworkReceiptBinding
    frozen_construct = _binding_methods[0]
    frozen_authenticates = _binding_methods[2]
    frozen_type = type
    frozen_int_type = int
    frozen_str_type = str
    frozen_tuple_type = tuple
    frozen_dict_type = dict
    frozen_member_descriptor_type = MemberDescriptorType
    frozen_member_get = MemberDescriptorType.__get__
    frozen_object_getattribute = object.__getattribute__
    frozen_dict_get = dict.get
    frozen_weakref_type = ReferenceType
    frozen_weakref_call = ReferenceType.__call__
    frozen_id = id
    frozen_len = len
    frozen_lock_type = type(RLock())
    frozen_state_error = StateError
    frozen_rejected_errors = (AttributeError, TypeError, ValueError)

    def detach(
        self: GeneratorLifecycleAuthority,
        receipt: object,
    ) -> LifecycleDetachedNetworkReceiptBinding:
        if frozen_type(self) is not frozen_authority_type or frozen_type(receipt) is not (
            frozen_receipt_type
        ):
            raise frozen_state_error(
                "Detached binding requires an authentic prepared-network receipt"
            )
        try:
            planner = frozen_object_getattribute(self, "_source_timing_planner")
            retained_records = frozen_object_getattribute(
                self,
                "_prepared_network_receipt_authorities",
            )
            if planner is None or frozen_type(retained_records) is not frozen_dict_type:
                raise frozen_state_error(
                    "Detached binding requires an authentic prepared-network receipt"
                )
            authority_lock = frozen_object_getattribute(
                planner,
                "_preparation_authority_lock",
            )
            timing_records = frozen_object_getattribute(
                planner,
                "_committed_preparation_receipts",
            )
            if (
                frozen_type(authority_lock) is not frozen_lock_type
                or frozen_type(timing_records) is not frozen_dict_type
            ):
                raise frozen_state_error(
                    "Detached binding requires an authentic prepared-network receipt"
                )
            receipt_id = frozen_id(receipt)
            with authority_lock:
                retained = frozen_dict_get(retained_records, receipt_id)
                if frozen_type(retained) is not frozen_record_type:
                    raise frozen_state_error(
                        "Detached binding requires an authentic prepared-network receipt"
                    )
                captured: list[object] = []
                for descriptor in frozen_record_descriptors:
                    if frozen_type(descriptor) is not frozen_member_descriptor_type:
                        raise frozen_state_error("Detached prepared-network authority is malformed")
                    captured.append(frozen_member_get(descriptor, retained, frozen_record_type))
                if frozen_len(captured) != frozen_record_field_count:
                    raise frozen_state_error("Detached prepared-network authority is malformed")
                (
                    receipt_ref,
                    timing_authority,
                    timing_receipt_id,
                    generation,
                    detached_values,
                    detached_proof,
                    committed,
                    receipt_graph,
                ) = captured
                if (
                    frozen_type(receipt_ref) is not frozen_weakref_type
                    or frozen_weakref_call(receipt_ref) is not receipt
                    or frozen_type(timing_receipt_id) is not frozen_int_type
                    or timing_receipt_id <= 0
                    or frozen_type(generation) is not frozen_int_type
                    or generation <= 0
                    or frozen_type(detached_values) is not frozen_tuple_type
                    or frozen_type(detached_proof) is not frozen_str_type
                    or committed is not True
                    or frozen_type(receipt_graph) is not frozen_tuple_type
                    or not receipt_graph
                    or frozen_dict_get(timing_records, timing_receipt_id) is not timing_authority
                ):
                    raise frozen_state_error(
                        "Detached binding requires an authentic prepared-network receipt"
                    )
            binding = frozen_construct(self, detached_values, detached_proof)
            if frozen_type(binding) is not frozen_binding_type or not frozen_authenticates(
                self,
                binding,
            ):
                raise frozen_state_error("Detached prepared-network proof is not authentic")
            return binding
        except frozen_rejected_errors as error:
            if frozen_type(error) is frozen_state_error:
                raise
            raise frozen_state_error(
                "Detached binding requires an authentic prepared-network receipt"
            ) from error

    detach.__name__ = "detach_prepared_network_receipt"
    detach.__qualname__ = "GeneratorLifecycleAuthority.detach_prepared_network_receipt"
    detach.__doc__ = (
        "Copy the issuance-sealed scalar proof for one exact live prepared receipt.\n\n"
        "The caller-visible receipt graph is never traversed. Byte-identical detached "
        "binding copies remain statelessly equivalent; exact source identity and lifetime "
        "are enforced by the bounded weak issuance record."
    )
    return detach


GeneratorLifecycleAuthority.detach_prepared_network_receipt = (
    _freeze_issued_prepared_network_detach_method()
)


# Security-boundary functions captured exact sealed handlers and inert contract
# data in distinct closure cells while the module initialized. Do not retain a
# replaceable module alias to either side of those boundaries.
del _DETACHED_NETWORK_BINDING_BOUNDARY_CAPABILITY
del _DETACHED_NETWORK_BINDING_BOUNDARY_METHODS
del _PREPARED_NETWORK_RECEIPT_AUTHORITY_DESCRIPTORS
