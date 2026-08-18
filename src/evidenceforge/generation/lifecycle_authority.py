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
from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from threading import Condition, Lock, RLock, Thread, current_thread
from typing import Any, Generic, Literal, Protocol, TypeVar

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
    ApplicationChannelRegistry,
)
from evidenceforge.generation.http_channels import (
    HttpApplicationChannelManager,
    HttpChannelAdmissionResult,
    HttpChannelAdmissionToken,
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
    ProcessLifecycleSnapshot,
)
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.generation.network_runtime import (
    NetworkConnectionCommitResult,
    NetworkTransactionPreparationReceipt,
    NetworkTransactionRuntime,
    NetworkTransportLifecycleMode,
    PreparedNetworkTransactionRoot,
)
from evidenceforge.generation.proxy_channels import (
    ExplicitProxyAdmissionCommitResult,
    ExplicitProxyAdmissionToken,
    ExplicitProxyChannelManager,
)
from evidenceforge.generation.source_timing import (
    SourceTimingPlanner,
    SourceTimingPreparation,
    SourceTimingPreparationReceipt,
    SourceTimingPreparationToken,
)
from evidenceforge.generation.state_manager import (
    ActionCohortMaterializationPlan,
    ConnectionCompositeMaterializationPlan,
    ConnectionCompositeMaterializationResult,
    ConnectionMaterializationMode,
    MaterializationBatchPlan,
    PhysicalTransportFingerprint,
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
_MAX_MATERIALIZATION_BATCH_TRANSACTION_BYTES = 4 * 1024 * 1024
_MAX_MATERIALIZATION_BATCH_PAYLOAD_NODES = 65_536
_MAX_MATERIALIZATION_BATCH_SCALAR_BYTES = 64 * 1024

_ApplicationAdmissionToken = (
    ApplicationChannelAdmissionToken | HttpChannelAdmissionToken | ExplicitProxyAdmissionToken
)
_ApplicationAdmissionResult = (
    ApplicationChannelAdmissionResult
    | HttpChannelAdmissionResult
    | ExplicitProxyAdmissionCommitResult
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

    manager_kind: Literal["protocol_neutral", "http", "explicit_proxy"]
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


@dataclass(frozen=True, slots=True)
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


@dataclass(frozen=True, slots=True)
class LifecyclePreparedNetworkResult:
    """Exact committed connection, runtime, and source-timing results."""

    connection: LifecycleConnectionCompositeResult
    runtime: NetworkTransactionPreparationReceipt
    timing: SourceTimingPreparationReceipt
    receipt: LifecyclePreparedNetworkReceipt


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
        self._network_runtime: NetworkTransactionRuntime | None = None
        self._source_timing_planner: SourceTimingPlanner | None = None

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
        if batch is None:
            return ()
        return tuple(
            member.publication_token
            for member in (
                *((batch.session,) if batch.session is not None else ()),
                *batch.processes,
            )
        )

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
        if identity.parent_pid not in {0, 4}:
            parent = self._registry.process_for_pid_at(
                identity.hostname,
                identity.parent_pid,
                identity.started_at,
            )
            if parent is None:
                raise StateError(
                    "Action cohort registered process has no exact lifecycle parent: "
                    f"{identity.object_id}"
                )
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
        if batch is None:
            return ()
        session_plan = batch.session
        staged_session = session_plan.identity if session_plan is not None else None
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

        staged_processes: dict[tuple[str, int], ProcessIdentity] = {}
        for process_plan in batch.processes:
            identity = process_plan.identity
            parent_object_id = ""
            if identity.parent_pid:
                staged_parent = staged_processes.get((identity.hostname, identity.parent_pid))
                if staged_parent is not None:
                    parent_object_id = staged_parent.object_id
                else:
                    parent = self._state_manager.get_process_identity(
                        identity.hostname,
                        identity.parent_pid,
                    )
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
        registry = self._application_registry
        if registry is None or not isinstance(result, ApplicationChannelAdmissionResult):
            raise AssertionError("Common application commit returned an incompatible result")
        receipt = result.receipt
        if receipt is None or not registry.authenticates_admission_receipt(receipt):
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
    ) -> object:
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
            ),
        ):
            raise AssertionError("Application manager returned an incompatible commit result")
        return result

    def materialize_connection_composite(
        self,
        plan: ConnectionCompositeMaterializationPlan,
        owner_rng: random.Random,
        *,
        lifecycle_token: LifecycleClosedTransportAdmissionToken | None = None,
        application_token: _ApplicationAdmissionToken | None = None,
        prerequisite_receipts: tuple[LifecycleConnectionCompositeReceipt, ...] = (),
        finalize_external_no_fail: Callable[[], None] | None = None,
    ) -> LifecycleConnectionCompositeResult:
        """Atomically consume and publish State, lifecycle, and application admissions.

        Passing an admission token transfers its one-shot reservation to this
        authority. Every failure path releases still-uncommitted exact capabilities;
        committed prior receipts remain immutable proof inputs and are never consumed.
        ``finalize_external_no_fail`` runs last while every lower authority fence is
        retained and must contain only already-claimed, structurally no-fail commits.
        """

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
                    if lifecycle_commit is not None:
                        lifecycle_receipt = lifecycle_commit.commit_no_fail()
                    state_result = state_commit.commit()
                    if application_commit is not None:
                        application_result = self._commit_application_admission_no_fail(
                            application_commit
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
        except BaseException:
            self._discard_connection_composite_admissions(
                lifecycle_token,
                application_token,
            )
            raise

        receipt = LifecycleConnectionCompositeReceipt._issue(
            authority_secret=self._receipt_secret,
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
        return LifecycleConnectionCompositeResult(
            state=state_result,
            lifecycle=lifecycle_receipt,
            application=application_result,
            receipt=receipt,
        )

    @staticmethod
    def _prepared_network_result_digest(result: NetworkConnectionCommitResult) -> str:
        """Return the exact immutable commit-result digest bound into the outer receipt."""

        if type(result) is not NetworkConnectionCommitResult:
            raise StateError("Prepared network root has no exact commit result")
        return sha256(repr(("prepared-network-result-v1", result)).encode()).hexdigest()

    def _authenticates_issued_prepared_network_receipt(self, receipt: object) -> bool:
        """Authenticate a complete prior receipt without retained caller root state."""

        runtime = self._network_runtime
        planner = self._source_timing_planner
        if (
            runtime is None
            or planner is None
            or type(receipt) is not LifecyclePreparedNetworkReceipt
        ):
            return False
        try:
            if (
                type(receipt._runtime_publication_token) is not str
                or not receipt._runtime_publication_token
                or type(receipt._state_publication_token) is not str
                or not receipt._state_publication_token
                or type(receipt._transaction_id) is not str
                or not receipt._transaction_id
                or type(receipt._materialization_mode) is not ConnectionMaterializationMode
                or receipt._lifecycle_mode not in {"network", "application_child"}
                or type(receipt._physical_transport) is not PhysicalTransportFingerprint
                or type(receipt._result_digest) is not str
                or not receipt._result_digest
                or type(receipt._timing_binding_token) is not SourceTimingPreparationToken
                or type(receipt._connection_receipt) is not LifecycleConnectionCompositeReceipt
                or type(receipt._runtime_receipt) is not NetworkTransactionPreparationReceipt
                or type(receipt._timing_receipt) is not SourceTimingPreparationReceipt
                or type(receipt._integrity_token) is not str
                or not receipt._integrity_token
                or not receipt._has_valid_integrity(self._receipt_secret)
                or not self._authenticates_issued_connection_receipt(receipt._connection_receipt)
                or not runtime.authenticates_preparation_receipt(receipt._runtime_receipt)
                or not planner.authenticates_preparation_receipt(receipt._timing_receipt)
            ):
                return False
            connection_receipt = receipt._connection_receipt
            runtime_receipt = receipt._runtime_receipt
            timing_receipt = receipt._timing_receipt
            if (
                receipt._runtime_publication_token != runtime_receipt.publication_token
                or receipt._state_publication_token != connection_receipt._state_publication_token
                or receipt._transaction_id != connection_receipt.transaction_id
                or receipt._transaction_id != runtime_receipt.transaction_id
                or receipt._physical_transport != connection_receipt._physical_transport
                or receipt._timing_binding_token != timing_receipt.binding_token
            ):
                return False
            if receipt._materialization_mode is ConnectionMaterializationMode.PHYSICAL:
                return (
                    receipt._lifecycle_mode == "network"
                    and connection_receipt.materializes_connection
                )
            return (
                receipt._materialization_mode is ConnectionMaterializationMode.APPLICATION_CHILD
                and receipt._lifecycle_mode == "application_child"
                and not connection_receipt.materializes_connection
            )
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

    def _validate_prepared_network_transaction(
        self,
        root: PreparedNetworkTransactionRoot,
        source_timing_preparation: SourceTimingPreparation,
        lifecycle_token: LifecycleClosedTransportAdmissionToken | None,
        application_token: _ApplicationAdmissionToken | None,
        prerequisite_receipts: tuple[LifecyclePreparedNetworkReceipt, ...],
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
        if root.runtime_token.lifecycle_mode == "deferred_session":
            raise StateError("Deferred-session network roots require their session authority")
        if root.runtime_token.lifecycle_mode not in {"network", "application_child"}:
            raise StateError("Prepared network root has an unsupported lifecycle mode")
        if root.state_plan.mode is ConnectionMaterializationMode.PHYSICAL:
            if root.runtime_token.lifecycle_mode != "network":
                raise StateError("Physical prepared network root requires network lifecycle mode")
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
        """Atomically publish a sealed network root through every owning authority.

        Source timing is claimed first, followed by the network runtime, application
        manager, StateManager, and lifecycle registry. The no-fail tail commits in
        lifecycle, State, application, runtime/crypto, then source-timing order.
        Every failure releases all still-uncommitted transferred capabilities.
        """

        runtime_receipt: NetworkTransactionPreparationReceipt | None = None
        expected_timing_receipt: SourceTimingPreparationReceipt | None = None
        timing_receipt: SourceTimingPreparationReceipt | None = None
        try:
            connection_prerequisites = self._validate_prepared_network_transaction(
                root,
                source_timing_preparation,
                lifecycle_token,
                application_token,
                prerequisite_receipts,
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
                    raise StateError("Prepared network source timing receipt failed authentication")
                with runtime.claimed_preparation(root.runtime_token) as runtime_commit:
                    timing_commit.certify_composite_commit(expected_timing_receipt)

                    def _finalize_prepared_network_no_fail() -> None:
                        nonlocal runtime_receipt, timing_receipt
                        runtime_receipt = runtime_commit.commit_no_fail()
                        timing_receipt = timing_commit.commit_no_fail()

                    connection_result = self.materialize_connection_composite(
                        root.state_plan,
                        owner_rng,
                        lifecycle_token=lifecycle_token,
                        application_token=application_token,
                        prerequisite_receipts=connection_prerequisites,
                        finalize_external_no_fail=_finalize_prepared_network_no_fail,
                    )
        except BaseException:
            self._discard_prepared_network_transaction(
                root,
                source_timing_preparation,
                lifecycle_token,
                application_token,
            )
            raise

        if runtime_receipt is None or expected_timing_receipt is None or timing_receipt is None:
            raise AssertionError("Prepared network finalizer returned no complete receipts")
        if timing_receipt is not expected_timing_receipt:
            raise AssertionError("Source timing finalizer returned a different receipt object")
        runtime = self._network_runtime
        planner = self._source_timing_planner
        assert runtime is not None and planner is not None
        if not runtime.authenticates_preparation_receipt(
            runtime_receipt,
            token=root.runtime_token,
        ):
            raise AssertionError("Network runtime returned an unauthenticated receipt")
        if not planner.authenticates_preparation_receipt(timing_receipt):
            raise AssertionError("Source timing planner returned an unauthenticated receipt")
        result_digest = self._prepared_network_result_digest(root.result)
        receipt = LifecyclePreparedNetworkReceipt._issue(
            authority_secret=self._receipt_secret,
            runtime_publication_token=root.runtime_token.publication_token,
            state_publication_token=root.state_plan.publication_token,
            transaction_id=root.transaction.stable_id,
            materialization_mode=root.state_plan.mode,
            lifecycle_mode=root.runtime_token.lifecycle_mode,
            physical_transport=root.state_plan.physical_transport_fingerprint,
            result_digest=result_digest,
            timing_binding_token=source_timing_preparation.binding_token,
            connection_receipt=connection_result.receipt,
            runtime_receipt=runtime_receipt,
            timing_receipt=timing_receipt,
        )
        return LifecyclePreparedNetworkResult(
            connection=connection_result,
            runtime=runtime_receipt,
            timing=timing_receipt,
            receipt=receipt,
        )

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
            if (
                type(root.result) is not NetworkConnectionCommitResult
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
                or not runtime.authenticates_preparation_receipt(
                    receipt.runtime_receipt,
                    token=root.runtime_token,
                )
            ):
                return False
            return self.authenticates_connection_composite_receipt(
                root.state_plan,
                receipt.connection_receipt,
            )
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
                    parent_object_id = staged_parent.object_id
                else:
                    parent = self._state_manager.get_process_identity(
                        identity.hostname,
                        identity.parent_pid,
                    )
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

        identity = plan.identity
        parent_object_id = ""
        if identity.parent_pid:
            parent = self._state_manager.get_process_identity(
                identity.hostname,
                identity.parent_pid,
            )
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
