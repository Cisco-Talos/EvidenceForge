# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Single typed action-keyed continuation for persistent SMB production."""

from __future__ import annotations

import hashlib
import random
import secrets
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from threading import Lock, get_ident
from typing import Any, Literal

from evidenceforge.events.dispatcher import (
    PersistentSmbSourcePublicationResult,
    PreparedActionCohortProjection,
    PreparedDispatch,
    PreparedPersistentSmbSourcePublication,
)
from evidenceforge.events.network import (
    NetworkSensorObservation,
    NetworkTrafficLedger,
    NetworkTransactionPlan,
)
from evidenceforge.generation.lifecycle_authority import (
    LifecycleDetachedNetworkReceiptBinding,
    LifecyclePreparedNetworkReceipt,
    LifecyclePreparedNetworkResult,
)
from evidenceforge.generation.lifecycle_registry import (
    LifecycleClosedTransportAdmissionToken,
)
from evidenceforge.generation.network_observation import PersistentSmbTrafficRebindBinding
from evidenceforge.generation.network_runtime import PreparedNetworkTransactionRoot
from evidenceforge.generation.persistent_smb_projection import (
    PersistentSmbProjectionGroupToken,
    PersistentSmbProjectionMemberCertification,
    PersistentSmbProjectionMemberToken,
    PersistentSmbProjectionPhase,
)
from evidenceforge.generation.smb_channels import (
    SmbApplicationChannelManager,
    SmbChannelAdmissionResult,
    SmbChannelAdmissionToken,
    SmbChannelAffinity,
    SmbClosedSessionBatch,
    SmbCompletedHandleView,
    SmbCompletedOperationPlan,
    SmbCompletedOperationView,
)
from evidenceforge.generation.source_timing import (
    SourceTimingActionCapacityReservation,
    SourceTimingPreparation,
)
from evidenceforge.generation.state_manager import (
    ActionCohortMaterializationPlan,
    SmbConnectionFinalizationResult,
    SmbConnectionPinInstallReceipt,
    SmbFileMutationCommitResult,
    SmbFileMutationJournal,
)
from evidenceforge.generation.storage_world import CompiledStorageFile
from evidenceforge.models.exceptions import EventContractError

MAX_PERSISTENT_SMB_OPERATIONS = 64
_MAX_PERSISTENT_SMB_ACTIVITY_BYTES = 2 * 1024 * 1024
_MAX_PERSISTENT_SMB_ACTIVITY_TEXT_BYTES = 256 * 1024
_MAX_SIGNED_63 = (1 << 63) - 1
_PERSISTENT_SMB_OPERATION_KEYS = frozenset(
    {
        "operation",
        "share",
        "path",
        "file_id",
        "content_version",
        "size_bytes",
        "outcome",
        "fuid",
    }
)
_PERSISTENT_SMB_OPERATION_KINDS = frozenset(
    {"browse", "read", "create", "update", "copy", "move", "delete"}
)
_PERSISTENT_SMB_OUTCOMES = frozenset({"success", "access_denied", "not_found", "sharing_violation"})


class NetworkConnectionPublicationOutcome(StrEnum):
    """Typed internal disposition of one committed canonical network root."""

    PUBLISHED = "published"
    COMMITTED_SUPPRESSED = "committed_suppressed"


@dataclass(frozen=True, slots=True)
class PersistentSmbRootHandoff:
    """Exact retained owners needed to continue one committed SMB root."""

    materialization: LifecyclePreparedNetworkResult = field(compare=False, repr=False)
    lifecycle_binding: LifecycleDetachedNetworkReceiptBinding = field(
        compare=False,
        repr=False,
    )
    file_journal: SmbFileMutationJournal = field(compare=False, repr=False)
    prepared_dispatch: PreparedDispatch = field(compare=False, repr=False)
    observations: tuple[NetworkSensorObservation, ...]
    pin_install_receipt: SmbConnectionPinInstallReceipt
    file_mutation: SmbFileMutationCommitResult
    application_token: SmbChannelAdmissionToken = field(compare=False, repr=False)
    application_result: SmbChannelAdmissionResult


@dataclass(frozen=True, slots=True)
class SmbActivityResult:
    """Ground-truth summary for one bounded SMB activity burst."""

    session_id: str
    tree_ids: tuple[str, ...]
    transport_uids: tuple[str, ...]
    operations: tuple[dict[str, Any], ...]
    completed_at: datetime


@dataclass(frozen=True, slots=True)
class _PersistentSmbOperationSnapshot:
    """Private callback-free truth for one persistent SMB operation."""

    operation: str
    share: str
    path: str
    file_id: str
    content_version: int
    size_bytes: int
    outcome: str
    fuid: str | None


@dataclass(frozen=True, slots=True)
class _PersistentSmbActivitySnapshot:
    """Private immutable activity truth retained across terminal retries."""

    session_id: str
    tree_ids: tuple[str, ...]
    transport_uids: tuple[str, ...]
    operations: tuple[_PersistentSmbOperationSnapshot, ...]
    completed_at: datetime


@dataclass(frozen=True, slots=True)
class PersistentSmbActivityCapture:
    """Opaque authenticated capture of one activity result and its root binding."""

    snapshot: _PersistentSmbActivitySnapshot = field(compare=False, repr=False)
    activity_digest: str
    binding_digest: str


@dataclass(frozen=True, slots=True)
class SmbOperationTiming:
    """One deterministic operation's bounded wire and lifecycle timing."""

    setup_seconds: float
    jitter_seconds: float
    transfer_seconds: float
    close_delay_seconds: float

    @property
    def total_seconds(self) -> float:
        """Return the complete open-to-close budget for the operation."""

        return (
            self.setup_seconds
            + self.jitter_seconds
            + self.transfer_seconds
            + self.close_delay_seconds
        )


@dataclass(frozen=True, slots=True)
class PersistentSmbPreparedOperation:
    """Bounded immutable file/source facts frozen before the physical root."""

    state: CompiledStorageFile
    timing: SmbOperationTiming
    phase_type: str
    phase: str
    action_time: datetime
    handle_close_time: datetime
    previous_path: str
    previous_client_path: str
    previous_server_path: str


@dataclass(frozen=True, slots=True)
class PersistentSmbClientProcessPreparation:
    """Allocation-free source-client actor recipe retained across SMB retries."""

    disposition: Literal["none", "reuse", "materialize"]
    hostname: str
    process_object_id: str
    pid: int
    parent_pid: int
    parent_object_id: str
    image: str
    command_line: str
    username: str
    logon_id: str
    session_object_id: str
    session_id: int
    logon_type: int
    started_at: datetime | None
    lifecycle_group_id: str
    os_category: Literal["windows", "linux"]
    integrity_level: str
    access_mode: str
    path_style: str
    transport_attribution: Literal["kernel", "process"]
    lifecycle: str

    def __post_init__(self) -> None:
        """Reject ambiguous recipes before any State or source owner is reserved."""

        if self.disposition == "none":
            if any(
                (
                    self.hostname,
                    self.process_object_id,
                    self.parent_object_id,
                    self.image,
                    self.command_line,
                    self.username,
                    self.logon_id,
                    self.session_object_id,
                    self.lifecycle_group_id,
                    self.access_mode,
                    self.path_style,
                    self.lifecycle,
                )
            ) or any((self.pid, self.parent_pid, self.session_id, self.logon_type)):
                raise ValueError("Empty persistent SMB client process recipe changed shape")
            if self.started_at is not None:
                raise ValueError("Empty persistent SMB client process recipe has a start time")
            return
        required = (
            self.hostname,
            self.image,
            self.command_line,
            self.username,
            self.logon_id,
            self.session_object_id,
            self.lifecycle_group_id,
            self.integrity_level,
            self.access_mode,
            self.path_style,
            self.lifecycle,
        )
        if any(type(value) is not str or not value for value in required):
            raise ValueError("Persistent SMB client process recipe requires complete identity")
        if self.started_at is None or type(self.started_at) is not datetime:
            raise TypeError("Persistent SMB client process recipe requires an exact start time")
        object.__setattr__(self, "started_at", self.started_at.astimezone(UTC))
        if self.pid < 0 or self.parent_pid < 0 or self.session_id < 0 or self.logon_type <= 0:
            raise ValueError("Persistent SMB client process recipe has invalid numeric identity")
        if self.disposition == "reuse":
            if self.pid <= 0 or not self.process_object_id:
                raise ValueError("Persistent SMB process reuse requires an exact live object")
        elif self.disposition == "materialize":
            if self.pid != 0 or self.process_object_id:
                raise ValueError("Persistent SMB process materialization cannot preassign identity")
        else:
            raise ValueError("Persistent SMB client process disposition is unsupported")

    @classmethod
    def none(cls) -> PersistentSmbClientProcessPreparation:
        """Return the exact actorless client recipe."""

        return cls(
            disposition="none",
            hostname="",
            process_object_id="",
            pid=0,
            parent_pid=0,
            parent_object_id="",
            image="",
            command_line="",
            username="",
            logon_id="",
            session_object_id="",
            session_id=0,
            logon_type=0,
            started_at=None,
            lifecycle_group_id="",
            os_category="windows",
            integrity_level="",
            access_mode="",
            path_style="",
            transport_attribution="kernel",
            lifecycle="",
        )

    def identity_snapshot(self) -> tuple[object, ...]:
        """Return the exact scalar identity safe for network-request hashing."""

        return (
            self.disposition,
            self.hostname,
            self.process_object_id,
            self.pid,
            self.parent_pid,
            self.parent_object_id,
            self.image,
            self.command_line,
            self.username,
            self.logon_id,
            self.session_object_id,
            self.session_id,
            self.logon_type,
            self.started_at,
            self.lifecycle_group_id,
            self.os_category,
            self.integrity_level,
            self.access_mode,
            self.path_style,
            self.transport_attribution,
            self.lifecycle,
        )

    @classmethod
    def from_identity_snapshot(cls, snapshot: object) -> PersistentSmbClientProcessPreparation:
        """Reconstruct one validated recipe without accepting callback-capable values."""

        if type(snapshot) is not tuple or len(snapshot) != 21:
            raise TypeError("Persistent SMB client process snapshot requires 21 scalar fields")
        if snapshot[13] is not None and type(snapshot[13]) is not datetime:
            raise TypeError("Persistent SMB client process snapshot has an invalid start time")
        return cls(*snapshot)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class PersistentSmbActionPreparation:
    """Exact reversible operation and mutation recipe retained before the TCP root."""

    auth_time: datetime
    tree_time: datetime
    close_time: datetime
    auth_session_ref: str
    affinity: SmbChannelAffinity
    byte_allocations: tuple[tuple[int, int], ...]
    journal: SmbFileMutationJournal
    operation_plans: tuple[SmbCompletedOperationPlan, ...]
    operations: tuple[PersistentSmbPreparedOperation, ...]
    client_process: PersistentSmbClientProcessPreparation


@dataclass(frozen=True, slots=True)
class PersistentSmbPreparedRoot:
    """Exact retry inputs sealed before the ordinary network root transfers."""

    root: PreparedNetworkTransactionRoot
    owner_rng: random.Random = field(compare=False, repr=False)
    source_timing_preparation: SourceTimingPreparation = field(compare=False, repr=False)
    lifecycle_token: LifecycleClosedTransportAdmissionToken
    application_token: SmbChannelAdmissionToken = field(compare=False, repr=False)
    file_journal: SmbFileMutationJournal = field(compare=False, repr=False)
    prerequisite_receipts: tuple[LifecyclePreparedNetworkReceipt, ...]
    prepared_dispatch: PreparedDispatch = field(compare=False, repr=False)
    observations: tuple[NetworkSensorObservation, ...]
    outcome: NetworkConnectionPublicationOutcome


@dataclass(frozen=True, slots=True)
class PersistentSmbPreparedSource:
    """All exact source/finalization owners frozen before terminal mutation."""

    opening: NetworkTransactionPlan
    lifecycle_receipt: LifecyclePreparedNetworkReceipt
    lifecycle_binding: LifecycleDetachedNetworkReceiptBinding
    traffic_binding: PersistentSmbTrafficRebindBinding
    final_transaction: NetworkTransactionPlan
    final_observation_traffic: tuple[NetworkTrafficLedger, ...]
    state_plan: ActionCohortMaterializationPlan
    source_carrier: PreparedPersistentSmbSourcePublication
    source_projections: tuple[PreparedActionCohortProjection, ...]
    publication_binding_digest: str
    timing_preparation: SourceTimingPreparation
    source_timing_capacity: SourceTimingActionCapacityReservation
    member_work: tuple[PersistentSmbProjectionMemberToken, ...]
    target_formats: tuple[str, ...]
    lifecycle_digest: str
    lifecycle_generation: int
    network_digest: str
    network_generation: int
    traffic_digest: str
    traffic_generation: int
    activity_capture: PersistentSmbActivityCapture


PersistentSmbProjectionMemberSpec = tuple[
    PersistentSmbProjectionPhase,
    str,
    str,
    bytes,
]


@dataclass(frozen=True, slots=True)
class PersistentSmbSourceBuilding:
    """Exact source shell and member plan retained before the first append."""

    source_shell: PersistentSmbPreparedSource
    member_specs: tuple[PersistentSmbProjectionMemberSpec, ...]


class PersistentSmbTerminalContinuation:
    """Opaque exact action-level cursor spanning reversible planning through release."""

    __slots__ = ("_authority_id", "_consumed", "_continuation_id", "_integrity")

    def __init__(
        self,
        *,
        authority_id: str,
        continuation_id: int,
        integrity: str,
    ) -> None:
        self._authority_id = authority_id
        self._continuation_id = continuation_id
        self._integrity = integrity
        self._consumed = False


@dataclass(frozen=True, slots=True)
class PersistentSmbTerminalContinuationCensus:
    """Constant-time bounded terminal-continuation retention metrics."""

    retained_continuations: int
    active_claims: int
    retained_bytes: int
    capacity: int
    byte_capacity: int
    high_water_continuations: int
    high_water_bytes: int


@dataclass(frozen=True, slots=True)
class PersistentSmbTerminalFacts:
    """Exact immutable terminal owner set exposed only to one active claim."""

    cursor: int
    action_id: str
    action_binding_digest: str
    member_budget: int
    source_carrier: PreparedPersistentSmbSourcePublication
    source_result: PersistentSmbSourcePublicationResult
    file_mutation: SmbFileMutationCommitResult
    finalization: SmbConnectionFinalizationResult
    activity_result: SmbActivityResult
    source_timing_capacity: SourceTimingActionCapacityReservation
    handoff: PersistentSmbRootHandoff | None
    receipt: object | None


PersistentSmbContinuationPhase = Literal[
    "reserved",
    "action_prepared",
    "cancelling",
    "root_prepared",
    "root_committed",
    "source_building",
    "source_prepared",
    "source_published",
]


@dataclass(frozen=True, slots=True)
class PersistentSmbRootFacts:
    """Exact phase-specific owners exposed to the one active action claim."""

    phase: PersistentSmbContinuationPhase
    cleanup_cursor: int
    action_id: str
    action_binding_digest: str
    member_budget: int
    projection_group: PersistentSmbProjectionGroupToken | None
    source_reservation: PreparedPersistentSmbSourcePublication | None
    source_timing_capacity: SourceTimingActionCapacityReservation | None
    action_preparation: PersistentSmbActionPreparation | None
    prepared_root: PersistentSmbPreparedRoot | None
    materialization: LifecyclePreparedNetworkResult | None
    handoff: PersistentSmbRootHandoff | None
    outcome: NetworkConnectionPublicationOutcome | None
    source_building: PersistentSmbSourceBuilding | None
    source_build_members: tuple[PersistentSmbProjectionMemberToken, ...]
    source_preparation: PersistentSmbPreparedSource | None
    source_certifications: tuple[PersistentSmbProjectionMemberCertification, ...]


@dataclass(slots=True)
class _PersistentSmbTerminalRecord:
    continuation: PersistentSmbTerminalContinuation
    continuation_id: int
    action_id: str
    action_binding_digest: str
    phase: PersistentSmbContinuationPhase
    projection_group: PersistentSmbProjectionGroupToken | None
    source_reservation: PreparedPersistentSmbSourcePublication | None
    source_timing_capacity: SourceTimingActionCapacityReservation | None
    action_preparation: PersistentSmbActionPreparation | None
    prepared_root: PersistentSmbPreparedRoot | None
    materialization: LifecyclePreparedNetworkResult | None
    handoff: PersistentSmbRootHandoff | None
    outcome: NetworkConnectionPublicationOutcome | None
    source_building: PersistentSmbSourceBuilding | None
    source_build_members: tuple[PersistentSmbProjectionMemberToken, ...]
    source_preparation: PersistentSmbPreparedSource | None
    source_certifications: tuple[PersistentSmbProjectionMemberCertification, ...]
    source_carrier: PreparedPersistentSmbSourcePublication | None
    source_result: PersistentSmbSourcePublicationResult | None
    file_mutation: SmbFileMutationCommitResult | None
    finalization: SmbConnectionFinalizationResult | None
    activity_capture: PersistentSmbActivityCapture | None
    activity_digest: str
    activity_binding_digest: str
    external_transport_uids: tuple[str, ...]
    retained_bytes: int
    integrity: str
    cursor: int = 0
    cleanup_cursor: int = 0
    active_thread_id: int | None = None


class PersistentSmbTerminalContinuationAuthority:
    """Single bounded exact owner for one persistent SMB action's whole continuation."""

    def __init__(
        self,
        *,
        capacity: int = 1_024,
        byte_capacity: int = 64 * 1024 * 1024,
        smb_channel_manager: SmbApplicationChannelManager | None = None,
    ) -> None:
        if type(capacity) is not int or capacity <= 0:
            raise ValueError("Persistent SMB terminal capacity must be a positive exact int")
        if type(byte_capacity) is not int or byte_capacity <= 0:
            raise ValueError("Persistent SMB terminal byte capacity must be a positive exact int")
        if (
            smb_channel_manager is not None
            and type(smb_channel_manager) is not SmbApplicationChannelManager
        ):
            raise TypeError("Persistent SMB terminal authority requires its exact SMB manager")
        self._authority_id = secrets.token_hex(16)
        self._secret = secrets.token_bytes(32)
        self._capacity = capacity
        self._byte_capacity = byte_capacity
        self._smb_channel_manager = smb_channel_manager
        self._lock = Lock()
        self._next_continuation_id = 1
        self._records_by_action: dict[str, _PersistentSmbTerminalRecord] = {}
        self._records_by_carrier: dict[int, _PersistentSmbTerminalRecord] = {}
        self._active_claims = 0
        self._retained_bytes = 0
        self._high_water_continuations = 0
        self._high_water_bytes = 0

    @staticmethod
    def _bounded_action_id(action_id: object) -> str:
        if (
            type(action_id) is not str
            or not action_id
            or len(action_id) > 512
            or len(action_id.encode("utf-8")) > 512
        ):
            raise EventContractError("Persistent SMB terminal action ID is invalid or oversized")
        return action_id

    @staticmethod
    def _binding_digest(binding_digest: object) -> str:
        if type(binding_digest) is not str or len(binding_digest) != 64:
            raise EventContractError("Persistent SMB terminal binding requires one SHA-256 digest")
        try:
            encoded = binding_digest.encode("ascii")
        except UnicodeEncodeError as error:
            raise EventContractError(
                "Persistent SMB terminal binding requires one SHA-256 digest"
            ) from error
        if any(byte not in b"0123456789abcdef" for byte in encoded):
            raise EventContractError("Persistent SMB terminal binding requires one SHA-256 digest")
        return binding_digest

    @staticmethod
    def _activity_text(value: object, *, field_name: str, allow_empty: bool = False) -> str:
        if type(value) is not str or (not value and not allow_empty):
            raise EventContractError(
                f"Persistent SMB terminal {field_name} has an invalid exact text value"
            )
        if len(value) > _MAX_PERSISTENT_SMB_ACTIVITY_TEXT_BYTES:
            raise EventContractError(f"Persistent SMB terminal {field_name} exceeds its text bound")
        if len(value.encode("utf-8")) > _MAX_PERSISTENT_SMB_ACTIVITY_TEXT_BYTES:
            raise EventContractError(f"Persistent SMB terminal {field_name} exceeds its text bound")
        return value

    @classmethod
    def _freeze_activity_result(
        cls,
        result: SmbActivityResult,
    ) -> tuple[_PersistentSmbActivitySnapshot, str]:
        if type(result) is not SmbActivityResult:
            raise EventContractError("Persistent SMB terminal result has an invalid exact type")
        session_id = cls._activity_text(
            object.__getattribute__(result, "session_id"),
            field_name="session_id",
        )
        tree_ids = object.__getattribute__(result, "tree_ids")
        transport_uids = object.__getattribute__(result, "transport_uids")
        operations = object.__getattribute__(result, "operations")
        completed_at = object.__getattribute__(result, "completed_at")
        if (
            type(tree_ids) is not tuple
            or len(tree_ids) != 1
            or type(transport_uids) is not tuple
            or len(transport_uids) != 1
            or type(operations) is not tuple
            or not 1 <= len(operations) <= MAX_PERSISTENT_SMB_OPERATIONS
            or type(completed_at) is not datetime
            or completed_at.tzinfo is not UTC
        ):
            raise EventContractError("Persistent SMB terminal result has an invalid exact shape")
        canonical_tree_ids = tuple(
            cls._activity_text(item, field_name="tree_id") for item in tree_ids
        )
        canonical_transport_uids = tuple(
            cls._activity_text(item, field_name="transport_uid") for item in transport_uids
        )
        frozen_operations: list[_PersistentSmbOperationSnapshot] = []
        for operation in operations:
            if type(operation) is not dict or len(operation) != len(_PERSISTENT_SMB_OPERATION_KEYS):
                raise EventContractError(
                    "Persistent SMB terminal operation has an invalid exact shape"
                )
            copied = dict.copy(operation)
            keys = tuple(copied.keys())
            if any(type(key) is not str for key in keys) or frozenset(keys) != (
                _PERSISTENT_SMB_OPERATION_KEYS
            ):
                raise EventContractError(
                    "Persistent SMB terminal operation has an invalid exact schema"
                )
            operation_kind = cls._activity_text(
                dict.__getitem__(copied, "operation"),
                field_name="operation",
            )
            share = cls._activity_text(
                dict.__getitem__(copied, "share"),
                field_name="share",
            )
            path = cls._activity_text(
                dict.__getitem__(copied, "path"),
                field_name="path",
            )
            file_id = cls._activity_text(
                dict.__getitem__(copied, "file_id"),
                field_name="file_id",
            )
            content_version = dict.__getitem__(copied, "content_version")
            size_bytes = dict.__getitem__(copied, "size_bytes")
            outcome = cls._activity_text(
                dict.__getitem__(copied, "outcome"),
                field_name="outcome",
            )
            raw_fuid = dict.__getitem__(copied, "fuid")
            fuid = None if raw_fuid is None else cls._activity_text(raw_fuid, field_name="fuid")
            if operation_kind not in _PERSISTENT_SMB_OPERATION_KINDS:
                raise EventContractError("Persistent SMB terminal operation kind is unsupported")
            if outcome not in _PERSISTENT_SMB_OUTCOMES:
                raise EventContractError("Persistent SMB terminal operation outcome is unsupported")
            if (
                type(content_version) is not int
                or not 1 <= content_version <= _MAX_SIGNED_63
                or type(size_bytes) is not int
                or not 0 <= size_bytes <= _MAX_SIGNED_63
            ):
                raise EventContractError(
                    "Persistent SMB terminal operation has invalid exact numeric values"
                )
            frozen_operations.append(
                _PersistentSmbOperationSnapshot(
                    operation=operation_kind,
                    share=share,
                    path=path,
                    file_id=file_id,
                    content_version=content_version,
                    size_bytes=size_bytes,
                    outcome=outcome,
                    fuid=fuid,
                )
            )
        snapshot = _PersistentSmbActivitySnapshot(
            session_id=session_id,
            tree_ids=canonical_tree_ids,
            transport_uids=canonical_transport_uids,
            operations=tuple(frozen_operations),
            completed_at=completed_at,
        )
        digest = hashlib.sha256(cls._activity_snapshot_payload(snapshot)).hexdigest()
        return snapshot, digest

    @classmethod
    def _activity_snapshot_payload(cls, snapshot: _PersistentSmbActivitySnapshot) -> bytes:
        """Encode one private activity snapshot with fixed fields and exact scalar types."""

        if (
            type(snapshot) is not _PersistentSmbActivitySnapshot
            or type(snapshot.tree_ids) is not tuple
            or len(snapshot.tree_ids) != 1
            or type(snapshot.transport_uids) is not tuple
            or len(snapshot.transport_uids) != 1
            or type(snapshot.operations) is not tuple
            or not 1 <= len(snapshot.operations) <= MAX_PERSISTENT_SMB_OPERATIONS
            or type(snapshot.completed_at) is not datetime
            or snapshot.completed_at.tzinfo is not UTC
        ):
            raise EventContractError("Persistent SMB activity capture has an invalid exact shape")
        buffer = bytearray(b"persistent-smb-activity-v1\x00")

        def append_text(value: object, field_name: str) -> None:
            canonical = cls._activity_text(value, field_name=field_name)
            encoded = canonical.encode("utf-8")
            buffer.extend(len(encoded).to_bytes(4, "big"))
            buffer.extend(encoded)
            if len(buffer) > _MAX_PERSISTENT_SMB_ACTIVITY_BYTES:
                raise EventContractError("Persistent SMB terminal result exceeds its byte bound")

        append_text(snapshot.session_id, "session_id")
        append_text(snapshot.tree_ids[0], "tree_id")
        append_text(snapshot.transport_uids[0], "transport_uid")
        buffer.extend(len(snapshot.operations).to_bytes(1, "big"))
        for operation in snapshot.operations:
            if type(operation) is not _PersistentSmbOperationSnapshot:
                raise EventContractError(
                    "Persistent SMB activity capture has an invalid operation type"
                )
            append_text(operation.operation, "operation")
            append_text(operation.share, "share")
            append_text(operation.path, "path")
            append_text(operation.file_id, "file_id")
            if (
                type(operation.content_version) is not int
                or not 1 <= operation.content_version <= _MAX_SIGNED_63
                or type(operation.size_bytes) is not int
                or not 0 <= operation.size_bytes <= _MAX_SIGNED_63
                or operation.operation not in _PERSISTENT_SMB_OPERATION_KINDS
                or operation.outcome not in _PERSISTENT_SMB_OUTCOMES
            ):
                raise EventContractError(
                    "Persistent SMB activity capture has invalid exact operation values"
                )
            buffer.extend(operation.content_version.to_bytes(8, "big", signed=False))
            buffer.extend(operation.size_bytes.to_bytes(8, "big", signed=False))
            append_text(operation.outcome, "outcome")
            if operation.fuid is None:
                buffer.extend(b"\x00")
            else:
                buffer.extend(b"\x01")
                append_text(operation.fuid, "fuid")
        completed_at = snapshot.completed_at
        buffer.extend(completed_at.year.to_bytes(2, "big"))
        buffer.extend(completed_at.month.to_bytes(1, "big"))
        buffer.extend(completed_at.day.to_bytes(1, "big"))
        buffer.extend(completed_at.hour.to_bytes(1, "big"))
        buffer.extend(completed_at.minute.to_bytes(1, "big"))
        buffer.extend(completed_at.second.to_bytes(1, "big"))
        buffer.extend(completed_at.microsecond.to_bytes(4, "big"))
        if len(buffer) > _MAX_PERSISTENT_SMB_ACTIVITY_BYTES:
            raise EventContractError("Persistent SMB terminal result exceeds its byte bound")
        return bytes(buffer)

    @classmethod
    def _thaw_activity_snapshot(
        cls,
        snapshot: _PersistentSmbActivitySnapshot,
    ) -> SmbActivityResult:
        cls._activity_snapshot_payload(snapshot)
        return SmbActivityResult(
            session_id=snapshot.session_id,
            tree_ids=tuple(snapshot.tree_ids),
            transport_uids=tuple(snapshot.transport_uids),
            operations=tuple(
                {
                    "operation": operation.operation,
                    "share": operation.share,
                    "path": operation.path,
                    "file_id": operation.file_id,
                    "content_version": operation.content_version,
                    "size_bytes": operation.size_bytes,
                    "outcome": operation.outcome,
                    "fuid": operation.fuid,
                }
                for operation in snapshot.operations
            ),
            completed_at=snapshot.completed_at,
        )

    @staticmethod
    def _cross_bind_activity_snapshot(
        snapshot: _PersistentSmbActivitySnapshot,
        batch: SmbClosedSessionBatch,
    ) -> None:
        """Require activity truth to describe the authenticated SMB sidecar exactly."""

        if (
            type(batch) is not SmbClosedSessionBatch
            or type(batch.operations) is not tuple
            or snapshot.session_id != batch.session.session_id
            or snapshot.tree_ids != (batch.tree.tree_id,)
            or snapshot.transport_uids != (batch.session.ground_truth_transport_uid,)
            or batch.session.transport_plan.zeek_uid != snapshot.transport_uids[0]
            or snapshot.completed_at != batch.closure.closed_at
            or len(snapshot.operations) != len(batch.operations)
        ):
            raise EventContractError(
                "Persistent SMB activity capture changed its authenticated root identity"
            )
        for ordinal, (activity, operation) in enumerate(
            zip(snapshot.operations, batch.operations, strict=True)
        ):
            if (
                type(operation) is not SmbCompletedOperationView
                or operation.ordinal != ordinal
                or type(operation.handles) is not tuple
                or activity.share != batch.tree.share_ref
            ):
                raise EventContractError(
                    "Persistent SMB activity capture changed its operation ordering"
                )
            for handle in operation.handles:
                if (
                    type(handle) is not SmbCompletedHandleView
                    or handle.file_id != activity.file_id
                    or handle.content_version != activity.content_version
                ):
                    raise EventContractError(
                        "Persistent SMB activity capture changed its handle identity"
                    )

    @classmethod
    def _activity_root_binding_digest(
        cls,
        *,
        action_id: str,
        activity_digest: str,
        application_result: SmbChannelAdmissionResult,
        publication_binding_digest: str,
    ) -> str:
        receipt = application_result.receipt
        common_receipt = application_result.application.receipt
        values = (
            "persistent-smb-activity-root-binding-v1",
            action_id,
            activity_digest,
            receipt.receipt_token,
            common_receipt.receipt_token,
            receipt.sidecar_result_digest,
            publication_binding_digest,
        )
        buffer = bytearray()
        for value in values:
            canonical = cls._activity_text(value, field_name="root binding")
            encoded = canonical.encode("utf-8")
            buffer.extend(len(encoded).to_bytes(4, "big"))
            buffer.extend(encoded)
        if len(buffer) > _MAX_PERSISTENT_SMB_ACTIVITY_BYTES:
            raise EventContractError("Persistent SMB activity root binding is oversized")
        return hashlib.sha256(buffer).hexdigest()

    def capture_activity_result(
        self,
        *,
        action_id: str,
        activity_result: SmbActivityResult,
        application_result: SmbChannelAdmissionResult,
        publication_binding_digest: str,
    ) -> PersistentSmbActivityCapture:
        """Freeze and cross-bind public activity truth before the authority retains it."""

        canonical_action = self._bounded_action_id(action_id)
        canonical_publication = self._binding_digest(publication_binding_digest)
        manager = self._smb_channel_manager
        if (
            type(manager) is not SmbApplicationChannelManager
            or type(application_result) is not SmbChannelAdmissionResult
            or not manager.authenticates_admission_result(application_result)
        ):
            raise EventContractError(
                "Persistent SMB activity capture requires an authenticated application result"
            )
        snapshot, activity_digest = self._freeze_activity_result(activity_result)
        self._cross_bind_activity_snapshot(snapshot, application_result.result)
        binding_digest = self._activity_root_binding_digest(
            action_id=canonical_action,
            activity_digest=activity_digest,
            application_result=application_result,
            publication_binding_digest=canonical_publication,
        )
        return PersistentSmbActivityCapture(
            snapshot=snapshot,
            activity_digest=activity_digest,
            binding_digest=binding_digest,
        )

    def _validate_activity_capture(
        self,
        capture: PersistentSmbActivityCapture,
        *,
        action_id: str,
        application_result: SmbChannelAdmissionResult | None,
        publication_binding_digest: str | None,
    ) -> _PersistentSmbActivitySnapshot:
        if type(capture) is not PersistentSmbActivityCapture:
            raise EventContractError("Persistent SMB activity capture has an invalid exact type")
        snapshot = object.__getattribute__(capture, "snapshot")
        activity_digest = hashlib.sha256(self._activity_snapshot_payload(snapshot)).hexdigest()
        if activity_digest != capture.activity_digest:
            raise EventContractError("Persistent SMB activity capture changed after admission")
        if application_result is not None or publication_binding_digest is not None:
            manager = self._smb_channel_manager
            if (
                type(manager) is not SmbApplicationChannelManager
                or type(application_result) is not SmbChannelAdmissionResult
                or type(publication_binding_digest) is not str
                or not manager.authenticates_admission_result_proof(application_result)
            ):
                raise EventContractError(
                    "Persistent SMB activity capture lost its authenticated application result"
                )
            self._cross_bind_activity_snapshot(snapshot, application_result.result)
            expected_binding = self._activity_root_binding_digest(
                action_id=self._bounded_action_id(action_id),
                activity_digest=activity_digest,
                application_result=application_result,
                publication_binding_digest=self._binding_digest(publication_binding_digest),
            )
            if expected_binding != capture.binding_digest:
                raise EventContractError(
                    "Persistent SMB activity root binding changed after capture"
                )
        else:
            self._binding_digest(capture.binding_digest)
        return snapshot

    @staticmethod
    def _encoded_scalar(value: str | int) -> bytes:
        encoded = str(value).encode("utf-8")
        return len(encoded).to_bytes(8, "big") + encoded

    @classmethod
    def _record_payload_bytes(cls, record: _PersistentSmbTerminalRecord) -> bytes:
        """Encode only authority-owned scalar state; nested owners self-authenticate."""

        parts: tuple[str | int, ...] = (
            "persistent-smb-terminal-continuation-v5",
            record.continuation_id,
            record.action_id,
            record.action_binding_digest,
            record.phase,
            record.cursor,
            record.cleanup_cursor,
            record.active_thread_id or 0,
            record.retained_bytes,
            record.activity_digest,
            record.activity_binding_digest,
            len(record.source_build_members),
            len(record.external_transport_uids),
            *record.external_transport_uids,
        )
        return b"".join(cls._encoded_scalar(part) for part in parts)

    def _integrity(self, record: _PersistentSmbTerminalRecord) -> str:
        return f"smb-continuation:{self._authority_id}:{record.continuation_id}"

    def _record_locked(
        self,
        continuation: PersistentSmbTerminalContinuation,
        *,
        require_active: bool,
    ) -> _PersistentSmbTerminalRecord:
        if type(continuation) is not PersistentSmbTerminalContinuation:
            raise EventContractError("Persistent SMB terminal continuation has an invalid type")
        record = self._records_by_carrier.get(id(continuation))
        if (
            record is None
            or record.continuation is not continuation
            or continuation._authority_id != self._authority_id
            or continuation._continuation_id != record.continuation_id
            or continuation._consumed
            or self._records_by_action.get(record.action_id) is not record
        ):
            raise EventContractError(
                "Persistent SMB terminal continuation is copied, foreign, or stale"
            )
        expected = self._integrity(record)
        if record.integrity != expected or continuation._integrity != expected:
            raise EventContractError("Persistent SMB terminal continuation integrity failed")
        if require_active and record.active_thread_id != get_ident():
            raise EventContractError("Persistent SMB terminal continuation has no active claim")
        return record

    def _refresh_locked(self, record: _PersistentSmbTerminalRecord) -> None:
        integrity = self._integrity(record)
        record.integrity = integrity
        record.continuation._integrity = integrity

    def reserve_claimed(
        self,
        *,
        action_id: str,
        action_binding_digest: str,
        retained_bytes: int,
    ) -> PersistentSmbTerminalContinuation:
        """Reserve and claim the one action-keyed owner before child admission."""

        canonical_action = self._bounded_action_id(action_id)
        canonical_binding = self._binding_digest(action_binding_digest)
        if type(retained_bytes) is not int or retained_bytes <= 0:
            raise EventContractError(
                "Persistent SMB continuation charge must be a positive exact int"
            )
        if retained_bytes > self._byte_capacity:
            raise EventContractError("Persistent SMB terminal work exceeds its byte capacity")
        with self._lock:
            if canonical_action in self._records_by_action:
                raise EventContractError("Persistent SMB terminal action is already retained")
            if (
                len(self._records_by_action) >= self._capacity
                or self._retained_bytes + retained_bytes > self._byte_capacity
            ):
                raise EventContractError("Persistent SMB terminal continuation capacity is full")
            continuation_id = self._next_continuation_id
            if continuation_id > (1 << 63) - 1:
                raise EventContractError("Persistent SMB terminal generation is exhausted")
            continuation = PersistentSmbTerminalContinuation(
                authority_id=self._authority_id,
                continuation_id=continuation_id,
                integrity="",
            )
            record = _PersistentSmbTerminalRecord(
                continuation=continuation,
                continuation_id=continuation_id,
                action_id=canonical_action,
                action_binding_digest=canonical_binding,
                phase="reserved",
                projection_group=None,
                source_reservation=None,
                source_timing_capacity=None,
                action_preparation=None,
                prepared_root=None,
                materialization=None,
                handoff=None,
                outcome=None,
                source_building=None,
                source_build_members=(),
                source_preparation=None,
                source_certifications=(),
                source_carrier=None,
                source_result=None,
                file_mutation=None,
                finalization=None,
                activity_capture=None,
                activity_digest="",
                activity_binding_digest="",
                external_transport_uids=(),
                retained_bytes=retained_bytes,
                integrity="",
                active_thread_id=get_ident(),
            )
            self._refresh_locked(record)
            self._records_by_action[canonical_action] = record
            self._records_by_carrier[id(continuation)] = record
            self._next_continuation_id += 1
            self._active_claims += 1
            self._retained_bytes += retained_bytes
            self._high_water_continuations = max(
                self._high_water_continuations,
                len(self._records_by_action),
            )
            self._high_water_bytes = max(self._high_water_bytes, self._retained_bytes)
            return continuation

    def bind_pre_root_reservations(
        self,
        continuation: PersistentSmbTerminalContinuation,
        *,
        projection_group: PersistentSmbProjectionGroupToken,
        source_reservation: PreparedPersistentSmbSourcePublication,
        source_timing_capacity: SourceTimingActionCapacityReservation,
    ) -> None:
        """Retain exact dispatcher reservations before reversible action planning."""

        if (
            type(projection_group) is not PersistentSmbProjectionGroupToken
            or type(source_reservation) is not PreparedPersistentSmbSourcePublication
            or type(source_timing_capacity) is not SourceTimingActionCapacityReservation
        ):
            raise EventContractError("Persistent SMB pre-root reservations have invalid types")
        with self._lock:
            record = self._record_locked(continuation, require_active=True)
            if (
                record.projection_group is not None
                or record.source_reservation is not None
                or record.source_timing_capacity is not None
            ):
                if (
                    record.projection_group is projection_group
                    and record.source_reservation is source_reservation
                    and record.source_timing_capacity is source_timing_capacity
                ):
                    return
                raise EventContractError("Persistent SMB pre-root reservations changed")
            if record.phase != "reserved":
                raise EventContractError("Persistent SMB pre-root reservations changed phase")
            record.projection_group = projection_group
            record.source_reservation = source_reservation
            record.source_timing_capacity = source_timing_capacity
            self._refresh_locked(record)

    def bind_action_prepared(
        self,
        continuation: PersistentSmbTerminalContinuation,
        preparation: PersistentSmbActionPreparation,
    ) -> None:
        """Freeze the reversible file/application recipe before the physical root."""

        if type(preparation) is not PersistentSmbActionPreparation:
            raise EventContractError("Persistent SMB action preparation has an invalid exact type")
        if (
            not 1 <= len(preparation.operations) <= MAX_PERSISTENT_SMB_OPERATIONS
            or len(preparation.operation_plans) != len(preparation.operations)
            or len(preparation.byte_allocations) != len(preparation.operations)
            or type(preparation.client_process) is not PersistentSmbClientProcessPreparation
        ):
            raise EventContractError("Persistent SMB action preparation has an invalid shape")
        with self._lock:
            record = self._record_locked(continuation, require_active=True)
            if record.phase == "action_prepared" and record.action_preparation is preparation:
                return
            if (
                record.phase != "reserved"
                or record.projection_group is None
                or record.source_reservation is None
                or record.source_timing_capacity is None
                or record.action_preparation is not None
            ):
                raise EventContractError("Persistent SMB action preparation changed phase")
            record.action_preparation = preparation
            record.phase = "action_prepared"
            self._refresh_locked(record)

    def bind_prepared_root(
        self,
        continuation: PersistentSmbTerminalContinuation,
        preparation: PersistentSmbPreparedRoot,
    ) -> None:
        """Retain exact materialization inputs before the network boundary transfers."""

        if (
            type(preparation) is not PersistentSmbPreparedRoot
            or type(preparation.root) is not PreparedNetworkTransactionRoot
            or type(preparation.owner_rng) is not random.Random
            or type(preparation.source_timing_preparation) is not SourceTimingPreparation
            or type(preparation.lifecycle_token) is not LifecycleClosedTransportAdmissionToken
            or type(preparation.application_token) is not SmbChannelAdmissionToken
            or type(preparation.file_journal) is not SmbFileMutationJournal
            or type(preparation.prerequisite_receipts) is not tuple
            or any(
                type(item) is not LifecyclePreparedNetworkReceipt
                for item in preparation.prerequisite_receipts
            )
            or type(preparation.prepared_dispatch) is not PreparedDispatch
            or type(preparation.observations) is not tuple
            or any(type(item) is not NetworkSensorObservation for item in preparation.observations)
            or type(preparation.outcome) is not NetworkConnectionPublicationOutcome
        ):
            raise EventContractError("Persistent SMB prepared root has invalid exact owners")
        with self._lock:
            record = self._record_locked(continuation, require_active=True)
            if record.phase in {
                "root_prepared",
                "root_committed",
                "source_building",
                "source_prepared",
                "source_published",
            }:
                if record.prepared_root is preparation:
                    return
                raise EventContractError("Persistent SMB prepared root changed on retry")
            if record.phase != "action_prepared" or record.action_preparation is None:
                raise EventContractError("Persistent SMB prepared root lacks action preparation")
            record.prepared_root = preparation
            record.phase = "root_prepared"
            self._refresh_locked(record)

    def authenticates_claimed(self, continuation: object) -> bool:
        """Return whether this authority owns the exact active action claim."""

        with self._lock:
            try:
                self._record_locked(continuation, require_active=True)  # type: ignore[arg-type]
            except (AttributeError, EventContractError, TypeError, ValueError):
                return False
            return True

    def bind_committed_root(
        self,
        continuation: PersistentSmbTerminalContinuation,
        *,
        materialization: LifecyclePreparedNetworkResult,
        handoff: PersistentSmbRootHandoff,
        outcome: NetworkConnectionPublicationOutcome,
    ) -> None:
        """Retain the exact committed root before capture publication or lifecycle ack."""

        if (
            type(materialization) is not LifecyclePreparedNetworkResult
            or type(handoff) is not PersistentSmbRootHandoff
            or type(outcome) is not NetworkConnectionPublicationOutcome
        ):
            raise EventContractError("Persistent SMB committed root has invalid exact owners")
        with self._lock:
            record = self._record_locked(continuation, require_active=True)
            if record.phase in {
                "root_committed",
                "source_building",
                "source_prepared",
                "source_published",
            }:
                if (
                    record.materialization is materialization
                    and record.handoff is handoff
                    and record.outcome is outcome
                ):
                    return
                raise EventContractError("Persistent SMB committed root changed on retry")
            prepared = record.prepared_root
            receipt = materialization.receipt
            application = materialization.connection.application
            state = materialization.connection.state
            manager = self._smb_channel_manager
            if (
                record.phase != "root_prepared"
                or prepared is None
                or receipt.transaction_id != prepared.root.transaction.stable_id
                or receipt.connection_receipt is not materialization.connection.receipt
                or receipt.runtime_receipt is not materialization.runtime
                or receipt.timing_receipt is not materialization.timing
                or type(application) is not SmbChannelAdmissionResult
                or application is not handoff.application_result
                or type(manager) is not SmbApplicationChannelManager
                or not manager.authenticates_admission_result(application)
                or handoff.materialization is not materialization
                or type(handoff.lifecycle_binding) is not LifecycleDetachedNetworkReceiptBinding
                or handoff.lifecycle_binding.source_receipt_token != receipt.receipt_token
                or handoff.lifecycle_binding.transaction_id != prepared.root.transaction.stable_id
                or record.action_preparation is None
                or handoff.file_journal is not prepared.file_journal
                or handoff.file_journal is not record.action_preparation.journal
                or handoff.prepared_dispatch is not prepared.prepared_dispatch
                or handoff.observations is not prepared.observations
                or state.smb_connection_pin_install is not handoff.pin_install_receipt
                or state.smb_file_mutation is not handoff.file_mutation
                or handoff.application_token is not prepared.application_token
                or outcome is not prepared.outcome
            ):
                raise EventContractError("Persistent SMB committed root changed prepared owners")
            record.materialization = materialization
            record.handoff = handoff
            record.outcome = outcome
            record.phase = "root_committed"
            self._refresh_locked(record)

    @staticmethod
    def _source_preparation_has_exact_shape(
        preparation: object,
        *,
        require_members: bool,
    ) -> bool:
        """Return whether one source carrier has the exact bounded owner shape."""

        if type(preparation) is not PersistentSmbPreparedSource:
            return False
        member_work = preparation.member_work
        return bool(
            type(preparation.opening) is NetworkTransactionPlan
            and type(preparation.lifecycle_receipt) is LifecyclePreparedNetworkReceipt
            and type(preparation.lifecycle_binding) is LifecycleDetachedNetworkReceiptBinding
            and type(preparation.traffic_binding) is PersistentSmbTrafficRebindBinding
            and type(preparation.final_transaction) is NetworkTransactionPlan
            and type(preparation.final_observation_traffic) is tuple
            and all(
                type(item) is NetworkTrafficLedger for item in preparation.final_observation_traffic
            )
            and type(preparation.state_plan) is ActionCohortMaterializationPlan
            and type(preparation.source_carrier) is PreparedPersistentSmbSourcePublication
            and type(preparation.source_projections) is tuple
            and bool(preparation.source_projections)
            and all(
                type(item) is PreparedActionCohortProjection
                for item in preparation.source_projections
            )
            and type(preparation.timing_preparation) is SourceTimingPreparation
            and type(preparation.source_timing_capacity) is SourceTimingActionCapacityReservation
            and type(member_work) is tuple
            and bool(member_work) is require_members
            and all(type(item) is PersistentSmbProjectionMemberToken for item in member_work)
            and type(preparation.activity_capture) is PersistentSmbActivityCapture
        )

    def bind_source_building(
        self,
        continuation: PersistentSmbTerminalContinuation,
        building: PersistentSmbSourceBuilding,
    ) -> None:
        """Own a sealed source plan before its first detached member append."""

        if (
            type(building) is not PersistentSmbSourceBuilding
            or not self._source_preparation_has_exact_shape(
                building.source_shell,
                require_members=False,
            )
            or type(building.member_specs) is not tuple
            or not 1 <= len(building.member_specs) <= 6 + 3 * MAX_PERSISTENT_SMB_OPERATIONS
            or len(building.member_specs) != len(building.source_shell.source_projections) + 1
        ):
            raise EventContractError("Persistent SMB source build has an invalid exact shape")
        for spec in building.member_specs:
            if (
                type(spec) is not tuple
                or len(spec) != 4
                or type(spec[0]) is not PersistentSmbProjectionPhase
                or type(spec[1]) is not str
                or type(spec[2]) is not str
                or type(spec[3]) is not bytes
                or not spec[3]
                or len(spec[3]) > _MAX_PERSISTENT_SMB_ACTIVITY_BYTES
            ):
                raise EventContractError("Persistent SMB source member plan is malformed")
            self._bounded_action_id(spec[1])
            self._binding_digest(spec[2])
        shell = building.source_shell
        self._binding_digest(shell.publication_binding_digest)
        with self._lock:
            record = self._record_locked(continuation, require_active=True)
            if record.phase == "source_building":
                if record.source_building is building:
                    return
                raise EventContractError("Persistent SMB source build changed on retry")
            handoff = record.handoff
            if (
                record.phase != "root_committed"
                or handoff is None
                or record.source_preparation is not None
                or record.source_building is not None
                or record.source_build_members
                or record.source_reservation is not shell.source_carrier
                or record.source_timing_capacity is not shell.source_timing_capacity
            ):
                raise EventContractError("Persistent SMB source build changed owner")
            self._validate_activity_capture(
                shell.activity_capture,
                action_id=record.action_id,
                application_result=handoff.application_result,
                publication_binding_digest=shell.publication_binding_digest,
            )
            record.source_building = building
            record.phase = "source_building"
            self._refresh_locked(record)

    def append_source_build_member(
        self,
        continuation: PersistentSmbTerminalContinuation,
        building: PersistentSmbSourceBuilding,
        member: PersistentSmbProjectionMemberToken,
        *,
        expected_ordinal: int,
    ) -> None:
        """Advance the bounded source-build cursor with one exact inactive member."""

        if (
            type(building) is not PersistentSmbSourceBuilding
            or type(member) is not PersistentSmbProjectionMemberToken
            or type(expected_ordinal) is not int
            or not 0 <= expected_ordinal < len(building.member_specs)
        ):
            raise EventContractError("Persistent SMB source member append is malformed")
        phase, operation_id, operation_digest, capsule = building.member_specs[expected_ordinal]
        shell = building.source_shell
        with self._lock:
            record = self._record_locked(continuation, require_active=True)
            if record.phase != "source_building" or record.source_building is not building:
                raise EventContractError("Persistent SMB source member changed build owner")
            if len(record.source_build_members) > expected_ordinal:
                if record.source_build_members[expected_ordinal] is member:
                    return
                raise EventContractError("Persistent SMB source member changed on retry")
            group = record.projection_group
            timing_token = shell.timing_preparation.binding_token
            if (
                len(record.source_build_members) != expected_ordinal
                or group is None
                or member.group_id != group.group_id
                or member.generation_id != group.generation_id
                or member.phase is not phase
                or member.operation_id != operation_id
                or member.operation_binding_digest != operation_digest
                or member.capsule_digest != hashlib.sha256(capsule).hexdigest()
                or member.timing_binding.preparation_id != timing_token.preparation_id
                or member.timing_binding.base_state_digest != timing_token.base_state_digest
            ):
                raise EventContractError("Persistent SMB source member changed planned facts")
            record.source_build_members += (member,)
            self._refresh_locked(record)

    @staticmethod
    def _source_preparation_matches_build(
        preparation: PersistentSmbPreparedSource,
        building: PersistentSmbSourceBuilding,
        members: tuple[PersistentSmbProjectionMemberToken, ...],
    ) -> bool:
        """Compare exact source-shell owners while allowing only the member tuple to fill."""

        shell = building.source_shell
        return bool(
            preparation.opening is shell.opening
            and preparation.lifecycle_receipt is shell.lifecycle_receipt
            and preparation.lifecycle_binding is shell.lifecycle_binding
            and preparation.traffic_binding is shell.traffic_binding
            and preparation.final_transaction is shell.final_transaction
            and preparation.final_observation_traffic is shell.final_observation_traffic
            and preparation.state_plan is shell.state_plan
            and preparation.source_carrier is shell.source_carrier
            and preparation.source_projections is shell.source_projections
            and preparation.publication_binding_digest == shell.publication_binding_digest
            and preparation.timing_preparation is shell.timing_preparation
            and preparation.source_timing_capacity is shell.source_timing_capacity
            and preparation.member_work is members
            and preparation.target_formats is shell.target_formats
            and preparation.lifecycle_digest == shell.lifecycle_digest
            and preparation.lifecycle_generation == shell.lifecycle_generation
            and preparation.network_digest == shell.network_digest
            and preparation.network_generation == shell.network_generation
            and preparation.traffic_digest == shell.traffic_digest
            and preparation.traffic_generation == shell.traffic_generation
            and preparation.activity_capture is shell.activity_capture
        )

    def complete_source_building(
        self,
        continuation: PersistentSmbTerminalContinuation,
        building: PersistentSmbSourceBuilding,
        preparation: PersistentSmbPreparedSource,
    ) -> None:
        """Atomically promote one fully appended build into source-prepared ownership."""

        if type(
            building
        ) is not PersistentSmbSourceBuilding or not self._source_preparation_has_exact_shape(
            preparation, require_members=True
        ):
            raise EventContractError("Persistent SMB completed source build is malformed")
        with self._lock:
            record = self._record_locked(continuation, require_active=True)
            if record.phase in {"source_prepared", "source_published"}:
                if record.source_preparation is preparation:
                    return
                raise EventContractError("Persistent SMB completed source changed on retry")
            if (
                record.phase != "source_building"
                or record.source_building is not building
                or len(record.source_build_members) != len(building.member_specs)
                or not self._source_preparation_matches_build(
                    preparation,
                    building,
                    record.source_build_members,
                )
            ):
                raise EventContractError("Persistent SMB completed source changed build facts")
            record.source_preparation = preparation
            record.activity_capture = preparation.activity_capture
            record.activity_digest = preparation.activity_capture.activity_digest
            record.activity_binding_digest = preparation.activity_capture.binding_digest
            record.source_building = None
            record.source_build_members = ()
            record.phase = "source_prepared"
            self._refresh_locked(record)

    def bind_source_prepared(
        self,
        continuation: PersistentSmbTerminalContinuation,
        preparation: PersistentSmbPreparedSource,
    ) -> None:
        """Retain every exact source/finalization owner before terminal mutation."""

        if not self._source_preparation_has_exact_shape(preparation, require_members=True):
            raise EventContractError("Persistent SMB source preparation has an invalid exact type")
        self._binding_digest(preparation.publication_binding_digest)
        with self._lock:
            record = self._record_locked(continuation, require_active=True)
            handoff = record.handoff
            if handoff is None:
                raise EventContractError("Persistent SMB source preparation lost its root handoff")
            self._validate_activity_capture(
                preparation.activity_capture,
                action_id=record.action_id,
                application_result=handoff.application_result,
                publication_binding_digest=preparation.publication_binding_digest,
            )
            if record.phase in {"source_prepared", "source_published"}:
                if record.source_preparation is preparation:
                    return
                raise EventContractError("Persistent SMB source preparation changed on retry")
            if (
                record.phase != "root_committed"
                or record.handoff is None
                or record.source_reservation is not preparation.source_carrier
                or record.source_timing_capacity is not preparation.source_timing_capacity
            ):
                raise EventContractError("Persistent SMB source preparation changed owner")
            record.source_preparation = preparation
            record.activity_capture = preparation.activity_capture
            record.activity_digest = preparation.activity_capture.activity_digest
            record.activity_binding_digest = preparation.activity_capture.binding_digest
            record.phase = "source_prepared"
            self._refresh_locked(record)

    def bind_source_certifications(
        self,
        continuation: PersistentSmbTerminalContinuation,
        certifications: tuple[PersistentSmbProjectionMemberCertification, ...],
    ) -> None:
        """Retain the exact member certifications before source-timing commit."""

        if (
            type(certifications) is not tuple
            or not certifications
            or len(certifications) > 6 + 3 * MAX_PERSISTENT_SMB_OPERATIONS
            or any(
                type(item) is not PersistentSmbProjectionMemberCertification
                for item in certifications
            )
        ):
            raise EventContractError("Persistent SMB source certifications have invalid shape")
        with self._lock:
            record = self._record_locked(continuation, require_active=True)
            if record.phase != "source_prepared" or record.source_preparation is None:
                raise EventContractError("Persistent SMB source certifications changed phase")
            if record.source_certifications:
                if record.source_certifications is certifications:
                    return
                raise EventContractError("Persistent SMB source certifications changed on retry")
            if len(certifications) != len(record.source_preparation.member_work):
                raise EventContractError("Persistent SMB source certification count changed")
            record.source_certifications = certifications
            self._refresh_locked(record)

    def bind_source_published(
        self,
        continuation: PersistentSmbTerminalContinuation,
        *,
        source_result: PersistentSmbSourcePublicationResult,
        file_mutation: SmbFileMutationCommitResult,
        finalization: SmbConnectionFinalizationResult,
        external_transport_uids: tuple[str, ...],
    ) -> None:
        """Install exact terminal owners with no post-root capacity admission."""

        if (
            type(source_result) is not PersistentSmbSourcePublicationResult
            or type(file_mutation) is not SmbFileMutationCommitResult
            or type(finalization) is not SmbConnectionFinalizationResult
            or type(external_transport_uids) is not tuple
            or len(external_transport_uids) != 1
        ):
            raise EventContractError("Persistent SMB published source has invalid exact owners")
        canonical_external_transport_uids = tuple(
            self._activity_text(item, field_name="external_transport_uid")
            for item in external_transport_uids
        )
        with self._lock:
            record = self._record_locked(continuation, require_active=True)
            preparation = record.source_preparation
            if record.phase == "source_published":
                if (
                    record.source_result is source_result
                    and record.file_mutation is file_mutation
                    and record.finalization is finalization
                    and record.external_transport_uids == canonical_external_transport_uids
                ):
                    return
                raise EventContractError("Persistent SMB published source changed on retry")
            if record.phase != "source_prepared" or preparation is None:
                raise EventContractError("Persistent SMB published source lacks preparation")
            record.source_carrier = preparation.source_carrier
            record.source_result = source_result
            record.file_mutation = file_mutation
            record.finalization = finalization
            record.external_transport_uids = canonical_external_transport_uids
            if record.activity_capture is not preparation.activity_capture:
                raise EventContractError("Persistent SMB published source changed activity capture")
            record.phase = "source_published"
            self._refresh_locked(record)

    def rollback_source_prepared(
        self,
        continuation: PersistentSmbTerminalContinuation,
        preparation: PersistentSmbPreparedSource,
    ) -> None:
        """Return a fully neutralized uncommitted source attempt to its committed root."""

        if type(preparation) is not PersistentSmbPreparedSource:
            raise EventContractError(
                "Persistent SMB source rollback requires its exact preparation"
            )
        with self._lock:
            record = self._record_locked(continuation, require_active=True)
            if (
                record.phase == "root_committed"
                and record.source_preparation is None
                and not record.source_certifications
            ):
                return
            if (
                record.phase != "source_prepared"
                or record.source_preparation is not preparation
                or record.source_carrier is not None
                or record.source_result is not None
                or record.file_mutation is not None
                or record.finalization is not None
                or record.activity_capture is not preparation.activity_capture
                or record.activity_digest != preparation.activity_capture.activity_digest
                or record.activity_binding_digest != preparation.activity_capture.binding_digest
            ):
                raise EventContractError("Persistent SMB source rollback changed exact owners")
            record.source_preparation = None
            record.source_certifications = ()
            record.activity_capture = None
            record.activity_digest = ""
            record.activity_binding_digest = ""
            record.phase = "root_committed"
            self._refresh_locked(record)

    def claim_existing(
        self,
        *,
        action_id: str,
        action_binding_digest: str,
    ) -> PersistentSmbTerminalContinuation | None:
        """Claim retained action work for one ordinary public retry."""

        canonical_action = self._bounded_action_id(action_id)
        canonical_binding = self._binding_digest(action_binding_digest)
        with self._lock:
            record = self._records_by_action.get(canonical_action)
            if record is None:
                return None
            self._record_locked(record.continuation, require_active=False)
            if record.action_binding_digest != canonical_binding:
                raise EventContractError(
                    "Persistent SMB terminal retry changed its exact action binding"
                )
            if record.active_thread_id is not None:
                raise EventContractError("Persistent SMB terminal continuation is already active")
            record.active_thread_id = get_ident()
            self._active_claims += 1
            self._refresh_locked(record)
            return record.continuation

    def root_facts(
        self,
        continuation: PersistentSmbTerminalContinuation,
    ) -> PersistentSmbRootFacts:
        """Return exact phase-specific owners to the active action claim."""

        with self._lock:
            record = self._record_locked(continuation, require_active=True)
            return PersistentSmbRootFacts(
                phase=record.phase,
                cleanup_cursor=record.cleanup_cursor,
                action_id=record.action_id,
                action_binding_digest=record.action_binding_digest,
                member_budget=(
                    len(record.source_preparation.member_work)
                    if record.source_preparation is not None
                    else 0
                ),
                projection_group=record.projection_group,
                source_reservation=record.source_reservation,
                source_timing_capacity=record.source_timing_capacity,
                action_preparation=record.action_preparation,
                prepared_root=record.prepared_root,
                materialization=record.materialization,
                handoff=record.handoff,
                outcome=record.outcome,
                source_building=record.source_building,
                source_build_members=record.source_build_members,
                source_preparation=record.source_preparation,
                source_certifications=record.source_certifications,
            )

    def facts(
        self,
        continuation: PersistentSmbTerminalContinuation,
    ) -> PersistentSmbTerminalFacts:
        """Return exact published terminal owners to the active action claim."""

        with self._lock:
            record = self._record_locked(continuation, require_active=True)
            if (
                record.phase != "source_published"
                or record.source_carrier is None
                or record.source_result is None
                or record.file_mutation is None
                or record.finalization is None
                or record.activity_capture is None
                or record.source_timing_capacity is None
                or record.source_preparation is None
            ):
                raise EventContractError("Persistent SMB terminal source is not published")
            snapshot = self._validate_activity_capture(
                record.activity_capture,
                action_id=record.action_id,
                application_result=(
                    None if record.handoff is None else record.handoff.application_result
                ),
                publication_binding_digest=record.source_preparation.publication_binding_digest,
            )
            if (
                record.activity_digest != record.activity_capture.activity_digest
                or record.activity_binding_digest != record.activity_capture.binding_digest
            ):
                raise EventContractError("Persistent SMB terminal activity binding changed")
            return PersistentSmbTerminalFacts(
                cursor=record.cursor,
                action_id=record.action_id,
                action_binding_digest=record.action_binding_digest,
                member_budget=len(record.source_preparation.member_work),
                source_carrier=record.source_carrier,
                source_result=record.source_result,
                file_mutation=record.file_mutation,
                finalization=record.finalization,
                activity_result=self._thaw_activity_snapshot(snapshot),
                source_timing_capacity=record.source_timing_capacity,
                handoff=record.handoff,
                receipt=(
                    None if record.materialization is None else record.materialization.receipt
                ),
            )

    def advance(
        self,
        continuation: PersistentSmbTerminalContinuation,
        *,
        expected_cursor: int,
    ) -> None:
        """Generation-CAS advance one authenticated terminal acknowledgement."""

        if type(expected_cursor) is not int or not 0 <= expected_cursor < 6:
            raise EventContractError("Persistent SMB terminal cursor is out of range")
        with self._lock:
            record = self._record_locked(continuation, require_active=True)
            if record.phase != "source_published" or record.cursor != expected_cursor:
                raise EventContractError("Persistent SMB terminal cursor changed concurrently")
            record.cursor += 1
            self._refresh_locked(record)

    def begin_uncommitted_cleanup(
        self,
        continuation: PersistentSmbTerminalContinuation,
    ) -> None:
        """Fence a reversible continuation into cleanup-only retry semantics."""

        with self._lock:
            record = self._record_locked(continuation, require_active=True)
            if record.phase == "cancelling":
                return
            if record.phase not in {"reserved", "action_prepared"}:
                raise EventContractError("Persistent SMB committed work cannot enter cleanup")
            record.phase = "cancelling"
            self._refresh_locked(record)

    def advance_uncommitted_cleanup(
        self,
        continuation: PersistentSmbTerminalContinuation,
        *,
        expected_cursor: int,
    ) -> None:
        """Advance one exact external-owner cleanup postcondition."""

        if type(expected_cursor) is not int or not 0 <= expected_cursor < 4:
            raise EventContractError("Persistent SMB cleanup cursor is out of range")
        with self._lock:
            record = self._record_locked(continuation, require_active=True)
            if record.phase != "cancelling" or record.cleanup_cursor != expected_cursor:
                raise EventContractError("Persistent SMB cleanup cursor changed concurrently")
            record.cleanup_cursor += 1
            self._refresh_locked(record)

    def cancel_uncommitted(
        self,
        continuation: PersistentSmbTerminalContinuation,
    ) -> bool:
        """Retire one reversible continuation only when no root committed."""

        with self._lock:
            record = self._record_locked(continuation, require_active=True)
            neutral_reserved = bool(
                record.phase == "reserved"
                and record.projection_group is None
                and record.source_reservation is None
                and record.source_timing_capacity is None
                and record.action_preparation is None
            )
            completed_cleanup = record.phase == "cancelling" and record.cleanup_cursor == 4
            if not neutral_reserved and not completed_cleanup:
                return False
            self._records_by_action.pop(record.action_id)
            self._records_by_carrier.pop(id(continuation))
            self._active_claims -= 1
            self._retained_bytes -= record.retained_bytes
            continuation._consumed = True
            return True

    def release_claim(self, continuation: PersistentSmbTerminalContinuation) -> None:
        """Release one failed active claim while retaining its exact phase and cursor."""

        with self._lock:
            record = self._record_locked(continuation, require_active=True)
            record.active_thread_id = None
            self._active_claims -= 1
            self._refresh_locked(record)

    def complete_no_fail(
        self,
        continuation: PersistentSmbTerminalContinuation,
    ) -> SmbActivityResult:
        """Return the frozen result and retire one fully acknowledged continuation."""

        with self._lock:
            record = self._record_locked(continuation, require_active=True)
            if record.cursor != 6 or record.activity_capture is None:
                raise EventContractError("Persistent SMB terminal continuation is incomplete")
            publication_binding = (
                None
                if record.source_preparation is None
                else record.source_preparation.publication_binding_digest
            )
            snapshot = self._validate_activity_capture(
                record.activity_capture,
                action_id=record.action_id,
                application_result=(
                    None if record.handoff is None else record.handoff.application_result
                ),
                publication_binding_digest=publication_binding,
            )
            if (
                record.activity_digest != record.activity_capture.activity_digest
                or record.activity_binding_digest != record.activity_capture.binding_digest
            ):
                raise EventContractError("Persistent SMB terminal activity binding changed")
            if len(record.external_transport_uids) != 1:
                raise EventContractError(
                    "Persistent SMB terminal continuation lost its external transport identity"
                )
            result = replace(
                self._thaw_activity_snapshot(snapshot),
                transport_uids=record.external_transport_uids,
            )
            self._records_by_action.pop(record.action_id)
            self._records_by_carrier.pop(id(continuation))
            self._active_claims -= 1
            self._retained_bytes -= record.retained_bytes
            continuation._consumed = True
            return result

    def install_claimed(
        self,
        *,
        action_id: str,
        action_binding_digest: str,
        source_carrier: PreparedPersistentSmbSourcePublication,
        source_result: PersistentSmbSourcePublicationResult,
        file_mutation: SmbFileMutationCommitResult,
        finalization: SmbConnectionFinalizationResult,
        activity_result: SmbActivityResult,
    ) -> PersistentSmbTerminalContinuation:
        """Compatibility-only install for direct terminal-authority guard tests."""

        if (
            type(source_carrier) is not PreparedPersistentSmbSourcePublication
            or type(source_result) is not PersistentSmbSourcePublicationResult
            or type(file_mutation) is not SmbFileMutationCommitResult
            or type(finalization) is not SmbConnectionFinalizationResult
            or type(activity_result) is not SmbActivityResult
        ):
            raise EventContractError("Persistent SMB terminal install requires exact owner types")
        snapshot, activity_digest = self._freeze_activity_result(activity_result)
        canonical_action = self._bounded_action_id(action_id)
        canonical_action_binding = self._binding_digest(action_binding_digest)
        binding_digest = hashlib.sha256(
            b"persistent-smb-activity-compatibility-binding-v1\x00"
            + self._encoded_scalar(canonical_action)
            + self._encoded_scalar(canonical_action_binding)
            + self._encoded_scalar(activity_digest)
        ).hexdigest()
        capture = PersistentSmbActivityCapture(
            snapshot=snapshot,
            activity_digest=activity_digest,
            binding_digest=binding_digest,
        )
        retained_bytes = (
            len(self._activity_snapshot_payload(snapshot))
            + sum(size for _row, _digest, size in source_result.row_facts)
            + 4_096
        )
        continuation = self.reserve_claimed(
            action_id=action_id,
            action_binding_digest=action_binding_digest,
            retained_bytes=retained_bytes,
        )
        with self._lock:
            record = self._record_locked(continuation, require_active=True)
            record.phase = "source_published"
            record.source_carrier = source_carrier
            record.source_result = source_result
            record.file_mutation = file_mutation
            record.finalization = finalization
            record.activity_capture = capture
            record.activity_digest = activity_digest
            record.activity_binding_digest = binding_digest
            record.external_transport_uids = snapshot.transport_uids
            self._refresh_locked(record)
        return continuation

    def census(self) -> PersistentSmbTerminalContinuationCensus:
        """Return constant-time exact continuation counts and retained bytes."""

        with self._lock:
            return PersistentSmbTerminalContinuationCensus(
                retained_continuations=len(self._records_by_action),
                active_claims=self._active_claims,
                retained_bytes=self._retained_bytes,
                capacity=self._capacity,
                byte_capacity=self._byte_capacity,
                high_water_continuations=self._high_water_continuations,
                high_water_bytes=self._high_water_bytes,
            )
