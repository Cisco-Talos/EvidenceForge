# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical SMB2/3 disk-share activity bundle."""

from __future__ import annotations

import hashlib
import hmac
import math
import ntpath
import posixpath
import random
import secrets
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from threading import Lock, get_ident
from typing import Any, Literal

from evidenceforge.events.authentication import (
    RemoteAuthenticationPlan,
    RemoteAuthenticationTransportPlan,
)
from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import (
    AuthContext,
    FileContext,
    FileTransferContext,
    ProcessContext,
    SmbContext,
)
from evidenceforge.events.contracts import (
    EffectOccurrenceKind,
    EffectOccurrenceOwner,
    EffectOccurrenceProvenance,
    OwnedEffectOccurrencePlan,
)
from evidenceforge.events.dispatcher import (
    PersistentSmbSourcePublicationResult,
    PreparedPersistentSmbSourcePublication,
)
from evidenceforge.events.identity import EventIdentityPlan
from evidenceforge.events.lifecycle import ActionLifecycleContext
from evidenceforge.events.network import (
    DirectionalTrafficLedger,
    NetworkTrafficLedger,
    NetworkTransactionPlan,
    NetworkTuple,
)
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.actions.network_connection import (
    NetworkConnectionIdentityCapture,
    PersistentSmbRootIntent,
)
from evidenceforge.generation.activity.smb_profiles import load_smb_profiles
from evidenceforge.generation.activity.timing_profiles import get_timing_window
from evidenceforge.generation.baseline_timing import BaselineTimingPlanner
from evidenceforge.generation.persistent_smb_projection import (
    PersistentSmbProjectionPhase,
    encode_persistent_smb_projection_capsule,
)
from evidenceforge.generation.smb_channels import SmbChannelAffinity
from evidenceforge.generation.state_manager import (
    SmbConnectionFinalizationResult,
    SmbFileMutationCommitResult,
)
from evidenceforge.generation.storage_world import (
    CompiledStorageFile,
    CompiledStorageShare,
    StorageWorldModel,
)
from evidenceforge.generation.timing import TimingRuntime
from evidenceforge.models.exceptions import EventContractError, StateError
from evidenceforge.models.scenario import (
    SmbActivityEventSpec,
    SmbClientLocation,
    SmbShareLocation,
    System,
    User,
)
from evidenceforge.utils.ids import generate_stable_zeek_uid
from evidenceforge.utils.rng import _stable_seed, stable_uuid
from evidenceforge.utils.time import parse_duration


@dataclass(frozen=True, slots=True)
class SmbActivityRequest:
    """One authored or baseline SMB activity intent."""

    spec: SmbActivityEventSpec
    actor: User
    parent_system: System
    time: datetime
    process_pid: int = -1
    process_image: str = ""
    activity_source: Literal["storyline", "baseline"] = "storyline"
    files_override: tuple[CompiledStorageFile, ...] = ()


@dataclass(frozen=True, slots=True)
class SmbActivityResult:
    """Ground-truth summary for one bounded SMB activity burst."""

    session_id: str
    tree_ids: tuple[str, ...]
    transport_uids: tuple[str, ...]
    operations: tuple[dict[str, Any], ...]
    completed_at: datetime


class PersistentSmbTerminalContinuation:
    """Opaque exact action-level cursor for post-publication terminal adoption."""

    __slots__ = (
        "_authority_id",
        "_consumed",
        "_continuation_id",
        "_integrity",
    )

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
class _PersistentSmbTerminalFacts:
    """Exact immutable owner set exposed only to the active coordinator claim."""

    cursor: int
    source_carrier: PreparedPersistentSmbSourcePublication
    source_result: PersistentSmbSourcePublicationResult
    file_mutation: SmbFileMutationCommitResult
    finalization: SmbConnectionFinalizationResult
    activity_result: SmbActivityResult


@dataclass(slots=True)
class _PersistentSmbTerminalRecord:
    """Authority-private retained terminal work for one stable action binding."""

    continuation: PersistentSmbTerminalContinuation
    continuation_id: int
    action_id: str
    action_binding_digest: str
    source_carrier: PreparedPersistentSmbSourcePublication
    source_result: PersistentSmbSourcePublicationResult
    file_mutation: SmbFileMutationCommitResult
    finalization: SmbConnectionFinalizationResult
    activity_result: SmbActivityResult
    retained_bytes: int
    integrity: str
    cursor: int = 0
    active_thread_id: int | None = None


class PersistentSmbTerminalContinuationAuthority:
    """Bounded exact owner of restartable post-publication SMB acknowledgements."""

    def __init__(
        self,
        *,
        capacity: int = 1_024,
        byte_capacity: int = 64 * 1024 * 1024,
    ) -> None:
        if type(capacity) is not int or capacity <= 0:
            raise ValueError("Persistent SMB terminal capacity must be a positive exact int")
        if type(byte_capacity) is not int or byte_capacity <= 0:
            raise ValueError("Persistent SMB terminal byte capacity must be a positive exact int")
        self._authority_id = secrets.token_hex(16)
        self._secret = secrets.token_bytes(32)
        self._capacity = capacity
        self._byte_capacity = byte_capacity
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
        if type(action_id) is not str or not action_id or len(action_id.encode("utf-8")) > 512:
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
    def _activity_result_snapshot(result: SmbActivityResult) -> tuple[object, ...]:
        if type(result) is not SmbActivityResult or len(result.operations) > 16:
            raise EventContractError("Persistent SMB terminal result has an invalid exact shape")
        operations: list[tuple[tuple[str, object], ...]] = []
        total_bytes = 0
        for operation in result.operations:
            if type(operation) is not dict or len(operation) > 32:
                raise EventContractError(
                    "Persistent SMB terminal operation has an invalid exact shape"
                )
            rows: list[tuple[str, object]] = []
            for key, value in operation.items():
                if type(key) is not str or type(value) not in {str, int, bool, type(None)}:
                    raise EventContractError(
                        "Persistent SMB terminal operation contains unsupported values"
                    )
                total_bytes += len(key.encode("utf-8"))
                if type(value) is str:
                    total_bytes += len(value.encode("utf-8"))
                if total_bytes > 2 * 1024 * 1024:
                    raise EventContractError(
                        "Persistent SMB terminal result exceeds its byte bound"
                    )
                rows.append((key, value))
            rows.sort(key=lambda item: item[0])
            operations.append(tuple(rows))
        return (
            result.session_id,
            result.tree_ids,
            result.transport_uids,
            tuple(operations),
            result.completed_at,
        )

    @classmethod
    def _record_payload(cls, record: _PersistentSmbTerminalRecord) -> tuple[object, ...]:
        source = record.source_result
        file_mutation = record.file_mutation
        finalization = record.finalization
        return (
            "persistent-smb-terminal-continuation-v1",
            id(record.continuation),
            record.continuation_id,
            record.action_id,
            record.action_binding_digest,
            id(record.source_carrier),
            id(source),
            source.group_id,
            source.generation_id,
            source.publication_key,
            source.publication_binding_digest,
            source.publication_digest,
            id(file_mutation),
            file_mutation.operation_id,
            file_mutation.postimage_digest,
            id(file_mutation.receipt),
            id(finalization),
            finalization.conn_id,
            finalization.final_transaction.stable_id,
            id(finalization.receipt),
            cls._activity_result_snapshot(record.activity_result),
            record.cursor,
            record.active_thread_id,
            record.retained_bytes,
        )

    def _integrity(self, record: _PersistentSmbTerminalRecord) -> str:
        return hmac.new(
            self._secret,
            repr(self._record_payload(record)).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

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
        if not hmac.compare_digest(record.integrity, expected) or not hmac.compare_digest(
            continuation._integrity,
            expected,
        ):
            raise EventContractError("Persistent SMB terminal continuation integrity failed")
        if require_active and record.active_thread_id != get_ident():
            raise EventContractError("Persistent SMB terminal continuation has no active claim")
        return record

    def _refresh_locked(self, record: _PersistentSmbTerminalRecord) -> None:
        integrity = self._integrity(record)
        record.integrity = integrity
        record.continuation._integrity = integrity

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
        """Install and claim exact terminal work before its first acknowledgement."""

        canonical_action = self._bounded_action_id(action_id)
        canonical_binding = self._binding_digest(action_binding_digest)
        if (
            type(source_carrier) is not PreparedPersistentSmbSourcePublication
            or type(source_result) is not PersistentSmbSourcePublicationResult
            or type(file_mutation) is not SmbFileMutationCommitResult
            or type(finalization) is not SmbConnectionFinalizationResult
            or type(activity_result) is not SmbActivityResult
        ):
            raise EventContractError("Persistent SMB terminal install requires exact owner types")
        result_snapshot = self._activity_result_snapshot(activity_result)
        retained_bytes = (
            len(repr(result_snapshot).encode("utf-8"))
            + sum(size for _row, _digest, size in source_result.row_facts)
            + 4_096
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
                source_carrier=source_carrier,
                source_result=source_result,
                file_mutation=file_mutation,
                finalization=finalization,
                activity_result=activity_result,
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

    def claim_existing(
        self,
        *,
        action_id: str,
        action_binding_digest: str,
    ) -> PersistentSmbTerminalContinuation | None:
        """Claim exact retained terminal work for one ordinary public retry."""

        canonical_action = self._bounded_action_id(action_id)
        canonical_binding = self._binding_digest(action_binding_digest)
        with self._lock:
            record = self._records_by_action.get(canonical_action)
            if record is None:
                return None
            self._record_locked(record.continuation, require_active=False)
            if not hmac.compare_digest(record.action_binding_digest, canonical_binding):
                raise EventContractError(
                    "Persistent SMB terminal retry changed its exact action binding"
                )
            if record.active_thread_id is not None:
                raise EventContractError("Persistent SMB terminal continuation is already active")
            record.active_thread_id = get_ident()
            self._active_claims += 1
            self._refresh_locked(record)
            return record.continuation

    def facts(
        self,
        continuation: PersistentSmbTerminalContinuation,
    ) -> _PersistentSmbTerminalFacts:
        """Return exact terminal owners to their one active coordinator claim."""

        with self._lock:
            record = self._record_locked(continuation, require_active=True)
            return _PersistentSmbTerminalFacts(
                cursor=record.cursor,
                source_carrier=record.source_carrier,
                source_result=record.source_result,
                file_mutation=record.file_mutation,
                finalization=record.finalization,
                activity_result=record.activity_result,
            )

    def advance(
        self,
        continuation: PersistentSmbTerminalContinuation,
        *,
        expected_cursor: int,
    ) -> None:
        """Generation-CAS advance one authenticated terminal acknowledgement."""

        if type(expected_cursor) is not int or not 0 <= expected_cursor < 4:
            raise EventContractError("Persistent SMB terminal cursor is out of range")
        with self._lock:
            record = self._record_locked(continuation, require_active=True)
            if record.cursor != expected_cursor:
                raise EventContractError("Persistent SMB terminal cursor changed concurrently")
            record.cursor += 1
            self._refresh_locked(record)

    def release_claim(self, continuation: PersistentSmbTerminalContinuation) -> None:
        """Release one failed active claim while retaining its exact cursor."""

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
            if record.cursor != 4:
                raise EventContractError("Persistent SMB terminal continuation is incomplete")
            self._records_by_action.pop(record.action_id)
            self._records_by_carrier.pop(id(continuation))
            self._active_claims -= 1
            self._retained_bytes -= record.retained_bytes
            continuation._consumed = True
            return record.activity_result

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


@dataclass(frozen=True, slots=True)
class _SmbOperationTiming:
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


class SmbActivityActionBundle:
    """Compose transport/auth contracts and own SMB application semantics."""

    def __init__(self, executor: Any, request: SmbActivityRequest) -> None:
        self.executor = executor
        self.request = request
        self.world: StorageWorldModel = executor._storage_world
        self.anchor = ActionAnchor(
            family="smb_activity",
            stable_id=stable_uuid(
                "smb-activity",
                request.time,
                request.actor.username,
                request.parent_system.hostname,
                request.spec.operation,
            ),
            source=request.activity_source,
        )
        self.rng = random.Random(_stable_seed(f"smb-activity:{self.anchor.stable_id}"))

    def _timing_planner(self) -> BaselineTimingPlanner:
        """Return the shared engine timing planner for this SMB action."""

        runtime = getattr(self.executor, "timing_runtime", None)
        if not isinstance(runtime, TimingRuntime):
            raise StateError("SMB activity requires the executor-owned TimingRuntime")
        return BaselineTimingPlanner(runtime, source="smb")

    def _timing_host(self) -> str:
        """Return the semantic host when direct timing fixtures omit it."""

        return str(getattr(getattr(self.request, "parent_system", None), "hostname", ""))

    def _persistent_terminal_binding_digest(
        self,
        *,
        share: CompiledStorageShare,
        selected: tuple[CompiledStorageFile, ...],
        server: System,
        client_system: System | None,
        client_ip: str,
        auth_protocol: str,
        duration: float,
        target_formats: tuple[str, ...],
    ) -> str:
        """Bind an ordinary retry to the exact pre-canonical Windows request."""

        payload = (
            "persistent-smb-terminal-action-binding-v1",
            self.anchor.stable_id,
            self.anchor.source,
            self.request.time,
            self.request.actor.username,
            self.request.parent_system.hostname,
            self.request.process_pid,
            self.request.process_image,
            self.request.spec.operation,
            self.request.spec.outcome,
            self.request.spec.purpose,
            share.ref,
            share.name,
            share.encryption,
            share.audit,
            server.hostname,
            server.ip,
            client_system.hostname if client_system is not None else "",
            client_ip,
            self.smb_principal,
            auth_protocol,
            duration,
            tuple(
                (
                    file.file_id,
                    file.version,
                    file.share,
                    file.path,
                    file.size_bytes,
                    file.mime_type,
                )
                for file in selected
            ),
            target_formats,
        )
        return hashlib.sha256(repr(payload).encode("utf-8")).hexdigest()

    def execute(self) -> SmbActivityResult:
        spec = self.request.spec
        composite = self._execute_composite_transfer()
        if composite is not None:
            return composite
        share_locations = self._share_locations()
        if not share_locations:
            raise ValueError("smb_activity requires at least one share location")
        primary_location = share_locations[0]
        share = self.world.share(primary_location.share)
        server = self._system(share.system)
        client_system, client_ip = self._client(server)
        self.server = server
        self.client_system = client_system
        self.mapping, self.smb_principal = self._resolve_share_leg(share)
        self.client_access = self._resolve_client_access(client_system)
        self.outcome = self._resolve_outcome(share, primary_location)
        auth_protocol = self._resolved_auth_protocol(server)
        principal_user = self.executor._user_model_for_username(self.smb_principal)
        effective_uid, effective_gid = self._effective_samba_identity(
            server,
            self.smb_principal,
        )
        selected = self._select(primary_location)
        creates_remote_copy = (
            spec.operation in {"copy", "move"}
            and not isinstance(spec.source, SmbShareLocation)
            and isinstance(spec.destination, SmbShareLocation)
        )
        if (spec.operation == "create" or creates_remote_copy) and not self.request.files_override:
            selected = (self._create_placeholder(primary_location, share),)
        if not selected and spec.outcome == "not_found" and primary_location.path is not None:
            selected = (self._missing_placeholder(primary_location, share),)
        if not selected:
            raise ValueError(f"smb_activity selected no files on {share.ref}")

        duration = self._duration(selected)
        if self._server_platform(server) == "windows":
            if len(selected) != 1:
                raise ValueError(
                    "Persistent Windows SMB production currently requires one file operation"
                )
            target_formats = self.executor.dispatcher.persistent_smb_configured_projection_targets()
            terminal_binding_digest = self._persistent_terminal_binding_digest(
                share=share,
                selected=selected,
                server=server,
                client_system=client_system,
                client_ip=client_ip,
                auth_protocol=auth_protocol or "ntlm",
                duration=duration,
                target_formats=target_formats,
            )
            terminal_continuation = (
                self.executor._persistent_smb_terminal_continuations.claim_existing(
                    action_id=self.anchor.stable_id,
                    action_binding_digest=terminal_binding_digest,
                )
            )
            if terminal_continuation is not None:
                return self._resume_persistent_windows_terminal(terminal_continuation)
            route_generation_digest = hashlib.sha256(
                repr(
                    (
                        "persistent-smb-production-route-v1",
                        self.anchor.stable_id,
                        target_formats,
                    )
                ).encode("utf-8")
            ).hexdigest()
            projection_group = self.executor.dispatcher.reserve_persistent_smb_projection_group(
                route_generation_digest=route_generation_digest,
                member_budget=8,
                byte_budget=2 * 1024 * 1024,
                required_target_formats=target_formats,
            )
            try:
                return self._execute_persistent_windows(
                    share=share,
                    selected=selected,
                    server=server,
                    client_system=client_system,
                    client_ip=client_ip,
                    principal_user=principal_user,
                    auth_protocol=auth_protocol or "ntlm",
                    effective_uid=effective_uid,
                    effective_gid=effective_gid,
                    process=None,
                    transport_pid=-1,
                    transport_image="",
                    duration=duration,
                    projection_group=projection_group,
                    target_formats=target_formats,
                    terminal_binding_digest=terminal_binding_digest,
                )
            except BaseException as primary:
                try:
                    self.executor.dispatcher.cancel_empty_persistent_smb_projection_group(
                        projection_group
                    )
                except BaseException as cleanup_error:
                    primary.add_note(
                        "Persistent SMB empty-group cancellation also failed: "
                        f"{type(cleanup_error).__name__}: {cleanup_error}"
                    )
                raise
        process_plan = None
        if client_system is not None:
            first_path = selected[0].path
            source_path, destination_path = self._process_transfer_operands(
                first_path,
                share,
            )
            process_plan = self.executor.ensure_smb_client_process(
                client_system=client_system,
                actor=self.request.actor,
                server=server.hostname,
                share=share.name,
                path=first_path,
                client_path=self._client_path(first_path, share),
                local_path=self._local_path(first_path),
                source_path=source_path,
                destination_path=destination_path,
                operation=spec.operation,
                time=self.request.time,
                client_access=self.client_access,
                smb_principal=self.smb_principal,
                auth_protocol=auth_protocol,
                transfer_direction=(
                    "upload"
                    if spec.operation in {"copy", "move"}
                    and isinstance(spec.source, SmbClientLocation)
                    else "download"
                    if spec.operation in {"copy", "move"}
                    and isinstance(spec.destination, SmbClientLocation)
                    else "remote"
                    if spec.operation in {"copy", "move"}
                    else None
                ),
                preferred_pid=self.request.process_pid or -1,
                source_visible_by=self.request.time,
            )
        process = self._process_context(
            client_system,
            preferred_pid=process_plan.actor_pid if process_plan is not None else None,
        )
        transport_pid = (
            process_plan.transport_pid
            if process_plan is not None
            else process.pid
            if process is not None
            else (self.request.process_pid or -1)
        )
        transport_image = (
            process_plan.transport_image
            if process_plan is not None
            else process.image
            if process is not None
            else self.request.process_image
        )
        transport_uid = self.executor.generate_connection(
            src_ip=client_ip,
            dst_ip=server.ip,
            time=self.request.time,
            dst_port=445,
            proto="tcp",
            service="smb",
            duration=duration,
            orig_bytes=self._transport_bytes(selected, write=True),
            resp_bytes=self._transport_bytes(selected, write=False),
            conn_state="SF",
            emit_dns=client_system is not None,
            source_system=client_system,
            pid=transport_pid,
            process_image=transport_image or None,
            preserve_explicit_payload=True,
            suppress_application_side_effects=True,
            suppress_source_pid_inference=self.client_access == "cifs_mount",
            parent_action_group_id=self.anchor.stable_id,
        )
        transport_plan = self.executor.dispatcher.network_plan_for(transport_uid)
        if transport_plan is None:
            raise ValueError(f"SMB transport {transport_uid!r} was not published for composition")
        if client_system is not None and process_plan is not None and process_plan.actor_pid > 0:
            self.executor._remember_process_dependent_hold(
                system=client_system,
                pid=process_plan.actor_pid,
                required_until=transport_plan.closed_at,
            )
        if process is None and client_system is not None and transport_plan.initiating_pid > 0:
            process = self._process_context(
                client_system,
                preferred_pid=transport_plan.initiating_pid,
            )
        self.transport_start = transport_plan.started_at
        ground_truth_transport_uid = self._ground_truth_transport_uid(transport_uid)
        source_port = (
            self.executor._last_effective_connection_source_port(
                src_ip=client_ip,
                dst_ip=server.ip,
                dst_port=445,
            )
            or 0
        )
        transaction_id = self.executor._last_effective_connection_transaction_id(
            src_ip=client_ip,
            src_port=source_port,
            dst_ip=server.ip,
            dst_port=445,
        )
        auth_delay_ms = self.rng.randint(28, 96)
        tree_delay_ms = self.rng.randint(14, 88)
        auth_time = self.transport_start + timedelta(milliseconds=auth_delay_ms)
        auth_session_ref = stable_uuid(
            "smb-auth-session",
            self.anchor.stable_id,
            server.hostname,
            self.smb_principal,
            client_ip,
            source_port,
            auth_time.isoformat(),
        )
        remote_authentication_plan = None
        if self._server_platform(server) == "linux":
            remote_authentication_plan = RemoteAuthenticationPlan(
                stable_id=f"smb-remote-auth-{self.anchor.stable_id}",
                source_hostname=client_system.hostname if client_system is not None else "",
                target_hostname=server.hostname,
                logon_type=3,
                auth_protocol=auth_protocol,
                outcome="success",
                canonical_auth_time=auth_time,
                transports=(
                    RemoteAuthenticationTransportPlan(
                        role="target_service",
                        transaction_id=transaction_id,
                        tuple=NetworkTuple(
                            src_ip=transport_plan.src_ip,
                            src_port=transport_plan.src_port,
                            dst_ip=transport_plan.dst_ip,
                            dst_port=transport_plan.dst_port,
                            protocol=transport_plan.protocol,
                        ),
                        started_at=transport_plan.started_at,
                        closed_at=transport_plan.closed_at,
                        primary=True,
                    ),
                ),
                session_kind="smb",
                principal=self.smb_principal,
                account_scope="directory",
                auth_session_ref=auth_session_ref,
                effective_uid=effective_uid,
                effective_gid=effective_gid,
            )
        logon_id = self.executor.generate_logon(
            user=principal_user,
            system=server,
            time=auth_time,
            logon_type=3,
            source_ip=client_ip,
            source_system=client_system,
            source_port=source_port,
            emit_network_evidence=False,
            remote_authentication_plan=remote_authentication_plan,
            remote_authentication_transport_id=transaction_id,
            remote_auth_destination_port=445,
            lifecycle_group_id=self.anchor.stable_id,
            session_kind="smb",
            auth_protocol=auth_protocol,
            smb_principal=self.smb_principal,
            account_scope="directory",
            auth_session_ref=auth_session_ref,
            effective_uid=effective_uid,
            effective_gid=effective_gid,
        )
        active_auth_session = self.executor.state_manager.get_session(logon_id)
        if active_auth_session is not None and active_auth_session.auth_protocol:
            auth_protocol = active_auth_session.auth_protocol
        session = self.executor.state_manager.open_smb_session(
            client_ip=client_ip,
            principal=self.smb_principal,
            server=server.hostname,
            security_policy="encrypted" if share.encryption == "required" else "standard",
            logon_id=logon_id,
            transport_uid=transport_uid,
            started_at=auth_time,
            auth_session_ref=auth_session_ref,
            auth_protocol=auth_protocol,
            account_scope="directory",
            effective_uid=effective_uid,
            effective_gid=effective_gid,
            client_access=self.client_access,
            idle_timeout=self._idle_timeout(),
            reuse=False,
        )
        tree = self.executor.state_manager.get_or_open_smb_tree(
            session.session_id,
            share.ref,
            auth_time + timedelta(milliseconds=tree_delay_ms),
        )
        net = self._application_network_plan(
            transport_plan=transport_plan,
        )
        auth = AuthContext(
            username=self.smb_principal,
            user_sid=self.executor._get_sid(self.smb_principal),
            logon_id=logon_id if self._server_platform(server) == "windows" else "",
            logon_type=3,
            source_ip=client_ip,
            source_port=source_port,
            session_kind="smb",
            auth_protocol=auth_protocol,
            smb_principal=self.smb_principal,
            account_scope="directory",
            auth_session_ref=auth_session_ref,
            effective_uid=effective_uid,
            effective_gid=effective_gid,
        )
        smb_platform_fields = self._smb_platform_fields(share, server)
        self._emit_phase(
            event_type="smb_tree_connect",
            timestamp=auth_time + timedelta(milliseconds=tree_delay_ms),
            network=net,
            server=server,
            client=client_system,
            auth=auth,
            process=process,
            smb=SmbContext(
                phase="tree_connect",
                operation=spec.operation,
                purpose=spec.purpose,
                session_id=session.session_id,
                tree_id=tree.tree_id,
                share_ref=share.ref,
                share_name=share.name,
                share_local_path=self.world.server_local_path(share, ""),
                result="success",
                requested_access=self._requested_access(),
                **smb_platform_fields,
                encrypted=share.encryption == "required",
                audit=share.audit,
            ),
        )

        operation_truth: list[dict[str, Any]] = []
        operation_start = (
            auth_time
            + timedelta(milliseconds=tree_delay_ms)
            + timedelta(seconds=self._session_setup_seconds())
        )
        operation_cursor = operation_start
        for index, file in enumerate(selected):
            planned_timing = self._operation_timing(
                file,
                index,
                size_bytes=self._planned_transfer_size(file, index),
            )
            truth = self._execute_file_operation(
                file=file,
                operation_index=index,
                share=share,
                tree_id=tree.tree_id,
                network=net,
                server=server,
                client=client_system,
                auth=auth,
                process=None,
                timestamp=operation_cursor,
            )
            operation_truth.append(truth)
            operation_cursor += timedelta(seconds=planned_timing.total_seconds)

        close_time = self.transport_start + timedelta(seconds=max(0.2, duration - 0.02))
        self.executor.generate_logoff(
            principal_user,
            server,
            close_time,
            logon_id,
            logon_type=3,
            from_storyline=True,
        )
        self.executor.state_manager.close_smb_session(session.session_id, close_time)
        return SmbActivityResult(
            session_id=session.session_id,
            tree_ids=(tree.tree_id,),
            transport_uids=(ground_truth_transport_uid,),
            operations=tuple(operation_truth),
            completed_at=close_time,
        )

    def _execute_persistent_windows(
        self,
        *,
        share: CompiledStorageShare,
        selected: tuple[CompiledStorageFile, ...],
        server: System,
        client_system: System | None,
        client_ip: str,
        principal_user: User,
        auth_protocol: str,
        effective_uid: int | None,
        effective_gid: int | None,
        process: ProcessContext | None,
        transport_pid: int,
        transport_image: str,
        duration: float,
        projection_group: object,
        target_formats: tuple[str, ...],
        terminal_binding_digest: str,
    ) -> SmbActivityResult:
        """Execute the first persistent Windows disk-share production vertical."""

        if self.request.spec.operation != "read":
            raise ValueError("Persistent Windows SMB production currently supports one read")
        file = selected[0]
        auth_time = self.request.time + timedelta(milliseconds=self.rng.randint(28, 96))
        tree_time = auth_time + timedelta(milliseconds=self.rng.randint(14, 88))
        close_time = self.request.time + timedelta(seconds=max(0.2, duration - 0.02))
        auth_session_ref = stable_uuid(
            "persistent-smb-auth-session",
            self.anchor.stable_id,
            server.hostname,
            self.smb_principal,
            client_ip,
            auth_time,
        )
        capture = NetworkConnectionIdentityCapture()
        transport_uid = self.executor.generate_connection(
            src_ip=client_ip,
            dst_ip=server.ip,
            time=self.request.time,
            dst_port=445,
            proto="tcp",
            service="smb",
            duration=duration,
            orig_bytes=1_024,
            resp_bytes=1_536,
            conn_state="SF",
            emit_dns=client_system is not None,
            source_system=client_system,
            pid=-1,
            process_image=None,
            preserve_start_time=True,
            preserve_explicit_payload=True,
            suppress_application_side_effects=True,
            suppress_source_pid_inference=True,
            parent_action_group_id=self.anchor.stable_id,
            persistent_smb_root_intent=PersistentSmbRootIntent(
                username=principal_user.username,
                system=server.hostname,
                auth_time=auth_time,
                lifecycle_group_id=self.anchor.stable_id,
                auth_protocol=auth_protocol,
                smb_principal=self.smb_principal,
                account_scope="directory",
                auth_session_ref=auth_session_ref,
                effective_uid=effective_uid,
                effective_gid=effective_gid,
            ),
            defer_source_publication=True,
            identity_capture=capture,
        )
        opening = capture.require()
        if opening.closed_at is None:
            raise StateError("Persistent SMB root lost its canonical close")
        close_time = opening.closed_at
        self.transport_start = opening.started_at
        handoff = capture.require_persistent_smb_root_handoff()
        pin_install = handoff.pin_install_receipt
        lifecycle_receipt = capture.require_receipt()
        if (
            opening.zeek_uid != transport_uid
            or not self.executor.state_manager.authenticates_smb_connection_pin_install_receipt(
                pin_install
            )
            or not self.executor._lifecycle_authority.authenticates_prepared_network_receipt(
                capture.require_prepared_root(),
                lifecycle_receipt,
            )
        ):
            raise StateError("Persistent SMB root handoff failed owner authentication")
        lifecycle_binding = self.executor._lifecycle_authority.detach_prepared_network_receipt(
            lifecycle_receipt
        )
        traffic_binding = self.executor._persistent_smb_traffic_authority.issue_binding(
            opening,
            handoff.observations,
        )
        self.executor.dispatcher.consume_persistent_smb_prepared_transport(
            handoff.prepared_dispatch,
            materialization_receipt=lifecycle_receipt,
        )
        if not self.executor.state_manager.acknowledge_smb_connection_pin_install(pin_install):
            raise StateError("Persistent SMB pin-install acknowledgement failed")
        session_identity = pin_install.session_identity
        operation_timing = self._operation_timing(
            file,
            0,
            size_bytes=self._planned_transfer_size(file, 0),
        )
        operation_start = tree_time + timedelta(seconds=self._session_setup_seconds())
        operation_end = operation_start + timedelta(seconds=operation_timing.total_seconds)
        affinity = SmbChannelAffinity(
            client_identity=(client_system.hostname if client_system is not None else client_ip),
            client_ip=client_ip,
            client_session=(
                process.logon_id if process is not None and process.logon_id else "none"
            ),
            server_identity=server.hostname,
            server_ip=server.ip,
            principal=self.smb_principal,
            auth_protocol=auth_protocol,
            account_scope="directory",
            dialect="3.1.1",
            signing_policy="required",
            encryption_policy="required" if share.encryption == "required" else "off",
            server_policy="windows:file-server",
            share_policy="disk:standard",
            client_access=self.client_access,
        )
        final_orig_bytes = self._transport_bytes(selected, write=True)
        final_resp_bytes = self._transport_bytes(selected, write=False)
        lease = self.executor._smb_channel_manager.open_session(
            affinity,
            transport_plan=opening,
            sensor_observations=handoff.observations,
            ground_truth_transport_uid=opening.zeek_uid,
            logon_id=session_identity.logon_id,
            auth_session_ref=auth_session_ref,
            principal=self.smb_principal,
            auth_protocol=auth_protocol,
            account_scope="directory",
            effective_uid=effective_uid,
            effective_gid=effective_gid,
            client_access=self.client_access,
            server_hostname=server.hostname,
            client_ip=client_ip,
            lifecycle_group_id=self.anchor.stable_id,
            share_ref=share.ref,
            semantic_operation_id=f"{self.anchor.stable_id}:0",
            operation_started_at=operation_start,
            operation_ended_at=operation_end,
            operation_initiator_bytes=final_orig_bytes,
            operation_responder_bytes=final_resp_bytes,
            idle_timeout=self._idle_timeout(),
            initiator_budget=final_orig_bytes,
            responder_budget=final_resp_bytes,
            operation_budget=1,
        )
        journal = self.executor.state_manager.begin_smb_file_mutation_journal(lease.operation_id)
        state = self.executor.state_manager.touch_smb_file(file, journal=journal)
        handle = self.executor._smb_channel_manager.open_handle(
            lease,
            file_id=state.file_id,
            content_version=state.version,
            access="read",
            opened_at=operation_start,
        )
        action_time = operation_start + timedelta(
            seconds=operation_timing.setup_seconds + operation_timing.jitter_seconds
        )
        handle_close_time = action_time + timedelta(
            seconds=operation_timing.transfer_seconds + operation_timing.close_delay_seconds
        )
        handle_closed = False
        try:
            handle_closed = self.executor._smb_channel_manager.close_handle(
                handle,
                lease,
                closed_at=handle_close_time,
            )
        except BaseException as primary:
            try:
                handle_closed = self.executor._smb_channel_manager.close_handle(
                    handle,
                    lease,
                    closed_at=handle_close_time,
                )
            except BaseException as recovery_error:
                primary.add_note(
                    "Persistent SMB handle-close retry also failed: "
                    f"{type(recovery_error).__name__}: {recovery_error}"
                )
                raise primary from recovery_error
            if not handle_closed:
                snapshot = self.executor._smb_channel_manager.channel_snapshot(lease.channel_id)
                if snapshot is None or snapshot.closed_at is not None:
                    raise primary from None
                handle_closed = True
        if not handle_closed:
            raise StateError("Persistent SMB handle did not close exactly once")

        operation_finalized = False
        try:
            operation_finalized = self.executor._smb_channel_manager.finalize_operation(lease)
        except BaseException as primary:
            try:
                operation_finalized = self.executor._smb_channel_manager.finalize_operation(lease)
            except BaseException as recovery_error:
                primary.add_note(
                    "Persistent SMB operation-finalization retry also failed: "
                    f"{type(recovery_error).__name__}: {recovery_error}"
                )
                raise primary from recovery_error
            if not operation_finalized:
                snapshot = self.executor._smb_channel_manager.channel_snapshot(lease.channel_id)
                if (
                    snapshot is None
                    or snapshot.active_operations != 0
                    or snapshot.completed_operations != 1
                ):
                    raise primary from None
                operation_finalized = True
        if not operation_finalized:
            raise StateError("Persistent SMB operation did not finalize exactly once")

        closure = None
        try:
            closure = self.executor._smb_channel_manager.close_session(
                lease.channel_id,
                closed_at=close_time,
                reason="logoff",
            )
        except BaseException as primary:
            try:
                closure = self.executor._smb_channel_manager.close_session(
                    lease.channel_id,
                    closed_at=close_time,
                    reason="logoff",
                )
            except BaseException as recovery_error:
                primary.add_note(
                    "Persistent SMB session-close retry also failed: "
                    f"{type(recovery_error).__name__}: {recovery_error}"
                )
                raise primary from recovery_error
            if closure is None:
                snapshot = self.executor._smb_channel_manager.channel_snapshot(lease.channel_id)
                if (
                    snapshot is None
                    or snapshot.closed_at != close_time
                    or snapshot.close_reason != "logoff"
                    or snapshot.active_operations != 0
                ):
                    raise primary from None
        if closure is None:
            snapshot = self.executor._smb_channel_manager.channel_snapshot(lease.channel_id)
            if (
                snapshot is None
                or snapshot.closed_at != close_time
                or snapshot.close_reason != "logoff"
            ):
                raise StateError("Persistent SMB channel close lost its live session")

        final_traffic = self._persistent_final_traffic(
            opening.traffic,
            orig_payload=final_orig_bytes,
            resp_payload=final_resp_bytes,
        )
        final_transaction = replace(opening, traffic=final_traffic)
        final_observation_traffic = tuple(
            final_traffic
            if observation.traffic is opening.traffic
            else self._persistent_final_traffic(
                observation.traffic,
                orig_payload=(
                    final_orig_bytes
                    - (opening.traffic.orig.payload_bytes - observation.traffic.orig.payload_bytes)
                ),
                resp_payload=(
                    final_resp_bytes
                    - (opening.traffic.resp.payload_bytes - observation.traffic.resp.payload_bytes)
                ),
            )
            for observation in handoff.observations
        )
        auth = AuthContext(
            username=self.smb_principal,
            user_sid=self.executor._get_sid(self.smb_principal),
            logon_id=session_identity.logon_id,
            logon_type=3,
            source_ip=client_ip,
            source_port=opening.src_port,
            session_kind="smb",
            auth_protocol=auth_protocol,
            smb_principal=self.smb_principal,
            account_scope="directory",
            auth_session_ref=auth_session_ref,
            effective_uid=effective_uid,
            effective_gid=effective_gid,
        )
        application_network = self._application_network_plan(transport_plan=final_transaction)
        smb_fields = self._smb_platform_fields(share, server)
        common = dict(
            operation="read",
            purpose=self.request.spec.purpose,
            session_id=lease.session_id,
            tree_id=lease.tree_id,
            share_ref=share.ref,
            share_name=share.name,
            result=self.outcome,
            requested_access=self._requested_access(),
            client_path=self._client_path(state.path, share),
            local_path=self._local_path(state.path),
            share_path=state.path,
            server_path=self.world.server_local_path(share, state.path),
            share_local_path=self.world.server_local_path(share, ""),
            file_id=state.file_id,
            content_version=state.version,
            handle_id=handle.handle_id,
            size_bytes=state.size_bytes,
            **smb_fields,
            encrypted=share.encryption == "required",
            audit=share.audit,
        )
        file_transfer = FileTransferContext(
            fuid=self._file_transfer_fuid(state, "read"),
            source="SMB",
            filename=state.path,
            analyzers=("MIME",),
            mime_type=state.mime_type,
            duration=operation_timing.transfer_seconds,
            local_orig=client_system is not None,
            is_orig=False,
            seen_bytes=state.size_bytes,
            total_bytes=state.size_bytes,
        )
        owned_projection_plan = OwnedEffectOccurrencePlan(
            owner=EffectOccurrenceOwner.SMB_PROTOCOL_FILE_PHASE,
            kind=EffectOccurrenceKind.FILE,
            root_action_id=self.anchor.stable_id,
            instance_key=lease.operation_id,
            occurrence_count=5,
        )
        events = (
            OccurrenceBuilder(
                timestamp=final_transaction.started_at,
                event_type="connection",
                src_host=(
                    self.executor._build_host_context(client_system)
                    if client_system is not None
                    else None
                ),
                dst_host=self.executor._build_host_context(server),
                process=None,
                network=final_transaction,
                identity_plan=EventIdentityPlan(session=session_identity),
                effect_provenance=owned_projection_plan.provenance(0),
                lifecycle=ActionLifecycleContext(
                    group_id=self.anchor.stable_id,
                    canonical_start=final_transaction.started_at,
                    phase="dependent",
                    parent_group_id=final_transaction.zeek_uid,
                ),
            ),
            OccurrenceBuilder(
                timestamp=auth_time,
                event_type="logon",
                dst_host=self.executor._build_host_context(server),
                auth=auth,
                identity_plan=EventIdentityPlan(
                    subject=session_identity,
                    session=session_identity,
                ),
                lifecycle=ActionLifecycleContext(
                    group_id=self.anchor.stable_id,
                    canonical_start=final_transaction.started_at,
                    phase="start",
                    parent_group_id=final_transaction.zeek_uid,
                ),
            ),
            self._phase_builder(
                event_type="smb_tree_connect",
                timestamp=tree_time,
                network=application_network,
                server=server,
                client=client_system,
                auth=auth,
                process=None,
                smb=SmbContext(phase="tree_connect", **common),
                identity_plan=EventIdentityPlan(session=session_identity),
                effect_provenance=owned_projection_plan.provenance(1),
            ),
            self._phase_builder(
                event_type="smb_file_open",
                timestamp=operation_start,
                network=application_network,
                server=server,
                client=client_system,
                auth=auth,
                process=None,
                smb=SmbContext(phase="open", **common),
                identity_plan=EventIdentityPlan(session=session_identity),
                effect_provenance=owned_projection_plan.provenance(2),
            ),
            self._phase_builder(
                event_type="smb_file_read",
                timestamp=action_time,
                network=application_network,
                server=server,
                client=client_system,
                auth=auth,
                process=None,
                smb=SmbContext(phase="read", **common),
                file_transfer=file_transfer,
                identity_plan=EventIdentityPlan(session=session_identity),
                include_file_context=False,
                effect_provenance=owned_projection_plan.provenance(3),
            ),
            self._phase_builder(
                event_type="smb_file_close",
                timestamp=handle_close_time,
                network=application_network,
                server=server,
                client=client_system,
                auth=auth,
                process=None,
                smb=SmbContext(phase="close", **common),
                identity_plan=EventIdentityPlan(session=session_identity),
                effect_provenance=owned_projection_plan.provenance(4),
            ),
            OccurrenceBuilder(
                timestamp=close_time,
                event_type="logoff",
                dst_host=self.executor._build_host_context(server),
                auth=auth,
                identity_plan=EventIdentityPlan(
                    subject=session_identity,
                    session=session_identity,
                ),
                lifecycle=ActionLifecycleContext(
                    group_id=self.anchor.stable_id,
                    canonical_start=final_transaction.started_at,
                    phase="end",
                    parent_group_id=final_transaction.zeek_uid,
                ),
            ),
        )
        state_builder = self.executor.state_manager.begin_action_cohort_materialization()
        state_builder.finalize_smb_connection(
            pin_install.pin,
            final_transaction,
            session_identity,
            end_time=close_time,
        )
        state_plan = state_builder.seal()
        if not self.executor._lifecycle_authority.authenticates_detached_network_receipt_binding(
            lifecycle_binding
        ):
            raise StateError("Persistent SMB lifecycle binding failed authentication")

        def owner_digest(label: str, values: tuple[object, ...]) -> str:
            return hashlib.sha256(repr((label, values)).encode("utf-8")).hexdigest()

        def owner_generation(digest: str) -> int:
            return (int(digest[:16], 16) % ((1 << 63) - 1)) + 1

        lifecycle_digest = owner_digest(
            "persistent-smb-lifecycle-binding-v1",
            (
                lifecycle_binding.transaction_id,
                lifecycle_binding.state_publication_token,
                lifecycle_binding.runtime_publication_token,
                lifecycle_binding.physical_transport_id,
                lifecycle_binding.conn_id,
                lifecycle_binding.zeek_uid,
                lifecycle_binding.network_result_digest,
                lifecycle_binding.timing_receipt_digest,
                lifecycle_binding.runtime_receipt_digest,
                lifecycle_binding.connection_receipt_digest,
                object.__getattribute__(lifecycle_binding, "_integrity_token"),
            ),
        )
        network_digest = owner_digest(
            "persistent-smb-network-binding-v1",
            (
                opening.stable_id,
                opening.conn_id,
                opening.zeek_uid,
                opening.src_ip,
                opening.src_port,
                opening.dst_ip,
                opening.dst_port,
                opening.started_at,
                opening.closed_at,
                pin_install.initial_transaction_digest,
                pin_install.pin.conn_id,
                pin_install.pin.zeek_uid,
                object.__getattribute__(pin_install, "_integrity_token"),
            ),
        )
        traffic_digest = owner_digest(
            "persistent-smb-traffic-binding-v1",
            (
                traffic_binding.authority_id,
                traffic_binding.binding_id,
                traffic_binding.transport_digest,
                traffic_binding.observation_digests,
                traffic_binding.lossless_ordinals,
                object.__getattribute__(traffic_binding, "_integrity"),
            ),
        )
        lifecycle_generation = owner_generation(lifecycle_digest)
        network_generation = owner_generation(network_digest)
        traffic_generation = owner_generation(traffic_digest)

        source_carriers: list[object] = []
        member_specs: list[tuple[PersistentSmbProjectionPhase, str, str, bytes]] = []
        source_specs = (
            (events[0], PersistentSmbProjectionPhase.TRANSPORT),
            (events[1], PersistentSmbProjectionPhase.TYPE3_LOGON),
            (events[2], PersistentSmbProjectionPhase.TREE_OR_FILE),
            (events[3], PersistentSmbProjectionPhase.TREE_OR_FILE),
            (events[4], PersistentSmbProjectionPhase.TREE_OR_FILE),
            (events[5], PersistentSmbProjectionPhase.TREE_OR_FILE),
        )
        operation_digests: list[str] = []
        with self.executor.dispatcher.source_timing_planner.prepared_planning() as timing:
            for ordinal, (event, phase) in enumerate(source_specs):
                operation_id = f"{self.anchor.stable_id}:{ordinal}:{phase.value}"
                operation_binding_digest = owner_digest(
                    "persistent-smb-projection-operation-v1",
                    (
                        operation_id,
                        event.event_type,
                        event.timestamp,
                        lifecycle_digest,
                        network_digest,
                    ),
                )
                capsule = encode_persistent_smb_projection_capsule(
                    (
                        self.anchor.stable_id.encode("utf-8"),
                        operation_id.encode("utf-8"),
                        phase.value.encode("ascii"),
                        str(event.event_type).encode("utf-8"),
                        event.timestamp.isoformat().encode("ascii"),
                    )
                )
                carrier = self.executor.dispatcher.prepare_persistent_smb_source_projection(
                    projection_group,
                    event,
                    source_timing_preparation=timing,
                    target_formats=target_formats,
                )
                source_carriers.append(carrier)
                member_specs.append((phase, operation_id, operation_binding_digest, capsule))
                operation_digests.append(operation_binding_digest)

            disconnect_ordinal = len(member_specs)
            disconnect_operation_id = (
                f"{self.anchor.stable_id}:{disconnect_ordinal}:"
                f"{PersistentSmbProjectionPhase.TREE_DISCONNECT.value}"
            )
            disconnect_digest = owner_digest(
                "persistent-smb-projection-operation-v1",
                (
                    disconnect_operation_id,
                    lease.tree_id,
                    close_time,
                    lifecycle_digest,
                    network_digest,
                ),
            )
            disconnect_capsule = encode_persistent_smb_projection_capsule(
                (
                    self.anchor.stable_id.encode("utf-8"),
                    disconnect_operation_id.encode("utf-8"),
                    PersistentSmbProjectionPhase.TREE_DISCONNECT.value.encode("ascii"),
                    lease.tree_id.encode("utf-8"),
                    close_time.isoformat().encode("ascii"),
                )
            )
            member_specs.append(
                (
                    PersistentSmbProjectionPhase.TREE_DISCONNECT,
                    disconnect_operation_id,
                    disconnect_digest,
                    disconnect_capsule,
                )
            )
            operation_digests.append(disconnect_digest)

            logoff_ordinal = len(member_specs)
            logoff_event = events[6]
            logoff_operation_id = (
                f"{self.anchor.stable_id}:{logoff_ordinal}:"
                f"{PersistentSmbProjectionPhase.LOGOFF.value}"
            )
            logoff_digest = owner_digest(
                "persistent-smb-projection-operation-v1",
                (
                    logoff_operation_id,
                    logoff_event.event_type,
                    logoff_event.timestamp,
                    lifecycle_digest,
                    network_digest,
                ),
            )
            logoff_capsule = encode_persistent_smb_projection_capsule(
                (
                    self.anchor.stable_id.encode("utf-8"),
                    logoff_operation_id.encode("utf-8"),
                    PersistentSmbProjectionPhase.LOGOFF.value.encode("ascii"),
                    str(logoff_event.event_type).encode("utf-8"),
                    logoff_event.timestamp.isoformat().encode("ascii"),
                )
            )
            logoff_carrier = self.executor.dispatcher.prepare_persistent_smb_source_projection(
                projection_group,
                logoff_event,
                source_timing_preparation=timing,
                target_formats=target_formats,
            )
            source_carriers.append(logoff_carrier)
            member_specs.append(
                (
                    PersistentSmbProjectionPhase.LOGOFF,
                    logoff_operation_id,
                    logoff_digest,
                    logoff_capsule,
                )
            )
            operation_digests.append(logoff_digest)

        member_work: list[object] = []
        for phase, operation_id, operation_binding_digest, capsule in member_specs:
            member_work.append(
                self.executor.dispatcher.prepare_persistent_smb_projection_member(
                    projection_group,
                    phase=phase,
                    operation_id=operation_id,
                    operation_binding_digest=operation_binding_digest,
                    projection_capsule=capsule,
                    timing_preparation=timing,
                )
            )

        publication_binding_digest = owner_digest(
            "persistent-smb-source-publication-v1",
            (
                self.anchor.stable_id,
                target_formats,
                tuple(operation_digests),
                lifecycle_digest,
                network_digest,
                traffic_digest,
            ),
        )
        source_publication = self.executor.dispatcher.prepare_persistent_smb_source_publication(
            projection_group,
            tuple(source_carriers),
            target_formats=target_formats,
            publication_key=self.anchor.stable_id,
            publication_binding_digest=publication_binding_digest,
        )
        try:
            file_mutation = self.executor.state_manager.commit_smb_file_mutation_journal(journal)
        except BaseException as primary:
            file_mutation = self.executor.state_manager.recover_smb_file_mutation_commit(journal)
            if file_mutation is None:
                try:
                    file_mutation = self.executor.state_manager.commit_smb_file_mutation_journal(
                        journal
                    )
                except BaseException as recovery_error:
                    primary.add_note(
                        "Persistent SMB file-mutation retry also failed: "
                        f"{type(recovery_error).__name__}: {recovery_error}"
                    )
                    raise primary from recovery_error

        try:
            materialization = self.executor.state_manager.materialize_action_cohort(state_plan)
            finalization = materialization.smb_connection_finalization
        except BaseException as primary:
            finalization = self.executor.state_manager.recover_smb_connection_finalization(
                pin_install.pin
            )
            if finalization is None:
                try:
                    materialization = self.executor.state_manager.materialize_action_cohort(
                        state_plan
                    )
                except BaseException as recovery_error:
                    primary.add_note(
                        "Persistent SMB State-finalization retry also failed: "
                        f"{type(recovery_error).__name__}: {recovery_error}"
                    )
                    raise primary from recovery_error
                finalization = materialization.smb_connection_finalization
        if (
            finalization is None
            or not self.executor.state_manager.authenticates_smb_connection_finalization_result(
                finalization
            )
            or not self.executor.state_manager.authenticates_smb_file_mutation_commit_receipt(
                file_mutation.receipt
            )
        ):
            raise StateError("Persistent SMB terminal State result failed authentication")
        rebound, rebound_observations = self.executor.dispatcher.rebind_persistent_smb_close(
            traffic_authority=self.executor._persistent_smb_traffic_authority,
            binding=traffic_binding,
            opening_transport=opening,
            opening_observations=handoff.observations,
            final_traffic=final_traffic,
            final_observation_traffic=final_observation_traffic,
            state_result=finalization,
        )
        if rebound != final_transaction or len(rebound_observations) != len(handoff.observations):
            raise StateError("Persistent SMB traffic close disagrees with terminal State")

        certifications = []
        with timing.claimed_commit() as claimed:
            for member in member_work:
                certifications.append(
                    self.executor.dispatcher.certify_persistent_smb_projection_member(
                        member,
                        target_formats=target_formats,
                        lifecycle_binding_digest=lifecycle_digest,
                        lifecycle_binding_generation=lifecycle_generation,
                        network_binding_digest=network_digest,
                        network_binding_generation=network_generation,
                        traffic_binding_digest=traffic_digest,
                        traffic_binding_generation=traffic_generation,
                        expected_timing_receipt=claimed.expected_receipt,
                    )
                )
            claimed.certify_composite_commit(claimed.expected_receipt)
            claimed.commit_no_fail()
        commit_receipts = []
        for certification in certifications:
            try:
                commit_receipt = self.executor.dispatcher.commit_persistent_smb_projection_member(
                    certification
                )
            except BaseException as primary:
                try:
                    recovery = (
                        self.executor.dispatcher.recover_committed_persistent_smb_projection_member(
                            projection_group,
                            operation_id=certification.operation_id,
                            operation_binding_digest=certification.operation_binding_digest,
                        )
                    )
                except BaseException:
                    recovery = None
                commit_receipt = recovery.commit_receipt if recovery is not None else None
                if commit_receipt is None:
                    try:
                        commit_receipt = (
                            self.executor.dispatcher.commit_persistent_smb_projection_member(
                                certification
                            )
                        )
                    except BaseException as recovery_error:
                        primary.add_note(
                            "Persistent SMB member-commit retry also failed: "
                            f"{type(recovery_error).__name__}: {recovery_error}"
                        )
                        raise primary from recovery_error
            commit_receipts.append(commit_receipt)
        committed_members = tuple(commit_receipts)
        try:
            source_result = self.executor.dispatcher.publish_persistent_smb_source_publication(
                source_publication,
                commit_receipts=committed_members,
            )
        except BaseException as primary:
            try:
                source_result = self.executor.dispatcher.publish_persistent_smb_source_publication(
                    source_publication,
                    commit_receipts=committed_members,
                )
            except BaseException as recovery_error:
                primary.add_note(
                    "Persistent SMB exact-publication retry also failed: "
                    f"{type(recovery_error).__name__}: {recovery_error}"
                )
                raise primary from recovery_error
        if self.executor._smb_channel_manager.census().open_sessions != 0:
            raise StateError("Persistent SMB application channel retained terminal state")
        activity_result = SmbActivityResult(
            session_id=lease.session_id,
            tree_ids=(lease.tree_id,),
            transport_uids=(opening.zeek_uid,),
            operations=(
                {
                    "operation": "read",
                    "share": share.ref,
                    "path": state.path,
                    "file_id": state.file_id,
                    "content_version": state.version,
                    "size_bytes": state.size_bytes,
                    "outcome": self.outcome,
                    "fuid": file_transfer.fuid,
                },
            ),
            completed_at=close_time,
        )
        if not self.executor.dispatcher.authenticates_published_persistent_smb_source_publication(
            source_publication,
            source_result,
        ):
            raise StateError("Persistent SMB published source result failed authentication")
        if not self.executor.state_manager.authenticates_smb_file_mutation_commit_receipt(
            file_mutation.receipt
        ):
            raise StateError("Persistent SMB retained file mutation failed authentication")
        if not self.executor.state_manager.authenticates_smb_connection_finalization_result(
            finalization
        ):
            raise StateError(
                "Persistent SMB retained connection finalization failed authentication"
            )
        continuation = self.executor._persistent_smb_terminal_continuations.install_claimed(
            action_id=self.anchor.stable_id,
            action_binding_digest=terminal_binding_digest,
            source_carrier=source_publication,
            source_result=source_result,
            file_mutation=file_mutation,
            finalization=finalization,
            activity_result=activity_result,
        )
        del lifecycle_binding
        return self._resume_persistent_windows_terminal(continuation)

    def _acknowledge_persistent_smb_source_terminal(
        self,
        facts: _PersistentSmbTerminalFacts,
    ) -> None:
        """Adopt one exact source acknowledgement across fail-before or lost-return."""

        dispatcher = self.executor.dispatcher
        if dispatcher.authenticates_acknowledged_persistent_smb_source_publication(
            facts.source_carrier,
            facts.source_result,
        ):
            return
        if not dispatcher.authenticates_published_persistent_smb_source_publication(
            facts.source_carrier,
            facts.source_result,
        ):
            raise StateError("Persistent SMB source terminal is neither published nor acknowledged")
        try:
            acknowledged = dispatcher.acknowledge_persistent_smb_source_publication(
                facts.source_carrier,
                facts.source_result,
            )
        except BaseException as primary:
            if dispatcher.authenticates_acknowledged_persistent_smb_source_publication(
                facts.source_carrier,
                facts.source_result,
            ):
                return
            try:
                acknowledged = dispatcher.acknowledge_persistent_smb_source_publication(
                    facts.source_carrier,
                    facts.source_result,
                )
            except BaseException as recovery_error:
                if dispatcher.authenticates_acknowledged_persistent_smb_source_publication(
                    facts.source_carrier,
                    facts.source_result,
                ):
                    return
                primary.add_note(
                    "Persistent SMB source-acknowledgement retry also failed: "
                    f"{type(recovery_error).__name__}: {recovery_error}"
                )
                raise primary from recovery_error
            if not acknowledged:
                raise primary
        if not acknowledged or not (
            dispatcher.authenticates_acknowledged_persistent_smb_source_publication(
                facts.source_carrier,
                facts.source_result,
            )
        ):
            raise StateError("Persistent SMB source acknowledgement did not retain exact proof")

    def _acknowledge_persistent_smb_file_terminal(
        self,
        facts: _PersistentSmbTerminalFacts,
    ) -> None:
        """Adopt one exact State file acknowledgement across an ambiguous return."""

        state_manager = self.executor.state_manager
        authenticates = state_manager.authenticates_smb_file_mutation_commit_receipt
        if not authenticates(facts.file_mutation.receipt):
            return
        try:
            acknowledged = state_manager.acknowledge_smb_file_mutation_commit(facts.file_mutation)
        except BaseException as primary:
            if not authenticates(facts.file_mutation.receipt):
                return
            try:
                acknowledged = state_manager.acknowledge_smb_file_mutation_commit(
                    facts.file_mutation
                )
            except BaseException as recovery_error:
                if not authenticates(facts.file_mutation.receipt):
                    return
                primary.add_note(
                    "Persistent SMB file-acknowledgement retry also failed: "
                    f"{type(recovery_error).__name__}: {recovery_error}"
                )
                raise primary from recovery_error
            if not acknowledged:
                raise primary
        if not acknowledged or authenticates(facts.file_mutation.receipt):
            raise StateError("Persistent SMB file acknowledgement did not retire its exact owner")

    def _acknowledge_persistent_smb_connection_terminal(
        self,
        facts: _PersistentSmbTerminalFacts,
    ) -> None:
        """Adopt one exact State connection acknowledgement across an ambiguous return."""

        state_manager = self.executor.state_manager
        authenticates = state_manager.authenticates_smb_connection_finalization_result
        if not authenticates(facts.finalization):
            return
        try:
            acknowledged = state_manager.acknowledge_smb_connection_finalization(facts.finalization)
        except BaseException as primary:
            if not authenticates(facts.finalization):
                return
            try:
                acknowledged = state_manager.acknowledge_smb_connection_finalization(
                    facts.finalization
                )
            except BaseException as recovery_error:
                if not authenticates(facts.finalization):
                    return
                primary.add_note(
                    "Persistent SMB connection-acknowledgement retry also failed: "
                    f"{type(recovery_error).__name__}: {recovery_error}"
                )
                raise primary from recovery_error
            if not acknowledged:
                raise primary
        if not acknowledged or authenticates(facts.finalization):
            raise StateError(
                "Persistent SMB connection acknowledgement did not retire its exact owner"
            )

    def _resume_persistent_windows_terminal(
        self,
        continuation: PersistentSmbTerminalContinuation,
    ) -> SmbActivityResult:
        """Resume only post-publication owners from an authenticated action cursor."""

        authority = self.executor._persistent_smb_terminal_continuations
        completed = False
        try:
            while True:
                facts = authority.facts(continuation)
                if facts.cursor == 0:
                    self._acknowledge_persistent_smb_source_terminal(facts)
                    authority.advance(continuation, expected_cursor=0)
                    continue
                if facts.cursor == 1:
                    self._acknowledge_persistent_smb_file_terminal(facts)
                    authority.advance(continuation, expected_cursor=1)
                    continue
                if facts.cursor == 2:
                    self._acknowledge_persistent_smb_connection_terminal(facts)
                    authority.advance(continuation, expected_cursor=2)
                    continue
                if facts.cursor == 3:
                    self.executor.dispatcher.release_acknowledged_persistent_smb_source_publication_no_fail(
                        facts.source_carrier,
                        facts.source_result,
                    )
                    authority.advance(continuation, expected_cursor=3)
                    continue
                result = authority.complete_no_fail(continuation)
                completed = True
                return result
        finally:
            if not completed:
                authority.release_claim(continuation)

    @staticmethod
    def _persistent_final_traffic(
        opening: NetworkTrafficLedger,
        *,
        orig_payload: int,
        resp_payload: int,
    ) -> NetworkTrafficLedger:
        """Return monotonic TCP accounting for a persistent SMB close."""

        orig = max(opening.orig.payload_bytes, orig_payload)
        resp = max(opening.resp.payload_bytes, resp_payload)
        orig_packets = max(opening.orig.packets, math.ceil(orig / 1_360))
        resp_packets = max(opening.resp.packets, math.ceil(resp / 1_360))
        return NetworkTrafficLedger(
            orig=DirectionalTrafficLedger(
                payload_bytes=orig,
                packets=orig_packets,
                ip_bytes=max(opening.orig.ip_bytes, orig + 40 * orig_packets),
            ),
            resp=DirectionalTrafficLedger(
                payload_bytes=resp,
                packets=resp_packets,
                ip_bytes=max(opening.resp.ip_bytes, resp + 40 * resp_packets),
            ),
            missed_orig_bytes=opening.missed_orig_bytes,
            missed_resp_bytes=opening.missed_resp_bytes,
        )

    def _ground_truth_transport_uid(self, canonical_uid: str) -> str:
        """Return the emitted Zeek UID when visible, otherwise canonical truth."""
        lookup = getattr(self.executor.dispatcher, "network_identifier_for_format", None)
        if callable(lookup):
            observed_uid = lookup(canonical_uid, "zeek_conn")
            if observed_uid:
                return str(observed_uid)
        return canonical_uid

    def _execute_composite_transfer(self) -> SmbActivityResult | None:
        """Expand multi-location copy/move into bounded canonical storage legs."""

        spec = self.request.spec
        source = spec.source
        destination = spec.destination
        if spec.operation not in {"copy", "move"} or not isinstance(source, SmbShareLocation):
            return None
        if (
            spec.operation == "move"
            and isinstance(destination, SmbShareLocation)
            and destination.share.casefold() == source.share.casefold()
        ):
            return None
        if not isinstance(destination, SmbShareLocation) and spec.operation == "copy":
            return None

        timing = self._timing_planner()
        selected = self._select(source)
        if not selected:
            raise ValueError(f"smb_activity selected no files on {source.share}")
        results: list[SmbActivityResult] = []
        copy_outcome = spec.outcome
        if spec.operation == "move" and not isinstance(destination, SmbShareLocation):
            copy_outcome = self._leg_outcome(source, operation="read")
        copy_spec = SmbActivityEventSpec(
            operation="copy",
            purpose=spec.purpose,
            source=source,
            destination=destination,
            outcome=copy_outcome,
            path_style=spec.path_style,
            mapping=spec.mapping,
            client=spec.client,
            client_access=spec.client_access,
            auth_protocol=spec.auth_protocol,
            smb_principal=spec.smb_principal,
        )
        if not isinstance(destination, SmbShareLocation):
            results.append(self._execute_child(copy_spec, selected, offset_ms=0))
        else:
            source_outcome = self._leg_outcome(source, operation="read")
            read_spec = SmbActivityEventSpec(
                operation="read",
                purpose=spec.purpose,
                target=source,
                outcome=source_outcome,
                path_style=spec.path_style,
                mapping=self._mapping_for_share(source.share),
                client=spec.client,
                client_access=spec.client_access,
                auth_protocol=spec.auth_protocol,
                smb_principal=spec.smb_principal,
            )
            results.append(self._execute_child(read_spec, selected, offset_ms=0))
            if any(operation["outcome"] != "success" for operation in results[-1].operations):
                return self._combine_results(results)
            destination_files = tuple(
                file.model_copy(
                    update={
                        "file_id": stable_uuid(
                            "smb-copy-destination",
                            self.anchor.stable_id,
                            destination.share,
                            self._destination_path(destination, file.path),
                        ),
                        "share": destination.share,
                        "path": self._destination_path(destination, file.path),
                    }
                )
                for file in selected
            )
            create_spec = SmbActivityEventSpec(
                operation="create",
                purpose=spec.purpose,
                target=destination.model_copy(
                    update={"path": destination.path if len(selected) == 1 else None}
                ),
                outcome=self._leg_outcome(destination, operation="create"),
                path_style=spec.path_style,
                mapping=self._mapping_for_share(destination.share),
                client=spec.client,
                client_access=spec.client_access,
                auth_protocol=spec.auth_protocol,
                smb_principal=spec.smb_principal,
            )
            results.append(self._execute_child(create_spec, destination_files, offset_ms=25))

        if spec.operation == "move" and any(
            operation["outcome"] != "success"
            for result in results
            for operation in result.operations
        ):
            return self._combine_results(results)
        if spec.operation == "move":
            completed_at = max(result.completed_at for result in results)
            destination_scope = getattr(destination, "share", "client")
            delete_window = get_timing_window(
                "smb.cross_server_delete_after_destination",
                default_min_ms=250,
                default_max_ms=1200,
                default_position="after",
            )
            minimum_seconds = delete_window.min_ms / 1000
            maximum_seconds = delete_window.max_ms / 1000
            delete_gap_seconds = timing.triangular_seconds(
                relationship_key="smb.cross_server_delete_after_destination",
                stable_id=stable_uuid(
                    "smb-cross-server-delete-gap",
                    self.anchor.stable_id,
                    source.share,
                    destination_scope,
                    completed_at,
                ),
                minimum=minimum_seconds,
                mode=minimum_seconds + ((maximum_seconds - minimum_seconds) * 0.5),
                maximum=maximum_seconds,
                host=self._timing_host(),
                lifecycle_id=self.anchor.stable_id,
                sample_key="cross_server_delete_gap",
            )
            delete_time = completed_at + timedelta(seconds=delete_gap_seconds)
            delete_spec = SmbActivityEventSpec(
                operation="delete",
                purpose=spec.purpose,
                target=source,
                outcome=self._leg_outcome(source, operation="delete"),
                path_style=spec.path_style,
                mapping=self._mapping_for_share(source.share),
                client=spec.client,
                client_access=spec.client_access,
                auth_protocol=spec.auth_protocol,
                smb_principal=spec.smb_principal,
            )
            results.append(
                self._execute_child(
                    delete_spec,
                    selected,
                    offset_ms=0,
                    execution_time=delete_time,
                )
            )
        return self._combine_results(results)

    def _execute_child(
        self,
        spec: SmbActivityEventSpec,
        files: tuple[CompiledStorageFile, ...],
        *,
        offset_ms: int,
        execution_time: datetime | None = None,
    ) -> SmbActivityResult:
        child_request = SmbActivityRequest(
            spec=spec,
            actor=self.request.actor,
            parent_system=self.request.parent_system,
            time=execution_time or self.request.time + timedelta(milliseconds=offset_ms),
            process_pid=self.request.process_pid,
            process_image=self.request.process_image,
            activity_source=self.request.activity_source,
            files_override=files,
        )
        return SmbActivityActionBundle(self.executor, child_request).execute()

    @staticmethod
    def _combine_results(results: list[SmbActivityResult]) -> SmbActivityResult:
        first = results[0]
        return SmbActivityResult(
            session_id=first.session_id,
            tree_ids=tuple(tree for result in results for tree in result.tree_ids),
            transport_uids=tuple(uid for result in results for uid in result.transport_uids),
            operations=tuple(operation for result in results for operation in result.operations),
            completed_at=max(result.completed_at for result in results),
        )

    def _destination_path(self, destination: SmbShareLocation, source_path: str) -> str:
        if destination.path is not None:
            return destination.path
        return f"Incoming\\{ntpath.basename(source_path)}"

    def _mapping_for_share(self, share_ref: str) -> str | None:
        mapping = self.world.mappings_by_id.get((self.request.spec.mapping or "").casefold())
        if mapping is None or mapping.share.casefold() != share_ref.casefold():
            return None
        return mapping.id

    def _leg_outcome(self, location: SmbShareLocation, *, operation: str) -> str:
        authored = self.request.spec.outcome
        if authored != "access_denied":
            return authored
        share = self.world.share(location.share)
        _mapping, principal = self._resolve_share_leg(share)
        return (
            "success"
            if self._has_access(
                share,
                location,
                principal_name=principal,
                operation=operation,
            )
            else "access_denied"
        )

    def _share_locations(self) -> list[SmbShareLocation]:
        spec = self.request.spec
        candidates = [spec.target, spec.source, spec.destination]
        return [candidate for candidate in candidates if isinstance(candidate, SmbShareLocation)]

    def _select(self, location: SmbShareLocation) -> tuple[CompiledStorageFile, ...]:
        if self.request.files_override:
            return self.request.files_override
        candidates = self.world.select(
            location.share,
            file_ref=location.file_ref,
            path=location.path,
            selector=location.selector,
        )
        candidates = tuple(
            file for file in candidates if self.executor.state_manager.smb_file_is_available(file)
        )
        batch = self.request.spec.batch
        if batch is None:
            if location.selector is not None:
                return candidates[:1]
            if location.file_ref is not None or location.path is not None:
                return candidates
            return candidates[:1]
        if batch.count is not None:
            count = batch.count
        elif batch.fraction is not None:
            count = max(1, round(len(candidates) * batch.fraction))
        else:
            count = len(candidates)
        return tuple(candidates[:count])

    def _create_placeholder(
        self,
        location: SmbShareLocation,
        share: CompiledStorageShare,
    ) -> CompiledStorageFile:
        path = location.path or (
            f"Incoming\\{self.request.actor.username}-{self.request.time:%Y%m%d-%H%M%S}.dat"
        )
        return CompiledStorageFile(
            file_id=stable_uuid("smb-create-placeholder", share.ref, path, self.anchor.stable_id),
            share=share.ref,
            path=path,
            size_bytes=self.rng.randint(4_096, 2_000_000),
            mime_type="application/octet-stream",
            tags=("created",),
        )

    def _missing_placeholder(
        self,
        location: SmbShareLocation,
        share: CompiledStorageShare,
    ) -> CompiledStorageFile:
        """Represent an asserted missing path without adding it to mutable state."""

        path = location.path or "missing.dat"
        return CompiledStorageFile(
            file_id=stable_uuid("smb-missing-path", share.ref, path),
            version=1,
            share=share.ref,
            path=path,
            size_bytes=0,
            mime_type="application/octet-stream",
            tags=("missing",),
        )

    def _execute_file_operation(
        self,
        *,
        file: CompiledStorageFile,
        operation_index: int,
        share: CompiledStorageShare,
        tree_id: str,
        network: NetworkTransactionPlan,
        server: System,
        client: System | None,
        auth: AuthContext,
        process: ProcessContext | None,
        timestamp: datetime,
    ) -> dict[str, Any]:
        spec = self.request.spec
        result = self.outcome
        action = spec.operation
        state = file
        creates_remote_copy = (
            action in {"copy", "move"}
            and not isinstance(spec.source, SmbShareLocation)
            and isinstance(spec.destination, SmbShareLocation)
        )
        conflict_handle = None
        if result in {"access_denied", "not_found"}:
            handle = None
        elif result == "sharing_violation":
            state = self.executor.state_manager.touch_smb_file(file)
            conflict_handle = self.executor.state_manager.open_smb_handle(
                tree_id=tree_id,
                file_id=state.file_id,
                timestamp=timestamp - timedelta(milliseconds=1),
                access="read",
                deny_write=True,
            )
            handle = None
        elif action == "create" or creates_remote_copy:
            state = self.executor.state_manager.create_smb_file(
                share=share.ref,
                path=file.path,
                size_bytes=file.size_bytes,
                mime_type=file.mime_type,
                timestamp=timestamp,
                tags=file.tags,
            )
            handle = self.executor.state_manager.open_smb_handle(
                tree_id=tree_id,
                file_id=state.file_id,
                timestamp=timestamp,
                access="write",
            )
        else:
            state = self.executor.state_manager.touch_smb_file(file)
            access = "read" if action in {"browse", "read", "copy"} else "write"
            handle = self.executor.state_manager.open_smb_handle(
                tree_id=tree_id,
                file_id=state.file_id,
                timestamp=timestamp,
                access=access,
            )
        path = state.path
        client_path = self._client_path(path, share)
        tree = self.executor.state_manager.get_smb_tree(tree_id)
        if tree is None:
            raise ValueError(f"SMB tree {tree_id!r} expired before its operation")
        common = dict(
            operation=action,
            purpose=spec.purpose,
            session_id=tree.session_id,
            tree_id=tree_id,
            share_ref=share.ref,
            share_name=share.name,
            result=result,
            requested_access=self._requested_access(),
            client_path=client_path,
            local_path=self._local_path(path),
            share_path=path,
            server_path=self.world.server_local_path(share, path),
            share_local_path=self.world.server_local_path(share, ""),
            file_id=state.file_id,
            content_version=state.version,
            handle_id=handle.handle_id if handle is not None else "",
            size_bytes=state.size_bytes,
            **self._smb_platform_fields(share, server),
            encrypted=share.encryption == "required",
            audit=share.audit,
        )
        self._emit_phase(
            event_type="smb_file_open",
            timestamp=timestamp,
            network=network,
            server=server,
            client=client,
            auth=auth,
            process=process,
            smb=SmbContext(phase="open", **common),
        )
        if result != "success":
            if conflict_handle is not None:
                self.executor.state_manager.close_smb_handle(
                    conflict_handle.handle_id,
                    timestamp + timedelta(milliseconds=5),
                )
            return {
                "operation": action,
                "share": share.ref,
                "path": state.path,
                "file_id": state.file_id,
                "content_version": state.version,
                "size_bytes": state.size_bytes,
                "outcome": result,
                "fuid": None,
            }
        phase_type = {
            "browse": "smb_directory_enumeration",
            "read": "smb_file_read",
            "create": "smb_file_write",
            "update": "smb_file_write",
            "copy": "smb_file_read"
            if isinstance(spec.source, SmbShareLocation)
            else "smb_file_write",
            "move": "smb_file_write" if creates_remote_copy else "smb_file_rename",
            "delete": "smb_file_delete",
        }[action]
        phase = phase_type.removeprefix("smb_file_").removeprefix("smb_")
        previous_path = ""
        previous_client_path = ""
        previous_server_path = ""
        if action == "update":
            state = self.executor.state_manager.update_smb_file(
                state.file_id,
                size_bytes=self._updated_size(state, operation_index),
            )
            common["content_version"] = state.version
            common["size_bytes"] = state.size_bytes
        elif action == "move" and not creates_remote_copy:
            destination = spec.destination
            destination_path = (
                destination.path
                if isinstance(destination, SmbShareLocation) and destination.path
                else f"Archive\\{ntpath.basename(path)}"
            )
            destination_share = (
                destination.share if isinstance(destination, SmbShareLocation) else share.ref
            )
            previous_path = path
            previous_client_path = self._client_path(path, share)
            previous_server_path = self.world.server_local_path(share, path)
            state = self.executor.state_manager.move_smb_file(
                state.file_id,
                share=destination_share,
                path=destination_path,
            )
            common["share_path"] = state.path
            common["client_path"] = self._client_path(state.path, share)
            common["server_path"] = self.world.server_local_path(share, state.path)
            common["content_version"] = state.version
        elif action == "delete":
            self.executor.state_manager.delete_smb_file(state.file_id)
        timing = self._operation_timing(
            state,
            operation_index,
            size_bytes=state.size_bytes,
        )
        file_transfer = None
        if phase in {"read", "write"} and result == "success":
            file_transfer = FileTransferContext(
                fuid=self._file_transfer_fuid(state, phase),
                source="SMB",
                filename=state.path,
                analyzers=("MIME",),
                mime_type=state.mime_type,
                duration=timing.transfer_seconds,
                local_orig=client is not None,
                is_orig=phase == "write",
                seen_bytes=state.size_bytes,
                total_bytes=state.size_bytes,
            )
        action_time = timestamp + timedelta(seconds=timing.setup_seconds + timing.jitter_seconds)
        self._emit_phase(
            event_type=phase_type,
            timestamp=action_time,
            network=network,
            server=server,
            client=client,
            auth=auth,
            process=process,
            smb=SmbContext(
                phase=phase,
                previous_path=previous_path,
                previous_client_path=previous_client_path,
                previous_server_path=previous_server_path,
                **common,
            ),
            file_transfer=file_transfer,
        )
        close_time = action_time + timedelta(
            seconds=timing.transfer_seconds + timing.close_delay_seconds
        )
        if handle is not None:
            self.executor.state_manager.close_smb_handle(handle.handle_id, close_time)
        if conflict_handle is not None:
            self.executor.state_manager.close_smb_handle(conflict_handle.handle_id, close_time)
        self._emit_phase(
            event_type="smb_file_close",
            timestamp=close_time,
            network=network,
            server=server,
            client=client,
            auth=auth,
            process=process,
            smb=SmbContext(
                phase="close",
                previous_path=previous_path,
                previous_client_path=previous_client_path,
                previous_server_path=previous_server_path,
                **common,
            ),
        )
        return {
            "operation": action,
            "share": share.ref,
            "path": common["share_path"],
            "file_id": state.file_id,
            "content_version": state.version,
            "size_bytes": state.size_bytes,
            "outcome": result,
            "fuid": file_transfer.fuid if file_transfer is not None else None,
        }

    def _file_transfer_fuid(self, file: CompiledStorageFile, phase: str) -> str:
        """Derive file identity from the operation's final canonical version."""

        return generate_stable_zeek_uid(
            "F",
            (
                f"{self.anchor.stable_id}:{file.file_id}:{file.version}:"
                f"{phase}:{'orig' if phase == 'write' else 'resp'}"
            ),
        )

    def _emit_phase(
        self,
        *,
        event_type: str,
        timestamp: datetime,
        network: NetworkTransactionPlan,
        server: System,
        client: System | None,
        auth: AuthContext,
        process: ProcessContext | None,
        smb: SmbContext,
        file_transfer: FileTransferContext | None = None,
    ) -> None:
        self.executor.dispatcher.dispatch_builder(
            self._phase_builder(
                event_type=event_type,
                timestamp=timestamp,
                network=network,
                server=server,
                client=client,
                auth=auth,
                process=process,
                smb=smb,
                file_transfer=file_transfer,
            )
        )

    def _phase_builder(
        self,
        *,
        event_type: str,
        timestamp: datetime,
        network: NetworkTransactionPlan,
        server: System,
        client: System | None,
        auth: AuthContext,
        process: ProcessContext | None,
        smb: SmbContext,
        file_transfer: FileTransferContext | None = None,
        identity_plan: EventIdentityPlan | None = None,
        include_file_context: bool = True,
        effect_provenance: EffectOccurrenceProvenance | None = None,
    ) -> OccurrenceBuilder:
        """Build one SMB application phase without publishing it."""

        file_context = None
        if include_file_context and smb.phase in {"read", "write", "delete", "rename"}:
            file_context = FileContext(
                path=smb.server_path,
                action={"write": "modify", "rename": "modify"}.get(smb.phase, smb.phase),
                pid=network.responding_pid,
            )
        return OccurrenceBuilder(
            timestamp=timestamp,
            event_type=event_type,
            src_host=self.executor._build_host_context(client) if client is not None else None,
            dst_host=self.executor._build_host_context(server),
            auth=auth,
            process=process,
            network=network,
            file=file_context,
            file_transfer=file_transfer,
            smb=smb,
            identity_plan=identity_plan,
            effect_provenance=effect_provenance,
            lifecycle=ActionLifecycleContext(
                group_id=self.anchor.stable_id,
                canonical_start=self.transport_start,
                phase="dependent",
                parent_group_id=network.zeek_uid,
            ),
        )

    def _application_network_plan(
        self,
        *,
        transport_plan: NetworkTransactionPlan,
    ) -> NetworkTransactionPlan:
        return replace(transport_plan, application_layer_only=True)

    def _client(self, server: System) -> tuple[System | None, str]:
        if self.request.spec.client is not None:
            return None, self.request.spec.client.ip
        if self.request.parent_system.hostname == server.hostname:
            raise ValueError("modeled SMB client must differ from the share server")
        return self.request.parent_system, self.request.parent_system.ip

    def _system(self, hostname: str) -> System:
        system = self.executor._system_for_hostname(hostname)
        if system is None:
            raise ValueError(f"unknown SMB server {hostname!r}")
        return system

    @staticmethod
    def _server_platform(system: System) -> str:
        """Return the normalized endpoint platform used by SMB projections."""

        return "windows" if "windows" in system.os.casefold() else "linux"

    def _eligible_mappings(self, share: CompiledStorageShare) -> list[Any]:
        """Return deterministic share mappings applicable to this actor/client."""

        eligible = [
            mapping
            for mapping in self.world.mappings
            if mapping.share.casefold() == share.ref.casefold()
            and (
                not mapping.users
                or self.request.actor.username.casefold()
                in {user.casefold() for user in mapping.users}
            )
            and (
                not mapping.systems
                or self.request.parent_system.hostname.casefold()
                in {system.casefold() for system in mapping.systems}
            )
        ]
        return sorted(eligible, key=lambda mapping: mapping.id.casefold())

    def _selected_mapping(self, share: CompiledStorageShare) -> Any | None:
        """Resolve an explicit or unambiguous platform presentation mapping."""

        eligible = self._eligible_mappings(share)
        mapping = self.world.mappings_by_id.get((self.request.spec.mapping or "").casefold())
        if mapping is not None and mapping.share.casefold() == share.ref.casefold():
            return mapping
        if self.request.spec.path_style in {"mapped", "mounted"} and len(eligible) == 1:
            return eligible[0]
        if self.request.spec.path_style == "auto":
            persistent = [item for item in eligible if item.lifecycle == "persistent"]
            if persistent:
                return persistent[0]
            if len(eligible) == 1:
                return eligible[0]
        return None

    def _resolve_share_leg(self, share: CompiledStorageShare) -> tuple[Any | None, str]:
        """Resolve one share leg's mapping and credential exactly as its child bundle will."""

        mapping = self._selected_mapping(share)
        return mapping, self._smb_principal_for_mapping(mapping)

    def _resolve_client_access(self, client: System | None) -> str:
        """Resolve one authored client-access mode to a concrete runtime view."""

        if client is None:
            if getattr(self.request.spec, "mapping", None) is not None:
                raise ValueError("external SMB clients cannot use storage mappings")
            if self.request.spec.client_access != "auto":
                raise ValueError("external SMB clients require client_access: auto")
            if self.request.spec.path_style not in {"auto", "unc"}:
                raise ValueError(
                    "external SMB clients require an automatic or UNC path presentation"
                )
            return "external"
        authored = self.request.spec.client_access
        path_style = self.request.spec.path_style
        client_platform = self._server_platform(client)
        if authored == "auto":
            if client_platform == "windows":
                resolved = "windows_native"
            elif self.mapping is not None and bool(getattr(self.mapping, "mount", None)):
                resolved = "cifs_mount"
            elif path_style == "mounted":
                raise ValueError(
                    "mounted SMB presentation requires an applicable storage mapping with a mount"
                )
            else:
                resolved = "smbclient"
        else:
            resolved = authored

        if resolved == "windows_native" and client_platform != "windows":
            raise ValueError("windows_native SMB access requires a Windows client")
        if resolved in {"cifs_mount", "smbclient"} and client_platform != "linux":
            raise ValueError(f"{resolved} SMB access requires a Linux client")
        allowed_path_styles = {
            "windows_native": {"auto", "unc", "mapped"},
            "cifs_mount": {"auto", "mounted"},
            "smbclient": {"auto", "unc"},
        }
        if path_style not in allowed_path_styles[resolved]:
            allowed = "/".join(sorted(allowed_path_styles[resolved]))
            raise ValueError(f"{resolved} SMB access requires one of these path styles: {allowed}")
        if resolved == "cifs_mount" and (
            self.mapping is None or not getattr(self.mapping, "mount", None)
        ):
            raise ValueError(
                "cifs_mount SMB access requires an applicable storage mapping with a mount"
            )
        return resolved

    def _resolve_smb_principal(self) -> str:
        """Keep the local actor distinct from the credential used on the share."""

        mapping = getattr(self, "mapping", None)
        if mapping is None and self.request.spec.mapping:
            mapping = self.world.mappings_by_id.get(self.request.spec.mapping.casefold())
        return self._smb_principal_for_mapping(mapping)

    def _smb_principal_for_mapping(self, mapping: Any | None) -> str:
        """Return the event or fixed credential associated with one resolved mapping."""

        if mapping is not None and getattr(mapping, "credential_mode", "per_user") == "fixed":
            fixed = str(getattr(mapping, "principal", "") or "")
            if self.request.spec.smb_principal and (
                self.request.spec.smb_principal.casefold() != fixed.casefold()
            ):
                raise ValueError(
                    "SMB activity principal conflicts with the fixed mapping credential"
                )
            return fixed
        return self.request.spec.smb_principal or self.request.actor.username

    def _resolved_auth_protocol(self, server: System) -> str:
        """Resolve authored SMB auth while preserving existing Windows defaults."""

        authored = self.request.spec.auth_protocol
        if authored != "auto":
            return authored
        # V1 Samba servers are domain members, so their automatic path uses
        # directory-backed Kerberos.  Windows retains its established
        # Negotiate selection; generate_logon records the concrete result.
        return "kerberos" if self._server_platform(server) == "linux" else ""

    def _effective_samba_identity(
        self,
        server: System,
        principal: str,
    ) -> tuple[int | None, int | None]:
        """Resolve the domain principal's host-local Unix identity for Samba."""

        if self._server_platform(server) != "linux":
            return None, None
        directory = getattr(self.executor, "identity_directory", None)
        if directory is None:
            return None, None
        account = directory.linux_account(principal, server.hostname)
        if account is None:
            account = directory.linux_account(principal)
        if account is None:
            return None, None
        return account.uid, account.gid

    def _smb_platform_fields(
        self,
        share: CompiledStorageShare,
        server: System,
    ) -> dict[str, Any]:
        """Return the independent backing and wire-advertised filesystem views."""

        volume = self.world.volumes_by_ref[f"{share.system}.{share.volume}".casefold()]
        backing = volume.filesystem
        platform = self._server_platform(server)
        advertised = share.smb_native_filesystem
        return {
            "filesystem": backing,
            "backing_filesystem": backing,
            "advertised_filesystem": advertised,
            "server_platform": platform,
            "provider": "windows" if platform == "windows" else "samba",
            "client_access": self.client_access,
        }

    def _process_context(
        self,
        client: System | None,
        *,
        preferred_pid: int | None = None,
    ) -> ProcessContext | None:
        if client is None:
            return None
        running = None
        selected_pid = preferred_pid or self.request.process_pid or -1
        if selected_pid > 0:
            running = self.executor.state_manager.get_process(
                client.hostname,
                selected_pid,
            )
        if running is None:
            candidates = [
                candidate
                for candidate in self.executor.state_manager.get_processes_on_system(
                    client.hostname
                )
                if candidate.username.casefold() == self.request.actor.username.casefold()
            ]
            candidates.sort(
                key=lambda candidate: (
                    0 if candidate.image.casefold().endswith("\\explorer.exe") else 1,
                    0
                    if candidate.image.casefold().endswith(
                        ("\\winword.exe", "\\excel.exe", "\\powerpnt.exe")
                    )
                    else 1,
                    candidate.start_time,
                    candidate.pid,
                )
            )
            running = candidates[0] if candidates else None
        if running is None:
            return None
        return ProcessContext(
            pid=running.pid,
            parent_pid=running.parent_pid,
            image=running.image,
            command_line=running.command_line,
            username=running.username,
            logon_id=running.logon_id,
            start_time=running.start_time,
        )

    def _client_path(self, path: str, share: CompiledStorageShare) -> str:
        spec = self.request.spec
        if spec.client is not None:
            return self.world.unc_path(share, path)
        if self.client_access == "cifs_mount":
            mount = str(getattr(self.mapping, "mount", "") or "")
            if mount:
                relative = path.replace("\\", "/")
                return posixpath.join(mount, relative)
        if self.client_access == "smbclient":
            relative = path.replace("\\", "/")
            return f"//{share.system}/{share.name}/{relative}"
        if spec.path_style == "unc":
            return self.world.unc_path(share, path)
        mapping = self.mapping
        drive = str(getattr(mapping, "drive", "") or "") if mapping is not None else ""
        if drive:
            return f"{drive}\\{path}"
        return self.world.unc_path(share, path)

    def _local_path(self, remote_path: str) -> str:
        source = self.request.spec.source
        destination = self.request.spec.destination
        location = source if isinstance(source, SmbClientLocation) else destination
        if not isinstance(location, SmbClientLocation):
            return ""
        client_is_linux = (
            self.client_system is not None and self._server_platform(self.client_system) == "linux"
        )
        basename = (
            posixpath.basename(remote_path.replace("\\", "/"))
            if client_is_linux
            else ntpath.basename(remote_path)
        )
        if location.path:
            if location.path.endswith(("\\", "/")):
                return f"{location.path}{basename}"
            return location.path
        if client_is_linux:
            directory = getattr(self.executor, "identity_directory", None)
            account = (
                directory.linux_account(
                    self.request.actor.username,
                    self.client_system.hostname,
                )
                if directory is not None
                else None
            )
            home = account.home if account is not None else f"/home/{self.request.actor.username}"
            return posixpath.join(home, "Downloads", basename)
        return f"C:\\Users\\{self.request.actor.username}\\Downloads\\{basename}"

    def _process_transfer_operands(
        self,
        remote_path: str,
        share: CompiledStorageShare,
    ) -> tuple[str, str]:
        """Resolve copy/move operands in the initiating client's native path view."""

        spec = self.request.spec
        if spec.operation not in {"copy", "move"}:
            return "", ""

        source_path = (
            self._local_path(remote_path)
            if isinstance(spec.source, SmbClientLocation)
            else self._client_path(remote_path, share)
        )
        if isinstance(spec.destination, SmbClientLocation):
            return source_path, self._local_path(remote_path)
        if isinstance(spec.destination, SmbShareLocation):
            destination_relative = self._destination_path(spec.destination, remote_path)
            if self.client_access == "cifs_mount":
                return source_path, self._client_path(destination_relative, share)
            return source_path, destination_relative
        return source_path, ""

    def _duration(self, files: tuple[CompiledStorageFile, ...]) -> float:
        authored = self.request.spec.batch.duration if self.request.spec.batch else None
        if authored is not None:
            duration = max(0.25, parse_duration(authored).total_seconds())
            self._operation_time_scale = 1.0
            self._session_setup_scale = 1.0
            unscaled = sum(
                self._operation_timing(
                    file,
                    index,
                    size_bytes=self._planned_transfer_size(file, index),
                ).total_seconds
                for index, file in enumerate(files)
            )
            config = load_smb_profiles().transfer_timing
            session_setup = self._raw_session_setup_seconds()
            fixed = 0.096 + 0.088 + config.transport_tail_seconds
            usable = max(0.001, duration - fixed)
            scale = min(1.0, usable / max(0.001, session_setup + unscaled))
            self._operation_time_scale = scale
            self._session_setup_scale = scale
            return duration
        self._operation_time_scale = 1.0
        self._session_setup_scale = 1.0
        timing_config = load_smb_profiles().transfer_timing
        operation_seconds = sum(
            self._operation_timing(
                file,
                index,
                size_bytes=self._planned_transfer_size(file, index),
            ).total_seconds
            for index, file in enumerate(files)
        )
        dwell = timing_config.purpose_dwell_seconds[self.request.spec.purpose]
        dwell_rng = self._timing_rng("session-dwell")
        # The transport budget covers the largest possible auth/tree delay used
        # by this bundle, plus the exact sampled operation spans and a tail.
        duration = (
            0.096
            + 0.088
            + self._session_setup_seconds()
            + operation_seconds
            + dwell_rng.uniform(*dwell)
            + timing_config.transport_tail_seconds
        )
        return duration

    def _timing_rng(self, scope: str) -> random.Random:
        """Return a dedicated stable RNG for one SMB session timing scope."""

        return random.Random(_stable_seed(f"smb-timing:{self.anchor.stable_id}:{scope}"))

    def _session_setup_seconds(self) -> float:
        """Sample the deterministic tree-to-first-operation setup delay."""

        return self._raw_session_setup_seconds() * getattr(self, "_session_setup_scale", 1.0)

    def _raw_session_setup_seconds(self) -> float:
        """Return the unscaled deterministic session setup delay."""

        bounds = load_smb_profiles().transfer_timing.session_setup_seconds
        return self._timing_rng("session-setup").uniform(*bounds)

    def _updated_size(self, file: CompiledStorageFile, operation_index: int) -> int:
        """Return the canonical post-update size without consuming shared RNG state."""

        current_size = self.executor.state_manager.smb_file_size(file)
        rng = self._timing_rng(f"update-size:{operation_index}:{file.file_id}")
        return max(1, int(current_size * rng.uniform(0.92, 1.15)))

    def _planned_transfer_size(self, file: CompiledStorageFile, operation_index: int) -> int:
        """Return the size that the operation will put on the wire."""

        if self.request.spec.operation == "update":
            return self._updated_size(file, operation_index)
        return self.executor.state_manager.smb_file_size(file)

    def _operation_timing(
        self,
        file: CompiledStorageFile,
        operation_index: int,
        *,
        size_bytes: int,
    ) -> _SmbOperationTiming:
        """Sample one bounded operation span using a stable session-scoped RNG."""

        config = load_smb_profiles().transfer_timing
        rng = self._timing_rng(f"operation:{operation_index}:{file.file_id}")
        throughput = min(
            config.throughput_max_bytes_per_second,
            max(
                config.throughput_min_bytes_per_second,
                rng.lognormvariate(
                    math.log(config.throughput_median_bytes_per_second),
                    config.throughput_sigma,
                ),
            ),
        )
        operation = self.request.spec.operation
        carries_payload = operation in {"read", "create", "update", "copy"} or (
            operation == "move"
            and not isinstance(self.request.spec.source, SmbShareLocation)
            and isinstance(self.request.spec.destination, SmbShareLocation)
        )
        transfer_seconds = max(0.000_001, size_bytes / throughput) if carries_payload else 0.0
        scale = getattr(self, "_operation_time_scale", 1.0)
        return _SmbOperationTiming(
            setup_seconds=rng.uniform(*config.operation_setup_seconds) * scale,
            jitter_seconds=rng.uniform(*config.operation_jitter_seconds) * scale,
            transfer_seconds=transfer_seconds * scale,
            close_delay_seconds=rng.uniform(*config.close_delay_seconds) * scale,
        )

    def _idle_timeout(self) -> timedelta:
        seconds = {
            "interactive": 15 * 60,
            "administrative": 8 * 60,
            "software": 20 * 60,
            "backup": 45 * 60,
            "collection": 5 * 60,
            "ransomware": 2 * 60,
            "auto": 15 * 60,
        }[self.request.spec.purpose]
        return timedelta(seconds=seconds)

    def _transport_bytes(self, files: tuple[CompiledStorageFile, ...], *, write: bool) -> int:
        operation = self.request.spec.operation
        data_bytes = sum(
            self._planned_transfer_size(file, index) for index, file in enumerate(files)
        )
        source_is_share = isinstance(self.request.spec.source, SmbShareLocation)
        destination_is_share = isinstance(self.request.spec.destination, SmbShareLocation)
        if write:
            carries_data = operation in {"create", "update"} or (
                operation in {"copy", "move"} and destination_is_share and not source_is_share
            )
        else:
            carries_data = operation == "read" or (
                operation in {"copy", "move"} and source_is_share and not destination_is_share
            )
        byte_rng = random.Random(
            _stable_seed(f"smb-wire-bytes:{self.anchor.stable_id}:{'orig' if write else 'resp'}")
        )
        if carries_data and operation == "update":
            data_bytes = int(data_bytes * byte_rng.uniform(1.16, 1.35))
        framing_bytes = byte_rng.randint(850, 2_650)
        framing_bytes += sum(byte_rng.randint(240, 1_050) for _file in files)
        return framing_bytes + (data_bytes if carries_data else 0)

    def _requested_access(self) -> str:
        """Return the access requested by the operation's remote handle."""

        spec = self.request.spec
        if spec.operation == "browse":
            return "list"
        if spec.operation in {"create", "update"}:
            return "write"
        if spec.operation == "delete":
            return "delete"
        if spec.operation == "move":
            if isinstance(spec.source, SmbShareLocation) and isinstance(
                spec.destination, SmbShareLocation
            ):
                return "rename"
            return "read" if isinstance(spec.source, SmbShareLocation) else "write"
        if spec.operation == "copy":
            return "read" if isinstance(spec.source, SmbShareLocation) else "write"
        return "read"

    def _resolve_outcome(
        self,
        share: CompiledStorageShare,
        location: SmbShareLocation,
    ) -> str:
        authored = self.request.spec.outcome
        allowed = self._has_access(share, location)
        if authored == "success" and not allowed:
            raise ValueError(
                f"SMB success is impossible: {self._resolve_smb_principal()!r} "
                f"cannot access {share.ref}"
            )
        if authored == "access_denied" and allowed:
            raise ValueError(
                f"SMB access_denied is not credible: {self._resolve_smb_principal()!r} "
                f"can access {share.ref}"
            )
        if authored == "auto":
            return "success" if allowed else "access_denied"
        return authored

    def _has_access(
        self,
        share: CompiledStorageShare,
        location: SmbShareLocation,
        *,
        principal_name: str | None = None,
        operation: str | None = None,
    ) -> bool:
        principal_name = (
            principal_name or getattr(self, "smb_principal", None) or self._resolve_smb_principal()
        )
        principal_user = self.executor._user_model_for_username(principal_name)
        username = principal_name.casefold()
        groups = {
            group.name.casefold()
            for group in self.executor._scenario_environment.groups or []
            if principal_name in group.members
        }
        groups.update(group.casefold() for group in principal_user.groups)
        principals = {username, *groups, "authenticated users", "domain users"}
        if principals.intersection(principal.casefold() for principal in share.access.deny):
            return False
        resolved_operation = operation or self.request.spec.operation
        read_access = resolved_operation in {"browse", "read"} or (
            resolved_operation == "copy" and location is self.request.spec.source
        )
        required = share.access.read if read_access else share.access.modify
        return bool(principals.intersection(principal.casefold() for principal in required))
