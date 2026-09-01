# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical SMB2/3 disk-share activity bundle."""

from __future__ import annotations

import hashlib
import math
import ntpath
import posixpath
import random
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from functools import partial
from typing import Any, Literal

from evidenceforge.events.authentication import (
    RemoteAuthenticationPlan,
    RemoteAuthenticationTransportPlan,
)
from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.content_identity import FileContentIdentity
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
    PreparedActionCohortProjection,
    PreparedPersistentSmbSourcePublication,
)
from evidenceforge.events.identity import EventIdentityPlan, ProcessIdentity
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
    PersistentSmbApplicationIntent,
    PersistentSmbRootIntent,
)
from evidenceforge.generation.activity.smb_profiles import (
    client_auth_options,
    client_process_for_operation,
    load_smb_profiles,
    local_smbclient_operand,
    select_client_profile,
    smb_file_evolution_profile,
)
from evidenceforge.generation.activity.smb_profiles import render_process as render_smb_process
from evidenceforge.generation.activity.timing_profiles import get_timing_window
from evidenceforge.generation.baseline_timing import BaselineTimingPlanner
from evidenceforge.generation.persistent_smb_continuation import (
    MAX_PERSISTENT_SMB_OPERATIONS,
    PersistentSmbClientProcessPreparation,
    PersistentSmbRootHandoff,
    PersistentSmbTerminalContinuation,
    SmbActivityResult,
)
from evidenceforge.generation.persistent_smb_continuation import (
    PersistentSmbActionPreparation as _PersistentSmbActionPreparation,
)
from evidenceforge.generation.persistent_smb_continuation import (
    PersistentSmbPreparedOperation as _PersistentSmbPreparedOperation,
)
from evidenceforge.generation.persistent_smb_continuation import (
    PersistentSmbPreparedSource as _PersistentSmbPreparedSource,
)
from evidenceforge.generation.persistent_smb_continuation import (
    PersistentSmbSourceBuilding as _PersistentSmbSourceBuilding,
)
from evidenceforge.generation.persistent_smb_continuation import (
    PersistentSmbTerminalFacts as _PersistentSmbTerminalFacts,
)
from evidenceforge.generation.persistent_smb_continuation import (
    SmbOperationTiming as _SmbOperationTiming,
)
from evidenceforge.generation.persistent_smb_projection import (
    PersistentSmbProjectionGroupToken,
    PersistentSmbProjectionMemberCertification,
    PersistentSmbProjectionMemberCommitReceipt,
    PersistentSmbProjectionMemberToken,
    PersistentSmbProjectionPhase,
    encode_persistent_smb_projection_capsule,
)
from evidenceforge.generation.smb_channels import (
    SmbChannelAffinity,
    SmbCompletedHandlePlan,
    SmbCompletedOperationPlan,
    SmbHandleView,
    SmbOperationLease,
)
from evidenceforge.generation.source_timing import (
    SourceTimingActionCapacityReservation,
    SourceTimingPreparation,
)
from evidenceforge.generation.state_manager import (
    SmbConnectionPinInstallReceipt,
    SmbFileMutationCommitResult,
    SmbFileMutationJournal,
)
from evidenceforge.generation.storage_world import (
    CompiledStorageFile,
    CompiledStorageMapping,
    CompiledStorageShare,
    StorageWorldModel,
)
from evidenceforge.generation.timing import TimingRuntime
from evidenceforge.models.exceptions import EventContractError, SmbActivityWindowError, StateError
from evidenceforge.models.scenario import (
    SmbActivityEventSpec,
    SmbClientLocation,
    SmbShareLocation,
    System,
    User,
)
from evidenceforge.models.state import SmbFileState
from evidenceforge.utils.ids import generate_stable_zeek_uid
from evidenceforge.utils.rng import _stable_seed, stable_uuid
from evidenceforge.utils.time import ensure_utc, parse_duration

_MAX_PERSISTENT_SMB_OPERATIONS = MAX_PERSISTENT_SMB_OPERATIONS
_MAX_PERSISTENT_SMB_SOURCE_MEMBERS = 6 + 3 * _MAX_PERSISTENT_SMB_OPERATIONS


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
class SmbFilePrecondition:
    """Exact read-only file state consumed by one SMB preparation."""

    file_id: str
    share: str
    path: str
    version: int
    size_bytes: int
    mime_type: str
    tags: tuple[str, ...]
    deleted: bool
    prior_paths: tuple[str, ...]

    @classmethod
    def from_state(cls, state: SmbFileState) -> SmbFilePrecondition:
        """Freeze a detached mutable state row into immutable planning truth."""

        return cls(
            file_id=state.file_id,
            share=state.share,
            path=state.path,
            version=state.version,
            size_bytes=state.size_bytes,
            mime_type=state.mime_type,
            tags=tuple(state.tags),
            deleted=state.deleted,
            prior_paths=tuple(state.prior_paths),
        )


@dataclass(frozen=True, slots=True)
class SmbActivityPreparation:
    """Immutable one-leg SMB selection, mutation, byte, and timing plan."""

    request: SmbActivityRequest
    primary_location: SmbShareLocation
    share: CompiledStorageShare
    server: System
    client_system: System | None
    client_ip: str
    mapping: CompiledStorageMapping | None
    smb_principal: str
    client_access: str
    outcome: str
    auth_protocol: str
    principal_user: User
    effective_uid: int | None
    effective_gid: int | None
    selected: tuple[CompiledStorageFile, ...]
    prestates: tuple[SmbFilePrecondition, ...]
    planned_sizes: tuple[int, ...]
    operation_timings: tuple[_SmbOperationTiming, ...]
    byte_allocations: tuple[tuple[int, int], ...]
    duration: float
    closed_at: datetime
    binding_digest: str
    client_source_by_destination: tuple[tuple[str, CompiledStorageFile], ...] = ()
    client_source_by_destination_path: tuple[tuple[str, CompiledStorageFile], ...] = ()


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
        self._client_source_by_destination: dict[str, CompiledStorageFile] = {}
        self._client_source_by_destination_path: dict[str, CompiledStorageFile] = {}
        self._preparation: SmbActivityPreparation | None = None
        self._planning_prestates: dict[str, SmbFilePrecondition] = {}
        self._planning_post_sizes: dict[str, int] = {}

    def _requires_composite_expansion(self) -> bool:
        """Return whether this request expands into separately prepared SMB legs."""

        spec = self.request.spec
        source = spec.source
        destination = spec.destination
        if spec.operation not in {"copy", "move"} or not isinstance(source, SmbShareLocation):
            return False
        if (
            spec.operation == "move"
            and isinstance(destination, SmbShareLocation)
            and destination.share.casefold() == source.share.casefold()
        ):
            return False
        if not isinstance(destination, SmbShareLocation) and spec.operation == "copy":
            return False
        return True

    def _adopt_preparation(self, preparation: SmbActivityPreparation) -> None:
        """Install exact immutable planning truth on its matching bundle."""

        if type(preparation) is not SmbActivityPreparation:
            raise StateError("SMB execution requires an exact activity preparation")
        if preparation.request != self.request:
            raise StateError("SMB preparation belongs to a different activity request")
        if preparation.binding_digest != self._preparation_binding_digest(preparation):
            raise StateError("SMB preparation binding digest does not authenticate its plan")
        if preparation.closed_at != self.request.time + timedelta(seconds=preparation.duration):
            raise StateError("SMB preparation close time does not match its duration")
        if len(preparation.selected) != len(preparation.prestates) or len(
            preparation.selected
        ) != len(preparation.planned_sizes):
            raise StateError("SMB preparation file vectors have inconsistent lengths")
        if len(preparation.selected) != len(preparation.operation_timings) or len(
            preparation.selected
        ) != len(preparation.byte_allocations):
            raise StateError("SMB preparation operation vectors have inconsistent lengths")
        self.server = preparation.server
        self.client_system = preparation.client_system
        self.mapping = preparation.mapping
        self.smb_principal = preparation.smb_principal
        self.client_access = preparation.client_access
        self.outcome = preparation.outcome
        self._client_source_by_destination = dict(preparation.client_source_by_destination)
        self._client_source_by_destination_path = dict(
            preparation.client_source_by_destination_path
        )
        self._preparation = preparation

    @staticmethod
    def _preparation_binding_digest(preparation: SmbActivityPreparation) -> str:
        """Digest every immutable field that execution consumes."""

        return hashlib.sha256(
            repr(
                (
                    "smb-activity-preparation-v1",
                    preparation.request,
                    preparation.primary_location,
                    preparation.share,
                    preparation.server,
                    preparation.client_system,
                    preparation.client_ip,
                    preparation.mapping,
                    preparation.smb_principal,
                    preparation.client_access,
                    preparation.outcome,
                    preparation.auth_protocol,
                    preparation.principal_user,
                    preparation.effective_uid,
                    preparation.effective_gid,
                    preparation.selected,
                    preparation.prestates,
                    preparation.planned_sizes,
                    preparation.operation_timings,
                    preparation.byte_allocations,
                    preparation.duration,
                    preparation.closed_at,
                    preparation.client_source_by_destination,
                    preparation.client_source_by_destination_path,
                )
            ).encode("utf-8")
        ).hexdigest()

    def _validate_preparation_prestate(self, preparation: SmbActivityPreparation) -> None:
        """Reject stale file state before opening any SMB mutation authority."""

        for file, expected in zip(
            preparation.selected,
            preparation.prestates,
            strict=True,
        ):
            actual = SmbFilePrecondition.from_state(
                self.executor.state_manager.smb_file_snapshot(file)
            )
            if actual != expected:
                raise StateError(
                    "SMB activity preparation is stale before mutation: "
                    f"file={file.file_id!r}, expected_version={expected.version}, "
                    f"actual_version={actual.version}, expected_size={expected.size_bytes}, "
                    f"actual_size={actual.size_bytes}"
                )

    def _validate_preparation_window(self, preparation: SmbActivityPreparation) -> None:
        """Reject an explicit prepared activity that exceeds the strict runtime window."""

        window_end = getattr(self.executor, "_scenario_end_time", None)
        if not isinstance(window_end, datetime) or preparation.closed_at <= window_end:
            return
        raise SmbActivityWindowError(
            action_id=self.anchor.stable_id,
            share=preparation.share.ref,
            file_ids=tuple(file.file_id for file in preparation.selected),
            operation=self.request.spec.operation,
            size_bytes=sum(preparation.planned_sizes),
            opened_at=self.request.time,
            closed_at=preparation.closed_at,
            window_end=window_end,
        )

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
            (
                preparation.binding_digest
                if (preparation := getattr(self, "_preparation", None)) is not None
                else ""
            ),
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
                    self._client_source_by_destination.get(file.file_id, file).file_id,
                )
                for file in selected
            ),
            target_formats,
        )
        return hashlib.sha256(repr(payload).encode("utf-8")).hexdigest()

    def prepare(self) -> SmbActivityPreparation:
        """Freeze one non-composite SMB activity without mutating runtime authorities."""

        spec = self.request.spec
        if self._requires_composite_expansion():
            raise StateError(
                "Composite SMB transfers prepare and execute one physical leg at a time"
            )
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
        creates_remote_copy = (
            spec.operation in {"copy", "move"}
            and not isinstance(spec.source, SmbShareLocation)
            and isinstance(spec.destination, SmbShareLocation)
        )
        if (
            creates_remote_copy
            and isinstance(spec.source, SmbClientLocation)
            and spec.source.file_set is not None
            and not self.request.files_override
        ):
            source_files = self._select_client_file_set(spec.source)
            selected = tuple(
                self._client_upload_destination_file(file, spec.destination)
                for file in source_files
            )
            self._client_source_by_destination = dict(
                zip((file.file_id for file in selected), source_files, strict=True)
            )
            self._client_source_by_destination_path = dict(
                zip((file.path.casefold() for file in selected), source_files, strict=True)
            )
        else:
            selected = self._select(primary_location)
        if (
            (spec.operation == "create" or creates_remote_copy)
            and not self.request.files_override
            and not self._client_source_by_destination
        ):
            selected = (self._create_placeholder(primary_location, share),)
        if not selected and spec.outcome == "not_found" and primary_location.path is not None:
            selected = (self._missing_placeholder(primary_location, share),)
        if not selected:
            raise ValueError(f"smb_activity selected no files on {share.ref}")

        prestates = tuple(
            SmbFilePrecondition.from_state(self.executor.state_manager.smb_file_snapshot(file))
            for file in selected
        )
        self._planning_prestates = {state.file_id: state for state in prestates}
        try:
            planned_sizes = tuple(
                self._updated_size(file, index)
                if spec.operation == "update" and self.outcome == "success"
                else self._planned_transfer_size(file, index)
                for index, file in enumerate(selected)
            )
            self._planning_post_sizes = dict(
                zip((file.file_id for file in selected), planned_sizes, strict=True)
            )
            duration = self._duration(selected)
            operation_timings = tuple(
                self._operation_timing(
                    file,
                    index,
                    size_bytes=self._planned_operation_size(file, index),
                )
                for index, file in enumerate(selected)
            )
            byte_allocations = self._transport_byte_allocations(selected)
        finally:
            self._planning_prestates = {}
            self._planning_post_sizes = {}
        closed_at = self.request.time + timedelta(seconds=duration)
        preparation = SmbActivityPreparation(
            request=self.request,
            primary_location=primary_location,
            share=share,
            server=server,
            client_system=client_system,
            client_ip=client_ip,
            mapping=self.mapping,
            smb_principal=self.smb_principal,
            client_access=self.client_access,
            outcome=self.outcome,
            auth_protocol=auth_protocol,
            principal_user=principal_user,
            effective_uid=effective_uid,
            effective_gid=effective_gid,
            selected=selected,
            prestates=prestates,
            planned_sizes=planned_sizes,
            operation_timings=operation_timings,
            byte_allocations=byte_allocations,
            duration=duration,
            closed_at=closed_at,
            binding_digest="",
            client_source_by_destination=tuple(self._client_source_by_destination.items()),
            client_source_by_destination_path=tuple(
                self._client_source_by_destination_path.items()
            ),
        )
        preparation = replace(
            preparation,
            binding_digest=self._preparation_binding_digest(preparation),
        )
        self._preparation = preparation
        return preparation

    def execute(
        self,
        preparation: SmbActivityPreparation | None = None,
    ) -> SmbActivityResult:
        """Execute one exact prepared SMB leg or expand a composite transfer."""

        spec = self.request.spec
        if preparation is None and self._requires_composite_expansion():
            composite = self._execute_composite_transfer()
            if composite is None:
                raise StateError("Composite SMB expansion did not produce a result")
            return composite
        preparation = preparation or self.prepare()
        self._adopt_preparation(preparation)
        self._validate_preparation_prestate(preparation)
        self._validate_preparation_window(preparation)
        share = preparation.share
        server = preparation.server
        client_system = preparation.client_system
        client_ip = preparation.client_ip
        auth_protocol = preparation.auth_protocol
        principal_user = preparation.principal_user
        effective_uid = preparation.effective_uid
        effective_gid = preparation.effective_gid
        selected = preparation.selected
        duration = preparation.duration
        if self._server_platform(server) == "windows":
            if not 1 <= len(selected) <= _MAX_PERSISTENT_SMB_OPERATIONS:
                raise ValueError("Persistent SMB production requires 1..64 file operations")
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
            retained_phase = None
            retained_root_facts = None
            if terminal_continuation is not None:
                retained_root_facts = (
                    self.executor._persistent_smb_terminal_continuations.root_facts(
                        terminal_continuation
                    )
                )
                retained_phase = retained_root_facts.phase
                if retained_phase == "source_published":
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
            retained_action_preparation = (
                retained_root_facts.action_preparation if retained_root_facts is not None else None
            )
            if type(retained_action_preparation) is _PersistentSmbActionPreparation:
                client_process_preparation = retained_action_preparation.client_process
            else:
                if retained_phase not in {None, "reserved", "cancelling"}:
                    raise StateError(
                        "Persistent SMB continuation lost its client process preparation"
                    )
                client_process_preparation = self._prepare_persistent_client_process(
                    share=share,
                    selected=selected,
                    server=server,
                    client_system=client_system,
                    auth_protocol=auth_protocol or "ntlm",
                )
            operation_member_count = 3 if self.outcome == "success" else 1
            member_budget = (
                5
                + len(selected) * operation_member_count
                + int(client_process_preparation.disposition == "materialize")
            )
            if member_budget > _MAX_PERSISTENT_SMB_SOURCE_MEMBERS:
                raise ValueError(
                    "Persistent SMB activity exceeds the bounded source-member capacity: "
                    f"{member_budget} > {_MAX_PERSISTENT_SMB_SOURCE_MEMBERS}"
                )
            continuation_authority = self.executor._persistent_smb_terminal_continuations
            source_byte_budget = max(2 * 1024 * 1024, member_budget * 64 * 1024)
            if terminal_continuation is not None and retained_phase == "cancelling":
                retry_cleanup = StateError("Persistent SMB retry resumed uncommitted cleanup")
                cleanup_consumed = self._cancel_or_release_persistent_smb_continuation(
                    terminal_continuation,
                    retry_cleanup,
                    action_binding_digest=terminal_binding_digest,
                    member_budget=member_budget,
                )
                if not cleanup_consumed:
                    raise retry_cleanup
                terminal_continuation = None
                retained_phase = None
            needs_pre_root_reservations = False
            if terminal_continuation is None:
                if client_system is not None:
                    # Nested DNS/AD-SRV publication must finish before the persistent
                    # source reservation installs its exact writer fence. The physical
                    # root below suppresses its ordinary prerequisite expansion.
                    self.executor._expand_and_emit(
                        "connection",
                        self.request.time,
                        src_ip=client_ip,
                        dst_ip=server.ip,
                        dst_port=445,
                        proto="tcp",
                        service="smb",
                        hostname=server.hostname,
                        source_system=client_system,
                        source_pid=-1,
                        source_image="",
                    )
                terminal_continuation = continuation_authority.reserve_claimed(
                    action_id=self.anchor.stable_id,
                    action_binding_digest=terminal_binding_digest,
                    retained_bytes=max(256 * 1024, len(selected) * 32 * 1024),
                )
                needs_pre_root_reservations = True
            else:
                retained_root_facts = continuation_authority.root_facts(terminal_continuation)
                if retained_root_facts.phase == "reserved":
                    retained_reservations = (
                        retained_root_facts.projection_group,
                        retained_root_facts.source_reservation,
                        retained_root_facts.source_timing_capacity,
                    )
                    if all(reservation is None for reservation in retained_reservations):
                        needs_pre_root_reservations = True
                    elif any(reservation is None for reservation in retained_reservations):
                        continuation_authority.release_claim(terminal_continuation)
                        raise StateError(
                            "Persistent SMB continuation retained a partial pre-root owner set"
                        )
            if needs_pre_root_reservations:
                projection_group = None
                source_reservation = None
                source_timing_capacity = None
                try:
                    source_timing_capacity = (
                        self.executor.dispatcher.source_timing_planner.reserve_action_capacity(
                            action_id=self.anchor.stable_id,
                            action_binding_digest=terminal_binding_digest,
                            detached_binding_budget=member_budget,
                        )
                    )
                    projection_group = (
                        self.executor.dispatcher.reserve_persistent_smb_projection_group(
                            route_generation_digest=route_generation_digest,
                            member_budget=member_budget,
                            byte_budget=source_byte_budget,
                            required_target_formats=target_formats,
                        )
                    )
                    source_reservation = (
                        self.executor.dispatcher.reserve_persistent_smb_source_publication(
                            projection_group,
                            target_formats=target_formats,
                            publication_key=self.anchor.stable_id,
                            row_budget=4 * member_budget,
                            byte_budget=source_byte_budget,
                        )
                    )
                    continuation_authority.bind_pre_root_reservations(
                        terminal_continuation,
                        projection_group=projection_group,
                        source_reservation=source_reservation,
                        source_timing_capacity=source_timing_capacity,
                    )
                except BaseException as primary:
                    primary_error = primary
                    recovery_ambiguous = False
                    planner = self.executor.dispatcher.source_timing_planner
                    if source_timing_capacity is None:
                        try:
                            source_timing_capacity = planner.recover_action_capacity(
                                action_id=self.anchor.stable_id,
                                action_binding_digest=terminal_binding_digest,
                                detached_binding_budget=member_budget,
                            )
                        except BaseException as recovery_error:
                            recovery_ambiguous = True
                            primary.add_note(
                                "Persistent SMB source-timing recovery also failed: "
                                f"{type(recovery_error).__name__}: {recovery_error}"
                            )
                    if projection_group is None:
                        try:
                            projection_group = (
                                self.executor.dispatcher.recover_persistent_smb_projection_group(
                                    route_generation_digest=route_generation_digest,
                                    member_budget=member_budget,
                                    byte_budget=source_byte_budget,
                                    required_target_formats=target_formats,
                                )
                            )
                        except BaseException as recovery_error:
                            recovery_ambiguous = True
                            primary.add_note(
                                "Persistent SMB projection-group recovery also failed: "
                                f"{type(recovery_error).__name__}: {recovery_error}"
                            )
                    if source_reservation is None and projection_group is not None:
                        try:
                            source_reservation = self.executor.dispatcher.recover_reserved_persistent_smb_source_publication(
                                projection_group,
                                target_formats=target_formats,
                                publication_key=self.anchor.stable_id,
                                row_budget=4 * member_budget,
                                byte_budget=source_byte_budget,
                            )
                        except BaseException as recovery_error:
                            recovery_ambiguous = True
                            primary.add_note(
                                "Persistent SMB source-reservation recovery also failed: "
                                f"{type(recovery_error).__name__}: {recovery_error}"
                            )
                    retained_pre_root = False
                    if (
                        source_reservation is not None
                        and projection_group is not None
                        and source_timing_capacity is not None
                    ):
                        try:
                            continuation_authority.bind_pre_root_reservations(
                                terminal_continuation,
                                projection_group=projection_group,
                                source_reservation=source_reservation,
                                source_timing_capacity=source_timing_capacity,
                            )
                        except BaseException as cleanup_error:
                            retained = continuation_authority.root_facts(terminal_continuation)
                            retained_pre_root = bool(
                                retained.projection_group is projection_group
                                and retained.source_reservation is source_reservation
                                and retained.source_timing_capacity is source_timing_capacity
                            )
                            if not retained_pre_root:
                                primary.add_note(
                                    "Persistent SMB pre-root retention also failed: "
                                    f"{type(cleanup_error).__name__}: {cleanup_error}"
                                )
                        else:
                            retained_pre_root = True
                    if retained_pre_root:
                        try:
                            cleanup_consumed = self._cancel_or_release_persistent_smb_continuation(
                                terminal_continuation,
                                primary,
                                action_binding_digest=terminal_binding_digest,
                                member_budget=member_budget,
                            )
                        except BaseException as cleanup_error:
                            primary.add_note(
                                "Persistent SMB retained pre-root cleanup also failed: "
                                f"{type(cleanup_error).__name__}: {cleanup_error}"
                            )
                        else:
                            if not cleanup_consumed:
                                primary.add_note(
                                    "Persistent SMB retained pre-root cleanup remains pending"
                                )
                        raise

                    def cancel_unbound_or_adopt(
                        *,
                        label: str,
                        authenticates: Callable[[], bool],
                        cancel: Callable[[], None],
                    ) -> bool:
                        last_error: BaseException | None = None
                        for _attempt in range(2):
                            if not authenticates():
                                return True
                            try:
                                cancel()
                            except BaseException as cleanup_error:
                                last_error = cleanup_error
                        if authenticates():
                            cleanup_error = last_error or StateError(
                                f"Persistent SMB unbound {label} retained its exact owner"
                            )
                            primary_error.add_note(
                                f"Persistent SMB unbound {label} cancellation also failed: "
                                f"{type(cleanup_error).__name__}: {cleanup_error}"
                            )
                            return False
                        return True

                    unbound_neutral = not recovery_ambiguous
                    if source_reservation is not None:
                        unbound_neutral = unbound_neutral and cancel_unbound_or_adopt(
                            label="source-reservation",
                            authenticates=lambda: (
                                self.executor.dispatcher.authenticates_reserved_persistent_smb_source_publication(
                                    source_reservation
                                )
                            ),
                            cancel=lambda: (
                                self.executor.dispatcher.cancel_reserved_persistent_smb_source_publication(
                                    source_reservation
                                )
                            ),
                        )
                    if unbound_neutral and projection_group is not None:
                        unbound_neutral = cancel_unbound_or_adopt(
                            label="empty-group",
                            authenticates=lambda: (
                                self.executor.dispatcher.authenticates_empty_persistent_smb_projection_group(
                                    projection_group
                                )
                            ),
                            cancel=lambda: (
                                self.executor.dispatcher.cancel_empty_persistent_smb_projection_group(
                                    projection_group
                                )
                            ),
                        )
                    if unbound_neutral and source_timing_capacity is not None:
                        unbound_neutral = cancel_unbound_or_adopt(
                            label="source-timing",
                            authenticates=lambda: planner.authenticates_action_capacity(
                                source_timing_capacity,
                                action_id=self.anchor.stable_id,
                                action_binding_digest=terminal_binding_digest,
                                detached_binding_budget=member_budget,
                            ),
                            cancel=lambda: planner.cancel_action_capacity(source_timing_capacity),
                        )
                    if not unbound_neutral:
                        primary.add_note(
                            "Persistent SMB pre-root owners remain action-keyed for retry"
                        )
                        continuation_authority.release_claim(terminal_continuation)
                        raise
                    cleanup_consumed = self._cancel_or_release_persistent_smb_continuation(
                        terminal_continuation,
                        primary,
                        action_binding_digest=terminal_binding_digest,
                        member_budget=member_budget,
                    )
                    if not cleanup_consumed:
                        primary.add_note(
                            "Persistent SMB neutral continuation cleanup remains pending"
                        )
                    raise
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
                    target_formats=target_formats,
                    terminal_binding_digest=terminal_binding_digest,
                    member_budget=member_budget,
                    terminal_continuation=terminal_continuation,
                    client_process_preparation=client_process_preparation,
                )
            except BaseException as primary:
                self._cancel_or_release_persistent_smb_continuation(
                    terminal_continuation,
                    primary,
                    action_binding_digest=terminal_binding_digest,
                    member_budget=member_budget,
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
            suppress_source_pid_inference=(
                self.client_access == "cifs_mount"
                or (process_plan is not None and transport_pid <= 0)
            ),
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
        affinity = self._channel_affinity(
            share=share,
            server=server,
            client_system=client_system,
            client_ip=client_ip,
            process=process,
            auth_protocol=auth_protocol,
        )
        byte_allocations = self._transport_byte_allocations(selected)
        total_orig_bytes = sum(orig for orig, _resp in byte_allocations)
        total_resp_bytes = sum(resp for _orig, resp in byte_allocations)
        operation_start = (
            auth_time
            + timedelta(milliseconds=tree_delay_ms)
            + timedelta(seconds=self._session_setup_seconds())
        )
        close_time = self.transport_start + timedelta(seconds=max(0.2, duration - 0.02))
        first_timing = self._operation_timing(
            selected[0],
            0,
            size_bytes=self._planned_operation_size(selected[0], 0),
        )
        first_lease = self.executor._smb_channel_manager.open_session(
            affinity,
            transport_plan=transport_plan,
            sensor_observations=self.executor.dispatcher.network_observations_for(transport_uid),
            ground_truth_transport_uid=ground_truth_transport_uid,
            logon_id=logon_id,
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
            operation_ended_at=operation_start + timedelta(seconds=first_timing.total_seconds),
            operation_initiator_bytes=byte_allocations[0][0],
            operation_responder_bytes=byte_allocations[0][1],
            idle_timeout=self._idle_timeout(),
            initiator_budget=total_orig_bytes,
            responder_budget=total_resp_bytes,
            operation_budget=len(selected),
        )
        journal = self.executor.state_manager.begin_smb_file_mutation_journal(
            f"{self.anchor.stable_id}:files"
        )
        operation_truth: list[dict[str, Any]] = []
        current_lease = first_lease
        try:
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
                    session_id=first_lease.session_id,
                    tree_id=first_lease.tree_id,
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
            operation_cursor = operation_start
            for index, file in enumerate(selected):
                planned_timing = self._operation_timing(
                    file,
                    index,
                    size_bytes=self._planned_operation_size(file, index),
                )
                if index > 0:
                    reuse = self.executor._smb_channel_manager.reserve_channel_reuse(
                        first_lease,
                        affinity,
                        share_ref=share.ref,
                        semantic_operation_id=f"{self.anchor.stable_id}:{index}",
                        requested_at=operation_cursor,
                        required_until=operation_cursor
                        + timedelta(seconds=planned_timing.total_seconds),
                        initiator_bytes=byte_allocations[index][0],
                        responder_bytes=byte_allocations[index][1],
                    )
                    if reuse.lease is None:
                        raise StateError(
                            "SMB application channel rejected a pre-budgeted operation reuse"
                        )
                    current_lease = reuse.lease
                truth = self._execute_file_operation(
                    file=file,
                    operation_index=index,
                    share=share,
                    lease=current_lease,
                    journal=journal,
                    network=net,
                    server=server,
                    client=client_system,
                    auth=auth,
                    process=None,
                    timestamp=current_lease.started_at,
                )
                operation_truth.append(truth)
                operation_cursor = current_lease.ended_at

            self._close_application_session_exactly_once(
                first_lease.channel_id,
                close_time=close_time,
            )
            self.executor.generate_logoff(
                principal_user,
                server,
                close_time,
                logon_id,
                logon_type=3,
                from_storyline=True,
            )
            self._commit_and_acknowledge_file_journal(journal)
        except BaseException as primary:
            self._cancel_file_journal_after_failure(journal, primary)
            self._close_application_session_after_failure(
                first_lease.channel_id,
                close_time=close_time,
                primary=primary,
            )
            raise
        return SmbActivityResult(
            session_id=first_lease.session_id,
            tree_ids=(first_lease.tree_id,),
            transport_uids=(ground_truth_transport_uid,),
            operations=tuple(operation_truth),
            completed_at=close_time,
        )

    def _cancel_or_release_persistent_smb_continuation(
        self,
        continuation: PersistentSmbTerminalContinuation,
        primary: BaseException,
        *,
        action_binding_digest: str,
        member_budget: int,
    ) -> bool:
        """Resume exact reversible cleanup, or retain its cleanup-only retry cursor."""

        authority = self.executor._persistent_smb_terminal_continuations
        if not authority.authenticates_claimed(continuation):
            return False
        try:
            return self._cancel_claimed_persistent_smb_continuation(
                continuation,
                primary,
                action_binding_digest=action_binding_digest,
                member_budget=member_budget,
            )
        except BaseException:
            if authority.authenticates_claimed(continuation):
                authority.release_claim(continuation)
            raise

    def _cancel_claimed_persistent_smb_continuation(
        self,
        continuation: PersistentSmbTerminalContinuation,
        primary: BaseException,
        *,
        action_binding_digest: str,
        member_budget: int,
    ) -> bool:
        """Run cleanup while the caller owns the exact active continuation claim."""

        authority = self.executor._persistent_smb_terminal_continuations
        facts = authority.root_facts(continuation)
        if facts.phase not in {"reserved", "action_prepared", "cancelling"}:
            authority.release_claim(continuation)
            return False
        authority.begin_uncommitted_cleanup(continuation)

        def cancel_or_adopt(
            *,
            label: str,
            authenticates: Callable[[], bool],
            cancel: Callable[[], None],
        ) -> bool:
            last_error: BaseException | None = None
            for _attempt in range(2):
                if not authenticates():
                    return True
                try:
                    cancel()
                except BaseException as cleanup_error:
                    last_error = cleanup_error
            if not authenticates():
                return True
            cleanup_error = last_error or StateError(
                f"Persistent SMB {label} cancellation retained its exact owner"
            )
            primary.add_note(
                f"Persistent SMB {label} cancellation also failed: "
                f"{type(cleanup_error).__name__}: {cleanup_error}"
            )
            return False

        while True:
            facts = authority.root_facts(continuation)
            if facts.cleanup_cursor == 0:
                preparation = facts.action_preparation
                if preparation is not None and not self._cancel_file_journal_after_failure(
                    preparation.journal,
                    primary,
                ):
                    authority.release_claim(continuation)
                    return False
                authority.advance_uncommitted_cleanup(continuation, expected_cursor=0)
                continue
            if facts.cleanup_cursor == 1:
                source_reservation = facts.source_reservation
                if source_reservation is not None and not cancel_or_adopt(
                    label="source-reservation",
                    authenticates=partial(
                        self.executor.dispatcher.authenticates_reserved_persistent_smb_source_publication,
                        source_reservation,
                    ),
                    cancel=partial(
                        self.executor.dispatcher.cancel_reserved_persistent_smb_source_publication,
                        source_reservation,
                    ),
                ):
                    authority.release_claim(continuation)
                    return False
                authority.advance_uncommitted_cleanup(continuation, expected_cursor=1)
                continue
            if facts.cleanup_cursor == 2:
                projection_group = facts.projection_group
                if projection_group is not None and not cancel_or_adopt(
                    label="empty-group",
                    authenticates=partial(
                        self.executor.dispatcher.authenticates_empty_persistent_smb_projection_group,
                        projection_group,
                    ),
                    cancel=partial(
                        self.executor.dispatcher.cancel_empty_persistent_smb_projection_group,
                        projection_group,
                    ),
                ):
                    authority.release_claim(continuation)
                    return False
                authority.advance_uncommitted_cleanup(continuation, expected_cursor=2)
                continue
            if facts.cleanup_cursor == 3:
                source_timing_capacity = facts.source_timing_capacity
                if source_timing_capacity is not None:
                    planner = self.executor.dispatcher.source_timing_planner
                    authenticates_capacity = partial(
                        planner.authenticates_action_capacity,
                        source_timing_capacity,
                        action_id=self.anchor.stable_id,
                        action_binding_digest=action_binding_digest,
                        detached_binding_budget=member_budget,
                    )
                    if not cancel_or_adopt(
                        label="source-timing",
                        authenticates=authenticates_capacity,
                        cancel=partial(planner.cancel_action_capacity, source_timing_capacity),
                    ):
                        authority.release_claim(continuation)
                        return False
                    if (
                        planner.recover_action_capacity(
                            action_id=self.anchor.stable_id,
                            action_binding_digest=action_binding_digest,
                            detached_binding_budget=member_budget,
                        )
                        is not None
                    ):
                        primary.add_note(
                            "Persistent SMB source-timing cancellation retained its action owner"
                        )
                        authority.release_claim(continuation)
                        return False
                authority.advance_uncommitted_cleanup(continuation, expected_cursor=3)
                continue
            break
        if not authority.cancel_uncommitted(continuation):
            authority.release_claim(continuation)
            return False
        return True

    def _prepare_persistent_client_process(
        self,
        *,
        share: CompiledStorageShare,
        selected: tuple[CompiledStorageFile, ...],
        server: System,
        client_system: System | None,
        auth_protocol: str,
    ) -> PersistentSmbClientProcessPreparation:
        """Freeze one SMB client actor without mutating State or source output."""

        if client_system is None:
            return PersistentSmbClientProcessPreparation.none()
        os_category = self._server_platform(client_system)
        access_mode = {
            "windows_native": "explorer",
            "cifs_mount": "mounted",
            "smbclient": "direct",
        }.get(self.client_access)
        profile = select_client_profile(
            os_category,
            client_system.services or (),
            system_type=client_system.type,
            access_mode=access_mode,
            scope_key=(
                f"{client_system.hostname}:{self.request.actor.username}:{server.hostname}:"
                f"{share.name}:{self.request.spec.operation}:{self.request.time.isoformat()}"
            ),
        )
        transfer_direction: Literal["download", "upload", "remote"] | None = None
        if self.request.spec.operation in {"copy", "move"}:
            if isinstance(self.request.spec.source, SmbClientLocation):
                transfer_direction = "upload"
            elif isinstance(self.request.spec.destination, SmbClientLocation):
                transfer_direction = "download"
            else:
                transfer_direction = "remote"
        process_profile = client_process_for_operation(
            profile,
            self.request.spec.operation,
            transfer_direction=transfer_direction,
        )
        if process_profile is None:
            return PersistentSmbClientProcessPreparation.none()

        first_path = selected[0].path
        source_path, destination_path = self._process_transfer_operands(first_path, share)
        local_path = self._local_path(first_path)
        local_operand = local_path
        if process_profile.operand_mode in {"download", "upload"}:
            local_operand = local_smbclient_operand(
                first_path,
                local_path or self._client_path(first_path, share),
            )
        rendered = render_smb_process(
            process_profile,
            server=server.hostname,
            share=share.name,
            path=first_path,
            client_path=self._client_path(first_path, share),
            local_path=local_operand,
            source_path=source_path,
            destination_path=destination_path,
            username=self.request.actor.username,
            smb_principal=self.smb_principal,
            auth_options=client_auth_options(
                profile,
                "ntlmssp" if auth_protocol == "ntlm" else auth_protocol,
            ),
            operation=self.request.spec.operation,
            client_ip=client_system.ip,
        )
        session = self.executor._smb_actor_session(
            client_system,
            self.request.actor,
            self.request.time,
        )
        if session is None:
            return PersistentSmbClientProcessPreparation.none()
        session_identity = self.executor.state_manager.get_session_identity(session.logon_id)
        if session_identity is None:
            raise StateError("Persistent SMB client process lost its exact local session")

        image_lower = rendered.image.casefold()
        require_exact_command = self.executor._connection_owner_requires_exact_command_line(
            rendered.image,
            rendered.command_line,
        )
        running_candidates = self.executor.state_manager.get_processes_on_system(
            client_system.hostname
        )
        candidates = [
            candidate
            for candidate in running_candidates
            if candidate.username.casefold() == rendered.username.casefold()
            and candidate.logon_id == session.logon_id
            and candidate.image.casefold() == image_lower
            and (not require_exact_command or candidate.command_line == rendered.command_line)
            and candidate.start_time is not None
            and ensure_utc(candidate.start_time) <= ensure_utc(self.request.time)
            and not self.executor._connection_owner_requires_unique_transport_process(
                candidate.image
            )
        ]
        preferred_pid = self.request.process_pid
        if preferred_pid > 0:
            preferred = next(
                (candidate for candidate in running_candidates if candidate.pid == preferred_pid),
                None,
            )
            requested_image = self.request.process_image.casefold()
            if (
                preferred is not None
                and preferred.username.casefold() == self.request.actor.username.casefold()
                and preferred.logon_id == session.logon_id
                and preferred.start_time is not None
                and ensure_utc(preferred.start_time) <= ensure_utc(self.request.time)
                and (not requested_image or preferred.image.casefold() == requested_image)
                and not self.executor._connection_owner_requires_unique_transport_process(
                    preferred.image
                )
                and all(candidate.pid != preferred.pid for candidate in candidates)
            ):
                candidates.append(preferred)
            candidates.sort(key=lambda candidate: candidate.pid != preferred_pid)
        if candidates:
            running = max(
                candidates,
                key=lambda candidate: (
                    candidate.pid == preferred_pid,
                    ensure_utc(candidate.start_time),
                    candidate.pid,
                ),
            )
            identity = self.executor.state_manager.get_process_identity(
                client_system.hostname,
                running.pid,
            )
            if identity is None:
                raise StateError("Persistent SMB client process reuse lost canonical identity")
            parent_identity = self.executor.state_manager.get_process_identity(
                client_system.hostname,
                identity.parent_pid,
            )
            return PersistentSmbClientProcessPreparation(
                disposition="reuse",
                hostname=identity.hostname,
                process_object_id=identity.object_id,
                pid=identity.pid,
                parent_pid=identity.parent_pid,
                parent_object_id=(parent_identity.object_id if parent_identity is not None else ""),
                image=identity.image,
                command_line=identity.command_line,
                username=identity.principal,
                logon_id=identity.logon_id,
                session_object_id=session_identity.object_id,
                session_id=session_identity.session_id,
                logon_type=session.logon_type,
                started_at=identity.started_at,
                lifecycle_group_id=identity.lifecycle_group_id,
                os_category=os_category,
                integrity_level=running.integrity_level or "Medium",
                access_mode=profile.access_mode,
                path_style=profile.path_style,
                transport_attribution=(
                    "process" if profile.transport_attribution == "process" else "kernel"
                ),
                lifecycle=(
                    "operation"
                    if running.pid == preferred_pid and bool(self.request.process_image)
                    else rendered.lifecycle
                ),
            )

        seed = _stable_seed(
            "persistent-smb-client-process:"
            f"{self.anchor.stable_id}:{client_system.hostname}:{rendered.command_line}"
        )
        session_floor = ensure_utc(session.start_time) + timedelta(milliseconds=500)
        if rendered.lifecycle == "resident":
            started_at = session_floor + timedelta(milliseconds=seed % 2500)
        else:
            started_at = ensure_utc(self.request.time) - timedelta(milliseconds=450 + seed % 4551)
        started_at = max(session_floor, started_at)
        if started_at >= ensure_utc(self.request.time):
            started_at = ensure_utc(self.request.time) - timedelta(milliseconds=100)
        parent_pid = self.executor._resolve_existing_prepared_process_parent(
            system=client_system,
            user=self.request.actor,
            time=started_at,
            logon_id=session.logon_id,
            parent_pid=0,
            process_username=rendered.username,
        )
        parent_identity = (
            self.executor.state_manager.get_process_identity(client_system.hostname, parent_pid)
            if parent_pid > 0
            else None
        )
        return PersistentSmbClientProcessPreparation(
            disposition="materialize",
            hostname=client_system.hostname,
            process_object_id="",
            pid=0,
            parent_pid=parent_pid,
            parent_object_id=parent_identity.object_id if parent_identity is not None else "",
            image=rendered.image,
            command_line=rendered.command_line,
            username=rendered.username,
            logon_id=session.logon_id,
            session_object_id=session_identity.object_id,
            session_id=session_identity.session_id,
            logon_type=session.logon_type,
            started_at=started_at,
            lifecycle_group_id=stable_uuid(
                "persistent-smb-client-process-lifecycle",
                self.anchor.stable_id,
                client_system.hostname,
                rendered.key,
            ),
            os_category=os_category,
            integrity_level="Medium",
            access_mode=profile.access_mode,
            path_style=profile.path_style,
            transport_attribution=(
                "process" if profile.transport_attribution == "process" else "kernel"
            ),
            lifecycle=rendered.lifecycle,
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
        target_formats: tuple[str, ...],
        terminal_binding_digest: str,
        member_budget: int,
        terminal_continuation: PersistentSmbTerminalContinuation,
        client_process_preparation: PersistentSmbClientProcessPreparation,
    ) -> SmbActivityResult:
        """Execute one bounded persistent Windows disk-share action."""

        authority = self.executor._persistent_smb_terminal_continuations
        root_facts = authority.root_facts(terminal_continuation)
        if root_facts.phase == "reserved":
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
            operation_start = tree_time + timedelta(seconds=self._session_setup_seconds())
            affinity = self._channel_affinity(
                share=share,
                server=server,
                client_system=client_system,
                client_ip=client_ip,
                process=process,
                client_logon_id=client_process_preparation.logon_id,
                auth_protocol=auth_protocol,
            )
            byte_allocations = self._transport_byte_allocations(selected)
            journal = self.executor.state_manager.begin_smb_file_mutation_journal(
                f"{self.anchor.stable_id}:files"
            )
            operation_plans: list[SmbCompletedOperationPlan] = []
            prepared_records: list[_PersistentSmbPreparedOperation] = []
            operation_cursor = operation_start
            try:
                for index, file in enumerate(selected):
                    timing = self._operation_timing(
                        file,
                        index,
                        size_bytes=self._planned_operation_size(file, index),
                    )
                    started_at = (
                        operation_cursor
                        if index == 0
                        else operation_cursor + timedelta(microseconds=1)
                    )
                    ended_at = started_at + timedelta(seconds=timing.total_seconds)
                    action = self.request.spec.operation
                    result = self.outcome
                    creates_remote_copy = (
                        action in {"copy", "move"}
                        and not isinstance(self.request.spec.source, SmbShareLocation)
                        and isinstance(self.request.spec.destination, SmbShareLocation)
                    )
                    state = file
                    handle_access = ""
                    handle_deny_write = False
                    handle_role = "operation"
                    if result in {"access_denied", "not_found"}:
                        pass
                    elif result == "sharing_violation":
                        state = self.executor.state_manager.touch_smb_file(file, journal=journal)
                        handle_access = "read"
                        handle_deny_write = True
                        handle_role = "sharing-conflict"
                    elif action == "create" or creates_remote_copy:
                        state = self.executor.state_manager.create_smb_file(
                            share=share.ref,
                            path=file.path,
                            size_bytes=file.size_bytes,
                            mime_type=file.mime_type,
                            timestamp=started_at,
                            tags=file.tags,
                            journal=journal,
                        )
                        handle_access = "write"
                        if result == "success" and action == "move" and creates_remote_copy:
                            source_file = self._client_source_by_destination.get(file.file_id)
                            if source_file is not None:
                                source_state = self.executor.state_manager.touch_smb_file(
                                    source_file,
                                    journal=journal,
                                )
                                self.executor.state_manager.delete_smb_file(
                                    source_state.file_id,
                                    journal=journal,
                                )
                    else:
                        state = self.executor.state_manager.touch_smb_file(file, journal=journal)
                        handle_access = "read" if action in {"browse", "read", "copy"} else "write"
                    previous_path = ""
                    previous_client_path = ""
                    previous_server_path = ""
                    if result == "success" and action == "update":
                        state = self.executor.state_manager.update_smb_file(
                            state.file_id,
                            size_bytes=self._updated_size(file, index),
                            journal=journal,
                        )
                    elif result == "success" and action == "move" and not creates_remote_copy:
                        destination = self.request.spec.destination
                        destination_path = (
                            destination.path
                            if isinstance(destination, SmbShareLocation) and destination.path
                            else f"Archive\\{ntpath.basename(state.path)}"
                        )
                        destination_share = (
                            destination.share
                            if isinstance(destination, SmbShareLocation)
                            else share.ref
                        )
                        previous_path = state.path
                        previous_client_path = self._client_path(state.path, share)
                        previous_server_path = self.world.server_local_path(share, state.path)
                        state = self.executor.state_manager.move_smb_file(
                            state.file_id,
                            share=destination_share,
                            path=destination_path,
                            journal=journal,
                        )
                    elif result == "success" and action == "delete":
                        state = self.executor.state_manager.delete_smb_file(
                            state.file_id,
                            journal=journal,
                        )

                    handle_file_id = state.file_id
                    handle_content_version = state.version

                    phase_type = {
                        "browse": "smb_directory_enumeration",
                        "read": "smb_file_read",
                        "create": "smb_file_write",
                        "update": "smb_file_write",
                        "copy": "smb_file_read"
                        if isinstance(self.request.spec.source, SmbShareLocation)
                        else "smb_file_write",
                        "move": "smb_file_write" if creates_remote_copy else "smb_file_rename",
                        "delete": "smb_file_delete",
                    }[action]
                    phase = phase_type.removeprefix("smb_file_").removeprefix("smb_")
                    action_time = started_at + timedelta(
                        seconds=timing.setup_seconds + timing.jitter_seconds
                    )
                    handle_close_time = min(
                        ended_at,
                        action_time
                        + timedelta(seconds=timing.transfer_seconds + timing.close_delay_seconds),
                    )
                    if result == "sharing_violation":
                        handle_close_time = min(
                            ended_at,
                            started_at + timedelta(milliseconds=5),
                        )
                    handles = (
                        (
                            SmbCompletedHandlePlan(
                                file_id=handle_file_id,
                                content_version=handle_content_version,
                                access=handle_access,
                                opened_at=started_at,
                                closed_at=handle_close_time,
                                deny_write=handle_deny_write,
                                role=handle_role,
                            ),
                        )
                        if handle_access
                        else ()
                    )
                    operation_plans.append(
                        SmbCompletedOperationPlan(
                            semantic_operation_id=f"{self.anchor.stable_id}:{index}",
                            started_at=started_at,
                            ended_at=ended_at,
                            initiator_bytes=byte_allocations[index][0],
                            responder_bytes=byte_allocations[index][1],
                            handles=handles,
                        )
                    )
                    prepared_records.append(
                        _PersistentSmbPreparedOperation(
                            state=state,
                            timing=timing,
                            phase_type=phase_type,
                            phase=phase,
                            action_time=action_time,
                            handle_close_time=handle_close_time,
                            previous_path=previous_path,
                            previous_client_path=previous_client_path,
                            previous_server_path=previous_server_path,
                        )
                    )
                    operation_cursor = ended_at
                if operation_cursor > close_time:
                    raise StateError("Persistent SMB operations exceed their physical transport")
                preparation = _PersistentSmbActionPreparation(
                    auth_time=auth_time,
                    tree_time=tree_time,
                    close_time=close_time,
                    auth_session_ref=auth_session_ref,
                    affinity=affinity,
                    byte_allocations=tuple(byte_allocations),
                    journal=journal,
                    operation_plans=tuple(operation_plans),
                    operations=tuple(prepared_records),
                    client_process=client_process_preparation,
                )
                authority.bind_action_prepared(terminal_continuation, preparation)
            except BaseException as primary:
                self._cancel_file_journal_after_failure(journal, primary)
                raise
            root_facts = authority.root_facts(terminal_continuation)
        preparation = root_facts.action_preparation
        if type(preparation) is not _PersistentSmbActionPreparation:
            raise StateError("Persistent SMB continuation lost its action preparation")
        auth_time = preparation.auth_time
        tree_time = preparation.tree_time
        close_time = preparation.close_time
        auth_session_ref = preparation.auth_session_ref
        affinity = preparation.affinity
        byte_allocations = preparation.byte_allocations
        journal = preparation.journal
        operation_plans = preparation.operation_plans
        prepared_records = preparation.operations
        final_orig_bytes = sum(orig for orig, _resp in byte_allocations)
        final_resp_bytes = sum(resp for _orig, resp in byte_allocations)

        capture: NetworkConnectionIdentityCapture | None = None
        transport_uid = ""
        if root_facts.phase in {"action_prepared", "root_prepared"}:
            capture = NetworkConnectionIdentityCapture()
            transport_uid = self.executor.generate_connection(
                src_ip=client_ip,
                dst_ip=server.ip,
                time=self.request.time,
                dst_port=445,
                proto="tcp",
                service="smb",
                duration=duration,
                orig_bytes=final_orig_bytes,
                resp_bytes=final_resp_bytes,
                conn_state="SF",
                emit_dns=False,
                source_system=client_system,
                pid=-1,
                process_image=None,
                hostname=server.hostname,
                preserve_start_time=True,
                preserve_explicit_payload=True,
                suppress_application_side_effects=True,
                suppress_source_pid_inference=True,
                suppress_prereq_dns=True,
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
                    client_process=preparation.client_process,
                ),
                persistent_smb_application_intent=PersistentSmbApplicationIntent(
                    manager=self.executor._smb_channel_manager,
                    affinity=affinity,
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
                    tree_connected_at=tree_time,
                    operations=operation_plans,
                    idle_timeout=max(
                        self._idle_timeout(),
                        close_time - operation_plans[-1].ended_at,
                    ),
                    closed_at=close_time,
                ),
                persistent_smb_file_mutation_journal=journal,
                persistent_smb_terminal_authority=authority,
                persistent_smb_terminal_continuation=terminal_continuation,
                defer_source_publication=True,
                identity_capture=capture,
            )
            root_facts = authority.root_facts(terminal_continuation)
        if root_facts.phase not in {
            "root_committed",
            "source_building",
            "source_prepared",
            "source_published",
        }:
            raise StateError("Persistent SMB root did not retain its committed continuation")
        prepared_root = root_facts.prepared_root
        materialization = root_facts.materialization
        handoff = root_facts.handoff
        if (
            prepared_root is None
            or materialization is None
            or type(handoff) is not PersistentSmbRootHandoff
            or handoff.materialization is not materialization
            or handoff.file_journal is not journal
        ):
            raise StateError("Persistent SMB committed root changed retained owners")
        projection_group = root_facts.projection_group
        source_reservation = root_facts.source_reservation
        source_timing_capacity = root_facts.source_timing_capacity
        if (
            type(projection_group) is not PersistentSmbProjectionGroupToken
            or type(source_reservation) is not PreparedPersistentSmbSourcePublication
            or type(source_timing_capacity) is not SourceTimingActionCapacityReservation
            or not self.executor.dispatcher.source_timing_planner.authenticates_action_capacity(
                source_timing_capacity,
                action_id=self.anchor.stable_id,
                action_binding_digest=terminal_binding_digest,
                detached_binding_budget=member_budget,
            )
        ):
            raise StateError("Persistent SMB committed root lost its pre-root source capacity")
        if root_facts.phase == "source_building":
            return self._resume_persistent_smb_source_building(terminal_continuation)
        if root_facts.phase == "source_prepared":
            return self._resume_persistent_smb_source_prepared(terminal_continuation)
        if root_facts.phase == "source_published":
            return self._resume_persistent_windows_terminal(terminal_continuation)
        opening = prepared_root.root.transaction
        if capture is not None and (
            capture.require() is not opening
            or capture.require_prepared_root() is not prepared_root.root
            or capture.require_persistent_smb_root_handoff() is not handoff
        ):
            raise StateError("Persistent SMB root capture changed retained owners")
        if opening.closed_at is None:
            raise StateError("Persistent SMB root lost its canonical close")
        close_time = opening.closed_at
        self.transport_start = opening.started_at
        client_process_preparation = preparation.client_process
        client_identity: ProcessIdentity | None = None
        if client_process_preparation.disposition == "materialize":
            staged_processes = prepared_root.root.state_plan.batch.processes
            committed_processes = materialization.connection.state.processes
            if len(staged_processes) != 1 or len(committed_processes) != 1:
                raise StateError("Persistent SMB root lost its materialized client process")
            client_identity = staged_processes[0].identity
            if committed_processes[0].ecar_object_id != client_identity.object_id:
                raise StateError("Persistent SMB root committed a different client process")
        elif client_process_preparation.disposition == "reuse":
            client_identity = self.executor.state_manager.get_process_identity(
                client_process_preparation.hostname,
                client_process_preparation.pid,
            )
        if client_identity is not None and (
            client_identity.hostname != client_process_preparation.hostname
            or client_identity.image != client_process_preparation.image
            or client_identity.command_line != client_process_preparation.command_line
            or client_identity.principal != client_process_preparation.username
            or client_identity.logon_id != client_process_preparation.logon_id
            or client_identity.started_at != client_process_preparation.started_at
            or (
                client_process_preparation.disposition == "reuse"
                and client_identity.object_id != client_process_preparation.process_object_id
            )
        ):
            raise StateError("Persistent SMB root changed its exact client process identity")
        client_process_context = (
            self._exact_client_process_context(client_system, client_identity)
            if client_identity is not None
            else None
        )
        if client_system is not None and client_identity is not None:
            self.executor._remember_process_dependent_hold(
                system=client_system,
                pid=client_identity.pid,
                required_until=close_time,
            )
            if client_process_preparation.lifecycle == "operation":
                self.executor._remember_foreground_process_finalizer(
                    system=client_system,
                    user=self.request.actor,
                    pid=client_identity.pid,
                    process_name=client_identity.image,
                    logon_id=client_identity.logon_id,
                    termination_time=close_time,
                )
        pin_install = handoff.pin_install_receipt
        lifecycle_receipt = materialization.receipt
        if (
            transport_uid and opening.zeek_uid != transport_uid
        ) or not self.executor.state_manager.authenticates_smb_connection_pin_install_receipt(
            pin_install
        ):
            raise StateError("Persistent SMB root handoff failed owner authentication")
        lifecycle_binding = handoff.lifecycle_binding
        if not self.executor._lifecycle_authority.authenticates_detached_network_receipt_binding(
            lifecycle_binding
        ):
            raise StateError("Persistent SMB root handoff lost its detached lifecycle proof")
        traffic_binding = self.executor._persistent_smb_traffic_authority.issue_binding(
            opening,
            handoff.observations,
        )
        session_identity = pin_install.session_identity
        application_batch = handoff.application_result.result
        if (
            application_batch.session.logon_id != session_identity.logon_id
            or application_batch.session.transport_plan != opening
            or len(application_batch.operations) != len(selected)
        ):
            raise StateError("Persistent SMB terminal application result changed root identity")
        operation_events: list[OccurrenceBuilder] = []
        operation_truth: list[dict[str, Any]] = []
        operation_commons: list[dict[str, Any]] = []
        application_network = self._application_network_plan(transport_plan=opening)
        for index, record in enumerate(prepared_records):
            state = record.state
            timing = record.timing
            phase_type = record.phase_type
            phase = record.phase
            action_time = record.action_time
            handle_close_time = record.handle_close_time
            previous_path = record.previous_path
            previous_client_path = record.previous_client_path
            previous_server_path = record.previous_server_path
            operation = application_batch.operations[index]
            handle = operation.handles[0] if operation.handles else None
            action = self.request.spec.operation
            result = self.outcome
            smb_fields = self._smb_platform_fields(share, server)
            common = dict(
                operation=action,
                purpose=self.request.spec.purpose,
                session_id=application_batch.session.session_id,
                tree_id=application_batch.tree.tree_id,
                share_ref=share.ref,
                share_name=share.name,
                result=result,
                requested_access=self._requested_access(),
                client_path=self._client_path(state.path, share),
                local_path=self._local_path(state.path),
                share_path=state.path,
                server_path=self.world.server_local_path(share, state.path),
                share_local_path=self.world.server_local_path(share, ""),
                file_id=state.file_id,
                content_version=state.version,
                local_file_id=self._local_file_identity(state).file_id,
                local_content_version=self._local_file_identity(state).version,
                handle_id=handle.handle_id if handle is not None else "",
                size_bytes=state.size_bytes,
                **smb_fields,
                encrypted=share.encryption == "required",
                audit=share.audit,
            )
            file_transfer = None
            if result == "success" and phase in {"read", "write"}:
                content = self._file_content_identity(state)
                file_transfer = FileTransferContext(
                    fuid=self._file_transfer_fuid(state, phase),
                    source="SMB",
                    filename=state.path,
                    analyzers=("MIME",),
                    mime_type=state.mime_type,
                    duration=timing.transfer_seconds,
                    local_orig=client_system is not None,
                    is_orig=phase == "write",
                    seen_bytes=state.size_bytes,
                    total_bytes=state.size_bytes,
                    content_identity=content.content_id,
                    md5=content.digests.md5,
                    sha1=content.digests.sha1,
                    sha256=content.digests.sha256,
                )
            operation_effect_plan = OwnedEffectOccurrencePlan(
                owner=EffectOccurrenceOwner.SMB_PROTOCOL_FILE_PHASE,
                kind=EffectOccurrenceKind.FILE,
                root_action_id=self.anchor.stable_id,
                instance_key=operation.operation_id,
                occurrence_count=3 if result == "success" else 1,
            )
            operation_events.append(
                self._phase_builder(
                    event_type="smb_file_open",
                    timestamp=operation.started_at,
                    network=application_network,
                    server=server,
                    client=client_system,
                    auth=AuthContext(
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
                    ),
                    process=client_process_context,
                    smb=SmbContext(phase="open", **common),
                    identity_plan=EventIdentityPlan(
                        actor=client_identity,
                        session=session_identity,
                    ),
                    effect_provenance=operation_effect_plan.provenance(0),
                )
            )
            if result == "success":
                operation_events.append(
                    self._phase_builder(
                        event_type=phase_type,
                        timestamp=action_time,
                        network=application_network,
                        server=server,
                        client=client_system,
                        auth=AuthContext(
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
                        ),
                        process=client_process_context,
                        smb=SmbContext(
                            phase=phase,
                            previous_path=previous_path,
                            previous_client_path=previous_client_path,
                            previous_server_path=previous_server_path,
                            **common,
                        ),
                        file_transfer=file_transfer,
                        identity_plan=EventIdentityPlan(
                            actor=client_identity,
                            session=session_identity,
                        ),
                        include_file_context=file_transfer is None,
                        effect_provenance=operation_effect_plan.provenance(1),
                    )
                )
                operation_events.append(
                    self._phase_builder(
                        event_type="smb_file_close",
                        timestamp=handle_close_time,
                        network=application_network,
                        server=server,
                        client=client_system,
                        auth=AuthContext(
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
                        ),
                        process=client_process_context,
                        smb=SmbContext(
                            phase="close",
                            previous_path=previous_path,
                            previous_client_path=previous_client_path,
                            previous_server_path=previous_server_path,
                            **common,
                        ),
                        identity_plan=EventIdentityPlan(
                            actor=client_identity,
                            session=session_identity,
                        ),
                        effect_provenance=operation_effect_plan.provenance(2),
                    )
                )
            operation_commons.append(common)
            operation_truth.append(
                {
                    "operation": action,
                    "share": share.ref,
                    "path": state.path,
                    "file_id": state.file_id,
                    "content_version": state.version,
                    "size_bytes": state.size_bytes,
                    "outcome": result,
                    "fuid": file_transfer.fuid if file_transfer is not None else None,
                }
            )

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
        owned_projection_plan = OwnedEffectOccurrencePlan(
            owner=EffectOccurrenceOwner.SMB_PROTOCOL_FILE_PHASE,
            kind=EffectOccurrenceKind.FILE,
            root_action_id=self.anchor.stable_id,
            instance_key=self.anchor.stable_id,
            occurrence_count=2,
        )
        process_create_event: OccurrenceBuilder | None = None
        client_session_identity = None
        if client_identity is not None:
            client_session_identity = self.executor.state_manager.get_session_identity(
                client_identity.logon_id
            )
            if client_session_identity is None:
                raise StateError("Persistent SMB client process lost its owning session")
        if (
            client_process_preparation.disposition == "materialize"
            and client_identity is not None
            and client_process_context is not None
            and client_system is not None
            and client_session_identity is not None
        ):
            parent_identity = self.executor.state_manager.get_process_identity(
                client_identity.hostname,
                client_identity.parent_pid,
            )
            process_create_event = OccurrenceBuilder(
                timestamp=client_identity.started_at,
                event_type="process_create",
                src_host=self.executor._build_host_context(client_system),
                auth=AuthContext(
                    username=client_identity.principal,
                    user_sid=self.executor._get_sid(client_identity.principal),
                    logon_id=client_identity.logon_id,
                    session_id=client_session_identity.session_id,
                    logon_type=client_process_preparation.logon_type,
                ),
                process=client_process_context,
                identity_plan=EventIdentityPlan(
                    subject=client_identity,
                    actor=parent_identity,
                    session=client_session_identity,
                ),
                lifecycle=ActionLifecycleContext(
                    group_id=client_identity.lifecycle_group_id,
                    canonical_start=client_identity.started_at,
                    phase="start",
                    parent_group_id=client_identity.parent_lifecycle_group_id or None,
                ),
            )
        transport_process = (
            client_process_context
            if client_process_preparation.transport_attribution == "process"
            else None
        )
        events: list[OccurrenceBuilder] = []
        if process_create_event is not None:
            events.append(process_create_event)
        events.extend(
            [
                OccurrenceBuilder(
                    timestamp=final_transaction.started_at,
                    event_type="connection",
                    src_host=(
                        self.executor._build_host_context(client_system)
                        if client_system is not None
                        else None
                    ),
                    dst_host=self.executor._build_host_context(server),
                    process=transport_process,
                    network=final_transaction,
                    identity_plan=EventIdentityPlan(
                        actor=(client_identity if transport_process is not None else None),
                        session=session_identity,
                    ),
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
                    process=client_process_context,
                    smb=SmbContext(phase="tree_connect", **operation_commons[0]),
                    identity_plan=EventIdentityPlan(
                        actor=client_identity,
                        session=session_identity,
                    ),
                    effect_provenance=owned_projection_plan.provenance(1),
                ),
            ]
        )
        for event in operation_events:
            event.network = application_network
            events.append(event)
        events.append(
            OccurrenceBuilder(
                timestamp=close_time,
                event_type="logoff",
                dst_host=self.executor._build_host_context(server),
                auth=auth,
                smb=SmbContext(phase="close", **operation_commons[0]),
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
            )
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

        source_carriers: list[PreparedActionCohortProjection] = []
        member_specs: list[tuple[PersistentSmbProjectionPhase, str, str, bytes]] = []
        transport_index = 1 if process_create_event is not None else 0
        source_specs = (
            *(
                ((process_create_event, PersistentSmbProjectionPhase.CLIENT_PROCESS),)
                if process_create_event is not None
                else ()
            ),
            (events[transport_index], PersistentSmbProjectionPhase.TRANSPORT),
            (events[transport_index + 1], PersistentSmbProjectionPhase.TYPE3_LOGON),
            *(
                (event, PersistentSmbProjectionPhase.TREE_OR_FILE)
                for event in events[transport_index + 2 : -1]
            ),
        )
        operation_digests: list[str] = []
        with self.executor.dispatcher.source_timing_planner.prepared_planning(
            action_capacity=source_timing_capacity
        ) as timing:
            for ordinal, (event, phase) in enumerate(source_specs):
                if phase is PersistentSmbProjectionPhase.CLIENT_PROCESS:
                    self.executor._plan_process_source_create_times(
                        event,
                        not_after=final_transaction.started_at,
                    )
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
                    application_batch.tree.tree_id,
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
                    application_batch.tree.tree_id.encode("utf-8"),
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
            logoff_event = events[-1]
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
        activity_result = SmbActivityResult(
            session_id=application_batch.session.session_id,
            tree_ids=(application_batch.tree.tree_id,),
            transport_uids=(opening.zeek_uid,),
            operations=tuple(operation_truth),
            completed_at=application_batch.closure.closed_at,
        )
        activity_capture = authority.capture_activity_result(
            action_id=self.anchor.stable_id,
            activity_result=activity_result,
            application_result=handoff.application_result,
            publication_binding_digest=publication_binding_digest,
        )
        source_shell = _PersistentSmbPreparedSource(
            opening=opening,
            lifecycle_receipt=lifecycle_receipt,
            lifecycle_binding=lifecycle_binding,
            traffic_binding=traffic_binding,
            final_transaction=final_transaction,
            final_observation_traffic=final_observation_traffic,
            state_plan=state_plan,
            source_carrier=source_reservation,
            source_projections=tuple(source_carriers),
            publication_binding_digest=publication_binding_digest,
            timing_preparation=timing,
            source_timing_capacity=source_timing_capacity,
            member_work=(),
            target_formats=target_formats,
            lifecycle_digest=lifecycle_digest,
            lifecycle_generation=lifecycle_generation,
            network_digest=network_digest,
            network_generation=network_generation,
            traffic_digest=traffic_digest,
            traffic_generation=traffic_generation,
            activity_capture=activity_capture,
        )
        source_building = _PersistentSmbSourceBuilding(
            source_shell=source_shell,
            member_specs=tuple(member_specs),
        )
        authority.bind_source_building(terminal_continuation, source_building)
        source_preparation = self._complete_persistent_smb_source_building(
            terminal_continuation,
        )
        member_work = source_preparation.member_work
        source_publication = self.executor.dispatcher.prepare_persistent_smb_source_publication(
            source_reservation,
            tuple(source_carriers),
            publication_binding_digest=publication_binding_digest,
        )
        self._acknowledge_persistent_smb_pin_install(pin_install)
        file_mutation = handoff.file_mutation

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

        certifications: list[PersistentSmbProjectionMemberCertification] = []
        expected_timing_receipt = None
        try:
            with timing.claimed_commit() as claimed:
                expected_timing_receipt = claimed.expected_receipt
                for member in member_work:
                    try:
                        certification = (
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
                    except BaseException as primary:
                        try:
                            certification = (
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
                        except BaseException as recovery_error:
                            primary.add_note(
                                "Persistent SMB member-certification retry also failed: "
                                f"{type(recovery_error).__name__}: {recovery_error}"
                            )
                            raise primary from recovery_error
                    certifications.append(certification)
                retained_certifications = tuple(certifications)
                authority.bind_source_certifications(
                    terminal_continuation,
                    retained_certifications,
                )
                claimed.certify_composite_commit(claimed.expected_receipt)
                claimed.commit_no_fail()
        except BaseException as primary:
            if not self._adopts_persistent_smb_timing_commit(
                timing,
                expected_timing_receipt,
            ):
                if not self._rollback_retained_persistent_smb_source_attempt(
                    terminal_continuation,
                    source_preparation,
                    action_binding_digest=terminal_binding_digest,
                    member_budget=member_budget,
                    primary=primary,
                ):
                    primary.add_note(
                        "Persistent SMB failed source certification retained cleanup-only work"
                    )
                raise
        commit_receipts: list[PersistentSmbProjectionMemberCommitReceipt] = []
        for certification in retained_certifications:
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
        if (
            self.executor._smb_channel_manager.session_view(application_batch.session.channel_id)
            is not None
        ):
            raise StateError("Persistent SMB application channel retained its exact session")
        if not self.executor.dispatcher.authenticates_published_persistent_smb_source_publication(
            source_publication,
            source_result,
        ):
            raise StateError("Persistent SMB published source result failed authentication")
        external_transport_uids = self._persistent_source_transport_uids(
            source_result,
            canonical_uid=application_batch.session.ground_truth_transport_uid,
        )
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
        authority.bind_source_published(
            terminal_continuation,
            source_result=source_result,
            file_mutation=file_mutation,
            finalization=finalization,
            external_transport_uids=external_transport_uids,
        )
        del lifecycle_binding
        return self._resume_persistent_windows_terminal(terminal_continuation)

    def _complete_persistent_smb_source_building(
        self,
        continuation: PersistentSmbTerminalContinuation,
    ) -> _PersistentSmbPreparedSource:
        """Append or recover every planned source member, then atomically promote it."""

        authority = self.executor._persistent_smb_terminal_continuations
        facts = authority.root_facts(continuation)
        building = facts.source_building
        projection_group = facts.projection_group
        if (
            facts.phase != "source_building"
            or type(building) is not _PersistentSmbSourceBuilding
            or type(projection_group) is not PersistentSmbProjectionGroupToken
            or building.source_shell.source_carrier is not facts.source_reservation
            or building.source_shell.source_timing_capacity is not facts.source_timing_capacity
        ):
            raise StateError("Persistent SMB source build changed its retained owners")
        dispatcher = self.executor.dispatcher
        for ordinal, (phase, operation_id, operation_digest, capsule) in enumerate(
            building.member_specs
        ):
            facts = authority.root_facts(continuation)
            if len(facts.source_build_members) > ordinal:
                continue
            try:
                member = dispatcher.prepare_persistent_smb_projection_member(
                    projection_group,
                    phase=phase,
                    operation_id=operation_id,
                    operation_binding_digest=operation_digest,
                    projection_capsule=capsule,
                    timing_preparation=building.source_shell.timing_preparation,
                )
            except BaseException as primary:
                try:
                    recovery = dispatcher.recover_inactive_persistent_smb_projection_member(
                        projection_group,
                        operation_id=operation_id,
                        operation_binding_digest=operation_digest,
                    )
                except BaseException as recovery_error:
                    primary.add_note(
                        "Persistent SMB source-member recovery also failed: "
                        f"{type(recovery_error).__name__}: {recovery_error}"
                    )
                    raise primary from recovery_error
                member = recovery.member_token
            try:
                authority.append_source_build_member(
                    continuation,
                    building,
                    member,
                    expected_ordinal=ordinal,
                )
            except BaseException:
                retained = authority.root_facts(continuation).source_build_members
                if len(retained) <= ordinal or retained[ordinal] is not member:
                    raise
        facts = authority.root_facts(continuation)
        members = facts.source_build_members
        if len(members) != len(building.member_specs):
            raise StateError("Persistent SMB source build did not retain every planned member")
        preparation = replace(building.source_shell, member_work=members)
        try:
            authority.complete_source_building(continuation, building, preparation)
        except BaseException:
            retained = authority.root_facts(continuation)
            if (
                retained.phase != "source_prepared"
                or retained.source_preparation is not preparation
            ):
                raise
        return preparation

    def _resume_persistent_smb_source_building(
        self,
        continuation: PersistentSmbTerminalContinuation,
    ) -> SmbActivityResult:
        """Resume a retained partial member build before any source mutation."""

        self._complete_persistent_smb_source_building(continuation)
        return self._resume_persistent_smb_source_prepared(continuation)

    def _resume_persistent_smb_source_prepared(
        self,
        continuation: PersistentSmbTerminalContinuation,
    ) -> SmbActivityResult:
        """Commit or adopt one fully reserved and retained source preparation."""

        authority = self.executor._persistent_smb_terminal_continuations
        facts = authority.root_facts(continuation)
        preparation = facts.source_preparation
        handoff = facts.handoff
        projection_group = facts.projection_group
        if (
            facts.phase != "source_prepared"
            or type(preparation) is not _PersistentSmbPreparedSource
            or type(handoff) is not PersistentSmbRootHandoff
            or type(projection_group) is not PersistentSmbProjectionGroupToken
            or preparation.lifecycle_receipt is not handoff.materialization.receipt
            or preparation.source_carrier is not facts.source_reservation
        ):
            raise StateError("Persistent SMB source retry changed its exact owners")
        source_publication = self.executor.dispatcher.prepare_persistent_smb_source_publication(
            preparation.source_carrier,
            preparation.source_projections,
            publication_binding_digest=preparation.publication_binding_digest,
        )
        self._acknowledge_persistent_smb_pin_install(handoff.pin_install_receipt)

        try:
            materialization = self.executor.state_manager.materialize_action_cohort(
                preparation.state_plan
            )
            finalization = materialization.smb_connection_finalization
        except BaseException as primary:
            finalization = self.executor.state_manager.recover_smb_connection_finalization(
                handoff.pin_install_receipt.pin
            )
            if finalization is None:
                try:
                    materialization = self.executor.state_manager.materialize_action_cohort(
                        preparation.state_plan
                    )
                except BaseException as recovery_error:
                    primary.add_note(
                        "Persistent SMB State-finalization retry also failed: "
                        f"{type(recovery_error).__name__}: {recovery_error}"
                    )
                    raise primary from recovery_error
                finalization = materialization.smb_connection_finalization
        file_mutation = handoff.file_mutation
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
            binding=preparation.traffic_binding,
            opening_transport=preparation.opening,
            opening_observations=handoff.observations,
            final_traffic=preparation.final_transaction.traffic,
            final_observation_traffic=preparation.final_observation_traffic,
            state_result=finalization,
        )
        if rebound != preparation.final_transaction or len(rebound_observations) != len(
            handoff.observations
        ):
            raise StateError("Persistent SMB traffic close disagrees with terminal State")

        certifications = facts.source_certifications
        timing = preparation.timing_preparation
        expected_timing_receipt = None
        try:
            if not certifications:
                built: list[PersistentSmbProjectionMemberCertification] = []
                with timing.claimed_commit() as claimed:
                    expected_timing_receipt = claimed.expected_receipt
                    for member in preparation.member_work:
                        try:
                            certification = (
                                self.executor.dispatcher.certify_persistent_smb_projection_member(
                                    member,
                                    target_formats=preparation.target_formats,
                                    lifecycle_binding_digest=preparation.lifecycle_digest,
                                    lifecycle_binding_generation=preparation.lifecycle_generation,
                                    network_binding_digest=preparation.network_digest,
                                    network_binding_generation=preparation.network_generation,
                                    traffic_binding_digest=preparation.traffic_digest,
                                    traffic_binding_generation=preparation.traffic_generation,
                                    expected_timing_receipt=claimed.expected_receipt,
                                )
                            )
                        except BaseException as primary:
                            try:
                                certification = self.executor.dispatcher.certify_persistent_smb_projection_member(
                                    member,
                                    target_formats=preparation.target_formats,
                                    lifecycle_binding_digest=preparation.lifecycle_digest,
                                    lifecycle_binding_generation=preparation.lifecycle_generation,
                                    network_binding_digest=preparation.network_digest,
                                    network_binding_generation=preparation.network_generation,
                                    traffic_binding_digest=preparation.traffic_digest,
                                    traffic_binding_generation=preparation.traffic_generation,
                                    expected_timing_receipt=claimed.expected_receipt,
                                )
                            except BaseException as recovery_error:
                                primary.add_note(
                                    "Persistent SMB member-certification retry also failed: "
                                    f"{type(recovery_error).__name__}: {recovery_error}"
                                )
                                raise primary from recovery_error
                        built.append(certification)
                    certifications = tuple(built)
                    authority.bind_source_certifications(continuation, certifications)
                    claimed.certify_composite_commit(claimed.expected_receipt)
                    claimed.commit_no_fail()
            elif not timing.committed:
                with timing.claimed_commit() as claimed:
                    expected_timing_receipt = claimed.expected_receipt
                    claimed.certify_composite_commit(claimed.expected_receipt)
                    claimed.commit_no_fail()
        except BaseException as primary:
            if not self._adopts_persistent_smb_timing_commit(
                timing,
                expected_timing_receipt,
            ):
                if not self._rollback_retained_persistent_smb_source_attempt(
                    continuation,
                    preparation,
                    action_binding_digest=facts.action_binding_digest,
                    member_budget=facts.member_budget,
                    primary=primary,
                ):
                    primary.add_note(
                        "Persistent SMB retried source certification retained cleanup-only work"
                    )
                raise

        commit_receipts: list[PersistentSmbProjectionMemberCommitReceipt] = []
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
        application_batch = handoff.application_result.result
        if (
            self.executor._smb_channel_manager.session_view(application_batch.session.channel_id)
            is not None
        ):
            raise StateError("Persistent SMB application channel retained its exact session")
        if not self.executor.dispatcher.authenticates_published_persistent_smb_source_publication(
            source_publication,
            source_result,
        ):
            raise StateError("Persistent SMB published source result failed authentication")
        external_transport_uids = self._persistent_source_transport_uids(
            source_result,
            canonical_uid=application_batch.session.ground_truth_transport_uid,
        )
        authority.bind_source_published(
            continuation,
            source_result=source_result,
            file_mutation=file_mutation,
            finalization=finalization,
            external_transport_uids=external_transport_uids,
        )
        return self._resume_persistent_windows_terminal(continuation)

    def _cancel_persistent_smb_projection_members(
        self,
        *,
        projection_group: PersistentSmbProjectionGroupToken,
        member_specs: tuple[
            tuple[PersistentSmbProjectionPhase, str, str, bytes],
            ...,
        ],
        member_work: tuple[PersistentSmbProjectionMemberToken, ...],
        primary: BaseException,
    ) -> bool:
        """Cancel or adopt every exact uncommitted member, including one lost append return."""

        dispatcher = self.executor.dispatcher
        candidates: dict[str, PersistentSmbProjectionMemberToken] = {
            member.operation_id: member for member in member_work
        }
        recovery_failed = False
        for _phase, operation_id, operation_binding_digest, _capsule in member_specs:
            if operation_id in candidates:
                continue
            try:
                recovery = dispatcher.recover_inactive_persistent_smb_projection_member(
                    projection_group,
                    operation_id=operation_id,
                    operation_binding_digest=operation_binding_digest,
                )
            except EventContractError:
                continue
            except BaseException as recovery_error:
                primary.add_note(
                    "Persistent SMB inactive-member recovery also failed: "
                    f"{type(recovery_error).__name__}: {recovery_error}"
                )
                recovery_failed = True
                continue
            candidates[operation_id] = recovery.member_token

        cleanup_failed = recovery_failed
        for member in reversed(tuple(candidates.values())):
            last_error: BaseException | None = None
            for _attempt in range(2):
                if not dispatcher.authenticates_cancellable_persistent_smb_projection_member(
                    member
                ):
                    break
                try:
                    dispatcher.cancel_persistent_smb_projection_member(member)
                except BaseException as cleanup_error:
                    last_error = cleanup_error
            if dispatcher.authenticates_cancellable_persistent_smb_projection_member(member):
                cleanup_error = last_error or StateError(
                    "Persistent SMB uncommitted member retained its exact owner"
                )
                primary.add_note(
                    "Persistent SMB member cancellation also failed: "
                    f"{type(cleanup_error).__name__}: {cleanup_error}"
                )
                cleanup_failed = True
        return not cleanup_failed

    def _source_timing_capacity_is_neutral(
        self,
        reservation: SourceTimingActionCapacityReservation,
        *,
        action_binding_digest: str,
        member_budget: int,
    ) -> bool:
        """Authenticate the exact reusable pre-root SourceTiming quota."""

        return self.executor.dispatcher.source_timing_planner.authenticates_neutral_action_capacity(
            reservation,
            action_id=self.anchor.stable_id,
            action_binding_digest=action_binding_digest,
            detached_binding_budget=member_budget,
        )

    def _adopts_persistent_smb_timing_commit(
        self,
        timing: SourceTimingPreparation,
        expected_receipt: object | None,
    ) -> bool:
        """Adopt only the exact retained receipt after a committed return is lost."""

        planner = self.executor.dispatcher.source_timing_planner
        receipt = timing.receipt
        return bool(
            receipt is not None
            and receipt is expected_receipt
            and planner.authenticates_preparation(timing)
            and planner.authenticates_preparation_receipt(receipt)
        )

    def _rollback_unretained_persistent_smb_source_attempt(
        self,
        *,
        projection_group: PersistentSmbProjectionGroupToken,
        timing: SourceTimingPreparation,
        source_projections: tuple[PreparedActionCohortProjection, ...],
        member_specs: tuple[
            tuple[PersistentSmbProjectionPhase, str, str, bytes],
            ...,
        ],
        member_work: tuple[PersistentSmbProjectionMemberToken, ...],
        source_timing_capacity: SourceTimingActionCapacityReservation,
        action_binding_digest: str,
        member_budget: int,
        primary: BaseException,
    ) -> bool:
        """Neutralize a partial pre-certification attempt so its committed root can retry."""

        if not self._cancel_persistent_smb_projection_members(
            projection_group=projection_group,
            member_specs=member_specs,
            member_work=member_work,
            primary=primary,
        ):
            return False
        dispatcher = self.executor.dispatcher
        if source_projections:
            first_projection = source_projections[0]
            last_error: BaseException | None = None
            for _attempt in range(2):
                if not dispatcher.authenticates_prepared_action_cohort_projection(first_projection):
                    break
                try:
                    dispatcher.cancel_prepared_action_cohort_projection(first_projection)
                except BaseException as cleanup_error:
                    last_error = cleanup_error
            if dispatcher.authenticates_prepared_action_cohort_projection(first_projection):
                cleanup_error = last_error or StateError(
                    "Persistent SMB source projection retained its timing group"
                )
                primary.add_note(
                    "Persistent SMB source-projection rollback also failed: "
                    f"{type(cleanup_error).__name__}: {cleanup_error}"
                )
                return False
        for _attempt in range(2):
            if self._source_timing_capacity_is_neutral(
                source_timing_capacity,
                action_binding_digest=action_binding_digest,
                member_budget=member_budget,
            ):
                return True
            try:
                timing.cancel()
            except BaseException as cleanup_error:
                primary.add_note(
                    "Persistent SMB source-timing rollback also failed: "
                    f"{type(cleanup_error).__name__}: {cleanup_error}"
                )
        return self._source_timing_capacity_is_neutral(
            source_timing_capacity,
            action_binding_digest=action_binding_digest,
            member_budget=member_budget,
        )

    def _rollback_retained_persistent_smb_source_attempt(
        self,
        continuation: PersistentSmbTerminalContinuation,
        preparation: _PersistentSmbPreparedSource,
        *,
        action_binding_digest: str,
        member_budget: int,
        primary: BaseException,
    ) -> bool:
        """Rollback a source-prepared attempt while preserving its pre-root capacity shell."""

        member_specs = tuple(
            (
                member.phase,
                member.operation_id,
                member.operation_binding_digest,
                b"",
            )
            for member in preparation.member_work
        )
        facts = self.executor._persistent_smb_terminal_continuations.root_facts(continuation)
        projection_group = facts.projection_group
        if type(projection_group) is not PersistentSmbProjectionGroupToken:
            primary.add_note("Persistent SMB source rollback lost its exact projection group")
            return False
        if not self._cancel_persistent_smb_projection_members(
            projection_group=projection_group,
            member_specs=member_specs,
            member_work=preparation.member_work,
            primary=primary,
        ):
            return False

        dispatcher = self.executor.dispatcher
        last_error: BaseException | None = None
        for _attempt in range(2):
            if not dispatcher.authenticates_prepared_persistent_smb_source_publication(
                preparation.source_carrier
            ):
                break
            try:
                dispatcher.rollback_prepared_persistent_smb_source_publication(
                    preparation.source_carrier
                )
            except BaseException as cleanup_error:
                last_error = cleanup_error
        if dispatcher.authenticates_prepared_persistent_smb_source_publication(
            preparation.source_carrier
        ):
            cleanup_error = last_error or StateError(
                "Persistent SMB prepared source retained frozen uncommitted rows"
            )
            primary.add_note(
                "Persistent SMB prepared-source rollback also failed: "
                f"{type(cleanup_error).__name__}: {cleanup_error}"
            )
            return False
        if not dispatcher.authenticates_reserved_persistent_smb_source_publication(
            preparation.source_carrier
        ):
            primary.add_note("Persistent SMB source rollback lost its pre-root reservation")
            return False

        for _attempt in range(2):
            if self._source_timing_capacity_is_neutral(
                preparation.source_timing_capacity,
                action_binding_digest=action_binding_digest,
                member_budget=member_budget,
            ):
                break
            try:
                preparation.timing_preparation.cancel()
            except BaseException as cleanup_error:
                primary.add_note(
                    "Persistent SMB retained source-timing rollback also failed: "
                    f"{type(cleanup_error).__name__}: {cleanup_error}"
                )
        if not self._source_timing_capacity_is_neutral(
            preparation.source_timing_capacity,
            action_binding_digest=action_binding_digest,
            member_budget=member_budget,
        ):
            return False
        try:
            self.executor._persistent_smb_terminal_continuations.rollback_source_prepared(
                continuation,
                preparation,
            )
        except BaseException as cleanup_error:
            primary.add_note(
                "Persistent SMB continuation source rollback also failed: "
                f"{type(cleanup_error).__name__}: {cleanup_error}"
            )
            return False
        return True

    def _acknowledge_persistent_smb_pin_install(
        self,
        receipt: SmbConnectionPinInstallReceipt,
    ) -> None:
        """Adopt one exact install acknowledgement across a lost return."""

        state_manager = self.executor.state_manager
        if state_manager.authenticates_acknowledged_smb_connection_pin_install(receipt):
            return
        if not state_manager.authenticates_smb_connection_pin_install_receipt(receipt):
            raise StateError("Persistent SMB pin install is neither pending nor acknowledged")
        try:
            acknowledged = state_manager.acknowledge_smb_connection_pin_install(receipt)
        except BaseException as primary:
            if state_manager.authenticates_acknowledged_smb_connection_pin_install(receipt):
                return
            try:
                acknowledged = state_manager.acknowledge_smb_connection_pin_install(receipt)
            except BaseException as recovery_error:
                if state_manager.authenticates_acknowledged_smb_connection_pin_install(receipt):
                    return
                primary.add_note(
                    "Persistent SMB pin-install acknowledgement retry also failed: "
                    f"{type(recovery_error).__name__}: {recovery_error}"
                )
                raise primary from recovery_error
        if (
            not acknowledged
            or not state_manager.authenticates_acknowledged_smb_connection_pin_install(receipt)
        ):
            raise StateError("Persistent SMB pin-install acknowledgement lost exact proof")

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

    def _release_persistent_smb_source_timing_capacity(
        self,
        facts: _PersistentSmbTerminalFacts,
    ) -> None:
        """Release or adopt the exact pre-root timing quota after all members retire."""

        capacity = facts.source_timing_capacity
        planner = self.executor.dispatcher.source_timing_planner
        if (
            type(capacity) is not SourceTimingActionCapacityReservation
            or facts.action_id != self.anchor.stable_id
            or type(facts.member_budget) is not int
            or facts.member_budget < 1
        ):
            raise StateError("Persistent SMB source-timing terminal facts are malformed")

        def recover() -> SourceTimingActionCapacityReservation | None:
            return planner.recover_action_capacity(
                action_id=facts.action_id,
                action_binding_digest=facts.action_binding_digest,
                detached_binding_budget=facts.member_budget,
            )

        def authenticates() -> bool:
            return planner.authenticates_action_capacity(
                capacity,
                action_id=facts.action_id,
                action_binding_digest=facts.action_binding_digest,
                detached_binding_budget=facts.member_budget,
            )

        if not authenticates():
            if recover() is None:
                return
            raise StateError("Persistent SMB source-timing quota lost its exact capability")
        try:
            planner.release_committed_action_capacity(capacity)
        except BaseException as primary:
            retained = recover()
            if retained is None:
                return
            if retained is not capacity or not authenticates():
                raise StateError(
                    "Persistent SMB source-timing quota changed during release"
                ) from primary
            try:
                planner.release_committed_action_capacity(capacity)
            except BaseException as recovery_error:
                if recover() is None:
                    return
                primary.add_note(
                    "Persistent SMB source-timing release retry also failed: "
                    f"{type(recovery_error).__name__}: {recovery_error}"
                )
                raise primary from recovery_error
        if recover() is not None:
            raise StateError("Persistent SMB source-timing release retained its action quota")

    def _consume_persistent_smb_transport_terminal(
        self,
        facts: _PersistentSmbTerminalFacts,
    ) -> None:
        """Retire the exact deferred TCP projection after all source work is durable."""

        handoff = facts.handoff
        if type(handoff) is not PersistentSmbRootHandoff:
            raise StateError("Persistent SMB terminal continuation lost its root handoff")
        dispatcher = self.executor.dispatcher
        receipt = dispatcher.consume_persistent_smb_prepared_transport(
            handoff.prepared_dispatch,
            lifecycle_binding=handoff.lifecycle_binding,
        )
        if not dispatcher.authenticates_persistent_smb_prepared_transport_consumption(
            handoff.prepared_dispatch,
            receipt,
        ):
            raise StateError("Persistent SMB deferred transport consumption was not certified")

    def _acknowledge_persistent_smb_application_terminal(
        self,
        facts: _PersistentSmbTerminalFacts,
    ) -> None:
        """Adopt the exact common-channel acknowledgement across a lost return."""

        handoff = facts.handoff
        if type(handoff) is not PersistentSmbRootHandoff:
            raise StateError("Persistent SMB terminal continuation lost its root handoff")
        registry = self.executor._smb_channel_manager.application_registry
        token = handoff.application_token.application_token
        expected = handoff.application_result.application
        receipt = expected.receipt
        if receipt is None:
            raise StateError("Persistent SMB application result lost its common receipt")
        retained = registry.recover_committed_admission(token)
        if retained is None:
            if registry.authenticates_admission_receipt(receipt):
                raise StateError("Persistent SMB common result lost its retained owner")
            return
        if retained is not expected:
            raise StateError("Persistent SMB common recovery changed its exact result")
        try:
            acknowledged = registry.acknowledge_committed_admission(token, expected)
        except BaseException as primary:
            retained = registry.recover_committed_admission(token)
            if retained is None and not registry.authenticates_admission_receipt(receipt):
                return
            try:
                acknowledged = registry.acknowledge_committed_admission(token, expected)
            except BaseException as recovery_error:
                if registry.recover_committed_admission(
                    token
                ) is None and not registry.authenticates_admission_receipt(receipt):
                    return
                primary.add_note(
                    "Persistent SMB common acknowledgement retry also failed: "
                    f"{type(recovery_error).__name__}: {recovery_error}"
                )
                raise primary from recovery_error
            if not acknowledged:
                raise primary
        if (
            not acknowledged
            or registry.recover_committed_admission(token) is not None
            or registry.authenticates_admission_receipt(receipt)
        ):
            raise StateError("Persistent SMB common acknowledgement did not retire its owner")

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
                    self._consume_persistent_smb_transport_terminal(facts)
                    authority.advance(continuation, expected_cursor=0)
                    continue
                if facts.cursor == 1:
                    self._acknowledge_persistent_smb_application_terminal(facts)
                    authority.advance(continuation, expected_cursor=1)
                    continue
                if facts.cursor == 2:
                    self._acknowledge_persistent_smb_source_terminal(facts)
                    self._release_persistent_smb_source_timing_capacity(facts)
                    authority.advance(continuation, expected_cursor=2)
                    continue
                if facts.cursor == 3:
                    self._acknowledge_persistent_smb_file_terminal(facts)
                    authority.advance(continuation, expected_cursor=3)
                    continue
                if facts.cursor == 4:
                    self._acknowledge_persistent_smb_connection_terminal(facts)
                    authority.advance(continuation, expected_cursor=4)
                    continue
                if facts.cursor == 5:
                    self.executor.dispatcher.release_acknowledged_persistent_smb_source_publication_no_fail(
                        facts.source_carrier,
                        facts.source_result,
                    )
                    authority.advance(continuation, expected_cursor=5)
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

    @staticmethod
    def _persistent_source_transport_uids(
        source_result: PersistentSmbSourcePublicationResult,
        *,
        canonical_uid: str,
    ) -> tuple[str, ...]:
        """Return the exact emitted transport UID frozen by persistent source publication."""

        if type(source_result) is not PersistentSmbSourcePublicationResult:
            raise EventContractError("Persistent SMB transport identity requires an exact result")
        if type(canonical_uid) is not str or not canonical_uid:
            raise EventContractError("Persistent SMB canonical transport UID is invalid")
        operation_ids = object.__getattribute__(source_result, "member_operation_ids")
        projection_identifiers = object.__getattribute__(source_result, "projection_identifiers")
        if (
            type(operation_ids) is not tuple
            or not operation_ids
            or type(projection_identifiers) is not tuple
            or not projection_identifiers
        ):
            raise EventContractError("Persistent SMB transport projection has an invalid shape")
        projected_operation_ids = tuple(
            operation_id
            for operation_id in operation_ids
            if type(operation_id) is str
            and not operation_id.endswith(f":{PersistentSmbProjectionPhase.TREE_DISCONNECT.value}")
        )
        if len(projected_operation_ids) != len(projection_identifiers):
            raise EventContractError("Persistent SMB transport projection has an invalid shape")
        transport_indexes = [
            index
            for index, operation_id in enumerate(projected_operation_ids)
            if operation_id.endswith(f":{PersistentSmbProjectionPhase.TRANSPORT.value}")
        ]
        if len(transport_indexes) != 1:
            raise EventContractError("Persistent SMB transport projection is ambiguous")
        transport_index = transport_indexes[0]
        if type(projection_identifiers[transport_index]) is not tuple:
            raise EventContractError("Persistent SMB transport projection has an invalid shape")

        zeek_uids: list[str] = []
        for item in projection_identifiers[transport_index]:
            if (
                type(item) is not tuple
                or len(item) != 2
                or type(item[0]) is not str
                or type(item[1]) is not str
                or not item[0]
            ):
                raise EventContractError(
                    "Persistent SMB transport projection has a malformed identifier"
                )
            if item[0] == "zeek_conn":
                zeek_uids.append(item[1])
        if len(zeek_uids) > 1:
            raise EventContractError("Persistent SMB transport projection is ambiguous")
        # The dispatcher freezes one blank ID when a planned Zeek projection is suppressed.
        return (zeek_uids[0] if zeek_uids and zeek_uids[0] else canonical_uid,)

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
        preparations: list[SmbActivityPreparation] = []
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
            preparations.append(self._prepare_child(copy_spec, selected, offset_ms=0))
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
            read_preparation = self._prepare_child(read_spec, selected, offset_ms=0)
            preparations.append(read_preparation)
            if read_preparation.outcome == "success":
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
                        update={
                            "path": destination.path if len(selected) == 1 else None,
                            "directory": None,
                        }
                    ),
                    outcome=self._leg_outcome(destination, operation="create"),
                    path_style=spec.path_style,
                    mapping=self._mapping_for_share(destination.share),
                    client=spec.client,
                    client_access=spec.client_access,
                    auth_protocol=spec.auth_protocol,
                    smb_principal=spec.smb_principal,
                )
                preparations.append(
                    self._prepare_child(create_spec, destination_files, offset_ms=25)
                )

        if spec.operation == "move" and all(
            preparation.outcome == "success" for preparation in preparations
        ):
            completed_at = max(preparation.closed_at for preparation in preparations)
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
            preparations.append(
                self._prepare_child(
                    delete_spec,
                    selected,
                    offset_ms=0,
                    execution_time=delete_time,
                )
            )
        self._validate_composite_preparations(preparations)
        results = [self._execute_prepared_child(preparation) for preparation in preparations]
        return self._combine_results(results)

    def _prepare_child(
        self,
        spec: SmbActivityEventSpec,
        files: tuple[CompiledStorageFile, ...],
        *,
        offset_ms: int,
        execution_time: datetime | None = None,
    ) -> SmbActivityPreparation:
        """Freeze one physical child leg without mutating shared runtime state."""

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
        return SmbActivityActionBundle(self.executor, child_request).prepare()

    def _validate_composite_preparations(
        self,
        preparations: list[SmbActivityPreparation],
    ) -> None:
        """Validate every child before the first composite leg can mutate state."""

        if not preparations:
            raise StateError("Composite SMB activity produced no physical preparations")
        for preparation in preparations:
            child = SmbActivityActionBundle(self.executor, preparation.request)
            child._adopt_preparation(preparation)
            child._validate_preparation_prestate(preparation)
            child._validate_preparation_window(preparation)

    def _execute_prepared_child(
        self,
        preparation: SmbActivityPreparation,
    ) -> SmbActivityResult:
        """Execute one already validated physical child leg exactly once."""

        return SmbActivityActionBundle(self.executor, preparation.request).execute(preparation)

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
        if destination.directory is not None:
            return f"{destination.directory}\\{source_path}".strip("\\")
        return f"Incoming\\{ntpath.basename(source_path)}"

    def _select_client_file_set(
        self,
        location: SmbClientLocation,
    ) -> tuple[CompiledStorageFile, ...]:
        if location.file_set is None:
            return ()
        candidates = self.world.select_file_set(
            location.file_set,
            file_ref=location.file_ref,
            selector=location.selector,
        )
        candidates = tuple(
            file for file in candidates if self.executor.state_manager.smb_file_is_available(file)
        )
        return self._apply_batch(candidates)

    def _apply_batch(
        self,
        candidates: tuple[CompiledStorageFile, ...],
    ) -> tuple[CompiledStorageFile, ...]:
        batch = self.request.spec.batch
        if batch is None:
            return candidates[:1]
        if batch.count is not None:
            count = batch.count
        elif batch.fraction is not None:
            count = max(1, round(len(candidates) * batch.fraction))
        else:
            count = len(candidates)
        if count > _MAX_PERSISTENT_SMB_OPERATIONS:
            raise ValueError("Persistent SMB production requires 1..64 file operations")
        return tuple(candidates[:count])

    def _client_upload_destination_file(
        self,
        source: CompiledStorageFile,
        destination: SmbShareLocation,
    ) -> CompiledStorageFile:
        path = self._destination_path(destination, source.path)
        return source.model_copy(
            update={
                "file_id": stable_uuid(
                    "smb-client-copy-destination",
                    self.anchor.stable_id,
                    destination.share,
                    path,
                ),
                "share": destination.share,
                "path": path,
                "seed_ref": source.seed_ref or source.file_id,
            }
        )

    def _local_file_identity(self, remote_file: Any) -> Any:
        return self._client_source_by_destination.get(
            remote_file.file_id,
            self._client_source_by_destination_path.get(remote_file.path.casefold(), remote_file),
        )

    def _file_content_identity(self, remote_file: Any) -> FileContentIdentity:
        """Return path-independent content identity, preserving client-copy lineage."""

        source = self._local_file_identity(remote_file)
        compiled = self.world.files_by_id.get(source.file_id)
        seed_ref = (
            compiled.seed_ref
            if compiled is not None and compiled.seed_ref is not None
            else source.file_id
        )
        return FileContentIdentity(
            file_object_id=source.file_id,
            version=source.version,
            size_bytes=source.size_bytes,
            mime_type=source.mime_type,
            seed_ref=seed_ref,
        )

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
            if location.file_ref is not None or location.path is not None:
                return candidates
            if not candidates:
                return ()
            index = _stable_seed(
                "smb-generic-file-selection:"
                f"{self.anchor.stable_id}:{location.share}:{self.request.spec.operation}"
            ) % len(candidates)
            return (candidates[index],)
        return self._apply_batch(candidates)

    def _create_placeholder(
        self,
        location: SmbShareLocation,
        share: CompiledStorageShare,
    ) -> CompiledStorageFile:
        source = self.request.spec.source
        if location.path is not None:
            path = location.path
        elif (
            location.directory is not None and isinstance(source, SmbClientLocation) and source.path
        ):
            path = self._destination_path(location, ntpath.basename(source.path.rstrip("\\/")))
        else:
            path = f"Incoming\\{self.request.actor.username}-{self.request.time:%Y%m%d-%H%M%S}.dat"
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
        lease: SmbOperationLease,
        journal: SmbFileMutationJournal,
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
        handle: SmbHandleView | None = None
        conflict_handle: SmbHandleView | None = None
        handle_closed = False
        conflict_closed = False
        operation_finalized = False
        try:
            if result in {"access_denied", "not_found"}:
                pass
            elif result == "sharing_violation":
                state = self.executor.state_manager.touch_smb_file(file, journal=journal)
                conflict_handle = self.executor._smb_channel_manager.open_handle(
                    lease,
                    file_id=state.file_id,
                    content_version=state.version,
                    access="read",
                    opened_at=timestamp,
                    deny_write=True,
                    role="sharing-conflict",
                )
            elif action == "create" or creates_remote_copy:
                state = self.executor.state_manager.create_smb_file(
                    share=share.ref,
                    path=file.path,
                    size_bytes=file.size_bytes,
                    mime_type=file.mime_type,
                    timestamp=timestamp,
                    tags=file.tags,
                    journal=journal,
                )
                if result == "success" and action == "move" and creates_remote_copy:
                    source_file = self._client_source_by_destination.get(file.file_id)
                    if source_file is not None:
                        source_state = self.executor.state_manager.touch_smb_file(
                            source_file,
                            journal=journal,
                        )
                        self.executor.state_manager.delete_smb_file(
                            source_state.file_id,
                            journal=journal,
                        )
                handle = self.executor._smb_channel_manager.open_handle(
                    lease,
                    file_id=state.file_id,
                    content_version=state.version,
                    access="write",
                    opened_at=timestamp,
                )
            else:
                state = self.executor.state_manager.touch_smb_file(file, journal=journal)
                access = "read" if action in {"browse", "read", "copy"} else "write"
                handle = self.executor._smb_channel_manager.open_handle(
                    lease,
                    file_id=state.file_id,
                    content_version=state.version,
                    access=access,
                    opened_at=timestamp,
                )
            path = state.path
            client_path = self._client_path(path, share)
            common = dict(
                operation=action,
                purpose=spec.purpose,
                session_id=lease.session_id,
                tree_id=lease.tree_id,
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
                local_file_id=self._local_file_identity(state).file_id,
                local_content_version=self._local_file_identity(state).version,
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
                    self._close_application_handle_exactly_once(
                        conflict_handle,
                        lease,
                        close_time=min(
                            lease.ended_at,
                            timestamp + timedelta(milliseconds=5),
                        ),
                    )
                    conflict_closed = True
                self._finalize_application_operation_exactly_once(lease)
                operation_finalized = True
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
                    size_bytes=self._updated_size(file, operation_index),
                    journal=journal,
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
                    journal=journal,
                )
                common["share_path"] = state.path
                common["client_path"] = self._client_path(state.path, share)
                common["server_path"] = self.world.server_local_path(share, state.path)
                common["content_version"] = state.version
            elif action == "delete":
                state = self.executor.state_manager.delete_smb_file(
                    state.file_id,
                    journal=journal,
                )
            timing = self._operation_timing(
                file,
                operation_index,
                size_bytes=state.size_bytes,
            )
            file_transfer = None
            if phase in {"read", "write"}:
                content = self._file_content_identity(state)
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
                    content_identity=content.content_id,
                    md5=content.digests.md5,
                    sha1=content.digests.sha1,
                    sha256=content.digests.sha256,
                )
            action_time = timestamp + timedelta(
                seconds=timing.setup_seconds + timing.jitter_seconds
            )
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
            close_time = min(
                lease.ended_at,
                action_time
                + timedelta(seconds=timing.transfer_seconds + timing.close_delay_seconds),
            )
            if handle is not None:
                self._close_application_handle_exactly_once(
                    handle,
                    lease,
                    close_time=close_time,
                )
                handle_closed = True
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
            self._finalize_application_operation_exactly_once(lease)
            operation_finalized = True
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
        except BaseException as primary:
            for retained_handle, already_closed in (
                (handle, handle_closed),
                (conflict_handle, conflict_closed),
            ):
                if retained_handle is None or already_closed:
                    continue
                try:
                    self._close_application_handle_exactly_once(
                        retained_handle,
                        lease,
                        close_time=lease.ended_at,
                    )
                except BaseException as cleanup_error:
                    primary.add_note(
                        "SMB handle cleanup also failed: "
                        f"{type(cleanup_error).__name__}: {cleanup_error}"
                    )
            if not operation_finalized:
                try:
                    self._finalize_application_operation_exactly_once(lease)
                except BaseException as cleanup_error:
                    primary.add_note(
                        "SMB operation cleanup also failed: "
                        f"{type(cleanup_error).__name__}: {cleanup_error}"
                    )
            raise

    def _close_application_handle_exactly_once(
        self,
        handle: SmbHandleView,
        lease: SmbOperationLease,
        *,
        close_time: datetime,
    ) -> None:
        """Close one manager-owned handle across fail-before or lost-return faults."""

        manager = self.executor._smb_channel_manager
        try:
            closed = manager.close_handle(handle, lease, closed_at=close_time)
        except BaseException as primary:
            try:
                closed = manager.close_handle(handle, lease, closed_at=close_time)
            except BaseException as recovery_error:
                primary.add_note(
                    "SMB handle-close retry also failed: "
                    f"{type(recovery_error).__name__}: {recovery_error}"
                )
                raise primary from recovery_error
            if not closed:
                snapshot = manager.channel_snapshot(lease.channel_id)
                if snapshot is None or snapshot.closed_at is not None:
                    raise primary from None
                return
        if not closed:
            raise StateError("SMB application handle did not close exactly once")

    def _finalize_application_operation_exactly_once(self, lease: SmbOperationLease) -> None:
        """Finalize one manager lease across fail-before or lost-return faults."""

        manager = self.executor._smb_channel_manager
        try:
            finalized = manager.finalize_operation(lease)
        except BaseException as primary:
            try:
                finalized = manager.finalize_operation(lease)
            except BaseException as recovery_error:
                primary.add_note(
                    "SMB operation-finalization retry also failed: "
                    f"{type(recovery_error).__name__}: {recovery_error}"
                )
                raise primary from recovery_error
            if not finalized:
                snapshot = manager.channel_snapshot(lease.channel_id)
                if (
                    snapshot is None
                    or snapshot.active_operations != 0
                    or snapshot.completed_operations < lease.ordinal + 1
                ):
                    raise primary from None
                return
        if not finalized:
            raise StateError("SMB application operation did not finalize exactly once")

    def _close_application_session_exactly_once(
        self,
        channel_id: str,
        *,
        close_time: datetime,
    ) -> None:
        """Close one manager-owned SMB session across an ambiguous return."""

        manager = self.executor._smb_channel_manager
        try:
            closure = manager.close_session(
                channel_id,
                closed_at=close_time,
                reason="logoff",
            )
        except BaseException as primary:
            try:
                closure = manager.close_session(
                    channel_id,
                    closed_at=close_time,
                    reason="logoff",
                )
            except BaseException as recovery_error:
                primary.add_note(
                    "SMB session-close retry also failed: "
                    f"{type(recovery_error).__name__}: {recovery_error}"
                )
                raise primary from recovery_error
            if closure is None:
                snapshot = manager.channel_snapshot(channel_id)
                if (
                    snapshot is None
                    or snapshot.closed_at != close_time
                    or snapshot.close_reason != "logoff"
                    or snapshot.active_operations != 0
                ):
                    raise primary from None
                return
        if closure is None:
            snapshot = manager.channel_snapshot(channel_id)
            if (
                snapshot is None
                or snapshot.closed_at != close_time
                or snapshot.close_reason != "logoff"
                or snapshot.active_operations != 0
            ):
                raise StateError("SMB application session close lost its terminal state")

    def _close_application_session_after_failure(
        self,
        channel_id: str,
        *,
        close_time: datetime,
        primary: BaseException,
    ) -> None:
        """Best-effort retire one application channel while preserving the primary error."""

        if self.executor._smb_channel_manager.session_view(channel_id) is None:
            return
        try:
            self._close_application_session_exactly_once(channel_id, close_time=close_time)
        except BaseException as cleanup_error:
            primary.add_note(
                "SMB application-session cleanup also failed: "
                f"{type(cleanup_error).__name__}: {cleanup_error}"
            )

    def _commit_and_acknowledge_file_journal(
        self,
        journal: SmbFileMutationJournal,
    ) -> SmbFileMutationCommitResult:
        """Commit one exact action journal and retire its recoverable terminal proof."""

        state_manager = self.executor.state_manager
        try:
            result = state_manager.commit_smb_file_mutation_journal(journal)
        except BaseException as primary:
            result = state_manager.recover_smb_file_mutation_commit(journal)
            if result is None:
                try:
                    result = state_manager.commit_smb_file_mutation_journal(journal)
                except BaseException as recovery_error:
                    primary.add_note(
                        "SMB file-mutation retry also failed: "
                        f"{type(recovery_error).__name__}: {recovery_error}"
                    )
                    raise primary from recovery_error
        if not state_manager.authenticates_smb_file_mutation_commit_receipt(result.receipt):
            raise StateError("SMB file mutation terminal result failed authentication")
        try:
            acknowledged = state_manager.acknowledge_smb_file_mutation_commit(result)
        except BaseException as primary:
            if not state_manager.authenticates_smb_file_mutation_commit_receipt(result.receipt):
                return result
            try:
                acknowledged = state_manager.acknowledge_smb_file_mutation_commit(result)
            except BaseException as recovery_error:
                if not state_manager.authenticates_smb_file_mutation_commit_receipt(result.receipt):
                    return result
                primary.add_note(
                    "SMB file-mutation acknowledgement retry also failed: "
                    f"{type(recovery_error).__name__}: {recovery_error}"
                )
                raise primary from recovery_error
        if acknowledged is not True or state_manager.authenticates_smb_file_mutation_commit_receipt(
            result.receipt
        ):
            raise StateError("SMB file mutation acknowledgement retained terminal authority")
        return result

    def _cancel_file_journal_after_failure(
        self,
        journal: SmbFileMutationJournal,
        primary: BaseException,
    ) -> bool:
        """Rollback or adopt one exact journal cancellation without replacing the primary."""

        state_manager = self.executor.state_manager
        needs_cleanup = state_manager.authenticates_smb_file_mutation_journal_cleanup
        if not needs_cleanup(journal):
            return True
        last_error: BaseException | None = None
        for _attempt in range(2):
            try:
                state_manager.cancel_smb_file_mutation_journal(journal)
            except BaseException as cleanup_error:
                last_error = cleanup_error
            if not needs_cleanup(journal):
                return True
        cleanup_error = last_error or StateError(
            "SMB file-mutation rollback retained its exact cleanup owner"
        )
        primary.add_note(
            "SMB file-mutation rollback also failed: "
            f"{type(cleanup_error).__name__}: {cleanup_error}"
        )
        return False

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

    def _exact_client_process_context(
        self,
        client: System | None,
        identity: ProcessIdentity,
    ) -> ProcessContext:
        """Return a client actor only when the live object matches its frozen identity."""

        if client is None or client.hostname != identity.hostname:
            raise StateError("Persistent SMB client process has no matching modeled host")
        running = self.executor.state_manager.get_process(identity.hostname, identity.pid)
        current = self.executor.state_manager.get_process_identity(identity.hostname, identity.pid)
        if (
            running is None
            or current is None
            or current.object_id != identity.object_id
            or current != identity
        ):
            raise StateError("Persistent SMB client PID no longer names its exact process object")
        return ProcessContext(
            pid=identity.pid,
            parent_pid=identity.parent_pid,
            image=identity.image,
            command_line=identity.command_line,
            username=identity.principal,
            integrity_level=running.integrity_level,
            logon_id=identity.logon_id,
            start_time=identity.started_at,
            parent_start_time=self.executor._lookup_parent_start_time(
                identity.hostname,
                identity.parent_pid,
            ),
            concurrency_group_id=running.concurrency_group_id,
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
        if isinstance(source, SmbClientLocation) and source.file_set is not None:
            file_set = self.world.file_set(source.file_set)
            relative_path = remote_path
            if isinstance(destination, SmbShareLocation) and destination.directory:
                prefix = destination.directory.rstrip("\\") + "\\"
                if relative_path.casefold().startswith(prefix.casefold()):
                    relative_path = relative_path[len(prefix) :]
            if file_set.root.startswith("/"):
                return posixpath.join(file_set.root, relative_path.replace("\\", "/"))
            root = file_set.root.rstrip("\\")
            native_relative = relative_path.replace("/", "\\")
            return f"{root}\\{native_relative}"
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
        if location.directory:
            separator = "/" if client_is_linux else "\\"
            local_directory = location.directory.rstrip("/\\")
            return f"{local_directory}{separator}{basename}"
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
        if (preparation := getattr(self, "_preparation", None)) is not None:
            return preparation.duration
        authored = (
            self.request.spec.batch.duration
            if self.outcome == "success" and self.request.spec.batch
            else None
        )
        if authored is not None:
            duration = max(0.25, parse_duration(authored).total_seconds())
            self._operation_time_scale = 1.0
            self._session_setup_scale = 1.0
            unscaled = sum(
                self._operation_timing(
                    file,
                    index,
                    size_bytes=self._planned_operation_size(file, index),
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
                size_bytes=self._planned_operation_size(file, index),
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

        if (preparation := getattr(self, "_preparation", None)) is not None:
            return self._prepared_file_value(
                preparation.planned_sizes,
                file,
                operation_index,
                label="planned size",
            )
        planned = getattr(self, "_planning_post_sizes", {}).get(file.file_id)
        if planned is not None:
            return planned
        prestate = getattr(self, "_planning_prestates", {}).get(file.file_id)
        current_size = (
            prestate.size_bytes
            if prestate is not None
            else self.executor.state_manager.smb_file_size(file)
        )
        nominal_size = max(1, file.size_bytes)
        profile = smb_file_evolution_profile(file.extension)
        rng = self._timing_rng(f"update-size:{operation_index}:{file.file_id}")
        drift = (nominal_size - current_size) * profile.mean_reversion
        variation = nominal_size * rng.uniform(
            -profile.variation_ratio,
            profile.variation_ratio,
        )
        minimum = max(1, int(nominal_size * profile.minimum_size_ratio))
        maximum = max(
            nominal_size,
            min(
                int(nominal_size * profile.maximum_size_ratio),
                profile.capacity_bytes,
            ),
        )
        return min(maximum, max(minimum, round(current_size + drift + variation)))

    def _planned_transfer_size(self, file: CompiledStorageFile, operation_index: int) -> int:
        """Return the size that the operation will put on the wire."""

        if (preparation := getattr(self, "_preparation", None)) is not None:
            return self._prepared_file_value(
                preparation.planned_sizes,
                file,
                operation_index,
                label="transfer size",
            )
        planned = getattr(self, "_planning_post_sizes", {}).get(file.file_id)
        if planned is not None:
            return planned
        if self.request.spec.operation == "update":
            return self._updated_size(file, operation_index)
        prestate = getattr(self, "_planning_prestates", {}).get(file.file_id)
        if prestate is not None:
            return prestate.size_bytes
        return self.executor.state_manager.smb_file_size(file)

    def _prepared_file_value(
        self,
        values: tuple[Any, ...],
        file: CompiledStorageFile,
        operation_index: int,
        *,
        label: str,
    ) -> Any:
        """Return one indexed prepared value after validating its file binding."""

        preparation = getattr(self, "_preparation", None)
        if preparation is None or not 0 <= operation_index < len(values):
            raise StateError(f"SMB preparation lost its {label} index")
        if preparation.selected[operation_index].file_id != file.file_id:
            raise StateError(f"SMB preparation {label} belongs to a different file")
        return values[operation_index]

    def _planned_operation_size(self, file: CompiledStorageFile, operation_index: int) -> int:
        """Return payload size for timing, excluding failed open-only operations."""

        if self.outcome != "success":
            return 0
        return self._planned_transfer_size(file, operation_index)

    def _operation_timing(
        self,
        file: CompiledStorageFile,
        operation_index: int,
        *,
        size_bytes: int,
    ) -> _SmbOperationTiming:
        """Sample one bounded operation span using a stable session-scoped RNG."""

        if (preparation := getattr(self, "_preparation", None)) is not None:
            return self._prepared_file_value(
                preparation.operation_timings,
                file,
                operation_index,
                label="operation timing",
            )
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

    def _channel_affinity(
        self,
        *,
        share: CompiledStorageShare,
        server: System,
        client_system: System | None,
        client_ip: str,
        process: ProcessContext | None,
        auth_protocol: str,
        client_logon_id: str = "",
    ) -> SmbChannelAffinity:
        """Return one canonical SMB2/3 application-channel compatibility key."""

        return SmbChannelAffinity(
            client_identity=(client_system.hostname if client_system is not None else client_ip),
            client_ip=client_ip,
            client_session=(
                process.logon_id
                if process is not None and process.logon_id
                else client_logon_id or "none"
            ),
            server_identity=server.hostname,
            server_ip=server.ip,
            principal=self.smb_principal,
            auth_protocol=auth_protocol,
            account_scope="directory",
            dialect="3.1.1",
            signing_policy="required",
            encryption_policy="required" if share.encryption == "required" else "off",
            server_policy=f"{self._server_platform(server)}:file-server",
            share_policy="disk:standard",
            client_access=self.client_access,
        )

    def _directional_transport_byte_allocations(
        self,
        files: tuple[CompiledStorageFile, ...],
        *,
        write: bool,
    ) -> tuple[int, ...]:
        """Allocate exact aggregate SMB wire bytes across deterministic operations."""

        if not files:
            return ()
        operation = self.request.spec.operation
        source_is_share = isinstance(self.request.spec.source, SmbShareLocation)
        destination_is_share = isinstance(self.request.spec.destination, SmbShareLocation)
        if self.outcome != "success":
            carries_data = False
        elif write:
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
        payloads = [
            self._planned_transfer_size(file, index) if carries_data else 0
            for index, file in enumerate(files)
        ]
        if carries_data and operation == "update":
            adjusted_total = int(sum(payloads) * byte_rng.uniform(1.16, 1.35))
            payloads[0] += adjusted_total - sum(payloads)
        base_framing = byte_rng.randint(850, 2_650)
        allocations = [payload + byte_rng.randint(240, 1_050) for payload in payloads]
        allocations[0] += base_framing
        return tuple(allocations)

    def _transport_byte_allocations(
        self,
        files: tuple[CompiledStorageFile, ...],
    ) -> tuple[tuple[int, int], ...]:
        """Return exact initiator/responder byte reservations for each selected file."""

        if (preparation := getattr(self, "_preparation", None)) is not None:
            if tuple(file.file_id for file in files) != tuple(
                file.file_id for file in preparation.selected
            ):
                raise StateError("SMB preparation byte allocations belong to different files")
            return preparation.byte_allocations
        initiator = self._directional_transport_byte_allocations(files, write=True)
        responder = self._directional_transport_byte_allocations(files, write=False)
        return tuple(zip(initiator, responder, strict=True))

    def _transport_bytes(self, files: tuple[CompiledStorageFile, ...], *, write: bool) -> int:
        return sum(self._directional_transport_byte_allocations(files, write=write))

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
