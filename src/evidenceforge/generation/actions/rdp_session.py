# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""RDP session action bundle.

The RDP bundle models a remote interactive Windows session above individual
canonical occurrences. It owns the source client, transport connection, target logon,
and source-visible ordering for a single RDP activity while using the current
activity generator as the runtime adapter for shared state and dispatch.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from threading import Lock
from typing import Any, Protocol

from evidenceforge.events.contexts import AuthContext, IdsAlertPlan, ProcessContext
from evidenceforge.events.contracts import EventKind
from evidenceforge.events.dispatcher import (
    ActionCohortProjectionDisposition,
    ActionCohortProjectionOutcome,
    ActionCohortPublicationReceipt,
    ActionCohortPublicationResult,
    EventDispatcher,
    StateNeutralProjectionPublicationReceipt,
    StateNeutralProjectionPublicationResult,
)
from evidenceforge.events.identity import EventIdentityPlan, ProcessIdentity, SessionIdentity
from evidenceforge.events.lifecycle import ActionLifecycleContext, SessionEndPlan
from evidenceforge.events.network import NetworkTuple
from evidenceforge.events.rdp import RdpSessionSnapshot
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.actions.network_connection import (
    DeferredRdpApplicationIntent,
    DeferredSessionNetworkAuthority,
    NetworkConnectionActionBundle,
    NetworkConnectionIdentityCapture,
    NetworkConnectionRequest,
)
from evidenceforge.generation.actions.windows_remote_authentication import (
    WindowsRemoteAuthenticationPlanner,
    WindowsRemoteAuthenticationRequest,
)
from evidenceforge.generation.activity.helpers import _get_os_category, _get_rng
from evidenceforge.generation.activity.timing_profiles import get_timing_window
from evidenceforge.generation.baseline_timing import BaselineTimingPlanner
from evidenceforge.generation.deferred_session_composition import (
    DeferredSessionCompositionCoordinator,
    DeferredSessionKind,
)
from evidenceforge.generation.deferred_session_preseal import (
    DeferredSessionBindingDisposition,
    DeferredSessionDependentOccurrenceSpec,
    DeferredSessionProtocol,
)
from evidenceforge.generation.network_runtime import NetworkTransactionPlan
from evidenceforge.generation.rdp_sessions import (
    RdpReconnectStateManager,
    RdpSessionAdmissionReceipt,
)
from evidenceforge.generation.source_timing import SourceTimingPlanner
from evidenceforge.generation.state_manager import (
    ConnectionExistingSessionPatch,
    ProcessMaterializationPlan,
    SessionMaterializationPlan,
    StateManager,
)
from evidenceforge.generation.timing import TemporalConstraintGraph, TimingRuntime
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import System, User
from evidenceforge.utils.rng import _stable_seed, stable_uuid
from evidenceforge.utils.time import ensure_utc

RDP_TRANSPORT_DURATION_MAX_SECONDS = 3600.0
RDP_EXPLICIT_END_CLOSE_GAP_MAX_MILLISECONDS = 1500
_RDP_EXPLICIT_END_CLOSE_GAP_MIN_MILLISECONDS = 100


@dataclass(frozen=True, slots=True)
class _RdpTerminalProjectionTimingProof:
    """Canonical owner time plus immutable source-native projection frontiers."""

    canonical_time: datetime
    source_frontiers: tuple[tuple[str, int, datetime], ...]
    disposition: ActionCohortProjectionDisposition

    def __post_init__(self) -> None:
        canonical_time = ensure_utc(self.canonical_time)
        if type(self.source_frontiers) is not tuple:
            raise StateError("Exact RDP terminal timing proof requires an exact frontier tuple")
        if type(self.disposition) is not ActionCohortProjectionDisposition:
            raise StateError("Exact RDP terminal timing proof requires its dispatcher disposition")
        normalized: list[tuple[str, int, datetime]] = []
        seen: set[tuple[str, int]] = set()
        for frontier in self.source_frontiers:
            if type(frontier) is not tuple or len(frontier) != 3:
                raise StateError("Exact RDP terminal source frontier is malformed")
            format_name, source_ordinal, timestamp = frontier
            if (
                type(format_name) is not str
                or format_name not in {"ecar", "windows_event_security", "windows_security"}
                or type(source_ordinal) is not int
                or source_ordinal < 0
                or not isinstance(timestamp, datetime)
            ):
                raise StateError("Exact RDP terminal source frontier is malformed")
            source_key = (format_name, source_ordinal)
            if source_key in seen:
                raise StateError("Exact RDP terminal timing proof repeats a source")
            seen.add(source_key)
            normalized.append((format_name, source_ordinal, ensure_utc(timestamp)))
        if self.disposition is ActionCohortProjectionDisposition.EXACT_WARMUP_SUPPRESSED:
            if normalized:
                raise StateError(
                    "Exact warm-up-suppressed RDP terminal proof cannot carry source frontiers"
                )
        elif not normalized:
            raise StateError("Exact visible RDP terminal timing proof requires source frontiers")
        object.__setattr__(self, "canonical_time", canonical_time)
        object.__setattr__(
            self,
            "source_frontiers",
            tuple(sorted(normalized, key=lambda item: (item[0], item[1]))),
        )


class _RdpTerminalProjectionLedger:
    """Retain exact terminal receipts until the RDP journal acknowledges them."""

    __slots__ = ("_completed", "_lock", "_recoveries", "_timing_proofs")

    def __init__(self) -> None:
        self._lock = Lock()
        self._recoveries: dict[
            str,
            tuple[
                str,
                object,
                object,
                str,
                str,
                str,
                _RdpTerminalProjectionTimingProof | None,
            ],
        ] = {}
        self._completed: set[str] = set()
        self._timing_proofs: dict[str, _RdpTerminalProjectionTimingProof] = {}

    def retain_action_cohort(
        self,
        phase: str,
        *,
        receipt: ActionCohortPublicationReceipt,
        result: ActionCohortPublicationResult,
        root_action_id: str,
        state_semantic_id: str,
        occurrence_id: str,
        timing_proof: _RdpTerminalProjectionTimingProof,
    ) -> None:
        """Retain one authenticated committed State-backed projection."""

        if type(timing_proof) is not _RdpTerminalProjectionTimingProof:
            raise StateError("Exact RDP terminal recovery requires its timing proof")
        retained = (
            "action",
            receipt,
            result,
            root_action_id,
            state_semantic_id,
            occurrence_id,
            timing_proof,
        )
        with self._lock:
            if phase in self._completed:
                return
            existing = self._recoveries.get(phase)
            if existing is not None and existing != retained:
                raise StateError("Exact RDP terminal phase changed its retained publication")
            self._recoveries[phase] = retained

    def retain_state_neutral(
        self,
        phase: str,
        *,
        receipt: StateNeutralProjectionPublicationReceipt,
        result: StateNeutralProjectionPublicationResult,
        occurrence_id: str,
    ) -> None:
        """Retain one authenticated committed State-neutral projection."""

        retained = ("state_neutral", receipt, result, "", "", occurrence_id, None)
        with self._lock:
            if phase in self._completed:
                return
            existing = self._recoveries.get(phase)
            if existing is not None and existing != retained:
                raise StateError("Exact RDP terminal phase changed its retained publication")
            self._recoveries[phase] = retained

    def recover(self, phase: str, dispatcher: EventDispatcher) -> bool:
        """Recover a committed sink tail and acknowledge its exact retained result."""

        with self._lock:
            if phase in self._completed:
                return True
            retained = self._recoveries.get(phase)
        if retained is None:
            return False
        (
            kind,
            receipt,
            expected,
            root_action_id,
            state_semantic_id,
            occurrence_id,
            timing_proof,
        ) = retained
        if kind == "action":
            if (
                type(receipt) is not ActionCohortPublicationReceipt
                or type(expected) is not ActionCohortPublicationResult
                or expected.receipt is not receipt
                or not dispatcher.authenticates_action_cohort_publication_receipt(receipt)
                or receipt.root_action_id != root_action_id
                or receipt.state_semantic_id != state_semantic_id
                or receipt.occurrence_ids != (occurrence_id,)
            ):
                raise StateError("Exact RDP terminal recovery lost its action-cohort proof")
            outcome = expected.projections[0] if len(expected.projections) == 1 else None
            result = (
                expected
                if type(outcome) is ActionCohortProjectionOutcome
                and outcome.status == "succeeded"
                and outcome.error is None
                else dispatcher.resume_action_cohort_projection(receipt)
            )
            succeeded = bool(
                result is expected
                and len(result.projections) == 1
                and type(result.projections[0]) is ActionCohortProjectionOutcome
                and result.projections[0].occurrence_id == occurrence_id
                and result.projections[0].status == "succeeded"
                and result.projections[0].error is None
            )
        else:
            if (
                kind != "state_neutral"
                or type(receipt) is not StateNeutralProjectionPublicationReceipt
                or type(expected) is not StateNeutralProjectionPublicationResult
                or expected.receipt is not receipt
                or not dispatcher.authenticates_state_neutral_projection_publication_receipt(
                    receipt
                )
                or receipt.occurrence_ids != (occurrence_id,)
            ):
                raise StateError("Exact RDP terminal recovery lost its state-neutral proof")
            outcome = expected.projection
            result = (
                expected
                if type(outcome) is ActionCohortProjectionOutcome
                and outcome.status == "succeeded"
                and outcome.error is None
                else dispatcher.resume_state_neutral_exact_projection(receipt)
            )
            succeeded = bool(
                result is expected
                and type(result.projection) is ActionCohortProjectionOutcome
                and result.projection.occurrence_id == occurrence_id
                and result.projection.status == "succeeded"
                and result.projection.error is None
            )
        if not succeeded:
            raise StateError("Exact RDP terminal recovery returned invalid sink proof")
        with self._lock:
            if self._recoveries.get(phase) != retained:
                raise StateError("Exact RDP terminal recovery changed its retained owner")
            self._recoveries.pop(phase)
            self._completed.add(phase)
            if timing_proof is not None:
                self._timing_proofs[phase] = timing_proof
        return True

    def mark_complete(
        self,
        phase: str,
        *,
        timing_proof: _RdpTerminalProjectionTimingProof | None = None,
    ) -> None:
        """Acknowledge a terminal phase after its exact publisher returns."""

        if timing_proof is not None and type(timing_proof) is not _RdpTerminalProjectionTimingProof:
            raise StateError("Exact RDP terminal completion requires its timing proof")
        with self._lock:
            existing = self._timing_proofs.get(phase)
            if existing is not None and existing != timing_proof:
                raise StateError("Exact RDP terminal phase changed its timing proof")
            self._recoveries.pop(phase, None)
            self._completed.add(phase)
            if timing_proof is not None:
                self._timing_proofs[phase] = timing_proof

    def timing_proof(self, phase: str) -> _RdpTerminalProjectionTimingProof | None:
        """Return the retained canonical/source timing proof for one completed phase."""

        with self._lock:
            if phase not in self._completed:
                return None
            return self._timing_proofs.get(phase)


@dataclass(frozen=True, slots=True)
class _RdpLifecycleContinuation:
    """One exact committed transport generation retained for terminal work."""

    prepared: _PreparedRdpLifecycleContinuation
    transaction: NetworkTransactionPlan
    session: RdpSessionSnapshot

    @property
    def continuation_id(self) -> str:
        """Return the stable bounded-journal key."""

        return self.prepared.continuation_id

    @property
    def disconnect_at(self) -> datetime:
        """Return the immutable transport close frontier."""

        assert self.transaction.closed_at is not None
        return self.transaction.closed_at


@dataclass(frozen=True, slots=True)
class _PreparedRdpLifecycleContinuation:
    """Precommit reservation facts for one RDP transport generation."""

    continuation_id: str
    identity_capture: NetworkConnectionIdentityCapture = field(compare=False, repr=False)
    manager: RdpReconnectStateManager = field(compare=False, repr=False)
    session_identity: SessionIdentity
    target_system: System
    user: User
    source_system: System | None
    source_identity: ProcessIdentity | None
    source_session_identity: SessionIdentity | None
    hard_deadline: datetime
    expected_generation: int
    source_tag: str
    projection_ledger: _RdpTerminalProjectionLedger = field(
        default_factory=_RdpTerminalProjectionLedger,
        compare=False,
        repr=False,
    )

    def bind(self) -> _RdpLifecycleContinuation:
        """Bind this reservation to its exact committed network/application receipt."""

        transaction = self.identity_capture.require()
        receipt = self.identity_capture.application_receipt
        if (
            type(receipt) is not RdpSessionAdmissionReceipt
            or not self.manager.authenticates_admission_receipt(receipt)
            or receipt.session.identity.logical_session_id != self.session_identity.object_id
            or receipt.session.generation.ordinal != self.expected_generation
            or receipt.session.generation.binding.transport_id != transaction.stable_id
            or receipt.session.generation.binding.closes_at != transaction.closed_at
        ):
            raise StateError("Exact RDP lifecycle continuation lost its committed generation")
        return _RdpLifecycleContinuation(
            prepared=self,
            transaction=transaction,
            session=receipt.session,
        )

    def recover_terminal_projection(self, phase: str, dispatcher: EventDispatcher) -> bool:
        """Recover one committed exact terminal tail without consulting mutable State."""

        return self.projection_ledger.recover(phase, dispatcher)

    def mark_terminal_projection_complete(
        self,
        phase: str,
        *,
        timing_proof: _RdpTerminalProjectionTimingProof | None = None,
    ) -> None:
        """Acknowledge one fully returned exact terminal projection."""

        self.projection_ledger.mark_complete(phase, timing_proof=timing_proof)

    def terminal_projection_timing_proof(
        self,
        phase: str,
    ) -> _RdpTerminalProjectionTimingProof | None:
        """Return canonical/source timing retained for a completed phase."""

        return self.projection_ledger.timing_proof(phase)


@dataclass(frozen=True, slots=True)
class _PreparedDeferredRdpOpen:
    """One allocation-free initial RDP publication handoff."""

    authority: DeferredSessionNetworkAuthority
    identity_capture: NetworkConnectionIdentityCapture
    session_plan: SessionMaterializationPlan
    process_plans: tuple[ProcessMaterializationPlan, ...]
    source_identity: ProcessIdentity | None
    source_session_identity: SessionIdentity | None
    lifecycle_continuation: _PreparedRdpLifecycleContinuation


@dataclass(frozen=True, slots=True)
class _PreparedDeferredRdpReconnect:
    """One allocation-free reconnect publication handoff."""

    authority: DeferredSessionNetworkAuthority
    identity_capture: NetworkConnectionIdentityCapture
    session_identity: SessionIdentity
    existing_session_patch: ConnectionExistingSessionPatch
    source_plan: ProcessMaterializationPlan
    source_session_identity: SessionIdentity
    lifecycle_continuation: _PreparedRdpLifecycleContinuation


@dataclass(frozen=True, slots=True)
class RdpSessionRequest:
    """Intent for one modeled RDP session action."""

    user: User
    target_system: System
    time: datetime
    source_ip: str
    source_system: System | None = None
    source_pid: int = -1
    source_port: int | None = None
    source_process_time: datetime | None = None
    logon_id: str = ""
    preserve_explicit_source: bool = False
    session_end_plan: SessionEndPlan | None = None
    ids_alerts: list[IdsAlertPlan] = field(default_factory=list)
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        source_host = self.source_system.hostname if self.source_system is not None else ""
        seed = _stable_seed(
            "action_bundle:rdp_session:"
            f"{self.user.username}:{source_host}:{self.source_ip}:{self.source_pid}:"
            f"{self.source_port or ''}:{self.preserve_explicit_source}:"
            f"{self.source_process_time.isoformat() if self.source_process_time else ''}:"
            f"{self.target_system.hostname}:{self.target_system.ip}:"
            f"{self.logon_id}:"
            f"{self.session_end_plan.canonical_end.isoformat() if self.session_end_plan else ''}:"
            f"{self.ids_alerts}:"
            f"{self.source}:{self.time.isoformat()}"
        )
        return f"rdp-session-{seed:016x}"


class RdpSourceProcessFactory(Protocol):
    """Callable that materializes the source-side RDP client process."""

    def __call__(
        self,
        *,
        user: User,
        source_system: System,
        target_system: System,
        time: datetime,
    ) -> int:
        """Return the source-side mstsc.exe PID."""
        ...


class RdpSessionExecutor(Protocol):
    """Adapter protocol implemented by the current activity generator."""

    state_manager: StateManager
    dispatcher: EventDispatcher
    _source_timing_planner: SourceTimingPlanner
    _ip_to_system: dict[str, System]
    timing_runtime: TimingRuntime
    _rdp_session_manager: Any

    def _coerce_windows_rdp_user_from_existing_session(
        self,
        user: User,
        target_system: System,
        source_ip: str,
    ) -> User:
        """Return the Windows account that should own the RDP session."""
        ...

    def _rdp_reconnect_source_frontier(self, logon_id: str) -> datetime | None:
        """Return the prior exact mstsc close observation for a logical session."""
        ...

    def _allocate_ephemeral_port(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        proto: str,
        time: datetime,
        os_category: str,
    ) -> int:
        """Reserve a source port for the RDP transport."""
        ...

    def _os_for_ip(self, ip: str) -> str:
        """Return the OS category for a source IP."""
        ...

    def generate_connection(
        self,
        src_ip: str,
        dst_ip: str,
        time: datetime,
        **kwargs: Any,
    ) -> str:
        """Generate canonical network evidence."""
        ...

    def generate_logon(
        self,
        user: User,
        system: System,
        time: datetime,
        **kwargs: Any,
    ) -> str:
        """Generate canonical Windows logon evidence."""
        ...

    def _preview_sid(self, username: str) -> str:
        """Return a mutation-free Windows SID preview."""
        ...

    def _build_host_context(self, system: System) -> Any:
        """Build one canonical modeled host context."""
        ...

    def _get_sid(self, username: str) -> str:
        """Return the canonical Windows SID for a principal."""
        ...

    def _plan_process_source_terminate_times(self, event: Any) -> None:
        """Prepare source-native process termination timing."""
        ...

    def _commit_exact_ssh_source_process_termination(self, event: Any) -> None:
        """Adopt committed process terminal facts into compatibility caches."""
        ...

    def _reserve_exact_rdp_lifecycle_continuation(
        self,
        prepared: _PreparedRdpLifecycleContinuation,
    ) -> None:
        """Reserve bounded RDP terminal-journal capacity before commit."""
        ...

    def _cancel_exact_rdp_lifecycle_continuation_reservation(
        self,
        prepared: _PreparedRdpLifecycleContinuation,
    ) -> None:
        """Release an uncommitted RDP terminal-journal reservation."""
        ...

    def _recover_exact_rdp_lifecycle_continuation_no_fail(
        self,
        continuation: _RdpLifecycleContinuation,
    ) -> None:
        """Install one authenticated committed RDP terminal continuation."""
        ...


class RdpSessionActionBundle:
    """Expand one RDP session intent into coordinated canonical evidence."""

    def __init__(
        self,
        executor: RdpSessionExecutor,
        request: RdpSessionRequest,
        *,
        source_process_factory: RdpSourceProcessFactory | None = None,
    ) -> None:
        self._executor = executor
        self._request = request
        self._source_process_factory = source_process_factory
        self._rendered_logon_id = ""

    def _timing_planner(self) -> BaselineTimingPlanner:
        """Return the engine planner or one stateless direct-test adapter."""

        runtime = getattr(self._executor, "timing_runtime", None)
        return BaselineTimingPlanner(
            runtime
            if isinstance(runtime, TimingRuntime)
            else TimingRuntime.compatibility_default(),
            source="rdp",
        )

    @property
    def rendered_logon_id(self) -> str:
        """Return the target session LogonID after execution."""

        return self._rendered_logon_id

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="rdp_session",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> str:
        """Expand and dispatch RDP transport and target-logon evidence."""

        rng = _get_rng()
        user = self._executor._coerce_windows_rdp_user_from_existing_session(
            self._request.user,
            self._request.target_system,
            self._request.source_ip,
        )
        source_ip, source_system, source_pid = self._resolve_source(rng, user)
        lifecycle_drain = getattr(
            self._executor,
            "advance_rdp_session_lifecycle_watermark",
            None,
        )
        if callable(lifecycle_drain):
            lifecycle_drain(self._request.time)
        duration = rng.uniform(60.0, RDP_TRANSPORT_DURATION_MAX_SECONDS)
        end_plan = self._request.session_end_plan
        if end_plan is not None and end_plan.is_authoritative:
            close_gap_ms = _RDP_EXPLICIT_END_CLOSE_GAP_MIN_MILLISECONDS + (
                _stable_seed(
                    "rdp_transport_before_explicit_logoff:"
                    f"{self._request.stable_id}:{end_plan.canonical_end.isoformat()}"
                )
                % (
                    RDP_EXPLICIT_END_CLOSE_GAP_MAX_MILLISECONDS
                    - _RDP_EXPLICIT_END_CLOSE_GAP_MIN_MILLISECONDS
                    + 1
                )
            )
            latest_close = end_plan.canonical_end - timedelta(milliseconds=close_gap_ms)
            if latest_close <= self._request.time:
                raise StateError(
                    "Explicit RDP session end must follow transport open: "
                    f"{self._request.target_system.hostname} at "
                    f"{end_plan.canonical_end.isoformat()}"
                )
            duration = min(duration, (latest_close - self._request.time).total_seconds())
        src_port = self._request.source_port
        if src_port is None:
            src_port = self._executor._allocate_ephemeral_port(
                source_ip,
                self._request.target_system.ip,
                3389,
                "tcp",
                self._request.time,
                self._executor._os_for_ip(source_ip),
            )

        logon_time = self._target_logon_time(
            source_ip=source_ip,
            src_port=src_port,
            transport_start_time=self._request.time,
        )
        if self._uses_exact_reconnect_publication(
            user=user,
            source_system=source_system,
        ):
            return self._execute_exact_reconnect(
                user=user,
                source_ip=source_ip,
                source_system=source_system,
                source_port=src_port,
                duration=duration,
                reconnect_time=logon_time,
            )
        source_pid = self._materialize_source_process(
            user=user,
            source_system=source_system,
            source_pid=source_pid,
        )
        if self._uses_exact_initial_publication(
            source_system=source_system,
            source_pid=source_pid,
        ):
            uid = self._execute_exact_initial_session(
                user=user,
                source_ip=source_ip,
                source_system=source_system,
                source_pid=source_pid,
                source_port=src_port,
                duration=duration,
                logon_time=logon_time,
            )
            return uid
        remote_request = WindowsRemoteAuthenticationRequest(
            target_system=self._request.target_system,
            time=logon_time,
            source_ip=source_ip,
            source_port=src_port,
            logon_type=10,
            auth_protocol="Negotiate",
            outcome="success",
            destination_port=3389,
            source_system=source_system,
            logon_id=self._request.logon_id,
            transport_role="rdp",
            source="rdp_session",
        )
        network_request = NetworkConnectionRequest(
            src_ip=source_ip,
            dst_ip=self._request.target_system.ip,
            time=self._request.time,
            dst_port=3389,
            proto="tcp",
            service="rdp",
            duration=duration,
            orig_bytes=rng.randint(50000, 500000),
            resp_bytes=rng.randint(100000, 2000000),
            src_port=src_port,
            emit_dns=True,
            source_system=source_system,
            pid=source_pid,
            conn_state="SF",
            parent_action_group_id=remote_request.stable_id,
            preserve_start_time=True,
            ids_alerts=tuple(self._request.ids_alerts),
            source="rdp_session",
        )
        transaction_id = network_request.stable_id
        uid = NetworkConnectionActionBundle(self._executor, network_request).execute()
        network_start_time, network_close_time = self._transport_interval(
            uid,
            fallback_start=self._request.time,
            fallback_close=self._request.time + timedelta(seconds=duration),
        )
        self._protect_source_client_lifecycle(
            source_system=source_system,
            source_pid=source_pid,
            network_close_time=network_close_time,
        )

        remote_authentication_plan = WindowsRemoteAuthenticationPlanner(
            self._executor
        ).from_existing_transport(
            remote_request,
            transaction_id=transaction_id,
            tuple_view=NetworkTuple(
                src_ip=source_ip,
                src_port=src_port,
                dst_ip=self._request.target_system.ip,
                dst_port=3389,
                protocol="tcp",
            ),
            started_at=network_start_time,
            closed_at=network_close_time,
        )
        logon_id = self._request.logon_id
        if logon_id:
            reassigned_logon_id = self._executor.state_manager.reassign_session_logon_id(
                logon_id,
                logon_time,
            )
            if reassigned_logon_id is not None:
                logon_id = reassigned_logon_id
            self._executor.state_manager.update_session_metadata(
                logon_id,
                username=user.username,
                start_time=logon_time,
                source_ip=source_ip,
                source_port=src_port,
                session_kind="rdp",
                transport_pid=source_pid if source_pid > 0 else None,
                network_close_time=network_close_time,
                source_ready_time=logon_time,
            )
        rendered_logon_id = self._executor.generate_logon(
            user=user,
            system=self._request.target_system,
            time=logon_time,
            logon_type=10,
            source_ip=source_ip,
            source_system=source_system,
            source_port=src_port,
            emit_network_evidence=False,
            logon_id=logon_id or None,
            lifecycle_group_id=self._request.stable_id,
            session_end_plan=self._request.session_end_plan,
            remote_authentication_plan=remote_authentication_plan,
        )
        self._rendered_logon_id = rendered_logon_id
        self._executor.state_manager.update_session_metadata(
            rendered_logon_id,
            username=user.username,
            start_time=logon_time,
            source_ip=source_ip,
            source_port=src_port,
            session_kind="rdp",
            transport_pid=source_pid if source_pid > 0 else None,
            network_close_time=network_close_time,
        )

        return uid

    def _has_exact_deferred_projection_owners(self) -> bool:
        """Return whether the built-in transport and optional Windows sinks are present."""

        dispatcher = getattr(self._executor, "dispatcher", None)
        emitters = getattr(dispatcher, "emitters", None)
        if type(emitters) is not dict:
            return False
        from evidenceforge.generation.emitters.ecar import EcarEmitter
        from evidenceforge.generation.emitters.windows import WindowsEventEmitter
        from evidenceforge.generation.emitters.zeek import ZeekEmitter

        windows = emitters.get("windows_event_security")
        return (
            type(emitters.get("ecar")) is EcarEmitter
            and type(emitters.get("zeek_conn")) is ZeekEmitter
            and (windows is None or type(windows) is WindowsEventEmitter)
        )

    def _uses_exact_initial_publication(
        self,
        *,
        source_system: System | None,
        source_pid: int,
    ) -> bool:
        """Return whether this call has the closed initial RDP source cohort."""

        if self._request.logon_id or _get_os_category(self._request.target_system.os) != "windows":
            return False
        if (
            source_system is not None
            and self._exact_source_binding(
                source_system,
                source_pid,
            )
            is None
        ):
            return False
        return self._has_exact_deferred_projection_owners()

    def _uses_exact_reconnect_publication(
        self,
        *,
        user: User,
        source_system: System | None,
    ) -> bool:
        """Return whether this request can advance one disconnected exact session."""

        if (
            not self._request.logon_id
            or source_system is None
            or _get_os_category(source_system.os) != "windows"
            or _get_os_category(self._request.target_system.os) != "windows"
            or not self._has_exact_deferred_projection_owners()
        ):
            return False
        from evidenceforge.generation.emitters.windows import WindowsEventEmitter

        if (
            type(self._executor.dispatcher.emitters.get("windows_event_security"))
            is not WindowsEventEmitter
        ):
            return False
        session_identity = self._executor.state_manager.get_session_identity(self._request.logon_id)
        if session_identity is None or session_identity.session_kind != "rdp":
            return False
        from evidenceforge.events.rdp import RdpSessionState

        prior = self._executor._rdp_session_manager.get(session_identity.object_id)
        source_session = self._executor._active_user_interactive_windows_session(
            user,
            source_system,
            self._request.time,
        )
        return bool(
            prior is not None
            and prior.state is RdpSessionState.DISCONNECTED
            and prior.identity.affinity.source_address == self._request.source_ip.casefold()
            and source_session is not None
        )

    def _exact_source_binding(
        self,
        source_system: System,
        source_pid: int,
    ) -> tuple[ProcessIdentity, SessionIdentity] | None:
        """Return the exact live source mstsc process and owning session."""

        if source_pid <= 0:
            return None
        state = self._executor.state_manager
        running = state.get_process(source_system.hostname, source_pid)
        identity = state.get_process_identity(source_system.hostname, source_pid)
        if (
            running is None
            or identity is None
            or identity.object_id != running.ecar_object_id
            or identity.started_at != ensure_utc(running.start_time)
            or identity.started_at > ensure_utc(self._request.time)
            or identity.image.replace("/", "\\").rsplit("\\", 1)[-1].casefold() != "mstsc.exe"
            or not identity.logon_id
        ):
            return None
        session = state.get_session(identity.logon_id)
        session_identity = state.get_session_identity(identity.logon_id)
        if (
            session is None
            or session_identity is None
            or session_identity.object_id != session.ecar_object_id
            or session_identity.hostname != source_system.hostname
            or session_identity.started_at > ensure_utc(self._request.time)
        ):
            return None
        return identity, session_identity

    def _exact_rdp_deadline(self, transport_close: datetime) -> datetime:
        """Return the half-open logical deadline protecting later logout."""

        registry_end = ensure_utc(
            self._executor._rdp_session_manager.application_registry.window_end
        )
        window_deadline = registry_end - timedelta(microseconds=1)
        end_plan = self._request.session_end_plan
        deadline = (
            min(ensure_utc(end_plan.canonical_end), window_deadline)
            if end_plan is not None
            else window_deadline
        )
        if deadline <= ensure_utc(transport_close):
            raise StateError(
                "Exact RDP transport leaves no half-open disconnect/logout window: "
                f"close={ensure_utc(transport_close).isoformat()}, "
                f"deadline={deadline.isoformat()}"
            )
        return deadline

    def _execute_exact_initial_session(
        self,
        *,
        user: User,
        source_ip: str,
        source_system: System | None,
        source_pid: int,
        source_port: int,
        duration: float,
        logon_time: datetime,
    ) -> str:
        """Publish one initial RDP transport, State batch, and source cohort exactly."""

        self._executor._lifecycle_authority.bind_rdp_session_manager(
            self._executor.rdp_session_manager
        )
        open_time = ensure_utc(self._request.time)
        transport_close = open_time + timedelta(seconds=duration)
        deadline = self._exact_rdp_deadline(transport_close)
        prepared = self._prepare_exact_initial_session(
            user=user,
            source_ip=source_ip,
            source_system=source_system,
            source_pid=source_pid,
            source_port=source_port,
            logon_time=logon_time,
            transport_close=transport_close,
            hard_deadline=deadline,
        )
        rng = _get_rng()
        try:
            uid = self._executor.generate_connection(
                src_ip=source_ip,
                dst_ip=self._request.target_system.ip,
                time=open_time,
                dst_port=3389,
                proto="tcp",
                service="rdp",
                duration=duration,
                orig_bytes=rng.randint(50_000, 500_000),
                resp_bytes=rng.randint(100_000, 2_000_000),
                src_port=source_port,
                emit_dns=False,
                source_system=source_system,
                pid=source_pid,
                conn_state="SF",
                hostname=self._request.target_system.hostname,
                process_image=(
                    prepared.source_identity.image if prepared.source_identity is not None else None
                ),
                preserve_dst_ip=True,
                preserve_start_time=True,
                suppress_source_pid_inference=True,
                suppress_prereq_dns=True,
                ids_alerts=list(self._request.ids_alerts),
                transport_lifecycle_mode="deferred_session",
                deferred_session_authority=prepared.authority,
                identity_capture=prepared.identity_capture,
            )
        except BaseException as primary:
            self._recover_or_cancel_lifecycle_continuation(
                prepared.lifecycle_continuation,
                primary,
            )
            raise
        transaction = prepared.identity_capture.require()
        if uid != transaction.zeek_uid:
            raise AssertionError("Exact RDP caller received a different transport identity")
        self._executor._recover_exact_rdp_lifecycle_continuation_no_fail(
            prepared.lifecycle_continuation.bind()
        )
        self._rendered_logon_id = prepared.session_plan.identity.logon_id
        return uid

    def _prepare_exact_initial_session(
        self,
        *,
        user: User,
        source_ip: str,
        source_system: System | None,
        source_pid: int,
        source_port: int,
        logon_time: datetime,
        transport_close: datetime,
        hard_deadline: datetime,
    ) -> _PreparedDeferredRdpOpen:
        """Prepare the exact initial RDP owner graph without State mutation."""

        state = self._executor.state_manager
        session_start = ensure_utc(logon_time)
        auth_time = session_start + timedelta(milliseconds=100)
        user_manager_time = auth_time + timedelta(milliseconds=100)
        explorer_time = user_manager_time + timedelta(milliseconds=150)
        if explorer_time >= transport_close:
            raise StateError("Exact RDP transport closes before desktop bootstrap completes")
        action_id = self._request.stable_id
        batch_builder = state.begin_materialization_batch()
        session_plan = batch_builder.plan_session(
            username=user.username,
            system=self._request.target_system.hostname,
            logon_type=10,
            source_ip=source_ip,
            source_port=source_port,
            session_kind="rdp",
            start_time=session_start,
            lifecycle_group_id=action_id,
            auth_protocol="rdp",
            network_close_time=transport_close,
            source_ready_time=auth_time,
            closure_owned_by_bundle=True,
            end_plan=self._request.session_end_plan,
        )
        winlogon = batch_builder.plan_process(
            system=self._request.target_system.hostname,
            parent_pid=4,
            image=r"C:\Windows\System32\winlogon.exe",
            command_line="winlogon.exe",
            username="SYSTEM",
            integrity_level="System",
            os_category="windows",
            logon_id="0x3e7",
            lifecycle_group_id=stable_uuid("rdp-winlogon-lifecycle", action_id),
            parent_lifecycle_group_id=session_plan.identity.lifecycle_group_id,
            start_time=session_start,
        )
        userinit = batch_builder.plan_process(
            system=self._request.target_system.hostname,
            parent_pid=winlogon.identity.pid,
            image=r"C:\Windows\System32\userinit.exe",
            command_line="userinit.exe",
            username=user.username,
            integrity_level="High" if self._rdp_user_is_elevated(user) else "Medium",
            os_category="windows",
            logon_id=session_plan.identity.logon_id,
            lifecycle_group_id=stable_uuid("rdp-userinit-lifecycle", action_id),
            parent_lifecycle_group_id=winlogon.identity.lifecycle_group_id,
            start_time=user_manager_time,
            require_session=True,
            auth_session_id=session_plan.identity.session_id,
            auth_logon_type=10,
            parent_plan=winlogon,
            session_plan=session_plan,
        )
        explorer = batch_builder.plan_process(
            system=self._request.target_system.hostname,
            parent_pid=userinit.identity.pid,
            image=r"C:\Windows\explorer.exe",
            command_line=r"C:\Windows\explorer.exe",
            username=user.username,
            integrity_level="Medium",
            os_category="windows",
            logon_id=session_plan.identity.logon_id,
            lifecycle_group_id=stable_uuid("rdp-explorer-lifecycle", action_id),
            parent_lifecycle_group_id=userinit.identity.lifecycle_group_id,
            start_time=explorer_time,
            require_session=True,
            auth_session_id=session_plan.identity.session_id,
            auth_logon_type=10,
            parent_plan=userinit,
            session_plan=session_plan,
        )
        batch_builder.bind_session_processes(
            session_plan,
            user_manager_plan=userinit,
            winlogon_plan=winlogon,
            explorer_plan=explorer,
            process_tree_root_plan=winlogon,
        )
        batch = batch_builder.seal()
        source_binding = (
            self._exact_source_binding(source_system, source_pid)
            if source_system is not None
            else None
        )
        source_identity = source_binding[0] if source_binding is not None else None
        source_session_identity = source_binding[1] if source_binding is not None else None
        state_authority = state.prepare_deferred_session_state_authority(
            protocol=DeferredSessionProtocol.RDP,
            binding_disposition=DeferredSessionBindingDisposition.NEW_SESSION,
            bound_at=auth_time,
            batch=batch,
        )
        elevated = self._rdp_user_is_elevated(user)
        application_intent = DeferredRdpApplicationIntent(
            manager=self._executor._rdp_session_manager,
            source_host=(source_system.hostname if source_system is not None else source_ip),
            target_host=self._request.target_system.hostname,
            principal=user.username,
            hard_deadline=hard_deadline,
            user_sid=self._executor._preview_sid(user.username),
            elevated=elevated,
            privilege_list=(
                self._executor._select_special_privileges(
                    user,
                    10,
                    self._request.target_system.hostname,
                )
                if elevated
                else ""
            ),
            source_identity=source_identity,
            source_session_identity=source_session_identity,
        )
        dependent_occurrences = (
            self._rdp_process_occurrence(winlogon, 1),
            DeferredSessionDependentOccurrenceSpec(
                occurrence_id=stable_uuid(
                    "rdp-deferred-login-occurrence",
                    session_plan.identity.object_id,
                ),
                event_type=EventKind.LOGON,
                canonical_time=auth_time,
                member_references=(session_plan.identity.object_id,),
                publication_ordinal=2,
            ),
            self._rdp_process_occurrence(userinit, 3),
            self._rdp_process_occurrence(explorer, 4),
        )
        authority = DeferredSessionNetworkAuthority(
            kind=DeferredSessionKind.RDP,
            coordinator=DeferredSessionCompositionCoordinator(kind=DeferredSessionKind.RDP),
            bound_at=auth_time,
            binding_disposition=DeferredSessionBindingDisposition.NEW_SESSION,
            strict_state_authority=state_authority,
            application_intent=application_intent,
            dependent_occurrences=dependent_occurrences,
        )
        lifecycle_continuation = _PreparedRdpLifecycleContinuation(
            continuation_id=stable_uuid(
                "rdp-lifecycle-continuation",
                session_plan.identity.object_id,
                "0",
                self._request.stable_id,
            ),
            identity_capture=NetworkConnectionIdentityCapture(),
            manager=self._executor._rdp_session_manager,
            session_identity=session_plan.identity,
            target_system=self._request.target_system,
            user=user,
            source_system=source_system,
            source_identity=source_identity,
            source_session_identity=source_session_identity,
            hard_deadline=hard_deadline,
            expected_generation=0,
            source_tag=self._request.source,
        )
        prepared = _PreparedDeferredRdpOpen(
            authority=authority,
            identity_capture=lifecycle_continuation.identity_capture,
            session_plan=session_plan,
            process_plans=(winlogon, userinit, explorer),
            source_identity=source_identity,
            source_session_identity=source_session_identity,
            lifecycle_continuation=lifecycle_continuation,
        )
        self._executor._reserve_exact_rdp_lifecycle_continuation(lifecycle_continuation)
        return prepared

    def _execute_exact_reconnect(
        self,
        *,
        user: User,
        source_ip: str,
        source_system: System,
        source_port: int,
        duration: float,
        reconnect_time: datetime,
    ) -> str:
        """Publish one later transport generation against the live RDP session."""

        self._executor._lifecycle_authority.bind_rdp_session_manager(
            self._executor.rdp_session_manager
        )
        open_time = ensure_utc(self._request.time)
        session_identity = self._executor.state_manager.get_session_identity(self._request.logon_id)
        prior = (
            self._executor._rdp_session_manager.get(session_identity.object_id)
            if session_identity is not None
            else None
        )
        if prior is None:
            raise StateError("Exact RDP reconnect lost its logical session deadline")
        close_gap_ms = _RDP_EXPLICIT_END_CLOSE_GAP_MIN_MILLISECONDS + (
            _stable_seed(
                "rdp_reconnect_transport_before_logout:"
                f"{self._request.stable_id}:{prior.identity.hard_deadline.isoformat()}"
            )
            % (
                RDP_EXPLICIT_END_CLOSE_GAP_MAX_MILLISECONDS
                - _RDP_EXPLICIT_END_CLOSE_GAP_MIN_MILLISECONDS
                + 1
            )
        )
        latest_close = prior.identity.hard_deadline - timedelta(milliseconds=close_gap_ms)
        if latest_close <= open_time:
            raise StateError("Exact RDP reconnect leaves no half-open logout interval")
        duration = min(
            duration,
            prior.identity.idle_timeout.total_seconds(),
            (latest_close - open_time).total_seconds(),
        )
        transport_close = open_time + timedelta(seconds=duration)
        prepared = self._prepare_exact_reconnect(
            user=user,
            source_ip=source_ip,
            source_system=source_system,
            source_port=source_port,
            reconnect_time=reconnect_time,
            transport_close=transport_close,
        )
        rng = _get_rng()
        try:
            uid = self._executor.generate_connection(
                src_ip=source_ip,
                dst_ip=self._request.target_system.ip,
                time=open_time,
                dst_port=3389,
                proto="tcp",
                service="rdp",
                duration=duration,
                orig_bytes=rng.randint(50_000, 500_000),
                resp_bytes=rng.randint(100_000, 2_000_000),
                src_port=source_port,
                emit_dns=False,
                source_system=source_system,
                pid=prepared.source_plan.identity.pid,
                conn_state="SF",
                hostname=self._request.target_system.hostname,
                process_image=prepared.source_plan.identity.image,
                preserve_dst_ip=True,
                preserve_start_time=True,
                suppress_source_pid_inference=True,
                suppress_prereq_dns=True,
                ids_alerts=list(self._request.ids_alerts),
                transport_lifecycle_mode="deferred_session",
                deferred_session_authority=prepared.authority,
                identity_capture=prepared.identity_capture,
            )
        except BaseException as primary:
            self._recover_or_cancel_lifecycle_continuation(
                prepared.lifecycle_continuation,
                primary,
            )
            raise
        transaction = prepared.identity_capture.require()
        if uid != transaction.zeek_uid:
            raise AssertionError("Exact RDP reconnect received a different transport identity")
        self._executor._recover_exact_rdp_lifecycle_continuation_no_fail(
            prepared.lifecycle_continuation.bind()
        )
        self._rendered_logon_id = prepared.session_identity.logon_id
        return uid

    def _recover_or_cancel_lifecycle_continuation(
        self,
        prepared: _PreparedRdpLifecycleContinuation,
        primary: BaseException,
    ) -> None:
        """Retain committed close ownership or release one precommit reservation."""

        receipt = prepared.identity_capture.application_receipt
        committed = bool(
            type(receipt) is RdpSessionAdmissionReceipt
            and prepared.manager.authenticates_admission_receipt(receipt)
        )
        try:
            if committed:
                self._executor._recover_exact_rdp_lifecycle_continuation_no_fail(prepared.bind())
            else:
                self._executor._cancel_exact_rdp_lifecycle_continuation_reservation(prepared)
        except BaseException as recovery_error:
            primary.add_note(f"Exact RDP lifecycle recovery also failed: {recovery_error!r}")

    def _prepare_exact_reconnect(
        self,
        *,
        user: User,
        source_ip: str,
        source_system: System,
        source_port: int,
        reconnect_time: datetime,
        transport_close: datetime,
    ) -> _PreparedDeferredRdpReconnect:
        """Prepare one source-only ACTIVE RDP State/application owner graph."""

        state = self._executor.state_manager
        session_identity = state.get_session_identity(self._request.logon_id)
        if session_identity is None or session_identity.session_kind != "rdp":
            raise StateError("Exact RDP reconnect has no live Type-10 State identity")
        prior = self._executor._rdp_session_manager.get(session_identity.object_id)
        from evidenceforge.events.rdp import RdpSessionState

        if prior is None or prior.state is not RdpSessionState.DISCONNECTED:
            raise StateError("Exact RDP reconnect requires one disconnected logical session")
        source_session = self._executor._active_user_interactive_windows_session(
            user,
            source_system,
            self._request.time,
        )
        if source_session is None:
            raise StateError("Exact RDP reconnect requires a live source interactive session")
        source_session_identity = state.get_session_identity(source_session.logon_id)
        if source_session_identity is None:
            raise StateError("Exact RDP reconnect lost its source session identity")

        parent_pid = source_session.explorer_pid or source_session.process_tree_root or 4
        source_start = ensure_utc(reconnect_time)
        batch_builder = state.begin_materialization_batch()
        source_plan = batch_builder.plan_process(
            system=source_system.hostname,
            parent_pid=parent_pid,
            image=r"C:\Windows\System32\mstsc.exe",
            command_line=f"mstsc.exe /v:{self._request.target_system.hostname}",
            username=user.username,
            integrity_level="Medium",
            os_category="windows",
            logon_id=source_session_identity.logon_id,
            lifecycle_group_id=stable_uuid(
                "rdp-reconnect-source-lifecycle",
                self._request.stable_id,
            ),
            parent_lifecycle_group_id=source_session_identity.lifecycle_group_id,
            start_time=source_start,
            require_session=True,
            auth_session_id=source_session_identity.session_id,
            auth_logon_type=2,
        )
        batch = batch_builder.seal()
        existing_patch = state.prepare_connection_live_session_patch(
            session_identity,
            source_ip=source_ip,
            source_port=source_port,
            transport_pid=None,
            source_ready_time=ensure_utc(reconnect_time),
            network_close_time=ensure_utc(transport_close),
            end_plan=self._request.session_end_plan,
        )
        state_authority = state.prepare_deferred_session_state_authority(
            protocol=DeferredSessionProtocol.RDP,
            binding_disposition=DeferredSessionBindingDisposition.ACTIVE_SESSION,
            bound_at=ensure_utc(reconnect_time),
            batch=batch,
            existing_session_patch=existing_patch,
        )
        elevated = self._rdp_user_is_elevated(user)
        application_intent = DeferredRdpApplicationIntent(
            manager=self._executor._rdp_session_manager,
            source_host=source_system.hostname,
            target_host=self._request.target_system.hostname,
            principal=user.username,
            hard_deadline=prior.identity.hard_deadline,
            user_sid=self._executor._preview_sid(user.username),
            elevated=elevated,
            privilege_list=(
                self._executor._select_special_privileges(
                    user,
                    10,
                    self._request.target_system.hostname,
                )
                if elevated
                else ""
            ),
            allow_omitted_transport_actor=True,
            source_identity=source_plan.identity,
            source_session_identity=source_session_identity,
            prior_session=prior,
            expected_generation=prior.generation.ordinal + 1,
        )
        dependent_occurrences = (
            self._rdp_process_occurrence(source_plan, 1),
            DeferredSessionDependentOccurrenceSpec(
                occurrence_id=stable_uuid(
                    "rdp-deferred-reconnect-occurrence",
                    session_identity.object_id,
                    str(prior.generation.ordinal + 1),
                ),
                event_type=EventKind.RDP_RECONNECT,
                canonical_time=ensure_utc(reconnect_time),
                member_references=(session_identity.object_id,),
                publication_ordinal=2,
            ),
        )
        authority = DeferredSessionNetworkAuthority(
            kind=DeferredSessionKind.RDP,
            coordinator=DeferredSessionCompositionCoordinator(kind=DeferredSessionKind.RDP),
            bound_at=ensure_utc(reconnect_time),
            binding_disposition=DeferredSessionBindingDisposition.ACTIVE_SESSION,
            strict_state_authority=state_authority,
            application_intent=application_intent,
            dependent_occurrences=dependent_occurrences,
        )
        lifecycle_continuation = _PreparedRdpLifecycleContinuation(
            continuation_id=stable_uuid(
                "rdp-lifecycle-continuation",
                session_identity.object_id,
                str(prior.generation.ordinal + 1),
                self._request.stable_id,
            ),
            identity_capture=NetworkConnectionIdentityCapture(),
            manager=self._executor._rdp_session_manager,
            session_identity=session_identity,
            target_system=self._request.target_system,
            user=user,
            source_system=source_system,
            source_identity=source_plan.identity,
            source_session_identity=source_session_identity,
            hard_deadline=prior.identity.hard_deadline,
            expected_generation=prior.generation.ordinal + 1,
            source_tag=self._request.source,
        )
        prepared = _PreparedDeferredRdpReconnect(
            authority=authority,
            identity_capture=lifecycle_continuation.identity_capture,
            session_identity=session_identity,
            existing_session_patch=existing_patch,
            source_plan=source_plan,
            source_session_identity=source_session_identity,
            lifecycle_continuation=lifecycle_continuation,
        )
        self._executor._reserve_exact_rdp_lifecycle_continuation(lifecycle_continuation)
        return prepared

    @staticmethod
    def _rdp_process_occurrence(
        plan: ProcessMaterializationPlan,
        ordinal: int,
    ) -> DeferredSessionDependentOccurrenceSpec:
        """Return one typed initial RDP process-start specification."""

        return DeferredSessionDependentOccurrenceSpec(
            occurrence_id=stable_uuid(
                "rdp-deferred-process-occurrence",
                plan.identity.object_id,
            ),
            event_type=(
                EventKind.SYSTEM_PROCESS_CREATE
                if plan.identity.principal.casefold() == "system"
                else EventKind.PROCESS_CREATE
            ),
            canonical_time=plan.identity.started_at,
            member_references=(plan.identity.object_id,),
            publication_ordinal=ordinal,
        )

    def _publish_exact_terminal_cohort(
        self,
        *,
        continuation: _RdpLifecycleContinuation,
        phase: str,
        terminal_kind: str,
        state_plan: Any,
        event: Any,
        expected_identity: ProcessIdentity | SessionIdentity,
    ) -> _RdpTerminalProjectionTimingProof:
        """Publish one RDP terminal State/event owner with exact sink recovery."""

        from evidenceforge.generation.actions.command_effects import (
            ExecutionEffectAuditCohortEntry,
            ExecutionEffectPlan,
        )

        root_action_id = f"rdp-close:{continuation.continuation_id}:{phase}:{terminal_kind}"
        audit_plan = ExecutionEffectPlan(
            ActionAnchor(
                family="rdp_session",
                stable_id=root_action_id,
                source=continuation.prepared.source_tag,
            ),
            (),
        )
        audit_entry = ExecutionEffectAuditCohortEntry(
            audit_plan,
            audit_plan.reconcile(()),
        )
        dispatcher = self._executor.dispatcher
        carrier = None
        timing_preparation = None
        batch = None
        try:
            with dispatcher.source_timing_planner.prepared_planning() as timing_preparation:
                if terminal_kind == "process-terminate":
                    self._executor._plan_process_source_terminate_times(event)
                carrier = dispatcher.prepare_action_cohort_projection(
                    event,
                    source_timing_preparation=timing_preparation,
                )
            projection_facts = dispatcher.action_cohort_projection_facts(carrier)
            occurrence_id = projection_facts.occurrence.occurrence_id
            source_frontiers: list[tuple[str, int, datetime]] = []
            for source in projection_facts.sources:
                if source.format_name not in {
                    "ecar",
                    "windows_event_security",
                    "windows_security",
                } or source.status not in {"visible", "delayed"}:
                    continue
                finalized = tuple(value for _key, value in source.finalized_times)
                if not finalized and source.projected_timestamp is not None:
                    finalized = (source.projected_timestamp,)
                if finalized:
                    source_frontiers.append(
                        (source.format_name, source.source_ordinal, max(finalized))
                    )
            timing_proof = _RdpTerminalProjectionTimingProof(
                canonical_time=projection_facts.occurrence.timestamp,
                source_frontiers=tuple(source_frontiers),
                disposition=projection_facts.disposition,
            )
            if timing_proof.canonical_time != ensure_utc(event.timestamp):
                raise StateError("Exact RDP terminal projection changed its canonical time")
            prepared_dispatch = dispatcher.bind_action_cohort_projection(
                carrier,
                state_plan=state_plan,
            )
            batch = dispatcher.prepare_action_cohort_batch(
                root_action_id,
                state_plan,
                (prepared_dispatch,),
                (audit_entry,),
                (),
                (),
                exact_projection=True,
            )
        except BaseException as primary:
            if carrier is not None:
                try:
                    dispatcher.cancel_prepared_action_cohort_projection(carrier)
                except BaseException as cleanup_error:
                    primary.add_note(f"RDP terminal projection cleanup failed: {cleanup_error!r}")
            dispatcher.prune_prepared_action_cohort_projections()
            dispatcher.prune_prepared_action_cohort_batches()
            if timing_preparation is not None and not timing_preparation.committed:
                timing_preparation.cancel()
            raise

        capability = None
        try:
            with dispatcher.claimed_action_cohort(batch) as capability:
                result = capability.commit_no_fail()
        except BaseException as error:
            receipt = capability.receipt if capability is not None else None
            attached_result = capability.result if capability is not None else None
            authentic = bool(
                type(receipt) is ActionCohortPublicationReceipt
                and type(attached_result) is ActionCohortPublicationResult
                and attached_result.receipt is receipt
                and dispatcher.authenticates_action_cohort_publication_receipt(receipt)
                and receipt.root_action_id == root_action_id
                and receipt.state_semantic_id == state_plan.semantic_id
                and receipt.occurrence_ids == (occurrence_id,)
            )
            if not authentic:
                if batch is not None:
                    dispatcher.cancel_prepared_action_cohort_batch(batch)
                dispatcher.prune_prepared_action_cohort_batches()
                raise
            continuation.prepared.projection_ledger.retain_action_cohort(
                phase,
                receipt=receipt,
                result=attached_result,
                root_action_id=root_action_id,
                state_semantic_id=state_plan.semantic_id,
                occurrence_id=occurrence_id,
                timing_proof=timing_proof,
            )
            if terminal_kind == "process-terminate":
                self._executor._commit_exact_ssh_source_process_termination(event)
            try:
                object.__setattr__(error, "action_cohort_receipt", receipt)
                object.__setattr__(error, "action_cohort_result", attached_result)
            except BaseException as attachment_error:
                error.add_note(
                    f"Exact RDP terminal receipt attachment also failed: {attachment_error!r}"
                )
            raise

        if (
            type(result) is not ActionCohortPublicationResult
            or not dispatcher.authenticates_action_cohort_publication_receipt(result.receipt)
            or result.receipt.root_action_id != root_action_id
            or result.receipt.state_semantic_id != state_plan.semantic_id
            or result.receipt.occurrence_ids != (occurrence_id,)
            or result.state.semantic_id != state_plan.semantic_id
            or result.state.started_sessions
            or result.state.started_processes
            or len(result.projections) != 1
            or type(result.projections[0]) is not ActionCohortProjectionOutcome
            or result.projections[0].occurrence_id != occurrence_id
            or result.projections[0].status != "succeeded"
            or result.projections[0].error is not None
            or (
                terminal_kind == "process-terminate"
                and (
                    type(expected_identity) is not ProcessIdentity
                    or result.state.terminated_processes != (expected_identity,)
                    or result.state.terminalized_sessions
                )
            )
            or (
                terminal_kind == "logout"
                and (
                    type(expected_identity) is not SessionIdentity
                    or result.state.terminated_processes
                    or result.state.terminalized_sessions != (expected_identity,)
                )
            )
        ):
            raise StateError("Exact RDP terminal publication returned invalid proof")
        if terminal_kind == "process-terminate":
            self._executor._commit_exact_ssh_source_process_termination(event)
        continuation.prepared.mark_terminal_projection_complete(
            phase,
            timing_proof=timing_proof,
        )
        return timing_proof

    def terminate_exact_rdp_process(
        self,
        continuation: _RdpLifecycleContinuation,
        identity: ProcessIdentity,
        terminate_time: datetime,
    ) -> _RdpTerminalProjectionTimingProof:
        """Terminate one exact source or target RDP process with 4689/eCAR evidence."""

        phase = f"process:{identity.object_id}"
        session_identity = continuation.prepared.session_identity
        owning_session = (
            continuation.prepared.source_session_identity
            if continuation.prepared.source_session_identity is not None
            and continuation.prepared.source_session_identity.logon_id == identity.logon_id
            else session_identity
            if session_identity.logon_id == identity.logon_id
            else None
        )
        system = (
            continuation.prepared.source_system
            if continuation.prepared.source_system is not None
            and continuation.prepared.source_system.hostname == identity.hostname
            else continuation.prepared.target_system
        )
        event = self._terminal_process_event(
            identity=identity,
            terminate_time=terminate_time,
            system=system,
            session_identity=owning_session,
        )
        if continuation.prepared.recover_terminal_projection(
            phase,
            self._executor.dispatcher,
        ):
            self._executor._commit_exact_ssh_source_process_termination(event)
            timing_proof = continuation.prepared.terminal_projection_timing_proof(phase)
            if timing_proof is None:
                raise StateError("Exact RDP process recovery lost its timing proof")
            if timing_proof.canonical_time != ensure_utc(terminate_time):
                raise StateError("Exact RDP process recovery changed its canonical time")
            return timing_proof
        state_builder = self._executor.state_manager.begin_action_cohort_materialization()
        if owning_session is not None:
            state_builder.patch_session_activity(owning_session, terminate_time)
        state_builder.terminate_process(identity, end_time=terminate_time)
        state_plan = state_builder.seal()
        return self._publish_exact_terminal_cohort(
            continuation=continuation,
            phase=phase,
            terminal_kind="process-terminate",
            state_plan=state_plan,
            event=event,
            expected_identity=identity,
        )

    def _terminal_process_event(
        self,
        *,
        identity: ProcessIdentity,
        terminate_time: datetime,
        system: System,
        session_identity: SessionIdentity | None,
    ) -> Any:
        """Build one exact process-close occurrence from immutable State identity."""

        from evidenceforge.events.base import OccurrenceBuilder

        return OccurrenceBuilder(
            timestamp=ensure_utc(terminate_time),
            event_type=EventKind.PROCESS_TERMINATE,
            src_host=self._executor._build_host_context(system),
            auth=AuthContext(
                username=identity.principal,
                user_sid=self._executor._get_sid(identity.principal),
                logon_id=identity.logon_id,
                session_id=session_identity.session_id if session_identity is not None else 0,
                logon_type=(
                    10
                    if session_identity is not None and session_identity.session_kind == "rdp"
                    else 2
                ),
            ),
            process=ProcessContext(
                pid=identity.pid,
                parent_pid=identity.parent_pid,
                image=identity.image,
                command_line="",
                username=identity.principal,
                logon_id=identity.logon_id,
                start_time=identity.started_at,
            ),
            identity_plan=EventIdentityPlan(subject=identity, session=session_identity),
            lifecycle=ActionLifecycleContext(
                group_id=identity.lifecycle_group_id,
                canonical_start=identity.started_at,
                phase="closure",
                parent_group_id=identity.parent_lifecycle_group_id or None,
            ),
        )

    def logout_exact_rdp_session(
        self,
        continuation: _RdpLifecycleContinuation,
        logout_time: datetime,
    ) -> None:
        """Terminalize one exact RDP State session with Security 4634/eCAR evidence."""

        from evidenceforge.events.base import OccurrenceBuilder

        identity = continuation.prepared.session_identity
        transaction = continuation.transaction
        event = OccurrenceBuilder(
            timestamp=ensure_utc(logout_time),
            event_type=EventKind.LOGOFF,
            dst_host=self._executor._build_host_context(continuation.prepared.target_system),
            auth=AuthContext(
                username=identity.principal,
                user_sid=self._executor._get_sid(identity.principal),
                logon_id=identity.logon_id,
                session_id=identity.session_id,
                logon_type=10,
                source_ip=transaction.src_ip,
                source_port=transaction.src_port,
                session_kind="rdp",
                auth_protocol="rdp",
            ),
            identity_plan=EventIdentityPlan(subject=identity, session=identity),
            lifecycle=ActionLifecycleContext(
                group_id=identity.lifecycle_group_id,
                canonical_start=identity.started_at,
                phase="closure",
                parent_group_id=identity.parent_lifecycle_group_id or None,
            ),
        )
        if continuation.prepared.recover_terminal_projection(
            "logout",
            self._executor.dispatcher,
        ):
            return
        state_builder = self._executor.state_manager.begin_action_cohort_materialization()
        state_builder.terminalize_session(identity, end_time=logout_time)
        state_plan = state_builder.seal()
        self._publish_exact_terminal_cohort(
            continuation=continuation,
            phase="logout",
            terminal_kind="logout",
            state_plan=state_plan,
            event=event,
            expected_identity=identity,
        )

    def _rdp_user_is_elevated(self, user: User) -> bool:
        """Return the deterministic account-class privilege disposition."""

        classifier = getattr(self._executor, "_special_privilege_profile_name", None)
        if not callable(classifier):
            return False
        return classifier(user, 10, self._request.target_system.hostname) != "regular_user"

    def _resolve_source(self, rng: random.Random, user: User) -> tuple[str, System | None, int]:
        """Resolve the remote source host, avoiding impossible self-sourced RDP."""

        source_ip = self._request.source_ip
        source_system = self._request.source_system
        source_pid = self._request.source_pid
        if source_system is None:
            source_system = self._executor._ip_to_system.get(source_ip)
        if (
            source_system is not None
            and _get_os_category(source_system.os) != "windows"
            and _get_os_category(self._request.target_system.os) == "windows"
            and not self._request.preserve_explicit_source
        ):
            replacement = self._choose_windows_source(rng, user)
            if replacement is not None:
                return replacement.ip, replacement, -1
            return source_ip, None, -1
        if source_ip != self._request.target_system.ip:
            return source_ip, source_system, source_pid

        replacement = self._choose_windows_source(rng, user)
        if replacement is not None:
            return replacement.ip, replacement, -1
        return source_ip, None, -1

    def _choose_windows_source(self, rng: random.Random, user: User) -> System | None:
        """Choose a modeled Windows RDP client host when the request source is unusable."""

        candidates = sorted(
            {
                candidate.hostname: candidate
                for candidate in getattr(self._executor, "_ip_to_system", {}).values()
                if candidate.ip != self._request.target_system.ip
                and _get_os_category(candidate.os) == "windows"
            }.values(),
            key=lambda candidate: candidate.hostname,
        )
        workstations = [
            candidate
            for candidate in candidates
            if (candidate.type or "workstation").lower() == "workstation"
        ]
        preferred = [
            candidate
            for candidate in workstations or candidates
            if candidate.assigned_user == user.username
        ]
        return rng.choice(preferred or workstations or candidates) if candidates else None

    def _materialize_source_process(
        self,
        *,
        user: User,
        source_system: System | None,
        source_pid: int,
    ) -> int:
        """Ensure source-side mstsc.exe exists when the caller provides a factory."""

        if (
            source_pid > 0
            or source_system is None
            or self._request.source_process_time is None
            or self._source_process_factory is None
        ):
            return source_pid
        return self._source_process_factory(
            user=user,
            source_system=source_system,
            target_system=self._request.target_system,
            time=self._request.source_process_time,
        )

    def _transport_interval(
        self,
        uid: str,
        *,
        fallback_start: datetime,
        fallback_close: datetime,
    ) -> tuple[datetime, datetime]:
        """Return the canonical network interval for the generated RDP transport."""

        if not uid:
            return fallback_start, fallback_close
        connection = self._executor.state_manager.get_connection_by_zeek_uid(uid)
        if connection is None or connection.close_time is None:
            return fallback_start, fallback_close
        return connection.start_time, connection.close_time

    def _protect_source_client_lifecycle(
        self,
        *,
        source_system: System | None,
        source_pid: int,
        network_close_time: datetime,
    ) -> None:
        """Keep the source-side mstsc process/session alive through the transport close."""

        if source_system is None or source_pid <= 0:
            return
        seed = _stable_seed(
            "rdp_source_client_close:"
            f"{source_system.hostname}:{source_pid}:{self._request.target_system.hostname}:"
            f"{network_close_time.isoformat()}"
        )
        activity_time = network_close_time + timedelta(
            milliseconds=250 + (seed % 1750),
            microseconds=97 + (seed % 719),
        )
        state_manager = self._executor.state_manager
        state_manager.update_process_activity_time(
            source_system.hostname, source_pid, activity_time
        )
        process = state_manager.get_process(source_system.hostname, source_pid)
        if process is not None and process.logon_id:
            state_manager.update_session_activity_time(process.logon_id, activity_time)

    def _target_logon_time(
        self,
        *,
        source_ip: str,
        src_port: int,
        transport_start_time: datetime | None = None,
    ) -> datetime:
        """Resolve canonical target authentication after the RDP transport starts."""

        timing = self._timing_planner()
        timing_id = (
            f"{self._request.stable_id}:transport:{source_ip}:{src_port}:"
            f"{self._request.target_system.ip}:3389:tcp:rdp"
        )
        observed_connection_time = transport_start_time
        if observed_connection_time is None:
            window = get_timing_window(
                "network.connection_start_jitter",
                default_min_ms=0,
                default_max_ms=0,
                default_position="after",
            )
            network_timing = BaselineTimingPlanner(timing.runtime, source="network")
            minimum_seconds = window.min_ms / 1_000
            maximum_seconds = (
                minimum_seconds
                if window.max_ms <= window.min_ms
                else ((window.max_ms * 1_000) + 1) / 1_000_000
            )
            observed_connection_time = self._request.time + timedelta(
                seconds=network_timing.triangular_seconds(
                    relationship_key="network.connection_start_jitter",
                    stable_id=timing_id,
                    minimum=minimum_seconds,
                    mode=(window.min_ms + (window.max_ms - window.min_ms) * 0.35) / 1_000,
                    maximum=maximum_seconds,
                    host=source_ip,
                    lifecycle_id=self._request.stable_id,
                    sample_key="transport_open",
                )
            )
        target_logon_gap = timing.triangular_seconds(
            relationship_key="rdp.target_logon_after_transport",
            stable_id=timing_id,
            minimum=0.899999,
            mode=1.12,
            maximum=1.600001,
            host=self._request.target_system.hostname,
            lifecycle_id=self._request.stable_id,
            sample_key="target_logon",
        )
        graph = TemporalConstraintGraph()
        graph.add_node(
            "transport_observed",
            observed_connection_time,
            not_before=self._request.time,
        )
        graph.add_node(
            "target_logon",
            observed_connection_time + timedelta(seconds=target_logon_gap),
        )
        graph.constrain_after(
            "target_logon",
            "transport_observed",
            min_gap=timedelta(milliseconds=900),
        )
        resolved = graph.resolved_time("target_logon")
        if self._request.logon_id:
            flow_window = get_timing_window(
                "source.ecar_flow",
                default_min_ms=180,
                default_max_ms=1800,
                default_position="after",
                default_class="source_latency",
            )
            resolved = max(
                resolved,
                ensure_utc(transport_start_time or self._request.time)
                + timedelta(milliseconds=flow_window.max_ms + 25),
            )
            prior_source_close = self._executor._rdp_reconnect_source_frontier(
                self._request.logon_id
            )
            if prior_source_close is not None and resolved <= prior_source_close:
                resolved = prior_source_close + timedelta(milliseconds=100)
        return resolved
