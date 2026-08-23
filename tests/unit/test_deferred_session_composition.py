# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Frozen owner-level SSH/RDP deferred-session composition contracts."""

import gc
import json
import random
import re
from collections.abc import Callable
from copy import copy, deepcopy
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier, Lock, Thread
from unittest.mock import Mock

import pytest

from evidenceforge.events.application import (
    ApplicationChannelBudget,
    ApplicationTransportBinding,
)
from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.collection_policy import (
    SourceCollectionPolicy,
    SourceInstanceIdentity,
)
from evidenceforge.events.contexts import (
    AuthContext,
    HostContext,
    IdsAlertPlan,
    IdsAlertPolicyContext,
    IdsEventFilterContext,
    ProcessContext,
    SyslogContext,
)
from evidenceforge.events.dispatcher import (
    EventDispatcher,
    PreparedDispatch,
    PreparedDispatchStateIntent,
)
from evidenceforge.events.identity import EventIdentityPlan, ProcessIdentity
from evidenceforge.events.lifecycle import ActionLifecycleContext, LifecycleHold
from evidenceforge.events.network import (
    DirectionalTrafficLedger,
    NatSensorObservation,
    NetworkSensorObservation,
    NetworkTrafficLedger,
    NetworkTransactionPlan,
    NetworkTuple,
)
from evidenceforge.events.observation import ObservationPolicy
from evidenceforge.events.rdp import (
    RdpLogicalSessionIdentity,
    RdpSessionAffinity,
    RdpTransportPlan,
)
from evidenceforge.events.source_catalog import DEFAULT_SOURCE_CATALOG
from evidenceforge.formats import load_format
from evidenceforge.generation.actions.network_connection import (
    DeferredRdpApplicationIntent,
    DeferredSessionNetworkAuthority,
    DeferredSessionStateIntent,
    NetworkConnectionActionBundle,
    NetworkConnectionRequest,
)
from evidenceforge.generation.actions.network_transaction_planner import (
    _PreparedNetworkBoundary,
)
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.application_channels import ApplicationChannelRegistry
from evidenceforge.generation.collection_deployment import (
    CompiledCollectionDeployment,
    SourceInstanceDeployment,
)
from evidenceforge.generation.cryptographic_material import CryptographicMaterialRegistry
from evidenceforge.generation.deferred_session_composition import (
    DeferredSessionComposition,
    DeferredSessionCompositionCoordinator,
    DeferredSessionKind,
    DeferredSessionStateMemberBinding,
)
from evidenceforge.generation.deferred_session_preseal import (
    DeferredSessionBindingDisposition,
    DeferredSessionProtocol,
)
from evidenceforge.generation.emitters.base import (
    ExactPublicationAuthority,
    ExactPublicationBatch,
    ExactPublicationKey,
    LogEmitter,
)
from evidenceforge.generation.emitters.cisco_asa import CiscoAsaEmitter
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.generation.emitters.snort import SnortEmitter
from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter
from evidenceforge.generation.emitters.syslog import SyslogEmitter
from evidenceforge.generation.emitters.sysmon import SysmonEventEmitter
from evidenceforge.generation.emitters.zeek import ZeekEmitter
from evidenceforge.generation.intent_ledger import (
    AuthoredIntentLedger,
    IntentExecutionBatchReceipt,
    IntentExecutionLedger,
    PreparedIntentExecutionBatch,
)
from evidenceforge.generation.lifecycle_authority import (
    GeneratorLifecycleAuthority,
    LifecycleConnectionCompositeReceipt,
)
from evidenceforge.generation.lifecycle_production_adapters import (
    LifecycleProductionAdapter,
    closed_transport_publication_plan,
)
from evidenceforge.generation.lifecycle_registry import (
    LifecycleClosedTransportAdmissionToken,
    LifecycleRegistry,
    PreparedLifecycleClosedTransportPublication,
)
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.generation.network_runtime import (
    NetworkTransactionPreparedCommit,
    NetworkTransactionRuntime,
    NetworkTransportLifecycleMode,
    PreparedNetworkTransactionRoot,
)
from evidenceforge.generation.rdp_sessions import (
    RdpReconnectStateManager,
    RdpSessionAdmissionToken,
)
from evidenceforge.generation.source_deployment_compiler import exact_source_instance_id
from evidenceforge.generation.source_finalization import SourceFinalizationCoordinator
from evidenceforge.generation.source_timing import SourceTimingPlanner, SourceTimingPreparation
from evidenceforge.generation.ssh_channels import (
    SshApplicationChannelManager,
    SshChannelAdmissionToken,
    SshChannelAffinity,
    SshChannelPreparedCommit,
    SshOperationKind,
    SshProcessHold,
    SshSessionBinding,
    SshTransportPlan,
)
from evidenceforge.generation.state_manager import (
    ConnectionMaterializationMode,
    ProcessActivityPatch,
    ProcessMaterializationPlan,
    SessionActivityPatch,
    SessionMaterializationPlan,
    StateManager,
)
from evidenceforge.models.exceptions import EventContractError, StateError
from evidenceforge.models.scenario import System

_START = datetime(2026, 8, 17, 13, 0, tzinfo=UTC)
_END = _START + timedelta(days=1)


@dataclass(frozen=True, slots=True)
class _Fixture:
    """Keep every live owner and exact capability used by one composition."""

    kind: DeferredSessionKind
    coordinator: DeferredSessionCompositionCoordinator
    state: StateManager
    runtime: NetworkTransactionRuntime
    lifecycle_registry: LifecycleRegistry
    application_owner: object | None
    timing_planner: SourceTimingPlanner
    owner_rng: random.Random
    prepared_root: PreparedNetworkTransactionRoot
    source_timing_preparation: SourceTimingPreparation
    lifecycle_token: LifecycleClosedTransportAdmissionToken
    state_members: tuple[DeferredSessionStateMemberBinding, ...]
    session_plan: SessionMaterializationPlan
    process_plan: ProcessMaterializationPlan | None
    application_token: SshChannelAdmissionToken | RdpSessionAdmissionToken | None
    transport_dispatch: PreparedDispatch
    dependent_dispatches: tuple[PreparedDispatch, ...]
    binding_time: datetime
    process_holds: tuple[LifecycleHold, ...]

    def issue(self, **overrides: object) -> DeferredSessionComposition:
        """Issue with this fixture's exact objects plus explicit test overrides."""

        arguments: dict[str, object] = {
            "prepared_root": self.prepared_root,
            "source_timing_preparation": self.source_timing_preparation,
            "lifecycle_token": self.lifecycle_token,
            "state_members": self.state_members,
            "application_token": self.application_token,
            "transport_dispatch": self.transport_dispatch,
            "dependent_dispatches": self.dependent_dispatches,
        }
        arguments.update(overrides)
        return self.coordinator.issue(**arguments)


def _transaction(
    *,
    stable_id: str,
    conn_id: str,
    zeek_uid: str,
    dst_port: int,
    started_at: datetime = _START,
    src_port: int = 50_001,
) -> NetworkTransactionPlan:
    """Return one closed successful SSH or RDP transport."""

    closed_at = started_at + timedelta(seconds=30)
    return NetworkTransactionPlan(
        stable_id=stable_id,
        hostname="db-01.example.test",
        outcome="success",
        phase_times=(("transport_start", started_at), ("transport_close", closed_at)),
        started_at=started_at,
        closed_at=closed_at,
        src_ip="10.0.0.10",
        src_port=src_port,
        dst_ip="10.0.0.20",
        dst_port=dst_port,
        protocol="tcp",
        service="ssh" if dst_port == 22 else "rdp",
        zeek_uid=zeek_uid,
        conn_id=conn_id,
        duration=30.0,
        conn_state="SF",
        history="ShADadFf",
        traffic=NetworkTrafficLedger(
            orig=DirectionalTrafficLedger(payload_bytes=4_000, packets=4, ip_bytes=5_000),
            resp=DirectionalTrafficLedger(payload_bytes=8_000, packets=8, ip_bytes=10_000),
        ),
    )


def _prepared_dispatch(message: str, *, offset_ms: int) -> PreparedDispatch:
    """Return a real opaque dispatch; composition deliberately does not inspect its intent."""

    dispatcher = EventDispatcher(state_manager=StateManager(), emitters={})
    return dispatcher.prepare_builder(
        OccurrenceBuilder(
            timestamp=_START + timedelta(milliseconds=offset_ms),
            event_type="syslog",
            src_host=HostContext(
                hostname="DB-01",
                ip="10.0.0.20",
                os="Ubuntu 24.04",
                os_category="linux",
                system_type="server",
            ),
            syslog=SyslogContext(
                app_name="systemd",
                pid=1,
                facility=3,
                severity=6,
                message=message,
            ),
        )
    )


def _sealed_timing(planner: SourceTimingPlanner) -> SourceTimingPreparation:
    """Return one authentic sealed and uncommitted timing preparation."""

    with planner.prepared_planning() as preparation:
        pass
    return preparation


def _ssh_application_token(
    root: PreparedNetworkTransactionRoot,
    session_plan: SessionMaterializationPlan,
    process_plan: ProcessMaterializationPlan,
    *,
    session_object_id: str | None = None,
) -> tuple[SshApplicationChannelManager, SshChannelAdmissionToken]:
    """Prepare one internally coherent SSH token over the selected session object."""

    transaction = root.transaction
    assert transaction.closed_at is not None
    selected_session_id = session_object_id or session_plan.identity.object_id
    registry = ApplicationChannelRegistry(
        window_start=_START,
        window_end=_END,
        shard_count=8,
    )
    manager = SshApplicationChannelManager(
        application_registry=registry,
        window_start=_START,
        window_end=_END,
    )
    ready_at = max(
        _START + timedelta(milliseconds=120),
        process_plan.identity.started_at + timedelta(milliseconds=10),
    )
    receiver = SshProcessHold(
        hostname=process_plan.identity.hostname,
        pid=process_plan.identity.pid,
        process_object_id=process_plan.identity.object_id,
        session_object_id=selected_session_id,
        principal=session_plan.identity.principal,
        started_at=process_plan.identity.started_at,
        required_until=transaction.closed_at,
    )
    transport = SshTransportPlan(
        transport_id=transaction.stable_id,
        zeek_uid=transaction.zeek_uid,
        conn_id=transaction.conn_id,
        source_ip=transaction.src_ip,
        server_ip=transaction.dst_ip,
        source_port=transaction.src_port,
        server_port=transaction.dst_port,
        opened_at=transaction.started_at,
        closes_at=transaction.closed_at,
        receiver_process=receiver,
    )
    binding = SshSessionBinding(
        hostname=session_plan.identity.hostname,
        logon_id=session_plan.identity.logon_id,
        session_object_id=selected_session_id,
        lifecycle_group_id=session_plan.identity.lifecycle_group_id,
        principal=session_plan.identity.principal,
        ready_at=ready_at,
    )
    token = manager.prepare_open_session_with_completed_operation(
        SshChannelAffinity(
            client_identity="ws-01",
            client_session_object_id="source-session-1",
            server_identity=session_plan.identity.hostname,
            server_session_object_id=selected_session_id,
            principal=session_plan.identity.principal,
            auth_method="password",
        ),
        transport=transport,
        binding=binding,
        idle_timeout=transaction.closed_at - ready_at,
        initiator_budget=transaction.orig_bytes,
        responder_budget=transaction.resp_bytes,
        operation_budget=1,
        kind=SshOperationKind.EXEC,
        semantic_operation_id="ssh-command-1",
        started_at=ready_at,
        ended_at=transaction.closed_at,
        initiator_bytes=transaction.orig_bytes,
        responder_bytes=transaction.resp_bytes,
    )
    return manager, token


def _rdp_application_token(
    root: PreparedNetworkTransactionRoot,
    session_plan: SessionMaterializationPlan,
    *,
    manager: RdpReconnectStateManager | None = None,
) -> tuple[RdpReconnectStateManager, RdpSessionAdmissionToken]:
    """Prepare one initial RDP logical-session generation over the root transport."""

    transaction = root.transaction
    assert transaction.closed_at is not None
    if manager is None:
        registry = ApplicationChannelRegistry(
            window_start=_START,
            window_end=_END,
            shard_count=8,
        )
        manager = RdpReconnectStateManager(
            application_registry=registry,
            window_start=_START,
            window_end=_END,
        )
    connected_at = transaction.started_at
    identity = RdpLogicalSessionIdentity(
        logical_session_id=session_plan.identity.object_id,
        affinity=RdpSessionAffinity(
            source_host="WS-01",
            source_address=transaction.src_ip,
            target_host=session_plan.identity.hostname,
            target_address=transaction.dst_ip,
            principal=session_plan.identity.principal,
            logon_id=session_plan.identity.logon_id,
            session_id=session_plan.identity.session_id,
        ),
        started_at=connected_at,
        idle_timeout=timedelta(minutes=10),
        reconnect_timeout=timedelta(minutes=5),
        hard_deadline=_END,
        budget=ApplicationChannelBudget(
            initiator_bytes=transaction.orig_bytes,
            responder_bytes=transaction.resp_bytes,
            operations=1,
        ),
    )
    token = manager.prepare_open_session(
        identity,
        RdpTransportPlan(
            channel_id=f"rdp-channel-{transaction.stable_id}",
            binding=ApplicationTransportBinding(
                transport_id=transaction.stable_id,
                opened_at=transaction.started_at,
                closes_at=transaction.closed_at,
            ),
            connected_at=connected_at,
            budget=identity.budget,
        ),
    )
    return manager, token


def _fixture(
    kind: DeferredSessionKind,
    *,
    with_application: bool = True,
    lifecycle_mode: NetworkTransportLifecycleMode = "deferred_session",
    dst_port: int | None = None,
    include_holds: bool = True,
    process_start_offset_ms: int = 110,
    include_responder_process: bool = False,
) -> _Fixture:
    """Build one complete uncommitted owner composition using only public planners."""

    expected_port = 22 if kind is DeferredSessionKind.SSH else 3389
    effective_port = expected_port if dst_port is None else dst_port
    state = StateManager()
    crypto = CryptographicMaterialRegistry()
    runtime = NetworkTransactionRuntime(
        state_manager=state,
        cryptographic_material=crypto,
        window_start=_START,
        window_end=_END,
    )
    owner_rng = random.Random(17)
    preparation = runtime.begin(
        owner_rng=owner_rng,
        stable_id=f"{kind.value}-transport-1",
        linearization_time=_START,
    )
    connection_identity = preparation.reserve_physical_identity()

    batch_builder = state.begin_materialization_batch()
    session_plan = batch_builder.plan_session(
        username="analyst",
        system="DB-01",
        logon_type=10,
        source_ip="10.0.0.10",
        start_time=_START + timedelta(milliseconds=100),
        source_ready_time=(
            _START + timedelta(milliseconds=120 if kind is DeferredSessionKind.SSH else 100)
        ),
        session_kind=kind.value,
    )
    process_plan: ProcessMaterializationPlan | None = None
    if kind is DeferredSessionKind.SSH or include_responder_process:
        is_ssh = kind is DeferredSessionKind.SSH
        process_plan = batch_builder.plan_process(
            system="DB-01",
            parent_pid=0,
            image=("/usr/sbin/sshd" if is_ssh else r"C:\Windows\System32\rdpclip.exe"),
            command_line=("sshd: analyst@pts/0" if is_ssh else "rdpclip.exe"),
            username="analyst",
            integrity_level="Medium",
            os_category=("linux" if is_ssh else "windows"),
            logon_id=session_plan.identity.logon_id,
            start_time=_START + timedelta(milliseconds=process_start_offset_ms),
            require_session=True,
            session_plan=session_plan,
            auth_session_id=session_plan.identity.session_id,
            auth_logon_type=10,
        )
        batch_builder.bind_session_processes(
            session_plan,
            transport_plan=process_plan,
            process_tree_root_plan=process_plan,
        )
    batch = batch_builder.seal()
    transaction = _transaction(
        stable_id=f"{kind.value}-transport-1",
        conn_id=connection_identity.conn_id,
        zeek_uid=connection_identity.zeek_uid,
        dst_port=effective_port,
    )
    assert transaction.closed_at is not None
    process_activity = (
        ()
        if process_plan is None
        else (ProcessActivityPatch(process_plan.identity, transaction.closed_at),)
    )
    session_activity = (
        ()
        if process_plan is None
        else (SessionActivityPatch(session_plan.identity, transaction.closed_at),)
    )
    root = preparation.seal(
        transaction=transaction,
        lifecycle_mode=lifecycle_mode,
        materialization_mode=ConnectionMaterializationMode.PHYSICAL,
        source_system="WS-01",
        source_hostname="ws-01.example.test",
        hostname="db-01.example.test",
        initiating_pid=-1,
        batch=batch,
        process_activity=process_activity,
        session_activity=session_activity,
    )

    lifecycle_registry = LifecycleRegistry(shard_count=8)
    authority = GeneratorLifecycleAuthority(
        state,
        LifecycleShadow(state, lifecycle_registry),
        shard_count=8,
    )
    lifecycle_adapter = LifecycleProductionAdapter(lifecycle_registry)
    lifecycle_members = authority.connection_composite_start_members(root.state_plan)
    state_plans = (
        *((batch.session,) if batch.session is not None else ()),
        *batch.processes,
    )
    process_holds: tuple[LifecycleHold, ...] = ()
    if process_plan is not None and include_holds:
        lifecycle_process = next(
            member
            for member in lifecycle_members
            if member.publication_token == process_plan.publication_token
        )
        process_holds = (
            LifecycleHold(
                hold_id=f"{kind.value}-receiver-hold",
                subject=lifecycle_process.request.identity.ref,
                acquired_at=process_plan.identity.started_at,
                hold_until=transaction.closed_at,
                action_id=f"{kind.value}-transport-hold",
                reason="canonical_transport_close",
            ),
        )
    binding_time = _START + timedelta(milliseconds=120 if kind is DeferredSessionKind.SSH else 100)
    if process_plan is not None:
        binding_time = max(
            binding_time,
            process_plan.identity.started_at + timedelta(milliseconds=10),
        )
    lifecycle_plan = closed_transport_publication_plan(
        transaction=transaction,
        authority_hostname="WS-01",
        src_hostname="WS-01",
        dst_hostname="DB-01",
        session_object_id=session_plan.identity.object_id,
        binding_role="session",
        bound_at=binding_time,
        action_id=f"{kind.value}-session-action",
    )
    lifecycle_token = lifecycle_adapter.prepare_closed_transport_publication(
        lifecycle_plan,
        start_members=lifecycle_members,
        process_holds=process_holds,
    )
    token_lifecycle_by_publication = {
        member.publication_token: member for member in lifecycle_token.request.start_members
    }
    state_members = tuple(
        DeferredSessionStateMemberBinding(
            state_member=member,
            lifecycle_member=token_lifecycle_by_publication[member.publication_token],
        )
        for member in state_plans
    )

    application_owner: object | None = None
    application_token: SshChannelAdmissionToken | RdpSessionAdmissionToken | None = None
    if with_application and kind is DeferredSessionKind.SSH:
        assert process_plan is not None
        application_owner, application_token = _ssh_application_token(
            root,
            session_plan,
            process_plan,
        )
    elif with_application:
        application_owner, application_token = _rdp_application_token(root, session_plan)

    timing_planner = SourceTimingPlanner()
    return _Fixture(
        kind=kind,
        coordinator=DeferredSessionCompositionCoordinator(kind=kind),
        state=state,
        runtime=runtime,
        lifecycle_registry=lifecycle_registry,
        application_owner=application_owner,
        timing_planner=timing_planner,
        owner_rng=owner_rng,
        prepared_root=root,
        source_timing_preparation=_sealed_timing(timing_planner),
        lifecycle_token=lifecycle_token,
        state_members=state_members,
        session_plan=session_plan,
        process_plan=process_plan,
        application_token=application_token,
        transport_dispatch=_prepared_dispatch("transport", offset_ms=1),
        dependent_dispatches=(_prepared_dispatch("session", offset_ms=2),),
        binding_time=binding_time,
        process_holds=process_holds,
    )


def _bound_authority(fixture: _Fixture) -> GeneratorLifecycleAuthority:
    """Return a facade bound to every exact owner retained by the fixture."""

    authority = GeneratorLifecycleAuthority(
        fixture.state,
        LifecycleShadow(fixture.state, fixture.lifecycle_registry),
        shard_count=8,
    )
    authority.bind_network_transaction_runtime(fixture.runtime)
    authority.bind_source_timing_planner(fixture.timing_planner)
    if fixture.kind is DeferredSessionKind.SSH:
        assert type(fixture.application_owner) is SshApplicationChannelManager
        authority.bind_ssh_channel_manager(fixture.application_owner)
    else:
        assert type(fixture.application_owner) is RdpReconnectStateManager
        authority.bind_rdp_session_manager(fixture.application_owner)
    return authority


def _replacement_lifecycle_token(
    fixture: _Fixture,
    *,
    transaction: NetworkTransactionPlan | None = None,
    process_holds: tuple[LifecycleHold, ...] | None = None,
) -> LifecycleClosedTransportAdmissionToken:
    """Prepare an independently authentic lifecycle token with selected relations."""

    selected_transaction = transaction or fixture.prepared_root.transaction
    registry = LifecycleRegistry(shard_count=8)
    adapter = LifecycleProductionAdapter(registry)
    plan = closed_transport_publication_plan(
        transaction=selected_transaction,
        authority_hostname="WS-01",
        src_hostname="WS-01",
        dst_hostname="DB-01",
        session_object_id=fixture.session_plan.identity.object_id,
        binding_role="session",
        bound_at=fixture.binding_time,
        action_id=f"replacement-{fixture.kind.value}-session-action",
    )
    return adapter.prepare_closed_transport_publication(
        plan,
        start_members=tuple(member.lifecycle_member for member in fixture.state_members),
        process_holds=fixture.process_holds if process_holds is None else process_holds,
    )


def _state_members_for_token(
    fixture: _Fixture,
    token: LifecycleClosedTransportAdmissionToken,
) -> tuple[DeferredSessionStateMemberBinding, ...]:
    """Rebind the same State plans to a replacement token's copied request members."""

    lifecycle_by_publication = {
        member.publication_token: member for member in token.request.start_members
    }
    return tuple(
        DeferredSessionStateMemberBinding(
            state_member=binding.state_member,
            lifecycle_member=lifecycle_by_publication[binding.state_member.publication_token],
        )
        for binding in fixture.state_members
    )


@pytest.mark.parametrize("kind", (DeferredSessionKind.SSH, DeferredSessionKind.RDP))
def test_coordinator_issues_valid_ssh_and_rdp_compositions(
    kind: DeferredSessionKind,
) -> None:
    fixture = _fixture(kind)

    composition = fixture.issue()

    assert fixture.coordinator.authenticates(composition)
    assert composition.kind is kind
    assert composition.prepared_root is fixture.prepared_root
    assert composition.source_timing_preparation is fixture.source_timing_preparation
    assert composition.lifecycle_token is fixture.lifecycle_token
    assert composition.application_token is fixture.application_token
    assert composition.state_members == fixture.state_members
    assert composition.publication_order == (
        fixture.transport_dispatch,
        *fixture.dependent_dispatches,
    )
    assert composition.physical_transport_id == fixture.prepared_root.transaction.stable_id
    assert composition.expected_state_version == fixture.prepared_root.state_plan.expected_version
    assert composition.publication_token


@pytest.mark.parametrize("kind", (DeferredSessionKind.SSH, DeferredSessionKind.RDP))
def test_coordinator_rejects_missing_persistent_manager_admission_neutrally(
    kind: DeferredSessionKind,
) -> None:
    """Strict deferred protocol authority cannot omit its persistent sidecar owner."""

    fixture = _fixture(kind, with_application=False)
    before_referents = tuple(sorted(id(item) for item in gc.get_referents(fixture.coordinator)))
    before_state_version = fixture.state.materialization_version
    before_lifecycle = fixture.lifecycle_registry.census()
    before_runtime = fixture.runtime.census()
    before_timing = fixture.timing_planner.census()

    with pytest.raises(StateError, match="persistent manager admission"):
        fixture.issue()

    assert (
        tuple(sorted(id(item) for item in gc.get_referents(fixture.coordinator)))
        == before_referents
    )
    assert fixture.state.materialization_version == before_state_version
    assert fixture.lifecycle_registry.census() == before_lifecycle
    assert fixture.runtime.census() == before_runtime
    assert fixture.timing_planner.census() == before_timing


@pytest.mark.parametrize("kind", (DeferredSessionKind.SSH, DeferredSessionKind.RDP))
def test_strict_network_authority_rejects_missing_manager_before_preparation(
    kind: DeferredSessionKind,
) -> None:
    fixture = _fixture(kind, with_application=False)
    batch = fixture.prepared_root.state_plan.batch
    assert batch is not None

    with pytest.raises(ValueError, match="persistent manager admission"):
        DeferredSessionNetworkAuthority(
            kind=kind,
            coordinator=fixture.coordinator,
            bound_at=fixture.binding_time,
            session_object_id=fixture.session_plan.identity.object_id,
            state_batch=batch,
        )

    assert fixture.state.get_session(fixture.session_plan.identity.logon_id) is None
    assert fixture.lifecycle_registry.get_session(fixture.session_plan.identity.object_id) is None


def test_strict_state_payload_binds_exact_outer_network_authority_once() -> None:
    fixture = _fixture(DeferredSessionKind.SSH)
    batch = fixture.prepared_root.state_plan.batch
    assert batch is not None and batch.session is fixture.session_plan
    assert fixture.application_token is not None
    assert type(fixture.application_owner) is SshApplicationChannelManager
    bound_at = fixture.binding_time
    digest = fixture.state.materialization_digest()
    payload = fixture.state.prepare_deferred_session_state_authority(
        protocol=DeferredSessionProtocol.SSH,
        binding_disposition=DeferredSessionBindingDisposition.NEW_SESSION,
        bound_at=bound_at,
        batch=batch,
    )
    with pytest.raises(ValueError, match="disposition changed"):
        DeferredSessionNetworkAuthority(
            kind=DeferredSessionKind.SSH,
            coordinator=fixture.coordinator,
            bound_at=bound_at,
            binding_disposition=DeferredSessionBindingDisposition.ACTIVE_SESSION,
            strict_state_authority=payload,
            application_manager=fixture.application_owner,
            application_token=fixture.application_token,
        )
    assert not payload.outer_bound
    authority = DeferredSessionNetworkAuthority(
        kind=DeferredSessionKind.SSH,
        coordinator=fixture.coordinator,
        bound_at=bound_at,
        binding_disposition=DeferredSessionBindingDisposition.NEW_SESSION,
        strict_state_authority=payload,
        application_manager=fixture.application_owner,
        application_token=fixture.application_token,
    )

    assert authority.has_strict_state_authority
    assert not authority.strict_state_authority_bound
    with pytest.raises(StateError, match="another owner"):
        authority.bind_strict_state_authority(StateManager())
    assert not payload.outer_bound
    authority.bind_strict_state_authority(fixture.state)
    assert authority.strict_state_authority_bound
    assert fixture.state.authenticates_deferred_session_state_authority(
        payload,
        outer_authority=authority,
    )
    assert not fixture.state.authenticates_deferred_session_state_authority(
        payload,
        outer_authority=copy(authority),
    )
    with pytest.raises(StateError, match="already owns a network handoff"):
        authority.bind_strict_state_authority(fixture.state)
    with pytest.raises(ValueError, match="failed authentication"):
        replace(authority)
    object.__setattr__(authority, "session_object_id", "tampered-session")
    assert not fixture.state.authenticates_deferred_session_state_authority(
        payload,
        outer_authority=authority,
    )
    assert fixture.state.materialization_digest() == digest


def test_composition_hmac_binds_strict_state_disposition() -> None:
    fixture = _fixture(DeferredSessionKind.SSH)
    batch = fixture.prepared_root.state_plan.batch
    assert batch is not None
    payload = fixture.state.prepare_deferred_session_state_authority(
        protocol=DeferredSessionProtocol.SSH,
        binding_disposition=DeferredSessionBindingDisposition.NEW_SESSION,
        bound_at=fixture.binding_time,
        batch=batch,
    )
    composition = fixture.issue(
        binding_disposition=DeferredSessionBindingDisposition.NEW_SESSION,
        state_authority=payload,
    )

    assert not fixture.coordinator.authenticates(composition)
    assert fixture.application_token is not None
    assert type(fixture.application_owner) is SshApplicationChannelManager
    authority = DeferredSessionNetworkAuthority(
        kind=DeferredSessionKind.SSH,
        coordinator=fixture.coordinator,
        bound_at=payload.bound_at,
        binding_disposition=DeferredSessionBindingDisposition.NEW_SESSION,
        strict_state_authority=payload,
        application_manager=fixture.application_owner,
        application_token=fixture.application_token,
    )
    authority.bind_strict_state_authority(fixture.state)
    assert fixture.coordinator.authenticates(composition)
    assert composition.binding_disposition is DeferredSessionBindingDisposition.NEW_SESSION
    tampered = replace(
        composition,
        binding_disposition=DeferredSessionBindingDisposition.ACTIVE_SESSION,
    )
    assert not fixture.coordinator.authenticates(tampered)
    with pytest.raises(StateError, match="requires exact State authority"):
        fixture.issue(binding_disposition=DeferredSessionBindingDisposition.NEW_SESSION)
    with pytest.raises(StateError, match="replaced its exact State authority"):
        fixture.issue(
            binding_disposition=DeferredSessionBindingDisposition.ACTIVE_SESSION,
            state_authority=payload,
        )


def test_strict_state_payload_allows_only_one_competing_outer_authority() -> None:
    fixture = _fixture(DeferredSessionKind.SSH)
    batch = fixture.prepared_root.state_plan.batch
    assert batch is not None and fixture.application_token is not None
    assert type(fixture.application_owner) is SshApplicationChannelManager
    payload = fixture.state.prepare_deferred_session_state_authority(
        protocol=DeferredSessionProtocol.SSH,
        binding_disposition=DeferredSessionBindingDisposition.NEW_SESSION,
        bound_at=fixture.binding_time,
        batch=batch,
    )

    def authority() -> DeferredSessionNetworkAuthority:
        return DeferredSessionNetworkAuthority(
            kind=DeferredSessionKind.SSH,
            coordinator=fixture.coordinator,
            bound_at=fixture.binding_time,
            binding_disposition=DeferredSessionBindingDisposition.NEW_SESSION,
            strict_state_authority=payload,
            application_manager=fixture.application_owner,
            application_token=fixture.application_token,
        )

    candidates = (authority(), authority())
    digest = fixture.state.materialization_digest()
    barrier = Barrier(3)
    outcomes: list[tuple[str, DeferredSessionNetworkAuthority]] = []

    def bind(candidate: DeferredSessionNetworkAuthority) -> None:
        barrier.wait()
        try:
            candidate.bind_strict_state_authority(fixture.state)
        except StateError:
            outcomes.append(("rejected", candidate))
        else:
            outcomes.append(("bound", candidate))

    threads = tuple(Thread(target=bind, args=(candidate,)) for candidate in candidates)
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join()

    assert sorted(status for status, _candidate in outcomes) == ["bound", "rejected"]
    winner = next(candidate for status, candidate in outcomes if status == "bound")
    assert fixture.state.authenticates_deferred_session_state_authority(
        payload,
        outer_authority=winner,
    )
    assert fixture.state.materialization_digest() == digest


@pytest.mark.parametrize("kind", (DeferredSessionKind.SSH, DeferredSessionKind.RDP))
def test_deferred_application_sidecar_commits_with_state_network_and_lifecycle(
    kind: DeferredSessionKind,
) -> None:
    """The protocol sidecar publishes in the exact prepared network transaction."""

    fixture = _fixture(kind)
    authority = _bound_authority(fixture)
    result = authority.materialize_prepared_deferred_session_transaction(
        fixture.issue(),
        fixture.coordinator,
        fixture.owner_rng,
    )

    assert authority.authenticates_prepared_network_receipt(
        fixture.prepared_root,
        result.receipt,
    )
    assert fixture.state.get_session(fixture.session_plan.identity.logon_id) is not None
    assert (
        fixture.state.get_connection_by_zeek_uid(fixture.prepared_root.transaction.zeek_uid)
        is not None
    )
    assert (
        fixture.lifecycle_registry.transport_for_transport_id(
            fixture.prepared_root.transaction.stable_id
        )
        is not None
    )
    assert result.connection.application is not None
    if kind is DeferredSessionKind.SSH:
        assert type(fixture.application_owner) is SshApplicationChannelManager
        assert (
            fixture.application_owner.session_view(fixture.application_token.session.channel_id)
            == fixture.application_token.session
        )
    else:
        assert type(fixture.application_owner) is RdpReconnectStateManager
        assert (
            fixture.application_owner.get(fixture.session_plan.identity.object_id)
            == fixture.application_token.session
        )


@pytest.mark.parametrize("kind", (DeferredSessionKind.SSH, DeferredSessionKind.RDP))
def test_deferred_application_sidecar_ordinary_rejection_is_neutral(
    kind: DeferredSessionKind,
) -> None:
    """A final validation failure releases every uncommitted owner capability."""

    fixture = _fixture(kind)
    authority = _bound_authority(fixture)

    def reject() -> None:
        raise StateError("injected deferred-session rejection")

    authority._materialization_precommit_hook = reject
    with pytest.raises(StateError, match="injected deferred-session rejection"):
        authority.materialize_prepared_deferred_session_transaction(
            fixture.issue(),
            fixture.coordinator,
            fixture.owner_rng,
        )

    assert fixture.state.get_session(fixture.session_plan.identity.logon_id) is None
    assert (
        fixture.state.get_connection_by_zeek_uid(fixture.prepared_root.transaction.zeek_uid) is None
    )
    assert (
        fixture.lifecycle_registry.transport_for_transport_id(
            fixture.prepared_root.transaction.stable_id
        )
        is None
    )
    assert fixture.application_token is not None
    if kind is DeferredSessionKind.SSH:
        assert type(fixture.application_owner) is SshApplicationChannelManager
    else:
        assert type(fixture.application_owner) is RdpReconnectStateManager
    assert not fixture.application_owner.authenticates_admission_token(fixture.application_token)


@pytest.mark.parametrize("kind", (DeferredSessionKind.SSH, DeferredSessionKind.RDP))
def test_deferred_application_sidecar_replay_cannot_publish_twice(
    kind: DeferredSessionKind,
) -> None:
    """A consumed composition is not a replayable protocol or State capability."""

    fixture = _fixture(kind)
    authority = _bound_authority(fixture)
    composition = fixture.issue()
    authority.materialize_prepared_deferred_session_transaction(
        composition,
        fixture.coordinator,
        fixture.owner_rng,
    )
    version = fixture.state.materialization_version

    with pytest.raises(StateError):
        authority.materialize_prepared_deferred_session_transaction(
            composition,
            fixture.coordinator,
            fixture.owner_rng,
        )

    assert fixture.state.materialization_version == version
    assert fixture.application_token is not None
    assert not fixture.application_owner.authenticates_admission_token(fixture.application_token)


@pytest.mark.parametrize("kind", (DeferredSessionKind.SSH, DeferredSessionKind.RDP))
def test_deferred_application_sidecar_rejects_preclaim_state_drift(
    kind: DeferredSessionKind,
) -> None:
    """Concurrent State drift before claim cannot leave a transport or sidecar."""

    fixture = _fixture(kind)
    authority = _bound_authority(fixture)
    composition = fixture.issue()
    fixture.state.set_current_time(_START + timedelta(microseconds=1))

    with pytest.raises(StateError):
        authority.materialize_prepared_deferred_session_transaction(
            composition,
            fixture.coordinator,
            fixture.owner_rng,
        )

    assert fixture.state.get_session(fixture.session_plan.identity.logon_id) is None
    assert (
        fixture.lifecycle_registry.transport_for_transport_id(
            fixture.prepared_root.transaction.stable_id
        )
        is None
    )
    assert fixture.application_token is not None
    assert not fixture.application_owner.authenticates_admission_token(fixture.application_token)


def test_authentication_accepts_replace_with_the_same_nested_objects_only() -> None:
    fixture = _fixture(DeferredSessionKind.SSH)
    composition = fixture.issue()

    equivalent = replace(composition)

    assert equivalent is not composition
    assert equivalent.prepared_root is composition.prepared_root
    assert fixture.coordinator.authenticates(equivalent)


def test_authentication_rejects_tampered_or_malformed_outer_integrity() -> None:
    fixture = _fixture(DeferredSessionKind.SSH)
    composition = fixture.issue()
    tampered = replace(composition, _integrity="0" * 64)
    malformed = replace(composition)
    object.__setattr__(malformed, "_integrity", None)

    assert not fixture.coordinator.authenticates(tampered)
    assert not fixture.coordinator.authenticates(malformed)


def test_authentication_rejects_copied_nested_capabilities_and_dispatches() -> None:
    fixture = _fixture(DeferredSessionKind.SSH)
    composition = fixture.issue()
    assert composition.application_token is not None

    copied_root = replace(composition, prepared_root=replace(composition.prepared_root))
    copied_lifecycle = replace(
        composition,
        lifecycle_token=deepcopy(composition.lifecycle_token),
    )
    copied_application = replace(
        composition,
        application_token=replace(composition.application_token),
    )
    copied_member = replace(
        composition,
        state_members=(deepcopy(composition.state_members[0]), *composition.state_members[1:]),
    )
    copied_dispatch_object = copy(composition.transport_dispatch)
    assert copied_dispatch_object.occurrence_id == composition.transport_dispatch.occurrence_id
    copied_dispatch = replace(
        composition,
        transport_dispatch=copied_dispatch_object,
    )

    assert not fixture.coordinator.authenticates(copied_root)
    assert not fixture.coordinator.authenticates(copied_lifecycle)
    assert not fixture.coordinator.authenticates(copied_application)
    assert not fixture.coordinator.authenticates(copied_member)
    assert not fixture.coordinator.authenticates(copied_dispatch)


def test_authentication_rejects_member_order_pairing_and_occurrence_object_substitution() -> None:
    fixture = _fixture(DeferredSessionKind.SSH)
    composition = fixture.issue()
    assert len(composition.state_members) == 2

    reversed_members = replace(
        composition,
        state_members=tuple(reversed(composition.state_members)),
    )
    with pytest.raises(ValueError, match="tokens disagree"):
        replace(
            composition.state_members[0],
            lifecycle_member=composition.state_members[1].lifecycle_member,
        )
    substituted = copy(composition.dependent_dispatches[0])
    assert substituted.occurrence_id == composition.dependent_dispatches[0].occurrence_id
    substituted_occurrence = replace(
        composition,
        dependent_dispatches=(substituted,),
    )

    assert not fixture.coordinator.authenticates(reversed_members)
    assert not fixture.coordinator.authenticates(substituted_occurrence)


@pytest.mark.parametrize("duplicate_position", ("transport", "dependent"))
def test_issue_rejects_duplicate_dispatch_objects_or_occurrence_ids(
    duplicate_position: str,
) -> None:
    fixture = _fixture(DeferredSessionKind.RDP)
    duplicate = (
        fixture.transport_dispatch
        if duplicate_position == "transport"
        else copy(fixture.dependent_dispatches[0])
    )

    with pytest.raises(StateError, match="dispatch|publication|occurrence"):
        fixture.issue(dependent_dispatches=(*fixture.dependent_dispatches, duplicate))


def test_issue_rejects_wrong_root_mode_and_protocol_port() -> None:
    ordinary_root = _fixture(
        DeferredSessionKind.SSH,
        lifecycle_mode="network",
    )

    with pytest.raises(StateError, match="deferred|mode"):
        ordinary_root.issue()
    with pytest.raises(ValueError, match="server_port must be 22"):
        _fixture(
            DeferredSessionKind.SSH,
            dst_port=443,
        )


def test_issue_rejects_lifecycle_transport_fingerprint_and_hold_drift() -> None:
    fixture = _fixture(DeferredSessionKind.SSH)
    fingerprint_drift = _replacement_lifecycle_token(
        fixture,
        transaction=replace(fixture.prepared_root.transaction, dst_ip="10.0.0.99"),
    )
    missing_holds = _replacement_lifecycle_token(fixture, process_holds=())

    with pytest.raises(StateError, match="fingerprint|transport|tuple"):
        fixture.issue(
            lifecycle_token=fingerprint_drift,
            state_members=_state_members_for_token(fixture, fingerprint_drift),
        )
    with pytest.raises(StateError, match="hold|activity"):
        fixture.issue(
            lifecycle_token=missing_holds,
            state_members=_state_members_for_token(fixture, missing_holds),
        )


def test_issue_rejects_ssh_application_session_binding_drift() -> None:
    fixture = _fixture(DeferredSessionKind.SSH)
    assert fixture.process_plan is not None
    _manager, unrelated_session_token = _ssh_application_token(
        fixture.prepared_root,
        fixture.session_plan,
        fixture.process_plan,
        session_object_id="unrelated-session-object",
    )

    with pytest.raises(StateError, match="session|binding"):
        fixture.issue(application_token=unrelated_session_token)


def test_issue_rejects_committed_source_timing_preparation() -> None:
    fixture = _fixture(DeferredSessionKind.RDP)
    planner = SourceTimingPlanner()
    committed = _sealed_timing(planner)
    with committed.claimed_commit():
        committed.commit_no_fail()

    with pytest.raises(StateError, match="timing|committed|sealed"):
        fixture.issue(source_timing_preparation=committed)


def test_coordinator_retains_no_caller_objects_and_failed_issue_is_shape_neutral() -> None:
    fixture = _fixture(DeferredSessionKind.RDP)
    coordinator = fixture.coordinator
    before_failure = tuple(sorted(id(item) for item in gc.get_referents(coordinator)))

    with pytest.raises(StateError):
        fixture.issue(dependent_dispatches=(fixture.transport_dispatch,))

    assert tuple(sorted(id(item) for item in gc.get_referents(coordinator))) == before_failure

    composition = fixture.issue()
    caller_objects = (
        fixture.prepared_root,
        fixture.source_timing_preparation,
        fixture.lifecycle_token,
        *fixture.state_members,
        fixture.transport_dispatch,
        *fixture.dependent_dispatches,
        composition,
    )
    coordinator_referents = gc.get_referents(coordinator)
    assert not any(
        retained is caller for retained in coordinator_referents for caller in caller_objects
    )


@dataclass(frozen=True, slots=True)
class _PublicationFixture:
    """Concrete exact sinks plus every owner retained by one bridge carrier."""

    fixture: _Fixture
    authority: GeneratorLifecycleAuthority
    dispatcher: EventDispatcher
    ecar: EcarEmitter
    zeek: ZeekEmitter
    ecar_root: Path
    zeek_path: Path
    composition: DeferredSessionComposition
    batch: object | None


def _compiled_ssh_syslog_deployment() -> CompiledCollectionDeployment:
    """Return visible concrete eCAR and Syslog host sources for an SSH open."""

    sources = []
    for format_name, hostname in (
        ("ecar", "WS-01"),
        ("ecar", "DB-01"),
        ("syslog", "DB-01"),
    ):
        descriptor = DEFAULT_SOURCE_CATALOG.descriptor(format_name)
        sources.append(
            SourceInstanceDeployment(
                identity=SourceInstanceIdentity(
                    source_instance=exact_source_instance_id(descriptor.family, hostname),
                    hostname=hostname,
                    family=descriptor.family,
                ),
                formats=(format_name,),
                policy=SourceCollectionPolicy(
                    enabled=True,
                    capabilities=descriptor.capabilities,
                ),
            )
        )
    return CompiledCollectionDeployment(tuple(sources))


def _compiled_ssh_cisco_deployment() -> CompiledCollectionDeployment:
    """Return visible eCAR hosts plus one exact Cisco ASA sensor source."""

    sources = []
    for format_name, hostname in (
        ("ecar", "WS-01"),
        ("ecar", "DB-01"),
        ("cisco_asa", "fw01"),
        ("zeek_conn", "fw01"),
    ):
        descriptor = DEFAULT_SOURCE_CATALOG.descriptor(format_name)
        sources.append(
            SourceInstanceDeployment(
                identity=SourceInstanceIdentity(
                    source_instance=exact_source_instance_id(descriptor.family, hostname),
                    hostname=hostname,
                    family=descriptor.family,
                ),
                formats=(format_name,),
                policy=SourceCollectionPolicy(
                    enabled=True,
                    capabilities=descriptor.capabilities,
                ),
            )
        )
    return CompiledCollectionDeployment(tuple(sources))


def _compiled_ssh_snort_deployment(
    sensor_hostnames: tuple[str, ...],
) -> CompiledCollectionDeployment:
    """Return exact endpoint evidence plus routed Zeek and Snort sensors."""

    source_pairs = [
        ("ecar", "WS-01"),
        ("ecar", "DB-01"),
        *(
            (format_name, hostname)
            for hostname in sensor_hostnames
            for format_name in ("zeek_conn", "snort_alert")
        ),
    ]
    sources = []
    for format_name, hostname in source_pairs:
        descriptor = DEFAULT_SOURCE_CATALOG.descriptor(format_name)
        sources.append(
            SourceInstanceDeployment(
                identity=SourceInstanceIdentity(
                    source_instance=exact_source_instance_id(descriptor.family, hostname),
                    hostname=hostname,
                    family=descriptor.family,
                ),
                formats=(format_name,),
                policy=SourceCollectionPolicy(
                    enabled=True,
                    capabilities=descriptor.capabilities,
                ),
            )
        )
    return CompiledCollectionDeployment(tuple(sources))


def _compiled_ssh_sysmon_deployment() -> CompiledCollectionDeployment:
    """Return visible eCAR hosts plus one concrete Sysmon source endpoint."""

    sources = []
    for format_name, hostname in (
        ("ecar", "WS-01"),
        ("ecar", "DB-01"),
        ("windows_event_sysmon", "WS-01"),
    ):
        descriptor = DEFAULT_SOURCE_CATALOG.descriptor(format_name)
        sources.append(
            SourceInstanceDeployment(
                identity=SourceInstanceIdentity(
                    source_instance=exact_source_instance_id(descriptor.family, hostname),
                    hostname=hostname,
                    family=descriptor.family,
                ),
                formats=(format_name,),
                policy=SourceCollectionPolicy(
                    enabled=True,
                    capabilities=descriptor.capabilities,
                ),
            )
        )
    return CompiledCollectionDeployment(tuple(sources))


def _compiled_ssh_sysmon_only_deployment() -> CompiledCollectionDeployment:
    """Return one Sysmon source so a filtered route cannot borrow another proof."""

    descriptor = DEFAULT_SOURCE_CATALOG.descriptor("windows_event_sysmon")
    return CompiledCollectionDeployment(
        (
            SourceInstanceDeployment(
                identity=SourceInstanceIdentity(
                    source_instance=exact_source_instance_id(descriptor.family, "WS-01"),
                    hostname="WS-01",
                    family=descriptor.family,
                ),
                formats=("windows_event_sysmon",),
                policy=SourceCollectionPolicy(
                    enabled=True,
                    capabilities=descriptor.capabilities,
                ),
            ),
        )
    )


def _compiled_deferred_ecar_deployment(
    *,
    missingness: float,
) -> CompiledCollectionDeployment:
    """Return exact endpoint eCAR sources with one explicit loss policy."""

    descriptor = DEFAULT_SOURCE_CATALOG.descriptor("ecar")
    return CompiledCollectionDeployment(
        tuple(
            SourceInstanceDeployment(
                identity=SourceInstanceIdentity(
                    source_instance=exact_source_instance_id(descriptor.family, hostname),
                    hostname=hostname,
                    family=descriptor.family,
                ),
                formats=("ecar",),
                policy=SourceCollectionPolicy(
                    enabled=True,
                    capabilities=descriptor.capabilities,
                    format_missingness={"ecar": missingness},
                ),
            )
            for hostname in ("WS-01", "DB-01")
        )
    )


def _foundation_publication_fixture(
    kind: DeferredSessionKind,
    tmp_path: Path,
    *,
    member_capacity: int = 65_536,
    preparation_capacity: int = 1_024,
    byte_capacity: int = 64 * 1_024 * 1_024,
    receipt_capacity: int = 4_096,
    extra_emitters: dict[str, LogEmitter] | None = None,
    with_intent: bool = False,
    include_syslog_context: bool = False,
    session_id_delta: int = 0,
    swap_dependent_target: bool = False,
    include_process_dependent: bool = False,
    reverse_process_host: bool = False,
    process_opposite_ip: bool = False,
    spoof_transport_source_hostname: bool = False,
    prepare_publication: bool = True,
    collection_deployment: CompiledCollectionDeployment | None = None,
    observation_policy: ObservationPolicy | None = None,
    output_start_time: datetime | None = None,
    output_end_time: datetime | None = None,
    rdp_elevated: bool = False,
    cisco_sensor_hostname: str | None = None,
    cisco_nat: NatSensorObservation | None = None,
    snort_sensor_hostnames: tuple[str, ...] = (),
    transport_ids_alerts: tuple[IdsAlertPlan, ...] = (),
    transport_source_pid: int = -1,
    transport_source_image: str = "",
) -> _PublicationFixture:
    """Build one exact eCAR/Zeek deferred bridge without using caller mocks."""

    fixture = _fixture(
        kind,
        process_start_offset_ms=2_000 if include_process_dependent else 110,
        include_responder_process=include_process_dependent,
    )
    planner = SourceTimingPlanner()
    ecar_root = tmp_path / "ecar"
    zeek_path = tmp_path / "zeek_conn.json"
    ecar = EcarEmitter(load_format("ecar"), ecar_root, threaded=False)
    zeek = ZeekEmitter(load_format("zeek_conn"), zeek_path, threaded=False)
    emitters: dict[str, LogEmitter] = {"zeek_conn": zeek, "ecar": ecar}
    if extra_emitters is not None:
        emitters.update(extra_emitters)
    intent_ledger = (
        IntentExecutionLedger(AuthoredIntentLedger("deferred-bridge-foundation", ()))
        if with_intent
        else None
    )
    dispatcher = EventDispatcher(
        state_manager=fixture.state,
        emitters=emitters,
        intent_execution_ledger=intent_ledger,
        source_timing_planner=planner,
        collection_deployment=collection_deployment,
        observation_policy=observation_policy,
        output_start_time=output_start_time,
        output_end_time=output_end_time,
        lifecycle_shadow=LifecycleShadow(fixture.state, fixture.lifecycle_registry),
        enforce_lifecycle_authority=True,
        action_cohort_preparation_capacity=preparation_capacity,
        action_cohort_member_capacity=member_capacity,
        action_cohort_byte_capacity=byte_capacity,
        action_cohort_receipt_capacity=receipt_capacity,
    )
    if with_intent:
        dispatcher.authored_intent_id = "deferred-bridge-intent"
    transaction = fixture.prepared_root.transaction
    src_host = HostContext(
        hostname="WS-01",
        ip=transaction.src_ip,
        os="Windows 11",
        os_category="windows",
        system_type="workstation",
        domain="example.test",
        fqdn="ws-01.example.test",
    )
    dst_host = HostContext(
        hostname="DB-01",
        ip=transaction.dst_ip,
        os=("Ubuntu 24.04" if kind is DeferredSessionKind.SSH else "Windows Server 2022"),
        os_category=("linux" if kind is DeferredSessionKind.SSH else "windows"),
        system_type="server",
        domain="example.test",
        fqdn="db-01.example.test",
    )
    transport_src_host = (
        replace(src_host, hostname=dst_host.hostname, fqdn=dst_host.fqdn)
        if spoof_transport_source_hostname
        else src_host
    )
    source_process_started_at = transaction.started_at - timedelta(seconds=5)
    source_process = (
        ProcessContext(
            pid=transport_source_pid,
            parent_pid=4,
            image=transport_source_image,
            command_line=f"{transport_source_image} {dst_host.hostname}",
            username="analyst",
            logon_id="0x50001",
            start_time=source_process_started_at,
        )
        if transport_source_pid > 0 and transport_source_image
        else None
    )
    source_process_identity = (
        ProcessIdentity(
            hostname=transport_src_host.hostname,
            object_id="source-ssh-process-1",
            pid=transport_source_pid,
            parent_pid=4,
            image=transport_source_image,
            command_line=f"{transport_source_image} {dst_host.hostname}",
            principal="analyst",
            logon_id="0x50001",
            started_at=source_process_started_at,
            lifecycle_group_id="source-ssh-process-lifecycle-1",
        )
        if source_process is not None
        else None
    )
    session = fixture.session_plan.identity
    dependent_time = session.started_at + timedelta(seconds=5)
    cisco_observations = (
        (
            NetworkSensorObservation(
                sensor_identity=cisco_sensor_hostname,
                path_role="transit",
                capture_profile="well_synced",
                tuple_view=NetworkTuple(
                    src_ip=transaction.src_ip,
                    src_port=transaction.src_port,
                    dst_ip=transaction.dst_ip,
                    dst_port=transaction.dst_port,
                    protocol=transaction.protocol,
                ),
                connection_uid=transaction.zeek_uid,
                connection_ids=((transaction.zeek_uid, transaction.zeek_uid),),
                file_ids=(),
                local_orig=transaction.local_orig,
                local_resp=transaction.local_resp,
                observed_start_time=transaction.started_at,
                observed_close_time=transaction.closed_at,
                traffic=transaction.traffic,
                visible_formats=frozenset({"cisco_asa", "zeek_conn"}),
                history=transaction.history,
                firewall_teardown_reason="TCP FINs",
                firewall_teardown_time=transaction.closed_at,
                nat=cisco_nat,
                source_times=(("zeek_conn", transaction.started_at),),
                source_durations=(
                    (("zeek_conn", transaction.duration),)
                    if transaction.duration is not None
                    else ()
                ),
            ),
        )
        if cisco_sensor_hostname is not None
        else ()
    )
    snort_observations = tuple(
        NetworkSensorObservation(
            sensor_identity=sensor_hostname,
            path_role="transit",
            capture_profile="well_synced",
            tuple_view=NetworkTuple(
                src_ip=transaction.src_ip,
                src_port=transaction.src_port,
                dst_ip=transaction.dst_ip,
                dst_port=transaction.dst_port,
                protocol=transaction.protocol,
            ),
            connection_uid=transaction.zeek_uid,
            connection_ids=((transaction.zeek_uid, transaction.zeek_uid),),
            file_ids=(),
            local_orig=transaction.local_orig,
            local_resp=transaction.local_resp,
            observed_start_time=transaction.started_at,
            observed_close_time=transaction.closed_at,
            traffic=transaction.traffic,
            visible_formats=frozenset({"snort_alert", "zeek_conn"}),
            history=transaction.history,
            source_times=(("zeek_conn", transaction.started_at),),
            source_durations=(
                (("zeek_conn", transaction.duration),) if transaction.duration is not None else ()
            ),
        )
        for sensor_hostname in snort_sensor_hostnames
    )
    network_observations = (*cisco_observations, *snort_observations)
    sensor_hostnames_by_format: dict[str, list[str]] = {}
    if cisco_sensor_hostname is not None:
        sensor_hostnames_by_format["cisco_asa"] = [cisco_sensor_hostname]
    zeek_sensors = (
        *((cisco_sensor_hostname,) if cisco_sensor_hostname is not None else ()),
        *snort_sensor_hostnames,
    )
    if zeek_sensors:
        sensor_hostnames_by_format["zeek_conn"] = list(zeek_sensors)
    if snort_sensor_hostnames:
        sensor_hostnames_by_format["snort_alert"] = list(snort_sensor_hostnames)
    with planner.prepared_planning() as timing:
        transport = dispatcher.prepare_builder(
            OccurrenceBuilder(
                timestamp=transaction.started_at,
                event_type="connection",
                src_host=transport_src_host,
                dst_host=dst_host,
                process=source_process,
                network=transaction,
                network_observations=network_observations,
                network_observations_planned=bool(network_observations),
                ids_alerts=transport_ids_alerts,
                _sensor_hostnames_by_format=sensor_hostnames_by_format,
                identity_plan=(
                    EventIdentityPlan(actor=source_process_identity)
                    if source_process_identity is not None
                    else None
                ),
            ),
            state_intent=PreparedDispatchStateIntent.EXTERNAL_DEFERRED_TRANSPORT,
            lifecycle_ticket=fixture.prepared_root,
            source_timing_preparation=timing,
        )
        session_dependent = dispatcher.prepare_builder(
            OccurrenceBuilder(
                timestamp=dependent_time,
                event_type="logon",
                src_host=dst_host if swap_dependent_target else None,
                dst_host=src_host if swap_dependent_target else dst_host,
                auth=AuthContext(
                    username=session.principal,
                    logon_id=session.logon_id,
                    session_id=session.session_id + session_id_delta,
                    logon_type=10,
                    source_ip=transaction.src_ip,
                    source_port=transaction.src_port,
                    elevated=rdp_elevated,
                ),
                syslog=(
                    SyslogContext(
                        app_name="sshd",
                        pid=1_104,
                        facility=10,
                        severity=6,
                        message="Accepted password for analyst from 10.0.0.10 port 50001 ssh2",
                    )
                    if include_syslog_context
                    else None
                ),
                identity_plan=EventIdentityPlan(subject=session, session=session),
                lifecycle=ActionLifecycleContext(
                    group_id=session.lifecycle_group_id,
                    canonical_start=dependent_time,
                    phase="start",
                ),
            ),
            state_intent=PreparedDispatchStateIntent.EXTERNAL_DEFERRED_DEPENDENT,
            lifecycle_ticket=fixture.session_plan,
            source_timing_preparation=timing,
        )
        process_dependent: PreparedDispatch | None = None
        if include_process_dependent:
            process_plan = fixture.process_plan
            assert process_plan is not None
            process_identity = process_plan.identity
            process_host = src_host if reverse_process_host else dst_host
            if process_opposite_ip:
                process_host = replace(dst_host, ip=transaction.src_ip)
            process_dependent = dispatcher.prepare_builder(
                OccurrenceBuilder(
                    timestamp=process_identity.started_at,
                    event_type="process_create",
                    src_host=process_host,
                    process=ProcessContext(
                        pid=process_identity.pid,
                        parent_pid=process_identity.parent_pid,
                        image=process_identity.image,
                        command_line=process_identity.command_line,
                        username=process_identity.principal,
                        integrity_level=process_plan.integrity_level,
                        logon_id=process_identity.logon_id,
                        start_time=process_identity.started_at,
                    ),
                    identity_plan=EventIdentityPlan(subject=process_identity),
                    lifecycle=ActionLifecycleContext(
                        group_id=process_identity.lifecycle_group_id,
                        canonical_start=process_identity.started_at,
                        phase="start",
                        parent_group_id=(process_identity.parent_lifecycle_group_id or None),
                    ),
                ),
                state_intent=PreparedDispatchStateIntent.EXTERNAL_DEFERRED_DEPENDENT,
                lifecycle_ticket=process_plan,
                source_timing_preparation=timing,
            )
    fixture = replace(
        fixture,
        timing_planner=planner,
        source_timing_preparation=timing,
        transport_dispatch=transport,
        dependent_dispatches=(
            *((process_dependent,) if process_dependent is not None else ()),
            session_dependent,
        ),
    )
    authority = _bound_authority(fixture)
    dispatcher.bind_lifecycle_authority(authority)
    composition = fixture.issue()
    batch = (
        dispatcher.prepare_deferred_session_publication_batch(
            composition,
            fixture.coordinator,
        )
        if prepare_publication
        else None
    )
    return _PublicationFixture(
        fixture=fixture,
        authority=authority,
        dispatcher=dispatcher,
        ecar=ecar,
        zeek=zeek,
        ecar_root=ecar_root,
        zeek_path=zeek_path,
        composition=composition,
        batch=batch,
    )


def _next_rdp_publication_fixture(
    previous: _PublicationFixture,
    *,
    ordinal: int,
    prepare_publication: bool = True,
) -> _PublicationFixture:
    """Prepare another independent RDP root on the same bounded dispatcher."""

    assert ordinal > 1
    prior = previous.fixture
    assert type(prior.application_owner) is RdpReconnectStateManager
    started_at = _START + timedelta(minutes=ordinal)
    stable_id = f"rdp-transport-{ordinal}"
    owner_rng = random.Random(17 + ordinal)
    runtime_preparation = prior.runtime.begin(
        owner_rng=owner_rng,
        stable_id=stable_id,
        linearization_time=started_at,
    )
    connection_identity = runtime_preparation.reserve_physical_identity()
    batch_builder = prior.state.begin_materialization_batch()
    session_plan = batch_builder.plan_session(
        username=f"analyst-{ordinal}",
        system="DB-01",
        logon_type=10,
        source_ip="10.0.0.10",
        start_time=started_at + timedelta(milliseconds=100),
        source_ready_time=started_at + timedelta(milliseconds=100),
        session_kind="rdp",
    )
    state_batch = batch_builder.seal()
    transaction = _transaction(
        stable_id=stable_id,
        conn_id=connection_identity.conn_id,
        zeek_uid=connection_identity.zeek_uid,
        dst_port=3389,
        started_at=started_at,
        src_port=50_000 + ordinal,
    )
    root = runtime_preparation.seal(
        transaction=transaction,
        lifecycle_mode="deferred_session",
        materialization_mode=ConnectionMaterializationMode.PHYSICAL,
        source_system="WS-01",
        source_hostname="ws-01.example.test",
        hostname="db-01.example.test",
        initiating_pid=-1,
        batch=state_batch,
    )
    lifecycle_members = previous.authority.connection_composite_start_members(root.state_plan)
    lifecycle_token = LifecycleProductionAdapter(
        prior.lifecycle_registry
    ).prepare_closed_transport_publication(
        closed_transport_publication_plan(
            transaction=transaction,
            authority_hostname="WS-01",
            src_hostname="WS-01",
            dst_hostname="DB-01",
            session_object_id=session_plan.identity.object_id,
            binding_role="session",
            bound_at=session_plan.identity.started_at,
            action_id=f"rdp-session-action-{ordinal}",
        ),
        start_members=lifecycle_members,
    )
    lifecycle_by_publication = {
        member.publication_token: member for member in lifecycle_token.request.start_members
    }
    state_members = (
        DeferredSessionStateMemberBinding(
            state_member=session_plan,
            lifecycle_member=lifecycle_by_publication[session_plan.publication_token],
        ),
    )
    application_owner, application_token = _rdp_application_token(
        root,
        session_plan,
        manager=prior.application_owner,
    )
    src_host = HostContext(
        hostname="WS-01",
        ip=transaction.src_ip,
        os="Windows 11",
        os_category="windows",
        system_type="workstation",
        domain="example.test",
        fqdn="ws-01.example.test",
    )
    dst_host = HostContext(
        hostname="DB-01",
        ip=transaction.dst_ip,
        os="Windows Server 2022",
        os_category="windows",
        system_type="server",
        domain="example.test",
        fqdn="db-01.example.test",
    )
    session = session_plan.identity
    dependent_time = session.started_at + timedelta(seconds=5)
    with prior.timing_planner.prepared_planning() as timing:
        transport = previous.dispatcher.prepare_builder(
            OccurrenceBuilder(
                timestamp=transaction.started_at,
                event_type="connection",
                src_host=src_host,
                dst_host=dst_host,
                network=transaction,
            ),
            state_intent=PreparedDispatchStateIntent.EXTERNAL_DEFERRED_TRANSPORT,
            lifecycle_ticket=root,
            source_timing_preparation=timing,
        )
        dependent = previous.dispatcher.prepare_builder(
            OccurrenceBuilder(
                timestamp=dependent_time,
                event_type="logon",
                dst_host=dst_host,
                auth=AuthContext(
                    username=session.principal,
                    logon_id=session.logon_id,
                    session_id=session.session_id,
                    logon_type=10,
                    source_ip=transaction.src_ip,
                    source_port=transaction.src_port,
                ),
                identity_plan=EventIdentityPlan(subject=session, session=session),
                lifecycle=ActionLifecycleContext(
                    group_id=session.lifecycle_group_id,
                    canonical_start=dependent_time,
                    phase="start",
                ),
            ),
            state_intent=PreparedDispatchStateIntent.EXTERNAL_DEFERRED_DEPENDENT,
            lifecycle_ticket=session_plan,
            source_timing_preparation=timing,
        )
    fixture = _Fixture(
        kind=DeferredSessionKind.RDP,
        coordinator=DeferredSessionCompositionCoordinator(kind=DeferredSessionKind.RDP),
        state=prior.state,
        runtime=prior.runtime,
        lifecycle_registry=prior.lifecycle_registry,
        application_owner=application_owner,
        timing_planner=prior.timing_planner,
        owner_rng=owner_rng,
        prepared_root=root,
        source_timing_preparation=timing,
        lifecycle_token=lifecycle_token,
        state_members=state_members,
        session_plan=session_plan,
        process_plan=None,
        application_token=application_token,
        transport_dispatch=transport,
        dependent_dispatches=(dependent,),
        binding_time=session.started_at,
        process_holds=(),
    )
    composition = fixture.issue()
    batch = (
        previous.dispatcher.prepare_deferred_session_publication_batch(
            composition,
            fixture.coordinator,
        )
        if prepare_publication
        else None
    )
    return _PublicationFixture(
        fixture=fixture,
        authority=previous.authority,
        dispatcher=previous.dispatcher,
        ecar=previous.ecar,
        zeek=previous.zeek,
        ecar_root=previous.ecar_root,
        zeek_path=previous.zeek_path,
        composition=composition,
        batch=batch,
    )


def _exact_cisco_emitter(
    output_path: Path,
    *,
    same_interface: bool,
) -> CiscoAsaEmitter:
    """Return one real ASA sink with deterministic test interface ownership."""

    emitter = CiscoAsaEmitter(
        load_format("cisco_asa"),
        output_path,
        threaded=False,
        sensor_hostnames=["fw01"],
    )
    emitter._segment_config = [
        {"name": "workstations", "cidr": "10.0.0.0/28"},
        {"name": "servers", "cidr": "10.0.0.16/28"},
    ]
    emitter._sensor_interfaces = {
        "fw01": {
            "workstations": "inside",
            "servers": "inside" if same_interface else "dmz",
            "_default": "outside",
        }
    }
    return emitter


def _close_and_read_publication(
    publication: _PublicationFixture,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """Close concrete sinks and return parsed eCAR and Zeek final rows."""

    publication.ecar.close()
    publication.zeek.close()
    ecar_rows = [
        json.loads(line)
        for output_path in publication.ecar_root.rglob("ecar.json")
        for line in output_path.read_text(encoding="utf-8").splitlines()
    ]
    zeek_rows = (
        [
            json.loads(line)
            for line in publication.zeek_path.read_text(encoding="utf-8").splitlines()
        ]
        if publication.zeek_path.exists()
        else []
    )
    return ecar_rows, zeek_rows


def _cancel_unmaterialized_publication(publication: _PublicationFixture) -> None:
    """Release every caller-owned capability retained by a negative fixture."""

    fixture = publication.fixture
    if (
        publication.batch is not None
        and publication.dispatcher.authenticates_prepared_deferred_session_publication_batch(
            publication.batch
        )
    ):
        publication.dispatcher.cancel_prepared_deferred_session_publication_batch(publication.batch)
    if fixture.application_owner is not None and fixture.application_token is not None:
        fixture.application_owner.cancel_prepared_admission(fixture.application_token)
    LifecycleProductionAdapter(fixture.lifecycle_registry).cancel_closed_transport_publication(
        fixture.lifecycle_token
    )
    fixture.runtime.cancel_preparation(fixture.prepared_root.runtime_token)
    if not fixture.source_timing_preparation.committed:
        fixture.source_timing_preparation.cancel()


def _assert_deferred_dispatcher_reservations_released(
    dispatcher: EventDispatcher,
) -> None:
    """Assert every bounded bridge/exact slot returned to its authority."""

    deferred = dispatcher.deferred_session_publication_census()
    recovery = dispatcher.exact_projection_recovery_census()
    assert deferred.prepared_batches == 0
    assert deferred.retained_members == 0
    assert deferred.retained_bytes == 0
    assert deferred.pending_receipts == 0
    assert deferred.receipt_reservations == 0
    assert deferred.receipt_eviction_reservations == 0
    assert deferred.recovery_reservations == 0
    assert recovery.unresolved_recoveries == 0
    assert recovery.reserved_recoveries == 0
    assert recovery.authority.active_batches == 0


def test_unmigrated_network_planner_stops_before_prepared_ownership_transfer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The newly recognized transport intent cannot activate the legacy caller path."""

    state = StateManager()
    state.set_current_time(_START)
    emitter = Mock()
    emitter.can_handle.return_value = True
    window_start = _START - timedelta(days=1)
    window_end = _END + timedelta(days=1)
    generator = ActivityGenerator(
        state,
        {"zeek_conn": emitter},
        generation_window_start=window_start,
        generation_window_end=window_end,
    )
    source = System(
        hostname="WS-01",
        ip="10.0.0.10",
        os="Windows 11",
        type="workstation",
    )
    target = System(
        hostname="DB-01",
        ip="10.0.0.20",
        os="Windows Server 2022",
        type="server",
    )
    generator._ip_to_system = {source.ip: source, target.ip: target}
    application_manager = RdpReconnectStateManager(
        application_registry=generator._application_channel_registry,
        window_start=window_start,
        window_end=window_end,
    )
    generator._lifecycle_authority.bind_rdp_session_manager(application_manager)
    session_time = _START + timedelta(seconds=5)
    authority = DeferredSessionNetworkAuthority(
        kind=DeferredSessionKind.RDP,
        coordinator=DeferredSessionCompositionCoordinator(kind=DeferredSessionKind.RDP),
        bound_at=session_time,
        state_intent=DeferredSessionStateIntent(
            username="analyst",
            system=target.hostname,
            source_ip=source.ip,
            source_port=50_001,
            start_time=session_time,
            source_ready_time=session_time,
            lifecycle_group_id="rdp-unmigrated-session",
            session_kind="rdp",
        ),
        application_intent=DeferredRdpApplicationIntent(
            manager=application_manager,
            source_host=source.hostname,
            target_host=target.hostname,
            principal="analyst",
            hard_deadline=_START + timedelta(hours=1),
        ),
    )
    request = NetworkConnectionRequest(
        src_ip=source.ip,
        dst_ip=target.ip,
        time=_START,
        dst_port=3389,
        proto="tcp",
        service="rdp",
        duration=30.0,
        orig_bytes=4_000,
        resp_bytes=8_000,
        src_port=50_001,
        source_system=source,
        conn_state="SF",
        preserve_dst_ip=True,
        preserve_start_time=True,
        transport_lifecycle_mode="deferred_session",
        deferred_session_authority=authority,
    )
    transfers = 0
    original_transfer = _PreparedNetworkBoundary.transfer

    def count_transfer(boundary: _PreparedNetworkBoundary) -> None:
        nonlocal transfers
        transfers += 1
        original_transfer(boundary)

    monkeypatch.setattr(_PreparedNetworkBoundary, "transfer", count_transfer)
    state_version = state.materialization_version
    state_digest = state.materialization_digest()
    timing_digest = generator._source_timing_planner.state_digest()
    runtime_digest = generator._network_transaction_runtime.state_digest()

    with pytest.raises(StateError, match="exact publication bridge"):
        NetworkConnectionActionBundle(generator, request).execute()

    assert transfers == 0
    assert state.materialization_version == state_version
    assert state.materialization_digest() == state_digest
    assert generator._source_timing_planner.state_digest() == timing_digest
    assert generator._network_transaction_runtime.state_digest() == runtime_digest
    timing_census = generator._source_timing_planner.preparation_authority_census()
    assert timing_census.retained_preparations == 0
    assert timing_census.active_claims == 0
    runtime_census = generator._network_transaction_runtime.census()
    assert runtime_census.open_preparations == 0
    assert runtime_census.prepared_transactions == 0
    assert runtime_census.claimed_transactions == 0
    application_census = application_manager.census()
    assert application_census.retained_sessions == 0
    assert application_census.application.prepared_admissions == 0
    assert application_census.application.claimed_admissions == 0
    assert generator._lifecycle_authority.registry.stats().live_transports == 0
    assert emitter.emit.call_count == 0
    assert generator.dispatcher is not None
    _assert_deferred_dispatcher_reservations_released(generator.dispatcher)


def test_exact_deferred_ssh_filters_same_interface_asa_before_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A same-interface/no-NAT ASA route cannot block other exact SSH evidence."""

    asa_root = tmp_path / "asa"
    asa = _exact_cisco_emitter(asa_root, same_interface=True)
    original_reserve = ExactPublicationBatch.reserve_participants
    reserved_participants: list[tuple[object, ...]] = []

    def capture_participants(
        batch: ExactPublicationBatch,
        participants: tuple[object, ...],
    ) -> None:
        reserved_participants.append(participants)
        original_reserve(batch, participants)

    monkeypatch.setattr(ExactPublicationBatch, "reserve_participants", capture_participants)
    publication = _foundation_publication_fixture(
        DeferredSessionKind.SSH,
        tmp_path,
        extra_emitters={"cisco_asa": asa},
        collection_deployment=_compiled_ssh_cisco_deployment(),
        cisco_sensor_hostname="fw01",
    )
    committed = publication.authority.materialize_prepared_deferred_session_publication(
        publication.composition,
        publication.fixture.coordinator,
        publication.fixture.owner_rng,
        dispatcher=publication.dispatcher,
        publication_batch=publication.batch,
    )

    assert all(outcome.status == "succeeded" for outcome in committed.publication.projections)
    assert (
        publication.fixture.state.get_session(publication.fixture.session_plan.identity.logon_id)
        is not None
    )
    assert reserved_participants
    assert all(asa not in participants for participants in reserved_participants)
    publication.ecar.close()
    publication.zeek.close()
    asa.close()
    assert not tuple(asa_root.rglob("cisco_asa.log"))
    zeek_outputs = tuple(tmp_path.rglob("conn.json"))
    assert len(zeek_outputs) == 1
    zeek_rows = [
        json.loads(line) for line in zeek_outputs[0].read_text(encoding="utf-8").splitlines()
    ]
    assert len(zeek_rows) == 1
    assert zeek_rows[0]["uid"] == publication.fixture.prepared_root.transaction.zeek_uid


def test_exact_deferred_ssh_cross_interface_asa_emits_one_stable_lifecycle(
    tmp_path: Path,
) -> None:
    """A real cross-interface ASA target publishes one correlated Built/Teardown pair."""

    asa_root = tmp_path / "asa"
    asa = _exact_cisco_emitter(asa_root, same_interface=False)
    publication = _foundation_publication_fixture(
        DeferredSessionKind.SSH,
        tmp_path,
        extra_emitters={"cisco_asa": asa},
        collection_deployment=_compiled_ssh_cisco_deployment(),
        cisco_sensor_hostname="fw01",
    )
    committed = publication.authority.materialize_prepared_deferred_session_publication(
        publication.composition,
        publication.fixture.coordinator,
        publication.fixture.owner_rng,
        dispatcher=publication.dispatcher,
        publication_batch=publication.batch,
    )

    assert all(outcome.status == "succeeded" for outcome in committed.publication.projections)
    publication.ecar.close()
    publication.zeek.close()
    asa.close()
    rendered = "\n".join(
        output.read_text(encoding="utf-8") for output in asa_root.rglob("cisco_asa.log")
    )
    built_ids = re.findall(r"Built .* connection (\d+) for", rendered)
    teardown_ids = re.findall(r"Teardown .* connection (\d+) for", rendered)
    assert len(built_ids) == len(teardown_ids) == 1
    assert built_ids == teardown_ids


@pytest.mark.parametrize("threaded", (False, True))
def test_exact_deferred_ssh_snort_publishes_one_candidate_per_sensor(
    threaded: bool,
    tmp_path: Path,
) -> None:
    """Correlated IDS candidates join the SSH transport's exact publication."""

    sensor_hostnames = ("ids-edge", "ids-core")
    snort_root = tmp_path / "snort"
    format_definition = load_format("snort_alert")
    if threaded:
        format_definition = format_definition.model_copy(deep=True)
    snort = SnortEmitter(
        format_definition,
        snort_root,
        threaded=threaded,
        sensor_hostnames=list(sensor_hostnames),
    )
    snort.emit_event(
        {
            "timestamp": _START - timedelta(seconds=1),
            "gid": 1,
            "sid": 9_000_001,
            "rev": 1,
            "message": "prior ordinary IDS candidate",
            "classification": "misc-activity",
            "priority": 3,
            "protocol": "TCP",
            "src_ip": "10.0.0.30",
            "src_port": 51_000,
            "dst_ip": "10.0.0.40",
            "dst_port": 443,
            "_ids_candidate": True,
            "_ids_policy": None,
            "_cluster_id": "ordinary-before-deferred",
            "_occurrence_id": "ordinary-before-deferred-1",
            "_source_observation_status": "visible",
            "_ids_origin": "built_in",
            "_sensor_hostnames": list(sensor_hostnames),
        }
    )
    alert = IdsAlertPlan(
        sid=2_002_911,
        rev=7,
        message="ET SCAN Potential SSH Scan",
        classification="attempted-recon",
        priority=2,
        origin="authored_attachment",
        policy=IdsAlertPolicyContext(
            event_filter=IdsEventFilterContext(
                type="limit",
                track="by_src",
                count=1,
                seconds=60,
            )
        ),
    )
    publication = _foundation_publication_fixture(
        DeferredSessionKind.SSH,
        tmp_path,
        extra_emitters={"snort_alert": snort},
        collection_deployment=_compiled_ssh_snort_deployment(sensor_hostnames),
        snort_sensor_hostnames=sensor_hostnames,
        transport_ids_alerts=(alert,),
    )

    committed = publication.authority.materialize_prepared_deferred_session_publication(
        publication.composition,
        publication.fixture.coordinator,
        publication.fixture.owner_rng,
        dispatcher=publication.dispatcher,
        publication_batch=publication.batch,
    )

    assert all(outcome.status == "succeeded" for outcome in committed.publication.projections)
    snort_proofs = tuple(
        proof for proof in committed.publication.target_proofs if proof.format_name == "snort_alert"
    )
    assert len(snort_proofs) == len(sensor_hostnames)
    assert all(proof.member_ordinal == 0 and proof.row_count == 1 for proof in snort_proofs)
    admitted = snort.journal_census()
    assert admitted.pending_rows == 2 * len(sensor_hostnames)
    assert admitted.active_receipts == admitted.admission_receipts == 0
    assert admitted.reserved_rows == admitted.reserved_bytes == 0

    publication.ecar.close()
    publication.zeek.close()
    snort.close()
    for sensor_hostname in sensor_hostnames:
        rendered = (snort_root / sensor_hostname / "snort_alert.log").read_text(encoding="utf-8")
        assert rendered.count("[1:2002911:7]") == 1
        assert rendered.count("ET SCAN Potential SSH Scan") == 1
        assert rendered.count("prior ordinary IDS candidate") == 1
    terminal = snort.journal_census()
    assert terminal.retained_rows == terminal.reserved_rows == terminal.active_receipts == 0


@pytest.mark.parametrize(
    "failure_mode",
    (
        "commit-fail-before",
        "commit-lost-return",
        "release-fail-before",
        "release-lost-return",
    ),
)
def test_exact_deferred_ssh_snort_recovers_candidate_publication(
    failure_mode: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Snort candidate commit and release retries converge without duplicate alerts."""

    sensor_hostnames = ("ids-core",)
    snort_root = tmp_path / "snort-recovery"
    snort = SnortEmitter(
        load_format("snort_alert"),
        snort_root,
        threaded=False,
        sensor_hostnames=list(sensor_hostnames),
    )
    original_commit = snort._commit_exact_row
    original_release = snort._release_exact_candidate
    commit_attempts = 0
    release_attempts = 0

    def fault_candidate_commit(key: ExactPublicationKey, digest: str, frozen: object) -> None:
        nonlocal commit_attempts
        envelope = SnortEmitter._parse_exact_envelope(frozen)
        if failure_mode.startswith("commit-") and commit_attempts == 0:
            commit_attempts += 1
            if failure_mode.endswith("lost-return"):
                original_commit(key, digest, frozen)
            raise OSError(f"injected Snort {failure_mode}")
        original_commit(key, digest, frozen)
        assert envelope["sid"] == 2_002_911

    def fault_candidate_release(key: ExactPublicationKey) -> None:
        nonlocal release_attempts
        if failure_mode.startswith("release-") and release_attempts == 0:
            release_attempts += 1
            if failure_mode.endswith("lost-return"):
                original_release(key)
            raise OSError(f"injected Snort {failure_mode}")
        original_release(key)

    monkeypatch.setattr(snort, "_commit_exact_row", fault_candidate_commit)
    monkeypatch.setattr(snort, "_release_exact_candidate", fault_candidate_release)
    alert = IdsAlertPlan(
        sid=2_002_911,
        rev=7,
        message="ET SCAN Potential SSH Scan",
        classification="attempted-recon",
        origin="authored_attachment",
    )
    publication = _foundation_publication_fixture(
        DeferredSessionKind.SSH,
        tmp_path,
        extra_emitters={"snort_alert": snort},
        collection_deployment=_compiled_ssh_snort_deployment(sensor_hostnames),
        snort_sensor_hostnames=sensor_hostnames,
        transport_ids_alerts=(alert,),
    )

    with pytest.raises(OSError, match=f"Snort {failure_mode}"):
        publication.authority.materialize_prepared_deferred_session_publication(
            publication.composition,
            publication.fixture.coordinator,
            publication.fixture.owner_rng,
            dispatcher=publication.dispatcher,
            publication_batch=publication.batch,
        )

    assert (
        publication.fixture.state.get_session(publication.fixture.session_plan.identity.logon_id)
        is not None
    )
    assert publication.dispatcher.exact_projection_recovery_census().unresolved_recoveries == 1
    resumed = publication.dispatcher.drain_exact_projection_recoveries()
    assert len(resumed) == 1
    assert all(
        outcome.status == "succeeded" for result in resumed for outcome in result.projections
    )
    assert commit_attempts == int(failure_mode.startswith("commit-"))
    assert release_attempts == int(failure_mode.startswith("release-"))
    recovery = publication.dispatcher.exact_projection_recovery_census()
    assert recovery.unresolved_recoveries == recovery.reserved_recoveries == 0
    assert recovery.authority.active_batches == 0
    census = snort.journal_census()
    assert census.pending_rows == 1
    assert census.reserved_rows == census.reserved_bytes == 0
    assert census.active_receipts == census.admission_receipts == 0

    publication.ecar.close()
    publication.zeek.close()
    snort.close()
    rendered = (snort_root / sensor_hostnames[0] / "snort_alert.log").read_text(encoding="utf-8")
    assert rendered.count("[1:2002911:7]") == 1
    terminal = snort.journal_census()
    assert terminal.retained_rows == terminal.active_receipts == terminal.admission_receipts == 0


class _OpenSnortSubclass(SnortEmitter):
    """Inherited exact machinery is not an approved projection target."""


@pytest.mark.parametrize(
    "target_kind",
    ("subclass", "custom-format", "closed", "replaced"),
)
def test_exact_deferred_ssh_rejects_unavailable_snort_before_state(
    target_kind: str,
    tmp_path: Path,
) -> None:
    """Deferred publication rejects an unsupported, closed, or replaced sink."""

    sensor_hostnames = ("ids-core",)
    emitter_type = _OpenSnortSubclass if target_kind == "subclass" else SnortEmitter
    format_definition = load_format("snort_alert")
    if target_kind == "custom-format":
        format_definition = format_definition.model_copy(deep=True)
        format_definition.output.template = f"{format_definition.output.template}\ncustom"
    snort = emitter_type(
        format_definition,
        tmp_path / target_kind,
        threaded=False,
        sensor_hostnames=list(sensor_hostnames),
    )
    alert = IdsAlertPlan(
        sid=2_002_911,
        message="ET SCAN Potential SSH Scan",
        classification="attempted-recon",
        origin="authored_attachment",
    )
    publication = _foundation_publication_fixture(
        DeferredSessionKind.SSH,
        tmp_path,
        extra_emitters={"snort_alert": snort},
        collection_deployment=_compiled_ssh_snort_deployment(sensor_hostnames),
        snort_sensor_hostnames=sensor_hostnames,
        transport_ids_alerts=(alert,),
        prepare_publication=False,
    )
    replacement: SnortEmitter | None = None
    if target_kind == "closed":
        snort.close()
    elif target_kind == "replaced":
        replacement = SnortEmitter(
            load_format("snort_alert"),
            tmp_path / "replacement",
            threaded=False,
            sensor_hostnames=list(sensor_hostnames),
        )
        publication.dispatcher.emitters["snort_alert"] = replacement
    state_version = publication.fixture.state.materialization_version
    state_digest = publication.fixture.state.materialization_digest()
    timing_digest = publication.fixture.timing_planner.state_digest()

    with pytest.raises(EventContractError, match="lacks exact projection publication"):
        publication.dispatcher.prepare_deferred_session_publication_batch(
            publication.composition,
            publication.fixture.coordinator,
        )

    assert publication.fixture.state.materialization_version == state_version
    assert publication.fixture.state.materialization_digest() == state_digest
    assert publication.fixture.timing_planner.state_digest() == timing_digest
    census = snort.journal_census()
    assert census.pending_rows == census.reserved_rows == census.active_receipts == 0
    _assert_deferred_dispatcher_reservations_released(publication.dispatcher)
    _cancel_unmaterialized_publication(publication)
    publication.ecar.close()
    publication.zeek.close()
    snort.close()
    if replacement is not None:
        replacement.close()


def test_exact_deferred_ssh_same_interface_planned_nat_remains_visible(
    tmp_path: Path,
) -> None:
    """A planned same-interface ASA NAT route remains a positive exact target."""

    asa_root = tmp_path / "asa"
    asa = _exact_cisco_emitter(asa_root, same_interface=True)
    close_time = _START + timedelta(seconds=30)
    publication = _foundation_publication_fixture(
        DeferredSessionKind.SSH,
        tmp_path,
        extra_emitters={"cisco_asa": asa},
        collection_deployment=_compiled_ssh_cisco_deployment(),
        cisco_sensor_hostname="fw01",
        cisco_nat=NatSensorObservation(
            nat_type="dynamic_pat",
            direction="source",
            local_ip="10.0.0.10",
            local_port=50_001,
            global_ip="198.51.100.10",
            global_port=60_001,
            built_time=_START,
            teardown_time=close_time,
        ),
    )
    committed = publication.authority.materialize_prepared_deferred_session_publication(
        publication.composition,
        publication.fixture.coordinator,
        publication.fixture.owner_rng,
        dispatcher=publication.dispatcher,
        publication_batch=publication.batch,
    )

    assert all(outcome.status == "succeeded" for outcome in committed.publication.projections)
    publication.ecar.close()
    publication.zeek.close()
    asa.close()
    rendered = "\n".join(
        output.read_text(encoding="utf-8") for output in asa_root.rglob("cisco_asa.log")
    )
    assert rendered.count("Built dynamic TCP translation") == 1
    assert rendered.count("Built outbound TCP connection") == 1
    assert rendered.count("Teardown TCP connection") == 1
    assert rendered.count("Teardown dynamic TCP translation") == 1


class _OpenCiscoSubclass(CiscoAsaEmitter):
    """Inherited exact marker that must not satisfy Cisco admission."""


class _OpenDuckCisco:
    """A foreign Cisco-shaped object whose marker and renderer must remain inert."""

    marker_reads = 0
    emit_calls = 0

    @property
    def supports_exact_projection_publication(self) -> bool:
        """Fail if exact admission executes a foreign descriptor."""

        type(self).marker_reads += 1
        raise AssertionError("duck Cisco exact marker executed")

    def can_handle(self, event: object) -> bool:
        """Claim the transport so concrete admission must reject this object."""

        return getattr(event, "network", None) is not None

    def emit(self, _event: object) -> None:
        """Remain inert because rejection must precede rendering."""

        type(self).emit_calls += 1


class _DescriptorCiscoFormat:
    """A foreign format object whose descriptor must remain inert."""

    name_reads = 0

    @property
    def name(self) -> str:
        """Fail if exact admission executes the foreign descriptor."""

        type(self).name_reads += 1
        raise AssertionError("foreign Cisco format descriptor executed")


@pytest.mark.parametrize(
    "target_kind",
    (
        "subclass",
        "duck",
        "alias",
        "wrong-format",
        "replaced",
        "copied-format",
        "mutated-format",
        "descriptor-format",
        "unsorted-writer",
    ),
)
def test_exact_deferred_ssh_rejects_nonowned_cisco_target_before_state(
    target_kind: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cisco type, format, identity, and writer substitutions fail closed."""

    _OpenDuckCisco.marker_reads = 0
    _OpenDuckCisco.emit_calls = 0
    _DescriptorCiscoFormat.name_reads = 0
    output_path = tmp_path / target_kind
    if target_kind == "subclass":
        emitter: object = _OpenCiscoSubclass(
            load_format("cisco_asa"),
            output_path,
            sensor_hostnames=["fw01"],
        )
    elif target_kind == "duck":
        emitter = _OpenDuckCisco()
    elif target_kind == "wrong-format":
        emitter = CiscoAsaEmitter(
            load_format("zeek_conn"),
            output_path,
            sensor_hostnames=["fw01"],
        )
    elif target_kind == "copied-format":
        emitter = CiscoAsaEmitter(
            load_format("cisco_asa").model_copy(deep=True),
            output_path,
            sensor_hostnames=["fw01"],
        )
    else:
        emitter = _exact_cisco_emitter(output_path, same_interface=False)
    if target_kind == "mutated-format":
        format_definition = object.__getattribute__(emitter, "__dict__")["format_def"]
        monkeypatch.setattr(
            format_definition,
            "description",
            f"{format_definition.description} (mutated)",
        )
    elif target_kind == "descriptor-format":
        object.__getattribute__(emitter, "__dict__")["format_def"] = _DescriptorCiscoFormat()
    elif target_kind == "unsorted-writer":
        writer = emitter._get_writer("fw01")
        object.__getattribute__(writer, "__dict__")["_sorted_writer"] = None
    format_name = "cisco_asa_alias" if target_kind == "alias" else "cisco_asa"
    publication = _foundation_publication_fixture(
        DeferredSessionKind.SSH,
        tmp_path,
        extra_emitters={format_name: emitter},  # type: ignore[dict-item]
        cisco_sensor_hostname="fw01",
        prepare_publication=False,
    )
    if target_kind == "replaced":
        publication.dispatcher.emitters["cisco_asa"] = _exact_cisco_emitter(
            tmp_path / "replacement",
            same_interface=False,
        )
    state_version = publication.fixture.state.materialization_version
    state_digest = publication.fixture.state.materialization_digest()
    timing_digest = publication.fixture.timing_planner.state_digest()

    with pytest.raises(EventContractError, match="lacks exact projection publication"):
        publication.dispatcher.prepare_deferred_session_publication_batch(
            publication.composition,
            publication.fixture.coordinator,
        )

    assert publication.fixture.state.materialization_version == state_version
    assert publication.fixture.state.materialization_digest() == state_digest
    assert publication.fixture.timing_planner.state_digest() == timing_digest
    assert _OpenDuckCisco.marker_reads == 0
    assert _OpenDuckCisco.emit_calls == 0
    assert _DescriptorCiscoFormat.name_reads == 0
    assert not output_path.exists()
    _assert_deferred_dispatcher_reservations_released(publication.dispatcher)


def test_exact_deferred_ssh_admitted_zero_row_cisco_fails_before_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An admitted concrete Cisco target must prove at least one immutable row."""

    asa = _exact_cisco_emitter(tmp_path / "asa", same_interface=False)
    publication = _foundation_publication_fixture(
        DeferredSessionKind.SSH,
        tmp_path,
        extra_emitters={"cisco_asa": asa},
        collection_deployment=_compiled_ssh_cisco_deployment(),
        cisco_sensor_hostname="fw01",
        prepare_publication=False,
    )
    monkeypatch.setattr(asa, "_emit_built", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(asa, "_emit_teardown", lambda *_args, **_kwargs: False)
    state_version = publication.fixture.state.materialization_version
    state_digest = publication.fixture.state.materialization_digest()
    timing_digest = publication.fixture.timing_planner.state_digest()

    with pytest.raises(EventContractError, match="staged no durable row"):
        publication.dispatcher.prepare_deferred_session_publication_batch(
            publication.composition,
            publication.fixture.coordinator,
        )

    assert publication.fixture.state.materialization_version == state_version
    assert publication.fixture.state.materialization_digest() == state_digest
    assert publication.fixture.timing_planner.state_digest() == timing_digest
    assert not tuple((tmp_path / "asa").rglob("cisco_asa.log"))
    _assert_deferred_dispatcher_reservations_released(publication.dispatcher)


@pytest.mark.parametrize("failure_mode", ("fail-before", "lost-return"))
def test_exact_deferred_ssh_cisco_prepare_retry_keeps_final_id_and_bytes(
    failure_mode: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed exact preflight rerenders the identical final Cisco lifecycle."""

    asa_root = tmp_path / "asa"
    asa = _exact_cisco_emitter(asa_root, same_interface=False)
    publication = _foundation_publication_fixture(
        DeferredSessionKind.SSH,
        tmp_path,
        extra_emitters={"cisco_asa": asa},
        collection_deployment=_compiled_ssh_cisco_deployment(),
        cisco_sensor_hostname="fw01",
        prepare_publication=False,
    )
    original_built = asa._emit_built
    original_prepare = ExactPublicationBatch.prepare
    attempted_ids: list[int] = []
    prepare_attempts = 0

    def capture_built(*args: object, **kwargs: object) -> None:
        attempted_ids.append(args[3])  # type: ignore[arg-type]
        original_built(*args, **kwargs)  # type: ignore[arg-type]

    def inject_prepare(
        batch: ExactPublicationBatch,
        render: Callable[[], object],
    ) -> object:
        nonlocal prepare_attempts
        prepare_attempts += 1
        if prepare_attempts == 1:
            if failure_mode == "lost-return":
                original_prepare(batch, render)
            raise OSError(f"injected Cisco prepare {failure_mode}")
        return original_prepare(batch, render)

    monkeypatch.setattr(asa, "_emit_built", capture_built)
    monkeypatch.setattr(ExactPublicationBatch, "prepare", inject_prepare)
    with pytest.raises(OSError, match=f"Cisco prepare {failure_mode}"):
        publication.dispatcher.prepare_deferred_session_publication_batch(
            publication.composition,
            publication.fixture.coordinator,
        )
    _assert_deferred_dispatcher_reservations_released(publication.dispatcher)
    batch = publication.dispatcher.prepare_deferred_session_publication_batch(
        publication.composition,
        publication.fixture.coordinator,
    )
    committed = publication.authority.materialize_prepared_deferred_session_publication(
        publication.composition,
        publication.fixture.coordinator,
        publication.fixture.owner_rng,
        dispatcher=publication.dispatcher,
        publication_batch=batch,
    )

    assert all(outcome.status == "succeeded" for outcome in committed.publication.projections)
    assert prepare_attempts == 2
    assert len(attempted_ids) == (2 if failure_mode == "lost-return" else 1)
    assert len(set(attempted_ids)) == 1
    publication.ecar.close()
    publication.zeek.close()
    asa.close()
    rendered = b"\n".join(output.read_bytes() for output in sorted(asa_root.rglob("cisco_asa.log")))
    assert rendered.count(b"Built outbound TCP connection") == 1
    assert rendered.count(b"Teardown TCP connection") == 1


@pytest.mark.parametrize(
    "failure_mode",
    ("commit-fail-before", "commit-lost-return", "release-fail-before", "release-lost-return"),
)
def test_exact_deferred_ssh_cisco_sink_recovery_is_exactly_once(
    failure_mode: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cisco exact row commit/release faults recover without ID or row duplication."""

    asa_root = tmp_path / "asa"
    asa = _exact_cisco_emitter(asa_root, same_interface=False)
    writer = asa._get_writer("fw01")
    assert writer._sorted_writer is not None
    sorted_writer = writer._sorted_writer
    original_commit = sorted_writer._commit_exact_row
    original_release = sorted_writer._release_exact_row
    attempts = 0

    def inject_commit(key: object, digest: str, frozen: object) -> None:
        nonlocal attempts
        if failure_mode.startswith("commit-") and attempts == 0:
            attempts += 1
            if failure_mode.endswith("lost-return"):
                original_commit(key, digest, frozen)  # type: ignore[arg-type]
            raise OSError(f"injected Cisco {failure_mode}")
        original_commit(key, digest, frozen)  # type: ignore[arg-type]

    def inject_release(key: object) -> None:
        nonlocal attempts
        if failure_mode.startswith("release-") and attempts == 0:
            attempts += 1
            if failure_mode.endswith("lost-return"):
                original_release(key)  # type: ignore[arg-type]
            raise OSError(f"injected Cisco {failure_mode}")
        original_release(key)  # type: ignore[arg-type]

    monkeypatch.setattr(sorted_writer, "_commit_exact_row", inject_commit)
    monkeypatch.setattr(sorted_writer, "_release_exact_row", inject_release)
    publication = _foundation_publication_fixture(
        DeferredSessionKind.SSH,
        tmp_path,
        extra_emitters={"cisco_asa": asa},
        collection_deployment=_compiled_ssh_cisco_deployment(),
        cisco_sensor_hostname="fw01",
    )
    with pytest.raises(OSError, match=f"Cisco {failure_mode}"):
        publication.authority.materialize_prepared_deferred_session_publication(
            publication.composition,
            publication.fixture.coordinator,
            publication.fixture.owner_rng,
            dispatcher=publication.dispatcher,
            publication_batch=publication.batch,
        )
    assert (
        publication.fixture.state.get_session(publication.fixture.session_plan.identity.logon_id)
        is not None
    )
    resumed = publication.dispatcher.drain_exact_projection_recoveries()
    assert len(resumed) == 1
    assert all(
        outcome.status == "succeeded" for result in resumed for outcome in result.projections
    )
    assert attempts == 1
    _assert_deferred_dispatcher_reservations_released(publication.dispatcher)
    publication.ecar.close()
    publication.zeek.close()
    asa.close()
    rendered = b"\n".join(output.read_bytes() for output in sorted(asa_root.rglob("cisco_asa.log")))
    built_ids = re.findall(rb"Built .* connection (\d+) for", rendered)
    teardown_ids = re.findall(rb"Teardown .* connection (\d+) for", rendered)
    assert len(built_ids) == len(teardown_ids) == 1
    assert built_ids == teardown_ids


def test_exact_deferred_ssh_cisco_warmup_stages_no_rows(
    tmp_path: Path,
) -> None:
    """A fully suppressed Cisco cohort preserves the sole zero-row warm-up exception."""

    asa_root = tmp_path / "asa"
    asa = _exact_cisco_emitter(asa_root, same_interface=False)
    publication = _foundation_publication_fixture(
        DeferredSessionKind.SSH,
        tmp_path,
        extra_emitters={"cisco_asa": asa},
        collection_deployment=_compiled_ssh_cisco_deployment(),
        cisco_sensor_hostname="fw01",
        output_start_time=_END,
    )
    committed = publication.authority.materialize_prepared_deferred_session_publication(
        publication.composition,
        publication.fixture.coordinator,
        publication.fixture.owner_rng,
        dispatcher=publication.dispatcher,
        publication_batch=publication.batch,
    )

    assert all(outcome.status == "succeeded" for outcome in committed.publication.projections)
    publication.ecar.close()
    publication.zeek.close()
    asa.close()
    assert not tuple(asa_root.rglob("cisco_asa.log"))


@pytest.mark.parametrize(
    "failure_mode",
    (
        "success",
        "commit-fail-before",
        "commit-lost-return",
        "release-fail-before",
        "release-lost-return",
    ),
)
def test_exact_deferred_ssh_open_accepts_compiled_visible_concrete_syslog(
    failure_mode: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A deployed concrete Syslog sink joins the recoverable atomic SSH open."""

    syslog_root = tmp_path / "syslog"
    syslog = SyslogEmitter(
        load_format("syslog"),
        syslog_root,
        threaded=False,
    )
    original_commit = syslog._commit_exact_candidate
    original_release = syslog._release_exact_candidate
    commit_attempts = 0
    release_attempts = 0

    def fault_open_commit(key: object, digest: str, frozen: object) -> None:
        nonlocal commit_attempts
        _route, _logical_route, rendered = SyslogEmitter._decode_exact_candidate(frozen)
        is_open = "Accepted password for analyst" in rendered
        if failure_mode.startswith("commit-") and is_open and commit_attempts == 0:
            commit_attempts += 1
            if failure_mode.endswith("lost-return"):
                original_commit(key, digest, frozen)
            raise OSError(f"injected SSH-open Syslog {failure_mode}")
        original_commit(key, digest, frozen)

    def fault_open_release(key: object) -> None:
        nonlocal release_attempts
        if failure_mode.startswith("release-") and release_attempts == 0:
            release_attempts += 1
            if failure_mode.endswith("lost-return"):
                original_release(key)
            raise OSError(f"injected SSH-open Syslog {failure_mode}")
        original_release(key)

    monkeypatch.setattr(syslog, "_commit_exact_candidate", fault_open_commit)
    monkeypatch.setattr(syslog, "_release_exact_candidate", fault_open_release)
    original_reserve = ExactPublicationBatch.reserve_participants
    reserved_participants: list[tuple[object, ...]] = []

    def capture_participants(
        batch: ExactPublicationBatch,
        participants: tuple[object, ...],
    ) -> None:
        reserved_participants.append(participants)
        original_reserve(batch, participants)

    monkeypatch.setattr(ExactPublicationBatch, "reserve_participants", capture_participants)
    publication = _foundation_publication_fixture(
        DeferredSessionKind.SSH,
        tmp_path,
        extra_emitters={"syslog": syslog},
        include_syslog_context=True,
        collection_deployment=_compiled_ssh_syslog_deployment(),
    )
    assert any(
        len(participants) == 2 and participants[0] is publication.ecar and participants[1] is syslog
        for participants in reserved_participants
    )
    if failure_mode == "success":
        committed = publication.authority.materialize_prepared_deferred_session_publication(
            publication.composition,
            publication.fixture.coordinator,
            publication.fixture.owner_rng,
            dispatcher=publication.dispatcher,
            publication_batch=publication.batch,
        )
        assert all(outcome.status == "succeeded" for outcome in committed.publication.projections)
    else:
        with pytest.raises(OSError, match=f"SSH-open Syslog {failure_mode}"):
            publication.authority.materialize_prepared_deferred_session_publication(
                publication.composition,
                publication.fixture.coordinator,
                publication.fixture.owner_rng,
                dispatcher=publication.dispatcher,
                publication_batch=publication.batch,
            )
        assert (
            publication.fixture.state.get_session(
                publication.fixture.session_plan.identity.logon_id
            )
            is not None
        )
        assert publication.dispatcher.exact_projection_recovery_census().unresolved_recoveries == 1
        resumed = publication.dispatcher.drain_exact_projection_recoveries()
        assert len(resumed) == 1
        assert all(
            outcome.status == "succeeded" for result in resumed for outcome in result.projections
        )

    assert (
        publication.fixture.state.get_session(publication.fixture.session_plan.identity.logon_id)
        is not None
    )
    assert commit_attempts == int(failure_mode.startswith("commit-"))
    assert release_attempts == int(failure_mode.startswith("release-"))
    recovery = publication.dispatcher.exact_projection_recovery_census()
    assert recovery.unresolved_recoveries == 0
    assert recovery.reserved_recoveries == 0
    assert recovery.authority.active_batches == 0
    before_close = syslog.exact_candidate_census()
    assert before_close.admitted_rows == before_close.released_rows == 1
    assert before_close.reserved_rows == before_close.reserved_bytes == 0
    publication.ecar.close()
    publication.zeek.close()
    syslog.close()
    rendered = "\n".join(
        output.read_text(encoding="utf-8") for output in syslog_root.rglob("syslog.log")
    )
    assert rendered.count("Accepted password for analyst") == 1
    exact = syslog.exact_candidate_census()
    assert exact.admitted_rows == exact.admitted_bytes == 0
    assert exact.reserved_rows == exact.reserved_bytes == 0


def test_exact_deferred_ssh_open_syslog_warmup_stages_zero_rows_without_marker_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A fully suppressed SSH open stays canonical and never inspects its Syslog sink."""

    syslog_root = tmp_path / "syslog"
    syslog = SyslogEmitter(load_format("syslog"), syslog_root, threaded=False)
    marker_reads = 0

    def reject_marker_read(_emitter: SyslogEmitter) -> bool:
        nonlocal marker_reads
        marker_reads += 1
        raise AssertionError("suppressed Syslog exact marker executed")

    monkeypatch.setattr(
        SyslogEmitter,
        "supports_exact_projection_publication",
        property(reject_marker_read),
    )
    original_prepare = ExactPublicationBatch.prepare
    prepared_row_counts: list[int] = []

    def capture_row_count(
        batch: ExactPublicationBatch,
        render: Callable[[], object],
    ) -> object:
        result = original_prepare(batch, render)
        prepared_row_counts.append(batch.prepared_row_count)
        return result

    monkeypatch.setattr(ExactPublicationBatch, "prepare", capture_row_count)
    publication = _foundation_publication_fixture(
        DeferredSessionKind.SSH,
        tmp_path,
        extra_emitters={"syslog": syslog},
        include_syslog_context=True,
        collection_deployment=_compiled_ssh_syslog_deployment(),
        output_start_time=_END,
    )
    committed = publication.authority.materialize_prepared_deferred_session_publication(
        publication.composition,
        publication.fixture.coordinator,
        publication.fixture.owner_rng,
        dispatcher=publication.dispatcher,
        publication_batch=publication.batch,
    )

    assert all(outcome.status == "succeeded" for outcome in committed.publication.projections)
    assert prepared_row_counts == [0]
    assert marker_reads == 0
    publication.ecar.close()
    publication.zeek.close()
    syslog.close()
    assert not tuple(syslog_root.rglob("syslog.log"))
    exact = syslog.exact_candidate_census()
    assert exact.high_water_rows == exact.high_water_bytes == 0
    assert exact.admitted_rows == exact.admitted_bytes == 0
    assert exact.reserved_rows == exact.reserved_bytes == 0


class _OpenSyslogSubclass(SyslogEmitter):
    """Inherited exact marker that must not satisfy the concrete open allowlist."""

    marker_reads = 0

    @property
    def supports_exact_projection_publication(self) -> bool:
        """Fail if SSH-open admission executes a subclass descriptor."""

        type(self).marker_reads += 1
        raise AssertionError("subclass Syslog exact marker executed")


class _OpenDuckSyslog:
    """Duck exact marker that must not execute during SSH-open admission."""

    marker_reads = 0
    emit_calls = 0

    @property
    def supports_exact_projection_publication(self) -> bool:
        """Fail if SSH-open admission executes a foreign descriptor."""

        type(self).marker_reads += 1
        raise AssertionError("duck Syslog exact marker executed")

    def can_handle(self, event: object) -> bool:
        """Participate only in the fixture's explicit SyslogContext dependent."""

        return getattr(event, "syslog", None) is not None

    def emit(self, _event: object) -> None:
        """Remain inert because admission must fail before rendering."""

        type(self).emit_calls += 1


@pytest.mark.parametrize("target_kind", ("subclass", "duck", "alias"))
def test_exact_deferred_ssh_open_rejects_nonconcrete_syslog_before_state(
    target_kind: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Subclass, duck, and wrongly aliased Syslog targets fail without marker calls."""

    _OpenSyslogSubclass.marker_reads = 0
    _OpenDuckSyslog.marker_reads = 0
    _OpenDuckSyslog.emit_calls = 0
    alias_marker_reads = 0
    output_path = tmp_path / target_kind
    if target_kind == "subclass":
        emitter: object = _OpenSyslogSubclass(load_format("syslog"), output_path)
    elif target_kind == "duck":
        emitter = _OpenDuckSyslog()
    else:

        def reject_alias_marker(_emitter: SyslogEmitter) -> bool:
            nonlocal alias_marker_reads
            alias_marker_reads += 1
            raise AssertionError("wrong-alias Syslog exact marker executed")

        monkeypatch.setattr(
            SyslogEmitter,
            "supports_exact_projection_publication",
            property(reject_alias_marker),
        )
        emitter = SyslogEmitter(load_format("syslog"), output_path)
    format_name = "syslog_alias" if target_kind == "alias" else "syslog"
    publication = _foundation_publication_fixture(
        DeferredSessionKind.SSH,
        tmp_path,
        extra_emitters={format_name: emitter},  # type: ignore[dict-item]
        include_syslog_context=True,
        prepare_publication=False,
    )
    state_version = publication.fixture.state.materialization_version
    state_digest = publication.fixture.state.materialization_digest()
    timing_digest = publication.fixture.timing_planner.state_digest()

    with pytest.raises(EventContractError, match="lacks exact projection publication"):
        publication.dispatcher.prepare_deferred_session_publication_batch(
            publication.composition,
            publication.fixture.coordinator,
        )

    assert publication.fixture.state.materialization_version == state_version
    assert publication.fixture.state.materialization_digest() == state_digest
    assert publication.fixture.timing_planner.state_digest() == timing_digest
    assert not output_path.exists()
    assert _OpenSyslogSubclass.marker_reads == 0
    assert _OpenDuckSyslog.marker_reads == 0
    assert _OpenDuckSyslog.emit_calls == 0
    assert alias_marker_reads == 0
    if isinstance(emitter, SyslogEmitter):
        exact = emitter.exact_candidate_census()
        assert exact.admitted_rows == exact.admitted_bytes == 0
        assert exact.reserved_rows == exact.reserved_bytes == 0
    _assert_deferred_dispatcher_reservations_released(publication.dispatcher)
    _cancel_unmaterialized_publication(publication)
    publication.ecar.close()
    publication.zeek.close()
    if isinstance(emitter, SyslogEmitter):
        emitter.close()


def _finalize_sysmon_source(emitter: SysmonEventEmitter) -> None:
    """Finalize and close one exact Sysmon source in engine owner order."""

    coordinator = SourceFinalizationCoordinator(
        (emitter,),
        ExactPublicationAuthority(
            capacity=1,
            row_capacity=256,
            byte_capacity=8 * 1024 * 1024,
        ),
    )
    coordinator.finalize()
    emitter.close()
    coordinator.mark_closed()


@pytest.mark.parametrize(
    "failure_mode",
    (
        "success",
        "commit-fail-before",
        "commit-lost-return",
        "release-fail-before",
        "release-lost-return",
    ),
)
def test_exact_deferred_ssh_open_publishes_bound_sysmon_event3_once(
    failure_mode: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A modeled SSH client makes one exact recoverable Sysmon Event 3 row."""

    sysmon_root = tmp_path / "sysmon"
    sysmon = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        sysmon_root,
        threaded=False,
        source_finalization=True,
    )
    original_commit = sysmon._commit_exact_candidate_row
    original_release = sysmon._release_exact_candidate_row
    commit_attempts = 0
    release_attempts = 0

    def fault_event3_commit(key: object, digest: str, frozen: object) -> None:
        nonlocal commit_attempts
        if failure_mode.startswith("commit-") and commit_attempts == 0:
            commit_attempts += 1
            if failure_mode.endswith("lost-return"):
                original_commit(key, digest, frozen)  # type: ignore[arg-type]
            raise OSError(f"injected SSH-open Sysmon {failure_mode}")
        original_commit(key, digest, frozen)  # type: ignore[arg-type]

    def fault_event3_release(key: object) -> None:
        nonlocal release_attempts
        if failure_mode.startswith("release-") and release_attempts == 0:
            release_attempts += 1
            if failure_mode.endswith("lost-return"):
                original_release(key)  # type: ignore[arg-type]
            raise OSError(f"injected SSH-open Sysmon {failure_mode}")
        original_release(key)  # type: ignore[arg-type]

    monkeypatch.setattr(sysmon, "_commit_exact_candidate_row", fault_event3_commit)
    monkeypatch.setattr(sysmon, "_release_exact_candidate_row", fault_event3_release)
    source_pid = 4_321
    source_image = r"C:\Windows\System32\OpenSSH\ssh.exe"
    publication = _foundation_publication_fixture(
        DeferredSessionKind.SSH,
        tmp_path,
        extra_emitters={"windows_event_sysmon": sysmon},
        collection_deployment=_compiled_ssh_sysmon_deployment(),
        transport_source_pid=source_pid,
        transport_source_image=source_image,
    )

    if failure_mode == "success":
        committed = publication.authority.materialize_prepared_deferred_session_publication(
            publication.composition,
            publication.fixture.coordinator,
            publication.fixture.owner_rng,
            dispatcher=publication.dispatcher,
            publication_batch=publication.batch,
        )
        assert all(outcome.status == "succeeded" for outcome in committed.publication.projections)
    else:
        with pytest.raises(OSError, match=f"SSH-open Sysmon {failure_mode}"):
            publication.authority.materialize_prepared_deferred_session_publication(
                publication.composition,
                publication.fixture.coordinator,
                publication.fixture.owner_rng,
                dispatcher=publication.dispatcher,
                publication_batch=publication.batch,
            )
        assert (
            publication.fixture.state.get_session(
                publication.fixture.session_plan.identity.logon_id
            )
            is not None
        )
        state_version = publication.fixture.state.materialization_version
        state_digest = publication.fixture.state.materialization_digest()
        recovery = publication.dispatcher.exact_projection_recovery_census()
        assert recovery.unresolved_recoveries == 1
        resumed = publication.dispatcher.drain_exact_projection_recoveries()
        assert len(resumed) == 1
        assert all(
            outcome.status == "succeeded" for result in resumed for outcome in result.projections
        )
        assert publication.fixture.state.materialization_version == state_version
        assert publication.fixture.state.materialization_digest() == state_digest

    assert (
        publication.fixture.state.get_session(publication.fixture.session_plan.identity.logon_id)
        is not None
    )
    assert commit_attempts == int(failure_mode.startswith("commit-"))
    assert release_attempts == int(failure_mode.startswith("release-"))
    _assert_deferred_dispatcher_reservations_released(publication.dispatcher)
    publication.ecar.close()
    publication.zeek.close()
    _finalize_sysmon_source(sysmon)
    rendered = "\n".join(
        output.read_text(encoding="utf-8")
        for output in sysmon_root.rglob("windows_event_sysmon.xml")
    )
    assert rendered.count("<EventID>3</EventID>") == 1
    assert f'<Data Name="ProcessId">{source_pid}</Data>' in rendered
    assert f'<Data Name="Image">{source_image}</Data>' in rendered
    assert '<Data Name="SourceIp">10.0.0.10</Data>' in rendered
    assert '<Data Name="SourcePort">50001</Data>' in rendered
    assert '<Data Name="DestinationIp">10.0.0.20</Data>' in rendered
    assert '<Data Name="DestinationPort">22</Data>' in rendered
    exact = sysmon.exact_candidate_census()
    assert exact.current_rows == exact.current_bytes == exact.current_participants == 0
    assert exact.released_rows == exact.released_bytes == exact.completed_participants == 0
    assert exact.high_water_rows == exact.high_water_participants == 1


def test_exact_deferred_ssh_open_filters_actorless_sysmon_before_admission(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An actorless transport keeps its eCAR proof without inventing Event 3."""

    sysmon_root = tmp_path / "sysmon"
    sysmon = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        sysmon_root,
        threaded=False,
        source_finalization=True,
    )
    marker_reads = 0
    helper_calls = 0
    original_helper = getattr(SysmonEventEmitter, "_event3_projection_eligible", None)

    def reject_marker_read(_emitter: SysmonEventEmitter) -> bool:
        nonlocal marker_reads
        marker_reads += 1
        raise AssertionError("filtered Sysmon exact marker executed")

    def capture_helper(emitter: SysmonEventEmitter, event: object) -> bool:
        nonlocal helper_calls
        helper_calls += 1
        if original_helper is None:
            return False
        return original_helper(emitter, event)

    monkeypatch.setattr(
        SysmonEventEmitter,
        "supports_exact_projection_publication",
        property(reject_marker_read),
    )
    monkeypatch.setattr(
        SysmonEventEmitter,
        "_event3_projection_eligible",
        capture_helper,
        raising=False,
    )
    publication = _foundation_publication_fixture(
        DeferredSessionKind.SSH,
        tmp_path,
        extra_emitters={"windows_event_sysmon": sysmon},
        collection_deployment=_compiled_ssh_sysmon_deployment(),
        prepare_publication=False,
    )
    assert "_filters" not in sysmon.__dict__
    state_version = publication.fixture.state.materialization_version
    state_digest = publication.fixture.state.materialization_digest()
    batch = publication.dispatcher.prepare_deferred_session_publication_batch(
        publication.composition,
        publication.fixture.coordinator,
    )
    assert publication.fixture.state.materialization_version == state_version
    assert publication.fixture.state.materialization_digest() == state_digest

    committed = publication.authority.materialize_prepared_deferred_session_publication(
        publication.composition,
        publication.fixture.coordinator,
        publication.fixture.owner_rng,
        dispatcher=publication.dispatcher,
        publication_batch=batch,
    )
    assert all(outcome.status == "succeeded" for outcome in committed.publication.projections)
    assert helper_calls == 1
    assert marker_reads == 0
    assert "_filters" not in sysmon.__dict__
    assert sysmon.exact_candidate_census().high_water_rows == 0
    _assert_deferred_dispatcher_reservations_released(publication.dispatcher)
    publication.ecar.close()
    publication.zeek.close()
    _finalize_sysmon_source(sysmon)
    assert not tuple(sysmon_root.rglob("windows_event_sysmon.xml"))


def test_actorless_sysmon_filter_preserves_positive_member_guard(
    tmp_path: Path,
) -> None:
    """Filtering the sole zero-row source cannot authorize an unproven member."""

    sysmon_root = tmp_path / "sysmon"
    sysmon = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        sysmon_root,
        threaded=False,
        source_finalization=True,
    )
    publication = _foundation_publication_fixture(
        DeferredSessionKind.SSH,
        tmp_path,
        extra_emitters={"windows_event_sysmon": sysmon},
        collection_deployment=_compiled_ssh_sysmon_only_deployment(),
        prepare_publication=False,
    )
    state_version = publication.fixture.state.materialization_version
    state_digest = publication.fixture.state.materialization_digest()
    timing_digest = publication.fixture.timing_planner.state_digest()

    with pytest.raises(EventContractError, match="positive exact target for every member"):
        publication.dispatcher.prepare_deferred_session_publication_batch(
            publication.composition,
            publication.fixture.coordinator,
        )

    assert publication.fixture.state.materialization_version == state_version
    assert publication.fixture.state.materialization_digest() == state_digest
    assert publication.fixture.timing_planner.state_digest() == timing_digest
    assert sysmon.exact_candidate_census().high_water_rows == 0
    _assert_deferred_dispatcher_reservations_released(publication.dispatcher)
    _cancel_unmaterialized_publication(publication)
    publication.ecar.close()
    publication.zeek.close()
    _finalize_sysmon_source(sysmon)
    assert not tuple(sysmon_root.rglob("windows_event_sysmon.xml"))


class _OpenSysmonSubclass(SysmonEventEmitter):
    """Inherited exact capability that must not satisfy the concrete allowlist."""

    marker_reads = 0

    @property
    def supports_exact_projection_publication(self) -> bool:
        """Fail if deferred admission executes a subclass descriptor."""

        type(self).marker_reads += 1
        raise AssertionError("subclass Sysmon exact marker executed")


class _OpenDuckSysmon:
    """Duck exact marker that must not execute during deferred admission."""

    marker_reads = 0
    emit_calls = 0

    @property
    def supports_exact_projection_publication(self) -> bool:
        """Fail if deferred admission executes a foreign descriptor."""

        type(self).marker_reads += 1
        raise AssertionError("duck Sysmon exact marker executed")

    def can_handle(self, event: object) -> bool:
        """Participate only in the actorful Windows connection member."""

        return getattr(event, "event_type", None) == "connection"

    def emit(self, _event: object) -> None:
        """Remain inert because admission must fail before rendering."""

        type(self).emit_calls += 1


@pytest.mark.parametrize(
    "target_kind",
    ("direct", "subclass", "duck", "alias", "replaced"),
)
def test_exact_deferred_ssh_open_rejects_unbound_or_nonconcrete_sysmon_before_state(
    target_kind: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only the exact bound concrete Sysmon instance can join an SSH open."""

    _OpenSysmonSubclass.marker_reads = 0
    _OpenDuckSysmon.marker_reads = 0
    _OpenDuckSysmon.emit_calls = 0
    alias_marker_reads = 0
    output_path = tmp_path / target_kind
    replaced: SysmonEventEmitter | None = None
    if target_kind == "direct":
        emitter: object = SysmonEventEmitter(
            load_format("windows_event_sysmon"),
            output_path,
            threaded=False,
        )
    elif target_kind == "subclass":
        emitter = _OpenSysmonSubclass(
            load_format("windows_event_sysmon"),
            output_path,
            threaded=False,
            source_finalization=True,
        )
    elif target_kind == "duck":
        emitter = _OpenDuckSysmon()
    else:
        if target_kind == "alias":

            def reject_alias_marker(_emitter: SysmonEventEmitter) -> bool:
                nonlocal alias_marker_reads
                alias_marker_reads += 1
                raise AssertionError("wrong-alias Sysmon exact marker executed")

            monkeypatch.setattr(
                SysmonEventEmitter,
                "supports_exact_projection_publication",
                property(reject_alias_marker),
            )
        emitter = SysmonEventEmitter(
            load_format("windows_event_sysmon"),
            output_path,
            threaded=False,
            source_finalization=True,
        )
    format_name = "sysmon_alias" if target_kind == "alias" else "windows_event_sysmon"
    publication = _foundation_publication_fixture(
        DeferredSessionKind.SSH,
        tmp_path,
        extra_emitters={format_name: emitter},  # type: ignore[dict-item]
        prepare_publication=False,
        transport_source_pid=4_321,
        transport_source_image=r"C:\Windows\System32\OpenSSH\ssh.exe",
    )
    if target_kind == "replaced":
        replaced = SysmonEventEmitter(
            load_format("windows_event_sysmon"),
            tmp_path / "replacement",
            threaded=False,
            source_finalization=True,
        )
        publication.dispatcher.emitters["windows_event_sysmon"] = replaced
    state_version = publication.fixture.state.materialization_version
    state_digest = publication.fixture.state.materialization_digest()
    timing_digest = publication.fixture.timing_planner.state_digest()

    with pytest.raises(EventContractError, match="lacks exact projection publication"):
        publication.dispatcher.prepare_deferred_session_publication_batch(
            publication.composition,
            publication.fixture.coordinator,
        )

    assert publication.fixture.state.materialization_version == state_version
    assert publication.fixture.state.materialization_digest() == state_digest
    assert publication.fixture.timing_planner.state_digest() == timing_digest
    assert not output_path.exists()
    assert _OpenSysmonSubclass.marker_reads == 0
    assert _OpenDuckSysmon.marker_reads == 0
    assert _OpenDuckSysmon.emit_calls == 0
    assert alias_marker_reads == 0
    _assert_deferred_dispatcher_reservations_released(publication.dispatcher)
    _cancel_unmaterialized_publication(publication)
    publication.ecar.close()
    publication.zeek.close()
    if isinstance(emitter, SysmonEventEmitter):
        emitter.close()
    if replaced is not None:
        replaced.close()


def test_exact_deferred_ssh_sysmon_warmup_skips_capability_and_filter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A fully suppressed actorful SSH open never consults its Sysmon sink."""

    sysmon_root = tmp_path / "sysmon"
    sysmon = SysmonEventEmitter(
        load_format("windows_event_sysmon"),
        sysmon_root,
        threaded=False,
        source_finalization=True,
    )
    marker_reads = 0
    helper_calls = 0

    def reject_marker_read(_emitter: SysmonEventEmitter) -> bool:
        nonlocal marker_reads
        marker_reads += 1
        raise AssertionError("suppressed Sysmon exact marker executed")

    def reject_helper(_emitter: SysmonEventEmitter, _event: object) -> bool:
        nonlocal helper_calls
        helper_calls += 1
        raise AssertionError("suppressed Sysmon Event 3 helper executed")

    monkeypatch.setattr(
        SysmonEventEmitter,
        "supports_exact_projection_publication",
        property(reject_marker_read),
    )
    monkeypatch.setattr(
        SysmonEventEmitter,
        "_event3_projection_eligible",
        reject_helper,
        raising=False,
    )
    original_prepare = ExactPublicationBatch.prepare
    prepared_row_counts: list[int] = []

    def capture_row_count(
        batch: ExactPublicationBatch,
        render: Callable[[], object],
    ) -> object:
        result = original_prepare(batch, render)
        prepared_row_counts.append(batch.prepared_row_count)
        return result

    monkeypatch.setattr(ExactPublicationBatch, "prepare", capture_row_count)
    publication = _foundation_publication_fixture(
        DeferredSessionKind.SSH,
        tmp_path,
        extra_emitters={"windows_event_sysmon": sysmon},
        collection_deployment=_compiled_ssh_sysmon_deployment(),
        output_start_time=_END,
        transport_source_pid=4_321,
        transport_source_image=r"C:\Windows\System32\OpenSSH\ssh.exe",
    )
    committed = publication.authority.materialize_prepared_deferred_session_publication(
        publication.composition,
        publication.fixture.coordinator,
        publication.fixture.owner_rng,
        dispatcher=publication.dispatcher,
        publication_batch=publication.batch,
    )

    assert all(outcome.status == "succeeded" for outcome in committed.publication.projections)
    assert prepared_row_counts == [0]
    assert marker_reads == helper_calls == 0
    assert "_filters" not in sysmon.__dict__
    assert sysmon.exact_candidate_census().high_water_rows == 0
    _assert_deferred_dispatcher_reservations_released(publication.dispatcher)
    publication.ecar.close()
    publication.zeek.close()
    _finalize_sysmon_source(sysmon)
    assert not tuple(sysmon_root.rglob("windows_event_sysmon.xml"))


def test_exact_deferred_bridge_rejects_marker_impostor_before_render(
    tmp_path: Path,
) -> None:
    """A custom class cannot opt itself into the closed eCAR exact contract."""

    class ImpostorEcarEmitter(EcarEmitter):
        @property
        def supports_exact_projection_publication(self) -> bool:
            return True

    output_path = tmp_path / "impostor"
    impostor = ImpostorEcarEmitter(
        load_format("ecar"),
        output_path,
        threaded=False,
    )
    publication = _foundation_publication_fixture(
        DeferredSessionKind.SSH,
        tmp_path,
        extra_emitters={"ecar": impostor},
        prepare_publication=False,
    )

    with pytest.raises(EventContractError, match="lacks exact projection publication"):
        publication.dispatcher.prepare_deferred_session_publication_batch(
            publication.composition,
            publication.fixture.coordinator,
        )

    assert not output_path.exists()
    _assert_deferred_dispatcher_reservations_released(publication.dispatcher)
    _cancel_unmaterialized_publication(publication)
    publication.ecar.close()
    publication.zeek.close()
    impostor.close()


def test_exact_deferred_bridge_rejects_different_lifecycle_authority_before_state(
    tmp_path: Path,
) -> None:
    """A valid batch cannot be committed through another lifecycle authority."""

    publication = _foundation_publication_fixture(DeferredSessionKind.RDP, tmp_path)
    fixture = publication.fixture
    other_authority = _bound_authority(fixture)
    state_version = fixture.state.materialization_version
    state_digest = fixture.state.materialization_digest()

    with pytest.raises(StateError, match="different lifecycle authority"):
        other_authority.materialize_prepared_deferred_session_publication(
            publication.composition,
            fixture.coordinator,
            fixture.owner_rng,
            dispatcher=publication.dispatcher,
            publication_batch=publication.batch,
        )

    assert fixture.state.materialization_version == state_version
    assert fixture.state.materialization_digest() == state_digest
    assert not fixture.source_timing_preparation.committed
    _cancel_unmaterialized_publication(publication)
    _assert_deferred_dispatcher_reservations_released(publication.dispatcher)
    publication.ecar.close()
    publication.zeek.close()


def test_exact_deferred_bridge_rejects_premature_precommit_claim_neutrally(
    tmp_path: Path,
) -> None:
    """Only lifecycle may claim a precommit after binding its exact result shell."""

    publication = _foundation_publication_fixture(DeferredSessionKind.SSH, tmp_path)
    dispatcher = publication.dispatcher
    precommit = dispatcher.prepare_deferred_session_publication_precommit(
        publication.batch,
        composition=publication.composition,
        coordinator=publication.fixture.coordinator,
    )
    before_deferred = dispatcher.deferred_session_publication_census()
    before_recovery = dispatcher.exact_projection_recovery_census()

    assert not dispatcher.claim_deferred_session_publication_precommit(precommit)

    assert dispatcher.deferred_session_publication_census() == before_deferred
    assert dispatcher.exact_projection_recovery_census() == before_recovery
    _cancel_unmaterialized_publication(publication)
    _assert_deferred_dispatcher_reservations_released(dispatcher)
    publication.ecar.close()
    publication.zeek.close()


@pytest.mark.parametrize("malformation", ("copy", "deepcopy", "foreign", "tampered"))
def test_exact_deferred_bridge_rejects_unauthentic_materialization_shell(
    malformation: str,
    tmp_path: Path,
) -> None:
    """Copied, foreign, or changed lifecycle result identities cannot reach State."""

    publication = _foundation_publication_fixture(DeferredSessionKind.RDP, tmp_path)
    fixture = publication.fixture
    dispatcher = publication.dispatcher
    precommit = dispatcher.prepare_deferred_session_publication_precommit(
        publication.batch,
        composition=publication.composition,
        coordinator=fixture.coordinator,
    )
    shells = publication.authority._prepare_deferred_session_materialization_shells(
        fixture.prepared_root,
        fixture.source_timing_preparation,
        (),
    )
    if malformation == "copy":
        shell = copy(shells.network_receipt)
    elif malformation == "deepcopy":
        shell = deepcopy(shells.network_receipt)
    elif malformation == "foreign":
        shell = (
            _bound_authority(fixture)
            ._prepare_deferred_session_materialization_shells(
                fixture.prepared_root,
                fixture.source_timing_preparation,
                (),
            )
            .network_receipt
        )
    else:
        shell = shells.network_receipt
        object.__setattr__(shell, "_transaction_id", "tampered-transport")
    state_version = fixture.state.materialization_version
    before_deferred = dispatcher.deferred_session_publication_census()

    with pytest.raises(EventContractError, match="lifecycle authentication"):
        dispatcher.bind_deferred_session_materialization_receipt_shell(
            precommit,
            shell,
        )

    assert not dispatcher.claim_deferred_session_publication_precommit(precommit)
    assert fixture.state.materialization_version == state_version
    assert dispatcher.deferred_session_publication_census() == before_deferred
    _cancel_unmaterialized_publication(publication)
    _assert_deferred_dispatcher_reservations_released(dispatcher)
    publication.ecar.close()
    publication.zeek.close()


@pytest.mark.parametrize("malformation", ("session_id", "swapped_target"))
def test_exact_deferred_bridge_rejects_malformed_session_binding_before_state(
    malformation: str,
    tmp_path: Path,
) -> None:
    """State identity alone cannot authorize a different session or target host."""

    publication = _foundation_publication_fixture(
        DeferredSessionKind.RDP,
        tmp_path,
        session_id_delta=1 if malformation == "session_id" else 0,
        swap_dependent_target=malformation == "swapped_target",
        prepare_publication=False,
    )
    state_version = publication.fixture.state.materialization_version
    state_digest = publication.fixture.state.materialization_digest()

    with pytest.raises(
        EventContractError,
        match=(
            "authentication dependent" if malformation == "session_id" else "exact State target"
        ),
    ):
        publication.dispatcher.prepare_deferred_session_publication_batch(
            publication.composition,
            publication.fixture.coordinator,
        )

    assert publication.fixture.state.materialization_version == state_version
    assert publication.fixture.state.materialization_digest() == state_digest
    _assert_deferred_dispatcher_reservations_released(publication.dispatcher)
    _cancel_unmaterialized_publication(publication)
    publication.ecar.close()
    publication.zeek.close()


@pytest.mark.parametrize("kind", (DeferredSessionKind.SSH, DeferredSessionKind.RDP))
def test_exact_deferred_bridge_accepts_exact_root_owned_process_dependent(
    kind: DeferredSessionKind,
    tmp_path: Path,
) -> None:
    """SSH/RDP may publish an exact State process on the canonical target host."""

    publication = _foundation_publication_fixture(
        kind,
        tmp_path,
        include_process_dependent=True,
    )
    committed = publication.authority.materialize_prepared_deferred_session_publication(
        publication.composition,
        publication.fixture.coordinator,
        publication.fixture.owner_rng,
        dispatcher=publication.dispatcher,
        publication_batch=publication.batch,
    )

    assert len(committed.publication.projections) == 3
    assert all(outcome.status == "succeeded" for outcome in committed.publication.projections)
    ecar_rows, zeek_rows = _close_and_read_publication(publication)
    objects = [row.get("object") for row in ecar_rows if row.get("hostname") == "DB-01"]
    assert "FLOW" in objects
    assert "PROCESS" in objects
    assert "USER_SESSION" in objects
    assert max(index for index, value in enumerate(objects) if value == "FLOW") < min(
        index for index, value in enumerate(objects) if value in {"PROCESS", "USER_SESSION"}
    )
    assert len(zeek_rows) == 1


@pytest.mark.parametrize("kind", (DeferredSessionKind.SSH, DeferredSessionKind.RDP))
def test_compiled_deferred_initial_cohort_preserves_target_ecar_proofs_under_missingness(
    kind: DeferredSessionKind,
    tmp_path: Path,
) -> None:
    """Required target eCAR rows keep every admitted initial member provable."""

    publication = _foundation_publication_fixture(
        kind,
        tmp_path,
        include_process_dependent=True,
        collection_deployment=_compiled_deferred_ecar_deployment(missingness=1.0),
        observation_policy=ObservationPolicy("enterprise_standard"),
    )
    committed = publication.authority.materialize_prepared_deferred_session_publication(
        publication.composition,
        publication.fixture.coordinator,
        publication.fixture.owner_rng,
        dispatcher=publication.dispatcher,
        publication_batch=publication.batch,
    )

    assert len(committed.publication.projections) == 3
    assert all(outcome.status == "succeeded" for outcome in committed.publication.projections)
    assert {
        proof.member_ordinal
        for proof in committed.publication.target_proofs
        if proof.format_name == "ecar" and proof.row_count > 0
    } == {0, 1, 2}
    ecar_rows, zeek_rows = _close_and_read_publication(publication)
    assert zeek_rows == []
    assert {str(row.get("hostname")) for row in ecar_rows} == {"DB-01"}
    assert [row.get("object") for row in ecar_rows] == [
        "FLOW",
        "PROCESS",
        "USER_SESSION",
    ]


def test_exact_deferred_bridge_rejects_reversed_process_host_before_state(
    tmp_path: Path,
) -> None:
    """A root process cannot be rendered on the transport's opposite endpoint."""

    publication = _foundation_publication_fixture(
        DeferredSessionKind.SSH,
        tmp_path,
        include_process_dependent=True,
        reverse_process_host=True,
        prepare_publication=False,
    )
    fixture = publication.fixture
    state_version = fixture.state.materialization_version
    state_digest = fixture.state.materialization_digest()

    with pytest.raises(EventContractError, match="exact State target"):
        publication.dispatcher.prepare_deferred_session_publication_batch(
            publication.composition,
            fixture.coordinator,
        )

    assert fixture.state.materialization_version == state_version
    assert fixture.state.materialization_digest() == state_digest
    _cancel_unmaterialized_publication(publication)
    _assert_deferred_dispatcher_reservations_released(publication.dispatcher)
    publication.ecar.close()
    publication.zeek.close()


@pytest.mark.parametrize("kind", (DeferredSessionKind.SSH, DeferredSessionKind.RDP))
@pytest.mark.parametrize(
    "spoof_transport_source_hostname",
    (False, True),
    ids=("canonical-transport-hosts", "spoofed-transport-source-host"),
)
def test_exact_deferred_bridge_rejects_process_hostname_with_opposite_endpoint_ip(
    kind: DeferredSessionKind,
    spoof_transport_source_hostname: bool,
    tmp_path: Path,
) -> None:
    """A State hostname cannot be paired with the root's other endpoint address."""

    publication = _foundation_publication_fixture(
        kind,
        tmp_path,
        include_process_dependent=True,
        process_opposite_ip=True,
        spoof_transport_source_hostname=spoof_transport_source_hostname,
        prepare_publication=False,
    )
    fixture = publication.fixture
    state_version = fixture.state.materialization_version
    state_digest = fixture.state.materialization_digest()

    with pytest.raises(EventContractError, match="exact State target"):
        publication.dispatcher.prepare_deferred_session_publication_batch(
            publication.composition,
            fixture.coordinator,
        )

    assert fixture.state.materialization_version == state_version
    assert fixture.state.materialization_digest() == state_digest
    _cancel_unmaterialized_publication(publication)
    _assert_deferred_dispatcher_reservations_released(publication.dispatcher)
    publication.ecar.close()
    publication.zeek.close()


@pytest.mark.parametrize("kind", (DeferredSessionKind.SSH, DeferredSessionKind.RDP))
def test_exact_deferred_bridge_commits_and_closes_transport_before_session(
    kind: DeferredSessionKind,
    tmp_path: Path,
) -> None:
    """Concrete final eCAR rows retain FLOW-before-USER_SESSION ordering."""

    publication = _foundation_publication_fixture(kind, tmp_path)
    fixture = publication.fixture
    dispatcher = publication.dispatcher
    assert dispatcher.authenticates_prepared_deferred_session_publication_batch(publication.batch)
    assert not publication.zeek_path.exists()
    assert not tuple(publication.ecar_root.rglob("ecar.json"))
    with pytest.raises(StateError, match="claimed|batch"):
        dispatcher.publish_prepared(publication.composition.transport_dispatch)

    committed = publication.authority.materialize_prepared_deferred_session_publication(
        publication.composition,
        fixture.coordinator,
        fixture.owner_rng,
        dispatcher=dispatcher,
        publication_batch=publication.batch,
    )

    assert all(outcome.status == "succeeded" for outcome in committed.publication.projections)
    assert dispatcher.authenticates_deferred_session_publication_receipt(
        committed.publication.receipt
    )
    assert fixture.state.get_session(fixture.session_plan.identity.logon_id) is not None
    assert not dispatcher.authenticates_prepared_deferred_session_publication_batch(
        publication.batch
    )
    ecar_rows, zeek_rows = _close_and_read_publication(publication)
    target_rows = [row for row in ecar_rows if row.get("hostname") == "DB-01"]
    flow_indexes = [index for index, row in enumerate(target_rows) if row.get("object") == "FLOW"]
    session_indexes = [
        index for index, row in enumerate(target_rows) if row.get("object") == "USER_SESSION"
    ]
    assert flow_indexes and session_indexes
    assert max(flow_indexes) < min(session_indexes)
    assert len(zeek_rows) == 1


def test_authored_ssh_planner_authentication_precedes_lifecycle_materialization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Planner prevalidation may precede the lifecycle-owned authored commit."""

    publication = _foundation_publication_fixture(
        DeferredSessionKind.SSH,
        tmp_path,
        with_intent=True,
        include_process_dependent=True,
    )
    dispatcher = publication.dispatcher
    ledger = dispatcher.intent_execution_ledger
    assert ledger is not None
    assert publication.batch is not None
    assert len(publication.composition.publication_order) == 3

    certification_calls = 0
    original_certify = PreparedIntentExecutionBatch.certify_composite_commit

    def count_certification(
        preparation: PreparedIntentExecutionBatch,
        expected_receipt: IntentExecutionBatchReceipt,
    ) -> None:
        nonlocal certification_calls
        certification_calls += 1
        original_certify(preparation, expected_receipt)

    monkeypatch.setattr(
        PreparedIntentExecutionBatch,
        "certify_composite_commit",
        count_certification,
    )
    boundary = _PreparedNetworkBoundary()
    boundary.track_deferred_session_publication_batch(dispatcher, publication.batch)
    boundary.validate_deferred_session_publication_batch()
    boundary.transfer()

    assert certification_calls == 1
    assert ledger.snapshot() == ()
    prepared_census = ledger.batch_preparation_census()
    assert (
        prepared_census.reservations,
        prepared_census.claimed_reservations,
        prepared_census.reserved_intents,
        prepared_census.prepared_deltas,
        prepared_census.prepared_commit_plans,
        prepared_census.mutation_fences,
    ) == (1, 1, 1, 3, 1, 1)

    committed = publication.authority.materialize_prepared_deferred_session_publication(
        publication.composition,
        publication.fixture.coordinator,
        publication.fixture.owner_rng,
        dispatcher=dispatcher,
        publication_batch=publication.batch,
    )

    assert all(outcome.status == "succeeded" for outcome in committed.publication.projections)
    assert certification_calls == 1
    snapshots = ledger.snapshot()
    assert len(snapshots) == 1
    snapshot = snapshots[0]
    assert snapshot.intent_id == "deferred-bridge-intent"
    assert snapshot.action_reference_count == 3
    assert snapshot.occurrence_reference_count == 3
    assert snapshot.duplicate_occurrence_count == 0
    final_census = ledger.batch_preparation_census()
    assert (
        final_census.reservations,
        final_census.claimed_reservations,
        final_census.reserved_intents,
        final_census.capability_locators,
        final_census.prepared_deltas,
        final_census.prepared_commit_plans,
        final_census.mutation_fences,
        final_census.retained_bytes,
    ) == (0, 0, 0, 0, 0, 0, 0, 0)
    assert (
        publication.fixture.lifecycle_registry.closed_transport_preparation_census().reservations
        == 0
    )
    _assert_deferred_dispatcher_reservations_released(dispatcher)
    ecar_rows, zeek_rows = _close_and_read_publication(publication)
    assert len(ecar_rows) == 4
    assert sum(row.get("object") == "PROCESS" for row in ecar_rows) == 1
    assert len(zeek_rows) == 1


@pytest.mark.parametrize("failure_mode", ("fail-before", "lost-return"))
def test_exact_deferred_bridge_recovers_connection_receipt_issuance(
    failure_mode: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The outer connection proof survives constructor failure and lost return."""

    publication = _foundation_publication_fixture(DeferredSessionKind.RDP, tmp_path)
    receipt_type = LifecycleConnectionCompositeReceipt
    original = receipt_type._issue
    attempts = 0

    def fail_receipt_issue(cls: object, **kwargs: object) -> object:
        nonlocal attempts
        attempts += 1
        if failure_mode == "lost-return":
            original(**kwargs)
        raise OSError(f"injected {failure_mode} receipt issuance")

    monkeypatch.setattr(receipt_type, "_issue", classmethod(fail_receipt_issue))
    committed = publication.authority.materialize_prepared_deferred_session_publication(
        publication.composition,
        publication.fixture.coordinator,
        publication.fixture.owner_rng,
        dispatcher=publication.dispatcher,
        publication_batch=publication.batch,
    )

    assert attempts == 1
    assert publication.authority.authenticates_prepared_network_receipt(
        publication.fixture.prepared_root,
        committed.materialization.receipt,
    )
    assert publication.dispatcher.authenticates_deferred_session_publication_receipt(
        committed.publication.receipt
    )
    ecar_rows, zeek_rows = _close_and_read_publication(publication)
    assert len(ecar_rows) == 3
    assert len(zeek_rows) == 1


@pytest.mark.parametrize(
    ("owner_name", "owner_type", "method_name"),
    (
        (
            "lifecycle",
            PreparedLifecycleClosedTransportPublication,
            "commit_no_fail",
        ),
        (
            "state",
            StateManager,
            "_commit_claimed_connection_composite_materialization",
        ),
        ("application", SshChannelPreparedCommit, "commit_no_fail"),
        ("runtime", NetworkTransactionPreparedCommit, "commit_no_fail"),
        ("timing", SourceTimingPreparation, "commit_no_fail"),
    ),
)
@pytest.mark.parametrize("failure_mode", ("fail-before", "lost-return"))
def test_exact_deferred_bridge_recovers_each_inner_canonical_owner(
    owner_name: str,
    owner_type: type[object],
    method_name: str,
    failure_mode: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every claimed canonical owner retries or adopts before claims unwind."""

    publication = _foundation_publication_fixture(DeferredSessionKind.SSH, tmp_path)
    original = getattr(owner_type, method_name)
    attempts = 0

    def inject_commit(*args: object) -> object:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            if failure_mode == "lost-return":
                original(*args)
            raise OSError(f"injected {owner_name} {failure_mode}")
        return original(*args)

    monkeypatch.setattr(owner_type, method_name, inject_commit)
    committed = publication.authority.materialize_prepared_deferred_session_publication(
        publication.composition,
        publication.fixture.coordinator,
        publication.fixture.owner_rng,
        dispatcher=publication.dispatcher,
        publication_batch=publication.batch,
    )

    assert attempts == (2 if failure_mode == "fail-before" else 1)
    assert publication.fixture.source_timing_preparation.committed
    assert (
        publication.fixture.state.get_session(publication.fixture.session_plan.identity.logon_id)
        is not None
    )
    assert publication.dispatcher.exact_projection_recovery_census().unresolved_recoveries == 0
    assert publication.authority.authenticates_prepared_network_receipt(
        publication.fixture.prepared_root,
        committed.materialization.receipt,
    )
    assert publication.dispatcher.authenticates_deferred_session_publication_receipt(
        committed.publication.receipt
    )
    ecar_rows, zeek_rows = _close_and_read_publication(publication)
    assert len(ecar_rows) == 3
    assert len(zeek_rows) == 1


def test_exact_deferred_bridge_precommit_rejection_cancels_every_reservation(
    tmp_path: Path,
) -> None:
    """A final owner rejection leaves no canonical or exact-source residue."""

    publication = _foundation_publication_fixture(DeferredSessionKind.SSH, tmp_path)
    fixture = publication.fixture
    dispatcher = publication.dispatcher

    def reject() -> None:
        raise StateError("injected deferred publication rejection")

    publication.authority._materialization_precommit_hook = reject
    with pytest.raises(StateError, match="injected deferred publication rejection"):
        publication.authority.materialize_prepared_deferred_session_publication(
            publication.composition,
            fixture.coordinator,
            fixture.owner_rng,
            dispatcher=dispatcher,
            publication_batch=publication.batch,
        )

    assert dispatcher.cancel_prepared_deferred_session_publication_batch(publication.batch)
    assert fixture.state.get_session(fixture.session_plan.identity.logon_id) is None
    assert fixture.lifecycle_registry.stats().live_transports == 0
    assert dispatcher.deferred_session_publication_census().prepared_batches == 0
    assert dispatcher.deferred_session_publication_census().retained_members == 0
    assert dispatcher.deferred_session_publication_census().retained_bytes == 0
    assert dispatcher.exact_projection_recovery_census().authority.active_batches == 0
    ecar_rows, zeek_rows = _close_and_read_publication(publication)
    assert ecar_rows == []
    assert zeek_rows == []


def test_exact_deferred_bridge_reauthenticates_after_hook_before_state_commit(
    tmp_path: Path,
) -> None:
    """A hook-time member mutation loses at the final reversible owner fence."""

    publication = _foundation_publication_fixture(DeferredSessionKind.RDP, tmp_path)
    fixture = publication.fixture
    dispatcher = publication.dispatcher
    state_version = fixture.state.materialization_version
    state_digest = fixture.state.materialization_digest()
    timing_digest = fixture.timing_planner.state_digest()
    runtime_digest = fixture.runtime.state_digest()

    def tamper_claimed_member() -> None:
        fixture.dependent_dispatches[0]._deferred_session_publication_batch_id = -1

    publication.authority._materialization_precommit_hook = tamper_claimed_member
    with pytest.raises(StateError, match="canonical precommit fence"):
        publication.authority.materialize_prepared_deferred_session_publication(
            publication.composition,
            fixture.coordinator,
            fixture.owner_rng,
            dispatcher=dispatcher,
            publication_batch=publication.batch,
        )

    assert fixture.state.materialization_version == state_version
    assert fixture.state.materialization_digest() == state_digest
    assert fixture.timing_planner.state_digest() == timing_digest
    assert fixture.runtime.state_digest() == runtime_digest
    assert not fixture.source_timing_preparation.committed
    with pytest.raises(EventContractError, match="reservations were cancelled"):
        dispatcher.cancel_prepared_deferred_session_publication_batch(publication.batch)
    assert fixture.dependent_dispatches[0]._deferred_session_publication_batch_id is None
    _assert_deferred_dispatcher_reservations_released(dispatcher)
    ecar_rows, zeek_rows = _close_and_read_publication(publication)
    assert ecar_rows == []
    assert zeek_rows == []


@pytest.mark.parametrize(
    "malformation",
    ("missing-claim", "other-claim", "valid-seal", "fresh-lock", "aliased-lock"),
)
def test_exact_deferred_bridge_rejects_valid_shaped_hook_member_tamper(
    malformation: str,
    tmp_path: Path,
) -> None:
    """The last claim verifies exact member ownership, not merely field shape."""

    publication = _foundation_publication_fixture(DeferredSessionKind.RDP, tmp_path)
    fixture = publication.fixture
    dispatcher = publication.dispatcher
    state_version = fixture.state.materialization_version
    state_digest = fixture.state.materialization_digest()
    timing_digest = fixture.timing_planner.state_digest()
    runtime_digest = fixture.runtime.state_digest()

    def tamper_claimed_member() -> None:
        prepared = fixture.dependent_dispatches[0]
        if malformation == "missing-claim":
            prepared._deferred_session_publication_batch_id = None
        elif malformation == "other-claim":
            prepared._deferred_session_publication_batch_id = 99_999
        elif malformation == "valid-seal":
            prepared._integrity_token = "a" * 64
        elif malformation == "fresh-lock":
            prepared._lock = Lock()
        else:
            prepared._lock = fixture.transport_dispatch._lock

    publication.authority._materialization_precommit_hook = tamper_claimed_member
    with pytest.raises(StateError, match="canonical precommit fence"):
        publication.authority.materialize_prepared_deferred_session_publication(
            publication.composition,
            fixture.coordinator,
            fixture.owner_rng,
            dispatcher=dispatcher,
            publication_batch=publication.batch,
        )

    assert fixture.state.materialization_version == state_version
    assert fixture.state.materialization_digest() == state_digest
    assert fixture.timing_planner.state_digest() == timing_digest
    assert fixture.runtime.state_digest() == runtime_digest
    assert not fixture.source_timing_preparation.committed
    with pytest.raises(EventContractError, match="reservations were cancelled"):
        dispatcher.cancel_prepared_deferred_session_publication_batch(publication.batch)
    assert fixture.dependent_dispatches[0]._deferred_session_publication_batch_id is None
    _assert_deferred_dispatcher_reservations_released(dispatcher)
    ecar_rows, zeek_rows = _close_and_read_publication(publication)
    assert ecar_rows == []
    assert zeek_rows == []


def test_exact_deferred_bridge_exposes_materialization_for_preinstall_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A receipt-construction failure leaves the committed root exactly retryable."""

    publication = _foundation_publication_fixture(DeferredSessionKind.SSH, tmp_path)
    dispatcher = publication.dispatcher
    original = dispatcher._deferred_session_publication_receipt_integrity
    attempts = 0

    def fail_once(receipt: object) -> str:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise OSError("injected deferred receipt preinstall failure")
        return original(receipt)

    monkeypatch.setattr(
        dispatcher,
        "_deferred_session_publication_receipt_integrity",
        fail_once,
    )
    with pytest.raises(OSError, match="preinstall failure") as raised:
        publication.authority.materialize_prepared_deferred_session_publication(
            publication.composition,
            publication.fixture.coordinator,
            publication.fixture.owner_rng,
            dispatcher=dispatcher,
            publication_batch=publication.batch,
        )

    materialization = raised.value.deferred_session_materialization
    assert (
        publication.fixture.state.get_session(publication.fixture.session_plan.identity.logon_id)
        is not None
    )
    assert dispatcher.exact_projection_recovery_census().unresolved_recoveries == 1
    result = dispatcher.publish_prepared_deferred_session_publication_batch(
        publication.batch,
        materialization_receipt=materialization.receipt,
    )
    assert all(outcome.status == "succeeded" for outcome in result.projections)
    assert dispatcher.authenticates_deferred_session_publication_receipt(result.receipt)
    ecar_rows, zeek_rows = _close_and_read_publication(publication)
    assert len(ecar_rows) == 3
    assert len(zeek_rows) == 1


def test_exact_deferred_bridge_adopts_dispatcher_ledger_lost_return(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A committed dispatcher-ledger tail is adopted without replaying its deltas."""

    publication = _foundation_publication_fixture(
        DeferredSessionKind.SSH,
        tmp_path,
        with_intent=True,
    )
    dispatcher = publication.dispatcher
    original = dispatcher._commit_deferred_session_dispatcher_ledgers_no_fail
    attempts = 0

    def lose_ledger_return(record: object) -> None:
        nonlocal attempts
        attempts += 1
        original(record)
        if attempts == 1:
            raise OSError("injected dispatcher-ledger lost return")

    monkeypatch.setattr(
        dispatcher,
        "_commit_deferred_session_dispatcher_ledgers_no_fail",
        lose_ledger_return,
    )
    committed = publication.authority.materialize_prepared_deferred_session_publication(
        publication.composition,
        publication.fixture.coordinator,
        publication.fixture.owner_rng,
        dispatcher=dispatcher,
        publication_batch=publication.batch,
    )

    assert attempts == 1
    assert dispatcher.authenticates_deferred_session_publication_receipt(
        committed.publication.receipt
    )
    assert dispatcher.exact_projection_recovery_census().unresolved_recoveries == 0
    ecar_rows, zeek_rows = _close_and_read_publication(publication)
    assert len(ecar_rows) == 3
    assert len(zeek_rows) == 1


def test_exact_deferred_bridge_engine_drain_resumes_owner_tail(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An owner-tail failure remains dispatcher-retained and engine-drainable."""

    publication = _foundation_publication_fixture(DeferredSessionKind.RDP, tmp_path)
    dispatcher = publication.dispatcher
    original = dispatcher._complete_deferred_session_owner_tail
    attempts = 0

    def fail_owner_tail_once(record: object) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise OSError("injected deferred owner-tail failure")
        original(record)

    monkeypatch.setattr(
        dispatcher,
        "_complete_deferred_session_owner_tail",
        fail_owner_tail_once,
    )
    with pytest.raises(OSError, match="owner-tail failure") as raised:
        publication.authority.materialize_prepared_deferred_session_publication(
            publication.composition,
            publication.fixture.coordinator,
            publication.fixture.owner_rng,
            dispatcher=dispatcher,
            publication_batch=publication.batch,
        )

    receipt = raised.value.deferred_session_publication_receipt
    assert not dispatcher.authenticates_deferred_session_publication_receipt(receipt)
    assert dispatcher.exact_projection_recovery_census().unresolved_recoveries == 1
    results = dispatcher.drain_exact_projection_recoveries()
    assert len(results) == 1
    assert dispatcher.authenticates_deferred_session_publication_receipt(receipt)
    assert all(outcome.status == "succeeded" for outcome in results[0].projections)
    assert attempts == 2
    ecar_rows, zeek_rows = _close_and_read_publication(publication)
    assert len(ecar_rows) == 3
    assert len(zeek_rows) == 1


def test_exact_deferred_bridge_rejects_copied_foreign_and_tampered_batches(
    tmp_path: Path,
) -> None:
    """Only the retained carrier identity may authenticate or release its claims."""

    publication = _foundation_publication_fixture(
        DeferredSessionKind.SSH,
        tmp_path / "owner",
    )
    foreign = _foundation_publication_fixture(
        DeferredSessionKind.RDP,
        tmp_path / "foreign",
    )
    for candidate in (copy(publication.batch), deepcopy(publication.batch)):
        assert not publication.dispatcher.authenticates_prepared_deferred_session_publication_batch(
            candidate
        )
        assert not publication.dispatcher.cancel_prepared_deferred_session_publication_batch(
            candidate
        )
    assert not publication.dispatcher.authenticates_prepared_deferred_session_publication_batch(
        foreign.batch
    )
    with pytest.raises(EventContractError):
        publication.dispatcher.cancel_prepared_deferred_session_publication_batch(foreign.batch)

    publication.batch._dispatcher_id = "tampered-dispatcher"
    assert not publication.dispatcher.authenticates_prepared_deferred_session_publication_batch(
        publication.batch
    )
    with pytest.raises(EventContractError, match="reservations were cancelled"):
        publication.dispatcher.cancel_prepared_deferred_session_publication_batch(publication.batch)
    _cancel_unmaterialized_publication(publication)
    _assert_deferred_dispatcher_reservations_released(publication.dispatcher)
    _cancel_unmaterialized_publication(foreign)
    _assert_deferred_dispatcher_reservations_released(foreign.dispatcher)
    publication.ecar.close()
    publication.zeek.close()
    foreign.ecar.close()
    foreign.zeek.close()


def test_exact_deferred_bridge_rejects_copied_foreign_and_tampered_receipts(
    tmp_path: Path,
) -> None:
    """Terminal receipt authentication remains identity-, authority-, and HMAC-bound."""

    publication = _foundation_publication_fixture(
        DeferredSessionKind.RDP,
        tmp_path / "owner",
    )
    committed = publication.authority.materialize_prepared_deferred_session_publication(
        publication.composition,
        publication.fixture.coordinator,
        publication.fixture.owner_rng,
        dispatcher=publication.dispatcher,
        publication_batch=publication.batch,
    )
    foreign = _foundation_publication_fixture(
        DeferredSessionKind.SSH,
        tmp_path / "foreign",
    )
    foreign_committed = foreign.authority.materialize_prepared_deferred_session_publication(
        foreign.composition,
        foreign.fixture.coordinator,
        foreign.fixture.owner_rng,
        dispatcher=foreign.dispatcher,
        publication_batch=foreign.batch,
    )
    receipt = committed.publication.receipt
    for candidate in (copy(receipt), deepcopy(receipt), foreign_committed.publication.receipt):
        assert not publication.dispatcher.authenticates_deferred_session_publication_receipt(
            candidate
        )
        with pytest.raises(EventContractError, match="copied|foreign|stale|released"):
            publication.dispatcher.resume_deferred_session_publication(candidate)

    object.__setattr__(receipt, "publication_token", "0" * 64)
    assert not publication.dispatcher.authenticates_deferred_session_publication_receipt(receipt)
    with pytest.raises(EventContractError, match="stale|released"):
        publication.dispatcher.resume_deferred_session_publication(receipt)
    _close_and_read_publication(publication)
    _close_and_read_publication(foreign)


def test_exact_deferred_bridge_pending_receipt_cannot_forge_terminal_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Changing the public flag cannot authenticate a still-pending owner tail."""

    publication = _foundation_publication_fixture(DeferredSessionKind.SSH, tmp_path)
    dispatcher = publication.dispatcher
    original = dispatcher._complete_deferred_session_owner_tail
    attempts = 0

    def fail_owner_tail_once(record: object) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise OSError("injected pending owner receipt")
        original(record)

    monkeypatch.setattr(
        dispatcher,
        "_complete_deferred_session_owner_tail",
        fail_owner_tail_once,
    )
    with pytest.raises(OSError, match="pending owner receipt") as raised:
        publication.authority.materialize_prepared_deferred_session_publication(
            publication.composition,
            publication.fixture.coordinator,
            publication.fixture.owner_rng,
            dispatcher=dispatcher,
            publication_batch=publication.batch,
        )
    receipt = raised.value.deferred_session_publication_receipt
    object.__setattr__(receipt, "_published", True)

    assert not dispatcher.authenticates_deferred_session_publication_receipt(receipt)
    results = dispatcher.drain_exact_projection_recoveries()
    assert len(results) == 1
    assert dispatcher.authenticates_deferred_session_publication_receipt(receipt)
    _close_and_read_publication(publication)


def test_exact_deferred_bridge_capacity_rejects_before_claiming_members(
    tmp_path: Path,
) -> None:
    """The bounded dispatcher rejects a two-row carrier with one member slot."""

    with pytest.raises(StateError, match="member capacity"):
        _foundation_publication_fixture(
            DeferredSessionKind.RDP,
            tmp_path,
            member_capacity=1,
        )


def test_exact_deferred_bridge_preparation_capacity_rejects_neutrally(
    tmp_path: Path,
) -> None:
    """A full preparation registry does not claim any second-root dispatch."""

    publication = _foundation_publication_fixture(
        DeferredSessionKind.RDP,
        tmp_path,
        prepare_publication=False,
    )
    publication.dispatcher._action_cohort_preparation_capacity = 0
    before = publication.dispatcher.deferred_session_publication_census()

    with pytest.raises(StateError, match="preparation capacity"):
        publication.dispatcher.prepare_deferred_session_publication_batch(
            publication.composition,
            publication.fixture.coordinator,
        )

    assert publication.dispatcher.deferred_session_publication_census() == before
    assert all(
        prepared._deferred_session_publication_batch_id is None
        for prepared in (
            publication.fixture.transport_dispatch,
            *publication.fixture.dependent_dispatches,
        )
    )
    _cancel_unmaterialized_publication(publication)
    _assert_deferred_dispatcher_reservations_released(publication.dispatcher)
    publication.ecar.close()
    publication.zeek.close()


def test_exact_deferred_bridge_retained_byte_capacity_rejects_neutrally(
    tmp_path: Path,
) -> None:
    """A too-small byte budget rejects before installing member or sink claims."""

    publication = _foundation_publication_fixture(
        DeferredSessionKind.SSH,
        tmp_path,
        byte_capacity=1,
        prepare_publication=False,
    )
    with pytest.raises(StateError, match="retained-byte capacity"):
        publication.dispatcher.prepare_deferred_session_publication_batch(
            publication.composition,
            publication.fixture.coordinator,
        )

    assert all(
        prepared._deferred_session_publication_batch_id is None
        for prepared in (
            publication.fixture.transport_dispatch,
            *publication.fixture.dependent_dispatches,
        )
    )
    _assert_deferred_dispatcher_reservations_released(publication.dispatcher)
    _cancel_unmaterialized_publication(publication)
    publication.ecar.close()
    publication.zeek.close()


@pytest.mark.parametrize("failure_mode", ("fail-before", "lost-return"))
def test_exact_deferred_bridge_reconciles_exact_preflight_cancel_failure(
    failure_mode: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed exact-batch cleanup remains either terminal or explicitly retryable."""

    publication = _foundation_publication_fixture(
        DeferredSessionKind.RDP,
        tmp_path,
        prepare_publication=False,
    )
    dispatcher = publication.dispatcher
    original_integrity = dispatcher._deferred_session_publication_batch_integrity
    integrity_failed = False

    def fail_after_exact(batch: object, record: object) -> str:
        nonlocal integrity_failed
        if not integrity_failed and record.exact_publication_batch is not None:
            integrity_failed = True
            raise StateError("injected post-exact preparation failure")
        return original_integrity(batch, record)

    original_cancel = ExactPublicationBatch.cancel

    def fail_cancel(exact_batch: ExactPublicationBatch) -> None:
        if failure_mode == "lost-return":
            original_cancel(exact_batch)
        raise OSError(f"injected exact cancel {failure_mode}")

    monkeypatch.setattr(
        dispatcher,
        "_deferred_session_publication_batch_integrity",
        fail_after_exact,
    )
    monkeypatch.setattr(ExactPublicationBatch, "cancel", fail_cancel)
    with pytest.raises(StateError, match="post-exact preparation failure") as raised:
        dispatcher.prepare_deferred_session_publication_batch(
            publication.composition,
            publication.fixture.coordinator,
        )

    monkeypatch.setattr(ExactPublicationBatch, "cancel", original_cancel)
    if failure_mode == "fail-before":
        retained = raised.value.deferred_session_publication_batch
        assert dispatcher.cancel_prepared_deferred_session_publication_batch(retained)
    _assert_deferred_dispatcher_reservations_released(dispatcher)
    _cancel_unmaterialized_publication(publication)
    publication.ecar.close()
    publication.zeek.close()


@pytest.mark.parametrize("failure_mode", ("fail-before", "lost-return"))
def test_exact_deferred_bridge_reconciles_intent_preflight_cancel_failure(
    failure_mode: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An authored-intent cleanup never loses its retained cancellation owner."""

    publication = _foundation_publication_fixture(
        DeferredSessionKind.SSH,
        tmp_path,
        with_intent=True,
        prepare_publication=False,
    )
    dispatcher = publication.dispatcher
    original_integrity = dispatcher._deferred_session_publication_batch_integrity
    integrity_failed = False

    def fail_after_intent(batch: object, record: object) -> str:
        nonlocal integrity_failed
        if not integrity_failed and record.intent_token is not None:
            integrity_failed = True
            raise StateError("injected post-intent preparation failure")
        return original_integrity(batch, record)

    original_cancel = IntentExecutionLedger.cancel_batch

    def fail_cancel(
        ledger: IntentExecutionLedger,
        token: object,
    ) -> None:
        if failure_mode == "lost-return":
            original_cancel(ledger, token)
        raise OSError(f"injected intent cancel {failure_mode}")

    monkeypatch.setattr(
        dispatcher,
        "_deferred_session_publication_batch_integrity",
        fail_after_intent,
    )
    monkeypatch.setattr(IntentExecutionLedger, "cancel_batch", fail_cancel)
    with pytest.raises(StateError, match="post-intent preparation failure") as raised:
        dispatcher.prepare_deferred_session_publication_batch(
            publication.composition,
            publication.fixture.coordinator,
        )

    monkeypatch.setattr(IntentExecutionLedger, "cancel_batch", original_cancel)
    if failure_mode == "fail-before":
        retained = raised.value.deferred_session_publication_batch
        assert dispatcher.cancel_prepared_deferred_session_publication_batch(retained)
    ledger = dispatcher.intent_execution_ledger
    assert ledger is not None
    assert ledger.batch_preparation_census().reservations == 0
    _assert_deferred_dispatcher_reservations_released(dispatcher)
    _cancel_unmaterialized_publication(publication)
    publication.ecar.close()
    publication.zeek.close()


@pytest.mark.parametrize("capacity_kind", ("recovery", "receipt"))
def test_exact_deferred_bridge_precommit_capacity_rejection_cleans_reservations(
    capacity_kind: str,
    tmp_path: Path,
) -> None:
    """Recovery and receipt saturation remain reversible before State mutation."""

    publication = _foundation_publication_fixture(
        DeferredSessionKind.RDP,
        tmp_path,
    )
    if capacity_kind == "recovery":
        publication.dispatcher._exact_projection_recovery_capacity = 0
    else:
        publication.dispatcher._action_cohort_receipt_capacity = 0
    state_version = publication.fixture.state.materialization_version
    state_digest = publication.fixture.state.materialization_digest()

    with pytest.raises(EventContractError, match="precommit source batch"):
        publication.dispatcher.prepare_deferred_session_publication_precommit(
            publication.batch,
            composition=publication.composition,
            coordinator=publication.fixture.coordinator,
        )

    assert publication.fixture.state.materialization_version == state_version
    assert publication.fixture.state.materialization_digest() == state_digest
    assert publication.dispatcher.cancel_prepared_deferred_session_publication_batch(
        publication.batch
    )
    _cancel_unmaterialized_publication(publication)
    _assert_deferred_dispatcher_reservations_released(publication.dispatcher)
    publication.ecar.close()
    publication.zeek.close()


def test_exact_deferred_bridge_evicts_only_terminal_receipts_at_capacity(
    tmp_path: Path,
) -> None:
    """A capacity-one dispatcher reuses only an acknowledged terminal slot."""

    first = _foundation_publication_fixture(
        DeferredSessionKind.RDP,
        tmp_path,
        receipt_capacity=1,
    )
    first_result = first.authority.materialize_prepared_deferred_session_publication(
        first.composition,
        first.fixture.coordinator,
        first.fixture.owner_rng,
        dispatcher=first.dispatcher,
        publication_batch=first.batch,
    )
    assert first.dispatcher.authenticates_deferred_session_publication_receipt(
        first_result.publication.receipt
    )

    second = _next_rdp_publication_fixture(first, ordinal=2)
    second_result = second.authority.materialize_prepared_deferred_session_publication(
        second.composition,
        second.fixture.coordinator,
        second.fixture.owner_rng,
        dispatcher=second.dispatcher,
        publication_batch=second.batch,
    )

    assert not first.dispatcher.authenticates_deferred_session_publication_receipt(
        first_result.publication.receipt
    )
    with pytest.raises(EventContractError, match="recovery|receipt"):
        first.dispatcher.resume_deferred_session_publication(first_result.publication.receipt)
    assert second.dispatcher.authenticates_deferred_session_publication_receipt(
        second_result.publication.receipt
    )
    census = second.dispatcher.deferred_session_publication_census()
    assert census.committed_receipts == 1
    assert census.pending_receipts == 0
    assert census.receipt_reservations == 0
    assert census.receipt_eviction_reservations == 0
    ecar_rows, zeek_rows = _close_and_read_publication(second)
    assert len(ecar_rows) == 6
    assert len(zeek_rows) == 2


def test_exact_deferred_bridge_adopts_owner_tail_lost_return_through_eviction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A lost terminal return never reruns receipt installation or eviction."""

    first = _foundation_publication_fixture(
        DeferredSessionKind.RDP,
        tmp_path,
        receipt_capacity=1,
    )
    first_result = first.authority.materialize_prepared_deferred_session_publication(
        first.composition,
        first.fixture.coordinator,
        first.fixture.owner_rng,
        dispatcher=first.dispatcher,
        publication_batch=first.batch,
    )
    second = _next_rdp_publication_fixture(first, ordinal=2)
    dispatcher = second.dispatcher
    original = dispatcher._complete_deferred_session_owner_tail
    attempts = 0

    def lose_owner_tail_return(record: object) -> None:
        nonlocal attempts
        attempts += 1
        original(record)
        raise OSError("injected owner-tail lost return")

    monkeypatch.setattr(
        dispatcher,
        "_complete_deferred_session_owner_tail",
        lose_owner_tail_return,
    )
    with pytest.raises(OSError, match="owner-tail lost return") as raised:
        second.authority.materialize_prepared_deferred_session_publication(
            second.composition,
            second.fixture.coordinator,
            second.fixture.owner_rng,
            dispatcher=dispatcher,
            publication_batch=second.batch,
        )

    receipt = raised.value.deferred_session_publication_receipt
    assert attempts == 1
    assert not dispatcher.authenticates_deferred_session_publication_receipt(
        first_result.publication.receipt
    )
    assert dispatcher.authenticates_deferred_session_publication_receipt(receipt)
    census = dispatcher.deferred_session_publication_census()
    assert census.committed_receipts == 1
    assert census.pending_receipts == 0
    assert census.receipt_reservations == 0
    assert census.receipt_eviction_reservations == 0
    assert dispatcher.exact_projection_recovery_census().unresolved_recoveries == 1

    results = dispatcher.drain_exact_projection_recoveries()
    assert len(results) == 1
    assert attempts == 1
    assert all(outcome.status == "succeeded" for outcome in results[0].projections)
    assert dispatcher.authenticates_deferred_session_publication_receipt(receipt)
    ecar_rows, zeek_rows = _close_and_read_publication(second)
    assert len(ecar_rows) == 6
    assert len(zeek_rows) == 2


def test_exact_deferred_bridge_recovers_transport_lost_return(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A durable Zeek transport row is never repeated after its return is lost."""

    original = ExternalSortedLineWriter._commit_exact_row
    attempts = 0

    def lose_transport_return(
        writer: ExternalSortedLineWriter,
        key: object,
        digest: str,
        frozen: object,
    ) -> None:
        nonlocal attempts
        original(writer, key, digest, frozen)
        if writer.output_path.name == "zeek_conn.json":
            attempts += 1
        if writer.output_path.name == "zeek_conn.json" and attempts == 1:
            raise OSError("injected transport exact-row lost return")

    monkeypatch.setattr(
        ExternalSortedLineWriter,
        "_commit_exact_row",
        lose_transport_return,
    )
    publication = _foundation_publication_fixture(DeferredSessionKind.SSH, tmp_path)
    with pytest.raises(OSError, match="transport exact-row lost return"):
        publication.authority.materialize_prepared_deferred_session_publication(
            publication.composition,
            publication.fixture.coordinator,
            publication.fixture.owner_rng,
            dispatcher=publication.dispatcher,
            publication_batch=publication.batch,
        )

    results = publication.dispatcher.drain_exact_projection_recoveries()
    assert len(results) == 1
    assert all(outcome.status == "succeeded" for outcome in results[0].projections)
    ecar_rows, zeek_rows = _close_and_read_publication(publication)
    assert len(ecar_rows) == 3
    assert len(zeek_rows) == 1


def test_exact_deferred_bridge_recovers_later_target_after_multi_emitter_progress(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A later eCAR lost return preserves prior Zeek and FLOW target progress."""

    original = ExternalSortedLineWriter._commit_exact_row
    dependent_attempts = 0

    def lose_dependent_return(
        writer: ExternalSortedLineWriter,
        key: object,
        digest: str,
        frozen: object,
    ) -> None:
        nonlocal dependent_attempts
        original(writer, key, digest, frozen)
        parsed = json.loads(frozen) if type(frozen) is str else {}
        if parsed.get("object") == "USER_SESSION":
            dependent_attempts += 1
            if dependent_attempts == 1:
                raise OSError("injected dependent exact-row lost return")

    monkeypatch.setattr(
        ExternalSortedLineWriter,
        "_commit_exact_row",
        lose_dependent_return,
    )
    publication = _foundation_publication_fixture(DeferredSessionKind.RDP, tmp_path)
    with pytest.raises(OSError, match="dependent exact-row lost return") as raised:
        publication.authority.materialize_prepared_deferred_session_publication(
            publication.composition,
            publication.fixture.coordinator,
            publication.fixture.owner_rng,
            dispatcher=publication.dispatcher,
            publication_batch=publication.batch,
        )

    recovery_result = raised.value.deferred_session_publication_result
    assert recovery_result.projections[0].status == "succeeded"
    assert recovery_result.projections[1].status == "recoverable"
    results = publication.dispatcher.drain_exact_projection_recoveries()
    assert all(outcome.status == "succeeded" for outcome in results[0].projections)
    ecar_rows, zeek_rows = _close_and_read_publication(publication)
    assert len(ecar_rows) == 3
    assert len(zeek_rows) == 1
