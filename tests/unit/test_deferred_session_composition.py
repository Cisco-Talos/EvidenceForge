# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Frozen owner-level SSH/RDP deferred-session composition contracts."""

import gc
import random
from copy import copy, deepcopy
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.events.application import (
    ApplicationChannelBudget,
    ApplicationTransportBinding,
)
from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import HostContext, SyslogContext
from evidenceforge.events.dispatcher import EventDispatcher, PreparedDispatch
from evidenceforge.events.lifecycle import LifecycleHold
from evidenceforge.events.network import (
    DirectionalTrafficLedger,
    NetworkTrafficLedger,
    NetworkTransactionPlan,
)
from evidenceforge.events.rdp import (
    RdpLogicalSessionIdentity,
    RdpSessionAffinity,
    RdpTransportPlan,
)
from evidenceforge.generation.application_channels import ApplicationChannelRegistry
from evidenceforge.generation.cryptographic_material import CryptographicMaterialRegistry
from evidenceforge.generation.deferred_session_composition import (
    DeferredSessionComposition,
    DeferredSessionCompositionCoordinator,
    DeferredSessionKind,
    DeferredSessionStateMemberBinding,
)
from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
from evidenceforge.generation.lifecycle_production_adapters import (
    LifecycleProductionAdapter,
    closed_transport_publication_plan,
)
from evidenceforge.generation.lifecycle_registry import (
    LifecycleClosedTransportAdmissionToken,
    LifecycleRegistry,
)
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.generation.network_runtime import (
    NetworkTransactionRuntime,
    NetworkTransportLifecycleMode,
    PreparedNetworkTransactionRoot,
)
from evidenceforge.generation.rdp_sessions import (
    RdpReconnectStateManager,
    RdpSessionAdmissionToken,
)
from evidenceforge.generation.source_timing import SourceTimingPlanner, SourceTimingPreparation
from evidenceforge.generation.ssh_channels import (
    SshApplicationChannelManager,
    SshChannelAdmissionToken,
    SshChannelAffinity,
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
from evidenceforge.models.exceptions import StateError

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
) -> NetworkTransactionPlan:
    """Return one closed successful SSH or RDP transport."""

    closed_at = _START + timedelta(seconds=30)
    return NetworkTransactionPlan(
        stable_id=stable_id,
        hostname="db-01.example.test",
        outcome="success",
        phase_times=(("transport_start", _START), ("transport_close", closed_at)),
        started_at=_START,
        closed_at=closed_at,
        src_ip="10.0.0.10",
        src_port=50_001,
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
    ready_at = _START + timedelta(milliseconds=120)
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
) -> tuple[RdpReconnectStateManager, RdpSessionAdmissionToken]:
    """Prepare one initial RDP logical-session generation over the root transport."""

    transaction = root.transaction
    assert transaction.closed_at is not None
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
    preparation = runtime.begin(
        owner_rng=random.Random(17),
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
        session_kind=kind.value,
    )
    process_plan: ProcessMaterializationPlan | None = None
    if kind is DeferredSessionKind.SSH:
        process_plan = batch_builder.plan_process(
            system="DB-01",
            parent_pid=0,
            image="/usr/sbin/sshd",
            command_line="sshd: analyst@pts/0",
            username="analyst",
            integrity_level="Medium",
            os_category="linux",
            logon_id=session_plan.identity.logon_id,
            start_time=_START + timedelta(milliseconds=110),
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


@pytest.mark.parametrize(
    ("kind", "with_application"),
    (
        (DeferredSessionKind.SSH, True),
        (DeferredSessionKind.SSH, False),
        (DeferredSessionKind.RDP, True),
        (DeferredSessionKind.RDP, False),
    ),
)
def test_coordinator_issues_valid_ssh_and_rdp_compositions(
    kind: DeferredSessionKind,
    with_application: bool,
) -> None:
    fixture = _fixture(kind, with_application=with_application)

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
    fixture = _fixture(DeferredSessionKind.RDP, with_application=False)
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
        with_application=False,
        lifecycle_mode="network",
    )
    wrong_port = _fixture(
        DeferredSessionKind.SSH,
        with_application=False,
        dst_port=443,
    )

    with pytest.raises(StateError, match="deferred|mode"):
        ordinary_root.issue()
    with pytest.raises(StateError, match="port|SSH"):
        wrong_port.issue()


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
    fixture = _fixture(DeferredSessionKind.RDP, with_application=False)
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
