# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Atomic State/lifecycle/application connection authority contracts."""

import random
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256

import pytest

from evidenceforge.events.application import (
    ApplicationChannelBudget,
    ApplicationChannelIdentity,
    ApplicationOperationReservation,
    ApplicationTransportBinding,
)
from evidenceforge.events.lifecycle import LifecycleHold
from evidenceforge.events.network import NetworkTrafficLedger, NetworkTransactionPlan
from evidenceforge.generation.application_channels import (
    ApplicationChannelAdmissionResult,
    ApplicationChannelPreparedCommit,
    ApplicationChannelRegistry,
)
from evidenceforge.generation.cryptographic_material import CryptographicMaterialRegistry
from evidenceforge.generation.http_channels import (
    HttpApplicationChannelManager,
    HttpChannelAdmissionResult,
    HttpChannelAdmissionToken,
    HttpChannelAffinity,
    HttpChannelReuse,
)
from evidenceforge.generation.lifecycle_authority import (
    ApplicationChannelCompositeProof,
    ConnectionCompositePrerequisiteProof,
    GeneratorLifecycleAuthority,
    LifecyclePreparedNetworkReceipt,
)
from evidenceforge.generation.lifecycle_production_adapters import (
    LifecycleProductionAdapter,
    closed_transport_publication_plan,
)
from evidenceforge.generation.lifecycle_registry import (
    LifecycleClosedTransportAdmissionToken,
    LifecycleClosedTransportPublicationReceipt,
    LifecycleRegistry,
)
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.generation.network_runtime import (
    NetworkTransactionPreparedCommit,
    NetworkTransactionRuntime,
    NetworkTransportLifecycleMode,
    PreparedNetworkTransactionRoot,
)
from evidenceforge.generation.proxy_channels import (
    ExplicitProxyAdmissionToken,
    ExplicitProxyChannelAffinity,
    ExplicitProxyChannelManager,
    ExplicitProxyTerminalRequest,
)
from evidenceforge.generation.source_timing import (
    SourceTimingPlanner,
    SourceTimingPreparation,
    SourceTimingPreparationReceipt,
)
from evidenceforge.generation.state_manager import (
    ConnectionCompositeMaterializationPlan,
    ConnectionCompositeMaterializationResult,
    ConnectionMaterializationMode,
    MaterializationBatchPlan,
    ProcessActivityPatch,
    SessionActivityPatch,
    StateManager,
)
from evidenceforge.models.exceptions import StateError

_START = datetime(2026, 8, 16, 13, 0, tzinfo=UTC)
_END = _START + timedelta(days=2)


def _transaction(
    *,
    conn_id: str,
    zeek_uid: str,
    stable_id: str = "transport-1",
    started_at: datetime = _START,
    duration: float = 30.0,
    application_layer_only: bool = False,
    src_ip: str = "10.0.0.10",
    src_port: int = 50_001,
    dst_ip: str = "203.0.113.20",
    dst_port: int = 443,
) -> NetworkTransactionPlan:
    closed_at = started_at + timedelta(seconds=duration)
    return NetworkTransactionPlan(
        stable_id=stable_id,
        hostname="portal.example.test",
        outcome="success",
        phase_times=(("transport_start", started_at), ("transport_close", closed_at)),
        started_at=started_at,
        closed_at=closed_at,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol="tcp",
        service="https",
        zeek_uid=zeek_uid,
        conn_id=conn_id,
        duration=duration,
        conn_state="SF",
        history="ShADadFf",
        traffic=NetworkTrafficLedger(),
        application_layer_only=application_layer_only,
    )


def _authority() -> tuple[
    GeneratorLifecycleAuthority,
    StateManager,
    LifecycleRegistry,
    LifecycleProductionAdapter,
]:
    state = StateManager()
    registry = LifecycleRegistry(shard_count=8)
    authority = GeneratorLifecycleAuthority(
        state,
        LifecycleShadow(state, registry),
        shard_count=8,
    )
    return authority, state, registry, LifecycleProductionAdapter(registry)


def _prepared_authority() -> tuple[
    GeneratorLifecycleAuthority,
    StateManager,
    LifecycleRegistry,
    LifecycleProductionAdapter,
    NetworkTransactionRuntime,
    CryptographicMaterialRegistry,
    SourceTimingPlanner,
]:
    authority, state, registry, adapter = _authority()
    crypto = CryptographicMaterialRegistry()
    runtime = NetworkTransactionRuntime(
        state_manager=state,
        cryptographic_material=crypto,
        window_start=_START,
        window_end=_END,
    )
    timing = SourceTimingPlanner()
    authority.bind_network_transaction_runtime(runtime)
    authority.bind_source_timing_planner(timing)
    return authority, state, registry, adapter, runtime, crypto, timing


def _prepared_physical_root(
    authority: GeneratorLifecycleAuthority,
    adapter: LifecycleProductionAdapter,
    runtime: NetworkTransactionRuntime,
    owner_rng: random.Random,
    *,
    stable_id: str,
    lifecycle_mode: NetworkTransportLifecycleMode = "network",
    started_at: datetime = _START,
    src_ip: str = "10.0.0.10",
    src_port: int = 50_001,
    dst_ip: str = "203.0.113.20",
    dst_port: int = 443,
) -> tuple[PreparedNetworkTransactionRoot, LifecycleClosedTransportAdmissionToken]:
    preparation = runtime.begin(
        owner_rng=owner_rng,
        stable_id=stable_id,
        linearization_time=started_at,
    )
    identity = preparation.reserve_physical_identity()
    transaction = _transaction(
        conn_id=identity.conn_id,
        zeek_uid=identity.zeek_uid,
        stable_id=stable_id,
        started_at=started_at,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
    )
    root = preparation.seal(
        transaction=transaction,
        lifecycle_mode=lifecycle_mode,
        materialization_mode=ConnectionMaterializationMode.PHYSICAL,
        source_system="WS-01",
        source_hostname="ws-01.example.test",
        hostname="portal.example.test",
        initiating_pid=-1,
    )
    return root, _lifecycle_token(authority, adapter, root.state_plan)


def _sealed_source_timing(planner: SourceTimingPlanner) -> SourceTimingPreparation:
    with planner.prepared_planning() as preparation:
        pass
    return preparation


def _physical_plan(
    state: StateManager,
    owner_rng: random.Random,
    *,
    stable_id: str = "transport-1",
    started_at: datetime = _START,
    batch: MaterializationBatchPlan | None = None,
    process_activity: tuple[ProcessActivityPatch, ...] = (),
    session_activity: tuple[SessionActivityPatch, ...] = (),
    src_ip: str = "10.0.0.10",
    src_port: int = 50_001,
    dst_ip: str = "203.0.113.20",
    dst_port: int = 443,
) -> ConnectionCompositeMaterializationPlan:
    cursor = state.begin_connection_planning(owner_rng)
    identity = cursor.reserve_identity()
    transaction = _transaction(
        conn_id=identity.conn_id,
        zeek_uid=identity.zeek_uid,
        stable_id=stable_id,
        started_at=started_at,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
    )
    return state.finalize_connection_composite_materialization(
        cursor,
        transaction,
        source_system="WS-01",
        source_hostname="ws-01.example.test",
        hostname="portal.example.test",
        initiating_pid=-1,
        batch=batch,
        process_activity=process_activity,
        session_activity=session_activity,
    )


def _lifecycle_token(
    authority: GeneratorLifecycleAuthority,
    adapter: LifecycleProductionAdapter,
    plan: ConnectionCompositeMaterializationPlan,
    *,
    process_holds: tuple[LifecycleHold, ...] = (),
) -> LifecycleClosedTransportAdmissionToken:
    lifecycle_plan = closed_transport_publication_plan(
        transaction=plan.transaction,
        authority_hostname="WS-01",
        src_hostname="WS-01",
        dst_hostname="INTERNET",
        action_id=f"{plan.transaction.stable_id}-lifecycle",
    )
    return adapter.prepare_closed_transport_publication(
        lifecycle_plan,
        start_members=authority.connection_composite_start_members(plan),
        process_holds=process_holds,
    )


def _http_affinity() -> HttpChannelAffinity:
    return HttpChannelAffinity.from_request(
        src_ip="10.0.0.10",
        dst_ip="203.0.113.20",
        dst_port=443,
        http_host="portal.example.test",
        user_agent="Mozilla/5.0",
        transport_security="tls",
    )


def _http_manager(
    authority: GeneratorLifecycleAuthority,
) -> tuple[ApplicationChannelRegistry, HttpApplicationChannelManager]:
    registry = ApplicationChannelRegistry(window_start=_START, window_end=_END, shard_count=8)
    manager = HttpApplicationChannelManager(
        window_start=_START,
        window_end=_END,
        registry=registry,
    )
    authority.bind_http_channel_manager(manager)
    return registry, manager


def _http_open_token(
    manager: HttpApplicationChannelManager,
    plan: ConnectionCompositeMaterializationPlan,
) -> HttpChannelAdmissionToken:
    transaction = plan.transaction
    assert transaction.closed_at is not None
    token = manager.prepare_open_transport(
        _http_affinity(),
        transport_id=plan.physical_transport_id,
        zeek_uid=transaction.zeek_uid,
        conn_id=transaction.conn_id,
        src_port=transaction.src_port,
        opened_at=transaction.started_at,
        closes_at=transaction.closed_at,
        initial_request_time=transaction.started_at + timedelta(milliseconds=100),
        orig_budget=1_000,
        resp_budget=5_000,
        initial_request_body_bytes=10,
        initial_response_body_bytes=100,
        operation_budget=4,
    )
    assert token is not None
    return token


def _http_child_plan(
    state: StateManager,
    parent_plan: ConnectionCompositeMaterializationPlan,
    token: HttpChannelAdmissionToken,
    owner_rng: random.Random,
) -> ConnectionCompositeMaterializationPlan:
    assert isinstance(token.result, HttpChannelReuse)
    cursor = state.begin_connection_planning(owner_rng)
    return state.finalize_connection_composite_materialization(
        cursor,
        _transaction(
            conn_id=parent_plan.transaction.conn_id,
            zeek_uid=parent_plan.transaction.zeek_uid,
            stable_id=token.result.operation_id,
            started_at=token.result.canonical_request_time,
            duration=0.1,
            application_layer_only=True,
        ),
        mode=ConnectionMaterializationMode.APPLICATION_CHILD,
    )


def test_physical_connection_composite_commits_exact_state_and_lifecycle_receipt() -> None:
    authority, state, registry, adapter = _authority()
    owner_rng = random.Random(1)
    plan = _physical_plan(state, owner_rng)
    token = _lifecycle_token(authority, adapter, plan)

    result = authority.materialize_connection_composite(
        plan,
        owner_rng,
        lifecycle_token=token,
    )

    assert result.state.connection is not None
    assert result.state.connection.transaction_id == plan.physical_transport_id
    assert result.lifecycle is not None
    assert result.lifecycle.transport.identity.transport_id == plan.physical_transport_id
    assert result.receipt.lifecycle_publication_token == result.lifecycle.publication_token
    assert authority.authenticates_connection_composite_receipt(plan, result.receipt)
    retained = registry.transport_for_transport_id(plan.physical_transport_id)
    assert retained is not None
    assert retained.identity.conn_id == plan.physical_transport_fingerprint.conn_id
    assert retained.identity.zeek_uid == plan.physical_transport_fingerprint.zeek_uid


def test_protocol_neutral_application_receipt_is_normalized_after_exact_commit() -> None:
    authority, state, _registry, adapter = _authority()
    application_registry = ApplicationChannelRegistry(
        window_start=_START,
        window_end=_END,
        shard_count=8,
    )
    authority.bind_application_channel_registry(application_registry)
    owner_rng = random.Random(19)
    plan = _physical_plan(state, owner_rng, stable_id="protocol-neutral-transport")
    transaction = plan.transaction
    assert transaction.closed_at is not None
    identity = ApplicationChannelIdentity(
        channel_id="ntp-channel-1",
        protocol="ntp",
        owner_id="ntp-client-1",
        affinity_digest="ntp-affinity-1",
        binding=ApplicationTransportBinding(
            transport_id=plan.physical_transport_id,
            opened_at=transaction.started_at,
            closes_at=transaction.closed_at,
        ),
        opened_at=transaction.started_at,
        idle_timeout=timedelta(seconds=10),
        hard_deadline=transaction.closed_at,
        budget=ApplicationChannelBudget(1_000, 1_000, 1),
    )
    operation = ApplicationOperationReservation(
        operation_id="ntp-operation-1",
        channel_id=identity.channel_id,
        ordinal=0,
        started_at=transaction.started_at,
        ended_at=transaction.started_at + timedelta(milliseconds=1),
        initiator_bytes=48,
        responder_bytes=48,
    )
    application_token = application_registry.prepare_open_channel_with_completed_operation(
        identity,
        operation,
    )

    result = authority.materialize_connection_composite(
        plan,
        owner_rng,
        lifecycle_token=_lifecycle_token(authority, adapter, plan),
        application_token=application_token,
    )

    proof = result.receipt.application_proof
    assert proof is not None
    assert proof.manager_kind == "protocol_neutral"
    assert proof.current_transport_id == plan.physical_transport_id
    assert proof.operation_id == operation.operation_id
    assert isinstance(result.application, ApplicationChannelAdmissionResult)
    assert result.application.receipt is not None
    assert application_registry.authenticates_admission_receipt(result.application.receipt)
    assert authority.authenticates_connection_composite_receipt(plan, result.receipt)


def test_connection_composite_commits_in_lifecycle_state_application_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority, state, _registry, adapter = _authority()
    _application_registry, http = _http_manager(authority)
    owner_rng = random.Random(23)
    plan = _physical_plan(state, owner_rng, stable_id="ordered-transport")
    lifecycle_token = _lifecycle_token(authority, adapter, plan)
    application_token = _http_open_token(http, plan)
    order: list[str] = []
    original_lifecycle = LifecycleRegistry._commit_claimed_closed_transport_publication
    original_state = StateManager._commit_prevalidated_connection_composite
    original_http = HttpApplicationChannelManager._commit_claimed_admission

    def _lifecycle_commit(
        registry: LifecycleRegistry,
        token: LifecycleClosedTransportAdmissionToken,
    ) -> LifecycleClosedTransportPublicationReceipt:
        order.append("lifecycle")
        return original_lifecycle(registry, token)

    def _state_commit(
        manager: StateManager,
        committed_plan: ConnectionCompositeMaterializationPlan,
        committed_rng: random.Random,
    ) -> ConnectionCompositeMaterializationResult:
        order.append("state")
        return original_state(manager, committed_plan, committed_rng)

    def _http_commit(
        manager: HttpApplicationChannelManager,
        token: HttpChannelAdmissionToken,
        application_commit: ApplicationChannelPreparedCommit,
    ) -> HttpChannelAdmissionResult:
        order.append("application")
        return original_http(manager, token, application_commit)

    monkeypatch.setattr(
        LifecycleRegistry,
        "_commit_claimed_closed_transport_publication",
        _lifecycle_commit,
    )
    monkeypatch.setattr(
        StateManager,
        "_commit_prevalidated_connection_composite",
        _state_commit,
    )
    monkeypatch.setattr(HttpApplicationChannelManager, "_commit_claimed_admission", _http_commit)
    authority._materialization_precommit_hook = lambda: order.append("precommit")

    authority.materialize_connection_composite(
        plan,
        owner_rng,
        lifecycle_token=lifecycle_token,
        application_token=application_token,
    )

    assert order == ["precommit", "lifecycle", "state", "application"]


def test_connection_composite_commits_staged_start_members_and_exact_holds() -> None:
    authority, state, registry, adapter = _authority()
    builder = state.begin_materialization_batch()
    session = builder.plan_session(
        username="analyst",
        system="LNX-01",
        logon_type=2,
        source_ip="-",
        start_time=_START,
        session_kind="interactive",
    )
    process = builder.plan_process(
        system="LNX-01",
        parent_pid=0,
        image="/bin/bash",
        command_line="/bin/bash -l",
        username="analyst",
        integrity_level="Medium",
        os_category="linux",
        logon_id=session.identity.logon_id,
        start_time=_START + timedelta(milliseconds=1),
        require_session=True,
        session_plan=session,
        auth_session_id=session.identity.session_id,
        auth_logon_type=2,
    )
    batch = builder.seal()
    hold_until = _START + timedelta(seconds=30)
    process_patch = ProcessActivityPatch(process.identity, hold_until)
    session_patch = SessionActivityPatch(session.identity, hold_until)
    owner_rng = random.Random(2)
    plan = _physical_plan(
        state,
        owner_rng,
        stable_id="transport-with-starts",
        batch=batch,
        process_activity=(process_patch,),
        session_activity=(session_patch,),
    )
    members = authority.connection_composite_start_members(plan)
    process_member = members[-1]
    hold = LifecycleHold(
        hold_id="transport-process-hold",
        subject=process_member.request.identity.ref,
        acquired_at=process.identity.started_at,
        hold_until=hold_until,
        action_id="transport-process-hold-action",
        reason="canonical_transport_close",
    )
    token = _lifecycle_token(authority, adapter, plan, process_holds=(hold,))

    result = authority.materialize_connection_composite(
        plan,
        owner_rng,
        lifecycle_token=token,
    )

    assert result.state.session is not None
    assert tuple(item.ecar_object_id for item in result.state.processes) == (
        process.identity.object_id,
    )
    assert result.receipt.start_plan_tokens == tuple(member.publication_token for member in members)
    assert result.receipt.process_holds == (hold,)
    assert registry.hold(hold.hold_id) == hold
    assert state.get_process("LNX-01", process.identity.pid).last_activity_time == hold_until
    assert state.get_session(session.identity.logon_id).last_activity_time == hold_until


def test_connection_composite_rejects_unowned_session_activity_patch() -> None:
    authority, state, _registry, adapter = _authority()
    session_plan = state.plan_session_materialization(
        username="analyst",
        system="LNX-01",
        logon_type=2,
        source_ip="-",
        start_time=_START,
        session_kind="interactive",
    )
    authority.materialize_session(session_plan)
    owner_rng = random.Random(20)
    plan = _physical_plan(
        state,
        owner_rng,
        stable_id="transport-with-unowned-session-patch",
        session_activity=(
            SessionActivityPatch(
                session_plan.identity,
                _START + timedelta(seconds=30),
            ),
        ),
    )
    token = _lifecycle_token(authority, adapter, plan)
    state_before = state.materialization_digest()

    with pytest.raises(StateError, match="session activity and lifecycle holds disagree"):
        authority.materialize_connection_composite(
            plan,
            owner_rng,
            lifecycle_token=token,
        )

    assert state.materialization_digest() == state_before
    assert adapter.closed_transport_preparation_census().reservations == 0


@pytest.mark.parametrize("mutation", ("state", "lifecycle", "application"))
def test_final_authentication_sweep_rejects_nested_token_tamper_without_rows(
    mutation: str,
) -> None:
    authority, state, registry, adapter = _authority()
    application_registry, http = _http_manager(authority)
    owner_rng = random.Random(3)
    plan = _physical_plan(state, owner_rng)
    lifecycle_token = _lifecycle_token(authority, adapter, plan)
    application_token = _http_open_token(http, plan)
    state_before = state.materialization_digest()
    rng_before = owner_rng.getstate()
    registry_before = replace(registry.stats(), lookup_candidates_inspected=0)
    original: object

    def _tamper() -> None:
        nonlocal original
        if mutation == "state":
            original = plan._final_state_time
            object.__setattr__(
                plan,
                "_final_state_time",
                plan.final_state_time + timedelta(microseconds=1),
            )
        elif mutation == "lifecycle":
            original = lifecycle_token.request.identity.conn_id
            object.__setattr__(
                lifecycle_token.request.identity,
                "conn_id",
                "tampered-connection",
            )
        else:
            original = application_token._integrity_token
            object.__setattr__(application_token, "_integrity_token", "0" * 64)

    original = None
    authority._materialization_precommit_hook = _tamper
    with pytest.raises(StateError):
        authority.materialize_connection_composite(
            plan,
            owner_rng,
            lifecycle_token=lifecycle_token,
            application_token=application_token,
        )

    assert state.materialization_digest() == state_before
    assert owner_rng.getstate() == rng_before
    assert replace(registry.stats(), lookup_candidates_inspected=0) == registry_before
    assert registry.transport_for_transport_id(plan.physical_transport_id) is None
    assert registry.closed_transport_preparation_census().reservations == 0
    assert http.census().open_transport_views == 0
    assert http.census().application.retained_channels == 0
    assert http.census().application.prepared_admissions == 0
    assert application_registry.census().claimed_admissions == 0

    if mutation == "state":
        object.__setattr__(plan, "_final_state_time", original)
    elif mutation == "lifecycle":
        object.__setattr__(lifecycle_token.request.identity, "conn_id", original)
    else:
        object.__setattr__(application_token, "_integrity_token", original)
    authority._materialization_precommit_hook = None
    retry = authority.materialize_connection_composite(
        plan,
        owner_rng,
        lifecycle_token=_lifecycle_token(authority, adapter, plan),
        application_token=_http_open_token(http, plan),
    )
    assert authority.authenticates_connection_composite_receipt(plan, retry.receipt)


@pytest.mark.parametrize(
    "rejection",
    (
        "lifecycle_only",
        "application_only",
        "both",
        "cross_binding",
        "tampered_application",
        "tampered_lifecycle",
    ),
)
def test_initial_validation_failure_consumes_every_exact_owned_reservation(
    rejection: str,
) -> None:
    authority, state, registry, adapter = _authority()
    _application_registry, http = _http_manager(authority)
    owner_rng = random.Random(30)
    plan = _physical_plan(state, owner_rng, stable_id=f"owned-{rejection}")
    foreign_plan = _physical_plan(
        state,
        random.Random(31),
        stable_id=f"foreign-{rejection}",
        src_port=50_002,
    )
    lifecycle_token: LifecycleClosedTransportAdmissionToken | None
    application_token: HttpChannelAdmissionToken | None
    if rejection == "lifecycle_only":
        lifecycle_token = _lifecycle_token(authority, adapter, foreign_plan)
        application_token = None
    elif rejection == "application_only":
        lifecycle_token = None
        application_token = _http_open_token(http, plan)
    elif rejection == "both":
        lifecycle_token = _lifecycle_token(authority, adapter, foreign_plan)
        application_token = _http_open_token(http, foreign_plan)
    elif rejection == "cross_binding":
        lifecycle_token = _lifecycle_token(authority, adapter, plan)
        application_token = _http_open_token(http, foreign_plan)
    elif rejection == "tampered_application":
        lifecycle_token = _lifecycle_token(authority, adapter, plan)
        application_token = _http_open_token(http, plan)
        object.__setattr__(application_token, "_integrity_token", "f" * 64)
    else:
        lifecycle_token = _lifecycle_token(authority, adapter, plan)
        application_token = _http_open_token(http, plan)
        object.__setattr__(lifecycle_token, "_integrity", "f" * 64)
    state_before = state.materialization_digest()
    rng_before = owner_rng.getstate()
    registry_before = registry.stats()

    with pytest.raises(StateError):
        authority.materialize_connection_composite(
            plan,
            owner_rng,
            lifecycle_token=lifecycle_token,
            application_token=application_token,
        )

    assert state.materialization_digest() == state_before
    assert owner_rng.getstate() == rng_before
    assert registry.stats() == registry_before
    assert registry.transport_for_transport_id(plan.physical_transport_id) is None
    preparation = adapter.closed_transport_preparation_census()
    assert preparation.reservations == 0
    assert preparation.claimed_reservations == 0
    http_census = http.census()
    assert http_census.open_transport_views == 0
    assert http_census.application.retained_channels == 0
    assert http_census.application.prepared_admissions == 0
    assert http_census.application.claimed_admissions == 0

    retry = authority.materialize_connection_composite(
        plan,
        owner_rng,
        lifecycle_token=_lifecycle_token(authority, adapter, plan),
        application_token=_http_open_token(http, plan),
    )
    assert retry.state.connection is not None
    assert retry.state.connection.transaction_id == plan.transaction.stable_id
    assert authority.authenticates_connection_composite_receipt(plan, retry.receipt)


def test_application_child_requires_exact_existing_lifecycle_and_http_parent() -> None:
    authority, state, _registry, adapter = _authority()
    _application_registry, http = _http_manager(authority)
    parent_rng = random.Random(4)
    parent_plan = _physical_plan(state, parent_rng)
    parent = authority.materialize_connection_composite(
        parent_plan,
        parent_rng,
        lifecycle_token=_lifecycle_token(authority, adapter, parent_plan),
        application_token=_http_open_token(http, parent_plan),
    )
    assert authority.authenticates_connection_composite_receipt(parent_plan, parent.receipt)

    reuse = http.prepare_reuse(
        _http_affinity(),
        requested_at=_START + timedelta(seconds=1),
        required_until=_START + timedelta(seconds=1, milliseconds=100),
        request_body_bytes=20,
        response_body_bytes=200,
    )
    assert reuse is not None
    child_rng = random.Random(5)
    child_plan = _http_child_plan(state, parent_plan, reuse, child_rng)

    child = authority.materialize_connection_composite(
        child_plan,
        child_rng,
        application_token=reuse,
    )

    assert child.lifecycle is None
    assert child.state.connection is parent.state.connection
    assert child.receipt.physical_transport_id == parent.receipt.physical_transport_id
    assert child.receipt.transaction_id == reuse.result.operation_id
    assert child.receipt.application_proof is not None
    assert child.receipt.application_proof.manager_kind == "http"
    assert authority.authenticates_connection_composite_receipt(child_plan, child.receipt)
    with pytest.raises(StateError, match="prerequisite must own a physical transport"):
        authority._normalize_prerequisite_proofs(
            (child.receipt,),
            (parent_plan.physical_transport_id,),
        )


@pytest.mark.parametrize("mismatch", ("tuple", "uid", "interval"))
def test_application_child_rejects_mismatched_parent_lifecycle_fingerprint(
    mismatch: str,
) -> None:
    authority, state, registry, adapter = _authority()
    _application_registry, http = _http_manager(authority)
    parent_rng = random.Random(21)
    parent_plan = _physical_plan(state, parent_rng, stable_id=f"parent-{mismatch}")
    state.materialize_connection_composite(parent_plan, parent_rng)
    transaction = parent_plan.transaction
    if mismatch == "tuple":
        lifecycle_transaction = replace(transaction, dst_port=transaction.dst_port + 1)
    elif mismatch == "uid":
        lifecycle_transaction = replace(transaction, zeek_uid="CwrongLifecycleUid")
    else:
        assert transaction.closed_at is not None
        wrong_close = transaction.closed_at - timedelta(seconds=1)
        lifecycle_transaction = replace(
            transaction,
            closed_at=wrong_close,
            duration=(wrong_close - transaction.started_at).total_seconds(),
            phase_times=(
                ("transport_start", transaction.started_at),
                ("transport_close", wrong_close),
            ),
        )
    adapter.publish_closed_transport(
        closed_transport_publication_plan(
            transaction=lifecycle_transaction,
            authority_hostname="WS-01",
            src_hostname="WS-01",
            dst_hostname="INTERNET",
            action_id=f"parent-{mismatch}-wrong-lifecycle",
        )
    )
    with http.prepared_admission(_http_open_token(http, parent_plan)) as prepared:
        prepared.commit_no_fail()
    reuse = http.prepare_reuse(
        _http_affinity(),
        requested_at=_START + timedelta(seconds=1),
        required_until=_START + timedelta(seconds=1, milliseconds=100),
        request_body_bytes=20,
        response_body_bytes=200,
    )
    assert reuse is not None
    child_rng = random.Random(22)
    child_plan = _http_child_plan(state, parent_plan, reuse, child_rng)
    state_before = state.materialization_digest()
    registry_before = replace(registry.stats(), lookup_candidates_inspected=0)

    with pytest.raises(StateError, match="lifecycle transport disagrees with State"):
        authority.materialize_connection_composite(
            child_plan,
            child_rng,
            application_token=reuse,
        )

    assert state.materialization_digest() == state_before
    assert replace(registry.stats(), lookup_candidates_inspected=0) == registry_before
    assert http.census().application.prepared_admissions == 0


def test_common_http_proof_and_public_normalized_proofs_are_not_authority_inputs() -> None:
    authority, state, _registry, adapter = _authority()
    application_registry = ApplicationChannelRegistry(
        window_start=_START,
        window_end=_END,
        shard_count=8,
    )
    authority.bind_application_channel_registry(application_registry)
    owner_rng = random.Random(6)
    plan = _physical_plan(state, owner_rng)
    transaction = plan.transaction
    assert transaction.closed_at is not None
    channel_id = "caller-http-channel"
    identity = ApplicationChannelIdentity(
        channel_id=channel_id,
        protocol="http",
        owner_id="caller-http-owner",
        affinity_digest="caller-http-affinity",
        binding=ApplicationTransportBinding(
            transport_id=plan.physical_transport_id,
            opened_at=transaction.started_at,
            closes_at=transaction.closed_at,
        ),
        opened_at=transaction.started_at,
        idle_timeout=timedelta(seconds=10),
        hard_deadline=transaction.closed_at,
        budget=ApplicationChannelBudget(1_000, 1_000, 2),
    )
    operation = ApplicationOperationReservation(
        operation_id="caller-http-operation",
        channel_id=channel_id,
        ordinal=0,
        started_at=transaction.started_at + timedelta(milliseconds=1),
        ended_at=transaction.started_at + timedelta(milliseconds=2),
        initiator_bytes=1,
        responder_bytes=1,
    )
    common_token = application_registry.prepare_open_channel_with_completed_operation(
        identity,
        operation,
    )
    lifecycle_token = _lifecycle_token(authority, adapter, plan)
    state_before = state.materialization_digest()
    with pytest.raises(StateError, match="requires its engine-owned sidecar receipt"):
        authority.materialize_connection_composite(
            plan,
            owner_rng,
            lifecycle_token=lifecycle_token,
            application_token=common_token,
        )
    assert state.materialization_digest() == state_before
    assert adapter.closed_transport_preparation_census().reservations == 0
    assert application_registry.census().prepared_admissions == 0

    public_proof = ApplicationChannelCompositeProof(
        manager_kind="http",
        manager_id="caller-manager",
        manager_receipt_token="caller-manager-receipt",
        common_receipt_token="caller-common-receipt",
        channel_id="caller-channel",
        operation_id="caller-operation",
        current_transport_id=plan.physical_transport_id,
        prerequisite_transport_ids=(),
        sidecar_result_digest="caller-sidecar-digest",
    )
    lifecycle_token = _lifecycle_token(authority, adapter, plan)
    with pytest.raises(StateError, match="common application token"):
        authority.materialize_connection_composite(
            plan,
            owner_rng,
            lifecycle_token=lifecycle_token,
            application_token=public_proof,  # type: ignore[arg-type]
        )
    assert adapter.closed_transport_preparation_census().reservations == 0
    compact_prerequisite = ConnectionCompositePrerequisiteProof(
        receipt_token="caller-prerequisite",
        receipt_digest="caller-digest",
        physical_transport_id="client-transport",
        transaction_id="client-transaction",
        conn_id="conn-caller",
        zeek_uid="Ccaller",
    )
    assert compact_prerequisite.physical_transport_id == "client-transport"


def test_public_same_field_sha_receipt_and_wrong_manager_token_are_rejected() -> None:
    authority, state, _registry, adapter = _authority()
    _application_registry, http = _http_manager(authority)
    owner_rng = random.Random(7)
    plan = _physical_plan(state, owner_rng)
    other_registry = ApplicationChannelRegistry(
        window_start=_START,
        window_end=_END,
        shard_count=8,
    )
    other_http = HttpApplicationChannelManager(
        window_start=_START,
        window_end=_END,
        registry=other_registry,
    )
    wrong_token = _http_open_token(other_http, plan)
    state_before = state.materialization_digest()
    lifecycle_token = _lifecycle_token(authority, adapter, plan)
    with pytest.raises(StateError, match="authentic HTTP admission token"):
        authority.materialize_connection_composite(
            plan,
            owner_rng,
            lifecycle_token=lifecycle_token,
            application_token=wrong_token,
        )
    assert state.materialization_digest() == state_before
    assert adapter.closed_transport_preparation_census().reservations == 0
    assert other_http.cancel_prepared_admission(wrong_token)

    lifecycle_token = _lifecycle_token(authority, adapter, plan)
    result = authority.materialize_connection_composite(
        plan,
        owner_rng,
        lifecycle_token=lifecycle_token,
        application_token=_http_open_token(http, plan),
    )
    receipt = result.receipt
    forged = replace(receipt, _integrity_token=sha256(repr(receipt).encode()).hexdigest())
    assert not authority.authenticates_connection_composite_receipt(plan, forged)


def _proxy_manager(
    authority: GeneratorLifecycleAuthority,
) -> ExplicitProxyChannelManager:
    registry = ApplicationChannelRegistry(window_start=_START, window_end=_END, shard_count=8)
    manager = ExplicitProxyChannelManager(
        window_start=_START,
        window_end=_END,
        registry=registry,
        shard_count=8,
    )
    authority.bind_explicit_proxy_manager(manager)
    return manager


def _proxy_token(
    manager: ExplicitProxyChannelManager,
    client_plan: ConnectionCompositeMaterializationPlan,
    origin_plan: ConnectionCompositeMaterializationPlan,
    *,
    request_count: int = 1,
) -> ExplicitProxyAdmissionToken:
    origin = origin_plan.transaction
    assert origin.closed_at is not None
    token = manager.prepare_open_tunnel(
        ExplicitProxyChannelAffinity(
            client_ip="10.0.0.10",
            proxy_ip="10.0.3.10",
            proxy_port=8080,
            origin_host="portal.example.test",
            origin_ip="203.0.113.20",
            origin_port=443,
            user_agent="Mozilla/5.0",
            auth_identity="EXAMPLE\\analyst",
            policy_id="TLS-Bump-Standard",
        ),
        client_transport_id=client_plan.physical_transport_id,
        origin_transport_id=origin_plan.physical_transport_id,
        client_zeek_uid=client_plan.transaction.zeek_uid,
        origin_zeek_uid=origin.zeek_uid,
        tunnel_group_id="proxy-group-1",
        client_source_port=client_plan.transaction.src_port,
        origin_source_port=origin.src_port,
        opened_at=origin.started_at,
        closes_at=origin.closed_at,
        setup_started_at=origin.started_at + timedelta(milliseconds=10),
        setup_completed_at=origin.started_at + timedelta(milliseconds=30),
        setup_request_wire_bytes=120,
        setup_response_wire_bytes=240,
        planned_request_count=request_count,
        aggregate_request_wire_bytes=(1_000 if request_count else 0),
        aggregate_response_wire_bytes=(5_000 if request_count else 0),
    )
    assert token is not None
    return token


def test_proxy_origin_requires_exact_prior_authority_receipt_and_final_sweep() -> None:
    authority, state, registry, adapter = _authority()
    proxy = _proxy_manager(authority)
    client_rng = random.Random(8)
    client_plan = _physical_plan(
        state,
        client_rng,
        stable_id="proxy-client-leg",
        dst_ip="10.0.3.10",
        dst_port=8080,
    )
    client = authority.materialize_connection_composite(
        client_plan,
        client_rng,
        lifecycle_token=_lifecycle_token(authority, adapter, client_plan),
    )
    origin_rng = random.Random(9)
    origin_plan = _physical_plan(
        state,
        origin_rng,
        stable_id="proxy-origin-leg",
        src_ip="10.0.3.10",
        src_port=40_001,
    )
    origin_token = _lifecycle_token(authority, adapter, origin_plan)
    proxy_token = _proxy_token(proxy, client_plan, origin_plan)
    state_before = state.materialization_digest()
    registry_before = registry.stats()
    rng_before = origin_rng.getstate()
    original_transaction_id = client.receipt._transaction_id
    public_prerequisite = ConnectionCompositePrerequisiteProof(
        receipt_token=client.receipt.receipt_token,
        receipt_digest="caller-computed-digest",
        physical_transport_id=client.receipt.physical_transport_id,
        transaction_id=client.receipt.transaction_id,
        conn_id=client.receipt.conn_id,
        zeek_uid=client.receipt.zeek_uid,
    )
    with pytest.raises(StateError, match="prerequisite receipt is not authentic"):
        authority.materialize_connection_composite(
            origin_plan,
            origin_rng,
            lifecycle_token=origin_token,
            application_token=proxy_token,
            prerequisite_receipts=(public_prerequisite,),  # type: ignore[arg-type]
        )
    assert state.materialization_digest() == state_before
    assert adapter.closed_transport_preparation_census().reservations == 0
    assert proxy.census().application.prepared_admissions == 0
    origin_token = _lifecycle_token(authority, adapter, origin_plan)
    proxy_token = _proxy_token(proxy, client_plan, origin_plan)

    def _tamper_prerequisite() -> None:
        object.__setattr__(client.receipt, "_transaction_id", "tampered-client-leg")

    authority._materialization_precommit_hook = _tamper_prerequisite
    with pytest.raises(StateError, match="prerequisite receipt is not authentic"):
        authority.materialize_connection_composite(
            origin_plan,
            origin_rng,
            lifecycle_token=origin_token,
            application_token=proxy_token,
            prerequisite_receipts=(client.receipt,),
        )

    assert state.materialization_digest() == state_before
    assert origin_rng.getstate() == rng_before
    assert registry.stats() == registry_before
    assert registry.transport_for_transport_id(origin_plan.physical_transport_id) is None
    assert proxy.census().open_tunnel_views == 0
    assert proxy.census().application.retained_channels == 0
    object.__setattr__(client.receipt, "_transaction_id", original_transaction_id)
    authority._materialization_precommit_hook = None

    origin = authority.materialize_connection_composite(
        origin_plan,
        origin_rng,
        lifecycle_token=_lifecycle_token(authority, adapter, origin_plan),
        application_token=_proxy_token(proxy, client_plan, origin_plan),
        prerequisite_receipts=(client.receipt,),
    )
    proof = origin.receipt.application_proof
    assert proof is not None
    assert proof.manager_kind == "explicit_proxy"
    assert proof.current_transport_id == origin_plan.physical_transport_id
    assert proof.prerequisite_transport_ids == (client_plan.physical_transport_id,)
    assert origin.receipt.prerequisite_proofs[0].receipt_token == client.receipt.receipt_token
    assert authority.authenticates_connection_composite_receipt(origin_plan, origin.receipt)


def test_prepared_network_commits_full_authority_chain_in_exact_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority, state, _registry, adapter, runtime, _crypto, timing = _prepared_authority()
    _application_registry, http = _http_manager(authority)
    owner_rng = random.Random(101)
    root, lifecycle_token = _prepared_physical_root(
        authority,
        adapter,
        runtime,
        owner_rng,
        stable_id="prepared-http-transport",
    )
    application_token = _http_open_token(http, root.state_plan)
    timing_preparation = _sealed_source_timing(timing)
    order: list[str] = []
    original_lifecycle = LifecycleRegistry._commit_claimed_closed_transport_publication
    original_state = StateManager._commit_prevalidated_connection_composite
    original_http = HttpApplicationChannelManager._commit_claimed_admission
    original_runtime = NetworkTransactionPreparedCommit.commit_no_fail
    original_timing = SourceTimingPreparation.commit_no_fail
    original_timing_authentication = SourceTimingPlanner.authenticates_expected_preparation_receipt
    original_timing_certification = SourceTimingPreparation.certify_composite_commit
    expected_timing_receipts: list[SourceTimingPreparationReceipt] = []

    def _lifecycle_commit(
        registry: LifecycleRegistry,
        token: LifecycleClosedTransportAdmissionToken,
    ) -> LifecycleClosedTransportPublicationReceipt:
        order.append("lifecycle")
        return original_lifecycle(registry, token)

    def _state_commit(
        manager: StateManager,
        plan: ConnectionCompositeMaterializationPlan,
        rng: random.Random,
    ) -> ConnectionCompositeMaterializationResult:
        order.append("state")
        return original_state(manager, plan, rng)

    def _http_commit(
        manager: HttpApplicationChannelManager,
        token: HttpChannelAdmissionToken,
        application_commit: ApplicationChannelPreparedCommit,
    ) -> HttpChannelAdmissionResult:
        order.append("application")
        return original_http(manager, token, application_commit)

    def _runtime_commit(
        prepared: NetworkTransactionPreparedCommit,
    ) -> object:
        order.append("runtime")
        return original_runtime(prepared)

    def _timing_authentication(
        planner: SourceTimingPlanner,
        receipt: object,
        *,
        preparation: object,
    ) -> bool:
        order.append("timing-authentication")
        if isinstance(receipt, SourceTimingPreparationReceipt):
            expected_timing_receipts.append(receipt)
        return original_timing_authentication(
            planner,
            receipt,
            preparation=preparation,
        )

    def _timing_certification(
        preparation: SourceTimingPreparation,
        expected_receipt: SourceTimingPreparationReceipt,
    ) -> None:
        order.append("timing-certification")
        original_timing_certification(preparation, expected_receipt)

    def _timing_commit(
        preparation: SourceTimingPreparation,
    ) -> SourceTimingPreparationReceipt:
        order.append("timing")
        return original_timing(preparation)

    monkeypatch.setattr(
        LifecycleRegistry,
        "_commit_claimed_closed_transport_publication",
        _lifecycle_commit,
    )
    monkeypatch.setattr(
        StateManager,
        "_commit_prevalidated_connection_composite",
        _state_commit,
    )
    monkeypatch.setattr(HttpApplicationChannelManager, "_commit_claimed_admission", _http_commit)
    monkeypatch.setattr(NetworkTransactionPreparedCommit, "commit_no_fail", _runtime_commit)
    monkeypatch.setattr(
        SourceTimingPlanner,
        "authenticates_expected_preparation_receipt",
        _timing_authentication,
    )
    monkeypatch.setattr(
        SourceTimingPreparation,
        "certify_composite_commit",
        _timing_certification,
    )
    monkeypatch.setattr(SourceTimingPreparation, "commit_no_fail", _timing_commit)
    authority._materialization_precommit_hook = lambda: order.append("precommit")

    result = authority.materialize_prepared_network_transaction(
        root,
        owner_rng,
        source_timing_preparation=timing_preparation,
        lifecycle_token=lifecycle_token,
        application_token=application_token,
    )

    assert order == [
        "timing-authentication",
        "timing-certification",
        "timing-authentication",
        "precommit",
        "lifecycle",
        "state",
        "application",
        "runtime",
        "timing",
    ]
    assert isinstance(result.receipt, LifecyclePreparedNetworkReceipt)
    assert authority.authenticates_prepared_network_receipt(root, result.receipt)
    assert runtime.authenticates_preparation_receipt(result.runtime, token=root.runtime_token)
    assert len(expected_timing_receipts) == 2
    assert expected_timing_receipts[1] is expected_timing_receipts[0]
    assert result.timing is expected_timing_receipts[0]
    assert result.timing is timing_preparation.receipt
    assert timing.authenticates_preparation_receipt(result.timing)
    assert result.connection.state.connection is not None
    committed_version = state.materialization_version
    with pytest.raises(StateError, match="failed runtime authentication"):
        authority.materialize_prepared_network_transaction(
            root,
            owner_rng,
            source_timing_preparation=timing_preparation,
            lifecycle_token=lifecycle_token,
            application_token=application_token,
        )
    assert state.materialization_version == committed_version


def test_prepared_network_rejects_deferred_session_and_cleans_every_capability() -> None:
    authority, state, registry, adapter, runtime, crypto, timing = _prepared_authority()
    owner_rng = random.Random(102)
    rng_before = owner_rng.getstate()
    state_before = state.materialization_digest()
    runtime_before = runtime.state_digest()
    crypto_before = crypto.state_digest()
    timing_before = timing.state_digest()
    root, lifecycle_token = _prepared_physical_root(
        authority,
        adapter,
        runtime,
        owner_rng,
        stable_id="deferred-prepared-transport",
        lifecycle_mode="deferred_session",
    )
    timing_preparation = _sealed_source_timing(timing)

    with pytest.raises(StateError, match="Deferred-session"):
        authority.materialize_prepared_network_transaction(
            root,
            owner_rng,
            source_timing_preparation=timing_preparation,
            lifecycle_token=lifecycle_token,
        )

    assert owner_rng.getstate() == rng_before
    assert state.materialization_digest() == state_before
    assert runtime.state_digest() == runtime_before
    assert crypto.state_digest() == crypto_before
    assert timing.state_digest() == timing_before
    assert runtime.census().prepared_transactions == 0
    assert adapter.closed_transport_preparation_census().reservations == 0
    assert registry.transport_for_transport_id(root.transaction.stable_id) is None
    assert not timing_preparation.sealed


def test_prepared_network_rejects_unauthenticated_expected_timing_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority, state, registry, adapter, runtime, crypto, timing = _prepared_authority()
    owner_rng = random.Random(106)
    rng_before = owner_rng.getstate()
    state_before = state.materialization_digest()
    runtime_before = runtime.state_digest()
    crypto_before = crypto.state_digest()
    timing_before = timing.state_digest()
    root, lifecycle_token = _prepared_physical_root(
        authority,
        adapter,
        runtime,
        owner_rng,
        stable_id="unauthenticated-timing-receipt",
    )
    timing_preparation = _sealed_source_timing(timing)

    def _reject_expected_receipt(
        _planner: SourceTimingPlanner,
        _receipt: object,
        *,
        preparation: object,
    ) -> bool:
        assert preparation is timing_preparation
        return False

    monkeypatch.setattr(
        SourceTimingPlanner,
        "authenticates_expected_preparation_receipt",
        _reject_expected_receipt,
    )

    with pytest.raises(
        StateError,
        match="source timing receipt failed authentication",
    ):
        authority.materialize_prepared_network_transaction(
            root,
            owner_rng,
            source_timing_preparation=timing_preparation,
            lifecycle_token=lifecycle_token,
        )

    assert owner_rng.getstate() == rng_before
    assert state.materialization_digest() == state_before
    assert runtime.state_digest() == runtime_before
    assert crypto.state_digest() == crypto_before
    assert timing.state_digest() == timing_before
    assert runtime.census().prepared_transactions == 0
    assert adapter.closed_transport_preparation_census().reservations == 0
    assert registry.transport_for_transport_id(root.transaction.stable_id) is None
    assert not timing_preparation.sealed


def test_prepared_network_rejects_foreign_runtime_and_timing_without_foreign_mutation() -> None:
    authority, state, _registry, adapter, runtime, _crypto, timing = _prepared_authority()
    (
        foreign_authority,
        foreign_state,
        _foreign_registry,
        foreign_adapter,
        foreign_runtime,
        (_foreign_crypto),
        foreign_timing,
    ) = _prepared_authority()
    local_state_before = state.materialization_digest()
    foreign_state_before = foreign_state.materialization_digest()
    foreign_timing_before = foreign_timing.state_digest()
    foreign_rng = random.Random(107)
    foreign_root, foreign_lifecycle = _prepared_physical_root(
        foreign_authority,
        foreign_adapter,
        foreign_runtime,
        foreign_rng,
        stable_id="foreign-runtime-root",
    )
    local_timing = _sealed_source_timing(timing)

    with pytest.raises(StateError, match="failed runtime authentication"):
        authority.materialize_prepared_network_transaction(
            foreign_root,
            foreign_rng,
            source_timing_preparation=local_timing,
        )

    assert state.materialization_digest() == local_state_before
    assert foreign_state.materialization_digest() == foreign_state_before
    assert foreign_runtime.authenticates_preparation_root(foreign_root)
    assert foreign_timing.state_digest() == foreign_timing_before
    assert not local_timing.sealed
    foreign_runtime.cancel_preparation(foreign_root.runtime_token)
    foreign_adapter.cancel_closed_transport_publication(foreign_lifecycle)

    local_rng = random.Random(108)
    local_root, local_lifecycle = _prepared_physical_root(
        authority,
        adapter,
        runtime,
        local_rng,
        stable_id="foreign-timing-root",
    )
    foreign_timing_preparation = _sealed_source_timing(foreign_timing)
    with pytest.raises(StateError, match="source timing capability"):
        authority.materialize_prepared_network_transaction(
            local_root,
            local_rng,
            source_timing_preparation=foreign_timing_preparation,
            lifecycle_token=local_lifecycle,
        )

    assert state.materialization_digest() == local_state_before
    assert foreign_state.materialization_digest() == foreign_state_before
    assert foreign_timing.authenticates_preparation(foreign_timing_preparation)
    assert foreign_timing_preparation.sealed
    foreign_timing_preparation.cancel()


def test_prepared_http_application_child_reuses_one_physical_transport() -> None:
    authority, state, registry, adapter, runtime, _crypto, timing = _prepared_authority()
    _application_registry, http = _http_manager(authority)
    parent_rng = random.Random(103)
    parent_root, parent_lifecycle = _prepared_physical_root(
        authority,
        adapter,
        runtime,
        parent_rng,
        stable_id="prepared-http-parent",
    )
    parent = authority.materialize_prepared_network_transaction(
        parent_root,
        parent_rng,
        source_timing_preparation=_sealed_source_timing(timing),
        lifecycle_token=parent_lifecycle,
        application_token=_http_open_token(http, parent_root.state_plan),
    )
    reuse = http.prepare_reuse(
        _http_affinity(),
        requested_at=_START + timedelta(seconds=1),
        required_until=_START + timedelta(seconds=1, milliseconds=100),
        request_body_bytes=20,
        response_body_bytes=200,
    )
    assert reuse is not None
    assert isinstance(reuse.result, HttpChannelReuse)
    child_rng = random.Random(104)
    child_preparation = runtime.begin(
        owner_rng=child_rng,
        stable_id=reuse.result.operation_id,
        linearization_time=reuse.result.canonical_request_time,
    )
    child_transaction = _transaction(
        conn_id=parent_root.transaction.conn_id,
        zeek_uid=parent_root.transaction.zeek_uid,
        stable_id=reuse.result.operation_id,
        started_at=reuse.result.canonical_request_time,
        duration=0.1,
        application_layer_only=True,
    )
    child_root = child_preparation.seal(
        transaction=child_transaction,
        lifecycle_mode="application_child",
        materialization_mode=ConnectionMaterializationMode.APPLICATION_CHILD,
    )
    transport_count = registry.stats().live_transports

    child = authority.materialize_prepared_network_transaction(
        child_root,
        child_rng,
        source_timing_preparation=_sealed_source_timing(timing),
        application_token=reuse,
    )

    assert child.connection.lifecycle is None
    assert child.connection.state.connection is parent.connection.state.connection
    assert child.receipt.physical_transport_id == parent.receipt.physical_transport_id
    assert not child.receipt.materializes_connection
    assert registry.stats().live_transports == transport_count
    assert authority.authenticates_prepared_network_receipt(child_root, child.receipt)


def test_prepared_proxy_origin_requires_full_prepared_prerequisite_receipt() -> None:
    authority, state, _registry, adapter, runtime, _crypto, timing = _prepared_authority()
    proxy = _proxy_manager(authority)
    client_rng = random.Random(105)
    client_root, client_lifecycle = _prepared_physical_root(
        authority,
        adapter,
        runtime,
        client_rng,
        stable_id="prepared-proxy-client",
        dst_ip="10.0.3.10",
        dst_port=8080,
    )
    client = authority.materialize_prepared_network_transaction(
        client_root,
        client_rng,
        source_timing_preparation=_sealed_source_timing(timing),
        lifecycle_token=client_lifecycle,
    )
    origin_rng = random.Random(106)
    origin_root, origin_lifecycle = _prepared_physical_root(
        authority,
        adapter,
        runtime,
        origin_rng,
        stable_id="prepared-proxy-origin",
        src_ip="10.0.3.10",
        src_port=40_001,
    )
    timing_preparation = _sealed_source_timing(timing)
    with pytest.raises(StateError, match="prerequisite receipt is not authentic"):
        authority.materialize_prepared_network_transaction(
            origin_root,
            origin_rng,
            source_timing_preparation=timing_preparation,
            lifecycle_token=origin_lifecycle,
            application_token=_proxy_token(
                proxy,
                client_root.state_plan,
                origin_root.state_plan,
            ),
            prerequisite_receipts=(client.connection.receipt,),  # type: ignore[arg-type]
        )

    origin_root, origin_lifecycle = _prepared_physical_root(
        authority,
        adapter,
        runtime,
        origin_rng,
        stable_id="prepared-proxy-origin",
        src_ip="10.0.3.10",
        src_port=40_001,
    )
    origin = authority.materialize_prepared_network_transaction(
        origin_root,
        origin_rng,
        source_timing_preparation=_sealed_source_timing(timing),
        lifecycle_token=origin_lifecycle,
        application_token=_proxy_token(
            proxy,
            client_root.state_plan,
            origin_root.state_plan,
        ),
        prerequisite_receipts=(client.receipt,),
    )

    assert origin.receipt.connection_receipt.prerequisite_proofs[0].receipt_token == (
        client.connection.receipt.receipt_token
    )
    assert authority.authenticates_prepared_network_receipt(origin_root, origin.receipt)
    forged = replace(origin.receipt, _result_digest="forged-result")
    assert not authority.authenticates_prepared_network_receipt(origin_root, forged)


def test_prepared_proxy_setup_only_origin_commits_one_closed_authenticated_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Setup-only proxy common state is atomically born closed before authority proofing."""

    authority, state, _registry, adapter, runtime, _crypto, timing = _prepared_authority()
    proxy = _proxy_manager(authority)
    client_rng = random.Random(107)
    client_root, client_lifecycle = _prepared_physical_root(
        authority,
        adapter,
        runtime,
        client_rng,
        stable_id="prepared-proxy-setup-only-client",
        dst_ip="10.0.3.10",
        dst_port=8080,
    )
    client = authority.materialize_prepared_network_transaction(
        client_root,
        client_rng,
        source_timing_preparation=_sealed_source_timing(timing),
        lifecycle_token=client_lifecycle,
    )
    origin_rng = random.Random(108)
    origin_root, origin_lifecycle = _prepared_physical_root(
        authority,
        adapter,
        runtime,
        origin_rng,
        stable_id="prepared-proxy-setup-only-origin",
        src_ip="10.0.3.10",
        src_port=40_001,
    )

    def fail_public_close(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("setup-only authority path called public common close")

    monkeypatch.setattr(ApplicationChannelRegistry, "close_channel_by_token", fail_public_close)
    origin = authority.materialize_prepared_network_transaction(
        origin_root,
        origin_rng,
        source_timing_preparation=_sealed_source_timing(timing),
        lifecycle_token=origin_lifecycle,
        application_token=_proxy_token(
            proxy,
            client_root.state_plan,
            origin_root.state_plan,
            request_count=0,
        ),
        prerequisite_receipts=(client.receipt,),
    )

    application = origin.connection.application
    assert application is not None
    assert proxy.authenticates_admission_receipt(application.receipt)
    assert application.receipt.application_receipt.kind == "open_completed_close"
    assert application.receipt.application_receipt.snapshot.close_reason == "setup-only"
    assert proxy.census().open_tunnel_views == 0
    assert proxy.census().application.open_channels == 0
    assert authority.authenticates_prepared_network_receipt(origin_root, origin.receipt)


@pytest.mark.parametrize("outcome", ["success", "denied"])
def test_prepared_proxy_request_commits_on_client_application_child_only(
    outcome: str,
) -> None:
    """A request token owns the client child root and requires no repeated prerequisite."""

    authority, state, registry, adapter, runtime, _crypto, timing = _prepared_authority()
    proxy = _proxy_manager(authority)
    client_rng = random.Random(109)
    client_root, client_lifecycle = _prepared_physical_root(
        authority,
        adapter,
        runtime,
        client_rng,
        stable_id="prepared-proxy-request-client",
        dst_ip="10.0.3.10",
        dst_port=8080,
    )
    client = authority.materialize_prepared_network_transaction(
        client_root,
        client_rng,
        source_timing_preparation=_sealed_source_timing(timing),
        lifecycle_token=client_lifecycle,
    )
    origin_rng = random.Random(110)
    origin_root, origin_lifecycle = _prepared_physical_root(
        authority,
        adapter,
        runtime,
        origin_rng,
        stable_id="prepared-proxy-request-origin",
        src_ip="10.0.3.10",
        src_port=40_001,
    )
    origin = authority.materialize_prepared_network_transaction(
        origin_root,
        origin_rng,
        source_timing_preparation=_sealed_source_timing(timing),
        lifecycle_token=origin_lifecycle,
        application_token=_proxy_token(proxy, client_root.state_plan, origin_root.state_plan),
        prerequisite_receipts=(client.receipt,),
    )
    request_token = proxy.prepare_request(
        ExplicitProxyChannelAffinity(
            client_ip="10.0.0.10",
            proxy_ip="10.0.3.10",
            proxy_port=8080,
            origin_host="portal.example.test",
            origin_ip="203.0.113.20",
            origin_port=443,
            user_agent="Mozilla/5.0",
            auth_identity="EXAMPLE\\analyst",
            policy_id="TLS-Bump-Standard",
        ),
        requested_at=_START + timedelta(seconds=1),
        completed_at=_START + timedelta(seconds=1, milliseconds=100),
        request_wire_bytes=100,
        response_wire_bytes=200,
        outcome=outcome,  # type: ignore[arg-type]
    )
    assert request_token is not None
    child_rng = random.Random(111)
    child_preparation = runtime.begin(
        owner_rng=child_rng,
        stable_id=request_token.result.operation_id,
        linearization_time=request_token.result.canonical_request_time,
    )
    child_transaction = _transaction(
        conn_id=client_root.transaction.conn_id,
        zeek_uid=client_root.transaction.zeek_uid,
        stable_id=request_token.result.operation_id,
        started_at=request_token.result.canonical_request_time,
        duration=0.1,
        application_layer_only=True,
        src_ip=client_root.transaction.src_ip,
        src_port=client_root.transaction.src_port,
        dst_ip=client_root.transaction.dst_ip,
        dst_port=client_root.transaction.dst_port,
    )
    child_root = child_preparation.seal(
        transaction=child_transaction,
        lifecycle_mode="application_child",
        materialization_mode=ConnectionMaterializationMode.APPLICATION_CHILD,
    )
    transport_count = registry.stats().live_transports

    child = authority.materialize_prepared_network_transaction(
        child_root,
        child_rng,
        source_timing_preparation=_sealed_source_timing(timing),
        application_token=request_token,
    )

    proof = child.connection.receipt.application_proof
    assert proof is not None
    assert proof.current_transport_id == client_root.transaction.stable_id
    assert proof.prerequisite_transport_ids == ()
    assert child.connection.state.connection is client.connection.state.connection
    assert child.connection.lifecycle is None
    assert child.receipt.physical_transport_id == client.receipt.physical_transport_id
    assert child.connection.receipt.prerequisite_proofs == ()
    assert registry.stats().live_transports == transport_count
    assert authority.authenticates_prepared_network_receipt(child_root, child.receipt)
    assert origin.receipt.materializes_connection
    if outcome == "denied":
        assert child.connection.application is not None
        assert isinstance(child.connection.application.result, ExplicitProxyTerminalRequest)
        assert proxy.get_tunnel(request_token.result.tunnel.channel_id) is None
    else:
        assert (
            proxy.get_tunnel(request_token.result.tunnel.channel_id) == request_token.result.tunnel
        )
