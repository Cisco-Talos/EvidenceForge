# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Production-adapter tests for service and transport lifecycle publication."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.events.content_identity import CompiledServiceDeploymentIdentity
from evidenceforge.events.lifecycle import (
    LifecycleCloseBarrier,
    LifecycleHold,
    LifecycleMembership,
    ProcessLifecycleIdentity,
    ProcessTokenIdentity,
    ServiceProcessBindingIdentity,
    SessionLifecycleIdentity,
)
from evidenceforge.events.network import NetworkTrafficLedger, NetworkTransactionPlan
from evidenceforge.generation import lifecycle_registry as lifecycle_registry_module
from evidenceforge.generation.lifecycle_production_adapters import (
    LifecycleProductionAdapter,
    TransportLifecyclePublicationPlan,
    builtin_service_publication_plan,
    closed_transport_publication_plan,
)
from evidenceforge.generation.lifecycle_registry import (
    LifecycleClosedTransportAdmissionToken,
    LifecycleClosedTransportStartMember,
    LifecycleProcessStartRequest,
    LifecycleRegistry,
    LifecycleSessionStartRequest,
)
from evidenceforge.models.exceptions import StateError

_OPENED_AT = datetime(2026, 8, 16, 13, 0, tzinfo=UTC)


def _transaction(
    *,
    stable_id: str = "network-action-1",
    zeek_uid: str = "CcanonicalTransport1",
) -> NetworkTransactionPlan:
    closed_at = _OPENED_AT + timedelta(seconds=30)
    return NetworkTransactionPlan(
        stable_id=stable_id,
        hostname="CLIENT-01",
        outcome="success",
        phase_times=(("transport_start", _OPENED_AT), ("transport_close", closed_at)),
        started_at=_OPENED_AT,
        closed_at=closed_at,
        src_ip="10.0.10.10",
        src_port=51_234,
        dst_ip="10.0.20.20",
        dst_port=3389,
        protocol="tcp",
        service="rdp",
        zeek_uid=zeek_uid,
        conn_id="connection-1",
        duration=30.0,
        conn_state="SF",
        history="ShADadFf",
        traffic=NetworkTrafficLedger(),
    )


def _registry_with_target_session() -> tuple[LifecycleRegistry, SessionLifecycleIdentity]:
    registry = LifecycleRegistry(shard_count=8)
    session = SessionLifecycleIdentity(
        hostname="SERVER-01",
        object_id="target-session-object",
        logon_id="0x1234",
        principal="analyst",
        session_kind="rdp",
        started_at=_OPENED_AT + timedelta(seconds=1),
        session_id=3,
    )
    registry.register_session(
        session,
        action_id="target-session-start-action",
        transition_id="target-session-start-transition",
    )
    return registry, session


def test_closed_transport_publication_is_exact_temporal_and_idempotent() -> None:
    """One action retry retains one immutable cross-host transport ledger."""

    registry, session = _registry_with_target_session()
    transaction = _transaction()
    assert transaction.closed_at is not None
    plan = closed_transport_publication_plan(
        transaction=transaction,
        authority_hostname="CLIENT-01",
        src_hostname="CLIENT-01",
        dst_hostname="SERVER-01",
        session_object_id=session.object_id,
        binding_role="session",
        bound_at=session.started_at,
        action_id="rdp-action-1",
    )
    adapter = LifecycleProductionAdapter(registry)

    first = adapter.publish_closed_transport(plan)
    registry.advance_watermark(transaction.closed_at + timedelta(minutes=1))
    second = adapter.publish_closed_transport(plan)

    assert second == first
    assert first.identity == plan.identity
    assert first.closed_at == transaction.closed_at
    assert first.active_binding_count == 0
    assert first.identity.src_hostname == "CLIENT-01"
    assert first.identity.dst_hostname == "SERVER-01"
    assert registry.transport_for_transport_id(transaction.stable_id) == first
    assert registry.transport_for_uid(transaction.zeek_uid) == first
    assert registry.transport_at(first.identity.object_id, transaction.started_at) == first
    assert registry.transport_at(first.identity.object_id, session.started_at) == first
    assert registry.transport_at(first.identity.object_id, transaction.closed_at) is None
    assert registry.session_transport_close_deadline(session.object_id) == transaction.closed_at
    binding = plan.binding_identity
    assert binding is not None
    binding_snapshot = registry.transport_session_binding(binding.binding_id)
    assert binding_snapshot is not None
    assert binding_snapshot.identity == binding
    assert binding_snapshot.closed_at == transaction.closed_at
    census = registry.census()
    assert census.transport_entries == 1
    assert census.transport_session_bindings == 1
    assert census.active_transport_session_bindings == 0


def test_transport_preflight_rejection_leaves_no_partial_registry_state() -> None:
    """An unknown target session rejects before transport or binding publication."""

    registry = LifecycleRegistry(shard_count=8)
    transaction = _transaction()
    plan = closed_transport_publication_plan(
        transaction=transaction,
        authority_hostname="CLIENT-01",
        src_hostname="CLIENT-01",
        dst_hostname="SERVER-01",
        session_object_id="missing-target-session",
        binding_role="session",
        bound_at=_OPENED_AT + timedelta(seconds=1),
        action_id="rdp-action-rejected",
    )
    adapter = LifecycleProductionAdapter(registry)

    with pytest.raises(StateError, match="Unknown target session"):
        adapter.validate_transport_publication(plan)

    assert registry.get_transport(plan.identity.object_id) is None
    census = registry.census()
    assert census.transport_entries == 0
    assert census.transport_session_bindings == 0


def test_transport_retry_rejects_immutable_identity_drift_without_new_rows() -> None:
    """A repeated canonical ID cannot silently change its network identity."""

    registry, session = _registry_with_target_session()
    transaction = _transaction()
    plan = closed_transport_publication_plan(
        transaction=transaction,
        authority_hostname="CLIENT-01",
        src_hostname="CLIENT-01",
        dst_hostname="SERVER-01",
        session_object_id=session.object_id,
        binding_role="session",
        bound_at=session.started_at,
        action_id="rdp-action-1",
    )
    adapter = LifecycleProductionAdapter(registry)
    adapter.publish_closed_transport(plan)
    drifted = closed_transport_publication_plan(
        transaction=replace(transaction, conn_id="connection-drift"),
        authority_hostname="CLIENT-01",
        src_hostname="CLIENT-01",
        dst_hostname="SERVER-01",
        session_object_id=session.object_id,
        binding_role="session",
        bound_at=session.started_at,
        action_id="rdp-action-1",
    )

    with pytest.raises(StateError, match="immutable identity drift"):
        adapter.validate_transport_publication(drifted)

    census = registry.census()
    assert census.transport_entries == 1
    assert census.transport_session_bindings == 1


def test_concurrent_transport_retries_converge_on_one_terminal_ledger() -> None:
    """Same-plan worker races retain one binding and one terminal transport."""

    registry, session = _registry_with_target_session()
    transaction = _transaction()
    plan = closed_transport_publication_plan(
        transaction=transaction,
        authority_hostname="CLIENT-01",
        src_hostname="CLIENT-01",
        dst_hostname="SERVER-01",
        session_object_id=session.object_id,
        binding_role="session",
        bound_at=session.started_at,
        action_id="rdp-action-concurrent",
    )
    adapter = LifecycleProductionAdapter(registry)

    with ThreadPoolExecutor(max_workers=8) as pool:
        snapshots = tuple(
            pool.map(lambda _ordinal: adapter.publish_closed_transport(plan), range(32))
        )

    assert all(snapshot == snapshots[0] for snapshot in snapshots)
    assert snapshots[0].closed_at == transaction.closed_at
    census = registry.census()
    assert census.transport_entries == 1
    assert census.transport_session_bindings == 1
    assert census.active_transport_session_bindings == 0


def _staged_start_members(
    session: SessionLifecycleIdentity,
) -> tuple[LifecycleClosedTransportStartMember, ...]:
    responder = ProcessLifecycleIdentity(
        hostname=session.hostname,
        object_id=f"{session.object_id}-responder",
        pid=6_001,
        started_at=session.started_at,
        image=r"C:\Windows\System32\winlogon.exe",
        role="session_shell",
    )
    shell = ProcessLifecycleIdentity(
        hostname=session.hostname,
        object_id=f"{session.object_id}-shell",
        pid=6_002,
        started_at=session.started_at + timedelta(microseconds=1),
        image=r"C:\Windows\explorer.exe",
        parent_object_id=responder.object_id,
        role="session_shell",
    )
    membership = LifecycleMembership(
        owner_kind="session",
        owner_object_id=session.object_id,
        session_object_id=session.object_id,
    )
    return (
        LifecycleClosedTransportStartMember(
            request=LifecycleSessionStartRequest(
                identity=session,
                action_id=f"{session.object_id}-start-action",
                transition_id=f"{session.object_id}-start-transition",
            ),
            publication_token=f"state-plan:{session.object_id}",
        ),
        LifecycleClosedTransportStartMember(
            request=LifecycleProcessStartRequest(
                identity=responder,
                token=ProcessTokenIdentity(
                    principal=session.principal,
                    logon_id=session.logon_id,
                    session_id=session.session_id,
                ),
                membership=membership,
                action_id=f"{responder.object_id}-start-action",
                transition_id=f"{responder.object_id}-start-transition",
            ),
            publication_token=f"state-plan:{responder.object_id}",
        ),
        LifecycleClosedTransportStartMember(
            request=LifecycleProcessStartRequest(
                identity=shell,
                token=ProcessTokenIdentity(
                    principal=session.principal,
                    logon_id=session.logon_id,
                    session_id=session.session_id,
                ),
                membership=membership,
                action_id=f"{shell.object_id}-start-action",
                transition_id=f"{shell.object_id}-start-transition",
            ),
            publication_token=f"state-plan:{shell.object_id}",
        ),
    )


def _register_source_process(
    registry: LifecycleRegistry,
    *,
    object_id: str = "source-process-object",
) -> ProcessLifecycleIdentity:
    process = ProcessLifecycleIdentity(
        hostname="CLIENT-01",
        object_id=object_id,
        pid=7_001,
        started_at=_OPENED_AT - timedelta(seconds=1),
        image=r"C:\Windows\System32\mstsc.exe",
        role="client",
    )
    registry.register_process(
        process,
        token=ProcessTokenIdentity(principal="analyst", logon_id="0x4040", session_id=2),
        membership=LifecycleMembership(
            owner_kind="boot",
            owner_object_id=process.object_id,
        ),
        action_id=f"{object_id}-start-action",
        transition_id=f"{object_id}-start-transition",
    )
    return process


def _transport_hold(
    process: ProcessLifecycleIdentity,
    *,
    acquired_at: datetime = _OPENED_AT,
    hold_id: str = "source-process-transport-hold",
) -> LifecycleHold:
    return LifecycleHold(
        hold_id=hold_id,
        subject=process.ref,
        acquired_at=acquired_at,
        hold_until=_OPENED_AT + timedelta(seconds=30),
        action_id=f"{hold_id}-action",
        reason="canonical_transport_close",
    )


def _prepared_staged_transport_with_hold(
    *,
    stable_id: str = "staged-held-transport",
) -> tuple[
    LifecycleRegistry,
    LifecycleProductionAdapter,
    TransportLifecyclePublicationPlan,
    tuple[LifecycleClosedTransportStartMember, ...],
    tuple[LifecycleHold, ...],
    LifecycleClosedTransportAdmissionToken,
]:
    registry = LifecycleRegistry(shard_count=8)
    adapter = LifecycleProductionAdapter(registry)
    session = SessionLifecycleIdentity(
        hostname="SERVER-01",
        object_id=f"{stable_id}-session",
        logon_id="0x7171",
        principal="analyst",
        session_kind="rdp",
        started_at=_OPENED_AT + timedelta(seconds=1),
        session_id=7,
    )
    members = _staged_start_members(session)
    shell = members[-1].request
    assert isinstance(shell, LifecycleProcessStartRequest)
    holds = (
        LifecycleHold(
            hold_id=f"{stable_id}-shell-hold",
            subject=shell.identity.ref,
            acquired_at=shell.identity.started_at,
            hold_until=_OPENED_AT + timedelta(seconds=30),
            action_id=f"{stable_id}-shell-hold-action",
            reason="canonical_transport_close",
        ),
    )
    plan = closed_transport_publication_plan(
        transaction=_transaction(stable_id=stable_id, zeek_uid=f"C{stable_id}"),
        authority_hostname="CLIENT-01",
        src_hostname="CLIENT-01",
        dst_hostname="SERVER-01",
        session_object_id=session.object_id,
        bound_at=session.started_at,
        action_id=f"{stable_id}-action",
    )
    token = adapter.prepare_closed_transport_publication(
        plan,
        start_members=members,
        process_holds=holds,
    )
    return registry, adapter, plan, members, holds, token


def _tamper_closed_transport_token(
    token: LifecycleClosedTransportAdmissionToken,
    mutation: str,
) -> None:
    if mutation == "preparation_id":
        object.__setattr__(token, "preparation_id", token.preparation_id + 10_000)
    elif mutation == "transport":
        object.__setattr__(token.request.identity, "conn_id", "tampered-connection")
    elif mutation == "start_member":
        object.__setattr__(
            token.request.start_members[0],
            "publication_token",
            "tampered-state-plan",
        )
    elif mutation == "hold":
        object.__setattr__(token.request.process_holds[0], "reason", "tampered-hold")
    else:
        raise AssertionError(f"Unknown test mutation {mutation}")


def test_prepared_closed_transport_commits_full_start_batch_atomically() -> None:
    """One claim publishes session, parent-ordered processes, and closed transport together."""

    registry = LifecycleRegistry(shard_count=8)
    session = SessionLifecycleIdentity(
        hostname="SERVER-01",
        object_id="staged-target-session",
        logon_id="0x5150",
        principal="analyst",
        session_kind="rdp",
        started_at=_OPENED_AT + timedelta(seconds=1),
        session_id=5,
    )
    members = _staged_start_members(session)
    plan = closed_transport_publication_plan(
        transaction=_transaction(),
        authority_hostname="CLIENT-01",
        src_hostname="CLIENT-01",
        dst_hostname="SERVER-01",
        session_object_id=session.object_id,
        binding_role="session",
        bound_at=session.started_at,
        action_id="rdp-staged-batch",
    )
    adapter = LifecycleProductionAdapter(registry)
    before = registry.census()

    token = adapter.prepare_closed_transport_publication(plan, start_members=members)
    prepared = registry.census()
    assert prepared.session_entries == before.session_entries == 0
    assert prepared.process_entries == before.process_entries == 0
    assert prepared.transport_entries == before.transport_entries == 0
    assert prepared.transport_session_bindings == before.transport_session_bindings == 0

    with adapter.claimed_closed_transport_publication(token) as claimed:
        assert registry.get_session(session.object_id) is None
        receipt = claimed.commit_no_fail()

    assert receipt.start_plan_tokens == tuple(member.publication_token for member in members)
    assert receipt.transport.identity == plan.identity
    assert receipt.transport.closed_at == plan.identity.close_deadline
    assert receipt.binding is not None
    assert receipt.binding.closed_at == plan.identity.close_deadline
    assert registry.get_session(session.object_id) is not None
    for member in members[1:]:
        assert isinstance(member.request, LifecycleProcessStartRequest)
        assert registry.get_process(member.request.identity.object_id) is not None
    assert adapter.authenticates_closed_transport_publication_receipt(
        receipt,
        start_plan_tokens=tuple(member.publication_token for member in members),
    )


def test_prepared_closed_transport_commits_process_hold_and_defers_owner_close() -> None:
    """An authenticated source hold is atomic and governs the later process ticket."""

    registry = LifecycleRegistry(shard_count=8)
    adapter = LifecycleProductionAdapter(registry)
    process = _register_source_process(registry)
    hold = _transport_hold(process)
    plan = closed_transport_publication_plan(
        transaction=_transaction(stable_id="held-transport", zeek_uid="CheldTransport"),
        authority_hostname="CLIENT-01",
        src_hostname="CLIENT-01",
        dst_hostname="SERVER-01",
        action_id="held-transport-action",
    )
    token = adapter.prepare_closed_transport_publication(plan, process_holds=(hold,))
    prepared = adapter.closed_transport_preparation_census()
    assert prepared.reservations == prepared.capability_locators == 1
    assert prepared.claimed_reservations == 0
    assert prepared.reserved_keys > 0
    assert adapter.authenticates_closed_transport_admission_token(
        token,
        plan=plan,
        process_holds=(hold,),
    )
    with pytest.raises(StateError, match="prepared closed-transport"):
        registry.add_hold(hold)
    with pytest.raises(StateError, match="prepared closed-transport"):
        registry.register_transport(
            plan.identity,
            action_id="ordinary-transport-action",
            transition_id=plan.transition_id,
        )

    with adapter.claimed_closed_transport_publication(token) as claimed:
        assert adapter.closed_transport_preparation_census().claimed_reservations == 1
        receipt = claimed.commit_no_fail()

    assert receipt.process_holds == (hold,)
    assert registry.hold(hold.hold_id) == hold
    assert adapter.closed_transport_preparation_census().reservations == 0
    barrier = LifecycleCloseBarrier(
        barrier_id="source-process-close-barrier",
        subject=process.ref,
        requested_at=hold.hold_until - timedelta(seconds=5),
        authority="generated",
        action_id="source-process-close-action",
    )
    ticket = registry.request_close(barrier, ticket_id="source-process-close-ticket")
    assert ticket.effective_at == hold.hold_until
    assert registry.close(ticket.ticket_id).closed_at == hold.hold_until
    assert adapter.authenticates_closed_transport_publication_receipt(
        receipt,
        plan=plan,
        process_holds=(hold,),
    )


def test_prepared_closed_transport_copy_is_not_the_one_shot_capability() -> None:
    """A value-equal copied token cannot claim or cancel the original capability."""

    registry, adapter, plan, members, holds, token = _prepared_staged_transport_with_hold(
        stable_id="copied-capability"
    )
    copied = replace(token)
    assert not adapter.authenticates_closed_transport_admission_token(
        copied,
        plan=plan,
        start_members=members,
        process_holds=holds,
    )
    with pytest.raises(StateError, match="stale or consumed"):
        with adapter.claimed_closed_transport_publication(copied):
            pytest.fail("copied token yielded a commit capability")
    assert adapter.closed_transport_preparation_census().reservations == 1
    adapter.cancel_closed_transport_publication(token)
    assert registry.census().transport_entries == 0
    assert adapter.closed_transport_preparation_census().reservations == 0


def test_prepared_closed_transport_adopts_exact_frozen_request_without_copy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The private adapter request transfers directly into registry ownership."""

    registry = LifecycleRegistry(shard_count=8)
    adapter = LifecycleProductionAdapter(registry)
    plan = closed_transport_publication_plan(
        transaction=_transaction(stable_id="frozen-request", zeek_uid="CfrozenRequest"),
        authority_hostname="CLIENT-01",
        src_hostname="CLIENT-01",
        dst_hostname="SERVER-01",
        action_id="frozen-request-action",
    )
    request = adapter._closed_transport_request(
        plan,
        start_members=(),
        process_holds=(),
    )

    def fail_copy(_value: object) -> object:
        raise AssertionError("trusted frozen request was copied")

    monkeypatch.setattr(lifecycle_registry_module, "deepcopy", fail_copy)

    token = registry.prepare_closed_transport_publication(request)

    assert token.request is request
    registry.cancel_closed_transport_publication(token)


def test_prepared_closed_transport_cancel_and_rejection_leave_zero_rows() -> None:
    """Cancellation and late-member rejection retain no lifecycle entity or control row."""

    registry = LifecycleRegistry(shard_count=8)
    adapter = LifecycleProductionAdapter(registry)
    transaction = _transaction()
    plan = closed_transport_publication_plan(
        transaction=transaction,
        authority_hostname="CLIENT-01",
        src_hostname="CLIENT-01",
        dst_hostname="SERVER-01",
        action_id="transport-cancel",
    )
    token = adapter.prepare_closed_transport_publication(plan)
    adapter.cancel_closed_transport_publication(token)

    census = registry.census()
    assert census.transport_entries == 0
    assert census.transitions == 0
    assert census.close_barriers == 0
    assert census.closure_tickets == 0

    session = SessionLifecycleIdentity(
        hostname="SERVER-01",
        object_id="invalid-staged-session",
        logon_id="0x6161",
        principal="analyst",
        session_kind="ssh",
        started_at=_OPENED_AT + timedelta(seconds=1),
    )
    members = list(_staged_start_members(session))
    shell = members[-1]
    assert isinstance(shell.request, LifecycleProcessStartRequest)
    members[-1] = replace(
        shell,
        request=replace(
            shell.request,
            identity=replace(shell.request.identity, parent_object_id="missing-parent"),
        ),
    )
    bound_plan = closed_transport_publication_plan(
        transaction=replace(transaction, stable_id="invalid-batch", zeek_uid="CinvalidBatch"),
        authority_hostname="CLIENT-01",
        src_hostname="CLIENT-01",
        dst_hostname="SERVER-01",
        session_object_id=session.object_id,
        bound_at=session.started_at,
        action_id="invalid-staged-batch",
    )
    with pytest.raises(StateError, match="parent"):
        adapter.prepare_closed_transport_publication(
            bound_plan,
            start_members=tuple(members),
        )
    census = registry.census()
    assert census.session_entries == 0
    assert census.process_entries == 0
    assert census.transport_entries == 0
    assert census.transport_session_bindings == 0


def test_prepared_closed_transport_token_and_receipt_authentication_is_one_shot() -> None:
    """Foreign, stale, and reused capabilities cannot publish lifecycle state."""

    registry = LifecycleRegistry(shard_count=8)
    other = LifecycleRegistry(shard_count=8)
    adapter = LifecycleProductionAdapter(registry)
    other_adapter = LifecycleProductionAdapter(other)
    plan = closed_transport_publication_plan(
        transaction=_transaction(),
        authority_hostname="CLIENT-01",
        src_hostname="CLIENT-01",
        dst_hostname="SERVER-01",
        action_id="authenticated-transport",
    )
    token = adapter.prepare_closed_transport_publication(plan)
    with pytest.raises(StateError, match="registry"):
        with other_adapter.claimed_closed_transport_publication(token):
            pytest.fail("foreign token yielded a commit capability")

    with adapter.claimed_closed_transport_publication(token) as claimed:
        receipt = claimed.commit_no_fail()
        with pytest.raises(StateError, match="already committed"):
            claimed.commit_no_fail()
    with pytest.raises(StateError, match="consumed"):
        with adapter.claimed_closed_transport_publication(token):
            pytest.fail("consumed token yielded another commit capability")

    assert adapter.authenticates_closed_transport_publication_receipt(receipt)
    assert not other_adapter.authenticates_closed_transport_publication_receipt(receipt)
    forged_receipt = replace(receipt, _integrity="f" * 64)
    assert not adapter.authenticates_closed_transport_publication_receipt(forged_receipt)

    retry_token = adapter.prepare_closed_transport_publication(plan)
    with adapter.claimed_closed_transport_publication(retry_token) as claimed:
        retry_receipt = claimed.commit_no_fail()
    assert retry_receipt == receipt
    assert registry.census().transport_entries == 1


def test_prepared_closed_transport_rejects_stale_watermark_and_fences_claim() -> None:
    """Unclaimed tokens stale on any watermark drift and claimed tokens fence advancement."""

    registry = LifecycleRegistry(shard_count=8)
    adapter = LifecycleProductionAdapter(registry)
    plan = closed_transport_publication_plan(
        transaction=_transaction(stable_id="watermark-transport", zeek_uid="Cwatermark"),
        authority_hostname="CLIENT-01",
        src_hostname="CLIENT-01",
        dst_hostname="SERVER-01",
        action_id="watermark-action",
    )
    token = adapter.prepare_closed_transport_publication(plan)
    registry.advance_watermark(plan.identity.opened_at)
    with pytest.raises(StateError, match="stale after watermark"):
        with adapter.claimed_closed_transport_publication(token):
            pytest.fail("stale token yielded a commit capability")
    adapter.cancel_closed_transport_publication(token)

    equal_registry = LifecycleRegistry(shard_count=8)
    equal_registry.advance_watermark(plan.identity.opened_at - timedelta(microseconds=1))
    equal_adapter = LifecycleProductionAdapter(equal_registry)
    equal_token = equal_adapter.prepare_closed_transport_publication(plan)
    with equal_adapter.claimed_closed_transport_publication(equal_token) as claimed:
        with pytest.raises(StateError, match="claimed closed-transport"):
            equal_registry.advance_watermark(plan.identity.opened_at)
        receipt = claimed.commit_no_fail()
    assert receipt.transport.closed_at == plan.identity.close_deadline


def test_claimed_transport_fences_earlier_hold_time_before_transport_open() -> None:
    """A hold earlier than transport open participates in the claimed watermark fence."""

    registry = LifecycleRegistry(shard_count=8)
    process = _register_source_process(registry, object_id="early-hold-process")
    hold_time = _OPENED_AT - timedelta(microseconds=500)
    registry.advance_watermark(hold_time - timedelta(microseconds=1))
    adapter = LifecycleProductionAdapter(registry)
    plan = closed_transport_publication_plan(
        transaction=_transaction(stable_id="early-hold-transport", zeek_uid="CearlyHold"),
        authority_hostname="CLIENT-01",
        src_hostname="CLIENT-01",
        dst_hostname="SERVER-01",
        action_id="early-hold-action",
    )
    hold = _transport_hold(process, acquired_at=hold_time, hold_id="early-transport-hold")
    token = adapter.prepare_closed_transport_publication(plan, process_holds=(hold,))
    assert token.request.linearization_time == hold_time

    with adapter.claimed_closed_transport_publication(token) as claimed:
        assert registry.advance_watermark(token.expected_watermark) == ()
        with pytest.raises(StateError, match="claimed closed-transport"):
            registry.advance_watermark(hold_time)
        receipt = claimed.commit_no_fail()
    assert receipt.process_holds == (hold,)


def test_terminal_transport_retry_requires_every_requested_prior_primitive() -> None:
    """A terminal transport cannot be healed with new starts, holds, or binding rows."""

    registry = LifecycleRegistry(shard_count=8)
    adapter = LifecycleProductionAdapter(registry)
    transaction = _transaction(stable_id="partial-terminal", zeek_uid="CpartialTerminal")
    unbound = closed_transport_publication_plan(
        transaction=transaction,
        authority_hostname="CLIENT-01",
        src_hostname="CLIENT-01",
        dst_hostname="SERVER-01",
        action_id="partial-terminal-action",
    )
    adapter.publish_closed_transport(unbound)
    before = registry.census()
    session = SessionLifecycleIdentity(
        hostname="SERVER-01",
        object_id="partial-terminal-session",
        logon_id="0x8181",
        principal="analyst",
        session_kind="rdp",
        started_at=_OPENED_AT + timedelta(seconds=1),
        session_id=8,
    )
    members = _staged_start_members(session)
    shell = members[-1].request
    assert isinstance(shell, LifecycleProcessStartRequest)
    hold = LifecycleHold(
        hold_id="partial-terminal-hold",
        subject=shell.identity.ref,
        acquired_at=shell.identity.started_at,
        hold_until=unbound.identity.close_deadline,
        action_id="partial-terminal-hold-action",
        reason="canonical_transport_close",
    )
    bound = closed_transport_publication_plan(
        transaction=transaction,
        authority_hostname="CLIENT-01",
        src_hostname="CLIENT-01",
        dst_hostname="SERVER-01",
        session_object_id=session.object_id,
        bound_at=session.started_at,
        action_id="partial-terminal-action",
    )

    with pytest.raises(StateError, match="Terminal transport retry|close barrier"):
        adapter.prepare_closed_transport_publication(
            bound,
            start_members=members,
            process_holds=(hold,),
        )

    after = registry.census()
    assert after.session_entries == before.session_entries == 0
    assert after.process_entries == before.process_entries == 0
    assert after.transport_entries == before.transport_entries == 1
    assert after.transport_session_bindings == before.transport_session_bindings == 0
    assert after.holds == before.holds == 0
    assert adapter.closed_transport_preparation_census().reservations == 0


def test_terminal_transport_only_rejects_new_hold_or_binding() -> None:
    """Terminal idempotence cannot append either omitted primitive after the fact."""

    hold_registry = LifecycleRegistry(shard_count=8)
    hold_adapter = LifecycleProductionAdapter(hold_registry)
    process = _register_source_process(hold_registry, object_id="terminal-hold-owner")
    hold_transaction = _transaction(
        stable_id="terminal-before-hold",
        zeek_uid="CterminalBeforeHold",
    )
    hold_plan = closed_transport_publication_plan(
        transaction=hold_transaction,
        authority_hostname="CLIENT-01",
        src_hostname="CLIENT-01",
        dst_hostname="SERVER-01",
        action_id="terminal-before-hold-action",
    )
    hold_adapter.publish_closed_transport(hold_plan)
    before_hold = hold_registry.census()
    with pytest.raises(StateError, match="new process holds"):
        hold_adapter.prepare_closed_transport_publication(
            hold_plan,
            process_holds=(_transport_hold(process, hold_id="late-terminal-hold"),),
        )
    after_hold = hold_registry.census()
    assert after_hold.holds == before_hold.holds == 0
    assert after_hold.transitions == before_hold.transitions

    binding_registry, session = _registry_with_target_session()
    binding_adapter = LifecycleProductionAdapter(binding_registry)
    binding_transaction = _transaction(
        stable_id="terminal-before-binding",
        zeek_uid="CterminalBeforeBinding",
    )
    unbound = closed_transport_publication_plan(
        transaction=binding_transaction,
        authority_hostname="CLIENT-01",
        src_hostname="CLIENT-01",
        dst_hostname="SERVER-01",
        action_id="terminal-before-binding-action",
    )
    binding_adapter.publish_closed_transport(unbound)
    before_binding = binding_registry.census()
    bound = closed_transport_publication_plan(
        transaction=binding_transaction,
        authority_hostname="CLIENT-01",
        src_hostname="CLIENT-01",
        dst_hostname="SERVER-01",
        session_object_id=session.object_id,
        bound_at=session.started_at,
        action_id="terminal-before-binding-action",
    )
    with pytest.raises(StateError, match="close barrier|exact closed session binding"):
        binding_adapter.prepare_closed_transport_publication(bound)
    after_binding = binding_registry.census()
    assert (
        after_binding.transport_session_bindings == before_binding.transport_session_bindings == 0
    )
    assert after_binding.transitions == before_binding.transitions


def test_full_terminal_transport_retry_proves_exact_starts_holds_and_binding() -> None:
    """A complete exact retry returns the same authenticated receipt without new rows."""

    registry, adapter, plan, members, holds, token = _prepared_staged_transport_with_hold(
        stable_id="complete-terminal"
    )
    with adapter.claimed_closed_transport_publication(token) as claimed:
        first = claimed.commit_no_fail()
    before = registry.census()
    retry = adapter.prepare_closed_transport_publication(
        plan,
        start_members=members,
        process_holds=holds,
    )
    with adapter.claimed_closed_transport_publication(retry) as claimed:
        second = claimed.commit_no_fail()

    assert second == first
    assert registry.census() == before
    assert adapter.authenticates_closed_transport_publication_receipt(
        second,
        plan=plan,
        start_members=members,
        process_holds=holds,
    )


def test_prepared_closed_transport_exact_reservations_block_conflicts_not_disjoint_owners() -> None:
    """Prepared exact keys reject collisions while another host can commit during an open claim."""

    registry = LifecycleRegistry(shard_count=8)
    adapter = LifecycleProductionAdapter(registry)
    first_plan = closed_transport_publication_plan(
        transaction=_transaction(stable_id="reserved-transport", zeek_uid="Creserved"),
        authority_hostname="CLIENT-A",
        src_hostname="CLIENT-A",
        dst_hostname="SERVER-A",
        action_id="reserved-action",
    )
    first_token = adapter.prepare_closed_transport_publication(first_plan)
    conflicting = closed_transport_publication_plan(
        transaction=_transaction(stable_id="reserved-transport", zeek_uid="Cother"),
        authority_hostname="CLIENT-B",
        src_hostname="CLIENT-B",
        dst_hostname="SERVER-B",
        action_id="conflicting-action",
    )
    with pytest.raises(StateError, match="prepared closed-transport"):
        adapter.prepare_closed_transport_publication(conflicting)

    second_plan = closed_transport_publication_plan(
        transaction=_transaction(stable_id="disjoint-transport", zeek_uid="Cdisjoint"),
        authority_hostname="CLIENT-B",
        src_hostname="CLIENT-B",
        dst_hostname="SERVER-B",
        action_id="disjoint-action",
    )
    second_token = adapter.prepare_closed_transport_publication(second_plan)
    with adapter.claimed_closed_transport_publication(first_token) as first_claim:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(
                lambda: _commit_closed_transport_token(adapter, second_token),
            )
            second_receipt = future.result(timeout=2)
        first_receipt = first_claim.commit_no_fail()
    assert first_receipt.transport.identity == first_plan.identity
    assert second_receipt.transport.identity == second_plan.identity


def _commit_closed_transport_token(adapter: LifecycleProductionAdapter, token: object) -> object:
    with adapter.claimed_closed_transport_publication(token) as claimed:
        return claimed.commit_no_fail()


def test_prepared_closed_transport_reverse_cross_partition_batches_do_not_deadlock() -> None:
    """Opposite authority/session host pairs use one deterministic partition lock order."""

    registry = LifecycleRegistry(shard_count=8)
    adapter = LifecycleProductionAdapter(registry)

    def prepared_pair(ordinal: int) -> tuple[object, object]:
        session_host = "HOST-B" if ordinal == 0 else "HOST-A"
        authority_host = "HOST-A" if ordinal == 0 else "HOST-B"
        session = SessionLifecycleIdentity(
            hostname=session_host,
            object_id=f"reverse-session-{ordinal}",
            logon_id=f"0x7{ordinal}",
            principal="operator",
            session_kind="ssh",
            started_at=_OPENED_AT + timedelta(seconds=1),
        )
        members = _staged_start_members(session)
        transaction = _transaction(
            stable_id=f"reverse-transport-{ordinal}",
            zeek_uid=f"Creverse{ordinal}",
        )
        plan = closed_transport_publication_plan(
            transaction=transaction,
            authority_hostname=authority_host,
            src_hostname=authority_host,
            dst_hostname=session_host,
            session_object_id=session.object_id,
            bound_at=session.started_at,
            action_id=f"reverse-action-{ordinal}",
        )
        return adapter.prepare_closed_transport_publication(plan, start_members=members), plan

    first, first_plan = prepared_pair(0)
    second, second_plan = prepared_pair(1)
    with ThreadPoolExecutor(max_workers=2) as pool:
        receipts = tuple(
            pool.map(lambda token: _commit_closed_transport_token(adapter, token), (first, second))
        )
    assert {receipt.transport.identity for receipt in receipts} == {
        first_plan.identity,
        second_plan.identity,
    }


def test_prepared_service_publication_is_atomic_typed_and_idempotent() -> None:
    """Schedule service and PID 600 binding appear together or not at all."""

    registry = LifecycleRegistry(shard_count=8)
    process = ProcessLifecycleIdentity(
        hostname="SERVER-01",
        object_id="schedule-process-object",
        pid=600,
        started_at=_OPENED_AT,
        image=r"C:\Windows\System32\svchost.exe",
        role="service_host",
    )
    registry.register_process(
        process,
        token=ProcessTokenIdentity(principal=r"NT AUTHORITY\SYSTEM", logon_id="0x3e7"),
        membership=LifecycleMembership(
            owner_kind="boot",
            owner_object_id=process.object_id,
        ),
        action_id="schedule-process-start",
        transition_id="schedule-process-transition",
    )
    deployment = CompiledServiceDeploymentIdentity(
        hostname="SERVER-01",
        service_id="windows-service-schedule",
    )
    base = builtin_service_publication_plan(
        hostname="SERVER-01",
        logical_service_id="windows-service-schedule",
        canonical_name="Schedule",
        boot_time=_OPENED_AT - timedelta(hours=1),
        started_at=_OPENED_AT + timedelta(seconds=1),
        deployment_identity=deployment,
    )
    binding = ServiceProcessBindingIdentity(
        binding_id="schedule-pid600-binding",
        service_object_id=base.instance_identity.object_id,
        process_object_id=process.object_id,
        bound_at=base.instance_identity.started_at,
        role="service_host",
        action_id=base.action_id,
    )
    plan = replace(base, process_bindings=(binding,))
    adapter = LifecycleProductionAdapter(registry)

    token = adapter.prepare_service_publication(plan)
    assert adapter.authenticates_service_admission_token(token, plan=plan)
    adapter.cancel_service_publication(token)
    assert registry.get_service_instance(plan.instance_identity.object_id) is None
    assert registry.service_process_binding(binding.binding_id) is None

    token = adapter.prepare_service_publication(plan)
    with adapter.claimed_service_publication(token) as prepared:
        first_receipt = prepared.commit_no_fail()
    token = adapter.prepare_service_publication(plan)
    with adapter.claimed_service_publication(token) as prepared:
        second_receipt = prepared.commit_no_fail()

    assert adapter.authenticates_service_publication_receipt(first_receipt, plan=plan)
    assert adapter.authenticates_service_publication_receipt(second_receipt, plan=plan)
    service, bindings = first_receipt.service, first_receipt.bindings
    assert (second_receipt.service, second_receipt.bindings) == (service, bindings)
    assert service.logical_identity.deployment_identity == deployment
    assert service.logical_identity.deployment_service_id == deployment.deployment_service_id
    assert bindings == (registry.service_process_binding(binding.binding_id),)
    census = registry.census()
    assert census.service_instance_entries == 1
    assert census.service_process_bindings == 1
    assert census.active_service_process_bindings == 1


def test_prepared_service_binding_rejection_leaves_no_service_row() -> None:
    """A missing exact worker rejects before logical or instance publication."""

    registry = LifecycleRegistry(shard_count=8)
    base = builtin_service_publication_plan(
        hostname="SERVER-01",
        logical_service_id="windows-service-schedule",
        canonical_name="Schedule",
        boot_time=_OPENED_AT - timedelta(hours=1),
        started_at=_OPENED_AT + timedelta(seconds=1),
    )
    binding = ServiceProcessBindingIdentity(
        binding_id="missing-schedule-binding",
        service_object_id=base.instance_identity.object_id,
        process_object_id="missing-process",
        bound_at=base.instance_identity.started_at,
        role="service_host",
        action_id=base.action_id,
    )
    plan = replace(base, process_bindings=(binding,))
    adapter = LifecycleProductionAdapter(registry)

    with pytest.raises(StateError, match="Unknown process lifecycle object"):
        adapter.prepare_service_publication(plan)

    assert registry.get_service_instance(plan.instance_identity.object_id) is None
    assert registry.service_process_binding(binding.binding_id) is None
