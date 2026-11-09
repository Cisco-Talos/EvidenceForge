# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Mac receiver bootstrap activity does not consume its future transport lifetime."""

from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.contexts import HostContext
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.generation.actions.command_effects import ExecutionEffectAuditCounter
from evidenceforge.generation.actions.network_connection import DeferredSshApplicationIntent
from evidenceforge.generation.actions.posix_process import (
    process_exec_occurrence,
    process_exit_occurrence,
)
from evidenceforge.generation.application_channels import ApplicationChannelRegistry
from evidenceforge.generation.deferred_session_composition import DeferredSessionKind
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.generation.ssh_channels import SshApplicationChannelManager, SshOperationKind
from evidenceforge.models.exceptions import EventContractError, StateError
from tests.unit.test_deferred_session_composition import _END, _START, _bound_authority, _fixture
from tests.unit.test_process_exit_projection import _prepare


def test_mac_receiver_executes_during_transport_while_its_lifetime_remains_held() -> None:
    fixture = _fixture(DeferredSessionKind.SSH, macos_receiver=True)
    authority = _bound_authority(fixture)
    authority.materialize_prepared_deferred_session_transaction(
        fixture.issue(),
        fixture.coordinator,
        fixture.owner_rng,
    )
    receiver = fixture.process_plan.identity
    close_at = fixture.prepared_root.transaction.closed_at
    assert (
        fixture.state.get_process(receiver.hostname, receiver.pid).last_activity_time
        == receiver.started_at
    )
    assert authority.process_hold_until(receiver.hostname, receiver.pid) == close_at
    assert fixture.state.get_session(receiver.logon_id).last_activity_time == close_at
    dispatcher = EventDispatcher(
        fixture.state,
        {},
        lifecycle_shadow=LifecycleShadow(fixture.state, fixture.lifecycle_registry),
        enforce_lifecycle_authority=True,
    )
    dispatcher.bind_lifecycle_authority(authority)
    dispatcher.bind_execution_effect_audit(ExecutionEffectAuditCounter())
    host = HostContext(
        hostname="DB-01",
        ip="192.0.2.20",
        os="macOS 26",
        os_category="macos",
        system_type="workstation",
    )
    execution_at = receiver.started_at + timedelta(milliseconds=1)
    builder = fixture.state.begin_action_cohort_materialization()
    after = builder.execute_process(
        receiver,
        image="/usr/sbin/sshd",
        command_line="/usr/sbin/sshd -i",
        executed_at=execution_at,
    )
    event = process_exec_occurrence(
        host=host, before=receiver, after=after, integrity_level="System"
    )
    dispatcher.publish_prepared_action_cohort_batch(
        _prepare(
            dispatcher,
            builder.seal(),
            event,
            exact=True,
            root=f"process-exec:{after.execution_id}",
        )
    )
    assert fixture.state.get_process_identity(receiver.hostname, receiver.pid) == after
    assert authority.process_hold_until(receiver.hostname, receiver.pid) == close_at
    early_close = execution_at + timedelta(milliseconds=1)
    builder = fixture.state.begin_action_cohort_materialization()
    builder.terminate_process(after, end_time=early_close)
    event = process_exit_occurrence(
        host=host, process=after, timestamp=early_close, integrity_level="System"
    )
    with pytest.raises((StateError, EventContractError)):
        dispatcher.publish_prepared_action_cohort_batch(_prepare(dispatcher, builder.seal(), event))
    assert fixture.state.get_process_identity(receiver.hostname, receiver.pid) == after


@pytest.mark.parametrize("macos", [False, True])
def test_ssh_application_intent_uses_authenticated_batch_activity_and_full_hold(
    macos: bool,
) -> None:
    fixture = _fixture(DeferredSessionKind.SSH, macos_receiver=macos, with_application=False)
    registry = ApplicationChannelRegistry(window_start=_START, window_end=_END, shard_count=4)
    manager = SshApplicationChannelManager(
        application_registry=registry, window_start=_START, window_end=_END
    )
    receiver = fixture.process_plan.identity
    session = fixture.session_plan.identity
    transaction = fixture.prepared_root.transaction
    intent = DeferredSshApplicationIntent(
        manager=manager,
        target_hostname=session.hostname,
        principal=session.principal,
        client_identity="source",
        client_session_object_id="source-session",
        receiver_identity=receiver,
        receiver_state_session_identity=session,
        source_identity=None,
        source_session_object_id="",
        source_state_session_identity=None,
        ready_at=fixture.binding_time,
        auth_method="publickey",
        operation_kind=SshOperationKind.SHELL,
        semantic_operation_id="synthetic-session-operation",
    )
    _, processes, sessions, holds = intent.prepare(
        session,
        transaction,
        state_batch=fixture.prepared_root.state_plan.batch,
    )
    assert processes[0].activity_time == (receiver.started_at if macos else transaction.closed_at)
    assert sessions[0].activity_time == holds[0].hold_until == transaction.closed_at


def test_mac_startup_activity_exception_requires_exact_transport_member() -> None:
    fixture = _fixture(DeferredSessionKind.SSH, macos_receiver=True)
    batch = fixture.prepared_root.state_plan.batch
    receiver = fixture.process_plan.identity
    close_at = fixture.prepared_root.transaction.closed_at
    assert batch.process_hold_activity_time(receiver, close_at) == receiver.started_at
    for changed in (
        replace(receiver, principal="other"),
        replace(receiver, logon_id="different"),
        replace(receiver, credentials=None),
        replace(receiver, image="/usr/bin/other"),
    ):
        assert batch.process_hold_activity_time(changed, close_at) == close_at
    detached = replace(
        batch, _session_process_links=replace(batch._session_process_links, transport=-1)
    )
    assert detached.process_hold_activity_time(receiver, close_at) == close_at


@pytest.mark.parametrize("macos", [False, True])
def test_ssh_manager_retention_cannot_drift_from_lifecycle_hold(macos: bool) -> None:
    from evidenceforge.generation.deferred_session_composition import _validate_ssh_process_holds

    fixture = _fixture(DeferredSessionKind.SSH, macos_receiver=macos)
    transport = fixture.application_token.session.transport
    changed = replace(
        transport,
        receiver_process=replace(
            transport.receiver_process,
            required_until=transport.closes_at + timedelta(seconds=1),
        ),
    )
    with pytest.raises(StateError, match="retention deadlines disagree"):
        _validate_ssh_process_holds(
            fixture.prepared_root.state_plan.process_activity,
            changed,
            batch=fixture.prepared_root.state_plan.batch,
            lifecycle_holds=fixture.lifecycle_token.request.process_holds,
        )


def test_complete_mac_startup_composes_with_committed_transport_retention() -> None:
    from evidenceforge.generation.actions.macos_ssh_receiver import (
        MacosSshReceiverStartup,
        MacosSshReceiverStartupRequest,
    )
    from tests.unit.test_macos_service_drop import _account
    from tests.unit.test_macos_ssh_startup import _descriptor

    fixture = _fixture(DeferredSessionKind.SSH, macos_receiver=True, process_start_offset_ms=100)
    authority = _bound_authority(fixture)
    authority.materialize_prepared_deferred_session_transaction(
        fixture.issue(), fixture.coordinator, fixture.owner_rng
    )
    receiver = fixture.process_plan.identity
    dispatcher = EventDispatcher(
        fixture.state,
        {},
        lifecycle_shadow=LifecycleShadow(fixture.state, fixture.lifecycle_registry),
        enforce_lifecycle_authority=True,
    )
    dispatcher.bind_lifecycle_authority(authority)
    dispatcher.bind_execution_effect_audit(ExecutionEffectAuditCounter())
    request = MacosSshReceiverStartupRequest(
        receiver=receiver,
        service_account=replace(_account(), host=receiver.hostname),
        wrapper=_descriptor("macos-sshd-keygen-wrapper"),
        daemon=_descriptor("macos-sshd"),
        session_worker=_descriptor("macos-sshd-session"),
        authentication_worker=_descriptor("macos-sshd-auth"),
        shell=_descriptor("macos-zsh"),
        phase_times=tuple(
            _START + timedelta(milliseconds=offset)
            for offset in (102, 104, 106, 108, 110, 112, 115, 116, 117, 118, 119)
        ),
    )
    startup = MacosSshReceiverStartup(
        request,
        state=fixture.state,
        dispatcher=dispatcher,
        host=HostContext(
            hostname="DB-01",
            ip="192.0.2.20",
            os="macOS 26",
            os_category="macos",
            system_type="workstation",
        ),
    )
    while startup.result is None:
        startup.advance()
    assert startup.result.privileged_receiver.pid == receiver.pid
    assert startup.result.shell.principal == "analyst"
    assert startup.result.shell.credentials.audit_uid == 501
    assert (
        authority.process_hold_until(receiver.hostname, receiver.pid)
        == fixture.prepared_root.transaction.closed_at
    )
