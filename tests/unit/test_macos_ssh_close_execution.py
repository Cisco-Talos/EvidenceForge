# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Mac close executor composes committed transport, startup and canonical closure."""

from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from threading import Lock
from types import SimpleNamespace

import pytest

from evidenceforge.events.contexts import HostContext
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.formats.loader import load_format
from evidenceforge.generation.actions.command_effects import ExecutionEffectAuditCounter
from evidenceforge.generation.actions.macos_ssh_receiver import (
    MacosSshReceiverStartup,
    MacosSshReceiverStartupRequest,
)
from evidenceforge.generation.actions.network_connection import NetworkConnectionIdentityCapture
from evidenceforge.generation.actions.ssh_session import (
    SshReceiverAuthentication,
    _PreparedSshCloseContinuation,
    _PreparedSshClosePlan,
    _ssh_receiver_process_terminate_time,
    _ssh_source_native_session_close_time,
    _SshCloseHostFacts,
    _SshCloseSystemFacts,
    _SshCloseUserFacts,
    _SshMacAuthState,
)
from evidenceforge.generation.deferred_session_composition import DeferredSessionKind
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.models.scenario import System, User
from tests.unit.test_deferred_session_composition import _END, _START, _bound_authority, _fixture
from tests.unit.test_macos_service_drop import _account
from tests.unit.test_macos_ssh_startup import _descriptor


def _close_fixture(tmp_path: Path, collected: bool = True) -> tuple:
    fixture = _fixture(DeferredSessionKind.SSH, macos_receiver=True, process_start_offset_ms=100)
    authority = _bound_authority(fixture)
    authority.materialize_prepared_deferred_session_transaction(
        fixture.issue(), fixture.coordinator, fixture.owner_rng
    )
    receiver = fixture.process_plan.identity
    state = fixture.state
    emitter = EcarEmitter(load_format("ecar"), tmp_path, threaded=True)
    dispatcher = EventDispatcher(
        state,
        {"ecar": emitter} if collected else {},
        output_start_time=None if collected else _END,
        lifecycle_shadow=LifecycleShadow(state, fixture.lifecycle_registry),
        enforce_lifecycle_authority=True,
        source_timing_planner=fixture.timing_planner,
    )
    dispatcher.bind_lifecycle_authority(authority)
    dispatcher.bind_execution_effect_audit(ExecutionEffectAuditCounter())
    host = HostContext(
        hostname="DB-01",
        ip="10.0.0.20",
        os="macOS 26",
        os_category="macos",
        system_type="workstation",
    )
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
    startup = MacosSshReceiverStartup(request, state=state, dispatcher=dispatcher, host=host)
    while startup.result is None:
        startup.advance()
    session = state.get_session_identity(receiver.logon_id)
    transaction = fixture.prepared_root.transaction
    auth = _SshMacAuthState(
        SshReceiverAuthentication(
            receiver.pid,
            session.session_id,
            _START + timedelta(milliseconds=101),
            _START + timedelta(milliseconds=115),
            _START + timedelta(milliseconds=115),
            fixture.binding_time,
        ),
        request.wrapper.image_path,
        request.session_worker.image_path,
    )
    logout = _ssh_source_native_session_close_time(
        target_hostname=host.hostname,
        username=session.principal,
        source_ip=transaction.src_ip,
        source_port=transaction.src_port,
        sshd_pid=receiver.pid,
        transport_close_time=transaction.closed_at,
    )
    root_end = _ssh_receiver_process_terminate_time(
        target_hostname=host.hostname,
        source_ip=transaction.src_ip,
        source_port=transaction.src_port,
        sshd_pid=receiver.pid,
        receiver_started_at=receiver.started_at,
        session_close_time=logout,
    )
    target = System(
        hostname=host.hostname,
        ip=host.ip,
        os=host.os,
        architecture="arm64",
        type="workstation",
        services=["ssh"],
    )
    plan = _PreparedSshClosePlan(
        continuation_id="synthetic-mac-close",
        username=session.principal,
        source_ip=transaction.src_ip,
        target_ip=host.ip,
        source_port=transaction.src_port,
        open_time=transaction.started_at,
        session_started_at=session.started_at,
        close_time=transaction.closed_at,
        source_terminate_time=None,
        receiver_started_at=receiver.started_at,
        receiver_terminate_time=root_end,
        session_close_time=logout,
        logind_remove_time=None,
        terminal_window_end=_END,
        action_source_deadline=None,
        session_object_id=session.object_id,
        logon_id=session.logon_id,
        session_id=session.session_id,
        session_lifecycle_group_id=session.lifecycle_group_id,
        session_logon_guid=session.logon_guid,
        session_parent_lifecycle_group_id=session.parent_lifecycle_group_id,
        user=_SshCloseUserFacts.capture(
            User(username="analyst", full_name="Synthetic Analyst", email="analyst@example.test")
        ),
        source_system=None,
        target_system=_SshCloseSystemFacts.capture(target),
        source_host=None,
        target_host=_SshCloseHostFacts.capture(host),
        source_identity=None,
        auth_state=auth,
        source_tag="synthetic-close-test",
    )
    capture = NetworkConnectionIdentityCapture()
    capture.publish(transaction, lifecycle_mode="deferred_session")
    manager = fixture.application_owner
    executor = SimpleNamespace(
        state_manager=state,
        dispatcher=dispatcher,
        _lifecycle_authority=authority,
        _source_timing_planner=dispatcher.source_timing_planner,
        timing_runtime=dispatcher.timing_runtime,
        _ssh_channel_manager=manager,
        _application_channel_registry=manager.application_registry,
    )
    # Compatibility-cache adoption is outside this close-owner test. State,
    # lifecycle, application retirement, timing and source sinks are real owners.
    executor.committed_process_events = []
    executor._commit_exact_ssh_source_process_termination = executor.committed_process_events.append
    prepared = _PreparedSshCloseContinuation(
        plan=plan,
        identity_capture=capture,
        dispatcher_owner=dispatcher,
        ecar_owner=emitter if collected else None,
        zeek_owner=None,
        ssh_manager_owner=manager,
        application_registry_owner=manager.application_registry,
    )
    continuation = prepared.bind(transaction)
    executor._pending_ssh_session_closures = [continuation]
    executor._ssh_close_journal_lock = Lock()
    return state, dispatcher, emitter, executor, continuation, startup.result


@pytest.mark.parametrize("collected", [False, True])
def test_mac_close_executor_retires_application_and_closes_receiver_graph(
    tmp_path: Path, collected: bool
) -> None:
    state, dispatcher, emitter, executor, continuation, roles = _close_fixture(tmp_path, collected)
    bundle = continuation.materialize_bundle(executor)
    transport = continuation.materialize_state()
    bundle._dispatch_session_close_lifecycle(
        transport,
        continuation.materialize_event(transport),
        continuation.plan.auth_state,
        continuation=continuation,
    )
    for identity in (roles.shell, roles.authenticated_child, roles.privileged_receiver):
        assert state.get_process(identity.hostname, identity.pid) is None
    assert state.get_session(continuation.plan.logon_id) is None
    continuation.prepared.require_application_session_retired()
    assert "logind-remove" not in continuation.prepared._progress._completed
    assert len(executor.committed_process_events) == 3
    dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()


@pytest.mark.parametrize("failed_row", [1, 2, 3, 4])
@pytest.mark.parametrize("after_write", [False, True])
def test_mac_close_retries_lost_sink_return_without_repeating_state_or_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failed_row: int, after_write: bool
) -> None:
    import json

    from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter

    state, dispatcher, emitter, executor, continuation, roles = _close_fixture(tmp_path)
    bundle = continuation.materialize_bundle(executor)
    transport = continuation.materialize_state()
    original = ExternalSortedLineWriter._commit_exact_row
    count = 0

    def lose_return(writer: ExternalSortedLineWriter, *args: object) -> None:
        nonlocal count
        count += 1
        if count == failed_row and not after_write:
            raise RuntimeError("injected Mac close lost return")
        original(writer, *args)
        if count == failed_row:
            raise RuntimeError("injected Mac close lost return")

    monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", lose_return)
    with pytest.raises(RuntimeError, match="Mac close lost return"):
        bundle._dispatch_session_close_lifecycle(
            transport,
            continuation.materialize_event(transport),
            continuation.plan.auth_state,
            continuation=continuation,
        )
    from evidenceforge.generation.checkpoints.activity_head import _capture_ssh_lifecycles
    from evidenceforge.generation.checkpoints.errors import CheckpointError

    with pytest.raises(CheckpointError, match="partially published"):
        _capture_ssh_lifecycles(executor)
    bundle._dispatch_session_close_lifecycle(
        transport,
        continuation.materialize_event(transport),
        continuation.plan.auth_state,
        continuation=continuation,
    )
    assert state.get_session(continuation.plan.logon_id) is None
    for identity in (roles.shell, roles.authenticated_child, roles.privileged_receiver):
        assert state.get_process(identity.hostname, identity.pid) is None
    continuation.prepared.require_application_session_retired()
    dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()
    rows = [
        json.loads(line)
        for path in tmp_path.rglob("ecar.json")
        for line in path.read_text().splitlines()
    ]
    assert len([row for row in rows if row["action"] == "LOGOUT"]) == 1
    for identity in (roles.shell, roles.authenticated_child, roles.privileged_receiver):
        assert (
            len(
                [
                    row
                    for row in rows
                    if row["action"] == "TERMINATE" and row["objectID"] == identity.object_id
                ]
            )
            == 1
        )


@pytest.mark.parametrize("same_image", [False, True])
def test_mac_close_rejects_unpublished_receiver_execution(tmp_path: Path, same_image: bool) -> None:
    from evidenceforge.models.exceptions import StateError

    state, _, emitter, executor, continuation, roles = _close_fixture(tmp_path)
    before = roles.privileged_receiver
    builder = state.begin_action_cohort_materialization()
    after = builder.execute_process(
        before,
        image=before.image if same_image else "/usr/bin/other",
        command_line="synthetic-unpublished-exec",
        executed_at=before.execution_started_at + timedelta(seconds=1),
    )
    state.materialize_action_cohort(builder.seal())
    bundle = continuation.materialize_bundle(executor)
    with pytest.raises(StateError, match="live receiver identity"):
        bundle._plan_exact_receiver_descendant_terminations(
            continuation.materialize_state(), continuation.plan.auth_state, continuation
        )
    assert state.get_process_identity(after.hostname, after.pid) == after
    assert state.get_session(continuation.plan.logon_id) is not None
    emitter.close()


def test_mac_close_journal_round_trip_rebinds_typed_facts_and_executes(tmp_path: Path) -> None:
    from evidenceforge.generation.checkpoints.activity_head import (
        _capture_ssh_lifecycles,
        _restore_ssh_lifecycles,
    )
    from evidenceforge.generation.checkpoints.packed import dumps, loads

    state, _, emitter, executor, original, roles = _close_fixture(tmp_path)
    rows = _capture_ssh_lifecycles(executor)
    assert rows[0][27][0] == "macos-v1"
    assert rows[0][12] is None
    executor._pending_ssh_session_closures.clear()
    executor._ssh_close_journal_capacity = 16
    _restore_ssh_lifecycles(executor, loads(dumps(rows)))
    restored = executor._pending_ssh_session_closures[0]
    assert restored is not original
    assert restored.plan == original.plan
    assert _capture_ssh_lifecycles(executor) == rows
    bundle = restored.materialize_bundle(executor)
    transport = restored.materialize_state()
    bundle._dispatch_session_close_lifecycle(
        transport,
        restored.materialize_event(transport),
        restored.plan.auth_state,
        continuation=restored,
    )
    assert state.get_session(restored.plan.logon_id) is None
    assert (
        state.get_process(roles.privileged_receiver.hostname, roles.privileged_receiver.pid) is None
    )
    restored.prepared.require_application_session_retired()
    emitter.close()
