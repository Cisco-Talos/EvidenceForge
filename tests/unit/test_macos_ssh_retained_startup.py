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
        startup_request=request,
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
    return state, dispatcher, emitter, executor, continuation, request


@pytest.mark.parametrize("failed_phase", list(range(1, 12)))
def test_retained_startup_rejects_checkpoint_and_recovers_each_lost_phase(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failed_phase: int
) -> None:
    from evidenceforge.generation.checkpoints.activity_head import _capture_ssh_lifecycles
    from evidenceforge.generation.checkpoints.errors import CheckpointError
    from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter

    state, dispatcher, emitter, executor, continuation, request = _close_fixture(tmp_path)
    prepared = continuation.prepared
    with pytest.raises(CheckpointError, match="unfinished receiver startup"):
        _capture_ssh_lifecycles(executor)
    original = ExternalSortedLineWriter._commit_exact_row
    count = 0

    def lose_return(writer: ExternalSortedLineWriter, *args: object) -> None:
        nonlocal count
        original(writer, *args)
        count += 1
        if count == failed_phase:
            raise RuntimeError("injected retained startup lost return")

    monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", lose_return)
    with pytest.raises(RuntimeError, match="retained startup lost return"):
        prepared.drain_receiver_startup(executor)
    coordinator = prepared._startup._coordinator
    with pytest.raises(CheckpointError, match="unfinished receiver startup"):
        _capture_ssh_lifecycles(executor)
    from evidenceforge.generation.activity.generator import ActivityGenerator

    ActivityGenerator.finalize_ssh_session_lifecycles(executor, _START + timedelta(seconds=1))
    assert executor._pending_ssh_session_closures == [continuation]
    assert prepared._startup._coordinator is coordinator
    assert coordinator.completed_phases == 11
    assert (
        state.get_session(request.receiver.logon_id).session_shell_pid
        == coordinator.result.shell.pid
    )
    before = state.materialization_version
    prepared.drain_receiver_startup(executor)
    assert state.materialization_version == before
    assert _capture_ssh_lifecycles(executor)[0][27][0] == "macos-v1"
    dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()


@pytest.mark.parametrize("damage", ["shell_role", "audit", "root_image", "platform"])
def test_restored_mac_startup_requires_canonical_graph_proof(tmp_path: Path, damage: str) -> None:
    from evidenceforge.generation.checkpoints.activity_head import (
        _capture_ssh_lifecycles,
        _restore_ssh_lifecycles,
    )
    from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError
    from tests.unit.test_macos_ssh_close_execution import _close_fixture as completed_fixture

    state, _, emitter, executor, continuation, roles = completed_fixture(tmp_path)
    rows = _capture_ssh_lifecycles(executor)
    executor._pending_ssh_session_closures.clear()
    executor._ssh_close_journal_capacity = 16
    session = state.get_session(continuation.plan.logon_id)
    if damage == "shell_role":
        session.session_shell_pid = 0
    elif damage == "audit":
        session.audit_origin = None
    elif damage == "root_image":
        state.get_process(
            roles.privileged_receiver.hostname, roles.privileged_receiver.pid
        ).image = "/usr/bin/other"
    else:
        state._pid_os[session.system] = "linux"
    with pytest.raises(CheckpointCorruptionError, match="application authority"):
        _restore_ssh_lifecycles(executor, rows)
    assert not executor._pending_ssh_session_closures
    emitter.close()


@pytest.mark.parametrize("damage", ["phase", "image", "receiver"])
def test_retained_startup_rejects_changed_precommit_facts(tmp_path: Path, damage: str) -> None:
    from evidenceforge.models.exceptions import StateError

    _, _, emitter, _, continuation, request = _close_fixture(tmp_path)
    close_plan = continuation.plan
    if damage == "phase":
        times = list(request.phase_times)
        times[6] += timedelta(microseconds=1)
        request = replace(request, phase_times=tuple(times))
    elif damage == "image":
        close_plan = replace(
            close_plan,
            auth_state=replace(close_plan.auth_state, initial_receiver_image="/usr/bin/other"),
        )
    else:
        request = replace(request, receiver=replace(request.receiver, logon_id="foreign"))
    old = continuation.prepared
    with pytest.raises(StateError, match="exact close facts"):
        _PreparedSshCloseContinuation(
            plan=close_plan,
            identity_capture=old.identity_capture,
            dispatcher_owner=old.dispatcher_owner,
            ecar_owner=old.ecar_owner,
            zeek_owner=old.zeek_owner,
            ssh_manager_owner=old.ssh_manager_owner,
            application_registry_owner=old.application_registry_owner,
            startup_request=request,
        )
    emitter.close()


def test_retained_startup_requires_bound_transport_before_mutation(tmp_path: Path) -> None:
    from evidenceforge.models.exceptions import StateError

    state, _, emitter, executor, continuation, request = _close_fixture(tmp_path)
    old = continuation.prepared
    prepared = _PreparedSshCloseContinuation(
        plan=old.plan,
        identity_capture=old.identity_capture,
        dispatcher_owner=old.dispatcher_owner,
        ecar_owner=old.ecar_owner,
        zeek_owner=old.zeek_owner,
        ssh_manager_owner=old.ssh_manager_owner,
        application_registry_owner=old.application_registry_owner,
        startup_request=request,
    )
    version = state.materialization_version
    with pytest.raises(StateError, match="bound committed transport"):
        prepared.drain_receiver_startup(executor)
    assert state.materialization_version == version
    assert prepared._startup._coordinator is None
    emitter.close()


def test_retained_mac_startup_without_endpoint_sink_keeps_canonical_behavior(
    tmp_path: Path,
) -> None:
    from evidenceforge.models.exceptions import StateError

    state, dispatcher, emitter, executor, continuation, _ = _close_fixture(
        tmp_path, collected=False
    )
    prepared = continuation.prepared
    before = state.materialization_version
    dispatcher.emitters["ecar"] = emitter
    with pytest.raises(StateError, match="original eCAR/Zeek"):
        prepared.drain_receiver_startup(executor)
    assert state.materialization_version == before
    del dispatcher.emitters["ecar"]
    prepared.drain_receiver_startup(executor)
    assert prepared._startup._coordinator.result is not None
    bundle = continuation.materialize_bundle(executor)
    transport = continuation.materialize_state()
    bundle._dispatch_session_close_lifecycle(
        transport,
        continuation.materialize_event(transport),
        continuation.plan.auth_state,
        continuation=continuation,
    )
    assert state.get_session(continuation.plan.logon_id) is None
    prepared.require_application_session_retired()
    emitter.close()
    assert not any(path.read_text() for path in tmp_path.rglob("ecar.json"))
