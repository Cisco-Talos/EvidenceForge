# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Boot and SSH owners compose POSIX lifetimes without using login/audit IDs."""

from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest

from evidenceforge.events.identity import PosixProcessCredentials
from evidenceforge.generation.actions.macos_ssh_receiver import MacosSshReceiverStartup
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.engine.emitter_setup import EmitterSetupMixin
from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
from evidenceforge.generation.lifecycle_registry import LifecycleRegistry
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import System
from tests.unit.test_macos_ssh_process_graph import _bootstrap
from tests.unit.test_macos_ssh_startup import _request
from tests.unit.test_process_execution_state import _START


@pytest.mark.parametrize("direct", [False, True])
def test_boot_profiles_materialize_distinct_sessions_and_restore(direct: bool) -> None:
    state = StateManager()
    state.set_current_time(_START)
    engine = Mock(spec=EmitterSetupMixin)
    engine.state_manager = state
    system = System(hostname="MAC-BOOT", ip="192.0.2.44", os="macOS 26", type="workstation")
    spec = EmitterSetupMixin._build_macos_boot_host_spec(engine, system, _START)
    engine._build_macos_boot_host_spec.return_value = spec
    registry = LifecycleRegistry(shard_count=4)
    shadow = LifecycleShadow(state, registry)
    authority = GeneratorLifecycleAuthority(state, shadow, shard_count=4)
    if direct:
        pids: dict[str, int] = {}
        EmitterSetupMixin._seed_macos_process_tree(engine, system, pids)
        authority.bootstrap_active_state()
    else:
        builder = state.begin_materialization_batch()
        pids = EmitterSetupMixin._plan_boot_host_spec(builder, spec)
        before = state.materialization_digest()
        plan = builder.seal()
        assert state.materialization_digest() == before
        authority.materialize_batch(plan)
    assert pids["launchd"] == 1 and len(pids) > 3
    for pid in pids.values():
        process = state.get_process_identity(system.hostname, pid)
        group = process.job_control
        assert group.pgid == group.session.sid == pid
        assert group.leader_object_id == group.session.leader_object_id == process.object_id
        assert state.get_posix_group_members(group) == (process,)
        assert process.logon_id == "" and process.credentials.audit_uid is None
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    for pid in pids.values():
        process = state.get_process_identity(system.hostname, pid)
        assert restored.get_process_identity(system.hostname, pid) == process
        assert restored.get_posix_group_members(process.job_control) == (process,)


@pytest.mark.parametrize("batch", [False, True])
@pytest.mark.parametrize(
    "damage", ["pid", "missing_pid", "uid", "credentials", "platform", "group"]
)
def test_initial_session_requires_exact_privileged_mac_boot_owner(batch: bool, damage: str) -> None:
    state = StateManager()
    state.set_current_time(_START)
    owner = state.begin_materialization_batch() if batch else state
    method = owner.plan_process if batch else owner.plan_process_materialization
    fields = dict(
        system="MAC-BOOT",
        parent_pid=0,
        fixed_pid=1,
        image="/sbin/launchd",
        command_line="launchd",
        username="root",
        integrity_level="System",
        os_category="macos",
        credentials=PosixProcessCredentials(0, 0, 0, 0),
        new_posix_session=True,
    )
    if damage == "pid":
        fields["fixed_pid"] = 2
    elif damage == "missing_pid":
        fields["fixed_pid"] = None
    elif damage == "uid":
        fields["credentials"] = PosixProcessCredentials(501, 20, 501, 20)
    elif damage == "credentials":
        fields["credentials"] = None
    elif damage == "platform":
        fields["os_category"] = "linux"
    else:
        fields["new_posix_group"] = True
    before = state.materialization_digest()
    with pytest.raises(StateError):
        method(**fields)
    assert state.materialization_digest() == before


@pytest.mark.parametrize("collected", [False, True])
@pytest.mark.parametrize("failure", [None, "before", "after"])
def test_ssh_shell_session_transition_is_atomic_and_recoverable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, collected: bool, failure: str | None
) -> None:
    from evidenceforge.events.dispatcher import PreparedActionCohortCapability

    state, dispatcher, emitter, host, receiver = _bootstrap(
        tmp_path, collected, session_ownership=True
    )
    startup = MacosSshReceiverStartup(
        _request(receiver, session_ownership=True), state=state, dispatcher=dispatcher, host=host
    )
    for _ in range(10):
        startup.advance()
    shell = startup._shell
    assert shell.job_control == receiver.job_control
    at = startup._request.phase_times[10]
    if failure:
        original = PreparedActionCohortCapability.commit_no_fail

        def fail_once(capability: PreparedActionCohortCapability) -> None:
            if failure == "after":
                original(capability)
            raise RuntimeError("injected membership publication failure")

        monkeypatch.setattr(PreparedActionCohortCapability, "commit_no_fail", fail_once)
        before = state.materialization_digest()
        with pytest.raises(RuntimeError, match="membership publication"):
            startup.advance()
        assert startup.completed_phases == 10
        if failure == "before":
            assert state.materialization_digest() == before
        monkeypatch.setattr(PreparedActionCohortCapability, "commit_no_fail", original)
    startup.advance()
    assert startup.result is None
    group = startup._shell.job_control
    assert group.pgid == group.session.sid == shell.pid
    assert group != receiver.job_control
    assert (
        state.get_process_identity_by_object_id(
            shell.object_id, event_time=at - timedelta(microseconds=1)
        )
        == shell
    )
    result = startup.advance()
    assert result.shell.job_control == group
    assert result.authenticated_child.job_control == receiver.job_control
    assert result.privileged_receiver.job_control == receiver.job_control
    assert (
        result.shell.credentials.audit_session_id
        == result.privileged_receiver.credentials.audit_session_id
    )
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    assert restored.get_process_identity(host.hostname, shell.pid) == result.shell
    assert restored.get_posix_group_members(group) == (result.shell,)
    dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()
    rows = [line for path in tmp_path.rglob("ecar.json") for line in path.read_text().splitlines()]
    assert len(rows) == (12 if collected else 0)


def test_session_owning_startup_rejects_unknown_receiver_membership(tmp_path: Path) -> None:
    _, _, emitter, _, receiver = _bootstrap(tmp_path)
    with pytest.raises(StateError, match="known membership"):
        _request(receiver, session_ownership=True)
    legacy = _request(receiver)
    assert len(replace(legacy).phase_times) == 11
    emitter.close()


@pytest.mark.parametrize("damage", [None, "root", "parent", "shell", "inherited_shell"])
def test_checkpoint_restoration_proves_new_ssh_session_membership(
    tmp_path: Path, damage: str | None
) -> None:
    from evidenceforge.generation.actions.ssh_session import SshSessionActionBundle
    from evidenceforge.generation.checkpoints.activity_head import (
        _capture_ssh_lifecycles,
        _restore_ssh_lifecycles,
    )
    from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError
    from tests.unit.test_macos_ssh_receiver_planning import _mac_fixture

    fixture = _mac_fixture(tmp_path)
    executor = fixture.generator
    bundle = SshSessionActionBundle(replace(fixture.request(), emit_session_close=True), executor)
    transport = bundle._plan_transport(deferred_publication=True)
    prepared = bundle._prepare_deferred_open(transport)
    transaction = bundle._open_deferred_transport(transport, prepared)
    continuation = bundle._bind_deferred_close_continuation(prepared, transaction)
    executor._defer_ssh_session_close(continuation)
    continuation.prepared.drain_receiver_startup(executor)
    rows = _capture_ssh_lifecycles(executor)
    assert rows[0][27][0] == "macos-v2"
    session = fixture.state.get_session(continuation.plan.logon_id)
    root = fixture.state.get_process(session.system, session.transport_pid)
    shell = fixture.state.get_process(session.system, session.session_shell_pid)
    parent = fixture.state.get_process(session.system, shell.parent_pid)
    if damage == "root":
        root.job_control = None
    elif damage == "parent":
        parent.job_control = shell.job_control
    elif damage == "shell":
        shell.job_control = None
    elif damage == "inherited_shell":
        shell.job_control = root.job_control
    executor._pending_ssh_session_closures.clear()
    executor._ssh_close_journal_capacity = 16
    if damage:
        with pytest.raises(CheckpointCorruptionError, match="application authority"):
            _restore_ssh_lifecycles(executor, rows)
        assert not executor._pending_ssh_session_closures
    else:
        _restore_ssh_lifecycles(executor, rows)
        assert len(executor._pending_ssh_session_closures) == 1
        executor._finalize_exact_ssh_close_continuation(executor._pending_ssh_session_closures[0])
        assert fixture.state.get_session(session.logon_id) is None
    fixture.close_and_read()
