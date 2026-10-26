# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented SSH channel pipes qualify command exec, never helper FD inventories."""

from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.events.identity import PosixProcessCredentials, ProcessIdentity
from evidenceforge.formats.macos_endpoint_security import decode_endpoint_security_record
from evidenceforge.generation.activity.macos_execution_metadata import (
    load_macos_execution_metadata_profile,
)
from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError
from evidenceforge.generation.checkpoints.packed import dumps, loads
from evidenceforge.generation.checkpoints.state_manager_head import (
    StateManagerParticipant,
    _capture_head,
    _restore_head,
)
from evidenceforge.generation.checkpoints.state_values import decode_state_value, encode_state_value
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.generation.state_manager import (
    MaterializationBatchBuilder,
    SessionMaterializationPlan,
    StateManager,
)
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.rng import generation_seed_scope, reset_thread_rng
from tests.support.macos_ssh import macos_ssh_scenario
from tests.unit.test_macos_audit_sessions import _START, _commit, _start


def _plan(
    state: StateManager, *, seconds: int = 0
) -> tuple[MaterializationBatchBuilder, SessionMaterializationPlan]:
    batch = state.begin_materialization_batch()
    session = batch.plan_session(
        username="casey",
        system="MAC-A",
        logon_type=10,
        source_ip="192.0.2.10",
        session_kind="ssh",
        auth_protocol="ssh",
        effective_uid=501,
        effective_gid=20,
        start_time=_START + timedelta(seconds=seconds),
        source_ready_time=_START + timedelta(seconds=seconds + 2),
        network_close_time=_START + timedelta(minutes=10),
    )
    session = batch.enrich_macos_audit_session(
        session, audit_uid=501, authenticated_at=_START + timedelta(seconds=seconds + 1)
    )
    session = batch.enrich_macos_ssh_command_streams(session, first_pipe_id=1_000_000)
    return batch, session


def _ready(*, pty: bool = False) -> tuple[StateManager, ProcessIdentity]:
    state = StateManager()
    root = state.plan_process_materialization(
        system="MAC-A",
        parent_pid=0,
        fixed_pid=1,
        image="/sbin/launchd",
        command_line="/sbin/launchd",
        username="root",
        integrity_level="System",
        os_category="macos",
        start_time=_START - timedelta(minutes=1),
        credentials=PosixProcessCredentials(0, 0, 0, 0, 2**32 - 1, 0),
        new_posix_session=True,
        macos_terminal="absent",
    )
    state.materialize_process(root)
    batch, session = _plan(state)
    origin = session.audit_origin
    shell = batch.plan_process(
        system="MAC-A",
        parent_pid=1,
        image="/bin/zsh",
        command_line="-zsh",
        arguments=("-zsh",),
        username="casey",
        integrity_level="Medium",
        os_category="macos",
        start_time=_START + timedelta(seconds=2),
        logon_id=session.identity.logon_id,
        session_plan=session,
        require_session=True,
        credentials=PosixProcessCredentials(
            501, 501, 20, 20, origin.audit_uid, origin.audit_session_id
        ),
        new_posix_session=True,
        macos_terminal=load_macos_execution_metadata_profile().terminal if pty else "absent",
    )
    batch.bind_session_processes(session, shell_plan=shell, process_tree_root_plan=shell)
    _commit(state, batch)
    return state, shell.identity


def test_channel_pipe_allocation_is_independent_transactional_and_checkpointed() -> None:
    state = StateManager()
    _start(state)
    before = state.materialization_digest()
    batch, session = _plan(state)
    streams = session.ssh_command_streams
    assert streams is not None
    assert tuple(item.fd for item in streams.bindings) == (0, 1, 2)
    assert tuple(item.native_pipe_id for item in streams.bindings) == (
        1_000_000,
        1_000_001,
        1_000_002,
    )
    assert len({item.object_id for item in streams.bindings}) == 3
    assert state.materialization_digest() == before
    with state.prepared_materialization_batch(batch.seal()) as prepared:
        prepared.apply_provisional()
        assert state._macos_pipe_counters == {"MAC-A": (1_000_000, 1_000_002)}
    assert state.materialization_digest() == before
    batch, retry = _plan(state)
    assert retry.ssh_command_streams == streams
    _commit(state, batch)
    participant = StateManagerParticipant(state)
    checkpoint = participant.prepare_checkpoint(0)
    participant.checkpoint_committed(0)
    restored = StateManager()
    StateManagerParticipant(restored).restore_checkpoint(
        checkpoint.head.payload, tuple(segment.payload for segment in checkpoint.segments)
    )
    assert restored.get_session(retry.identity.logon_id).ssh_command_streams == streams
    left, a = _plan(state, seconds=5)
    right, b = _plan(restored, seconds=5)
    assert a.ssh_command_streams == b.ssh_command_streams
    assert a.ssh_command_streams.bindings[0].native_pipe_id == 1_000_003
    _commit(state, left)
    _commit(restored, right)
    assert state._macos_pipe_counters == restored._macos_pipe_counters


def test_command_exec_consumes_channel_streams_without_changing_shell_unknowns() -> None:
    state, shell = _ready()
    assert state.process_descriptors_at(shell, event_time=shell.started_at) is None
    before = state.materialization_digest()
    builder = state.begin_action_cohort_materialization()
    child = builder.fork_process(shell, forked_at=_START + timedelta(seconds=5))
    after = builder.execute_process(
        child,
        image="/usr/bin/id",
        command_line="/usr/bin/id",
        executed_at=_START + timedelta(seconds=6),
        macos_ssh_standard_io=True,
    )
    plan = builder.seal()
    table = plan.process_executions[0].descriptors_after
    assert table.native_last_fd == 2
    assert all(item.kind == "pipe" and not item.close_on_exec for item in table.bindings)
    with state.prepared_action_cohort_materialization(plan) as prepared:
        prepared.certify_composite_commit(prepared.expected_result)
        prepared.apply_provisional()
        assert state.process_descriptors_at(after, event_time=after.execution_started_at) == table
    assert state.materialization_digest() == before
    state.materialize_action_cohort(plan)
    assert (
        state.process_descriptors_at(child.identity, event_time=child.identity.started_at) is None
    )
    assert state.process_descriptors_at(shell, event_time=after.execution_started_at) is None
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    assert restored.process_descriptors_at(after, event_time=after.execution_started_at) == table
    next_builder = restored.begin_action_cohort_materialization()
    next_child = next_builder.fork_process(shell, forked_at=_START + timedelta(seconds=7))
    next_builder.execute_process(
        next_child,
        image="/usr/bin/id",
        command_line="/usr/bin/id",
        executed_at=_START + timedelta(seconds=8),
        macos_ssh_standard_io=True,
    )
    assert next_builder.seal().process_executions[0].descriptors_after.bindings == table.bindings


@pytest.mark.parametrize("damage", ["role", "origin", "streams", "terminal", "pty", "readiness"])
def test_command_contract_rejects_foreign_unknown_or_pty_contexts(damage: str) -> None:
    state, shell = _ready(pty=damage == "pty")
    session = state.get_session(shell.logon_id)
    if damage == "role":
        session.session_shell_pid += 1
    elif damage == "origin":
        session.audit_origin = replace(session.audit_origin, audit_uid=502)
    elif damage == "streams":
        session.ssh_command_streams = None
    elif damage == "readiness":
        session.source_ready_time = _START + timedelta(minutes=1)
    elif damage == "terminal":
        state._macos_terminal_sessions.clear()
    before = state.materialization_digest()
    builder = state.begin_action_cohort_materialization()
    child = builder.fork_process(shell, forked_at=_START + timedelta(seconds=5))
    with pytest.raises(StateError, match="authenticated non-PTY"):
        builder.execute_process(
            child,
            image="/usr/bin/id",
            command_line="/usr/bin/id",
            executed_at=_START + timedelta(seconds=6),
            macos_ssh_standard_io=True,
        )
    assert state.materialization_digest() == before


def test_channel_and_exec_descriptor_tampering_cannot_reuse_capabilities() -> None:
    state = StateManager()
    _start(state)
    batch, session = _plan(state)
    changed = replace(session.ssh_command_streams, session_object_id="foreign")
    forged = replace(session, _payload=replace(session._payload, ssh_command_streams=changed))
    with pytest.raises(StateError, match="session/pipe allocation"):
        state.materialize_session(forged)
    state, shell = _ready()
    builder = state.begin_action_cohort_materialization()
    child = builder.fork_process(shell, forked_at=_START + timedelta(seconds=5))
    builder.execute_process(
        child,
        image="/usr/bin/id",
        command_line="/usr/bin/id",
        executed_at=_START + timedelta(seconds=6),
        macos_ssh_standard_io=True,
    )
    plan = builder.seal()
    table = plan.process_executions[0].descriptors_after
    object.__setattr__(table, "bindings", table.bindings[:2])
    with pytest.raises(StateError, match="identity|integrity|changed"):
        state.materialize_action_cohort(plan)


@pytest.mark.parametrize("damage", ["counter", "session", "protocol", "old_head"])
def test_checkpoint_rejects_unowned_or_disguised_channel_streams(damage: str) -> None:
    state, shell = _ready()
    session = state.get_session(shell.logon_id)
    if damage == "counter":
        state._macos_pipe_counters.clear()
    elif damage == "session":
        session.ssh_command_streams = replace(
            session.ssh_command_streams, session_object_id="foreign"
        )
    elif damage == "protocol":
        session.auth_protocol = "local"
    payload = _capture_head(state)
    if damage == "old_head":
        document = loads(payload)
        document["schema_version"] = "8"
        payload = dumps(document)
    with pytest.raises(CheckpointCorruptionError):
        _restore_head(StateManager(), payload)


def test_old_session_records_keep_unknown_command_streams() -> None:
    state = StateManager()
    state.set_current_time(_START)
    logon = state.create_session(
        username="casey", system="LINUX", logon_type=10, source_ip="192.0.2.10"
    )
    encoded = encode_state_value(state.get_session(logon))
    assert encoded[1] == "active-session-v2"
    assert decode_state_value(encoded).ssh_command_streams is None
    head = loads(_capture_head(state))
    head["schema_version"] = "8"
    restored = StateManager()
    _restore_head(restored, dumps(head))
    assert restored.get_session(logon).ssh_command_streams is None


@pytest.mark.parametrize(
    "counter", [(1_000_000, 2**64 - 3), (2_000_000, 2_000_002), (1_000_000, True), None]
)
def test_invalid_or_exhausted_channel_pipe_allocation_is_side_effect_free(counter: object) -> None:
    state = StateManager()
    _start(state)
    state._macos_pipe_counters["MAC-A"] = counter
    before = state.materialization_digest()
    with pytest.raises(StateError, match="pipe policy"):
        _plan(state)
    assert state.materialization_digest() == before


def test_known_command_table_stays_authoritative_and_shares_the_pipe_allocator() -> None:
    state, shell = _ready()
    builder = state.begin_action_cohort_materialization()
    child = builder.fork_process(shell, forked_at=_START + timedelta(seconds=5))
    after = builder.execute_process(
        child,
        image="/usr/bin/id",
        command_line="/usr/bin/id",
        executed_at=_START + timedelta(seconds=6),
        macos_ssh_standard_io=True,
    )
    state.materialize_action_cohort(builder.seal())
    builder = state.begin_action_cohort_materialization()
    table = builder.open_macos_pipe(
        after,
        at=_START + timedelta(seconds=7),
        read_fd=3,
        write_fd=4,
        first_pipe_id=1_000_000,
        close_on_exec=True,
    )
    state.materialize_action_cohort(builder.seal())
    assert table.bindings[-1].native_pipe_id == 1_000_003
    builder = state.begin_action_cohort_materialization()
    next_child = builder.fork_process(after, forked_at=_START + timedelta(seconds=8))
    with pytest.raises(StateError, match="known inherited FD table"):
        builder.execute_process(
            next_child,
            image="/usr/bin/id",
            command_line="/usr/bin/id",
            executed_at=_START + timedelta(seconds=9),
            macos_ssh_standard_io=True,
        )
    next_execution = builder.execute_process(
        next_child,
        image="/usr/bin/id",
        command_line="/usr/bin/id",
        executed_at=_START + timedelta(seconds=9),
    )
    plan = builder.seal()
    assert len(plan.process_executions[0].descriptors_after.bindings) == 3
    state.materialize_action_cohort(plan)
    assert (
        state.process_descriptors_at(
            next_execution, event_time=next_execution.execution_started_at
        ).native_last_fd
        == 2
    )


@pytest.mark.parametrize("legacy", [False, True])
@pytest.mark.parametrize("native", [False, True])
def test_real_ssh_command_exports_complete_exec_only_under_selected_policy(
    tmp_path: Path, scenarios_dir: Path, legacy: bool, native: bool
) -> None:
    scenario = macos_ssh_scenario(scenarios_dir, macos_receiver=True)
    scenario.output.logs = [{"format": "ecar"}] + (
        [{"format": "macos_endpoint_security"}] if native else []
    )
    with generation_seed_scope(335):
        reset_thread_rng()
        engine = GenerationEngine(scenario, tmp_path)
        try:
            engine._initialize()
            generator = engine.activity_generator
            if legacy:
                engine.macos_execution_metadata.profile = (
                    engine.macos_execution_metadata.profile.model_copy(
                        update={"ssh_command_descriptors": None}
                    )
                )
            user = scenario.environment.users[0]
            target = scenario.environment.systems[-1]
            opened = engine.start_time + timedelta(minutes=10)
            generator.generate_ssh_session(
                user=user,
                target_system=target,
                time=opened,
                source_ip="192.0.2.55",
                source_port=50001,
                duration=600,
                emit_session_close=True,
                defer_session_close=True,
            )
            session = next(
                s
                for s in engine.state_manager.get_sessions_for_user(user.username)
                if s.system == target.hostname and s.session_kind == "ssh"
            )
            shell = engine.state_manager.get_process_identity(
                target.hostname, session.session_shell_pid
            )
            assert (
                engine.state_manager.process_descriptors_at(
                    shell, event_time=shell.execution_started_at
                )
                is None
            )
            pid = generator.generate_process(
                user,
                target,
                opened + timedelta(minutes=1),
                session.logon_id,
                "/usr/bin/id",
                "/usr/bin/id",
                parent_pid=shell.pid,
                require_exact_parent=True,
            )
            after = engine.state_manager.get_process_identity(target.hostname, pid)
            assert after.execution_ordinal == 1
            table = engine.state_manager.process_descriptors_at(
                after, event_time=after.execution_started_at
            )
            assert (table is None) == legacy
            if not legacy:
                assert table.bindings == session.ssh_command_streams.bindings
            assert (
                engine.state_manager.process_descriptors_at(
                    shell, event_time=after.execution_started_at
                )
                is None
            )
        finally:
            engine._close_emitters()
    records = [
        decode_endpoint_security_record(line)
        for path in tmp_path.rglob("macos_endpoint_security.ndjson")
        for line in path.read_text().splitlines()
    ]
    executions = [
        record
        for record in records
        if record.event_type == 9 and record.event.exec.target.audit_token.pid == pid
    ]
    assert bool(executions) == (native and not legacy)
    if executions:
        fds = executions[0].event.exec.fds
        assert tuple(item.fd for item in fds) == (0, 1, 2)
        assert all(item.fdtype == 6 for item in fds)
        assert tuple(item.pipe.pipe_id for item in fds) == tuple(
            item.native_pipe_id for item in table.bindings
        )
