# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented real-engine PTY startup and foreground command execution."""

import json
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from evidenceforge.events.dispatcher import PreparedActionCohortCapability
from evidenceforge.events.macos_terminal import MacosTerminalObservation
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.actions.command_effects import ExecutionEffectPlan
from evidenceforge.generation.actions.process_execution import ProcessExecutionRequest
from evidenceforge.generation.checkpoints.activity_head import _assert_transient_empty
from evidenceforge.generation.checkpoints.errors import CheckpointError
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import SshSessionEventSpec
from tests.unit.test_macos_installed_provisioning import _scenario


@pytest.mark.parametrize("value", ["true", 1, None])
def test_pty_intent_rejects_ambiguous_boolean_inputs(value: object) -> None:
    with pytest.raises(ValidationError):
        SshSessionEventSpec(pty=value)


@pytest.mark.parametrize("macos", [False, True])
def test_authored_pty_requires_the_qualified_mac_receiver(scenarios_dir: Path, macos: bool) -> None:
    from evidenceforge.validation.schema import ScenarioValidator
    from tests.support.macos_ssh import macos_ssh_scenario

    scenario = macos_ssh_scenario(scenarios_dir, macos_receiver=macos)
    scenario.storyline[1].events[0].pty = True
    issues = ScenarioValidator(scenario).validate()
    assert any(issue.severity == "error" and "PTY" in issue.message for issue in issues) == (
        not macos
    )


def test_pty_checkpoint_tag_is_distinct_and_legacy_auth_rows_keep_their_mode() -> None:
    from evidenceforge.generation.actions.ssh_session import (
        SshReceiverAuthentication,
        _SshMacAuthState,
    )
    from evidenceforge.generation.checkpoints.activity_head import _decode_ssh_auth, _ssh_auth_row
    from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError
    from tests.unit.test_macos_audit_sessions import _START

    auth = SshReceiverAuthentication(
        1200,
        10,
        _START,
        _START + timedelta(seconds=1),
        _START + timedelta(seconds=1),
        _START + timedelta(seconds=2),
    )
    for pty in (False, True):
        state = _SshMacAuthState(auth, "/sbin/launchd", "/usr/libexec/sshd-session", True, pty)
        row = _ssh_auth_row(state)
        assert row[0] == ("macos-v3-pty" if pty else "macos-v2")
        assert _decode_ssh_auth(row) == state
    legacy = _SshMacAuthState(auth, "/usr/libexec/sshd-keygen-wrapper", "/usr/libexec/sshd-session")
    row = _ssh_auth_row(legacy)
    assert row[0] == "macos-v1" and _decode_ssh_auth(row) == legacy
    row[0] = "macos-v3-pty"
    with pytest.raises(CheckpointCorruptionError):
        _decode_ssh_auth(row)


def _engine(
    tmp_path: Path,
    *,
    native: bool = True,
    unified: bool = False,
    pty: bool = True,
    history: bool = False,
) -> GenerationEngine:
    scenario = _scenario()
    scenario.environment.systems[0].services = ["ssh"]
    scenario.macos_process_coverage = "complete" if native else "partial"
    scenario.output.logs = [{"format": "ecar"}] + (
        [{"format": "macos_endpoint_security"}] if native else []
    )
    if unified:
        scenario.output.logs.append({"format": "macos_unified_log"})
    if history:
        scenario.output.logs.append({"format": "zsh_history"})
    engine = GenerationEngine(scenario, tmp_path, generation_seed=370)
    engine._chronological_es_delivery = True
    engine._initialize()
    engine.activity_generator.generate_ssh_session(
        scenario.environment.users[0],
        scenario.environment.systems[0],
        engine.start_time + timedelta(minutes=10),
        source_ip="192.0.2.80",
        source_port=51000,
        duration=120,
        emit_session_close=True,
        defer_session_close=True,
        pty=pty,
    )
    return engine


def test_pty_password_intent_uses_the_same_root_pam_authentication_source(tmp_path: Path) -> None:
    engine = _engine(tmp_path, unified=True)
    try:
        engine._finalize_macos_process_coverage()
    finally:
        engine._close_emitters()
    rows = [
        json.loads(line)
        for path in tmp_path.rglob("macos_unified_log.ndjson")
        for line in path.read_text().splitlines()
    ]
    assert len(rows) == 1
    assert rows[0]["eventMessage"] == (
        "Accepted keyboard-interactive/pam for alex from 192.0.2.80 port 51000 ssh2"
    )
    assert rows[0]["userID"] == 0
    assert rows[0]["processImagePath"] == "/usr/libexec/sshd-session"


def test_pty_canonical_terminal_and_foreground_group_do_not_require_native_output(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path, native=False)
    try:
        generator, state = engine.activity_generator, engine.state_manager
        target, user = engine.scenario.environment.systems[0], engine.scenario.environment.users[0]
        session = next(
            item
            for item in state.get_sessions_for_user(user.username)
            if item.session_kind == "ssh"
        )
        shell = state.get_process_identity(target.hostname, session.session_shell_pid)
        pid = generator.generate_process(
            user,
            target,
            engine.start_time + timedelta(minutes=10, seconds=30),
            session.logon_id,
            "/usr/bin/id",
            "/usr/bin/id",
            parent_pid=shell.pid,
            require_exact_parent=True,
            suppress_command_file_effect=True,
        )
        command = state.get_process_identity(target.hostname, pid)
        assert (
            command.job_control.pgid == pid
            and command.job_control.session == shell.job_control.session
        )
        assert (
            type(
                state.known_macos_terminal(
                    command.job_control.session, command.execution_started_at
                )
            )
            is MacosTerminalObservation
        )
        census = dict(state.macos_process_census_snapshot())[target.hostname]
        assert census.forks.count == census.execs.count == 7 and census.aggregate_births == 0
        generator.finalize_ssh_session_lifecycles(engine.end_time)
        engine._finalize_macos_process_coverage()
    finally:
        engine._close_emitters()
    assert not list(tmp_path.rglob("macos_endpoint_security.ndjson"))


@pytest.mark.slow
@pytest.mark.parametrize("phase", [0, 1, 2], ids=["fork", "group", "exec"])
@pytest.mark.parametrize("fault", ["before-commit", "lost-return", "source-release"])
def test_pty_command_recovers_each_phase_without_duplicate_state_or_native_starts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: int, fault: str
) -> None:
    from evidenceforge.generation.emitters.base import ExactPublicationBatch

    engine = _engine(tmp_path)
    try:
        generator, state = engine.activity_generator, engine.state_manager
        target, user = engine.scenario.environment.systems[0], engine.scenario.environment.users[0]
        session = next(
            item
            for item in state.get_sessions_for_user(user.username)
            if item.session_kind == "ssh"
        )
        request = ProcessExecutionRequest(
            user,
            target,
            engine.start_time + timedelta(minutes=10, seconds=30),
            session.logon_id,
            "/usr/bin/id",
            "/usr/bin/id",
            parent_pid=session.session_shell_pid,
            require_exact_parent=True,
            arguments=("/usr/bin/id",),
            from_storyline=True,
            effect_plan=ExecutionEffectPlan(
                ActionAnchor("process_execution", "invented-pty-recovery", source="test"), ()
            ),
        )
        original, release = (
            PreparedActionCohortCapability.commit_no_fail,
            ExactPublicationBatch.release_no_fail,
        )
        attempts = releases = 0

        def interrupted(capability: PreparedActionCohortCapability) -> object:
            nonlocal attempts
            current = attempts
            attempts += 1
            if current == phase and fault == "before-commit":
                raise OSError("invented PTY interruption")
            result = original(capability)
            if current == phase and fault == "lost-return":
                raise OSError("invented PTY interruption")
            return result

        def interrupted_release(batch: ExactPublicationBatch) -> None:
            nonlocal releases
            current = releases
            releases += 1
            if current == phase:
                raise OSError("invented PTY interruption")
            release(batch)

        with monkeypatch.context() as fault_scope:
            if fault == "source-release":
                fault_scope.setattr(ExactPublicationBatch, "release_no_fail", interrupted_release)
            else:
                fault_scope.setattr(PreparedActionCohortCapability, "commit_no_fail", interrupted)
            with pytest.raises(OSError, match="invented PTY interruption"):
                generator._process_execution_service().create(request)
        with pytest.raises(CheckpointError, match="_macos_finder_startups"):
            _assert_transient_empty(generator)
        before = dict(state.macos_process_census_snapshot())[target.hostname]
        engine.dispatcher.drain_exact_projection_recoveries()
        assert dict(state.macos_process_census_snapshot())[target.hostname] == before
        pid = generator._process_execution_service().create(request)
        assert not generator._macos_finder_startups
        after = dict(state.macos_process_census_snapshot())[target.hostname]
        assert after.forks.count == 7 and after.execs.count == 7 and after.aggregate_births == 0
        command = state.get_process_identity(target.hostname, pid)
        assert command.job_control.pgid == pid and command.execution_ordinal == 1
        engine.dispatcher.assert_exact_projection_recoveries_drained()
        generator.finalize_ssh_session_lifecycles(engine.end_time)
        engine._finalize_macos_process_coverage()
        assert engine.dispatcher.macos_es_ingress.coverage.hosts[0].process_census.complete
    finally:
        engine._close_emitters()


@pytest.mark.parametrize("damage", ["profile", "shell_syntax"])
def test_unqualified_pty_command_rejects_before_another_process_is_allocated(
    tmp_path: Path, damage: str
) -> None:
    engine = _engine(tmp_path)
    try:
        generator, state = engine.activity_generator, engine.state_manager
        target, user = engine.scenario.environment.systems[0], engine.scenario.environment.users[0]
        session = next(
            item
            for item in state.get_sessions_for_user(user.username)
            if item.session_kind == "ssh"
        )
        if damage == "profile":
            engine.macos_execution_metadata.profile = (
                engine.macos_execution_metadata.profile.model_copy(
                    update={"ssh_pty_execution": None}
                )
            )
        before = state.macos_process_census_snapshot()
        with pytest.raises(StateError, match="SSH PTY"):
            generator.generate_process(
                user,
                target,
                engine.start_time + timedelta(minutes=10, seconds=30),
                session.logon_id,
                "/usr/bin/id",
                "/usr/bin/id | /usr/bin/id" if damage == "shell_syntax" else "/usr/bin/id",
                parent_pid=session.session_shell_pid,
                require_exact_parent=True,
                suppress_command_file_effect=True,
            )
        assert state.macos_process_census_snapshot() == before
    finally:
        engine._close_emitters()


def test_complete_pty_receiver_and_command_keep_measured_terminal_group_and_native_starts(
    tmp_path: Path,
) -> None:
    scenario = _scenario()
    target, user = scenario.environment.systems[0], scenario.environment.users[0]
    target.services = ["ssh"]
    scenario.macos_process_coverage = "complete"
    scenario.output.logs = [{"format": "ecar"}, {"format": "macos_endpoint_security"}]
    engine = GenerationEngine(scenario, tmp_path, generation_seed=370)
    engine._chronological_es_delivery = True
    try:
        engine._initialize()
        generator, state = engine.activity_generator, engine.state_manager
        opened = engine.start_time + timedelta(minutes=10)
        generator.generate_ssh_session(
            user,
            target,
            opened,
            source_ip="192.0.2.80",
            source_port=51000,
            duration=120,
            emit_session_close=True,
            defer_session_close=True,
            pty=True,
        )
        session = next(
            item
            for item in state.get_sessions_for_user(user.username)
            if item.session_kind == "ssh"
        )
        shell = state.get_process_identity(target.hostname, session.session_shell_pid)
        assert shell is not None and shell.image == "/bin/zsh"
        terminal = state.known_macos_terminal(shell.job_control.session, shell.execution_started_at)
        assert type(terminal) is MacosTerminalObservation
        table = state.process_descriptors_at(shell, event_time=shell.execution_started_at)
        assert table.native_last_fd == 2
        assert tuple(binding.fd for binding in table.bindings) == (0, 1, 2)
        assert all(binding.kind == "file" for binding in table.bindings)
        assert len({binding.object_id for binding in table.bindings}) == 1
        assert session.ssh_command_streams is None
        pid = generator.generate_process(
            user,
            target,
            opened + timedelta(seconds=30),
            session.logon_id,
            "/usr/bin/id",
            "/usr/bin/id",
            parent_pid=shell.pid,
            require_exact_parent=True,
            suppress_command_file_effect=True,
        )
        command = state.get_process_identity(target.hostname, pid)
        assert command.execution_ordinal == 1
        assert command.job_control.pgid == pid
        assert command.job_control.session == shell.job_control.session
        assert command.job_control != shell.job_control
        assert command.credentials == shell.credentials
        assert command.responsibility == shell.responsibility
        assert (
            state.process_descriptors_at(command, event_time=command.execution_started_at).bindings
            == table.bindings
        )
        assert not generator._macos_finder_startups
        generator.finalize_ssh_session_lifecycles(engine.end_time)
        engine._finalize_macos_process_coverage()
        census = engine.dispatcher.macos_es_ingress.coverage.hosts[0].process_census
        assert census.complete and census.aggregate_births == 0
        assert census.expected_forks == census.published_forks == 7
        assert census.expected_execs == census.published_execs == 7
    finally:
        engine._close_emitters()
    rows = [
        json.loads(line)
        for path in tmp_path.rglob("macos_endpoint_security.ndjson")
        for line in path.read_text().splitlines()
    ]
    fork = next(
        row
        for row in rows
        if row["event_type"] == 11 and row["event"]["fork"]["child"]["audit_token"]["pid"] == pid
    )
    executed = next(
        row
        for row in rows
        if row["event_type"] == 9 and row["event"]["exec"]["target"]["audit_token"]["pid"] == pid
    )
    assert fork["event"]["fork"]["child"]["group_id"] == shell.pid
    assert executed["process"]["group_id"] == executed["event"]["exec"]["target"]["group_id"] == pid
    assert executed["event"]["exec"]["target"]["session_id"] == shell.pid
    assert executed["event"]["exec"]["target"]["tty"] is not None
    assert executed["event"]["exec"]["fds"] == [{"fd": fd, "fdtype": 1} for fd in range(3)]
