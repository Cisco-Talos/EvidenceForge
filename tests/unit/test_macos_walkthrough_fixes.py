# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Regressions for the actual-scenario sleep and non-PTY history contradictions."""

import json
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.events.process_outcome import PosixProcessExit
from evidenceforge.generation.actions.macos_launch_item import macos_successful_exit_not_before
from evidenceforge.generation.checkpoints.lifecycle_head import _capture, _restore
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.macos_shell_history import interactive_history_shell
from evidenceforge.generation.timing import TemporalConstraintError
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_native_system_job import _setup
from tests.unit.test_macos_ssh_pty_execution import _engine
from tests.unit.test_process_execution_state import _process


@pytest.mark.parametrize("shell", ["zsh", "bash"])
@pytest.mark.parametrize(
    "options,terminal,eligible",
    [
        ((), True, True),
        ((), False, False),
        ((), None, False),
        (("-i",), False, True),
        (("-li",), False, True),
        (("--interactive",), False, True),
        (("+i",), True, False),
        (("-i", "+i"), True, False),
        (("-c", "id"), True, False),
        (("script.sh",), True, False),
        (("--unknown",), True, False),
    ],
)
def test_history_requires_interactive_invocation_facts(
    shell: str, options: tuple[str, ...], terminal: bool | None, eligible: bool
) -> None:
    assert (
        interactive_history_shell(
            f"/bin/{shell}", (f"-{shell}", *options), stdin_is_terminal=terminal
        )
        is eligible
    )
    assert not interactive_history_shell(f"/bin/{shell}", None, stdin_is_terminal=terminal)


@pytest.mark.parametrize(
    "operand,microseconds", [("600", 600_000_000), (".5", 500_000), (".0000001", 1)]
)
def test_sleep_duration_bound_is_exact_and_does_not_invent_unknown_outcomes(
    operand: str, microseconds: int
) -> None:
    _state, original = _process()
    process = replace(
        original,
        image="/bin/sleep",
        command_line=f"/bin/sleep {operand}",
        arguments=("/bin/sleep", operand),
    )
    assert macos_successful_exit_not_before(process, PosixProcessExit(exit_code=0)) == (
        process.execution_started_at + timedelta(microseconds=microseconds)
    )
    for outcome in (None, PosixProcessExit(exit_code=1), PosixProcessExit(signal=15)):
        assert macos_successful_exit_not_before(process, outcome) is None
    assert (
        macos_successful_exit_not_before(
            replace(process, arguments=("/bin/sleep", "600s"), command_line="/bin/sleep 600s"),
            PosixProcessExit(exit_code=0),
        )
        is None
    )


@pytest.mark.parametrize("restore", [False, True])
def test_sleep_success_uses_actual_exec_duration_and_bounded_completion_plan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, restore: bool
) -> None:
    engine, bundle, request = _setup(
        tmp_path, monkeypatch, program="/bin/sleep", arguments=("/bin/sleep", "600")
    )
    try:
        process = bundle.execute(request("activate", 63)).process
        early = request("exit", 643)
        before = engine.state_manager.materialization_digest()
        with pytest.raises(StateError, match="requested command duration"):
            bundle.execute(early)
        assert engine.state_manager.materialization_digest() == before
        kwargs = dict(
            hostname=process.hostname,
            label=early.label,
            requested_at=early.timestamp,
            exit_code=0,
            latest_at=engine.start_time + timedelta(seconds=700),
        )
        planned = bundle.plan_exit_time(**kwargs)
        minimum = process.execution_started_at + timedelta(seconds=600)
        assert minimum <= planned < minimum + timedelta(milliseconds=26)
        with pytest.raises(TemporalConstraintError):
            bundle.plan_exit_time(**(kwargs | {"latest_at": minimum - timedelta(microseconds=1)}))
        assert engine.state_manager.materialization_digest() == before
        if restore:
            engine.lifecycle_registry.prune_action_cohort_receipt_authorities()
            _restore_head(engine.state_manager, _capture_head(engine.state_manager))
            _restore(engine.lifecycle_registry, _capture(engine.lifecycle_registry))
            assert bundle.plan_exit_time(**kwargs) == planned
        bundle.execute(replace(early, timestamp=planned))
        bundle.execute(replace(request("unload", 701), timestamp=planned + timedelta(seconds=1)))
        engine._finalize_macos_process_coverage()
    finally:
        engine._close_emitters()
    rows = [
        json.loads(line)
        for path in tmp_path.rglob("macos_endpoint_security.ndjson")
        for line in path.read_text().splitlines()
    ]
    assert [row["event_type"] for row in rows] == [11, 9, 9, 15]


@pytest.mark.parametrize("pty", [False, True])
@pytest.mark.parametrize("restore", [False, True])
def test_ssh_history_follows_stdin_interactivity_without_losing_process_evidence(
    tmp_path: Path, pty: bool, restore: bool
) -> None:
    engine = _engine(tmp_path, pty=pty, history=True)
    try:
        state, generator = engine.state_manager, engine.activity_generator
        if restore:
            _restore_head(state, _capture_head(state))
        user, system = engine.scenario.environment.users[0], engine.scenario.environment.systems[0]
        session = next(
            item
            for item in state.get_sessions_for_user(user.username)
            if item.session_kind == "ssh"
        )
        when = engine.start_time + timedelta(minutes=10, seconds=30)
        generator.generate_process(
            user,
            system,
            when,
            session.logon_id,
            "/usr/bin/id",
            "/usr/bin/id",
            parent_pid=session.session_shell_pid,
            require_exact_parent=True,
            suppress_command_file_effect=True,
        )
        assert (
            generator.emit_macos_shell_history(
                user,
                system,
                when,
                "id",
                logon_id=session.logon_id,
                shell_pid=session.session_shell_pid,
            )
            is pty
        )
        engine._finalize_macos_process_coverage()
        assert engine.dispatcher.macos_es_ingress.coverage.hosts[0].process_census.complete
    finally:
        engine._close_emitters()
    rows = [
        json.loads(line)
        for path in tmp_path.rglob("macos_endpoint_security.ndjson")
        for line in path.read_text().splitlines()
    ]
    assert (
        sum(
            row["event_type"] == 9
            and row["event"]["exec"]["target"]["executable"]["path"] == "/usr/bin/id"
            for row in rows
        )
        == 1
    )
    history = [path.read_text() for path in tmp_path.rglob("*history*") if path.is_file()]
    assert any(";id" in content for content in history) is pty
