# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Each Windows CLI invocation owns its parent preparation phase."""

from datetime import timedelta

import pytest

from tests.unit.test_terminal_generator_admission import (
    _START,
    _generator,
    _process_state_snapshot,
    _register_interactive_parent,
    _register_windows_service_parents,
    _user,
    _windows_system,
)


def _parent_intervals(command: str) -> list[float]:
    generator, state, _ = _generator()
    host, user = _windows_system(), _user()
    session_id = _register_interactive_parent(state, host, user)
    session = state.get_session(session_id)
    assert session is not None
    result: list[float] = []
    for minute in [0, 5, 10, 20, 30, 40, 50]:
        child_at = _START + timedelta(minutes=minute)
        pid = generator._ensure_windows_user_cli_parent(
            system=host,
            user=user,
            session=session,
            child_time=child_at,
            candidate_pid=1000,
            child_command_line=command,
        )
        parent = state.get_process(host.hostname, pid)
        assert parent is not None
        assert parent.logon_id == session_id
        assert parent.start_time >= session.start_time
        result.append((child_at - parent.start_time).total_seconds())
    return result


@pytest.mark.parametrize(
    "command",
    [
        "ssh.exe alice@app.example",
        r"scp.exe C:\Temp\report.csv alice@app.example:/tmp/report.csv",
        "sftp.exe alice@app.example",
    ],
)
def test_dedicated_cli_parent_preparation_varies_by_invocation_and_replays(command: str) -> None:
    first = _parent_intervals(command)
    replay = _parent_intervals(command)
    assert first == replay
    assert len(set(first)) >= 6
    assert all(1.2 <= gap <= 6.0 for gap in first)


def test_impossible_cli_parent_source_deadline_rejects_before_timing_or_bootstrap() -> None:
    generator, state, emitters = _generator()
    host, user = _windows_system(), _user()
    _register_windows_service_parents(generator, state, host)
    start = _START - timedelta(minutes=10)
    state.set_current_time(start)
    session_id = state.create_session(
        username=user.username,
        system=host.hostname,
        logon_type=2,
        source_ip="-",
        start_time=start,
        session_kind="interactive",
    )
    session = state.get_session(session_id)
    assert session is not None
    before = _process_state_snapshot(state, host.hostname)
    timing_before = generator.timing_runtime.state_digest()
    pid = generator._ensure_windows_user_cli_parent(
        system=host,
        user=user,
        session=session,
        child_time=_START,
        candidate_pid=500,
        child_command_line="ssh.exe alice@app.example",
        source_visible_by=start,
    )
    assert pid == 0
    assert _process_state_snapshot(state, host.hostname) == before
    assert generator.timing_runtime.state_digest() == timing_before
    assert not session.windows_shell_bootstrapped
    assert not any(emitter.emit.called for emitter in emitters.values())


def test_cli_parent_cannot_be_placed_before_its_session_when_no_time_slot_exists() -> None:
    generator, state, emitters = _generator()
    host, user = _windows_system(), _user()
    session_id = _register_interactive_parent(state, host, user)
    session = state.get_session(session_id)
    assert session is not None
    before = _process_state_snapshot(state, host.hostname)
    timing_before = generator.timing_runtime.state_digest()
    pid = generator._ensure_windows_user_cli_parent(
        system=host,
        user=user,
        session=session,
        child_time=session.start_time + timedelta(milliseconds=50),
        candidate_pid=1000,
        child_command_line="ssh.exe alice@app.example",
    )
    assert pid == 0
    assert _process_state_snapshot(state, host.hostname) == before
    assert generator.timing_runtime.state_digest() == timing_before
    assert not any(emitter.emit.called for emitter in emitters.values())
