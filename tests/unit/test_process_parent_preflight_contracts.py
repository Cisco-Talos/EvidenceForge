# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Parent and preparation contracts frozen before the final ownership extraction."""

from copy import deepcopy
from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.generation.actions.process_execution import (
    ProcessExecutionActionBundle,
    ProcessExecutionRequest,
)
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import System, User
from evidenceforge.utils.rng import _get_rng


def _fixture(linux: bool = False) -> tuple[ActivityGenerator, System, User, str, datetime]:
    timestamp = datetime(2024, 3, 18, 13, tzinfo=UTC)
    state = StateManager()
    state.set_current_time(timestamp - timedelta(minutes=5))
    generator = ActivityGenerator(
        state, {}, dispatcher=EventDispatcher(state_manager=state, emitters={})
    )
    system = System(
        hostname="HOST",
        ip="10.0.0.1",
        os="Ubuntu 24.04" if linux else "Windows 11",
        type="workstation",
    )
    user = User(username="alice", full_name="Alice", email="alice@example.test")
    logon_id = state.create_session(
        user.username,
        system.hostname,
        2,
        "-",
        start_time=timestamp - timedelta(minutes=4),
        session_kind="interactive",
    )
    if linux:
        state.register_process(
            system=system.hostname,
            pid=1,
            parent_pid=0,
            image="/usr/lib/systemd/systemd",
            command_line="systemd",
            username="root",
            integrity_level="System",
            os_category="linux",
            start_time=timestamp - timedelta(minutes=5),
        )
    image = "/bin/bash" if linux else r"C:\Windows\explorer.exe"
    state.register_process(
        system=system.hostname,
        pid=1100,
        parent_pid=1 if linux else 4,
        image=image,
        command_line=image,
        username=user.username,
        integrity_level="Medium",
        os_category="linux" if linux else "windows",
        logon_id=logon_id,
        start_time=timestamp - timedelta(minutes=3),
    )
    session = state.get_session(logon_id)
    assert session is not None
    session.session_shell_pid = 1100
    if not linux:
        session.explorer_pid = 1100
    generator._system_pids = {system.hostname: {"bash" if linux else "explorer": 1100}}
    state.set_current_time(timestamp)
    return generator, system, user, logon_id, timestamp


@pytest.mark.parametrize("linux", [False, True])
@pytest.mark.parametrize("candidate", ["valid", "future", "ended", "foreign", "missing"])
def test_existing_parent_selection_never_materializes_or_consumes_rng(
    linux: bool,
    candidate: str,
) -> None:
    generator, system, user, logon_id, timestamp = _fixture(linux)
    state = generator.state_manager
    if candidate != "missing":
        state.register_process(
            system=system.hostname,
            pid=1200,
            parent_pid=1100,
            image="/bin/bash" if linux else r"C:\Windows\System32\cmd.exe",
            command_line="bash" if linux else "cmd.exe",
            username=user.username,
            integrity_level="Medium",
            os_category="linux" if linux else "windows",
            logon_id="other-session" if candidate == "foreign" else logon_id,
            start_time=timestamp + timedelta(seconds=5)
            if candidate == "future"
            else timestamp - timedelta(seconds=5),
        )
        if candidate == "ended":
            state.end_process(system.hostname, 1200, timestamp - timedelta(seconds=1))
    processes = deepcopy(dict(state.state.running_processes))
    rng = _get_rng().getstate()

    selected = generator._resolve_existing_prepared_process_parent(
        system=system,
        user=user,
        time=timestamp,
        logon_id=logon_id,
        parent_pid=1200,
        process_username=user.username,
    )

    assert selected == (1200 if candidate == "valid" else 1100)
    assert dict(state.state.running_processes) == processes
    assert _get_rng().getstate() == rng


@pytest.mark.parametrize("linux", [False, True])
@pytest.mark.parametrize("ensure_file", [False, True])
def test_repeated_preflight_preserves_process_state_and_timing_owner(
    linux: bool,
    ensure_file: bool,
) -> None:
    generator, system, user, logon_id, timestamp = _fixture(linux)
    request = ProcessExecutionRequest(
        user=user,
        system=system,
        time=timestamp,
        logon_id=logon_id,
        process_name="/usr/bin/id" if linux else r"C:\Tools\whoami.exe",
        command_line="id" if linux else "whoami.exe",
        parent_pid=1100,
        ensure_file_event=ensure_file,
        suppress_command_file_effect=True,
    )
    processes = deepcopy(dict(generator.state_manager.state.running_processes))
    timing = generator.timing_runtime.state_digest()
    rng = _get_rng().getstate()

    first = ProcessExecutionActionBundle(generator, request).preflight()
    second = ProcessExecutionActionBundle(generator, request).preflight()

    assert first == second
    assert first.prepared_effects is not None
    assert dict(generator.state_manager.state.running_processes) == processes
    assert generator.timing_runtime.state_digest() == timing
    assert _get_rng().getstate() == rng


def test_explicit_second_linux_shell_survives_parent_sanitization() -> None:
    generator, system, user, logon_id, timestamp = _fixture(True)
    generator.state_manager.register_process(
        system=system.hostname,
        pid=1200,
        parent_pid=1100,
        image="/bin/bash",
        command_line="bash",
        username=user.username,
        integrity_level="Medium",
        os_category="linux",
        logon_id=logon_id,
        start_time=timestamp - timedelta(seconds=5),
    )
    assert (
        generator._sanitize_user_parent_pid(
            system=system,
            user=user,
            time=timestamp,
            logon_id=logon_id,
            process_name="/usr/bin/id",
            command_line="id",
            parent_pid=1200,
            process_username=user.username,
        )
        == 1200
    )


def test_platform_parent_helpers_bind_current_shared_history_and_state() -> None:
    from dataclasses import fields

    generator, _system, _user, _logon_id, _timestamp = _fixture()
    first = generator._process_parents()
    replacement, *_ = _fixture()
    for name in ("state_manager", "_system_pids", "_user_process_history"):
        setattr(generator, name, getattr(replacement, name))
    current = generator._process_parents()
    for helper in (current.windows, current.linux, current.history):
        assert helper.state_manager is replacement.state_manager
        assert helper.queries.state_manager is replacement.state_manager
        assert all(getattr(helper, field.name) is not current for field in fields(helper))
        assert all(getattr(helper, field.name) is not generator for field in fields(helper))
    assert current.windows.history._user_process_history is replacement._user_process_history
    assert current.history._user_process_history is replacement._user_process_history
    assert current.windows._system_pids is replacement._system_pids
    assert current.linux._system_pids is replacement._system_pids
    assert first.state_manager is not current.state_manager


@pytest.mark.parametrize("observing", [False, True])
def test_linux_parent_materialization_receives_current_observation_start(
    observing: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    from unittest.mock import Mock

    generator, system, user, logon_id, timestamp = _fixture(True)
    generator._scenario_start_time = timestamp if observing else None
    materialize = Mock(return_value=1300)
    monkeypatch.setattr(generator, "ensure_linux_session_shell", materialize)

    selected = generator._materialize_visible_linux_shell_parent_for_child(
        system=system,
        time=timestamp,
        logon_id=logon_id,
        parent_pid=1100,
        process_username=user.username,
    )

    assert selected == (1300 if observing else 1100)
    assert materialize.call_count == int(observing)
    assert generator._process_parents().linux._scenario_start_time == (
        timestamp if observing else None
    )
