# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused ownership tests for Linux sudo fallback session identities."""

import random
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import Mock

import pytest

from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.formats.loader import load_format
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import System
from evidenceforge.utils.rng import _thread_local

_SCENARIO_START = datetime(2024, 1, 15, 9, 0, 0, tzinfo=UTC)


def _sudo_generator() -> tuple[ActivityGenerator, StateManager, System]:
    state = StateManager()
    ecar = Mock()
    ecar.can_handle.return_value = True
    emitters = {"ecar": ecar}
    dispatcher = EventDispatcher(state_manager=state, emitters=emitters)
    generator = ActivityGenerator(state, emitters, dispatcher=dispatcher)
    generator._scenario_start_time = _SCENARIO_START
    generator._scenario_end_time = _SCENARIO_START + timedelta(hours=6)
    system = _system()
    return generator, state, system


def _system() -> System:
    return System(
        hostname="APP-LINUX-01",
        ip="10.0.0.42",
        os="Ubuntu 22.04",
        type="server",
    )


def _generate_sudo_processes(
    generator: ActivityGenerator,
    system: System,
    *,
    sudo_time: datetime,
    lifecycle_group_id: str,
    command: str = "/usr/bin/id",
) -> tuple[int, int | None, timedelta, str]:
    return generator.generate_linux_sudo_processes(
        system=system,
        sudo_time=sudo_time,
        child_time=sudo_time + timedelta(milliseconds=200),
        sudo_user="testuser",
        tty="pts/1",
        command=command,
        reserve_until=sudo_time + timedelta(seconds=2),
        lifecycle_group_id=lifecycle_group_id,
    )


def _rendered_sudo_run(
    output_path: Path,
    *,
    sudo_time: datetime,
) -> tuple[bytes, str, str]:
    if hasattr(_thread_local, "rng"):
        del _thread_local.rng
    random.seed(42)
    state = StateManager()
    emitter = EcarEmitter(load_format("ecar"), output_path, threaded=False)
    emitters = {"ecar": emitter}
    dispatcher = EventDispatcher(state_manager=state, emitters=emitters)
    generator = ActivityGenerator(state, emitters, dispatcher=dispatcher)
    generator._scenario_start_time = _SCENARIO_START
    generator._scenario_end_time = _SCENARIO_START + timedelta(hours=6)
    system = _system()
    canonical_allocator = state.allocate_logon_id
    standalone_allocator = Mock(
        side_effect=AssertionError("sudo fallback must not allocate a standalone LogonID")
    )
    state.allocate_logon_id = standalone_allocator

    _generate_sudo_processes(
        generator,
        system,
        sudo_time=sudo_time,
        lifecycle_group_id="sudo:rendered",
    )
    session = state.get_sessions_for_user("testuser")[0]
    assert standalone_allocator.call_count == 0
    emitter.close()
    next_logon_id = canonical_allocator(
        system.hostname,
        _SCENARIO_START + timedelta(hours=2),
    )
    rendered = (output_path / system.hostname / "ecar.json").read_bytes()
    return rendered, session.logon_id, next_logon_id


@pytest.mark.parametrize(
    "sudo_time",
    [
        _SCENARIO_START + timedelta(seconds=30),
        _SCENARIO_START + timedelta(hours=1),
    ],
    ids=["carried-in", "in-window"],
)
def test_sudo_fallback_consumes_one_canonical_session_without_standalone_luid(
    sudo_time: datetime,
) -> None:
    generator, state, system = _sudo_generator()
    allocate_logon_id = Mock(
        side_effect=AssertionError("sudo fallback must not allocate a standalone LogonID")
    )
    state.allocate_logon_id = allocate_logon_id
    used_before = set(state._used_logon_ids)

    sudo_pid, child_pid, _shift, _tty = _generate_sudo_processes(
        generator,
        system,
        sudo_time=sudo_time,
        lifecycle_group_id=f"sudo:{sudo_time.isoformat()}",
    )

    sessions = state.get_sessions_for_user("testuser")
    used_after = set(state._used_logon_ids)
    assert allocate_logon_id.call_count == 0
    assert sudo_pid > 0
    assert child_pid is not None
    assert len(sessions) == 1
    assert used_after - used_before == {int(sessions[0].logon_id, 16)}


def test_sudo_reused_tty_gets_fresh_canonical_identity_after_session_end() -> None:
    generator, state, system = _sudo_generator()
    allocate_logon_id = Mock(
        side_effect=AssertionError("sudo fallback must not allocate a standalone LogonID")
    )
    state.allocate_logon_id = allocate_logon_id

    _generate_sudo_processes(
        generator,
        system,
        sudo_time=_SCENARIO_START + timedelta(seconds=30),
        lifecycle_group_id="sudo:first",
    )
    first = state.get_sessions_for_user("testuser")[0]
    assert state.end_session(first.logon_id, _SCENARIO_START + timedelta(minutes=1))

    _generate_sudo_processes(
        generator,
        system,
        sudo_time=_SCENARIO_START + timedelta(minutes=5),
        lifecycle_group_id="sudo:second",
        command="/usr/bin/hostname",
    )
    second = state.get_sessions_for_user("testuser")[0]

    assert allocate_logon_id.call_count == 0
    assert second.logon_id != first.logon_id
    assert second.ecar_object_id != first.ecar_object_id
    assert second.session_id != first.session_id
    assert {int(first.logon_id, 16), int(second.logon_id, 16)} <= state._used_logon_ids


def test_sudo_reuses_live_session_without_allocating_another_identity() -> None:
    generator, state, system = _sudo_generator()
    activity_time = _SCENARIO_START + timedelta(hours=1)
    logon_id = state.create_session(
        username="testuser",
        system=system.hostname,
        logon_type=2,
        source_ip="-",
        start_time=activity_time - timedelta(minutes=5),
        session_kind="interactive",
        session_id=0,
    )
    used_before = set(state._used_logon_ids)
    state.allocate_logon_id = Mock(
        side_effect=AssertionError("live session reuse must not allocate a standalone LogonID")
    )
    state.create_session = Mock(
        side_effect=AssertionError("live session reuse must not create another session")
    )

    sudo_pid, child_pid, _shift, _tty = _generate_sudo_processes(
        generator,
        system,
        sudo_time=activity_time,
        lifecycle_group_id="sudo:live",
    )

    assert sudo_pid > 0
    assert child_pid is not None
    assert state.get_session(logon_id) is not None
    assert state._used_logon_ids == used_before
    assert [session.logon_id for session in state.get_sessions_for_user("testuser")] == [logon_id]


@pytest.mark.parametrize(
    "sudo_time",
    [
        _SCENARIO_START + timedelta(seconds=30),
        _SCENARIO_START + timedelta(hours=1),
    ],
    ids=["carried-in", "in-window"],
)
def test_sudo_fallback_rendering_and_next_luid_are_deterministic(
    tmp_path: Path,
    sudo_time: datetime,
) -> None:
    first = _rendered_sudo_run(tmp_path / "first", sudo_time=sudo_time)
    second = _rendered_sudo_run(tmp_path / "second", sudo_time=sudo_time)

    assert second == first
