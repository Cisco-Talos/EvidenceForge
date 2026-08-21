# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused ownership tests for Linux sudo fallback session identities."""

import gc
import json
import random
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier, Event
from typing import Any
from unittest.mock import Mock, patch

import pytest

from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.formats.loader import load_format
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models import Scenario
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import System, User
from evidenceforge.models.state import ActiveSession
from evidenceforge.utils.files import load_yaml
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
    sudo_user: str = "testuser",
    tty: str = "pts/1",
) -> tuple[int, int | None, timedelta, str]:
    return generator.generate_linux_sudo_processes(
        system=system,
        sudo_time=sudo_time,
        child_time=sudo_time + timedelta(milliseconds=200),
        sudo_user=sudo_user,
        tty=tty,
        command=command,
        reserve_until=sudo_time + timedelta(seconds=2),
        lifecycle_group_id=lifecycle_group_id,
    )


def _probe_lock_callback(
    lock: Any,
    callbacks: list[tuple[str, bool]],
    name: str,
) -> None:
    """Record whether a hostile callback can acquire the sudo TTY mutex."""

    acquired = lock.acquire(blocking=False)
    callbacks.append((name, acquired))
    if acquired:
        lock.release()


class _CallbackStr(str):
    """A string subclass whose equality and hash operations probe the mutex."""

    lock: Any
    callbacks: list[tuple[str, bool]]

    def __new__(
        cls,
        value: str,
        *,
        lock: Any,
        callbacks: list[tuple[str, bool]],
    ) -> "_CallbackStr":
        instance = super().__new__(cls, value)
        instance.lock = lock
        instance.callbacks = callbacks
        return instance

    def __hash__(self) -> int:
        _probe_lock_callback(self.lock, self.callbacks, "hash")
        return str.__hash__(self)

    def __eq__(self, other: object) -> bool:
        _probe_lock_callback(self.lock, self.callbacks, "eq")
        return bool(str.__eq__(self, other))

    def __ne__(self, other: object) -> bool:
        _probe_lock_callback(self.lock, self.callbacks, "eq")
        return bool(str.__ne__(self, other))


class _CallbackOwner:
    """An inverse owner value whose equality probes the mutex."""

    def __init__(self, lock: Any, callbacks: list[tuple[str, bool]]) -> None:
        self.lock = lock
        self.callbacks = callbacks

    def __eq__(self, other: object) -> bool:
        _probe_lock_callback(self.lock, self.callbacks, "owner-eq")
        return False


class _DestructorProbe:
    """Report the lock state when the last reference is released."""

    def __init__(self, lock: Any, callbacks: list[tuple[str, bool]]) -> None:
        self.lock = lock
        self.callbacks = callbacks

    def __del__(self) -> None:
        _probe_lock_callback(self.lock, self.callbacks, "destructor")


class _CallbackMap(dict[object, object]):
    """A caller-replaceable mapping whose complete callback surface probes the mutex."""

    def __init__(
        self,
        lock: Any,
        callbacks: list[tuple[str, bool]],
        destructor_probe: _DestructorProbe,
    ) -> None:
        super().__init__()
        self.lock = lock
        self.callbacks = callbacks
        self.destructor_probe: _DestructorProbe | None = destructor_probe

    def __setitem__(self, key: object, value: object) -> None:
        _probe_lock_callback(self.lock, self.callbacks, "setitem")
        self.destructor_probe = None
        dict.__setitem__(self, key, value)

    def __getitem__(self, key: object) -> object:
        _probe_lock_callback(self.lock, self.callbacks, "getitem")
        return dict.__getitem__(self, key)

    def get(self, key: object, default: object = None) -> object:
        _probe_lock_callback(self.lock, self.callbacks, "get")
        return dict.get(self, key, default)

    def items(self) -> object:
        _probe_lock_callback(self.lock, self.callbacks, "items")
        return dict.items(self)


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


def _strict_sudo_generator(
    output_path: Path,
) -> tuple[GenerationEngine, ActivityGenerator, StateManager, System]:
    scenario_path = (
        Path(__file__).parent.parent / "fixtures" / "scenarios" / ("smb-linux-matrix.yaml")
    )
    engine = GenerationEngine(Scenario(**load_yaml(scenario_path)), output_path)

    def initialize_without_emitters() -> None:
        engine.emitters = {}

    with patch.object(engine, "_init_emitters", side_effect=initialize_without_emitters):
        engine._initialize()

    generator = engine.activity_generator
    assert isinstance(generator, ActivityGenerator)
    system = next(
        candidate
        for candidate in engine.scenario.environment.systems
        if candidate.hostname == "LNX-CLIENT-01"
    )
    return engine, generator, engine.state_manager, system


def _sudo_tty_state(
    generator: ActivityGenerator,
) -> tuple[dict[object, object], ...]:
    return (
        dict(generator._linux_sudo_tty_assignments),
        dict(generator._linux_sudo_tty_owners),
        dict(getattr(generator, "_linux_sudo_tty_capacity_claims", {})),
        dict(getattr(generator, "_linux_sudo_tty_sessions", {})),
        dict(getattr(generator, "_linux_sudo_tty_available", {})),
        {
            logon_id: set(tty_keys)
            for logon_id, tty_keys in getattr(
                generator,
                "_linux_sudo_tty_keys_by_logon_id",
                {},
            ).items()
        },
    )


def _materialize_strict_session(
    engine: GenerationEngine,
    state: StateManager,
    system: System,
    user: User,
    *,
    session_id: int,
    lifecycle_group_id: str,
) -> ActiveSession:
    """Create one exact live session without child processes."""

    plan = state.plan_session_materialization(
        username=user.username,
        system=system.hostname,
        logon_type=2,
        source_ip="-",
        start_time=engine.start_time + timedelta(seconds=15),
        session_kind="interactive",
        lifecycle_group_id=lifecycle_group_id,
        session_id=session_id,
    )
    session, receipt = engine.lifecycle_authority.materialize_session(plan)
    assert engine.lifecycle_authority.authenticates_materialization_receipt(plan, receipt)
    return session


def _materialize_strict_sudo_tty_route(
    engine: GenerationEngine,
    generator: ActivityGenerator,
    state: StateManager,
    system: System,
    user: User,
    *,
    session_id: int,
    lifecycle_group_id: str,
) -> tuple[ActiveSession, tuple[str, str, str]]:
    """Create one exact live session and bind a sudo TTY without child processes."""

    session = _materialize_strict_session(
        engine,
        state,
        system,
        user,
        session_id=session_id,
        lifecycle_group_id=lifecycle_group_id,
    )
    tty_key = (system.hostname, user.username, "pts/1")
    generator._linux_sudo_tty_assignments[tty_key] = tty_key[2]
    generator._linux_sudo_tty_owners[(system.hostname, tty_key[2])] = tty_key
    generator._remember_linux_sudo_tty_session(
        tty_key,
        session.logon_id,
        available_until=session.start_time + timedelta(seconds=30),
        session=session,
    )
    return session, tty_key


def _seed_sudo_tty_pairs(
    generator: ActivityGenerator,
    *,
    hostname: str,
    count: int,
) -> None:
    """Populate exact unrelated forward/inverse TTY pairs near the hard census."""

    for ordinal in range(count):
        tty = f"pts/{10_000 + ordinal}"
        requested_key = (hostname, f"seed-user-{ordinal}", tty)
        dict.__setitem__(generator._linux_sudo_tty_assignments, requested_key, tty)
        dict.__setitem__(
            generator._linux_sudo_tty_owners,
            (hostname, tty),
            requested_key,
        )


def _strict_rendered_sudo_run(
    output_path: Path,
    *,
    threaded: bool,
) -> tuple[tuple[tuple[str, bytes], ...], str, int, str, int, int]:
    if hasattr(_thread_local, "rng"):
        del _thread_local.rng
    random.seed(42)
    scenario_path = (
        Path(__file__).parent.parent / "fixtures" / "scenarios" / ("smb-linux-matrix.yaml")
    )
    engine = GenerationEngine(Scenario(**load_yaml(scenario_path)), output_path)

    def initialize_ecar() -> None:
        engine.emitters = {
            "ecar": EcarEmitter(load_format("ecar"), output_path, threaded=threaded),
        }

    with patch.object(engine, "_init_emitters", side_effect=initialize_ecar):
        engine._initialize()

    generator = engine.activity_generator
    assert isinstance(generator, ActivityGenerator)
    system = next(
        candidate
        for candidate in engine.scenario.environment.systems
        if candidate.hostname == "LNX-CLIENT-01"
    )
    try:
        _generate_sudo_processes(
            generator,
            system,
            sudo_time=engine.start_time + timedelta(seconds=30),
            lifecycle_group_id="sudo:strict-rendered",
            sudo_user="linux_user",
        )
        session = engine.state_manager.get_sessions_for_user("linux_user")[0]
        next_logon_id = engine.state_manager.allocate_logon_id(
            system.hostname,
            engine.start_time + timedelta(hours=2),
        )
        next_logind_id = engine.state_manager.next_linux_logind_session_id(
            system.hostname,
            random.Random(90210),
            engine.start_time + timedelta(hours=2),
        )
    finally:
        engine._close_emitters()

    rendered = tuple(
        (str(path.relative_to(output_path)), path.read_bytes())
        for path in sorted(output_path.rglob("ecar.json"))
    )
    login_count = sum(
        1
        for _path, content in rendered
        for line in content.splitlines()
        if (row := json.loads(line))["object"] == "USER_SESSION" and row["action"] == "LOGIN"
    )
    return (
        rendered,
        session.logon_id,
        session.session_id,
        next_logon_id,
        next_logind_id,
        login_count,
    )


def test_strict_carried_in_sudo_materializes_session_before_shell(tmp_path: Path) -> None:
    engine, generator, state, system = _strict_sudo_generator(tmp_path)
    authority = engine.lifecycle_authority

    with (
        patch.object(
            state,
            "plan_session_materialization",
            wraps=state.plan_session_materialization,
        ) as plan_session,
        patch.object(
            state,
            "plan_linux_logind_session_materialization",
            wraps=state.plan_linux_logind_session_materialization,
        ) as plan_logind,
        patch.object(
            authority,
            "materialize_session",
            wraps=authority.materialize_session,
        ) as materialize_session,
        patch.object(
            generator,
            "_ensure_linux_local_session_id",
            side_effect=AssertionError("strict carried-in sudo used postcommit logind allocation"),
        ),
        patch.object(
            authority,
            "ensure_session",
            side_effect=AssertionError("strict carried-in sudo used lifecycle backfill"),
        ),
    ):
        sudo_pid, child_pid, _shift, assigned_tty = _generate_sudo_processes(
            generator,
            system,
            sudo_time=engine.start_time + timedelta(seconds=30),
            lifecycle_group_id="sudo:strict-carried-in",
            sudo_user="linux_user",
        )

    plan_session.assert_called_once()
    plan_logind.assert_called_once()
    materialize_session.assert_called_once()
    assert plan_session.call_args.kwargs["session_id"] == 0
    assert sudo_pid > 0
    assert child_pid is not None
    assert assigned_tty == "pts/1"
    sessions = state.get_sessions_for_user("linux_user")
    assert len(sessions) == 1
    session = sessions[0]
    assert session.start_time < engine.start_time
    assert session.session_id > 0
    identity = state.get_session_identity(session.logon_id)
    assert identity is not None
    snapshot = engine.lifecycle_registry.get_session(session.ecar_object_id)
    assert snapshot is not None
    assert snapshot.closed_at is None
    assert snapshot.identity == LifecycleShadow.project_session_start(identity)
    census = authority.census()
    assert census.bootstrapped_sessions == 0
    assert engine.lifecycle_shadow.violation_summary["total"] == 0


def test_strict_sudo_replaces_historically_active_closed_session_owner(
    tmp_path: Path,
) -> None:
    engine, generator, state, system = _strict_sudo_generator(tmp_path)
    user = next(
        candidate
        for candidate in engine.scenario.environment.users
        if candidate.username == "linux_user"
    )
    historical_plan = state.plan_session_materialization(
        username=user.username,
        system=system.hostname,
        logon_type=10,
        source_ip="10.30.0.99",
        source_port=51249,
        start_time=engine.start_time - timedelta(minutes=5),
        session_kind="ssh",
        lifecycle_group_id="sudo:historical-ssh-owner",
        session_id=349741,
    )
    historical_session, historical_receipt = engine.lifecycle_authority.materialize_session(
        historical_plan
    )
    assert engine.lifecycle_authority.authenticates_materialization_receipt(
        historical_plan,
        historical_receipt,
    )

    generator.generate_logoff(
        user,
        system,
        engine.start_time + timedelta(minutes=2),
        historical_session.logon_id,
        logon_type=10,
        from_storyline=True,
    )
    historical_snapshot = engine.lifecycle_registry.get_session(historical_session.ecar_object_id)
    assert historical_snapshot is not None
    assert historical_snapshot.closed_at is not None
    tty_key = (system.hostname, user.username, "pts/1")
    generator._linux_sudo_tty_sessions[tty_key] = historical_session.logon_id

    sudo_pid, child_pid, _shift, _tty = _generate_sudo_processes(
        generator,
        system,
        sudo_time=engine.start_time + timedelta(seconds=30),
        lifecycle_group_id="sudo:after-historical-ssh-close",
        sudo_user=user.username,
    )

    assert sudo_pid > 0
    assert child_pid is not None
    sudo_process = state.get_process(system.hostname, sudo_pid)
    assert sudo_process is not None
    assert sudo_process.logon_id != historical_session.logon_id
    replacement = state.get_session(sudo_process.logon_id)
    assert replacement is not None
    replacement_snapshot = engine.lifecycle_registry.get_session(replacement.ecar_object_id)
    assert replacement_snapshot is not None
    assert replacement_snapshot.closed_at is None
    assert generator._linux_sudo_tty_sessions[tty_key] == replacement.logon_id
    assert len(generator._linux_sudo_tty_sessions) == 1
    assert generator._linux_sudo_tty_assignments == {tty_key: "pts/1"}
    assert generator._linux_sudo_tty_owners == {
        (system.hostname, "pts/1"): tty_key,
    }
    assert not generator._linux_sudo_tty_capacity_claims


def test_strict_sudo_bootstrap_does_not_reuse_closed_local_session_owner(
    tmp_path: Path,
) -> None:
    engine, generator, state, system = _strict_sudo_generator(tmp_path)
    user = next(
        candidate
        for candidate in engine.scenario.environment.users
        if candidate.username == "linux_user"
    )
    historical_plan = state.plan_session_materialization(
        username=user.username,
        system=system.hostname,
        logon_type=2,
        source_ip="-",
        source_port=0,
        start_time=engine.start_time + timedelta(minutes=5),
        session_kind="interactive",
        lifecycle_group_id="sudo:historical-local-owner",
        session_id=349742,
    )
    historical_session, historical_receipt = engine.lifecycle_authority.materialize_session(
        historical_plan
    )
    assert engine.lifecycle_authority.authenticates_materialization_receipt(
        historical_plan,
        historical_receipt,
    )
    generator.generate_logoff(
        user,
        system,
        engine.start_time + timedelta(minutes=30),
        historical_session.logon_id,
        logon_type=2,
        from_storyline=True,
    )

    with patch.object(
        generator, "generate_logon", wraps=generator.generate_logon
    ) as generate_logon:
        sudo_pid, child_pid, _shift, _tty = _generate_sudo_processes(
            generator,
            system,
            sudo_time=engine.start_time + timedelta(minutes=20),
            lifecycle_group_id="sudo:after-historical-local-close",
            sudo_user=user.username,
        )

    generate_logon.assert_called_once()
    assert sudo_pid > 0
    assert child_pid is not None
    sudo_process = state.get_process(system.hostname, sudo_pid)
    assert sudo_process is not None
    assert sudo_process.logon_id != historical_session.logon_id
    replacement = state.get_session(sudo_process.logon_id)
    assert replacement is not None
    replacement_snapshot = engine.lifecycle_registry.get_session(replacement.ecar_object_id)
    assert replacement_snapshot is not None
    assert replacement_snapshot.closed_at is None


def test_strict_sudo_tty_route_releases_after_public_generic_session_close(
    tmp_path: Path,
) -> None:
    engine, generator, state, system = _strict_sudo_generator(tmp_path)
    user = next(
        candidate
        for candidate in engine.scenario.environment.users
        if candidate.username == "linux_user"
    )
    session, tty_key = _materialize_strict_sudo_tty_route(
        engine,
        generator,
        state,
        system,
        user,
        session_id=349_743,
        lifecycle_group_id="sudo:generic-close-success",
    )
    assert generator._linux_sudo_tty_sessions == {tty_key: session.logon_id}
    assert tty_key in generator._linux_sudo_tty_available

    generator.generate_logoff(
        user,
        system,
        session.start_time + timedelta(minutes=5),
        session.logon_id,
        logon_type=2,
        from_storyline=True,
    )

    lifecycle = engine.lifecycle_registry.get_session(session.ecar_object_id)
    assert state.get_session(session.logon_id) is None
    assert lifecycle is not None and lifecycle.closed_at is not None
    assert tty_key not in generator._linux_sudo_tty_sessions
    assert tty_key not in generator._linux_sudo_tty_available
    assert not generator._linux_sudo_tty_assignments
    assert not generator._linux_sudo_tty_owners
    assert not generator._linux_sudo_tty_keys_by_logon_id


def test_strict_sudo_tty_route_survives_rejected_generic_close_and_retry(
    tmp_path: Path,
) -> None:
    engine, generator, state, system = _strict_sudo_generator(tmp_path)
    user = next(
        candidate
        for candidate in engine.scenario.environment.users
        if candidate.username == "linux_user"
    )
    session, _tty_key = _materialize_strict_sudo_tty_route(
        engine,
        generator,
        state,
        system,
        user,
        session_id=349_744,
        lifecycle_group_id="sudo:generic-close-retry",
    )
    snapshot_before = _sudo_tty_state(generator)
    original_dispatch = generator.dispatcher.dispatch_builder

    def reject_logoff(event: object) -> object:
        if getattr(event, "event_type", "") == "logoff":
            raise RuntimeError("injected generic close rejection")
        return original_dispatch(event)  # type: ignore[arg-type]

    with patch.object(generator.dispatcher, "dispatch_builder", side_effect=reject_logoff):
        with pytest.raises(RuntimeError, match="generic close rejection"):
            generator.generate_logoff(
                user,
                system,
                session.start_time + timedelta(minutes=5),
                session.logon_id,
                logon_type=2,
                from_storyline=True,
            )

    lifecycle = engine.lifecycle_registry.get_session(session.ecar_object_id)
    assert state.get_session(session.logon_id) is session
    assert lifecycle is not None and lifecycle.closed_at is None
    assert _sudo_tty_state(generator) == snapshot_before

    generator.generate_logoff(
        user,
        system,
        session.start_time + timedelta(minutes=5),
        session.logon_id,
        logon_type=2,
        from_storyline=True,
    )

    assert state.get_session(session.logon_id) is None
    assert not generator._linux_sudo_tty_sessions
    assert not generator._linux_sudo_tty_keys_by_logon_id


def test_strict_sudo_tty_route_survives_prepared_but_unclosed_generic_lifecycle(
    tmp_path: Path,
) -> None:
    engine, generator, state, system = _strict_sudo_generator(tmp_path)
    user = next(
        candidate
        for candidate in engine.scenario.environment.users
        if candidate.username == "linux_user"
    )
    sudo_time = engine.start_time + timedelta(seconds=30)
    generator.generate_linux_sudo_session(
        system=system,
        time=sudo_time,
        command_message=(
            "linux_user : TTY=pts/1 ; PWD=/home/linux_user ; USER=root ; COMMAND=/usr/bin/id"
        ),
        sudo_user=user.username,
        uid=1000,
        runtime=timedelta(seconds=2),
    )
    session = state.get_sessions_for_user(user.username)[0]
    snapshot_before = _sudo_tty_state(generator)

    with pytest.raises(StateError, match="exact accepted lifecycle close ownership"):
        generator.generate_logoff(
            user,
            system,
            sudo_time + timedelta(minutes=5),
            session.logon_id,
            logon_type=2,
            from_storyline=True,
        )

    lifecycle = engine.lifecycle_registry.get_session(session.ecar_object_id)
    assert state.get_session(session.logon_id) is None
    assert lifecycle is not None
    assert lifecycle.close_barrier is not None
    assert lifecycle.closure_ticket is not None
    assert lifecycle.closed_at is None
    assert _sudo_tty_state(generator) == snapshot_before


def test_strict_sudo_tty_close_at_inverse_postcommit_rolls_back_pair_and_retries(
    tmp_path: Path,
) -> None:
    engine, generator, state, system = _strict_sudo_generator(tmp_path)
    user = next(
        candidate
        for candidate in engine.scenario.environment.users
        if candidate.username == "linux_user"
    )
    session = _materialize_strict_session(
        engine,
        state,
        system,
        user,
        session_id=349_745,
        lifecycle_group_id="sudo:inverse-postcommit-close",
    )
    _seed_sudo_tty_pairs(generator, hostname=system.hostname, count=3)
    tty_before = _sudo_tty_state(generator)
    processes_before = tuple(state.list_running_processes())
    close_time = session.start_time + timedelta(minutes=5)

    def close_after_exact_pair(phase: str) -> None:
        if phase != "inverse-postcommit":
            return
        generator._linux_sudo_tty_publication_hook = None
        generator.generate_logoff(
            user,
            system,
            close_time,
            session.logon_id,
            logon_type=2,
            from_storyline=True,
        )

    generator._linux_sudo_tty_publication_hook = close_after_exact_pair
    with pytest.raises(StateError, match="exact lifecycle ownership"):
        _generate_sudo_processes(
            generator,
            system,
            sudo_time=engine.start_time + timedelta(seconds=30),
            lifecycle_group_id="sudo:inverse-postcommit-close:first",
            sudo_user=user.username,
        )

    closed = engine.lifecycle_registry.get_session(session.ecar_object_id)
    assert state.get_session(session.logon_id) is None
    assert closed is not None and closed.closed_at is not None
    assert tuple(state.list_running_processes()) == processes_before
    assert _sudo_tty_state(generator) == tty_before

    sudo_pid, child_pid, _shift, assigned_tty = _generate_sudo_processes(
        generator,
        system,
        sudo_time=engine.start_time + timedelta(seconds=30),
        lifecycle_group_id="sudo:inverse-postcommit-close:retry",
        sudo_user=user.username,
    )

    assert sudo_pid > 0 and child_pid is not None
    assert assigned_tty == "pts/1"
    replacement = state.get_session(
        generator._linux_sudo_tty_sessions[(system.hostname, user.username, assigned_tty)]
    )
    assert replacement is not None
    assert replacement.logon_id != session.logon_id
    assert not generator._linux_sudo_tty_capacity_claims


def test_strict_sudo_tty_route_releases_after_public_exact_ssh_close(
    tmp_path: Path,
) -> None:
    engine, generator, state, system = _strict_sudo_generator(tmp_path)
    user = next(
        candidate
        for candidate in engine.scenario.environment.users
        if candidate.username == "linux_user"
    )
    ssh_time = engine.start_time + timedelta(minutes=10)
    generator.generate_ssh_session(
        user=user,
        target_system=system,
        time=ssh_time,
        source_ip="10.30.0.99",
        source_port=51249,
        duration=180.0,
        emit_session_close=True,
        defer_session_close=True,
    )
    session = state.get_active_sessions_for_user_at(
        user.username,
        ssh_time + timedelta(minutes=1),
    )[0]
    generator.generate_linux_sudo_session(
        system=system,
        time=session.start_time + timedelta(seconds=30),
        command_message=(
            "linux_user : TTY=pts/1 ; PWD=/home/linux_user ; USER=root ; COMMAND=/usr/bin/id"
        ),
        sudo_user=user.username,
        uid=1000,
        runtime=timedelta(seconds=2),
    )
    tty_key = (system.hostname, user.username, "pts/1")
    assert generator._linux_sudo_tty_sessions == {tty_key: session.logon_id}
    assert generator.ssh_close_journal_census().total_pending == 1

    generator.finalize_ssh_session_lifecycles(session.network_close_time + timedelta(minutes=1))

    snapshot = engine.lifecycle_registry.get_session(session.ecar_object_id)
    assert state.get_session(session.logon_id) is None
    assert snapshot is not None and snapshot.closed_at is not None
    assert generator.ssh_close_journal_census().total_pending == 0
    assert not generator._linux_sudo_tty_assignments
    assert not generator._linux_sudo_tty_owners
    assert not generator._linux_sudo_tty_sessions
    assert not generator._linux_sudo_tty_available
    assert not generator._linux_sudo_tty_keys_by_logon_id


def test_sudo_tty_reverse_release_is_exact_idempotent_and_plateaus() -> None:
    generator, _state, system = _sudo_generator()
    hostname = system.hostname
    username = "testuser"
    old_logon_id = "0xold"
    new_logon_id = "0xnew"
    main_requested = (hostname, username, "pts/1")
    main_actual = (hostname, username, "pts/2")
    second_key = (hostname, username, "pts/3")
    foreign_key = ("OTHER-LINUX-01", "other", "pts/9")

    for requested_key, actual_key in (
        (main_requested, main_actual),
        (second_key, second_key),
        (foreign_key, foreign_key),
    ):
        generator._linux_sudo_tty_assignments[requested_key] = actual_key[2]
        generator._linux_sudo_tty_owners[(actual_key[0], actual_key[2])] = requested_key
        generator._remember_linux_sudo_tty_session(
            actual_key,
            old_logon_id,
            available_until=_SCENARIO_START + timedelta(seconds=1),
        )

    generator._remember_linux_sudo_tty_session(
        main_actual,
        new_logon_id,
        available_until=_SCENARIO_START + timedelta(seconds=2),
    )

    released = generator._release_session_retention_state(
        hostname=hostname,
        username=username,
        logon_id=old_logon_id,
    )

    assert released.sudo_tty_rows == 5
    assert generator._linux_sudo_tty_sessions == {
        main_actual: new_logon_id,
        foreign_key: old_logon_id,
    }
    assert generator._linux_sudo_tty_keys_by_logon_id == {
        old_logon_id: {foreign_key},
        new_logon_id: {main_actual},
    }
    assert main_requested in generator._linux_sudo_tty_assignments
    assert second_key not in generator._linux_sudo_tty_assignments
    assert foreign_key in generator._linux_sudo_tty_assignments
    assert (
        generator._release_session_retention_state(
            hostname=hostname,
            username=username,
            logon_id=old_logon_id,
        ).total_rows
        == 0
    )

    generator._release_session_retention_state(
        hostname=foreign_key[0],
        username=foreign_key[1],
        logon_id=old_logon_id,
    )
    generator._release_session_retention_state(
        hostname=hostname,
        username=username,
        logon_id=new_logon_id,
    )
    assert not generator._linux_sudo_tty_assignments
    assert not generator._linux_sudo_tty_owners
    assert not generator._linux_sudo_tty_sessions
    assert not generator._linux_sudo_tty_available
    assert not generator._linux_sudo_tty_keys_by_logon_id

    plateau_key = (hostname, username, "pts/7")
    for ordinal in range(256):
        logon_id = f"0xplateau-{ordinal:x}"
        generator._linux_sudo_tty_assignments[plateau_key] = plateau_key[2]
        generator._linux_sudo_tty_owners[(hostname, plateau_key[2])] = plateau_key
        generator._remember_linux_sudo_tty_session(
            plateau_key,
            logon_id,
            available_until=_SCENARIO_START + timedelta(seconds=ordinal),
        )
        assert generator._linux_sudo_tty_keys_by_logon_id == {logon_id: {plateau_key}}
        assert (
            generator._release_session_retention_state(
                hostname=hostname,
                username=username,
                logon_id=logon_id,
            ).sudo_tty_rows
            == 5
        )
        assert sum(len(mapping) for mapping in _sudo_tty_state(generator)) == 0


def test_strict_sudo_tty_namespace_is_host_local_and_retry_exact(tmp_path: Path) -> None:
    engine, generator, state, first_system = _strict_sudo_generator(tmp_path)
    second_system = next(
        candidate
        for candidate in engine.scenario.environment.systems
        if candidate.hostname == "SAMBA-01"
    )

    first = _generate_sudo_processes(
        generator,
        first_system,
        sudo_time=engine.start_time + timedelta(seconds=30),
        lifecycle_group_id="sudo:host-local:first",
        sudo_user="linux_user",
    )
    second = _generate_sudo_processes(
        generator,
        second_system,
        sudo_time=engine.start_time + timedelta(seconds=30),
        lifecycle_group_id="sudo:host-local:second",
        sudo_user="linux_user",
    )
    sessions_after_first_pass = tuple(state.get_sessions_for_user("linux_user"))
    used_logon_ids = set(state._used_logon_ids)
    used_logind_ids = {
        hostname: set(state._linux_logind_session_used_ids[hostname])
        for hostname in (first_system.hostname, second_system.hostname)
    }

    first_retry = _generate_sudo_processes(
        generator,
        first_system,
        sudo_time=engine.start_time + timedelta(seconds=30),
        lifecycle_group_id="sudo:host-local:first-retry",
        command="/usr/bin/hostname",
        sudo_user="linux_user",
    )
    second_retry = _generate_sudo_processes(
        generator,
        second_system,
        sudo_time=engine.start_time + timedelta(seconds=30),
        lifecycle_group_id="sudo:host-local:second-retry",
        command="/usr/bin/hostname",
        sudo_user="linux_user",
    )

    assert all(result[0] > 0 and result[1] is not None for result in (first, second))
    assert all(result[0] > 0 and result[1] is not None for result in (first_retry, second_retry))
    assert {first[3], second[3], first_retry[3], second_retry[3]} == {"pts/1"}
    sessions = tuple(state.get_sessions_for_user("linux_user"))
    assert sessions == sessions_after_first_pass
    assert {session.system for session in sessions} == {
        first_system.hostname,
        second_system.hostname,
    }
    assert state._used_logon_ids == used_logon_ids
    assert {
        hostname: set(state._linux_logind_session_used_ids[hostname])
        for hostname in (first_system.hostname, second_system.hostname)
    } == used_logind_ids
    for system in (first_system, second_system):
        requested_key = (system.hostname, "linux_user", "pts/1")
        assert generator._linux_sudo_tty_assignments[requested_key] == "pts/1"
        assert generator._linux_sudo_tty_owners[(system.hostname, "pts/1")] == requested_key


def test_strict_carried_in_sudo_session_precommit_rejection_is_neutral(
    tmp_path: Path,
) -> None:
    engine, generator, state, system = _strict_sudo_generator(tmp_path)
    authority = engine.lifecycle_authority
    state_before = state.materialization_digest()
    registry_before = engine.lifecycle_registry.stats()
    tty_before = _sudo_tty_state(generator)
    reject = Mock(side_effect=RuntimeError("injected sudo session precommit rejection"))
    authority._materialization_precommit_hook = reject

    try:
        with pytest.raises(RuntimeError, match="sudo session precommit rejection"):
            _generate_sudo_processes(
                generator,
                system,
                sudo_time=engine.start_time + timedelta(seconds=30),
                lifecycle_group_id="sudo:strict-precommit",
                sudo_user="linux_user",
            )
    finally:
        authority._materialization_precommit_hook = None

    reject.assert_called_once_with()
    assert state.materialization_digest() == state_before
    assert engine.lifecycle_registry.stats() == registry_before
    assert _sudo_tty_state(generator) == tty_before


@pytest.mark.parametrize(
    "lost_return",
    [False, True],
    ids=["claim-fail-before", "claim-lost-return"],
)
def test_strict_sudo_tty_capacity_claim_failure_is_neutral_and_retry_exact(
    tmp_path: Path,
    lost_return: bool,
) -> None:
    engine, generator, state, system = _strict_sudo_generator(tmp_path)
    authority = engine.lifecycle_authority
    original_reconcile = generator._reconcile_linux_sudo_tty_assignment
    injected = False
    state_before = state.materialization_digest()
    registry_before = engine.lifecycle_registry.stats()
    tty_before = _sudo_tty_state(generator)
    processes_before = tuple(state.list_running_processes())

    def inject_capacity_claim_failure(**kwargs: Any) -> str:
        nonlocal injected
        is_initial_claim = (
            kwargs.get("capacity_claim") is not None
            and kwargs.get("release_capacity_claim", False) is False
            and kwargs.get("publish") is False
            and kwargs.get("assigned_tty") is None
        )
        if is_initial_claim and not injected:
            injected = True
            if lost_return:
                original_reconcile(**kwargs)
            raise RuntimeError("injected sudo TTY capacity claim failure")
        return original_reconcile(**kwargs)

    with (
        patch.object(
            generator,
            "_reconcile_linux_sudo_tty_assignment",
            side_effect=inject_capacity_claim_failure,
        ),
        patch.object(
            authority,
            "materialize_session",
            wraps=authority.materialize_session,
        ) as materialize_session,
    ):
        with pytest.raises(RuntimeError, match="TTY capacity claim failure"):
            _generate_sudo_processes(
                generator,
                system,
                sudo_time=engine.start_time + timedelta(seconds=30),
                lifecycle_group_id=f"sudo:capacity-claim-failure:{lost_return}",
                sudo_user="linux_user",
            )

        materialize_session.assert_not_called()
        assert state.materialization_digest() == state_before
        assert engine.lifecycle_registry.stats() == registry_before
        assert tuple(state.list_running_processes()) == processes_before
        assert _sudo_tty_state(generator) == tty_before

        sudo_pid, child_pid, _shift, assigned_tty = _generate_sudo_processes(
            generator,
            system,
            sudo_time=engine.start_time + timedelta(seconds=30),
            lifecycle_group_id=f"sudo:capacity-claim-retry:{lost_return}",
            command="/usr/bin/hostname",
            sudo_user="linux_user",
        )

    materialize_session.assert_called_once()
    assert sudo_pid > 0 and child_pid is not None
    assert assigned_tty == "pts/1"
    assert not generator._linux_sudo_tty_capacity_claims


def test_strict_carried_in_sudo_session_lost_return_reuses_exact_owner(
    tmp_path: Path,
) -> None:
    engine, generator, state, system = _strict_sudo_generator(tmp_path)
    authority = engine.lifecycle_authority
    registry_sessions_before = engine.lifecycle_registry.stats().live_sessions
    original_materialize = authority.materialize_session

    def commit_then_raise(*args: object, **kwargs: object) -> object:
        original_materialize(*args, **kwargs)
        raise RuntimeError("injected sudo session materialization lost return")

    with patch.object(
        authority,
        "materialize_session",
        side_effect=commit_then_raise,
    ) as materialize_session:
        first = _generate_sudo_processes(
            generator,
            system,
            sudo_time=engine.start_time + timedelta(seconds=30),
            lifecycle_group_id="sudo:strict-lost-return",
            sudo_user="linux_user",
        )
        session = state.get_sessions_for_user("linux_user")[0]
        identity = state.get_session_identity(session.logon_id)
        used_logon_ids = set(state._used_logon_ids)
        used_logind_ids = set(state._linux_logind_session_used_ids[system.hostname])
        second = _generate_sudo_processes(
            generator,
            system,
            sudo_time=engine.start_time + timedelta(seconds=30),
            lifecycle_group_id="sudo:strict-lost-return-retry",
            command="/usr/bin/hostname",
            sudo_user="linux_user",
        )

    materialize_session.assert_called_once()
    assert first[0] > 0 and first[1] is not None
    assert second[0] > 0 and second[1] is not None
    assert len(state.get_sessions_for_user("linux_user")) == 1
    assert state.get_session_identity(session.logon_id) == identity
    assert state._used_logon_ids == used_logon_ids
    assert state._linux_logind_session_used_ids[system.hostname] == used_logind_ids
    assert engine.lifecycle_registry.stats().live_sessions == registry_sessions_before + 1
    assert identity is not None
    snapshot = engine.lifecycle_registry.get_session(identity.object_id)
    assert snapshot is not None
    assert snapshot.identity == LifecycleShadow.project_session_start(identity)


@pytest.mark.parametrize(
    "malformed_shape",
    ["scalar", "list", "short-tuple", "long-tuple"],
)
def test_strict_carried_in_sudo_rejects_malformed_materialization_return_shape(
    tmp_path: Path,
    malformed_shape: str,
) -> None:
    engine, generator, state, system = _strict_sudo_generator(tmp_path)
    authority = engine.lifecycle_authority
    original_materialize = authority.materialize_session
    planned_results: list[tuple[Any, Any, Any]] = []
    tty_before = _sudo_tty_state(generator)
    processes_before = tuple(state.list_running_processes())

    def commit_then_return_malformed(plan: Any) -> object:
        planned_session, planned_receipt = original_materialize(plan)
        planned_results.append((plan, planned_session, planned_receipt))
        if malformed_shape == "scalar":
            return planned_session
        if malformed_shape == "list":
            return [planned_session, planned_receipt]
        if malformed_shape == "short-tuple":
            return (planned_session,)
        return planned_session, planned_receipt, planned_receipt

    with patch.object(
        authority,
        "materialize_session",
        side_effect=commit_then_return_malformed,
    ) as materialize_session:
        with pytest.raises(StateError, match="malformed materialization result"):
            _generate_sudo_processes(
                generator,
                system,
                sudo_time=engine.start_time + timedelta(seconds=30),
                lifecycle_group_id="sudo:malformed-return-rejected",
                sudo_user="linux_user",
            )

        assert _sudo_tty_state(generator) == tty_before
        assert tuple(state.list_running_processes()) == processes_before
        assert len(planned_results) == 1
        planned_plan, planned_session, planned_receipt = planned_results[0]
        assert authority.authenticates_materialization_receipt(planned_plan, planned_receipt)
        assert state.get_session(planned_plan.identity.logon_id) is planned_session
        used_logon_ids = set(state._used_logon_ids)
        used_logind_ids = set(state._linux_logind_session_used_ids[system.hostname])

        sudo_pid, child_pid, _shift, assigned_tty = _generate_sudo_processes(
            generator,
            system,
            sudo_time=engine.start_time + timedelta(seconds=30),
            lifecycle_group_id="sudo:malformed-return-retry",
            command="/usr/bin/hostname",
            sudo_user="linux_user",
        )

    materialize_session.assert_called_once()
    assert sudo_pid > 0 and child_pid is not None
    assert assigned_tty == "pts/1"
    assert state._used_logon_ids == used_logon_ids
    assert state._linux_logind_session_used_ids[system.hostname] == used_logind_ids
    sudo_process = state.get_process(system.hostname, sudo_pid)
    child_process = state.get_process(system.hostname, child_pid)
    assert sudo_process is not None and sudo_process.logon_id == planned_plan.identity.logon_id
    assert child_process is not None and child_process.logon_id == planned_plan.identity.logon_id


@pytest.mark.parametrize(
    "return_foreign_session",
    [True, False],
    ids=["foreign-session-and-receipt", "exact-session-foreign-receipt"],
)
def test_strict_carried_in_sudo_rejects_unauthenticated_materialization_return(
    tmp_path: Path,
    return_foreign_session: bool,
) -> None:
    engine, generator, state, system = _strict_sudo_generator(tmp_path)
    authority = engine.lifecycle_authority
    foreign_plan = state.plan_session_materialization(
        username="linux_user",
        system=system.hostname,
        logon_type=3,
        source_ip="10.0.0.99",
        start_time=engine.start_time - timedelta(minutes=10),
        session_kind="network",
        lifecycle_group_id="sudo:foreign-network-session",
        session_id=0,
    )
    foreign_session, foreign_receipt = authority.materialize_session(foreign_plan)
    assert authority.authenticates_materialization_receipt(foreign_plan, foreign_receipt)
    original_materialize = authority.materialize_session
    planned_results: list[tuple[Any, Any, Any]] = []
    tty_before = _sudo_tty_state(generator)
    processes_before = tuple(state.list_running_processes())

    def commit_planned_return_foreign(plan: Any) -> tuple[Any, Any]:
        planned_session, planned_receipt = original_materialize(plan)
        planned_results.append((plan, planned_session, planned_receipt))
        returned_session = foreign_session if return_foreign_session else planned_session
        return returned_session, foreign_receipt

    with patch.object(
        authority,
        "materialize_session",
        side_effect=commit_planned_return_foreign,
    ) as materialize_session:
        with pytest.raises(StateError, match="unauthenticated exact planned result"):
            _generate_sudo_processes(
                generator,
                system,
                sudo_time=engine.start_time + timedelta(seconds=30),
                lifecycle_group_id="sudo:unauthenticated-return-rejected",
                sudo_user="linux_user",
            )

        assert _sudo_tty_state(generator) == tty_before
        assert tuple(state.list_running_processes()) == processes_before
        assert len(planned_results) == 1
        planned_plan, planned_session, planned_receipt = planned_results[0]
        assert authority.authenticates_materialization_receipt(planned_plan, planned_receipt)
        assert state.get_session(planned_plan.identity.logon_id) is planned_session
        assert not authority.authenticates_materialization_receipt(
            planned_plan,
            foreign_receipt,
        )
        used_logon_ids = set(state._used_logon_ids)
        used_logind_ids = set(state._linux_logind_session_used_ids[system.hostname])

        sudo_pid, child_pid, _shift, assigned_tty = _generate_sudo_processes(
            generator,
            system,
            sudo_time=engine.start_time + timedelta(seconds=30),
            lifecycle_group_id="sudo:unauthenticated-return-retry",
            command="/usr/bin/hostname",
            sudo_user="linux_user",
        )

    materialize_session.assert_called_once()
    assert sudo_pid > 0 and child_pid is not None
    assert assigned_tty == "pts/1"
    assert state._used_logon_ids == used_logon_ids
    assert state._linux_logind_session_used_ids[system.hostname] == used_logind_ids
    sudo_process = state.get_process(system.hostname, sudo_pid)
    child_process = state.get_process(system.hostname, child_pid)
    assert sudo_process is not None and sudo_process.logon_id == planned_plan.identity.logon_id
    assert child_process is not None and child_process.logon_id == planned_plan.identity.logon_id
    assert (
        generator._linux_sudo_tty_sessions[(system.hostname, "linux_user", assigned_tty)]
        == planned_plan.identity.logon_id
    )
    assert all(
        process.logon_id != foreign_session.logon_id for process in state.list_running_processes()
    )


@pytest.mark.parametrize(
    "interrupt_type",
    [KeyboardInterrupt, SystemExit],
    ids=["keyboard-interrupt", "system-exit"],
)
def test_strict_carried_in_sudo_materialization_interrupt_propagates_and_retries_exactly(
    tmp_path: Path,
    interrupt_type: type[BaseException],
) -> None:
    engine, generator, state, system = _strict_sudo_generator(tmp_path)
    authority = engine.lifecycle_authority
    original_materialize = authority.materialize_session
    committed: list[tuple[Any, Any, Any]] = []
    tty_before = _sudo_tty_state(generator)
    processes_before = tuple(state.list_running_processes())

    def commit_then_interrupt(plan: Any) -> None:
        session, receipt = original_materialize(plan)
        committed.append((plan, session, receipt))
        raise interrupt_type("injected sudo materialization interrupt")

    with patch.object(
        authority,
        "materialize_session",
        side_effect=commit_then_interrupt,
    ) as materialize_session:
        with pytest.raises(interrupt_type, match="sudo materialization interrupt"):
            _generate_sudo_processes(
                generator,
                system,
                sudo_time=engine.start_time + timedelta(seconds=30),
                lifecycle_group_id="sudo:materialization-interrupt",
                sudo_user="linux_user",
            )

        assert len(committed) == 1
        plan, session, receipt = committed[0]
        assert authority.authenticates_materialization_receipt(plan, receipt)
        assert state.get_session(plan.identity.logon_id) is session
        assert _sudo_tty_state(generator) == tty_before
        assert tuple(state.list_running_processes()) == processes_before
        used_logon_ids = set(state._used_logon_ids)
        used_logind_ids = set(state._linux_logind_session_used_ids[system.hostname])

        sudo_pid, child_pid, _shift, assigned_tty = _generate_sudo_processes(
            generator,
            system,
            sudo_time=engine.start_time + timedelta(seconds=30),
            lifecycle_group_id="sudo:materialization-interrupt-retry",
            command="/usr/bin/hostname",
            sudo_user="linux_user",
        )

    materialize_session.assert_called_once()
    assert sudo_pid > 0 and child_pid is not None
    assert assigned_tty == "pts/1"
    assert len(state.get_sessions_for_user("linux_user")) == 1
    assert state._used_logon_ids == used_logon_ids
    assert state._linux_logind_session_used_ids[system.hostname] == used_logind_ids
    assert not generator._linux_sudo_tty_capacity_claims


def test_strict_carried_in_sudo_rejects_state_only_reuse_without_backfill(
    tmp_path: Path,
) -> None:
    engine, generator, state, system = _strict_sudo_generator(tmp_path)
    logon_id = state.create_session(
        username="linux_user",
        system=system.hostname,
        logon_type=2,
        source_ip="-",
        start_time=engine.start_time - timedelta(minutes=5),
        session_kind="interactive",
        lifecycle_group_id="sudo:state-only",
        session_id=17,
    )
    session = state.get_session(logon_id)
    assert session is not None
    state_before = state.materialization_digest()
    registry_before = engine.lifecycle_registry.stats()
    authority_before = engine.lifecycle_authority.census()
    shadow_before = dict(engine.lifecycle_shadow.violation_summary)
    tty_before = _sudo_tty_state(generator)
    processes_before = tuple(state.list_running_processes())

    with patch.object(
        generator.dispatcher,
        "dispatch_builder",
        wraps=generator.dispatcher.dispatch_builder,
    ) as dispatch_builder:
        with pytest.raises(StateError, match="exact lifecycle ownership"):
            _generate_sudo_processes(
                generator,
                system,
                sudo_time=engine.start_time + timedelta(seconds=30),
                lifecycle_group_id="sudo:state-only-reuse",
                sudo_user="linux_user",
            )

    dispatch_builder.assert_not_called()
    assert state.materialization_digest() == state_before
    assert engine.lifecycle_registry.get_session(session.ecar_object_id) is None
    assert engine.lifecycle_registry.stats() == registry_before
    assert engine.lifecycle_authority.census() == authority_before
    assert engine.lifecycle_shadow.violation_summary == shadow_before
    assert tuple(state.list_running_processes()) == processes_before
    assert _sudo_tty_state(generator) == tty_before


def test_strict_sudo_rejects_foreign_lifecycle_identity_and_retries_exactly(
    tmp_path: Path,
) -> None:
    engine, generator, state, system = _strict_sudo_generator(tmp_path)
    candidate_plan = state.plan_session_materialization(
        username="linux_user",
        system=system.hostname,
        logon_type=2,
        source_ip="-",
        start_time=engine.start_time - timedelta(minutes=5),
        session_kind="interactive",
        lifecycle_group_id="sudo:identity-drift-candidate",
        session_id=41,
    )
    candidate, candidate_receipt = engine.lifecycle_authority.materialize_session(candidate_plan)
    assert engine.lifecycle_authority.authenticates_materialization_receipt(
        candidate_plan,
        candidate_receipt,
    )
    foreign_plan = state.plan_session_materialization(
        username="windows_user",
        system=system.hostname,
        logon_type=2,
        source_ip="-",
        start_time=engine.start_time - timedelta(minutes=4),
        session_kind="interactive",
        lifecycle_group_id="sudo:identity-drift-foreign",
        session_id=42,
    )
    foreign, foreign_receipt = engine.lifecycle_authority.materialize_session(foreign_plan)
    assert engine.lifecycle_authority.authenticates_materialization_receipt(
        foreign_plan,
        foreign_receipt,
    )
    foreign_snapshot = engine.lifecycle_registry.get_session(foreign.ecar_object_id)
    assert foreign_snapshot is not None
    original_get_session = engine.lifecycle_registry.get_session
    state_before = state.materialization_digest()
    registry_before = engine.lifecycle_registry.stats()
    authority_before = engine.lifecycle_authority.census()
    shadow_before = dict(engine.lifecycle_shadow.violation_summary)
    tty_before = _sudo_tty_state(generator)
    processes_before = tuple(state.list_running_processes())

    def return_foreign_snapshot(object_id: str) -> object:
        if object_id == candidate.ecar_object_id:
            return foreign_snapshot
        return original_get_session(object_id)

    with (
        patch.object(
            engine.lifecycle_registry,
            "get_session",
            side_effect=return_foreign_snapshot,
        ),
        patch.object(
            generator.dispatcher,
            "dispatch_builder",
            wraps=generator.dispatcher.dispatch_builder,
        ) as dispatch_builder,
    ):
        with pytest.raises(StateError, match="exact lifecycle ownership"):
            _generate_sudo_processes(
                generator,
                system,
                sudo_time=engine.start_time + timedelta(seconds=30),
                lifecycle_group_id="sudo:identity-drift-rejected",
                sudo_user="linux_user",
            )

    dispatch_builder.assert_not_called()
    assert state.materialization_digest() == state_before
    assert engine.lifecycle_registry.stats() == registry_before
    assert engine.lifecycle_authority.census() == authority_before
    assert engine.lifecycle_shadow.violation_summary == shadow_before
    assert tuple(state.list_running_processes()) == processes_before
    assert _sudo_tty_state(generator) == tty_before

    sudo_pid, child_pid, _shift, assigned_tty = _generate_sudo_processes(
        generator,
        system,
        sudo_time=engine.start_time + timedelta(seconds=30),
        lifecycle_group_id="sudo:identity-drift-retry",
        sudo_user="linux_user",
    )

    assert sudo_pid > 0 and child_pid is not None
    assert assigned_tty == "pts/1"
    sudo_process = state.get_process(system.hostname, sudo_pid)
    assert sudo_process is not None
    assert sudo_process.logon_id == candidate.logon_id


def test_strict_carried_in_sudo_rendering_and_allocators_are_deterministic(
    tmp_path: Path,
) -> None:
    serial = _strict_rendered_sudo_run(tmp_path / "serial", threaded=False)
    threaded = _strict_rendered_sudo_run(tmp_path / "threaded", threaded=True)

    assert threaded == serial
    assert serial[-1] == 0


@pytest.mark.parametrize(
    ("failure_phase", "forward_after_failure", "inverse_after_failure"),
    [
        ("forward-precommit", None, None),
        ("forward-postcommit", "pts/1", None),
        ("inverse-precommit", "pts/1", None),
        ("inverse-postcommit", "pts/1", "requested"),
    ],
    ids=[
        "assignment-fail-before",
        "assignment-lost-return",
        "owner-fail-before",
        "owner-lost-return",
    ],
)
def test_strict_sudo_tty_assignment_write_failure_retry_is_exact(
    tmp_path: Path,
    failure_phase: str,
    forward_after_failure: str | None,
    inverse_after_failure: str | None,
) -> None:
    engine, generator, state, system = _strict_sudo_generator(tmp_path)
    authority = engine.lifecycle_authority
    _seed_sudo_tty_pairs(generator, hostname=system.hostname, count=4_095)
    requested_key = (system.hostname, "linux_user", "pts/1")
    inverse_key = (system.hostname, "pts/1")
    callback_lock_states: list[bool] = []

    def fail_once(phase: str) -> None:
        acquired = generator._linux_sudo_tty_lock.acquire(blocking=False)
        callback_lock_states.append(acquired)
        if acquired:
            generator._linux_sudo_tty_lock.release()
        if phase == failure_phase:
            generator._linux_sudo_tty_publication_hook = None
            raise RuntimeError(f"injected TTY {failure_phase} write")

    generator._linux_sudo_tty_publication_hook = fail_once
    processes_before = {
        (process.system, process.pid, process.ecar_object_id)
        for process in state.list_running_processes()
    }
    registry_sessions_before = engine.lifecycle_registry.stats().live_sessions

    with patch.object(
        authority,
        "materialize_session",
        wraps=authority.materialize_session,
    ) as materialize_session:
        with pytest.raises(RuntimeError, match=f"TTY {failure_phase} write"):
            _generate_sudo_processes(
                generator,
                system,
                sudo_time=engine.start_time + timedelta(seconds=30),
                lifecycle_group_id=f"sudo:tty-{failure_phase}",
                sudo_user="linux_user",
            )

        sessions = state.get_sessions_for_user("linux_user")
        assert len(sessions) == 1
        session = sessions[0]
        identity = state.get_session_identity(session.logon_id)
        assert identity is not None
        snapshot = engine.lifecycle_registry.get_session(identity.object_id)
        assert snapshot is not None
        assert snapshot.identity == LifecycleShadow.project_session_start(identity)
        assert {
            (process.system, process.pid, process.ecar_object_id)
            for process in state.list_running_processes()
        } == processes_before
        assert engine.lifecycle_registry.stats().live_sessions == registry_sessions_before + 1
        expected_inverse = requested_key if inverse_after_failure == "requested" else None
        assert dict.get(generator._linux_sudo_tty_assignments, requested_key) == (
            forward_after_failure
        )
        assert dict.get(generator._linux_sudo_tty_owners, inverse_key) == expected_inverse
        assert len(generator._linux_sudo_tty_assignments) == 4_095 + (
            forward_after_failure is not None
        )
        assert len(generator._linux_sudo_tty_owners) == 4_095 + (inverse_after_failure is not None)
        capacity_claims = dict(generator._linux_sudo_tty_capacity_claims)
        if forward_after_failure is not None and inverse_after_failure is None:
            assert len(capacity_claims) == 1
            claim = capacity_claims[requested_key]
            assert claim[1:] == ("pts/1", False, True, False)
        else:
            assert capacity_claims == {}
        used_logon_ids = set(state._used_logon_ids)
        used_logind_ids = set(state._linux_logind_session_used_ids[system.hostname])

        sudo_pid, child_pid, _shift, assigned_tty = _generate_sudo_processes(
            generator,
            system,
            sudo_time=engine.start_time + timedelta(seconds=30),
            lifecycle_group_id=f"sudo:tty-{failure_phase}-retry",
            command="/usr/bin/hostname",
            sudo_user="linux_user",
        )

    materialize_session.assert_called_once()
    assert sudo_pid > 0 and child_pid is not None
    assert assigned_tty == "pts/1"
    assert len(state.get_sessions_for_user("linux_user")) == 1
    assert state._used_logon_ids == used_logon_ids
    assert state._linux_logind_session_used_ids[system.hostname] == used_logind_ids
    assert callback_lock_states
    assert all(callback_lock_states)
    assert len(generator._linux_sudo_tty_assignments) == 4_096
    assert len(generator._linux_sudo_tty_owners) == 4_096
    assert not generator._linux_sudo_tty_capacity_claims
    assert dict.get(generator._linux_sudo_tty_assignments, requested_key) == "pts/1"
    assert dict.get(generator._linux_sudo_tty_owners, inverse_key) == requested_key


def test_strict_sudo_tty_owner_first_orphan_repairs_before_session_admission(
    tmp_path: Path,
) -> None:
    """A unique inverse owner can restore its missing mirror without new logical truth."""

    engine, generator, state, system = _strict_sudo_generator(tmp_path)
    authority = engine.lifecycle_authority
    requested_key = (system.hostname, "linux_user", "pts/1")
    inverse_key = (system.hostname, "pts/1")
    dict.__setitem__(generator._linux_sudo_tty_owners, inverse_key, requested_key)
    state_before = state.materialization_digest()
    registry_before = engine.lifecycle_registry.stats()
    reject = Mock(side_effect=RuntimeError("injected orphan repair admission rejection"))
    authority._materialization_precommit_hook = reject

    try:
        with pytest.raises(RuntimeError, match="orphan repair admission rejection"):
            _generate_sudo_processes(
                generator,
                system,
                sudo_time=engine.start_time + timedelta(seconds=30),
                lifecycle_group_id="sudo:tty-owner-first-orphan",
                sudo_user="linux_user",
            )
    finally:
        authority._materialization_precommit_hook = None

    assert state.materialization_digest() == state_before
    assert engine.lifecycle_registry.stats() == registry_before
    # The preexisting inverse already owns this exact logical assignment. Restoring
    # its missing forward mirror allocates no TTY, session, process, LUID, or logind ID.
    assert dict.get(generator._linux_sudo_tty_assignments, requested_key) == "pts/1"
    assert dict.get(generator._linux_sudo_tty_owners, inverse_key) == requested_key
    sudo_pid, child_pid, _shift, assigned_tty = _generate_sudo_processes(
        generator,
        system,
        sudo_time=engine.start_time + timedelta(seconds=30),
        lifecycle_group_id="sudo:tty-owner-first-orphan-retry",
        sudo_user="linux_user",
    )
    assert sudo_pid > 0 and child_pid is not None
    assert assigned_tty == "pts/1"


def test_strict_sudo_tty_conflicting_pair_rejects_before_session_admission(
    tmp_path: Path,
) -> None:
    engine, generator, state, system = _strict_sudo_generator(tmp_path)
    requested_key = (system.hostname, "linux_user", "pts/1")
    foreign_key = (system.hostname, "foreign-user", "pts/1")
    inverse_key = (system.hostname, "pts/1")
    dict.__setitem__(generator._linux_sudo_tty_assignments, requested_key, "pts/1")
    dict.__setitem__(generator._linux_sudo_tty_owners, inverse_key, foreign_key)
    state_before = state.materialization_digest()
    registry_before = engine.lifecycle_registry.stats()
    processes_before = tuple(state.list_running_processes())

    with pytest.raises(StateError, match="TTY ownership conflict"):
        _generate_sudo_processes(
            generator,
            system,
            sudo_time=engine.start_time + timedelta(seconds=30),
            lifecycle_group_id="sudo:tty-conflict",
            sudo_user="linux_user",
        )

    assert state.materialization_digest() == state_before
    assert engine.lifecycle_registry.stats() == registry_before
    assert tuple(state.list_running_processes()) == processes_before
    assert dict.get(generator._linux_sudo_tty_assignments, requested_key) == "pts/1"
    assert dict.get(generator._linux_sudo_tty_owners, inverse_key) == foreign_key


def test_sudo_tty_assignment_reconciliation_is_concurrent_and_bijective() -> None:
    generator, _state, system = _sudo_generator()
    first_key = (system.hostname, "testuser", "pts/1")
    first_candidate = generator._reconcile_linux_sudo_tty_assignment(
        requested_tty_key=first_key,
        requested_tty="pts/1",
        assigned_tty=None,
        publish=False,
    )

    def publish(key: tuple[str, str, str], candidate: str) -> tuple[str, str]:
        try:
            result = generator._reconcile_linux_sudo_tty_assignment(
                requested_tty_key=key,
                requested_tty="pts/1",
                assigned_tty=candidate,
                publish=True,
            )
        except StateError:
            return "conflict", ""
        return "published", result

    with ThreadPoolExecutor(max_workers=2) as executor:
        same_key_results = tuple(
            executor.map(
                lambda _ordinal: publish(first_key, first_candidate),
                range(2),
            )
        )
    assert same_key_results == (("published", "pts/1"), ("published", "pts/1"))

    second_key = (system.hostname, "second-user", "pts/1")
    third_key = (system.hostname, "third-user", "pts/1")
    second_candidate = generator._reconcile_linux_sudo_tty_assignment(
        requested_tty_key=second_key,
        requested_tty="pts/1",
        assigned_tty=None,
        publish=False,
    )
    third_candidate = generator._reconcile_linux_sudo_tty_assignment(
        requested_tty_key=third_key,
        requested_tty="pts/1",
        assigned_tty=None,
        publish=False,
    )
    assert second_candidate == third_candidate == "pts/2"
    with ThreadPoolExecutor(max_workers=2) as executor:
        competing_results = tuple(
            executor.map(
                lambda item: publish(*item),
                ((second_key, second_candidate), (third_key, third_candidate)),
            )
        )
    assert [status for status, _tty in competing_results].count("published") == 1
    assert [status for status, _tty in competing_results].count("conflict") == 1
    losing_key = third_key if competing_results[0][0] == "published" else second_key
    retry_candidate = generator._reconcile_linux_sudo_tty_assignment(
        requested_tty_key=losing_key,
        requested_tty="pts/1",
        assigned_tty=None,
        publish=False,
    )
    assert retry_candidate == "pts/3"
    assert publish(losing_key, retry_candidate) == ("published", "pts/3")
    forward = dict(generator._linux_sudo_tty_assignments)
    inverse = dict(generator._linux_sudo_tty_owners)
    assert set(forward.values()) == {"pts/1", "pts/2", "pts/3"}
    assert len(forward) == len(inverse) == 3
    assert all(inverse[(system.hostname, assigned)] == key for key, assigned in forward.items())


@pytest.mark.parametrize(
    "attribute",
    [
        "_linux_sudo_tty_assignments",
        "_linux_sudo_tty_owners",
        "_linux_sudo_tty_capacity_claims",
    ],
    ids=["forward-map", "inverse-map", "capacity-claim-map"],
)
def test_sudo_tty_assignment_reconciliation_rejects_mapping_callbacks_before_lock(
    attribute: str,
) -> None:
    generator, _state, system = _sudo_generator()
    callbacks: list[tuple[str, bool]] = []
    destructor_probe = _DestructorProbe(generator._linux_sudo_tty_lock, callbacks)
    hostile_map = _CallbackMap(
        generator._linux_sudo_tty_lock,
        callbacks,
        destructor_probe,
    )
    setattr(generator, attribute, hostile_map)
    del destructor_probe
    del hostile_map
    requested_key = (system.hostname, "testuser", "pts/1")

    with pytest.raises(StateError, match="exact dictionaries"):
        generator._reconcile_linux_sudo_tty_assignment(
            requested_tty_key=requested_key,
            requested_tty="pts/1",
            assigned_tty="pts/1",
            publish=True,
        )
    assert callbacks == []

    setattr(generator, attribute, {})
    gc.collect()
    assert callbacks == [("destructor", True)]


def test_sudo_tty_assignment_reconciliation_rejects_hostile_values_before_lock() -> None:
    generator, _state, system = _sudo_generator()
    callbacks: list[tuple[str, bool]] = []
    hostile_tty = _CallbackStr(
        "pts/1",
        lock=generator._linux_sudo_tty_lock,
        callbacks=callbacks,
    )

    with pytest.raises(StateError, match="exact strings"):
        generator._reconcile_linux_sudo_tty_assignment(
            requested_tty_key=(system.hostname, "testuser", hostile_tty),
            requested_tty="pts/1",
            assigned_tty=None,
            publish=False,
        )
    assert callbacks == []

    dict.__setitem__(
        generator._linux_sudo_tty_assignments,
        (system.hostname, "foreign-user", hostile_tty),
        "pts/2",
    )
    callbacks.clear()
    with pytest.raises(StateError, match="malformed forward assignment"):
        generator._reconcile_linux_sudo_tty_assignment(
            requested_tty_key=(system.hostname, "testuser", "pts/1"),
            requested_tty="pts/1",
            assigned_tty=None,
            publish=False,
        )
    assert callbacks == []
    dict.clear(generator._linux_sudo_tty_assignments)

    dict.__setitem__(
        generator._linux_sudo_tty_capacity_claims,
        (system.hostname, "testuser", "pts/1"),
        (object(), hostile_tty, True, True, True),
    )
    callbacks.clear()
    with pytest.raises(StateError, match="malformed capacity claim"):
        generator._reconcile_linux_sudo_tty_assignment(
            requested_tty_key=(system.hostname, "testuser", "pts/1"),
            requested_tty="pts/1",
            assigned_tty=None,
            publish=False,
        )
    assert callbacks == []
    dict.clear(generator._linux_sudo_tty_capacity_claims)

    inverse_key = (system.hostname, "pts/1")
    dict.__setitem__(
        generator._linux_sudo_tty_owners,
        inverse_key,
        _CallbackOwner(generator._linux_sudo_tty_lock, callbacks),
    )
    with pytest.raises(StateError, match="malformed inverse owner"):
        generator._reconcile_linux_sudo_tty_assignment(
            requested_tty_key=(system.hostname, "testuser", "pts/1"),
            requested_tty="pts/1",
            assigned_tty=None,
            publish=False,
        )
    assert callbacks == []


def test_sudo_tty_assignment_reconciliation_caps_map_census() -> None:
    generator, _state, system = _sudo_generator()
    for ordinal in range(4_097):
        dict.__setitem__(
            generator._linux_sudo_tty_assignments,
            (system.hostname, f"user-{ordinal}", f"pts/{ordinal}"),
            f"pts/{ordinal}",
        )

    with pytest.raises(StateError, match="bounded census"):
        generator._reconcile_linux_sudo_tty_assignment(
            requested_tty_key=(system.hostname, "testuser", "pts/5000"),
            requested_tty="pts/5000",
            assigned_tty=None,
            publish=False,
        )


def test_sudo_tty_assignment_new_pair_fills_last_capacity_slot() -> None:
    generator, _state, system = _sudo_generator()
    _seed_sudo_tty_pairs(generator, hostname=system.hostname, count=4_095)
    requested_key = (system.hostname, "testuser", "pts/1")
    maps_before = _sudo_tty_state(generator)

    assigned_tty = generator._reconcile_linux_sudo_tty_assignment(
        requested_tty_key=requested_key,
        requested_tty="pts/1",
        assigned_tty=None,
        publish=False,
    )
    assert assigned_tty == "pts/1"
    assert _sudo_tty_state(generator) == maps_before
    assert (
        generator._reconcile_linux_sudo_tty_assignment(
            requested_tty_key=requested_key,
            requested_tty="pts/1",
            assigned_tty=assigned_tty,
            publish=True,
        )
        == "pts/1"
    )
    assert len(generator._linux_sudo_tty_assignments) == 4_096
    assert len(generator._linux_sudo_tty_owners) == 4_096
    assert generator._linux_sudo_tty_assignments[requested_key] == "pts/1"
    assert generator._linux_sudo_tty_owners[(system.hostname, "pts/1")] == requested_key


def test_strict_sudo_tty_full_capacity_rejects_before_lifecycle_admission(
    tmp_path: Path,
) -> None:
    engine, generator, state, system = _strict_sudo_generator(tmp_path)
    authority = engine.lifecycle_authority
    _seed_sudo_tty_pairs(generator, hostname=system.hostname, count=4_096)
    publication_hook = Mock()
    generator._linux_sudo_tty_publication_hook = publication_hook
    state_before = state.materialization_digest()
    registry_before = engine.lifecycle_registry.stats()
    authority_before = authority.census()
    shadow_before = dict(engine.lifecycle_shadow.violation_summary)
    tty_before = _sudo_tty_state(generator)
    processes_before = tuple(state.list_running_processes())

    with patch.object(
        authority,
        "materialize_session",
        wraps=authority.materialize_session,
    ) as materialize_session:
        with pytest.raises(StateError, match="TTY ownership capacity"):
            _generate_sudo_processes(
                generator,
                system,
                sudo_time=engine.start_time + timedelta(seconds=30),
                lifecycle_group_id="sudo:tty-capacity-reject",
                sudo_user="linux_user",
            )

    materialize_session.assert_not_called()
    publication_hook.assert_not_called()
    assert state.materialization_digest() == state_before
    assert engine.lifecycle_registry.stats() == registry_before
    assert authority.census() == authority_before
    assert engine.lifecycle_shadow.violation_summary == shadow_before
    assert tuple(state.list_running_processes()) == processes_before
    assert _sudo_tty_state(generator) == tty_before


def test_strict_sudo_tty_last_capacity_is_reserved_across_session_materialization(
    tmp_path: Path,
) -> None:
    engine, generator, state, system = _strict_sudo_generator(tmp_path)
    authority = engine.lifecycle_authority
    _seed_sudo_tty_pairs(generator, hostname=system.hostname, count=4_095)
    original_materialize = authority.materialize_session
    materialized = Event()
    release_return = Event()

    def commit_then_pause(plan: Any) -> tuple[Any, Any]:
        result = original_materialize(plan)
        materialized.set()
        if not release_return.wait(timeout=10):
            raise AssertionError("timed out waiting to return sudo session materialization")
        return result

    with (
        patch.object(
            authority,
            "materialize_session",
            side_effect=commit_then_pause,
        ) as materialize_session,
        ThreadPoolExecutor(max_workers=1) as executor,
    ):
        first_future = executor.submit(
            _generate_sudo_processes,
            generator,
            system,
            sudo_time=engine.start_time + timedelta(seconds=30),
            lifecycle_group_id="sudo:capacity-reservation:first",
            sudo_user="linux_user",
            tty="pts/1",
        )
        assert materialized.wait(timeout=10)
        state_before_second = state.materialization_digest()
        registry_before_second = engine.lifecycle_registry.stats()
        processes_before_second = tuple(state.list_running_processes())
        tty_before_second = _sudo_tty_state(generator)
        try:
            with pytest.raises(StateError, match="TTY ownership capacity"):
                _generate_sudo_processes(
                    generator,
                    system,
                    sudo_time=engine.start_time + timedelta(seconds=31),
                    lifecycle_group_id="sudo:capacity-reservation:second",
                    sudo_user="linux_user",
                    tty="pts/2",
                )
            assert state.materialization_digest() == state_before_second
            assert engine.lifecycle_registry.stats() == registry_before_second
            assert tuple(state.list_running_processes()) == processes_before_second
            assert _sudo_tty_state(generator) == tty_before_second
        finally:
            release_return.set()
        first = first_future.result(timeout=10)

    materialize_session.assert_called_once()
    assert first[0] > 0 and first[1] is not None and first[3] == "pts/1"
    assert len(state.get_sessions_for_user("linux_user")) == 1
    first_key = (system.hostname, "linux_user", "pts/1")
    second_key = (system.hostname, "linux_user", "pts/2")
    assert generator._linux_sudo_tty_assignments[first_key] == "pts/1"
    assert first_key == generator._linux_sudo_tty_owners[(system.hostname, "pts/1")]
    assert second_key not in generator._linux_sudo_tty_assignments
    assert not generator._linux_sudo_tty_capacity_claims
    assert len(generator._linux_sudo_tty_assignments) == 4_096
    assert len(generator._linux_sudo_tty_owners) == 4_096


def test_strict_sudo_tty_active_claim_rejects_same_request_until_exact_retry(
    tmp_path: Path,
) -> None:
    engine, generator, state, system = _strict_sudo_generator(tmp_path)
    authority = engine.lifecycle_authority
    original_materialize = authority.materialize_session
    materialized = Event()
    release_return = Event()

    def commit_then_pause(plan: Any) -> tuple[Any, Any]:
        result = original_materialize(plan)
        materialized.set()
        if not release_return.wait(timeout=10):
            raise AssertionError("timed out waiting to return sudo session materialization")
        return result

    with (
        patch.object(
            authority,
            "materialize_session",
            side_effect=commit_then_pause,
        ) as materialize_session,
        ThreadPoolExecutor(max_workers=1) as executor,
    ):
        first_future = executor.submit(
            _generate_sudo_processes,
            generator,
            system,
            sudo_time=engine.start_time + timedelta(seconds=30),
            lifecycle_group_id="sudo:active-claim:first",
            sudo_user="linux_user",
            tty="pts/1",
        )
        assert materialized.wait(timeout=10)
        state_before_conflict = state.materialization_digest()
        registry_before_conflict = engine.lifecycle_registry.stats()
        processes_before_conflict = tuple(state.list_running_processes())
        tty_before_conflict = _sudo_tty_state(generator)
        try:
            with pytest.raises(StateError, match="active capacity claim"):
                _generate_sudo_processes(
                    generator,
                    system,
                    sudo_time=engine.start_time + timedelta(seconds=30),
                    lifecycle_group_id="sudo:active-claim:conflict",
                    sudo_user="linux_user",
                    tty="pts/1",
                )
            assert state.materialization_digest() == state_before_conflict
            assert engine.lifecycle_registry.stats() == registry_before_conflict
            assert tuple(state.list_running_processes()) == processes_before_conflict
            assert _sudo_tty_state(generator) == tty_before_conflict
        finally:
            release_return.set()
        first = first_future.result(timeout=10)
        session = state.get_sessions_for_user("linux_user")[0]
        used_logon_ids = set(state._used_logon_ids)
        used_logind_ids = set(state._linux_logind_session_used_ids[system.hostname])

        retry = _generate_sudo_processes(
            generator,
            system,
            sudo_time=engine.start_time + timedelta(seconds=30),
            lifecycle_group_id="sudo:active-claim:retry",
            command="/usr/bin/hostname",
            sudo_user="linux_user",
            tty="pts/1",
        )

    materialize_session.assert_called_once()
    assert first[0] > 0 and first[1] is not None and first[3] == "pts/1"
    assert retry[0] > 0 and retry[1] is not None and retry[3] == "pts/1"
    assert state.get_sessions_for_user("linux_user") == [session]
    assert state._used_logon_ids == used_logon_ids
    assert state._linux_logind_session_used_ids[system.hostname] == used_logind_ids
    assert not generator._linux_sudo_tty_capacity_claims


def test_strict_sudo_tty_postclaim_concurrency_retains_both_authoritative_caches(
    tmp_path: Path,
) -> None:
    engine, generator, state, system = _strict_sudo_generator(tmp_path)
    authority = engine.lifecycle_authority
    first_pair_published = Event()
    release_first = Event()

    def pause_first_after_pair(phase: str) -> None:
        if phase == "inverse-postcommit":
            generator._linux_sudo_tty_publication_hook = None
            first_pair_published.set()
            if not release_first.wait(timeout=10):
                raise AssertionError("timed out waiting to resume first sudo cache publication")

    generator._linux_sudo_tty_publication_hook = pause_first_after_pair
    with (
        patch.object(
            authority,
            "materialize_session",
            wraps=authority.materialize_session,
        ) as materialize_session,
        ThreadPoolExecutor(max_workers=1) as executor,
    ):
        first_future = executor.submit(
            _generate_sudo_processes,
            generator,
            system,
            sudo_time=engine.start_time + timedelta(seconds=30),
            lifecycle_group_id="sudo:postclaim-cache:first",
            sudo_user="linux_user",
            tty="pts/1",
        )
        assert first_pair_published.wait(timeout=10)
        first_key = (system.hostname, "linux_user", "pts/1")
        handoff_claim = generator._linux_sudo_tty_capacity_claims[first_key]
        assert handoff_claim[1:] == ("pts/1", False, False, True)
        try:
            with pytest.raises(StateError, match="active capacity claim"):
                _generate_sudo_processes(
                    generator,
                    system,
                    sudo_time=engine.start_time + timedelta(seconds=31),
                    lifecycle_group_id="sudo:postclaim-cache:conflict",
                    sudo_user="linux_user",
                    tty="pts/1",
                )
            second = _generate_sudo_processes(
                generator,
                system,
                sudo_time=engine.start_time + timedelta(seconds=31),
                lifecycle_group_id="sudo:postclaim-cache:second",
                command="/usr/bin/hostname",
                sudo_user="linux_user",
                tty="pts/2",
            )
        finally:
            release_first.set()
        first = first_future.result(timeout=10)

    materialize_session.assert_called_once()
    assert first[0] > 0 and first[1] is not None and first[3] == "pts/1"
    assert second[0] > 0 and second[1] is not None and second[3] == "pts/2"
    sessions = state.get_sessions_for_user("linux_user")
    assert len(sessions) == 1
    session = sessions[0]
    expected_keys = {
        first_key,
        (system.hostname, "linux_user", "pts/2"),
    }
    assert set(generator._linux_sudo_tty_assignments) >= expected_keys
    assert {
        generator._linux_sudo_tty_owners[(system.hostname, key[2])] for key in expected_keys
    } == expected_keys
    assert set(generator._linux_sudo_tty_sessions) == expected_keys
    assert set(generator._linux_sudo_tty_available) == expected_keys
    assert set(generator._linux_sudo_tty_sessions.values()) == {session.logon_id}
    assert all(
        generator._linux_sudo_tty_available[key] >= engine.start_time + timedelta(seconds=32)
        for key in expected_keys
    )
    assert not generator._linux_sudo_tty_capacity_claims


@pytest.mark.parametrize(
    ("partial_side", "has_capacity"),
    [
        ("forward", True),
        ("inverse", True),
        ("forward", False),
        ("inverse", False),
    ],
    ids=[
        "forward-completes-at-cap",
        "inverse-completes-at-cap",
        "forward-rejects-at-cap",
        "inverse-rejects-at-cap",
    ],
)
def test_sudo_tty_assignment_partial_capacity_is_atomic(
    partial_side: str,
    has_capacity: bool,
) -> None:
    generator, _state, system = _sudo_generator()
    seed_count = 4_095 if has_capacity else 4_096
    _seed_sudo_tty_pairs(generator, hostname=system.hostname, count=seed_count)
    requested_key = (system.hostname, "testuser", "pts/1")
    inverse_key = (system.hostname, "pts/1")
    if not has_capacity:
        seed_tty = "pts/10000"
        seed_key = (system.hostname, "seed-user-0", seed_tty)
        if partial_side == "forward":
            dict.pop(generator._linux_sudo_tty_assignments, seed_key)
        else:
            dict.pop(generator._linux_sudo_tty_owners, (system.hostname, seed_tty))
    if partial_side == "forward":
        dict.__setitem__(generator._linux_sudo_tty_assignments, requested_key, "pts/1")
    else:
        dict.__setitem__(generator._linux_sudo_tty_owners, inverse_key, requested_key)
    maps_before = _sudo_tty_state(generator)

    if has_capacity:
        assert (
            generator._reconcile_linux_sudo_tty_assignment(
                requested_tty_key=requested_key,
                requested_tty="pts/1",
                assigned_tty=None,
                publish=False,
            )
            == "pts/1"
        )
        assert len(generator._linux_sudo_tty_assignments) == 4_096
        assert len(generator._linux_sudo_tty_owners) == 4_096
        assert generator._linux_sudo_tty_assignments[requested_key] == "pts/1"
        assert generator._linux_sudo_tty_owners[inverse_key] == requested_key
    else:
        with pytest.raises(StateError, match="TTY ownership capacity"):
            generator._reconcile_linux_sudo_tty_assignment(
                requested_tty_key=requested_key,
                requested_tty="pts/1",
                assigned_tty=None,
                publish=False,
            )
        assert _sudo_tty_state(generator) == maps_before


def test_sudo_tty_assignment_concurrent_last_slot_has_one_exact_owner() -> None:
    generator, _state, system = _sudo_generator()
    _seed_sudo_tty_pairs(generator, hostname=system.hostname, count=4_095)
    first_key = (system.hostname, "first-user", "pts/1")
    second_key = (system.hostname, "second-user", "pts/2")
    barrier = Barrier(2)

    def synchronize_last_slot(phase: str) -> None:
        if phase == "forward-precommit":
            barrier.wait()
            generator._linux_sudo_tty_publication_hook = None

    def publish(key: tuple[str, str, str]) -> tuple[str, str]:
        candidate = generator._reconcile_linux_sudo_tty_assignment(
            requested_tty_key=key,
            requested_tty=key[2],
            assigned_tty=None,
            publish=False,
        )
        try:
            assigned = generator._reconcile_linux_sudo_tty_assignment(
                requested_tty_key=key,
                requested_tty=key[2],
                assigned_tty=candidate,
                publish=True,
            )
        except StateError as error:
            assert "TTY ownership capacity" in str(error)
            return "capacity", candidate
        return "published", assigned

    generator._linux_sudo_tty_publication_hook = synchronize_last_slot
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(publish, (first_key, second_key)))

    assert [status for status, _candidate in results].count("published") == 1
    assert [status for status, _candidate in results].count("capacity") == 1
    winning_key = first_key if results[0][0] == "published" else second_key
    losing_key = second_key if winning_key == first_key else first_key
    assert generator._linux_sudo_tty_assignments[winning_key] == winning_key[2]
    assert losing_key not in generator._linux_sudo_tty_assignments
    assert len(generator._linux_sudo_tty_assignments) == 4_096
    assert len(generator._linux_sudo_tty_owners) == 4_096
    assert all(
        generator._linux_sudo_tty_owners[(system.hostname, assigned_tty)] == requested_key
        for requested_key, assigned_tty in generator._linux_sudo_tty_assignments.items()
    )


def test_sudo_tty_assignment_revalidates_hook_mutation_without_owner_callback() -> None:
    generator, _state, system = _sudo_generator()
    callbacks: list[tuple[str, bool]] = []
    requested_key = (system.hostname, "testuser", "pts/1")
    inverse_key = (system.hostname, "pts/1")

    def inject_hostile_owner(phase: str) -> None:
        acquired = generator._linux_sudo_tty_lock.acquire(blocking=False)
        callbacks.append(("hook", acquired))
        if acquired:
            generator._linux_sudo_tty_lock.release()
        if phase == "forward-precommit":
            generator._linux_sudo_tty_publication_hook = None
            dict.__setitem__(
                generator._linux_sudo_tty_owners,
                inverse_key,
                _CallbackOwner(generator._linux_sudo_tty_lock, callbacks),
            )

    generator._linux_sudo_tty_publication_hook = inject_hostile_owner
    with pytest.raises(StateError, match="malformed inverse owner"):
        generator._reconcile_linux_sudo_tty_assignment(
            requested_tty_key=requested_key,
            requested_tty="pts/1",
            assigned_tty="pts/1",
            publish=True,
        )

    assert callbacks == [("hook", True)]


def test_strict_sudo_tty_postwrite_concurrent_conflict_is_not_overwritten(
    tmp_path: Path,
) -> None:
    engine, generator, state, system = _strict_sudo_generator(tmp_path)
    authority = engine.lifecycle_authority
    requested_key = (system.hostname, "linux_user", "pts/1")
    foreign_key = (system.hostname, "foreign-user", "pts/1")
    inverse_key = (system.hostname, "pts/1")
    hook_lock_states: list[bool] = []

    def inject_conflict(phase: str) -> None:
        acquired = generator._linux_sudo_tty_lock.acquire(blocking=False)
        hook_lock_states.append(acquired)
        if acquired:
            generator._linux_sudo_tty_lock.release()
        if phase == "forward-postcommit":
            generator._linux_sudo_tty_publication_hook = None
            dict.__setitem__(generator._linux_sudo_tty_owners, inverse_key, foreign_key)

    generator._linux_sudo_tty_publication_hook = inject_conflict
    processes_before = tuple(state.list_running_processes())

    with patch.object(
        authority,
        "materialize_session",
        wraps=authority.materialize_session,
    ) as materialize_session:
        with pytest.raises(StateError, match="TTY ownership conflict"):
            _generate_sudo_processes(
                generator,
                system,
                sudo_time=engine.start_time + timedelta(seconds=30),
                lifecycle_group_id="sudo:tty-postwrite-conflict",
                sudo_user="linux_user",
            )
        with pytest.raises(StateError, match="TTY ownership conflict"):
            _generate_sudo_processes(
                generator,
                system,
                sudo_time=engine.start_time + timedelta(seconds=30),
                lifecycle_group_id="sudo:tty-postwrite-conflict-retry",
                sudo_user="linux_user",
            )

    materialize_session.assert_called_once()
    assert len(state.get_sessions_for_user("linux_user")) == 1
    assert tuple(state.list_running_processes()) == processes_before
    assert hook_lock_states
    assert all(hook_lock_states)
    assert dict.get(generator._linux_sudo_tty_assignments, requested_key) == "pts/1"
    assert dict.get(generator._linux_sudo_tty_owners, inverse_key) == foreign_key


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
