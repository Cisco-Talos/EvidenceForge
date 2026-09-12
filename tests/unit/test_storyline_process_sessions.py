# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Session selection contracts shared by typed processes and command spills."""

import random
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock, call

import pytest

from evidenceforge.generation.engine.storyline import StorylineMixin
from evidenceforge.generation.engine.typed_handlers.context import TypedEventContext
from evidenceforge.generation.engine.typed_handlers.process import handle_process
from evidenceforge.models import System, User
from evidenceforge.models.scenario import ProcessEventSpec


class ResolutionCompleteError(RuntimeError):
    """Stop a typed event after session selection, before process generation."""


@pytest.mark.parametrize("entrypoint", ["typed", "spill"])
@pytest.mark.parametrize(
    ("username", "os_name", "existing", "path"),
    [
        ("alice", "Ubuntu 22.04", False, "interactive"),
        ("alice", "Ubuntu 22.04", True, "storyline"),
        ("root", "Ubuntu 22.04", False, "interactive"),
        ("apache", "Ubuntu 22.04", False, "daemon"),
        ("WWW-DATA", "Ubuntu 22.04", False, "interactive"),
        ("SYSTEM", "Windows 10", False, "service"),
        ("SYSTEM", "Windows 10", True, "existing_service"),
        ("svc", "Windows 10", False, "service"),
    ],
)
def test_process_session_selection_contract(
    entrypoint: str, username: str, os_name: str, existing: bool, path: str
) -> None:
    _check_resolution(entrypoint, username, os_name, existing, path, planner=True)


@pytest.mark.parametrize("existing", [False, True])
def test_typed_process_without_world_planner(existing: bool) -> None:
    _check_resolution(
        "typed",
        "alice",
        "Windows 10",
        existing,
        "fallback_existing" if existing else "fallback",
        planner=False,
    )


def _check_resolution(
    entrypoint: str,
    username: str,
    os_name: str,
    existing: bool,
    path: str,
    *,
    planner: bool,
) -> None:
    engine = StorylineMixin()
    actor = User(username=username, full_name=username, email="user@example.com")
    system = System(hostname="HOST", ip="10.0.0.1", os=os_name, type="workstation")
    time = datetime(2024, 3, 15, 10, tzinfo=UTC)
    required_until = time + timedelta(hours=1)
    rng = random.Random(137)
    expected_rng = random.Random(137)
    calls = Mock()
    engine.scenario = SimpleNamespace(environment=SimpleNamespace(service_accounts=["svc"]))
    engine.state_manager = calls.state
    engine.activity_generator = calls.activity
    if planner:
        engine.world_planner = calls.planner
    engine._last_storyline_logon_for_actor_system = calls.last
    engine._next_storyline_logoff_time_for_actor_system = calls.until
    engine._storyline_non_session_kind = calls.kind
    engine._record_storyline_logon = calls.record
    calls.last.return_value = "storyline" if existing else None
    calls.until.return_value = required_until
    calls.kind.side_effect = lambda *args: "interactive" if rng.random() < 1 else "ssh"
    calls.planner.ensure_user_session.return_value = SimpleNamespace(logon_id="created")
    calls.activity.generate_logon.return_value = "fallback"
    calls.activity.generate_service_logon.return_value = "service"
    sessions = (
        [
            SimpleNamespace(system="HOST", start_time=time - timedelta(minutes=2), logon_id="old"),
            SimpleNamespace(system="HOST", start_time=time - timedelta(minutes=1), logon_id="new"),
            SimpleNamespace(system="OTHER", start_time=time, logon_id="wrong_host"),
        ]
        if existing
        else []
    )
    calls.state.get_sessions_for_user.return_value = sessions
    calls.state.get_sessions_for_user_at.return_value = sessions
    selected: list[str] = []

    def capture_selection(user: User, host: System, logon_id: str) -> User:
        selected.append(logon_id)
        raise ResolutionCompleteError

    engine._linux_native_service_user_for_storyline_actor = lambda *args: actor
    engine._storyline_local_process_actor_for_logon = capture_selection
    if entrypoint == "typed":
        context = TypedEventContext(
            actor=actor,
            system=system,
            time=time,
            activity="process",
            explicit_types={"process"},
            future_specs=(),
            authored_time_shift=timedelta(),
            session_required_until=None,
            rng=rng,
            dispatcher=None,
            malicious_event={},
            _ground_truth_uid=lambda *args: "uid",
        )
        with pytest.raises(ResolutionCompleteError):
            handle_process(engine, ProcessEventSpec(type="process", process_name="whoami"), context)
    else:
        selected.append(engine._resolve_storyline_process_spill_logon_id(actor, system, time, rng))

    expected: list = []
    if path in {"interactive", "storyline"}:
        expected.append(call.last(actor, system, at_time=time))
        if path == "interactive":
            expected_rng.random()
            expected.extend(
                [
                    call.until(actor, system, time),
                    call.kind(actor, system, rng),
                    call.planner.ensure_user_session(
                        actor,
                        system,
                        time,
                        rng,
                        session_kind="interactive",
                        storyline_protected=True,
                        required_until=required_until,
                    ),
                    call.record(actor, system, "created"),
                ]
            )
        result = "created" if path == "interactive" else "storyline"
    elif path == "daemon":
        result = ""
    else:
        fallback = path.startswith("fallback")
        expected.append(
            call.state.get_sessions_for_user(username)
            if fallback
            else call.state.get_sessions_for_user_at(username, time)
        )
        result = "new" if existing else "fallback" if fallback else "service"
        if not existing:
            logon_time = time - timedelta(seconds=expected_rng.uniform(0.5, 2.0))
            if fallback:
                expected.extend(
                    [
                        call.activity.generate_logon(actor, system, logon_time, logon_type=3),
                        call.record(actor, system, "fallback"),
                    ]
                )
            else:
                expected.append(
                    call.activity.generate_service_logon(
                        system=system,
                        time=logon_time,
                        service_account=username,
                    )
                )
    assert selected == [result]
    assert calls.mock_calls == expected
    assert rng.getstate() == expected_rng.getstate()
