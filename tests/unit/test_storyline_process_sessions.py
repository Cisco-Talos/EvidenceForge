# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Session selection contracts shared by typed processes and command spills."""

import random
from datetime import UTC, datetime, timedelta
from threading import RLock
from types import SimpleNamespace
from unittest.mock import Mock, call

import pytest

from evidenceforge.events.rdp import RdpSessionState
from evidenceforge.generation.activity.generator import ActivityGenerator
from evidenceforge.generation.engine.storyline import StorylineMixin
from evidenceforge.generation.engine.typed_handlers.context import TypedEventContext
from evidenceforge.generation.engine.typed_handlers.process import handle_process
from evidenceforge.models import System, User
from evidenceforge.models.scenario import ProcessEventSpec


class ResolutionCompleteError(RuntimeError):
    """Stop a typed event after session selection, before process generation."""


def test_storyline_activity_reconnects_disconnected_rdp_owner_before_process() -> None:
    """Fresh desktop work consumes the exact reconnect path before process admission."""

    source = System(
        hostname="WS-01",
        ip="10.10.0.25",
        os="Windows 11",
        type="workstation",
    )
    target = System(
        hostname="RDS-01",
        ip="10.20.0.10",
        os="Windows Server 2022",
        type="server",
        services=["rdp"],
    )
    user = User(
        username="analyst",
        full_name="Security Analyst",
        email="analyst@example.test",
    )
    activity_time = datetime(2024, 3, 15, 10, tzinfo=UTC)
    ready_time = activity_time + timedelta(milliseconds=750)
    session_identity = SimpleNamespace(object_id="rdp-logical", session_kind="rdp")
    snapshot = SimpleNamespace(
        state=RdpSessionState.DISCONNECTED,
        generation=SimpleNamespace(ordinal=3),
        identity=SimpleNamespace(
            affinity=SimpleNamespace(source_address=source.ip),
        ),
    )
    prepared = SimpleNamespace(source_system=source, user=user)
    entry = SimpleNamespace(
        continuation=SimpleNamespace(
            session=SimpleNamespace(
                identity=SimpleNamespace(logical_session_id="rdp-logical"),
                generation=SimpleNamespace(ordinal=3),
            ),
            prepared=prepared,
        )
    )
    live_session = SimpleNamespace(source_ready_time=ready_time)
    state = SimpleNamespace(
        get_session_identity=lambda logon_id: session_identity,
        get_session=lambda logon_id: live_session,
    )
    reconnect_calls: list[dict[str, object]] = []
    owner = SimpleNamespace(
        state_manager=state,
        _rdp_session_manager=SimpleNamespace(get=lambda logical_id: snapshot),
        _rdp_lifecycle_journal_lock=RLock(),
        _pending_rdp_lifecycle_continuations={"entry": entry},
        _rdp_session_lifecycle_frontier=lambda: activity_time - timedelta(seconds=1),
        advance_rdp_session_lifecycle_watermark=lambda cutoff: None,
        _active_user_interactive_windows_session=lambda actor, system, at_time: object(),
        _execute_rdp_session_bundle=lambda **kwargs: reconnect_calls.append(kwargs),
    )

    admitted_at = ActivityGenerator.ensure_storyline_rdp_session_connected(
        owner,
        logon_id="0xabc",
        target_system=target,
        activity_time=activity_time,
    )

    assert admitted_at == ready_time + timedelta(milliseconds=1)
    assert reconnect_calls == [
        {
            "user": user,
            "target_system": target,
            "time": activity_time,
            "source_ip": source.ip,
            "source_system": source,
            "logon_id": "0xabc",
            "preserve_explicit_source": True,
        }
    ]


def test_storyline_rdp_process_admission_clamps_to_lifecycle_frontier() -> None:
    """Source alignment cannot make a later process move the RDP watermark backward."""

    authored_time = datetime(2024, 3, 15, 10, tzinfo=UTC)
    lifecycle_frontier = authored_time + timedelta(minutes=4)
    owner = SimpleNamespace(
        state_manager=SimpleNamespace(
            get_session_identity=lambda logon_id: SimpleNamespace(
                object_id="rdp-logical",
                session_kind="rdp",
            ),
            get_session=lambda logon_id: SimpleNamespace(source_ready_time=authored_time),
        ),
        _rdp_session_lifecycle_frontier=lambda: lifecycle_frontier,
        advance_rdp_session_lifecycle_watermark=lambda cutoff: None,
        _rdp_session_manager=SimpleNamespace(
            get=lambda logical_id: SimpleNamespace(state=RdpSessionState.CONNECTED)
        ),
    )

    admitted_at = ActivityGenerator.ensure_storyline_rdp_session_connected(
        owner,
        logon_id="0xabc",
        target_system=System(
            hostname="RDS-01",
            ip="10.20.0.10",
            os="Windows Server 2022",
            type="server",
        ),
        activity_time=authored_time,
    )

    assert admitted_at == lifecycle_frontier


def test_non_rdp_process_admission_preserves_authored_time() -> None:
    """A global RDP watermark must not delay Type 9 or local session activity."""

    authored_time = datetime(2024, 3, 15, 10, tzinfo=UTC)
    owner = SimpleNamespace(
        state_manager=SimpleNamespace(
            get_session_identity=lambda logon_id: SimpleNamespace(
                object_id="new-credentials",
                session_kind="new_credentials",
            )
        ),
        _rdp_session_lifecycle_frontier=lambda: authored_time + timedelta(hours=1),
    )

    admitted_at = ActivityGenerator.ensure_storyline_rdp_session_connected(
        owner,
        logon_id="0x900",
        target_system=System(
            hostname="WS-01",
            ip="10.20.0.10",
            os="Windows 11",
            type="workstation",
        ),
        activity_time=authored_time,
    )

    assert admitted_at == authored_time


def test_linux_process_resolves_session_after_shell_availability_shift() -> None:
    """A serialized Linux child must not retain a session selected at its stale anchor."""

    engine = StorylineMixin()
    actor = User(username="root", full_name="root", email="root@example.com")
    system = System(hostname="WEB-01", ip="10.0.0.20", os="Ubuntu 22.04", type="server")
    authored_time = datetime(2024, 3, 15, 10, tzinfo=UTC)
    shell_available_at = authored_time + timedelta(minutes=5)
    rng = random.Random(137)
    engine._storyline_shell_available_at = {
        (system.hostname, actor.username): shell_available_at,
    }
    engine._linux_native_service_user_for_storyline_actor = lambda *args: actor
    engine._resolve_storyline_process_logon_id = Mock(return_value="fresh-session")

    def capture_selection(user: User, host: System, logon_id: str) -> User:
        raise ResolutionCompleteError

    engine._storyline_local_process_actor_for_logon = capture_selection
    context = TypedEventContext(
        actor=actor,
        system=system,
        time=authored_time,
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
        handle_process(
            engine,
            ProcessEventSpec(type="process", process_name="/usr/sbin/ip"),
            context,
        )

    resolved_time = engine._resolve_storyline_process_logon_id.call_args.args[2]
    assert shell_available_at < resolved_time < shell_available_at + timedelta(seconds=2)


def test_linux_process_rebinds_when_shell_reservation_crosses_ssh_close() -> None:
    """A delayed command must bootstrap a new session instead of using a closed SSH shell."""

    engine = StorylineMixin()
    actor = User(username="root", full_name="root", email="root@example.com")
    system = System(hostname="WEB-01", ip="10.0.0.20", os="Ubuntu 22.04", type="server")
    authored_time = datetime(2024, 3, 15, 10, tzinfo=UTC)
    reserved_time = authored_time + timedelta(minutes=18)
    old_session = SimpleNamespace(session_kind="ssh")
    fresh_session = SimpleNamespace(session_kind="ssh")
    engine.state_manager = SimpleNamespace(
        get_session=lambda logon_id: old_session if logon_id == "old" else fresh_session,
        get_session_at=lambda logon_id, at_time: fresh_session if logon_id == "fresh" else None,
    )
    activity = Mock()
    activity.reserve_linux_foreground_process_start.side_effect = [
        reserved_time,
        reserved_time,
    ]
    activity._resolve_parent.side_effect = [101, 202]
    activity._prepare_bash_history_command.side_effect = lambda host, command: command
    activity.generate_process.side_effect = ResolutionCompleteError
    engine.activity_generator = activity
    engine._linux_native_service_user_for_storyline_actor = lambda *args: actor
    engine._resolve_storyline_process_logon_id = Mock(side_effect=["old", "fresh"])
    engine._storyline_local_process_actor_for_logon = lambda user, host, logon_id: user
    engine._extract_output_file = lambda *args: None
    engine._storyline_process_ref_for_parent = lambda **kwargs: None
    engine._storyline_service_process_identity = lambda **kwargs: None
    engine._storyline_service_context_for_process = lambda **kwargs: None
    engine._emit_linux_storyline_shell_friction = lambda **kwargs: None
    context = TypedEventContext(
        actor=actor,
        system=system,
        time=authored_time,
        activity="process",
        explicit_types={"process"},
        future_specs=(),
        authored_time_shift=timedelta(),
        session_required_until=None,
        rng=random.Random(137),
        dispatcher=None,
        malicious_event={},
        _ground_truth_uid=lambda *args: "uid",
    )

    with pytest.raises(ResolutionCompleteError):
        handle_process(
            engine,
            ProcessEventSpec(type="process", process_name="/usr/sbin/ip"),
            context,
        )

    assert engine._resolve_storyline_process_logon_id.call_args_list == [
        call(actor, system, authored_time, context.rng),
        call(actor, system, reserved_time, context.rng),
    ]
    assert activity._resolve_parent.call_args_list == [
        call(system, actor, authored_time, "old", "/usr/sbin/ip", "/usr/sbin/ip"),
        call(system, actor, reserved_time, "fresh", "/usr/sbin/ip", "/usr/sbin/ip"),
    ]
    assert activity.generate_process.call_args.kwargs["logon_id"] == "fresh"
    assert activity.generate_process.call_args.kwargs["parent_pid"] == 202
    assert activity.generate_process.call_args.kwargs["time"] == reserved_time


def test_type9_process_does_not_reuse_ambient_service_context() -> None:
    """An explicit NewCredentials process must retain its exact LUID and local token."""

    engine = StorylineMixin()
    actor = User(username="admin", full_name="Admin", email="admin@example.com")
    local_actor = User(username="alice", full_name="Alice", email="alice@example.com")
    system = System(hostname="WS-01", ip="10.0.0.20", os="Windows 11", type="workstation")
    event_time = datetime(2024, 3, 15, 10, tzinfo=UTC)
    engine.state_manager = SimpleNamespace(
        get_session=lambda logon_id: SimpleNamespace(logon_type=9),
    )
    activity = Mock()
    activity._resolve_parent.return_value = 4321
    activity.generate_process.side_effect = ResolutionCompleteError
    engine.activity_generator = activity
    engine._linux_native_service_user_for_storyline_actor = lambda *args: actor
    engine._resolve_storyline_process_logon_id = Mock(return_value="0x900")
    engine._storyline_local_process_actor_for_logon = lambda *args: local_actor
    engine._extract_output_file = lambda *args: None
    engine._storyline_process_ref_for_parent = lambda **kwargs: None
    engine._storyline_service_process_identity = lambda **kwargs: None
    engine._storyline_service_context_for_process = Mock(
        return_value=(local_actor, "0x3e4", 9999, "stale-service")
    )
    context = TypedEventContext(
        actor=actor,
        system=system,
        time=event_time,
        activity="process",
        explicit_types={"process"},
        future_specs=(SimpleNamespace(type="smb_activity"),),
        authored_time_shift=timedelta(),
        session_required_until=None,
        rng=random.Random(137),
        dispatcher=None,
        malicious_event={},
        _ground_truth_uid=lambda *args: "uid",
    )

    with pytest.raises(ResolutionCompleteError):
        handle_process(
            engine,
            ProcessEventSpec(
                type="process",
                process_name=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            ),
            context,
        )

    engine._storyline_service_context_for_process.assert_not_called()
    assert activity.generate_process.call_args.kwargs["user"] == local_actor
    assert activity.generate_process.call_args.kwargs["logon_id"] == "0x900"
    assert activity.generate_process.call_args.kwargs["parent_pid"] == 4321


def test_client_rdp_alias_starts_share_one_explicit_logoff_plan() -> None:
    """Equivalent authored client RDP starts must receive the same close fence."""

    engine = StorylineMixin()
    engine.start_time = datetime(2024, 3, 18, 12, tzinfo=UTC)
    client = System(
        hostname="WS-01",
        ip="10.0.0.10",
        os="Windows 11",
        type="workstation",
    )
    engine.scenario = SimpleNamespace(
        environment=SimpleNamespace(systems=[client]),
        storyline=[
            SimpleNamespace(
                id="first",
                actor="root",
                system=client.hostname,
                time="+1h",
                events=[SimpleNamespace(type="rdp_session", source_ip="10.0.0.99")],
            ),
            SimpleNamespace(
                id="alias",
                actor="alice",
                system=client.hostname,
                time="+1h20m",
                events=[SimpleNamespace(type="logon", logon_type=10, source_ip="10.0.0.99")],
            ),
            SimpleNamespace(
                id="close",
                actor="alice",
                system=client.hostname,
                time="+2h",
                events=[SimpleNamespace(type="logoff")],
            ),
        ],
    )

    engine._ensure_storyline_session_end_pairs()

    assert engine._storyline_start_to_logoff == {
        "first:0": "close:0",
        "alias:0": "close:0",
    }
    assert engine._storyline_session_end_plans["close:0"].canonical_end == (
        engine.start_time + timedelta(hours=2)
    )


def test_server_rdp_starts_retain_independent_logoff_pairing() -> None:
    """Server multi-session semantics must not merge separate authored starts."""

    engine = StorylineMixin()
    engine.start_time = datetime(2024, 3, 18, 12, tzinfo=UTC)
    server = System(
        hostname="APP-01",
        ip="10.0.0.20",
        os="Windows Server 2022",
        type="server",
    )
    engine.scenario = SimpleNamespace(
        environment=SimpleNamespace(systems=[server]),
        storyline=[
            SimpleNamespace(
                id="first",
                actor="alice",
                system=server.hostname,
                time="+1h",
                events=[SimpleNamespace(type="rdp_session", source_ip="10.0.0.99")],
            ),
            SimpleNamespace(
                id="second",
                actor="alice",
                system=server.hostname,
                time="+1h20m",
                events=[SimpleNamespace(type="rdp_session", source_ip="10.0.0.99")],
            ),
            SimpleNamespace(
                id="close",
                actor="alice",
                system=server.hostname,
                time="+2h",
                events=[SimpleNamespace(type="logoff")],
            ),
        ],
    )

    engine._ensure_storyline_session_end_pairs()

    assert engine._storyline_start_to_logoff == {"second:0": "close:0"}


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
