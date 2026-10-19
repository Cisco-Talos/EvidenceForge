# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Independently authored Mac platform and cross-source isolation contracts."""

import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.source_catalog import DEFAULT_SOURCE_CATALOG, source_platform_for_os
from evidenceforge.formats.loader import load_format
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.activity.application_catalog import resolve_image_path
from evidenceforge.generation.activity.helpers import _get_os_category
from evidenceforge.generation.activity.suspicious_benign import generate_suspicious_cli
from evidenceforge.generation.activity.timing_profiles import endpoint_clock_timing
from evidenceforge.generation.deployment_compiler import infer_system_platform
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.generation.source_timing import SourceTimingPlanner
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import System, User
from evidenceforge.utils.platforms import platform_for_os

_TIME = datetime(2026, 10, 12, 14, tzinfo=UTC)


def _system(os_name: str = "macOS 26") -> System:
    return System(
        hostname="MAC-TEST",
        ip="192.0.2.10",
        os=os_name,
        os_build="25A354",
        architecture="arm64",
        type="workstation",
        assigned_user="alex",
    )


def _user() -> User:
    return User(
        username="alex",
        full_name="Alex Example",
        email="alex@example.test",
        persona="developer",
        primary_system="MAC-TEST",
    )


@pytest.mark.parametrize("label", ["macOS 26", "Mac OS X", "Darwin 25", "OS X", "MACOS"])
def test_mac_aliases_agree_at_runtime_and_deployment_boundaries(label: str) -> None:
    assert platform_for_os(label) == "macos"
    assert _get_os_category(label) == "macos"
    assert source_platform_for_os(label) == "macos"
    assert infer_system_platform(_system(label)) == "macos"


@pytest.mark.parametrize(
    ("label", "expected"),
    [
        ("Windows 11", "windows"),
        ("Ubuntu 24.04", "linux"),
        ("Red Hat Enterprise Linux", "linux"),
        ("FreeBSD", "unknown"),
        ("", "unknown"),
    ],
)
def test_other_platform_classification_is_preserved(label: str, expected: str) -> None:
    assert platform_for_os(label) == expected


def test_mac_source_admission_does_not_enable_windows_or_linux_endpoint_logs() -> None:
    applicable = {
        descriptor.name
        for descriptor in DEFAULT_SOURCE_CATALOG.descriptors
        if descriptor.applies_to_host("macos")
    }
    assert "ecar" in applicable
    assert applicable.isdisjoint({"windows_event_security", "windows_event_sysmon", "syslog"})


def test_mac_path_resolution_never_uses_windows_system_defaults() -> None:
    assert resolve_image_path("zsh", "macos") == "/bin/zsh"
    with pytest.raises(ValueError, match="Mac|macos"):
        resolve_image_path("svchost.exe", "macos")
    assert resolve_image_path("svchost.exe", "windows").startswith("C:")


def test_mac_clock_is_a_distinct_modeled_profile() -> None:
    timing = endpoint_clock_timing("enterprise_standard", "macos")
    assert timing.host_offset_min_ms < 0 < timing.host_offset_max_ms
    planner = SourceTimingPlanner(clock_profile_name="enterprise_standard")
    assert planner.process_create_positive_headroom(_TIME, "macos") > timedelta(0)
    with pytest.raises(ValueError, match="Windows formats"):
        planner.process_create_positive_headroom(
            _TIME, "macos", format_names=("windows_event_sysmon",)
        )


def test_mac_benign_commands_come_from_native_catalog() -> None:
    result = generate_suspicious_cli(random.Random(10), [_user()], [_system()], _TIME)
    assert result is not None
    assert result["process_name"] == "/bin/zsh"
    assert "systemctl" not in result["command_line"]


def _seed_launchd(state: StateManager) -> None:
    state.set_current_time(_TIME - timedelta(hours=1))
    plan = state.plan_process_materialization(
        system="MAC-TEST",
        parent_pid=0,
        image="/sbin/launchd",
        command_line="/sbin/launchd",
        username="root",
        integrity_level="System",
        os_category="macos",
        fixed_pid=1,
    )
    with state.materialization_guard(plan.expected_version):
        state.materialize_process(plan)


def _render_lifecycle(path: Path, *, threaded: bool) -> list[dict[str, object]]:
    state = StateManager()
    _seed_launchd(state)
    emitter = EcarEmitter(load_format("ecar"), path, threaded=threaded)
    dispatcher = EventDispatcher(state, {"ecar": emitter})
    generator = ActivityGenerator(state, {"ecar": emitter}, dispatcher=dispatcher)
    user, system = _user(), _system()
    logon = generator.generate_logon(user, system, _TIME)
    pid = generator.generate_process(
        user, system, _TIME + timedelta(seconds=30), logon, "/bin/zsh", "/bin/zsh -c id"
    )
    identity = state.get_process_identity(system.hostname, pid)
    assert identity is not None
    assert identity.parent_pid == 1
    assert 100 <= pid < 100000
    assert identity.primary_thread is not None
    assert identity.primary_thread.tid != pid
    generator.generate_process_termination(
        user, system, _TIME + timedelta(seconds=40), pid, "/bin/zsh", logon
    )
    generator.generate_logoff(user, system, _TIME + timedelta(minutes=5), logon)
    emitter.close()
    return [json.loads(line) for line in path.read_text().splitlines()]


@pytest.mark.parametrize("threaded", [False, True])
def test_mac_ecar_lifecycle_is_correlated_and_deterministic(tmp_path: Path, threaded: bool) -> None:
    rows = _render_lifecycle(tmp_path / "first.json", threaded=threaded)
    assert rows == _render_lifecycle(tmp_path / "second.json", threaded=threaded)
    by_action = {(row["object"], row["action"]): row for row in rows}
    create = by_action[("PROCESS", "CREATE")]
    terminate = by_action[("PROCESS", "TERMINATE")]
    login = by_action[("USER_SESSION", "LOGIN")]
    logout = by_action[("USER_SESSION", "LOGOUT")]
    assert create["objectID"] == terminate["objectID"]
    assert login["objectID"] == logout["objectID"]
    assert create["properties"]["parent_image_path"] == "/sbin/launchd"
    assert create["properties"]["logon_id"] == login["properties"]["logon_id"]
    assert (
        login["timestamp_ms"]
        < create["timestamp_ms"]
        < terminate["timestamp_ms"]
        < logout["timestamp_ms"]
    )
    assert "systemd" not in json.dumps(rows)
    assert "C:\\" not in json.dumps(rows)


def test_mac_account_defaults_are_host_scoped_and_do_not_change_linux_identity() -> None:
    from evidenceforge.generation.identity import IdentityDirectory
    from evidenceforge.models.scenario import (
        BaselineActivity,
        Environment,
        OutputSpec,
        Scenario,
        TimeWindow,
    )

    scenario = Scenario(
        name="mac-identity",
        description="Invented identity contract",
        environment=Environment(description="Test", users=[_user()], systems=[_system()]),
        time_window=TimeWindow(start=_TIME, duration="1h"),
        baseline_activity=BaselineActivity(description="Test", intensity="low", variation="low"),
        output=OutputSpec(logs=[{"format": "ecar"}], destination="unused"),
    )
    directory = IdentityDirectory.from_scenario(scenario)
    account = directory.macos_account("alex", "MAC-TEST")
    assert account is not None
    assert (account.uid, account.gid, account.home, account.shell) == (
        501,
        20,
        "/Users/alex",
        "/bin/zsh",
    )
    assert directory.macos_account("alex", "another-host") is None
    assert directory.macos_account("root", "MAC-TEST").uid == 0
    linux = directory.linux_account("alex")
    assert linux is not None and linux.home == "/home/alex"
    assert linux.uid != account.uid


def test_mac_gui_logon_reuses_local_session_and_excludes_service_sessions() -> None:
    state = StateManager()
    _seed_launchd(state)
    generator = ActivityGenerator(state, {}, dispatcher=EventDispatcher(state, {}))
    user, system = _user(), _system()
    service = generator.generate_logon(user, system, _TIME, logon_type=5)
    first = generator.generate_logon(user, system, _TIME + timedelta(seconds=10))
    second = generator.generate_logon(user, system, _TIME + timedelta(minutes=1))
    assert service != first
    assert first == second
    assert (
        generator._active_user_local_macos_session(
            user, system, _TIME + timedelta(minutes=1)
        ).logon_id
        == first
    )


@pytest.mark.parametrize(
    ("image", "family"),
    [
        ("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "Chrome/"),
        ("/Applications/Firefox.app/Contents/MacOS/firefox", "Firefox/"),
        ("/Applications/Safari.app/Contents/MacOS/Safari", "Version/26"),
        ("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge", "Edg/"),
    ],
)
def test_mac_browser_agents_match_the_process_and_stay_stable(image: str, family: str) -> None:
    from evidenceforge.generation.activity.proxy_user_agents import (
        stable_browser_user_agent_for_process,
    )

    first = stable_browser_user_agent_for_process(_system(), image, "invented-process-identity")
    second = stable_browser_user_agent_for_process(
        _system(), image, "invented-process-identity", hostname="another.example.test"
    )
    assert first == second
    assert family in first and "Macintosh" in first
    assert "Windows NT" not in first and "X11" not in first


def test_mac_document_pools_keep_platform_paths_separate() -> None:
    from evidenceforge.config.provider import _document_parameter_pools

    assert _document_parameter_pools(["Quarterly"], "macos")["doc_path"] == [
        "/Users/{username}/Documents/Quarterly.docx"
    ]
    assert _document_parameter_pools(["Quarterly"], "linux")["doc_path"] == [
        "/home/{username}/Documents/Quarterly.docx"
    ]


def test_mac_terminal_chain_is_session_owned_and_reused(tmp_path: Path) -> None:
    state = StateManager()
    _seed_launchd(state)
    emitter = EcarEmitter(load_format("ecar"), tmp_path / "terminal.json")
    dispatcher = EventDispatcher(state, {"ecar": emitter})
    generator = ActivityGenerator(state, {"ecar": emitter}, dispatcher=dispatcher)
    user, system = _user(), _system()
    logon = generator.generate_logon(user, system, _TIME)
    activity = _TIME + timedelta(seconds=30)
    shell_pid = generator.ensure_macos_session_shell(user, system, logon, activity)
    assert shell_pid is not None
    assert (
        generator.ensure_macos_session_shell(user, system, logon, activity + timedelta(seconds=10))
        == shell_pid
    )
    shell = state.get_process(system.hostname, shell_pid)
    login = state.get_process(system.hostname, shell.parent_pid)
    terminal = state.get_process(system.hostname, login.parent_pid)
    assert shell.image == "/bin/zsh" and shell.command_line == "-zsh"
    assert login.image == "/usr/bin/login"
    assert terminal.image.endswith("Terminal.app/Contents/MacOS/Terminal")
    assert terminal.parent_pid == 1
    assert terminal.job_control is None
    assert shell.job_control == login.job_control
    assert login.job_control.pgid == login.job_control.session.sid == login.pid
    assert shell.logon_id == login.logon_id == terminal.logon_id == logon
    generator.generate_logoff(user, system, _TIME + timedelta(minutes=2), logon)
    emitter.close()
    rows = [json.loads(line) for line in (tmp_path / "terminal.json").read_text().splitlines()]
    creates = {
        row["objectID"] for row in rows if row["object"] == "PROCESS" and row["action"] == "CREATE"
    }
    closes = {
        row["objectID"]
        for row in rows
        if row["object"] == "PROCESS" and row["action"] == "TERMINATE"
    }
    assert len(creates) == 3
    assert closes == creates


def test_mac_ssh_client_binds_catalog_terminal_history_and_transport_hold(tmp_path: Path) -> None:
    from evidenceforge.generation.emitters.zsh_history import ZshHistoryEmitter

    state = StateManager()
    _seed_launchd(state)
    history = ZshHistoryEmitter(load_format("zsh_history"), tmp_path)
    endpoint = EcarEmitter(load_format("ecar"), tmp_path / "ssh.json")
    emitters = {"zsh_history": history, "ecar": endpoint}
    generator = ActivityGenerator(state, emitters, dispatcher=EventDispatcher(state, emitters))
    user, system = _user(), _system()
    target = System(
        hostname="SSH-TEST", ip="192.0.2.20", os="Ubuntu 24.04", type="server", services=["ssh"]
    )
    logon = generator.generate_logon(user, system, _TIME)
    opened, closed = _TIME + timedelta(minutes=2), _TIME + timedelta(minutes=4)
    before = state.materialization_digest()
    assert generator.has_implicit_ssh_client_owner(
        user=user, source_system=system, time=opened, required_until=closed
    )
    assert state.materialization_digest() == before
    result = generator.ensure_ssh_client_process(
        user=user,
        source_system=system,
        target_system=target,
        time=opened,
        process_image="",
        source_port=50001,
        required_until=closed,
    )
    assert result is not None
    pid, image = result
    client = state.get_process(system.hostname, pid)
    shell = state.get_process(system.hostname, client.parent_pid)
    assert image == client.image == "/usr/bin/ssh"
    assert client.logon_id == shell.logon_id == logon
    assert shell.image == "/bin/zsh" and shell.command_line == "-zsh"
    assert shell.start_time < client.start_time < opened
    assert "alex@SSH-TEST" in client.command_line
    assert generator.process_source_create_time(system.hostname, pid) < opened
    assert state.get_process_identity(system.hostname, pid).principal == "alex"
    history.close()
    endpoint.close()
    outputs = list(tmp_path.rglob("*.zsh_history"))
    assert len(outputs) == 1
    assert outputs[0].read_text().count(client.command_line) == 1


@pytest.mark.parametrize(
    "reason", ["no_session", "network_session", "early", "foreign_image", "clock", "deadline"]
)
def test_mac_ssh_rejection_does_not_create_prerequisite_processes(
    monkeypatch: pytest.MonkeyPatch, reason: str
) -> None:
    state = StateManager()
    _seed_launchd(state)
    generator = ActivityGenerator(state, {}, dispatcher=EventDispatcher(state, {}))
    user, system = _user(), _system()
    target = System(
        hostname="SSH-TEST", ip="192.0.2.20", os="Ubuntu 24.04", type="server", services=["ssh"]
    )
    if reason != "no_session":
        logon = state.create_session(
            username=user.username,
            system=system.hostname,
            source_ip=system.ip,
            start_time=_TIME,
            logon_type=3 if reason == "network_session" else 2,
            session_kind="network" if reason == "network_session" else "interactive",
        )
        if reason == "deadline":
            from evidenceforge.events.lifecycle import SessionEndPlan

            state.plan_session_end(
                logon, SessionEndPlan(_TIME + timedelta(seconds=150), "action_bundle")
            )
    when = _TIME + timedelta(seconds=1 if reason == "early" else 120)
    if reason == "clock":
        monkeypatch.setattr(
            generator, "_process_create_source_bound", lambda **kwargs: when + timedelta(seconds=1)
        )
    before = state.materialization_digest()
    assert (
        generator.ensure_ssh_client_process(
            user=user,
            source_system=system,
            target_system=target,
            time=when,
            process_image="/usr/bin/scp" if reason == "foreign_image" else "",
            source_port=50001,
            required_until=when + timedelta(minutes=1),
        )
        is None
    )
    assert state.materialization_digest() == before


def test_mac_ssh_busy_foreground_cannot_move_client_past_transport() -> None:
    state = StateManager()
    _seed_launchd(state)
    generator = ActivityGenerator(state, {}, dispatcher=EventDispatcher(state, {}))
    user, system = _user(), _system()
    target = System(hostname="SSH-TEST", ip="192.0.2.20", os="Ubuntu 24.04", type="server")
    logon = generator.generate_logon(user, system, _TIME)
    shell = generator.ensure_macos_session_shell(user, system, logon, _TIME + timedelta(seconds=30))
    pid = generator.generate_process(
        user,
        system,
        _TIME + timedelta(seconds=40),
        logon,
        "/usr/bin/tail",
        "tail -f /tmp/example.log",
        parent_pid=shell,
    )
    assert pid > 0
    processes = {
        (proc.pid, proc.start_time) for proc in state.get_processes_on_system(system.hostname)
    }
    result = generator.ensure_ssh_client_process(
        user=user,
        source_system=system,
        target_system=target,
        time=_TIME + timedelta(minutes=2),
        process_image="",
        source_port=50001,
        required_until=_TIME + timedelta(minutes=4),
    )
    assert result is None
    assert processes == {
        (proc.pid, proc.start_time) for proc in state.get_processes_on_system(system.hostname)
    }


@pytest.mark.parametrize("missing", [False, True])
def test_mac_ssh_uses_frozen_catalog_without_falling_back_to_package(
    monkeypatch: pytest.MonkeyPatch, missing: bool
) -> None:
    from evidenceforge.generation.activity import application_catalog

    state = StateManager()
    _seed_launchd(state)
    generator = ActivityGenerator(state, {}, dispatcher=EventDispatcher(state, {}))
    user, system = _user(), _system()
    target = System(hostname="SSH-TEST", ip="192.0.2.20", os="Ubuntu 24.04", type="server")
    logon = generator.generate_logon(user, system, _TIME)
    generator.ensure_macos_session_shell(user, system, logon, _TIME + timedelta(seconds=30))
    descriptor = SimpleNamespace(
        image_path="/example/bin/ssh",
        command_templates=["/example/bin/ssh -l {username} {ssh_target}"],
    )
    lookup = Mock(return_value=None if missing else descriptor)
    generator.dispatcher.deployment_registry = SimpleNamespace(application_descriptor=lookup)
    monkeypatch.setattr(
        application_catalog,
        "application_descriptor",
        Mock(side_effect=AssertionError("package fallback")),
    )
    # The deployment registry has independent process-content APIs; capture only
    # the process request here, while the integration gate exercises the real registry.
    materialize = Mock(return_value=-1)
    monkeypatch.setattr(generator, "generate_process", materialize)
    before = state.materialization_digest()
    assert (
        generator.ensure_ssh_client_process(
            user=user,
            source_system=system,
            target_system=target,
            time=_TIME + timedelta(minutes=2),
            process_image="",
            source_port=50001,
        )
        is None
    )
    lookup.assert_called_once_with("macos-ssh", "macos")
    if missing:
        materialize.assert_not_called()
    else:
        assert materialize.call_args.kwargs["process_name"] == "/example/bin/ssh"
        assert materialize.call_args.kwargs["command_line"].startswith(
            "/example/bin/ssh -l alex SSH-TEST"
        )
    assert state.materialization_digest() == before


@pytest.mark.parametrize("missing_entry", [False, True])
def test_mac_terminal_uses_frozen_descriptors_before_process_mutation(
    monkeypatch: pytest.MonkeyPatch, missing_entry: bool
) -> None:
    from evidenceforge.generation.activity import application_catalog
    from evidenceforge.models.exceptions import StateError

    state = StateManager()
    _seed_launchd(state)
    dispatcher = EventDispatcher(state, {})
    generator = ActivityGenerator(state, {}, dispatcher=dispatcher)
    user, system = _user(), _system()
    logon = generator.generate_logon(user, system, _TIME)
    catalog = application_catalog.load_catalog()
    descriptors = {
        entry["id"]: SimpleNamespace(
            image_path=entry["platforms"]["macos"]["image_path"],
            command_templates=entry["platforms"]["macos"]["command_templates"],
        )
        for entry in catalog["applications"]
        if entry["id"] in {"macos-terminal", "macos-login", "macos-zsh"}
    }
    if missing_entry:
        descriptors.pop("macos-zsh")
    else:
        descriptors["macos-terminal"].image_path = "/frozen/Terminal"
        descriptors["macos-terminal"].command_templates = ['"/frozen/Terminal" --test-profile']
    lookup = Mock(side_effect=lambda app_id, platform: descriptors.get(app_id))
    dispatcher.deployment_registry = SimpleNamespace(application_descriptor=lookup)
    packaged_lookup = Mock(side_effect=AssertionError("consulted mutable package catalog"))
    monkeypatch.setattr(application_catalog, "application_descriptor", packaged_lookup)
    materialize = Mock(side_effect=[501, 502, 503])
    monkeypatch.setattr(generator, "generate_process", materialize)
    if missing_entry:
        with pytest.raises(StateError, match="compiled entry macos-zsh"):
            generator.ensure_macos_session_shell(user, system, logon, _TIME + timedelta(seconds=30))
        materialize.assert_not_called()
    else:
        assert (
            generator.ensure_macos_session_shell(user, system, logon, _TIME + timedelta(seconds=30))
            == 503
        )
        assert (
            materialize.call_args_list[0].kwargs["command_line"]
            == "/frozen/Terminal --test-profile"
        )
        assert materialize.call_args_list[2].kwargs["command_line"] == "-zsh"
    packaged_lookup.assert_not_called()


@pytest.mark.parametrize("threaded", [False, True])
@pytest.mark.parametrize("shell_name", ["zsh", "bash"])
def test_mac_history_requires_an_interactive_shell_and_keeps_bash_separate(
    tmp_path: Path, threaded: bool, shell_name: str
) -> None:
    from evidenceforge.evaluation.parsers import discover_log_files
    from evidenceforge.evaluation.parsers.zsh_history import ZshHistoryParser
    from evidenceforge.generation.emitters.bash_history import BashHistoryEmitter
    from evidenceforge.generation.emitters.zsh_history import ZshHistoryEmitter

    state = StateManager()
    _seed_launchd(state)
    zsh = ZshHistoryEmitter(load_format("zsh_history"), tmp_path, threaded=threaded)
    bash = BashHistoryEmitter(load_format("bash_history"), tmp_path, threaded=threaded)
    emitters = {"zsh_history": zsh, "bash_history": bash}
    generator = ActivityGenerator(state, emitters, dispatcher=EventDispatcher(state, emitters))
    user, system = _user(), _system()
    logon = generator.generate_logon(user, system, _TIME)
    when = _TIME + timedelta(seconds=30)
    shell_pid = generator.ensure_macos_session_shell(user, system, logon, when)
    assert shell_pid is not None
    if shell_name == "bash":
        shell_pid = generator.generate_process(
            user,
            system,
            when,
            logon,
            "/bin/bash",
            "-bash",
            parent_pid=shell_pid,
        )
        when += timedelta(seconds=10)
    assert not generator.emit_macos_shell_history(
        user, system, when, "id", logon_id=logon, shell_pid=1
    )
    assert generator.emit_macos_shell_history(
        user, system, when, "id", logon_id=logon, shell_pid=shell_pid
    )
    zsh.close()
    bash.close()
    discovered = discover_log_files(tmp_path)
    other_shell = "bash" if shell_name == "zsh" else "zsh"
    assert f"{other_shell}_history" not in discovered
    history = discovered[f"{shell_name}_history"]
    assert len(history) == 1
    if shell_name == "bash":
        assert history[0].read_text().strip() == f"#{int(when.timestamp())}\nid"
        return
    assert history[0].read_text().strip() == f": {int(when.timestamp())}:0;id"
    records = list(ZshHistoryParser().parse_file(history[0]))
    assert len(records) == 1 and not records[0].parse_errors
    assert records[0].timestamp == when and records[0].fields["command"] == "id"


@pytest.mark.parametrize(
    ("image", "command", "bounded"),
    [
        (
            "/opt/homebrew/bin/git",
            "/opt/homebrew/bin/git -C /Users/alex/Projects/demo status",
            True,
        ),
        ("/opt/homebrew/bin/ssh", "/opt/homebrew/bin/ssh -V", True),
        ("/opt/homebrew/bin/ssh", "/opt/homebrew/bin/ssh server.example.test", False),
        ("/opt/homebrew/bin/kubectl", "/opt/homebrew/bin/kubectl get pods", True),
        ("/opt/homebrew/bin/kubectl", "/opt/homebrew/bin/kubectl get pods --watch", False),
        ("/opt/homebrew/bin/git", "/opt/homebrew/bin/git status &", False),
        ("/usr/bin/systemctl", "/usr/bin/systemctl status", False),
        ("/bin/zsh", "-zsh", False),
    ],
)
def test_mac_lifetime_admits_only_profiled_short_commands(
    image: str, command: str, bounded: bool
) -> None:
    from evidenceforge.generation.activity.process_helpers import _macos_foreground_lifetime

    assert (_macos_foreground_lifetime(image, command) is not None) is bounded


def test_mac_foreground_commands_serialize_and_close_before_session(tmp_path: Path) -> None:
    state = StateManager()
    _seed_launchd(state)
    path = tmp_path / "process.json"
    emitter = EcarEmitter(load_format("ecar"), path)
    emitters = {"ecar": emitter}
    generator = ActivityGenerator(state, emitters, dispatcher=EventDispatcher(state, emitters))
    user, system = _user(), _system()
    logon = generator.generate_logon(user, system, _TIME)
    when = _TIME + timedelta(seconds=30)
    shell_pid = generator.ensure_macos_session_shell(user, system, logon, when)
    assert shell_pid is not None
    image = "/opt/homebrew/bin/git"
    command = image + " -C /Users/alex/Projects/demo status"
    first = generator.generate_process(
        user, system, when, logon, image, command, parent_pid=shell_pid
    )
    first_close = generator.foreground_process_termination_time(system.hostname, first)
    assert first_close is not None and when < first_close < when + timedelta(seconds=50)
    second = generator.generate_process(
        user, system, when, logon, image, command, parent_pid=shell_pid
    )
    second_state = state.get_process(system.hostname, second)
    assert second_state is not None and second_state.start_time > first_close
    second_close = generator.foreground_process_termination_time(system.hostname, second)
    assert second_close is not None and second_close > second_state.start_time
    generator._finalize_due_process_lifetimes(when + timedelta(minutes=2), exhaust=True)
    generator.generate_logoff(user, system, when + timedelta(minutes=3), logon)
    emitter.close()
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    processes = [row for row in rows if row["object"] == "PROCESS"]
    creates = {row["objectID"] for row in processes if row["action"] == "CREATE"}
    closes = [row["objectID"] for row in processes if row["action"] == "TERMINATE"]
    assert set(closes) == creates
    assert len(closes) == len(set(closes))


def test_mac_unbounded_foreground_child_requires_an_explicit_release() -> None:
    state = StateManager()
    _seed_launchd(state)
    generator = ActivityGenerator(state, {}, dispatcher=EventDispatcher(state, {}))
    user, system = _user(), _system()
    logon = generator.generate_logon(user, system, _TIME)
    when = _TIME + timedelta(seconds=30)
    shell = generator.ensure_macos_session_shell(user, system, logon, when)
    assert shell is not None
    image = "/opt/homebrew/bin/kubectl"
    first = generator.generate_process(
        user, system, when, logon, image, image + " get pods --watch", parent_pid=shell
    )
    assert (
        first > 0 and generator.foreground_process_termination_time(system.hostname, first) is None
    )
    command = "/opt/homebrew/bin/ssh -V"
    assert (
        generator.generate_process(
            user,
            system,
            when + timedelta(seconds=10),
            logon,
            "/opt/homebrew/bin/ssh",
            command,
            parent_pid=shell,
        )
        == 0
    )
    generator.generate_process_termination(
        user, system, when + timedelta(seconds=20), first, image, logon
    )
    assert (
        generator.generate_process(
            user,
            system,
            when + timedelta(seconds=30),
            logon,
            "/opt/homebrew/bin/ssh",
            command,
            parent_pid=shell,
        )
        > 0
    )


def test_history_disk_forecasts_count_only_eligible_platforms() -> None:
    from evidenceforge.generation.resource_forecast import _system_count_for_scope

    # Only the environment/system interface is consumed by this counting policy.
    scenario = SimpleNamespace(
        environment=SimpleNamespace(
            systems=[
                _system("macOS 26"),
                _system("Windows 11"),
                _system("Ubuntu 24.04"),
                _system("FreeBSD"),
            ]
        )
    )
    assert _system_count_for_scope(scenario, "macos") == 1
    assert _system_count_for_scope(scenario, "posix") == 2
    assert _system_count_for_scope(scenario, "windows") == 1
    assert _system_count_for_scope(scenario, "linux") == 1


def test_mac_reused_pid_and_tid_preserve_distinct_retained_lifetime_snapshots(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = StateManager()
    state.set_current_time(_TIME)
    # Simulate allocator wrap without reserving a permanent boot-service PID.
    preview = state._preview_linux_pid

    def reused_pid(**kwargs: object) -> tuple:
        _pid, logical_position, bucket_patch, candidates = preview(**kwargs)
        return 1200, logical_position, bucket_patch, candidates

    monkeypatch.setattr(state, "_preview_linux_pid", reused_pid)
    snapshots = []
    threads = []
    for index, image in enumerate(("/bin/zsh", "/usr/bin/id")):
        start = _TIME + timedelta(seconds=index * 10)
        plan = state.plan_process_materialization(
            system="MAC-TEST",
            parent_pid=0,
            image=image,
            command_line=image,
            username="alex",
            integrity_level="Medium",
            os_category="macos",
            start_time=start,
        )
        process = state.materialize_process(plan)
        snapshot = state.get_process_identity("MAC-TEST", process.pid)
        assert snapshot is not None
        snapshots.append(snapshot)
        threads.append(state.create_thread("MAC-TEST", snapshot.object_id, tid=7777))
        if index == 0:
            assert state.end_process("MAC-TEST", process.pid, start + timedelta(seconds=2))

    first, second = snapshots
    assert first.pid == second.pid == 1200
    assert first.object_id != second.object_id
    assert first.lifecycle_group_id != second.lifecycle_group_id
    assert first.image == "/bin/zsh" and second.image == "/usr/bin/id"
    assert state.get_process_identity_by_object_id(first.object_id) == first
    assert state.get_process_identity_by_object_id(second.object_id) == second
    assert threads[0].canonical_key != threads[1].canonical_key
    assert threads[0].object_id != threads[1].object_id
    assert state.get_thread("MAC-TEST", first.object_id, 7777) is None
    assert state.get_thread("MAC-TEST", second.object_id, 7777) == threads[1]
