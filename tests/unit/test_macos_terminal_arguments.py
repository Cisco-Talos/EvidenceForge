# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

import shlex
from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.responsibility import ProcessResponsibility
from evidenceforge.generation.actions.process_execution import ProcessExecutionRequest
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.state_manager import StateManager
from tests.unit.test_macos_foundations import _TIME, _seed_launchd, _system, _user


def _request() -> ProcessExecutionRequest:
    return ProcessExecutionRequest(
        user=_user(),
        system=_system(),
        time=_TIME,
        logon_id="invented-session",
        process_name="/usr/bin/login",
        command_line="/usr/bin/login -fp alex",
        parent_pid=1,
        require_exact_parent=True,
    )


def test_explicit_argument_identity_preserves_omitted_request_defaults() -> None:
    request = _request()
    assert request.stable_id == replace(request, arguments=None).stable_id
    explicit = replace(request, arguments=("/usr/bin/login", "-fp", "alex"))
    assert explicit.stable_id != request.stable_id
    assert explicit.stable_id == replace(explicit).stable_id


def test_explicit_launch_responsibility_participates_in_intent_identity() -> None:
    request = replace(
        _request(), macos_launch_kind="user", arguments=("/usr/bin/login", "-fp", "alex")
    )
    assert request.stable_id == replace(request, macos_responsibility=None).stable_id
    assert (
        replace(request, macos_responsibility=ProcessResponsibility(None)).stable_id
        != request.stable_id
    )


@pytest.mark.parametrize("damage", ["linux", "kind", "parent", "arguments", "type"])
def test_explicit_launch_responsibility_requires_exact_mac_user_intent(damage: str) -> None:
    changes: dict[str, object] = {
        "macos_launch_kind": "user",
        "arguments": ("/usr/bin/login", "-fp", "alex"),
        "macos_responsibility": ProcessResponsibility(None),
    }
    if damage == "linux":
        changes["system"] = _system("Ubuntu 24.04")
    elif damage == "kind":
        changes["macos_launch_kind"] = None
    elif damage == "parent":
        changes["require_exact_parent"] = False
    elif damage == "arguments":
        changes["arguments"] = None
    else:
        changes["macos_responsibility"] = "self"
    with pytest.raises(ValueError, match="responsibility"):
        replace(_request(), **changes)


@pytest.mark.parametrize(
    "damage", ["display", "list", "empty", "nul", "windows", "linux", "parent"]
)
def test_explicit_process_argument_admission_rejects_invalid_or_foreign_requests(
    damage: str,
) -> None:
    changes: dict[str, object] = {"arguments": ("/usr/bin/login", "-fp", "alex")}
    if damage == "display":
        changes["command_line"] = "another display"
    elif damage == "list":
        changes["arguments"] = ["/usr/bin/login", "-fp", "alex"]
    elif damage == "empty":
        changes["arguments"] = ()
    elif damage == "nul":
        changes["arguments"] = ("/usr/bin/login", "bad\0")
    elif damage in {"windows", "linux"}:
        changes["system"] = _system("Windows 11" if damage == "windows" else "Ubuntu 24.04")
    else:
        changes["require_exact_parent"] = False
    with pytest.raises(ValueError):
        replace(_request(), **changes)


def test_production_terminal_chain_retains_exact_argument_vectors_through_recovery() -> None:
    state = StateManager()
    _seed_launchd(state)
    generator = ActivityGenerator(state, {}, dispatcher=EventDispatcher(state, {}))
    user, system = _user(), _system()
    logon = generator.generate_logon(user, system, _TIME)
    at = _TIME + timedelta(seconds=30)
    shell_pid = generator.ensure_macos_session_shell(user, system, logon, at)
    assert shell_pid is not None
    shell = state.get_process_identity(system.hostname, shell_pid)
    login = state.get_process_identity(system.hostname, shell.parent_pid)
    terminal = state.get_process_identity(system.hostname, login.parent_pid)
    assert shell.arguments == ("-zsh",)
    assert login.arguments == ("/usr/bin/login", "-fp", user.username)
    assert terminal.arguments == (terminal.image,)
    for process in (terminal, login, shell):
        assert process.command_line == shlex.join(process.arguments)
        assert process.environment is None
    recovered = StateManager()
    _restore_head(recovered, _capture_head(state))
    for process in (terminal, login, shell):
        assert recovered.get_process_identity(system.hostname, process.pid) == process
    assert (
        generator.ensure_macos_session_shell(user, system, logon, at + timedelta(seconds=1))
        == shell_pid
    )
