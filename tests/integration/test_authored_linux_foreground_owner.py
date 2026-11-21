# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""An occupied GUI terminal can use a sibling without canceling its foreground job."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import Scenario
from tests.integration.test_ground_truth_reconciliation import _scenario
from tests.unit.test_process_lifetimes import _linux_interactive_shell


@pytest.mark.parametrize("command", ["docker compose logs -f --tail 20", "journalctl -f -u api"])
def test_authored_gui_command_uses_an_independent_shell_without_cancelling_work(
    command: str,
) -> None:
    generator, state, system, user, luid, shell_pid, _events = _linux_interactive_shell(
        session_kind="interactive"
    )
    start = datetime(2024, 3, 18, 13, tzinfo=UTC)
    image = "/usr/bin/" + command.split()[0]
    blocked_pid = generator.generate_process(
        user=user,
        system=system,
        time=start,
        logon_id=luid,
        process_name=image,
        command_line=command,
        parent_pid=shell_pid,
        suppress_command_file_effect=True,
    )
    blocked = state.get_process(system.hostname, blocked_pid)
    assert blocked is not None and blocked.end_time is None
    candidate = start + timedelta(minutes=5)
    assert (
        generator.reserve_linux_foreground_process_start(
            system=system,
            username=user.username,
            logon_id=luid,
            parent_pid=shell_pid,
            requested_time=candidate,
            process_name="/usr/bin/tar",
            command_line="tar -czf /tmp/x /tmp/a",
            authoritative_time=True,
        )
        is None
    )
    prepared = generator._prepare_linux_authored_foreground_owner(
        system=system,
        user=user,
        logon_id=luid,
        time=candidate,
        process_name="/usr/bin/tar",
        command_line="tar -czf /tmp/x /tmp/a",
    )
    assert prepared is not None
    parent_pid, at = prepared
    assert parent_pid != shell_pid and at >= candidate
    sibling = state.get_process(system.hostname, parent_pid)
    original_shell = state.get_process(system.hostname, shell_pid)
    assert sibling is not None and original_shell is not None
    assert sibling.image == "/bin/bash" and sibling.logon_id == luid
    assert sibling.parent_pid == original_shell.parent_pid
    assert state.get_process(system.hostname, blocked_pid) is blocked
    assert blocked.end_time is None
    assert generator.foreground_process_termination_time(system.hostname, blocked_pid) is None
    again = generator._prepare_linux_authored_foreground_owner(
        system=system,
        user=user,
        logon_id=luid,
        time=candidate,
        process_name="/usr/bin/curl",
        command_line="curl https://example.test/",
    )
    assert again is not None and again[0] == parent_pid


@pytest.mark.parametrize("kind", ["ssh", "interactive"])
def test_authored_adapter_does_not_invent_an_ssh_channel_or_console_terminal(kind: str) -> None:
    generator, state, system, user, luid, shell_pid, _events = _linux_interactive_shell(
        session_kind=kind
    )
    shell = state.get_process(system.hostname, shell_pid)
    assert shell is not None
    root = state.get_process(system.hostname, shell.parent_pid)
    assert root is not None
    if kind == "interactive":
        root.image = "/bin/login"
    before = tuple(p.pid for p in state.get_processes_on_system(system.hostname))
    assert (
        generator._prepare_linux_authored_foreground_owner(
            system=system,
            user=user,
            logon_id=luid,
            time=datetime(2024, 3, 18, 13, 5, tzinfo=UTC),
            process_name="/usr/bin/tar",
            command_line="tar -czf /tmp/x /tmp/a",
        )
        is None
    )
    assert tuple(p.pid for p in state.get_processes_on_system(system.hostname)) == before


@pytest.mark.parametrize("explicit_parent", [False, True])
def test_typed_authored_commands_only_rebind_an_implicit_gui_shell(
    tmp_path: Path, explicit_parent: bool
) -> None:
    events: list[dict] = []
    if explicit_parent:
        events.append(
            {
                "type": "process",
                "process_name": "/bin/bash",
                "command_line": "bash -il",
                "process_ref": "chosen-shell",
            }
        )
    events.append(
        {
            "type": "process",
            "process_name": "/usr/bin/nc",
            "command_line": "nc -l 127.0.0.1 9999",
        }
    )
    events.append(
        {
            "type": "process",
            "process_name": "/usr/bin/tar",
            "command_line": "tar -czf /tmp/review.tgz /var/log/app.log",
        }
    )
    if explicit_parent:
        for event in events[1:]:
            event["parent_ref"] = "chosen-shell"
    scenario = _scenario(tmp_path, events, formats=["ecar", "syslog"])
    data = scenario.model_dump(mode="json")
    data["environment"]["systems"][0]["os"] = "Ubuntu 22.04"
    data["storyline"][0]["event_spacing"] = {
        "mode": "automated",
        "min_delay": "20s",
        "max_delay": "25s",
    }
    engine = GenerationEngine(Scenario.model_validate(data), tmp_path)
    if explicit_parent:
        with pytest.raises(StateError, match="shell_foreground_occupied"):
            engine.generate()
        return
    engine.generate()
    rows = [
        json.loads(line)
        for path in tmp_path.rglob("ecar.json")
        for line in path.read_text().splitlines()
    ]
    creates = [r for r in rows if r.get("object") == "PROCESS" and r.get("action") == "CREATE"]
    watcher = next(
        r for r in creates if r["properties"].get("command_line") == events[0]["command_line"]
    )
    tar = next(
        r for r in creates if r["properties"].get("command_line") == events[1]["command_line"]
    )
    assert watcher["ppid"] != tar["ppid"]
    assert not any(
        r.get("action") == "TERMINATE" and r.get("objectID") == watcher["objectID"] for r in rows
    )
