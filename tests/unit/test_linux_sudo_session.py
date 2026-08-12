"""Tests for the Linux sudo action lifecycle."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from evidenceforge.generation.actions import (
    LinuxSudoSessionActionBundle,
    LinuxSudoSessionRequest,
)
from evidenceforge.generation.emitters.syslog import SyslogEmitter


def _request() -> LinuxSudoSessionRequest:
    """Return one representative allowed sudo request."""

    return LinuxSudoSessionRequest(
        system=SimpleNamespace(hostname="APP-01"),
        time=datetime(2024, 3, 18, 12, 0, tzinfo=UTC),
        command_message=(
            "deploy : TTY=pts/1 ; PWD=/srv/app ; USER=root ; COMMAND=/usr/bin/systemctl status nginx"
        ),
        sudo_user="deploy",
        uid=1002,
        runtime=timedelta(seconds=2),
    )


def test_linux_sudo_action_orders_authorization_before_pam_lifecycle() -> None:
    """The action bundle should own command, open, and close causal order."""

    executor = Mock()
    executor.generate_linux_sudo_processes.return_value = (
        701258,
        701259,
        timedelta(0),
        "pts/1",
    )
    request = _request()

    LinuxSudoSessionActionBundle(executor=executor, request=request).execute()

    calls = executor.generate_syslog_event.call_args_list
    assert len(calls) == 3
    assert "COMMAND=/usr/bin/systemctl" in calls[0].kwargs["message"]
    assert "session opened" in calls[1].kwargs["message"]
    assert "session closed" in calls[2].kwargs["message"]
    assert calls[0].kwargs["time"] < calls[1].kwargs["time"] < calls[2].kwargs["time"]
    assert {call.kwargs["pid"] for call in calls} == {701258}
    auth_contexts = [call.kwargs["auth"] for call in calls]
    assert auth_contexts[0] is auth_contexts[1] is auth_contexts[2]
    assert auth_contexts[0].username == "deploy"
    assert auth_contexts[0].logon_id.startswith("linux-sudo-session-")
    create = executor.generate_linux_sudo_processes.call_args.kwargs
    assert create["command"] == "/usr/bin/systemctl status nginx"
    assert create["sudo_user"] == "deploy"
    assert create["tty"] == "pts/1"
    terminations = executor.terminate_linux_sudo_process.call_args_list
    assert [call.kwargs["pid"] for call in terminations] == [701259, 701258]
    assert terminations[-1].kwargs["time"] > calls[2].kwargs["time"]


def test_linux_sudo_action_anchor_and_timing_are_deterministic() -> None:
    """Sibling callers should receive the same durable identity and phase timing."""

    first_executor = Mock()
    second_executor = Mock()
    first_executor.generate_linux_sudo_processes.return_value = (
        701258,
        701259,
        timedelta(0),
        "pts/1",
    )
    second_executor.generate_linux_sudo_processes.return_value = (
        701258,
        701259,
        timedelta(0),
        "pts/1",
    )
    request = _request()
    first = LinuxSudoSessionActionBundle(first_executor, request)
    second = LinuxSudoSessionActionBundle(second_executor, request)

    first.execute()
    second.execute()

    assert first.anchor == second.anchor
    assert first_executor.generate_syslog_event.call_args_list == (
        second_executor.generate_syslog_event.call_args_list
    )


def test_linux_sudo_action_renders_canonical_tty_assignment() -> None:
    """The syslog command should use the session layer's conflict-free TTY."""

    executor = Mock()
    executor.generate_linux_sudo_processes.return_value = (
        701258,
        701259,
        timedelta(0),
        "pts/7",
    )

    LinuxSudoSessionActionBundle(executor=executor, request=_request()).execute()

    command_event = executor.generate_syslog_event.call_args_list[0]
    assert "TTY=pts/7" in command_event.kwargs["message"]
    assert "TTY=pts/1" not in command_event.kwargs["message"]


def test_linux_sudo_action_rejects_denied_command_as_session() -> None:
    """Denied sudo attempts must remain standalone and never open PAM sessions."""

    with pytest.raises(ValueError, match="allowed COMMAND"):
        LinuxSudoSessionRequest(
            system=SimpleNamespace(hostname="APP-01"),
            time=datetime(2024, 3, 18, 12, 0, tzinfo=UTC),
            command_message=(
                "deploy : command not allowed ; TTY=pts/1 ; USER=root ; COMMAND=/usr/bin/id"
            ),
            sudo_user="deploy",
            uid=1002,
            runtime=timedelta(seconds=1),
        )


def test_sudo_finalizer_repairs_observation_jitter_to_command_open_close() -> None:
    """Both syslog output paths should preserve the source-native lifecycle order."""

    lines = [
        "<86>1 2024-03-18T12:00:00.080000Z APP-01 sudo 701258 - - "
        "pam_unix(sudo:session): session opened for user root(uid=0) by deploy(uid=1002)",
        "<85>1 2024-03-18T12:00:00.100000Z APP-01 sudo 701258 - - "
        "deploy : TTY=pts/1 ; PWD=/srv/app ; USER=root ; COMMAND=/usr/bin/id",
        "<86>1 2024-03-18T12:00:00.090000Z APP-01 sudo 701258 - - "
        "pam_unix(sudo:session): session closed for user root",
    ]

    normalized = SyslogEmitter._normalize_sudo_session_lifecycles_for_lines(lines)

    assert "COMMAND=/usr/bin/id" in normalized[0]
    assert "session opened" in normalized[1]
    assert "session closed" in normalized[2]
    assert "2024-03-18T12:00:00.101000Z" in normalized[1]
    assert "2024-03-18T12:00:00.102000Z" in normalized[2]
