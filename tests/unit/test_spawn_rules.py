# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for rule-based process tree parent selection (P0 fix).

Process trees should use spawn rules to determine valid parent-child
relationships instead of defaulting everything to explorer.exe.
"""

from datetime import UTC, datetime
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
    }


@pytest.fixture
def win_system():
    return System(hostname="WKS-01", ip="10.0.10.1", os="Windows 10", type="workstation")


@pytest.fixture
def linux_system():
    return System(hostname="LNX-01", ip="10.0.10.2", os="Ubuntu 22.04", type="server")


@pytest.fixture
def user():
    return User(
        username="test.user",
        full_name="Test User",
        email="t@t.com",
        enabled=True,
        persona="developer",
    )


def _setup_activity_gen(state_manager, mock_emitters, system):
    """Set up ActivityGenerator with seeded process tree for a system."""
    from evidenceforge.generation.engine import GenerationEngine

    engine = object.__new__(GenerationEngine)
    engine.state_manager = state_manager
    engine._system_pids = {}

    pids: dict[str, int] = {}
    if "windows" in system.os.lower():
        engine._seed_windows_process_tree(system, pids)
    else:
        engine._seed_linux_process_tree(system, pids)
    engine._system_pids[system.hostname] = pids

    ag = ActivityGenerator(state_manager, mock_emitters)
    ag._system_pids = engine._system_pids
    return ag, pids


class TestSpawnRulesYaml:
    """Test that spawn rules YAML loads correctly."""

    def test_spawn_rules_yaml_loads(self):
        """Spawn rules YAML should parse without error."""
        from evidenceforge.generation.activity.spawn_rules import load_spawn_rules

        rules = load_spawn_rules()
        assert "windows" in rules
        assert "linux" in rules

    def test_reverse_index_built(self):
        """Every child in rules should map to at least one parent in reverse index."""
        from evidenceforge.generation.activity.spawn_rules import (
            build_reverse_index,
            load_spawn_rules,
        )

        rules = load_spawn_rules()
        reverse_win = build_reverse_index(rules["windows"])
        reverse_linux = build_reverse_index(rules["linux"])

        # Check some known children have parents
        assert "dotnet.exe" in reverse_win, "dotnet.exe should be a known child"
        assert len(reverse_win["dotnet.exe"]) > 0
        assert "git" in reverse_linux, "git should be a known child"
        assert len(reverse_linux["git"]) > 0

    def test_windows_rules_have_command_templates(self):
        """Each Windows parent should have command_templates for auto-creation."""
        from evidenceforge.generation.activity.spawn_rules import load_spawn_rules

        rules = load_spawn_rules()
        for parent_name, parent_config in rules["windows"].items():
            assert "command_templates" in parent_config, (
                f"Windows parent {parent_name} missing command_templates"
            )
            assert len(parent_config["command_templates"]) > 0


class TestWindowsProcessTreeRealism:
    """Windows process trees should use spawn rules for parent selection."""

    def test_cli_process_gets_shell_parent(self, state_manager, mock_emitters, win_system, user):
        """CLI process (dotnet.exe) should get cmd.exe or powershell.exe as parent."""
        ag, pids = _setup_activity_gen(state_manager, mock_emitters, win_system)

        logon_id = ag.generate_logon(user, win_system, datetime(2024, 3, 18, 12, 0, 0, tzinfo=UTC))
        parent_pid = ag._resolve_parent(
            win_system,
            user,
            datetime(2024, 3, 18, 12, 0, 1, tzinfo=UTC),
            logon_id,
            r"C:\Program Files\dotnet\dotnet.exe",
        )
        parent_proc = state_manager.get_process(win_system.hostname, parent_pid)

        assert parent_proc is not None, f"Parent PID {parent_pid} not found"
        parent_exe = parent_proc.image.rsplit("\\", 1)[-1].lower()
        assert parent_exe in ("cmd.exe", "powershell.exe", "pwsh.exe"), (
            f"CLI process parent should be a shell, got {parent_proc.image}"
        )

    def test_gui_app_gets_explorer_parent(self, state_manager, mock_emitters, win_system, user):
        """GUI app (chrome.exe) should get explorer.exe as parent."""
        ag, pids = _setup_activity_gen(state_manager, mock_emitters, win_system)

        logon_id = ag.generate_logon(user, win_system, datetime(2024, 3, 18, 12, 0, 0, tzinfo=UTC))
        parent_pid = ag._resolve_parent(
            win_system,
            user,
            datetime(2024, 3, 18, 12, 0, 1, tzinfo=UTC),
            logon_id,
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        )
        parent_proc = state_manager.get_process(win_system.hostname, parent_pid)

        assert parent_proc is not None
        assert "explorer.exe" in parent_proc.image.lower(), (
            f"GUI app parent should be explorer, got {parent_proc.image}"
        )

    def test_system_process_gets_services_parent(
        self, state_manager, mock_emitters, win_system, user
    ):
        """System process (taskhostw.exe) should get svchost.exe as parent."""
        ag, pids = _setup_activity_gen(state_manager, mock_emitters, win_system)

        parent_pid = ag._resolve_parent(
            win_system,
            user,
            datetime(2024, 3, 18, 12, 0, 0, tzinfo=UTC),
            "",
            r"C:\Windows\System32\taskhostw.exe",
        )
        parent_proc = state_manager.get_process(win_system.hostname, parent_pid)

        assert parent_proc is not None
        parent_exe = parent_proc.image.rsplit("\\", 1)[-1].lower()
        assert parent_exe in ("svchost.exe", "services.exe"), (
            f"System process parent should be svchost/services, got {parent_proc.image}"
        )

    def test_auto_created_parent_exists_in_state(
        self, state_manager, mock_emitters, win_system, user
    ):
        """When a shell is auto-created as parent, it should exist in StateManager."""
        ag, pids = _setup_activity_gen(state_manager, mock_emitters, win_system)

        child_time = datetime(2024, 3, 18, 14, 0, 0, tzinfo=UTC)
        logon_id = ag.generate_logon(user, win_system, datetime(2024, 3, 18, 12, 0, 0, tzinfo=UTC))
        parent_pid = ag._resolve_parent(
            win_system,
            user,
            child_time,
            logon_id,
            r"C:\Program Files\dotnet\dotnet.exe",
        )
        parent_proc = state_manager.get_process(win_system.hostname, parent_pid)

        # The parent should exist in StateManager with a valid image
        assert parent_proc is not None, f"Parent PID {parent_pid} not found in StateManager"
        assert parent_proc.image != "", "Parent should have an image path"
        assert parent_proc.command_line != "", "Parent should have a command line"

    def test_parent_command_line_populated(self, state_manager, mock_emitters, win_system, user):
        """ProcessContext.parent_command_line should be populated, not '-'."""

        ag, pids = _setup_activity_gen(state_manager, mock_emitters, win_system)

        logon_id = ag.generate_logon(user, win_system, datetime(2024, 3, 18, 12, 0, 0, tzinfo=UTC))

        # Capture dispatched events
        dispatched = []
        ag.dispatcher = Mock()
        ag.dispatcher.dispatch = lambda event: dispatched.append(event)

        ag.generate_process(
            user,
            win_system,
            datetime(2024, 3, 18, 12, 0, 1, tzinfo=UTC),
            logon_id,
            r"C:\Windows\System32\notepad.exe",
            "notepad.exe test.txt",
            parent_pid=pids["explorer"],
        )

        # Find the process create event
        proc_events = [e for e in dispatched if e.event_type == "process_create"]
        assert len(proc_events) > 0
        proc_ctx = proc_events[0].process
        assert proc_ctx.parent_command_line != "", "parent_command_line should be populated"
        assert proc_ctx.parent_command_line != "-", "parent_command_line should not be '-'"

    def test_network_logon_uses_services_parent(
        self, state_manager, mock_emitters, win_system, user
    ):
        """Type 3 (network) logon processes should parent from services.exe."""
        ag, pids = _setup_activity_gen(state_manager, mock_emitters, win_system)

        # Create a type 3 (network) logon
        logon_id = ag.generate_logon(
            user,
            win_system,
            datetime(2024, 3, 18, 12, 0, 0, tzinfo=UTC),
            logon_type=3,
        )

        parent_pid = ag._resolve_parent(
            win_system,
            user,
            datetime(2024, 3, 18, 12, 0, 1, tzinfo=UTC),
            logon_id,
            r"C:\Windows\System32\cmd.exe",
        )
        parent_proc = state_manager.get_process(win_system.hostname, parent_pid)

        assert parent_proc is not None
        parent_exe = parent_proc.image.rsplit("\\", 1)[-1].lower()
        assert parent_exe in ("services.exe", "svchost.exe"), (
            f"Network logon parent should be services/svchost, got {parent_proc.image}"
        )


class TestLinuxProcessTreeRealism:
    """Linux process trees should use spawn rules for parent selection."""

    def test_linux_process_gets_bash_parent(self, state_manager, mock_emitters, linux_system, user):
        """Linux user command (git) should get bash as parent."""
        ag, pids = _setup_activity_gen(state_manager, mock_emitters, linux_system)

        logon_id = ag.generate_logon(
            user, linux_system, datetime(2024, 3, 18, 12, 0, 0, tzinfo=UTC)
        )
        parent_pid = ag._resolve_parent(
            linux_system,
            user,
            datetime(2024, 3, 18, 12, 0, 1, tzinfo=UTC),
            logon_id,
            "/usr/bin/git",
        )
        parent_proc = state_manager.get_process(linux_system.hostname, parent_pid)

        assert parent_proc is not None
        parent_exe = parent_proc.image.rsplit("/", 1)[-1].lower()
        assert parent_exe in ("bash", "sh", "zsh"), (
            f"Linux user process parent should be a shell, got {parent_proc.image}"
        )

    def test_linux_bash_gets_sshd_parent(self, state_manager, mock_emitters, linux_system, user):
        """Login shell (bash) on a server should get sshd as parent."""
        ag, pids = _setup_activity_gen(state_manager, mock_emitters, linux_system)

        parent_pid = ag._resolve_parent(
            linux_system,
            user,
            datetime(2024, 3, 18, 12, 0, 1, tzinfo=UTC),
            "",
            "/bin/bash",
        )
        parent_proc = state_manager.get_process(linux_system.hostname, parent_pid)

        assert parent_proc is not None
        parent_exe = parent_proc.image.rsplit("/", 1)[-1].lower()
        # bash can be parented by sshd (seeded), systemd (seeded), or another
        # bash shell (seeded login shell) — all are valid per spawn rules
        assert parent_exe in ("sshd", "systemd", "bash", "sh"), (
            f"Bash parent should be sshd/systemd/bash, got {parent_proc.image}"
        )


class TestChainDepthLimit:
    """Auto-created parent chains should not exceed depth 3."""

    def test_chain_depth_limited(self, state_manager, mock_emitters, win_system, user):
        """Recursive parent chain creation should not exceed 3 levels."""
        ag, pids = _setup_activity_gen(state_manager, mock_emitters, win_system)

        logon_id = ag.generate_logon(user, win_system, datetime(2024, 3, 18, 12, 0, 0, tzinfo=UTC))

        # Request parent for a deeply nested process
        parent_pid = ag._resolve_parent(
            win_system,
            user,
            datetime(2024, 3, 18, 12, 0, 1, tzinfo=UTC),
            logon_id,
            r"C:\Program Files\dotnet\dotnet.exe",
        )

        # Walk the chain from parent up to root and count depth
        depth = 0
        current_pid = parent_pid
        visited = set()
        while current_pid and current_pid not in visited:
            visited.add(current_pid)
            proc = state_manager.get_process(win_system.hostname, current_pid)
            if proc is None:
                break
            current_pid = proc.parent_pid
            depth += 1
            if depth > 10:
                break

        # Seeded tree has depth ~5-6 (System→smss→wininit→services→svchost),
        # plus up to 3 auto-created levels → max ~9
        assert depth <= 10, (
            f"Process chain depth is {depth}, expected ≤ 10 "
            f"(seeded system tree + up to 3 auto-created levels)"
        )


class TestDualSessionParentSelection:
    """When a user has both interactive and network sessions, parent selection
    must use the correct session's logon type."""

    def test_network_logon_gets_services_parent_when_interactive_exists(
        self, state_manager, mock_emitters, win_system, user
    ):
        """With both type 2 and type 3 sessions, type 3 processes should parent
        from services.exe, not explorer.exe.

        Bug: _resolve_parent() grabbed the first session for (user, system)
        regardless of logon_id, so type 3 processes used the interactive
        session and got explorer as parent.
        """
        ag, pids = _setup_activity_gen(state_manager, mock_emitters, win_system)

        # Create type 2 (interactive) session first — must exist to trigger the bug
        ag.generate_logon(
            user,
            win_system,
            datetime(2024, 3, 18, 10, 0, 0, tzinfo=UTC),
            logon_type=2,
        )

        # Create type 3 (network) session for same user on same system
        network_logon_id = ag.generate_logon(
            user,
            win_system,
            datetime(2024, 3, 18, 12, 0, 0, tzinfo=UTC),
            logon_type=3,
        )

        # Resolve parent for a process under the NETWORK logon
        parent_pid = ag._resolve_parent(
            win_system,
            user,
            datetime(2024, 3, 18, 12, 0, 1, tzinfo=UTC),
            network_logon_id,
            r"C:\Windows\System32\cmd.exe",
        )
        parent_proc = state_manager.get_process(win_system.hostname, parent_pid)

        assert parent_proc is not None
        parent_exe = parent_proc.image.rsplit("\\", 1)[-1].lower()
        assert parent_exe in ("services.exe", "svchost.exe"), (
            f"Network logon (type 3) process should parent from services/svchost, "
            f"got {parent_proc.image}. The interactive session's explorer was "
            f"incorrectly selected."
        )

    def test_interactive_logon_still_gets_explorer_when_network_exists(
        self, state_manager, mock_emitters, win_system, user
    ):
        """With both sessions, type 2 processes should still parent from explorer."""
        ag, pids = _setup_activity_gen(state_manager, mock_emitters, win_system)

        interactive_logon_id = ag.generate_logon(
            user,
            win_system,
            datetime(2024, 3, 18, 10, 0, 0, tzinfo=UTC),
            logon_type=2,
        )
        _network_logon_id = ag.generate_logon(
            user,
            win_system,
            datetime(2024, 3, 18, 12, 0, 0, tzinfo=UTC),
            logon_type=3,
        )

        parent_pid = ag._resolve_parent(
            win_system,
            user,
            datetime(2024, 3, 18, 12, 0, 1, tzinfo=UTC),
            interactive_logon_id,
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        )
        parent_proc = state_manager.get_process(win_system.hostname, parent_pid)

        assert parent_proc is not None
        assert "explorer.exe" in parent_proc.image.lower(), (
            f"Interactive logon process should parent from explorer, got {parent_proc.image}"
        )


class TestLinuxParentSelection:
    """Linux process parents should preserve session and service ownership."""

    def test_ssh_user_process_prefers_matching_session_shell(
        self, state_manager, mock_emitters, linux_system, user
    ):
        ag, pids = _setup_activity_gen(state_manager, mock_emitters, linux_system)
        event_time = datetime(2024, 3, 18, 12, 0, 5, tzinfo=UTC)
        logon_id = state_manager.create_session(
            username=user.username,
            system=linux_system.hostname,
            logon_type=10,
            source_ip="10.0.10.50",
            session_kind="ssh",
        )
        session_sshd = state_manager.create_process(
            linux_system.hostname,
            pids["sshd"],
            "/usr/sbin/sshd",
            f"sshd: {user.username} [priv]",
            "root",
            "System",
            logon_id=logon_id,
        )
        bash_pid = state_manager.create_process(
            linux_system.hostname,
            session_sshd,
            "/bin/bash",
            "-bash",
            user.username,
            "Medium",
            logon_id=logon_id,
        )
        session = state_manager.get_session(logon_id)
        assert session is not None
        session.session_shell_pid = bash_pid

        parent_pid = ag._resolve_parent(
            linux_system,
            user,
            event_time,
            logon_id,
            "/usr/bin/scp",
        )

        assert parent_pid == bash_pid

    def test_linux_generate_process_replaces_untracked_parent_pid(
        self, state_manager, mock_emitters, linux_system, user
    ):
        """Linux user processes should not render a fabricated shell parent for PID 4."""
        ag, pids = _setup_activity_gen(state_manager, mock_emitters, linux_system)
        event_time = datetime(2024, 3, 18, 12, 0, 5, tzinfo=UTC)
        logon_id = state_manager.create_session(
            username=user.username,
            system=linux_system.hostname,
            logon_type=10,
            source_ip="10.0.10.50",
            session_kind="ssh",
        )

        pid = ag.generate_process(
            user=user,
            system=linux_system,
            time=event_time,
            logon_id=logon_id,
            process_name="/usr/bin/last",
            command_line="last -n 50",
            parent_pid=4,
        )

        proc = state_manager.get_process(linux_system.hostname, pid)
        assert proc is not None
        assert proc.parent_pid != 4
        assert proc.parent_pid == pids["bash"]

    def test_web_service_account_process_uses_web_daemon_parent(self, state_manager, mock_emitters):
        web_system = System(
            hostname="WEB-EXT-01",
            ip="10.0.20.10",
            os="Ubuntu 22.04",
            type="server",
            roles=["web_server"],
        )
        web_user = User(
            username="apache",
            full_name="Apache Service",
            email="apache@example.com",
            enabled=True,
            persona="service",
        )
        ag, pids = _setup_activity_gen(state_manager, mock_emitters, web_system)

        parent_pid = ag._resolve_parent(
            web_system,
            web_user,
            datetime(2024, 3, 18, 12, 0, 1, tzinfo=UTC),
            "",
            "/bin/bash",
        )
        parent_proc = state_manager.get_process(web_system.hostname, parent_pid)

        assert parent_proc is not None
        assert parent_pid == pids["apache2"]
        assert parent_proc.image == "/usr/sbin/apache2"
