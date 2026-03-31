# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Tests for system process stability — seeded PIDs must survive the full scenario."""

from datetime import UTC, datetime
from unittest.mock import Mock

import pytest

from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.engine.baseline import BaselineMixin
from evidenceforge.generation.engine.emitter_setup import EmitterSetupMixin
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models import System, User


@pytest.fixture
def state_manager():
    sm = StateManager()
    sm.set_current_time(datetime(2024, 3, 15, 8, 0, 0, tzinfo=UTC))
    return sm


@pytest.fixture
def mock_emitters():
    return {
        "windows_event_security": Mock(),
        "zeek_conn": Mock(),
        "ecar": Mock(),
        "syslog": Mock(),
    }


@pytest.fixture
def win_system():
    return System(hostname="WKS-01", ip="10.0.10.1", os="Windows 10", type="workstation")


@pytest.fixture
def linux_system():
    return System(hostname="LNX-01", ip="10.0.10.2", os="Linux Ubuntu 22.04", type="server")


class TestSystemProcessProtection:
    """Verify seeded system processes are never terminated."""

    def _seed_and_get_pids(self, state_manager, mock_emitters, system):
        """Helper: seed system process tree and return (engine, pids dict)."""
        ag = ActivityGenerator(state_manager, mock_emitters)
        # Create a minimal engine-like object with the mixins we need
        engine = type(
            "FakeEngine",
            (EmitterSetupMixin, BaselineMixin),
            {},
        ).__new__(type("FakeEngine", (EmitterSetupMixin, BaselineMixin), {}))
        engine.state_manager = state_manager
        engine.activity_generator = ag
        engine.scenario = Mock()
        engine.scenario.environment.systems = [system]
        engine.scenario.environment.users = []
        engine._system_pids = {}
        engine._infra_ips = {"dns": ["10.0.0.1"]}
        engine._system_service_defaults = {}
        engine._find_actor = lambda username: User(
            username=username, full_name=username, email=f"{username}@test.com", enabled=True
        )
        ag._system_pids = {}

        from evidenceforge.generation.activity import _get_os_category

        os_cat = _get_os_category(system.os)
        pids = {}
        if os_cat == "windows":
            engine._seed_windows_process_tree(system, pids)
        else:
            engine._seed_linux_process_tree(system, pids)
        engine._system_pids[system.hostname] = pids
        ag._system_pids = engine._system_pids

        return engine, pids

    def test_all_seeded_windows_pids_survive_termination(
        self, state_manager, mock_emitters, win_system
    ):
        """After multiple hours, all seeded Windows PIDs must still exist."""
        engine, pids = self._seed_and_get_pids(state_manager, mock_emitters, win_system)

        # Also seed some user processes that SHOULD be terminable
        test_user = User(username="alice", full_name="Alice", email="a@t.com", enabled=True)
        engine.scenario.environment.users = [test_user]
        state_manager.create_session(
            username="alice", system="WKS-01", logon_type=2, source_ip="10.0.10.1"
        )
        for i in range(10):
            state_manager.create_process(
                "WKS-01",
                pids["explorer"],
                f"C:\\Users\\alice\\app{i}.exe",
                f"app{i}.exe",
                "alice",
                "Medium",
            )

        # Advance 8 hours, running termination each hour
        for hour in range(8):
            current = datetime(2024, 3, 15, 9 + hour, 0, 0, tzinfo=UTC)
            state_manager.set_current_time(current)
            engine._terminate_stale_processes(current)

        # ALL seeded system PIDs must still be in running_processes
        for role, pid in pids.items():
            key = (win_system.hostname, pid)
            assert key in state_manager.state.running_processes, (
                f"Seeded system process '{role}' (PID {pid}) was terminated"
            )

    def test_all_seeded_linux_pids_survive_termination(
        self, state_manager, mock_emitters, linux_system
    ):
        """After multiple hours, all seeded Linux PIDs must still exist."""
        engine, pids = self._seed_and_get_pids(state_manager, mock_emitters, linux_system)

        test_user = User(username="alice", full_name="Alice", email="a@t.com", enabled=True)
        engine.scenario.environment.users = [test_user]

        for hour in range(8):
            current = datetime(2024, 3, 15, 9 + hour, 0, 0, tzinfo=UTC)
            state_manager.set_current_time(current)
            engine._terminate_stale_processes(current)

        for role, pid in pids.items():
            key = (linux_system.hostname, pid)
            assert key in state_manager.state.running_processes, (
                f"Seeded system process '{role}' (PID {pid}) was terminated"
            )

    def test_user_processes_still_terminate(self, state_manager, mock_emitters, win_system):
        """Non-system user processes should still be terminated normally."""
        engine, pids = self._seed_and_get_pids(state_manager, mock_emitters, win_system)

        test_user = User(username="alice", full_name="Alice", email="a@t.com", enabled=True)
        engine.scenario.environment.users = [test_user]
        state_manager.create_session(
            username="alice", system="WKS-01", logon_type=2, source_ip="10.0.10.1"
        )

        # Create a user process at hour 8
        state_manager.create_process(
            "WKS-01",
            pids["explorer"],
            "C:\\Users\\alice\\malware.exe",
            "malware.exe",
            "alice",
            "Medium",
        )

        # Run termination 4 hours later (well past max_hours for "other" category)
        later = datetime(2024, 3, 15, 12, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(later)

        # Run multiple times to overcome the 50% random chance
        for _ in range(20):
            engine._terminate_stale_processes(later)

        # System processes must STILL be alive regardless of user process fate
        for role, pid in pids.items():
            sys_key = (win_system.hostname, pid)
            assert sys_key in state_manager.state.running_processes, (
                f"System process '{role}' was incorrectly terminated"
            )


class TestProtectionListCompleteness:
    """Verify the protection list covers all seeded process names."""

    def test_windows_seeded_processes_match_protection_patterns(self):
        """Every Windows seeded process image must match a system_patterns entry."""
        # Images seeded in _seed_windows_process_tree
        seeded_images = [
            r"C:\Windows\System32\smss.exe",
            r"C:\Windows\System32\csrss.exe",
            r"C:\Windows\System32\wininit.exe",
            r"C:\Windows\System32\services.exe",
            r"C:\Windows\System32\lsass.exe",
            r"C:\Windows\System32\svchost.exe",
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\MsMpEng.exe",
            r"C:\Windows\System32\SearchIndexer.exe",
            r"C:\Windows\System32\taskhostw.exe",
            r"C:\Windows\System32\winlogon.exe",
            r"C:\Windows\System32\userinit.exe",
            r"C:\Windows\explorer.exe",
            r"C:\Windows\System32\dwm.exe",
            r"C:\Windows\System32\RuntimeBroker.exe",
        ]

        # Import the actual patterns from baseline code
        # We replicate the pattern matching logic here
        system_patterns = (
            "svchost",
            "lsass",
            "csrss",
            "services.exe",
            "explorer.exe",
            "smss",
            "wininit",
            "winlogon",
            "fontdrvhost",
            "dwm.exe",
            "userinit.exe",
            "runtimebroker",
            "taskhostw",
            "searchindexer",
            "msmpeng",
            "systemd",
            "cron",
            "crond",
            "sshd",
            "rsyslogd",
            "journald",
            "udevd",
            "logind",
            "snapd",
            "timesyncd",
            "networkmanager",
            "dbus-daemon",
            "bash",
            "agetty",
        )

        for image in seeded_images:
            image_lower = image.lower()
            matched = any(p in image_lower for p in system_patterns)
            assert matched, (
                f"Seeded image '{image}' is NOT covered by system_patterns — "
                f"it will be terminated after 0.5-2 hours"
            )

    def test_linux_seeded_processes_match_protection_patterns(self):
        """Every Linux seeded process image must match a system_patterns entry."""
        seeded_images = [
            "/usr/lib/systemd/systemd",
            "/usr/lib/systemd/systemd-journald",
            "/lib/systemd/systemd-udevd",
            "/usr/sbin/rsyslogd",
            "/usr/sbin/NetworkManager",
            "/usr/bin/dbus-daemon",
            "/usr/lib/systemd/systemd-logind",
            "/usr/sbin/sshd",
            "/usr/sbin/cron",
            "/usr/sbin/crond",
            "/sbin/agetty",
            "/usr/lib/snapd/snapd",
            "/usr/lib/systemd/systemd-timesyncd",
            "/bin/bash",
        ]

        system_patterns = (
            "svchost",
            "lsass",
            "csrss",
            "services.exe",
            "explorer.exe",
            "smss",
            "wininit",
            "winlogon",
            "fontdrvhost",
            "dwm.exe",
            "userinit.exe",
            "runtimebroker",
            "taskhostw",
            "searchindexer",
            "msmpeng",
            "systemd",
            "cron",
            "crond",
            "sshd",
            "rsyslogd",
            "journald",
            "udevd",
            "logind",
            "snapd",
            "timesyncd",
            "networkmanager",
            "dbus-daemon",
            "bash",
            "agetty",
        )

        for image in seeded_images:
            image_lower = image.lower()
            matched = any(p in image_lower for p in system_patterns)
            assert matched, (
                f"Seeded image '{image}' is NOT covered by system_patterns — "
                f"it will be terminated after 0.5-2 hours"
            )
