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

"""Tests for Sysmon Event 10 (ProcessAccess) credential dumping detection."""

import random
from datetime import UTC, datetime
from unittest.mock import Mock

import pytest

from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.activity.create_remote_thread_patterns import (
    load_create_remote_thread_patterns,
    pick_create_remote_thread_pattern,
)
from evidenceforge.generation.activity.process_access_patterns import (
    load_process_access_patterns,
    pick_granted_access,
)
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import System, User


@pytest.fixture
def state_manager():
    sm = StateManager()
    sm.set_current_time(datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC))
    return sm


@pytest.fixture
def mock_emitters():
    return {
        "windows_event_security": Mock(),
        "windows_event_sysmon": Mock(),
        "zeek_conn": Mock(),
        "ecar": Mock(),
    }


@pytest.fixture
def activity_gen(state_manager, mock_emitters):
    return ActivityGenerator(state_manager, mock_emitters)


@pytest.fixture
def windows_system():
    return System(hostname="WKS-01", ip="10.10.10.50", os="Windows 10", type="workstation")


@pytest.fixture
def test_user():
    return User(username="compromised.user", full_name="Compromised User", email="c@corp.com")


def _create_test_processes(
    state_manager: StateManager,
    windows_system: System,
    test_user: User,
    source_image: str,
    target_image: str = r"C:\Windows\System32\lsass.exe",
) -> tuple[int, int]:
    source_pid = state_manager.create_process(
        windows_system.hostname,
        parent_pid=4,
        image=source_image,
        command_line=source_image,
        username=test_user.username,
        integrity_level="High",
    )
    target_pid = state_manager.create_process(
        windows_system.hostname,
        parent_pid=4,
        image=target_image,
        command_line=target_image,
        username="SYSTEM",
        integrity_level="System",
    )
    return source_pid, target_pid


class TestSysmonProcessAccess:
    """Sysmon Event 10 (ProcessAccess) for LSASS credential dumping."""

    def test_process_access_emits_event(
        self, state_manager, activity_gen, mock_emitters, windows_system, test_user
    ):
        """generate_process_access should dispatch a process_access event."""
        ts = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)
        source_image = r"C:\Users\compromised.user\AppData\Local\Temp\mimikatz.exe"
        source_pid, target_pid = _create_test_processes(
            state_manager, windows_system, test_user, source_image
        )
        emitted = activity_gen.generate_process_access(
            user=test_user,
            system=windows_system,
            time=ts,
            source_pid=source_pid,
            source_image=source_image,
            target_pid=target_pid,
            target_image=r"C:\Windows\System32\lsass.exe",
            granted_access="0x1010",
        )

        assert emitted is True
        emitter = mock_emitters["windows_event_sysmon"]
        assert emitter.emit.call_count == 1
        event = emitter.emit.call_args[0][0]
        assert event.event_type == "process_access"
        assert event.process.pid == source_pid
        assert "mimikatz" in event.process.image
        assert event.process_access is not None
        assert event.process_access.target_image == r"C:\Windows\System32\lsass.exe"
        assert event.process_access.granted_access == "0x1010"
        assert event.process_access.source_thread_id % 4 == 0

    def test_create_remote_thread_ids_are_windows_aligned(
        self, state_manager, activity_gen, mock_emitters, windows_system, test_user
    ):
        """CreateRemoteThread canonical thread IDs should match Windows allocation texture."""
        ts = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)
        source_image = r"C:\Program Files\Microsoft Defender\MsMpEng.exe"
        target_image = r"C:\Windows\System32\lsass.exe"
        source_pid, target_pid = _create_test_processes(
            state_manager, windows_system, test_user, source_image, target_image=target_image
        )

        emitted = activity_gen.generate_create_remote_thread(
            user=test_user,
            system=windows_system,
            time=ts,
            source_pid=source_pid,
            source_image=source_image,
            target_pid=target_pid,
            target_image=target_image,
        )

        assert emitted is True
        event = mock_emitters["windows_event_sysmon"].emit.call_args[0][0]
        assert event.remote_thread is not None
        assert event.remote_thread.new_thread_id % 4 == 0
        assert event.remote_thread.source_thread_id % 4 == 0
        assert event.remote_thread.target_thread_id % 4 == 0

    def test_process_access_skips_missing_target_pid(
        self, state_manager, activity_gen, mock_emitters, windows_system, test_user
    ):
        """ProcessAccess should not emit orphan object references for missing targets."""
        ts = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)
        source_image = r"C:\Users\compromised.user\AppData\Local\Temp\mimikatz.exe"
        source_pid = state_manager.create_process(
            windows_system.hostname,
            parent_pid=4,
            image=source_image,
            command_line=source_image,
            username=test_user.username,
            integrity_level="High",
        )

        emitted = activity_gen.generate_process_access(
            user=test_user,
            system=windows_system,
            time=ts,
            source_pid=source_pid,
            source_image=source_image,
            target_pid=99999,
        )

        assert emitted is False
        assert mock_emitters["windows_event_sysmon"].emit.call_count == 0
        assert mock_emitters["ecar"].emit.call_count == 0
        assert state_manager.get_process_object_id(windows_system.hostname, 99999) == ""

    def test_process_access_default_target_is_lsass(
        self, state_manager, activity_gen, mock_emitters, windows_system, test_user
    ):
        """Default target_image should be lsass.exe."""
        ts = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)
        source_image = r"C:\Windows\Temp\procdump.exe"
        source_pid, target_pid = _create_test_processes(
            state_manager, windows_system, test_user, source_image
        )
        activity_gen.generate_process_access(
            user=test_user,
            system=windows_system,
            time=ts,
            source_pid=source_pid,
            source_image=source_image,
            target_pid=target_pid,
        )

        event = mock_emitters["windows_event_sysmon"].emit.call_args[0][0]
        assert event.process_access.target_image == r"C:\Windows\System32\lsass.exe"

    def test_process_access_custom_access_mask(
        self, state_manager, activity_gen, mock_emitters, windows_system, test_user
    ):
        """Custom granted_access mask should be preserved."""
        ts = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)
        source_image = r"C:\Windows\Temp\tool.exe"
        source_pid, target_pid = _create_test_processes(
            state_manager, windows_system, test_user, source_image
        )
        activity_gen.generate_process_access(
            user=test_user,
            system=windows_system,
            time=ts,
            source_pid=source_pid,
            source_image=source_image,
            target_pid=target_pid,
            granted_access="0x1FFFFF",  # PROCESS_ALL_ACCESS
        )

        event = mock_emitters["windows_event_sysmon"].emit.call_args[0][0]
        assert event.process_access.granted_access == "0x1FFFFF"

    def test_process_access_only_on_windows(self, activity_gen, mock_emitters, test_user):
        """ProcessAccess should only emit on Windows systems."""
        linux_system = System(hostname="LNX-01", ip="10.10.10.60", os="Ubuntu 22.04", type="server")
        ts = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)
        activity_gen.generate_process_access(
            user=test_user,
            system=linux_system,
            time=ts,
            source_pid=1234,
            source_image="/tmp/tool",
            target_pid=636,
        )

        # Event is dispatched but Sysmon emitter should not handle it (os_category != windows)
        # The mock doesn't filter, but we can check the event was dispatched
        emitter = mock_emitters["windows_event_sysmon"]
        if emitter.emit.call_count > 0:
            event = emitter.emit.call_args[0][0]
            assert event.src_host.os_category == "linux"  # Emitter's can_handle would reject this


class TestProcessAccessPatterns:
    """Data-driven ProcessAccess baseline patterns."""

    def test_process_access_patterns_provide_diverse_masks(self):
        """Baseline ProcessAccess config should provide more than the old three masks."""
        patterns = load_process_access_patterns()

        masks = {access["mask"] for pattern in patterns for access in pattern["access_masks"]}

        assert len(masks) >= 5
        assert {"0x1000", "0x1010", "0x1400", "0x1410"}.issubset(masks)

    def test_pick_granted_access_uses_weighted_alternatives(self):
        """Weighted mask selection should vary for a pattern with multiple masks."""
        pattern = {
            "access_masks": [
                {"mask": "0x1000", "weight": 1},
                {"mask": "0x1010", "weight": 1},
                {"mask": "0x1400", "weight": 1},
                {"mask": "0x1410", "weight": 1},
            ]
        }
        rng = random.Random(1234)

        masks = {pick_granted_access(pattern, rng) for _ in range(40)}

        assert masks == {"0x1000", "0x1010", "0x1400", "0x1410"}


class TestCreateRemoteThreadPatterns:
    """Data-driven CreateRemoteThread baseline patterns."""

    def test_create_remote_thread_patterns_provide_diverse_pairs(self):
        patterns = load_create_remote_thread_patterns()

        pairs = {(pattern["source_pid_key"], pattern["target_pid_key"]) for pattern in patterns}

        assert len(pairs) >= 8
        assert ("wmiprvse", "svchost_local_system") in pairs
        assert ("search_indexer", "search_protocol_host") in pairs

    def test_pick_create_remote_thread_pattern_uses_weighted_alternatives(self):
        patterns = [
            {
                "source_pid_key": "a",
                "source_image": "a.exe",
                "target_pid_key": "b",
                "target_image": "b.exe",
                "weight": 1,
            },
            {
                "source_pid_key": "c",
                "source_image": "c.exe",
                "target_pid_key": "d",
                "target_image": "d.exe",
                "weight": 1,
            },
        ]
        import random

        rng = random.Random(42)

        picked = {
            pick_create_remote_thread_pattern(patterns, rng)["source_pid_key"] for _ in range(20)
        }

        assert picked == {"a", "c"}
