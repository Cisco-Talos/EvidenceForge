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

"""Unit tests for StateManager."""

from datetime import UTC, datetime, timedelta
from itertools import pairwise

import pytest

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import HostContext, ProcessContext
from evidenceforge.generation import state_manager as state_manager_module
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError


class TestStateManagerInit:
    """Tests for StateManager initialization."""

    def test_init_creates_empty_state(self):
        """Test that new StateManager has empty state."""
        sm = StateManager()
        assert len(sm.state.active_sessions) == 0
        assert len(sm.state.running_processes) == 0
        assert len(sm.state.open_connections) == 0
        assert len(sm.state.dns_cache) == 0
        assert sm.state.current_time is None

    def test_init_sets_counters(self):
        """Test that counters are initialized correctly."""
        sm = StateManager()
        assert sm._connection_id_counter == 0
        assert len(sm._pid_counters) == 0
        assert len(sm._used_logon_ids) == 0

    def test_linux_logind_session_ids_follow_event_time(self):
        """Logind session IDs should sort with event time, not generation order."""
        import random

        sm = StateManager()
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        sm.register_boot_time("linux01", start)
        rng = random.Random(7)

        later_id = sm.next_linux_logind_session_id(
            "linux01",
            rng,
            start + timedelta(minutes=10),
        )
        earlier_id = sm.next_linux_logind_session_id(
            "linux01",
            rng,
            start + timedelta(minutes=1),
        )

        assert earlier_id < later_id
        assert later_id - earlier_id < 600

    def test_linux_logind_session_ids_do_not_encode_elapsed_seconds(self):
        """Logind session IDs should look like allocator counters, not uptime seconds."""
        import random

        sm = StateManager()
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        sm.register_boot_time("linux01", start)
        rng = random.Random(13)

        first = sm.next_linux_logind_session_id(
            "linux01",
            rng,
            start + timedelta(minutes=4, seconds=58),
        )
        second = sm.next_linux_logind_session_id(
            "linux01",
            rng,
            start + timedelta(minutes=21, seconds=23),
        )

        assert second > first
        assert second - first != 985
        assert second - first < 80

    def test_sessions_for_user_at_stops_at_transport_close(self):
        """Transport-backed sessions should not own activity after their close time."""
        sm = StateManager()
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        close = start + timedelta(minutes=8)
        logon_id = sm.create_session(
            username="alice",
            system="linux01",
            logon_type=10,
            source_ip="10.0.1.50",
            start_time=start,
            session_kind="ssh",
        )
        sm.update_session_metadata(logon_id, network_close_time=close)

        assert [
            s.logon_id for s in sm.get_sessions_for_user_at("alice", close - timedelta(seconds=1))
        ] == [logon_id]
        assert sm.get_sessions_for_user_at("alice", close) == []
        assert sm.get_sessions_for_user_at("alice", close + timedelta(minutes=1)) == []

    def test_linux_logind_session_collision_ids_avoid_elapsed_second_deltas(self):
        """Collision bumps should not recreate an exact session-time delta."""
        import random

        sm = StateManager()
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        sm.register_boot_time("linux01", start)
        rng = random.Random(23)
        event_times = [
            start + timedelta(minutes=37, seconds=offset)
            for offset in (0, 2, 5, 7, 12, 18, 24, 31, 43, 56)
        ]

        ids = [
            sm.next_linux_logind_session_id("linux01", rng, event_time)
            for event_time in event_times
        ]

        assert len(set(ids)) == len(ids)
        allocations = list(zip(event_times, ids, strict=True))
        for (prev_time, prev_id), (next_time, next_id) in pairwise(allocations):
            elapsed_seconds = int((next_time - prev_time).total_seconds())
            assert abs(next_id - prev_id) != elapsed_seconds

    def test_linux_logind_session_ids_use_syslog_visible_seconds(self):
        """Subsecond allocation timestamps should not leak whole-second deltas."""
        import random

        sm = StateManager()
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        sm.register_boot_time("linux01", start)
        rng = random.Random(29)

        first_time = start + timedelta(minutes=37, seconds=39, milliseconds=950)
        second_time = start + timedelta(minutes=37, seconds=51, milliseconds=50)
        first = sm.next_linux_logind_session_id("linux01", rng, first_time)
        second = sm.next_linux_logind_session_id("linux01", rng, second_time)

        visible_elapsed = int(
            (second_time.replace(microsecond=0) - first_time.replace(microsecond=0)).total_seconds()
        )
        assert abs(second - first) != visible_elapsed

    def test_linux_logind_session_ids_preboot_events_remain_monotonic(self):
        """Pre-boot events should still allocate monotonic IDs without collisions."""
        import random

        sm = StateManager()
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        sm.register_boot_time("linux01", start)
        rng = random.Random(17)

        ids = [
            sm.next_linux_logind_session_id("linux01", rng, start - timedelta(hours=2))
            for _ in range(10)
        ]

        assert ids == sorted(ids)
        assert len(set(ids)) == len(ids)

    def test_linux_logind_session_far_future_time_does_not_materialize_blocks(self):
        """Far-future logind IDs should not cache every elapsed four-hour block."""
        import random

        sm = StateManager()
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        sm.register_boot_time("linux01", start)
        rng = random.Random(31)

        session_id = sm.next_linux_logind_session_id(
            "linux01",
            rng,
            start + timedelta(days=1_000_000),
        )

        assert session_id > 0
        assert sm._linux_logind_session_block_offsets == {}

    def test_linux_pid_far_future_block_offset_does_not_materialize_blocks(self):
        """Far-future Linux PID offsets should be direct arithmetic, not catch-up caches."""
        sm = StateManager()

        offset = sm._linux_pid_block_offset("linux01", 1_000_000_000)

        assert offset > 0
        assert sm._linux_pid_block_offsets == {}

    def test_linux_visible_pids_stay_in_lived_in_desktop_range_after_days(self):
        """Long collection windows should not create obvious million-range PID bands."""
        sm = StateManager()
        boot_time = datetime(2024, 1, 15, 8, 0, 0, tzinfo=UTC)
        sm.register_boot_time("linux01", boot_time)
        sm.set_current_time(boot_time + timedelta(days=3, hours=2))

        pid = sm.create_process(
            system="linux01",
            parent_pid=0,
            image="/usr/bin/mysql",
            command_line="mysql -u root",
            username="root",
            integrity_level="Medium",
        )

        assert 8_000 <= pid < 180_000

    def test_linux_pids_increase_across_time_bucket_boundary(self):
        """Linux PIDs should not sawtooth downward at five-minute boundaries."""
        sm = StateManager()
        boot_time = datetime(2024, 1, 15, 8, 0, 0, tzinfo=UTC)
        sm.register_boot_time("linux01", boot_time)

        sm.set_current_time(boot_time + timedelta(minutes=4, seconds=59))
        first_pid = sm.create_process(
            system="linux01",
            parent_pid=0,
            image="/usr/bin/python3",
            command_line="python3 first.py",
            username="alice",
            integrity_level="Medium",
        )
        sm.set_current_time(boot_time + timedelta(minutes=5, seconds=1))
        second_pid = sm.create_process(
            system="linux01",
            parent_pid=0,
            image="/usr/bin/python3",
            command_line="python3 second.py",
            username="alice",
            integrity_level="Medium",
        )

        assert second_pid > first_pid

    def test_linux_pids_keep_chronological_shape_when_allocated_out_of_order(self):
        """Out-of-order generation should not make earlier Linux PIDs look newer."""
        sm = StateManager()
        boot_time = datetime(2024, 1, 15, 8, 0, 0, tzinfo=UTC)
        sm.register_boot_time("linux01", boot_time)

        sm.set_current_time(boot_time + timedelta(minutes=5, seconds=1))
        later_pid = sm.create_process(
            system="linux01",
            parent_pid=0,
            image="/usr/bin/python3",
            command_line="python3 later.py",
            username="alice",
            integrity_level="Medium",
        )
        sm.set_current_time(boot_time + timedelta(minutes=4, seconds=59))
        earlier_pid = sm.create_process(
            system="linux01",
            parent_pid=0,
            image="/usr/bin/python3",
            command_line="python3 earlier.py",
            username="alice",
            integrity_level="Medium",
        )

        assert earlier_pid < later_pid

    def test_linux_pids_keep_parent_child_shape_before_future_process(self):
        """Earlier parent/child allocations should fit below known future PIDs."""
        sm = StateManager()
        boot_time = datetime(2024, 1, 15, 8, 0, 0, tzinfo=UTC)
        sm.register_boot_time("linux01", boot_time)

        sm.set_current_time(boot_time + timedelta(minutes=5, seconds=1))
        later_pid = sm.create_process(
            system="linux01",
            parent_pid=0,
            image="/usr/bin/journalctl",
            command_line="journalctl -p warning",
            username="alice",
            integrity_level="Medium",
        )
        sm.set_current_time(boot_time + timedelta(seconds=35))
        parent_pid = sm.create_process(
            system="linux01",
            parent_pid=0,
            image="/bin/sh",
            command_line="/bin/sh -c debian-sa1",
            username="sysstat",
            integrity_level="Medium",
        )
        sm.set_current_time(boot_time + timedelta(seconds=38))
        child_pid = sm.create_process(
            system="linux01",
            parent_pid=parent_pid,
            image="/usr/lib/sysstat/debian-sa1",
            command_line="debian-sa1 1 1",
            username="sysstat",
            integrity_level="Medium",
        )

        assert parent_pid < child_pid < later_pid

    def test_linux_transient_syslog_pids_share_process_namespace(self):
        """Syslog-only transient PIDs should not come from a separate low random pool."""
        sm = StateManager()
        boot_time = datetime(2024, 1, 15, 8, 0, 0, tzinfo=UTC)
        event_time = boot_time + timedelta(days=9, hours=4)
        sm.register_boot_time("linux01", boot_time)

        sudo_pid = sm.allocate_transient_linux_pid("linux01", event_time)
        sm.set_current_time(event_time + timedelta(seconds=2))
        ecar_pid = sm.create_process(
            system="linux01",
            parent_pid=0,
            image="/usr/bin/journalctl",
            command_line="journalctl -u sshd --since today",
            username="root",
            integrity_level="Medium",
        )
        sshd_pid = sm.allocate_transient_linux_pid(
            "linux01",
            event_time + timedelta(seconds=5),
        )

        assert sudo_pid > 180_000
        assert ecar_pid > 180_000
        assert sshd_pid > 180_000
        assert len({sudo_pid, ecar_pid, sshd_pid}) == 3
        assert max(sudo_pid, ecar_pid, sshd_pid) - min(sudo_pid, ecar_pid, sshd_pid) < 15_000

    def test_linux_transient_pid_rejects_non_linux_hosts_before_allocator_init(self):
        """Transient Linux PIDs should not initialize a Windows host namespace."""
        sm = StateManager()
        event_time = datetime(2024, 1, 15, 8, 0, 0, tzinfo=UTC)

        with pytest.raises(StateError, match="non-Linux host"):
            sm.allocate_transient_linux_pid("win01", event_time, os_category="windows")

        assert "win01" not in sm._pid_os

    def test_linux_transient_pid_rejects_existing_windows_namespace(self):
        """Transient Linux PID calls should not poison an established Windows allocator."""
        sm = StateManager()
        event_time = datetime(2024, 1, 15, 8, 0, 0, tzinfo=UTC)
        sm.set_current_time(event_time)
        win_pid = sm.create_process(
            system="win01",
            parent_pid=0,
            image=r"C:\Windows\System32\svchost.exe",
            command_line="svchost.exe",
            username="SYSTEM",
            integrity_level="System",
        )

        with pytest.raises(StateError, match="non-Linux host"):
            sm.allocate_transient_linux_pid("win01", event_time, os_category="windows")

        with pytest.raises(StateError, match="PID namespace"):
            sm.allocate_transient_linux_pid("win01", event_time)

        next_pid = sm.create_process(
            system="win01",
            parent_pid=0,
            image=r"C:\Windows\System32\cmd.exe",
            command_line="cmd.exe",
            username="SYSTEM",
            integrity_level="System",
        )

        assert win_pid % 4 == 0
        assert next_pid % 4 == 0
        assert sm._pid_os["win01"] == "windows"


class TestSessionManagement:
    """Tests for session lifecycle."""

    def test_create_session(self):
        """Test creating a new session."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        logon_id = sm.create_session(
            username="jdoe",
            system="WS-01",
            logon_type=2,
            source_ip="192.168.1.50",
        )

        assert logon_id.startswith("0x")
        assert 0x10000 <= int(logon_id, 16) <= 0xFFFFFFFF
        session = sm.get_session(logon_id)
        assert session is not None
        assert session.username == "jdoe"
        assert session.system == "WS-01"
        assert session.logon_type == 2
        assert session.source_ip == "192.168.1.50"
        assert session.session_id > 0
        assert sm.get_session_id(logon_id) == session.session_id

    def test_windows_session_ids_are_canonical_and_collision_safe(self):
        """Overlapping Windows interactive sessions should not hash-collide by LogonID."""
        sm = StateManager()
        base = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        sm.set_current_time(base)

        console = sm.create_session(
            "aisha.johnson",
            "WS-AJOHNSON-01",
            2,
            "-",
            session_kind="interactive",
        )
        rdp = sm.create_session(
            "aisha.johnson",
            "WS-AJOHNSON-01",
            10,
            "10.10.1.10",
            session_kind="rdp",
            start_time=base + timedelta(minutes=5),
        )
        network = sm.create_session(
            "aisha.johnson",
            "WS-AJOHNSON-01",
            3,
            "10.10.1.20",
            session_kind="network",
            start_time=base + timedelta(minutes=6),
        )

        console_session_id = sm.get_session_id(console)
        rdp_session_id = sm.get_session_id(rdp)

        assert console_session_id > 0
        assert rdp_session_id > 0
        assert console_session_id != rdp_session_id
        assert sm.get_session_id(network) == 0

    def test_ssh_sessions_do_not_get_windows_session_ids(self):
        """Linux SSH-style sessions should not consume Windows terminal IDs."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        ssh = sm.create_session(
            "marcus.chen",
            "DB-PROD-01",
            10,
            "10.10.1.10",
            session_kind="ssh",
        )

        assert sm.get_session_id(ssh) == 0

    def test_create_session_uses_host_local_monotonic_luids(self):
        """New LogonIDs on one host should follow source-native LUID ordering."""
        sm = StateManager()
        boot = datetime(2024, 1, 15, 9, 0, 0, tzinfo=UTC)
        sm.register_boot_time("WS-01", boot)

        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))
        id1 = sm.create_session("user1", "WS-01", 2, "192.168.1.1")
        sm.set_current_time(datetime(2024, 1, 15, 10, 5, 0, tzinfo=UTC))
        id2 = sm.create_session("user2", "WS-01", 3, "192.168.1.2")
        sm.set_current_time(datetime(2024, 1, 15, 10, 5, 0, tzinfo=UTC))
        id3 = sm.create_session("user3", "WS-01", 3, "192.168.1.3")

        assert int(id1, 16) < int(id2, 16) < int(id3, 16)

    def test_create_session_luids_do_not_encode_elapsed_seconds(self):
        """LUID gaps should not expose a fixed wall-clock stride."""
        sm = StateManager()
        boot = datetime(2024, 1, 15, 9, 0, 0, tzinfo=UTC)
        sm.register_boot_time("WS-01", boot)

        first = sm.create_session(
            "user1",
            "WS-01",
            2,
            "192.168.1.1",
            start_time=datetime(2024, 1, 15, 12, 3, 37, 27_000, tzinfo=UTC),
        )
        second = sm.create_session(
            "user2",
            "WS-01",
            3,
            "192.168.1.2",
            start_time=datetime(2024, 1, 15, 12, 9, 6, 698_000, tzinfo=UTC),
        )

        diff = int(second, 16) - int(first, 16)
        assert diff > 0
        assert diff != 329 * 4096
        assert diff < 329 * 512

    def test_create_session_varies_low_luid_nibble(self):
        """Generated LogonIDs should not all expose a fixed trailing hex digit."""
        sm = StateManager()
        boot = datetime(2024, 1, 15, 9, 0, 0, tzinfo=UTC)
        sm.register_boot_time("WS-01", boot)
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        ids = [sm.create_session(f"user{i}", "WS-01", 3, f"192.168.1.{i}") for i in range(12)]

        assert all(0x10000 <= int(logon_id, 16) <= 0xFFFFFFFF for logon_id in ids)
        assert len({int(logon_id, 16) & 0xF for logon_id in ids}) > 1
        assert ids == [f"0x{value:x}" for value in sorted(int(logon_id, 16) for logon_id in ids)]

    def test_session_logon_guid_is_stable_per_logon_id(self):
        """Session LogonGuid should be canonical state, not per-emitter derivation."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))
        logon_id = sm.create_session("jdoe", "WS-01", 3, "192.168.1.50")

        guid_a = sm.get_or_create_session_logon_guid(logon_id, "WS-01")
        guid_b = sm.get_or_create_session_logon_guid(logon_id, "WS-01")
        session = sm.get_session(logon_id)

        assert guid_a == guid_b
        assert session is not None
        assert session.logon_guid == guid_a
        assert guid_a != "{00000000-0000-0000-0000-000000000000}"

    def test_generated_logon_guids_use_uuid4_morphology(self):
        """Deterministic LogonGuid values should use normal RFC variant/version nibbles."""
        sm = StateManager()

        guids = [
            sm.get_or_create_session_logon_guid(f"0x{value:x}", "WS-01") for value in range(32)
        ]
        version_nibbles = {guid[15] for guid in guids}
        variant_nibbles = {guid[20] for guid in guids}

        assert all(guid.startswith("{") and guid.endswith("}") for guid in guids)
        assert version_nibbles == {"4"}
        assert variant_nibbles <= {"8", "9", "a", "b"}
        assert len(variant_nibbles) > 1

    def test_create_session_uses_explicit_start_time_for_luid(self):
        """Explicit session start time should drive LogonID order despite stale state time."""
        sm = StateManager()
        boot = datetime(2024, 1, 15, 9, 0, 0, tzinfo=UTC)
        sm.register_boot_time("WS-01", boot)
        sm.set_current_time(datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC))

        later = sm.create_session(
            "svc-late",
            "WS-01",
            5,
            "-",
            start_time=datetime(2024, 1, 15, 10, 20, 0, tzinfo=UTC),
        )
        earlier = sm.create_session(
            "svc-early",
            "WS-01",
            5,
            "-",
            start_time=datetime(2024, 1, 15, 10, 5, 0, tzinfo=UTC),
        )

        assert int(earlier, 16) < int(later, 16)
        assert sm.get_session(earlier).start_time == datetime(2024, 1, 15, 10, 5, 0, tzinfo=UTC)
        assert sm.get_session(later).start_time == datetime(2024, 1, 15, 10, 20, 0, tzinfo=UTC)

    def test_allocate_logon_id_uses_event_time_without_session(self):
        """Standalone 4624 records should use the same boot-relative LUID model."""
        sm = StateManager()
        boot = datetime(2024, 1, 15, 9, 0, 0, tzinfo=UTC)
        sm.register_boot_time("DC-01", boot)
        sm.set_current_time(datetime(2024, 1, 15, 12, 0, 0, tzinfo=UTC))

        later = sm.allocate_logon_id("DC-01", datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC))
        earlier = sm.allocate_logon_id("DC-01", datetime(2024, 1, 15, 10, 1, 0, tzinfo=UTC))

        assert int(earlier, 16) < int(later, 16)
        assert all(0x10000 <= int(logon_id, 16) <= 0xFFFFFFFF for logon_id in (earlier, later))
        assert sm.get_session(earlier) is None
        assert sm.get_session(later) is None

    def test_allocate_logon_id_preserves_subsecond_event_time_order(self):
        """Out-of-order same-second allocation should still sort by event timestamp."""
        sm = StateManager()
        boot = datetime(2024, 1, 15, 9, 0, 0, tzinfo=UTC)
        sm.register_boot_time("DC-01", boot)

        later = sm.allocate_logon_id("DC-01", datetime(2024, 1, 15, 10, 1, 0, 700000, UTC))
        earlier = sm.allocate_logon_id(
            "DC-01",
            datetime(2024, 1, 15, 10, 1, 0, 100000, UTC),
        )

        assert int(earlier, 16) < int(later, 16)

    def test_allocate_logon_id_far_future_time_does_not_materialize_blocks(self):
        """Far-future Windows LogonIDs should not cache every elapsed minute block."""
        sm = StateManager()
        boot = datetime(2024, 1, 15, 9, 0, 0, tzinfo=UTC)
        sm.register_boot_time("DC-01", boot)

        logon_id = sm.allocate_logon_id("DC-01", boot + timedelta(days=1_000_000))

        assert 0x10000 <= int(logon_id, 16) <= 0xFFFFFFFF
        assert sm._logon_id_block_offsets == {}

    def test_reassign_session_logon_id_rekeys_session_to_event_time(self):
        """Planned sessions can be re-keyed once final source-native logon time is known."""
        sm = StateManager()
        boot = datetime(2024, 1, 15, 9, 0, 0, tzinfo=UTC)
        sm.register_boot_time("DC-01", boot)
        sm.set_current_time(datetime(2024, 1, 15, 15, 39, 4, tzinfo=UTC))
        original = sm.create_session("aisha.johnson", "DC-01", 10, "10.10.1.35")

        intervening = sm.allocate_logon_id(
            "DC-01",
            datetime(2024, 1, 15, 15, 39, 5, 397056, UTC),
        )
        reassigned = sm.reassign_session_logon_id(
            original,
            datetime(2024, 1, 15, 15, 39, 9, 751464, UTC),
        )

        assert reassigned is not None
        assert sm.state.active_sessions.get(original) is None
        session = sm.get_session(reassigned)
        assert session is not None
        assert sm.get_session(original) is session
        assert session.start_time == datetime(2024, 1, 15, 15, 39, 9, 751464, UTC)
        assert int(reassigned, 16) > int(intervening, 16)
        assert sm.get_session_id(original) == session.session_id
        assert sm.get_session_id(reassigned) == session.session_id

    def test_create_session_keeps_host_ranges_unique(self):
        """Host-local LUID sequences should not collide in global state."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        ids = [sm.create_session(f"user{i}", f"WS-{i:02d}", 3, f"192.168.1.{i}") for i in range(20)]

        assert len(set(ids)) == len(ids)

    def test_create_session_supports_more_than_legacy_host_bucket_count(self):
        """Large scenarios should not exhaust Windows LogonID host ranges."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        ids = [
            sm.create_session(f"user{i}", f"WS-{i:03d}", 3, f"192.168.{i // 255}.{i % 255}")
            for i in range(300)
        ]

        assert len(ids) == 300
        assert len(set(ids)) == len(ids)
        assert len(sm._logon_id_host_bases) == 300
        assert all(0x10000 <= int(logon_id, 16) <= 0xFFFFFFFF for logon_id in ids)

    def test_create_session_probes_unbounded_host_bucket_collision_layers(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        """Host bucket collisions should probe alternate offsets without failing."""
        monkeypatch.setattr(state_manager_module, "_stable_seed", lambda _key: 7)
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        ids = [sm.create_session(f"user{i}", f"WS-{i:03d}", 3, f"192.168.1.{i}") for i in range(3)]

        assert len(set(ids)) == 3
        assert len(set(sm._logon_id_host_bases.values())) == 3
        assert all(0x10000 <= int(logon_id, 16) <= 0xFFFFFFFF for logon_id in ids)

    def test_register_session_marks_external_logon_id_used(self):
        """Externally registered sessions should reserve their LogonID value."""
        sm = StateManager()
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

        sm.register_session(
            logon_id="0x123456",
            username="external",
            system="WS-01",
            logon_type=3,
            source_ip="192.168.1.10",
            start_time=start,
        )

        assert int("0x123456", 16) in sm._used_logon_ids

    def test_create_session_requires_current_time(self):
        """Test that creating session fails if current_time not set."""
        sm = StateManager()

        with pytest.raises(StateError, match="current_time not set"):
            sm.create_session("jdoe", "WS-01", 2, "192.168.1.1")

    def test_get_sessions_for_user(self):
        """Test getting all sessions for a user."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        sm.create_session("jdoe", "WS-01", 2, "192.168.1.1")
        sm.create_session("jdoe", "WS-02", 3, "192.168.1.1")
        sm.create_session("asmith", "WS-03", 2, "192.168.1.2")

        jdoe_sessions = sm.get_sessions_for_user("jdoe")
        assert len(jdoe_sessions) == 2
        assert all(s.username == "jdoe" for s in jdoe_sessions)

    def test_get_sessions_on_system(self):
        """Test getting all sessions on a system."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        sm.create_session("jdoe", "WS-01", 2, "192.168.1.1")
        sm.create_session("asmith", "WS-01", 3, "192.168.1.2")
        sm.create_session("bsmith", "WS-02", 2, "192.168.1.3")

        ws01_sessions = sm.get_sessions_on_system("WS-01")
        assert len(ws01_sessions) == 2
        assert all(s.system == "WS-01" for s in ws01_sessions)

    def test_end_session(self):
        """Test ending a session."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        logon_id = sm.create_session("jdoe", "WS-01", 2, "192.168.1.1")
        assert sm.get_session(logon_id) is not None

        result = sm.end_session(logon_id)
        assert result is True
        assert sm.get_session(logon_id) is None

    def test_end_nonexistent_session(self):
        """Test ending a non-existent session returns False."""
        sm = StateManager()
        result = sm.end_session("0xnonexistent")
        assert result is False

    def test_list_active_sessions(self):
        """Test listing all active sessions."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        sm.create_session("user1", "WS-01", 2, "192.168.1.1")
        sm.create_session("user2", "WS-02", 3, "192.168.1.2")

        sessions = sm.list_active_sessions()
        assert len(sessions) == 2


class TestProcessManagement:
    """Tests for process lifecycle."""

    def test_create_process(self):
        """Test creating a new process."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        pid = sm.create_process(
            system="WS-01",
            parent_pid=0,
            image="C:\\Windows\\System32\\explorer.exe",
            command_line="explorer.exe",
            username="jdoe",
            integrity_level="Medium",
        )

        # Phase 6.0: PIDs are now OS-aware (multiples of 4 for Windows, starting in realistic range)
        assert pid >= 2000  # Windows PIDs start in realistic range
        assert pid % 4 == 0  # Windows PIDs are multiples of 4
        process = sm.get_process("WS-01", pid)
        assert process is not None
        assert process.system == "WS-01"
        assert process.image == "C:\\Windows\\System32\\explorer.exe"
        assert process.username == "jdoe"

    def test_create_process_increments_per_system(self):
        """Test that PIDs increment per system with OS-aware allocation."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        # Windows path → multiples of 4
        pid1 = sm.create_process(
            "WS-01", 0, r"C:\Windows\explorer.exe", "explorer.exe", "jdoe", "Medium"
        )
        pid2 = sm.create_process("WS-01", 0, r"C:\Windows\cmd.exe", "cmd.exe", "jdoe", "Medium")
        # Linux path → sequential
        pid3 = sm.create_process("WS-02", 0, "/usr/bin/bash", "bash", "asmith", "Medium")

        assert pid1 % 4 == 0  # Windows: multiple of 4
        assert pid2 % 4 == 0  # Windows: multiple of 4
        assert pid2 > pid1  # Incrementing
        assert pid3 >= 500  # Linux: starts in realistic range

    def test_create_process_requires_current_time(self):
        """Test that creating process fails if current_time not set."""
        sm = StateManager()

        with pytest.raises(StateError, match="current_time not set"):
            sm.create_process("WS-01", 0, "explorer.exe", "explorer.exe", "jdoe", "Medium")

    def test_create_process_validates_parent_exists(self):
        """Test that creating process fails if parent doesn't exist."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        with pytest.raises(StateError, match="parent PID .* does not exist"):
            sm.create_process("WS-01", 999, "cmd.exe", "cmd.exe", "jdoe", "Medium")

    def test_create_process_allows_parent_zero(self):
        """Test that parent_pid=0 is allowed (system processes)."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        pid = sm.create_process("WS-01", 0, "System", "System", "SYSTEM", "System")
        assert pid > 0  # PID allocated successfully

    def test_create_process_with_valid_parent(self):
        """Test creating child process with valid parent."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        parent_pid = sm.create_process("WS-01", 0, "explorer.exe", "explorer.exe", "jdoe", "Medium")
        child_pid = sm.create_process("WS-01", parent_pid, "cmd.exe", "cmd.exe", "jdoe", "Medium")

        assert child_pid > parent_pid
        child = sm.get_process("WS-01", child_pid)
        assert child.parent_pid == parent_pid

    def test_get_processes_for_user(self):
        """Test getting all processes for a user."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        sm.create_process("WS-01", 0, "explorer.exe", "explorer.exe", "jdoe", "Medium")
        sm.create_process("WS-01", 0, "cmd.exe", "cmd.exe", "jdoe", "Medium")
        sm.create_process("WS-01", 0, "notepad.exe", "notepad.exe", "asmith", "Medium")

        jdoe_procs = sm.get_processes_for_user("jdoe")
        assert len(jdoe_procs) == 2
        assert all(p.username == "jdoe" for p in jdoe_procs)

    def test_get_processes_on_system(self):
        """Test getting all processes on a system."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        sm.create_process("WS-01", 0, "explorer.exe", "explorer.exe", "jdoe", "Medium")
        sm.create_process("WS-01", 0, "cmd.exe", "cmd.exe", "asmith", "Medium")
        sm.create_process("WS-02", 0, "bash", "bash", "jdoe", "Medium")

        ws01_procs = sm.get_processes_on_system("WS-01")
        assert len(ws01_procs) == 2
        assert all(p.system == "WS-01" for p in ws01_procs)

    def test_end_process(self):
        """Test ending a process."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        pid = sm.create_process("WS-01", 0, "explorer.exe", "explorer.exe", "jdoe", "Medium")
        assert sm.get_process("WS-01", pid) is not None

        result = sm.end_process("WS-01", pid)
        assert result is True
        assert sm.get_process("WS-01", pid) is None

    def test_end_nonexistent_process(self):
        """Test ending non-existent process returns False."""
        sm = StateManager()
        result = sm.end_process("WS-01", 999)
        assert result is False

    def test_update_process_activity_time_keeps_latest(self):
        """Process activity marker should track the latest dependent event."""
        sm = StateManager()
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        sm.set_current_time(start)
        pid = sm.create_process("WS-01", 0, "explorer.exe", "explorer.exe", "jdoe", "Medium")

        assert sm.update_process_activity_time("WS-01", pid, start + timedelta(minutes=5))
        assert sm.update_process_activity_time("WS-01", pid, start + timedelta(minutes=2))
        proc = sm.get_process("WS-01", pid)

        assert proc is not None
        assert proc.last_activity_time == start + timedelta(minutes=5)

    def test_update_session_activity_time_keeps_latest(self):
        """Session activity marker should track the latest dependent event."""
        sm = StateManager()
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        sm.set_current_time(start)
        logon_id = sm.create_session(
            username="jdoe",
            system="WS-01",
            logon_type=2,
            source_ip="-",
        )

        assert sm.update_session_activity_time(logon_id, start + timedelta(minutes=5))
        assert sm.update_session_activity_time(logon_id, start + timedelta(minutes=2))
        session = sm.get_session(logon_id)

        assert session is not None
        assert session.last_activity_time == start + timedelta(minutes=5)

    def test_apply_tracks_process_dependent_activity_time(self):
        """Any process-owned event should extend the process lifecycle marker."""
        sm = StateManager()
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        activity_time = start + timedelta(minutes=3)
        sm.set_current_time(start)
        pid = sm.create_process("WS-01", 0, "proc.exe", "proc.exe", "jdoe", "Medium")

        sm.apply(
            SecurityEvent(
                timestamp=activity_time,
                event_type="process_access",
                src_host=HostContext(
                    hostname="WS-01",
                    ip="10.0.0.10",
                    os="Windows 11",
                    os_category="windows",
                    system_type="workstation",
                ),
                process=ProcessContext(
                    pid=pid,
                    parent_pid=0,
                    image="proc.exe",
                    command_line="proc.exe",
                    username="jdoe",
                ),
            )
        )

        proc = sm.get_process("WS-01", pid)
        assert proc is not None
        assert proc.last_activity_time == activity_time

    def test_list_running_processes(self):
        """Test listing all running processes."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        sm.create_process("WS-01", 0, "explorer.exe", "explorer.exe", "jdoe", "Medium")
        sm.create_process("WS-02", 0, "bash", "bash", "asmith", "Medium")

        procs = sm.list_running_processes()
        assert len(procs) == 2


class TestConnectionManagement:
    """Tests for connection lifecycle."""

    def test_open_connection(self):
        """Test opening a new connection."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        conn_id = sm.open_connection(
            src_ip="192.168.1.100",
            src_port=50000,
            dst_ip="8.8.8.8",
            dst_port=53,
            protocol="udp",
        )

        assert conn_id == "conn-0"
        conn = sm.get_connection(conn_id)
        assert conn is not None
        assert conn.src_ip == "192.168.1.100"
        assert conn.dst_ip == "8.8.8.8"
        assert conn.protocol == "udp"
        assert conn.state == "established"

    def test_open_connection_increments_counter(self):
        """Test that connection IDs increment."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        id1 = sm.open_connection("192.168.1.1", 50000, "8.8.8.8", 53, "udp")
        id2 = sm.open_connection("192.168.1.1", 50001, "8.8.4.4", 53, "udp")

        assert id1 == "conn-0"
        assert id2 == "conn-1"

    def test_open_connection_requires_current_time(self):
        """Test that opening connection fails if current_time not set."""
        sm = StateManager()

        with pytest.raises(StateError, match="current_time not set"):
            sm.open_connection("192.168.1.1", 50000, "8.8.8.8", 53, "udp")

    def test_update_connection_bytes(self):
        """Test updating connection byte counts."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        conn_id = sm.open_connection("192.168.1.1", 50000, "8.8.8.8", 53, "udp")
        result = sm.update_connection_bytes(conn_id, 1024, 2048)

        assert result is True
        conn = sm.get_connection(conn_id)
        assert conn.bytes_sent == 1024
        assert conn.bytes_received == 2048

    def test_update_nonexistent_connection(self):
        """Test updating non-existent connection returns False."""
        sm = StateManager()
        result = sm.update_connection_bytes("conn-999", 1024, 2048)
        assert result is False

    def test_close_connection(self):
        """Test closing a connection."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        conn_id = sm.open_connection("192.168.1.1", 50000, "8.8.8.8", 53, "udp")
        assert sm.get_connection(conn_id) is not None

        result = sm.close_connection(conn_id)
        assert result is True
        assert sm.get_connection(conn_id) is None

    def test_close_nonexistent_connection(self):
        """Test closing non-existent connection returns False."""
        sm = StateManager()
        result = sm.close_connection("conn-999")
        assert result is False

    def test_list_open_connections(self):
        """Test listing all open connections."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

        sm.open_connection("192.168.1.1", 50000, "8.8.8.8", 53, "udp")
        sm.open_connection("192.168.1.2", 50001, "8.8.4.4", 53, "udp")

        conns = sm.list_open_connections()
        assert len(conns) == 2


class TestDNSManagement:
    """Tests for DNS cache."""

    def test_register_hostname(self):
        """Test registering a hostname."""
        sm = StateManager()
        sm.register_hostname("google.com", "8.8.8.8")

        ip = sm.resolve_hostname("google.com")
        assert ip == "8.8.8.8"

    def test_register_duplicate_hostname_same_ip(self):
        """Test registering same hostname with same IP is allowed."""
        sm = StateManager()
        sm.register_hostname("google.com", "8.8.8.8")
        sm.register_hostname("google.com", "8.8.8.8")  # Should not raise

        ip = sm.resolve_hostname("google.com")
        assert ip == "8.8.8.8"

    def test_register_duplicate_hostname_different_ip(self):
        """Test registering same hostname with different IP raises error."""
        sm = StateManager()
        sm.register_hostname("google.com", "8.8.8.8")

        with pytest.raises(StateError, match="already mapped to"):
            sm.register_hostname("google.com", "8.8.4.4")

    def test_resolve_nonexistent_hostname(self):
        """Test resolving non-existent hostname returns None."""
        sm = StateManager()
        ip = sm.resolve_hostname("nonexistent.com")
        assert ip is None

    def test_list_dns_cache(self):
        """Test listing all DNS cache entries."""
        sm = StateManager()
        sm.register_hostname("google.com", "8.8.8.8")
        sm.register_hostname("cloudflare.com", "1.1.1.1")

        cache = sm.list_dns_cache()
        assert len(cache) == 2
        assert cache["google.com"] == "8.8.8.8"
        assert cache["cloudflare.com"] == "1.1.1.1"


class TestTimeManagement:
    """Tests for time tracking."""

    def test_set_current_time(self):
        """Test setting current time."""
        sm = StateManager()
        dt = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

        sm.set_current_time(dt)
        assert sm.get_current_time() == dt

    def test_advance_time(self):
        """Test advancing time by delta."""
        sm = StateManager()
        dt = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        sm.set_current_time(dt)

        sm.advance_time(timedelta(hours=1))
        assert sm.get_current_time() == datetime(2024, 1, 15, 11, 0, 0, tzinfo=UTC)

    def test_advance_time_requires_current_time(self):
        """Test that advancing time fails if current_time not set."""
        sm = StateManager()

        with pytest.raises(StateError, match="current_time not set"):
            sm.advance_time(timedelta(hours=1))


class TestStateQueries:
    """Tests for state query methods."""

    def test_get_state(self):
        """Test getting complete state."""
        sm = StateManager()
        state = sm.get_state()
        assert state is sm.state

    def test_get_state_summary(self):
        """Test getting state summary."""
        sm = StateManager()
        sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))
        sm.create_session("jdoe", "WS-01", 2, "192.168.1.1")
        sm.create_process("WS-01", 0, "explorer.exe", "explorer.exe", "jdoe", "Medium")

        summary = sm.get_state_summary()
        assert summary["active_sessions"] == 1
        assert summary["running_processes"] == 1
        assert summary["open_connections"] == 0
        assert summary["dns_cache_entries"] == 0
        assert "2024-01-15" in summary["current_time"]
