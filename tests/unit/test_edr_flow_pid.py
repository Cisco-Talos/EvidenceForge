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

"""Tests for eCAR FLOW pid propagation.

Verifies that baseline and storyline connections carry realistic
initiating process PIDs in eCAR FLOW records.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest

from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models import System


@pytest.fixture
def state_manager():
    return StateManager()


@pytest.fixture
def mock_emitters():
    return {
        "windows_event_security": Mock(),
        "zeek_conn": Mock(),
        "ecar": Mock(),
    }


@pytest.fixture
def activity_gen(state_manager, mock_emitters):
    return ActivityGenerator(state_manager, mock_emitters)


@pytest.fixture
def win_system():
    return System(hostname="WKS-01", ip="10.0.10.1", os="Windows 10", type="workstation")


@pytest.fixture
def timestamp():
    return datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)


class TestEmitterSetupProcessTree:
    """Test that process tree seeding creates the right entries per distro."""

    def test_ubuntu_gets_systemd_resolved(self, state_manager, timestamp):
        """Ubuntu should have systemd_resolved in _system_pids."""
        from evidenceforge.generation.engine.emitter_setup import EmitterSetupMixin

        ubuntu = System(hostname="SRV-01", ip="10.0.10.1", os="Ubuntu 22.04", type="server")
        state_manager.set_current_time(timestamp)
        mixin = EmitterSetupMixin.__new__(EmitterSetupMixin)
        mixin.state_manager = state_manager

        pids: dict[str, int] = {}
        mixin._seed_linux_process_tree(ubuntu, pids)
        assert "systemd_resolved" in pids
        assert "chronyd" not in pids
        assert "timesyncd" in pids

    def test_rhel_gets_chronyd(self, state_manager, timestamp):
        """RHEL/CentOS should have chronyd, not timesyncd or systemd_resolved."""
        from evidenceforge.generation.engine.emitter_setup import EmitterSetupMixin

        rhel = System(hostname="SRV-01", ip="10.0.10.1", os="CentOS 8", type="server")
        state_manager.set_current_time(timestamp)
        mixin = EmitterSetupMixin.__new__(EmitterSetupMixin)
        mixin.state_manager = state_manager

        pids: dict[str, int] = {}
        mixin._seed_linux_process_tree(rhel, pids)
        assert "chronyd" in pids
        assert "timesyncd" not in pids
        assert "systemd_resolved" not in pids


class TestConnectionPidPropagation:
    """Test that generate_connection passes pid through to eCAR emitter."""

    def test_connection_with_explicit_pid(
        self, activity_gen, state_manager, timestamp, win_system, mock_emitters
    ):
        """When pid is passed, eCAR FLOW record should carry it."""
        state_manager.set_current_time(timestamp)
        pid = state_manager.create_process(
            "WKS-01", 4, r"C:\Windows\System32\svchost.exe", "svchost.exe", "SYSTEM", "System"
        )
        activity_gen.generate_connection(
            src_ip="10.0.10.1",
            dst_ip="10.0.0.1",
            time=timestamp,
            dst_port=53,
            proto="udp",
            service="dns",
            source_system=win_system,
            pid=pid,
        )
        assert mock_emitters["ecar"].emit.called
        event = mock_emitters["ecar"].emit.call_args[0][0]
        assert event.network.initiating_pid == pid

    @staticmethod
    def _find_connection_event(mock_emitters):
        """Find the main 'connection' event (not wfp_connection) from eCAR mock calls."""
        for call in mock_emitters["ecar"].emit.call_args_list:
            evt = call[0][0]
            if evt.event_type == "connection":
                return evt
        return None

    def test_connection_without_pid_defaults_negative_one(
        self, activity_gen, state_manager, timestamp, win_system, mock_emitters
    ):
        """When pid= not passed, initiating_pid should be -1."""
        state_manager.set_current_time(timestamp)
        activity_gen.generate_connection(
            src_ip="10.0.10.1",
            dst_ip="93.184.216.34",
            time=timestamp,
            dst_port=443,
            proto="tcp",
            source_system=win_system,
        )
        event = self._find_connection_event(mock_emitters)
        assert event is not None
        assert event.network.initiating_pid == -1

    def test_inferred_dns_pid_from_source_ip(
        self, activity_gen, state_manager, timestamp, win_system, mock_emitters
    ):
        """DNS connections inferred from an internal source IP should use resolver PID."""
        state_manager.set_current_time(timestamp)
        pid = state_manager.create_process(
            "WKS-01",
            4,
            r"C:\Windows\System32\svchost.exe",
            "svchost.exe -k netsvcs",
            "NETWORK SERVICE",
            "System",
        )
        activity_gen._ip_to_system = {"10.0.10.1": win_system}
        activity_gen._system_pids = {"WKS-01": {"svchost_netsvcs": pid}}

        activity_gen.generate_connection(
            src_ip="10.0.10.1",
            dst_ip="10.0.0.10",
            time=timestamp,
            dst_port=53,
            proto="udp",
            service="dns",
        )

        event = self._find_connection_event(mock_emitters)
        assert event is not None
        assert event.network.initiating_pid == pid
        assert event.edr is not None
        assert event.edr.actor_id == state_manager.get_process_object_id("WKS-01", pid)

    def test_inferred_dns_pid_prefers_dns_client_service(
        self, activity_gen, state_manager, timestamp, win_system, mock_emitters
    ):
        """DNS FLOW attribution should match Sysmon Event 22's DNS Client PID."""
        state_manager.set_current_time(timestamp)
        netsvcs_pid = state_manager.create_process(
            "WKS-01",
            4,
            r"C:\Windows\System32\svchost.exe",
            "svchost.exe -k netsvcs",
            "NETWORK SERVICE",
            "System",
        )
        local_svc_pid = state_manager.create_process(
            "WKS-01",
            4,
            r"C:\Windows\System32\svchost.exe",
            "svchost.exe -k LocalService",
            "LOCAL SERVICE",
            "System",
        )
        activity_gen._ip_to_system = {"10.0.10.1": win_system}
        activity_gen._system_pids = {
            "WKS-01": {
                "svchost_netsvcs": netsvcs_pid,
                "svchost_local_svc": local_svc_pid,
            }
        }

        activity_gen.generate_connection(
            src_ip="10.0.10.1",
            dst_ip="10.0.0.10",
            time=timestamp,
            dst_port=53,
            proto="udp",
            service="dns",
        )

        event = self._find_connection_event(mock_emitters)
        assert event is not None
        assert event.network.initiating_pid == local_svc_pid
        assert event.edr is not None
        assert event.edr.actor_id == state_manager.get_process_object_id("WKS-01", local_svc_pid)

    def test_connection_timestamp_not_before_process_start(
        self, activity_gen, state_manager, timestamp, win_system, mock_emitters
    ):
        """A FLOW attributed to a process should not predate that process."""
        state_manager.set_current_time(timestamp)
        pid = state_manager.create_process(
            "WKS-01",
            4,
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r'"C:\Program Files\Google\Chrome\Application\chrome.exe"',
            "jdoe",
            "Medium",
        )

        activity_gen.generate_connection(
            src_ip="10.0.10.1",
            dst_ip="93.184.216.34",
            time=timestamp - timedelta(milliseconds=100),
            dst_port=443,
            proto="tcp",
            service="ssl",
            source_system=win_system,
            pid=pid,
        )

        event = self._find_connection_event(mock_emitters)
        assert event is not None
        assert event.timestamp > timestamp

    def test_connection_updates_process_last_activity_time(
        self, activity_gen, state_manager, timestamp, win_system, mock_emitters
    ):
        """FLOW attribution should keep process termination after dependent network evidence."""
        state_manager.set_current_time(timestamp)
        pid = state_manager.create_process(
            "WKS-01",
            4,
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r'"C:\Program Files\Google\Chrome\Application\chrome.exe"',
            "jdoe",
            "Medium",
        )

        activity_gen.generate_connection(
            src_ip="10.0.10.1",
            dst_ip="93.184.216.34",
            time=timestamp + timedelta(minutes=5),
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=3.0,
            orig_bytes=500,
            resp_bytes=1500,
            conn_state="SF",
            source_system=win_system,
            pid=pid,
        )

        proc = state_manager.get_process("WKS-01", pid)
        assert proc is not None
        assert proc.last_activity_time is not None
        assert proc.last_activity_time >= timestamp + timedelta(minutes=5, seconds=3)

    def test_connection_drops_stale_non_system_pid_attribution(
        self, activity_gen, state_manager, timestamp, win_system, mock_emitters
    ):
        """A FLOW should not claim a PID that is no longer running in source state."""
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection(
            src_ip="10.0.10.1",
            dst_ip="93.184.216.34",
            time=timestamp,
            dst_port=443,
            proto="tcp",
            service="ssl",
            source_system=win_system,
            pid=5156,
            process_image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        )

        event = self._find_connection_event(mock_emitters)
        assert event is not None
        assert event.network.initiating_pid == -1
        assert event.process is None
        assert event.edr is not None
        assert event.edr.actor_id == ""

    def test_connection_with_pid_gets_edr_actor_id(
        self, activity_gen, state_manager, timestamp, win_system, mock_emitters
    ):
        """FLOW with known pid should have EdrContext with actorID linking to the process."""
        state_manager.set_current_time(timestamp)
        pid = state_manager.create_process(
            "WKS-01", 4, r"C:\Windows\System32\svchost.exe", "svchost.exe", "SYSTEM", "System"
        )
        proc_obj_id = state_manager.get_process_object_id("WKS-01", pid)

        activity_gen.generate_connection(
            src_ip="10.0.10.1",
            dst_ip="10.0.0.1",
            time=timestamp,
            dst_port=53,
            proto="udp",
            source_system=win_system,
            pid=pid,
        )
        event = self._find_connection_event(mock_emitters)
        assert event is not None
        assert event.edr is not None
        assert event.edr.actor_id == proc_obj_id

    def test_connection_without_pid_has_no_actor_id(
        self, activity_gen, state_manager, timestamp, win_system, mock_emitters
    ):
        """FLOW without known pid should have empty actorID."""
        state_manager.set_current_time(timestamp)
        activity_gen.generate_connection(
            src_ip="10.0.10.1",
            dst_ip="93.184.216.34",
            time=timestamp,
            dst_port=443,
            proto="tcp",
            source_system=win_system,
        )
        event = self._find_connection_event(mock_emitters)
        assert event is not None
        assert event.edr is not None
        assert event.edr.actor_id == ""
