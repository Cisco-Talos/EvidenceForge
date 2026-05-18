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

from evidenceforge.events.contexts import HttpContext
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models import System, User


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

    @staticmethod
    def _browser_http_context() -> HttpContext:
        return HttpContext(
            method="GET",
            host="intranet.example.org",
            uri="/",
            version="1.1",
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"
            ),
            request_body_len=0,
            response_body_len=2048,
            status_code=200,
            status_msg="OK",
            resp_mime_types=["text/html"],
            tags=[],
        )

    def test_browser_http_flow_preserves_explicit_non_browser_process(
        self, activity_gen, state_manager, timestamp, win_system, mock_emitters
    ):
        """Explicit malware/tool HTTP ownership should survive browser UA spoofing."""
        state_manager.set_current_time(timestamp - timedelta(seconds=5))
        attacker_pid = state_manager.create_process(
            win_system.hostname,
            4,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            r"powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Users\Public\stage.ps1",
            "jdoe",
            "Medium",
        )
        activity_gen._ip_to_system = {win_system.ip: win_system}

        activity_gen.generate_connection(
            src_ip=win_system.ip,
            dst_ip="10.0.20.10",
            time=timestamp,
            dst_port=80,
            proto="tcp",
            service="http",
            duration=0.5,
            orig_bytes=400,
            resp_bytes=2048,
            conn_state="SF",
            source_system=win_system,
            http=self._browser_http_context(),
            pid=attacker_pid,
        )

        event = self._find_connection_event(mock_emitters)
        assert event is not None
        assert event.network.initiating_pid == attacker_pid
        assert event.process is not None
        assert event.process.image.endswith(r"\WindowsPowerShell\v1.0\powershell.exe")
        assert event.edr is not None
        assert event.edr.actor_id == state_manager.get_process_object_id(
            win_system.hostname,
            attacker_pid,
        )

    def test_browser_http_flow_uses_interactive_browser_instead_of_svchost(
        self, activity_gen, state_manager, timestamp, win_system, mock_emitters
    ):
        """Browser-like HTTP should resolve to a user browser process, not service svchost."""
        user = User(username="jdoe", full_name="Jane Doe", email="jdoe@example.org")
        activity_gen._users_by_username = {user.username: user}
        state_manager.set_current_time(timestamp - timedelta(minutes=10))
        logon_id = state_manager.create_session(
            username=user.username,
            system=win_system.hostname,
            logon_type=2,
            source_ip=win_system.ip,
        )
        explorer_pid = state_manager.create_process(
            win_system.hostname,
            4,
            r"C:\Windows\explorer.exe",
            "explorer.exe",
            user.username,
            "Medium",
            logon_id=logon_id,
        )
        session = state_manager.get_session(logon_id)
        assert session is not None
        session.explorer_pid = explorer_pid
        svchost_pid = state_manager.create_process(
            win_system.hostname,
            4,
            r"C:\Windows\System32\svchost.exe",
            "svchost.exe -k netsvcs",
            "NETWORK SERVICE",
            "System",
            logon_id="0x3e4",
        )
        activity_gen._ip_to_system = {win_system.ip: win_system}
        activity_gen._system_pids = {win_system.hostname: {"svchost_netsvcs": svchost_pid}}

        activity_gen.generate_connection(
            src_ip=win_system.ip,
            dst_ip="10.0.20.10",
            time=timestamp,
            dst_port=80,
            proto="tcp",
            service="http",
            duration=0.5,
            orig_bytes=400,
            resp_bytes=2048,
            conn_state="SF",
            source_system=win_system,
            http=self._browser_http_context(),
        )

        event = self._find_connection_event(mock_emitters)
        assert event is not None
        assert event.process is not None
        assert event.process.pid == event.network.initiating_pid
        assert event.process.pid != svchost_pid
        assert event.process.username == user.username
        assert event.process.image.endswith(r"\Mozilla Firefox\firefox.exe")
        wfp_event = next(
            call.args[0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call.args[0].event_type == "wfp_connection"
        )
        assert wfp_event.process is not None
        assert wfp_event.process.image.endswith(r"\Mozilla Firefox\firefox.exe")

    def test_browser_http_flow_without_interactive_session_clears_svchost_attribution(
        self, activity_gen, state_manager, timestamp, win_system, mock_emitters
    ):
        """A browser UA without a user session should not be rendered as svchost-owned."""
        state_manager.set_current_time(timestamp)
        svchost_pid = state_manager.create_process(
            win_system.hostname,
            4,
            r"C:\Windows\System32\svchost.exe",
            "svchost.exe -k netsvcs",
            "NETWORK SERVICE",
            "System",
            logon_id="0x3e4",
        )
        activity_gen._ip_to_system = {win_system.ip: win_system}
        activity_gen._system_pids = {win_system.hostname: {"svchost_netsvcs": svchost_pid}}

        activity_gen.generate_connection(
            src_ip=win_system.ip,
            dst_ip="10.0.20.10",
            time=timestamp,
            dst_port=80,
            proto="tcp",
            service="http",
            duration=0.5,
            orig_bytes=400,
            resp_bytes=2048,
            conn_state="SF",
            source_system=win_system,
            http=self._browser_http_context(),
        )

        event = self._find_connection_event(mock_emitters)
        assert event is not None
        assert event.network.initiating_pid == -1
        assert event.process is None
        assert event.edr is not None
        assert event.edr.actor_id == ""
        wfp_events = [
            call.args[0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call.args[0].event_type == "wfp_connection"
        ]
        assert not wfp_events

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

    def test_connection_drops_expired_one_shot_process_pid_attribution(
        self, activity_gen, state_manager, timestamp, win_system, mock_emitters
    ):
        """Short-lived admin utilities should not own later unrelated network flows."""
        state_manager.set_current_time(timestamp)
        pid = state_manager.create_process(
            "WKS-01",
            4,
            r"C:\Windows\System32\dsquery.exe",
            'dsquery.exe group -name "Domain Admins"',
            "jdoe",
            "Medium",
        )

        activity_gen.generate_connection(
            src_ip="10.0.10.1",
            dst_ip="10.0.20.10",
            time=timestamp + timedelta(minutes=10),
            dst_port=389,
            proto="tcp",
            service="ldap",
            duration=0.5,
            source_system=win_system,
            pid=pid,
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
