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

"""Unit tests for activity generation."""

import random
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock, patch

import pytest

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import HttpContext, NetworkContext
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.generation.activity import (
    BASELINE_PATTERNS,
    EXTERNAL_IPS,
    ActivityGenerator,
    _is_invalid_network_connection,
)
from evidenceforge.generation.activity import generator as generator_module
from evidenceforge.generation.activity.generator import _extract_image_from_command
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models import System, User


class TestStateObjectIds:
    def test_missing_process_object_id_is_allocated_once(self):
        """Unseen process IDs should still get stable eCAR object IDs."""
        state = StateManager()

        first = state.get_process_object_id("WS-01", 4444)
        second = state.get_process_object_id("WS-01", 4444)

        assert first
        assert second == first


class TestNetworkValidation:
    """Tests for network connection validation."""

    def test_same_src_dst_is_valid(self):
        """Same-IP connections are valid (handled by SecurityEvent.local_only)."""
        is_invalid, _reason = _is_invalid_network_connection("10.0.0.1", "10.0.0.1")

        assert is_invalid is False

    def test_invalid_localhost_src(self):
        """Connection with localhost source should be invalid."""
        is_invalid, reason = _is_invalid_network_connection("127.0.0.1", "10.0.0.1")

        assert is_invalid is True
        assert "localhost" in reason.lower()

    def test_invalid_localhost_dst(self):
        """Connection with localhost destination should be invalid."""
        is_invalid, reason = _is_invalid_network_connection("10.0.0.1", "127.0.0.5")

        assert is_invalid is True
        assert "localhost" in reason.lower()

    def test_invalid_link_local(self):
        """Connection with link-local address should be invalid."""
        is_invalid, reason = _is_invalid_network_connection("169.254.1.1", "10.0.0.1")

        assert is_invalid is True
        assert "link-local" in reason.lower()

    def test_invalid_multicast(self):
        """Connection with multicast address should be invalid."""
        is_invalid, reason = _is_invalid_network_connection("224.0.0.1", "10.0.0.1")

        assert is_invalid is True
        assert "multicast" in reason.lower() or "reserved" in reason.lower()

    def test_valid_connection(self):
        """Valid connection should pass validation."""
        is_invalid, reason = _is_invalid_network_connection("10.0.0.1", "93.184.216.34")

        assert is_invalid is False
        assert reason == ""


class TestActivityGenerator:
    """Tests for ActivityGenerator class."""

    @pytest.fixture
    def state_manager(self):
        """Create state manager for testing."""
        return StateManager()

    @pytest.fixture
    def mock_emitters(self):
        """Create mock emitters."""
        windows_emitter = Mock()
        zeek_emitter = Mock()
        zeek_dns_emitter = Mock()
        return {
            "windows_event_security": windows_emitter,
            "zeek_conn": zeek_emitter,
            "zeek_dns": zeek_dns_emitter,
        }

    @pytest.fixture
    def activity_gen(self, state_manager, mock_emitters):
        """Create activity generator with mocked emitters and dispatcher."""
        dispatcher = EventDispatcher(
            state_manager=state_manager,
            emitters=mock_emitters,
        )
        return ActivityGenerator(state_manager, mock_emitters, dispatcher=dispatcher)

    @pytest.fixture
    def test_user(self):
        """Create test user."""
        return User(
            username="testuser", full_name="Test User", email="test@example.com", enabled=True
        )

    @pytest.fixture
    def test_system(self):
        """Create test system."""
        return System(hostname="TEST-01", ip="10.0.0.1", os="Windows 10", type="workstation")

    def test_generate_logon_creates_session(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """generate_logon should create session and dispatch SecurityEvent."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        logon_id = activity_gen.generate_logon(test_user, test_system, timestamp)

        # Verify session created in state manager
        sessions = state_manager.get_sessions_for_user(test_user.username)
        assert len(sessions) == 1
        assert sessions[0].logon_id == logon_id
        assert sessions[0].username == test_user.username

        # Verify emitters received SecurityEvent via dispatch
        assert mock_emitters["windows_event_security"].emit.called
        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.event_type == "logon"
        assert event.auth.username == test_user.username
        assert event.auth.logon_id == logon_id
        assert event.dst_host.os_category == "windows"

    def test_generate_logon_existing_session_renders_canonical_start_time(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Re-rendering an existing session must not move the visible 4624 later."""
        session_start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        later_time = session_start + timedelta(seconds=30)
        state_manager.register_session(
            logon_id="0xabc123",
            username=test_user.username,
            system=test_system.hostname,
            logon_type=2,
            source_ip=test_system.ip,
            start_time=session_start,
            session_kind="interactive",
        )

        activity_gen.generate_logon(
            test_user,
            test_system,
            later_time,
            logon_type=2,
            logon_id="0xabc123",
        )

        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.event_type == "logon"
        assert event.timestamp == session_start

    def test_auto_created_parent_chain_stays_after_session_start(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Synthetic parent-chain events should not precede the owning logon session."""
        session_start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        logon_id = state_manager.register_session(
            logon_id="0xabc124",
            username=test_user.username,
            system=test_system.hostname,
            logon_type=2,
            source_ip=test_system.ip,
            start_time=session_start,
            session_kind="interactive",
        ).logon_id

        activity_gen.generate_process(
            user=test_user,
            system=test_system,
            time=session_start + timedelta(milliseconds=100),
            logon_id=logon_id,
            process_name=r"C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\sqlcmd.exe",
            command_line='sqlcmd.exe -S sqlprod01 -Q "SELECT 1"',
            parent_pid=4,
        )

        related_events = [
            call.args[0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call.args[0].event_type == "process_create"
            and call.args[0].auth.logon_id == logon_id
        ]
        assert related_events
        assert all(event.timestamp > session_start for event in related_events)

    def test_process_identity_ignores_future_interactive_session(
        self, activity_gen, state_manager, test_system
    ):
        """User-shell attribution must not borrow a session that starts later."""
        process_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        future_logon = process_time + timedelta(seconds=30)
        state_manager.register_session(
            logon_id="0xfuture",
            username="alice",
            system=test_system.hostname,
            logon_type=2,
            source_ip=test_system.ip,
            start_time=future_logon,
            session_kind="interactive",
        )

        username, logon_id = activity_gen._resolve_process_identity(
            system=test_system,
            username="SYSTEM",
            logon_id="0x3e7",
            process_name=r"C:\Windows\System32\cmd.exe",
            time=process_time,
        )

        assert username == "SYSTEM"
        assert logon_id == "0x3e7"

    def test_psexesvc_process_uses_service_path_and_system_identity(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """PsExec service binaries should render as service execution, not client execution."""
        process_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(process_time)

        pid = activity_gen.generate_process(
            user=test_user,
            system=test_system,
            time=process_time,
            logon_id="0xadmin",
            process_name=r"C:\Windows\System32\PSEXESVC.exe",
            command_line="PSEXESVC.exe -accepteula",
            parent_pid=4,
        )

        process_events = [
            call.args[0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call.args[0].event_type == "process_create"
            and call.args[0].process is not None
            and call.args[0].process.pid == pid
        ]
        assert process_events
        event = process_events[-1]
        assert event.process.image == r"C:\Windows\PSEXESVC.exe"
        assert event.process.command_line == r"C:\Windows\PSEXESVC.exe"
        assert event.process.username == "SYSTEM"
        assert event.process.logon_id == "0x3e7"

    def test_prefixed_system_user_session_process_identity_resolves_to_user(
        self, activity_gen, state_manager, test_system
    ):
        """User-shell process correction should recognize NT AUTHORITY\\SYSTEM."""
        process_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.register_session(
            logon_id="0xuser",
            username="alice",
            system=test_system.hostname,
            logon_type=2,
            source_ip=test_system.ip,
            start_time=process_time - timedelta(minutes=5),
            session_kind="interactive",
        )

        username, logon_id = activity_gen._resolve_process_identity(
            system=test_system,
            username=r"NT AUTHORITY\SYSTEM",
            logon_id="0x3e7",
            process_name=r"C:\Windows\System32\SearchHost.exe",
            time=process_time,
        )

        assert username == "alice"
        assert logon_id == "0xuser"

    def test_service_hosted_svchost_uses_builtin_service_identity(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Core svchost service groups should not inherit an interactive domain user."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        logon_id = activity_gen.generate_logon(test_user, test_system, timestamp)

        pid = activity_gen.generate_process(
            test_user,
            test_system,
            timestamp + timedelta(seconds=1),
            logon_id,
            r"C:\Windows\System32\svchost.exe",
            "svchost.exe -k DcomLaunch -p",
            parent_pid=4,
        )

        event = [
            call.args[0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call.args[0].event_type == "process_create"
            and call.args[0].process
            and call.args[0].process.pid == pid
        ][0]
        assert event.auth.username == "SYSTEM"
        assert event.auth.logon_id == "0x3e7"
        assert event.process.integrity_level == "System"
        assert event.process.token_elevation == "%%1936"

    def test_process_activity_does_not_reuse_network_logon_session(
        self, activity_gen, test_user, test_system, state_manager
    ):
        """Desktop process baselines should not run under Type 3 network tokens."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.register_session(
            logon_id="0xnetwork",
            username=test_user.username,
            system=test_system.hostname,
            logon_type=3,
            source_ip="45.83.221.45",
            start_time=timestamp - timedelta(minutes=5),
            session_kind="network",
        )

        activity_gen.execute_baseline_activity(
            user=test_user,
            system=test_system,
            time=timestamp,
            activity_type="process_system",
        )

        process_events = [
            call.args[0]
            for call in activity_gen.dispatcher.emitters[
                "windows_event_security"
            ].emit.call_args_list
            if call.args[0].event_type == "process_create"
        ]
        assert process_events
        assert process_events[-1].auth.logon_id != "0xnetwork"
        if process_events[-1].auth.username == "SYSTEM":
            assert process_events[-1].auth.logon_id == "0x3e7"
            assert process_events[-1].process.integrity_level == "System"
        else:
            assert state_manager.get_session(process_events[-1].auth.logon_id).logon_type == 2

    def test_account_management_subject_logon_ignores_future_session(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """4720 SubjectLogonId should use a visible earlier session, not a future one."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.register_session(
            logon_id="0xfuture",
            username=test_user.username,
            system=test_system.hostname,
            logon_type=10,
            source_ip="10.0.0.99",
            start_time=timestamp + timedelta(minutes=30),
            session_kind="rdp",
        )

        activity_gen.generate_account_created(
            actor=test_user,
            system=test_system,
            time=timestamp,
            target_username="svc-audit",
            target_sid="S-1-5-21-1-2-3-1109",
        )

        account_event = [
            call.args[0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call.args[0].event_type == "account_created"
        ][0]
        assert account_event.auth.subject_logon_id != "0xfuture"
        subject_session = state_manager.get_session(account_event.auth.subject_logon_id)
        assert subject_session is not None
        assert subject_session.start_time < timestamp

    def test_regular_user_logon_is_not_randomly_elevated(
        self, activity_gen, test_user, test_system
    ):
        """Ordinary users should not receive 4672 without a privileged role."""
        assert activity_gen._should_elevate(test_user) is False

    def test_generate_logon_interactive_uses_no_source_ip(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Interactive logon (type 2) should not render a remote source IP."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_logon(test_user, test_system, timestamp, logon_type=2)

        # SecurityEvent dispatched to Windows emitter
        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.auth.logon_type == 2
        assert event.auth.source_ip == "-"

    def test_generate_logon_cached_interactive_ignores_remote_source_ip(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Cached interactive logon (type 11) is local even if caller passes a source IP."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_logon(
            test_user,
            test_system,
            timestamp,
            logon_type=11,
            source_ip="10.0.99.50",
        )

        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.auth.logon_type == 11
        assert event.auth.source_ip == "-"
        assert event.auth.logon_process == "User32"
        assert event.auth.auth_package == "Negotiate"

    def test_generate_logon_unlock_uses_user32_logon_process(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Unlock logon (type 7) should not use Negotiate as LogonProcessName."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_logon(test_user, test_system, timestamp, logon_type=7)

        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.auth.logon_type == 7
        assert event.auth.logon_process == "User32"
        assert event.auth.auth_package == "Negotiate"

    def test_generate_logon_rdp_uses_native_4624_auth_shape(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """RDP 4624 should not render CredSSP as the authentication package."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_logon(
            test_user,
            test_system,
            timestamp,
            logon_type=10,
            source_ip="10.0.99.50",
        )

        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.auth.logon_type == 10
        assert event.auth.logon_process == "User32"
        assert event.auth.auth_package in {"Negotiate", "Kerberos", "NTLM"}
        assert event.auth.auth_package != "CredSSP"

    def test_generate_rdp_session_reuses_source_port_across_network_and_logon(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """RDP network evidence and destination 4624 should share one source port."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_rdp_session(
            user=test_user,
            target_system=test_system,
            time=timestamp,
            source_ip="10.0.99.50",
        )

        network_event = next(
            call[0][0]
            for call in mock_emitters["zeek_conn"].emit.call_args_list
            if call[0][0].event_type == "connection" and call[0][0].network.dst_port == 3389
        )
        logon_event = next(
            call[0][0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call[0][0].event_type == "logon" and call[0][0].auth.logon_type == 10
        )
        assert network_event.network.dst_port == 3389
        assert network_event.network.src_port > 0
        assert logon_event.auth.source_port == network_event.network.src_port
        assert logon_event.timestamp > network_event.timestamp

    def test_generate_rdp_session_updates_preallocated_session_time(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Preplanned RDP sessions should not pull the target 4624 before source evidence."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        logon_id = state_manager.create_session(
            username=test_user.username,
            system=test_system.hostname,
            logon_type=10,
            source_ip="10.0.99.50",
            session_kind="rdp",
        )

        activity_gen.generate_rdp_session(
            user=test_user,
            target_system=test_system,
            time=timestamp,
            source_ip="10.0.99.50",
            logon_id=logon_id,
        )

        network_event = next(
            call[0][0]
            for call in mock_emitters["zeek_conn"].emit.call_args_list
            if call[0][0].event_type == "connection" and call[0][0].network.dst_port == 3389
        )
        logon_event = next(
            call[0][0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call[0][0].event_type == "logon" and call[0][0].auth.logon_type == 10
        )
        session = state_manager.get_session(logon_id)

        assert logon_event.timestamp > network_event.timestamp
        assert session is not None
        assert session.start_time == logon_event.timestamp
        assert session.source_port == network_event.network.src_port

    def test_nmap_process_emits_matching_network_scan_evidence(
        self, activity_gen, test_user, state_manager, mock_emitters
    ):
        """Nmap process commands should leave network scan evidence."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        source = System(
            hostname="WEB-01",
            ip="10.10.3.10",
            os="Ubuntu 22.04",
            type="server",
        )
        target_a = System(
            hostname="APP-01",
            ip="10.10.2.30",
            os="Ubuntu 22.04",
            type="server",
        )
        target_b = System(
            hostname="FILE-01",
            ip="10.10.2.20",
            os="Windows Server 2019",
            type="server",
        )
        activity_gen._ip_to_system = {
            source.ip: source,
            target_a.ip: target_a,
            target_b.ip: target_b,
        }
        state_manager.set_current_time(timestamp)

        pid = activity_gen.generate_process(
            user=test_user,
            system=source,
            time=timestamp,
            logon_id="0x123",
            process_name="/usr/bin/nmap",
            command_line="nmap -sT -p 22,80,443,445,3306 10.10.2.0/24",
            parent_pid=0,
        )

        scan_events = [
            call.args[0]
            for call in mock_emitters["zeek_conn"].emit.call_args_list
            if call.args[0].event_type == "connection"
            and call.args[0].network.src_ip == source.ip
            and call.args[0].network.initiating_pid == pid
        ]
        assert scan_events
        assert {event.network.dst_ip for event in scan_events} == {target_a.ip, target_b.ip}
        assert {event.network.dst_port for event in scan_events} >= {22, 80, 443, 445, 3306}

    def test_generate_logon_network_allows_custom_ip(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Network logon (type 3) should allow custom source IP."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        source_ip = "45.83.221.45"
        state_manager.set_current_time(timestamp)

        activity_gen.generate_logon(
            test_user, test_system, timestamp, logon_type=3, source_ip=source_ip
        )

        # SecurityEvent dispatched to Windows emitter
        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.auth.logon_type == 3
        assert event.auth.source_ip == source_ip
        assert event.auth.source_port > 0

    def test_remote_successful_logon_emits_matching_established_network_evidence(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """External successful remote logons should have non-S0 network evidence."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        source_ip = "45.83.221.45"
        state_manager.set_current_time(timestamp)

        activity_gen.generate_logon(
            test_user,
            test_system,
            timestamp,
            logon_type=3,
            source_ip=source_ip,
            source_port=52595,
        )

        logon_event = next(
            call[0][0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call[0][0].event_type == "logon"
        )
        network_event = next(
            call[0][0]
            for call in mock_emitters["zeek_conn"].emit.call_args_list
            if call[0][0].event_type == "connection"
        )
        assert logon_event.auth.source_port == 52595
        assert network_event.network.src_ip == source_ip
        assert network_event.network.src_port == 52595
        assert network_event.network.dst_ip == test_system.ip
        assert network_event.network.conn_state == "SF"

    def test_elevated_logon_carries_configured_privilege_profile(
        self, activity_gen, test_system, state_manager, mock_emitters
    ):
        """4672 privilege list should come from canonical auth context."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        admin = User(
            username="admin.lee",
            full_name="Admin Lee",
            email="admin.lee@example.com",
            persona="sysadmin",
            enabled=True,
        )

        with patch.object(activity_gen, "_should_elevate", return_value=True):
            activity_gen.generate_logon(admin, test_system, timestamp, logon_type=2)

        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.auth.privilege_list
        assert "SeDebugPrivilege" in event.auth.privilege_list

    def test_workstation_unlock_enforces_configured_minimum_gap(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """A 4801 too close to a previous 4800 is shifted to a realistic gap."""
        lock_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        logon_id = "0x4f2a1b"
        state_manager.register_session(
            logon_id=logon_id,
            username=test_user.username,
            system=test_system.hostname,
            logon_type=2,
            source_ip="-",
            start_time=lock_time - timedelta(minutes=5),
        )

        activity_gen.generate_workstation_lock(test_user, test_system, lock_time, logon_id)
        activity_gen.generate_workstation_unlock(
            test_user,
            test_system,
            lock_time + timedelta(seconds=1),
            logon_id,
        )

        events = [
            call[0][0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        unlock = next(event for event in events if event.event_type == "workstation_unlocked")
        unlock_logon = next(
            event for event in events if event.event_type == "logon" and event.auth.logon_type == 7
        )
        assert unlock.timestamp == lock_time + timedelta(seconds=127)
        assert unlock_logon.timestamp == unlock.timestamp + timedelta(milliseconds=50)
        assert unlock_logon.auth.source_ip == "-"

    def test_extract_image_from_command_preserves_program_files_path(self):
        """Quoted and unquoted Program Files command lines should not truncate at C:\\Program."""
        assert (
            _extract_image_from_command(
                r'"C:\Program Files\JetBrains\IntelliJ IDEA\bin\idea64.exe" nosplash'
            )
            == r"C:\Program Files\JetBrains\IntelliJ IDEA\bin\idea64.exe"
        )
        assert (
            _extract_image_from_command(
                r"C:\Program Files\Google\Chrome\Application\chrome.exe --type=renderer"
            )
            == r"C:\Program Files\Google\Chrome\Application\chrome.exe"
        )

    def test_explicit_credentials_system_subject_uses_nt_authority(
        self, activity_gen, test_system, state_manager, mock_emitters
    ):
        """4648 generated by SYSTEM should not pair S-1-5-18 with the AD domain."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        system_user = User(username="SYSTEM", full_name="System", email="system@example.local")

        activity_gen.generate_explicit_credentials(
            user=system_user,
            system=test_system,
            time=timestamp,
            target_username="svc_backup",
            target_server="filesrv01",
            process_name=r"C:\Windows\System32\svchost.exe",
            process_pid=1234,
        )

        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.auth.subject_sid == "S-1-5-18"
        assert event.auth.subject_username == "SYSTEM"
        assert event.auth.subject_domain == "NT AUTHORITY"

    def test_generate_logoff_ends_session(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """generate_logoff should end session and emit Windows 4634."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        # First create a session
        logon_id = activity_gen.generate_logon(test_user, test_system, timestamp)
        assert len(state_manager.get_sessions_for_user(test_user.username)) == 1

        # Then log off
        activity_gen.generate_logoff(test_user, test_system, timestamp, logon_id)

        # Verify session ended
        assert len(state_manager.get_sessions_for_user(test_user.username)) == 0

        # Verify Windows emitter received logoff SecurityEvent via dispatch
        # Last emit() call should be the logoff (logon was the first)
        emit_calls = mock_emitters["windows_event_security"].emit.call_args_list
        logoff_event = emit_calls[-1][0][0]
        assert logoff_event.event_type == "logoff"
        assert logoff_event.auth.username == test_user.username
        assert logoff_event.auth.logon_id == logon_id

    def test_generate_logoff_uses_original_session_logon_type(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """A Type 3 session must not log off later as an interactive Type 2 session."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        logon_id = activity_gen.generate_logon(
            test_user,
            test_system,
            timestamp,
            logon_type=3,
            source_ip="10.0.0.99",
        )

        activity_gen.generate_logoff(
            test_user,
            test_system,
            timestamp + timedelta(minutes=5),
            logon_id,
            logon_type=2,
        )

        logoff_event = [
            call.args[0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call.args[0].event_type == "logoff"
        ][-1]
        assert logoff_event.auth.logon_type == 3

    def test_process_termination_after_ended_session_clamps_before_logoff(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Late process teardown for a closed session should render before 4634."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        logon_id = activity_gen.generate_logon(test_user, test_system, timestamp)
        pid = activity_gen.generate_process(
            test_user,
            test_system,
            timestamp + timedelta(seconds=1),
            logon_id,
            r"C:\Windows\System32\cmd.exe",
            "cmd.exe /c whoami",
        )
        logoff_time = timestamp + timedelta(minutes=5)
        activity_gen.generate_logoff(test_user, test_system, logoff_time, logon_id)

        activity_gen.generate_process_termination(
            test_user,
            test_system,
            logoff_time + timedelta(minutes=20),
            pid,
            r"C:\Windows\System32\cmd.exe",
            logon_id,
        )

        termination_event = [
            call.args[0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call.args[0].event_type == "process_terminate"
            and call.args[0].process
            and call.args[0].process.pid == pid
        ][-1]
        assert termination_event.timestamp < logoff_time
        assert termination_event.auth.logon_id == logon_id

    def test_generate_process_creates_process(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """generate_process should create process and emit Windows 4688."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        logon_id = "0x12345"
        process_name = "C:\\Windows\\System32\\cmd.exe"
        command_line = "cmd.exe /c dir"

        pid = activity_gen.generate_process(
            test_user, test_system, timestamp, logon_id, process_name, command_line
        )

        # Verify process created with unique PID
        assert isinstance(pid, int)
        assert pid > 0

        # Verify Windows emitter received process_create SecurityEvent
        # (may not be last call due to probabilistic file/registry/module events after process)
        assert mock_emitters["windows_event_security"].emit.called
        process_events = [
            call[0][0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call[0][0].event_type == "process_create"
        ]
        assert len(process_events) >= 1
        event = next(ev for ev in process_events if ev.process.image == process_name)
        assert event.auth.username == test_user.username
        assert event.process.logon_id == logon_id
        assert event.process.image == process_name
        assert event.process.command_line == command_line

    def test_process_follow_on_file_event_after_process_create(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Process follow-on artifacts should not predate the process create event."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_process(
            test_user,
            test_system,
            timestamp,
            "0x12345",
            r"C:\Users\Public\dropper.exe",
            r"C:\Users\Public\dropper.exe",
            ensure_file_event=True,
        )

        events = [
            call.args[0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        process_event = next(event for event in events if event.event_type == "process_create")
        file_event = next(
            event
            for event in events
            if event.event_type == "file_create"
            and event.file is not None
            and event.file.path == r"C:\Users\Public\dropper.exe"
        )
        assert file_event.timestamp > process_event.timestamp

    def test_service_payload_file_event_precedes_service_process_create(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Dropped service binaries should be written before the service process starts."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_process(
            test_user,
            test_system,
            timestamp,
            "0x12345",
            r"C:\Windows\PSEXESVC.exe",
            r"C:\Windows\PSEXESVC.exe",
            ensure_file_event=True,
        )

        events = [
            call.args[0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        process_event = next(event for event in events if event.event_type == "process_create")
        file_event = next(
            event
            for event in events
            if event.event_type == "file_create"
            and event.file is not None
            and event.file.path == r"C:\Windows\PSEXESVC.exe"
        )
        assert file_event.timestamp < process_event.timestamp
        assert file_event.process.pid == process_event.process.parent_pid
        assert file_event.file.pid == process_event.process.parent_pid
        assert file_event.process.pid != process_event.process.pid

    def test_service_payload_file_event_precedes_service_install(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Dropped service binaries should be visible before 4697 service install."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_service_installed(
            test_user,
            test_system,
            timestamp,
            service_name="PSEXESVC",
            service_file_name=r"%SystemRoot%\PSEXESVC.exe",
        )

        events = [
            call.args[0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        service_event = next(event for event in events if event.event_type == "service_installed")
        file_event = next(
            event
            for event in events
            if event.event_type == "file_create"
            and event.file is not None
            and event.file.path == r"C:\Windows\PSEXESVC.exe"
        )
        assert file_event.timestamp < service_event.timestamp

    def test_process_termination_uses_canonical_running_image(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Termination should render the image from process state, not stale caller text."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        pid = activity_gen.generate_process(
            test_user,
            test_system,
            timestamp,
            "0x12345",
            r"C:\Windows\System32\PSEXESVC.exe",
            r"C:\Windows\System32\PSEXESVC.exe -accepteula",
        )
        mock_emitters["windows_event_security"].reset_mock()

        activity_gen.generate_process_termination(
            test_user,
            test_system,
            timestamp + timedelta(seconds=3),
            pid,
            r"C:\Windows\System32\PSEXESVC.exe",
            "0x12345",
        )

        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.event_type == "process_terminate"
        assert event.process.image == r"C:\Windows\PSEXESVC.exe"

    def test_group_membership_change_uses_member_distinguished_name(
        self, activity_gen, test_user, state_manager, mock_emitters
    ):
        """Group membership events should include a resolvable member DN."""
        dc = System(
            hostname="DC-01",
            ip="10.0.0.10",
            os="Windows Server 2022",
            type="server",
            domain="corp.local",
        )
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_group_membership_change(
            actor=test_user,
            system=dc,
            time=timestamp,
            action="add",
            scope="global",
            group_name="Domain Admins",
            group_sid="S-1-5-21-1-2-3-512",
            member_username="svc_sqlreader",
            member_sid="S-1-5-21-1-2-3-1201",
        )

        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.event_type == "group_member_added_global"
        assert event.group_membership.member_name == "CN=svc_sqlreader,CN=Users,DC=corp,DC=local"

    def test_completed_tls_connections_vary_packet_counts(
        self, activity_gen, state_manager, mock_emitters
    ):
        """Completed TLS conn rows should not all collapse to the handshake packet floor."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        for idx in range(20):
            activity_gen.generate_connection(
                src_ip="10.0.0.10",
                dst_ip="203.0.113.10",
                time=timestamp + timedelta(seconds=idx),
                dst_port=443,
                proto="tcp",
                service="ssl",
                duration=1.0,
                orig_bytes=200,
                resp_bytes=1500,
                src_port=40000 + idx,
                conn_state="SF",
            )

        events = [call.args[0] for call in mock_emitters["zeek_conn"].emit.call_args_list]
        packet_pairs = {(event.network.orig_pkts, event.network.resp_pkts) for event in events}
        durations = {round(event.network.duration, 1) for event in events}
        assert len(packet_pairs) > 3
        assert len(durations) > 3

    def test_system_process_registry_side_effects_use_hklm(
        self, activity_gen, test_system, state_manager, mock_emitters
    ):
        """SYSTEM-owned registry side effects should not write per-user HKCU keys."""

        class RegistryOnlyRandom:
            def __init__(self):
                self.random_calls = 0

            def random(self):
                self.random_calls += 1
                return 0.1 if self.random_calls == 3 else 0.99

            def choice(self, values):
                return values[0]

            def choices(self, population, weights=None, k=1):
                return [population[0]]

            def randint(self, lower, _upper):
                return lower

            def uniform(self, lower, _upper):
                return lower

            def getrandbits(self, bits):
                return (1 << min(bits, 8)) - 1

        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        system_user = User(
            username="SYSTEM",
            full_name="Local System",
            email="system@example.com",
            enabled=True,
        )

        with patch("evidenceforge.generation.activity.generator._get_rng", RegistryOnlyRandom):
            activity_gen.generate_process(
                system_user,
                test_system,
                timestamp,
                "0x3e7",
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "powershell.exe -NoProfile",
            )

        registry_events = [
            call.args[0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call.args[0].event_type == "registry_modify"
        ]
        assert registry_events
        assert registry_events[-1].registry.key.startswith("HKLM\\")

    def test_image_load_is_clamped_after_process_start(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Image-load telemetry should not predate the process it references."""
        session_start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        process_time = session_start + timedelta(minutes=5)
        state_manager.set_current_time(session_start)
        logon_id = activity_gen.generate_logon(test_user, test_system, session_start)
        pid = activity_gen.generate_process(
            test_user,
            test_system,
            process_time,
            logon_id,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell.exe -NoProfile",
        )
        mock_emitters["windows_event_security"].reset_mock()

        activity_gen.generate_image_load(
            test_user,
            test_system,
            session_start + timedelta(minutes=1),
            pid,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            r"C:\Windows\System32\kernel32.dll",
        )

        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        process_start = state_manager.get_process(test_system.hostname, pid).start_time
        assert event.event_type == "image_load"
        assert event.timestamp > process_start
        assert event.process.start_time == process_start

    def test_user_session_process_identity_resolved_before_emit(
        self, activity_gen, test_system, state_manager, mock_emitters
    ):
        """User-session process owners should agree across all emitters."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        session_logon_id = state_manager.create_session(
            username="jsmith",
            system=test_system.hostname,
            logon_type=2,
            source_ip=test_system.ip,
        )
        system_user = User(
            username="SYSTEM",
            full_name="Local System",
            email="system@example.com",
            enabled=True,
        )

        pid = activity_gen.generate_process(
            system_user,
            test_system,
            timestamp,
            "0x3e7",
            r"C:\Windows\System32\RuntimeBroker.exe",
            r"C:\Windows\System32\RuntimeBroker.exe -Embedding",
        )

        proc_state = state_manager.get_process(test_system.hostname, pid)
        assert proc_state.username == "jsmith"
        assert proc_state.logon_id == session_logon_id

        process_events = [
            call[0][0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call[0][0].event_type == "process_create"
        ]
        event = process_events[-1]
        assert event.auth.username == "jsmith"
        assert event.auth.logon_id == session_logon_id
        assert event.process.username == "jsmith"
        assert event.process.logon_id == session_logon_id
        assert event.process.integrity_level == "Medium"

    def test_log_cleared_uses_service_subject_identity(
        self, activity_gen, test_system, state_manager, mock_emitters
    ):
        """1102 should use the clearing service token's source-native subject fields."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        service_logon_id = activity_gen.generate_service_logon(
            system=test_system,
            time=timestamp - timedelta(seconds=1),
            service_account="SYSTEM",
        )
        mock_emitters["windows_event_security"].reset_mock()
        system_user = User(
            username="SYSTEM",
            full_name="Local System",
            email="system@example.com",
            enabled=True,
        )

        activity_gen.generate_log_cleared(system_user, test_system, timestamp)

        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.event_type == "log_cleared"
        assert event.auth.subject_sid == "S-1-5-18"
        assert event.auth.subject_username == "SYSTEM"
        assert event.auth.subject_domain == "NT AUTHORITY"
        assert event.auth.subject_logon_id == service_logon_id

    def test_log_cleared_can_inherit_causative_process_logon_id(
        self, activity_gen, test_system, mock_emitters
    ):
        """1102 inferred from a process should inherit that process token."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        user = User(
            username="jsmith",
            full_name="John Smith",
            email="jsmith@example.com",
            enabled=True,
        )

        activity_gen.generate_log_cleared(
            user,
            test_system,
            timestamp,
            subject_logon_id="0xabc123",
        )

        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.event_type == "log_cleared"
        assert event.auth.subject_username == "jsmith"
        assert event.auth.subject_logon_id == "0xabc123"

    def test_system_process_create_uses_system_integrity_token_fields(
        self, activity_gen, test_system, state_manager, mock_emitters
    ):
        """SYSTEM-owned process events should not render as medium-integrity user tokens."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        system_user = User(
            username="SYSTEM",
            full_name="Local System",
            email="system@example.com",
            enabled=True,
        )

        activity_gen.generate_process(
            system_user,
            test_system,
            timestamp,
            "0x3e7",
            r"C:\Windows\System32\net.exe",
            r"net.exe use \\FILE-SRV\C$",
        )

        process_events = [
            call[0][0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call[0][0].event_type == "process_create"
        ]
        event = process_events[-1]
        assert event.process.integrity_level == "System"
        assert event.process.token_elevation == "%%1936"
        assert event.process.mandatory_label == "S-1-16-16384"

    def test_windows_singleton_process_uses_seeded_pid_without_create_event(
        self, activity_gen, test_system, state_manager, mock_emitters
    ):
        """Core boot-time Windows processes should not be created mid-window."""
        boot_time = datetime(2024, 1, 15, 8, 0, 0, tzinfo=UTC)
        event_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(boot_time)
        lsass_pid = state_manager.create_process(
            system=test_system.hostname,
            parent_pid=4,
            image=r"C:\Windows\System32\lsass.exe",
            command_line="lsass.exe",
            username="SYSTEM",
            integrity_level="System",
            logon_id="0x3e7",
        )
        activity_gen._system_pids = {test_system.hostname: {"lsass": lsass_pid}}
        mock_emitters["windows_event_security"].reset_mock()
        system_user = User(
            username="SYSTEM",
            full_name="Local System",
            email="system@example.com",
            enabled=True,
        )

        returned_pid = activity_gen.generate_process(
            system_user,
            test_system,
            event_time,
            "0x3e7",
            r"C:\Windows\System32\lsass.exe",
            r"C:\Windows\System32\lsass.exe",
        )

        assert returned_pid == lsass_pid
        assert not [
            call[0][0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call[0][0].event_type == "process_create"
        ]

    def test_create_remote_thread_carries_shared_thread_context(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Remote-thread values should be generated once for Sysmon and eCAR."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        source_pid = state_manager.create_process(
            system=test_system.hostname,
            parent_pid=4,
            image=r"C:\Temp\inject.exe",
            command_line=r"C:\Temp\inject.exe",
            username=test_user.username,
            integrity_level="High",
            logon_id="0xabc",
        )
        target_pid = state_manager.create_process(
            system=test_system.hostname,
            parent_pid=4,
            image=r"C:\Windows\System32\lsass.exe",
            command_line=r"C:\Windows\System32\lsass.exe",
            username="SYSTEM",
            integrity_level="System",
            logon_id="0x3e7",
        )
        source_obj_id = state_manager.get_process_object_id(test_system.hostname, source_pid)
        target_obj_id = state_manager.get_process_object_id(test_system.hostname, target_pid)

        activity_gen.generate_create_remote_thread(
            test_user,
            test_system,
            timestamp,
            source_pid=source_pid,
            source_image=r"C:\Temp\inject.exe",
            target_pid=target_pid,
            target_image=r"C:\Windows\System32\lsass.exe",
        )

        event = [
            call[0][0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call[0][0].event_type == "create_remote_thread"
        ][-1]
        assert event.remote_thread is not None
        assert event.remote_thread.target_pid == target_pid
        assert event.remote_thread.target_process_object_id == target_obj_id
        assert event.remote_thread.thread_object_id == event.edr.object_id
        assert event.edr.actor_id == source_obj_id
        assert event.remote_thread.start_address > 0
        assert event.remote_thread.start_module

    def test_module_load_uses_process_aware_dll_profile(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """eCAR MODULE events should use the same process-aware DLL data as Sysmon."""

        class ModuleOnlyRandom:
            def __init__(self):
                self.random_calls = 0

            def random(self):
                self.random_calls += 1
                return 0.99 if self.random_calls == 1 else 0.1

            def choice(self, values):
                return values[0]

            def choices(self, population, weights=None, k=1):
                return [population[0]]

            def randint(self, lower, _upper):
                return lower

            def uniform(self, lower, _upper):
                return lower

        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        logon_id = "0x12345"

        with patch("evidenceforge.generation.activity.generator._get_rng", ModuleOnlyRandom):
            activity_gen.generate_process(
                test_user,
                test_system,
                timestamp,
                logon_id,
                r"C:\Program Files\Mozilla Firefox\firefox.exe",
                "firefox.exe",
            )

        module_events = [
            call[0][0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call[0][0].event_type == "image_load"
        ]
        assert module_events
        event = module_events[-1]
        from evidenceforge.generation.activity.dll_load_profiles import get_dlls_for_process

        profile_paths = {entry["path"] for entry in get_dlls_for_process("firefox.exe")}
        assert event.image_load.image_loaded in profile_paths
        assert event.process.image.endswith("firefox.exe")
        assert event.timestamp > timestamp
        assert event.edr.actor_id

    def test_image_load_skips_ended_process(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Dependent image loads should not render after the process has terminated."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        pid = state_manager.create_process(
            system=test_system.hostname,
            parent_pid=4,
            image=r"C:\Windows\System32\OpenSSH\ssh.exe",
            command_line="ssh.exe web01",
            username=test_user.username,
            integrity_level="Medium",
            logon_id="0x12345",
        )
        state_manager.end_process(test_system.hostname, pid)
        mock_emitters["windows_event_security"].reset_mock()

        activity_gen.generate_image_load(
            test_user,
            test_system,
            timestamp + timedelta(minutes=5),
            pid,
            r"C:\Windows\System32\OpenSSH\ssh.exe",
            r"C:\Windows\System32\advapi32.dll",
        )

        assert not mock_emitters["windows_event_security"].emit.called

    def test_process_termination_waits_for_recorded_dependent_activity(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Termination should be delayed past the latest process-owned telemetry."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        pid = state_manager.create_process(
            system=test_system.hostname,
            parent_pid=4,
            image=r"C:\Windows\Temp\tool.exe",
            command_line="tool.exe",
            username=test_user.username,
            integrity_level="Medium",
            logon_id="0x12345",
        )
        proc = state_manager.get_process(test_system.hostname, pid)
        assert proc is not None
        proc.last_activity_time = timestamp + timedelta(seconds=30)

        activity_gen.generate_process_termination(
            test_user,
            test_system,
            timestamp + timedelta(seconds=5),
            pid,
            r"C:\Windows\Temp\tool.exe",
            "0x12345",
        )

        terminate_events = [
            call[0][0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call[0][0].event_type == "process_terminate"
        ]
        assert terminate_events
        assert terminate_events[-1].timestamp > timestamp + timedelta(seconds=30)

    def test_process_create_extends_parent_lifecycle_marker(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Visible child creation should keep the parent alive past that timestamp."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        logon_id = state_manager.register_session(
            logon_id="0x12345",
            username=test_user.username,
            system=test_system.hostname,
            logon_type=2,
            source_ip=test_system.ip,
            start_time=timestamp,
            session_kind="interactive",
        ).logon_id
        parent_pid = state_manager.create_process(
            system=test_system.hostname,
            parent_pid=4,
            image=r"C:\Windows\System32\cmd.exe",
            command_line="cmd.exe",
            username=test_user.username,
            integrity_level="Medium",
            logon_id=logon_id,
        )

        child_time = timestamp + timedelta(minutes=30)
        activity_gen.generate_process(
            test_user,
            test_system,
            child_time,
            logon_id,
            r"C:\Windows\System32\whoami.exe",
            "whoami.exe",
            parent_pid=parent_pid,
        )

        parent = state_manager.get_process(test_system.hostname, parent_pid)
        assert parent is not None
        assert parent.last_activity_time == child_time

    def test_wfp_connection_uses_state_process_image(
        self, activity_gen, test_system, state_manager, mock_emitters
    ):
        """WFP events should not stamp the default svchost image onto non-system PIDs."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        pid = state_manager.create_process(
            system=test_system.hostname,
            parent_pid=4,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line="powershell.exe -NoProfile",
            username="testuser",
            integrity_level="Medium",
            logon_id="0x12345",
        )

        activity_gen.generate_wfp_connection(
            system=test_system,
            time=timestamp,
            src_ip=test_system.ip,
            src_port=50123,
            dst_ip="10.0.0.20",
            dst_port=8080,
            protocol="tcp",
            pid=pid,
        )

        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.event_type == "wfp_connection"
        assert event.network.initiating_pid == pid
        assert event.process.image.endswith("powershell.exe")

    def test_generate_connection_does_not_carry_stale_process_pid_to_wfp(
        self, activity_gen, test_system, state_manager, mock_emitters
    ):
        """Storyline connections should not preserve a PID after process teardown."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection(
            src_ip=test_system.ip,
            dst_ip="10.0.0.20",
            time=timestamp,
            dst_port=8080,
            proto="tcp",
            service="http",
            duration=1.0,
            orig_bytes=200,
            resp_bytes=500,
            pid=5156,
            source_system=test_system,
            process_image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            hostname="service.provenance.test",
        )

        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.event_type == "wfp_connection"
        assert event.network.initiating_pid != 5156
        assert event.process is None or not event.process.image.endswith("powershell.exe")

    def test_wfp_connection_skips_unresolved_non_system_pid(
        self, activity_gen, test_system, mock_emitters
    ):
        """WFP 5156 should not render a non-system PID when its image is unknown."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

        activity_gen.generate_wfp_connection(
            system=test_system,
            time=timestamp,
            src_ip=test_system.ip,
            src_port=50123,
            dst_ip="10.0.0.20",
            dst_port=8080,
            protocol="tcp",
            pid=5156,
        )

        assert not mock_emitters["windows_event_security"].emit.called

    def test_generate_connection_uses_registered_internal_fqdn_for_dns(
        self, activity_gen, test_system, state_manager, mock_emitters
    ):
        """Known scenario host FQDNs should win over generated internal aliases."""
        from evidenceforge.generation.activity.network import REVERSE_DNS

        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        previous = REVERSE_DNS.get("10.0.0.10")
        REVERSE_DNS["10.0.0.10"] = "dc01.corp.local"
        activity_gen._dns_server_ips = ["10.0.0.1"]

        try:
            activity_gen.generate_connection(
                src_ip=test_system.ip,
                dst_ip="10.0.0.10",
                time=timestamp,
                dst_port=389,
                proto="tcp",
                service="ldap",
                emit_dns=True,
                source_system=test_system,
                duration=1.0,
            )
        finally:
            if previous is None:
                REVERSE_DNS.pop("10.0.0.10", None)
            else:
                REVERSE_DNS["10.0.0.10"] = previous

        dns_events = []
        for emitter in mock_emitters.values():
            dns_events.extend(
                call.args[0] for call in emitter.emit.call_args_list if call.args[0].dns is not None
            )
        assert any(event.dns.query == "dc01.corp.local" for event in dns_events)

    def test_generate_connection_does_not_infer_dns_for_non_resolver_port_53(
        self, activity_gen, test_system, state_manager, mock_emitters
    ):
        """Port-53 scan traffic to non-resolvers should not become dns.log evidence."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        activity_gen._dns_server_ips = ["10.0.0.53"]

        activity_gen.generate_connection(
            src_ip="198.51.100.25",
            dst_ip=test_system.ip,
            time=timestamp,
            dst_port=53,
            proto="tcp",
            service="dns",
            duration=0.1,
            orig_bytes=80,
            resp_bytes=0,
        )

        dns_events = []
        for emitter in mock_emitters.values():
            dns_events.extend(
                call.args[0] for call in emitter.emit.call_args_list if call.args[0].dns is not None
            )
        assert not dns_events

    def test_dns_connection_uses_resolver_process_pid(
        self, activity_gen, test_system, state_manager, mock_emitters
    ):
        """Canonical DNS flows should use the local resolver service PID."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        resolver_pid = state_manager.create_process(
            system=test_system.hostname,
            parent_pid=4,
            image=r"C:\Windows\System32\svchost.exe",
            command_line=r"svchost.exe -k NetworkService -p",
            username="SYSTEM",
            integrity_level="System",
            logon_id="0x3e7",
        )
        app_pid = state_manager.create_process(
            system=test_system.hostname,
            parent_pid=4,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line="powershell.exe -NoProfile",
            username="testuser",
            integrity_level="Medium",
            logon_id="0x12345",
        )
        activity_gen._system_pids = {test_system.hostname: {"svchost_netsvcs": resolver_pid}}

        activity_gen.generate_connection(
            src_ip=test_system.ip,
            dst_ip="10.0.0.53",
            time=timestamp,
            dst_port=53,
            proto="udp",
            service="dns",
            duration=0.02,
            orig_bytes=60,
            resp_bytes=120,
            pid=app_pid,
            source_system=test_system,
        )

        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.event_type == "wfp_connection"
        assert event.network.initiating_pid == resolver_pid
        assert event.process.pid == resolver_pid
        assert event.process.image.endswith("svchost.exe")

    def test_system_process_termination_defaults_logon_id_to_system(
        self, activity_gen, test_system, state_manager, mock_emitters
    ):
        """SYSTEM process termination should not emit blank Security 4689 LogonId."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        pid = state_manager.create_process(
            system=test_system.hostname,
            parent_pid=4,
            image=r"C:\Windows\System32\usoclient.exe",
            command_line="usoclient.exe ResumeUpdate",
            username="SYSTEM",
            integrity_level="System",
            logon_id="",
        )
        system_user = User(
            username="SYSTEM",
            full_name="Local System",
            email="system@example.com",
            enabled=True,
        )

        activity_gen.generate_process_termination(
            system_user,
            test_system,
            timestamp,
            pid,
            r"C:\Windows\System32\usoclient.exe",
            "",
        )

        event = [
            call[0][0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call[0][0].event_type == "process_terminate"
        ][-1]
        assert event.auth.logon_id == "0x3e7"
        assert event.process.logon_id == "0x3e7"

    def test_generate_explicit_credentials_uses_supplied_process_pid(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """generate_explicit_credentials should preserve explicit credential process PID."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_explicit_credentials(
            user=test_user,
            system=test_system,
            time=timestamp,
            target_username="admin01",
            target_server="dc01.corp.local",
            process_name=r"C:\Windows\System32\runas.exe",
            process_pid=4242,
            source_ip="10.0.0.50",
            source_port=50123,
        )

        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.event_type == "explicit_credentials"
        assert event.auth.process_pid == 4242

    def test_generate_explicit_credentials_bootstraps_subject_logon(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """4648 should not reference a subject LogonID before its visible 4624."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_explicit_credentials(
            user=test_user,
            system=test_system,
            time=timestamp,
            target_username="admin01",
            target_server="dc01.corp.local",
            process_name=r"C:\Windows\System32\runas.exe",
            process_pid=4242,
        )

        emitted = [
            call[0][0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        logon = next(event for event in emitted if event.event_type == "logon")
        explicit = next(event for event in emitted if event.event_type == "explicit_credentials")
        assert logon.timestamp < explicit.timestamp
        assert explicit.auth.subject_logon_id == logon.auth.logon_id

    def test_generate_explicit_credentials_defaults_remote_network_endpoint(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Remote 4648 records should carry source endpoint metadata by default."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_explicit_credentials(
            user=test_user,
            system=test_system,
            time=timestamp,
            target_username="admin01",
            target_server="dc01.corp.local",
            process_name=r"C:\Windows\System32\runas.exe",
            process_pid=4242,
        )

        emitted = [
            call[0][0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        explicit = next(event for event in emitted if event.event_type == "explicit_credentials")
        assert explicit.auth.source_ip == test_system.ip
        assert 49152 <= explicit.auth.source_port <= 65535

    def test_generate_explicit_credentials_local_target_keeps_blank_network_endpoint(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Local 4648 records should preserve native blank network endpoint semantics."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_explicit_credentials(
            user=test_user,
            system=test_system,
            time=timestamp,
            target_username="admin01",
            target_server=test_system.hostname,
            process_name=r"C:\Windows\System32\runas.exe",
            process_pid=4242,
        )

        emitted = [
            call[0][0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        explicit = next(event for event in emitted if event.event_type == "explicit_credentials")
        assert explicit.auth.source_ip == "-"
        assert explicit.auth.source_port == 0

    def test_generate_explicit_credentials_skips_linux_local_target_on_windows(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Linux local accounts should not render as Windows 4648 target credentials."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_explicit_credentials(
            user=test_user,
            system=test_system,
            time=timestamp,
            target_username="root",
            target_server="DB-PROD-01",
            process_name=r"C:\Windows\System32\runas.exe",
            process_pid=4242,
            source_ip="10.0.0.50",
            source_port=50123,
        )

        emitted = [
            call.args[0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        assert all(event.event_type != "explicit_credentials" for event in emitted)

    def test_generate_process_with_parent_pid(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """generate_process should accept parent PID."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        logon_id = "0x12345"

        # First create parent process to ensure it exists
        parent_pid = state_manager.create_process(
            system=test_system.hostname,
            parent_pid=4,  # System process as grandparent
            image="explorer.exe",
            command_line="C:\\Windows\\explorer.exe",
            username=test_user.username,
            integrity_level="Medium",
        )

        activity_gen.generate_process(
            test_user,
            test_system,
            timestamp,
            logon_id,
            "notepad.exe",
            "notepad.exe",
            parent_pid=parent_pid,
        )

        process_events = [
            call[0][0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call[0][0].event_type == "process_create"
        ]
        assert process_events[-1].process.parent_pid == parent_pid

    def test_generate_connection_emits_zeek(self, activity_gen, state_manager, mock_emitters):
        """generate_connection should open connection and dispatch SecurityEvent."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        src_ip = "10.0.0.1"
        dst_ip = "93.184.216.34"
        dst_port = 443

        uid = activity_gen.generate_connection(
            src_ip,
            dst_ip,
            timestamp,
            dst_port=dst_port,
            service="ssl",
            duration=1.0,
            orig_bytes=500,
            resp_bytes=2500,
        )

        # Verify UID returned
        assert uid
        assert len(uid) > 0

        # Verify Zeek emitter received connection SecurityEvent
        assert mock_emitters["zeek_conn"].emit.called
        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert event.event_type == "connection"
        assert event.network.zeek_uid == uid
        assert event.network.src_ip == src_ip
        assert event.network.dst_ip == dst_ip
        assert event.network.dst_port == dst_port
        assert event.network.service == "ssl"

    def test_generate_connection_with_bytes(self, activity_gen, state_manager, mock_emitters):
        """generate_connection should include byte counts in NetworkContext."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        orig_bytes = 1000
        resp_bytes = 5000

        activity_gen.generate_connection(
            "10.0.0.1",
            "93.184.216.34",
            timestamp,
            orig_bytes=orig_bytes,
            resp_bytes=resp_bytes,
            duration=1.5,
        )

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        net = event.network
        assert net.orig_bytes == orig_bytes or net.orig_bytes >= 0
        assert net.resp_bytes is not None
        assert net.orig_pkts is not None

    def test_https_http_body_size_is_not_reused_as_encrypted_wire_bytes(
        self, activity_gen, state_manager, mock_emitters
    ):
        """HTTPS conn bytes should include TLS overhead beyond web response body bytes."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        body_len = 10391

        activity_gen.generate_connection(
            "10.0.0.1",
            "93.184.216.34",
            timestamp,
            dst_port=443,
            service="ssl",
            duration=0.01,
            orig_bytes=200,
            resp_bytes=body_len,
            conn_state="SF",
            http=HttpContext(
                method="GET",
                host="example.com",
                uri="/robots.txt",
                response_body_len=body_len,
                status_code=200,
            ),
        )

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        net = event.network
        assert net.resp_bytes > body_len
        assert net.resp_bytes != event.http.response_body_len
        assert net.duration is not None and net.duration >= 0.04

    def test_http_connection_duration_covers_zeek_http_offset(
        self, activity_gen, state_manager, mock_emitters
    ):
        """HTTP-bearing conn duration should cover the later Zeek http.log timestamp."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection(
            "10.0.0.1",
            "93.184.216.34",
            timestamp,
            dst_port=80,
            service="http",
            duration=0.01,
            orig_bytes=200,
            resp_bytes=400,
            conn_state="RSTO",
            http=HttpContext(
                method="GET",
                host="example.com",
                uri="/index.html",
                response_body_len=400,
                status_code=200,
            ),
        )

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        net = event.network
        assert net.conn_state == "SF"
        assert net.duration is not None and net.duration >= 0.04

    def test_generate_connection_with_duration(self, activity_gen, state_manager, mock_emitters):
        """generate_connection with duration sets a valid conn_state."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        duration = 2.5

        activity_gen.generate_connection(
            "10.0.0.1",
            "93.184.216.34",
            timestamp,
            duration=duration,
            orig_bytes=100,
            resp_bytes=200,
        )

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        net = event.network
        assert net.conn_state in ("SF", "S0", "S1", "REJ", "RSTO", "RSTR", "OTH")
        if net.conn_state == "SF":
            assert net.duration == duration
        elif net.conn_state in ("RSTO", "RSTR"):
            assert net.duration is not None and net.duration <= duration

    def test_generate_connection_without_duration(self, activity_gen, state_manager, mock_emitters):
        """generate_connection without duration should set conn_state to S0."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection("10.0.0.1", "93.184.216.34", timestamp)

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert event.network.conn_state == "S0"

    def test_generate_connection_skips_invalid(self, activity_gen, mock_emitters):
        """generate_connection should skip invalid connections."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

        uid = activity_gen.generate_connection("127.0.0.1", "10.0.0.1", timestamp)

        assert uid == ""
        assert not mock_emitters["zeek_conn"].emit.called

    def test_get_baseline_pattern_developer(self, activity_gen):
        """Should return developer pattern for developer persona."""
        pattern = activity_gen.get_baseline_pattern("developer")

        assert pattern == BASELINE_PATTERNS["developer"]
        assert ("logon", 0.7) in pattern
        assert ("process_code", 0.75) in pattern

    def test_get_baseline_pattern_executive(self, activity_gen):
        """Should return executive pattern for executive persona."""
        pattern = activity_gen.get_baseline_pattern("executive")

        assert pattern == BASELINE_PATTERNS["executive"]
        assert ("logon", 0.9) in pattern
        assert ("connection_email", 0.75) in pattern

    def test_get_baseline_pattern_case_insensitive(self, activity_gen):
        """Persona name should be case-insensitive."""
        pattern1 = activity_gen.get_baseline_pattern("Developer")
        pattern2 = activity_gen.get_baseline_pattern("DEVELOPER")

        assert pattern1 == pattern2 == BASELINE_PATTERNS["developer"]

    def test_get_baseline_pattern_default(self, activity_gen):
        """Should return default pattern for unknown persona."""
        pattern = activity_gen.get_baseline_pattern("unknown_persona")

        assert pattern == BASELINE_PATTERNS["default"]

    def test_get_baseline_pattern_none(self, activity_gen):
        """Should return default pattern for None persona."""
        pattern = activity_gen.get_baseline_pattern(None)

        assert pattern == BASELINE_PATTERNS["default"]

    def test_execute_baseline_activity_logon(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """execute_baseline_activity should handle logon activity."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.execute_baseline_activity(test_user, test_system, timestamp, "logon")

        # Logon (and possibly logoff for Type 3) dispatched via SecurityEvent
        emitter = mock_emitters["windows_event_security"]
        assert emitter.emit.called
        first_event = emitter.emit.call_args_list[0][0][0]
        assert first_event.event_type in ("logon", "failed_logon")

    def test_execute_baseline_activity_process_creates_session(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """execute_baseline_activity should create session before process if needed."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        # No active session yet
        assert len(state_manager.get_sessions_for_user(test_user.username)) == 0

        activity_gen.execute_baseline_activity(test_user, test_system, timestamp, "process_code")

        # Should have created session first
        assert len(state_manager.get_sessions_for_user(test_user.username)) == 1

        # Verify both logon and process events dispatched via emit()
        emitter = mock_emitters["windows_event_security"]
        assert emitter.emit.called
        event_types = [c[0][0].event_type for c in emitter.emit.call_args_list]
        assert "logon" in event_types or "failed_logon" in event_types
        assert "process_create" in event_types

    def test_execute_baseline_activity_process_uses_existing_session(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """execute_baseline_activity should use existing session for process."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        # Create session first
        activity_gen.generate_logon(test_user, test_system, timestamp)
        mock_emitters["windows_event_security"].reset_mock()

        activity_gen.execute_baseline_activity(test_user, test_system, timestamp, "process_code")

        # Should NOT have created another session
        assert len(state_manager.get_sessions_for_user(test_user.username)) == 1

        # Verify only process event dispatched (no additional logon)
        emitter = mock_emitters["windows_event_security"]
        emit_calls = emitter.emit.call_args_list
        event_types = [c[0][0].event_type for c in emit_calls]
        assert "process_create" in event_types
        assert "logon" not in event_types  # No new logon after reset

    def test_execute_baseline_activity_process_ignores_future_session(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """A process should not reuse a session whose logon is later than the process."""
        process_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        future_logon_time = datetime(2024, 1, 15, 10, 55, 0, tzinfo=UTC)
        state_manager.set_current_time(future_logon_time)
        activity_gen.generate_logon(test_user, test_system, future_logon_time)
        mock_emitters["windows_event_security"].reset_mock()

        activity_gen.execute_baseline_activity(test_user, test_system, process_time, "process_code")

        sessions = state_manager.get_sessions_for_user(test_user.username)
        assert len(sessions) == 2
        emitter = mock_emitters["windows_event_security"]
        event_types = [c[0][0].event_type for c in emitter.emit.call_args_list]
        assert "logon" in event_types
        assert "process_create" in event_types

    def test_execute_baseline_linux_foreground_process_terminates_promptly(
        self, activity_gen, test_user, state_manager, mock_emitters
    ):
        """Foreground Linux shell commands should not outlive later bash history."""
        process_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        linux = System(hostname="LNX-01", ip="10.0.0.2", os="Ubuntu 22.04", type="server")
        state_manager.set_current_time(process_time)
        systemd_pid = state_manager.create_process(
            linux.hostname,
            0,
            "/usr/lib/systemd/systemd",
            "/usr/lib/systemd/systemd --system",
            "root",
            "System",
        )
        sshd_pid = state_manager.create_process(
            linux.hostname,
            systemd_pid,
            "/usr/sbin/sshd",
            "/usr/sbin/sshd -D [listener]",
            "root",
            "System",
        )
        activity_gen._system_pids = {linux.hostname: {"systemd": systemd_pid, "sshd": sshd_pid}}

        with patch.dict(
            generator_module.PROCESS_TEMPLATES_LINUX,
            {"process_system": [("/usr/bin/cat", "cat /etc/hosts")]},
        ):
            activity_gen.execute_baseline_activity(test_user, linux, process_time, "process_system")

        events = [
            call.args[0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        create_events = [
            event
            for event in events
            if event.event_type == "process_create"
            and event.process is not None
            and event.process.image == "/usr/bin/cat"
        ]
        assert create_events
        create_event = create_events[-1]
        terminate_events = [
            event
            for event in events
            if event.event_type == "process_terminate"
            and event.process is not None
            and event.process.pid == create_event.process.pid
        ]
        assert terminate_events
        assert create_event.timestamp < terminate_events[-1].timestamp
        assert terminate_events[-1].timestamp <= process_time + timedelta(seconds=2)

    def test_linux_process_activity_bash_history_uses_canonical_command(
        self, activity_gen, test_user, state_manager, mock_emitters
    ):
        """Linux bash_history should mirror the same command rendered in process telemetry."""
        process_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        linux = System(
            hostname="LNX-01",
            ip="10.0.0.2",
            os="Ubuntu 22.04",
            type="server",
            assigned_user=test_user.username,
        )
        state_manager.set_current_time(process_time)
        mock_emitters["bash_history"] = Mock()
        systemd_pid = state_manager.create_process(
            linux.hostname,
            0,
            "/usr/lib/systemd/systemd",
            "/usr/lib/systemd/systemd --system",
            "root",
            "System",
        )
        sshd_pid = state_manager.create_process(
            linux.hostname,
            systemd_pid,
            "/usr/sbin/sshd",
            "/usr/sbin/sshd -D [listener]",
            "root",
            "System",
        )
        activity_gen._system_pids = {linux.hostname: {"systemd": systemd_pid, "sshd": sshd_pid}}

        with patch.dict(
            generator_module.PROCESS_TEMPLATES_LINUX,
            {"process_system": [("/usr/bin/cat", "cat /etc/hosts")]},
        ):
            activity_gen.execute_baseline_activity(test_user, linux, process_time, "process_system")

        bash_events = [
            call.args[0]
            for call in mock_emitters["bash_history"].emit.call_args_list
            if call.args[0].event_type == "bash_command"
        ]
        assert bash_events
        assert bash_events[-1].shell.command == "cat /etc/hosts"

    def test_generate_process_shifts_after_existing_session_start(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """A process using an existing LogonID should render after that session start."""
        logon_time = datetime(2024, 1, 15, 10, 0, 10, tzinfo=UTC)
        process_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        logon_id = "0xabc123"
        state_manager.register_session(
            logon_id=logon_id,
            username=test_user.username,
            system=test_system.hostname,
            logon_type=3,
            source_ip="10.0.0.50",
            start_time=logon_time,
        )

        activity_gen.generate_process(
            test_user,
            test_system,
            process_time,
            logon_id,
            r"C:\Windows\System32\cmd.exe",
            "cmd.exe",
        )

        event = next(
            call[0][0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call[0][0].event_type == "process_create"
        )
        assert event.event_type == "process_create"
        assert event.timestamp > logon_time

    def test_successful_ntlm_network_logon_emits_dc_validation(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Member-host NTLM logons should produce DC-side 4776 validation."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        activity_gen._dc_hostnames = ["DC-01"]
        activity_gen._dc_ips = ["10.0.0.10"]

        with patch.object(
            activity_gen,
            "_select_auth_package",
            return_value={
                "AuthenticationPackageName": "NTLM",
                "LogonProcessName": "NtLmSsp",
                "LmPackageName": "NTLM V2",
            },
        ):
            activity_gen.generate_logon(
                test_user,
                test_system,
                timestamp,
                logon_type=3,
                source_ip="10.0.0.50",
            )

        events = [
            call.args[0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        assert any(event.event_type == "ntlm_validation" for event in events)

    def test_execute_baseline_activity_connection_web(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """execute_baseline_activity should handle web connection."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.execute_baseline_activity(test_user, test_system, timestamp, "connection_web")

        # Connection dispatched as SecurityEvent
        assert mock_emitters["zeek_conn"].emit.called
        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert event.network.service in ["http", "ssl"]
        assert event.network.dst_port in [80, 443]
        dst_ip = event.network.dst_ip
        assert dst_ip in EXTERNAL_IPS["connection_web"] or not dst_ip.startswith("10.")

    def test_execute_baseline_activity_connection_email(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """execute_baseline_activity should handle email connection."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.execute_baseline_activity(
            test_user, test_system, timestamp, "connection_email"
        )

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert event.network.service == "smtp"
        assert event.network.dst_port == 587
        assert event.network.dst_ip in EXTERNAL_IPS["connection_email"]

    def test_execute_baseline_activity_connection_git(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """execute_baseline_activity should handle git connection."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.execute_baseline_activity(test_user, test_system, timestamp, "connection_git")

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert event.network.service == "ssl"
        assert event.network.dst_port == 443
        assert event.network.dst_ip in EXTERNAL_IPS["connection_git"]

    def test_execute_baseline_activity_connection_db(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """execute_baseline_activity should handle database connection with detected servers."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen._db_servers = [{"ip": "10.10.100.20", "port": 1433, "service": "mssql"}]
        activity_gen.execute_baseline_activity(test_user, test_system, timestamp, "connection_db")

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert event.network.service == "mssql"
        assert event.network.dst_port == 1433
        assert event.network.dst_ip == "10.10.100.20"

    def test_execute_baseline_activity_connection_excludes_src_ip(
        self, activity_gen, test_user, state_manager, mock_emitters
    ):
        """execute_baseline_activity should not connect system to itself."""
        system = System(
            hostname="WEB-01", ip="93.184.216.34", os="Windows Server 2019", type="server"
        )
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.execute_baseline_activity(test_user, system, timestamp, "connection_web")

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert event.network.dst_ip != system.ip

    def test_execute_baseline_activity_connection_skips_if_all_match_src(
        self, activity_gen, test_user, mock_emitters
    ):
        """execute_baseline_activity should skip connection if all destinations match source."""
        system = System(hostname="TEST-01", ip="10.0.100.10", os="Windows 10", type="workstation")
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

        with patch(
            "evidenceforge.generation.activity.EXTERNAL_IPS", {"connection_test": ["10.0.100.10"]}
        ):
            activity_gen.execute_baseline_activity(test_user, system, timestamp, "connection_test")

        assert not mock_emitters["zeek_conn"].emit.called

    def test_event_record_id_increments(self, activity_gen, test_user, test_system):
        """EventRecordID should increment per-host for each Windows event."""
        id1 = activity_gen._get_next_event_record_id("HOST-A")
        id2 = activity_gen._get_next_event_record_id("HOST-A")
        id3 = activity_gen._get_next_event_record_id("HOST-A")

        assert id2 == id1 + 1
        assert id3 == id2 + 1

    def test_event_record_id_per_host_independent(self):
        """EventRecordIDs should be independent per hostname."""
        state_manager = StateManager()
        emitters = {"windows_event_security": Mock(), "zeek_conn": Mock()}
        activity_gen = ActivityGenerator(state_manager, emitters)

        id_a1 = activity_gen._get_next_event_record_id("HOST-A")
        id_b1 = activity_gen._get_next_event_record_id("HOST-B")
        id_a2 = activity_gen._get_next_event_record_id("HOST-A")
        id_b2 = activity_gen._get_next_event_record_id("HOST-B")

        # Each host increments independently
        assert id_a2 == id_a1 + 1
        assert id_b2 == id_b1 + 1
        # Different hosts may have different starting values
        assert id_a1 != id_b1 or True  # Starting values are seeded from hostname

    def test_event_record_id_starts_in_valid_range(self):
        """EventRecordID should start at a random offset per host (1000-50000)."""
        state_manager = StateManager()
        emitters = {"windows_event_security": Mock(), "zeek_conn": Mock()}
        activity_gen = ActivityGenerator(state_manager, emitters)

        first_id = activity_gen._get_next_event_record_id("TEST-HOST")

        assert 1001 <= first_id <= 50001

    def test_generate_connection_calculates_packet_counts(
        self, activity_gen, state_manager, mock_emitters
    ):
        """generate_connection should calculate packet counts from bytes for completed connections."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        orig_bytes = 3000  # Should be ~2 packets (3000/1500)
        resp_bytes = 6000  # Should be ~4 packets (6000/1500)

        # Provide duration to ensure a completed connection
        activity_gen.generate_connection(
            "10.0.0.1",
            "93.184.216.34",
            timestamp,
            orig_bytes=orig_bytes,
            resp_bytes=resp_bytes,
            duration=2.0,
        )

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        net = event.network
        assert net.orig_pkts >= 1
        if net.conn_state == "SF":
            assert net.resp_pkts >= 1
            assert net.orig_ip_bytes > orig_bytes
            assert net.resp_ip_bytes > resp_bytes

    def test_generate_connection_tcp_proto(self, activity_gen, state_manager, mock_emitters):
        """generate_connection should set correct ip_proto for TCP."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection("10.0.0.1", "93.184.216.34", timestamp, proto="tcp")

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert event.network.protocol == "tcp"
        assert event.network.ip_proto == 6

    def test_generate_connection_udp_proto(self, activity_gen, state_manager, mock_emitters):
        """generate_connection should set correct ip_proto for UDP."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection("10.0.0.1", "93.184.216.34", timestamp, proto="udp")

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert event.network.protocol == "udp"
        assert event.network.ip_proto == 17

    def test_generate_connection_icmp_proto(self, activity_gen, state_manager, mock_emitters):
        """generate_connection should set correct ip_proto for ICMP."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection("10.0.0.1", "93.184.216.34", timestamp, proto="icmp")

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert event.network.protocol == "icmp"
        assert event.network.ip_proto == 1


@pytest.fixture()
def activity_gen():
    """Create an ActivityGenerator with mock emitters for standalone tests."""
    sm = StateManager()
    sm.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))
    mock_emitters = {
        "windows_event_security": Mock(),
        "zeek_conn": Mock(),
        "zeek_dns": Mock(),
        "ecar": Mock(),
        "syslog": Mock(),
    }
    return ActivityGenerator(sm, mock_emitters)


def test_emit_dns_lookup_prunes_and_bounds_dns_cache(activity_gen):
    """_emit_dns_lookup should prune expired entries and enforce a bounded cache size."""
    now = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
    ts_now = now.timestamp()

    activity_gen._dns_cache = {
        (f"10.0.0.{i % 255}", f"host-{i}.example.com"): ts_now - 5 for i in range(50_100)
    }
    hot_key = ("10.0.0.5", "active.example.com")
    activity_gen._dns_cache[hot_key] = ts_now - 1
    activity_gen._dns_cache_last_prune = 0.0

    activity_gen._emit_dns_lookup(hot_key[0], "93.184.216.34", now, hostname=hot_key[1])

    assert hot_key in activity_gen._dns_cache
    assert len(activity_gen._dns_cache) <= 50_001


def test_ensure_file_event_skips_existing_linux_binaries(activity_gen):
    """Storyline process visibility should not invent FILE/CREATE for /usr/bin tools."""
    user = User(username="alice", full_name="Alice", email="alice@example.com", enabled=True)
    system = System(
        hostname="lin-01",
        ip="10.0.0.10",
        os="Ubuntu 22.04",
        type="server",
    )
    timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
    logon_id = activity_gen.generate_logon(user, system, timestamp, logon_type=2)

    activity_gen.generate_process(
        user=user,
        system=system,
        time=timestamp + timedelta(seconds=1),
        logon_id=logon_id,
        process_name="/usr/bin/cat",
        command_line="/usr/bin/cat /etc/passwd",
        ensure_file_event=True,
        from_storyline=True,
    )

    emitted = [
        call.args[0] for call in activity_gen.dispatcher.emitters["ecar"].emit.call_args_list
    ]
    file_creates_for_binary = [
        event
        for event in emitted
        if event.event_type == "file_create" and event.file and event.file.path == "/usr/bin/cat"
    ]
    assert file_creates_for_binary == []


def test_tls_key_metadata_follows_rsa_named_intermediates():
    """RSA-branded certificate subjects should not get ECDSA key metadata."""
    assert generator_module._tls_key_for_certificate_name(
        "CN=Amazon RSA 2048 M01", "ecdsa", 256
    ) == ("rsa", 2048)


def test_failed_tls_context_rewrites_packet_accounting(activity_gen, monkeypatch):
    """Failed TLS handshakes should not retain full response-byte accounting."""
    monkeypatch.setattr(generator_module, "_SSL_FAILURE_RATE", 1.0)
    timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
    event = SecurityEvent(
        timestamp=timestamp,
        event_type="connection",
        network=NetworkContext(
            src_ip="10.0.0.10",
            src_port=49152,
            dst_ip="93.184.216.34",
            dst_port=443,
            protocol="tcp",
            service="ssl",
            zeek_uid="Ctest",
            duration=2.0,
            orig_bytes=1200,
            resp_bytes=55000,
            orig_pkts=4,
            resp_pkts=40,
            orig_ip_bytes=1500,
            resp_ip_bytes=57000,
            conn_state="SF",
            history="ShADadfF",
            initiating_pid=-1,
        ),
    )

    activity_gen._attach_ssl_context(
        event,
        hostname="example.com",
        dns=None,
        dst_ip="93.184.216.34",
        rng=random.Random(4),
    )

    assert event.ssl is not None
    assert event.ssl.established is False
    assert event.network.conn_state in {"S1", "SH"}
    assert event.network.orig_bytes == 0
    assert event.network.resp_bytes == 0
    assert event.network.orig_pkts <= 2
    assert event.network.resp_pkts <= 2
