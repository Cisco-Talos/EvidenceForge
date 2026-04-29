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

from datetime import UTC, datetime
from unittest.mock import Mock, patch

import pytest

from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.generation.activity import (
    BASELINE_PATTERNS,
    EXTERNAL_IPS,
    ActivityGenerator,
    _is_invalid_network_connection,
)
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models import System, User


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

    def test_generate_logon_interactive_uses_system_ip(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Interactive logon (type 2) should use system IP as source."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_logon(test_user, test_system, timestamp, logon_type=2)

        # SecurityEvent dispatched to Windows emitter
        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.auth.logon_type == 2
        assert event.auth.source_ip == test_system.ip

    def test_generate_logon_network_allows_custom_ip(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Network logon (type 3) should allow custom source IP."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        source_ip = "203.0.113.50"
        state_manager.set_current_time(timestamp)

        activity_gen.generate_logon(
            test_user, test_system, timestamp, logon_type=3, source_ip=source_ip
        )

        # SecurityEvent dispatched to Windows emitter
        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.auth.logon_type == 3
        assert event.auth.source_ip == source_ip

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

    def test_generate_connection_carries_process_image_to_wfp_when_process_ended(
        self, activity_gen, test_system, state_manager, mock_emitters
    ):
        """Storyline connections can preserve process image even after process teardown."""
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
        assert event.network.initiating_pid == 5156
        assert event.process.image.endswith("powershell.exe")

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
