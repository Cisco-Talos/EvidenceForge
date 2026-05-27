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

"""Unit tests for Phase 5.2.2: Failed logon generation."""

import random
from datetime import UTC, datetime
from unittest.mock import Mock

import pytest

from evidenceforge.formats.loader import load_format
from evidenceforge.formats.validator import validate_event
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.activity import generator as generator_mod
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
        "syslog": Mock(),
        "ecar": Mock(),
    }


@pytest.fixture
def activity_gen(state_manager, mock_emitters):
    return ActivityGenerator(state_manager, mock_emitters)


@pytest.fixture
def test_user():
    return User(username="alice.smith", full_name="Alice Smith", email="a@t.com", enabled=True)


@pytest.fixture
def win_system():
    return System(hostname="WKS-01", ip="10.0.10.1", os="Windows 10", type="workstation")


@pytest.fixture
def linux_system():
    return System(hostname="LNX-01", ip="10.0.10.2", os="Linux Ubuntu 22.04", type="workstation")


@pytest.fixture
def timestamp():
    return datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)


class TestFailedLogonWindows:
    """Test failed logon event generation on Windows."""

    def test_emits_failed_logon(
        self, activity_gen, test_user, win_system, timestamp, state_manager, mock_emitters
    ):
        state_manager.set_current_time(timestamp)
        activity_gen.generate_failed_logon(test_user, win_system, timestamp)

        assert mock_emitters["windows_event_security"].emit.called
        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.event_type == "failed_logon"
        assert event.auth.username == "alice.smith"
        assert event.auth.failure_status == "0xc000006d"
        assert event.auth.failure_substatus == "0xc000006a"

    def test_enabled_known_user_failed_logon_never_uses_stateful_substatus(
        self, activity_gen, test_user, win_system, timestamp, state_manager, mock_emitters
    ):
        """Enabled known accounts should fail as bad passwords unless state is modeled."""
        state_manager.set_current_time(timestamp)

        for _ in range(50):
            activity_gen.generate_failed_logon(test_user, win_system, timestamp)

        events = [
            call[0][0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call[0][0].event_type == "failed_logon"
        ]
        assert events
        assert {event.auth.failure_substatus for event in events} == {"0xc000006a"}

    def test_disabled_user_failed_logon_uses_disabled_substatus(
        self, activity_gen, win_system, timestamp, state_manager, mock_emitters
    ):
        """Explicitly disabled accounts should render disabled-account failures."""
        state_manager.set_current_time(timestamp)
        disabled_user = User(
            username="svc_old_backup",
            full_name="svc_old_backup",
            email="svc_old_backup@example.com",
            enabled=False,
        )

        activity_gen.generate_failed_logon(disabled_user, win_system, timestamp, logon_type=4)

        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.auth.failure_substatus == "0xc0000072"
        assert event.auth.failure_reason == "%%2307"

    def test_unknown_target_failed_logon_uses_unknown_user_substatus(
        self, activity_gen, test_user, win_system, timestamp, state_manager, mock_emitters
    ):
        """Unknown target accounts should not be rendered as locked or disabled users."""
        state_manager.set_current_time(timestamp)

        activity_gen.generate_failed_logon(
            test_user,
            win_system,
            timestamp,
            target_username="not.a.real.user",
        )

        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.auth.failure_substatus == "0xc0000064"
        assert event.auth.user_sid == "S-1-0-0"

    def test_no_session_created(
        self, activity_gen, test_user, win_system, timestamp, state_manager
    ):
        state_manager.set_current_time(timestamp)
        activity_gen.generate_failed_logon(test_user, win_system, timestamp)

        sessions = state_manager.get_sessions_for_user("alice.smith")
        assert len(sessions) == 0

    def test_subject_is_null_for_failed_logon(
        self, activity_gen, test_user, win_system, timestamp, state_manager, mock_emitters
    ):
        state_manager.set_current_time(timestamp)
        activity_gen.generate_failed_logon(test_user, win_system, timestamp)

        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.auth.subject_sid == "S-1-0-0"
        assert event.auth.subject_username == "-"
        assert event.auth.subject_domain == "-"
        assert event.auth.subject_logon_id == "0x0"


class TestFailedLogonLinux:
    """Test failed logon on Linux."""

    def test_emits_syslog_failed_password(
        self, activity_gen, test_user, linux_system, timestamp, state_manager, mock_emitters
    ):
        state_manager.set_current_time(timestamp)
        activity_gen.generate_failed_logon(
            test_user, linux_system, timestamp, logon_type=3, source_ip="203.0.113.50"
        )

        assert mock_emitters["syslog"].emit.called
        event = mock_emitters["syslog"].emit.call_args[0][0]
        assert event.event_type == "failed_logon"
        assert event.auth.username == "alice.smith"
        assert event.auth.source_ip == "203.0.113.50"

    def test_baseline_linux_logon_does_not_emit_generic_remote_success(
        self,
        activity_gen,
        test_user,
        linux_system,
        timestamp,
        state_manager,
        mock_emitters,
        monkeypatch,
    ):
        """Baseline Linux logon activity should stay local unless the SSH bundle owns it."""
        rng = random.Random(42)
        monkeypatch.setattr(generator_mod, "_get_rng", lambda: rng)
        activity_gen._all_system_ips = [linux_system.ip, "10.0.10.99"]
        state_manager.set_current_time(timestamp)

        activity_gen.execute_baseline_activity(test_user, linux_system, timestamp, "logon")

        ecar_events = [call.args[0] for call in mock_emitters["ecar"].emit.call_args_list]
        logon_events = [
            event for event in ecar_events if event.event_type == "logon" and event.auth is not None
        ]
        assert logon_events
        assert {event.auth.logon_type for event in logon_events} == {2}
        assert {event.auth.source_ip for event in logon_events} == {"-"}
        assert not any(event.event_type == "ssh_session" for event in ecar_events)


class TestFailedLogonEcar:
    """Test eCAR emission for failed logon."""

    def test_emits_ecar_failed_logon(
        self, activity_gen, test_user, win_system, timestamp, state_manager, mock_emitters
    ):
        state_manager.set_current_time(timestamp)
        activity_gen.generate_failed_logon(test_user, win_system, timestamp)

        assert mock_emitters["ecar"].emit.called
        event = mock_emitters["ecar"].emit.call_args[0][0]
        assert event.event_type == "failed_logon"
        assert event.auth.result == "failure"


class TestFailedLogonFormatValidation:
    """Test that 4625 events pass format validation with all fields."""

    def test_4625_with_all_fields_validates(self):
        """A 4625 event with TransmittedServices, LmPackageName, KeyLength, ProcessId, ProcessName should validate."""
        fmt_def = load_format("windows_event_security")
        event = {
            "EventID": 4625,
            "TimeCreated": "2024-03-15T10:00:00Z",
            "Computer": "WKS-01.corp.local",
            "Channel": "Security",
            "Level": 0,
            "EventRecordID": 1001,
            "ExecutionProcessID": 4,
            "ExecutionThreadID": 64,
            "SubjectUserSid": "S-1-5-18",
            "SubjectUserName": "-",
            "SubjectDomainName": "-",
            "SubjectLogonId": "0x0",
            "TargetUserSid": "S-1-0-0",
            "TargetUserName": "alice.smith",
            "TargetDomainName": "CORP",
            "Status": "0xc000006d",
            "SubStatus": "0xc0000064",
            "FailureReason": "%%2313",
            "LogonType": 3,
            "LogonProcessName": "NtLmSsp",
            "AuthenticationPackageName": "NTLM",
            "WorkstationName": "WKS-02",
            "IpAddress": "10.0.10.2",
            "IpPort": 49152,
            "TransmittedServices": "-",
            "LmPackageName": "-",
            "KeyLength": 0,
            "ProcessId": "0x0",
            "ProcessName": "-",
        }
        result = validate_event(fmt_def, event, variant_name="failed_logon")
        assert result.valid, f"Validation errors: {result.errors}"


class TestFailedLogonRate:
    """Test that baseline activity includes ~10% failed logons."""

    def test_baseline_logon_failure_rate(self, state_manager, timestamp):
        """Over many logon attempts, ~10% should fail."""
        emitters = {"windows_event_security": Mock(), "zeek_conn": Mock()}
        gen = ActivityGenerator(state_manager, emitters)
        user = User(username="test", full_name="Test", email="t@t.com", enabled=True)
        system = System(hostname="W1", ip="10.0.0.1", os="Windows 10", type="workstation")
        state_manager.set_current_time(timestamp)

        total = 0
        failed = 0
        for _ in range(200):
            emitters["windows_event_security"].reset_mock()
            gen.execute_baseline_activity(user, system, timestamp, "logon")
            emitter = emitters["windows_event_security"]
            # Both successful and failed logons now dispatched via emit()
            if emitter.emit.called:
                event = emitter.emit.call_args[0][0]
                total += 1
                if event.event_type == "failed_logon":
                    failed += 1

        # Expect ~10% failure rate (allow 3-25% for statistical variation)
        assert total > 0
        failure_rate = failed / total
        assert 0.03 < failure_rate < 0.25, f"Failure rate {failure_rate:.2%} outside expected range"


class TestFailedLogonDC:
    """Test failed logon domain-controller validation evidence."""

    def test_failed_logon_does_not_clone_4625_on_dc(
        self, state_manager, mock_emitters, timestamp, monkeypatch
    ):
        """Failed logon with dc_system should keep 4625 on target and validation on DC."""
        monkeypatch.setattr(
            generator_mod,
            "failed_logon_config",
            lambda: {
                "network": {
                    "validation_path_weights": {
                        "ntlm_only": {"emit_4776": True, "emit_4771": False, "weight": 1}
                    }
                }
            },
        )
        ag = ActivityGenerator(state_manager, mock_emitters)
        state_manager.set_current_time(timestamp)

        wks = System(hostname="WKS-01", ip="10.0.10.1", os="Windows 10", type="workstation")
        dc = System(
            hostname="DC-01", ip="10.0.10.100", os="Windows Server 2019", type="domain_controller"
        )
        user = User(username="alice", full_name="Alice", email="a@t.com", enabled=True)

        ag.generate_failed_logon(
            user=user,
            system=wks,
            time=timestamp,
            logon_type=3,
            source_ip="10.0.10.1",
            dc_system=dc,
        )

        win_emitter = mock_emitters["windows_event_security"]
        events = [call[0][0] for call in win_emitter.emit.call_args_list]
        failed_logons = [event for event in events if event.event_type == "failed_logon"]
        dc_events = [
            event for event in events if event.dst_host and event.dst_host.hostname == "DC-01"
        ]

        assert len(failed_logons) == 1
        assert failed_logons[0].dst_host.hostname == "WKS-01"
        assert "ntlm_validation" in {event.event_type for event in dc_events}

    def test_failed_logon_dc_gets_4776(self, state_manager, mock_emitters, timestamp, monkeypatch):
        """DC should receive a failed NTLM validation (4776) event."""
        monkeypatch.setattr(
            generator_mod,
            "failed_logon_config",
            lambda: {
                "network": {
                    "validation_path_weights": {
                        "ntlm_only": {"emit_4776": True, "emit_4771": False, "weight": 1}
                    }
                }
            },
        )
        ag = ActivityGenerator(state_manager, mock_emitters)
        state_manager.set_current_time(timestamp)

        wks = System(hostname="WKS-01", ip="10.0.10.1", os="Windows 10", type="workstation")
        dc = System(
            hostname="DC-01", ip="10.0.10.100", os="Windows Server 2019", type="domain_controller"
        )
        user = User(username="alice", full_name="Alice", email="a@t.com", enabled=True)

        ag.generate_failed_logon(
            user=user,
            system=wks,
            time=timestamp,
            logon_type=3,
            source_ip="10.0.10.1",
            dc_system=dc,
        )

        # Check for ntlm_validation event type on DC
        win_emitter = mock_emitters["windows_event_security"]
        dc_events = [
            call[0][0]
            for call in win_emitter.emit.call_args_list
            if call[0][0].dst_host and call[0][0].dst_host.hostname == "DC-01"
        ]
        event_types = {e.event_type for e in dc_events}
        assert "ntlm_validation" in event_types, "Missing 4776 on DC"
        ntlm_event = next(e for e in dc_events if e.event_type == "ntlm_validation")
        assert ntlm_event.auth.failure_status != "0x0"

    def test_failed_logon_can_emit_kerberos_without_ntlm(
        self, state_manager, mock_emitters, timestamp, monkeypatch
    ):
        """Failed-auth validation paths should be data-driven, not always Kerberos+NTLM."""
        monkeypatch.setattr(
            generator_mod,
            "failed_logon_config",
            lambda: {
                "network": {
                    "validation_path_weights": {
                        "kerberos_only": {"emit_4776": False, "emit_4771": True, "weight": 1}
                    },
                    "logon_process_weights": {
                        "negotiate": {
                            "logon_process_name": "NtLmSsp",
                            "authentication_package_name": "Negotiate",
                            "lm_package_name": "-",
                            "weight": 1,
                        }
                    },
                    "emit_network_connection_probability": 1.0,
                    "network_ports": {"smb": {"port": 445, "weight": 1}},
                }
            },
        )
        ag = ActivityGenerator(state_manager, mock_emitters)
        state_manager.set_current_time(timestamp)
        wks = System(hostname="WKS-01", ip="10.0.10.1", os="Windows 10", type="workstation")
        dc = System(
            hostname="DC-01", ip="10.0.10.100", os="Windows Server 2019", type="domain_controller"
        )
        user = User(username="alice", full_name="Alice", email="a@t.com", enabled=True)

        for _ in range(5):
            ag.generate_failed_logon(
                user=user,
                system=wks,
                time=timestamp,
                logon_type=3,
                source_ip="45.83.221.45",
                dc_system=dc,
            )

        event_types = {
            call[0][0].event_type
            for call in mock_emitters["windows_event_security"].emit.call_args_list
        }
        assert "kerberos_preauth_failed" in event_types
        assert "ntlm_validation" not in event_types

    def test_failed_logon_network_evidence_is_not_syn_only(
        self, state_manager, mock_emitters, timestamp, monkeypatch
    ):
        """Remote Windows 4625 evidence should not pair with Zeek S0 connections."""
        monkeypatch.setattr(
            generator_mod,
            "failed_logon_config",
            lambda: {
                "network": {
                    "validation_path_weights": {
                        "ntlm_only": {"emit_4776": True, "emit_4771": False, "weight": 1}
                    },
                    "logon_process_weights": {
                        "ntlm": {
                            "logon_process_name": "NtLmSsp",
                            "authentication_package_name": "NTLM",
                            "lm_package_name": "NTLM V2",
                            "weight": 1,
                        }
                    },
                    "emit_network_connection_probability": 1.0,
                    "network_ports": {"smb": {"port": 445, "weight": 1}},
                }
            },
        )
        ag = ActivityGenerator(state_manager, mock_emitters)
        state_manager.set_current_time(timestamp)
        wks = System(hostname="WKS-01", ip="10.0.10.1", os="Windows 10", type="workstation")
        user = User(username="alice", full_name="Alice", email="a@t.com", enabled=True)

        ag.generate_failed_logon(
            user=user,
            system=wks,
            time=timestamp,
            logon_type=3,
            source_ip="45.83.221.45",
        )

        network_events = [
            call[0][0]
            for call in mock_emitters["zeek_conn"].emit.call_args_list
            if call[0][0].event_type == "connection"
        ]
        assert network_events
        assert all(event.network.conn_state != "S0" for event in network_events)

    def test_known_user_failed_logon_uses_wrong_password_substatus(
        self, state_manager, mock_emitters, timestamp
    ):
        """A known user should not receive the nonexistent-user SubStatus."""
        ag = ActivityGenerator(state_manager, mock_emitters)
        state_manager.set_current_time(timestamp)
        wks = System(hostname="WKS-01", ip="10.0.10.1", os="Windows 10", type="workstation")
        user = User(username="alice", full_name="Alice", email="a@t.com", enabled=True)

        for _ in range(50):
            ag.generate_failed_logon(user=user, system=wks, time=timestamp, logon_type=3)

        events = [
            call[0][0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call[0][0].event_type == "failed_logon"
        ]
        assert events
        assert {event.auth.failure_substatus for event in events} == {"0xc000006a"}

    def test_interactive_failed_logon_uses_local_windows_shape(
        self, state_manager, mock_emitters, timestamp
    ):
        """Interactive 4625 context should look like a local workstation failure."""
        ag = ActivityGenerator(state_manager, mock_emitters)
        state_manager.set_current_time(timestamp)
        wks = System(hostname="WKS-01", ip="10.0.10.1", os="Windows 10", type="workstation")
        user = User(username="alice", full_name="Alice", email="a@t.com", enabled=True)

        ag.generate_failed_logon(user=user, system=wks, time=timestamp, logon_type=2)

        event = mock_emitters["windows_event_security"].emit.call_args_list[0][0][0]
        assert event.auth.logon_process == "User32"
        assert event.auth.auth_package == "Negotiate"
        assert event.auth.workstation_name == "WKS-01"
        assert event.auth.source_ip == "-"
        assert event.auth.process_name == r"C:\Windows\System32\winlogon.exe"

    def test_no_dc_no_extra_events(self, state_manager, mock_emitters, timestamp):
        """Without dc_system, only workstation events are emitted."""
        ag = ActivityGenerator(state_manager, mock_emitters)
        state_manager.set_current_time(timestamp)

        wks = System(hostname="WKS-01", ip="10.0.10.1", os="Windows 10", type="workstation")
        user = User(username="alice", full_name="Alice", email="a@t.com", enabled=True)

        ag.generate_failed_logon(user=user, system=wks, time=timestamp, source_ip="10.0.10.1")

        win_emitter = mock_emitters["windows_event_security"]
        hosts = {call[0][0].dst_host.hostname for call in win_emitter.emit.call_args_list}
        assert hosts == {"WKS-01"}, "Should only emit on workstation without DC"
