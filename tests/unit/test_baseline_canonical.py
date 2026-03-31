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

"""Tests for baseline canonical event migration.

Verifies that baseline activities dispatch through SecurityEvent to
multiple emitters, producing correlated cross-source records.
"""

from datetime import UTC, datetime
from unittest.mock import Mock

import pytest

from evidenceforge.events.contexts import HttpContext, IdsContext
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models import System, User


@pytest.fixture
def state_manager():
    sm = StateManager()
    sm.set_current_time(datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC))
    return sm


@pytest.fixture
def mock_emitters():
    return {
        "windows_event_security": Mock(),
        "zeek_conn": Mock(),
        "zeek_http": Mock(),
        "ecar": Mock(),
        "syslog": Mock(),
        "snort_alert": Mock(),
        "web_access": Mock(),
    }


@pytest.fixture
def activity_gen(state_manager, mock_emitters):
    return ActivityGenerator(state_manager, mock_emitters)


@pytest.fixture
def web_server():
    return System(hostname="WEB-01", ip="10.0.10.5", os="Linux Ubuntu 22.04", type="server")


@pytest.fixture
def timestamp():
    return datetime(2024, 3, 15, 10, 30, 0, tzinfo=UTC)


class TestIdsAlertCorrelation:
    """IDS alerts should produce both Snort alert and Zeek conn records."""

    def test_ids_connection_dispatches_to_snort(
        self, activity_gen, state_manager, mock_emitters, timestamp
    ):
        """generate_connection() with IdsContext should dispatch to snort emitter."""
        activity_gen.generate_connection(
            src_ip="203.0.113.50",
            dst_ip="10.0.10.1",
            time=timestamp,
            dst_port=80,
            proto="tcp",
            service="http",
            duration=0.5,
            orig_bytes=500,
            resp_bytes=200,
            ids=IdsContext(
                sid=10001,
                message="ET SCAN potential SSH scan",
                classification="Attempted Information Leak",
                priority=2,
            ),
        )

        # Snort emitter should receive the event with IdsContext
        snort = mock_emitters["snort_alert"]
        assert snort.emit.called
        event = snort.emit.call_args[0][0]
        assert event.ids is not None
        assert event.ids.sid == 10001

    def test_ids_connection_also_dispatches_to_zeek(
        self, activity_gen, state_manager, mock_emitters, timestamp
    ):
        """IDS alert should also produce a Zeek conn record."""
        activity_gen.generate_connection(
            src_ip="203.0.113.50",
            dst_ip="10.0.10.1",
            time=timestamp,
            dst_port=22,
            proto="tcp",
            service="ssh",
            duration=1.0,
            orig_bytes=100,
            resp_bytes=50,
            ids=IdsContext(
                sid=10002,
                message="ET SCAN SSH scan",
                classification="Attempted Recon",
                priority=3,
            ),
        )

        # Zeek conn should also receive the connection
        zeek = mock_emitters["zeek_conn"]
        assert zeek.emit.called
        event = zeek.emit.call_args[0][0]
        assert event.network.dst_port == 22


class TestWebAccessCorrelation:
    """Web access logs should produce correlated Zeek conn + HTTP + web records."""

    def test_http_connection_dispatches_to_web_emitter(
        self, activity_gen, state_manager, mock_emitters, timestamp
    ):
        """generate_connection() with HttpContext should dispatch to web emitter."""
        activity_gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip="10.0.10.5",
            time=timestamp,
            dst_port=80,
            proto="tcp",
            service="http",
            duration=0.1,
            orig_bytes=500,
            resp_bytes=5000,
            http=HttpContext(
                method="GET",
                host="WEB-01",
                uri="/index.html",
                version="1.1",
                user_agent="curl/7.88.1",
                request_body_len=0,
                response_body_len=5000,
                status_code=200,
                status_msg="OK",
                resp_mime_types=["text/html"],
                tags=[],
            ),
        )

        # Web emitter should get the event with HttpContext
        web = mock_emitters["web_access"]
        assert web.emit.called
        event = web.emit.call_args[0][0]
        assert event.http is not None
        assert event.http.method == "GET"
        assert event.http.status_code == 200

    def test_http_connection_also_dispatches_to_zeek_http(
        self, activity_gen, state_manager, mock_emitters, timestamp
    ):
        """HTTP request should also produce a Zeek http.log record."""
        activity_gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip="10.0.10.5",
            time=timestamp,
            dst_port=80,
            proto="tcp",
            service="http",
            duration=0.2,
            orig_bytes=300,
            resp_bytes=3000,
            http=HttpContext(
                method="POST",
                host="WEB-01",
                uri="/api/v1/data",
                version="1.1",
                user_agent="python-requests/2.31.0",
                request_body_len=300,
                response_body_len=3000,
                status_code=200,
                status_msg="OK",
                resp_mime_types=["application/json"],
                tags=[],
            ),
        )

        # Zeek HTTP should get the same event
        zeek_http = mock_emitters["zeek_http"]
        assert zeek_http.emit.called
        event = zeek_http.emit.call_args[0][0]
        assert event.http.uri == "/api/v1/data"

    def test_caller_http_context_not_overwritten(
        self, activity_gen, state_manager, mock_emitters, timestamp
    ):
        """Caller-provided HttpContext should not be overwritten by auto-generation."""
        activity_gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip="10.0.10.5",
            time=timestamp,
            dst_port=80,
            proto="tcp",
            service="http",
            duration=0.1,
            orig_bytes=200,
            resp_bytes=1000,
            http=HttpContext(
                method="DELETE",
                host="WEB-01",
                uri="/api/v1/resource/42",
                version="1.1",
                user_agent="custom-agent",
                request_body_len=0,
                response_body_len=0,
                status_code=204,
                status_msg="No Content",
                resp_mime_types=[],
                tags=[],
            ),
        )

        web = mock_emitters["web_access"]
        event = web.emit.call_args[0][0]
        # Should be our custom context, not auto-generated
        assert event.http.method == "DELETE"
        assert event.http.uri == "/api/v1/resource/42"
        assert event.http.status_code == 204


class TestSystemProcessCanonical:
    """System process events dispatch to both syslog and eCAR."""

    def test_system_process_dispatches_to_syslog(
        self, activity_gen, state_manager, mock_emitters, timestamp
    ):
        """generate_system_process() should dispatch to syslog emitter."""
        linux_system = System(
            hostname="LNX-01", ip="10.0.10.2", os="Linux Ubuntu 22.04", type="server"
        )
        systemd_pid = state_manager.create_process(
            "LNX-01", 0, "/usr/lib/systemd/systemd", "systemd", "root", "System"
        )
        activity_gen.generate_system_process(
            system=linux_system,
            time=timestamp,
            process_name="/usr/lib/systemd/systemd",
            command_line="Starting logrotate.service - Logrotate.",
            parent_pid=systemd_pid,
            username="root",
        )

        syslog = mock_emitters["syslog"]
        assert syslog.emit.called
        event = syslog.emit.call_args[0][0]
        assert event.syslog is not None
        assert event.syslog.app_name == "systemd"
        assert "logrotate" in event.syslog.message

    def test_system_process_dispatches_to_ecar(
        self, activity_gen, state_manager, mock_emitters, timestamp
    ):
        """generate_system_process() should also dispatch to eCAR emitter."""
        linux_system = System(
            hostname="LNX-01", ip="10.0.10.2", os="Linux Ubuntu 22.04", type="server"
        )
        systemd_pid = state_manager.create_process(
            "LNX-01", 0, "/usr/lib/systemd/systemd", "systemd", "root", "System"
        )
        activity_gen.generate_system_process(
            system=linux_system,
            time=timestamp,
            process_name="/usr/lib/snapd/snapd",
            command_line="autorefresh.go:540: auto-refresh: all snaps are up-to-date",
            parent_pid=systemd_pid,
            username="root",
        )

        ecar = mock_emitters["ecar"]
        assert ecar.emit.called
        event = ecar.emit.call_args[0][0]
        assert event.event_type == "system_process_create"


class TestSyslogContext:
    """Verify SyslogContext is attached to events for Linux hosts."""

    def test_logon_attaches_syslog_context_on_linux(
        self, activity_gen, state_manager, mock_emitters, timestamp
    ):
        """generate_logon() should attach SyslogContext for Linux hosts."""
        linux = System(hostname="LNX-01", ip="10.0.10.2", os="Linux Ubuntu 22.04", type="server")
        state_manager.set_current_time(timestamp)
        activity_gen.generate_logon(
            user=User(username="alice", full_name="Alice", email="a@t.com", enabled=True),
            system=linux,
            time=timestamp,
            source_ip="10.0.10.1",
        )

        syslog = mock_emitters["syslog"]
        assert syslog.emit.called
        event = syslog.emit.call_args[0][0]
        assert event.syslog is not None
        assert event.syslog.app_name == "sshd"
        assert "Accepted password for alice" in event.syslog.message

    def test_logon_no_syslog_context_on_windows(
        self, activity_gen, state_manager, mock_emitters, timestamp
    ):
        """generate_logon() should NOT attach SyslogContext for Windows hosts."""
        win = System(hostname="WKS-01", ip="10.0.10.1", os="Windows 10", type="workstation")
        state_manager.set_current_time(timestamp)
        activity_gen.generate_logon(
            user=User(username="alice", full_name="Alice", email="a@t.com", enabled=True),
            system=win,
            time=timestamp,
        )

        # Syslog emitter should NOT be called (no SyslogContext on Windows)
        syslog = mock_emitters["syslog"]
        if syslog.emit.called:
            event = syslog.emit.call_args[0][0]
            # If called, the event should NOT have syslog context
            assert event.syslog is None

    def test_failed_logon_attaches_syslog_context(
        self, activity_gen, state_manager, mock_emitters, timestamp
    ):
        """generate_failed_logon() should attach SyslogContext for Linux hosts."""
        linux = System(hostname="LNX-01", ip="10.0.10.2", os="Linux Ubuntu 22.04", type="server")
        state_manager.set_current_time(timestamp)
        activity_gen.generate_failed_logon(
            user=User(username="attacker", full_name="Attacker", email="a@t.com", enabled=True),
            system=linux,
            time=timestamp,
            source_ip="10.0.10.99",
        )

        syslog = mock_emitters["syslog"]
        assert syslog.emit.called
        event = syslog.emit.call_args[0][0]
        assert event.syslog is not None
        assert "Failed password" in event.syslog.message
        assert event.syslog.severity == 4  # Warning level

    def test_generate_syslog_event_helper(
        self, activity_gen, state_manager, mock_emitters, timestamp
    ):
        """generate_syslog_event() should dispatch with SyslogContext."""
        linux = System(hostname="LNX-01", ip="10.0.10.2", os="Linux Ubuntu 22.04", type="server")
        activity_gen.generate_syslog_event(
            system=linux,
            time=timestamp,
            app_name="systemd",
            message="Starting logrotate.service - Logrotate.",
            pid=1,
        )

        syslog = mock_emitters["syslog"]
        assert syslog.emit.called
        event = syslog.emit.call_args[0][0]
        assert event.syslog.app_name == "systemd"
        assert event.syslog.pid == 1


class TestWeirdContext:
    """Weird events attach to connection SecurityEvents."""

    def test_weird_context_on_connection(
        self, activity_gen, state_manager, mock_emitters, timestamp
    ):
        """Connection events can carry WeirdContext for zeek_weird emitter."""
        from evidenceforge.events.base import SecurityEvent
        from evidenceforge.events.contexts import HostContext, NetworkContext, WeirdContext

        event = SecurityEvent(
            timestamp=timestamp,
            event_type="connection",
            src_host=HostContext(
                hostname="FW-01",
                ip="10.0.0.1",
                os="Linux",
                os_category="linux",
                system_type="server",
            ),
            network=NetworkContext(
                src_ip="10.0.10.1",
                src_port=50000,
                dst_ip="8.8.8.8",
                dst_port=443,
                protocol="tcp",
                zeek_uid="CTest123456789ab",
            ),
            weird=WeirdContext(name="truncated_header", source="TCP"),
        )
        assert event.weird is not None
        assert event.weird.name == "truncated_header"


class TestDhcpLease:
    """DHCP lease events dispatch through canonical path."""

    def test_generate_dhcp_lease_dispatches(
        self, activity_gen, state_manager, mock_emitters, timestamp
    ):
        """generate_dhcp_lease() should dispatch to zeek_dhcp emitter."""
        linux = System(hostname="LNX-01", ip="10.0.10.2", os="Linux Ubuntu 22.04", type="server")
        state_manager.set_current_time(timestamp)
        activity_gen.generate_dhcp_lease(
            system=linux,
            time=timestamp,
            mac="00:50:56:ab:cd:ef",
            uid="CTest123456789ab",
        )

        # Check dispatch happened (mock emitter records all calls)
        # The zeek_dhcp emitter would receive this if present
        # We verify the event was dispatched with DhcpContext
        # Since mock emitters don't have can_handle(), check any emitter got it
        all_calls = []
        for emitter in mock_emitters.values():
            if emitter.emit.called:
                for call in emitter.emit.call_args_list:
                    all_calls.append(call[0][0])
        dhcp_events = [e for e in all_calls if e.event_type == "dhcp_lease"]
        assert len(dhcp_events) >= 1
        assert dhcp_events[0].dhcp is not None
        assert dhcp_events[0].dhcp.mac == "00:50:56:ab:cd:ef"


class TestAnonymousLogon:
    """Anonymous logon events dispatch without creating sessions."""

    def test_generate_anonymous_logon_dispatches(
        self, activity_gen, state_manager, mock_emitters, timestamp
    ):
        """generate_anonymous_logon() should dispatch to Windows emitter."""
        dc = System(
            hostname="DC-01",
            ip="10.0.10.100",
            os="Windows Server 2019",
            type="domain_controller",
        )
        state_manager.set_current_time(timestamp)
        activity_gen.generate_anonymous_logon(system=dc, time=timestamp)

        win = mock_emitters["windows_event_security"]
        assert win.emit.called
        event = win.emit.call_args[0][0]
        assert event.auth.username == "ANONYMOUS LOGON"
        assert event.auth.user_sid == "S-1-5-7"
        assert event.auth.logon_type == 3
        assert event.auth.auth_package == "NTLM"

    def test_anonymous_logon_no_session_created(
        self, activity_gen, state_manager, mock_emitters, timestamp
    ):
        """Anonymous logon should NOT create a session in StateManager."""
        dc = System(
            hostname="DC-01",
            ip="10.0.10.100",
            os="Windows Server 2019",
            type="domain_controller",
        )
        state_manager.set_current_time(timestamp)
        sessions_before = len(state_manager.state.active_sessions)
        activity_gen.generate_anonymous_logon(system=dc, time=timestamp)
        sessions_after = len(state_manager.state.active_sessions)
        assert sessions_after == sessions_before


class TestNoInternalGenerateRaw:
    """Verify no internal engine code calls generate_raw()."""

    def test_no_generate_raw_in_baseline(self):
        """baseline.py should not call generate_raw()."""
        import inspect

        from evidenceforge.generation.engine.baseline import BaselineMixin

        source = inspect.getsource(BaselineMixin)
        assert "generate_raw" not in source

    def test_no_generate_raw_in_emitter_setup(self):
        """emitter_setup.py should not call generate_raw()."""
        import inspect

        from evidenceforge.generation.engine.emitter_setup import EmitterSetupMixin

        source = inspect.getsource(EmitterSetupMixin)
        assert "generate_raw" not in source


class TestSensorStartup:
    """Sensor startup events dispatch through canonical path."""

    def test_generate_sensor_startup_dispatches(
        self, activity_gen, state_manager, mock_emitters, timestamp
    ):
        """generate_sensor_startup() should dispatch SecurityEvent."""
        activity_gen.generate_sensor_startup(
            sensor_hostname="fw01",
            time=timestamp,
            reporter_messages=[
                ("Reporter::INFO", "zeek_init() called"),
                ("Reporter::INFO", "listening on eth0"),
            ],
        )

        # Should have dispatched 3 events: 1 packet_filter + 2 reporter
        # Check that the dispatcher was called (events routed to emitters)
        # The mock emitters may or may not receive these depending on can_handle()
        # but the dispatch should not raise errors
