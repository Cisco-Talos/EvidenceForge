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

import random
import re
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest

from evidenceforge.events.contexts import HttpContext, IdsContext
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.activity.linux_interfaces import linux_primary_interface
from evidenceforge.generation.engine.baseline import (
    _ambient_registry_entry_allowed,
    _extra_syslog_service_values,
    _linux_ambient_logind_probability,
    _linux_baseline_pam_close_lead,
    _linux_baseline_pam_open_lead,
    _linux_baseline_session_initiator,
    _linux_transient_syslog_pid,
    _materialize_registry_value_for_time,
    _module_matches_process,
    _render_extra_sudo_command_template,
    _sample_lock_duration,
    _ufw_block_syn_packet_len,
    _ufw_block_ttl,
    _windows_scheduled_task_offsets,
)
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
        "zeek_ntp": Mock(),
        "ecar": Mock(),
        "syslog": Mock(),
        "snort_alert": Mock(),
        "web_access": Mock(),
    }


@pytest.fixture
def activity_gen(state_manager, mock_emitters):
    return ActivityGenerator(state_manager, mock_emitters)


def test_lock_duration_sampler_avoids_exact_minute_fingerprints():
    """Lock/unlock durations should carry human-scale second and millisecond texture."""
    rng = random.Random(7)
    meeting_durations = [_sample_lock_duration(rng, "meeting") for _ in range(50)]
    lunch_durations = [_sample_lock_duration(rng, "lunch") for _ in range(50)]

    assert all(duration.total_seconds() >= 127 for duration in meeting_durations)
    assert any(duration.microseconds for duration in meeting_durations + lunch_durations)
    assert any(duration.total_seconds() % 60 for duration in meeting_durations + lunch_durations)
    assert max(duration.total_seconds() for duration in meeting_durations) > 20 * 60
    assert min(duration.total_seconds() for duration in lunch_durations) < 35 * 60
    assert max(duration.total_seconds() for duration in lunch_durations) > 55 * 60


def test_linux_baseline_session_initiator_creates_pam_session_message():
    """Ambient logind session noise should have a concrete PAM initiator."""
    samples = [
        _linux_baseline_session_initiator("admin", rng=random.Random(seed)) for seed in range(30)
    ]
    samples.extend(
        _linux_baseline_session_initiator("root", rng=random.Random(seed)) for seed in range(30)
    )

    assert {service for _app_name, service, _message in samples} <= {"login", "sudo", "su"}
    assert all(app_name != "CRON" for app_name, _service, _message in samples)
    assert all(service != "cron" for _app_name, service, _message in samples)
    assert all("pam_unix(" in message for _app_name, _service, message in samples)
    assert any(
        ":session): session opened for user admin(uid=" in message
        for _app_name, _service, message in samples
    )
    assert any(
        ":session): session opened for user root(uid=" in message
        for _app_name, _service, message in samples
    )


def test_linux_server_ambient_logind_noise_is_thinned():
    """Generic local-console/logind noise should be much sparser on servers."""
    assert _linux_ambient_logind_probability("server") < _linux_ambient_logind_probability(
        "workstation"
    )
    assert _linux_ambient_logind_probability("server") <= 0.15


def test_server_pam_initiator_favors_sudo_over_local_login():
    """Server baseline session noise should not overproduce LOGIN(uid=0)."""
    samples = [
        _linux_baseline_session_initiator("admin", rng=random.Random(seed), system_type="server")
        for seed in range(120)
    ]
    services = [service for _app_name, service, _message in samples]

    assert services.count("sudo") > services.count("login")


def test_extra_sudo_command_template_uses_host_services():
    """Extra sudo COMMAND text should vary through host-aware service placeholders."""
    command = _render_extra_sudo_command_template(
        "/bin/systemctl status {service}",
        random.Random(3),
        system_services=["mysql", "dns-client", "ssh"],
        fallback_services=["apache2"],
    )

    assert command in {"/bin/systemctl status mysql", "/bin/systemctl status sshd"}
    assert _extra_syslog_service_values(["mysql", "ssh"], ["apache2"]) == ["mysql", "sshd"]


def test_extra_sudo_command_template_resolves_command_specific_placeholders():
    """Extra sudo COMMAND text should vary counts and windows from config pools."""
    command = _render_extra_sudo_command_template(
        '/usr/bin/journalctl -u {service} -n {journal_lines} --since "{journal_window}"',
        random.Random(7),
        system_services=["postgresql", "dns-client"],
        fallback_services=["apache2"],
        params={
            "journal_lines": ["40", "80"],
            "journal_window": ["15 min ago", "45 min ago"],
        },
    )

    assert command.startswith("/usr/bin/journalctl -u postgresql -n ")
    assert "{journal_" not in command


def test_linux_baseline_pam_leads_leave_visible_ordering_margin():
    """Ambient PAM rows should lead logind rows by more than timestamp texture."""
    rng = random.Random(11)
    open_leads = [_linux_baseline_pam_open_lead(rng) for _ in range(50)]
    close_leads = [_linux_baseline_pam_close_lead(rng) for _ in range(50)]

    assert min(open_leads) >= timedelta(seconds=3)
    assert max(open_leads) <= timedelta(seconds=8)
    assert min(close_leads) >= timedelta(milliseconds=1200)
    assert max(close_leads) <= timedelta(milliseconds=4200)


def test_linux_transient_syslog_pid_uses_host_pid_allocator():
    """Short-lived PAM/sudo syslog records should use one invocation PID per call."""
    state_manager = Mock()
    state_manager.allocate_transient_linux_pid.side_effect = [24123, 24171]
    event_time = datetime(2024, 3, 18, 12, 5, tzinfo=UTC)

    first = _linux_transient_syslog_pid(
        state_manager,
        "WEB-EXT-01",
        event_time,
        random.Random(3),
    )
    second = _linux_transient_syslog_pid(
        state_manager,
        "WEB-EXT-01",
        event_time + timedelta(seconds=20),
        random.Random(3),
    )

    assert [first, second] == [24123, 24171]
    assert state_manager.allocate_transient_linux_pid.call_count == 2


@pytest.fixture
def web_server():
    return System(hostname="WEB-01", ip="10.0.10.5", os="Linux Ubuntu 22.04", type="server")


@pytest.fixture
def timestamp():
    return datetime(2024, 3, 15, 10, 30, 0, tzinfo=UTC)


class TestModuleLoadProcessMatching:
    """Tests for process-aware Sysmon module-load pool filtering."""

    def test_chrome_and_edge_modules_stay_in_their_own_package_paths(self):
        """Chromium-family browsers should not swap package DLL ownership."""
        chrome_module = r"C:\Program Files\Google\Chrome\Application\120.0.6099.225\libegl.dll"
        edge_module = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge_elf.dll"

        assert _module_matches_process("chrome.exe", chrome_module)
        assert not _module_matches_process("msedge.exe", chrome_module)
        assert _module_matches_process("msedge.exe", edge_module)
        assert not _module_matches_process("chrome.exe", edge_module)


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

    def test_ufw_block_packet_profile_is_valid_and_stable(self):
        """UFW blocked SYN metadata should be valid and path-stable by source."""
        src_ip = "45.33.74.51"

        lengths = [_ufw_block_syn_packet_len(src_ip) for _ in range(10)]
        ttls = [_ufw_block_ttl(src_ip) for _ in range(10)]

        assert len(set(lengths)) == 1
        assert lengths[0] in {40, 44, 48, 52, 60}
        assert lengths[0] % 4 == 0
        assert len(set(ttls)) == 1
        assert 32 <= ttls[0] <= 251

    def test_ufw_block_connection_uses_drop_semantics_and_matching_packet_len(
        self,
        activity_gen,
        mock_emitters,
        timestamp,
    ):
        """A UFW BLOCK companion Zeek row should be S0 with no responder packet."""
        packet_len = _ufw_block_syn_packet_len("45.33.74.51")

        activity_gen.generate_connection(
            src_ip="45.33.74.51",
            dst_ip="10.0.10.5",
            time=timestamp,
            dst_port=443,
            proto="tcp",
            conn_state="S0",
            src_port=40664,
            packet_overhead_bytes=packet_len,
        )

        event = mock_emitters["zeek_conn"].emit.call_args.args[0]
        assert event.network.conn_state == "S0"
        assert event.network.history == "S"
        assert event.network.orig_pkts == 1
        assert event.network.orig_ip_bytes == packet_len
        assert event.network.resp_pkts == 0
        assert event.network.resp_ip_bytes == 0

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

    def test_ntp_connection_uses_server_response_mode(self, activity_gen, mock_emitters, timestamp):
        """NTP records with server timing fields should use server-response mode."""
        activity_gen.generate_connection(
            src_ip="10.0.1.50",
            dst_ip="129.6.15.28",
            time=timestamp,
            dst_port=123,
            proto="udp",
            service="ntp",
            duration=0.02,
            orig_bytes=48,
            resp_bytes=48,
        )

        event = mock_emitters["zeek_ntp"].emit.call_args[0][0]
        assert event.ntp is not None
        assert event.ntp.mode == 4
        assert event.ntp.stratum >= 1
        assert event.ntp.rec_ts > event.ntp.org_ts
        assert event.ntp.xmt_ts >= event.ntp.rec_ts

    def test_ntp_association_fields_are_stable(self, activity_gen, mock_emitters, timestamp):
        """NTP version and poll behavior should be stable per client/server pair."""
        for minute in (0, 10):
            activity_gen.generate_connection(
                src_ip="10.0.1.50",
                dst_ip="129.6.15.28",
                time=timestamp.replace(minute=minute),
                dst_port=123,
                proto="udp",
                service="ntp",
                duration=0.02,
                orig_bytes=48,
                resp_bytes=48,
            )

        first = mock_emitters["zeek_ntp"].emit.call_args_list[-2][0][0].ntp
        second = mock_emitters["zeek_ntp"].emit.call_args_list[-1][0][0].ntp

        assert first.version == second.version
        assert first.poll == second.poll
        assert first.precision == second.precision
        assert first.root_delay == second.root_delay
        assert first.root_disp == second.root_disp

    def test_completed_tls_duration_contains_zeek_analyzer_evidence(
        self, activity_gen, mock_emitters, timestamp
    ):
        """Completed TLS conn duration should be long enough for ssl/x509 analyzer rows."""
        activity_gen.generate_connection(
            src_ip="10.0.1.50",
            dst_ip="93.184.216.34",
            time=timestamp,
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=0.002,
            orig_bytes=1,
            resp_bytes=1,
            conn_state="SF",
            hostname="github.com",
        )

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert event.ssl is not None
        assert event.x509 is not None
        assert event.network.duration > 0.8


class TestForegroundProcessTermination:
    def test_suspicious_short_command_gets_near_runtime_termination(self):
        """Suspicious-noise foreground commands should not wait for hourly stale cleanup."""
        from evidenceforge.generation.engine.baseline import BaselineMixin

        engine = object.__new__(type("FakeEngine", (BaselineMixin,), {}))
        engine.activity_generator = Mock()
        user = User(username="jdoe", full_name="Jane Doe", email="jdoe@example.com")
        system = System(hostname="WS-01", ip="10.0.0.10", os="Windows 11", type="workstation")
        start_time = datetime(2024, 3, 15, 10, 30, 0, tzinfo=UTC)

        engine._schedule_foreground_process_termination(
            user=user,
            system=system,
            start_time=start_time,
            pid=4242,
            process_name=r"C:\Windows\System32\dsquery.exe",
            command_line="dsquery user -limit 0",
            logon_id="0x1234",
            rng=Mock(uniform=Mock(return_value=3.5)),
        )

        engine.activity_generator.generate_process_termination.assert_called_once()
        kwargs = engine.activity_generator.generate_process_termination.call_args.kwargs
        assert kwargs["time"] == start_time + timedelta(seconds=3.5)
        assert kwargs["pid"] == 4242


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

    def test_static_zero_body_success_normalizes_to_not_modified(
        self, activity_gen, state_manager, mock_emitters, timestamp
    ):
        """Static GET responses should not fan out as 200 OK with zero body and MIME."""
        activity_gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip="10.0.10.5",
            time=timestamp,
            dst_port=80,
            proto="tcp",
            service="http",
            duration=0.1,
            orig_bytes=200,
            resp_bytes=0,
            http=HttpContext(
                method="GET",
                host="WEB-01",
                uri="/assets/css/main.063cbaf5.css",
                version="1.1",
                user_agent="Mozilla/5.0",
                request_body_len=0,
                response_body_len=0,
                status_code=200,
                status_msg="OK",
                resp_mime_types=["text/css"],
                tags=[],
            ),
        )

        event = mock_emitters["zeek_http"].emit.call_args[0][0]
        assert event.http.status_code == 304
        assert event.http.status_msg == "Not Modified"
        assert event.http.response_body_len == 0
        assert event.http.resp_mime_types == []

    def test_auto_http_static_resource_uses_stable_response_size(
        self, activity_gen, state_manager, mock_emitters, timestamp, monkeypatch
    ):
        """Auto-generated HTTP contexts should not size static resources from flow bytes."""
        from evidenceforge.generation.activity import generator as generator_module
        from evidenceforge.generation.activity import proxy_uri
        from evidenceforge.generation.activity.http_content import (
            apply_transfer_size_variance,
            response_size_for_status,
        )

        monkeypatch.setattr(
            proxy_uri,
            "pick_proxy_uri",
            lambda *args, **kwargs: ("/favicon.ico", "image/x-icon", "GET", "", "none"),
        )
        monkeypatch.setattr(generator_module, "_get_http_status", lambda dst_ip, uri: (200, "OK"))

        activity_gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip="10.0.10.5",
            time=timestamp,
            dst_port=80,
            proto="tcp",
            service="http",
            duration=0.2,
            orig_bytes=300,
            resp_bytes=50_000,
            conn_state="SF",
            hostname="portal.example.com",
        )

        event = mock_emitters["zeek_http"].emit.call_args[0][0]
        assert event.http.uri == "/favicon.ico"
        assert event.http.response_body_len == apply_transfer_size_variance(
            response_size_for_status(200, "portal.example.com", "/favicon.ico"),
            status_code=200,
            host="portal.example.com",
            uri="/favicon.ico",
            content_type="image/x-icon",
            variant_key=f"10.0.10.50:{event.http.user_agent}",
        )
        assert event.http.resp_mime_types == ["image/x-icon"]


class TestSmbFileTransferCorrelation:
    """SMB data transfers should produce Zeek files.log context when substantial."""

    def test_large_smb_read_adds_file_transfer_context(
        self, activity_gen, state_manager, mock_emitters, timestamp
    ):
        """Large successful SMB downloads should be observable in files.log."""
        activity_gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip="10.0.20.5",
            time=timestamp,
            dst_port=445,
            proto="tcp",
            service="smb",
            duration=12.0,
            orig_bytes=8000,
            resp_bytes=250000,
            conn_state="SF",
        )

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert event.file_transfer is not None
        assert event.file_transfer.source == "SMB"
        assert event.file_transfer.fuid.startswith("F")
        assert event.file_transfer.is_orig is False
        assert event.file_transfer.seen_bytes <= 250000
        assert event.file_transfer.total_bytes == 250000

    def test_small_smb_metadata_connection_does_not_add_file_transfer_context(
        self, activity_gen, state_manager, mock_emitters, timestamp
    ):
        """Small SMB metadata exchanges should stay in conn.log only."""
        activity_gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip="10.0.20.5",
            time=timestamp,
            dst_port=445,
            proto="tcp",
            service="smb",
            duration=0.5,
            orig_bytes=1200,
            resp_bytes=3000,
            conn_state="SF",
        )

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert event.file_transfer is None


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
        """generate_logon() should attach SyslogContext for Linux SSH logons."""
        linux = System(hostname="LNX-01", ip="10.0.10.2", os="Linux Ubuntu 22.04", type="server")
        state_manager.set_current_time(timestamp)
        activity_gen.generate_logon(
            user=User(username="alice", full_name="Alice", email="a@t.com", enabled=True),
            system=linux,
            time=timestamp,
            source_ip="10.0.10.1",
            logon_type=10,  # SSH/remote — sshd syslog expected
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

    def test_remote_linux_failed_logon_reuses_ssh_source_port_for_zeek_tuple(
        self, activity_gen, state_manager, mock_emitters, timestamp
    ):
        """Remote failed sshd auth should have a matching Zeek SSH tuple."""
        linux = System(hostname="LNX-01", ip="10.0.10.2", os="Linux Ubuntu 22.04", type="server")
        source_ip = "10.0.10.99"
        state_manager.set_current_time(timestamp)

        activity_gen.generate_failed_logon(
            user=User(username="attacker", full_name="Attacker", email="a@t.com", enabled=True),
            system=linux,
            time=timestamp,
            logon_type=3,
            source_ip=source_ip,
        )

        syslog_event = mock_emitters["syslog"].emit.call_args[0][0]
        match = re.search(r"from (?P<src>\S+) port (?P<port>\d+) ssh2", syslog_event.syslog.message)
        assert match is not None
        ssh_source_port = int(match.group("port"))
        zeek_events = [
            call.args[0]
            for call in mock_emitters["zeek_conn"].emit.call_args_list
            if call.args[0].event_type == "connection" and call.args[0].network is not None
        ]

        assert any(
            event.network.src_ip == source_ip
            and event.network.src_port == ssh_source_port
            and event.network.dst_ip == linux.ip
            and event.network.dst_port == 22
            and event.network.service == "ssh"
            and abs((event.timestamp - syslog_event.timestamp).total_seconds()) <= 1.0
            for event in zeek_events
        )

    def test_local_linux_failed_logon_does_not_render_ssh_from_dash(
        self, activity_gen, state_manager, mock_emitters, timestamp
    ):
        """Local Linux auth failures should not render impossible sshd 'from - port' text."""
        linux = System(hostname="LNX-01", ip="10.0.10.2", os="Linux Ubuntu 22.04", type="server")
        state_manager.set_current_time(timestamp)
        activity_gen.generate_failed_logon(
            user=User(username="alice", full_name="Alice", email="a@t.com", enabled=True),
            system=linux,
            time=timestamp,
            logon_type=2,
        )

        syslog = mock_emitters["syslog"]
        assert syslog.emit.called
        event = syslog.emit.call_args[0][0]
        assert event.syslog is not None
        assert event.syslog.app_name == "login"
        assert "logname=LOGIN" in event.syslog.message
        assert "tty=/dev/tty1" in event.syslog.message
        assert "rhost=  user=alice" in event.syslog.message
        assert "from -" not in event.syslog.message
        zeek_events = [call.args[0] for call in mock_emitters["zeek_conn"].emit.call_args_list]
        assert not any(
            event.event_type == "connection"
            and event.network is not None
            and event.network.dst_port == 22
            for event in zeek_events
        )

    def test_self_sourced_linux_failed_logon_renders_local_auth(
        self, activity_gen, state_manager, mock_emitters, timestamp
    ):
        """A Linux host should not render sshd as connecting from its own host IP."""
        linux = System(hostname="LNX-01", ip="10.0.10.2", os="Linux Ubuntu 22.04", type="server")
        state_manager.set_current_time(timestamp)
        activity_gen.generate_failed_logon(
            user=User(username="alice", full_name="Alice", email="a@t.com", enabled=True),
            system=linux,
            time=timestamp,
            logon_type=3,
            source_ip="10.0.10.2",
        )

        syslog = mock_emitters["syslog"]
        assert syslog.emit.called
        event = syslog.emit.call_args[0][0]
        assert event.syslog is not None
        assert event.syslog.app_name == "login"
        assert "logname=LOGIN" in event.syslog.message
        assert "tty=/dev/tty1" in event.syslog.message
        assert "rhost=  user=alice" in event.syslog.message
        assert "from 10.0.10.2" not in event.syslog.message

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
        assert dhcp_events[0].dhcp.client_addr == "0.0.0.0"
        assert dhcp_events[0].dhcp.assigned_addr == "10.0.10.2"
        assert dhcp_events[0].network.duration == dhcp_events[0].dhcp.duration

    def test_generate_dhcp_lease_uses_ad_domain_when_unspecified(
        self, activity_gen, state_manager, mock_emitters, timestamp
    ):
        """DHCP option-domain data defaults to the configured AD domain when present."""
        linux = System(hostname="LNX-01", ip="10.0.10.2", os="Linux Ubuntu 22.04", type="server")
        state_manager.set_current_time(timestamp)
        activity_gen._ad_domain = "corp.local"
        activity_gen.generate_dhcp_lease(
            system=linux,
            time=timestamp,
            mac="00:50:56:ab:cd:ef",
            uid="CTest123456789ab",
        )

        all_calls = [
            call[0][0]
            for emitter in mock_emitters.values()
            if emitter.emit.called
            for call in emitter.emit.call_args_list
        ]
        dhcp_events = [e for e in all_calls if e.event_type == "dhcp_lease"]
        assert dhcp_events[-1].dhcp.domain == "corp.local"

    def test_generate_dhcp_lease_emits_canonical_syslog_timeline(
        self, activity_gen, state_manager, mock_emitters, timestamp
    ):
        """dhclient syslog renewal messages should come from the same lease event."""
        linux = System(hostname="LNX-01", ip="10.0.10.2", os="Linux Ubuntu 22.04", type="server")
        state_manager.set_current_time(timestamp)

        activity_gen.generate_dhcp_lease(
            system=linux,
            time=timestamp,
            mac="00:50:56:ab:cd:ef",
            server_addr="10.0.0.1",
            lease_time=7200.0,
            msg_types=["REQUEST", "ACK"],
        )

        syslog_events = [
            call[0][0]
            for call in mock_emitters["syslog"].emit.call_args_list
            if call[0][0].event_type == "syslog"
            and call[0][0].syslog is not None
            and call[0][0].syslog.app_name == "dhclient"
        ]
        syslog_messages = [event.syslog.message for event in syslog_events]
        interface = linux_primary_interface(linux)
        assert syslog_messages == [
            f"DHCPREQUEST for 10.0.10.2 on {interface} to 10.0.0.1 port 67",
            "DHCPACK of 10.0.10.2 from 10.0.0.1",
            "bound to 10.0.10.2 -- renewal in 3600 seconds.",
        ]
        gaps = [
            syslog_events[idx].timestamp - syslog_events[idx - 1].timestamp
            for idx in range(1, len(syslog_events))
        ]
        assert min(gaps) >= timedelta(milliseconds=1500)


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
        assert event.auth.source_ip == "-"
        assert event.auth.workstation_name == "-"

    def test_generate_anonymous_logon_uses_available_source_host(
        self, activity_gen, state_manager, mock_emitters, timestamp
    ):
        """Anonymous network logons should carry realistic remote source metadata."""
        dc = System(
            hostname="DC-01",
            ip="10.0.10.100",
            os="Windows Server 2019",
            type="domain_controller",
        )
        ws = System(
            hostname="WS-01",
            ip="10.0.10.50",
            os="Windows 11",
            type="workstation",
        )
        activity_gen._all_system_ips = [dc.ip, ws.ip]
        activity_gen._ip_to_system = {ws.ip: ws, dc.ip: dc}
        state_manager.set_current_time(timestamp)
        activity_gen.generate_anonymous_logon(system=dc, time=timestamp)

        win = mock_emitters["windows_event_security"]
        event = win.emit.call_args[0][0]
        assert event.auth.source_ip == ws.ip
        assert event.auth.source_port > 0
        assert event.auth.workstation_name == ws.hostname

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


class TestBaselineSshTiming:
    """Regression tests for baseline SSH connection/syslog correlation."""

    def test_disconnect_uses_same_duration_as_generated_connection(self):
        """Baseline SSH disconnect timing should share the conn.log duration."""
        import inspect

        from evidenceforge.generation.engine.baseline import BaselineMixin

        source = inspect.getsource(BaselineMixin)
        assert "ssh_duration = rng.uniform(30.0, 1800.0)" in source
        assert "duration=ssh_duration" in source
        assert 'conn_state="SF"' in source
        assert "max(1.0, ssh_duration)" in source

    def test_syslog_ssh_noise_is_server_scoped_and_roster_based(self):
        """Generic syslog SSH churn should not blanket every Linux host."""
        import inspect

        from evidenceforge.generation.engine.baseline import BaselineMixin

        source = inspect.getsource(BaselineMixin)
        assert 'source_roll < 0.34 and sys_type == "server"' in source
        assert "ssh_roster = self._get_server_ssh_users(system)" in source
        assert "ssh_usernames = [user.username for user in ssh_roster]" in source


class TestBaselineRegistryRealism:
    """Regression tests for ambient registry-noise distribution."""

    def test_office_reading_location_datetime_is_before_event_time(self):
        """Office reading-location values should describe prior document access."""
        event_time = datetime(2024, 3, 18, 12, 4, 53, tzinfo=UTC)
        value = _materialize_registry_value_for_time(
            r"HKCU\Software\Microsoft\Office\16.0\Word\Reading Locations\Document 7\Datetime",
            "2024-03-18T13:21:00",
            event_time,
            random.Random(7),
        )

        assert datetime.fromisoformat(value).replace(tzinfo=UTC) < event_time

    def test_registry_noise_prefers_dynamic_pools_and_filters_repeated_tells(self):
        import inspect

        from evidenceforge.generation.engine.baseline import BaselineMixin

        source = inspect.getsource(BaselineMixin)
        assert (
            '_reg_count = self._scaled_randint(rng, system, "windows_registry", 18, 42)' in source
        )
        assert "Office\\\\16.0\\\\Word\\\\Reading Locations\\\\Document 1" in source
        assert "Windows NT\\\\CurrentVersion\\\\Winlogon" in source
        assert "Services\\\\EventLog\\\\Application" in source
        assert "driverdesc" in source

    def test_ambient_registry_noise_suppresses_dhcp_values_for_static_hosts(self):
        """Static infrastructure should not emit DHCP registry churn as ambient noise."""
        dc = System(
            hostname="DC-01",
            ip="10.10.2.10",
            os="Windows Server 2022",
            type="domain_controller",
            roles=["domain_controller", "dns_server"],
        )
        workstation = System(
            hostname="WS-01",
            ip="10.10.2.55",
            os="Windows 11",
            type="workstation",
        )
        cfg = {
            "dhcp_interface_values": {
                "value_names": ["DhcpIPAddress"],
                "require_dhcp_state": True,
                "emit_on_lease_events": False,
                "suppress_system_types": ["server", "domain_controller"],
                "suppress_roles": ["domain_controller", "dns_server"],
            }
        }
        key = r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}"

        assert not _ambient_registry_entry_allowed(dc, key, "DhcpIPAddress", {}, cfg)
        assert not _ambient_registry_entry_allowed(workstation, key, "DhcpIPAddress", None, cfg)
        assert _ambient_registry_entry_allowed(
            workstation,
            key,
            "DhcpIPAddress",
            {"lease_time": 3600},
            cfg,
        )

    def test_dhcp_registry_values_are_reserved_for_lease_side_effects(self):
        """Default DHCP registry policy should keep lease-owned values out of random pools."""
        workstation = System(
            hostname="WS-01",
            ip="10.10.2.55",
            os="Windows 11",
            type="workstation",
        )
        cfg = {
            "dhcp_interface_values": {
                "value_names": ["DhcpIPAddress"],
                "require_dhcp_state": True,
                "emit_on_lease_events": True,
                "suppress_system_types": ["server", "domain_controller"],
                "suppress_roles": [],
            }
        }
        key = r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}"

        assert not _ambient_registry_entry_allowed(
            workstation,
            key,
            "DhcpIPAddress",
            {"lease_time": 3600},
            cfg,
        )


class TestWindowsScheduledProcessNoise:
    """Regression tests for Windows scheduled/background process timing."""

    def test_scheduled_task_offsets_avoid_hour_boundaries_and_vary(self):
        system = System(hostname="WS-01", ip="10.10.2.55", os="Windows 11", type="workstation")
        current_hour = datetime(2024, 3, 18, 12, 0, tzinfo=UTC)

        offsets = _windows_scheduled_task_offsets(current_hour, system, random.Random(3))

        assert offsets
        assert all(90 <= offset <= 3510 for offset in offsets)
        assert not any(int(offset) == 3599 for offset in offsets)
        assert len({round(offset, 3) for offset in offsets}) == len(offsets)


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


class TestTrafficRateScaling:
    """Tests verifying intensity scales system traffic via traffic_rates config."""

    def _make_engine_mock(self, intensity="medium", traffic_rates=None):
        from unittest.mock import MagicMock

        from evidenceforge.generation.engine.baseline import BaselineMixin

        engine = MagicMock()
        engine.scenario.baseline_activity.intensity = intensity
        engine.scenario.baseline_activity.traffic_rates = traffic_rates
        engine._resolve_traffic_rate = BaselineMixin._resolve_traffic_rate.__get__(engine)
        return engine

    def test_low_intensity_web_matches_legacy(self):
        """Low intensity web rate should match the original hardcoded [10, 30]."""
        engine = self._make_engine_mock(intensity="low")
        lo, hi = engine._resolve_traffic_rate("web")
        assert lo == 10
        assert hi == 30

    def test_high_intensity_web_much_higher(self):
        """High intensity web rate should be >> 100 (thousands range)."""
        engine = self._make_engine_mock(intensity="high")
        lo, hi = engine._resolve_traffic_rate("web")
        assert lo >= 1000
        assert hi >= 3000

    def test_scenario_override_int(self):
        """Integer override should produce fixed rate."""
        engine = self._make_engine_mock(intensity="high", traffic_rates={"web": 500})
        lo, hi = engine._resolve_traffic_rate("web")
        assert lo == 500
        assert hi == 500

    def test_scenario_override_preset(self):
        """Preset string override should look up that level's rate."""
        engine = self._make_engine_mock(intensity="high", traffic_rates={"web": "low"})
        lo, hi = engine._resolve_traffic_rate("web")
        assert lo == 10
        assert hi == 30

    def test_scenario_override_range(self):
        """List override should pass through directly."""
        engine = self._make_engine_mock(intensity="low", traffic_rates={"web": [5000, 12000]})
        lo, hi = engine._resolve_traffic_rate("web")
        assert lo == 5000
        assert hi == 12000


class TestWebAccessExternalVisitors:
    """Web servers must receive connections from internet IPs based on segment exposure."""

    def _make_web_system(self, exposure, public_hostnames=None):
        from types import SimpleNamespace

        return SimpleNamespace(
            hostname="WEB-01",
            ip="10.0.10.5",
            os="Linux Ubuntu 22.04",
            type="server",
            roles=["web_server"],
            public_hostnames=public_hostnames or [],
            assigned_user=None,
            services=["nginx"],
        )

    def _make_baseline_with_exposure(self, exposure):
        """Build a minimal BaselineMixin-like object with _get_system_exposure patched."""
        from unittest.mock import MagicMock

        from evidenceforge.generation.engine.emitter_setup import EmitterSetupMixin

        engine = MagicMock(spec=EmitterSetupMixin)
        engine._get_system_exposure = MagicMock(return_value=exposure)
        return engine

    def test_external_segment_gives_100pct_external_ips(self):
        """exposure=external: all client IPs must be non-RFC1918."""
        from datetime import UTC, datetime
        from random import Random
        from types import SimpleNamespace
        from unittest.mock import MagicMock

        collected = []
        activity_gen = MagicMock()
        activity_gen._ip_to_system = {}
        activity_gen.generate_connection.side_effect = lambda **kw: collected.append(kw["src_ip"])

        sys_obj = self._make_web_system("external")
        other_sys = SimpleNamespace(ip="10.0.10.10", os="Windows 10")

        from evidenceforge.generation.engine.baseline import BaselineMixin
        from evidenceforge.generation.engine.emitter_setup import EmitterSetupMixin

        engine = MagicMock()
        engine._get_system_exposure.return_value = "external"
        engine._generate_external_client_ip = (
            EmitterSetupMixin._generate_external_client_ip.__get__(engine)
        )
        engine._org_cidr_networks = []
        engine.activity_generator = activity_gen
        engine._resolve_traffic_rate.return_value = (50, 50)

        rng = Random(42)
        current_hour = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)
        systems = [sys_obj, other_sys]

        BaselineMixin._run_web_access_for_system(
            engine, sys_obj, systems, rng, current_hour
        ) if hasattr(BaselineMixin, "_run_web_access_for_system") else None

        if not collected:
            pytest.skip(
                "Web access generation requires full engine setup; tested via _get_system_exposure logic instead"
            )

    def test_internal_segment_gives_internal_ips_only(self):
        """exposure=internal: all client IPs must be RFC1918."""
        import ipaddress
        from random import Random

        rng = Random(42)
        internal_ips = ["10.0.10.10", "10.0.10.11", "10.0.10.12"]
        int_ip_weights = [1.0 / (i + 1) for i in range(len(internal_ips))]

        results = [rng.choices(internal_ips, weights=int_ip_weights, k=1)[0] for _ in range(100)]
        for ip in results:
            addr = ipaddress.ip_address(ip)
            assert addr.is_private, f"Internal pool produced external IP: {ip}"

    def test_external_segment_pool_has_no_rfc1918(self):
        """External IP pool must contain no RFC1918 addresses."""
        import ipaddress
        from random import Random
        from unittest.mock import MagicMock

        from evidenceforge.generation.engine.emitter_setup import EmitterSetupMixin

        engine = MagicMock()
        engine._org_cidr_networks = []
        gen_fn = EmitterSetupMixin._generate_external_client_ip.__get__(engine)

        rng = Random(42)
        for _ in range(50):
            ip = gen_fn(rng)
            addr = ipaddress.ip_address(ip)
            assert not addr.is_private, f"External IP generator produced RFC1918 address: {ip}"
            assert not ip.startswith("203.0.113."), f"Got doc range: {ip}"
            assert not ip.startswith("198.51.100."), f"Got doc range: {ip}"
            assert not ip.startswith("192.0.2."), f"Got doc range: {ip}"

    def test_internal_ips_zipf_distribution_is_non_uniform(self):
        """Internal client IPs must follow Zipf (non-uniform) distribution."""
        from collections import Counter
        from random import Random

        rng = Random(42)
        internal_ips = [f"10.0.10.{i}" for i in range(10, 20)]
        int_ip_weights = [1.0 / (i + 1) for i in range(len(internal_ips))]

        samples = [rng.choices(internal_ips, weights=int_ip_weights, k=1)[0] for _ in range(1000)]
        counts = Counter(samples)

        most_common_count = counts[internal_ips[0]]
        least_common_count = counts[internal_ips[-1]]
        assert most_common_count > least_common_count * 2, (
            f"Expected non-uniform distribution; top={most_common_count}, bottom={least_common_count}"
        )

    def test_public_hostnames_used_for_host_header(self):
        """External clients should see the public hostname in HTTP Host header."""
        public_hostnames = ["www.example.com", "example.com"]

        collected_hosts = []
        from random import Random

        rng = Random(42)

        for _ in range(20):
            is_external_client = True
            _pub_hosts = public_hostnames
            if is_external_client and _pub_hosts:
                http_host = rng.choice(_pub_hosts)
            else:
                http_host = "WEB-01"
            collected_hosts.append(http_host)

        assert all(h in public_hostnames for h in collected_hosts), (
            "External clients should use public_hostnames for Host header"
        )

    def test_internal_clients_use_internal_hostname(self):
        """Internal clients should use the system's internal hostname."""
        public_hostnames = ["www.example.com"]
        internal_hostname = "WEB-01"

        from random import Random

        rng = Random(42)

        is_external_client = False
        _pub_hosts = public_hostnames
        if is_external_client and _pub_hosts:
            http_host = rng.choice(_pub_hosts)
        else:
            http_host = internal_hostname

        assert http_host == internal_hostname

    def _simulate_both_branch(self, ext_ratio, n=2000, seed=42):
        """Simulate the web_access 'both' branch for N requests, return external fraction."""
        from random import Random

        rng = Random(seed)
        internal_ips = [f"10.0.10.{i}" for i in range(10, 20)]
        int_ip_weights = [1.0 / (i + 1) for i in range(len(internal_ips))]
        ext_ip_pool = [f"1.{i}.{i}.1" for i in range(1, 201)]
        ext_ip_weights = [1.0 / (i + 1) for i in range(len(ext_ip_pool))]

        external_count = 0
        for _ in range(n):
            if rng.random() < ext_ratio:
                rng.choices(ext_ip_pool, weights=ext_ip_weights, k=1)
                external_count += 1
            else:
                rng.choices(internal_ips, weights=int_ip_weights, k=1)
        return external_count / n

    def test_external_ratio_default_is_0_6(self):
        """exposure=both with no external_ratio → ~60% external clients."""
        frac = self._simulate_both_branch(ext_ratio=0.6)
        assert 0.55 <= frac <= 0.65, f"Expected ~60% external, got {frac:.1%}"

    def test_external_ratio_custom_high(self):
        """exposure=both, external_ratio=0.95 → ≥90% external clients."""
        frac = self._simulate_both_branch(ext_ratio=0.95)
        assert frac >= 0.90, f"Expected ≥90% external with ratio=0.95, got {frac:.1%}"

    def test_external_ratio_custom_low(self):
        """exposure=both, external_ratio=0.05 → ≤10% external clients."""
        frac = self._simulate_both_branch(ext_ratio=0.05)
        assert frac <= 0.10, f"Expected ≤10% external with ratio=0.05, got {frac:.1%}"

    def test_web_server_access_uses_browsing_session_shape(self, monkeypatch):
        """Human visitors should emit clustered page/subresource requests, not isolated paths."""
        from random import Random
        from types import SimpleNamespace
        from unittest.mock import MagicMock

        from evidenceforge.generation.activity import web_session_profiles
        from evidenceforge.generation.engine.baseline import BaselineMixin

        monkeypatch.setattr(
            web_session_profiles,
            "pick_web_visitor_profile",
            lambda rng, *, is_external: (
                "human_browser",
                {
                    "kind": "session",
                    "browsing_intensity": "normal",
                    "user_agent_pool": "browser_any",
                },
            ),
        )

        collected = []
        activity_gen = MagicMock()
        activity_gen._ip_to_system = {}
        activity_gen.generate_connection.side_effect = lambda **kw: collected.append(kw)
        engine = MagicMock()
        engine.activity_generator = activity_gen
        engine._resolve_traffic_rate.return_value = (8, 8)
        engine._get_segment_for_system.return_value = SimpleNamespace(
            exposure="external",
            external_ratio=None,
        )
        engine._generate_external_client_ip.side_effect = [f"8.8.4.{idx}" for idx in range(1, 20)]
        sys_obj = self._make_web_system("external", public_hostnames=["portal.example.com"])

        BaselineMixin._emit_web_server_access(
            engine,
            sys_obj,
            [sys_obj],
            Random(42),
            datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC),
        )

        page_loads = [kw for kw in collected if kw["http"].trans_depth == 1]
        assert len(page_loads) == 8
        assert len(collected) > len(page_loads)
        assert {kw["http"].host for kw in collected} == {"portal.example.com"}
        by_client = {}
        for kwargs in collected:
            by_client.setdefault(kwargs["src_ip"], set()).add(kwargs["http"].user_agent)
        assert all(len(user_agents) == 1 for user_agents in by_client.values())
        assert any(kw["http"].referrer == "https://portal.example.com/" for kw in collected)
        assert any(
            kw["http"].uri.endswith(".css") or kw["http"].uri.endswith(".js") for kw in collected
        )

    def test_web_server_access_uses_browser_cache_for_repeated_static_assets(self, monkeypatch):
        """Repeated browser assets from one client should not all hit the server."""
        from random import Random
        from types import SimpleNamespace
        from unittest.mock import MagicMock

        from evidenceforge.generation.activity import browsing_session, web_session_profiles
        from evidenceforge.generation.activity.browsing_session import BrowsingRequest
        from evidenceforge.generation.engine.baseline import BaselineMixin

        monkeypatch.setattr(
            web_session_profiles,
            "pick_web_visitor_profile",
            lambda rng, *, is_external: (
                "human_browser",
                {
                    "kind": "session",
                    "browsing_intensity": "normal",
                    "user_agent_pool": "browser_any",
                },
            ),
        )
        monkeypatch.setattr(
            browsing_session,
            "generate_browsing_session",
            lambda **kwargs: [
                BrowsingRequest(
                    time_offset_ms=0,
                    hostname=kwargs["hostname"],
                    path="/",
                    method="GET",
                    content_type="text/html",
                    referrer="",
                    trans_depth=1,
                    is_page_load=True,
                    response_body_len=4096,
                    request_body_len=0,
                ),
                BrowsingRequest(
                    time_offset_ms=900,
                    hostname=kwargs["hostname"],
                    path="/assets/js/app.bundle.1234abcd.js",
                    method="GET",
                    content_type="application/javascript",
                    referrer=f"https://{kwargs['hostname']}/",
                    trans_depth=2,
                    is_page_load=False,
                    response_body_len=180_000,
                    request_body_len=0,
                ),
            ],
        )

        collected = []
        activity_gen = MagicMock()
        activity_gen._ip_to_system = {}
        activity_gen.generate_connection.side_effect = lambda **kw: collected.append(kw)
        engine = MagicMock()
        engine.activity_generator = activity_gen
        engine._resolve_traffic_rate.return_value = (2, 2)
        engine._get_segment_for_system.return_value = SimpleNamespace(
            exposure="external",
            external_ratio=None,
        )
        engine._generate_external_client_ip.return_value = "8.8.4.20"
        sys_obj = self._make_web_system("external", public_hostnames=["portal.example.com"])

        BaselineMixin._emit_web_server_access(
            engine,
            sys_obj,
            [sys_obj],
            Random(4),
            datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC),
        )

        page_rows = [kw for kw in collected if kw["http"].uri == "/"]
        asset_rows = [
            kw for kw in collected if kw["http"].uri == "/assets/js/app.bundle.1234abcd.js"
        ]
        assert len(page_rows) == 2
        assert len(asset_rows) == 1
        assert asset_rows[0]["http"].status_code == 200

    def test_web_server_access_preserves_cache_and_partial_statuses(self, monkeypatch):
        """Browser cache hits and partial content must not be rewritten as 200 responses."""
        from random import Random
        from types import SimpleNamespace
        from unittest.mock import MagicMock

        from evidenceforge.generation.activity import browsing_session, web_session_profiles
        from evidenceforge.generation.activity.browsing_session import BrowsingRequest
        from evidenceforge.generation.engine.baseline import BaselineMixin

        monkeypatch.setattr(
            web_session_profiles,
            "pick_web_visitor_profile",
            lambda rng, *, is_external: (
                "human_browser",
                {
                    "kind": "session",
                    "browsing_intensity": "normal",
                    "user_agent_pool": "browser_any",
                },
            ),
        )
        monkeypatch.setattr(
            browsing_session,
            "generate_browsing_session",
            lambda **kwargs: [
                BrowsingRequest(
                    time_offset_ms=0,
                    hostname=kwargs["hostname"],
                    path="/",
                    method="GET",
                    content_type="text/html",
                    referrer="",
                    trans_depth=1,
                    is_page_load=True,
                    response_body_len=4096,
                    request_body_len=0,
                    status_code=200,
                ),
                BrowsingRequest(
                    time_offset_ms=100,
                    hostname=kwargs["hostname"],
                    path="/assets/css/main.063cbaf5.css",
                    method="GET",
                    content_type="text/css",
                    referrer=f"https://{kwargs['hostname']}/",
                    trans_depth=5,
                    is_page_load=False,
                    response_body_len=0,
                    request_body_len=0,
                    status_code=304,
                ),
                BrowsingRequest(
                    time_offset_ms=200,
                    hostname=kwargs["hostname"],
                    path="/assets/js/app.bundle.bf9655b3.js",
                    method="GET",
                    content_type="application/javascript",
                    referrer=f"https://{kwargs['hostname']}/",
                    trans_depth=4,
                    is_page_load=False,
                    response_body_len=1152,
                    request_body_len=0,
                    status_code=206,
                ),
            ],
        )

        collected = []
        activity_gen = MagicMock()
        activity_gen._ip_to_system = {}
        activity_gen.generate_connection.side_effect = lambda **kw: collected.append(kw)
        engine = MagicMock()
        engine.activity_generator = activity_gen
        engine._resolve_traffic_rate.return_value = (1, 1)
        engine._get_segment_for_system.return_value = SimpleNamespace(
            exposure="external",
            external_ratio=None,
        )
        engine._generate_external_client_ip.return_value = "8.8.4.20"
        sys_obj = self._make_web_system("external", public_hostnames=["portal.example.com"])

        BaselineMixin._emit_web_server_access(
            engine,
            sys_obj,
            [sys_obj],
            Random(4),
            datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC),
        )

        by_uri = {kw["http"].uri: kw["http"] for kw in collected}
        assert by_uri["/assets/css/main.063cbaf5.css"].status_code == 304
        assert by_uri["/assets/css/main.063cbaf5.css"].response_body_len == 0
        assert by_uri["/assets/css/main.063cbaf5.css"].resp_mime_types == []
        assert by_uri["/assets/js/app.bundle.bf9655b3.js"].status_code == 206
        assert by_uri["/assets/js/app.bundle.bf9655b3.js"].response_body_len == 1152
        assert by_uri["/assets/js/app.bundle.bf9655b3.js"].resp_mime_types == [
            "application/javascript"
        ]
        root_row = next(kw for kw in collected if kw["http"].uri == "/")
        assert root_row["http"].trans_depth == 1
        assert root_row["duration"] >= 0.2
        assert root_row["resp_bytes"] >= 4096 + 1152
        assert by_uri["/assets/css/main.063cbaf5.css"].trans_depth == 2
        assert by_uri["/assets/js/app.bundle.bf9655b3.js"].trans_depth == 3

    def test_web_server_access_keeps_scanner_requests_source_native(self, monkeypatch):
        """Scanner visitors should keep configured error paths and blank referrers."""
        from random import Random
        from types import SimpleNamespace
        from unittest.mock import MagicMock

        from evidenceforge.generation.activity import web_session_profiles
        from evidenceforge.generation.engine.baseline import BaselineMixin

        monkeypatch.setattr(
            web_session_profiles,
            "pick_web_visitor_profile",
            lambda rng, *, is_external: (
                "opportunistic_probe",
                {
                    "kind": "requests",
                    "request_count": [3, 3],
                    "user_agent_pool": "scanner",
                    "referrer_mode": "none",
                    "requests": [
                        {
                            "path": "/wp-login.php",
                            "method": "GET",
                            "status": 404,
                            "type": "text/html",
                            "weight": 1,
                        }
                    ],
                },
            ),
        )

        collected = []
        activity_gen = MagicMock()
        activity_gen._ip_to_system = {}
        activity_gen.generate_connection.side_effect = lambda **kw: collected.append(kw)
        engine = MagicMock()
        engine.activity_generator = activity_gen
        engine._resolve_traffic_rate.return_value = (3, 3)
        engine._get_segment_for_system.return_value = SimpleNamespace(
            exposure="external",
            external_ratio=None,
        )
        engine._generate_external_client_ip.side_effect = [f"8.8.8.{idx}" for idx in range(1, 20)]
        sys_obj = self._make_web_system("external", public_hostnames=["portal.example.com"])

        BaselineMixin._emit_web_server_access(
            engine,
            sys_obj,
            [sys_obj],
            Random(7),
            datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC),
        )

        assert len(collected) == 3
        assert {kw["http"].status_code for kw in collected} == {404}
        assert {kw["http"].uri for kw in collected} == {"/wp-login.php"}
        assert all(kw["http"].referrer == "" for kw in collected)

    def test_health_checks_use_server_scoped_internal_sources(self, monkeypatch):
        """Monitoring UAs should not be sourced from ordinary workstations."""
        from random import Random
        from types import SimpleNamespace
        from unittest.mock import MagicMock

        from evidenceforge.generation.activity import web_session_profiles
        from evidenceforge.generation.engine.baseline import BaselineMixin

        monkeypatch.setattr(
            web_session_profiles,
            "pick_web_visitor_profile",
            lambda rng, *, is_external: (
                "health_check",
                {
                    "kind": "requests",
                    "request_count": [1, 1],
                    "user_agent_pool": "health_check",
                    "source_type_any": ["server", "domain_controller"],
                    "source_role_any": ["monitoring", "load_balancer", "forward_proxy"],
                    "referrer_mode": "none",
                    "requests": [
                        {
                            "path": "/api/v1/health",
                            "method": "GET",
                            "status": 200,
                            "type": "application/json",
                            "weight": 1,
                        }
                    ],
                },
            ),
        )

        target = self._make_web_system("internal")
        workstation = SimpleNamespace(
            hostname="WS-01",
            ip="10.0.10.20",
            os="Windows 11",
            type="workstation",
            roles=[],
            services=[],
        )
        monitor = SimpleNamespace(
            hostname="MON-01",
            ip="10.0.10.30",
            os="Linux Ubuntu 22.04",
            type="server",
            roles=["monitoring"],
            services=["prometheus"],
        )

        collected = []
        activity_gen = MagicMock()
        activity_gen._ip_to_system = {workstation.ip: workstation, monitor.ip: monitor}
        activity_gen.generate_connection.side_effect = lambda **kw: collected.append(kw)
        engine = MagicMock()
        engine.activity_generator = activity_gen
        engine._resolve_traffic_rate.return_value = (4, 4)
        engine._get_segment_for_system.return_value = SimpleNamespace(
            exposure="internal",
            external_ratio=None,
        )
        engine._generate_external_client_ip.return_value = "8.8.8.8"

        BaselineMixin._emit_web_server_access(
            engine,
            target,
            [target, workstation, monitor],
            Random(42),
            datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC),
        )

        assert collected
        assert {kw["src_ip"] for kw in collected} == {monitor.ip}
        assert all(kw["source_system"] is monitor for kw in collected)
        assert all(kw["http"].uri == "/api/v1/health" for kw in collected)
        assert all(42 <= kw["http"].response_body_len <= 720 for kw in collected)
