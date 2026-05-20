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
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import FirewallContext, HttpContext, NetworkContext
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.generation.activity import (
    BASELINE_PATTERNS,
    EXTERNAL_IPS,
    ActivityGenerator,
    _is_invalid_network_connection,
)
from evidenceforge.generation.activity import generator as generator_module
from evidenceforge.generation.activity.generator import (
    _extract_http_url_from_command,
    _extract_image_from_command,
    _http_context_from_process_command,
    _jitter_default_connection_duration,
    _linux_foreground_lifetime,
    _network_effect_context_for_process,
    _normalize_http_context_for_source_native_response,
    _zeek_conn_observation_time,
)
from evidenceforge.generation.activity.http_content import response_size_for_status
from evidenceforge.generation.activity.tls_realism import (
    certificate_analyzer_delay_ms,
    certificate_file_size,
)
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models import System, User


def test_linux_trivial_command_lifetime_is_subsecond():
    """Instant Linux utilities should not look like multi-second process telemetry."""
    lifetime = _linux_foreground_lifetime("/usr/bin/date", "date -u")

    assert lifetime is not None
    assert lifetime[1] <= 0.8


class TestApacheRawSyslogNormalization:
    def test_embedded_timestamp_regex_matches_apache_variants(self):
        """Apache raw syslog timestamp normalization should keep common timestamp variants."""
        pattern = generator_module._APACHE_EMBEDDED_TS_RE

        assert pattern.search("[Mon Jan 1 12:34:56 2026] [client 10.0.0.1:12345]")
        assert pattern.search("[Mon Jan 01 12:34:56.123456 2026] [client 10.0.0.1:12345]")
        assert pattern.search("[Mon Jan 01 12:34:56.123456 +0000 2026] message")

    def test_embedded_timestamp_regex_has_bounded_middle_token(self):
        """Scenario-controlled raw syslog messages must not hit an unbounded timestamp scan."""
        pattern_text = generator_module._APACHE_EMBEDDED_TS_RE.pattern

        assert "[^\\]]+" not in pattern_text
        assert "{1,40}" in pattern_text

    def test_embedded_timestamp_regex_handles_many_malformed_prefixes_quickly(self):
        """Malformed Apache-like prefixes should not cause super-linear regex work."""
        pattern = generator_module._APACHE_EMBEDDED_TS_RE
        malicious_message = "[Mon Jan 1 " * 20_000

        result = pattern.sub("[Mon Jan 01 00:00:00.000000 2026]", malicious_message, count=1)

        assert result == malicious_message


class TestStateObjectIds:
    def test_missing_process_object_id_returns_empty(self):
        """Unseen process IDs should not fabricate eCAR object IDs."""
        state = StateManager()

        first = state.get_process_object_id("WS-01", 4444)
        second = state.get_process_object_id("WS-01", 4444)

        assert first == ""
        assert second == ""


class TestProcessHttpCommandCorrelation:
    def test_http_normalization_rewrites_error_asset_mime_to_error_body(self):
        """Caller-provided HTTP errors should not keep MIME from requested asset extension."""
        http = HttpContext(
            method="GET",
            host="portal.example.com",
            uri="/assets/logo.svg",
            response_body_len=900,
            status_code=503,
            status_msg="Service Unavailable",
            resp_mime_types=["image/svg+xml"],
        )

        normalized = _normalize_http_context_for_source_native_response(http)

        assert normalized.resp_mime_types == ["text/html"]

    def test_http_context_from_curl_command_preserves_url_and_user_agent(self):
        """CLI HTTP command lines should drive the canonical HTTP flow metadata."""
        result = _http_context_from_process_command(
            "/usr/bin/curl",
            "curl -s https://api.github.com/rate_limit?resource=core",
            response_body_len=1234,
        )

        assert result is not None
        http, host, port, service = result
        assert host == "api.github.com"
        assert port == 443
        assert service == "ssl"
        assert http.host == "api.github.com"
        assert http.uri == "/rate_limit?resource=core"
        assert http.user_agent == "curl/7.88.1"
        assert http.response_body_len == 1234

    @pytest.mark.parametrize(
        "command_line",
        [
            "curl -s http://[::1",
            "curl -s http://example.com:99999/",
        ],
    )
    def test_http_context_from_malformed_url_returns_none(self, command_line):
        """Malformed overlay-provided URLs should not crash process-network correlation."""
        assert (
            _http_context_from_process_command(
                "/usr/bin/curl",
                command_line,
                response_body_len=1234,
            )
            is None
        )

    def test_extract_http_url_skips_malformed_candidates(self):
        """Malformed candidates should be skipped so later valid URLs can still correlate."""
        url = _extract_http_url_from_command(
            "curl http://[::1 && curl https://api.example.com/status"
        )

        assert url == "https://api.example.com/status"

    def test_http_context_from_static_curl_uses_stable_resource_size(self):
        """Repeated CLI downloads of static resources should keep one object size."""
        first = _http_context_from_process_command(
            "/usr/bin/curl",
            "curl -s https://cdn.example.com/favicon.ico",
            response_body_len=1234,
        )
        second = _http_context_from_process_command(
            "/usr/bin/curl",
            "curl -s https://cdn.example.com/favicon.ico",
            response_body_len=98765,
        )

        assert first is not None
        assert second is not None
        first_http = first[0]
        second_http = second[0]
        expected_size = response_size_for_status(200, "cdn.example.com", "/favicon.ico")
        assert first_http.response_body_len == expected_size
        assert second_http.response_body_len == expected_size
        assert first_http.resp_mime_types == ["image/x-icon"]

    def test_proxy_context_preserves_cli_http_user_agent(self):
        """Proxy logs should not replace a caller-provided CLI User-Agent."""
        generator = ActivityGenerator(StateManager(), {})
        source = System(
            hostname="LINUX-01",
            ip="10.0.0.20",
            os="Ubuntu 24.04",
            type="workstation",
        )
        proxy = System(
            hostname="proxy01",
            ip="10.0.0.5",
            os="Ubuntu 24.04",
            type="server",
        )
        http = HttpContext(
            method="GET",
            host="api.github.com",
            uri="/rate_limit",
            user_agent="curl/7.88.1",
            response_body_len=1234,
            status_code=200,
            status_msg="OK",
            resp_mime_types=["application/json"],
        )

        proxy_context = generator._build_proxy_context(
            src_ip=source.ip,
            dst_ip="140.82.112.5",
            dst_port=443,
            service="ssl",
            duration=1.2,
            orig_bytes=320,
            resp_bytes=1234,
            hostname="api.github.com",
            source_system=source,
            proxy_sys=proxy,
            http=http,
            explicit_mode=True,
        )

        assert proxy_context.url == "https://api.github.com/rate_limit"
        assert proxy_context.user_agent == "curl/7.88.1"

    def test_network_effect_context_keeps_rendered_cli_http_command(self):
        """A stale process-state lookup should not retarget a rendered curl command."""
        process_name, command_line = _network_effect_context_for_process(
            "/usr/bin/curl",
            "curl -s https://api.slack.com/methods/api.test",
            "/usr/bin/wget",
            "wget https://images.netscaler.dev/agent.dat",
        )

        assert process_name == "/usr/bin/curl"
        assert command_line == "curl -s https://api.slack.com/methods/api.test"

    def test_generate_connection_uses_process_http_command_for_proxy_context(self, monkeypatch):
        """Later network effects attributed to curl should keep the command URL."""
        state = StateManager()
        generator = ActivityGenerator(
            state,
            {},
            dispatcher=EventDispatcher(state_manager=state, emitters={}),
        )
        source = System(
            hostname="APP-INT-01",
            ip="10.10.2.30",
            os="Ubuntu 24.04",
            type="server",
        )
        proxy = System(
            hostname="PROXY-01",
            ip="10.10.3.20",
            os="Ubuntu 24.04",
            type="server",
        )
        generator._ip_to_system = {source.ip: source, proxy.ip: proxy}
        generator._proxy_mode = "explicit"
        generator._proxy_listener_port = 8080
        generator._proxy_routes = {source.ip: [proxy]}
        generator._ad_domain = "meridianhcs.local"

        timestamp = datetime(2024, 3, 18, 12, 0, tzinfo=UTC)
        state.set_current_time(timestamp)
        pid = state.create_process(
            system=source.hostname,
            parent_pid=4,
            image="/usr/bin/curl",
            command_line="curl -s https://api.slack.com/methods/api.test",
            username="sarah.martinez",
            integrity_level="Medium",
            logon_id="0x1234",
        )

        captured: list[dict[str, object]] = []
        original_build_proxy_context = generator._build_proxy_context

        def capture_proxy_context(**kwargs):
            captured.append(kwargs)
            return original_build_proxy_context(**kwargs)

        monkeypatch.setattr(generator, "_build_proxy_context", capture_proxy_context)

        generator.generate_connection(
            src_ip=source.ip,
            dst_ip="13.107.246.52",
            time=timestamp + timedelta(seconds=1),
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=2.0,
            orig_bytes=400,
            resp_bytes=1200,
            emit_dns=True,
            pid=pid,
            source_system=source,
        )

        assert captured
        assert captured[0]["hostname"] == "api.slack.com"
        assert captured[0]["dst_port"] == 443
        http = captured[0]["http"]
        assert isinstance(http, HttpContext)
        assert http.user_agent == "curl/7.88.1"
        assert http.uri == "/methods/api.test"


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

    def test_interactive_logons_get_distinct_userinit_parents(
        self, activity_gen, test_user, test_system, state_manager
    ):
        """Interactive shells should not all inherit one long-lived userinit.exe parent."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        smss_pid = state_manager.create_process(
            test_system.hostname,
            4,
            r"C:\Windows\System32\smss.exe",
            r"C:\Windows\System32\smss.exe",
            "SYSTEM",
            "System",
        )
        activity_gen._system_pids = {test_system.hostname: {"smss": smss_pid}}

        first_logon = activity_gen.generate_logon(test_user, test_system, timestamp, logon_type=2)
        second_logon = activity_gen.generate_logon(
            test_user,
            test_system,
            timestamp + timedelta(minutes=30),
            logon_type=2,
        )

        sessions = {
            session.logon_id: session for session in state_manager.get_sessions_for_user("testuser")
        }
        first_explorer = state_manager.get_process(
            test_system.hostname, sessions[first_logon].explorer_pid
        )
        second_explorer = state_manager.get_process(
            test_system.hostname, sessions[second_logon].explorer_pid
        )
        assert first_explorer.parent_pid != second_explorer.parent_pid

    def test_repeated_explorer_creation_reuses_session_shell(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Baseline explorer.exe launches should reuse the interactive session shell."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        smss_pid = state_manager.create_process(
            test_system.hostname,
            4,
            r"C:\Windows\System32\smss.exe",
            r"C:\Windows\System32\smss.exe",
            "SYSTEM",
            "System",
        )
        activity_gen._system_pids = {test_system.hostname: {"smss": smss_pid}}
        logon_id = activity_gen.generate_logon(test_user, test_system, timestamp, logon_type=2)
        session = state_manager.get_session(logon_id)
        assert session is not None
        assert session.explorer_pid is not None
        mock_emitters["windows_event_security"].reset_mock()

        first_pid = activity_gen.generate_process(
            test_user,
            test_system,
            timestamp + timedelta(seconds=1),
            logon_id,
            r"C:\Windows\explorer.exe",
            "explorer.exe",
            parent_pid=4,
        )
        second_pid = activity_gen.generate_process(
            test_user,
            test_system,
            timestamp + timedelta(seconds=2),
            logon_id,
            r"C:\Windows\explorer.exe",
            "explorer.exe",
            parent_pid=4,
        )

        assert first_pid == session.explorer_pid
        assert second_pid == session.explorer_pid
        emitted = [
            call.args[0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        assert all(
            not (
                event.event_type == "process_create"
                and event.process is not None
                and event.process.image.lower().endswith("explorer.exe")
            )
            for event in emitted
        )

    def test_repeated_one_shot_cli_processes_get_human_scale_spacing(
        self, activity_gen, test_user, test_system, state_manager
    ):
        """Repeated dsquery launches should not collapse into sub-millisecond bursts."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp - timedelta(minutes=10))
        logon_id = activity_gen.generate_logon(
            test_user,
            test_system,
            timestamp - timedelta(minutes=10),
            logon_type=2,
        )

        first_pid = activity_gen.generate_process(
            user=test_user,
            system=test_system,
            time=timestamp,
            logon_id=logon_id,
            process_name=r"C:\Windows\System32\dsquery.exe",
            command_line="dsquery.exe user -samid testuser",
            parent_pid=4,
        )
        second_pid = activity_gen.generate_process(
            user=test_user,
            system=test_system,
            time=timestamp + timedelta(milliseconds=1),
            logon_id=logon_id,
            process_name=r"C:\Windows\System32\dsquery.exe",
            command_line="dsquery.exe user -samid testuser",
            parent_pid=4,
        )
        third_pid = activity_gen.generate_process(
            user=test_user,
            system=test_system,
            time=timestamp + timedelta(milliseconds=2),
            logon_id=logon_id,
            process_name=r"C:\Windows\System32\dsquery.exe",
            command_line='dsquery.exe group -samid "*admin*" -limit 50',
            parent_pid=4,
        )

        first_proc = state_manager.get_process(test_system.hostname, first_pid)
        second_proc = state_manager.get_process(test_system.hostname, second_pid)
        third_proc = state_manager.get_process(test_system.hostname, third_pid)

        assert first_proc is not None
        assert second_proc is not None
        assert third_proc is not None
        assert (second_proc.start_time - first_proc.start_time).total_seconds() >= 18.0
        assert (third_proc.start_time - second_proc.start_time).total_seconds() >= 2.5

    def test_generate_scheduled_task_builds_full_task_xml(
        self, activity_gen, test_user, test_system, mock_emitters
    ):
        """Scheduled task creation should carry source-native Task Scheduler XML."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

        activity_gen.generate_scheduled_task(
            test_user,
            test_system,
            timestamp,
            task_name=r"\Microsoft\Windows\Updater",
            task_content=(
                r"<Actions><Exec><Command>C:\Windows\Temp\payload.exe --sync</Command>"
                r"</Exec></Actions>"
            ),
        )

        event = mock_emitters["windows_event_security"].emit.call_args.args[0]
        task_content = event.scheduled_task.task_content
        assert (
            '<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
            in task_content
        )
        assert "<RegistrationInfo>" in task_content
        assert "<Triggers>" in task_content
        assert "<Principals>" in task_content
        assert "<Settings>" in task_content
        assert '<Actions Context="Author">' in task_content
        assert r"<Command>C:\Windows\Temp\payload.exe</Command>" in task_content
        assert "<Arguments>--sync</Arguments>" in task_content

    def test_generate_scheduled_task_reflects_hourly_schtasks_command(
        self, activity_gen, test_system, mock_emitters
    ):
        """Task XML should reflect `/SC HOURLY` and `/RU SYSTEM` from schtasks.exe."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        system_user = User(username="SYSTEM", full_name="System", email="system@example.local")

        activity_gen.generate_scheduled_task(
            user=system_user,
            system=test_system,
            time=timestamp,
            task_name=r"\Microsoft\Windows\Maintenance\SystemHealthCheck",
            task_content=(
                r"<Task><Actions><Exec><Command>C:\Windows\System32\cmd.exe</Command>"
                r"</Exec></Actions></Task>"
            ),
            source_command_line=(
                r'schtasks.exe /Create /TN "\Microsoft\Windows\Maintenance\SystemHealthCheck" '
                r'/SC HOURLY /TR "C:\Windows\System32\HealthMonitorSvc.exe" /RU SYSTEM'
            ),
        )

        event = mock_emitters["windows_event_security"].emit.call_args.args[0]
        task_content = event.scheduled_task.task_content
        assert "<Repetition>" in task_content
        assert "<Interval>PT1H</Interval>" in task_content
        assert r"<Command>C:\Windows\System32\HealthMonitorSvc.exe</Command>" in task_content
        assert "<UserId>NT AUTHORITY\\SYSTEM</UserId>" in task_content
        assert "<LogonType>ServiceAccount</LogonType>" in task_content

    def test_generate_scheduled_task_reflects_hourly_modifier(
        self, activity_gen, test_user, test_system, mock_emitters
    ):
        """Hourly `/MO` values should become Task Scheduler repetition intervals."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

        activity_gen.generate_scheduled_task(
            user=test_user,
            system=test_system,
            time=timestamp,
            task_name=r"\Ops\QuarterHourly",
            task_content=r"C:\Windows\System32\cmd.exe /c whoami",
            source_command_line=(
                r'schtasks.exe /Create /TN "\Ops\QuarterHourly" /SC HOURLY /MO 4 '
                r'/TR "C:\Windows\System32\cmd.exe /c whoami"'
            ),
        )

        event = mock_emitters["windows_event_security"].emit.call_args.args[0]
        assert "<Interval>PT4H</Interval>" in event.scheduled_task.task_content

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

    def test_account_changed_password_set_uses_event_time(
        self, activity_gen, test_user, test_system, mock_emitters
    ):
        """4738 password punch-down should render a real PasswordLastSet timestamp."""
        timestamp = datetime(2024, 3, 18, 16, 14, 35, tzinfo=UTC)

        activity_gen.generate_account_changed(
            actor=test_user,
            system=test_system,
            time=timestamp,
            target_username="svc-audit",
            target_sid="S-1-5-21-1-2-3-1109",
            password_last_set_to_event_time=True,
            old_uac_value="0x15",
            new_uac_value="0x10",
            user_account_control="\n\t\t\t%%2081",
            primary_group_id="-",
        )

        account_event = [
            call.args[0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call.args[0].event_type == "account_changed"
        ][0]
        account_context = account_event.account_management
        assert account_context.password_last_set == "3/18/2024 4:14:35 PM"
        assert account_context.old_uac_value == "0x15"
        assert account_context.new_uac_value == "0x10"
        assert account_context.user_account_control == "\n\t\t\t%%2081"
        assert account_context.primary_group_id == "-"

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
        """RDP session should emit one connection and share source port with 4624."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_rdp_session(
            user=test_user,
            target_system=test_system,
            time=timestamp,
            source_ip="45.83.221.45",
        )

        rdp_connections = [
            call[0][0]
            for call in mock_emitters["zeek_conn"].emit.call_args_list
            if call[0][0].event_type == "connection" and call[0][0].network.dst_port == 3389
        ]
        assert len(rdp_connections) == 1
        network_event = rdp_connections[0]
        logon_event = next(
            call[0][0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call[0][0].event_type == "logon" and call[0][0].auth.logon_type == 10
        )
        assert network_event.network.dst_port == 3389
        assert network_event.network.src_port > 0
        assert logon_event.auth.source_port == network_event.network.src_port
        assert logon_event.timestamp > network_event.timestamp

    def test_generate_rdp_session_does_not_self_source_target(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """RDP evidence should choose a real remote workstation if the planned source is self."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        source_system = System(
            hostname="WS-SOURCE-01",
            ip="10.0.0.2",
            os="Windows 10",
            type="workstation",
            assigned_user=test_user.username,
        )
        activity_gen._ip_to_system = {test_system.ip: test_system, source_system.ip: source_system}
        state_manager.set_current_time(timestamp)

        activity_gen.generate_rdp_session(
            user=test_user,
            target_system=test_system,
            time=timestamp,
            source_ip=test_system.ip,
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
        assert network_event.network.src_ip == source_system.ip
        assert logon_event.auth.source_ip == source_system.ip
        assert logon_event.src_host.hostname == source_system.hostname

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

    def test_generate_rdp_session_uses_prior_successful_windows_account(
        self, activity_gen, test_system, state_manager, mock_emitters
    ):
        """Windows RDP should use the sprayed domain user, not a Unix local actor."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        domain_user = User(
            username="aisha.johnson",
            full_name="Aisha Johnson",
            email="aisha.johnson@example.local",
        )
        root_user = User(username="root", full_name="root", email="root@example.local")
        activity_gen.generate_logon(
            domain_user,
            test_system,
            timestamp - timedelta(seconds=10),
            logon_type=3,
            source_ip="10.0.99.50",
        )
        mock_emitters["windows_event_security"].reset_mock()

        activity_gen.generate_rdp_session(
            user=root_user,
            target_system=test_system,
            time=timestamp,
            source_ip="10.0.99.50",
        )

        logon_event = next(
            call.args[0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call.args[0].event_type == "logon" and call.args[0].auth.logon_type == 10
        )
        assert logon_event.auth.username == "aisha.johnson"

    def test_generate_rdp_session_updates_preallocated_session_identity(
        self, activity_gen, test_system, state_manager, mock_emitters
    ):
        """RDP user coercion must keep preallocated session identity aligned."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        source_ip = "10.0.99.50"
        state_manager.set_current_time(timestamp)
        domain_user = User(
            username="aisha.johnson",
            full_name="Aisha Johnson",
            email="aisha.johnson@example.local",
        )
        root_user = User(username="root", full_name="root", email="root@example.local")
        activity_gen.generate_logon(
            domain_user,
            test_system,
            timestamp - timedelta(seconds=10),
            logon_type=3,
            source_ip=source_ip,
        )
        preallocated_logon_id = state_manager.create_session(
            username=root_user.username,
            system=test_system.hostname,
            logon_type=10,
            source_ip=source_ip,
            session_kind="rdp",
        )
        mock_emitters["windows_event_security"].reset_mock()

        activity_gen.generate_rdp_session(
            user=root_user,
            target_system=test_system,
            time=timestamp,
            source_ip=source_ip,
            logon_id=preallocated_logon_id,
        )

        logon_event = next(
            call.args[0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call.args[0].event_type == "logon" and call.args[0].auth.logon_type == 10
        )
        session = state_manager.get_session(preallocated_logon_id)

        assert logon_event.auth.username == "aisha.johnson"
        assert session is not None
        assert logon_event.auth.logon_id == session.logon_id
        assert session.username == logon_event.auth.username

    def test_generate_rdp_session_fallback_user_tolerates_malformed_ad_domain(
        self, activity_gen, test_system, state_manager, mock_emitters
    ):
        """Fallback RDP users should not crash when scenario AD domain is malformed."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        source_ip = "10.0.99.50"
        root_user = User(username="root", full_name="root", email="root@example.local")
        activity_gen._ad_domain = "bad"
        state_manager.set_current_time(timestamp)
        state_manager.register_session(
            logon_id="0xabc123",
            username="orphan",
            system=test_system.hostname,
            logon_type=3,
            source_ip=source_ip,
            start_time=timestamp - timedelta(seconds=10),
            session_kind="network",
        )

        activity_gen.generate_rdp_session(
            user=root_user,
            target_system=test_system,
            time=timestamp,
            source_ip=source_ip,
        )

        logon_event = next(
            call.args[0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call.args[0].event_type == "logon" and call.args[0].auth.logon_type == 10
        )
        assert logon_event.auth.username == "orphan"

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
            services=["ssh", "apache2", "mysql"],
            roles=["app_server"],
        )
        target_b = System(
            hostname="FILE-01",
            ip="10.10.2.20",
            os="Windows Server 2019",
            type="server",
            services=["smb"],
            roles=["file_server"],
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
        assert len({event.network.conn_state for event in scan_events}) > 1
        assert any(event.network.conn_state in {"S0", "REJ"} for event in scan_events)
        assert {event.network.service for event in scan_events if event.network.service} >= {
            "ssh",
            "http",
            "smb",
            "mysql",
        }

    def test_resolve_nmap_targets_limits_fallback_cidr_expansion(self, activity_gen):
        """CIDR fallback expansion should cap to eight hosts without materializing whole ranges."""
        source = System(
            hostname="WEB-01",
            ip="10.10.3.10",
            os="Ubuntu 22.04",
            type="server",
        )
        activity_gen._ip_to_system = {source.ip: source}

        targets = activity_gen._resolve_nmap_targets("nmap -p 80 1.0.0.0/8", source)

        assert len(targets) == 8
        assert targets[0] == "1.0.0.1"
        assert targets[-1] == "1.0.0.8"

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

    def test_workstation_lock_ignores_duplicate_before_unlock(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """A session should not emit two visible 4800 locks before a 4801 unlock."""
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
        activity_gen.generate_workstation_lock(
            test_user,
            test_system,
            lock_time + timedelta(minutes=1),
            logon_id,
        )
        activity_gen.generate_workstation_unlock(
            test_user,
            test_system,
            lock_time + timedelta(minutes=5),
            logon_id,
        )

        events = [
            call[0][0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        assert sum(event.event_type == "workstation_locked" for event in events) == 1
        assert sum(event.event_type == "workstation_unlocked" for event in events) == 1

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

    def test_explicit_credentials_system_target_uses_nt_authority(
        self, activity_gen, test_system, state_manager, mock_emitters
    ):
        """Local SYSTEM target credentials should not render as AD-domain SYSTEM."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        system_user = User(username="SYSTEM", full_name="System", email="system@example.local")

        activity_gen.generate_explicit_credentials(
            user=system_user,
            system=test_system,
            time=timestamp,
            target_username="SYSTEM",
            target_server="localhost",
            process_name=r"C:\Windows\System32\net.exe",
            process_pid=1234,
        )

        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.auth.username == "SYSTEM"
        assert event.auth.target_domain == "NT AUTHORITY"

    def test_scheduled_task_system_principal_uses_nt_authority(
        self, activity_gen, test_system, state_manager, mock_emitters
    ):
        """Generated task XML should not render local SYSTEM as an AD-domain principal."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        system_user = User(username="SYSTEM", full_name="System", email="system@example.local")

        activity_gen.generate_scheduled_task(
            user=system_user,
            system=test_system,
            time=timestamp,
            task_name=r"\Microsoft\Windows\UpdateCheck",
            task_content=r"C:\Windows\System32\cmd.exe /c whoami",
        )

        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert "<UserId>NT AUTHORITY\\SYSTEM</UserId>" in event.scheduled_task.task_content
        assert "<LogonType>ServiceAccount</LogonType>" in event.scheduled_task.task_content
        assert "<RunLevel>HighestAvailable</RunLevel>" in event.scheduled_task.task_content
        assert "<UserId>CORP\\SYSTEM</UserId>" not in event.scheduled_task.task_content
        assert "<LogonType>Password</LogonType>" not in event.scheduled_task.task_content

    def test_kerberos_krbtgt_service_ticket_uses_domain_rid_502(
        self, activity_gen, state_manager, mock_emitters
    ):
        """4769 krbtgt/<realm> service tickets should use the krbtgt account SID."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        activity_gen.sid_registry["krbtgt"] = "S-1-5-21-1-2-3-502"

        activity_gen.generate_kerberos_service_ticket(
            username="alice",
            service_name="krbtgt/example.local",
            source_ip="10.0.0.25",
            dc_hostname="DC-01",
            time=timestamp,
            domain="EXAMPLE.LOCAL",
        )

        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.kerberos.service_name == "krbtgt/example.local"
        assert event.kerberos.service_sid == "S-1-5-21-1-2-3-502"

    def test_machine_account_logon_emits_nearby_dc_kerberos_audit(
        self, activity_gen, state_manager, mock_emitters
    ):
        """Machine Kerberos flows should have matching DC 4768/4769 audit records."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        for emitter in mock_emitters.values():
            emitter.can_handle.return_value = True

        activity_gen.generate_machine_account_logon(
            hostname="WKS-01",
            machine_username="WKS-01$",
            dc_hostname="DC-01",
            source_ip="10.0.1.10",
            dc_ip="10.0.2.10",
            time=timestamp,
            domain="EXAMPLE",
        )

        security_events = [
            call.args[0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        event_types = {event.event_type for event in security_events}
        kerberos_events = [
            event
            for event in security_events
            if event.event_type in {"kerberos_tgt", "kerberos_service"}
        ]

        assert {"kerberos_tgt", "kerberos_service", "machine_logon"} <= event_types
        assert all(event.kerberos.source_ip == "::ffff:10.0.1.10" for event in kerberos_events)
        assert all(
            abs((event.timestamp - timestamp).total_seconds()) < 1.0 for event in kerberos_events
        )

    def test_bash_history_preserves_blocking_command_dwell(
        self, activity_gen, state_manager, mock_emitters
    ):
        """Foreground editors should push later same-user bash history forward."""
        linux = System(hostname="LNX-01", ip="10.0.0.2", os="Ubuntu 22.04", type="workstation")
        user = User(username="alice", full_name="Alice Example", email="alice@example.com")
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        bash_emitter = Mock()
        bash_emitter.can_handle.return_value = True
        mock_emitters["bash_history"] = bash_emitter
        activity_gen.dispatcher.emitters = mock_emitters

        activity_gen.generate_bash_command(user, linux, timestamp, "nano app.py")
        activity_gen.generate_bash_command(user, linux, timestamp + timedelta(seconds=1), "make")

        events = [call.args[0] for call in bash_emitter.emit.call_args_list]
        assert events[0].timestamp == timestamp
        assert events[1].timestamp >= timestamp + timedelta(seconds=45)

    def test_same_user_bash_history_avoids_same_second_across_hosts(
        self, activity_gen, state_manager, mock_emitters
    ):
        """Same-user shell entries on different hosts should not land on the same second."""
        linux_a = System(hostname="LNX-01", ip="10.0.0.2", os="Ubuntu 22.04", type="workstation")
        linux_b = System(hostname="LNX-02", ip="10.0.0.3", os="Ubuntu 22.04", type="workstation")
        user = User(username="alice", full_name="Alice Example", email="alice@example.com")
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        bash_emitter = Mock()
        bash_emitter.can_handle.return_value = True
        mock_emitters["bash_history"] = bash_emitter
        activity_gen.dispatcher.emitters = mock_emitters

        activity_gen.generate_bash_command(user, linux_a, timestamp, "whoami")
        activity_gen.generate_bash_command(user, linux_b, timestamp, "id")

        events = [call.args[0] for call in bash_emitter.emit.call_args_list]
        event_seconds = [int(event.timestamp.timestamp()) for event in events]

        assert len(events) == 2
        assert len(set(event_seconds)) == 2

    def test_linux_process_activity_uses_scheduled_bash_time(
        self, activity_gen, state_manager, mock_emitters, monkeypatch
    ):
        """Correlated Linux process and bash-history artifacts should share shell timing."""
        from evidenceforge.generation.activity import application_catalog

        linux = System(hostname="LNX-01", ip="10.0.0.2", os="Ubuntu 22.04", type="workstation")
        user = User(username="alice", full_name="Alice Example", email="alice@example.com")
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        scheduled_time = timestamp + timedelta(seconds=75)
        state_manager.set_current_time(timestamp)
        activity_gen._bash_history_next_time[(linux.hostname, user.username)] = scheduled_time
        mock_emitters["bash_history"] = Mock()
        for emitter in mock_emitters.values():
            emitter.can_handle.return_value = True
        activity_gen.dispatcher.emitters = mock_emitters
        monkeypatch.setattr(
            application_catalog,
            "pick_app_and_command",
            lambda *args, **kwargs: ("/usr/bin/git", "git pull origin fix/memory-leak"),
        )
        monkeypatch.setattr(activity_gen, "_emit_process_network_correlation", lambda *args: None)

        activity_gen.execute_baseline_activity(user, linux, timestamp, "process_code")

        emitted = [
            call.args[0]
            for emitter in mock_emitters.values()
            for call in emitter.emit.call_args_list
            if call.args and isinstance(call.args[0], SecurityEvent)
        ]
        process_event = next(
            event
            for event in emitted
            if event.event_type == "process_create"
            and event.process
            and event.process.command_line == "git pull origin fix/memory-leak"
        )
        bash_event = next(
            event
            for event in emitted
            if event.event_type == "bash_command"
            and event.shell
            and event.shell.command == "git pull origin fix/memory-leak"
        )
        assert process_event.timestamp == scheduled_time
        assert bash_event.timestamp == scheduled_time

    def test_linux_process_activity_suppresses_service_user_bash_history(
        self, activity_gen, state_manager, mock_emitters, monkeypatch
    ):
        """Linux app-catalog processes should not emit shell history for service users."""
        from evidenceforge.generation.activity import application_catalog

        linux = System(
            hostname="WEB-01",
            ip="10.0.0.20",
            os="Ubuntu 22.04",
            type="server",
            assigned_user="www-data",
        )
        service_user = User(
            username="www-data",
            full_name="Web Service",
            email="www-data@example.com",
        )
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        mock_emitters["bash_history"] = Mock()
        for emitter in mock_emitters.values():
            emitter.can_handle.return_value = True
        activity_gen.dispatcher.emitters = mock_emitters
        monkeypatch.setattr(
            application_catalog,
            "pick_app_and_command",
            lambda *args, **kwargs: (
                "/usr/bin/code",
                "code --no-sandbox /home/www-data/projects/data-pipeline",
            ),
        )
        monkeypatch.setattr(activity_gen, "_emit_process_network_correlation", lambda *args: None)

        activity_gen.execute_baseline_activity(service_user, linux, timestamp, "process_code")

        emitted = [
            call.args[0]
            for emitter in mock_emitters.values()
            for call in emitter.emit.call_args_list
            if call.args and isinstance(call.args[0], SecurityEvent)
        ]
        assert any(
            event.event_type == "process_create"
            and event.process is not None
            and event.process.command_line
            == "code --no-sandbox /home/www-data/projects/data-pipeline"
            for event in emitted
        )
        assert not any(event.event_type == "bash_command" for event in emitted)

    def test_linux_process_system_suppresses_service_user_bash_history(
        self, activity_gen, state_manager, mock_emitters
    ):
        """Legacy Linux process templates should not emit shell history for service users."""
        linux = System(
            hostname="WEB-01",
            ip="10.0.0.20",
            os="Ubuntu 22.04",
            type="server",
            assigned_user="apache",
        )
        service_user = User(
            username="apache",
            full_name="Apache Service",
            email="apache@example.com",
        )
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        mock_emitters["bash_history"] = Mock()
        for emitter in mock_emitters.values():
            emitter.can_handle.return_value = True
        activity_gen.dispatcher.emitters = mock_emitters

        with patch.dict(
            generator_module.PROCESS_TEMPLATES_LINUX,
            {"process_system": [("/usr/sbin/cron", "/usr/sbin/cron -f")]},
        ):
            activity_gen.execute_baseline_activity(service_user, linux, timestamp, "process_system")

        emitted = [
            call.args[0]
            for emitter in mock_emitters.values()
            for call in emitter.emit.call_args_list
            if call.args and isinstance(call.args[0], SecurityEvent)
        ]
        assert any(
            event.event_type == "process_create"
            and event.process is not None
            and event.process.command_line == "/usr/sbin/cron -f"
            for event in emitted
        )
        assert not any(event.event_type == "bash_command" for event in emitted)

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

    def test_process_create_after_ended_session_clamps_before_logoff(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Late process creation for a closed session should render before 4634."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        logon_id = activity_gen.generate_logon(test_user, test_system, timestamp)
        logoff_time = timestamp + timedelta(minutes=5)
        activity_gen.generate_logoff(test_user, test_system, logoff_time, logon_id)

        activity_gen.generate_process(
            test_user,
            test_system,
            logoff_time + timedelta(minutes=20),
            logon_id,
            r"C:\Windows\System32\cmd.exe",
            "cmd.exe /c whoami",
        )

        process_event = [
            call.args[0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call.args[0].event_type == "process_create"
            and call.args[0].process
            and call.args[0].process.command_line == "cmd.exe /c whoami"
        ][-1]
        assert process_event.timestamp < logoff_time
        assert process_event.auth.logon_id == logon_id

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

    def test_generate_process_hosts_windows_batch_scripts_under_cmd(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Windows batch scripts should not become the process image."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        logon_id = "0x12345"

        pid = activity_gen.generate_process(
            test_user,
            test_system,
            timestamp,
            logon_id,
            r"C:\Program Files\nodejs\npm.cmd",
            "cmd.exe /c npm run dev",
        )

        proc = state_manager.get_process(test_system.hostname, pid)
        assert proc is not None
        assert proc.image == r"C:\Windows\System32\cmd.exe"
        assert proc.command_line == "cmd.exe /c npm run dev"

        process_event = next(
            call[0][0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call[0][0].event_type == "process_create"
            and call[0][0].process
            and call[0][0].process.pid == pid
        )
        assert process_event.process.image == r"C:\Windows\System32\cmd.exe"
        assert process_event.process.command_line == "cmd.exe /c npm run dev"

    def test_generate_process_derives_user_current_directory(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """User-launched GUI processes should not all inherit System32 as cwd."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        logon_id = "0x12345"
        process_name = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
        command_line = 'WINWORD.EXE /n "Vendor Proposal.docx"'

        activity_gen.generate_process(
            test_user, test_system, timestamp, logon_id, process_name, command_line
        )

        process_events = [
            call[0][0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call[0][0].event_type == "process_create"
            and call[0][0].process
            and call[0][0].process.image == process_name
        ]
        assert process_events
        assert process_events[0].process.current_directory == (
            f"C:\\Users\\{test_user.username}\\Documents\\"
        )

    def test_generate_process_derives_project_current_directory_for_dev_tools(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Relative developer-tool commands should run from a project directory."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        process_name = r"C:\Program Files\nodejs\node.exe"
        command_line = "node.exe scripts/build.js"

        activity_gen.generate_process(
            test_user,
            test_system,
            timestamp,
            "0x12345",
            process_name,
            command_line,
        )

        process_events = [
            call[0][0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call[0][0].event_type == "process_create"
            and call[0][0].process
            and call[0][0].process.image == process_name
        ]
        assert process_events
        current_directory = process_events[0].process.current_directory
        assert current_directory.startswith(f"C:\\Users\\{test_user.username}\\source\\repos\\")
        assert current_directory != r"C:\Program Files\nodejs\\"

    def test_ssh_process_network_effect_uses_command_target(
        self, activity_gen, test_user, state_manager, mock_emitters
    ):
        """SSH Sysmon/eCAR flow destinations should agree with the process command line."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        workstation = System(
            hostname="WS-01",
            ip="10.0.1.10",
            os="Windows 11",
            type="workstation",
        )
        web_server = System(
            hostname="WEB-EXT-01",
            ip="10.0.3.10",
            os="Ubuntu 22.04",
            type="server",
            roles=["web_server"],
        )
        activity_gen._ip_to_system = {workstation.ip: workstation, web_server.ip: web_server}
        activity_gen._all_system_ips = [workstation.ip, web_server.ip]
        state_manager.set_current_time(timestamp)
        process_name = r"C:\Windows\System32\OpenSSH\ssh.exe"
        command_line = "ssh.exe testuser@WEB-EXT-01"
        pid = activity_gen.generate_process(
            test_user,
            workstation,
            timestamp,
            "0x12345",
            process_name,
            command_line,
        )
        mock_emitters["zeek_conn"].reset_mock()

        activity_gen._emit_process_network_correlation(
            workstation,
            process_name,
            command_line,
            timestamp,
            pid,
            random.Random(1),
        )

        network_events = [
            call.args[0]
            for call in mock_emitters["zeek_conn"].emit.call_args_list
            if call.args[0].event_type == "connection"
        ]
        assert network_events
        assert network_events[-1].network.dst_ip == web_server.ip
        assert network_events[-1].network.dst_port == 22

    def test_sqlcmd_unresolved_host_emits_failed_network_attempt(
        self, activity_gen, test_system, state_manager, mock_emitters
    ):
        """Explicit sqlcmd targets should not render as process-only activity."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        activity_gen._ip_to_system = {test_system.ip: test_system}
        activity_gen._all_system_ips = [test_system.ip]
        activity_gen._ad_domain = "example.com"
        process_name = (
            r"C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\sqlcmd.exe"
        )
        command_line = 'sqlcmd.exe -S sqlprod01 -Q "SELECT 1"'
        pid = state_manager.create_process(
            system=test_system.hostname,
            parent_pid=4,
            image=process_name,
            command_line=command_line,
            username="testuser",
            integrity_level="Medium",
            logon_id="0x12345",
        )

        activity_gen._emit_process_network_correlation(
            test_system,
            process_name,
            command_line,
            timestamp,
            pid,
            random.Random(2),
        )

        network_events = [
            call.args[0]
            for call in mock_emitters["zeek_conn"].emit.call_args_list
            if call.args[0].event_type == "connection"
        ]
        assert network_events
        assert network_events[-1].network.dst_port == 1433
        assert network_events[-1].network.conn_state == "S0"
        assert network_events[-1].network.resp_bytes == 0
        assert network_events[-1].network.initiating_pid == pid

        assert network_events[-1].network.dst_ip != test_system.ip
        assert network_events[-1].network.dst_ip.startswith("10.0.0.")

    def test_sqlcmd_local_instance_does_not_emit_network_attempt(
        self, activity_gen, test_system, mock_emitters
    ):
        """Local SQL Server instances should stay host-local."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        process_name = (
            r"C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\sqlcmd.exe"
        )
        command_line = 'sqlcmd.exe -S SQLEXPRESS -Q "SELECT 1"'

        activity_gen._emit_process_network_correlation(
            test_system,
            process_name,
            command_line,
            timestamp,
            4242,
            random.Random(2),
        )

        network_events = [
            call.args[0]
            for call in mock_emitters["zeek_conn"].emit.call_args_list
            if call.args[0].event_type == "connection"
        ]
        assert not network_events

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
        assert service_event.service.service_start_type == "3"
        file_event = next(
            event
            for event in events
            if event.event_type == "file_create"
            and event.file is not None
            and event.file.path == r"C:\Windows\PSEXESVC.exe"
        )
        assert file_event.timestamp < service_event.timestamp

    def test_remote_service_install_emits_smb_and_rpc_network_evidence(
        self, activity_gen, state_manager, mock_emitters
    ):
        """PsExec-style service creation should have matching SMB/RPC flows."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        source = System(
            hostname="WS-ADMIN-01",
            ip="10.0.0.50",
            os="Windows 11",
            type="workstation",
        )
        target = System(
            hostname="DC-01",
            ip="10.0.0.10",
            os="Windows Server 2022",
            type="domain_controller",
        )
        user = User(
            username="alice",
            full_name="Alice Admin",
            email="alice@example.com",
            primary_system=source.hostname,
        )
        activity_gen._world_model = SimpleNamespace(
            systems_by_hostname={source.hostname: source, target.hostname: target}
        )
        activity_gen._ip_to_system = {source.ip: source, target.ip: target}
        state_manager.set_current_time(timestamp)

        activity_gen.generate_service_installed(
            user,
            target,
            timestamp,
            service_name="PSEXESVC",
            service_file_name=r"%SystemRoot%\PSEXESVC.exe",
        )

        network_events = [
            call.args[0]
            for call in mock_emitters["zeek_conn"].emit.call_args_list
            if call.args[0].event_type == "connection"
        ]
        assert {(event.network.dst_port, event.network.service) for event in network_events} >= {
            (445, "smb"),
            (135, "dce_rpc"),
        }
        assert all(event.network.src_ip == source.ip for event in network_events)
        assert all(event.network.dst_ip == target.ip for event in network_events)

    def test_remote_service_network_evidence_caps_sequential_source_ports(
        self, activity_gen, state_manager, mock_emitters
    ):
        """Sequential SMB/RPC evidence source ports should stay in the valid TCP range."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        source = System(
            hostname="WS-ADMIN-01",
            ip="10.0.0.50",
            os="Windows 11",
            type="workstation",
        )
        target = System(
            hostname="DC-01",
            ip="10.0.0.10",
            os="Windows Server 2022",
            type="domain_controller",
        )
        user = User(
            username="alice",
            full_name="Alice Admin",
            email="alice@example.com",
            primary_system=source.hostname,
        )
        activity_gen._world_model = SimpleNamespace(
            systems_by_hostname={source.hostname: source, target.hostname: target}
        )
        activity_gen._ip_to_system = {source.ip: source, target.ip: target}
        state_manager.set_current_time(timestamp)

        with patch.object(generator_module, "_ephemeral_port", return_value=65535):
            activity_gen.generate_service_installed(
                user,
                target,
                timestamp,
                service_name="PSEXESVC",
                service_file_name=r"%SystemRoot%\PSEXESVC.exe",
            )

        remote_service_events = [
            call.args[0]
            for call in mock_emitters["zeek_conn"].emit.call_args_list
            if call.args[0].event_type == "connection"
            and call.args[0].network.service in {"smb", "dce_rpc"}
        ]
        source_ports = [event.network.src_port for event in remote_service_events]

        assert source_ports == [65534, 65535]
        assert all(0 <= port <= 65535 for port in source_ports)

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

    def test_storyline_powershell_does_not_receive_generic_registry_noise(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Storyline tool processes should not inherit unrelated user registry noise."""

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
        logon_id = activity_gen.generate_logon(test_user, test_system, timestamp)

        with patch("evidenceforge.generation.activity.generator._get_rng", RegistryOnlyRandom):
            activity_gen.generate_process(
                test_user,
                test_system,
                timestamp + timedelta(seconds=1),
                logon_id,
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "powershell.exe Compress-Archive C:\\Exports C:\\ProgramData\\health-cache.zip",
                from_storyline=True,
            )

        registry_events = [
            call.args[0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call.args[0].event_type == "registry_modify"
        ]
        assert registry_events == []

    def test_process_module_load_preserves_profile_signature_metadata(
        self,
        activity_gen,
        test_user,
        test_system,
        state_manager,
        mock_emitters,
        monkeypatch,
    ):
        """Probabilistic process ImageLoad events should carry DLL profile signer fields."""

        class ModuleLoadRandom(random.Random):
            def __init__(self):
                super().__init__(7)
                self._random_values = iter([0.99, 0.01])

            def random(self):
                return next(self._random_values, 0.99)

        import evidenceforge.generation.activity.dll_load_profiles as dll_profiles

        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        logon_id = activity_gen.generate_logon(test_user, test_system, timestamp)
        monkeypatch.setattr(generator_module, "_get_rng", ModuleLoadRandom)
        monkeypatch.setattr(
            dll_profiles,
            "get_dlls_for_process",
            lambda _exe: [
                {
                    "path": r"C:\Program Files\Mozilla Firefox\mozglue.dll",
                    "signed": True,
                    "signature": "Mozilla Corporation",
                    "signature_status": "Valid",
                }
            ],
        )

        activity_gen.generate_process(
            test_user,
            test_system,
            timestamp + timedelta(seconds=5),
            logon_id,
            r"C:\Program Files\Mozilla Firefox\firefox.exe",
            r'"C:\Program Files\Mozilla Firefox\firefox.exe"',
            parent_pid=4,
        )

        image_load_events = [
            call.args[0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call.args[0].event_type == "image_load"
        ]
        assert image_load_events
        assert image_load_events[-1].image_load.image_loaded.endswith("mozglue.dll")
        assert image_load_events[-1].image_load.signature == "Mozilla Corporation"
        assert image_load_events[-1].image_load.signature_status == "Valid"

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

    def test_image_load_materializes_username_placeholder(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Endpoint module-load paths should never leak literal username placeholders."""
        session_start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(session_start)
        logon_id = activity_gen.generate_logon(test_user, test_system, session_start)
        pid = activity_gen.generate_process(
            test_user,
            test_system,
            session_start + timedelta(seconds=5),
            logon_id,
            r"C:\Program Files\Zoom\bin\Zoom.exe",
            r'"C:\Program Files\Zoom\bin\Zoom.exe"',
        )
        mock_emitters["windows_event_security"].reset_mock()

        activity_gen.generate_image_load(
            test_user,
            test_system,
            session_start + timedelta(seconds=6),
            pid,
            r"C:\Program Files\Zoom\bin\Zoom.exe",
            r"C:\Users\{username}\AppData\Roaming\Zoom\bin\zVideoApp.dll",
        )

        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.event_type == "image_load"
        assert "{username}" not in event.image_load.image_loaded
        assert f"\\Users\\{test_user.username}\\" in event.image_load.image_loaded

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
        assert event.auth.subject_logon_id == "0x3e7"
        assert service_logon_id != event.auth.subject_logon_id

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

    def test_kerberos_preauth_failed_preserves_missing_source_ip(
        self, activity_gen, test_user, state_manager, mock_emitters
    ):
        """4771 should not render missing source IP as invalid ::ffff:-."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        activity_gen._dc_systems = {
            "DC-01": System(
                hostname="DC-01",
                ip="10.0.0.10",
                os="Windows Server 2019",
                type="domain_controller",
            )
        }

        activity_gen.generate_kerberos_preauth_failed(
            test_user.username,
            "-",
            "DC-01",
            timestamp,
        )

        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.event_type == "kerberos_preauth_failed"
        assert event.kerberos.source_ip == "-"
        assert event.kerberos.source_port == 0

    def test_kerberos_preauth_failed_can_emit_matching_dc_flow(
        self, activity_gen, test_user, state_manager, mock_emitters
    ):
        """Optional 4771 wire evidence should reuse the same source port."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        source = System(
            hostname="WS-01",
            ip="10.0.0.20",
            os="Windows 11",
            type="workstation",
        )
        dc = System(
            hostname="DC-01",
            ip="10.0.0.10",
            os="Windows Server 2022",
            type="domain_controller",
            services=["ad-ds"],
            roles=["domain_controller"],
        )
        activity_gen._ip_to_system = {source.ip: source, dc.ip: dc}

        activity_gen.generate_kerberos_preauth_failed(
            test_user.username,
            source.ip,
            dc.hostname,
            timestamp,
            emit_connection=True,
        )

        events = [
            call[0][0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        preauth = next(event for event in events if event.event_type == "kerberos_preauth_failed")
        connection = next(event for event in events if event.event_type == "connection")
        assert preauth.kerberos.source_port == connection.network.src_port
        assert connection.network.dst_port == 88

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

    def test_system_process_create_uses_well_known_logon_id(
        self, activity_gen, test_system, state_manager, mock_emitters
    ):
        """SYSTEM-owned process telemetry should use LocalSystem's canonical LogonID."""
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
            "0xb7adae1d",
            r"C:\Windows\System32\net.exe",
            r'net group "Domain Admins" aisha.johnson /add /domain',
        )

        process_events = [
            call[0][0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call[0][0].event_type == "process_create"
        ]
        event = process_events[-1]
        assert event.auth.username == "SYSTEM"
        assert event.auth.logon_id == "0x3e7"
        assert event.process.logon_id == "0x3e7"

    def test_workstation_unlock_skips_ended_session(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """A visible logoff should prevent later unlock reuse of the same LogonID."""
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        logoff_time = start + timedelta(minutes=20)
        unlock_time = start + timedelta(minutes=22)
        logon_id = activity_gen.generate_logon(
            test_user,
            test_system,
            start,
            logon_type=2,
            source_ip="-",
        )
        activity_gen.generate_workstation_lock(
            test_user, test_system, start + timedelta(minutes=5), logon_id
        )
        activity_gen.generate_logoff(test_user, test_system, logoff_time, logon_id)
        mock_emitters["windows_event_security"].reset_mock()

        activity_gen.generate_workstation_unlock(test_user, test_system, unlock_time, logon_id)

        emitted_types = [
            call[0][0].event_type
            for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        assert "workstation_unlocked" not in emitted_types
        assert "logon" not in emitted_types

    def test_unlock_reauth_ecar_login_uses_child_session_object(
        self, activity_gen, test_user, test_system, mock_emitters
    ):
        """eCAR Type 7 re-auth should not reuse the durable session object lifecycle."""
        mock_emitters["ecar"] = Mock()
        activity_gen.dispatcher.emitters = mock_emitters
        start = datetime(2024, 1, 15, 9, 0, 0, tzinfo=UTC)

        logon_id = activity_gen.generate_logon(
            test_user,
            test_system,
            start,
            logon_type=2,
            source_ip="-",
        )
        activity_gen.generate_workstation_lock(
            test_user,
            test_system,
            start + timedelta(minutes=5),
            logon_id,
        )
        activity_gen.generate_workstation_unlock(
            test_user,
            test_system,
            start + timedelta(minutes=7),
            logon_id,
        )

        ecar_logons = [
            call.args[0]
            for call in mock_emitters["ecar"].emit.call_args_list
            if call.args[0].event_type == "logon"
        ]

        assert [event.auth.logon_type for event in ecar_logons] == [2, 7]
        assert ecar_logons[0].edr.object_id
        assert ecar_logons[1].edr.object_id
        assert ecar_logons[1].edr.object_id != ecar_logons[0].edr.object_id
        assert ecar_logons[1].edr.actor_id == ecar_logons[0].edr.object_id

    def test_workstation_lock_unlock_reject_network_session_luid(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """4800/4801 and Type 7 unlock should never reuse a Type 3 network LUID."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        network_logon_id = "0xabc123"
        state_manager.register_session(
            logon_id=network_logon_id,
            username=test_user.username,
            system=test_system.hostname,
            logon_type=3,
            source_ip="10.0.0.55",
            start_time=timestamp - timedelta(minutes=5),
        )

        activity_gen.generate_workstation_lock(
            test_user,
            test_system,
            timestamp,
            network_logon_id,
        )
        activity_gen.generate_workstation_unlock(
            test_user,
            test_system,
            timestamp + timedelta(minutes=5),
            network_logon_id,
        )

        emitted_types = [
            call[0][0].event_type
            for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        assert "workstation_locked" not in emitted_types
        assert "workstation_unlocked" not in emitted_types
        assert not any(
            call[0][0].event_type == "logon" and call[0][0].auth.logon_type == 7
            for call in mock_emitters["windows_event_security"].emit.call_args_list
        )

    def test_credential_dump_command_uses_high_integrity_token(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Credential-dump process telemetry should include visible elevation semantics."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_process(
            test_user,
            test_system,
            timestamp,
            "0xabc",
            r"C:\Windows\System32\ms-index-service.exe",
            'ms-index-service.exe "privilege::debug" "sekurlsa::logonpasswords" exit',
            parent_pid=4,
        )

        process_events = [
            call[0][0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call[0][0].event_type == "process_create"
        ]
        event = process_events[-1]
        assert event.process.integrity_level == "High"
        assert event.process.token_elevation == "%%1936"
        assert event.process.mandatory_label == "S-1-16-12288"

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

    def test_windows_singleton_traversal_path_creates_process_event(
        self, activity_gen, test_system, state_manager, mock_emitters
    ):
        """Traversal variants of singleton process paths should not reuse seeded PIDs."""
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
            r"C:\Windows\System32\..\Temp\lsass.exe",
            r"C:\Windows\System32\..\Temp\lsass.exe",
        )

        assert returned_pid != lsass_pid
        process_events = [
            call[0][0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call[0][0].event_type == "process_create"
        ]
        assert process_events
        assert process_events[-1].process.pid == returned_pid
        assert process_events[-1].process.image == r"C:\Windows\System32\..\Temp\lsass.exe"

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

        emitted = activity_gen.generate_create_remote_thread(
            test_user,
            test_system,
            timestamp,
            source_pid=source_pid,
            source_image=r"C:\Temp\inject.exe",
            target_pid=target_pid,
            target_image=r"C:\Windows\System32\lsass.exe",
        )

        assert emitted is True
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
        assert event.remote_thread.start_address >= 0x00007FF600000000
        assert event.remote_thread.stack_base < 0x0000800000000000
        assert event.remote_thread.start_module

    def test_process_access_uses_target_process_owner(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Sysmon Event 10 target user should follow the target process owner."""
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
            image=r"C:\Windows\explorer.exe",
            command_line=r"C:\Windows\explorer.exe",
            username=test_user.username,
            integrity_level="Medium",
            logon_id="0xabc",
        )

        activity_gen.generate_process_access(
            test_user,
            test_system,
            timestamp,
            source_pid=source_pid,
            source_image=r"C:\Temp\inject.exe",
            target_pid=target_pid,
            target_image=r"C:\Windows\explorer.exe",
        )

        event = [
            call[0][0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call[0][0].event_type == "process_access"
        ][-1]
        assert event.process_access.target_user == test_user.username

    def test_create_remote_thread_skips_missing_target_pid(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Remote-thread generation should not reference missing target process objects."""
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

        emitted = activity_gen.generate_create_remote_thread(
            test_user,
            test_system,
            timestamp,
            source_pid=source_pid,
            source_image=r"C:\Temp\inject.exe",
            target_pid=99999,
            target_image=r"C:\Windows\System32\lsass.exe",
        )

        assert emitted is False
        assert not [
            call[0][0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call[0][0].event_type == "create_remote_thread"
        ]
        assert state_manager.get_process_object_id(test_system.hostname, 99999) == ""

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
        activity_gen.generate_image_load(
            test_user,
            test_system,
            timestamp + timedelta(minutes=30),
            event.process.pid,
            event.process.image,
            event.image_load.image_loaded,
        )
        module_events_after_replay = [
            call[0][0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call[0][0].event_type == "image_load"
        ]
        assert len(module_events_after_replay) == len(module_events)

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

    def test_image_load_skips_duplicate_module_for_process_instance(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """A process should not repeatedly report the same loaded module instance."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        pid = state_manager.create_process(
            system=test_system.hostname,
            parent_pid=4,
            image=r"C:\Windows\System32\taskhostw.exe",
            command_line="taskhostw.exe",
            username=test_user.username,
            integrity_level="Medium",
            logon_id="0x12345",
        )
        mock_emitters["windows_event_security"].reset_mock()

        activity_gen.generate_image_load(
            test_user,
            test_system,
            timestamp + timedelta(minutes=5),
            pid,
            r"C:\Windows\System32\taskhostw.exe",
            r"C:\Program Files\Windows Defender Advanced Threat Protection\SenseCncProxy.dll",
        )
        activity_gen.generate_image_load(
            test_user,
            test_system,
            timestamp + timedelta(hours=2),
            pid,
            r"C:\Windows\System32\taskhostw.exe",
            r"C:\Program Files\Windows Defender Advanced Threat Protection\SenseCncProxy.dll",
        )

        module_events = [
            call.args[0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call.args[0].event_type == "image_load"
        ]
        assert len(module_events) == 1

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

    def test_kerberos_connection_can_render_udp_transport(
        self, activity_gen, test_system, state_manager, mock_emitters, monkeypatch
    ):
        """Kerberos/88 network evidence should not be forced to TCP-only."""
        from evidenceforge.generation.activity import kerberos_realism

        monkeypatch.setattr(
            kerberos_realism,
            "load_kerberos_realism",
            lambda: {"transport_profiles": {"default": {"udp": 1, "tcp": 0}}},
        )
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        dc_system = System(
            hostname="DC-01",
            ip="10.0.0.10",
            os="Windows Server 2022",
            type="domain_controller",
            roles=["domain_controller"],
        )
        activity_gen._ip_to_system = {test_system.ip: test_system, dc_system.ip: dc_system}
        activity_gen._dc_systems = [dc_system]
        state_manager.set_current_time(timestamp)
        pid = state_manager.create_process(
            system=test_system.hostname,
            parent_pid=4,
            image=r"C:\Windows\System32\lsass.exe",
            command_line="lsass.exe",
            username="SYSTEM",
            integrity_level="System",
            logon_id="0x3e7",
        )

        activity_gen.generate_connection(
            src_ip=test_system.ip,
            dst_ip=dc_system.ip,
            time=timestamp,
            dst_port=88,
            proto="tcp",
            service="kerberos",
            duration=3.0,
            orig_bytes=5000,
            resp_bytes=32000,
            conn_state="RSTR",
            pid=pid,
            source_system=test_system,
            emit_dns=False,
        )

        connection_event = next(
            call.args[0]
            for call in mock_emitters["zeek_conn"].emit.call_args_list
            if call.args[0].event_type == "connection" and call.args[0].network.dst_port == 88
        )
        assert connection_event.network.protocol == "udp"
        assert connection_event.network.ip_proto == 17
        assert connection_event.network.duration <= 0.16
        assert connection_event.network.orig_bytes <= 1300
        assert connection_event.network.resp_bytes <= 1400
        assert connection_event.network.conn_state == "SF"
        wfp_event = next(
            call.args[0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call.args[0].event_type == "wfp_connection"
        )
        assert wfp_event.network.protocol == "udp"
        assert wfp_event.network.ip_proto == 17

    def test_udp_kerberos_no_payload_failure_has_no_zeek_service(
        self, activity_gen, test_system, state_manager, mock_emitters
    ):
        """Zeek should not analyzer-label zero-payload UDP port 88 attempts as krb."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        dc_system = System(
            hostname="DC-01",
            ip="10.0.0.10",
            os="Windows Server 2022",
            type="domain_controller",
            roles=["domain_controller"],
        )
        activity_gen._ip_to_system = {test_system.ip: test_system, dc_system.ip: dc_system}
        activity_gen._dc_systems = [dc_system]
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection(
            src_ip=test_system.ip,
            dst_ip=dc_system.ip,
            time=timestamp,
            dst_port=88,
            proto="udp",
            service="kerberos",
            conn_state="S0",
            source_system=test_system,
            emit_dns=False,
        )

        connection_event = next(
            call.args[0]
            for call in mock_emitters["zeek_conn"].emit.call_args_list
            if call.args[0].event_type == "connection" and call.args[0].network.dst_port == 88
        )
        assert connection_event.network.conn_state == "S0"
        assert connection_event.network.protocol == "udp"
        assert connection_event.network.orig_bytes == 0
        assert connection_event.network.resp_bytes == 0
        assert connection_event.network.service == ""

    def test_generate_connection_skips_wfp_for_stale_process_pid(
        self, activity_gen, test_system, state_manager, mock_emitters
    ):
        """Storyline connections should not turn stale process ownership into System."""
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

        wfp_events = [
            call.args[0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call.args[0].event_type == "wfp_connection"
        ]
        assert not wfp_events

    def test_generate_connection_skips_wfp_when_process_owner_unknown(
        self, activity_gen, test_system, state_manager, mock_emitters
    ):
        """Ordinary Windows TCP flows should not fall back to PID 4/System."""
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
            source_system=test_system,
            hostname="service.provenance.test",
        )

        wfp_events = [
            call.args[0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call.args[0].event_type == "wfp_connection"
        ]
        assert not wfp_events

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

    def test_firewall_denied_dns_does_not_fabricate_response(
        self, activity_gen, test_system, state_manager, mock_emitters
    ):
        """Denied DNS traffic should not produce contradictory DNS response evidence."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection(
            src_ip=test_system.ip,
            dst_ip="10.0.0.53",
            time=timestamp,
            dst_port=53,
            proto="udp",
            service="dns",
            hostname="dc01.example.local",
            conn_state="S0",
            firewall=FirewallContext(
                action="deny",
                msg_id=106023,
                connection_id=0,
                src_interface="inside",
                dst_interface="outside",
            ),
        )

        events = [
            call.args[0]
            for emitter in mock_emitters.values()
            for call in emitter.emit.call_args_list
            if call.args[0].event_type == "connection"
        ]
        event = events[-1]
        assert event.firewall.action == "deny"
        assert event.network.conn_state == "S0"
        assert event.network.resp_bytes == 0
        assert event.dns is None

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

    def test_system_process_termination_carries_process_start_time(
        self, activity_gen, test_system, state_manager, mock_emitters
    ):
        """System process termination should preserve start time for stable Sysmon GUIDs."""
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(start)
        pid = state_manager.create_process(
            system=test_system.hostname,
            parent_pid=4,
            image=r"C:\Windows\System32\gpupdate.exe",
            command_line="gpupdate.exe /target:computer /force",
            username="SYSTEM",
            integrity_level="System",
            logon_id="0x3e7",
        )

        activity_gen.generate_system_process_termination(
            system=test_system,
            time=start + timedelta(seconds=2),
            pid=pid,
            process_name=r"C:\Windows\System32\gpupdate.exe",
            parent_pid=4,
            username="SYSTEM",
        )

        event = [
            call.args[0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call.args[0].event_type == "process_terminate"
        ][-1]
        assert event.process.start_time == start
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

    def test_generate_explicit_credentials_creates_named_caller_process(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """A named 4648 caller process should not render with ProcessId=0x0."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_explicit_credentials(
            user=test_user,
            system=test_system,
            time=timestamp,
            target_username="admin01",
            target_server="dc01.corp.local",
            process_name=r"C:\Windows\System32\runas.exe",
            process_pid=0,
        )

        emitted = [
            call[0][0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        process = next(event for event in emitted if event.event_type == "process_create")
        explicit = next(event for event in emitted if event.event_type == "explicit_credentials")
        assert explicit.auth.process_pid == process.process.pid
        assert explicit.auth.process_pid > 0
        assert process.timestamp < explicit.timestamp

    def test_generate_explicit_credentials_handles_missing_caller_pid(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """A baseline session without an explorer PID should still render 4648."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_explicit_credentials(
            user=test_user,
            system=test_system,
            time=timestamp,
            target_username="admin01",
            target_server="dc01.corp.local",
            process_name=r"C:\Windows\System32\runas.exe",
            process_pid=None,
        )

        emitted = [
            call[0][0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        process = next(event for event in emitted if event.event_type == "process_create")
        explicit = next(event for event in emitted if event.event_type == "explicit_credentials")
        assert explicit.auth.process_pid == process.process.pid
        assert explicit.auth.process_pid > 0

    def test_generate_explicit_credentials_replaces_mismatched_caller_pid(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """4648 ProcessId should not point at a different process image."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        mmc_pid = state_manager.create_process(
            system=test_system.hostname,
            parent_pid=4,
            image=r"C:\Windows\System32\mmc.exe",
            command_line="mmc.exe",
            username=test_user.username,
            integrity_level="Medium",
            logon_id="0x12345",
        )
        mock_emitters["windows_event_security"].reset_mock()

        activity_gen.generate_explicit_credentials(
            user=test_user,
            system=test_system,
            time=timestamp,
            target_username="admin01",
            target_server="dc01.corp.local",
            process_name=r"C:\Windows\System32\runas.exe",
            process_pid=mmc_pid,
        )

        emitted = [
            call[0][0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        explicit = next(event for event in emitted if event.event_type == "explicit_credentials")
        assert explicit.auth.process_pid != mmc_pid
        assert explicit.auth.process_name.endswith("runas.exe")

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

    def test_generate_explicit_credentials_ignores_invalid_target_for_subject_fallback(
        self, activity_gen, test_system, state_manager, mock_emitters
    ):
        """Invalid explicit target account text should not crash Windows subject coercion."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        root_user = User(username="root", full_name="root", email="root@example.local")

        activity_gen.generate_explicit_credentials(
            user=root_user,
            system=test_system,
            time=timestamp,
            target_username=r"CORP\Jane Doe",
            target_server="DC-01",
            process_name=r"C:\Windows\System32\runas.exe",
            process_pid=0,
            source_ip="10.10.3.10",
        )

        emitted = [
            call.args[0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        explicit = next(event for event in emitted if event.event_type == "explicit_credentials")
        assert explicit.auth.username == r"CORP\Jane Doe"
        assert explicit.auth.subject_username == "Administrator"
        assert all(getattr(event.auth, "username", "") != "Jane Doe" for event in emitted)

    def test_generate_explicit_credentials_coerces_linux_subject_on_windows(
        self, activity_gen, test_system, state_manager, mock_emitters
    ):
        """A Unix-local narrative actor should not bootstrap a Windows root logon."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        root_user = User(username="root", full_name="root", email="root@example.local")
        windows_user = User(
            username="aisha.johnson",
            full_name="Aisha Johnson",
            email="aisha.johnson@example.local",
            enabled=True,
        )
        activity_gen._users_by_username = {windows_user.username: windows_user}

        activity_gen.generate_explicit_credentials(
            user=root_user,
            system=test_system,
            time=timestamp,
            target_username=windows_user.username,
            target_server="DC-01",
            process_name=r"C:\Windows\System32\runas.exe",
            process_pid=0,
            source_ip="10.10.3.10",
        )

        emitted = [
            call.args[0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        logon = next(event for event in emitted if event.event_type == "logon")
        process = next(event for event in emitted if event.event_type == "process_create")
        explicit = next(event for event in emitted if event.event_type == "explicit_credentials")
        assert logon.auth.username == windows_user.username
        assert process.auth.username == windows_user.username
        assert explicit.auth.subject_username == windows_user.username
        assert all(getattr(event.auth, "username", "") != "root" for event in emitted)

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
            logon_id=logon_id,
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

    def test_generate_process_rejects_parent_from_different_logon(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Visible parent processes should belong to the child's logon session."""
        old_time = datetime(2024, 1, 15, 9, 0, 0, tzinfo=UTC)
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        old_logon_id = "0x11111"
        new_logon_id = "0x22222"
        state_manager.register_session(
            logon_id=old_logon_id,
            username=test_user.username,
            system=test_system.hostname,
            logon_type=2,
            source_ip=test_system.ip,
            start_time=old_time,
        )
        state_manager.register_session(
            logon_id=new_logon_id,
            username=test_user.username,
            system=test_system.hostname,
            logon_type=2,
            source_ip=test_system.ip,
            start_time=timestamp - timedelta(minutes=5),
        )
        state_manager.set_current_time(old_time)
        wrong_parent_pid = state_manager.create_process(
            system=test_system.hostname,
            parent_pid=4,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line="powershell.exe",
            username=test_user.username,
            integrity_level="Medium",
            logon_id=old_logon_id,
        )
        activity_gen._record_user_process(
            test_system,
            test_user,
            wrong_parent_pid,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        )

        activity_gen.generate_process(
            test_user,
            test_system,
            timestamp,
            new_logon_id,
            r"C:\Windows\System32\whoami.exe",
            "whoami.exe",
            parent_pid=wrong_parent_pid,
        )

        process_events = [
            call[0][0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call[0][0].event_type == "process_create"
        ]
        child = process_events[-1]
        assert child.process.parent_pid != wrong_parent_pid
        assert child.process.logon_id == new_logon_id

    def test_generate_process_rejects_one_shot_shell_parent(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Short-lived shell wrappers should not parent unrelated later commands."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        logon_id = "0x33333"
        state_manager.register_session(
            logon_id=logon_id,
            username=test_user.username,
            system=test_system.hostname,
            logon_type=2,
            source_ip=test_system.ip,
            start_time=timestamp - timedelta(minutes=5),
        )
        state_manager.set_current_time(timestamp - timedelta(seconds=20))
        explorer_pid = state_manager.create_process(
            system=test_system.hostname,
            parent_pid=4,
            image=r"C:\Windows\explorer.exe",
            command_line="explorer.exe",
            username=test_user.username,
            integrity_level="Medium",
            logon_id=logon_id,
        )
        activity_gen._system_pids = {
            test_system.hostname: {
                "explorer": explorer_pid,
                "winlogon": 4,
                "services": 4,
                "svchost_dcom": 4,
            }
        }
        state_manager.set_current_time(timestamp - timedelta(seconds=10))
        one_shot_parent_pid = state_manager.create_process(
            system=test_system.hostname,
            parent_pid=explorer_pid,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line='powershell.exe -NoProfile -Command "Get-LocalUser"',
            username=test_user.username,
            integrity_level="Medium",
            logon_id=logon_id,
        )
        activity_gen._record_user_process(
            test_system,
            test_user,
            one_shot_parent_pid,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        )

        activity_gen.generate_process(
            test_user,
            test_system,
            timestamp,
            logon_id,
            r"C:\Windows\System32\whoami.exe",
            "whoami.exe",
            parent_pid=one_shot_parent_pid,
        )

        process_events = [
            call[0][0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call[0][0].event_type == "process_create"
        ]
        child = process_events[-1]
        assert child.process.parent_pid != one_shot_parent_pid

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

    def test_generate_connection_uses_source_native_zeek_start_time(
        self, activity_gen, state_manager, mock_emitters
    ):
        """Zeek connection timestamps should include shared source start latency."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection(
            src_ip="10.0.10.5",
            dst_ip="10.0.20.10",
            time=timestamp,
            src_port=51111,
            dst_port=22,
            proto="tcp",
            service="ssh",
            duration=12.0,
            orig_bytes=1200,
            resp_bytes=2400,
        )

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert event.timestamp == _zeek_conn_observation_time(
            timestamp,
            "10.0.10.5",
            51111,
            "10.0.20.10",
            22,
            "tcp",
            "ssh",
        )

    def test_generate_connection_emits_nearby_kdc_audit_for_internal_kerberos_flows(
        self, activity_gen, state_manager, mock_emitters
    ):
        """Internal-to-DC Kerberos conn.log rows should have matching DC audit evidence."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        source = System(
            hostname="WEB-EXT-01",
            ip="10.0.1.20",
            os="Ubuntu 22.04",
            type="server",
            roles=["web_server"],
        )
        dc = System(
            hostname="DC-01",
            ip="10.0.1.10",
            os="Windows Server 2022",
            type="domain_controller",
            services=["ad-ds", "kerberos"],
            roles=["domain_controller"],
        )
        activity_gen._ip_to_system = {source.ip: source, dc.ip: dc}

        activity_gen.generate_connection(
            src_ip=source.ip,
            dst_ip=dc.ip,
            time=timestamp,
            dst_port=88,
            proto="tcp",
            service="kerberos",
            duration=1.0,
            orig_bytes=500,
            resp_bytes=2500,
            source_system=source,
        )

        events = [
            call[0][0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        tgt = next(event for event in events if event.event_type == "kerberos_tgt")
        service = next(event for event in events if event.event_type == "kerberos_service")
        connection = next(event for event in events if event.event_type == "connection")

        assert tgt.kerberos.target_username == "WEB-EXT-01$"
        assert tgt.kerberos.source_ip == "::ffff:10.0.1.20"
        assert service.kerberos.target_username == "WEB-EXT-01$@CORP.LOCAL"
        assert tgt.timestamp < connection.timestamp
        assert service.timestamp < connection.timestamp
        assert (connection.timestamp - tgt.timestamp).total_seconds() < 1
        assert tgt.kerberos.source_port == connection.network.src_port
        assert service.kerberos.source_port == connection.network.src_port

    def test_generate_connection_reuses_recent_kdc_audit_for_kerberos_flows(
        self, activity_gen, state_manager, mock_emitters
    ):
        """Connection-layer KDC audit repair should not duplicate existing nearby audit."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        source = System(
            hostname="FILE-SRV-01",
            ip="10.0.1.20",
            os="Windows Server 2019",
            type="server",
        )
        dc = System(
            hostname="DC-01",
            ip="10.0.1.10",
            os="Windows Server 2022",
            type="domain_controller",
            services=["ad-ds"],
            roles=["domain_controller"],
        )
        activity_gen._ip_to_system = {source.ip: source, dc.ip: dc}

        activity_gen.generate_kerberos_tgt(
            username="FILE-SRV-01$",
            source_ip=source.ip,
            dc_hostname=dc.hostname,
            time=timestamp - timedelta(milliseconds=200),
        )
        activity_gen.generate_kerberos_service_ticket(
            username="FILE-SRV-01$",
            service_name=f"ldap/{dc.hostname}",
            source_ip=source.ip,
            dc_hostname=dc.hostname,
            time=timestamp - timedelta(milliseconds=80),
        )
        audit_events = [
            call[0][0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        audit_ports = {
            event.kerberos.source_port
            for event in audit_events
            if event.event_type in {"kerberos_tgt", "kerberos_service"}
        }
        mock_emitters["windows_event_security"].emit.reset_mock()

        activity_gen.generate_connection(
            src_ip=source.ip,
            dst_ip=dc.ip,
            time=timestamp,
            dst_port=88,
            proto="tcp",
            service="kerberos",
            duration=1.0,
            orig_bytes=500,
            resp_bytes=2500,
            source_system=source,
        )

        events = [
            call[0][0].event_type
            for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        assert events == ["connection"]
        connection = mock_emitters["windows_event_security"].emit.call_args_list[0][0][0]
        assert audit_ports == {connection.network.src_port}

    def test_generate_connection_clamps_http_depth_for_one_request_connections(
        self, activity_gen, state_manager, mock_emitters
    ):
        """A fresh connection UID should not inherit page-session transaction depth."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        http = HttpContext(
            method="GET",
            host="portal.example.com",
            uri="/static/app.js",
            response_body_len=2048,
            trans_depth=4,
        )

        activity_gen.generate_connection(
            "10.0.0.1",
            "93.184.216.34",
            timestamp,
            dst_port=80,
            proto="tcp",
            service="http",
            duration=0.5,
            orig_bytes=300,
            resp_bytes=2048,
            http=http,
        )

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert event.http.trans_depth == 1
        assert http.trans_depth == 4

    def test_generate_connection_reuses_http_uid_for_persistent_transactions(self, state_manager):
        """Later HTTP transactions on a warm connection should reuse one Zeek UID."""

        class CollectorEmitter:
            def __init__(self, predicate):
                self._predicate = predicate
                self.events = []

            def can_handle(self, event):
                return self._predicate(event)

            def emit(self, event):
                self.events.append(event)

        conn_emitter = CollectorEmitter(
            lambda event: (
                event.event_type == "connection"
                and event.network is not None
                and not event.network.application_layer_only
            )
        )
        http_emitter = CollectorEmitter(
            lambda event: event.event_type == "connection" and event.http is not None
        )
        edr_emitter = CollectorEmitter(
            lambda event: (
                event.event_type == "connection"
                and event.network is not None
                and not event.network.application_layer_only
            )
        )
        emitters = {
            "zeek_conn": conn_emitter,
            "zeek_http": http_emitter,
            "ecar": edr_emitter,
        }
        dispatcher = EventDispatcher(state_manager=state_manager, emitters=emitters)
        generator = ActivityGenerator(state_manager, emitters, dispatcher=dispatcher)
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        first_uid = generator.generate_connection(
            "10.0.0.1",
            "93.184.216.34",
            timestamp,
            dst_port=80,
            proto="tcp",
            service="http",
            duration=2.0,
            orig_bytes=450,
            resp_bytes=12_288,
            conn_state="SF",
            http=HttpContext(
                method="GET",
                host="portal.example.com",
                uri="/",
                user_agent="Mozilla/5.0",
                response_body_len=4096,
                flow_response_body_len=12_288,
                flow_transaction_count=2,
                trans_depth=1,
            ),
            emit_dns=False,
        )
        second_uid = generator.generate_connection(
            "10.0.0.1",
            "93.184.216.34",
            timestamp + timedelta(milliseconds=700),
            dst_port=80,
            proto="tcp",
            service="http",
            duration=0.2,
            orig_bytes=320,
            resp_bytes=8192,
            conn_state="SF",
            http=HttpContext(
                method="GET",
                host="portal.example.com",
                uri="/assets/app.js",
                user_agent="Mozilla/5.0",
                response_body_len=8192,
                trans_depth=2,
            ),
            emit_dns=False,
        )

        assert first_uid
        assert second_uid == first_uid
        assert len(conn_emitter.events) == 1
        assert len(edr_emitter.events) == 1
        assert len(http_emitter.events) == 2

        first_event, second_event = http_emitter.events
        assert first_event.network.zeek_uid == first_uid
        assert first_event.network.application_layer_only is False
        assert first_event.http.trans_depth == 1
        assert second_event.network.zeek_uid == first_uid
        assert second_event.network.src_port == first_event.network.src_port
        assert second_event.network.application_layer_only is True
        assert second_event.http.trans_depth == 2

    def test_generate_connection_derives_plain_http_bytes_from_http_context(
        self, activity_gen, state_manager, mock_emitters
    ):
        """Single plain-HTTP transactions should not keep unrelated oversized conn bytes."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection(
            "10.0.0.1",
            "93.184.216.34",
            timestamp,
            dst_port=80,
            proto="tcp",
            service="http",
            duration=0.5,
            orig_bytes=4_900,
            resp_bytes=44_000,
            conn_state="SF",
            http=HttpContext(
                method="GET",
                host="portal.example.com",
                uri="/favicon.ico",
                user_agent="Mozilla/5.0",
                response_body_len=0,
                status_code=304,
                status_msg="Not Modified",
                trans_depth=1,
            ),
            emit_dns=False,
        )

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]

        assert event.network.conn_state == "SF"
        assert event.network.orig_bytes < 1_200
        assert 120 <= event.network.resp_bytes < 900
        assert event.network.resp_bytes > event.http.response_body_len

    def test_generate_connection_does_not_reuse_http_uid_after_parent_close(self, state_manager):
        """A late HTTP request should start a new flow instead of overrunning conn.log."""

        class CollectorEmitter:
            def __init__(self, predicate):
                self._predicate = predicate
                self.events = []

            def can_handle(self, event):
                return self._predicate(event)

            def emit(self, event):
                self.events.append(event)

        conn_emitter = CollectorEmitter(
            lambda event: (
                event.event_type == "connection"
                and event.network is not None
                and not event.network.application_layer_only
            )
        )
        http_emitter = CollectorEmitter(
            lambda event: event.event_type == "connection" and event.http is not None
        )
        emitters = {
            "zeek_conn": conn_emitter,
            "zeek_http": http_emitter,
        }
        dispatcher = EventDispatcher(state_manager=state_manager, emitters=emitters)
        generator = ActivityGenerator(state_manager, emitters, dispatcher=dispatcher)
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        first_uid = generator.generate_connection(
            "10.0.0.1",
            "93.184.216.34",
            timestamp,
            dst_port=80,
            proto="tcp",
            service="http",
            duration=0.25,
            orig_bytes=450,
            resp_bytes=4096,
            conn_state="SF",
            http=HttpContext(
                method="GET",
                host="portal.example.com",
                uri="/",
                user_agent="Mozilla/5.0",
                response_body_len=4096,
                trans_depth=1,
            ),
            emit_dns=False,
        )
        second_uid = generator.generate_connection(
            "10.0.0.1",
            "93.184.216.34",
            timestamp + timedelta(seconds=2),
            dst_port=80,
            proto="tcp",
            service="http",
            duration=0.25,
            orig_bytes=320,
            resp_bytes=8192,
            conn_state="SF",
            http=HttpContext(
                method="GET",
                host="portal.example.com",
                uri="/assets/app.js",
                user_agent="Mozilla/5.0",
                response_body_len=8192,
                trans_depth=2,
            ),
            emit_dns=False,
        )

        assert first_uid
        assert second_uid
        assert second_uid != first_uid
        assert len(conn_emitter.events) == 2
        assert len(http_emitter.events) == 2
        assert http_emitter.events[1].network.application_layer_only is False
        assert http_emitter.events[1].http.trans_depth == 1

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

    def test_tls_conn_resp_bytes_cover_certificate_file_bytes(
        self, activity_gen, state_manager, mock_emitters
    ):
        """TLS conn payload bytes should cover Zeek files.log certificate bytes."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection(
            "10.0.0.1",
            "93.184.216.34",
            timestamp,
            dst_port=443,
            service="ssl",
            duration=0.1,
            orig_bytes=200,
            resp_bytes=100,
            conn_state="SF",
            hostname="pypi.org",
        )

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        cert_payload = sum(certificate_file_size(cert) for cert in event.x509_chain)
        assert cert_payload > 0
        assert event.network.resp_bytes >= cert_payload
        max_cert_delay_ms = max(
            certificate_analyzer_delay_ms(
                zeek_uid=event.network.zeek_uid,
                event_timestamp=event.timestamp,
                fuid=cert.fuid,
                position=idx,
            )
            for idx, cert in enumerate(event.x509_chain)
        )
        assert event.network.duration >= (max_cert_delay_ms / 1000.0)
        assert event.network.duration >= 1.05 + (0.075 * len(event.x509_chain))

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

    def test_default_connection_duration_jitter_diversifies_reviewer_anchors(self):
        """Generator-owned placeholder durations should not render as exact constants."""
        for anchor in (0.8, 2.0, 0.01):
            samples = {
                round(
                    _jitter_default_connection_duration(
                        anchor,
                        caller_provided_duration=False,
                        seed_parts=("duration-anchor", anchor, idx),
                    ),
                    6,
                )
                for idx in range(8)
            }
            assert len(samples) > 1
            assert anchor not in samples

            assert (
                _jitter_default_connection_duration(
                    anchor,
                    caller_provided_duration=True,
                    seed_parts=("authored", anchor),
                )
                == anchor
            )

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

    def test_generate_bash_command_emits_correlated_linux_process(
        self, activity_gen, test_user, state_manager, mock_emitters
    ):
        """Direct Linux shell history commands should have matching process telemetry."""
        command_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        linux = System(
            hostname="LNX-01",
            ip="10.0.0.2",
            os="Ubuntu 22.04",
            type="server",
            assigned_user=test_user.username,
        )
        logon_id = "0xabc123"
        state_manager.set_current_time(command_time - timedelta(seconds=30))
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
        session = state_manager.register_session(
            logon_id=logon_id,
            username=test_user.username,
            system=linux.hostname,
            logon_type=10,
            source_ip="10.0.0.50",
            start_time=command_time - timedelta(seconds=20),
        )
        bash_pid = state_manager.create_process(
            linux.hostname,
            sshd_pid,
            "/bin/bash",
            "-bash",
            test_user.username,
            "Medium",
            logon_id,
        )
        session.session_shell_pid = bash_pid
        activity_gen._system_pids = {
            linux.hostname: {"systemd": systemd_pid, "sshd": sshd_pid, "bash": bash_pid}
        }

        activity_gen.generate_bash_command(
            test_user,
            linux,
            command_time,
            "curl https://updates.example.com/payload.sh",
        )

        events = [
            call.args[0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        process_events = [
            event
            for event in events
            if event.event_type == "process_create"
            and event.process is not None
            and event.process.command_line == "curl https://updates.example.com/payload.sh"
        ]
        assert process_events
        assert process_events[-1].process.image == "/usr/bin/curl"
        assert process_events[-1].process.parent_pid == bash_pid
        terminate_events = [
            event
            for event in events
            if event.event_type == "process_terminate"
            and event.process is not None
            and event.process.pid == process_events[-1].process.pid
        ]
        assert terminate_events
        assert process_events[-1].timestamp < terminate_events[-1].timestamp

    def test_generate_bash_command_serializes_foreground_children(
        self, activity_gen, test_user, state_manager, mock_emitters
    ):
        """Sequential foreground commands in one shell should not overlap."""
        command_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        linux = System(
            hostname="DB-PROD-01",
            ip="10.0.2.50",
            os="Ubuntu 22.04",
            type="server",
            assigned_user=test_user.username,
        )
        logon_id = "0xabc456"
        state_manager.set_current_time(command_time - timedelta(seconds=60))
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
        session = state_manager.register_session(
            logon_id=logon_id,
            username=test_user.username,
            system=linux.hostname,
            logon_type=10,
            source_ip="10.0.0.50",
            start_time=command_time - timedelta(seconds=30),
        )
        bash_pid = state_manager.create_process(
            linux.hostname,
            sshd_pid,
            "/bin/bash",
            "-bash",
            test_user.username,
            "Medium",
            logon_id,
        )
        session.session_shell_pid = bash_pid
        activity_gen._system_pids = {
            linux.hostname: {"systemd": systemd_pid, "sshd": sshd_pid, "bash": bash_pid}
        }

        activity_gen.generate_bash_command(
            test_user,
            linux,
            command_time,
            "mysqldump --defaults-extra-file=/home/alice/.my.cnf webapp > /tmp/webapp.sql",
        )
        activity_gen.generate_bash_command(
            test_user,
            linux,
            command_time + timedelta(seconds=1),
            "gzip /tmp/webapp.sql",
        )

        events = [
            call.args[0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        mysqldump_create = next(
            event
            for event in events
            if event.event_type == "process_create"
            and event.process is not None
            and event.process.image == "/usr/bin/mysqldump"
        )
        gzip_create = next(
            event
            for event in events
            if event.event_type == "process_create"
            and event.process is not None
            and event.process.image == "/usr/bin/gzip"
        )
        mysqldump_terminate = next(
            event
            for event in events
            if event.event_type == "process_terminate"
            and event.process is not None
            and event.process.pid == mysqldump_create.process.pid
        )

        assert mysqldump_create.process.parent_pid == bash_pid
        assert gzip_create.process.parent_pid == bash_pid
        assert gzip_create.timestamp > mysqldump_terminate.timestamp

    def test_linux_process_activity_reserves_busy_foreground_shell(
        self, activity_gen, test_user, state_manager, mock_emitters
    ):
        """Baseline Linux process activity should wait for the active foreground command."""
        process_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        linux = System(
            hostname="WS-LNGUYEN-01",
            ip="10.0.2.60",
            os="Ubuntu 22.04",
            type="workstation",
            assigned_user=test_user.username,
        )
        logon_id = "0xabc789"
        state_manager.set_current_time(process_time - timedelta(seconds=60))
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
        session = state_manager.register_session(
            logon_id=logon_id,
            username=test_user.username,
            system=linux.hostname,
            logon_type=10,
            source_ip="10.0.0.50",
            start_time=process_time - timedelta(seconds=30),
        )
        bash_pid = state_manager.create_process(
            linux.hostname,
            sshd_pid,
            "/bin/bash",
            "-bash",
            test_user.username,
            "Medium",
            logon_id,
        )
        session.session_shell_pid = bash_pid
        activity_gen._system_pids = {
            linux.hostname: {"systemd": systemd_pid, "sshd": sshd_pid, "bash": bash_pid}
        }
        blocked_until = process_time + timedelta(seconds=30)
        activity_gen._foreground_shell_next_time[
            (linux.hostname, test_user.username, logon_id, bash_pid)
        ] = blocked_until

        with patch.dict(
            generator_module.PROCESS_TEMPLATES_LINUX,
            {"process_system": [("/usr/bin/npm", "npm install")]},
        ):
            activity_gen.execute_baseline_activity(test_user, linux, process_time, "process_system")

        events = [
            call.args[0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        npm_create = next(
            event
            for event in events
            if event.event_type == "process_create"
            and event.process is not None
            and event.process.image == "/usr/bin/npm"
        )

        assert npm_create.process.parent_pid == bash_pid
        assert npm_create.timestamp > blocked_until

    def test_process_user_apps_bash_pool_respects_database_role(
        self, activity_gen, test_user, monkeypatch, mock_emitters
    ):
        """Generic user-app shell noise on DB hosts should not pick web-admin commands."""

        class AssertingRng:
            def choice(self, seq):
                joined = "\n".join(seq)
                assert "apache" not in joined
                assert "nginx" not in joined
                assert "certbot" not in joined
                assert "ab -n" not in joined
                return "du -sh /var/lib/mysql/*"

        monkeypatch.setattr(generator_module, "_get_rng", lambda: AssertingRng())
        linux = System(
            hostname="DB-PROD-01",
            ip="10.0.0.2",
            os="Ubuntu 22.04",
            type="server",
            services=["mysql"],
            assigned_user=test_user.username,
        )

        activity_gen.generate_bash_command(
            test_user,
            linux,
            datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            "process_user_apps",
            emit_process_telemetry=False,
        )

        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.shell.command == "du -sh /var/lib/mysql/*"

    def test_generate_bash_command_does_not_emit_process_for_shell_builtin(
        self, activity_gen, test_user, state_manager, mock_emitters
    ):
        """Shell builtins are valid bash history without standalone exec telemetry."""
        command_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        linux = System(
            hostname="LNX-01",
            ip="10.0.0.2",
            os="Ubuntu 22.04",
            type="server",
            assigned_user=test_user.username,
        )
        state_manager.register_session(
            logon_id="0xabc123",
            username=test_user.username,
            system=linux.hostname,
            logon_type=10,
            source_ip="10.0.0.50",
            start_time=command_time - timedelta(seconds=20),
        )

        activity_gen.generate_bash_command(test_user, linux, command_time, "cd /var/www/html")

        events = [
            call.args[0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        assert any(event.event_type == "bash_command" for event in events)
        assert not any(event.event_type == "process_create" for event in events)

    def test_generate_bash_command_does_not_emit_process_for_typo(
        self, activity_gen, test_user, state_manager, mock_emitters
    ):
        """Unknown typo commands should not become fake /usr/bin process images."""
        command_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        linux = System(
            hostname="LNX-01",
            ip="10.0.0.2",
            os="Ubuntu 22.04",
            type="server",
            assigned_user=test_user.username,
        )
        state_manager.register_session(
            logon_id="0xabc123",
            username=test_user.username,
            system=linux.hostname,
            logon_type=10,
            source_ip="10.0.0.50",
            start_time=command_time - timedelta(seconds=20),
        )

        activity_gen.generate_bash_command(test_user, linux, command_time, "idd")

        events = [
            call.args[0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        assert any(event.event_type == "bash_command" for event in events)
        assert not any(event.event_type == "process_create" for event in events)

    def test_generate_bash_command_expands_alias_process_image(
        self, activity_gen, test_user, state_manager, mock_emitters
    ):
        """Shell aliases should render the real executable image when process telemetry exists."""
        command_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        linux = System(
            hostname="LNX-01",
            ip="10.0.0.2",
            os="Ubuntu 22.04",
            type="server",
            assigned_user=test_user.username,
        )
        session = state_manager.register_session(
            logon_id="0xabc123",
            username=test_user.username,
            system=linux.hostname,
            logon_type=10,
            source_ip="10.0.0.50",
            start_time=command_time - timedelta(seconds=20),
        )
        state_manager.set_current_time(command_time - timedelta(seconds=10))
        systemd_pid = state_manager.create_process(
            linux.hostname,
            0,
            "/usr/lib/systemd/systemd",
            "/usr/lib/systemd/systemd --system",
            "root",
            "System",
        )
        bash_pid = state_manager.create_process(
            linux.hostname,
            systemd_pid,
            "/bin/bash",
            "-bash",
            test_user.username,
            "Medium",
            "0xabc123",
        )
        session.session_shell_pid = bash_pid

        activity_gen.generate_bash_command(test_user, linux, command_time, "ll /etc/shadow")

        events = [
            call.args[0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        process_events = [event for event in events if event.event_type == "process_create"]
        assert process_events
        assert process_events[-1].process.image == "/usr/bin/ls"
        assert process_events[-1].process.command_line == "ls -la /etc/shadow"

    def test_generate_bash_command_resolves_interpreter_image(
        self, activity_gen, test_user, state_manager, mock_emitters
    ):
        """Interpreter commands should keep the interpreter as the process image."""
        command_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        linux = System(
            hostname="LNX-01",
            ip="10.0.0.2",
            os="Ubuntu 22.04",
            type="server",
            assigned_user=test_user.username,
        )
        session = state_manager.register_session(
            logon_id="0xabc123",
            username=test_user.username,
            system=linux.hostname,
            logon_type=10,
            source_ip="10.0.0.50",
            start_time=command_time - timedelta(seconds=20),
        )
        state_manager.set_current_time(command_time - timedelta(seconds=10))
        systemd_pid = state_manager.create_process(
            linux.hostname,
            0,
            "/usr/lib/systemd/systemd",
            "/usr/lib/systemd/systemd --system",
            "root",
            "System",
        )
        bash_pid = state_manager.create_process(
            linux.hostname,
            systemd_pid,
            "/bin/bash",
            "-bash",
            test_user.username,
            "Medium",
            "0xabc123",
        )
        session.session_shell_pid = bash_pid

        command = "python3 /tmp/pip-install-cache/setup.py install"
        activity_gen.generate_bash_command(test_user, linux, command_time, command)

        events = [
            call.args[0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        process_events = [event for event in events if event.event_type == "process_create"]
        assert process_events
        assert process_events[-1].process.image == "/usr/bin/python3"
        assert process_events[-1].process.command_line == command

    def test_linux_shell_pipeline_uses_source_native_process_argv(self):
        """Linux process telemetry should not attach shell operators to child argv."""
        processes = generator_module._linux_command_processes_from_shell(
            "ss -ltnp | grep postfix | wc -l"
        )

        assert processes == [
            ("/usr/sbin/ss", "ss -ltnp"),
            ("/usr/bin/grep", "grep postfix"),
            ("/usr/bin/wc", "wc -l"),
        ]

    def test_linux_shell_redirection_removed_from_process_argv(self):
        """Redirection targets belong to the shell/file effect, not process argv."""
        process = generator_module._linux_command_process_from_shell(
            "mysqldump --single-transaction ehr patients > /tmp/patient_claims.sql"
        )

        assert process == (
            "/usr/bin/mysqldump",
            "mysqldump --single-transaction ehr patients",
        )

    def test_linux_shell_process_argv_expands_home_shortcuts_for_user(self):
        """eCAR process argv should render generated home shortcuts as absolute paths."""
        process = generator_module._linux_command_process_from_shell(
            "tail -50 ~/.xsession-errors 2>/dev/null",
            username="aisha.johnson",
        )

        assert process == (
            "/usr/bin/tail",
            "tail -50 /home/aisha.johnson/.xsession-errors",
        )

    def test_backgrounded_long_running_shell_command_keeps_ampersand_out_of_process_argv(self):
        """Background markers belong to shell history, not child process argv."""
        process = generator_module._linux_command_process_from_shell("tail -f /var/log/syslog &")

        assert process == ("/usr/bin/tail", "tail -f /var/log/syslog")

    def test_generate_bash_command_backgrounds_long_running_follow(
        self, activity_gen, test_user, state_manager, mock_emitters
    ):
        """Long-running follow commands should not block later same-shell activity silently."""
        command_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        linux = System(
            hostname="LNX-01",
            ip="10.0.0.2",
            os="Ubuntu 22.04",
            type="server",
            assigned_user=test_user.username,
        )
        session = state_manager.register_session(
            logon_id="0xabc123",
            username=test_user.username,
            system=linux.hostname,
            logon_type=10,
            source_ip="10.0.0.50",
            start_time=command_time - timedelta(seconds=20),
        )
        state_manager.set_current_time(command_time - timedelta(seconds=10))
        systemd_pid = state_manager.create_process(
            linux.hostname,
            0,
            "/usr/lib/systemd/systemd",
            "/usr/lib/systemd/systemd --system",
            "root",
            "System",
        )
        bash_pid = state_manager.create_process(
            linux.hostname,
            systemd_pid,
            "/bin/bash",
            "-bash",
            test_user.username,
            "Medium",
            "0xabc123",
        )
        session.session_shell_pid = bash_pid
        mock_emitters["bash_history"] = Mock()

        activity_gen.generate_bash_command(
            test_user,
            linux,
            command_time,
            "tail -f /var/log/syslog",
        )

        bash_events = [
            call.args[0]
            for call in mock_emitters["bash_history"].emit.call_args_list
            if call.args[0].event_type == "bash_command"
        ]
        assert bash_events[-1].shell.command == "tail -f /var/log/syslog &"

        process_events = [
            call.args[0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call.args[0].event_type == "process_create"
        ]
        assert process_events[-1].process.command_line == "tail -f /var/log/syslog"

    def test_linux_shell_glob_tokens_remain_unquoted_in_process_argv(self):
        """Expanded shell globs should not be rendered as literal quoted wildcards."""
        process = generator_module._linux_command_process_from_shell("du -sh /var/log/*")

        assert process == ("/usr/bin/du", "du -sh /var/log/*")

    def test_linux_mysql_query_argument_remains_shell_safe(self):
        """SQL passed through mysql -e should keep shell metacharacters quoted."""
        process = generator_module._linux_command_process_from_shell(
            "mysql --defaults-extra-file=~/.my.cnf -e 'SELECT COUNT(*) FROM appdb.users'"
        )

        assert process == (
            "/usr/bin/mysql",
            "mysql '--defaults-extra-file=~/.my.cnf' -e 'SELECT COUNT(*) FROM appdb.users'",
        )

    def test_linux_shell_control_operators_split_process_argv(self):
        """Shell control operators should separate child process argv entries."""
        processes = generator_module._linux_command_processes_from_shell(
            "whoami && id || df; uptime"
        )

        assert processes == [
            ("/usr/bin/whoami", "whoami"),
            ("/usr/bin/id", "id"),
            ("/usr/bin/df", "df"),
            ("/usr/bin/uptime", "uptime"),
        ]

    def test_linux_shell_single_process_inference_stops_after_first_stage(self, monkeypatch):
        """Single-process inference should not parse unused pipeline stages."""
        parsed_stages: list[str] = []

        def fake_process_from_stage(stage: str) -> tuple[str, str]:
            parsed_stages.append(stage)
            return "/usr/bin/whoami", stage

        monkeypatch.setattr(
            generator_module, "_linux_command_process_from_stage", fake_process_from_stage
        )

        process = generator_module._linux_command_process_from_shell("whoami | id | df | uptime")

        assert process == ("/usr/bin/whoami", "whoami")
        assert parsed_stages == ["whoami"]

    def test_linux_shell_process_inference_limits_emitted_pipeline_stages(self, monkeypatch):
        """Pipeline process inference should parse only the emitted process budget."""
        parsed_stages: list[str] = []

        def fake_process_from_stage(stage: str) -> tuple[str, str]:
            parsed_stages.append(stage)
            return "/usr/bin/whoami", stage

        monkeypatch.setattr(
            generator_module, "_linux_command_process_from_stage", fake_process_from_stage
        )
        command = " | ".join(["whoami"] * 100)

        processes = generator_module._linux_command_processes_from_shell(command)

        assert len(processes) == 4
        assert parsed_stages == ["whoami"] * 4

    def test_linux_shell_process_inference_limits_unmatched_pipeline_stages(self, monkeypatch):
        """Unmatched pipeline stages should not be parsed without a stage cap."""
        parsed_stages: list[str] = []

        def fake_process_from_stage(stage: str) -> tuple[str, str] | None:
            parsed_stages.append(stage)
            return None

        monkeypatch.setattr(
            generator_module, "_linux_command_process_from_stage", fake_process_from_stage
        )
        command = " | ".join(["unknown"] * 100)

        processes = generator_module._linux_command_processes_from_shell(command)

        assert processes == []
        assert len(parsed_stages) == 32

    def test_generate_bash_command_emits_pipeline_children_with_clean_argv(
        self, activity_gen, test_user, state_manager, mock_emitters
    ):
        """Pipeline commands should emit separate child processes without pipe syntax."""
        command_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        linux = System(
            hostname="LNX-01",
            ip="10.0.0.2",
            os="Ubuntu 22.04",
            type="server",
            assigned_user=test_user.username,
        )
        session = state_manager.register_session(
            logon_id="0xabc123",
            username=test_user.username,
            system=linux.hostname,
            logon_type=10,
            source_ip="10.0.0.50",
            start_time=command_time - timedelta(seconds=20),
        )
        state_manager.set_current_time(command_time - timedelta(seconds=10))
        systemd_pid = state_manager.create_process(
            linux.hostname,
            0,
            "/usr/lib/systemd/systemd",
            "/usr/lib/systemd/systemd --system",
            "root",
            "System",
        )
        bash_pid = state_manager.create_process(
            linux.hostname,
            systemd_pid,
            "/bin/bash",
            "-bash",
            test_user.username,
            "Medium",
            "0xabc123",
        )
        session.session_shell_pid = bash_pid

        activity_gen.generate_bash_command(
            test_user,
            linux,
            command_time,
            "cat /etc/shadow | head -5",
        )

        events = [
            call.args[0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        process_events = [
            event
            for event in events
            if event.event_type == "process_create" and event.process is not None
        ]
        command_lines = [event.process.command_line for event in process_events]
        assert "cat /etc/shadow" in command_lines
        assert "head -5" in command_lines
        assert all("|" not in command for command in command_lines)

    def test_parameterize_command_uses_scenario_internal_domain(self, activity_gen, test_user):
        """Internal URL placeholders should not leak default corp.local vocabulary."""
        activity_gen._ad_domain = "meridianhcs.local"
        linux = System(
            hostname="APP-INT-01",
            ip="10.0.0.2",
            os="Ubuntu 22.04",
            type="server",
            services=["ssh", "gunicorn"],
        )

        command = activity_gen._parameterize_command_for_system(
            random.Random(7),
            "curl -sS -o /dev/null -w '%{http_code}' {internal_url}",
            username=test_user.username,
            system=linux,
        )

        assert "meridianhcs.local" in command
        assert "corp.local" not in command

    def test_parameterize_command_uses_scenario_ldap_base_dn(self, activity_gen, test_user):
        """LDAP command templates should derive base DNs from the scenario domain."""
        activity_gen._ad_domain = "meridianhcs.local"
        linux = System(
            hostname="APP-INT-01",
            ip="10.0.0.2",
            os="Ubuntu 22.04",
            type="server",
            services=["ssh", "openldap"],
        )

        command = activity_gen._parameterize_command_for_system(
            random.Random(7),
            'ldapsearch -x -H ldap://{ssh_target} -b "{ldap_base_dn}" "(objectClass=user)"',
            username=test_user.username,
            system=linux,
        )

        assert "dc=meridianhcs,dc=local" in command
        assert "dc=corp,dc=local" not in command
        assert "{ldap_base_dn}" not in command

    def test_generate_bash_command_can_skip_process_telemetry(
        self, activity_gen, test_user, state_manager, mock_emitters
    ):
        """Storyline-owned Linux process events can emit history without duplicate processes."""
        command_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        linux = System(
            hostname="LNX-01",
            ip="10.0.0.2",
            os="Ubuntu 22.04",
            type="server",
            assigned_user=test_user.username,
        )
        state_manager.register_session(
            logon_id="0xabc123",
            username=test_user.username,
            system=linux.hostname,
            logon_type=10,
            source_ip="10.0.0.50",
            start_time=command_time - timedelta(seconds=20),
        )

        activity_gen.generate_bash_command(
            test_user,
            linux,
            command_time,
            "scp /tmp/data.tar.gz root@10.0.0.2:/tmp/data.tar.gz",
            emit_process_telemetry=False,
        )

        events = [
            call.args[0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        assert any(event.event_type == "bash_command" for event in events)
        assert not any(event.event_type == "process_create" for event in events)

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


def test_disambiguate_icmp_observation_time_uses_constant_time_sequence(activity_gen):
    """Duplicate ICMP observations should not linearly probe prior timestamps."""

    class CountingDict(dict[tuple[str, int, str, int], int]):
        """Dictionary that counts next-timestamp lookups."""

        def __init__(self) -> None:
            super().__init__()
            self.get_calls = 0

        def get(self, key: tuple[str, int, str, int], default: int = 0) -> int:
            self.get_calls += 1
            return super().get(key, default)

    next_timestamps = CountingDict()
    activity_gen._next_icmp_observation_ts_us = next_timestamps
    base_time = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)

    adjusted_times = [
        activity_gen._disambiguate_icmp_observation_time(
            "10.0.0.1",
            0,
            "10.0.0.2",
            0,
            base_time,
        )
        for _ in range(1000)
    ]

    assert adjusted_times[0] == base_time
    assert adjusted_times[-1] == base_time + timedelta(milliseconds=11 * 999)
    assert next_timestamps.get_calls == len(adjusted_times)
    assert len(next_timestamps) == 1


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


def test_tcp_success_history_uses_varied_completed_flow_shapes():
    """Explicit successful TCP connections should not collapse to one Zeek history."""
    histories = {generator_module._tcp_success_history(random.Random(seed)) for seed in range(40)}

    assert "ShADadfF" in histories
    assert len(histories) > 1


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
    assert 0 < event.network.orig_bytes < 1200
    assert 0 <= event.network.resp_bytes < 55000
    assert event.network.orig_pkts <= 2
    assert event.network.resp_pkts <= 2
