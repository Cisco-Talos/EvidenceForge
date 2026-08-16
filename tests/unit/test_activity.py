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

from evidenceforge.events.base import CanonicalOccurrence, OccurrenceBuilder
from evidenceforge.events.contexts import (
    FirewallContext,
    HttpContext,
    HttpRequestEntityContext,
    ProxyContext,
)
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.lifecycle import SessionEndPlan
from evidenceforge.events.observation import ObservationPolicy
from evidenceforge.generation.actions import (
    AccountChangedActionBundle,
    AccountChangedRequest,
    AccountCreatedActionBundle,
    AccountCreatedRequest,
    AccountDeletedActionBundle,
    AccountDeletedRequest,
    AnonymousLogonActionBundle,
    AnonymousLogonRequest,
    CreateRemoteThreadActionBundle,
    CreateRemoteThreadRequest,
    ExplicitCredentialUseActionBundle,
    ExplicitCredentialUseRequest,
    FailedLogonActionBundle,
    FailedLogonRequest,
    GroupMembershipChangeActionBundle,
    GroupMembershipChangeRequest,
    KerberosConnectionAuditActionBundle,
    KerberosConnectionAuditRequest,
    KerberosLogonTicketsActionBundle,
    KerberosLogonTicketsRequest,
    KerberosPreauthFailureActionBundle,
    KerberosPreauthFailureRequest,
    KerberosServiceTicketActionBundle,
    KerberosServiceTicketRequest,
    KerberosTgtActionBundle,
    KerberosTgtRenewalActionBundle,
    KerberosTgtRenewalRequest,
    KerberosTgtRequest,
    LinuxShellCommandActionBundle,
    LinuxShellCommandRequest,
    LogClearedActionBundle,
    LogClearedRequest,
    LogoffActionBundle,
    LogoffRequest,
    LogonActionBundle,
    LogonRequest,
    MachineAccountLogonActionBundle,
    MachineAccountLogonRequest,
    NetworkConnectionActionBundle,
    NetworkConnectionRequest,
    NmapCommandProbeActionBundle,
    NmapCommandProbeRequest,
    NtlmValidationActionBundle,
    NtlmValidationRequest,
    PasswordChangeActionBundle,
    PasswordChangeRequest,
    PasswordResetActionBundle,
    PasswordResetRequest,
    ProcessAccessActionBundle,
    ProcessAccessRequest,
    ProcessExecutionActionBundle,
    ProcessExecutionRequest,
    ProcessTerminationActionBundle,
    ProcessTerminationRequest,
    RdpSessionActionBundle,
    RdpSessionRequest,
    ScheduledTaskActionBundle,
    ScheduledTaskRequest,
    ServiceLogonActionBundle,
    ServiceLogonRequest,
    WindowsServiceInstallActionBundle,
    WindowsServiceInstallRequest,
    WorkstationLockActionBundle,
    WorkstationLockRequest,
    WorkstationLockResult,
    WorkstationUnlockActionBundle,
    WorkstationUnlockRequest,
    plan_linux_pipeline_stage_times,
)
from evidenceforge.generation.activity import (
    BASELINE_PATTERNS,
    EXTERNAL_IPS,
    ActivityGenerator,
    _is_invalid_network_connection,
)
from evidenceforge.generation.activity import generator as generator_module
from evidenceforge.generation.activity.generator import (
    _apply_plaintext_http_policy,
    _extract_http_url_from_command,
    _extract_image_from_command,
    _http_context_from_process_command,
    _jitter_default_connection_duration,
    _linux_foreground_lifetime,
    _linux_ssh_client_command_line,
    _network_effect_context_for_process,
    _normalize_http_context_for_source_native_response,
    _source_native_http_referrer,
    _windows_foreground_lifetime,
    _zeek_conn_observation_time,
)
from evidenceforge.generation.activity.http_content import response_size_for_status
from evidenceforge.generation.activity.tls_realism import (
    certificate_analyzer_delay_ms,
    certificate_file_size,
)
from evidenceforge.generation.network_visibility import NetworkVisibilityEngine
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models import NetworkConfig, NetworkSegment, System, User
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.rng import reset_thread_rng
from tests.network_factories import network_plan


def test_linux_trivial_command_lifetime_is_subsecond():
    """Instant Linux utilities should not look like multi-second process telemetry."""
    lifetime = _linux_foreground_lifetime("/usr/bin/date", "date -u")

    assert lifetime is not None
    assert lifetime[1] <= 0.8


def test_linux_gui_editor_process_is_not_modeled_as_short_foreground_exit():
    """Electron-style editor launches should not terminate like a one-shot CLI command."""
    lifetime = _linux_foreground_lifetime(
        "/usr/bin/code",
        "code --no-sandbox /home/lina.nguyen/repos/infra-config",
    )

    assert lifetime is None


@pytest.mark.parametrize(
    ("image", "command_line"),
    [
        (r"C:\Users\alice\AppData\Local\Temp\ChromeSetup.exe", "ChromeSetup.exe --silent"),
        (r"C:\Windows\Temp\KB5034441_update.exe", "KB5034441_update.exe /quiet"),
        (
            r"C:\Program Files\Meridian\OpsAgent\ops-agent.exe",
            r'"C:\Program Files\Meridian\OpsAgent\ops-agent.exe" check --once',
        ),
    ],
)
def test_windows_one_shot_install_and_check_commands_have_bounded_lifetimes(
    image: str,
    command_line: str,
) -> None:
    """One-shot installers and checks must not inherit workstation-session lifetimes."""
    lifetime = _windows_foreground_lifetime(image, command_line)

    assert lifetime is not None
    assert lifetime[1] <= 360.0


def test_linux_server_ssh_client_requires_ssh_source_session():
    """Linux server SSH client telemetry should not attach to invisible local sessions."""
    state_manager = StateManager()
    generator = ActivityGenerator(state_manager, {})
    timestamp = datetime(2024, 3, 18, 15, 33, tzinfo=UTC)
    user = User(username="aisha.johnson", full_name="Aisha Johnson", email="aisha@example.com")
    server = System(hostname="DB-PROD-01", ip="10.10.4.10", os="Ubuntu 22.04", type="server")
    generator._scenario_start_time = timestamp - timedelta(hours=1)

    state_manager.set_current_time(timestamp - timedelta(minutes=30))
    state_manager.create_session(
        username=user.username,
        system=server.hostname,
        logon_type=2,
        source_ip="-",
        session_kind="interactive",
    )

    assert generator._active_source_linux_session(user, server, timestamp) is None


def test_linux_server_ssh_client_uses_active_ssh_source_session():
    """Linux server SSH client telemetry can attach to a visible SSH session."""
    state_manager = StateManager()
    generator = ActivityGenerator(state_manager, {})
    timestamp = datetime(2024, 3, 18, 15, 33, tzinfo=UTC)
    user = User(username="aisha.johnson", full_name="Aisha Johnson", email="aisha@example.com")
    server = System(hostname="DB-PROD-01", ip="10.10.4.10", os="Ubuntu 22.04", type="server")

    state_manager.set_current_time(timestamp - timedelta(minutes=5))
    logon_id = state_manager.create_session(
        username=user.username,
        system=server.hostname,
        logon_type=10,
        source_ip="10.10.1.21",
        source_port=51234,
        session_kind="ssh",
    )
    state_manager.update_session_metadata(
        logon_id,
        network_close_time=timestamp + timedelta(minutes=15),
    )

    session = generator._active_source_linux_session(user, server, timestamp)

    assert session is not None
    assert session.logon_id == logon_id


def test_linux_server_ssh_client_requires_session_through_transport_close():
    """A source SSH process must not outlive the inbound session that owns it."""
    state_manager = StateManager()
    generator = ActivityGenerator(state_manager, {})
    timestamp = datetime(2024, 3, 18, 15, 33, tzinfo=UTC)
    user = User(username="aisha.johnson", full_name="Aisha Johnson", email="aisha@example.com")
    server = System(hostname="APP-INT-01", ip="10.10.3.10", os="Ubuntu 22.04", type="server")

    state_manager.set_current_time(timestamp - timedelta(minutes=5))
    logon_id = state_manager.create_session(
        username=user.username,
        system=server.hostname,
        logon_type=10,
        source_ip="10.10.1.21",
        source_port=51234,
        session_kind="ssh",
    )
    state_manager.update_session_metadata(
        logon_id,
        network_close_time=timestamp + timedelta(minutes=5),
    )

    session = generator._active_source_linux_session(
        user,
        server,
        timestamp,
        required_until=timestamp + timedelta(minutes=10),
    )

    assert session is None


def test_linux_ssh_client_command_line_varies_source_native_forms():
    """Source-side SSH history should not collapse to one bare user@host form."""
    commands = {
        _linux_ssh_client_command_line(
            exe_name="ssh",
            username="aisha.johnson",
            target_host="WEB-EXT-01.meridianhcs.local",
            target_ip="10.10.2.30",
            source_hostname="WS-OHADDAD-01",
            source_port=51000 + idx,
            requested_time=datetime(2024, 3, 18, 12, idx % 60, tzinfo=UTC),
        )
        for idx in range(24)
    }

    assert len(commands) >= 6
    assert any(command.startswith("ssh -l aisha.johnson ") for command in commands)
    assert any(" -i " in command for command in commands)
    assert any(command.startswith("ssh -o ") for command in commands)
    assert all(command.startswith("ssh ") for command in commands)


def test_linux_server_bash_history_requires_visible_session():
    """Linux server bash history should not be emitted without a session owner."""
    generator = ActivityGenerator(StateManager(), {})
    timestamp = datetime(2024, 3, 18, 12, 0, tzinfo=UTC)
    user = User(username="lina.nguyen", full_name="Lina Nguyen", email="lina@example.com")
    server = System(hostname="DB-PROD-01", ip="10.10.4.10", os="Ubuntu 22.04", type="server")
    generator._scenario_start_time = timestamp - timedelta(hours=1)

    assert generator._fit_bash_history_time_to_linux_session(user, server, timestamp) is None


def test_zeek_connection_observation_time_varies_submillisecond_suffixes():
    """Burst flows should not preserve one generated microsecond suffix across tuples."""
    base = datetime(2024, 3, 18, 14, 11, 22, 705641, tzinfo=UTC)

    observed = [
        _zeek_conn_observation_time(
            base + timedelta(milliseconds=idx * 307),
            "10.10.3.10",
            32768 + idx,
            "10.10.2.20",
            port,
            "tcp",
            "",
        )
        for idx, port in enumerate([22, 80, 445, 443, 3306])
    ]

    assert len({ts.microsecond % 1000 for ts in observed}) > 1


class TestApacheRawSyslogNormalization:
    def test_generate_raw_skips_format_disabled_by_output_filter(self):
        """Valid raw events should not fail when their emitter was intentionally filtered."""
        dispatcher = EventDispatcher(state_manager=StateManager(), emitters={})
        generator = ActivityGenerator(dispatcher.state_manager, {}, dispatcher=dispatcher)

        generator.generate_raw(
            datetime(2024, 3, 18, 12, 0, tzinfo=UTC),
            "syslog",
            {"message": "filtered"},
        )

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
    def test_http_normalization_preserves_explicit_error_response_mime(self):
        """Caller-provided response content types remain authoritative for errors."""
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

        assert normalized.resp_mime_types == ("image/svg+xml",)

    def test_http_normalization_removes_head_response_body(self):
        """HEAD response metadata must not claim entity-body bytes."""
        http = HttpContext(
            method="HEAD",
            host="portal.example.com",
            uri="/sitemap.xml",
            response_body_len=478,
            status_code=200,
            status_msg="OK",
            resp_mime_types=["application/xml"],
        )

        normalized = _normalize_http_context_for_source_native_response(http)

        assert normalized.response_body_len == 0
        assert normalized.resp_mime_types == ()

    def test_plaintext_redirect_does_not_restore_head_response_body(self, monkeypatch):
        """Redirect policy must preserve bodyless HEAD semantics."""
        monkeypatch.setattr(
            "evidenceforge.generation.activity.proxy_uri.plaintext_http_redirect_status",
            lambda *_args, **_kwargs: 301,
        )
        http = HttpContext(
            method="HEAD",
            host="portal.example.com",
            uri="/sitemap.xml",
            response_body_len=0,
            status_code=200,
            status_msg="OK",
        )

        redirected = _apply_plaintext_http_policy(
            http,
            hostname="portal.example.com",
            dst_ip="203.0.113.25",
            dst_port=80,
        )

        assert redirected.status_code in {301, 302}
        assert redirected.response_body_len == 0

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
        assert first_http.resp_mime_types == ("image/x-icon",)

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

    def test_tool_http_referrer_drops_browser_navigation_context(self):
        """Command-line HTTP clients should not inherit browser search referrers."""
        assert (
            _source_native_http_referrer(
                "curl/7.88.1",
                "https://www.google.com/search?q=www+office+com",
            )
            == ""
        )
        assert _source_native_http_referrer(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "https://www.google.com/search?q=www+office+com",
        ).startswith("https://www.google.com/")

    def test_plaintext_http_referrer_drops_https_downgrade(self):
        """Browser HTTP requests should follow no-referrer-when-downgrade defaults."""
        assert (
            _source_native_http_referrer(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
                "https://www.bing.com/search?q=www+office+com",
                request_scheme="http",
                request_port=80,
            )
            == ""
        )
        assert _source_native_http_referrer(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "http://www.office.com/",
            request_scheme="http",
            request_port=80,
        ).startswith("http://www.office.com/")

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


class TestNetworkConnectionActionBundle:
    """Tests for the internal network connection bundle boundary."""

    def test_network_connection_bundle_anchor_is_stable(self):
        """Network connection requests should expose durable deterministic anchors."""
        source_system = System(
            hostname="APP-01",
            ip="10.0.0.10",
            os="Ubuntu 24.04",
            type="server",
        )
        request = NetworkConnectionRequest(
            src_ip=source_system.ip,
            dst_ip="203.0.113.10",
            time=datetime(2024, 3, 18, 12, 0, tzinfo=UTC),
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=1.25,
            orig_bytes=512,
            resp_bytes=4096,
            src_port=49152,
            emit_dns=True,
            pid=1234,
            source_system=source_system,
            hostname="api.example.com",
        )

        first = NetworkConnectionActionBundle(Mock(), request).anchor
        second = NetworkConnectionActionBundle(Mock(), request).anchor

        assert first == second
        assert first.family == "network_connection"
        assert first.stable_id.startswith("network-connection-")

    def test_network_connection_bundle_delegates_to_adapter(self):
        """The bundle should execute through the action-owned transaction planner."""
        request = NetworkConnectionRequest(
            src_ip="10.0.0.10",
            dst_ip="203.0.113.10",
            time=datetime(2024, 3, 18, 12, 0, tzinfo=UTC),
            dst_port=80,
            proto="tcp",
            service="http",
        )
        executor = Mock()
        with patch(
            "evidenceforge.generation.actions.network_transaction_planner."
            "NetworkTransactionPlanner.execute",
            return_value="Cabc123",
        ) as execute:
            uid = NetworkConnectionActionBundle(executor, request).execute()

        assert uid == "Cabc123"
        execute.assert_called_once_with(request)


class TestNetworkValidation:
    """Tests for network connection validation."""

    def test_same_src_dst_is_valid(self):
        """Same-IP connections are valid (handled by OccurrenceBuilder.local_only)."""
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
        """generate_logon should create session and dispatch OccurrenceBuilder."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        logon_id = activity_gen.generate_logon(test_user, test_system, timestamp)

        # Verify session created in state manager
        sessions = state_manager.get_sessions_for_user(test_user.username)
        assert len(sessions) == 1
        assert sessions[0].logon_id == logon_id
        assert sessions[0].username == test_user.username

        # Verify emitters received OccurrenceBuilder via dispatch
        assert mock_emitters["windows_event_security"].emit.called
        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.event_type == "logon"
        assert event.auth.username == test_user.username
        assert event.auth.logon_id == logon_id
        assert event.dst_host.os_category == "windows"

    def test_user_connection_owner_rejects_session_past_authoritative_end(
        self, activity_gen, test_user, test_system, state_manager
    ):
        """Background flows must not create user processes after a fixed logoff."""
        session_start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        session_end = session_start + timedelta(hours=1)
        activity_time = session_end + timedelta(minutes=1)
        logon_id = "0xabc123"
        state_manager.register_session(
            logon_id=logon_id,
            username=test_user.username,
            system=test_system.hostname,
            logon_type=2,
            source_ip="-",
            start_time=session_start,
            session_kind="interactive",
        )
        state_manager.plan_session_end(
            logon_id,
            SessionEndPlan(
                canonical_end=session_end,
                authority="explicit_storyline",
                storyline_event_id="evt-logoff",
            ),
        )
        activity_gen._users_by_username = {test_user.username: test_user}

        owner = activity_gen._ensure_user_connection_owner_process(
            source_system=test_system,
            time=activity_time,
            service="ssh",
            dst_port=22,
            os_category="windows",
            hostname="server.example",
            ssh_attempted_username=None,
        )

        assert owner == (-1, None)
        assert state_manager.get_processes_on_system(test_system.hostname) == []

    def test_catalog_singleton_reuses_top_level_slack_but_not_renderer(
        self, activity_gen, test_user, test_system, state_manager
    ):
        """Canonical process creation reuses bootstrap owners across entry paths."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        logon_id = state_manager.create_session(
            username=test_user.username,
            system=test_system.hostname,
            logon_type=2,
            source_ip="-",
            start_time=timestamp - timedelta(minutes=1),
            session_kind="interactive",
        )
        image = rf"C:\Users\{test_user.username}\AppData\Local\slack\Slack.exe"
        first_pid = activity_gen.generate_process(
            test_user,
            test_system,
            timestamp,
            logon_id,
            image,
            f'"{image}" --startup',
        )
        reused_pid = activity_gen.generate_process(
            test_user,
            test_system,
            timestamp + timedelta(minutes=5),
            logon_id,
            image,
            f'"{image}" --process-start-args',
        )
        renderer_pid = activity_gen.generate_process(
            test_user,
            test_system,
            timestamp + timedelta(minutes=5, seconds=1),
            logon_id,
            image,
            f'"{image}" --type=renderer',
            parent_pid=first_pid,
        )

        assert reused_pid == first_pid
        assert renderer_pid != first_pid

    def test_singleton_application_interval_rejects_reverse_order_overlap(
        self, activity_gen, test_system
    ) -> None:
        """A later-planned owner also blocks an earlier overlapping request."""
        key = activity_gen._singleton_application_key(
            test_system,
            "analyst",
            "0x1234",
            r"C:\Program Files\Example\Example.exe",
        )
        later_start = datetime(2024, 1, 15, 12, 0, 0, tzinfo=UTC)
        session_end = later_start + timedelta(hours=3)

        assert activity_gen.claim_singleton_application_interval(key, later_start, session_end)
        assert not activity_gen.claim_singleton_application_interval(
            key,
            later_start - timedelta(hours=1),
            session_end,
        )

    def test_linux_read_file_side_effect_maps_to_file_read(self, monkeypatch):
        """Linux read side effects from EDR pools should emit file_read events."""
        state_manager = StateManager()
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        ecar_emitter = Mock()
        emitters = {"ecar": ecar_emitter}
        dispatcher = EventDispatcher(state_manager=state_manager, emitters=emitters)
        activity_gen = ActivityGenerator(state_manager, emitters, dispatcher=dispatcher)
        system = System(hostname="LNX-01", ip="10.0.0.2", os="Ubuntu 22.04", type="server")
        user = User(username="root", full_name="Root", email="root@example.com")
        systemd_pid = state_manager.create_process(
            system=system.hostname,
            parent_pid=0,
            image="/usr/lib/systemd/systemd",
            command_line="/usr/lib/systemd/systemd",
            username="root",
            integrity_level="System",
        )

        class AlwaysSideEffectRng(random.Random):
            def random(self) -> float:
                return 0.0

        monkeypatch.setattr(
            "evidenceforge.generation.activity.generator._get_rng",
            lambda: AlwaysSideEffectRng(1),
        )
        monkeypatch.setattr(
            "evidenceforge.generation.activity.edr_pools.select_file_side_effect",
            lambda **_kwargs: ("read", "/etc/ssh/sshd_config"),
        )

        activity_gen.generate_process(
            user=user,
            system=system,
            time=timestamp + timedelta(seconds=1),
            logon_id="",
            process_name="/usr/sbin/sshd",
            command_line="/usr/sbin/sshd -D",
            parent_pid=systemd_pid,
            allow_existing_browser_reuse=False,
            allow_browser_launch_spacing=False,
        )

        file_events = [
            call.args[0]
            for call in ecar_emitter.emit.call_args_list
            if call.args[0].event_type == "file_read"
        ]
        assert len(file_events) == 1
        assert file_events[0].file is not None
        assert file_events[0].file.action == "read"
        assert file_events[0].file.path == "/etc/ssh/sshd_config"

    def test_auth_session_bundle_anchors_are_stable(self, test_user, test_system):
        """Auth/session requests should expose durable deterministic anchors."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        logon_request = LogonRequest(
            user=test_user,
            system=test_system,
            time=timestamp,
            logon_type=3,
            source_ip="10.0.0.44",
            source_port=51234,
        )
        logoff_request = LogoffRequest(
            user=test_user,
            system=test_system,
            time=timestamp + timedelta(minutes=5),
            logon_id="0x12345",
            logon_type=3,
        )
        failed_request = FailedLogonRequest(
            user=test_user,
            system=test_system,
            time=timestamp,
            logon_type=3,
            source_ip="10.0.0.44",
        )

        assert (
            LogonActionBundle(Mock(), logon_request).anchor
            == LogonActionBundle(
                Mock(),
                logon_request,
            ).anchor
        )
        assert (
            LogoffActionBundle(Mock(), logoff_request).anchor
            == LogoffActionBundle(
                Mock(),
                logoff_request,
            ).anchor
        )
        assert (
            FailedLogonActionBundle(
                Mock(),
                failed_request,
            ).anchor
            == FailedLogonActionBundle(Mock(), failed_request).anchor
        )

    def test_auth_session_bundles_delegate_to_adapter(self, test_user, test_system):
        """Auth/session bundles should preserve the current generator adapter contract."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        logon_request = LogonRequest(user=test_user, system=test_system, time=timestamp)
        logoff_request = LogoffRequest(
            user=test_user,
            system=test_system,
            time=timestamp + timedelta(minutes=5),
            logon_id="0x12345",
        )
        failed_request = FailedLogonRequest(user=test_user, system=test_system, time=timestamp)
        executor = Mock()
        executor._execute_logon_bundle.return_value = "0x12345"

        assert LogonActionBundle(executor, logon_request).execute() == "0x12345"
        LogoffActionBundle(executor, logoff_request).execute()
        FailedLogonActionBundle(executor, failed_request).execute()

        executor._execute_logon_bundle.assert_called_once_with(logon_request)
        executor._execute_logoff_bundle.assert_called_once_with(logoff_request)
        executor._execute_failed_logon_bundle.assert_called_once_with(failed_request)

    def test_auxiliary_auth_session_bundle_anchors_are_stable(self, test_user, test_system):
        """Auxiliary auth/session requests should expose durable deterministic anchors."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        requests_and_bundles = [
            (
                ServiceLogonRequest(system=test_system, time=timestamp, service_account="SYSTEM"),
                ServiceLogonActionBundle,
            ),
            (
                MachineAccountLogonRequest(
                    hostname=test_system.hostname,
                    machine_username=f"{test_system.hostname}$",
                    dc_hostname="DC-01",
                    source_ip=test_system.ip,
                    dc_ip="10.0.0.10",
                    time=timestamp,
                ),
                MachineAccountLogonActionBundle,
            ),
            (
                NtlmValidationRequest(
                    username=test_user.username,
                    workstation=test_system.hostname,
                    dc_hostname="DC-01",
                    time=timestamp,
                ),
                NtlmValidationActionBundle,
            ),
            (
                AnonymousLogonRequest(system=test_system, time=timestamp),
                AnonymousLogonActionBundle,
            ),
            (
                WorkstationLockRequest(
                    user=test_user,
                    system=test_system,
                    time=timestamp,
                    logon_id="0x12345",
                ),
                WorkstationLockActionBundle,
            ),
            (
                WorkstationUnlockRequest(
                    user=test_user,
                    system=test_system,
                    time=timestamp,
                    logon_id="0x12345",
                ),
                WorkstationUnlockActionBundle,
            ),
        ]

        for request, bundle_cls in requests_and_bundles:
            assert bundle_cls(Mock(), request).anchor == bundle_cls(Mock(), request).anchor

    def test_auxiliary_auth_session_bundles_delegate_to_adapter(self, test_user, test_system):
        """Auxiliary auth/session bundles should preserve the generator adapter contract."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        service_request = ServiceLogonRequest(
            system=test_system,
            time=timestamp,
            service_account="SYSTEM",
        )
        machine_request = MachineAccountLogonRequest(
            hostname=test_system.hostname,
            machine_username=f"{test_system.hostname}$",
            dc_hostname="DC-01",
            source_ip=test_system.ip,
            dc_ip="10.0.0.10",
            time=timestamp,
        )
        ntlm_request = NtlmValidationRequest(
            username=test_user.username,
            workstation=test_system.hostname,
            dc_hostname="DC-01",
            time=timestamp,
        )
        anonymous_request = AnonymousLogonRequest(system=test_system, time=timestamp)
        lock_request = WorkstationLockRequest(
            user=test_user,
            system=test_system,
            time=timestamp,
            logon_id="0x12345",
        )
        unlock_request = WorkstationUnlockRequest(
            user=test_user,
            system=test_system,
            time=timestamp,
            logon_id="0x12345",
        )
        executor = Mock()
        executor._execute_service_logon_bundle.return_value = "0x3e7"
        executor._execute_workstation_lock_bundle.return_value = WorkstationLockResult(emitted=True)

        assert ServiceLogonActionBundle(executor, service_request).execute() == "0x3e7"
        MachineAccountLogonActionBundle(executor, machine_request).execute()
        NtlmValidationActionBundle(executor, ntlm_request).execute()
        AnonymousLogonActionBundle(executor, anonymous_request).execute()
        lock_result = WorkstationLockActionBundle(executor, lock_request).execute()
        WorkstationUnlockActionBundle(executor, unlock_request).execute()

        executor._execute_service_logon_bundle.assert_called_once_with(service_request)
        executor._execute_machine_account_logon_bundle.assert_called_once_with(machine_request)
        executor._execute_ntlm_validation_bundle.assert_called_once_with(ntlm_request)
        executor._execute_anonymous_logon_bundle.assert_called_once_with(anonymous_request)
        executor._execute_workstation_lock_bundle.assert_called_once_with(lock_request)
        executor._execute_workstation_unlock_bundle.assert_called_once_with(unlock_request)
        assert lock_result.emitted is True

    def test_kerberos_dc_bundle_anchors_are_stable(self, test_user, test_system):
        """Kerberos/DC requests should expose durable deterministic anchors."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        logon_request = KerberosLogonTicketsRequest(
            user=test_user,
            system=test_system,
            time=timestamp,
            auth_package="Kerberos",
            source_ip="10.0.0.44",
        )
        connection_request = KerberosConnectionAuditRequest(
            src_ip="10.0.0.44",
            src_port=51234,
            dst_ip="10.0.0.10",
            time=timestamp,
            dst_port=88,
            proto="tcp",
            service="kerberos",
            source_system=test_system,
        )
        tgt_request = KerberosTgtRequest(
            username=test_user.username,
            source_ip="10.0.0.44",
            dc_hostname="DC-01",
            time=timestamp,
        )
        renewal_request = KerberosTgtRenewalRequest(
            username=test_user.username,
            source_ip="10.0.0.44",
            dc_hostname="DC-01",
            time=timestamp,
        )
        service_request = KerberosServiceTicketRequest(
            username=test_user.username,
            service_name="cifs/FILE-01",
            source_ip="10.0.0.44",
            dc_hostname="DC-01",
            time=timestamp,
        )
        failure_request = KerberosPreauthFailureRequest(
            username=test_user.username,
            source_ip="10.0.0.44",
            dc_hostname="DC-01",
            time=timestamp,
            status="0x18",
        )

        assert (
            KerberosLogonTicketsActionBundle(Mock(), logon_request).anchor
            == KerberosLogonTicketsActionBundle(Mock(), logon_request).anchor
        )
        assert (
            KerberosConnectionAuditActionBundle(Mock(), connection_request).anchor
            == KerberosConnectionAuditActionBundle(Mock(), connection_request).anchor
        )
        assert (
            KerberosTgtActionBundle(Mock(), tgt_request).anchor
            == KerberosTgtActionBundle(Mock(), tgt_request).anchor
        )
        assert (
            KerberosTgtRenewalActionBundle(Mock(), renewal_request).anchor
            == KerberosTgtRenewalActionBundle(Mock(), renewal_request).anchor
        )
        assert (
            KerberosServiceTicketActionBundle(Mock(), service_request).anchor
            == KerberosServiceTicketActionBundle(Mock(), service_request).anchor
        )
        assert (
            KerberosPreauthFailureActionBundle(Mock(), failure_request).anchor
            == KerberosPreauthFailureActionBundle(Mock(), failure_request).anchor
        )

    def test_kerberos_dc_bundles_delegate_to_adapter(self, test_user, test_system):
        """Kerberos/DC bundles should preserve the current generator adapter contract."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        logon_request = KerberosLogonTicketsRequest(
            user=test_user,
            system=test_system,
            time=timestamp,
            auth_package="Kerberos",
            source_ip="10.0.0.44",
        )
        connection_request = KerberosConnectionAuditRequest(
            src_ip="10.0.0.44",
            src_port=51234,
            dst_ip="10.0.0.10",
            time=timestamp,
            dst_port=88,
            proto="tcp",
            service="kerberos",
            source_system=test_system,
        )
        tgt_request = KerberosTgtRequest(
            username=test_user.username,
            source_ip="10.0.0.44",
            dc_hostname="DC-01",
            time=timestamp,
        )
        renewal_request = KerberosTgtRenewalRequest(
            username=test_user.username,
            source_ip="10.0.0.44",
            dc_hostname="DC-01",
            time=timestamp,
        )
        service_request = KerberosServiceTicketRequest(
            username=test_user.username,
            service_name="cifs/FILE-01",
            source_ip="10.0.0.44",
            dc_hostname="DC-01",
            time=timestamp,
        )
        failure_request = KerberosPreauthFailureRequest(
            username=test_user.username,
            source_ip="10.0.0.44",
            dc_hostname="DC-01",
            time=timestamp,
        )
        executor = Mock()

        KerberosLogonTicketsActionBundle(executor, logon_request).execute()
        KerberosConnectionAuditActionBundle(executor, connection_request).execute()
        KerberosTgtActionBundle(executor, tgt_request).execute()
        KerberosTgtRenewalActionBundle(executor, renewal_request).execute()
        KerberosServiceTicketActionBundle(executor, service_request).execute()
        KerberosPreauthFailureActionBundle(executor, failure_request).execute()

        executor._execute_kerberos_logon_tickets_bundle.assert_called_once_with(logon_request)
        executor._execute_kerberos_connection_audit_bundle.assert_called_once_with(
            connection_request
        )
        executor._execute_kerberos_tgt_bundle.assert_called_once_with(tgt_request)
        executor._execute_kerberos_tgt_renewal_bundle.assert_called_once_with(renewal_request)
        executor._execute_kerberos_service_ticket_bundle.assert_called_once_with(service_request)
        executor._execute_kerberos_preauth_failure_bundle.assert_called_once_with(failure_request)

    def test_windows_audit_bundle_anchors_are_stable(self, test_user, test_system):
        """Windows audit requests should expose durable deterministic anchors."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        requests_and_bundles = [
            (
                LogClearedRequest(user=test_user, system=test_system, time=timestamp),
                LogClearedActionBundle,
            ),
            (
                ScheduledTaskRequest(
                    user=test_user,
                    system=test_system,
                    time=timestamp,
                    task_name="Updater",
                    source_command_line="schtasks /create /tn Updater /tr calc.exe",
                ),
                ScheduledTaskActionBundle,
            ),
            (
                GroupMembershipChangeRequest(
                    actor=test_user,
                    system=test_system,
                    time=timestamp,
                    action="add",
                    scope="global",
                    group_name="Domain Admins",
                    group_sid="S-1-5-21-1-2-3-512",
                    member_username="svc_sqlreader",
                    member_sid="S-1-5-21-1-2-3-1105",
                ),
                GroupMembershipChangeActionBundle,
            ),
            (
                AccountCreatedRequest(
                    actor=test_user,
                    system=test_system,
                    time=timestamp,
                    target_username="svc_sqlreader",
                    target_sid="S-1-5-21-1-2-3-1105",
                ),
                AccountCreatedActionBundle,
            ),
            (
                AccountDeletedRequest(
                    actor=test_user,
                    system=test_system,
                    time=timestamp,
                    target_username="svc_sqlreader",
                    target_sid="S-1-5-21-1-2-3-1105",
                ),
                AccountDeletedActionBundle,
            ),
            (
                PasswordResetRequest(
                    actor=test_user,
                    system=test_system,
                    time=timestamp,
                    target_username="svc_sqlreader",
                    target_sid="S-1-5-21-1-2-3-1105",
                ),
                PasswordResetActionBundle,
            ),
            (
                PasswordChangeRequest(user=test_user, system=test_system, time=timestamp),
                PasswordChangeActionBundle,
            ),
            (
                AccountChangedRequest(
                    actor=test_user,
                    system=test_system,
                    time=timestamp,
                    target_username="svc_sqlreader",
                    target_sid="S-1-5-21-1-2-3-1105",
                    password_last_set_to_event_time=True,
                ),
                AccountChangedActionBundle,
            ),
            (
                CreateRemoteThreadRequest(
                    user=test_user,
                    system=test_system,
                    time=timestamp,
                    source_pid=4242,
                    source_image=r"C:\Windows\System32\rundll32.exe",
                    target_pid=636,
                    target_image=r"C:\Windows\System32\lsass.exe",
                ),
                CreateRemoteThreadActionBundle,
            ),
            (
                ProcessAccessRequest(
                    user=test_user,
                    system=test_system,
                    time=timestamp,
                    source_pid=4242,
                    source_image=r"C:\Windows\System32\rundll32.exe",
                    target_pid=636,
                    target_image=r"C:\Windows\System32\lsass.exe",
                    granted_access="0x1FFFFF",
                ),
                ProcessAccessActionBundle,
            ),
        ]

        for request, bundle_cls in requests_and_bundles:
            assert bundle_cls(Mock(), request).anchor == bundle_cls(Mock(), request).anchor

    def test_windows_audit_bundles_delegate_to_adapter(self, test_user, test_system):
        """Windows audit bundles should preserve the current generator adapter contract."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        log_cleared = LogClearedRequest(user=test_user, system=test_system, time=timestamp)
        scheduled_task = ScheduledTaskRequest(
            user=test_user,
            system=test_system,
            time=timestamp,
            task_name="Updater",
        )
        group_change = GroupMembershipChangeRequest(
            actor=test_user,
            system=test_system,
            time=timestamp,
            action="add",
            scope="global",
            group_name="Domain Admins",
            group_sid="S-1-5-21-1-2-3-512",
            member_username="svc_sqlreader",
            member_sid="S-1-5-21-1-2-3-1105",
        )
        account_created = AccountCreatedRequest(
            actor=test_user,
            system=test_system,
            time=timestamp,
            target_username="svc_sqlreader",
            target_sid="S-1-5-21-1-2-3-1105",
        )
        account_deleted = AccountDeletedRequest(
            actor=test_user,
            system=test_system,
            time=timestamp,
            target_username="svc_sqlreader",
            target_sid="S-1-5-21-1-2-3-1105",
        )
        password_reset = PasswordResetRequest(
            actor=test_user,
            system=test_system,
            time=timestamp,
            target_username="svc_sqlreader",
            target_sid="S-1-5-21-1-2-3-1105",
        )
        password_change = PasswordChangeRequest(
            user=test_user,
            system=test_system,
            time=timestamp,
        )
        account_changed = AccountChangedRequest(
            actor=test_user,
            system=test_system,
            time=timestamp,
            target_username="svc_sqlreader",
            target_sid="S-1-5-21-1-2-3-1105",
        )
        remote_thread = CreateRemoteThreadRequest(
            user=test_user,
            system=test_system,
            time=timestamp,
            source_pid=4242,
            source_image=r"C:\Windows\System32\rundll32.exe",
            target_pid=636,
            target_image=r"C:\Windows\System32\lsass.exe",
        )
        process_access = ProcessAccessRequest(
            user=test_user,
            system=test_system,
            time=timestamp,
            source_pid=4242,
            source_image=r"C:\Windows\System32\rundll32.exe",
            target_pid=636,
            target_image=r"C:\Windows\System32\lsass.exe",
        )
        executor = Mock()
        executor._execute_create_remote_thread_bundle.return_value = True
        executor._execute_process_access_bundle.return_value = True

        LogClearedActionBundle(executor, log_cleared).execute()
        ScheduledTaskActionBundle(executor, scheduled_task).execute()
        GroupMembershipChangeActionBundle(executor, group_change).execute()
        AccountCreatedActionBundle(executor, account_created).execute()
        AccountDeletedActionBundle(executor, account_deleted).execute()
        PasswordResetActionBundle(executor, password_reset).execute()
        PasswordChangeActionBundle(executor, password_change).execute()
        AccountChangedActionBundle(executor, account_changed).execute()
        assert CreateRemoteThreadActionBundle(executor, remote_thread).execute() is True
        assert ProcessAccessActionBundle(executor, process_access).execute() is True

        executor._execute_log_cleared_bundle.assert_called_once_with(log_cleared)
        executor._execute_scheduled_task_bundle.assert_called_once_with(scheduled_task)
        executor._execute_group_membership_change_bundle.assert_called_once_with(group_change)
        executor._execute_account_created_bundle.assert_called_once_with(account_created)
        executor._execute_account_deleted_bundle.assert_called_once_with(account_deleted)
        executor._execute_password_reset_bundle.assert_called_once_with(password_reset)
        executor._execute_password_change_bundle.assert_called_once_with(password_change)
        executor._execute_account_changed_bundle.assert_called_once_with(account_changed)
        executor._execute_create_remote_thread_bundle.assert_called_once_with(remote_thread)
        executor._execute_process_access_bundle.assert_called_once_with(process_access)

    def test_generate_logon_reuses_active_workstation_session_over_long_window(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Repeated local workstation sign-ins should reuse the durable session."""
        first_time = datetime(2024, 1, 15, 9, 0, 0, tzinfo=UTC)
        later_time = first_time + timedelta(minutes=45)
        state_manager.set_current_time(first_time)

        logon_id = activity_gen.generate_logon(test_user, test_system, first_time, logon_type=2)
        mock_emitters["windows_event_security"].reset_mock()

        reused_logon_id = activity_gen.generate_logon(
            test_user,
            test_system,
            later_time,
            logon_type=2,
        )

        sessions = state_manager.get_sessions_for_user(test_user.username)
        assert reused_logon_id == logon_id
        assert [session.logon_id for session in sessions] == [logon_id]
        assert sessions[0].last_activity_time == later_time
        emitted_types = [
            call.args[0].event_type
            for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        assert "logon" not in emitted_types

    def test_generate_logon_reuses_session_with_future_rendered_logoff(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Out-of-order future logoff rendering must not create overlapping Type 2 sessions."""
        first_time = datetime(2024, 1, 15, 13, 1, 0, tzinfo=UTC)
        second_time = datetime(2024, 1, 15, 13, 8, 0, tzinfo=UTC)
        logoff_time = datetime(2024, 1, 15, 15, 51, 0, tzinfo=UTC)

        logon_id = activity_gen.generate_logon(test_user, test_system, first_time, logon_type=2)
        activity_gen.generate_logoff(test_user, test_system, logoff_time, logon_id, logon_type=2)
        assert state_manager.get_sessions_for_user(test_user.username) == []
        assert [
            session.logon_id
            for session in state_manager.get_sessions_for_user_at(test_user.username, second_time)
        ] == [logon_id]

        mock_emitters["windows_event_security"].reset_mock()
        reused_logon_id = activity_gen.generate_logon(
            test_user,
            test_system,
            second_time,
            logon_type=2,
        )

        assert reused_logon_id == logon_id
        emitted_types = [
            call.args[0].event_type
            for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        assert "logon" not in emitted_types

    def test_generate_logon_reuses_active_linux_local_session_with_syslog_companion(
        self, state_manager, test_user
    ):
        """Repeated local Linux activity should reuse one login with logind evidence."""
        syslog_emitter = Mock()
        syslog_emitter.can_handle.side_effect = lambda event: event.syslog is not None
        ecar_emitter = Mock()
        ecar_emitter.can_handle.side_effect = lambda event: event.event_type == "logon"
        emitters = {"syslog": syslog_emitter, "ecar": ecar_emitter}
        dispatcher = EventDispatcher(state_manager=state_manager, emitters=emitters)
        activity_gen = ActivityGenerator(state_manager, emitters, dispatcher=dispatcher)
        linux_system = System(
            hostname="WS-LINUX-01",
            ip="10.0.0.41",
            os="Ubuntu 22.04",
            type="workstation",
            assigned_user=test_user.username,
        )
        first_time = datetime(2024, 1, 15, 9, 0, 0, tzinfo=UTC)
        later_time = first_time + timedelta(minutes=35)

        logon_id = activity_gen.generate_logon(test_user, linux_system, first_time, logon_type=2)
        reused_logon_id = activity_gen.generate_logon(
            test_user,
            linux_system,
            later_time,
            logon_type=2,
        )

        sessions = state_manager.get_sessions_for_user(test_user.username)
        emitted_logons = [
            call.args[0]
            for call in ecar_emitter.emit.call_args_list
            if call.args[0].event_type == "logon"
        ]
        syslog_messages = [
            call.args[0].syslog.message for call in syslog_emitter.emit.call_args_list
        ]
        assert reused_logon_id == logon_id
        assert [session.logon_id for session in sessions] == [logon_id]
        assert sessions[0].last_activity_time == later_time
        assert len(emitted_logons) == 1
        assert emitted_logons[0].auth.session_id == sessions[0].session_id
        assert sessions[0].session_id > 1
        assert any("New session" in msg and test_user.username in msg for msg in syslog_messages)
        logind_events = [
            call.args[0]
            for call in syslog_emitter.emit.call_args_list
            if call.args[0].syslog.message.startswith("New session")
        ]
        assert logind_events
        assert logind_events[0].auth is not None
        assert logind_events[0].auth.logon_id == logon_id
        assert logind_events[0].auth.session_id == sessions[0].session_id

    def test_linux_local_session_emits_one_login_and_shares_login_process_pid(
        self, state_manager, test_user
    ):
        """One local session owns one LOGIN occurrence and one PAM/eCAR login PID."""
        syslog_emitter = Mock()
        syslog_emitter.can_handle.side_effect = lambda event: event.syslog is not None
        ecar_emitter = Mock()
        ecar_emitter.can_handle.side_effect = lambda event: (
            event.event_type
            in {
                "logon",
                "process_create",
            }
        )
        emitters = {"syslog": syslog_emitter, "ecar": ecar_emitter}
        dispatcher = EventDispatcher(state_manager=state_manager, emitters=emitters)
        activity_gen = ActivityGenerator(state_manager, emitters, dispatcher=dispatcher)
        linux_server = System(
            hostname="APP-LINUX-01",
            ip="10.0.0.42",
            os="Ubuntu 22.04",
            type="server",
        )
        logon_time = datetime(2024, 1, 15, 9, 0, 0, tzinfo=UTC)
        logon_id = "0x12345"
        state_manager.set_current_time(logon_time - timedelta(hours=1))
        systemd_pid = state_manager.create_process(
            linux_server.hostname,
            0,
            "/usr/lib/systemd/systemd",
            "/usr/lib/systemd/systemd --system",
            "root",
            "System",
            logon_id="0x3e7",
        )
        agetty_pid = state_manager.create_process(
            linux_server.hostname,
            systemd_pid,
            "/sbin/agetty",
            "/sbin/agetty --noclear tty1 linux",
            "root",
            "System",
            logon_id="0x3e7",
        )
        activity_gen._system_pids = {
            linux_server.hostname: {
                "systemd": systemd_pid,
                "agetty1": agetty_pid,
            }
        }

        first_id = activity_gen.generate_logon(
            test_user,
            linux_server,
            logon_time,
            logon_type=2,
            logon_id=logon_id,
            lifecycle_group_id="first-consumer",
        )
        second_id = activity_gen.generate_logon(
            test_user,
            linux_server,
            logon_time,
            logon_type=2,
            logon_id=logon_id,
            lifecycle_group_id="sibling-consumer",
        )
        shell_pid = activity_gen.ensure_linux_session_shell(
            user=test_user,
            target_system=linux_server,
            logon_id=logon_id,
            logon_time=logon_time,
            activity_time=logon_time + timedelta(minutes=10),
        )

        events = [call.args[0] for call in ecar_emitter.emit.call_args_list]
        login_events = [event for event in events if event.event_type == "logon"]
        process_events = [
            event
            for event in events
            if event.event_type == "process_create" and event.process.image == "/bin/login"
        ]
        pam_event = next(
            call.args[0]
            for call in syslog_emitter.emit.call_args_list
            if "pam_unix(login:session): session opened" in call.args[0].syslog.message
        )

        assert first_id == second_id == logon_id
        assert shell_pid is not None
        assert len(login_events) == 1
        assert len(process_events) == 1
        assert pam_event.syslog.pid == process_events[0].process.pid
        assert process_events[0].process.username == "root"
        assert process_events[0].process.logon_id == "0x3e7"
        assert process_events[0].process.parent_pid == agetty_pid
        assert pam_event.timestamp - process_events[0].timestamp >= timedelta(milliseconds=2500)
        source_create_time = activity_gen.process_source_create_time(
            linux_server.hostname,
            process_events[0].process.pid,
        )
        assert source_create_time is not None
        assert pam_event.timestamp >= source_create_time + (
            dispatcher.observation_policy.maximum_delay_difference("ecar", "syslog")
        )
        login_process = state_manager.get_process(
            linux_server.hostname,
            process_events[0].process.pid,
        )
        shell_process = state_manager.get_process(linux_server.hostname, shell_pid)
        assert login_process is not None
        assert shell_process is not None
        assert shell_process.parent_pid == login_process.pid

    def test_linux_sudo_bootstrap_before_window_is_registered_without_login_event(
        self, state_manager, test_user
    ):
        """Carried-in sudo sessions should be state, not boundary LOGIN initiators."""
        ecar_emitter = Mock()
        ecar_emitter.can_handle.return_value = True
        emitters = {"ecar": ecar_emitter}
        dispatcher = EventDispatcher(state_manager=state_manager, emitters=emitters)
        activity_gen = ActivityGenerator(state_manager, emitters, dispatcher=dispatcher)
        scenario_start = datetime(2024, 1, 15, 9, 0, 0, tzinfo=UTC)
        activity_gen._scenario_start_time = scenario_start
        activity_gen._scenario_end_time = scenario_start + timedelta(hours=6)
        linux_server = System(
            hostname="APP-LINUX-01",
            ip="10.0.0.42",
            os="Ubuntu 22.04",
            type="server",
        )

        sudo_pid, child_pid, _, _ = activity_gen.generate_linux_sudo_processes(
            system=linux_server,
            sudo_time=scenario_start + timedelta(seconds=30),
            child_time=scenario_start + timedelta(seconds=30, milliseconds=200),
            sudo_user=test_user.username,
            tty="pts/1",
            command="/usr/bin/id",
            reserve_until=scenario_start + timedelta(seconds=32),
            lifecycle_group_id="sudo-test",
        )

        sessions = state_manager.get_sessions_for_user(test_user.username)
        emitted_types = [call.args[0].event_type for call in ecar_emitter.emit.call_args_list]
        assert sudo_pid > 0
        assert child_pid is not None
        assert len(sessions) == 1
        assert sessions[0].start_time < scenario_start
        assert sessions[0].session_id > 0
        assert "logon" not in emitted_types

    def test_linux_sudo_bootstrap_allocates_fresh_identity_after_completed_session(
        self, state_manager, test_user
    ):
        """A reused TTY must not resurrect the prior completed session's LogonID."""
        ecar_emitter = Mock()
        ecar_emitter.can_handle.return_value = True
        emitters = {"ecar": ecar_emitter}
        dispatcher = EventDispatcher(state_manager=state_manager, emitters=emitters)
        activity_gen = ActivityGenerator(state_manager, emitters, dispatcher=dispatcher)
        scenario_start = datetime(2024, 1, 15, 9, 0, 0, tzinfo=UTC)
        activity_gen._scenario_start_time = scenario_start
        activity_gen._scenario_end_time = scenario_start + timedelta(hours=6)
        linux_server = System(
            hostname="APP-LINUX-01",
            ip="10.0.0.42",
            os="Ubuntu 22.04",
            type="server",
        )

        activity_gen.generate_linux_sudo_processes(
            system=linux_server,
            sudo_time=scenario_start + timedelta(seconds=30),
            child_time=scenario_start + timedelta(seconds=30, milliseconds=200),
            sudo_user=test_user.username,
            tty="pts/1",
            command="/usr/bin/id",
            reserve_until=scenario_start + timedelta(seconds=32),
            lifecycle_group_id="sudo-first",
        )
        first = state_manager.get_sessions_for_user(test_user.username)[0]
        assert state_manager.end_session(first.logon_id, scenario_start + timedelta(minutes=1))

        activity_gen.generate_linux_sudo_processes(
            system=linux_server,
            sudo_time=scenario_start + timedelta(minutes=5),
            child_time=scenario_start + timedelta(minutes=5, milliseconds=200),
            sudo_user=test_user.username,
            tty="pts/1",
            command="/usr/bin/hostname",
            reserve_until=scenario_start + timedelta(minutes=5, seconds=2),
            lifecycle_group_id="sudo-second",
        )
        second = state_manager.get_sessions_for_user(test_user.username)[0]

        assert second.logon_id != first.logon_id
        assert second.ecar_object_id != first.ecar_object_id
        assert second.session_id != first.session_id

    def test_linux_sudo_reuses_eligible_live_session_across_ttys(self, state_manager, test_user):
        """Sudo terminal changes should not create duplicate local login sessions."""
        ecar_emitter = Mock()
        ecar_emitter.can_handle.return_value = True
        emitters = {"ecar": ecar_emitter}
        dispatcher = EventDispatcher(state_manager=state_manager, emitters=emitters)
        activity_gen = ActivityGenerator(state_manager, emitters, dispatcher=dispatcher)
        activity_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        linux_server = System(
            hostname="APP-LINUX-01",
            ip="10.0.0.42",
            os="Ubuntu 22.04",
            type="server",
        )
        logon_id = state_manager.create_session(
            username=test_user.username,
            system=linux_server.hostname,
            logon_type=2,
            source_ip="-",
            start_time=activity_time - timedelta(minutes=10),
            session_kind="interactive",
        )

        sudo_pid, _child_pid, _, _ = activity_gen.generate_linux_sudo_processes(
            system=linux_server,
            sudo_time=activity_time,
            child_time=activity_time + timedelta(milliseconds=200),
            sudo_user=test_user.username,
            tty="pts/4",
            command="/usr/bin/id",
            reserve_until=activity_time + timedelta(seconds=2),
            lifecycle_group_id="sudo-live-session-test",
        )

        sessions = state_manager.get_sessions_for_user(test_user.username)
        assert sudo_pid > 0
        assert [session.logon_id for session in sessions] == [logon_id]
        assert not any(
            call.args[0].event_type == "logon" for call in ecar_emitter.emit.call_args_list
        )

    def test_linux_local_logon_with_stale_ssh_kind_gets_logind_companion(
        self, state_manager, test_user
    ):
        """Local-looking Linux sessions should get logind evidence before eCAR rendering."""
        syslog_emitter = Mock()
        syslog_emitter.can_handle.side_effect = lambda event: event.syslog is not None
        ecar_emitter = Mock()
        ecar_emitter.can_handle.side_effect = lambda event: event.event_type == "logon"
        emitters = {"syslog": syslog_emitter, "ecar": ecar_emitter}
        dispatcher = EventDispatcher(state_manager=state_manager, emitters=emitters)
        activity_gen = ActivityGenerator(state_manager, emitters, dispatcher=dispatcher)
        linux_system = System(
            hostname="DB-PROD-01",
            ip="10.0.0.20",
            os="Ubuntu 22.04",
            type="server",
        )
        logon_time = datetime(2024, 1, 15, 12, 26, 0, tzinfo=UTC)
        logon_id = state_manager.create_session(
            username=test_user.username,
            system=linux_system.hostname,
            logon_type=2,
            source_ip="-",
            session_kind="ssh",
            start_time=logon_time,
        )

        rendered_logon_id = activity_gen.generate_logon(
            test_user,
            linux_system,
            logon_time,
            logon_type=2,
            source_ip="-",
            logon_id=logon_id,
        )

        session = state_manager.get_session(logon_id)
        emitted_logons = [
            call.args[0]
            for call in ecar_emitter.emit.call_args_list
            if call.args[0].event_type == "logon"
        ]
        logind_events = [
            call.args[0]
            for call in syslog_emitter.emit.call_args_list
            if call.args[0].syslog.message.startswith("New session")
        ]
        assert rendered_logon_id == logon_id
        assert session is not None
        assert session.session_id > 0
        assert emitted_logons
        assert emitted_logons[0].auth.session_id == session.session_id
        assert logind_events
        assert logind_events[0].auth.session_id == session.session_id

    def test_linux_self_sourced_type3_logon_is_local_logind_session(self, state_manager, test_user):
        """Linux self-sourced Type 3 compatibility calls should render as local logind sessions."""
        syslog_emitter = Mock()
        syslog_emitter.can_handle.side_effect = lambda event: event.syslog is not None
        ecar_emitter = Mock()
        ecar_emitter.can_handle.side_effect = lambda event: event.event_type == "logon"
        emitters = {"syslog": syslog_emitter, "ecar": ecar_emitter}
        dispatcher = EventDispatcher(state_manager=state_manager, emitters=emitters)
        activity_gen = ActivityGenerator(state_manager, emitters, dispatcher=dispatcher)
        linux_system = System(
            hostname="DB-PROD-01",
            ip="10.0.0.20",
            os="CentOS 8",
            type="server",
        )
        logon_time = datetime(2024, 1, 15, 14, 30, 0, tzinfo=UTC)

        logon_id = activity_gen.generate_logon(
            test_user,
            linux_system,
            logon_time,
            logon_type=3,
            source_ip=linux_system.ip,
        )

        session = state_manager.get_session(logon_id)
        emitted_logons = [
            call.args[0]
            for call in ecar_emitter.emit.call_args_list
            if call.args[0].event_type == "logon"
        ]
        logind_events = [
            call.args[0]
            for call in syslog_emitter.emit.call_args_list
            if call.args[0].syslog.message.startswith("New session")
        ]
        assert session is not None
        assert session.logon_type == 2
        assert session.source_ip == "-"
        assert session.session_id > 0
        assert emitted_logons
        assert emitted_logons[0].auth.logon_type == 2
        assert emitted_logons[0].auth.source_ip == "-"
        assert emitted_logons[0].auth.session_id == session.session_id
        assert logind_events
        assert logind_events[0].auth.logon_id == logon_id
        assert logind_events[0].auth.session_id == session.session_id

    def test_overlapping_linux_local_sessions_keep_distinct_ecar_session_ids(
        self, state_manager, test_user
    ):
        """Linux eCAR login/logout rows should preserve source-native logind session IDs."""
        syslog_emitter = Mock()
        syslog_emitter.can_handle.side_effect = lambda event: event.syslog is not None
        ecar_emitter = Mock()
        ecar_emitter.can_handle.side_effect = lambda event: (
            event.event_type
            in {
                "logon",
                "logoff",
            }
        )
        emitters = {"syslog": syslog_emitter, "ecar": ecar_emitter}
        dispatcher = EventDispatcher(state_manager=state_manager, emitters=emitters)
        activity_gen = ActivityGenerator(state_manager, emitters, dispatcher=dispatcher)
        linux_system = System(
            hostname="WS-LINUX-01",
            ip="10.0.0.41",
            os="Ubuntu 22.04",
            type="workstation",
            assigned_user=test_user.username,
        )
        other_user = User(
            username="other.user",
            full_name="Other User",
            email="other.user@example.com",
            enabled=True,
        )
        first_time = datetime(2024, 1, 15, 9, 0, 0, tzinfo=UTC)
        second_time = first_time + timedelta(minutes=8)
        first_logoff_time = first_time + timedelta(minutes=20)

        first_logon_id = activity_gen.generate_logon(
            test_user,
            linux_system,
            first_time,
            logon_type=2,
        )
        second_logon_id = activity_gen.generate_logon(
            other_user,
            linux_system,
            second_time,
            logon_type=2,
        )
        activity_gen.generate_logoff(
            test_user,
            linux_system,
            first_logoff_time,
            first_logon_id,
            logon_type=2,
        )

        ecar_events = [call.args[0] for call in ecar_emitter.emit.call_args_list]
        first_login = next(
            event
            for event in ecar_events
            if event.event_type == "logon" and event.auth.logon_id == first_logon_id
        )
        second_login = next(
            event
            for event in ecar_events
            if event.event_type == "logon" and event.auth.logon_id == second_logon_id
        )
        first_logout = next(
            event
            for event in ecar_events
            if event.event_type == "logoff" and event.auth.logon_id == first_logon_id
        )

        assert first_login.auth.session_id > 1
        assert second_login.auth.session_id > 1
        assert first_login.auth.session_id != second_login.auth.session_id
        assert first_logout.auth.session_id == first_login.auth.session_id

    def test_interactive_logons_get_distinct_userinit_parents(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
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

        other_user = User(
            username="otheruser",
            full_name="Other User",
            email="other@example.com",
            enabled=True,
        )

        first_logon = activity_gen.generate_logon(test_user, test_system, timestamp, logon_type=2)
        second_logon = activity_gen.generate_logon(
            other_user,
            test_system,
            timestamp + timedelta(minutes=30),
            logon_type=2,
        )

        sessions = {}
        for username in ("testuser", "otheruser"):
            sessions.update(
                {
                    session.logon_id: session
                    for session in state_manager.get_sessions_for_user(username)
                }
            )
        first_explorer = state_manager.get_process(
            test_system.hostname, sessions[first_logon].explorer_pid
        )
        second_explorer = state_manager.get_process(
            test_system.hostname, sessions[second_logon].explorer_pid
        )
        assert first_explorer.parent_pid != second_explorer.parent_pid
        logon_events = [
            call.args[0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call.args[0].event_type == "logon"
        ]
        caller_pids = {
            event.auth.logon_id: event.auth.process_pid
            for event in logon_events
            if event.auth is not None
        }
        assert caller_pids[first_logon] == sessions[first_logon].session_winlogon_pid
        assert caller_pids[second_logon] == sessions[second_logon].session_winlogon_pid
        assert caller_pids[first_logon] != caller_pids[second_logon]

    def test_windows_session_shell_has_visible_lifecycle_and_varied_teardown(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Session shell helpers should not appear as fixed-cadence termination-only rows."""
        logon_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(logon_time - timedelta(minutes=1))
        smss_pid = state_manager.create_process(
            test_system.hostname,
            4,
            r"C:\Windows\System32\smss.exe",
            r"C:\Windows\System32\smss.exe",
            "SYSTEM",
            "System",
        )
        activity_gen._system_pids = {test_system.hostname: {"smss": smss_pid}}

        logon_id = activity_gen.generate_logon(
            test_user,
            test_system,
            logon_time,
            logon_type=2,
        )
        logoff_time = logon_time + timedelta(hours=1)
        activity_gen.generate_logoff(
            test_user,
            test_system,
            logoff_time,
            logon_id,
            logon_type=2,
        )

        events = [
            call.args[0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        shell_names = {"winlogon.exe", "userinit.exe", "explorer.exe"}
        creates = {
            event.process.image.rsplit("\\", 1)[-1].lower(): event
            for event in events
            if event.event_type == "process_create"
            and event.process is not None
            and event.process.image.rsplit("\\", 1)[-1].lower() in shell_names
        }
        terminations = [
            event
            for event in events
            if event.event_type == "process_terminate"
            and event.process is not None
            and event.process.image.rsplit("\\", 1)[-1].lower() in shell_names
        ]

        assert set(creates) == shell_names
        by_name = {event.process.image.rsplit("\\", 1)[-1].lower(): event for event in terminations}
        assert set(by_name) == shell_names
        assert creates["explorer.exe"].timestamp < by_name["userinit.exe"].timestamp
        assert by_name["userinit.exe"].timestamp < logoff_time - timedelta(minutes=50)
        assert creates["winlogon.exe"].auth is not None
        assert creates["winlogon.exe"].auth.username == "SYSTEM"
        assert creates["winlogon.exe"].auth.logon_id == "0x3e7"
        assert by_name["winlogon.exe"].auth is not None
        assert by_name["winlogon.exe"].auth.username == "SYSTEM"
        assert by_name["winlogon.exe"].auth.logon_id == "0x3e7"
        assert by_name["winlogon.exe"].auth.session_id == creates["winlogon.exe"].auth.session_id
        assert by_name["winlogon.exe"].process.logon_id == "0x3e7"
        assert by_name["explorer.exe"].auth is not None
        assert by_name["explorer.exe"].auth.logon_id == logon_id
        logout_gap = abs(by_name["winlogon.exe"].timestamp - by_name["explorer.exe"].timestamp)
        assert logout_gap != timedelta(milliseconds=50)

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

    def test_repeated_logon_render_does_not_duplicate_session_shell(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """One active Logon ID must own only one Windows shell bootstrap chain."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp - timedelta(minutes=1))
        smss_pid = state_manager.create_process(
            test_system.hostname,
            4,
            r"C:\Windows\System32\smss.exe",
            r"C:\Windows\System32\smss.exe",
            "SYSTEM",
            "System",
        )
        activity_gen._system_pids = {test_system.hostname: {"smss": smss_pid}}

        logon_id = activity_gen.generate_logon(
            test_user,
            test_system,
            timestamp,
            logon_type=10,
            source_ip="192.0.2.25",
            emit_network_evidence=False,
        )
        session = state_manager.get_session(logon_id)
        assert session is not None
        first_explorer_pid = session.explorer_pid
        assert first_explorer_pid is not None
        state_manager.end_process(
            test_system.hostname,
            first_explorer_pid,
            end_time=timestamp + timedelta(hours=1),
        )
        assert session.explorer_pid is None
        assert (
            activity_gen._ensure_session_explorer_pid(
                test_system,
                test_user,
                timestamp + timedelta(seconds=1),
                logon_id,
            )
            is None
        )

        activity_gen.generate_logon(
            test_user,
            test_system,
            timestamp + timedelta(milliseconds=12),
            logon_type=10,
            source_ip="192.0.2.25",
            emit_network_evidence=False,
            logon_id=logon_id,
        )

        session = state_manager.get_session(logon_id)
        assert session is not None
        assert session.explorer_pid is None
        assert session.windows_shell_bootstrapped is True
        shell_creates = [
            call.args[0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call.args[0].event_type == "process_create"
            and call.args[0].process is not None
            and call.args[0].process.image.rsplit("\\", 1)[-1].lower()
            in {"winlogon.exe", "userinit.exe", "explorer.exe"}
        ]
        assert len(shell_creates) == 3

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

    def test_help_desk_persona_does_not_imply_special_privileges(self, activity_gen, test_system):
        """Delegated support users need explicit admin groups for 4672 privileges."""
        user = User(
            username="help.desk",
            full_name="Help Desk",
            email="help.desk@example.com",
            persona="help_desk",
            groups=["it-support"],
            enabled=True,
        )

        assert activity_gen._special_privilege_profile_name(user, 2, test_system.hostname) == (
            "regular_user"
        )
        assert activity_gen._should_elevate(user, logon_type=2, hostname=test_system.hostname) is (
            False
        )

    def test_generate_logon_interactive_uses_no_source_ip(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Interactive logon (type 2) should not render a remote source IP."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_logon(test_user, test_system, timestamp, logon_type=2)

        # OccurrenceBuilder dispatched to Windows emitter
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
        """Direct Type 10 calls should delegate transport and auth to the RDP bundle."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        mock_emitters["ecar"] = Mock()
        activity_gen.dispatcher.emitters = mock_emitters
        state_manager.set_current_time(timestamp - timedelta(minutes=1))
        smss_pid = state_manager.create_process(
            test_system.hostname,
            4,
            r"C:\Windows\System32\smss.exe",
            r"C:\Windows\System32\smss.exe",
            "SYSTEM",
            "System",
            logon_id="0x3e7",
        )
        activity_gen._system_pids = {test_system.hostname: {"smss": smss_pid}}
        state_manager.set_current_time(timestamp)

        logon_id = activity_gen.generate_logon(
            test_user,
            test_system,
            timestamp,
            logon_type=10,
            source_ip="10.0.99.50",
            source_port=49306,
        )

        event = next(
            call.args[0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call.args[0].event_type == "logon" and call.args[0].auth.logon_type == 10
        )
        rdp_connections = [
            call.args[0]
            for call in mock_emitters["zeek_conn"].emit.call_args_list
            if call.args[0].event_type == "connection" and call.args[0].network.dst_port == 3389
        ]
        assert len(rdp_connections) == 1
        network_event = rdp_connections[0]
        assert event.timestamp > network_event.timestamp
        assert event.auth.source_port == network_event.network.src_port == 49306
        assert event.auth.logon_id == logon_id
        assert event.auth.logon_type == 10
        assert event.auth.logon_process == "User32"
        assert event.auth.auth_package in {"Negotiate", "Kerberos", "NTLM"}
        assert event.auth.auth_package != "CredSSP"
        assert event.lifecycle is not None
        ecar_login_time = activity_gen.dispatcher.source_timing_planner.session_start_source_time(
            "ecar",
            event.lifecycle.group_id,
        )
        session = state_manager.get_session(logon_id)
        assert session is not None
        assert session.source_ready_time == ecar_login_time
        assert session.session_winlogon_pid is not None
        winlogon_pid = session.session_winlogon_pid
        winlogon = state_manager.get_process(test_system.hostname, winlogon_pid)
        assert winlogon is not None
        assert winlogon.username == "SYSTEM"
        assert winlogon.logon_id == "0x3e7"

        activity_gen.generate_logoff(
            test_user,
            test_system,
            timestamp + timedelta(hours=1),
            logon_id,
            logon_type=10,
        )

        winlogon_terminate = next(
            call.args[0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call.args[0].event_type == "process_terminate"
            and call.args[0].process is not None
            and call.args[0].process.pid == winlogon_pid
        )
        assert winlogon_terminate.auth is not None
        assert winlogon_terminate.auth.username == "SYSTEM"
        assert winlogon_terminate.auth.logon_id == "0x3e7"
        assert winlogon_terminate.auth.session_id == session.session_id
        assert winlogon_terminate.process.logon_id == "0x3e7"

    def test_generate_logon_rdp_preserves_explicit_modeled_source(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Compatibility delegation should not replace an explicit storyline source."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        linux_source = System(
            hostname="LT-REDTEAM-01",
            ip="10.0.0.99",
            os="Ubuntu 22.04",
            type="workstation",
        )
        activity_gen._ip_to_system = {
            test_system.ip: test_system,
            linux_source.ip: linux_source,
        }
        state_manager.set_current_time(timestamp)

        activity_gen.generate_logon(
            test_user,
            test_system,
            timestamp,
            logon_type=10,
            source_ip=linux_source.ip,
        )

        network_event = next(
            call.args[0]
            for call in mock_emitters["zeek_conn"].emit.call_args_list
            if call.args[0].event_type == "connection" and call.args[0].network.dst_port == 3389
        )
        logon_event = next(
            call.args[0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call.args[0].event_type == "logon" and call.args[0].auth.logon_type == 10
        )
        assert network_event.network.src_ip == linux_source.ip
        assert logon_event.auth.source_ip == linux_source.ip
        assert logon_event.src_host.hostname == linux_source.hostname

    def test_generate_logon_rdp_without_remote_source_downgrades_to_interactive(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Direct Type 10 compatibility calls should not fabricate self-sourced RDP."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_logon(test_user, test_system, timestamp, logon_type=10)

        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.auth.logon_type == 2
        assert event.auth.source_ip == "-"

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
        assert network_event.network.conn_state == "SF"
        assert network_event.network.duration is not None
        assert network_event.network.orig_bytes > 0
        assert network_event.network.resp_bytes > 0
        assert logon_event.auth.source_port == network_event.network.src_port
        assert logon_event.timestamp > network_event.timestamp
        connection = next(
            conn
            for conn in state_manager.list_open_connections()
            if conn.zeek_uid == network_event.network.zeek_uid
        )
        assert connection.start_time == network_event.timestamp
        assert connection.close_time == network_event.timestamp + timedelta(
            seconds=network_event.network.duration
        )
        assert logon_event.timestamp < connection.close_time

    def test_rdp_session_bundle_anchor_is_stable(self, test_user, test_system):
        """Identical RDP bundle requests should have stable action anchors."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        first = RdpSessionRequest(
            user=test_user,
            target_system=test_system,
            time=timestamp,
            source_ip="10.0.99.50",
        )
        second = RdpSessionRequest(
            user=test_user,
            target_system=test_system,
            time=timestamp,
            source_ip="10.0.99.50",
        )

        assert (
            RdpSessionActionBundle(Mock(), first).anchor
            == RdpSessionActionBundle(Mock(), second).anchor
        )

    def test_rdp_session_bundle_materializes_source_process(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """RDP bundle should own source mstsc materialization before target logon."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        source_process_time = timestamp - timedelta(seconds=3)
        source_system = System(
            hostname="WS-SOURCE-01",
            ip="10.0.0.2",
            os="Windows 10",
            type="workstation",
            assigned_user=test_user.username,
        )
        state_manager.set_current_time(timestamp)
        calls = []

        def source_process_factory(
            *,
            user: User,
            source_system: System,
            target_system: System,
            time: datetime,
        ) -> int:
            calls.append((user, source_system, target_system, time))
            state_manager.set_current_time(time - timedelta(seconds=10))
            logon_id = state_manager.create_session(
                username=user.username,
                system=source_system.hostname,
                logon_type=2,
                source_ip="-",
                start_time=time - timedelta(seconds=10),
                session_kind="interactive",
            )
            return activity_gen.generate_process(
                user=user,
                system=source_system,
                time=time,
                logon_id=logon_id,
                process_name=r"C:\Windows\System32\mstsc.exe",
                command_line=f"mstsc.exe /v:{target_system.hostname}",
                parent_pid=4,
            )

        bundle = RdpSessionActionBundle(
            activity_gen,
            RdpSessionRequest(
                user=test_user,
                target_system=test_system,
                time=timestamp,
                source_ip=source_system.ip,
                source_system=source_system,
                source_process_time=source_process_time,
            ),
            source_process_factory=source_process_factory,
        )

        bundle.execute()

        assert calls == [(test_user, source_system, test_system, source_process_time)]
        network_event = next(
            call.args[0]
            for call in mock_emitters["zeek_conn"].emit.call_args_list
            if call.args[0].event_type == "connection" and call.args[0].network.dst_port == 3389
        )
        logon_event = next(
            call.args[0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call.args[0].event_type == "logon" and call.args[0].auth.logon_type == 10
        )
        source_process = next(
            call.args[0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call.args[0].event_type == "process_create"
            and call.args[0].process is not None
            and call.args[0].process.image.endswith("mstsc.exe")
        )
        assert network_event.network.conn_state == "SF"
        assert network_event.network.initiating_pid == source_process.process.pid
        assert logon_event.auth.source_port == network_event.network.src_port
        assert logon_event.auth.subject_username == "SYSTEM"
        assert logon_event.auth.subject_domain == "NT AUTHORITY"
        assert logon_event.timestamp > network_event.timestamp
        network_close_time = network_event.timestamp + timedelta(
            seconds=network_event.network.duration
        )
        running_source_process = state_manager.get_process(
            source_system.hostname,
            source_process.process.pid,
        )
        assert running_source_process is not None
        assert running_source_process.last_activity_time is not None
        assert running_source_process.last_activity_time > network_close_time
        source_session = state_manager.get_session(running_source_process.logon_id)
        assert source_session is not None
        assert logon_event.auth.subject_logon_id == "0x3e7"
        assert logon_event.auth.subject_logon_id != source_session.logon_id
        assert source_session.last_activity_time == running_source_process.last_activity_time

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

    def test_generate_rdp_session_replaces_linux_source_with_windows_client(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """RDP bundles should not model Linux hosts as mstsc-capable Windows clients."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        linux_source = System(
            hostname="SRV-LIN-01",
            ip="10.0.0.20",
            os="Ubuntu Server 22.04",
            type="server",
            assigned_user=test_user.username,
        )
        windows_source = System(
            hostname="WS-SOURCE-01",
            ip="10.0.0.2",
            os="Windows 10",
            type="workstation",
            assigned_user=test_user.username,
        )
        activity_gen._ip_to_system = {
            test_system.ip: test_system,
            linux_source.ip: linux_source,
            windows_source.ip: windows_source,
        }
        state_manager.set_current_time(timestamp)

        activity_gen.generate_rdp_session(
            user=test_user,
            target_system=test_system,
            time=timestamp,
            source_ip=linux_source.ip,
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

        assert network_event.network.src_ip == windows_source.ip
        assert logon_event.auth.source_ip == windows_source.ip
        assert logon_event.src_host.hostname == windows_source.hostname

    def test_direct_rdp_source_factory_materializes_mstsc_process(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Direct Type 10 adapters should route source process ownership through RDP."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        linux_source = System(
            hostname="SRV-LIN-01",
            ip="10.0.0.20",
            os="Ubuntu Server 22.04",
            type="server",
            assigned_user=test_user.username,
        )
        windows_source = System(
            hostname="WS-SOURCE-01",
            ip="10.0.0.2",
            os="Windows 10",
            type="workstation",
            assigned_user=test_user.username,
        )
        activity_gen._ip_to_system = {
            test_system.ip: test_system,
            linux_source.ip: linux_source,
            windows_source.ip: windows_source,
        }
        chosen = activity_gen._resolve_direct_rdp_source_system(
            test_user,
            test_system,
            linux_source.ip,
            random.Random(7),
        )
        assert chosen == windows_source

        factory = activity_gen._direct_rdp_source_process_factory(random.Random(11))
        pid = factory(
            user=test_user,
            source_system=windows_source,
            target_system=test_system,
            time=timestamp,
        )

        process_event = next(
            call.args[0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call.args[0].event_type == "process_create"
            and call.args[0].process is not None
            and call.args[0].process.image.endswith("mstsc.exe")
        )
        assert pid == process_event.process.pid
        assert process_event.src_host.hostname == windows_source.hostname
        assert process_event.process.command_line == f"mstsc.exe /v:{test_system.hostname}"

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

    def test_reserve_ssh_source_port_reuses_recent_explicit_reservation(self, activity_gen):
        """Pre-reserved SSH ports should be idempotent for the owning near-time tuple."""

        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        first = activity_gen.reserve_ssh_source_port(
            "10.0.0.10",
            "10.0.0.20",
            None,
            random.Random(7),
            "linux",
            time=timestamp,
        )
        second = activity_gen.reserve_ssh_source_port(
            "10.0.0.10",
            "10.0.0.20",
            first,
            random.Random(11),
            "linux",
            time=timestamp + timedelta(milliseconds=250),
        )

        assert second == first

    def test_nmap_process_emits_matching_network_scan_evidence(
        self, activity_gen, test_user, state_manager, mock_emitters, monkeypatch
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
        probe_requests = []
        original_generate_connection = activity_gen.generate_connection

        def capture_probe_connection(**kwargs):
            if kwargs.get("process_image") == "/usr/bin/nmap":
                probe_requests.append(dict(kwargs))
            return original_generate_connection(**kwargs)

        monkeypatch.setattr(activity_gen, "generate_connection", capture_probe_connection)

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
        assert probe_requests
        assert {request["dst_ip"] for request in probe_requests} == {target_a.ip, target_b.ip}
        assert {request["dst_port"] for request in probe_requests} >= {22, 80, 443, 445, 3306}
        assert {request.get("service") for request in probe_requests if request.get("service")} >= {
            "ssh",
            "http",
            "ssl",
            "smb",
            "mysql",
        }
        assert all(
            request["suppress_application_side_effects"] is True for request in probe_requests
        )
        assert scan_events
        assert {event.network.dst_ip for event in scan_events} == {target_a.ip, target_b.ip}
        assert {event.network.dst_port for event in scan_events} >= {22, 80, 443, 445}
        assert len({event.network.conn_state for event in scan_events}) > 1
        assert any(event.network.conn_state in {"S0", "REJ"} for event in scan_events)
        assert all(event.protocol.http is None for event in scan_events)
        assert all(event.protocol.ssl is None for event in scan_events)
        assert all(event.protocol.leaf_certificate is None for event in scan_events)
        assert all(event.protocol.ocsp is None for event in scan_events)
        assert all(event.protocol.primary_file_transfer is None for event in scan_events)

    def test_nmap_command_probe_bundle_anchor_is_stable(self, test_user):
        """Nmap command probe bundles should expose deterministic anchors."""
        system = System(
            hostname="WEB-01",
            ip="10.10.3.10",
            os="Ubuntu 22.04",
            type="server",
        )
        request = NmapCommandProbeRequest(
            user=test_user,
            system=system,
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            pid=4242,
            process_name="/usr/bin/nmap",
            command_line="nmap -p 22,80 10.10.2.0/24",
        )

        first = NmapCommandProbeActionBundle(Mock(), request).anchor
        second = NmapCommandProbeActionBundle(Mock(), request).anchor

        assert first == second
        assert first.family == "nmap_command_probe"
        assert first.stable_id.startswith("nmap-command-probe-")

    def test_nmap_command_probe_bundle_delegates_to_adapter(self, test_user):
        """Nmap command probe bundles should delegate expansion to the adapter."""
        system = System(
            hostname="WEB-01",
            ip="10.10.3.10",
            os="Ubuntu 22.04",
            type="server",
        )
        request = NmapCommandProbeRequest(
            user=test_user,
            system=system,
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            pid=4242,
            process_name="/usr/bin/nmap",
            command_line="nmap -p 22,80 10.10.2.0/24",
        )

        executor = Mock()

        NmapCommandProbeActionBundle(executor, request).execute()

        executor._execute_nmap_command_probe_bundle.assert_called_once_with(request)

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

        # OccurrenceBuilder dispatched to Windows emitter
        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.auth.logon_type == 3
        assert event.auth.source_ip == source_ip
        assert event.auth.source_port > 0

    def test_network_logon_with_modeled_source_session_uses_target_local_subject(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Target Type 3 4624 must not copy source-host LUID into Subject fields."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        source_system = System(
            hostname="WS-SOURCE-01",
            ip="10.0.0.50",
            os="Windows 11",
            type="workstation",
            assigned_user=test_user.username,
        )
        activity_gen._ip_to_system = {source_system.ip: source_system, test_system.ip: test_system}
        state_manager.set_current_time(timestamp - timedelta(minutes=5))
        source_logon_id = state_manager.create_session(
            username=test_user.username,
            system=source_system.hostname,
            logon_type=2,
            source_ip="-",
            start_time=timestamp - timedelta(minutes=5),
            session_kind="interactive",
        )
        state_manager.set_current_time(timestamp)

        activity_gen.generate_logon(
            test_user,
            test_system,
            timestamp,
            logon_type=3,
            source_ip=source_system.ip,
        )

        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.auth.logon_type == 3
        assert event.auth.subject_username == "SYSTEM"
        assert event.auth.subject_domain == "NT AUTHORITY"
        assert event.auth.subject_logon_id == "0x3e7"
        assert event.auth.subject_logon_id != source_logon_id

    def test_network_logon_without_modeled_source_keeps_system_subject(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """External Type 3 logons should not invent a user Subject session."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_logon(
            test_user,
            test_system,
            timestamp,
            logon_type=3,
            source_ip="45.83.221.45",
        )

        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.auth.subject_username == "SYSTEM"
        assert event.auth.subject_domain == "NT AUTHORITY"
        assert event.auth.subject_logon_id == "0x3e7"

    def test_generate_logon_network_with_inventory_avoids_missing_human_source(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Unspecified human Type 3 logons should use a real remote host when possible."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        activity_gen._all_system_ips = [test_system.ip, "10.0.0.50"]
        state_manager.set_current_time(timestamp)

        activity_gen.generate_logon(test_user, test_system, timestamp, logon_type=3)

        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.auth.logon_type == 3
        assert event.auth.source_ip == "10.0.0.50"
        assert event.auth.source_port > 0

    def test_generate_logon_network_with_inventory_downgrades_if_human_source_missing(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Unspecified Type 3 logons should not become human self-IP sessions."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        activity_gen._all_system_ips = [test_system.ip]
        state_manager.set_current_time(timestamp)

        activity_gen.generate_logon(test_user, test_system, timestamp, logon_type=3)

        event = mock_emitters["windows_event_security"].emit.call_args[0][0]
        assert event.auth.logon_type == 2
        assert event.auth.source_ip == "-"

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
            remote_auth_destination_port=445,
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
        assert logon_event.remote_auth is not None
        assert logon_event.remote_auth.primary_transport is not None
        assert (
            logon_event.remote_auth.primary_transport.transaction_id
            == network_event.network.stable_id
        )
        assert network_event.lifecycle.parent_group_id == logon_event.remote_auth.stable_id
        session = state_manager.get_session(logon_event.auth.logon_id)
        assert session is not None
        assert session.parent_lifecycle_group_id == logon_event.remote_auth.stable_id

    def test_generic_remote_type3_does_not_invent_smb_transport(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """A Type 3 record needs an owning service before it can claim TCP/445 evidence."""

        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_logon(
            test_user,
            test_system,
            timestamp,
            logon_type=3,
            source_ip="10.0.0.50",
        )

        logon_event = next(
            call[0][0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call[0][0].event_type == "logon"
        )
        network_events = [
            call[0][0]
            for call in mock_emitters["zeek_conn"].emit.call_args_list
            if call[0][0].event_type == "connection"
        ]
        assert logon_event.auth.logon_type == 3
        assert logon_event.auth.source_port > 0
        assert logon_event.remote_auth is None
        assert network_events == []

    def test_remote_logon_reuses_existing_exact_transport_without_duplicate_flow(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Compatibility SMB paths bind the prior transaction into remote-auth timing."""

        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        source_ip = "10.0.0.50"
        source_port = 52595
        state_manager.set_current_time(timestamp)
        activity_gen.generate_connection(
            src_ip=source_ip,
            src_port=source_port,
            dst_ip=test_system.ip,
            dst_port=445,
            proto="tcp",
            service="smb",
            time=timestamp,
            duration=5.0,
            conn_state="SF",
        )
        network_event = next(
            call[0][0]
            for call in mock_emitters["zeek_conn"].emit.call_args_list
            if call[0][0].event_type == "connection"
        )
        transaction_id = network_event.network.stable_id

        activity_gen.generate_logon(
            test_user,
            test_system,
            timestamp,
            logon_type=3,
            source_ip=source_ip,
            source_port=source_port,
            emit_network_evidence=False,
            remote_authentication_transport_id=transaction_id,
        )

        logon_event = next(
            call[0][0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call[0][0].event_type == "logon"
        )
        assert logon_event.remote_auth is not None
        assert logon_event.remote_auth.primary_transport is not None
        assert logon_event.remote_auth.primary_transport.transaction_id == transaction_id
        network_events = [
            call[0][0]
            for call in mock_emitters["zeek_conn"].emit.call_args_list
            if call[0][0].event_type == "connection"
        ]
        assert len(network_events) == 1

    def test_remote_logon_rejects_wrong_explicit_transport_transaction(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """A reused tuple cannot bind authentication without its exact transaction ID."""

        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        source_ip = "10.0.0.50"
        source_port = 52595
        state_manager.set_current_time(timestamp)
        activity_gen.generate_connection(
            src_ip=source_ip,
            src_port=source_port,
            dst_ip=test_system.ip,
            dst_port=445,
            proto="tcp",
            service="smb",
            time=timestamp,
            duration=5.0,
            conn_state="SF",
        )

        activity_gen.generate_logon(
            test_user,
            test_system,
            timestamp,
            logon_type=3,
            source_ip=source_ip,
            source_port=source_port,
            emit_network_evidence=False,
            remote_authentication_transport_id="network-connection-wrong",
        )

        logon_event = next(
            call[0][0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call[0][0].event_type == "logon"
        )
        assert logon_event.remote_auth is not None
        assert logon_event.remote_auth.primary_transport is None

    def test_internal_remote_successful_logon_emits_matching_network_evidence(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Internal Type 3 logon IpPort should be owned by matching network evidence."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        source_ip = "10.0.0.50"
        state_manager.set_current_time(timestamp)

        activity_gen.generate_logon(
            test_user,
            test_system,
            timestamp,
            logon_type=3,
            source_ip=source_ip,
            source_port=52595,
            remote_auth_destination_port=445,
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
        assert logon_event.auth.source_ip == source_ip
        assert logon_event.auth.source_port == network_event.network.src_port == 52595
        assert network_event.network.src_ip == source_ip
        assert network_event.network.dst_ip == test_system.ip

    def test_same_host_network_logon_does_not_claim_unowned_source_port(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Same-host Type 3 logons should not invent a source port without a flow."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_logon(
            test_user,
            test_system,
            timestamp,
            logon_type=3,
            source_ip=test_system.ip,
        )

        logon_event = next(
            call[0][0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call[0][0].event_type == "logon"
        )
        network_events = [
            call[0][0]
            for call in mock_emitters["zeek_conn"].emit.call_args_list
            if call[0][0].event_type == "connection"
        ]
        assert logon_event.auth.source_ip == test_system.ip
        assert logon_event.auth.source_port == 0
        assert network_events == []

    def test_baseline_human_type3_source_avoids_self_ip(self, activity_gen, test_user, test_system):
        """Ambient human Type 3 logons should come from a different host."""
        activity_gen._all_system_ips = [test_system.ip, "10.0.0.50"]

        source_ip = activity_gen._baseline_type3_source_ip(
            test_user,
            test_system,
            random.Random(1),
            is_service_account=False,
        )

        assert source_ip == "10.0.0.50"

    def test_baseline_human_type3_without_remote_source_downgrades_to_interactive(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Human baseline logon noise should not fabricate workstation self-IP Type 3 rows."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        activity_gen._all_system_ips = [test_system.ip]
        reset_thread_rng(0)
        state_manager.set_current_time(timestamp)

        with patch.object(random.Random, "choices", return_value=[3]):
            activity_gen.execute_baseline_activity(test_user, test_system, timestamp, "logon")

        logon_event = next(
            call[0][0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call[0][0].event_type == "logon"
        )
        assert logon_event.auth.logon_type == 2
        assert logon_event.auth.source_ip == "-"

    def test_baseline_service_type3_can_use_self_ip(self, activity_gen, test_system):
        """Self-sourced Type 3 remains available for service-account semantics."""
        service_user = User(
            username="svc_backup",
            full_name="Backup Service",
            email="svc_backup@example.com",
        )
        activity_gen._all_system_ips = [test_system.ip, "10.0.0.50"]

        source_ip = activity_gen._baseline_type3_source_ip(
            service_user,
            test_system,
            random.Random(1),
            is_service_account=True,
        )

        assert source_ip == test_system.ip

    def test_network_auth_package_never_pairs_ntlmssp_with_negotiate(self, activity_gen):
        """Network logons should not emit the reviewer-flagged NtLmSsp/Negotiate tuple."""
        reset_thread_rng(0)

        profiles = [activity_gen._select_auth_package(3) for _ in range(100)]

        assert all(
            not (
                profile["LogonProcessName"] == "NtLmSsp"
                and profile["AuthenticationPackageName"] == "Negotiate"
            )
            for profile in profiles
        )
        for profile in profiles:
            if profile["LogonProcessName"] == "NtLmSsp":
                assert profile["AuthenticationPackageName"] == "NTLM"
                assert profile["LmPackageName"] == "NTLM V2"

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

    def test_repeated_logon_request_claims_one_privilege_companion(
        self, activity_gen, test_system, state_manager, mock_emitters
    ):
        """Identical successful-logon intents claim one 4672 companion."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        admin = User(
            username="admin.lee",
            full_name="Admin Lee",
            email="admin.lee@example.com",
            persona="sysadmin",
            enabled=True,
        )

        with patch.object(activity_gen, "_should_elevate", return_value=True):
            for _ in range(2):
                activity_gen.generate_logon(
                    admin,
                    test_system,
                    timestamp,
                    logon_type=7,
                    logon_id="0x4f2a1b",
                )

        logons = [
            call.args[0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call.args[0].event_type == "logon"
        ]
        assert len(logons) == 2
        assert [event.auth.emit_special_privileges for event in logons] == [True, False]

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
        assert unlock.timestamp >= lock_time + timedelta(seconds=127)
        assert unlock_logon.timestamp < unlock.timestamp
        assert (
            timedelta(milliseconds=80)
            <= (unlock.timestamp - unlock_logon.timestamp)
            <= timedelta(milliseconds=650)
        )
        assert unlock_logon.auth.source_ip == "-"

    def test_locked_workstation_session_does_not_own_foreground_process_activity(
        self, activity_gen, test_user, test_system, state_manager
    ):
        """Foreground user-app activity should not launch while the session is locked."""
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
        locked_time = lock_time + timedelta(minutes=2)

        assert (
            activity_gen._active_user_interactive_windows_session(
                test_user,
                test_system,
                locked_time,
            )
            is None
        )
        assert activity_gen._active_interactive_windows_session(test_system, locked_time) is None
        assert (
            activity_gen._locked_user_interactive_windows_session(
                test_user,
                test_system,
                locked_time,
            )
            is not None
        )

        activity_gen.generate_process = Mock(return_value=4242)
        activity_gen.execute_baseline_activity(
            test_user,
            test_system,
            locked_time,
            "process_user_apps",
        )

        activity_gen.generate_process.assert_not_called()

    def test_workstation_unlock_reauth_precedes_4801_with_varied_gap(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Type 7 re-auth should precede 4801 without a fleet-wide fixed delta."""
        start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        gaps: set[timedelta] = set()

        for index in range(4):
            mock_emitters["windows_event_security"].reset_mock()
            logon_id = f"0x4f2a1{index}"
            lock_time = start + timedelta(hours=index)
            state_manager.register_session(
                logon_id=logon_id,
                username=test_user.username,
                system=test_system.hostname,
                logon_type=2,
                source_ip="-",
                start_time=lock_time - timedelta(minutes=5),
                session_id=10 + index,
            )
            activity_gen.generate_workstation_lock(test_user, test_system, lock_time, logon_id)
            activity_gen.generate_workstation_unlock(
                test_user,
                test_system,
                lock_time + timedelta(minutes=10),
                logon_id,
            )
            events = [
                call[0][0] for call in mock_emitters["windows_event_security"].emit.call_args_list
            ]
            unlock = next(event for event in events if event.event_type == "workstation_unlocked")
            unlock_logon = next(
                event
                for event in events
                if event.event_type == "logon" and event.auth.logon_type == 7
            )

            assert unlock_logon.timestamp < unlock.timestamp
            gaps.add(unlock.timestamp - unlock_logon.timestamp)

        assert len(gaps) > 1
        assert timedelta(milliseconds=50) not in gaps

    def test_workstation_lock_unlock_carry_state_session_id(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """4800, 4801, and Type 7 4624 should carry the canonical session ID."""
        lock_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        logon_id = "0x4f2a1b"
        state_manager.register_session(
            logon_id=logon_id,
            username=test_user.username,
            system=test_system.hostname,
            logon_type=2,
            source_ip="-",
            start_time=lock_time - timedelta(minutes=5),
            session_id=5,
        )

        activity_gen.generate_workstation_lock(test_user, test_system, lock_time, logon_id)
        activity_gen.generate_workstation_unlock(
            test_user,
            test_system,
            lock_time + timedelta(minutes=5),
            logon_id,
        )

        events = [
            call[0][0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        lock = next(event for event in events if event.event_type == "workstation_locked")
        unlock = next(event for event in events if event.event_type == "workstation_unlocked")
        unlock_logon = next(
            event for event in events if event.event_type == "logon" and event.auth.logon_type == 7
        )

        assert lock.auth.session_id == 5
        assert unlock.auth.session_id == 5
        assert unlock_logon.auth.session_id == 5

    def test_workstation_unlock_prefers_locked_session_over_newer_session(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """A 4801 should unlock the locked terminal session, not a newer active one."""
        lock_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        locked_logon_id = "0x2664c4e"
        newer_logon_id = "0x2802b88"
        state_manager.register_session(
            logon_id=locked_logon_id,
            username=test_user.username,
            system=test_system.hostname,
            logon_type=2,
            source_ip="-",
            start_time=lock_time - timedelta(minutes=30),
            session_id=5,
        )
        state_manager.register_session(
            logon_id=newer_logon_id,
            username=test_user.username,
            system=test_system.hostname,
            logon_type=10,
            source_ip="10.0.0.25",
            start_time=lock_time + timedelta(minutes=20),
            session_id=6,
            session_kind="rdp",
        )

        activity_gen.generate_workstation_lock(test_user, test_system, lock_time, locked_logon_id)
        activity_gen.generate_workstation_unlock(
            test_user,
            test_system,
            lock_time + timedelta(minutes=35),
            newer_logon_id,
        )

        events = [
            call[0][0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        unlock = next(event for event in events if event.event_type == "workstation_unlocked")
        unlock_logon = next(
            event for event in events if event.event_type == "logon" and event.auth.logon_type == 7
        )

        assert unlock.auth.logon_id == locked_logon_id
        assert unlock.auth.session_id == 5
        assert unlock_logon.auth.logon_id == locked_logon_id
        assert unlock_logon.auth.session_id == 5

    def test_workstation_lock_ignores_second_locked_session_for_user_host(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """One user/host should not visibly enter a second locked state before unlock."""
        lock_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        first_logon_id = "0x2664c4e"
        second_logon_id = "0x2700ea3"
        state_manager.register_session(
            logon_id=first_logon_id,
            username=test_user.username,
            system=test_system.hostname,
            logon_type=2,
            source_ip="-",
            start_time=lock_time - timedelta(minutes=30),
            session_id=5,
        )
        state_manager.register_session(
            logon_id=second_logon_id,
            username=test_user.username,
            system=test_system.hostname,
            logon_type=10,
            source_ip="10.0.0.25",
            start_time=lock_time + timedelta(minutes=10),
            session_id=6,
            session_kind="rdp",
        )

        activity_gen.generate_workstation_lock(test_user, test_system, lock_time, first_logon_id)
        activity_gen.generate_workstation_lock(
            test_user,
            test_system,
            lock_time + timedelta(minutes=20),
            second_logon_id,
        )

        locks = [
            call[0][0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call[0][0].event_type == "workstation_locked"
        ]

        assert len(locks) == 1
        assert locks[0].auth.logon_id == first_logon_id
        assert locks[0].auth.session_id == 5

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

        first_result = activity_gen.generate_workstation_lock(
            test_user,
            test_system,
            lock_time,
            logon_id,
        )
        second_result = activity_gen.generate_workstation_lock(
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
        assert first_result == WorkstationLockResult(emitted=True)
        assert second_result == WorkstationLockResult(
            emitted=False,
            skipped_reason="workstation_already_locked",
        )
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
        assert event.kerberos.target_username == "alice"
        assert event.kerberos.target_domain == "EXAMPLE.LOCAL"

    def test_machine_account_logon_emits_nearby_dc_kerberos_audit(
        self, activity_gen, state_manager, mock_emitters
    ):
        """Machine Kerberos flows should have matching DC 4768/4769 audit records."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        for emitter in mock_emitters.values():
            emitter.can_handle.return_value = True

        sessions_before = len(state_manager.state.active_sessions)
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
        machine_logon = next(
            event for event in security_events if event.event_type == "machine_logon"
        )
        machine_logoff = next(event for event in security_events if event.event_type == "logoff")
        assert machine_logon.remote_auth is not None
        assert machine_logon.remote_auth.outcome == "success"
        assert machine_logon.remote_auth.primary_transport is not None
        assert machine_logon.remote_auth.primary_transport.role == "target_service"
        assert machine_logon.remote_auth.primary_transport.tuple.dst_port in {389, 445}
        assert machine_logon.identity_plan.object_id == machine_logoff.identity_plan.object_id
        assert machine_logon.lifecycle.group_id == machine_logoff.lifecycle.group_id
        assert machine_logon.lifecycle.phase == "start"
        assert machine_logoff.lifecycle.phase == "closure"
        assert len(state_manager.state.active_sessions) == sessions_before
        identity = state_manager.get_session_identity(machine_logon.auth.logon_id)
        assert identity is not None
        assert identity.object_id == machine_logon.identity_plan.object_id
        service_connection = next(
            call.args[0]
            for call in mock_emitters["zeek_conn"].emit.call_args_list
            if call.args[0].event_type == "connection"
            and call.args[0].network.dst_port in {389, 445}
        )
        assert machine_logon.auth.source_port == service_connection.network.src_port
        assert (
            machine_logon.remote_auth.primary_transport.transaction_id
            == service_connection.network.stable_id
        )
        assert all(
            event.kerberos.source_port != machine_logon.auth.source_port
            for event in kerberos_events
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

    def test_bash_history_preserves_transfer_command_dwell(
        self, activity_gen, state_manager, mock_emitters
    ):
        """Archive and transfer commands should keep the shell busy for realistic dwell."""
        linux = System(hostname="DB-PROD-01", ip="10.0.0.2", os="Ubuntu 22.04", type="server")
        user = User(username="root", full_name="Root", email="root@example.com")
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        bash_emitter = Mock()
        bash_emitter.can_handle.return_value = True
        mock_emitters["bash_history"] = bash_emitter
        activity_gen.dispatcher.emitters = mock_emitters

        activity_gen.generate_bash_command(user, linux, timestamp, "gzip -9 /tmp/rpt.sql")
        activity_gen.generate_bash_command(
            user,
            linux,
            timestamp + timedelta(seconds=1),
            "scp /tmp/rpt.sql.gz root@10.10.2.30:/tmp/rpt.sql.gz",
        )

        events = [call.args[0] for call in bash_emitter.emit.call_args_list]
        assert events[0].timestamp == timestamp
        assert events[1].timestamp >= timestamp + timedelta(seconds=14)

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

    def test_bash_history_suppresses_command_after_ssh_session_close(
        self, activity_gen, state_manager, mock_emitters
    ):
        """Serialized bash history should not leak past a concrete SSH session close."""
        linux = System(hostname="DB-PROD-01", ip="10.0.0.2", os="Ubuntu 22.04", type="server")
        user = User(username="alice", full_name="Alice Example", email="alice@example.com")
        start_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        close_time = start_time + timedelta(minutes=5)
        session = state_manager.register_session(
            logon_id="0xabc100",
            username=user.username,
            system=linux.hostname,
            logon_type=10,
            source_ip="10.0.0.50",
            source_port=48222,
            start_time=start_time,
            session_kind="ssh",
        )
        state_manager.update_session_metadata(
            session.logon_id,
            source_ready_time=start_time + timedelta(seconds=3),
            network_close_time=close_time,
        )
        activity_gen._bash_history_next_time[(linux.hostname, user.username, session.logon_id)] = (
            close_time + timedelta(seconds=10)
        )
        bash_emitter = Mock()
        bash_emitter.can_handle.return_value = True
        mock_emitters["bash_history"] = bash_emitter
        activity_gen.dispatcher.emitters = mock_emitters

        scheduled = activity_gen.generate_bash_command(
            user,
            linux,
            close_time - timedelta(seconds=20),
            "exit",
            emit_process_telemetry=False,
        )

        assert scheduled is None
        assert not bash_emitter.emit.called

    def test_bash_history_moves_serialized_command_to_next_ssh_session(
        self, activity_gen, state_manager, mock_emitters
    ):
        """A delayed command may land in the next visible session, not after the closed one."""
        linux = System(hostname="WEB-EXT-01", ip="10.0.0.3", os="Ubuntu 22.04", type="server")
        user = User(username="alice", full_name="Alice Example", email="alice@example.com")
        first_start = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        first_close = first_start + timedelta(minutes=5)
        second_start = first_start + timedelta(minutes=20)
        second_ready = second_start + timedelta(seconds=4)
        second_close = second_start + timedelta(minutes=25)
        first = state_manager.register_session(
            logon_id="0xabc101",
            username=user.username,
            system=linux.hostname,
            logon_type=10,
            source_ip="10.0.0.50",
            source_port=48222,
            start_time=first_start,
            session_kind="ssh",
        )
        second = state_manager.register_session(
            logon_id="0xabc102",
            username=user.username,
            system=linux.hostname,
            logon_type=10,
            source_ip="10.0.0.51",
            source_port=49222,
            start_time=second_start,
            session_kind="ssh",
        )
        state_manager.update_session_metadata(
            first.logon_id,
            source_ready_time=first_start + timedelta(seconds=3),
            network_close_time=first_close,
        )
        state_manager.update_session_metadata(
            second.logon_id,
            source_ready_time=second_ready,
            network_close_time=second_close,
        )
        activity_gen._bash_history_next_time[(linux.hostname, user.username, first.logon_id)] = (
            first_close + timedelta(seconds=10)
        )
        bash_emitter = Mock()
        bash_emitter.can_handle.return_value = True
        mock_emitters["bash_history"] = bash_emitter
        activity_gen.dispatcher.emitters = mock_emitters

        scheduled = activity_gen.generate_bash_command(
            user,
            linux,
            first_close - timedelta(seconds=20),
            "systemctl reload apache2",
            emit_process_telemetry=False,
        )

        assert scheduled is not None
        assert second_ready <= scheduled < second_close - timedelta(milliseconds=900)
        event = bash_emitter.emit.call_args[0][0]
        assert event.timestamp == scheduled

    def test_bash_history_suppresses_after_recorded_session_close_without_active_session(
        self, activity_gen, mock_emitters
    ):
        """Closed-session memory should block later bash noise until another session exists."""
        linux = System(hostname="PROXY-01", ip="10.0.0.4", os="Ubuntu 22.04", type="server")
        user = User(username="marcus.chen", full_name="Marcus Chen", email="marcus@example.com")
        close_time = datetime(2024, 1, 15, 14, 11, 42, tzinfo=UTC)
        command_time = close_time + timedelta(seconds=30)
        activity_gen._linux_shell_last_session_close[(linux.hostname, user.username)] = close_time
        bash_emitter = Mock()
        bash_emitter.can_handle.return_value = True
        mock_emitters["bash_history"] = bash_emitter
        activity_gen.dispatcher.emitters = mock_emitters

        scheduled = activity_gen.generate_bash_command(
            user,
            linux,
            command_time,
            "systemctl status sshd",
            emit_process_telemetry=False,
        )

        assert scheduled is None
        assert not bash_emitter.emit.called

    def test_bash_history_updates_owning_session_activity(
        self, activity_gen, state_manager, mock_emitters
    ):
        """Session logoff planning should see serialized bash-history activity."""
        linux = System(hostname="PROXY-01", ip="10.0.0.4", os="Ubuntu 22.04", type="server")
        user = User(username="marcus.chen", full_name="Marcus Chen", email="marcus@example.com")
        start_time = datetime(2024, 1, 15, 13, 24, 8, tzinfo=UTC)
        command_time = start_time + timedelta(minutes=47)
        session = state_manager.register_session(
            logon_id="0xabc103",
            username=user.username,
            system=linux.hostname,
            logon_type=10,
            source_ip="10.0.0.50",
            source_port=58031,
            start_time=start_time,
            session_kind="ssh",
        )
        bash_emitter = Mock()
        bash_emitter.can_handle.return_value = True
        mock_emitters["bash_history"] = bash_emitter
        activity_gen.dispatcher.emitters = mock_emitters

        scheduled = activity_gen.generate_bash_command(
            user,
            linux,
            command_time,
            "journalctl -u systemd-resolved --since '30 min ago' --no-pager | tail -20",
            emit_process_telemetry=False,
        )

        assert scheduled is not None
        assert session.last_activity_time is not None
        assert session.last_activity_time >= scheduled

    def test_linux_ssh_client_bash_updates_source_session_activity(
        self, activity_gen, state_manager, test_user, mock_emitters
    ):
        """Source-side ssh commands should keep their local shell session alive."""
        source = System(
            hostname="WEB-EXT-01",
            ip="10.0.0.3",
            os="Ubuntu 22.04",
            type="server",
        )
        target = System(
            hostname="PROXY-01",
            ip="10.0.0.4",
            os="Ubuntu 22.04",
            type="server",
        )
        start_time = datetime(2024, 1, 15, 12, 0, 0, tzinfo=UTC)
        requested_time = start_time + timedelta(minutes=8)
        state_manager.set_current_time(start_time - timedelta(seconds=30))
        systemd_pid = state_manager.create_process(
            source.hostname,
            0,
            "/usr/lib/systemd/systemd",
            "/usr/lib/systemd/systemd --system",
            "root",
            "System",
        )
        session = state_manager.register_session(
            logon_id="0xabc104",
            username=test_user.username,
            system=source.hostname,
            logon_type=2,
            source_ip="-",
            start_time=start_time,
            session_kind="interactive",
        )
        activity_gen._system_pids = {source.hostname: {"systemd": systemd_pid}}
        for emitter in mock_emitters.values():
            emitter.can_handle.return_value = True
        activity_gen.dispatcher.emitters = mock_emitters

        result = activity_gen.ensure_linux_ssh_client_process(
            user=test_user,
            source_system=source,
            target_system=target,
            time=requested_time,
            process_image="/usr/bin/ssh",
            source_port=50222,
        )

        assert result is not None
        assert session.last_activity_time is not None
        assert session.last_activity_time >= requested_time

    def test_linux_shell_command_bundle_anchor_is_stable(self):
        """Identical shell command requests should have stable action anchors."""
        linux = System(hostname="LNX-01", ip="10.0.0.2", os="Ubuntu 22.04", type="workstation")
        user = User(username="alice", full_name="Alice Example", email="alice@example.com")
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        request = LinuxShellCommandRequest(
            user=user,
            system=linux,
            time=timestamp,
            activity_type_or_command="whoami",
            emit_process_telemetry=False,
        )

        assert (
            LinuxShellCommandActionBundle(Mock(), request).anchor
            == LinuxShellCommandActionBundle(Mock(), request).anchor
        )

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
        activity_gen._bash_history_next_time[(linux.hostname, user.username, "")] = scheduled_time
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
            if call.args and isinstance(call.args[0], CanonicalOccurrence)
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

    def test_linux_process_activity_skips_when_shell_schedule_exits_window(
        self, activity_gen, state_manager, mock_emitters, monkeypatch
    ):
        """Serialized Linux shell activity should not emit process rows after collection end."""
        from evidenceforge.generation.activity import application_catalog

        linux = System(hostname="LNX-01", ip="10.0.0.2", os="Ubuntu 22.04", type="workstation")
        user = User(username="alice", full_name="Alice Example", email="alice@example.com")
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        activity_gen._scenario_end_time = timestamp + timedelta(minutes=5)
        activity_gen._bash_history_next_time[(linux.hostname, user.username, "")] = (
            timestamp + timedelta(days=1)
        )
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
            if call.args and isinstance(call.args[0], CanonicalOccurrence)
        ]
        matching = [
            event
            for event in emitted
            if (
                (event.process and event.process.command_line == "git pull origin fix/memory-leak")
                or (event.shell and event.shell.command == "git pull origin fix/memory-leak")
            )
        ]
        assert matching == []

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
            if call.args and isinstance(call.args[0], CanonicalOccurrence)
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
            if call.args and isinstance(call.args[0], CanonicalOccurrence)
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

        # Verify Windows emitter received logoff OccurrenceBuilder via dispatch
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

        # Verify Windows emitter received process_create OccurrenceBuilder
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

    def test_process_execution_bundle_anchor_is_stable(self, test_user, test_system):
        """Process execution requests should expose durable deterministic anchors."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        request = ProcessExecutionRequest(
            user=test_user,
            system=test_system,
            time=timestamp,
            logon_id="0x12345",
            process_name=r"C:\Windows\System32\cmd.exe",
            command_line="cmd.exe /c dir",
        )

        first = ProcessExecutionActionBundle(Mock(), request).anchor
        second = ProcessExecutionActionBundle(Mock(), request).anchor

        assert first == second
        assert first.family == "process_execution"
        assert first.stable_id.startswith("process-execution-")

    def test_process_execution_bundle_delegates_to_adapter(self, test_user, test_system):
        """The bundle should own the entrypoint while preserving the adapter contract."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        request = ProcessExecutionRequest(
            user=test_user,
            system=test_system,
            time=timestamp,
            logon_id="0x12345",
            process_name=r"C:\Windows\System32\cmd.exe",
            command_line="cmd.exe /c dir",
        )
        executor = Mock()
        executor._execute_process_create_bundle.return_value = 4242

        pid = ProcessExecutionActionBundle(executor, request).execute()

        assert pid == 4242
        executor._execute_process_create_bundle.assert_called_once_with(request)

    def test_process_termination_bundle_delegates_to_adapter(self, test_user, test_system):
        """Termination should share the process action-bundle boundary."""
        timestamp = datetime(2024, 1, 15, 10, 5, 0, tzinfo=UTC)
        request = ProcessTerminationRequest(
            user=test_user,
            system=test_system,
            time=timestamp,
            pid=4242,
            process_name=r"C:\Windows\System32\cmd.exe",
            logon_id="0x12345",
        )
        executor = Mock()

        ProcessTerminationActionBundle(executor, request).execute()

        anchor = ProcessTerminationActionBundle(Mock(), request).anchor
        assert anchor.family == "process_termination"
        assert anchor.stable_id.startswith("process-termination-")
        executor._execute_process_termination_bundle.assert_called_once_with(request)

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

    def test_ssh_process_network_effect_passes_command_username(self, activity_gen, test_user):
        """SSH process-network correlation should pass the attempted username."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        workstation = System(
            hostname="WS-LINUX-01",
            ip="10.0.1.10",
            os="Ubuntu 22.04",
            type="workstation",
        )
        app_server = System(
            hostname="APP-INT-01",
            ip="10.0.2.30",
            os="Ubuntu 22.04",
            type="server",
            roles=["app_server"],
            services=["ssh"],
        )
        activity_gen._ip_to_system = {workstation.ip: workstation, app_server.ip: app_server}
        activity_gen._all_system_ips = [workstation.ip, app_server.ip]
        activity_gen.generate_connection = Mock(return_value="")

        activity_gen._emit_process_network_correlation(
            workstation,
            "/usr/bin/ssh",
            f"ssh -l {test_user.username} APP-INT-01",
            timestamp,
            4242,
            random.Random(1),
        )

        assert activity_gen.generate_connection.called
        assert (
            activity_gen.generate_connection.call_args.kwargs["ssh_attempted_username"]
            == test_user.username
        )

    def test_generic_ssh_preauth_syslog_uses_attempted_username(
        self, activity_gen, test_user, state_manager, mock_emitters
    ):
        """Generic destination sshd failure rows should use the source command username."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        workstation = System(
            hostname="WS-LINUX-01",
            ip="10.0.1.10",
            os="Ubuntu 22.04",
            type="workstation",
        )
        app_server = System(
            hostname="APP-INT-01",
            ip="10.0.2.30",
            os="Ubuntu 22.04",
            type="server",
            roles=["app_server"],
            services=["ssh"],
        )
        mock_emitters["syslog"] = Mock()
        activity_gen._ip_to_system = {workstation.ip: workstation, app_server.ip: app_server}
        activity_gen._all_system_ips = [workstation.ip, app_server.ip]
        activity_gen._users_by_username = {test_user.username: test_user}
        activity_gen.sid_registry[test_user.username] = "S-1-5-21-1-2-3-1001"
        state_manager.set_current_time(timestamp)
        pid = state_manager.create_process(
            system=workstation.hostname,
            parent_pid=0,
            image="/usr/bin/ssh",
            command_line=f"ssh {test_user.username}@APP-INT-01",
            username=test_user.username,
            integrity_level="Medium",
            logon_id="0x12345",
        )

        activity_gen.generate_connection(
            src_ip=workstation.ip,
            dst_ip=app_server.ip,
            time=timestamp,
            dst_port=22,
            proto="tcp",
            service="ssh",
            duration=1.2,
            orig_bytes=500,
            resp_bytes=900,
            src_port=52876,
            pid=pid,
            source_system=workstation,
            conn_state="SF",
            ssh_attempted_username=test_user.username,
        )

        messages = [
            call.args[0].syslog.message
            for call in mock_emitters["syslog"].emit.call_args_list
            if call.args[0].syslog is not None and call.args[0].syslog.app_name == "sshd"
        ]
        assert any(
            message.startswith("Connection from 10.0.1.10 port 52876 ") for message in messages
        )
        assert any(f"Failed password for {test_user.username} " in message for message in messages)
        assert any(
            f"Connection closed by authenticating user {test_user.username} " in message
            for message in messages
        )
        assert not any("unknown" in message for message in messages)

    def test_web_to_database_connection_materializes_service_owner(
        self, activity_gen, state_manager, mock_emitters
    ):
        """Known web-to-DB service flows should not render as actorless endpoint telemetry."""
        timestamp = datetime(2024, 3, 18, 14, 20, tzinfo=UTC)
        web_server = System(
            hostname="WEB-EXT-01",
            ip="10.10.3.10",
            os="Ubuntu 22.04",
            type="server",
            roles=["web_server"],
        )
        db_server = System(
            hostname="DB-PROD-01",
            ip="10.10.4.10",
            os="Ubuntu 22.04",
            type="server",
            roles=["database"],
        )
        activity_gen._ip_to_system = {web_server.ip: web_server, db_server.ip: db_server}
        activity_gen._all_system_ips = [web_server.ip, db_server.ip]
        activity_gen._scenario_start_time = timestamp - timedelta(hours=1)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection(
            src_ip=web_server.ip,
            dst_ip=db_server.ip,
            time=timestamp,
            dst_port=3306,
            proto="tcp",
            service="mysql",
            duration=0.45,
            orig_bytes=420,
            resp_bytes=3600,
            conn_state="SF",
            source_system=web_server,
            hostname=db_server.hostname,
        )

        connection_event = next(
            call.args[0]
            for call in mock_emitters["zeek_conn"].emit.call_args_list
            if call.args[0].event_type == "connection" and call.args[0].network.dst_port == 3306
        )
        assert connection_event.network.initiating_pid > 0
        assert connection_event.process is not None
        assert connection_event.process.image == "/usr/sbin/apache2"
        assert connection_event.process.username == "www-data"

    def test_proxy_service_agent_is_reused_across_targets(self, activity_gen, state_manager):
        """One durable service agent owns probes to multiple destinations."""
        timestamp = datetime(2024, 3, 18, 14, 20, tzinfo=UTC)
        dc_system = System(
            hostname="DC-01",
            ip="10.10.2.10",
            os="Windows Server 2022",
            type="domain_controller",
            roles=["domain_controller"],
        )
        activity_gen._ip_to_system = {dc_system.ip: dc_system}
        state_manager.set_current_time(timestamp)
        first_http = HttpContext(
            method="CONNECT",
            host="config.zscaler.net",
            uri="config.zscaler.net:443",
            user_agent="Go-http-client/1.1",
        )
        second_http = HttpContext(
            method="CONNECT",
            host="secure-client-updates.cisco.com",
            uri="secure-client-updates.cisco.com:443",
            user_agent="Go-http-client/1.1",
        )

        first_pid, _ = activity_gen._ensure_high_confidence_connection_owner(
            source_system=dc_system,
            time=timestamp,
            service="http",
            dst_port=8080,
            proto="tcp",
            hostname=first_http.host,
            http=first_http,
        )
        second_pid, _ = activity_gen._ensure_high_confidence_connection_owner(
            source_system=dc_system,
            time=timestamp + timedelta(seconds=3),
            service="http",
            dst_port=8080,
            proto="tcp",
            hostname=second_http.host,
            http=second_http,
        )

        first_proc = state_manager.get_process(dc_system.hostname, first_pid)
        second_proc = state_manager.get_process(dc_system.hostname, second_pid)
        assert first_proc is not None
        assert second_proc is not None
        assert first_pid == second_pid
        assert first_proc.command_line.endswith("--service")
        assert first_proc.command_line == second_proc.command_line
        assert "config.zscaler.net" not in first_proc.command_line
        assert "secure-client-updates.cisco.com" not in second_proc.command_line

    def test_service_connection_owner_command_lines_do_not_leak_planning_notes(self, activity_gen):
        """Rendered endpoint command lines should not contain hidden generation labels."""
        timestamp = datetime(2024, 3, 18, 14, 20, tzinfo=UTC)
        mail_server = System(
            hostname="MAIL-CLIN-01",
            ip="10.10.2.25",
            os="Ubuntu 22.04",
            type="server",
            roles=["mail_server"],
        )
        db_server = System(
            hostname="DB-PROD-01",
            ip="10.10.4.10",
            os="Ubuntu 22.04",
            type="server",
            roles=["database"],
        )

        mail_pid, _ = activity_gen._ensure_high_confidence_connection_owner(
            source_system=mail_server,
            time=timestamp,
            service="http",
            dst_port=8080,
            proto="tcp",
            hostname="api.github.com",
            http=HttpContext(
                method="CONNECT",
                host="api.github.com",
                uri="api.github.com:443",
                user_agent="python-requests/2.31.0",
            ),
        )
        smb_pid, _ = activity_gen._ensure_high_confidence_connection_owner(
            source_system=db_server,
            time=timestamp,
            service="smb",
            dst_port=445,
            proto="tcp",
            hostname="FILE-SRV-01.meridianhcs.local",
            http=None,
        )

        for system, pid in ((mail_server, mail_pid), (db_server, smb_pid)):
            proc = activity_gen.state_manager.get_process(system.hostname, pid)
            assert proc is not None
            assert "#" not in proc.command_line

        smb_proc = activity_gen.state_manager.get_process(db_server.hostname, smb_pid)
        assert smb_proc is not None
        assert smb_proc.image == "/usr/local/sbin/database-backup-agent"
        assert "smb://FILE-SRV-01.meridianhcs.local/DatabaseBackups" in smb_proc.command_line
        assert "rsyncd" not in smb_proc.command_line

    def test_linux_smb_connection_owner_is_role_specific_or_unattributed(self, activity_gen):
        """Linux SMB ownership should reflect a deployed role-specific service."""
        expected = {
            "app_server": ("/opt/meridian/bin/document-sync", "meridian-app"),
            "database": ("/usr/local/sbin/database-backup-agent", "backup"),
            "mail_server": ("/usr/libexec/meridian/attachment-archive", "dovecot"),
            "web_server": ("/opt/meridian/bin/content-publisher", "www-data"),
        }
        for index, (role, (image, username)) in enumerate(expected.items(), start=1):
            system = System(
                hostname=f"LNX-{index}",
                ip=f"10.0.20.{index}",
                os="Ubuntu 22.04",
                type="server",
                roles=[role],
            )
            spec = activity_gen._service_connection_owner_spec(
                source_system=system,
                service="smb",
                dst_port=445,
                os_category="linux",
                hostname="FILE-SRV-01.example.local",
                http=None,
            )
            assert spec is not None
            assert spec[1] == image
            assert spec[3] == username
            assert "FILE-SRV-01.example.local" in spec[2]

        proxy = System(
            hostname="PROXY-01",
            ip="10.0.20.20",
            os="Ubuntu 22.04",
            type="server",
            roles=["forward_proxy"],
        )
        assert (
            activity_gen._service_connection_owner_spec(
                source_system=proxy,
                service="smb",
                dst_port=445,
                os_category="linux",
                hostname="FILE-SRV-01.example.local",
                http=None,
            )
            is None
        )

    def test_linux_smb_connection_owner_is_scoped_to_declared_peer(
        self, activity_gen, state_manager
    ):
        """A target-bearing SMB worker must not own flows to a different peer."""
        timestamp = datetime(2024, 3, 18, 14, 20, tzinfo=UTC)
        server = System(
            hostname="DB-PROD-01",
            ip="10.0.20.10",
            os="Ubuntu 22.04",
            type="server",
            roles=["database"],
        )
        state_manager.set_current_time(timestamp)

        first_pid, _ = activity_gen._ensure_high_confidence_connection_owner(
            source_system=server,
            time=timestamp,
            service="smb",
            dst_port=445,
            proto="tcp",
            hostname="FILE-SRV-01.example.local",
            http=None,
        )
        second_pid, _ = activity_gen._ensure_high_confidence_connection_owner(
            source_system=server,
            time=timestamp + timedelta(minutes=1),
            service="smb",
            dst_port=445,
            proto="tcp",
            hostname="DC-01.example.local",
            http=None,
        )

        first = state_manager.get_process(server.hostname, first_pid)
        second = state_manager.get_process(server.hostname, second_pid)
        assert first is not None
        assert second is not None
        assert first_pid != second_pid
        assert "FILE-SRV-01.example.local" in first.command_line
        assert "DC-01.example.local" not in first.command_line
        assert "DC-01.example.local" in second.command_line
        assert "FILE-SRV-01.example.local" not in second.command_line

    def test_one_shot_connection_owner_starts_near_first_network_action(
        self, activity_gen, state_manager
    ):
        """Target-bearing clients should not idle for minutes before their first flow."""
        timestamp = datetime(2024, 3, 18, 14, 20, tzinfo=UTC)
        server = System(
            hostname="APP-INT-01",
            ip="10.10.2.30",
            os="Ubuntu 22.04",
            type="server",
            roles=["app_server"],
        )
        state_manager.set_current_time(timestamp)

        pid, _ = activity_gen._ensure_high_confidence_connection_owner(
            source_system=server,
            time=timestamp,
            service="http",
            dst_port=8080,
            proto="tcp",
            hostname="registry.npmjs.org",
            http=HttpContext(
                method="CONNECT",
                host="registry.npmjs.org",
                uri="registry.npmjs.org:443",
                user_agent="python-requests/2.31.0",
            ),
        )

        proc = state_manager.get_process(server.hostname, pid)
        assert proc is not None
        assert timedelta(milliseconds=120) <= timestamp - proc.start_time <= timedelta(seconds=3.5)

    @pytest.mark.parametrize(
        "image,command_line",
        [
            ("/usr/bin/wget", "wget -q -O - https://example.test/"),
            ("/usr/bin/smbclient", "smbclient //FILE-SRV/Shared -c 'ls'"),
            ("/usr/lib/apt/methods/https", "/usr/lib/apt/methods/https"),
            (
                "/usr/local/bin/service-healthcheck",
                "service-healthcheck --url https://example.test/health",
            ),
        ],
    )
    def test_one_shot_connection_owner_classification(self, image, command_line):
        """Sibling one-shot network client families share the startup contract."""
        assert ActivityGenerator._connection_owner_is_one_shot_network_client(
            image,
            command_line,
        )

    def test_windows_healthcheck_connection_owner_has_bounded_lifecycle(
        self, activity_gen, state_manager, test_system
    ):
        """One-shot Windows health checks terminate instead of lingering for hours."""
        timestamp = datetime(2024, 3, 18, 14, 20, tzinfo=UTC)
        image = r"C:\Program Files\Meridian\ServiceHealth\service-healthcheck.exe"
        command_line = f'"{image}" --target "gateway.zscaler.net"'
        state_manager.set_current_time(timestamp)

        pid, _ = activity_gen._ensure_system_connection_owner_process(
            source_system=test_system,
            time=timestamp,
            key="service_healthcheck:gateway.zscaler.net",
            image=image,
            command_line=command_line,
            username="SYSTEM",
        )
        process = state_manager.get_process(test_system.hostname, pid)
        assert process is not None

        activity_gen.finalize_foreground_process_lifetimes(timestamp + timedelta(minutes=5))

        assert activity_gen._process_termination_recorded(
            test_system.hostname,
            pid,
            process.start_time,
        )

    def test_smbclient_connection_owner_is_not_reused_for_later_transport(
        self, activity_gen, state_manager
    ):
        """Each noninteractive smbclient invocation owns one bounded process."""
        timestamp = datetime(2024, 3, 18, 14, 20, tzinfo=UTC)
        server = System(
            hostname="APP-INT-01",
            ip="10.10.2.30",
            os="Ubuntu 22.04",
            type="server",
            roles=["app_server"],
        )
        command_line = "smbclient //FILE-SRV-01/Shared --use-kerberos=required -c 'ls'"
        state_manager.set_current_time(timestamp)

        first_pid, _ = activity_gen._ensure_system_connection_owner_process(
            source_system=server,
            time=timestamp,
            key="smbclient:FILE-SRV-01",
            image="/usr/bin/smbclient",
            command_line=command_line,
            username="root",
        )
        second_pid, _ = activity_gen._ensure_system_connection_owner_process(
            source_system=server,
            time=timestamp + timedelta(minutes=5),
            key="smbclient:FILE-SRV-01",
            image="/usr/bin/smbclient",
            command_line=command_line,
            username="root",
        )

        assert first_pid != second_pid

    def test_windows_healthcheck_service_agent_is_durable_and_target_agnostic(
        self, activity_gen, state_manager, test_system
    ):
        """The installed monitoring service owns multiple probes without worker churn."""
        timestamp = datetime(2024, 3, 18, 14, 20, tzinfo=UTC)
        image = r"C:\Program Files\Meridian\ServiceHealth\service-healthcheck.exe"
        command_line = f'"{image}" --service'
        state_manager.set_current_time(timestamp)

        first_pid, _ = activity_gen._ensure_system_connection_owner_process(
            source_system=test_system,
            time=timestamp,
            key="service_healthcheck_agent",
            image=image,
            command_line=command_line,
            username="SYSTEM",
        )
        second_pid, _ = activity_gen._ensure_system_connection_owner_process(
            source_system=test_system,
            time=timestamp + timedelta(minutes=5),
            key="service_healthcheck_agent",
            image=image,
            command_line=command_line,
            username="SYSTEM",
        )

        assert first_pid == second_pid
        assert "--target" not in command_line
        activity_gen.finalize_foreground_process_lifetimes(timestamp + timedelta(hours=1))
        assert not activity_gen._process_termination_recorded(
            test_system.hostname,
            first_pid,
            timestamp,
        )

    def test_postfix_workers_share_root_owned_master_across_entry_paths(
        self, activity_gen, state_manager
    ):
        """SMTP flow owners from email and generic LDAP paths share one Postfix master."""
        timestamp = datetime(2024, 3, 18, 14, 20, tzinfo=UTC)
        mail = System(
            hostname="MAIL-EDGE-01",
            ip="10.10.2.25",
            os="Ubuntu 22.04",
            type="server",
            services=["smtp", "postfix"],
            roles=["mail_server"],
        )
        state_manager.set_current_time(timestamp - timedelta(hours=1))
        state_manager.register_process(
            system=mail.hostname,
            pid=1,
            parent_pid=0,
            image="/usr/lib/systemd/systemd",
            command_line="/usr/lib/systemd/systemd --system",
            username="root",
            integrity_level="System",
            os_category="linux",
        )
        activity_gen._system_pids = {mail.hostname: {"systemd": 1}}

        generic_pid, _ = activity_gen._ensure_system_connection_owner_process(
            source_system=mail,
            time=timestamp,
            key="postfix",
            image="/usr/lib/postfix/sbin/smtpd",
            command_line="smtpd -n smtp -t inet -u",
            username="postfix",
        )
        smtpd_pid = activity_gen._ensure_email_server_process(
            mail,
            time=timestamp + timedelta(minutes=1),
            port=25,
        )
        smtp_pid = activity_gen._ensure_email_mta_outbound_process(
            mail,
            time=timestamp + timedelta(minutes=2),
        )

        smtpd = state_manager.get_process(mail.hostname, smtpd_pid)
        smtp = state_manager.get_process(mail.hostname, smtp_pid)
        assert smtpd is not None
        assert smtp is not None
        assert generic_pid == smtpd_pid
        assert smtpd.parent_pid == smtp.parent_pid
        master = state_manager.get_process(mail.hostname, smtpd.parent_pid)
        assert master is not None
        assert master.image == "/usr/lib/postfix/sbin/master"
        assert master.username == "root"
        assert master.parent_pid == 1
        assert master.start_time < min(smtpd.start_time, smtp.start_time)

    def test_owa_worker_descends_from_reused_was_service_host(self, activity_gen, state_manager):
        """Exchange OWA workers are children of WAS, never direct children of services.exe."""
        timestamp = datetime(2024, 3, 18, 14, 20, tzinfo=UTC)
        exchange = System(
            hostname="MAIL-FIN-01",
            ip="10.10.2.27",
            os="Windows Server 2022",
            type="server",
            services=["owa", "exchange"],
            roles=["mail_server"],
        )
        state_manager.set_current_time(timestamp - timedelta(hours=1))
        state_manager.register_process(
            system=exchange.hostname,
            pid=4,
            parent_pid=0,
            image="System",
            command_line="",
            username="SYSTEM",
            integrity_level="System",
            os_category="windows",
        )
        state_manager.register_process(
            system=exchange.hostname,
            pid=500,
            parent_pid=4,
            image=r"C:\Windows\System32\services.exe",
            command_line="services.exe",
            username="SYSTEM",
            integrity_level="System",
            os_category="windows",
        )
        activity_gen._system_pids = {exchange.hostname: {"system": 4, "services": 500}}

        first_pid = activity_gen._ensure_email_server_process(
            exchange,
            time=timestamp,
            port=443,
        )
        second_pid = activity_gen._ensure_email_server_process(
            exchange,
            time=timestamp + timedelta(minutes=5),
            port=443,
        )

        assert second_pid == first_pid
        worker = state_manager.get_process(exchange.hostname, first_pid)
        assert worker is not None
        assert worker.parent_pid != 500
        was = state_manager.get_process(exchange.hostname, worker.parent_pid)
        assert was is not None
        assert was.image == r"C:\Windows\System32\svchost.exe"
        assert was.command_line == "svchost.exe -k iissvcs -p -s WAS"
        assert was.parent_pid == 500
        assert was.start_time < worker.start_time

    def test_direct_owa_system_process_uses_profiled_was_parent(self, activity_gen, state_manager):
        """Direct system-process callers cannot bypass configured service ancestry."""
        timestamp = datetime(2024, 3, 18, 14, 20, tzinfo=UTC)
        exchange = System(
            hostname="MAIL-FIN-01",
            ip="10.10.2.27",
            os="Windows Server 2022",
            type="server",
            services=["owa", "exchange"],
            roles=["mail_server"],
        )
        state_manager.set_current_time(timestamp - timedelta(hours=1))
        state_manager.register_process(
            system=exchange.hostname,
            pid=4,
            parent_pid=0,
            image="System",
            command_line="",
            username="SYSTEM",
            integrity_level="System",
            os_category="windows",
        )
        state_manager.register_process(
            system=exchange.hostname,
            pid=500,
            parent_pid=4,
            image=r"C:\Windows\System32\services.exe",
            command_line="services.exe",
            username="SYSTEM",
            integrity_level="System",
            os_category="windows",
        )
        activity_gen._system_pids = {exchange.hostname: {"system": 4, "services": 500}}

        pid = activity_gen.generate_system_process(
            system=exchange,
            time=timestamp,
            process_name=r"C:\Windows\System32\inetsrv\w3wp.exe",
            command_line=(r'C:\Windows\System32\inetsrv\w3wp.exe -ap "MSExchangeOWAAppPool"'),
            parent_pid=500,
            username="SYSTEM",
            emit_linux_syslog=False,
        )

        worker = state_manager.get_process(exchange.hostname, pid)
        assert worker is not None
        assert worker.parent_pid != 500
        was = state_manager.get_process(exchange.hostname, worker.parent_pid)
        assert was is not None
        assert was.image == r"C:\Windows\System32\svchost.exe"
        assert was.parent_pid == 500

        process_bundle_pid = activity_gen.generate_process(
            user=User(
                username="SYSTEM",
                full_name="Local System",
                email="system@example.test",
            ),
            system=exchange,
            time=timestamp + timedelta(minutes=1),
            logon_id="0x3e7",
            process_name=r"C:\Windows\System32\inetsrv\w3wp.exe",
            command_line=(r'C:\Windows\System32\inetsrv\w3wp.exe -ap "MSExchangeOWAAppPool"'),
            parent_pid=500,
        )
        assert process_bundle_pid == pid

    @pytest.mark.parametrize("method", ["http", "https"])
    def test_apt_method_connection_owner_has_frontend_parent(
        self, activity_gen, state_manager, method
    ):
        """APT transport helpers should be children of a live apt-get frontend."""
        timestamp = datetime(2024, 3, 18, 14, 20, tzinfo=UTC)
        server = System(
            hostname="APP-INT-01",
            ip="10.10.2.30",
            os="Ubuntu 22.04",
            type="server",
            roles=["app_server"],
        )
        state_manager.set_current_time(timestamp)

        helper_pid, _ = activity_gen._ensure_system_connection_owner_process(
            source_system=server,
            time=timestamp,
            key=f"apt_proxy_method:{method}",
            image=f"/usr/lib/apt/methods/{method}",
            command_line=f"/usr/lib/apt/methods/{method}",
            username="root",
        )

        helper = state_manager.get_process(server.hostname, helper_pid)
        assert helper is not None
        frontend = state_manager.get_process(server.hostname, helper.parent_pid)
        assert frontend is not None
        assert frontend.image == "/usr/bin/apt-get"
        assert frontend.command_line == "apt-get update"
        assert frontend.start_time < helper.start_time
        systemd = state_manager.get_process(server.hostname, frontend.parent_pid)
        assert systemd is not None
        assert systemd.image == "/usr/lib/systemd/systemd"

    def test_apt_frontend_reuses_active_transaction_and_closes(self, activity_gen, state_manager):
        """APT helper fan-out should share one bounded serialized frontend."""
        first_time = datetime(2024, 3, 18, 14, 20, tzinfo=UTC)
        server = System(
            hostname="APP-INT-01",
            ip="10.10.2.30",
            os="Ubuntu 22.04",
            type="server",
            roles=["app_server"],
        )
        state_manager.set_current_time(first_time)

        first_pid = activity_gen._ensure_linux_apt_frontend_process(
            source_system=server,
            helper_time=first_time,
            rng=random.Random(1),
        )
        second_pid = activity_gen._ensure_linux_apt_frontend_process(
            source_system=server,
            helper_time=first_time + timedelta(seconds=10),
            rng=random.Random(2),
        )

        assert second_pid == first_pid
        _pid, termination_time = activity_gen._linux_apt_frontends[server.hostname]
        assert first_time + timedelta(seconds=35) < termination_time
        assert termination_time < first_time + timedelta(seconds=101)
        frontend = state_manager.get_process(server.hostname, first_pid)
        assert frontend is not None
        frontend_start = frontend.start_time
        activity_gen.finalize_foreground_process_lifetimes(first_time + timedelta(minutes=3))
        assert activity_gen._process_termination_recorded(
            server.hostname,
            first_pid,
            frontend_start,
        )

    def test_apt_method_owner_and_frontend_close_as_one_bounded_family(
        self, activity_gen, state_manager
    ):
        """System-owned APT helpers close before their serialized frontend."""
        timestamp = datetime(2024, 3, 18, 14, 20, tzinfo=UTC)
        server = System(
            hostname="APP-INT-01",
            ip="10.10.2.30",
            os="Ubuntu 22.04",
            type="server",
            roles=["app_server"],
        )
        state_manager.set_current_time(timestamp)

        helper_pid, _ = activity_gen._ensure_system_connection_owner_process(
            source_system=server,
            time=timestamp,
            key="apt_proxy_method:https",
            image="/usr/lib/apt/methods/https",
            command_line="/usr/lib/apt/methods/https",
            username="root",
        )
        helper = state_manager.get_process(server.hostname, helper_pid)
        assert helper is not None
        frontend = state_manager.get_process(server.hostname, helper.parent_pid)
        assert frontend is not None
        helper_start = helper.start_time
        frontend_start = frontend.start_time

        activity_gen.finalize_foreground_process_lifetimes(timestamp + timedelta(minutes=3))

        assert activity_gen._process_termination_recorded(
            server.hostname,
            helper_pid,
            helper_start,
        )
        assert activity_gen._process_termination_recorded(
            server.hostname,
            frontend.pid,
            frontend_start,
        )
        helper_end = activity_gen.process_source_terminate_time(server.hostname, helper_pid)
        frontend_end = activity_gen.process_source_terminate_time(server.hostname, frontend.pid)
        assert helper_end is not None
        assert frontend_end is not None
        assert timestamp < helper_end < frontend_end < timestamp + timedelta(minutes=3)

    def test_system_owner_deadline_anchors_to_actual_process_start(
        self, activity_gen, state_manager
    ):
        """Out-of-order package intent cannot schedule closure before process creation."""
        state_time = datetime(2024, 3, 18, 14, 20, tzinfo=UTC)
        requested_time = state_time - timedelta(minutes=15)
        server = System(
            hostname="APP-INT-01",
            ip="10.10.2.30",
            os="Ubuntu 22.04",
            type="server",
            roles=["app_server"],
        )
        state_manager.set_current_time(state_time)

        helper_pid, _ = activity_gen._ensure_system_connection_owner_process(
            source_system=server,
            time=requested_time,
            key="apt_proxy_method:https",
            image="/usr/lib/apt/methods/https",
            command_line="/usr/lib/apt/methods/https",
            username="root",
        )
        helper = state_manager.get_process(server.hostname, helper_pid)
        deadline = activity_gen.foreground_process_termination_time(
            server.hostname,
            helper_pid,
        )

        assert helper is not None
        assert deadline is not None
        assert helper.start_time < deadline <= helper.start_time + timedelta(seconds=60)

    def test_workstation_ssh_connection_materializes_user_owner(
        self, activity_gen, test_user, state_manager, mock_emitters
    ):
        """User-owned SSH flows should carry the interactive user's client process."""
        timestamp = datetime(2024, 3, 18, 14, 20, tzinfo=UTC)
        workstation = System(
            hostname="WS-AJOHNSON-01",
            ip="10.10.1.35",
            os="Windows 11",
            type="workstation",
            assigned_user=test_user.username,
        )
        app_server = System(
            hostname="APP-INT-01",
            ip="10.10.2.30",
            os="Ubuntu 22.04",
            type="server",
            roles=["app_server"],
            services=["ssh"],
        )
        activity_gen._ip_to_system = {workstation.ip: workstation, app_server.ip: app_server}
        activity_gen._all_system_ips = [workstation.ip, app_server.ip]
        activity_gen._users_by_username = {test_user.username: test_user}
        state_manager.set_current_time(timestamp - timedelta(minutes=10))
        state_manager.create_session(
            username=test_user.username,
            system=workstation.hostname,
            logon_type=2,
            source_ip="-",
            session_kind="interactive",
        )
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection(
            src_ip=workstation.ip,
            dst_ip=app_server.ip,
            time=timestamp,
            dst_port=22,
            proto="tcp",
            service="ssh",
            duration=8.0,
            orig_bytes=1500,
            resp_bytes=3000,
            conn_state="SF",
            source_system=workstation,
            hostname=app_server.hostname,
        )

        connection_event = next(
            call.args[0]
            for call in mock_emitters["zeek_conn"].emit.call_args_list
            if call.args[0].event_type == "connection" and call.args[0].network.dst_port == 22
        )
        assert connection_event.network.initiating_pid > 0
        assert connection_event.process is not None
        assert connection_event.process.image == r"C:\Windows\System32\OpenSSH\ssh.exe"
        assert connection_event.process.username == test_user.username

    def test_workstation_ssh_owner_is_one_shot_per_transport(
        self, activity_gen, test_user, state_manager
    ):
        """Each SSH transport should have a distinct client unless multiplexing is explicit."""
        timestamp = datetime(2024, 3, 18, 14, 20, tzinfo=UTC)
        workstation = System(
            hostname="WS-AJOHNSON-01",
            ip="10.10.1.35",
            os="Windows 11",
            type="workstation",
            assigned_user=test_user.username,
        )
        app_server = System(
            hostname="APP-INT-01",
            ip="10.10.2.30",
            os="Ubuntu 22.04",
            type="server",
            roles=["app_server"],
            services=["ssh"],
        )
        proxy_server = System(
            hostname="PROXY-01",
            ip="10.10.3.20",
            os="Ubuntu 22.04",
            type="server",
            roles=["forward_proxy"],
            services=["ssh"],
        )
        activity_gen._ip_to_system = {
            workstation.ip: workstation,
            app_server.ip: app_server,
            proxy_server.ip: proxy_server,
        }
        activity_gen._users_by_username = {test_user.username: test_user}
        state_manager.set_current_time(timestamp - timedelta(minutes=10))
        state_manager.create_session(
            username=test_user.username,
            system=workstation.hostname,
            logon_type=2,
            source_ip="-",
            session_kind="interactive",
        )
        state_manager.set_current_time(timestamp)

        app_pid, _ = activity_gen._ensure_high_confidence_connection_owner(
            source_system=workstation,
            time=timestamp,
            service="ssh",
            dst_port=22,
            proto="tcp",
            hostname=app_server.hostname,
            http=None,
        )
        proxy_pid, _ = activity_gen._ensure_high_confidence_connection_owner(
            source_system=workstation,
            time=timestamp + timedelta(seconds=3),
            service="ssh",
            dst_port=22,
            proto="tcp",
            hostname=proxy_server.hostname,
            http=None,
        )
        app_reuse_pid, _ = activity_gen._ensure_high_confidence_connection_owner(
            source_system=workstation,
            time=timestamp + timedelta(seconds=6),
            service="ssh",
            dst_port=22,
            proto="tcp",
            hostname=app_server.hostname,
            http=None,
        )

        app_proc = state_manager.get_process(workstation.hostname, app_pid)
        proxy_proc = state_manager.get_process(workstation.hostname, proxy_pid)
        assert app_proc is not None
        assert proxy_proc is not None
        assert app_pid != proxy_pid
        assert app_reuse_pid not in {app_pid, proxy_pid}
        assert app_proc.command_line == "ssh.exe APP-INT-01"
        assert proxy_proc.command_line == "ssh.exe PROXY-01"
        assert app_proc.parent_pid != proxy_proc.parent_pid

    def test_connection_owner_process_is_not_reused_across_logon_sessions(
        self, activity_gen, test_user, state_manager
    ):
        """A process from an ended session cannot own a new session's transport."""
        first_time = datetime(2024, 3, 18, 14, 20, tzinfo=UTC)
        workstation = System(
            hostname="WS-AJOHNSON-01",
            ip="10.10.1.35",
            os="Windows 11",
            type="workstation",
            assigned_user=test_user.username,
        )
        activity_gen._users_by_username = {test_user.username: test_user}
        state_manager.set_current_time(first_time - timedelta(minutes=10))
        first_logon_id = state_manager.create_session(
            username=test_user.username,
            system=workstation.hostname,
            logon_type=2,
            source_ip="-",
            session_kind="interactive",
        )
        state_manager.set_current_time(first_time)
        first_pid, _ = activity_gen._ensure_user_connection_owner_process(
            source_system=workstation,
            time=first_time,
            service="smb",
            dst_port=445,
            os_category="windows",
            hostname="FILE-SRV-01",
            ssh_attempted_username=None,
        )
        first_process = state_manager.get_process(workstation.hostname, first_pid)
        assert first_process is not None
        assert first_process.logon_id == first_logon_id

        state_manager.end_session(first_logon_id, first_time + timedelta(minutes=1))
        second_time = first_time + timedelta(minutes=5)
        state_manager.set_current_time(second_time - timedelta(minutes=1))
        second_logon_id = state_manager.create_session(
            username=test_user.username,
            system=workstation.hostname,
            logon_type=2,
            source_ip="-",
            session_kind="interactive",
        )
        state_manager.set_current_time(second_time)
        second_pid, _ = activity_gen._ensure_user_connection_owner_process(
            source_system=workstation,
            time=second_time,
            service="smb",
            dst_port=445,
            os_category="windows",
            hostname="FILE-SRV-01",
            ssh_attempted_username=None,
        )

        second_process = state_manager.get_process(workstation.hostname, second_pid)
        assert second_process is not None
        assert second_pid != first_pid
        assert second_process.logon_id == second_logon_id

    def test_ssh_session_windows_client_command_names_remote_user(
        self, activity_gen, state_manager, mock_emitters
    ):
        """Successful SSH sessions should expose alternate remote users in client commands."""
        timestamp = datetime(2024, 3, 18, 14, 20, tzinfo=UTC)
        source_user = User(
            username="priya.patel",
            full_name="Priya Patel",
            email="priya.patel@example.local",
        )
        remote_user = User(
            username="aisha.johnson",
            full_name="Aisha Johnson",
            email="aisha.johnson@example.local",
        )
        workstation = System(
            hostname="WS-PPATEL-01",
            ip="10.10.1.32",
            os="Windows 11",
            type="workstation",
            assigned_user=source_user.username,
        )
        web_server = System(
            hostname="WEB-EXT-01",
            ip="10.10.3.10",
            os="Ubuntu 22.04",
            type="server",
            roles=["web_server"],
            services=["ssh"],
        )
        activity_gen._ip_to_system = {workstation.ip: workstation, web_server.ip: web_server}
        activity_gen._all_system_ips = [workstation.ip, web_server.ip]
        activity_gen._users_by_username = {
            source_user.username: source_user,
            remote_user.username: remote_user,
        }
        mock_emitters["syslog"] = Mock()
        state_manager.set_current_time(timestamp - timedelta(minutes=10))
        source_logon_id = state_manager.create_session(
            username=source_user.username,
            system=workstation.hostname,
            logon_type=2,
            source_ip="-",
            session_kind="interactive",
        )
        state_manager.set_current_time(timestamp)
        activity_gen._last_one_shot_cli_launch_by_exe[
            (workstation.hostname, source_user.username, source_logon_id, "ssh.exe")
        ] = timestamp + timedelta(seconds=30)

        activity_gen.generate_ssh_session(
            user=remote_user,
            target_system=web_server,
            time=timestamp,
            source_ip=workstation.ip,
            source_system=workstation,
            duration=30.0,
        )

        ssh_processes = [
            proc
            for proc in state_manager.get_processes_on_system(workstation.hostname)
            if proc.image == r"C:\Windows\System32\OpenSSH\ssh.exe"
        ]
        assert ssh_processes
        ssh_proc = ssh_processes[-1]
        assert ssh_proc.username == source_user.username
        assert ssh_proc.command_line == "ssh.exe aisha.johnson@WEB-EXT-01"
        parent = state_manager.get_process(workstation.hostname, ssh_proc.parent_pid)
        assert parent is not None
        assert parent.image.rsplit("\\", 1)[-1].lower() in {
            "cmd.exe",
            "powershell.exe",
            "pwsh.exe",
            "windowsterminal.exe",
        }
        assert parent.logon_id == ssh_proc.logon_id
        assert parent.start_time < ssh_proc.start_time

        connection_event = next(
            call.args[0]
            for call in mock_emitters["zeek_conn"].emit.call_args_list
            if call.args[0].event_type == "connection" and call.args[0].network.dst_port == 22
        )
        assert connection_event.process is not None
        assert connection_event.process.username == source_user.username
        assert connection_event.process.command_line == ssh_proc.command_line
        source_create_time = activity_gen.process_source_create_time(
            workstation.hostname,
            ssh_proc.pid,
        )
        assert source_create_time is not None
        assert ssh_proc.start_time < connection_event.network.started_at
        assert source_create_time <= connection_event.network.started_at

        ssh_syslog_events = [
            call.args[0]
            for call in mock_emitters["syslog"].emit.call_args_list
            if call.args[0].event_type == "syslog"
            and call.args[0].syslog is not None
            and call.args[0].syslog.app_name == "sshd"
        ]
        accepted = next(
            event for event in ssh_syslog_events if event.syslog.message.startswith("Accepted ")
        )
        pam_open = next(
            event
            for event in ssh_syslog_events
            if "pam_unix(sshd:session): session opened" in event.syslog.message
        )
        assert connection_event.network.started_at < accepted.timestamp < pam_open.timestamp

    def test_ssh_session_linux_client_create_precedes_transport_when_shell_is_busy(
        self, activity_gen, state_manager, mock_emitters
    ):
        """A busy source shell must not move its SSH client behind transport or target auth."""
        timestamp = datetime(2024, 3, 18, 14, 20, tzinfo=UTC)
        user = User(
            username="marcus.chen",
            full_name="Marcus Chen",
            email="marcus.chen@example.local",
        )
        workstation = System(
            hostname="LT-MCHEN-01",
            ip="10.10.1.33",
            os="Ubuntu 22.04",
            type="workstation",
            assigned_user=user.username,
        )
        target = System(
            hostname="DB-PROD-01",
            ip="10.10.3.20",
            os="Ubuntu 22.04",
            type="server",
            roles=["database_server"],
            services=["ssh"],
        )
        activity_gen._ip_to_system = {workstation.ip: workstation, target.ip: target}
        activity_gen._all_system_ips = [workstation.ip, target.ip]
        activity_gen._users_by_username = {user.username: user}
        mock_emitters["syslog"] = Mock()
        logon_time = timestamp - timedelta(minutes=10)
        state_manager.set_current_time(logon_time)
        logon_id = state_manager.create_session(
            username=user.username,
            system=workstation.hostname,
            logon_type=2,
            source_ip="-",
            session_kind="interactive",
        )
        shell_pid = activity_gen.ensure_linux_session_shell(
            user=user,
            target_system=workstation,
            logon_id=logon_id,
            logon_time=logon_time,
            activity_time=timestamp - timedelta(seconds=30),
        )
        assert shell_pid is not None
        activity_gen._foreground_shell_next_time[
            (workstation.hostname, user.username, logon_id, shell_pid)
        ] = timestamp + timedelta(seconds=30)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_ssh_session(
            user=user,
            target_system=target,
            time=timestamp,
            source_ip=workstation.ip,
            source_system=workstation,
            duration=30.0,
        )

        ssh_processes = [
            proc
            for proc in state_manager.get_processes_on_system(workstation.hostname)
            if proc.image == "/usr/bin/ssh"
        ]
        assert ssh_processes
        ssh_proc = ssh_processes[-1]
        connection_event = next(
            call.args[0]
            for call in mock_emitters["zeek_conn"].emit.call_args_list
            if call.args[0].event_type == "connection" and call.args[0].network.dst_port == 22
        )
        source_create_time = activity_gen.process_source_create_time(
            workstation.hostname,
            ssh_proc.pid,
        )
        assert source_create_time is not None
        assert ssh_proc.start_time < connection_event.network.started_at
        assert source_create_time <= connection_event.network.started_at

        ssh_syslog_events = [
            call.args[0]
            for call in mock_emitters["syslog"].emit.call_args_list
            if call.args[0].event_type == "syslog"
            and call.args[0].syslog is not None
            and call.args[0].syslog.app_name == "sshd"
        ]
        accepted = next(
            event for event in ssh_syslog_events if event.syslog.message.startswith("Accepted ")
        )
        pam_open = next(
            event
            for event in ssh_syslog_events
            if "pam_unix(sshd:session): session opened" in event.syslog.message
        )
        assert connection_event.network.started_at < accepted.timestamp < pam_open.timestamp

    def test_linux_smb_browse_owner_is_scoped_to_command_target(
        self, activity_gen, test_user, state_manager
    ):
        """Target-bearing Linux SMB browse clients should not be reused across hosts."""
        timestamp = datetime(2024, 3, 18, 14, 20, tzinfo=UTC)
        workstation = System(
            hostname="LT-MRIVERA-02",
            ip="10.10.1.50",
            os="Ubuntu 22.04",
            type="workstation",
            assigned_user=test_user.username,
        )
        file_server = System(
            hostname="FILE-SRV-01",
            ip="10.10.2.20",
            os="Windows Server 2022",
            type="server",
            roles=["file_server"],
            services=["smb"],
        )
        dc_server = System(
            hostname="DC-01",
            ip="10.10.2.10",
            os="Windows Server 2022",
            type="domain_controller",
            roles=["domain_controller"],
            services=["smb"],
        )
        activity_gen._ip_to_system = {
            workstation.ip: workstation,
            file_server.ip: file_server,
            dc_server.ip: dc_server,
        }
        activity_gen._users_by_username = {test_user.username: test_user}
        state_manager.set_current_time(timestamp - timedelta(minutes=10))
        state_manager.create_session(
            username=test_user.username,
            system=workstation.hostname,
            logon_type=2,
            source_ip="-",
            session_kind="interactive",
        )
        state_manager.set_current_time(timestamp)

        file_pid, _ = activity_gen._ensure_high_confidence_connection_owner(
            source_system=workstation,
            time=timestamp,
            service="smb",
            dst_port=445,
            proto="tcp",
            hostname=file_server.hostname,
            http=None,
        )
        dc_pid, _ = activity_gen._ensure_high_confidence_connection_owner(
            source_system=workstation,
            time=timestamp + timedelta(seconds=3),
            service="smb",
            dst_port=445,
            proto="tcp",
            hostname=dc_server.hostname,
            http=None,
        )
        file_reuse_pid, _ = activity_gen._ensure_high_confidence_connection_owner(
            source_system=workstation,
            time=timestamp + timedelta(seconds=6),
            service="smb",
            dst_port=445,
            proto="tcp",
            hostname=file_server.hostname,
            http=None,
        )

        file_proc = state_manager.get_process(workstation.hostname, file_pid)
        dc_proc = state_manager.get_process(workstation.hostname, dc_pid)
        assert file_proc is not None
        assert dc_proc is not None
        assert file_pid != dc_pid
        assert file_reuse_pid == file_pid
        assert file_proc.command_line == 'gvfsd-smb-browse "smb://FILE-SRV-01/shared"'
        assert dc_proc.command_line == 'gvfsd-smb-browse "smb://DC-01/shared"'

    def test_cifs_mount_operation_actor_is_not_transport_owner(
        self, activity_gen, test_user, state_manager
    ) -> None:
        """Mounted CIFS uses a local operation actor and kernel-owned transport."""
        timestamp = datetime(2024, 3, 18, 14, 20, tzinfo=UTC)
        workstation = System(
            hostname="LT-CIFS-01",
            ip="10.10.1.60",
            os="Ubuntu 24.04",
            type="workstation",
            assigned_user=test_user.username,
            services=["cifs-utils"],
        )
        activity_gen._users_by_username = {test_user.username: test_user}
        state_manager.set_current_time(timestamp - timedelta(minutes=10))
        state_manager.create_session(
            username=test_user.username,
            system=workstation.hostname,
            logon_type=2,
            source_ip="-",
            session_kind="interactive",
        )
        state_manager.set_current_time(timestamp)

        plan = activity_gen.ensure_smb_client_process(
            client_system=workstation,
            actor=test_user,
            server="SAMBA-01",
            share="Engineering",
            path="Reports/Q1.csv",
            client_path="/mnt/engineering/Reports/Q1.csv",
            operation="read",
            time=timestamp,
        )

        process = state_manager.get_process(workstation.hostname, plan.actor_pid)
        assert process is not None
        assert process.image == "/usr/bin/head"
        assert process.command_line == 'head -c 4096 "/mnt/engineering/Reports/Q1.csv"'
        assert plan.access_mode == "mounted"
        assert plan.transport_pid == -1
        assert plan.transport_image == ""

    @pytest.mark.parametrize(
        ("operation", "transfer_direction", "source_path", "destination_path", "image"),
        [
            (
                "copy",
                "download",
                "/mnt/engineering/Reports/Q1.csv",
                "/var/tmp/smb-cache/Q1.csv",
                "/usr/bin/cp",
            ),
            (
                "copy",
                "upload",
                "/var/tmp/outgoing/Q1.csv",
                "/mnt/engineering/Incoming/Q1.csv",
                "/usr/bin/cp",
            ),
            (
                "move",
                "upload",
                "/var/tmp/outgoing/Q1.csv",
                "/mnt/engineering/Incoming/Q1.csv",
                "/usr/bin/mv",
            ),
            (
                "move",
                "remote",
                "/mnt/engineering/Reports/Q1.csv",
                "/mnt/engineering/Archive/Q1.csv",
                "/usr/bin/mv",
            ),
        ],
    )
    def test_cifs_mount_transfer_uses_resolved_native_operands(
        self,
        activity_gen,
        test_user,
        state_manager,
        operation: str,
        transfer_direction: str,
        source_path: str,
        destination_path: str,
        image: str,
    ) -> None:
        """Mounted transfers retain cp/mv and the authored native endpoints."""

        timestamp = datetime(2024, 3, 18, 14, 20, tzinfo=UTC)
        workstation = System(
            hostname="LT-CIFS-XFER-01",
            ip="10.10.1.64",
            os="Ubuntu 24.04",
            type="workstation",
            assigned_user=test_user.username,
            services=["cifs-utils"],
        )
        activity_gen._users_by_username = {test_user.username: test_user}
        state_manager.set_current_time(timestamp - timedelta(minutes=10))
        state_manager.create_session(
            username=test_user.username,
            system=workstation.hostname,
            logon_type=2,
            source_ip="-",
            session_kind="interactive",
        )
        state_manager.set_current_time(timestamp)

        plan = activity_gen.ensure_smb_client_process(
            client_system=workstation,
            actor=test_user,
            server="SAMBA-01",
            share="Engineering",
            path="Reports/Q1.csv",
            client_path="/mnt/engineering/Reports/Q1.csv",
            local_path="/var/tmp/outgoing/Q1.csv",
            source_path=source_path,
            destination_path=destination_path,
            operation=operation,
            transfer_direction=transfer_direction,
            time=timestamp,
        )

        process = state_manager.get_process(workstation.hostname, plan.actor_pid)
        assert process is not None
        assert process.image == image
        assert process.command_line == (
            f'{image.rsplit("/", 1)[-1]} -- "{source_path}" "{destination_path}"'
        )
        assert "/home/" not in process.command_line
        assert "/usr/bin/touch" not in process.command_line
        assert plan.transport_pid == -1
        assert plan.transport_image == ""

    def test_smbclient_operation_process_owns_direct_transport(
        self, activity_gen, test_user, state_manager
    ) -> None:
        """Direct Linux SMB activity uses one bounded smbclient transport owner."""
        timestamp = datetime(2024, 3, 18, 14, 20, tzinfo=UTC)
        workstation = System(
            hostname="LT-SMBCLIENT-01",
            ip="10.10.1.61",
            os="Ubuntu 24.04",
            type="workstation",
            assigned_user=test_user.username,
            services=["smbclient"],
        )
        activity_gen._users_by_username = {test_user.username: test_user}
        state_manager.set_current_time(timestamp - timedelta(minutes=10))
        state_manager.create_session(
            username=test_user.username,
            system=workstation.hostname,
            logon_type=2,
            source_ip="-",
            session_kind="interactive",
        )
        state_manager.set_current_time(timestamp)

        plan = activity_gen.ensure_smb_client_process(
            client_system=workstation,
            actor=test_user,
            server="SAMBA-01",
            share="Engineering",
            path="Reports/Q1.csv",
            client_path="/home/testuser/Q1.csv",
            operation="update",
            time=timestamp,
            smb_principal=r"EXAMPLE\finance-writer",
            auth_protocol="ntlmssp",
        )

        process = state_manager.get_process(workstation.hostname, plan.actor_pid)
        assert process is not None
        assert process.image == "/usr/bin/smbclient"
        assert process.username == test_user.username
        assert 'smbclient "//SAMBA-01/Engineering"' in process.command_line
        assert '-U "EXAMPLE\\finance-writer"' in process.command_line
        assert "--use-kerberos=off" in process.command_line
        assert 'put "/home/testuser/Q1.csv" "Reports/Q1.csv"' in process.command_line
        assert plan.access_mode == "direct"
        assert plan.transport_pid == plan.actor_pid
        assert (
            activity_gen.foreground_process_termination_time(
                workstation.hostname,
                plan.actor_pid,
            )
            is not None
        )

    def test_smbclient_remote_presentation_never_becomes_local_get_operand(
        self, activity_gen, test_user, state_manager
    ) -> None:
        """Direct SMB downloads fall back to a local basename, not a second UNC path."""
        timestamp = datetime(2024, 3, 18, 14, 20, tzinfo=UTC)
        workstation = System(
            hostname="LT-SMBCLIENT-02",
            ip="10.10.1.63",
            os="Ubuntu 24.04",
            type="workstation",
            assigned_user=test_user.username,
            services=["smbclient"],
        )
        activity_gen._users_by_username = {test_user.username: test_user}
        state_manager.set_current_time(timestamp - timedelta(minutes=10))
        state_manager.create_session(
            username=test_user.username,
            system=workstation.hostname,
            logon_type=2,
            source_ip="-",
            session_kind="interactive",
        )
        state_manager.set_current_time(timestamp)

        plan = activity_gen.ensure_smb_client_process(
            client_system=workstation,
            actor=test_user,
            server="SAMBA-01",
            share="Engineering",
            path=r"Reports\Q1.csv",
            client_path="//SAMBA-01/Engineering/Reports/Q1.csv",
            operation="read",
            time=timestamp,
            smb_principal="share-reader",
            auth_protocol="kerberos",
        )

        process = state_manager.get_process(workstation.hostname, plan.actor_pid)
        assert process is not None
        assert process.username == test_user.username
        assert '-U "share-reader"' in process.command_line
        assert "--use-kerberos=required" in process.command_line
        assert 'get "Reports\\Q1.csv" "Q1.csv"' in process.command_line
        assert process.command_line.count("//SAMBA-01/Engineering") == 1

    def test_linux_smb_source_pid_never_uses_local_smbd(self, activity_gen, state_manager) -> None:
        """A Samba listener cannot be inferred as an outbound Linux client."""
        system = System(
            hostname="SAMBA-CLIENT-01",
            ip="10.10.1.62",
            os="Ubuntu 24.04",
            type="server",
            services=["samba", "smbclient"],
        )
        state_manager.set_current_time(datetime(2024, 3, 18, 14, 20, tzinfo=UTC))
        state_manager.register_process(
            system=system.hostname,
            pid=1440,
            parent_pid=0,
            image="/usr/sbin/smbd",
            command_line="/usr/sbin/smbd --foreground",
            username="root",
            integrity_level="System",
            os_category="linux",
        )
        activity_gen._system_pids = {system.hostname: {"smbd": 1440}}

        assert activity_gen._infer_connection_pid(system, "smb", 445, "tcp") == -1

    def test_linux_samba_responder_is_tuple_scoped_worker(
        self, activity_gen, state_manager
    ) -> None:
        """Successful inbound SMB transports resolve to smbd children, not the master."""
        timestamp = datetime(2024, 3, 18, 14, 20, tzinfo=UTC)
        server = System(
            hostname="SAMBA-01",
            ip="10.10.2.20",
            os="Ubuntu 24.04",
            type="server",
            services=["samba"],
        )
        state_manager.set_current_time(timestamp - timedelta(minutes=10))
        state_manager.register_process(
            system=server.hostname,
            pid=1,
            parent_pid=0,
            image="/usr/lib/systemd/systemd",
            command_line="/usr/lib/systemd/systemd --system",
            username="root",
            integrity_level="System",
            os_category="linux",
        )
        activity_gen._system_pids = {server.hostname: {"systemd": 1}}
        state_manager.set_current_time(timestamp)

        first = activity_gen.ensure_linux_smb_responder_process(
            target_system=server,
            time=timestamp,
            source_ip="10.10.1.60",
            source_port=51000,
            close_time=timestamp + timedelta(seconds=30),
        )
        reused = activity_gen.ensure_linux_smb_responder_process(
            target_system=server,
            time=timestamp + timedelta(seconds=1),
            source_ip="10.10.1.60",
            source_port=51000,
        )
        second = activity_gen.ensure_linux_smb_responder_process(
            target_system=server,
            time=timestamp + timedelta(seconds=2),
            source_ip="10.10.1.61",
            source_port=51001,
        )

        master = activity_gen._system_pids[server.hostname]["smbd"]
        first_process = state_manager.get_process(server.hostname, first)
        assert first_process is not None
        assert first == reused
        assert first != second
        assert first != master
        assert first_process.parent_pid == master
        assert first_process.image == "/usr/sbin/smbd"

        activity_gen.finalize_foreground_process_lifetimes(timestamp + timedelta(minutes=1))

        assert activity_gen._process_termination_recorded(
            server.hostname,
            first,
            first_process.start_time,
        )

    def test_linux_smb_browse_owner_reuses_resource_when_requests_arrive_out_of_order(
        self, activity_gen, test_user, state_manager
    ):
        """Resident SMB helpers bootstrap near session start and survive planner order."""
        timestamp = datetime(2024, 3, 18, 14, 20, tzinfo=UTC)
        workstation = System(
            hostname="LT-MRIVERA-02",
            ip="10.10.1.50",
            os="Ubuntu 22.04",
            type="workstation",
            assigned_user=test_user.username,
        )
        file_server = System(
            hostname="FILE-SRV-01",
            ip="10.10.2.20",
            os="Windows Server 2022",
            type="server",
            roles=["file_server"],
            services=["smb"],
        )
        activity_gen._ip_to_system = {
            workstation.ip: workstation,
            file_server.ip: file_server,
        }
        activity_gen._users_by_username = {test_user.username: test_user}
        state_manager.set_current_time(timestamp - timedelta(minutes=10))
        state_manager.create_session(
            username=test_user.username,
            system=workstation.hostname,
            logon_type=2,
            source_ip="-",
            session_kind="interactive",
        )
        state_manager.set_current_time(timestamp)

        later_pid, _ = activity_gen._ensure_high_confidence_connection_owner(
            source_system=workstation,
            time=timestamp + timedelta(hours=2),
            service="smb",
            dst_port=445,
            proto="tcp",
            hostname=file_server.hostname,
            http=None,
        )
        earlier_pid, _ = activity_gen._ensure_high_confidence_connection_owner(
            source_system=workstation,
            time=timestamp,
            service="smb",
            dst_port=445,
            proto="tcp",
            hostname=file_server.hostname,
            http=None,
        )

        owners = [
            process
            for process in state_manager.get_processes_on_system(workstation.hostname)
            if process.image == "/usr/bin/gvfsd-smb-browse"
            and process.command_line == 'gvfsd-smb-browse "smb://FILE-SRV-01/shared"'
        ]
        assert earlier_pid == later_pid
        assert len(owners) == 1
        assert owners[0].start_time < timestamp

    def test_outlook_catalog_singleton_reuses_recycle_launch(
        self, activity_gen, test_user, test_system, state_manager
    ):
        """Outlook /recycle resolves to the live session owner."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        logon_id = state_manager.create_session(
            username=test_user.username,
            system=test_system.hostname,
            logon_type=2,
            source_ip="-",
            start_time=timestamp - timedelta(minutes=1),
            session_kind="interactive",
        )
        image = r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"
        first_pid = activity_gen.generate_process(
            test_user, test_system, timestamp, logon_id, image, "OUTLOOK.EXE /recycle"
        )
        reused_pid = activity_gen.generate_process(
            test_user,
            test_system,
            timestamp + timedelta(minutes=5),
            logon_id,
            image,
            f'"{image}" /recycle',
        )

        assert reused_pid == first_pid

    def test_outlook_email_client_reuses_owner_when_requests_arrive_out_of_order(
        self, activity_gen, test_user, test_system, state_manager
    ):
        """Email access bootstraps one resident Outlook owner near session start."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.create_session(
            username=test_user.username,
            system=test_system.hostname,
            logon_type=2,
            source_ip="-",
            start_time=timestamp - timedelta(minutes=1),
            session_kind="interactive",
        )
        image = r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"

        later_pid, _ = activity_gen._ensure_email_client_process(
            user=test_user,
            system=test_system,
            time=timestamp + timedelta(hours=2),
            image=image,
            command_line=f'"{image}" /recycle',
        )
        earlier_pid, _ = activity_gen._ensure_email_client_process(
            user=test_user,
            system=test_system,
            time=timestamp,
            image=image,
            command_line=f'"{image}" /recycle',
        )

        owners = [
            process
            for process in state_manager.get_processes_on_system(test_system.hostname)
            if process.image == image and process.username == test_user.username
        ]
        assert earlier_pid == later_pid
        assert len(owners) == 1
        assert owners[0].start_time < timestamp

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

    def test_smb_process_network_effect_uses_service_compatible_target(
        self, activity_gen, test_user, state_manager, mock_emitters
    ):
        """Explorer SMB side effects should target Windows/Samba hosts, not Linux app hosts."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        workstation = System(
            hostname="WS-01",
            ip="10.0.1.10",
            os="Windows 11",
            type="workstation",
        )
        linux_app = System(
            hostname="APP-01",
            ip="10.0.2.30",
            os="Ubuntu 22.04",
            type="server",
            services=["ssh", "gunicorn"],
            roles=["app_server"],
        )
        file_server = System(
            hostname="FILE-01",
            ip="10.0.2.20",
            os="Windows Server 2019",
            type="server",
            services=["smb", "dns-client"],
            roles=["file_server"],
        )
        activity_gen._ip_to_system = {
            workstation.ip: workstation,
            linux_app.ip: linux_app,
            file_server.ip: file_server,
        }
        activity_gen._all_system_ips = [workstation.ip, linux_app.ip, file_server.ip]
        state_manager.set_current_time(timestamp)
        process_name = r"C:\Windows\explorer.exe"
        command_line = "explorer.exe"
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
        assert network_events[-1].network.dst_ip == file_server.ip
        assert network_events[-1].network.dst_port == 445
        assert network_events[-1].network.conn_state != "S0"

    def test_smb_process_network_effect_skips_without_service_compatible_target(
        self, activity_gen, test_user, state_manager, mock_emitters
    ):
        """Explorer SMB side effects should not invent successful SMB to Linux-only hosts."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        workstation = System(
            hostname="WS-01",
            ip="10.0.1.10",
            os="Windows 11",
            type="workstation",
        )
        linux_app = System(
            hostname="APP-01",
            ip="10.0.2.30",
            os="Ubuntu 22.04",
            type="server",
            services=["ssh", "gunicorn"],
            roles=["app_server"],
        )
        activity_gen._ip_to_system = {workstation.ip: workstation, linux_app.ip: linux_app}
        activity_gen._all_system_ips = [workstation.ip, linux_app.ip]
        state_manager.set_current_time(timestamp)
        process_name = r"C:\Windows\explorer.exe"
        command_line = "explorer.exe"

        activity_gen._emit_process_network_correlation(
            workstation,
            process_name,
            command_line,
            timestamp,
            4242,
            random.Random(1),
        )

        network_events = [
            call.args[0]
            for call in mock_emitters["zeek_conn"].emit.call_args_list
            if call.args[0].event_type == "connection"
        ]
        assert not network_events

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

    @pytest.mark.parametrize(
        "service_image",
        [
            r"C:\Windows\PSEXESVC.exe",
            r"C:\Windows\HealthMonitorSvc.exe",
        ],
    )
    def test_bundle_owned_service_payload_excludes_generic_process_file_create(
        self,
        activity_gen,
        test_user,
        test_system,
        state_manager,
        mock_emitters,
        service_image,
    ):
        """Generic process generation must not duplicate bundle-owned service payloads."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_process(
            test_user,
            test_system,
            timestamp,
            "0x12345",
            service_image,
            service_image,
            ensure_file_event=True,
        )

        events = [
            call.args[0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        process_event = next(event for event in events if event.event_type == "process_create")
        matching_file_events = [
            event
            for event in events
            if event.event_type == "file_create"
            and event.file is not None
            and event.file.path.casefold() == service_image.casefold()
        ]
        assert process_event.process.image.casefold() == service_image.casefold()
        assert matching_file_events == []

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
        assert file_event.process.pid == 4
        assert file_event.process.parent_pid == 0
        assert file_event.process.image == "System"
        assert file_event.process.command_line == "System"
        assert file_event.file.pid == 4
        assert file_event.lifecycle is not None
        assert service_event.lifecycle is not None
        assert file_event.lifecycle.group_id == service_event.lifecycle.group_id
        assert file_event.lifecycle.phase == "start"
        assert service_event.lifecycle.phase == "dependent"
        assert file_event.lifecycle.canonical_start == file_event.timestamp
        assert service_event.lifecycle.canonical_start == file_event.timestamp
        policy = ObservationPolicy("messy_collection")
        for format_name in ("windows_event_sysmon", "ecar"):
            assert policy.decide(format_name, file_event) == policy.decide(
                format_name,
                service_event,
            )

    def test_preexisting_service_binary_starts_lifecycle_without_payload_file(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Preinstalled service images should not acquire a fabricated drop prerequisite."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_service_installed(
            test_user,
            test_system,
            timestamp,
            service_name="DeviceSyncSvc",
            service_file_name=r"C:\Windows\System32\DeviceSyncSvc.exe",
        )

        events = [
            call.args[0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        service_event = next(event for event in events if event.event_type == "service_installed")
        matching_files = [
            event
            for event in events
            if event.event_type == "file_create"
            and event.file is not None
            and event.file.path.casefold() == r"C:\Windows\System32\DeviceSyncSvc.exe".casefold()
        ]

        assert matching_files == []
        assert service_event.lifecycle is not None
        assert service_event.lifecycle.phase == "start"
        assert service_event.lifecycle.canonical_start == timestamp

    def test_windows_service_install_bundle_anchor_is_stable(self, test_user, test_system):
        """Identical service-install bundle requests should have stable action anchors."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        first = WindowsServiceInstallRequest(
            user=test_user,
            system=test_system,
            time=timestamp,
            service_name="PSEXESVC",
            service_file_name=r"%SystemRoot%\PSEXESVC.exe",
        )
        second = WindowsServiceInstallRequest(
            user=test_user,
            system=test_system,
            time=timestamp,
            service_name="PSEXESVC",
            service_file_name=r"%SystemRoot%\PSEXESVC.exe",
        )

        assert (
            WindowsServiceInstallActionBundle(Mock(), first).anchor
            == WindowsServiceInstallActionBundle(Mock(), second).anchor
        )

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

    def test_process_registry_uses_occurrence_aware_canonical_materializer(self):
        """Process-owned registry effects must supply time and type before dispatch."""
        import inspect

        source = inspect.getsource(ActivityGenerator._execute_process_create_bundle)
        assert "_key, _vname, _details, _value_type = materialize_registry_effect(" in source
        assert "_template_user,\n                    _reg_ts," in source
        assert "value_type=_value_type" in source

    def test_process_userassist_effect_preserves_actor_session_and_time(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """A process-side UserAssist effect stays owned by its Explorer session."""

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

        timestamp = datetime(2027, 8, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        logon_id = activity_gen.generate_logon(test_user, test_system, timestamp)
        userassist_template = [
            (
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
                r"\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count",
                "{userassist_value}",
                "{userassist_binary}",
            )
        ]

        with (
            patch("evidenceforge.generation.activity.generator._get_rng", RegistryOnlyRandom),
            patch(
                "evidenceforge.generation.activity.edr_pools.get_registry_keys_hkcu",
                return_value=userassist_template,
            ),
            patch(
                "evidenceforge.generation.activity.edr_pools.get_registry_keys_hklm",
                return_value=[],
            ),
        ):
            activity_gen.generate_process(
                test_user,
                test_system,
                timestamp + timedelta(seconds=1),
                logon_id,
                r"C:\Windows\explorer.exe",
                r"C:\Windows\explorer.exe",
            )

        registry_events = [
            call.args[0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call.args[0].event_type == "registry_modify"
        ]
        assert len(registry_events) == 1
        event = registry_events[0]
        assert event.process.image.lower().endswith(r"\explorer.exe")
        assert event.process.logon_id == event.auth.logon_id == logon_id
        assert event.registry.value_type == "binary"
        payload = bytes.fromhex(event.registry.value)
        filetime = int.from_bytes(payload[60:68], "little")
        embedded_time = datetime(1601, 1, 1, tzinfo=UTC) + timedelta(microseconds=filetime // 10)
        assert embedded_time <= event.timestamp

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
    ):
        """Startup ImageLoad events should carry DLL profile signer fields."""

        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        logon_id = activity_gen.generate_logon(test_user, test_system, timestamp)

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
        mozglue = next(
            event
            for event in image_load_events
            if event.image_load.image_loaded.endswith("mozglue.dll")
        )
        assert mozglue.image_load.signature == "Mozilla Corporation"
        assert mozglue.image_load.signature_status == "Valid"
        assert mozglue.image_load.load_phase == "startup"
        assert mozglue.image_load.load_order > 0

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
            r"C:\Windows\System32\netapi32.dll",
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
            r"C:\Users\{username}\AppData\Roaming\Zoom\bin\meetingPlugin.dll",
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
        assert service_logon_id == event.auth.subject_logon_id == "0x3e7"

    @pytest.mark.parametrize(
        ("service_account", "expected_logon_id"),
        [
            ("SYSTEM", "0x3e7"),
            ("LOCAL SERVICE", "0x3e5"),
            ("NETWORK SERVICE", "0x3e4"),
        ],
    )
    def test_builtin_service_logon_uses_well_known_authentication_id(
        self,
        activity_gen,
        test_system,
        state_manager,
        mock_emitters,
        service_account,
        expected_logon_id,
    ):
        """Built-in Type 5 logons reuse the token's Windows well-known LUID."""

        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        first = activity_gen.generate_service_logon(test_system, timestamp, service_account)
        second = activity_gen.generate_service_logon(
            test_system,
            timestamp + timedelta(minutes=5),
            service_account,
        )

        events = [
            call.args[0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call.args[0].event_type == "logon" and call.args[0].auth.logon_type == 5
        ]
        assert first == second == expected_logon_id
        assert {event.auth.logon_id for event in events} == {expected_logon_id}
        assert len({event.identity_plan.session.object_id for event in events}) == 2
        assert len({event.lifecycle.group_id for event in events}) == 2
        assert all(event.identity_plan.session.logon_id == expected_logon_id for event in events)
        assert state_manager.get_session(expected_logon_id) is None

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
        assert ecar_logons[0].identity_plan.object_id
        assert ecar_logons[1].identity_plan.object_id
        assert ecar_logons[1].identity_plan.object_id != ecar_logons[0].identity_plan.object_id
        assert ecar_logons[1].identity_plan.actor_id == ecar_logons[0].identity_plan.object_id

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

    def test_workstation_lock_unlock_reject_rdp_session_luid(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """A local workstation lock/unlock should never reuse a Type 10 RDP LUID."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        rdp_logon_id = "0xabc124"
        state_manager.register_session(
            logon_id=rdp_logon_id,
            username=test_user.username,
            system=test_system.hostname,
            logon_type=10,
            source_ip="10.0.0.55",
            start_time=timestamp - timedelta(minutes=5),
            session_kind="rdp",
            session_id=6,
        )

        activity_gen.generate_workstation_lock(
            test_user,
            test_system,
            timestamp,
            rdp_logon_id,
        )
        activity_gen.generate_workstation_unlock(
            test_user,
            test_system,
            timestamp + timedelta(minutes=5),
            rdp_logon_id,
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

    def test_local_interactive_logon_does_not_reuse_rdp_session_luid(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """A fresh local Type 2 logon should not inherit an active RDP session LUID."""
        rdp_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        local_time = rdp_time + timedelta(minutes=30)
        rdp_logon_id = "0xabc125"
        state_manager.register_session(
            logon_id=rdp_logon_id,
            username=test_user.username,
            system=test_system.hostname,
            logon_type=10,
            source_ip="10.0.0.55",
            start_time=rdp_time,
            session_kind="rdp",
            session_id=6,
        )

        local_logon_id = activity_gen.generate_logon(
            test_user,
            test_system,
            local_time,
            logon_type=2,
            source_ip="-",
        )

        assert local_logon_id != rdp_logon_id
        local_session = state_manager.get_session(local_logon_id)
        assert local_session is not None
        assert local_session.logon_type == 2
        assert local_session.session_kind == "interactive"
        logon_events = [
            call[0][0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call[0][0].event_type == "logon"
        ]
        assert any(
            event.auth.logon_type == 2 and event.auth.logon_id == local_logon_id
            for event in logon_events
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
        emitted_events = [
            call[0][0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        process_access = [
            event for event in emitted_events if event.event_type == "process_access"
        ][-1]
        event = [
            emitted_event
            for emitted_event in emitted_events
            if emitted_event.event_type == "create_remote_thread"
        ][-1]
        assert process_access.timestamp < event.timestamp
        assert process_access.process_access is not None
        assert process_access.process_access.target_pid == target_pid
        assert process_access.process_access.target_process_object_id == target_obj_id
        assert process_access.identity_plan.actor_id == source_obj_id
        assert event.remote_thread is not None
        assert event.remote_thread.target_pid == target_pid
        assert event.remote_thread.target_process_object_id == target_obj_id
        assert event.remote_thread.thread_object_id == event.identity_plan.object_id
        assert event.identity_plan.actor_id == source_obj_id
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
        from evidenceforge.generation.activity.dll_load_profiles import (
            get_startup_dlls_for_process,
        )

        profile_paths = {entry["path"] for entry in get_startup_dlls_for_process("firefox.exe")}
        emitted_paths = {event.image_load.image_loaded for event in module_events}
        assert emitted_paths <= profile_paths
        assert any(path.lower().endswith("\\ntdll.dll") for path in emitted_paths)
        assert [event.image_load.load_order for event in module_events] == list(
            range(1, len(module_events) + 1)
        )
        assert all(event.image_load.load_phase == "startup" for event in module_events)
        assert all(
            timestamp < event.timestamp < timestamp + timedelta(milliseconds=100)
            for event in module_events
        )
        event = module_events[-1]
        assert event.process.image.endswith("firefox.exe")
        assert event.timestamp > timestamp
        assert event.identity_plan.actor_id
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

    def test_image_load_skips_process_after_owning_session_end(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Ambient module loads should not attach to processes after logoff."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        logon_id = state_manager.create_session(
            username=test_user.username,
            system=test_system.hostname,
            logon_type=2,
            source_ip=test_system.ip,
        )
        pid = state_manager.create_process(
            system=test_system.hostname,
            parent_pid=4,
            image=r"C:\Program Files (x86)\Dropbox\Client\Dropbox.exe",
            command_line=r'"C:\Program Files (x86)\Dropbox\Client\Dropbox.exe" /systemstartup',
            username=test_user.username,
            integrity_level="Medium",
            logon_id=logon_id,
        )
        state_manager.end_session(logon_id, timestamp + timedelta(minutes=30))
        mock_emitters["windows_event_security"].reset_mock()

        activity_gen.generate_image_load(
            test_user,
            test_system,
            timestamp + timedelta(hours=1),
            pid,
            r"C:\Program Files (x86)\Dropbox\Client\Dropbox.exe",
            r"C:\Windows\System32\ws2_32.dll",
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
            r"C:\Windows\System32\taskschd.dll",
        )
        activity_gen.generate_image_load(
            test_user,
            test_system,
            timestamp + timedelta(hours=2),
            pid,
            r"C:\Windows\System32\taskhostw.exe",
            r"C:\Windows\System32\taskschd.dll",
        )

        module_events = [
            call.args[0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call.args[0].event_type == "image_load"
        ]
        assert len(module_events) == 1

    def test_image_load_rejects_known_third_party_module_for_wrong_process(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Configured vendor modules should not attach to an unrelated executable."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        pid = state_manager.create_process(
            system=test_system.hostname,
            parent_pid=4,
            image=r"C:\Windows\System32\svchost.exe",
            command_line="svchost.exe -k netsvcs",
            username="SYSTEM",
            integrity_level="System",
            logon_id="0x3e7",
        )
        mock_emitters["windows_event_security"].reset_mock()

        activity_gen.generate_image_load(
            test_user,
            test_system,
            timestamp + timedelta(seconds=1),
            pid,
            r"C:\Windows\System32\svchost.exe",
            r"C:\Program Files (x86)\Cisco\Cisco AnyConnect Secure Mobility Client\vpnapi.dll",
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
            network=network_plan(
                src_ip=test_system.ip,
                src_port=50123,
                dst_ip="10.0.0.20",
                dst_port=8080,
                protocol="tcp",
                source_visible_start_time=timestamp,
                initiating_pid=pid,
            ),
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

    def test_inbound_windows_service_connection_emits_target_wfp(
        self, activity_gen, test_system, state_manager, mock_emitters
    ):
        """Windows server service traffic should include destination-side 5156 evidence."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        dc_system = System(
            hostname="DC-01",
            ip="10.0.0.10",
            os="Windows Server 2022",
            type="domain_controller",
            roles=["domain_controller"],
        )
        activity_gen._ip_to_system = {test_system.ip: test_system, dc_system.ip: dc_system}

        state_manager.set_current_time(timestamp - timedelta(minutes=10))
        lsass_pid = state_manager.create_process(
            system=dc_system.hostname,
            parent_pid=4,
            image=r"C:\Windows\System32\lsass.exe",
            command_line="lsass.exe",
            username="SYSTEM",
            integrity_level="System",
            logon_id="0x3e7",
        )
        activity_gen._system_pids = {dc_system.hostname: {"lsass": lsass_pid}}
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection(
            src_ip=test_system.ip,
            dst_ip=dc_system.ip,
            time=timestamp,
            dst_port=88,
            proto="tcp",
            service="kerberos",
            duration=0.18,
            orig_bytes=800,
            resp_bytes=1200,
            conn_state="SF",
            emit_dns=False,
        )

        wfp_events = [
            call.args[0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call.args[0].event_type == "wfp_connection"
        ]
        assert len(wfp_events) == 1
        target_wfp = wfp_events[0]
        assert target_wfp.src_host.hostname == dc_system.hostname
        assert target_wfp.network.src_ip == test_system.ip
        assert target_wfp.network.dst_ip == dc_system.ip
        assert target_wfp.network.responding_pid == lsass_pid
        assert target_wfp.process.image.endswith("lsass.exe")
        connection_event = next(
            call.args[0]
            for call in mock_emitters["zeek_conn"].emit.call_args_list
            if call.args[0].event_type == "connection"
        )
        assert target_wfp.lifecycle is not None
        assert target_wfp.lifecycle.parent_group_id is None
        assert target_wfp.lifecycle.group_id == connection_event.network.stable_id

    def test_failed_inbound_windows_probe_does_not_emit_target_wfp(
        self, activity_gen, test_system, state_manager, mock_emitters
    ):
        """Unanswered probes should not become successful inbound 5156 audit rows."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        file_server = System(
            hostname="FILE-SRV-01",
            ip="10.0.0.20",
            os="Windows Server 2022",
            type="server",
            roles=["file_server"],
        )
        activity_gen._ip_to_system = {test_system.ip: test_system, file_server.ip: file_server}
        activity_gen._system_pids = {file_server.hostname: {"system": 4}}
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection(
            src_ip=test_system.ip,
            dst_ip=file_server.ip,
            time=timestamp,
            dst_port=445,
            proto="tcp",
            service="smb",
            duration=0.02,
            orig_bytes=0,
            resp_bytes=0,
            conn_state="S0",
            emit_dns=False,
        )

        wfp_events = [
            call.args[0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call.args[0].event_type == "wfp_connection"
        ]
        assert not wfp_events

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
            network=network_plan(
                src_ip=test_system.ip,
                src_port=50123,
                dst_ip="10.0.0.20",
                dst_port=8080,
                protocol="tcp",
                source_visible_start_time=timestamp,
                initiating_pid=5156,
            ),
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

    def test_ephemeral_allocator_skips_existing_state_tuple(self, activity_gen, state_manager):
        """Source ports should not repeat an already-opened tuple within a day."""
        first_time = datetime(2024, 3, 18, 15, 25, tzinfo=UTC)
        state_manager.set_current_time(first_time)
        state_manager.open_connection(
            src_ip="10.10.4.10",
            src_port=42430,
            dst_ip="10.10.2.10",
            dst_port=389,
            protocol="tcp",
        )

        candidates = iter([42430, 42431])
        with patch.object(
            generator_module,
            "_ephemeral_port",
            side_effect=lambda rng, os_category="windows": next(candidates),
        ):
            allocated = activity_gen._allocate_ephemeral_port(
                "10.10.4.10",
                "10.10.2.10",
                389,
                "tcp",
                first_time + timedelta(hours=2),
                "linux",
            )

        assert allocated == 42431

    def test_ephemeral_allocator_skips_future_state_tuple(self, activity_gen, state_manager):
        """Non-monotonic generation order should still avoid visible tuple reuse."""
        future_time = datetime(2024, 3, 18, 17, 50, tzinfo=UTC)
        state_manager.set_current_time(future_time)
        state_manager.open_connection(
            src_ip="10.10.4.10",
            src_port=45652,
            dst_ip="10.10.2.10",
            dst_port=389,
            protocol="tcp",
        )

        candidates = iter([45652, 45653])
        with patch.object(
            generator_module,
            "_ephemeral_port",
            side_effect=lambda rng, os_category="windows": next(candidates),
        ):
            allocated = activity_gen._allocate_ephemeral_port(
                "10.10.4.10",
                "10.10.2.10",
                389,
                "tcp",
                future_time - timedelta(hours=2),
                "linux",
            )

        assert allocated == 45653

    def test_recent_connection_tuple_cache_prunes_stale_entries(self, activity_gen):
        """Tuple reservations older than the reuse window should be removed by event time."""
        old_time = datetime(2024, 3, 17, 12, 0, tzinfo=UTC)
        current_time = old_time + timedelta(hours=25)
        old_key = ("10.10.4.10", 42430, "10.10.2.10", 389, "tcp")

        activity_gen._remember_connection_tuple(*old_key, time=old_time)
        assert old_key in activity_gen._recent_connection_tuples

        activity_gen._remember_connection_tuple(
            "10.10.4.10",
            42431,
            "10.10.2.10",
            389,
            "tcp",
            current_time,
        )

        assert old_key not in activity_gen._recent_connection_tuples

    def test_recent_connection_tuple_cache_preserves_recent_entries(self, activity_gen):
        """Tuple reservations inside the reuse window should still block reuse."""
        seen_time = datetime(2024, 3, 18, 12, 0, tzinfo=UTC)
        check_time = seen_time + timedelta(hours=23, minutes=59)
        activity_gen._remember_connection_tuple(
            "10.10.4.10",
            42430,
            "10.10.2.10",
            389,
            "tcp",
            seen_time,
        )

        assert activity_gen._connection_tuple_recently_used(
            "10.10.4.10",
            42430,
            "10.10.2.10",
            389,
            "tcp",
            check_time,
        )

    def test_recent_connection_tuple_cache_preserves_future_entries(self, activity_gen):
        """Future tuple reservations should still protect non-monotonic generation order."""
        check_time = datetime(2024, 3, 18, 12, 0, tzinfo=UTC)
        future_time = check_time + timedelta(hours=2)
        activity_gen._remember_connection_tuple(
            "10.10.4.10",
            45652,
            "10.10.2.10",
            389,
            "tcp",
            future_time,
        )

        assert activity_gen._connection_tuple_recently_used(
            "10.10.4.10",
            45652,
            "10.10.2.10",
            389,
            "tcp",
            check_time,
        )

    def test_system_hostname_lookup_cache_refreshes_when_system_map_changes(self, activity_gen):
        """Hostname lookup should stay indexed while tracking engine/test map updates."""
        first = System(
            hostname="APP-01",
            ip="10.0.0.10",
            os="Windows Server 2022",
            type="server",
        )
        second = System(
            hostname="DB-01",
            ip="10.0.0.11",
            os="Windows Server 2022",
            type="server",
        )
        activity_gen._ad_domain = "example.test"
        activity_gen._ip_to_system = {first.ip: first}

        assert activity_gen._system_for_hostname("app-01") is first
        assert activity_gen._system_for_hostname("APP-01.EXAMPLE.TEST.") is first

        activity_gen._ip_to_system[second.ip] = second

        assert activity_gen._system_for_hostname("db-01.example.test") is second

    def test_recent_connection_tuple_cache_ignores_stale_heap_entries(self, activity_gen):
        """Old heap records must not delete newer reservations for the same tuple."""
        first_time = datetime(2024, 3, 18, 12, 0, tzinfo=UTC)
        second_time = first_time + timedelta(hours=1)
        prune_time = first_time + timedelta(hours=25)
        key = ("10.10.4.10", 42430, "10.10.2.10", 389, "tcp")

        activity_gen._remember_connection_tuple(*key, time=first_time)
        activity_gen._remember_connection_tuple(*key, time=second_time)
        activity_gen._prune_recent_connection_tuples(prune_time.timestamp())

        assert activity_gen._recent_connection_tuples[key] == second_time.timestamp()

    def test_recent_connection_tuple_cache_prunes_many_old_entries(self, activity_gen):
        """Large stale tuple sets should shrink to the active event-time window."""
        old_time = datetime(2024, 3, 17, 12, 0, tzinfo=UTC)
        current_time = old_time + timedelta(hours=25)
        for src_port in range(20_000, 22_000):
            activity_gen._remember_connection_tuple(
                "10.10.4.10",
                src_port,
                "10.10.2.10",
                389,
                "tcp",
                old_time,
            )

        activity_gen._remember_connection_tuple(
            "10.10.4.10",
            42430,
            "10.10.2.10",
            389,
            "tcp",
            current_time,
        )

        assert len(activity_gen._recent_connection_tuples) == 1

    def test_recent_connection_tuple_cache_prunes_directly_seeded_entries(self, activity_gen):
        """Compatibility fixture seeds should still follow event-time pruning."""
        old_time = datetime(2024, 3, 17, 12, 0, tzinfo=UTC)
        current_time = old_time + timedelta(hours=25)
        old_key = ("10.10.4.10", 42430, "10.10.2.10", 389, "tcp")
        activity_gen._recent_connection_tuples[old_key] = old_time.timestamp()

        activity_gen._prune_recent_connection_tuples(current_time.timestamp())

        assert activity_gen._recent_connection_tuples == {}

    def test_generate_connection_does_not_infer_dns_for_non_resolver_port_53(
        self, activity_gen, test_system, state_manager, mock_emitters
    ):
        """Port-53 scan traffic to non-resolvers should not become dns.log evidence."""
        from evidenceforge.generation.activity.network import REVERSE_DNS

        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        activity_gen._dns_server_ips = ["10.0.0.53"]
        previous = REVERSE_DNS.get(test_system.ip)
        REVERSE_DNS[test_system.ip] = f"{test_system.hostname}.example.com"

        try:
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
        finally:
            if previous is None:
                REVERSE_DNS.pop(test_system.ip, None)
            else:
                REVERSE_DNS[test_system.ip] = previous

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

    def test_explicit_credential_bundle_anchor_is_stable(self, test_user, test_system):
        """Identical explicit-credential bundle requests should have stable action anchors."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        first = ExplicitCredentialUseRequest(
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
        second = ExplicitCredentialUseRequest(
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

        assert (
            ExplicitCredentialUseActionBundle(Mock(), first).anchor
            == ExplicitCredentialUseActionBundle(Mock(), second).anchor
        )

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
        terminated = next(event for event in emitted if event.event_type == "process_terminate")
        assert explicit.auth.process_pid == process.process.pid
        assert explicit.auth.process_pid > 0
        assert process.timestamp < explicit.timestamp
        assert process.process.command_line.startswith("runas.exe /netonly /user:admin01 ")
        assert r"\\dc01\ADMIN$" in process.process.command_line
        assert terminated.process.pid == process.process.pid
        assert (
            timedelta(seconds=1) < terminated.timestamp - explicit.timestamp < timedelta(seconds=8)
        )

    def test_runas_netonly_owns_strict_new_credentials_session(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """runas /netonly should clone local identity without creating a desktop."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_explicit_credentials(
            user=test_user,
            system=test_system,
            time=timestamp,
            target_username=r"CORP\admin01",
            target_server="dc01.corp.local",
            process_name=r"C:\Windows\System32\runas.exe",
            process_pid=0,
        )

        emitted = [
            call.args[0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        explicit = next(event for event in emitted if event.event_type == "explicit_credentials")
        new_credentials = next(
            event for event in emitted if event.event_type == "logon" and event.auth.logon_type == 9
        )
        session = state_manager.get_session_at(
            new_credentials.auth.logon_id,
            new_credentials.timestamp,
        )

        assert session is not None
        assert session.username == test_user.username
        assert session.session_kind == "new_credentials"
        assert session.session_id == 0
        assert new_credentials.auth.source_ip == "-"
        assert new_credentials.auth.subject_username == test_user.username
        assert new_credentials.auth.subject_logon_id == explicit.auth.subject_logon_id
        assert new_credentials.auth.username == test_user.username
        assert new_credentials.auth.outbound_username == "admin01"
        assert new_credentials.auth.outbound_domain == "CORP"
        assert new_credentials.auth.process_pid != explicit.auth.process_pid
        assert new_credentials.auth.process_name.endswith("svchost.exe")
        assert new_credentials.auth.logon_process == "seclogo"
        assert new_credentials.auth.auth_package == "Negotiate"

        shell_names = {"winlogon.exe", "userinit.exe", "explorer.exe"}
        assert not any(
            event.event_type == "process_create"
            and event.auth is not None
            and event.auth.logon_id == new_credentials.auth.logon_id
            and event.process is not None
            and event.process.image.rsplit("\\", 1)[-1].casefold() in shell_names
            for event in (
                call.args[0] for call in mock_emitters["windows_event_security"].emit.call_args_list
            )
        )
        assert any(
            event.event_type == "logoff"
            and event.auth.logon_id == new_credentials.auth.logon_id
            and event.auth.logon_type == 9
            for event in (
                call.args[0] for call in mock_emitters["windows_event_security"].emit.call_args_list
            )
        )

    def test_direct_type9_logon_rejects_missing_new_credentials_facts(
        self, activity_gen, test_user, test_system
    ):
        """The generic logon API must not invent a NewCredentials caller."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)

        with pytest.raises(StateError, match="explicit_credentials event"):
            activity_gen.generate_logon(
                test_user,
                test_system,
                timestamp,
                logon_type=9,
                source_ip=test_system.ip,
            )

    def test_non_runas_explicit_credentials_do_not_create_type9(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """4648 from other tools must not imply a NewCredentials token clone."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_explicit_credentials(
            user=test_user,
            system=test_system,
            time=timestamp,
            target_username="admin01",
            target_server="dc01.corp.local",
            process_name=r"C:\Windows\System32\mmc.exe",
            process_pid=0,
        )

        emitted = [
            call.args[0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        assert any(event.event_type == "explicit_credentials" for event in emitted)
        assert all(event.event_type != "logon" or event.auth.logon_type != 9 for event in emitted)

    @pytest.mark.parametrize("logon_type", [4, 7, 8, 9])
    def test_non_desktop_logon_siblings_never_lazy_bootstrap_shell(
        self,
        logon_type,
        activity_gen,
        test_user,
        test_system,
        state_manager,
        mock_emitters,
    ):
        """Batch, unlock, and NetworkCleartext sessions cannot acquire Explorer lazily."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        if logon_type == 9:
            state_manager.set_current_time(timestamp)
            logon_id = state_manager.create_session(
                username=test_user.username,
                system=test_system.hostname,
                logon_type=9,
                source_ip="-",
                session_kind="new_credentials",
            )
        else:
            source_ip = "192.0.2.50" if logon_type == 8 else None
            logon_id = activity_gen.generate_logon(
                test_user,
                test_system,
                timestamp,
                logon_type=logon_type,
                source_ip=source_ip,
            )

        activity_gen.generate_process(
            user=test_user,
            system=test_system,
            time=timestamp + timedelta(seconds=10),
            logon_id=logon_id,
            process_name=r"C:\Windows\System32\cmd.exe",
            command_line="cmd.exe /c whoami",
        )

        session = state_manager.get_session(logon_id)
        assert session is not None
        assert session.explorer_pid is None
        shell_names = {"winlogon.exe", "userinit.exe", "explorer.exe"}
        assert not any(
            event.event_type == "process_create"
            and event.auth is not None
            and event.auth.logon_id == logon_id
            and event.process is not None
            and event.process.image.rsplit("\\", 1)[-1].casefold() in shell_names
            for event in (
                call.args[0] for call in mock_emitters["windows_event_security"].emit.call_args_list
            )
        )

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

    def test_generate_explicit_credentials_ignores_newer_expired_subject_session(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """A materialized 4648 caller must bind a session valid at the event time."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        valid_logon_id = state_manager.create_session(
            username=test_user.username,
            system=test_system.hostname,
            logon_type=2,
            source_ip="-",
            start_time=timestamp - timedelta(hours=2),
        )
        expired_logon_id = state_manager.create_session(
            username=test_user.username,
            system=test_system.hostname,
            logon_type=10,
            source_ip="10.0.0.99",
            start_time=timestamp - timedelta(hours=1),
        )
        state_manager.plan_session_end(
            expired_logon_id,
            SessionEndPlan(
                timestamp - timedelta(seconds=30),
                "explicit_storyline",
                "expired-rdp-session",
            ),
        )
        state_manager.set_current_time(timestamp - timedelta(seconds=10))
        explorer_pid = state_manager.create_process(
            system=test_system.hostname,
            parent_pid=4,
            image=r"C:\Windows\explorer.exe",
            command_line=r"C:\Windows\explorer.exe",
            username=test_user.username,
            integrity_level="Medium",
            logon_id=valid_logon_id,
        )

        activity_gen.generate_explicit_credentials(
            user=test_user,
            system=test_system,
            time=timestamp,
            target_username="admin01",
            target_server="dc01.corp.local",
            process_name=r"C:\Windows\System32\msra.exe",
            process_pid=explorer_pid,
        )

        emitted = [
            call.args[0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        process = next(event for event in emitted if event.event_type == "process_create")
        explicit = next(event for event in emitted if event.event_type == "explicit_credentials")
        assert explicit.auth.subject_logon_id == valid_logon_id
        assert process.process.logon_id == valid_logon_id
        assert explicit.auth.process_pid == process.process.pid

    def test_generate_explicit_credentials_never_uses_type3_subject_session(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """A Type 3 network token must not own a desktop explicit-credential caller."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        network_logon_id = state_manager.create_session(
            username=test_user.username,
            system=test_system.hostname,
            logon_type=3,
            source_ip="10.0.0.50",
            start_time=timestamp - timedelta(seconds=1),
            session_kind="network",
        )

        activity_gen.generate_explicit_credentials(
            user=test_user,
            system=test_system,
            time=timestamp,
            target_username="admin01",
            target_server="dc01.corp.local",
            process_name=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            process_pid=0,
        )

        emitted = [
            call.args[0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        logon = next(event for event in emitted if event.event_type == "logon")
        process = next(event for event in emitted if event.event_type == "process_create")
        explicit = next(event for event in emitted if event.event_type == "explicit_credentials")
        session = state_manager.get_session(explicit.auth.subject_logon_id)

        assert explicit.auth.subject_logon_id != network_logon_id
        assert session is not None
        assert session.logon_type == 2
        assert process.auth.logon_id == explicit.auth.subject_logon_id
        assert logon.auth.logon_id == explicit.auth.subject_logon_id
        assert logon.timestamp < process.timestamp < explicit.timestamp

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

    def test_generate_explicit_credentials_defaults_remote_network_endpoint_to_origin(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Remote 4648 records should identify the local machine as the attempt origin."""
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
        assert explicit.auth.source_port == 0

    def test_generate_explicit_credentials_uses_local_origin_for_known_remote_target(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """4648 Network Address identifies the attempt origin, not the target server."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        target_system = System(
            hostname="FILE-SRV-01",
            ip="10.0.0.50",
            os="Windows Server 2022",
            type="server",
        )
        activity_gen._ip_to_system = {
            test_system.ip: test_system,
            target_system.ip: target_system,
        }
        activity_gen._world_model = SimpleNamespace(
            systems_by_hostname={target_system.hostname: target_system}
        )

        activity_gen.generate_explicit_credentials(
            user=test_user,
            system=test_system,
            time=timestamp,
            target_username="admin01",
            target_server=target_system.hostname,
            process_name=r"C:\Windows\System32\mmc.exe",
            process_pid=4242,
        )

        emitted = [
            call[0][0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        explicit = next(event for event in emitted if event.event_type == "explicit_credentials")
        assert explicit.auth.source_ip == test_system.ip
        assert explicit.auth.source_port == 0

    def test_generate_explicit_credentials_ignores_unrelated_source_ip_override(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """A 4648 on a workstation should not borrow an unknown source address."""
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
            source_ip="10.0.0.99",
            source_port=50001,
        )

        emitted = [
            call[0][0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        explicit = next(event for event in emitted if event.event_type == "explicit_credentials")
        assert explicit.auth.source_ip == "-"
        assert explicit.auth.source_port == 0

    def test_generate_explicit_credentials_preserves_modeled_remote_origin(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """A modeled remote-origin 4648 may carry its known source endpoint."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        remote_system = System(
            hostname="ADMIN-01",
            ip="10.0.0.50",
            os="Windows 11",
            type="workstation",
        )
        activity_gen._ip_to_system = {
            test_system.ip: test_system,
            remote_system.ip: remote_system,
        }

        activity_gen.generate_explicit_credentials(
            user=test_user,
            system=test_system,
            time=timestamp,
            target_username="admin01",
            target_server="dc01.corp.local",
            process_name=r"C:\Windows\System32\runas.exe",
            process_pid=4242,
            source_ip=remote_system.ip,
            source_port=50001,
        )

        emitted = [
            call[0][0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        explicit = next(event for event in emitted if event.event_type == "explicit_credentials")
        assert explicit.auth.source_ip == remote_system.ip
        assert explicit.auth.source_port == 50001

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

    def test_generate_explicit_credentials_clamps_after_visible_process_create(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """4648 should not render before the visible create for its caller process."""
        process_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        explicit_time = process_time + timedelta(milliseconds=100)
        state_manager.set_current_time(process_time)
        pid = state_manager.create_process(
            system=test_system.hostname,
            parent_pid=4,
            image=r"C:\Windows\System32\runas.exe",
            command_line="runas.exe /user:admin01 cmd.exe",
            username=test_user.username,
            integrity_level="Medium",
            logon_id="0x12345",
        )
        visible_create_time = explicit_time + timedelta(seconds=1)
        activity_gen._process_source_create_times[(test_system.hostname, pid)] = visible_create_time

        activity_gen.generate_explicit_credentials(
            user=test_user,
            system=test_system,
            time=explicit_time,
            target_username="admin01",
            target_server="dc01.corp.local",
            process_name=r"C:\Windows\System32\runas.exe",
            process_pid=pid,
        )

        emitted = [
            call[0][0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        explicit = next(event for event in emitted if event.event_type == "explicit_credentials")
        assert explicit.auth.process_pid == pid
        assert explicit.timestamp > visible_create_time

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

    def test_generate_process_spaces_bare_shell_child_commands(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Human-entered commands should not spawn immediately after an interactive shell."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        logon_id = "0x44444"
        state_manager.register_session(
            logon_id=logon_id,
            username=test_user.username,
            system=test_system.hostname,
            logon_type=2,
            source_ip=test_system.ip,
            start_time=timestamp - timedelta(minutes=5),
        )
        state_manager.set_current_time(timestamp)
        shell_pid = state_manager.create_process(
            system=test_system.hostname,
            parent_pid=4,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line="powershell.exe",
            username=test_user.username,
            integrity_level="Medium",
            logon_id=logon_id,
        )

        activity_gen.generate_process(
            test_user,
            test_system,
            timestamp + timedelta(seconds=1),
            logon_id,
            r"C:\Users\testuser\.cargo\bin\cargo.exe",
            "cargo.exe build --release",
            parent_pid=shell_pid,
        )

        process_events = [
            call[0][0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call[0][0].event_type == "process_create"
        ]
        child = process_events[-1]
        assert child.process.parent_pid == shell_pid
        assert child.timestamp >= timestamp + timedelta(seconds=8)

    def test_storyline_process_preserves_bare_shell_child_timing(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Explicit storyline timing remains authoritative for shell child commands."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        logon_id = "0x55555"
        state_manager.register_session(
            logon_id=logon_id,
            username=test_user.username,
            system=test_system.hostname,
            logon_type=2,
            source_ip=test_system.ip,
            start_time=timestamp - timedelta(minutes=5),
        )
        state_manager.set_current_time(timestamp)
        shell_pid = state_manager.create_process(
            system=test_system.hostname,
            parent_pid=4,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line="powershell.exe",
            username=test_user.username,
            integrity_level="Medium",
            logon_id=logon_id,
        )

        requested_time = timestamp + timedelta(seconds=1)
        activity_gen.generate_process(
            test_user,
            test_system,
            requested_time,
            logon_id,
            r"C:\Users\testuser\.cargo\bin\cargo.exe",
            "cargo.exe build --release",
            parent_pid=shell_pid,
            from_storyline=True,
        )

        process_events = [
            call[0][0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call[0][0].event_type == "process_create"
        ]
        child = process_events[-1]
        assert child.process.parent_pid == shell_pid
        assert child.timestamp == requested_time

    def test_generate_connection_emits_zeek(self, activity_gen, state_manager, mock_emitters):
        """generate_connection should open connection and dispatch OccurrenceBuilder."""
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

        # Verify Zeek emitter received connection OccurrenceBuilder
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

    def test_generate_connection_drops_recorded_terminated_process_pid(
        self,
        activity_gen,
        state_manager,
        mock_emitters,
        test_user,
        test_system,
    ):
        """Connections should not inherit PID identity from a terminated process instance."""
        start_time = datetime(2024, 1, 15, 9, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(start_time)
        pid = state_manager.create_process(
            system=test_system.hostname,
            parent_pid=0,
            image=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            command_line="chrome.exe --type=renderer",
            username=test_user.username,
            integrity_level="Medium",
            logon_id="0x1234",
        )
        running = state_manager.get_process(test_system.hostname, pid)
        assert running is not None
        activity_gen._terminated_process_keys.add((test_system.hostname, pid, running.start_time))
        activity_gen._ip_to_system = {test_system.ip: test_system}

        activity_gen.generate_connection(
            src_ip=test_system.ip,
            dst_ip="93.184.216.34",
            time=start_time + timedelta(minutes=20),
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=1.0,
            orig_bytes=500,
            resp_bytes=2500,
            pid=pid,
            source_system=test_system,
            process_image=running.image,
        )

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert event.process is None
        assert event.network.initiating_pid == -1

    def test_generate_connection_preserves_public_vip_for_inbound_web_host(
        self,
        state_manager,
    ):
        """Explicit public-hostname traffic should keep the caller's inbound VIP."""
        captured = []

        class _Visibility:
            _vip_to_real_ip = {"203.14.220.10": "10.10.3.10"}

            @staticmethod
            def is_connection_visible(_src_ip, _dst_ip):
                return True

        class _Dispatcher:
            visibility_engine = _Visibility()

            @staticmethod
            def dispatch_builder(event):
                captured.append(event)

            @staticmethod
            def record_filtered_network_observation():
                return None

        generator = ActivityGenerator(state_manager, {}, dispatcher=_Dispatcher())
        web_server = System(
            hostname="WEB-EXT-01",
            ip="10.10.3.10",
            os="Ubuntu 22.04",
            type="server",
            roles=["web_server"],
            public_hostnames=["ehr-portal.meridianhcs.com"],
        )
        generator._ip_to_system = {web_server.ip: web_server}
        timestamp = datetime(2024, 3, 18, 13, 20, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        generator.generate_connection(
            src_ip="185.70.41.45",
            dst_ip="203.14.220.10",
            time=timestamp,
            dst_port=443,
            proto="tcp",
            service="http",
            duration=1.2,
            orig_bytes=18432,
            resp_bytes=912,
            conn_state="SF",
            http=HttpContext(
                method="POST",
                host="ehr-portal.meridianhcs.com",
                uri="/ehr/admin/upload.php",
                user_agent="Mozilla/5.0",
                request_body_len=18432,
                response_body_len=912,
                status_code=200,
                status_msg="OK",
                resp_mime_types=["text/html"],
            ),
            hostname="ehr-portal.meridianhcs.com",
            preserve_dst_ip=True,
        )

        event = captured[-1]
        assert event.network.dst_ip == "203.14.220.10"
        assert event.dst_host is not None
        assert event.dst_host.hostname == "WEB-EXT-01"
        assert "web_server" in event.dst_host.roles
        assert event.protocol.http is not None
        assert event.protocol.http.uri == "/ehr/admin/upload.php"

    def test_generate_connection_with_topology_but_no_sensors_still_dispatches(
        self,
        state_manager,
    ):
        """Topology without sensors should not suppress canonical connection activity."""
        captured = []
        visibility = NetworkVisibilityEngine(
            NetworkConfig(
                segments=[
                    NetworkSegment(
                        name="workstations",
                        cidr="10.10.10.0/24",
                        systems=[],
                        exposure="internal",
                    ),
                    NetworkSegment(
                        name="servers",
                        cidr="10.10.20.0/24",
                        systems=[],
                        exposure="internal",
                    ),
                ],
            ),
            [],
        )

        class _Dispatcher:
            visibility_engine = visibility

            @staticmethod
            def dispatch_builder(event):
                captured.append(event)

            @staticmethod
            def record_filtered_network_observation():
                raise AssertionError("connection generation should not pre-filter by sensors")

        generator = ActivityGenerator(
            state_manager,
            {},
            dispatcher=_Dispatcher(),
            network_visibility=visibility,
        )
        timestamp = datetime(2024, 3, 18, 13, 20, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        uid = generator.generate_connection(
            src_ip="10.10.10.5",
            dst_ip="10.10.20.10",
            time=timestamp,
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=1.0,
            orig_bytes=1200,
            resp_bytes=2400,
        )

        assert uid
        assert captured
        assert captured[-1].network.src_ip == "10.10.10.5"
        assert captured[-1].network.dst_ip == "10.10.20.10"

    def test_generate_connection_finalizes_one_source_visible_interval(
        self,
        state_manager,
    ):
        """Canonical context and state should share the finalized transport interval."""
        captured: list[OccurrenceBuilder] = []

        class _Dispatcher:
            visibility_engine = None

            @staticmethod
            def dispatch_builder(event):
                captured.append(event)

            @staticmethod
            def record_filtered_network_observation():
                return None

        generator = ActivityGenerator(state_manager, {}, dispatcher=_Dispatcher())
        timestamp = datetime(2024, 3, 18, 13, 20, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        generator.generate_connection(
            src_ip="10.10.10.5",
            dst_ip="10.10.20.53",
            time=timestamp,
            dst_port=53,
            proto="udp",
            service="dns",
            duration=0.04,
            orig_bytes=72,
            resp_bytes=128,
            conn_state="SF",
        )

        event = captured[-1]
        connection = state_manager.get_connection(event.network.conn_id)
        assert event.network is not None
        assert event.network.started_at == event.timestamp
        assert event.network.hostname
        assert event.network.outcome == "success"
        assert event.network.phase_times[0] == (
            "transport_start",
            event.timestamp,
        )
        assert event.network.started_at == event.timestamp
        assert event.network.closed_at == event.timestamp + timedelta(seconds=0.04)
        assert connection is not None
        assert connection.start_time == event.network.started_at
        assert connection.close_time == event.network.closed_at

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

        with patch.object(activity_gen, "_should_emit_visible_kerberos_tgt", return_value=True):
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

    def test_generate_connection_can_use_cached_tgt_for_internal_kerberos_flows(
        self, activity_gen, state_manager, mock_emitters
    ):
        """Cached-TGT client flows can emit DC 4769 evidence without a fresh visible 4768."""
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

        with patch.object(activity_gen, "_should_emit_visible_kerberos_tgt", return_value=False):
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
        event_types = [event.event_type for event in events]
        service = next(event for event in events if event.event_type == "kerberos_service")
        connection = next(event for event in events if event.event_type == "connection")

        assert "kerberos_tgt" not in event_types
        assert service.timestamp < connection.timestamp
        assert service.kerberos.target_username == "WEB-EXT-01$@CORP.LOCAL"
        assert service.kerberos.source_port == connection.network.src_port

    def test_newly_created_account_service_ticket_emits_visible_tgt_and_kdc_flow(
        self, activity_gen, state_manager, mock_emitters
    ):
        """First visible TGS for a visible-created account should not use pre-window cache."""
        created_at = datetime(2024, 3, 18, 16, 15, 24, tzinfo=UTC)
        service_time = datetime(2024, 3, 18, 17, 1, 29, 335000, tzinfo=UTC)
        state_manager.set_current_time(created_at)
        actor = User(
            username="aisha.johnson",
            full_name="Aisha Johnson",
            email="aisha.johnson@example.com",
        )
        source = System(
            hostname="WS-AJOHNSON",
            ip="10.10.1.35",
            os="Windows 11",
            type="workstation",
        )
        dc = System(
            hostname="DC-01",
            ip="10.10.1.10",
            os="Windows Server 2022",
            type="domain_controller",
            services=["ad-ds", "kerberos"],
            roles=["domain_controller"],
        )
        activity_gen._ip_to_system = {source.ip: source, dc.ip: dc}

        activity_gen.generate_account_created(
            actor=actor,
            system=dc,
            time=created_at,
            target_username="svc_mhsync",
            target_sid="S-1-5-21-1000-1000-1000-1901",
        )
        mock_emitters["windows_event_security"].emit.reset_mock()
        mock_emitters["zeek_conn"].emit.reset_mock()

        activity_gen.generate_kerberos_service_ticket(
            username="svc_mhsync",
            service_name="cifs/FILE-SRV-01",
            source_ip=source.ip,
            dc_hostname=dc.hostname,
            time=service_time,
            source_port=55466,
        )

        win_events = [
            call.args[0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        kerberos_events = [
            event
            for event in win_events
            if event.event_type in {"kerberos_tgt", "kerberos_service"}
        ]
        assert [event.event_type for event in kerberos_events] == [
            "kerberos_tgt",
            "kerberos_service",
        ]
        tgt, service = kerberos_events
        assert tgt.timestamp < service.timestamp
        assert tgt.kerberos.target_username == "svc_mhsync"
        assert service.kerberos.target_username == "svc_mhsync"
        assert tgt.kerberos.source_port == 55466
        assert service.kerberos.source_port == 55466

        conn_events = [
            call.args[0]
            for call in mock_emitters["zeek_conn"].emit.call_args_list
            if call.args[0].event_type == "connection"
        ]
        assert len(conn_events) == 1
        connection = conn_events[0]
        assert connection.timestamp < service.timestamp
        assert connection.network.src_ip == source.ip
        assert connection.network.dst_ip == dc.ip
        assert connection.network.src_port == 55466
        assert connection.network.dst_port == 88
        assert connection.network.service == "kerberos"

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
        assert event.protocol.http.trans_depth == 1
        assert http.trans_depth == 4

    def test_http_request_body_always_creates_originator_file_transfer(
        self, activity_gen, state_manager, mock_emitters
    ):
        """Anonymous background POST bodies receive canonical originator file analysis."""

        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        activity_gen.generate_connection(
            "10.0.0.1",
            "93.184.216.34",
            timestamp,
            dst_port=80,
            service="http",
            duration=0.5,
            http=HttpContext(
                method="POST",
                host="forms.example.test",
                uri="/submit",
                user_agent="Mozilla/5.0",
                request_body_len=321,
                response_body_len=0,
                status_code=500,
                status_msg="Internal Server Error",
            ),
        )

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        request_transfer = next(ft for ft in event.protocol.file_transfers if ft.is_orig)
        assert request_transfer.total_bytes == 321
        assert request_transfer.mime_type == "application/x-www-form-urlencoded"
        assert request_transfer.filename == ""
        assert event.protocol.http.orig_fuids == (request_transfer.fuid,)
        assert event.network.orig_bytes > 321

    def test_opaque_https_request_body_has_no_zeek_file_transfer(
        self, activity_gen, state_manager, mock_emitters
    ):
        """An undecrypted direct HTTPS request remains opaque to Zeek file analysis."""

        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        activity_gen.generate_connection(
            "10.0.0.1",
            "93.184.216.34",
            timestamp,
            dst_port=443,
            service="ssl",
            duration=0.5,
            http=HttpContext(
                method="PUT",
                host="api.example.test",
                uri="/api/v1/telemetry",
                request_body_len=8192,
                response_body_len=0,
            ),
        )

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert not any(ft.is_orig for ft in event.protocol.file_transfers)
        assert event.protocol.http.orig_fuids == ()

    def test_http_request_and_response_files_coexist(
        self, activity_gen, state_manager, mock_emitters
    ):
        """One HTTP transaction can carry independently analyzed files both ways."""

        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        request_body_len = 42 * 1024 * 1024
        entity = HttpRequestEntityContext(
            size=request_body_len,
            mime_type="application/vnd.rar",
            content_identity=f"upload:exfildata.rar:{request_body_len}",
            local_source_path="/tmp/exfildata.rar",
            local_source_filename="exfildata.rar",
        )
        activity_gen.generate_connection(
            "10.0.0.1",
            "93.184.216.34",
            timestamp,
            dst_port=80,
            service="http",
            duration=1.0,
            http=HttpContext(
                method="POST",
                host="some.site",
                uri="/uploads/accept-upload",
                request_body_len=request_body_len,
                request_content_type=entity.mime_type,
                request_entity=entity,
                response_body_len=2_000_000,
                resp_mime_types=("application/zip",),
            ),
        )

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert {ft.is_orig for ft in event.protocol.file_transfers} == {True, False}
        assert len(event.protocol.http.orig_fuids) == 1
        assert len(event.protocol.http.resp_fuids) == 1
        request_transfer = next(ft for ft in event.protocol.file_transfers if ft.is_orig)
        assert request_transfer.total_bytes == 44_040_192
        assert request_transfer.mime_type == "application/vnd.rar"
        assert request_transfer.filename == ""
        assert event.network.orig_bytes > request_body_len
        assert request_transfer.duration <= event.network.duration

    @pytest.mark.parametrize("response_body_len", [1, 100, 101, 4096, 2_000_000])
    def test_every_nonempty_plaintext_http_response_creates_responder_file(
        self,
        activity_gen,
        state_manager,
        mock_emitters,
        response_body_len,
    ):
        """Response file analysis has no size threshold or sampling gate."""

        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        activity_gen.generate_connection(
            "10.0.0.1",
            "93.184.216.34",
            timestamp,
            dst_port=80,
            service="http",
            duration=0.5,
            conn_state="SF",
            http=HttpContext(
                method="GET",
                host="api.example.test",
                uri="/api/v1/result",
                response_body_len=response_body_len,
                status_code=200,
                status_msg="OK",
                resp_mime_types=("application/json",),
            ),
        )

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        responses = [ft for ft in event.protocol.file_transfers if not ft.is_orig]
        assert len(responses) == 1
        assert responses[0].total_bytes == response_body_len
        assert responses[0].mime_type == "application/json"
        assert responses[0].filename == ""
        assert event.protocol.http.resp_fuids == (responses[0].fuid,)

    @pytest.mark.parametrize("status_code", [200, 301, 302, 401, 403, 404, 500, 502, 503])
    def test_body_bearing_http_statuses_create_responder_files(
        self,
        activity_gen,
        state_manager,
        mock_emitters,
        status_code,
    ):
        """Redirect and error provenance does not suppress a transmitted entity."""

        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        activity_gen.generate_connection(
            "10.0.0.1",
            "93.184.216.34",
            timestamp,
            dst_port=80,
            service="http",
            conn_state="SF",
            http=HttpContext(
                method="GET",
                host="portal.example.test",
                uri="/result",
                response_body_len=321,
                status_code=status_code,
                status_msg="",
            ),
        )

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        response = next(ft for ft in event.protocol.file_transfers if not ft.is_orig)
        assert response.total_bytes == 321
        assert response.mime_type == (
            "application/octet-stream" if status_code == 200 else "text/html"
        )
        assert event.protocol.http.resp_filenames == ()

    @pytest.mark.parametrize(
        ("method", "status_code"),
        [
            ("HEAD", 200),
            ("GET", 100),
            ("GET", 199),
            ("GET", 204),
            ("GET", 205),
            ("GET", 304),
            ("CONNECT", 200),
        ],
    )
    def test_body_prohibited_http_responses_are_normalized_fileless(
        self,
        activity_gen,
        state_manager,
        mock_emitters,
        method,
        status_code,
    ):
        """HTTP semantics override authored bytes for responses prohibited from carrying bodies."""

        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        activity_gen.generate_connection(
            "10.0.0.1",
            "93.184.216.34",
            timestamp,
            dst_port=80,
            service="http",
            conn_state="SF",
            http=HttpContext(
                method=method,
                host="portal.example.test",
                uri="/result",
                response_body_len=321,
                status_code=status_code,
                status_msg="",
                resp_mime_types=("text/html",),
            ),
        )

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert event.protocol.http.response_body_len == 0
        assert event.protocol.http.resp_mime_types == ()
        assert not any(not ft.is_orig for ft in event.protocol.file_transfers)

    def test_failed_http_transport_does_not_create_response_file(
        self, activity_gen, state_manager, mock_emitters
    ):
        """An uncompleted transport cannot expose an authored response body."""

        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)
        activity_gen.generate_connection(
            "10.0.0.1",
            "93.184.216.34",
            timestamp,
            dst_port=80,
            service="http",
            conn_state="S0",
            http=HttpContext(
                method="GET",
                host="portal.example.test",
                uri="/result",
                response_body_len=321,
                status_code=200,
                resp_mime_types=("text/html",),
            ),
        )

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        assert not any(not ft.is_orig for ft in event.protocol.file_transfers)

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
            lambda event: event.event_type == "connection" and event.protocol.http is not None
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
        assert first_event.protocol.http.trans_depth == 1
        assert second_event.network.zeek_uid == first_uid
        assert second_event.network.src_port == first_event.network.src_port
        assert second_event.network.application_layer_only is True
        assert second_event.protocol.http.trans_depth == 2
        first_response = next(ft for ft in first_event.protocol.file_transfers if not ft.is_orig)
        second_response = next(ft for ft in second_event.protocol.file_transfers if not ft.is_orig)
        assert first_response.fuid != second_response.fuid
        assert first_event.protocol.http.resp_fuids == (first_response.fuid,)
        assert second_event.protocol.http.resp_fuids == (second_response.fuid,)

    def test_generate_connection_orders_reused_http_transactions_by_depth(self, state_manager):
        """Persistent request timestamps should advance with assigned transaction depth."""

        class CollectorEmitter:
            def __init__(self):
                self.events = []

            def can_handle(self, event):
                return event.event_type == "connection" and event.protocol.http is not None

            def emit(self, event):
                self.events.append(event)

        http_emitter = CollectorEmitter()
        emitters = {"zeek_http": http_emitter}
        dispatcher = EventDispatcher(state_manager=state_manager, emitters=emitters)
        generator = ActivityGenerator(state_manager, emitters, dispatcher=dispatcher)
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        def emit_request(offset_ms, trans_depth, uri):
            return generator.generate_connection(
                "10.0.0.1",
                "93.184.216.34",
                timestamp + timedelta(milliseconds=offset_ms),
                dst_port=80,
                proto="tcp",
                service="http",
                duration=4.0 if trans_depth == 1 else 0.2,
                orig_bytes=1_000,
                resp_bytes=10_000,
                conn_state="SF",
                http=HttpContext(
                    method="GET",
                    host="portal.example.com",
                    uri=uri,
                    user_agent="Mozilla/5.0",
                    response_body_len=1_000,
                    flow_response_body_len=10_000 if trans_depth == 1 else None,
                    trans_depth=trans_depth,
                ),
                emit_dns=False,
            )

        first_uid = emit_request(0, 1, "/")
        second_uid = emit_request(700, 2, "/asset-a.js")
        third_uid = emit_request(500, 3, "/asset-b.js")

        assert first_uid == second_uid == third_uid
        assert [event.protocol.http.trans_depth for event in http_emitter.events] == [1, 2, 3]
        request_times = [
            event.protocol.http.canonical_request_time for event in http_emitter.events
        ]
        assert request_times == sorted(request_times)
        assert request_times[2] > request_times[1]
        assert all(
            request_time > event.timestamp
            for request_time, event in zip(request_times, http_emitter.events, strict=True)
            if not event.network.application_layer_only
        )

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
        assert event.network.resp_bytes > event.protocol.http.response_body_len

    def test_generate_connection_derives_tls_bytes_from_http_flow_context(
        self, activity_gen, state_manager, mock_emitters
    ):
        """TLS transport accounting should honor flow-level HTTP body budgets."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection(
            "10.0.0.1",
            "93.184.216.34",
            timestamp,
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=4.0,
            orig_bytes=400,
            resp_bytes=4_000,
            conn_state="SF",
            http=HttpContext(
                method="GET",
                host="updates.example.com",
                uri="/bundle",
                user_agent="Mozilla/5.0",
                response_body_len=4096,
                flow_response_body_len=512_000,
                flow_transaction_count=3,
                trans_depth=1,
            ),
            emit_dns=False,
        )

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]

        assert event.network.conn_state == "SF"
        assert event.network.service == "ssl"
        assert event.network.resp_bytes >= event.protocol.http.flow_response_body_len
        assert event.network.resp_pkts >= 300
        assert event.network.resp_ip_bytes >= event.network.resp_bytes

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
            lambda event: event.event_type == "connection" and event.protocol.http is not None
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
        assert http_emitter.events[1].protocol.http.trans_depth == 1

    def test_generate_connection_with_bytes(self, activity_gen, state_manager, mock_emitters):
        """generate_connection should include byte counts in NetworkTransactionPlan."""
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
        assert net.resp_bytes != event.protocol.http.response_body_len
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
        cert_payload = sum(certificate_file_size(cert) for cert in event.protocol.x509_chain)
        assert cert_payload > 0
        assert event.network.resp_bytes >= cert_payload
        max_cert_delay_ms = max(
            certificate_analyzer_delay_ms(
                zeek_uid=event.network.zeek_uid,
                event_timestamp=event.timestamp,
                fuid=cert.fuid,
                position=idx,
            )
            for idx, cert in enumerate(event.protocol.x509_chain)
        )
        assert event.network.duration >= (max_cert_delay_ms / 1000.0)
        assert event.network.duration >= 1.05 + (0.075 * len(event.protocol.x509_chain))

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

    def test_tcp_handshake_only_history_does_not_claim_payload_bytes(
        self, activity_gen, state_manager, mock_emitters
    ):
        """TCP conn.log byte counts must agree with source-native history markers."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection(
            "10.0.0.1",
            "93.184.216.34",
            timestamp,
            duration=2.5,
            orig_bytes=1000,
            resp_bytes=2000,
            conn_state="S1",
        )

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        net = event.network
        assert net.history == "Sh"
        assert "D" not in net.history
        assert "d" not in net.history
        assert net.orig_bytes == 0
        assert net.resp_bytes == 0
        assert net.orig_ip_bytes >= net.orig_pkts * 40
        assert net.resp_ip_bytes >= net.resp_pkts * 40

    def test_tcp_one_sided_history_zeroes_unmarked_payload_side(
        self, activity_gen, state_manager, mock_emitters
    ):
        """One-sided TCP history may only claim payload bytes for the marked side."""
        timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        state_manager.set_current_time(timestamp)

        activity_gen.generate_connection(
            "10.0.0.1",
            "93.184.216.34",
            timestamp,
            duration=2.5,
            orig_bytes=1000,
            resp_bytes=2000,
            conn_state="RSTO",
        )

        event = mock_emitters["zeek_conn"].emit.call_args[0][0]
        net = event.network
        assert net.history == "ShADaR"
        assert "D" in net.history
        assert "d" not in net.history
        assert net.orig_bytes > 0
        assert net.resp_bytes == 0

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

        # Logon (and possibly logoff for Type 3) dispatched via OccurrenceBuilder
        emitter = mock_emitters["windows_event_security"]
        assert emitter.emit.called
        first_event = emitter.emit.call_args_list[0][0][0]
        assert first_event.event_type in ("logon", "failed_logon")

    def test_execute_baseline_activity_logon_reuses_active_workstation_session(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Baseline logon activity should not mint same-user Type 2 bursts."""
        session_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        activity_time = session_time + timedelta(seconds=20)
        state_manager.set_current_time(session_time)
        logon_id = activity_gen.generate_logon(
            test_user,
            test_system,
            session_time,
            logon_type=2,
        )
        mock_emitters["windows_event_security"].reset_mock()

        class FixedInteractiveRng(random.Random):
            def random(self) -> float:
                return 0.5

            def choices(self, population, weights=None, *, cum_weights=None, k=1):
                return [2]

        with patch.object(generator_module, "_get_rng", return_value=FixedInteractiveRng()):
            activity_gen.execute_baseline_activity(
                test_user,
                test_system,
                activity_time,
                "logon",
            )

        sessions = state_manager.get_sessions_for_user(test_user.username)
        assert [session.logon_id for session in sessions] == [logon_id]
        assert sessions[0].last_activity_time == activity_time
        emitted_types = [
            call.args[0].event_type
            for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        assert "logon" not in emitted_types

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

    def test_execute_baseline_activity_process_shifts_to_near_future_session(
        self, activity_gen, test_user, test_system, state_manager, mock_emitters
    ):
        """Near-future workstation sessions should absorb out-of-order foreground work."""
        process_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        future_logon_time = datetime(2024, 1, 15, 10, 4, 0, tzinfo=UTC)
        state_manager.set_current_time(future_logon_time)
        logon_id = activity_gen.generate_logon(test_user, test_system, future_logon_time)
        mock_emitters["windows_event_security"].reset_mock()

        activity_gen.execute_baseline_activity(test_user, test_system, process_time, "process_code")

        sessions = state_manager.get_sessions_for_user(test_user.username)
        assert [session.logon_id for session in sessions] == [logon_id]
        emitter = mock_emitters["windows_event_security"]
        emitted_events = [c[0][0] for c in emitter.emit.call_args_list]
        event_types = [event.event_type for event in emitted_events]
        assert "logon" not in event_types
        process_events = [
            event
            for event in emitted_events
            if event.event_type == "process_create"
            and event.process is not None
            and not event.process.image.endswith("explorer.exe")
        ]
        assert len(process_events) == 1
        assert process_events[0].timestamp > future_logon_time
        assert process_events[0].process.logon_id == logon_id

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
            "/usr/sbin/sshd -D",
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
        assert terminate_events[-1].timestamp <= create_event.timestamp + timedelta(seconds=2)

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
            "/usr/sbin/sshd -D",
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

    def test_linux_catalog_compound_command_uses_source_native_child_argv(
        self,
        activity_gen,
        state_manager,
        mock_emitters,
        monkeypatch,
    ):
        """Linux catalog shell compounds should not render as one non-shell process argv."""
        from evidenceforge.generation.activity import application_catalog

        process_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        linux = System(
            hostname="LNX-01",
            ip="10.0.0.2",
            os="Ubuntu 22.04",
            type="workstation",
            assigned_user="alice",
        )
        user = User(
            username="alice",
            full_name="Alice Example",
            email="alice@example.com",
            persona="developer",
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
        bash_pid = state_manager.create_process(
            linux.hostname,
            systemd_pid,
            "/bin/bash",
            "-bash",
            user.username,
            "Medium",
        )
        activity_gen._system_pids = {linux.hostname: {"systemd": systemd_pid, "bash": bash_pid}}

        monkeypatch.setattr(
            application_catalog,
            "pick_app_and_command",
            lambda *args, **kwargs: ("/usr/bin/make", "make clean && make all"),
        )

        activity_gen.execute_baseline_activity(user, linux, process_time, "process_build")

        events = [
            call.args[0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        make_commands = [
            event.process.command_line
            for event in events
            if event.event_type == "process_create"
            and event.process is not None
            and event.process.image == "/usr/bin/make"
        ]
        bash_events = [
            call.args[0]
            for call in mock_emitters["bash_history"].emit.call_args_list
            if call.args[0].event_type == "bash_command"
        ]

        assert make_commands[:2] == ["make clean", "make all"]
        assert all("&&" not in command for command in make_commands)
        assert bash_events[-1].shell.command == "make clean && make all"

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
            "/usr/sbin/sshd -D",
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

    def test_generate_bash_command_emits_ordinary_external_process(
        self, activity_gen, test_user, state_manager, mock_emitters
    ):
        """Ordinary executable shell commands should not be arbitrary history-only rows."""
        command_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        linux = System(
            hostname="WS-LNGUYEN-01",
            ip="10.0.0.2",
            os="Ubuntu 22.04",
            type="workstation",
            assigned_user=test_user.username,
        )
        logon_id = "0xabc124"
        state_manager.set_current_time(command_time - timedelta(seconds=30))
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
            logon_id,
        )
        session = state_manager.register_session(
            logon_id=logon_id,
            username=test_user.username,
            system=linux.hostname,
            logon_type=2,
            source_ip="-",
            start_time=command_time - timedelta(seconds=20),
            session_kind="interactive",
        )
        session.session_shell_pid = bash_pid
        activity_gen._system_pids = {linux.hostname: {"systemd": systemd_pid, "bash": bash_pid}}

        activity_gen.generate_bash_command(test_user, linux, command_time, "git status")

        events = [
            call.args[0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        process_events = [
            event
            for event in events
            if event.event_type == "process_create"
            and event.process is not None
            and event.process.command_line == "git status"
        ]
        assert process_events
        assert process_events[-1].process.image == "/usr/bin/git"
        assert process_events[-1].process.parent_pid == bash_pid

    def test_workstation_bash_command_bootstraps_local_session_process_telemetry(
        self, activity_gen, test_user, state_manager, mock_emitters
    ):
        """Assigned Linux workstation shell commands should not render as history-only rows."""
        command_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        linux = System(
            hostname="WS-LNGUYEN-01",
            ip="10.0.0.2",
            os="Ubuntu 22.04",
            type="workstation",
            assigned_user=test_user.username,
        )
        activity_gen._scenario_start_time = command_time - timedelta(minutes=30)
        state_manager.set_current_time(command_time - timedelta(minutes=30))
        systemd_pid = state_manager.create_process(
            linux.hostname,
            0,
            "/usr/lib/systemd/systemd",
            "/usr/lib/systemd/systemd --system",
            "root",
            "System",
        )
        activity_gen._system_pids = {linux.hostname: {"systemd": systemd_pid}}

        activity_gen.generate_bash_command(test_user, linux, command_time, "git status")

        sessions = [
            session
            for session in state_manager.get_sessions_for_user(test_user.username)
            if session.system == linux.hostname and session.logon_type == 2
        ]
        assert sessions
        assert sessions[-1].session_kind == "interactive"
        assert sessions[-1].start_time < command_time

        events = [
            call.args[0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        shell_events = [
            event
            for event in events
            if event.event_type == "process_create"
            and event.process is not None
            and event.process.image == "/bin/bash"
        ]
        process_events = [
            event
            for event in events
            if event.event_type == "process_create"
            and event.process is not None
            and event.process.command_line == "git status"
        ]
        assert shell_events
        assert process_events
        assert process_events[-1].process.image == "/usr/bin/git"
        assert process_events[-1].process.parent_pid == shell_events[-1].process.pid

    def test_dropped_workstation_bash_command_does_not_bootstrap_local_session(
        self, activity_gen, test_user, state_manager, mock_emitters
    ):
        """Rejected Linux workstation shell commands should not leave orphan logon evidence."""
        scenario_end = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        linux = System(
            hostname="WS-LNGUYEN-01",
            ip="10.0.0.2",
            os="Ubuntu 22.04",
            type="workstation",
            assigned_user=test_user.username,
        )
        activity_gen._scenario_start_time = scenario_end - timedelta(minutes=30)
        activity_gen._scenario_end_time = scenario_end
        state_manager.set_current_time(scenario_end - timedelta(minutes=30))
        systemd_pid = state_manager.create_process(
            linux.hostname,
            0,
            "/usr/lib/systemd/systemd",
            "/usr/lib/systemd/systemd --system",
            "root",
            "System",
        )
        activity_gen._system_pids = {linux.hostname: {"systemd": systemd_pid}}

        scheduled = activity_gen.generate_bash_command(test_user, linux, scenario_end, "git status")

        assert scheduled is None
        assert [
            session
            for session in state_manager.get_sessions_for_user(test_user.username)
            if session.system == linux.hostname
        ] == []
        emitted_events = [
            call.args[0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        assert not [
            event
            for event in emitted_events
            if event.event_type in {"logon", "process_create", "bash_command"}
        ]

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
            "/usr/sbin/sshd -D",
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

    def test_generate_bash_command_waits_for_new_local_shell_readiness(
        self, activity_gen, test_user, state_manager, mock_emitters
    ):
        """First foreground child should not appear simultaneous with a new local shell."""
        command_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        linux = System(
            hostname="WS-LNGUYEN-01",
            ip="10.0.2.60",
            os="Ubuntu 22.04",
            type="workstation",
            assigned_user=test_user.username,
        )
        logon_id = "0xabc457"
        state_manager.set_current_time(command_time - timedelta(seconds=60))
        systemd_pid = state_manager.create_process(
            linux.hostname,
            0,
            "/usr/lib/systemd/systemd",
            "/usr/lib/systemd/systemd --system",
            "root",
            "System",
        )
        state_manager.register_session(
            logon_id=logon_id,
            username=test_user.username,
            system=linux.hostname,
            logon_type=2,
            source_ip="-",
            start_time=command_time - timedelta(seconds=30),
            session_kind="interactive",
        )
        activity_gen._system_pids = {linux.hostname: {"systemd": systemd_pid}}

        activity_gen.generate_bash_command(
            test_user,
            linux,
            command_time,
            "python3 -m pip install -r requirements.txt",
        )

        events = [
            call.args[0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        bash_create = next(
            event
            for event in events
            if event.event_type == "process_create"
            and event.process is not None
            and event.process.image == "/bin/bash"
        )
        python_create = next(
            event
            for event in events
            if event.event_type == "process_create"
            and event.process is not None
            and event.process.image == "/usr/bin/python3"
        )

        assert python_create.process.parent_pid == bash_create.process.pid
        assert python_create.timestamp - bash_create.timestamp >= timedelta(milliseconds=1800)

    def test_linux_foreground_completion_updates_user_shell_without_parent_state(
        self, activity_gen, test_user
    ):
        """Storyline shell chains should serialize even when parent shell state is sparse."""
        command_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        linux = System(
            hostname="DB-PROD-01",
            ip="10.0.2.50",
            os="Ubuntu 22.04",
            type="server",
            assigned_user=test_user.username,
        )
        logon_id = "0xabc456"
        parent_pid = 707122
        gzip_done = command_time + timedelta(seconds=42)

        activity_gen.remember_linux_foreground_process_completion(
            system=linux,
            username=test_user.username,
            logon_id=logon_id,
            parent_pid=parent_pid,
            termination_time=gzip_done,
            process_name="/usr/bin/gzip",
            command_line="gzip -9 /tmp/rpt_0318.sql",
        )
        reserved = activity_gen.reserve_linux_foreground_process_start(
            system=linux,
            username=test_user.username,
            logon_id=logon_id,
            parent_pid=parent_pid,
            requested_time=command_time + timedelta(seconds=1),
            process_name="/usr/bin/scp",
            command_line="scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/rpt_0318.sql.gz",
        )
        scheduled_history = activity_gen._schedule_bash_history_time(
            test_user,
            linux,
            command_time + timedelta(seconds=1),
            "scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/rpt_0318.sql.gz",
        )

        assert reserved > gzip_done
        assert scheduled_history > gzip_done

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
            "/usr/sbin/sshd -D",
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

    def test_generate_bash_command_moves_history_with_busy_foreground_shell(
        self, activity_gen, test_user, state_manager, mock_emitters
    ):
        """Bash history and process telemetry should share the foreground-shell slot."""
        command_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        linux = System(
            hostname="WS-LNGUYEN-01",
            ip="10.0.2.60",
            os="Ubuntu 22.04",
            type="workstation",
            assigned_user=test_user.username,
        )
        logon_id = "0xabc458"
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
            "/usr/sbin/sshd -D",
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
        blocked_until = command_time + timedelta(minutes=30)
        activity_gen._foreground_shell_next_time[
            (linux.hostname, test_user.username, logon_id, bash_pid)
        ] = blocked_until

        scheduled = activity_gen.generate_bash_command(
            test_user,
            linux,
            command_time,
            "hostname -f",
        )

        events = [
            call.args[0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        bash_event = next(
            event
            for event in events
            if event.event_type == "bash_command"
            and event.shell is not None
            and event.shell.command == "hostname -f"
        )
        hostname_create = next(
            event
            for event in events
            if event.event_type == "process_create"
            and event.process is not None
            and event.process.image == "/usr/bin/hostname"
        )

        assert scheduled == bash_event.timestamp
        assert bash_event.timestamp > blocked_until
        assert hostname_create.process.parent_pid == bash_pid
        assert hostname_create.process.concurrency_group_id.startswith("bash-history:")
        assert (
            timedelta(0) < hostname_create.timestamp - bash_event.timestamp < timedelta(seconds=1)
        )

    def test_foreground_termination_uses_source_visible_release_time(
        self, activity_gen, test_user, state_manager, monkeypatch
    ):
        """Foreground shell availability should follow rendered endpoint completion."""
        command_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        linux = System(
            hostname="WS-LNGUYEN-01",
            ip="10.0.2.60",
            os="Ubuntu 22.04",
            type="workstation",
            assigned_user=test_user.username,
        )
        logon_id = "0xabc459"
        state_manager.set_current_time(command_time)
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
            logon_id,
        )
        child_pid = state_manager.create_process(
            linux.hostname,
            bash_pid,
            "/usr/bin/python3",
            "python3 -m pytest",
            test_user.username,
            "Medium",
            logon_id,
        )
        source_visible_done = command_time + timedelta(minutes=7)

        def source_terminate_time(hostname: str, pid: int) -> datetime | None:
            if hostname == linux.hostname and pid == child_pid:
                return source_visible_done
            return None

        monkeypatch.setattr(
            activity_gen,
            "process_source_terminate_time",
            source_terminate_time,
        )

        release_time = activity_gen._generate_bounded_foreground_process_termination(
            user=test_user,
            system=linux,
            start_time=command_time,
            pid=child_pid,
            process_name="/usr/bin/python3",
            logon_id=logon_id,
            lifetime=(1.0, 1.0),
            rng=random.Random(7),
        )
        activity_gen._remember_foreground_shell_available(
            system=linux,
            username=test_user.username,
            logon_id=logon_id,
            parent_pid=bash_pid,
            termination_time=release_time,
            seed_text="python3 -m pytest",
        )
        reserved = activity_gen.reserve_linux_foreground_process_start(
            system=linux,
            username=test_user.username,
            logon_id=logon_id,
            parent_pid=bash_pid,
            requested_time=command_time + timedelta(seconds=2),
            process_name="/usr/bin/hostname",
            command_line="hostname -f",
        )

        assert release_time == source_visible_done
        assert reserved > source_visible_done

    def test_foreground_termination_respects_authoritative_session_deadline(
        self, activity_gen, test_user, state_manager, monkeypatch
    ):
        """A bounded command cannot be scheduled beyond an explicit session close."""
        start_time = datetime(2024, 3, 18, 15, 0, 32, tzinfo=UTC)
        deadline = start_time + timedelta(seconds=30)
        linux = System(
            hostname="APP-INT-01",
            ip="10.0.2.20",
            os="Ubuntu 22.04",
            type="server",
        )
        state_manager.set_current_time(start_time)
        logon_id = state_manager.create_session(
            username=test_user.username,
            system=linux.hostname,
            logon_type=10,
            source_ip="10.0.2.10",
            session_kind="ssh",
            start_time=start_time - timedelta(minutes=20),
        )
        plan = SessionEndPlan(deadline, "explicit_storyline", "evt-ssh-close")
        state_manager.plan_session_end(logon_id, plan)
        generated: list[dict[str, object]] = []
        monkeypatch.setattr(
            activity_gen,
            "generate_process_termination",
            lambda **kwargs: generated.append(kwargs),
        )
        monkeypatch.setattr(activity_gen, "process_source_terminate_time", lambda *_args: None)

        release_time = activity_gen._generate_bounded_foreground_process_termination(
            user=test_user,
            system=linux,
            start_time=start_time,
            pid=1099641,
            process_name="/usr/bin/git",
            logon_id=logon_id,
            lifetime=(90.0, 90.0),
            rng=random.Random(7),
        )

        assert release_time == deadline - timedelta(seconds=2)
        assert generated[0]["time"] == release_time
        assert generated[0]["session_end_plan"] == plan

    def test_foreground_termination_respects_ssh_transport_close(
        self, activity_gen, test_user, state_manager, monkeypatch
    ):
        """A sampled command lifetime is bounded even without an explicit end plan."""
        start_time = datetime(2024, 3, 18, 15, 0, 32, tzinfo=UTC)
        transport_close = start_time + timedelta(seconds=30)
        linux = System(
            hostname="APP-INT-01",
            ip="10.0.2.20",
            os="Ubuntu 22.04",
            type="server",
        )
        state_manager.set_current_time(start_time)
        logon_id = state_manager.create_session(
            username=test_user.username,
            system=linux.hostname,
            logon_type=10,
            source_ip="10.0.2.10",
            session_kind="ssh",
            start_time=start_time - timedelta(minutes=20),
        )
        state_manager.update_session_metadata(logon_id, network_close_time=transport_close)
        generated: list[dict[str, object]] = []
        monkeypatch.setattr(
            activity_gen,
            "generate_process_termination",
            lambda **kwargs: generated.append(kwargs),
        )
        monkeypatch.setattr(activity_gen, "process_source_terminate_time", lambda *_args: None)

        release_time = activity_gen._generate_bounded_foreground_process_termination(
            user=test_user,
            system=linux,
            start_time=start_time,
            pid=1099641,
            process_name="/usr/bin/git",
            logon_id=logon_id,
            lifetime=(90.0, 90.0),
            rng=random.Random(7),
        )

        assert release_time == transport_close - timedelta(seconds=2)
        assert generated[0]["session_end_plan"] is None

    def test_linux_session_shell_reuses_user_manager_when_rebuilt(
        self, activity_gen, test_user, state_manager
    ):
        """Rebuilding a local Linux shell should not duplicate `systemd --user`."""
        session_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        linux = System(
            hostname="WS-LNGUYEN-01",
            ip="10.0.2.60",
            os="Ubuntu 22.04",
            type="workstation",
            assigned_user=test_user.username,
        )
        state_manager.set_current_time(session_time)
        systemd_pid = state_manager.create_process(
            linux.hostname,
            0,
            "/usr/lib/systemd/systemd",
            "/usr/lib/systemd/systemd --system",
            "root",
            "System",
        )
        logon_id = state_manager.create_session(
            username=test_user.username,
            system=linux.hostname,
            logon_type=2,
            source_ip="-",
            session_kind="interactive",
            start_time=session_time,
        )
        activity_gen._users_by_username = {test_user.username: test_user}
        activity_gen._system_pids = {linux.hostname: {"systemd": systemd_pid}}

        first_shell = activity_gen.ensure_linux_session_shell(
            user=test_user,
            target_system=linux,
            logon_id=logon_id,
            logon_time=session_time,
            activity_time=session_time + timedelta(minutes=5),
        )

        assert first_shell is not None
        first_shell_proc = state_manager.get_process(linux.hostname, first_shell)
        assert first_shell_proc is not None
        first_terminal = state_manager.get_process(linux.hostname, first_shell_proc.parent_pid)
        assert first_terminal is not None
        first_user_manager_pid = first_terminal.parent_pid
        first_user_manager = state_manager.get_process(linux.hostname, first_user_manager_pid)
        assert first_user_manager is not None
        assert first_user_manager.command_line == "/usr/lib/systemd/systemd --user"

        state_manager.end_process(linux.hostname, first_shell)
        state_manager.end_process(linux.hostname, first_terminal.pid)

        second_shell = activity_gen.ensure_linux_session_shell(
            user=test_user,
            target_system=linux,
            logon_id=logon_id,
            logon_time=session_time,
            activity_time=session_time + timedelta(minutes=35),
        )

        assert second_shell is not None
        second_shell_proc = state_manager.get_process(linux.hostname, second_shell)
        assert second_shell_proc is not None
        second_terminal = state_manager.get_process(linux.hostname, second_shell_proc.parent_pid)
        assert second_terminal is not None
        assert second_terminal.parent_pid == first_user_manager_pid
        user_managers = [
            proc
            for proc in state_manager.get_processes_on_system(linux.hostname)
            if proc.command_line == "/usr/lib/systemd/systemd --user" and proc.logon_id == logon_id
        ]
        assert len(user_managers) == 1

    def test_linux_server_console_login_is_not_child_of_user_systemd(
        self, activity_gen, test_user, state_manager
    ):
        """Server console ancestry should be system manager -> login -> shell."""
        session_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        linux = System(
            hostname="APP-INT-01",
            ip="10.0.2.60",
            os="Ubuntu 22.04",
            type="server",
            assigned_user=test_user.username,
        )
        state_manager.set_current_time(session_time)
        systemd_pid = state_manager.create_process(
            linux.hostname,
            0,
            "/usr/lib/systemd/systemd",
            "/usr/lib/systemd/systemd --system",
            "root",
            "System",
        )
        logon_id = state_manager.create_session(
            username=test_user.username,
            system=linux.hostname,
            logon_type=2,
            source_ip="-",
            session_kind="interactive",
            start_time=session_time,
        )
        activity_gen._users_by_username = {test_user.username: test_user}
        activity_gen._system_pids = {linux.hostname: {"systemd": systemd_pid}}

        shell_pid = activity_gen.ensure_linux_session_shell(
            user=test_user,
            target_system=linux,
            logon_id=logon_id,
            logon_time=session_time,
            activity_time=session_time + timedelta(minutes=5),
        )

        assert shell_pid is not None
        shell = state_manager.get_process(linux.hostname, shell_pid)
        assert shell is not None
        login = state_manager.get_process(linux.hostname, shell.parent_pid)
        assert login is not None
        assert login.image == "/bin/login"
        assert login.parent_pid == systemd_pid
        assert not any(
            process.command_line == "/usr/lib/systemd/systemd --user"
            and process.logon_id == logon_id
            for process in state_manager.get_processes_on_system(linux.hostname)
        )

    def test_linux_workstation_python_requests_proxy_stays_unattributed(
        self, activity_gen, test_user, state_manager
    ):
        """Generic Python proxy User-Agents should not synthesize desktop snippets."""
        request_time = datetime(2024, 1, 15, 10, 5, 0, tzinfo=UTC)
        linux = System(
            hostname="WS-LNGUYEN-01",
            ip="10.0.2.60",
            os="Ubuntu 22.04",
            type="workstation",
            assigned_user=test_user.username,
        )
        proxy = System(
            hostname="PROXY-01",
            ip="10.0.3.20",
            os="Ubuntu 22.04",
            type="server",
            roles=["forward_proxy"],
        )
        logon_id = "0xabc460"
        state_manager.set_current_time(request_time - timedelta(minutes=10))
        systemd_pid = state_manager.create_process(
            linux.hostname,
            0,
            "/usr/lib/systemd/systemd",
            "/usr/lib/systemd/systemd --system",
            "root",
            "System",
        )
        user_systemd_pid = state_manager.create_process(
            linux.hostname,
            systemd_pid,
            "/usr/lib/systemd/systemd",
            "/usr/lib/systemd/systemd --user",
            test_user.username,
            "Medium",
            logon_id,
        )
        terminal_pid = state_manager.create_process(
            linux.hostname,
            user_systemd_pid,
            "/usr/libexec/gnome-terminal-server",
            "/usr/libexec/gnome-terminal-server",
            test_user.username,
            "Medium",
            logon_id,
        )
        bash_pid = state_manager.create_process(
            linux.hostname,
            terminal_pid,
            "/bin/bash",
            "-bash",
            test_user.username,
            "Medium",
            logon_id,
        )
        session = state_manager.register_session(
            logon_id=logon_id,
            username=test_user.username,
            system=linux.hostname,
            logon_type=2,
            source_ip="-",
            start_time=request_time - timedelta(minutes=9),
            session_kind="interactive",
        )
        session.process_tree_root = terminal_pid
        session.session_shell_pid = bash_pid
        activity_gen._users_by_username = {test_user.username: test_user}
        activity_gen._system_pids = {linux.hostname: {"systemd": systemd_pid, "bash": bash_pid}}
        proxy_context = ProxyContext(
            client_ip=linux.ip,
            username=test_user.username,
            method="GET",
            url="https://api.gitlab.com/",
            host="api.gitlab.com",
            status_code=200,
            user_agent="python-requests/2.31.0",
            proxy_fqdn="PROXY-01.meridianhcs.local",
        )

        pid, image = activity_gen._ensure_explicit_proxy_client_process(
            source_system=linux,
            time=request_time,
            proxy_context=proxy_context,
            proxy_sys=proxy,
            dst_port=443,
        )

        assert pid == -1
        assert image is None
        assert state_manager.get_process(linux.hostname, terminal_pid) is not None
        assert state_manager.get_process(linux.hostname, bash_pid) is not None
        python_snippets = [
            proc
            for proc in state_manager.get_processes_on_system(linux.hostname)
            if proc.image == "/usr/bin/python3" and "requests.get" in proc.command_line
        ]
        assert python_snippets == []

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

    @pytest.mark.parametrize(
        ("command", "expected"),
        [
            ("cat /tmp/a | grep x", True),
            ("cat /tmp/a || grep x", False),
            ("cat /tmp/a |& grep x", False),
            ("cat /tmp/a && grep x", False),
            ("cat /tmp/a ; grep x", False),
            ("printf 'a|b'", False),
            (r"printf a\|b", False),
        ],
    )
    def test_contains_unquoted_shell_pipe_requires_true_single_pipe(self, command, expected):
        """Only an unquoted, unescaped single pipe denotes concurrent pipeline stages."""
        assert generator_module._contains_unquoted_shell_pipe(command) is expected

    def test_linux_shell_process_groups_separate_control_operators(self):
        """Control operators split foreground cohorts while a true pipeline stays grouped."""
        groups = generator_module._linux_command_process_groups_from_shell(
            "cat /tmp/a | grep x && sha256sum /tmp/a || cut -c1-8 ; wc -l",
            max_processes=None,
        )

        assert groups == [
            [("/usr/bin/cat", "cat /tmp/a"), ("/usr/bin/grep", "grep x")],
            [("/usr/bin/sha256sum", "sha256sum /tmp/a")],
            [("/usr/bin/cut", "cut -c1-8")],
            [("/usr/bin/wc", "wc -l")],
        ]

    def test_generate_bash_command_serializes_control_after_pipeline(
        self, activity_gen, test_user, state_manager, mock_emitters
    ):
        """A sequential/control stage is admitted after, not inside, a pipeline cohort."""
        command_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        linux = System(
            hostname="LNX-OPERATORS-01",
            ip="10.0.0.4",
            os="Ubuntu 22.04",
            type="server",
            assigned_user=test_user.username,
        )
        session = state_manager.register_session(
            logon_id="0xoperators",
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
            session.logon_id,
        )
        session.session_shell_pid = bash_pid

        activity_gen.generate_bash_command(
            test_user,
            linux,
            command_time,
            "cat /tmp/a | grep x && sha256sum /tmp/a",
        )

        events = [
            call.args[0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        creates = {
            event.process.command_line: event
            for event in events
            if event.event_type == "process_create" and event.process is not None
        }
        terminations = {
            event.process.pid: event
            for event in events
            if event.event_type == "process_terminate" and event.process is not None
        }
        cat = creates["cat /tmp/a"]
        grep = creates["grep x"]
        sha256sum = creates["sha256sum /tmp/a"]
        assert cat.process.concurrency_group_id == grep.process.concurrency_group_id
        assert sha256sum.process.concurrency_group_id != cat.process.concurrency_group_id
        assert cat.timestamp < grep.timestamp
        assert sha256sum.timestamp > terminations[cat.process.pid].timestamp
        assert sha256sum.timestamp > terminations[grep.process.pid].timestamp

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

    def test_linux_shell_process_resolves_common_bash_pool_commands(self):
        """Common commands from bash pools should map to source-native executable paths."""
        expected = {
            "vmstat 1 5": [("/usr/bin/vmstat", "vmstat 1 5")],
            "nginx -t": [("/usr/sbin/nginx", "nginx -t")],
            "google-chrome --new-tab https://jira.example.test/browse/PROJ-1951": [
                (
                    "/usr/bin/google-chrome",
                    "google-chrome --new-tab https://jira.example.test/browse/PROJ-1951",
                )
            ],
            "sha256sum /tmp/rpt.sql.gz | cut -c1-16": [
                ("/usr/bin/sha256sum", "sha256sum /tmp/rpt.sql.gz"),
                ("/usr/bin/cut", "cut -c1-16"),
            ],
            "pt-query-digest /var/log/mysql/slow.log | head -50": [
                (
                    "/usr/bin/pt-query-digest",
                    "pt-query-digest /var/log/mysql/slow.log",
                ),
                ("/usr/bin/head", "head -50"),
            ],
            "code --no-sandbox /home/lina.nguyen/projects/data-pipeline": [
                (
                    "/usr/bin/code",
                    "code --no-sandbox /home/lina.nguyen/projects/data-pipeline",
                )
            ],
        }

        for command, processes in expected.items():
            assert generator_module._linux_command_processes_from_shell(command) == processes

    def test_interactive_nginx_check_uses_exact_session_shell_parent(
        self, activity_gen, test_user, state_manager, mock_emitters
    ):
        """An interactive nginx diagnostic remains shell-owned while daemon startup does not."""
        command_time = datetime(2024, 3, 18, 14, 20, tzinfo=UTC)
        linux = System(
            hostname="WEB-EXT-01",
            ip="10.10.3.20",
            os="Ubuntu 22.04",
            type="server",
            services=["nginx", "ssh"],
            roles=["web_server"],
        )
        state_manager.set_current_time(command_time - timedelta(hours=1))
        state_manager.register_process(
            system=linux.hostname,
            pid=1,
            parent_pid=0,
            image="/usr/lib/systemd/systemd",
            command_line="/usr/lib/systemd/systemd --system",
            username="root",
            integrity_level="System",
            os_category="linux",
        )
        session = state_manager.register_session(
            logon_id="0xabc123",
            username=test_user.username,
            system=linux.hostname,
            logon_type=10,
            source_ip="10.10.1.50",
            start_time=command_time - timedelta(minutes=10),
            session_kind="ssh",
        )
        state_manager.set_current_time(command_time - timedelta(minutes=9))
        shell_pid = state_manager.create_process(
            linux.hostname,
            1,
            "/bin/bash",
            "-bash",
            test_user.username,
            "Medium",
            session.logon_id,
        )
        session.session_shell_pid = shell_pid
        activity_gen._system_pids = {linux.hostname: {"systemd": 1}}

        activity_gen.generate_bash_command(test_user, linux, command_time, "nginx -t")
        daemon_pid = activity_gen.generate_system_process(
            system=linux,
            time=command_time + timedelta(minutes=1),
            process_name="/usr/sbin/nginx",
            command_line="/usr/sbin/nginx -g 'daemon off;'",
            parent_pid=1,
            username="root",
            emit_linux_syslog=False,
        )

        events = [
            call.args[0]
            for call in mock_emitters["windows_event_security"].emit.call_args_list
            if call.args[0].process is not None and call.args[0].process.image == "/usr/sbin/nginx"
        ]
        interactive = next(event for event in events if event.process.command_line == "nginx -t")
        daemon = state_manager.get_process(linux.hostname, daemon_pid)
        assert interactive.auth.username == test_user.username
        assert interactive.process.logon_id == session.logon_id
        assert interactive.process.parent_pid == shell_pid
        assert interactive.process.parent_image == "/bin/bash"
        assert daemon is not None
        assert daemon.username == "root"
        assert daemon.parent_pid == 1

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

    def test_linux_catalog_compound_command_splits_process_argv(self):
        """Catalog process commands should use child argv, not shell compound text."""
        processes = generator_module._linux_catalog_processes_from_shell_command(
            "/usr/bin/make",
            "make clean && make all",
            username="alice",
        )

        assert processes == [
            ("/usr/bin/make", "make clean"),
            ("/usr/bin/make", "make all"),
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
        pipeline_events = [
            event
            for event in process_events
            if event.process.command_line in {"cat /etc/shadow", "head -5"}
        ]
        assert len(pipeline_events) == 2
        assert pipeline_events[0].process.parent_pid == pipeline_events[1].process.parent_pid
        assert (
            pipeline_events[0].process.concurrency_group_id
            == pipeline_events[1].process.concurrency_group_id
        )
        gap = pipeline_events[1].timestamp - pipeline_events[0].timestamp
        assert timedelta(milliseconds=6) <= gap <= timedelta(milliseconds=115)

    def test_linux_pipeline_stage_planner_is_deterministic_varied_and_load_sensitive(self):
        """Pipeline stages use scoped continuous texture instead of one fixed gap."""
        base = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        first = plan_linux_pipeline_stage_times(
            base,
            stage_count=4,
            scope_parts=("LNX-01", "alice", "0xabc", "pipeline-a"),
            active_process_count=8,
        )
        repeated = plan_linux_pipeline_stage_times(
            base,
            stage_count=4,
            scope_parts=("LNX-01", "alice", "0xabc", "pipeline-a"),
            active_process_count=8,
        )

        assert first == repeated
        assert first[0] == base
        assert all(first[index] < first[index + 1] for index in range(len(first) - 1))

        gaps = []
        for index in range(128):
            stage_times = plan_linux_pipeline_stage_times(
                base,
                stage_count=2,
                scope_parts=(f"LNX-{index:03d}", "alice", "0xabc", f"pipeline-{index}"),
                active_process_count=index % 32,
            )
            gaps.append(stage_times[1] - stage_times[0])

        assert min(gaps) >= timedelta(milliseconds=6)
        assert max(gaps) <= timedelta(milliseconds=115)
        assert len(set(gaps)) > 110
        rounded_ms = [round(gap.total_seconds() * 1_000) for gap in gaps]
        assert max(rounded_ms.count(value) for value in set(rounded_ms)) < 8

        idle = plan_linux_pipeline_stage_times(
            base,
            stage_count=2,
            scope_parts=("LNX-LOAD", "alice", "0xabc", "pipeline-load"),
            active_process_count=0,
        )
        busy = plan_linux_pipeline_stage_times(
            base,
            stage_count=2,
            scope_parts=("LNX-LOAD", "alice", "0xabc", "pipeline-load"),
            active_process_count=96,
        )
        assert busy[1] - busy[0] > idle[1] - idle[0]

    def test_linux_catalog_pipeline_uses_shared_stage_planner(
        self,
        activity_gen,
        test_user,
        state_manager,
        mock_emitters,
        monkeypatch,
    ):
        """Legacy catalog generation adapts into the action-owned stage schedule."""
        command_time = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        linux = System(
            hostname="LNX-CATALOG-01",
            ip="10.0.0.3",
            os="Ubuntu 22.04",
            type="workstation",
            assigned_user=test_user.username,
        )
        session = state_manager.register_session(
            logon_id="0xcatalog",
            username=test_user.username,
            system=linux.hostname,
            logon_type=2,
            source_ip=linux.ip,
            start_time=command_time - timedelta(minutes=5),
        )
        state_manager.set_current_time(command_time - timedelta(minutes=4))
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
            session.logon_id,
        )
        session.session_shell_pid = bash_pid
        monkeypatch.setattr(
            "evidenceforge.generation.activity.application_catalog.pick_app_and_command",
            lambda *_args, **_kwargs: (
                "/usr/bin/sha256sum",
                "sha256sum /tmp/rpt.sql.gz | cut -c1-16",
            ),
        )

        activity_gen.execute_baseline_activity(
            test_user,
            linux,
            command_time,
            "process_code",
        )

        events = [
            call.args[0] for call in mock_emitters["windows_event_security"].emit.call_args_list
        ]
        pipeline_events = [
            event
            for event in events
            if event.event_type == "process_create"
            and event.process is not None
            and event.process.command_line in {"sha256sum /tmp/rpt.sql.gz", "cut -c1-16"}
        ]
        assert len(pipeline_events) == 2
        assert pipeline_events[0].process.parent_pid == bash_pid
        assert pipeline_events[1].process.parent_pid == bash_pid
        assert (
            pipeline_events[0].process.concurrency_group_id
            == pipeline_events[1].process.concurrency_group_id
        )
        gap = pipeline_events[1].timestamp - pipeline_events[0].timestamp
        assert timedelta(milliseconds=6) <= gap <= timedelta(milliseconds=115)

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

    def test_parameterize_command_internal_url_placeholder_is_bounded(
        self, activity_gen, test_user
    ):
        """Internal URL replacement should terminate even with placeholder-tainted domains."""
        activity_gen._ad_domain = "{internal_url}"
        linux = System(
            hostname="APP-INT-01",
            ip="10.0.0.2",
            os="Ubuntu 22.04",
            type="server",
            services=["ssh", "gunicorn"],
        )

        command = activity_gen._parameterize_command_for_system(
            random.Random(7),
            "curl {internal_url} && curl {internal_url}",
            username=test_user.username,
            system=linux,
        )

        assert "{internal_url}" not in command
        assert command.count("https://") == 2
        assert "corp.local" in command

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

        # Connection dispatched as OccurrenceBuilder
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


def test_disambiguate_icmp_observation_time_uses_monotonic_varied_sequence(activity_gen):
    """Duplicate ICMP observations should not linearly probe or use fixed spacing."""

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

    gaps = [
        (current - previous).total_seconds()
        for previous, current in zip(adjusted_times[:-1], adjusted_times[1:], strict=True)
    ]

    assert adjusted_times[0] == base_time
    assert all(gap > 0 for gap in gaps)
    assert min(gaps) >= timedelta(milliseconds=7).total_seconds()
    assert max(gaps) < timedelta(milliseconds=84).total_seconds()
    assert len({round(gap, 6) for gap in gaps}) > 100
    assert next_timestamps.get_calls == len(adjusted_times)
    assert len(next_timestamps) == 1


def test_emit_dns_lookup_prunes_and_bounds_dns_cache(activity_gen):
    """_emit_dns_lookup should prune expired entries and enforce a bounded cache size."""
    now = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
    ts_now = now.timestamp()

    activity_gen._dns_cache = {
        (f"10.0.0.{i % 255}", "10.0.0.1", f"host-{i}.example.com", "ADDR"): (
            ts_now - 35,
            ts_now - 5,
        )
        for i in range(50_100)
    }
    hot_key = ("10.0.0.5", "10.0.0.1", "active.example.com", "ADDR")
    activity_gen._dns_cache[hot_key] = (ts_now - 1, ts_now + 30)
    activity_gen._dns_cache_last_prune = 0.0

    activity_gen._emit_dns_lookup(hot_key[0], "93.184.216.34", now, hostname=hot_key[2])

    assert hot_key in activity_gen._dns_cache
    assert len(activity_gen._dns_cache) <= 2


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


def test_public_sni_on_private_destination_uses_public_ca(activity_gen, monkeypatch):
    """Public SNI observed through private listener addresses should not use internal CA."""
    monkeypatch.setattr(generator_module, "_TLS_VERSION_WEIGHTS", (100, 0))
    activity_gen._ad_domain = "corp.local"
    event = OccurrenceBuilder(
        timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
        event_type="connection",
        network=network_plan(
            src_ip="198.51.100.44",
            src_port=49152,
            dst_ip="10.0.3.10",
            dst_port=443,
            protocol="tcp",
            service="ssl",
            zeek_uid="Cpublicsni",
            duration=2.0,
            orig_bytes=900,
            resp_bytes=9000,
            orig_pkts=4,
            resp_pkts=10,
            orig_ip_bytes=1200,
            resp_ip_bytes=9500,
            conn_state="SF",
            history="ShADadfF",
            initiating_pid=-1,
        ),
    )

    activity_gen._attach_ssl_context(
        event,
        hostname="portal.example.com",
        dns=None,
        dst_ip="10.0.3.10",
        rng=random.Random(7),
        allow_failure=False,
    )

    assert event.protocol.leaf_certificate is not None
    assert event.protocol.leaf_certificate.certificate_subject == "CN=portal.example.com"
    assert "Enterprise Issuing CA" not in event.protocol.leaf_certificate.certificate_issuer


def test_internal_sni_on_private_destination_uses_enterprise_ca(activity_gen, monkeypatch):
    """Internal SNI on private addresses should keep enterprise certificate semantics."""
    monkeypatch.setattr(generator_module, "_TLS_VERSION_WEIGHTS", (100, 0))
    activity_gen._ad_domain = "corp.local"
    event = OccurrenceBuilder(
        timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
        event_type="connection",
        network=network_plan(
            src_ip="10.0.1.10",
            src_port=49152,
            dst_ip="10.0.3.10",
            dst_port=443,
            protocol="tcp",
            service="ssl",
            zeek_uid="Cinternalsni",
            duration=2.0,
            orig_bytes=900,
            resp_bytes=9000,
            orig_pkts=4,
            resp_pkts=10,
            orig_ip_bytes=1200,
            resp_ip_bytes=9500,
            conn_state="SF",
            history="ShADadfF",
            initiating_pid=-1,
        ),
    )

    activity_gen._attach_ssl_context(
        event,
        hostname="portal.corp.local",
        dns=None,
        dst_ip="10.0.3.10",
        rng=random.Random(7),
        allow_failure=False,
    )

    assert event.protocol.leaf_certificate is not None
    assert event.protocol.leaf_certificate.certificate_subject == "CN=portal.corp.local"
    assert (
        event.protocol.leaf_certificate.certificate_issuer
        == "CN=Enterprise Enterprise Issuing CA, O=Enterprise, C=US"
    )


def test_tcp_success_history_uses_varied_completed_flow_shapes():
    """Explicit successful TCP connections should not collapse to one Zeek history."""
    histories = {generator_module._tcp_success_history(random.Random(seed)) for seed in range(40)}

    assert "ShADadfF" in histories
    assert len(histories) > 1


def test_failed_tls_context_rewrites_packet_accounting(activity_gen, monkeypatch):
    """Failed TLS handshakes should keep byte counts aligned with Zeek history."""
    monkeypatch.setattr(generator_module, "_SSL_FAILURE_RATE", 1.0)
    timestamp = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
    event = OccurrenceBuilder(
        timestamp=timestamp,
        event_type="connection",
        network=network_plan(
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

    assert event.protocol.ssl is not None
    assert event.protocol.ssl.established is False
    assert event.network.conn_state == "S1"
    assert event.network.history in {"ShAD", "ShADd"}
    assert "D" in event.network.history
    if event.network.resp_bytes:
        assert "d" in event.network.history
    assert 0 < event.network.orig_bytes < 1200
    assert 0 <= event.network.resp_bytes < 55000
    assert event.network.orig_pkts >= 1
    assert event.network.resp_pkts >= 0
