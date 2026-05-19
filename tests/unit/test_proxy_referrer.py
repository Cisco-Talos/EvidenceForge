# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for proxy emitter referrer field and CONNECT tunnel behavior."""

from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import HttpContext, NetworkContext, ProxyContext


class TestProxyContextReferrer:
    """Verify ProxyContext has referrer field."""

    def test_referrer_field_exists(self):
        px = ProxyContext(client_ip="10.0.0.1")
        assert hasattr(px, "referrer")
        assert px.referrer == ""

    def test_referrer_field_settable(self):
        px = ProxyContext(
            client_ip="10.0.0.1",
            referrer="https://outlook.office365.com/owa/",
        )
        assert px.referrer == "https://outlook.office365.com/owa/"


class TestProxyEmitterReferrer:
    """Verify proxy emitter renders referrer in output."""

    def test_referrer_in_rendered_output(self):
        from pathlib import Path

        from evidenceforge.formats import load_format
        from evidenceforge.generation.emitters.proxy import ProxyEmitter

        fmt = load_format("proxy_access")
        emitter = ProxyEmitter(fmt, Path("/tmp/test_proxy"))

        event = SecurityEvent(
            timestamp=datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC),
            event_type="connection",
            network=NetworkContext(
                src_ip="10.0.10.50",
                src_port=54321,
                dst_ip="93.184.216.34",
                dst_port=80,
                protocol="tcp",
            ),
            proxy=ProxyContext(
                client_ip="10.0.10.50",
                method="GET",
                url="http://example.com/page",
                host="example.com",
                referrer="https://google.com/search?q=example",
                proxy_fqdn="PROXY-01",
            ),
        )

        # Capture rendered output
        rendered_lines = []
        emitter.emit_to_host = lambda line, fqdn: rendered_lines.append(line)

        emitter.emit(event)

        assert len(rendered_lines) == 1
        assert "https://google.com/search?q=example" in rendered_lines[0]

    def test_empty_referrer_renders_as_dash(self):
        from pathlib import Path

        from evidenceforge.formats import load_format
        from evidenceforge.generation.emitters.proxy import ProxyEmitter

        fmt = load_format("proxy_access")
        emitter = ProxyEmitter(fmt, Path("/tmp/test_proxy"))

        event = SecurityEvent(
            timestamp=datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC),
            event_type="connection",
            network=NetworkContext(
                src_ip="10.0.10.50",
                src_port=54321,
                dst_ip="93.184.216.34",
                dst_port=80,
                protocol="tcp",
            ),
            proxy=ProxyContext(
                client_ip="10.0.10.50",
                method="GET",
                url="http://example.com/",
                host="example.com",
                proxy_fqdn="PROXY-01",
            ),
        )

        rendered_lines = []
        emitter.emit_to_host = lambda line, fqdn: rendered_lines.append(line)
        emitter.emit(event)

        assert len(rendered_lines) == 1
        fields = rendered_lines[0].split()
        assert fields[13] == "-"

    def test_proxy_access_flush_sorts_by_request_timestamp(self, tmp_path):
        from evidenceforge.formats import load_format
        from evidenceforge.generation.emitters.proxy import ProxyEmitter

        fmt = load_format("proxy_access")
        emitter = ProxyEmitter(fmt, tmp_path, buffer_size=2)

        for ts in [
            datetime(2024, 3, 15, 10, 5, 0, tzinfo=UTC),
            datetime(2024, 3, 15, 10, 1, 0, tzinfo=UTC),
            datetime(2024, 3, 15, 10, 3, 0, tzinfo=UTC),
        ]:
            event = SecurityEvent(
                timestamp=ts,
                event_type="connection",
                network=NetworkContext(
                    src_ip="10.0.10.50",
                    src_port=54321,
                    dst_ip="93.184.216.34",
                    dst_port=80,
                    protocol="tcp",
                ),
                proxy=ProxyContext(
                    client_ip="10.0.10.50",
                    method="GET",
                    url="http://example.com/page",
                    host="example.com",
                    proxy_fqdn="PROXY-01",
                ),
            )
            emitter.emit(event)

        emitter.close()

        lines = (tmp_path / "PROXY-01" / "proxy_access.log").read_text().splitlines()
        assert lines[0] == "#Software: Meridian Secure Web Gateway"
        assert lines[2].endswith("x-proxy-action")
        data_lines = [line for line in lines if not line.startswith("#")]
        assert data_lines[0].startswith("2024-03-15 10:01:00")
        assert data_lines[1].startswith("2024-03-15 10:03:00")
        assert data_lines[2].startswith("2024-03-15 10:05:00")


class TestConnectTunnelBehavior:
    """Verify CONNECT is emitted once per tunnel, not per request."""

    def test_dynamic_https_api_request_is_not_cached(self):
        """TLS-inspected dynamic API requests should reach origin even when cache roll is low."""
        from evidenceforge.generation.activity import ActivityGenerator
        from evidenceforge.generation.state_manager import StateManager
        from evidenceforge.models.scenario import System

        class LowCacheRollRandom:
            def random(self):
                return 0.1

            def randint(self, lower, _upper):
                return lower

            def choice(self, values):
                return values[0]

        generator = ActivityGenerator(StateManager(), {})
        source_system = System(
            hostname="ws01",
            ip="10.0.10.10",
            os="Windows 11",
            type="workstation",
        )
        proxy_system = System(
            hostname="proxy01",
            ip="10.0.20.10",
            os="Ubuntu 24.04",
            type="server",
            roles=["forward_proxy"],
        )

        with (
            patch("evidenceforge.generation.activity.generator._get_rng", LowCacheRollRandom),
            patch(
                "evidenceforge.generation.activity.generator.pick_proxy_domain_user_agent",
                return_value="",
            ),
            patch(
                "evidenceforge.generation.activity.generator.pick_proxy_user_agent",
                return_value="Mozilla/5.0",
            ),
        ):
            proxy_context = generator._build_proxy_context(
                src_ip="10.0.10.10",
                dst_ip="45.33.49.112",
                dst_port=443,
                service="ssl",
                duration=1.0,
                orig_bytes=500,
                resp_bytes=1000,
                hostname="telemetry-sync.example.net",
                source_system=source_system,
                proxy_sys=proxy_system,
                http=HttpContext(
                    method="GET",
                    host="telemetry-sync.example.net",
                    uri="/v1/checkin",
                    user_agent="FixtureBeacon/1.0",
                    response_body_len=1000,
                    status_code=200,
                    resp_mime_types=["text/html"],
                ),
                explicit_mode=True,
            )

        assert proxy_context.cache_result == "MISS"

    def test_http_context_status_prevents_random_proxy_denial(self):
        """Canonical HTTP success should not be overwritten by proxy cache randomness."""
        from evidenceforge.generation.activity import ActivityGenerator
        from evidenceforge.generation.state_manager import StateManager
        from evidenceforge.models.scenario import System

        class HighCacheRollRandom:
            def random(self):
                return 0.99

            def randint(self, lower, _upper):
                return lower

            def choice(self, values):
                return values[0]

        generator = ActivityGenerator(StateManager(), {})
        source_system = System(
            hostname="ws01",
            ip="10.0.10.10",
            os="Windows 11",
            type="workstation",
        )
        proxy_system = System(
            hostname="proxy01",
            ip="10.0.20.10",
            os="Ubuntu 24.04",
            type="server",
            roles=["forward_proxy"],
        )

        with (
            patch("evidenceforge.generation.activity.generator._get_rng", HighCacheRollRandom),
            patch(
                "evidenceforge.generation.activity.generator.pick_proxy_domain_user_agent",
                return_value="",
            ),
            patch(
                "evidenceforge.generation.activity.generator.pick_proxy_user_agent",
                return_value="FixtureBeacon/1.0",
            ),
        ):
            proxy_context = generator._build_proxy_context(
                src_ip="10.0.10.10",
                dst_ip="45.33.49.112",
                dst_port=443,
                service="ssl",
                duration=1.0,
                orig_bytes=500,
                resp_bytes=1000,
                hostname="telemetry-sync.example.net",
                source_system=source_system,
                proxy_sys=proxy_system,
                http=HttpContext(
                    method="GET",
                    host="telemetry-sync.example.net",
                    uri="/v1/checkin",
                    user_agent="FixtureBeacon/1.0",
                    response_body_len=1000,
                    status_code=200,
                    resp_mime_types=["text/html"],
                ),
                explicit_mode=True,
            )

        assert proxy_context.status_code == 200
        assert proxy_context.cache_result == "MISS"

    def test_first_https_request_emits_connect(self):
        from pathlib import Path

        from evidenceforge.formats import load_format
        from evidenceforge.generation.emitters.proxy import ProxyEmitter

        fmt = load_format("proxy_access")
        emitter = ProxyEmitter(fmt, Path("/tmp/test_proxy"))

        event = SecurityEvent(
            timestamp=datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC),
            event_type="connection",
            network=NetworkContext(
                src_ip="10.0.10.50",
                src_port=54321,
                dst_ip="93.184.216.34",
                dst_port=443,
                protocol="tcp",
            ),
            proxy=ProxyContext(
                client_ip="10.0.10.50",
                method="GET",
                url="https://example.com/page",
                host="example.com",
                proxy_fqdn="PROXY-01",
            ),
        )

        rendered_lines = []
        emitter.emit_to_host = lambda line, fqdn: rendered_lines.append(line)
        emitter.emit(event)

        assert len(rendered_lines) == 2
        fields = rendered_lines[0].split()
        assert fields[4] == "CONNECT"
        assert fields[5] == "example.com:443"
        assert fields[6] == "HTTP/1.1"
        assert fields[-1] == "tunnel-setup"
        inspected_fields = rendered_lines[1].split()
        assert inspected_fields[4] == "GET"
        assert inspected_fields[5] == "https://example.com/page"
        assert inspected_fields[-1] == "ssl-inspect"

    def test_connect_setup_row_differs_from_inspected_request_accounting(self):
        from pathlib import Path

        from evidenceforge.formats import load_format
        from evidenceforge.generation.emitters.proxy import ProxyEmitter

        fmt = load_format("proxy_access")
        emitter = ProxyEmitter(fmt, Path("/tmp/test_proxy"))

        event = SecurityEvent(
            timestamp=datetime(2024, 3, 15, 10, 0, 5, tzinfo=UTC),
            event_type="connection",
            network=NetworkContext(
                src_ip="10.0.10.50",
                src_port=54321,
                dst_ip="10.0.20.10",
                dst_port=8080,
                protocol="tcp",
            ),
            proxy=ProxyContext(
                client_ip="10.0.10.50",
                method="GET",
                url="https://example.com/status.gif",
                host="example.com",
                sc_bytes=4096,
                cs_bytes=700,
                time_taken=900,
                proxy_fqdn="PROXY-01",
            ),
        )

        rendered_lines = []
        emitter.emit_to_host = lambda line, fqdn: rendered_lines.append(line)
        emitter.emit(event)

        assert len(rendered_lines) == 2
        connect_fields = rendered_lines[0].split()
        inspected_fields = rendered_lines[1].split()
        assert connect_fields[4] == "CONNECT"
        assert inspected_fields[4] == "GET"
        assert connect_fields[-1] == "tunnel-setup"
        assert inspected_fields[-1] == "ssl-inspect"
        assert connect_fields[0:2] <= inspected_fields[0:2]
        assert connect_fields[7:10] != inspected_fields[7:10]
        assert connect_fields[7] == "200"
        assert int(connect_fields[8]) < int(inspected_fields[8])
        assert int(connect_fields[9]) < int(inspected_fields[9])

    def test_inspected_https_denial_has_successful_connect_setup(self):
        from pathlib import Path

        from evidenceforge.formats import load_format
        from evidenceforge.generation.emitters.proxy import ProxyEmitter

        fmt = load_format("proxy_access")
        emitter = ProxyEmitter(fmt, Path("/tmp/test_proxy"))

        event = SecurityEvent(
            timestamp=datetime(2024, 3, 15, 10, 0, 5, tzinfo=UTC),
            event_type="connection",
            network=NetworkContext(
                src_ip="10.0.10.50",
                src_port=54321,
                dst_ip="10.0.20.10",
                dst_port=8080,
                protocol="tcp",
            ),
            proxy=ProxyContext(
                client_ip="10.0.10.50",
                method="GET",
                url="https://example.com/blocked.js",
                host="example.com",
                status_code=403,
                sc_bytes=1200,
                cs_bytes=700,
                time_taken=900,
                content_type="text/html",
                cache_result="DENIED",
                proxy_fqdn="PROXY-01",
            ),
        )

        rendered_lines = []
        emitter.emit_to_host = lambda line, fqdn: rendered_lines.append(line)
        emitter.emit(event)

        assert len(rendered_lines) == 2
        connect_fields = rendered_lines[0].split()
        denied_fields = rendered_lines[1].split()
        assert connect_fields[4] == "CONNECT"
        assert connect_fields[7] == "200"
        assert connect_fields[-1] == "tunnel-setup"
        assert denied_fields[4] == "GET"
        assert denied_fields[7] == "403"
        assert denied_fields[-1] == "deny"

    def test_denied_connect_does_not_emit_inspected_request(self):
        from pathlib import Path

        from evidenceforge.formats import load_format
        from evidenceforge.generation.emitters.proxy import ProxyEmitter

        fmt = load_format("proxy_access")
        emitter = ProxyEmitter(fmt, Path("/tmp/test_proxy"))

        event = SecurityEvent(
            timestamp=datetime(2024, 3, 15, 10, 0, 5, tzinfo=UTC),
            event_type="connection",
            network=NetworkContext(
                src_ip="10.0.10.50",
                src_port=54321,
                dst_ip="10.0.20.10",
                dst_port=8080,
                protocol="tcp",
            ),
            proxy=ProxyContext(
                client_ip="10.0.10.50",
                method="CONNECT",
                url="example.com:443",
                host="example.com",
                status_code=403,
                sc_bytes=1200,
                cs_bytes=700,
                time_taken=900,
                content_type="text/html",
                cache_result="DENIED",
                proxy_fqdn="PROXY-01",
            ),
        )

        rendered_lines = []
        emitter.emit_to_host = lambda line, fqdn: rendered_lines.append(line)
        emitter.emit(event)

        assert len(rendered_lines) == 1
        denied_fields = rendered_lines[0].split()
        assert denied_fields[4] == "CONNECT"
        assert denied_fields[7] == "403"
        assert denied_fields[-1] == "deny"

    def test_tunnel_reuse_within_timeout(self):
        """TLS-intercepting proxies log one CONNECT plus inspected HTTPS requests."""
        from pathlib import Path

        from evidenceforge.formats import load_format
        from evidenceforge.generation.emitters.proxy import ProxyEmitter

        fmt = load_format("proxy_access")
        emitter = ProxyEmitter(fmt, Path("/tmp/test_proxy"))

        all_lines: list[str] = []
        emitter.emit_to_host = lambda line, fqdn: all_lines.append(line)

        base_ts = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)
        for i in range(5):
            event = SecurityEvent(
                timestamp=base_ts + timedelta(seconds=i * 2),
                event_type="connection",
                network=NetworkContext(
                    src_ip="10.0.10.50",
                    src_port=54321,
                    dst_ip="93.184.216.34",
                    dst_port=443,
                    protocol="tcp",
                ),
                proxy=ProxyContext(
                    client_ip="10.0.10.50",
                    method="GET",
                    url=f"https://example.com/page{i}",
                    host="example.com",
                    proxy_fqdn="PROXY-01",
                ),
            )
            emitter.emit(event)

        connect_count = sum(1 for line in all_lines if "CONNECT" in line)
        get_count = sum(1 for line in all_lines if " GET " in line)

        assert connect_count == 1, f"Expected 1 CONNECT, got {connect_count}"
        assert get_count == 5, f"Expected 5 inspected GET rows, got {get_count}"

    def test_tunnel_expires_after_timeout(self):
        """CONNECT re-emitted after tunnel timeout expires."""
        from pathlib import Path

        from evidenceforge.formats import load_format
        from evidenceforge.generation.emitters.proxy import ProxyEmitter

        fmt = load_format("proxy_access")
        emitter = ProxyEmitter(fmt, Path("/tmp/test_proxy"))

        all_lines: list[str] = []
        emitter.emit_to_host = lambda line, fqdn: all_lines.append(line)

        ts1 = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)
        ts2 = ts1 + timedelta(minutes=10)  # Well past 5-minute timeout

        for ts in [ts1, ts2]:
            event = SecurityEvent(
                timestamp=ts,
                event_type="connection",
                network=NetworkContext(
                    src_ip="10.0.10.50",
                    src_port=54321,
                    dst_ip="93.184.216.34",
                    dst_port=443,
                    protocol="tcp",
                ),
                proxy=ProxyContext(
                    client_ip="10.0.10.50",
                    method="GET",
                    url="https://example.com/page",
                    host="example.com",
                    proxy_fqdn="PROXY-01",
                ),
            )
            emitter.emit(event)

        connect_count = sum(1 for line in all_lines if "CONNECT" in line)
        assert connect_count == 2, f"Expected 2 CONNECTs (tunnel expired), got {connect_count}"

    def test_different_hosts_get_separate_connects(self):
        """Different destination hosts each get their own CONNECT."""
        from pathlib import Path

        from evidenceforge.formats import load_format
        from evidenceforge.generation.emitters.proxy import ProxyEmitter

        fmt = load_format("proxy_access")
        emitter = ProxyEmitter(fmt, Path("/tmp/test_proxy"))

        all_lines: list[str] = []
        emitter.emit_to_host = lambda line, fqdn: all_lines.append(line)

        ts = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)
        for host in ["example.com", "google.com", "github.com"]:
            event = SecurityEvent(
                timestamp=ts,
                event_type="connection",
                network=NetworkContext(
                    src_ip="10.0.10.50",
                    src_port=54321,
                    dst_ip="93.184.216.34",
                    dst_port=443,
                    protocol="tcp",
                ),
                proxy=ProxyContext(
                    client_ip="10.0.10.50",
                    method="GET",
                    url=f"https://{host}/",
                    host=host,
                    proxy_fqdn="PROXY-01",
                ),
            )
            emitter.emit(event)
            ts += timedelta(seconds=1)

        connect_count = sum(1 for line in all_lines if "CONNECT" in line)
        assert connect_count == 3, f"Expected 3 CONNECTs (one per host), got {connect_count}"

    def test_same_host_on_different_proxy_gets_separate_connect(self):
        """CONNECT tunnel reuse is scoped to the proxy that owns the tunnel."""
        from pathlib import Path

        from evidenceforge.formats import load_format
        from evidenceforge.generation.emitters.proxy import ProxyEmitter

        fmt = load_format("proxy_access")
        emitter = ProxyEmitter(fmt, Path("/tmp/test_proxy"))

        all_lines: list[str] = []
        emitter.emit_to_host = lambda line, fqdn: all_lines.append(line)

        ts = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)
        for proxy_fqdn in ["PROXY-01", "PROXY-02"]:
            event = SecurityEvent(
                timestamp=ts,
                event_type="connection",
                network=NetworkContext(
                    src_ip="10.0.10.50",
                    src_port=54321,
                    dst_ip="93.184.216.34",
                    dst_port=443,
                    protocol="tcp",
                ),
                proxy=ProxyContext(
                    client_ip="10.0.10.50",
                    method="GET",
                    url="https://example.com/",
                    host="example.com",
                    proxy_fqdn=proxy_fqdn,
                ),
            )
            emitter.emit(event)
            ts += timedelta(seconds=1)

        connect_count = sum(1 for line in all_lines if "CONNECT" in line)
        assert connect_count == 2, f"Expected 2 CONNECTs (one per proxy), got {connect_count}"
