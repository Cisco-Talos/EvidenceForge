# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for proxy emitter referrer field and CONNECT tunnel behavior."""

from datetime import UTC, datetime, timedelta

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import NetworkContext, ProxyContext


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
        assert '"-"' in rendered_lines[0]


class TestConnectTunnelBehavior:
    """Verify CONNECT is emitted once per tunnel, not per request."""

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

        # Should have CONNECT + GET = 2 lines
        assert len(rendered_lines) == 2
        assert "CONNECT" in rendered_lines[0]
        assert "GET" in rendered_lines[1]

    def test_tunnel_reuse_within_timeout(self):
        """Multiple HTTPS requests within timeout produce only one CONNECT."""
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
        get_count = sum(1 for line in all_lines if "GET" in line)

        assert connect_count == 1, f"Expected 1 CONNECT, got {connect_count}"
        assert get_count == 5, f"Expected 5 GETs, got {get_count}"

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
