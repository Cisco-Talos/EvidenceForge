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

"""Tests for activity generator SSL/HTTP/FileTransfer context population."""

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from evidenceforge.events.contexts import HttpContext
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.state_manager import StateManager


@pytest.fixture
def activity_gen():
    """Create ActivityGenerator with mock dependencies that capture dispatched events."""
    state_manager = StateManager()
    state_manager.set_current_time(datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC))

    # Create mock emitters dict
    mock_emitters = {}
    for name in [
        "zeek_conn",
        "zeek_dns",
        "zeek_ssl",
        "zeek_http",
        "zeek_files",
        "windows_event_security",
        "ecar",
        "syslog",
        "bash_history",
        "snort_alert",
        "web_access",
    ]:
        m = MagicMock()
        m.can_handle.return_value = False
        mock_emitters[name] = m
    # conn emitter accepts connection events
    mock_emitters["zeek_conn"].can_handle.side_effect = lambda e: (
        e.event_type in {"connection", "ssh_session"} and e.network is not None
    )

    dispatcher = EventDispatcher(state_manager, mock_emitters)

    captured_events = []
    original_dispatch = dispatcher.dispatch

    def capturing_dispatch(event):
        captured_events.append(event)
        original_dispatch(event)

    dispatcher.dispatch = capturing_dispatch

    gen = ActivityGenerator(state_manager, mock_emitters, dispatcher=dispatcher)
    return gen, captured_events


class TestSslContextPopulation:
    """Verify SSL context is attached to connection events for port 443."""

    def test_ssl_service_gets_ssl_context(self, activity_gen):
        gen, events = activity_gen

        gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip="93.184.216.34",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=2.0,
            orig_bytes=1024,
            resp_bytes=4096,
        )

        assert len(events) > 0
        event = events[-1]
        # SF connections with ssl service should have SslContext
        if event.network.conn_state == "SF":
            assert event.ssl is not None
            assert event.ssl.version in {"TLSv12", "TLSv13"}
            assert event.ssl.cipher != ""
            assert event.ssl.established is True
            assert event.x509 is not None
            assert event.x509.fuid.startswith("F")
            assert event.ssl.cert_chain_fuids == [event.x509.fuid]

    def test_http_service_no_ssl_context(self, activity_gen):
        gen, events = activity_gen

        gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip="93.184.216.34",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=80,
            proto="tcp",
            service="http",
            duration=1.0,
            orig_bytes=200,
            resp_bytes=5000,
        )

        event = events[-1]
        assert event.ssl is None

    def test_dns_service_gets_dns_context(self, activity_gen):
        gen, events = activity_gen

        gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip="10.0.20.10",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=53,
            proto="udp",
            service="dns",
            duration=0.01,
            orig_bytes=60,
            resp_bytes=120,
            hostname="example.com",
        )

        event = events[-1]
        assert event.dns is not None
        assert event.dns.query == "example.com"
        assert event.dns.answers == ["10.0.20.10"]

    def test_tls12_cipher_matches_certificate_key_type(self, activity_gen):
        gen, events = activity_gen

        gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip="142.250.72.36",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=2.0,
            orig_bytes=1024,
            resp_bytes=4096,
            hostname="www.gstatic.com",
            conn_state="SF",
        )

        event = events[-1]
        assert event.ssl is not None
        assert event.x509 is not None
        if event.ssl.version == "TLSv12":
            if "ECDSA" in event.ssl.cipher:
                assert event.x509.certificate_key_type == "ecdsa"
            if "RSA" in event.ssl.cipher:
                assert event.x509.certificate_key_type == "rsa"

    def test_ssl_server_name_from_reverse_dns(self, activity_gen):
        """SslContext.server_name should be derived from REVERSE_DNS."""
        gen, events = activity_gen

        gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip="93.184.216.34",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=2.0,
            orig_bytes=1024,
            resp_bytes=4096,
        )

        event = events[-1]
        if event.ssl is not None:
            # server_name should be set (either from REVERSE_DNS or fallback to IP)
            assert event.ssl.server_name != ""

    def test_same_certificate_identity_has_stable_validity_window(self, activity_gen):
        gen, events = activity_gen

        for offset in (0, 3600):
            gen.generate_connection(
                src_ip="10.0.10.50",
                dst_ip="142.250.72.36",
                time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC) + timedelta(seconds=offset),
                dst_port=443,
                proto="tcp",
                service="ssl",
                duration=2.0,
                orig_bytes=1024,
                resp_bytes=4096,
                hostname="www.gstatic.com",
                conn_state="SF",
            )
            gen._tls_seen_server_names.clear()

        cert_events = [event for event in events if event.x509 is not None]
        assert len(cert_events) == 2
        first = cert_events[0].x509
        second = cert_events[1].x509
        assert first.fingerprint == second.fingerprint
        assert first.certificate_serial == second.certificate_serial
        assert first.certificate_not_valid_before == second.certificate_not_valid_before
        assert first.certificate_not_valid_after == second.certificate_not_valid_after


class TestHttpContextPopulation:
    """Verify HTTP context is attached to connection events for port 80."""

    def test_http_service_gets_http_context(self, activity_gen):
        gen, events = activity_gen

        gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip="93.184.216.34",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=80,
            proto="tcp",
            service="http",
            duration=1.0,
            orig_bytes=200,
            resp_bytes=5000,
        )

        event = events[-1]
        if event.network.conn_state == "SF":
            assert event.http is not None
            assert event.http.method == "GET"
            assert event.http.host != ""
            assert event.http.uri.startswith("/")
            assert event.http.status_code in {200, 301, 302, 304, 403, 404, 500}

    def test_http_host_includes_port_for_non_standard(self, activity_gen):
        """Host header should include port for non-80/443 ports."""
        gen, events = activity_gen

        gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip="93.184.216.34",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=8080,
            proto="tcp",
            service="http",
            duration=1.0,
            orig_bytes=200,
            resp_bytes=5000,
        )

        event = events[-1]
        if event.http is not None:
            assert ":8080" in event.http.host

    def test_ssl_service_no_http_context(self, activity_gen):
        gen, events = activity_gen

        gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip="93.184.216.34",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=443,
            proto="tcp",
            service="ssl",
            duration=2.0,
            orig_bytes=1024,
            resp_bytes=4096,
        )

        event = events[-1]
        assert event.http is None

    def test_caller_provided_http_forces_conn_accounting_consistency(self, activity_gen):
        gen, events = activity_gen

        gen.generate_connection(
            src_ip="10.0.10.50",
            dst_ip="93.184.216.34",
            time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
            dst_port=80,
            proto="tcp",
            service="http",
            duration=1.0,
            orig_bytes=0,
            resp_bytes=0,
            conn_state="S1",
            http=HttpContext(
                method="GET",
                host="example.com",
                uri="/index.html",
                version="1.1",
                user_agent="Mozilla/5.0",
                response_body_len=4096,
                status_code=200,
                status_msg="OK",
            ),
        )

        event = events[-1]
        assert event.network.conn_state == "SF"
        assert event.network.resp_bytes >= event.http.response_body_len
        assert event.network.resp_pkts > 0


class TestFileTransferContext:
    """Verify FileTransferContext populated probabilistically for HTTP."""

    def test_file_transfer_sometimes_populated(self, activity_gen):
        """Over many HTTP connections, some should have FileTransferContext."""
        gen, events = activity_gen

        has_file_transfer = False
        for _ in range(100):
            gen.generate_connection(
                src_ip="10.0.10.50",
                dst_ip="93.184.216.34",
                time=datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC),
                dst_port=80,
                proto="tcp",
                service="http",
                duration=1.0,
                orig_bytes=200,
                resp_bytes=5000,
            )

        for event in events:
            if event.file_transfer is not None:
                has_file_transfer = True
                assert event.file_transfer.fuid.startswith("F")
                assert event.file_transfer.source == "HTTP"
                assert event.file_transfer.seen_bytes > 0
                if event.http is not None:
                    assert event.file_transfer.fuid in event.http.resp_fuids
                break

        assert has_file_transfer, (
            "Expected at least one FileTransferContext in 100 HTTP connections"
        )
