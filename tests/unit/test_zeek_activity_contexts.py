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

from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest

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
