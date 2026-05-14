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

"""Tests for WebEmitter role-gated can_handle() logic."""

from datetime import UTC, datetime

import pytest

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import HostContext, HttpContext, NetworkContext
from evidenceforge.formats import load_format
from evidenceforge.generation.emitters.web import WebEmitter


def _make_host(system_type: str, roles: list[str]) -> HostContext:
    return HostContext(
        hostname="target",
        ip="10.0.0.5",
        os="Linux Ubuntu 24.04",
        os_category="linux",
        system_type=system_type,
        roles=roles,
    )


def _make_event(
    dst_host: HostContext | None,
    http: HttpContext | None,
    timestamp: datetime | None = None,
) -> SecurityEvent:
    return SecurityEvent(
        timestamp=timestamp or datetime(2024, 7, 15, 12, 0, 0, tzinfo=UTC),
        event_type="connection",
        dst_host=dst_host,
        http=http,
        network=NetworkContext(
            src_ip="192.168.1.10",
            src_port=54321,
            dst_ip="10.0.0.5",
            dst_port=80,
            protocol="tcp",
        ),
    )


_HTTP = HttpContext(
    method="GET",
    host="web01.example.com",
    uri="/index.html",
    version="1.1",
    user_agent="Mozilla/5.0",
    request_body_len=0,
    response_body_len=1024,
    status_code=200,
    status_msg="OK",
    referrer="-",
    resp_mime_types=["text/html"],
    tags=[],
)


@pytest.fixture
def emitter(tmp_path):
    fmt = load_format("web_access")
    return WebEmitter(fmt, tmp_path)


class TestWebEmitterCanHandle:
    def test_web_server_role_accepted(self, emitter):
        host = _make_host("server", ["web_server"])
        event = _make_event(dst_host=host, http=_HTTP)
        assert emitter.can_handle(event) is True

    def test_workstation_no_role_rejected(self, emitter):
        """Regression: WSUS→workstation HTTP (port 8530) must not emit web_access."""
        host = _make_host("workstation", [])
        event = _make_event(dst_host=host, http=_HTTP)
        assert emitter.can_handle(event) is False

    def test_server_without_web_server_role_rejected(self, emitter):
        host = _make_host("server", ["dns_server", "mail_server"])
        event = _make_event(dst_host=host, http=_HTTP)
        assert emitter.can_handle(event) is False

    def test_no_dst_host_rejected(self, emitter):
        event = _make_event(dst_host=None, http=_HTTP)
        assert emitter.can_handle(event) is False

    def test_no_http_context_rejected(self, emitter):
        host = _make_host("server", ["web_server"])
        event = _make_event(dst_host=host, http=None)
        assert emitter.can_handle(event) is False

    def test_wrong_event_type_rejected(self, emitter):
        host = _make_host("server", ["web_server"])
        event = SecurityEvent(
            timestamp=datetime(2024, 7, 15, 12, 0, 0, tzinfo=UTC),
            event_type="logon",
            dst_host=host,
            http=_HTTP,
        )
        assert emitter.can_handle(event) is False

    def test_multiple_roles_including_web_server_accepted(self, emitter):
        host = _make_host("server", ["web_server", "forward_proxy"])
        event = _make_event(dst_host=host, http=_HTTP)
        assert emitter.can_handle(event) is True

    def test_web_access_flush_sorts_by_request_timestamp(self, tmp_path):
        """Out-of-order web events should be written chronologically per host."""
        fmt = load_format("web_access")
        emitter = WebEmitter(fmt, tmp_path, buffer_size=2)
        host = _make_host("server", ["web_server"])

        for ts in [
            datetime(2024, 7, 15, 12, 5, 0, tzinfo=UTC),
            datetime(2024, 7, 15, 12, 1, 0, tzinfo=UTC),
            datetime(2024, 7, 15, 12, 3, 0, tzinfo=UTC),
        ]:
            emitter.emit(_make_event(dst_host=host, http=_HTTP, timestamp=ts))

        emitter.close()

        lines = (tmp_path / "target" / "web_access.log").read_text().splitlines()
        assert "[15/Jul/2024:12:01:00 +0000]" in lines[0]
        assert "[15/Jul/2024:12:03:00 +0000]" in lines[1]
        assert "[15/Jul/2024:12:05:00 +0000]" in lines[2]

    def test_web_access_same_second_sort_keeps_page_before_assets(self, tmp_path):
        """Same-second rendered logs should keep document requests before subresources."""
        fmt = load_format("web_access")
        emitter = WebEmitter(fmt, tmp_path, buffer_size=10)
        host = _make_host("server", ["web_server"])
        ts = datetime(2024, 7, 15, 12, 1, 0, 500000, tzinfo=UTC)

        for path, referrer in [
            ("/assets/js/app.bundle.12345678.js", "https://web01.example.com/blog"),
            ("/assets/css/main.12345678.css", "https://web01.example.com/blog"),
            ("/blog", "https://web01.example.com/"),
        ]:
            http = HttpContext(
                method="GET",
                host="web01.example.com",
                uri=path,
                version="1.1",
                user_agent="Mozilla/5.0",
                response_body_len=1024,
                status_code=200,
                referrer=referrer,
            )
            emitter.emit(_make_event(dst_host=host, http=http, timestamp=ts))

        emitter.close()

        lines = (tmp_path / "target" / "web_access.log").read_text().splitlines()
        assert '"GET /blog HTTP/1.1"' in lines[0]
        assert '"GET /assets/' in lines[1]
        assert '"GET /assets/' in lines[2]

    def test_combined_log_quoted_fields_are_escaped(self, emitter):
        """Referer and User-Agent quotes should not break combined-log fields."""
        host = _make_host("server", ["web_server"])
        http = HttpContext(
            method="GET",
            host="web01.example.com",
            uri="/index.html",
            version="1.1",
            user_agent='Mozilla/5.0 "Test"',
            response_body_len=1024,
            status_code=200,
            referrer='https://example.com/search?q="quoted"',
        )
        event = _make_event(dst_host=host, http=http)
        rendered_lines = []
        emitter.emit_to_host = lambda line, fqdn: rendered_lines.append(line)

        emitter.emit(event)

        assert r'"https://example.com/search?q=\"quoted\""' in rendered_lines[0]
        assert r'"Mozilla/5.0 \"Test\""' in rendered_lines[0]
