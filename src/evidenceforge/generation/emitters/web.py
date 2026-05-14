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

"""Web server access log emitter."""

from datetime import datetime
from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.generation.emitters.host_base import HostMultiplexEmitter


def _combined_log_quoted(value: str | None) -> str:
    """Return a value safe for an Apache/Nginx combined quoted field."""
    if not value or value == "-":
        return "-"
    return value.replace("\\", "\\\\").replace('"', r"\"")


class WebEmitter(HostMultiplexEmitter):
    """Emitter for Apache/Nginx combined web server access logs.

    Per-host FQDN directory routing: each web server gets its own access log.

    Handles SecurityEvents with HttpContext (fan-out from connection events
    to web servers) and raw dict events from baseline web traffic generation.
    """

    _log_filename = "web_access.log"
    _supported_types: set[str] = {"connection"}
    _sort_flat_file = True
    _defer_sorted_flush_until_close = True

    @staticmethod
    def _sort_key(line: str) -> tuple[datetime, str, int, str]:
        """Extract a stable chronological key for Combined Log sorting.

        The rendered format has only second-level precision. When page HTML
        and subresources land in the same rendered second, keep document
        requests before assets so referrer chains read like browser fetches.
        """
        start = line.find("[")
        end = line.find("]", start + 1)
        if start == -1 or end == -1:
            return (datetime.max, "", 99, line)
        try:
            ts = datetime.strptime(line[start + 1 : end], "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            return (datetime.max, "", 99, line)
        client_ip = line.split(" ", 1)[0]
        path = ""
        quote_start = line.find('"')
        quote_end = line.find('"', quote_start + 1)
        if quote_start != -1 and quote_end != -1:
            request = line[quote_start + 1 : quote_end]
            parts = request.split(" ")
            if len(parts) >= 2:
                path = parts[1]
        return (ts, client_ip, _request_sort_bucket(path), line)

    def can_handle(self, event: SecurityEvent) -> bool:
        """Handle connection events that carry an HttpContext and target a web server.

        Only fires when dst_host has the 'web_server' role.  Two earlier
        constraints prevent adjacent misrouting:
        - dst_host must be set (avoids writing on the source workstation for
          outbound HTTPS browsing sessions).
        - dst_host must have role 'web_server' (avoids writing on hosts that
          happen to receive HTTP on internal management ports — e.g., WSUS on
          8530 targeting Windows workstations).
        """
        return (
            event.event_type in self._supported_types
            and event.http is not None
            and event.dst_host is not None
            and "web_server" in event.dst_host.roles
        )

    def emit(self, event: SecurityEvent) -> None:
        """Render HttpContext to Combined Log Format."""
        http = event.http
        # Web access logs are written on the web server (dst_host)
        host = event.dst_host
        net = event.network

        event_data = {
            "timestamp": event.timestamp,
            "client_ip": net.src_ip if net else "",
            "username": "-",
            "method": http.method,
            "path": http.uri,
            "protocol": f"HTTP/{http.version}",
            "status_code": http.status_code,
            "bytes_sent": http.response_body_len,
            "referer": _combined_log_quoted(http.referrer),
            "user_agent": _combined_log_quoted(http.user_agent),
            "_host_fqdn": host.fqdn or host.hostname,
        }
        self._dispatch(event_data)

    def _dispatch(self, event_data: dict[str, Any]) -> None:
        """Route web access event to per-host file."""
        rendered = self._render_event(event_data)
        host_fqdn = event_data.pop("_host_fqdn", "")
        self.emit_to_host(rendered, host_fqdn)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        """Render web access log entry.

        Format: <client_ip> - <username> [<timestamp>] "<method> <path> <protocol>" <status> <bytes> "<referer>" "<user_agent>"
        """
        context = {
            "timestamp": event_data.get("timestamp"),
            "client_ip": event_data.get("client_ip"),
            "username": event_data.get("username"),
            "method": event_data.get("method"),
            "path": event_data.get("path"),
            "protocol": event_data.get("protocol"),
            "status_code": event_data.get("status_code"),
            "bytes_sent": event_data.get("bytes_sent"),
            "referer": event_data.get("referer"),
            "user_agent": event_data.get("user_agent"),
        }

        # Render template
        rendered = self._template.render(**context)
        return rendered.strip()


def _request_sort_bucket(path: str) -> int:
    """Order same-second web requests so documents precede dependent assets."""
    static_prefixes = (
        "/assets/",
        "/static/",
        "/favicon.ico",
        "/images/",
        "/img/",
        "/fonts/",
    )
    static_suffixes = (
        ".css",
        ".js",
        ".mjs",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".webp",
        ".ico",
        ".woff",
        ".woff2",
    )
    if path.startswith(static_prefixes) or path.endswith(static_suffixes):
        return 1
    if path.startswith(("/api/", "/graphql", "/owa/service.svc")):
        return 2
    return 0
