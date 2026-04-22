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

from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.generation.emitters.host_base import HostMultiplexEmitter


class WebEmitter(HostMultiplexEmitter):
    """Emitter for W3C web server access logs (Apache/Nginx Combined Log Format).

    Per-host FQDN directory routing: each web server gets its own access log.

    Handles SecurityEvents with HttpContext (fan-out from connection events
    to web servers) and raw dict events from baseline web traffic generation.
    """

    _log_filename = "web_access.log"
    _supported_types: set[str] = {"connection"}

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
            "referer": http.referrer or "-",
            "user_agent": http.user_agent,
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
