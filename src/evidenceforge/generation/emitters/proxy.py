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

"""HTTP/HTTPS forward proxy access log emitter (W3C Extended format)."""

from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.generation.emitters.host_base import HostMultiplexEmitter


class ProxyEmitter(HostMultiplexEmitter):
    """Emitter for forward proxy access logs (W3C Extended Log Format).

    Per-host FQDN directory routing: each proxy server gets its own access log.

    Handles SecurityEvents with ProxyContext (fan-out from connection events).
    For HTTPS connections, emits a CONNECT entry followed by the actual request.
    """

    _log_filename = "proxy_access.log"
    _supported_types: set[str] = {"connection"}

    def can_handle(self, event: SecurityEvent) -> bool:
        """Handle connection events that carry a ProxyContext."""
        return event.event_type in self._supported_types and event.proxy is not None

    def emit(self, event: SecurityEvent) -> None:
        """Render ProxyContext to W3C Extended format.

        For HTTPS (port 443), emits CONNECT entry first, then the actual request.
        """
        px = event.proxy
        net = event.network

        # For HTTPS: emit CONNECT entry first (unless generator already set CONNECT)
        if net and net.dst_port == 443 and px.method != "CONNECT":
            connect_data = {
                "timestamp": event.timestamp,
                "client_ip": px.client_ip,
                "username": px.username,
                "method": "CONNECT",
                "url": f"{px.host}:443",
                "status_code": 200,
                "sc_bytes": 0,
                "cs_bytes": 0,
                "time_taken": 0,
                "user_agent": px.user_agent,
                "host": f"{px.host}:443",
                "content_type": None,
                "cache_result": "NONE",
                "_host_fqdn": px.proxy_fqdn,
            }
            self._dispatch(connect_data)

        # Emit the actual request
        event_data = {
            "timestamp": event.timestamp,
            "client_ip": px.client_ip,
            "username": px.username,
            "method": px.method,
            "url": px.url,
            "status_code": px.status_code,
            "sc_bytes": px.sc_bytes,
            "cs_bytes": px.cs_bytes,
            "time_taken": px.time_taken,
            "user_agent": px.user_agent,
            "host": px.host,
            "content_type": px.content_type,
            "cache_result": px.cache_result,
            "_host_fqdn": px.proxy_fqdn,
        }
        self._dispatch(event_data)

    def _dispatch(self, event_data: dict[str, Any]) -> None:
        """Route proxy access event to per-host file."""
        rendered = self._render_event(event_data)
        host_fqdn = event_data.pop("_host_fqdn", "")
        self.emit_to_host(rendered, host_fqdn)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        """Render proxy access log entry in W3C Extended format."""
        context = {
            "timestamp": event_data.get("timestamp"),
            "client_ip": event_data.get("client_ip"),
            "username": event_data.get("username"),
            "method": event_data.get("method"),
            "url": event_data.get("url"),
            "status_code": event_data.get("status_code"),
            "sc_bytes": event_data.get("sc_bytes"),
            "cs_bytes": event_data.get("cs_bytes"),
            "time_taken": event_data.get("time_taken"),
            "user_agent": event_data.get("user_agent"),
            "host": event_data.get("host"),
            "content_type": event_data.get("content_type"),
            "cache_result": event_data.get("cache_result"),
        }
        rendered = self._template.render(**context)
        return rendered.strip()
