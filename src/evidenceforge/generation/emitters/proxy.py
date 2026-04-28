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

import random
from datetime import datetime, timedelta
from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.generation.emitters.host_base import HostMultiplexEmitter
from evidenceforge.utils.rng import _stable_seed

# CONNECT tunnel inactivity timeout (seconds).  A new CONNECT is emitted
# only when no tunnel exists for this (client_ip, host) pair, or the
# existing tunnel has been idle longer than this threshold.
_CONNECT_TUNNEL_TIMEOUT_S = 300  # 5 minutes


def _w3c_extended_field(value: Any) -> str:
    """Return a value safe for a W3C Extended whitespace-delimited field."""
    if value is None or value == "":
        return "-"
    text = str(value)
    if text == "-":
        return "-"
    return "+".join(text.split())


def _is_https_request(px: Any, net: Any) -> bool:
    """Return True when a proxy request represents inspected HTTPS traffic."""
    url = str(getattr(px, "url", "") or "")
    return url.lower().startswith("https://") or (net is not None and net.dst_port == 443)


def _connect_setup_fields(px: Any, request_time: datetime) -> dict[str, int | datetime]:
    """Derive CONNECT setup timing and byte fields distinct from inspected requests."""
    seed = _stable_seed(f"proxy-connect:{px.client_ip}:{px.host}:{request_time.timestamp()}")
    rng = random.Random(seed)
    host_len = len(str(px.host or ""))
    return {
        "timestamp": request_time - timedelta(milliseconds=rng.randint(80, 850)),
        "sc_bytes": rng.randint(90, 260),
        "cs_bytes": rng.randint(180 + host_len, 520 + host_len),
        "time_taken": rng.randint(20, 450),
    }


class ProxyEmitter(HostMultiplexEmitter):
    """Emitter for forward proxy access logs (W3C Extended Log Format).

    Per-host FQDN directory routing: each proxy server gets its own access log.

    Handles SecurityEvents with ProxyContext (fan-out from connection events).
    For HTTPS connections, emits a CONNECT entry only for the first request
    in a tunnel session (per client_ip + host), then subsequent requests
    reuse the existing tunnel without additional CONNECTs.
    """

    _log_filename = "proxy_access.log"
    _supported_types: set[str] = {"connection"}
    _sort_flat_file = True
    _defer_sorted_flush_until_close = True

    @staticmethod
    def _sort_key(line: str) -> tuple[datetime, str]:
        """Extract W3C date/time prefix for chronological flush sorting."""
        parts = line.split(maxsplit=2)
        if len(parts) < 2 or parts[0].startswith("#"):
            return (datetime.max, line)
        try:
            ts = datetime.strptime(f"{parts[0]} {parts[1]}", "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return (datetime.max, line)
        return (ts, line)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        # Track active CONNECT tunnels: (client_ip, host) -> last_activity_time
        self._active_tunnels: dict[tuple[str, str], datetime] = {}

    def can_handle(self, event: SecurityEvent) -> bool:
        """Handle connection events that carry a ProxyContext."""
        return event.event_type in self._supported_types and event.proxy is not None

    def emit(self, event: SecurityEvent) -> None:
        """Render ProxyContext to W3C Extended format.

        For HTTPS (port 443), emits CONNECT entry only for the first request
        to a (client_ip, host) pair within the tunnel timeout window.
        """
        px = event.proxy
        net = event.network

        # For HTTPS: emit CONNECT only if no active tunnel exists
        if _is_https_request(px, net) and px.method != "CONNECT":
            tunnel_key = (px.client_ip, px.host)
            last_activity = self._active_tunnels.get(tunnel_key)
            needs_connect = True
            if last_activity is not None:
                elapsed = (event.timestamp - last_activity).total_seconds()
                if elapsed < _CONNECT_TUNNEL_TIMEOUT_S:
                    needs_connect = False

            if needs_connect:
                setup = _connect_setup_fields(px, event.timestamp)
                connect_data = {
                    "timestamp": setup["timestamp"],
                    "client_ip": px.client_ip,
                    "username": px.username,
                    "method": "CONNECT",
                    "url": f"{px.host}:443",
                    "protocol": "HTTP/1.1",
                    "status_code": px.status_code,
                    "sc_bytes": setup["sc_bytes"],
                    "cs_bytes": setup["cs_bytes"],
                    "time_taken": setup["time_taken"],
                    "user_agent": px.user_agent,
                    "host": px.host,
                    "content_type": None,
                    "cache_result": "NONE",
                    "referrer": None,
                    "_host_fqdn": px.proxy_fqdn,
                }
                self._dispatch(connect_data)

            # Update tunnel last-activity timestamp
            self._active_tunnels[tunnel_key] = event.timestamp

        # Emit the actual request
        event_data = {
            "timestamp": event.timestamp,
            "client_ip": px.client_ip,
            "username": px.username,
            "method": px.method,
            "url": px.url,
            "protocol": "HTTP/1.1",
            "status_code": px.status_code,
            "sc_bytes": px.sc_bytes,
            "cs_bytes": px.cs_bytes,
            "time_taken": px.time_taken,
            "user_agent": px.user_agent,
            "host": px.host,
            "content_type": px.content_type,
            "cache_result": px.cache_result,
            "referrer": px.referrer or None,
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
            "client_ip": _w3c_extended_field(event_data.get("client_ip")),
            "username": _w3c_extended_field(event_data.get("username")),
            "method": _w3c_extended_field(event_data.get("method")),
            "url": _w3c_extended_field(event_data.get("url")),
            "protocol": _w3c_extended_field(event_data.get("protocol")),
            "status_code": event_data.get("status_code"),
            "sc_bytes": event_data.get("sc_bytes"),
            "cs_bytes": event_data.get("cs_bytes"),
            "time_taken": event_data.get("time_taken"),
            "user_agent": _w3c_extended_field(event_data.get("user_agent")),
            "host": _w3c_extended_field(event_data.get("host")),
            "content_type": _w3c_extended_field(event_data.get("content_type")),
            "cache_result": _w3c_extended_field(event_data.get("cache_result")),
            "referrer": _w3c_extended_field(event_data.get("referrer")),
        }
        rendered = self._template.render(**context)
        return rendered.strip()
