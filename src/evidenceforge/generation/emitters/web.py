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

import json
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from evidenceforge.events.base import SecurityEvent
from evidenceforge.generation.activity.web_session_profiles import escape_log_control_chars
from evidenceforge.generation.emitters.host_base import HostMultiplexEmitter
from evidenceforge.output_targets import OutputTarget


def _combined_log_value(value: str | None) -> str:
    """Return text safe for one Apache/Nginx combined-log physical line."""
    if value is None:
        return ""
    return escape_log_control_chars(str(value))


def _combined_log_quoted(value: str | None) -> str:
    """Return a value safe for an Apache/Nginx combined quoted field."""
    if not value or value == "-":
        return "-"
    return _combined_log_value(value).replace("\\", "\\\\").replace('"', r"\"")


def _splunk_json_timestamp(value: datetime | str | None) -> str:
    """Return an RFC3339-ish timestamp accepted by the Apache TA JSON stanza."""
    if isinstance(value, datetime):
        timestamp = value
        if timestamp.tzinfo is not None:
            timestamp = timestamp.astimezone(UTC)
        return timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    if value:
        return str(value)
    return ""


def _split_uri_for_apache_json(uri: str | None) -> tuple[str, str]:
    """Split a request target into Apache TA JSON path and query fields."""
    request_uri = uri or "/"
    parsed = urlsplit(request_uri)
    if parsed.scheme or parsed.netloc:
        path = parsed.path or "/"
    else:
        path = parsed.path or request_uri or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    return path, query


def _int_value(value: object, default: int = 0) -> int:
    """Return *value* as an int, falling back for blank Apache-style fields."""
    if value in (None, "", "-"):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _response_time_microseconds(event: SecurityEvent) -> int:
    """Return an approximate web response time for Apache TA JSON records."""
    duration = event.network.duration if event.network else None
    if duration is None or duration <= 0:
        return 0
    return max(1, int(duration * 1_000_000))


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
    def _sort_key(line: str) -> tuple[datetime, str]:
        """Extract Apache/Nginx Combined Log timestamp for chronological flush sorting."""
        if line.startswith("{"):
            try:
                timestamp = json.loads(line).get("timestamp", "")
                parsed = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
            except (AttributeError, TypeError, ValueError, json.JSONDecodeError):
                return (datetime.max, line)
            return (parsed, line)

        start = line.find("[")
        end = line.find("]", start + 1)
        if start == -1 or end == -1:
            return (datetime.max, line)
        try:
            ts = datetime.strptime(line[start + 1 : end], "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            return (datetime.max, line)
        return (ts, line)

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
        """Render HttpContext to the configured web access format."""
        http = event.http
        # Web access logs are written on the web server (dst_host)
        host = event.dst_host
        net = event.network
        host_fqdn = host.fqdn or host.hostname

        if self.output_target == OutputTarget.SPLUNK:
            uri_path, uri_query = _split_uri_for_apache_json(http.uri)
            event_data = {
                "timestamp": event.timestamp,
                "client": net.src_ip if net else "",
                "server": http.host or host_fqdn,
                "dest_port": net.dst_port if net else 0,
                "ident": "-",
                "user": "-",
                "http_method": http.method,
                "uri_path": uri_path,
                "uri_query": uri_query,
                "http_version": f"HTTP/{http.version}",
                "status": http.status_code,
                "http_referrer": http.referrer if http.referrer != "-" else "",
                "http_user_agent": http.user_agent,
                "bytes_in": http.request_body_len,
                "bytes_out": http.response_body_len,
                "response_time_microseconds": _response_time_microseconds(event),
                "http_content_type": http.resp_mime_types[0] if http.resp_mime_types else "",
                "_host_fqdn": host_fqdn,
            }
        else:
            event_data = {
                "timestamp": event.timestamp,
                "client_ip": net.src_ip if net else "",
                "username": "-",
                "method": _combined_log_value(http.method),
                "path": _combined_log_value(http.uri),
                "protocol": _combined_log_value(f"HTTP/{http.version}"),
                "status_code": http.status_code,
                "bytes_sent": http.response_body_len,
                "referer": _combined_log_quoted(http.referrer),
                "user_agent": _combined_log_quoted(http.user_agent),
                "_host_fqdn": host_fqdn,
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
        if self.output_target == OutputTarget.SPLUNK:
            return self._render_splunk_json_event(event_data)

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

    def _render_splunk_json_event(self, event_data: dict[str, Any]) -> str:
        """Render an Apache TA `apache:access:json` access event."""
        path, query = _split_uri_for_apache_json(str(event_data.get("path") or "/"))
        record = {
            "timestamp": _splunk_json_timestamp(event_data.get("timestamp")),
            "client": str(event_data.get("client") or event_data.get("client_ip") or ""),
            "server": str(event_data.get("server") or event_data.get("dest_host") or ""),
            "dest_port": _int_value(event_data.get("dest_port"), 0),
            "ident": str(event_data.get("ident") or "-"),
            "user": str(event_data.get("user") or event_data.get("username") or "-"),
            "http_method": str(event_data.get("http_method") or event_data.get("method") or ""),
            "uri_path": str(event_data.get("uri_path") or path),
            "uri_query": str(event_data.get("uri_query") or query),
            "http_version": str(event_data.get("http_version") or event_data.get("protocol") or ""),
            "status": _int_value(event_data.get("status") or event_data.get("status_code"), 0),
            "http_referrer": str(
                event_data.get("http_referrer") or event_data.get("referer") or ""
            ),
            "http_user_agent": str(
                event_data.get("http_user_agent") or event_data.get("user_agent") or ""
            ),
            "bytes_in": _int_value(event_data.get("bytes_in"), 0),
            "bytes_out": _int_value(event_data.get("bytes_out") or event_data.get("bytes_sent"), 0),
            "response_time_microseconds": _int_value(
                event_data.get("response_time_microseconds"), 0
            ),
        }
        content_type = event_data.get("http_content_type") or event_data.get("content_type")
        if content_type:
            record["http_content_type"] = str(content_type)
        return json.dumps(record, sort_keys=True, separators=(",", ":"))
