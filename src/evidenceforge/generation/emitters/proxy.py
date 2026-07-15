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

"""HTTP/HTTPS forward proxy access log emitter."""

import json
import random
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from evidenceforge.events.base import SecurityEvent
from evidenceforge.generation.activity.web_session_profiles import escape_log_control_chars
from evidenceforge.generation.emitters.host_base import HostMultiplexEmitter
from evidenceforge.output_targets import OutputTarget
from evidenceforge.utils.rng import _stable_seed

# CONNECT tunnel inactivity timeout (seconds).  A new CONNECT is emitted
# only when no tunnel exists for this (proxy_fqdn, client_ip, host, port)
# tuple, or the existing tunnel has been idle longer than this threshold.
_CONNECT_TUNNEL_TIMEOUT_S = 240  # about 4 minutes


def _combined_log_value(value: Any) -> str:
    """Return text safe for one Apache/Nginx combined-log physical line."""
    if value is None:
        return ""
    return escape_log_control_chars(str(value))


def _combined_log_token(value: Any) -> str:
    """Return a combined-log token safe inside the quoted request field."""
    text = _combined_log_value(value)
    if not text:
        return "-"
    return text.replace("\\", "\\\\").replace('"', r"\"")


def _sof_elk_combined_log_username(value: Any) -> str:
    """Return a SOF-ELK-compatible combined-log auth token."""
    text = _combined_log_value(value)
    if not text or text == "-":
        return ""
    account = text.rsplit("\\", maxsplit=1)[-1]
    if account.endswith("$"):
        return account[:-1]
    return account


def _combined_log_quoted(value: Any) -> str:
    """Return a value safe for an Apache/Nginx combined quoted field."""
    if value is None or value == "" or value == "-":
        return "-"
    return _combined_log_value(value).replace("\\", "\\\\").replace('"', r"\"")


def _is_https_request(px: Any, net: Any) -> bool:
    """Return True when a proxy request represents inspected HTTPS traffic."""
    url = str(getattr(px, "url", "") or "")
    return url.lower().startswith("https://") or (net is not None and net.dst_port == 443)


def _proxy_action(px: Any, *, setup: bool = False) -> str:
    """Return a source-native proxy action when the event did not set one."""
    if setup:
        return "tunnel-setup"
    action = str(getattr(px, "proxy_action", "") or "")
    if action:
        return action
    cache_result = str(getattr(px, "cache_result", "") or "").upper()
    status_code = int(getattr(px, "status_code", 0) or 0)
    if cache_result == "DENIED" or status_code == 403:
        return "deny"
    if cache_result == "AUTH_REQUIRED" or status_code == 407:
        return "auth-required"
    if cache_result == "GATEWAY_ERROR" or status_code in {502, 503, 504}:
        return "gateway-error"
    method = str(getattr(px, "method", "") or "").upper()
    url = str(getattr(px, "url", "") or "").lower()
    if method == "CONNECT":
        return "tunnel"
    if url.startswith("https://"):
        return "ssl-inspect"
    return "forward"


def _connect_setup_fields(px: Any, request_time: datetime) -> dict[str, int | datetime]:
    """Return action-planned CONNECT setup fields, with raw-event compatibility."""

    transaction = getattr(px, "transaction", None)
    if transaction is not None and transaction.tunnel_request_at is not None:
        return {
            "timestamp": transaction.tunnel_request_at,
            "sc_bytes": transaction.tunnel_setup_sc_bytes,
            "cs_bytes": transaction.tunnel_setup_cs_bytes,
            "time_taken": transaction.tunnel_setup_time_taken_ms,
        }
    seed = _stable_seed(f"proxy-connect:{px.client_ip}:{px.host}:{request_time.timestamp()}")
    rng = random.Random(seed)
    host_len = len(str(px.host or ""))
    return {
        "timestamp": request_time,
        "sc_bytes": rng.randint(90, 260),
        "cs_bytes": rng.randint(180 + host_len, 520 + host_len),
        "time_taken": rng.randint(20, 450),
    }


def _splunk_json_timestamp(value: datetime | str | None) -> str:
    """Return a timestamp accepted by the Apache TA JSON stanza."""
    if isinstance(value, datetime):
        timestamp = value
        if timestamp.tzinfo is not None:
            timestamp = timestamp.astimezone(UTC)
        return timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    if value:
        return str(value)
    return ""


def _int_value(value: object, default: int = 0) -> int:
    """Return *value* as an int, falling back for blank proxy fields."""
    if value in (None, "", "-"):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _proxy_url_parts(
    *,
    method: str,
    url: str,
    host: str,
    fallback_port: int,
) -> tuple[str, int, str, str]:
    """Return Apache TA JSON server, port, path, and query values for a proxy URL."""
    method_upper = method.upper()
    if method_upper == "CONNECT":
        authority = url or host
        server, separator, port_text = authority.partition(":")
        return (
            server or host,
            _int_value(port_text, fallback_port or 443) if separator else fallback_port or 443,
            "/",
            "",
        )

    request_url = url or "/"
    try:
        parsed = urlsplit(request_url)
        server = parsed.hostname or host
        parsed_port = parsed.port
    except ValueError:
        return host, fallback_port, request_url or "/", ""

    if parsed_port is not None:
        dest_port = parsed_port
    elif parsed.scheme.lower() == "https":
        dest_port = 443
    elif parsed.scheme.lower() == "http":
        dest_port = 80
    else:
        dest_port = fallback_port
    if parsed.scheme or parsed.netloc:
        path = parsed.path or "/"
    else:
        path = parsed.path or url or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    return server, dest_port, path, query


def _proxy_url_category(event_data: dict[str, Any]) -> str:
    """Return a coarse URL category for CIM proxy validation."""
    action = str(event_data.get("proxy_action") or "").lower()
    cache_result = str(event_data.get("cache_result") or "").upper()
    host = str(event_data.get("host") or "")
    content_type = str(event_data.get("content_type") or "")
    if action in {"deny", "auth-required"} or cache_result in {"DENIED", "AUTH_REQUIRED"}:
        return "Blocked"
    if any(token in host.lower() for token in ("update", "cdn", "download", "packages")):
        return "Software/Updates"
    if content_type.startswith(("application/", "text/javascript", "text/css")):
        return "Technology"
    return "Business/Economy"


def _ssl_bump_action(event_data: dict[str, Any]) -> str:
    """Return source-native TLS inspection metadata for proxy access rows."""
    action = str(event_data.get("proxy_action") or "").lower()
    method = str(event_data.get("method") or "").upper()
    url = str(event_data.get("url") or "").lower()
    status_code = _int_value(event_data.get("status_code"), 0)
    if action == "ssl-inspect":
        return "bump"
    if url.startswith("https://") and method != "CONNECT":
        return "bump"
    if action == "tunnel-setup":
        return "peek"
    if method == "CONNECT" and (action in {"deny", "auth-required"} or status_code >= 400):
        return "terminate"
    return ""


def _proxy_metadata(event_data: dict[str, Any]) -> str:
    """Return optional key-value metadata for extended proxy combined logs."""
    parts: list[str] = []
    cs_bytes = event_data.get("cs_bytes")
    if cs_bytes not in {None, ""}:
        parts.append(f"cs_bytes={_int_value(cs_bytes, 0)}")
    sc_bytes = event_data.get("sc_bytes")
    if sc_bytes not in {None, ""}:
        parts.append(f"sc_bytes={_int_value(sc_bytes, 0)}")
    proxy_action = str(event_data.get("proxy_action") or "")
    if proxy_action:
        parts.append(f"proxy_action={proxy_action}")
    ssl_bump = _ssl_bump_action(event_data)
    if ssl_bump:
        parts.append(f"ssl_bump={ssl_bump}")
    return " ".join(parts)


class ProxyEmitter(HostMultiplexEmitter):
    """Emitter for forward proxy access logs.

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
        """Extract proxy access timestamps for chronological flush sorting."""
        if line.startswith("{"):
            try:
                timestamp = json.loads(line).get("timestamp", "")
                parsed = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
            except (AttributeError, TypeError, ValueError, json.JSONDecodeError):
                return (datetime.max, line)
            return (parsed, line)

        start = line.find("[")
        end = line.find("]", start + 1)
        if start != -1 and end != -1:
            try:
                ts = datetime.strptime(line[start + 1 : end], "%d/%b/%Y:%H:%M:%S %z")
            except ValueError:
                return (datetime.max, line)
            return (ts, line)

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
        # Track active CONNECT tunnels:
        # (proxy_fqdn, client_ip, host, dst_port) -> last_activity_time
        self._active_tunnels: dict[tuple[str, str, str, int], datetime] = {}

    def _get_writer(self, host_fqdn: str) -> Any:
        """Return a host writer, suppressing text headers for Splunk JSON output."""
        if self.output_target != OutputTarget.SPLUNK:
            return super()._get_writer(host_fqdn)
        header_template = self.format_def.output.header_template
        self.format_def.output.header_template = None
        try:
            return super()._get_writer(host_fqdn)
        finally:
            self.format_def.output.header_template = header_template

    def can_handle(self, event: SecurityEvent) -> bool:
        """Handle connection events that carry a ProxyContext."""
        return event.event_type in self._supported_types and event.proxy is not None

    def emit(self, event: SecurityEvent) -> None:
        """Render ProxyContext to the configured proxy access format.

        For HTTPS (port 443), emits CONNECT entry only for the first request
        to a (proxy_fqdn, client_ip, host, dst_port) tuple within the tunnel timeout window.
        """
        px = event.proxy
        net = event.network
        request_time = px.transaction.request_at if px.transaction is not None else event.timestamp

        # For HTTPS: emit CONNECT only if no active tunnel exists
        if _is_https_request(px, net) and px.method != "CONNECT":
            dst_port = net.dst_port if net is not None and net.dst_port else 443
            tunnel_key = (px.proxy_fqdn, px.client_ip, px.host, dst_port)
            last_activity = self._active_tunnels.get(tunnel_key)
            needs_connect = True
            if last_activity is not None:
                elapsed = (request_time - last_activity).total_seconds()
                if 0 <= elapsed < _CONNECT_TUNNEL_TIMEOUT_S:
                    needs_connect = False

            if needs_connect:
                setup = _connect_setup_fields(px, request_time)
                connect_data = {
                    "timestamp": setup["timestamp"],
                    "client_ip": px.client_ip,
                    "username": px.username,
                    "method": "CONNECT",
                    "url": f"{px.host}:443",
                    "protocol": "HTTP/1.1",
                    "status_code": px.tunnel_status_code
                    if px.tunnel_status_code is not None
                    else 200,
                    "sc_bytes": setup["sc_bytes"],
                    "cs_bytes": setup["cs_bytes"],
                    "time_taken": setup["time_taken"],
                    "user_agent": px.user_agent,
                    "host": px.host,
                    "content_type": None,
                    "cache_result": "NONE",
                    "referrer": None,
                    "proxy_action": _proxy_action(px, setup=True),
                    "_host_fqdn": px.proxy_fqdn,
                }
                self._dispatch(connect_data)

            # Update tunnel last-activity timestamp
            self._active_tunnels[tunnel_key] = request_time

        # Emit the actual request
        event_data = {
            "timestamp": request_time,
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
            "proxy_action": _proxy_action(px),
            "_host_fqdn": px.proxy_fqdn,
        }
        self._dispatch(event_data)

    def _dispatch(self, event_data: dict[str, Any]) -> None:
        """Route proxy access event to per-host file."""
        rendered = self._render_event(event_data)
        host_fqdn = event_data.pop("_host_fqdn", "")
        self.emit_to_host(rendered, host_fqdn)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        """Render proxy access log entry."""
        if self.output_target == OutputTarget.SPLUNK:
            return self._render_splunk_json_event(event_data)

        context = {
            "timestamp": event_data.get("timestamp"),
            "client_ip": _combined_log_value(event_data.get("client_ip")),
            "username": (
                _sof_elk_combined_log_username(event_data.get("username"))
                if self.output_target == OutputTarget.SOF_ELK
                else _combined_log_value(event_data.get("username"))
            ),
            "method": _combined_log_token(event_data.get("method")),
            "url": _combined_log_token(event_data.get("url")),
            "protocol": _combined_log_token(event_data.get("protocol")),
            "status_code": event_data.get("status_code"),
            "sc_bytes": event_data.get("sc_bytes"),
            "user_agent": _combined_log_quoted(event_data.get("user_agent")),
            "referrer": _combined_log_quoted(event_data.get("referrer")),
            "proxy_metadata": ""
            if self.output_target == OutputTarget.SOF_ELK
            else _combined_log_quoted(_proxy_metadata(event_data)),
        }
        rendered = self._template.render(**context)
        return rendered.strip()

    def _render_splunk_json_event(self, event_data: dict[str, Any]) -> str:
        """Render proxy access as Apache TA JSON plus proxy classification fields."""
        method = str(event_data.get("method") or "")
        fallback_port = (
            443 if str(event_data.get("url") or "").lower().startswith("https://") else 80
        )
        server, dest_port, uri_path, uri_query = _proxy_url_parts(
            method=method,
            url=str(event_data.get("url") or ""),
            host=str(event_data.get("host") or ""),
            fallback_port=fallback_port,
        )
        proxy_action = str(event_data.get("proxy_action") or "")
        record = {
            "timestamp": _splunk_json_timestamp(event_data.get("timestamp")),
            "client": str(event_data.get("client_ip") or ""),
            "server": server,
            "dest_port": dest_port,
            "ident": "-",
            "user": str(event_data.get("username") or "-"),
            "http_method": method,
            "uri_path": uri_path,
            "uri_query": uri_query,
            "http_version": str(event_data.get("protocol") or "HTTP/1.1"),
            "status": _int_value(event_data.get("status_code"), 0),
            "http_referrer": str(event_data.get("referrer") or ""),
            "http_user_agent": str(event_data.get("user_agent") or ""),
            "bytes_in": _int_value(event_data.get("cs_bytes"), 0),
            "bytes_out": _int_value(event_data.get("sc_bytes"), 0),
            "response_time_microseconds": _int_value(event_data.get("time_taken"), 0) * 1000,
            "cache_result": str(event_data.get("cache_result") or ""),
            "proxy_action": proxy_action,
            "url_category": _proxy_url_category(event_data),
        }
        ssl_bump_action = _ssl_bump_action(event_data)
        if ssl_bump_action:
            record["ssl_bump_action"] = ssl_bump_action
        content_type = event_data.get("content_type")
        if content_type:
            record["http_content_type"] = str(content_type)
        return json.dumps(record, sort_keys=True, separators=(",", ":"))
