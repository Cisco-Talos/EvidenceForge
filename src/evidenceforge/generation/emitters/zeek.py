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

"""Zeek conn.log emitter."""

from typing import Any

from evidenceforge.events.base import CanonicalOccurrence
from evidenceforge.events.network import normalize_zeek_history
from evidenceforge.generation.emitters.zeek_base import (
    SensorMultiplexEmitter,
    direct_zeek_source_duration,
    direct_zeek_source_time,
)
from evidenceforge.generation.network_observation import network_source_timing_key

_ZEEK_SERVICE_ALIASES: dict[str, str] = {
    "kerberos": "krb",
    "mssql": "tds",
    "sql": "tds",
    "sqlserver": "tds",
    "ms-sql": "tds",
    "rpc": "dce_rpc",
}


def _tls_completed_duration_floor(
    event: CanonicalOccurrence,
    min_ms: int,
    max_ms: int,
) -> float:
    """Compatibility view of the planner-owned direct TLS duration."""

    del min_ms, max_ms
    duration = direct_zeek_source_duration(
        event,
        network_source_timing_key("zeek_conn"),
    )
    return float(duration or 0.0)


class ZeekEmitter(SensorMultiplexEmitter):
    """Emitter for Zeek conn.log format (JSON).

    Generates Zeek connection logs in JSON format (one JSON object per line).
    Each connection includes source/dest IPs, ports, protocol, and connection state.
    """

    _log_filename = "conn.json"
    _flat_filename = "zeek_conn.json"
    _supported_types: set[str] = {"connection", "dhcp_lease"}
    supports_exact_projection_publication = True

    def can_handle(self, event: CanonicalOccurrence) -> bool:
        """Zeek conn emitter handles canonical network transport events."""
        return (
            event.event_type in self._supported_types
            and event.network is not None
            and not event.network.application_layer_only
        )

    @staticmethod
    def _normalize_history_for_state(conn_state: str, history: str) -> str:
        """Keep generated Zeek history direction consistent with conn_state semantics."""
        return normalize_zeek_history(conn_state, history)

    @staticmethod
    def _render_service_name(service: str | None) -> str | None:
        """Render canonical services using Zeek analyzer vocabulary."""
        if not service:
            return None
        normalized = service.strip().lower()
        return _ZEEK_SERVICE_ALIASES.get(normalized, normalized)

    def emit(self, event: CanonicalOccurrence) -> None:
        """Render CanonicalOccurrence to Zeek conn.log format."""
        net = event.network
        duration = net.duration
        src_ip = net.src_ip
        dst_ip = net.dst_ip
        src_port = net.src_port
        dst_port = net.dst_port
        conn_state = net.conn_state
        history = self._normalize_history_for_state(net.conn_state, net.history)
        if net.protocol == "icmp":
            src_port = net.src_port if net.src_port else 8
            dst_port = net.dst_port if net.dst_port else 0
            if (net.resp_bytes or 0) > 0:
                conn_state = "SF"
                history = "Dd"
            else:
                conn_state = "S0"
                history = "D"
        if event.event_type == "dhcp_lease" and event.dhcp is not None:
            msg_types = set(event.dhcp.msg_types)
            if "DISCOVER" in msg_types:
                src_ip = "0.0.0.0"
                dst_ip = "255.255.255.255"
        timing_key = network_source_timing_key("zeek_conn")
        if event.network_observations_planned:
            event_ts = net.started_at
            planned_duration = net.duration
        else:
            event_ts = direct_zeek_source_time(event, timing_key)
            planned_duration = direct_zeek_source_duration(event, timing_key)
        if planned_duration is not None:
            duration = planned_duration
        event_data = {
            "ts": event_ts,
            "uid": net.zeek_uid,
            "id.orig_h": src_ip,
            "id.orig_p": src_port,
            "id.resp_h": dst_ip,
            "id.resp_p": dst_port,
            "proto": net.protocol,
            "service": self._render_service_name(net.service),
            "duration": duration,
            "_min_duration": event.dns.rtt if event.dns is not None else None,
            "_lock_duration": event.dns is not None
            or event.protocol.primary_file_transfer is not None
            or event.protocol.leaf_certificate is not None
            or bool(event.protocol.x509_chain),
            "orig_bytes": net.orig_bytes,
            "resp_bytes": net.resp_bytes,
            "conn_state": conn_state,
            "local_orig": net.local_orig,
            "local_resp": net.local_resp,
            "missed_bytes": net.missed_bytes,
            "history": history,
            "orig_pkts": net.orig_pkts,
            "orig_ip_bytes": net.orig_ip_bytes,
            "resp_pkts": net.resp_pkts,
            "resp_ip_bytes": net.resp_ip_bytes,
            "ip_proto": net.ip_proto,
            "_http_request_body_len": (
                event.protocol.http.flow_request_body_len
                if event.protocol.http and event.protocol.http.flow_request_body_len is not None
                else event.protocol.http.request_body_len
                if event.protocol.http
                else None
            ),
            "_http_response_body_len": (
                event.protocol.http.flow_response_body_len
                if event.protocol.http and event.protocol.http.flow_response_body_len is not None
                else event.protocol.http.response_body_len
                if event.protocol.http
                else None
            ),
            "_source_timing_key": timing_key,
            "_source_duration_key": timing_key if duration is not None else None,
            **self._sensor_metadata(event, self.format_def.name),
        }
        self.emit_event(event_data)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        """Render Zeek connection to JSON format."""
        # Ensure all optional fields exist with None to prevent Jinja2 Undefined errors
        optional_fields = [
            "service",
            "duration",
            "orig_bytes",
            "resp_bytes",
            "local_orig",
            "local_resp",
            "missed_bytes",
            "history",
            "orig_pkts",
            "orig_ip_bytes",
            "resp_pkts",
            "resp_ip_bytes",
            "ip_proto",
            "tunnel_parents",
        ]
        for f in optional_fields:
            if f not in event_data:
                event_data[f] = None

        return self._render_zeek_json(event_data)
