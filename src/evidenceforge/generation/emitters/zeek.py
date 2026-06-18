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

from evidenceforge.events.base import SecurityEvent
from evidenceforge.generation.activity.timing_profiles import get_timing_window
from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter
from evidenceforge.generation.source_timing import SourceTimingPlanner
from evidenceforge.utils.rng import _stable_seed

_ZEEK_SERVICE_ALIASES: dict[str, str] = {
    "kerberos": "krb",
    "mssql": "tds",
    "sql": "tds",
    "sqlserver": "tds",
    "ms-sql": "tds",
    "rpc": "dce_rpc",
}
_SOURCE_TIMING = SourceTimingPlanner()


def _tls_completed_duration_floor(event: SecurityEvent, min_ms: int, max_ms: int) -> float:
    """Return a deterministic TLS analyzer duration floor with source-native texture."""
    net = event.network
    if net is None:
        return min_ms / 1000
    span_ms = max(1, max_ms - min_ms)
    seed = _stable_seed(
        "zeek_tls_duration_floor:"
        f"{net.zeek_uid}:{net.src_ip}:{net.src_port}:{net.dst_ip}:{net.dst_port}:"
        f"{event.timestamp.isoformat()}"
    )
    extra_ms = 1 + (seed % span_ms)
    return (min_ms + extra_ms) / 1000


class ZeekEmitter(SensorMultiplexEmitter):
    """Emitter for Zeek conn.log format (JSON).

    Generates Zeek connection logs in JSON format (one JSON object per line).
    Each connection includes source/dest IPs, ports, protocol, and connection state.
    """

    _log_filename = "conn.json"
    _flat_filename = "zeek_conn.json"
    _supported_types: set[str] = {"connection", "dhcp_lease"}

    def can_handle(self, event: SecurityEvent) -> bool:
        """Zeek conn emitter handles canonical network transport events."""
        return (
            event.event_type in self._supported_types
            and event.network is not None
            and not event.network.application_layer_only
        )

    @staticmethod
    def _normalize_history_for_state(conn_state: str, history: str) -> str:
        """Keep generated Zeek history direction consistent with conn_state semantics."""
        if conn_state == "RSTR" and history:
            return history[:-1] + "r" if history.endswith("R") else history
        if conn_state == "RSTO" and history:
            return history[:-1] + "R" if history.endswith("r") else history
        return history

    @staticmethod
    def _render_service_name(service: str | None) -> str | None:
        """Render canonical services using Zeek analyzer vocabulary."""
        if not service:
            return None
        normalized = service.strip().lower()
        return _ZEEK_SERVICE_ALIASES.get(normalized, normalized)

    def emit(self, event: SecurityEvent) -> None:
        """Render SecurityEvent to Zeek conn.log format."""
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
        if (
            net.protocol == "tcp"
            and net.dst_port == 443
            and net.conn_state == "SF"
            and (event.ssl is not None or self._render_service_name(net.service) == "ssl")
        ):
            tls_min_window = get_timing_window(
                "network.tls_completed_min_duration",
                default_min_ms=800,
                default_max_ms=2500,
                default_position="after",
                default_class="same_observation",
            )
            min_duration = tls_min_window.min_ms / 1000
            if (
                duration is None
                or duration < min_duration
                or abs(duration - min_duration) < 0.000001
                or (
                    self._render_service_name(net.service) == "ssl"
                    and abs(float(duration) - 1.2) < 0.000001
                )
            ):
                duration = _tls_completed_duration_floor(
                    event,
                    tls_min_window.min_ms,
                    tls_min_window.max_ms,
                )
        event_ts = _SOURCE_TIMING.source_time(
            event,
            "source.zeek_conn_start",
            seed_parts=(
                net.zeek_uid,
                net.src_ip,
                net.src_port,
                net.dst_ip,
                net.dst_port,
                event.timestamp,
            ),
            not_before=event.timestamp,
        )
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
            or event.file_transfer is not None
            or event.x509 is not None
            or bool(event.x509_chain),
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
                event.http.flow_request_body_len
                if event.http and event.http.flow_request_body_len is not None
                else event.http.request_body_len
                if event.http
                else None
            ),
            "_http_response_body_len": (
                event.http.flow_response_body_len
                if event.http and event.http.flow_response_body_len is not None
                else event.http.response_body_len
                if event.http
                else None
            ),
            "_allow_sensor_observation_variance": True,
            "_sensor_hostnames": event._sensor_hostnames_by_format.get(self.format_def.name, []),
        }
        if event._nat_swaps_by_sensor:
            event_data["_nat_swaps_by_sensor"] = event._nat_swaps_by_sensor
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
