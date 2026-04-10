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
from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter


class ZeekEmitter(SensorMultiplexEmitter):
    """Emitter for Zeek conn.log format (JSON).

    Generates Zeek connection logs in JSON format (one JSON object per line).
    Each connection includes source/dest IPs, ports, protocol, and connection state.
    """

    _log_filename = "conn.json"
    _flat_filename = "zeek_conn.json"
    _supported_types: set[str] = {"connection", "ssh_session"}

    def can_handle(self, event: SecurityEvent) -> bool:
        """Zeek conn emitter handles connection and session events with network context."""
        return event.event_type in self._supported_types and event.network is not None

    def emit(self, event: SecurityEvent) -> None:
        """Render SecurityEvent to Zeek conn.log format."""
        net = event.network
        event_data = {
            "ts": event.timestamp,
            "uid": net.zeek_uid,
            "id.orig_h": net.src_ip,
            "id.orig_p": net.src_port,
            "id.resp_h": net.dst_ip,
            "id.resp_p": net.dst_port,
            "proto": net.protocol,
            "service": net.service or None,
            "duration": net.duration,
            "orig_bytes": net.orig_bytes,
            "resp_bytes": net.resp_bytes,
            "conn_state": net.conn_state,
            "local_orig": net.local_orig,
            "local_resp": net.local_resp,
            "missed_bytes": net.missed_bytes,
            "history": net.history,
            "orig_pkts": net.orig_pkts,
            "orig_ip_bytes": net.orig_ip_bytes,
            "resp_pkts": net.resp_pkts,
            "resp_ip_bytes": net.resp_ip_bytes,
            "ip_proto": net.ip_proto,
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
