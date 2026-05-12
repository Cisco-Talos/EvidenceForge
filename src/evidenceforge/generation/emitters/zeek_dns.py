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

"""Zeek dns.log emitter."""

from datetime import timedelta
from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.generation.activity.timing_profiles import sample_timing_delta
from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter
from evidenceforge.utils.rng import _stable_seed


class ZeekDnsEmitter(SensorMultiplexEmitter):
    """Emitter for Zeek dns.log format (NDJSON).

    Generates Zeek DNS query/response logs. Each record represents a DNS
    transaction with query name, type, response code, and answers.

    Handles SecurityEvents with DnsContext (fan-out from connection events)
    and also retains emit_raw() for backward compatibility.
    """

    _log_filename = "dns.json"
    _flat_filename = "zeek_dns.json"
    _supported_types: set[str] = {"connection"}

    def can_handle(self, event: SecurityEvent) -> bool:
        """Handle connection events that carry a DnsContext."""
        return (
            event.event_type in self._supported_types
            and event.network is not None
            and event.dns is not None
        )

    def emit(self, event: SecurityEvent) -> None:
        """Render DnsContext + NetworkContext to Zeek dns.log NDJSON."""
        net = event.network
        dns = event.dns
        offset = sample_timing_delta(
            "source.zeek_dns_query",
            seed_parts=(
                net.zeek_uid,
                net.src_ip,
                net.src_port,
                net.dst_ip,
                net.dst_port,
                event.timestamp,
            ),
        ).total_seconds()
        conn_lifetime = net.duration if net.duration is not None else dns.rtt
        if conn_lifetime is not None and conn_lifetime > 0:
            max_inside_conn = max(0.0, conn_lifetime - 0.000001)
            if offset > max_inside_conn:
                seed = _stable_seed(
                    f"zeek_dns_offset:{net.zeek_uid}:{net.src_ip}:{net.src_port}:"
                    f"{net.dst_ip}:{net.dst_port}:{event.timestamp}"
                )
                fraction = 0.08 + (seed % 720) / 1000.0
                offset = min(max_inside_conn, conn_lifetime * fraction)
        event_ts = event.timestamp + timedelta(seconds=max(0.0, offset))
        event_data: dict[str, Any] = {
            "ts": event_ts,
            "uid": net.zeek_uid,
            "id.orig_h": net.src_ip,
            "id.orig_p": net.src_port,
            "id.resp_h": net.dst_ip,
            "id.resp_p": net.dst_port,
            "proto": net.protocol,
            "trans_id": dns.trans_id,
            "query": dns.query,
            "qclass": dns.qclass,
            "qclass_name": dns.qclass_name,
            "qtype": dns.qtype,
            "qtype_name": dns.query_type,
            "rcode": dns.rcode_num,
            "rcode_name": dns.rcode,
            "AA": dns.AA,
            "TC": dns.TC,
            "RD": dns.RD,
            "RA": dns.RA,
            "Z": dns.Z,
            "rejected": dns.rejected,
            "opcode": dns.opcode,
            "opcode_name": dns.opcode_name,
        }
        if dns.rtt is not None:
            event_data["rtt"] = dns.rtt
        if dns.answers:
            event_data["answers"] = dns.answers
        if dns.TTLs:
            event_data["TTLs"] = dns.TTLs

        # Sensor hostname routing (set by dispatcher for network visibility)
        event_data["_sensor_hostnames"] = event._sensor_hostnames_by_format.get(
            self.format_def.name if self.format_def else "zeek_dns", []
        )

        if event._nat_swaps_by_sensor:
            event_data["_nat_swaps_by_sensor"] = event._nat_swaps_by_sensor
        self.emit_event(event_data)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        """Render Zeek DNS record to NDJSON format."""
        # Ensure optional fields exist with None to prevent Jinja2 Undefined errors
        optional_fields = ["rtt", "answers", "TTLs"]
        for f in optional_fields:
            if f not in event_data:
                event_data[f] = None

        return self._render_zeek_json(event_data)
