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

"""Zeek ssl.log emitter."""

from datetime import timedelta
from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter
from evidenceforge.generation.source_timing import SourceTimingPlanner

_SOURCE_TIMING = SourceTimingPlanner()


class ZeekSslEmitter(SensorMultiplexEmitter):
    """Emitter for Zeek ssl.log format (NDJSON).

    Generates SSL/TLS handshake logs. Requires both NetworkContext and SslContext.
    Shares conn.log UID via event.network.zeek_uid.
    """

    _log_filename = "ssl.json"
    _flat_filename = "zeek_ssl.json"
    _supported_types: set[str] = {"connection"}

    def can_handle(self, event: SecurityEvent) -> bool:
        return (
            event.event_type in self._supported_types
            and event.network is not None
            and event.network.conn_state == "SF"
            and event.ssl is not None
        )

    def emit(self, event: SecurityEvent) -> None:
        net = event.network
        ssl = event.ssl
        conn_ts = _SOURCE_TIMING.source_time(
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
        within = None
        if net.duration is not None and net.duration > 0:
            latest = conn_ts + timedelta(seconds=max(0.0, net.duration - 0.000001))
            within = (conn_ts, latest)
        event_ts = _SOURCE_TIMING.source_time(
            event,
            "source.zeek_ssl_analyzer",
            seed_parts=(
                net.zeek_uid,
                net.src_ip,
                net.src_port,
                net.dst_ip,
                net.dst_port,
                event.timestamp,
            ),
            not_before=conn_ts,
            within=within,
        )
        event_data: dict[str, Any] = {
            "ts": event_ts,
            "uid": net.zeek_uid,
            "id.orig_h": net.src_ip,
            "id.orig_p": net.src_port,
            "id.resp_h": net.dst_ip,
            "id.resp_p": net.dst_port,
            "version": ssl.version or None,
            "cipher": ssl.cipher or None,
            "server_name": ssl.server_name or None,
            "resumed": ssl.resumed,
            "established": ssl.established,
            "ssl_history": ssl.ssl_history or None,
            "cert_chain_fuids": ssl.cert_chain_fuids or None,
            "_sensor_hostnames": event._sensor_hostnames_by_format.get(self.format_def.name, []),
        }
        if event._nat_swaps_by_sensor:
            event_data["_nat_swaps_by_sensor"] = event._nat_swaps_by_sensor
        self.emit_event(event_data)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        optional_fields = [
            "version",
            "cipher",
            "server_name",
            "resumed",
            "established",
            "ssl_history",
            "cert_chain_fuids",
        ]
        for f in optional_fields:
            if f not in event_data:
                event_data[f] = None
        return self._render_zeek_json(event_data)
