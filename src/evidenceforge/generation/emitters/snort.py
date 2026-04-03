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

"""Snort/Suricata alert emitter."""

import hashlib
from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter


class SnortEmitter(SensorMultiplexEmitter):
    """Emitter for Snort/Suricata fast alert format.

    Per-sensor directory routing: each IDS sensor gets its own alert file.

    Handles SecurityEvents with IdsContext (fan-out from connection events
    through IDS sensors) and raw dict events from baseline false-positive
    alert generation.
    """

    _log_filename = "snort_alert.log"
    _flat_filename = "snort_alert.log"
    _sort_before_flush: bool = True
    _supported_types: set[str] = {"connection"}

    def can_handle(self, event: SecurityEvent) -> bool:
        """Handle connection events that carry an IdsContext."""
        return event.event_type in self._supported_types and event.ids is not None

    def emit(self, event: SecurityEvent) -> None:
        """Render IdsContext to Snort fast alert format."""
        ids = event.ids
        net = event.network

        # Add microsecond jitter for realistic Snort timestamps
        ts = event.timestamp
        us_seed = int(hashlib.md5(f"{ts.isoformat()}{ids.sid}".encode()).hexdigest()[:6], 16)
        ts = ts.replace(microsecond=(us_seed % 1000) * 1000)

        event_data = {
            "timestamp": ts,
            "sid": ids.sid,
            "message": ids.message,
            "classification": ids.classification,
            "priority": ids.priority,
            "protocol": (net.protocol or "TCP").upper() if net else "TCP",
            "src_ip": net.src_ip if net else "",
            "src_port": net.src_port if net else 0,
            "dst_ip": net.dst_ip if net else "",
            "dst_port": net.dst_port if net else 0,
        }
        # Get sensor routing from the event's visibility metadata
        if hasattr(event, "_sensor_hostnames_by_format"):
            sensor_hosts = event._sensor_hostnames_by_format.get("snort_alert", [])
            if sensor_hosts:
                event_data["_sensor_hostnames"] = sensor_hosts

        self._dispatch(event_data)

    def _render_event(self, event_data: dict[str, Any]) -> str | None:
        """Render Snort/Suricata alert to fast alert format.

        Returns None if the event lacks required IDS alert fields (sid, message),
        which means it's a plain connection event that should not generate an
        IDS alert. The caller must handle None returns.
        """
        if not event_data.get("sid") and not event_data.get("message"):
            return None

        proto = event_data.get("protocol") or event_data.get("proto")

        context = {
            "timestamp": event_data.get("timestamp") or event_data.get("ts"),
            "sid": event_data.get("sid"),
            "classification": event_data.get("classification"),
            "priority": event_data.get("priority"),
            "protocol": proto.upper() if proto else None,
            "src_ip": event_data.get("src_ip") or event_data.get("id.orig_h"),
            "src_port": event_data.get("src_port") or event_data.get("id.orig_p"),
            "dst_ip": event_data.get("dst_ip") or event_data.get("id.resp_h"),
            "dst_port": event_data.get("dst_port") or event_data.get("id.resp_p"),
            "message": event_data.get("message"),
        }

        rendered = self._template.render(**context)
        return rendered.strip()
