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

"""Zeek weird.log emitter."""

from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter


class ZeekWeirdEmitter(SensorMultiplexEmitter):
    """Emitter for Zeek weird.log format (NDJSON).

    Renders network anomaly records from WeirdContext on connection events.
    """

    _log_filename = "weird.json"
    _flat_filename = "zeek_weird.json"
    _supported_types: set[str] = {"connection"}

    def can_handle(self, event: SecurityEvent) -> bool:
        """Only handle connection events that carry WeirdContext."""
        return (
            event.event_type == "connection"
            and event.weird is not None
            and not (event.network is not None and event.network.application_layer_only)
        )

    def emit(self, event: SecurityEvent) -> None:
        """Render weird.log entry from WeirdContext + NetworkContext."""
        net = event.network
        weird = event.weird
        event_data = {
            "ts": event.timestamp,
            "uid": net.zeek_uid if net else "",
            "id.orig_h": net.src_ip if net else "",
            "id.orig_p": net.src_port if net else 0,
            "id.resp_h": net.dst_ip if net else "",
            "id.resp_p": net.dst_port if net else 0,
            "name": weird.name,
            "notice": weird.notice,
            "peer": weird.peer,
            "source": weird.source,
            **self._sensor_metadata(event, self.format_def.name),
        }
        self.emit_event(event_data)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        optional_fields = ["uid", "addl", "source"]
        for f in optional_fields:
            if f not in event_data:
                event_data[f] = None
        return self._render_zeek_json(event_data)
