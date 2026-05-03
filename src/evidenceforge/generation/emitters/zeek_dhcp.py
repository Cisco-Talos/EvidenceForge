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

"""Zeek dhcp.log emitter."""

from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter


class ZeekDhcpEmitter(SensorMultiplexEmitter):
    """Emitter for Zeek dhcp.log format (NDJSON).

    Renders DHCP transaction logs from DhcpContext on SecurityEvent.
    """

    _log_filename = "dhcp.json"
    _flat_filename = "zeek_dhcp.json"
    _supported_types: set[str] = {"dhcp_lease"}

    def can_handle(self, event: SecurityEvent) -> bool:
        """DHCP emitter handles dhcp_lease events with DHCP context."""
        return event.event_type in self._supported_types and event.dhcp is not None

    def emit(self, event: SecurityEvent) -> None:
        """Render dhcp.log entry from DhcpContext."""
        if event.dhcp is None:
            return
        dhcp = event.dhcp
        event_data = {
            "ts": event.timestamp,
            "uids": dhcp.uids,
            "client_addr": dhcp.client_addr,
            "server_addr": dhcp.server_addr,
            "mac": dhcp.mac.lower() if dhcp.mac else dhcp.mac,
            "host_name": dhcp.host_name,
            "domain": dhcp.domain or None,
            "assigned_addr": dhcp.assigned_addr,
            "lease_time": dhcp.lease_time,
            "msg_types": dhcp.msg_types,
            "duration": dhcp.duration,
            "_sensor_hostnames": event._sensor_hostnames_by_format.get(self.format_def.name, []),
        }
        if event._nat_swaps_by_sensor:
            event_data["_nat_swaps_by_sensor"] = event._nat_swaps_by_sensor
        self.emit_event(event_data)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        optional_fields = ["mac", "host_name", "domain", "duration"]
        for f in optional_fields:
            if f not in event_data:
                event_data[f] = None
        return self._render_zeek_json(event_data)
