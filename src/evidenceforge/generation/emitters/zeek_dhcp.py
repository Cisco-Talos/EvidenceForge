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
            "mac": dhcp.mac,
            "host_name": dhcp.host_name,
            "assigned_addr": dhcp.assigned_addr,
            "lease_time": dhcp.lease_time,
            "msg_types": dhcp.msg_types,
            "duration": dhcp.duration,
        }
        rendered = self._render_event(event_data)
        if rendered:
            self._buffer_event(rendered)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        optional_fields = ["mac", "host_name", "domain", "duration"]
        for f in optional_fields:
            if f not in event_data:
                event_data[f] = None
        return self._render_zeek_json(event_data)
