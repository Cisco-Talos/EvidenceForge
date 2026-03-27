"""Zeek packet_filter.log emitter."""

from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter


class ZeekPacketFilterEmitter(SensorMultiplexEmitter):
    """Emitter for Zeek packet_filter.log format (NDJSON).

    Handles sensor_startup events and raw dict rendering for backward compat.
    """

    _log_filename = "packet_filter.json"
    _flat_filename = "zeek_packet_filter.json"
    _supported_types: set[str] = {"sensor_startup"}

    def emit(self, event: SecurityEvent) -> None:
        """Render a sensor startup packet_filter.log entry."""
        if event.event_type != "sensor_startup":
            return
        hostname = event.src_host.hostname if event.src_host else "unknown"
        event_data = {
            "ts": event.timestamp,
            "node": hostname,
            "filter": "ip or not ip",
            "init": True,
            "success": True,
            "_sensor_hostnames": [hostname],
        }
        rendered = self._render_event(event_data)
        if rendered:
            self._buffer_event(rendered)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        return self._render_zeek_json(event_data)
