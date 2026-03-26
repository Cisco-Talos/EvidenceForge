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
        return event.event_type == "connection" and event.weird is not None

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
        }
        if net:
            event_data["_sensor_hostnames"] = event._sensor_hostnames_by_format.get(
                "zeek_weird", []
            )
        rendered = self._render_event(event_data)
        if rendered:
            self._buffer_event(rendered)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        optional_fields = ["uid", "addl", "source"]
        for f in optional_fields:
            if f not in event_data:
                event_data[f] = None
        return self._render_zeek_json(event_data)
