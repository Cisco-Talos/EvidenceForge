"""Zeek reporter.log emitter."""

from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter


class ZeekReporterEmitter(SensorMultiplexEmitter):
    """Emitter for Zeek reporter.log format (NDJSON).

    Handles sensor_startup events and raw dict rendering for backward compat.
    """

    _log_filename = "reporter.json"
    _flat_filename = "zeek_reporter.json"
    _supported_types: set[str] = {"sensor_startup"}

    def emit(self, event: SecurityEvent) -> None:
        """Render sensor startup reporter.log entries."""
        if event.event_type != "sensor_startup":
            return
        hostname = event.host.hostname if event.host else "unknown"
        # Reporter startup messages are stored in shell.command field
        level = "Reporter::INFO"
        message = ""
        if event.shell:
            # Format: "level|message"
            parts = event.shell.command.split("|", 1)
            if len(parts) == 2:
                level, message = parts
            else:
                message = event.shell.command
        event_data = {
            "ts": event.timestamp,
            "level": level,
            "message": message,
            "location": "",
            "_sensor_hostnames": [hostname],
        }
        rendered = self._render_event(event_data)
        if rendered:
            self._buffer_event(rendered)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        return self._render_zeek_json(event_data)
