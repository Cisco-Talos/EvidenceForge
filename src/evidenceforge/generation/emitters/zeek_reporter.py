"""Zeek reporter.log emitter."""

from typing import Any

from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter


class ZeekReporterEmitter(SensorMultiplexEmitter):
    """Emitter for Zeek reporter.log format (NDJSON).

    Generates Zeek sensor diagnostic/warning logs.
    Uses dispatch_raw — emitted for sensor startup warnings.
    """

    _log_filename = "reporter.json"
    _flat_filename = "zeek_reporter.json"
    _supported_types: set[str] = set()

    def _render_event(self, event_data: dict[str, Any]) -> str:
        return self._render_zeek_json(event_data)
