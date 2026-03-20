"""Zeek weird.log emitter."""

from typing import Any

from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter


class ZeekWeirdEmitter(SensorMultiplexEmitter):
    """Emitter for Zeek weird.log format (NDJSON).

    Generates network anomaly/weird records. Uses dispatch_raw since
    weird events are probabilistic side-effects, not tied to specific event types.
    """

    _log_filename = "weird.json"
    _flat_filename = "zeek_weird.json"
    # Weird events dispatched via dispatch_raw(), not SecurityEvent pipeline
    _supported_types: set[str] = set()

    def _render_event(self, event_data: dict[str, Any]) -> str:
        optional_fields = ["uid", "addl", "source"]
        for f in optional_fields:
            if f not in event_data:
                event_data[f] = None
        return self._render_zeek_json(event_data)
