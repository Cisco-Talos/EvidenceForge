"""Zeek pe.log emitter."""

from typing import Any

from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter


class ZeekPeEmitter(SensorMultiplexEmitter):
    """Emitter for Zeek pe.log format (NDJSON).

    Generates Portable Executable analysis logs.
    Uses dispatch_raw since PE analysis is a side-effect of file transfers.
    """

    _log_filename = "pe.json"
    _flat_filename = "zeek_pe.json"
    _supported_types: set[str] = set()

    def _render_event(self, event_data: dict[str, Any]) -> str:
        optional_fields = ["section_names"]
        for f in optional_fields:
            if f not in event_data:
                event_data[f] = None
        return self._render_zeek_json(event_data)
