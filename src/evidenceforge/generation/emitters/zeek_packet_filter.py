"""Zeek packet_filter.log emitter."""

from typing import Any

from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter


class ZeekPacketFilterEmitter(SensorMultiplexEmitter):
    """Emitter for Zeek packet_filter.log format (NDJSON).

    Generates sensor packet filter state logs.
    Uses dispatch_raw — emitted once at sensor startup.
    """

    _log_filename = "packet_filter.json"
    _flat_filename = "zeek_packet_filter.json"
    _supported_types: set[str] = set()

    def _render_event(self, event_data: dict[str, Any]) -> str:
        return self._render_zeek_json(event_data)
