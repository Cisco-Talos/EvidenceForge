"""Zeek x509.log emitter."""

from typing import Any

from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter


class ZeekX509Emitter(SensorMultiplexEmitter):
    """Emitter for Zeek x509.log format (NDJSON).

    Generates X.509 certificate logs. No conn UID — keyed by fingerprint.
    Uses dispatch_raw since certificates are side-effects of SSL connections.
    """

    _log_filename = "x509.json"
    _flat_filename = "zeek_x509.json"
    _supported_types: set[str] = set()

    def _render_event(self, event_data: dict[str, Any]) -> str:
        optional_fields = ["san_dns", "basic_constraints_ca"]
        for f in optional_fields:
            if f not in event_data:
                event_data[f] = None
        return self._render_zeek_json(event_data)
