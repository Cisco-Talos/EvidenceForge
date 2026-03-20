"""Zeek ocsp.log emitter."""

from typing import Any

from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter


class ZeekOcspEmitter(SensorMultiplexEmitter):
    """Emitter for Zeek ocsp.log format (NDJSON).

    Generates OCSP certificate status response logs.
    Uses dispatch_raw since OCSP responses are side-effects of SSL connections.
    """

    _log_filename = "ocsp.json"
    _flat_filename = "zeek_ocsp.json"
    _supported_types: set[str] = set()

    def _render_event(self, event_data: dict[str, Any]) -> str:
        return self._render_zeek_json(event_data)
