"""Zeek ocsp.log emitter."""

from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter


class ZeekOcspEmitter(SensorMultiplexEmitter):
    """Emitter for Zeek ocsp.log format (NDJSON).

    Generates OCSP certificate status response logs.
    Uses dispatch_raw since OCSP responses are side-effects of SSL connections.
    """

    _log_filename = "ocsp.json"
    _flat_filename = "zeek_ocsp.json"
    _supported_types: set[str] = {"connection"}

    def can_handle(self, event: SecurityEvent) -> bool:
        return event.event_type in self._supported_types and event.ocsp is not None

    def emit(self, event: SecurityEvent) -> None:
        ocsp = event.ocsp
        event_data: dict[str, Any] = {
            "ts": event.timestamp,
            "id": ocsp.id,
            "hashAlgorithm": ocsp.hash_algorithm,
            "issuerNameHash": ocsp.issuer_name_hash,
            "issuerKeyHash": ocsp.issuer_key_hash,
            "serialNumber": ocsp.serial_number,
            "certStatus": ocsp.cert_status,
            "thisUpdate": ocsp.this_update,
            "nextUpdate": ocsp.next_update,
            "_sensor_hostnames": event._sensor_hostnames_by_format.get(
                self.format_def.name if self.format_def else "zeek_ocsp", []
            ),
        }
        self.emit_event(event_data)

    def _render_event(self, event_data: dict[str, Any]) -> str:
        return self._render_zeek_json(event_data)
