"""Zeek dns.log emitter."""

from typing import Any

from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter


class ZeekDnsEmitter(SensorMultiplexEmitter):
    """Emitter for Zeek dns.log format (NDJSON).

    Generates Zeek DNS query/response logs. Each record represents a DNS
    transaction with query name, type, response code, and answers.
    """

    _log_filename = "dns.json"
    _flat_filename = "zeek_dns.json"
    # DNS events dispatched via dispatch_raw(), not SecurityEvent pipeline
    _supported_types: set[str] = set()

    def _render_event(self, event_data: dict[str, Any]) -> str:
        """Render Zeek DNS record to NDJSON format."""
        # Ensure optional fields exist with None to prevent Jinja2 Undefined errors
        optional_fields = ["rtt", "answers", "TTLs"]
        for f in optional_fields:
            if f not in event_data:
                event_data[f] = None

        return self._render_zeek_json(event_data)
