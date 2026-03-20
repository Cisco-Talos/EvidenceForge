"""Zeek dhcp.log emitter."""

from typing import Any

from evidenceforge.generation.emitters.zeek_base import SensorMultiplexEmitter


class ZeekDhcpEmitter(SensorMultiplexEmitter):
    """Emitter for Zeek dhcp.log format (NDJSON).

    Generates DHCP transaction logs. Uses dispatch_raw since DHCP has
    a `uids` array (not single uid) and no standard id.* tuple.
    """

    _log_filename = "dhcp.json"
    _flat_filename = "zeek_dhcp.json"
    # DHCP events dispatched via dispatch_raw(), not SecurityEvent pipeline
    _supported_types: set[str] = set()

    def _render_event(self, event_data: dict[str, Any]) -> str:
        optional_fields = ["mac", "host_name", "domain", "duration"]
        for f in optional_fields:
            if f not in event_data:
                event_data[f] = None
        return self._render_zeek_json(event_data)
