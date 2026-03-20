"""EventDispatcher routes SecurityEvents to StateManager and emitters.

Two-layer filtering for emitter selection:
1. Format eligibility: emitter.can_handle(event)
2. Network visibility: for network events, check NetworkVisibilityEngine
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from evidenceforge.events.base import RawLogEntry, SecurityEvent

if TYPE_CHECKING:
    from evidenceforge.generation.emitters.base import LogEmitter
    from evidenceforge.generation.network_visibility import NetworkVisibilityEngine
    from evidenceforge.generation.state_manager import StateManager

logger = logging.getLogger(__name__)

# Formats subject to network visibility filtering
_NETWORK_FORMATS = {
    "zeek_conn", "zeek_dns", "zeek_http", "zeek_ssl", "zeek_files",
    "zeek_x509", "zeek_dhcp", "zeek_ntp", "zeek_weird",
    "zeek_ocsp", "zeek_pe", "zeek_packet_filter", "zeek_reporter",
    "snort_alert",
}


class EventDispatcher:
    """Routes SecurityEvents to StateManager and matching emitters."""

    def __init__(
        self,
        state_manager: StateManager,
        emitters: dict[str, LogEmitter],
        visibility_engine: NetworkVisibilityEngine | None = None,
    ) -> None:
        self.state_manager = state_manager
        self.emitters = emitters
        self.visibility_engine = visibility_engine

    def dispatch(self, event: SecurityEvent) -> None:
        """Route a structured event to StateManager + matching emitters."""
        self.state_manager.apply(event)
        for emitter in self._get_matching_emitters(event):
            emitter.emit(event)

    def dispatch_raw(self, entry: RawLogEntry) -> None:
        """Route a raw log entry directly to a specific emitter (escape hatch).

        target_emitter must match a key in self.emitters dict.
        """
        emitter = self.emitters.get(entry.target_emitter)
        if emitter is None:
            raise KeyError(f"Unknown emitter: {entry.target_emitter!r}")
        emitter.emit_raw(entry.data)

    def _get_matching_emitters(self, event: SecurityEvent) -> list[LogEmitter]:
        """Two-layer filtering: format eligibility + network visibility."""
        # For network events, determine which formats can see this traffic
        # and annotate the event with observing sensor hostnames
        visible_formats: set[str] | None = None
        if event.network and self.visibility_engine:
            visible_formats = self.visibility_engine.get_log_formats_for_connection(
                event.network.src_ip, event.network.dst_ip
            )
            # Annotate event with per-format sensor hostname mapping
            # Each format only gets sensors that actually produce it
            sensors = self.visibility_engine.get_observing_sensors(
                event.network.src_ip, event.network.dst_ip
            )
            format_to_sensors: dict[str, list[str]] = {}
            for sensor in sensors:
                hostname = sensor.hostname or sensor.name
                for fmt in sensor.log_formats:
                    format_to_sensors.setdefault(fmt, []).append(hostname)
            event._sensor_hostnames_by_format = format_to_sensors

        matched = []
        for format_name, emitter in self.emitters.items():
            if not emitter.can_handle(event):
                continue
            # Network visibility filter: only applies to network-format emitters
            if visible_formats is not None and format_name in _NETWORK_FORMATS:
                if format_name not in visible_formats:
                    continue
            matched.append(emitter)
        return matched
