# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

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

# Format groups: a single name that expands to multiple emitter-level formats.
# Sensors and output.logs declare groups; the engine expands to individual emitters.
FORMAT_GROUPS: dict[str, set[str]] = {
    "zeek": {
        "zeek_conn",
        "zeek_dns",
        "zeek_http",
        "zeek_ssl",
        "zeek_files",
        "zeek_x509",
        "zeek_dhcp",
        "zeek_ntp",
        "zeek_weird",
        "zeek_ocsp",
        "zeek_pe",
        "zeek_packet_filter",
        "zeek_reporter",
    },
    "windows": {
        "windows_event_security",
        "windows_event_sysmon",
    },
}

# Formats subject to network visibility filtering (expanded emitter names)
_NETWORK_FORMATS = FORMAT_GROUPS["zeek"] | {"snort_alert", "cisco_asa"}


def expand_formats(formats: list[str] | set[str]) -> set[str]:
    """Expand format group names (e.g., 'zeek') to individual emitter names."""
    expanded: set[str] = set()
    for fmt in formats:
        if fmt in FORMAT_GROUPS:
            expanded.update(FORMAT_GROUPS[fmt])
        else:
            expanded.add(fmt)
    return expanded


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
            if event.raw is not None:
                emitter.emit_raw(event.raw.fields)
            else:
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
        # Raw event routing: target a single specific emitter
        if event.raw is not None:
            emitter = self.emitters.get(event.raw.target_format)
            if emitter is None:
                logger.warning(f"Raw event targets unknown emitter: {event.raw.target_format!r}")
                return []
            if event.local_only and event.raw.target_format in _NETWORK_FORMATS:
                return []
            return [emitter]

        # For network events, determine which formats can see this traffic
        # and annotate the event with observing sensor hostnames
        visible_formats: set[str] | None = None
        if event.network and self.visibility_engine:
            # Denied connections only visible from the source side (packets
            # never reach the destination — firewall blocks them)
            is_fw_deny = event.firewall is not None and event.firewall.action == "deny"
            if is_fw_deny:
                visible_formats = self.visibility_engine.get_log_formats_for_source_only(
                    event.network.src_ip, event.network.dst_ip
                )
                sensors = self.visibility_engine.get_source_side_sensors(
                    event.network.src_ip, event.network.dst_ip
                )
            else:
                visible_formats = self.visibility_engine.get_log_formats_for_connection(
                    event.network.src_ip, event.network.dst_ip
                )
                sensors = self.visibility_engine.get_observing_sensors(
                    event.network.src_ip, event.network.dst_ip
                )
            format_to_sensors: dict[str, list[str]] = {}
            for sensor in sensors:
                hostname = sensor.hostname or sensor.name
                # Expand group names to individual emitter names
                for fmt in expand_formats(sensor.log_formats):
                    format_to_sensors.setdefault(fmt, []).append(hostname)
            event._sensor_hostnames_by_format = format_to_sensors

        matched = []
        for format_name, emitter in self.emitters.items():
            if not emitter.can_handle(event):
                continue
            # Host-local events (same src/dst IP) are invisible to network sensors
            if event.local_only and format_name in _NETWORK_FORMATS:
                continue
            # Network visibility filter: only applies to network-format emitters
            if visible_formats is not None and format_name in _NETWORK_FORMATS:
                if format_name not in visible_formats:
                    continue
            matched.append(emitter)
        return matched
