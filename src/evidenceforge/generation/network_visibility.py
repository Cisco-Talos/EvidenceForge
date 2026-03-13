"""Network visibility engine for EvidenceForge.

Determines whether network connections are observable by configured sensors
based on network topology (segments) and sensor placement.

If no network config is provided, all connections are visible (backward compat).
"""

import ipaddress
import logging
from typing import Optional

from evidenceforge.models.scenario import NetworkConfig, NetworkSensor, System

logger = logging.getLogger(__name__)


class NetworkVisibilityEngine:
    """Determines whether network connections are observable by configured sensors.

    Thread-safe by design: all internal state is built during __init__ and
    read-only thereafter.
    """

    def __init__(
        self,
        network_config: Optional[NetworkConfig],
        systems: list[System],
    ):
        """Initialize visibility engine.

        Args:
            network_config: Optional NetworkConfig from scenario. If None,
                           all connections are visible (backward compat).
            systems: List of systems in the environment (for IP→segment mapping).
        """
        self._enabled = network_config is not None
        self._segment_networks: dict[str, ipaddress.IPv4Network | ipaddress.IPv6Network] = {}
        self._ip_to_segments: dict[str, set[str]] = {}
        self._sensors: list[NetworkSensor] = []

        if self._enabled:
            self._build_topology(network_config, systems)

    def _build_topology(
        self, config: NetworkConfig, systems: list[System]
    ) -> None:
        """Build internal lookup structures from config.

        1. Parse each segment's CIDR into an ip_network
        2. Map each system IP to the segment(s) it belongs to
        3. Store sensors for later matching
        """
        # Build hostname→IP lookup
        hostname_to_ip: dict[str, str] = {}
        for system in systems:
            hostname_to_ip[system.hostname] = system.ip

        # Parse segments
        for segment in config.segments:
            network = ipaddress.ip_network(segment.cidr, strict=False)
            self._segment_networks[segment.name] = network

            if segment.systems:
                # Explicit system list: map those system IPs to this segment
                for hostname in segment.systems:
                    ip = hostname_to_ip.get(hostname)
                    if ip:
                        self._ip_to_segments.setdefault(ip, set()).add(segment.name)
            else:
                # Auto-infer: check all system IPs against CIDR
                for system in systems:
                    try:
                        if ipaddress.ip_address(system.ip) in network:
                            self._ip_to_segments.setdefault(system.ip, set()).add(
                                segment.name
                            )
                    except ValueError:
                        pass

        self._sensors = list(config.sensors)

        logger.info(
            f"Network visibility engine initialized: "
            f"{len(config.segments)} segments, {len(config.sensors)} sensors, "
            f"{len(self._ip_to_segments)} mapped IPs"
        )

    def _resolve_ip_segments(self, ip: str) -> set[str]:
        """Return the set of segment names an IP belongs to.

        First checks the pre-built IP→segment map. If not found, falls back
        to checking CIDR containment (for IPs not explicitly mapped).

        Returns empty set for external IPs not in any segment.
        """
        # Fast path: pre-mapped IP
        if ip in self._ip_to_segments:
            return self._ip_to_segments[ip]

        # Slow path: check CIDR containment for unmapped IPs
        segments = set()
        try:
            addr = ipaddress.ip_address(ip)
            for seg_name, network in self._segment_networks.items():
                if addr in network:
                    segments.add(seg_name)
        except ValueError:
            pass

        return segments

    def _sensor_can_observe(
        self,
        sensor: NetworkSensor,
        src_segments: set[str],
        dst_segments: set[str],
    ) -> bool:
        """Check if a single sensor can observe a connection.

        Considers direction (inbound/outbound/bidirectional) and placement
        (span sees intra-segment traffic, tap does not).
        """
        monitored = set(sensor.monitoring_segments)

        if sensor.direction == "bidirectional":
            visible = bool(monitored & src_segments or monitored & dst_segments)
        elif sensor.direction == "outbound":
            visible = bool(monitored & src_segments)
        elif sensor.direction == "inbound":
            visible = bool(monitored & dst_segments)
        else:
            visible = False

        if not visible:
            return False

        # TAP placement: only sees cross-segment traffic.
        # If both endpoints are in the exact same segment(s), a TAP on the
        # uplink between that segment and the rest of the network won't see it.
        if sensor.placement == "tap":
            if src_segments and dst_segments and src_segments == dst_segments:
                return False

        return True

    def is_connection_visible(self, src_ip: str, dst_ip: str) -> bool:
        """Determine if any sensor would observe traffic between src_ip and dst_ip.

        Returns True if:
        - No network config (backward compat: everything visible)
        - Any sensor monitors a segment containing src_ip or dst_ip
          AND the direction matches AND placement allows it

        Direction logic:
        - "bidirectional": sensor sees traffic where src OR dst is in a monitored segment
        - "outbound": sensor sees traffic where src is in a monitored segment
        - "inbound": sensor sees traffic where dst is in a monitored segment

        Placement logic:
        - "span": sees all traffic including intra-segment (SPAN port on switch)
        - "tap": only sees cross-segment traffic (inline TAP on uplink)
        """
        if not self._enabled:
            return True

        src_segments = self._resolve_ip_segments(src_ip)
        dst_segments = self._resolve_ip_segments(dst_ip)

        return any(
            self._sensor_can_observe(sensor, src_segments, dst_segments)
            for sensor in self._sensors
        )

    def get_observing_sensors(
        self, src_ip: str, dst_ip: str
    ) -> list[NetworkSensor]:
        """Return list of sensors that would observe this connection.

        If no network config, returns empty list (caller uses default behavior).
        """
        if not self._enabled:
            return []

        src_segments = self._resolve_ip_segments(src_ip)
        dst_segments = self._resolve_ip_segments(dst_ip)

        return [
            sensor for sensor in self._sensors
            if self._sensor_can_observe(sensor, src_segments, dst_segments)
        ]

    def get_log_formats_for_connection(
        self, src_ip: str, dst_ip: str
    ) -> set[str]:
        """Return the union of log_formats from all observing sensors.

        If no network config (backward compat), returns {"zeek_conn"} to
        maintain current default behavior.
        """
        if not self._enabled:
            return {"zeek_conn"}

        formats: set[str] = set()
        for sensor in self.get_observing_sensors(src_ip, dst_ip):
            formats.update(sensor.log_formats)
        return formats
