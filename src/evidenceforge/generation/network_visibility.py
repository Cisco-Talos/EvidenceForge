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

"""Network visibility engine for EvidenceForge.

Determines whether network connections are observable by configured sensors
based on network topology (segments) and sensor placement.

If no network config is provided, all connections are visible (backward compat).
"""

import ipaddress
import logging
import random

from evidenceforge.events.contexts import NatContext
from evidenceforge.models.scenario import NatRule, NetworkConfig, NetworkSensor, System

logger = logging.getLogger(__name__)


class NetworkVisibilityEngine:
    """Determines whether network connections are observable by configured sensors.

    Thread-safe by design: all internal state is built during __init__ and
    read-only thereafter.
    """

    def __init__(
        self,
        network_config: NetworkConfig | None,
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
        # NAT: per-rule PAT port counters keyed by (sensor_name, rule_idx)
        self._pat_port_counters: dict[tuple[str, int], int] = {}
        # VIP routing: static NAT mapped_ip ↔ real_ip lookups
        self._vip_to_real_ip: dict[str, str] = {}
        self._real_ip_to_vip: dict[str, str] = {}
        # Public address space for external scan targets
        self._public_cidrs: list[ipaddress.IPv4Network] = []

        if self._enabled:
            self._build_topology(network_config, systems)

    @property
    def enabled(self) -> bool:
        """True when a network topology (segments/sensors) is configured.

        When False, there is no sensor to capture sensor-only formats (e.g. Zeek), so callers
        deciding whether such a source will actually land must treat it as not observed.
        """
        return self._enabled

    def _build_topology(self, config: NetworkConfig, systems: list[System]) -> None:
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
                            self._ip_to_segments.setdefault(system.ip, set()).add(segment.name)
                    except ValueError:
                        pass

        self._sensors = list(config.sensors)

        # Build per-sensor PAT port counters for firewalls with NAT rules
        nat_rule_count = 0
        for sensor in config.sensors:
            if sensor.type == "firewall" and sensor.nat_rules:
                sensor_name = sensor.hostname or sensor.name
                for rule_idx in range(len(sensor.nat_rules)):
                    import hashlib as _hl

                    seed = int(_hl.md5(f"{sensor_name}:{rule_idx}".encode()).hexdigest()[:8], 16)
                    self._pat_port_counters[(sensor_name, rule_idx)] = 1024 + (seed % 50000)
                    nat_rule_count += 1

        # Build VIP reverse lookups from static NAT rules and register
        # VIPs in segment membership so visibility/NAT resolution works.
        for sensor in config.sensors:
            if sensor.type != "firewall" or not sensor.nat_rules:
                continue
            for rule in sensor.nat_rules:
                if rule.type == "static" and rule.mapped_ip and rule.real_ip:
                    self._vip_to_real_ip[rule.mapped_ip] = rule.real_ip
                    self._real_ip_to_vip[rule.real_ip] = rule.mapped_ip
                    # VIP inherits the real_ip's segment membership
                    real_segs = self._ip_to_segments.get(rule.real_ip, set())
                    if real_segs:
                        self._ip_to_segments[rule.mapped_ip] = set(real_segs)

        # Public address space for scan targets: explicit or auto-derived
        if hasattr(config, "public_cidrs") and config.public_cidrs:
            for cidr_str in config.public_cidrs:
                try:
                    self._public_cidrs.append(ipaddress.ip_network(cidr_str, strict=False))
                except ValueError:
                    logger.warning(f"Invalid public_cidrs entry: {cidr_str!r}")
        elif self._real_ip_to_vip:
            # Auto-derive: group VIPs by /24 prefix
            seen_prefixes: set[str] = set()
            for vip in self._real_ip_to_vip.values():
                try:
                    addr = ipaddress.ip_address(vip)
                    prefix = str(ipaddress.ip_network(f"{addr}/24", strict=False))
                    if prefix not in seen_prefixes:
                        seen_prefixes.add(prefix)
                        self._public_cidrs.append(ipaddress.ip_network(prefix))
                except ValueError:
                    pass

        logger.info(
            f"Network visibility engine initialized: "
            f"{len(config.segments)} segments, {len(config.sensors)} sensors, "
            f"{len(self._ip_to_segments)} mapped IPs, "
            f"{nat_rule_count} NAT rules, "
            f"{len(self._vip_to_real_ip)} VIPs, "
            f"{len(self._public_cidrs)} public CIDRs"
        )

    def get_inbound_vip(self, real_ip: str) -> str | None:
        """Return the public VIP for a given real (internal) IP, or None."""
        return self._real_ip_to_vip.get(real_ip)

    def get_public_inbound_address(self, real_ip: str) -> str | None:
        """Return the address an external source can use to reach a host.

        Static-NAT hosts are reached through their VIP. Hosts with directly
        public addresses can be reached as-is. Private hosts without static NAT
        are unreachable from outside and return None.
        """
        vip = self.get_inbound_vip(real_ip)
        if vip:
            return vip
        try:
            addr = ipaddress.ip_address(real_ip)
        except ValueError:
            return None
        if not addr.is_private:
            return real_ip
        if any(addr in public_net for public_net in self._public_cidrs):
            return real_ip
        return None

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
            if (
                len(monitored) > 1
                and src_segments
                and dst_segments
                and not (monitored & src_segments and monitored & dst_segments)
            ):
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
        - "tap": sees external/boundary traffic for monitored segments, and internal
          cross-segment traffic only when both endpoint segments are monitored
        """
        if not self._enabled:
            return True

        src_segments = self._resolve_ip_segments(src_ip)
        dst_segments = self._resolve_ip_segments(dst_ip)

        return any(
            self._sensor_can_observe(sensor, src_segments, dst_segments) for sensor in self._sensors
        )

    def get_observing_sensors(self, src_ip: str, dst_ip: str) -> list[NetworkSensor]:
        """Return list of sensors that would observe this connection.

        If no network config, returns empty list (caller uses default behavior).
        """
        if not self._enabled:
            return []

        src_segments = self._resolve_ip_segments(src_ip)
        dst_segments = self._resolve_ip_segments(dst_ip)

        return [
            sensor
            for sensor in self._sensors
            if self._sensor_can_observe(sensor, src_segments, dst_segments)
        ]

    def get_link_local_sensors(self, src_ip: str) -> list[NetworkSensor]:
        """Return sensors that can observe source-segment link-local traffic.

        DHCP broadcast and similar L2-local exchanges do not traverse routed
        boundaries. A SPAN sensor monitoring the client segment can see them;
        TAP/firewall boundary sensors cannot unless a separate relay/unicast
        transaction is explicitly modeled.
        """
        if not self._enabled:
            return []

        src_segments = self._resolve_ip_segments(src_ip)
        if not src_segments:
            return []

        return [
            sensor
            for sensor in self._sensors
            if sensor.placement == "span"
            and sensor.type != "firewall"
            and set(sensor.monitoring_segments) & src_segments
            and sensor.direction in {"bidirectional", "outbound"}
        ]

    def get_log_formats_for_link_local(self, src_ip: str) -> set[str]:
        """Return expanded log formats for source-segment link-local traffic."""
        from evidenceforge.events.dispatcher import FORMAT_GROUPS, expand_formats

        if not self._enabled:
            return set(FORMAT_GROUPS["zeek"])

        formats: set[str] = set()
        for sensor in self.get_link_local_sensors(src_ip):
            formats.update(sensor.log_formats)
        return expand_formats(formats)

    def get_source_side_sensors(self, src_ip: str, dst_ip: str = "") -> list[NetworkSensor]:
        """Return sensors that can observe denied traffic originating from src_ip.

        For denied connections, traffic only exists on the source side of the
        firewall — packets never reach the destination. Uses _sensor_can_observe()
        with empty dst_segments to respect direction and placement rules.

        Args:
            src_ip: Source IP of the denied connection
            dst_ip: Destination IP (used for external sources to scope which
                    firewall's boundary segments are relevant)
        """
        if not self._enabled:
            return []

        src_segments = self._resolve_ip_segments(src_ip)
        if not src_segments:
            # External IP not in any segment. External traffic arrives at
            # boundary segments monitored by firewall sensors. Only include
            # firewalls that monitor the destination's segment to avoid
            # fanning out to unrelated segments.
            dst_segments = self._resolve_ip_segments(dst_ip) if dst_ip else set()
            boundary_segments: set[str] = set()
            for sensor in self._sensors:
                if sensor.type == "firewall":
                    fw_segments = set(sensor.monitoring_segments)
                    if not dst_segments:
                        boundary_segments.update(fw_segments)
                    elif fw_segments & dst_segments:
                        boundary_segments.update(fw_segments & dst_segments)
            if not boundary_segments:
                return []
            # For external denied traffic, only firewall sensors see the
            # packets — non-firewall sensors (Zeek, IDS) behind the firewall
            # never receive denied/dropped flows.
            return [
                sensor
                for sensor in self._sensors
                if sensor.type == "firewall"
                and self._sensor_can_observe(sensor, set(), boundary_segments)
            ]

        # Internal IP: check which sensors can observe traffic FROM this
        # segment. Empty dst_segments means only bidirectional/outbound
        # sensors that monitor the source's segment will match.
        return [
            sensor
            for sensor in self._sensors
            if self._sensor_can_observe(sensor, src_segments, set())
        ]

    def get_log_formats_for_source_only(self, src_ip: str, dst_ip: str = "") -> set[str]:
        """Return log formats from sensors that can see traffic FROM this IP.

        Used for denied connections: only sensors on the source side see them.
        """
        from evidenceforge.events.dispatcher import FORMAT_GROUPS, expand_formats

        if not self._enabled:
            return set(FORMAT_GROUPS["zeek"])

        formats: set[str] = set()
        for sensor in self.get_source_side_sensors(src_ip, dst_ip):
            formats.update(sensor.log_formats)
        return expand_formats(formats)

    def get_log_formats_for_connection(self, src_ip: str, dst_ip: str) -> set[str]:
        """Return the expanded union of log_formats from all observing sensors.

        If no network config (backward compat), returns all Zeek formats
        so all emitters receive events when there's no network topology.
        Format group names (e.g., 'zeek') are expanded to individual emitter names.
        """
        from evidenceforge.events.dispatcher import FORMAT_GROUPS, expand_formats

        if not self._enabled:
            return set(FORMAT_GROUPS["zeek"])

        formats: set[str] = set()
        for sensor in self.get_observing_sensors(src_ip, dst_ip):
            formats.update(sensor.log_formats)
        return expand_formats(formats)

    # ------------------------------------------------------------------
    # NAT computation
    # ------------------------------------------------------------------

    def _ip_matches_src(self, ip: str, rule: NatRule) -> bool:
        """Check if an IP matches any of a NAT rule's src entries."""
        ip_segments = self._resolve_ip_segments(ip)
        for src_entry in rule.src:
            # Check segment name match
            if src_entry in self._segment_networks and src_entry in ip_segments:
                return True
            # Check direct IP match
            if src_entry == ip:
                return True
            # Check CIDR match
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(src_entry, strict=False):
                    return True
            except ValueError:
                pass
        return False

    def compute_nat(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
    ) -> NatContext | None:
        """Compute NAT translation for a connection.

        Returns NatContext with mapped addresses if a NAT rule matches,
        or None if no translation applies.

        NAT rules are scoped per-firewall: only rules from firewalls that
        monitor segments relevant to the connection are considered.
        Rules are evaluated in order (first match wins). NAT only applies
        when traffic crosses a segment boundary — same-segment traffic
        is never NATted.
        """
        src_segments = self._resolve_ip_segments(src_ip)
        dst_segments = self._resolve_ip_segments(dst_ip)

        # Static VIPs inherit the real host's segment for visibility, but a
        # connection aimed at the public VIP still needs DNAT context before
        # endpoint sources render the host-local tuple.
        for sensor in self._sensors:
            if sensor.type != "firewall" or not sensor.nat_rules:
                continue
            sensor_segs = set(sensor.monitoring_segments)
            if not (sensor_segs & src_segments or sensor_segs & dst_segments):
                continue
            for rule in sensor.nat_rules:
                if (
                    rule.type == "static"
                    and rule.mapped_ip
                    and rule.real_ip
                    and dst_ip == rule.mapped_ip
                ):
                    return NatContext(
                        nat_type="static",
                        mapped_src_ip=src_ip,
                        mapped_src_port=src_port,
                        mapped_dst_ip=rule.real_ip,
                        mapped_dst_port=dst_port,
                    )

        # Same-segment traffic: no NAT
        if src_segments and dst_segments and src_segments & dst_segments:
            return None

        # Iterate firewall sensors with NAT rules, scoped to connection path
        for sensor in self._sensors:
            if sensor.type != "firewall" or not sensor.nat_rules:
                continue
            sensor_segs = set(sensor.monitoring_segments)
            # Firewall must monitor a segment relevant to this connection,
            # OR the dst_ip matches a static NAT mapped_ip on this firewall
            # (for inbound connections to a public VIP not in any segment)
            has_static_vip_match = any(
                r.type == "static" and r.mapped_ip == dst_ip for r in sensor.nat_rules
            )
            if not (
                sensor_segs & src_segments or sensor_segs & dst_segments or has_static_vip_match
            ):
                continue

            sensor_name = sensor.hostname or sensor.name
            for rule_idx, rule in enumerate(sensor.nat_rules):
                if rule.type == "dynamic_pat":
                    # Outbound PAT: src matches rule's src segments
                    if self._ip_matches_src(src_ip, rule) and not dst_segments:
                        key = (sensor_name, rule_idx)
                        port = self._pat_port_counters[key]
                        pat_rng = random.Random(port)
                        gap = pat_rng.randint(1, 255)
                        next_port = port + gap
                        if next_port > 65535:
                            next_port = 1024 + (next_port - 1024) % (65535 - 1024 + 1)
                        self._pat_port_counters[key] = next_port
                        return NatContext(
                            nat_type="dynamic_pat",
                            mapped_src_ip=rule.mapped_ip,
                            mapped_src_port=port,
                            mapped_dst_ip=dst_ip,
                            mapped_dst_port=dst_port,
                        )

                elif rule.type == "static":
                    # Outbound static: src_ip is the real_ip, dst must be external
                    if rule.real_ip and src_ip == rule.real_ip and not dst_segments:
                        return NatContext(
                            nat_type="static",
                            mapped_src_ip=rule.mapped_ip,
                            mapped_src_port=src_port,
                            mapped_dst_ip=dst_ip,
                            mapped_dst_port=dst_port,
                        )
                    # Inbound static: dst_ip is the mapped_ip (public)
                    if rule.mapped_ip and dst_ip == rule.mapped_ip and rule.real_ip:
                        return NatContext(
                            nat_type="static",
                            mapped_src_ip=src_ip,
                            mapped_src_port=src_port,
                            mapped_dst_ip=rule.real_ip,
                            mapped_dst_port=dst_port,
                        )
                    # Inbound static with an already-translated canonical tuple:
                    # some generators model the real DMZ host as the destination
                    # while the firewall still needs the public VIP for ASA
                    # source-native rendering.
                    if (
                        rule.mapped_ip
                        and rule.real_ip
                        and dst_ip == rule.real_ip
                        and not src_segments
                    ):
                        return NatContext(
                            nat_type="static",
                            mapped_src_ip=src_ip,
                            mapped_src_port=src_port,
                            mapped_dst_ip=rule.real_ip,
                            mapped_dst_port=dst_port,
                            pre_nat_dst_ip=rule.mapped_ip,
                            pre_nat_dst_port=dst_port,
                        )

        return None
