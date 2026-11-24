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
from dataclasses import dataclass

from evidenceforge.events.contexts import NatContext
from evidenceforge.generation.firewall_policy import evaluate_firewall_policy
from evidenceforge.generation.routing import Path, RoutingTable
from evidenceforge.models.scenario import NatRule, NetworkConfig, NetworkSensor, System

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RoutedConnection:
    forward: Path
    reverse: Path
    denied_by: NetworkSensor | None = None

    @property
    def reachable(self) -> bool:
        return self.forward.delivered and self.reverse.delivered


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
        self._vip_firewall: dict[str, str] = {}
        self._real_ip_to_vip: dict[str, str] = {}
        # Public address space for external scan targets
        self._public_cidrs: list[ipaddress.IPv4Network] = []
        self.routing = (
            RoutingTable(network_config, systems)
            if network_config is not None and network_config.routing is not None
            else None
        )

        if self._enabled:
            self._build_topology(network_config, systems)

    @property
    def enabled(self) -> bool:
        """True when a network topology (segments/sensors) is configured.

        When False, there is no sensor to capture sensor-only formats (e.g. Zeek), so callers
        deciding whether such a source will actually land must treat it as not observed.
        """
        return self._enabled

    def get_sensor(self, hostname: str) -> NetworkSensor | None:
        """Return the configured sensor identified by hostname or logical name.

        Deployed source identities fold hostname case, so lookups are case-insensitive.
        """

        key = hostname.casefold()
        return next(
            (
                sensor
                for sensor in self._sensors
                if key in {sensor.name.casefold(), (sensor.hostname or sensor.name).casefold()}
            ),
            None,
        )

    def sensor_interface(self, hostname: str, ip: str) -> str:
        """Resolve a sensor's native interface from the canonical real-address topology."""
        sensor = self.get_sensor(hostname)
        if sensor is None:
            return ""
        return self._interface_for(sensor, ip)

    def resolve_endpoint_ip(self, ip: str) -> str:
        """Return the modeled real endpoint behind a configured static NAT address."""
        return self._vip_to_real_ip.get(ip, ip)

    def _interface_for(self, sensor: NetworkSensor, ip: str) -> str:
        """Return the interface whose real-address segment contains ``ip``."""
        address = ipaddress.ip_address(self.resolve_endpoint_ip(ip))
        for name, network in self._segment_networks.items():
            if address in network:
                return sensor.interfaces.get(name, name)
        return sensor.interfaces.get("_default", "outside")

    def firewall_traverses(self, sensor: NetworkSensor, src_ip: str, dst_ip: str) -> bool:
        """Return whether a firewall is on the forwarding path between two endpoints.

        A firewall forwards traffic between its interfaces. Segments assigned to the
        same interface reach each other without crossing it, unless the destination
        is one of the firewall's translated addresses (including hairpin access to
        a static-NAT VIP). Non-firewall sensors are unaffected.
        """
        if sensor.type != "firewall" or not src_ip or not dst_ip:
            return True
        if self.routing is not None:
            return any(
                self.routing.firewalls.get(hop.forwarder) == sensor.name
                for hop in self.routed_connection(src_ip, dst_ip).forward.hops
            )
        if src_ip in self._vip_to_real_ip or dst_ip in self._vip_to_real_ip:
            return True
        try:
            return self._interface_for(sensor, src_ip) != self._interface_for(sensor, dst_ip)
        except ValueError:
            return True

    def routed_connection(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None = None,
        *,
        denied_entities: tuple[str, ...] | None = None,
    ) -> RoutedConnection | None:
        """Resolve the observed prefix and return path for a stateful flow."""
        if self.routing is None:
            return None
        src, dst = self.resolve_endpoint_ip(src_ip), self.resolve_endpoint_ip(dst_ip)
        try:
            forward = self.routing.trace(src, dst)
        except ValueError:
            return RoutedConnection(Path((), False, "invalid endpoint"), Path((), False))
        translator = self._vip_firewall.get(dst_ip)
        if translator is not None and not any(
            self.routing.firewalls.get(hop.forwarder) == translator for hop in forward.hops
        ):
            # Follow the address actually requested. A shortcut to the private
            # endpoint does not carry a packet addressed to its public VIP.
            attempted = self.routing.trace(src, dst_ip)
            stop = next(
                (
                    index
                    for index, hop in enumerate(attempted.hops)
                    if self.routing.firewalls.get(hop.forwarder) == translator
                ),
                len(attempted.hops),
            )
            forward = Path(
                attempted.hops[:stop], False, f"VIP {dst_ip} needs a path through {translator}"
            )
        for index, hop in enumerate(forward.hops):
            sensor_name = self.routing.firewalls.get(hop.forwarder)
            sensor = self.get_sensor(sensor_name) if sensor_name else None
            if sensor is None:
                continue
            forced_deny = denied_entities is not None and (
                not denied_entities
                or {sensor.name.casefold(), (sensor.hostname or sensor.name).casefold()}
                & {name.casefold() for name in denied_entities}
            )
            policy_deny = (
                dst_port is not None
                and evaluate_firewall_policy(src, dst, dst_port, sensor, self.routing.segments)
                == "deny"
            )
            if forced_deny or policy_deny:
                return RoutedConnection(
                    Path(forward.hops[:index], False, f"{sensor.name} denied traffic"),
                    Path((), False),
                    sensor,
                )
        reverse = self.routing.trace(dst, src) if forward.delivered else Path((), False)
        return RoutedConnection(forward, reverse)

    def _routed_sensors(
        self, src_ip: str, dst_ip: str, flow: RoutedConnection, *, has_response: bool
    ) -> list[NetworkSensor]:
        src = self.resolve_endpoint_ip(src_ip)
        dst = self.resolve_endpoint_ip(dst_ip)
        if src == dst and not flow.forward.hops:
            return []
        source_segments = self._resolve_ip_segments(src)
        destination_segments = self._resolve_ip_segments(dst)
        hops = flow.forward.hops + (flow.reverse.hops if flow.reachable and has_response else ())
        links = {hop.link for hop in hops}
        firewalls = {
            self.routing.firewalls[hop.forwarder]
            for hop in flow.forward.hops
            if hop.forwarder in self.routing.firewalls
        }
        if flow.denied_by is not None:
            firewalls.add(flow.denied_by.name)
        observed = {self.routing.topology.links[link].segment for link in links}
        # Same-subnet unicast can reach a segment SPAN without crossing an uplink.
        if not hops and flow.forward.delivered:
            observed.update(source_segments & destination_segments)
        visible_source = source_segments & observed
        visible_destination = destination_segments & observed if flow.forward.delivered else set()
        sensors: list[NetworkSensor] = []
        for sensor in self._sensors:
            if sensor.type == "firewall":
                visible = sensor.name in firewalls
            elif sensor.link_tap is not None:
                visible = sensor.link_tap.link in links and (
                    sensor.link_tap.scope == "all" or self.routing.is_internet_flow(src, dst)
                )
            else:
                visible = self._sensor_can_observe(sensor, visible_source, visible_destination)
            if visible:
                sensors.append(sensor)
        return sensors

    def tap_path_role(self, sensor: NetworkSensor, src_ip: str, dst_ip: str, dst_port: int) -> str:
        """Identify a TAP that sees only one direction of an established flow."""
        if sensor.link_tap is None:
            return ""
        flow = self.routed_connection(src_ip, dst_ip, dst_port)
        if flow is None or not flow.reachable:
            return ""
        link = sensor.link_tap.link
        forward = any(hop.link == link for hop in flow.forward.hops)
        reverse = any(hop.link == link for hop in flow.reverse.hops)
        if forward != reverse:
            return "forward_only" if forward else "return_only"
        return ""

    def forwarding_interfaces(self, hostname: str, src_ip: str, dst_ip: str) -> tuple[str, str]:
        """Get the actual ingress and egress interface names at one firewall."""
        sensor = self.get_sensor(hostname)
        if sensor is None:
            return "", ""
        if self.routing is not None:
            flow = self.routed_connection(src_ip, dst_ip)
            for index, hop in enumerate(flow.forward.hops):
                if index and self.routing.firewalls.get(hop.forwarder) == sensor.name:
                    links = self.routing.topology.links
                    return (
                        links[flow.forward.hops[index - 1].link].interfaces[hop.forwarder].name,
                        links[hop.link].interfaces[hop.forwarder].name,
                    )
        return self._interface_for(sensor, src_ip), self._interface_for(sensor, dst_ip)

    def tap_uses_external_tuple(
        self, sensor: NetworkSensor, src_ip: str, dst_ip: str, nat: NatContext
    ) -> bool:
        """Locate the TAP relative to the translation applied to this connection."""
        if self.routing is None or sensor.link_tap is None:
            return False
        flow = self.routed_connection(src_ip, dst_ip)
        if flow is None:
            return False
        pre_nat_dst = nat.pre_nat_dst_ip or dst_ip
        destination_nat = nat.nat_type == "static" and nat.mapped_dst_ip != pre_nat_dst
        if destination_nat:
            translator = self._vip_firewall.get(pre_nat_dst)
        else:
            translator = None
            for hop in flow.forward.hops:
                name = self.routing.firewalls.get(hop.forwarder)
                firewall = self.get_sensor(name) if name else None
                if firewall is not None and any(
                    rule.type == nat.nat_type
                    and rule.mapped_ip == nat.mapped_src_ip
                    and (
                        rule.real_ip == src_ip
                        if rule.type == "static"
                        else self._ip_matches_src(src_ip, rule)
                    )
                    for rule in firewall.nat_rules
                ):
                    translator = name
                    break
        if translator is None:
            return False
        for path, before_translation in (
            (flow.forward, destination_nat),
            (flow.reverse, not destination_nat),
        ):
            external = before_translation
            for hop in path.hops:
                if self.routing.firewalls.get(hop.forwarder) == translator:
                    external = not before_translation
                if hop.link == sensor.link_tap.link:
                    return external
        return False

    def infer_sensor_path_role(
        self,
        hostname: str,
        src_ip: str,
        dst_ip: str,
        *,
        link_local: bool = False,
    ) -> str:
        """Return the sensor's topological role for one canonical connection."""

        sensor = self.get_sensor(hostname)
        if sensor is None:
            return "unspecified"
        if link_local:
            return "link_local"
        monitored = set(sensor.monitoring_segments)
        source_side = bool(monitored & self._resolve_ip_segments(src_ip))
        destination_side = bool(monitored & self._resolve_ip_segments(dst_ip))
        if source_side and destination_side:
            return "local_segment"
        if source_side:
            return "source_side"
        if destination_side:
            return "destination_side"
        return "transit"

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
                    self._vip_firewall[rule.mapped_ip] = sensor.name
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

        Routed traffic uses the most specific subnet selected by the forwarding
        table. The legacy model can associate an address with multiple segments.

        Returns empty set for external IPs not in any segment.
        """
        if self.routing is not None:
            try:
                segment = self.routing.segment(ipaddress.ip_address(self.resolve_endpoint_ip(ip)))
            except ValueError:
                return set()
            return {segment} if segment is not None else set()

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

        if self.routing is not None:
            return bool(self.get_observing_sensors(src_ip, dst_ip))

        src_segments = self._resolve_ip_segments(src_ip)
        dst_segments = self._resolve_ip_segments(dst_ip)
        return any(
            self._sensor_can_observe(sensor, src_segments, dst_segments)
            and self.firewall_traverses(sensor, src_ip, dst_ip)
            for sensor in self._sensors
        )

    def get_observing_sensors(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None = None,
        *,
        denied_entities: tuple[str, ...] | None = None,
        has_response: bool = True,
    ) -> list[NetworkSensor]:
        """Return sensors on the resolved path, or with legacy segment coverage."""
        if not self._enabled:
            return []
        flow = self.routed_connection(src_ip, dst_ip, dst_port, denied_entities=denied_entities)
        if flow is not None:
            return self._routed_sensors(src_ip, dst_ip, flow, has_response=has_response)
        src_segments = self._resolve_ip_segments(src_ip)
        dst_segments = self._resolve_ip_segments(dst_ip)
        return [
            sensor
            for sensor in self._sensors
            if self._sensor_can_observe(sensor, src_segments, dst_segments)
            and self.firewall_traverses(sensor, src_ip, dst_ip)
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

        if self.routing is not None and dst_ip:
            return self.get_observing_sensors(src_ip, dst_ip, denied_entities=())

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
            and self.firewall_traverses(sensor, src_ip, dst_ip)
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
        flow = self.routed_connection(src_ip, dst_ip, dst_port)
        if flow is None:
            traversed = self._sensors
        else:
            names = dict.fromkeys(
                self.routing.firewalls[hop.forwarder]
                for hop in flow.forward.hops
                if hop.forwarder in self.routing.firewalls
            )
            traversed = [sensor for name in names if (sensor := self.get_sensor(name)) is not None]
        src_segments = self._resolve_ip_segments(src_ip)
        dst_segments = self._resolve_ip_segments(dst_ip)

        # Static VIPs inherit the real host's segment for visibility, but a
        # connection aimed at the public VIP still needs DNAT context before
        # endpoint sources render the host-local tuple.
        for sensor in traversed:
            if sensor.type != "firewall" or not sensor.nat_rules:
                continue
            sensor_segs = set(sensor.monitoring_segments)
            if flow is None and not (sensor_segs & src_segments or sensor_segs & dst_segments):
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
        for sensor in traversed:
            if sensor.type != "firewall" or not sensor.nat_rules:
                continue
            sensor_segs = set(sensor.monitoring_segments)
            # Firewall must monitor a segment relevant to this connection,
            # OR the dst_ip matches a static NAT mapped_ip on this firewall
            # (for inbound connections to a public VIP not in any segment)
            has_static_vip_match = any(
                r.type == "static" and r.mapped_ip == dst_ip for r in sensor.nat_rules
            )
            if flow is None and not (
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
