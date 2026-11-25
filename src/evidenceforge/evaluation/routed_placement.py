"""Independent sensor placement for scenarios with authored routing.

Ground-truth agreement re-derives which sensors should observe each flow instead of trusting
the generator. This module deliberately imports nothing from the generator's routing or
visibility code: it reads the authored topology and applies the documented forwarding rules
itself, so a defect in either implementation shows up as a disagreement. The visibility parity
tests hold both implementations to hand-written expectations.

Rules, as documented in the scenario network reference:

- A flow follows connected subnets, then the longest matching static route at each device.
- Traffic to a static NAT address is delivered to its real host only through the translating
  firewall.
- A firewall observes traffic it forwards, and denied traffic at the first firewall on the path.
- A link TAP observes traffic crossing its link (``scope: internet`` only Internet flows).
- A segment sensor observes traffic on its segments' links, with its direction and TAP rules.
"""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network

from evidenceforge.models.scenario import NetworkConfig, NetworkSensor, System

Address = IPv4Address | IPv6Address
Network = IPv4Network | IPv6Network


@dataclass(frozen=True)
class _Route:
    prefix: Network
    link: str
    peer: str | None


@dataclass(frozen=True)
class _Flow:
    """A routed attempt: the links crossed and the devices that forwarded onto them."""

    hops: tuple[tuple[str, str | None], ...]
    delivered: bool


class RoutedPlacement:
    """Which sensors an authored routed topology places on a flow's path."""

    def __init__(self, network: NetworkConfig, systems: list[System]) -> None:
        if network.routing is None:
            raise ValueError("RoutedPlacement needs an authored routing topology")
        self._network = network
        self._routing = network.routing
        self._segments = sorted(
            (
                (segment.name, ip_network(segment.cidr, strict=False))
                for segment in network.segments
            ),
            key=lambda item: item[1].prefixlen,
            reverse=True,
        )
        self._hosts = {ip_address(system.ip) for system in systems}
        self._segment_link: dict[str, str] = {}
        self._internet: dict[int, str] = {}
        self._interfaces: dict[Address, tuple[str, str]] = {}
        self._routes: dict[str, list[_Route]] = {device: [] for device in self._routing.devices}
        for link_id, link in self._routing.links.items():
            if link.segment is not None:
                self._segment_link[link.segment] = link_id
            for device, interface in link.interfaces.items():
                self._interfaces[interface.ip] = (device, link_id)
                if link.internet:
                    self._internet[interface.ip.version] = link_id
                elif link.segment is not None:
                    subnet = dict(self._segments)[link.segment]
                    self._routes[device].append(_Route(subnet, link_id, None))
        for device, routes in self._routing.routes.items():
            for route in routes:
                if route.next_hop is not None:
                    peer, link_id = self._interfaces[route.next_hop]
                    self._routes[device].append(_Route(route.destination, link_id, peer))
                elif route.internet_link is not None:
                    self._routes[device].append(
                        _Route(route.destination, route.internet_link, None)
                    )
        for routes in self._routes.values():
            routes.sort(key=lambda route: route.prefix.prefixlen, reverse=True)
        self._firewall = {
            device: declaration.firewall
            for device, declaration in self._routing.devices.items()
            if declaration.firewall
        }
        # Static NAT: public address -> (private address, translating firewall).
        self._published: dict[str, tuple[str, str]] = {}
        for sensor in network.sensors:
            if sensor.type != "firewall":
                continue
            for rule in sensor.nat_rules:
                if rule.type == "static" and rule.real_ip:
                    self._published.setdefault(rule.mapped_ip, (rule.real_ip, sensor.name))

    def _segment(self, address: Address) -> str | None:
        return next((name for name, subnet in self._segments if address in subnet), None)

    def _external(self, address: Address) -> bool:
        return (
            self._segment(address) is None
            and address not in self._interfaces
            and address not in self._hosts
        )

    def _trace(self, source: Address, destination: Address) -> _Flow:
        if source.version != destination.version:
            return _Flow((), False)
        if source == destination:
            return _Flow((), True)
        source_segment, destination_segment = self._segment(source), self._segment(destination)
        source_interface = self._interfaces.get(source)
        destination_interface = self._interfaces.get(destination)
        if (
            source_interface is None
            and destination_interface is None
            and source_segment is not None
            and source_segment == destination_segment
        ):
            return _Flow((), True)  # Same-LAN unicast never reaches a router.
        hops: list[tuple[str, str | None]] = []
        if source_interface is not None:
            device = source_interface[0]
        elif source_segment is not None:
            access = self._segment_link.get(source_segment)
            if access is not None and destination_interface and destination_interface[1] == access:
                return _Flow(((access, None),), True)
            gateway = self._routing.gateways.get(source_segment)
            if gateway is None:
                return _Flow((), False)
            device = gateway
            if access is not None:
                hops.append((access, None))
        elif not self._external(source):
            return _Flow((), False)
        else:
            ingress = self._internet.get(source.version)
            if ingress is None or self._external(destination):
                return _Flow((), False)
            hops.append((ingress, None))
            device = next(iter(self._routing.links[ingress].interfaces))
        visited: set[str] = set()
        while device not in visited:
            visited.add(device)
            if destination_interface is not None and destination_interface[0] == device:
                return _Flow(tuple(hops), True)
            route = next((r for r in self._routes[device] if destination in r.prefix), None)
            if route is None:
                return _Flow(tuple(hops), False)
            originated = source_interface is not None and not hops
            hops.append((route.link, None if originated else device))
            if route.peer is not None:
                device = route.peer
                continue
            link = self._routing.links[route.link]
            arrived = (
                (link.internet and self._external(destination))
                or (destination_interface is not None and destination_interface[1] == route.link)
                or (destination_segment is not None and link.segment == destination_segment)
            )
            return _Flow(tuple(hops), bool(arrived))
        return _Flow(tuple(hops), False)  # Routing loop.

    def observing(self, src_ip: str, dst_ip: str, *, denied: bool = False) -> set[str]:
        """Names of the sensors placed on a flow, including its response path."""
        source = ip_address(self._published.get(src_ip, (src_ip, ""))[0])
        destination = ip_address(self._published.get(dst_ip, (dst_ip, ""))[0])
        forward = self._trace(source, destination)
        published = self._published.get(dst_ip)
        if published is not None and published[1] not in {
            self._firewall.get(forwarder or "") for _link, forwarder in forward.hops
        }:
            # A packet addressed to the public address must reach the translating firewall.
            attempt = self._trace(source, ip_address(dst_ip))
            stop = next(
                (
                    index
                    for index, (_link, forwarder) in enumerate(attempt.hops)
                    if self._firewall.get(forwarder or "") == published[1]
                ),
                len(attempt.hops),
            )
            forward = _Flow(attempt.hops[:stop], False)
        denied_by: str | None = None
        if denied:
            for index, (_link, forwarder) in enumerate(forward.hops):
                if forwarder in self._firewall:
                    denied_by = self._firewall[forwarder]
                    forward = _Flow(forward.hops[:index], False)
                    break
        if source == destination and not forward.hops:
            return set()
        reverse = self._trace(destination, source) if forward.delivered else _Flow((), False)
        hops = forward.hops + (reverse.hops if forward.delivered and reverse.delivered else ())
        links = {link for link, _forwarder in hops}
        firewalls = {self._firewall[f] for _link, f in forward.hops if f in self._firewall}
        if denied_by is not None:
            firewalls.add(denied_by)
        observed = {self._routing.links[link].segment for link in links} - {None}
        source_segments = {s for s in [self._segment(source)] if s is not None}
        destination_segments = {s for s in [self._segment(destination)] if s is not None}
        if not hops and forward.delivered:
            observed |= source_segments & destination_segments
        visible_source = source_segments & observed
        visible_destination = destination_segments & observed if forward.delivered else set()
        internet_flow = (
            source.version == destination.version
            and source.version in self._internet
            and self._external(source) != self._external(destination)
        )
        names: set[str] = set()
        for sensor in self._network.sensors:
            if sensor.type == "firewall":
                seen = sensor.name in firewalls
            elif sensor.link_tap is not None:
                seen = sensor.link_tap.link in links and (
                    sensor.link_tap.scope == "all" or internet_flow
                )
            else:
                seen = _segment_sensor_sees(sensor, visible_source, visible_destination)
            if seen:
                names.add(sensor.name)
        return names


def _segment_sensor_sees(sensor: NetworkSensor, source: set[str], destination: set[str]) -> bool:
    """A SPAN or segment TAP sensor, by its direction; a TAP misses traffic within its segment."""
    monitored = set(sensor.monitoring_segments)
    if sensor.direction == "outbound":
        seen = bool(monitored & source)
    elif sensor.direction == "inbound":
        seen = bool(monitored & destination)
    else:
        seen = bool(monitored & (source | destination))
    if seen and sensor.placement == "tap" and source and destination:
        if source == destination:
            return False
        if len(monitored) > 1 and not (monitored & source and monitored & destination):
            return False
    return seen
