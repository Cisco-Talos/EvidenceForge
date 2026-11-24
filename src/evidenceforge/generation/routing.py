"""Resolve static next hops and retain the links a packet actually reaches."""

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network

from evidenceforge.models.routing import RoutingTopology
from evidenceforge.models.scenario import NetworkConfig, System

type Address = IPv4Address | IPv6Address
type Prefix = IPv4Network | IPv6Network


@dataclass(frozen=True)
class Hop:
    """A packet entering a link from a forwarding device or endpoint."""

    link: str
    forwarder: str | None = None


@dataclass(frozen=True)
class Path:
    """Directional packet path, including the prefix of an unsuccessful attempt."""

    hops: tuple[Hop, ...]
    delivered: bool
    reason: str = ""


@dataclass(frozen=True)
class Route:
    prefix: Prefix
    link: str
    peer: str | None = None


class RoutingTable:
    """Compile and validate the topology of an effective scenario."""

    def __init__(self, network: NetworkConfig, systems: list[System]) -> None:
        routing = network.routing
        if routing is None:
            raise ValueError("No routing topology is declared")
        self.topology: RoutingTopology = routing
        segments = {
            segment.name: ip_network(segment.cidr, strict=False) for segment in network.segments
        }
        if len(segments) != len(network.segments) or len(set(segments.values())) != len(segments):
            raise ValueError("Routed segments need unique names and address ranges")
        self.segments = dict(
            sorted(segments.items(), key=lambda item: item[1].prefixlen, reverse=True)
        )
        system_ips = {system.hostname: ip_address(system.ip) for system in systems}
        self.host_addresses = {ip: name for name, ip in system_ips.items()}
        self.segment_links: dict[str, str] = {}
        self.internet: dict[int, str] = {}
        self.interfaces: dict[Address, tuple[str, str]] = {}
        self.firewalls: dict[str, str] = {}
        self.tables: dict[str, list[Route]] = {device: [] for device in routing.devices}
        self._validate_devices(network, systems)
        self._compile_links()
        for device, declaration in routing.devices.items():
            if declaration.system is None:
                continue
            system_ip = system_ips[declaration.system]
            if self.interfaces.get(system_ip, (None, None))[0] != device:
                raise ValueError(
                    f"System {declaration.system!r} must match an interface IP of {device!r}"
                )
        for segment, device in routing.gateways.items():
            link_id = self.segment_links.get(segment)
            if link_id is None or device not in routing.links[link_id].interfaces:
                raise ValueError(
                    f"Gateway {device!r} must have an interface on segment {segment!r}"
                )
        for device, routes in routing.routes.items():
            if device not in self.tables:
                raise ValueError(f"Routes reference unknown device {device!r}")
            for route in routes:
                if (route.next_hop is None) == (route.internet_link is None):
                    raise ValueError(
                        f"Route {device}/{route.destination} needs exactly one next hop"
                    )
                if route.next_hop is not None:
                    neighbor = self.interfaces.get(route.next_hop)
                    if neighbor is None or neighbor[0] == device:
                        raise ValueError(
                            f"Route {device}/{route.destination} needs a neighbor's IP"
                        )
                    peer, link_id = neighbor
                    local = routing.links[link_id].interfaces.get(device)
                    if (
                        local is None
                        or local.ip.version != route.destination.version
                        or route.next_hop.version != local.ip.version
                    ):
                        raise ValueError(f"Next hop {route.next_hop} is not on-link for {device}")
                    self.tables[device].append(Route(route.destination, link_id, peer))
                else:
                    link_id = self.internet.get(route.destination.version)
                    if (
                        link_id is None
                        or link_id != route.internet_link
                        or device not in routing.links[link_id].interfaces
                    ):
                        raise ValueError(
                            f"Route {device}/{route.destination} has an invalid Internet link"
                        )
                    self.tables[device].append(Route(route.destination, link_id))
        for device, routes in self.tables.items():
            if len({route.prefix for route in routes}) != len(routes):
                raise ValueError(f"Device {device!r} has ambiguous routes for the same prefix")
            routes.sort(key=lambda route: route.prefix.prefixlen, reverse=True)
        for sensor in network.sensors:
            if sensor.link_tap is None:
                continue
            if sensor.type == "firewall" or sensor.placement != "tap" or sensor.monitoring_segments:
                raise ValueError(f"Link TAP {sensor.name!r} requires tap placement and no segments")
            if sensor.direction != "bidirectional":
                raise ValueError(f"Link TAP {sensor.name!r} requires bidirectional capture")
            if sensor.link_tap.link not in routing.links:
                raise ValueError(f"Link TAP {sensor.name!r} references an unknown link")

    def _validate_devices(self, network: NetworkConfig, systems: list[System]) -> None:
        hosts = {system.hostname: system.ip for system in systems}
        firewalls = {sensor.name for sensor in network.sensors if sensor.type == "firewall"}
        claimed: set[str] = set()
        for name, device in self.topology.devices.items():
            if device.system is not None:
                if device.system not in hosts or device.system in claimed:
                    raise ValueError(f"Device {name!r} references an unknown or reused system")
                claimed.add(device.system)
            if device.kind == "firewall":
                if device.firewall not in firewalls or device.firewall in self.firewalls.values():
                    raise ValueError(f"Device {name!r} needs a unique firewall sensor name")
                self.firewalls[name] = device.firewall
            elif device.firewall is not None:
                raise ValueError(
                    f"Only firewall devices can reference a firewall sensor ({name!r})"
                )

    def _compile_links(self) -> None:
        names: set[tuple[str, str]] = set()
        for link_id, link in self.topology.links.items():
            if link.internet == (link.segment is not None):
                raise ValueError(f"Link {link_id!r} must name a segment or declare Internet")
            subnet = self.segments.get(link.segment) if link.segment is not None else None
            if link.segment is not None:
                if subnet is None or link.segment in self.segment_links:
                    raise ValueError(f"Link {link_id!r} needs a unique, known segment")
                self.segment_links[link.segment] = link_id
            if link.internet:
                if len(link.interfaces) != 1:
                    raise ValueError(f"Internet link {link_id!r} must have one device interface")
                version = next(iter(link.interfaces.values())).ip.version
                if version in self.internet:
                    raise ValueError(f"Only one Internet boundary can be declared for IPv{version}")
                self.internet[version] = link_id
            for device, interface in link.interfaces.items():
                key = (device, interface.name)
                if device not in self.tables or key in names or interface.ip in self.interfaces:
                    raise ValueError(
                        f"Link {link_id!r} has an unknown device or duplicate interface"
                    )
                names.add(key)
                owner = self.host_addresses.get(interface.ip)
                if owner is not None and self.topology.devices[device].system != owner:
                    raise ValueError(
                        f"Interface address {interface.ip} is already used by host {owner!r}"
                    )
                self.interfaces[interface.ip] = (device, link_id)
                if subnet is not None:
                    if interface.ip not in subnet:
                        raise ValueError(
                            f"Address {interface.ip} is outside segment {link.segment!r}"
                        )
                    self.tables[device].append(Route(subnet, link_id))
        unattached = self.topology.devices.keys() - {device for device, _ in names}
        if unattached:
            raise ValueError(f"Routing devices without interfaces: {', '.join(sorted(unattached))}")

    def segment(self, address: Address) -> str | None:
        """Use the most specific authored segment for an address."""
        return next((name for name, prefix in self.segments.items() if address in prefix), None)

    def is_internet_flow(self, src: str, dst: str) -> bool:
        """Check whether exactly one endpoint is beyond the authored boundary."""
        source, destination = ip_address(src), ip_address(dst)
        return (
            source.version == destination.version
            and source.version in self.internet
            and self._is_external(source) != self._is_external(destination)
        )

    def _is_external(self, address: Address) -> bool:
        return (
            self.segment(address) is None
            and address not in self.interfaces
            and address not in self.host_addresses
        )

    def trace(self, src: str, dst: str) -> Path:
        """Follow connected or longest-prefix static routes, detecting loops."""
        source, destination = ip_address(src), ip_address(dst)
        if source.version != destination.version:
            return Path((), False, "address families differ")
        if source == destination:
            return Path((), True)
        src_segment, dst_segment = self.segment(source), self.segment(destination)
        src_interface, dst_interface = self.interfaces.get(source), self.interfaces.get(destination)
        src_link = self.segment_links.get(src_segment) if src_segment else None
        if (
            src_interface is None
            and dst_interface is None
            and src_segment
            and src_segment == dst_segment
        ):
            # A local unicast stays on the LAN and never uses its routed attachment.
            return Path((), True)

        hops: list[Hop] = []
        if src_interface is not None:
            device, _ = src_interface
        elif src_segment is not None:
            if src_link is not None and dst_interface is not None and dst_interface[1] == src_link:
                return Path((Hop(src_link),), True)
            device = self.topology.gateways.get(src_segment)
            if device is None:
                return Path((), False, f"segment {src_segment} has no gateway")
            if src_link is not None:
                hops.append(Hop(src_link))
        elif not self._is_external(source):
            return Path((), False, f"host {source} has no segment")
        else:
            ingress = self.internet.get(source.version)
            if ingress is None:
                return Path((), False, "no Internet ingress")
            if self._is_external(destination):
                return Path((), False, "both endpoints are external")
            hops.append(Hop(ingress))
            device = next(iter(self.topology.links[ingress].interfaces))

        seen: set[str] = set()
        while device not in seen:
            seen.add(device)
            if dst_interface is not None and device == dst_interface[0]:
                return Path(tuple(hops), True)
            route = next(
                (route for route in self.tables[device] if destination in route.prefix), None
            )
            if route is None:
                return Path(tuple(hops), False, f"{device} has no route to {destination}")
            originator = src_interface is not None and not hops
            hops.append(Hop(route.link, None if originator else device))
            if route.peer is not None:
                device = route.peer
            elif self.topology.links[route.link].internet and self._is_external(destination):
                return Path(tuple(hops), True)
            elif (
                dst_interface is not None
                and dst_interface[1] == route.link
                or self.topology.links[route.link].segment == dst_segment
                and dst_segment is not None
            ):
                return Path(tuple(hops), True)
            else:
                return Path(tuple(hops), False, f"{device} sends {destination} to the wrong link")
        return Path(tuple(hops), False, f"routing loop at {device}")
