"""Project resolved environment facts into the Studio network diagram."""

from __future__ import annotations

import base64
import binascii
import ipaddress
from collections import Counter
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from evidenceforge.events.source_catalog import DEFAULT_SOURCE_CATALOG, SourceCatalogError
from evidenceforge.generation.network_visibility import NetworkVisibilityEngine
from evidenceforge.models.routing import LinkTap, RoutingTopology
from evidenceforge.models.scenario import (
    FirewallRule,
    NatRule,
    NetworkConfig,
    NetworkSegment,
    NetworkSensor,
    System,
)
from evidenceforge.source_families import FORMAT_FAMILIES
from evidenceforge.utils.platforms import platform_for_os

type DeviceKind = Literal["network", "ids", "firewall"]
type EvidenceDepth = Literal["protocol", "connection", "alert", "firewall", "other"]

# Display names for sensor source families in Studio. Unknown families keep their catalog name.
_FAMILY_LABELS = {"zeek": "Zeek", "ids": "Snort", "asa": "Cisco ASA"}
# Zeek logs that describe connections or sensor health rather than application protocols.
_ZEEK_CONNECTION_LOGS = frozenset(
    {"zeek_conn", "zeek_weird", "zeek_packet_filter", "zeek_reporter"}
)


class TopologySegment(BaseModel):
    """A configured segment with the address range and modeled exposure."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    cidr: str
    exposure: Literal["internal", "external", "both"]
    description: str
    parent_id: str | None = Field(
        default=None, description="The smallest other segment whose range contains this one."
    )


class TopologyHost(BaseModel):
    """One host and every segment that contains its configured address."""

    model_config = ConfigDict(extra="forbid")

    id: str
    hostname: str
    ip: str
    os: str
    os_family: str
    segment_ids: list[str]
    primary_users: list[str] = Field(default_factory=list)
    roles: list[str] = Field(default_factory=list)
    type: str = Field(default="", description="Declared system type, used when roles are absent.")
    primary_segment_id: str | None = Field(
        default=None, description="The most specific containing segment (longest prefix)."
    )
    public_address: str | None = Field(
        default=None, description="A static NAT address or globally routable host address."
    )
    public_address_source: Literal["static_nat", "public_ip"] | None = None


class SensorEvidence(BaseModel):
    """Logs one sensor writes for one source family, and how much traffic detail they carry."""

    model_config = ConfigDict(extra="forbid")

    family: str
    label: str
    depth: EvidenceDepth
    formats: list[str]


class TopologyNatRule(BaseModel):
    """One firewall address translation."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["dynamic_pat", "static"]
    src: list[str] = Field(default_factory=list)
    mapped_ip: str
    real_ip: str = ""


class TopologyPolicyRule(BaseModel):
    """One ordered firewall rule."""

    model_config = ConfigDict(extra="forbid")

    src: str
    dst: str
    ports: list[str] = Field(default_factory=list)
    action: Literal["permit", "deny"]


class TopologyAssociation(BaseModel):
    """A monitored segment, an explicit firewall interface mapping, or both."""

    model_config = ConfigDict(extra="forbid")

    segment_id: str
    monitored: bool
    interface_name: str | None


class TopologyDevice(BaseModel):
    """One configured observation or control point and its segment associations."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    hostname: str
    kind: DeviceKind
    placement: Literal["span", "tap"]
    direction: Literal["inbound", "outbound", "bidirectional"]
    log_formats: list[str]
    description: str
    default_interface: str | None
    associations: list[TopologyAssociation]
    evidence: list[SensorEvidence] = Field(default_factory=list)
    nat_rules: list[TopologyNatRule] = Field(default_factory=list)
    policy: list[TopologyPolicyRule] = Field(default_factory=list)
    default_action: Literal["permit", "deny"] | None = None


class TopologyFinding(BaseModel):
    """An unresolved or ambiguous declaration in the diagram's source."""

    model_config = ConfigDict(extra="forbid")

    entity_id: str
    message: str


class TopologyGraph(BaseModel):
    """Logical relationships from one environment snapshot, independent of layout."""

    model_config = ConfigDict(extra="forbid")

    segments: list[TopologySegment]
    hosts: list[TopologyHost]
    devices: list[TopologyDevice]
    findings: list[TopologyFinding]


class NetworkChatContext(BaseModel):
    """The topology and optional viewport captured when a user opens Author from Network."""

    model_config = ConfigDict(extra="forbid")
    revision: str = Field(min_length=1, max_length=128)
    topology: TopologyGraph
    selected_id: str | None = Field(default=None, max_length=512)
    selection_label: str | None = Field(default=None, max_length=512)
    visible_layers: list[Literal["sensors", "firewalls", "hosts"]] = Field(default_factory=list)
    expanded_subnet_ids: list[str] = Field(default_factory=list)
    sensor_key: dict[str, str] = Field(default_factory=dict)
    image: str | None = Field(default=None, max_length=3_000_000)

    @field_validator("image")
    @classmethod
    def validate_png(cls, value: str | None) -> str | None:
        if value is None:
            return None
        prefix = "data:image/png;base64,"
        try:
            image = base64.b64decode(value.removeprefix(prefix), validate=True)
        except (ValueError, binascii.Error) as error:
            raise ValueError("The network view must be a PNG image") from error
        if (
            not value.startswith(prefix)
            or len(image) < 24
            or not image.startswith(b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR")
        ):
            raise ValueError("The network view must be a PNG image")
        width = int.from_bytes(image[16:20], "big")
        height = int.from_bytes(image[20:24], "big")
        if not (0 < width <= 1400 and 0 < height <= 1400):
            raise ValueError("The network view must fit within 1400 by 1400 pixels")
        return value


class RoutedTopologyGraph(TopologyGraph):
    """Topology with optional authored routing and physical TAP attachments."""

    routing: RoutingTopology | None = None
    link_taps: dict[str, LinkTap] = Field(default_factory=dict)
    public_cidrs: list[str] = Field(default_factory=list)


class RoutedNetworkChatContext(NetworkChatContext):
    """Capture physical topology and the visibility of the firewall policy overlay."""

    topology: RoutedTopologyGraph
    firewall_scopes_visible: bool | None = None


class PackTopology(BaseModel):
    """An exact organization pack fragment and its captured identity."""

    model_config = ConfigDict(extra="forbid")

    reference: str
    source_sha256: str
    digest: str
    topology: RoutedTopologyGraph


class _SensorDeclaration(BaseModel):
    # These fields have already been validated by the resolver. Parsing the projection
    # does not need the effective catalogs or named capture profile.
    type: DeviceKind
    name: str
    hostname: str = ""
    monitoring_segments: list[str] = Field(default_factory=list)
    link_tap: LinkTap | None = None
    placement: Literal["span", "tap"] = "span"
    direction: Literal["inbound", "outbound", "bidirectional"] = "bidirectional"
    log_formats: list[str] = Field(default_factory=lambda: ["zeek"])
    interfaces: dict[str, str] = Field(default_factory=dict)
    description: str = ""
    nat_rules: list[NatRule] = Field(default_factory=list)
    policy: list[FirewallRule] = Field(default_factory=list)
    default_action: Literal["permit", "deny"] = "deny"


class _NetworkDeclaration(BaseModel):
    routing: RoutingTopology | None = None
    segments: list[NetworkSegment]
    sensors: list[_SensorDeclaration] = Field(default_factory=list)
    public_cidrs: list[str] = Field(default_factory=list)


class _UserPlacement(BaseModel):
    username: str
    primary_system: str | None = None


class _EnvironmentDeclaration(BaseModel):
    systems: list[System] = Field(default_factory=list)
    users: list[_UserPlacement] = Field(default_factory=list)
    network: _NetworkDeclaration | None = None


def sensor_evidence(log_formats: list[str]) -> list[SensorEvidence]:
    """Describe the logs a sensor writes, one entry per source family.

    Format groups expand through the canonical source catalog. Unknown names are kept as their
    own family so a custom or misspelled format remains visible in the diagram.
    """
    by_family: dict[str, set[str]] = {}
    for selection in log_formats:
        try:
            expanded: tuple[str, ...] = DEFAULT_SOURCE_CATALOG.expand((selection,))
        except SourceCatalogError:
            expanded = (selection,)
        for name in expanded:
            by_family.setdefault(FORMAT_FAMILIES.get(name, name), set()).add(name)
    evidence: list[SensorEvidence] = []
    for family in sorted(by_family):
        formats = sorted(by_family[family])
        label = _FAMILY_LABELS.get(family, family)
        depth: EvidenceDepth
        if family == "zeek":
            # The label names the tool; `formats` says which Zeek logs this sensor writes.
            depth = "connection" if set(formats) <= _ZEEK_CONNECTION_LOGS else "protocol"
        elif family == "ids":
            depth = "alert"
        elif family == "asa":
            depth = "firewall"
        else:
            depth = "other"
        evidence.append(SensorEvidence(family=family, label=label, depth=depth, formats=formats))
    return evidence


def _segment_parents(segments: list[TopologySegment]) -> dict[str, str]:
    """Map each segment to the smallest other segment whose range strictly contains it."""
    networks: list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
    for segment in segments:
        try:
            networks.append((segment.id, ipaddress.ip_network(segment.cidr, strict=False)))
        except ValueError:
            continue
    parents: dict[str, str] = {}
    for child_id, child in networks:
        containing = [
            (parent.prefixlen, parent_id)
            for parent_id, parent in networks
            if parent_id != child_id
            and parent.version == child.version
            and parent.prefixlen < child.prefixlen
            and child.subnet_of(parent)  # type: ignore[arg-type]
        ]
        if containing:
            parents[child_id] = max(containing)[1]
    return parents


def _primary_segment(ip: str, segment_ids: list[str], cidrs: dict[str, str]) -> str | None:
    """Choose the most specific segment, as longest-prefix routing does."""
    best: tuple[int, str] | None = None
    for segment_id in segment_ids:
        try:
            prefix = ipaddress.ip_network(cidrs[segment_id], strict=False).prefixlen
        except (KeyError, ValueError):
            continue
        if best is None or prefix > best[0] or (prefix == best[0] and segment_id < best[1]):
            best = (prefix, segment_id)
    return best[1] if best else None


def project_topology(environment: dict[str, Any]) -> RoutedTopologyGraph:
    """Project an effective scenario environment or a partial organization model."""
    declaration = _EnvironmentDeclaration.model_validate(environment)
    segments = declaration.network.segments if declaration.network else []
    sensors = declaration.network.sensors if declaration.network else []
    systems = declaration.systems
    public_cidrs = declaration.network.public_cidrs if declaration.network else []
    # Resolve the same configured host memberships and public addresses as generation. Only
    # firewall NAT is passed through, so capture placement and sensor runtime state stay out.
    nat_sensors = [
        NetworkSensor(
            type="firewall",
            name=sensor.name,
            hostname=sensor.hostname,
            monitoring_segments=[],
            nat_rules=sensor.nat_rules,
        )
        for sensor in sensors
        if sensor.type == "firewall" and sensor.nat_rules
    ]
    visibility = NetworkVisibilityEngine(
        NetworkConfig(segments=segments, sensors=nat_sensors, public_cidrs=public_cidrs)
        if segments
        else None,
        systems,
    )
    segment_counts = Counter(segment.name for segment in segments)
    host_counts = Counter(host.hostname for host in systems)
    device_counts = Counter(sensor.hostname or sensor.name for sensor in sensors)
    segment_ids = {name: f"segment:{name}" for name, count in segment_counts.items() if count == 1}
    findings: list[TopologyFinding] = []
    for kind, counts in (
        ("segment", segment_counts),
        ("host", host_counts),
        ("device", device_counts),
    ):
        for name, count in sorted(counts.items()):
            if count > 1:
                findings.append(
                    TopologyFinding(
                        entity_id=f"{kind}:{name}", message=f"Multiple {kind} entries use {name}."
                    )
                )

    diagram_segments: list[TopologySegment] = []
    for segment in sorted(segments, key=lambda item: item.name):
        if segment.name not in segment_ids:
            continue
        segment_id = segment_ids[segment.name]
        diagram_segments.append(
            TopologySegment(
                id=segment_id,
                name=segment.name,
                cidr=segment.cidr,
                exposure=segment.exposure,
                description=segment.description,
            )
        )
        for hostname in sorted(set(segment.systems) - host_counts.keys()):
            findings.append(
                TopologyFinding(
                    entity_id=segment_id,
                    message=f"{segment.name} refers to host {hostname}, which is absent from this environment.",
                )
            )

    primary_users: dict[str, set[str]] = {}
    for user in declaration.users:
        if user.primary_system:
            primary_users.setdefault(user.primary_system, set()).add(user.username)
    for host in systems:
        if host.assigned_user:
            primary_users.setdefault(host.hostname, set()).add(host.assigned_user)

    parents = _segment_parents(diagram_segments)
    for segment in diagram_segments:
        segment.parent_id = parents.get(segment.id)
    cidrs = {segment.id: segment.cidr for segment in diagram_segments}
    hosts: list[TopologyHost] = []
    for host in sorted(systems, key=lambda item: item.hostname):
        if host_counts[host.hostname] != 1:
            continue
        member_ids = [
            segment_ids[name]
            for name in sorted(visibility._resolve_ip_segments(host.ip))
            if name in segment_ids
        ]
        public_address = visibility.get_public_inbound_address(host.ip)
        hosts.append(
            TopologyHost(
                id=f"host:{host.hostname}",
                hostname=host.hostname,
                ip=host.ip,
                os=host.os,
                os_family=platform_for_os(host.os),
                primary_users=sorted(primary_users.get(host.hostname, ())),
                roles=host.roles,
                type=host.type,
                segment_ids=member_ids,
                primary_segment_id=_primary_segment(host.ip, member_ids, cidrs),
                public_address=public_address,
                public_address_source=(
                    None
                    if public_address is None
                    else "static_nat"
                    if visibility.get_inbound_vip(host.ip)
                    else "public_ip"
                ),
            )
        )
    devices: list[TopologyDevice] = []
    for sensor in sorted(sensors, key=lambda item: item.hostname or item.name):
        hostname = sensor.hostname or sensor.name
        if device_counts[hostname] != 1:
            continue
        device_id = f"device:{hostname}"
        monitored = set(sensor.monitoring_segments)
        interfaces = sensor.interfaces if sensor.type == "firewall" else {}
        associations: list[TopologyAssociation] = []
        for name in sorted(monitored | (interfaces.keys() - {"_default"})):
            if name not in segment_ids:
                reason = "is ambiguous" if name in segment_counts else "is absent"
                findings.append(
                    TopologyFinding(
                        entity_id=device_id,
                        message=f"{hostname} refers to segment {name}, which {reason} in this environment.",
                    )
                )
                continue
            associations.append(
                TopologyAssociation(
                    segment_id=segment_ids[name],
                    monitored=name in monitored,
                    interface_name=interfaces.get(name) if name != "_default" else None,
                )
            )
        devices.append(
            TopologyDevice(
                id=device_id,
                name=sensor.name,
                hostname=hostname,
                kind=sensor.type,
                placement=sensor.placement,
                direction=sensor.direction,
                log_formats=sensor.log_formats,
                description=sensor.description,
                default_interface=interfaces.get("_default"),
                associations=associations,
                evidence=sensor_evidence(sensor.log_formats),
                nat_rules=[
                    TopologyNatRule(
                        type="static" if rule.type == "static" else "dynamic_pat",
                        src=rule.src,
                        mapped_ip=rule.mapped_ip,
                        real_ip=rule.real_ip,
                    )
                    for rule in sensor.nat_rules
                ]
                if sensor.type == "firewall"
                else [],
                policy=[
                    TopologyPolicyRule(
                        src=rule.src,
                        dst=rule.dst,
                        ports=[str(port) for port in rule.ports],
                        action="permit" if rule.action == "permit" else "deny",
                    )
                    for rule in sensor.policy
                ]
                if sensor.type == "firewall"
                else [],
                default_action=sensor.default_action if sensor.type == "firewall" else None,
            )
        )
    return RoutedTopologyGraph(
        segments=diagram_segments,
        hosts=hosts,
        devices=devices,
        findings=findings,
        routing=declaration.network.routing if declaration.network else None,
        public_cidrs=public_cidrs,
        link_taps={
            f"device:{sensor.hostname or sensor.name}": sensor.link_tap
            for sensor in sensors
            if sensor.link_tap is not None and device_counts[sensor.hostname or sensor.name] == 1
        },
    )
