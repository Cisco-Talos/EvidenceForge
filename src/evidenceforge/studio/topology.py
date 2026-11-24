"""Project resolved environment facts into the Studio network diagram."""

from __future__ import annotations

import base64
import binascii
from collections import Counter
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from evidenceforge.generation.network_visibility import NetworkVisibilityEngine
from evidenceforge.models.routing import LinkTap, RoutingTopology
from evidenceforge.models.scenario import NetworkConfig, NetworkSegment, System
from evidenceforge.utils.platforms import platform_for_os

type DeviceKind = Literal["network", "ids", "firewall"]


class TopologySegment(BaseModel):
    """A configured segment with the address range and modeled exposure."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    cidr: str
    exposure: Literal["internal", "external", "both"]
    description: str


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


class _NetworkDeclaration(BaseModel):
    routing: RoutingTopology | None = None
    segments: list[NetworkSegment]
    sensors: list[_SensorDeclaration] = Field(default_factory=list)


class _UserPlacement(BaseModel):
    username: str
    primary_system: str | None = None


class _EnvironmentDeclaration(BaseModel):
    systems: list[System] = Field(default_factory=list)
    users: list[_UserPlacement] = Field(default_factory=list)
    network: _NetworkDeclaration | None = None


def project_topology(environment: dict[str, Any]) -> RoutedTopologyGraph:
    """Project an effective scenario environment or a partial organization model."""
    declaration = _EnvironmentDeclaration.model_validate(environment)
    segments = declaration.network.segments if declaration.network else []
    sensors = declaration.network.sensors if declaration.network else []
    systems = declaration.systems
    # Resolve the same configured host memberships as generation. The segment-only
    # index keeps translated addresses and sensor runtime state out of the diagram.
    visibility = NetworkVisibilityEngine(
        NetworkConfig(segments=segments) if segments else None, systems
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

    hosts = [
        TopologyHost(
            id=f"host:{host.hostname}",
            hostname=host.hostname,
            ip=host.ip,
            os=host.os,
            os_family=platform_for_os(host.os),
            primary_users=sorted(primary_users.get(host.hostname, ())),
            roles=host.roles,
            segment_ids=[
                segment_ids[name]
                for name in sorted(visibility._resolve_ip_segments(host.ip))
                if name in segment_ids
            ],
        )
        for host in sorted(systems, key=lambda item: item.hostname)
        if host_counts[host.hostname] == 1
    ]
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
            )
        )
    return RoutedTopologyGraph(
        segments=diagram_segments,
        hosts=hosts,
        devices=devices,
        findings=findings,
        routing=declaration.network.routing if declaration.network else None,
        link_taps={
            f"device:{sensor.hostname or sensor.name}": sensor.link_tap
            for sensor in sensors
            if sensor.link_tap is not None and device_counts[sensor.hostname or sensor.name] == 1
        },
    )
