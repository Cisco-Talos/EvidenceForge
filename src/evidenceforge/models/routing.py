"""Optional, explicitly authored routed topology."""

from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class RoutingDevice(BaseModel):
    """Forwarding device, optionally represented by a system or firewall sensor."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["router", "switch", "firewall"] = "router"
    system: str | None = None
    firewall: str | None = None


class RoutingInterface(BaseModel):
    """One addressed interface on a link."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    ip: IPv4Address | IPv6Address


class RoutingLink(BaseModel):
    """A segment with attached interfaces, or a link to the Internet boundary."""

    model_config = ConfigDict(extra="forbid")

    segment: str | None = None
    internet: bool = False
    kind: Literal["network", "wan", "vpn"] = Field(
        default_factory=lambda: "network",
        exclude_if=lambda value: value == "network",
        description="Ordinary network link (the default), WAN circuit, or abstract VPN tunnel.",
    )
    interfaces: dict[str, RoutingInterface] = Field(min_length=1)


class StaticRoute(BaseModel):
    """A route via a neighbor's address or an explicit Internet link."""

    model_config = ConfigDict(extra="forbid")

    destination: IPv4Network | IPv6Network
    next_hop: IPv4Address | IPv6Address | None = None
    internet_link: str | None = None


class RoutingTopology(BaseModel):
    """Static topology shared by generation, validation, and Studio."""

    model_config = ConfigDict(extra="forbid")

    devices: dict[str, RoutingDevice] = Field(min_length=1)
    links: dict[str, RoutingLink] = Field(min_length=1)
    gateways: dict[str, str] = Field(default_factory=dict)
    routes: dict[str, list[StaticRoute]] = Field(default_factory=dict)


class LinkTap(BaseModel):
    """Observe a declared link, optionally limited to Internet flows."""

    model_config = ConfigDict(extra="forbid")

    link: str
    scope: Literal["all", "internet"] = "all"
