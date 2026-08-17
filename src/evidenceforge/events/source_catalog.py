# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical source-format, family, and collection-capability catalog.

The catalog is immutable generation metadata. It names concrete renderer
formats once, describes where each source can be deployed, and expands authored
group names without importing the dispatcher or emitter implementations.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType

from evidenceforge.events.collection_policy import CollectionCapability
from evidenceforge.models.exceptions import ConfigurationError


class SourceCatalogError(ConfigurationError):
    """A source catalog name or relationship is invalid or ambiguous."""


class SourceOwnerKind(StrEnum):
    """Runtime owner of one concrete collection source."""

    HOST = "host"
    SENSOR = "sensor"


def _catalog_name(value: str, field_name: str) -> str:
    normalized = value.strip().casefold()
    if not normalized:
        raise SourceCatalogError(f"{field_name} must not be empty")
    if any(not (character.isalnum() or character in "._-") for character in normalized):
        raise SourceCatalogError(
            f"{field_name} {value!r} may contain only letters, digits, '.', '_', and '-'"
        )
    return normalized


def _marker(value: str) -> str:
    return _catalog_name(value.replace("_", "-"), "applicability marker")


def source_platform_for_os(os_name: str) -> str:
    """Return the canonical deployment platform for a scenario OS label."""

    normalized = os_name.strip().casefold()
    if "windows" in normalized:
        return "windows"
    if any(
        marker in normalized
        for marker in ("linux", "ubuntu", "centos", "debian", "rhel", "red hat")
    ):
        return "linux"
    if any(marker in normalized for marker in ("macos", "mac os", "darwin", "os x")):
        return "macos"
    return "unknown"


@dataclass(frozen=True, slots=True)
class SourceFormatDescriptor:
    """Immutable semantics for one concrete emitter format."""

    name: str
    family: str
    owner: SourceOwnerKind
    capabilities: CollectionCapability
    platforms: frozenset[str] = frozenset()
    sensor_types: frozenset[str] = frozenset()
    required_roles: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        """Normalize identity and reject contradictory applicability rules."""

        name = _catalog_name(self.name, "source format")
        family = _catalog_name(self.family, "source family")
        owner = SourceOwnerKind(self.owner)
        capabilities = CollectionCapability(self.capabilities)
        platforms = frozenset(_marker(value) for value in self.platforms)
        sensor_types = frozenset(_marker(value) for value in self.sensor_types)
        required_roles = frozenset(_marker(value) for value in self.required_roles)

        if capabilities == CollectionCapability.NONE:
            raise SourceCatalogError(f"source format {name!r} must provide capabilities")
        if owner is SourceOwnerKind.HOST:
            if not platforms:
                raise SourceCatalogError(f"host source format {name!r} requires a platform")
            if sensor_types:
                raise SourceCatalogError(f"host source format {name!r} cannot declare sensor types")
        elif platforms or required_roles:
            raise SourceCatalogError(
                f"sensor source format {name!r} cannot declare host applicability"
            )
        elif not sensor_types:
            raise SourceCatalogError(f"sensor source format {name!r} requires a sensor type")

        object.__setattr__(self, "name", name)
        object.__setattr__(self, "family", family)
        object.__setattr__(self, "owner", owner)
        object.__setattr__(self, "capabilities", capabilities)
        object.__setattr__(self, "platforms", platforms)
        object.__setattr__(self, "sensor_types", sensor_types)
        object.__setattr__(self, "required_roles", required_roles)

    def applies_to_host(self, platform: str, roles: Iterable[str] = ()) -> bool:
        """Return whether this format is deployable on one normalized host."""

        if self.owner is not SourceOwnerKind.HOST:
            return False
        normalized_platform = _marker(platform)
        normalized_roles = frozenset(_marker(role) for role in roles)
        return normalized_platform in self.platforms and (
            not self.required_roles or bool(self.required_roles & normalized_roles)
        )

    def applies_to_sensor(self, sensor_type: str) -> bool:
        """Return whether this format is deployable on one sensor type."""

        return self.owner is SourceOwnerKind.SENSOR and _marker(sensor_type) in self.sensor_types


@dataclass(frozen=True, slots=True)
class SourceCatalog:
    """Validated immutable catalog with deterministic group expansion."""

    descriptors: tuple[SourceFormatDescriptor, ...]
    groups: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    aliases: Mapping[str, str] = field(default_factory=dict)
    _by_name: Mapping[str, SourceFormatDescriptor] = field(init=False, repr=False)
    _expanded: Mapping[str, tuple[str, ...]] = field(init=False, repr=False)
    _families: Mapping[str, tuple[str, ...]] = field(init=False, repr=False)
    _digest: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        """Build exact maps and prove every alias/group expansion is unambiguous."""

        descriptors = tuple(sorted(self.descriptors, key=lambda item: item.name))
        by_name: dict[str, SourceFormatDescriptor] = {}
        for descriptor in descriptors:
            if descriptor.name in by_name:
                raise SourceCatalogError(f"duplicate source format {descriptor.name!r}")
            by_name[descriptor.name] = descriptor

        groups: dict[str, tuple[str, ...]] = {}
        for raw_name, raw_members in self.groups.items():
            name = _catalog_name(raw_name, "source format group")
            if name in by_name or name in groups:
                raise SourceCatalogError(f"ambiguous source catalog name {name!r}")
            members = tuple(
                sorted(
                    {
                        _catalog_name(member, f"member of source group {name!r}")
                        for member in raw_members
                    }
                )
            )
            if not members:
                raise SourceCatalogError(f"source format group {name!r} must not be empty")
            groups[name] = members

        aliases: dict[str, str] = {}
        for raw_name, raw_target in self.aliases.items():
            name = _catalog_name(raw_name, "source format alias")
            if name in by_name or name in groups or name in aliases:
                raise SourceCatalogError(f"ambiguous source catalog name {name!r}")
            aliases[name] = _catalog_name(raw_target, f"target of source alias {name!r}")

        expanded: dict[str, tuple[str, ...]] = {}

        def expand_token(token: str, stack: tuple[str, ...] = ()) -> tuple[str, ...]:
            if token in expanded:
                return expanded[token]
            if token in stack:
                cycle = " -> ".join((*stack, token))
                raise SourceCatalogError(f"cyclic source catalog expansion: {cycle}")
            if token in by_name:
                result = (token,)
            elif token in aliases:
                result = expand_token(aliases[token], (*stack, token))
            elif token in groups:
                members: set[str] = set()
                for member in groups[token]:
                    members.update(expand_token(member, (*stack, token)))
                result = tuple(sorted(members))
            else:
                raise SourceCatalogError(f"unknown source catalog name {token!r}")
            expanded[token] = result
            return result

        for name in (*by_name, *groups, *aliases):
            expand_token(name)

        families: dict[str, list[str]] = {}
        for descriptor in descriptors:
            families.setdefault(descriptor.family, []).append(descriptor.name)
        frozen_families = {
            family: tuple(sorted(format_names)) for family, format_names in families.items()
        }

        payload = {
            "formats": [
                {
                    "name": descriptor.name,
                    "family": descriptor.family,
                    "owner": descriptor.owner.value,
                    "capabilities": int(descriptor.capabilities),
                    "platforms": sorted(descriptor.platforms),
                    "sensor_types": sorted(descriptor.sensor_types),
                    "required_roles": sorted(descriptor.required_roles),
                }
                for descriptor in descriptors
            ],
            "groups": {name: list(groups[name]) for name in sorted(groups)},
            "aliases": {name: aliases[name] for name in sorted(aliases)},
        }
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

        object.__setattr__(self, "descriptors", descriptors)
        object.__setattr__(self, "groups", MappingProxyType(groups))
        object.__setattr__(self, "aliases", MappingProxyType(aliases))
        object.__setattr__(self, "_by_name", MappingProxyType(by_name))
        object.__setattr__(self, "_expanded", MappingProxyType(expanded))
        object.__setattr__(self, "_families", MappingProxyType(frozen_families))
        object.__setattr__(self, "_digest", digest)

    @property
    def digest(self) -> str:
        """Return the deterministic catalog definition digest."""

        return self._digest

    @property
    def format_names(self) -> tuple[str, ...]:
        """Return every concrete format name in deterministic order."""

        return tuple(self._by_name)

    @property
    def family_names(self) -> tuple[str, ...]:
        """Return every source family name in deterministic order."""

        return tuple(sorted(self._families))

    def descriptor(self, format_name: str) -> SourceFormatDescriptor:
        """Return one exact concrete format descriptor."""

        name = _catalog_name(format_name, "source format")
        descriptor = self._by_name.get(name)
        if descriptor is None:
            raise SourceCatalogError(f"unknown concrete source format {name!r}")
        return descriptor

    def expand(self, names: Iterable[str]) -> tuple[str, ...]:
        """Expand concrete names, aliases, and groups into sorted formats."""

        result: set[str] = set()
        for raw_name in names:
            name = _catalog_name(raw_name, "source format selection")
            expansion = self._expanded.get(name)
            if expansion is None:
                raise SourceCatalogError(f"unknown source format selection {name!r}")
            result.update(expansion)
        return tuple(sorted(result))

    def formats_for_family(self, family: str) -> tuple[str, ...]:
        """Return concrete formats for one exact family without scanning."""

        return self._families.get(_catalog_name(family, "source family"), ())


_NETWORK_DIRECTIONS = (
    CollectionCapability.NETWORK
    | CollectionCapability.SOURCE_ENDPOINT
    | CollectionCapability.DESTINATION_ENDPOINT
)
_ENDPOINT_ACTOR = CollectionCapability.SOURCE_ENDPOINT | CollectionCapability.COHERENT_ACTOR


def _host(
    name: str,
    family: str,
    capabilities: CollectionCapability,
    platforms: frozenset[str],
    *,
    roles: frozenset[str] = frozenset(),
) -> SourceFormatDescriptor:
    return SourceFormatDescriptor(
        name=name,
        family=family,
        owner=SourceOwnerKind.HOST,
        capabilities=capabilities,
        platforms=platforms,
        required_roles=roles,
    )


def _sensor(
    name: str,
    family: str,
    capabilities: CollectionCapability,
    sensor_type: str,
) -> SourceFormatDescriptor:
    return SourceFormatDescriptor(
        name=name,
        family=family,
        owner=SourceOwnerKind.SENSOR,
        capabilities=capabilities,
        sensor_types=frozenset({sensor_type}),
    )


_WINDOWS = frozenset({"windows"})
_LINUX = frozenset({"linux"})
_ENDPOINT_PLATFORMS = frozenset({"windows", "linux"})

DEFAULT_SOURCE_CATALOG = SourceCatalog(
    descriptors=(
        _host(
            "windows_event_security",
            "windows_security",
            CollectionCapability.PROCESS
            | CollectionCapability.AUTHENTICATION
            | CollectionCapability.SESSION
            | CollectionCapability.NETWORK
            | CollectionCapability.FILE
            | CollectionCapability.SERVICE
            | CollectionCapability.TASK
            | CollectionCapability.ACCOUNT
            | CollectionCapability.SMB
            | _ENDPOINT_ACTOR
            | CollectionCapability.DESTINATION_ENDPOINT,
            _WINDOWS,
        ),
        _host(
            "windows_event_sysmon",
            "sysmon",
            CollectionCapability.PROCESS
            | CollectionCapability.NETWORK
            | CollectionCapability.DNS
            | CollectionCapability.FILE
            | CollectionCapability.REGISTRY
            | _ENDPOINT_ACTOR,
            _WINDOWS,
        ),
        _host(
            "ecar",
            "ecar",
            CollectionCapability.PROCESS
            | CollectionCapability.AUTHENTICATION
            | CollectionCapability.SESSION
            | CollectionCapability.NETWORK
            | CollectionCapability.DNS
            | CollectionCapability.FILE
            | CollectionCapability.REGISTRY
            | CollectionCapability.SERVICE
            | CollectionCapability.TASK
            | CollectionCapability.ACCOUNT
            | CollectionCapability.SMB
            | _ENDPOINT_ACTOR
            | CollectionCapability.DESTINATION_ENDPOINT,
            _ENDPOINT_PLATFORMS,
        ),
        _host(
            "syslog",
            "syslog",
            CollectionCapability.PROCESS
            | CollectionCapability.AUTHENTICATION
            | CollectionCapability.SESSION
            | CollectionCapability.FILE
            | CollectionCapability.SERVICE
            | CollectionCapability.TASK
            | CollectionCapability.SSH
            | CollectionCapability.SMB
            | _ENDPOINT_ACTOR,
            _LINUX,
        ),
        _host(
            "bash_history",
            "bash_history",
            CollectionCapability.PROCESS | CollectionCapability.COHERENT_ACTOR,
            _LINUX,
        ),
        _host(
            "proxy_access",
            "proxy",
            CollectionCapability.AUTHENTICATION
            | CollectionCapability.NETWORK
            | CollectionCapability.HTTP
            | CollectionCapability.COHERENT_ACTOR,
            _ENDPOINT_PLATFORMS,
            roles=frozenset({"forward-proxy"}),
        ),
        _host(
            "web_access",
            "web",
            CollectionCapability.AUTHENTICATION
            | CollectionCapability.NETWORK
            | CollectionCapability.HTTP
            | CollectionCapability.COHERENT_ACTOR,
            _ENDPOINT_PLATFORMS,
            roles=frozenset({"web-server"}),
        ),
        _sensor("zeek_conn", "zeek", _NETWORK_DIRECTIONS, "network"),
        _sensor(
            "zeek_dns",
            "zeek",
            _NETWORK_DIRECTIONS | CollectionCapability.DNS | CollectionCapability.DNS_ANALYZER,
            "network",
        ),
        _sensor(
            "zeek_http",
            "zeek",
            _NETWORK_DIRECTIONS | CollectionCapability.HTTP | CollectionCapability.HTTP_ANALYZER,
            "network",
        ),
        _sensor("zeek_smtp", "zeek", _NETWORK_DIRECTIONS, "network"),
        _sensor(
            "zeek_ssl",
            "zeek",
            _NETWORK_DIRECTIONS | CollectionCapability.TLS | CollectionCapability.TLS_ANALYZER,
            "network",
        ),
        _sensor(
            "zeek_files",
            "zeek",
            _NETWORK_DIRECTIONS | CollectionCapability.FILE | CollectionCapability.FILE_ANALYZER,
            "network",
        ),
        _sensor(
            "zeek_smb_files",
            "zeek",
            _NETWORK_DIRECTIONS
            | CollectionCapability.SMB
            | CollectionCapability.FILE
            | CollectionCapability.SMB_ANALYZER
            | CollectionCapability.FILE_ANALYZER,
            "network",
        ),
        _sensor(
            "zeek_smb_mapping",
            "zeek",
            _NETWORK_DIRECTIONS | CollectionCapability.SMB | CollectionCapability.SMB_ANALYZER,
            "network",
        ),
        _sensor(
            "zeek_x509",
            "zeek",
            _NETWORK_DIRECTIONS | CollectionCapability.TLS | CollectionCapability.TLS_ANALYZER,
            "network",
        ),
        _sensor("zeek_dhcp", "zeek", _NETWORK_DIRECTIONS, "network"),
        _sensor("zeek_ntp", "zeek", _NETWORK_DIRECTIONS, "network"),
        _sensor("zeek_weird", "zeek", _NETWORK_DIRECTIONS, "network"),
        _sensor(
            "zeek_ocsp",
            "zeek",
            _NETWORK_DIRECTIONS | CollectionCapability.TLS | CollectionCapability.TLS_ANALYZER,
            "network",
        ),
        _sensor(
            "zeek_pe",
            "zeek",
            _NETWORK_DIRECTIONS | CollectionCapability.FILE | CollectionCapability.FILE_ANALYZER,
            "network",
        ),
        _sensor("zeek_packet_filter", "zeek", _NETWORK_DIRECTIONS, "network"),
        _sensor("zeek_reporter", "zeek", _NETWORK_DIRECTIONS, "network"),
        _sensor("snort_alert", "ids", _NETWORK_DIRECTIONS | CollectionCapability.IDS, "ids"),
        _sensor("cisco_asa", "asa", _NETWORK_DIRECTIONS, "firewall"),
    ),
    groups={
        "windows": ("windows_event_security", "windows_event_sysmon"),
        "zeek": (
            "zeek_conn",
            "zeek_dns",
            "zeek_http",
            "zeek_smtp",
            "zeek_ssl",
            "zeek_files",
            "zeek_smb_files",
            "zeek_smb_mapping",
            "zeek_x509",
            "zeek_dhcp",
            "zeek_ntp",
            "zeek_weird",
            "zeek_ocsp",
            "zeek_pe",
            "zeek_packet_filter",
            "zeek_reporter",
        ),
    },
)


def source_family_for_format(format_name: str) -> str:
    """Return the canonical family, preserving unknown legacy renderer names."""

    name = _catalog_name(format_name, "source format")
    descriptor = DEFAULT_SOURCE_CATALOG._by_name.get(name)
    return descriptor.family if descriptor is not None else name


def expand_source_formats(names: Iterable[str]) -> tuple[str, ...]:
    """Expand source selections with the canonical catalog."""

    return DEFAULT_SOURCE_CATALOG.expand(names)


__all__ = [
    "DEFAULT_SOURCE_CATALOG",
    "SourceCatalog",
    "SourceCatalogError",
    "SourceFormatDescriptor",
    "SourceOwnerKind",
    "expand_source_formats",
    "source_family_for_format",
    "source_platform_for_os",
]
