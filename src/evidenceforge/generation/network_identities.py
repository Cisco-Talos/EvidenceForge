# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Scenario-local network identity resolution.

Network identities are an in-memory overlay above the packaged DNS registry.
They let a scenario pin host/IP ownership without mutating reusable config files.
"""

from __future__ import annotations

import ipaddress
import random
from dataclasses import dataclass

from evidenceforge.generation.activity.dns_registry import (
    get_domain_ips,
    get_domain_tags,
    resolve_domain_ip,
)
from evidenceforge.models.scenario import NetworkIdentity, Scenario
from evidenceforge.utils.rng import _stable_seed


def _normalize_host(host: str) -> str:
    return host.strip().lower().rstrip(".")


def is_ip_literal(value: str | None) -> bool:
    """Return whether value is an IP literal."""

    if not value:
        return False
    try:
        ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return False
    return True


@dataclass(frozen=True, slots=True)
class ResolvedNetworkIdentity:
    """Resolved identity/host/IP tuple used during generation."""

    identity_id: str | None
    host: str | None
    ip: str | None
    tags: tuple[str, ...] = ()
    source: str = "fallback"


class ScenarioNetworkResolver:
    """Resolve scenario network identities before package DNS fallback."""

    def __init__(self, identities: list[NetworkIdentity]):
        self._identities_by_id = {identity.id: identity for identity in identities}
        self._host_to_identity: dict[str, NetworkIdentity] = {}
        self._ip_to_identity: dict[str, NetworkIdentity] = {}
        for identity in identities:
            for host in identity.hosts:
                self._host_to_identity[_normalize_host(host)] = identity
            for ip in identity.ips:
                self._ip_to_identity[ip] = identity

    @classmethod
    def from_scenario(cls, scenario: Scenario) -> ScenarioNetworkResolver:
        """Build a resolver from scenario-local identities."""

        return cls(list(scenario.environment.network_identities))

    def identity(self, identity_id: str | None) -> NetworkIdentity | None:
        """Return a declared identity by id."""

        if not identity_id:
            return None
        return self._identities_by_id.get(identity_id)

    def resolve_identity(
        self,
        identity_id: str,
        *,
        src_host: str = "",
        host: str | None = None,
    ) -> ResolvedNetworkIdentity:
        """Resolve an identity reference to a host/IP tuple."""

        identity = self._identities_by_id.get(identity_id)
        if identity is None:
            return ResolvedNetworkIdentity(identity_id, host, None, (), "missing_identity")
        selected_host = host or (identity.hosts[0] if identity.hosts else None)
        selected_ip = self._select_identity_ip(identity, src_host=src_host, host=selected_host)
        return ResolvedNetworkIdentity(
            identity.id,
            selected_host,
            selected_ip,
            tuple(identity.tags),
            "scenario_identity",
        )

    def resolve_host(self, host: str, *, src_host: str = "") -> ResolvedNetworkIdentity:
        """Resolve host through scenario identities, package DNS, then stable fallback."""

        normalized = _normalize_host(host)
        identity = self._host_to_identity.get(normalized)
        if identity is not None:
            return self.resolve_identity(identity.id, src_host=src_host, host=host)

        package_ips = get_domain_ips(host)
        if package_ips:
            return ResolvedNetworkIdentity(
                None,
                host,
                resolve_domain_ip(host, src_host=src_host),
                tuple(get_domain_tags(host)),
                "package_dns",
            )

        return ResolvedNetworkIdentity(
            None,
            host,
            resolve_domain_ip(host, src_host=src_host),
            (),
            "stable_fallback",
        )

    def identity_for_host(self, host: str | None) -> NetworkIdentity | None:
        """Return declared identity for host, if any."""

        if not host:
            return None
        return self._host_to_identity.get(_normalize_host(host))

    def identity_for_ip(self, ip: str | None) -> NetworkIdentity | None:
        """Return declared identity for IP, if any."""

        if not ip:
            return None
        return self._ip_to_identity.get(ip)

    def tags_for_host(self, host: str | None) -> tuple[str, ...]:
        """Return scenario or package tags for host."""

        if not host or is_ip_literal(host):
            return ()
        identity = self.identity_for_host(host)
        if identity is not None:
            return tuple(identity.tags)
        return tuple(get_domain_tags(host))

    def declared_hosts(self) -> set[str]:
        """Return normalized scenario-declared hosts."""

        return set(self._host_to_identity)

    def _select_identity_ip(
        self,
        identity: NetworkIdentity,
        *,
        src_host: str,
        host: str | None,
    ) -> str | None:
        if not identity.ips:
            if host:
                return resolve_domain_ip(host, src_host=src_host)
            return None
        if len(identity.ips) == 1:
            return identity.ips[0]
        seed_host = host or identity.id
        rng = random.Random(_stable_seed(f"network_identity_ip:{src_host}:{seed_host}"))
        return identity.ips[rng.randrange(len(identity.ips))]
