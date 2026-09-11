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

"""Scanner and probe action bundles."""

from __future__ import annotations

import ipaddress
import random
import shlex
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.models.scenario import System, User
from evidenceforge.utils.rng import _stable_seed


def _spec_value(spec: Any, name: str, default: Any = "") -> Any:
    """Return a stable scalar-ish field from a storyline event spec."""

    value = getattr(spec, name, default)
    if isinstance(value, list | tuple):
        return ",".join(str(item) for item in value)
    if isinstance(value, dict):
        return ",".join(f"{key}={value[key]}" for key in sorted(value))
    if value is None:
        return ""
    return value


@dataclass(frozen=True, slots=True)
class PortScanRequest:
    """Intent for one modeled port-scan activity."""

    spec: Any
    actor: User | None
    system: System
    time: datetime
    rng: random.Random
    malicious_event: dict[str, Any]
    source: str = "storyline"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        actor_name = self.actor.username if self.actor is not None else ""
        seed = _stable_seed(
            "action_bundle:port_scan:"
            f"{actor_name}:{self.system.hostname}:{self.time.isoformat()}:"
            f"{_spec_value(self.spec, 'source_ip')}:{_spec_value(self.spec, 'target_ips')}:"
            f"{_spec_value(self.spec, 'target_segment')}:{_spec_value(self.spec, 'target_count')}:"
            f"{_spec_value(self.spec, 'ports')}:{_spec_value(self.spec, 'protocol')}:"
            f"{_spec_value(self.spec, 'scan_rate')}:{self.source}"
        )
        return f"port-scan-{seed:016x}"


@dataclass(frozen=True, slots=True)
class WebScanRequest:
    """Intent for one modeled web-scanner activity."""

    spec: Any
    actor: User
    system: System
    time: datetime
    rng: random.Random
    malicious_event: dict[str, Any]
    source: str = "storyline"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        seed = _stable_seed(
            "action_bundle:web_scan:"
            f"{self.actor.username}:{self.system.hostname}:{self.time.isoformat()}:"
            f"{_spec_value(self.spec, 'source_ip')}:{_spec_value(self.spec, 'dst_ip')}:"
            f"{_spec_value(self.spec, 'dst_port')}:{_spec_value(self.spec, 'preset')}:"
            f"{_spec_value(self.spec, 'paths')}:{_spec_value(self.spec, 'hostname')}:"
            f"{_spec_value(self.spec, 'user_agent')}:{_spec_value(self.spec, 'rate')}:"
            f"{_spec_value(self.spec, 'count')}:{_spec_value(self.spec, 'duration')}:"
            f"{_spec_value(self.spec, 'end_time')}:{self.source}"
        )
        return f"web-scan-{seed:016x}"


@dataclass(frozen=True, slots=True)
class ScheduledScanOverlapRequest:
    """Intent for one suspicious-but-benign scheduled scanner burst."""

    scanner: System
    targets: tuple[System, ...]
    time: datetime
    rng: random.Random
    source: str = "baseline_suspicious_noise"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        target_names = ",".join(target.hostname for target in self.targets)
        seed = _stable_seed(
            "action_bundle:scheduled_scan_overlap:"
            f"{self.scanner.hostname}:{target_names}:{self.time.isoformat()}:{self.source}"
        )
        return f"scheduled-scan-overlap-{seed:016x}"


@dataclass(frozen=True, slots=True)
class NmapCommandProbeRequest:
    """Intent for scanner probes produced by an nmap-like process."""

    user: User
    system: System
    time: datetime
    pid: int
    process_name: str
    command_line: str
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        seed = _stable_seed(
            "action_bundle:nmap_command_probe:"
            f"{self.user.username}:{self.system.hostname}:{self.pid}:"
            f"{self.process_name}:{self.command_line}:{self.time.isoformat()}:{self.source}"
        )
        return f"nmap-command-probe-{seed:016x}"


@dataclass(frozen=True, slots=True)
class NmapCommandProbeTarget:
    """One bounded address-space target in an nmap command plan."""

    ip: str
    modeled: bool


@dataclass(frozen=True, slots=True)
class NmapCommandProbePlan:
    """Canonical bounded plan for one nmap process command."""

    discovery: bool
    ports: tuple[int, ...]
    targets: tuple[NmapCommandProbeTarget, ...]


class NmapCommandProbePlanningProfile(Protocol):
    """Validated target and volume limits consumed by the nmap planner."""

    full_cidr_max_hosts: int
    max_expanded_targets: int
    large_cidr_connect_targets: int
    large_cidr_discovery_targets: int
    large_cidr_unmodeled_targets: int
    max_ports: int
    connect_window_seconds_min: float
    connect_window_seconds_max: float
    discovery_window_seconds_min: float
    discovery_window_seconds_max: float


class NmapCommandProbePlanner:
    """Compile an nmap command into bounded address-space probe intent."""

    def __init__(self, profile: NmapCommandProbePlanningProfile) -> None:
        self._profile = profile

    def plan(
        self,
        request: NmapCommandProbeRequest,
        systems_by_ip: Mapping[str, System],
    ) -> NmapCommandProbePlan | None:
        """Return canonical scan mode, ports, and modeled/silent targets."""

        tokens = self._tokens(request.command_line)
        discovery = any(token.casefold() in {"-sn", "-sp"} for token in tokens)
        ports = tuple(self._ports(tokens)[: self._profile.max_ports])
        if not discovery and not ports:
            return None

        networks = self._target_networks(tokens)
        if not networks:
            return None
        target_limit = self._profile.max_expanded_targets
        large_cidr_limit = (
            self._profile.large_cidr_discovery_targets
            if discovery
            else self._profile.large_cidr_connect_targets
        )
        rng = random.Random(_stable_seed(f"{request.stable_id}:address_space"))
        targets: list[NmapCommandProbeTarget] = []
        seen: set[str] = set()
        for network, explicit_literal in networks:
            remaining = target_limit - len(targets)
            if remaining <= 0:
                break
            modeled = [
                ip
                for ip in sorted(
                    systems_by_ip,
                    key=lambda value: (
                        ipaddress.ip_address(value).version,
                        int(ipaddress.ip_address(value)),
                    ),
                )
                if ip != request.system.ip and ipaddress.ip_address(ip) in network
            ]
            if explicit_literal:
                literal_ip = str(network.network_address)
                if (
                    literal_ip != request.system.ip
                    and literal_ip not in seen
                    and len(targets) < target_limit
                ):
                    targets.append(
                        NmapCommandProbeTarget(
                            ip=literal_ip,
                            modeled=literal_ip in systems_by_ip,
                        )
                    )
                    seen.add(literal_ip)
                continue

            usable_hosts = self._usable_host_count(network)
            if usable_hosts <= self._profile.full_cidr_max_hosts:
                for address in network.hosts():
                    ip = str(address)
                    if ip == request.system.ip or ip in seen:
                        continue
                    targets.append(
                        NmapCommandProbeTarget(
                            ip=ip,
                            modeled=ip in systems_by_ip,
                        )
                    )
                    seen.add(ip)
                    if len(targets) >= target_limit:
                        break
                continue

            bounded_limit = min(remaining, large_cidr_limit)
            modeled_capacity = max(
                0,
                bounded_limit - self._profile.large_cidr_unmodeled_targets,
            )
            selected_modeled = modeled[:modeled_capacity]
            unmodeled_count = bounded_limit - len(selected_modeled)
            unmodeled = self._sample_stratified_unmodeled_hosts(
                network=network,
                excluded={*seen, request.system.ip, *modeled},
                count=unmodeled_count,
                rng=rng,
            )
            for ip in selected_modeled:
                if ip not in seen:
                    targets.append(NmapCommandProbeTarget(ip=ip, modeled=True))
                    seen.add(ip)
            for ip in unmodeled:
                targets.append(NmapCommandProbeTarget(ip=ip, modeled=False))
                seen.add(ip)

        if not targets:
            return None
        return NmapCommandProbePlan(
            discovery=discovery,
            ports=() if discovery else ports,
            targets=tuple(targets),
        )

    @staticmethod
    def _usable_host_count(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> int:
        """Return the count yielded by ``network.hosts()`` without iterating it."""

        if network.version == 4 and network.prefixlen < 31:
            return max(0, network.num_addresses - 2)
        if network.version == 6 and network.prefixlen < 128:
            return max(0, network.num_addresses - 1)
        return network.num_addresses

    @staticmethod
    def _tokens(command_line: str) -> list[str]:
        """Split a command line without treating malformed quoting as fatal."""

        try:
            return shlex.split(command_line, posix=True)
        except ValueError:
            return command_line.replace(",", " ").split()

    @staticmethod
    def _ports(tokens: list[str]) -> list[int]:
        """Extract bounded explicit nmap destination ports."""

        ports: list[int] = []
        for index, token in enumerate(tokens):
            values: list[str] = []
            if token == "-p" and index + 1 < len(tokens):
                values = [tokens[index + 1]]
            elif token.startswith("-p") and len(token) > 2:
                values = [token[2:]]
            if not values:
                continue
            for value in values[0].split(","):
                if "-" in value:
                    start_text, end_text = value.split("-", 1)
                    if start_text.isdigit() and end_text.isdigit():
                        start = int(start_text)
                        end = min(int(end_text), start + 20)
                        ports.extend(range(start, end + 1))
                    continue
                if value.isdigit():
                    ports.append(int(value))
            break
        return list(dict.fromkeys(port for port in ports if 0 < port <= 65535))

    @staticmethod
    def _target_networks(
        tokens: list[str],
    ) -> list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, bool]]:
        """Return explicit address/CIDR operands, excluding option values."""

        networks: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, bool]] = []
        skip_next = False
        for token in tokens:
            if skip_next:
                skip_next = False
                continue
            if token == "-p":
                skip_next = True
                continue
            if token.startswith("-"):
                continue
            stripped = token.strip("'\"")
            if not any(marker in stripped for marker in (".", ":", "/")):
                continue
            try:
                network = ipaddress.ip_network(stripped, strict=False)
            except ValueError:
                continue
            networks.append((network, "/" not in stripped))
        return networks

    @staticmethod
    def _sample_stratified_unmodeled_hosts(
        *,
        network: ipaddress.IPv4Network | ipaddress.IPv6Network,
        excluded: set[str],
        count: int,
        rng: random.Random,
    ) -> list[str]:
        """Sample every region of a broad CIDR without materializing its hosts."""

        if count <= 0:
            return []
        if network.version == 4 and network.prefixlen < 31:
            first = int(network.network_address) + 1
            last = int(network.broadcast_address) - 1
        elif network.version == 6 and network.prefixlen < 128:
            first = int(network.network_address) + 1
            last = int(network.broadcast_address)
        else:
            first = int(network.network_address)
            last = int(network.broadcast_address)
        if first > last:
            return []
        excluded_in_range = sum(
            ipaddress.ip_address(candidate) in network for candidate in excluded
        )
        available = max(0, (last - first + 1) - excluded_in_range)
        wanted = min(count, available)
        sampled: list[str] = []
        sampled_set: set[str] = set()
        span = last - first + 1
        for stratum in range(wanted):
            low = first + (span * stratum) // wanted
            high = first + (span * (stratum + 1)) // wanted - 1
            start = rng.randint(low, max(low, high))
            stratum_size = max(1, high - low + 1)
            for offset in range(min(stratum_size, len(excluded) + 2)):
                value = low + ((start - low + offset) % stratum_size)
                candidate = str(ipaddress.ip_address(value))
                if candidate in excluded or candidate in sampled_set:
                    continue
                sampled.append(candidate)
                sampled_set.add(candidate)
                break
        return sampled


def estimate_nmap_command_probe_occurrences(
    command_line: str,
    profile: NmapCommandProbePlanningProfile,
) -> int:
    """Conservatively estimate canonical probes for workload admission."""

    tokens = NmapCommandProbePlanner._tokens(command_line)
    discovery = any(token.casefold() in {"-sn", "-sp"} for token in tokens)
    ports = NmapCommandProbePlanner._ports(tokens)[: profile.max_ports]
    if not discovery and not ports:
        return 0
    networks = NmapCommandProbePlanner._target_networks(tokens)
    if not networks:
        return 0
    large_limit = (
        profile.large_cidr_discovery_targets if discovery else profile.large_cidr_connect_targets
    )
    targets = 0
    for network, explicit_literal in networks:
        if explicit_literal:
            targets += 1
        else:
            usable = NmapCommandProbePlanner._usable_host_count(network)
            targets += usable if usable <= profile.full_cidr_max_hosts else large_limit
        if targets >= profile.max_expanded_targets:
            targets = profile.max_expanded_targets
            break
    return targets if discovery else targets * len(ports)


class ScannerProbeExecutor(Protocol):
    """Adapter protocol implemented by the current storyline executor."""

    def _execute_port_scan_bundle(self, request: PortScanRequest) -> dict[str, Any]:
        """Expand one port-scan request into canonical evidence."""
        ...

    def _execute_web_scan_bundle(self, request: WebScanRequest) -> dict[str, Any]:
        """Expand one web-scan request into canonical evidence."""
        ...

    def _execute_scheduled_scan_overlap_bundle(self, request: ScheduledScanOverlapRequest) -> None:
        """Expand one scheduled scanner overlap into canonical evidence."""
        ...


class NmapCommandProbeExecutor(Protocol):
    """Adapter protocol implemented by the current activity generator."""

    def _execute_nmap_command_probe_bundle(self, request: NmapCommandProbeRequest) -> None:
        """Expand one nmap process command into network probe evidence."""
        ...


@dataclass(frozen=True, slots=True)
class PortScanActionBundle:
    """Expand one port-scan activity into firewall/network evidence."""

    executor: ScannerProbeExecutor
    request: PortScanRequest

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="port_scan",
            stable_id=self.request.stable_id,
            source=self.request.source,
        )

    def execute(self) -> dict[str, Any]:
        """Emit port-scan evidence and return the ground-truth summary."""

        return self.executor._execute_port_scan_bundle(self.request)


@dataclass(frozen=True, slots=True)
class WebScanActionBundle:
    """Expand one web-scanner activity into HTTP/network/IDS evidence."""

    executor: ScannerProbeExecutor
    request: WebScanRequest

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="web_scan",
            stable_id=self.request.stable_id,
            source=self.request.source,
        )

    def execute(self) -> dict[str, Any]:
        """Emit web-scan evidence and return the ground-truth summary."""

        return self.executor._execute_web_scan_bundle(self.request)


@dataclass(frozen=True, slots=True)
class ScheduledScanOverlapActionBundle:
    """Expand one suspicious-but-benign scanner burst into connection evidence."""

    executor: ScannerProbeExecutor
    request: ScheduledScanOverlapRequest

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="scheduled_scan_overlap",
            stable_id=self.request.stable_id,
            source=self.request.source,
        )

    def execute(self) -> None:
        """Emit scheduled scanner overlap evidence."""

        self.executor._execute_scheduled_scan_overlap_bundle(self.request)


@dataclass(frozen=True, slots=True)
class NmapCommandProbeActionBundle:
    """Expand one nmap-like process command into probe connection evidence."""

    executor: NmapCommandProbeExecutor
    request: NmapCommandProbeRequest

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="nmap_command_probe",
            stable_id=self.request.stable_id,
            source=self.request.source,
        )

    def execute(self) -> None:
        """Emit scanner process network effects."""

        self.executor._execute_nmap_command_probe_bundle(self.request)
