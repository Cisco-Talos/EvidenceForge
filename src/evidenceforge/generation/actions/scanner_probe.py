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

import random
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
