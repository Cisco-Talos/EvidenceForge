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

"""DHCP lease action bundle."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from random import Random
from typing import Protocol

from evidenceforge.events.contexts import IdsAlertPlan
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.models.scenario import System
from evidenceforge.utils.rng import _stable_seed


def dhcp_renewal_interval_seconds(
    lease_time: float,
    rng: Random,
    *,
    timer_granularity: float = 1.0,
) -> float:
    """Return one client-timer realization around the lease's T1 boundary.

    DHCP clients normally target T1, but wakeups, scheduler latency, timer
    granularity, and occasional retry/backoff alter the observed interval after
    each ACK.  The caller owns a client-scoped RNG so successive lease cycles
    retain one implementation character without repeating one fixed interval.
    """

    base_renewal = max(60.0, lease_time / 2)
    scheduling_drift = lease_time * rng.triangular(-0.015, 0.025, 0.002)
    if rng.random() < 0.08:
        scheduling_drift += lease_time * rng.uniform(0.02, 0.08)
    if rng.random() < 0.05:
        scheduling_drift += rng.uniform(1.0, 8.0)
    interval = max(60.0, base_renewal + scheduling_drift)
    granularity = max(0.05, timer_granularity)
    quantized = round(interval / granularity) * granularity
    return max(60.0, quantized + rng.uniform(0.0, min(1.0, granularity)))


@dataclass(frozen=True, slots=True)
class DhcpLeaseRequest:
    """Intent for one DHCP acquisition or renewal transaction."""

    system: System
    time: datetime
    mac: str
    server_addr: str
    lease_time: float = 3600.0
    uid: str = ""
    msg_types: list[str] | None = None
    domain: str | None = None
    renewal_interval: float | None = None
    ids_alerts: list[IdsAlertPlan] = field(default_factory=list)
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        msg_types = ",".join(self.msg_types or ["DISCOVER", "OFFER", "REQUEST", "ACK"])
        seed = _stable_seed(
            "action_bundle:dhcp_lease:"
            f"{self.system.hostname}:{self.system.ip}:{self.time.isoformat()}:"
            f"{self.mac}:{self.server_addr}:{self.lease_time}:{self.uid}:"
            f"{msg_types}:{self.domain or ''}:{self.renewal_interval or ''}:"
            f"{self.ids_alerts}:{self.source}"
        )
        return f"dhcp-lease-{seed:016x}"


class DhcpLeaseExecutor(Protocol):
    """Adapter protocol implemented by the current activity generator."""

    def _execute_dhcp_lease_bundle(self, request: DhcpLeaseRequest) -> None:
        """Expand one DHCP lease request into canonical evidence."""
        ...


class DhcpLeaseActionBundle:
    """Expand one DHCP lease acquisition or renewal into source evidence."""

    def __init__(self, executor: DhcpLeaseExecutor, request: DhcpLeaseRequest) -> None:
        self._executor = executor
        self._request = request

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="dhcp_lease",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> None:
        """Emit DHCP lease and companion source-native evidence."""

        self._executor._execute_dhcp_lease_bundle(self._request)
