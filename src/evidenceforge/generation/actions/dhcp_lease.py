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

import math
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

from evidenceforge.events.contexts import IdsAlertPlan
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.source_timing import (
    SourceTimingPlanningRuntime,
    active_source_timing_planning_runtime,
)
from evidenceforge.generation.timing import (
    ConstantDistribution,
    DistributionSpec,
    MixtureDistribution,
    TimingRuntime,
    TimingScope,
    TriangularDistribution,
    WeightedDistribution,
)
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import System
from evidenceforge.utils.rng import _stable_seed


def _uniform_distribution(minimum: float, maximum: float) -> DistributionSpec:
    """Return a continuous-uniform law using supported timing primitives."""

    if minimum == maximum:
        return ConstantDistribution(minimum)
    return MixtureDistribution(
        (
            WeightedDistribution(
                1.0,
                TriangularDistribution(minimum=minimum, mode=minimum, maximum=maximum),
            ),
            WeightedDistribution(
                1.0,
                TriangularDistribution(minimum=minimum, mode=maximum, maximum=maximum),
            ),
        )
    )


def _planning_timing_runtime(
    timing_runtime: TimingRuntime | SourceTimingPlanningRuntime | None,
) -> TimingRuntime | SourceTimingPlanningRuntime:
    """Return an exact canonical or active staged timing runtime."""

    # Direct engine-mixin fixtures may run before GenerationEngine._initialize.
    # Production initialization always injects its exact engine-owned runtime.
    if timing_runtime is None:
        return TimingRuntime.compatibility_default()
    if type(timing_runtime) is SourceTimingPlanningRuntime:
        return timing_runtime
    if type(timing_runtime) is not TimingRuntime:
        raise StateError("DHCP renewal timing requires an exact engine TimingRuntime")
    return active_source_timing_planning_runtime(timing_runtime) or timing_runtime


def dhcp_renewal_interval_seconds(
    lease_time: float,
    *,
    timing_runtime: TimingRuntime | SourceTimingPlanningRuntime | None,
    stable_id: str,
    host: str,
    renewal_sequence: int,
    timer_granularity: float = 1.0,
) -> float:
    """Return one client-timer realization around the lease's T1 boundary.

    DHCP clients normally target T1, but wakeups, scheduler latency, timer
    granularity, and occasional retry/backoff alter the observed interval after
    each ACK. A stable lease identity plus monotonic sequence gives successive
    cycles implementation texture without a mutable RNG cursor.
    """

    runtime = _planning_timing_runtime(timing_runtime)
    if type(stable_id) is not str or not stable_id:
        raise StateError("DHCP renewal timing requires a stable lease identity")
    if type(host) is not str:
        raise StateError("DHCP renewal timing requires an exact host identity")
    if type(renewal_sequence) is not int or renewal_sequence < 0:
        raise StateError("DHCP renewal timing requires a non-negative renewal sequence")
    if type(lease_time) not in {int, float} or not math.isfinite(lease_time) or lease_time <= 0:
        raise StateError("DHCP renewal timing requires a finite positive lease time")
    if (
        type(timer_granularity) not in {int, float}
        or not math.isfinite(timer_granularity)
        or timer_granularity <= 0
    ):
        raise StateError("DHCP renewal timing requires finite positive timer granularity")

    scope = TimingScope(
        stable_id=stable_id,
        host=host,
        source="dhcp",
        lifecycle_id="lease_renewal",
        ordinal=renewal_sequence,
    )
    base_renewal = max(60.0, lease_time / 2)
    scheduling_drift = runtime.sampler.sample_value(
        TriangularDistribution(
            minimum=lease_time * -0.015,
            mode=lease_time * 0.002,
            maximum=lease_time * 0.025,
        ),
        relationship_key="dhcp.lease.renewal.scheduling_drift_seconds",
        scope=scope,
        sample_key="scheduling_drift",
    )
    wakeup_backoff = runtime.sampler.sample_value(
        MixtureDistribution(
            (
                WeightedDistribution(0.92, ConstantDistribution(0.0)),
                WeightedDistribution(
                    0.08,
                    _uniform_distribution(lease_time * 0.02, lease_time * 0.08),
                ),
            )
        ),
        relationship_key="dhcp.lease.renewal.wakeup_backoff_seconds",
        scope=scope,
        sample_key="wakeup_backoff",
    )
    scheduler_latency = runtime.sampler.sample_value(
        MixtureDistribution(
            (
                WeightedDistribution(0.95, ConstantDistribution(0.0)),
                WeightedDistribution(0.05, _uniform_distribution(1.0, 8.0)),
            )
        ),
        relationship_key="dhcp.lease.renewal.scheduler_latency_seconds",
        scope=scope,
        sample_key="scheduler_latency",
    )
    scheduling_drift += wakeup_backoff + scheduler_latency
    interval = max(60.0, base_renewal + scheduling_drift)
    granularity = max(0.05, timer_granularity)
    quantized = round(interval / granularity) * granularity
    quantization_jitter = runtime.sampler.sample_value(
        _uniform_distribution(0.0, min(1.0, granularity)),
        relationship_key="dhcp.lease.renewal.timer_quantization_jitter_seconds",
        scope=scope,
        sample_key="timer_quantization_jitter",
    )
    return max(60.0, quantized + quantization_jitter)


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
