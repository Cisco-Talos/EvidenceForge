# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Timing realism profile loader and helpers."""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Literal, Protocol

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import deep_merge_dict, load_with_overlay
from evidenceforge.generation.baseline_timing import BaselineTimingPlanner
from evidenceforge.generation.timing import (
    ConstantDistribution,
    DistributionSpec,
    MixtureDistribution,
    TimingRuntime,
    TimingSampler,
    TimingScope,
    TriangularDistribution,
    WeightedDistribution,
)
from evidenceforge.utils.rng import _stable_seed

_CONFIG_PATH = get_activity_directory() / "timing_profiles.yaml"
_CACHED_DATA: dict[str, Any] | None = None
_MAX_RELATIONSHIP_MS = 86_400_000
_MAX_COLLISION_NEAR_ZERO_UNTIL = 10_000
_MAX_COLLISION_GAP_US = 1_000_000
_MAX_COLLISION_GAP_MS = 60_000
_MAX_SENSOR_TIMING_US = 1_000_000
_MAX_ENDPOINT_CLOCK_OFFSET_MS = 300_000
_MAX_ENDPOINT_CLOCK_DRIFT_PPM = 500


@dataclass(frozen=True, slots=True)
class TimingWindow:
    """A sampled timing window for a named causal relationship."""

    min_ms: int
    max_ms: int
    position: Literal["before", "after"]
    relationship_class: str = ""


@dataclass(frozen=True, slots=True)
class StartupModuleObservationTiming:
    """Source-visible Windows process initialization timing parameters."""

    initial_delay_min_us: int
    initial_delay_max_us: int
    inter_load_gap_median_us: int
    inter_load_gap_sigma: float
    inter_load_gap_min_us: int
    inter_load_gap_max_us: int


@dataclass(frozen=True, slots=True)
class NetworkSensorObservationTiming:
    """Per-sensor clock, route, jitter, and capture-loss bounds."""

    profile_name: str
    clock_offset_min_us: int
    clock_offset_max_us: int
    clock_drift_min_ppm: int
    clock_drift_max_ppm: int
    route_delay_min_us: int
    route_delay_max_us: int
    event_jitter_min_us: int
    event_jitter_max_us: int
    capture_loss_probability: float
    capture_loss_min_fraction: float
    capture_loss_max_fraction: float
    capture_loss_max_missed_bytes: int

    @property
    def clock_skew_min_us(self) -> int:
        """Compatibility alias for the former clock-skew field."""

        return self.clock_offset_min_us

    @property
    def clock_skew_max_us(self) -> int:
        """Compatibility alias for the former clock-skew field."""

        return self.clock_offset_max_us

    @property
    def path_delay_min_us(self) -> int:
        """Compatibility alias for the former path-delay field."""

        return self.route_delay_min_us

    @property
    def path_delay_max_us(self) -> int:
        """Compatibility alias for the former path-delay field."""

        return self.route_delay_max_us


@dataclass(frozen=True, slots=True)
class EndpointClockTiming:
    """Per-host endpoint clock offset and drift bounds."""

    host_offset_min_ms: int
    host_offset_max_ms: int
    host_drift_min_ppm: int
    host_drift_max_ppm: int


@dataclass(frozen=True, slots=True)
class FirewallObservationTiming:
    """Source-native connection-table timers for one firewall sensor."""

    policy_name: str
    tcp_embryonic_timeout_seconds: int
    tcp_idle_timeout_seconds: int


@dataclass(frozen=True, slots=True)
class SysmonEnvelopeTiming:
    """Provider-envelope latency parameters for one Sysmon event family."""

    median_us: int
    sigma: float
    min_us: int
    max_us: int
    tail_probability: float
    tail_min_us: int
    tail_max_us: int


@dataclass(frozen=True, slots=True)
class SshAuthenticationTiming:
    """Contextual SSH authentication-phase timing parameters."""

    fast_probability: float
    fast_min_ms: int
    fast_max_ms: int
    typical_min_ms: int
    typical_max_ms: int
    tail_probability: float
    tail_min_ms: int
    tail_max_ms: int
    cache_miss_probability: float
    cache_miss_min_ms: int
    cache_miss_max_ms: int


@dataclass(frozen=True, slots=True)
class SshAcceptedAuthenticationTiming:
    """Audited component gaps composing one SSH authentication acceptance."""

    phase_ms: float
    cache_delay_ms: float
    route_delay_ms: float
    receiver_delay_ms: float
    key_penalty_ms: float

    @property
    def total_ms(self) -> float:
        """Return the complete accepted-authentication gap."""

        return (
            self.phase_ms
            + self.cache_delay_ms
            + self.route_delay_ms
            + self.receiver_delay_ms
            + self.key_penalty_ms
        )


@dataclass(frozen=True, slots=True)
class InclusiveMillisecondTimingSupport:
    """One normalized union of inclusive millisecond timing intervals."""

    intervals: tuple[tuple[float, float], ...]

    def __post_init__(self) -> None:
        """Validate, sort, and merge overlapping or adjacent intervals."""

        if not self.intervals:
            raise ValueError("millisecond timing support must contain at least one interval")
        merged: list[tuple[float, float]] = []
        for minimum, maximum in sorted(self.intervals):
            if maximum < minimum:
                raise ValueError("millisecond timing support maximum must not precede minimum")
            if merged and minimum <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], maximum))
            else:
                merged.append((minimum, maximum))
        object.__setattr__(self, "intervals", tuple(merged))

    @property
    def bounds(self) -> tuple[float, float]:
        """Return the minimum and maximum across the exact interval union."""

        return self.intervals[0][0], self.intervals[-1][1]

    def __contains__(self, value: object) -> bool:
        """Return whether a millisecond value belongs to any exact support interval."""

        return (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and any(minimum <= value <= maximum for minimum, maximum in self.intervals)
        )

    def __add__(
        self,
        other: InclusiveMillisecondTimingSupport,
    ) -> InclusiveMillisecondTimingSupport:
        """Return the exact Minkowski sum of two millisecond interval unions."""

        return InclusiveMillisecondTimingSupport(
            tuple(
                (left_min + right_min, left_max + right_max)
                for left_min, left_max in self.intervals
                for right_min, right_max in other.intervals
            )
        )


def _millisecond_support(
    *intervals: tuple[float, float],
) -> InclusiveMillisecondTimingSupport:
    """Construct one normalized exact millisecond timing support."""

    return InclusiveMillisecondTimingSupport(intervals)


@dataclass(frozen=True, slots=True)
class SshAcceptedAuthenticationTimingSupport:
    """Exact millisecond supports for accepted-authentication components."""

    phase_ms: InclusiveMillisecondTimingSupport
    cache_delay_ms: InclusiveMillisecondTimingSupport
    route_delay_ms: InclusiveMillisecondTimingSupport
    receiver_delay_ms: InclusiveMillisecondTimingSupport
    key_penalty_ms: InclusiveMillisecondTimingSupport

    @property
    def total_ms(self) -> InclusiveMillisecondTimingSupport:
        """Return the exact support of the component sum."""

        supports = (
            self.phase_ms,
            self.cache_delay_ms,
            self.route_delay_ms,
            self.receiver_delay_ms,
            self.key_penalty_ms,
        )
        total = _millisecond_support((0, 0))
        for support in supports:
            total += support
        return total


@dataclass(frozen=True, slots=True)
class SshAuthenticationTimingPlan:
    """One complete ordered SSH authentication lifecycle timing plan."""

    connection_gap_ms: float
    accepted: SshAcceptedAuthenticationTiming
    pam_gap_ms: float
    logind_gap_ms: float

    @property
    def accepted_gap_ms(self) -> float:
        """Return the composed gap between connection and accepted evidence."""

        return self.accepted.total_ms

    @property
    def lifecycle_gap_ms(self) -> float:
        """Return the complete transport-to-logind phase-gap sum."""

        return self.connection_gap_ms + self.accepted_gap_ms + self.pam_gap_ms + self.logind_gap_ms


@dataclass(frozen=True, slots=True)
class SshAuthenticationTimingSupport:
    """Exact millisecond supports for one full SSH authentication plan."""

    connection_gap_ms: InclusiveMillisecondTimingSupport
    accepted: SshAcceptedAuthenticationTimingSupport
    pam_gap_ms: InclusiveMillisecondTimingSupport
    logind_gap_ms: InclusiveMillisecondTimingSupport

    @property
    def accepted_gap_ms(self) -> InclusiveMillisecondTimingSupport:
        """Return the exact support of the accepted-authentication sum."""

        return self.accepted.total_ms

    @property
    def lifecycle_gap_ms(self) -> InclusiveMillisecondTimingSupport:
        """Return the exact support of every ordered phase gap."""

        supports = (
            self.connection_gap_ms,
            self.accepted_gap_ms,
            self.pam_gap_ms,
            self.logind_gap_ms,
        )
        total = _millisecond_support((0, 0))
        for support in supports:
            total += support
        return total


class _SshTimingRuntime(Protocol):
    """Sampling surface shared by canonical and prepared timing runtimes."""

    @property
    def sampler(self) -> TimingSampler:
        """Return the runtime-owned stateless audited sampler."""


_SSH_CONNECTION_GAP_MS = (35, 160)
_SSH_PAM_GAP_MS = (45, 180)
_SSH_LOGIND_GAP_MS = (420, 760)


def load_timing_profiles() -> dict[str, Any]:
    """Load timing profiles, merged with project-local overlay."""
    global _CACHED_DATA
    if _CACHED_DATA is None:
        _CACHED_DATA = load_with_overlay(
            _CONFIG_PATH,
            "activity/timing_profiles.yaml",
            deep_merge_dict,
        )
    return _CACHED_DATA


def reset_timing_profiles_cache() -> None:
    """Clear cached timing profiles. Intended for tests."""
    global _CACHED_DATA
    _CACHED_DATA = None


def _safe_int(value: Any, fallback: int, *, minimum: int, maximum: int) -> int:
    """Convert input to int and clamp to a safe range."""
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = fallback
    return max(minimum, min(parsed, maximum))


def _safe_int_range(
    value: Any,
    *,
    fallback_min: int,
    fallback_max: int,
    minimum: int,
    maximum: int,
) -> tuple[int, int]:
    """Read a ``{min, max}`` mapping and fall back when the range is invalid."""
    if not isinstance(value, dict):
        return fallback_min, fallback_max
    min_value = _safe_int(value.get("min"), fallback_min, minimum=minimum, maximum=maximum)
    max_value = _safe_int(value.get("max"), fallback_max, minimum=minimum, maximum=maximum)
    if max_value < min_value:
        return fallback_min, fallback_max
    return min_value, max_value


def _safe_float(
    value: Any,
    fallback: float,
    *,
    minimum: float,
    maximum: float,
) -> float:
    """Convert input to float and clamp it to a safe range."""

    try:
        parsed = float(value)
    except (TypeError, ValueError):
        parsed = fallback
    return max(minimum, min(parsed, maximum))


def get_timing_window(
    key: str,
    *,
    default_min_ms: int,
    default_max_ms: int,
    default_position: Literal["before", "after"],
    default_class: str = "",
) -> TimingWindow:
    """Return a named timing relationship with safe code defaults."""
    entry = load_timing_profiles().get("relationships", {}).get(key, {})
    if not isinstance(entry, dict):
        entry = {}
    min_ms = _safe_int(
        entry.get("min_ms", default_min_ms),
        default_min_ms,
        minimum=0,
        maximum=_MAX_RELATIONSHIP_MS,
    )
    max_ms = _safe_int(
        entry.get("max_ms", default_max_ms),
        default_max_ms,
        minimum=0,
        maximum=_MAX_RELATIONSHIP_MS,
    )
    if max_ms < min_ms:
        min_ms, max_ms = default_min_ms, default_max_ms
    position = entry.get("position", default_position)
    if position not in {"before", "after"}:
        position = default_position
    return TimingWindow(
        min_ms=min_ms,
        max_ms=max_ms,
        position=position,
        relationship_class=str(entry.get("class", default_class)),
    )


def sample_timing_delta(key: str, *, seed_parts: tuple[Any, ...] = ()) -> timedelta:
    """Sample a deterministic timedelta for a named timing relationship."""
    window = get_timing_window(
        key,
        default_min_ms=0,
        default_max_ms=0,
        default_position="after",
    )
    if window.max_ms <= window.min_ms:
        return timedelta(milliseconds=window.min_ms)
    seed = "timing_delta:" + key + ":" + ":".join(str(part) for part in seed_parts)
    rng = random.Random(_stable_seed(seed))
    return timedelta(milliseconds=rng.randint(window.min_ms, window.max_ms))


def sample_packet_timing_delta(key: str, *, seed_parts: tuple[Any, ...] = ()) -> timedelta:
    """Sample a direct-helper-compatible typed packet-observation delta.

    Production generators inject their engine timing runtime directly. This
    stateless adapter remains only for direct helper tests and external callers
    that have not constructed an engine.
    """

    window = get_timing_window(
        key,
        default_min_ms=0,
        default_max_ms=0,
        default_position="after",
    )
    stable_id = (
        "packet-timing-compatibility:" + key + ":" + ":".join(str(part) for part in seed_parts)
    )
    return BaselineTimingPlanner(
        TimingRuntime.compatibility_default(),
        source="network",
    ).packet_observation_delta(
        relationship_key=key,
        stable_id=stable_id,
        minimum_ms=window.min_ms,
        maximum_ms=window.max_ms,
    )


def ssh_authentication_timing(auth_method: str) -> SshAuthenticationTiming:
    """Return bounded data-driven timing for one SSH authentication method."""

    normalized_method = auth_method.strip().lower()
    fallback = {
        "publickey": {
            "fast_probability": 0.22,
            "fast_ms": (25, 180),
            "typical_ms": (180, 1250),
            "tail_probability": 0.12,
            "tail_ms": (1250, 4800),
            "cache_miss_probability": 0.18,
            "cache_miss_ms": (120, 1500),
        },
        "password": {
            "fast_probability": 0.08,
            "fast_ms": (180, 550),
            "typical_ms": (550, 3600),
            "tail_probability": 0.18,
            "tail_ms": (3600, 9000),
            "cache_miss_probability": 0.32,
            "cache_miss_ms": (250, 2800),
        },
    }
    fallback_profile = fallback.get(normalized_method, fallback["password"])
    data = load_timing_profiles().get("ssh_authentication", {})
    if not isinstance(data, dict):
        data = {}
    profiles = data.get("profiles", {})
    if not isinstance(profiles, dict):
        profiles = {}
    profile = profiles.get(normalized_method, {})
    if not isinstance(profile, dict):
        profile = {}

    fast_min, fast_max = _safe_int_range(
        profile.get("fast_ms"),
        fallback_min=fallback_profile["fast_ms"][0],
        fallback_max=fallback_profile["fast_ms"][1],
        minimum=1,
        maximum=60_000,
    )
    typical_min, typical_max = _safe_int_range(
        profile.get("typical_ms"),
        fallback_min=fallback_profile["typical_ms"][0],
        fallback_max=fallback_profile["typical_ms"][1],
        minimum=1,
        maximum=60_000,
    )
    tail_min, tail_max = _safe_int_range(
        profile.get("tail_ms"),
        fallback_min=fallback_profile["tail_ms"][0],
        fallback_max=fallback_profile["tail_ms"][1],
        minimum=1,
        maximum=60_000,
    )
    cache_min, cache_max = _safe_int_range(
        profile.get("cache_miss_ms"),
        fallback_min=fallback_profile["cache_miss_ms"][0],
        fallback_max=fallback_profile["cache_miss_ms"][1],
        minimum=0,
        maximum=60_000,
    )
    return SshAuthenticationTiming(
        fast_probability=_safe_float(
            profile.get("fast_probability"),
            fallback_profile["fast_probability"],
            minimum=0.0,
            maximum=0.75,
        ),
        fast_min_ms=fast_min,
        fast_max_ms=fast_max,
        typical_min_ms=typical_min,
        typical_max_ms=typical_max,
        tail_probability=_safe_float(
            profile.get("tail_probability"),
            fallback_profile["tail_probability"],
            minimum=0.0,
            maximum=0.5,
        ),
        tail_min_ms=tail_min,
        tail_max_ms=tail_max,
        cache_miss_probability=_safe_float(
            profile.get("cache_miss_probability"),
            fallback_profile["cache_miss_probability"],
            minimum=0.0,
            maximum=1.0,
        ),
        cache_miss_min_ms=cache_min,
        cache_miss_max_ms=cache_max,
    )


def _inclusive_uniform_millisecond_distribution(
    minimum: float,
    maximum: float,
) -> DistributionSpec:
    """Return an edge-triangular mixture with the exact former millisecond support."""

    if minimum == maximum:
        return ConstantDistribution(float(minimum * 1_000))
    lower = float(minimum * 1_000) - 0.5
    upper = float(maximum * 1_000) + 0.5
    return MixtureDistribution(
        (
            WeightedDistribution(
                1.0,
                TriangularDistribution(minimum=lower, mode=lower, maximum=upper),
            ),
            WeightedDistribution(
                1.0,
                TriangularDistribution(minimum=lower, mode=upper, maximum=upper),
            ),
        )
    )


def _inclusive_triangular_millisecond_distribution(
    minimum: float,
    mode: float,
    maximum: float,
) -> DistributionSpec:
    """Return a triangular distribution with the exact former millisecond support."""

    if minimum == maximum:
        return ConstantDistribution(float(minimum * 1_000))
    lower = float(minimum * 1_000) - 0.5
    upper = float(maximum * 1_000) + 0.5
    return TriangularDistribution(
        minimum=lower,
        mode=min(upper, max(lower, mode * 1_000)),
        maximum=upper,
    )


def _sample_ssh_milliseconds(
    planner: BaselineTimingPlanner,
    distribution: DistributionSpec,
    *,
    relationship_key: str,
    scope: TimingScope,
    sample_key: str,
) -> float:
    """Sample one audited microsecond-quantized component in milliseconds."""

    microseconds = planner.runtime.sampler.sample_microseconds(
        distribution,
        relationship_key=relationship_key,
        scope=scope,
        sample_key=sample_key,
    )
    return microseconds / 1_000


def _ssh_authentication_context_support(
    auth_method: str,
    *,
    public_key_type: str,
    route_class: str,
) -> tuple[SshAuthenticationTiming, SshAcceptedAuthenticationTimingSupport]:
    """Resolve one profile and its exact accepted-authentication component supports."""

    profile = ssh_authentication_timing(auth_method)
    tail_weight = min(1.0, profile.tail_probability)
    fast_weight = min(max(0.0, 1.0 - tail_weight), profile.fast_probability)
    typical_weight = max(0.0, 1.0 - tail_weight - fast_weight)
    phase_supports = tuple(
        support
        for weight, support in (
            (tail_weight, (profile.tail_min_ms, profile.tail_max_ms)),
            (fast_weight, (profile.fast_min_ms, profile.fast_max_ms)),
            (typical_weight, (profile.typical_min_ms, profile.typical_max_ms)),
        )
        if weight > 0
    )

    data = load_timing_profiles().get("ssh_authentication", {})
    if not isinstance(data, dict):
        data = {}
    route_profiles = data.get("route_rtt_ms", {})
    if not isinstance(route_profiles, dict):
        route_profiles = {}
    route_support = _safe_int_range(
        route_profiles.get(route_class),
        fallback_min=2 if route_class == "private" else 25,
        fallback_max=55 if route_class == "private" else 320,
        minimum=0,
        maximum=10_000,
    )
    receiver_support = _safe_int_range(
        data.get("receiver_load_ms"),
        fallback_min=0,
        fallback_max=650,
        minimum=0,
        maximum=10_000,
    )
    penalties = data.get("public_key_penalty_ms", {})
    if not isinstance(penalties, dict):
        penalties = {}
    key_type = public_key_type.strip().upper()
    key_support = (
        _safe_int_range(
            penalties.get(key_type),
            fallback_min=0,
            fallback_max=0,
            minimum=0,
            maximum=10_000,
        )
        if key_type
        else (0, 0)
    )
    cache_intervals: list[tuple[int, int]] = []
    if profile.cache_miss_probability < 1.0:
        cache_intervals.append((0, 0))
    if profile.cache_miss_probability > 0.0:
        cache_intervals.append((profile.cache_miss_min_ms, profile.cache_miss_max_ms))
    return profile, SshAcceptedAuthenticationTimingSupport(
        phase_ms=_millisecond_support(*phase_supports),
        cache_delay_ms=_millisecond_support(*cache_intervals),
        route_delay_ms=_millisecond_support(route_support),
        receiver_delay_ms=_millisecond_support(receiver_support),
        key_penalty_ms=_millisecond_support(key_support),
    )


def ssh_authentication_timing_support(
    auth_method: str,
    *,
    public_key_type: str = "",
    route_class: str = "private",
) -> SshAuthenticationTimingSupport:
    """Return exact inclusive component and total supports for one SSH auth plan."""

    _profile, accepted_support = _ssh_authentication_context_support(
        auth_method,
        public_key_type=public_key_type,
        route_class=route_class,
    )
    return SshAuthenticationTimingSupport(
        connection_gap_ms=_millisecond_support(_SSH_CONNECTION_GAP_MS),
        accepted=accepted_support,
        pam_gap_ms=_millisecond_support(_SSH_PAM_GAP_MS),
        logind_gap_ms=_millisecond_support(_SSH_LOGIND_GAP_MS),
    )


def _plan_ssh_accepted_authentication_timing(
    auth_method: str,
    *,
    public_key_type: str,
    route_class: str,
    planner: BaselineTimingPlanner,
    scope: TimingScope,
) -> SshAcceptedAuthenticationTiming:
    """Plan every independently stable component of SSH authentication acceptance."""

    profile, support = _ssh_authentication_context_support(
        auth_method,
        public_key_type=public_key_type,
        route_class=route_class,
    )
    tail_weight = min(1.0, profile.tail_probability)
    fast_weight = min(max(0.0, 1.0 - tail_weight), profile.fast_probability)
    typical_weight = max(0.0, 1.0 - tail_weight - fast_weight)
    phase_components: list[WeightedDistribution] = []
    for weight, distribution in (
        (
            tail_weight,
            _inclusive_uniform_millisecond_distribution(
                profile.tail_min_ms,
                profile.tail_max_ms,
            ),
        ),
        (
            fast_weight,
            _inclusive_uniform_millisecond_distribution(
                profile.fast_min_ms,
                profile.fast_max_ms,
            ),
        ),
        (
            typical_weight,
            _inclusive_triangular_millisecond_distribution(
                profile.typical_min_ms,
                profile.typical_min_ms + (profile.typical_max_ms - profile.typical_min_ms) * 0.35,
                profile.typical_max_ms,
            ),
        ),
    ):
        if weight > 0:
            phase_components.append(WeightedDistribution(weight, distribution))
    phase_ms = _sample_ssh_milliseconds(
        planner,
        MixtureDistribution(tuple(phase_components)),
        relationship_key="ssh.authentication.phase",
        scope=scope,
        sample_key="phase",
    )

    cache_components: list[WeightedDistribution] = []
    if profile.cache_miss_probability < 1.0:
        cache_components.append(
            WeightedDistribution(
                1.0 - profile.cache_miss_probability,
                ConstantDistribution(0.0),
            )
        )
    if profile.cache_miss_probability > 0.0:
        cache_components.append(
            WeightedDistribution(
                profile.cache_miss_probability,
                _inclusive_uniform_millisecond_distribution(
                    profile.cache_miss_min_ms,
                    profile.cache_miss_max_ms,
                ),
            )
        )
    cache_delay_ms = _sample_ssh_milliseconds(
        planner,
        MixtureDistribution(tuple(cache_components)),
        relationship_key="ssh.authentication.cache_delay",
        scope=scope,
        sample_key="cache",
    )
    route_delay_ms = _sample_ssh_milliseconds(
        planner,
        _inclusive_uniform_millisecond_distribution(*support.route_delay_ms.bounds),
        relationship_key="ssh.authentication.route_delay",
        scope=scope,
        sample_key="route",
    )
    receiver_delay_ms = _sample_ssh_milliseconds(
        planner,
        _inclusive_triangular_millisecond_distribution(
            support.receiver_delay_ms.bounds[0],
            float(support.receiver_delay_ms.bounds[0]),
            support.receiver_delay_ms.bounds[1],
        ),
        relationship_key="ssh.authentication.receiver_delay",
        scope=scope,
        sample_key="receiver",
    )
    key_type = public_key_type.strip().upper()
    key_penalty_ms = 0.0
    if key_type:
        key_penalty_ms = _sample_ssh_milliseconds(
            planner,
            _inclusive_uniform_millisecond_distribution(*support.key_penalty_ms.bounds),
            relationship_key="ssh.authentication.key_penalty",
            scope=scope,
            sample_key=f"key:{key_type}",
        )
    return SshAcceptedAuthenticationTiming(
        phase_ms=phase_ms,
        cache_delay_ms=cache_delay_ms,
        route_delay_ms=route_delay_ms,
        receiver_delay_ms=receiver_delay_ms,
        key_penalty_ms=key_penalty_ms,
    )


def plan_ssh_authentication_timing(
    auth_method: str,
    *,
    public_key_type: str,
    route_class: str,
    timing_runtime: _SshTimingRuntime,
    scope: TimingScope,
) -> SshAuthenticationTimingPlan:
    """Plan all ordered SSH authentication gaps through one exact injected runtime."""

    planner = BaselineTimingPlanner(timing_runtime, source=scope.source)
    connection_gap_ms = _sample_ssh_milliseconds(
        planner,
        _inclusive_uniform_millisecond_distribution(*_SSH_CONNECTION_GAP_MS),
        relationship_key="ssh.authentication.connection_after_transport",
        scope=scope,
        sample_key="connection_gap",
    )
    accepted = _plan_ssh_accepted_authentication_timing(
        auth_method,
        public_key_type=public_key_type,
        route_class=route_class,
        planner=planner,
        scope=scope,
    )
    pam_gap_ms = _sample_ssh_milliseconds(
        planner,
        _inclusive_uniform_millisecond_distribution(*_SSH_PAM_GAP_MS),
        relationship_key="ssh.authentication.pam_after_accepted",
        scope=scope,
        sample_key="pam_gap",
    )
    logind_gap_ms = _sample_ssh_milliseconds(
        planner,
        _inclusive_uniform_millisecond_distribution(*_SSH_LOGIND_GAP_MS),
        relationship_key="ssh.authentication.logind_after_pam",
        scope=scope,
        sample_key="logind_gap",
    )
    return SshAuthenticationTimingPlan(
        connection_gap_ms=connection_gap_ms,
        accepted=accepted,
        pam_gap_ms=pam_gap_ms,
        logind_gap_ms=logind_gap_ms,
    )


def sample_ssh_authentication_phase_ms_compatibility(
    auth_method: str,
    *,
    public_key_type: str = "",
    route_class: str = "private",
    seed_parts: tuple[Any, ...] = (),
) -> float:
    """Sample accepted-auth timing for direct legacy helper callers only."""

    seed_text = ":".join(str(part) for part in seed_parts)
    stable_id = f"{auth_method}:{seed_text}"
    runtime = TimingRuntime.compatibility_default()
    planner = BaselineTimingPlanner(runtime, source="ssh-auth-compatibility")
    return _plan_ssh_accepted_authentication_timing(
        auth_method,
        public_key_type=public_key_type,
        route_class=route_class,
        planner=planner,
        scope=TimingScope(
            stable_id=stable_id,
            source=planner.source,
            lifecycle_id=stable_id,
        ),
    ).total_ms


def sysmon_envelope_timing(event_id: int) -> SysmonEnvelopeTiming:
    """Return data-driven Sysmon provider-envelope timing for an event ID."""

    data = load_timing_profiles().get("sysmon_event_envelope", {})
    if not isinstance(data, dict):
        data = {}
    default = data.get("default", {})
    if not isinstance(default, dict):
        default = {}
    event_profiles = data.get("event_ids", {})
    if not isinstance(event_profiles, dict):
        event_profiles = {}
    override = event_profiles.get(str(event_id), {})
    if not isinstance(override, dict):
        override = {}
    profile = {**default, **override}
    minimum_us = _safe_int(profile.get("min_us"), 80, minimum=1, maximum=1_000_000)
    maximum_us = _safe_int(profile.get("max_us"), 18_000, minimum=minimum_us, maximum=1_000_000)
    tail_min_us = _safe_int(
        profile.get("tail_min_us"), 12_000, minimum=minimum_us, maximum=1_000_000
    )
    tail_max_us = _safe_int(
        profile.get("tail_max_us"), 85_000, minimum=tail_min_us, maximum=1_000_000
    )
    return SysmonEnvelopeTiming(
        median_us=_safe_int(profile.get("median_us"), 850, minimum=minimum_us, maximum=maximum_us),
        sigma=_safe_float(profile.get("sigma"), 0.8, minimum=0.05, maximum=3.0),
        min_us=minimum_us,
        max_us=maximum_us,
        tail_probability=_safe_float(
            profile.get("tail_probability"), 0.012, minimum=0.0, maximum=0.25
        ),
        tail_min_us=tail_min_us,
        tail_max_us=tail_max_us,
    )


def startup_module_observation_timing() -> StartupModuleObservationTiming:
    """Return safe data-driven timing for source-visible startup module bursts."""
    data = load_timing_profiles().get("windows_startup_modules", {})
    if not isinstance(data, dict):
        data = {}
    initial_min, initial_max = _safe_int_range(
        data.get("initial_delay_us"),
        fallback_min=250,
        fallback_max=6_500,
        minimum=1,
        maximum=1_000_000,
    )
    gap_data = data.get("inter_load_gap_us", {})
    if not isinstance(gap_data, dict):
        gap_data = {}
    gap_min = _safe_int(
        gap_data.get("min"),
        120,
        minimum=1,
        maximum=1_000_000,
    )
    gap_max = _safe_int(
        gap_data.get("max"),
        65_000,
        minimum=1,
        maximum=1_000_000,
    )
    if gap_max < gap_min:
        gap_min, gap_max = 120, 65_000
    gap_median = _safe_int(
        gap_data.get("median"),
        1_900,
        minimum=gap_min,
        maximum=gap_max,
    )
    gap_sigma = _safe_float(
        gap_data.get("sigma"),
        0.95,
        minimum=0.05,
        maximum=3.0,
    )
    return StartupModuleObservationTiming(
        initial_delay_min_us=initial_min,
        initial_delay_max_us=initial_max,
        inter_load_gap_median_us=gap_median,
        inter_load_gap_sigma=gap_sigma,
        inter_load_gap_min_us=gap_min,
        inter_load_gap_max_us=gap_max,
    )


def network_sensor_observation_timing(
    profile_name: str | None = None,
) -> NetworkSensorObservationTiming:
    """Return safe timing and capture bounds for one network sensor profile."""
    data = load_timing_profiles().get("network_sensor_observation", {})
    if not isinstance(data, dict):
        data = {}
    profiles = data.get("profiles", {})
    if not isinstance(profiles, dict):
        profiles = {}
    default_profile = str(data.get("default_profile", "well_synced") or "well_synced")
    selected_profile = str(profile_name or default_profile)
    profile = profiles.get(selected_profile, {})
    if not isinstance(profile, dict):
        selected_profile = default_profile
        profile = profiles.get(default_profile, {})
    if not isinstance(profile, dict):
        profile = {}

    skew_min, skew_max = _safe_int_range(
        profile.get("clock_offset_us", profile.get("clock_skew_us")),
        fallback_min=-18_000,
        fallback_max=22_000,
        minimum=-_MAX_SENSOR_TIMING_US,
        maximum=_MAX_SENSOR_TIMING_US,
    )
    drift_min, drift_max = _safe_int_range(
        profile.get("clock_drift_ppm"),
        fallback_min=0,
        fallback_max=0,
        minimum=-500,
        maximum=500,
    )
    delay_min, delay_max = _safe_int_range(
        profile.get("route_delay_us", profile.get("path_delay_us")),
        fallback_min=1_200,
        fallback_max=58_000,
        minimum=0,
        maximum=_MAX_SENSOR_TIMING_US,
    )
    jitter_min, jitter_max = _safe_int_range(
        profile.get("event_jitter_us"),
        fallback_min=-997,
        fallback_max=997,
        minimum=-_MAX_SENSOR_TIMING_US,
        maximum=_MAX_SENSOR_TIMING_US,
    )
    capture_loss = profile.get("capture_loss", {})
    if not isinstance(capture_loss, dict):
        capture_loss = {}
    loss_probability = _safe_float(
        capture_loss.get("probability", 0.0),
        0.0,
        minimum=0.0,
        maximum=1.0,
    )
    loss_min_fraction = _safe_float(
        capture_loss.get("min_fraction", 0.0),
        0.0,
        minimum=0.0,
        maximum=1.0,
    )
    loss_max_fraction = _safe_float(
        capture_loss.get("max_fraction", 0.0),
        0.0,
        minimum=0.0,
        maximum=1.0,
    )
    if loss_max_fraction < loss_min_fraction:
        loss_min_fraction = 0.0
        loss_max_fraction = 0.0
    loss_max_missed_bytes = _safe_int(
        capture_loss.get("max_missed_bytes", 0),
        0,
        minimum=0,
        maximum=1_000_000_000,
    )
    return NetworkSensorObservationTiming(
        profile_name=selected_profile,
        clock_offset_min_us=skew_min,
        clock_offset_max_us=skew_max,
        clock_drift_min_ppm=drift_min,
        clock_drift_max_ppm=drift_max,
        route_delay_min_us=delay_min,
        route_delay_max_us=delay_max,
        event_jitter_min_us=jitter_min,
        event_jitter_max_us=jitter_max,
        capture_loss_probability=loss_probability,
        capture_loss_min_fraction=loss_min_fraction,
        capture_loss_max_fraction=loss_max_fraction,
        capture_loss_max_missed_bytes=loss_max_missed_bytes,
    )


def endpoint_clock_timing(profile_name: str, os_category: str) -> EndpointClockTiming:
    """Return safe endpoint host-clock bounds for an observation profile and OS."""
    data = load_timing_profiles().get("endpoint_clock", {})
    if not isinstance(data, dict):
        data = {}
    profiles = data.get("profiles", {})
    if not isinstance(profiles, dict):
        profiles = {}
    profile = profiles.get(profile_name)
    if not isinstance(profile, dict):
        profile = profiles.get("complete", {})
    if not isinstance(profile, dict):
        profile = {}

    os_key = "windows" if os_category == "windows" else "linux"
    os_profile = profile.get(os_key, {})
    if not isinstance(os_profile, dict):
        os_profile = {}
    offset_min, offset_max = _safe_int_range(
        os_profile.get("host_offset_ms"),
        fallback_min=0,
        fallback_max=0,
        minimum=-_MAX_ENDPOINT_CLOCK_OFFSET_MS,
        maximum=_MAX_ENDPOINT_CLOCK_OFFSET_MS,
    )
    drift_min, drift_max = _safe_int_range(
        os_profile.get("host_drift_ppm"),
        fallback_min=0,
        fallback_max=0,
        minimum=-_MAX_ENDPOINT_CLOCK_DRIFT_PPM,
        maximum=_MAX_ENDPOINT_CLOCK_DRIFT_PPM,
    )
    return EndpointClockTiming(
        host_offset_min_ms=offset_min,
        host_offset_max_ms=offset_max,
        host_drift_min_ppm=drift_min,
        host_drift_max_ppm=drift_max,
    )


def firewall_observation_timing(sensor_identity: str = "") -> FirewallObservationTiming:
    """Return the configured firewall timer policy for one sensor."""

    data = load_timing_profiles().get("firewall_observation", {})
    if not isinstance(data, dict):
        data = {}
    policies = data.get("policies", {})
    if not isinstance(policies, dict):
        policies = {}
    sensor_policies = data.get("sensor_policies", {})
    if not isinstance(sensor_policies, dict):
        sensor_policies = {}
    default_policy = str(data.get("default_policy", "asa_default") or "asa_default")
    policy_name = str(sensor_policies.get(sensor_identity, default_policy) or default_policy)
    policy = policies.get(policy_name, {})
    if not isinstance(policy, dict):
        policy_name = default_policy
        policy = policies.get(default_policy, {})
    if not isinstance(policy, dict):
        policy = {}
    return FirewallObservationTiming(
        policy_name=policy_name,
        tcp_embryonic_timeout_seconds=_safe_int(
            policy.get("tcp_embryonic_timeout_seconds", 30),
            30,
            minimum=1,
            maximum=3600,
        ),
        tcp_idle_timeout_seconds=_safe_int(
            policy.get("tcp_idle_timeout_seconds", 3600),
            3600,
            minimum=1,
            maximum=604_800,
        ),
    )


def windows_collision_spacing_config() -> dict[str, int]:
    """Return Windows/Sysmon same-timestamp collision spacing settings."""
    spacing = load_timing_profiles().get("windows_event_time", {}).get("collision_spacing", {})
    if not isinstance(spacing, dict):
        spacing = {}
    config = {
        "near_zero_until": _safe_int(
            spacing.get("near_zero_until", 25),
            25,
            minimum=0,
            maximum=_MAX_COLLISION_NEAR_ZERO_UNTIL,
        ),
        "near_gap_min_us": _safe_int(
            spacing.get("near_gap_min_us", 50),
            50,
            minimum=1,
            maximum=_MAX_COLLISION_GAP_US,
        ),
        "near_gap_max_us": _safe_int(
            spacing.get("near_gap_max_us", 500),
            500,
            minimum=1,
            maximum=_MAX_COLLISION_GAP_US,
        ),
        "large_gap_min_ms": _safe_int(
            spacing.get("large_gap_min_ms", 1000),
            1000,
            minimum=1,
            maximum=_MAX_COLLISION_GAP_MS,
        ),
        "large_gap_max_ms": _safe_int(
            spacing.get("large_gap_max_ms", 4000),
            4000,
            minimum=1,
            maximum=_MAX_COLLISION_GAP_MS,
        ),
    }
    if config["near_gap_max_us"] < config["near_gap_min_us"]:
        config["near_gap_min_us"], config["near_gap_max_us"] = 50, 500
    if config["large_gap_max_ms"] < config["large_gap_min_ms"]:
        config["large_gap_min_ms"], config["large_gap_max_ms"] = 1000, 4000
    return config
