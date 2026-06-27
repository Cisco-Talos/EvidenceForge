# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Source-aware timestamp planning for canonical SecurityEvents.

``SecurityEvent.timestamp`` remains canonical world time. This module plans the
timestamps individual sources render from that event, using shared timing
profiles and explicit constraints instead of independent emitter-local jitter.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from evidenceforge.generation.activity.timing_profiles import (
    endpoint_clock_timing,
    get_timing_window,
    network_sensor_observation_timing,
    sample_timing_delta,
)
from evidenceforge.generation.timing import TemporalConstraintGraph
from evidenceforge.utils.rng import _stable_seed

if TYPE_CHECKING:
    from evidenceforge.events.base import SecurityEvent

_SOURCE_EPSILON = timedelta(milliseconds=1)
_OBSERVATION_NOISE_US = 997


@dataclass(slots=True)
class SourceTimingPlan:
    """Planned source-native timestamps for one canonical event."""

    canonical_timestamp: datetime
    clock_profile_name: str = "complete"
    source_times: dict[str, datetime] = field(default_factory=dict)


class SourceTimingPlanner:
    """Plan source-native observation times with deterministic constraints."""

    def __init__(self, clock_profile_name: str = "complete") -> None:
        self.clock_profile_name = clock_profile_name or "complete"

    def plan_event(self, event: SecurityEvent) -> SecurityEvent:
        """Return ``event`` with an attached source timing plan."""
        self._ensure_plan(event)
        return event

    def source_time(
        self,
        event: SecurityEvent,
        source_key: str,
        seed_parts: tuple[Any, ...] = (),
        not_before: datetime | None = None,
        not_after: datetime | None = None,
        within: tuple[datetime, datetime] | None = None,
    ) -> datetime:
        """Return a deterministic source timestamp for ``event``.

        The sampled profile gives the source's preferred observation time; the
        optional bounds then clamp it so declared causal relationships cannot be
        inverted by jitter. If bounds conflict, the lower bound wins because
        preserving causality is more important than preserving a sampled delay.
        """
        plan = self._ensure_plan(event)
        effective_seed = seed_parts or self._event_seed_parts(event)
        cache_key = self._cache_key(source_key, effective_seed)
        preferred_time = plan.source_times.get(cache_key)
        if preferred_time is None:
            preferred_time = self._sample_source_time(event, source_key, effective_seed)
        constrained_time = self._apply_constraints(
            preferred_time,
            not_before=not_before,
            not_after=not_after,
            within=within,
        )
        plan.source_times[cache_key] = constrained_time
        return constrained_time

    def record_source_time(
        self,
        event: SecurityEvent,
        source_key: str,
        timestamp: datetime,
        seed_parts: tuple[Any, ...] = (),
    ) -> None:
        """Record a finalized source timestamp for later correlated renderers.

        Some emitters perform source-native ordering repairs that depend on
        previously rendered rows from the same log. Once an emitter has chosen
        that final timestamp, downstream correlated sources should reuse it
        instead of recomputing the pre-repair preferred time.
        """
        plan = self._ensure_plan(event)
        effective_seed = seed_parts or self._event_seed_parts(event)
        plan.source_times[self._cache_key(source_key, effective_seed)] = timestamp

    def source_time_after_source(
        self,
        event: SecurityEvent,
        source_key: str,
        *,
        after_source_key: str,
        gap_key: str,
        seed_parts: tuple[Any, ...] = (),
        after_seed_parts: tuple[Any, ...] = (),
        after_not_before: datetime | None = None,
        not_before: datetime | None = None,
        not_after: datetime | None = None,
        within: tuple[datetime, datetime] | None = None,
    ) -> datetime:
        """Return a source timestamp constrained after another source observation."""
        effective_seed = seed_parts or self._event_seed_parts(event)
        anchor_seed = after_seed_parts or effective_seed

        anchor_cache_key = self._cache_key(after_source_key, anchor_seed)
        source_cache_key = self._cache_key(source_key, effective_seed)
        graph = TemporalConstraintGraph()
        graph.add_node(
            "anchor",
            self._preferred_source_time(event, after_source_key, anchor_seed),
            not_before=after_not_before,
        )
        graph.add_node(
            "source",
            self._preferred_source_time(event, source_key, effective_seed),
            not_before=not_before,
            not_after=not_after,
            within=within,
        )
        graph.constrain_after(
            "source",
            "anchor",
            min_gap=sample_timing_delta(gap_key, seed_parts=effective_seed),
        )
        resolved = graph.resolve()

        plan = self._ensure_plan(event)
        plan.source_times[anchor_cache_key] = resolved["anchor"]
        plan.source_times[source_cache_key] = resolved["source"]
        return resolved["source"]

    def ordered_pair(
        self,
        before_event: SecurityEvent,
        after_event: SecurityEvent,
        source_key: str,
        min_gap_ms: int = 1,
    ) -> tuple[datetime, datetime]:
        """Plan a same-source causal pair such that ``before < after``."""
        gap = max(timedelta(milliseconds=max(1, min_gap_ms)), _SOURCE_EPSILON)
        before_seed = ("ordered-before", *self._event_seed_parts(before_event))
        after_seed = ("ordered-after", *self._event_seed_parts(after_event))

        graph = TemporalConstraintGraph()
        graph.add_node(
            "before",
            self._preferred_source_time(before_event, source_key, before_seed),
        )
        graph.add_node(
            "after",
            self._preferred_source_time(after_event, source_key, after_seed),
        )
        graph.constrain_after("after", "before", min_gap=gap)
        resolved = graph.resolve()

        before_time = resolved["before"]
        after_time = resolved["after"]
        self._ensure_plan(before_event).source_times[self._cache_key(source_key, before_seed)] = (
            before_time
        )
        self._ensure_plan(after_event).source_times[self._cache_key(source_key, after_seed)] = (
            after_time
        )
        return before_time, after_time

    def sensor_observation_time(
        self,
        event: SecurityEvent,
        sensor: str,
        route_key: str,
        source_key: str,
    ) -> datetime:
        """Return the timestamp a network sensor sees for this source event."""
        source_time = self.source_time(
            event,
            source_key,
            seed_parts=(route_key, *self._event_seed_parts(event)),
        )
        timing = network_sensor_observation_timing()
        skew = self._bounded_us(
            "sensor-clock-skew",
            timing.clock_skew_min_us,
            timing.clock_skew_max_us,
            (sensor,),
        )
        path_delay = self._bounded_us(
            "sensor-path-delay",
            timing.path_delay_min_us,
            timing.path_delay_max_us,
            (sensor, route_key),
        )
        noise = self._bounded_us(
            "sensor-capture-noise",
            -_OBSERVATION_NOISE_US,
            _OBSERVATION_NOISE_US,
            (sensor, route_key, *self._event_seed_parts(event)),
        )
        return source_time + timedelta(microseconds=skew + path_delay + noise)

    def _ensure_plan(self, event: SecurityEvent) -> SourceTimingPlan:
        """Attach and return a mutable source timing plan for ``event``."""
        if event.source_timing is None:
            event.source_timing = SourceTimingPlan(
                canonical_timestamp=event.timestamp,
                clock_profile_name=self.clock_profile_name,
            )
        elif not event.source_timing.clock_profile_name:
            event.source_timing.clock_profile_name = self.clock_profile_name
        return event.source_timing

    def _sample_source_time(
        self,
        event: SecurityEvent,
        source_key: str,
        seed_parts: tuple[Any, ...],
    ) -> datetime:
        """Sample the preferred source timestamp from timing profiles."""
        window = get_timing_window(
            source_key,
            default_min_ms=0,
            default_max_ms=0,
            default_position="after",
        )
        delta = sample_timing_delta(source_key, seed_parts=seed_parts)
        micro_noise = (
            self._source_micro_noise(source_key, seed_parts)
            if window.relationship_class == "same_observation"
            and source_key != "source.zeek_conn_start"
            else timedelta(0)
        )
        canonical_time = event.timestamp
        if window.position == "before":
            source_time = canonical_time - delta - micro_noise
        else:
            source_time = canonical_time + delta + micro_noise
        return source_time + self._endpoint_clock_adjustment(event, source_key, seed_parts)

    def _preferred_source_time(
        self,
        event: SecurityEvent,
        source_key: str,
        seed_parts: tuple[Any, ...],
    ) -> datetime:
        """Return cached or sampled preferred source time before graph constraints."""

        plan = self._ensure_plan(event)
        cache_key = self._cache_key(source_key, seed_parts)
        preferred_time = plan.source_times.get(cache_key)
        if preferred_time is not None:
            return preferred_time
        return self._sample_source_time(event, source_key, seed_parts)

    def _endpoint_clock_adjustment(
        self,
        event: SecurityEvent,
        source_key: str,
        seed_parts: tuple[Any, ...],
    ) -> timedelta:
        """Return shared host-clock adjustment for host-resident endpoint sources."""
        scope = self._endpoint_clock_scope(event, source_key)
        if scope is None:
            return timedelta(0)
        host_key, os_category = scope
        plan = self._ensure_plan(event)
        timing = endpoint_clock_timing(plan.clock_profile_name, os_category)
        offset_ms = self._bounded_int(
            "endpoint-clock-offset",
            timing.host_offset_min_ms,
            timing.host_offset_max_ms,
            (plan.clock_profile_name, os_category, host_key),
        )
        drift_ppm = self._bounded_int(
            "endpoint-clock-drift",
            timing.host_drift_min_ppm,
            timing.host_drift_max_ppm,
            (plan.clock_profile_name, os_category, host_key),
        )
        seconds_since_midnight = (
            event.timestamp.hour * 3600
            + event.timestamp.minute * 60
            + event.timestamp.second
            + event.timestamp.microsecond / 1_000_000
        )
        drift_us = round(seconds_since_midnight * drift_ppm)
        return timedelta(milliseconds=offset_ms, microseconds=drift_us)

    @staticmethod
    def _endpoint_clock_scope(
        event: SecurityEvent,
        source_key: str,
    ) -> tuple[str, str] | None:
        """Return ``(host, os_category)`` for endpoint sources, else ``None``."""
        if source_key.startswith(("source.zeek_", "network.")):
            return None
        if source_key.startswith(("source.windows_", "source.sysmon_")):
            host = event.src_host or event.dst_host
            hostname = getattr(host, "hostname", "") or ""
            return (hostname, "windows") if hostname else None
        if source_key.startswith("source.ecar_"):
            host = event.src_host or event.dst_host
            hostname = getattr(host, "hostname", "") or ""
            os_category = getattr(host, "os_category", "") or ""
            if os_category not in {"windows", "linux"}:
                return None
            return (hostname, os_category) if hostname else None
        if source_key.startswith(("source.syslog_", "source.bash_history_")):
            host = event.src_host or event.dst_host
            hostname = getattr(host, "hostname", "") or ""
            return (hostname, "linux") if hostname else None
        return None

    @staticmethod
    def _source_micro_noise(
        source_key: str,
        seed_parts: tuple[Any, ...],
    ) -> timedelta:
        """Return deterministic sub-millisecond texture for packet-like source rows."""
        seed = _stable_seed(
            "source-micro-noise:" + source_key + ":" + ":".join(str(part) for part in seed_parts)
        )
        return timedelta(microseconds=37 + (seed % 961))

    @staticmethod
    def _apply_constraints(
        preferred_time: datetime,
        *,
        not_before: datetime | None,
        not_after: datetime | None,
        within: tuple[datetime, datetime] | None,
    ) -> datetime:
        """Clamp preferred time to hard causal bounds."""
        lower = not_before
        upper = not_after
        if within is not None:
            start, end = within
            lower = start if lower is None else max(lower, start)
            upper = end if upper is None else min(upper, end)
        if lower is not None and upper is not None and upper < lower:
            return lower
        result = preferred_time
        if lower is not None and result < lower:
            result = lower
        if upper is not None and result > upper:
            result = upper
        return result

    @staticmethod
    def _bounded_us(prefix: str, minimum: int, maximum: int, parts: tuple[Any, ...]) -> int:
        """Return a deterministic integer in the inclusive microsecond range."""
        if maximum <= minimum:
            return minimum
        seed = _stable_seed(prefix + ":" + ":".join(str(part) for part in parts))
        return minimum + (seed % (maximum - minimum + 1))

    @staticmethod
    def _bounded_int(prefix: str, minimum: int, maximum: int, parts: tuple[Any, ...]) -> int:
        """Return a deterministic integer in the inclusive range."""
        if maximum <= minimum:
            return minimum
        seed = _stable_seed(prefix + ":" + ":".join(str(part) for part in parts))
        return minimum + (seed % (maximum - minimum + 1))

    @staticmethod
    def _cache_key(source_key: str, seed_parts: tuple[Any, ...]) -> str:
        """Build a deterministic cache key for a source observation."""
        return source_key + "|" + "|".join(str(part) for part in seed_parts)

    @staticmethod
    def _event_seed_parts(event: SecurityEvent) -> tuple[Any, ...]:
        """Return stable content-derived identity parts for a SecurityEvent."""
        net = event.network
        proc = event.process
        auth = event.auth
        krb = event.kerberos
        edr = event.edr
        return (
            event.event_type,
            event.timestamp.isoformat(),
            getattr(event.src_host, "hostname", ""),
            getattr(event.dst_host, "hostname", ""),
            getattr(proc, "pid", ""),
            getattr(proc, "start_time", ""),
            getattr(net, "zeek_uid", ""),
            getattr(net, "src_ip", ""),
            getattr(net, "src_port", ""),
            getattr(net, "dst_ip", ""),
            getattr(net, "dst_port", ""),
            getattr(auth, "logon_id", ""),
            getattr(krb, "service_name", ""),
            getattr(krb, "source_ip", ""),
            getattr(krb, "source_port", ""),
            getattr(edr, "object_id", ""),
            event.storyline_cluster_id or "",
        )
