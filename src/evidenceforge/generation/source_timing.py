# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Source-aware timestamp planning for canonical SecurityEvents.

``SecurityEvent.timestamp`` remains canonical world time. This module plans the
timestamps individual sources render from that event, using shared timing
profiles and explicit constraints instead of independent emitter-local jitter.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.generation.activity.timing_profiles import (
    endpoint_clock_timing,
    get_timing_window,
    network_sensor_observation_timing,
    sample_timing_delta,
)
from evidenceforge.generation.timing import TemporalConstraintGraph
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.rng import _stable_seed
from evidenceforge.utils.time import ensure_utc

if TYPE_CHECKING:
    from evidenceforge.events.base import SecurityEvent

_SOURCE_EPSILON = timedelta(milliseconds=1)
_OBSERVATION_NOISE_US = 997
_PROCESS_CREATE_SOURCE_KEYS = {
    "source.windows_security_process_create",
    "source.sysmon_process_create",
    "source.ecar_process_create",
}
_PROCESS_START_EVENT_TYPES = {"process_create", "system_process_create"}
_SESSION_CLOSURE_SOURCE_KEYS = {
    "ecar": "source.ecar_session_logout",
    "windows_security": "source.windows_security_session_logout",
    "windows_event_security": "source.windows_security_session_logout",
    "syslog": "source.syslog_session_logout",
}


@dataclass(slots=True)
class SourceTimingPlan:
    """Planned source-native timestamps for one canonical event."""

    canonical_timestamp: datetime
    clock_profile_name: str = "complete"
    source_times: dict[str, datetime] = field(default_factory=dict)
    finalized_times: dict[str, datetime] = field(default_factory=dict)
    finalized_flags: dict[str, bool] = field(default_factory=dict)


def ecar_flow_render_key(direction: str, hostname: str) -> str:
    """Return the finalized-plan key for one host-local eCAR FLOW row."""

    return f"ecar.flow.{direction.lower()}.{hostname}"


def ecar_session_render_key(lifecycle: str) -> str:
    """Return the finalized-plan key for one eCAR USER_SESSION row."""

    return f"ecar.session.{lifecycle}"


def ecar_flow_identity_key(direction: str, hostname: str) -> str:
    """Return the finalized-plan key for FLOW process-attribution safety."""

    return f"ecar.flow_identity_safe.{direction.lower()}.{hostname}"


_WINDOWS_WFP_RENDER_KEY = "windows.wfp_connection"
_REMOTE_TRANSPORT_KEY = tuple[str, str, str, str, int, str, int, str]


class SourceTimingPlanner:
    """Plan source-native observation times with deterministic constraints."""

    def __init__(self, clock_profile_name: str = "complete") -> None:
        self.clock_profile_name = clock_profile_name or "complete"
        self._ecar_process_create_times: dict[str, datetime] = {}
        self._latest_session_dependent_times: dict[tuple[str, str], datetime] = {}
        self._admitted_ecar_remote_transports: dict[_REMOTE_TRANSPORT_KEY, datetime] = {}
        self._admitted_windows_remote_transports: dict[_REMOTE_TRANSPORT_KEY, datetime] = {}

    def plan_event(
        self,
        event: SecurityEvent,
        format_name: str | None = None,
    ) -> SecurityEvent:
        """Return ``event`` with an attached source timing plan."""
        self._ensure_plan(event)
        if format_name in {None, "ecar"}:
            self._plan_ecar_identity_times(event)
        if format_name == "ecar":
            self._plan_ecar_render_times(event)
        if format_name in {"windows_security", "windows_event_security"}:
            event = self._plan_windows_remote_auth_time(event)
        if format_name is not None:
            event = self._plan_session_lifecycle_time(event, format_name)
        return event

    def initialize_event(self, event: SecurityEvent) -> None:
        """Retain canonical time before source observation delay is applied.

        Initialization deliberately does not plan identities or render timestamps;
        those decisions belong to the visible source path selected by the
        dispatcher.
        """

        self._ensure_plan(event)

    def record_admitted_source_event(
        self,
        event: SecurityEvent,
        format_name: str,
    ) -> None:
        """Publish an admitted transport anchor for later authentication siblings."""

        lifecycle = event.lifecycle
        network = event.network
        if lifecycle is None or network is None or lifecycle.parent_group_id is None:
            return
        if not lifecycle.parent_group_id.startswith("windows-remote-auth-"):
            return
        target_host = event.dst_host or event.src_host
        target_hostname = getattr(target_host, "hostname", "")
        if not target_hostname:
            return
        if event.event_type == "connection" and network.transaction is not None:
            transaction_id = network.transaction.stable_id
            if format_name == "ecar" and event.dst_host is not None:
                timestamp = self._finalized_time(
                    event,
                    ecar_flow_render_key("inbound", event.dst_host.hostname),
                )
                if timestamp is not None:
                    self._admitted_ecar_remote_transports[
                        self._remote_transport_key(
                            lifecycle.parent_group_id,
                            transaction_id,
                            target_hostname,
                            network.src_ip,
                            network.src_port,
                            network.dst_ip,
                            network.dst_port,
                            network.protocol,
                        )
                    ] = timestamp
            return
        if event.event_type != "wfp_connection" or format_name not in {
            "windows_security",
            "windows_event_security",
        }:
            return
        host = event.src_host or event.dst_host
        if host is None or network.dst_ip != host.ip:
            return
        timestamp = self._finalized_time(event, _WINDOWS_WFP_RENDER_KEY)
        if timestamp is not None:
            self._admitted_windows_remote_transports[
                self._remote_transport_key(
                    lifecycle.parent_group_id,
                    lifecycle.group_id,
                    host.hostname,
                    network.src_ip,
                    network.src_port,
                    network.dst_ip,
                    network.dst_port,
                    network.protocol,
                )
            ] = timestamp

    def _plan_ecar_render_times(self, event: SecurityEvent) -> None:
        """Finalize eCAR FLOW and USER_SESSION times before emitter admission."""

        if event.event_type == "connection" and event.network is not None:
            self._plan_ecar_flow_times(event)
            return
        if event.auth is None or event.event_type not in {
            "logon",
            "machine_logon",
            "ssh_session",
            "failed_logon",
            "logoff",
        }:
            return
        lifecycle = (
            "logout"
            if event.event_type == "logoff"
            else "failed_login"
            if event.event_type == "failed_logon"
            else "login"
        )
        plan = self._ensure_plan(event)
        if lifecycle == "logout":
            plan.finalized_times[ecar_session_render_key(lifecycle)] = event.timestamp
            return
        host = event.dst_host or event.src_host
        canonical_timestamp = plan.canonical_timestamp
        seed_parts = (
            lifecycle,
            getattr(host, "hostname", ""),
            getattr(event.auth, "username", ""),
            getattr(event.auth, "source_ip", ""),
            getattr(event.auth, "source_port", ""),
            getattr(event.auth, "logon_id", ""),
            getattr(event.auth, "logon_type", ""),
            getattr(event.edr, "object_id", ""),
            canonical_timestamp,
        )
        timestamp = self.source_time(
            event,
            "source.ecar_session",
            seed_parts=seed_parts,
        )
        anchor = self._remote_auth_transport_anchor(
            event,
            self._admitted_ecar_remote_transports,
        )
        if anchor is not None:
            timestamp = anchor + sample_timing_delta(
                "windows.network_logon_after_transport",
                seed_parts=(
                    "ecar",
                    event.remote_auth.stable_id,
                    event.remote_auth.primary_transport.transaction_id,
                    lifecycle,
                ),
            )
        plan.finalized_times[ecar_session_render_key(lifecycle)] = timestamp

    def _plan_windows_remote_auth_time(self, event: SecurityEvent) -> SecurityEvent:
        """Finalize source-local WFP-before-authentication ordering."""

        if event.event_type == "wfp_connection" and event.network is not None:
            host = event.src_host or event.dst_host
            timestamp = self.source_time(
                event,
                "source.windows_wfp_connection",
                seed_parts=(
                    getattr(host, "hostname", ""),
                    event.network.initiating_pid if event.network.initiating_pid > 0 else 4,
                    event.network.src_ip,
                    event.network.src_port,
                    event.network.dst_ip,
                    event.network.dst_port,
                    event.timestamp,
                ),
                not_before=event.timestamp,
            )
            self._ensure_plan(event).finalized_times[_WINDOWS_WFP_RENDER_KEY] = timestamp
            return event
        if (
            event.event_type not in {"logon", "machine_logon", "failed_logon"}
            or event.remote_auth is None
        ):
            return event
        anchor = self._remote_auth_transport_anchor(
            event,
            self._admitted_windows_remote_transports,
        )
        if anchor is None:
            return event
        timestamp = anchor + sample_timing_delta(
            "windows.network_logon_after_transport",
            seed_parts=(
                "windows_security",
                event.remote_auth.stable_id,
                event.remote_auth.primary_transport.transaction_id,
                event.event_type,
            ),
        )
        self._ensure_plan(event).finalized_times["windows.remote_authentication"] = timestamp
        return replace(event, timestamp=timestamp)

    @staticmethod
    def _remote_auth_transport_anchor(
        event: SecurityEvent,
        registry: dict[_REMOTE_TRANSPORT_KEY, datetime],
    ) -> datetime | None:
        remote_auth = event.remote_auth
        if remote_auth is None or remote_auth.primary_transport is None:
            return None
        transport = remote_auth.primary_transport
        tuple_view = transport.tuple
        return registry.get(
            SourceTimingPlanner._remote_transport_key(
                remote_auth.stable_id,
                transport.transaction_id,
                remote_auth.target_hostname,
                tuple_view.src_ip,
                tuple_view.src_port,
                tuple_view.dst_ip,
                tuple_view.dst_port,
                tuple_view.protocol,
            )
        )

    @staticmethod
    def _remote_transport_key(
        action_group_id: str,
        transaction_id: str,
        target_hostname: str,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        protocol: str,
    ) -> _REMOTE_TRANSPORT_KEY:
        """Return the exact source-view key for one remote-auth transport."""

        return (
            action_group_id,
            transaction_id,
            target_hostname,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            protocol.lower(),
        )

    @staticmethod
    def _finalized_time(event: SecurityEvent, key: str) -> datetime | None:
        plan = event.source_timing
        return plan.finalized_times.get(key) if plan is not None else None

    def _plan_ecar_flow_times(self, event: SecurityEvent) -> None:
        """Finalize every host-local FLOW timestamp and attribution decision."""

        network = event.network
        if network is None:
            return
        identity_plan = event.identity_plan
        source_identity = (
            identity_plan.actor
            if identity_plan is not None and isinstance(identity_plan.actor, ProcessIdentity)
            else None
        )
        target_identity = (
            identity_plan.target
            if identity_plan is not None and isinstance(identity_plan.target, ProcessIdentity)
            else None
        )
        plan = self._ensure_plan(event)
        paired_endpoint = event.src_host is not None and event.dst_host is not None
        if event.src_host is not None:
            direction = "outbound"
            hostname = event.src_host.hostname
            not_before = (
                self._ecar_process_identity_not_before(event, source_identity)
                if source_identity is not None
                else None
            )
            timestamp, identity_safe = self._ecar_flow_source_time(
                event,
                seed_parts=(
                    direction,
                    hostname,
                    network.initiating_pid,
                    network.src_ip,
                    network.src_port,
                    network.dst_ip,
                    network.dst_port,
                    event.timestamp,
                ),
                not_before=not_before,
                drop_late_process_identity=(
                    network.protocol == "tcp" and network.dst_port in {22, 3389}
                ),
                paired_endpoint=paired_endpoint,
            )
            plan.finalized_times[ecar_flow_render_key(direction, hostname)] = timestamp
            plan.finalized_flags[ecar_flow_identity_key(direction, hostname)] = identity_safe
        if event.dst_host is not None:
            direction = "inbound"
            hostname = event.dst_host.hostname
            not_before = (
                self._ecar_process_identity_not_before(event, target_identity)
                if target_identity is not None
                else None
            )
            timestamp, identity_safe = self._ecar_flow_source_time(
                event,
                seed_parts=(
                    direction,
                    hostname,
                    network.initiating_pid,
                    network.src_ip,
                    network.src_port,
                    network.dst_ip,
                    network.dst_port,
                    event.timestamp,
                ),
                not_before=not_before,
                drop_late_process_identity=(
                    network.protocol == "tcp" and network.dst_port in {22, 3389}
                ),
                paired_endpoint=paired_endpoint,
            )
            plan.finalized_times[ecar_flow_render_key(direction, hostname)] = timestamp
            plan.finalized_flags[ecar_flow_identity_key(direction, hostname)] = identity_safe

    def _ecar_process_identity_not_before(
        self,
        event: SecurityEvent,
        identity: ProcessIdentity,
    ) -> datetime:
        """Return the earliest FLOW time that can safely claim a process."""

        if event.timestamp - identity.started_at >= timedelta(seconds=5):
            return identity.started_at
        create_time = self._prime_ecar_process_create_time(event, identity)
        return create_time + _SOURCE_EPSILON

    def _ecar_flow_source_time(
        self,
        event: SecurityEvent,
        *,
        seed_parts: tuple[Any, ...],
        not_before: datetime | None,
        drop_late_process_identity: bool,
        paired_endpoint: bool,
    ) -> tuple[datetime, bool]:
        """Return a finalized FLOW time bounded by its canonical interval."""

        interval_start, not_after = self._ecar_flow_interval(event, seed_parts)
        lifecycle = event.lifecycle
        if (
            lifecycle is not None
            and lifecycle.parent_group_id is not None
            and lifecycle.parent_group_id.startswith("proxy-transaction-")
        ):
            host_key = str(seed_parts[1]) if len(seed_parts) > 1 else ""
            flow_time = self.lifecycle_child_source_time(
                event,
                "source.ecar_flow",
                host_key=host_key,
                seed_parts=seed_parts,
                within=(interval_start, not_after) if not_after is not None else None,
            )
            if flow_time is not None:
                return flow_time, not_before is None or not_before <= flow_time

        if drop_late_process_identity and not_before is not None:
            flow_time = self.source_time(
                event,
                "source.ecar_flow",
                seed_parts=seed_parts,
                within=(interval_start, not_after) if not_after is not None else None,
            )
            flow_time = self._paired_ecar_flow_observation_time(
                event,
                flow_time,
                seed_parts=seed_parts,
                interval_start=interval_start,
                not_before=None,
                not_after=not_after,
                enabled=paired_endpoint,
            )
            return flow_time, not_before <= flow_time

        identity_safe = not_before is None or not_after is None or not_before <= not_after
        flow_time = self.source_time(
            event,
            "source.ecar_flow",
            seed_parts=seed_parts,
            not_before=not_before if identity_safe else None,
            within=(interval_start, not_after) if not_after is not None else None,
        )
        flow_time = self._paired_ecar_flow_observation_time(
            event,
            flow_time,
            seed_parts=seed_parts,
            interval_start=interval_start,
            not_before=not_before if identity_safe else None,
            not_after=not_after,
            enabled=paired_endpoint,
        )
        if identity_safe and not_before is not None and flow_time < not_before:
            identity_safe = False
        return flow_time, identity_safe

    @staticmethod
    def _paired_ecar_flow_observation_time(
        event: SecurityEvent,
        timestamp: datetime,
        *,
        seed_parts: tuple[Any, ...],
        interval_start: datetime,
        not_before: datetime | None,
        not_after: datetime | None,
        enabled: bool,
    ) -> datetime:
        """Add deterministic host-local texture to paired endpoint FLOWs."""

        if not enabled:
            return timestamp
        if not_after is None:
            return SourceTimingPlanner._unbounded_paired_ecar_flow_time(
                event,
                seed_parts=seed_parts,
                not_before=not_before,
            )
        short_interval = not_after <= interval_start + timedelta(milliseconds=5)
        lower_bound = not_before
        if not short_interval and not_after > interval_start:
            lower_bound = (
                interval_start if lower_bound is None else max(lower_bound, interval_start)
            )
        min_offset_ms = SourceTimingPlanner._ecar_flow_min_endpoint_offset_ms(
            event,
            seed_parts,
        )
        if min_offset_ms > 0:
            minimum_time = interval_start + timedelta(milliseconds=min_offset_ms)
            if minimum_time <= not_after:
                lower_bound = (
                    minimum_time if lower_bound is None else max(lower_bound, minimum_time)
                )

        seed = _stable_seed(
            "ecar_paired_flow_observation:"
            + ":".join(str(part) for part in (*seed_parts, event.timestamp.isoformat()))
        )
        direction = str(seed_parts[0]) if seed_parts else ""
        if short_interval and direction == "inbound":
            minimum_jitter_ms, maximum_jitter_ms = 22, 55
        elif short_interval and direction == "outbound":
            minimum_jitter_ms, maximum_jitter_ms = 1, 16
        elif direction == "inbound":
            minimum_jitter_ms, maximum_jitter_ms = 75, 540
        elif direction == "outbound":
            minimum_jitter_ms, maximum_jitter_ms = 12, 220
        else:
            minimum_jitter_ms, maximum_jitter_ms = 12, 360
        jitter_ms = minimum_jitter_ms + (seed % (maximum_jitter_ms - minimum_jitter_ms + 1))
        candidate = timestamp - timedelta(milliseconds=jitter_ms)
        if lower_bound is not None and candidate < lower_bound:
            available_ms = int((timestamp - lower_bound).total_seconds() * 1000)
            if available_ms <= 0:
                return timestamp
            if available_ms < minimum_jitter_ms:
                if direction == "inbound" and available_ms >= 4:
                    slice_min_ms, slice_max_ms = max(1, (available_ms * 2) // 3), available_ms
                elif direction == "outbound" and available_ms >= 4:
                    slice_min_ms, slice_max_ms = 1, max(1, available_ms // 3)
                else:
                    slice_min_ms, slice_max_ms = 1, available_ms
                bounded_jitter_ms = slice_min_ms + (seed % (slice_max_ms - slice_min_ms + 1))
            else:
                bounded_jitter_ms = minimum_jitter_ms + (
                    seed % (available_ms - minimum_jitter_ms + 1)
                )
            candidate = timestamp - timedelta(milliseconds=bounded_jitter_ms)
        return min(candidate, not_after)

    @staticmethod
    def _unbounded_paired_ecar_flow_time(
        event: SecurityEvent,
        *,
        seed_parts: tuple[Any, ...],
        not_before: datetime | None,
    ) -> datetime:
        """Return coordinated paired FLOW timing when no close bound exists."""

        network = event.network
        if network is None:
            return event.timestamp
        tuple_seed = _stable_seed(
            "ecar_paired_flow_base:"
            + ":".join(
                str(part)
                for part in (
                    network.src_ip,
                    network.src_port,
                    network.dst_ip,
                    network.dst_port,
                    network.protocol,
                    event.timestamp.isoformat(),
                )
            )
        )
        base_delay_ms = 220 + (tuple_seed % 900)
        direction = str(seed_parts[0]) if seed_parts else ""
        host = str(seed_parts[1]) if len(seed_parts) > 1 else ""
        offset_seed = _stable_seed(
            "ecar_paired_flow_host_offset:"
            + ":".join(str(part) for part in (direction, host, *seed_parts))
        )
        if direction == "inbound":
            offset_ms = 300 + (offset_seed % 360)
        elif direction == "outbound":
            offset_ms = 20 + (offset_seed % 180)
        else:
            offset_ms = 80 + (offset_seed % 420)
        candidate = event.timestamp + timedelta(milliseconds=base_delay_ms + offset_ms)
        if not_before is not None and candidate < not_before:
            candidate = not_before + timedelta(milliseconds=6 + (offset_seed % 180))
        return candidate

    @staticmethod
    def _ecar_flow_interval(
        event: SecurityEvent,
        seed_parts: tuple[Any, ...],
    ) -> tuple[datetime, datetime | None]:
        """Return the finalized canonical interval for an endpoint FLOW."""

        network = event.network
        if network is None:
            return event.timestamp, None
        start_time = network.source_visible_start_time or event.timestamp
        if network.duration is None:
            if network.conn_state in {"S0", "REJ", "RSTO", "RSTR", "SH", "SHR"}:
                seed = _stable_seed(
                    "ecar_failed_flow_not_after:"
                    + ":".join(str(part) for part in (*seed_parts, start_time.isoformat()))
                )
                return start_time, start_time + timedelta(milliseconds=45 + (seed % 620))
            return start_time, None
        close_time = network.source_visible_close_time or (
            start_time + timedelta(seconds=max(0.0, network.duration))
        )
        if close_time <= start_time:
            return start_time, close_time
        duration_us = int((close_time - start_time).total_seconds() * 1_000_000)
        seed = _stable_seed("ecar_flow_not_after:" + ":".join(str(part) for part in seed_parts))
        margin_us = 1000 + (seed % 4000)
        if duration_us <= margin_us:
            margin_us = max(0, duration_us // 2)
        return start_time, close_time - timedelta(microseconds=margin_us)

    @staticmethod
    def _ecar_flow_min_endpoint_offset_ms(
        event: SecurityEvent,
        seed_parts: tuple[Any, ...],
    ) -> int:
        """Return the minimum endpoint delay for very short FLOWs."""

        network = event.network
        if network is None:
            return 0
        applies = (
            network.conn_state in {"S0", "REJ", "RSTO", "RSTR", "SH", "SHR"}
            if network.duration is None
            else 0 <= network.duration < 0.1
        )
        if not applies:
            return 0
        seed = _stable_seed(
            "ecar_flow_min_endpoint_offset:"
            + ":".join(str(part) for part in (*seed_parts, event.timestamp.isoformat()))
        )
        return 18 + (seed % 65)

    def _plan_session_lifecycle_time(
        self,
        event: SecurityEvent,
        format_name: str,
    ) -> SecurityEvent:
        """Order same-source process termination and session closure observations."""

        lifecycle = event.lifecycle
        if lifecycle is None:
            return event
        if event.event_type == "process_terminate" and lifecycle.parent_group_id:
            source_time = self._process_termination_source_time(event, format_name)
            key = (format_name, lifecycle.parent_group_id)
            previous = self._latest_session_dependent_times.get(key)
            if previous is None or source_time > previous:
                self._latest_session_dependent_times[key] = source_time
            return event
        if event.event_type != "logoff" or format_name not in _SESSION_CLOSURE_SOURCE_KEYS:
            return event
        return replace(
            event,
            timestamp=self.session_closure_source_time(event, format_name),
        )

    def _process_termination_source_time(
        self,
        event: SecurityEvent,
        format_name: str,
    ) -> datetime:
        """Return the timestamp a source will render for a process termination."""

        process = event.process
        host = event.src_host
        if process is None or host is None:
            return event.timestamp
        start_time = process.start_time or event.timestamp
        if format_name in {"windows_security", "windows_event_security"}:
            return self.source_time(
                event,
                "source.windows_security_process_terminate",
                seed_parts=(host.hostname, process.pid, start_time, event.timestamp),
                not_before=event.timestamp,
            )
        if format_name == "ecar":
            identity = (
                event.identity_plan.subject
                if event.identity_plan is not None
                and isinstance(event.identity_plan.subject, ProcessIdentity)
                else None
            )
            process_start = identity.started_at if identity is not None else start_time
            create_time = (
                self._prime_ecar_process_create_time(event, identity)
                if identity is not None
                else process_start
            )
            canonical_lifetime = max(
                timedelta(milliseconds=100),
                event.timestamp - process_start,
            )
            return self.source_time(
                event,
                "source.ecar_process_terminate",
                seed_parts=(host.hostname, process.pid, process_start, event.timestamp),
                not_before=max(event.timestamp, create_time + canonical_lifetime),
            )
        return event.timestamp

    def session_closure_source_time(
        self,
        event: SecurityEvent,
        format_name: str,
    ) -> datetime:
        """Return the bounded source-native closure time for one session group."""

        lifecycle = event.lifecycle
        source_key = _SESSION_CLOSURE_SOURCE_KEYS.get(format_name)
        if lifecycle is None or source_key is None:
            return event.timestamp
        plan = self._ensure_plan(event)
        canonical_end = ensure_utc(plan.canonical_timestamp)
        seed_parts = (
            "session-closure",
            format_name,
            lifecycle.group_id,
            getattr(event.auth, "logon_id", ""),
            canonical_end,
        )
        cache_key = self._cache_key(source_key, seed_parts)
        preferred = plan.source_times.get(cache_key)
        if preferred is None:
            preferred = canonical_end
        latest = self._latest_session_dependent_times.get((format_name, lifecycle.group_id))
        earliest = canonical_end
        if latest is not None:
            earliest = latest + sample_timing_delta(
                "windows.logoff_after_rendered_dependents",
                seed_parts=(format_name, lifecycle.group_id, latest),
            )
        tail_seconds = 4 if format_name == "syslog" else 15
        latest_allowed = canonical_end + timedelta(seconds=tail_seconds)
        if earliest > latest_allowed:
            raise StateError(
                "Source-visible session dependents exceed the closure tail bound: "
                f"format={format_name} group={lifecycle.group_id} "
                f"dependent={earliest.isoformat()} end={canonical_end.isoformat()}"
            )
        closure_time = min(max(preferred, earliest), latest_allowed)
        plan.source_times[cache_key] = closure_time
        return closure_time

    def record_session_closure_source_time(
        self,
        event: SecurityEvent,
        format_name: str,
        timestamp: datetime,
    ) -> None:
        """Record a bundle-planned closure time for a source before dispatch."""

        lifecycle = event.lifecycle
        source_key = _SESSION_CLOSURE_SOURCE_KEYS.get(format_name)
        if lifecycle is None or source_key is None:
            return
        plan = self._ensure_plan(event)
        canonical_end = ensure_utc(plan.canonical_timestamp)
        seed_parts = (
            "session-closure",
            format_name,
            lifecycle.group_id,
            getattr(event.auth, "logon_id", ""),
            canonical_end,
        )
        plan.source_times[self._cache_key(source_key, seed_parts)] = ensure_utc(timestamp)

    def _plan_ecar_identity_times(self, event: SecurityEvent) -> None:
        """Prime stable process-create anchors for eCAR lifecycle consumers.

        Process creation and dependent telemetry are separate canonical events.
        Their independent source-latency samples must still share the exact
        source-visible process-create anchor, including parent-before-child
        ordering. The dispatcher-owned planner retains that cross-event state;
        emitters only consume the timestamp recorded on each event plan.
        """

        identity_plan = event.identity_plan
        if identity_plan is None:
            return
        identities: list[ProcessIdentity] = []
        for identity in (
            identity_plan.subject,
            identity_plan.actor,
            identity_plan.target,
        ):
            if isinstance(identity, ProcessIdentity) and identity not in identities:
                identities.append(identity)
        if not identities:
            return

        subject = (
            identity_plan.subject if isinstance(identity_plan.subject, ProcessIdentity) else None
        )
        parent = (
            identity_plan.actor
            if event.event_type in _PROCESS_START_EVENT_TYPES
            and isinstance(identity_plan.actor, ProcessIdentity)
            else None
        )
        parent_time = self._ecar_process_create_times.get(parent.object_id) if parent else None
        if parent is not None and parent_time is None:
            parent_time = self._prime_ecar_process_create_time(event, parent)

        for identity in identities:
            anchor_timestamp = (
                event.timestamp
                if event.event_type in _PROCESS_START_EVENT_TYPES and identity is subject
                else identity.started_at
            )
            not_before = None
            if identity is subject and parent_time is not None:
                not_before = parent_time + sample_timing_delta(
                    "source.ecar_dependent_after_process_create",
                    seed_parts=(
                        "parent-before-child",
                        parent.object_id,
                        identity.object_id,
                    ),
                )
            create_time = self._prime_ecar_process_create_time(
                event,
                identity,
                anchor_timestamp=anchor_timestamp,
                not_before=not_before,
            )
            self.record_source_time(
                event,
                "source.ecar_process_create",
                create_time,
                seed_parts=(identity.hostname, identity.pid, identity.started_at),
            )

    def _prime_ecar_process_create_time(
        self,
        event: SecurityEvent,
        identity: ProcessIdentity,
        *,
        anchor_timestamp: datetime | None = None,
        not_before: datetime | None = None,
    ) -> datetime:
        """Return and retain one source-visible eCAR create time per process object."""

        cached = self._ecar_process_create_times.get(identity.object_id)
        if cached is not None:
            if not_before is not None and cached < not_before:
                cached = not_before
                self._ecar_process_create_times[identity.object_id] = cached
            return cached
        anchor = replace(
            event,
            timestamp=anchor_timestamp or identity.started_at,
            source_timing=None,
        )
        create_time = self.source_time(
            anchor,
            "source.ecar_process_create",
            seed_parts=(identity.hostname, identity.pid, identity.started_at),
            not_before=max(identity.started_at, not_before)
            if not_before is not None
            else identity.started_at,
        )
        self._ecar_process_create_times[identity.object_id] = create_time
        return create_time

    def admission_time(self, event: SecurityEvent, format_name: str) -> datetime:
        """Return the finalized source-visible timestamp used for window admission."""

        if event.source_timing is not None:
            if format_name == "ecar":
                ecar_times = [
                    timestamp
                    for key, timestamp in event.source_timing.finalized_times.items()
                    if key.startswith("ecar.flow.") or key.startswith("ecar.session.")
                ]
                if ecar_times:
                    return max(ecar_times)
            if format_name in {"windows_security", "windows_event_security"}:
                windows_time = event.source_timing.finalized_times.get(
                    "windows.remote_authentication"
                ) or event.source_timing.finalized_times.get(_WINDOWS_WFP_RENDER_KEY)
                if windows_time is not None:
                    return windows_time
        if format_name == "proxy_access" and event.proxy is not None:
            transaction = event.proxy.transaction
            if transaction is not None:
                return transaction.request_at
        if format_name == "zeek_http" and event.http is not None:
            request_time = event.http.canonical_request_time
            if request_time is not None:
                observation = next(
                    (
                        candidate
                        for candidate in event.network_observations
                        if format_name in candidate.visible_formats
                    ),
                    None,
                )
                if observation is not None:
                    return observation.observed_start_time + (request_time - event.timestamp)
                return request_time
        if event.network_observations:
            observed = [
                observation.observed_start_time
                for observation in event.network_observations
                if format_name in observation.visible_formats
            ]
            if observed:
                return min(observed)
        return event.timestamp

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
        if not_before is not None and preferred_time < not_before:
            preferred_time = self._source_floor_repair_time(
                source_key,
                effective_seed,
                not_before,
            )
        constrained_time = self._apply_constraints(
            preferred_time,
            not_before=not_before,
            not_after=not_after,
            within=within,
        )
        plan.source_times[cache_key] = constrained_time
        return constrained_time

    def lifecycle_child_source_time(
        self,
        event: SecurityEvent,
        source_key: str,
        *,
        host_key: str,
        seed_parts: tuple[Any, ...] = (),
        within: tuple[datetime, datetime] | None = None,
    ) -> datetime | None:
        """Return a coherent host-local timestamp for one nested action child.

        Independent source-latency samples can invert sibling transports that are
        phases of one higher-level action (for example proxy ingress followed by
        proxy-origin egress). Nested children on the same host therefore share a
        small, deterministic observation offset from each child's canonical start.
        The offset stays source-owned and preserves the action bundle's phase gaps.
        """

        lifecycle = event.lifecycle
        if lifecycle is None or lifecycle.parent_group_id is None:
            return None
        network = event.network
        if network is None:
            return None

        parent_group_id = lifecycle.parent_group_id
        anchor = (
            network.transaction.started_at
            if network.transaction is not None
            else network.source_visible_start_time or event.timestamp
        )
        effective_seed = seed_parts or self._event_seed_parts(event)
        cache_seed = ("lifecycle-child", parent_group_id, host_key, *effective_seed)
        cache_key = self._cache_key(source_key, cache_seed)
        plan = self._ensure_plan(event)
        cached = plan.source_times.get(cache_key)
        if cached is not None:
            return cached

        group_seed = _stable_seed(
            f"lifecycle-child-source-time:{source_key}:{parent_group_id}:{host_key}"
        )
        observation_offset = timedelta(microseconds=250 + (group_seed % 751))
        preferred_time = anchor + observation_offset
        constrained_time = self._apply_constraints(
            preferred_time,
            not_before=None,
            not_after=None,
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
        scope = self._endpoint_clock_scope(event, source_key, seed_parts)
        if scope is None:
            return timedelta(0)
        host_key, os_category = scope
        return self.endpoint_clock_adjustment_for_host(
            hostname=host_key,
            os_category=os_category,
            timestamp=event.timestamp,
        )

    def endpoint_clock_adjustment_for_host(
        self,
        *,
        hostname: str,
        os_category: str,
        timestamp: datetime,
    ) -> timedelta:
        """Return the active profile's deterministic clock adjustment for one host."""

        if not hostname or os_category not in {"windows", "linux"}:
            return timedelta(0)
        timing = endpoint_clock_timing(self.clock_profile_name, os_category)
        offset_ms = self._bounded_int(
            "endpoint-clock-offset",
            timing.host_offset_min_ms,
            timing.host_offset_max_ms,
            (self.clock_profile_name, os_category, hostname),
        )
        drift_ppm = self._bounded_int(
            "endpoint-clock-drift",
            timing.host_drift_min_ppm,
            timing.host_drift_max_ppm,
            (self.clock_profile_name, os_category, hostname),
        )
        seconds_since_midnight = (
            timestamp.hour * 3600
            + timestamp.minute * 60
            + timestamp.second
            + timestamp.microsecond / 1_000_000
        )
        drift_us = round(seconds_since_midnight * drift_ppm)
        return timedelta(milliseconds=offset_ms, microseconds=drift_us)

    @staticmethod
    def _endpoint_clock_scope(
        event: SecurityEvent,
        source_key: str,
        seed_parts: tuple[Any, ...],
    ) -> tuple[str, str] | None:
        """Return ``(host, os_category)`` for endpoint sources, else ``None``."""
        if source_key.startswith(("source.zeek_", "network.")):
            return None
        if source_key.startswith(("source.windows_", "source.sysmon_")):
            host = event.src_host or event.dst_host
            hostname = getattr(host, "hostname", "") or ""
            return (hostname, "windows") if hostname else None
        if source_key.startswith("source.ecar_"):
            direction = str(seed_parts[0]).lower() if seed_parts else ""
            if source_key == "source.ecar_flow" and direction == "inbound":
                host = event.dst_host or event.src_host
            else:
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
    def _source_floor_repair_time(
        source_key: str,
        seed_parts: tuple[Any, ...],
        lower_bound: datetime,
    ) -> datetime:
        """Keep clamped process-create sources source-native after a shared floor."""
        if source_key not in _PROCESS_CREATE_SOURCE_KEYS:
            return lower_bound
        delay = sample_timing_delta(
            source_key,
            seed_parts=("floor-repair", source_key, *seed_parts),
        )
        return lower_bound + max(delay, _SOURCE_EPSILON)

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
