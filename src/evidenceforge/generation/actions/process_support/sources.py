# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Plan and remember process source timestamps on the current timing owner."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import ProcessContext
from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.generation.activity.helpers import _get_os_category
from evidenceforge.generation.activity.network_common import (
    _activity_timing_stable_id as _activity_timing_stable_id,
)
from evidenceforge.generation.source_timing import SourceTimingPlanner, SourceTimingPlanningRuntime
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.timing import TimingRuntime
from evidenceforge.models.scenario import System
from evidenceforge.utils.time import ensure_utc

from .capabilities import ProcessActivityTiming
from .policy import _PROCESS_SOURCE_BOUND_MAX_ANCESTORS, _session_source_ready_time
from .queries import ProcessStateQueries

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProcessSourceTiming:
    """Ephemeral operations; injected maps and managers remain on their existing owners."""

    _process_source_create_bounds: dict[tuple[str, int, datetime, str], datetime]
    _process_source_create_latest: dict[tuple[str, int], tuple[datetime | None, datetime]]
    _process_source_create_times: dict[tuple[str, int, datetime | None], datetime]
    _process_source_terminate_latest: dict[tuple[str, int], tuple[datetime | None, datetime]]
    _process_source_terminate_times: dict[tuple[str, int, datetime | None], datetime]
    _session_process_source_terminate_times: dict[tuple[str, str], datetime]
    _source_timing_planner: SourceTimingPlanner
    state_manager: StateManager
    queries: ProcessStateQueries
    activity_timing: ProcessActivityTiming

    def _clamp_after_visible_process_create(
        self,
        system: System,
        pid: int,
        time: datetime,
        relationship_key: str,
        *,
        timing_runtime: TimingRuntime | SourceTimingPlanningRuntime | None = None,
    ) -> datetime:
        """Keep fast same-process dependents after visible Windows process creation."""
        if pid <= 0 or _get_os_category(system.os) != "windows":
            return time
        visible_create_time = self.process_source_create_bound(system, pid)
        if visible_create_time is None or time > visible_create_time:
            return time
        return visible_create_time + self.activity_timing.sample_profile_gap(
            relationship_key,
            stable_id=_activity_timing_stable_id(
                "windows-visible-process-dependent",
                system.hostname,
                pid,
                visible_create_time,
                time,
            ),
            host=system.hostname,
            source="endpoint_process",
            lifecycle_id=str(pid),
            sample_key="visible_create_gap",
            timing_runtime=timing_runtime,
        )

    def _plan_process_source_create_times(
        self,
        event: OccurrenceBuilder,
        *,
        not_after: datetime | None = None,
    ) -> None:
        """Precompute source-create timestamps before threaded emitters render."""
        host = event.src_host
        proc = event.process
        if host is None or proc is None:
            return

        process_start_time = proc.start_time or event.timestamp
        session_ready_floor = self._process_session_source_ready_floor(host.hostname, proc)

        if host.os_category == "windows":
            sysmon_not_before = event.timestamp
            ecar_not_before = process_start_time
            if session_ready_floor is not None:
                sysmon_not_before = max(sysmon_not_before, session_ready_floor)
                ecar_not_before = max(ecar_not_before, session_ready_floor)
            if proc.parent_pid > 0:
                parent_visible_time = self.process_source_create_time(
                    host.hostname, proc.parent_pid
                )
                if parent_visible_time is not None:
                    sysmon_not_before = max(
                        sysmon_not_before,
                        parent_visible_time + timedelta(milliseconds=1),
                    )
            self._source_timing_planner.source_time(
                event,
                "source.sysmon_process_create",
                seed_parts=(host.hostname, proc.pid, process_start_time),
                not_before=sysmon_not_before,
                not_after=not_after,
            )
            self._source_timing_planner.source_time(
                event,
                "source.windows_security_process_create",
                seed_parts=(host.hostname, proc.pid, process_start_time),
                not_before=sysmon_not_before,
                not_after=not_after,
            )
            self._source_timing_planner.source_time(
                event,
                "source.ecar_process_create",
                seed_parts=(host.hostname, proc.pid, process_start_time),
                not_before=ecar_not_before,
                not_after=not_after,
            )
            return
        else:
            ecar_not_before = process_start_time

        self._source_timing_planner.source_time(
            event,
            "source.ecar_process_create",
            seed_parts=(host.hostname, proc.pid, process_start_time),
            not_before=ecar_not_before,
            not_after=not_after,
        )

    def _record_process_source_create_time(
        self,
        hostname: str,
        pid: int,
        event: OccurrenceBuilder,
        *,
        not_after: datetime | None = None,
        publish_finalized: bool = True,
    ) -> None:
        """Remember the latest rendered source timestamp for a process create."""
        if event.process is not None and event.auth is not None:
            self.state_manager.publish_process_auth_identity(
                hostname,
                pid,
                logon_id=event.auth.logon_id,
                session_id=event.auth.session_id,
                logon_type=event.auth.logon_type,
            )
        self._plan_process_source_create_times(event, not_after=not_after)
        if not publish_finalized:
            return
        start_time = event.process.start_time if event.process is not None else None
        if start_time is None:
            return
        self._remember_process_source_create_bound(hostname, pid, event)
        visible_create_time = self._source_timing_planner.admitted_process_create_frontier(
            hostname=hostname,
            pid=pid,
            started_at=start_time,
        )
        if visible_create_time is not None:
            self._process_source_create_times[(hostname, pid, start_time)] = visible_create_time
            latest = self._process_source_create_latest
            latest[(hostname, pid)] = (
                start_time,
                visible_create_time,
            )

    def _record_process_source_terminate_time(
        self,
        hostname: str,
        pid: int,
        event: OccurrenceBuilder,
    ) -> None:
        """Remember the rendered eCAR source timestamp for process termination."""
        self._plan_process_source_terminate_times(event)
        self._remember_process_source_terminate_time(hostname, pid, event)

    def _process_source_visible_by(
        self,
        *,
        system: System,
        pid: int,
        deadline: datetime | None,
    ) -> bool:
        """Return whether a process's format-independent source bound fits a deadline."""

        if deadline is None:
            return True
        source_time = self._process_source_frontier_or_bound(system=system, pid=pid)
        return source_time is not None and source_time <= ensure_utc(deadline)

    def process_source_create_bound(self, system: System, pid: int) -> datetime | None:
        """Return the conservative process-create frontier used by canonical planning."""

        return self._process_source_frontier_or_bound(system=system, pid=pid)

    def _process_source_frontier_or_bound(
        self,
        *,
        system: System,
        pid: int,
    ) -> datetime | None:
        """Return the frozen conservative bound for one exact process instance."""

        process = self.state_manager.get_process_identity(system.hostname, pid)
        if process is None:
            return None
        return self._process_identity_source_bound(
            os_category=_get_os_category(system.os),
            process=process,
        )

    def _process_identity_source_bound(
        self,
        *,
        os_category: str,
        process: ProcessIdentity,
    ) -> datetime | None:
        """Freeze one exact process bound through a bounded iterative ancestry walk."""

        cache = self._process_source_create_bounds
        process_key = (
            process.hostname,
            process.pid,
            process.started_at,
            process.object_id,
        )
        cached = cache.get(process_key)
        if cached is not None:
            return cached

        chain: list[ProcessIdentity] = []
        seen_object_ids: set[str] = set()
        cursor = process
        parent_source_time: datetime | None = None
        for _ in range(_PROCESS_SOURCE_BOUND_MAX_ANCESTORS):
            cursor_key = (
                cursor.hostname,
                cursor.pid,
                cursor.started_at,
                cursor.object_id,
            )
            cached = cache.get(cursor_key)
            if cached is not None:
                parent_source_time = cached
                break
            if cursor.object_id in seen_object_ids:
                return None
            seen_object_ids.add(cursor.object_id)
            chain.append(cursor)
            if cursor.parent_pid <= 0 or cursor.parent_pid == cursor.pid:
                break
            parent = self.state_manager.get_process_identity(
                cursor.hostname,
                cursor.parent_pid,
            )
            if parent is None or parent.started_at > cursor.started_at:
                break
            cursor = parent
        else:
            return None

        for identity in reversed(chain):
            session = (
                self.state_manager.get_session(identity.logon_id) if identity.logon_id else None
            )
            parent_source_time = self._process_create_source_bound_for_os(
                os_category=os_category,
                canonical_time=identity.started_at,
                parent_source_time=parent_source_time,
                session_source_time=(
                    _session_source_ready_time(session) if session is not None else None
                ),
            )
            cache[
                (
                    identity.hostname,
                    identity.pid,
                    identity.started_at,
                    identity.object_id,
                )
            ] = parent_source_time
        return parent_source_time

    def _process_create_source_bound_for_os(
        self,
        *,
        os_category: str,
        canonical_time: datetime,
        parent_source_time: datetime | None = None,
        session_source_time: datetime | None = None,
    ) -> datetime:
        """Return a process-create source bound for one canonical OS family."""

        canonical_time = ensure_utc(canonical_time)
        return canonical_time + self._source_timing_planner.process_create_positive_headroom(
            canonical_time,
            os_category,
            parent_source_time=parent_source_time,
            session_source_time=session_source_time,
        )

    def _remember_process_source_create_bound(
        self,
        hostname: str,
        pid: int,
        event: OccurrenceBuilder,
    ) -> None:
        """Freeze format-independent source timing for a finalized process create."""

        host = event.src_host
        process_context = event.process
        if (
            host is None
            or process_context is None
            or host.hostname != hostname
            or process_context.pid != pid
            or process_context.start_time is None
            or host.os_category not in {"windows", "linux"}
        ):
            return
        identity = self.state_manager.get_process_identity(hostname, pid)
        if identity is None or identity.started_at != ensure_utc(process_context.start_time):
            return
        self._process_identity_source_bound(
            os_category=host.os_category,
            process=identity,
        )

    def _process_create_source_bound(
        self,
        *,
        system: System,
        canonical_time: datetime,
        parent_source_time: datetime | None = None,
        session_source_time: datetime | None = None,
    ) -> datetime:
        """Return the conservative finalized source frontier for one process create."""

        return self._process_create_source_bound_for_os(
            os_category=_get_os_category(system.os),
            canonical_time=canonical_time,
            parent_source_time=parent_source_time,
            session_source_time=session_source_time,
        )

    def process_source_create_time(self, hostname: str, pid: int) -> datetime | None:
        """Return the latest rendered source-create timestamp for a process."""
        return self.queries._process_cached_time(
            self._process_source_create_times,
            getattr(self, "_process_source_create_latest", {}),
            hostname,
            pid,
        )

    def _process_session_source_ready_floor(
        self,
        hostname: str,
        proc: ProcessContext,
    ) -> datetime | None:
        """Return the session-visible floor for process-owned source evidence."""
        logon_id = str(getattr(proc, "logon_id", "") or "")
        if not logon_id or logon_id in {"0x3e7", "0x3e4", "0x3e5", "-"}:
            return None
        session = self.state_manager.get_session(logon_id)
        if session is None or session.system != hostname:
            return None
        ready_time = _session_source_ready_time(session)
        if ready_time is None:
            return None
        return ready_time + timedelta(milliseconds=1)

    def _plan_process_source_terminate_times(self, event: OccurrenceBuilder) -> None:
        """Precompute eCAR terminate timestamps for source-visible shell ordering."""
        host = event.src_host
        proc = event.process
        if host is None or proc is None or proc.start_time is None:
            return
        process_start = ensure_utc(proc.start_time)
        identity_lookup = getattr(
            getattr(self, "state_manager", None), "get_process_identity", None
        )
        identity = identity_lookup(host.hostname, proc.pid) if callable(identity_lookup) else None
        process_create_ts = (
            self._process_identity_source_bound(
                os_category=host.os_category,
                process=identity,
            )
            if identity is not None and identity.started_at == process_start
            else None
        )
        if process_create_ts is None:
            process_create_ts = self._process_create_source_bound_for_os(
                os_category=host.os_category,
                canonical_time=process_start,
            )
        canonical_lifetime = max(timedelta(milliseconds=100), event.timestamp - proc.start_time)
        self._source_timing_planner.source_time(
            event,
            "source.ecar_process_terminate",
            seed_parts=(
                host.hostname,
                proc.pid,
                proc.start_time,
                event.timestamp,
            ),
            not_before=max(event.timestamp, process_create_ts + canonical_lifetime),
        )

    def _remember_process_source_terminate_time(
        self,
        hostname: str,
        pid: int,
        event: OccurrenceBuilder,
    ) -> None:
        """Adopt already-planned source timing without advancing its canonical owner."""

        source_timing = event.source_timing
        if source_timing is None:
            return
        source_terminate_times = [
            timestamp
            for key, timestamp in source_timing.source_times.items()
            if key.startswith("source.ecar_process_terminate|")
        ]
        if source_terminate_times:
            visible_terminate_time = max(source_terminate_times)
            start_time = event.process.start_time if event.process is not None else None
            self._process_source_terminate_times[(hostname, pid, start_time)] = (
                visible_terminate_time
            )
            latest = self._process_source_terminate_latest
            latest[(hostname, pid)] = (
                start_time,
                visible_terminate_time,
            )
            logon_id = str(getattr(event.process, "logon_id", "") or "")
            if logon_id:
                key = (hostname, logon_id)
                previous = self._session_process_source_terminate_times.get(key)
                if previous is None or visible_terminate_time > previous:
                    self._session_process_source_terminate_times[key] = visible_terminate_time
