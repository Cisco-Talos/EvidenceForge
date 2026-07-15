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

"""RDP session action bundle.

The RDP bundle models a remote interactive Windows session above individual
SecurityEvents. It owns the source client, transport connection, target logon,
and source-visible ordering for a single RDP activity while using the current
activity generator as the runtime adapter for shared state and dispatch.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Protocol

from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.generation.actions.base import (
    ActionAnchor,
    endpoint_clock_difference,
    source_observation_delay_difference,
)
from evidenceforge.generation.activity.helpers import _get_os_category, _get_rng
from evidenceforge.generation.activity.timing_profiles import get_timing_window, sample_timing_delta
from evidenceforge.generation.source_timing import SourceTimingPlanner
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.timing import TemporalConstraintGraph
from evidenceforge.models.scenario import System, User
from evidenceforge.utils.rng import _stable_seed


@dataclass(frozen=True, slots=True)
class RdpSessionRequest:
    """Intent for one modeled RDP session action."""

    user: User
    target_system: System
    time: datetime
    source_ip: str
    source_system: System | None = None
    source_pid: int = -1
    source_port: int | None = None
    source_process_time: datetime | None = None
    logon_id: str = ""
    preserve_explicit_source: bool = False
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        source_host = self.source_system.hostname if self.source_system is not None else ""
        seed = _stable_seed(
            "action_bundle:rdp_session:"
            f"{self.user.username}:{source_host}:{self.source_ip}:{self.source_pid}:"
            f"{self.source_port or ''}:{self.preserve_explicit_source}:"
            f"{self.source_process_time.isoformat() if self.source_process_time else ''}:"
            f"{self.target_system.hostname}:{self.target_system.ip}:"
            f"{self.logon_id}:{self.source}:{self.time.isoformat()}"
        )
        return f"rdp-session-{seed:016x}"


class RdpSourceProcessFactory(Protocol):
    """Callable that materializes the source-side RDP client process."""

    def __call__(
        self,
        *,
        user: User,
        source_system: System,
        target_system: System,
        time: datetime,
    ) -> int:
        """Return the source-side mstsc.exe PID."""
        ...


class RdpSessionExecutor(Protocol):
    """Adapter protocol implemented by the current activity generator."""

    state_manager: StateManager
    dispatcher: EventDispatcher
    _source_timing_planner: SourceTimingPlanner
    _ip_to_system: dict[str, System]

    def _coerce_windows_rdp_user_from_existing_session(
        self,
        user: User,
        target_system: System,
        source_ip: str,
    ) -> User:
        """Return the Windows account that should own the RDP session."""
        ...

    def _allocate_ephemeral_port(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        proto: str,
        time: datetime,
        os_category: str,
    ) -> int:
        """Reserve a source port for the RDP transport."""
        ...

    def _os_for_ip(self, ip: str) -> str:
        """Return the OS category for a source IP."""
        ...

    def generate_connection(
        self,
        src_ip: str,
        dst_ip: str,
        time: datetime,
        **kwargs: Any,
    ) -> str:
        """Generate canonical network evidence."""
        ...

    def generate_logon(
        self,
        user: User,
        system: System,
        time: datetime,
        **kwargs: Any,
    ) -> str:
        """Generate canonical Windows logon evidence."""
        ...


class RdpSessionActionBundle:
    """Expand one RDP session intent into coordinated canonical evidence."""

    def __init__(
        self,
        executor: RdpSessionExecutor,
        request: RdpSessionRequest,
        *,
        source_process_factory: RdpSourceProcessFactory | None = None,
    ) -> None:
        self._executor = executor
        self._request = request
        self._source_process_factory = source_process_factory
        self._rendered_logon_id = ""

    @property
    def rendered_logon_id(self) -> str:
        """Return the target session LogonID after execution."""

        return self._rendered_logon_id

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="rdp_session",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> str:
        """Expand and dispatch RDP transport and target-logon evidence."""

        rng = _get_rng()
        user = self._executor._coerce_windows_rdp_user_from_existing_session(
            self._request.user,
            self._request.target_system,
            self._request.source_ip,
        )
        source_ip, source_system, source_pid = self._resolve_source(rng, user)
        duration = rng.uniform(60.0, 3600.0)
        source_pid = self._materialize_source_process(
            user=user,
            source_system=source_system,
            source_pid=source_pid,
        )
        src_port = self._request.source_port
        if src_port is None:
            src_port = self._executor._allocate_ephemeral_port(
                source_ip,
                self._request.target_system.ip,
                3389,
                "tcp",
                self._request.time,
                self._executor._os_for_ip(source_ip),
            )

        uid = self._executor.generate_connection(
            src_ip=source_ip,
            dst_ip=self._request.target_system.ip,
            time=self._request.time,
            dst_port=3389,
            proto="tcp",
            service="rdp",
            duration=duration,
            orig_bytes=rng.randint(50000, 500000),
            resp_bytes=rng.randint(100000, 2000000),
            src_port=src_port,
            emit_dns=True,
            source_system=source_system,
            pid=source_pid,
            conn_state="SF",
        )
        network_start_time, network_close_time = self._transport_interval(
            uid,
            fallback_start=self._request.time,
            fallback_close=self._request.time + timedelta(seconds=duration),
        )
        self._protect_source_client_lifecycle(
            source_system=source_system,
            source_pid=source_pid,
            network_close_time=network_close_time,
        )

        logon_time = self._target_logon_time(
            rng=rng,
            source_ip=source_ip,
            src_port=src_port,
            transport_start_time=network_start_time,
            source_system=source_system,
        )
        logon_id = self._request.logon_id
        if logon_id:
            reassigned_logon_id = self._executor.state_manager.reassign_session_logon_id(
                logon_id,
                logon_time,
            )
            if reassigned_logon_id is not None:
                logon_id = reassigned_logon_id
            self._executor.state_manager.update_session_metadata(
                logon_id,
                username=user.username,
                start_time=logon_time,
                source_ip=source_ip,
                source_port=src_port,
                session_kind="rdp",
                transport_pid=source_pid if source_pid > 0 else None,
                network_close_time=network_close_time,
                source_ready_time=logon_time,
            )
        rendered_logon_id = self._executor.generate_logon(
            user=user,
            system=self._request.target_system,
            time=logon_time,
            logon_type=10,
            source_ip=source_ip,
            source_system=source_system,
            source_port=src_port,
            emit_network_evidence=False,
            logon_id=logon_id or None,
            lifecycle_group_id=self._request.stable_id,
        )
        self._rendered_logon_id = rendered_logon_id
        self._executor.state_manager.update_session_metadata(
            rendered_logon_id,
            username=user.username,
            start_time=logon_time,
            source_ip=source_ip,
            source_port=src_port,
            session_kind="rdp",
            transport_pid=source_pid if source_pid > 0 else None,
            network_close_time=network_close_time,
            source_ready_time=logon_time,
        )

        return uid

    def _resolve_source(self, rng: random.Random, user: User) -> tuple[str, System | None, int]:
        """Resolve the remote source host, avoiding impossible self-sourced RDP."""

        source_ip = self._request.source_ip
        source_system = self._request.source_system
        source_pid = self._request.source_pid
        if source_system is None:
            source_system = self._executor._ip_to_system.get(source_ip)
        if (
            source_system is not None
            and _get_os_category(source_system.os) != "windows"
            and _get_os_category(self._request.target_system.os) == "windows"
            and not self._request.preserve_explicit_source
        ):
            replacement = self._choose_windows_source(rng, user)
            if replacement is not None:
                return replacement.ip, replacement, -1
            return source_ip, None, -1
        if source_ip != self._request.target_system.ip:
            return source_ip, source_system, source_pid

        replacement = self._choose_windows_source(rng, user)
        if replacement is not None:
            return replacement.ip, replacement, -1
        return source_ip, None, -1

    def _choose_windows_source(self, rng: random.Random, user: User) -> System | None:
        """Choose a modeled Windows RDP client host when the request source is unusable."""

        candidates = sorted(
            {
                candidate.hostname: candidate
                for candidate in getattr(self._executor, "_ip_to_system", {}).values()
                if candidate.ip != self._request.target_system.ip
                and _get_os_category(candidate.os) == "windows"
            }.values(),
            key=lambda candidate: candidate.hostname,
        )
        workstations = [
            candidate
            for candidate in candidates
            if (candidate.type or "workstation").lower() == "workstation"
        ]
        preferred = [
            candidate
            for candidate in workstations or candidates
            if candidate.assigned_user == user.username
        ]
        return rng.choice(preferred or workstations or candidates) if candidates else None

    def _materialize_source_process(
        self,
        *,
        user: User,
        source_system: System | None,
        source_pid: int,
    ) -> int:
        """Ensure source-side mstsc.exe exists when the caller provides a factory."""

        if (
            source_pid > 0
            or source_system is None
            or self._request.source_process_time is None
            or self._source_process_factory is None
        ):
            return source_pid
        return self._source_process_factory(
            user=user,
            source_system=source_system,
            target_system=self._request.target_system,
            time=self._request.source_process_time,
        )

    def _transport_interval(
        self,
        uid: str,
        *,
        fallback_start: datetime,
        fallback_close: datetime,
    ) -> tuple[datetime, datetime]:
        """Return the canonical network interval for the generated RDP transport."""

        if not uid:
            return fallback_start, fallback_close
        connection = next(
            (
                conn
                for conn in self._executor.state_manager.list_open_connections()
                if conn.zeek_uid == uid
            ),
            None,
        )
        if connection is None or connection.close_time is None:
            return fallback_start, fallback_close
        return connection.start_time, connection.close_time

    def _protect_source_client_lifecycle(
        self,
        *,
        source_system: System | None,
        source_pid: int,
        network_close_time: datetime,
    ) -> None:
        """Keep the source-side mstsc process/session alive through the transport close."""

        if source_system is None or source_pid <= 0:
            return
        seed = _stable_seed(
            "rdp_source_client_close:"
            f"{source_system.hostname}:{source_pid}:{self._request.target_system.hostname}:"
            f"{network_close_time.isoformat()}"
        )
        activity_time = network_close_time + timedelta(
            milliseconds=250 + (seed % 1750),
            microseconds=97 + (seed % 719),
        )
        state_manager = self._executor.state_manager
        state_manager.update_process_activity_time(
            source_system.hostname, source_pid, activity_time
        )
        process = state_manager.get_process(source_system.hostname, source_pid)
        if process is not None and process.logon_id:
            state_manager.update_session_activity_time(process.logon_id, activity_time)

    def _target_logon_time(
        self,
        *,
        rng: random.Random,
        source_ip: str,
        src_port: int,
        transport_start_time: datetime | None = None,
        source_system: System | None = None,
    ) -> datetime:
        """Resolve target 4624 timing after source-visible network evidence."""

        observed_connection_time = transport_start_time
        if observed_connection_time is None:
            observed_connection_time = self._request.time + sample_timing_delta(
                "network.connection_start_jitter",
                seed_parts=(
                    source_ip,
                    src_port,
                    self._request.target_system.ip,
                    3389,
                    "tcp",
                    "rdp",
                    self._request.time,
                ),
            )
        graph = TemporalConstraintGraph()
        graph.add_node(
            "transport_observed",
            observed_connection_time,
            not_before=self._request.time,
        )
        graph.add_node(
            "target_logon",
            observed_connection_time
            + timedelta(milliseconds=self._target_logon_gap_after_transport(rng)),
        )
        graph.constrain_after(
            "target_logon",
            "transport_observed",
            min_gap=timedelta(
                milliseconds=self._endpoint_flow_visible_gap_ms(
                    source_system=source_system,
                    timestamp=observed_connection_time,
                )
                + 25
            ),
        )
        return graph.resolved_time("target_logon")

    def _endpoint_flow_visible_gap_ms(
        self,
        *,
        source_system: System | None = None,
        timestamp: datetime | None = None,
    ) -> int:
        """Return the latest expected same-tuple endpoint FLOW observation delay."""
        flow_window = get_timing_window(
            "source.ecar_flow",
            default_min_ms=40,
            default_max_ms=300,
            default_position="after",
            default_class="source_latency",
        )
        observation_delay = source_observation_delay_difference(
            self._executor,
            earlier_source="ecar",
            later_source="windows_security",
        )
        clock_delay = timedelta(0)
        if source_system is not None and timestamp is not None:
            clock_delay = endpoint_clock_difference(
                self._executor,
                earlier_host=source_system.hostname,
                earlier_os="windows",
                later_host=self._request.target_system.hostname,
                later_os="windows",
                timestamp=timestamp,
            )
        return flow_window.max_ms + math.ceil(
            (observation_delay + clock_delay).total_seconds() * 1000
        )

    def _target_logon_gap_after_transport(self, rng: random.Random) -> int:
        """Choose an RDP target logon gap after endpoint transport visibility."""
        return max(
            rng.randint(900, 1600),
            self._endpoint_flow_visible_gap_ms() + rng.randint(75, 260),
        )
