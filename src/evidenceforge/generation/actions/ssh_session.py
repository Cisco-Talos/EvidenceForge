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

"""SSH session action bundle.

The SSH bundle sits above individual SecurityEvents. It owns the ordered SSH
activity lifecycle and uses the current activity generator as a runtime adapter
for shared state, host context construction, source timing, and dispatch.
"""

from __future__ import annotations

import logging
import math
import random
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Protocol

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import (
    AuthContext,
    EdrContext,
    HostContext,
    ProcessContext,
    SyslogContext,
)
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.activity.helpers import _get_os_category, _get_rng
from evidenceforge.generation.activity.timing_profiles import (
    get_timing_window,
    sample_timing_delta,
)
from evidenceforge.generation.source_timing import SourceTimingPlanner
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.timing import TemporalConstraintGraph
from evidenceforge.models.scenario import System, User
from evidenceforge.utils.rng import _stable_seed, stable_uuid
from evidenceforge.utils.time import ensure_utc

logger = logging.getLogger(__name__)


_SSH_SYSLOG_MICRO_JITTER_BANDS = {
    "connection": 101,
    "accepted": 301,
    "pam": 501,
    "logind": 701,
    "closed": 901,
}


def _ssh_syslog_time(
    base_time: datetime,
    label: str,
    milliseconds: int,
    *seed_parts: Any,
    before: bool = False,
) -> datetime:
    """Return an SSH syslog lifecycle timestamp with non-repeating sub-ms texture."""
    band_start = _SSH_SYSLOG_MICRO_JITTER_BANDS.get(label, 101)
    seed = _stable_seed(
        "ssh_syslog_micro_jitter:" + label + ":" + ":".join(str(part) for part in seed_parts)
    )
    delta = timedelta(milliseconds=milliseconds, microseconds=band_start + (seed % 89))
    return base_time - delta if before else base_time + delta


def _linux_uid_for_user(username: str) -> int:
    """Return a stable plausible Linux UID for a login username."""
    if username == "root":
        return 0
    well_known = {
        "ubuntu": 1000,
        "ec2-user": 1000,
        "admin": 1001,
        "ansible": 998,
        "deploy": 1002,
    }
    if username in well_known:
        return well_known[username]
    return 2000 + (_stable_seed(f"linux_uid_{username}") % 5000)


@dataclass(frozen=True, slots=True)
class SshSessionRequest:
    """Intent for one modeled SSH session action."""

    user: User
    target_system: System
    time: datetime
    source_ip: str
    source_system: System | None = None
    source_port: int | None = None
    source_pid: int = -1
    source_process_image: str = ""
    sshd_pid: int | None = None
    logon_id: str = ""
    session_obj_id: str = ""
    min_duration: float | None = None
    duration: float | None = None
    orig_bytes: int | None = None
    resp_bytes: int | None = None
    auth_method: str = "password"
    public_key_type: str = ""
    public_key_hash: str = ""
    emit_session_close: bool = False
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        source_host = self.source_system.hostname if self.source_system is not None else ""
        seed = _stable_seed(
            "action_bundle:ssh_session:"
            f"{self.user.username}:{source_host}:{self.source_ip}:"
            f"{self.source_port or ''}:{self.target_system.hostname}:"
            f"{self.target_system.ip}:{self.source_pid}:{self.source_process_image}:"
            f"{self.sshd_pid or ''}:{self.logon_id}:{self.session_obj_id}:"
            f"{self.min_duration or ''}:{self.duration or ''}:"
            f"{self.orig_bytes or ''}:{self.resp_bytes or ''}:"
            f"{self.auth_method}:{self.public_key_type}:{self.public_key_hash}:"
            f"{self.emit_session_close}:{self.source}:{self.time.isoformat()}"
        )
        return f"ssh-session-{seed:016x}"

    def execution_stable_id(self, source_port: int) -> str:
        """Return a deterministic execution identifier after source-port reservation."""

        source_host = self.source_system.hostname if self.source_system is not None else ""
        seed = _stable_seed(
            "action_bundle:ssh_session:execution:"
            f"{self.user.username}:{source_host}:{self.source_ip}:{source_port}:"
            f"{self.target_system.hostname}:{self.target_system.ip}:"
            f"{self.source_pid}:{self.source_process_image}:{self.sshd_pid or ''}:"
            f"{self.logon_id}:{self.session_obj_id}:{self.min_duration or ''}:"
            f"{self.duration or ''}:{self.orig_bytes or ''}:{self.resp_bytes or ''}:"
            f"{self.auth_method}:{self.public_key_type}:{self.public_key_hash}:"
            f"{self.emit_session_close}:{self.source}:{self.time.isoformat()}"
        )
        return f"ssh-session-exec-{seed:016x}"


@dataclass(slots=True)
class _SshTransportState:
    """Mutable state accumulated across SSH bundle lifecycle phases."""

    rng: random.Random
    source_port: int
    duration: float
    close_time: datetime
    orig_bytes: int
    resp_bytes: int
    network_visible: bool
    dst_host: HostContext
    session_obj_id: str
    src_host: HostContext | None = None
    conn_id: str = ""
    uid: str = ""
    source_process: ProcessContext | None = None
    history: str = ""
    orig_pkts: int = 0
    resp_pkts: int = 0
    orig_ip_bytes: int = 0
    resp_ip_bytes: int = 0
    open_time: datetime | None = None
    execution_anchor: ActionAnchor | None = None


@dataclass(frozen=True, slots=True)
class _SshLinuxAuthState:
    """Source-native Linux SSH authentication lifecycle timestamps."""

    sshd_pid: int
    logind_session_id: int
    syslog_seed: tuple[Any, ...]
    connection_time: datetime
    accepted_time: datetime
    pam_time: datetime
    logind_time: datetime


@dataclass(frozen=True, slots=True)
class _SshLinuxAuthPlan:
    """Linux SSH auth ownership that must be known before transport opens."""

    sshd_pid: int
    conn_delay_ms: int
    accepted_gap_ms: int
    pam_gap_ms: int
    logind_gap_ms: int
    syslog_seed: tuple[Any, ...]


class SshSessionExecutor(Protocol):
    """Adapter protocol implemented by the current activity generator."""

    state_manager: StateManager
    dispatcher: EventDispatcher
    _ip_to_system: dict[str, System]
    _network_visibility: Any
    _source_timing_planner: SourceTimingPlanner

    def _build_host_context(self, system: System) -> HostContext:
        """Build canonical host context for a scenario system."""
        ...

    def _emit_dns_lookup(
        self,
        src_ip: str,
        dst_ip: str,
        time: datetime,
        *,
        force_address: bool = False,
    ) -> None:
        """Emit a DNS lookup for correlated activity."""
        ...

    def generate_connection(self, **kwargs: Any) -> str:
        """Generate one canonical network connection through the shared connection bundle."""
        ...

    def reserve_ssh_source_port(
        self,
        source_ip: str,
        target_ip: str,
        source_port: int | None,
        rng: random.Random,
        source_os: str,
        time: datetime | None = None,
    ) -> int:
        """Reserve a source port for an SSH 5-tuple."""
        ...

    def ssh_responder_pid_for_tuple(
        self,
        source_ip: str,
        source_port: int,
        target_ip: str,
    ) -> int | None:
        """Return a remembered responder-side sshd PID for a tuple."""
        ...

    def ensure_linux_ssh_responder_process(
        self,
        *,
        target_system: System,
        time: datetime,
        source_ip: str,
        source_port: int,
        target_user: str | None = None,
    ) -> int:
        """Return or materialize the destination-side sshd process."""
        ...

    def ensure_linux_ssh_client_process(
        self,
        *,
        user: User,
        source_system: System,
        target_system: System,
        time: datetime,
        process_image: str,
        source_port: int,
    ) -> tuple[int, str] | None:
        """Return or materialize the source-side SSH client process."""
        ...

    def _remember_ssh_responder_pid(
        self,
        source_ip: str,
        source_port: int,
        target_ip: str,
        pid: int,
    ) -> None:
        """Remember the destination-side sshd PID for a tuple."""
        ...

    def _get_system_pid(self, hostname: str, role: str, fallback: int) -> int:
        """Return a stable system process PID."""
        ...

    def _remember_ssh_session_ready_time(
        self,
        source_ip: str,
        source_port: int,
        target_ip: str,
        ready_time: datetime,
    ) -> None:
        """Remember when tuple-scoped receiver-side SSH child evidence may appear."""
        ...

    def generate_process_termination(
        self,
        user: User,
        system: System,
        time: datetime,
        pid: int,
        process_name: str,
        logon_id: str,
        from_storyline: bool = False,
    ) -> None:
        """Generate source-native process termination evidence."""
        ...


@dataclass(frozen=True, slots=True)
class SshSessionActionBundle:
    """Action bundle for a single SSH session lifecycle."""

    request: SshSessionRequest
    executor: SshSessionExecutor

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor for this SSH session."""

        return ActionAnchor(
            family="ssh_session",
            stable_id=self.request.stable_id,
            source=self.request.source,
        )

    def execute(self) -> str:
        """Expand and dispatch SSH session evidence through the generator runtime."""

        state = self._plan_transport()
        auth_plan = self._prepare_linux_auth_plan(state)
        self._open_transport(
            state,
            responding_pid=auth_plan.sshd_pid if auth_plan is not None else self.request.sshd_pid,
        )
        planning_event = self._build_session_event(state)
        auth_state = self._plan_linux_auth(state, planning_event, auth_plan)
        event = self._build_session_event(state, auth_state)
        if auth_state is not None:
            self._dispatch_linux_connection_message(state, event, auth_state)
            self._mark_edr_login_readiness(state, event, auth_state)
        self.executor.dispatcher.dispatch(event)
        if auth_state is not None:
            self._dispatch_linux_auth_messages(state, event, auth_state)
            if self.request.emit_session_close:
                self._dispatch_linux_session_close_lifecycle(state, event, auth_state)

        logger.debug(
            "Generated SSH session: %s -> %s (UID: %s)",
            self.request.user.username,
            self.request.target_system.hostname,
            state.uid,
        )
        return state.uid if state.network_visible else ""

    def _source_os(self) -> str:
        """Return the source OS category used for source-port reservation."""

        request = self.request
        if request.source_system is not None:
            return _get_os_category(request.source_system.os)
        if request.source_ip in self.executor._ip_to_system:
            return _get_os_category(self.executor._ip_to_system[request.source_ip].os)
        return "windows"

    def _source_host_context(self) -> HostContext | None:
        """Resolve the canonical source host context if the source belongs to the scenario."""

        request = self.request
        if request.source_system is not None:
            return self.executor._build_host_context(request.source_system)
        if request.source_ip in self.executor._ip_to_system:
            return self.executor._build_host_context(self.executor._ip_to_system[request.source_ip])
        return None

    def _source_system(self) -> System | None:
        """Resolve the modeled source system for endpoint process ownership."""

        request = self.request
        if request.source_system is not None:
            return request.source_system
        return self.executor._ip_to_system.get(request.source_ip)

    def _is_network_visible(self) -> bool:
        """Return whether network sensors should reveal this SSH transport."""

        request = self.request
        visibility = self.executor._network_visibility or (
            self.executor.dispatcher.visibility_engine if self.executor.dispatcher else None
        )
        return (
            True
            if visibility is None
            else visibility.is_connection_visible(request.source_ip, request.target_system.ip)
        )

    def _plan_transport(self) -> _SshTransportState:
        """Plan transport-level identity, byte counts, and host contexts."""

        request = self.request
        rng = _get_rng()
        src_port = self.executor.reserve_ssh_source_port(
            request.source_ip,
            request.target_system.ip,
            request.source_port,
            rng,
            self._source_os(),
            time=request.time,
        )
        if request.duration is not None:
            duration = max(1.0, request.duration)
        else:
            duration = rng.uniform(30.0, 3600.0)
        if request.min_duration is not None and request.duration is None:
            duration = max(duration, request.min_duration)
        orig_bytes = (
            request.orig_bytes if request.orig_bytes is not None else rng.randint(2000, 50000)
        )
        resp_bytes = (
            request.resp_bytes if request.resp_bytes is not None else rng.randint(5000, 200000)
        )
        return _SshTransportState(
            rng=rng,
            source_port=src_port,
            duration=duration,
            close_time=request.time + timedelta(seconds=duration),
            orig_bytes=max(0, orig_bytes),
            resp_bytes=max(0, resp_bytes),
            network_visible=self._is_network_visible(),
            dst_host=self.executor._build_host_context(request.target_system),
            session_obj_id=request.session_obj_id,
            src_host=self._source_host_context(),
            open_time=request.time,
            execution_anchor=ActionAnchor(
                family="ssh_session",
                stable_id=request.execution_stable_id(src_port),
                source=request.source,
            ),
        )

    def _open_transport(self, state: _SshTransportState, responding_pid: int | None) -> None:
        """Delegate SSH TCP transport to the canonical network connection contract."""

        request = self.request
        executor = self.executor

        source_system = self._source_system()
        source_pid = request.source_pid
        source_process_image = request.source_process_image
        if (
            source_pid <= 0
            and source_system is not None
            and _get_os_category(source_system.os) == "linux"
        ):
            client = executor.ensure_linux_ssh_client_process(
                user=request.user,
                source_system=source_system,
                target_system=request.target_system,
                time=request.time,
                process_image=source_process_image or "/usr/bin/ssh",
                source_port=state.source_port,
            )
            if client is not None:
                source_pid, source_process_image = client

        state.source_process = self._resolve_source_process(source_pid, source_process_image)
        network_uid = executor.generate_connection(
            src_ip=request.source_ip,
            dst_ip=request.target_system.ip,
            time=request.time,
            dst_port=22,
            proto="tcp",
            service="ssh",
            duration=state.duration,
            orig_bytes=state.orig_bytes,
            resp_bytes=state.resp_bytes,
            src_port=state.source_port,
            emit_dns=True,
            pid=source_pid,
            source_system=source_system,
            conn_state="SF",
            hostname=state.dst_host.fqdn or request.target_system.hostname,
            process_image=source_process_image,
            preserve_dst_ip=True,
            responding_pid=responding_pid or -1,
        )
        state.uid = network_uid
        state.network_visible = bool(network_uid)
        if network_uid:
            self._sync_transport_from_connection_state(state, network_uid)

        if request.logon_id:
            executor.state_manager.update_session_metadata(
                request.logon_id,
                source_port=state.source_port,
                session_kind="ssh",
                transport_pid=responding_pid,
                network_close_time=state.close_time,
            )
            if not state.session_obj_id:
                state.session_obj_id = executor.state_manager.get_session_object_id(
                    request.logon_id
                )
        if not state.session_obj_id:
            state.session_obj_id = self._stable_session_object_id(state)

    def _stable_session_object_id(self, state: _SshTransportState) -> str:
        """Return a tuple-stable session object ID for unmanaged SSH sessions."""

        request = self.request
        return stable_uuid(
            "ssh-session-object",
            request.target_system.hostname,
            request.user.username,
            request.source_ip,
            state.source_port,
            request.time.isoformat(),
            request.source,
        )

    def _sync_transport_from_connection_state(
        self,
        state: _SshTransportState,
        network_uid: str,
    ) -> None:
        """Copy canonical network ownership details back into the SSH lifecycle state."""

        connection = next(
            (
                conn
                for conn in self.executor.state_manager.list_open_connections()
                if conn.zeek_uid == network_uid
            ),
            None,
        )
        if connection is None:
            return
        state.conn_id = connection.conn_id
        state.open_time = connection.start_time
        state.orig_bytes = connection.bytes_sent
        state.resp_bytes = connection.bytes_received
        if connection.close_time is not None:
            state.close_time = connection.close_time
            state.duration = max(
                1.0,
                (state.close_time - self.request.time).total_seconds(),
            )

    def _resolve_source_process(
        self,
        source_pid: int,
        source_process_image: str,
    ) -> ProcessContext | None:
        """Return source process context when the caller supplied one."""

        source_system = self._source_system()
        if source_system is not None and source_pid > 0:
            running = self.executor.state_manager.get_process(
                source_system.hostname,
                source_pid,
            )
            if running is not None:
                return ProcessContext(
                    pid=source_pid,
                    parent_pid=running.parent_pid,
                    image=running.image,
                    command_line=running.command_line,
                    username=running.username,
                    logon_id=running.logon_id,
                    start_time=running.start_time,
                )
            if source_process_image:
                return ProcessContext(
                    pid=source_pid,
                    parent_pid=0,
                    image=source_process_image,
                    command_line="",
                    username="",
                )
        return None

    def _build_session_event(
        self,
        state: _SshTransportState,
        auth_state: _SshLinuxAuthState | None = None,
    ) -> SecurityEvent:
        """Build the canonical SSH session occurrence.

        The TCP transport is a separate canonical ``connection`` occurrence owned by
        the network-connection bundle. The SSH session event carries only the
        authentication/session facts needed by endpoint session renderers.
        """

        request = self.request
        return SecurityEvent(
            timestamp=request.time,
            event_type="ssh_session",
            src_host=state.src_host,
            dst_host=state.dst_host,
            auth=AuthContext(
                username=request.user.username,
                source_ip=request.source_ip,
                source_port=state.source_port,
                logon_id=request.logon_id,
                session_id=auth_state.logind_session_id if auth_state is not None else 0,
                logon_type=10,
            ),
            process=state.source_process,
            edr=EdrContext(object_id=state.session_obj_id),
        )

    def _plan_linux_auth(
        self,
        state: _SshTransportState,
        event: SecurityEvent,
        plan: _SshLinuxAuthPlan | None,
    ) -> _SshLinuxAuthState | None:
        """Plan Linux SSH auth evidence and destination-side sshd ownership."""

        request = self.request
        executor = self.executor
        if plan is None or not event.dst_host or event.dst_host.os_category != "linux":
            return None

        if request.logon_id:
            executor.state_manager.update_session_metadata(
                request.logon_id,
                transport_pid=plan.sshd_pid,
            )
        resolved_times = self._resolve_linux_auth_lifecycle(
            event=event,
            syslog_seed=plan.syslog_seed,
            conn_delay_ms=plan.conn_delay_ms,
            accepted_gap_ms=plan.accepted_gap_ms,
            pam_gap_ms=plan.pam_gap_ms,
            logind_gap_ms=plan.logind_gap_ms,
            transport_open_time=state.open_time or request.time,
        )
        if request.emit_session_close:
            self._extend_transport_close_after(
                state,
                event,
                resolved_times["logind"] + timedelta(milliseconds=1),
            )
        logind_session_id = executor.state_manager.next_linux_logind_session_id(
            request.target_system.hostname,
            state.rng,
            resolved_times["logind"],
        )
        return _SshLinuxAuthState(
            sshd_pid=plan.sshd_pid,
            logind_session_id=logind_session_id,
            syslog_seed=plan.syslog_seed,
            connection_time=resolved_times["connection"],
            accepted_time=resolved_times["accepted"],
            pam_time=resolved_times["pam"],
            logind_time=resolved_times["logind"],
        )

    def _prepare_linux_auth_plan(self, state: _SshTransportState) -> _SshLinuxAuthPlan | None:
        """Resolve Linux SSH responder identity before opening canonical transport."""

        request = self.request
        if state.dst_host.os_category != "linux":
            return None

        conn_delay_ms = state.rng.randint(35, 160)
        if request.auth_method == "publickey":
            accepted_gap_ms = state.rng.randint(90, 550)
        else:
            accepted_gap_ms = state.rng.randint(450, 3500)
        pam_gap_ms = state.rng.randint(45, 180)
        logind_gap_ms = state.rng.randint(420, 760)
        sshd_pid = self._resolve_responder_pid(state, conn_delay_ms)
        return _SshLinuxAuthPlan(
            sshd_pid=sshd_pid,
            conn_delay_ms=conn_delay_ms,
            accepted_gap_ms=accepted_gap_ms,
            pam_gap_ms=pam_gap_ms,
            logind_gap_ms=logind_gap_ms,
            syslog_seed=(
                request.target_system.hostname,
                request.source_ip,
                state.source_port,
                sshd_pid,
                request.time.isoformat(),
            ),
        )

    def _resolve_linux_auth_lifecycle(
        self,
        *,
        event: SecurityEvent,
        syslog_seed: tuple[Any, ...],
        conn_delay_ms: int,
        accepted_gap_ms: int,
        pam_gap_ms: int,
        logind_gap_ms: int,
        transport_open_time: datetime,
    ) -> dict[str, datetime]:
        """Resolve SSH auth/syslog lifecycle times through the temporal graph."""

        request = self.request
        flow_window = get_timing_window(
            "source.ecar_flow",
            default_min_ms=40,
            default_max_ms=300,
            default_position="after",
            default_class="source_latency",
        )
        canonical_event_time = ensure_utc(event.timestamp)
        canonical_transport_open_time = ensure_utc(transport_open_time)
        canonical_offset_ms = max(
            0,
            math.ceil(
                (canonical_event_time - canonical_transport_open_time).total_seconds() * 1000
            ),
        )
        transport_to_syslog_ms = max(
            conn_delay_ms,
            canonical_offset_ms + flow_window.max_ms + 25,
        )
        graph = TemporalConstraintGraph()
        graph.add_node("transport_open", transport_open_time)
        graph.add_node(
            "connection",
            _ssh_syslog_time(
                transport_open_time,
                "connection",
                transport_to_syslog_ms,
                *syslog_seed,
            ),
        )
        graph.add_node(
            "accepted",
            _ssh_syslog_time(
                transport_open_time,
                "accepted",
                transport_to_syslog_ms + accepted_gap_ms,
                *syslog_seed,
            ),
        )
        graph.add_node(
            "pam",
            _ssh_syslog_time(
                transport_open_time,
                "pam",
                transport_to_syslog_ms + accepted_gap_ms + pam_gap_ms,
                *syslog_seed,
            ),
        )
        graph.add_node(
            "logind",
            _ssh_syslog_time(
                transport_open_time,
                "logind",
                transport_to_syslog_ms + accepted_gap_ms + pam_gap_ms + logind_gap_ms,
                *syslog_seed,
            ),
        )
        graph.constrain_after(
            "connection",
            "transport_open",
            min_gap=timedelta(milliseconds=transport_to_syslog_ms),
        )
        graph.constrain_after(
            "accepted",
            "connection",
            min_gap=timedelta(milliseconds=max(1, accepted_gap_ms)),
        )
        graph.constrain_after("pam", "accepted", min_gap=timedelta(milliseconds=pam_gap_ms))
        graph.constrain_after(
            "logind",
            "pam",
            min_gap=timedelta(milliseconds=logind_gap_ms),
        )
        resolved = graph.resolve()
        logger.debug(
            "Planned SSH auth graph for %s -> %s: connection=%s accepted=%s pam=%s logind=%s",
            request.source_ip,
            event.dst_host.hostname if event.dst_host else request.target_system.hostname,
            resolved["connection"],
            resolved["accepted"],
            resolved["pam"],
            resolved["logind"],
        )
        return resolved

    def _extend_transport_close_after(
        self,
        state: _SshTransportState,
        event: SecurityEvent,
        earliest_close_time: datetime,
    ) -> None:
        """Extend too-short SSH transport lifetimes to satisfy lifecycle ordering."""

        request = self.request
        if state.close_time >= earliest_close_time:
            return

        state.close_time = earliest_close_time
        state.duration = max(1.0, (state.close_time - request.time).total_seconds())

        if request.logon_id:
            self.executor.state_manager.update_session_metadata(
                request.logon_id,
                network_close_time=state.close_time,
            )

        if state.conn_id:
            connection = self.executor.state_manager.get_connection(state.conn_id)
            if connection is not None:
                connection.close_time = state.close_time

    def _resolve_responder_pid(self, state: _SshTransportState, conn_delay_ms: int) -> int:
        """Resolve or materialize the destination-side sshd process for this tuple."""

        request = self.request
        executor = self.executor
        remembered_sshd_pid = executor.ssh_responder_pid_for_tuple(
            request.source_ip,
            state.source_port,
            request.target_system.ip,
        )
        sshd_pid = request.sshd_pid
        if sshd_pid is None and remembered_sshd_pid is not None:
            sshd_pid = remembered_sshd_pid
        if (
            sshd_pid is None
            or executor.state_manager.get_process(
                request.target_system.hostname,
                sshd_pid,
            )
            is None
        ):
            return executor.ensure_linux_ssh_responder_process(
                target_system=request.target_system,
                time=(state.open_time or request.time)
                + timedelta(milliseconds=max(5, conn_delay_ms - 15)),
                source_ip=request.source_ip,
                source_port=state.source_port,
                target_user=request.user.username,
            )
        executor._remember_ssh_responder_pid(
            request.source_ip,
            state.source_port,
            request.target_system.ip,
            sshd_pid,
        )
        return sshd_pid

    def _dispatch_linux_connection_message(
        self,
        state: _SshTransportState,
        event: SecurityEvent,
        auth_state: _SshLinuxAuthState,
    ) -> None:
        """Dispatch the pre-auth sshd connection syslog message."""

        request = self.request
        self.executor.dispatcher.dispatch(
            SecurityEvent(
                timestamp=auth_state.connection_time,
                event_type="syslog",
                src_host=event.dst_host,
                syslog=SyslogContext(
                    app_name="sshd",
                    pid=auth_state.sshd_pid,
                    facility=10,
                    severity=6,
                    message=(
                        f"Connection from {request.source_ip} port {state.source_port} "
                        f"on {request.target_system.ip} port 22"
                    ),
                ),
            )
        )

    def _mark_edr_login_readiness(
        self,
        state: _SshTransportState,
        event: SecurityEvent,
        auth_state: _SshLinuxAuthState,
    ) -> None:
        """Record when EDR/session-owned child evidence may appear."""

        request = self.request
        ecar_after_accept_gap = sample_timing_delta(
            "source.ecar_ssh_session_after_accept",
            seed_parts=auth_state.syslog_seed,
        )
        ecar_seed = (
            "login",
            event.dst_host.hostname if event.dst_host else request.target_system.hostname,
            request.user.username,
            request.source_ip,
            state.source_port,
            request.logon_id,
            10,
            state.session_obj_id,
            event.timestamp,
        )
        preferred_ecar_login_time = self.executor._source_timing_planner.source_time(
            event,
            "source.ecar_session",
            seed_parts=ecar_seed,
        )
        graph = TemporalConstraintGraph()
        graph.add_node("pam", auth_state.pam_time)
        graph.add_node("ecar_login", preferred_ecar_login_time)
        graph.constrain_after("ecar_login", "pam", min_gap=ecar_after_accept_gap)
        ecar_login_time = graph.resolved_time("ecar_login")
        self.executor._source_timing_planner.record_source_time(
            event,
            "source.ecar_session",
            ecar_login_time,
            seed_parts=ecar_seed,
        )
        ready_seed = _stable_seed(
            "ssh_session_source_ready:"
            f"{request.target_system.hostname}:{request.user.username}:{request.source_ip}:"
            f"{state.source_port}:{request.logon_id}:{request.time.isoformat()}"
        )
        ready_time = max(ecar_login_time, auth_state.logind_time) + timedelta(
            milliseconds=80 + (ready_seed % 160)
        )
        self.executor._remember_ssh_session_ready_time(
            request.source_ip,
            state.source_port,
            request.target_system.ip,
            ready_time,
        )
        if request.logon_id:
            self.executor.state_manager.update_session_metadata(
                request.logon_id,
                source_ready_time=ready_time,
            )

    def _dispatch_linux_auth_messages(
        self,
        state: _SshTransportState,
        event: SecurityEvent,
        auth_state: _SshLinuxAuthState,
    ) -> None:
        """Dispatch accepted-auth, PAM session-open, and logind session messages."""

        request = self.request
        executor = self.executor
        executor.dispatcher.dispatch(
            SecurityEvent(
                timestamp=auth_state.accepted_time,
                event_type="syslog",
                src_host=event.dst_host,
                syslog=SyslogContext(
                    app_name="sshd",
                    pid=auth_state.sshd_pid,
                    facility=10,
                    severity=6,
                    message=self._accepted_auth_message(state),
                ),
            )
        )
        executor.dispatcher.dispatch(
            SecurityEvent(
                timestamp=auth_state.pam_time,
                event_type="syslog",
                src_host=event.dst_host,
                syslog=SyslogContext(
                    app_name="sshd",
                    pid=auth_state.sshd_pid,
                    facility=10,
                    severity=6,
                    message=(
                        "pam_unix(sshd:session): session opened for user "
                        f"{request.user.username}(uid={_linux_uid_for_user(request.user.username)}) "
                        "by (uid=0)"
                    ),
                ),
            )
        )
        hostname = request.target_system.hostname
        session_id = auth_state.logind_session_id
        executor.dispatcher.dispatch(
            SecurityEvent(
                timestamp=auth_state.logind_time,
                event_type="syslog",
                src_host=event.dst_host,
                syslog=SyslogContext(
                    app_name="systemd-logind",
                    pid=executor._get_system_pid(hostname, "logind", 456),
                    facility=10,
                    severity=6,
                    message=f"New session {session_id} of user {request.user.username}.",
                ),
            )
        )

    def _accepted_auth_message(self, state: _SshTransportState) -> str:
        """Return the source-native accepted-auth syslog message."""

        request = self.request
        if request.auth_method == "publickey":
            key_suffix = ""
            if request.public_key_type or request.public_key_hash:
                key_suffix = f": {request.public_key_type or 'ED25519'}"
                if request.public_key_hash:
                    key_suffix += f" {request.public_key_hash}"
            return (
                f"Accepted publickey for {request.user.username} from {request.source_ip} "
                f"port {state.source_port} ssh2{key_suffix}"
            )
        return (
            f"Accepted password for {request.user.username} from {request.source_ip} "
            f"port {state.source_port} ssh2"
        )

    def _dispatch_linux_session_close_lifecycle(
        self,
        state: _SshTransportState,
        event: SecurityEvent,
        auth_state: _SshLinuxAuthState,
    ) -> None:
        """Dispatch source-native close/logout evidence for a modeled SSH session."""

        request = self.request
        close_time = self._source_native_session_close_time(state, auth_state)
        self.executor.dispatcher.dispatch(
            SecurityEvent(
                timestamp=close_time,
                event_type="logoff",
                dst_host=event.dst_host,
                auth=AuthContext(
                    username=request.user.username,
                    source_ip=request.source_ip,
                    source_port=state.source_port,
                    logon_id=request.logon_id,
                    session_id=auth_state.logind_session_id,
                    logon_type=10,
                ),
                edr=EdrContext(object_id=state.session_obj_id),
                syslog=SyslogContext(
                    app_name="sshd",
                    pid=auth_state.sshd_pid,
                    facility=10,
                    severity=6,
                    message=(
                        f"pam_unix(sshd:session): session closed for user {request.user.username}"
                    ),
                ),
            )
        )
        self._terminate_receiver_sshd_process(state, auth_state, close_time)

    def _terminate_receiver_sshd_process(
        self,
        state: _SshTransportState,
        auth_state: _SshLinuxAuthState,
        close_time: datetime,
    ) -> None:
        """Emit receiver-side accepted sshd termination when the tuple child is modeled."""

        request = self.request
        running = self.executor.state_manager.get_process(
            request.target_system.hostname,
            auth_state.sshd_pid,
        )
        if running is None:
            return
        command_line = running.command_line or ""
        if "sshd:" not in command_line:
            return
        seed = _stable_seed(
            "ssh_session_responder_terminate:"
            f"{request.target_system.hostname}:{request.source_ip}:{state.source_port}:"
            f"{auth_state.sshd_pid}:{close_time.isoformat()}"
        )
        terminate_time = close_time + timedelta(
            milliseconds=80 + (seed % 920),
            microseconds=307 + (seed % 491),
        )
        self.executor.generate_process_termination(
            user=request.user,
            system=request.target_system,
            time=terminate_time,
            pid=auth_state.sshd_pid,
            process_name=running.image,
            logon_id=running.logon_id,
            from_storyline=request.source.startswith("storyline"),
        )

    def _source_native_session_close_time(
        self,
        state: _SshTransportState,
        auth_state: _SshLinuxAuthState,
    ) -> datetime:
        """Return a PAM close time compatible with, but not identical to, transport close."""

        request = self.request
        seed = _stable_seed(
            "ssh_session_source_close:"
            f"{request.target_system.hostname}:{request.user.username}:{request.source_ip}:"
            f"{state.source_port}:{auth_state.sshd_pid}:{state.close_time.isoformat()}"
        )
        return state.close_time + timedelta(
            milliseconds=120 + (seed % 2380),
            microseconds=211 + (seed % 613),
        )
