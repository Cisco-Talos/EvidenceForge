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

The SSH bundle sits above individual canonical occurrences. It owns the ordered SSH
activity lifecycle and uses the current activity generator as a runtime adapter
for shared state, host context construction, source timing, and dispatch.
"""

from __future__ import annotations

import logging
import math
import random
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from threading import Lock
from typing import TYPE_CHECKING, Any, Protocol

from evidenceforge.events.application import (
    ApplicationChannelIdentity,
    ApplicationChannelSnapshot,
)
from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import (
    AuthContext,
    HostContext,
    IdsAlertPlan,
    ProcessContext,
    SyslogContext,
)
from evidenceforge.events.contracts import EventKind
from evidenceforge.events.dispatcher import (
    ActionCohortPublicationReceipt,
    ActionCohortPublicationResult,
    EventDispatcher,
    StateNeutralProjectionPublicationReceipt,
    StateNeutralProjectionPublicationResult,
)
from evidenceforge.events.identity import EventIdentityPlan, ProcessIdentity, SessionIdentity
from evidenceforge.events.lifecycle import ActionLifecycleContext, SessionEndPlan
from evidenceforge.events.network import NetworkTransactionPlan
from evidenceforge.generation.actions.base import (
    ActionAnchor,
    source_observation_delay_difference,
)
from evidenceforge.generation.actions.network_connection import (
    DeferredSessionNetworkAuthority,
    DeferredSshApplicationIntent,
    DeferredSshTimingIntent,
    NetworkConnectionIdentityCapture,
)
from evidenceforge.generation.activity.helpers import _get_os_category, _get_rng
from evidenceforge.generation.activity.timing_profiles import (
    SshAuthenticationTimingPlan,
    get_timing_window,
    plan_ssh_authentication_timing,
)
from evidenceforge.generation.application_channels import ApplicationChannelRegistry
from evidenceforge.generation.baseline_timing import BaselineTimingPlanner
from evidenceforge.generation.deferred_session_composition import (
    DeferredSessionCompositionCoordinator,
    DeferredSessionKind,
)
from evidenceforge.generation.deferred_session_preseal import (
    DeferredSessionBindingDisposition,
    DeferredSessionDependentOccurrenceSpec,
    DeferredSessionProtocol,
)
from evidenceforge.generation.identity import IdentityDirectory, default_linux_uid_for_user
from evidenceforge.generation.process_runtime_cache import (
    ActivityGeneratorSessionRetentionRelease,
)
from evidenceforge.generation.source_timing import SourceTimingPlanner, SourceTimingPlanningRuntime
from evidenceforge.generation.ssh_channels import (
    SshApplicationChannelManager,
    SshChannelClosure,
    SshOperationKind,
    SshSessionView,
)
from evidenceforge.generation.state_manager import (
    ProcessMaterializationPlan,
    SessionMaterializationPlan,
    StateManager,
)
from evidenceforge.generation.timing import (
    ConstantDistribution,
    DistributionSpec,
    TemporalConstraintGraph,
    TimingRuntime,
    TimingSampler,
    TimingScope,
    TriangularDistribution,
)
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import System, User
from evidenceforge.utils.rng import _stable_seed, stable_uuid
from evidenceforge.utils.time import ensure_utc

if TYPE_CHECKING:
    from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority

logger = logging.getLogger(__name__)

_SSH_TERMINAL_TAIL_RESERVATION = timedelta(milliseconds=3_500)
_SSH_RECEIVER_DESCENDANT_PHASE_PREFIX = "receiver-descendant:"
_SSH_RECEIVER_DESCENDANT_CAPACITY = 4_096


def _ssh_receiver_descendant_phase_object_id(phase: str) -> str | None:
    """Return the bounded per-object suffix for one descendant phase."""

    if type(phase) is not str or not phase.startswith(_SSH_RECEIVER_DESCENDANT_PHASE_PREFIX):
        return None
    object_id = phase.removeprefix(_SSH_RECEIVER_DESCENDANT_PHASE_PREFIX)
    if not object_id or ":" in object_id or len(object_id) > 4_096:
        return None
    return object_id


def _is_ssh_process_termination_phase(phase: str) -> bool:
    """Return whether a close-journal phase owns one exact process close."""

    if type(phase) is not str:
        return False
    return phase in {"source-terminate", "receiver-terminate"} or bool(
        _ssh_receiver_descendant_phase_object_id(phase)
    )


def _linux_uid_for_user(username: str) -> int:
    """Return a stable plausible Linux UID for a login username."""
    return default_linux_uid_for_user(username)


def _is_ssh_client_image(image: str) -> bool:
    """Return whether one exact process image names a modeled SSH client."""

    executable = image.casefold().replace("\\", "/").rsplit("/", 1)[-1]
    return executable in {"ssh", "ssh.exe", "scp", "scp.exe", "sftp", "sftp.exe"}


def _ssh_source_process_terminate_time(
    *,
    source_hostname: str,
    source_pid: int,
    source_port: int,
    target_hostname: str,
    transport_close_time: datetime,
) -> datetime:
    """Return the deterministic canonical SSH-client termination time."""

    close_time = ensure_utc(transport_close_time)
    seed = _stable_seed(
        "ssh_session_source_client_terminate:"
        f"{source_hostname}:{source_pid}:{source_port}:"
        f"{target_hostname}:{close_time.isoformat()}"
    )
    return close_time + timedelta(
        milliseconds=80 + (seed % 1420),
        microseconds=191 + (seed % 613),
    )


def _ssh_source_native_session_close_time(
    *,
    target_hostname: str,
    username: str,
    source_ip: str,
    source_port: int,
    sshd_pid: int,
    transport_close_time: datetime,
) -> datetime:
    """Return the deterministic canonical PAM/logout time."""

    close_time = ensure_utc(transport_close_time)
    seed = _stable_seed(
        "ssh_session_source_close:"
        f"{target_hostname}:{username}:{source_ip}:"
        f"{source_port}:{sshd_pid}:{close_time.isoformat()}"
    )
    return close_time + timedelta(
        milliseconds=120 + (seed % 2380),
        microseconds=211 + (seed % 613),
    )


def _ssh_receiver_process_terminate_time(
    *,
    target_hostname: str,
    source_ip: str,
    source_port: int,
    sshd_pid: int,
    receiver_started_at: datetime,
    session_close_time: datetime,
) -> datetime:
    """Return the exact per-session sshd termination time before logout."""

    close_time = ensure_utc(session_close_time)
    seed = _stable_seed(
        "ssh_session_responder_terminate:"
        f"{target_hostname}:{source_ip}:{source_port}:"
        f"{sshd_pid}:{close_time.isoformat()}"
    )
    return max(
        ensure_utc(receiver_started_at) + timedelta(milliseconds=100),
        close_time - timedelta(milliseconds=2, microseconds=seed % 701),
    )


def _ssh_logind_removed_time(
    *,
    target_hostname: str,
    username: str,
    source_ip: str,
    source_port: int,
    logind_session_id: int,
    session_close_time: datetime,
) -> datetime:
    """Return the deterministic canonical logind removal time."""

    close_time = ensure_utc(session_close_time)
    seed = _stable_seed(
        "ssh_session_logind_removed:"
        f"{target_hostname}:{username}:{source_ip}:"
        f"{source_port}:{logind_session_id}:{close_time.isoformat()}"
    )
    return close_time + timedelta(
        milliseconds=120 + (seed % 880),
        microseconds=701 + (seed % 173),
    )


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
    defer_session_close: bool = False
    session_end_plan: SessionEndPlan | None = None
    ids_alerts: list[IdsAlertPlan] = field(default_factory=list)
    source: str = "activity_generator"

    @property
    def bundle_owns_close(self) -> bool:
        """Return whether this action, rather than explicit intent, owns closure."""

        return self.emit_session_close and not (
            self.session_end_plan is not None and self.session_end_plan.is_authoritative
        )

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
            f"{self.emit_session_close}:"
            f"{self.defer_session_close}:"
            f"{self.session_end_plan.canonical_end.isoformat() if self.session_end_plan else ''}:"
            f"{self.ids_alerts}:"
            f"{self.source}:{self.time.isoformat()}"
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
            f"{self.session_end_plan.canonical_end.isoformat() if self.session_end_plan else ''}:"
            f"{self.emit_session_close}:{self.defer_session_close}:"
            f"{self.ids_alerts}:{self.source}:{self.time.isoformat()}"
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
    logon_id: str = ""
    transport_id: str = ""


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
class _SshCloseUserFacts:
    """Immutable scalar copy of the user model needed by terminal generation."""

    username: str
    full_name: str
    email: str
    groups: tuple[str, ...]
    enabled: bool
    persona: str | None
    primary_system: str | None
    browsing_intensity: str | None

    @classmethod
    def capture(cls, user: User) -> _SshCloseUserFacts:
        """Copy one mutable Pydantic user into bounded immutable facts."""

        if type(user) is not User or type(user.groups) is not list:
            raise TypeError("Exact SSH close user requires the built-in user model")
        text = (
            user.username,
            user.full_name,
            user.email,
            *(
                value
                for value in (user.persona, user.primary_system, user.browsing_intensity)
                if value
            ),
            *user.groups,
        )
        if (
            len(user.groups) > 4_096
            or any(type(value) is not str or len(value) > 4_096 for value in text)
            or type(user.enabled) is not bool
        ):
            raise ValueError("Exact SSH close user contains malformed or oversized facts")
        return cls(
            username=user.username,
            full_name=user.full_name,
            email=user.email,
            groups=tuple(user.groups),
            enabled=user.enabled,
            persona=user.persona,
            primary_system=user.primary_system,
            browsing_intensity=user.browsing_intensity,
        )

    def materialize(self) -> User:
        """Return a detached user model for terminal process publication."""

        return User(
            username=self.username,
            full_name=self.full_name,
            email=self.email,
            groups=list(self.groups),
            enabled=self.enabled,
            persona=self.persona,
            primary_system=self.primary_system,
            browsing_intensity=self.browsing_intensity,
        )


@dataclass(frozen=True, slots=True)
class _SshCloseSystemFacts:
    """Immutable scalar copy of a system model needed by terminal generation."""

    hostname: str
    ip: str
    os: str
    os_build: str | None
    architecture: str | None
    system_type: str
    assigned_user: str | None
    services: tuple[str, ...]
    roles: tuple[str, ...]
    public_hostnames: tuple[str, ...]

    @classmethod
    def capture(cls, system: System) -> _SshCloseSystemFacts:
        """Copy one mutable Pydantic system into bounded immutable facts."""

        if (
            type(system) is not System
            or type(system.services) is not list
            or type(system.roles) is not list
            or type(system.public_hostnames) is not list
        ):
            raise TypeError("Exact SSH close system requires the built-in system model")
        collections = (system.services, system.roles, system.public_hostnames)
        text = (
            system.hostname,
            system.ip,
            system.os,
            system.type,
            *(
                value
                for value in (system.os_build, system.architecture, system.assigned_user)
                if value
            ),
            *(value for collection in collections for value in collection),
        )
        if any(len(collection) > 4_096 for collection in collections) or any(
            type(value) is not str or len(value) > 4_096 for value in text
        ):
            raise ValueError("Exact SSH close system contains malformed or oversized facts")
        return cls(
            hostname=system.hostname,
            ip=system.ip,
            os=system.os,
            os_build=system.os_build,
            architecture=system.architecture,
            system_type=system.type,
            assigned_user=system.assigned_user,
            services=tuple(system.services),
            roles=tuple(system.roles),
            public_hostnames=tuple(system.public_hostnames),
        )

    def materialize(self) -> System:
        """Return a detached system model for terminal process publication."""

        return System(
            hostname=self.hostname,
            ip=self.ip,
            os=self.os,
            os_build=self.os_build,
            architecture=self.architecture,
            type=self.system_type,
            assigned_user=self.assigned_user,
            services=list(self.services),
            roles=list(self.roles),
            public_hostnames=list(self.public_hostnames),
        )


@dataclass(frozen=True, slots=True)
class _SshCloseHostFacts:
    """Immutable scalar copy of one host context retained by the close journal."""

    hostname: str
    ip: str
    os: str
    os_category: str
    system_type: str
    domain: str
    fqdn: str
    netbios_domain: str
    roles: tuple[str, ...]

    @classmethod
    def capture(cls, host: HostContext) -> _SshCloseHostFacts:
        """Copy one mutable builder context into bounded immutable facts."""

        if type(host) is not HostContext or type(host.roles) is not list:
            raise TypeError("Exact SSH close host requires the built-in host context")
        values = (
            host.hostname,
            host.ip,
            host.os,
            host.os_category,
            host.system_type,
            host.domain,
            host.fqdn,
            host.netbios_domain,
            *host.roles,
        )
        if any(type(value) is not str or len(value) > 4_096 for value in values):
            raise ValueError("Exact SSH close host contains malformed or oversized text")
        if not host.hostname or not host.ip or host.os_category not in {"linux", "windows"}:
            raise ValueError("Exact SSH close host has incomplete canonical identity")
        return cls(
            hostname=host.hostname,
            ip=host.ip,
            os=host.os,
            os_category=host.os_category,
            system_type=host.system_type,
            domain=host.domain,
            fqdn=host.fqdn,
            netbios_domain=host.netbios_domain,
            roles=tuple(host.roles),
        )

    def materialize(self) -> HostContext:
        """Return a fresh compatibility context for terminal occurrence construction."""

        return HostContext(
            hostname=self.hostname,
            ip=self.ip,
            os=self.os,
            os_category=self.os_category,
            system_type=self.system_type,
            domain=self.domain,
            fqdn=self.fqdn,
            netbios_domain=self.netbios_domain,
            roles=list(self.roles),
        )


@dataclass(frozen=True, slots=True)
class _PreparedSshClosePlan:
    """Precommit immutable facts sufficient to execute one action-owned SSH close."""

    continuation_id: str
    username: str
    source_ip: str
    target_ip: str
    source_port: int
    open_time: datetime
    session_started_at: datetime
    close_time: datetime
    source_terminate_time: datetime | None
    receiver_started_at: datetime
    receiver_terminate_time: datetime
    session_close_time: datetime
    logind_remove_time: datetime
    terminal_window_end: datetime
    session_object_id: str
    logon_id: str
    session_id: int
    session_lifecycle_group_id: str
    session_logon_guid: str
    session_parent_lifecycle_group_id: str
    user: _SshCloseUserFacts
    source_system: _SshCloseSystemFacts | None
    target_system: _SshCloseSystemFacts
    source_host: _SshCloseHostFacts | None
    target_host: _SshCloseHostFacts
    source_identity: ProcessIdentity | None
    auth_state: _SshLinuxAuthState
    source_tag: str

    def __post_init__(self) -> None:
        """Reject incomplete, mutable, or temporally impossible close facts."""

        if any(
            type(value) is not str or not value or len(value) > 4_096
            for value in (
                self.continuation_id,
                self.username,
                self.source_ip,
                self.target_ip,
                self.session_object_id,
                self.logon_id,
                self.session_lifecycle_group_id,
            )
        ):
            raise ValueError("Exact SSH close plan requires bounded non-empty identity")
        if type(self.source_port) is not int or not 1 <= self.source_port <= 65_535:
            raise ValueError("Exact SSH close plan source port is invalid")
        if type(self.session_id) is not int or self.session_id < 0:
            raise ValueError("Exact SSH close plan session ID is invalid")
        if (
            type(self.session_logon_guid) is not str
            or len(self.session_logon_guid) > 4_096
            or type(self.session_parent_lifecycle_group_id) is not str
            or len(self.session_parent_lifecycle_group_id) > 4_096
        ):
            raise ValueError("Exact SSH close plan session lineage is malformed or oversized")
        if type(self.target_host) is not _SshCloseHostFacts:
            raise TypeError("Exact SSH close plan requires immutable target-host facts")
        if type(self.user) is not _SshCloseUserFacts or self.user.username != self.username:
            raise TypeError("Exact SSH close plan requires immutable user facts")
        if type(self.target_system) is not _SshCloseSystemFacts:
            raise TypeError("Exact SSH close plan requires immutable target-system facts")
        if self.source_system is not None and type(self.source_system) is not _SshCloseSystemFacts:
            raise TypeError("Exact SSH close plan source-system facts changed type")
        if self.source_host is not None and type(self.source_host) is not _SshCloseHostFacts:
            raise TypeError("Exact SSH close plan source-host facts changed type")
        if self.source_identity is not None and type(self.source_identity) is not ProcessIdentity:
            raise TypeError("Exact SSH close plan source process changed type")
        if type(self.auth_state) is not _SshLinuxAuthState:
            raise TypeError("Exact SSH close plan authentication state changed type")
        terminal_times = (
            self.receiver_started_at,
            self.receiver_terminate_time,
            self.session_close_time,
            self.logind_remove_time,
            self.terminal_window_end,
        )
        if any(type(value) is not datetime for value in terminal_times) or (
            self.source_terminate_time is not None
            and type(self.source_terminate_time) is not datetime
        ):
            raise TypeError("Exact SSH close plan terminal times changed type")
        open_time = ensure_utc(self.open_time)
        session_started_at = ensure_utc(self.session_started_at)
        close_time = ensure_utc(self.close_time)
        receiver_started_at = ensure_utc(self.receiver_started_at)
        receiver_terminate_time = ensure_utc(self.receiver_terminate_time)
        session_close_time = ensure_utc(self.session_close_time)
        logind_remove_time = ensure_utc(self.logind_remove_time)
        terminal_window_end = ensure_utc(self.terminal_window_end)
        source_terminate_time = (
            ensure_utc(self.source_terminate_time)
            if self.source_terminate_time is not None
            else None
        )
        if (
            session_started_at < open_time
            or session_started_at > self.auth_state.logind_time
            or close_time <= open_time
            or self.auth_state.logind_time >= close_time
        ):
            raise ValueError("Exact SSH close plan does not contain its authenticated session")
        if self.target_host.ip != self.target_ip:
            raise ValueError("Exact SSH close plan target host changed its transport address")
        if (
            self.target_system.hostname != self.target_host.hostname
            or self.target_system.ip != self.target_host.ip
            or self.target_system.os != self.target_host.os
        ):
            raise ValueError("Exact SSH close plan target system crossed its host context")
        if (self.source_host is None) is not (self.source_system is None):
            raise ValueError("Exact SSH close plan source system and host disagree")
        if self.source_host is not None and (
            self.source_host.ip != self.source_ip
            or self.source_system is None
            or self.source_system.hostname != self.source_host.hostname
            or self.source_system.ip != self.source_host.ip
            or self.source_system.os != self.source_host.os
        ):
            raise ValueError("Exact SSH close plan source host changed its transport address")
        if self.source_identity is not None and (
            self.source_system is None
            or self.source_identity.hostname != self.source_system.hostname
        ):
            raise ValueError("Exact SSH close plan source process crossed its system owner")
        if type(self.source_tag) is not str or not self.source_tag or len(self.source_tag) > 4_096:
            raise ValueError("Exact SSH close plan source tag is malformed or oversized")
        object.__setattr__(self, "open_time", open_time)
        object.__setattr__(self, "session_started_at", session_started_at)
        object.__setattr__(self, "close_time", close_time)
        object.__setattr__(self, "source_terminate_time", source_terminate_time)
        object.__setattr__(self, "receiver_started_at", receiver_started_at)
        object.__setattr__(self, "receiver_terminate_time", receiver_terminate_time)
        object.__setattr__(self, "session_close_time", session_close_time)
        object.__setattr__(self, "logind_remove_time", logind_remove_time)
        object.__setattr__(self, "terminal_window_end", terminal_window_end)
        self.require_terminal_tail(terminal_window_end)

    def require_terminal_tail(self, window_end: datetime) -> None:
        """Authenticate every frozen close timestamp against its exact half-open owner."""

        if type(window_end) is not datetime:
            raise TypeError("Exact SSH terminal window changed type")
        canonical_window_end = ensure_utc(window_end)
        if canonical_window_end != self.terminal_window_end:
            raise StateError("Exact SSH terminal tail crossed its generation-window owner")
        expected_session_close = _ssh_source_native_session_close_time(
            target_hostname=self.target_system.hostname,
            username=self.username,
            source_ip=self.source_ip,
            source_port=self.source_port,
            sshd_pid=self.auth_state.sshd_pid,
            transport_close_time=self.close_time,
        )
        expected_receiver_terminate = _ssh_receiver_process_terminate_time(
            target_hostname=self.target_system.hostname,
            source_ip=self.source_ip,
            source_port=self.source_port,
            sshd_pid=self.auth_state.sshd_pid,
            receiver_started_at=self.receiver_started_at,
            session_close_time=expected_session_close,
        )
        expected_logind_remove = _ssh_logind_removed_time(
            target_hostname=self.target_system.hostname,
            username=self.username,
            source_ip=self.source_ip,
            source_port=self.source_port,
            logind_session_id=self.auth_state.logind_session_id,
            session_close_time=expected_session_close,
        )
        expected_source_terminate = (
            _ssh_source_process_terminate_time(
                source_hostname=self.source_identity.hostname,
                source_pid=self.source_identity.pid,
                source_port=self.source_port,
                target_hostname=self.target_system.hostname,
                transport_close_time=self.close_time,
            )
            if self.source_identity is not None and _is_ssh_client_image(self.source_identity.image)
            else None
        )
        if (
            self.session_close_time != expected_session_close
            or self.receiver_terminate_time != expected_receiver_terminate
            or self.logind_remove_time != expected_logind_remove
            or self.source_terminate_time != expected_source_terminate
        ):
            raise StateError("Exact SSH terminal tail changed after precommit preparation")
        if (
            canonical_window_end - self.close_time < _SSH_TERMINAL_TAIL_RESERVATION
            or not self.close_time
            < self.session_close_time
            < self.logind_remove_time
            < canonical_window_end
            or not self.auth_state.logind_time
            < self.receiver_terminate_time
            < self.session_close_time
            or (
                self.source_terminate_time is not None
                and not self.close_time < self.source_terminate_time < canonical_window_end
            )
        ):
            raise StateError(
                "Exact SSH terminal tail does not fit inside its half-open generation window"
            )

    def session_identity(self) -> SessionIdentity:
        """Rebuild the exact immutable target-session identity from scalar facts."""

        return SessionIdentity(
            hostname=self.target_system.hostname,
            object_id=self.session_object_id,
            logon_id=self.logon_id,
            session_id=self.session_id,
            principal=self.username,
            session_kind="ssh",
            started_at=self.session_started_at,
            lifecycle_group_id=self.session_lifecycle_group_id,
            logon_guid=self.session_logon_guid,
            parent_lifecycle_group_id=self.session_parent_lifecycle_group_id,
        )


class _SshCloseProjectionProgress:
    """Exact receipt-backed progress for every source-native SSH close projection."""

    __slots__ = ("_bindings", "_completed", "_lock", "_recoveries")

    _PHASES = frozenset({"source-terminate", "receiver-terminate", "logout", "logind-remove"})

    def __init__(self) -> None:
        self._lock = Lock()
        self._completed: set[str] = set()
        self._bindings: dict[
            str,
            tuple[str, str, str, ProcessIdentity | SessionIdentity],
        ] = {}
        self._recoveries: dict[
            str,
            tuple[
                ActionCohortPublicationReceipt | StateNeutralProjectionPublicationReceipt,
                ActionCohortPublicationResult | StateNeutralProjectionPublicationResult,
            ],
        ] = {}

    @classmethod
    def _validate_phase(cls, phase: str) -> None:
        if type(phase) is not str or (
            phase not in cls._PHASES and not _is_ssh_process_termination_phase(phase)
        ):
            raise StateError(f"Exact SSH close projection phase is unsupported: {phase!r}")

    @staticmethod
    def _facts_authenticate(
        receipt: ActionCohortPublicationReceipt | StateNeutralProjectionPublicationReceipt,
        result: ActionCohortPublicationResult | StateNeutralProjectionPublicationResult,
    ) -> bool:
        if result.receipt is not receipt or len(receipt.occurrence_ids) != 1:
            return False
        if type(result) is ActionCohortPublicationResult:
            return bool(
                type(receipt) is ActionCohortPublicationReceipt
                and len(result.projections) == 1
                and result.projections[0].occurrence_id == receipt.occurrence_ids[0]
            )
        return bool(
            type(result) is StateNeutralProjectionPublicationResult
            and type(receipt) is StateNeutralProjectionPublicationReceipt
            and result.projection.occurrence_id == receipt.occurrence_ids[0]
        )

    @staticmethod
    def _binding_authenticates(
        phase: str,
        binding: tuple[str, str, str, ProcessIdentity | SessionIdentity],
        receipt: ActionCohortPublicationReceipt,
        result: ActionCohortPublicationResult,
    ) -> bool:
        """Bind one action receipt to its exact terminal phase and State identity."""

        root_action_id, state_semantic_id, occurrence_id, expected_identity = binding
        if (
            result.receipt is not receipt
            or receipt.root_action_id != root_action_id
            or receipt.state_semantic_id != state_semantic_id
            or receipt.occurrence_ids != (occurrence_id,)
            or result.state.semantic_id != state_semantic_id
            or result.state.started_sessions
            or result.state.started_processes
            or len(result.projections) != 1
            or result.projections[0].occurrence_id != occurrence_id
        ):
            return False
        if _is_ssh_process_termination_phase(phase):
            return bool(
                type(expected_identity) is ProcessIdentity
                and result.state.terminated_processes == (expected_identity,)
                and not result.state.terminalized_sessions
            )
        return bool(
            phase == "logout"
            and type(expected_identity) is SessionIdentity
            and not result.state.terminated_processes
            and result.state.terminalized_sessions == (expected_identity,)
        )

    def bind_action_phase(
        self,
        phase: str,
        *,
        root_action_id: str,
        state_semantic_id: str,
        occurrence_id: str,
        expected_identity: ProcessIdentity | SessionIdentity,
    ) -> None:
        """Install exact replay facts immediately before the canonical claim commits."""

        self._validate_phase(phase)
        binding = (
            root_action_id,
            state_semantic_id,
            occurrence_id,
            expected_identity,
        )
        with self._lock:
            retained = self._bindings.get(phase)
            if retained is not None and retained != binding:
                raise StateError("Exact SSH close phase changed its action-cohort binding")
            self._bindings[phase] = binding

    def cancel_action_phase(self, phase: str) -> None:
        """Release a phase binding only while no committed receipt is retained."""

        self._validate_phase(phase)
        with self._lock:
            if phase in self._recoveries:
                raise StateError("Committed exact SSH close phase cannot cancel its binding")
            if phase not in self._completed:
                self._bindings.pop(phase, None)

    def retain_failure(self, phase: str, error: BaseException) -> None:
        """Retain the dispatcher's exact receipt attached to one sink failure."""

        self._validate_phase(phase)
        try:
            attributes = object.__getattribute__(error, "__dict__")
        except BaseException:
            return
        if type(attributes) is not dict:
            return
        receipt = attributes.get("action_cohort_receipt")
        result = attributes.get("action_cohort_result")
        if not (
            type(receipt) is ActionCohortPublicationReceipt
            and type(result) is ActionCohortPublicationResult
            and self._facts_authenticate(receipt, result)
        ):
            receipt = attributes.get("state_neutral_projection_receipt")
            result = attributes.get("state_neutral_projection_result")
            if not (
                type(receipt) is StateNeutralProjectionPublicationReceipt
                and type(result) is StateNeutralProjectionPublicationResult
                and self._facts_authenticate(receipt, result)
            ):
                return
        self.retain_publication(phase, receipt, result)

    def retain_publication(
        self,
        phase: str,
        receipt: ActionCohortPublicationReceipt | StateNeutralProjectionPublicationReceipt,
        result: ActionCohortPublicationResult | StateNeutralProjectionPublicationResult,
    ) -> None:
        """Retain exact canonical facts without depending on exception mutability."""

        self._validate_phase(phase)
        if not self._facts_authenticate(receipt, result):
            raise StateError("Exact SSH close received forged projection recovery facts")
        with self._lock:
            binding = self._bindings.get(phase)
            if type(receipt) is ActionCohortPublicationReceipt and (
                type(result) is not ActionCohortPublicationResult
                or binding is None
                or not self._binding_authenticates(phase, binding, receipt, result)
            ):
                raise StateError("Exact SSH close projection crossed its action-cohort binding")
            retained = self._recoveries.get(phase)
            if retained is not None and (retained[0] is not receipt or retained[1] is not result):
                raise StateError("Exact SSH close phase changed its projection receipt")
            self._recoveries[phase] = (receipt, result)

    def mark_complete(self, phase: str) -> None:
        """Acknowledge one phase only after its exact publisher returned successfully."""

        self._validate_phase(phase)
        with self._lock:
            self._completed.add(phase)
            self._recoveries.pop(phase, None)
            self._bindings.pop(phase, None)

    def recover(self, phase: str, dispatcher: EventDispatcher) -> bool:
        """Resume or authenticate a retained exact receipt without consulting State."""

        self._validate_phase(phase)
        with self._lock:
            if phase in self._completed:
                return True
            retained = self._recoveries.get(phase)
            binding = self._bindings.get(phase)
        if retained is None:
            return False
        receipt, expected_result = retained
        if type(receipt) is ActionCohortPublicationReceipt:
            if binding is None or not self._binding_authenticates(
                phase,
                binding,
                receipt,
                expected_result,
            ):
                raise StateError("Exact SSH close recovery crossed its action-cohort binding")
            authentic = dispatcher.authenticates_action_cohort_publication_receipt(receipt)
            already_succeeded = bool(
                type(expected_result) is ActionCohortPublicationResult
                and len(expected_result.projections) == 1
                and expected_result.projections[0].status == "succeeded"
            )
            result = (
                expected_result
                if authentic and already_succeeded
                else dispatcher.resume_action_cohort_projection(receipt)
            )
            authentic = dispatcher.authenticates_action_cohort_publication_receipt(receipt)
            succeeded = bool(
                type(result) is ActionCohortPublicationResult
                and len(result.projections) == 1
                and result.projections[0].status == "succeeded"
            )
        else:
            authentic = dispatcher.authenticates_state_neutral_projection_publication_receipt(
                receipt
            )
            already_succeeded = bool(
                type(expected_result) is StateNeutralProjectionPublicationResult
                and expected_result.projection.status == "succeeded"
            )
            result = (
                expected_result
                if authentic and already_succeeded
                else dispatcher.resume_state_neutral_exact_projection(receipt)
            )
            authentic = dispatcher.authenticates_state_neutral_projection_publication_receipt(
                receipt
            )
            succeeded = bool(
                type(result) is StateNeutralProjectionPublicationResult
                and result.projection.status == "succeeded"
            )
        if (
            result is not expected_result
            or not self._facts_authenticate(receipt, result)
            or not succeeded
            or not authentic
        ):
            raise StateError("Exact SSH close projection recovery returned a forged receipt")
        with self._lock:
            current = self._recoveries.get(phase)
            if current is None or current[0] is not receipt or current[1] is not expected_result:
                raise StateError("Exact SSH close projection recovery changed owner")
            self._recoveries.pop(phase)
            self._bindings.pop(phase, None)
            self._completed.add(phase)
        return True


@dataclass(frozen=True, slots=True)
class _SshReceiverDescendantTermination:
    """One frozen target-process close owned by an exact SSH continuation."""

    identity: ProcessIdentity
    terminate_at: datetime
    concurrency_group_id: str
    session_identity: SessionIdentity | None

    def __post_init__(self) -> None:
        """Normalize time and reject mutable or anonymous process facts."""

        if type(self.identity) is not ProcessIdentity:
            raise TypeError("Exact SSH descendant close requires a ProcessIdentity")
        if (
            _ssh_receiver_descendant_phase_object_id(
                f"{_SSH_RECEIVER_DESCENDANT_PHASE_PREFIX}{self.identity.object_id}"
            )
            != self.identity.object_id
        ):
            raise ValueError("Exact SSH descendant process object ID is malformed or oversized")
        if type(self.terminate_at) is not datetime:
            raise TypeError("Exact SSH descendant close requires a datetime")
        if type(self.concurrency_group_id) is not str or len(self.concurrency_group_id) > 4_096:
            raise ValueError("Exact SSH descendant concurrency group is malformed or oversized")
        if self.session_identity is not None and type(self.session_identity) is not SessionIdentity:
            raise TypeError("Exact SSH descendant session identity changed type")
        if self.session_identity is not None and (
            self.session_identity.hostname != self.identity.hostname
            or self.session_identity.logon_id != self.identity.logon_id
        ):
            raise ValueError("Exact SSH descendant crossed its owning session identity")
        object.__setattr__(self, "terminate_at", ensure_utc(self.terminate_at))

    @property
    def phase(self) -> str:
        """Return the exact per-process close-journal phase."""

        return f"{_SSH_RECEIVER_DESCENDANT_PHASE_PREFIX}{self.identity.object_id}"


class _SshReceiverDescendantTerminationBinding:
    """One-shot frozen children-first target-process schedule."""

    __slots__ = ("_entries", "_lock")

    def __init__(self) -> None:
        self._lock = Lock()
        self._entries: tuple[_SshReceiverDescendantTermination, ...] | None = None

    def bind(
        self,
        entries: tuple[_SshReceiverDescendantTermination, ...],
    ) -> tuple[_SshReceiverDescendantTermination, ...]:
        """Install or authenticate the sole immutable descendant schedule."""

        if type(entries) is not tuple or any(
            type(entry) is not _SshReceiverDescendantTermination for entry in entries
        ):
            raise TypeError("Exact SSH descendant schedule requires an immutable typed tuple")
        if len(entries) > _SSH_RECEIVER_DESCENDANT_CAPACITY:
            raise StateError("Exact SSH descendant schedule exceeds its bounded capacity")
        object_ids = tuple(entry.identity.object_id for entry in entries)
        if len(object_ids) != len(set(object_ids)):
            raise StateError("Exact SSH descendant schedule repeats a process identity")
        if any(
            prior.terminate_at >= following.terminate_at
            for prior, following in zip(entries, entries[1:], strict=False)
        ):
            raise StateError("Exact SSH descendant schedule is not strictly children-first")
        with self._lock:
            if self._entries is None:
                self._entries = entries
            elif self._entries != entries:
                raise StateError("Exact SSH descendant schedule changed after first close attempt")
            return self._entries

    def retained(self) -> tuple[_SshReceiverDescendantTermination, ...] | None:
        """Return the already-frozen schedule, if finalization has planned it."""

        with self._lock:
            return self._entries


class _SshCloseContinuationBinding:
    """One-shot exact transaction binding retained by a precommit close payload."""

    __slots__ = ("_continuation", "_lock", "_prepared", "_transaction")

    def __init__(self) -> None:
        self._lock = Lock()
        self._prepared: _PreparedSshCloseContinuation | None = None
        self._transaction: NetworkTransactionPlan | None = None
        self._continuation: _SshCloseContinuation | None = None

    def claim(self, prepared: _PreparedSshCloseContinuation) -> None:
        """Bind this mutable one-shot cell to its sole frozen prepared owner."""

        with self._lock:
            if self._prepared is None:
                self._prepared = prepared
                return
            if self._prepared is not prepared:
                raise StateError("Prepared exact SSH close copied its binding capability")

    def bind(
        self,
        prepared: _PreparedSshCloseContinuation,
        transaction: NetworkTransactionPlan,
    ) -> _SshCloseContinuation:
        """Return the sole carrier authorized for this payload and transaction."""

        with self._lock:
            if self._prepared is not prepared:
                raise StateError("Prepared exact SSH close crossed its binding owner")
            if self._continuation is None:
                continuation = _SshCloseContinuation(
                    prepared=prepared,
                    transaction=transaction,
                )
                self._transaction = transaction
                self._continuation = continuation
                return continuation
            if self._transaction is not transaction:
                raise StateError("Prepared exact SSH close changed its bound transaction")
            return self._continuation

    def authenticates(self, continuation: _SshCloseContinuation) -> bool:
        """Return whether a carrier is the sole object produced by this binding."""

        with self._lock:
            return bool(
                self._continuation is continuation
                and self._prepared is continuation.prepared
                and self._transaction is continuation.transaction
            )


class _SshApplicationRetirementBinding:
    """Exact original SSH application owner and its retryable retirement proof."""

    __slots__ = (
        "_application_identity",
        "_expected_closed_at",
        "_expected_close_reason",
        "_lock",
        "_prepared",
        "_retired",
        "_session",
        "_transaction",
    )

    def __init__(self) -> None:
        self._lock = Lock()
        self._prepared: _PreparedSshCloseContinuation | None = None
        self._transaction: NetworkTransactionPlan | None = None
        self._session: SshSessionView | None = None
        self._application_identity: ApplicationChannelIdentity | None = None
        self._expected_closed_at: datetime | None = None
        self._expected_close_reason: str | None = None
        self._retired = False

    def claim(self, prepared: _PreparedSshCloseContinuation) -> None:
        """Bind the one-shot proof cell to the sole immutable close owner."""

        with self._lock:
            if self._prepared is None:
                self._prepared = prepared
                return
            if self._prepared is not prepared:
                raise StateError("Prepared exact SSH close copied its application capability")

    @staticmethod
    def _require_bound_facts(
        prepared: _PreparedSshCloseContinuation,
        transaction: NetworkTransactionPlan,
        session: SshSessionView,
        snapshot: ApplicationChannelSnapshot,
    ) -> None:
        """Authenticate the committed SSH sidecar against precommit scalar facts."""

        plan = prepared.plan
        transport = session.transport
        binding = session.binding
        if (
            transport.transport_id != transaction.stable_id
            or transport.zeek_uid != transaction.zeek_uid
            or transport.conn_id != transaction.conn_id
            or transport.source_ip != transaction.src_ip
            or transport.server_ip != transaction.dst_ip
            or transport.source_port != transaction.src_port
            or transport.server_port != transaction.dst_port
            or transport.opened_at != transaction.started_at
            or transport.closes_at != transaction.closed_at
            or binding.hostname != plan.target_system.hostname.casefold()
            or binding.logon_id != plan.logon_id
            or binding.session_object_id != plan.session_object_id
            or binding.lifecycle_group_id != plan.session_lifecycle_group_id
            or binding.principal != plan.username.casefold()
            or binding.ready_at != plan.auth_state.logind_time
            or session.affinity.server_identity != plan.target_system.hostname.casefold()
            or session.affinity.server_session_object_id != plan.session_object_id
            or session.affinity.principal != plan.username.casefold()
        ):
            raise StateError("Exact SSH close crossed its committed application session")
        identity = snapshot.identity
        if (
            not snapshot.is_open
            or identity.channel_id != session.channel_id
            or identity.protocol != "ssh"
            or identity.owner_id != session.owner_id
            or identity.affinity_digest != session.affinity.digest
            or identity.binding.transport_id != transaction.stable_id
            or identity.binding.opened_at != transaction.started_at
            or identity.binding.closes_at != transaction.closed_at
        ):
            raise StateError("Exact SSH close crossed its shared application identity")

    def bind(
        self,
        prepared: _PreparedSshCloseContinuation,
        transaction: NetworkTransactionPlan,
    ) -> None:
        """Capture the exact committed SSH sidecar outside all owner locks."""

        with self._lock:
            if self._prepared is not prepared:
                raise StateError("Prepared exact SSH close crossed its application owner")
            if self._session is not None:
                if self._transaction is not transaction:
                    raise StateError("Prepared exact SSH close changed its application transport")
                return

        prepared.require_application_owner_shape()
        manager = prepared.ssh_manager_owner
        registry = prepared.application_registry_owner
        session = manager.find_by_transport(transaction.stable_id)
        if type(session) is not SshSessionView:
            raise StateError("Exact SSH close cannot bind its committed application session")
        snapshot = registry.get(session.channel_id)
        if type(snapshot) is not ApplicationChannelSnapshot:
            raise StateError("Exact SSH close cannot bind its shared application identity")
        self._require_bound_facts(prepared, transaction, session, snapshot)

        with self._lock:
            if self._prepared is not prepared:
                raise StateError("Prepared exact SSH close changed its application owner")
            if self._session is None:
                self._transaction = transaction
                self._session = session
                self._application_identity = snapshot.identity
                return
            if (
                self._transaction is not transaction
                or self._session != session
                or self._application_identity != snapshot.identity
            ):
                raise StateError("Prepared exact SSH close changed its bound application session")

    def _bound_facts(
        self,
        prepared: _PreparedSshCloseContinuation,
    ) -> tuple[SshSessionView, ApplicationChannelIdentity, datetime | None, str | None]:
        """Return immutable facts without invoking an external owner under the cell lock."""

        with self._lock:
            if self._prepared is not prepared:
                raise StateError("Exact SSH close crossed its application retirement owner")
            if self._session is None or self._application_identity is None:
                raise StateError("Exact SSH close has no bound application session")
            return (
                self._session,
                self._application_identity,
                self._expected_closed_at,
                self._expected_close_reason,
            )

    def _retain_expected_close(
        self,
        prepared: _PreparedSshCloseContinuation,
        expected: datetime,
        reason: str,
    ) -> None:
        """Retain the exact pre-call close time across a lost manager return."""

        with self._lock:
            if self._prepared is not prepared:
                raise StateError("Exact SSH close crossed its application retirement owner")
            if self._expected_closed_at is None:
                self._expected_closed_at = expected
                self._expected_close_reason = reason
            elif self._expected_closed_at != expected or self._expected_close_reason != reason:
                raise StateError("Exact SSH application retirement changed its close time")

    @staticmethod
    def _expected_close_time(
        snapshot: ApplicationChannelSnapshot,
        requested: datetime,
    ) -> datetime:
        """Mirror the canonical SSH manager's bounded common-channel close time."""

        identity = snapshot.identity
        effective_deadline = min(
            snapshot.idle_deadline,
            identity.hard_deadline,
            identity.binding.closes_at,
        )
        return min(
            effective_deadline,
            max(requested, identity.opened_at, snapshot.last_activity_at),
        )

    @staticmethod
    def _require_closure(
        closure: SshChannelClosure,
        session: SshSessionView,
        expected_closed_at: datetime,
    ) -> None:
        """Authenticate the lock-free SSH manager return against the retained sidecar."""

        if (
            closure.channel_id != session.channel_id
            or closure.ssh_session_id != session.ssh_session_id
            or closure.logon_id != session.binding.logon_id
            or closure.session_object_id != session.binding.session_object_id
            or closure.lifecycle_group_id != session.binding.lifecycle_group_id
            or closure.principal != session.binding.principal
            or closure.transport_id != session.transport.transport_id
            or closure.closed_at != expected_closed_at
            or closure.reason != "bundle_close"
            or closure.source_process != session.transport.source_process
            or closure.receiver_process != session.transport.receiver_process
        ):
            raise StateError("Exact SSH application retirement returned a forged closure")

    def _require_retirement_proof(
        self,
        prepared: _PreparedSshCloseContinuation,
    ) -> None:
        """Prove the original sidecar and shared channel are both terminal."""

        prepared.require_application_owner_shape()
        (
            session,
            application_identity,
            expected_closed_at,
            expected_close_reason,
        ) = self._bound_facts(prepared)
        if expected_closed_at is None or expected_close_reason is None:
            raise StateError("Exact SSH application retirement has no retained close intent")
        manager = prepared.ssh_manager_owner
        registry = prepared.application_registry_owner
        if manager.session_view(session.channel_id) is not None:
            raise StateError("Exact SSH application sidecar remains open after retirement")
        snapshot = registry.get(session.channel_id)
        if (
            type(snapshot) is not ApplicationChannelSnapshot
            or snapshot.identity != application_identity
            or snapshot.closed_at != expected_closed_at
            or snapshot.close_reason != expected_close_reason
        ):
            raise StateError("Exact SSH shared application retirement is not proven")
        prepared.require_application_owner_shape()

    def retire(
        self,
        prepared: _PreparedSshCloseContinuation,
        requested_close: datetime,
    ) -> None:
        """Retire the bound original SSH owner idempotently outside progress locks."""

        prepared.require_application_owner_shape()
        session, application_identity, retained_close, retained_reason = self._bound_facts(prepared)
        manager = prepared.ssh_manager_owner
        registry = prepared.application_registry_owner
        current_sidecar = manager.session_view(session.channel_id)
        snapshot = registry.get(session.channel_id)
        if current_sidecar is not None:
            if type(current_sidecar) is not SshSessionView or current_sidecar != session:
                raise StateError("Exact SSH application sidecar changed before retirement")
            if (
                type(snapshot) is not ApplicationChannelSnapshot
                or not snapshot.is_open
                or snapshot.identity != application_identity
            ):
                raise StateError("Exact SSH shared application owner changed before retirement")
            expected_close = self._expected_close_time(snapshot, requested_close)
            self._retain_expected_close(prepared, expected_close, "bundle_close")
            closure = manager.close_session(
                session.channel_id,
                closed_at=requested_close,
                reason="bundle_close",
            )
            if type(closure) is not SshChannelClosure:
                raise StateError("Exact SSH application retirement returned no closure")
            self._require_closure(closure, session, expected_close)
        elif retained_close is None:
            if (
                type(snapshot) is not ApplicationChannelSnapshot
                or snapshot.identity != application_identity
                or snapshot.closed_at is None
                or snapshot.close_reason != "deadline"
            ):
                raise StateError("Exact SSH application session disappeared before retirement")
            expected_close = self._expected_close_time(snapshot, requested_close)
            if snapshot.closed_at != expected_close:
                raise StateError("Exact SSH application deadline retirement changed its close time")
            self._retain_expected_close(prepared, expected_close, "deadline")
        elif retained_reason is None:
            raise StateError("Exact SSH application retirement lost its close reason")

        self._require_retirement_proof(prepared)
        with self._lock:
            if self._prepared is not prepared:
                raise StateError("Exact SSH close changed its application retirement owner")
            self._retired = True

    def require_retired(self, prepared: _PreparedSshCloseContinuation) -> None:
        """Reauthenticate exact retirement immediately before journal acknowledgement."""

        with self._lock:
            if self._prepared is not prepared or not self._retired:
                raise StateError("Exact SSH application retirement is incomplete")
        prepared.require_application_owner_shape()
        self._require_retirement_proof(prepared)


@dataclass(frozen=True, slots=True)
class _PreparedSshCloseContinuation:
    """Scalar-only close payload plus its exact precommit transaction capture."""

    plan: _PreparedSshClosePlan
    identity_capture: NetworkConnectionIdentityCapture = field(compare=False, repr=False)
    dispatcher_owner: EventDispatcher = field(compare=False, repr=False)
    ecar_owner: object = field(compare=False, repr=False)
    zeek_owner: object = field(compare=False, repr=False)
    ssh_manager_owner: SshApplicationChannelManager = field(compare=False, repr=False)
    application_registry_owner: ApplicationChannelRegistry = field(compare=False, repr=False)
    _binding: _SshCloseContinuationBinding = field(
        default_factory=_SshCloseContinuationBinding,
        compare=False,
        repr=False,
    )
    _progress: _SshCloseProjectionProgress = field(
        default_factory=_SshCloseProjectionProgress,
        compare=False,
        repr=False,
    )
    _receiver_descendants: _SshReceiverDescendantTerminationBinding = field(
        default_factory=_SshReceiverDescendantTerminationBinding,
        compare=False,
        repr=False,
    )
    _application_retirement: _SshApplicationRetirementBinding = field(
        default_factory=_SshApplicationRetirementBinding,
        compare=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        """Reject copied payload shapes before journal capacity is reserved."""

        if type(self.plan) is not _PreparedSshClosePlan:
            raise TypeError("Prepared exact SSH close changed its immutable facts")
        if type(self.identity_capture) is not NetworkConnectionIdentityCapture:
            raise TypeError("Prepared exact SSH close changed its transaction capture")
        self.require_projection_owner_shape()
        self._binding.claim(self)
        self._application_retirement.claim(self)

    def require_application_owner_shape(self) -> None:
        """Require the exact built-in manager and its original shared registry."""

        if (
            type(self.ssh_manager_owner) is not SshApplicationChannelManager
            or type(self.application_registry_owner) is not ApplicationChannelRegistry
            or self.ssh_manager_owner.application_registry is not self.application_registry_owner
        ):
            raise StateError("Exact SSH close requires its original SSH application owner")

    def require_projection_owner_shape(self) -> None:
        """Reject any non-built-in or replaced terminal projection owner."""

        from evidenceforge.generation.emitters.ecar import EcarEmitter
        from evidenceforge.generation.emitters.zeek import ZeekEmitter

        emitters = getattr(self.dispatcher_owner, "emitters", None)
        if (
            type(self.dispatcher_owner) is not EventDispatcher
            or type(emitters) is not dict
            or emitters.get("ecar") is not self.ecar_owner
            or emitters.get("zeek_conn") is not self.zeek_owner
            or type(self.ecar_owner) is not EcarEmitter
            or type(self.zeek_owner) is not ZeekEmitter
            or getattr(self.ecar_owner, "supports_exact_projection_publication", None) is not True
            or getattr(self.zeek_owner, "supports_exact_projection_publication", None) is not True
        ):
            raise StateError("Exact SSH close requires its original eCAR/Zeek projection owners")
        self.require_application_owner_shape()

    def require_projection_owner(self, executor: SshSessionExecutor) -> None:
        """Identity-bind every close retry to its original runtime and dispatcher."""

        if (
            executor.dispatcher is not self.dispatcher_owner
            or executor.state_manager is not self.dispatcher_owner.state_manager
            or executor._source_timing_planner is not self.dispatcher_owner.source_timing_planner
            or executor.timing_runtime is not self.dispatcher_owner.timing_runtime
            or executor._ssh_channel_manager is not self.ssh_manager_owner
            or executor._ssh_channel_manager.application_registry
            is not self.application_registry_owner
        ):
            raise StateError(
                "Exact SSH close crossed its State, timing, dispatcher, or original SSH "
                "application owner"
            )
        self.require_projection_owner_shape()
        self.plan.require_terminal_tail(
            executor._ssh_channel_manager.application_registry.window_end
        )

    def bind(self, transaction: NetworkTransactionPlan) -> _SshCloseContinuation:
        """Bind this exact prepared payload to its captured committed transport."""

        captured = self.identity_capture.transaction
        if captured is None:
            raise StateError("Prepared exact SSH close has no committed transaction")
        if captured is not transaction:
            raise StateError("Prepared exact SSH close crossed its captured transaction")
        continuation = self._binding.bind(self, transaction)
        self._application_retirement.bind(self, transaction)
        return continuation

    def retire_application_session(self, requested_close: datetime) -> None:
        """Retire the exact original SSH manager session through its retained proof."""

        self._application_retirement.retire(self, requested_close)

    def require_application_session_retired(self) -> None:
        """Prove exact original application retirement before journal acknowledgement."""

        self._application_retirement.require_retired(self)

    def authenticates_bound(self, continuation: _SshCloseContinuation) -> bool:
        """Return whether this exact prepared payload created the supplied carrier."""

        return self._binding.authenticates(continuation)

    def retain_projection_failure(self, phase: str, error: BaseException) -> None:
        """Retain one exact terminal projection receipt on the prepared owner."""

        self._progress.retain_failure(phase, error)

    def retain_projection_publication(
        self,
        phase: str,
        receipt: ActionCohortPublicationReceipt,
        result: ActionCohortPublicationResult,
    ) -> None:
        """Retain one committed action cohort directly on its prepared owner."""

        self._progress.retain_publication(phase, receipt, result)

    def bind_projection_phase(
        self,
        phase: str,
        *,
        root_action_id: str,
        state_semantic_id: str,
        occurrence_id: str,
        expected_identity: ProcessIdentity | SessionIdentity,
    ) -> None:
        """Bind a terminal phase to its sole exact action-cohort preimage."""

        self._progress.bind_action_phase(
            phase,
            root_action_id=root_action_id,
            state_semantic_id=state_semantic_id,
            occurrence_id=occurrence_id,
            expected_identity=expected_identity,
        )

    def cancel_projection_phase(self, phase: str) -> None:
        """Release one uncommitted terminal action-cohort binding."""

        self._progress.cancel_action_phase(phase)

    def mark_projection_complete(self, phase: str) -> None:
        """Record one terminal phase whose publisher returned successfully."""

        self._progress.mark_complete(phase)

    def recover_projection(self, phase: str, dispatcher: EventDispatcher) -> bool:
        """Recover one terminal phase from its exact retained dispatcher receipt."""

        return self._progress.recover(phase, dispatcher)

    def receiver_descendant_terminations(
        self,
    ) -> tuple[_SshReceiverDescendantTermination, ...] | None:
        """Return the retained target-process close schedule, when planned."""

        return self._receiver_descendants.retained()

    def bind_receiver_descendant_terminations(
        self,
        entries: tuple[_SshReceiverDescendantTermination, ...],
    ) -> tuple[_SshReceiverDescendantTermination, ...]:
        """Freeze the sole children-first target-process close schedule."""

        return self._receiver_descendants.bind(entries)


@dataclass(frozen=True, slots=True)
class _SshCloseContinuation:
    """Exact journal entry binding one reserved payload to one committed transport."""

    prepared: _PreparedSshCloseContinuation
    transaction: NetworkTransactionPlan

    def __post_init__(self) -> None:
        """Bind the immutable close plan to its exact committed SSH transaction."""

        if type(self.prepared) is not _PreparedSshCloseContinuation:
            raise TypeError("Exact SSH close continuation changed its prepared owner")
        if type(self.transaction) is not NetworkTransactionPlan:
            raise TypeError("Exact SSH close continuation requires one frozen transaction")
        transaction = self.transaction
        plan = self.plan
        if (
            transaction.src_ip != plan.source_ip
            or transaction.src_port != plan.source_port
            or transaction.dst_ip != plan.target_ip
            or transaction.dst_port != 22
            or transaction.protocol != "tcp"
            or transaction.started_at != plan.open_time
            or transaction.closed_at != plan.close_time
        ):
            raise ValueError("Exact SSH close continuation crossed its committed transport")

    @property
    def plan(self) -> _PreparedSshClosePlan:
        """Return the exact immutable close facts reserved before commit."""

        return self.prepared.plan

    @property
    def continuation_id(self) -> str:
        """Return the stable idempotency key used by the generator journal."""

        return self.plan.continuation_id

    @property
    def close_time(self) -> datetime:
        """Return the canonical transport close used for journal ordering."""

        return self.plan.close_time

    def authenticates(self, other: _SshCloseContinuation) -> bool:
        """Return whether another carrier names the same exact owner and facts."""

        return bool(
            type(other) is _SshCloseContinuation
            and other.continuation_id == self.continuation_id
            and other.prepared is self.prepared
            and other.transaction is self.transaction
        )

    def retain_projection_failure(self, phase: str, error: BaseException) -> None:
        """Retain one terminal sink recovery on this exact prepared owner."""

        self.prepared.retain_projection_failure(phase, error)

    def bind_projection_phase(
        self,
        phase: str,
        *,
        root_action_id: str,
        state_semantic_id: str,
        occurrence_id: str,
        expected_identity: ProcessIdentity | SessionIdentity,
    ) -> None:
        """Bind one terminal action cohort before its canonical commit."""

        self.prepared.bind_projection_phase(
            phase,
            root_action_id=root_action_id,
            state_semantic_id=state_semantic_id,
            occurrence_id=occurrence_id,
            expected_identity=expected_identity,
        )

    def cancel_projection_phase(self, phase: str) -> None:
        """Release one terminal binding whose canonical commit did not occur."""

        self.prepared.cancel_projection_phase(phase)

    def retain_projection_publication(
        self,
        phase: str,
        receipt: ActionCohortPublicationReceipt,
        result: ActionCohortPublicationResult,
    ) -> None:
        """Retain one canonical terminal cohort without an exception callback."""

        self.prepared.retain_projection_publication(phase, receipt, result)

    def mark_projection_complete(self, phase: str) -> None:
        """Acknowledge one exact terminal projection phase."""

        self.prepared.mark_projection_complete(phase)

    def recover_projection(self, phase: str, dispatcher: EventDispatcher) -> bool:
        """Resume one terminal sink projection from retained facts and receipt."""

        return self.prepared.recover_projection(phase, dispatcher)

    def receiver_descendant_terminations(
        self,
    ) -> tuple[_SshReceiverDescendantTermination, ...] | None:
        """Return the exact retained target-process schedule, when planned."""

        return self.prepared.receiver_descendant_terminations()

    def bind_receiver_descendant_terminations(
        self,
        entries: tuple[_SshReceiverDescendantTermination, ...],
    ) -> tuple[_SshReceiverDescendantTermination, ...]:
        """Freeze one children-first target-process schedule on this journal owner."""

        return self.prepared.bind_receiver_descendant_terminations(entries)

    def materialize_state(self) -> _SshTransportState:
        """Build fresh mutable compatibility state from immutable committed facts."""

        transaction = self.transaction
        source_identity = self.plan.source_identity
        source_process = (
            None
            if source_identity is None
            else ProcessContext(
                pid=source_identity.pid,
                parent_pid=source_identity.parent_pid,
                image=source_identity.image,
                command_line=source_identity.command_line,
                username=source_identity.principal,
                logon_id=source_identity.logon_id,
                start_time=source_identity.started_at,
            )
        )
        return _SshTransportState(
            rng=random.Random(_stable_seed(f"ssh-close:{self.continuation_id}")),
            source_port=transaction.src_port,
            duration=transaction.duration or 0.0,
            close_time=self.plan.close_time,
            orig_bytes=transaction.orig_bytes,
            resp_bytes=transaction.resp_bytes,
            network_visible=bool(transaction.zeek_uid),
            dst_host=self.plan.target_host.materialize(),
            session_obj_id=self.plan.session_object_id,
            src_host=(
                self.plan.source_host.materialize() if self.plan.source_host is not None else None
            ),
            conn_id=transaction.conn_id,
            uid=transaction.zeek_uid,
            source_process=source_process,
            history=transaction.history,
            orig_pkts=transaction.orig_pkts,
            resp_pkts=transaction.resp_pkts,
            orig_ip_bytes=transaction.orig_ip_bytes,
            resp_ip_bytes=transaction.resp_ip_bytes,
            open_time=transaction.started_at,
            logon_id=self.plan.logon_id,
            transport_id=transaction.stable_id,
        )

    def materialize_bundle(self, executor: SshSessionExecutor) -> SshSessionActionBundle:
        """Build a detached close executor using only the immutable prepared facts."""

        plan = self.plan
        source_identity = plan.source_identity
        request = SshSessionRequest(
            user=plan.user.materialize(),
            target_system=plan.target_system.materialize(),
            time=plan.open_time,
            source_ip=plan.source_ip,
            source_system=(
                plan.source_system.materialize() if plan.source_system is not None else None
            ),
            source_port=plan.source_port,
            source_pid=source_identity.pid if source_identity is not None else -1,
            source_process_image=source_identity.image if source_identity is not None else "",
            duration=self.transaction.duration,
            orig_bytes=self.transaction.orig_bytes,
            resp_bytes=self.transaction.resp_bytes,
            emit_session_close=True,
            defer_session_close=True,
            source=plan.source_tag,
        )
        return SshSessionActionBundle(request=request, executor=executor)

    def materialize_event(self, state: _SshTransportState) -> OccurrenceBuilder:
        """Build a fresh terminal input event without invoking a postcommit callback."""

        return OccurrenceBuilder(
            timestamp=self.plan.auth_state.pam_time,
            event_type="ssh_session",
            src_host=state.src_host,
            dst_host=state.dst_host,
            auth=AuthContext(
                username=self.plan.username,
                source_ip=self.plan.source_ip,
                source_port=self.plan.source_port,
                logon_id=self.plan.logon_id,
                session_id=self.plan.auth_state.logind_session_id,
                logon_type=10,
            ),
            process=state.source_process,
        )


@dataclass(frozen=True, slots=True)
class _FrozenSshTimingDelta:
    """One detached SSH timing value and its deferred logical audit write.

    The compatibility SSH path publishes after its current action succeeds;
    post-mutation rollback remains owned by its later action-cohort migration.
    """

    value: timedelta
    relationship_key: str
    distribution: DistributionSpec
    sampler: TimingSampler

    def publish(self) -> None:
        """Record the already-sampled logical draw through its captured owner."""

        self.sampler.record_logical_sample(
            self.distribution,
            relationship_key=self.relationship_key,
        )


@dataclass(frozen=True, slots=True)
class _SshLinuxAuthPlan:
    """Linux SSH auth ownership that must be known before transport opens."""

    sshd_pid: int
    timing: SshAuthenticationTimingPlan
    timing_runtime: TimingRuntime
    timing_scope: TimingScope
    syslog_seed: tuple[Any, ...]
    ecar_after_accept: _FrozenSshTimingDelta

    @property
    def conn_delay_ms(self) -> float:
        """Return the transport-to-connection phase gap."""

        return self.timing.connection_gap_ms

    @property
    def accepted_gap_ms(self) -> float:
        """Return the complete connection-to-accepted phase gap."""

        return self.timing.accepted_gap_ms

    @property
    def pam_gap_ms(self) -> float:
        """Return the accepted-to-PAM phase gap."""

        return self.timing.pam_gap_ms

    @property
    def logind_gap_ms(self) -> float:
        """Return the PAM-to-logind phase gap."""

        return self.timing.logind_gap_ms


@dataclass(frozen=True, slots=True)
class _PreparedDeferredSshOpen:
    """Allocation-free SSH authority handed to the canonical network owner."""

    authority: DeferredSessionNetworkAuthority
    identity_capture: NetworkConnectionIdentityCapture
    session_plan: SessionMaterializationPlan
    receiver_plan: ProcessMaterializationPlan
    source_identity: ProcessIdentity | None
    source_session_object_id: str
    auth_state: _SshLinuxAuthState
    close_continuation: _PreparedSshCloseContinuation | None


@dataclass(frozen=True, slots=True)
class _SshTimingPreviewRuntime:
    """Detached stateless sampler used before the exact timing owner opens."""

    sampler: TimingSampler


class SshSessionExecutor(Protocol):
    """Adapter protocol implemented by the current activity generator."""

    state_manager: StateManager
    dispatcher: EventDispatcher
    _ip_to_system: dict[str, System]
    _network_visibility: Any
    _source_timing_planner: SourceTimingPlanner
    identity_directory: IdentityDirectory | None
    timing_runtime: TimingRuntime
    _ssh_channel_manager: SshApplicationChannelManager
    _lifecycle_authority: GeneratorLifecycleAuthority

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

    def preview_ssh_source_port(
        self,
        source_ip: str,
        target_ip: str,
        source_port: int | None,
        rng: random.Random,
        source_os: str,
        time: datetime,
    ) -> int:
        """Select a collision-free source port without publishing cache state."""
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
        required_until: datetime | None = None,
    ) -> tuple[int, str] | None:
        """Return or materialize the source-side SSH client process."""
        ...

    def ensure_ssh_client_process(
        self,
        *,
        user: User,
        source_system: System,
        target_system: System,
        time: datetime,
        process_image: str,
        source_port: int,
        required_until: datetime | None = None,
    ) -> tuple[int, str] | None:
        """Return the modeled source-side SSH client for any supported endpoint OS."""
        ...

    def _clamp_after_visible_linux_process_create_with_runtime(
        self,
        system: System,
        pid: int,
        time: datetime,
        relationship_key: str = "source.ecar_dependent_after_process_create",
        *,
        later_source: str | None = None,
        timing_runtime: TimingRuntime | SourceTimingPlanningRuntime,
        timing_scope: TimingScope,
    ) -> datetime:
        """Keep Linux observations visible using one exact injected timing runtime."""
        ...

    def process_source_create_time(self, hostname: str, pid: int) -> datetime | None:
        """Return the latest planned source timestamp for a process creation."""
        ...

    def _plan_process_source_terminate_times(self, event: OccurrenceBuilder) -> None:
        """Stage exact source-native process-termination timing on one builder."""
        ...

    def _commit_exact_ssh_source_process_termination(
        self,
        event: OccurrenceBuilder,
    ) -> None:
        """Adopt exact terminal cache facts only after canonical commit."""
        ...

    def _get_sid(self, username: str) -> str:
        """Return the canonical user SID used by process evidence."""
        ...

    def _defer_ssh_session_close(
        self,
        bundle_or_continuation: SshSessionActionBundle | _SshCloseContinuation,
        state: _SshTransportState | None = None,
        event: OccurrenceBuilder | None = None,
        auth_state: _SshLinuxAuthState | None = None,
    ) -> None:
        """Queue an action-owned SSH closure until dependent generation is complete."""
        ...

    def _reserve_exact_ssh_close_continuation(
        self,
        prepared: _PreparedSshCloseContinuation,
    ) -> None:
        """Reserve bounded journal capacity for one precommit exact close."""
        ...

    def _cancel_exact_ssh_close_continuation_reservation(
        self,
        prepared: _PreparedSshCloseContinuation,
    ) -> None:
        """Release one exact close reservation after a precommit rejection."""
        ...

    def _recover_exact_ssh_close_continuation_no_fail(
        self,
        continuation: _SshCloseContinuation,
    ) -> None:
        """Idempotently install a prevalidated exact close continuation."""
        ...

    def _finalize_exact_ssh_close_continuation(
        self,
        continuation: _SshCloseContinuation,
    ) -> None:
        """Execute and acknowledge one installed immediate-close continuation."""
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

    def _release_session_retention_state(
        self,
        *,
        hostname: str,
        username: str,
        logon_id: str,
    ) -> ActivityGeneratorSessionRetentionRelease:
        """Release exact sudo-TTY state after a complete accepted session close."""
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

    def _timing_planner(self) -> BaselineTimingPlanner:
        """Return the engine planner or one stateless direct-test adapter."""

        runtime = getattr(self.executor, "timing_runtime", None)
        return BaselineTimingPlanner(
            runtime
            if isinstance(runtime, TimingRuntime)
            else TimingRuntime.compatibility_default(),
            source="ssh",
        )

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

        uid, _logon_id = self.execute_with_identity()
        return uid

    def execute_with_identity(self) -> tuple[str, str]:
        """Expand the bundle and return its transport UID and owned session LogonID."""

        if self._uses_exact_deferred_publication():
            owner_rng = _get_rng()
            rng_state_before = owner_rng.getstate()
            state: _SshTransportState | None = None
            prepared: _PreparedDeferredSshOpen | None = None
            transaction: NetworkTransactionPlan | None = None
            continuation: _SshCloseContinuation | None = None
            try:
                state = self._plan_transport(deferred_publication=True)
                prepared = self._prepare_deferred_open(state)
                transaction = self._open_deferred_transport(state, prepared)
                continuation = self._bind_deferred_close_continuation(
                    prepared,
                    transaction,
                )
                if continuation is not None:
                    # This exact journal is the first postcommit owner.  Cache
                    # publication and source teardown are consequences of an
                    # already-durable terminal continuation.
                    self.executor._defer_ssh_session_close(continuation)
                self._remember_deferred_open_tuple(state, prepared)
                if self.request.emit_session_close:
                    close_bundle = (
                        continuation.materialize_bundle(self.executor)
                        if continuation is not None
                        else self
                    )
                    close_bundle._terminate_source_ssh_client_process(
                        state,
                        continuation=continuation,
                    )
                if continuation is not None and not self.request.defer_session_close:
                    self.executor._finalize_exact_ssh_close_continuation(continuation)
            except BaseException as primary:
                committed = bool(
                    prepared is not None and prepared.identity_capture.transaction is not None
                )
                if not committed and prepared is not None:
                    try:
                        live_session = self.executor.state_manager.get_session(
                            prepared.session_plan.identity.logon_id
                        )
                        committed = bool(
                            live_session is not None
                            and live_session.ecar_object_id
                            == prepared.session_plan.identity.object_id
                            and ensure_utc(live_session.start_time)
                            == prepared.session_plan.identity.started_at
                        )
                    except BaseException as recovery_error:
                        self._note_exact_recovery_error(
                            primary,
                            "commit detection",
                            recovery_error,
                        )
                if not committed:
                    if prepared is not None and prepared.close_continuation is not None:
                        try:
                            self.executor._cancel_exact_ssh_close_continuation_reservation(
                                prepared.close_continuation
                            )
                        except BaseException as recovery_error:
                            self._note_exact_recovery_error(
                                primary,
                                "close-reservation cancellation",
                                recovery_error,
                            )
                    try:
                        owner_rng.setstate(rng_state_before)
                    except BaseException as recovery_error:
                        self._note_exact_recovery_error(
                            primary,
                            "precommit RNG rollback",
                            recovery_error,
                        )
                elif state is not None and prepared is not None:
                    self._recover_committed_deferred_open(primary, state, prepared)
                raise
            logger.debug(
                "Generated exact SSH session: %s -> %s (UID: %s)",
                self.request.user.username,
                self.request.target_system.hostname,
                state.uid,
            )
            return (state.uid if state.network_visible else ""), state.logon_id

        ecar_after_accept = self._freeze_linux_ecar_readiness()
        state = self._plan_transport()
        auth_plan = self._prepare_linux_auth_plan(state, ecar_after_accept=ecar_after_accept)
        self._ensure_session_identity(state)
        self._open_transport(
            state,
            responding_pid=auth_plan.sshd_pid if auth_plan is not None else self.request.sshd_pid,
        )
        planning_event = self._build_session_event(state)
        auth_state = self._plan_linux_auth(state, planning_event, auth_plan)
        event = self._build_session_event(state, auth_state)
        if auth_state is not None:
            self._dispatch_linux_connection_message(state, event, auth_state)
            if auth_plan is None:
                raise StateError("SSH auth state lost its frozen timing plan")
            self._mark_edr_login_readiness(
                state,
                event,
                auth_state,
                ecar_after_accept_gap=auth_plan.ecar_after_accept.value,
            )
        self.executor.dispatcher.dispatch_builder(event)
        if self.request.emit_session_close:
            self._terminate_source_ssh_client_process(state)
        if auth_state is not None:
            self._dispatch_linux_auth_messages(state, event, auth_state)
            if self.request.bundle_owns_close:
                if self.request.defer_session_close:
                    self.executor._defer_ssh_session_close(self, state, event, auth_state)
                else:
                    self._dispatch_linux_session_close_lifecycle(state, event, auth_state)
            if auth_plan is None:
                raise StateError("SSH auth completion lost its frozen timing plan")
            auth_plan.ecar_after_accept.publish()

        logger.debug(
            "Generated SSH session: %s -> %s (UID: %s)",
            self.request.user.username,
            self.request.target_system.hostname,
            state.uid,
        )
        return (state.uid if state.network_visible else ""), state.logon_id

    def _remember_deferred_open_tuple(
        self,
        state: _SshTransportState,
        prepared: _PreparedDeferredSshOpen,
    ) -> None:
        """Publish compatibility lookups after the exact owners have committed."""

        self.executor._remember_ssh_responder_pid(
            self.request.source_ip,
            state.source_port,
            state.dst_host.ip,
            prepared.receiver_plan.identity.pid,
        )
        self.executor._remember_ssh_session_ready_time(
            self.request.source_ip,
            state.source_port,
            state.dst_host.ip,
            prepared.auth_state.logind_time,
        )

    def _bind_deferred_close_continuation(
        self,
        prepared: _PreparedDeferredSshOpen,
        transaction: NetworkTransactionPlan,
    ) -> _SshCloseContinuation | None:
        """Bind precommit close facts to the exact committed transport identity."""

        if prepared.close_continuation is None:
            return None
        return prepared.close_continuation.bind(transaction)

    @staticmethod
    def _note_exact_recovery_error(
        primary: BaseException, label: str, error: BaseException
    ) -> None:
        """Annotate, but never replace, the exact postcommit caller exception."""

        primary.add_note(f"Exact SSH {label} recovery also failed: {error!r}")

    def _recover_committed_deferred_open(
        self,
        primary: BaseException,
        state: _SshTransportState,
        prepared: _PreparedDeferredSshOpen,
    ) -> None:
        """Retain close ownership and replay idempotent followups after commit."""

        try:
            transaction = self._adopt_deferred_transport_identity(state, prepared)
            continuation = self._bind_deferred_close_continuation(prepared, transaction)
        except BaseException as error:
            self._note_exact_recovery_error(primary, "identity adoption", error)
            return

        if continuation is not None:
            try:
                self.executor._recover_exact_ssh_close_continuation_no_fail(continuation)
            except BaseException as error:
                self._note_exact_recovery_error(primary, "close-journal", error)
                return

        try:
            self._remember_deferred_open_tuple(state, prepared)
        except BaseException as error:
            self._note_exact_recovery_error(primary, "compatibility-cache", error)
        # Never retry source-native teardown while a sink may still hold an
        # unresolved exact projection.  The already-installed close journal
        # executes the same idempotent teardown after projection recovery and
        # before target-session retirement.

    def _uses_exact_deferred_publication(self) -> bool:
        """Return whether this call has the closed exact SSH source cohort."""

        if (
            self.request.logon_id
            or self.request.session_obj_id
            or self.request.sshd_pid is not None
            or _get_os_category(self.request.target_system.os) != "linux"
        ):
            return False
        if (self.request.source_pid > 0 or self.request.source_process_image) and (
            self._deferred_source_process_binding() is None
        ):
            return False
        dispatcher = getattr(self.executor, "dispatcher", None)
        emitters = getattr(dispatcher, "emitters", None)
        if type(emitters) is not dict:
            return False
        from evidenceforge.generation.emitters.ecar import EcarEmitter
        from evidenceforge.generation.emitters.zeek import ZeekEmitter

        return (
            type(emitters.get("ecar")) is EcarEmitter
            and type(emitters.get("zeek_conn")) is ZeekEmitter
        )

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

    def _deferred_source_process_binding(self) -> tuple[ProcessIdentity, str] | None:
        """Return an exact existing source-process/session binding when authored."""

        request = self.request
        if request.source_pid <= 0:
            return None
        source_system = self._source_system()
        if source_system is None:
            return None
        running = self.executor.state_manager.get_process(
            source_system.hostname,
            request.source_pid,
        )
        if running is None:
            return None
        identity = self.executor.state_manager.get_process_identity(
            source_system.hostname,
            request.source_pid,
        )
        request_time = ensure_utc(request.time)
        if (
            identity is None
            or identity.object_id != running.ecar_object_id
            or identity.started_at != ensure_utc(running.start_time)
            or identity.started_at > request_time
        ):
            return None
        if request.source_process_image and (
            identity.image != request.source_process_image
            or running.image != request.source_process_image
        ):
            return None
        if not identity.logon_id:
            return None
        session = self.executor.state_manager.get_session(identity.logon_id)
        session_identity = self.executor.state_manager.get_session_identity(identity.logon_id)
        if (
            session is None
            or session_identity is None
            or session_identity.object_id != session.ecar_object_id
            or session_identity.hostname != source_system.hostname
            or ensure_utc(session.start_time) > request_time
        ):
            return None
        return identity, session_identity.object_id

    def _exact_deferred_timing_runtime(self) -> TimingRuntime:
        """Require every exact SSH timing owner to share one runtime identity."""

        executor = self.executor
        runtime = getattr(executor, "timing_runtime", None)
        planner = getattr(executor, "_source_timing_planner", None)
        dispatcher = getattr(executor, "dispatcher", None)
        dispatcher_planner = getattr(dispatcher, "source_timing_planner", None)
        dispatcher_runtime = getattr(dispatcher, "timing_runtime", None)
        planner_runtime = getattr(planner, "timing_runtime", None)
        if (
            type(runtime) is not TimingRuntime
            or type(planner) is not SourceTimingPlanner
            or dispatcher_planner is not planner
            or planner_runtime is not runtime
            or dispatcher_runtime is not runtime
        ):
            raise StateError(
                "Exact SSH executor, dispatcher, and source timing planner must share one exact "
                "TimingRuntime"
            )
        return runtime

    def _deferred_receiver_parent(self, receiver_start: datetime) -> tuple[int, str]:
        """Resolve the live canonical global sshd parent, when one exists."""

        hostname = self.request.target_system.hostname
        sys_pids = getattr(self.executor, "_system_pids", {}).get(hostname, {})
        parent_pid = sys_pids.get("sshd")
        if type(parent_pid) is not int or parent_pid <= 0:
            return 0, ""
        running = self.executor.state_manager.get_process(hostname, parent_pid)
        identity = self.executor.state_manager.get_process_identity(hostname, parent_pid)
        if (
            running is None
            or identity is None
            or identity.object_id != running.ecar_object_id
            or identity.started_at != ensure_utc(running.start_time)
            or identity.started_at > ensure_utc(receiver_start)
            or identity.image != "/usr/sbin/sshd"
            or identity.principal.casefold() != "root"
        ):
            return 0, ""
        return identity.pid, identity.lifecycle_group_id

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

    def _plan_transport(self, *, deferred_publication: bool = False) -> _SshTransportState:
        """Plan transport-level identity, byte counts, and host contexts."""

        request = self.request
        rng = _get_rng()
        src_port = (
            self.executor.preview_ssh_source_port(
                request.source_ip,
                request.target_system.ip,
                request.source_port,
                rng,
                self._source_os(),
                request.time,
            )
            if deferred_publication
            else self.executor.reserve_ssh_source_port(
                request.source_ip,
                request.target_system.ip,
                request.source_port,
                rng,
                self._source_os(),
                time=request.time,
            )
        )
        transport_open_time = (
            ensure_utc(request.time)
            if deferred_publication
            else self._transport_open_time(src_port)
        )
        if request.duration is not None:
            duration = max(1.0, request.duration)
        else:
            duration = rng.uniform(30.0, 3600.0)
        if request.min_duration is not None and request.duration is None:
            duration = max(duration, request.min_duration)
        end_plan = request.session_end_plan
        if end_plan is not None and end_plan.is_authoritative:
            close_gap_ms = 100 + (
                _stable_seed(
                    "ssh_transport_before_explicit_logoff:"
                    f"{request.stable_id}:{end_plan.canonical_end.isoformat()}"
                )
                % 1401
            )
            planned_close = ensure_utc(end_plan.canonical_end) - timedelta(
                milliseconds=close_gap_ms
            )
            if planned_close <= ensure_utc(transport_open_time):
                raise StateError(
                    "Explicit SSH session end must follow transport open: "
                    f"{request.target_system.hostname} at {end_plan.canonical_end.isoformat()}"
                )
            # The bundle preserves the authored TCP-open anchor at request.time.
            # The predicted packet timestamp is used for receiver process timing,
            # not as a second canonical start for duration arithmetic.
            duration = (planned_close - ensure_utc(request.time)).total_seconds()
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
            close_time=transport_open_time + timedelta(seconds=duration),
            orig_bytes=max(0, orig_bytes),
            resp_bytes=max(0, resp_bytes),
            network_visible=self._is_network_visible(),
            dst_host=self.executor._build_host_context(request.target_system),
            session_obj_id=request.session_obj_id,
            src_host=self._source_host_context(),
            open_time=transport_open_time,
            logon_id=request.logon_id,
            execution_anchor=ActionAnchor(
                family="ssh_session",
                stable_id=request.execution_stable_id(src_port),
                source=request.source,
            ),
        )

    def _prepare_deferred_close_plan(
        self,
        state: _SshTransportState,
        *,
        session_plan: SessionMaterializationPlan,
        receiver_identity: ProcessIdentity,
        source_identity: ProcessIdentity | None,
        auth_state: _SshLinuxAuthState,
    ) -> _PreparedSshClosePlan | None:
        """Freeze an action-owned close before the network owner may commit."""

        if not self.request.bundle_owns_close:
            return None
        source_process = (
            None
            if source_identity is None
            else ProcessContext(
                pid=source_identity.pid,
                parent_pid=source_identity.parent_pid,
                image=source_identity.image,
                command_line=source_identity.command_line,
                username=source_identity.principal,
                logon_id=source_identity.logon_id,
                start_time=source_identity.started_at,
            )
        )
        planned_state = replace(
            state,
            logon_id=session_plan.identity.logon_id,
            session_obj_id=session_plan.identity.object_id,
            source_process=source_process,
        )
        # This is deliberately the only exact-path invocation. Any custom or
        # malformed event construction fails before State/lifecycle transfer.
        event = self._build_session_event(planned_state, auth_state)
        if (
            type(event) is not OccurrenceBuilder
            or event.event_type != "ssh_session"
            or event.timestamp != auth_state.pam_time
            or type(event.auth) is not AuthContext
            or event.auth.username != self.request.user.username
            or event.auth.source_ip != self.request.source_ip
            or event.auth.source_port != state.source_port
            or event.auth.logon_id != session_plan.identity.logon_id
            or event.auth.session_id != auth_state.logind_session_id
            or type(event.dst_host) is not HostContext
            or event.dst_host.hostname != self.request.target_system.hostname
            or event.dst_host.ip != self.request.target_system.ip
            or event.process != source_process
        ):
            raise StateError("Exact SSH close event changed its precommit semantic facts")
        if event.src_host is not None and type(event.src_host) is not HostContext:
            raise TypeError("Exact SSH close event source host changed exact type")
        source_system = self._source_system()
        transport_close_time = ensure_utc(state.close_time)
        session_close_time = _ssh_source_native_session_close_time(
            target_hostname=self.request.target_system.hostname,
            username=self.request.user.username,
            source_ip=self.request.source_ip,
            source_port=state.source_port,
            sshd_pid=auth_state.sshd_pid,
            transport_close_time=transport_close_time,
        )
        receiver_terminate_time = _ssh_receiver_process_terminate_time(
            target_hostname=self.request.target_system.hostname,
            source_ip=self.request.source_ip,
            source_port=state.source_port,
            sshd_pid=auth_state.sshd_pid,
            receiver_started_at=receiver_identity.started_at,
            session_close_time=session_close_time,
        )
        logind_remove_time = _ssh_logind_removed_time(
            target_hostname=self.request.target_system.hostname,
            username=self.request.user.username,
            source_ip=self.request.source_ip,
            source_port=state.source_port,
            logind_session_id=auth_state.logind_session_id,
            session_close_time=session_close_time,
        )
        source_terminate_time = (
            _ssh_source_process_terminate_time(
                source_hostname=source_identity.hostname,
                source_pid=source_identity.pid,
                source_port=state.source_port,
                target_hostname=self.request.target_system.hostname,
                transport_close_time=transport_close_time,
            )
            if source_identity is not None and _is_ssh_client_image(source_identity.image)
            else None
        )
        return _PreparedSshClosePlan(
            continuation_id=stable_uuid(
                "ssh-deferred-close-continuation",
                session_plan.identity.object_id,
                session_plan.identity.lifecycle_group_id,
            ),
            username=self.request.user.username,
            source_ip=self.request.source_ip,
            target_ip=self.request.target_system.ip,
            source_port=state.source_port,
            open_time=ensure_utc(state.open_time or self.request.time),
            session_started_at=session_plan.identity.started_at,
            close_time=transport_close_time,
            source_terminate_time=source_terminate_time,
            receiver_started_at=receiver_identity.started_at,
            receiver_terminate_time=receiver_terminate_time,
            session_close_time=session_close_time,
            logind_remove_time=logind_remove_time,
            terminal_window_end=(
                self.executor._ssh_channel_manager.application_registry.window_end
            ),
            session_object_id=session_plan.identity.object_id,
            logon_id=session_plan.identity.logon_id,
            session_id=session_plan.identity.session_id,
            session_lifecycle_group_id=session_plan.identity.lifecycle_group_id,
            session_logon_guid=session_plan.identity.logon_guid,
            session_parent_lifecycle_group_id=(session_plan.identity.parent_lifecycle_group_id),
            user=_SshCloseUserFacts.capture(self.request.user),
            source_system=(
                _SshCloseSystemFacts.capture(source_system) if source_system is not None else None
            ),
            target_system=_SshCloseSystemFacts.capture(self.request.target_system),
            source_host=(
                _SshCloseHostFacts.capture(event.src_host) if event.src_host is not None else None
            ),
            target_host=_SshCloseHostFacts.capture(event.dst_host),
            source_identity=source_identity,
            auth_state=auth_state,
            source_tag=self.request.source,
        )

    def _prepare_deferred_open(self, state: _SshTransportState) -> _PreparedDeferredSshOpen:
        """Prepare the exact SSH State/application/dependent handoff without mutation."""

        request = self.request
        executor = self.executor
        timing_runtime = self._exact_deferred_timing_runtime()
        open_time = ensure_utc(state.open_time or request.time)
        execution_id = (
            state.execution_anchor.stable_id
            if state.execution_anchor is not None
            else request.execution_stable_id(state.source_port)
        )
        timing_scope = TimingScope(
            stable_id=execution_id,
            host=request.target_system.hostname,
            source="ssh",
            lifecycle_id=execution_id,
        )
        route_class = "private" if self._source_system() is not None else "public"
        canonical_sampler = timing_runtime.sampler
        if type(canonical_sampler) is not TimingSampler:
            raise StateError("Exact SSH timing preview requires the engine's exact sampler")
        timing_preview = _SshTimingPreviewRuntime(
            TimingSampler(
                namespace=canonical_sampler.namespace,
                generation_seed=canonical_sampler.generation_seed,
            )
        )
        timing = plan_ssh_authentication_timing(
            request.auth_method,
            public_key_type=request.public_key_type,
            route_class=route_class,
            timing_runtime=timing_preview,
            scope=timing_scope,
        )
        session_start = open_time + timedelta(milliseconds=100)
        receiver_start = open_time + timedelta(seconds=2)
        connection_time = receiver_start + timedelta(
            milliseconds=max(1.0, timing.connection_gap_ms)
        )
        accepted_time = connection_time + timedelta(milliseconds=max(250, timing.accepted_gap_ms))
        pam_time = accepted_time + timedelta(milliseconds=max(1, timing.pam_gap_ms))
        logind_time = pam_time + timedelta(milliseconds=max(1, timing.logind_gap_ms))
        if logind_time >= state.close_time:
            raise StateError(
                "Exact SSH transport must remain open through receiver authentication: "
                f"close={state.close_time.isoformat()}, ready={logind_time.isoformat()}"
            )
        if request.session_end_plan is not None and (
            ensure_utc(request.session_end_plan.canonical_end) < state.close_time
        ):
            raise StateError("Exact SSH session end cannot precede its transport close")

        batch_builder = executor.state_manager.begin_materialization_batch()
        session_plan = batch_builder.plan_session(
            username=request.user.username,
            system=request.target_system.hostname,
            logon_type=10,
            source_ip=request.source_ip,
            source_port=state.source_port,
            session_kind="ssh",
            start_time=session_start,
            lifecycle_group_id=execution_id,
            auth_protocol="ssh",
            effective_uid=_linux_uid_for_user(request.user.username),
            effective_gid=_linux_uid_for_user(request.user.username),
            network_close_time=state.close_time,
            source_ready_time=logind_time,
            closure_owned_by_bundle=request.bundle_owns_close,
            end_plan=request.session_end_plan,
        )
        logind_rng = random.Random(
            _stable_seed(
                "ssh_deferred_logind:"
                f"{request.target_system.hostname}:{request.user.username}:"
                f"{request.source_ip}:{state.source_port}:{logind_time.isoformat()}"
            )
        )
        session_plan = batch_builder.enrich_linux_logind_session(
            session_plan,
            rng=logind_rng,
            event_time=logind_time,
        )
        receiver_parent_pid, receiver_parent_group = self._deferred_receiver_parent(receiver_start)
        receiver_plan = batch_builder.plan_process(
            system=request.target_system.hostname,
            parent_pid=receiver_parent_pid,
            image="/usr/sbin/sshd",
            command_line=f"sshd: {request.user.username} [priv]",
            username="root",
            integrity_level="System",
            os_category="linux",
            logon_id=session_plan.identity.logon_id,
            lifecycle_group_id=stable_uuid(
                "ssh-deferred-receiver-lifecycle",
                execution_id,
            ),
            parent_lifecycle_group_id=(
                receiver_parent_group or session_plan.identity.lifecycle_group_id
            ),
            start_time=receiver_start,
            require_session=True,
            session_plan=session_plan,
            auth_session_id=session_plan.identity.session_id,
            auth_logon_type=10,
        )
        batch_builder.bind_session_processes(
            session_plan,
            transport_plan=receiver_plan,
            process_tree_root_plan=receiver_plan,
        )
        batch = batch_builder.seal()
        source_binding = self._deferred_source_process_binding()
        if (request.source_pid > 0 or request.source_process_image) and source_binding is None:
            raise StateError("Exact SSH source process changed before deferred-session preparation")
        source_identity = source_binding[0] if source_binding is not None else None
        source_session_object_id = source_binding[1] if source_binding is not None else ""
        auth_state = _SshLinuxAuthState(
            sshd_pid=receiver_plan.identity.pid,
            logind_session_id=session_plan.identity.session_id,
            syslog_seed=(
                request.target_system.hostname,
                request.source_ip,
                state.source_port,
                receiver_plan.identity.pid,
                request.time.isoformat(),
            ),
            connection_time=connection_time,
            accepted_time=accepted_time,
            pam_time=pam_time,
            logind_time=logind_time,
        )
        close_plan = self._prepare_deferred_close_plan(
            state,
            session_plan=session_plan,
            receiver_identity=receiver_plan.identity,
            source_identity=source_identity,
            auth_state=auth_state,
        )
        identity_capture = NetworkConnectionIdentityCapture()
        close_continuation = (
            _PreparedSshCloseContinuation(
                plan=close_plan,
                identity_capture=identity_capture,
                dispatcher_owner=executor.dispatcher,
                ecar_owner=executor.dispatcher.emitters.get("ecar"),
                zeek_owner=executor.dispatcher.emitters.get("zeek_conn"),
                ssh_manager_owner=executor._ssh_channel_manager,
                application_registry_owner=(executor._ssh_channel_manager.application_registry),
            )
            if close_plan is not None
            else None
        )
        state_authority = executor.state_manager.prepare_deferred_session_state_authority(
            protocol=DeferredSessionProtocol.SSH,
            binding_disposition=DeferredSessionBindingDisposition.NEW_SESSION,
            bound_at=logind_time,
            batch=batch,
        )
        operation_kind = self._deferred_operation_kind()
        application_intent = DeferredSshApplicationIntent(
            manager=executor._ssh_channel_manager,
            target_hostname=session_plan.identity.hostname,
            principal=session_plan.identity.principal,
            client_identity=(
                self._source_system().hostname
                if self._source_system() is not None
                else request.source_ip
            ),
            client_session_object_id=(
                source_session_object_id
                or stable_uuid(
                    "ssh-deferred-client",
                    request.source_ip,
                    state.source_port,
                    execution_id,
                )
            ),
            receiver_identity=receiver_plan.identity,
            receiver_state_session_identity=session_plan.identity,
            source_identity=source_identity,
            source_session_object_id=source_session_object_id,
            ready_at=logind_time,
            auth_method=self._deferred_auth_method(),
            operation_kind=operation_kind,
            semantic_operation_id=stable_uuid(
                "ssh-deferred-operation",
                execution_id,
                operation_kind.value,
            ),
        )
        dependent_occurrences = (
            DeferredSessionDependentOccurrenceSpec(
                occurrence_id=stable_uuid(
                    "ssh-deferred-receiver-occurrence",
                    receiver_plan.identity.object_id,
                ),
                event_type=EventKind.SYSTEM_PROCESS_CREATE,
                canonical_time=receiver_plan.identity.started_at,
                member_references=(receiver_plan.identity.object_id,),
                publication_ordinal=1,
            ),
            DeferredSessionDependentOccurrenceSpec(
                occurrence_id=stable_uuid(
                    "ssh-deferred-login-occurrence",
                    session_plan.identity.object_id,
                ),
                event_type=EventKind.SSH_SESSION,
                canonical_time=logind_time,
                member_references=(session_plan.identity.object_id,),
                publication_ordinal=2,
            ),
        )
        authority = DeferredSessionNetworkAuthority(
            kind=DeferredSessionKind.SSH,
            coordinator=DeferredSessionCompositionCoordinator(kind=DeferredSessionKind.SSH),
            bound_at=logind_time,
            binding_disposition=DeferredSessionBindingDisposition.NEW_SESSION,
            strict_state_authority=state_authority,
            application_intent=application_intent,
            dependent_occurrences=dependent_occurrences,
            ssh_timing_intent=DeferredSshTimingIntent(
                auth_method=request.auth_method,
                public_key_type=request.public_key_type,
                route_class=route_class,
                scope=timing_scope,
                expected_plan=timing,
                transport_open_time=open_time,
                ready_at=logind_time,
            ),
            ssh_timing_runtime=timing_runtime,
        )
        prepared_open = _PreparedDeferredSshOpen(
            authority=authority,
            identity_capture=identity_capture,
            session_plan=session_plan,
            receiver_plan=receiver_plan,
            source_identity=source_identity,
            source_session_object_id=source_session_object_id,
            auth_state=auth_state,
            close_continuation=close_continuation,
        )
        if close_continuation is not None:
            try:
                executor._reserve_exact_ssh_close_continuation(close_continuation)
            except BaseException as primary:
                try:
                    executor._cancel_exact_ssh_close_continuation_reservation(close_continuation)
                except BaseException as recovery_error:
                    self._note_exact_recovery_error(
                        primary,
                        "close-reservation rollback",
                        recovery_error,
                    )
                raise
        return prepared_open

    def _deferred_auth_method(self) -> str:
        """Normalize the bounded SSH manager authentication vocabulary."""

        value = self.request.auth_method.strip().casefold().replace("_", "-")
        aliases = {
            "keyboardinteractive": "keyboard-interactive",
            "gssapi": "gssapi-with-mic",
        }
        return aliases.get(value, value)

    def _deferred_operation_kind(self) -> SshOperationKind:
        """Classify the first synchronous SSH child without source-specific callbacks."""

        executable = self.request.source_process_image.casefold().replace("\\", "/")
        executable = executable.rsplit("/", 1)[-1]
        source = self.request.source.casefold()
        if executable in {"scp", "scp.exe"} or "scp" in source:
            return SshOperationKind.SCP
        if executable in {"sftp", "sftp.exe"} or "sftp" in source:
            return SshOperationKind.SFTP
        return SshOperationKind.SHELL

    def _open_deferred_transport(
        self,
        state: _SshTransportState,
        prepared: _PreparedDeferredSshOpen,
    ) -> NetworkTransactionPlan:
        """Publish one exact transport/session/process/application composition."""

        request = self.request
        if prepared.authority.ssh_timing_runtime is not self._exact_deferred_timing_runtime():
            raise StateError("Exact SSH timing authority changed its runtime owner before use")
        if prepared.close_continuation is not None:
            prepared.close_continuation.require_projection_owner(self.executor)
        uid = self.executor.generate_connection(
            src_ip=request.source_ip,
            dst_ip=request.target_system.ip,
            time=ensure_utc(state.open_time or request.time),
            dst_port=22,
            proto="tcp",
            service="ssh",
            duration=state.duration,
            orig_bytes=state.orig_bytes,
            resp_bytes=state.resp_bytes,
            src_port=state.source_port,
            emit_dns=False,
            pid=(prepared.source_identity.pid if prepared.source_identity is not None else -1),
            source_system=self._source_system(),
            conn_state="SF",
            hostname=state.dst_host.fqdn or request.target_system.hostname,
            process_image=(
                prepared.source_identity.image if prepared.source_identity is not None else None
            ),
            preserve_dst_ip=True,
            responding_pid=prepared.receiver_plan.identity.pid,
            ssh_attempted_username=request.user.username,
            ids_alerts=list(request.ids_alerts),
            preserve_start_time=True,
            suppress_source_pid_inference=True,
            suppress_prereq_dns=True,
            transport_lifecycle_mode="deferred_session",
            deferred_session_authority=prepared.authority,
            identity_capture=prepared.identity_capture,
        )
        transaction = self._adopt_deferred_transport_identity(state, prepared)
        if uid != transaction.zeek_uid:
            raise AssertionError("Exact SSH caller received a different transport identity")
        return transaction

    def _adopt_deferred_transport_identity(
        self,
        state: _SshTransportState,
        prepared: _PreparedDeferredSshOpen,
    ) -> NetworkTransactionPlan:
        """Synchronize mutable compatibility state from one committed exact transport."""

        transaction = prepared.identity_capture.require()
        state.uid = transaction.zeek_uid
        state.network_visible = bool(transaction.zeek_uid)
        state.logon_id = prepared.session_plan.identity.logon_id
        state.session_obj_id = prepared.session_plan.identity.object_id
        state.transport_id = transaction.stable_id
        state.open_time = transaction.started_at
        if transaction.closed_at is not None:
            state.close_time = transaction.closed_at
            state.duration = (transaction.closed_at - transaction.started_at).total_seconds()
        self._sync_transport_from_connection_state(state, transaction.zeek_uid)
        return transaction

    def _ensure_session_identity(self, state: _SshTransportState) -> None:
        """Ensure this SSH action has one canonical session identity."""

        request = self.request
        executor = self.executor
        session_identity = (
            executor.state_manager.get_session_identity(state.logon_id) if state.logon_id else None
        )
        if state.logon_id and session_identity is None:
            raise StateError(
                "SSH bundle logon_id must reference a StateManager-owned session: "
                f"{request.target_system.hostname} {state.logon_id}"
            )
        if session_identity is None:
            state.logon_id = executor.state_manager.create_session(
                username=request.user.username,
                system=request.target_system.hostname,
                logon_type=10,
                source_ip=request.source_ip,
                source_port=state.source_port,
                session_kind="ssh",
                start_time=request.time,
                lifecycle_group_id=(
                    state.execution_anchor.stable_id
                    if state.execution_anchor is not None
                    else request.stable_id
                ),
            )
            session_identity = executor.state_manager.get_session_identity(state.logon_id)
        if session_identity is None:
            raise StateError(
                "SSH bundle could not resolve the session identity it created: "
                f"{request.target_system.hostname} {state.logon_id}"
            )
        if state.session_obj_id and state.session_obj_id != session_identity.object_id:
            raise StateError(
                "SSH bundle session_obj_id contradicts the StateManager-owned session: "
                f"{request.target_system.hostname} {state.logon_id}"
            )
        state.session_obj_id = session_identity.object_id
        if request.session_end_plan is not None:
            executor.state_manager.plan_session_end(state.logon_id, request.session_end_plan)

    def _open_transport(self, state: _SshTransportState, responding_pid: int | None) -> None:
        """Delegate SSH TCP transport to the canonical network connection contract."""

        request = self.request
        executor = self.executor

        source_system = self._source_system()
        source_pid = request.source_pid
        source_process_image = request.source_process_image
        if source_pid <= 0 and source_system is not None:
            client = executor.ensure_ssh_client_process(
                user=request.user,
                source_system=source_system,
                target_system=request.target_system,
                time=request.time,
                process_image=source_process_image or "/usr/bin/ssh",
                source_port=state.source_port,
                required_until=(
                    state.close_time if _get_os_category(source_system.os) == "linux" else None
                ),
            )
            if client is not None:
                source_pid, source_process_image = client

        if source_system is not None and source_pid > 0:
            source_process = executor.state_manager.get_process(source_system.hostname, source_pid)
            source_session_end = None
            if source_process is not None and source_process.logon_id:
                source_end_plan = executor.state_manager.get_session_end_plan(
                    source_process.logon_id
                )
                if source_end_plan is not None and source_end_plan.is_authoritative:
                    source_session_end = ensure_utc(source_end_plan.canonical_end)
                else:
                    source_session_end = executor.state_manager.get_session_end_time(
                        source_process.logon_id
                    )
            if source_session_end is not None and state.close_time >= source_session_end:
                close_margin_ms = 250 + (
                    _stable_seed(
                        "ssh-before-source-session-end:"
                        f"{source_system.hostname}:{source_pid}:{state.source_port}:"
                        f"{source_session_end.isoformat()}"
                    )
                    % 751
                )
                state.close_time = source_session_end - timedelta(milliseconds=close_margin_ms)
                state.duration = max(
                    1.0,
                    (state.close_time - ensure_utc(request.time)).total_seconds(),
                )

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
            ssh_attempted_username=request.user.username,
            ids_alerts=list(request.ids_alerts),
            # The SSH bundle already owns the transport/auth lifecycle anchor.
            # If a source-side client process becomes visible too late, the
            # network contract must omit that attribution instead of moving TCP
            # open behind the receiver sshd child and authentication evidence.
            preserve_start_time=True,
        )
        state.uid = network_uid
        state.network_visible = bool(network_uid)
        if network_uid:
            self._sync_transport_from_connection_state(state, network_uid)

        if state.logon_id:
            executor.state_manager.update_session_metadata(
                state.logon_id,
                source_port=state.source_port,
                session_kind="ssh",
                transport_pid=responding_pid,
                closure_owned_by_bundle=request.bundle_owns_close,
                network_close_time=state.close_time,
            )
            if not state.session_obj_id:
                state.session_obj_id = executor.state_manager.get_session_object_id(state.logon_id)
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
            state.logon_id,
            request.time.isoformat(),
            request.source,
        )

    def _sync_transport_from_connection_state(
        self,
        state: _SshTransportState,
        network_uid: str,
    ) -> None:
        """Copy canonical network ownership details back into the SSH lifecycle state."""

        connection = self.executor.state_manager.get_connection_by_zeek_uid(network_uid)
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
        if state.source_process is None and connection.initiating_pid > 0:
            state.source_process = self._resolve_source_process(
                connection.initiating_pid,
                self.request.source_process_image,
            )

    @staticmethod
    def _exact_terminal_result_authenticates(
        dispatcher: EventDispatcher,
        result: object,
        *,
        phase: str,
        root_action_id: str,
        state_semantic_id: str,
        occurrence_id: str,
        expected_identity: ProcessIdentity | SessionIdentity,
        require_succeeded: bool,
    ) -> bool:
        """Totally validate one exact SSH terminal cohort without consulting State."""

        try:
            if type(result) is not ActionCohortPublicationResult:
                return False
            receipt = result.receipt
            if (
                type(receipt) is not ActionCohortPublicationReceipt
                or not dispatcher.authenticates_action_cohort_publication_receipt(receipt)
                or receipt.root_action_id != root_action_id
                or receipt.state_semantic_id != state_semantic_id
                or receipt.occurrence_ids != (occurrence_id,)
                or result.state.semantic_id != state_semantic_id
                or result.state.started_sessions
                or result.state.started_processes
                or len(result.projections) != 1
                or result.projections[0].occurrence_id != occurrence_id
            ):
                return False
            if require_succeeded and (
                result.projections[0].status != "succeeded"
                or result.projections[0].error is not None
            ):
                return False
            if _is_ssh_process_termination_phase(phase):
                return bool(
                    type(expected_identity) is ProcessIdentity
                    and result.state.terminated_processes == (expected_identity,)
                    and not result.state.terminalized_sessions
                )
            return bool(
                phase == "logout"
                and type(expected_identity) is SessionIdentity
                and not result.state.terminated_processes
                and result.state.terminalized_sessions == (expected_identity,)
            )
        except BaseException:
            return False

    def _publish_exact_ssh_terminal_cohort(
        self,
        *,
        continuation: _SshCloseContinuation,
        phase: str,
        state_plan: object,
        event: OccurrenceBuilder,
        expected_identity: ProcessIdentity | SessionIdentity,
    ) -> ActionCohortPublicationResult:
        """Publish one typed SSH close owner through the exact action-cohort tail."""

        from evidenceforge.generation.actions.command_effects import (
            ExecutionEffectAuditCohortEntry,
            ExecutionEffectPlan,
        )
        from evidenceforge.generation.state_manager import ActionCohortMaterializationPlan

        if (
            type(continuation) is not _SshCloseContinuation
            or not (_is_ssh_process_termination_phase(phase) or phase == "logout")
            or type(state_plan) is not ActionCohortMaterializationPlan
            or type(event) is not OccurrenceBuilder
            or type(expected_identity) not in {ProcessIdentity, SessionIdentity}
        ):
            raise TypeError("Exact SSH terminal cohort received an invalid typed owner")
        continuation.prepared.require_projection_owner(self.executor)
        root_action_id = f"ssh-close:{continuation.continuation_id}:{phase}"
        audit_plan = ExecutionEffectPlan(
            ActionAnchor(
                family="ssh_session",
                stable_id=root_action_id,
                source=continuation.plan.source_tag,
            ),
            (),
        )
        audit_entry = ExecutionEffectAuditCohortEntry(
            audit_plan,
            audit_plan.reconcile(()),
        )
        dispatcher = self.executor.dispatcher
        carrier = None
        timing_preparation = None
        try:
            with dispatcher.source_timing_planner.prepared_planning() as timing_preparation:
                if phase == "source-terminate":
                    self.executor._plan_process_source_terminate_times(event)
                carrier = dispatcher.prepare_action_cohort_projection(
                    event,
                    source_timing_preparation=timing_preparation,
                )
            occurrence_id = dispatcher.action_cohort_projection_occurrence(carrier).occurrence_id
            prepared = dispatcher.bind_action_cohort_projection(
                carrier,
                state_plan=state_plan,
            )
            batch = dispatcher.prepare_action_cohort_batch(
                root_action_id,
                state_plan,
                (prepared,),
                (audit_entry,),
                (),
                (),
                exact_projection=True,
            )
        except BaseException as primary:
            if carrier is not None:
                try:
                    dispatcher.cancel_prepared_action_cohort_projection(carrier)
                except BaseException as cleanup_error:
                    self._note_exact_recovery_error(
                        primary,
                        f"{phase} projection cleanup",
                        cleanup_error,
                    )
            for label, cleanup in (
                ("projection prune", dispatcher.prune_prepared_action_cohort_projections),
                ("batch prune", dispatcher.prune_prepared_action_cohort_batches),
            ):
                try:
                    cleanup()
                except BaseException as cleanup_error:
                    self._note_exact_recovery_error(
                        primary,
                        f"{phase} {label}",
                        cleanup_error,
                    )
            if timing_preparation is not None and not timing_preparation.committed:
                try:
                    timing_preparation.cancel()
                except BaseException as cleanup_error:
                    self._note_exact_recovery_error(
                        primary,
                        f"{phase} timing cleanup",
                        cleanup_error,
                    )
            raise

        capability = None
        try:
            with dispatcher.claimed_action_cohort(batch) as capability:
                continuation.bind_projection_phase(
                    phase,
                    root_action_id=root_action_id,
                    state_semantic_id=state_plan.semantic_id,
                    occurrence_id=occurrence_id,
                    expected_identity=expected_identity,
                )
                result = capability.commit_no_fail()
                if result is not capability.result or not self._exact_terminal_result_authenticates(
                    dispatcher,
                    result,
                    phase=phase,
                    root_action_id=root_action_id,
                    state_semantic_id=state_plan.semantic_id,
                    occurrence_id=occurrence_id,
                    expected_identity=expected_identity,
                    require_succeeded=True,
                ):
                    raise StateError("Exact SSH terminal publisher returned a forged cohort result")
        except BaseException as primary:
            committed_result = capability.result if capability is not None else None
            committed_receipt = capability.receipt if capability is not None else None
            committed = bool(capability is not None and capability.committed)
            authentic_commit = bool(
                committed
                and type(committed_receipt) is ActionCohortPublicationReceipt
                and type(committed_result) is ActionCohortPublicationResult
                and self._exact_terminal_result_authenticates(
                    dispatcher,
                    committed_result,
                    phase=phase,
                    root_action_id=root_action_id,
                    state_semantic_id=state_plan.semantic_id,
                    occurrence_id=occurrence_id,
                    expected_identity=expected_identity,
                    require_succeeded=False,
                )
            )
            if authentic_commit:
                try:
                    continuation.retain_projection_publication(
                        phase,
                        committed_receipt,
                        committed_result,
                    )
                except BaseException as recovery_error:
                    self._note_exact_recovery_error(
                        primary,
                        f"{phase} receipt retention",
                        recovery_error,
                    )
                try:
                    object.__setattr__(
                        primary,
                        "action_cohort_receipt",
                        committed_receipt,
                    )
                    object.__setattr__(
                        primary,
                        "action_cohort_result",
                        committed_result,
                    )
                except BaseException as attachment_error:
                    self._note_exact_recovery_error(
                        primary,
                        f"{phase} receipt attachment",
                        attachment_error,
                    )
                if _is_ssh_process_termination_phase(phase):
                    try:
                        self.executor._commit_exact_ssh_source_process_termination(event)
                    except BaseException as cache_error:
                        self._note_exact_recovery_error(
                            primary,
                            f"{phase} compatibility cache",
                            cache_error,
                        )
            elif not committed:
                try:
                    continuation.cancel_projection_phase(phase)
                except BaseException as cleanup_error:
                    self._note_exact_recovery_error(
                        primary,
                        f"{phase} binding cleanup",
                        cleanup_error,
                    )
            raise

        if _is_ssh_process_termination_phase(phase):
            self.executor._commit_exact_ssh_source_process_termination(event)
        continuation.mark_projection_complete(phase)
        return result

    def _publish_exact_source_process_termination(
        self,
        *,
        continuation: _SshCloseContinuation,
        identity: ProcessIdentity,
        terminate_time: datetime,
        auth_session_id: int,
        auth_logon_type: int,
        concurrency_group_id: str,
        source_session_identity: SessionIdentity | None,
    ) -> None:
        """Commit the live SSH client close and its exact eCAR row atomically."""

        plan = continuation.plan
        source_host = plan.source_host
        if source_host is None:
            raise StateError("Exact SSH source termination lost its frozen host facts")
        state_builder = self.executor.state_manager.begin_action_cohort_materialization()
        if source_session_identity is not None:
            state_builder.patch_session_activity(source_session_identity, terminate_time)
        state_builder.terminate_process(identity, end_time=terminate_time)
        state_plan = state_builder.seal()
        exact_termination = state_plan.process_terminations[0]
        event = OccurrenceBuilder(
            timestamp=exact_termination.end_time,
            event_type="process_terminate",
            src_host=source_host.materialize(),
            auth=AuthContext(
                username=identity.principal,
                user_sid=self.executor._get_sid(identity.principal),
                logon_id=identity.logon_id,
                session_id=auth_session_id,
                logon_type=auth_logon_type,
            ),
            process=ProcessContext(
                pid=identity.pid,
                parent_pid=0,
                image=identity.image,
                command_line="",
                username=identity.principal,
                logon_id=identity.logon_id,
                start_time=identity.started_at,
                concurrency_group_id=concurrency_group_id,
            ),
            storyline_origin=plan.source_tag.startswith("storyline"),
            identity_plan=EventIdentityPlan(
                subject=identity,
                session=source_session_identity,
            ),
            lifecycle=ActionLifecycleContext(
                group_id=identity.lifecycle_group_id,
                canonical_start=identity.started_at,
                phase="closure",
                parent_group_id=identity.parent_lifecycle_group_id or None,
            ),
        )
        self._publish_exact_ssh_terminal_cohort(
            continuation=continuation,
            phase="source-terminate",
            state_plan=state_plan,
            event=event,
            expected_identity=identity,
        )

    def _publish_exact_receiver_process_termination(
        self,
        *,
        continuation: _SshCloseContinuation,
        identity: ProcessIdentity,
        terminate_time: datetime,
        concurrency_group_id: str,
    ) -> None:
        """Commit the session-owned sshd worker close before target logout."""

        plan = continuation.plan
        session_identity = plan.session_identity()
        state_builder = self.executor.state_manager.begin_action_cohort_materialization()
        state_builder.patch_session_activity(session_identity, terminate_time)
        state_builder.terminate_process(identity, end_time=terminate_time)
        state_plan = state_builder.seal()
        exact_termination = state_plan.process_terminations[0]
        event = OccurrenceBuilder(
            timestamp=exact_termination.end_time,
            event_type="process_terminate",
            src_host=plan.target_host.materialize(),
            auth=AuthContext(
                username=identity.principal,
                user_sid=self.executor._get_sid(identity.principal),
                logon_id=identity.logon_id,
                session_id=session_identity.session_id,
                logon_type=10,
            ),
            process=ProcessContext(
                pid=identity.pid,
                parent_pid=0,
                image=identity.image,
                command_line="",
                username=identity.principal,
                logon_id=identity.logon_id,
                start_time=identity.started_at,
                concurrency_group_id=concurrency_group_id,
            ),
            storyline_origin=plan.source_tag.startswith("storyline"),
            identity_plan=EventIdentityPlan(
                subject=identity,
                session=session_identity,
            ),
            lifecycle=ActionLifecycleContext(
                group_id=identity.lifecycle_group_id,
                canonical_start=identity.started_at,
                phase="closure",
                parent_group_id=identity.parent_lifecycle_group_id or None,
            ),
        )
        self._publish_exact_ssh_terminal_cohort(
            continuation=continuation,
            phase="receiver-terminate",
            state_plan=state_plan,
            event=event,
            expected_identity=identity,
        )

    def _publish_exact_receiver_descendant_termination(
        self,
        *,
        continuation: _SshCloseContinuation,
        planned: _SshReceiverDescendantTermination,
    ) -> None:
        """Commit one frozen SSH target-process close and exact eCAR row atomically."""

        plan = continuation.plan
        identity = planned.identity
        session_identity = planned.session_identity
        if (
            identity.hostname != plan.target_system.hostname
            or identity.pid == plan.auth_state.sshd_pid
            or planned.terminate_at >= plan.receiver_terminate_time
        ):
            raise StateError("Exact SSH descendant close crossed its receiver owner")
        state_builder = self.executor.state_manager.begin_action_cohort_materialization()
        if session_identity is not None:
            state_builder.patch_session_activity(session_identity, planned.terminate_at)
        state_builder.terminate_process(identity, end_time=planned.terminate_at)
        state_plan = state_builder.seal()
        exact_termination = state_plan.process_terminations[0]
        event = OccurrenceBuilder(
            timestamp=exact_termination.end_time,
            event_type=EventKind.PROCESS_TERMINATE,
            src_host=plan.target_host.materialize(),
            auth=AuthContext(
                username=identity.principal,
                user_sid=self.executor._get_sid(identity.principal),
                logon_id=identity.logon_id,
                session_id=session_identity.session_id if session_identity is not None else 0,
                logon_type=(
                    10
                    if session_identity is not None and session_identity.session_kind == "ssh"
                    else 2
                ),
            ),
            process=ProcessContext(
                pid=identity.pid,
                parent_pid=identity.parent_pid,
                image=identity.image,
                command_line="",
                username=identity.principal,
                logon_id=identity.logon_id,
                start_time=identity.started_at,
                concurrency_group_id=planned.concurrency_group_id,
            ),
            storyline_origin=plan.source_tag.startswith("storyline"),
            identity_plan=EventIdentityPlan(
                subject=identity,
                session=session_identity,
            ),
            lifecycle=ActionLifecycleContext(
                group_id=identity.lifecycle_group_id,
                canonical_start=identity.started_at,
                phase="closure",
                parent_group_id=identity.parent_lifecycle_group_id or None,
            ),
        )
        self._publish_exact_ssh_terminal_cohort(
            continuation=continuation,
            phase=planned.phase,
            state_plan=state_plan,
            event=event,
            expected_identity=identity,
        )

    def _terminate_source_ssh_client_process(
        self,
        state: _SshTransportState,
        *,
        continuation: _SshCloseContinuation | None = None,
    ) -> None:
        """End a one-transport SSH client immediately after its owned connection."""

        if continuation is not None:
            continuation.prepared.require_projection_owner(self.executor)
        if continuation is not None and continuation.recover_projection(
            "source-terminate",
            self.executor.dispatcher,
        ):
            return
        source_system = self._source_system()
        source_process = state.source_process
        if source_system is None or source_process is None or source_process.pid <= 0:
            if continuation is not None:
                if continuation.plan.source_identity is not None:
                    raise StateError("Exact SSH source teardown lost its prepared process identity")
                continuation.mark_projection_complete("source-terminate")
            return
        if not _is_ssh_client_image(source_process.image):
            if continuation is not None:
                continuation.mark_projection_complete("source-terminate")
            return
        running = self.executor.state_manager.get_process(
            source_system.hostname,
            source_process.pid,
        )
        if running is None:
            if continuation is not None:
                raise StateError(
                    "Exact SSH source teardown lost live State without a projection receipt"
                )
            return
        if (
            running.image != source_process.image
            or running.logon_id != source_process.logon_id
            or (
                source_process.start_time is not None
                and ensure_utc(running.start_time) != ensure_utc(source_process.start_time)
            )
        ):
            # The original one-shot client has already ended and its numeric PID
            # was reused.  Never terminate the foreign live process.
            if continuation is not None:
                raise StateError(
                    "Exact SSH source teardown encountered PID reuse without terminal proof"
                )
            return
        terminate_time = (
            continuation.plan.source_terminate_time
            if continuation is not None
            else _ssh_source_process_terminate_time(
                source_hostname=source_system.hostname,
                source_pid=source_process.pid,
                source_port=state.source_port,
                target_hostname=self.request.target_system.hostname,
                transport_close_time=state.close_time,
            )
        )
        if terminate_time is None:
            raise StateError("Exact SSH source termination lost its frozen terminal time")
        try:
            if continuation is None:
                self.executor.generate_process_termination(
                    user=self.request.user,
                    system=source_system,
                    time=terminate_time,
                    pid=source_process.pid,
                    process_name=running.image,
                    logon_id=running.logon_id,
                    from_storyline=self.request.source.startswith("storyline"),
                )
            else:
                identity = self.executor.state_manager.get_process_identity(
                    source_system.hostname,
                    source_process.pid,
                )
                expected = continuation.plan.source_identity
                if (
                    expected is None
                    or identity != expected
                    or identity.object_id != running.ecar_object_id
                ):
                    raise StateError("Exact SSH source process changed its canonical identity")
                owning_session = self.executor.state_manager.get_session(running.logon_id)
                source_session_identity = self.executor.state_manager.get_session_identity(
                    running.logon_id
                )
                self._publish_exact_source_process_termination(
                    continuation=continuation,
                    identity=identity,
                    terminate_time=terminate_time,
                    auth_session_id=(
                        running.auth_session_id
                        if running.auth_session_id is not None
                        else owning_session.session_id
                        if owning_session is not None
                        else 0
                    ),
                    auth_logon_type=(
                        running.auth_logon_type
                        if running.auth_logon_type is not None
                        else owning_session.logon_type
                        if owning_session is not None
                        else 0
                    ),
                    concurrency_group_id=running.concurrency_group_id,
                    source_session_identity=source_session_identity,
                )
        except BaseException as error:
            if continuation is not None:
                continuation.retain_projection_failure("source-terminate", error)
            raise
        if continuation is not None:
            continuation.mark_projection_complete("source-terminate")

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
    ) -> OccurrenceBuilder:
        """Build the canonical SSH session occurrence.

        The TCP transport is a separate canonical ``connection`` occurrence owned by
        the network-connection bundle. The SSH session event carries only the
        authentication/session facts needed by endpoint session renderers.
        """

        request = self.request
        return OccurrenceBuilder(
            timestamp=auth_state.pam_time if auth_state is not None else request.time,
            event_type="ssh_session",
            src_host=state.src_host,
            dst_host=state.dst_host,
            auth=AuthContext(
                username=request.user.username,
                source_ip=request.source_ip,
                source_port=state.source_port,
                logon_id=state.logon_id,
                session_id=auth_state.logind_session_id if auth_state is not None else 0,
                logon_type=10,
            ),
            process=state.source_process,
        )

    def _plan_linux_auth(
        self,
        state: _SshTransportState,
        event: OccurrenceBuilder,
        plan: _SshLinuxAuthPlan | None,
    ) -> _SshLinuxAuthState | None:
        """Plan Linux SSH auth evidence and destination-side sshd ownership."""

        request = self.request
        executor = self.executor
        if plan is None or not event.dst_host or event.dst_host.os_category != "linux":
            return None

        if state.logon_id:
            executor.state_manager.update_session_metadata(
                state.logon_id,
                transport_pid=plan.sshd_pid,
            )
            responder = executor.state_manager.get_process(
                request.target_system.hostname,
                plan.sshd_pid,
            )
            if responder is not None and not (
                executor.state_manager.assign_process_to_session(
                    request.target_system.hostname,
                    plan.sshd_pid,
                    state.logon_id,
                )
            ):
                raise StateError(
                    "SSH responder could not be attached to its receiver session: "
                    f"{request.target_system.hostname} pid={plan.sshd_pid} "
                    f"logon_id={state.logon_id}"
                )
        resolved_times = self._resolve_linux_auth_lifecycle(
            event=event,
            responder_pid=plan.sshd_pid,
            conn_delay_ms=plan.conn_delay_ms,
            accepted_gap_ms=plan.accepted_gap_ms,
            pam_gap_ms=plan.pam_gap_ms,
            logind_gap_ms=plan.logind_gap_ms,
            transport_open_time=state.open_time or request.time,
            timing_runtime=plan.timing_runtime,
            timing_scope=plan.timing_scope,
        )
        if state.logon_id:
            executor.state_manager.update_session_metadata(
                state.logon_id,
                start_time=resolved_times["pam"],
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
        if state.logon_id:
            executor.state_manager.update_session_metadata(
                state.logon_id,
                session_id=logind_session_id,
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

    def _freeze_linux_ecar_readiness(self) -> _FrozenSshTimingDelta | None:
        """Freeze compatibility EDR readiness before transport planning mutates state."""

        request = self.request
        if _get_os_category(request.target_system.os) != "linux":
            return None
        timing_runtime = getattr(self.executor, "timing_runtime", None)
        if type(timing_runtime) is not TimingRuntime:
            raise StateError("SSH readiness planning requires the executor TimingRuntime")
        timing_scope = TimingScope(
            stable_id=request.stable_id,
            host=request.target_system.hostname,
            source="ssh",
            lifecycle_id=request.stable_id,
        )
        ecar_window = get_timing_window(
            "source.ecar_ssh_session_after_accept",
            default_min_ms=275,
            default_max_ms=650,
            default_position="after",
            default_class="source_latency",
        )
        minimum_us = float(ecar_window.min_ms * 1_000)
        maximum_us = float(ecar_window.max_ms * 1_000)
        if maximum_us <= minimum_us:
            ecar_distribution = ConstantDistribution(minimum_us)
        else:
            maximum_us += 1.0
            ecar_distribution = TriangularDistribution(
                minimum=minimum_us,
                mode=minimum_us + ((maximum_us - minimum_us) * 0.35),
                maximum=maximum_us,
            )
        canonical_sampler = timing_runtime.sampler
        if type(canonical_sampler) is not TimingSampler:
            raise StateError("SSH readiness requires the exact engine timing sampler")
        preview_sampler = TimingSampler(
            namespace=canonical_sampler.namespace,
            generation_seed=canonical_sampler.generation_seed,
        )
        ecar_after_accept_gap = preview_sampler.sample_timedelta(
            ecar_distribution,
            relationship_key="source.ecar_ssh_session_after_accept",
            scope=timing_scope,
            sample_key="ecar_session_ready",
        )
        return _FrozenSshTimingDelta(
            value=ecar_after_accept_gap,
            relationship_key="source.ecar_ssh_session_after_accept",
            distribution=ecar_distribution,
            sampler=canonical_sampler,
        )

    def _prepare_linux_auth_plan(
        self,
        state: _SshTransportState,
        *,
        ecar_after_accept: _FrozenSshTimingDelta | None = None,
    ) -> _SshLinuxAuthPlan | None:
        """Resolve Linux SSH responder identity before opening canonical transport."""

        request = self.request
        if state.dst_host.os_category != "linux":
            return None

        timing_runtime = getattr(self.executor, "timing_runtime", None)
        if type(timing_runtime) is not TimingRuntime:
            raise StateError("SSH authentication planning requires the executor TimingRuntime")
        if ecar_after_accept is None:
            ecar_after_accept = self._freeze_linux_ecar_readiness()
        if ecar_after_accept is None:
            raise StateError("Linux SSH authentication requires frozen EDR readiness")
        execution_id = (
            state.execution_anchor.stable_id
            if state.execution_anchor is not None
            else request.execution_stable_id(state.source_port)
        )
        route_class = "private" if self._source_system() is not None else "public"
        timing_scope = TimingScope(
            stable_id=execution_id,
            host=request.target_system.hostname,
            source="ssh",
            lifecycle_id=execution_id,
        )
        timing = plan_ssh_authentication_timing(
            request.auth_method,
            public_key_type=request.public_key_type,
            route_class=route_class,
            timing_runtime=timing_runtime,
            scope=timing_scope,
        )
        sshd_pid = self._resolve_responder_pid(state, timing.connection_gap_ms)
        return _SshLinuxAuthPlan(
            sshd_pid=sshd_pid,
            timing=timing,
            timing_runtime=timing_runtime,
            timing_scope=timing_scope,
            syslog_seed=(
                request.target_system.hostname,
                request.source_ip,
                state.source_port,
                sshd_pid,
                request.time.isoformat(),
            ),
            ecar_after_accept=ecar_after_accept,
        )

    def _resolve_linux_auth_lifecycle(
        self,
        *,
        event: OccurrenceBuilder,
        responder_pid: int,
        conn_delay_ms: float,
        accepted_gap_ms: float,
        pam_gap_ms: float,
        logind_gap_ms: float,
        transport_open_time: datetime,
        timing_runtime: TimingRuntime | SourceTimingPlanningRuntime,
        timing_scope: TimingScope,
    ) -> dict[str, datetime]:
        """Resolve SSH auth/syslog lifecycle times through the temporal graph."""

        if type(timing_runtime) not in {TimingRuntime, SourceTimingPlanningRuntime}:
            raise StateError("SSH lifecycle resolution requires the exact injected timing runtime")
        if type(timing_scope) is not TimingScope:
            raise StateError("SSH lifecycle resolution requires an exact TimingScope")

        request = self.request
        flow_window = get_timing_window(
            "source.ecar_flow",
            default_min_ms=40,
            default_max_ms=300,
            default_position="after",
            default_class="source_latency",
        )
        canonical_transport_open_time = ensure_utc(transport_open_time)
        canonical_event_time = ensure_utc(event.timestamp)
        canonical_offset_ms = max(
            0,
            math.ceil(
                (canonical_event_time - canonical_transport_open_time).total_seconds() * 1000
            ),
        )
        observation_delay_ms = math.ceil(
            source_observation_delay_difference(
                self.executor,
                earlier_source="ecar",
                later_source="syslog",
            ).total_seconds()
            * 1000
        )
        visibility_floor_ms = max(
            conn_delay_ms,
            canonical_offset_ms + flow_window.max_ms + observation_delay_ms + 25,
        )
        auth_ready_delay_ms = visibility_floor_ms + accepted_gap_ms
        graph = TemporalConstraintGraph(
            timing_runtime=timing_runtime,
            scope=timing_scope,
            relationship_key="ssh.authentication.lifecycle_repair",
        )
        graph.add_node("transport_open", canonical_transport_open_time)
        preferred_connection_time = canonical_transport_open_time + timedelta(
            milliseconds=conn_delay_ms
        )
        connection_time = self.executor._clamp_after_visible_linux_process_create_with_runtime(
            request.target_system,
            responder_pid,
            preferred_connection_time,
            later_source="syslog",
            timing_runtime=timing_runtime,
            timing_scope=timing_scope,
        )
        responder_source_shift = connection_time - preferred_connection_time
        graph.add_node(
            "connection",
            connection_time,
        )
        graph.add_node(
            "accepted",
            canonical_transport_open_time
            + timedelta(milliseconds=auth_ready_delay_ms)
            + responder_source_shift,
        )
        graph.add_node(
            "pam",
            canonical_transport_open_time
            + timedelta(milliseconds=auth_ready_delay_ms + pam_gap_ms)
            + responder_source_shift,
        )
        graph.add_node(
            "logind",
            canonical_transport_open_time
            + timedelta(milliseconds=auth_ready_delay_ms + pam_gap_ms + logind_gap_ms)
            + responder_source_shift,
        )
        graph.constrain_after(
            "connection",
            "transport_open",
            min_gap=timedelta(milliseconds=conn_delay_ms),
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
        event: OccurrenceBuilder,
        earliest_close_time: datetime,
    ) -> None:
        """Extend too-short SSH transport lifetimes to satisfy lifecycle ordering."""

        request = self.request
        if state.close_time >= earliest_close_time:
            return

        state.close_time = earliest_close_time
        state.duration = max(1.0, (state.close_time - request.time).total_seconds())

        if state.logon_id:
            self.executor.state_manager.update_session_metadata(
                state.logon_id,
                network_close_time=state.close_time,
            )

        if state.conn_id:
            connection = self.executor.state_manager.get_connection(state.conn_id)
            if connection is not None:
                connection.close_time = state.close_time

    def _predicted_transport_open_time(self, state: _SshTransportState) -> datetime:
        """Return the single planned source-visible transport anchor for this SSH tuple."""

        if isinstance(state.open_time, datetime):
            return ensure_utc(state.open_time)
        return self._transport_open_time(state.source_port)

    def _transport_open_time(self, source_port: int) -> datetime:
        """Sample one tuple-scoped SSH transport-open time through the engine runtime."""

        request = self.request
        relationship_key = "network.connection_start_jitter"
        window = get_timing_window(
            relationship_key,
            default_min_ms=0,
            default_max_ms=0,
            default_position="after",
        )
        execution_id = request.execution_stable_id(source_port)
        source_host = (
            request.source_system.hostname
            if request.source_system is not None
            else request.source_ip
        )
        network_timing = BaselineTimingPlanner(self._timing_planner().runtime, source="network")
        return request.time + network_timing.packet_observation_delta(
            relationship_key=relationship_key,
            stable_id=f"{execution_id}:transport-open",
            minimum_ms=window.min_ms,
            maximum_ms=window.max_ms,
            host=source_host,
            lifecycle_id=execution_id,
            sample_key="transport_open",
        )

    def _resolve_responder_pid(self, state: _SshTransportState, conn_delay_ms: float) -> int:
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
            transport_open_time = self._predicted_transport_open_time(state)
            return executor.ensure_linux_ssh_responder_process(
                target_system=request.target_system,
                time=transport_open_time + timedelta(milliseconds=max(5, conn_delay_ms - 15)),
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
        event: OccurrenceBuilder,
        auth_state: _SshLinuxAuthState,
    ) -> None:
        """Dispatch the pre-auth sshd connection syslog message."""

        request = self.request
        self.executor.dispatcher.dispatch_builder(
            OccurrenceBuilder(
                timestamp=auth_state.connection_time,
                event_type="syslog",
                src_host=event.dst_host,
                auth=AuthContext(
                    username=request.user.username,
                    source_ip=request.source_ip,
                    source_port=state.source_port,
                    logon_id=state.logon_id,
                    session_id=auth_state.logind_session_id,
                    logon_type=10,
                ),
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
        event: OccurrenceBuilder,
        auth_state: _SshLinuxAuthState,
        *,
        ecar_after_accept_gap: timedelta,
    ) -> None:
        """Record when EDR/session-owned child evidence may appear."""

        request = self.request
        ecar_seed = (
            "login",
            event.dst_host.hostname if event.dst_host else request.target_system.hostname,
            request.user.username,
            request.source_ip,
            state.source_port,
            state.logon_id,
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
            f"{state.source_port}:{state.logon_id}:{request.time.isoformat()}"
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
        if state.logon_id:
            self.executor.state_manager.update_session_metadata(
                state.logon_id,
                source_ready_time=ready_time,
            )

    def _dispatch_linux_auth_messages(
        self,
        state: _SshTransportState,
        event: OccurrenceBuilder,
        auth_state: _SshLinuxAuthState,
    ) -> None:
        """Dispatch accepted-auth, PAM session-open, and logind session messages."""

        request = self.request
        executor = self.executor
        identity_directory = getattr(executor, "identity_directory", None)
        if identity_directory is not None:
            user_uid = identity_directory.linux_uid_for_user(
                request.user.username,
                host=request.target_system.hostname,
            )
        else:
            user_uid = _linux_uid_for_user(request.user.username)
        executor.dispatcher.dispatch_builder(
            OccurrenceBuilder(
                timestamp=auth_state.accepted_time,
                event_type="syslog",
                src_host=event.dst_host,
                auth=AuthContext(
                    username=request.user.username,
                    source_ip=request.source_ip,
                    source_port=state.source_port,
                    logon_id=state.logon_id,
                    session_id=auth_state.logind_session_id,
                    logon_type=10,
                ),
                syslog=SyslogContext(
                    app_name="sshd",
                    pid=auth_state.sshd_pid,
                    facility=10,
                    severity=6,
                    message=self._accepted_auth_message(state),
                ),
            )
        )
        executor.dispatcher.dispatch_builder(
            OccurrenceBuilder(
                timestamp=auth_state.pam_time,
                event_type="syslog",
                src_host=event.dst_host,
                auth=AuthContext(
                    username=request.user.username,
                    source_ip=request.source_ip,
                    source_port=state.source_port,
                    logon_id=state.logon_id,
                    session_id=auth_state.logind_session_id,
                    logon_type=10,
                ),
                syslog=SyslogContext(
                    app_name="sshd",
                    pid=auth_state.sshd_pid,
                    facility=10,
                    severity=6,
                    message=(
                        "pam_unix(sshd:session): session opened for user "
                        f"{request.user.username}(uid={user_uid}) "
                        "by (uid=0)"
                    ),
                ),
            )
        )
        hostname = request.target_system.hostname
        session_id = auth_state.logind_session_id
        executor.dispatcher.dispatch_builder(
            OccurrenceBuilder(
                timestamp=auth_state.logind_time,
                event_type="syslog",
                src_host=event.dst_host,
                auth=AuthContext(
                    username=request.user.username,
                    source_ip=request.source_ip,
                    source_port=state.source_port,
                    logon_id=state.logon_id,
                    session_id=session_id,
                    logon_type=10,
                ),
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
        event: OccurrenceBuilder,
        auth_state: _SshLinuxAuthState,
        *,
        continuation: _SshCloseContinuation | None = None,
    ) -> None:
        """Dispatch source-native close/logout evidence for a modeled SSH session."""

        if continuation is not None:
            continuation.prepared.require_projection_owner(self.executor)
        logout_complete = bool(
            continuation is not None
            and continuation.recover_projection("logout", self.executor.dispatcher)
        )
        if continuation is not None and not logout_complete:
            session = self.executor.state_manager.get_session(state.logon_id)
            if session is None:
                raise StateError(
                    "Exact SSH close lost live session State without a retained logout receipt"
                )
            if (
                session.ecar_object_id != continuation.plan.session_object_id
                or session.username != continuation.plan.username
                or session.system != continuation.plan.target_host.hostname
                or ensure_utc(session.start_time) != continuation.plan.session_started_at
            ):
                raise StateError("Exact SSH close continuation crossed its live session owner")
        close_time = (
            continuation.plan.session_close_time
            if continuation is not None
            else self._source_native_session_close_time(state, auth_state)
        )
        if not logout_complete:
            self._retire_exact_application_session(
                state,
                close_time,
                continuation=continuation,
            )
            if continuation is None:
                self._terminate_receiver_session_children(state, auth_state, close_time)
                self._terminate_receiver_session_shell(state, close_time)
            else:
                self._terminate_exact_receiver_descendants(
                    state,
                    auth_state,
                    continuation,
                )
            # A real dispatcher applies the logoff to StateManager immediately.
            # Capture and schedule responder termination before that logoff
            # consumes the live session/process graph.
            self._terminate_receiver_sshd_process(
                state,
                auth_state,
                close_time,
                continuation=continuation,
            )
            try:
                self._dispatch_linux_session_logout(
                    state,
                    event,
                    auth_state,
                    close_time,
                    continuation=continuation,
                )
            except BaseException as error:
                if continuation is not None:
                    continuation.retain_projection_failure("logout", error)
                raise
            if continuation is not None:
                continuation.mark_projection_complete("logout")

        logind_complete = bool(
            continuation is not None
            and continuation.recover_projection("logind-remove", self.executor.dispatcher)
        )
        if not logind_complete:
            try:
                self._dispatch_linux_logind_removed(
                    state,
                    event,
                    auth_state,
                    close_time,
                    continuation=continuation,
                )
            except BaseException as error:
                if continuation is not None:
                    continuation.retain_projection_failure("logind-remove", error)
                raise
            if continuation is not None:
                continuation.mark_projection_complete("logind-remove")

        if continuation is None:
            self.executor._release_session_retention_state(
                hostname=self.request.target_system.hostname,
                username=self.request.user.username,
                logon_id=state.logon_id,
            )

    def _dispatch_linux_session_logout(
        self,
        state: _SshTransportState,
        event: OccurrenceBuilder,
        auth_state: _SshLinuxAuthState,
        close_time: datetime,
        *,
        continuation: _SshCloseContinuation | None = None,
    ) -> None:
        """Publish the immutable target LOGOUT occurrence."""

        request = self.request
        logout_event = OccurrenceBuilder(
            timestamp=close_time,
            event_type="logoff",
            dst_host=(
                continuation.plan.target_host.materialize()
                if continuation is not None
                else event.dst_host
            ),
            auth=AuthContext(
                username=(
                    continuation.plan.username
                    if continuation is not None
                    else request.user.username
                ),
                source_ip=(
                    continuation.plan.source_ip if continuation is not None else request.source_ip
                ),
                source_port=(
                    continuation.plan.source_port if continuation is not None else state.source_port
                ),
                logon_id=(
                    continuation.plan.logon_id if continuation is not None else state.logon_id
                ),
                session_id=(
                    continuation.plan.session_id
                    if continuation is not None
                    else auth_state.logind_session_id
                ),
                logon_type=10,
            ),
            syslog=SyslogContext(
                app_name="sshd",
                pid=(
                    continuation.plan.auth_state.sshd_pid
                    if continuation is not None
                    else auth_state.sshd_pid
                ),
                facility=10,
                severity=6,
                message=(
                    "pam_unix(sshd:session): session closed for user "
                    f"{continuation.plan.username if continuation is not None else request.user.username}"
                ),
            ),
        )
        if continuation is None:
            self.executor.dispatcher.dispatch_builder(logout_event)
            return
        identity = continuation.plan.session_identity()
        retained_identity = self.executor.state_manager.get_session_identity(identity.logon_id)
        if retained_identity != identity:
            raise StateError("Exact SSH logout changed its canonical session identity")
        state_builder = self.executor.state_manager.begin_action_cohort_materialization()
        state_builder.terminalize_session(identity, end_time=close_time)
        state_plan = state_builder.seal()
        logout_event.identity_plan = EventIdentityPlan(subject=identity, session=identity)
        logout_event.lifecycle = ActionLifecycleContext(
            group_id=identity.lifecycle_group_id,
            canonical_start=identity.started_at,
            phase="closure",
            parent_group_id=identity.parent_lifecycle_group_id or None,
        )
        self._publish_exact_ssh_terminal_cohort(
            continuation=continuation,
            phase="logout",
            state_plan=state_plan,
            event=logout_event,
            expected_identity=identity,
        )

    def _dispatch_linux_logind_removed(
        self,
        state: _SshTransportState,
        event: OccurrenceBuilder,
        auth_state: _SshLinuxAuthState,
        close_time: datetime,
        *,
        continuation: _SshCloseContinuation | None = None,
    ) -> None:
        """Publish the immutable post-logout systemd-logind occurrence."""

        request = self.request
        target_hostname = (
            continuation.plan.target_system.hostname
            if continuation is not None
            else request.target_system.hostname
        )
        session_id = (
            continuation.plan.session_id
            if continuation is not None
            else auth_state.logind_session_id
        )
        self.executor.dispatcher.dispatch_builder(
            OccurrenceBuilder(
                timestamp=(
                    continuation.plan.logind_remove_time
                    if continuation is not None
                    else self._source_native_logind_removed_time(state, auth_state, close_time)
                ),
                event_type="syslog",
                src_host=(
                    continuation.plan.target_host.materialize()
                    if continuation is not None
                    else event.dst_host
                ),
                auth=AuthContext(
                    username=(
                        continuation.plan.username
                        if continuation is not None
                        else request.user.username
                    ),
                    source_ip=(
                        continuation.plan.source_ip
                        if continuation is not None
                        else request.source_ip
                    ),
                    source_port=(
                        continuation.plan.source_port
                        if continuation is not None
                        else state.source_port
                    ),
                    logon_id=(
                        continuation.plan.logon_id if continuation is not None else state.logon_id
                    ),
                    session_id=session_id,
                    logon_type=10,
                ),
                syslog=SyslogContext(
                    app_name="systemd-logind",
                    pid=self.executor._get_system_pid(
                        target_hostname,
                        "logind",
                        456,
                    ),
                    facility=10,
                    severity=6,
                    message=f"Removed session {session_id}.",
                ),
            )
        )

    def _retire_exact_application_session(
        self,
        state: _SshTransportState,
        close_time: datetime,
        *,
        continuation: _SshCloseContinuation | None = None,
    ) -> None:
        """Retire the exact SSH sidecar before publishing its endpoint close."""

        if continuation is not None:
            continuation.prepared.require_projection_owner(self.executor)
            continuation.prepared.retire_application_session(close_time)
            return
        if not state.transport_id:
            return
        manager = self.executor._ssh_channel_manager
        session = manager.find_by_transport(state.transport_id)
        if session is None:
            return
        manager.close_session(
            session.channel_id,
            closed_at=close_time,
            reason="bundle_close",
        )

    def _plan_exact_receiver_descendant_terminations(
        self,
        state: _SshTransportState,
        auth_state: _SshLinuxAuthState,
        continuation: _SshCloseContinuation,
    ) -> tuple[_SshReceiverDescendantTermination, ...]:
        """Freeze all SSH target processes in structural children-first order."""

        plan = continuation.plan
        authority = self.executor._lifecycle_authority
        expected_session_identity = plan.session_identity()
        receiver = self.executor.state_manager.get_process(
            plan.target_system.hostname,
            auth_state.sshd_pid,
        )
        receiver_identity = self.executor.state_manager.get_process_identity(
            plan.target_system.hostname,
            auth_state.sshd_pid,
        )
        receiver_snapshot = (
            authority.registry.get_process(receiver_identity.object_id)
            if receiver_identity is not None
            else None
        )
        if (
            auth_state != plan.auth_state
            or ensure_utc(state.close_time) != plan.close_time
            or receiver is None
            or receiver_identity is None
            or receiver_snapshot is None
            or receiver_snapshot.closed_at is not None
            or receiver_snapshot.close_barrier is not None
            or receiver_snapshot.closure_ticket is not None
            or receiver.ecar_object_id != receiver_identity.object_id
            or receiver_identity.hostname != plan.target_system.hostname
            or receiver_identity.pid != auth_state.sshd_pid
            or receiver_identity.image != "/usr/sbin/sshd"
            or receiver_identity.principal.casefold() != "root"
            or receiver_identity.started_at != plan.receiver_started_at
            or receiver_identity.logon_id != plan.logon_id
            or receiver.logon_id != plan.logon_id
            or receiver.token_logon_id != plan.logon_id
            or receiver.auth_session_id != plan.session_id
            or receiver.auth_logon_type != 10
            or receiver_snapshot.identity.object_id != receiver_identity.object_id
            or receiver_snapshot.identity.hostname != receiver_identity.hostname
            or receiver_snapshot.identity.pid != receiver_identity.pid
            or receiver_snapshot.identity.image != receiver_identity.image
            or receiver_snapshot.identity.started_at != receiver_identity.started_at
            or receiver_snapshot.token.logon_id != plan.logon_id
            or receiver_snapshot.token.session_id != plan.session_id
            or receiver_snapshot.token.logon_type != 10
            or receiver_snapshot.membership.owner_kind != "session"
            or receiver_snapshot.membership.owner_object_id != plan.session_object_id
            or receiver_snapshot.membership.session_object_id != plan.session_object_id
            or self.executor.state_manager.get_session_identity(plan.logon_id)
            != expected_session_identity
        ):
            raise StateError("Exact SSH descendant planning lost its live receiver identity")

        snapshots = {
            snapshot.identity.object_id: snapshot
            for snapshot in authority.live_process_descendant_postorder(
                receiver_identity.object_id,
                limit=_SSH_RECEIVER_DESCENDANT_CAPACITY,
            )
        }
        members = authority.live_session_member_process_census(
            plan.target_system.hostname,
            plan.logon_id,
            limit=_SSH_RECEIVER_DESCENDANT_CAPACITY,
        )
        for member in members:
            object_id = member.identity.object_id
            if object_id == receiver_identity.object_id:
                continue
            if object_id in snapshots:
                if snapshots[object_id] != member:
                    raise StateError(
                        f"Exact SSH lifecycle process {object_id} changed during census"
                    )
                continue
            snapshots[object_id] = member
            for descendant in authority.live_process_descendant_postorder(
                object_id,
                limit=_SSH_RECEIVER_DESCENDANT_CAPACITY,
            ):
                descendant_id = descendant.identity.object_id
                retained = snapshots.get(descendant_id)
                if retained is not None and retained != descendant:
                    raise StateError(
                        f"Exact SSH lifecycle process {descendant_id} changed during census"
                    )
                snapshots.setdefault(descendant_id, descendant)
            if len(snapshots) > _SSH_RECEIVER_DESCENDANT_CAPACITY:
                raise StateError("Exact SSH descendant schedule exceeds its bounded capacity")

        for snapshot in snapshots.values():
            if (
                snapshot.token.logon_id != plan.logon_id
                or snapshot.membership.owner_kind != "session"
                or snapshot.membership.owner_object_id != plan.session_object_id
                or snapshot.membership.session_object_id != plan.session_object_id
            ):
                raise StateError(
                    "Exact SSH lifecycle target crossed its session owner: "
                    f"process={snapshot.identity.object_id}"
                )

        def structural_depth(object_id: str) -> int:
            depth = 0
            seen: set[str] = set()
            current = snapshots.get(object_id)
            while current is not None:
                current_id = current.identity.object_id
                if current_id in seen:
                    raise StateError(
                        f"Exact SSH descendant ancestry cycle detected at process {current_id}"
                    )
                seen.add(current_id)
                parent = snapshots.get(current.identity.parent_object_id)
                if parent is None:
                    break
                depth += 1
                current = parent
            return depth

        ordered = sorted(
            snapshots.values(),
            key=lambda snapshot: (
                structural_depth(snapshot.identity.object_id),
                snapshot.identity.started_at,
                snapshot.identity.pid,
            ),
            reverse=True,
        )
        receiver_terminate_at = plan.receiver_terminate_time
        retained_receiver_child_close = authority.process_latest_closed_child_at_for_object(
            receiver_identity.object_id
        )
        if (
            retained_receiver_child_close is not None
            and retained_receiver_child_close >= receiver_terminate_at
        ):
            raise StateError("Exact SSH retained child close does not precede its receiver")
        transport_close_at = plan.close_time
        available = receiver_terminate_at - transport_close_at
        if ordered and available <= timedelta(0):
            raise StateError("Exact SSH receiver has no structural descendant close interval")
        step = available / max(2, len(ordered) + 1)
        prior = transport_close_at
        planned: list[_SshReceiverDescendantTermination] = []
        for ordinal, snapshot in enumerate(ordered, start=1):
            if snapshot.close_barrier is not None or snapshot.closure_ticket is not None:
                raise StateError(
                    "Exact SSH descendant entered finalization with a prior close ticket: "
                    f"process={snapshot.identity.object_id}"
                )
            running = self.executor.state_manager.get_process(
                snapshot.identity.hostname,
                snapshot.identity.pid,
            )
            identity = self.executor.state_manager.get_process_identity(
                snapshot.identity.hostname,
                snapshot.identity.pid,
            )
            if (
                running is None
                or identity is None
                or identity.object_id != snapshot.identity.object_id
                or identity.hostname != snapshot.identity.hostname
                or identity.pid != snapshot.identity.pid
                or identity.image != snapshot.identity.image
                or identity.started_at != snapshot.identity.started_at
                or identity.principal != snapshot.token.principal
                or identity.logon_id != plan.logon_id
                or running.logon_id != plan.logon_id
                or running.token_logon_id != snapshot.token.logon_id
                or running.auth_session_id != snapshot.token.session_id
                or running.auth_logon_type != snapshot.token.logon_type
            ):
                raise StateError(
                    "Exact SSH lifecycle descendant disagrees with live State identity: "
                    f"process={snapshot.identity.object_id}"
                )
            owning_session = self.executor.state_manager.get_session_identity(running.logon_id)
            if (
                owning_session != expected_session_identity
                or self.executor.state_manager.get_session(running.logon_id) is None
            ):
                raise StateError(
                    "Exact SSH State target crossed its session owner: "
                    f"process={snapshot.identity.object_id}"
                )
            retained_child_close = authority.process_latest_closed_child_at_for_object(
                snapshot.identity.object_id
            )
            minimum = max(
                transport_close_at,
                identity.started_at,
                ensure_utc(running.last_activity_time or identity.started_at),
                ensure_utc(snapshot.latest_dependent_at or identity.started_at)
                + timedelta(microseconds=1),
                ensure_utc(snapshot.latest_hold_until or identity.started_at)
                + timedelta(microseconds=1),
                ensure_utc(retained_child_close or identity.started_at) + timedelta(microseconds=1),
                prior,
            )
            terminate_at = max(transport_close_at + step * ordinal, minimum)
            if terminate_at >= receiver_terminate_at:
                raise StateError(
                    "Exact SSH descendant cannot terminate before its receiver parent: "
                    f"process={identity.object_id} "
                    f"process_close={terminate_at.isoformat()} "
                    f"receiver_close={receiver_terminate_at.isoformat()}"
                )
            planned.append(
                _SshReceiverDescendantTermination(
                    identity=identity,
                    terminate_at=terminate_at,
                    concurrency_group_id=running.concurrency_group_id,
                    session_identity=owning_session,
                )
            )
            prior = terminate_at + timedelta(microseconds=1)
        return continuation.bind_receiver_descendant_terminations(tuple(planned))

    def _terminate_exact_receiver_descendants(
        self,
        state: _SshTransportState,
        auth_state: _SshLinuxAuthState,
        continuation: _SshCloseContinuation,
    ) -> None:
        """Publish the frozen SSH target-process schedule before receiver close."""

        planned = continuation.receiver_descendant_terminations()
        if planned is None:
            planned = self._plan_exact_receiver_descendant_terminations(
                state,
                auth_state,
                continuation,
            )
        for entry in planned:
            if continuation.recover_projection(entry.phase, self.executor.dispatcher):
                continue
            running = self.executor.state_manager.get_process(
                entry.identity.hostname,
                entry.identity.pid,
            )
            identity = self.executor.state_manager.get_process_identity(
                entry.identity.hostname,
                entry.identity.pid,
            )
            if (
                running is None
                or identity is None
                or identity != entry.identity
                or running.ecar_object_id != entry.identity.object_id
            ):
                raise StateError(
                    "Exact SSH descendant lost live State without a retained receipt: "
                    f"process={entry.identity.object_id}"
                )
            try:
                self._publish_exact_receiver_descendant_termination(
                    continuation=continuation,
                    planned=entry,
                )
            except BaseException as error:
                continuation.retain_projection_failure(entry.phase, error)
                raise

        receiver_identity = self.executor.state_manager.get_process_identity(
            continuation.plan.target_system.hostname,
            auth_state.sshd_pid,
        )
        if receiver_identity is None:
            raise StateError("Exact SSH descendant census lost its receiver identity")
        live_children = self.executor._lifecycle_authority.live_child_process_page_for_object(
            receiver_identity.object_id,
            limit=1,
        )
        live_members = self.executor._lifecycle_authority.live_session_member_process_census(
            continuation.plan.target_system.hostname,
            continuation.plan.logon_id,
            limit=_SSH_RECEIVER_DESCENDANT_CAPACITY,
        )
        residual_members = tuple(
            member
            for member in live_members
            if member.identity.object_id != receiver_identity.object_id
        )
        if live_children or residual_members:
            residual = tuple(
                sorted(
                    {
                        *(child.identity.object_id for child in live_children),
                        *(member.identity.object_id for member in residual_members),
                    }
                )
            )
            raise StateError(
                "Exact SSH target-process terminal census retained live descendants: "
                f"receiver={receiver_identity.object_id} residual={residual!r}"
            )

    def _terminate_receiver_session_children(
        self,
        state: _SshTransportState,
        auth_state: _SshLinuxAuthState,
        close_time: datetime,
    ) -> None:
        """End residual commands before their owning SSH session closes."""
        if not state.logon_id:
            return
        request = self.request
        session = self.executor.state_manager.get_session(state.logon_id)
        shell_pid = session.session_shell_pid if session is not None else None
        children = [
            process
            for process in self.executor.state_manager.get_processes_for_session(
                state.logon_id,
                request.target_system.hostname,
            )
            if process.pid not in {shell_pid, auth_state.sshd_pid}
        ]
        children.sort(key=lambda process: process.start_time, reverse=True)
        for ordinal, process in enumerate(children):
            terminate_time = close_time - timedelta(milliseconds=50 + (ordinal * 25))
            terminate_time = max(
                process.start_time + timedelta(milliseconds=100),
                terminate_time,
            )
            if terminate_time >= close_time:
                terminate_time = close_time - timedelta(milliseconds=1)
            self.executor.generate_process_termination(
                user=request.user,
                system=request.target_system,
                time=terminate_time,
                pid=process.pid,
                process_name=process.image,
                logon_id=process.logon_id,
                from_storyline=request.source.startswith("storyline"),
                session_end_plan=session.end_plan if session is not None else None,
            )

    def _terminate_receiver_session_shell(
        self,
        state: _SshTransportState,
        close_time: datetime,
    ) -> None:
        """End the bundle-owned login shell before the SSH session closes."""

        request = self.request
        if not state.logon_id:
            return
        session = self.executor.state_manager.get_session(state.logon_id)
        shell_pid = session.session_shell_pid if session is not None else None
        if shell_pid is None:
            return
        running = self.executor.state_manager.get_process(
            request.target_system.hostname,
            shell_pid,
        )
        if running is None:
            return
        seed = _stable_seed(
            "ssh_session_shell_terminate:"
            f"{request.target_system.hostname}:{state.logon_id}:{shell_pid}:"
            f"{state.close_time.isoformat()}"
        )
        gap = close_time - state.close_time
        maximum_offset_ms = max(20, int(gap.total_seconds() * 1000) - 25)
        terminate_time = state.close_time + timedelta(
            milliseconds=20 + (seed % max(1, maximum_offset_ms - 19)),
            microseconds=101 + (seed % 733),
        )
        if terminate_time >= close_time:
            terminate_time = close_time - timedelta(milliseconds=1)
        self.executor.generate_process_termination(
            user=request.user,
            system=request.target_system,
            time=terminate_time,
            pid=shell_pid,
            process_name=running.image,
            logon_id=running.logon_id,
            from_storyline=request.source.startswith("storyline"),
        )

    def _terminate_receiver_sshd_process(
        self,
        state: _SshTransportState,
        auth_state: _SshLinuxAuthState,
        close_time: datetime,
        *,
        continuation: _SshCloseContinuation | None = None,
    ) -> None:
        """Emit receiver-side accepted sshd termination when the tuple child is modeled."""

        if continuation is not None and continuation.recover_projection(
            "receiver-terminate",
            self.executor.dispatcher,
        ):
            return
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
        # PAM close has its own source-native delay (up to 2.5 seconds) before
        # collection delay is applied.  Leave a real teardown tail so an eCAR
        # process-termination observation cannot render before the same PID's
        # syslog PAM-close record merely because the two sources sampled
        # different latency values.
        if continuation is None:
            terminate_time = close_time + timedelta(
                milliseconds=3200 + (seed % 2000),
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
            return
        terminate_time = continuation.plan.receiver_terminate_time
        if terminate_time >= close_time:
            raise StateError("Exact SSH receiver lifetime leaves no interval before logout")
        identity = self.executor.state_manager.get_process_identity(
            request.target_system.hostname,
            auth_state.sshd_pid,
        )
        if (
            identity is None
            or identity.object_id != running.ecar_object_id
            or identity.image != "/usr/sbin/sshd"
            or identity.started_at != ensure_utc(running.start_time)
        ):
            raise StateError("Exact SSH receiver changed its canonical process identity")
        try:
            self._publish_exact_receiver_process_termination(
                continuation=continuation,
                identity=identity,
                terminate_time=terminate_time,
                concurrency_group_id=running.concurrency_group_id,
            )
        except BaseException as error:
            continuation.retain_projection_failure("receiver-terminate", error)
            raise

    def _source_native_session_close_time(
        self,
        state: _SshTransportState,
        auth_state: _SshLinuxAuthState,
    ) -> datetime:
        """Return a PAM close time compatible with, but not identical to, transport close."""

        request = self.request
        return _ssh_source_native_session_close_time(
            target_hostname=request.target_system.hostname,
            username=request.user.username,
            source_ip=request.source_ip,
            source_port=state.source_port,
            sshd_pid=auth_state.sshd_pid,
            transport_close_time=state.close_time,
        )

    def _source_native_logind_removed_time(
        self,
        state: _SshTransportState,
        auth_state: _SshLinuxAuthState,
        close_time: datetime,
    ) -> datetime:
        """Return systemd-logind removal time for the same visible SSH session ID."""

        request = self.request
        return _ssh_logind_removed_time(
            target_hostname=request.target_system.hostname,
            username=request.user.username,
            source_ip=request.source_ip,
            source_port=state.source_port,
            logind_session_id=auth_state.logind_session_id,
            session_close_time=close_time,
        )
