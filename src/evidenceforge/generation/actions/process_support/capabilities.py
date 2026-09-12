# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Typed cross-family callbacks consumed by process operations."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol

from evidenceforge.events.contexts import HostContext
from evidenceforge.events.lifecycle import SessionEndPlan
from evidenceforge.generation.actions import NmapCommandProbeRequest
from evidenceforge.generation.actions.process_execution import ProcessTerminationRequest
from evidenceforge.generation.source_timing import SourceTimingPlanningRuntime
from evidenceforge.generation.timing import TimingRuntime, TimingScope
from evidenceforge.models.scenario import System, User
from evidenceforge.models.state import ActiveSession, RunningProcess


class FrozenSessionProcessClose(Protocol):
    """Read the end selected by the existing auth/session teardown owner."""

    end_time: datetime


class BuildHostContextCapability(Protocol):
    def __call__(self, system: System) -> HostContext:
        """Delegate to the existing build host context owner."""
        ...


class CreateWindowsSessionShellLifecycleCapability(Protocol):
    def __call__(
        self,
        *,
        user: User,
        system: System,
        session: ActiveSession,
        winlogon_pid: int,
        logon_time: datetime,
    ) -> int:
        """Delegate to the existing create windows session shell lifecycle owner."""
        ...


class ExecuteNmapCommandProbeBundleCapability(Protocol):
    def __call__(self, request: NmapCommandProbeRequest) -> int:
        """Delegate to the existing execute nmap command probe bundle owner."""
        ...


class GenericLogoffOwnsProcessCloseCapability(Protocol):
    def __call__(self, parent: RunningProcess | None) -> bool:
        """Delegate to the existing generic logoff owns process close owner."""
        ...


class GetSidCapability(Protocol):
    def __call__(self, username: str) -> str:
        """Delegate to the existing get sid owner."""
        ...


class IsWithinScenarioWindowCapability(Protocol):
    def __call__(self, event_time: datetime) -> bool:
        """Delegate to the existing is within scenario window owner."""
        ...


class SampleActivityGapCapability(Protocol):
    def __call__(
        self,
        *,
        relationship_key: str,
        stable_id: str,
        minimum_ms: float,
        maximum_ms: float,
        host: str = "",
        source: str = "activity",
        lifecycle_id: str = "",
        ordinal: int = 0,
        sample_key: str = "gap",
        mode_fraction: float = 0.35,
        timing_runtime: TimingRuntime | SourceTimingPlanningRuntime | None = None,
        timing_scope: TimingScope | None = None,
    ) -> timedelta:
        """Delegate to the existing sample activity gap owner."""
        ...


class SampleProfileActivityGapCapability(Protocol):
    def __call__(
        self,
        relationship_key: str,
        *,
        stable_id: str,
        host: str = "",
        source: str = "activity",
        lifecycle_id: str = "",
        ordinal: int = 0,
        sample_key: str = "gap",
        mode_fraction: float = 0.35,
        timing_runtime: TimingRuntime | SourceTimingPlanningRuntime | None = None,
        timing_scope: TimingScope | None = None,
    ) -> timedelta:
        """Delegate to the existing sample profile activity gap owner."""
        ...


class UserModelForUsernameCapability(Protocol):
    def __call__(self, username: str) -> User:
        """Delegate to the existing user model for username owner."""
        ...


class WorkstationLogonLockedAtCapability(Protocol):
    def __call__(self, system: System, username: str, logon_id: str, time: datetime) -> bool:
        """Delegate to the existing workstation logon locked at owner."""
        ...


class EnsureLinuxSessionShellCapability(Protocol):
    def __call__(
        self,
        user: User,
        target_system: System,
        logon_id: str,
        logon_time: datetime,
        activity_time: datetime,
        source_visible_by: datetime | None = None,
    ) -> int | None:
        """Delegate to the existing ensure linux session shell owner."""
        ...


class EnsureLinuxVisibleShellParentCapability(Protocol):
    def __call__(
        self,
        user: User,
        target_system: System,
        activity_time: datetime,
        logon_id: str = "",
        logon_time: datetime | None = None,
        source_visible_by: datetime | None = None,
        existing_only: bool = False,
    ) -> int | None:
        """Delegate to the existing ensure linux visible shell parent owner."""
        ...


class GenerateProcessCapability(Protocol):
    def __call__(
        self,
        user: User,
        system: System,
        time: datetime,
        logon_id: str,
        process_name: str,
        command_line: str,
        parent_pid: int = 4,
        ensure_file_event: bool = False,
        from_storyline: bool = False,
        suppress_command_file_effect: bool = False,
        allow_existing_browser_reuse: bool = True,
        allow_browser_launch_spacing: bool = True,
        concurrency_group_id: str = "",
        lifecycle_group_id: str = "",
        source_visible_by: datetime | None = None,
        require_exact_parent: bool = False,
    ) -> int:
        """Delegate to the existing generate process owner."""
        ...


class GenerateProcessTerminationCapability(Protocol):
    def __call__(
        self,
        user: User,
        system: System,
        time: datetime,
        pid: int,
        process_name: str,
        logon_id: str,
        from_storyline: bool = False,
        session_end_plan: SessionEndPlan | None = None,
    ) -> None:
        """Delegate to the existing generate process termination owner."""
        ...


class GenerateSystemProcessCapability(Protocol):
    def __call__(
        self,
        system: System,
        time: datetime,
        process_name: str,
        command_line: str,
        parent_pid: int = 4,
        username: str = "SYSTEM",
        syslog_message: str | None = None,
        *,
        emit_linux_syslog: bool = True,
        concurrency_group_id: str = "",
        _profiled_service_bypass: bool = False,
        _skip_singleton_reuse: bool = False,
        source_visible_by: datetime | None = None,
    ) -> int:
        """Delegate to the existing generate system process owner."""
        ...


@dataclass(frozen=True)
class ProcessIdentityCapabilities:
    """Bind shared host and user identity capabilities without exposing the generator interface."""

    user_for_username: UserModelForUsernameCapability
    host_context: BuildHostContextCapability
    user_sid: GetSidCapability


@dataclass(frozen=True)
class ProcessActivityTiming:
    """Bind shared activity timing capabilities without exposing the generator interface."""

    sample_gap: SampleActivityGapCapability
    sample_profile_gap: SampleProfileActivityGapCapability


class FrozenGenericLogoffProcessCloseCapability(Protocol):
    """Read and authenticate the existing auth/session owner's frozen process close."""

    def __call__(
        self, request: ProcessTerminationRequest, running_process: RunningProcess | None
    ) -> FrozenSessionProcessClose | None:
        """Return the authenticated teardown close when this session owns it."""
        ...
