# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""System and service process execution through explicit existing owners."""

from __future__ import annotations

import ntpath
from dataclasses import dataclass
from datetime import datetime, timedelta

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import AuthContext
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.generation.actions.process_execution import ProcessExecutionRequest
from evidenceforge.generation.activity.helpers import _get_os_category
from evidenceforge.generation.activity.process_helpers import _windows_script_host_process
from evidenceforge.generation.activity.service_process_profiles import matching_service_worker
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import System
from evidenceforge.utils.time import ensure_utc

from .actors import ProcessActorResolver
from .capabilities import GenerateProcessCapability, ProcessIdentityCapabilities
from .parents import ProcessParentResolver
from .policy import _WINDOWS_SHELL_UWP_USER_PROCESS_EXES, _session_source_ready_time
from .queries import ProcessStateQueries
from .reuse import ProcessReusePolicy
from .sources import ProcessSourceTiming


@dataclass(frozen=True)
class SystemProcessService:
    """Execute service/system process requests against the current process owners."""

    state_manager: StateManager
    dispatcher: EventDispatcher
    sid_registry: dict[str, str]
    actors: ProcessActorResolver
    parents: ProcessParentResolver
    queries: ProcessStateQueries
    reuse: ProcessReusePolicy
    sources: ProcessSourceTiming
    identity: ProcessIdentityCapabilities
    generate_process: GenerateProcessCapability

    def generate_system_process(
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
        """Generate a system process creation event (no user session required).

        Used for scheduled tasks, service spawns, and other system-initiated
        processes that don't have an associated user logon session.

        Args:
            system: System where process is created
            time: Process creation timestamp
            process_name: Full path to executable
            command_line: Command line string
            parent_pid: Parent process PID
            username: System account name (SYSTEM, root, etc.)
            syslog_message: Custom syslog message (overrides auto-generated message)
            emit_linux_syslog: Whether to attach a Linux syslog record to this process event.
            concurrency_group_id: Optional source-local process group for related
                foreground children such as cron shell/workload pairs.
            source_visible_by: Optional deadline for every process-create source view.

        Returns:
            PID of the new process
        """
        from evidenceforge.events.contexts import ProcessContext

        source_deadline = ensure_utc(source_visible_by) if source_visible_by is not None else None
        if source_deadline is not None and ensure_utc(time) > source_deadline:
            return 0
        if source_deadline is None:
            self.state_manager.set_current_time(time)
        if _get_os_category(system.os) == "windows":
            process_name, command_line = _windows_script_host_process(
                process_name,
                command_line,
            )

        if not _profiled_service_bypass:
            profiled_worker = matching_service_worker(
                os_category=_get_os_category(system.os),
                image=process_name,
                command_line=command_line,
                username=username,
            )
            if profiled_worker is not None:
                family_name, worker_name, _family = profiled_worker
                return self.parents._ensure_profiled_service_worker(
                    system=system,
                    worker_time=time,
                    activity_time=time,
                    family_name=family_name,
                    worker_name=worker_name,
                    source_visible_by=source_visible_by,
                )

        exe_name = ntpath.basename(process_name).lower()
        if (
            _get_os_category(system.os) == "windows"
            and exe_name in _WINDOWS_SHELL_UWP_USER_PROCESS_EXES
        ):
            session = self.actors._active_interactive_windows_session(system, time)
            if session is None:
                return 0
            session_user = self.identity.user_for_username(session.username)
            if self.state_manager.get_process(system.hostname, parent_pid) is None:
                parent_pid = (
                    self.parents._resolve_existing_prepared_process_parent(
                        system=system,
                        user=session_user,
                        time=time,
                        logon_id=session.logon_id,
                        parent_pid=parent_pid,
                        process_username=session_user.username,
                    )
                    if source_deadline is not None
                    else self.parents._resolve_parent(
                        system,
                        session_user,
                        time,
                        session.logon_id,
                        process_name,
                    )
                )
            if source_deadline is not None:
                source_floor = ensure_utc(time)
                session_ready = _session_source_ready_time(session)
                if session_ready is not None:
                    source_floor = max(
                        source_floor,
                        session_ready + timedelta(milliseconds=1),
                    )
                parent_visible_time = self.sources._process_source_frontier_or_bound(
                    system=system,
                    pid=parent_pid,
                )
                persistent_app_pid = self.reuse._existing_persistent_user_app_pid(
                    system=system,
                    username=session_user.username,
                    logon_id=session.logon_id,
                    process_name=process_name,
                    command_line=command_line,
                    time=time,
                    source_visible_by=source_deadline,
                )
                if persistent_app_pid is not None:
                    return persistent_app_pid
                if parent_visible_time is not None:
                    source_floor = max(
                        source_floor,
                        ensure_utc(parent_visible_time) + timedelta(milliseconds=1),
                    )
                prepared_actor = self.actors._prepare_process_effect_actor(
                    ProcessExecutionRequest(
                        user=session_user,
                        system=system,
                        time=time,
                        logon_id=session.logon_id,
                        process_name=process_name,
                        command_line=command_line,
                        parent_pid=parent_pid,
                        allow_existing_browser_reuse=False,
                        source_visible_by=source_visible_by,
                    )
                )
                source_floor = max(
                    source_floor,
                    self.sources._process_create_source_bound(
                        system=system,
                        canonical_time=prepared_actor.started_at,
                        parent_source_time=parent_visible_time,
                        session_source_time=session_ready,
                    ),
                )
                if source_floor > source_deadline:
                    return 0
            return self.generate_process(
                user=session_user,
                system=system,
                time=time,
                logon_id=session.logon_id,
                process_name=process_name,
                command_line=command_line,
                parent_pid=parent_pid,
                allow_existing_browser_reuse=False,
                source_visible_by=source_visible_by,
            )

        singleton_service_pid = None
        if not _skip_singleton_reuse:
            singleton_service_pid = self.reuse._existing_windows_singleton_service_pid(
                system=system,
                process_name=process_name,
                time=time,
                username=username,
                command_line=command_line,
            )
        if singleton_service_pid is not None:
            if not self.sources._process_source_visible_by(
                system=system,
                pid=singleton_service_pid,
                deadline=source_deadline,
            ):
                return 0
            return singleton_service_pid

        system_logon_ids = {"SYSTEM": "0x3e7", "LOCAL SERVICE": "0x3e5", "NETWORK SERVICE": "0x3e4"}
        logon_id = system_logon_ids.get(username, "0x3e7")
        if source_deadline is not None:
            parent_pid = self.parents._resolve_existing_prepared_process_parent(
                system=system,
                user=self.identity.user_for_username(username),
                time=time,
                logon_id=logon_id,
                parent_pid=parent_pid,
                process_username=username,
            )
        else:
            parent_pid = self.parents._repair_process_parent_pid(
                system=system,
                time=time,
                logon_id=logon_id,
                process_name=process_name,
                command_line=command_line,
                parent_pid=parent_pid,
                process_username=username,
            )
        repaired_parent = self.state_manager.get_process(system.hostname, parent_pid)
        if repaired_parent is not None and time <= repaired_parent.start_time:
            time = repaired_parent.start_time + timedelta(milliseconds=50)
        source_floor = ensure_utc(time)
        parent_visible_time = None
        if parent_pid > 0:
            parent_visible_time = self.sources._process_source_frontier_or_bound(
                system=system,
                pid=parent_pid,
            )
            if parent_visible_time is not None:
                source_floor = max(
                    source_floor,
                    ensure_utc(parent_visible_time) + timedelta(milliseconds=1),
                )
        if source_deadline is not None:
            source_floor = max(
                source_floor,
                self.sources._process_create_source_bound(
                    system=system,
                    canonical_time=time,
                    parent_source_time=parent_visible_time,
                ),
            )
            if source_floor > source_deadline:
                return 0
        self.state_manager.set_current_time(time)
        self.state_manager.update_process_activity_time(system.hostname, parent_pid, time)
        pid = self.state_manager.create_process(
            system=system.hostname,
            parent_pid=parent_pid,
            image=process_name,
            command_line=command_line,
            username=username,
            integrity_level="System",
            logon_id=logon_id,
        )

        # Determine system-level SID and logon ID
        sid = self.sid_registry.get(username, "S-1-5-18") if self.sid_registry else "S-1-5-18"

        self.state_manager.get_process_object_id(system.hostname, pid)
        self.state_manager.get_process_object_id(system.hostname, parent_pid)
        event = OccurrenceBuilder(
            timestamp=time,
            event_type="system_process_create",
            src_host=self.identity.host_context(system),
            auth=AuthContext(
                username=username,
                user_sid=sid,
                logon_id=logon_id,
                subject_sid=sid,
                subject_username=username,
                subject_domain="NT AUTHORITY",
                subject_logon_id=logon_id,
            ),
            process=ProcessContext(
                pid=pid,
                parent_pid=parent_pid,
                image=process_name,
                command_line=command_line,
                username=username,
                integrity_level="System",
                logon_id=logon_id,
                parent_image=self.queries._lookup_parent_image(system.hostname, parent_pid),
                parent_command_line=self.queries._lookup_parent_command_line(
                    system.hostname, parent_pid
                ),
                parent_start_time=self.queries._lookup_parent_start_time(
                    system.hostname, parent_pid
                ),
                token_elevation="%%1936",
                mandatory_label="S-1-16-16384",
                start_time=self.queries._lookup_parent_start_time(system.hostname, pid),
                current_directory=self.actors._derive_current_directory(
                    system=system,
                    username=username,
                    process_name=process_name,
                    command_line=command_line,
                    parent_pid=parent_pid,
                ),
                concurrency_group_id=concurrency_group_id,
            ),
        )

        self.sources._record_process_source_create_time(
            system.hostname,
            pid,
            event,
            not_after=source_visible_by,
            publish_finalized=False,
        )
        # Attach SyslogContext for Linux hosts
        if emit_linux_syslog and event.src_host and event.src_host.os_category == "linux":
            from evidenceforge.events.contexts import SyslogContext

            if syslog_message:
                event.syslog = SyslogContext(
                    app_name="systemd",
                    pid=1,
                    facility=3,
                    severity=6,
                    message=syslog_message,
                )
            elif "cron" in (process_name or "").lower():
                event.syslog = SyslogContext(
                    app_name="CRON",
                    pid=pid,
                    facility=9,
                    severity=6,
                    message=f"({username}) CMD ({command_line})",
                )
            else:
                app_name = process_name.split("/")[-1]
                event.syslog = SyslogContext(
                    app_name=app_name,
                    pid=pid,
                    facility=3,
                    severity=6,
                    message=f"started: {command_line}",
                )

        self.dispatcher.dispatch_builder(event)
        self.sources._record_process_source_create_time(
            system.hostname,
            pid,
            event,
            not_after=source_visible_by,
        )

        return pid
