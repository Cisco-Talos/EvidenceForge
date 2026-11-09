# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Select reusable processes and account for optional execution effects."""

from __future__ import annotations

import logging
import ntpath
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from evidenceforge.generation.actions import (
    EffectExecutionOutcome,
    EffectOutcomeStatus,
    EffectRequirement,
    ExecutionEffectPlanError,
    ExecutionEffectPlanErrorCode,
    ProcessExecutionPreparedEffects,
)
from evidenceforge.generation.actions.command_effects import ExecutionEffectAuditCounter
from evidenceforge.generation.activity.helpers import _get_os_category
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import System
from evidenceforge.models.state import RunningProcess

from . import policy
from .policy import (
    _PERSISTENT_USER_APP_EXES,
    _WINDOWS_ELECTRON_CHILD_MARKERS,
    _WINDOWS_SINGLETON_SERVICE_PATHS,
    _WINDOWS_SINGLETON_SYSTEM_PROCESSES,
)
from .queries import ProcessStateQueries
from .sources import ProcessSourceTiming

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProcessReusePolicy:
    """Ephemeral operations; injected maps and managers remain on their existing owners."""

    _execution_effect_audit: ExecutionEffectAuditCounter
    _preferred_browser_by_session: dict[tuple[str, str, str], str]
    _system_pids: dict[str, dict[str, int]] | None
    state_manager: StateManager
    sources: ProcessSourceTiming
    queries: ProcessStateQueries

    def _existing_persistent_user_app_pid(
        self,
        *,
        system: System,
        username: str,
        logon_id: str,
        process_name: str,
        command_line: str,
        time: datetime,
        source_visible_by: datetime | None = None,
        update_activity: bool = True,
    ) -> int | None:
        """Reuse already-open desktop apps that normally stay resident."""
        requested_exe = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        from evidenceforge.generation.activity.application_catalog import (
            is_singleton_application_image,
        )

        if requested_exe not in _PERSISTENT_USER_APP_EXES and not is_singleton_application_image(
            process_name, _get_os_category(system.os)
        ):
            return None
        command = f" {command_line.lower()} "
        if any(marker in command for marker in _WINDOWS_ELECTRON_CHILD_MARKERS):
            return None

        candidates: list[RunningProcess] = []
        for proc in self.state_manager.get_processes_on_system(system.hostname):
            if proc.username != username:
                continue
            if proc.logon_id and logon_id and proc.logon_id != logon_id:
                continue
            if not self.queries._is_pid_active_at(system, proc.pid, time):
                continue
            if self._foreground_process_expired_for_attribution(system, proc, time):
                continue
            proc_exe = proc.image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
            if proc_exe == requested_exe:
                candidates.append(proc)

        if not candidates:
            return None
        chosen = max(
            candidates,
            key=lambda candidate: candidate.last_activity_time or candidate.start_time,
        )
        if not self.sources._process_source_visible_by(
            system=system,
            pid=chosen.pid,
            deadline=source_visible_by,
        ):
            # ``0`` is the bounded caller's explicit reject sentinel. Returning
            # ``None`` would make it fabricate a duplicate singleton process.
            return 0
        if update_activity:
            self.state_manager.update_process_activity_time(system.hostname, chosen.pid, time)
        return chosen.pid

    def _existing_user_browser_pid(
        self,
        *,
        system: System,
        username: str,
        logon_id: str,
        process_name: str,
        command_line: str,
        time: datetime,
        source_visible_by: datetime | None = None,
        allow_deferred_start: bool = False,
    ) -> int | None:
        """Reuse an open browser instead of emitting repeated top-level launches."""
        from evidenceforge.generation.activity.browser_instances import browser_instance_key

        os_category = _get_os_category(system.os)
        requested = browser_instance_key(process_name, command_line, os_category, username)
        if requested is None:
            return None
        candidates = []
        future_candidates = []
        for process in self.state_manager.get_processes_on_system(
            system.hostname, include_retained=True
        ):
            identity = self.state_manager.get_process_identity_at(
                system.hostname, process.pid, time
            )
            if (
                identity is not None
                and identity.object_id == process.ecar_object_id
                and identity.principal == username
                and browser_instance_key(
                    identity.image, identity.command_line, os_category, username
                )
                == requested
            ):
                candidates.append(identity)
            elif process.username == username:
                ready_at = process.executed_at or process.start_time
                if ready_at > time:
                    future = self.state_manager.get_process_identity_at(
                        system.hostname, process.pid, ready_at
                    )
                    if (
                        future is not None
                        and future.object_id == process.ecar_object_id
                        and browser_instance_key(
                            future.image, future.command_line, os_category, username
                        )
                        == requested
                    ):
                        future_candidates.append(future)
        if candidates:
            chosen = min(candidates, key=lambda process: (process.started_at, process.object_id))
        elif future_candidates:
            # A committed future root already owns this profile. Flexible baseline
            # work may wait for it; bounded callers must not create a duplicate.
            if not allow_deferred_start:
                return 0
            chosen = min(
                future_candidates,
                key=lambda process: (process.execution_started_at, process.object_id),
            )
        else:
            return None
        if not self.sources._process_source_visible_by(
            system=system, pid=chosen.pid, deadline=source_visible_by
        ):
            return 0
        current = self.state_manager.get_process(system.hostname, chosen.pid)
        if current is not None and current.ecar_object_id == chosen.object_id:
            self.state_manager.update_process_activity_time(
                system.hostname, chosen.pid, max(time, chosen.execution_started_at)
            )
        return chosen.pid

    def _existing_windows_singleton_pid(
        self,
        system: System,
        process_name: str,
        time: datetime,
    ) -> int | None:
        """Return a seeded Windows singleton PID instead of creating a duplicate."""
        if _get_os_category(system.os) != "windows":
            return None
        normalized_path = ntpath.normpath(process_name.replace("/", "\\")).lower()
        exe_name = normalized_path.rsplit("\\", 1)[-1]
        role = _WINDOWS_SINGLETON_SYSTEM_PROCESSES.get(exe_name)
        if role is None:
            return None
        if "\\" in normalized_path and normalized_path != f"c:\\windows\\system32\\{exe_name}":
            return None
        pid = policy.system_process_roles(self._system_pids).get(system.hostname, {}).get(role)
        if pid is None or not self.queries._is_pid_active_at(system, pid, time):
            return None
        return pid

    def _existing_windows_singleton_service_pid(
        self,
        system: System,
        process_name: str,
        time: datetime,
        username: str,
        command_line: str = "",
    ) -> int | None:
        """Return an active canonical Windows service singleton PID when one exists."""
        if _get_os_category(system.os) != "windows":
            return None

        normalized_path = ntpath.normpath(process_name.replace("/", "\\")).lower()
        exe_name = normalized_path.rsplit("\\", 1)[-1]
        service_match = re.search(r"(?:^|\s)-s\s+(?P<service>[^\s]+)", command_line, re.IGNORECASE)
        service_name = service_match.group("service").lower() if service_match else ""
        from evidenceforge.generation.activity.system_processes import (
            get_windows_singleton_service_paths,
        )

        singleton_paths = {
            key: set(paths) for key, paths in _WINDOWS_SINGLETON_SERVICE_PATHS.items()
        }
        for key, paths in get_windows_singleton_service_paths().items():
            singleton_paths.setdefault(key, set()).update(paths)
        valid_paths = singleton_paths.get(exe_name)
        is_named_svchost = exe_name == "svchost.exe" and bool(service_name)
        if not valid_paths and not is_named_svchost:
            return None

        if valid_paths and "\\" in normalized_path and normalized_path not in valid_paths:
            return None

        normalized_username = username.upper()
        candidates: list[RunningProcess] = []
        for proc in self.state_manager.get_processes_on_system(system.hostname):
            proc_path = ntpath.normpath(proc.image.replace("/", "\\")).lower()
            if is_named_svchost:
                if ntpath.basename(proc_path) != "svchost.exe":
                    continue
                proc_service_match = re.search(
                    r"(?:^|\s)-s\s+(?P<service>[^\s]+)",
                    proc.command_line,
                    re.IGNORECASE,
                )
                if (
                    proc_service_match is None
                    or proc_service_match.group("service").lower() != service_name
                ):
                    continue
            elif valid_paths is not None and proc_path not in valid_paths:
                continue
            if proc.username.upper() != normalized_username:
                continue
            parent = self.state_manager.get_process(system.hostname, proc.parent_pid)
            parent_image = parent.image if parent else ""
            if ntpath.basename(parent_image).lower() != "services.exe":
                continue
            candidates.append(proc)

        if not candidates:
            return None
        return max(candidates, key=lambda proc: proc.start_time).pid

    def _foreground_process_expired_for_attribution(
        self,
        system: System,
        proc: Any,
        time: datetime,
    ) -> bool:
        """Return whether a foreground process is not active for new effects."""
        if proc is None or proc.start_time is None:
            return False
        if time < proc.start_time:
            return True
        lifetime = policy._foreground_process_lifetime_for_attribution(system, proc)
        if lifetime is None:
            return False
        max_process_time = proc.start_time + timedelta(seconds=lifetime[1] + 5.0)
        return time > max_process_time

    def _record_reused_process_optional_effects(
        self,
        prepared_effects: ProcessExecutionPreparedEffects | None,
    ) -> None:
        """Reconcile planned optionals explicitly when an existing root is reused."""

        endpoint = prepared_effects.endpoint if prepared_effects is not None else None
        if endpoint is None:
            return
        plan = endpoint.execution_plan
        if plan is None or any(
            node.requirement != EffectRequirement.OPTIONAL for node in plan.nodes
        ):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "a reused process root may suppress only explicitly optional endpoint effects",
            )
        reconciliation = plan.reconcile(
            tuple(
                EffectExecutionOutcome(
                    node_id=node.node_id,
                    status=EffectOutcomeStatus.SUPPRESSED,
                    completed_at=endpoint.actor.started_at,
                    reason="optional endpoint effect omitted because an exact live root was reused",
                    canonical_occurrence_count=0,
                )
                for node in plan.ordered_nodes
            )
        )
        reconciliation.require_complete()
        self._execution_effect_audit.record(reconciliation)
