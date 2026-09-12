# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Apply Linux shell, service and system-anchor parent policies."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from evidenceforge.generation.activity.helpers import _get_os_category
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import System, User
from evidenceforge.models.state import ActiveSession
from evidenceforge.utils.time import ensure_utc

from . import policy
from .capabilities import (
    EnsureLinuxSessionShellCapability,
    EnsureLinuxVisibleShellParentCapability,
    ProcessIdentityCapabilities,
)
from .queries import ProcessStateQueries

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class LinuxProcessParents:
    """Parent operations over existing owners; no independent runtime state."""

    _scenario_start_time: datetime | None
    _system_pids: dict[str, dict[str, int]] | None
    state_manager: StateManager
    queries: ProcessStateQueries
    identity: ProcessIdentityCapabilities
    ensure_linux_session_shell: EnsureLinuxSessionShellCapability
    ensure_linux_visible_shell_parent: EnsureLinuxVisibleShellParentCapability

    def _linux_system_parent_fallback(self, system: System, time: datetime) -> int:
        """Return a live Linux service ancestry fallback for system processes."""
        sys_pids = policy.system_process_roles(self._system_pids).get(system.hostname, {})
        for role in ("systemd", "init", "cron", "crond"):
            pid = sys_pids.get(role)
            if pid and self.queries._is_pid_active_at(system, pid, time):
                return pid
        return self._linux_anchor_pid(system, time)

    def _linux_anchor_pid(self, system: System, time: datetime) -> int:
        """Return a tracked Linux init/systemd process for parent-chain fallbacks."""
        sys_pids = policy.system_process_roles(self._system_pids).setdefault(system.hostname, {})
        for role in ("systemd", "init"):
            pid = sys_pids.get(role)
            if pid and self.queries._is_pid_active_at(system, pid, time):
                return pid
        for proc in self.state_manager.get_processes_on_system(system.hostname):
            proc_exe = proc.image.rsplit("/", 1)[-1].lower()
            if proc_exe in {"systemd", "init"} and proc.start_time <= time:
                sys_pids.setdefault("systemd", proc.pid)
                return proc.pid

        current_time = time - timedelta(minutes=5)
        self.state_manager.set_current_time(current_time)
        pid = self.state_manager.create_process(
            system=system.hostname,
            parent_pid=0,
            image="/usr/lib/systemd/systemd",
            command_line="/usr/lib/systemd/systemd",
            username="root",
            integrity_level="System",
            logon_id="",
        )
        sys_pids["systemd"] = pid
        return pid

    def _materialize_visible_linux_shell_parent_for_child(
        self,
        *,
        system: System,
        time: datetime,
        logon_id: str,
        parent_pid: int,
        process_username: str,
    ) -> int:
        """Ensure post-window Linux shell parents are source-visible."""
        if _get_os_category(system.os) != "linux":
            return parent_pid
        parent_proc = self.state_manager.get_process(system.hostname, parent_pid)
        if parent_proc is None or not self.queries._is_pid_active_at(system, parent_pid, time):
            return parent_pid

        parent_exe = parent_proc.image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        if parent_exe not in {"bash", "sh", "zsh"}:
            return parent_pid

        scenario_start = self._scenario_start_time
        if scenario_start is None:
            return parent_pid
        scenario_start = ensure_utc(scenario_start)
        activity_time = ensure_utc(time)
        if activity_time < scenario_start:
            return parent_pid
        if ensure_utc(parent_proc.start_time) >= scenario_start:
            return parent_pid

        user = self.identity.user_for_username(process_username)
        session = self.state_manager.get_session(logon_id)
        if session is not None:
            session_shell_pid = self.ensure_linux_session_shell(
                user=user,
                target_system=system,
                logon_id=logon_id,
                logon_time=session.start_time,
                activity_time=activity_time,
            )
            if session_shell_pid is not None:
                return session_shell_pid

        visible_shell_pid = self.ensure_linux_visible_shell_parent(
            user=user,
            target_system=system,
            activity_time=activity_time,
            logon_id=logon_id,
            logon_time=session.start_time if session is not None else None,
        )
        return visible_shell_pid if visible_shell_pid is not None else parent_pid

    def _linux_service_parent_pid(
        self,
        system: System,
        username: str,
        time: datetime,
        possible_parents: list[str] | None = None,
    ) -> int | None:
        """Return a live Linux service daemon parent for service-account commands."""
        if username not in policy._LINUX_SERVICE_USERS:
            return None
        parent_names = {parent.lower() for parent in possible_parents or []}
        sys_pids = policy.system_process_roles(self._system_pids).get(system.hostname, {})
        for key in policy._LINUX_SERVICE_PARENT_KEYS:
            if parent_names and key not in parent_names:
                continue
            pid = sys_pids.get(key)
            if pid and self.queries._is_pid_active_at(system, pid, time):
                return pid
        return None

    def select_from_history(
        self,
        system: System,
        user: User,
        time: datetime | None,
        logon_id: str,
        *,
        sys_pids: dict[str, int],
        effective_time: datetime,
        alive_history: list[tuple[int, str]],
    ) -> int:
        """Select a parent after shared history filtering without changing draw order."""
        session_shell_pid = self.queries._active_session_shell_pid(
            system,
            user,
            time,
            logon_id,
        )
        if session_shell_pid is not None:
            return session_shell_pid
        shells = [(pid, name) for pid, name in alive_history if name in policy._LINUX_SHELLS]
        if shells:
            return shells[-1][0]
        for role in ("bash", "sshd"):
            candidate = sys_pids.get(role)
            if candidate and self.queries._linux_parent_usable_for_child_at(
                system=system,
                parent_pid=candidate,
                time=effective_time or datetime.now(UTC),
                logon_id=logon_id,
            ):
                return candidate
        return self._linux_system_parent_fallback(system, effective_time or datetime.now(UTC))

    def select_spawn_parent(
        self,
        system: System,
        user: User,
        time: datetime,
        logon_id: str,
        possible_parents: list[str],
        active_session: ActiveSession | None,
    ) -> int | None:
        """Apply Linux service and shell rules before shared ancestry search."""
        service_parent = self._linux_service_parent_pid(
            system, user.username, time, possible_parents
        )
        if service_parent is not None:
            return service_parent
        shell_parent_allowed = not possible_parents or any(
            parent in {"bash", "sh", "zsh"} for parent in possible_parents
        )
        if shell_parent_allowed:
            if active_session is not None:
                session_shell_pid = self.ensure_linux_session_shell(
                    user=user,
                    target_system=system,
                    logon_id=active_session.logon_id,
                    logon_time=active_session.start_time,
                    activity_time=time,
                )
                if session_shell_pid is not None:
                    return session_shell_pid
            visible_shell_pid = self.ensure_linux_visible_shell_parent(
                user=user,
                target_system=system,
                activity_time=time,
                logon_id=logon_id,
                logon_time=active_session.start_time if active_session is not None else None,
            )
            if visible_shell_pid is not None:
                return visible_shell_pid
        session_shell_pid = self.queries._active_session_shell_pid(system, user, time, logon_id)
        if session_shell_pid is not None and any(
            parent in {"bash", "sh", "zsh"} for parent in possible_parents
        ):
            return session_shell_pid
        return None

    def existing_parent_fallback(
        self,
        system: System,
        user: User,
        time: datetime,
        logon_id: str,
        system_pids: dict[str, int],
    ) -> int:
        """Select an existing fallback after the shared explicit-parent checks."""
        session_shell = self.queries._active_session_shell_pid(system, user, time, logon_id)
        if session_shell is not None:
            return session_shell
        for role in ("bash", "sshd", "systemd", "init"):
            candidate = system_pids.get(role)
            if candidate is not None and self.queries._linux_parent_usable_for_child_at(
                system=system,
                parent_pid=candidate,
                time=time,
                logon_id=logon_id,
            ):
                return candidate
        return 0
