# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Resolve process ancestry and materialize required parent/service chains."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from evidenceforge.events.authentication import windows_logon_can_own_desktop
from evidenceforge.events.contexts import AuthContext, ProcessContext
from evidenceforge.events.dispatcher import EventDispatcher, PreparedDispatchStateIntent
from evidenceforge.events.identity import EventIdentityPlan
from evidenceforge.events.lifecycle import ActionLifecycleContext
from evidenceforge.generation.activity.helpers import _get_os_category, _get_rng
from evidenceforge.generation.activity.process_helpers import _SYSTEM_ACCOUNTS as _SYSTEM_ACCOUNTS
from evidenceforge.generation.activity.process_helpers import (
    _is_bare_windows_explorer_launch as _is_bare_windows_explorer_launch,
)
from evidenceforge.generation.activity.service_process_profiles import (
    ServiceProcessFamily,
    ServiceProcessSpec,
    matching_service_worker,
    service_process_family,
)
from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import System, User
from evidenceforge.utils.rng import _stable_seed
from evidenceforge.utils.time import ensure_utc

from . import policy
from .capabilities import (
    CreateWindowsSessionShellLifecycleCapability,
    EnsureLinuxSessionShellCapability,
    EnsureLinuxVisibleShellParentCapability,
    GenerateProcessCapability,
    GenerateSystemProcessCapability,
    ProcessIdentityCapabilities,
)
from .policy import (
    _WINDOWS_BROWSER_EXES,
    _WINDOWS_ELECTRON_CHILD_EXES,
    _WINDOWS_ELECTRON_CHILD_MARKERS,
    _extract_image_from_command,
    _session_active_for_activity,
)
from .queries import ProcessStateQueries
from .reuse import ProcessReusePolicy
from .sources import ProcessSourceTiming

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProcessParentResolver:
    """Ephemeral operations; injected maps and managers remain on their existing owners."""

    _create_windows_session_shell_lifecycle: CreateWindowsSessionShellLifecycleCapability
    _lifecycle_authority: GeneratorLifecycleAuthority
    _scenario_start_time: datetime | None
    _system_pids: dict[str, dict[str, int]] | None
    _user_process_history: dict[tuple[str, str], list[tuple[int, str]]]
    dispatcher: EventDispatcher
    ensure_linux_session_shell: EnsureLinuxSessionShellCapability
    ensure_linux_visible_shell_parent: EnsureLinuxVisibleShellParentCapability
    generate_process: GenerateProcessCapability
    generate_system_process: GenerateSystemProcessCapability
    state_manager: StateManager
    reuse: ProcessReusePolicy
    sources: ProcessSourceTiming
    queries: ProcessStateQueries
    identity: ProcessIdentityCapabilities

    def _ensure_session_explorer_pid(
        self,
        system: System,
        user: User,
        time: datetime,
        logon_id: str,
    ) -> int | None:
        """Return or create the per-session Explorer state for GUI children."""
        existing = self._get_session_explorer_pid(system, user, time=time, logon_id=logon_id)
        if existing is not None:
            return existing

        session = self.state_manager.get_session(logon_id)
        if session is None:
            return None
        if session.system != system.hostname or session.username != user.username:
            return None
        if not windows_logon_can_own_desktop(session.logon_type) or session.session_kind in {
            "network",
            "new_credentials",
            "service",
        }:
            return None
        if session.windows_shell_bootstrapped and session.initial_explorer_pid is not None:
            initial_pid = session.initial_explorer_pid
            if self.state_manager.get_process(system.hostname, initial_pid) is not None:
                session.explorer_pid = initial_pid
                return initial_pid
            # Future-dated teardown may have eagerly removed the process from live
            # state. `_get_session_explorer_pid()` still returns the retained identity
            # when it spans this canonical time. A genuinely ended shell may be repaired.
            if self.state_manager.is_process_active_at(system.hostname, initial_pid, time):
                return initial_pid

        sys_pids = policy.system_process_roles(self._system_pids).get(system.hostname, {})
        parent_for_chain = None
        for candidate in ("smss", "wininit", "winlogon", "services"):
            pid = sys_pids.get(candidate)
            if pid and self.queries._is_pid_active_at(system, pid, time):
                parent_for_chain = pid
                break
        if parent_for_chain is None:
            return None

        original_time = self.state_manager.state.current_time
        chain_time = max(session.start_time, time - timedelta(seconds=1))
        self.state_manager.set_current_time(chain_time)
        try:
            winlogon_pid = session.session_winlogon_pid
            if winlogon_pid is None or not self.queries._is_pid_active_at(
                system, winlogon_pid, time
            ):
                winlogon_pid = self.state_manager.create_process(
                    system.hostname,
                    parent_for_chain,
                    r"C:\Windows\System32\winlogon.exe",
                    "winlogon.exe",
                    "SYSTEM",
                    "System",
                    logon_id="0x3e7",
                )
                session.session_winlogon_pid = winlogon_pid
                session.process_tree_root = winlogon_pid

            explorer_pid = self._create_windows_session_shell_lifecycle(
                user=user,
                system=system,
                session=session,
                winlogon_pid=winlogon_pid,
                logon_time=chain_time,
            )
            session.explorer_pid = explorer_pid
            if session.initial_explorer_pid is None:
                session.initial_explorer_pid = explorer_pid
            session.windows_shell_bootstrapped = True
            return explorer_pid
        finally:
            if original_time is not None:
                self.state_manager.set_current_time(original_time)

    def _get_session_explorer_pid(
        self,
        system: System,
        user: User,
        time: datetime | None = None,
        logon_id: str = "",
    ) -> int | None:
        """Get the explorer.exe PID for the user's active interactive session.

        Returns None if no interactive session exists or explorer PID not set.
        """
        sessions = (
            self.state_manager.get_sessions_for_user_at(user.username, time)
            if time is not None
            else self.state_manager.get_sessions_for_user(user.username)
        )
        candidates = [
            session
            for session in sessions
            if session.system == system.hostname
            and session.explorer_pid is not None
            and (not logon_id or session.logon_id == logon_id)
        ]
        candidates.sort(key=lambda session: session.start_time, reverse=True)
        for session in candidates:
            if session.explorer_pid is None:
                continue
            if time is not None:
                if self.state_manager.is_process_active_at(
                    system.hostname,
                    session.explorer_pid,
                    time,
                ):
                    return session.explorer_pid
                continue
            if self.queries._is_pid_alive(system, session.explorer_pid):
                return session.explorer_pid
        return None

    def _linux_system_parent_fallback(self, system: System, time: datetime) -> int:
        """Return a live Linux service ancestry fallback for system processes."""
        sys_pids = policy.system_process_roles(self._system_pids).get(system.hostname, {})
        for role in ("systemd", "init", "cron", "crond"):
            pid = sys_pids.get(role)
            if pid and self.queries._is_pid_active_at(system, pid, time):
                return pid
        return self._linux_anchor_pid(system, time)

    def _windows_system_parent_fallback(self, system: System, time: datetime) -> int:
        """Return a live Windows service ancestry fallback for system processes."""
        sys_pids = policy.system_process_roles(self._system_pids).get(system.hostname, {})
        for role in ("services", "svchost_netsvcs", "svchost_dcom", "wininit"):
            pid = sys_pids.get(role)
            if pid and self.queries._is_pid_active_at(system, pid, time):
                return pid
        return 4

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

        scenario_start = getattr(self, "_scenario_start_time", None)
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

    def _repair_process_parent_pid(
        self,
        *,
        system: System,
        time: datetime,
        logon_id: str,
        process_name: str,
        command_line: str,
        parent_pid: int,
        process_username: str,
    ) -> int:
        """Resolve a live parent PID before process state allocation."""
        os_category = _get_os_category(system.os)
        process_exe = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        user_context = process_username not in _SYSTEM_ACCOUNTS and not process_username.endswith(
            "$"
        )

        if os_category == "windows":
            if user_context:
                repair_user = self.identity.user_for_username(process_username)
                if self._is_windows_same_exe_gui_child(process_name, command_line):
                    same_exe_parent = self._windows_same_exe_gui_parent_pid(
                        system=system,
                        user=repair_user,
                        time=time,
                        logon_id=logon_id,
                        process_name=process_name,
                        parent_pid=parent_pid,
                        process_username=process_username,
                    )
                    if (
                        same_exe_parent is not None
                        and self.state_manager.get_process(system.hostname, same_exe_parent)
                        is not None
                    ):
                        return same_exe_parent
                if self.queries._is_valid_process_parent_at(
                    system=system,
                    parent_pid=parent_pid,
                    time=time,
                ):
                    return parent_pid
                if process_exe in policy._WINDOWS_GUI_APPS or process_exe == "explorer.exe":
                    explorer_pid = self._ensure_session_explorer_pid(
                        system,
                        repair_user,
                        time,
                        logon_id,
                    )
                    if explorer_pid is not None and self.queries._is_valid_process_parent_at(
                        system=system,
                        parent_pid=explorer_pid,
                        time=time,
                    ):
                        return explorer_pid
                resolved = self._resolve_parent(
                    system,
                    repair_user,
                    time,
                    logon_id,
                    process_name,
                    command_line,
                )
                if self.queries._is_valid_process_parent_at(
                    system=system,
                    parent_pid=resolved,
                    time=time,
                ):
                    return resolved
            if self.queries._is_valid_process_parent_at(
                system=system, parent_pid=parent_pid, time=time
            ):
                return parent_pid
            return self._windows_system_parent_fallback(system, time)

        if user_context:
            repair_user = self.identity.user_for_username(process_username)
            materialized_parent = self._materialize_visible_linux_shell_parent_for_child(
                system=system,
                time=time,
                logon_id=logon_id,
                parent_pid=parent_pid,
                process_username=process_username,
            )
            if materialized_parent != parent_pid and self.queries._is_valid_process_parent_at(
                system=system, parent_pid=materialized_parent, time=time
            ):
                return materialized_parent
            if (
                materialized_parent != parent_pid
                and self.state_manager.get_process(system.hostname, materialized_parent) is not None
            ):
                return materialized_parent
            parent_proc = self.state_manager.get_process(system.hostname, parent_pid)
            if parent_proc is not None and ensure_utc(parent_proc.start_time) > ensure_utc(time):
                return parent_pid
            if self.queries._linux_parent_usable_for_child_at(
                system=system,
                parent_pid=parent_pid,
                time=time,
                logon_id=logon_id,
            ):
                return parent_pid
            session_shell = self._active_session_shell_pid(system, repair_user, time, logon_id)
            if session_shell is not None:
                return session_shell
            resolved = self._resolve_parent(
                system,
                repair_user,
                time,
                logon_id,
                process_name,
                command_line,
            )
            if self.queries._linux_parent_usable_for_child_at(
                system=system,
                parent_pid=resolved,
                time=time,
                logon_id=logon_id,
            ):
                return resolved
        if self.queries._linux_parent_usable_for_child_at(
            system=system,
            parent_pid=parent_pid,
            time=time,
            logon_id=logon_id,
        ):
            return parent_pid
        return self._linux_system_parent_fallback(system, time)

    def _sanitize_user_parent_pid(
        self,
        *,
        system: System,
        user: User,
        time: datetime,
        logon_id: str,
        process_name: str,
        command_line: str,
        parent_pid: int,
        process_username: str,
    ) -> int:
        """Prevent user-context processes from being parented by impossible fallbacks."""
        os_category = _get_os_category(system.os)
        if os_category not in {"windows", "linux"}:
            return parent_pid
        if process_username in _SYSTEM_ACCOUNTS or process_username.endswith("$"):
            return parent_pid
        parent_proc = self.state_manager.get_process(system.hostname, parent_pid)
        parent_image = (parent_proc.image if parent_proc is not None else "").lower()
        process_exe = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        session = self.state_manager.get_session(logon_id)
        if (
            os_category == "windows"
            and session is not None
            and session.logon_type == 5
            and parent_image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1] == "explorer.exe"
        ):
            sys_pids = policy.system_process_roles(self._system_pids).get(system.hostname, {})
            if process_exe in policy._WINDOWS_SHELLS:
                return sys_pids.get(
                    "svchost_netsvcs",
                    sys_pids.get("svchost_dcom", sys_pids.get("services", parent_pid)),
                )
            return sys_pids.get(
                "services", sys_pids.get("svchost_dcom", sys_pids.get("wininit", parent_pid))
            )
        is_browser_child = process_exe in _WINDOWS_BROWSER_EXES and not (
            policy._is_top_level_browser_launch(process_name, command_line)
        )
        is_same_exe_gui_child = self._is_windows_same_exe_gui_child(
            process_name,
            command_line,
        )
        if os_category == "windows" and process_exe == "explorer.exe":
            if not _is_bare_windows_explorer_launch(process_name, command_line):
                explorer_pid = self._get_session_explorer_pid(
                    system,
                    user,
                    time=time,
                    logon_id=logon_id,
                )
                if explorer_pid is not None:
                    return explorer_pid
            return self._windows_explorer_parent_pid(system, user, time, logon_id)

        if os_category == "windows":
            parent_is_one_shot_shell = self.queries._is_one_shot_shell_parent(system, parent_pid)
            one_shot_parent_invokes_child = parent_is_one_shot_shell and (
                self.queries._windows_shell_parent_invokes_child(
                    system=system,
                    parent_pid=parent_pid,
                    process_name=process_name,
                    command_line=command_line,
                )
            )
            if is_same_exe_gui_child:
                same_exe_parent = self._windows_same_exe_gui_parent_pid(
                    system=system,
                    user=user,
                    time=time,
                    logon_id=logon_id,
                    process_name=process_name,
                    parent_pid=parent_pid,
                    process_username=process_username,
                )
                if same_exe_parent is not None:
                    return same_exe_parent
            if process_exe in policy._WINDOWS_GUI_APPS and not is_browser_child:
                explorer_pid = self._ensure_session_explorer_pid(system, user, time, logon_id)
                if explorer_pid is not None:
                    return explorer_pid
            if (
                parent_pid != 4
                and parent_image not in {"system", "ntoskrnl.exe"}
                and parent_image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
                not in {"winlogon.exe", "userinit.exe"}
                and self.queries._is_pid_active_at(system, parent_pid, time)
                and self.queries._parent_process_matches_logon(
                    hostname=system.hostname,
                    parent_pid=parent_pid,
                    logon_id=logon_id,
                    os_category=os_category,
                )
                and (not parent_is_one_shot_shell or one_shot_parent_invokes_child)
            ):
                return parent_pid
        elif parent_proc is not None and self.queries._linux_parent_usable_for_child_at(
            system=system,
            parent_pid=parent_pid,
            time=time,
            logon_id=logon_id,
        ):
            parent_exe = parent_image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
            if parent_exe in {"bash", "sh", "zsh"}:
                if parent_proc.username == process_username and (
                    not logon_id or parent_proc.logon_id == logon_id
                ):
                    # The caller may have deliberately selected a second
                    # terminal/channel shell because the session's primary shell
                    # is occupied. Preserve that concrete valid parent.
                    return parent_pid
                session = self.state_manager.get_session(logon_id)
                if session is not None:
                    session_shell_pid = self.ensure_linux_session_shell(
                        user=self.identity.user_for_username(process_username),
                        target_system=system,
                        logon_id=logon_id,
                        logon_time=session.start_time,
                        activity_time=time,
                    )
                    if session_shell_pid is not None:
                        return session_shell_pid
                visible_shell_pid = self.ensure_linux_visible_shell_parent(
                    user=self.identity.user_for_username(process_username),
                    target_system=system,
                    activity_time=time,
                    logon_id=logon_id,
                    logon_time=session.start_time if session is not None else None,
                )
                if visible_shell_pid is not None:
                    return visible_shell_pid
            return parent_pid

        resolved = self._resolve_parent(
            system,
            user,
            time,
            logon_id,
            process_name,
            command_line,
        )
        resolved_proc = self.state_manager.get_process(system.hostname, resolved)
        resolved_image = (resolved_proc.image if resolved_proc is not None else "").lower()
        if os_category == "windows":
            if (
                resolved != 4
                and resolved_image not in {"system", "ntoskrnl.exe"}
                and self.queries._is_pid_active_at(system, resolved, time)
            ):
                return resolved
        elif resolved_proc is not None and self.queries._linux_parent_usable_for_child_at(
            system=system,
            parent_pid=resolved,
            time=time,
            logon_id=logon_id,
        ):
            return resolved

        sys_pids = policy.system_process_roles(self._system_pids).get(system.hostname, {})
        if os_category == "linux":
            for role in ("bash", "sshd", "systemd"):
                candidate = sys_pids.get(role)
                if candidate and self.queries._linux_parent_usable_for_child_at(
                    system=system,
                    parent_pid=candidate,
                    time=time,
                    logon_id=logon_id,
                ):
                    return candidate
            return self._linux_system_parent_fallback(system, time)
        for role in ("explorer", "winlogon", "services", "svchost_dcom"):
            candidate = sys_pids.get(role)
            candidate_proc = self.state_manager.get_process(system.hostname, candidate or -1)
            candidate_exe = (
                candidate_proc.image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
                if candidate_proc is not None
                else ""
            )
            if process_exe in policy._WINDOWS_GUI_APPS and candidate_exe != "explorer.exe":
                continue
            if (
                candidate
                and candidate != 4
                and self.queries._is_pid_active_at(system, candidate, time)
                and self.queries._parent_process_matches_logon(
                    hostname=system.hostname,
                    parent_pid=candidate,
                    logon_id=logon_id,
                    os_category=os_category,
                )
            ):
                return candidate
        return parent_pid

    def _resolve_existing_prepared_process_parent(
        self,
        *,
        system: System,
        user: User,
        time: datetime,
        logon_id: str,
        parent_pid: int,
        process_username: str,
    ) -> int:
        """Resolve an existing parent for a required bundle without materializing helpers."""

        os_category = _get_os_category(system.os)
        if parent_pid not in {0, 4}:
            if (
                os_category == "windows"
                and self.queries._is_valid_process_parent_at(
                    system=system,
                    parent_pid=parent_pid,
                    time=time,
                )
                and self.queries._parent_process_matches_logon(
                    hostname=system.hostname,
                    parent_pid=parent_pid,
                    logon_id=logon_id,
                    os_category=os_category,
                )
            ):
                return parent_pid
            if os_category == "linux" and self.queries._linux_parent_usable_for_child_at(
                system=system,
                parent_pid=parent_pid,
                time=time,
                logon_id=logon_id,
            ):
                return parent_pid

        system_pids = policy.system_process_roles(self._system_pids).get(system.hostname, {})
        if os_category == "windows":
            user_context = (
                process_username not in _SYSTEM_ACCOUNTS and not process_username.endswith("$")
            )
            if user_context:
                explorer_pid = self._get_session_explorer_pid(
                    system,
                    user,
                    time=time,
                    logon_id=logon_id,
                )
                if explorer_pid is not None:
                    return explorer_pid
            for role in ("explorer", "winlogon", "services", "svchost_dcom", "wininit"):
                candidate = system_pids.get(role)
                if (
                    candidate is not None
                    and self.queries._is_valid_process_parent_at(
                        system=system,
                        parent_pid=candidate,
                        time=time,
                    )
                    and self.queries._parent_process_matches_logon(
                        hostname=system.hostname,
                        parent_pid=candidate,
                        logon_id=logon_id,
                        os_category=os_category,
                    )
                ):
                    return candidate
            return 4

        session_shell = self._active_session_shell_pid(system, user, time, logon_id)
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

    def _active_session_shell_pid(
        self,
        system: System,
        user: User,
        time: datetime | None,
        logon_id: str = "",
    ) -> int | None:
        """Return the actor's live per-session shell when one owns the command."""
        sessions = (
            self.state_manager.get_sessions_for_user_at(user.username, time)
            if time is not None
            else self.state_manager.get_sessions_for_user(user.username)
        )
        if logon_id:
            sessions = [sess for sess in sessions if sess.logon_id == logon_id]
        for sess in sessions:
            if sess.system != system.hostname or sess.session_shell_pid is None:
                continue
            if time is not None and not _session_active_for_activity(
                sess,
                time,
                margin_seconds=1.5,
            ):
                continue
            is_active = (
                self.queries._is_pid_active_at(system, sess.session_shell_pid, time)
                if time is not None
                else self.queries._is_pid_alive(system, sess.session_shell_pid)
            )
            if is_active:
                return sess.session_shell_pid
        return None

    def _windows_same_exe_gui_parent_pid(
        self,
        *,
        system: System,
        user: User,
        time: datetime,
        logon_id: str,
        process_name: str,
        parent_pid: int,
        process_username: str,
    ) -> int | None:
        """Return or create a same-family parent for browser/Electron child processes."""
        process_exe = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        parent_proc = self.state_manager.get_process(system.hostname, parent_pid)
        if (
            parent_proc is not None
            and parent_proc.image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower() == process_exe
            and not self._is_windows_same_exe_gui_child(parent_proc.image, parent_proc.command_line)
            and self.queries._is_pid_active_at(system, parent_pid, time)
            and self.queries._parent_process_matches_logon(
                hostname=system.hostname,
                parent_pid=parent_pid,
                logon_id=logon_id,
                os_category="windows",
            )
        ):
            return parent_pid

        candidates = []
        for proc in self.state_manager.get_processes_on_system(system.hostname):
            proc_exe = proc.image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
            if proc_exe != process_exe:
                continue
            if self._is_windows_same_exe_gui_child(proc.image, proc.command_line):
                continue
            if proc.username != process_username:
                continue
            if proc.logon_id and proc.logon_id != logon_id:
                continue
            if not self.queries._is_pid_active_at(system, proc.pid, time):
                continue
            candidates.append(proc)
        if candidates:
            return max(candidates, key=lambda candidate: candidate.start_time or time).pid

        from evidenceforge.generation.activity.application_catalog import resolve_image_path
        from evidenceforge.generation.activity.spawn_rules import get_parent_config

        parent_time = time - timedelta(
            milliseconds=150
            + (_stable_seed(f"same_exe_gui_parent:{system.hostname}:{process_exe}:{time}") % 850)
        )
        session = self.state_manager.get_session(logon_id)
        if session is not None and parent_time <= session.start_time:
            parent_time = session.start_time + timedelta(milliseconds=120)

        explorer_pid = self._ensure_session_explorer_pid(system, user, parent_time, logon_id)
        if explorer_pid is None:
            return None

        config = get_parent_config("windows", process_exe)
        templates = config.get("command_templates", [])
        parent_command = templates[0] if templates else ""
        parent_command = parent_command.replace("{username}", user.username)
        parent_image = resolve_image_path(process_exe, "windows", username=user.username)
        if not parent_image:
            parent_image = _extract_image_from_command(parent_command) or process_name
        parent_image = parent_image.replace("{username}", user.username)
        if not parent_command:
            parent_command = f'"{parent_image}"'

        return self.generate_process(
            user=user,
            system=system,
            time=parent_time,
            logon_id=logon_id,
            process_name=parent_image,
            command_line=parent_command,
            parent_pid=explorer_pid,
            allow_existing_browser_reuse=False,
        )

    def _is_windows_same_exe_gui_child(self, process_name: str, command_line: str) -> bool:
        """Return whether a Windows GUI command should be parented by its own executable."""
        process_exe = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        command = f" {command_line.lower()} "
        if process_exe in _WINDOWS_BROWSER_EXES:
            return not policy._is_top_level_browser_launch(process_name, command_line)
        if process_exe in _WINDOWS_ELECTRON_CHILD_EXES:
            return any(marker in command for marker in _WINDOWS_ELECTRON_CHILD_MARKERS)
        return False

    def _windows_explorer_parent_pid(
        self,
        system: System,
        user: User,
        time: datetime,
        logon_id: str = "",
    ) -> int:
        """Return the Windows logon-chain parent for explorer.exe.

        Explorer is the interactive shell. It is created by userinit/winlogon,
        not by arbitrary user applications that happen to be alive in the same
        session.
        """
        sessions = self.state_manager.get_sessions_for_user_at(user.username, time)
        for session in sessions:
            if session.system != system.hostname:
                continue
            if logon_id and session.logon_id != logon_id:
                continue
            if session.explorer_pid is None:
                continue
            explorer = self.state_manager.get_process(system.hostname, session.explorer_pid)
            if explorer is None:
                continue
            parent_pid = explorer.parent_pid
            if (
                parent_pid
                and self.state_manager.get_process(system.hostname, parent_pid) is not None
                and self.queries._is_pid_active_at(system, parent_pid, time)
            ):
                return parent_pid
            if (
                session.session_winlogon_pid
                and self.state_manager.get_process(system.hostname, session.session_winlogon_pid)
                is not None
                and self.queries._is_pid_active_at(system, session.session_winlogon_pid, time)
            ):
                return session.session_winlogon_pid

        sys_pids = policy.system_process_roles(self._system_pids).get(system.hostname, {})
        for role in ("userinit", "winlogon", "services", "wininit"):
            pid = sys_pids.get(role)
            if (
                pid
                and self.state_manager.get_process(system.hostname, pid) is not None
                and self.queries._is_pid_active_at(system, pid, time)
            ):
                return pid
        return sys_pids.get("winlogon", sys_pids.get("services", 4))

    def _resolve_parent(
        self,
        system: System,
        user: User,
        time: datetime,
        logon_id: str,
        process_name: str,
        command_line: str = "",
    ) -> int:
        """Resolve the parent PID for a process using spawn rules.

        Transparently finds an existing valid parent or auto-creates the
        parent chain (with realistic timing) using the spawn rules YAML.
        Falls back to the legacy _select_parent_pid() for unknown processes.
        """
        from evidenceforge.generation.activity.spawn_rules import (
            get_reverse_index_linux,
            get_reverse_index_windows,
        )

        rng = _get_rng()
        os_cat = _get_os_category(system.os)
        sys_pids = policy.system_process_roles(self._system_pids).get(system.hostname, {})

        # Extract basename for rule lookup
        if os_cat == "windows":
            exe_name = (
                process_name.rsplit("\\", 1)[-1].lower()
                if "\\" in process_name
                else process_name.lower()
            )
        else:
            exe_name = (
                process_name.rsplit("/", 1)[-1].lower()
                if "/" in process_name
                else process_name.lower()
            )

        # Special override: SYSTEM user or network logon → svchost (not services.exe directly)
        # Real Windows: services.exe → svchost.exe → cmd.exe (never services.exe → cmd.exe)
        _SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "conhost.exe"}
        is_shell = exe_name in _SHELLS
        remote_wrapper_pid = self._active_remote_execution_wrapper_pid(system, time)
        if user.username in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
            if remote_wrapper_pid is not None:
                return remote_wrapper_pid
            if is_shell:
                # Shells get svchost as parent (realistic: service host spawns shell)
                return sys_pids.get(
                    "svchost_netsvcs", sys_pids.get("svchost_dcom", sys_pids.get("wininit", 4))
                )
            shell_parent_pid = self._ensure_windows_service_shell_parent(
                system=system,
                user=user,
                time=time,
                logon_id=logon_id,
                child_exe=exe_name,
                child_command_line=command_line,
            )
            if shell_parent_pid is not None:
                return shell_parent_pid
            return sys_pids.get(
                "services", sys_pids.get("svchost_dcom", sys_pids.get("wininit", 4))
            )

        sessions = self.state_manager.get_sessions_for_user_at(user.username, time)
        # Match by logon_id when available to avoid picking the wrong session
        # when a user has both interactive (type 2) and network (type 3) sessions
        # on the same host.
        if logon_id and sessions:
            active_session = next(
                (s for s in sessions if s.system == system.hostname and s.logon_id == logon_id),
                None,
            )
        else:
            active_session = (
                next((s for s in sessions if s.system == system.hostname), None)
                if sessions
                else None
            )
        is_network_logon = active_session and active_session.logon_type == 3
        is_service_logon = active_session and active_session.logon_type == 5
        is_other_non_desktop_logon = active_session and not windows_logon_can_own_desktop(
            active_session.logon_type
        )
        if is_network_logon or (is_other_non_desktop_logon and not is_service_logon):
            if remote_wrapper_pid is not None:
                return remote_wrapper_pid
            history = self._prune_user_process_history(
                system=system,
                username=user.username,
                time=time,
                logon_id=logon_id,
            )
            remote_wrappers = []
            shells = []
            for pid, name in history:
                if not self.queries._is_pid_active_at(system, pid, time):
                    continue
                if not self.queries._parent_process_matches_logon(
                    hostname=system.hostname,
                    parent_pid=pid,
                    logon_id=logon_id,
                    os_category=os_cat,
                ):
                    continue
                hist_exe = (
                    name.rsplit("\\", 1)[-1].lower()
                    if "\\" in name
                    else name.rsplit("/", 1)[-1].lower()
                )
                if hist_exe in {"psexesvc.exe", "wmiprvse.exe", "healthmonitorsvc.exe"}:
                    remote_wrappers.append(pid)
                elif hist_exe in policy._WINDOWS_SHELL_NAMES and not (
                    self.queries._is_one_shot_shell_parent(system, pid)
                ):
                    shells.append(pid)
            if remote_wrappers:
                return remote_wrappers[-1]
            if shells:
                return shells[-1]
            if is_shell:
                return sys_pids.get(
                    "svchost_netsvcs", sys_pids.get("svchost_dcom", sys_pids.get("wininit", 4))
                )
            shell_parent_pid = self._ensure_windows_service_shell_parent(
                system=system,
                user=user,
                time=time,
                logon_id=logon_id,
                child_exe=exe_name,
                child_command_line=command_line,
            )
            if shell_parent_pid is not None:
                return shell_parent_pid
            return sys_pids.get(
                "services", sys_pids.get("svchost_dcom", sys_pids.get("wininit", 4))
            )
        if is_service_logon:
            if is_shell:
                return sys_pids.get(
                    "svchost_netsvcs",
                    sys_pids.get("svchost_dcom", sys_pids.get("services", 4)),
                )
            shell_parent_pid = self._ensure_windows_service_shell_parent(
                system=system,
                user=user,
                time=time,
                logon_id=logon_id,
                child_exe=exe_name,
                child_command_line=command_line,
            )
            if shell_parent_pid is not None:
                return shell_parent_pid
            return sys_pids.get(
                "services", sys_pids.get("svchost_dcom", sys_pids.get("wininit", 4))
            )

        if os_cat == "windows" and exe_name == "explorer.exe":
            return self._windows_explorer_parent_pid(system, user, time, logon_id)

        # Look up valid parents from spawn rules
        if os_cat == "windows":
            reverse = get_reverse_index_windows()
        else:
            reverse = get_reverse_index_linux()

        possible_parents = reverse.get(exe_name, [])
        if os_cat == "linux":
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
            session_shell_pid = self._active_session_shell_pid(system, user, time, logon_id)
            if session_shell_pid is not None and any(
                parent in {"bash", "sh", "zsh"} for parent in possible_parents
            ):
                return session_shell_pid

        if not possible_parents:
            # No rules for this exe — fall back to legacy logic
            return self._select_parent_pid(system, user, process_name, time=time, logon_id=logon_id)

        # Check alive_history for a matching parent
        history = self._prune_user_process_history(
            system=system,
            username=user.username,
            time=time,
            logon_id=logon_id,
        )
        alive_parents = []
        for pid, name in history:
            if not self.queries._is_pid_active_at(system, pid, time):
                continue
            if not self.queries._parent_process_matches_logon(
                hostname=system.hostname,
                parent_pid=pid,
                logon_id=logon_id,
                os_category=os_cat,
            ):
                continue
            hist_exe = (
                name.rsplit("\\", 1)[-1].lower()
                if "\\" in name
                else name.rsplit("/", 1)[-1].lower()
            )
            if (
                os_cat == "windows"
                and hist_exe in policy._WINDOWS_SHELL_NAMES
                and self.queries._is_one_shot_shell_parent(system, pid)
            ):
                continue
            if hist_exe in possible_parents:
                alive_parents.append((pid, name))

        # Also check seeded system processes as potential parents
        for _role, pid in sys_pids.items():
            proc = self.state_manager.get_process(system.hostname, pid)
            if proc and proc.start_time <= time:
                if os_cat == "linux" and not self.queries._linux_parent_usable_for_child_at(
                    system=system,
                    parent_pid=pid,
                    time=time,
                    logon_id=logon_id,
                ):
                    continue
                if not self.queries._parent_process_matches_logon(
                    hostname=system.hostname,
                    parent_pid=pid,
                    logon_id=logon_id,
                    os_category=os_cat,
                ):
                    continue
                proc_exe = (
                    proc.image.rsplit("\\", 1)[-1].lower()
                    if "\\" in proc.image
                    else proc.image.rsplit("/", 1)[-1].lower()
                )
                if proc_exe in possible_parents:
                    alive_parents.append((pid, proc.image))

        if alive_parents:
            # Deduplicate by PID
            seen = set()
            unique = []
            for pid, name in alive_parents:
                if pid not in seen:
                    seen.add(pid)
                    unique.append((pid, name))
            return rng.choice(unique)[0]

        # No valid parent alive — auto-create the chain
        return self._ensure_parent_chain(system, user, time, logon_id, exe_name, os_cat, depth=0)

    def _ensure_parent_chain(
        self,
        system: System,
        user: User,
        time: datetime,
        logon_id: str,
        child_exe: str,
        os_cat: str,
        depth: int = 0,
    ) -> int:
        """Recursively create parent processes needed for child_exe.

        Builds the chain up to the nearest seeded system process (explorer,
        services, sshd, systemd). Depth-limited to 3 to prevent infinite
        recursion.
        """
        from evidenceforge.generation.activity.spawn_rules import (
            get_parent_config,
            get_reverse_index_linux,
            get_reverse_index_windows,
        )

        rng = _get_rng()
        sys_pids = policy.system_process_roles(self._system_pids).get(system.hostname, {})

        if os_cat == "windows":
            reverse = get_reverse_index_windows()
        else:
            reverse = get_reverse_index_linux()

        # Safety limit
        if depth > 3:
            return self._live_parent_chain_anchor(
                system=system,
                user=user,
                time=time,
                logon_id=logon_id,
                os_cat=os_cat,
            )

        # Pick a parent for child_exe from the rules
        possible_parents = reverse.get(child_exe, [])
        if not possible_parents:
            return self._live_parent_chain_anchor(
                system=system,
                user=user,
                time=time,
                logon_id=logon_id,
                os_cat=os_cat,
            )

        # Auto-created parent chains should not fabricate a fresh parent with
        # the same executable as the child when another valid parent exists.
        # Existing same-exe parents are still honored in _resolve_parent().
        child_exe_lower = child_exe.lower()
        nonself_parents = [
            parent for parent in possible_parents if parent.lower() != child_exe_lower
        ]
        if nonself_parents:
            possible_parents = nonself_parents

        if (
            os_cat == "windows"
            and child_exe_lower in {"cmd.exe", "powershell.exe", "pwsh.exe"}
            and "explorer.exe" in {parent.lower() for parent in possible_parents}
        ):
            possible_parents = ["explorer.exe"]

        # Fresh CLI parent chains should start from a shell when the rules
        # allow it. Existing IDE/editor parents are still honored in
        # _resolve_parent(), but auto-creating a new Code.exe just to launch a
        # command-line tool looks less like a normal interactive session.
        if os_cat == "windows":
            shell_parents = [
                parent
                for parent in possible_parents
                if parent.lower() in {"cmd.exe", "powershell.exe", "pwsh.exe"}
            ]
            if shell_parents:
                possible_parents = shell_parents

        # Prefer shells for CLI tools on Windows, sshd→bash for Linux
        chosen_parent = rng.choice(possible_parents)
        if os_cat == "windows" and chosen_parent.lower() == "explorer.exe":
            session_explorer = self._ensure_session_explorer_pid(
                system, user, time=time, logon_id=logon_id
            )
            if session_explorer is not None:
                return session_explorer

        # Check if chosen parent is already a seeded system process
        for _role, pid in sys_pids.items():
            proc = self.state_manager.get_process(system.hostname, pid)
            if proc and proc.start_time <= time:
                if not self.queries._parent_process_matches_logon(
                    hostname=system.hostname,
                    parent_pid=pid,
                    logon_id=logon_id,
                    os_category=os_cat,
                ):
                    continue
                proc_exe = (
                    proc.image.rsplit("\\", 1)[-1].lower()
                    if "\\" in proc.image
                    else proc.image.rsplit("/", 1)[-1].lower()
                )
                if proc_exe == chosen_parent:
                    return pid

        # Not a seeded process — need to create it, but first ensure ITS parent
        grandparent_pid = self._ensure_parent_chain(
            system, user, time, logon_id, chosen_parent, os_cat, depth=depth + 1
        )

        # Get command template for the parent we're creating
        config = get_parent_config(os_cat, chosen_parent)
        cmd_templates = config.get("command_templates", [chosen_parent])
        cmd_line = rng.choice(cmd_templates)

        # Derive image path from command_templates (which have correct full paths)
        # rather than blindly prefixing C:\Windows\System32\
        image = None
        from evidenceforge.generation.activity.application_catalog import resolve_image_path

        if os_cat == "windows":
            for tmpl in cmd_templates:
                if "\\" in tmpl:
                    image = _extract_image_from_command(tmpl)
                    break
            if not image:
                image = resolve_image_path(chosen_parent, "windows", username=user.username)
        else:
            for tmpl in cmd_templates:
                if "/" in tmpl:
                    image = _extract_image_from_command(tmpl)
                    break
            if not image:
                image = resolve_image_path(chosen_parent, "linux")
                if chosen_parent in ("bash", "sh", "zsh"):
                    image = f"/bin/{chosen_parent}"

        profiled_worker = matching_service_worker(
            os_category=os_cat,
            image=image,
            command_line=cmd_line,
            username=user.username,
        )
        if profiled_worker is not None:
            family_name, worker_name, _family = profiled_worker
            return self._ensure_profiled_service_worker(
                system=system,
                worker_time=time,
                activity_time=time,
                family_name=family_name,
                worker_name=worker_name,
            )

        # Timing: parent is created before child
        spawn_delay = config.get("spawn_delay", [0.5, 3.0])
        delay_sec = rng.uniform(spawn_delay[0], spawn_delay[1])
        parent_time = time - timedelta(seconds=delay_sec * (depth + 1))
        session = self.state_manager.get_session(logon_id)
        if session is not None and parent_time <= session.start_time:
            parent_time = session.start_time + timedelta(milliseconds=10 * (4 - depth))

        if not self.queries._is_valid_process_parent_at(
            system=system,
            parent_pid=grandparent_pid,
            time=parent_time,
        ):
            grandparent_pid = self._live_parent_chain_anchor(
                system=system,
                user=user,
                time=parent_time,
                logon_id=logon_id,
                os_cat=os_cat,
            )

        # Determine if this is a pre-existing process (no creation event)
        # Long-lived parents early in the scenario were "already running"
        lifetime = config.get("lifetime", "long")
        scenario_start = getattr(self, "_scenario_start_time", None)
        is_pre_existing = False
        if lifetime == "long" and scenario_start:
            elapsed = (time - scenario_start).total_seconds()
            if elapsed < 1800 and rng.random() < 0.7:  # First 30 min, 70% chance
                is_pre_existing = True
        # Parents created before the output window are always pre-existing
        # (their creation events would be suppressed by the warm-up filter anyway)
        if not is_pre_existing and scenario_start and parent_time < scenario_start:
            is_pre_existing = True

        # Parent-chain members are canonical lifecycle owners, not State-only
        # compatibility objects. Freeze the exact identity before publication so
        # every positive PID returned to a strict child is already registered and
        # live under that same identity.
        process_plan = self.state_manager.plan_process_materialization(
            system=system.hostname,
            parent_pid=grandparent_pid,
            image=image,
            command_line=cmd_line,
            username=user.username,
            integrity_level="System" if user.username == "SYSTEM" else "Medium",
            os_category=os_cat,
            logon_id=logon_id,
            start_time=parent_time,
        )
        process_identity = process_plan.identity
        parent_pid = process_identity.pid

        if is_pre_existing:
            self._lifecycle_authority.materialize_process(process_plan)
        else:
            # Emit the same single parent process-creation row, but bind it to the
            # external materialization plan and authenticate publication with the
            # lifecycle receipt.
            from evidenceforge.events.base import OccurrenceBuilder

            event = OccurrenceBuilder(
                timestamp=parent_time,
                event_type="process_create",
                src_host=self.identity.host_context(system),
                auth=AuthContext(
                    username=user.username,
                    user_sid=self.identity.user_sid(user.username),
                    logon_id=logon_id,
                ),
                process=ProcessContext(
                    pid=parent_pid,
                    parent_pid=grandparent_pid,
                    image=image,
                    command_line=cmd_line,
                    username=user.username,
                    integrity_level="Medium",
                    logon_id=logon_id,
                    parent_image=self.queries._lookup_process_name(
                        system.hostname, grandparent_pid, _get_os_category(system.os)
                    ),
                    parent_command_line=self.queries._lookup_parent_command_line(
                        system.hostname, grandparent_pid
                    ),
                    parent_start_time=self.queries._lookup_parent_start_time(
                        system.hostname, grandparent_pid
                    ),
                    token_elevation="%%1938",
                    mandatory_label="S-1-16-8192",
                    start_time=process_identity.started_at,
                ),
                identity_plan=EventIdentityPlan(
                    subject=process_identity,
                    actor=process_plan.parent_identity,
                ),
                lifecycle=ActionLifecycleContext(
                    group_id=process_identity.lifecycle_group_id,
                    canonical_start=process_identity.started_at,
                    phase="start",
                    parent_group_id=process_identity.parent_lifecycle_group_id or None,
                ),
            )
            with self.dispatcher.source_timing_planner.prepared_planning() as timing_preparation:
                prepared_dispatch = self.dispatcher.prepare_builder(
                    event,
                    state_intent=PreparedDispatchStateIntent.EXTERNAL_MATERIALIZED_START,
                    lifecycle_ticket=process_plan,
                    source_timing_preparation=timing_preparation,
                )
            self.dispatcher.validate_prepared(prepared_dispatch)
            with timing_preparation.claimed_commit():
                _parent, materialization_receipt = self._lifecycle_authority.materialize_process(
                    process_plan,
                    finalize_external_no_fail=timing_preparation.commit_no_fail,
                )
            self.dispatcher.publish_prepared(
                prepared_dispatch,
                materialization_receipt=materialization_receipt,
            )

        # Record in user process history
        self._record_user_process(system, user, parent_pid, image)
        return parent_pid

    def _ensure_windows_service_shell_parent(
        self,
        *,
        system: System,
        user: User,
        time: datetime,
        logon_id: str,
        child_exe: str,
        child_command_line: str = "",
    ) -> int | None:
        """Create a short-lived SYSTEM shell for service-context admin utilities."""
        if _get_os_category(system.os) != "windows":
            return None
        if child_exe not in policy._WINDOWS_SERVICE_SHELL_CHILDREN:
            return None

        parent_pid = self._windows_remote_command_owner_pid(
            system=system,
            time=time,
            child_exe=child_exe,
            child_command_line=child_command_line,
        )
        shell_time = time - timedelta(
            milliseconds=120
            + (_stable_seed(f"windows-service-shell:{system.hostname}:{child_exe}:{time}") % 90)
        )
        session = self.state_manager.get_session(logon_id)
        if session is not None and shell_time <= session.start_time:
            shell_time = session.start_time + timedelta(milliseconds=40)
        if shell_time >= time:
            shell_time = time - timedelta(milliseconds=40)

        rendered_child = child_command_line.strip() or child_exe
        shell_command = f"C:\\Windows\\System32\\cmd.exe /c {rendered_child}"
        shell_pid = self.generate_process(
            user=user,
            system=system,
            time=shell_time,
            logon_id=logon_id,
            process_name=r"C:\Windows\System32\cmd.exe",
            command_line=shell_command,
            parent_pid=parent_pid,
            ensure_file_event=False,
            from_storyline=True,
            suppress_command_file_effect=True,
            allow_existing_browser_reuse=False,
            allow_browser_launch_spacing=False,
        )
        self._record_user_process(system, user, shell_pid, r"C:\Windows\System32\cmd.exe")
        return shell_pid

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

    def _active_remote_execution_wrapper_pid(self, system: System, time: datetime) -> int | None:
        """Return a live explicit remote-execution service wrapper, if one exists."""
        wrappers = []
        for proc in self.state_manager.get_processes_on_system(system.hostname):
            exe = proc.image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
            if exe not in {"psexesvc.exe", "healthmonitorsvc.exe"}:
                continue
            if not self.queries._is_pid_active_at(system, proc.pid, time):
                continue
            wrappers.append(proc)
        if not wrappers:
            return None
        wrappers.sort(key=lambda proc: proc.start_time or time)
        return wrappers[-1].pid

    def _select_parent_pid(
        self,
        system: System,
        user: User,
        process_name: str,
        time: datetime | None = None,
        logon_id: str = "",
    ) -> int:
        """Select a realistic parent PID based on process type and history.

        Builds process trees with depth by tracking recent user processes.
        Windows GUI apps always spawn from explorer.exe.
        CLI/script processes can spawn from shells.
        Linux user processes typically spawn from login shells.

        Only returns PIDs that are still alive in the state manager.
        """
        rng = _get_rng()
        sys_pids = policy.system_process_roles(self._system_pids).get(system.hostname, {})
        os_cat = _get_os_category(system.os)
        effective_time = time or self.state_manager.state.current_time or datetime.now(UTC)
        history = self._prune_user_process_history(
            system=system,
            username=user.username,
            time=effective_time,
            logon_id=logon_id,
        )
        # Filter history to only include still-running processes
        alive_history = []
        for pid, name in history:
            if not self.queries._parent_process_matches_logon(
                hostname=system.hostname,
                parent_pid=pid,
                logon_id=logon_id,
                os_category=os_cat,
            ):
                continue
            if time is not None:
                if self.queries._is_pid_active_at(system, pid, time):
                    alive_history.append((pid, name))
            elif self.queries._is_pid_alive(system, pid):
                alive_history.append((pid, name))

        if os_cat == "windows":
            exe_name = (
                process_name.rsplit("\\", 1)[-1].lower()
                if "\\" in process_name
                else process_name.lower()
            )
            # Check if the user's active session on this system is a network
            # logon (type 3). Network logons never spawn explorer.exe — processes
            # are parented by svchost.exe or services.exe instead.
            sessions = self.state_manager.get_sessions_for_user(user.username)
            if logon_id and sessions:
                active_session = next(
                    (s for s in sessions if s.system == system.hostname and s.logon_id == logon_id),
                    None,
                )
            else:
                active_session = (
                    next((s for s in sessions if s.system == system.hostname), None)
                    if sessions
                    else None
                )
            is_network_logon = active_session and active_session.logon_type == 3
            is_service_logon = active_session and active_session.logon_type == 5
            is_other_non_desktop_logon = active_session and not windows_logon_can_own_desktop(
                active_session.logon_type
            )

            if is_network_logon or (is_other_non_desktop_logon and not is_service_logon):
                # Network logon: parent is services.exe or svchost.exe
                # (processes arrive via PsExec, WMI, or SMB)
                # CLI/script processes: check for a running shell as parent first
                shells = [
                    (pid, name)
                    for pid, name in alive_history
                    if name.rsplit("\\", 1)[-1].lower() in policy._WINDOWS_SHELL_NAMES
                    and not self.queries._is_one_shot_shell_parent(system, pid)
                ]
                if shells and rng.random() < 0.6:
                    return shells[-1][0]
                return sys_pids.get(
                    "services", sys_pids.get("svchost_dcom", sys_pids.get("wininit", 4))
                )
            if is_service_logon:
                if exe_name in policy._WINDOWS_SHELLS:
                    return sys_pids.get(
                        "svchost_netsvcs",
                        sys_pids.get("svchost_dcom", sys_pids.get("services", 4)),
                    )
                return sys_pids.get(
                    "services", sys_pids.get("svchost_dcom", sys_pids.get("wininit", 4))
                )

            if exe_name == "explorer.exe":
                return self._windows_explorer_parent_pid(
                    system, user, effective_time, active_session.logon_id if active_session else ""
                )

            # Prefer session-specific explorer PID over system-wide default
            session_explorer = self._ensure_session_explorer_pid(
                system, user, time=time, logon_id=logon_id
            )
            fallback_explorer = sys_pids.get("explorer")
            if fallback_explorer:
                fallback_proc = self.state_manager.get_process(system.hostname, fallback_explorer)
                fallback_exe = (
                    fallback_proc.image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
                    if fallback_proc is not None
                    else ""
                )
                if fallback_exe != "explorer.exe" or not self.queries._parent_process_matches_logon(
                    hostname=system.hostname,
                    parent_pid=fallback_explorer,
                    logon_id=logon_id,
                    os_category=os_cat,
                ):
                    fallback_explorer = None
            explorer_pid = (
                session_explorer
                or fallback_explorer
                or sys_pids.get("winlogon", sys_pids.get("services", 4))
            )

            # Shells and terminals spawn from explorer.exe
            if exe_name in policy._WINDOWS_SHELLS:
                return explorer_pid

            # GUI apps always spawn from explorer.exe (user launches via Start Menu/desktop)
            if exe_name in policy._WINDOWS_GUI_APPS:
                return explorer_pid

            # CLI/script processes: check for a running shell as parent
            shells = [
                (pid, name)
                for pid, name in alive_history
                if name.rsplit("\\", 1)[-1].lower() in policy._WINDOWS_SHELL_NAMES
                and not self.queries._is_one_shot_shell_parent(system, pid)
            ]
            if shells and rng.random() < 0.6:
                return shells[-1][0]

            # Check for a browser/app that could spawn this process (e.g. download+run)
            spawners = [
                (pid, name)
                for pid, name in alive_history
                if name.rsplit("\\", 1)[-1].lower() in policy._WINDOWS_SPAWNERS
            ]
            if spawners and rng.random() < 0.3:
                return spawners[-1][0]

            # Default: session-specific or system-wide explorer.exe
            return explorer_pid
        else:
            # Linux: most user commands spawn from a shell
            session_shell_pid = self._active_session_shell_pid(
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

    def _prune_user_process_history(
        self,
        *,
        system: System,
        username: str,
        time: datetime,
        logon_id: str = "",
    ) -> list[tuple[int, str]]:
        """Drop ended process PIDs from recent parent-selection history."""
        key = (system.hostname, username)
        history = self._user_process_history.get(key, [])
        if not history:
            return []

        os_category = _get_os_category(system.os)
        pruned = [
            (pid, image)
            for pid, image in history
            if self.queries._is_pid_active_at(system, pid, time)
            and self.queries._parent_process_matches_logon(
                hostname=system.hostname,
                parent_pid=pid,
                logon_id=logon_id,
                os_category=os_category,
            )
            and (
                os_category != "linux"
                or self.queries._linux_parent_usable_for_child_at(
                    system=system,
                    parent_pid=pid,
                    time=time,
                    logon_id=logon_id,
                )
            )
        ]
        self._user_process_history[key] = pruned[-10:]
        return self._user_process_history[key]

    def _windows_remote_command_owner_pid(
        self,
        *,
        system: System,
        time: datetime,
        child_exe: str,
        child_command_line: str,
    ) -> int:
        """Return a concrete service-family owner for a remote/admin shell."""
        sys_pids = policy.system_process_roles(self._system_pids).get(system.hostname, {})
        exe = child_exe.lower()
        command = child_command_line.lower()
        owner_keys: tuple[str, ...]

        if exe == "schtasks.exe" or "schtasks" in command:
            if "/create" in command or " /create" in command:
                owner_keys = ("wmiprvse", "svchost_dcom", "services")
            else:
                owner_keys = ("taskhostw", "svchost_local_system", "services")
        elif exe in {"wmic.exe", "wmic"} or "wmic " in command:
            owner_keys = ("wmiprvse", "svchost_dcom", "services")
        elif exe in {"sc.exe", "sc"} or "sc.exe create" in command or " sc create" in command:
            owner_keys = ("wmiprvse", "svchost_dcom", "services")
        elif exe in {"wevtutil.exe", "wevtutil", "net.exe", "net1.exe", "net", "net1"}:
            owner_keys = ("wmiprvse", "taskhostw", "services")
        elif "powershell" in command or "winrm" in command or "invoke-command" in command:
            owner_keys = ("wmiprvse", "svchost_dcom", "services")
        else:
            seed = _stable_seed(
                f"windows_remote_owner:{system.hostname}:{exe}:{child_command_line}"
            )
            owner_keys = (
                ("wmiprvse", "taskhostw", "services")
                if seed % 2
                else ("taskhostw", "wmiprvse", "services")
            )

        for key in owner_keys:
            pid = sys_pids.get(key)
            if pid and self.queries._is_pid_active_at(system, pid, time):
                return pid
        return sys_pids.get("services", sys_pids.get("svchost_dcom", sys_pids.get("wininit", 4)))

    def _record_user_process(self, system: System, user: User, pid: int, process_name: str) -> None:
        """Record a user process in history for future parent selection."""
        proc = self.state_manager.get_process(system.hostname, pid)
        if proc is not None:
            process_name = proc.image
        key = (system.hostname, user.username)
        self._user_process_history.setdefault(key, []).append((pid, process_name))
        # Keep only last 10 processes per user/system
        if len(self._user_process_history[key]) > 10:
            self._user_process_history[key] = self._user_process_history[key][-10:]

    def _live_parent_chain_anchor(
        self,
        *,
        system: System,
        user: User,
        time: datetime,
        logon_id: str,
        os_cat: str,
    ) -> int:
        """Return a verified live process anchor for recursive parent-chain repair."""
        sys_pids = policy.system_process_roles(self._system_pids).get(system.hostname, {})
        if os_cat == "windows":
            session_explorer = self._ensure_session_explorer_pid(
                system,
                user,
                time=time,
                logon_id=logon_id,
            )
            if session_explorer is not None and self.queries._is_valid_process_parent_at(
                system=system,
                parent_pid=session_explorer,
                time=time,
            ):
                return session_explorer
            return self._windows_system_parent_fallback(system, time)

        for role in ("bash", "sshd"):
            candidate = sys_pids.get(role)
            if candidate and self.queries._linux_parent_usable_for_child_at(
                system=system,
                parent_pid=candidate,
                time=time,
                logon_id=logon_id,
            ):
                return candidate
        return self._linux_system_parent_fallback(system, time)

    def _ensure_profiled_service_worker(
        self,
        *,
        system: System,
        worker_time: datetime,
        activity_time: datetime,
        family_name: str,
        worker_name: str,
        source_visible_by: datetime | None = None,
    ) -> int:
        """Create or reuse one worker beneath its exact resident service manager."""

        worker_time = ensure_utc(worker_time)
        activity_time = ensure_utc(activity_time)
        source_deadline = ensure_utc(source_visible_by) if source_visible_by is not None else None
        if source_deadline is not None and worker_time > source_deadline:
            return 0

        family = service_process_family(family_name)
        if family.os_category != _get_os_category(system.os):
            raise ValueError(f"service family {family_name!r} does not support {system.os!r}")
        try:
            worker = family.workers[worker_name]
        except KeyError as exc:
            raise KeyError(
                f"unknown worker {worker_name!r} for service family {family_name!r}"
            ) from exc

        singleton_worker_pid = None
        if source_deadline is not None:
            singleton_worker_pid = self.reuse._existing_windows_singleton_service_pid(
                system=system,
                process_name=worker.image,
                time=activity_time,
                username=worker.username,
                command_line=worker.command_line,
            )
            if singleton_worker_pid is not None and not self.sources._process_source_visible_by(
                system=system,
                pid=singleton_worker_pid,
                deadline=source_deadline,
            ):
                # The recursive worker path must not discover this conflict only
                # after publishing a newly materialized service manager.
                return 0

        manager_parent = self._profiled_service_manager_parent_pid(
            system=system,
            time=activity_time,
            family=family,
            existing_only=source_deadline is not None,
        )
        if source_deadline is not None and manager_parent <= 0:
            return 0
        manager_pid = self._active_profiled_service_process(
            system=system,
            time=activity_time,
            spec=family.manager,
            parent_pid=manager_parent,
        )
        manager_source_deadline = (
            source_deadline - timedelta(milliseconds=1) if source_deadline is not None else None
        )
        manager_time = None
        manager_source_time = None
        if manager_pid is not None:
            manager_source_time = self.sources._process_source_frontier_or_bound(
                system=system,
                pid=manager_pid,
            )
            if manager_source_deadline is not None and (
                manager_source_time is None or manager_source_time > manager_source_deadline
            ):
                return 0
        else:
            manager_seed = _stable_seed(
                f"service_process_manager:{system.hostname}:{family_name}:{worker_time.isoformat()}"
            )
            manager_time = worker_time - timedelta(seconds=30 + (manager_seed % 271))
            if manager_source_deadline is not None:
                manager_source_time = self.sources._process_create_source_bound(
                    system=system,
                    canonical_time=manager_time,
                    parent_source_time=self.sources._process_source_frontier_or_bound(
                        system=system,
                        pid=manager_parent,
                    ),
                )
                if manager_source_time > manager_source_deadline:
                    return 0

        worker_pid = (
            self._active_profiled_service_process(
                system=system,
                time=activity_time,
                spec=worker,
                parent_pid=manager_pid,
            )
            if manager_pid is not None
            else None
        )
        if worker_pid is not None and source_deadline is not None:
            if not self.sources._process_source_visible_by(
                system=system,
                pid=worker_pid,
                deadline=source_deadline,
            ):
                return 0
        if (
            source_deadline is not None
            and singleton_worker_pid is None
            and manager_source_time is not None
            and worker_pid is None
        ):
            prospective_worker_time = worker_time
            manager_process = (
                self.state_manager.get_process(system.hostname, manager_pid)
                if manager_pid is not None
                else None
            )
            manager_start_time = (
                manager_process.start_time if manager_process is not None else manager_time
            )
            if manager_start_time is not None:
                earliest_worker_time = manager_start_time + timedelta(milliseconds=1)
                if earliest_worker_time < activity_time:
                    prospective_worker_time = max(
                        prospective_worker_time,
                        earliest_worker_time,
                    )
                else:
                    prospective_worker_time = activity_time
            worker_source_bound = self.sources._process_create_source_bound(
                system=system,
                canonical_time=prospective_worker_time,
                parent_source_time=manager_source_time,
            )
            if worker_source_bound > source_deadline:
                return 0

        if manager_pid is None:
            if manager_time is None:
                raise StateError("Profiled service manager preflight lost its canonical start")
            manager_pid = self.generate_system_process(
                system=system,
                time=manager_time,
                process_name=family.manager.image,
                command_line=family.manager.command_line,
                parent_pid=manager_parent,
                username=family.manager.username,
                emit_linux_syslog=False,
                _profiled_service_bypass=True,
                _skip_singleton_reuse=True,
                source_visible_by=manager_source_deadline,
            )
            if manager_pid <= 0:
                return 0

        if worker_pid is None:
            worker_pid = self._active_profiled_service_process(
                system=system,
                time=activity_time,
                spec=worker,
                parent_pid=manager_pid,
            )
        if worker_pid is None:
            manager_process = self.state_manager.get_process(system.hostname, manager_pid)
            if manager_process is not None:
                earliest_worker_time = manager_process.start_time + timedelta(milliseconds=1)
                if earliest_worker_time < activity_time:
                    worker_time = max(worker_time, earliest_worker_time)
                else:
                    worker_time = activity_time
            worker_pid = self.generate_system_process(
                system=system,
                time=worker_time,
                process_name=worker.image,
                command_line=worker.command_line,
                parent_pid=manager_pid,
                username=worker.username,
                emit_linux_syslog=False,
                _profiled_service_bypass=True,
                source_visible_by=source_visible_by,
            )
            if worker_pid <= 0:
                return 0
        retained_pids = policy.system_process_roles(self._system_pids).setdefault(
            system.hostname, {}
        )
        retained_pids[family.manager.key] = manager_pid
        retained_pids[worker.key] = worker_pid
        return worker_pid

    def _profiled_service_manager_parent_pid(
        self,
        *,
        system: System,
        time: datetime,
        family: ServiceProcessFamily,
        existing_only: bool = False,
    ) -> int:
        """Resolve the configured service-control parent for one resident manager."""

        sys_pids = policy.system_process_roles(self._system_pids).get(system.hostname, {})
        configured = sys_pids.get(family.manager.parent_key)
        if configured and self.queries._is_pid_active_at(system, configured, time):
            return configured
        if existing_only:
            return self._resolve_existing_prepared_process_parent(
                system=system,
                user=self.identity.user_for_username(family.manager.username),
                time=time,
                logon_id="0x3e7",
                parent_pid=0,
                process_username=family.manager.username,
            )
        if family.os_category == "windows":
            return self._windows_system_parent_fallback(system, time)
        return self._linux_system_parent_fallback(system, time)

    def _active_profiled_service_process(
        self,
        *,
        system: System,
        time: datetime,
        spec: ServiceProcessSpec,
        parent_pid: int,
    ) -> int | None:
        """Return one exact active service manager or worker process."""

        candidates = [
            process
            for process in self.state_manager.get_processes_on_system(system.hostname)
            if process.image.replace("/", "\\").casefold()
            == spec.image.replace("/", "\\").casefold()
            and process.command_line == spec.command_line
            and process.username.casefold() == spec.username.casefold()
            and process.parent_pid == parent_pid
            and process.start_time <= time
            and self.queries._is_pid_active_at(system, process.pid, time)
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda process: process.start_time).pid
