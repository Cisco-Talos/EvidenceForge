# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Apply Windows desktop, service and remote-command parent policies."""

from __future__ import annotations

import logging
import random
from dataclasses import dataclass
from datetime import datetime, timedelta

from evidenceforge.events.authentication import windows_logon_can_own_desktop
from evidenceforge.generation.activity.helpers import _get_os_category
from evidenceforge.generation.activity.process_helpers import _SYSTEM_ACCOUNTS
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import System, User
from evidenceforge.utils.rng import _stable_seed

from . import policy
from .capabilities import (
    CreateWindowsSessionShellLifecycleCapability,
    GenerateProcessCapability,
)
from .parent_history import ProcessParentHistory
from .policy import (
    _WINDOWS_BROWSER_EXES,
    _WINDOWS_ELECTRON_CHILD_EXES,
    _WINDOWS_ELECTRON_CHILD_MARKERS,
    _extract_image_from_command,
)
from .queries import ProcessStateQueries

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class WindowsProcessParents:
    """Parent operations over existing owners; no independent runtime state."""

    _create_windows_session_shell_lifecycle: CreateWindowsSessionShellLifecycleCapability
    _system_pids: dict[str, dict[str, int]] | None
    generate_process: GenerateProcessCapability
    state_manager: StateManager
    queries: ProcessStateQueries
    history: ProcessParentHistory

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

    def _windows_system_parent_fallback(self, system: System, time: datetime) -> int:
        """Return a live Windows service ancestry fallback for system processes."""
        sys_pids = policy.system_process_roles(self._system_pids).get(system.hostname, {})
        for role in ("services", "svchost_netsvcs", "svchost_dcom", "wininit"):
            pid = sys_pids.get(role)
            if pid and self.queries._is_pid_active_at(system, pid, time):
                return pid
        return 4

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
        self.history._record_user_process(system, user, shell_pid, r"C:\Windows\System32\cmd.exe")
        return shell_pid

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

    def select_from_history(
        self,
        system: System,
        user: User,
        process_name: str,
        time: datetime | None,
        logon_id: str,
        *,
        sys_pids: dict[str, int],
        effective_time: datetime,
        alive_history: list[tuple[int, str]],
        rng: random.Random,
    ) -> int:
        """Select a parent after shared history filtering without changing draw order."""
        os_cat = "windows"
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

    def sanitize_candidate(
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
        parent_image: str,
        process_exe: str,
        is_browser_child: bool,
        is_same_exe_gui_child: bool,
    ) -> int | None:
        """Accept or materialize a Windows candidate before shared resolution fallback."""
        os_category = "windows"
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
        return None

    def system_account_parent(
        self,
        system: System,
        user: User,
        time: datetime,
        logon_id: str,
        exe_name: str,
        command_line: str,
        is_shell: bool,
        remote_wrapper_pid: int | None,
        sys_pids: dict[str, int],
    ) -> int:
        """Resolve this account/session branch at its original shared selection phase."""
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
        return sys_pids.get("services", sys_pids.get("svchost_dcom", sys_pids.get("wininit", 4)))

    def non_desktop_parent(
        self,
        system: System,
        user: User,
        time: datetime,
        logon_id: str,
        exe_name: str,
        command_line: str,
        is_shell: bool,
        remote_wrapper_pid: int | None,
        sys_pids: dict[str, int],
        os_cat: str,
    ) -> int:
        """Resolve this account/session branch at its original shared selection phase."""
        if remote_wrapper_pid is not None:
            return remote_wrapper_pid
        history = self.history._prune_user_process_history(
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
        return sys_pids.get("services", sys_pids.get("svchost_dcom", sys_pids.get("wininit", 4)))

    def service_logon_parent(
        self,
        system: System,
        user: User,
        time: datetime,
        logon_id: str,
        exe_name: str,
        command_line: str,
        is_shell: bool,
        sys_pids: dict[str, int],
    ) -> int:
        """Resolve this account/session branch at its original shared selection phase."""
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
        return sys_pids.get("services", sys_pids.get("svchost_dcom", sys_pids.get("wininit", 4)))

    def existing_parent_fallback(
        self,
        system: System,
        user: User,
        time: datetime,
        logon_id: str,
        process_username: str,
        system_pids: dict[str, int],
    ) -> int:
        """Select an existing fallback after the shared explicit-parent checks."""
        os_category = "windows"
        user_context = process_username not in _SYSTEM_ACCOUNTS and not process_username.endswith(
            "$"
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

    def service_user_parent(self, system: System, process_exe: str, parent_pid: int) -> int:
        """Replace a service session's Explorer parent using existing role precedence."""
        sys_pids = policy.system_process_roles(self._system_pids).get(system.hostname, {})
        if process_exe in policy._WINDOWS_SHELLS:
            return sys_pids.get(
                "svchost_netsvcs",
                sys_pids.get("svchost_dcom", sys_pids.get("services", parent_pid)),
            )
        return sys_pids.get(
            "services", sys_pids.get("svchost_dcom", sys_pids.get("wininit", parent_pid))
        )

    def sanitized_role_fallback(
        self,
        system: System,
        time: datetime,
        logon_id: str,
        process_exe: str,
        parent_pid: int,
        sys_pids: dict[str, int],
    ) -> int:
        """Apply Windows fallback-role eligibility after shared ancestry resolution."""
        os_category = "windows"
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
