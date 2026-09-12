# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Read canonical process and session identity from existing State indexes."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from evidenceforge.generation.activity.helpers import _get_os_category
from evidenceforge.generation.activity.process_helpers import _SYSTEM_ACCOUNTS as _SYSTEM_ACCOUNTS
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import System
from evidenceforge.utils.time import ensure_utc

from . import policy

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProcessStateQueries:
    """Ephemeral operations; injected maps and managers remain on their existing owners."""

    _terminated_process_keys: set[tuple[str, int, datetime | None]]
    state_manager: StateManager

    def _lookup_process_name(self, hostname: str, pid: int, os_category: str = "windows") -> str:
        """Look up the image path of a running process by PID.

        PID 4 is always the Windows System process (ntoskrnl.exe). Unknown
        Linux PIDs have no safe parent image: returning a shell there fabricates
        impossible eCAR parent relationships such as bash with ppid=4.
        """
        if pid == 4 and os_category == "windows":
            return r"C:\Windows\System32\ntoskrnl.exe"
        key = (hostname, pid)
        proc = self.state_manager.state.running_processes.get(key)
        if proc:
            return proc.image
        if os_category == "linux":
            return "-"
        return r"C:\Windows\explorer.exe"

    def _lookup_parent_command_line(self, hostname: str, parent_pid: int) -> str:
        """Look up parent process command line from StateManager."""
        proc = self.state_manager.get_process(hostname, parent_pid)
        if proc:
            return proc.command_line
        return "-"

    def _lookup_parent_start_time(self, hostname: str, parent_pid: int) -> datetime | None:
        """Look up parent process start time at event construction time."""
        proc = self.state_manager.get_process(hostname, parent_pid)
        return proc.start_time if proc else None

    def _session_id_for_logon(self, logon_id: str) -> int:
        """Return the canonical source-native session ID for a LogonID."""
        if not logon_id:
            return 0
        return self.state_manager.get_session_id(logon_id)

    def _is_pid_active_at(self, system: System, pid: int, time: datetime) -> bool:
        """Check whether a PID exists and has started by the requested time."""
        if pid == 4 and _get_os_category(system.os) == "windows":
            return True
        proc = self.state_manager.get_process(system.hostname, pid)
        return proc is not None and proc.start_time <= time

    def _is_pid_alive(self, system: System, pid: int) -> bool:
        """Check if a PID is still running in state manager."""
        return self.state_manager.get_process(system.hostname, pid) is not None

    def _is_valid_process_parent_at(
        self,
        *,
        system: System,
        parent_pid: int,
        time: datetime,
    ) -> bool:
        """Return whether a PID can be passed to StateManager.create_process()."""
        if parent_pid == 0:
            return True
        if parent_pid == 4 and _get_os_category(system.os) == "windows":
            return True
        return self._is_pid_active_at(system, parent_pid, time)

    def _parent_process_matches_logon(
        self,
        *,
        hostname: str,
        parent_pid: int,
        logon_id: str,
        os_category: str,
    ) -> bool:
        """Return whether a parent process can source-native spawn this session's child."""
        if os_category != "windows" or not logon_id:
            return True
        parent_proc = self.state_manager.get_process(hostname, parent_pid)
        if parent_proc is None or not parent_proc.logon_id:
            if parent_proc is not None:
                parent_exe = parent_proc.image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
                if (
                    parent_exe == "explorer.exe"
                    and parent_proc.username not in _SYSTEM_ACCOUNTS
                    and not parent_proc.username.endswith("$")
                ):
                    return False
            return True
        if parent_proc.username in _SYSTEM_ACCOUNTS or parent_proc.username.endswith("$"):
            return True
        return parent_proc.logon_id == logon_id

    def _process_instance_key(
        self,
        hostname: str,
        pid: int,
        start_time: datetime | None = None,
    ) -> tuple[str, int, datetime | None]:
        """Return a PID-reuse-safe key for the current process instance."""
        if start_time is None:
            state_manager = getattr(self, "state_manager", None)
            process = (
                state_manager.get_process(hostname, pid) if state_manager is not None else None
            )
            if process is not None:
                start_time = process.start_time
        return hostname, pid, start_time

    def _process_termination_recorded(
        self,
        hostname: str,
        pid: int,
        start_time: datetime | None,
    ) -> bool:
        """Return whether a process instance termination was already generated."""
        if start_time is None:
            return any(
                terminated_host == hostname and terminated_pid == pid
                for terminated_host, terminated_pid, _ in self._terminated_process_keys
            )
        return (hostname, pid, start_time) in self._terminated_process_keys

    def _windows_shell_parent_invokes_child(
        self,
        *,
        system: System,
        parent_pid: int,
        process_name: str,
        command_line: str,
    ) -> bool:
        """Return whether a one-shot shell parent directly invokes this child command."""
        parent_proc = self.state_manager.get_process(system.hostname, parent_pid)
        if parent_proc is None:
            return False
        if not policy._is_one_shot_shell_command(parent_proc.image, parent_proc.command_line):
            return False
        payload = policy._windows_one_shot_shell_payload(
            parent_proc.image,
            parent_proc.command_line,
        )
        if not payload:
            return False
        parent_signature = policy._windows_shell_command_signature(payload)
        if not parent_signature:
            return False
        return parent_signature in policy._windows_child_command_signatures(
            process_name,
            command_line,
        )

    def _is_one_shot_shell_parent(self, system: System, pid: int) -> bool:
        """Return whether PID is a short-lived shell unsuitable as a later parent."""
        proc = self.state_manager.get_process(system.hostname, pid)
        if proc is None:
            return False
        return policy._is_one_shot_shell_command(proc.image, proc.command_line)

    def _linux_parent_usable_for_child_at(
        self,
        *,
        system: System,
        parent_pid: int,
        time: datetime,
        logon_id: str = "",
    ) -> bool:
        """Return whether a Linux parent process is usable at a child timestamp."""
        parent_proc = self.state_manager.get_process(system.hostname, parent_pid)
        if parent_proc is None:
            return False
        if not self._is_pid_active_at(system, parent_pid, time):
            return False
        if self._process_termination_recorded(
            system.hostname,
            parent_pid,
            parent_proc.start_time,
        ):
            return False

        parent_logon_id = parent_proc.logon_id or ""
        if parent_logon_id:
            parent_session_end = self.state_manager.get_session_end_time(parent_logon_id)
            if parent_session_end is not None and ensure_utc(time) >= ensure_utc(
                parent_session_end
            ):
                return False
            if logon_id and parent_logon_id != logon_id:
                parent_username = parent_proc.username or ""
                parent_exe = parent_proc.image.rsplit("/", 1)[-1].lower()
                is_linux_ssh_priv_parent = (
                    parent_username == "root"
                    and parent_exe == "sshd"
                    and parent_proc.command_line.startswith("sshd: ")
                    and parent_proc.command_line.endswith(" [priv]")
                )
                is_linux_login_priv_parent = (
                    parent_username == "root"
                    and parent_exe == "login"
                    and parent_proc.command_line.startswith("login -- ")
                )
                if (
                    not is_linux_ssh_priv_parent
                    and not is_linux_login_priv_parent
                    and parent_username not in _SYSTEM_ACCOUNTS
                    and not parent_username.endswith("$")
                ):
                    return False

        if logon_id and logon_id != "0x3e7":
            child_session_end = self.state_manager.get_session_end_time(logon_id)
            if child_session_end is not None and ensure_utc(time) >= ensure_utc(child_session_end):
                return False
        return True

    def _process_cached_time(
        self,
        cache: dict[Any, datetime],
        latest: dict[tuple[str, int], tuple[datetime | None, datetime]],
        hostname: str,
        pid: int,
    ) -> datetime | None:
        """Read an instance timestamp with compatibility for direct unit fixtures."""
        instance_key = self._process_instance_key(hostname, pid)
        value = cache.get(instance_key)
        if value is not None:
            return value
        value = cache.get((hostname, pid))
        if value is not None:
            return value
        if instance_key[2] is not None:
            return None
        latest_value = latest.get((hostname, pid))
        return latest_value[1] if latest_value is not None else None

    def _lookup_parent_image(self, hostname: str, parent_pid: int) -> str:
        """Look up parent process image from StateManager, with fallback."""
        proc = self.state_manager.get_process(hostname, parent_pid)
        if proc:
            return proc.image
        return "-"
