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

"""Linux sudo session action bundle."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol

from evidenceforge.events.contexts import AuthContext
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.models.scenario import System
from evidenceforge.utils.rng import _stable_seed


def linux_sudo_intrinsic_close_headroom() -> timedelta:
    """Return the maximum bundle-owned tail after the requested command runtime.

    The PAM close may trail the runtime by 950 milliseconds and the owning sudo
    process terminates at most another 50 milliseconds later. Executor-owned TTY
    serialization is separate and is returned as ``timing_shift`` during execution.
    """

    return timedelta(seconds=1)


@dataclass(frozen=True, slots=True)
class LinuxSudoSessionRequest:
    """Intent for one allowed sudo command and its PAM session lifecycle."""

    system: System
    time: datetime
    command_message: str
    sudo_user: str
    uid: int
    runtime: timedelta
    source: str = "baseline"
    latest_end: datetime | None = None

    def __post_init__(self) -> None:
        """Reject requests that cannot represent an allowed sudo invocation."""

        if "COMMAND=" not in self.command_message or "command not allowed" in self.command_message:
            raise ValueError("Linux sudo session requests require one allowed COMMAND= message")
        if not self.sudo_user.strip():
            raise ValueError("Linux sudo session requests require a non-empty invoking user")
        if self.runtime < timedelta(0):
            raise ValueError("Linux sudo session runtime cannot be negative")
        if self.latest_end is not None and self.latest_end < self.time:
            raise ValueError("Linux sudo session latest_end cannot precede its command time")

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        seed = _stable_seed(
            "action_bundle:linux_sudo_session:"
            f"{self.system.hostname}:{self.time.isoformat()}:{self.command_message}:"
            f"{self.sudo_user}:{self.uid}:{self.runtime.total_seconds()}:{self.source}"
        )
        return f"linux-sudo-session-{seed:016x}"


class LinuxSudoSessionExecutor(Protocol):
    """Adapter protocol implemented by the current activity generator."""

    def generate_syslog_event(
        self,
        system: System,
        time: datetime,
        app_name: str,
        message: str,
        pid: int | None = None,
        facility: int = 3,
        severity: int = 6,
        auth: object | None = None,
    ) -> None:
        """Dispatch one canonical syslog event."""
        ...

    def generate_linux_sudo_processes(
        self,
        *,
        system: System,
        sudo_time: datetime,
        child_time: datetime,
        sudo_user: str,
        tty: str,
        command: str,
        reserve_until: datetime,
        lifecycle_group_id: str,
        complete_by: datetime | None = None,
        latest_end: datetime | None = None,
    ) -> tuple[int, int | None, timedelta, str]:
        """Create session-owned sudo and elevated child processes."""
        ...

    def terminate_linux_sudo_process(
        self,
        *,
        system: System,
        time: datetime,
        pid: int,
    ) -> None:
        """Terminate one session-owned sudo-family process."""
        ...


class LinuxSudoSessionActionBundle:
    """Expand one allowed sudo invocation into its ordered PAM lifecycle."""

    def __init__(
        self,
        executor: LinuxSudoSessionExecutor,
        request: LinuxSudoSessionRequest,
    ) -> None:
        self._executor = executor
        self._request = request

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="linux_sudo_session",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> None:
        """Emit one endpoint process around the ordered sudo/PAM lifecycle."""

        request = self._request
        auth = AuthContext(
            username=request.sudo_user,
            logon_id=request.stable_id,
            result="success",
            elevated=True,
        )
        timing_seed = _stable_seed(f"{request.stable_id}:source_timing")
        process_time = request.time - timedelta(milliseconds=30 + ((timing_seed >> 24) % 71))
        open_time = request.time + timedelta(milliseconds=12 + (timing_seed % 289))
        close_time = (
            request.time
            + request.runtime
            + timedelta(milliseconds=120 + ((timing_seed >> 12) % 831))
        )
        close_time = max(close_time, open_time + timedelta(milliseconds=1))
        parent_end_time = close_time + timedelta(milliseconds=10 + ((timing_seed >> 32) % 41))
        command = request.command_message.split("COMMAND=", 1)[1].strip()
        tty = (
            request.command_message.split("TTY=", 1)[1].split(" ;", 1)[0].strip()
            if "TTY=" in request.command_message
            else "unknown"
        )
        group_id = request.stable_id
        pid, child_pid, timing_shift, effective_tty = self._executor.generate_linux_sudo_processes(
            system=request.system,
            sudo_time=process_time,
            child_time=open_time + timedelta(milliseconds=1),
            sudo_user=request.sudo_user,
            tty=tty,
            command=command,
            reserve_until=close_time,
            complete_by=parent_end_time,
            latest_end=request.latest_end,
            lifecycle_group_id=group_id,
        )
        if pid <= 0:
            return
        command_time = request.time + timing_shift
        open_time += timing_shift
        close_time += timing_shift

        command_message = request.command_message.replace(
            f"TTY={tty} ;",
            f"TTY={effective_tty} ;",
            1,
        )
        self._executor.generate_syslog_event(
            system=request.system,
            time=command_time,
            app_name="sudo",
            message=command_message,
            pid=pid,
            facility=10,
            severity=5,
            auth=auth,
        )
        self._executor.generate_syslog_event(
            system=request.system,
            time=open_time,
            app_name="sudo",
            message=(
                "pam_unix(sudo:session): session opened for user "
                f"root(uid=0) by {request.sudo_user}(uid={request.uid})"
            ),
            pid=pid,
            facility=10,
            severity=6,
            auth=auth,
        )
        self._executor.generate_syslog_event(
            system=request.system,
            time=close_time,
            app_name="sudo",
            message="pam_unix(sudo:session): session closed for user root",
            pid=pid,
            facility=10,
            severity=6,
            auth=auth,
        )
        if child_pid is not None:
            self._executor.terminate_linux_sudo_process(
                system=request.system,
                time=max(
                    open_time + timedelta(milliseconds=2), close_time - timedelta(milliseconds=1)
                ),
                pid=child_pid,
            )
        self._executor.terminate_linux_sudo_process(
            system=request.system,
            time=parent_end_time + timing_shift,
            pid=pid,
        )
