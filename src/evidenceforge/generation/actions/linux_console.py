# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Console terminal admission derived from canonical process lifetimes."""

import shlex
from dataclasses import dataclass
from datetime import datetime

from evidenceforge.config.schemas import LinuxConsolePolicy
from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import System
from evidenceforge.models.state import ActiveSession
from evidenceforge.utils.platforms import platform_for_os


@dataclass(frozen=True, slots=True)
class LinuxConsoleAdmission:
    """One configured terminal and an optional idle getty to consume."""

    terminal: str
    existing_getty: ProcessIdentity | None


def console_session_root_matches(identity: ProcessIdentity, session: ActiveSession) -> bool:
    """Recognize the exact privileged getty/login lifetime owned for teardown.

    Owning a console login does not replace the process's root authentication
    identity with the human identity whose shell it starts.
    """
    return (
        identity.hostname == session.system
        and session.session_kind == "interactive"
        and session.process_tree_root == identity.pid
        and identity.principal == "root"
        and identity.logon_id in {"", "0x3e7"}
        and identity.image == "/bin/login"
        and identity.initial_image == "/sbin/agetty"
        and identity.execution_ordinal == 1
        and identity.arguments == ("/bin/login", "--", session.username)
        and identity.execution_started_at < session.start_time
    )


def plan_linux_console_login(
    state: StateManager,
    system: System,
    at: datetime,
    policy: LinuxConsolePolicy,
    *,
    occupied_since: datetime | None = None,
) -> LinuxConsoleAdmission:
    """Reserve no state; select a terminal without reusing an occupied lifetime.

    A current future execution also reserves its terminal: State cannot replay an
    earlier image transition into that already materialized lifetime. Retained
    closed lifetimes protect historical overlap without another history cache.
    """
    if platform_for_os(system.os) != "linux":
        raise StateError("Virtual console admission requires a Linux host")
    if occupied_since is not None and occupied_since > at:
        raise StateError("Console occupancy interval cannot begin after login")
    occupancy_start = at if occupied_since is None else occupied_since
    candidates: list[tuple[str, ProcessIdentity]] = []
    occupied: set[str] = set()
    for process in state.get_processes_on_system(system.hostname, include_retained=True):
        identity = state.get_process_identity(system.hostname, process.pid)
        if identity is None or process.end_time is not None and process.end_time <= occupancy_start:
            continue
        epochs = (*process.prior_executions, identity)
        getty = next((epoch for epoch in epochs if epoch.image == policy.getty_image), None)
        if getty is None:
            continue
        terminal = next(
            (part for part in shlex.split(getty.command_line) if part in policy.terminals), None
        )
        if terminal is None:
            continue
        occupied.add(terminal)
        if (
            process.end_time is None
            and identity.image == policy.getty_image
            and identity.execution_started_at < at
        ):
            candidates.append((terminal, identity))
    if candidates:
        terminal, before = min(candidates, key=lambda item: policy.terminals.index(item[0]))
        return LinuxConsoleAdmission(terminal, before)
    terminal = next((tty for tty in policy.terminals if tty not in occupied), None)
    if terminal is None:
        raise StateError("Local console login has no free configured virtual terminal")
    return LinuxConsoleAdmission(terminal, None)
