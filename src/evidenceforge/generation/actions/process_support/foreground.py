# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Coordinate foreground shell ownership and modeled lifecycle releases."""

from __future__ import annotations

import logging
import random
from dataclasses import dataclass
from datetime import datetime, timedelta

from evidenceforge.events.lifecycle import SessionEndPlan
from evidenceforge.generation.activity.helpers import _get_os_category
from evidenceforge.generation.activity.process_helpers import (
    _linux_foreground_lifetime as _linux_foreground_lifetime,
)
from evidenceforge.generation.activity.process_helpers import (
    _linux_shell_process_reserves_foreground as _linux_shell_process_reserves_foreground,
)
from evidenceforge.generation.indexes import ExpiringIndex
from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import System, User
from evidenceforge.models.state import RunningProcess
from evidenceforge.utils.rng import _stable_seed
from evidenceforge.utils.time import ensure_utc

from . import policy
from .capabilities import (
    GenerateProcessTerminationCapability,
    GenericLogoffOwnsProcessCloseCapability,
    IsWithinScenarioWindowCapability,
    ProcessIdentityCapabilities,
)
from .policy import _FOREGROUND_SHELL_INITIAL_READY_MIN_MS, _FOREGROUND_SHELL_INITIAL_READY_SPAN_MS
from .queries import ProcessStateQueries

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProcessForegroundLifecycle:
    """Ephemeral operations; injected maps and managers remain on their existing owners."""

    _bash_history_next_time: dict[tuple[str, str, str], datetime]
    _foreground_process_finalizers: ExpiringIndex[
        tuple[str, int, datetime | None], tuple[System, str, str, str, datetime]
    ]
    _foreground_shell_next_time: dict[tuple[str, str, str, int], datetime]
    _foreground_shell_release_groups: dict[tuple[str, str, str, int], str]
    _generic_logoff_owns_process_close: GenericLogoffOwnsProcessCloseCapability
    _is_within_scenario_window: IsWithinScenarioWindowCapability
    _lifecycle_authority: GeneratorLifecycleAuthority
    _lifecycle_compatibility_fixture_mode: bool
    _process_connection_hold_until: dict[tuple[str, int, datetime | None], datetime]
    _scenario_end_time: datetime | None
    _terminated_process_times: dict[tuple[str, int, datetime | None], datetime]
    _users_by_username: dict[str, User]
    generate_process_termination: GenerateProcessTerminationCapability
    state_manager: StateManager
    queries: ProcessStateQueries
    identity: ProcessIdentityCapabilities

    def _held_process_termination_time(
        self,
        *,
        system: System,
        pid: int,
        requested_time: datetime,
    ) -> datetime:
        """Move process termination after any active process-owned transport hold."""
        hold_until = self._process_connection_hold_until.get(
            self.queries._process_instance_key(system.hostname, pid)
        )
        if hold_until is None:
            return requested_time
        hold_until = ensure_utc(hold_until)
        requested_time = ensure_utc(requested_time)
        if requested_time > hold_until:
            return requested_time
        delay_rng = random.Random(
            _stable_seed(
                "process_terminate_after_connection_hold:"
                f"{system.hostname}:{pid}:{hold_until.isoformat()}"
            )
        )
        return hold_until + timedelta(seconds=delay_rng.uniform(1.0, 12.0))

    def _finalize_due_process_lifetimes(
        self,
        cutoff: datetime,
        *,
        exhaust: bool,
    ) -> None:
        """Render bounded due-close pages outside lifecycle-authority locks.

        Hot allocation boundaries drain one fixed page and apply backpressure if
        more work is already due.  Engine watermarks and finalization explicitly
        repeat pages before sealing the canonical frontier.
        """

        known_users = getattr(self, "_users_by_username", {})
        normalized_cutoff = ensure_utc(cutoff)
        while True:
            due = self._lifecycle_authority.pop_due_process_closes(normalized_cutoff)
            if not due:
                return
            for intent in due:
                system = intent.system
                running = self.state_manager.get_process(system.hostname, intent.pid)
                if running is None:
                    continue
                if running.start_time != intent.started_at:
                    continue
                if self.queries._process_termination_recorded(
                    system.hostname,
                    intent.pid,
                    running.start_time,
                ):
                    continue
                process_user = known_users.get(intent.username) or User(
                    username=intent.username,
                    full_name=intent.username,
                    email=f"{intent.username}@example.local",
                )
                session = self.state_manager.get_session(running.logon_id or intent.logon_id)
                self.generate_process_termination(
                    user=process_user,
                    system=system,
                    time=intent.close_at,
                    pid=intent.pid,
                    process_name=running.image or intent.process_name,
                    logon_id=running.logon_id or intent.logon_id,
                    session_end_plan=session.end_plan if session is not None else None,
                )
            if not exhaust:
                if self._lifecycle_authority.has_due_process_closes(normalized_cutoff):
                    raise StateError(
                        "Process allocation cannot proceed while more than one bounded "
                        "lifecycle close page is already due; advance the engine watermark"
                    )
                return

    def _foreground_shell_key(
        self,
        *,
        system: System,
        username: str,
        logon_id: str,
        parent_pid: int,
    ) -> tuple[str, str, str, int] | None:
        """Return the interactive shell key that serializes foreground Linux children."""
        proc = self.state_manager.get_process(system.hostname, parent_pid)
        if proc is None:
            return None
        image = (proc.image or "").rsplit("/", 1)[-1].lower()
        if image not in {"bash", "sh", "zsh"}:
            return None
        shell_logon_id = proc.logon_id or logon_id
        return (system.hostname, username, shell_logon_id, parent_pid)

    def _remember_foreground_process_finalizer(
        self,
        *,
        system: System,
        user: User,
        pid: int,
        process_name: str,
        logon_id: str,
        termination_time: datetime,
    ) -> None:
        """Track a bounded foreground process until its terminate event is observed."""
        key = self.queries._process_instance_key(system.hostname, pid)
        termination_time = self._held_process_termination_time(
            system=system,
            pid=pid,
            requested_time=ensure_utc(termination_time),
        )
        self._foreground_process_finalizers[key] = (
            system,
            user.username,
            process_name,
            logon_id,
            termination_time,
        )
        running = self.state_manager.get_process(system.hostname, pid)
        if (
            running is not None
            and _get_os_category(system.os) == "linux"
            and _linux_shell_process_reserves_foreground(
                running.image,
                running.command_line,
            )
            and self._foreground_shell_key(
                system=system,
                username=running.username,
                logon_id=running.logon_id,
                parent_pid=running.parent_pid,
            )
            is not None
        ):
            self._remember_foreground_shell_available(
                system=system,
                username=running.username,
                logon_id=running.logon_id,
                parent_pid=running.parent_pid,
                termination_time=termination_time,
                seed_text=running.command_line,
                concurrency_group_id=running.concurrency_group_id,
            )

    def _remember_foreground_shell_available(
        self,
        *,
        system: System,
        username: str,
        logon_id: str,
        parent_pid: int,
        termination_time: datetime,
        seed_text: str,
        concurrency_group_id: str = "",
    ) -> None:
        """Remember when an interactive Linux shell can plausibly accept more input."""
        release_time = policy._foreground_shell_release_time(
            system=system,
            username=username,
            logon_id=logon_id,
            parent_pid=parent_pid,
            termination_time=termination_time,
            seed_text=seed_text,
        )
        bash_key = (system.hostname, username, logon_id)
        self._bash_history_next_time[bash_key] = max(
            self._bash_history_next_time.get(bash_key, release_time),
            release_time,
        )
        generic_bash_key = (system.hostname, username, "")
        self._bash_history_next_time[generic_bash_key] = max(
            self._bash_history_next_time.get(generic_bash_key, release_time),
            release_time,
        )
        key = self._foreground_shell_key(
            system=system,
            username=username,
            logon_id=logon_id,
            parent_pid=parent_pid,
        )
        if key is None:
            return
        self._foreground_shell_next_time[key] = max(
            release_time,
            self._foreground_shell_next_time.get(key, release_time),
        )
        if self._foreground_shell_next_time[key] == release_time:
            self._foreground_shell_release_groups[key] = concurrency_group_id

    def _reserve_foreground_shell_time(
        self,
        *,
        system: System,
        username: str,
        logon_id: str,
        parent_pid: int,
        requested_time: datetime,
        seed_text: str,
        concurrency_group_id: str = "",
    ) -> datetime | None:
        """Delay a new foreground command until the same interactive shell is free."""
        key = self._foreground_shell_key(
            system=system,
            username=username,
            logon_id=logon_id,
            parent_pid=parent_pid,
        )
        if key is None:
            return requested_time
        ready_at = self._unbounded_foreground_shell_ready_at(
            system=system,
            username=username,
            logon_id=logon_id,
            parent_pid=parent_pid,
            requested_time=requested_time,
            concurrency_group_id=concurrency_group_id,
        )
        if ready_at is None:
            return None
        requested_time = max(requested_time, ready_at)
        shell_proc = self.state_manager.get_process(system.hostname, parent_pid)
        if shell_proc is not None:
            shell_start = ensure_utc(shell_proc.start_time)
            readiness_seed = _stable_seed(
                "foreground_shell_initial_ready:"
                f"{system.hostname}:{username}:{logon_id}:{parent_pid}:"
                f"{shell_start.isoformat()}"
            )
            requested_time = max(
                requested_time,
                shell_start
                + timedelta(
                    milliseconds=(
                        _FOREGROUND_SHELL_INITIAL_READY_MIN_MS
                        + (readiness_seed % _FOREGROUND_SHELL_INITIAL_READY_SPAN_MS)
                    )
                ),
            )
        next_time = self._foreground_shell_next_time.get(key)
        if next_time is None or requested_time >= next_time:
            return requested_time
        if (
            concurrency_group_id
            and self._foreground_shell_release_groups.get(key) == concurrency_group_id
        ):
            return requested_time
        rng = random.Random(
            _stable_seed(
                f"foreground_shell_gap:{system.hostname}:{username}:{logon_id}:"
                f"{parent_pid}:{seed_text}:{next_time.timestamp()}"
            )
        )
        return next_time + timedelta(milliseconds=rng.randint(120, 900))

    def _unbounded_foreground_shell_ready_at(
        self,
        *,
        system: System,
        username: str,
        logon_id: str,
        parent_pid: int,
        requested_time: datetime,
        concurrency_group_id: str = "",
    ) -> datetime | None:
        """Derive open foreground occupancy from canonical process/session state.

        None means no release has been modeled. Collection boundaries are not
        lifecycle deadlines, and no prospective release is cached here.
        """
        if (
            self._foreground_shell_key(
                system=system, username=username, logon_id=logon_id, parent_pid=parent_pid
            )
            is None
        ):
            return requested_time
        ready_at = requested_time
        for process in self.state_manager.get_processes_for_session(logon_id, system.hostname):
            if (
                process.parent_pid != parent_pid
                or process.start_time > requested_time
                or (process.end_time is not None and process.end_time <= requested_time)
                or (concurrency_group_id and process.concurrency_group_id == concurrency_group_id)
                or not _linux_shell_process_reserves_foreground(process.image, process.command_line)
                or _linux_foreground_lifetime(process.image, process.command_line) is not None
            ):
                continue
            session = self.state_manager.get_session(process.logon_id)
            deadlines = [
                value
                for value in (
                    process.end_time,
                    self.foreground_process_termination_time(system.hostname, process.pid),
                    self.state_manager.get_session_end_time(process.logon_id),
                    session.network_close_time if session is not None else None,
                )
                if value is not None
            ]
            if not deadlines:
                return None
            deadline = min(ensure_utc(value) for value in deadlines)
            if deadline > requested_time:
                # This is a scheduling fence, not a fabricated process close.
                ready_at = max(ready_at, deadline + timedelta(milliseconds=1))
        return ready_at

    def _discard_superseded_foreground_reservation(
        self, *, system: System, process: RunningProcess, termination_time: datetime
    ) -> None:
        """Retire an exact planned or older-build release superseded by termination.

        Old checkpoints can retain a session/collection deadline as shell readiness.
        Match its deterministic value and group before removing it; unrelated shell
        and history reservations must survive. Canonical process state owns occupancy.
        """
        key = self._foreground_shell_key(
            system=system,
            username=process.username,
            logon_id=process.logon_id,
            parent_pid=process.parent_pid,
        )
        if (
            key is None
            or self._foreground_shell_release_groups.get(key) != process.concurrency_group_id
        ):
            return
        reserved = self._foreground_shell_next_time.get(key)
        session = self.state_manager.get_session(process.logon_id)
        deadlines = [self.foreground_process_termination_time(system.hostname, process.pid)]
        if _linux_foreground_lifetime(process.image, process.command_line) is None:
            deadlines.extend(
                (
                    self.state_manager.get_session_end_time(process.logon_id),
                    session.network_close_time if session is not None else None,
                    getattr(self, "_scenario_end_time", None),
                )
            )
        for deadline in deadlines:
            if (
                reserved is None
                or deadline is None
                or deadline >= reserved
                or deadline <= termination_time
            ):
                continue
            legacy_release = policy._foreground_shell_release_time(
                system=system,
                username=process.username,
                logon_id=process.logon_id,
                parent_pid=process.parent_pid,
                termination_time=deadline,
                seed_text=process.command_line,
            )
            if reserved != legacy_release:
                continue
            self._foreground_shell_next_time.pop(key)
            self._foreground_shell_release_groups.pop(key)
            for history_logon in (process.logon_id, ""):
                history_key = (system.hostname, process.username, history_logon)
                if self._bash_history_next_time.get(history_key) == legacy_release:
                    self._bash_history_next_time.pop(history_key)
            # The removed maximum may have hidden another pipeline member's
            # still-valid completion. Rebuild only from existing lifecycle owners.
            for sibling in self.state_manager.get_processes_for_session(
                process.logon_id, system.hostname
            ):
                if (
                    sibling.pid == process.pid
                    or sibling.parent_pid != process.parent_pid
                    or not _linux_shell_process_reserves_foreground(
                        sibling.image, sibling.command_line
                    )
                ):
                    continue
                completion = self.foreground_process_termination_time(system.hostname, sibling.pid)
                if completion is not None and completion > termination_time:
                    self._remember_foreground_shell_available(
                        system=system,
                        username=sibling.username,
                        logon_id=sibling.logon_id,
                        parent_pid=sibling.parent_pid,
                        termination_time=completion,
                        seed_text=sibling.command_line,
                        concurrency_group_id=sibling.concurrency_group_id,
                    )
            return

    def foreground_process_termination_time(self, hostname: str, pid: int) -> datetime | None:
        """Return the canonical bounded-process deadline, when one is registered."""
        finalizer = self._foreground_process_finalizers.get(
            self.queries._process_instance_key(hostname, pid)
        )
        return finalizer[4] if finalizer is not None else None

    def _terminate_completed_one_shot_shell_parent(
        self,
        *,
        user: User,
        system: System,
        child: RunningProcess | None,
        child_termination_time: datetime,
        from_storyline: bool,
        session_end_plan: SessionEndPlan | None,
    ) -> None:
        """Close a one-shot Windows wrapper just after its final foreground child."""

        if child is None or _get_os_category(system.os) != "windows" or child.parent_pid <= 0:
            return
        parent = self.state_manager.get_process(system.hostname, child.parent_pid)
        if self._generic_logoff_owns_process_close(parent):
            return
        if parent is None or not policy._is_one_shot_shell_command(
            parent.image, parent.command_line
        ):
            return
        if not self.queries._windows_shell_parent_invokes_child(
            system=system,
            parent_pid=parent.pid,
            process_name=child.image,
            command_line=child.command_line,
        ):
            return
        if any(
            process.pid != child.pid and process.parent_pid == parent.pid
            for process in self.state_manager.get_processes_on_system(system.hostname)
        ):
            return
        child_lifecycle = self._lifecycle_authority.registry.get_process(child.ecar_object_id)
        if child_lifecycle is None or child_lifecycle.closed_at != ensure_utc(
            child_termination_time
        ):
            # Compatibility dispatch may record a non-strict lifecycle close
            # failure after ending the child in State.  Do not cascade that
            # split-brain state into the shell parent; the owning session will
            # close it after the exact child graph drains.
            return
        seed = _stable_seed(
            "one_shot_shell_after_final_child:"
            f"{system.hostname}:{parent.pid}:{child.pid}:{child_termination_time.isoformat()}"
        )
        parent_termination_time = child_termination_time + timedelta(
            milliseconds=80 + (seed % 920),
            microseconds=137 + (seed % 719),
        )
        resolved_parent_termination_time = self.resolve_process_lifecycle_close_candidate(
            system.hostname,
            parent.pid,
            parent_termination_time,
        )
        if resolved_parent_termination_time is None:
            return
        parent_session = self.state_manager.get_session(parent.logon_id)
        parent_deadlines = [
            ensure_utc(deadline)
            for deadline in (
                (
                    session_end_plan.canonical_end
                    if session_end_plan is not None and session_end_plan.is_authoritative
                    else None
                ),
                (
                    parent_session.end_plan.canonical_end
                    if parent_session is not None
                    and parent_session.end_plan is not None
                    and parent_session.end_plan.is_authoritative
                    else None
                ),
                parent_session.network_close_time if parent_session is not None else None,
            )
            if deadline is not None
        ]
        if (
            parent_deadlines and resolved_parent_termination_time >= min(parent_deadlines)
        ) or not self._is_within_scenario_window(resolved_parent_termination_time):
            return
        parent_termination_time = resolved_parent_termination_time
        parent_user = (
            user
            if parent.username == user.username
            else self.identity.user_for_username(parent.username)
        )
        self.generate_process_termination(
            user=parent_user,
            system=system,
            time=parent_termination_time,
            pid=parent.pid,
            process_name=parent.image,
            logon_id=parent.logon_id,
            from_storyline=from_storyline,
            session_end_plan=session_end_plan,
        )

    def resolve_process_lifecycle_close_candidate(
        self,
        hostname: str,
        pid: int,
        close_at: datetime,
    ) -> datetime | None:
        """Resolve one advisory process close against its exact child frontier."""

        running = self.state_manager.get_process(hostname, pid)
        if running is None:
            raise StateError(
                f"Process close admission lost its live State identity: {hostname} pid={pid}"
            )
        lifecycle_process = self._lifecycle_authority.registry.get_process(running.ecar_object_id)
        if lifecycle_process is None and self._lifecycle_compatibility_fixture_mode:
            self._lifecycle_authority.ensure_process(hostname, pid)
            lifecycle_process = self._lifecycle_authority.registry.get_process(
                running.ecar_object_id
            )
        if (
            lifecycle_process is None
            or lifecycle_process.closed_at is not None
            or lifecycle_process.close_barrier is not None
            or lifecycle_process.closure_ticket is not None
            or lifecycle_process.identity.hostname != running.system
            or lifecycle_process.identity.pid != running.pid
            or lifecycle_process.identity.started_at != running.start_time
            or lifecycle_process.identity.image != running.image
        ):
            raise StateError(
                "Process close admission has no matching live lifecycle identity: "
                f"{hostname} pid={pid} object={running.ecar_object_id}"
            )
        if self._lifecycle_compatibility_fixture_mode:
            direct_children = tuple(
                child
                for child in self.state_manager.get_processes_on_system(hostname)
                if child.parent_pid == pid
            )
            for child in direct_children:
                self._lifecycle_authority.ensure_process(hostname, child.pid)
                child_lifecycle = self._lifecycle_authority.registry.get_process(
                    child.ecar_object_id
                )
                if (
                    child_lifecycle is None
                    or child_lifecycle.closed_at is not None
                    or child_lifecycle.identity.object_id != child.ecar_object_id
                    or child_lifecycle.identity.hostname != child.system
                    or child_lifecycle.identity.pid != child.pid
                    or child_lifecycle.identity.started_at != child.start_time
                    or child_lifecycle.identity.image != child.image
                    or child_lifecycle.identity.parent_object_id != running.ecar_object_id
                ):
                    raise StateError(
                        "Compatibility process close admission has no matching live child "
                        f"lifecycle identity: {hostname} pid={child.pid} "
                        f"object={child.ecar_object_id}"
                    )
        try:
            latest_closed_child = self._lifecycle_authority.process_child_close_deadline(
                hostname,
                pid,
            )
        except StateError as error:
            if self._lifecycle_authority.live_child_process_page_for_object(running.ecar_object_id):
                return None
            raise StateError(
                "Process close admission child frontier changed during resolution: "
                f"{hostname} pid={pid} object={running.ecar_object_id}"
            ) from error
        candidate = ensure_utc(close_at)
        if latest_closed_child is not None:
            candidate = max(
                candidate,
                ensure_utc(latest_closed_child) + timedelta(microseconds=1),
            )
        return candidate

    def record_termination(
        self, hostname: str, pid: int, start_time: datetime | None, timestamp: datetime
    ) -> None:
        """Record the published terminal event on the existing checkpoint-owned indexes."""
        key = (hostname, pid, start_time)
        self.queries._terminated_process_keys.add(key)
        self._terminated_process_times[key] = ensure_utc(timestamp)
