# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Maintain shared process-parent history on the existing runtime map."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime

from evidenceforge.generation.activity.helpers import _get_os_category
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import System, User

from .queries import ProcessStateQueries

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProcessParentHistory:
    """Parent operations over existing owners; no independent runtime state."""

    _user_process_history: dict[tuple[str, str], list[tuple[int, str]]]
    state_manager: StateManager
    queries: ProcessStateQueries

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
