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

"""Linux shell command action bundle."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.models.scenario import System, User
from evidenceforge.utils.rng import _stable_seed

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class LinuxShellCommandRequest:
    """Intent for one interactive shell command."""

    user: User
    system: System
    time: datetime
    activity_type_or_command: str = "default"
    emit_process_telemetry: bool = True
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        seed = _stable_seed(
            "action_bundle:linux_shell_command:"
            f"{self.user.username}:{self.system.hostname}:{self.time.isoformat()}:"
            f"{self.activity_type_or_command}:{self.emit_process_telemetry}:{self.source}"
        )
        return f"linux-shell-command-{seed:016x}"


class LinuxShellCommandExecutor(Protocol):
    """Adapter protocol implemented by the current activity generator."""

    def _resolve_bash_command(
        self,
        user: User,
        system: System,
        activity_type_or_command: str,
    ) -> str:
        """Return the concrete shell command for this request."""
        ...

    def _should_skip_bash_history(self, user: User, system: System) -> bool:
        """Return true when bash history should not be emitted."""
        ...

    def _prepare_bash_history_command(self, system: System, command: str) -> str:
        """Return a source-native command suitable for bash history."""
        ...

    def _schedule_bash_history_time(
        self,
        user: User,
        system: System,
        requested_time: datetime,
        command: str,
    ) -> datetime | None:
        """Return the source-visible bash-history timestamp, or none if no session can own it."""
        ...

    def _is_within_scenario_window(self, time: datetime) -> bool:
        """Return true when the timestamp is within the generation window."""
        ...

    def _emit_bash_command_event(
        self,
        user: User,
        system: System,
        time: datetime,
        command: str,
    ) -> None:
        """Dispatch bash-history evidence."""
        ...

    def _maybe_emit_bash_process_telemetry(
        self,
        user: User,
        system: System,
        time: datetime,
        command: str,
    ) -> None:
        """Emit correlated process evidence when appropriate."""
        ...


class LinuxShellCommandActionBundle:
    """Expand one shell-command intent into bash history and optional process telemetry."""

    def __init__(
        self,
        executor: LinuxShellCommandExecutor,
        request: LinuxShellCommandRequest,
    ) -> None:
        self._executor = executor
        self._request = request

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="linux_shell_command",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> datetime | None:
        """Emit bash-history and optional process telemetry for the command."""

        command = self._executor._resolve_bash_command(
            self._request.user,
            self._request.system,
            self._request.activity_type_or_command,
        )
        if self._executor._should_skip_bash_history(self._request.user, self._request.system):
            logger.debug(
                "Skipping bash_history for noninteractive web service user %s on %s",
                self._request.user.username,
                self._request.system.hostname,
            )
            return None

        command = self._executor._prepare_bash_history_command(self._request.system, command)
        scheduled_time = self._executor._schedule_bash_history_time(
            self._request.user,
            self._request.system,
            self._request.time,
            command,
        )
        if scheduled_time is None:
            return None
        if not self._executor._is_within_scenario_window(scheduled_time):
            return None
        self._executor._emit_bash_command_event(
            self._request.user,
            self._request.system,
            scheduled_time,
            command,
        )
        if self._request.emit_process_telemetry:
            self._executor._maybe_emit_bash_process_telemetry(
                self._request.user,
                self._request.system,
                scheduled_time,
                command,
            )
        logger.debug(
            "Generated bash command: %s by %s on %s",
            command,
            self._request.user.username,
            self._request.system.hostname,
        )
        return scheduled_time
