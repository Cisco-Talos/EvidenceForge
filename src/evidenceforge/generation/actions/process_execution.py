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

"""Process execution action bundles."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.models.scenario import System, User
from evidenceforge.utils.rng import _stable_seed


@dataclass(frozen=True, slots=True)
class ProcessExecutionRequest:
    """Intent for one canonical process execution."""

    user: User
    system: System
    time: datetime
    logon_id: str
    process_name: str
    command_line: str
    parent_pid: int = 4
    ensure_file_event: bool = False
    from_storyline: bool = False
    suppress_command_file_effect: bool = False
    allow_existing_browser_reuse: bool = True
    allow_browser_launch_spacing: bool = True
    concurrency_group_id: str = ""
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        concurrency_suffix = f":{self.concurrency_group_id}" if self.concurrency_group_id else ""
        seed = _stable_seed(
            "action_bundle:process_execution:"
            f"{self.user.username}:{self.system.hostname}:{self.time.isoformat()}:"
            f"{self.logon_id}:{self.process_name}:{self.command_line}:"
            f"{self.parent_pid}:{self.ensure_file_event}:{self.from_storyline}:"
            f"{self.suppress_command_file_effect}:{self.allow_existing_browser_reuse}:"
            f"{self.allow_browser_launch_spacing}{concurrency_suffix}:{self.source}"
        )
        return f"process-execution-{seed:016x}"


@dataclass(frozen=True, slots=True)
class ProcessTerminationRequest:
    """Intent for one canonical process termination."""

    user: User
    system: System
    time: datetime
    pid: int
    process_name: str
    logon_id: str
    from_storyline: bool = False
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        seed = _stable_seed(
            "action_bundle:process_termination:"
            f"{self.user.username}:{self.system.hostname}:{self.time.isoformat()}:"
            f"{self.pid}:{self.process_name}:{self.logon_id}:{self.from_storyline}:"
            f"{self.source}"
        )
        return f"process-termination-{seed:016x}"


class ProcessExecutionExecutor(Protocol):
    """Adapter protocol implemented by the current activity generator."""

    def _execute_process_create_bundle(self, request: ProcessExecutionRequest) -> int:
        """Expand one process-execution request into canonical evidence."""
        ...

    def _execute_process_termination_bundle(self, request: ProcessTerminationRequest) -> None:
        """Expand one process-termination request into canonical evidence."""
        ...


class ProcessExecutionActionBundle:
    """Expand one process execution into process and process-owned side effects."""

    def __init__(
        self,
        executor: ProcessExecutionExecutor,
        request: ProcessExecutionRequest,
    ) -> None:
        self._executor = executor
        self._request = request

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="process_execution",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> int:
        """Emit process-create evidence and process-owned side effects."""

        return self._executor._execute_process_create_bundle(self._request)


class ProcessTerminationActionBundle:
    """Expand one process termination into source-native termination evidence."""

    def __init__(
        self,
        executor: ProcessExecutionExecutor,
        request: ProcessTerminationRequest,
    ) -> None:
        self._executor = executor
        self._request = request

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="process_termination",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> None:
        """Emit process-termination evidence."""

        self._executor._execute_process_termination_bundle(self._request)
