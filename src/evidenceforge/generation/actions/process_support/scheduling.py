# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Plan launch spacing against the existing process activity caches."""

from __future__ import annotations

import logging
import random
from dataclasses import dataclass
from datetime import datetime, timedelta

from evidenceforge.generation.activity.helpers import _get_os_category
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.timing import TimingRuntime, TimingScope, TriangularDistribution
from evidenceforge.models.scenario import System
from evidenceforge.utils.rng import _stable_seed

from . import policy
from .policy import _WINDOWS_ONE_SHOT_CLI_EXES

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProcessLaunchScheduler:
    """Ephemeral operations; injected maps and managers remain on their existing owners."""

    _last_browser_launch_by_session: dict[tuple[str, str, str], datetime]
    _last_one_shot_cli_launch_by_command: dict[tuple[str, str, str, str, str], datetime]
    _last_one_shot_cli_launch_by_exe: dict[tuple[str, str, str, str], datetime]
    state_manager: StateManager
    timing_runtime: TimingRuntime

    def _space_one_shot_cli_launch(
        self,
        *,
        system: System,
        username: str,
        logon_id: str,
        process_name: str,
        command_line: str,
        time: datetime,
    ) -> datetime:
        """Avoid machine-impossible bursts of repeated one-shot admin commands."""
        if _get_os_category(system.os) != "windows":
            return time

        exe_name = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        if exe_name not in _WINDOWS_ONE_SHOT_CLI_EXES:
            return time

        normalized_command = " ".join(command_line.lower().split())
        exe_key = (system.hostname, username, logon_id, exe_name)
        command_key = (*exe_key, normalized_command)
        adjusted_time = time

        command_last = self._last_one_shot_cli_launch_by_command.get(command_key)
        if command_last is not None:
            min_gap = timedelta(
                seconds=random.Random(
                    _stable_seed(
                        f"one_shot_cli_same_command:{system.hostname}:{username}:"
                        f"{exe_name}:{normalized_command}:{command_last.isoformat()}"
                    )
                ).uniform(18.0, 75.0)
            )
            if adjusted_time < command_last + min_gap:
                adjusted_time = command_last + min_gap

        exe_last = self._last_one_shot_cli_launch_by_exe.get(exe_key)
        if exe_last is not None:
            min_gap = timedelta(
                seconds=random.Random(
                    _stable_seed(
                        f"one_shot_cli_same_exe:{system.hostname}:{username}:"
                        f"{exe_name}:{exe_last.isoformat()}"
                    )
                ).uniform(2.5, 9.0)
            )
            if adjusted_time < exe_last + min_gap:
                adjusted_time = exe_last + min_gap

        self._last_one_shot_cli_launch_by_exe[exe_key] = adjusted_time
        self._last_one_shot_cli_launch_by_command[command_key] = adjusted_time
        return adjusted_time

    def _space_browser_launch(
        self,
        *,
        system: System,
        username: str,
        logon_id: str,
        process_name: str,
        command_line: str,
        time: datetime,
    ) -> datetime:
        """Avoid rendered bursts of repeated top-level browser process creates."""
        if _get_os_category(system.os) != "windows":
            return time
        if not policy._is_top_level_browser_launch(process_name, command_line):
            return time

        key = (system.hostname, username, logon_id)
        previous = self._last_browser_launch_by_session.get(key)
        adjusted_time = time
        if previous is not None:
            rng = random.Random(
                _stable_seed(
                    f"browser_launch_gap:{system.hostname}:{username}:{logon_id}:"
                    f"{previous.isoformat()}"
                )
            )
            min_gap = timedelta(seconds=rng.uniform(4.0, 18.0))
            if adjusted_time < previous + min_gap:
                adjusted_time = previous + min_gap
        self._last_browser_launch_by_session[key] = adjusted_time
        return adjusted_time

    def _space_interactive_shell_child_launch(
        self,
        *,
        system: System,
        process_name: str,
        parent_pid: int,
        time: datetime,
    ) -> datetime:
        """Add human-scale dwell time before visible children of bare shells."""
        if _get_os_category(system.os) != "windows":
            return time
        process_exe = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        if process_exe in policy._WINDOWS_SHELL_NAMES or process_exe == "conhost.exe":
            return time
        parent_proc = self.state_manager.get_process(system.hostname, parent_pid)
        if parent_proc is None or parent_proc.start_time is None:
            return time
        if not policy._is_bare_interactive_windows_shell(
            parent_proc.image, parent_proc.command_line
        ):
            return time
        rng = random.Random(
            _stable_seed(
                f"interactive_shell_child_gap:{system.hostname}:{parent_pid}:"
                f"{process_exe}:{parent_proc.start_time.isoformat()}"
            )
        )
        minimum_child_time = parent_proc.start_time + timedelta(seconds=rng.uniform(8.0, 45.0))
        if time < minimum_child_time:
            return minimum_child_time
        return time

    def _preview_one_shot_cli_launch(
        self,
        *,
        system: System,
        username: str,
        logon_id: str,
        process_name: str,
        command_line: str,
        time: datetime,
    ) -> datetime:
        """Return one-shot spacing without updating compatibility caches."""

        if _get_os_category(system.os) != "windows":
            return time
        exe_name = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        if exe_name not in _WINDOWS_ONE_SHOT_CLI_EXES:
            return time
        normalized_command = " ".join(command_line.lower().split())
        exe_key = (system.hostname, username, logon_id, exe_name)
        command_key = (*exe_key, normalized_command)
        adjusted = time
        command_last = self._last_one_shot_cli_launch_by_command.get(command_key)
        if command_last is not None:
            gap = self._sample_process_spacing_gap(
                relationship_key="activity.process.one_shot_same_command_gap",
                stable_id=(
                    f"{system.hostname}:{username}:{logon_id}:{exe_name}:"
                    f"{normalized_command}:{command_last.isoformat()}"
                ),
                system=system,
                logon_id=logon_id,
                minimum_seconds=18.0,
                mode_seconds=32.0,
                maximum_seconds=75.0,
            )
            adjusted = max(adjusted, command_last + gap)
        exe_last = self._last_one_shot_cli_launch_by_exe.get(exe_key)
        if exe_last is not None:
            gap = self._sample_process_spacing_gap(
                relationship_key="activity.process.one_shot_same_exe_gap",
                stable_id=(
                    f"{system.hostname}:{username}:{logon_id}:{exe_name}:{exe_last.isoformat()}"
                ),
                system=system,
                logon_id=logon_id,
                minimum_seconds=2.5,
                mode_seconds=4.2,
                maximum_seconds=9.0,
            )
            adjusted = max(adjusted, exe_last + gap)
        return adjusted

    def _preview_browser_launch(
        self,
        *,
        system: System,
        username: str,
        logon_id: str,
        process_name: str,
        command_line: str,
        time: datetime,
    ) -> datetime:
        """Return top-level browser spacing without updating compatibility caches."""

        if _get_os_category(system.os) != "windows" or not policy._is_top_level_browser_launch(
            process_name,
            command_line,
        ):
            return time
        previous = self._last_browser_launch_by_session.get((system.hostname, username, logon_id))
        if previous is None:
            return time
        gap = self._sample_process_spacing_gap(
            relationship_key="activity.process.browser_launch_gap",
            stable_id=f"{system.hostname}:{username}:{logon_id}:{previous.isoformat()}",
            system=system,
            logon_id=logon_id,
            minimum_seconds=4.0,
            mode_seconds=7.5,
            maximum_seconds=18.0,
        )
        return max(time, previous + gap)

    def _remember_one_shot_cli_launch(
        self,
        *,
        system: System,
        username: str,
        logon_id: str,
        process_name: str,
        command_line: str,
        time: datetime,
    ) -> None:
        """Record the final launch timestamp for later one-shot CLI spacing."""
        if _get_os_category(system.os) != "windows":
            return
        exe_name = process_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
        if exe_name not in _WINDOWS_ONE_SHOT_CLI_EXES:
            return
        normalized_command = " ".join(command_line.lower().split())
        exe_key = (system.hostname, username, logon_id, exe_name)
        command_key = (*exe_key, normalized_command)
        self._last_one_shot_cli_launch_by_exe[exe_key] = time
        self._last_one_shot_cli_launch_by_command[command_key] = time

    def _sample_process_spacing_gap(
        self,
        *,
        relationship_key: str,
        stable_id: str,
        system: System,
        logon_id: str,
        minimum_seconds: float,
        mode_seconds: float,
        maximum_seconds: float,
    ) -> timedelta:
        """Sample one order-independent process spacing gap through the shared runtime."""

        return self.timing_runtime.sampler.sample_timedelta(
            TriangularDistribution(
                minimum=minimum_seconds * 1_000_000,
                mode=mode_seconds * 1_000_000,
                maximum=maximum_seconds * 1_000_000,
            ),
            relationship_key=relationship_key,
            scope=TimingScope(
                stable_id=stable_id,
                host=system.hostname,
                source="endpoint_process",
                lifecycle_id=logon_id,
            ),
            sample_key="gap",
        )
