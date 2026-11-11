# Copyright (c) 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: MIT

"""Typed storyline adapters for Linux shell pipeline process stages."""

from __future__ import annotations

import random
import shlex
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from evidenceforge.generation.actions.linux_shell_command import plan_linux_pipeline_stage_times
from evidenceforge.generation.activity.generator import (
    _linux_command_process_groups_from_shell,
    _linux_foreground_lifetime,
)
from evidenceforge.models.scenario import System, User
from evidenceforge.utils.rng import _stable_seed

if TYPE_CHECKING:
    from evidenceforge.generation.engine.storyline import StorylineMixin


@dataclass(frozen=True, slots=True)
class LinuxPipelineChild:
    """A canonical process created for one executable pipeline stage."""

    pid: int
    image: str
    command_line: str
    start_time: datetime
    lifetime: tuple[float, float] | None


def linux_pipeline_submission_command(
    runtime: StorylineMixin, *, system: System, pid: int, command_line: str
) -> str:
    """Retain submission semantics when a pipeline stage owns a later effect."""
    process = runtime.state_manager.get_process(system.hostname, pid)
    if process is None:
        return command_line
    prefix = f"storyline-linux-pipeline:{system.hostname}:{process.parent_pid}:"
    if not process.concurrency_group_id.startswith(prefix):
        return command_line
    parent = runtime.state_manager.get_process(system.hostname, process.parent_pid)
    return parent.command_line if parent is not None else command_line


def _nested_shell_pipeline_groups(
    process_name: str,
    command_line: str,
    *,
    username: str,
) -> list[list[tuple[str, str]]]:
    """Extract bounded executable stages from a shell's explicit ``-c`` script."""
    if process_name.rsplit("/", 1)[-1].casefold() not in {"bash", "sh", "dash", "zsh"}:
        return []
    try:
        arguments = shlex.split(command_line, comments=False, posix=True)
    except ValueError:
        return []
    command_index = next(
        (
            index
            for index, argument in enumerate(arguments[1:], start=1)
            if argument in {"-c", "--command"} or (argument.startswith("-") and "c" in argument[1:])
        ),
        None,
    )
    if command_index is None or command_index + 1 >= len(arguments):
        return []
    script = arguments[command_index + 1]
    groups = _linux_command_process_groups_from_shell(
        script,
        max_processes=8,
        max_stages=4,
        username=username,
    )
    return [group for group in groups if len(group) > 1]


def emit_storyline_linux_pipeline_children(
    runtime: StorylineMixin,
    *,
    user: User,
    system: System,
    start_time: datetime,
    logon_id: str,
    shell_pid: int,
    shell_image: str,
    command_line: str,
) -> tuple[LinuxPipelineChild, ...]:
    """Emit typed storyline pipeline stages under their authored shell process.

    The action reuses the bounded stage resolver and shared pipeline timing planner
    used by Bash-history and catalog activity. It returns visible stage identities
    so the caller can close their lifecycles with the parent command.
    """
    groups = _nested_shell_pipeline_groups(
        shell_image,
        command_line,
        username=user.username,
    )
    if not groups:
        return ()

    activity = runtime.activity_generator
    children: list[LinuxPipelineChild] = []
    active_count = len(runtime.state_manager.get_processes_on_system(system.hostname))
    for group_index, group in enumerate(groups):
        # The shell itself occupies one slot in the shared four-stage bound.
        bounded_group = group[:3]
        concurrency_group_id = (
            f"storyline-linux-pipeline:{system.hostname}:{shell_pid}:"
            f"{start_time.isoformat()}:{group_index}"
        )
        stage_times = plan_linux_pipeline_stage_times(
            start_time,
            stage_count=len(bounded_group) + 1,
            scope_parts=(system.hostname, user.username, logon_id, concurrency_group_id),
            active_process_count=active_count,
            timing_runtime=activity.timing_runtime,
        )
        for (image, child_command), child_time in zip(
            bounded_group,
            stage_times[1:],
            strict=True,
        ):
            child_pid = activity.generate_process(
                user=user,
                system=system,
                time=child_time,
                logon_id=logon_id,
                process_name=image,
                command_line=child_command,
                parent_pid=shell_pid,
                require_exact_parent=True,
                ensure_file_event=False,
                from_storyline=True,
                suppress_command_file_effect=True,
                concurrency_group_id=concurrency_group_id,
            )
            if child_pid <= 0:
                continue
            actual = activity.state_manager.get_process(system.hostname, child_pid)
            actual_start = actual.start_time if actual is not None else child_time
            activity._record_user_process(system, user, child_pid, image)
            runtime.state_manager.mark_story_process(system.hostname, child_pid)
            children.append(
                LinuxPipelineChild(
                    pid=child_pid,
                    image=image,
                    command_line=child_command,
                    start_time=actual_start,
                    lifetime=_linux_foreground_lifetime(image, child_command),
                )
            )
    return tuple(children)


def terminate_storyline_linux_pipeline_children(
    runtime: StorylineMixin,
    *,
    children: tuple[LinuxPipelineChild, ...],
    user: User,
    system: System,
    logon_id: str,
    parent_termination_time: datetime | None,
    owner_pid: int,
) -> None:
    """Close short stages and keep the flow-owning final stage through its parent."""
    if not children:
        return
    activity = runtime.activity_generator
    final_close = (
        parent_termination_time - timedelta(milliseconds=100)
        if parent_termination_time is not None
        else None
    )
    for child in children:
        if child.pid == owner_pid:
            if final_close is None:
                continue
            termination_time = max(child.start_time + timedelta(milliseconds=250), final_close)
            activity._remember_foreground_process_finalizer(
                system=system,
                user=user,
                pid=child.pid,
                process_name=child.image,
                logon_id=logon_id,
                termination_time=termination_time,
            )
            continue
        else:
            lifetime = child.lifetime or (0.25, 1.5)
            child_rng = random.Random(
                _stable_seed(
                    f"storyline_linux_pipeline_close:{system.hostname}:{child.pid}:"
                    f"{child.start_time.isoformat()}"
                )
            )
            termination_time = activity._generate_bounded_foreground_process_termination(
                user=user,
                system=system,
                start_time=child.start_time,
                pid=child.pid,
                process_name=child.image,
                logon_id=logon_id,
                lifetime=lifetime,
                rng=child_rng,
            )
        activity.generate_process_termination(
            user=user,
            system=system,
            time=termination_time,
            pid=child.pid,
            process_name=child.image,
            logon_id=logon_id,
            from_storyline=True,
        )


def linux_pipeline_parent_termination_time(
    runtime: StorylineMixin,
    *,
    system: System,
    shell_pid: int,
    requested_time: datetime,
) -> datetime:
    """Keep a typed pipeline shell open until every bounded child finalizer completes."""
    activity = runtime.activity_generator
    prefix = f"storyline-linux-pipeline:{system.hostname}:{shell_pid}:"
    deadline = requested_time
    finalizer_time = getattr(activity, "foreground_process_termination_time", None)
    if not callable(finalizer_time):
        return deadline
    for child in runtime.state_manager.get_processes_on_system(system.hostname):
        if child.parent_pid != shell_pid or not child.concurrency_group_id:
            continue
        if not child.concurrency_group_id.startswith(prefix):
            continue
        child_deadline = finalizer_time(system.hostname, child.pid)
        if child_deadline is None:
            continue
        seed = _stable_seed(
            f"storyline_linux_pipeline_parent_wait:{system.hostname}:"
            f"{shell_pid}:{child.pid}:{child_deadline.isoformat()}"
        )
        deadline = max(deadline, child_deadline + timedelta(milliseconds=80 + seed % 921))
    return deadline
