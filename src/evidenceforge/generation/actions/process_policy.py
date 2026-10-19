# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical terminal pre-spawn denial; no policy-native evidence is fabricated."""

from dataclasses import dataclass
from datetime import datetime

from evidenceforge.events.identity import (
    ProcessIdentity,
    validate_process_arguments,
    validate_process_environment,
)
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError


@dataclass(frozen=True, slots=True)
class DeniedProcessLaunch:
    """One completed attempt owned by an existing caller, with no child lifetime."""

    actor: ProcessIdentity
    attempted_at: datetime
    image: str
    command_line: str

    def __post_init__(self) -> None:
        if (
            type(self.actor) is not ProcessIdentity
            or type(self.attempted_at) is not datetime
            or self.attempted_at.utcoffset() is None
        ):
            raise ValueError("Denied launch requires an exact caller and aware attempt time")
        if self.attempted_at < self.actor.execution_started_at:
            raise ValueError("Denied launch cannot precede the caller execution")
        if (
            type(self.image) is not str
            or not self.image.startswith("/")
            or self.image == "/"
            or "\0" in self.image
        ):
            raise ValueError("Denied launch requires an absolute executable path")
        if type(self.command_line) is not str or not self.command_line or "\0" in self.command_line:
            raise ValueError("Denied launch requires an explicit NUL-free command")


def record_denied_process_launch(
    state: StateManager,
    *,
    actor: ProcessIdentity,
    attempted_at: datetime,
    image: str,
    command_line: str,
) -> DeniedProcessLaunch:
    """Admit an explicit terminal denial while retaining only legitimate caller activity.

    This bounded outcome occurs before child allocation. It is not failed exec
    in an already allocated child, prompting, or a policy-product attribution.
    The successful process bundle and its automatic effects are never entered.
    """
    result = DeniedProcessLaunch(actor, attempted_at, image, command_line)
    if state._pid_os.get(actor.hostname) != "macos":
        raise StateError("Denied process launch currently requires an exact Mac caller")
    builder = state.begin_action_cohort_materialization()
    builder.patch_process_activity(actor, attempted_at)
    state.materialize_action_cohort(builder.seal())
    return result


@dataclass(frozen=True, slots=True)
class FailedProcessExec:
    """An image-replacement call that returned an explicit error to its caller.

    This bounded result preserves the existing execution. It does not describe
    a failure after the kernel's irreversible replacement point, a process exit,
    or a named security product's decision. A later exit is a separate action.
    """

    actor: ProcessIdentity
    attempted_at: datetime
    image: str
    command_line: str
    error_number: int
    arguments: tuple[str, ...] | None = None
    environment: tuple[str, ...] | None = None

    def __post_init__(self) -> None:
        DeniedProcessLaunch(self.actor, self.attempted_at, self.image, self.command_line)
        if type(self.error_number) is not int or not 0 < self.error_number < 2**31:
            raise ValueError("Failed exec requires an explicit positive errno")
        validate_process_arguments(self.arguments, command_line=self.command_line)
        validate_process_environment(self.environment)


def record_failed_process_exec(
    state: StateManager,
    *,
    actor: ProcessIdentity,
    attempted_at: datetime,
    image: str,
    command_line: str,
    error_number: int,
    arguments: tuple[str, ...] | None = None,
    environment: tuple[str, ...] | None = None,
) -> FailedProcessExec:
    """Record a returning Mac exec failure without allocating or replacing an image.

    Only the exact live caller's activity frontier changes. Attempted argv/envp,
    executable metadata, threads and privilege effects are not installed into
    the caller. The successful execution/effect bundle is never entered. No
    native Gatekeeper or ES event is inferred from the supplied error number.
    """
    result = FailedProcessExec(
        actor, attempted_at, image, command_line, error_number, arguments, environment
    )
    if state._pid_os.get(actor.hostname) != "macos":
        raise StateError("Returning failed exec currently requires an exact Mac caller")
    builder = state.begin_action_cohort_materialization()
    builder.patch_process_activity(actor, attempted_at)
    state.materialize_action_cohort(builder.seal())
    return result
