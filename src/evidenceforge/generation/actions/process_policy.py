# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical terminal pre-spawn denial; no policy-native evidence is fabricated."""

from dataclasses import dataclass
from datetime import datetime

from evidenceforge.events.identity import ProcessIdentity
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
