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

from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import StrEnum
from inspect import getattr_static
from typing import TYPE_CHECKING, Literal, Protocol

from evidenceforge.events.content_identity import canonical_native_path
from evidenceforge.events.identity import ProcessIdentity, validate_process_arguments
from evidenceforge.events.lifecycle import SessionEndPlan
from evidenceforge.events.macos_exec_script import MacosExecScript, validate_macos_exec_script
from evidenceforge.events.process_outcome import PosixProcessExit
from evidenceforge.events.responsibility import ProcessResponsibility
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.actions.command_effects import (
    ExecutionEffectPlan,
    ExecutionEffectPlanError,
    ExecutionEffectPlanErrorCode,
)
from evidenceforge.generation.actions.endpoint_effects import (
    PreparedEndpointEffect,
    PreparedFileEffectPayload,
    PreparedProcessEffectActor,
    PreparedProcessEndpointEffectPlan,
)
from evidenceforge.generation.deployment_registry import LocalArtifactPublishToken
from evidenceforge.models.scenario import System, User
from evidenceforge.utils.platforms import platform_for_os
from evidenceforge.utils.rng import _stable_seed
from evidenceforge.utils.time import ensure_utc

if TYPE_CHECKING:
    from .process_execution_service import ProcessExecutionService, ProcessTerminationService


class ProcessLifetimeMode(StrEnum):
    """Canonical ownership mode for one process execution lifetime."""

    BOUNDED = "bounded"
    OPERATION_OWNED = "operation_owned"
    SESSION_OWNED = "session_owned"
    PERSISTENT = "persistent"
    UNCLASSIFIED = "unclassified"


@dataclass(frozen=True, slots=True)
class ProcessLifetimePlan:
    """Immutable lifetime ownership selected before process publication."""

    mode: ProcessLifetimeMode
    minimum_seconds: float | None = None
    maximum_seconds: float | None = None
    classification: str = ""

    def __post_init__(self) -> None:
        bounded = self.mode in {
            ProcessLifetimeMode.BOUNDED,
            ProcessLifetimeMode.OPERATION_OWNED,
            ProcessLifetimeMode.UNCLASSIFIED,
        }
        has_bounds = self.minimum_seconds is not None or self.maximum_seconds is not None
        if bounded:
            if (
                self.minimum_seconds is None
                or self.maximum_seconds is None
                or self.minimum_seconds <= 0
                or self.maximum_seconds < self.minimum_seconds
            ):
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_PLAN,
                    "bounded process lifetime plans require positive ordered bounds",
                )
        elif has_bounds:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "session-owned and persistent lifetime plans cannot carry bounded deadlines",
            )
        if not self.classification.strip():
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "process lifetime plans require a classification reason",
            )

    @property
    def bounds(self) -> tuple[float, float] | None:
        """Return the sampled bounds when this mode has a provisional close."""

        if self.minimum_seconds is None or self.maximum_seconds is None:
            return None
        return (self.minimum_seconds, self.maximum_seconds)


@dataclass(frozen=True, slots=True)
class ProcessRuntimeImageLoadPlan:
    """One optional runtime image-load choice frozen before root publication."""

    timestamp: datetime
    path: str
    signed: bool
    signature: str
    signature_status: str

    def __post_init__(self) -> None:
        if not self.path.strip() or not self.signature_status.strip():
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "runtime image-load plans require exact path and signature status",
            )


@dataclass(frozen=True, slots=True)
class ProcessExecutionPreparedEffects:
    """Allocation-free root binding plus all preselected process side effects."""

    root_anchor: ActionAnchor
    actor: PreparedProcessEffectActor
    endpoint: PreparedProcessEndpointEffectPlan | None = None
    runtime_image_load: ProcessRuntimeImageLoadPlan | None = None
    lifetime_plan: ProcessLifetimePlan | None = None
    provisional_termination: datetime | None = None
    root_binary_publication: LocalArtifactPublishToken | None = field(
        default=None,
        repr=False,
    )

    root_script_publication: LocalArtifactPublishToken | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.root_anchor.family != "process_execution":
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "prepared process effects require a process-execution root anchor",
            )
        if self.endpoint is not None and (
            self.endpoint.root_anchor != self.root_anchor or self.endpoint.actor != self.actor
        ):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "prepared endpoint effects drifted from their root process intent",
            )
        if self.provisional_termination is not None:
            if self.provisional_termination <= self.actor.started_at:
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_PLAN,
                    "prepared process termination must follow its root start",
                )
            if (
                self.actor.session_deadline is not None
                and self.provisional_termination >= self.actor.session_deadline
            ):
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_PLAN,
                    "prepared process termination must precede its session deadline",
                )
        if self.lifetime_plan is not None:
            if self.provisional_termination is not None and self.lifetime_plan.bounds is None:
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_PLAN,
                    "unbounded process lifetime plan cannot own a provisional termination",
                )
        publication = self.root_binary_publication
        if publication is not None:
            record = publication.record
            if record.binary is None or canonical_native_path(
                record.artifact.native_path,
                record.artifact.platform,
            ) != canonical_native_path(self.actor.image, record.artifact.platform):
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_PLAN,
                    "prepared root binary publication must identify the exact process image",
                )

    @property
    def artifact_publications(self) -> tuple[LocalArtifactPublishToken, ...]:
        """Return admitted runtime-artifact tokens in canonical effect order."""

        endpoint_effects = self.endpoint.admitted_effects if self.endpoint is not None else ()
        endpoint_publications = tuple(
            publication
            for effect in endpoint_effects
            if isinstance(effect.payload, PreparedFileEffectPayload)
            if (publication := effect.payload.artifact_publication) is not None
        )
        roots = tuple(
            token
            for token in (self.root_binary_publication, self.root_script_publication)
            if token is not None
        )
        return (*roots, *endpoint_publications)

    @property
    def process_binary_publication(self) -> LocalArtifactPublishToken | None:
        """Return the exact executable token matching the prepared process image."""

        matches = tuple(
            token
            for token in self.artifact_publications
            if token.record.binary is not None
            and canonical_native_path(
                token.record.artifact.native_path,
                token.record.artifact.platform,
            )
            == canonical_native_path(self.actor.image, token.record.artifact.platform)
        )
        if len(matches) > 1:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "prepared process owns multiple executable publications for its image",
            )
        return matches[0] if matches else None


@dataclass(frozen=True, slots=True)
class ProcessExecutionReuseIntent:
    """Authenticated identity for one allocation-free bounded process reuse."""

    hostname: str
    process_object_id: str
    pid: int
    parent_pid: int
    image: str
    command_line: str
    username: str
    logon_id: str
    started_at: datetime
    source_frontier: datetime

    def __post_init__(self) -> None:
        """Normalize immutable timestamps and reject incomplete reuse identities."""

        if not self.hostname or not self.process_object_id or self.pid <= 0:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_ACTOR,
                "bounded process reuse requires exact host, object, and positive PID identity",
            )
        object.__setattr__(self, "started_at", ensure_utc(self.started_at))
        object.__setattr__(self, "source_frontier", ensure_utc(self.source_frontier))


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
    lifecycle_group_id: str = ""
    source_visible_by: datetime | None = None
    require_exact_parent: bool = field(default=False, kw_only=True)
    new_posix_session: bool = field(default=False, kw_only=True)
    arguments: tuple[str, ...] | None = field(default=None, kw_only=True)
    exec_script: MacosExecScript | None = field(default=None, kw_only=True)
    macos_launch_kind: Literal["user", "system", "finder"] | None = field(
        default=None, kw_only=True
    )
    macos_terminal: Literal["allocate", "absent"] | None = field(default=None, kw_only=True)
    macos_standard_io: Literal["terminal", "null", "inherit"] | None = field(
        default=None, kw_only=True
    )
    macos_responsibility: ProcessResponsibility | None = field(default=None, kw_only=True)
    requested_endpoint_effects: tuple[PreparedEndpointEffect, ...] = ()
    source: str = "activity_generator"
    effect_plan: ExecutionEffectPlan | None = field(default=None, compare=False, repr=False)
    prepared_effects: ProcessExecutionPreparedEffects | None = field(
        default=None,
        compare=False,
        repr=False,
    )
    reuse_intent: ProcessExecutionReuseIntent | None = field(
        default=None,
        compare=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        """Freeze caller-authored endpoint consequences into the root intent."""

        if self.macos_responsibility is not None and (
            type(self.macos_responsibility) is not ProcessResponsibility
            or self.macos_launch_kind != "user"
            or platform_for_os(self.system.os) != "macos"
            or not self.require_exact_parent
            or self.arguments is None
            or self.reuse_intent is not None
        ):
            raise ValueError("Mac responsibility requires a fresh literal exact-parent user launch")
        if any(
            value is not None
            for value in (self.macos_launch_kind, self.macos_terminal, self.macos_standard_io)
        ):
            if (
                platform_for_os(self.system.os) != "macos"
                or not self.require_exact_parent
                or self.arguments is None
                or self.reuse_intent is not None
                or self.macos_launch_kind not in {"user", "system", "finder", None}
                or self.macos_terminal not in {"allocate", "absent", None}
                or self.macos_standard_io not in {"terminal", "null", "inherit", None}
                or (self.macos_terminal is not None and not self.new_posix_session)
            ):
                raise ValueError(
                    "Modeled Mac launch metadata requires a fresh literal exact-parent intent"
                )
        if self.macos_launch_kind == "finder" and (
            type(self.parent_pid) is not int
            or self.parent_pid != 1
            or self.exec_script is not None
            or self.macos_terminal is not None
            or self.macos_standard_io is not None
            or not self.process_name.startswith("/")
            or canonical_native_path(self.process_name, "macos") != self.process_name
            or ".app/Contents/MacOS/" not in self.process_name
            or not self.process_name.rsplit(".app/Contents/MacOS/", 1)[-1]
            or "/" in self.process_name.rsplit(".app/Contents/MacOS/", 1)[-1]
            or not self.arguments
            or self.arguments[0] != self.process_name
        ):
            raise ValueError(
                "Finder relationship intent requires launchd and a literal app-bundle executable; "
                "script, descriptor and controlling-terminal facts remain separate"
            )

        validate_macos_exec_script(
            self.exec_script,
            platform=platform_for_os(self.system.os),
            hostname=self.system.hostname,
        )
        if self.exec_script is not None and (
            not self.require_exact_parent or self.reuse_intent is not None
        ):
            raise ValueError("Explicit Mac script requires a fresh exact-parent launch")
        validate_process_arguments(self.arguments, command_line=self.command_line)
        if self.arguments is not None and (
            platform_for_os(self.system.os) != "macos"
            or not self.require_exact_parent
            or self.reuse_intent is not None
        ):
            raise ValueError("Explicit Mac process argv requires a fresh exact-parent launch")
        if type(self.new_posix_session) is not bool:
            raise ValueError("New POSIX launch session requires an exact boolean")
        if self.new_posix_session and (
            not self.require_exact_parent
            or self.reuse_intent is not None
            or platform_for_os(self.system.os) not in {"macos", "linux"}
        ):
            raise ValueError("New POSIX launch session requires a fresh exact-parent launch")
        requested_effects = tuple(self.requested_endpoint_effects)
        if any(not isinstance(effect, PreparedEndpointEffect) for effect in requested_effects):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "process endpoint consequences must be immutable PreparedEndpointEffect values",
            )
        instance_keys = tuple(effect.spec.instance_key for effect in requested_effects)
        if len(instance_keys) != len(set(instance_keys)):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.DUPLICATE_NODE_ID,
                "process endpoint consequences require unique instance keys",
            )
        object.__setattr__(self, "requested_endpoint_effects", requested_effects)

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        concurrency_suffix = f":{self.concurrency_group_id}" if self.concurrency_group_id else ""
        lifecycle_suffix = f":{self.lifecycle_group_id}" if self.lifecycle_group_id else ""
        exact_parent_suffix = ":exact_parent" if self.require_exact_parent else ""
        session_suffix = ":new_posix_session" if self.new_posix_session else ""
        arguments_suffix = f":argv={self.arguments!r}" if self.arguments is not None else ""
        script_suffix = f":script={self.exec_script!r}" if self.exec_script is not None else ""
        responsibility_suffix = (
            f":responsibility={self.macos_responsibility!r}"
            if self.macos_responsibility is not None
            else ""
        )
        native_suffix = (
            f":macos={self.macos_launch_kind}:{self.macos_terminal}:{self.macos_standard_io}"
            if any(
                value is not None
                for value in (self.macos_launch_kind, self.macos_terminal, self.macos_standard_io)
            )
            else ""
        )
        endpoint_effect_signature = tuple(
            (
                effect.spec.instance_key,
                effect.spec.intent.semantic_key,
                effect.spec.requirement.value,
                tuple(value.isoformat() for value in effect.spec.occurrence_times),
                effect.event_type,
                repr(effect.payload),
            )
            for effect in self.requested_endpoint_effects
        )
        seed = _stable_seed(
            "action_bundle:process_execution:"
            f"{self.user.username}:{self.system.hostname}:{self.time.isoformat()}:"
            f"{self.logon_id}:{self.process_name}:{self.command_line}:"
            f"{self.parent_pid}:{self.ensure_file_event}:{self.from_storyline}:"
            f"{self.suppress_command_file_effect}:{self.allow_existing_browser_reuse}:"
            f"{self.allow_browser_launch_spacing}{concurrency_suffix}{lifecycle_suffix}:"
            f"{self.source_visible_by.isoformat() if self.source_visible_by else ''}:"
            f"{endpoint_effect_signature}:{self.source}{exact_parent_suffix}{session_suffix}{arguments_suffix}{script_suffix}{native_suffix}{responsibility_suffix}"
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
    session_end_plan: SessionEndPlan | None = None
    source: str = "activity_generator"
    exit_outcome: PosixProcessExit | None = None
    expected_process: ProcessIdentity | None = None
    macos_command_completed: bool = False

    def __post_init__(self) -> None:
        if type(self.macos_command_completed) is not bool:
            raise ValueError("Mac command completion requires an exact bool")
        if self.exit_outcome is not None:
            if type(self.exit_outcome) is not PosixProcessExit:
                raise ValueError("Process termination requires an exact terminal result")
            self.exit_outcome.__post_init__()
            if type(self.expected_process) is not ProcessIdentity:
                raise ValueError("An explicit terminal result requires its exact process execution")
        if self.expected_process is not None and (
            type(self.expected_process) is not ProcessIdentity
            or self.expected_process.hostname != self.system.hostname
            or self.expected_process.pid != self.pid
        ):
            raise ValueError("Process termination expected identity disagrees with host/PID")
        if (self.exit_outcome is not None or self.macos_command_completed) and platform_for_os(
            self.system.os
        ) != "macos":
            raise ValueError(
                "Explicit process completion is currently supported only for Mac hosts"
            )

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        completion_suffix = ""
        if (
            self.exit_outcome is not None
            or self.expected_process is not None
            or self.macos_command_completed
        ):
            completion_suffix = (
                f":completion:{self.exit_outcome!r}:{self.macos_command_completed}:"
                f"{self.expected_process.execution_id if self.expected_process is not None else ''}"
            )
        seed = _stable_seed(
            "action_bundle:process_termination:"
            f"{self.user.username}:{self.system.hostname}:{self.time.isoformat()}:"
            f"{self.pid}:{self.process_name}:{self.logon_id}:{self.from_storyline}:"
            f"{self.session_end_plan.canonical_end.isoformat() if self.session_end_plan else ''}:"
            f"{self.source}{completion_suffix}"
        )
        return f"process-termination-{seed:016x}"


class ProcessExecutionExecutor(Protocol):
    """Existing owners injected into bundle-owned process execution."""

    def _process_execution_service(self) -> ProcessExecutionService:
        """Bind creation to the current state, timing, identity and lifecycle owners."""
        ...

    def _process_termination_service(self) -> ProcessTerminationService:
        """Bind termination to the current owners without retaining a generator."""
        ...


class ProcessExecutionEffectPlanner(Protocol):
    """Optional allocation-free process-effect planning adapter."""

    def _plan_process_execution_effects(
        self,
        request: ProcessExecutionRequest,
        anchor: ActionAnchor,
    ) -> ExecutionEffectPlan:
        """Build and validate command-effect cardinality before root allocation."""
        ...

    def _plan_process_execution_side_effects(
        self,
        request: ProcessExecutionRequest,
        anchor: ActionAnchor,
    ) -> ProcessExecutionPreparedEffects | None:
        """Freeze endpoint/module effects and root actor before root allocation."""
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

        request = self.preflight()
        try:
            return self._executor._process_execution_service().create(request)
        finally:
            cleanup = getattr(
                self._executor,
                "_cancel_uncommitted_process_artifact_publications",
                None,
            )
            if callable(cleanup):
                cleanup(request.prepared_effects)

    def preflight(self) -> ProcessExecutionRequest:
        """Freeze the exact root/effect request without entering the mutable executor."""

        return self._preflight_request()

    def _preflight_request(self) -> ProcessExecutionRequest:
        """Resolve an optional effect plan before entering the stateful executor."""

        anchor = self.anchor
        plan = self._request.effect_plan
        planner_marker = getattr_static(
            self._executor,
            "_plan_process_execution_effects",
            None,
        )
        if plan is None and planner_marker is not None:
            planner = getattr(self._executor, "_plan_process_execution_effects", None)
            if not callable(planner):
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_PLAN,
                    "process effect planning hook must be callable",
                )
            plan = planner(self._request, anchor)
        if plan is not None and not isinstance(plan, ExecutionEffectPlan):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "process effect planning hook must return an ExecutionEffectPlan",
            )
        if plan is not None and plan.anchor != anchor:
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "process effect plan anchor does not match the root execution anchor",
            )

        prepared_effects = self._request.prepared_effects
        side_planner_marker = getattr_static(
            self._executor,
            "_plan_process_execution_side_effects",
            None,
        )
        if prepared_effects is None and side_planner_marker is not None:
            side_planner = getattr(
                self._executor,
                "_plan_process_execution_side_effects",
                None,
            )
            if not callable(side_planner):
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_PLAN,
                    "process side-effect planning hook must be callable",
                )
            prepared_effects = side_planner(self._request, anchor)
        if prepared_effects is not None:
            if not isinstance(prepared_effects, ProcessExecutionPreparedEffects):
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_PLAN,
                    "process side-effect planning hook returned an invalid prepared plan",
                )
            if prepared_effects.root_anchor != anchor:
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_PLAN,
                    "prepared process side effects do not match the root execution anchor",
                )
            expected_lifecycle_id = self._request.lifecycle_group_id or self._request.stable_id
            if (
                prepared_effects.actor.hostname.casefold()
                != self._request.system.hostname.casefold()
                or prepared_effects.actor.lifecycle_id != expected_lifecycle_id
            ):
                raise ExecutionEffectPlanError(
                    ExecutionEffectPlanErrorCode.INVALID_ACTOR,
                    "prepared process actor drifted from the root execution intent",
                )

        if plan is self._request.effect_plan and prepared_effects is self._request.prepared_effects:
            return self._request
        return replace(
            self._request,
            effect_plan=plan,
            prepared_effects=prepared_effects,
        )


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

        self._executor._process_termination_service().terminate(self._request)
