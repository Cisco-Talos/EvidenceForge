# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Retained canonical Finder startup, independent of selected output formats."""

import shlex
from dataclasses import dataclass, replace
from datetime import datetime

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.content_identity import BinaryReleaseIdentity
from evidenceforge.events.contexts import HostContext
from evidenceforge.events.dispatcher import (
    ActionCohortPublicationReceipt,
    EventDispatcher,
    PreparedActionCohortBatch,
    PreparedActionCohortCapability,
)
from evidenceforge.events.identity import ProcessIdentity, SessionIdentity
from evidenceforge.events.process_executable import ProcessExecutableVersion
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.actions.command_effects import (
    ExecutionEffectAuditCohortEntry,
    ExecutionEffectPlan,
)
from evidenceforge.generation.actions.posix_process import (
    process_credential_occurrence,
    process_exec_occurrence,
    process_fork_occurrence,
)
from evidenceforge.generation.macos_execution_metadata import MacosExecutionMetadataProducer
from evidenceforge.generation.state_manager import (
    ActionCohortMaterializationPlan,
    ProcessMaterializationPlan,
    StateManager,
)
from evidenceforge.models.exceptions import StateError


@dataclass(slots=True)
class _PendingFinderPhase:
    batch: PreparedActionCohortBatch
    after: ProcessIdentity
    events: tuple[OccurrenceBuilder, ...]
    birth: ProcessMaterializationPlan | None = None
    receipt: ActionCohortPublicationReceipt | None = None
    capability: PreparedActionCohortCapability | None = None


class MacosFinderStartup:
    """Finish each exact publication before advancing the same process lifetime.

    The process owner retains this coordinator across failed calls and refuses
    checkpoints while it is pending. Each State cohort retains the existing
    one-exec-per-process invariant. Only installed native apps are admitted here;
    runtime content and command effects need their own retention contract.
    """

    def __init__(
        self,
        *,
        state: StateManager,
        dispatcher: EventDispatcher,
        metadata: MacosExecutionMetadataProducer,
        host: HostContext,
        parent: ProcessIdentity,
        session: SessionIdentity,
        launcher: BinaryReleaseIdentity,
        app: BinaryReleaseIdentity,
        arguments: tuple[str, ...],
        service_label: str,
        times: tuple[datetime, datetime, datetime, datetime],
        lifecycle_group_id: str,
        concurrency_group_id: str,
        storyline: bool,
    ) -> None:
        if (
            dispatcher.state_manager is not state
            or host.os_category != "macos"
            or host.hostname != parent.hostname
            or state.get_process_identity(host.hostname, 1) != parent
            or parent.pid != 1
            or parent.image != "/sbin/launchd"
            or parent.principal != "root"
            or parent.credentials is None
            or not parent.credentials.is_unattributed_root
            or state.get_session_identity(session.logon_id) != session
            or session.hostname != host.hostname
            or session.session_kind != "interactive"
            or not all(left < right for left, right in zip(times, times[1:], strict=False))
            or metadata.profile.finder_launcher_xpc_flags is None
        ):
            raise StateError("Finder startup requires its exact root parent, GUI owner and policy")
        for binary in (launcher, app):
            if (
                type(binary) is not BinaryReleaseIdentity
                or binary.mach_o_image is None
                or binary.mach_o_image.architecture != "arm64"
                or binary.code_signature is None
                or metadata.image_security(binary) is None
            ):
                raise StateError("Finder startup requires qualified installed native executables")
        self._state = state
        self._dispatcher = dispatcher
        self._metadata = metadata
        self._host = replace(host, roles=list(host.roles))
        self._parent = parent
        self._session = session
        self._launcher = launcher
        self._app = app
        self._arguments = arguments
        self._times = times
        self._lifecycle_group_id = lifecycle_group_id
        self._concurrency_group_id = concurrency_group_id
        self._storyline = storyline
        self._launcher_arguments = ("xpcproxy", service_label)
        self._launcher_environment = (f"XPC_FLAGS={metadata.profile.finder_launcher_xpc_flags}",)
        # Preflight explicit synthetic launch inputs before the first mutation.
        self._launcher_metadata = metadata.launch(
            host.hostname,
            "root",
            at=times[1],
            requested_path="/usr/libexec/xpcproxy",
            binary=launcher,
            kind="system",
        )
        self._app_metadata = metadata.launch(
            host.hostname,
            session.principal,
            at=times[3],
            requested_path=arguments[0],
            binary=app,
            kind="user",
        )
        keys = {entry.split("=", 1)[0] for entry in self._app_metadata.environment}
        if keys & {"XPC_FLAGS", "XPC_SERVICE_NAME"}:
            raise StateError("Finder app environment conflicts with its declared service inputs")
        self._app_environment = self._app_metadata.environment + (
            "XPC_FLAGS=1",
            f"XPC_SERVICE_NAME={service_label}",
        )
        self._launcher_directory = metadata.directory(host.hostname, "/", times[1])
        self._app_directory = metadata.directory(host.hostname, "/", times[3])
        current = state.process_directory_at(parent, event_time=times[0])
        if current is None:
            raise StateError("Finder startup requires its boot parent's modeled working directory")
        self._fork_directory = metadata.directory(host.hostname, current.native_path, times[0])
        if self._fork_directory.metadata != current.metadata:
            raise StateError("Finder startup changed the boot parent's directory object")
        self._phase = 0
        self._pending: _PendingFinderPhase | None = None
        self.process: ProcessIdentity | None = None
        self.birth: ProcessMaterializationPlan | None = None
        self.fork_event: OccurrenceBuilder | None = None
        self.app_event: OccurrenceBuilder | None = None

    @property
    def complete(self) -> bool:
        """Expose completion only when all three canonical phases reached their sinks."""
        return self._phase == 3

    def advance(self) -> None:
        """Publish or resume one exact phase without reforking or repeating an exec."""
        if self.complete:
            return
        if self._pending is None:
            self._pending = self._prepare_next()
        pending = self._pending
        capability: PreparedActionCohortCapability | None = None
        try:
            if pending.receipt is None:
                with self._dispatcher.claimed_action_cohort(pending.batch) as capability:
                    pending.capability = capability
                    try:
                        capability.commit_no_fail()
                    finally:
                        if capability.committed:
                            pending.receipt = capability.receipt
            elif pending.capability is None or not pending.capability.projection_complete:
                self._dispatcher.resume_action_cohort_projection(pending.receipt)
        except BaseException:
            if pending.receipt is None:
                cancelled = self._dispatcher.cancel_prepared_action_cohort_batch(pending.batch)
                if cancelled or (capability is not None and not capability.committed):
                    self._pending = None
            raise
        self.process = pending.after
        if self._phase == 0:
            self.birth = pending.birth
            self.fork_event = pending.events[0]
        elif self._phase == 2:
            self.app_event = pending.events[0]
        self._phase += 1
        self._pending = None

    def _prepare_next(self) -> _PendingFinderPhase:
        builder = self._state.begin_action_cohort_materialization()
        birth = None
        if self._phase == 0:
            birth = builder.fork_process(
                self._parent,
                forked_at=self._times[0],
                execution_directory=self._fork_directory,
                lifecycle_group_id=self._lifecycle_group_id,
                concurrency_group_id=self._concurrency_group_id,
            )
            before = birth.identity
            metadata = self._launcher_metadata
            after = builder.execute_process(
                birth,
                image="/usr/libexec/xpcproxy",
                command_line=shlex.join(self._launcher_arguments),
                arguments=self._launcher_arguments,
                environment=self._launcher_environment,
                executed_at=self._times[1],
                execution_directory=self._launcher_directory,
                exec_image=metadata.image,
                exec_script=metadata.script,
                image_security=metadata.image_security,
                executable_version=ProcessExecutableVersion.from_binary(self._launcher),
                macos_finder_spawn=True,
            )
            fork = process_fork_occurrence(
                host=self._host,
                parent=self._parent,
                child=before,
                integrity_level="System",
            )
            event = process_exec_occurrence(
                host=self._host,
                before=before,
                after=after,
                integrity_level="System",
            )
            event.process.binary_identity = self._launcher
            events = (fork, event)
        else:
            before = self.process
            assert before is not None
            if self._phase == 1:
                after = builder.drop_macos_gui_launcher_credentials(
                    before,
                    session=self._session,
                    dropped_at=self._times[2],
                )
                event = process_credential_occurrence(
                    host=self._host,
                    before=before,
                    after=after,
                    timestamp=self._times[2],
                    kind="process_service_drop",
                    integrity_level="Medium",
                    session=self._session,
                )
            else:
                after = self._metadata.plan_exec(
                    builder,
                    self._state,
                    before,
                    at=self._times[3],
                    image=self._arguments[0],
                    requested_path=self._arguments[0],
                    arguments=self._arguments,
                    binary=self._app,
                    environment=self._app_environment,
                    execution_directory=self._app_directory,
                    gui_session=self._session,
                ).process
                event = process_exec_occurrence(
                    host=self._host,
                    before=before,
                    after=after,
                    integrity_level="Medium",
                    session=self._session,
                )
                event.process.binary_identity = self._app
            events = (event,)
        plan = builder.seal()
        root = (
            f"macos-process-cohort:{plan.semantic_id}"
            if self._phase == 0
            else f"process_service_drop:{after.execution_id}"
            if self._phase == 1
            else f"process-exec:{after.execution_id}"
        )
        return _PendingFinderPhase(
            self._prepare_publication(plan, events, root), after, events, birth
        )

    def _prepare_publication(
        self,
        plan: ActionCohortMaterializationPlan,
        events: tuple[OccurrenceBuilder, ...],
        root: str,
    ) -> PreparedActionCohortBatch:
        dispatcher = self._dispatcher
        for event in events:
            event.storyline_origin = self._storyline
        with dispatcher.source_timing_planner.prepared_planning() as timing:
            carriers = tuple(
                dispatcher.prepare_action_cohort_projection(event, source_timing_preparation=timing)
                for event in events
            )
        members = tuple(
            dispatcher.bind_action_cohort_projection(carrier, state_plan=plan)
            for carrier in carriers
        )
        effects = ExecutionEffectPlan(ActionAnchor("process_execution", root, source="finder"), ())
        return dispatcher.prepare_action_cohort_batch(
            root,
            plan,
            members,
            (ExecutionEffectAuditCohortEntry(effects, effects.reconcile(())),),
            (),
            (),
            exact_projection=True,
        )
