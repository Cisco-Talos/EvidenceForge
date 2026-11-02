# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Reviewed system-job startup through the existing retained native phase journal."""

import shlex
from dataclasses import replace
from datetime import datetime
from typing import TYPE_CHECKING

from evidenceforge.events.content_identity import BinaryReleaseIdentity
from evidenceforge.events.contexts import HostContext
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.macos_launchd import LaunchdSystemJobDefinition
from evidenceforge.events.macos_spawn_io import MacosSpawnIO
from evidenceforge.events.process_executable import ProcessExecutableVersion
from evidenceforge.generation.actions.macos_finder import (
    MacosFinderStartup,
    PendingMacosStartupPhase,
)
from evidenceforge.generation.actions.posix_process import (
    process_exec_occurrence,
    process_fork_occurrence,
    process_job_control_occurrence,
)
from evidenceforge.generation.macos_execution_metadata import MacosExecutionMetadataProducer
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError

if TYPE_CHECKING:
    from evidenceforge.generation.actions.macos_persistence import MacosPersistenceRequest
    from evidenceforge.generation.lifecycle_production_adapters import (
        ServiceLifecyclePublicationPlan,
    )


class MacosSystemJobStartup(MacosFinderStartup):
    """One root fork/launcher exec, setsid and target exec, with exact source recovery."""

    publication_source: str = "launchd_system_job"

    def __init__(
        self,
        *,
        state: StateManager,
        dispatcher: EventDispatcher,
        metadata: MacosExecutionMetadataProducer,
        host: HostContext,
        parent: ProcessIdentity,
        launcher: BinaryReleaseIdentity,
        app: BinaryReleaseIdentity,
        definition: LaunchdSystemJobDefinition,
        times: tuple[datetime, datetime, datetime, datetime],
    ) -> None:
        policy = metadata.profile
        if (
            dispatcher.state_manager is not state
            or host.os_category != "macos"
            or host.hostname != parent.hostname
            or state.get_process_identity(parent.hostname, 1) != parent
            or parent.pid != 1
            or parent.image != "/sbin/launchd"
            or parent.principal != "root"
            or parent.logon_id
            or parent.credentials is None
            or not parent.credentials.is_unattributed_root
            or parent.credentials.audit_session_id in (None, 0)
            or parent.job_control is None
            or parent.job_control.pgid != 1
            or parent.job_control.session.sid != 1
            or parent.responsibility is None
            or parent.responsibility.responsible is not None
            or policy.system_job_startup != "root_xpcproxy_v11"
            or definition.launch_profile != policy.system_job_startup
            or definition.principal != "root"
            or definition.program not in policy.system_job_images
            or definition.run_at_load
            or definition.arguments[0] != definition.program
            or not all(left < right for left, right in zip(times, times[1:], strict=False))
            or times[0] <= parent.execution_started_at
        ):
            raise StateError(
                "Native system-job startup requires its qualified root preset, boot parent and installed image"
            )
        for binary in (launcher, app):
            if (
                type(binary) is not BinaryReleaseIdentity
                or binary.mach_o_image is None
                or binary.mach_o_image.architecture != "arm64"
                or binary.code_signature is None
                or metadata.image_security(binary) is None
            ):
                raise StateError(
                    "Native system-job startup requires qualified installed native binaries"
                )
        if not definition.launch_environment or any(
            item.split("=", 1)[0] in {"XPC_FLAGS", "XPC_SERVICE_NAME", "OSLogRateLimit"}
            or "{" in item
            or "}" in item
            for item in definition.launch_environment
        ):
            raise StateError(
                "Native system-job preset requires literal, disjoint environment inputs"
            )
        horizon = dispatcher.output_end_time
        if horizon is not None and times[-1] >= horizon:
            raise StateError(
                "Native system-job startup does not fit before the collection boundary"
            )
        current = state.process_directory_at(parent, event_time=times[0])
        if current is None or current.native_path != "/":
            raise StateError("Native system-job startup requires its boot parent's root directory")
        self._state, self._dispatcher, self._metadata = state, dispatcher, metadata
        self._host, self._parent = replace(host, roles=list(host.roles)), parent
        self._launcher, self._app, self._definition = launcher, app, definition
        self._times, self._storyline = times, True
        self._launcher_arguments = ("xpcproxy", definition.label)
        self._launcher_environment = ("XPC_FLAGS=0x0",)
        self._app_environment = definition.launch_environment + (
            "OSLogRateLimit=64",
            "XPC_FLAGS=1",
            f"XPC_SERVICE_NAME={definition.label}",
        )
        self._fork_directory = metadata.directory(parent.hostname, "/", times[0])
        if self._fork_directory.metadata != current.metadata:
            raise StateError("Native system-job fork changed its boot directory object")
        self._launcher_directory = metadata.directory(parent.hostname, "/", times[1])
        self._app_directory = metadata.directory(parent.hostname, "/", times[3])
        self._launcher_metadata = metadata.launch(
            parent.hostname,
            "root",
            at=times[1],
            requested_path="/usr/libexec/xpcproxy",
            binary=launcher,
            kind="system",
        )
        self._app_metadata = metadata.launch(
            parent.hostname,
            "root",
            at=times[3],
            requested_path=definition.program,
            binary=app,
            kind="system",
        )
        self._phase = 0
        self._pending: PendingMacosStartupPhase | None = None
        self.process = self.birth = self.fork_event = self.app_event = None
        self.binding_plan: ServiceLifecyclePublicationPlan | None = None
        self.request: MacosPersistenceRequest | None = None

    def _prepare_next(self) -> PendingMacosStartupPhase:
        builder = self._state.begin_action_cohort_materialization()
        birth = None
        if self._phase == 0:
            birth = builder.fork_process(
                self._parent, forked_at=self._times[0], execution_directory=self._fork_directory
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
                macos_spawn_io=MacosSpawnIO("launchd_job_launcher"),
            )
            fork = process_fork_occurrence(
                host=self._host, parent=self._parent, child=before, integrity_level="System"
            )
            event = process_exec_occurrence(
                host=self._host, before=before, after=after, integrity_level="System"
            )
            event.process.binary_identity = self._launcher
            events = (fork, event)
        else:
            before = self.process
            assert before is not None
            if self._phase == 1:
                after = builder.change_posix_job_control(
                    before, operation="setsid", changed_at=self._times[2], macos_terminal="absent"
                )
                event = process_job_control_occurrence(
                    host=self._host,
                    before=before,
                    after=after,
                    timestamp=self._times[2],
                    integrity_level="System",
                )
                root = f"process-job-control:{after.execution_id}:{self._times[2].isoformat()}"
            else:
                after = self._metadata.plan_exec(
                    builder,
                    self._state,
                    before,
                    at=self._times[3],
                    image=self._definition.program,
                    requested_path=self._definition.program,
                    arguments=self._definition.arguments,
                    binary=self._app,
                    environment=self._app_environment,
                    execution_directory=self._app_directory,
                ).process
                event = process_exec_occurrence(
                    host=self._host, before=before, after=after, integrity_level="System"
                )
                event.process.binary_identity = self._app
                root = f"process-exec:{after.execution_id}"
            events = (event,)
        plan = builder.seal()
        if self._phase == 0:
            root = f"macos-process-cohort:{plan.semantic_id}"
        return PendingMacosStartupPhase(
            self._prepare_publication(plan, events, root), after, events, birth
        )
