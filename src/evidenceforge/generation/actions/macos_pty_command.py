# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Measured direct SSH PTY command startup through the retained Mac phase journal."""

from dataclasses import replace
from datetime import datetime

from evidenceforge.events.content_identity import BinaryReleaseIdentity
from evidenceforge.events.contexts import HostContext
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.identity import ProcessIdentity, SessionIdentity
from evidenceforge.events.macos_terminal import MacosTerminalObservation
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


class MacosPtyCommandStartup(MacosFinderStartup):
    """Reuse exact phase commit/recovery for fork, foreground setpgid and exec.

    No subprocess is inferred from shell text. Only a literal installed command
    launched from the qualified initial SSH zsh consumes this bounded producer.
    """

    publication_source: str = "ssh_pty_command"

    def __init__(
        self,
        *,
        state: StateManager,
        dispatcher: EventDispatcher,
        metadata: MacosExecutionMetadataProducer,
        host: HostContext,
        parent: ProcessIdentity,
        session: SessionIdentity,
        app: BinaryReleaseIdentity,
        arguments: tuple[str, ...],
        times: tuple[datetime, datetime, datetime],
        lifecycle_group_id: str,
        concurrency_group_id: str,
        storyline: bool,
    ) -> None:
        active = state.get_session(session.logon_id)
        terminal = (
            state.known_macos_terminal(parent.job_control.session, times[0])
            if parent.job_control is not None
            else None
        )
        table = state.process_descriptors_at(parent, event_time=times[0])
        if (
            dispatcher.state_manager is not state
            or host.os_category != "macos"
            or host.hostname != parent.hostname
            or session.hostname != parent.hostname
            or state.get_process_identity(parent.hostname, parent.pid) != parent
            or state.get_session_identity(session.logon_id) != session
            or session.session_kind != "ssh"
            or active is None
            or active.auth_protocol != "ssh"
            or active.session_shell_pid != parent.pid
            or active.ssh_command_streams is not None
            or active.audit_origin is None
            or parent.credentials is None
            or parent.principal != session.principal
            or parent.logon_id != session.logon_id
            or parent.credentials.audit_uid != active.audit_origin.audit_uid
            or parent.credentials.audit_session_id != active.audit_origin.audit_session_id
            or parent.image != "/bin/zsh"
            or parent.arguments != ("-zsh",)
            or parent.job_control is None
            or parent.job_control.session.sid != parent.pid
            or parent.responsibility is None
            or parent.environment is None
            or metadata.profile.ssh_pty_execution != "zsh_foreground_v11"
            or type(terminal) is not MacosTerminalObservation
            or terminal.session != parent.job_control.session
            or table is None
            or tuple(binding.fd for binding in table.bindings) != (0, 1, 2)
            or any(binding.kind != "file" or binding.close_on_exec for binding in table.bindings)
            or table.native_last_fd != 2
            or len({binding.object_id for binding in table.bindings}) != 1
            or type(app) is not BinaryReleaseIdentity
            or app.code_signature is None
            or app.mach_o_image is None
            or app.mach_o_image.architecture != "arm64"
            or metadata.image_security(app) is None
            or not arguments
            or times[0] <= parent.execution_started_at
            or not times[0] < times[1] < times[2]
            or active.source_ready_time is None
            or times[0] < active.source_ready_time
            or active.network_close_time is None
            or times[2] >= active.network_close_time
        ):
            raise StateError(
                "SSH PTY command requires its qualified initial zsh, terminal and installed image"
            )
        current = state.process_directory_at(parent, event_time=times[0])
        if current is None:
            raise StateError("SSH PTY command requires its shell's current directory")
        self._state, self._dispatcher, self._metadata = state, dispatcher, metadata
        self._host = replace(host, roles=list(host.roles))
        self._parent, self._session, self._app = parent, session, app
        self._arguments, self._times = arguments, times
        self._lifecycle_group_id, self._concurrency_group_id = (
            lifecycle_group_id,
            concurrency_group_id,
        )
        self._storyline = storyline
        self._fork_directory = metadata.directory(parent.hostname, current.native_path, times[0])
        self._app_directory = metadata.directory(parent.hostname, current.native_path, times[2])
        self._app_metadata = metadata.launch(
            parent.hostname,
            parent.principal,
            at=times[2],
            requested_path=arguments[0],
            binary=app,
            kind="user",
        )
        self._phase = 0
        self._pending: PendingMacosStartupPhase | None = None
        self.process = None
        self.birth = None
        self.fork_event = None
        self.app_event = None

    def _prepare_next(self) -> PendingMacosStartupPhase:
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
            after = birth.identity
            event = process_fork_occurrence(
                host=self._host, parent=self._parent, child=after, integrity_level="Medium"
            )
            root = f"process-fork:{after.object_id}"
        else:
            before = self.process
            assert before is not None
            if self._phase == 1:
                after = builder.change_posix_job_control(
                    before, operation="setpgid", changed_at=self._times[1]
                )
                event = process_job_control_occurrence(
                    host=self._host,
                    before=before,
                    after=after,
                    timestamp=self._times[1],
                    integrity_level="Medium",
                )
                root = f"process-job-control:{after.execution_id}:{self._times[1].isoformat()}"
            else:
                after = self._metadata.plan_exec(
                    builder,
                    self._state,
                    before,
                    at=self._times[2],
                    image=self._arguments[0],
                    requested_path=self._arguments[0],
                    arguments=self._arguments,
                    binary=self._app,
                    environment=self._parent.environment,
                    execution_directory=self._app_directory,
                ).process
                event = process_exec_occurrence(
                    host=self._host,
                    before=before,
                    after=after,
                    integrity_level="Medium",
                )
                event.process.binary_identity = self._app
                root = f"process-exec:{after.execution_id}"
        events = (event,)
        return PendingMacosStartupPhase(
            self._prepare_publication(builder.seal(), events, root), after, events, birth
        )
