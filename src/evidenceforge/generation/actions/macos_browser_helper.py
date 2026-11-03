# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Bounded browser helper startup through the shared retained Mac phase journal."""

from dataclasses import replace
from datetime import datetime

from evidenceforge.events.content_identity import BinaryReleaseIdentity
from evidenceforge.events.contexts import HostContext
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.identity import ProcessIdentity, SessionIdentity
from evidenceforge.events.macos_spawn_io import MacosSpawnIO
from evidenceforge.generation.actions.macos_finder import (
    MacosFinderStartup,
    PendingMacosStartupPhase,
)
from evidenceforge.generation.actions.posix_process import (
    process_exec_occurrence,
    process_fork_occurrence,
)
from evidenceforge.generation.macos_execution_metadata import MacosExecutionMetadataProducer
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError


class MacosBrowserHelperStartup(MacosFinderStartup):
    """Reuse exact fork/exec commit recovery, with one State-owned sandbox pipe."""

    publication_source: str = "browser_helper"
    app_phase: int = 1

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
        environment: tuple[str, ...],
        spawn_io: MacosSpawnIO,
        times: tuple[datetime, datetime],
        lifecycle_group_id: str,
        concurrency_group_id: str,
        storyline: bool,
    ) -> None:
        current = state.process_directory_at(parent, event_time=times[0])
        table = state.process_descriptors_at(parent, event_time=times[0])
        if (
            dispatcher.state_manager is not state
            or host.hostname != parent.hostname
            or state.get_process_identity(parent.hostname, parent.pid) != parent
            or state.get_session_identity(session.logon_id) != session
            or session.session_kind != "interactive"
            or parent.logon_id != session.logon_id
            or host.os_category != "macos"
            or parent.job_control is None
            or state.known_macos_terminal(parent.job_control.session, times[0]) != "absent"
            or current is None
            or table is None
            or table.native_last_fd is None
            or tuple(binding.fd for binding in table.bindings if binding.fd <= 2) != (0, 1, 2)
            or any(
                binding.kind != "file" or binding.close_on_exec
                for binding in table.bindings
                if binding.fd <= 2
            )
            or app.code_signature is None
            or app.code_signature.entitlements is None
            or app.mach_o_image is None
            or app.mach_o_image.architecture != "arm64"
            or metadata.image_security(app) is None
            or spawn_io.kind != "browser_sandbox"
            or not parent.execution_started_at < times[0] < times[1]
        ):
            raise StateError(
                "Mac browser startup requires its qualified GUI parent, standard vnodes and installed image"
            )
        spawn_io.__post_init__()
        self._state, self._dispatcher, self._metadata = state, dispatcher, metadata
        self._host = replace(host, roles=list(host.roles))
        self._parent, self._session, self._app = parent, session, app
        self._arguments, self._app_environment, self._spawn_io = arguments, environment, spawn_io
        self._times, self._lifecycle_group_id = times, lifecycle_group_id
        self._concurrency_group_id, self._storyline = concurrency_group_id, storyline
        self._fork_directory = metadata.directory(parent.hostname, current.native_path, times[0])
        self._app_directory = metadata.directory(parent.hostname, current.native_path, times[1])
        self._phase = 0
        self._pending: PendingMacosStartupPhase | None = None
        self.process = self.birth = self.fork_event = self.app_event = None

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
            after = self._metadata.plan_exec(
                builder,
                self._state,
                before,
                at=self._times[1],
                image=self._arguments[0],
                requested_path=self._arguments[0],
                arguments=self._arguments,
                binary=self._app,
                environment=self._app_environment,
                execution_directory=self._app_directory,
                spawn_io=self._spawn_io,
            ).process
            event = process_exec_occurrence(
                host=self._host, before=before, after=after, integrity_level="Medium"
            )
            event.process.binary_identity = self._app
            root = f"process-exec:{after.execution_id}"
        events = (event,)
        return PendingMacosStartupPhase(
            self._prepare_publication(builder.seal(), events, root), after, events, birth
        )
