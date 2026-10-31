# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Reviewed non-PTY SSH graph through the existing exact startup publication owner."""

from evidenceforge.events.content_identity import BinaryReleaseIdentity
from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.macos_spawn_io import MacosSpawnIO
from evidenceforge.events.process_outcome import PosixProcessExit
from evidenceforge.events.responsibility import ProcessResponsibility, ResponsibleProcessReference
from evidenceforge.generation.actions.macos_ssh_receiver import (
    MacosSshReceiverStartup,
    _PendingStartupPhase,
    macos_ssh_command_arguments,
)
from evidenceforge.generation.actions.posix_process import (
    process_credential_occurrence,
    process_exec_occurrence,
    process_exit_occurrence,
    process_fork_occurrence,
    process_job_control_occurrence,
)
from evidenceforge.models.exceptions import StateError


class MacosNativeSshReceiverStartup(MacosSshReceiverStartup):
    """Preserve actual forks, same-PID replacements and closed fork-only children.

    The enclosing network/session owner has committed the exact initial launchd
    fork. Every subsequent transition reuses the existing retained State/source
    journal. Shell startup commands are separate modeled actions, never inferred
    from a private user's initialization files.
    """

    stages: tuple[tuple[str, str], ...] = (
        ("receiver", "launcher_exec"),
        ("receiver", "setsid"),
        ("receiver", "wrapper_exec"),
        ("receiver", "daemon_exec"),
        ("daemon_child", "fork"),
        ("receiver", "session_exec"),
        ("daemon_child", "exit"),
        ("preauth", "fork"),
        ("preauth", "auth_exec"),
        ("preauth", "service_drop"),
        ("session_child", "fork"),
        ("session_child", "exit"),
        ("preauth", "exit"),
        ("receiver", "audit_bind"),
        ("postauth", "fork"),
        ("postauth", "user_drop"),
        ("shell", "fork"),
        ("shell", "setsid"),
        ("shell", "shell_exec"),
    )

    def _accept_phase(self, after: ProcessIdentity) -> None:
        role, _action = self.stages[self._phase]
        setattr(self, f"_{role}", after)

    def _prepare_next(self) -> _PendingStartupPhase:
        request, provider = self._request, self._metadata
        if provider is None or request.launcher is None or request.service_label is None:
            raise StateError("Native SSH startup requires explicit launcher and metadata policy")
        role, action = self.stages[self._phase]
        at = request.phase_times[self._phase]
        state = self._state
        session = state.get_session_identity(self._receiver.logon_id)
        if session is None:
            raise StateError("Native SSH startup lost its exact session")
        builder = state.begin_action_cohort_materialization()
        if action == "fork":
            before = self._postauth if role == "shell" else self._receiver
            assert before is not None
            responsible = ProcessResponsibility(
                ResponsibleProcessReference(
                    self._receiver.hostname,
                    self._receiver.object_id,
                    self._receiver.pid,
                    self._receiver.started_at,
                )
            )
            birth = provider.plan_fork(builder, state, before, at=at, responsibility=responsible)
            after = birth.identity
            event = process_fork_occurrence(
                host=self._host,
                parent=before,
                child=after,
                integrity_level="System" if before.principal == "root" else "Medium",
            )
            key = f"process-fork:{after.object_id}"
        else:
            before = getattr(self, f"_{role}", None)
            if before is None:
                raise StateError("Native SSH startup lost its already published role")
            integrity = "System" if before.principal == "root" else "Medium"
            if action.endswith("_exec"):
                descriptor = {
                    "launcher_exec": request.launcher,
                    "wrapper_exec": request.wrapper,
                    "daemon_exec": request.daemon,
                    "session_exec": request.session_worker,
                    "auth_exec": request.authentication_worker,
                    "shell_exec": request.shell,
                }[action]
                binary = self._dispatcher.resolve_process_binary_identity(
                    before.hostname, before.principal, descriptor.image_path, "macos"
                )
                if type(binary) is not BinaryReleaseIdentity:
                    raise StateError("Native SSH startup requires its exact installed role image")
                launch = provider.launch(
                    before.hostname,
                    before.principal,
                    at=at,
                    requested_path=descriptor.image_path,
                    binary=binary,
                    kind="user" if action == "shell_exec" else "system",
                )
                arguments = (
                    ("xpcproxy", request.service_label)
                    if action == "launcher_exec"
                    else (f"-{descriptor.executable}",)
                    if action == "shell_exec"
                    else macos_ssh_command_arguments(descriptor)
                )
                if action == "wrapper_exec" and arguments != (descriptor.executable,):
                    raise StateError("Reviewed SSH wrapper requires its basename-only argv")
                layout = {
                    "launcher_exec": "ssh_launcher",
                    "wrapper_exec": "ssh_inetd",
                    "session_exec": "ssh_session",
                    "auth_exec": "ssh_auth",
                    "shell_exec": "ssh_shell",
                }.get(action)
                after = provider.plan_exec(
                    builder,
                    state,
                    before,
                    at=at,
                    image=descriptor.image_path,
                    requested_path=descriptor.image_path,
                    arguments=arguments,
                    binary=binary,
                    environment=launch.environment
                    if action in {"launcher_exec", "shell_exec"}
                    else None,
                    execution_directory=launch.directory if action == "shell_exec" else None,
                    spawn_io=MacosSpawnIO(
                        layout,
                        provider.profile.first_pipe_id if action == "auth_exec" else None,
                    )
                    if layout is not None
                    else None,
                ).process
                if action == "shell_exec":
                    builder.bind_macos_ssh_session_shell(session, shell=after)
                event = process_exec_occurrence(
                    host=self._host,
                    before=before,
                    after=after,
                    integrity_level=integrity,
                    session=session if action == "shell_exec" else None,
                )
                event.process.binary_identity = binary
                key = f"process-exec:{after.execution_id}"
            elif action == "setsid":
                after = builder.change_posix_job_control(
                    before, operation="setsid", changed_at=at, macos_terminal="absent"
                )
                event = process_job_control_occurrence(
                    host=self._host,
                    before=before,
                    after=after,
                    timestamp=at,
                    integrity_level=integrity,
                )
                key = f"process-job-control:{after.execution_id}:{at.isoformat()}"
            elif action == "exit":
                outcome = PosixProcessExit(exit_code=0)
                builder.terminate_process(before, end_time=at, exit_outcome=outcome)
                after = before
                event = process_exit_occurrence(
                    host=self._host,
                    process=before,
                    timestamp=at,
                    integrity_level=integrity,
                    exit_outcome=outcome,
                )
                key = f"process-exit:{before.object_id}"
            else:
                if action == "audit_bind":
                    after = builder.bind_macos_process_audit_origin(before, bound_at=at)
                    kind = "process_audit_bind"
                elif action == "service_drop":
                    after = builder.drop_macos_service_child_privileges(
                        before, service_account=request.service_account, dropped_at=at
                    )
                    kind = "process_service_drop"
                elif action == "user_drop":
                    after = builder.drop_macos_ssh_child_privileges(before, dropped_at=at)
                    kind = "process_privilege_drop"
                else:
                    raise StateError("Native SSH startup selected an unknown semantic stage")
                event = process_credential_occurrence(
                    host=self._host,
                    before=before,
                    after=after,
                    timestamp=at,
                    kind=kind,
                    integrity_level="System" if action == "audit_bind" else "Medium",
                )
                key = f"{kind}:{after.execution_id}"
        batch = self._prepare_publication(builder.seal(), event, key)
        return _PendingStartupPhase(batch, after)
