# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Bounded process-side startup for a preallocated Mac SSH receiver.

Transport, session admission, timing allocation and durable continuation installation
remain the enclosing SSH bundle's responsibility. This coordinator does not enable
receiver authoring or publish a native authentication message.
"""

from dataclasses import dataclass, replace
from datetime import datetime

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import HostContext
from evidenceforge.events.dispatcher import (
    ActionCohortPublicationReceipt,
    EventDispatcher,
    PreparedActionCohortBatch,
    PreparedActionCohortCapability,
)
from evidenceforge.events.identity import PosixProcessCredentials, ProcessIdentity
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.actions.command_effects import (
    ExecutionEffectAuditCohortEntry,
    ExecutionEffectPlan,
)
from evidenceforge.generation.actions.posix_process import (
    process_credential_occurrence,
    process_exec_occurrence,
    process_exit_occurrence,
    process_fork_occurrence,
    process_job_control_occurrence,
)
from evidenceforge.generation.deployment_registry import (
    CompiledApplicationDescriptor,
    DeploymentContentRegistry,
)
from evidenceforge.generation.identity import IdentityDirectory, MacAccount
from evidenceforge.generation.state_manager import ActionCohortMaterializationPlan, StateManager
from evidenceforge.models.exceptions import StateError


@dataclass(frozen=True, slots=True)
class MacosSshReceiverEnvironment:
    """Explicit local identities and effective compiled executables for one receiver."""

    account: MacAccount
    service_account: MacAccount
    parent: ProcessIdentity
    wrapper: CompiledApplicationDescriptor
    daemon: CompiledApplicationDescriptor
    session_worker: CompiledApplicationDescriptor
    authentication_worker: CompiledApplicationDescriptor
    shell: CompiledApplicationDescriptor


def resolve_macos_ssh_receiver_environment(
    *,
    hostname: str,
    username: str,
    started_at: datetime,
    state: StateManager,
    identities: IdentityDirectory | None,
    deployment: DeploymentContentRegistry | None,
) -> MacosSshReceiverEnvironment:
    """Resolve existing modeled owners without allocating identities or host I/O."""
    if identities is None or deployment is None:
        raise StateError("Mac SSH receiver requires modeled accounts and compiled applications")
    account = identities.macos_account(username, hostname)
    service = identities.macos_account("_sshd", hostname)
    if (
        account is None
        or account.host != hostname
        or account.logical_name != username
        or account.scope != "local"
        or account.uid <= 0
        or account.gid < 0
        or service is None
        or service.host != hostname
        or service.account_name != "_sshd"
        or service.scope != "well_known"
    ):
        raise StateError("Mac SSH receiver requires an explicit local user and _sshd account")
    # Match the existing account shell to a compiled native entry, without a
    # basename guess, cross-platform fallback, or consulting the generator host.
    shells = tuple(
        descriptor
        for application in ("macos-zsh", "macos-bash")
        if (descriptor := deployment.application_descriptor(application, "macos")) is not None
        and descriptor.image_path == account.shell
    )
    if len(shells) != 1:
        raise StateError("Mac SSH receiver account shell requires a unique compiled zsh/bash entry")
    applications: list[CompiledApplicationDescriptor] = []
    for application in (
        "macos-launchd",
        "macos-sshd-keygen-wrapper",
        "macos-sshd",
        "macos-sshd-session",
        "macos-sshd-auth",
    ):
        descriptor = deployment.application_descriptor(application, "macos")
        if descriptor is None or descriptor.platform != "macos":
            raise StateError(f"Mac SSH receiver requires compiled entry {application}")
        applications.append(descriptor)
    launchd, wrapper, daemon, worker, authentication = applications
    parent = state.get_process_identity(hostname, 1)
    running = state.get_process(hostname, 1)
    if (
        state._pid_os.get(hostname) != "macos"
        or parent is None
        or running is None
        or parent.object_id != running.ecar_object_id
        or parent.started_at > started_at
        or parent.image != launchd.image_path
        or parent.principal != "root"
        or parent.credentials != PosixProcessCredentials(0, 0, 0, 0)
    ):
        raise StateError("Mac SSH receiver requires its live modeled launchd parent")
    return MacosSshReceiverEnvironment(
        account, service, parent, wrapper, daemon, worker, authentication, shells[0]
    )


@dataclass(frozen=True, slots=True)
class MacosSshReceiverStartupRequest:
    """Existing receiver and compiled executable/timing facts for legacy or session-owning startup."""

    receiver: ProcessIdentity
    service_account: MacAccount
    wrapper: CompiledApplicationDescriptor
    daemon: CompiledApplicationDescriptor
    session_worker: CompiledApplicationDescriptor
    authentication_worker: CompiledApplicationDescriptor
    shell: CompiledApplicationDescriptor
    phase_times: tuple[datetime, ...]

    def __post_init__(self) -> None:
        if (
            type(self.receiver) is not ProcessIdentity
            or type(self.service_account) is not MacAccount
        ):
            raise StateError("Mac receiver startup requires exact process and service identities")
        descriptors = (
            (self.wrapper, "macos-sshd-keygen-wrapper"),
            (self.daemon, "macos-sshd"),
            (self.session_worker, "macos-sshd-session"),
            (self.authentication_worker, "macos-sshd-auth"),
        )
        for descriptor, application in descriptors:
            if (
                type(descriptor) is not CompiledApplicationDescriptor
                or descriptor.application_id != application
                or descriptor.platform != "macos"
                or len(descriptor.command_templates) != 1
                or descriptor.command_parameter_pools
            ):
                raise StateError("Mac receiver startup requires its compiled role executables")
        if (
            type(self.shell) is not CompiledApplicationDescriptor
            or self.shell.platform != "macos"
            or self.shell.application_id not in {"macos-zsh", "macos-bash"}
            or self.shell.command_parameter_pools
            or self.receiver.image != self.wrapper.image_path
            or self.receiver.command_line != self.wrapper.command_templates[0]
            or self.receiver.execution_ordinal != 0
            or self.receiver.principal != "root"
            or self.receiver.credentials != PosixProcessCredentials(0, 0, 0, 0)
            or self.service_account.host != self.receiver.hostname
            or self.service_account.account_name != "_sshd"
            or self.service_account.scope != "well_known"
        ):
            raise StateError("Mac receiver startup changed its wrapper, shell or service owner")
        times = self.phase_times
        if (
            type(times) is not tuple
            or len(times) not in {11, 12}
            or any(type(at) is not datetime or at.utcoffset() is None for at in times)
            or times[0] <= self.receiver.started_at
            or any(left >= right for left, right in zip(times, times[1:], strict=False))
        ):
            raise StateError(
                "Mac receiver startup requires eleven or twelve strictly ordered aware times"
            )
        if len(times) == 12 and self.receiver.job_control is None:
            raise StateError("Mac receiver session-owning startup requires known membership")


@dataclass(frozen=True, slots=True)
class MacosSshReceiverProcesses:
    """Exact live roles after startup; the pre-authentication child has already exited."""

    privileged_receiver: ProcessIdentity
    authenticated_child: ProcessIdentity
    shell: ProcessIdentity


@dataclass(slots=True)
class _PendingStartupPhase:
    batch: PreparedActionCohortBatch
    resulting_identity: ProcessIdentity
    receipt: ActionCohortPublicationReceipt | None = None
    capability: PreparedActionCohortCapability | None = None


class MacosSshReceiverStartup:
    """Publish ordered canonical phases, retaining the current exact sink recovery.

    The enclosing owner must retain this object until completion and cannot checkpoint
    an unfinished startup. The SSH continuation supplies retained ownership and rejects unfinished startup at its checkpoint barrier.
    Each call advances one phase; failed source publication must finish before another
    phase can create State or expose a ready shell.
    """

    def __init__(
        self,
        request: MacosSshReceiverStartupRequest,
        *,
        state: StateManager,
        dispatcher: EventDispatcher,
        host: HostContext,
    ) -> None:
        request.__post_init__()
        receiver = request.receiver
        session = state.get_session(receiver.logon_id)
        if (
            host.hostname != receiver.hostname
            or host.os_category != "macos"
            or state._pid_os.get(receiver.hostname) != "macos"
            or state.get_process_identity(receiver.hostname, receiver.pid) != receiver
            or dispatcher.state_manager is not state
            or session is None
            or session.session_kind != "ssh"
            or session.auth_protocol != "ssh"
            or session.transport_pid != receiver.pid
            or session.audit_origin is None
            or session.audit_origin.created_at != request.phase_times[6]
            or session.source_ready_time is None
            or session.source_ready_time < request.phase_times[-1]
            or session.network_close_time is None
            or session.network_close_time <= request.phase_times[-1]
            or session.effective_uid is None
            or session.effective_gid is None
        ):
            raise StateError("Mac receiver startup lost its exact host/session/timing owner")
        self._request = request
        self._state = state
        self._dispatcher = dispatcher
        # Detach mutable presentation context from the caller.
        self._host = replace(host, roles=list(host.roles))
        self._phase = 0
        self._receiver = receiver
        self._preauth: ProcessIdentity | None = None
        self._postauth: ProcessIdentity | None = None
        self._shell: ProcessIdentity | None = None
        self._pending: _PendingStartupPhase | None = None

    @property
    def completed_phases(self) -> int:
        """Return the number of phases with successful canonical/source publication."""
        return self._phase

    @property
    def result(self) -> MacosSshReceiverProcesses | None:
        """Expose ready process roles only after every phase has published."""
        if self._phase != len(self._request.phase_times):
            return None
        assert self._postauth is not None and self._shell is not None
        return MacosSshReceiverProcesses(self._receiver, self._postauth, self._shell)

    def advance(self) -> MacosSshReceiverProcesses | None:
        """Publish or recover one phase without repeating an already committed mutation."""
        if self.result is not None:
            return self.result
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
                        # The exact claim owns commit truth even if the sink or
                        # caller loses its return value after publication.
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
        after = pending.resulting_identity
        if self._phase in {0, 1, 6}:
            self._receiver = after
        elif self._phase in {2, 3, 4}:
            self._preauth = after
        elif self._phase in {7, 8}:
            self._postauth = after
        elif self._phase in {9, 10, 11}:
            self._shell = after
        self._phase += 1
        self._pending = None
        return self.result

    def _prepare_next(self) -> _PendingStartupPhase:
        request = self._request
        phase = self._phase
        timestamp = request.phase_times[phase]
        builder = self._state.begin_action_cohort_materialization()
        before = (
            self._receiver
            if phase in {0, 1, 2, 6, 7}
            else self._preauth
            if phase in {3, 4, 5}
            else self._postauth
            if phase in {8, 9}
            else self._shell
        )
        assert before is not None
        integrity = "System" if before.principal == "root" else "Medium"
        shell_exec = len(request.phase_times) - 1
        if phase in {0, 1, 3, shell_exec}:
            descriptor = (
                request.daemon
                if phase == 0
                else request.session_worker
                if phase == 1
                else request.authentication_worker
                if phase == 3
                else request.shell
            )
            after = builder.execute_process(
                before,
                image=descriptor.image_path,
                command_line=(
                    f"-{descriptor.executable}"
                    if phase == shell_exec
                    else descriptor.command_templates[0]
                ),
                executed_at=timestamp,
            )
            session_identity = None
            if phase == shell_exec:
                session_identity = self._state.get_session_identity(after.logon_id)
                if session_identity is None:
                    raise StateError("Mac receiver shell lost its live session")
                builder.bind_macos_ssh_session_shell(session_identity, shell=after)
            event = process_exec_occurrence(
                host=self._host,
                before=before,
                after=after,
                integrity_level=integrity,
                session=session_identity,
            )
            root = f"process-exec:{after.execution_id}"
        elif phase == 10:
            after = builder.change_posix_job_control(
                before, operation="setsid", changed_at=timestamp
            )
            event = process_job_control_occurrence(
                host=self._host,
                before=before,
                after=after,
                timestamp=timestamp,
                integrity_level=integrity,
            )
            root = f"process-job-control:{after.execution_id}:{timestamp.isoformat()}"
        elif phase in {2, 7, 9}:
            after = builder.fork_process(before, forked_at=timestamp).identity
            event = process_fork_occurrence(
                host=self._host,
                parent=before,
                child=after,
                integrity_level=integrity,
            )
            root = f"process-fork:{after.object_id}"
        elif phase == 5:
            after = before
            builder.terminate_process(before, end_time=timestamp)
            event = process_exit_occurrence(
                host=self._host,
                process=before,
                timestamp=timestamp,
                integrity_level=integrity,
            )
            root = f"process-exit:{before.object_id}"
        else:
            if phase == 4:
                after = builder.drop_macos_service_child_privileges(
                    before,
                    service_account=request.service_account,
                    dropped_at=timestamp,
                )
                kind = "process_service_drop"
            elif phase == 6:
                after = builder.bind_macos_process_audit_origin(before, bound_at=timestamp)
                kind = "process_audit_bind"
            else:
                after = builder.drop_macos_ssh_child_privileges(before, dropped_at=timestamp)
                kind = "process_privilege_drop"
            event = process_credential_occurrence(
                host=self._host,
                before=before,
                after=after,
                timestamp=timestamp,
                kind=kind,
                integrity_level="System" if phase == 6 else "Medium",
            )
            root = f"{kind}:{after.execution_id}"
        batch = self._prepare_publication(builder.seal(), event, root)
        return _PendingStartupPhase(batch, after)

    def _prepare_publication(
        self,
        plan: ActionCohortMaterializationPlan,
        event: OccurrenceBuilder,
        root: str,
    ) -> PreparedActionCohortBatch:
        dispatcher = self._dispatcher
        with dispatcher.source_timing_planner.prepared_planning() as timing:
            carrier = dispatcher.prepare_action_cohort_projection(
                event,
                source_timing_preparation=timing,
            )
        dispatch = dispatcher.bind_action_cohort_projection(carrier, state_plan=plan)
        effects = ExecutionEffectPlan(
            ActionAnchor("process_execution", root, source="ssh_receiver"), ()
        )
        return dispatcher.prepare_action_cohort_batch(
            root,
            plan,
            (dispatch,),
            (ExecutionEffectAuditCohortEntry(effects, effects.reconcile(())),),
            (),
            (),
            exact_projection=True,
        )
