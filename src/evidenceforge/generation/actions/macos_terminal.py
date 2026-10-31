# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""One retained native startup owner with explicit Apple Terminal and iTerm2 stages."""

from datetime import datetime

from evidenceforge.config.schemas import MacosTerminalStartupPolicy
from evidenceforge.events.content_identity import BinaryReleaseIdentity
from evidenceforge.events.contexts import HostContext
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.identity import ProcessIdentity, SessionIdentity
from evidenceforge.events.macos_spawn_io import MacosSpawnIO
from evidenceforge.events.responsibility import ProcessResponsibility, ResponsibleProcessReference
from evidenceforge.generation.actions.macos_finder import (
    MacosFinderStartup,
    PendingMacosStartupPhase,
)
from evidenceforge.generation.actions.posix_process import (
    process_credential_occurrence,
    process_exec_occurrence,
    process_fork_occurrence,
    process_job_control_occurrence,
)
from evidenceforge.generation.deployment_registry import DeploymentContentRegistry
from evidenceforge.generation.macos_execution_metadata import MacosExecutionMetadataProducer
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError


class MacosTerminalStartup(MacosFinderStartup):
    """Reuse the GUI prefix and exact phase publication for two measured topologies.

    Each fork, membership change, credential drop and exec finishes its retained
    transaction before the next phase. An app or server already running needs a
    separate reuse contract; it cannot silently become another fresh startup.
    """

    @staticmethod
    def stages(policy: MacosTerminalStartupPolicy) -> tuple[str, ...]:
        """Return semantic stages; executable names and launch inputs remain catalog facts."""
        prefix = ("fork", "setsid_absent", "server_exec") if policy.kind == "iterm2" else ()
        tail = ("shell_launcher_exec", "shell_exec") if policy.kind == "iterm2" else ("shell_exec",)
        return prefix + ("fork", "setsid", "login_exec", "fork", "drop") + tail

    def __init__(
        self,
        *,
        state: StateManager,
        dispatcher: EventDispatcher,
        metadata: MacosExecutionMetadataProducer,
        registry: DeploymentContentRegistry,
        host: HostContext,
        session: SessionIdentity,
        policy: MacosTerminalStartupPolicy,
        service_label: str,
        times: tuple[datetime, ...],
    ) -> None:
        steps = self.stages(policy)
        if (
            len(times) != 4 + len(steps)
            or not all(left < right for left, right in zip(times, times[1:], strict=False))
            or metadata.profile.terminal_responsibility != "terminal_application"
            or metadata.profile.finder_launch_execution != "xpcproxy_app_exec"
            or policy not in metadata.profile.terminal_startups
        ):
            raise StateError(
                "Native terminal startup requires its qualified topology and strict timeline"
            )
        paths: dict[str, str] = {}
        binaries: dict[str, BinaryReleaseIdentity] = {}
        for role, application_id in (
            ("app", policy.application_id),
            ("login", "macos-login"),
            ("shell", "macos-zsh"),
            ("server", policy.server_application_id),
            ("shell_launcher", policy.shell_launcher_application_id),
        ):
            if application_id is None:
                continue
            entry = registry.application_descriptor(application_id, "macos")
            if entry is None:
                raise StateError(
                    f"Native terminal startup requires installed catalog entry {application_id}"
                )
            path = entry.image_path.replace("{username}", session.principal)
            binary = registry.resolve_binary(
                host.hostname, path, "macos", principal=session.principal
            )
            if (
                type(binary) is not BinaryReleaseIdentity
                or binary.mach_o_image is None
                or binary.code_signature is None
                or metadata.image_security(binary) is None
            ):
                raise StateError(
                    f"Native terminal startup requires qualified installed {role} metadata"
                )
            paths[role], binaries[role] = path, binary
        if policy.kind == "iterm2" and (
            binaries["app"].key.product_id != "iterm2"
            or binaries["app"].key.version != "3.7.6"
            or any(
                binaries[role].release_id != binaries["app"].release_id
                for role in ("server", "shell_launcher")
            )
        ):
            raise StateError("Native iTerm2 startup requires the qualified complete 3.7.6 release")
        if policy.kind == "apple" and (
            binaries["app"].key.product_id != "apple-macos"
            or binaries["app"].key.artifact_name != "Terminal"
        ):
            raise StateError(
                "Native Apple Terminal startup requires its exact installed Apple image"
            )
        metadata.login_setuid_owner(host.hostname, session.principal, binaries["login"], times[-1])
        launch = metadata.launch(
            host.hostname,
            session.principal,
            at=times[-1],
            requested_path=paths["shell"],
            binary=binaries["shell"],
            kind="user",
        )
        environment = launch.environment + policy.shell_environment
        keys = tuple(value.split("=", 1)[0] for value in environment)
        if len(keys) != len(set(keys)):
            raise StateError("Native terminal startup environment repeats a launch variable")
        launcher = registry.resolve_binary(
            host.hostname, "/usr/libexec/xpcproxy", "macos", principal="root"
        )
        parent = state.get_process_identity(host.hostname, 1)
        if type(launcher) is not BinaryReleaseIdentity or parent is None:
            raise StateError(
                "Native terminal startup requires its installed xpcproxy and boot parent"
            )
        super().__init__(
            state=state,
            dispatcher=dispatcher,
            metadata=metadata,
            host=host,
            parent=parent,
            session=session,
            launcher=launcher,
            app=binaries["app"],
            arguments=(paths["app"],),
            service_label=service_label,
            times=(times[0], times[1], times[2], times[3]),
            lifecycle_group_id=f"mac-terminal-app:{host.hostname}:{session.logon_id}:{times[0].isoformat()}",
            concurrency_group_id="",
            storyline=False,
        )
        self._steps, self._timeline = steps, times
        self._policy, self._paths, self._binaries = policy, paths, binaries
        self._shell_environment = environment
        self._home = launch.directory.native_path
        self.application: ProcessIdentity | None = None

    @property
    def complete(self) -> bool:
        """Expose the initial shell only after every native stage reaches its sinks."""
        return self._phase == 3 + len(self._steps)

    def advance(self) -> None:
        """Reuse exact retained publication, recording the app before advancing its children."""
        super().advance()
        if self._phase == 3:
            self.application = self.process

    def _prepare_next(self) -> PendingMacosStartupPhase:
        if self._phase < 3:
            return super()._prepare_next()
        step = self._steps[self._phase - 3]
        at = self._timeline[self._phase + 1]
        before, app = self.process, self.application
        assert before is not None and app is not None
        builder = self._state.begin_action_cohort_materialization()
        birth = None
        if step == "fork":
            responsibility = (
                ProcessResponsibility(
                    ResponsibleProcessReference(
                        app.hostname, app.object_id, app.pid, app.started_at
                    )
                )
                if before.object_id == app.object_id
                else None
            )
            birth = self._metadata.plan_fork(
                builder, self._state, before, at=at, responsibility=responsibility
            )
            after = birth.identity
            event = process_fork_occurrence(
                host=self._host,
                parent=before,
                child=after,
                integrity_level="Medium",
            )
            root = f"process-fork:{after.object_id}"
        elif step in {"setsid", "setsid_absent"}:
            after = builder.change_posix_job_control(
                before,
                operation="setsid",
                changed_at=at,
                macos_terminal=self._metadata.profile.terminal if step == "setsid" else "absent",
            )
            event = process_job_control_occurrence(
                host=self._host,
                before=before,
                after=after,
                timestamp=at,
                integrity_level="Medium",
            )
            root = f"process-job-control:{after.execution_id}:{at.isoformat()}"
        elif step == "drop":
            after = builder.drop_macos_login_child_privileges(before, dropped_at=at)
            event = process_credential_occurrence(
                host=self._host,
                before=before,
                after=after,
                timestamp=at,
                kind="process_privilege_drop",
                integrity_level="Medium",
            )
            root = f"process_privilege_drop:{after.execution_id}"
        else:
            role = step.removesuffix("_exec")
            binary, path = self._binaries[role], self._paths[role]
            spawn_io = None
            environment = self._shell_environment
            directory = self._metadata.directory(self._host.hostname, self._home, at)
            if role == "server":
                assert self._policy.server_socket_path is not None
                arguments = (path, self._policy.server_socket_path.format(home=self._home))
                spawn_io = MacosSpawnIO("server_channels", self._metadata.profile.first_pipe_id)
                environment = before.environment
                directory = self._metadata.directory(self._host.hostname, "/", at)
            elif role == "login":
                arguments = (
                    ("login", "-pf", before.principal)
                    if self._policy.kind == "apple"
                    else (
                        path,
                        "-fpl",
                        before.principal,
                        self._paths["shell_launcher"],
                        "--launch_shell",
                    )
                )
                spawn_io = (
                    MacosSpawnIO("login_pipes", self._metadata.profile.first_pipe_id)
                    if self._policy.kind == "apple"
                    else MacosSpawnIO("login_standard")
                )
            elif role == "shell_launcher":
                arguments, spawn_io = (
                    ("ShellLauncher", "--launch_shell"),
                    MacosSpawnIO("standard_only"),
                )
            else:
                arguments = ("-zsh",)
                spawn_io = MacosSpawnIO("standard_only")
            after = self._metadata.plan_exec(
                builder,
                self._state,
                before,
                at=at,
                image=path,
                requested_path=path,
                arguments=arguments,
                binary=binary,
                environment=environment,
                execution_directory=directory,
                spawn_io=spawn_io,
            ).process
            event = process_exec_occurrence(
                host=self._host,
                before=before,
                after=after,
                integrity_level="Medium",
            )
            event.process.binary_identity = binary
            root = f"process-exec:{after.execution_id}"
        plan = builder.seal()
        events = (event,)
        return PendingMacosStartupPhase(
            self._prepare_publication(plan, events, root), after, events, birth
        )
