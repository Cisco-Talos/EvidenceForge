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

"""Windows remote administration action bundles."""

from __future__ import annotations

import ntpath
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from random import Random
from typing import Any, Protocol

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.content_identity import RuntimeServiceDeploymentIdentity
from evidenceforge.events.contexts import (
    AuthContext,
    FileContext,
    HostContext,
    ProcessContext,
    ServiceContext,
)
from evidenceforge.events.contracts import (
    EffectOccurrenceKind,
    EffectOccurrenceProvenance,
    OccurrenceRole,
)
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.lifecycle import ActionLifecycleContext
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.actions.command_effects import (
    ChildProcessEffectIntent,
    EffectActorRef,
    EffectExecutionOutcome,
    EffectOutcomeStatus,
    EffectRequirement,
    ExecutionEffectAuditCounter,
    ExecutionEffectNode,
    ExecutionEffectPlan,
    ExecutionEffectPlanError,
    ExecutionEffectPlanErrorCode,
    FileEffectAction,
    FileEffectIntent,
    NetworkEffectIntent,
    ServiceEffectAction,
    ServiceEffectIntent,
)
from evidenceforge.generation.activity.helpers import _get_os_category
from evidenceforge.generation.baseline_timing import BaselineTimingPlanner
from evidenceforge.generation.lifecycle_production_adapters import (
    ServiceLifecyclePublicationPlan,
    installed_service_publication_plan,
    lifecycle_production_adapter_for,
)
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.timing import TimingRuntime
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import System, User
from evidenceforge.utils.rng import _get_rng, _stable_seed
from evidenceforge.utils.time import ensure_utc

_LINUX_LOCAL_ACCOUNTS = {
    "apache",
    "mysql",
    "nginx",
    "postgres",
    "root",
    "sshd",
    "www-data",
}


@dataclass(frozen=True, slots=True)
class ExplicitCredentialUseRequest:
    """Intent for one Windows explicit-credential use event."""

    user: User
    system: System
    time: datetime
    target_username: str
    target_server: str
    process_name: str
    process_pid: int | None
    source_ip: str = ""
    source_port: int = 0
    source: str = "activity_generator"

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        seed = _stable_seed(
            "action_bundle:windows_explicit_credentials:"
            f"{self.user.username}:{self.system.hostname}:{self.time.isoformat()}:"
            f"{self.target_username}:{self.target_server}:{self.process_name}:"
            f"{self.process_pid or ''}:{self.source_ip}:{self.source_port}:{self.source}"
        )
        return f"windows-explicit-credentials-{seed:016x}"


@dataclass(frozen=True, slots=True)
class WindowsServiceInstallRequest:
    """Intent for one modeled Windows remote service installation."""

    user: User
    system: System
    time: datetime
    service_name: str
    service_file_name: str
    service_type: str = "0x10"
    service_start_type: str = "3"
    service_account: str = "LocalSystem"
    lifecycle_group_id: str = ""
    source: str = "activity_generator"
    effect_plan: ExecutionEffectPlan | None = field(default=None, compare=False, repr=False)

    @property
    def stable_id(self) -> str:
        """Return a deterministic intent identifier for durable references."""

        seed = _stable_seed(
            "action_bundle:windows_service_install:"
            f"{self.user.username}:{self.system.hostname}:{self.time.isoformat()}:"
            f"{self.service_name}:{self.service_file_name}:{self.service_type}:"
            f"{self.service_start_type}:{self.service_account}:{self.source}"
        )
        return f"windows-service-install-{seed:016x}"

    @property
    def effective_lifecycle_group_id(self) -> str:
        """Return the shared lifecycle owner for all remote-service phases."""

        return self.lifecycle_group_id or self.stable_id


@dataclass(frozen=True, slots=True)
class _RemoteServiceControlFlowPlan:
    """One exact canonical transport occurrence in a service-control sub-plan."""

    destination_port: int
    service: str
    timestamp: datetime


@dataclass(frozen=True, slots=True)
class _RemoteServiceControlPlan:
    """Immutable SMB/RPC execution plan shared by preflight and realization."""

    source_system: System | None
    flows: tuple[_RemoteServiceControlFlowPlan, ...] = ()
    base_source_port: int = 0

    @property
    def canonical_occurrence_count(self) -> int:
        """Return the exact number of connection actions this plan will execute."""

        return len(self.flows)


@dataclass(frozen=True, slots=True)
class _ServicePayloadPlan:
    """Deterministic file-effect classification for one service image path."""

    path: str
    emit_create: bool
    suppression_reason: str = ""


@dataclass(frozen=True, slots=True)
class _WindowsServiceInstallExecutionPlan:
    """Validated effect graph and its exact allocation-free execution inputs."""

    effects: ExecutionEffectPlan
    remote_control: _RemoteServiceControlPlan
    payload: _ServicePayloadPlan
    lifecycle_publication: ServiceLifecyclePublicationPlan | None = None


def _remote_service_ephemeral_port(rng: Random, os_category: str) -> int:
    """Use the generator's compatibility sampler while it owns legacy port policy."""

    # Imported lazily because ActivityGenerator imports this action module.  Keeping
    # this compatibility call preserves the existing patched boundary and RNG stream
    # until ephemeral-port policy moves into a shared planner in a later migration.
    from evidenceforge.generation.activity.generator import _ephemeral_port

    return _ephemeral_port(rng, os_category)


def _validate_exact_effect_plan(
    candidate: ExecutionEffectPlan,
    expected: ExecutionEffectPlan,
    *,
    action_label: str,
) -> None:
    """Reject caller-supplied node or cardinality drift before side effects."""

    if candidate.anchor != expected.anchor:
        raise ExecutionEffectPlanError(
            ExecutionEffectPlanErrorCode.INVALID_PLAN,
            f"{action_label} effect_plan anchor does not match the request anchor",
        )
    candidate_by_id = {node.node_id: node for node in candidate.nodes}
    expected_by_id = {node.node_id: node for node in expected.nodes}
    missing = expected_by_id.keys() - candidate_by_id.keys()
    unexpected = candidate_by_id.keys() - expected_by_id.keys()
    drifted = {
        node_id
        for node_id in expected_by_id.keys() & candidate_by_id.keys()
        if expected_by_id[node_id] != candidate_by_id[node_id]
    }
    if not (missing or unexpected or drifted):
        return

    def _instance_keys(
        node_ids: set[str],
        nodes: dict[str, ExecutionEffectNode],
    ) -> str:
        rendered = sorted(nodes[node_id].instance_key for node_id in node_ids)[:6]
        return ", ".join(rendered)

    details = []
    if missing:
        details.append(f"missing={_instance_keys(missing, expected_by_id)}")
    if unexpected:
        details.append(f"unexpected={_instance_keys(unexpected, candidate_by_id)}")
    if drifted:
        details.append(f"drifted={_instance_keys(drifted, expected_by_id)}")
    raise ExecutionEffectPlanError(
        ExecutionEffectPlanErrorCode.INVALID_PLAN,
        f"{action_label} effect_plan does not match the canonical plan: " + "; ".join(details),
    )


class WindowsRemoteAdminExecutor(Protocol):
    """Adapter protocol implemented by the current activity generator."""

    dispatcher: EventDispatcher
    state_manager: StateManager
    timing_runtime: TimingRuntime

    def _coerce_windows_explicit_credentials_subject(
        self,
        user: User,
        system: System,
        target_username: str,
    ) -> User:
        """Return the source-native 4648 subject user."""
        ...

    def _ensure_explicit_credentials_subject_logon(
        self,
        user: User,
        system: System,
        time: datetime,
    ) -> str:
        """Return a visible subject logon ID for 4648."""
        ...

    def _account_subject_fields(
        self,
        username: str,
        system: System,
        logon_id: str = "",
    ) -> dict[str, str]:
        """Return Windows subject account fields."""
        ...

    def _get_system_pid(self, hostname: str, process: str, default: int) -> int:
        """Return a stable seeded system process PID."""
        ...

    def _get_sid(self, username: str) -> str:
        """Return a SID for a username."""
        ...

    def _build_host_context(self, system: System) -> HostContext:
        """Build canonical host context for a scenario system."""
        ...

    def generate_process(
        self,
        user: User,
        system: System,
        time: datetime,
        logon_id: str,
        process_name: str,
        command_line: str,
        **kwargs: Any,
    ) -> int:
        """Generate canonical process-create evidence."""
        ...

    def generate_process_termination(
        self,
        user: User,
        system: System,
        time: datetime,
        pid: int,
        process_name: str,
        logon_id: str,
        **kwargs: Any,
    ) -> None:
        """Generate canonical process-termination evidence."""
        ...

    def generate_logoff(
        self,
        user: User,
        system: System,
        time: datetime,
        logon_id: str,
        logon_type: int = 2,
        **kwargs: Any,
    ) -> None:
        """Generate canonical session-close evidence."""
        ...

    def _clamp_after_visible_process_create(
        self,
        system: System,
        pid: int,
        time: datetime,
        relationship_name: str,
    ) -> datetime:
        """Clamp source-visible activity after process creation."""
        ...

    def _explicit_credentials_source_ip(
        self,
        system: System,
        target_server: str,
        source_ip: str = "",
    ) -> str:
        """Return source-native network endpoint metadata for 4648."""
        ...

    def _explicit_credentials_target_domain(
        self,
        target_username: str,
        target_server: str,
        source_system: System,
    ) -> str:
        """Return source-native 4648 target domain."""
        ...

    def _emit_new_credentials_logon(
        self,
        *,
        user: User,
        system: System,
        time: datetime,
        caller_logon_id: str,
        outbound_username: str,
        outbound_domain: str,
        lifecycle_group_id: str,
    ) -> str:
        """Emit the Type 9 token clone owned by runas /netonly."""
        ...

    def _emit_remote_service_control_network_evidence(
        self,
        user: User,
        target_system: System,
        time: datetime,
    ) -> None:
        """Emit SMB/RPC service-control transport evidence."""
        ...

    def generate_connection(self, **kwargs: Any) -> str:
        """Execute one canonical network-connection action bundle."""
        ...

    def _get_user_logon_id(
        self,
        username: str,
        hostname: str,
        at_time: datetime | None = None,
    ) -> str:
        """Return a user's active logon ID on a host."""
        ...


class ExplicitCredentialUseActionBundle:
    """Expand one explicit-credential use into coordinated source evidence."""

    def __init__(
        self,
        executor: WindowsRemoteAdminExecutor,
        request: ExplicitCredentialUseRequest,
    ) -> None:
        self._executor = executor
        self._request = request

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="windows_explicit_credentials",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> None:
        """Emit Windows Security 4648 evidence for explicit credential use."""

        target_account = self._request.target_username.split("\\")[-1].split("@", 1)[0].lower()
        if _get_os_category(self._request.system.os) == "windows" and (
            target_account in _LINUX_LOCAL_ACCOUNTS
        ):
            return

        subject_user = self._executor._coerce_windows_explicit_credentials_subject(
            self._request.user,
            self._request.system,
            self._request.target_username,
        )
        reporting_pid = self._executor._get_system_pid(
            self._request.system.hostname,
            "lsass",
            0x2E0,
        )
        subject_logon_id = self._executor._ensure_explicit_credentials_subject_logon(
            subject_user,
            self._request.system,
            self._request.time,
        )
        subject = self._executor._account_subject_fields(
            subject_user.username,
            self._request.system,
            subject_logon_id,
        )
        process_pid, materialized_caller = self._resolve_process_pid(
            subject_user,
            subject_logon_id,
        )
        event_time = self._request.time
        if process_pid > 0:
            event_time = self._executor._clamp_after_visible_process_create(
                self._request.system,
                process_pid,
                event_time,
                "source.windows_explicit_credentials_after_process_create",
            )
        target_domain = self._executor._explicit_credentials_target_domain(
            self._request.target_username,
            self._request.target_server,
            self._request.system,
        )
        network_source_ip = self._executor._explicit_credentials_source_ip(
            self._request.system,
            self._request.target_server,
            self._request.source_ip,
        )
        network_source_port = 0
        if self._request.source_port > 0:
            network_source_port = (
                self._request.source_port
                if self._request.source_ip.strip().removeprefix("::ffff:") == network_source_ip
                else 0
            )
        event = OccurrenceBuilder(
            timestamp=event_time,
            event_type="explicit_credentials",
            dst_host=self._executor._build_host_context(self._request.system),
            auth=AuthContext(
                username=self._request.target_username,
                user_sid=self._executor._get_sid(self._request.target_username),
                target_domain=target_domain,
                subject_sid=subject["sid"],
                subject_username=subject["username"],
                subject_domain=subject["domain"],
                subject_logon_id=subject["logon_id"],
                logon_guid="{00000000-0000-0000-0000-000000000000}",
                reporting_pid=reporting_pid,
                process_pid=process_pid,
                target_server=self._request.target_server,
                process_name=self._request.process_name,
                source_ip=network_source_ip or "-",
                source_port=network_source_port,
            ),
        )
        self._executor.dispatcher.dispatch_builder(event)
        running_process = self._executor.state_manager.get_process(
            self._request.system.hostname,
            process_pid,
        )
        is_runas_netonly = (
            ntpath.basename(self._request.process_name).casefold() == "runas.exe"
            and running_process is not None
            and "/netonly" in running_process.command_line.casefold()
        )
        new_credentials_logon_id = ""
        if is_runas_netonly:
            new_credentials_logon_id = self._executor._emit_new_credentials_logon(
                user=subject_user,
                system=self._request.system,
                time=event_time + timedelta(milliseconds=1),
                caller_logon_id=subject_logon_id,
                outbound_username=self._request.target_username,
                outbound_domain=target_domain,
                lifecycle_group_id=self._request.stable_id,
            )
        if materialized_caller:
            lifetime_ms = 1800 + (_stable_seed(f"{self._request.stable_id}:caller_lifetime") % 5201)
            termination_time = event_time + timedelta(milliseconds=lifetime_ms)
            self._executor.generate_process_termination(
                subject_user,
                self._request.system,
                termination_time,
                process_pid,
                self._request.process_name,
                subject_logon_id,
            )
            if new_credentials_logon_id:
                self._executor.generate_logoff(
                    subject_user,
                    self._request.system,
                    termination_time + timedelta(milliseconds=1),
                    new_credentials_logon_id,
                    logon_type=9,
                )

    def _resolve_process_pid(
        self,
        subject_user: User,
        subject_logon_id: str,
    ) -> tuple[int, bool]:
        """Return the caller PID and whether this bundle materialized it."""

        process_pid = self._request.process_pid or 0
        materialized_caller = False
        if process_pid > 0 and self._request.process_name:
            running_process = self._executor.state_manager.get_process(
                self._request.system.hostname,
                process_pid,
            )
            running_image = running_process.image if running_process is not None else ""
            if (
                running_image
                and ntpath.basename(running_image).lower()
                != ntpath.basename(self._request.process_name).lower()
            ):
                process_pid = 0
        if process_pid <= 0 and self._request.process_name:
            process_time = self._request.time - timedelta(seconds=1)
            scenario_start = getattr(self._executor, "_scenario_start_time", None)
            if scenario_start is not None and ensure_utc(process_time) < ensure_utc(scenario_start):
                process_time = self._request.time - timedelta(milliseconds=500)
            process_pid = self._executor.generate_process(
                subject_user,
                self._request.system,
                process_time,
                subject_logon_id,
                self._request.process_name,
                self._materialized_caller_command_line(),
            )
            materialized_caller = True
        return process_pid, materialized_caller

    def _materialized_caller_command_line(self) -> str:
        """Return action-native command semantics for a generated caller process."""

        process_name = self._request.process_name
        basename = ntpath.basename(process_name)
        basename_lower = basename.lower()
        target_username = self._request.target_username
        target_server = self._request.target_server or self._request.system.hostname
        if basename_lower == "runas.exe":
            target = target_server.split(".", 1)[0]
            return (
                f'{basename} /netonly /user:{target_username} "cmd.exe /c dir \\\\{target}\\ADMIN$"'
            )
        if basename_lower == "mmc.exe":
            return f"{basename} compmgmt.msc /computer={target_server}"
        if basename_lower in {"powershell.exe", "pwsh.exe"}:
            return (
                f'{basename} -NoProfile -Command "Get-CimInstance Win32_OperatingSystem '
                f"-ComputerName '{target_server}' -Credential '{target_username}'\""
            )
        return f'{basename} "{target_server}"'


class WindowsServiceInstallActionBundle:
    """Expand one Windows service install into remote-admin evidence."""

    _NETWORK_NODE_KEY = "service-control-network"
    _PAYLOAD_NODE_KEY = "service-payload-file-create"
    _SERVICE_NODE_KEY = "service-install"
    _PROCESS_START_NODE_KEY = "service-process-start"
    _PROCESS_CLOSE_NODE_KEY = "service-process-close"

    def __init__(
        self,
        executor: WindowsRemoteAdminExecutor,
        request: WindowsServiceInstallRequest,
    ) -> None:
        self._executor = executor
        self._request = request

    def _timing_planner(self) -> BaselineTimingPlanner:
        """Return the engine planner or one stateless direct-test adapter."""

        runtime = getattr(self._executor, "timing_runtime", None)
        return BaselineTimingPlanner(
            runtime
            if isinstance(runtime, TimingRuntime)
            else TimingRuntime.compatibility_default(),
            source="windows-remote-admin",
        )

    @property
    def anchor(self) -> ActionAnchor:
        """Return the stable action anchor."""

        return ActionAnchor(
            family="windows_service_install",
            stable_id=self._request.stable_id,
            source=self._request.source,
        )

    def execute(self) -> None:
        """Execute a validated service-install plan through semantic action bundles."""

        execution_plan = self._preflight_execution_plan()
        lifecycle_publication = execution_plan.lifecycle_publication
        if lifecycle_publication is None:
            self._execute_plan(execution_plan)
            return
        adapter = lifecycle_production_adapter_for(self._executor)
        if adapter is None:
            raise StateError("Windows service lifecycle authority disappeared after preflight")
        token = adapter.prepare_service_publication(lifecycle_publication)
        with adapter.claimed_service_publication(token) as claimed:
            self._execute_plan(execution_plan)
            claimed.commit_no_fail()

    def _execute_plan(self, execution_plan: _WindowsServiceInstallExecutionPlan) -> None:
        """Realize one fully prepared plan inside an optional service claim."""

        nodes_by_key = {node.instance_key: node for node in execution_plan.effects.ordered_nodes}
        outcomes: list[EffectExecutionOutcome] = []

        network_node = nodes_by_key[self._NETWORK_NODE_KEY]
        network_count = self._execute_remote_service_control_plan(execution_plan.remote_control)
        if execution_plan.remote_control.canonical_occurrence_count:
            outcomes.append(
                EffectExecutionOutcome(
                    node_id=network_node.node_id,
                    status=EffectOutcomeStatus.REALIZED,
                    completed_at=max(
                        flow.timestamp for flow in execution_plan.remote_control.flows
                    ),
                    canonical_occurrence_count=network_count,
                )
            )
        else:
            outcomes.append(
                EffectExecutionOutcome(
                    node_id=network_node.node_id,
                    status=EffectOutcomeStatus.SUPPRESSED,
                    reason="no distinct remote Windows source is available",
                )
            )

        payload_node = nodes_by_key[self._PAYLOAD_NODE_KEY]
        payload_time = self._emit_payload_file_create(execution_plan.payload, payload_node)
        if payload_time is not None:
            outcomes.append(
                EffectExecutionOutcome(
                    node_id=payload_node.node_id,
                    status=EffectOutcomeStatus.REALIZED,
                    completed_at=payload_time,
                    canonical_occurrence_count=1,
                )
            )
        else:
            outcomes.append(
                EffectExecutionOutcome(
                    node_id=payload_node.node_id,
                    status=EffectOutcomeStatus.SUPPRESSED,
                    reason=execution_plan.payload.suppression_reason,
                )
            )

        lifecycle_start = payload_time or self._request.time
        reporting_pid = self._executor._get_system_pid(
            self._request.system.hostname,
            "lsass",
            0x2E0,
        )
        host = self._executor._build_host_context(self._request.system)
        event = OccurrenceBuilder(
            timestamp=self._request.time,
            event_type="service_installed",
            src_host=host,
            auth=AuthContext(
                username=self._request.user.username,
                subject_sid=self._executor._get_sid(self._request.user.username),
                subject_username=self._request.user.username,
                subject_domain=host.netbios_domain,
                subject_logon_id=self._executor._get_user_logon_id(
                    self._request.user.username,
                    self._request.system.hostname,
                    self._request.time,
                ),
                reporting_pid=reporting_pid,
            ),
            service=ServiceContext(
                service_name=self._request.service_name,
                service_file_name=self._request.service_file_name,
                service_type=self._request.service_type,
                service_start_type=self._request.service_start_type,
                service_account=self._request.service_account,
            ),
            lifecycle=ActionLifecycleContext(
                group_id=self._request.effective_lifecycle_group_id,
                canonical_start=lifecycle_start,
                phase="dependent" if payload_time is not None else "start",
            ),
        )
        self._executor.dispatcher.dispatch_builder(event)

        service_node = nodes_by_key[self._SERVICE_NODE_KEY]
        outcomes.append(
            EffectExecutionOutcome(
                node_id=service_node.node_id,
                status=EffectOutcomeStatus.REALIZED,
                completed_at=self._request.time,
                canonical_occurrence_count=1,
            )
        )
        if self._request.lifecycle_group_id:
            for instance_key in (
                self._PROCESS_START_NODE_KEY,
                self._PROCESS_CLOSE_NODE_KEY,
            ):
                process_node = nodes_by_key[instance_key]
                outcomes.append(
                    EffectExecutionOutcome(
                        node_id=process_node.node_id,
                        status=EffectOutcomeStatus.LINKED,
                        child_action_id=self._request.lifecycle_group_id,
                        completed_at=self._request.time,
                        canonical_occurrence_count=1,
                    )
                )

        reconciliation = execution_plan.effects.reconcile(tuple(outcomes))
        audit_counter = getattr(self._executor, "_execution_effect_audit", None)
        if isinstance(audit_counter, ExecutionEffectAuditCounter):
            audit_counter.record(reconciliation)
        reconciliation.require_complete()

    def plan_effects(self) -> ExecutionEffectPlan:
        """Return the allocation-free canonical effect graph for this request."""

        remote_source = self._resolve_remote_service_control_source()
        payload = self._plan_payload_file_effect()
        return self._build_effect_plan(remote_source=remote_source, payload=payload)

    def _preflight_execution_plan(self) -> _WindowsServiceInstallExecutionPlan:
        """Validate the exact graph before RNG, transport, PID, or state allocation."""

        remote_source = self._resolve_remote_service_control_source()
        payload = self._plan_payload_file_effect()
        expected = self._build_effect_plan(remote_source=remote_source, payload=payload)
        candidate = self._request.effect_plan
        if candidate is None:
            candidate = expected
        elif not isinstance(candidate, ExecutionEffectPlan):
            raise ExecutionEffectPlanError(
                ExecutionEffectPlanErrorCode.INVALID_PLAN,
                "Windows service-install effect_plan must be an ExecutionEffectPlan",
            )
        else:
            _validate_exact_effect_plan(
                candidate,
                expected,
                action_label="Windows service-install",
            )

        lifecycle_publication: ServiceLifecyclePublicationPlan | None = None
        lifecycle_adapter = lifecycle_production_adapter_for(self._executor)
        if lifecycle_adapter is not None:
            get_boot_time = getattr(self._executor.state_manager, "get_boot_time", None)
            boot_time = (
                get_boot_time(self._request.system.hostname) if callable(get_boot_time) else None
            )
            if not isinstance(boot_time, datetime):
                boot_time = self._request.time
            deployment_identity = self._runtime_service_deployment_identity()
            lifecycle_publication = installed_service_publication_plan(
                hostname=self._request.system.hostname,
                service_name=self._request.service_name,
                deployment_service_id=deployment_identity.deployment_service_id,
                boot_time=boot_time,
                started_at=self._request.time,
                action_id=self._request.stable_id,
                deployment_identity=deployment_identity,
            )

        remote_control = self._materialize_remote_service_control_plan(remote_source)
        return _WindowsServiceInstallExecutionPlan(
            effects=candidate,
            remote_control=remote_control,
            payload=payload,
            lifecycle_publication=lifecycle_publication,
        )

    def _runtime_service_deployment_identity(self) -> RuntimeServiceDeploymentIdentity:
        """Resolve the exact runtime-only deployment identity for this install."""

        registry = getattr(self._executor.dispatcher, "deployment_registry", None)
        if registry is None:
            return RuntimeServiceDeploymentIdentity(
                hostname=self._request.system.hostname,
                canonical_name=self._request.service_name,
                action_id=self._request.stable_id,
            )
        resolver = getattr(registry, "runtime_service_deployment_identity", None)
        if not callable(resolver):
            raise StateError("Deployment registry cannot resolve runtime service identity")
        identity = resolver(
            hostname=self._request.system.hostname,
            canonical_name=self._request.service_name,
            action_id=self._request.stable_id,
        )
        if not isinstance(identity, RuntimeServiceDeploymentIdentity):
            raise StateError("Deployment registry returned an invalid runtime service identity")
        return identity

    def _build_effect_plan(
        self,
        *,
        remote_source: System | None,
        payload: _ServicePayloadPlan,
    ) -> ExecutionEffectPlan:
        """Build the canonical service-control, payload, service, and process DAG."""

        network_node = ExecutionEffectNode.create(
            self.anchor,
            NetworkEffectIntent(
                destination=self._request.system.ip,
                destination_port=445,
                protocol="tcp",
                service="windows_service_control_smb_rpc",
                occurrence_cardinality=2,
            ),
            role=OccurrenceRole.PREREQUISITE,
            requirement=(
                EffectRequirement.REQUIRED
                if remote_source is not None
                else EffectRequirement.OPTIONAL
            ),
            actor=EffectActorRef.session(),
            instance_key=self._NETWORK_NODE_KEY,
        )
        payload_node = ExecutionEffectNode.create(
            self.anchor,
            FileEffectIntent(
                action=FileEffectAction.CREATE,
                path=payload.path,
                occurrence_cardinality=1,
            ),
            role=OccurrenceRole.PREREQUISITE,
            requirement=(
                EffectRequirement.REQUIRED if payload.emit_create else EffectRequirement.OPTIONAL
            ),
            actor=EffectActorRef.system(),
            instance_key=self._PAYLOAD_NODE_KEY,
        )
        service_node = ExecutionEffectNode.create(
            self.anchor,
            ServiceEffectIntent(
                action=ServiceEffectAction.INSTALL,
                service_name=self._request.service_name,
                image=payload.path,
                occurrence_cardinality=1,
            ),
            role=OccurrenceRole.DEPENDENT,
            requirement=EffectRequirement.REQUIRED,
            actor=EffectActorRef.system(),
            depends_on=(network_node.node_id, payload_node.node_id),
            instance_key=self._SERVICE_NODE_KEY,
        )
        nodes = [network_node, payload_node, service_node]
        if self._request.lifecycle_group_id:
            process_intent = ChildProcessEffectIntent(
                image=payload.path,
                command_line=payload.path,
                occurrence_cardinality=1,
            )
            process_start_node = ExecutionEffectNode.create(
                self.anchor,
                process_intent,
                role=OccurrenceRole.DEPENDENT,
                requirement=EffectRequirement.EXTERNALLY_OWNED,
                actor=EffectActorRef.system(),
                depends_on=(service_node.node_id,),
                instance_key=self._PROCESS_START_NODE_KEY,
            )
            process_close_node = ExecutionEffectNode.create(
                self.anchor,
                process_intent,
                role=OccurrenceRole.CLOSURE,
                requirement=EffectRequirement.EXTERNALLY_OWNED,
                actor=EffectActorRef.system(),
                depends_on=(process_start_node.node_id,),
                instance_key=self._PROCESS_CLOSE_NODE_KEY,
            )
            nodes.extend((process_start_node, process_close_node))
        return ExecutionEffectPlan(anchor=self.anchor, nodes=tuple(nodes))

    def _resolve_remote_service_control_source(self) -> System | None:
        """Resolve the exact existing remote source used by service-control execution."""

        if _get_os_category(self._request.system.os) != "windows":
            return None
        world_model = getattr(self._executor, "_world_model", None)
        source_system = None
        primary_system_name = getattr(self._request.user, "primary_system", None)
        if world_model is not None and primary_system_name:
            source_system = world_model.systems_by_hostname.get(primary_system_name)
        if source_system is None:
            sessions = [
                session
                for session in self._executor.state_manager.get_sessions_for_user(
                    self._request.user.username
                )
                if session.system != self._request.system.hostname
            ]
            if sessions and world_model is not None:
                newest = max(sessions, key=lambda session: session.start_time)
                source_system = world_model.systems_by_hostname.get(newest.system)
        if source_system is None or source_system.ip == self._request.system.ip:
            return None
        return source_system

    def _materialize_remote_service_control_plan(
        self,
        source_system: System | None,
    ) -> _RemoteServiceControlPlan:
        """Sample the exact immutable SMB/RPC plan before transport allocation."""

        if source_system is None:
            return _RemoteServiceControlPlan(source_system=None)
        rng = _get_rng()
        timing = self._timing_planner()
        timing_id = (
            f"{source_system.hostname}:{self._request.system.hostname}:"
            f"{self._request.time.isoformat()}"
        )
        flows = (
            _RemoteServiceControlFlowPlan(
                destination_port=445,
                service="smb",
                timestamp=self._request.time
                - timedelta(
                    seconds=timing.right_skew_seconds(
                        relationship_key="windows_remote_admin.smb_transport_lead",
                        stable_id=timing_id,
                        minimum=1.1,
                        median=1.3,
                        maximum=1.8,
                        host=source_system.hostname,
                        sample_key="lead",
                    )
                ),
            ),
            _RemoteServiceControlFlowPlan(
                destination_port=135,
                service="dce_rpc",
                timestamp=self._request.time
                - timedelta(
                    seconds=timing.right_skew_seconds(
                        relationship_key="windows_remote_admin.rpc_transport_lead",
                        stable_id=timing_id,
                        minimum=0.35,
                        median=0.5,
                        maximum=0.9,
                        host=source_system.hostname,
                        sample_key="lead",
                    )
                ),
            ),
        )
        source_os = _get_os_category(source_system.os)
        max_ephemeral_port = 60999 if source_os == "linux" else 65535
        base_source_port = min(
            _remote_service_ephemeral_port(rng, source_os),
            max_ephemeral_port - len(flows) + 1,
        )
        return _RemoteServiceControlPlan(
            source_system=source_system,
            flows=flows,
            base_source_port=base_source_port,
        )

    def _execute_remote_service_control_plan(
        self,
        plan: _RemoteServiceControlPlan,
    ) -> int:
        """Execute the exact preflight transport plan through connection bundles."""

        if plan.source_system is None:
            return 0
        rng = _get_rng()
        timing = self._timing_planner()
        for index, flow in enumerate(plan.flows):
            duration = timing.right_skew_seconds(
                relationship_key="windows_remote_admin.transport_duration",
                stable_id=(
                    f"{plan.source_system.hostname}:{self._request.system.hostname}:"
                    f"{flow.destination_port}:{self._request.time.isoformat()}"
                ),
                minimum=0.08,
                median=0.22,
                maximum=0.9,
                host=plan.source_system.hostname,
                ordinal=index,
                sample_key="duration",
            )
            orig_bytes = (
                rng.randint(45_000, 160_000)
                if flow.destination_port == 445
                else rng.randint(450, 1800)
            )
            resp_bytes = (
                rng.randint(1500, 7000) if flow.destination_port == 445 else rng.randint(350, 2200)
            )
            self._executor.generate_connection(
                src_ip=plan.source_system.ip,
                dst_ip=self._request.system.ip,
                time=flow.timestamp,
                dst_port=flow.destination_port,
                proto="tcp",
                service=flow.service,
                duration=duration,
                orig_bytes=orig_bytes,
                resp_bytes=resp_bytes,
                src_port=plan.base_source_port + index,
                emit_dns=False,
                source_system=plan.source_system,
                conn_state="SF",
            )
        return plan.canonical_occurrence_count

    def _expanded_service_path(self) -> str:
        """Return the service image path with SystemRoot expanded."""

        service_path = self._request.service_file_name.replace("%SystemRoot%", r"C:\Windows")
        return service_path.replace("%systemroot%", r"C:\Windows")

    def _plan_payload_file_effect(self) -> _ServicePayloadPlan:
        """Classify the service image once for both effect planning and execution."""

        service_path = self._expanded_service_path()
        if _get_os_category(self._request.system.os) != "windows":
            return _ServicePayloadPlan(
                path=service_path,
                emit_create=False,
                suppression_reason="target platform is not Windows",
            )
        service_path_lower = service_path.lower().replace("/", "\\")
        is_preexisting_binary = (
            service_path_lower.startswith("c:\\windows\\system32\\")
            or service_path_lower.startswith("c:\\windows\\syswow64\\")
            or service_path_lower.startswith("c:\\program files\\")
            or service_path_lower.startswith("c:\\program files (x86)\\")
        )
        return _ServicePayloadPlan(
            path=service_path,
            emit_create=not is_preexisting_binary,
            suppression_reason=(
                "service image path is classified as preexisting" if is_preexisting_binary else ""
            ),
        )

    def _emit_payload_file_create(
        self,
        plan: _ServicePayloadPlan,
        node: ExecutionEffectNode,
    ) -> datetime | None:
        """Emit dropped service binary evidence when the service path is not preexisting."""

        if not plan.emit_create:
            return None
        system_pid = 4
        self._executor.state_manager.get_process_object_id(
            self._request.system.hostname,
            system_pid,
        )
        file_time = self._request.time - timedelta(milliseconds=250)
        self._executor.dispatcher.dispatch_builder(
            OccurrenceBuilder(
                timestamp=file_time,
                event_type="file_create",
                src_host=self._executor._build_host_context(self._request.system),
                auth=AuthContext(username="SYSTEM"),
                process=ProcessContext(
                    pid=system_pid,
                    parent_pid=0,
                    image="System",
                    command_line="System",
                    username="SYSTEM",
                    logon_id="0x3e7",
                ),
                file=FileContext(path=plan.path, action="create", pid=system_pid),
                effect_provenance=EffectOccurrenceProvenance.planned(
                    kind=EffectOccurrenceKind.FILE,
                    root_action_id=self.anchor.action_id,
                    plan_action_id=self.anchor.action_id,
                    node_id=node.node_id,
                    occurrence_ordinal=0,
                ),
                lifecycle=ActionLifecycleContext(
                    group_id=self._request.effective_lifecycle_group_id,
                    canonical_start=file_time,
                    phase="start",
                ),
            )
        )
        return file_time
