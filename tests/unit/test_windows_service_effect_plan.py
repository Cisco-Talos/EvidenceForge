# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Production effect-plan coverage for Windows service-install actions."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any, Never

import pytest

from evidenceforge.events.content_identity import RuntimeServiceDeploymentIdentity
from evidenceforge.events.contexts import HostContext
from evidenceforge.events.contracts import OccurrenceRole
from evidenceforge.events.observation import ObservationPolicy
from evidenceforge.generation.actions.command_effects import (
    ChildProcessEffectIntent,
    EffectOutcomeStatus,
    EffectRequirement,
    ExecutionEffectAuditCounter,
    ExecutionEffectNode,
    ExecutionEffectPlan,
    ExecutionEffectPlanError,
    ExecutionEffectPlanErrorCode,
    ExecutionEffectReconciliation,
    FileEffectIntent,
    NetworkEffectIntent,
    ServiceEffectIntent,
)
from evidenceforge.generation.actions.windows_remote_admin import (
    WindowsServiceInstallActionBundle,
    WindowsServiceInstallRequest,
)
from evidenceforge.generation.causal.engine import ExpansionContext
from evidenceforge.generation.causal.rules import SupplementaryAuditEvents
from evidenceforge.generation.lifecycle_production_adapters import (
    installed_service_publication_plan,
)
from evidenceforge.generation.lifecycle_registry import LifecycleRegistry
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.models.exceptions import StateError
from evidenceforge.models.scenario import System, User
from evidenceforge.utils.rng import reset_thread_rng


class _RecordingAuditCounter(ExecutionEffectAuditCounter):
    """Retain reconciliations only inside a bounded unit-test executor."""

    __slots__ = ("reconciliations",)

    def __init__(self) -> None:
        super().__init__()
        self.reconciliations: list[ExecutionEffectReconciliation] = []

    def record(self, reconciliation: ExecutionEffectReconciliation) -> None:
        self.reconciliations.append(reconciliation)
        super().record(reconciliation)


class _StateManager:
    """Minimal read/state adapter with explicit mutation-call census."""

    def __init__(self) -> None:
        self.process_object_lookups: list[tuple[str, int]] = []
        self.session_lookups: list[str] = []

    def get_sessions_for_user(self, username: str) -> list[object]:
        self.session_lookups.append(username)
        return []

    def get_process_object_id(self, hostname: str, pid: int) -> str:
        self.process_object_lookups.append((hostname, pid))
        return "system-object-id"

    @staticmethod
    def get_boot_time(hostname: str) -> datetime | None:
        del hostname
        return None


class _Dispatcher:
    """Capture mutable canonical builders before their publication boundary."""

    def __init__(self) -> None:
        self.events: list[Any] = []
        self.lifecycle_shadow: LifecycleShadow | None = None
        self.enforces_lifecycle_authority = False
        self.reject = False

    def dispatch_builder(self, event: Any) -> dict[str, str]:
        if self.reject:
            raise RuntimeError("rejected service publication")
        self.events.append(event)
        return {}


class _Executor:
    """Small service-install executor that records every stateful boundary."""

    def __init__(
        self,
        *,
        source: System | None,
        target: System,
    ) -> None:
        systems = {target.hostname: target}
        if source is not None:
            systems[source.hostname] = source
        self._world_model = SimpleNamespace(systems_by_hostname=systems)
        self.state_manager = _StateManager()
        self.dispatcher = _Dispatcher()
        self._execution_effect_audit = _RecordingAuditCounter()
        self.connection_calls: list[dict[str, Any]] = []
        self.system_pid_calls: list[tuple[str, str, int]] = []

    def generate_connection(self, **kwargs: Any) -> str:
        self.connection_calls.append(kwargs)
        return f"uid-{len(self.connection_calls)}"

    def _get_system_pid(self, hostname: str, process: str, default: int) -> int:
        self.system_pid_calls.append((hostname, process, default))
        return default

    @staticmethod
    def _get_sid(username: str) -> str:
        return f"S-1-5-21-{username}"

    @staticmethod
    def _get_user_logon_id(
        username: str,
        hostname: str,
        at_time: datetime | None = None,
    ) -> str:
        del username, hostname, at_time
        return "0x1234"

    @staticmethod
    def _build_host_context(system: System) -> HostContext:
        return HostContext(
            hostname=system.hostname,
            ip=system.ip,
            os=system.os,
            os_category="windows",
            system_type=system.type,
            domain="example.test",
            fqdn=f"{system.hostname}.example.test",
            netbios_domain="EXAMPLE",
        )


def _systems() -> tuple[System, System]:
    source = System(
        hostname="WS-ADMIN-01",
        ip="10.0.0.50",
        os="Windows 11",
        type="workstation",
    )
    target = System(
        hostname="DC-01",
        ip="10.0.0.10",
        os="Windows Server 2022",
        type="domain_controller",
    )
    return source, target


def _user(source: System) -> User:
    return User(
        username="alice",
        full_name="Alice Admin",
        email="alice@example.test",
        primary_system=source.hostname,
    )


def _request(
    *,
    user: User,
    target: System,
    service_file_name: str,
    lifecycle_group_id: str = "",
) -> WindowsServiceInstallRequest:
    return WindowsServiceInstallRequest(
        user=user,
        system=target,
        time=datetime(2026, 8, 16, 14, 0, tzinfo=UTC),
        service_name="PSEXESVC",
        service_file_name=service_file_name,
        lifecycle_group_id=lifecycle_group_id,
    )


def _nodes_by_key(plan: ExecutionEffectPlan) -> dict[str, ExecutionEffectNode]:
    return {node.instance_key: node for node in plan.nodes}


def _enable_lifecycle(executor: _Executor) -> LifecycleRegistry:
    registry = LifecycleRegistry(shard_count=1)
    executor.dispatcher.lifecycle_shadow = LifecycleShadow(executor.state_manager, registry)
    return registry


def test_dropped_remote_service_reconciles_exact_effects_and_external_process_links() -> None:
    """PsExec-like installs account for transport, payload, service, and sibling process phases."""

    source, target = _systems()
    executor = _Executor(source=source, target=target)
    request = _request(
        user=_user(source),
        target=target,
        service_file_name=r"%SystemRoot%\PSEXESVC.exe",
        lifecycle_group_id="remote-service-lifecycle-1",
    )
    bundle = WindowsServiceInstallActionBundle(executor, request)

    plan = bundle.plan_effects()
    nodes = _nodes_by_key(plan)

    assert request.stable_id == replace(request, effect_plan=plan).stable_id
    assert len(plan.nodes) == 5
    assert sum(isinstance(node.intent, FileEffectIntent) for node in plan.nodes) == 1
    assert nodes["service-control-network"].requirement == EffectRequirement.REQUIRED
    assert isinstance(nodes["service-control-network"].intent, NetworkEffectIntent)
    assert nodes["service-control-network"].intent.occurrence_cardinality == 2
    assert nodes["service-payload-file-create"].requirement == EffectRequirement.REQUIRED
    assert isinstance(nodes["service-install"].intent, ServiceEffectIntent)
    assert nodes["service-install"].requirement == EffectRequirement.REQUIRED
    assert isinstance(nodes["service-process-start"].intent, ChildProcessEffectIntent)
    assert nodes["service-process-start"].requirement == EffectRequirement.EXTERNALLY_OWNED
    assert nodes["service-process-start"].role == OccurrenceRole.DEPENDENT
    assert nodes["service-process-close"].requirement == EffectRequirement.EXTERNALLY_OWNED
    assert nodes["service-process-close"].role == OccurrenceRole.CLOSURE

    reset_thread_rng(8675309)
    bundle.execute()

    assert [(call["dst_port"], call["service"]) for call in executor.connection_calls] == [
        (445, "smb"),
        (135, "dce_rpc"),
    ]
    assert executor.connection_calls[1]["src_port"] == (
        executor.connection_calls[0]["src_port"] + 1
    )
    file_event, service_event = executor.dispatcher.events
    assert file_event.event_type == "file_create"
    assert file_event.file.path == r"C:\Windows\PSEXESVC.exe"
    assert file_event.process.image == "System"
    assert file_event.process.pid == 4
    assert file_event.file.pid == 4
    assert executor.state_manager.process_object_lookups == [(target.hostname, 4)]
    assert service_event.event_type == "service_installed"
    assert file_event.lifecycle.group_id == "remote-service-lifecycle-1"
    assert service_event.lifecycle.group_id == "remote-service-lifecycle-1"
    assert file_event.lifecycle.canonical_start == service_event.lifecycle.canonical_start
    for format_name in ("windows_event_sysmon", "ecar"):
        policy = ObservationPolicy("messy_collection")
        assert policy.decide(format_name, file_event) == policy.decide(
            format_name,
            service_event,
        )

    reconciliation = executor._execution_effect_audit.reconciliations[-1]
    assert reconciliation.complete is True
    outcomes = {outcome.node_id: outcome for outcome in reconciliation.outcomes}
    assert outcomes[nodes["service-control-network"].node_id].canonical_occurrence_count == 2
    assert outcomes[nodes["service-payload-file-create"].node_id].canonical_occurrence_count == 1
    assert outcomes[nodes["service-install"].node_id].canonical_occurrence_count == 1
    for instance_key in ("service-process-start", "service-process-close"):
        outcome = outcomes[nodes[instance_key].node_id]
        assert outcome.status == EffectOutcomeStatus.LINKED
        assert outcome.child_action_id == "remote-service-lifecycle-1"
        assert outcome.canonical_occurrence_count == 1


def test_preexisting_local_service_suppresses_optional_transport_and_payload() -> None:
    """A local preinstalled image keeps only the required service-install occurrence."""

    source, target = _systems()
    executor = _Executor(source=None, target=target)
    request = _request(
        user=_user(source),
        target=target,
        service_file_name=r"C:\Windows\System32\DeviceSyncSvc.exe",
    )
    bundle = WindowsServiceInstallActionBundle(executor, request)
    plan = bundle.plan_effects()
    nodes = _nodes_by_key(plan)

    assert len(plan.nodes) == 3
    assert nodes["service-control-network"].requirement == EffectRequirement.OPTIONAL
    assert nodes["service-payload-file-create"].requirement == EffectRequirement.OPTIONAL
    assert nodes["service-install"].requirement == EffectRequirement.REQUIRED

    bundle.execute()

    assert executor.connection_calls == []
    assert executor.state_manager.process_object_lookups == []
    assert [event.event_type for event in executor.dispatcher.events] == ["service_installed"]
    service_event = executor.dispatcher.events[0]
    assert service_event.lifecycle.group_id == request.stable_id
    assert service_event.lifecycle.phase == "start"
    reconciliation = executor._execution_effect_audit.reconciliations[-1]
    assert reconciliation.complete is True
    assert reconciliation.summary.suppressed_count == 2
    assert reconciliation.summary.realized_count == 1


def test_cardinality_drift_fails_preflight_without_partial_state() -> None:
    """A stale caller plan cannot enter transport, PID, registry, or dispatcher mutation."""

    source, target = _systems()
    executor = _Executor(source=source, target=target)
    request = _request(
        user=_user(source),
        target=target,
        service_file_name=r"C:\Windows\Temp\custom-service.exe",
    )
    canonical = WindowsServiceInstallActionBundle(executor, request).plan_effects()
    network_node = _nodes_by_key(canonical)["service-control-network"]
    assert isinstance(network_node.intent, NetworkEffectIntent)
    drifted_network_node = replace(
        network_node,
        intent=replace(network_node.intent, occurrence_cardinality=1),
    )
    drifted_plan = ExecutionEffectPlan(
        anchor=canonical.anchor,
        nodes=tuple(
            drifted_network_node if node.node_id == network_node.node_id else node
            for node in canonical.nodes
        ),
    )
    drifted_request = replace(request, effect_plan=drifted_plan)

    with pytest.raises(ExecutionEffectPlanError) as exc_info:
        WindowsServiceInstallActionBundle(executor, drifted_request).execute()

    assert exc_info.value.code == ExecutionEffectPlanErrorCode.INVALID_PLAN
    assert "drifted=service-control-network" in str(exc_info.value)
    assert executor.connection_calls == []
    assert executor.system_pid_calls == []
    assert executor.state_manager.process_object_lookups == []
    assert executor.dispatcher.events == []
    assert executor._execution_effect_audit.reconciliations == []


def test_service_action_publishes_one_immutable_registry_identity_idempotently() -> None:
    """Successful retries converge on one installed logical/runtime service row."""

    source, target = _systems()
    executor = _Executor(source=None, target=target)
    registry = _enable_lifecycle(executor)
    request = _request(
        user=_user(source),
        target=target,
        service_file_name=r"C:\Windows\System32\DeviceSyncSvc.exe",
    )
    expected = installed_service_publication_plan(
        hostname=target.hostname,
        service_name=request.service_name,
        deployment_service_id=(
            runtime_identity := RuntimeServiceDeploymentIdentity(
                hostname=target.hostname,
                canonical_name=request.service_name,
                action_id=request.stable_id,
            )
        ).deployment_service_id,
        boot_time=request.time,
        started_at=request.time,
        action_id=request.stable_id,
        deployment_identity=runtime_identity,
    )
    publication_state_during_dispatch: list[tuple[int, int]] = []
    dispatch = executor.dispatcher.dispatch_builder

    def _dispatch_while_claimed(event: object) -> dict[str, str]:
        publication_state_during_dispatch.append(
            (
                registry.census().service_instance_entries,
                registry.service_preparation_census().claimed_publications,
            )
        )
        return dispatch(event)

    executor.dispatcher.dispatch_builder = _dispatch_while_claimed

    WindowsServiceInstallActionBundle(executor, request).execute()
    assert publication_state_during_dispatch == [(0, 1)]
    registry.advance_watermark(request.time + timedelta(seconds=1))
    WindowsServiceInstallActionBundle(executor, request).execute()

    snapshot = registry.get_service_instance(expected.instance_identity.object_id)
    assert snapshot is not None
    assert snapshot.identity == expected.instance_identity
    assert snapshot.logical_identity == expected.logical_identity
    assert snapshot.logical_identity.service_kind == "installed"
    assert snapshot.logical_identity.deployment_identity == runtime_identity
    assert snapshot.logical_identity.deployment_service_id != request.stable_id
    census = registry.census()
    assert census.logical_service_entries == 1
    assert census.service_instance_entries == 1


def test_service_action_rejection_leaves_no_partial_lifecycle_publication() -> None:
    """A rejected canonical action never publishes its prepared service row."""

    source, target = _systems()
    executor = _Executor(source=None, target=target)
    registry = _enable_lifecycle(executor)
    executor.dispatcher.reject = True
    request = _request(
        user=_user(source),
        target=target,
        service_file_name=r"C:\Windows\System32\DeviceSyncSvc.exe",
    )

    with pytest.raises(RuntimeError, match="rejected service publication"):
        WindowsServiceInstallActionBundle(executor, request).execute()

    census = registry.census()
    assert census.logical_service_entries == 0
    assert census.service_instance_entries == 0
    preparation = registry.service_preparation_census()
    assert preparation.publication_reservations == 0
    assert preparation.claimed_publications == 0


def test_service_admission_rejection_precedes_every_visible_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A lifecycle reservation rejection leaves evidence, audit, and state untouched."""

    source, target = _systems()
    executor = _Executor(source=source, target=target)
    registry = _enable_lifecycle(executor)
    before_registry = registry.census()
    request = _request(
        user=_user(source),
        target=target,
        service_file_name=r"C:\Windows\PSEXESVC.exe",
    )

    def _reject_service(_request: object) -> Never:
        raise StateError("injected service admission rejection")

    monkeypatch.setattr(registry, "prepare_service_publication", _reject_service)

    with pytest.raises(StateError, match="injected service admission rejection"):
        WindowsServiceInstallActionBundle(executor, request).execute()

    assert executor.connection_calls == []
    assert executor.system_pid_calls == []
    assert executor.state_manager.process_object_lookups == []
    assert executor.dispatcher.events == []
    assert executor._execution_effect_audit.reconciliations == []
    assert registry.census() == before_registry
    assert registry.service_preparation_census().publication_reservations == 0


def test_bound_deployment_registry_must_validate_runtime_service_before_effects() -> None:
    """A bound but incompatible deployment authority cannot fall back to an action ID."""

    source, target = _systems()
    executor = _Executor(source=source, target=target)
    registry = _enable_lifecycle(executor)
    executor.dispatcher.deployment_registry = SimpleNamespace()
    request = _request(
        user=_user(source),
        target=target,
        service_file_name=r"C:\Windows\PSEXESVC.exe",
    )

    with pytest.raises(StateError, match="cannot resolve runtime service identity"):
        WindowsServiceInstallActionBundle(executor, request).execute()

    assert executor.connection_calls == []
    assert executor.dispatcher.events == []
    assert executor._execution_effect_audit.reconciliations == []
    assert registry.census().service_instance_entries == 0


def test_service_stale_claim_rejects_before_every_visible_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A watermark-stale reservation cancels before transport or event publication."""

    source, target = _systems()
    executor = _Executor(source=source, target=target)
    registry = _enable_lifecycle(executor)
    request = _request(
        user=_user(source),
        target=target,
        service_file_name=r"C:\Windows\PSEXESVC.exe",
    )
    prepare = registry.prepare_service_publication

    def _prepare_then_seal(publication: object) -> object:
        token = prepare(publication)
        registry.advance_watermark(request.time)
        return token

    monkeypatch.setattr(registry, "prepare_service_publication", _prepare_then_seal)

    with pytest.raises(StateError, match="stale after watermark advance"):
        WindowsServiceInstallActionBundle(executor, request).execute()

    assert executor.connection_calls == []
    assert executor.dispatcher.events == []
    assert executor._execution_effect_audit.reconciliations == []
    assert registry.census().service_instance_entries == 0
    assert registry.service_preparation_census().publication_reservations == 0


def test_service_action_rejects_overlapping_identity_before_new_effects() -> None:
    """A second live installation cannot mutate evidence or registry state."""

    source, target = _systems()
    executor = _Executor(source=None, target=target)
    registry = _enable_lifecycle(executor)
    first = _request(
        user=_user(source),
        target=target,
        service_file_name=r"C:\Windows\System32\DeviceSyncSvc.exe",
    )
    WindowsServiceInstallActionBundle(executor, first).execute()
    event_count = len(executor.dispatcher.events)
    second = replace(
        first,
        time=first.time.replace(minute=1),
        service_file_name=r"C:\Windows\System32\DeviceSyncSvc-v2.exe",
    )

    with pytest.raises(StateError, match="logical identity already has an active instance"):
        WindowsServiceInstallActionBundle(executor, second).execute()

    assert len(executor.dispatcher.events) == event_count
    census = registry.census()
    assert census.logical_service_entries == 1
    assert census.service_instance_entries == 1


def test_causal_sc_create_and_direct_request_converge_on_one_effect_plan() -> None:
    """Causal ``sc create`` and direct service intents enter the same bundle contract."""

    source, target = _systems()
    user = _user(source)
    timestamp = datetime(2026, 8, 16, 14, 0, tzinfo=UTC)
    context = ExpansionContext(
        event_type="process_create",
        timestamp=timestamp,
        os_category="windows",
        command_line=(r'sc create PSEXESVC binpath= "C:\Windows\PSEXESVC.exe" start= demand'),
        actor=user,
        target_system=target,
    )
    expanded = SupplementaryAuditEvents().expand("process_create", context)

    assert len(expanded) == 1
    assert expanded[0].method == "generate_service_installed"
    causal_request = WindowsServiceInstallRequest(time=timestamp, **expanded[0].kwargs)
    direct_request = WindowsServiceInstallRequest(
        user=user,
        system=target,
        time=timestamp,
        service_name="PSEXESVC",
        service_file_name=r"C:\Windows\PSEXESVC.exe",
        service_start_type="3",
    )
    causal_plan = WindowsServiceInstallActionBundle(
        _Executor(source=source, target=target),
        causal_request,
    ).plan_effects()
    direct_plan = WindowsServiceInstallActionBundle(
        _Executor(source=source, target=target),
        direct_request,
    ).plan_effects()

    assert causal_request.stable_id == direct_request.stable_id
    assert causal_plan == direct_plan
