# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Atomic staged-process and service publication through lifecycle authority."""

from __future__ import annotations

from copy import copy
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.events.content_identity import CompiledServiceDeploymentIdentity
from evidenceforge.events.lifecycle import (
    LifecycleCloseBarrier,
    LifecycleEntityRef,
    LifecycleMembership,
    ProcessLifecycleIdentity,
    ProcessTokenIdentity,
    ServiceProcessBindingIdentity,
)
from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
from evidenceforge.generation.lifecycle_production_adapters import (
    LifecycleProductionAdapter,
    ServiceLifecyclePublicationPlan,
    builtin_service_publication_plan,
)
from evidenceforge.generation.lifecycle_registry import (
    LifecycleRegistry,
    LifecycleServiceAdmissionToken,
    LifecycleServiceProcessBindingClosure,
    LifecycleServiceProcessClosureRequest,
    LifecycleSubjectClosureControl,
)
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.generation.state_manager import ProcessMaterializationPlan, StateManager
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.rng import stable_uuid

_START = datetime(2024, 1, 15, 9, 0, tzinfo=UTC)


def _authority(
    *,
    hostname: str = "WIN-01",
) -> tuple[
    GeneratorLifecycleAuthority, StateManager, LifecycleRegistry, LifecycleProductionAdapter
]:
    state = StateManager()
    state.set_current_time(_START)
    registry = LifecycleRegistry(shard_count=8)
    authority = GeneratorLifecycleAuthority(state, LifecycleShadow(state, registry), shard_count=8)
    return authority, state, registry, LifecycleProductionAdapter(registry)


def _process_plan(
    state: StateManager,
    *,
    hostname: str = "WIN-01",
    parent_pid: int = 4,
    image: str = r"C:\Windows\System32\spoolsv.exe",
    username: str = "SYSTEM",
    os_category: str = "windows",
) -> ProcessMaterializationPlan:
    return state.plan_process_materialization(
        system=hostname,
        parent_pid=parent_pid,
        image=image,
        command_line=image,
        username=username,
        integrity_level="System" if os_category == "windows" else "root",
        os_category=os_category,
        start_time=state.get_current_time(),
    )


def _compiled_service_base(
    plan: ProcessMaterializationPlan,
    *,
    service_id: str = "print-spooler",
    canonical_name: str = "Print Spooler",
) -> ServiceLifecyclePublicationPlan:
    deployment = CompiledServiceDeploymentIdentity(plan.identity.hostname, service_id)
    return builtin_service_publication_plan(
        hostname=plan.identity.hostname,
        logical_service_id=service_id,
        canonical_name=canonical_name,
        boot_time=_START - timedelta(hours=1),
        started_at=plan.identity.started_at,
        deployment_identity=deployment,
    )


def _stage_binding(
    authority: GeneratorLifecycleAuthority,
    plan: ProcessMaterializationPlan,
    base: ServiceLifecyclePublicationPlan,
    *,
    role: str,
    prior_bindings: tuple[ServiceProcessBindingIdentity, ...] = (),
) -> ServiceLifecyclePublicationPlan:
    binding = ServiceProcessBindingIdentity(
        binding_id=stable_uuid(
            "test-service-process-binding",
            base.instance_identity.object_id,
            plan.identity.object_id,
            role,
        ),
        service_object_id=base.instance_identity.object_id,
        process_object_id=plan.identity.object_id,
        bound_at=max(base.instance_identity.started_at, plan.identity.started_at),
        role=role,
        action_id=base.action_id,
    )
    member = authority.service_staged_process_binding_member(plan, binding)
    return replace(
        base,
        process_bindings=(*prior_bindings, binding),
        staged_process_bindings=(member,),
    )


def _token(
    adapter: LifecycleProductionAdapter,
    service_plan: ServiceLifecyclePublicationPlan,
) -> LifecycleServiceAdmissionToken:
    return adapter.prepare_service_publication(service_plan)


def _canonical_stats(registry: LifecycleRegistry):
    return replace(registry.stats(), lookup_candidates_inspected=0)


def _assert_no_transient_service_state(adapter: LifecycleProductionAdapter) -> None:
    census = adapter.service_preparation_census()
    assert census.publication_reservations == 0
    assert census.claimed_publications == 0
    assert census.reserved_keys == 0
    assert census.capability_locators == 0


def _closure_control(
    kind: str,
    object_id: str,
    *,
    at: datetime,
) -> LifecycleSubjectClosureControl:
    return LifecycleSubjectClosureControl(
        barrier=LifecycleCloseBarrier(
            barrier_id=f"barrier:{kind}:{object_id}:{at.isoformat()}",
            subject=LifecycleEntityRef(kind, object_id),
            requested_at=at,
            authority="generated",
            action_id=f"close:{kind}:{object_id}:{at.isoformat()}",
        ),
        ticket_id=f"ticket:{kind}:{object_id}:{at.isoformat()}",
    )


def _closure_request(
    service_plan: ServiceLifecyclePublicationPlan,
    *,
    process_object_id: str,
    at: datetime,
    close_service: bool,
) -> LifecycleServiceProcessClosureRequest:
    binding = next(
        item
        for item in service_plan.process_bindings
        if item.process_object_id == process_object_id
    )
    return LifecycleServiceProcessClosureRequest(
        binding_closures=(
            LifecycleServiceProcessBindingClosure(
                identity=binding,
                closed_at=at,
                action_id=f"unbind:{binding.binding_id}:{at.isoformat()}",
            ),
        ),
        process_closures=(_closure_control("process", process_object_id, at=at),),
        service_closures=(
            (
                _closure_control(
                    "service",
                    service_plan.instance_identity.object_id,
                    at=at,
                ),
            )
            if close_service
            else ()
        ),
    )


def test_compiled_baseline_process_service_and_binding_commit_as_one_receipt() -> None:
    authority, state, registry, adapter = _authority()
    plan = _process_plan(state)
    service_plan = _stage_binding(
        authority,
        plan,
        _compiled_service_base(plan),
        role="service_process",
    )
    state_before = state.materialization_digest()

    result = authority.materialize_process_service_composite(
        plan,
        _token(adapter, service_plan),
    )

    assert state.materialization_digest() != state_before
    assert result.process.ecar_object_id == plan.identity.object_id
    assert authority.authenticates_process_service_composite_receipt(plan, result.receipt)
    service_receipt = result.receipt.service_receipt
    assert service_receipt.service.logical_identity.deployment_identity == (
        service_plan.logical_identity.deployment_identity
    )
    assert service_receipt.processes[0].identity.object_id == plan.identity.object_id
    assert service_receipt.start_plan_tokens == (plan.publication_token,)
    assert service_receipt.bindings[0].identity == service_plan.process_bindings[0]
    assert registry.get_process(plan.identity.object_id) is not None
    assert registry.get_service_instance(service_plan.instance_identity.object_id) is not None
    assert registry.service_process_binding(service_plan.process_bindings[0].binding_id) is not None
    _assert_no_transient_service_state(adapter)


def test_resident_manager_and_workers_bind_each_new_process_to_one_service() -> None:
    authority, state, registry, adapter = _authority(hostname="MAIL-01")
    manager_plan = _process_plan(
        state,
        hostname="MAIL-01",
        parent_pid=0,
        image="/usr/lib/postfix/sbin/master",
        username="root",
        os_category="linux",
    )
    base = _compiled_service_base(
        manager_plan,
        service_id="postfix",
        canonical_name="postfix",
    )
    manager_service = _stage_binding(
        authority,
        manager_plan,
        base,
        role="manager",
    )
    manager_result = authority.materialize_process_service_composite(
        manager_plan,
        _token(adapter, manager_service),
    )
    bindings = tuple(item.identity for item in manager_result.receipt.service_receipt.bindings)

    worker_results = []
    for ordinal, (image, role) in enumerate(
        (
            ("/usr/lib/postfix/sbin/smtpd", "worker:smtpd"),
            ("/usr/lib/postfix/sbin/smtp", "worker:smtp"),
        ),
        start=1,
    ):
        state.set_current_time(_START + timedelta(seconds=ordinal))
        worker_plan = _process_plan(
            state,
            hostname="MAIL-01",
            parent_pid=manager_plan.identity.pid,
            image=image,
            username="postfix",
            os_category="linux",
        )
        worker_service = _stage_binding(
            authority,
            worker_plan,
            base,
            role=role,
            prior_bindings=bindings,
        )
        worker_result = authority.materialize_process_service_composite(
            worker_plan,
            _token(adapter, worker_service),
        )
        assert authority.authenticates_process_service_composite_receipt(
            worker_plan,
            worker_result.receipt,
        )
        bindings = tuple(item.identity for item in worker_result.receipt.service_receipt.bindings)
        worker_results.append(worker_result)

    assert [binding.role for binding in bindings] == [
        "manager",
        "worker:smtpd",
        "worker:smtp",
    ]
    assert all(
        registry.get_process(result.process.ecar_object_id) is not None for result in worker_results
    )
    active, cursor = registry.service_process_binding_page(
        service_object_id=base.instance_identity.object_id,
        limit=10,
    )
    assert tuple(item.identity for item in active) == bindings
    assert cursor is None


def test_staged_service_reservation_blocks_sequential_process_start() -> None:
    authority, state, registry, adapter = _authority()
    plan = _process_plan(state)
    service_plan = _stage_binding(
        authority,
        plan,
        _compiled_service_base(plan),
        role="service_process",
    )
    token = _token(adapter, service_plan)
    state_before = state.materialization_digest()

    with pytest.raises(StateError, match="prepared service operation"):
        authority.materialize_process(plan)

    assert state.materialization_digest() == state_before
    assert registry.get_process(plan.identity.object_id) is None
    adapter.cancel_service_publication(token)
    result = authority.materialize_process_service_composite(
        plan,
        _token(adapter, service_plan),
    )
    assert authority.authenticates_process_service_composite_receipt(plan, result.receipt)


def test_staged_service_preparation_rejects_existing_pid_before_reservation() -> None:
    authority, state, registry, adapter = _authority()
    plan = _process_plan(state)
    conflict = ProcessLifecycleIdentity(
        hostname=plan.identity.hostname,
        object_id="process:conflicting-pid",
        pid=plan.identity.pid,
        started_at=plan.identity.started_at - timedelta(milliseconds=1),
        image=r"C:\Windows\System32\other.exe",
        role="service_process",
    )
    registry.register_process(
        conflict,
        token=ProcessTokenIdentity(principal=r"NT AUTHORITY\SYSTEM", logon_id="0x3e7"),
        membership=LifecycleMembership(
            owner_kind="boot",
            owner_object_id="boot:WIN-01",
        ),
        action_id="start:conflict",
        transition_id="transition:start:conflict",
    )
    service_plan = _stage_binding(
        authority,
        plan,
        _compiled_service_base(plan),
        role="service_process",
    )
    state_before = state.materialization_digest()

    with pytest.raises(StateError, match="Process lifecycle PID overlap"):
        adapter.prepare_service_publication(service_plan)

    assert state.materialization_digest() == state_before
    assert registry.get_process(plan.identity.object_id) is None
    assert registry.get_service_instance(service_plan.instance_identity.object_id) is None
    _assert_no_transient_service_state(adapter)


def test_staged_service_token_cannot_publish_without_its_process_state_boundary() -> None:
    authority, state, registry, adapter = _authority()
    plan = _process_plan(state)
    service_plan = _stage_binding(
        authority,
        plan,
        _compiled_service_base(plan),
        role="service_process",
    )
    token = _token(adapter, service_plan)
    state_before = state.materialization_digest()

    with pytest.raises(StateError, match="combined lifecycle start ticket"):
        with adapter.claimed_service_publication(token) as claimed:
            claimed.commit_no_fail()

    assert state.materialization_digest() == state_before
    assert registry.get_process(plan.identity.object_id) is None
    assert registry.get_service_instance(service_plan.instance_identity.object_id) is None
    assert registry.service_process_binding(service_plan.process_bindings[0].binding_id) is None
    _assert_no_transient_service_state(adapter)


def test_injected_rejection_consumes_exact_token_and_preserves_full_digest() -> None:
    authority, state, registry, adapter = _authority()
    plan = _process_plan(state)
    service_plan = _stage_binding(
        authority,
        plan,
        _compiled_service_base(plan),
        role="service_process",
    )
    token = _token(adapter, service_plan)
    state_before = state.materialization_digest()
    stats_before = _canonical_stats(registry)

    def _reject() -> None:
        raise StateError("injected process/service rejection")

    authority._materialization_precommit_hook = _reject
    with pytest.raises(StateError, match="injected process/service rejection"):
        authority.materialize_process_service_composite(plan, token)

    assert state.materialization_digest() == state_before
    assert _canonical_stats(registry) == stats_before
    assert not adapter.authenticates_service_admission_token(token)
    _assert_no_transient_service_state(adapter)
    authority._materialization_precommit_hook = None
    retry = authority.materialize_process_service_composite(
        plan,
        _token(adapter, service_plan),
    )
    assert retry.process.ecar_object_id == plan.identity.object_id


def test_same_registry_token_for_another_process_is_consumed_without_mutation() -> None:
    authority, state, registry, adapter = _authority()
    plan = _process_plan(state)
    other_plan = _process_plan(
        state,
        hostname="OTHER-01",
        parent_pid=0,
        image="/usr/bin/true",
        username="root",
        os_category="linux",
    )
    other_service = _stage_binding(
        authority,
        other_plan,
        _compiled_service_base(other_plan, service_id="other-service"),
        role="service_process",
    )
    token = _token(adapter, other_service)
    state_before = state.materialization_digest()
    stats_before = _canonical_stats(registry)

    with pytest.raises(StateError, match="hosts do not match"):
        authority.materialize_process_service_composite(plan, token)

    assert state.materialization_digest() == state_before
    assert _canonical_stats(registry) == stats_before
    assert not adapter.authenticates_service_admission_token(token)
    _assert_no_transient_service_state(adapter)


def test_foreign_and_copied_service_capabilities_are_not_consumed() -> None:
    authority, state, registry, adapter = _authority()
    plan = _process_plan(state)
    service_plan = _stage_binding(
        authority,
        plan,
        _compiled_service_base(plan),
        role="service_process",
    )
    original = _token(adapter, service_plan)
    copied = copy(original)
    state_before = state.materialization_digest()
    stats_before = _canonical_stats(registry)
    with pytest.raises(StateError, match="not authentic"):
        authority.materialize_process_service_composite(plan, copied)
    assert state.materialization_digest() == state_before
    assert _canonical_stats(registry) == stats_before
    assert adapter.authenticates_service_admission_token(original, plan=service_plan)
    adapter.cancel_service_publication(original)

    foreign_registry = LifecycleRegistry(shard_count=8)
    foreign_adapter = LifecycleProductionAdapter(foreign_registry)
    foreign_token = _token(foreign_adapter, service_plan)
    with pytest.raises(StateError, match="not authentic"):
        authority.materialize_process_service_composite(plan, foreign_token)
    assert state.materialization_digest() == state_before
    assert _canonical_stats(registry) == stats_before
    assert foreign_adapter.authenticates_service_admission_token(
        foreign_token,
        plan=service_plan,
    )
    foreign_adapter.cancel_service_publication(foreign_token)


def test_stale_state_and_lifecycle_tokens_leave_no_partial_publication() -> None:
    authority, state, registry, adapter = _authority()
    plan = _process_plan(state)
    service_plan = _stage_binding(
        authority,
        plan,
        _compiled_service_base(plan),
        role="service_process",
    )
    stale_state_token = _token(adapter, service_plan)
    state.set_current_time(_START + timedelta(milliseconds=1))
    disjoint = _process_plan(
        state,
        hostname="OTHER-01",
        parent_pid=0,
        image="/usr/bin/true",
        username="root",
        os_category="linux",
    )
    authority.materialize_process(disjoint)
    state_before = state.materialization_digest()
    with pytest.raises(StateError, match="stale"):
        authority.materialize_process_service_composite(plan, stale_state_token)
    assert state.materialization_digest() == state_before
    _assert_no_transient_service_state(adapter)

    state.set_current_time(_START + timedelta(seconds=1))
    fresh_plan = _process_plan(state)
    fresh_service = _stage_binding(
        authority,
        fresh_plan,
        _compiled_service_base(fresh_plan),
        role="service_process",
    )
    stale_lifecycle_token = _token(adapter, fresh_service)
    registry.advance_watermark(_START + timedelta(milliseconds=500))
    state_before = state.materialization_digest()
    with pytest.raises(StateError, match="stale after watermark"):
        authority.materialize_process_service_composite(
            fresh_plan,
            stale_lifecycle_token,
        )
    assert state.materialization_digest() == state_before
    _assert_no_transient_service_state(adapter)
    retry = authority.materialize_process_service_composite(
        fresh_plan,
        _token(adapter, fresh_service),
    )
    assert retry.process.ecar_object_id == fresh_plan.identity.object_id


def test_composite_receipt_rejects_nested_process_and_token_tamper() -> None:
    authority, state, _registry, adapter = _authority()
    plan = _process_plan(state)
    service_plan = _stage_binding(
        authority,
        plan,
        _compiled_service_base(plan),
        role="service_process",
    )
    result = authority.materialize_process_service_composite(
        plan,
        _token(adapter, service_plan),
    )
    receipt = result.receipt
    assert authority.authenticates_process_service_composite_receipt(plan, receipt)

    object.__setattr__(
        receipt.service_receipt,
        "start_plan_tokens",
        ("0" * 64,),
    )
    assert not authority.authenticates_process_service_composite_receipt(plan, receipt)


def test_service_process_close_commits_binding_process_and_last_service_once() -> None:
    authority, state, registry, adapter = _authority()
    start_plan = _process_plan(state)
    service_plan = _stage_binding(
        authority,
        start_plan,
        _compiled_service_base(start_plan),
        role="service_process",
    )
    authority.materialize_process_service_composite(
        start_plan,
        _token(adapter, service_plan),
    )
    close_at = _START + timedelta(seconds=10)
    state.set_current_time(close_at)
    close_plan = state.plan_process_termination_materialization(
        system=start_plan.identity.hostname,
        pid=start_plan.identity.pid,
        end_time=close_at,
    )
    request = _closure_request(
        service_plan,
        process_object_id=start_plan.identity.object_id,
        at=close_at,
        close_service=True,
    )
    token = adapter.prepare_service_process_closure(request)
    callback_observations: list[tuple[bool, bool]] = []

    result = authority.materialize_process_service_closure_composite(
        close_plan,
        token,
        finalize_external_no_fail=lambda: callback_observations.append(
            (
                state.get_process(start_plan.identity.hostname, start_plan.identity.pid) is None,
                registry.get_process(start_plan.identity.object_id).closed_at == close_at,
            )
        ),
    )

    assert result.process == start_plan.identity
    assert callback_observations == [(True, True)]
    assert authority.authenticates_process_service_closure_composite_receipt(
        close_plan,
        result.receipt,
    )
    assert state.get_process(start_plan.identity.hostname, start_plan.identity.pid) is None
    assert registry.get_process(start_plan.identity.object_id).closed_at == close_at
    assert registry.get_service_instance(service_plan.instance_identity.object_id).closed_at == (
        close_at
    )
    assert (
        registry.service_process_binding(service_plan.process_bindings[0].binding_id).closed_at
        == close_at
    )
    _assert_no_transient_service_state(adapter)


def test_service_process_close_rejection_is_full_digest_atomic_and_exact_retry() -> None:
    authority, state, registry, adapter = _authority()
    start_plan = _process_plan(state)
    service_plan = _stage_binding(
        authority,
        start_plan,
        _compiled_service_base(start_plan),
        role="service_process",
    )
    authority.materialize_process_service_composite(
        start_plan,
        _token(adapter, service_plan),
    )
    close_at = _START + timedelta(seconds=10)
    state.set_current_time(close_at)
    close_plan = state.plan_process_termination_materialization(
        system=start_plan.identity.hostname,
        pid=start_plan.identity.pid,
        end_time=close_at,
    )
    request = _closure_request(
        service_plan,
        process_object_id=start_plan.identity.object_id,
        at=close_at,
        close_service=True,
    )
    token = adapter.prepare_service_process_closure(request)
    state_before = state.materialization_digest()
    stats_before = _canonical_stats(registry)

    def _reject() -> None:
        raise StateError("injected process/service close rejection")

    authority._materialization_precommit_hook = _reject
    with pytest.raises(StateError, match="injected process/service close rejection"):
        authority.materialize_process_service_closure_composite(close_plan, token)

    assert state.materialization_digest() == state_before
    assert _canonical_stats(registry) == stats_before
    assert registry.get_process(start_plan.identity.object_id).closed_at is None
    assert registry.get_service_instance(service_plan.instance_identity.object_id).closed_at is None
    assert (
        registry.service_process_binding(service_plan.process_bindings[0].binding_id).closed_at
        is None
    )
    assert not adapter.authenticates_service_closure_admission_token(token)
    _assert_no_transient_service_state(adapter)

    authority._materialization_precommit_hook = None
    retry = authority.materialize_process_service_closure_composite(
        close_plan,
        adapter.prepare_service_process_closure(request),
    )
    assert retry.process == start_plan.identity
    assert authority.authenticates_process_service_closure_composite_receipt(
        close_plan,
        retry.receipt,
    )


def test_foreign_service_close_token_is_not_consumed_or_published() -> None:
    authority, state, registry, adapter = _authority()
    start_plan = _process_plan(state)
    service_plan = _stage_binding(
        authority,
        start_plan,
        _compiled_service_base(start_plan),
        role="service_process",
    )
    authority.materialize_process_service_composite(
        start_plan,
        _token(adapter, service_plan),
    )
    close_at = _START + timedelta(seconds=10)
    state.set_current_time(close_at)
    close_plan = state.plan_process_termination_materialization(
        system=start_plan.identity.hostname,
        pid=start_plan.identity.pid,
        end_time=close_at,
    )

    foreign_authority, foreign_state, _foreign_registry, foreign_adapter = _authority()
    foreign_start = _process_plan(foreign_state)
    foreign_service = _stage_binding(
        foreign_authority,
        foreign_start,
        _compiled_service_base(foreign_start),
        role="service_process",
    )
    foreign_authority.materialize_process_service_composite(
        foreign_start,
        _token(foreign_adapter, foreign_service),
    )
    foreign_state.set_current_time(close_at)
    foreign_request = _closure_request(
        foreign_service,
        process_object_id=foreign_start.identity.object_id,
        at=close_at,
        close_service=True,
    )
    foreign_token = foreign_adapter.prepare_service_process_closure(foreign_request)
    state_before = state.materialization_digest()
    stats_before = _canonical_stats(registry)

    with pytest.raises(StateError, match="not authentic"):
        authority.materialize_process_service_closure_composite(close_plan, foreign_token)

    assert state.materialization_digest() == state_before
    assert _canonical_stats(registry) == stats_before
    assert foreign_adapter.authenticates_service_closure_admission_token(foreign_token)
    foreign_adapter.cancel_service_process_closure(foreign_token)


def test_stale_process_close_plan_and_lifecycle_token_are_full_digest_atomic() -> None:
    authority, state, registry, adapter = _authority()
    start_plan = _process_plan(state)
    service_plan = _stage_binding(
        authority,
        start_plan,
        _compiled_service_base(start_plan),
        role="service_process",
    )
    authority.materialize_process_service_composite(
        start_plan,
        _token(adapter, service_plan),
    )
    close_at = _START + timedelta(seconds=10)
    state.set_current_time(close_at)
    close_plan = state.plan_process_termination_materialization(
        system=start_plan.identity.hostname,
        pid=start_plan.identity.pid,
        end_time=close_at,
    )
    request = _closure_request(
        service_plan,
        process_object_id=start_plan.identity.object_id,
        at=close_at,
        close_service=True,
    )
    stale_state_token = adapter.prepare_service_process_closure(request)
    disjoint = _process_plan(
        state,
        hostname="OTHER-01",
        parent_pid=0,
        image="/usr/bin/true",
        username="root",
        os_category="linux",
    )
    authority.materialize_process(disjoint)
    state_before = state.materialization_digest()
    stats_before = _canonical_stats(registry)

    with pytest.raises(StateError, match="stale"):
        authority.materialize_process_service_closure_composite(
            close_plan,
            stale_state_token,
        )

    assert state.materialization_digest() == state_before
    assert _canonical_stats(registry) == stats_before
    _assert_no_transient_service_state(adapter)

    fresh_close = state.plan_process_termination_materialization(
        system=start_plan.identity.hostname,
        pid=start_plan.identity.pid,
        end_time=close_at,
    )
    stale_lifecycle_token = adapter.prepare_service_process_closure(request)
    registry.advance_watermark(_START - timedelta(milliseconds=1))
    state_before = state.materialization_digest()
    with pytest.raises(StateError, match="stale after watermark"):
        authority.materialize_process_service_closure_composite(
            fresh_close,
            stale_lifecycle_token,
        )
    assert state.materialization_digest() == state_before
    _assert_no_transient_service_state(adapter)
    retry = authority.materialize_process_service_closure_composite(
        fresh_close,
        adapter.prepare_service_process_closure(request),
    )
    assert retry.process == start_plan.identity
