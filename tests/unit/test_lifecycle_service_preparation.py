# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Authenticated short-reservation contracts for lifecycle service authority."""

from __future__ import annotations

from copy import copy, deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from threading import Barrier, Thread

import pytest

from evidenceforge.events.lifecycle import (
    LifecycleCloseBarrier,
    LifecycleEntityRef,
    LifecycleMembership,
    ProcessLifecycleIdentity,
    ProcessTokenIdentity,
    ServiceProcessBindingIdentity,
)
from evidenceforge.generation.lifecycle_production_adapters import (
    LifecycleProductionAdapter,
    ServiceLifecyclePublicationPlan,
    builtin_service_publication_plan,
)
from evidenceforge.generation.lifecycle_registry import (
    LifecycleRegistry,
    LifecycleServiceProcessBindingClosure,
    LifecycleServiceProcessClosureRequest,
    LifecycleSubjectClosureControl,
)
from evidenceforge.models.exceptions import StateError

_START = datetime(2024, 1, 15, 9, 0, tzinfo=UTC)


def _process(
    registry: LifecycleRegistry,
    *,
    hostname: str,
    object_id: str,
    pid: int,
) -> ProcessLifecycleIdentity:
    """Register one boot-owned process for service binding tests."""

    identity = ProcessLifecycleIdentity(
        hostname=hostname,
        object_id=object_id,
        pid=pid,
        started_at=_START,
        image=r"C:\Windows\System32\svchost.exe",
        role="service_host",
    )
    registry.register_process(
        identity,
        token=ProcessTokenIdentity(principal=r"NT AUTHORITY\SYSTEM", logon_id="0x3e7"),
        membership=LifecycleMembership(owner_kind="boot", owner_object_id=f"boot:{hostname}"),
        action_id=f"start:{object_id}",
        transition_id=f"transition:start:{object_id}",
    )
    return identity


def _plan(
    *,
    hostname: str,
    logical_id: str,
    process: ProcessLifecycleIdentity,
) -> ServiceLifecyclePublicationPlan:
    """Build one exact built-in service publication and binding."""

    base = builtin_service_publication_plan(
        hostname=hostname,
        logical_service_id=logical_id,
        canonical_name=logical_id,
        boot_time=_START - timedelta(hours=1),
        started_at=_START,
    )
    binding = ServiceProcessBindingIdentity(
        binding_id=f"binding:{logical_id}:{process.object_id}",
        service_object_id=base.instance_identity.object_id,
        process_object_id=process.object_id,
        bound_at=_START,
        role="service_host",
        action_id=base.action_id,
    )
    return replace(base, process_bindings=(binding,))


def _publish(
    adapter: LifecycleProductionAdapter,
    plan: ServiceLifecyclePublicationPlan,
):
    """Publish one plan through its public token/claim/receipt flow."""

    token = adapter.prepare_service_publication(plan)
    with adapter.claimed_service_publication(token) as claimed:
        return claimed.commit_no_fail()


def _binding_close(
    binding: ServiceProcessBindingIdentity,
    *,
    at: datetime,
) -> LifecycleServiceProcessBindingClosure:
    return LifecycleServiceProcessBindingClosure(
        identity=binding,
        closed_at=at,
        action_id=f"unbind:{binding.binding_id}",
    )


def _control(kind: str, object_id: str, *, at: datetime) -> LifecycleSubjectClosureControl:
    return LifecycleSubjectClosureControl(
        barrier=LifecycleCloseBarrier(
            barrier_id=f"barrier:{kind}:{object_id}",
            subject=(
                LifecycleEntityRef("process", object_id)
                if kind == "process"
                else LifecycleEntityRef("service", object_id)
            ),
            requested_at=at,
            authority="generated",
            action_id=f"close:{kind}:{object_id}",
        ),
        ticket_id=f"ticket:{kind}:{object_id}",
    )


def test_service_token_is_authenticated_copy_safe_and_mutation_free_until_commit() -> None:
    """Only the exact untampered capability can publish its canonical deep copy."""

    registry = LifecycleRegistry(shard_count=8)
    adapter = LifecycleProductionAdapter(registry)
    process = _process(registry, hostname="HOST-01", object_id="process:1", pid=600)
    plan = _plan(hostname="HOST-01", logical_id="Schedule", process=process)
    token = adapter.prepare_service_publication(plan)

    assert token.publication_token
    assert adapter.authenticates_service_admission_token(token, plan=plan)
    assert not adapter.authenticates_service_admission_token(copy(token))
    assert not adapter.authenticates_service_admission_token(deepcopy(token))
    assert registry.get_service_instance(plan.instance_identity.object_id) is None
    assert registry.service_process_binding(plan.process_bindings[0].binding_id) is None
    census = adapter.service_preparation_census()
    assert (census.publication_reservations, census.claimed_publications) == (1, 0)

    with adapter.claimed_service_publication(token) as claimed:
        assert adapter.service_preparation_census().claimed_publications == 1
        assert adapter.authenticates_service_admission_token(token, plan=plan)
        with pytest.raises(StateError, match="cannot cancel directly"):
            adapter.cancel_service_publication(token)
        with pytest.raises(StateError, match="cannot move while a claimed service operation"):
            registry.advance_watermark(_START - timedelta(seconds=1))
        receipt = claimed.commit_no_fail()
        with pytest.raises(StateError, match="already committed"):
            claimed.commit_no_fail()

    assert adapter.authenticates_service_publication_receipt(receipt, plan=plan)
    assert not adapter.authenticates_service_admission_token(token)
    assert adapter.service_preparation_census().publication_reservations == 0


def test_service_token_cancel_stale_aba_and_foreign_registry_are_rejected() -> None:
    """Token identity prevents copying, ABA, stale, and foreign use."""

    registry = LifecycleRegistry(shard_count=8)
    foreign = LifecycleRegistry(shard_count=8)
    adapter = LifecycleProductionAdapter(registry)
    process = _process(registry, hostname="HOST-01", object_id="process:1", pid=600)
    plan = _plan(hostname="HOST-01", logical_id="Schedule", process=process)

    first = adapter.prepare_service_publication(plan)
    assert not foreign.authenticates_service_admission_token(first)
    adapter.cancel_service_publication(first)
    second = adapter.prepare_service_publication(plan)
    assert first.preparation_id != second.preparation_id
    assert not adapter.authenticates_service_admission_token(first)
    assert adapter.authenticates_service_admission_token(second)
    adapter.cancel_service_publication(second)

    stale = adapter.prepare_service_publication(plan)
    registry.advance_watermark(_START - timedelta(seconds=1))
    with pytest.raises(StateError, match="stale after watermark"):
        with adapter.claimed_service_publication(stale):
            pytest.fail("stale service capability entered its no-lock body")
    assert adapter.service_preparation_census().publication_reservations == 0


def test_claim_body_holds_no_registry_lock_and_disjoint_publication_progresses() -> None:
    """A claimed caller body cannot block an unrelated service publication."""

    registry = LifecycleRegistry(shard_count=8)
    adapter = LifecycleProductionAdapter(registry)
    first_process = _process(registry, hostname="HOST-01", object_id="process:1", pid=600)
    second_process = _process(registry, hostname="HOST-02", object_id="process:2", pid=601)
    first_plan = _plan(hostname="HOST-01", logical_id="Schedule", process=first_process)
    second_plan = _plan(hostname="HOST-02", logical_id="Spooler", process=second_process)
    first_token = adapter.prepare_service_publication(first_plan)
    rendezvous = Barrier(2)
    results: list[object] = []

    def publish_disjoint() -> None:
        rendezvous.wait()
        results.append(_publish(adapter, second_plan))

    worker = Thread(target=publish_disjoint)
    worker.start()
    with adapter.claimed_service_publication(first_token) as claimed:
        rendezvous.wait()
        worker.join(timeout=2)
        assert not worker.is_alive()
        first_receipt = claimed.commit_no_fail()
    assert first_receipt.service.identity == first_plan.instance_identity
    assert len(results) == 1


def test_service_closure_requires_complete_bindings_and_preserves_shared_process() -> None:
    """One service may close while another binding keeps its shared process live."""

    registry = LifecycleRegistry(shard_count=8)
    adapter = LifecycleProductionAdapter(registry)
    process = _process(registry, hostname="HOST-01", object_id="process:shared", pid=600)
    first_plan = _plan(hostname="HOST-01", logical_id="Service-A", process=process)
    second_plan = _plan(hostname="HOST-01", logical_id="Service-B", process=process)
    first = _publish(adapter, first_plan)
    second = _publish(adapter, second_plan)
    close_at = _START + timedelta(hours=1)

    incomplete_process = LifecycleServiceProcessClosureRequest(
        binding_closures=(_binding_close(first.bindings[0].identity, at=close_at),),
        process_closures=(_control("process", process.object_id, at=close_at),),
    )
    with pytest.raises(StateError, match="every active service binding"):
        adapter.prepare_service_process_closure(incomplete_process)
    incomplete_service = LifecycleServiceProcessClosureRequest(
        binding_closures=(),
        service_closures=(_control("service", first.service.identity.object_id, at=close_at),),
    )
    with pytest.raises(StateError, match="every active process binding"):
        adapter.prepare_service_process_closure(incomplete_service)

    first_request = LifecycleServiceProcessClosureRequest(
        binding_closures=(_binding_close(first.bindings[0].identity, at=close_at),),
        service_closures=(_control("service", first.service.identity.object_id, at=close_at),),
    )
    token = adapter.prepare_service_process_closure(first_request)
    assert adapter.authenticates_service_closure_admission_token(token, request=first_request)
    assert registry.service_process_binding(first.bindings[0].identity.binding_id).closed_at is None
    with adapter.claimed_service_process_closure(token) as claimed:
        first_close = claimed.commit_no_fail()
    assert adapter.authenticates_service_process_closure_receipt(first_close, request=first_request)
    assert not adapter.authenticates_service_process_closure_receipt(
        replace(first_close, committed_digest="0" * 64),
        request=first_request,
    )
    assert first_close.services[0].closed_at == close_at
    assert registry.get_process(process.object_id).closed_at is None
    assert (
        registry.service_process_binding(second.bindings[0].identity.binding_id).closed_at is None
    )

    final_at = close_at + timedelta(minutes=1)
    final_request = LifecycleServiceProcessClosureRequest(
        binding_closures=(_binding_close(second.bindings[0].identity, at=final_at),),
        process_closures=(_control("process", process.object_id, at=final_at),),
        service_closures=(_control("service", second.service.identity.object_id, at=final_at),),
    )
    token = adapter.prepare_service_process_closure(final_request)
    with adapter.claimed_service_process_closure(token) as claimed:
        final_close = claimed.commit_no_fail()
    assert final_close.processes[0].closed_at == final_at
    assert final_close.services[0].closed_at == final_at

    retry = adapter.prepare_service_process_closure(final_request)
    with adapter.claimed_service_process_closure(retry) as claimed:
        retry_receipt = claimed.commit_no_fail()
    assert retry_receipt.bindings == final_close.bindings
    assert retry_receipt.processes == final_close.processes
    assert retry_receipt.services == final_close.services


def test_service_closure_rejects_partial_terminal_retry_and_cleans_reservation() -> None:
    """A preclosed relation cannot be healed by a later staged service close."""

    registry = LifecycleRegistry(shard_count=8)
    adapter = LifecycleProductionAdapter(registry)
    process = _process(registry, hostname="HOST-01", object_id="process:1", pid=600)
    plan = _plan(hostname="HOST-01", logical_id="Schedule", process=process)
    published = _publish(adapter, plan)
    close_at = _START + timedelta(hours=1)
    binding_close = _binding_close(published.bindings[0].identity, at=close_at)
    registry.close_service_process_binding(
        binding_close.identity.binding_id,
        expected_identity=binding_close.identity,
        closed_at=close_at,
        action_id=binding_close.action_id,
        transition_ordinal=binding_close.transition_ordinal,
    )
    partial = LifecycleServiceProcessClosureRequest(
        binding_closures=(binding_close,),
        service_closures=(_control("service", published.service.identity.object_id, at=close_at),),
    )
    with pytest.raises(StateError, match="Partial service/process terminal retry"):
        adapter.prepare_service_process_closure(partial)
    census = adapter.service_preparation_census()
    assert (census.closure_reservations, census.claimed_closures) == (0, 0)


def test_service_closure_token_rejects_copy_tamper_cancel_stale_and_foreign_use() -> None:
    """Closure reservations use the same HMAC, capability, ABA, and watermark fences."""

    registry = LifecycleRegistry(shard_count=8)
    foreign = LifecycleRegistry(shard_count=8)
    adapter = LifecycleProductionAdapter(registry)
    process = _process(registry, hostname="HOST-01", object_id="process:1", pid=600)
    plan = _plan(hostname="HOST-01", logical_id="Schedule", process=process)
    published = _publish(adapter, plan)
    close_at = _START + timedelta(hours=1)
    request = LifecycleServiceProcessClosureRequest(
        binding_closures=(_binding_close(published.bindings[0].identity, at=close_at),),
        service_closures=(_control("service", published.service.identity.object_id, at=close_at),),
    )

    first = adapter.prepare_service_process_closure(request)
    assert first.publication_token
    assert adapter.authenticates_service_closure_admission_token(first, request=request)
    assert not adapter.authenticates_service_closure_admission_token(copy(first))
    assert not foreign.authenticates_service_closure_admission_token(first)
    with pytest.raises(StateError, match="prepared service operation"):
        registry.close_service_process_binding(
            published.bindings[0].identity.binding_id,
            expected_identity=published.bindings[0].identity,
            closed_at=close_at,
            action_id=f"unbind:{published.bindings[0].identity.binding_id}",
        )
    adapter.cancel_service_process_closure(first)

    second = adapter.prepare_service_process_closure(request)
    assert second.preparation_id != first.preparation_id
    assert not adapter.authenticates_service_closure_admission_token(first)
    adapter.cancel_service_process_closure(second)

    stale = adapter.prepare_service_process_closure(request)
    registry.advance_watermark(_START + timedelta(minutes=30))
    with pytest.raises(StateError, match="stale after watermark"):
        with adapter.claimed_service_process_closure(stale):
            pytest.fail("stale service closure entered its no-lock body")
    assert adapter.service_preparation_census().closure_reservations == 0


def test_disjoint_reverse_partition_service_closures_make_progress() -> None:
    """Reverse-ordered multi-host closures serialize by sorted partitions without deadlock."""

    registry = LifecycleRegistry(shard_count=8)
    adapter = LifecycleProductionAdapter(registry)
    publications: dict[str, object] = {}
    for ordinal, (hostname, logical_id) in enumerate(
        (
            ("HOST-01", "A-ONE"),
            ("HOST-01", "B-ONE"),
            ("HOST-02", "A-TWO"),
            ("HOST-02", "B-TWO"),
        ),
        start=1,
    ):
        process = _process(
            registry,
            hostname=hostname,
            object_id=f"process:{logical_id}",
            pid=600 + ordinal,
        )
        publications[logical_id] = _publish(
            adapter,
            _plan(hostname=hostname, logical_id=logical_id, process=process),
        )

    close_at = _START + timedelta(hours=1)

    def request_for(*logical_ids: str) -> LifecycleServiceProcessClosureRequest:
        receipts = [publications[logical_id] for logical_id in logical_ids]
        return LifecycleServiceProcessClosureRequest(
            binding_closures=tuple(
                _binding_close(receipt.bindings[0].identity, at=close_at) for receipt in receipts
            ),
            service_closures=tuple(
                _control("service", receipt.service.identity.object_id, at=close_at)
                for receipt in receipts
            ),
        )

    requests = (request_for("A-ONE", "A-TWO"), request_for("B-TWO", "B-ONE"))
    rendezvous = Barrier(2)
    results: list[object] = []
    failures: list[BaseException] = []

    def close(request: LifecycleServiceProcessClosureRequest) -> None:
        try:
            rendezvous.wait()
            token = adapter.prepare_service_process_closure(request)
            with adapter.claimed_service_process_closure(token) as claimed:
                results.append(claimed.commit_no_fail())
        except BaseException as exc:  # pragma: no cover - surfaced by assertion below
            failures.append(exc)

    workers = [Thread(target=close, args=(request,)) for request in requests]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=3)
    assert not failures
    assert all(not worker.is_alive() for worker in workers)
    assert len(results) == 2
    assert adapter.service_preparation_census().closure_reservations == 0
