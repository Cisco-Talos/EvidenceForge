# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Service closure allocates exact terminal results before publishing canonical state."""

from concurrent.futures import ThreadPoolExecutor

import pytest

from evidenceforge.models.exceptions import StateError
from tests.unit.test_service_group_closure import _tree


def test_preallocated_service_result_is_exact_before_and_after_first_commit_and_retry() -> None:
    registry, adapter, request = _tree()
    for attempt in range(2):
        token = adapter.prepare_service_process_closure(request)
        with adapter.claimed_service_process_closure(token) as claimed:
            expected = claimed.expected_receipt
            assert not registry.authenticates_service_process_closure_receipt(expected)
            assert claimed.receipt is None
            if attempt == 0:
                assert all(
                    registry.get_process(item.identity.object_id).closed_at is None
                    for item in expected.processes
                )
                assert all(
                    registry.get_service_instance(item.identity.object_id).closed_at is None
                    for item in expected.services
                )
            actual = claimed.commit_no_fail()
            assert actual is expected
            assert claimed.receipt is expected
        assert registry.authenticates_service_process_closure_receipt(expected, request=request)
        assert expected.processes == tuple(
            registry.get_process(item.identity.object_id) for item in expected.processes
        )
        assert expected.services == tuple(
            registry.get_service_instance(item.identity.object_id) for item in expected.services
        )
        assert expected.bindings == tuple(
            registry.service_process_binding(item.identity.binding_id) for item in expected.bindings
        )
    assert adapter.service_preparation_census().reserved_keys == 0


def test_uncommitted_expected_result_cannot_authorize_closure_after_claim_rejection() -> None:
    registry, adapter, request = _tree()
    with pytest.raises(RuntimeError, match="cancel expected"):
        with adapter.claimed_service_process_closure(
            adapter.prepare_service_process_closure(request)
        ) as claimed:
            expected = claimed.expected_receipt
            raise RuntimeError("cancel expected")
    assert not registry.authenticates_service_process_closure_receipt(expected)
    assert all(
        registry.get_process(item.identity.object_id).closed_at is None
        for item in expected.processes
    )
    with pytest.raises(StateError, match="active same-thread"):
        _ = claimed.expected_receipt
    assert adapter.service_preparation_census().reserved_keys == 0


def test_expected_service_result_cannot_cross_claim_threads() -> None:
    _, adapter, request = _tree()
    with adapter.claimed_service_process_closure(
        adapter.prepare_service_process_closure(request)
    ) as claimed:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(lambda: claimed.expected_receipt)
            with pytest.raises(StateError, match="active same-thread"):
                future.result(timeout=5)
        assert claimed.commit_no_fail() is claimed.expected_receipt


@pytest.mark.parametrize("field", ["committed_digest", "processes", "bindings", "services"])
def test_changed_expected_service_result_rejects_before_mutating_any_owner(field: str) -> None:
    registry, adapter, request = _tree()
    before = tuple(
        registry.get_process(item.barrier.subject.object_id) for item in request.process_closures
    )
    with pytest.raises(StateError, match="expected result changed"):
        with adapter.claimed_service_process_closure(
            adapter.prepare_service_process_closure(request)
        ) as claimed:
            expected = claimed.expected_receipt
            object.__setattr__(expected, field, "changed" if field == "committed_digest" else ())
            claimed.commit_no_fail()
    assert (
        tuple(
            registry.get_process(item.barrier.subject.object_id)
            for item in request.process_closures
        )
        == before
    )
    assert adapter.service_preparation_census().reserved_keys == 0


@pytest.mark.parametrize("history_limit", [1, 2, 4])
def test_preallocated_results_preserve_bounded_transition_history(history_limit: int) -> None:
    from datetime import timedelta

    from evidenceforge.generation.lifecycle_production_adapters import LifecycleProductionAdapter
    from evidenceforge.generation.lifecycle_registry import (
        LifecycleRegistry,
        LifecycleServiceProcessClosureRequest,
    )
    from tests.unit.test_lifecycle_service_preparation import (
        _START,
        _binding_close,
        _control,
        _plan,
        _process,
        _publish,
    )

    registry = LifecycleRegistry(shard_count=4, snapshot_history_limit=history_limit)
    adapter = LifecycleProductionAdapter(registry)
    process = _process(registry, hostname="INVENTED-HOST", object_id="worker", pid=19)
    publication = _publish(
        adapter, _plan(hostname="INVENTED-HOST", logical_id="service", process=process)
    )
    at = _START + timedelta(seconds=20)
    request = LifecycleServiceProcessClosureRequest(
        binding_closures=(_binding_close(publication.bindings[0].identity, at=at),),
        process_closures=(_control("process", process.object_id, at=at),),
        service_closures=(_control("service", publication.service.identity.object_id, at=at),),
    )
    with adapter.claimed_service_process_closure(
        adapter.prepare_service_process_closure(request)
    ) as claimed:
        expected = claimed.expected_receipt
        assert claimed.commit_no_fail() is expected
    assert expected.processes[0] == registry.get_process(process.object_id)
    assert expected.services[0] == registry.get_service_instance(
        publication.service.identity.object_id
    )
    assert len(expected.processes[0].transitions) <= history_limit
    assert len(expected.services[0].transitions) <= history_limit
    assert expected.processes[0].transition_count == 4
    assert expected.services[0].transition_count == 4


def test_result_construction_failure_releases_reservation_before_canonical_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry, adapter, request = _tree()
    before = tuple(
        registry.get_process(item.barrier.subject.object_id) for item in request.process_closures
    )
    original = registry._prepare_service_closure_receipt_locked

    def fail(plan: object) -> None:
        original(plan)
        raise RuntimeError("injected expected result construction failure")

    with monkeypatch.context() as patch:
        patch.setattr(registry, "_prepare_service_closure_receipt_locked", fail)
        with pytest.raises(RuntimeError, match="expected result construction"):
            with adapter.claimed_service_process_closure(
                adapter.prepare_service_process_closure(request)
            ):
                pytest.fail("Failed result construction must not expose a claim")
    assert (
        tuple(
            registry.get_process(item.barrier.subject.object_id)
            for item in request.process_closures
        )
        == before
    )
    assert adapter.service_preparation_census().reserved_keys == 0
    with adapter.claimed_service_process_closure(
        adapter.prepare_service_process_closure(request)
    ) as claimed:
        assert claimed.commit_no_fail() is claimed.expected_receipt


def test_expected_retry_tracks_current_compacted_snapshots_without_reclosing() -> None:
    from datetime import timedelta

    from tests.unit.test_lifecycle_service_preparation import _START

    registry, adapter, request = _tree()
    with adapter.claimed_service_process_closure(
        adapter.prepare_service_process_closure(request)
    ) as claimed:
        first = claimed.commit_no_fail()
    registry.advance_watermark(_START + timedelta(seconds=5))
    current = tuple(registry.get_process(item.identity.object_id) for item in first.processes)
    with adapter.claimed_service_process_closure(
        adapter.prepare_service_process_closure(request)
    ) as claimed:
        expected = claimed.expected_receipt
        assert expected.processes == current
        assert claimed.commit_no_fail() is expected
    assert (
        tuple(registry.get_process(item.identity.object_id) for item in expected.processes)
        == current
    )
    assert [item.closed_at for item in expected.processes] == [
        item.closed_at for item in first.processes
    ]
