# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Certified service closure uses prevalidated primitive operands."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

from evidenceforge.models.exceptions import StateError
from tests.unit.test_service_group_closure import _tree


def _snapshots(registry: object, request: object) -> tuple:
    return (
        tuple(
            registry.get_process(item.barrier.subject.object_id)
            for item in request.process_closures
        ),
        tuple(
            registry.get_service_instance(item.barrier.subject.object_id)
            for item in request.service_closures
        ),
        tuple(
            registry.service_process_binding(item.identity.binding_id)
            for item in request.binding_closures
        ),
    )


@pytest.mark.parametrize("certified", [False, True])
def test_service_closure_results_match_actual_state_and_exact_retries(certified: bool) -> None:
    registry, adapter, request = _tree()
    for _ in range(2):
        with adapter.claimed_service_process_closure(
            adapter.prepare_service_process_closure(request)
        ) as claimed:
            expected = claimed.expected_receipt
            if certified:
                claimed.certify_composite_commit(expected)
            assert claimed.commit_no_fail() is expected
        assert _snapshots(registry, request) == (
            expected.processes,
            expected.services,
            expected.bindings,
        )
        assert registry.authenticates_service_process_closure_receipt(expected)
    assert adapter.service_preparation_census().reserved_keys == 0


def test_certified_service_tail_calls_no_validation_projection_or_legacy_close_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry, adapter, request = _tree()

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("late admission or receipt construction")

    with adapter.claimed_service_process_closure(
        adapter.prepare_service_process_closure(request)
    ) as claimed:
        expected = claimed.expected_receipt
        claimed.certify_composite_commit(expected)
        with monkeypatch.context() as patch:
            for name in (
                "_validate_service_closure_token",
                "_prepare_service_closure_commit_locked",
                "_prepare_service_closure_receipt_locked",
                "_service_receipt_integrity",
            ):
                patch.setattr(registry, name, forbidden)
            for partition in registry._partitions:
                for name in ("close_service_process_binding", "request_close", "close"):
                    patch.setattr(partition, name, forbidden)
            assert claimed.commit_no_fail() is expected
    assert _snapshots(registry, request) == (
        expected.processes,
        expected.services,
        expected.bindings,
    )


def test_certification_is_exact_one_shot_and_thread_bound() -> None:
    registry, adapter, request = _tree()
    with adapter.claimed_service_process_closure(
        adapter.prepare_service_process_closure(request)
    ) as claimed:
        expected = claimed.expected_receipt
        with pytest.raises(StateError, match="exact uncommitted result"):
            claimed.certify_composite_commit(replace(expected))
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(claimed.certify_composite_commit, expected)
            with pytest.raises(StateError, match="active same-thread"):
                future.result(timeout=5)
        claimed.certify_composite_commit(expected)
        with pytest.raises(StateError, match="exact uncommitted result"):
            claimed.certify_composite_commit(expected)
        assert claimed.commit_no_fail() is expected
    with pytest.raises(StateError, match="active same-thread"):
        claimed.certify_composite_commit(expected)
    assert registry.authenticates_service_process_closure_receipt(expected)


def test_cancelled_certified_claim_changes_no_lifecycle_or_binding() -> None:
    registry, adapter, request = _tree()
    before = _snapshots(registry, request)
    with pytest.raises(RuntimeError, match="cancel certified"):
        with adapter.claimed_service_process_closure(
            adapter.prepare_service_process_closure(request)
        ) as claimed:
            expected = claimed.expected_receipt
            claimed.certify_composite_commit(expected)
            raise RuntimeError("cancel certified")
    assert _snapshots(registry, request) == before
    assert not registry.authenticates_service_process_closure_receipt(expected)
    assert adapter.service_preparation_census().reserved_keys == 0


def test_damaged_expected_result_rejects_certification_before_mutation() -> None:
    registry, adapter, request = _tree()
    before = _snapshots(registry, request)
    with pytest.raises(StateError, match="exact uncommitted result"):
        with adapter.claimed_service_process_closure(
            adapter.prepare_service_process_closure(request)
        ) as claimed:
            expected = claimed.expected_receipt
            object.__setattr__(expected, "processes", ())
            claimed.certify_composite_commit(expected)
    assert _snapshots(registry, request) == before
    assert adapter.service_preparation_census().reserved_keys == 0


def test_certified_closure_counts_multiple_bindings_to_the_same_process_once_each() -> None:
    from tests.unit.test_lifecycle_service_preparation import (
        _binding_close,
        _control,
        _plan,
        _publish,
    )

    registry, adapter, request = _tree()
    parent = registry.get_process("parent").identity
    second = _publish(
        adapter, _plan(hostname=parent.hostname, logical_id="second-job", process=parent)
    )
    at = request.process_closures[0].barrier.requested_at
    request = replace(
        request,
        binding_closures=(
            *request.binding_closures,
            _binding_close(second.bindings[0].identity, at=at),
        ),
        service_closures=(
            *request.service_closures,
            _control("service", second.service.identity.object_id, at=at),
        ),
    )
    with adapter.claimed_service_process_closure(
        adapter.prepare_service_process_closure(request)
    ) as claimed:
        expected = claimed.expected_receipt
        claimed.certify_composite_commit(expected)
        assert claimed.commit_no_fail() is expected
    assert len(expected.bindings) == len(expected.services) == 2
    assert _snapshots(registry, request) == (
        expected.processes,
        expected.services,
        expected.bindings,
    )


def test_certified_process_close_can_leave_a_job_loaded_then_close_the_dormant_service() -> None:
    from evidenceforge.generation.lifecycle_registry import LifecycleServiceProcessClosureRequest

    registry, adapter, request = _tree()
    process_only = replace(request, service_closures=())
    with adapter.claimed_service_process_closure(
        adapter.prepare_service_process_closure(process_only)
    ) as claimed:
        claimed.certify_composite_commit(claimed.expected_receipt)
        process_receipt = claimed.commit_no_fail()
    assert not process_receipt.services
    service_id = request.service_closures[0].barrier.subject.object_id
    assert registry.get_service_instance(service_id).closed_at is None
    dormant = LifecycleServiceProcessClosureRequest(
        binding_closures=(), service_closures=request.service_closures
    )
    with adapter.claimed_service_process_closure(
        adapter.prepare_service_process_closure(dormant)
    ) as claimed:
        expected = claimed.expected_receipt
        claimed.certify_composite_commit(expected)
        assert claimed.commit_no_fail() is expected
    assert not expected.bindings and not expected.processes
    assert expected.services[0] == registry.get_service_instance(service_id)
