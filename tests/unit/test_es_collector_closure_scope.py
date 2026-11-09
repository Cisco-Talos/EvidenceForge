# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Disconnect claims compose with canonical owners without advancing source counters."""

from concurrent.futures import ThreadPoolExecutor
from copy import copy
from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.es_collector import ESCollectorClosure, ESCollectorRegistry
from evidenceforge.models.exceptions import StateError
from tests.unit.test_es_collector import _prepare as prepare_delivery
from tests.unit.test_es_collector_ownership import _setup
from tests.unit.test_process_execution_state import _START, _execute


def _connections() -> tuple:
    state, process, owner, first = _setup()
    second = owner.open(first.model_copy(update={"source_instance": "mac-a:second"}), process)
    requests = tuple(
        ESCollectorClosure(before=item, closed_at=_START + timedelta(seconds=6))
        for item in (first, second)
    )
    return state, process, owner, requests


@pytest.mark.parametrize("finalize", [False, True])
@pytest.mark.parametrize("failure", [False, True])
def test_disconnect_set_is_reversible_until_finalized(finalize: bool, failure: bool) -> None:
    state, process, owner, requests = _connections()
    before = owner.collectors.snapshot()
    canonical = state.materialization_digest()
    try:
        with owner.prepared_closures(requests, (process, process)) as claim:
            expected = claim.expected_result
            token = claim.publication_token
            assert len(token) == 64
            claim.apply_provisional()
            claim.apply_provisional()
            assert not claim.committed
            assert all(
                owner.collectors.connection(item.source_instance) == item for item in expected
            )
            with pytest.raises(StateError, match="checkpoint"):
                owner.collectors.snapshot()
            if finalize:
                claim.finalize_no_fail()
                claim.finalize_no_fail()
                assert claim.committed and claim.publication_token == token
            if failure:
                raise RuntimeError("outer transaction failed")
    except RuntimeError:
        assert failure
    assert owner.collectors.snapshot() == (expected if finalize else before)
    assert state.materialization_digest() == canonical
    assert all(
        a.next_delivery == b.next_delivery and a.next_global_sequence == b.next_global_sequence
        for a, b in zip(before, owner.collectors.snapshot(), strict=True)
    )
    with pytest.raises(StateError, match="active claim"):
        claim.apply_provisional()


@pytest.mark.parametrize("operation", ["delivery", "close", "restart", "nested"])
def test_claim_excludes_competing_mutations_of_its_exact_connections(operation: str) -> None:
    _, process, owner, requests = _connections()
    before = owner.collectors.snapshot()
    first = requests[0].before
    with owner.prepared_closures(requests, (process, process)):
        with pytest.raises(StateError):
            if operation == "delivery":
                prepare_delivery(owner.collectors)
            elif operation == "close":
                owner.collectors.close(first, requests[0].closed_at)
            elif operation == "restart":
                owner.collectors.open(
                    first.model_copy(
                        update={
                            "generation": 2,
                            "opened_at": _START + timedelta(seconds=1),
                            "last_delivery_at": _START + timedelta(seconds=1),
                        }
                    )
                )
            else:
                with owner.collectors.prepared_closures(requests):
                    pytest.fail("overlapping closure admitted")
    assert owner.collectors.snapshot() == before


@pytest.mark.parametrize("damage", ["copy", "thread", "result"])
def test_changed_or_foreign_claim_cannot_publish_disconnects(damage: str) -> None:
    _, process, owner, requests = _connections()
    before = owner.collectors.snapshot()
    with owner.prepared_closures(requests, (process, process)) as claim:
        if damage == "copy":
            with pytest.raises(StateError):
                copy(claim).commit_no_fail()
        elif damage == "thread":
            with ThreadPoolExecutor(max_workers=1) as executor:
                with pytest.raises(StateError, match="same-thread"):
                    executor.submit(claim.commit_no_fail).result(timeout=2)
        else:
            result = claim.expected_result
            claim.apply_provisional()
            object.__setattr__(result[1], "next_delivery", result[1].next_delivery + 1)
            with pytest.raises(StateError, match="result changed"):
                claim.finalize_no_fail()
    assert owner.collectors.snapshot() == before


@pytest.mark.parametrize("damage", ["pending", "changed", "duplicate", "empty", "list"])
def test_invalid_closure_set_changes_no_connection(damage: str) -> None:
    _, process, owner, requests = _connections()
    before = owner.collectors.snapshot()
    pending = None
    if damage == "pending":
        pending = prepare_delivery(owner.collectors)
    elif damage == "changed":
        requests = (
            requests[0],
            requests[1].model_copy(
                update={"before": requests[1].before.model_copy(update={"generation": 3})}
            ),
        )
    elif damage == "duplicate":
        requests = (requests[0], requests[0])
    elif damage == "empty":
        requests = ()
    elif damage == "list":
        requests = list(requests)
    with pytest.raises(StateError):
        with owner.collectors.prepared_closures(requests):
            pytest.fail("invalid closure admitted")
    if pending is not None:
        owner.collectors.cancel(pending)
    assert owner.collectors.snapshot() == before


@pytest.mark.parametrize("damage", ["execution", "identity", "host", "count"])
def test_bound_disconnect_requires_exact_live_execution(damage: str) -> None:
    state, process, owner, requests = _connections()
    owners = (process, process)
    if damage == "execution":
        _execute(state, process)
    elif damage == "identity":
        owners = (replace(process, image="/other"), process)
    elif damage == "host":
        requests = (
            requests[0],
            requests[1].model_copy(
                update={"before": requests[1].before.model_copy(update={"hostname": "OTHER"})}
            ),
        )
    else:
        owners = (process,)
    before = owner.collectors.snapshot()
    with pytest.raises(StateError):
        with owner.prepared_closures(requests, owners):
            pytest.fail("foreign live owner admitted")
    assert owner.collectors.snapshot() == before


def test_disjoint_delivery_commits_even_when_another_disconnect_rolls_back() -> None:
    _, process, owner, requests = _connections()
    with owner.prepared_closures((requests[1],), (process,)) as claim:
        claim.apply_provisional()
        observation = owner.collectors.commit(prepare_delivery(owner.collectors))
    assert owner.collectors.connection(requests[1].before.source_instance) == requests[1].before
    first = owner.collectors.connection(requests[0].before.source_instance)
    assert first.next_delivery == 1 and first.next_global_sequence == observation.global_seq_num + 1


def test_disconnect_completion_restores_through_existing_checkpoint_contract() -> None:
    _, process, owner, requests = _connections()
    with owner.prepared_closures(requests, (process, process)) as claim:
        expected = claim.expected_result
        claim.commit_no_fail()
    restored = ESCollectorRegistry()
    restored.restore(owner.collectors.snapshot())
    assert restored.snapshot() == expected
    with pytest.raises(StateError, match="open idle"):
        prepare_delivery(restored)


def test_certified_closure_finalization_uses_only_prevalidated_primitive_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, process, owner, requests = _connections()
    with owner.prepared_closures(requests, (process, process)) as claim:
        expected = claim.expected_result
        with pytest.raises(StateError, match="certification"):
            claim.certify_composite_commit(tuple(list(expected)))
        claim.certify_composite_commit(expected)
        claim.apply_provisional()

        def fail(*args: object) -> bytes:
            raise AssertionError("late closure fact serialization")

        with monkeypatch.context() as fault:
            fault.setattr(owner.collectors, "_closure_proof", fail)
            claim.finalize_no_fail()
        assert claim.committed
    assert owner.collectors.snapshot() == expected
