# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Reversible counter preparation for the canonical publication boundary."""

from contextlib import AbstractContextManager
from datetime import timedelta

import pytest

from evidenceforge.events.es_collector import (
    ESCollectorRegistry,
    ESDeliveryBatchPreparation,
    ESDeliveryPreparation,
    PreparedESDeliveryBatchCommit,
    PreparedESDeliveryCommit,
)
from evidenceforge.models.exceptions import StateError
from tests.unit.test_es_collector import _prepare, _registry
from tests.unit.test_es_collector_batch import _prepare as _batch


def _scope(
    registry: ESCollectorRegistry, token: ESDeliveryPreparation | ESDeliveryBatchPreparation
) -> AbstractContextManager[PreparedESDeliveryCommit | PreparedESDeliveryBatchCommit]:
    return (
        registry.prepared_delivery(token)
        if type(token) is ESDeliveryPreparation
        else registry.prepared_batch(token)
    )


def _completed(
    registry: ESCollectorRegistry, token: ESDeliveryPreparation | ESDeliveryBatchPreparation
) -> object:
    return (
        registry.completed_observation(token)
        if type(token) is ESDeliveryPreparation
        else registry.completed_batch(token)
    )


@pytest.mark.parametrize("batch", [False, True])
@pytest.mark.parametrize("failure", [False, True])
def test_unfinalized_counter_application_restores_connection_and_retains_exact_retry(
    batch: bool, failure: bool
) -> None:
    registry = _registry()
    token = _batch(registry) if batch else _prepare(registry)
    before = registry.connection("mac-a:es-client")
    try:
        with _scope(registry, token) as claim:
            claim.apply_provisional()
            claim.apply_provisional()
            assert registry.connection(before.source_instance) != before
            assert not claim.committed and _completed(registry, token) is None
            with pytest.raises(StateError, match="checkpoint"):
                registry.snapshot()
            if failure:
                raise RuntimeError("outer owner failed")
    except RuntimeError as error:
        assert failure and str(error) == "outer owner failed"
    assert registry.connection(before.source_instance) == before
    assert _completed(registry, token) is None
    with _scope(registry, token) as claim:
        claim.apply_provisional()
        claim.finalize_no_fail()
        assert claim.committed
        claim.finalize_no_fail()
    assert _completed(registry, token) is not None
    after = registry.snapshot()
    restored = ESCollectorRegistry()
    restored.restore(after)
    assert restored.snapshot() == after


@pytest.mark.parametrize("batch", [False, True])
def test_counter_finalization_requires_application_and_native_binding_precedes_it(
    batch: bool,
) -> None:
    registry = _registry()
    token = _batch(registry) if batch else _prepare(registry)
    with _scope(registry, token) as claim:
        with pytest.raises(StateError, match="provisional"):
            claim.finalize_no_fail()
        claim.apply_provisional()
        with pytest.raises(StateError, match="freeze before"):
            if batch:
                claim.freeze_native_projections(tuple("{}\n" for _ in token.observations))
            else:
                claim.freeze_native_projection("{}\n")
    with _scope(registry, token) as claim:
        if batch:
            frozen = claim.freeze_native_projections(tuple("{}\n" for _ in token.observations))
        else:
            frozen = claim.freeze_native_projection("{}\n")
        claim.apply_provisional()
        # Applying a previously frozen claim does not change its native evidence.
        if batch:
            assert claim.freeze_native_projections(frozen) == frozen
        else:
            assert claim.freeze_native_projection(frozen) == frozen
        claim.commit_no_fail()
    assert _completed(registry, token) is not None


@pytest.mark.parametrize("batch", [False, True])
def test_completed_retry_never_rolls_back_a_later_connection_epoch(batch: bool) -> None:
    registry = _registry()
    token = _batch(registry) if batch else _prepare(registry)
    with _scope(registry, token) as claim:
        claim.commit_no_fail()
    before = registry.connection("mac-a:es-client")
    after = before.model_copy(
        update={
            "generation": 2,
            "next_delivery": 0,
            "opened_at": before.last_delivery_at + timedelta(seconds=1),
            "last_delivery_at": before.last_delivery_at + timedelta(seconds=1),
        }
    )
    registry.open(after)
    with _scope(registry, token) as claim:
        claim.apply_provisional()
    assert registry.connection(after.source_instance) == after
    assert _completed(registry, token) is not None


@pytest.mark.parametrize("batch", [False, True])
def test_counter_and_state_provisional_changes_both_roll_back_on_outer_failure(batch: bool) -> None:
    from tests.unit.test_macos_es_exit_batch_preparation import _group
    from tests.unit.test_macos_es_exit_batch_preparation import _prepare as group_prepare
    from tests.unit.test_macos_es_exit_preparation import _fixture
    from tests.unit.test_macos_es_exit_preparation import _prepare as single_prepare

    fixture = _group() if batch else _fixture()
    state = fixture.owner.state
    before = state.materialization_digest()
    observation = fixture.delivery.observations[0] if batch else fixture.delivery.observation
    connection = fixture.owner.collectors.connection(observation.source_instance)
    with pytest.raises(RuntimeError, match="outer commit failed"):
        with state.prepared_action_cohort_materialization(fixture.cohort) as canonical:
            with group_prepare(fixture) if batch else single_prepare(fixture) as native:
                native.collector.apply_provisional()
                canonical.certify_composite_commit(canonical.expected_result)
                canonical.apply_provisional()
                assert state.materialization_digest() != before
                raise RuntimeError("outer commit failed")
    assert state.materialization_digest() == before
    assert fixture.owner.collectors.connection(connection.source_instance) == connection
    assert _completed(fixture.owner.collectors, fixture.delivery) is None
    # The exact frozen bytes and reservation remain reusable after rollback.
    with state.prepared_action_cohort_materialization(fixture.cohort) as canonical:
        with group_prepare(fixture) if batch else single_prepare(fixture) as native:
            native.collector.apply_provisional()
            canonical.certify_composite_commit(canonical.expected_result)
            canonical.apply_provisional()
            canonical.finalize_no_fail()
            native.collector.finalize_no_fail()
            assert native.collector.committed
    assert _completed(fixture.owner.collectors, fixture.delivery) is not None


@pytest.mark.parametrize("batch", [False, True])
@pytest.mark.parametrize("operation", ["apply_provisional", "finalize_no_fail"])
def test_provisional_capabilities_reject_copies_foreign_threads_and_expired_scopes(
    batch: bool, operation: str
) -> None:
    from concurrent.futures import ThreadPoolExecutor
    from dataclasses import replace

    registry = _registry()
    token = _batch(registry) if batch else _prepare(registry)
    with _scope(registry, token) as claim:
        with pytest.raises(StateError, match="active preparation scope"):
            getattr(replace(claim), operation)()
        with ThreadPoolExecutor(max_workers=1) as pool:
            with pytest.raises(StateError, match="active preparation scope"):
                pool.submit(getattr(claim, operation)).result(timeout=2)
    with pytest.raises(StateError, match="active preparation scope"):
        getattr(claim, operation)()


@pytest.mark.parametrize("batch", [False, True])
def test_lost_counter_finalization_return_preserves_committed_proof(
    batch: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry = _registry()
    token = _batch(registry) if batch else _prepare(registry)
    method = "_finalize_claimed_batch" if batch else "_finalize_claimed_delivery"
    original = getattr(ESCollectorRegistry, method)

    def fail_after(owner: ESCollectorRegistry, claim: object) -> None:
        original(owner, claim)
        raise RuntimeError("lost counter acknowledgement")

    monkeypatch.setattr(ESCollectorRegistry, method, fail_after)
    with pytest.raises(RuntimeError, match="lost counter acknowledgement"):
        with _scope(registry, token) as claim:
            claim.apply_provisional()
            claim.finalize_no_fail()
    assert _completed(registry, token) is not None
    before = registry.snapshot()
    monkeypatch.setattr(ESCollectorRegistry, method, original)
    with _scope(registry, token) as claim:
        claim.commit_no_fail()
    assert registry.snapshot() == before
