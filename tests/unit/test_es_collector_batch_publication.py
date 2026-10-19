# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Batch cleanup uses exact ownership even when caller-held facts are damaged."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

from evidenceforge.events.es_collector import ESDeliveryBatchPreparation
from evidenceforge.models.exceptions import StateError
from tests.unit.test_es_collector import _profile, _registry
from tests.unit.test_es_collector_batch import _prepare


@pytest.mark.parametrize("damage", ["source", "sequence", "empty", "list", "member", "native"])
def test_changed_batch_facts_reject_publication_but_do_not_strand_cleanup(damage: str) -> None:
    registry = _registry()
    batch = _prepare(registry)
    before = registry.connection("mac-a:es-client")
    if damage == "source":
        object.__setattr__(batch.observations[0], "source_instance", "invented-other-client")
    elif damage == "sequence":
        object.__setattr__(batch.observations[-1], "seq_num", 999)
    elif damage == "empty":
        object.__setattr__(batch, "observations", ())
    elif damage == "list":
        object.__setattr__(batch, "observations", list(batch.observations))
    elif damage == "member":
        object.__setattr__(batch, "observations", (None,))
    else:
        object.__setattr__(batch, "_native_projection", object())
    assert registry.owns_pending_batch(batch)
    assert not registry.authenticates_pending_batch(batch)
    with pytest.raises(StateError):
        registry.commit_batch(batch)
    registry.cancel_batch(batch)
    assert registry.snapshot() == (before,)
    retry = _prepare(registry)
    registry.cancel_batch(retry)


@pytest.mark.parametrize("copy_kind", ["copy", "foreign", "wrong-type"])
def test_batch_queries_and_cancellation_cannot_claim_another_reservation(copy_kind: str) -> None:
    registry = _registry()
    batch = _prepare(registry)
    candidate = (
        replace(batch)
        if copy_kind == "copy"
        else _prepare(_registry())
        if copy_kind == "foreign"
        else object()
    )
    assert registry.owns_pending_batch(batch)
    assert registry.authenticates_pending_batch(batch)
    assert not registry.owns_pending_batch(candidate)
    assert not registry.authenticates_pending_batch(candidate)
    with pytest.raises(StateError):
        registry.cancel_batch(candidate)
    assert registry.authenticates_pending_batch(batch)
    registry.cancel_batch(batch)
    assert not registry.owns_pending_batch(batch)
    assert not registry.authenticates_pending_batch(batch)


def test_changed_locator_does_not_cancel_another_clients_batch() -> None:
    registry = _registry()
    registry.open(_profile(source_instance="mac-a:other-client"))
    first = _prepare(registry)
    second = _prepare(registry, source_instance="mac-a:other-client")
    object.__setattr__(first.observations[0], "source_instance", "mac-a:other-client")
    registry.cancel_batch(first)
    assert registry.authenticates_pending_batch(second)
    assert registry.connection("mac-a:es-client") == _profile()
    registry.cancel_batch(second)
    assert len(registry.snapshot()) == 2


def test_claimed_batch_cannot_be_cancelled_even_with_a_changed_locator() -> None:
    registry = _registry()
    batch = _prepare(registry)
    with registry.prepared_batch(batch):
        object.__setattr__(batch.observations[0], "source_instance", "invented-other-client")
        with pytest.raises(StateError, match="unclaimed"):
            registry.cancel_batch(batch)
        assert registry.owns_pending_batch(batch)
    registry.cancel_batch(batch)
    assert registry.snapshot() == (_profile(),)


def test_batch_publication_token_is_scoped_and_authenticates_frozen_order() -> None:
    registry = _registry()
    batch = _prepare(registry)
    rows = ('{"one":1}\n', '{"two":2}\n', '{"three":3}\n')
    with registry.prepared_batch(batch) as claimed:
        before = claimed.publication_token
        assert len(before) == 64
        claimed.freeze_native_projections(rows, canonical_token="a" * 64)
        frozen = claimed.publication_token
        assert frozen != before
        assert registry.authenticates_pending_batch(batch)
        with pytest.raises(StateError, match="active preparation"):
            _ = replace(claimed).publication_token
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(lambda: claimed.publication_token)
            with pytest.raises(StateError, match="active preparation"):
                future.result()
        claimed.apply_provisional()
        assert claimed.publication_token == frozen
        claimed.finalize_no_fail()
        assert claimed.publication_token == frozen
        assert not registry.owns_pending_batch(batch)
        assert not registry.authenticates_pending_batch(batch)
    assert registry.completed_batch(batch) == batch.observations
    with pytest.raises(StateError, match="active preparation"):
        _ = claimed.publication_token
    with registry.prepared_batch(batch) as replay:
        assert replay.publication_token == frozen
        replay.commit_no_fail()
    assert registry.retained_native_batch_projection(batch, canonical_token="a" * 64) == rows
    with pytest.raises(StateError, match="stale"):
        registry.cancel_batch(batch)


@pytest.mark.parametrize("bad", [None, (), [], ESDeliveryBatchPreparation(())])
def test_pending_batch_query_rejects_missing_or_unshaped_capabilities(bad: object) -> None:
    registry = _registry()
    assert not registry.owns_pending_batch(bad)
    assert not registry.authenticates_pending_batch(bad)
