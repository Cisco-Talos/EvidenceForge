# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Pending native facts retain modeled membership; completed facts remain historical."""

from datetime import timedelta

import pytest

from evidenceforge.events.es_collector import ESCollectorClosure, ESCollectorProcess
from evidenceforge.models.exceptions import StateError
from tests.unit.test_es_collector import _prepare, _profile, _registry
from tests.unit.test_es_collector_batch import _prepare as prepare_batch
from tests.unit.test_process_execution_state import _START


def _client(registry: object, *, hostname: str = "MAC-A", known: bool = True) -> object:
    profile = _profile(
        source_instance=f"{hostname}:other-client",
        hostname=hostname,
        process=ESCollectorProcess(
            object_id="invented-process",
            pid=77,
            started_at=_START,
            execution_ordinal=0,
            execution_started_at=_START,
        )
        if known
        else None,
    )
    registry.open(profile)
    return profile


def _scope(registry: object, cap: object, batch: bool) -> object:
    return registry.prepared_batch(cap) if batch else registry.prepared_delivery(cap)


def _frozen(registry: object, batch: bool) -> tuple:
    cap = prepare_batch(registry) if batch else _prepare(registry)
    rows = tuple(
        '{"invented":' + str(index) + "}\n"
        for index in range(len(cap.observations) if batch else 1)
    )
    with _scope(registry, cap, batch) as claim:
        if batch:
            claim.freeze_native_projections(rows)
        else:
            claim.freeze_native_projection(rows[0])
    return cap, rows


def _retained(registry: object, cap: object, batch: bool) -> tuple[str, ...]:
    return (
        registry.retained_native_batch_projection(cap)
        if batch
        else (registry.retained_native_projection(cap),)
    )


def _pending(registry: object, cap: object, batch: bool) -> bool:
    return (
        registry.authenticates_pending_batch(cap)
        if batch
        else registry.authenticates_pending_delivery(cap)
    )


def _cancel(registry: object, cap: object, batch: bool) -> None:
    if batch:
        registry.cancel_batch(cap)
    else:
        registry.cancel(cap)


@pytest.mark.parametrize("batch", [False, True])
@pytest.mark.parametrize("change", ["open", "close", "restart"])
def test_changed_same_host_membership_invalidates_pending_bytes_without_losing_cleanup(
    batch: bool, change: str
) -> None:
    registry = _registry()
    client = _client(registry) if change != "open" else None
    cap, _ = _frozen(registry, batch)
    before = registry.connection("mac-a:es-client")
    if change == "open":
        _client(registry)
    elif change == "close":
        registry.close(client, _START + timedelta(seconds=3))
    else:
        registry.open(
            client.model_copy(
                update={
                    "generation": 2,
                    "opened_at": _START + timedelta(seconds=3),
                    "last_delivery_at": _START + timedelta(seconds=3),
                }
            )
        )
    assert not _pending(registry, cap, batch)
    with pytest.raises(StateError):
        _retained(registry, cap, batch)
    with pytest.raises(StateError):
        with _scope(registry, cap, batch) as claim:
            claim.commit_no_fail()
    assert registry.connection(before.source_instance) == before
    _cancel(registry, cap, batch)
    assert registry.snapshot()


@pytest.mark.parametrize("batch", [False, True])
@pytest.mark.parametrize("change", ["other_host", "unknown_owner", "counters"])
def test_independent_hosts_unbound_profiles_and_counter_progress_preserve_native_facts(
    batch: bool, change: str
) -> None:
    registry = _registry()
    client = _client(registry) if change == "counters" else None
    cap, rows = _frozen(registry, batch)
    if change == "other_host":
        _client(registry, hostname="OTHER-MAC")
    elif change == "unknown_owner":
        _client(registry, known=False)
    else:
        registry.commit(_prepare(registry, source_instance=client.source_instance))
    assert _pending(registry, cap, batch)
    with _scope(registry, cap, batch) as claim:
        claim.commit_no_fail()
    assert _retained(registry, cap, batch) == rows


@pytest.mark.parametrize("batch", [False, True])
def test_membership_changed_inside_claim_rejects_before_provisional_counter_application(
    batch: bool,
) -> None:
    registry = _registry()
    cap, _ = _frozen(registry, batch)
    before = registry.connection("mac-a:es-client")
    with _scope(registry, cap, batch) as claim:
        _client(registry)
        with pytest.raises(StateError, match="membership changed"):
            claim.apply_provisional()
    assert registry.connection(before.source_instance) == before
    _cancel(registry, cap, batch)


@pytest.mark.parametrize("batch", [False, True])
def test_completed_native_facts_survive_later_membership_changes_and_retry(batch: bool) -> None:
    registry = _registry()
    cap, rows = _frozen(registry, batch)
    with _scope(registry, cap, batch) as claim:
        claim.commit_no_fail()
    before = registry.connection("mac-a:es-client")
    _client(registry)
    assert _retained(registry, cap, batch) == rows
    with _scope(registry, cap, batch) as claim:
        if batch:
            assert claim.freeze_native_projections(rows) == rows
        else:
            assert claim.freeze_native_projection(rows[0]) == rows[0]
        claim.commit_no_fail()
    assert registry.connection(before.source_instance) == before


@pytest.mark.parametrize("batch", [False, True])
def test_rolled_back_disconnect_restores_pending_native_membership_proof(batch: bool) -> None:
    registry = _registry()
    client = _client(registry)
    cap, rows = _frozen(registry, batch)
    request = ESCollectorClosure(before=client, closed_at=_START + timedelta(seconds=3))
    with registry.prepared_closures((request,)) as claim:
        claim.apply_provisional()
        assert not _pending(registry, cap, batch)
    assert _pending(registry, cap, batch)
    assert _retained(registry, cap, batch) == rows
    _cancel(registry, cap, batch)


@pytest.mark.parametrize("batch", [False, True])
def test_membership_fingerprint_is_authenticated_even_for_completed_records(batch: bool) -> None:
    registry = _registry()
    cap, _ = _frozen(registry, batch)
    with _scope(registry, cap, batch) as claim:
        claim.commit_no_fail()
    object.__setattr__(cap._native_projection, "membership", b"x" * 32)
    with pytest.raises(StateError):
        _retained(registry, cap, batch)
    with pytest.raises(StateError):
        with _scope(registry, cap, batch) as claim:
            claim.commit_no_fail()
