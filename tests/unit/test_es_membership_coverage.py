# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from dataclasses import replace
from datetime import timedelta

import pytest
from pydantic import ValidationError

from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.es_collector import ESCollectorClosure, ESCollectorRegistry
from evidenceforge.events.es_membership import ESClientMembershipCoverage
from evidenceforge.events.macos_process_observation import MacosProcessCollectionObservation
from evidenceforge.events.observation import ObservationDecision
from evidenceforge.generation.actions.es_collection import ESCollectionActionOwner
from evidenceforge.generation.checkpoints.dispatcher_observation_head import (
    DispatcherObservationParticipant,
)
from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError
from evidenceforge.generation.checkpoints.packed import dumps, loads
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit import test_macos_es_exec_preparation as native_exec
from tests.unit.test_es_collector import _profile
from tests.unit.test_es_collector_ownership import _prepare, _setup
from tests.unit.test_process_execution_state import _START


def _coverage(hostname: str = "MAC-A", **changes: object) -> ESClientMembershipCoverage:
    return ESClientMembershipCoverage.model_validate(
        dict(hostname=hostname, known_from=_START, known_until=_START + timedelta(hours=1))
        | changes
    )


@pytest.mark.parametrize("change", ["blank", "naive", "empty", "reversed", "unknown"])
def test_coverage_requires_exact_host_and_finite_ordered_bounds(change: str) -> None:
    changes = {
        "blank": {"hostname": "   "},
        "naive": {"known_from": _START.replace(tzinfo=None)},
        "empty": {"known_until": _START},
        "reversed": {"known_until": _START - timedelta(seconds=1)},
        "unknown": {"extra": True},
    }
    with pytest.raises(ValidationError):
        _coverage(**changes[change])


def test_negative_knowledge_requires_explicit_complete_host_and_half_open_window() -> None:
    _, process, owner, profile = _setup()
    other = profile.process.model_copy(update={"object_id": "another-execution"})
    registry = owner.collectors
    assert registry.known_client_membership(process.hostname, other, _START) is None
    bounds = _coverage(process.hostname, known_from=_START + timedelta(seconds=1))
    owner.declare_complete_membership(bounds)
    assert registry.known_client_membership(process.hostname, other, _START) is None
    assert registry.known_client_membership(process.hostname, other, bounds.known_from) is False
    assert registry.known_client_membership(process.hostname, other, bounds.known_until) is None
    assert registry.known_client_membership("other-host", other, bounds.known_from) is None
    assert registry.known_client_membership(process.hostname, profile.process, _START) is True
    assert (
        registry.known_client_membership(process.hostname, profile.process, bounds.known_until)
        is True
    )
    with pytest.raises(StateError, match="precede"):
        registry.known_client_membership(process.hostname, other, _START - timedelta(seconds=1))


def test_closed_client_is_negative_only_inside_declared_inventory() -> None:
    _, process, owner, profile = _setup()
    owner.declare_complete_membership(_coverage(process.hostname))
    at = _START + timedelta(seconds=5)
    before = owner.observe_process_collection(process, observed_at=_START, terminal="absent")
    assert before.is_es_client
    owner.close(profile, process, at)
    observed = owner.observe_process_collection(process, observed_at=at, terminal="absent")
    assert not observed.is_es_client and observed.terminal == "absent"
    owner.validate_client_observation(observed)
    with pytest.raises(StateError, match="contradicts"):
        owner.validate_client_observation(replace(observed, is_es_client=True))
    with pytest.raises(StateError, match="known client"):
        owner.observe_process_collection(
            process, observed_at=_START + timedelta(hours=1), terminal="absent"
        )
    with pytest.raises(StateError, match="live Mac"):
        owner.observe_process_collection(
            replace(process, object_id="foreign", primary_thread=None),
            observed_at=at,
            terminal="absent",
        )


def test_empty_explicit_inventory_can_produce_nonclient_facts_for_live_process() -> None:
    state, process, _, _ = _setup()
    owner = ESCollectionActionOwner(state, ESCollectorRegistry())
    with pytest.raises(StateError, match="known client"):
        owner.observe_process_collection(process, observed_at=_START, terminal="absent")
    owner.declare_complete_membership(_coverage(process.hostname))
    observed = owner.observe_process_collection(process, observed_at=_START, terminal="absent")
    assert observed == MacosProcessCollectionObservation(process, _START, False, "absent")
    with pytest.raises(StateError, match="already declared"):
        owner.declare_complete_membership(_coverage(process.hostname))
    with pytest.raises(StateError, match="initialized Mac"):
        owner.declare_complete_membership(_coverage("unknown"))


def test_unknown_legacy_clients_cannot_coexist_with_complete_inventory() -> None:
    registry = ESCollectorRegistry()
    registry.open(_profile())
    with pytest.raises(StateError, match="unknown owners"):
        registry.declare_complete_membership(_coverage())
    registry = ESCollectorRegistry()
    registry.declare_complete_membership(_coverage())
    with pytest.raises(StateError, match="exact connection owners"):
        registry.open(_profile())
    assert registry.snapshot() == ()


def test_restart_retires_negative_history_without_affecting_other_hosts() -> None:
    _, process, owner, profile = _setup()
    owner.declare_complete_membership(_coverage(process.hostname))
    owner.collectors.declare_complete_membership(_coverage("other-host"))
    other = profile.process.model_copy(update={"object_id": "another"})
    at = _START + timedelta(seconds=10)
    owner.close(profile, process, at)
    replacement = owner.open(
        _profile(
            hostname=process.hostname,
            generation=2,
            opened_at=at + timedelta(seconds=1),
            last_delivery_at=at + timedelta(seconds=1),
        ),
        process,
    )
    assert owner.collectors.known_client_membership(process.hostname, other, at) is None
    assert owner.collectors.known_client_membership(process.hostname, profile.process, at) is None
    assert (
        owner.collectors.known_client_membership(process.hostname, other, replacement.opened_at)
        is False
    )
    assert (
        owner.collectors.known_client_membership(
            process.hostname, profile.process, replacement.opened_at
        )
        is True
    )
    assert owner.collectors.known_client_membership("other-host", other, _START) is False
    recovered = ESCollectorRegistry()
    recovered.restore(*owner.collectors.snapshot_with_membership())
    assert recovered.known_client_membership(process.hostname, other, at) is None
    assert (
        recovered.known_client_membership(process.hostname, other, replacement.opened_at) is False
    )
    with pytest.raises(StateError, match="discarded epochs"):
        fresh = ESCollectorRegistry()
        fresh.restore((replacement,))
        fresh.declare_complete_membership(_coverage(process.hostname))


def test_restart_beyond_coverage_discards_completeness() -> None:
    _, process, owner, profile = _setup()
    owner.declare_complete_membership(_coverage(process.hostname))
    at = _START + timedelta(hours=1)
    owner.close(profile, process, at)
    owner.open(
        _profile(
            hostname=process.hostname,
            generation=2,
            opened_at=at + timedelta(seconds=1),
            last_delivery_at=at + timedelta(seconds=1),
        ),
        process,
    )
    assert owner.collectors.snapshot_with_membership()[1] == ()


def test_delivered_history_blocks_backdated_inventory_and_connection_transitions() -> None:
    _, process, owner, profile = _setup()
    owner.declare_complete_membership(_coverage(process.hostname))
    other = owner.open(_profile(source_instance="other", hostname=process.hostname), process)
    owner.commit(_prepare(owner, process), process)
    before = owner.collectors.snapshot_with_membership()
    with pytest.raises(StateError, match="backdate"):
        owner.open(_profile(source_instance="another", hostname=process.hostname), process)
    with pytest.raises(StateError, match="backdate"):
        owner.open(
            _profile(
                source_instance="another",
                hostname=process.hostname,
                opened_at=_START + timedelta(seconds=5),
                last_delivery_at=_START + timedelta(seconds=5),
            ),
            process,
        )
    with pytest.raises(StateError, match="backdate"):
        owner.close(other, process, _START + timedelta(seconds=4))
    assert owner.collectors.snapshot_with_membership() == before
    _, process, owner, _ = _setup()
    owner.commit(_prepare(owner, process), process)
    with pytest.raises(StateError, match="delivered history"):
        owner.declare_complete_membership(_coverage(process.hostname))


def test_declaration_cannot_race_same_host_delivery_or_closure() -> None:
    _, process, owner, profile = _setup()
    token = _prepare(owner, process)
    with pytest.raises(StateError, match="quiescent"):
        owner.declare_complete_membership(_coverage(process.hostname))
    owner.collectors.cancel(token)
    with owner.collectors.prepared_closures(
        (ESCollectorClosure(before=profile, closed_at=_START + timedelta(seconds=1)),)
    ):
        with pytest.raises(StateError, match="quiescent"):
            owner.declare_complete_membership(_coverage(process.hostname))
    owner.declare_complete_membership(_coverage(process.hostname))


def test_atomic_checkpoint_retains_complete_inventory_and_legacy_heads_stay_unknown() -> None:
    state, process, owner, profile = _setup()
    owner.declare_complete_membership(_coverage(process.hostname))
    dispatcher = EventDispatcher(state, {})
    dispatcher.es_collectors = owner.collectors
    payload = DispatcherObservationParticipant(dispatcher).prepare_checkpoint(1).head.payload
    document = loads(payload)
    assert document["schema_version"] == "6"
    restored = EventDispatcher(StateManager(), {})
    DispatcherObservationParticipant(restored).restore_checkpoint(payload, ())
    assert (
        restored.es_collectors.snapshot_with_membership()
        == owner.collectors.snapshot_with_membership()
    )
    other = profile.process.model_copy(update={"object_id": "another"})
    assert restored.es_collectors.known_client_membership(process.hostname, other, _START) is False
    document["schema_version"] = "4"
    DispatcherObservationParticipant(restored).restore_checkpoint(dumps(document), ())
    assert restored.es_collectors.known_client_membership(process.hostname, other, _START) is False
    document["schema_version"] = "3"
    with pytest.raises(CheckpointCorruptionError, match="collector"):
        DispatcherObservationParticipant(restored).restore_checkpoint(dumps(document), ())
    document.pop("es_membership")
    DispatcherObservationParticipant(restored).restore_checkpoint(dumps(document), ())
    assert restored.es_collectors.known_client_membership(process.hostname, other, _START) is None
    assert (
        restored.es_collectors.known_client_membership(process.hostname, profile.process, _START)
        is True
    )


@pytest.mark.parametrize(
    "defect", ["duplicate", "unsorted", "unbound", "lost_history", "wrong_type"]
)
def test_corrupt_membership_restore_rejects_before_mutation(defect: str) -> None:
    _, process, owner, profile = _setup()
    states = (profile,)
    bounds = _coverage(process.hostname)
    membership = (bounds,)
    if defect == "duplicate":
        membership = (bounds, bounds)
    elif defect == "unsorted":
        membership = (_coverage("zzz"), bounds)
    elif defect == "unbound":
        states = (profile.model_copy(update={"process": None}),)
    elif defect == "lost_history":
        states = (
            profile.model_copy(
                update={
                    "generation": 2,
                    "opened_at": _START + timedelta(seconds=1),
                    "last_delivery_at": _START + timedelta(seconds=1),
                }
            ),
        )
    else:
        membership = (object(),)
    restored = ESCollectorRegistry()
    with pytest.raises(StateError):
        restored.restore(states, membership)
    assert restored.snapshot_with_membership() == ((), ())


def test_native_exec_rejects_positive_target_contradicted_by_complete_inventory() -> None:
    fixture = native_exec._fixture()
    # The fixture already reserved a delivery; declare the inventory at a
    # quiescent point, then reconstruct its exact native reservation.
    request = fixture.delivery.observation
    fixture.owner.collectors.cancel(fixture.delivery)

    fixture.owner.declare_complete_membership(_coverage(fixture.before.process.hostname))
    fixture.delivery = fixture.owner.prepare(
        source_instance=request.source_instance,
        process=fixture.collector,
        generation=request.generation,
        delivery=request.delivery,
        occurrence_id=request.occurrence_id,
        event_type=request.event_type,
        observed_at=request.observed_at,
        decision=ObservationDecision(request.status, request.delay),
    )
    fixture.after = replace(fixture.after, is_es_client=True)
    before = fixture.owner.state.materialization_digest()
    with pytest.raises(StateError, match="contradicts"):
        with native_exec._prepare(fixture):
            pytest.fail("positive target was admitted without a modeled connection")
    assert fixture.owner.state.materialization_digest() == before
    fixture.after = replace(fixture.after, is_es_client=False)
    with native_exec._prepare(fixture) as prepared:
        assert '"is_es_client":false' in prepared.ndjson
    fixture.owner.collectors.cancel(fixture.delivery)


def test_provisional_disconnect_restores_membership_on_outer_rollback() -> None:
    _, process, owner, profile = _setup()
    owner.declare_complete_membership(_coverage(process.hostname))
    at = _START + timedelta(seconds=2)
    before = owner.collectors.snapshot_with_membership()
    with owner.collectors.prepared_closures(
        (ESCollectorClosure(before=profile, closed_at=at),)
    ) as claim:
        claim.apply_provisional()
        assert (
            owner.collectors.known_client_membership(process.hostname, profile.process, at) is False
        )
    assert owner.collectors.snapshot_with_membership() == before
    assert owner.collectors.known_client_membership(process.hostname, profile.process, at) is True


@pytest.mark.parametrize("complete", [False, True])
def test_completed_native_proof_survives_restart_but_pending_proof_does_not(complete: bool) -> None:
    _, process, owner, profile = _setup()
    owner.declare_complete_membership(_coverage(process.hostname))
    owner.open(_profile(source_instance="other", hostname=process.hostname), process)
    token = _prepare(owner, process)
    with owner.prepared_commit(token, process) as claim:
        frozen = claim.freeze_native_projection("{}\n")
        if complete:
            claim.commit_no_fail()
    at = _START + timedelta(seconds=6)
    owner.open(
        _profile(
            source_instance="other",
            hostname=process.hostname,
            generation=2,
            opened_at=at,
            last_delivery_at=at,
        ),
        process,
    )
    if complete:
        assert owner.collectors.retained_native_projection(token) == frozen
        assert owner.commit(token, process) == token.observation
    else:
        with pytest.raises(StateError):
            owner.collectors.retained_native_projection(token)
        with pytest.raises(StateError):
            owner.commit(token, process)
        owner.collectors.cancel(token)
