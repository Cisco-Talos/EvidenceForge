# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from datetime import timedelta

import pytest

from evidenceforge.events.es_collector import ESCollectorRegistry, ESDeliveryRequest
from evidenceforge.events.es_membership import ESClientMembershipCoverage
from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.observation import ObservationDecision
from evidenceforge.generation.actions.es_collection import ESCollectionActionOwner
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_es_collector import _profile
from tests.unit.test_process_execution_state import _START, _process


def _inventory() -> tuple[
    StateManager, ProcessIdentity, ESCollectionActionOwner, ESClientMembershipCoverage
]:
    state, process = _process()
    owner = ESCollectionActionOwner(state, ESCollectorRegistry())
    coverage = ESClientMembershipCoverage(
        hostname=process.hostname, known_from=_START, known_until=_START + timedelta(hours=1)
    )
    return state, process, owner, coverage


@pytest.mark.parametrize("empty", [False, True])
def test_complete_inventory_is_atomic_idempotent_and_restorable(empty: bool) -> None:
    _, process, owner, coverage = _inventory()
    clients = () if empty else ((_profile(hostname=process.hostname), process),)
    result = owner.initialize_inventory(coverage, clients)
    assert len(result) == (0 if empty else 1)
    assert owner.initialize_inventory(coverage, clients) == result
    snapshot = owner.collectors.snapshot_with_membership()
    restored = ESCollectorRegistry()
    restored.restore(*snapshot)
    assert restored.snapshot_with_membership() == snapshot
    from evidenceforge.generation.actions.es_collection import _process as collector_process

    assert restored.known_client_membership(
        process.hostname, collector_process(process), _START
    ) is (not empty)


@pytest.mark.parametrize(
    "damage", ["foreign", "later", "generation", "duplicate", "missing_owner", "linux"]
)
def test_invalid_initial_client_never_publishes_partial_completeness(damage: str) -> None:
    state, process, owner, coverage = _inventory()
    first = _profile(hostname=process.hostname)
    second = _profile(hostname=process.hostname, source_instance="invented-second")
    selected = process
    if damage == "foreign":
        second = second.model_copy(update={"hostname": "OTHER"})
    elif damage == "later":
        second = second.model_copy(
            update={
                "opened_at": _START + timedelta(seconds=1),
                "last_delivery_at": _START + timedelta(seconds=1),
            }
        )
    elif damage == "generation":
        second = second.model_copy(update={"generation": 2})
    elif damage == "duplicate":
        second = first
    elif damage == "missing_owner":
        selected = None
    else:
        state._pid_os[process.hostname] = "linux"
    before = owner.collectors.snapshot_with_membership()
    with pytest.raises((StateError, ValueError)):
        owner.initialize_inventory(coverage, ((first, process), (second, selected)))
    assert owner.collectors.snapshot_with_membership() == before


def test_initialization_cannot_reset_delivery_history() -> None:
    _, process, owner, coverage = _inventory()
    clients = ((_profile(hostname=process.hostname), process),)
    owner.initialize_inventory(coverage, clients)
    token = owner.prepare(
        source_instance="mac-a:es-client",
        process=process,
        generation=1,
        delivery=0,
        occurrence_id="invented",
        event_type=1,
        observed_at=_START + timedelta(seconds=1),
        decision=ObservationDecision("visible"),
    )
    owner.commit(token, process)
    before = owner.collectors.snapshot_with_membership()
    with pytest.raises(StateError, match="history"):
        owner.initialize_inventory(coverage, clients)
    assert owner.collectors.snapshot_with_membership() == before


@pytest.mark.parametrize("close", [False, True])
@pytest.mark.parametrize("offset", [-1, 0, 1])
def test_observer_retires_at_its_transition_without_fake_delivery_or_loss(
    close: bool, offset: int
) -> None:
    state, process, owner, coverage = _inventory()
    owner.initialize_inventory(coverage, ((_profile(hostname=process.hostname), process),))
    builder = state.begin_action_cohort_materialization()
    boundary = _START + timedelta(seconds=10)
    if close:
        builder.terminate_process(process, end_time=boundary)
    else:
        builder.execute_process(
            process, image="/bin/true", command_line="true", executed_at=boundary
        )
    cohort = builder.seal()
    before = owner.collectors.snapshot_with_membership()
    request = ESDeliveryRequest(
        occurrence_id="invented-self-transition",
        event_type=1,
        observed_at=boundary + timedelta(seconds=offset),
        decision=ObservationDecision("visible"),
    )
    delivery = owner.prepare_observable(
        cohort,
        source_instance="mac-a:es-client",
        process=process,
        generation=1,
        delivery=0,
        request=request,
    )
    if offset < 0:
        assert delivery is not None
        owner.validate_observing_cohort(cohort, process, observed_at=request.observed_at)
        owner.collectors.cancel(delivery)
    else:
        assert delivery is None
        with pytest.raises(StateError, match="same observing"):
            owner.validate_observing_cohort(cohort, process, observed_at=request.observed_at)
    assert owner.collectors.snapshot_with_membership() == before


def test_distinct_surviving_observer_can_collect_another_clients_exit() -> None:
    state, process, owner, coverage = _inventory()
    owner.initialize_inventory(coverage, ((_profile(hostname=process.hostname), process),))
    builder = state.begin_action_cohort_materialization()
    other = builder.fork_process(process, forked_at=_START + timedelta(seconds=1))
    state.materialize_action_cohort(builder.seal())
    owner.open(
        _profile(
            hostname=process.hostname,
            source_instance="other-client",
            opened_at=_START + timedelta(seconds=2),
            last_delivery_at=_START + timedelta(seconds=2),
        ),
        other.identity,
    )
    builder = state.begin_action_cohort_materialization()
    builder.terminate_process(process, end_time=_START + timedelta(seconds=10))
    cohort = builder.seal()
    request = ESDeliveryRequest(
        occurrence_id="invented-client-exit",
        event_type=1,
        observed_at=_START + timedelta(seconds=10),
        decision=ObservationDecision("visible"),
    )
    delivery = owner.prepare_observable(
        cohort,
        source_instance="other-client",
        process=other.identity,
        generation=1,
        delivery=0,
        request=request,
    )
    assert delivery is not None
    owner.collectors.cancel(delivery)


def test_pending_initial_inventory_retry_cannot_rewrite_reservation() -> None:
    _, process, owner, coverage = _inventory()
    clients = ((_profile(hostname=process.hostname), process),)
    (profile,) = owner.initialize_inventory(coverage, clients)
    delivery = owner.prepare(
        source_instance=profile.source_instance,
        process=process,
        generation=1,
        delivery=0,
        occurrence_id="invented-pending",
        event_type=1,
        observed_at=_START + timedelta(seconds=1),
        decision=ObservationDecision("visible"),
    )
    with pytest.raises(StateError, match="history"):
        owner.initialize_inventory(coverage, clients)
    assert owner.collectors.authenticates_pending_delivery(delivery)
    owner.collectors.cancel(delivery)
    assert owner.initialize_inventory(coverage, clients) == (profile,)
