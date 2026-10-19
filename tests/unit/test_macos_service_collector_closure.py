# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Service/leader closure preserves exact collector ownership in the same transaction."""

from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.es_collector import ESCollectorRegistry
from evidenceforge.generation.actions.es_collection import ESCollectionActionOwner
from evidenceforge.models.exceptions import StateError
from tests.unit.test_es_collector import _profile
from tests.unit.test_service_group_closure import _owned_group


def _bound() -> tuple:
    state, registry, authority, adapter, group, plan, request = _owned_group()
    collectors = ESCollectorRegistry()
    owner = ESCollectionActionOwner(state, collectors)
    profiles = tuple(
        owner.open(
            _profile(
                source_instance=f"group-client-{index}",
                hostname=terminal.identity.hostname,
                opened_at=terminal.identity.execution_started_at,
                last_delivery_at=terminal.identity.execution_started_at,
            ),
            terminal.identity,
        )
        for index, terminal in enumerate(plan.process_terminations)
    )
    return state, registry, authority, adapter, group, plan, request, owner, profiles


def _commit(fixture: tuple) -> object:
    _, _, authority, adapter, group, plan, request, owner, _ = fixture
    return authority.materialize_process_group_service_closure_composite(
        plan, group, adapter.prepare_service_process_closure(request), collectors=owner.collectors
    )


def test_service_group_closure_authenticates_collector_completion_with_its_process_receipt() -> (
    None
):
    fixture = _bound()
    state, registry, authority, adapter, _, plan, _, owner, profiles = fixture
    proof = _commit(fixture)
    assert len(proof.collector_publication_token) == 64
    for terminal, profile in zip(plan.process_terminations, profiles, strict=True):
        assert state.get_process(terminal.identity.hostname, terminal.identity.pid) is None
        assert registry.get_process(terminal.identity.object_id).closed_at == terminal.end_time
        after = owner.collectors.connection(profile.source_instance)
        assert after.closed_at == terminal.end_time and after.next_delivery == profile.next_delivery
        assert authority.authenticates_process_service_closure_composite_receipt(
            terminal.target, proof
        )
        assert not authority.authenticates_process_service_closure_composite_receipt(
            terminal.target, replace(proof, collector_publication_token="0" * 64)
        )
    assert adapter.service_preparation_census().reserved_keys == 0


@pytest.mark.parametrize("stage", ["precommit", "collector_apply"])
def test_service_group_failure_before_irreversible_commit_restores_every_owner(
    monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    fixture = _bound()
    state, registry, authority, adapter, _, plan, _, owner, _ = fixture
    before = state.materialization_digest()
    connections = owner.collectors.snapshot()
    if stage == "precommit":

        def fail() -> None:
            raise RuntimeError("injected group precommit failure")

        authority._materialization_precommit_hook = fail
    else:
        original = ESCollectorRegistry._apply_closures

        def fail(registry: ESCollectorRegistry, handle: object) -> None:
            original(registry, handle)
            raise RuntimeError("injected group provisional failure")

        monkeypatch.setattr(ESCollectorRegistry, "_apply_closures", fail)
    with pytest.raises(RuntimeError, match="injected group"):
        _commit(fixture)
    assert state.materialization_digest() == before
    assert owner.collectors.snapshot() == connections
    assert all(
        registry.get_process(item.identity.object_id).closed_at is None
        for item in plan.process_terminations
    )
    assert adapter.service_preparation_census().reserved_keys == 0


@pytest.mark.parametrize("stage", ["service", "collector_finalize", "state_finalize"])
def test_lost_composite_acknowledgement_finishes_all_owners_and_retains_exact_proof(
    monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    from evidenceforge.generation.state_manager import PreparedActionCohortMaterialization

    fixture = _bound()
    state, registry, authority, adapter, _, plan, _, owner, profiles = fixture
    if stage == "service":
        original = registry._service_closure_receipt_locked

        def fail(commit_plan: object) -> None:
            original(commit_plan)
            raise RuntimeError("injected lost group acknowledgement")

        monkeypatch.setattr(registry, "_service_closure_receipt_locked", fail)
    elif stage == "collector_finalize":
        original = ESCollectorRegistry._finalize_closures

        def fail(registry: ESCollectorRegistry, handle: object) -> None:
            original(registry, handle)
            raise RuntimeError("injected lost group acknowledgement")

        monkeypatch.setattr(ESCollectorRegistry, "_finalize_closures", fail)
    else:
        original = PreparedActionCohortMaterialization.finalize_no_fail

        def fail(prepared: PreparedActionCohortMaterialization) -> None:
            original(prepared)
            raise RuntimeError("injected lost group acknowledgement")

        monkeypatch.setattr(PreparedActionCohortMaterialization, "finalize_no_fail", fail)
    with pytest.raises(RuntimeError, match="lost group acknowledgement") as caught:
        _commit(fixture)
    proof = caught.value.process_group_service_receipt
    assert proof.collector_publication_token
    assert all(
        state.get_process(item.identity.hostname, item.identity.pid) is None
        for item in plan.process_terminations
    )
    assert all(
        owner.collectors.connection(item.source_instance).closed_at is not None for item in profiles
    )
    assert all(
        authority.authenticates_process_service_closure_composite_receipt(item.target, proof)
        for item in plan.process_terminations
    )
    assert adapter.service_preparation_census().reserved_keys == 0


@pytest.mark.parametrize("pending", [False, True])
def test_unsettled_or_future_deliveries_block_service_closure_before_any_mutation(
    pending: bool,
) -> None:
    from evidenceforge.events.observation import ObservationDecision

    fixture = _bound()
    state, registry, _, adapter, _, plan, _, owner, profiles = fixture
    first = plan.process_terminations[0]
    delivery = owner.prepare(
        source_instance=profiles[0].source_instance,
        process=first.identity,
        generation=1,
        delivery=0,
        occurrence_id="invented-delivery",
        event_type=1,
        observed_at=first.end_time + timedelta(seconds=-1 if pending else 1),
        decision=ObservationDecision("visible"),
    )
    if not pending:
        owner.commit(delivery, first.identity)
    before = state.materialization_digest()
    with pytest.raises(StateError):
        _commit(fixture)
    assert state.materialization_digest() == before
    assert all(
        registry.get_process(item.identity.object_id).closed_at is None
        for item in plan.process_terminations
    )
    assert adapter.service_preparation_census().reserved_keys == 0
    if pending:
        assert owner.collectors.owns_pending_delivery(delivery)
        owner.collectors.cancel(delivery)
    assert all(item.closed_at is None for item in owner.collectors.snapshot())


@pytest.mark.parametrize("operation", ["exit", "unload"])
@pytest.mark.parametrize("collect", [False, True])
def test_authored_launchd_workflow_closes_its_process_bound_client(
    operation: str, collect: bool
) -> None:
    from tests.unit.test_macos_persistence_workflow import _request, _workflow

    bundle, caller, host, definition, path, _ = _workflow(collect)
    for index, stage in enumerate(("write", "bootstrap", "activate"), 1):
        result = bundle.execute(_request(bundle, caller, host, definition, path, stage, index))
    process = result.process
    owner = ESCollectionActionOwner(bundle.state, bundle.dispatcher.es_collectors)
    profile = owner.open(
        _profile(
            hostname=process.hostname,
            opened_at=process.started_at,
            last_delivery_at=process.started_at,
        ),
        process,
    )
    request = _request(bundle, caller, host, definition, path, operation, 10)
    bundle.execute(request)
    assert owner.collectors.connection(profile.source_instance).closed_at == request.timestamp
    assert bundle.state.get_process(process.hostname, process.pid) is None
    assert bundle.state.get_process_identity_by_object_id(process.object_id) == process
    assert bundle.services.service_preparation_census().reserved_keys == 0
