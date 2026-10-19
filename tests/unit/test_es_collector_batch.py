# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta

import pytest
from pydantic import ValidationError

from evidenceforge.events.es_collector import (
    ESCollectorRegistry,
    ESDeliveryBatchPreparation,
    ESDeliveryRequest,
    ESEventCounter,
    ESKernelLoss,
)
from evidenceforge.events.observation import ObservationDecision
from evidenceforge.models.exceptions import StateError
from tests.unit.test_es_collector import _profile, _registry
from tests.unit.test_es_collector_ownership import _setup
from tests.unit.test_process_execution_state import _START, _execute


def _requests() -> tuple[ESDeliveryRequest, ...]:
    return tuple(
        ESDeliveryRequest(
            occurrence_id=f"batch-occurrence-{index}",
            event_type=1 if index != 1 else 2,
            observed_at=_START + timedelta(seconds=index + 1),
            decision=ObservationDecision(
                "delayed" if index == 2 else "filtered" if index == 1 else "visible",
                timedelta(milliseconds=20) if index == 2 else timedelta(0),
            ),
            kernel_lost=(ESKernelLoss(event_type=1, count=2), ESKernelLoss(event_type=2, count=3))
            if index == 2
            else (),
        )
        for index in range(3)
    )


def _prepare(registry: ESCollectorRegistry, **changes: object) -> ESDeliveryBatchPreparation:
    return registry.prepare_batch(
        **(
            dict(source_instance="mac-a:es-client", generation=1, delivery=0, requests=_requests())
            | changes
        )
    )


def test_batch_matches_sequential_delivery_and_commits_no_partial_prefix() -> None:
    grouped, sequential = _registry(), _registry()
    token = _prepare(grouped)
    assert grouped.connection("mac-a:es-client") == _profile()
    expected = []
    for index, request in enumerate(_requests()):
        one = sequential.prepare(
            source_instance="mac-a:es-client",
            generation=1,
            delivery=index,
            occurrence_id=request.occurrence_id,
            event_type=request.event_type,
            observed_at=request.observed_at,
            decision=request.decision,
            kernel_lost=request.kernel_lost,
        )
        expected.append(sequential.commit(one))
    assert token.observations == tuple(expected)
    assert [(row.seq_num, row.global_seq_num) for row in token.observations] == [
        (0, 0),
        (0, 1),
        (3, 7),
    ]
    assert grouped.commit_batch(token) == tuple(expected)
    assert grouped.snapshot() == sequential.snapshot()
    restored = ESCollectorRegistry()
    restored.restore(grouped.snapshot())
    next_request = _requests()[0].model_copy(update={"observed_at": _START + timedelta(seconds=4)})
    next_batch = _prepare(restored, delivery=3, requests=(next_request,))
    assert next_batch.observations[0].global_seq_num == 8
    assert next_batch.observations[0].seq_num == 4
    restored.cancel_batch(next_batch)


@pytest.mark.parametrize(
    "damage", ["unsubscribed", "time", "loss", "ordinal", "generation", "overflow"]
)
def test_invalid_later_member_does_not_reserve_or_advance_a_prefix(damage: str) -> None:
    registry = _registry()
    requests = list(_requests())
    changes: dict[str, object] = {}
    if damage == "unsubscribed":
        requests[1] = requests[1].model_copy(update={"event_type": 99})
    elif damage == "time":
        requests[1] = requests[1].model_copy(update={"observed_at": _START})
    elif damage == "loss":
        requests[1] = requests[1].model_copy(
            update={"kernel_lost": (ESKernelLoss(event_type=99, count=1),)}
        )
    elif damage == "ordinal":
        changes["delivery"] = True
    elif damage == "generation":
        changes["generation"] = 2
    else:
        registry = ESCollectorRegistry()
        registry.open(
            _profile(
                event_counters=(
                    ESEventCounter(event_type=1, next_sequence=2**64 - 2),
                    ESEventCounter(event_type=2, next_sequence=0),
                )
            )
        )
    before = registry.snapshot()
    with pytest.raises((StateError, ValidationError)):
        _prepare(registry, requests=tuple(requests), **changes)
    assert registry.snapshot() == before


def test_pending_batch_fences_single_delivery_close_restart_and_checkpoint() -> None:
    from tests.unit.test_es_collector import _prepare as single

    registry = _registry()
    token = _prepare(registry)
    with pytest.raises(StateError, match="idle"):
        single(registry)
    with pytest.raises(StateError, match="idle"):
        _prepare(registry)
    with pytest.raises(StateError, match="unchanged idle"):
        registry.close(_profile(), _START + timedelta(seconds=5))
    with pytest.raises(StateError, match="completed publication"):
        registry.open(
            _profile(
                generation=2,
                opened_at=_START + timedelta(seconds=5),
                last_delivery_at=_START + timedelta(seconds=5),
            )
        )
    with pytest.raises(StateError, match="completed or cancelled"):
        registry.snapshot()
    registry.cancel_batch(token)
    assert registry.snapshot() == (_profile(),)
    with pytest.raises(StateError, match="stale"):
        registry.commit_batch(token)


def test_claim_is_same_thread_opaque_and_has_precomputed_proof(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = _registry()
    token = _prepare(registry)
    with registry.prepared_batch(token) as claimed:
        with ThreadPoolExecutor(max_workers=1) as worker:
            with pytest.raises(StateError, match="active preparation"):
                worker.submit(claimed.commit_no_fail).result(timeout=2)
        with pytest.raises(StateError, match="active preparation"):
            replace(claimed).commit_no_fail()
        with pytest.raises(StateError, match="active commit"):
            registry.commit_batch(token)
        with pytest.raises(StateError, match="unclaimed"):
            registry.cancel_batch(token)
        with monkeypatch.context() as patch:

            def forbidden(*args: object, **kwargs: object) -> None:
                raise AssertionError("proof computation inside final commit")

            patch.setattr(ESCollectorRegistry, "_batch_proof", forbidden)
            claimed.commit_no_fail()
            claimed.commit_no_fail()
    assert registry.completed_batch(token) == token.observations
    assert registry.connection("mac-a:es-client").next_delivery == 3
    with pytest.raises(StateError, match="active preparation"):
        claimed.commit_no_fail()


def test_copied_changed_or_foreign_capability_cannot_authorize_commit() -> None:
    registry = _registry()
    token = _prepare(registry)
    for bad in (replace(token), replace(token, observations=token.observations[:1])):
        with pytest.raises(StateError, match="stale or changed"):
            registry.commit_batch(bad)
    registry.commit_batch(token)
    assert registry.completed_batch(replace(token)) is None
    assert _registry().completed_batch(token) is None
    original = token.observations
    object.__setattr__(token, "observations", original[:1])
    assert registry.completed_batch(token) is None
    object.__setattr__(token, "observations", original)
    assert registry.commit_batch(token) == original


def test_lost_return_retries_all_members_without_allocating_again() -> None:
    registry = _registry()
    token = _prepare(registry)
    with pytest.raises(RuntimeError, match="lost return"):
        with registry.prepared_batch(token) as claimed:
            claimed.commit_no_fail()
            raise RuntimeError("lost return")
    before = registry.snapshot()
    assert registry.commit_batch(token) == token.observations
    assert registry.snapshot() == before


def test_bound_batch_precommit_rollback_and_completed_retry_after_exec() -> None:
    state, process, owner, profile = _setup()
    requests = tuple(item.model_copy(update={"event_type": 1}) for item in _requests())
    token = owner.prepare_batch(
        source_instance=profile.source_instance,
        process=process,
        generation=1,
        delivery=0,
        requests=requests,
    )
    builder = state.begin_action_cohort_materialization()
    builder.patch_process_activity(process, requests[-1].observed_at)
    plan = builder.seal()
    before = state.materialization_digest()
    with pytest.raises(RuntimeError, match="precommit"):
        with owner.prepared_batch_commit(token, process):
            with state.prepared_action_cohort_materialization(plan) as prepared:
                prepared.certify_composite_commit(prepared.expected_result)
                prepared.apply_provisional()
                raise RuntimeError("precommit")
    assert state.materialization_digest() == before
    assert owner.collectors.connection(profile.source_instance) == profile
    assert owner.commit_batch(token, process) == token.observations
    _execute(state, process, seconds=6)
    assert owner.commit_batch(token, process) == token.observations
    assert owner.collectors.connection(profile.source_instance).next_delivery == 3


def test_stale_collector_cannot_commit_unfinished_batch() -> None:
    state, process, owner, profile = _setup()
    requests = (_requests()[0],)
    token = owner.prepare_batch(
        source_instance=profile.source_instance,
        process=process,
        generation=1,
        delivery=0,
        requests=requests,
    )
    _execute(state, process, seconds=6)
    with pytest.raises(StateError, match="live Mac"):
        owner.commit_batch(token, process)
    owner.collectors.cancel_batch(token)
    assert owner.collectors.connection(profile.source_instance) == profile


@pytest.mark.parametrize("requests", [(), [], (object(),)])
def test_empty_or_untyped_batch_is_rejected(requests: object) -> None:
    with pytest.raises(StateError, match="exact delivery"):
        _prepare(_registry(), requests=requests)


def test_batch_capacity_is_bounded_without_leaving_a_reservation() -> None:
    registry = _registry()
    request = _requests()[0]
    with pytest.raises(StateError, match="256"):
        _prepare(registry, requests=(request,) * 257)
    assert registry.snapshot() == (_profile(),)
    token = _prepare(registry, requests=(request,) * 256)
    assert len(token.observations) == 256
    assert token.observations[-1].delivery == 255
    registry.cancel_batch(token)
    assert registry.snapshot() == (_profile(),)


def test_uncommitted_claim_exception_preserves_cancellable_batch() -> None:
    registry = _registry()
    token = _prepare(registry)
    with pytest.raises(RuntimeError):
        with registry.prepared_batch(token):
            raise RuntimeError("precommit failure")
    assert registry.connection("mac-a:es-client") == _profile()
    assert registry.completed_batch(token) is None
    registry.cancel_batch(token)
    assert registry.snapshot() == (_profile(),)


def test_export_decisions_do_not_change_member_sequence_allocation() -> None:
    visible, filtered = _registry(), _registry()
    first = _prepare(visible)
    requests = tuple(
        item.model_copy(update={"decision": ObservationDecision("out_of_window")})
        for item in _requests()
    )
    second = _prepare(filtered, requests=requests)
    assert [(item.seq_num, item.global_seq_num) for item in first.observations] == [
        (item.seq_num, item.global_seq_num) for item in second.observations
    ]
    visible.commit_batch(first)
    filtered.commit_batch(second)
    assert visible.snapshot() == filtered.snapshot()


def test_completed_batch_proof_survives_connection_restart_without_rewinding_counters() -> None:
    registry = _registry()
    token = _prepare(registry)
    registry.commit_batch(token)
    next_profile = _profile(
        generation=2,
        opened_at=_START + timedelta(seconds=10),
        last_delivery_at=_START + timedelta(seconds=10),
    )
    registry.open(next_profile)
    assert registry.commit_batch(token) == token.observations
    assert registry.snapshot() == (next_profile,)


def test_bound_batch_joins_prepared_state_commit_without_final_proof_callback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state, process, owner, profile = _setup()
    requests = _requests()
    token = owner.prepare_batch(
        source_instance=profile.source_instance,
        process=process,
        generation=1,
        delivery=0,
        requests=requests,
    )
    builder = state.begin_action_cohort_materialization()
    builder.patch_process_activity(process, requests[-1].observed_at)
    plan = builder.seal()
    with owner.prepared_batch_commit(token, process) as collector:
        with state.prepared_action_cohort_materialization(plan) as prepared:
            prepared.certify_composite_commit(prepared.expected_result)
            prepared.apply_provisional()
            with monkeypatch.context() as patch:

                def forbidden(*args: object, **kwargs: object) -> None:
                    raise AssertionError("proof callback during final batch commit")

                patch.setattr(ESCollectorRegistry, "_batch_proof", forbidden)
                prepared.finalize_no_fail()
                collector.commit_no_fail()
                collector.commit_no_fail()
    assert (
        state.get_process(process.hostname, process.pid).last_activity_time
        == requests[-1].observed_at
    )
    assert owner.collectors.connection(profile.source_instance).next_delivery == 3
    assert owner.collectors.completed_batch(token) == token.observations
