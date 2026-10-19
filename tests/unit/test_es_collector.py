# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Collector delivery state is independent of exported selection and source delay."""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from pydantic import ValidationError

from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.es_collector import (
    ESCollectorRegistry,
    ESCollectorState,
    ESDeliveryPreparation,
    ESEventCounter,
    ESKernelLoss,
)
from evidenceforge.events.observation import ObservationDecision
from evidenceforge.generation.checkpoints.dispatcher_observation_head import (
    DispatcherObservationParticipant,
)
from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError
from evidenceforge.generation.checkpoints.packed import dumps, loads
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_process_execution_state import _START


def _profile(**changes: object) -> ESCollectorState:
    return ESCollectorState.model_validate(
        dict(
            source_instance="mac-a:es-client",
            hostname="MAC-A",
            generation=1,
            opened_at=_START,
            last_delivery_at=_START,
            next_delivery=0,
            next_global_sequence=0,
            event_counters=(
                ESEventCounter(event_type=1, next_sequence=0),
                ESEventCounter(event_type=2, next_sequence=0),
            ),
        )
        | changes
    )


def _registry() -> ESCollectorRegistry:
    registry = ESCollectorRegistry()
    registry.open(_profile())
    return registry


def _prepare(
    registry: ESCollectorRegistry, delivery: int = 0, **changes: object
) -> ESDeliveryPreparation:
    return registry.prepare(
        **(
            dict(
                source_instance="mac-a:es-client",
                generation=1,
                delivery=delivery,
                occurrence_id=f"invented-occurrence-{delivery}",
                event_type=1,
                observed_at=_START + timedelta(seconds=delivery),
                decision=ObservationDecision("visible"),
            )
            | changes
        )
    )


def test_counters_distinguish_event_types_kernel_loss_and_export_omission() -> None:
    registry = _registry()
    first = registry.commit(_prepare(registry))
    dropped = registry.commit(
        _prepare(registry, 1, event_type=2, decision=ObservationDecision("dropped"))
    )
    third = registry.commit(
        _prepare(
            registry,
            2,
            kernel_lost=(ESKernelLoss(event_type=1, count=2), ESKernelLoss(event_type=2, count=3)),
        )
    )
    assert (first.seq_num, first.global_seq_num) == (0, 0)
    assert (dropped.seq_num, dropped.global_seq_num) == (0, 1)
    assert (third.seq_num, third.global_seq_num) == (3, 7)
    assert registry.snapshot()[0].next_global_sequence == 8
    assert [entry.next_sequence for entry in registry.snapshot()[0].event_counters] == [4, 4]


def test_cancelled_reservation_and_completed_retry_do_not_allocate_extra_sequences() -> None:
    registry = _registry()
    before = registry.snapshot()
    cancelled = _prepare(registry)
    with pytest.raises(StateError, match="completed or cancelled"):
        registry.snapshot()
    registry.cancel(cancelled)
    assert registry.snapshot() == before
    with pytest.raises(StateError, match="stale"):
        registry.commit(cancelled)
    committed = _prepare(registry)
    observation = registry.commit(committed)
    next_observation = registry.commit(_prepare(registry, 1))
    with ThreadPoolExecutor(max_workers=4) as workers:
        assert list(workers.map(registry.commit, [committed] * 12)) == [observation] * 12
    assert next_observation.global_seq_num == 1
    assert registry.snapshot()[0].next_global_sequence == 2
    with pytest.raises(StateError, match="ordinal"):
        _prepare(registry)


def test_restart_resets_only_explicit_client_counters_and_invalidates_old_generation() -> None:
    registry = _registry()
    registry.commit(_prepare(registry))
    registry.open(
        _profile(
            generation=2,
            opened_at=_START + timedelta(seconds=3),
            last_delivery_at=_START + timedelta(seconds=3),
            next_global_sequence=10,
        )
    )
    with pytest.raises(StateError, match="connection"):
        _prepare(registry, observed_at=_START + timedelta(seconds=4))
    observed = registry.commit(
        _prepare(registry, generation=2, observed_at=_START + timedelta(seconds=4))
    )
    assert observed.generation == 2 and observed.seq_num == 0 and observed.global_seq_num == 10
    with pytest.raises(StateError, match="next same-host"):
        registry.open(_profile())


def test_two_collectors_on_one_host_do_not_share_counters() -> None:
    registry = _registry()
    registry.open(_profile(source_instance="mac-a:second-client"))
    registry.commit(_prepare(registry))
    second = registry.commit(_prepare(registry, source_instance="mac-a:second-client"))
    assert second.global_seq_num == 0


@pytest.mark.parametrize(
    "changes",
    [
        {"event_type": 9},
        {"event_type": True},
        {"delivery": 1},
        {"generation": 2},
        {"observed_at": _START - timedelta(seconds=1)},
        {"observed_at": _START.replace(tzinfo=None)},
        {"kernel_lost": (ESKernelLoss(event_type=9, count=1),)},
        {"kernel_lost": (ESKernelLoss(event_type=1, count=1), ESKernelLoss(event_type=1, count=2))},
        {"decision": ObservationDecision("visible", timedelta(seconds=-1))},
    ],
)
def test_invalid_delivery_rejects_without_counter_changes(changes: dict[str, object]) -> None:
    registry = _registry()
    before = registry.snapshot()
    with pytest.raises((StateError, ValidationError)):
        _prepare(registry, **changes)
    assert registry.snapshot() == before


def test_counter_overflow_rejects_before_reservation() -> None:
    registry = ESCollectorRegistry()
    registry.open(_profile(next_global_sequence=2**64 - 1))
    before = registry.snapshot()
    with pytest.raises(ValidationError):
        _prepare(registry)
    assert registry.snapshot() == before


@pytest.mark.parametrize("committed", [False, True])
def test_mutated_capability_cannot_publish_or_replay_changed_counters(committed: bool) -> None:
    registry = _registry()
    capability = _prepare(registry)
    if committed:
        registry.commit(capability)
    object.__setattr__(capability.observation, "seq_num", 999)
    with pytest.raises(StateError, match="stale or changed"):
        registry.commit(capability)
    if not committed:
        registry.cancel(capability)
    assert registry.snapshot()[0].next_global_sequence == int(committed)


def test_dispatcher_checkpoint_resume_preserves_filtered_and_delayed_delivery_sequence() -> None:
    source = EventDispatcher(StateManager(), {})
    source.es_collectors.open(_profile())
    source.es_collectors.commit(
        _prepare(source.es_collectors, decision=ObservationDecision("filtered"))
    )
    seal = DispatcherObservationParticipant(source).prepare_checkpoint(1)
    restored = EventDispatcher(StateManager(), {})
    DispatcherObservationParticipant(restored).restore_checkpoint(seal.head.payload, ())
    kwargs = dict(event_type=2, decision=ObservationDecision("delayed", timedelta(seconds=5)))
    expected = source.es_collectors.commit(_prepare(source.es_collectors, 1, **kwargs))
    actual = restored.es_collectors.commit(_prepare(restored.es_collectors, 1, **kwargs))
    assert expected == actual
    assert actual.global_seq_num == 1 and actual.delay == timedelta(seconds=5)
    assert source.es_collectors.snapshot() == restored.es_collectors.snapshot()


def test_legacy_observation_checkpoint_restores_empty_collectors() -> None:
    source = EventDispatcher(StateManager(), {})
    head = DispatcherObservationParticipant(source).prepare_checkpoint(1).head.payload
    document = loads(head)
    document["schema_version"] = "1"
    document.pop("es_collectors")
    restored = EventDispatcher(StateManager(), {})
    DispatcherObservationParticipant(restored).restore_checkpoint(dumps(document), ())
    assert restored.es_collectors.snapshot() == ()
    document["es_collectors"] = [_profile().model_dump_json()]
    with pytest.raises(CheckpointCorruptionError, match="schema"):
        DispatcherObservationParticipant(EventDispatcher(StateManager(), {})).restore_checkpoint(
            dumps(document), ()
        )


def test_restore_validates_all_collector_rows_before_mutating_dispatcher() -> None:
    source = EventDispatcher(StateManager(), {})
    document = loads(DispatcherObservationParticipant(source).prepare_checkpoint(1).head.payload)
    document["es_collectors"] = [_profile().model_dump_json(), _profile().model_dump_json()]
    restored = EventDispatcher(StateManager(), {})
    with pytest.raises(CheckpointCorruptionError, match="collector"):
        DispatcherObservationParticipant(restored).restore_checkpoint(dumps(document), ())
    assert restored.es_collectors.snapshot() == ()
    assert restored._source_evidence_version == 0


@pytest.mark.parametrize("count", [-1, True, 2**64])
def test_mutated_kernel_loss_cannot_rewind_or_coerce_counters(count: int) -> None:
    registry = _registry()
    registry.commit(_prepare(registry))
    before = registry.snapshot()
    loss = ESKernelLoss(event_type=1, count=1)
    object.__setattr__(loss, "count", count)
    with pytest.raises(ValidationError):
        _prepare(registry, 1, kernel_lost=(loss,))
    assert registry.snapshot() == before
