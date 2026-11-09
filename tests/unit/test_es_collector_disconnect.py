# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.es_collector import ESCollectorRegistry
from evidenceforge.models.exceptions import StateError
from tests.unit.test_es_collector_ownership import _prepare, _setup
from tests.unit.test_process_execution_state import _START, _execute


def test_explicit_disconnect_blocks_future_delivery_without_changing_counters() -> None:
    state, process, owner, profile = _setup()
    before = state.materialization_digest()
    closed = owner.close(profile, process, _START + timedelta(seconds=6))
    assert closed.closed_at == _START + timedelta(seconds=6)
    assert closed.next_global_sequence == profile.next_global_sequence
    assert owner.collectors.connection(profile.source_instance) == closed
    assert state.materialization_digest() == before
    with pytest.raises(StateError, match="open idle"):
        _prepare(owner, process)
    assert owner.close(profile, process, closed.closed_at) == closed
    assert owner.close(closed, process, closed.closed_at) == closed


@pytest.mark.parametrize("phase", ["before", "after"])
def test_disconnect_retry_preserves_exact_terminal_time_after_lost_return(
    monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    _, process, owner, profile = _setup()
    original = ESCollectorRegistry.close
    at = _START + timedelta(seconds=6)

    def fail(registry: ESCollectorRegistry, *args: object) -> None:
        if phase == "after":
            original(registry, *args)
        raise RuntimeError("injected disconnect failure")

    with monkeypatch.context() as fault:
        fault.setattr(ESCollectorRegistry, "close", fail)
        with pytest.raises(RuntimeError, match="disconnect failure"):
            owner.close(profile, process, at)
    current = owner.collectors.connection(profile.source_instance)
    assert current.closed_at == (at if phase == "after" else None)
    result = owner.close(profile, process, at)
    assert result.closed_at == at
    with pytest.raises(StateError):
        owner.close(result, process, at + timedelta(seconds=1))
    assert owner.collectors.connection(profile.source_instance) == result


@pytest.mark.parametrize("transition", ["exec", "exit"])
def test_completed_disconnect_retry_survives_process_change_but_new_close_cannot(
    transition: str,
) -> None:
    state, process, owner, profile = _setup()
    at = _START + timedelta(seconds=1)
    closed = owner.close(profile, process, at)
    if transition == "exec":
        _execute(state, process)
    else:
        builder = state.begin_action_cohort_materialization()
        builder.terminate_process(process, end_time=_START + timedelta(seconds=2))
        state.materialize_action_cohort(builder.seal())
    assert owner.close(profile, process, at) == closed
    with pytest.raises(StateError):
        owner.close(profile, process, _START + timedelta(seconds=3))
    assert owner.collectors.connection(profile.source_instance) == closed


@pytest.mark.parametrize(
    "damage", ["host", "lifetime", "execution", "pending", "advanced", "naive", "exited"]
)
def test_invalid_disconnect_preserves_state_and_collector_snapshot(damage: str) -> None:
    state, process, owner, profile = _setup()
    at = _START + timedelta(seconds=6)
    supplied = process
    pending = None
    if damage == "host":
        profile = profile.model_copy(update={"hostname": "OTHER"})
    elif damage == "lifetime":
        foreign_id = process.object_id + "-foreign"
        supplied = replace(
            process,
            object_id=foreign_id,
            primary_thread=replace(process.primary_thread, process_object_id=foreign_id),
        )
    elif damage == "execution":
        _execute(state, process)
    elif damage == "pending":
        pending = _prepare(owner, process)
    elif damage == "advanced":
        owner.commit(_prepare(owner, process), process)
    elif damage == "naive":
        at = at.replace(tzinfo=None)
    else:
        builder = state.begin_action_cohort_materialization()
        builder.terminate_process(process, end_time=_START + timedelta(seconds=2))
        state.materialize_action_cohort(builder.seal())
    before = state.materialization_digest()
    collectors = owner.collectors.connection(profile.source_instance)
    with pytest.raises(StateError):
        owner.close(profile, supplied, at)
    assert state.materialization_digest() == before
    assert owner.collectors.connection(profile.source_instance) == collectors
    if pending is not None:
        owner.collectors.cancel(pending)


def test_old_disconnect_cannot_close_a_reopened_connection() -> None:
    _, process, owner, profile = _setup()
    at = _START + timedelta(seconds=1)
    owner.close(profile, process, at)
    later = _START + timedelta(seconds=2)
    replacement = owner.open(
        profile.model_copy(update={"generation": 2, "opened_at": later, "last_delivery_at": later}),
        process,
    )
    with pytest.raises(StateError, match="unchanged idle"):
        owner.close(profile, process, at)
    assert owner.collectors.connection(profile.source_instance) == replacement


def test_completed_disconnect_restores_without_requiring_the_old_process_to_be_live() -> None:
    from evidenceforge.generation.actions.es_collection import ESCollectionActionOwner
    from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
    from evidenceforge.generation.state_manager import StateManager

    state, process, owner, profile = _setup()
    at = _START + timedelta(seconds=1)
    closed = owner.close(profile, process, at)
    _execute(state, process, seconds=2)
    fresh = StateManager()
    _restore_head(fresh, _capture_head(state))
    registry = ESCollectorRegistry()
    registry.restore(owner.collectors.snapshot())
    restored = ESCollectionActionOwner(fresh, registry)
    assert restored.close(profile, process, at) == closed
    assert registry.connection(profile.source_instance) == closed
