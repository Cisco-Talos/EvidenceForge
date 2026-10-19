# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.es_collector import (
    ESCollectorRegistry,
    ESCollectorState,
    ESDeliveryPreparation,
)
from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.observation import ObservationDecision
from evidenceforge.generation.actions.es_collection import ESCollectionActionOwner
from evidenceforge.generation.checkpoints.dispatcher_observation_head import (
    DispatcherObservationParticipant,
)
from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError
from evidenceforge.generation.checkpoints.packed import dumps, loads
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_es_collector import _profile
from tests.unit.test_process_execution_state import _START, _execute, _process


def _setup() -> tuple[StateManager, ProcessIdentity, ESCollectionActionOwner, ESCollectorState]:
    state, process = _process()
    owner = ESCollectionActionOwner(state, ESCollectorRegistry())
    profile = owner.open(_profile(hostname=process.hostname), process)
    return state, process, owner, profile


def _prepare(
    owner: ESCollectionActionOwner, process: ProcessIdentity, **changes: object
) -> ESDeliveryPreparation:
    return owner.prepare(
        **(
            dict(
                source_instance="mac-a:es-client",
                process=process,
                generation=1,
                delivery=0,
                occurrence_id="invented-occurrence",
                event_type=1,
                observed_at=_START + timedelta(seconds=5),
                decision=ObservationDecision("visible"),
            )
            | changes
        )
    )


def test_bound_collection_preserves_exact_epoch_and_isolated_counters() -> None:
    _, process, owner, profile = _setup()
    assert profile.process.object_id == process.object_id
    assert profile.process.execution_ordinal == 0
    token = _prepare(owner, process)
    first = owner.collectors.commit(token)
    assert first.seq_num == first.global_seq_num == 0
    assert first.collector_process == profile.process
    assert owner.collectors.commit(token) == first
    assert owner.collectors.connection(profile.source_instance).next_delivery == 1


@pytest.mark.parametrize(
    "change", ["foreign_host", "foreign_lifetime", "foreign_pid", "linux", "before_execution"]
)
def test_invalid_collector_admission_leaves_registry_unchanged(change: str) -> None:
    state, process = _process("linux" if change == "linux" else "macos")
    owner = ESCollectionActionOwner(state, ESCollectorRegistry())
    profile = _profile(hostname=process.hostname)
    if change == "foreign_host":
        profile = profile.model_copy(update={"hostname": "other-host"})
    elif change == "foreign_lifetime":
        process = replace(process, object_id="another-lifetime", primary_thread=None)
    elif change == "foreign_pid":
        process = replace(process, pid=process.pid + 1, primary_thread=None)
    elif change == "before_execution":
        profile = profile.model_copy(update={"opened_at": _START - timedelta(seconds=1)})
    with pytest.raises(StateError):
        owner.open(profile, process)
    assert owner.collectors.snapshot() == ()


def test_exec_does_not_silently_reassign_existing_connection() -> None:
    state, before, owner, profile = _setup()
    after = _execute(state, before)
    with pytest.raises(StateError, match="live Mac"):
        _prepare(owner, before)
    with pytest.raises(StateError, match="established collector"):
        _prepare(owner, after)
    assert owner.collectors.connection(profile.source_instance) == profile
    restarted = _profile(
        hostname=after.hostname,
        generation=2,
        opened_at=after.execution_started_at,
        last_delivery_at=after.execution_started_at,
    )
    owner.open(restarted, after)
    token = _prepare(owner, after, generation=2)
    assert owner.collectors.commit(token).global_seq_num == 0


def test_unknown_legacy_owner_cannot_authorize_bound_delivery() -> None:
    state, process = _process()
    registry = ESCollectorRegistry()
    registry.open(_profile(hostname=process.hostname))
    owner = ESCollectionActionOwner(state, registry)
    with pytest.raises(StateError, match="established collector"):
        _prepare(owner, process)
    assert registry.snapshot()[0].next_delivery == 0


def test_explicit_close_blocks_new_delivery_and_preserves_completed_proof() -> None:
    _, process, owner, profile = _setup()
    token = _prepare(owner, process)
    with pytest.raises(StateError, match="unchanged idle"):
        owner.collectors.close(profile, _START + timedelta(seconds=6))
    observed = owner.collectors.commit(token)
    current = owner.collectors.connection(profile.source_instance)
    owner.collectors.close(current, _START + timedelta(seconds=6))
    with pytest.raises(StateError, match="open idle"):
        _prepare(owner, process, delivery=1)
    assert owner.collectors.commit(token) == observed
    closed = owner.collectors.connection(profile.source_instance)
    assert closed.closed_at == _START + timedelta(seconds=6)
    owner.collectors.close(closed, closed.closed_at)


def test_bound_closed_collector_restores_through_dispatcher_checkpoint() -> None:
    state, process, owner, profile = _setup()
    owner.collectors.close(profile, _START + timedelta(seconds=1))
    dispatcher = EventDispatcher(state, {})
    dispatcher.es_collectors = owner.collectors
    payload = DispatcherObservationParticipant(dispatcher).prepare_checkpoint(1).head.payload
    restored = EventDispatcher(StateManager(), {})
    DispatcherObservationParticipant(restored).restore_checkpoint(payload, ())
    assert restored.es_collectors.snapshot() == owner.collectors.snapshot()
    document = loads(payload)
    document["schema_version"] = "2"
    rejected = EventDispatcher(StateManager(), {})
    with pytest.raises(CheckpointCorruptionError, match="collector"):
        DispatcherObservationParticipant(rejected).restore_checkpoint(dumps(document), ())
    assert rejected.es_collectors.snapshot() == ()


def test_legacy_v2_checkpoint_retains_unknown_attachment() -> None:
    dispatcher = EventDispatcher(StateManager(), {})
    dispatcher.es_collectors.open(_profile())
    document = loads(
        DispatcherObservationParticipant(dispatcher).prepare_checkpoint(1).head.payload
    )
    document["schema_version"] = "2"
    restored = EventDispatcher(StateManager(), {})
    DispatcherObservationParticipant(restored).restore_checkpoint(dumps(document), ())
    assert restored.es_collectors.snapshot()[0].process is None


def test_exited_collector_cannot_deliver_and_pid_reuse_does_not_inherit_binding() -> None:
    state, before, owner, profile = _setup()
    builder = state.begin_action_cohort_materialization()
    builder.terminate_process(before, end_time=_START + timedelta(seconds=1))
    state.materialize_action_cohort(builder.seal())
    with pytest.raises(StateError, match="live Mac"):
        _prepare(owner, before)
    # Force an independently planned incarnation to use the retired numeric PID.
    plan = state.plan_process_materialization(
        system=before.hostname,
        parent_pid=0,
        image="/usr/bin/invented-collector",
        command_line="invented-collector",
        username="alex",
        integrity_level="Medium",
        os_category="macos",
        fixed_pid=before.pid,
        start_time=_START + timedelta(seconds=2),
    )
    state.materialize_process(plan)
    assert plan.identity.pid == before.pid
    assert plan.identity.object_id != before.object_id
    with pytest.raises(StateError, match="established collector"):
        _prepare(owner, plan.identity)
    assert owner.collectors.connection(profile.source_instance) == profile


def test_prepared_observation_retains_owner_after_connection_restart() -> None:
    state, before, owner, profile = _setup()
    token = _prepare(owner, before, observed_at=_START + timedelta(seconds=1))
    observation = owner.collectors.commit(token)
    after = _execute(state, before, seconds=2)
    owner.open(
        _profile(
            hostname=after.hostname,
            generation=2,
            opened_at=after.execution_started_at,
            last_delivery_at=after.execution_started_at,
        ),
        after,
    )
    assert observation.collector_process == profile.process
    assert owner.collectors.commit(token) == observation
    assert owner.collectors.connection(profile.source_instance).process.execution_ordinal == 1


def test_state_and_collector_restore_preserve_bound_continuation() -> None:
    state, process, owner, _ = _setup()
    owner.collectors.commit(_prepare(owner, process, decision=ObservationDecision("filtered")))
    dispatcher = EventDispatcher(state, {})
    dispatcher.es_collectors = owner.collectors
    head = DispatcherObservationParticipant(dispatcher).prepare_checkpoint(1).head.payload
    restored_state = StateManager()
    _restore_head(restored_state, _capture_head(state))
    restored = EventDispatcher(restored_state, {})
    DispatcherObservationParticipant(restored).restore_checkpoint(head, ())
    continuation = ESCollectionActionOwner(restored_state, restored.es_collectors)
    expected = owner.collectors.commit(_prepare(owner, process, delivery=1, occurrence_id="second"))
    actual = continuation.collectors.commit(
        _prepare(continuation, process, delivery=1, occurrence_id="second")
    )
    assert actual == expected
    assert actual.collector_process.object_id == process.object_id


def test_epoch_change_between_preparation_and_commit_cannot_consume_counter() -> None:
    state, process, owner, profile = _setup()
    token = _prepare(owner, process)
    _execute(state, process, seconds=1)
    with pytest.raises(StateError, match="live Mac"):
        owner.commit(token, process)
    owner.collectors.cancel(token)
    assert owner.collectors.connection(profile.source_instance) == profile


def test_bound_completed_retry_remains_valid_after_exit() -> None:
    state, process, owner, _ = _setup()
    token = _prepare(owner, process)
    observation = owner.commit(token, process)
    builder = state.begin_action_cohort_materialization()
    builder.terminate_process(process, end_time=_START + timedelta(seconds=6))
    state.materialize_action_cohort(builder.seal())
    assert owner.commit(token, process) == observation
