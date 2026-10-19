# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Image replacement closes an execution's explicit collector connections atomically."""

from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.events.es_collector import ESCollectorRegistry
from evidenceforge.formats.loader import load_format
from evidenceforge.generation.actions.es_collection import ESCollectionActionOwner
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.models.exceptions import EventContractError, StateError
from tests.unit.test_es_collector import _prepare as prepare_delivery
from tests.unit.test_es_collector import _profile
from tests.unit.test_process_exec_projection import _environment, _prepare


def _bound(tmp_path: Path, *, collected: bool = True) -> tuple:
    state, dispatcher, _ = _environment()
    emitter = EcarEmitter(load_format("ecar"), tmp_path, threaded=False)
    dispatcher.emitters = {"ecar": emitter} if collected else {}
    actor = state.get_process_identity("HOST-01", next(iter(state._running_processes.values())).pid)
    owner = ESCollectionActionOwner(state, dispatcher.es_collectors)
    profile = owner.open(
        _profile(
            hostname=actor.hostname,
            opened_at=actor.started_at,
            last_delivery_at=actor.started_at,
        ),
        actor,
    )
    return state, dispatcher, emitter, owner, profile


@pytest.mark.parametrize("collected", [False, True])
def test_exec_closes_old_attachment_and_requires_a_new_explicit_epoch(
    tmp_path: Path, collected: bool
) -> None:
    state, dispatcher, emitter, owner, profile = _bound(tmp_path, collected=collected)
    before, after, _, batch = _prepare(state, dispatcher, exact_projection=True)
    result = dispatcher.publish_prepared_action_cohort_batch(batch)
    closed = owner.collectors.connection(profile.source_instance)
    assert closed.closed_at == after.execution_started_at
    assert closed.process == profile.process
    assert closed.next_delivery == profile.next_delivery
    assert closed.next_global_sequence == profile.next_global_sequence
    assert "es_closures" in dict(result.receipt.nested_publication_tokens)
    assert state.get_process_identity(after.hostname, after.pid) == after
    assert after.object_id == before.object_id
    at = after.execution_started_at + timedelta(seconds=1)
    with pytest.raises(StateError, match="live Mac execution"):
        owner.open(_profile(hostname=before.hostname, opened_at=at, last_delivery_at=at), before)
    replacement = owner.open(
        _profile(hostname=after.hostname, generation=2, opened_at=at, last_delivery_at=at), after
    )
    assert replacement.process.execution_ordinal == after.execution_ordinal
    dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()


@pytest.mark.parametrize("late", [False, True])
def test_bound_exec_requires_exact_publication_even_if_client_attaches_after_preparation(
    tmp_path: Path, late: bool
) -> None:
    state, dispatcher, emitter, owner, profile = _bound(tmp_path)
    if late:
        owner.collectors = dispatcher.es_collectors = ESCollectorRegistry()
        before, _, _, batch = _prepare(state, dispatcher)
        owner.open(profile, before)
        with pytest.raises(EventContractError, match="exact.*publication"):
            dispatcher.publish_prepared_action_cohort_batch(batch)
    else:
        with pytest.raises(EventContractError, match="exact.*publication"):
            _prepare(state, dispatcher)
    assert owner.collectors.connection(profile.source_instance).closed_at is None
    assert dispatcher.action_cohort_publication_census().retained_bytes == 0
    emitter.close()


def test_cancelled_exec_preserves_attachment_and_original_execution(tmp_path: Path) -> None:
    state, dispatcher, emitter, owner, profile = _bound(tmp_path)
    before, _, _, batch = _prepare(state, dispatcher, exact_projection=True)
    assert dispatcher.cancel_prepared_action_cohort_batch(batch)
    assert owner.collectors.connection(profile.source_instance) == profile
    assert state.get_process_identity(before.hostname, before.pid) == before
    assert dispatcher.action_cohort_publication_census().retained_bytes == 0
    emitter.close()


def test_disconnect_failure_rolls_back_exec_and_connection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state, dispatcher, emitter, owner, profile = _bound(tmp_path)
    before, _, _, batch = _prepare(state, dispatcher, exact_projection=True)
    digest = state.materialization_digest()
    original = ESCollectorRegistry._apply_closures

    def fail(registry: ESCollectorRegistry, handle: object) -> None:
        original(registry, handle)
        raise RuntimeError("injected disconnect application failure")

    monkeypatch.setattr(ESCollectorRegistry, "_apply_closures", fail)
    with pytest.raises(RuntimeError, match="disconnect application failure"):
        dispatcher.publish_prepared_action_cohort_batch(batch)
    assert state.materialization_digest() == digest
    assert state.get_process_identity(before.hostname, before.pid) == before
    assert owner.collectors.connection(profile.source_instance) == profile
    assert dispatcher.action_cohort_publication_census().retained_bytes == 0
    emitter.close()


@pytest.mark.parametrize("change", ["pending", "future_delivery", "new_client"])
def test_changed_collection_prevents_stale_exec_publication(tmp_path: Path, change: str) -> None:
    state, dispatcher, emitter, owner, profile = _bound(tmp_path)
    before, after, _, batch = _prepare(state, dispatcher, exact_projection=True)
    delivery = None
    if change == "new_client":
        owner.open(
            _profile(
                source_instance="second-client",
                hostname=before.hostname,
                opened_at=before.started_at,
                last_delivery_at=before.started_at,
            ),
            before,
        )
    else:
        delivery = prepare_delivery(
            owner.collectors, observed_at=after.execution_started_at + timedelta(seconds=1)
        )
        if change == "future_delivery":
            owner.collectors.commit(delivery)
    with pytest.raises((StateError, EventContractError)):
        dispatcher.publish_prepared_action_cohort_batch(batch)
    assert state.get_process_identity(before.hostname, before.pid) == before
    if change == "pending":
        assert owner.collectors.owns_pending_delivery(delivery)
        owner.collectors.cancel(delivery)
    assert all(item.closed_at is None for item in owner.collectors.snapshot())
    assert dispatcher.action_cohort_publication_census().retained_bytes == 0
    emitter.close()


def test_returning_failed_exec_keeps_the_same_attached_execution(tmp_path: Path) -> None:
    from evidenceforge.generation.actions.process_policy import record_failed_process_exec

    state, dispatcher, emitter, owner, profile = _bound(tmp_path)
    actor = state.get_process_identity(profile.hostname, profile.process.pid)
    record_failed_process_exec(
        state,
        actor=actor,
        attempted_at=actor.started_at + timedelta(seconds=1),
        image="/usr/bin/invented-missing",
        command_line="invented-missing",
        error_number=2,
    )
    assert state.get_process_identity(actor.hostname, actor.pid) == actor
    assert owner.collectors.connection(profile.source_instance) == profile
    emitter.close()


def test_exec_closes_all_matching_clients_and_preserves_unknown_owners(tmp_path: Path) -> None:
    state, dispatcher, emitter, owner, profile = _bound(tmp_path)
    actor = state.get_process_identity(profile.hostname, profile.process.pid)
    second = owner.open(
        _profile(
            source_instance="second-client",
            hostname=actor.hostname,
            opened_at=actor.started_at,
            last_delivery_at=actor.started_at,
        ),
        actor,
    )
    unknown = _profile(source_instance="unknown-owner", hostname=actor.hostname)
    owner.collectors.open(unknown)
    _, after, _, batch = _prepare(state, dispatcher, exact_projection=True)
    dispatcher.publish_prepared_action_cohort_batch(batch)
    for item in (profile, second):
        assert (
            owner.collectors.connection(item.source_instance).closed_at
            == after.execution_started_at
        )
    assert owner.collectors.connection(unknown.source_instance) == unknown
    emitter.close()


def test_lost_disconnect_acknowledgement_does_not_repeat_exec(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state, dispatcher, emitter, owner, profile = _bound(tmp_path)
    _, after, _, batch = _prepare(state, dispatcher, exact_projection=True)
    original = ESCollectorRegistry._finalize_closures
    calls = 0

    def fail(registry: ESCollectorRegistry, handle: object) -> None:
        nonlocal calls
        calls += 1
        original(registry, handle)
        raise RuntimeError("injected lost disconnect acknowledgement")

    monkeypatch.setattr(ESCollectorRegistry, "_finalize_closures", fail)
    dispatcher.publish_prepared_action_cohort_batch(batch)
    assert calls == 1
    assert state.get_process_identity(after.hostname, after.pid) == after
    assert (
        owner.collectors.connection(profile.source_instance).closed_at == after.execution_started_at
    )
    dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()


@pytest.mark.parametrize("after_write", [False, True])
def test_source_retry_keeps_exec_and_disconnect_committed_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, after_write: bool
) -> None:
    from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter

    state, dispatcher, emitter, owner, _ = _bound(tmp_path)
    original = ExternalSortedLineWriter._commit_exact_row
    attempts = 0

    def fail(writer: object, key: tuple, digest: str, row: object) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            if after_write:
                original(writer, key, digest, row)
            raise RuntimeError("injected exec row failure")
        original(writer, key, digest, row)

    monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", fail)
    _, after, _, batch = _prepare(state, dispatcher, exact_projection=True)
    with pytest.raises(RuntimeError, match="exec row failure") as caught:
        dispatcher.publish_prepared_action_cohort_batch(batch)
    connections = owner.collectors.snapshot()
    version = state.materialization_version
    assert all(item.closed_at == after.execution_started_at for item in connections)
    dispatcher.resume_action_cohort_projection(caught.value.action_cohort_receipt)
    assert state.materialization_version == version
    assert owner.collectors.snapshot() == connections
    assert state.get_process_identity(after.hostname, after.pid) == after
    dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()
    rows = [line for path in tmp_path.rglob("ecar.json") for line in path.read_text().splitlines()]
    assert len(rows) == 1


def test_exec_and_closed_attachment_restore_together(tmp_path: Path) -> None:
    from evidenceforge.events.dispatcher import EventDispatcher
    from evidenceforge.generation.checkpoints.dispatcher_observation_head import (
        DispatcherObservationParticipant,
    )
    from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
    from evidenceforge.generation.state_manager import StateManager

    state, dispatcher, emitter, owner, profile = _bound(tmp_path, collected=False)
    _, after, _, batch = _prepare(state, dispatcher, exact_projection=True)
    dispatcher.publish_prepared_action_cohort_batch(batch)
    checkpoint = DispatcherObservationParticipant(dispatcher).prepare_checkpoint(1)
    restored_state = StateManager()
    _restore_head(restored_state, _capture_head(state))
    restored = EventDispatcher(restored_state, {})
    DispatcherObservationParticipant(restored).restore_checkpoint(checkpoint.head.payload, ())
    assert restored.es_collectors.snapshot() == owner.collectors.snapshot()
    assert restored_state.get_process_identity(after.hostname, after.pid) == after
    assert (
        restored.es_collectors.connection(profile.source_instance).closed_at
        == after.execution_started_at
    )
    emitter.close()


@pytest.mark.slow
def test_exec_disconnects_are_stable_across_fresh_processes_and_filtering() -> None:
    import os
    import subprocess
    import sys
    import textwrap

    script = textwrap.dedent("""
        import json, sys, tempfile
        from pathlib import Path
        from tests.unit.test_macos_process_collector_exec import _bound
        from tests.unit.test_process_exec_projection import _prepare
        with tempfile.TemporaryDirectory() as directory:
            state, dispatcher, emitter, owner, profile = _bound(
                Path(directory), collected=sys.argv[1] == 'True')
            before, after, event, batch = _prepare(state, dispatcher, exact_projection=True)
            dispatcher.publish_prepared_action_cohort_batch(batch)
            emitter.close()
            print(json.dumps({'state': state.materialization_digest(),
                'clients': [item.model_dump_json() for item in owner.collectors.snapshot()]}, sort_keys=True))
    """)
    results: list[str] = []
    for seed, collected in (("7", True), ("31", False)):
        result = subprocess.run(
            [sys.executable, "-c", script, str(collected)],
            env=dict(os.environ, PYTHONHASHSEED=seed),
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
        results.append(result.stdout)
    assert results[0] == results[1]
