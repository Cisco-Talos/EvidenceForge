# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Prepared collector counters join the existing exact canonical publication path."""

import json
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.events.contexts import HostContext
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.es_collector import ESCollectorRegistry
from evidenceforge.events.observation import ObservationDecision, ObservationStatus
from evidenceforge.formats.loader import load_format
from evidenceforge.generation.actions.command_effects import ExecutionEffectAuditCounter
from evidenceforge.generation.actions.posix_process import process_exit_occurrence
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
from evidenceforge.generation.lifecycle_registry import LifecycleRegistry
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.models.exceptions import EventContractError, StateError
from tests.unit.test_macos_es_exit_preparation import _fixture, _prepare
from tests.unit.test_process_exit_projection import _prepare as prepare_dispatch


def _setup(
    tmp_path: Path,
    *,
    collected: bool = True,
    installed: bool = False,
    status: ObservationStatus = "visible",
    threaded: bool = True,
    installed_filesystem: bool = False,
) -> tuple:
    native = _fixture(installed=installed)
    state = native.owner.state
    # Start the integrated fixture with a fresh loaded lifetime. The lower-level
    # provider fixture deliberately exercised exec without a lifecycle registry.
    native.owner.collectors.cancel(native.delivery)
    prior = native.process.process
    close = state.begin_action_cohort_materialization()
    close.terminate_process(
        prior, end_time=prior.execution_started_at + timedelta(milliseconds=500)
    )
    state.materialize_action_cohort(close.seal())
    birth = state.plan_process_materialization(
        system=prior.hostname,
        parent_pid=native.collector.pid,
        image=prior.image,
        command_line=prior.command_line,
        username=prior.principal,
        integrity_level="Medium",
        os_category="macos",
        credentials=prior.credentials,
        start_time=prior.execution_started_at + timedelta(seconds=1),
        executable_version=prior.executable_version,
        image_security=prior.image_security,
        responsibility=prior.responsibility,
    )
    state.materialize_process(birth)
    at = birth.identity.started_at + timedelta(seconds=2)
    close = state.begin_action_cohort_materialization()
    close.terminate_process(
        birth.identity, end_time=at, exit_outcome=native.cohort.process_terminations[0].exit_outcome
    )
    native.cohort = close.seal()
    observation = native.delivery.observation
    native.delivery = native.owner.prepare(
        source_instance=observation.source_instance,
        process=native.collector,
        generation=observation.generation,
        delivery=observation.delivery,
        occurrence_id=f"process-exit:{birth.identity.object_id}",
        event_type=15,
        observed_at=at,
        decision=ObservationDecision(
            status, timedelta(milliseconds=2) if status == "delayed" else timedelta(0)
        ),
    )
    native.process = replace(native.process, process=birth.identity, observed_at=at)
    registry = LifecycleRegistry(shard_count=4)
    shadow = LifecycleShadow(state, registry)
    authority = GeneratorLifecycleAuthority(state, shadow, shard_count=4)
    authority.bootstrap_active_state()
    emitter = EcarEmitter(load_format("ecar"), tmp_path, threaded=threaded)
    dispatcher = EventDispatcher(
        state,
        {"ecar": emitter} if collected else {},
        lifecycle_shadow=shadow,
        enforce_lifecycle_authority=True,
    )
    dispatcher.bind_lifecycle_authority(authority)
    dispatcher.bind_execution_effect_audit(ExecutionEffectAuditCounter())
    dispatcher.es_collectors = native.owner.collectors
    if installed:
        dispatcher.deployment_registry = native.executables
    else:
        dispatcher.local_artifact_registry = native.executables
    preparation = {}
    if installed_filesystem:
        from tests.unit.test_macos_installed_filesystem import _provider

        preparation = {
            "installed_file": None,
            "installed_filesystem": _provider(native.executables, native.process.process),
        }
    with _prepare(native, **preparation) as prepared:
        frozen = prepared.ndjson
    subject = native.process.process
    event = process_exit_occurrence(
        host=HostContext(
            hostname=subject.hostname,
            ip="192.0.2.41",
            os="macOS 26",
            os_category="macos",
            system_type="workstation",
        ),
        process=subject,
        timestamp=native.process.observed_at,
        integrity_level="Medium",
    )
    event.process.exit_outcome = native.cohort.process_terminations[0].exit_outcome
    batch = prepare_dispatch(dispatcher, native.cohort, event, exact=True)
    return native, dispatcher, emitter, batch, frozen


def _bind(native: object, dispatcher: EventDispatcher, batch: object) -> None:
    dispatcher.bind_es_delivery_to_action_cohort(
        batch, delivery=native.delivery, collector_process=native.collector
    )


@pytest.mark.parametrize("collected", [False, True])
@pytest.mark.parametrize("installed", [False, True])
def test_exact_exit_publication_commits_state_lifecycle_and_bound_counter_once(
    tmp_path: Path, collected: bool, installed: bool
) -> None:
    native, dispatcher, emitter, batch, frozen = _setup(
        tmp_path, collected=collected, installed=installed
    )
    _bind(native, dispatcher, batch)
    assert native.owner.collectors.completed_observation(native.delivery) is None
    result = dispatcher.publish_prepared_action_cohort_batch(batch)
    assert dispatcher.authenticates_action_cohort_publication_receipt(result.receipt)
    assert (
        native.owner.collectors.completed_observation(native.delivery)
        == native.delivery.observation
    )
    assert native.owner.collectors.retained_native_projection(native.delivery) == frozen
    assert (
        dict(result.receipt.nested_publication_tokens)["es_collector"]
        == native.delivery._proof.hex()
    )
    subject = native.process.process
    assert native.owner.state.get_process(subject.hostname, subject.pid) is None
    dispatcher.assert_exact_projection_recoveries_drained()
    assert native.owner.collectors.snapshot()
    emitter.close()
    assert not list(tmp_path.rglob("*endpoint_security*"))


def test_cancelling_bound_batch_releases_collector_reservation_without_advancing(
    tmp_path: Path,
) -> None:
    native, dispatcher, emitter, batch, _ = _setup(tmp_path)
    before = native.owner.state.materialization_digest()
    connection = native.owner.collectors.connection(native.delivery.observation.source_instance)
    _bind(native, dispatcher, batch)
    assert dispatcher.cancel_prepared_action_cohort_batch(batch)
    assert native.owner.collectors.connection(connection.source_instance) == connection
    assert not native.owner.collectors.authenticates_pending_delivery(native.delivery)
    assert native.owner.collectors.completed_observation(native.delivery) is None
    assert native.owner.state.materialization_digest() == before
    assert native.owner.collectors.snapshot()
    emitter.close()


@pytest.mark.parametrize(
    "damage", ["copy", "foreign_registry", "collector", "double_bind", "completed"]
)
def test_invalid_binding_cannot_publish_or_consume_an_unowned_collector(
    tmp_path: Path, damage: str
) -> None:
    native, dispatcher, emitter, batch, _ = _setup(tmp_path)
    delivery, collector = native.delivery, native.collector
    if damage == "copy":
        delivery = replace(delivery)
    elif damage == "foreign_registry":
        dispatcher.es_collectors = ESCollectorRegistry()
    elif damage == "collector":
        collector = replace(collector, image="/different")
    elif damage == "double_bind":
        _bind(native, dispatcher, batch)
    else:
        native.owner.commit(delivery, collector)
    before = native.owner.state.materialization_digest()
    with pytest.raises((EventContractError, StateError)):
        dispatcher.bind_es_delivery_to_action_cohort(
            batch, delivery=delivery, collector_process=collector
        )
    assert native.owner.state.materialization_digest() == before
    dispatcher.cancel_prepared_action_cohort_batch(batch)
    if native.owner.collectors.authenticates_pending_delivery(native.delivery):
        native.owner.collectors.cancel(native.delivery)
    emitter.close()


@pytest.mark.parametrize("status", ["delayed", "filtered", "dropped", "out_of_window"])
def test_native_collection_gap_does_not_suppress_canonical_exit(
    tmp_path: Path, status: ObservationStatus
) -> None:
    native, dispatcher, emitter, batch, frozen = _setup(tmp_path, status=status)
    _bind(native, dispatcher, batch)
    dispatcher.publish_prepared_action_cohort_batch(batch)
    assert native.owner.collectors.completed_observation(native.delivery).status == status
    assert native.owner.collectors.retained_native_projection(native.delivery) == frozen
    assert (
        native.owner.state.get_process(native.collector.hostname, native.process.process.pid)
        is None
    )
    emitter.close()
    rows = [
        json.loads(line)
        for path in tmp_path.rglob("ecar.json")
        for line in path.read_text().splitlines()
    ]
    assert len(rows) == 1 and rows[0]["action"] == "TERMINATE"


def test_failed_counter_application_rolls_back_state_and_counters_and_cleans_reservations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    native, dispatcher, emitter, batch, _ = _setup(tmp_path)
    _bind(native, dispatcher, batch)
    before = native.owner.state.materialization_digest()
    connection = native.owner.collectors.connection(native.delivery.observation.source_instance)
    original = ESCollectorRegistry._apply_claimed_delivery

    def fail_after_apply(registry: ESCollectorRegistry, handle: object) -> None:
        original(registry, handle)
        raise RuntimeError("injected provisional counter failure")

    monkeypatch.setattr(ESCollectorRegistry, "_apply_claimed_delivery", fail_after_apply)
    with pytest.raises(RuntimeError, match="provisional counter failure"):
        dispatcher.publish_prepared_action_cohort_batch(batch)
    assert native.owner.state.materialization_digest() == before
    assert native.owner.collectors.connection(connection.source_instance) == connection
    assert native.owner.collectors.completed_observation(native.delivery) is None
    assert not native.owner.collectors.authenticates_pending_delivery(native.delivery)
    assert native.owner.collectors.snapshot()
    assert dispatcher.action_cohort_publication_census().retained_bytes == 0
    emitter.close()
    assert not list(tmp_path.rglob("ecar.json"))


def test_lost_counter_finalization_acknowledgement_is_adopted_without_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    native, dispatcher, emitter, batch, frozen = _setup(tmp_path)
    _bind(native, dispatcher, batch)
    original = ESCollectorRegistry._finalize_claimed_delivery
    attempts = 0

    def lose_ack(registry: ESCollectorRegistry, handle: object) -> None:
        nonlocal attempts
        attempts += 1
        original(registry, handle)
        raise RuntimeError("injected finalized counter lost acknowledgement")

    monkeypatch.setattr(ESCollectorRegistry, "_finalize_claimed_delivery", lose_ack)
    result = dispatcher.publish_prepared_action_cohort_batch(batch)
    assert attempts == 1
    assert dispatcher.authenticates_action_cohort_publication_receipt(result.receipt)
    assert (
        native.owner.collectors.completed_observation(native.delivery)
        == native.delivery.observation
    )
    assert native.owner.collectors.retained_native_projection(native.delivery) == frozen
    dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()


@pytest.mark.parametrize("after_write", [False, True])
def test_existing_source_failure_retains_completed_collector_and_frozen_native_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, after_write: bool
) -> None:
    from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter

    original = ExternalSortedLineWriter._commit_exact_row
    attempts = 0

    def fail_once(
        writer: ExternalSortedLineWriter, key: tuple[str, int, int], digest: str, row: object
    ) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            if after_write:
                original(writer, key, digest, row)
            raise RuntimeError("injected source failure")
        original(writer, key, digest, row)

    monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", fail_once)
    native, dispatcher, emitter, batch, frozen = _setup(tmp_path, threaded=False)
    _bind(native, dispatcher, batch)
    with pytest.raises(RuntimeError, match="source failure") as caught:
        dispatcher.publish_prepared_action_cohort_batch(batch)
    assert (
        native.owner.collectors.completed_observation(native.delivery)
        == native.delivery.observation
    )
    assert native.owner.collectors.retained_native_projection(native.delivery) == frozen
    connection = native.owner.collectors.connection(native.delivery.observation.source_instance)
    version = native.owner.state.materialization_version
    result = dispatcher.resume_action_cohort_projection(caught.value.action_cohort_receipt)
    assert result.projections[0].status == "succeeded"
    assert native.owner.state.materialization_version == version
    assert native.owner.collectors.connection(connection.source_instance) == connection
    assert attempts == 2
    dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()
    rows = [line for path in tmp_path.rglob("ecar.json") for line in path.read_text().splitlines()]
    assert len(rows) == 1


@pytest.mark.parametrize("after_cancel", [False, True])
def test_collector_cleanup_failure_retains_retry_ownership_or_adopts_completed_cancel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, after_cancel: bool
) -> None:
    native, dispatcher, emitter, batch, _ = _setup(tmp_path)
    _bind(native, dispatcher, batch)
    original = ESCollectorRegistry.cancel
    attempts = 0

    def fail_once(registry: ESCollectorRegistry, delivery: object) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            if after_cancel:
                original(registry, delivery)
            raise RuntimeError("injected collector cancel failure")
        original(registry, delivery)

    monkeypatch.setattr(ESCollectorRegistry, "cancel", fail_once)
    if after_cancel:
        assert dispatcher.cancel_prepared_action_cohort_batch(batch)
        assert attempts == 1
    else:
        with pytest.raises(EventContractError, match="cancellation cleanup failed"):
            dispatcher.cancel_prepared_action_cohort_batch(batch)
        assert native.owner.collectors.authenticates_pending_delivery(native.delivery)
        assert dispatcher.cancel_prepared_action_cohort_batch(batch)
        assert attempts == 2
    assert dispatcher.action_cohort_publication_census().retained_bytes == 0
    assert not native.owner.collectors.authenticates_pending_delivery(native.delivery)
    assert native.owner.collectors.snapshot()
    emitter.close()


def test_native_bytes_use_existing_aggregate_retention_limit(tmp_path: Path) -> None:
    native, dispatcher, emitter, batch, _ = _setup(tmp_path)
    dispatcher._action_cohort_byte_capacity = (
        dispatcher.action_cohort_publication_census().retained_bytes
    )
    with pytest.raises(EventContractError, match="retained capacity"):
        _bind(native, dispatcher, batch)
    assert native.owner.collectors.authenticates_pending_delivery(native.delivery)
    dispatcher.cancel_prepared_action_cohort_batch(batch)
    native.owner.collectors.cancel(native.delivery)
    emitter.close()


@pytest.mark.parametrize("kind,subject_client", [("fork", False), ("exec", False), ("exec", True)])
@pytest.mark.parametrize("collected", [False, True])
def test_bound_fork_and_exec_publish_through_the_same_canonical_owner(
    tmp_path: Path, kind: str, collected: bool, subject_client: bool
) -> None:
    from evidenceforge.generation.actions.posix_process import (
        process_exec_occurrence,
        process_fork_occurrence,
    )
    from tests.unit.test_macos_es_exec_preparation import _fixture as exec_fixture
    from tests.unit.test_macos_es_exec_preparation import _prepare as prepare_exec_native
    from tests.unit.test_macos_es_fork_preparation import _fixture as fork_fixture
    from tests.unit.test_macos_es_fork_preparation import _prepare as prepare_fork_native

    native = fork_fixture(born_loaded=True) if kind == "fork" else exec_fixture(born_loaded=True)
    state = native.owner.state
    collector = native.parent.process if kind == "fork" else native.collector
    target = native.child.process if kind == "fork" else native.after.process
    if subject_client:
        from tests.unit.test_es_collector import _profile

        actor = native.before.process
        native.owner.open(
            _profile(
                source_instance="replaced-client",
                hostname=actor.hostname,
                opened_at=actor.started_at,
                last_delivery_at=actor.started_at,
            ),
            actor,
        )
        native.before = replace(native.before, is_es_client=True)
    registry = LifecycleRegistry(shard_count=4)
    shadow = LifecycleShadow(state, registry)
    authority = GeneratorLifecycleAuthority(state, shadow, shard_count=4)
    authority.bootstrap_active_state()
    emitter = EcarEmitter(load_format("ecar"), tmp_path, threaded=True)
    dispatcher = EventDispatcher(
        state,
        {"ecar": emitter} if collected else {},
        lifecycle_shadow=shadow,
        enforce_lifecycle_authority=True,
    )
    dispatcher.bind_lifecycle_authority(authority)
    dispatcher.bind_execution_effect_audit(ExecutionEffectAuditCounter())
    dispatcher.es_collectors = native.owner.collectors
    dispatcher.local_artifact_registry = native.executables if kind == "fork" else native.artifacts
    host = HostContext(
        hostname=target.hostname,
        ip="192.0.2.41",
        os="macOS 26",
        os_category="macos",
        system_type="workstation",
    )
    if kind == "fork":
        event = process_fork_occurrence(
            host=host, parent=native.parent.process, child=target, integrity_level="Medium"
        )
        with prepare_fork_native(native) as prepared:
            frozen = prepared.ndjson
    else:
        event = process_exec_occurrence(
            host=host, before=native.before.process, after=target, integrity_level="Medium"
        )
        with prepare_exec_native(native) as prepared:
            frozen = prepared.ndjson
    batch = prepare_dispatch(
        dispatcher,
        native.cohort,
        event,
        exact=True,
        root=native.delivery.observation.occurrence_id,
    )
    dispatcher.bind_es_delivery_to_action_cohort(
        batch, delivery=native.delivery, collector_process=collector
    )
    result = dispatcher.publish_prepared_action_cohort_batch(batch)
    assert dispatcher.authenticates_action_cohort_publication_receipt(result.receipt)
    assert state.get_process_identity(target.hostname, target.pid) == target
    assert (
        native.owner.collectors.completed_observation(native.delivery)
        == native.delivery.observation
    )
    assert native.owner.collectors.retained_native_projection(native.delivery) == frozen
    if subject_client:
        row = json.loads(frozen)
        assert row["process"]["is_es_client"] is True
        assert row["event"]["exec"]["target"]["is_es_client"] is False
        assert (
            native.owner.collectors.connection("replaced-client").closed_at
            == target.execution_started_at
        )
        observer = native.owner.collectors.connection(native.delivery.observation.source_instance)
        assert observer.closed_at is None and observer.next_delivery == 1
        assert {"es_collector", "es_closures"} <= dict(
            result.receipt.nested_publication_tokens
        ).keys()
    dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()
    rows = [
        json.loads(line)
        for path in tmp_path.rglob("ecar.json")
        for line in path.read_text().splitlines()
    ]
    assert len(rows) == int(collected)
    if rows:
        assert rows[0]["action"] == ("CREATE" if kind == "fork" else "MODIFY")


@pytest.mark.parametrize("field,value", [("seq_num", 999), ("source_instance", "foreign:client")])
def test_changed_delivery_cannot_publish_and_cleanup_releases_its_original_reservation(
    tmp_path: Path, field: str, value: object
) -> None:
    native, dispatcher, emitter, batch, _ = _setup(tmp_path)
    _bind(native, dispatcher, batch)
    before = native.owner.state.materialization_digest()
    object.__setattr__(native.delivery.observation, field, value)
    with pytest.raises((EventContractError, StateError)):
        dispatcher.publish_prepared_action_cohort_batch(batch)
    assert native.owner.state.materialization_digest() == before
    assert dispatcher.action_cohort_publication_census().retained_bytes == 0
    assert native.owner.collectors.snapshot()
    emitter.close()


def test_completed_joint_publication_restores_counter_and_terminal_state_together(
    tmp_path: Path,
) -> None:
    from evidenceforge.generation.checkpoints.dispatcher_observation_head import (
        DispatcherObservationParticipant,
    )
    from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
    from evidenceforge.generation.state_manager import StateManager

    native, dispatcher, emitter, batch, _ = _setup(tmp_path, collected=False, status="filtered")
    _bind(native, dispatcher, batch)
    participant = DispatcherObservationParticipant(dispatcher)
    with pytest.raises(StateError, match="checkpoint"):
        participant.prepare_checkpoint(1)
    dispatcher.publish_prepared_action_cohort_batch(batch)
    seal = participant.prepare_checkpoint(1)
    restored_state = StateManager()
    _restore_head(restored_state, _capture_head(native.owner.state))
    restored = EventDispatcher(restored_state, {})
    DispatcherObservationParticipant(restored).restore_checkpoint(seal.head.payload, ())
    assert restored.es_collectors.snapshot() == dispatcher.es_collectors.snapshot()
    subject = native.process.process
    assert restored_state.get_process(subject.hostname, subject.pid) is None
    assert (
        restored_state.get_process_identity(native.collector.hostname, native.collector.pid)
        == native.collector
    )
    emitter.close()


@pytest.mark.slow
@pytest.mark.parametrize("installed", [False, True])
def test_joint_publication_is_stable_across_process_hash_seed_filtering_and_threads(
    installed: bool,
) -> None:
    import os
    import subprocess
    import sys
    import textwrap

    script = textwrap.dedent(
        """
        import json
        import sys
        import tempfile
        from pathlib import Path
        from tests.unit.test_macos_es_dispatch_publication import _setup, _bind
        with tempfile.TemporaryDirectory() as directory:
            native, dispatcher, emitter, batch, frozen = _setup(
                Path(directory), installed=sys.argv[1] == "True",
                collected=sys.argv[2] == "True", threaded=sys.argv[3] == "True",
            )
            _bind(native, dispatcher, batch)
            dispatcher.publish_prepared_action_cohort_batch(batch)
            emitter.close()
            print(json.dumps({
                "native": frozen,
                "state": native.owner.state.materialization_digest(),
                "collectors": [state.model_dump_json() for state in native.owner.collectors.snapshot()],
            }, sort_keys=True))
        """
    )
    results: list[str] = []
    for seed, collected, threaded in (
        ("17", True, False),
        ("83", True, True),
        ("137", False, True),
    ):
        completed = subprocess.run(
            [sys.executable, "-c", script, str(installed), str(collected), str(threaded)],
            env=dict(os.environ, PYTHONHASHSEED=seed),
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
        results.append(completed.stdout)
    assert len(set(results)) == 1
