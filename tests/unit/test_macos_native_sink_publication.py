# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

import json
from pathlib import Path

import pytest

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.dispatcher import EventDispatcher, PreparedActionCohortBatch
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.actions.command_effects import (
    ExecutionEffectAuditCohortEntry,
    ExecutionEffectPlan,
)
from evidenceforge.generation.actions.posix_process import process_exit_occurrence
from evidenceforge.generation.deployment_registry import LocalArtifactPublishToken
from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter
from evidenceforge.generation.macos_es_native_sink import create_es_native_sink
from evidenceforge.generation.state_manager import ActionCohortMaterializationPlan
from tests.unit.test_macos_es_dispatch_publication import _setup


def _prepare(
    dispatcher: EventDispatcher,
    cohort: ActionCohortMaterializationPlan,
    events: tuple[OccurrenceBuilder, ...],
    *,
    root: str,
    artifact_publications: tuple[LocalArtifactPublishToken, ...] = (),
    **native: object,
) -> PreparedActionCohortBatch:
    with dispatcher.source_timing_planner.prepared_planning() as timing:
        carriers = tuple(
            dispatcher.prepare_action_cohort_projection(event, source_timing_preparation=timing)
            for event in events
        )
    members = tuple(
        dispatcher.bind_action_cohort_projection(
            carrier,
            state_plan=cohort,
            artifact_publications=artifact_publications if index == 0 else (),
        )
        for index, carrier in enumerate(carriers)
    )
    effects = ExecutionEffectPlan(ActionAnchor("process_execution", root, source="unit_test"), ())
    return dispatcher.prepare_action_cohort_batch(
        root,
        cohort,
        members,
        (ExecutionEffectAuditCohortEntry(effects, effects.reconcile(())),),
        (),
        (),
        exact_projection=True,
        **native,
    )


def _native_setup(tmp_path: Path, *, status: str = "visible", collected: bool = True) -> tuple:
    native, dispatcher, emitter, old, frozen = _setup(
        tmp_path, collected=collected, status=status, threaded=False
    )
    assert dispatcher.cancel_prepared_action_cohort_batch(old)
    from evidenceforge.events.contexts import HostContext

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
    sink = create_es_native_sink(tmp_path / "native.ndjson")
    batch = _prepare(
        dispatcher,
        native.cohort,
        (event,),
        root=f"process-exit:{subject.object_id}",
        es_delivery=native.delivery,
        es_collector_process=native.collector,
        es_native_sink=sink,
    )
    return native, dispatcher, emitter, batch, frozen, sink


@pytest.mark.parametrize("collected", [False, True])
@pytest.mark.parametrize("status", ["visible", "delayed", "filtered", "dropped", "out_of_window"])
def test_native_export_joins_exact_publication_and_uses_frozen_visibility(
    tmp_path: Path, collected: bool, status: str
) -> None:
    native, dispatcher, emitter, batch, frozen, sink = _native_setup(
        tmp_path, status=status, collected=collected
    )
    assert sink.event_count == 0
    result = dispatcher.publish_prepared_action_cohort_batch(batch)
    assert dispatcher.authenticates_action_cohort_publication_receipt(result.receipt)
    assert (
        native.owner.collectors.completed_observation(native.delivery)
        == native.delivery.observation
    )
    assert (
        native.owner.state.get_process(native.process.process.hostname, native.process.process.pid)
        is None
    )
    dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()
    sink.close()
    expected = frozen if status in {"visible", "delayed"} else ""
    assert (sink.output_path.read_text() if sink.output_path.exists() else "") == expected


@pytest.mark.parametrize("after_write", [False, True])
def test_native_write_failure_resumes_without_repeating_canonical_owners(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, after_write: bool
) -> None:
    original = ExternalSortedLineWriter._commit_exact_row
    attempts = 0
    sink = None

    def fail(writer: ExternalSortedLineWriter, key: tuple, digest: str, row: object) -> None:
        nonlocal attempts
        if writer is sink:
            attempts += 1
            if attempts == 1:
                if after_write:
                    original(writer, key, digest, row)
                raise RuntimeError("invented native sink failure")
        original(writer, key, digest, row)

    with monkeypatch.context() as patch:
        patch.setattr(ExternalSortedLineWriter, "_commit_exact_row", fail)
        native, dispatcher, emitter, batch, frozen, sink = _native_setup(tmp_path)
        with pytest.raises(RuntimeError, match="native sink failure") as caught:
            dispatcher.publish_prepared_action_cohort_batch(batch)
        version = native.owner.state.materialization_version
        profile = native.owner.collectors.connection(native.delivery.observation.source_instance)
        result = dispatcher.resume_action_cohort_projection(caught.value.action_cohort_receipt)
        assert dispatcher.authenticates_action_cohort_publication_receipt(result.receipt)
        assert native.owner.state.materialization_version == version
        assert native.owner.collectors.connection(profile.source_instance) == profile
        assert attempts == 2
    dispatcher.assert_exact_projection_recoveries_drained()
    emitter.close()
    sink.close()
    assert sink.output_path.read_text() == frozen
    rows = [
        json.loads(line)
        for path in tmp_path.rglob("ecar.json")
        for line in path.read_text().splitlines()
    ]
    assert len(rows) == 1


def test_cancel_releases_native_capacity_and_reservation_without_writing(tmp_path: Path) -> None:
    native, dispatcher, emitter, batch, _, sink = _native_setup(tmp_path)
    before = native.owner.state.materialization_digest()
    assert dispatcher.cancel_prepared_action_cohort_batch(batch)
    assert native.owner.state.materialization_digest() == before
    assert not native.owner.collectors.authenticates_pending_delivery(native.delivery)
    assert sink.exact_journal_census().reserved_rows == 0
    emitter.close()
    sink.close()
    assert not sink.output_path.exists() or sink.output_path.read_bytes() == b""


@pytest.mark.parametrize("field", ["seq_num", "global_seq_num", "time", "audit_token", "exit_stat"])
def test_initial_frozen_native_bytes_must_match_their_canonical_delivery(
    tmp_path: Path, field: str
) -> None:
    from datetime import timedelta

    from evidenceforge.events.contexts import HostContext
    from evidenceforge.events.observation import ObservationDecision
    from evidenceforge.models.exceptions import EventContractError

    native, dispatcher, emitter, old, frozen = _setup(tmp_path, threaded=False)
    assert dispatcher.cancel_prepared_action_cohort_batch(old)
    observation = native.delivery.observation
    native.owner.collectors.cancel(native.delivery)
    delivery = native.owner.prepare(
        source_instance=observation.source_instance,
        process=native.collector,
        generation=observation.generation,
        delivery=observation.delivery,
        occurrence_id=observation.occurrence_id,
        event_type=observation.event_type,
        observed_at=observation.observed_at,
        decision=ObservationDecision("visible"),
    )
    raw = json.loads(frozen)
    if field in {"seq_num", "global_seq_num"}:
        raw[field] += 1
    elif field == "time":
        raw[field] = (observation.observed_at + timedelta(seconds=1)).strftime(
            "%Y-%m-%dT%H:%M:%S.%f"
        ) + "000Z"
    elif field == "audit_token":
        raw["process"]["audit_token"]["pidversion"] += 1
    else:
        raw["event"]["exit"]["stat"] = 256
    with native.owner.prepared_commit(delivery, native.collector) as prepared:
        # The generic counter owner deliberately treats the renderer's bytes as
        # opaque. The native publication boundary must enforce the semantic join.
        prepared.freeze_native_projection(
            json.dumps(raw) + "\n", canonical_token=native.cohort.publication_token
        )
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
    sink = create_es_native_sink(tmp_path / "invalid-native.ndjson")
    before = native.owner.state.materialization_digest()
    profile = native.owner.collectors.connection(observation.source_instance)
    with pytest.raises(EventContractError, match="counters|event time|token|terminal outcome"):
        _prepare(
            dispatcher,
            native.cohort,
            (event,),
            root=f"process-exit:{subject.object_id}",
            es_delivery=delivery,
            es_collector_process=native.collector,
            es_native_sink=sink,
        )
    assert native.owner.state.materialization_digest() == before
    assert native.owner.collectors.connection(profile.source_instance) == profile
    assert sink.exact_journal_census().admitted_rows == 0
    native.owner.collectors.cancel(delivery)
    emitter.close()
    sink.close()
