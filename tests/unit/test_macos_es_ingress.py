# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented process snapshots test source chronology without native collection."""

import json
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from evidenceforge.formats.macos_endpoint_security import decode_endpoint_security_record
from evidenceforge.generation.actions.macos_ssh_receiver import MacosSshReceiverStartup
from evidenceforge.generation.checkpoints.dispatcher_observation_head import (
    DispatcherObservationParticipant,
)
from evidenceforge.generation.checkpoints.emitter_spools import EmitterSpoolParticipant
from evidenceforge.generation.macos_es_ingress import ESProcessIngressRow, MacosESIngress
from tests.unit.test_macos_es_source_integration import _routed


def _publish(tmp_path: Path, exported: bool = True) -> tuple:
    source, dispatcher, output, cohort, event, _, _, child = _routed(
        tmp_path / "output", exported=exported
    )
    ingress = MacosESIngress(tmp_path / "ingress")
    dispatcher.macos_es_ingress = ingress
    ingress.spool.enable_incremental_checkpointing()
    startup = object.__new__(MacosSshReceiverStartup)
    startup._dispatcher = dispatcher
    batch = startup._prepare_retained_publication(
        cohort, event, f"process-fork:{child.object_id}", ()
    )
    dispatcher.publish_prepared_action_cohort_batch(batch)
    dispatcher.assert_exact_projection_recoveries_drained()
    return source, dispatcher, output, ingress, event


@pytest.mark.parametrize("exported", [False, True])
def test_source_ingress_freezes_facts_then_sequences_out_of_order_occurrences(
    tmp_path: Path, exported: bool
) -> None:
    source, dispatcher, output, ingress, event = _publish(tmp_path, exported)
    assert source.connection().next_delivery == 0
    assert ingress.event_count == 1
    route = next(iter(ingress.spool._writers.values()))
    # An earlier omitted occurrence arrives after a later visible canonical birth.
    row = ESProcessIngressRow(
        host=event.src_host,
        initial=source.connection(),
        occurrence_id="earlier-filtered-exec",
        event_type=9,
        observed_at=event.timestamp - timedelta(microseconds=1),
        status="filtered",
        delay=timedelta(),
    )
    route._sorted_writer.write(row.encode())
    ingress.finalize(dispatcher)
    final = dispatcher.es_collectors.connection(source.source_instance)
    assert final.next_delivery == 2
    assert final.next_global_sequence == 2
    assert final.last_delivery_at == event.timestamp
    output.close()
    paths = list((tmp_path / "output").rglob("macos_endpoint_security.ndjson"))
    assert len(paths) == int(exported)
    if exported:
        records = [
            decode_endpoint_security_record(line) for line in paths[0].read_text().splitlines()
        ]
        assert len(records) == 1
        assert records[0].global_seq_num == 1
        assert records[0].seq_num == 0
        assert records[0].time.startswith(event.timestamp.isoformat()[:19])
    ingress.cleanup()
    assert not ingress.root.exists()


def test_source_ingress_rejects_sequence_fields_and_time_changes(tmp_path: Path) -> None:
    _, dispatcher, output, ingress, _ = _publish(tmp_path)
    ingress.spool.close()
    path = next(iter(ingress.spool._writers.values())).output_path
    row = ESProcessIngressRow.model_validate_json(path.read_text())
    body = json.loads(row.native_body)
    with pytest.raises(ValidationError, match="assigned delivery sequences"):
        ESProcessIngressRow.model_validate(
            dict(row) | {"native_body": json.dumps(body | {"seq_num": 3})}
        )
    with pytest.raises(ValidationError, match="occurrence family and time"):
        ESProcessIngressRow.model_validate(
            dict(row) | {"observed_at": row.observed_at + timedelta(seconds=1)}
        )
    output.close()


def test_source_ingress_retries_native_commit_without_duplicate_rows(
    tmp_path: Path, monkeypatch
) -> None:
    _, dispatcher, output, ingress, _ = _publish(tmp_path)
    from evidenceforge.generation.emitters.base import ExactPublicationBatch

    original = ExactPublicationBatch.commit
    failed = False

    def commit_then_fail(batch) -> None:
        nonlocal failed
        original(batch)
        if not failed:
            failed = True
            raise RuntimeError("injected after sink commit")

    monkeypatch.setattr(ExactPublicationBatch, "commit", commit_then_fail)
    with pytest.raises(RuntimeError, match="injected"):
        ingress.finalize(dispatcher)
    ingress.finalize(dispatcher)
    ingress.finalize(dispatcher)
    output.close()
    path = next((tmp_path / "output").rglob("macos_endpoint_security.ndjson"))
    assert len(path.read_text().splitlines()) == 1
    assert dispatcher.es_collectors.snapshot()[0].next_delivery == 1


def test_source_ingress_checkpoint_round_trip_and_legacy_mode(tmp_path: Path) -> None:
    _, dispatcher, output, ingress, _ = _publish(tmp_path / "first")
    ingress.spool.enable_incremental_checkpointing()
    ingress.barrier_flush()
    head = DispatcherObservationParticipant(dispatcher).prepare_checkpoint(1).head.payload
    spool = EmitterSpoolParticipant(
        emitters={"macos_es_ingress": ingress.spool}, output_root=tmp_path
    )
    seal = spool.prepare_checkpoint(1)
    assert seal.segments
    _, fresh, fresh_output, _, _, _, _, _ = _routed(tmp_path / "fresh-output")
    restored = MacosESIngress(tmp_path / "restored-ingress")
    restored.spool.enable_incremental_checkpointing()
    fresh.macos_es_ingress = restored
    DispatcherObservationParticipant(fresh).restore_checkpoint(head, ())
    restored_spool = EmitterSpoolParticipant(
        emitters={"macos_es_ingress": restored.spool}, output_root=tmp_path
    )
    restored_spool.restore_checkpoint(
        seal.head.payload, tuple(item.payload for item in seal.segments)
    )
    restored.assert_restored_count()
    assert restored.event_count == 1
    restored.finalize(fresh)
    fresh_output.close()
    assert (
        len(
            next((tmp_path / "fresh-output").rglob("macos_endpoint_security.ndjson"))
            .read_text()
            .splitlines()
        )
        == 1
    )
    participant = DispatcherObservationParticipant(dispatcher)
    participant.restore_checkpoint(head, ())
    ingress.assert_restored_count()
    from evidenceforge.generation.checkpoints.packed import dumps, loads

    legacy = loads(head)
    legacy["schema_version"] = "5"
    legacy.pop("es_ingress_enabled")
    legacy.pop("es_ingress_rows")
    participant.restore_checkpoint(dumps(legacy), ())
    assert ingress.enabled is False
    output.close()
    ingress.spool.close()


def test_cancelled_cohort_never_admits_source_snapshots(tmp_path: Path) -> None:
    source, dispatcher, output, cohort, event, _, _, child = _routed(tmp_path / "output")
    ingress = MacosESIngress(tmp_path / "ingress")
    dispatcher.macos_es_ingress = ingress
    startup = object.__new__(MacosSshReceiverStartup)
    startup._dispatcher = dispatcher
    before = dispatcher.state_manager.materialization_digest()
    batch = startup._prepare_retained_publication(
        cohort, event, f"process-fork:{child.object_id}", ()
    )
    assert ingress.event_count == 0
    dispatcher.cancel_prepared_action_cohort_batch(batch)
    assert ingress.event_count == 0
    assert dispatcher.state_manager.materialization_digest() == before
    assert source.connection().next_delivery == 0
    output.close()
    ingress.spool.close()


def test_source_ingress_retries_release_after_durable_native_admission(
    tmp_path: Path, monkeypatch
) -> None:
    _, dispatcher, output, ingress, _ = _publish(tmp_path)
    from evidenceforge.generation.emitters.base import ExactPublicationBatch

    original = ExactPublicationBatch.release_no_fail
    failed = False

    def release_then_fail(batch) -> None:
        nonlocal failed
        original(batch)
        if not failed:
            failed = True
            raise RuntimeError("injected after release")

    monkeypatch.setattr(ExactPublicationBatch, "release_no_fail", release_then_fail)
    with pytest.raises(RuntimeError, match="injected"):
        ingress.finalize(dispatcher)
    ingress.finalize(dispatcher)
    output.close()
    assert ingress._authority.census().active_batches == 0
    path = next((tmp_path / "output").rglob("macos_endpoint_security.ndjson"))
    assert len(path.read_text().splitlines()) == 1


def test_unknown_loaded_version_remains_counted_without_native_placeholder(tmp_path: Path) -> None:
    source, dispatcher, output, cohort, event, _, _, child = _routed(
        tmp_path / "output", known_version=False
    )
    ingress = MacosESIngress(tmp_path / "ingress")
    dispatcher.macos_es_ingress = ingress
    dispatcher.storyline_cluster_id = "unknown-loaded-version"
    startup = object.__new__(MacosSshReceiverStartup)
    startup._dispatcher = dispatcher
    batch = startup._prepare_retained_publication(
        cohort, event, f"process-fork:{child.object_id}", ()
    )
    dispatcher.publish_prepared_action_cohort_batch(batch)
    ingress.finalize(dispatcher)
    output.close()
    assert dispatcher.state_manager.get_process_identity(child.hostname, child.pid) == child
    assert dispatcher.es_collectors.snapshot()[0].next_delivery == 1
    observation = ingress.coverage.hosts[0].observations[0]
    assert observation.reason == "executable_version_unknown"
    assert observation.status == "filtered"
    assert not list((tmp_path / "output").rglob("macos_endpoint_security.ndjson"))
