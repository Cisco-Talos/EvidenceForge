# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented canonical file facts exercise exact native publication and placement fences."""

from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from evidenceforge.events.content_identity import LocalArtifactVersionRecord
from evidenceforge.events.contexts import HostContext
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.macos_execution_directory import MacosExecutionDirectory
from evidenceforge.events.macos_file import MacosDirectoryMetadata
from evidenceforge.events.macos_file_operation import MacosFileOperationObservation
from evidenceforge.formats.macos_endpoint_security import decode_endpoint_security_record
from evidenceforge.generation.actions.macos_filesystem import (
    MacosFilesystemActionBundle,
    MacosFilesystemRequest,
)
from evidenceforge.generation.emitters.macos_endpoint_security import MacosEndpointSecurityEmitter
from evidenceforge.generation.macos_es_ingress import MacosESIngress
from evidenceforge.generation.macos_es_source import MacosESSource
from evidenceforge.generation.runtime_content import RuntimeContentIdentityManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_es_source_integration import _routed
from tests.unit.test_macos_launch_file import _descriptor, _spec
from tests.unit.test_macos_runtime_file_metadata import _metadata


def _file(
    dispatcher: EventDispatcher,
    actor: ProcessIdentity,
    time: datetime,
    *,
    size: int = 0,
    version: int = 1,
    name: str = "source",
    inode: int = 30001,
) -> LocalArtifactVersionRecord:
    manager = RuntimeContentIdentityManager(dispatcher.local_artifact_registry)
    descriptor = replace(
        _descriptor(_spec(), version),
        hostname=actor.hostname,
        principal=actor.principal,
        native_path=f"/Users/invented/{name}",
        launchd_job=None,
        source_object_id=name,
        file_object_id=name,
        size_bytes=size,
        seed_ref=f"invented-content-{name}-{version}",
        macos_file=_metadata(
            file_object_id=name,
            inode=inode,
            size_bytes=size,
            uid=actor.credentials.effective_uid,
            gid=actor.credentials.effective_gid,
        ),
    )
    token = manager.prepare_publication(descriptor, time)
    record = token.record
    manager.registry.cancel_prepared(token)
    return record


def _parent(source: LocalArtifactVersionRecord, time: datetime) -> MacosExecutionDirectory:
    facts = source.macos_file.model_dump() | {
        "file_object_id": "invented-directory",
        "inode": 30000,
        "mode": 0o040755,
        "size_bytes": 96,
        "link_count": 3,
    }
    return MacosExecutionDirectory(
        source.artifact.hostname,
        "/Users/invented",
        time,
        MacosDirectoryMetadata.model_validate(facts),
    )


def _environment(
    tmp_path: Path, exported: bool = True
) -> tuple[
    MacosESSource, EventDispatcher, MacosEndpointSecurityEmitter, HostContext, ProcessIdentity
]:
    source, dispatcher, output, _, event, _, actor, _ = _routed(
        tmp_path / "output", exported=exported
    )
    dispatcher.macos_es_ingress = MacosESIngress(tmp_path / "ingress")
    return source, dispatcher, output, event.src_host, actor


@pytest.mark.parametrize("exported", [False, True])
@pytest.mark.parametrize("replacement", [False, True])
def test_create_modified_close_rename_unlink_share_canonical_file_and_actor(
    tmp_path: Path,
    exported: bool,
    replacement: bool,
) -> None:
    source, dispatcher, output, host, actor = _environment(tmp_path, exported)
    bundle = MacosFilesystemActionBundle(dispatcher)
    start = actor.execution_started_at + timedelta(seconds=3)
    empty = _file(dispatcher, actor, start)
    full = _file(dispatcher, actor, start, size=1537, version=2)
    target = replace(
        full, artifact=replace(full.artifact, native_path="/Users/invented/target", version=3)
    )
    old_target = (
        _file(dispatcher, actor, start, name="target", inode=30002) if replacement else None
    )
    if old_target is not None:
        registry = dispatcher.local_artifact_registry
        token = registry.prepare_publish_version(old_target, start - timedelta(seconds=1))
        with registry.prepared_publication(token) as prepared:
            prepared.commit()
    observations = (
        MacosFileOperationObservation("create", empty, start),
        MacosFileOperationObservation(
            "close",
            full,
            start + timedelta(seconds=1),
            previous=empty,
            modified=True,
            was_mapped_writable=False,
        ),
        MacosFileOperationObservation(
            "close", full, start + timedelta(seconds=2), modified=False, was_mapped_writable=False
        ),
        MacosFileOperationObservation(
            "rename",
            full,
            start + timedelta(seconds=3),
            parent=_parent(full, start + timedelta(seconds=3)),
            target=target,
            replacement=old_target,
        ),
        MacosFileOperationObservation(
            "unlink",
            target,
            start + timedelta(seconds=4),
            parent=_parent(target, start + timedelta(seconds=4)),
        ),
    )
    for index, observation in enumerate(observations):
        result = bundle.execute(
            MacosFilesystemRequest(f"file-step-{index}", host, actor, observation)
        )
        assert result.projection_errors == (None,)
    registry = dispatcher.local_artifact_registry
    assert (
        registry.resolve_record_for_execution_path(
            actor.hostname, actor.principal, empty.artifact.native_path, "macos"
        )
        is None
    )
    assert (
        registry.resolve_record_for_execution_path(
            actor.hostname, actor.principal, target.artifact.native_path, "macos"
        )
        is None
    )
    assert registry.resolve_version(full.artifact.artifact_version_id) == full
    assert registry.census().prepared_publications == 0
    assert dispatcher.macos_es_ingress.event_count == 5
    dispatcher.macos_es_ingress.finalize(dispatcher)
    assert dispatcher.es_collectors.connection(source.source_instance).next_delivery == 5
    output.close()
    paths = list((tmp_path / "output").rglob("macos_endpoint_security.ndjson"))
    if exported:
        records = [
            decode_endpoint_security_record(line) for line in paths[0].read_text().splitlines()
        ]
        assert [record.event_type for record in records] == [13, 12, 12, 25, 32]
        assert [record.global_seq_num for record in records] == list(range(5))
        assert all(record.process.audit_token.pid == actor.pid for record in records)
        assert records[0].event.create.destination.existing_file.stat.st_size == 0
        assert records[1].event.close.modified is True
        assert records[1].event.close.target.stat.st_size == 1537
        assert records[2].event.close.modified is False
        assert records[3].event.rename.destination_type == (0 if replacement else 1)
        if replacement:
            assert records[3].event.rename.destination.existing_file.stat.st_ino == 30002
        assert records[4].event.unlink.target.stat.st_nlink == 1
        assert records[4].event.unlink.target.stat.st_ino == 30001
    else:
        assert paths == []


def test_file_placement_race_rejects_before_state_and_source_commit(tmp_path: Path) -> None:
    _, dispatcher, output, host, actor = _environment(tmp_path)
    time = actor.execution_started_at + timedelta(seconds=3)
    source = _file(dispatcher, actor, time)
    bundle = MacosFilesystemActionBundle(dispatcher)
    batch = bundle.prepare(
        MacosFilesystemRequest(
            "raced-create", host, actor, MacosFileOperationObservation("create", source, time)
        )
    )
    rival = _file(dispatcher, actor, time, inode=30003, name="rival")
    rival = replace(
        rival, artifact=replace(rival.artifact, native_path=source.artifact.native_path)
    )
    registry = dispatcher.local_artifact_registry
    token = registry.prepare_publish_version(rival, time)
    with registry.prepared_publication(token) as publication:
        publication.commit()
    before = dispatcher.state_manager.materialization_digest()
    with pytest.raises(StateError, match="expected current placement"):
        dispatcher.publish_prepared_action_cohort_batch(batch)
    assert dispatcher.state_manager.materialization_digest() == before
    assert dispatcher.macos_es_ingress.event_count == 0
    assert registry.census().prepared_publications == 0
    output.close()


def test_ecar_file_identity_matches_the_same_canonical_operation() -> None:
    from tests.unit.test_macos_persistence_workflow import _workflow

    persistence, plan, host, _, _, emitter = _workflow()
    dispatcher, actor = persistence.dispatcher, plan.identity
    time = actor.execution_started_at + timedelta(seconds=3)
    record = _file(dispatcher, actor, time)
    result = MacosFilesystemActionBundle(dispatcher).execute(
        MacosFilesystemRequest(
            "invented-ecar-create",
            host,
            actor,
            MacosFileOperationObservation("create", record, time),
        )
    )
    assert result.projection_errors == (None,)
    event = emitter.emit.call_args.args[0]
    assert event.file.artifact_identity == record.artifact
    assert event.file.content_identity == record.content
    assert event.file.macos_metadata == record.macos_file
    assert event.identity_plan.actor == actor
    assert event.identity_plan.object_id == record.artifact.artifact_id
    assert event.file.pid == actor.pid


@pytest.mark.parametrize("lost_return", [False, True])
def test_artifact_commit_failure_never_splits_file_state_and_native_ingress(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    lost_return: bool,
) -> None:
    from evidenceforge.generation.deployment_registry import LocalArtifactPreparedGroupCommit

    _, dispatcher, output, host, actor = _environment(tmp_path)
    time = actor.execution_started_at + timedelta(seconds=3)
    record = _file(dispatcher, actor, time)
    bundle = MacosFilesystemActionBundle(dispatcher)
    request = MacosFilesystemRequest(
        "interrupted-file", host, actor, MacosFileOperationObservation("create", record, time)
    )
    original = LocalArtifactPreparedGroupCommit.commit_no_fail

    def fault(group: LocalArtifactPreparedGroupCommit) -> object:
        if lost_return:
            original(group)
        raise OSError("invented file artifact interruption")

    before = dispatcher.state_manager.materialization_digest()
    with monkeypatch.context() as scoped:
        scoped.setattr(LocalArtifactPreparedGroupCommit, "commit_no_fail", fault)
        if lost_return:
            result = bundle.execute(request)
            assert result.projection_errors == (None,)
        else:
            with pytest.raises(OSError, match="invented file artifact interruption"):
                bundle.execute(request)
    if not lost_return:
        assert dispatcher.state_manager.materialization_digest() == before
        assert dispatcher.macos_es_ingress.event_count == 0
        result = bundle.execute(request)
        assert result.projection_errors == (None,)
    assert dispatcher.macos_es_ingress.event_count == 1
    assert dispatcher.local_artifact_registry.census().prepared_publications == 0
    dispatcher.assert_exact_projection_recoveries_drained()
    output.close()


def test_file_source_tail_recovery_does_not_repeat_artifact_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter

    _, dispatcher, output, host, actor = _environment(tmp_path)
    time = actor.execution_started_at + timedelta(seconds=3)
    record = _file(dispatcher, actor, time)
    original = ExternalSortedLineWriter._commit_exact_row

    failed = False

    def fault(writer: ExternalSortedLineWriter, key: tuple, digest: str, content: object) -> None:
        nonlocal failed
        original(writer, key, digest, content)
        if not failed:
            failed = True
            raise OSError("invented file ingress lost return")

    with monkeypatch.context() as scoped:
        scoped.setattr(ExternalSortedLineWriter, "_commit_exact_row", fault)
        with pytest.raises(OSError, match="invented file ingress lost return") as caught:
            MacosFilesystemActionBundle(dispatcher).execute(
                MacosFilesystemRequest(
                    "file-source-tail",
                    host,
                    actor,
                    MacosFileOperationObservation("create", record, time),
                )
            )
    registry = dispatcher.local_artifact_registry
    version = dispatcher.state_manager.materialization_version
    assert registry.resolve_version(record.artifact.artifact_version_id) == record
    result = dispatcher.resume_action_cohort_projection(caught.value.action_cohort_receipt)
    assert result.projection_errors == (None,)
    assert dispatcher.state_manager.materialization_version == version
    assert dispatcher.macos_es_ingress.event_count == 1
    dispatcher.assert_exact_projection_recoveries_drained()
    dispatcher.macos_es_ingress.finalize(dispatcher)
    output.close()
    path = next((tmp_path / "output").rglob("macos_endpoint_security.ndjson"))
    assert len(path.read_text().splitlines()) == 1


@pytest.mark.parametrize("pending", [False, True])
def test_rename_destination_race_preserves_original_placement_and_source_rows(
    tmp_path: Path,
    pending: bool,
) -> None:
    _, dispatcher, output, host, actor = _environment(tmp_path)
    time = actor.execution_started_at + timedelta(seconds=3)
    source = _file(dispatcher, actor, time)
    bundle = MacosFilesystemActionBundle(dispatcher)
    bundle.execute(
        MacosFilesystemRequest(
            "create-before-rename",
            host,
            actor,
            MacosFileOperationObservation("create", source, time),
        )
    )
    at = time + timedelta(seconds=1)
    target = replace(
        source, artifact=replace(source.artifact, native_path="/Users/invented/target", version=2)
    )
    batch = bundle.prepare(
        MacosFilesystemRequest(
            "raced-rename",
            host,
            actor,
            MacosFileOperationObservation(
                "rename", source, at, parent=_parent(source, at), target=target
            ),
        )
    )
    rival = _file(dispatcher, actor, at, name="target", inode=30002)
    registry = dispatcher.local_artifact_registry
    token = registry.prepare_publish_version(rival, at)
    if not pending:
        with registry.prepared_publication(token) as publication:
            publication.commit()
    before = dispatcher.state_manager.materialization_digest()
    with pytest.raises(StateError, match="destination"):
        dispatcher.publish_prepared_action_cohort_batch(batch)
    assert dispatcher.state_manager.materialization_digest() == before
    assert (
        registry.resolve_record_for_execution_path(
            actor.hostname, actor.principal, source.artifact.native_path, "macos"
        )
        == source
    )
    assert dispatcher.macos_es_ingress.event_count == 1
    if pending:
        registry.cancel_prepared(token)
    assert registry.census().prepared_publications == 0
    output.close()


def test_file_operation_cannot_backdate_its_current_placement(tmp_path: Path) -> None:
    _, dispatcher, output, host, actor = _environment(tmp_path)
    time = actor.execution_started_at + timedelta(seconds=3)
    source = _file(dispatcher, actor, time)
    bundle = MacosFilesystemActionBundle(dispatcher)
    bundle.execute(
        MacosFilesystemRequest(
            "chronological-create",
            host,
            actor,
            MacosFileOperationObservation("create", source, time),
        )
    )
    before = dispatcher.state_manager.materialization_digest()
    with pytest.raises(StateError, match="chronological placement history"):
        bundle.execute(
            MacosFilesystemRequest(
                "backdated-close",
                host,
                actor,
                MacosFileOperationObservation(
                    "close",
                    source,
                    time - timedelta(seconds=1),
                    modified=False,
                    was_mapped_writable=False,
                ),
            )
        )
    assert dispatcher.state_manager.materialization_digest() == before
    assert dispatcher.macos_es_ingress.event_count == 1
    output.close()


def test_native_file_ingress_and_artifact_checkpoint_restore_exact_bytes(tmp_path: Path) -> None:
    from evidenceforge.generation.checkpoints.artifact_registry_head import (
        LocalArtifactVersionRegistryParticipant,
    )
    from evidenceforge.generation.checkpoints.dispatcher_observation_head import (
        DispatcherObservationParticipant,
    )
    from evidenceforge.generation.checkpoints.emitter_spools import EmitterSpoolParticipant
    from tests.support.state_checkpoint import capture_complete_state, restore_complete_state

    _, dispatcher, output, host, actor = _environment(tmp_path / "original")
    ingress = dispatcher.macos_es_ingress
    ingress.spool.enable_incremental_checkpointing()
    time = actor.execution_started_at + timedelta(seconds=3)
    file = _file(dispatcher, actor, time)
    MacosFilesystemActionBundle(dispatcher).execute(
        MacosFilesystemRequest(
            "checkpoint-file", host, actor, MacosFileOperationObservation("create", file, time)
        )
    )
    ingress.barrier_flush()
    head = DispatcherObservationParticipant(dispatcher).prepare_checkpoint(1).head.payload
    artifact_head = (
        LocalArtifactVersionRegistryParticipant(dispatcher.local_artifact_registry)
        .prepare_checkpoint(1)
        .head.payload
    )
    seal = EmitterSpoolParticipant(
        emitters={"macos_es_ingress": ingress.spool}, output_root=tmp_path
    ).prepare_checkpoint(1)
    _, fresh, fresh_output, _, _ = _environment(tmp_path / "restored")
    from tests.unit.test_macos_launch_file import _manager

    fresh.local_artifact_registry = _manager().registry
    restored = fresh.macos_es_ingress
    restored.spool.enable_incremental_checkpointing()
    restore_complete_state(fresh.state_manager, capture_complete_state(dispatcher.state_manager))
    DispatcherObservationParticipant(fresh).restore_checkpoint(head, ())
    LocalArtifactVersionRegistryParticipant(fresh.local_artifact_registry).restore_checkpoint(
        artifact_head, ()
    )
    EmitterSpoolParticipant(
        emitters={"macos_es_ingress": restored.spool}, output_root=tmp_path
    ).restore_checkpoint(seal.head.payload, tuple(item.payload for item in seal.segments))
    assert fresh.local_artifact_registry.resolve_version(file.artifact.artifact_version_id) == file
    restored.assert_restored_count()
    restored.finalize(fresh)
    ingress.finalize(dispatcher)
    fresh_output.close()
    output.close()
    original = next((tmp_path / "original/output").rglob("macos_endpoint_security.ndjson"))
    resumed = next((tmp_path / "restored/output").rglob("macos_endpoint_security.ndjson"))
    assert original.read_bytes() == resumed.read_bytes()
