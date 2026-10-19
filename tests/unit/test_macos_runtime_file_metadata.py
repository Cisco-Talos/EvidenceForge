# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Synthetic file facts stay bound to exact published versions and retained snapshots."""

from dataclasses import replace

import pytest
from pydantic import ValidationError

from evidenceforge.events.content_identity import MachOCodeSignature, MachOImageIdentity
from evidenceforge.events.macos_file import MacosFileMetadata, MacosFileTime
from evidenceforge.formats.macos_file_metadata import es_file_from_runtime_record
from evidenceforge.generation.checkpoints.artifact_registry_head import (
    LocalArtifactVersionRegistryParticipant,
)
from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError
from evidenceforge.generation.checkpoints.packed import dumps, loads
from evidenceforge.generation.deployment_registry import _pack_artifact_payload
from evidenceforge.generation.runtime_content import RuntimeArtifactDescriptor
from tests.unit.test_macos_launch_file import _descriptor, _manager, _publish, _spec
from tests.unit.test_macos_launch_registration import _START


def _metadata(**changes: object) -> MacosFileMetadata:
    time = MacosFileTime(seconds=1_750_000_000, nanoseconds=123456789)
    return MacosFileMetadata.model_validate(
        dict(
            volume_id="invented-data-volume",
            file_object_id="invented-worker-plist",
            device=1,
            inode=735,
            mode=0o100644,
            link_count=1,
            uid=0,
            gid=0,
            special_device=0,
            accessed=time,
            modified=time,
            changed=time,
            born=MacosFileTime(seconds=1_749_999_999, nanoseconds=1),
            size_bytes=512,
            allocated_blocks=0,
            preferred_block_size=4096,
            flags=0,
            generation=1,
        )
        | changes
    )


def _executable() -> RuntimeArtifactDescriptor:
    return replace(
        _descriptor(_spec()),
        launchd_job=None,
        executable=True,
        architecture="arm64",
        native_path="/usr/local/libexec/invented-worker",
        mime_type="application/x-mach-binary",
        seed_ref="invented-image-content",
        macos_file=_metadata(mode=0o100755),
        code_signature=MachOCodeSignature("org.example.invented", None, "a" * 40),
        mach_o_image=MachOImageIdentity("bcb4f118-1063-4fe1-a520-d1eaf7222e17"),
    )


def test_published_file_has_exact_stat_and_distinct_content_and_signing_identity() -> None:
    manager = _manager()
    descriptor = _executable()
    _publish(manager, descriptor)
    record = manager.resolve_record("MAC-A", "root", descriptor.native_path, "macos")
    assert record.macos_file == descriptor.macos_file
    assert record.binary.code_signature == descriptor.code_signature
    assert record.binary.mach_o_image == descriptor.mach_o_image
    assert record.binary.digests == record.content.digests
    assert record.binary.code_signature.cdhash != record.content.digests.sha1
    file = es_file_from_runtime_record(record)
    assert file.path == descriptor.native_path
    assert file.path_truncated is False
    assert file.stat.st_size == 512
    assert file.stat.st_blocks == 0  # Explicit sparse/allocation fact, never ceil(size/512).
    assert file.stat.st_mtimespec.endswith(".123456789Z")
    assert file.stat.st_birthtimespec.endswith(".000000001Z")
    assert file.stat.st_ino == 735


@pytest.mark.parametrize("executable", [False, True])
def test_atomic_publication_and_checkpoint_retain_all_metadata(executable: bool) -> None:
    manager = _manager()
    descriptor = (
        _executable() if executable else replace(_descriptor(_spec()), macos_file=_metadata())
    )
    token = manager.prepare_publication(descriptor, _START)
    with manager.registry.prepared_publication(token):
        pass
    assert manager.resolve_record("MAC-A", "root", descriptor.native_path, "macos") is None
    _publish(manager, descriptor)
    seal = LocalArtifactVersionRegistryParticipant(manager.registry).prepare_checkpoint(1)
    assert seal.head.schema_version == "5"
    restored = _manager()
    LocalArtifactVersionRegistryParticipant(restored.registry).restore_checkpoint(
        seal.head.payload, ()
    )
    assert restored.resolve_record(
        "MAC-A", "root", descriptor.native_path, "macos"
    ) == manager.resolve_record("MAC-A", "root", descriptor.native_path, "macos")


def test_metadata_does_not_become_a_content_digest_or_path_identity() -> None:
    manager = _manager()
    first = manager.build_record(_executable())
    changed = manager.build_record(replace(_executable(), macos_file=_metadata(mode=0o100700)))
    assert first.content == changed.content
    assert first.artifact == changed.artifact
    assert first.binary == changed.binary
    assert first != changed
    assert _pack_artifact_payload(first.artifact, first) != _pack_artifact_payload(
        changed.artifact, changed
    )
    _publish(manager, _executable())
    with pytest.raises(ValueError):
        _publish(manager, replace(_executable(), macos_file=changed.macos_file))
    assert manager.resolve_record("MAC-A", "root", first.artifact.native_path, "macos") == first


def test_explicit_rename_keeps_file_object_and_inode_without_rewriting_old_observation() -> None:
    manager = _manager()
    first_descriptor = replace(_descriptor(_spec()), macos_file=_metadata())
    _publish(manager, first_descriptor)
    first = manager.resolve_record("MAC-A", "root", first_descriptor.native_path, "macos")
    moved = replace(
        first_descriptor,
        native_path="/Library/LaunchDaemons/org.example.moved.plist",
        artifact_version=2,
    )
    with manager.prepared_macos_file_rename(
        first,
        native_path=moved.native_path,
        artifact_version=moved.artifact_version,
        metadata=moved.macos_file,
        observed_at=_START,
    ) as rename:
        rename.commit()
    assert manager.resolve_record("MAC-A", "root", first_descriptor.native_path, "macos") is None
    second = manager.resolve_record("MAC-A", "root", moved.native_path, "macos")
    assert second.macos_file == first.macos_file
    assert second.content == first.content
    assert es_file_from_runtime_record(first).path == first_descriptor.native_path
    assert es_file_from_runtime_record(second).path == moved.native_path


@pytest.mark.parametrize(
    "changes",
    [
        {"size_bytes": 513},
        {"file_object_id": "different-file"},
    ],
)
def test_stat_must_match_the_canonical_content(changes: dict[str, object]) -> None:
    manager = _manager()
    with pytest.raises(ValueError, match="exact object, platform and size"):
        manager.prepare_publication(
            replace(_descriptor(_spec()), macos_file=_metadata(**changes)), _START
        )
    assert manager.census().live_versions == 0


@pytest.mark.parametrize(
    "changes",
    [
        {"inode": True},
        {"inode": 0},
        {"inode": 2**64},
        {"mode": 0o040755},
        {"allocated_blocks": -1},
        {"preferred_block_size": 0},
        {"uid": -1},
        {"device": 2**31},
        {"special_device": 7},
        {"volume_id": "bad\0id"},
    ],
)
def test_malformed_stat_facts_are_rejected(changes: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        _metadata(**changes)


@pytest.mark.parametrize(
    "changes",
    [
        {"nanoseconds": 1_000_000_000},
        {"nanoseconds": -1},
        {"seconds": True},
        {"seconds": 10**30},
    ],
)
def test_timespec_requires_exact_representable_fields(changes: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        MacosFileTime.model_validate(dict(seconds=0, nanoseconds=0) | changes)


@pytest.mark.parametrize("version", ["1", "2", "3"])
def test_older_heads_preserve_unknown_metadata_and_reject_new_facts(version: str) -> None:
    manager = _manager()
    # v1 predates launchd semantics as well.
    legacy = replace(_descriptor(_spec()), launchd_job=None)
    _publish(manager, legacy)
    document = loads(
        LocalArtifactVersionRegistryParticipant(manager.registry).prepare_checkpoint(1).head.payload
    )
    document["schema_version"] = version
    if version in {"1", "2"}:
        for row in document["records"]:
            row.pop()
    restored = _manager()
    LocalArtifactVersionRegistryParticipant(restored.registry).restore_checkpoint(
        dumps(document), ()
    )
    record = restored.resolve_record("MAC-A", "root", legacy.native_path, "macos")
    assert record.macos_file is None
    with pytest.raises(ValueError, match="complete canonical"):
        es_file_from_runtime_record(record)
    rich = _manager()
    _publish(rich, _executable())
    document = loads(
        LocalArtifactVersionRegistryParticipant(rich.registry).prepare_checkpoint(1).head.payload
    )
    document["schema_version"] = version
    if version in {"1", "2"}:
        for row in document["records"]:
            row.pop()
    with pytest.raises(CheckpointCorruptionError):
        LocalArtifactVersionRegistryParticipant(_manager().registry).restore_checkpoint(
            dumps(document), ()
        )


def test_prepared_metadata_is_detached_from_caller_mutation() -> None:
    manager = _manager()
    descriptor = _executable()
    token = manager.prepare_publication(descriptor, _START)
    object.__setattr__(descriptor.macos_file, "inode", 999)
    object.__setattr__(descriptor.code_signature, "cdhash", "b" * 40)
    object.__setattr__(token.record.macos_file, "uid", 999)
    with manager.registry.prepared_publication(token) as prepared:
        prepared.commit()
    record = manager.resolve_record("MAC-A", "root", descriptor.native_path, "macos")
    assert record.macos_file.inode == 735
    assert record.macos_file.uid == 0
    assert record.binary.code_signature.cdhash == "A" * 40


@pytest.mark.parametrize("collected", [False, True])
def test_file_metadata_uses_authenticated_process_effect_publication(collected: bool) -> None:
    from unittest.mock import patch

    from evidenceforge.generation.actions.process_execution import ProcessExecutionActionBundle
    from evidenceforge.generation.actions.process_support.preflight import ProcessPreflightPlanner
    from tests.unit import test_macos_launch_write as writer
    from tests.unit.test_generator_endpoint_effect_integration import (
        _events,
        _NoAmbientEffectsRandom,
    )

    publication = writer._publication

    def explicit_publication(manager, **changes):
        return publication(
            manager,
            **(
                dict(authored_file_object_id="invented-worker-plist", macos_file=_metadata())
                | changes
            ),
        )

    with patch.object(writer, "_publication", side_effect=explicit_publication):
        generator, _, emitter, manager, request = writer._writer(collected)
    with patch.object(
        ProcessPreflightPlanner,
        "_process_endpoint_effect_rng",
        return_value=_NoAmbientEffectsRandom(),
    ):
        ProcessExecutionActionBundle(generator, request).execute()
    record = manager.resolve_record("MAC-TEST", "root", writer._PATH, "macos")
    assert record.macos_file == _metadata()
    if collected:
        events = [
            event for event in _events(emitter) if event.file and event.file.path == writer._PATH
        ]
        assert len(events) == 1
        assert events[0].file.macos_metadata == record.macos_file
    else:
        emitter.emit.assert_not_called()
