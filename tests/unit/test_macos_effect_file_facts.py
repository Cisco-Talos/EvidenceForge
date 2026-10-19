# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from datetime import timedelta

import pytest

from evidenceforge.formats.macos_file_metadata import es_file_from_runtime_record
from evidenceforge.generation.checkpoints.artifact_registry_head import (
    LocalArtifactVersionRegistryParticipant,
)
from evidenceforge.generation.deployment_registry import LocalArtifactPublishToken
from evidenceforge.generation.runtime_content import RuntimeContentIdentityManager
from tests.unit.test_macos_runtime_file_metadata import _manager, _metadata
from tests.unit.test_process_exec_projection import _START


def _prepare(
    manager: RuntimeContentIdentityManager, **changes: object
) -> LocalArtifactPublishToken:
    token = manager.prepare_effect_publication(
        **(
            dict(
                root_action_id="invented-file-write",
                stable_source_id="invented-file",
                hostname="MAC-A",
                principal="root",
                platform="macos",
                architecture=None,
                native_path="/Library/LaunchDaemons/org.example.invented.plist",
                action="create",
                observed_at=_START,
                owner_kind="system",
                macos_file=_metadata(),
            )
            | changes
        )
    )
    assert token is not None
    return token


@pytest.mark.parametrize("size", [0, 512, 4097])
def test_complete_file_observation_supplies_object_and_size_once(size: int) -> None:
    manager = _manager()
    metadata = _metadata(size_bytes=size)
    token = _prepare(manager, macos_file=metadata)
    assert token.record.content.size_bytes == size
    assert token.record.content.file_object_id == metadata.file_object_id
    assert token.record.macos_file == metadata
    assert manager.census().live_versions == 0
    with manager.registry.prepared_publication(token) as publication:
        publication.commit()
    record = manager.registry.resolve_version(token.record.artifact.artifact_version_id)
    assert record == token.record
    assert es_file_from_runtime_record(record).stat.st_size == size
    # Supplying matching legacy scalar values produces the same canonical truth.
    other = _manager()
    redundant = _prepare(
        other,
        macos_file=metadata,
        authored_size_bytes=size,
        authored_file_object_id=metadata.file_object_id,
    )
    assert redundant.record == record
    other.registry.cancel_prepared(redundant)


@pytest.mark.parametrize(
    "changes",
    [
        {"authored_size_bytes": 7},
        {"authored_size_bytes": True},
        {"authored_size_bytes": 512.0},
        {"authored_file_object_id": "another-file"},
        {"platform": "linux"},
    ],
)
def test_conflicting_or_foreign_facts_fail_before_any_reservation(
    changes: dict[str, object],
) -> None:
    manager = _manager()
    with pytest.raises(ValueError, match="disagrees|requires a Mac"):
        _prepare(manager, **changes)
    assert manager.census().live_versions == manager.census().prepared_publications == 0


def test_observed_file_facts_are_detached_and_survive_checkpoint_restore() -> None:
    manager = _manager()
    metadata = _metadata()
    token = _prepare(manager, macos_file=metadata)
    object.__setattr__(metadata, "inode", 9999)
    assert token.record.macos_file.inode == 735
    with manager.registry.prepared_publication(token) as publication:
        publication.commit()
    del publication
    checkpoint = LocalArtifactVersionRegistryParticipant(manager.registry).prepare_checkpoint(1)
    restored = _manager()
    LocalArtifactVersionRegistryParticipant(restored.registry).restore_checkpoint(
        checkpoint.head.payload, ()
    )
    assert (
        restored.registry.resolve_version(token.record.artifact.artifact_version_id) == token.record
    )


def test_omitted_metadata_keeps_legacy_unknown_length_and_object_derivation() -> None:
    manager = _manager()
    token = _prepare(manager, macos_file=None)
    assert token.record.macos_file is None
    assert token.record.content.size_bytes == 0
    assert token.record.content.file_object_id != _metadata().file_object_id
    manager.registry.cancel_prepared(token)


def test_cancelled_observation_does_not_publish_or_change_subsequent_content() -> None:
    manager = _manager()
    token = _prepare(manager)
    expected = token.record
    with manager.registry.prepared_publication(token):
        pass
    assert manager.census().live_versions == 0
    retried = _prepare(manager, observed_at=_START + timedelta(seconds=1))
    assert retried.record == expected
    manager.registry.cancel_prepared(retried)
