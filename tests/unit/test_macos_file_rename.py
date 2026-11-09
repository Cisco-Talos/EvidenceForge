# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Independently authored canonical rename and loaded-content retention contracts."""

from contextlib import AbstractContextManager
from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.content_identity import LocalArtifactVersionRecord
from evidenceforge.events.macos_file import MacosFileTime
from evidenceforge.generation.checkpoints.artifact_registry_head import (
    LocalArtifactVersionRegistryParticipant,
)
from evidenceforge.generation.deployment_registry import (
    LocalArtifactCapacityError,
    LocalArtifactVersionRegistry,
)
from evidenceforge.generation.runtime_content import (
    PreparedMacosFileRename,
    RuntimeContentIdentityManager,
)
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_launch_registration import _START
from tests.unit.test_macos_runtime_file_metadata import _executable, _manager, _metadata


def _setup() -> tuple[RuntimeContentIdentityManager, LocalArtifactVersionRecord]:
    manager = _manager()
    descriptor = _executable()
    token = manager.prepare_publication(
        descriptor,
        _START,
        lease_owner="invented-loaded-image",
        lease_until=_START + timedelta(days=9),
    )
    with manager.registry.prepared_publication(token) as publication:
        publication.commit()
    return manager, token.record


def _rename(
    manager: RuntimeContentIdentityManager, source: LocalArtifactVersionRecord, **changes: object
) -> AbstractContextManager[PreparedMacosFileRename]:
    return manager.prepared_macos_file_rename(
        source,
        **dict(
            native_path="/usr/local/libexec/renamed-worker",
            artifact_version=2,
            metadata=source.macos_file.model_copy(
                update={"changed": MacosFileTime(seconds=1_750_000_001, nanoseconds=9)}
            ),
            observed_at=_START + timedelta(seconds=1),
            retention=timedelta(hours=1),
        )
        | changes,
    )


def _at(manager: RuntimeContentIdentityManager, path: str) -> LocalArtifactVersionRecord | None:
    return manager.resolve_record("MAC-A", "root", path, "macos")


def test_rename_preserves_loaded_content_and_does_not_restore_old_name_after_expiry() -> None:
    manager, source = _setup()
    old_path = source.artifact.native_path
    with _rename(manager, source) as rename:
        assert _at(manager, old_path) == source
        assert _at(manager, "/usr/local/libexec/renamed-worker") is None
        assert rename.committed_receipt is None
        receipt = rename.commit()
        assert rename.committed_receipt is receipt
        assert receipt is rename.expected_receipt
        assert manager.registry.authenticates_publication_group_receipt(receipt)
    target = _at(manager, "/usr/local/libexec/renamed-worker")
    assert target is not None
    assert _at(manager, old_path) is None
    assert target.content == source.content
    assert target.binary.code_signature == source.binary.code_signature
    assert target.binary.mach_o_image == source.binary.mach_o_image
    assert target.artifact.artifact_id == source.artifact.artifact_id
    assert target.artifact.artifact_version_id != source.artifact.artifact_version_id
    assert target.macos_file.inode == source.macos_file.inode
    assert target.binary.artifact_name == "renamed-worker"
    assert manager.registry.resolve_version(source.artifact.artifact_version_id) == source
    manager.registry.advance_watermark(_START + timedelta(days=2))
    assert _at(manager, old_path) is None
    assert _at(manager, target.artifact.native_path) == target
    assert manager.registry.resolve_version(source.artifact.artifact_version_id) == source
    manager.registry.advance_watermark(_START + timedelta(days=10))
    assert _at(manager, target.artifact.native_path) is None
    assert manager.registry.resolve_version(source.artifact.artifact_version_id) is None


def test_rename_checkpoint_retains_both_versions_and_only_new_placement() -> None:
    manager, source = _setup()
    with _rename(manager, source) as rename:
        rename.commit()
    del rename
    head = LocalArtifactVersionRegistryParticipant(manager.registry).prepare_checkpoint(1)
    restored = _manager()
    LocalArtifactVersionRegistryParticipant(restored.registry).restore_checkpoint(
        head.head.payload, ()
    )
    assert _at(restored, source.artifact.native_path) is None
    assert _at(restored, "/usr/local/libexec/renamed-worker") == _at(
        manager, "/usr/local/libexec/renamed-worker"
    )
    assert restored.registry.resolve_version(source.artifact.artifact_version_id) == source


@pytest.mark.parametrize("failure", ["cancel", "first", "second"])
def test_rename_group_failure_restores_original_placement(
    monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    manager, source = _setup()
    original = LocalArtifactVersionRegistry._commit_prepared_locked
    count = 0

    def fail(registry: LocalArtifactVersionRegistry, *args: object) -> object:
        nonlocal count
        result = original(registry, *args)
        count += 1
        if count == {"first": 1, "second": 2}.get(failure):
            raise RuntimeError("injected rename failure")
        return result

    monkeypatch.setattr(LocalArtifactVersionRegistry, "_commit_prepared_locked", fail)
    if failure == "cancel":
        with _rename(manager, source):
            pass
    else:
        with pytest.raises(RuntimeError, match="rename failure"):
            with _rename(manager, source) as rename:
                rename.commit()
    assert _at(manager, source.artifact.native_path) == source
    assert _at(manager, "/usr/local/libexec/renamed-worker") is None
    assert manager.census().prepared_publications == 0
    assert manager.census().live_versions == 1


@pytest.mark.parametrize("pending", [False, True])
def test_destination_write_between_preparation_and_commit_rejects_rename(pending: bool) -> None:
    manager, source = _setup()
    with pytest.raises(StateError, match="destination"):
        with _rename(manager, source) as rename:
            rival = manager.prepare_publication(
                replace(
                    _executable(),
                    source_object_id="another-object",
                    file_object_id="another-object",
                    native_path="/usr/local/libexec/renamed-worker",
                    macos_file=_metadata(file_object_id="another-object", inode=736, mode=0o100755),
                ),
                _START + timedelta(seconds=1),
            )
            try:
                if not pending:
                    with manager.registry.prepared_publication(rival) as publication:
                        publication.commit()
                rename.commit()
            finally:
                manager.registry.cancel_prepared(rival)
    assert _at(manager, source.artifact.native_path) == source
    assert manager.census().prepared_publications == 0


@pytest.mark.parametrize(
    "change",
    [
        {"native_path": "/another/directory/worker"},
        {"native_path": "/usr/local/libexec/invented-worker"},
        {"artifact_version": 1},
        {"metadata": _metadata(mode=0o100755, inode=736)},
        {"metadata": _metadata(mode=0o100755, volume_id="other-volume")},
        {"metadata": _metadata(mode=0o100755, link_count=2)},
        {"metadata": _metadata(mode=0o100700)},
        {"metadata": _metadata(mode=0o100755, changed=MacosFileTime(seconds=1, nanoseconds=0))},
    ],
)
def test_unsupported_rename_rejects_without_mutating_placement(change: dict[str, object]) -> None:
    manager, source = _setup()
    with pytest.raises((StateError, ValueError)):
        with _rename(manager, source, **change) as rename:
            rename.commit()
    assert _at(manager, source.artifact.native_path) == source
    assert manager.census().prepared_publications == 0
    assert manager.census().live_versions == 1


def test_source_replacement_between_preparation_and_commit_rejects_rename() -> None:
    manager, source = _setup()
    with pytest.raises(StateError, match="removal"):
        with _rename(manager, source) as rename:
            token = manager.prepare_publication(
                replace(_executable(), artifact_version=3, content_version=2), _START
            )
            with manager.registry.prepared_publication(token) as publication:
                publication.commit()
            rename.commit()
    assert _at(manager, source.artifact.native_path).artifact.version == 3
    assert _at(manager, "/usr/local/libexec/renamed-worker") is None
    assert manager.census().prepared_publications == 0


def test_lost_rename_return_retains_exact_completed_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager, source = _setup()
    original = LocalArtifactVersionRegistry._commit_claimed_group

    def lost_return(registry: LocalArtifactVersionRegistry, transaction: object) -> object:
        original(registry, transaction)
        raise RuntimeError("injected lost rename return")

    monkeypatch.setattr(LocalArtifactVersionRegistry, "_commit_claimed_group", lost_return)
    with pytest.raises(RuntimeError, match="lost rename return"):
        with _rename(manager, source) as rename:
            rename.commit()
    assert rename.committed_receipt is rename.expected_receipt
    assert _at(manager, source.artifact.native_path) is None
    assert _at(manager, "/usr/local/libexec/renamed-worker") is not None
    assert manager.census().prepared_publications == 0


def test_chained_rename_keeps_each_historical_version_without_old_name_resurrection() -> None:
    manager, source = _setup()
    with _rename(manager, source) as rename:
        rename.commit()
    second = _at(manager, "/usr/local/libexec/renamed-worker")
    with _rename(
        manager,
        second,
        native_path="/usr/local/libexec/final-worker",
        artifact_version=3,
        observed_at=_START + timedelta(seconds=2),
    ) as rename:
        rename.commit()
    assert _at(manager, source.artifact.native_path) is None
    assert _at(manager, second.artifact.native_path) is None
    assert _at(manager, "/usr/local/libexec/final-worker").content == source.content
    assert manager.registry.resolve_version(source.artifact.artifact_version_id) == source
    assert manager.registry.resolve_version(second.artifact.artifact_version_id) == second
    with pytest.raises(StateError, match="current file version"):
        with _rename(manager, source, artifact_version=4):
            pass
    assert manager.census().prepared_publications == 0


def test_preparation_capacity_failure_cancels_source_reservation() -> None:
    manager = RuntimeContentIdentityManager(LocalArtifactVersionRegistry(capacity=1))
    token = manager.prepare_publication(_executable(), _START)
    with manager.registry.prepared_publication(token) as publication:
        publication.commit()
    with pytest.raises(LocalArtifactCapacityError, match="capacity|free slot"):
        with _rename(manager, token.record):
            pass
    assert manager.census().prepared_publications == 0
    assert _at(manager, token.record.artifact.native_path) == token.record
