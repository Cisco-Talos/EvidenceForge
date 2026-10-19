# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.content_identity import LocalArtifactVersionRecord
from evidenceforge.generation.checkpoints.artifact_registry_head import (
    LocalArtifactVersionRegistryParticipant,
)
from evidenceforge.generation.deployment_registry import LocalArtifactVersionRegistry
from evidenceforge.generation.runtime_content import (
    RuntimeArtifactDescriptor,
    RuntimeContentIdentityManager,
)
from tests.unit.test_process_exec_projection import _START
from tests.unit.test_runtime_content import _descriptor


def _manager(capacity: int = 12) -> RuntimeContentIdentityManager:
    return RuntimeContentIdentityManager(
        LocalArtifactVersionRegistry(capacity=capacity, shard_count=2, retention=timedelta(days=1))
    )


def _image(platform: str = "macos", version: int = 1) -> RuntimeArtifactDescriptor:
    return replace(
        _descriptor(
            native_path="/usr/local/bin/invented-worker"
            if platform != "windows"
            else r"C:\Tools\invented-worker.exe"
        ),
        platform=platform,
        artifact_version=version,
        content_version=version,
        architecture="arm64" if platform == "macos" else "x64",
    )


def _publish(
    manager: RuntimeContentIdentityManager,
    image: RuntimeArtifactDescriptor,
    *,
    retain: bool = False,
) -> None:
    token = manager.prepare_publication(
        image,
        _START,
        lease_owner="invented-old-execution" if retain else "",
        lease_until=_START + timedelta(days=10) if retain else None,
    )
    with manager.registry.prepared_publication(token) as publication:
        publication.commit()


def _resolve(
    manager: RuntimeContentIdentityManager, image: RuntimeArtifactDescriptor
) -> LocalArtifactVersionRecord | None:
    return manager.resolve_record(
        image.hostname, image.principal, image.native_path, image.platform
    )


@pytest.mark.parametrize("platform", ["macos", "windows", "linux"])
@pytest.mark.parametrize("reverse", [False, True])
def test_old_loaded_content_cannot_become_current_after_replacement_expiry(
    platform: str, reverse: bool
) -> None:
    manager = _manager()
    old, new = _image(platform), _image(platform, 2)
    for image in (new, old) if reverse else (old, new):
        _publish(manager, image, retain=image == old)
    assert _resolve(manager, old) == manager.build_record(new)
    manager.registry.advance_watermark(_START + timedelta(days=2))
    assert _resolve(manager, old) is None
    assert manager.registry.resolve_version(
        manager.build_record(old).artifact.artifact_version_id
    ) == manager.build_record(old)
    token = manager.registry.prepare_version_retention(
        manager.build_record(old).artifact.artifact_version_id,
        observed_at=_START + timedelta(days=2),
        retained_until=_START + timedelta(days=11),
        lease_owner="invented-old-execution",
    )
    with manager.registry.prepared_publication(token) as publication:
        publication.commit()
    assert _resolve(manager, old) is None


def test_checkpoint_preserves_supersession_independently_of_retained_content() -> None:
    manager = _manager()
    old, new = _image(), _image(version=2)
    _publish(manager, old, retain=True)
    _publish(manager, new)
    checkpoint = LocalArtifactVersionRegistryParticipant(manager.registry).prepare_checkpoint(1)
    restored = _manager()
    LocalArtifactVersionRegistryParticipant(restored.registry).restore_checkpoint(
        checkpoint.head.payload, ()
    )
    restored.registry.advance_watermark(_START + timedelta(days=2))
    assert _resolve(restored, old) is None
    assert restored.registry.resolve_version(
        manager.build_record(old).artifact.artifact_version_id
    ) == manager.build_record(old)


@pytest.mark.parametrize("failed_member", [1, 2])
def test_failed_replacement_group_restores_original_placement_and_leases(
    monkeypatch: pytest.MonkeyPatch, failed_member: int
) -> None:
    manager = _manager()
    old = _image()
    _publish(manager, old, retain=True)
    tokens = tuple(
        manager.prepare_publication(_image(version=version), _START) for version in (2, 3)
    )
    original = LocalArtifactVersionRegistry._commit_prepared_locked
    count = 0

    def fail(registry: LocalArtifactVersionRegistry, *args: object) -> object:
        nonlocal count
        result = original(registry, *args)
        count += 1
        if count == failed_member:
            raise RuntimeError("injected replacement group failure")
        return result

    monkeypatch.setattr(LocalArtifactVersionRegistry, "_commit_prepared_locked", fail)
    with pytest.raises(RuntimeError, match="replacement group"):
        with manager.registry.prepared_publication_group(tokens) as group:
            group.commit()
    assert _resolve(manager, old) == manager.build_record(old)
    assert manager.registry.census().live_versions == 1
    assert manager.registry.census().prepared_publications == 0


def test_capacity_eviction_does_not_reinstall_the_retained_previous_version() -> None:
    manager = _manager(capacity=2)
    old, new = _image(), _image(version=2)
    _publish(manager, old, retain=True)
    _publish(manager, new)
    other = replace(
        _image(), native_path="/usr/local/bin/another-worker", source_object_id="another-object"
    )
    # The legacy bounded identity admission evicts; prepared admission instead
    # requires spare capacity and cannot evict before its transaction commits.
    manager.registry.publish(manager.build_record(other).artifact, _START)
    assert _resolve(manager, old) is None
    assert manager.registry.resolve_version(
        manager.build_record(old).artifact.artifact_version_id
    ) == manager.build_record(old)


def test_an_explicit_new_file_can_reestablish_a_withdrawn_placement() -> None:
    manager = _manager()
    old, new = _image(), _image(version=2)
    _publish(manager, old, retain=True)
    _publish(manager, new)
    manager.registry.advance_watermark(_START + timedelta(days=2))
    fresh = replace(
        old, source_object_id="new-file", file_object_id="new-file", seed_ref="new-file"
    )
    token = manager.prepare_publication(fresh, _START + timedelta(days=2))
    with manager.registry.prepared_publication(token) as publication:
        publication.commit()
    assert _resolve(manager, fresh) == manager.build_record(fresh)


def test_identity_only_admission_is_not_authenticated_file_retention() -> None:
    manager = _manager()
    old, new = _image(), _image(version=2)
    _publish(manager, old, retain=True)
    # A legacy identity is not a canonical content publication.
    manager.registry.publish(manager.build_record(new).artifact, _START)
    token = manager.prepare_publication(new, _START)
    assert not manager.registry.authenticates_prepared_retention(token)
    with manager.registry.prepared_publication(token) as publication:
        publication.commit()
    assert _resolve(manager, new) == manager.build_record(new)
    manager.registry.advance_watermark(_START + timedelta(days=2))
    assert _resolve(manager, old) is None
    assert manager.registry.resolve_version(
        manager.build_record(old).artifact.artifact_version_id
    ) == manager.build_record(old)


def test_require_existing_rejects_identity_only_rows_without_reservation() -> None:
    from evidenceforge.models.exceptions import StateError

    manager = _manager()
    record = manager.build_record(_image())
    manager.registry.publish(record.artifact, _START)
    with pytest.raises(StateError, match="existing record"):
        manager.registry.prepare_publish_version(record, _START, require_existing=True)
    assert manager.registry.census().prepared_publications == 0
    assert manager.registry.resolve_version(record.artifact.artifact_version_id) is None
