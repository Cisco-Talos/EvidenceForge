# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""A renamed placement covers its source's already-known loaded-content horizon."""

from datetime import datetime, timedelta

import pytest

from evidenceforge.generation.deployment_registry import LocalArtifactVersionRegistry
from evidenceforge.generation.indexes import ReferenceLeaseIndex
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_file_rename import _at, _rename, _setup
from tests.unit.test_macos_launch_registration import _START


def test_lease_deadline_lookup_is_key_scoped_and_survives_owner_changes_and_restore() -> None:
    leases = ReferenceLeaseIndex[str, str]()
    assert leases.latest_deadline("image") is None
    leases.acquire("image", "first", deadline=100.0)
    leases.acquire("image", "second", deadline=200.0)
    leases.acquire("unrelated", "third", deadline=900.0)
    assert leases.latest_deadline("image") == 200.0
    restored = ReferenceLeaseIndex[str, str]()
    restored.restore_checkpoint_records(leases.checkpoint_records())
    assert restored.latest_deadline("image") == 200.0
    restored.release("image", "second")
    assert restored.latest_deadline("image") == 100.0
    restored.release_owner("first")
    assert restored.latest_deadline("image") is None
    assert restored.latest_deadline("unrelated") == 900.0


def test_rename_chain_preserves_existing_retention_without_copying_loaded_identity() -> None:
    manager, source = _setup()
    registry = manager.registry
    version = source.artifact.artifact_version_id
    horizon = registry.retained_version_deadline(version)
    assert horizon == _START + timedelta(days=9)
    with _rename(manager, source) as rename:
        rename.commit()
    first = _at(manager, "/usr/local/libexec/renamed-worker")
    with _rename(
        manager,
        first,
        native_path="/usr/local/libexec/third-worker",
        artifact_version=3,
        observed_at=_START + timedelta(seconds=2),
    ) as rename:
        rename.commit()
    third = _at(manager, "/usr/local/libexec/third-worker")
    registry.advance_watermark(_START + timedelta(days=2))
    assert (
        registry.observe_macos_file_placement(version, _START + timedelta(days=2)).placed == third
    )
    assert registry.resolve_version(version) == source
    for record in (source, first, third):
        assert registry.retained_version_deadline(record.artifact.artifact_version_id) == horizon
    registry.advance_watermark(horizon)
    assert registry.resolve_version(version) is None
    assert _at(manager, third.artifact.native_path) is None


def test_source_retention_growth_during_preparation_requires_rename_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager, source = _setup()
    registry = manager.registry
    version = source.artifact.artifact_version_id
    original = LocalArtifactVersionRegistry.retained_version_deadline
    changed = False

    def grow(owner: LocalArtifactVersionRegistry, artifact_version_id: str) -> datetime | None:
        nonlocal changed
        horizon = original(owner, artifact_version_id)
        if not changed:
            changed = True
            owner.acquire_lease(version, "concurrent-loaded-owner", _START + timedelta(days=12))
        return horizon

    monkeypatch.setattr(LocalArtifactVersionRegistry, "retained_version_deadline", grow)
    with pytest.raises(StateError, match="retention horizon"):
        with _rename(manager, source) as rename:
            rename.commit()
    assert _at(manager, source.artifact.native_path) == source
    assert _at(manager, "/usr/local/libexec/renamed-worker") is None
    assert registry.census().prepared_publications == 0
    with _rename(manager, source) as rename:
        rename.commit()
    target = _at(manager, "/usr/local/libexec/renamed-worker")
    assert registry.retained_version_deadline(
        target.artifact.artifact_version_id
    ) == _START + timedelta(days=12)
