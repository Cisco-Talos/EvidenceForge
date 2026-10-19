# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Placement history survives retained bytes, rename, rollback and old checkpoints."""

from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.generation.checkpoints.artifact_registry_head import (
    LocalArtifactVersionRegistryParticipant,
)
from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError
from evidenceforge.generation.checkpoints.packed import dumps, loads
from evidenceforge.generation.deployment_registry import LocalArtifactVersionRegistry
from tests.unit.test_macos_file_rename import _at, _rename, _setup
from tests.unit.test_macos_file_replace import _destination
from tests.unit.test_macos_launch_registration import _START
from tests.unit.test_macos_runtime_file_metadata import _executable, _manager


def test_publication_and_lease_refresh_keep_the_original_placement_time() -> None:
    manager, source = _setup()
    version = source.artifact.artifact_version_id
    original = manager.registry.observe_version_placement(version)
    assert original.introduced_at == _START
    assert not original.withdrawn and original.withdrawn_at is None
    assert original.present_at(_START)
    assert not original.present_at(_START - timedelta(microseconds=1))
    token = manager.registry.prepare_version_retention(
        version,
        observed_at=_START + timedelta(hours=1),
        retained_until=_START + timedelta(days=10),
        lease_owner="second-loaded-image",
    )
    with manager.registry.prepared_publication(token) as claim:
        claim.commit()
    assert manager.registry.observe_version_placement(version) == original


def test_chained_rename_preserves_distinct_half_open_placement_intervals() -> None:
    manager, source = _setup()
    with _rename(manager, source) as rename:
        rename.commit()
    target = _at(manager, "/usr/local/libexec/renamed-worker")
    source_view = manager.registry.observe_version_placement(source.artifact.artifact_version_id)
    target_view = manager.registry.observe_version_placement(target.artifact.artifact_version_id)
    boundary = _START + timedelta(seconds=1)
    assert source_view.withdrawn_at == target_view.introduced_at == boundary
    assert source_view.present_at(boundary - timedelta(microseconds=1))
    assert not source_view.present_at(boundary)
    assert target_view.present_at(boundary)
    with _rename(
        manager,
        target,
        native_path="/usr/local/libexec/worker-again",
        artifact_version=3,
        observed_at=_START + timedelta(seconds=2),
    ) as rename:
        rename.commit()
    assert (
        manager.registry.observe_version_placement(source.artifact.artifact_version_id)
        == source_view
    )
    assert manager.registry.observe_version_placement(
        target.artifact.artifact_version_id
    ).withdrawn_at == _START + timedelta(seconds=2)
    assert source_view.artifact.native_path == source.artifact.native_path


def test_replacement_records_both_withdrawals_without_discarding_loaded_content() -> None:
    manager, source = _setup()
    destination = _destination(manager)
    with _rename(manager, source, replacement=destination) as rename:
        rename.commit()
    for record in (source, destination):
        view = manager.registry.observe_version_placement(record.artifact.artifact_version_id)
        assert view.introduced_at == _START
        assert view.withdrawn_at == _START + timedelta(seconds=1)
        assert manager.registry.resolve_version(record.artifact.artifact_version_id) == record
    manager.registry.advance_watermark(_START + timedelta(days=2))
    assert manager.registry.observe_version_placement(
        source.artifact.artifact_version_id
    ).withdrawn_at == _START + timedelta(seconds=1)


@pytest.mark.parametrize("stage", [1, 2, 3])
def test_rename_rollback_restores_placement_times_at_every_mutation_stage(
    monkeypatch: pytest.MonkeyPatch, stage: int
) -> None:
    manager, source = _setup()
    destination = _destination(manager)
    before = {
        row.artifact.artifact_version_id: manager.registry.observe_version_placement(
            row.artifact.artifact_version_id
        )
        for row in (source, destination)
    }
    original = LocalArtifactVersionRegistry._commit_prepared_locked
    calls = 0

    def fail(registry: LocalArtifactVersionRegistry, *args: object) -> object:
        nonlocal calls
        result = original(registry, *args)
        calls += 1
        if calls == stage:
            raise RuntimeError("injected timed placement fault")
        return result

    with monkeypatch.context() as patch:
        patch.setattr(LocalArtifactVersionRegistry, "_commit_prepared_locked", fail)
        with pytest.raises(RuntimeError, match="timed placement fault"):
            with _rename(manager, source, replacement=destination) as rename:
                rename.commit()
    assert {
        version: manager.registry.observe_version_placement(version) for version in before
    } == before
    # Capturing also checks that freed/reserved handles retain no timestamp columns.
    LocalArtifactVersionRegistryParticipant(manager.registry).prepare_checkpoint(1)


def test_remove_and_republish_retained_version_do_not_rewrite_the_withdrawal() -> None:
    manager, source = _setup()
    registry = manager.registry
    boundary = _START + timedelta(seconds=5)
    assert registry.withdraw_execution_path(source, boundary)
    view = registry.observe_version_placement(source.artifact.artifact_version_id)
    assert not registry.withdraw_execution_path(source, boundary + timedelta(seconds=1))
    registry.publish_version(source, boundary + timedelta(seconds=2))
    assert registry.observe_version_placement(source.artifact.artifact_version_id) == view
    assert view.withdrawn_at == boundary and not view.present_at(boundary)
    assert _at(manager, source.artifact.native_path) is None


@pytest.mark.parametrize("legacy", [False, True])
def test_checkpoint_keeps_exact_bounds_or_explicit_unknown_legacy_times(legacy: bool) -> None:
    manager, source = _setup()
    with _rename(manager, source) as rename:
        rename.commit()
    del rename
    document = loads(
        LocalArtifactVersionRegistryParticipant(manager.registry).prepare_checkpoint(1).head.payload
    )
    if legacy:
        document["schema_version"] = "5"
        for row in document["records"]:
            del row[10:]
    restored = _manager()
    LocalArtifactVersionRegistryParticipant(restored.registry).restore_checkpoint(
        dumps(document), ()
    )
    actual = restored.registry.observe_version_placement(source.artifact.artifact_version_id)
    assert actual.withdrawn
    if legacy:
        assert actual.introduced_at is None and actual.withdrawn_at is None
        assert actual.present_at(_START) is None
        restored.registry.publish_version(source, _START + timedelta(seconds=5))
        assert (
            restored.registry.observe_version_placement(source.artifact.artifact_version_id)
            == actual
        )
    else:
        assert actual == manager.registry.observe_version_placement(
            source.artifact.artifact_version_id
        )


@pytest.mark.parametrize("column,value", [(10, True), (10, 1.5), (10, 2**63), (11, 100)])
def test_checkpoint_rejects_noncanonical_or_contradictory_placement_fields(
    column: int, value: object
) -> None:
    manager, _ = _setup()
    document = loads(
        LocalArtifactVersionRegistryParticipant(manager.registry).prepare_checkpoint(1).head.payload
    )
    document["records"][0][column] = value
    with pytest.raises(CheckpointCorruptionError, match="placement time"):
        LocalArtifactVersionRegistryParticipant(_manager().registry).restore_checkpoint(
            dumps(document), ()
        )


def test_out_of_order_legacy_bounds_remain_unknown_instead_of_inventing_an_interval() -> None:
    manager, source = _setup()
    replacement = replace(_executable(), artifact_version=2, content_version=2)
    token = manager.prepare_publication(replacement, _START - timedelta(seconds=1))
    with manager.registry.prepared_publication(token) as claim:
        claim.commit()
    view = manager.registry.observe_version_placement(source.artifact.artifact_version_id)
    assert view.introduced_at == _START
    assert view.withdrawn_at == _START - timedelta(seconds=1)
    assert view.present_at(_START) is None


def test_new_removal_after_legacy_restore_does_not_invent_the_birth_bound() -> None:
    manager, source = _setup()
    document = loads(
        LocalArtifactVersionRegistryParticipant(manager.registry).prepare_checkpoint(1).head.payload
    )
    document["schema_version"] = "5"
    for row in document["records"]:
        del row[10:]
    restored = _manager()
    LocalArtifactVersionRegistryParticipant(restored.registry).restore_checkpoint(
        dumps(document), ()
    )
    at = _START + timedelta(seconds=10)
    restored.registry.withdraw_execution_path(source, at)
    observed = restored.registry.observe_version_placement(source.artifact.artifact_version_id)
    assert observed.introduced_at is None and observed.withdrawn_at == at
    assert observed.present_at(_START) is None


def test_legacy_publish_refresh_preserves_its_first_timestamp() -> None:
    manager = _manager()
    record = manager.build_record(_executable())
    registry = manager.registry
    registry.publish(record.artifact, _START)
    first = registry.observe_version_placement(record.artifact.artifact_version_id)
    registry.publish(record.artifact, _START + timedelta(hours=1))
    assert first.introduced_at == _START and first.present_at(_START)
    assert registry.observe_version_placement(record.artifact.artifact_version_id) == first


def test_expired_handle_reuse_cannot_inherit_old_placement_bounds() -> None:
    from tests.unit.test_runtime_placement_supersession import _image
    from tests.unit.test_runtime_placement_supersession import _manager as small_manager

    manager = small_manager(capacity=2)
    first = manager.prepare_publication(_image(), _START, retention=timedelta(hours=1))
    with manager.registry.prepared_publication(first) as claim:
        claim.commit()
    first_version = first.record.artifact.artifact_version_id
    manager.registry.advance_watermark(_START + timedelta(days=2))
    assert manager.registry.observe_version_placement(first_version) is None
    at = _START + timedelta(days=3)
    second = manager.prepare_publication(_image(version=2), at)
    with manager.registry.prepared_publication(second) as claim:
        claim.commit()
    observed = manager.registry.observe_version_placement(
        second.record.artifact.artifact_version_id
    )
    assert observed.introduced_at == at and not observed.withdrawn
    assert observed.withdrawn_at is None
    assert not observed.present_at(_START)
