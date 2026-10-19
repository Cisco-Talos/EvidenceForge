# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Retained loaded bytes and event-time file names remain separate canonical facts."""

from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.artifact_placement import MacosRuntimeFilePlacementObservation
from evidenceforge.generation.checkpoints.artifact_registry_head import (
    LocalArtifactVersionRegistryParticipant,
)
from evidenceforge.generation.checkpoints.packed import dumps, loads
from tests.unit.test_macos_file_rename import _at, _rename, _setup
from tests.unit.test_macos_file_replace import _destination
from tests.unit.test_macos_launch_registration import _START
from tests.unit.test_macos_runtime_file_metadata import _executable, _manager


def test_event_time_lookup_preserves_loaded_identity_across_rename_and_round_trip() -> None:
    manager, source = _setup()
    registry = manager.registry
    version = source.artifact.artifact_version_id
    original = registry.observe_macos_file_placement(version, _START)
    assert original.reference == original.placed == source
    with _rename(manager, source) as rename:
        rename.commit()
    target = _at(manager, "/usr/local/libexec/renamed-worker")
    assert registry.observe_macos_file_placement(version, _START).placed == original.placed
    boundary = _START + timedelta(seconds=1)
    current = registry.observe_macos_file_placement(version, boundary)
    assert current.reference == source and current.placed == target
    assert current.reference.binary.artifact_name != current.placed.binary.artifact_name
    assert current.reference.binary.code_signature == current.placed.binary.code_signature
    with _rename(
        manager,
        target,
        native_path=source.artifact.native_path,
        artifact_version=3,
        observed_at=_START + timedelta(seconds=2),
    ) as rename:
        rename.commit()
    returned = registry.observe_macos_file_placement(version, _START + timedelta(seconds=2))
    assert returned.placed.artifact.native_path == source.artifact.native_path
    assert returned.placed.artifact.version == 3
    assert registry.observe_macos_file_placement(version, boundary).placed == current.placed
    assert registry.resolve_version(version) == source


def test_replaced_destination_does_not_adopt_the_replacing_file_object() -> None:
    manager, source = _setup()
    destination = _destination(manager)
    version = destination.artifact.artifact_version_id
    assert manager.registry.observe_macos_file_placement(version, _START).placed == destination
    with _rename(manager, source, replacement=destination) as rename:
        rename.commit()
    assert (
        manager.registry.observe_macos_file_placement(version, _START + timedelta(seconds=1))
        is None
    )
    assert manager.registry.resolve_version(version) == destination


def test_expired_new_name_does_not_resurrect_retained_loaded_name() -> None:
    manager, source = _setup()
    version = source.artifact.artifact_version_id
    with _rename(manager, source) as rename:
        rename.commit()
    manager.registry.advance_watermark(_START + timedelta(days=2))
    assert manager.registry.resolve_version(version) == source
    assert manager.registry.observe_macos_file_placement(version, _START).placed == source
    assert (
        manager.registry.observe_macos_file_placement(version, _START + timedelta(seconds=1))
        is None
    )
    assert (
        manager.registry.observe_macos_file_placement(version, _START + timedelta(days=2)) is None
    )
    assert _at(manager, source.artifact.native_path) is None


@pytest.mark.parametrize("legacy", [False, True])
def test_checkpoint_restores_known_placement_or_leaves_legacy_history_unknown(legacy: bool) -> None:
    manager, source = _setup()
    with _rename(manager, source) as rename:
        rename.commit()
    del rename
    version = source.artifact.artifact_version_id
    boundary = _START + timedelta(seconds=1)
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
    actual = restored.registry.observe_macos_file_placement(version, boundary)
    assert actual == (
        None if legacy else manager.registry.observe_macos_file_placement(version, boundary)
    )


def test_lookup_refuses_partial_history_and_does_not_mutate_placement() -> None:
    manager, source = _setup()
    with _rename(manager, source) as rename:
        rename.commit()
    del rename
    version = source.artifact.artifact_version_id
    boundary = _START + timedelta(seconds=1)
    before = (
        LocalArtifactVersionRegistryParticipant(manager.registry).prepare_checkpoint(1).head.payload
    )
    assert manager.registry.observe_macos_file_placement(version, boundary, max_versions=1) is None
    assert (
        manager.registry.observe_macos_file_placement(version, boundary, max_versions=2) is not None
    )
    assert (
        LocalArtifactVersionRegistryParticipant(manager.registry).prepare_checkpoint(1).head.payload
        == before
    )


@pytest.mark.parametrize("bound", [0, 257, True, 1.5])
def test_invalid_query_bounds_fail_before_observation(bound: object) -> None:
    manager, source = _setup()
    with pytest.raises(ValueError, match="bound"):
        manager.registry.observe_macos_file_placement(
            source.artifact.artifact_version_id, _START, max_versions=bound
        )


def test_query_cannot_infer_missing_or_prebirth_history() -> None:
    manager, source = _setup()
    assert manager.registry.observe_macos_file_placement("absent", _START) is None
    version = source.artifact.artifact_version_id
    assert (
        manager.registry.observe_macos_file_placement(version, _START - timedelta(microseconds=1))
        is None
    )
    with pytest.raises(ValueError, match="aware"):
        manager.registry.observe_macos_file_placement(version, _START.replace(tzinfo=None))


def test_content_mutation_is_not_misrepresented_as_rename() -> None:
    manager, source = _setup()
    changed = replace(_executable(), artifact_version=2, content_version=2)
    token = manager.prepare_publication(changed, _START + timedelta(seconds=1))
    with manager.registry.prepared_publication(token) as publication:
        publication.commit()
    assert (
        manager.registry.observe_macos_file_placement(
            source.artifact.artifact_version_id, _START + timedelta(seconds=1)
        )
        is None
    )


def test_detached_observation_rejects_changed_file_identity_or_wrong_interval() -> None:
    manager, source = _setup()
    view = manager.registry.observe_macos_file_placement(
        source.artifact.artifact_version_id, _START
    )
    assert type(view) is MacosRuntimeFilePlacementObservation
    with pytest.raises(ValueError, match="unchanged"):
        replace(view, observed_at=_START - timedelta(microseconds=1))
    with pytest.raises(ValueError, match="unchanged"):
        replace(
            view,
            placed=replace(source, macos_file=source.macos_file.model_copy(update={"inode": 999})),
        )
