# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Explicit destination replacement preserves loaded identities and atomic placement."""

from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.content_identity import LocalArtifactVersionRecord
from evidenceforge.generation.checkpoints.artifact_registry_head import (
    LocalArtifactVersionRegistryParticipant,
)
from evidenceforge.generation.deployment_registry import (
    LocalArtifactCapacityError,
    LocalArtifactVersionRegistry,
)
from evidenceforge.generation.runtime_content import RuntimeContentIdentityManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_file_rename import _at, _rename, _setup
from tests.unit.test_macos_launch_registration import _START
from tests.unit.test_macos_runtime_file_metadata import _executable, _manager, _metadata


def _destination(
    manager: RuntimeContentIdentityManager, **changes: object
) -> LocalArtifactVersionRecord:
    descriptor = replace(
        _executable(),
        **dict(
            source_object_id="invented-old-destination",
            file_object_id="invented-old-destination",
            native_path="/usr/local/libexec/renamed-worker",
            artifact_version=9,
            seed_ref="invented-old-destination-content",
            macos_file=_metadata(
                file_object_id="invented-old-destination", inode=736, mode=0o100755
            ),
        )
        | changes,
    )
    token = manager.prepare_publication(
        descriptor,
        _START,
        lease_owner="invented-destination-loaded-image",
        lease_until=_START + timedelta(days=8),
    )
    with manager.registry.prepared_publication(token) as publication:
        publication.commit()
    return token.record


def test_explicit_replacement_retains_both_loaded_contents_and_moves_source_object() -> None:
    manager, source = _setup()
    destination = _destination(manager)
    assert source.content != destination.content
    with _rename(manager, source, replacement=destination) as rename:
        assert _at(manager, source.artifact.native_path) == source
        assert _at(manager, destination.artifact.native_path) == destination
        receipt = rename.commit()
        assert rename.committed_receipt is receipt
        assert len(receipt.receipts) == 3
    current = _at(manager, destination.artifact.native_path)
    assert current is not None
    assert current.artifact.version == 2  # The replaced object's version 9 is unrelated.
    assert current.artifact.artifact_id == source.artifact.artifact_id
    assert current.content == source.content
    assert current.macos_file.inode == source.macos_file.inode
    assert current.binary.code_signature == source.binary.code_signature
    assert _at(manager, source.artifact.native_path) is None
    for loaded in (source, destination):
        assert manager.registry.resolve_version(loaded.artifact.artifact_version_id) == loaded
    manager.registry.advance_watermark(_START + timedelta(days=2))
    assert _at(manager, source.artifact.native_path) is None
    assert _at(manager, destination.artifact.native_path) == current
    for loaded in (source, destination):
        assert manager.registry.resolve_version(loaded.artifact.artifact_version_id) == loaded
    assert manager.census().prepared_publications == 0


@pytest.mark.parametrize("failure", [0, 1, 2, 3])
def test_failure_at_each_replacement_stage_restores_both_placements_and_leases(
    monkeypatch: pytest.MonkeyPatch, failure: int
) -> None:
    manager, source = _setup()
    destination = _destination(manager)
    original = LocalArtifactVersionRegistry._commit_prepared_locked
    calls = 0

    def fail_after_stage(registry: LocalArtifactVersionRegistry, *args: object) -> object:
        nonlocal calls
        result = original(registry, *args)
        calls += 1
        if calls == failure:
            raise RuntimeError("injected replacement stage failure")
        return result

    monkeypatch.setattr(LocalArtifactVersionRegistry, "_commit_prepared_locked", fail_after_stage)
    if failure:
        with pytest.raises(RuntimeError, match="replacement stage failure"):
            with _rename(manager, source, replacement=destination) as rename:
                rename.commit()
    else:
        with _rename(manager, source, replacement=destination):
            pass
    assert _at(manager, source.artifact.native_path) == source
    assert _at(manager, destination.artifact.native_path) == destination
    assert manager.census().live_versions == 2
    assert manager.census().prepared_publications == 0
    manager.registry.advance_watermark(_START + timedelta(days=2))
    for loaded in (source, destination):
        assert manager.registry.resolve_version(loaded.artifact.artifact_version_id) == loaded


def test_replacement_checkpoint_keeps_current_name_and_both_historical_versions() -> None:
    manager, source = _setup()
    destination = _destination(manager)
    with _rename(manager, source, replacement=destination) as rename:
        rename.commit()
    del rename
    seal = LocalArtifactVersionRegistryParticipant(manager.registry).prepare_checkpoint(1)
    restored = _manager()
    LocalArtifactVersionRegistryParticipant(restored.registry).restore_checkpoint(
        seal.head.payload, ()
    )
    assert _at(restored, source.artifact.native_path) is None
    assert _at(restored, destination.artifact.native_path) == _at(
        manager, destination.artifact.native_path
    )
    for loaded in (source, destination):
        assert restored.registry.resolve_version(loaded.artifact.artifact_version_id) == loaded
    restored.registry.advance_watermark(_START + timedelta(days=2))
    assert _at(restored, destination.artifact.native_path) == _at(
        manager, destination.artifact.native_path
    )
    restored.registry.advance_watermark(_START + timedelta(days=10))
    assert _at(restored, destination.artifact.native_path) is None


@pytest.mark.parametrize(
    "damage", ["host", "principal", "path", "volume", "device", "links", "inode", "object"]
)
def test_replacement_rejects_wrong_destination_identity_or_incomplete_supported_semantics(
    damage: str,
) -> None:
    manager, source = _setup()
    changes: dict[str, object] = {}
    if damage == "host":
        changes["hostname"] = "OTHER-MAC"
    elif damage == "principal":
        changes["principal"] = "casey"
    elif damage == "path":
        changes["native_path"] = "/usr/local/libexec/unrelated-worker"
    else:
        metadata = dict(file_object_id="invented-old-destination", inode=736, mode=0o100755)
        if damage == "volume":
            metadata["volume_id"] = "another-volume"
        elif damage == "device":
            metadata["device"] = source.macos_file.device + 1
        elif damage == "links":
            metadata["link_count"] = 2
        elif damage == "inode":
            metadata["inode"] = source.macos_file.inode
        else:
            metadata["file_object_id"] = source.macos_file.file_object_id
            changes["file_object_id"] = source.content.file_object_id
        changes["macos_file"] = _metadata(**metadata)
    destination = _destination(manager, **changes)
    with pytest.raises((StateError, ValueError)):
        with _rename(manager, source, replacement=destination):
            pytest.fail("unsupported replacement was prepared")
    assert _at(manager, source.artifact.native_path) == source
    assert manager.census().prepared_publications == 0


@pytest.mark.parametrize("pending", [False, True])
def test_competing_destination_replacement_prevents_commit(pending: bool) -> None:
    manager, source = _setup()
    destination = _destination(manager)
    with pytest.raises(StateError, match="destination"):
        with _rename(manager, source, replacement=destination) as rename:
            rival = manager.prepare_publication(
                replace(
                    _executable(),
                    native_path=destination.artifact.native_path,
                    source_object_id="rival-destination",
                    file_object_id="rival-destination",
                    artifact_version=10,
                    macos_file=_metadata(
                        file_object_id="rival-destination", inode=737, mode=0o100755
                    ),
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


def test_replacement_capacity_failure_releases_both_removal_reservations() -> None:
    manager = RuntimeContentIdentityManager(LocalArtifactVersionRegistry(capacity=2))
    token = manager.prepare_publication(_executable(), _START)
    with manager.registry.prepared_publication(token) as publication:
        publication.commit()
    source = token.record
    destination = _destination(manager)
    with pytest.raises(LocalArtifactCapacityError, match="capacity|free slot"):
        with _rename(manager, source, replacement=destination):
            pass
    assert manager.census().prepared_publications == 0
    assert _at(manager, source.artifact.native_path) == source
    assert _at(manager, destination.artifact.native_path) == destination


def test_lost_replacement_return_preserves_authenticated_completion_and_retained_files(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager, source = _setup()
    destination = _destination(manager)
    original = LocalArtifactVersionRegistry.commit_macos_file_rename

    def lose_return(registry: LocalArtifactVersionRegistry, transaction: object) -> object:
        original(registry, transaction)
        raise RuntimeError("injected replacement lost acknowledgement")

    monkeypatch.setattr(LocalArtifactVersionRegistry, "commit_macos_file_rename", lose_return)
    with pytest.raises(RuntimeError, match="replacement lost acknowledgement"):
        with _rename(manager, source, replacement=destination) as rename:
            rename.commit()
    assert rename.committed_receipt is rename.expected_receipt
    assert manager.registry.authenticates_publication_group_receipt(rename.committed_receipt)
    assert _at(manager, source.artifact.native_path) is None
    assert _at(manager, destination.artifact.native_path).content == source.content
    for loaded in (source, destination):
        assert manager.registry.resolve_version(loaded.artifact.artifact_version_id) == loaded


@pytest.mark.parametrize("damage", ["reversed", "different_time", "two_successors"])
def test_atomic_group_replacement_exception_is_limited_to_one_ordered_same_time_successor(
    damage: str,
) -> None:
    manager, source = _setup()
    removal = manager.registry.prepare_publish_version(
        source, _START + timedelta(seconds=1), withdraw_placement=True, require_existing=True
    )
    descriptor = replace(_executable(), artifact_version=2, content_version=2)
    target = manager.prepare_publication(
        descriptor, _START + timedelta(seconds=2 if damage == "different_time" else 1)
    )
    extra = None
    tokens = (removal, target)
    if damage == "reversed":
        tokens = (target, removal)
    elif damage == "two_successors":
        extra = manager.prepare_publication(
            replace(descriptor, artifact_version=3, content_version=3),
            _START + timedelta(seconds=1),
        )
        tokens = (*tokens, extra)
    try:
        with pytest.raises(StateError, match="removal|publication"):
            with manager.registry.prepared_publication_group(tokens) as transaction:
                transaction.commit_no_fail()
    finally:
        for token in tokens:
            manager.registry.cancel_prepared(token)
    assert _at(manager, source.artifact.native_path) == source
    assert manager.census().prepared_publications == 0
    assert manager.census().live_versions == 1


@pytest.mark.slow
def test_replacement_and_historical_retention_are_fresh_process_deterministic() -> None:
    import os
    import subprocess
    import sys
    import textwrap

    script = textwrap.dedent(
        """
        import json
        from tests.unit.test_macos_file_replace import _setup, _destination, _rename, _at
        manager, source = _setup()
        destination = _destination(manager)
        with _rename(manager, source, replacement=destination) as rename:
            rename.commit()
        current = _at(manager, destination.artifact.native_path)
        print(json.dumps({
            'current': current.artifact.artifact_version_id,
            'content': current.content.content_id,
            'old_source': manager.registry.resolve_version(source.artifact.artifact_version_id).content.content_id,
            'old_destination': manager.registry.resolve_version(destination.artifact.artifact_version_id).content.content_id,
            'old_path': _at(manager, source.artifact.native_path),
        }, sort_keys=True))
        """
    )
    outputs: list[str] = []
    for seed in ("31", "137"):
        result = subprocess.run(
            [sys.executable, "-c", script],
            env=dict(os.environ, PYTHONHASHSEED=seed),
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        )
        outputs.append(result.stdout)
    assert outputs[0] == outputs[1]
