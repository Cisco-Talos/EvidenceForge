# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.generation.deployment_registry import LocalArtifactVersionRegistry
from evidenceforge.models.exceptions import EventContractError
from tests.unit.test_macos_exec_content_retention import _fixture
from tests.unit.test_process_exec_projection import _START


@pytest.mark.parametrize("scripts", [False, True])
def test_fork_retains_loaded_content_even_when_the_path_has_already_been_replaced(
    tmp_path: Path,
    scripts: bool,
) -> None:
    fixture = _fixture(tmp_path, scripts=scripts, fork=True)
    result = fixture.dispatcher.publish_prepared_action_cohort_batch(fixture.batch)
    assert result.projections[0].status == "succeeded"
    assert fixture.state.get_process_identity("HOST-01", fixture.before.pid) == fixture.before
    assert fixture.state.get_process_identity("HOST-01", fixture.after.pid) == fixture.after
    assert fixture.before.executable_version == fixture.after.executable_version
    fixture.content.registry.advance_watermark(_START + timedelta(days=8))
    for record in fixture.records:
        assert (
            fixture.content.registry.resolve_version(record.artifact.artifact_version_id) == record
        )
        current = fixture.content.resolve_record(
            "HOST-01", "root", record.artifact.native_path, "macos"
        )
        assert current is None or current != record
    fixture.emitter.close()


@pytest.mark.parametrize("failed_member", [1, 2])
def test_failed_fork_retention_rolls_back_the_child_and_every_content_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failed_member: int,
) -> None:
    fixture = _fixture(tmp_path, fork=True)
    before = fixture.state.materialization_digest()
    original = LocalArtifactVersionRegistry._commit_prepared_locked
    count = 0

    def fail(registry: LocalArtifactVersionRegistry, *args: object) -> object:
        nonlocal count
        result = original(registry, *args)
        count += 1
        if count == failed_member:
            raise RuntimeError("injected fork retention failure")
        return result

    monkeypatch.setattr(LocalArtifactVersionRegistry, "_commit_prepared_locked", fail)
    with pytest.raises(RuntimeError, match="fork retention"):
        fixture.dispatcher.publish_prepared_action_cohort_batch(fixture.batch)
    assert fixture.state.materialization_digest() == before
    assert fixture.state.get_process("HOST-01", fixture.after.pid) is None
    assert fixture.content.registry.census().prepared_publications == 0
    fixture.content.registry.advance_watermark(_START + timedelta(days=8))
    assert all(
        fixture.content.registry.resolve_version(record.artifact.artifact_version_id) is None
        for record in fixture.records
    )
    fixture.emitter.close()


def test_fork_cannot_retain_an_unrelated_script(tmp_path: Path) -> None:
    with pytest.raises(
        EventContractError, match="owner drifted|unrelated|existing image or script"
    ):
        _fixture(tmp_path, fork=True, foreign=True)


def test_inherited_file_versions_and_both_lifetimes_restore_together(tmp_path: Path) -> None:
    from evidenceforge.generation.checkpoints.artifact_registry_head import (
        LocalArtifactVersionRegistryParticipant,
    )
    from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
    from evidenceforge.generation.state_manager import StateManager
    from tests.unit.test_macos_runtime_file_metadata import _manager

    fixture = _fixture(tmp_path, fork=True)
    fixture.dispatcher.publish_prepared_action_cohort_batch(fixture.batch)
    saved = LocalArtifactVersionRegistryParticipant(fixture.content.registry).prepare_checkpoint(1)
    restored = _manager()
    LocalArtifactVersionRegistryParticipant(restored.registry).restore_checkpoint(
        saved.head.payload, ()
    )
    state = StateManager()
    _restore_head(state, _capture_head(fixture.state))
    for identity in (fixture.before, fixture.after):
        assert state.get_process_identity(identity.hostname, identity.pid) == identity
        assert (
            restored.registry.resolve_version(identity.executable_version.artifact_version_id)
            == fixture.records[0]
        )
        assert (
            restored.registry.resolve_version(identity.exec_script.artifact_version_id)
            == fixture.records[1]
        )
    restored.registry.advance_watermark(_START + timedelta(days=8))
    assert all(
        restored.registry.resolve_version(record.artifact.artifact_version_id) == record
        for record in fixture.records
    )
    fixture.emitter.close()
