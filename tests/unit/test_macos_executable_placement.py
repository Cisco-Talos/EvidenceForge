# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Executable name observations never replace loaded execution/content identities."""

from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.macos_process_observation import MacosProcessCollectionObservation
from evidenceforge.generation.checkpoints.artifact_registry_head import (
    LocalArtifactVersionRegistryParticipant,
)
from evidenceforge.generation.checkpoints.packed import dumps, loads
from evidenceforge.generation.macos_endpoint_security import (
    prepare_planned_runtime_es_process_snapshot,
    prepare_runtime_es_process_snapshot,
)
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_file_rename import _rename
from tests.unit.test_macos_runtime_es_preparation import _setup
from tests.unit.test_macos_runtime_file_metadata import _manager


@pytest.mark.parametrize("version", [6, 9, 10])
def test_native_snapshot_observes_renamed_file_without_rewriting_loaded_image(version: int) -> None:
    state, content, process, collection = _setup()
    original = prepare_runtime_es_process_snapshot(
        state, content.registry, process=process, collection=collection, version=version
    )
    source = content.registry.resolve_version(process.executable_version.artifact_version_id)
    renamed_at = collection.observed_at + timedelta(seconds=1)
    with _rename(content, source, observed_at=renamed_at) as rename:
        rename.commit()
    before = state.materialization_digest()
    later = replace(collection, observed_at=renamed_at)
    current = prepare_runtime_es_process_snapshot(
        state, content.registry, process=process, collection=later, version=version
    )
    assert current.executable.path == "/usr/local/libexec/renamed-worker"
    assert current.executable.stat.st_ino == original.executable.stat.st_ino
    assert current.cdhash == original.cdhash
    assert current.audit_token == original.audit_token
    assert state.get_process_identity(process.hostname, process.pid) == process
    assert state.materialization_digest() == before
    assert (
        content.registry.resolve_version(process.executable_version.artifact_version_id) == source
    )
    assert (
        prepare_runtime_es_process_snapshot(
            state, content.registry, process=process, collection=collection, version=version
        )
        == original
    )


def test_fork_after_rename_inherits_loaded_identity_and_observes_new_name() -> None:
    state, content, process, collection = _setup()
    source = content.registry.resolve_version(process.executable_version.artifact_version_id)
    at = collection.observed_at + timedelta(seconds=1)
    with _rename(content, source, observed_at=at) as rename:
        rename.commit()
    builder = state.begin_action_cohort_materialization()
    child = builder.fork_process(process, forked_at=at + timedelta(seconds=1))
    cohort = builder.seal()
    observation = MacosProcessCollectionObservation(
        child.identity, child.identity.started_at, False, "absent"
    )
    native = prepare_planned_runtime_es_process_snapshot(
        state, content.registry, cohort=cohort, collection=observation, version=9
    )
    assert native.executable.path == "/usr/local/libexec/renamed-worker"
    assert child.identity.image == process.image
    assert child.identity.executable_version == process.executable_version
    assert state.get_process(child.identity.hostname, child.identity.pid) is None


@pytest.mark.parametrize("damage", ["removed", "legacy", "expired"])
def test_unavailable_placement_does_not_fall_back_to_original_image(damage: str) -> None:
    state, content, process, collection = _setup()
    source = content.registry.resolve_version(process.executable_version.artifact_version_id)
    at = collection.observed_at + timedelta(seconds=1)
    if damage == "removed":
        content.registry.withdraw_execution_path(source, at)
    elif damage == "expired":
        with _rename(content, source, observed_at=at) as rename:
            rename.commit()
        content.registry.advance_watermark(at + timedelta(days=3))
    else:
        document = loads(
            LocalArtifactVersionRegistryParticipant(content.registry)
            .prepare_checkpoint(1)
            .head.payload
        )
        document["schema_version"] = "5"
        for row in document["records"]:
            del row[10:]
        content = _manager()
        LocalArtifactVersionRegistryParticipant(content.registry).restore_checkpoint(
            dumps(document), ()
        )
    with pytest.raises(StateError, match="retained executable"):
        prepare_runtime_es_process_snapshot(
            state,
            content.registry,
            process=process,
            collection=replace(collection, observed_at=at),
            version=9,
        )
