# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Ordinary Mac baseline activity reaches the canonical native filesystem producer."""

from __future__ import annotations

import random
import shlex
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Literal

import pytest

from evidenceforge.config.provider import effective_config_scope
from evidenceforge.formats.macos_endpoint_security import decode_endpoint_security_record
from evidenceforge.generation.actions.macos_filesystem import MacosFilesystemActionBundle
from evidenceforge.generation.checkpoints.errors import CheckpointError
from evidenceforge.generation.macos_filesystem_workload import (
    MacosFilesystemWorkflow,
    document_requests,
    emit_macos_document_workload,
)
from tests.unit.test_macos_finder_generation import _finder_engine
from tests.unit.test_macos_vscode_generation import MAIN

if TYPE_CHECKING:
    from evidenceforge.events.dispatcher import PreparedActionCohortCapability
    from evidenceforge.events.identity import ProcessIdentity
    from evidenceforge.generation.deployment_registry import LocalArtifactPreparedGroupCommit
    from evidenceforge.generation.engine import GenerationEngine
    from evidenceforge.generation.state_manager import (
        PreparedActionCohortMaterialization,
        StateManager,
    )
    from evidenceforge.models.scenario import System


class _OneSave(random.Random):
    def randint(self, a: int, b: int) -> int:
        return 1 if (a, b) == (0, 2) else b

    def random(self) -> float:
        return 0.9


def _engine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, native: bool = True
) -> tuple[GenerationEngine, System, ProcessIdentity]:
    engine = _finder_engine(tmp_path, monkeypatch, native=native, gui_application="vscode")
    with effective_config_scope(engine.compiled_scenario.effective_config):
        engine._initialize()
    generator = engine.activity_generator
    user, system = engine.scenario.environment.users[0], engine.scenario.environment.systems[0]
    logon = generator.generate_logon(
        user, system, engine.start_time - timedelta(minutes=5), allow_local_session_reuse=False
    )
    at = engine.start_time + timedelta(minutes=2)
    pid = generator.generate_process(
        user, system, at, logon, MAIN, shlex.join((MAIN,)), arguments=(MAIN,)
    )
    actor = engine.state_manager.get_process_identity(system.hostname, pid)
    assert actor is not None
    return engine, system, actor


@pytest.mark.parametrize("native", [False, True])
def test_baseline_produces_empty_create_and_modified_close_without_manual_registry_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    native: bool,
) -> None:
    engine, system, actor = _engine(tmp_path, monkeypatch, native)
    try:
        assert engine.dispatcher.local_artifact_registry is not None
        emit_macos_document_workload(engine, system, engine.start_time, _OneSave(17))
        registry = engine.dispatcher.local_artifact_registry
        policy = engine.macos_execution_metadata.profile.filesystem_workload
        account = engine._identity_directory.macos_account(actor.principal, system.hostname)
        directory = account.home + "/" + policy.directory_name
        changed = engine.state_manager.macos_filesystem_directory(
            system.hostname, directory, engine.start_time + timedelta(hours=1)
        )
        assert changed is not None
        assert (
            changed.metadata.size_bytes
            == engine.macos_execution_metadata.profile.directory_size_bytes
            + policy.directory_entry_bytes
        )
        assert engine.state_manager._macos_filesystem_inodes[system.hostname.casefold()] == (
            policy.first_inode,
            policy.first_inode,
        )
        assert registry.census().prepared_publications == 0
        assert engine.activity_generator._macos_filesystem_workflows == {}
        engine._finalize_macos_process_coverage()
        if native:
            assert engine.dispatcher.macos_es_ingress.coverage.hosts[0].process_census.complete
    finally:
        engine._close_emitters()
    records = [
        decode_endpoint_security_record(line)
        for path in (tmp_path / "run").rglob("macos_endpoint_security.ndjson")
        for line in path.read_text().splitlines()
    ]
    files = [row for row in records if row.event_type in {12, 13}]
    assert [row.event_type for row in files] == ([13, 12] if native else [])
    if native:
        created = files[0].event.create.destination.existing_file
        closed = files[1].event.close.target
        assert created.stat.st_size == 0 and closed.stat.st_size == policy.size_max
        assert created.stat.st_ino == closed.stat.st_ino == policy.first_inode
        assert created.stat.st_uid == actor.credentials.effective_uid
        assert files[1].event.close.modified is True


def test_document_rewrite_preserves_inode_and_retires_only_old_placement_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine, system, actor = _engine(tmp_path, monkeypatch)
    try:
        host = engine.activity_generator._build_host_context(system)
        provider = engine.macos_execution_metadata
        first = engine.start_time + timedelta(minutes=3)
        old_directory = provider.directory(
            system.hostname,
            engine._identity_directory.macos_account(actor.principal, system.hostname).home
            + "/Documents",
            first,
        )
        for index in range(3):
            requests = document_requests(
                engine,
                host,
                actor,
                first + timedelta(seconds=index),
                "work-notes.md",
                256 + index,
                0.01,
                f"save-{index}",
            )
            assert len(requests) == (2 if index == 0 else 1)
            MacosFilesystemWorkflow(MacosFilesystemActionBundle(engine.dispatcher), requests).run()
        registry = engine.dispatcher.local_artifact_registry
        current = registry.resolve_record_for_execution_path(
            system.hostname, actor.principal, old_directory.native_path + "/work-notes.md", "macos"
        )
        assert current.macos_file.inode == provider.profile.filesystem_workload.first_inode
        assert current.content.size_bytes == 258
        # Directory entry stat changes only at creation, not at content writes.
        latest = provider.directory(
            system.hostname, old_directory.native_path, first + timedelta(seconds=4)
        )
        assert latest.metadata.modified == current.macos_file.born
        assert latest.metadata.inode == old_directory.metadata.inode
        assert registry.census().prepared_publications == 0
        assert registry.census().active_leases == 1
        registry.advance_watermark(engine.end_time + timedelta(hours=48) - timedelta(seconds=1))
        assert (
            registry.resolve_record_for_execution_path(
                system.hostname,
                actor.principal,
                old_directory.native_path + "/work-notes.md",
                "macos",
            )
            == current
        )
        assert registry.census().live_versions == registry.census().active_leases == 1
    finally:
        engine._close_emitters()


@pytest.mark.parametrize("fault", ["artifact", "provisional_state"])
def test_filesystem_state_and_inode_reservation_roll_back_with_the_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    from evidenceforge.generation.deployment_registry import LocalArtifactPreparedGroupCommit
    from evidenceforge.generation.state_manager import StateManager

    engine, system, actor = _engine(tmp_path, monkeypatch)
    try:
        state = engine.state_manager
        requests = document_requests(
            engine,
            engine.activity_generator._build_host_context(system),
            actor,
            engine.start_time + timedelta(minutes=3),
            "work-notes.md",
            256,
            0.01,
            "rollback-file",
        )
        workflow = MacosFilesystemWorkflow(MacosFilesystemActionBundle(engine.dispatcher), requests)
        before = state.materialization_digest()
        ingress_count = engine.dispatcher.macos_es_ingress.event_count
        original = StateManager._apply_claimed_action_cohort_materialization

        def fail_state(
            owner: StateManager,
            preparation: PreparedActionCohortMaterialization,
            *,
            require_certified: bool,
        ) -> None:
            original(owner, preparation, require_certified=require_certified)
            raise OSError("invented filesystem state interruption")

        def fail_artifact(_group: LocalArtifactPreparedGroupCommit) -> None:
            raise OSError("invented filesystem state interruption")

        with monkeypatch.context() as scoped:
            if fault == "artifact":
                scoped.setattr(LocalArtifactPreparedGroupCommit, "commit_no_fail", fail_artifact)
            else:
                scoped.setattr(
                    StateManager, "_apply_claimed_action_cohort_materialization", fail_state
                )
            with pytest.raises(OSError, match="invented filesystem state interruption"):
                workflow.run()
        assert state.materialization_digest() == before
        assert state._macos_filesystem_directories == state._macos_filesystem_inodes == {}
        assert engine.dispatcher.macos_es_ingress.event_count == ingress_count
        assert engine.dispatcher.local_artifact_registry.census().prepared_publications == 0
        workflow.run()
        policy = engine.macos_execution_metadata.profile.filesystem_workload
        assert state._macos_filesystem_inodes[system.hostname.casefold()] == (
            policy.first_inode,
            policy.first_inode,
        )
        assert engine.dispatcher.macos_es_ingress.event_count == ingress_count + 2
    finally:
        engine._close_emitters()


@pytest.mark.parametrize(
    "mode,phase",
    [
        ("write_close", 0),
        ("write_close", 1),
        ("atomic_replace", 0),
        ("atomic_replace", 1),
        ("atomic_replace", 2),
        ("atomic_replace", 3),
    ],
)
def test_save_retry_does_not_repeat_committed_operations_or_directory_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: Literal["write_close", "atomic_replace"],
    phase: int,
) -> None:
    from evidenceforge.events.dispatcher import PreparedActionCohortCapability

    engine, system, actor = _engine(tmp_path, monkeypatch)
    try:
        requests = document_requests(
            engine,
            engine.activity_generator._build_host_context(system),
            actor,
            engine.start_time + timedelta(minutes=3),
            "work-notes.md",
            256,
            0.01,
            "lost-file",
            mode=mode,
            cleanup=mode == "atomic_replace",
        )
        workflow = MacosFilesystemWorkflow(MacosFilesystemActionBundle(engine.dispatcher), requests)
        original = PreparedActionCohortCapability.commit_no_fail
        calls = 0
        failed = False

        def lose_return(capability: PreparedActionCohortCapability) -> None:
            nonlocal calls, failed
            current = calls
            calls += 1
            original(capability)
            if current == phase and not failed:
                failed = True
                raise OSError("invented filesystem lost return")

        count = engine.dispatcher.macos_es_ingress.event_count
        with monkeypatch.context() as scoped:
            scoped.setattr(PreparedActionCohortCapability, "commit_no_fail", lose_return)
            with pytest.raises(OSError, match="invented filesystem lost return"):
                workflow.run()
        workflow.run()
        assert engine.dispatcher.macos_es_ingress.event_count == count + len(requests)
        assert workflow.index == len(requests)
        assert len(engine.state_manager._macos_filesystem_directories) == 1
        assert (
            next(iter(engine.state_manager._macos_filesystem_inodes.values()))[1]
            == requests[0].observation.source.macos_file.inode
        )
    finally:
        engine._close_emitters()


def test_hour_retry_retains_all_sampled_saves_and_blocks_checkpoint_until_complete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from evidenceforge.events.dispatcher import PreparedActionCohortCapability
    from evidenceforge.generation.checkpoints.activity_head import ActivityGeneratorStateParticipant

    class TwoSaves(random.Random):
        def randint(self, a: int, b: int) -> int:
            return 2 if (a, b) == (0, 2) else super().randint(a, b)

    engine, system, _ = _engine(tmp_path, monkeypatch)
    try:
        provider = engine.macos_execution_metadata
        provider.profile = provider.profile.model_copy(
            update={
                "filesystem_workload": provider.profile.filesystem_workload.model_copy(
                    update={
                        "atomic_replace_probability": 0.0,
                        "cleanup_probability": 0.0,
                    }
                ),
            }
        )
        ingress_count = engine.dispatcher.macos_es_ingress.event_count
        original = PreparedActionCohortCapability.commit_no_fail
        failed = False

        def fail_once(capability: PreparedActionCohortCapability) -> None:
            nonlocal failed
            original(capability)
            if not failed:
                failed = True
                raise OSError("invented activity-page interruption")

        with monkeypatch.context() as scoped:
            scoped.setattr(PreparedActionCohortCapability, "commit_no_fail", fail_once)
            with pytest.raises(OSError, match="activity-page interruption"):
                emit_macos_document_workload(engine, system, engine.start_time, TwoSaves(17))
        batches = engine.activity_generator._macos_filesystem_workflows
        assert len(batches) == 1
        batch = next(iter(batches.values()))
        assert len(batch.intents) == 2
        expected_files = {item.filename for item in batch.intents}
        with pytest.raises(CheckpointError, match="_macos_filesystem_workflows"):
            ActivityGeneratorStateParticipant(engine.activity_generator).prepare_checkpoint(1)

        # Reentry drains the same page; no additional random sampling is allowed.
        class NoRandom(random.Random):
            def random(self) -> float:
                raise AssertionError("Retried activity sampled another workload")

        emit_macos_document_workload(engine, system, engine.start_time, NoRandom(99))
        assert batches == {} and batch.index == 2
        assert engine.dispatcher.macos_es_ingress.event_count == ingress_count + 2 + len(
            expected_files
        )
        ActivityGeneratorStateParticipant(engine.activity_generator).prepare_checkpoint(1)
    finally:
        engine._close_emitters()


@pytest.mark.parametrize("cleanup", [False, True])
def test_atomic_save_replaces_the_destination_and_cleanup_withdraws_its_placement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cleanup: bool
) -> None:
    engine, system, actor = _engine(tmp_path, monkeypatch)
    try:
        host = engine.activity_generator._build_host_context(system)
        registry = engine.dispatcher.local_artifact_registry
        provider = engine.macos_execution_metadata
        at = engine.start_time + timedelta(minutes=3)
        directory_path = (
            engine._identity_directory.macos_account(actor.principal, system.hostname).home
            + "/Documents"
        )
        old_directory = provider.directory(system.hostname, directory_path, at)
        records = []
        for index in range(2):
            requests = document_requests(
                engine,
                host,
                actor,
                at + timedelta(seconds=index),
                "work-notes.md",
                256,
                0.01,
                f"atomic-{index}",
                mode="atomic_replace",
                cleanup=cleanup and index == 1,
            )
            MacosFilesystemWorkflow(MacosFilesystemActionBundle(engine.dispatcher), requests).run()
            records.append(requests[2].observation.target)
            if index:
                assert requests[2].observation.replacement == records[0]
                assert records[1].macos_file.inode != records[0].macos_file.inode
        final = registry.resolve_record_for_execution_path(
            system.hostname, actor.principal, directory_path + "/work-notes.md", "macos"
        )
        assert final == (None if cleanup else records[1])
        latest = provider.directory(system.hostname, directory_path, at + timedelta(seconds=3))
        assert latest.metadata.size_bytes == old_directory.metadata.size_bytes + (
            0 if cleanup else provider.profile.filesystem_workload.directory_entry_bytes
        )
        assert registry.census().active_leases == (0 if cleanup else 1)
        assert registry.census().prepared_publications == 0
        engine._finalize_macos_process_coverage()
    finally:
        engine._close_emitters()
    rows = [
        decode_endpoint_security_record(line)
        for path in (tmp_path / "run").rglob("macos_endpoint_security.ndjson")
        for line in path.read_text().splitlines()
    ]
    files = [row for row in rows if row.event_type in {12, 13, 25, 32}]
    assert [row.event_type for row in files] == [13, 12, 25, 13, 12, 25] + ([32] if cleanup else [])
    assert files[2].event.rename.destination_type == 1
    assert files[5].event.rename.destination_type == 0
    assert (
        files[5].event.rename.destination.existing_file.stat.st_ino == records[0].macos_file.inode
    )
    if cleanup:
        assert files[-1].event.unlink.target.stat.st_nlink == 1
        assert files[-1].event.unlink.parent_dir.stat.st_size == (
            old_directory.metadata.size_bytes
            + provider.profile.filesystem_workload.directory_entry_bytes
        )


def test_filesystem_checkpoint_restores_shared_stat_inode_allocator_and_current_placement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from evidenceforge.generation.checkpoints.artifact_registry_head import (
        LocalArtifactVersionRegistryParticipant,
    )
    from evidenceforge.generation.checkpoints.state_manager_head import StateManagerParticipant
    from evidenceforge.generation.deployment_registry import LocalArtifactVersionRegistry
    from evidenceforge.generation.state_manager import StateManager

    engine, system, actor = _engine(tmp_path, monkeypatch)
    try:
        emit_macos_document_workload(engine, system, engine.start_time, _OneSave(17))
        participant = StateManagerParticipant(engine.state_manager)
        seal = participant.prepare_checkpoint(1)
        restored = StateManager()
        StateManagerParticipant(restored).restore_checkpoint(
            seal.head.payload, tuple(segment.payload for segment in seal.segments)
        )
        assert (
            restored._macos_filesystem_directories
            == engine.state_manager._macos_filesystem_directories
        )
        assert restored._macos_filesystem_inodes == engine.state_manager._macos_filesystem_inodes
        assert restored.get_process_identity(system.hostname, actor.pid) == actor
        policy = engine.macos_execution_metadata.profile.filesystem_workload
        assert (
            restored.macos_filesystem_next_inode(system.hostname, policy.first_inode)
            == policy.first_inode + 1
        )
        directory = next(iter(restored._macos_filesystem_directories.values()))[-1]
        observed = restored.macos_filesystem_directory(
            system.hostname, directory.native_path, directory.observed_at
        )
        assert observed.metadata == directory.metadata
        assert observed.metadata is not directory.metadata
        artifacts = engine.dispatcher.local_artifact_registry
        artifact_seal = LocalArtifactVersionRegistryParticipant(artifacts).prepare_checkpoint(1)
        recovered_artifacts = LocalArtifactVersionRegistry()
        LocalArtifactVersionRegistryParticipant(recovered_artifacts).restore_checkpoint(
            artifact_seal.head.payload, ()
        )
        assert recovered_artifacts.census() == artifacts.census()
        for filename in policy.filenames:
            arguments = (
                system.hostname,
                actor.principal,
                directory.native_path + "/" + filename,
                "macos",
            )
            assert recovered_artifacts.resolve_record_for_execution_path(
                *arguments
            ) == artifacts.resolve_record_for_execution_path(*arguments)
    finally:
        engine._close_emitters()


def test_fork_uses_current_shared_directory_stat_without_changing_its_object(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, system, actor = _engine(tmp_path, monkeypatch)
    try:
        provider = engine.macos_execution_metadata
        at = engine.start_time + timedelta(minutes=3)
        path = (
            engine._identity_directory.macos_account(actor.principal, system.hostname).home
            + "/Documents"
        )
        before = provider.directory(system.hostname, path, at)
        builder = engine.state_manager.begin_action_cohort_materialization()
        builder.change_macos_process_directory(actor, directory=before)
        engine.state_manager.materialize_action_cohort(builder.seal())
        requests = document_requests(
            engine,
            engine.activity_generator._build_host_context(system),
            actor,
            at + timedelta(seconds=1),
            "work-notes.md",
            256,
            0.01,
            "directory-save",
        )
        MacosFilesystemWorkflow(MacosFilesystemActionBundle(engine.dispatcher), requests).run()
        builder = engine.state_manager.begin_action_cohort_materialization()
        child = provider.plan_fork(
            builder, engine.state_manager, actor, at=at + timedelta(seconds=2)
        )
        observed = child.identity.execution_directory
        assert observed.metadata.file_object_id == before.metadata.file_object_id
        assert observed.metadata.inode == before.metadata.inode
        assert observed.metadata.size_bytes > before.metadata.size_bytes
        assert observed.metadata.modified != before.metadata.modified
        assert actor.execution_directory != observed
    finally:
        engine._close_emitters()


def test_document_activity_respects_owning_session_deadline_before_process_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from evidenceforge.events.lifecycle import SessionEndPlan

    engine, system, actor = _engine(tmp_path, monkeypatch)
    try:
        # The main is still present in live State, but no new work may cross
        # the predeclared GUI-session end awaiting its finalizer.
        engine.state_manager.plan_session_end(
            actor.logon_id,
            SessionEndPlan(engine.start_time + timedelta(minutes=3), "action_bundle"),
        )
        assert engine.state_manager.get_process(system.hostname, actor.pid) is not None
        count = engine.dispatcher.macos_es_ingress.event_count
        emit_macos_document_workload(engine, system, engine.start_time, _OneSave(17))
        assert engine.dispatcher.macos_es_ingress.event_count == count
        assert engine.state_manager._macos_filesystem_inodes == {}
        assert engine.dispatcher.local_artifact_registry.census().live_versions == 0
    finally:
        engine._close_emitters()
