# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.events.content_identity import LocalArtifactVersionRecord
from evidenceforge.events.dispatcher import (
    EventDispatcher,
    PreparedActionCohortBatch,
    PreparedActionCohortCapability,
)
from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.process_executable import ProcessExecutableVersion
from evidenceforge.formats.loader import load_format
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.actions.command_effects import (
    ExecutionEffectAuditCohortEntry,
    ExecutionEffectPlan,
)
from evidenceforge.generation.deployment_registry import (
    LocalArtifactPreparedGroupCommit,
    LocalArtifactVersionRegistry,
)
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.generation.emitters.sorted_writer import ExternalSortedLineWriter
from evidenceforge.generation.runtime_content import RuntimeContentIdentityManager
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import EventContractError
from tests.unit.test_macos_runtime_es_preparation import _publish
from tests.unit.test_macos_runtime_file_metadata import _executable, _manager
from tests.unit.test_process_exec_projection import _START, _environment, _exec_event


def _prepared(
    tmp_path: Path,
    *,
    collected: bool = True,
    new_file: bool = False,
    file_principal: str = "casey",
) -> tuple[
    StateManager,
    EventDispatcher,
    EcarEmitter,
    RuntimeContentIdentityManager,
    ProcessIdentity,
    ProcessIdentity,
    LocalArtifactVersionRecord,
    PreparedActionCohortBatch,
]:
    state, dispatcher, _ = _environment()
    emitter = EcarEmitter(load_format("ecar"), tmp_path, threaded=True)
    dispatcher.emitters = {"ecar": emitter} if collected else {}
    content = _manager()
    dispatcher.bind_local_artifact_registry(content.registry)
    descriptor = replace(_executable(), hostname="HOST-01", principal=file_principal)
    if not new_file:
        _publish(content, descriptor, _START)
    record = content.build_record(descriptor)
    before = state.get_process_identity(
        "HOST-01", next(iter(state._running_processes.values())).pid
    )
    at = _START + timedelta(seconds=2)
    token = content.registry.prepare_publish_version(
        record,
        at,
        retention=timedelta(days=8),
        lease_owner="invented-exec-retention",
        lease_until=_START + timedelta(days=8, seconds=3),
    )
    builder = state.begin_action_cohort_materialization()
    after = builder.execute_process(
        before,
        image=descriptor.native_path,
        command_line="invented-worker",
        executed_at=at,
        executable_version=ProcessExecutableVersion.from_binary(record.binary),
    )
    plan = builder.seal()
    event = _exec_event(before, after)
    event.process.binary_identity = record.binary
    with dispatcher.source_timing_planner.prepared_planning() as timing:
        carrier = dispatcher.prepare_action_cohort_projection(
            event, source_timing_preparation=timing
        )
    dispatch = dispatcher.bind_action_cohort_projection(
        carrier, state_plan=plan, artifact_publications=(token,)
    )
    effects = ExecutionEffectPlan(
        ActionAnchor("process_execution", f"process-exec:{after.execution_id}", source="unit_test"),
        (),
    )
    batch = dispatcher.prepare_action_cohort_batch(
        f"process-exec:{after.execution_id}",
        plan,
        (dispatch,),
        (ExecutionEffectAuditCohortEntry(effects, effects.reconcile(())),),
        (),
        (),
        exact_projection=True,
    )
    return state, dispatcher, emitter, content, before, after, record, batch


@pytest.mark.parametrize("collected", [False, True])
def test_exact_exec_extends_loaded_version_with_source_filtering(
    tmp_path: Path, collected: bool
) -> None:
    state, dispatcher, emitter, content, before, after, record, batch = _prepared(
        tmp_path, collected=collected
    )
    dispatcher.publish_prepared_action_cohort_batch(batch)
    assert state.get_process_identity("HOST-01", before.pid) == after
    content.registry.advance_watermark(_START + timedelta(days=7))
    assert content.registry.resolve_version(record.artifact.artifact_version_id) == record
    emitter.close()
    rows = [line for path in tmp_path.rglob("ecar.json") for line in path.read_text().splitlines()]
    assert len(rows) == int(collected)


def test_exact_exec_rejects_new_artifact_publication(tmp_path: Path) -> None:
    with pytest.raises(EventContractError, match="existing image|exact retained content version"):
        _prepared(tmp_path, new_file=True)


def test_cancelled_exact_exec_does_not_extend_or_change_process(tmp_path: Path) -> None:
    state, dispatcher, emitter, content, before, after, record, batch = _prepared(tmp_path)
    assert dispatcher.cancel_prepared_action_cohort_batch(batch)
    assert state.get_process_identity("HOST-01", before.pid) == before
    assert content.registry.census().prepared_publications == 0
    content.registry.advance_watermark(_START + timedelta(days=7))
    assert content.registry.resolve_version(record.artifact.artifact_version_id) is None
    emitter.close()


def test_retention_commit_failure_rolls_back_provisional_exec(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state, dispatcher, emitter, content, before, after, record, batch = _prepared(tmp_path)
    original = LocalArtifactVersionRegistry._commit_prepared_locked

    def fail(registry: LocalArtifactVersionRegistry, *args: object) -> None:
        original(registry, *args)
        raise RuntimeError("injected retention failure")

    monkeypatch.setattr(LocalArtifactVersionRegistry, "_commit_prepared_locked", fail)
    with pytest.raises(RuntimeError, match="retention failure"):
        dispatcher.publish_prepared_action_cohort_batch(batch)
    assert state.get_process_identity("HOST-01", before.pid) == before
    assert content.registry.census().prepared_publications == 0
    content.registry.advance_watermark(_START + timedelta(days=7))
    assert content.registry.resolve_version(record.artifact.artifact_version_id) is None
    emitter.close()


@pytest.mark.parametrize("boundary", ["group", "capability"])
def test_retention_lost_return_adopts_exact_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str
) -> None:
    state, dispatcher, emitter, content, before, after, record, batch = _prepared(tmp_path)
    target = (
        LocalArtifactVersionRegistry if boundary == "group" else LocalArtifactPreparedGroupCommit
    )
    name = "_commit_claimed_group" if boundary == "group" else "commit_no_fail"
    original = getattr(target, name)

    def lose_return(owner: object, *args: object) -> None:
        original(owner, *args)
        raise RuntimeError("injected artifact lost return")

    monkeypatch.setattr(target, name, lose_return)
    dispatcher.publish_prepared_action_cohort_batch(batch)
    assert state.get_process_identity("HOST-01", before.pid) == after
    content.registry.advance_watermark(_START + timedelta(days=7))
    assert content.registry.resolve_version(record.artifact.artifact_version_id) == record
    emitter.close()


def test_exact_sink_retry_retains_image_without_repeating_exec(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = ExternalSortedLineWriter._commit_exact_row
    attempts = 0

    def lose_return(writer: ExternalSortedLineWriter, *args: object) -> None:
        nonlocal attempts
        original(writer, *args)
        attempts += 1
        if attempts == 1:
            raise RuntimeError("injected source lost return")

    monkeypatch.setattr(ExternalSortedLineWriter, "_commit_exact_row", lose_return)
    state, dispatcher, emitter, content, before, after, record, batch = _prepared(tmp_path)
    capability: PreparedActionCohortCapability | None = None
    with pytest.raises(RuntimeError, match="source lost return"):
        with dispatcher.claimed_action_cohort(batch) as capability:
            capability.commit_no_fail()
    assert capability.committed
    version = state.materialization_version
    assert state.get_process_identity("HOST-01", before.pid) == after
    monkeypatch.undo()
    dispatcher.resume_action_cohort_projection(capability.receipt)
    assert state.materialization_version == version
    content.registry.advance_watermark(_START + timedelta(days=7))
    assert content.registry.resolve_version(record.artifact.artifact_version_id) == record
    emitter.close()
    rows = [line for path in tmp_path.rglob("ecar.json") for line in path.read_text().splitlines()]
    assert len(rows) == 1


def test_shared_root_image_retention_does_not_change_execution_principal(tmp_path: Path) -> None:
    state, dispatcher, emitter, content, before, after, record, batch = _prepared(
        tmp_path, file_principal="root"
    )
    dispatcher.publish_prepared_action_cohort_batch(batch)
    assert state.get_process_identity("HOST-01", before.pid) == after
    assert after.principal == "casey" and record.artifact.principal == "root"
    content.registry.advance_watermark(_START + timedelta(days=7))
    assert content.registry.resolve_version(record.artifact.artifact_version_id) == record
    emitter.close()
