# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from dataclasses import dataclass, replace
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.events.content_identity import LocalArtifactVersionRecord
from evidenceforge.events.contexts import HostContext
from evidenceforge.events.dispatcher import EventDispatcher, PreparedActionCohortBatch
from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.macos_exec_script import MacosExecScript
from evidenceforge.events.process_executable import ProcessExecutableVersion
from evidenceforge.formats.loader import load_format
from evidenceforge.generation.actions.base import ActionAnchor
from evidenceforge.generation.actions.command_effects import (
    ExecutionEffectAuditCohortEntry,
    ExecutionEffectAuditCounter,
    ExecutionEffectPlan,
)
from evidenceforge.generation.actions.posix_process import process_fork_occurrence
from evidenceforge.generation.deployment_registry import (
    LocalArtifactPublishToken,
    LocalArtifactVersionRegistry,
)
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.generation.lifecycle_authority import GeneratorLifecycleAuthority
from evidenceforge.generation.lifecycle_registry import LifecycleRegistry
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.generation.runtime_content import RuntimeContentIdentityManager
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import EventContractError
from tests.unit.test_macos_runtime_es_preparation import _publish
from tests.unit.test_macos_runtime_file_metadata import _executable, _manager, _metadata
from tests.unit.test_process_exec_projection import _START, _exec_event


@dataclass
class _Fixture:
    state: StateManager
    dispatcher: EventDispatcher
    content: RuntimeContentIdentityManager
    emitter: EcarEmitter
    before: ProcessIdentity
    after: ProcessIdentity
    records: tuple[LocalArtifactVersionRecord, ...]
    tokens: tuple[LocalArtifactPublishToken, ...]
    batch: PreparedActionCohortBatch


def _fixture(
    tmp_path: Path, *, scripts: bool = True, foreign: bool = False, fork: bool = False
) -> _Fixture:
    content = _manager()
    image = replace(_executable(), hostname="HOST-01", principal="root")
    script = replace(
        image,
        native_path="/usr/local/share/invented-job",
        executable=False,
        architecture=None,
        code_signature=None,
        mach_o_image=None,
        mime_type="text/plain",
        seed_ref="invented-script",
        source_object_id="independent-script-source",
        file_object_id="independent-script",
        macos_file=_metadata(file_object_id="independent-script", inode=736),
    )
    old_descriptors = (image, script) if scripts else (image,)
    for descriptor in old_descriptors:
        _publish(content, descriptor, _START - timedelta(seconds=1))
    old = tuple(content.build_record(descriptor) for descriptor in old_descriptors)
    state = StateManager()
    state.set_current_time(_START)
    initial = state.plan_process_materialization(
        system="HOST-01",
        parent_pid=0,
        image=image.native_path,
        command_line=image.native_path,
        username="casey",
        integrity_level="Medium",
        os_category="macos",
        start_time=_START,
        executable_version=ProcessExecutableVersion.from_binary(old[0].binary),
        exec_script=MacosExecScript.from_runtime_record(old[1]) if scripts else None,
    )
    state.materialize_process(initial)
    lifecycle = LifecycleRegistry(shard_count=4)
    shadow = LifecycleShadow(state, lifecycle)
    authority = GeneratorLifecycleAuthority(state, shadow, shard_count=4)
    authority.bootstrap_active_state()
    emitter = EcarEmitter(load_format("ecar"), tmp_path, threaded=False)
    dispatcher = EventDispatcher(
        state,
        {"ecar": emitter},
        lifecycle_shadow=shadow,
        enforce_lifecycle_authority=True,
        local_artifact_registry=content.registry,
    )
    dispatcher.bind_lifecycle_authority(authority)
    dispatcher.bind_execution_effect_audit(ExecutionEffectAuditCounter())
    new_descriptors = tuple(
        replace(descriptor, artifact_version=2, content_version=2) for descriptor in old_descriptors
    )
    for descriptor in new_descriptors:
        _publish(content, descriptor, _START + timedelta(seconds=1))
    new = tuple(content.build_record(descriptor) for descriptor in new_descriptors)
    builder = state.begin_action_cohort_materialization()
    if fork:
        after = builder.fork_process(
            initial.identity, forked_at=_START + timedelta(seconds=2)
        ).identity
        event = process_fork_occurrence(
            host=HostContext(
                hostname="HOST-01",
                ip="192.0.2.20",
                os="macOS 26",
                os_category="macos",
                system_type="workstation",
            ),
            parent=initial.identity,
            child=after,
            integrity_level="Medium",
        )
        event.process.binary_identity = old[0].binary
        records = old
    else:
        after = builder.execute_process(
            initial.identity,
            image=image.native_path,
            command_line=image.native_path,
            executed_at=_START + timedelta(seconds=2),
            executable_version=ProcessExecutableVersion.from_binary(new[0].binary),
            exec_script=MacosExecScript.from_runtime_record(new[1]) if scripts else None,
        )
        event = _exec_event(initial.identity, after)
        event.process.binary_identity = new[0].binary
        records = (*old, *new)
    plan = builder.seal()
    if foreign:
        descriptor = replace(
            script,
            native_path="/usr/local/share/unrelated",
            seed_ref="unrelated",
            source_object_id="unrelated",
        )
        _publish(content, descriptor, _START + timedelta(seconds=1))
        records = (content.build_record(descriptor),)
    tokens = tuple(
        content.registry.prepare_version_retention(
            record.artifact.artifact_version_id,
            observed_at=event.timestamp,
            retained_until=_START + timedelta(days=10),
            lease_owner="invented-exec-content-window",
        )
        for record in records
    )
    with dispatcher.source_timing_planner.prepared_planning() as timing:
        carrier = dispatcher.prepare_action_cohort_projection(
            event, source_timing_preparation=timing
        )
    try:
        dispatch = dispatcher.bind_action_cohort_projection(
            carrier, state_plan=plan, artifact_publications=tokens
        )
        root = f"process-fork:{after.object_id}" if fork else f"process-exec:{after.execution_id}"
        effects = ExecutionEffectPlan(
            ActionAnchor("process_execution", root, source="unit_test"), ()
        )
        batch = dispatcher.prepare_action_cohort_batch(
            root,
            plan,
            (dispatch,),
            (ExecutionEffectAuditCohortEntry(effects, effects.reconcile(())),),
            (),
            (),
            exact_projection=True,
        )
    except BaseException:
        for token in tokens:
            content.registry.cancel_prepared(token)
        emitter.close()
        raise
    return _Fixture(
        state, dispatcher, content, emitter, initial.identity, after, records, tokens, batch
    )


@pytest.mark.parametrize("scripts", [False, True])
def test_exec_retains_prior_and_replacement_versions_without_restoring_old_paths(
    tmp_path: Path, scripts: bool
) -> None:
    fixture = _fixture(tmp_path, scripts=scripts)
    result = fixture.dispatcher.publish_prepared_action_cohort_batch(fixture.batch)
    assert result.projections[0].status == "succeeded"
    assert fixture.state.get_process_identity("HOST-01", fixture.before.pid) == fixture.after
    fixture.content.registry.advance_watermark(_START + timedelta(days=8))
    for record in fixture.records:
        assert (
            fixture.content.registry.resolve_version(record.artifact.artifact_version_id) == record
        )
    for record in fixture.records[len(fixture.records) // 2 :]:
        assert (
            fixture.content.resolve_record("HOST-01", "root", record.artifact.native_path, "macos")
            == record
        )
    fixture.emitter.close()


@pytest.mark.parametrize("failed_member", [1, 2, 3, 4])
def test_multi_content_failure_rolls_back_every_lease_and_exec(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failed_member: int
) -> None:
    fixture = _fixture(tmp_path)
    original = LocalArtifactVersionRegistry._commit_prepared_locked
    count = 0

    def fail(registry: LocalArtifactVersionRegistry, *args: object) -> object:
        nonlocal count
        result = original(registry, *args)
        count += 1
        if count == failed_member:
            raise RuntimeError("injected grouped content retention failure")
        return result

    monkeypatch.setattr(LocalArtifactVersionRegistry, "_commit_prepared_locked", fail)
    with pytest.raises(RuntimeError, match="grouped content retention"):
        fixture.dispatcher.publish_prepared_action_cohort_batch(fixture.batch)
    assert fixture.state.get_process_identity("HOST-01", fixture.before.pid) == fixture.before
    assert fixture.content.registry.census().prepared_publications == 0
    fixture.content.registry.advance_watermark(_START + timedelta(days=8))
    assert all(
        fixture.content.registry.resolve_version(record.artifact.artifact_version_id) is None
        for record in fixture.records
    )
    fixture.emitter.close()


def test_unrelated_script_cannot_use_exec_as_a_retention_owner(tmp_path: Path) -> None:
    with pytest.raises(
        EventContractError, match="owner drifted|unrelated|existing image or script"
    ):
        _fixture(tmp_path, foreign=True)


def test_exec_content_and_historical_identity_restore_together(tmp_path: Path) -> None:
    from evidenceforge.generation.checkpoints.artifact_registry_head import (
        LocalArtifactVersionRegistryParticipant,
    )
    from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head

    fixture = _fixture(tmp_path)
    fixture.dispatcher.publish_prepared_action_cohort_batch(fixture.batch)
    head = LocalArtifactVersionRegistryParticipant(fixture.content.registry).prepare_checkpoint(1)
    restored_content = _manager()
    LocalArtifactVersionRegistryParticipant(restored_content.registry).restore_checkpoint(
        head.head.payload, ()
    )
    restored = StateManager()
    _restore_head(restored, _capture_head(fixture.state))
    assert restored.get_process_identity("HOST-01", fixture.before.pid) == fixture.after
    assert restored.get_process_identity_at("HOST-01", fixture.before.pid, _START) == fixture.before
    restored_content.registry.advance_watermark(_START + timedelta(days=8))
    assert all(
        restored_content.registry.resolve_version(record.artifact.artifact_version_id) == record
        for record in fixture.records
    )
    fixture.emitter.close()
