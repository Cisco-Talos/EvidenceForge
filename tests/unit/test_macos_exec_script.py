# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Invented script references cannot be replaced by argv or current-path guesses."""

from dataclasses import replace
from datetime import timedelta

import pytest

from evidenceforge.events.content_identity import LocalArtifactVersionRecord
from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.macos_exec_script import MacosExecScript
from evidenceforge.formats.macos_file_metadata import es_script_at_execution
from evidenceforge.generation.actions.process_policy import record_failed_process_exec
from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.checkpoints.state_values import decode_state_value, encode_state_value
from evidenceforge.generation.macos_endpoint_security import prepare_runtime_es_exec_script
from evidenceforge.generation.runtime_content import (
    RuntimeArtifactDescriptor,
    RuntimeContentIdentityManager,
)
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_runtime_es_preparation import _publish, _setup
from tests.unit.test_macos_runtime_file_metadata import _executable


def _script(
    content: RuntimeContentIdentityManager, hostname: str
) -> tuple[RuntimeArtifactDescriptor, LocalArtifactVersionRecord]:
    original = _executable()
    descriptor = replace(
        original,
        hostname=hostname,
        native_path="/usr/local/lib/invented-script",
        source_object_id="invented-script-source",
        seed_ref="invented-script-content",
        mime_type="text/x-shellscript",
        file_object_id="invented-script-file",
        executable=False,
        architecture=None,
        code_signature=None,
        mach_o_image=None,
        macos_file=original.macos_file.model_copy(
            update={"file_object_id": "invented-script-file"}
        ),
    )
    return descriptor, content.build_record(descriptor)


def _replace_script(
    state: StateManager, actor: ProcessIdentity, script: MacosExecScript | None, seconds: int = 1
) -> ProcessIdentity:
    builder = state.begin_action_cohort_materialization()
    after = builder.execute_process(
        actor,
        image=actor.image,
        command_line=actor.command_line,
        executed_at=actor.execution_started_at + timedelta(seconds=seconds),
        executable_version=actor.executable_version,
        exec_script=script,
    )
    state.materialize_action_cohort(builder.seal())
    return after


def test_unknown_absent_and_present_are_distinct_and_file_version_is_exact() -> None:
    state, content, actor, _ = _setup()
    with pytest.raises(StateError, match="known script"):
        prepare_runtime_es_exec_script(state, content.registry, process=actor)
    absent = _replace_script(state, actor, MacosExecScript())
    assert prepare_runtime_es_exec_script(state, content.registry, process=absent) is None
    descriptor, record = _script(content, actor.hostname)
    _publish(content, descriptor, absent.execution_started_at)
    present = _replace_script(state, absent, MacosExecScript.from_runtime_record(record))
    result = prepare_runtime_es_exec_script(state, content.registry, process=present)
    assert result.path == descriptor.native_path
    assert result.path != present.image
    assert present.executable_version == actor.executable_version
    replacement = replace(descriptor, content_version=2, artifact_version=2)
    _publish(content, replacement, present.execution_started_at + timedelta(seconds=1))
    assert prepare_runtime_es_exec_script(state, content.registry, process=present) == result
    with pytest.raises(ValueError, match="exact file"):
        es_script_at_execution(present, content.build_record(replacement))
    with pytest.raises(ValueError, match="absence"):
        es_script_at_execution(absent, record)
    with pytest.raises(ValueError, match="known execution"):
        es_script_at_execution(actor, record)


def test_script_survives_fork_failed_exec_and_checkpoint_then_exec_resets_unknown() -> None:
    state, content, actor, _ = _setup()
    descriptor, record = _script(content, actor.hostname)
    _publish(content, descriptor, actor.execution_started_at)
    actor = _replace_script(state, actor, MacosExecScript.from_runtime_record(record))
    builder = state.begin_action_cohort_materialization()
    child = builder.fork_process(actor, forked_at=actor.execution_started_at + timedelta(seconds=1))
    state.materialize_action_cohort(builder.seal())
    assert child.identity.exec_script == actor.exec_script
    record_failed_process_exec(
        state,
        actor=child.identity,
        attempted_at=child.identity.started_at + timedelta(seconds=1),
        image="/usr/bin/missing",
        command_line="missing",
        error_number=2,
    )
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    assert (
        restored.get_process_identity(child.identity.hostname, child.identity.pid) == child.identity
    )
    assert (
        prepare_runtime_es_exec_script(restored, content.registry, process=child.identity).path
        == descriptor.native_path
    )
    after = _replace_script(restored, child.identity, None, seconds=3)
    assert after.exec_script is None
    assert (
        restored.get_process_identity_at(
            actor.hostname, child.identity.pid, child.identity.started_at
        ).exec_script
        == actor.exec_script
    )
    with pytest.raises(StateError, match="live Mac"):
        prepare_runtime_es_exec_script(restored, content.registry, process=child.identity)


@pytest.mark.parametrize("damage", ["host", "content", "version", "path", "missing_stat"])
def test_script_projection_rejects_foreign_or_incomplete_facts(damage: str) -> None:
    state, content, actor, _ = _setup()
    _, record = _script(content, actor.hostname)
    actor = _replace_script(state, actor, MacosExecScript.from_runtime_record(record))
    if damage == "missing_stat":
        record = replace(record, macos_file=None)
    else:
        field = {
            "host": "hostname",
            "content": "content_id",
            "version": "artifact_version_id",
            "path": "native_path",
        }[damage]
        script = replace(actor.exec_script, **{field: "/wrong" if damage == "path" else "wrong"})
        if damage == "host":
            with pytest.raises(ValueError, match="another host"):
                replace(actor, exec_script=script)
            return
        actor = replace(actor, exec_script=script)
    with pytest.raises(ValueError):
        es_script_at_execution(actor, record)


def test_checkpoint_old_records_do_not_infer_script_and_reject_coercion() -> None:
    state, content, actor, _ = _setup()
    _, record = _script(content, actor.hostname)
    actor = _replace_script(state, actor, MacosExecScript.from_runtime_record(record))
    for value, tag, width in (
        (actor, "process-identity-v13", 26),
        (state.get_process(actor.hostname, actor.pid), "running-process-v20", 44),
    ):
        encoded = encode_state_value(value)
        assert decode_state_value(["record", tag, encoded[2][:width]]).exec_script is None
        with pytest.raises(CheckpointCorruptionError):
            decode_state_value(["record", tag, encoded[2]])
    encoded = encode_state_value(actor.exec_script)
    encoded[2][1] = b"wrong"
    with pytest.raises(CheckpointCorruptionError):
        decode_state_value(encoded)


def test_foreign_platform_and_native_binary_cannot_supply_script_reference() -> None:
    state, content, actor, _ = _setup()
    with pytest.raises(ValueError, match="distinct"):
        MacosExecScript.from_runtime_record(
            content.build_record(replace(_executable(), hostname=actor.hostname))
        )
    with pytest.raises(ValueError, match="macOS"):
        state.plan_process_materialization(
            system="LINUX-SCRIPT",
            parent_pid=0,
            image="/bin/sh",
            command_line="sh script",
            username="casey",
            integrity_level="Medium",
            os_category="linux",
            exec_script=MacosExecScript(),
        )


def test_script_replacement_is_authenticated_and_provisional_rollback_preserves_old_facts() -> None:
    state, content, actor, _ = _setup()
    _, record = _script(content, actor.hostname)
    builder = state.begin_action_cohort_materialization()
    after = builder.execute_process(
        actor,
        image=actor.image,
        command_line=actor.command_line,
        executed_at=actor.execution_started_at + timedelta(seconds=1),
        executable_version=actor.executable_version,
        exec_script=MacosExecScript.from_runtime_record(record),
    )
    plan = builder.seal()
    before = state.materialization_digest()
    with state.prepared_action_cohort_materialization(plan) as prepared:
        prepared.certify_composite_commit(prepared.expected_result)
        prepared.apply_provisional()
        assert (
            state.get_process_identity(after.hostname, after.pid).exec_script == after.exec_script
        )
    assert state.materialization_digest() == before
    forged = replace(
        plan,
        _process_executions=(
            replace(
                plan.process_executions[0], after=replace(after, exec_script=MacosExecScript())
            ),
        ),
    )
    with pytest.raises(StateError):
        state.materialize_action_cohort(forged)
    assert state.materialization_digest() == before
    state.materialize_action_cohort(plan)
    assert state.get_process_identity(after.hostname, after.pid).exec_script == after.exec_script


@pytest.mark.parametrize("damage", ["host", "platform"])
def test_invalid_script_checkpoint_cannot_publish(damage: str) -> None:
    state, content, actor, _ = _setup()
    _, record = _script(content, actor.hostname)
    script = MacosExecScript.from_runtime_record(record)
    row = state.get_process(actor.hostname, actor.pid)
    row.exec_script = replace(script, hostname="FOREIGN") if damage == "host" else script
    if damage == "platform":
        state._pid_os[actor.hostname] = "linux"
    restored = StateManager()
    before = restored.materialization_digest()
    with pytest.raises(CheckpointCorruptionError):
        _restore_head(restored, _capture_head(state))
    assert restored.materialization_digest() == before


def test_script_cannot_be_its_own_loaded_interpreter_and_retained_registry_recovers() -> None:
    from evidenceforge.events.process_executable import ProcessExecutableVersion
    from evidenceforge.generation.checkpoints.artifact_registry_head import (
        LocalArtifactVersionRegistryParticipant,
    )
    from tests.unit.test_macos_launch_file import _manager

    state, content, actor, _ = _setup()
    descriptor, record = _script(content, actor.hostname)
    _publish(content, descriptor, actor.execution_started_at)
    actor = _replace_script(state, actor, MacosExecScript.from_runtime_record(record))
    with pytest.raises(ValueError, match="distinct file"):
        replace(
            actor,
            executable_version=ProcessExecutableVersion(
                "macos",
                "local_artifact",
                actor.exec_script.content_id,
                actor.exec_script.artifact_version_id,
            ),
        )
    expected = prepare_runtime_es_exec_script(state, content.registry, process=actor)
    fresh = StateManager()
    _restore_head(fresh, _capture_head(state))
    participant = LocalArtifactVersionRegistryParticipant(content.registry)
    seal = participant.prepare_checkpoint(1)
    fresh_content = _manager()
    LocalArtifactVersionRegistryParticipant(fresh_content.registry).restore_checkpoint(
        seal.head.payload, ()
    )
    assert prepare_runtime_es_exec_script(fresh, fresh_content.registry, process=actor) == expected
    with pytest.raises(StateError, match="exact file"):
        prepare_runtime_es_exec_script(fresh, _manager().registry, process=actor)


@pytest.mark.slow
def test_script_reference_and_native_file_are_fresh_process_deterministic() -> None:
    import os
    import subprocess
    import sys

    script = """
import json
from tests.unit.test_macos_runtime_es_preparation import _setup, _publish
from tests.unit.test_macos_exec_script import _script, _replace_script
from evidenceforge.events.macos_exec_script import MacosExecScript
from evidenceforge.generation.macos_endpoint_security import prepare_runtime_es_exec_script
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.checkpoints.state_values import encode_state_value
state, content, actor, _ = _setup()
descriptor, record = _script(content, actor.hostname)
_publish(content, descriptor, actor.execution_started_at)
actor = _replace_script(state, actor, MacosExecScript.from_runtime_record(record))
fresh = StateManager()
_restore_head(fresh, _capture_head(state))
results = []
for manager in (state, fresh):
    identity = manager.get_process_identity(actor.hostname, actor.pid)
    native = prepare_runtime_es_exec_script(manager, content.registry, process=identity)
    results.append([encode_state_value(identity), native.model_dump(mode='json')])
assert results[0] == results[1]
print(json.dumps(results[0], sort_keys=True))
"""
    results: list[str] = []
    for seed in ("17", "983"):
        run = subprocess.run(
            [sys.executable, "-c", script],
            env=os.environ | {"PYTHONHASHSEED": seed},
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert run.returncode == 0, run.stdout + run.stderr
        results.append(run.stdout)
    assert results[0] == results[1]
