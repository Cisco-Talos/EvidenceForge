# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.events.identity import ProcessIdentity
from evidenceforge.events.process_executable import ProcessExecutableVersion
from evidenceforge.generation.checkpoints.errors import CheckpointCorruptionError
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.checkpoints.state_values import decode_state_value, encode_state_value
from evidenceforge.generation.lifecycle_authority import _process_identity_payload
from evidenceforge.generation.state_manager import StateManager
from tests.unit.test_macos_runtime_file_metadata import _executable, _manager
from tests.unit.test_process_execution_state import _START


def _version(number: int = 1) -> ProcessExecutableVersion:
    record = _manager().build_record(
        replace(_executable(), content_version=number, artifact_version=number)
    )
    return ProcessExecutableVersion.from_binary(record.binary)


def _create(version: ProcessExecutableVersion | None) -> tuple[StateManager, ProcessIdentity]:
    state = StateManager()
    state.set_current_time(_START)
    plan = state.plan_process_materialization(
        system="MAC-EXEC",
        parent_pid=0,
        image="/usr/local/libexec/invented-worker",
        command_line="invented-worker",
        username="root",
        integrity_level="System",
        os_category="macos",
        executable_version=version,
    )
    state.materialize_process(plan)
    return state, plan.identity


def test_fork_inherits_loaded_version_exec_replaces_it_and_omission_is_unknown() -> None:
    state, original = _create(_version())
    builder = state.begin_action_cohort_materialization()
    child = builder.fork_process(original, forked_at=_START + timedelta(seconds=1))
    state.materialize_action_cohort(builder.seal())
    assert child.identity.executable_version == original.executable_version
    builder = state.begin_action_cohort_materialization()
    after = builder.execute_process(
        child.identity,
        image=child.identity.image,
        command_line=child.identity.command_line,
        executed_at=_START + timedelta(seconds=2),
        executable_version=_version(2),
    )
    plan = builder.seal()
    before = state.materialization_digest()
    with state.prepared_action_cohort_materialization(plan) as prepared:
        prepared.certify_composite_commit(prepared.expected_result)
        prepared.apply_provisional()
        assert state.get_process_identity(after.hostname, after.pid).executable_version == _version(
            2
        )
    assert state.materialization_digest() == before
    state.materialize_action_cohort(plan)
    builder = state.begin_action_cohort_materialization()
    unknown = builder.execute_process(
        after,
        image=after.image,
        command_line=after.command_line,
        executed_at=_START + timedelta(seconds=3),
    )
    state.materialize_action_cohort(builder.seal())
    restored = StateManager()
    _restore_head(restored, _capture_head(state))
    assert unknown.executable_version is None
    assert restored.get_process_identity_at(
        after.hostname, after.pid, after.execution_started_at
    ).executable_version == _version(2)
    assert (
        restored.get_process_identity_at(
            child.identity.hostname, child.identity.pid, child.identity.started_at
        ).executable_version
        == _version()
    )
    assert _process_identity_payload(original) != _process_identity_payload(
        replace(original, executable_version=None)
    )


def test_old_codec_records_migrate_without_guessing_a_loaded_image() -> None:
    state, identity = _create(_version())
    for value, tag, width in [
        (identity, "process-identity-v11", 24),
        (state.get_process(identity.hostname, identity.pid), "running-process-v16", 40),
    ]:
        fields = encode_state_value(value)[2]
        assert decode_state_value(["record", tag, fields[:width]]).executable_version is None
        with pytest.raises(CheckpointCorruptionError):
            decode_state_value(["record", tag, fields])


def test_foreign_version_cannot_launch_or_restore() -> None:
    with pytest.raises(ValueError, match="platform"):
        _create(replace(_version(), platform="linux"))
    state, identity = _create(_version())
    state.get_process(identity.hostname, identity.pid).executable_version = replace(
        _version(), platform="linux"
    )
    restored = StateManager()
    before = restored.materialization_digest()
    with pytest.raises(CheckpointCorruptionError, match="executable version"):
        _restore_head(restored, _capture_head(state))
    assert restored.materialization_digest() == before


@pytest.mark.parametrize(
    "changes",
    [
        dict(content_id=""),
        dict(content_id=True),
        dict(artifact_version_id=None),
        dict(identity_kind="installed_release"),
        dict(platform="unknown"),
    ],
)
def test_incomplete_or_coerced_version_references_are_rejected(changes: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        replace(_version(), **changes)


def test_full_native_snapshot_cannot_substitute_a_new_version_at_the_same_path() -> None:
    from evidenceforge.formats.macos_process_snapshot import es_process_from_observations
    from tests.unit.test_macos_process_snapshot import _inputs

    relationships, collection, context, original = _inputs()
    replacement = _manager().build_record(
        replace(
            _executable(),
            hostname=collection.process.hostname,
            content_version=2,
            artifact_version=2,
        )
    )
    context.binary_identity = replacement.binary
    assert replacement.artifact.native_path == original.artifact.native_path
    with pytest.raises(ValueError, match="exact executable version"):
        es_process_from_observations(relationships, collection, context, replacement, version=10)
    context.binary_identity = original.binary
    assert (
        es_process_from_observations(
            relationships, collection, context, original, version=10
        ).executable.path
        == original.artifact.native_path
    )


@pytest.mark.parametrize("collect", [False, True])
def test_production_process_launch_retains_the_exact_runtime_image_version(
    tmp_path: Path, collect: bool
) -> None:
    from evidenceforge.events.dispatcher import EventDispatcher
    from evidenceforge.formats.loader import load_format
    from evidenceforge.generation.activity import ActivityGenerator
    from evidenceforge.generation.emitters.ecar import EcarEmitter
    from tests.unit.test_macos_foundations import _TIME, _seed_launchd, _system, _user
    from tests.unit.test_macos_launch_file import _publish

    state = StateManager()
    _seed_launchd(state)
    manager = _manager()
    descriptor = replace(_executable(), hostname="MAC-TEST", principal="alex")
    _publish(manager, descriptor)
    record = manager.build_record(descriptor)
    emitter = EcarEmitter(load_format("ecar"), tmp_path / "ecar.json")
    emitters = {"ecar": emitter} if collect else {}
    dispatcher = EventDispatcher(state, emitters, local_artifact_registry=manager.registry)
    generator = ActivityGenerator(state, emitters, dispatcher=dispatcher)
    try:
        user, system = _user(), _system()
        logon = generator.generate_logon(user, system, _TIME)
        pid = generator.generate_process(
            user,
            system,
            _TIME + timedelta(seconds=30),
            logon,
            descriptor.native_path,
            "invented-worker",
            parent_pid=1,
        )
        identity = state.get_process_identity(system.hostname, pid)
        assert identity.executable_version == ProcessExecutableVersion.from_binary(record.binary)
        # Later placement replacement cannot rewrite the already loaded version.
        _publish(manager, replace(descriptor, content_version=2, artifact_version=2))
        assert (
            state.get_process_identity(system.hostname, pid).executable_version
            == identity.executable_version
        )
    finally:
        emitter.close()
