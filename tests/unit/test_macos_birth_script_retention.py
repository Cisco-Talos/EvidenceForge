# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.macos_exec_script import MacosExecScript
from evidenceforge.formats.loader import load_format
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.checkpoints.artifact_registry_head import (
    LocalArtifactVersionRegistryParticipant,
)
from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
from evidenceforge.generation.emitters.ecar import EcarEmitter
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_exec_script import _script
from tests.unit.test_macos_foundations import _TIME, _seed_launchd, _system, _user
from tests.unit.test_macos_runtime_es_preparation import _publish
from tests.unit.test_macos_runtime_file_metadata import _executable, _manager


@pytest.mark.parametrize("collect", [False, True])
def test_birth_retains_explicit_script_and_interpreter_through_replacement_and_restore(
    tmp_path: Path, collect: bool
) -> None:
    state = StateManager()
    _seed_launchd(state)
    content = _manager()
    image = replace(_executable(), hostname="MAC-TEST", principal="alex")
    script, record = _script(content, "MAC-TEST")
    _publish(content, image, _TIME)
    _publish(content, script, _TIME)
    loaded = content.build_record(image)
    emitter = EcarEmitter(load_format("ecar"), tmp_path / "ecar.json")
    emitters = {"ecar": emitter} if collect else {}
    dispatcher = EventDispatcher(
        state,
        emitters,
        local_artifact_registry=content.registry,
        output_end_time=_TIME + timedelta(days=7),
    )
    generator = ActivityGenerator(state, emitters, dispatcher=dispatcher)
    try:
        user, system = _user(), _system()
        logon = generator.generate_logon(user, system, _TIME)
        pid = generator.generate_process(
            user,
            system,
            _TIME + timedelta(seconds=30),
            logon,
            image.native_path,
            "invented-interpreter",
            parent_pid=1,
            require_exact_parent=True,
            suppress_command_file_effect=True,
            exec_script=MacosExecScript.from_runtime_record(record),
        )
        assert pid > 0
        identity = state.get_process_identity(system.hostname, pid)
        assert identity.exec_script == MacosExecScript.from_runtime_record(record)
        assert identity.executable_version.content_id == loaded.content.content_id
        for descriptor in (image, script):
            _publish(
                content,
                replace(descriptor, content_version=2, artifact_version=2),
                _TIME + timedelta(minutes=1),
            )
        assert content.registry.census().active_leases == 2
        recovered = StateManager()
        _restore_head(recovered, _capture_head(state))
        restored = _manager()
        participant = LocalArtifactVersionRegistryParticipant(content.registry)
        LocalArtifactVersionRegistryParticipant(restored.registry).restore_checkpoint(
            participant.prepare_checkpoint(1).head.payload, ()
        )
        restored.registry.advance_watermark(_TIME + timedelta(days=5))
        assert recovered.get_process_identity(system.hostname, pid) == identity
        assert restored.registry.resolve_version(record.artifact.artifact_version_id) == record
        assert restored.registry.resolve_version(loaded.artifact.artifact_version_id) == loaded
    finally:
        emitter.close()


@pytest.mark.parametrize(
    "invalid",
    ["missing", "content", "unbounded", "parent", "plan_failure", "script_commit_failure"],
)
def test_birth_script_admission_failure_does_not_allocate_or_pin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, invalid: str
) -> None:
    state = StateManager()
    _seed_launchd(state)
    content = _manager()
    image = replace(_executable(), hostname="MAC-TEST", principal="alex")
    script, record = _script(content, "MAC-TEST")
    _publish(content, image, _TIME)
    if invalid != "missing":
        _publish(content, script, _TIME)
    dispatcher = EventDispatcher(
        state,
        {},
        local_artifact_registry=content.registry,
        output_end_time=None if invalid == "unbounded" else _TIME + timedelta(days=7),
    )
    generator = ActivityGenerator(state, {}, dispatcher=dispatcher)
    user, system = _user(), _system()
    logon = generator.generate_logon(user, system, _TIME)
    before = state.get_state_summary()
    reference = MacosExecScript.from_runtime_record(record)
    if invalid == "content":
        reference = replace(reference, content_id="foreign-content")
    if invalid == "plan_failure":

        def fail(*args: object, **kwargs: object) -> object:
            raise StateError("injected process planning failure")

        monkeypatch.setattr(StateManager, "begin_action_cohort_materialization", fail)
    if invalid in {"script_commit_failure", "image_commit_failure"}:
        from evidenceforge.generation.deployment_registry import (
            LocalArtifactPublicationReceipt,
            LocalArtifactVersionRegistry,
            _LocalArtifactPreparedCommitPlan,
            _LocalArtifactPreparedReservation,
        )

        original = LocalArtifactVersionRegistry._commit_prepared_locked

        def fail_script(
            registry: LocalArtifactVersionRegistry,
            reservation: _LocalArtifactPreparedReservation,
            plan: _LocalArtifactPreparedCommitPlan,
        ) -> LocalArtifactPublicationReceipt:
            result = original(registry, reservation, plan)
            if reservation.canonical_token.record.artifact.artifact_version_id == (
                reference.artifact_version_id
                if invalid == "script_commit_failure"
                else content.build_record(image).artifact.artifact_version_id
            ):
                raise StateError("injected script commit failure")
            return result

        monkeypatch.setattr(LocalArtifactVersionRegistry, "_commit_prepared_locked", fail_script)
    with pytest.raises((StateError, ValueError)):
        generator.generate_process(
            user,
            system,
            _TIME + timedelta(seconds=30),
            logon,
            image.native_path,
            "invented-interpreter",
            parent_pid=1,
            require_exact_parent=invalid != "parent",
            suppress_command_file_effect=True,
            exec_script=reference,
        )
    assert state.get_state_summary() == before
    assert content.registry.census().active_leases == 0
    assert content.registry.census().prepared_publications == 0


def test_known_absence_needs_no_content_registry_or_horizon() -> None:
    state = StateManager()
    _seed_launchd(state)
    generator = ActivityGenerator(state, {}, dispatcher=EventDispatcher(state, {}))
    user, system = _user(), _system()
    logon = generator.generate_logon(user, system, _TIME)
    pid = generator.generate_process(
        user,
        system,
        _TIME + timedelta(seconds=30),
        logon,
        "/usr/local/bin/invented",
        "invented",
        parent_pid=1,
        require_exact_parent=True,
        suppress_command_file_effect=True,
        exec_script=MacosExecScript(),
    )
    assert state.get_process_identity(system.hostname, pid).exec_script == MacosExecScript()
