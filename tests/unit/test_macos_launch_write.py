# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Canonical Mac definition writes compose through process-owned file effects."""

from dataclasses import replace
from datetime import timedelta
from unittest.mock import Mock, patch

import pytest

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.dispatcher import EventDispatcher, PreparedDispatch
from evidenceforge.generation.actions.command_effects import FileEffectAction
from evidenceforge.generation.actions.macos_launch_item import macos_system_job_write_effect
from evidenceforge.generation.actions.process_execution import (
    ProcessExecutionActionBundle,
    ProcessExecutionRequest,
)
from evidenceforge.generation.actions.process_support.preflight import ProcessPreflightPlanner
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.deployment_registry import (
    LocalArtifactPreparedGroupCommit,
    LocalArtifactPublishToken,
)
from evidenceforge.generation.runtime_content import RuntimeContentIdentityManager
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.exceptions import EventContractError, StateError
from evidenceforge.models.scenario import User
from tests.unit.test_generator_endpoint_effect_integration import _events, _NoAmbientEffectsRandom
from tests.unit.test_macos_foundations import _TIME, _seed_launchd, _system
from tests.unit.test_macos_launch_file import _manager, _spec

_PATH = "/Library/LaunchDaemons/org.example.worker.plist"


def _publication(
    manager: RuntimeContentIdentityManager, **changes: object
) -> LocalArtifactPublishToken:
    values = dict(
        root_action_id="provision-worker",
        stable_source_id="worker-job-definition",
        hostname="MAC-TEST",
        principal="root",
        platform="macos",
        architecture="arm64",
        native_path=_PATH,
        action="create",
        observed_at=_TIME + timedelta(seconds=5),
        owner_kind="system",
        authored_size_bytes=512,
        authored_mime_type="application/xml",
        launchd_job=_spec(),
    )
    token = manager.prepare_effect_publication(**(values | changes))
    assert token is not None
    return token


def _writer(
    collected: bool = True,
) -> tuple[
    ActivityGenerator, StateManager, Mock, RuntimeContentIdentityManager, ProcessExecutionRequest
]:
    state = StateManager()
    _seed_launchd(state)
    state.set_current_time(_TIME)
    manager = _manager()
    emitter = Mock()
    emitters = {"ecar": emitter} if collected else {}
    dispatcher = EventDispatcher(state, emitters, local_artifact_registry=manager.registry)
    generator = ActivityGenerator(
        state, emitters, dispatcher=dispatcher, runtime_content_manager=manager
    )
    token = _publication(manager)
    effect = macos_system_job_write_effect(
        publication=token,
        action=FileEffectAction.CREATE,
        instance_key="job-file",
        retention_deadline=_TIME + timedelta(hours=1),
    )
    user = User(username="root", full_name="Fixture Administrator", email="root@example.test")
    request = ProcessExecutionRequest(
        user=user,
        system=_system(),
        time=_TIME,
        logon_id="0x0",
        process_name="/usr/local/libexec/provisioner",
        command_line="/usr/local/libexec/provisioner --job worker",
        parent_pid=1,
        require_exact_parent=True,
        from_storyline=True,
        suppress_command_file_effect=True,
        requested_endpoint_effects=(effect,),
    )
    return generator, state, emitter, manager, request


@pytest.mark.parametrize("collected", [True, False])
def test_job_write_uses_shared_file_effect_and_does_not_register_or_activate(
    collected: bool,
) -> None:
    generator, state, emitter, manager, request = _writer(collected)
    with patch.object(
        ProcessPreflightPlanner,
        "_process_endpoint_effect_rng",
        return_value=_NoAmbientEffectsRandom(),
    ):
        pid = ProcessExecutionActionBundle(generator, request).execute()
    record = manager.resolve_record("MAC-TEST", "root", _PATH, "macos")
    assert record is not None and record.launchd_job == _spec()
    assert record.content.seed_ref == _spec().content_seed
    assert record.binary is None
    assert manager.registry.census().prepared_publications == 0
    assert state.get_process("MAC-TEST", pid).image == request.process_name
    assert not any(process.image == _spec().program for process in state.list_running_processes())
    if collected:
        files = [event for event in _events(emitter) if event.file and event.file.path == _PATH]
        assert len(files) == 1
        event = files[0]
        assert event.event_type == "file_create"
        assert event.identity_plan.actor_id == state.get_process_identity("MAC-TEST", pid).object_id
        assert event.file.artifact_identity == record.artifact
        assert event.file.content_identity == record.content
        assert (
            event.effect_provenance.root_action_id
            == ProcessExecutionActionBundle(generator, request).anchor.action_id
        )
    else:
        emitter.emit.assert_not_called()


@pytest.mark.parametrize(
    "changes",
    [
        {"platform": "linux"},
        {"action": "delete"},
        {"action": "read"},
        {"executable": True},
        {"authored_content_seed_ref": "unrelated-content"},
    ],
)
def test_job_metadata_rejects_incompatible_file_effects_before_reserving(
    changes: dict[str, object],
) -> None:
    manager = _manager()
    with pytest.raises(ValueError, match="launchd"):
        _publication(manager, **changes)
    assert manager.registry.census().prepared_publications == 0


def test_modify_effect_preserves_explicit_version_and_job_definition() -> None:
    manager = _manager()
    token = _publication(manager, action="modify", content_version=2, artifact_version=2)
    effect = macos_system_job_write_effect(
        publication=token,
        action=FileEffectAction.MODIFY,
        instance_key="replace-job",
        retention_deadline=_TIME + timedelta(hours=1),
    )
    assert effect.event_type == "file_modify"
    assert effect.payload.artifact_publication is token
    assert token.record.artifact.version == 2 and token.record.content.version == 2
    assert effect.spec.retention_deadline == _TIME + timedelta(hours=1)
    manager.registry.cancel_prepared(token)


def test_remove_cannot_masquerade_as_a_definition_write() -> None:
    manager = _manager()
    token = _publication(manager)
    with pytest.raises(ValueError, match="create or modify"):
        macos_system_job_write_effect(
            publication=token,
            action=FileEffectAction.DELETE,
            instance_key="delete-job",
            retention_deadline=_TIME + timedelta(hours=1),
        )
    manager.registry.cancel_prepared(token)


@pytest.mark.parametrize("fault", ["required-file", "artifact-commit"])
def test_failed_job_write_leaves_no_partial_process_or_file_and_retry_succeeds(fault: str) -> None:
    generator, state, emitter, manager, request = _writer()
    before = state.materialization_digest()
    original_prepare = generator.dispatcher.prepare_builder

    def prepare(builder: OccurrenceBuilder, **kwargs: object) -> PreparedDispatch:
        if builder.file is not None and builder.file.path == _PATH:
            raise EventContractError("injected job file preparation failure")
        return original_prepare(builder, **kwargs)

    failure = (
        patch.object(generator.dispatcher, "prepare_builder", prepare)
        if fault == "required-file"
        else patch.object(
            LocalArtifactPreparedGroupCommit,
            "commit_no_fail",
            side_effect=StateError("injected job artifact failure"),
        )
    )
    with (
        failure,
        patch.object(
            ProcessPreflightPlanner,
            "_process_endpoint_effect_rng",
            return_value=_NoAmbientEffectsRandom(),
        ),
        pytest.raises((EventContractError, StateError), match="injected job"),
    ):
        ProcessExecutionActionBundle(generator, request).execute()
    assert state.materialization_digest() == before
    assert manager.resolve_record("MAC-TEST", "root", _PATH, "macos") is None
    assert manager.registry.census().prepared_publications == 0
    assert manager.registry.census().live_versions == 0
    emitter.emit.assert_not_called()
    effect = macos_system_job_write_effect(
        publication=_publication(manager),
        action=FileEffectAction.CREATE,
        instance_key="job-file",
        retention_deadline=_TIME + timedelta(hours=1),
    )
    request = replace(request, requested_endpoint_effects=(effect,))
    with patch.object(
        ProcessPreflightPlanner,
        "_process_endpoint_effect_rng",
        return_value=_NoAmbientEffectsRandom(),
    ):
        pid = ProcessExecutionActionBundle(generator, request).execute()
    assert pid > 0
    assert manager.resolve_record("MAC-TEST", "root", _PATH, "macos").launchd_job == _spec()
    assert (
        len([event for event in _events(emitter) if event.file and event.file.path == _PATH]) == 1
    )


def test_write_cannot_claim_retention_beyond_reserved_file_lifetime() -> None:
    manager = _manager()
    token = _publication(manager)
    with pytest.raises(ValueError, match="reserved file lifetime"):
        macos_system_job_write_effect(
            publication=token,
            action=FileEffectAction.CREATE,
            instance_key="job-file",
            retention_deadline=token.retained_until + timedelta(seconds=1),
        )
    manager.registry.cancel_prepared(token)
