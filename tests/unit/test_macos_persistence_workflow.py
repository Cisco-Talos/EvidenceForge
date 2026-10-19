# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

from datetime import timedelta
from unittest.mock import Mock

import pytest

from evidenceforge.events.contexts import HostContext
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.events.identity import PosixProcessCredentials
from evidenceforge.events.macos_launchd_spec import LaunchdSystemJobSpec
from evidenceforge.generation.actions.command_effects import ExecutionEffectAuditCounter
from evidenceforge.generation.actions.macos_persistence import (
    MacosPersistenceActionBundle,
    MacosPersistenceRequest,
)
from evidenceforge.generation.lifecycle_shadow import LifecycleShadow
from evidenceforge.generation.state_manager import ProcessMaterializationPlan
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_launch_activation import _setup
from tests.unit.test_macos_launch_file import _manager
from tests.unit.test_macos_launch_registration import _START, _deployments


def _workflow(
    collect: bool = True,
) -> tuple[
    MacosPersistenceActionBundle,
    ProcessMaterializationPlan,
    HostContext,
    LaunchdSystemJobSpec,
    str,
    Mock,
]:
    manager = _manager()
    state, registry, authority, _, _ = _setup(manager, known_boot_group=True)
    plan = state.plan_process_materialization(
        system="MAC-A",
        parent_pid=1,
        image="/usr/local/libexec/invented-provisioner",
        command_line="invented-provisioner",
        username="root",
        integrity_level="System",
        os_category="macos",
        credentials=PosixProcessCredentials(0, 0, 0, 0),
        start_time=_START,
    )
    authority.materialize_process(plan)
    emitter = Mock()
    dispatcher = EventDispatcher(
        state,
        {"ecar": emitter} if collect else {},
        lifecycle_shadow=LifecycleShadow(state, registry),
        enforce_lifecycle_authority=True,
        local_artifact_registry=manager.registry,
    )
    dispatcher.bind_lifecycle_authority(authority)
    dispatcher.bind_execution_effect_audit(ExecutionEffectAuditCounter())
    bundle = MacosPersistenceActionBundle(
        state=state,
        lifecycle=registry,
        authority=authority,
        dispatcher=dispatcher,
        deployments=_deployments(),
        content=manager,
    )
    host = HostContext(
        hostname="MAC-A",
        ip="192.0.2.25",
        os="macOS 26",
        os_category="macos",
        system_type="workstation",
    )
    definition = LaunchdSystemJobSpec(
        label="org.example.workflow",
        program="/usr/local/libexec/invented-worker",
        arguments=("invented-worker",),
        principal="root",
    )
    path = "/Library/LaunchDaemons/org.example.workflow.plist"
    return bundle, plan, host, definition, path, emitter


@pytest.mark.parametrize("collect", [True, False])
def test_distinct_workflow_stages_preserve_loaded_definition_after_removal(collect: bool) -> None:
    bundle, plan, host, definition, path, emitter = _workflow(collect)
    for index, operation in enumerate(
        ("write", "bootstrap", "remove", "activate", "exit", "activate", "unload"), 1
    ):
        result = bundle.execute(
            MacosPersistenceRequest(
                caller=plan.identity,
                host=host,
                timestamp=_START + timedelta(seconds=index),
                action_id=f"workflow-{index}",
                operation=operation,
                label=definition.label,
                path=path if operation in {"write", "bootstrap", "remove"} else None,
                definition=definition if operation == "write" else None,
                size_bytes=512 if operation == "write" else None,
                exit_code=0 if operation == "exit" else None,
            )
        )
        if operation == "activate":
            assert result.process is not None
            assert (
                bundle.state.get_process_identity_by_object_id(result.process.object_id)
                == result.process
            )
        if operation == "remove":
            assert bundle.content.resolve_record("MAC-A", "root", path, "macos") is None
    assert bundle.state.get_process_identity_by_object_id(plan.identity.object_id) == plan.identity
    assert not any(
        process.image == definition.program for process in bundle.state.list_running_processes()
    )


def _request(
    bundle: MacosPersistenceActionBundle,
    plan: ProcessMaterializationPlan,
    host: HostContext,
    definition: LaunchdSystemJobSpec,
    path: str,
    operation: str,
    index: int,
) -> MacosPersistenceRequest:
    return MacosPersistenceRequest(
        caller=plan.identity,
        host=host,
        timestamp=_START + timedelta(seconds=index),
        action_id=f"stage-{index}",
        operation=operation,
        label=definition.label,
        path=path if operation in {"write", "bootstrap", "remove"} else None,
        definition=definition if operation == "write" else None,
        size_bytes=512 if operation == "write" else None,
    )


def test_write_preflight_failure_releases_reserved_file_and_preserves_caller(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle, plan, host, definition, path, emitter = _workflow()
    before = bundle.state.get_process_identity_by_object_id(plan.identity.object_id)

    def reject(*args: object, **kwargs: object) -> None:
        raise StateError("injected source preflight failure")

    monkeypatch.setattr(bundle.dispatcher, "prepare_builder", reject)
    with pytest.raises(StateError, match="injected"):
        bundle.execute(_request(bundle, plan, host, definition, path, "write", 1))
    assert bundle.content.resolve_record("MAC-A", "root", path, "macos") is None
    assert bundle.state.get_process_identity_by_object_id(plan.identity.object_id) == before
    emitter.emit.assert_not_called()
    monkeypatch.undo()
    bundle.execute(_request(bundle, plan, host, definition, path, "write", 1))
    assert bundle.content.resolve_record("MAC-A", "root", path, "macos") is not None


def test_activation_precommit_failure_keeps_registration_dormant_and_retryable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from dataclasses import replace

    from tests.unit.test_macos_runtime_es_preparation import _publish
    from tests.unit.test_macos_runtime_file_metadata import _executable

    bundle, plan, host, definition, path, emitter = _workflow()
    bundle.dispatcher.output_end_time = _START + timedelta(days=7)
    _publish(bundle.content, replace(_executable(), hostname=host.hostname), _START)
    for index, operation in enumerate(("write", "bootstrap"), 1):
        bundle.execute(_request(bundle, plan, host, definition, path, operation, index))
    before = tuple(bundle.state.list_running_processes())

    def reject() -> None:
        raise StateError("injected lifecycle precommit failure")

    monkeypatch.setattr(bundle.authority, "_materialization_precommit_hook", reject)
    with pytest.raises(StateError, match="injected"):
        bundle.execute(_request(bundle, plan, host, definition, path, "activate", 3))
    assert tuple(bundle.state.list_running_processes()) == before
    assert bundle.content.registry.census().active_leases == 0
    assert bundle.content.registry.census().prepared_publications == 0
    monkeypatch.undo()
    process = bundle.execute(_request(bundle, plan, host, definition, path, "activate", 3))
    assert process.process is not None
    assert bundle.content.registry.census().active_leases == 1
    bundle.execute(_request(bundle, plan, host, definition, path, "unload", 4))


def test_dormant_unload_never_creates_a_job_process() -> None:
    bundle, plan, host, definition, path, emitter = _workflow()
    before = tuple(bundle.state.list_running_processes())
    for index, operation in enumerate(("write", "bootstrap", "unload", "remove"), 1):
        bundle.execute(_request(bundle, plan, host, definition, path, operation, index))
    assert tuple(bundle.state.list_running_processes()) == before


def test_foreign_or_stale_caller_rejected_before_file_publication() -> None:
    bundle, plan, host, definition, path, emitter = _workflow()
    host.hostname = "FOREIGN-MAC"
    with pytest.raises(StateError, match="exact live Mac root"):
        bundle.execute(_request(bundle, plan, host, definition, path, "write", 1))
    assert bundle.content.resolve_record("MAC-A", "root", path, "macos") is None


@pytest.mark.parametrize(
    "operation", ["write", "bootstrap", "activate", "exit", "unload", "remove"]
)
def test_retained_exited_caller_cannot_authorize_any_stage(operation: str) -> None:
    bundle, plan, host, definition, path, _ = _workflow()
    builder = bundle.state.begin_action_cohort_materialization()
    builder.terminate_process(plan.identity, end_time=_START + timedelta(seconds=1))
    bundle.state.materialize_action_cohort(builder.seal())
    assert bundle.state.get_process_identity(plan.identity.hostname, plan.identity.pid) is not None
    with pytest.raises(StateError, match="exact live Mac root"):
        bundle.execute(_request(bundle, plan, host, definition, path, operation, 2))


@pytest.mark.parametrize("collect", [True, False])
def test_job_activation_binds_the_current_image_but_retains_earlier_execution_version(
    collect: bool,
) -> None:
    from dataclasses import replace

    from evidenceforge.events.process_executable import ProcessExecutableVersion
    from evidenceforge.generation.checkpoints.state_manager_head import _capture_head, _restore_head
    from evidenceforge.generation.state_manager import StateManager
    from tests.unit.test_macos_runtime_es_preparation import _publish
    from tests.unit.test_macos_runtime_file_metadata import _executable

    bundle, plan, host, definition, path, _ = _workflow(collect)
    bundle.dispatcher.output_end_time = _START + timedelta(days=7)
    descriptor = replace(_executable(), hostname=host.hostname, principal="root")
    assert descriptor.native_path == definition.program
    _publish(bundle.content, descriptor, _START)
    first = bundle.content.build_record(descriptor)
    for index, operation in enumerate(("write", "bootstrap", "activate"), 1):
        result = bundle.execute(_request(bundle, plan, host, definition, path, operation, index))
    identity = result.process
    assert identity.executable_version == ProcessExecutableVersion.from_binary(first.binary)
    replacement = replace(descriptor, artifact_version=2, content_version=2)
    _publish(bundle.content, replacement, _START + timedelta(seconds=4))
    assert (
        bundle.state.get_process_identity(host.hostname, identity.pid).executable_version
        == identity.executable_version
    )
    restored = StateManager()
    _restore_head(restored, _capture_head(bundle.state))
    assert (
        restored.get_process_identity(host.hostname, identity.pid).executable_version
        == identity.executable_version
    )
    bundle.execute(_request(bundle, plan, host, definition, path, "exit", 5))
    restarted = bundle.execute(
        _request(bundle, plan, host, definition, path, "activate", 6)
    ).process
    assert restarted.executable_version == ProcessExecutableVersion.from_binary(
        bundle.content.build_record(replacement).binary
    )
    assert restarted.executable_version != identity.executable_version
    assert (
        bundle.state.get_process_identity_by_object_id(identity.object_id).executable_version
        == identity.executable_version
    )
    bundle.execute(_request(bundle, plan, host, definition, path, "unload", 7))
    bundle.content.registry.advance_watermark(_START + timedelta(days=5))
    assert bundle.content.registry.resolve_version(first.artifact.artifact_version_id) == first
    assert bundle.content.registry.census().active_leases == 2


@pytest.mark.parametrize("finite", [False, True])
def test_activation_without_future_finite_window_does_not_overflow_retention(
    monkeypatch: pytest.MonkeyPatch, finite: bool
) -> None:
    from dataclasses import replace
    from datetime import datetime

    from evidenceforge.generation.deployment_registry import LocalArtifactVersionRegistry
    from tests.unit.test_macos_runtime_es_preparation import _publish
    from tests.unit.test_macos_runtime_file_metadata import _executable

    bundle, plan, host, definition, path, _ = _workflow(False)
    bundle.dispatcher.output_end_time = (
        _START if finite else datetime.max.replace(tzinfo=_START.tzinfo)
    )
    _publish(
        bundle.content, replace(_executable(), hostname=host.hostname, principal="root"), _START
    )
    for index, operation in enumerate(("write", "bootstrap"), 1):
        bundle.execute(_request(bundle, plan, host, definition, path, operation, index))

    def reject(*args: object, **kwargs: object) -> None:
        raise AssertionError("No finite future retention window was supplied")

    monkeypatch.setattr(LocalArtifactVersionRegistry, "prepare_version_retention", reject)
    result = bundle.execute(_request(bundle, plan, host, definition, path, "activate", 3))
    assert result.process.executable_version is not None


@pytest.mark.parametrize("failure", ["rollback", "lost_acknowledgement"])
def test_activation_image_retention_failure_cannot_allocate_job_or_binding(
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    from dataclasses import replace

    from evidenceforge.generation.deployment_registry import (
        LocalArtifactPreparedCommit,
        LocalArtifactPublicationReceipt,
        LocalArtifactVersionRegistry,
        _LocalArtifactPreparedCommitPlan,
        _LocalArtifactPreparedReservation,
    )
    from tests.unit.test_macos_runtime_es_preparation import _publish
    from tests.unit.test_macos_runtime_file_metadata import _executable

    bundle, caller, host, definition, path, emitter = _workflow()
    bundle.dispatcher.output_end_time = _START + timedelta(days=7)
    descriptor = replace(_executable(), hostname=host.hostname, principal="root")
    _publish(bundle.content, descriptor, _START)
    version = bundle.content.build_record(descriptor).artifact.artifact_version_id
    for index, operation in enumerate(("write", "bootstrap"), 1):
        bundle.execute(_request(bundle, caller, host, definition, path, operation, index))
    state_before = bundle.state.materialization_digest()
    processes_before = tuple(bundle.state.list_running_processes())
    lifecycle_before = bundle.lifecycle.stats()
    leases_before = bundle.content.registry.census().active_leases
    emitted_before = emitter.emit.call_count
    original = LocalArtifactVersionRegistry._commit_prepared_locked

    def fail_image(
        registry: LocalArtifactVersionRegistry,
        reservation: _LocalArtifactPreparedReservation,
        plan: _LocalArtifactPreparedCommitPlan,
    ) -> LocalArtifactPublicationReceipt:
        result = original(registry, reservation, plan)
        if reservation.canonical_token.record.artifact.artifact_version_id == version:
            raise StateError("injected job image retention failure")
        return result

    original_ack = LocalArtifactPreparedCommit.commit_no_fail

    def lose_acknowledgement(
        commit: LocalArtifactPreparedCommit,
    ) -> LocalArtifactPublicationReceipt:
        original_ack(commit)
        raise StateError("injected job image retention acknowledgement failure")

    with monkeypatch.context() as fault:
        if failure == "rollback":
            fault.setattr(LocalArtifactVersionRegistry, "_commit_prepared_locked", fail_image)
        else:
            fault.setattr(LocalArtifactPreparedCommit, "commit_no_fail", lose_acknowledgement)
        with pytest.raises(StateError, match="job image retention"):
            bundle.execute(_request(bundle, caller, host, definition, path, "activate", 3))
    assert bundle.state.materialization_digest() == state_before
    assert tuple(bundle.state.list_running_processes()) == processes_before
    assert (
        replace(
            bundle.lifecycle.stats(),
            lookup_candidates_inspected=lifecycle_before.lookup_candidates_inspected,
        )
        == lifecycle_before
    )
    assert bundle.content.registry.census().active_leases == leases_before + (
        failure == "lost_acknowledgement"
    )
    assert bundle.content.registry.census().prepared_publications == 0
    assert emitter.emit.call_count == emitted_before
    result = bundle.execute(_request(bundle, caller, host, definition, path, "activate", 3))
    assert result.process is not None
    assert bundle.state.get_process_identity(host.hostname, result.process.pid) == result.process
    bundle.execute(_request(bundle, caller, host, definition, path, "unload", 4))


@pytest.mark.parametrize("collect", [False, True])
def test_group_unload_projects_each_descendants_own_integrity(collect: bool) -> None:
    bundle, caller, host, definition, path, emitter = _workflow(collect)
    for index, operation in enumerate(("write", "bootstrap", "activate"), 1):
        result = bundle.execute(_request(bundle, caller, host, definition, path, operation, index))
    parent = result.process
    assert parent is not None
    identities = [parent]
    for index, integrity in enumerate(("High", "Medium"), 4):
        plan = bundle.state.plan_process_materialization(
            system=host.hostname,
            parent_pid=identities[-1].pid,
            image=f"/usr/local/libexec/invented-helper-{index}",
            command_line="invented-helper",
            username="root",
            integrity_level=integrity,
            os_category="macos",
            credentials=PosixProcessCredentials(0, 0, 0, 0),
            start_time=_START + timedelta(seconds=index),
        )
        bundle.authority.materialize_process(plan)
        identities.append(plan.identity)
    if collect:
        emitter.reset_mock()
    closed = bundle.execute(_request(bundle, caller, host, definition, path, "unload", 10))
    assert {identity.object_id for identity in closed.terminated} == {
        identity.object_id for identity in identities
    }
    assert all(
        bundle.state.get_process(host.hostname, identity.pid) is None for identity in identities
    )
    if collect:
        events = [call.args[0] for call in emitter.emit.call_args_list]
        assert [event.process.integrity_level for event in events] == ["Medium", "High", "System"]
