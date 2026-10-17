# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Registration is distinct from process activation, removal and re-registration."""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from evidenceforge.events.content_identity import RuntimeServiceDeploymentIdentity
from evidenceforge.events.macos_launchd import LaunchdSystemJobDefinition, LaunchdSystemJobSpec
from evidenceforge.generation.actions.macos_launch_item import (
    macos_system_job_bootstrap_plan,
    macos_system_job_content_seed,
    macos_system_job_deployment_identity,
)
from evidenceforge.generation.checkpoints.lifecycle_head import _capture, _restore
from evidenceforge.generation.deployment_registry import (
    DeploymentContentRegistry,
    HostDeploymentSpec,
    LocalArtifactVersionRegistry,
)
from evidenceforge.generation.lifecycle_production_adapters import (
    LifecycleProductionAdapter,
    ServiceLifecyclePublicationPlan,
)
from evidenceforge.generation.lifecycle_registry import (
    LifecycleRegistry,
    LifecycleServiceProcessClosureRequest,
)
from evidenceforge.generation.runtime_content import (
    RuntimeArtifactDescriptor,
    RuntimeContentIdentityManager,
)
from evidenceforge.models.exceptions import StateError
from tests.unit.test_lifecycle_service_preparation import _control, _publish

_START = datetime(2026, 10, 19, 12, tzinfo=UTC)


def _deployments(platform: str = "macos", architecture: str = "arm64") -> DeploymentContentRegistry:
    return DeploymentContentRegistry(
        host_deployments=(
            HostDeploymentSpec(
                hostname="MAC-A",
                roles=("workstation",),
                platform=platform,
                os_build="26.0",
                architecture=architecture,
            ),
        ),
    )


def _plan(
    label: str = "org.example.agent", action: str = "register-1", **changes: Any
) -> ServiceLifecyclePublicationPlan:
    values: dict[str, Any] = dict(
        deployment_registry=_deployments(),
        hostname="MAC-A",
        label=label,
        boot_time=_START - timedelta(hours=1),
        bootstrapped_at=_START,
        action_id=action,
    )
    values.update(changes)
    values.setdefault(
        "deployment_identity",
        macos_system_job_deployment_identity(
            deployment_registry=values["deployment_registry"],
            hostname=values["hostname"],
            label=values["label"],
            installation_action_id="installation-1",
        ),
    )
    runtime = values.setdefault(
        "runtime_content", RuntimeContentIdentityManager(LocalArtifactVersionRegistry(capacity=8))
    )
    if "definition" not in values:
        values["definition"] = _definition(runtime, values["deployment_identity"], label=label)
    return macos_system_job_bootstrap_plan(**values)


def _definition(
    runtime: RuntimeContentIdentityManager,
    installation: RuntimeServiceDeploymentIdentity,
    *,
    label: str = "org.example.agent",
    version: int = 1,
    program: str = "/usr/local/libexec/example-agent",
    run_at_load: bool = False,
) -> LaunchdSystemJobDefinition:
    spec = LaunchdSystemJobSpec(
        label=label,
        program=program,
        arguments=(program, "--worker"),
        principal="root",
        run_at_load=run_at_load,
    )
    descriptor = RuntimeArtifactDescriptor(
        hostname=installation.hostname,
        principal="root",
        platform="macos",
        user_profile_id="system:root",
        application_profile_id="runtime:launchd",
        application_id="runtime-filesystem",
        family="launchd-definition",
        source_object_id="invented-plist",
        native_path=f"/Library/LaunchDaemons/{label}.plist",
        file_object_id="invented-plist",
        content_version=version,
        artifact_version=version,
        size_bytes=512,
        mime_type="application/xml",
        seed_ref=macos_system_job_content_seed(spec),
    )
    token = runtime.prepare_publication(descriptor, _START - timedelta(minutes=1))
    with runtime.registry.prepared_publication(token) as prepared:
        prepared.commit()
    return LaunchdSystemJobDefinition(
        **spec.model_dump(), installation=installation, plist=token.record.artifact
    )


def test_registration_is_dormant_and_roundtrips_existing_checkpoint_contract() -> None:
    registry = LifecycleRegistry(shard_count=8)
    plan = _plan()
    assert not plan.process_bindings and not plan.staged_process_bindings
    assert registry.get_service_instance(plan.instance_identity.object_id) is None
    receipt = _publish(LifecycleProductionAdapter(registry), plan)
    assert receipt.service.identity == plan.instance_identity
    assert not receipt.bindings
    del receipt
    restored = LifecycleRegistry(shard_count=8)
    _restore(restored, _capture(registry))
    snapshot = restored.get_service_instance(plan.instance_identity.object_id)
    assert snapshot == registry.get_service_instance(plan.instance_identity.object_id)
    assert snapshot.logical_identity.canonical_name == "system/org.example.agent"
    assert _deployments().admits_service_deployment_identity(
        snapshot.identity.launchd_job.installation
    )


def test_exact_labels_and_hosts_have_distinct_logical_keys() -> None:
    assert (
        _plan().instance_identity.object_id == _plan(hostname="mac-a").instance_identity.object_id
    )
    assert (
        _plan().logical_identity.logical_service_id
        != _plan("org.example.Agent").logical_identity.logical_service_id
    )
    assert (
        _plan().logical_identity.logical_service_id
        != _plan("org.example.agent2").logical_identity.logical_service_id
    )
    assert (
        _plan().logical_identity.logical_service_id
        == _plan(action="register-2").logical_identity.logical_service_id
    )
    assert _plan().instance_identity != _plan(action="register-2").instance_identity


def test_unload_dormant_registration_then_register_new_instance() -> None:
    registry = LifecycleRegistry(shard_count=8)
    adapter = LifecycleProductionAdapter(registry)
    first = _plan()
    _publish(adapter, first)
    second = _plan(action="register-2", bootstrapped_at=_START + timedelta(minutes=2))
    with pytest.raises(StateError, match="overlap"):
        adapter.prepare_service_publication(second)
    close_at = _START + timedelta(minutes=1)
    request = LifecycleServiceProcessClosureRequest(
        binding_closures=(),
        service_closures=(_control("service", first.instance_identity.object_id, at=close_at),),
    )
    token = adapter.prepare_service_process_closure(request)
    with adapter.claimed_service_process_closure(token) as prepared:
        receipt = prepared.commit_no_fail()
    assert receipt.services[0].closed_at == close_at
    _publish(adapter, second)
    assert registry.get_service_instance(second.instance_identity.object_id).closed_at is None
    assert registry.get_service_instance(first.instance_identity.object_id).closed_at == close_at


@pytest.mark.parametrize(
    "label", ["", " space", "space ", "bad/label", "bad\nlabel", "bad\x7flabel"]
)
def test_ambiguous_targets_are_rejected(label: str) -> None:
    with pytest.raises(ValueError, match="label"):
        _plan(label)


@pytest.mark.parametrize(
    "platform,architecture", [("windows", "arm64"), ("linux", "arm64"), ("macos", "x64")]
)
def test_other_platforms_and_architectures_are_not_relabelled(
    platform: str, architecture: str
) -> None:
    with pytest.raises(ValueError, match="compiled arm64 Mac"):
        _plan(deployment_registry=_deployments(platform, architecture))


def test_unknown_host_and_preboot_registration_fail_before_publication() -> None:
    with pytest.raises(ValueError, match="compiled arm64 Mac"):
        _plan(hostname="missing")
    with pytest.raises(ValueError, match="precede"):
        _plan(bootstrapped_at=_START - timedelta(hours=2))


def test_wrong_label_installation_is_rejected_before_registration() -> None:
    installation = macos_system_job_deployment_identity(
        deployment_registry=_deployments(),
        hostname="MAC-A",
        label="org.example.other",
        installation_action_id="installation-1",
    )
    with pytest.raises(ValueError, match="exact label"):
        _plan(deployment_identity=installation)


@pytest.mark.parametrize("action", ["", " ambiguous", "ambiguous "])
def test_registration_action_must_be_exact(action: str) -> None:
    with pytest.raises(ValueError, match="exact action"):
        _plan(action=action)


def test_new_boot_gets_a_new_registration_instance_but_retains_installation() -> None:
    first = _plan()
    second = _plan(boot_time=_START)
    assert first.logical_identity == second.logical_identity
    assert first.instance_identity.boot_id != second.instance_identity.boot_id
    assert first.instance_identity.object_id != second.instance_identity.object_id


def test_registration_publication_retries_without_duplicate_state() -> None:
    registry = LifecycleRegistry(shard_count=8)
    adapter = LifecycleProductionAdapter(registry)
    plan = _plan()
    first = _publish(adapter, plan)
    second = _publish(adapter, plan)
    assert first.service == second.service
    assert registry.get_service_instance(plan.instance_identity.object_id) == first.service


def test_activation_is_a_separate_binding_and_prevents_premature_unload() -> None:
    from evidenceforge.events.lifecycle import (
        LifecycleMembership,
        ProcessLifecycleIdentity,
        ProcessTokenIdentity,
        ServiceProcessBindingIdentity,
    )

    registry = LifecycleRegistry(shard_count=8)
    adapter = LifecycleProductionAdapter(registry)
    plan = _plan()
    _publish(adapter, plan)
    at = _START + timedelta(seconds=1)
    process = ProcessLifecycleIdentity(
        hostname="MAC-A",
        object_id="invented-job-process",
        pid=700,
        started_at=at,
        image="/usr/local/libexec/example-agent",
        role="service_host",
    )
    registry.register_process(
        process,
        token=ProcessTokenIdentity(principal="root", logon_id=""),
        membership=LifecycleMembership(
            owner_kind="boot", owner_object_id=plan.instance_identity.boot_id
        ),
        action_id="activate-1",
        transition_id="activate-1-process-start",
    )
    binding = ServiceProcessBindingIdentity(
        binding_id="invented-job-binding",
        service_object_id=plan.instance_identity.object_id,
        process_object_id=process.object_id,
        bound_at=at,
        role="service_host",
        action_id="activate-1",
    )
    registry.bind_service_process(binding)
    with pytest.raises(StateError, match="every active process binding"):
        adapter.prepare_service_process_closure(
            LifecycleServiceProcessClosureRequest(
                binding_closures=(),
                service_closures=(
                    _control(
                        "service", plan.instance_identity.object_id, at=at + timedelta(seconds=1)
                    ),
                ),
            )
        )
    assert registry.get_service_instance(plan.instance_identity.object_id).closed_at is None
    assert registry.get_process(process.object_id).closed_at is None


def test_replacement_plist_and_installation_do_not_mutate_loaded_definition() -> None:
    runtime = RuntimeContentIdentityManager(LocalArtifactVersionRegistry(capacity=8))
    registry = LifecycleRegistry(shard_count=8)
    adapter = LifecycleProductionAdapter(registry)
    first = _plan(runtime_content=runtime)
    _publish(adapter, first)
    installed = macos_system_job_deployment_identity(
        deployment_registry=_deployments(),
        hostname="MAC-A",
        label="org.example.agent",
        installation_action_id="installation-2",
    )
    definition = _definition(runtime, installed, version=2, program="/usr/local/libexec/new-agent")
    second = _plan(
        action="register-2",
        runtime_content=runtime,
        definition=definition,
        deployment_identity=installed,
        bootstrapped_at=_START + timedelta(minutes=2),
    )
    assert second.logical_identity == first.logical_identity
    assert (
        registry.get_service_instance(first.instance_identity.object_id).identity
        == first.instance_identity
    )
    with pytest.raises(StateError, match="overlap"):
        adapter.prepare_service_publication(second)
    with pytest.raises(ValueError, match="current canonical plist"):
        _plan(runtime_content=runtime, definition=first.instance_identity.launchd_job)
    request = LifecycleServiceProcessClosureRequest(
        binding_closures=(),
        service_closures=(
            _control(
                "service", first.instance_identity.object_id, at=_START + timedelta(minutes=1)
            ),
        ),
    )
    token = adapter.prepare_service_process_closure(request)
    with adapter.claimed_service_process_closure(token) as prepared:
        prepared.commit_no_fail()
    del prepared
    _publish(adapter, second)
    restored = LifecycleRegistry(shard_count=8)
    _restore(restored, _capture(registry))
    assert (
        restored.get_service_instance(first.instance_identity.object_id).identity
        == first.instance_identity
    )
    assert (
        restored.get_service_instance(second.instance_identity.object_id).identity
        == second.instance_identity
    )


def test_definition_cannot_claim_different_program_for_the_same_content() -> None:
    runtime = RuntimeContentIdentityManager(LocalArtifactVersionRegistry(capacity=8))
    plan = _plan(runtime_content=runtime)
    loaded = plan.instance_identity.launchd_job
    forged = LaunchdSystemJobDefinition(
        **{name: getattr(loaded, name) for name in LaunchdSystemJobDefinition.model_fields}
        | {"program": "/bin/sh", "arguments": ("sh", "-c", "true")}
    )
    with pytest.raises(ValueError, match="current canonical plist"):
        _plan(runtime_content=runtime, definition=forged)


def test_file_expiry_does_not_unload_a_bootstrapped_job() -> None:
    runtime = RuntimeContentIdentityManager(
        LocalArtifactVersionRegistry(capacity=8, retention=timedelta(minutes=5))
    )
    plan = _plan(runtime_content=runtime)
    registry = LifecycleRegistry(shard_count=8)
    _publish(LifecycleProductionAdapter(registry), plan)
    runtime.advance_watermark(_START + timedelta(hours=1))
    assert runtime.census().live_versions == 0
    assert (
        registry.get_service_instance(plan.instance_identity.object_id).identity
        == plan.instance_identity
    )
    with pytest.raises(ValueError, match="current canonical plist"):
        _plan(runtime_content=runtime, definition=plan.instance_identity.launchd_job)


@pytest.mark.parametrize(
    "changes",
    [
        {"program": "relative"},
        {"arguments": ()},
        {"arguments": ("",)},
        {"arguments": ("agent", "bad\x00arg")},
        {"principal": " root"},
        {"run_at_load": "false"},
        {"keep_alive": True},
        {"sockets": {}},
    ],
)
def test_definition_rejects_unsupported_or_ambiguous_semantics(changes: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        LaunchdSystemJobSpec(
            **{
                "label": "org.example.agent",
                "program": "/usr/local/libexec/agent",
                "arguments": ("agent",),
                "principal": "root",
            }
            | changes
        )


def test_run_at_load_records_intent_without_implying_activation() -> None:
    from dataclasses import replace

    runtime = RuntimeContentIdentityManager(LocalArtifactVersionRegistry(capacity=8))
    plan = _plan(runtime_content=runtime)
    job = plan.instance_identity.launchd_job
    definition = _definition(runtime, job.installation, version=2, run_at_load=True)
    active_intent = _plan(runtime_content=runtime, definition=definition)
    assert active_intent.instance_identity.launchd_job.run_at_load
    assert not active_intent.process_bindings and not active_intent.staged_process_bindings
    assert macos_system_job_content_seed(definition) != macos_system_job_content_seed(job)
    with pytest.raises(StateError, match="loaded job definition"):
        LifecycleProductionAdapter(LifecycleRegistry(shard_count=8)).prepare_service_publication(
            replace(plan, instance_identity=replace(plan.instance_identity, launchd_job=None))
        )
