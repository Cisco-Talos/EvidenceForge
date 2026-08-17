# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for engine-owned runtime file/content identity preparation."""

from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.events.content_identity import (
    UserProfileIdentity,
)
from evidenceforge.generation.actions.command_effects import (
    ExecutionEffectPlanError,
    FileEffectAction,
)
from evidenceforge.generation.actions.endpoint_effects import PreparedFileEffectPayload
from evidenceforge.generation.deployment_registry import (
    DeploymentContentRegistry,
    HostDeploymentSpec,
    LocalArtifactRegistryCensus,
    LocalArtifactVersionRegistry,
)
from evidenceforge.generation.runtime_content import (
    RuntimeArtifactDescriptor,
    RuntimeContentIdentityManager,
    RuntimeContentOwnerError,
)


def _descriptor(
    *,
    hostname: str = "WS-01",
    principal: str = "alice",
    native_path: str = r"C:\Windows\Temp\mimikatz.exe",
) -> RuntimeArtifactDescriptor:
    return RuntimeArtifactDescriptor(
        hostname=hostname,
        principal=principal,
        platform="windows",
        user_profile_id=f"profile:{hostname}:{principal}",
        application_profile_id=f"runtime-files:{hostname}:{principal}",
        application_id="runtime-filesystem",
        family="dropped-executable",
        source_object_id="storyline:credential-dump:payload",
        native_path=native_path,
        file_object_id="attack-payload:mimikatz",
        content_version=1,
        artifact_version=1,
        size_bytes=1_327_104,
        mime_type="application/vnd.microsoft.portable-executable",
        seed_ref="attack-payload:mimikatz:v1",
        executable=True,
        architecture="x64",
    )


def test_runtime_content_is_path_independent_but_local_artifact_is_not() -> None:
    """One modeled payload shares hashes while each placement has its own artifact ID."""

    first = RuntimeContentIdentityManager.build_record(_descriptor())
    second = RuntimeContentIdentityManager.build_record(
        _descriptor(
            hostname="WS-02",
            principal="bob",
            native_path=r"C:\Users\bob\Downloads\renamed.exe",
        )
    )

    assert first.content.content_id == second.content.content_id
    assert first.content.digests == second.content.digests
    assert first.artifact.artifact_id != second.artifact.artifact_id
    assert first.artifact.artifact_version_id != second.artifact.artifact_version_id
    assert first.binary is not None and second.binary is not None
    assert first.binary.digests == second.binary.digests


def test_runtime_manager_prepares_coupled_commit_and_exact_lease() -> None:
    """The manager delegates one invisible token and retains it only through its lease."""

    start = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
    registry = LocalArtifactVersionRegistry(capacity=4, retention=timedelta(hours=1))
    manager = RuntimeContentIdentityManager(registry)
    descriptor = _descriptor()
    token = manager.prepare_publication(
        descriptor,
        start,
        lease_owner="process:4242",
        lease_until=start + timedelta(hours=2),
    )

    assert manager.census().live_versions == 0
    with registry.prepared_publication(token) as publication:
        publication.commit()

    record = manager.resolve_record(
        descriptor.hostname,
        descriptor.principal,
        descriptor.native_path,
        descriptor.platform,
    )
    assert record == token.record
    assert manager.census().active_leases == 1
    assert manager.advance_watermark(start + timedelta(hours=1)) == ()
    assert registry.release_lease(record.artifact.artifact_version_id, "process:4242")
    assert manager.census().live_versions == 0


def test_prepared_file_payload_binds_exact_runtime_artifact_token() -> None:
    """A file mutation carries its typed token without exposing it through repr."""

    start = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
    registry = LocalArtifactVersionRegistry(capacity=4)
    token = RuntimeContentIdentityManager(registry).prepare_publication(
        _descriptor(),
        start,
    )

    payload = PreparedFileEffectPayload(
        path=_descriptor().native_path.lower(),
        action=FileEffectAction.CREATE,
        artifact_publication=token,
    )
    assert payload.artifact_publication is token
    assert "artifact_publication" not in repr(payload)
    with pytest.raises(ExecutionEffectPlanError, match="path drifted"):
        PreparedFileEffectPayload(
            path=r"C:\Windows\Temp\other.exe",
            action=FileEffectAction.CREATE,
            artifact_publication=token,
        )
    with pytest.raises(ExecutionEffectPlanError, match="only file create/modify"):
        PreparedFileEffectPayload(
            path=_descriptor().native_path,
            action=FileEffectAction.READ,
            artifact_publication=token,
        )
    assert registry.cancel_prepared(token)


def test_effect_publication_centralizes_profile_content_and_unknown_size_policy() -> None:
    """Runtime effects share path-free content while retaining exact local ownership."""

    start = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
    profiles = (
        UserProfileIdentity("WS-01", "alice", "windows"),
        UserProfileIdentity("WS-02", "alice", "windows"),
    )
    deployment = DeploymentContentRegistry(user_profiles=profiles)
    registry = LocalArtifactVersionRegistry(capacity=4)
    manager = RuntimeContentIdentityManager(registry)
    common = {
        "root_action_id": "process-action-1",
        "stable_source_id": "authored-payload:mimikatz:v1",
        "principal": "alice",
        "platform": "windows",
        "architecture": "x64",
        "action": "create",
        "observed_at": start,
        "owner_kind": "user",
        "deployment_registry": deployment,
        "executable": True,
    }
    first = manager.prepare_effect_publication(
        **common,
        hostname="WS-01",
        native_path=r"C:\Windows\Temp\mimikatz.exe",
    )
    second = manager.prepare_effect_publication(
        **common,
        hostname="WS-02",
        native_path=r"C:\Users\alice\Downloads\renamed.exe",
    )

    assert first is not None and second is not None
    assert first.record.content.content_id == second.record.content.content_id
    assert first.record.content.digests == second.record.content.digests
    assert first.record.artifact.artifact_id != second.record.artifact.artifact_id
    assert first.record.content.size_bytes == 0
    assert first.record.content.mime_type == "application/vnd.microsoft.portable-executable"
    assert first.record.binary is not None
    assert first.record.binary.pe_version_info is None
    assert first.record.artifact.user_profile_id == profiles[0].profile_id
    assert registry.cancel_prepared(first)
    assert registry.cancel_prepared(second)


def test_effect_publication_rejects_uncompiled_user_and_skips_nonmutating_actions() -> None:
    """User artifacts fail closed at ownership lookup; reads allocate no registry state."""

    start = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
    registry = LocalArtifactVersionRegistry(capacity=2)
    manager = RuntimeContentIdentityManager(registry)
    values = {
        "root_action_id": "process-action-2",
        "stable_source_id": "payload-2",
        "hostname": "WS-01",
        "principal": "alice",
        "platform": "windows",
        "architecture": "x64",
        "native_path": r"C:\Temp\payload.bin",
        "observed_at": start,
        "owner_kind": "user",
        "deployment_registry": DeploymentContentRegistry(),
    }
    with pytest.raises(RuntimeContentOwnerError, match="exact compiled host/principal profile"):
        manager.prepare_effect_publication(**values, action="create")
    assert manager.prepare_effect_publication(**values, action="read") is None
    census = registry.census()
    assert census.live_versions == census.prepared_publications == census.reserved_slots == 0


def test_runtime_executable_uses_exact_compiler_resolved_host_architecture() -> None:
    """An omitted authored architecture resolves from host deployment truth once."""

    profile = UserProfileIdentity("WS-01", "alice", "windows")
    deployment = DeploymentContentRegistry(
        user_profiles=(profile,),
        host_deployments=(
            HostDeploymentSpec(
                hostname="WS-01",
                roles=("workstation",),
                platform="windows",
                os_build="22621.3155",
                architecture="x64",
            ),
        ),
    )
    registry = LocalArtifactVersionRegistry(capacity=2)
    token = RuntimeContentIdentityManager(registry).prepare_effect_publication(
        root_action_id="process-action-arch",
        stable_source_id="payload-arch",
        hostname="WS-01",
        principal="alice",
        platform="windows",
        architecture=None,
        native_path=r"C:\Temp\payload.exe",
        action="create",
        observed_at=datetime(2026, 8, 16, 12, 0, tzinfo=UTC),
        owner_kind="user",
        deployment_registry=deployment,
        executable=True,
    )

    assert token is not None
    assert deployment.host_architecture("WS-01") == "x64"
    assert token.record.binary is not None
    assert token.record.binary.architecture == "x64"
    assert registry.cancel_prepared(token)


def test_runtime_executable_requires_explicit_architecture() -> None:
    """The manager never guesses architecture from an .exe suffix."""

    values = {
        field_name: getattr(_descriptor(), field_name)
        for field_name in RuntimeArtifactDescriptor.__dataclass_fields__
    }
    values["architecture"] = None

    with pytest.raises(ValueError, match="explicit architecture"):
        RuntimeArtifactDescriptor(**values)


def test_effect_publication_requires_authored_or_compiled_host_architecture() -> None:
    """Executable admission reports a typed actor error when host truth is absent."""

    with pytest.raises(RuntimeContentOwnerError, match="compiler-resolved architecture"):
        RuntimeContentIdentityManager(
            LocalArtifactVersionRegistry(capacity=2)
        ).prepare_effect_publication(
            root_action_id="process-action-no-arch",
            stable_source_id="payload-no-arch",
            hostname="WS-01",
            principal="SYSTEM",
            platform="windows",
            architecture=None,
            native_path=r"C:\Temp\payload.exe",
            action="create",
            observed_at=datetime(2026, 8, 16, 12, 0, tzinfo=UTC),
            owner_kind="system",
            deployment_registry=DeploymentContentRegistry(),
            executable=True,
        )


def _runtime_artifact_plateau_census(days: int) -> LocalArtifactRegistryCensus:
    """Return the exact retained census after a fixed-rate runtime-artifact window."""

    start = datetime(2026, 8, 1, tzinfo=UTC)
    registry = LocalArtifactVersionRegistry(
        capacity=128,
        retention=timedelta(hours=48),
    )
    manager = RuntimeContentIdentityManager(registry)
    for hour in range(days * 24):
        observed_at = start + timedelta(hours=hour)
        descriptor = _descriptor(
            native_path=rf"C:\Windows\Temp\drop-{hour:04d}.exe",
        )
        descriptor = RuntimeArtifactDescriptor(
            **{
                field_name: (
                    f"attack-payload:drop-{hour:04d}"
                    if field_name in {"file_object_id", "seed_ref", "source_object_id"}
                    else getattr(descriptor, field_name)
                )
                for field_name in RuntimeArtifactDescriptor.__dataclass_fields__
            }
        )
        registry.publish_version(manager.build_record(descriptor), observed_at)
        manager.advance_watermark(observed_at)

    return manager.census(estimate_bytes=True)


@pytest.mark.parametrize("days", [1, 7, 30])
def test_runtime_artifact_registry_plateaus_across_long_windows(days: int) -> None:
    """Hourly runtime versions plateau at the retention horizon, not scenario duration."""

    census = _runtime_artifact_plateau_census(days)
    assert 0 < census.live_versions <= min(days * 24, 48)
    assert census.backing_slots <= census.capacity == 128
    assert census.prepared_publications == 0
    assert census.reserved_slots == 0
    assert census.estimated_bytes > 0


def test_runtime_artifact_registry_week_to_month_retained_state_is_flat() -> None:
    """Seven- and thirty-day windows plateau in live rows and retained memory."""

    week = _runtime_artifact_plateau_census(7)
    month = _runtime_artifact_plateau_census(30)

    assert month.live_versions == week.live_versions
    assert week.backing_slots <= month.backing_slots <= month.capacity
    assert month.high_water_mark == week.high_water_mark
    assert month.estimated_bytes <= int(week.estimated_bytes * 1.10)
    assert month.estimated_index_bytes <= int(week.estimated_index_bytes * 1.10)
