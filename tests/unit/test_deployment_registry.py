# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for path-independent content and exact deployment identity indexes."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from threading import Barrier, Event, Lock

import pytest

import evidenceforge.generation.deployment_registry as deployment_registry
from evidenceforge.events.content_identity import (
    ApplicationProfileIdentity,
    BinaryReleaseIdentity,
    BinaryReleaseKey,
    CompiledServiceDeploymentIdentity,
    CompiledTaskDeploymentIdentity,
    FileContentIdentity,
    InstalledSoftwareReleaseIdentity,
    LocalArtifactBinaryIdentity,
    LocalArtifactIdentity,
    LocalArtifactVersionRecord,
    PeVersionInfo,
    RuntimeServiceDeploymentIdentity,
    SoftwareInstallationIdentity,
    UserProfileIdentity,
)
from evidenceforge.generation.deployment_registry import (
    DeploymentContentRegistry,
    HostDeploymentSpec,
    LocalArtifactCapacityError,
    LocalArtifactVersionRegistry,
    UserApplicationAssignmentSpec,
)
from evidenceforge.models.exceptions import StateError
from evidenceforge.utils.rng import generation_seed_scope


def _windows_release(
    *,
    product_id: str = "slack",
    version: str = "4.38.125",
    build: str = "4.38.125.0",
    architecture: str = "x64",
    artifact_name: str = "slack.exe",
    variant: str = "stable",
) -> BinaryReleaseIdentity:
    return BinaryReleaseIdentity(
        key=BinaryReleaseKey(
            product_id=product_id,
            version=version,
            build=build,
            architecture=architecture,  # type: ignore[arg-type]
            platform="windows",
            artifact_name=artifact_name,
            variant=variant,
        ),
        pe_version_info=PeVersionInfo(
            file_version=build,
            description=f"{product_id.title()} executable",
            product=product_id.title(),
            company="Example Software, Inc.",
            original_filename=artifact_name,
        ),
    )


def _user_profile(
    hostname: str,
    principal: str,
    *,
    profile_name: str = "default",
) -> UserProfileIdentity:
    return UserProfileIdentity(
        hostname=hostname,
        principal=principal,
        platform="windows",
        profile_name=profile_name,
        profile_root=rf"C:\Users\{principal}",
    )


def _user_installation(
    release: BinaryReleaseIdentity,
    profile: UserProfileIdentity,
    path: str,
    *,
    application_id: str = "slack",
) -> SoftwareInstallationIdentity:
    return SoftwareInstallationIdentity(
        hostname=profile.hostname,
        application_id=application_id,
        release_id=release.release_id,
        platform="windows",
        scope="user",
        principal=profile.principal,
        user_profile_id=profile.profile_id,
        install_root=path.rsplit("\\", 1)[0],
        image_paths=(path,),
    )


def _application_profile(
    user_profile: UserProfileIdentity,
    installation: SoftwareInstallationIdentity,
    *,
    application_id: str = "slack",
) -> ApplicationProfileIdentity:
    return ApplicationProfileIdentity(
        hostname=user_profile.hostname,
        principal=user_profile.principal,
        platform=user_profile.platform,
        user_profile_id=user_profile.profile_id,
        installation_id=installation.installation_id,
        application_id=application_id,
        profile_root=rf"{user_profile.profile_root}\AppData\Roaming\{application_id}",
    )


def _local_artifact(
    user_profile: UserProfileIdentity,
    application_profile: ApplicationProfileIdentity,
    *,
    source_object_id: str,
    native_name: str,
    version: int = 1,
    content_id: str = "",
) -> LocalArtifactIdentity:
    return LocalArtifactIdentity(
        hostname=user_profile.hostname,
        principal=user_profile.principal,
        platform=user_profile.platform,
        user_profile_id=user_profile.profile_id,
        application_profile_id=application_profile.application_profile_id,
        application_id=application_profile.application_id,
        family="message-cache",
        source_object_id=source_object_id,
        native_path=rf"{application_profile.profile_root}\Cache\{native_name}",
        content_id=content_id,
        version=version,
    )


def _local_artifact_record(
    user_profile: UserProfileIdentity,
    application_profile: ApplicationProfileIdentity,
    *,
    source_object_id: str,
    native_name: str,
    version: int = 1,
) -> LocalArtifactVersionRecord:
    content = FileContentIdentity(
        file_object_id=f"drop:{source_object_id}",
        version=version,
        size_bytes=128_000,
        mime_type="application/vnd.microsoft.portable-executable",
        seed_ref=f"payload:{source_object_id}",
    )
    artifact = _local_artifact(
        user_profile,
        application_profile,
        source_object_id=source_object_id,
        native_name=native_name,
        version=version,
        content_id=content.content_id,
    )
    binary = LocalArtifactBinaryIdentity(
        artifact_version_id=artifact.artifact_version_id,
        content_id=content.content_id,
        digests=content.digests,
        platform=artifact.platform,
        architecture="x64",
        artifact_name=native_name,
    )
    return LocalArtifactVersionRecord(artifact=artifact, content=content, binary=binary)


def test_same_release_has_path_independent_hashes_across_users_and_hosts() -> None:
    """Per-user installation paths must not change one release's bytes."""

    release = _windows_release()
    alice = _user_profile("WS-ALICE", "alice")
    bob = _user_profile("WS-BOB", "bob")
    alice_install = _user_installation(
        release,
        alice,
        r"C:\Users\alice\AppData\Local\slack\app-4.38.125\slack.exe",
    )
    bob_install = _user_installation(
        release,
        bob,
        r"C:\Users\bob\AppData\Local\slack\app-4.38.125\slack.exe",
    )
    registry = DeploymentContentRegistry(
        binary_releases=(release,),
        user_profiles=(alice, bob),
        installations=(alice_install, bob_install),
    )

    alice_binary = registry.resolve_binary(
        "ws-alice",
        r"c:/USERS/ALICE/AppData/Local/Slack/app-4.38.125/SLACK.EXE",
        "windows",
        principal="ALICE",
    )
    bob_binary = registry.resolve_binary(
        "WS-BOB",
        r"C:\Users\bob\AppData\Local\slack\app-4.38.125\slack.exe",
        "windows",
        principal="bob",
    )

    assert alice_install.installation_id != bob_install.installation_id
    assert alice_binary is release
    assert bob_binary is release
    assert alice_binary.content_id == bob_binary.content_id
    assert alice_binary.digests == bob_binary.digests


def test_installed_software_inventory_is_path_free_arch_exact_and_pageable() -> None:
    """Host inventory projects global release descriptors without per-host path copies."""

    neutral = InstalledSoftwareReleaseIdentity(
        product_id="microsoft-update-health-tools",
        name="Microsoft Update Health Tools",
        publisher="Microsoft Corporation",
        version="5.72.0.0",
        build="5.72.0.0",
        architecture="neutral",
        platform="windows",
        scope="machine",
    )
    x64 = InstalledSoftwareReleaseIdentity(
        product_id="7-zip-23-01-x64",
        name="7-Zip 23.01 (x64)",
        publisher="Igor Pavlov",
        version="23.01",
        build="23.01",
        architecture="x64",
        platform="windows",
        scope="machine",
    )
    x86 = InstalledSoftwareReleaseIdentity(
        product_id="legacy-x86-only",
        name="Legacy x86 Only",
        publisher="Example Software",
        version="1.0",
        build="1.0",
        architecture="x86",
        platform="windows",
        scope="machine",
    )
    registry = DeploymentContentRegistry(
        installed_software_releases=(neutral, x64, x86),
        host_deployments=(
            HostDeploymentSpec(
                hostname="WS-01",
                roles=("workstation",),
                platform="windows",
                os_build="10.0.22631.3880",
                architecture="x64",
            ),
        ),
    )

    assert tuple(registry.iter_installed_software_on_host("ws-01")) == (x64, neutral)
    assert registry.count_installed_software_on_host("WS-01") == 2
    assert registry.installed_software_on_host_at("WS-01", 0) is x64
    assert registry.installed_software_on_host_at("WS-01", 1) is neutral
    assert registry.installed_software_on_host_at("WS-01", 2) is None
    with pytest.raises(ValueError, match="ordinal must be non-negative"):
        registry.installed_software_on_host_at("WS-01", -1)
    assert registry.installed_software_for_product("WS-01", x64.product_id) is x64
    assert registry.installed_software_for_product("WS-01", x86.product_id) is None
    first, cursor = registry.page_installed_software_on_host("WS-01", limit=1)
    second, cursor = registry.page_installed_software_on_host(
        "WS-01",
        limit=1,
        cursor=cursor,
    )
    assert first + second == (x64, neutral)
    assert cursor is None
    assert registry.census().installed_software_releases == 3


@pytest.mark.parametrize(
    ("override", "value"),
    [
        ("version", "4.39.0"),
        ("build", "4.38.125.1"),
        ("architecture", "x86"),
        ("variant", "enterprise"),
        ("artifact_name", "slack-helper.exe"),
    ],
)
def test_binary_content_changes_for_every_release_artifact_dimension(
    override: str,
    value: str,
) -> None:
    """Every semantic byte-identity dimension must affect content hashes."""

    baseline = _windows_release()
    kwargs = {override: value}
    changed = _windows_release(**kwargs)  # type: ignore[arg-type]

    assert changed.content_id != baseline.content_id
    assert changed.digests.sha256 != baseline.digests.sha256


def test_binary_identity_is_independent_of_generation_seed() -> None:
    """A named release represents the same bytes in every generated corpus."""

    with generation_seed_scope(101):
        first = _windows_release()
    with generation_seed_scope(202):
        second = _windows_release()

    assert first == second


def test_binary_lookup_is_exact_and_never_falls_back_to_basename() -> None:
    """An uninstalled path must not inherit identity from a matching filename."""

    release = _windows_release()
    profile = _user_profile("WS-01", "alice")
    installation = _user_installation(
        release,
        profile,
        r"C:\Users\alice\AppData\Local\slack\slack.exe",
    )
    registry = DeploymentContentRegistry(
        binary_releases=(release,),
        user_profiles=(profile,),
        installations=(installation,),
    )

    assert (
        registry.resolve_binary(
            "WS-01",
            r"C:\Temp\slack.exe",
            "windows",
            principal="alice",
        )
        is None
    )
    assert (
        registry.installation_for_image(
            "WS-01",
            r"C:\Temp\slack.exe",
            "windows",
            principal="alice",
        )
        is None
    )


def test_compact_binary_path_index_preserves_user_override_then_machine_fallback() -> None:
    """Packed handles must preserve exact per-user precedence without string-tuple keys."""

    machine_release = _windows_release(product_id="slack-machine")
    user_release = _windows_release(product_id="slack-user", variant="user")
    alice = _user_profile("WS-01", "alice")
    shared_path = r"C:\Tools\slack.exe"
    machine_installation = SoftwareInstallationIdentity(
        hostname="WS-01",
        application_id="slack-machine",
        release_id=machine_release.release_id,
        platform="windows",
        scope="machine",
        image_paths=(shared_path,),
    )
    user_installation = _user_installation(
        user_release,
        alice,
        shared_path,
        application_id="slack-user",
    )
    registry = DeploymentContentRegistry(
        binary_releases=(machine_release, user_release),
        user_profiles=(alice,),
        installations=(machine_installation, user_installation),
    )

    assert (
        registry.resolve_binary("WS-01", shared_path, "windows", principal="alice") is user_release
    )
    assert (
        registry.resolve_binary("WS-01", shared_path, "windows", principal="bob") is machine_release
    )
    assert registry.resolve_binary("WS-01", shared_path, "windows") is machine_release
    assert (
        registry.installation_for_image(
            "WS-01",
            shared_path,
            "windows",
            principal="alice",
        )
        == user_installation
    )
    census = registry.binary_path_index_census(estimate_bytes=True)
    assert census.bindings == 2
    assert census.interned_hosts == 1
    assert census.interned_principals == 1
    assert census.interned_native_paths == 1
    assert census.packed_integer_keys == 2
    assert census.packed_integer_targets == 2
    assert census.estimated_bytes > 0


def test_product_installation_index_seals_a_skewed_bucket_once() -> None:
    """Many host/product installations should retain exact insertion order after sealing."""

    release = _windows_release()
    installations = tuple(
        SoftwareInstallationIdentity(
            hostname="WS-01",
            application_id="slack",
            release_id=release.release_id,
            platform="windows",
            scope="machine",
            installation_slot=f"slot-{index:04d}",
            install_root=rf"C:\Program Files\Slack\slot-{index:04d}",
            image_paths=(rf"C:\Program Files\Slack\slot-{index:04d}\slack.exe",),
        )
        for index in range(512)
    )
    registry = DeploymentContentRegistry(
        binary_releases=(release,),
        installations=installations,
    )

    assert registry.installations_for_product("WS-01", "slack") == installations
    assert registry.count_installations_for_product("WS-01", "slack") == len(installations)
    assert tuple(registry.iter_installations_for_product("WS-01", "slack")) == installations
    first_page, cursor = registry.page_installations_for_product(
        "WS-01",
        "slack",
        limit=257,
    )
    second_page, final_cursor = registry.page_installations_for_product(
        "WS-01",
        "slack",
        limit=257,
        cursor=cursor,
    )
    assert first_page == installations[:257]
    assert second_page == installations[257:]
    assert final_cursor is None
    with pytest.raises(ValueError, match="belongs to another query"):
        registry.page_installations_for_product(
            "WS-01",
            "different-product",
            limit=1,
            cursor=cursor,
        )


def test_file_content_is_object_versioned_and_path_free() -> None:
    """Rename is irrelevant while an explicit content-version increment changes bytes."""

    first = FileContentIdentity(
        file_object_id="storage-file-quarterly-report",
        version=1,
        size_bytes=48_512,
        mime_type="application/pdf",
        seed_ref="quarterly-report-payload",
    )
    equivalent = FileContentIdentity(
        file_object_id="storage-file-quarterly-report",
        version=1,
        size_bytes=48_512,
        mime_type="application/pdf",
        seed_ref="quarterly-report-payload",
    )
    copied = FileContentIdentity(
        file_object_id="email-copy-quarterly-report",
        version=1,
        size_bytes=48_512,
        mime_type="application/pdf",
        seed_ref="quarterly-report-payload",
    )
    copied_with_different_classification = FileContentIdentity(
        file_object_id="email-copy-quarterly-report",
        version=1,
        size_bytes=48_512,
        mime_type="application/octet-stream",
        seed_ref="quarterly-report-payload",
    )
    copied_with_different_size = FileContentIdentity(
        file_object_id="download-copy-quarterly-report",
        version=1,
        size_bytes=48_513,
        mime_type="application/pdf",
        seed_ref="quarterly-report-payload",
    )
    updated = FileContentIdentity(
        file_object_id="storage-file-quarterly-report",
        version=2,
        size_bytes=49_104,
        mime_type="application/pdf",
        seed_ref="quarterly-report-payload",
    )
    registry = DeploymentContentRegistry(file_contents=(first, copied, updated))

    assert first == equivalent
    assert first.content_id == equivalent.content_id
    assert first.content_id == copied.content_id
    assert first.content_id == copied_with_different_classification.content_id
    assert first.digests == copied_with_different_classification.digests
    assert first.content_id != updated.content_id
    assert first.digests.sha256 != updated.digests.sha256
    assert registry.file_content(first.file_object_id, 1) is first
    assert registry.file_content(copied.file_object_id, 1) is copied
    assert registry.file_content(first.file_object_id, 2) is updated
    with pytest.raises(ValueError, match="contradictory file size, MIME, or digest"):
        DeploymentContentRegistry(file_contents=(first, copied_with_different_classification))
    with pytest.raises(ValueError, match="contradictory file size, MIME, or digest"):
        DeploymentContentRegistry(file_contents=(first, copied_with_different_size))
    assert not hasattr(first, "path")
    assert not hasattr(first, "payload")


def test_file_content_exact_lookup_does_not_scan_large_registry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contents = tuple(
        FileContentIdentity(
            file_object_id=f"storage-file-{index:05d}",
            version=1,
            size_bytes=4_096 + index,
            mime_type="application/octet-stream",
        )
        for index in range(10_000)
    )
    registry = DeploymentContentRegistry(file_contents=contents)

    def reject_values(_store: object) -> None:
        raise AssertionError("exact file-content lookup scanned registry values")

    monkeypatch.setattr(deployment_registry.CompactIndexedStore, "values", reject_values)

    for index in (0, 4_999, 9_999):
        content = registry.file_content(f"storage-file-{index:05d}", 1)
        assert content is contents[index]
        assert registry.file_content_by_id(content.content_id) is content


def test_packed_immutable_indexes_verify_exact_keys_after_digest_collision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Packed routes must never treat their compact digest as canonical identity."""

    monkeypatch.setattr(deployment_registry, "_packed_index_digest", lambda _key: 7)
    first = FileContentIdentity(
        file_object_id="collision-object-alpha",
        version=1,
        size_bytes=4_096,
        mime_type="application/octet-stream",
    )
    second = FileContentIdentity(
        file_object_id="collision-object-bravo",
        version=2,
        size_bytes=8_192,
        mime_type="application/pdf",
    )

    registry = DeploymentContentRegistry(file_contents=(first, second))

    assert registry.file_content(first.file_object_id, first.version) is first
    assert registry.file_content(second.file_object_id, second.version) is second
    assert registry.file_content_by_id(first.content_id) is first
    assert registry.file_content_by_id(second.content_id) is second


def test_application_profiles_and_local_artifacts_are_scope_isolated() -> None:
    """Shared message content must not collapse independent local cache objects."""

    release = _windows_release()
    shared_content = FileContentIdentity(
        file_object_id="email-attachment-budget",
        version=1,
        size_bytes=15_632,
        mime_type="application/pdf",
        seed_ref="message-attachment-budget",
    )
    alice = _user_profile("WS-ALICE", "alice")
    bob = _user_profile("WS-BOB", "bob")
    alice_install = _user_installation(
        release,
        alice,
        r"C:\Users\alice\AppData\Local\slack\slack.exe",
    )
    bob_install = _user_installation(
        release,
        bob,
        r"C:\Users\bob\AppData\Local\slack\slack.exe",
    )
    alice_app = _application_profile(alice, alice_install)
    bob_app = _application_profile(bob, bob_install)
    alice_artifact = LocalArtifactIdentity(
        hostname=alice.hostname,
        principal=alice.principal,
        platform="windows",
        user_profile_id=alice.profile_id,
        application_profile_id=alice_app.application_profile_id,
        application_id="slack",
        family="message-cache",
        source_object_id="message-123",
        native_path=r"C:\Users\alice\AppData\Roaming\slack\Cache\entry-001",
        content_id=shared_content.content_id,
    )
    bob_artifact = LocalArtifactIdentity(
        hostname=bob.hostname,
        principal=bob.principal,
        platform="windows",
        user_profile_id=bob.profile_id,
        application_profile_id=bob_app.application_profile_id,
        application_id="slack",
        family="message-cache",
        source_object_id="message-123",
        native_path=r"C:\Users\bob\AppData\Roaming\slack\Cache\entry-001",
        content_id=shared_content.content_id,
    )
    registry = DeploymentContentRegistry(
        binary_releases=(release,),
        user_profiles=(alice, bob),
        installations=(alice_install, bob_install),
        application_profiles=(alice_app, bob_app),
        file_contents=(shared_content,),
        local_artifacts=(alice_artifact, bob_artifact),
    )

    assert alice_app.application_profile_id != bob_app.application_profile_id
    assert alice_app.native_profile_token != bob_app.native_profile_token
    assert alice_artifact.artifact_id != bob_artifact.artifact_id
    assert alice_artifact.content_id == bob_artifact.content_id
    assert registry.local_artifact(alice_artifact.artifact_id, 1) is alice_artifact
    assert (
        registry.local_artifact_for_path(
            alice.profile_id,
            alice_app.application_profile_id,
            alice_artifact.native_path.lower(),
            "windows",
            1,
        )
        is alice_artifact
    )


def test_registry_rejects_unknown_content_and_duplicate_path_bindings() -> None:
    """Compile-time referential integrity must fail before ambiguous lookup is possible."""

    release = _windows_release()
    profile = _user_profile("WS-01", "alice")
    installation = _user_installation(
        release,
        profile,
        r"C:\Users\alice\AppData\Local\slack\slack.exe",
    )
    app_profile = _application_profile(profile, installation)
    bad_artifact = LocalArtifactIdentity(
        hostname=profile.hostname,
        principal=profile.principal,
        platform="windows",
        user_profile_id=profile.profile_id,
        application_profile_id=app_profile.application_profile_id,
        application_id="slack",
        family="cache",
        source_object_id="object-1",
        native_path=r"C:\Users\alice\AppData\Local\slack\Cache\one",
        content_id="content-does-not-exist",
    )

    with pytest.raises(ValueError, match="unknown content_id"):
        DeploymentContentRegistry(
            binary_releases=(release,),
            user_profiles=(profile,),
            installations=(installation,),
            application_profiles=(app_profile,),
            local_artifacts=(bad_artifact,),
        )

    other_release = _windows_release(product_id="slack-beta", variant="beta")
    duplicate_path = _user_installation(
        other_release,
        profile,
        installation.image_paths[0],
        application_id="slack-beta",
    )
    with pytest.raises(ValueError, match="duplicate installation path binding"):
        DeploymentContentRegistry(
            binary_releases=(release, other_release),
            user_profiles=(profile,),
            installations=(installation, duplicate_path),
        )


def test_registry_deduplicates_compatible_logical_application_path_bindings() -> None:
    """Two catalog entry points may share one exact physical release and path."""

    release = _windows_release(
        product_id="native.python",
        variant="host-build",
        artifact_name="python.exe",
    )
    profile = _user_profile("WS-01", "alice")
    path = r"C:\Python311\python.exe"
    pytest_installation = _user_installation(
        release,
        profile,
        path,
        application_id="pytest",
    )
    pip_installation = _user_installation(
        release,
        profile,
        path,
        application_id="pip",
    )

    registry = DeploymentContentRegistry(
        binary_releases=(release,),
        user_profiles=(profile,),
        installations=(pip_installation, pytest_installation),
    )

    assert registry.resolve_binary("ws-01", path, "windows", principal="alice") == release
    assert registry.installation_by_id(pip_installation.installation_id) == pip_installation
    assert registry.installation_by_id(pytest_installation.installation_id) == pytest_installation
    assert registry.census().binary_path_bindings == 1


def test_host_deployment_compiles_capabilities_to_compact_handles() -> None:
    """Host deployments should retain handles rather than copying identity inventories."""

    executable = _windows_release()
    module = _windows_release(artifact_name="slack-core.dll")
    profile = _user_profile("WS-01", "alice")
    installation = SoftwareInstallationIdentity(
        hostname=profile.hostname,
        application_id="slack",
        release_id=executable.release_id,
        platform="windows",
        scope="user",
        principal=profile.principal,
        user_profile_id=profile.profile_id,
        image_paths=(
            r"C:\Users\alice\AppData\Local\slack\slack.exe",
            r"C:\Users\alice\AppData\Local\slack\slack-core.dll",
        ),
    )
    app_profile = _application_profile(profile, installation)
    deployment_spec = HostDeploymentSpec(
        hostname="WS-01",
        roles=("workstation", "collaboration-client"),
        platform="windows",
        os_build="22621.3155",
        architecture="x64",
        installation_ids=(installation.installation_id,),
        service_ids=("service:slack-update",),
        task_ids=("task:slack-update",),
        module_content_ids=(module.content_id,),
    )
    registry = DeploymentContentRegistry(
        binary_releases=(executable, module),
        user_profiles=(profile,),
        installations=(installation,),
        application_profiles=(app_profile,),
        host_deployments=(deployment_spec,),
    )

    deployment = registry.host_deployment("ws-01")
    assert deployment is not None
    assert deployment.deployment_id == deployment_spec.deployment_id
    assert deployment.os_build == "22621.3155"
    assert registry.installation_by_handle(deployment.installation_handles[0]) == installation
    assert (
        registry.service_identity_by_handle(deployment.service_handles[0]) == "service:slack-update"
    )
    assert registry.task_identity_by_handle(deployment.task_handles[0]) == "task:slack-update"
    assert registry.module_identity_by_handle(deployment.module_handles[0]) is module
    assert registry.installations_for_product("WS-01", "slack") == (installation,)
    assert registry.installations_for_release("WS-01", executable.release_id) == (installation,)
    assert registry.application_profiles_for_user_profile(profile.profile_id) == (app_profile,)
    assert not hasattr(deployment, "installation_ids")
    assert registry.deployment_census().host_deployments == 1


def test_compiled_service_and_task_views_preserve_exact_compiler_ids() -> None:
    """Typed deployment views must project the exact compiler-owned IDs."""

    spec = HostDeploymentSpec(
        hostname="WS-01",
        roles=("workstation",),
        platform="windows",
        os_build="22621.3155",
        architecture="x64",
        service_ids=("Service:Exact-Spelling",),
        task_ids=("Task:Exact-Spelling",),
    )
    registry = DeploymentContentRegistry(host_deployments=(spec,))

    service = registry.compiled_service_deployment_identity(
        "ws-01",
        "Service:Exact-Spelling",
    )
    task = registry.compiled_task_deployment_identity("ws-01", "Task:Exact-Spelling")

    assert service == CompiledServiceDeploymentIdentity(
        hostname="WS-01",
        service_id="Service:Exact-Spelling",
    )
    assert task == CompiledTaskDeploymentIdentity(
        hostname="WS-01",
        task_id="Task:Exact-Spelling",
    )
    assert service.deployment_service_id == "Service:Exact-Spelling"
    assert task.deployment_task_id == "Task:Exact-Spelling"
    assert service.primitive == (
        "compiled_service",
        "ws-01",
        "Service:Exact-Spelling",
    )
    assert task.primitive == ("compiled_task", "ws-01", "Task:Exact-Spelling")
    assert registry.admits_service_deployment_identity(service)
    assert registry.compiled_service_deployment_identity("ws-02", service.service_id) is None
    assert registry.compiled_task_deployment_identity("ws-02", task.task_id) is None


def test_runtime_service_identity_is_typed_deterministic_and_not_an_action_alias() -> None:
    """Dynamic installs use a runtime-only identity rather than the request ID."""

    registry = DeploymentContentRegistry(
        host_deployments=(
            HostDeploymentSpec(
                hostname="WS-01",
                roles=("workstation",),
                platform="windows",
                os_build="22621.3155",
                architecture="x64",
                service_ids=("preinstalled-service",),
            ),
        ),
    )
    first = registry.runtime_service_deployment_identity(
        hostname="WS-01",
        canonical_name="UpdaterSvc",
        action_id="root-action-123",
    )
    second = registry.runtime_service_deployment_identity(
        hostname="ws-01",
        canonical_name="UpdaterSvc",
        action_id="root-action-123",
    )

    assert (
        first
        == second
        == RuntimeServiceDeploymentIdentity(
            hostname="WS-01",
            canonical_name="UpdaterSvc",
            action_id="root-action-123",
        )
    )
    assert first.canonical_id != first.action_id
    assert first.canonical_id.startswith("runtime-service-deployment-")
    assert first.primitive == (
        "runtime_created_service",
        "ws-01",
        first.canonical_id,
    )
    assert registry.admits_service_deployment_identity(first)


def test_runtime_service_identity_rejects_unknown_hosts_and_compiled_id_collisions() -> None:
    """Prepared runtime service admission must fail before lifecycle publication."""

    candidate = RuntimeServiceDeploymentIdentity(
        hostname="WS-01",
        canonical_name="UpdaterSvc",
        action_id="root-action-123",
    )
    registry = DeploymentContentRegistry(
        host_deployments=(
            HostDeploymentSpec(
                hostname="WS-01",
                roles=("workstation",),
                platform="windows",
                os_build="22621.3155",
                architecture="x64",
                service_ids=(candidate.canonical_id,),
            ),
        ),
    )

    assert not registry.admits_service_deployment_identity(candidate)
    with pytest.raises(ValueError, match="collides with a compiler-owned service ID"):
        registry.runtime_service_deployment_identity(
            hostname="WS-01",
            canonical_name="UpdaterSvc",
            action_id="root-action-123",
        )
    with pytest.raises(ValueError, match="exact compiled host deployment"):
        registry.runtime_service_deployment_identity(
            hostname="WS-02",
            canonical_name="UpdaterSvc",
            action_id="root-action-123",
        )


def test_host_deployment_permutations_compile_to_identical_handle_order() -> None:
    """Set-like spec inputs must not change identity or compiled capability ordering."""

    slack = _windows_release()
    teams = _windows_release(product_id="teams", artifact_name="teams.exe")
    profile = _user_profile("WS-01", "alice")
    slack_install = _user_installation(
        slack,
        profile,
        r"C:\Users\alice\AppData\Local\slack\slack.exe",
    )
    teams_install = _user_installation(
        teams,
        profile,
        r"C:\Users\alice\AppData\Local\teams\teams.exe",
        application_id="teams",
    )
    first = HostDeploymentSpec(
        hostname="WS-01",
        roles=("workstation", "collaboration-client"),
        platform="windows",
        os_build="22621.3155",
        architecture="x64",
        installation_ids=(slack_install.installation_id, teams_install.installation_id),
        service_ids=("service:slack-update", "service:teams-update"),
        task_ids=("task:slack-update", "task:teams-update"),
        module_content_ids=(slack.content_id, teams.content_id),
    )
    permuted = HostDeploymentSpec(
        hostname="WS-01",
        roles=("collaboration-client", "workstation"),
        platform="windows",
        os_build="22621.3155",
        architecture="x64",
        installation_ids=(teams_install.installation_id, slack_install.installation_id),
        service_ids=("service:teams-update", "service:slack-update"),
        task_ids=("task:teams-update", "task:slack-update"),
        module_content_ids=(teams.content_id, slack.content_id),
    )
    registries = tuple(
        DeploymentContentRegistry(
            binary_releases=(slack, teams),
            user_profiles=(profile,),
            installations=(slack_install, teams_install),
            host_deployments=(spec,),
        )
        for spec in (first, permuted)
    )

    assert first == permuted
    assert first.deployment_id == permuted.deployment_id
    assert registries[0].host_deployment("WS-01") == registries[1].host_deployment("WS-01")


def test_host_deployment_rejects_incompatible_installation_and_module_architectures() -> None:
    """Platform equality cannot hide an incompatible binary architecture."""

    arm_release = _windows_release(architecture="arm64")
    profile = _user_profile("WS-01", "alice")
    installation = _user_installation(
        arm_release,
        profile,
        r"C:\Users\alice\AppData\Local\slack\slack.exe",
    )
    installation_spec = HostDeploymentSpec(
        hostname="WS-01",
        roles=("workstation",),
        platform="windows",
        os_build="22621.3155",
        architecture="x64",
        installation_ids=(installation.installation_id,),
    )
    module_spec = HostDeploymentSpec(
        hostname="WS-01",
        roles=("workstation",),
        platform="windows",
        os_build="22621.3155",
        architecture="x64",
        module_content_ids=(arm_release.content_id,),
    )

    with pytest.raises(ValueError, match="installation architecture"):
        DeploymentContentRegistry(
            binary_releases=(arm_release,),
            user_profiles=(profile,),
            installations=(installation,),
            host_deployments=(installation_spec,),
        )
    with pytest.raises(ValueError, match="module architecture"):
        DeploymentContentRegistry(
            binary_releases=(arm_release,),
            host_deployments=(module_spec,),
        )


def test_user_application_assignment_is_one_validated_persona_intersection() -> None:
    """Assignments should reference one installed app, not duplicate the host inventory."""

    release = _windows_release()
    profile = _user_profile("WS-01", "alice")
    installation = _user_installation(
        release,
        profile,
        r"C:\Users\alice\AppData\Local\slack\slack.exe",
    )
    app_profile = _application_profile(profile, installation)
    deployment_spec = HostDeploymentSpec(
        hostname="WS-01",
        roles=("workstation",),
        platform="windows",
        os_build="22621.3155",
        architecture="x64",
        installation_ids=(installation.installation_id,),
    )
    assignment_spec = UserApplicationAssignmentSpec(
        hostname="WS-01",
        principal="ALICE",
        platform="windows",
        user_profile_id=profile.profile_id,
        application_profile_id=app_profile.application_profile_id,
        persona="developer",
        eligible_categories=("collaboration", "user_app"),
        intensity=0.85,
    )
    registry = DeploymentContentRegistry(
        binary_releases=(release,),
        user_profiles=(profile,),
        installations=(installation,),
        application_profiles=(app_profile,),
        host_deployments=(deployment_spec,),
        user_application_assignments=(assignment_spec,),
    )

    assignment = registry.user_application_assignment(assignment_spec.assignment_id)
    assert assignment is not None
    assert assignment.persona == "developer"
    assert assignment.intensity == 0.85
    assert registry.installation_by_handle(assignment.installation_handle) == installation
    assert (
        registry.user_application_assignment_for_profile(
            profile.profile_id,
            app_profile.application_profile_id,
        )
        is assignment
    )
    assert registry.user_application_assignments_for_product("WS-01", "slack") == (assignment,)
    assert registry.user_application_assignments_for_release("WS-01", release.release_id) == (
        assignment,
    )
    assert not hasattr(assignment, "installations")
    assert not hasattr(assignment, "installation_ids")


def test_assignment_category_index_selects_without_profile_bucket_materialization() -> None:
    """Category routing preserves catalog ordinal, weights, pages, and bounded affinity."""

    profile = _user_profile("WS-01", "alice")
    definitions = (
        ("postman", "postman.exe", 60, 0, ("user_app",)),
        ("firefox", "firefox.exe", 10, 1, ("browser", "user_app")),
        ("chrome", "chrome.exe", 30, 2, ("browser", "user_app")),
    )
    releases = tuple(
        _windows_release(
            product_id=application_id,
            artifact_name=artifact_name,
            variant="stable",
        )
        for application_id, artifact_name, _weight, _ordinal, _categories in definitions
    )
    installations = tuple(
        _user_installation(
            release,
            profile,
            rf"C:\Users\alice\AppData\Local\{application_id}\{artifact_name}",
            application_id=application_id,
        )
        for (
            application_id,
            artifact_name,
            _weight,
            _ordinal,
            _categories,
        ), release in zip(definitions, releases, strict=True)
    )
    application_profiles = tuple(
        _application_profile(
            profile,
            installation,
            application_id=application_id,
        )
        for (application_id, _artifact, _weight, _ordinal, _categories), installation in zip(
            definitions,
            installations,
            strict=True,
        )
    )
    assignments = tuple(
        UserApplicationAssignmentSpec(
            hostname=profile.hostname,
            principal=profile.principal,
            platform="windows",
            user_profile_id=profile.profile_id,
            application_profile_id=application_profile.application_profile_id,
            persona="developer",
            eligible_categories=categories,
            intensity=weight / 10,
            selection_weight=weight,
            selection_ordinal=ordinal,
        )
        for (
            _application_id,
            _artifact,
            weight,
            ordinal,
            categories,
        ), application_profile in zip(definitions, application_profiles, strict=True)
    )
    registry = DeploymentContentRegistry(
        binary_releases=releases,
        user_profiles=(profile,),
        installations=installations,
        application_profiles=application_profiles,
        host_deployments=(
            HostDeploymentSpec(
                hostname=profile.hostname,
                roles=("workstation",),
                platform="windows",
                os_build="22621.3155",
                architecture="x64",
                installation_ids=tuple(
                    installation.installation_id for installation in installations
                ),
            ),
        ),
        user_application_assignments=assignments,
    )

    routed = tuple(
        registry.iter_user_application_assignments_for_category(
            profile.profile_id,
            "user_app",
        )
    )
    assert tuple(assignment.application_id for assignment in routed) == (
        "postman",
        "firefox",
        "chrome",
    )
    assert (
        registry.count_user_application_assignments_for_category(
            profile.profile_id,
            "browser",
        )
        == 2
    )
    assert (
        registry.select_user_application_assignment_for_category(
            profile.profile_id,
            "user_app",
            unit_interval=0.0,
        ).application_id
        == "postman"
    )
    assert (
        registry.select_user_application_assignment_for_category(
            profile.profile_id,
            "user_app",
            unit_interval=0.61,
        ).application_id
        == "firefox"
    )
    assert (
        registry.select_user_application_assignment_for_category(
            profile.profile_id,
            "user_app",
            unit_interval=0.99,
        ).application_id
        == "chrome"
    )
    first, cursor = registry.page_user_application_assignments_for_category(
        profile.profile_id,
        "user_app",
        limit=2,
    )
    second, cursor = registry.page_user_application_assignments_for_category(
        profile.profile_id,
        "user_app",
        limit=2,
        cursor=cursor,
    )
    assert first + second == routed
    assert cursor is None
    preferred = registry.preferred_browser_assignment(profile.profile_id)
    assert preferred is not None and preferred.application_id in {"firefox", "chrome"}
    alternative = registry.browser_alternative_assignment_at(
        profile.profile_id,
        preferred.assignment_id,
        0,
    )
    assert alternative is not None
    assert {preferred.application_id, alternative.application_id} == {"firefox", "chrome"}
    assert (
        registry.user_application_assignment_for_application(
            profile.profile_id,
            "POSTMAN",
        )
        is routed[0]
    )
    census = registry.assignment_category_index_census(estimate_bytes=True)
    assert (census.buckets, census.links, census.max_bucket_size) == (2, 5, 3)
    assert census.browser_affinities == census.exact_selection_candidates == 1
    assert census.lookup_candidates_inspected > 0
    assert census.estimated_bytes > 0

    before = registry.scale_census()
    for ordinal in range(30 * 24):
        assert (
            registry.select_user_application_assignment_for_category(
                profile.profile_id,
                "user_app",
                unit_interval=(ordinal % 100) / 100,
            )
            is not None
        )
    after = registry.scale_census()
    assert before.physical_records == after.physical_records == 14
    assert before.live_entries == before.retained_entries == 14
    assert before.stale_entries == before.leased_entries == 0
    assert before.relationship_bindings == 11
    assert before.backing_entries == 25
    assert before.maximum_bucket_size == 3
    assert 0 < before.estimated_index_bytes <= before.estimated_bytes
    assert after.lookup_candidates_inspected == before.lookup_candidates_inspected + 30 * 24
    assert registry.deployment_census().browser_affinities == 1

    draws = tuple((ordinal % 100) / 100 for ordinal in range(128))
    expected = tuple(
        registry.select_user_application_assignment_for_category(
            profile.profile_id,
            "user_app",
            unit_interval=draw,
        ).application_id
        for draw in draws
    )
    for workers in (1, 4, 8):
        with ThreadPoolExecutor(max_workers=workers) as executor:
            selected = tuple(
                executor.map(
                    lambda draw: (
                        registry.select_user_application_assignment_for_category(
                            profile.profile_id,
                            "user_app",
                            unit_interval=draw,
                        ).application_id
                    ),
                    draws,
                )
            )
        assert selected == expected


def test_assignment_rejects_an_application_absent_from_host_deployment() -> None:
    """Persona eligibility cannot make an application installed by implication."""

    release = _windows_release()
    profile = _user_profile("WS-01", "alice")
    installation = _user_installation(
        release,
        profile,
        r"C:\Users\alice\AppData\Local\slack\slack.exe",
    )
    app_profile = _application_profile(profile, installation)
    empty_deployment = HostDeploymentSpec(
        hostname="WS-01",
        roles=("workstation",),
        platform="windows",
        os_build="22621.3155",
        architecture="x64",
    )
    assignment = UserApplicationAssignmentSpec(
        hostname="WS-01",
        principal="alice",
        platform="windows",
        user_profile_id=profile.profile_id,
        application_profile_id=app_profile.application_profile_id,
        persona="developer",
        eligible_categories=("user_app",),
        intensity=1.0,
    )

    with pytest.raises(ValueError, match="installation in the host deployment"):
        DeploymentContentRegistry(
            binary_releases=(release,),
            user_profiles=(profile,),
            installations=(installation,),
            application_profiles=(app_profile,),
            host_deployments=(empty_deployment,),
            user_application_assignments=(assignment,),
        )


def test_local_artifact_registry_bounds_versions_and_honors_leases() -> None:
    """Expired cache versions should leave compact indexes unless explicitly leased."""

    release = _windows_release()
    profile = _user_profile("WS-01", "alice")
    installation = _user_installation(
        release,
        profile,
        r"C:\Users\alice\AppData\Local\slack\slack.exe",
    )
    app_profile = _application_profile(profile, installation)
    first = _local_artifact(
        profile,
        app_profile,
        source_object_id="message-1",
        native_name="entry-1",
    )
    second = _local_artifact(
        profile,
        app_profile,
        source_object_id="message-2",
        native_name="entry-2",
    )
    third = _local_artifact(
        profile,
        app_profile,
        source_object_id="message-3",
        native_name="entry-3",
    )
    start = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
    artifacts = LocalArtifactVersionRegistry(capacity=2, retention=timedelta(hours=1))
    artifacts.publish(first, start)
    artifacts.acquire_lease(first.artifact_version_id, "email-bundle", start + timedelta(hours=2))
    artifacts.publish(second, start + timedelta(minutes=10))
    artifacts.publish(third, start + timedelta(minutes=20))

    assert len(artifacts) == 2
    assert artifacts.get(first.artifact_version_id) == first
    assert artifacts.get(second.artifact_version_id) is None
    assert (
        artifacts.get_for_path(
            profile.profile_id,
            app_profile.application_profile_id,
            third.native_path.lower(),
            "windows",
            1,
        )
        == third
    )
    assert artifacts.census().pending_expiry == 0

    assert artifacts.advance_watermark(start + timedelta(hours=1, minutes=30)) == (third,)
    assert artifacts.get(first.artifact_version_id) == first
    assert artifacts.census().pending_expiry == 1
    assert artifacts.advance_watermark(start + timedelta(hours=2)) == (first,)
    assert len(artifacts) == 0
    assert artifacts.census().backing_slots <= 2
    retained = artifacts.census(estimate_bytes=True)
    assert retained.estimated_bytes == retained.estimated_index_bytes > 0


def test_local_artifact_prepared_publication_is_atomic_and_exactly_resolvable() -> None:
    """Prepared records stay invisible until the coupled transaction commits last."""

    profile = _user_profile("WS-01", "alice")
    installation = _user_installation(
        _windows_release(),
        profile,
        r"C:\Users\alice\AppData\Local\slack\slack.exe",
    )
    app_profile = _application_profile(profile, installation)
    record = _local_artifact_record(
        profile,
        app_profile,
        source_object_id="attack-drop-1",
        native_name="mimikatz.exe",
    )
    start = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
    artifacts = LocalArtifactVersionRegistry(capacity=4, retention=timedelta(hours=1))

    token = artifacts.prepare_publish_version(record, start)
    prepared = artifacts.census(estimate_bytes=True)
    assert prepared.live_versions == 0
    assert prepared.prepared_publications == 1
    assert prepared.reserved_slots == 1
    assert prepared.estimated_prepared_bytes > 0
    assert artifacts.resolve_version(record.artifact.artifact_version_id) is None

    with pytest.raises(RuntimeError, match="external allocation rejected"):
        with artifacts.prepared_publication(token):
            raise RuntimeError("external allocation rejected")

    assert artifacts.resolve_version(record.artifact.artifact_version_id) is None
    assert artifacts.census().prepared_publications == 0

    token = artifacts.prepare_publish_version(record, start)
    with artifacts.prepared_publication(token) as publication:
        handle = publication.commit()
    assert handle >= 0
    assert artifacts.resolve_version(record.artifact.artifact_version_id) == record
    assert (
        artifacts.resolve_binary_for_path(
            "ws-01",
            "ALICE",
            record.artifact.native_path.lower(),
            "windows",
        )
        == record.binary
    )


def test_local_artifact_claim_has_no_reverse_state_lock_edge() -> None:
    """A claimed token must not retain artifact locks while waiting on StateManager."""

    profile = _user_profile("WS-01", "alice")
    installation = _user_installation(
        _windows_release(),
        profile,
        r"C:\Users\alice\AppData\Local\slack\slack.exe",
    )
    app_profile = _application_profile(profile, installation)
    first = _local_artifact_record(
        profile,
        app_profile,
        source_object_id="lock-order-a",
        native_name="a.exe",
    )
    second = _local_artifact_record(
        profile,
        app_profile,
        source_object_id="lock-order-b",
        native_name="b.exe",
    )
    start = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
    artifacts = LocalArtifactVersionRegistry(capacity=4, retention=timedelta(hours=1))
    first_token = artifacts.prepare_publish_version(first, start)
    second_token = artifacts.prepare_publish_version(second, start)
    state_lane = Lock()
    second_claimed = Event()

    def publish_after_state_lane() -> int:
        with artifacts.prepared_publication(second_token) as publication:
            second_claimed.set()
            with state_lane:
                return publication.commit()

    with artifacts.prepared_publication(first_token) as first_publication:
        state_lane.acquire()
        try:
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(publish_after_state_lane)
                assert second_claimed.wait(timeout=2)
                first_publication.commit()
                state_lane.release()
                assert future.result(timeout=2) >= 0
        finally:
            if state_lane.locked():
                state_lane.release()

    assert artifacts.resolve_version(first.artifact.artifact_version_id) == first
    assert artifacts.resolve_version(second.artifact.artifact_version_id) == second


def test_local_artifact_claim_fences_watermark_until_commit() -> None:
    """A claimed row linearizes before watermark and cannot appear behind sealed history."""

    profile = _user_profile("WS-01", "alice")
    installation = _user_installation(
        _windows_release(),
        profile,
        r"C:\Users\alice\AppData\Local\slack\slack.exe",
    )
    app_profile = _application_profile(profile, installation)
    record = _local_artifact_record(
        profile,
        app_profile,
        source_object_id="watermark-race",
        native_name="race.exe",
    )
    start = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
    artifacts = LocalArtifactVersionRegistry(capacity=1, retention=timedelta(minutes=30))
    token = artifacts.prepare_publish_version(record, start)

    with artifacts.prepared_publication(token) as publication:
        claimed = artifacts.census()
        assert claimed.prepared_publications == 1
        assert claimed.claimed_publications == 1
        assert artifacts.cancel_prepared(token) is False
        with pytest.raises(StateError, match="active claimed publication"):
            artifacts.advance_watermark(start + timedelta(hours=1))
        assert artifacts.watermark is None
        publication.commit()

    assert artifacts.resolve_version(record.artifact.artifact_version_id) == record
    assert artifacts.advance_watermark(start + timedelta(hours=1)) == (record.artifact,)
    final = artifacts.census()
    assert final.live_versions == 0
    assert final.prepared_publications == 0
    assert final.claimed_publications == 0
    assert final.reserved_slots == 0


def test_local_artifact_prepared_version_fences_watermark_and_late_commit() -> None:
    """A due prepared version is retained, then evicted when its stale token cancels."""

    profile = _user_profile("WS-01", "alice")
    installation = _user_installation(
        _windows_release(),
        profile,
        r"C:\Users\alice\AppData\Local\slack\slack.exe",
    )
    app_profile = _application_profile(profile, installation)
    record = _local_artifact_record(
        profile,
        app_profile,
        source_object_id="attack-drop-2",
        native_name="tool.exe",
    )
    start = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
    artifacts = LocalArtifactVersionRegistry(capacity=1, retention=timedelta(minutes=30))
    artifacts.publish_version(record, start)
    token = artifacts.prepare_publish_version(record, start + timedelta(minutes=10))

    assert artifacts.advance_watermark(start + timedelta(hours=1)) == ()
    assert artifacts.census().pending_expiry == 1
    entered = False
    with pytest.raises(StateError, match="before the current artifact watermark"):
        with artifacts.prepared_publication(token):
            entered = True
    assert entered is False
    assert artifacts.resolve_version(record.artifact.artifact_version_id) is None
    census = artifacts.census()
    assert census.live_versions == 0
    assert census.prepared_publications == 0
    assert census.reserved_slots == 0


def test_local_artifact_prepare_capacity_rejection_has_no_side_effects() -> None:
    """Allocation-free admission fails before visibility or reservation mutation."""

    profile = _user_profile("WS-01", "alice")
    installation = _user_installation(
        _windows_release(),
        profile,
        r"C:\Users\alice\AppData\Local\slack\slack.exe",
    )
    app_profile = _application_profile(profile, installation)
    first = _local_artifact_record(
        profile,
        app_profile,
        source_object_id="drop-a",
        native_name="a.exe",
    )
    second = _local_artifact_record(
        profile,
        app_profile,
        source_object_id="drop-b",
        native_name="b.exe",
    )
    start = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
    artifacts = LocalArtifactVersionRegistry(capacity=1, retention=timedelta(hours=1))
    first_token = artifacts.prepare_publish_version(first, start)
    before = artifacts.census(estimate_bytes=True)

    with pytest.raises(LocalArtifactCapacityError, match="no free slot"):
        artifacts.prepare_publish_version(second, start)

    after = artifacts.census(estimate_bytes=True)
    assert after == before
    assert artifacts.cancel_prepared(first_token)
    assert artifacts.census().reserved_slots == 0


def test_failed_publish_at_fully_leased_capacity_is_atomic_until_original_deadline() -> None:
    """A rejected admission must not consume a leased version's future expiry state."""

    release = _windows_release()
    profile = _user_profile("WS-01", "alice")
    installation = _user_installation(
        release,
        profile,
        r"C:\Users\alice\AppData\Local\slack\slack.exe",
    )
    app_profile = _application_profile(profile, installation)
    first = _local_artifact(
        profile,
        app_profile,
        source_object_id="message-1",
        native_name="entry-1",
    )
    second = _local_artifact(
        profile,
        app_profile,
        source_object_id="message-2",
        native_name="entry-2",
    )
    start = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
    artifacts = LocalArtifactVersionRegistry(capacity=1, retention=timedelta(hours=1))
    artifacts.publish(first, start)
    artifacts.acquire_lease(first.artifact_version_id, "owner", start + timedelta(hours=2))
    before_census = artifacts.census()
    before_metrics = artifacts.index_metrics()

    with pytest.raises(LocalArtifactCapacityError, match="at capacity"):
        artifacts.publish(second, start + timedelta(minutes=1))

    assert artifacts.census() == before_census
    assert artifacts.index_metrics() == before_metrics
    assert len(artifacts) == 1
    assert artifacts.get(first.artifact_version_id) == first
    assert artifacts.release_lease(first.artifact_version_id, "owner")
    assert artifacts.census().pending_expiry == 0
    assert artifacts.get(first.artifact_version_id) == first
    assert artifacts.advance_watermark(start + timedelta(minutes=59)) == ()
    assert artifacts.get(first.artifact_version_id) == first
    assert artifacts.advance_watermark(start + timedelta(hours=1)) == (first,)


def test_local_artifact_history_queries_are_lazy_bounded_and_counted() -> None:
    """Potentially large version histories expose iterator/page/count APIs only."""

    release = _windows_release()
    profile = _user_profile("WS-01", "alice")
    installation = _user_installation(
        release,
        profile,
        r"C:\Users\alice\AppData\Local\slack\slack.exe",
    )
    app_profile = _application_profile(profile, installation)
    versions = tuple(
        _local_artifact(
            profile,
            app_profile,
            source_object_id="message-history",
            native_name="history-entry",
            version=version,
            content_id="content-shared",
        )
        for version in range(1, 4)
    )
    start = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
    artifacts = LocalArtifactVersionRegistry(capacity=8)
    for version in versions:
        artifacts.publish(version, start)

    assert artifacts.count_versions_for_object(versions[0].artifact_id) == 3
    first_page, cursor = artifacts.page_versions_for_object(
        versions[0].artifact_id,
        limit=2,
    )
    second_page, final_cursor = artifacts.page_versions_for_object(
        versions[0].artifact_id,
        limit=2,
        cursor=cursor,
    )
    assert first_page == versions[:2]
    assert second_page == versions[2:]
    assert final_cursor is None
    assert (
        tuple(artifacts.iter_versions_for_object(versions[0].artifact_id, page_size=1)) == versions
    )
    assert artifacts.count_versions_for_application_profile(app_profile.application_profile_id) == 3
    assert (
        tuple(
            artifacts.iter_versions_for_application_profile(
                app_profile.application_profile_id,
                page_size=2,
            )
        )
        == versions
    )
    assert artifacts.count_versions_for_content("content-shared") == 3
    assert tuple(artifacts.iter_versions_for_content("content-shared", page_size=2)) == versions
    assert not hasattr(artifacts, "versions_for_object")
    assert not hasattr(artifacts, "versions_for_application_profile")
    assert not hasattr(artifacts, "versions_for_content")


def test_local_artifact_history_cursor_rejects_mutation_and_cross_query_reuse() -> None:
    """Opaque history cursors must never survive publish, eviction, or query changes."""

    release = _windows_release()
    profile = _user_profile("WS-01", "alice")
    installation = _user_installation(
        release,
        profile,
        r"C:\Users\alice\AppData\Local\slack\slack.exe",
    )
    app_profile = _application_profile(profile, installation)
    versions = tuple(
        _local_artifact(
            profile,
            app_profile,
            source_object_id="message-history",
            native_name="history-entry",
            version=version,
            content_id="content-shared",
        )
        for version in range(1, 4)
    )
    extra = _local_artifact(
        profile,
        app_profile,
        source_object_id="extra",
        native_name="extra",
    )
    another = _local_artifact(
        profile,
        app_profile,
        source_object_id="another",
        native_name="another",
    )
    start = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
    artifacts = LocalArtifactVersionRegistry(capacity=8)
    for version in versions:
        artifacts.publish(version, start)

    _page, cursor = artifacts.page_versions_for_object(versions[0].artifact_id, limit=1)
    assert cursor is not None
    with pytest.raises(StateError, match="belongs to another query"):
        artifacts.page_versions_for_content("content-shared", limit=1, cursor=cursor)

    artifacts.publish(extra, start)
    with pytest.raises(StateError, match="invalidated by mutation"):
        artifacts.page_versions_for_object(
            versions[0].artifact_id,
            limit=1,
            cursor=cursor,
        )

    iterator = artifacts.iter_versions_for_object(versions[0].artifact_id, page_size=1)
    assert next(iterator) == versions[0]
    artifacts.publish(another, start)
    with pytest.raises(StateError, match="invalidated by mutation"):
        next(iterator)


def test_local_artifact_secondary_indexes_verify_exact_values_after_digest_collision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Compact fingerprints must never merge distinct application or content identities."""

    release = _windows_release()
    profile = _user_profile("WS-01", "alice")
    installation = _user_installation(
        release,
        profile,
        r"C:\Users\alice\AppData\Local\slack\slack.exe",
    )
    app_profile = _application_profile(profile, installation)
    first = _local_artifact(
        profile,
        app_profile,
        source_object_id="collision-first",
        native_name="collision-first",
        content_id="content-first",
    )
    second = LocalArtifactIdentity(
        hostname=profile.hostname,
        principal=profile.principal,
        platform=profile.platform,
        user_profile_id=profile.profile_id,
        application_profile_id="application-profile-exact-second",
        application_id="slack",
        family="message-cache",
        source_object_id="collision-second",
        native_path=rf"{app_profile.profile_root}\Cache\collision-second",
        content_id="content-second",
    )
    monkeypatch.setattr(
        deployment_registry,
        "_artifact_text_digest",
        lambda _value: b"\x5a" * 16,
    )
    artifacts = LocalArtifactVersionRegistry(capacity=8)
    start = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
    artifacts.publish(first, start)
    artifacts.publish(second, start)

    assert artifacts.count_versions_for_application_profile(first.application_profile_id) == 1
    assert artifacts.count_versions_for_application_profile(second.application_profile_id) == 1
    assert tuple(artifacts.iter_versions_for_content(first.content_id)) == (first,)
    assert tuple(artifacts.iter_versions_for_content(second.content_id)) == (second,)


def test_local_artifact_large_exact_payload_uses_bounded_overflow_storage() -> None:
    """Rare large descriptors remain exact without expanding every inline payload slot."""

    release = _windows_release()
    profile = _user_profile("WS-01", "alice")
    installation = _user_installation(
        release,
        profile,
        r"C:\Users\alice\AppData\Local\slack\slack.exe",
    )
    app_profile = _application_profile(profile, installation)
    large_content_id = "content-" + "".join(chr(0x1000 + ordinal) for ordinal in range(512))
    artifact = _local_artifact(
        profile,
        app_profile,
        source_object_id="large-payload",
        native_name="large-payload",
        content_id=large_content_id,
    )
    artifacts = LocalArtifactVersionRegistry(capacity=4)
    artifacts.publish(artifact, datetime(2026, 8, 16, 12, 0, tzinfo=UTC))

    shard = artifacts._existing_shard(artifact.artifact_version_id)
    assert shard is not None
    assert shard.store._payload_overflow
    assert artifacts.get(artifact.artifact_version_id) == artifact
    assert tuple(artifacts.iter_versions_for_content(large_content_id)) == (artifact,)


def test_local_artifact_late_publish_and_lease_fences_are_atomic() -> None:
    """Sealed history and elapsed leases cannot mutate retained artifact state."""

    release = _windows_release()
    profile = _user_profile("WS-01", "alice")
    installation = _user_installation(
        release,
        profile,
        r"C:\Users\alice\AppData\Local\slack\slack.exe",
    )
    app_profile = _application_profile(profile, installation)
    first = _local_artifact(
        profile,
        app_profile,
        source_object_id="first",
        native_name="first",
    )
    boundary = _local_artifact(
        profile,
        app_profile,
        source_object_id="boundary",
        native_name="boundary",
    )
    start = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
    watermark = start + timedelta(minutes=30)
    artifacts = LocalArtifactVersionRegistry(capacity=8, retention=timedelta(hours=1))
    artifacts.publish(first, start)
    assert artifacts.advance_watermark(watermark) == ()
    before_census = artifacts.census()
    before_metrics = artifacts.index_metrics()

    with pytest.raises(StateError, match="before the current artifact watermark"):
        artifacts.publish(boundary, watermark - timedelta(microseconds=1))
    assert artifacts.census() == before_census
    assert artifacts.index_metrics() == before_metrics
    assert artifacts.get(boundary.artifact_version_id) is None

    artifacts.publish(boundary, watermark)
    before_lease_census = artifacts.census()
    before_lease_metrics = artifacts.index_metrics()
    with pytest.raises(StateError, match="at or before the current artifact watermark"):
        artifacts.acquire_lease(first.artifact_version_id, "elapsed", watermark)
    with pytest.raises(StateError, match="extend beyond the artifact retention deadline"):
        artifacts.acquire_lease(
            first.artifact_version_id,
            "redundant",
            watermark + timedelta(minutes=15),
        )
    assert artifacts.census() == before_lease_census
    assert artifacts.index_metrics() == before_lease_metrics
    artifacts.acquire_lease(first.artifact_version_id, "valid", start + timedelta(hours=2))


def test_local_artifact_registry_serializes_concurrent_publish_and_lease_commits() -> None:
    """Concurrent writers and lease owners must preserve every bounded-index invariant."""

    release = _windows_release()
    profile = _user_profile("WS-01", "alice")
    installation = _user_installation(
        release,
        profile,
        r"C:\Users\alice\AppData\Local\slack\slack.exe",
    )
    app_profile = _application_profile(profile, installation)
    anchor = _local_artifact(
        profile,
        app_profile,
        source_object_id="anchor",
        native_name="anchor",
    )
    candidates = tuple(
        _local_artifact(
            profile,
            app_profile,
            source_object_id=f"message-{index}",
            native_name=f"entry-{index}",
        )
        for index in range(24)
    )
    start = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
    artifacts = LocalArtifactVersionRegistry(capacity=8, retention=timedelta(hours=1))
    artifacts.publish(anchor, start)
    artifacts.acquire_lease(anchor.artifact_version_id, "root-owner", start + timedelta(hours=2))
    barrier = Barrier(8)

    def publish_and_lease(worker_id: int) -> None:
        barrier.wait()
        for offset, artifact in enumerate(candidates[worker_id::8]):
            owner = f"worker-{worker_id}-{offset}"
            artifacts.acquire_lease(
                anchor.artifact_version_id,
                owner,
                start + timedelta(hours=2),
            )
            artifacts.publish(
                artifact,
                start + timedelta(minutes=worker_id * 3 + offset),
            )
            assert artifacts.release_lease(anchor.artifact_version_id, owner)

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = tuple(executor.submit(publish_and_lease, worker_id) for worker_id in range(8))
        for future in futures:
            future.result()

    assert artifacts.get(anchor.artifact_version_id) == anchor
    assert len(artifacts) == 8
    assert artifacts.census().backing_slots <= 8
    assert artifacts.census().active_leases == 1
    assert artifacts.release_lease(anchor.artifact_version_id, "root-owner")
    assert artifacts.get(anchor.artifact_version_id) == anchor


def test_local_artifact_registry_disjoint_owner_shards_make_overlapping_progress() -> None:
    """A blocked owner lane must not serialize a refresh in another owner lane."""

    release = _windows_release()
    profile = _user_profile("WS-01", "alice")
    installation = _user_installation(
        release,
        profile,
        r"C:\Users\alice\AppData\Local\slack\slack.exe",
    )
    app_profile = _application_profile(profile, installation)
    artifacts = LocalArtifactVersionRegistry(capacity=8, shard_count=4)
    candidates = tuple(
        _local_artifact(
            profile,
            app_profile,
            source_object_id=f"owner-{index}",
            native_name=f"owner-{index}",
        )
        for index in range(32)
    )
    first = candidates[0]
    second = next(
        candidate
        for candidate in candidates[1:]
        if artifacts._shard_id_for(candidate.artifact_id)
        != artifacts._shard_id_for(first.artifact_id)
    )
    start = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
    artifacts.publish(first, start)
    artifacts.publish(second, start)
    first_shard = artifacts._existing_shard(first.artifact_version_id)
    second_shard = artifacts._existing_shard(second.artifact_version_id)
    assert first_shard is not None and second_shard is not None
    assert first_shard is not second_shard
    entered_gate = Event()

    def refresh_blocked_owner() -> int:
        with artifacts._gate.mutation():
            entered_gate.set()
            return artifacts.publish(first, start + timedelta(minutes=1))

    first_shard.lock.acquire()
    lock_held = True
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            blocked = executor.submit(refresh_blocked_owner)
            assert entered_gate.wait(timeout=1)
            disjoint = executor.submit(
                artifacts.publish,
                second,
                start + timedelta(minutes=1),
            )
            assert disjoint.result(timeout=1) >= 0
            assert not blocked.done()
            first_shard.lock.release()
            lock_held = False
            assert blocked.result(timeout=1) >= 0
    finally:
        if lock_held:
            first_shard.lock.release()


def test_identity_values_are_frozen_and_registry_census_is_constant_time_shape() -> None:
    """Published identities are immutable and the registry exposes compact cardinalities."""

    release = _windows_release()
    registry = DeploymentContentRegistry(binary_releases=(release,))

    with pytest.raises(FrozenInstanceError):
        release.content_id = "changed"  # type: ignore[misc]

    census = registry.census()
    assert census.binary_releases == 1
    assert census.binary_path_bindings == 0
    assert census.file_versions == 0
