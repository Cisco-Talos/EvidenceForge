# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for path-independent content and exact deployment identity indexes."""

import copy
import random
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from threading import Barrier, Event, Lock

import pytest

import evidenceforge.generation.deployment_compiler as deployment_compiler
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
    CompiledApplicationDescriptor,
    DeploymentContentRegistry,
    HostDeploymentSpec,
    LocalArtifactCapacityError,
    LocalArtifactVersionRegistry,
    UserApplicationAssignment,
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
    artifact_by_id = registry.local_artifact(alice_artifact.artifact_id, 1)
    artifact_by_path = registry.local_artifact_for_path(
        alice.profile_id,
        alice_app.application_profile_id,
        alice_artifact.native_path.lower(),
        "windows",
        1,
    )
    assert artifact_by_id == artifact_by_path == alice_artifact
    assert artifact_by_id is not alice_artifact
    assert artifact_by_path is not alice_artifact


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
    profile_assignment = registry.user_application_assignment_for_profile(
        profile.profile_id,
        app_profile.application_profile_id,
    )
    assert profile_assignment == assignment
    assert profile_assignment is not assignment
    assert registry.user_application_assignments_for_product("WS-01", "slack") == (assignment,)
    assert registry.user_application_assignments_for_release("WS-01", release.release_id) == (
        assignment,
    )
    assert not hasattr(assignment, "installations")
    assert not hasattr(assignment, "installation_ids")


def test_direct_registry_materialization_uses_installed_principal_presentation() -> None:
    """Direct assignment/caller aliases cannot rewrite installation-owned command bytes."""

    aliases = ("Alice", "ALICE", "aLiCe")
    profile = _user_profile("WS-01", "Alice")
    release = _windows_release(
        product_id="custom_slack",
        artifact_name="custom-slack.exe",
        variant="custom",
    )
    installation = _user_installation(
        release,
        profile,
        r"C:\Users\Alice\AppData\Local\Custom\custom-slack.exe",
        application_id="custom_slack",
    )
    application_profile = _application_profile(
        profile,
        installation,
        application_id="custom_slack",
    )
    descriptor = CompiledApplicationDescriptor(
        application_id="custom_slack",
        platform="windows",
        image_path=r"C:\Users\{username}\AppData\Local\Custom\custom-slack.exe",
        command_templates=(
            r'"C:\Users\{username}\AppData\Local\Custom\custom-slack.exe" '
            r"--user {username}",
        ),
        categories=("user_app",),
    )
    deployment = HostDeploymentSpec(
        hostname="WS-01",
        roles=("workstation",),
        platform="windows",
        os_build="22621.3155",
        architecture="x64",
        installation_ids=(installation.installation_id,),
    )
    expected_materialization = (
        r"C:\Users\Alice\AppData\Local\Custom\custom-slack.exe",
        r'"C:\Users\Alice\AppData\Local\Custom\custom-slack.exe" --user Alice',
    )

    for assignment_alias in aliases:
        assignment_spec = UserApplicationAssignmentSpec(
            hostname="WS-01",
            principal=assignment_alias,
            platform="windows",
            user_profile_id=profile.profile_id,
            application_profile_id=application_profile.application_profile_id,
            persona="developer",
            eligible_categories=("user_app",),
            intensity=1.0,
        )
        registry = DeploymentContentRegistry(
            binary_releases=(release,),
            user_profiles=(profile,),
            installations=(installation,),
            application_profiles=(application_profile,),
            application_descriptors=(descriptor,),
            host_deployments=(deployment,),
            user_application_assignments=(assignment_spec,),
        )
        assignment = registry.user_application_assignment(assignment_spec.assignment_id)
        assert assignment is not None
        assert assignment.principal == "alice"
        assert assignment.materialization_principal == "Alice"
        assert registry.application_ids_for_executable(
            "windows",
            "custom-slack.exe",
        ) == ("custom_slack",)
        assert (
            registry.application_executable_for_assignment(assignment)
            == expected_materialization[0]
        )
        census_before = (
            registry.census(),
            registry.deployment_census(),
            registry.assignment_category_index_census(),
            registry.scale_census(),
        )
        for caller_alias in aliases:
            rng = random.Random(8675309)
            expected_rng = random.Random(8675309)
            expected_rng.choice(descriptor.command_templates)
            assert (
                registry.materialize_application_command(
                    rng,
                    assignment,
                    username=caller_alias,
                )
                == expected_materialization
            )
            assert rng.getstate() == expected_rng.getstate()
        assert (
            registry.census(),
            registry.deployment_census(),
            registry.assignment_category_index_census(),
            registry.scale_census(),
        ) == census_before

    retained_census = (
        registry.census(),
        registry.deployment_census(),
        registry.assignment_category_index_census(),
        registry.scale_census(),
    )
    source_templates = descriptor.command_templates
    object.__setattr__(descriptor, "command_templates", ("calc.exe --unexpected",))
    object.__setattr__(descriptor, "selection_ordinal", 99)
    retained_descriptor = registry.application_descriptor("custom_slack", "windows")
    assert retained_descriptor is not None and retained_descriptor is not descriptor
    assert retained_descriptor.command_templates == source_templates
    assert retained_descriptor.selection_ordinal == 0
    object.__setattr__(retained_descriptor, "command_templates", ("calc.exe --returned",))
    object.__setattr__(retained_descriptor, "selection_ordinal", 101)
    canonical_descriptor = registry.application_descriptor("custom_slack", "windows")
    assert canonical_descriptor is not None and canonical_descriptor is not retained_descriptor
    assert canonical_descriptor.command_templates == source_templates
    assert canonical_descriptor.selection_ordinal == 0
    assignment_descriptor = registry.application_descriptor_for_assignment(assignment)
    assert assignment_descriptor == canonical_descriptor
    assert assignment_descriptor is not canonical_descriptor
    object.__setattr__(assignment_descriptor, "command_templates", ("calc.exe --assignment",))
    object.__setattr__(assignment_descriptor, "selection_ordinal", 102)
    assert registry.application_descriptor_for_assignment(assignment) == canonical_descriptor
    rng = random.Random(8675309)
    expected_rng = random.Random(8675309)
    expected_rng.choice(source_templates)
    assert (
        registry.materialize_application_command(
            rng,
            assignment,
            username="aLiCe",
        )
        == expected_materialization
    )
    assert rng.getstate() == expected_rng.getstate()
    assert registry.application_ids_for_executable(
        "windows",
        "custom-slack.exe",
    ) == ("custom_slack",)
    assert (
        registry.census(),
        registry.deployment_census(),
        registry.assignment_category_index_census(),
        registry.scale_census(),
    ) == retained_census

    canonical_assignment = registry.user_application_assignment(assignment.assignment_id)
    assert canonical_assignment == assignment
    assert canonical_assignment is not assignment
    object.__setattr__(assignment, "selection_ordinal", 99)
    rejected_rng = random.Random(8675309)
    rejected_rng_before = rejected_rng.getstate()
    assert registry.application_descriptor_for_assignment(assignment) is None
    assert registry.application_executable_for_assignment(assignment) is None
    assert (
        registry.materialize_application_command(
            rejected_rng,
            assignment,
            username="Alice",
        )
        is None
    )
    assert rejected_rng.getstate() == rejected_rng_before
    assert (
        registry.census(),
        registry.deployment_census(),
        registry.assignment_category_index_census(),
        registry.scale_census(),
    ) == retained_census
    fresh_assignment = registry.user_application_assignment(assignment.assignment_id)
    assert fresh_assignment == canonical_assignment
    fresh_rng = random.Random(8675309)
    assert (
        registry.materialize_application_command(
            fresh_rng,
            fresh_assignment,
            username="Alice",
        )
        == expected_materialization
    )


def test_direct_registry_charges_username_and_nested_pool_replacement_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Direct assignment admission enforces literal and scoped expansion work together."""

    profile = _user_profile("WS-01", "alice")
    release = _windows_release(
        product_id="custom_slack",
        artifact_name="custom-slack.exe",
        variant="custom",
    )
    installation = _user_installation(
        release,
        profile,
        r"C:\Custom\custom-slack.exe",
        application_id="custom_slack",
    )
    application_profile = _application_profile(
        profile,
        installation,
        application_id="custom_slack",
    )
    deployment = HostDeploymentSpec(
        hostname="WS-01",
        roles=("workstation",),
        platform="windows",
        os_build="22621.3155",
        architecture="x64",
        installation_ids=(installation.installation_id,),
    )
    assignment_spec = UserApplicationAssignmentSpec(
        hostname="WS-01",
        principal="alice",
        platform="windows",
        user_profile_id=profile.profile_id,
        application_profile_id=application_profile.application_profile_id,
        persona="developer",
        eligible_categories=("user_app",),
        intensity=1.0,
    )

    def compile_descriptor(
        descriptor: CompiledApplicationDescriptor,
    ) -> DeploymentContentRegistry:
        return DeploymentContentRegistry(
            binary_releases=(release,),
            user_profiles=(profile,),
            installations=(installation,),
            application_profiles=(application_profile,),
            application_descriptors=(descriptor,),
            host_deployments=(deployment,),
            user_application_assignments=(assignment_spec,),
        )

    prefix = r'"C:\Custom\custom-slack.exe"'
    accepted_template = prefix + (" {username}" * 1_024)
    accepted = CompiledApplicationDescriptor(
        application_id="custom_slack",
        platform="windows",
        image_path=r"C:\Custom\custom-slack.exe",
        command_templates=(accepted_template,),
        categories=("user_app",),
    )
    registry = compile_descriptor(accepted)
    assignment = registry.user_application_assignment(assignment_spec.assignment_id)
    assert assignment is not None
    rng = random.Random(8675309)
    expected_rng = random.Random(8675309)
    expected_rng.choice((accepted_template,))
    assert registry.materialize_application_command(rng, assignment, username="alice") == (
        r"C:\Custom\custom-slack.exe",
        prefix + (" alice" * 1_024),
    )
    assert rng.getstate() == expected_rng.getstate()
    census_before = (registry.census(), registry.deployment_census(), registry.scale_census())

    rejected = CompiledApplicationDescriptor(
        application_id="custom_slack",
        platform="windows",
        image_path=r"C:\Custom\custom-slack.exe",
        command_templates=(prefix + (" {username}" * 1_025),),
        categories=("user_app",),
    )
    rejected_rng = random.Random(8675309)
    rejected_rng_before = rejected_rng.getstate()
    with pytest.raises(ValueError, match="bounded output contract"):
        compile_descriptor(rejected)

    nested_accepted = CompiledApplicationDescriptor(
        application_id="custom_slack",
        platform="windows",
        image_path=r"C:\Custom\custom-slack.exe",
        command_templates=(prefix + " {outer}",),
        command_parameter_pools=(("outer", ("{username}" * 1_023,)),),
        categories=("user_app",),
    )
    compile_descriptor(nested_accepted)
    nested_rejected = CompiledApplicationDescriptor(
        application_id="custom_slack",
        platform="windows",
        image_path=r"C:\Custom\custom-slack.exe",
        command_templates=(prefix + " {outer}",),
        command_parameter_pools=(("outer", ("{username}" * 1_024,)),),
        categories=("user_app",),
    )
    with pytest.raises(ValueError, match="bounded output contract"):
        compile_descriptor(nested_rejected)

    assert rejected_rng.getstate() == rejected_rng_before
    assert (registry.census(), registry.deployment_census(), registry.scale_census()) == (
        census_before
    )

    packed_registry = DeploymentContentRegistry(
        binary_releases=(release,),
        user_profiles=(profile,),
        installations=(installation,),
        application_profiles=(application_profile,),
        application_descriptors=(accepted,),
        host_deployments=(deployment,),
        user_application_assignments=(spec for spec in (assignment_spec,)),
    )
    assert packed_registry._user_assignments._compat_values is None
    assert packed_registry._user_assignments.retained_identity_entries == 0
    assert packed_registry.scale_census().user_application_assignment_owner_snapshots == 0
    validation_calls = 0
    original_post_init = UserApplicationAssignment.__post_init__

    def count_validation(value: UserApplicationAssignment) -> None:
        nonlocal validation_calls
        validation_calls += 1
        original_post_init(value)

    monkeypatch.setattr(UserApplicationAssignment, "__post_init__", count_validation)
    packed_assignment = packed_registry.user_application_assignment(assignment_spec.assignment_id)
    assert packed_assignment is not None
    packed_census = (
        packed_registry.census(),
        packed_registry.deployment_census(),
        packed_registry.scale_census(),
    )
    packed_rng = random.Random(8675309)
    expected_packed_rng = random.Random(8675309)
    for _ in range(32):
        expected_packed_rng.choice((accepted_template,))
        assert packed_registry.application_descriptor_for_assignment(packed_assignment) == accepted
        assert (
            packed_registry.application_executable_for_assignment(packed_assignment)
            == r"C:\Custom\custom-slack.exe"
        )
        assert packed_registry.materialize_application_command(
            packed_rng,
            packed_assignment,
            username="alice",
        ) == (
            r"C:\Custom\custom-slack.exe",
            prefix + (" alice" * 1_024),
        )
    assert validation_calls == 0
    assert packed_rng.getstate() == expected_packed_rng.getstate()
    assert (
        packed_registry.census(),
        packed_registry.deployment_census(),
        packed_registry.scale_census(),
    ) == packed_census


def test_trusted_assignment_decoder_stays_validation_free_above_snapshot_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Packed owner rows never re-enter validation after compatibility snapshots drop."""

    stores: list[
        tuple[
            deployment_registry._PackedFrozenIndexedStore[str, UserApplicationAssignment],
            int,
        ]
    ] = []
    for count, preserve_limit in (
        (1, 0),
        (
            deployment_registry._PACKED_IDENTITY_COMPAT_LIMIT + 1,
            deployment_registry._PACKED_IDENTITY_COMPAT_LIMIT,
        ),
    ):
        store = deployment_registry._PackedFrozenIndexedStore[str, UserApplicationAssignment](
            pack=deployment_registry._pack_user_assignment,
            unpack=deployment_registry._unpack_user_assignment,
            primary_key=lambda assignment: assignment.assignment_id,
            preserve_identity=True,
            preserve_identity_limit=preserve_limit,
        )
        for ordinal in range(count):
            assignment = UserApplicationAssignment(
                assignment_id=f"assignment-{ordinal:05d}",
                hostname="ws-01",
                principal="alice",
                materialization_principal="Alice",
                platform="windows",
                user_profile_id="profile-1",
                application_profile_id="application-profile-1",
                application_id="custom_slack",
                product_id="custom_slack",
                release_id="release-1",
                persona="developer",
                eligible_categories=("user_app",),
                intensity=1.0,
                host_deployment_handle=0,
                user_profile_handle=0,
                installation_handle=0,
                application_profile_handle=0,
                selection_ordinal=ordinal,
            )
            store[assignment.assignment_id] = assignment
        store.seal()
        assert store._compat_values is None
        assert store.retained_identity_entries == 0
        assert store.metrics().backing_entries == store.metrics().high_water_mark == count
        stores.append((store, count))

    validation_calls = 0
    original_post_init = UserApplicationAssignment.__post_init__

    def count_validation(value: UserApplicationAssignment) -> None:
        nonlocal validation_calls
        validation_calls += 1
        original_post_init(value)

    monkeypatch.setattr(UserApplicationAssignment, "__post_init__", count_validation)
    for store, count in stores:
        target_id = f"assignment-{count - 1:05d}"
        for _ in range(32):
            decoded = store.get(target_id)
            assert decoded is not None
            assert decoded.assignment_id == target_id
            assert decoded.selection_ordinal == count - 1
    assert validation_calls == 0


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
    application_assignment = registry.user_application_assignment_for_application(
        profile.profile_id,
        "POSTMAN",
    )
    assert application_assignment == routed[0]
    assert application_assignment is not routed[0]
    census = registry.assignment_category_index_census(estimate_bytes=True)
    assert (census.buckets, census.links, census.max_bucket_size) == (2, 5, 3)
    assert census.browser_affinities == census.exact_selection_candidates == 1
    assert census.lookup_candidates_inspected > 0
    assert census.estimated_bytes > 0

    profile_page, _profile_cursor = registry.page_user_application_assignments_for_profile(
        profile.profile_id,
        limit=10,
    )
    profile_assignment = registry.user_application_assignment_for_profile(
        profile.profile_id,
        application_profiles[0].application_profile_id,
    )
    assert profile_assignment == routed[0]
    assert profile_assignment is not routed[0]
    product_page, _product_cursor = registry.page_user_application_assignments_for_product(
        "WS-01",
        "postman",
        limit=10,
    )
    release_page, _release_cursor = registry.page_user_application_assignments_for_release(
        "WS-01",
        releases[0].release_id,
        limit=10,
    )

    def postman_from(values: tuple[UserApplicationAssignment, ...]) -> UserApplicationAssignment:
        return next(value for value in values if value.application_id == "postman")

    postman_views = (
        routed[0],
        registry.user_application_assignment(routed[0].assignment_id),
        profile_assignment,
        application_assignment,
        registry.user_application_assignment_for_category_at(
            profile.profile_id,
            "user_app",
            0,
        ),
        registry.select_user_application_assignment_for_category(
            profile.profile_id,
            "user_app",
            unit_interval=0.0,
        ),
        registry.select_user_application_assignment_for_applications(
            profile.profile_id,
            ("postman",),
            unit_interval=0.0,
        ),
        first[0],
        postman_from(registry.user_application_assignments_for_profile(profile.profile_id)),
        postman_from(
            tuple(registry.iter_user_application_assignments_for_profile(profile.profile_id))
        ),
        postman_from(profile_page),
        registry.user_application_assignments_for_product("WS-01", "postman")[0],
        tuple(registry.iter_user_application_assignments_for_product("WS-01", "postman"))[0],
        product_page[0],
        registry.user_application_assignments_for_release("WS-01", releases[0].release_id)[0],
        tuple(
            registry.iter_user_application_assignments_for_release(
                "WS-01",
                releases[0].release_id,
            )
        )[0],
        release_page[0],
    )
    assert all(view is not None for view in postman_views)
    detached_postman_views = tuple(
        view for view in postman_views if isinstance(view, UserApplicationAssignment)
    )
    owner_postman = registry._owned_user_application_assignment(routed[0].assignment_id)
    assert owner_postman is not None
    assert all(
        view == owner_postman and view is not owner_postman for view in detached_postman_views
    )
    assert len({id(view) for view in detached_postman_views}) == len(detached_postman_views)

    preferred_view = registry.preferred_browser_assignment(profile.profile_id)
    assert preferred_view is not None
    alternative_view = registry.browser_alternative_assignment_at(
        profile.profile_id,
        preferred_view.assignment_id,
        0,
    )
    assert alternative_view is not None
    owner_preferred = registry._owned_user_application_assignment(preferred_view.assignment_id)
    owner_alternative = registry._owned_user_application_assignment(alternative_view.assignment_id)
    assert owner_preferred is not None and owner_alternative is not None
    assert preferred_view == owner_preferred and preferred_view is not owner_preferred
    assert alternative_view == owner_alternative and alternative_view is not owner_alternative

    mutation_census = (
        registry.census(),
        registry.deployment_census(),
        registry.assignment_category_index_census(),
        registry.scale_census(),
    )
    expected_assignments = {
        owner.assignment_id: (owner.application_id, owner.selection_ordinal)
        for owner in (owner_postman, owner_preferred, owner_alternative)
    }
    for view in (*detached_postman_views, preferred_view, alternative_view):
        object.__setattr__(view, "application_id", "forged")
        object.__setattr__(view, "selection_ordinal", 99_999)
    assert (
        registry.census(),
        registry.deployment_census(),
        registry.assignment_category_index_census(),
        registry.scale_census(),
    ) == mutation_census
    for assignment_id, expected in expected_assignments.items():
        fresh = registry.user_application_assignment(assignment_id)
        assert fresh is not None
        assert (fresh.application_id, fresh.selection_ordinal) == expected

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
    assert before.live_entries == 14
    assert before.retained_entries == before.high_water_mark == 17
    assert before.application_descriptor_owner_snapshots == 0
    assert before.user_application_assignment_owner_snapshots == 3
    assert (
        registry._user_assignments._preserve_identity_limit
        == deployment_registry._PACKED_IDENTITY_COMPAT_LIMIT
    )
    assert registry._user_assignments.retained_identity_entries == 3
    assert before.stale_entries == before.leased_entries == 0
    assert before.relationship_bindings == 11
    assert before.backing_entries == 28
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


def test_compiled_application_descriptor_lookup_is_exact_bounded_and_order_independent() -> None:
    """Executable routes are frozen once and exact descriptor lookups never revisit inputs."""

    descriptors = tuple(
        CompiledApplicationDescriptor(
            application_id=f"application-{ordinal:05d}",
            platform="windows",
            image_path=r"C:\Apps\shared.exe",
            command_templates=(r'"C:\Apps\shared.exe"',),
            categories=("user_app",),
            selection_ordinal=ordinal,
        )
        for ordinal in range(4_096)
    )
    mutable_input = list(descriptors)
    registry = DeploymentContentRegistry(
        application_descriptors=(descriptor for descriptor in mutable_input)
    )
    mutable_input.clear()

    executable_ids = registry.application_ids_for_executable("windows", "SHARED.EXE")
    assert len(executable_ids) == 4_096
    assert executable_ids[0] == "application-00000"
    assert executable_ids[-1] == "application-04095"
    assert executable_ids is registry.application_ids_for_executable(
        "windows",
        r"C:\Apps\shared.exe",
    )
    assert (
        registry.application_descriptor(
            "application-02048",
            "windows",
        )
        == descriptors[2_048]
    )
    census = registry.census()
    assert census.application_descriptors == 4_096
    assert census.application_executable_bindings == 4_096
    scale = registry.scale_census()
    assert scale.physical_records == scale.live_entries == 4_096
    assert scale.retained_entries == scale.high_water_mark == 8_192
    assert scale.application_descriptor_owner_snapshots == 4_096
    assert scale.user_application_assignment_owner_snapshots == 0
    assert scale.relationship_bindings == scale.application_executable_bindings == 4_096
    assert scale.backing_entries == 12_288
    assert scale.maximum_bucket_size == 4_096
    assert 0 < scale.estimated_index_bytes <= scale.estimated_bytes

    reversed_registry = DeploymentContentRegistry(
        application_descriptors=tuple(reversed(descriptors))
    )
    assert (
        reversed_registry.application_ids_for_executable(
            "windows",
            "shared.exe",
        )
        == executable_ids
    )
    tied = (
        CompiledApplicationDescriptor(
            application_id="zeta",
            platform="windows",
            image_path=r"C:\Apps\tie.exe",
            command_templates=(r'"C:\Apps\tie.exe"',),
            categories=("user_app",),
            selection_ordinal=7,
        ),
        CompiledApplicationDescriptor(
            application_id="alpha",
            platform="windows",
            image_path=r"C:\Apps\tie.exe",
            command_templates=(r'"C:\Apps\tie.exe"',),
            categories=("user_app",),
            selection_ordinal=7,
        ),
    )
    tied_registry = DeploymentContentRegistry(application_descriptors=tied)
    assert tied_registry.application_ids_for_executable("windows", "tie.exe") == (
        "alpha",
        "zeta",
    )


def test_descriptor_owner_snapshot_survives_generic_compatibility_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Runtime ownership and detached public reads stay constant above the generic limit."""

    count = deployment_registry._PACKED_IDENTITY_COMPAT_LIMIT + 1
    descriptors = tuple(
        CompiledApplicationDescriptor(
            application_id=f"application-{ordinal:05d}",
            platform="windows",
            image_path=r"C:\Apps\shared.exe",
            command_templates=(r'"C:\Apps\shared.exe" --flag',),
            categories=("user_app",),
            selection_ordinal=ordinal,
        )
        for ordinal in range(count)
    )
    registry = DeploymentContentRegistry(application_descriptors=descriptors)
    census_before = (registry.census(), registry.deployment_census(), registry.scale_census())

    monkeypatch.setattr(
        deployment_registry,
        "_validate_application_command_expansion_bounds",
        lambda *_args, **_kwargs: pytest.fail("retained descriptor was revalidated"),
    )
    target_id = f"application-{count - 1:05d}"
    public_descriptor = registry.application_descriptor(target_id, "windows")
    assert public_descriptor == descriptors[-1]
    owned_descriptor = registry._owned_application_descriptor(target_id, "windows")
    assert owned_descriptor == public_descriptor
    assert owned_descriptor is not public_descriptor
    object.__setattr__(public_descriptor, "command_templates", ("calc.exe --returned",))
    object.__setattr__(public_descriptor, "selection_ordinal", count + 1)
    assert registry.application_descriptor(target_id, "windows") == descriptors[-1]
    executable_ids = registry.application_ids_for_executable("windows", "shared.exe")
    assert len(executable_ids) == count
    assert executable_ids[-1] == target_id
    scale = registry.scale_census()
    assert scale.physical_records == count
    assert scale.retained_entries == scale.high_water_mark == count * 2
    assert scale.application_descriptor_owner_snapshots == count
    assert scale.user_application_assignment_owner_snapshots == 0
    assert scale.relationship_bindings == count
    assert scale.backing_entries == count * 3
    descriptor_store = registry._application_descriptors
    descriptor_metrics = descriptor_store.metrics(estimate_bytes=True)
    retained_snapshots = descriptor_store._compat_values
    assert retained_snapshots is not None and len(retained_snapshots) == count
    retained_snapshot_bytes = deployment_registry._owned_graph_size(retained_snapshots)
    assert descriptor_metrics.backing_entries == descriptor_metrics.high_water_mark == count * 2
    assert descriptor_metrics.estimated_bytes >= (
        descriptor_store._rows.estimated_bytes() + retained_snapshot_bytes
    )
    assert scale.estimated_bytes >= descriptor_metrics.estimated_bytes
    assert (registry.census(), registry.deployment_census(), scale) == census_before


def test_descriptor_registry_bounds_owner_snapshot_graph_neutrally(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Shared admission bounds both descriptor count and cumulative owner text."""

    descriptors = tuple(
        CompiledApplicationDescriptor(
            application_id=f"custom-{ordinal}",
            platform="windows",
            image_path=r"C:\Apps\shared.exe",
            command_templates=(r'"C:\Apps\shared.exe" --flag',),
            categories=("user_app",),
            selection_ordinal=ordinal,
        )
        for ordinal in range(2)
    )
    baseline = DeploymentContentRegistry(application_descriptors=(descriptors[0],))
    census_before = (baseline.census(), baseline.deployment_census(), baseline.scale_census())
    rng = random.Random(8675309)
    rng_before = rng.getstate()
    count_limit = deployment_registry._MAX_APPLICATION_DESCRIPTOR_REGISTRY_COUNT

    monkeypatch.setattr(deployment_registry, "_MAX_APPLICATION_DESCRIPTOR_REGISTRY_COUNT", 1)
    with pytest.raises(ValueError, match="bounded registry count"):
        DeploymentContentRegistry(application_descriptors=descriptors)

    monkeypatch.setattr(
        deployment_registry,
        "_MAX_APPLICATION_DESCRIPTOR_REGISTRY_COUNT",
        count_limit,
    )
    monkeypatch.setattr(
        deployment_registry,
        "_MAX_APPLICATION_DESCRIPTOR_REGISTRY_TEXT_BYTES",
        descriptors[0].retained_text_bytes,
    )
    with pytest.raises(ValueError, match="bounded registry text budget"):
        DeploymentContentRegistry(application_descriptors=descriptors)

    assert rng.getstate() == rng_before
    assert (baseline.census(), baseline.deployment_census(), baseline.scale_census()) == (
        census_before
    )


def test_descriptor_graph_rejects_callback_capable_values_before_virtual_operations() -> None:
    """Only exact inert builtins may enter descriptor normalization or packed ownership."""

    callbacks: list[str] = []

    class HostileString(str):
        def strip(self, *_args: object, **_kwargs: object) -> str:
            callbacks.append("strip")
            raise AssertionError("hostile strip callback ran")

        def __len__(self) -> int:
            callbacks.append("len")
            raise AssertionError("hostile len callback ran")

        def encode(self, *_args: object, **_kwargs: object) -> bytes:
            callbacks.append("encode")
            raise AssertionError("hostile encode callback ran")

        def casefold(self) -> str:
            callbacks.append("casefold")
            raise AssertionError("hostile casefold callback ran")

    class HostileTuple(tuple[object, ...]):
        def __iter__(self) -> Iterator[object]:
            callbacks.append("iter")
            raise AssertionError("hostile iter callback ran")

        def __len__(self) -> int:
            callbacks.append("len")
            raise AssertionError("hostile len callback ran")

        def __getitem__(self, key: object) -> object:
            callbacks.append("getitem")
            raise AssertionError("hostile getitem callback ran")

    base: dict[str, object] = {
        "application_id": "custom_slack",
        "platform": "windows",
        "image_path": r"C:\Custom\custom-slack.exe",
        "command_templates": (r'"C:\Custom\custom-slack.exe" --flag',),
        "categories": ("user_app",),
        "command_parameter_pools": (("tenant", ("blue",)),),
        "singleton_per_session": False,
        "selection_ordinal": 0,
    }
    hostile_text = HostileString("x" * 70_005)
    invalid_overrides: tuple[tuple[str, object], ...] = (
        ("application_id", hostile_text),
        ("platform", HostileString("windows")),
        ("image_path", HostileString(r"C:\Custom\custom-slack.exe")),
        ("command_templates", HostileTuple((base["command_templates"],))),
        ("command_templates", [r'"C:\Custom\custom-slack.exe"']),
        ("command_templates", iter((r'"C:\Custom\custom-slack.exe"',))),
        ("command_templates", (hostile_text,)),
        ("categories", HostileTuple(("user_app",))),
        ("categories", (HostileString("user_app"),)),
        ("command_parameter_pools", HostileTuple((("tenant", ("blue",)),))),
        ("command_parameter_pools", ((HostileString("tenant"), ("blue",)),)),
        ("command_parameter_pools", (("tenant", HostileTuple(("blue",))),)),
        ("command_parameter_pools", (("tenant", (HostileString("blue"),)),)),
    )
    for field_name, value in invalid_overrides:
        values = {**base, field_name: value}
        with pytest.raises(ValueError, match="exact"):
            CompiledApplicationDescriptor(**values)  # type: ignore[arg-type]
    assert callbacks == []

    valid = CompiledApplicationDescriptor(**base)  # type: ignore[arg-type]
    baseline = DeploymentContentRegistry(application_descriptors=(valid,))
    census_before = (baseline.census(), baseline.deployment_census(), baseline.scale_census())
    rng = random.Random(8675309)
    rng_before = rng.getstate()
    object.__setattr__(valid, "command_templates", (hostile_text,))
    with pytest.raises(ValueError, match="exact str"):
        DeploymentContentRegistry(application_descriptors=(valid,))
    assert callbacks == []

    retained = baseline.application_descriptor("custom_slack", "windows")
    assert retained is not None
    assert type(retained.application_id) is str
    assert type(retained.platform) is str
    assert type(retained.image_path) is str
    assert type(retained.command_templates) is tuple
    assert all(type(value) is str for value in retained.command_templates)
    assert type(retained.categories) is tuple
    assert all(type(value) is str for value in retained.categories)
    assert type(retained.command_parameter_pools) is tuple
    assert len(baseline._application_descriptors._rows.get(0)) < 65_536
    assert rng.getstate() == rng_before
    assert (baseline.census(), baseline.deployment_census(), baseline.scale_census()) == (
        census_before
    )


def test_direct_descriptor_rejects_command_image_mismatch_neutrally() -> None:
    """Direct admission shares compiler executable parity before registry publication."""

    valid = CompiledApplicationDescriptor(
        application_id="custom_slack",
        platform="windows",
        image_path=r"C:\Custom\custom-slack.exe",
        command_templates=(r'"C:\Custom\custom-slack.exe" --flag',),
        categories=("user_app",),
    )
    baseline = DeploymentContentRegistry(application_descriptors=(valid,))
    stored_before = baseline.application_descriptor("custom_slack", "windows")
    assert stored_before is not None and stored_before is not valid
    assert copy.copy(stored_before) == stored_before
    assert copy.deepcopy(stored_before) == stored_before
    census_before = (baseline.census(), baseline.deployment_census(), baseline.scale_census())
    rng = random.Random(8675309)
    rng_before = rng.getstate()

    with pytest.raises(ValueError, match="not its declared image"):
        CompiledApplicationDescriptor(
            application_id="custom_slack",
            platform="windows",
            image_path=r"C:\Custom\custom-slack.exe",
            command_templates=("calc.exe --stale",),
            categories=("user_app",),
        )
    with pytest.raises(ValueError, match="not its declared image"):
        CompiledApplicationDescriptor(
            application_id="custom_slack",
            platform="windows",
            image_path=r"C:\Custom\custom-slack.exe",
            command_templates=("C:custom-slack.exe --stale",),
            categories=("user_app",),
        )
    for quoted_command in (
        r"'/opt/acme\bin/tool' --flag",
        r'"/opt/acme\bin/tool" --flag',
    ):
        with pytest.raises(ValueError, match="not its declared image"):
            CompiledApplicationDescriptor(
                application_id="posix_tool",
                platform="linux",
                image_path="/opt/acme/bin/tool",
                command_templates=(quoted_command,),
                categories=("user_app",),
            )
    with pytest.raises(ValueError, match="image_path cannot contain backslashes"):
        CompiledApplicationDescriptor(
            application_id="posix_tool",
            platform="linux",
            image_path=r"/opt/acme\bin/tool",
            command_templates=(r"'/opt/acme\bin/tool' --flag",),
            categories=("user_app",),
        )
    escaped_space = CompiledApplicationDescriptor(
        application_id="posix_tool",
        platform="linux",
        image_path="/opt/acme bin/tool",
        command_templates=(r"/opt/acme\ bin/tool --flag",),
        categories=("user_app",),
    )
    assert escaped_space.executable == "tool"

    tampered_before_admission = CompiledApplicationDescriptor(
        application_id="custom_slack",
        platform="windows",
        image_path=r"C:\Custom\custom-slack.exe",
        command_templates=(r'"C:\Custom\custom-slack.exe" --flag',),
        categories=("user_app",),
    )
    object.__setattr__(tampered_before_admission, "command_templates", ("calc.exe --stale",))
    with pytest.raises(ValueError, match="not its declared image"):
        DeploymentContentRegistry(application_descriptors=(tampered_before_admission,))
    with pytest.raises(ValueError, match="exact CompiledApplicationDescriptor"):
        DeploymentContentRegistry(
            application_descriptors=(object(),),  # type: ignore[arg-type]
        )

    object.__setattr__(valid, "command_templates", ("calc.exe --unexpected",))
    object.__setattr__(valid, "selection_ordinal", 99)
    stored_after = baseline.application_descriptor("custom_slack", "windows")
    assert stored_after is not None and stored_after is not valid
    assert stored_after.command_templates == (r'"C:\Custom\custom-slack.exe" --flag',)
    assert stored_after.selection_ordinal == 0
    assert baseline.application_ids_for_executable(
        "windows",
        "custom-slack.exe",
    ) == ("custom_slack",)
    assert rng.getstate() == rng_before
    assert (baseline.census(), baseline.deployment_census(), baseline.scale_census()) == (
        census_before
    )


def test_direct_registry_rejects_posix_installation_backslashes_neutrally(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """POSIX installation truth cannot collapse a literal backslash into a path separator."""

    release = BinaryReleaseIdentity(
        key=BinaryReleaseKey(
            product_id="posix_tool",
            version="1.0.0",
            build="1",
            architecture="x64",
            platform="linux",
            artifact_name="tool",
            variant="stable",
        )
    )
    profile = UserProfileIdentity(
        hostname="LINUX-01",
        principal="alice",
        platform="linux",
        profile_name="default",
        profile_root="/home/alice",
    )

    def installation(image_path: str) -> SoftwareInstallationIdentity:
        return SoftwareInstallationIdentity(
            hostname="LINUX-01",
            application_id="posix_tool",
            release_id=release.release_id,
            platform="linux",
            scope="user",
            principal="alice",
            user_profile_id=profile.profile_id,
            install_root="/opt/acme",
            image_paths=(image_path,),
        )

    valid_installation = installation("/opt/acme/bin/tool")
    application_profile = ApplicationProfileIdentity(
        hostname="LINUX-01",
        principal="alice",
        platform="linux",
        user_profile_id=profile.profile_id,
        installation_id=valid_installation.installation_id,
        application_id="posix_tool",
        profile_name="default",
        profile_root="/home/alice/.config/posix-tool",
    )
    descriptor = CompiledApplicationDescriptor(
        application_id="posix_tool",
        platform="linux",
        image_path="/opt/acme/bin/tool",
        command_templates=("/opt/acme/bin/tool --user {username}",),
        categories=("user_app",),
    )
    deployment = HostDeploymentSpec(
        hostname="LINUX-01",
        roles=("workstation",),
        platform="linux",
        os_build="ubuntu-24.04",
        architecture="x64",
        installation_ids=(valid_installation.installation_id,),
    )
    assignment_spec = UserApplicationAssignmentSpec(
        hostname="LINUX-01",
        principal="alice",
        platform="linux",
        user_profile_id=profile.profile_id,
        application_profile_id=application_profile.application_profile_id,
        persona="developer",
        eligible_categories=("user_app",),
        intensity=1.0,
    )
    content = FileContentIdentity(
        file_object_id="posix-tool-cache",
        version=1,
        size_bytes=4_096,
        mime_type="application/octet-stream",
        seed_ref="posix-tool-cache",
    )

    def local_artifact(
        native_path: str,
        *,
        source_object_id: str = "cache-entry-1",
    ) -> LocalArtifactIdentity:
        return LocalArtifactIdentity(
            hostname="LINUX-01",
            principal="alice",
            platform="linux",
            user_profile_id=profile.profile_id,
            application_profile_id=application_profile.application_profile_id,
            application_id="posix_tool",
            family="message-cache",
            source_object_id=source_object_id,
            native_path=native_path,
            content_id=content.content_id,
            version=1,
        )

    valid_artifact_path = "/home/alice/.config/posix-tool/cache/entry.bin"
    valid_artifact = local_artifact(valid_artifact_path)
    valid_artifact_binary = LocalArtifactBinaryIdentity(
        artifact_version_id=valid_artifact.artifact_version_id,
        content_id=content.content_id,
        digests=content.digests,
        platform="linux",
        architecture="x64",
        artifact_name="entry.bin",
    )
    valid_artifact_record = LocalArtifactVersionRecord(
        artifact=valid_artifact,
        content=content,
        binary=valid_artifact_binary,
    )

    def compile_registry(
        selected_installation: SoftwareInstallationIdentity,
        selected_profile: UserProfileIdentity = profile,
        selected_artifact: LocalArtifactIdentity = valid_artifact,
    ) -> DeploymentContentRegistry:
        return DeploymentContentRegistry(
            binary_releases=(release,),
            user_profiles=(selected_profile,),
            installations=(selected_installation,),
            application_profiles=(application_profile,),
            application_descriptors=(descriptor,),
            host_deployments=(deployment,),
            user_application_assignments=(assignment_spec,),
            file_contents=(content,),
            local_artifacts=(selected_artifact,),
        )

    source_installation = copy.copy(valid_installation)
    source_artifact = copy.copy(valid_artifact)
    baseline = compile_registry(source_installation, profile, source_artifact)
    object.__setattr__(source_installation, "installation_id", "forged-installation")
    object.__setattr__(source_installation, "image_paths", (r"/opt/acme\bin/tool",))
    object.__setattr__(
        source_artifact,
        "native_path",
        r"/home/alice/.config/posix-tool/cache\entry.bin",
    )
    object.__setattr__(source_artifact, "artifact_id", "forged-artifact")
    object.__setattr__(source_artifact, "artifact_version_id", "forged-version")
    assignment = baseline.user_application_assignment(assignment_spec.assignment_id)
    assert assignment is not None
    baseline_rng = random.Random(8675309)
    expected_rng = random.Random(8675309)
    expected_rng.choice(descriptor.command_templates)
    assert baseline.materialize_application_command(
        baseline_rng,
        assignment,
        username="alice",
    ) == ("/opt/acme/bin/tool", "/opt/acme/bin/tool --user alice")
    assert baseline_rng.getstate() == expected_rng.getstate()
    census_before = (baseline.census(), baseline.deployment_census(), baseline.scale_census())
    retained_artifacts = LocalArtifactVersionRegistry(
        capacity=4,
        retention=timedelta(hours=1),
    )
    observed_at = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)
    retained_artifacts.publish_version(valid_artifact_record, observed_at)
    retained_census_before = retained_artifacts.census()
    assert baseline.application_ids_for_executable("linux", "tool") == ("posix_tool",)
    assert baseline.application_ids_for_executable("linux", "/opt/acme/bin/tool") == ("posix_tool",)
    assert (
        baseline.resolve_binary(
            "LINUX-01",
            "/opt/acme/./bin/tool",
            "linux",
            principal="alice",
        )
        == release
    )
    assert (
        baseline.installation_for_image(
            "LINUX-01",
            "/opt//acme/bin/tool",
            "linux",
            principal="alice",
        )
        == valid_installation
    )
    assert (
        baseline.local_artifact_for_path(
            profile.profile_id,
            application_profile.application_profile_id,
            "/home/alice/.config/posix-tool/cache/./entry.bin",
            "linux",
            1,
        )
        == valid_artifact
    )
    retained_direct_artifact = baseline.local_artifact(valid_artifact.artifact_id, 1)
    assert retained_direct_artifact == valid_artifact
    assert retained_direct_artifact is not source_artifact
    object.__setattr__(
        retained_direct_artifact,
        "native_path",
        r"/home/alice/.config/posix-tool/cache\entry.bin",
    )
    assert baseline.local_artifact(valid_artifact.artifact_id, 1) == valid_artifact
    assert (
        retained_artifacts.get_for_path(
            profile.profile_id,
            application_profile.application_profile_id,
            "/home/alice/.config/posix-tool//cache/entry.bin",
            "linux",
            1,
        )
        == valid_artifact
    )
    assert (
        retained_artifacts.resolve_record_for_execution_path(
            "LINUX-01",
            "alice",
            "/home/alice/.config/posix-tool/cache/./entry.bin",
            "linux",
        )
        == valid_artifact_record
    )
    assert (
        retained_artifacts.resolve_binary_for_path(
            "LINUX-01",
            "alice",
            valid_artifact_path,
            "linux",
        )
        == valid_artifact_binary
    )

    invalid_binary_paths = (
        r"/opt/acme\bin/tool",
        r"/opt/acme/bin\tool",
        r"\opt\acme\bin\tool",
    )
    invalid_artifact_paths = (
        r"/home/alice/.config/posix-tool/cache\entry.bin",
        r"/home/alice/.config/posix-tool\cache/entry.bin",
        r"\home\alice\.config\posix-tool\cache\entry.bin",
    )
    for invalid_path in invalid_binary_paths:
        assert (
            baseline.installation_for_image(
                "LINUX-01",
                invalid_path,
                "linux",
                principal="alice",
            ),
            baseline.resolve_binary(
                "LINUX-01",
                invalid_path,
                "linux",
                principal="alice",
            ),
        ) == (None, None)
        assert baseline.application_ids_for_executable("linux", invalid_path) == ()
    for invalid_path in invalid_artifact_paths:
        assert (
            baseline.local_artifact_for_path(
                profile.profile_id,
                application_profile.application_profile_id,
                invalid_path,
                "linux",
                1,
            ),
            retained_artifacts.get_for_path(
                profile.profile_id,
                application_profile.application_profile_id,
                invalid_path,
                "linux",
                1,
            ),
            retained_artifacts.resolve_record_for_execution_path(
                "LINUX-01",
                "alice",
                invalid_path,
                "linux",
            ),
            retained_artifacts.resolve_binary_for_path(
                "LINUX-01",
                "alice",
                invalid_path,
                "linux",
            ),
        ) == (None, None, None, None)
    assert deployment_compiler._artifact_name(r"/tmp\redis-cli", "linux") == (r"tmp\redis-cli")
    with pytest.raises(ValueError, match="artifact_name must not contain an installation path"):
        BinaryReleaseIdentity(
            key=BinaryReleaseKey(
                product_id="redis",
                version="1.0.0",
                build="1",
                architecture="x64",
                platform="linux",
                artifact_name=deployment_compiler._artifact_name(
                    r"/tmp\redis-cli",
                    "linux",
                ),
                variant="stable",
            )
        )
    rejected_rng = random.Random(8675309)
    rejected_rng_before = rejected_rng.getstate()
    forged_installation = copy.copy(valid_installation)
    object.__setattr__(forged_installation, "installation_id", "forged-installation")
    with pytest.raises(ValueError, match="canonical derived identity"):
        compile_registry(forged_installation)
    for derived_field in ("artifact_id", "artifact_version_id"):
        forged_artifact = copy.copy(valid_artifact)
        object.__setattr__(forged_artifact, derived_field, f"forged-{derived_field}")
        with pytest.raises(ValueError, match="canonical derived identity"):
            compile_registry(valid_installation, profile, forged_artifact)
    with pytest.raises(ValueError, match="POSIX.*image_paths cannot contain backslashes"):
        compile_registry(installation(r"/opt/acme\bin/tool"))
    invalid_artifact = local_artifact(invalid_artifact_paths[0])
    with pytest.raises(ValueError, match="POSIX local artifact native_path"):
        compile_registry(valid_installation, profile, invalid_artifact)
    invalid_artifact_binary = LocalArtifactBinaryIdentity(
        artifact_version_id=invalid_artifact.artifact_version_id,
        content_id=content.content_id,
        digests=content.digests,
        platform="linux",
        architecture="x64",
        artifact_name="entry.bin",
    )
    invalid_artifact_record = LocalArtifactVersionRecord(
        artifact=invalid_artifact,
        content=content,
        binary=invalid_artifact_binary,
    )
    with pytest.raises(StateError, match="POSIX local artifact native_path"):
        retained_artifacts.publish(invalid_artifact, observed_at)
    with pytest.raises(StateError, match="POSIX local artifact native_path"):
        retained_artifacts.publish_version(invalid_artifact_record, observed_at)

    atomic_artifacts = LocalArtifactVersionRegistry(
        capacity=1,
        retention=timedelta(hours=1),
    )
    atomic_artifacts.publish(valid_artifact, observed_at)
    publication_source = local_artifact(
        "/home/alice/.config/posix-tool/cache/entry-2.bin",
        source_object_id="cache-entry-2",
    )
    expected_publication = copy.copy(publication_source)
    expected_publication_id = publication_source.artifact_version_id
    snapshot_ready = Event()
    resume_publication = Event()
    original_canonical_artifact = deployment_registry._canonical_local_artifact_identity

    def pause_after_snapshot(source: object) -> LocalArtifactIdentity:
        canonical = original_canonical_artifact(source)
        if source is publication_source:
            snapshot_ready.set()
            if not resume_publication.wait(timeout=2):
                raise AssertionError("publication snapshot test timed out")
        return canonical

    monkeypatch.setattr(
        deployment_registry,
        "_canonical_local_artifact_identity",
        pause_after_snapshot,
    )
    with ThreadPoolExecutor(max_workers=1) as executor:
        publication = executor.submit(
            atomic_artifacts.publish,
            publication_source,
            observed_at,
        )
        assert snapshot_ready.wait(timeout=2)
        object.__setattr__(publication_source, "native_path", invalid_artifact_paths[0])
        object.__setattr__(publication_source, "artifact_id", "forged-after-snapshot")
        object.__setattr__(publication_source, "artifact_version_id", "forged-after-snapshot")
        resume_publication.set()
        assert publication.result(timeout=2) >= 0
    published = atomic_artifacts.get(expected_publication_id)
    assert published == expected_publication
    assert published is not publication_source
    assert atomic_artifacts.census().live_versions == 1
    for profile_root in ("/home/alice\\", "/home/alice\\/"):
        invalid_profile = UserProfileIdentity(
            hostname="LINUX-01",
            principal="alice",
            platform="linux",
            profile_name="default",
            profile_root=profile_root,
        )
        assert invalid_profile.profile_id == profile.profile_id
        with pytest.raises(ValueError, match="presentation principal must match"):
            compile_registry(valid_installation, invalid_profile)
    assert rejected_rng.getstate() == rejected_rng_before
    assert (baseline.census(), baseline.deployment_census(), baseline.scale_census()) == (
        census_before
    )
    assert retained_artifacts.census() == retained_census_before


def test_assignment_ordinal_must_match_descriptor_before_publication() -> None:
    """Direct assignment order is authenticated against immutable descriptor order."""

    profile = _user_profile("WS-01", "alice")
    release = _windows_release()
    installation = _user_installation(
        release,
        profile,
        r"C:\Users\alice\AppData\Local\slack\slack.exe",
    )
    application_profile = _application_profile(profile, installation)
    descriptor = CompiledApplicationDescriptor(
        application_id="slack",
        platform="windows",
        image_path=r"C:\Users\{username}\AppData\Local\slack\slack.exe",
        command_templates=(
            r'"C:\Users\{username}\AppData\Local\slack\slack.exe" --user {username}',
        ),
        categories=("user_app",),
        selection_ordinal=7,
    )
    deployment = HostDeploymentSpec(
        hostname="WS-01",
        roles=("workstation",),
        platform="windows",
        os_build="22621.3155",
        architecture="x64",
        installation_ids=(installation.installation_id,),
    )

    def assignment_spec(ordinal: int) -> UserApplicationAssignmentSpec:
        return UserApplicationAssignmentSpec(
            hostname="WS-01",
            principal="ALICE",
            platform="windows",
            user_profile_id=profile.profile_id,
            application_profile_id=application_profile.application_profile_id,
            persona="developer",
            eligible_categories=("user_app",),
            intensity=1.0,
            selection_ordinal=ordinal,
        )

    valid_spec = assignment_spec(7)
    baseline = DeploymentContentRegistry(
        binary_releases=(release,),
        user_profiles=(profile,),
        installations=(installation,),
        application_profiles=(application_profile,),
        application_descriptors=(descriptor,),
        host_deployments=(deployment,),
        user_application_assignments=(valid_spec,),
    )
    assignment = baseline.user_application_assignment(valid_spec.assignment_id)
    assert assignment is not None and assignment.selection_ordinal == 7
    census_before = (
        baseline.census(),
        baseline.deployment_census(),
        baseline.assignment_category_index_census(),
        baseline.scale_census(),
    )
    rng = random.Random(8675309)
    rng_before = rng.getstate()

    for forged_ordinal in (6, 8):
        with pytest.raises(ValueError, match="selection_ordinal must match"):
            DeploymentContentRegistry(
                binary_releases=(release,),
                user_profiles=(profile,),
                installations=(installation,),
                application_profiles=(application_profile,),
                application_descriptors=(descriptor,),
                host_deployments=(deployment,),
                user_application_assignments=(assignment_spec(forged_ordinal),),
            )

    tampered_before_admission = CompiledApplicationDescriptor(
        application_id="slack",
        platform="windows",
        image_path=r"C:\Users\{username}\AppData\Local\slack\slack.exe",
        command_templates=(
            r'"C:\Users\{username}\AppData\Local\slack\slack.exe" --user {username}',
        ),
        categories=("user_app",),
        selection_ordinal=7,
    )
    object.__setattr__(tampered_before_admission, "selection_ordinal", 99)
    with pytest.raises(ValueError, match="selection_ordinal must match"):
        DeploymentContentRegistry(
            binary_releases=(release,),
            user_profiles=(profile,),
            installations=(installation,),
            application_profiles=(application_profile,),
            application_descriptors=(tampered_before_admission,),
            host_deployments=(deployment,),
            user_application_assignments=(valid_spec,),
        )

    assert rng.getstate() == rng_before
    assert (
        baseline.census(),
        baseline.deployment_census(),
        baseline.assignment_category_index_census(),
        baseline.scale_census(),
    ) == census_before


def test_release_minimum_deployment_population_preserves_direct_constructor_census() -> None:
    """The exact 11-family release fixture remains valid without compiled descriptors."""

    from scripts.deployment_population_scale_probe import build_deployment_population

    registry = build_deployment_population(11)
    census = registry.census()
    scale = registry.scale_census()

    assert census.application_descriptors == 0
    assert scale.application_descriptor_owner_snapshots == 0
    assert census.application_executable_bindings == 0
    assert scale.physical_records == scale.live_entries == scale.retained_entries == 11
    assert scale.high_water_mark == 11
    assert scale.relationship_bindings == 8
    assert scale.backing_entries == 19
    assert 0 < scale.estimated_index_bytes <= scale.estimated_bytes


@pytest.mark.parametrize(
    "ordinal",
    [True, False, 1.0, float("nan"), float("inf"), float("-inf"), -1],
)
def test_compiled_application_descriptor_rejects_non_exact_ordinals(
    ordinal: object,
) -> None:
    """Catalog ordering accepts only finite, non-negative exact integers."""

    with pytest.raises(ValueError, match="non-negative exact int"):
        CompiledApplicationDescriptor(
            application_id="invalid-ordinal",
            platform="windows",
            image_path=r"C:\Apps\invalid.exe",
            command_templates=(r'"C:\Apps\invalid.exe"',),
            categories=("user_app",),
            selection_ordinal=ordinal,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    "ordinal",
    [True, False, 1.0, float("nan"), float("inf"), float("-inf"), -1],
)
def test_assignment_spec_rejects_non_exact_ordinals(ordinal: object) -> None:
    """Assignment ordering accepts only finite, non-negative exact integers."""

    with pytest.raises(ValueError, match="non-negative exact int"):
        UserApplicationAssignmentSpec(
            hostname="WS-01",
            principal="alice",
            platform="windows",
            user_profile_id="profile-1",
            application_profile_id="application-profile-1",
            persona="developer",
            eligible_categories=("user_app",),
            intensity=1.0,
            selection_ordinal=ordinal,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    "pools",
    [
        (("self", ("{self}",)),),
        (("first", ("{second}",)), ("second", ("{first}",))),
    ],
)
def test_compiled_application_descriptor_rejects_parameter_pool_cycles(
    pools: tuple[tuple[str, tuple[str, ...]], ...],
) -> None:
    """Scoped command parameters cannot recurse directly or mutually."""

    with pytest.raises(ValueError, match="contains a cycle"):
        CompiledApplicationDescriptor(
            application_id="cyclic",
            platform="linux",
            image_path="/usr/bin/tool",
            command_templates=("tool {first}",),
            command_parameter_pools=pools,
            categories=("user_app",),
        )


@pytest.mark.parametrize(
    "pools",
    [
        (("self-cycle", ("{self-cycle}",)),),
        (("first-pool", ("{second-pool}",)), ("second-pool", ("{first-pool}",))),
    ],
)
def test_compiled_application_descriptor_rejects_non_identifier_pool_names(
    pools: tuple[tuple[str, tuple[str, ...]], ...],
) -> None:
    """Invalid placeholder names reject before cycle analysis can recurse."""

    with pytest.raises(ValueError, match="names must match"):
        CompiledApplicationDescriptor(
            application_id="invalid-pool-name",
            platform="linux",
            image_path="/usr/bin/tool",
            command_templates=("tool {self-cycle}",),
            command_parameter_pools=pools,
            categories=("user_app",),
        )


def test_compiled_application_descriptor_rejects_unbounded_expansion() -> None:
    """Acyclic replacement bombs fail before runtime RNG or output allocation."""

    bounded = CompiledApplicationDescriptor(
        application_id="bounded-expansion",
        platform="linux",
        image_path="/usr/bin/tool",
        command_templates=("tool " + ("{value}" * 1_024),),
        command_parameter_pools=(("value", ("x",)),),
        categories=("user_app",),
    )
    assert bounded.command_templates[0].count("{value}") == 1_024

    with pytest.raises(ValueError, match="bounded replacement limit"):
        CompiledApplicationDescriptor(
            application_id="one-too-many-expansions",
            platform="linux",
            image_path="/usr/bin/tool",
            command_templates=("tool " + ("{value}" * 1_025),),
            command_parameter_pools=(("value", ("x",)),),
            categories=("user_app",),
        )

    exponential_pools = tuple(
        (
            f"level_{level}",
            (("x" if level == 0 else f"{{level_{level - 1}}}{{level_{level - 1}}}"),),
        )
        for level in range(11)
    )
    with pytest.raises(ValueError, match="bounded replacement limit"):
        CompiledApplicationDescriptor(
            application_id="expansion-bomb",
            platform="linux",
            image_path="/usr/bin/tool",
            command_templates=("tool {level_10}",),
            command_parameter_pools=exponential_pools,
            categories=("user_app",),
        )

    with pytest.raises(ValueError, match="bounded output length"):
        CompiledApplicationDescriptor(
            application_id="output-bomb",
            platform="linux",
            image_path="/usr/bin/tool",
            command_templates=("tool {payload}",),
            command_parameter_pools=(("payload", ("x" * 65_537,)),),
            categories=("user_app",),
        )

    with pytest.raises(ValueError, match="bounded pool limit"):
        CompiledApplicationDescriptor(
            application_id="pool-count-bomb",
            platform="linux",
            image_path="/usr/bin/tool",
            command_templates=("tool {pool_0}",),
            command_parameter_pools=tuple(
                (f"pool_{ordinal}", ("value",)) for ordinal in range(129)
            ),
            categories=("user_app",),
        )

    with pytest.raises(ValueError, match="reserved name 'username'"):
        CompiledApplicationDescriptor(
            application_id="reserved-pool",
            platform="linux",
            image_path="/usr/bin/tool",
            command_templates=("tool {username}",),
            command_parameter_pools=(("username", ("mallory",)),),
            categories=("user_app",),
        )

    with pytest.raises(ValueError, match="bounded text budget"):
        CompiledApplicationDescriptor(
            application_id="descriptor-text-bomb",
            platform="linux",
            image_path="/usr/bin/tool",
            command_templates=("tool {payload}",),
            command_parameter_pools=(
                (
                    "payload",
                    tuple(f"{ordinal:04d}" + ("x" * 1_020) for ordinal in range(1_025)),
                ),
            ),
            categories=("user_app",),
        )


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
