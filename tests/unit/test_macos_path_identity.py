# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Modeled Mac filenames retain literal backslashes through durable identity owners."""

import shlex
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.events.content_identity import (
    BinaryReleaseIdentity,
    BinaryReleaseKey,
    SoftwareInstallationIdentity,
    canonical_native_path,
)
from evidenceforge.generation.actions.command_effects import (
    ExecutionEffectPlanError,
    FileEffectAction,
)
from evidenceforge.generation.actions.endpoint_effects import PreparedFileEffectPayload
from evidenceforge.generation.checkpoints import LocalArtifactVersionRegistryParticipant
from evidenceforge.generation.deployment_registry import (
    CompiledApplicationDescriptor,
    DeploymentContentRegistry,
    LocalArtifactVersionRegistry,
)
from evidenceforge.generation.runtime_content import (
    RuntimeArtifactDescriptor,
    RuntimeContentIdentityManager,
)

_PATHS = (r"/Users/casey/Downloads/tool\run", "/Users/casey/Downloads/tool/run")


def _descriptor(path: str, label: str) -> RuntimeArtifactDescriptor:
    return RuntimeArtifactDescriptor(
        hostname="MAC-01",
        principal="casey",
        platform="macos",
        user_profile_id="profile-casey",
        application_profile_id="profile-downloads",
        application_id="browser",
        family="download",
        source_object_id=label,
        native_path=path,
        file_object_id=f"content-{label}",
        content_version=1,
        artifact_version=1,
        size_bytes=8192,
        mime_type="application/x-mach-binary",
        seed_ref=f"payload-{label}",
        executable=True,
        architecture="arm64",
    )


def test_mac_path_keys_preserve_literal_components_and_legacy_platform_behavior() -> None:
    assert canonical_native_path(_PATHS[0], "macos") == _PATHS[0]
    assert canonical_native_path(_PATHS[0], "macos") != canonical_native_path(_PATHS[1], "macos")
    assert canonical_native_path("/Users/casey/./Downloads/tool/../run", "macos") == (
        "/Users/casey/Downloads/run"
    )
    assert canonical_native_path("/Users/Casey/Downloads/run", "macos") != (
        canonical_native_path("/Users/casey/Downloads/run", "macos")
    )
    assert canonical_native_path(r"/opt/tool\run", "linux") == "/opt/tool/run"
    assert canonical_native_path("C:/Tools/Run.exe", "windows") == r"c:\tools\run.exe"


def test_mac_runtime_paths_do_not_alias_across_publication_checkpoint_and_expiry() -> None:
    now = datetime(2026, 10, 16, 12, tzinfo=UTC)
    registry = LocalArtifactVersionRegistry(capacity=4)
    manager = RuntimeContentIdentityManager(registry)
    tokens = []
    for index, path in enumerate(_PATHS):
        token = manager.prepare_publication(
            _descriptor(path, str(index)), now, retention=timedelta(minutes=index + 1)
        )
        assert token.record.binary.artifact_name == path.rsplit("/", 1)[1]
        PreparedFileEffectPayload(
            path=path, action=FileEffectAction.CREATE, artifact_publication=token
        )
        with pytest.raises(ExecutionEffectPlanError, match="path drifted"):
            PreparedFileEffectPayload(
                path=_PATHS[1 - index],
                action=FileEffectAction.CREATE,
                artifact_publication=token,
            )
        with registry.prepared_publication(token) as publication:
            publication.commit()
        # Completed transaction receipts are transient and must leave the barrier.
        del publication
        tokens.append(token)

    seal = LocalArtifactVersionRegistryParticipant(registry).prepare_checkpoint(0)
    restored = LocalArtifactVersionRegistry(capacity=4)
    LocalArtifactVersionRegistryParticipant(restored).restore_checkpoint(seal.head.payload, ())
    for owner in (manager, RuntimeContentIdentityManager(restored)):
        for token, path in zip(tokens, _PATHS, strict=True):
            assert owner.resolve_record("MAC-01", "casey", path, "macos") == token.record
        assert owner.resolve_record("MAC-01", "other", _PATHS[0], "macos") is None
        assert owner.resolve_record("MAC-02", "casey", _PATHS[0], "macos") is None
    assert tokens[0].record.content.content_id != tokens[1].record.content.content_id
    # Evicting one path must not disturb the other path's index entry.
    assert RuntimeContentIdentityManager(restored).advance_watermark(
        now + timedelta(seconds=90)
    ) == (tokens[0].record.artifact.artifact_version_id,)
    assert (
        RuntimeContentIdentityManager(restored).resolve_record(
            "MAC-01", "casey", _PATHS[1], "macos"
        )
        == tokens[1].record
    )


def test_mac_release_and_compiled_installation_retain_exact_literal_filename() -> None:
    releases = tuple(
        BinaryReleaseIdentity(
            BinaryReleaseKey("example", "1", "1", "arm64", "macos", path.rsplit("/", 1)[1])
        )
        for path in _PATHS
    )
    installation = SoftwareInstallationIdentity(
        hostname="MAC-01",
        application_id="example",
        release_id=releases[0].release_id,
        platform="macos",
        scope="machine",
        image_paths=_PATHS,
    )
    descriptor = CompiledApplicationDescriptor(
        application_id="example",
        platform="macos",
        image_path=_PATHS[0],
        command_templates=(shlex.quote(_PATHS[0]),),
        categories=("user_app",),
    )
    registry = DeploymentContentRegistry(
        binary_releases=iter(releases),
        installations=iter([installation]),
        application_descriptors=(descriptor,),
    )
    for path, release in zip(_PATHS, releases, strict=True):
        assert registry.resolve_binary("MAC-01", path, "macos") == release
    assert registry.application_descriptor("example", "macos").executable == r"tool\run"
    with pytest.raises(ValueError, match="not its declared image"):
        replace(descriptor, command_templates=(shlex.quote(_PATHS[1]),))
    with pytest.raises(ValueError, match="installation path"):
        replace(releases[0].key, artifact_name="tool/run")
    for platform in ("windows", "linux"):
        with pytest.raises(ValueError, match="installation path"):
            replace(releases[0].key, platform=platform)
