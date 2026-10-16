# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Explicit Mach-O facts survive canonical deployment and correlated request identity."""

import json
from dataclasses import replace
from uuid import UUID

import pytest

from evidenceforge.events.content_identity import BinaryReleaseIdentity, MachOImageIdentity
from evidenceforge.generation.deployment_compiler import _intern_release
from evidenceforge.generation.deployment_registry import (
    DeploymentContentRegistry,
    _pack_binary_release,
    _unpack_binary_release,
)
from evidenceforge.models.exceptions import StateError
from tests.unit.test_macos_code_signature import _application, _network_request, _release


def test_image_uuid_is_explicit_and_independent_of_signing_content_and_installation() -> None:
    app = _application()
    release = _release(app)
    assert release.mach_o_image is None
    image = MachOImageIdentity.derive(release.key)
    binary = replace(release, mach_o_image=image)
    assert binary.content_id == release.content_id
    assert binary.release_id == release.release_id
    assert binary.digests == release.digests
    assert image.build_uuid.replace("-", "") != binary.digests.md5
    assert UUID(image.build_uuid).version == 4
    moved = app.model_copy(deep=True)
    moved.platforms[
        "macos"
    ].image_path = "/Users/casey/Applications/Example.app/Contents/MacOS/Example"
    assert MachOImageIdentity.derive(_release(moved).key) == image
    assert replace(binary, code_signature=None).mach_o_image == image
    for field, value in (
        ("version", "2"),
        ("build", "2"),
        ("artifact_name", "Worker"),
        ("variant", "debug"),
    ):
        assert MachOImageIdentity.derive(replace(binary.key, **{field: value})) != image


@pytest.mark.parametrize("signed", [False, True])
def test_image_metadata_roundtrips_packed_registry_and_authenticates_network_identity(
    signed: bool,
) -> None:
    release = _release(_application())
    if not signed:
        release = replace(release, code_signature=None)
    binary = replace(release, mach_o_image=MachOImageIdentity.derive(release.key))
    packed = _pack_binary_release(binary)
    assert len(json.loads(packed)) == 16
    restored = _unpack_binary_release(packed)
    assert restored == binary
    registry = DeploymentContentRegistry(binary_releases=iter([binary]))
    assert registry.binary_release_by_content_id(binary.content_id) == binary
    assert _network_request(restored).stable_id == _network_request(binary).stable_id
    assert _network_request(release).stable_id != _network_request(binary).stable_id
    changed = replace(
        binary, mach_o_image=MachOImageIdentity("12345678-1234-4234-8234-123456789ABC")
    )
    assert _network_request(changed).stable_id != _network_request(binary).stable_id


def test_metadata_interning_enriches_absence_and_rejects_conflicting_same_release_images() -> None:
    release = _release(_application())
    binary = replace(release, mach_o_image=MachOImageIdentity.derive(release.key))
    releases = {release.canonical_key: replace(release, code_signature=None)}
    assert _intern_release(releases, binary) == binary
    assert _intern_release(releases, release) == binary
    conflict = replace(
        binary, mach_o_image=MachOImageIdentity("12345678-1234-4234-8234-123456789ABC")
    )
    with pytest.raises(ValueError, match="contradictory mach_o_image"):
        _intern_release(releases, conflict)
    assert releases[release.canonical_key] == binary


@pytest.mark.parametrize(
    "platform,architecture",
    [("windows", "arm64"), ("linux", "arm64"), ("macos", "x64"), ("macos", "neutral")],
)
def test_native_image_facts_reject_foreign_or_unsupported_architectures(
    platform: str, architecture: str
) -> None:
    key = replace(_release(_application()).key, platform=platform, architecture=architecture)
    with pytest.raises(ValueError, match="native macOS arm64"):
        MachOImageIdentity.derive(key)
    with pytest.raises(ValueError, match="native binary architecture"):
        BinaryReleaseIdentity(
            key, mach_o_image=MachOImageIdentity("12345678-1234-4234-8234-123456789ABC")
        )


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "0" * 32,
        "00000000-0000-0000-0000-000000000000",
        "{12345678-1234-4234-8234-123456789abc}",
    ],
)
def test_native_image_uuid_does_not_silently_accept_unknown_or_noncanonical_values(
    value: object,
) -> None:
    with pytest.raises(ValueError, match="UUID"):
        MachOImageIdentity(value)


@pytest.mark.parametrize(
    "field,value",
    [
        (3, "x64"),
        (4, "linux"),
        (15, None),
        (15, ["bad", "arm64"]),
        (15, ["12345678-1234-4234-8234-123456789ABC", "x64"]),
    ],
)
def test_packed_image_recovery_rejects_corrupt_native_facts(field: int, value: object) -> None:
    release = _release(_application())
    binary = replace(release, mach_o_image=MachOImageIdentity.derive(release.key))
    packed = json.loads(_pack_binary_release(binary))
    packed[field] = value
    with pytest.raises(StateError, match="Mach-O image"):
        _unpack_binary_release(json.dumps(packed).encode())


def test_absent_image_keeps_existing_registry_row_shapes_and_network_ids() -> None:
    release = _release(_application())
    assert len(json.loads(_pack_binary_release(release))) == 15
    unsigned = replace(release, code_signature=None)
    assert len(json.loads(_pack_binary_release(unsigned))) == 14
    for binary in (release, unsigned):
        restored = _unpack_binary_release(_pack_binary_release(binary))
        assert restored.mach_o_image is None
        assert restored == binary
        assert _network_request(restored).stable_id == _network_request(binary).stable_id
