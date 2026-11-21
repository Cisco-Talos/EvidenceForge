# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT
"""Presented APFS root identities differ from ordinary allocated directories."""

from evidenceforge.generation.activity.macos_execution_metadata import (
    load_macos_execution_metadata_profile,
)
from evidenceforge.generation.identity import IdentityDirectory
from evidenceforge.generation.macos_execution_metadata import MacosExecutionMetadataProducer
from evidenceforge.utils.time import resolve_time_window
from tests.unit.test_macos_installed_provisioning import _compile, _deployments, _scenario


def test_modeled_presented_root_has_reserved_identity_without_rebasing_home() -> None:
    scenario = _scenario(two_macs=True)
    start, end = resolve_time_window(scenario.time_window)
    deployments = _deployments(scenario)
    installed = _compile(scenario, deployments)
    assert installed is not None
    profile = load_macos_execution_metadata_profile()
    assert profile is not None
    producer = MacosExecutionMetadataProducer(
        installed.filesystem,
        IdentityDirectory.from_scenario(scenario),
        profile,
        window_start=start,
        window_end=end,
    )
    roots = []
    for host in ("MAC-01", "MAC-02"):
        root = producer.directory(host, "/", start)
        home = producer.directory(host, "/Users/alex", start)
        assert root.metadata.inode == 2
        assert profile.directory_inode_range.min <= home.metadata.inode
        assert home.metadata.inode <= profile.directory_inode_range.max
        assert root.metadata.device == home.metadata.device
        assert root.metadata.file_object_id != home.metadata.file_object_id
        roots.append(root.metadata)
    assert roots[0].file_object_id != roots[1].file_object_id


def test_missing_root_policy_keeps_legacy_allocation() -> None:
    scenario = _scenario()
    start, end = resolve_time_window(scenario.time_window)
    deployments = _deployments(scenario)
    installed = _compile(scenario, deployments)
    assert installed is not None
    profile = load_macos_execution_metadata_profile()
    assert profile is not None
    data = profile.model_dump()
    data.pop("filesystem_root_identity", None)
    legacy = type(profile).model_validate(data)
    provider = MacosExecutionMetadataProducer(
        installed.filesystem,
        IdentityDirectory.from_scenario(scenario),
        legacy,
        window_start=start,
        window_end=end,
    )
    root = provider.directory("MAC-01", "/", start)
    assert legacy.directory_inode_range.min <= root.metadata.inode
    assert root.metadata.inode <= legacy.directory_inode_range.max


def test_reserved_root_cannot_alias_an_installed_file() -> None:
    import pytest

    from evidenceforge.generation.macos_installed_filesystem import MacosInstalledFilesystem
    from evidenceforge.models.exceptions import StateError
    from tests.unit.test_macos_installed_es_preparation import _setup
    from tests.unit.test_macos_installed_filesystem import _spec, _volume

    _state, deployments, process, _collection = _setup()
    filesystem = MacosInstalledFilesystem(
        deployments,
        volumes=(_volume(process.hostname, first_inode=2),),
        files=(_spec(deployments, process),),
    )
    with pytest.raises(StateError, match="overlaps an installed file"):
        filesystem.directory_volume(process.hostname, 1_000_000, reserved_inode=2)
    # Legacy ordinary-directory allocation remains valid in the same file world.
    assert filesystem.directory_volume(process.hostname, 1_000_000).first_inode == 2


def test_root_policy_rejects_unknown_roles_and_overlapping_ranges() -> None:
    import pytest
    from pydantic import ValidationError

    profile = load_macos_execution_metadata_profile()
    assert profile is not None
    for changes in (
        {"filesystem_root_identity": "all-roots-are-random"},
        {
            "filesystem_root_identity": "apfs_presented_root",
            "directory_inode_range": {"min": 1, "max": 3},
        },
    ):
        with pytest.raises(ValidationError):
            type(profile).model_validate(profile.model_dump() | changes)
