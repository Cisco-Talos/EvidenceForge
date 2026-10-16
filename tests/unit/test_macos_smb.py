# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Mac SMB admission follows existing mapping and profile semantics."""

from pathlib import Path

import pytest

from evidenceforge.config.schemas import SmbProfilesConfig
from evidenceforge.generation.activity.smb_profiles import (
    advertised_filesystem_default,
    client_process_for_operation,
    load_smb_profiles,
    select_client_profile,
    select_server_profile,
)
from evidenceforge.generation.storage_world import StorageWorldModel
from evidenceforge.models.scenario import Scenario
from evidenceforge.validation import ScenarioValidator
from tests.support.macos_smb import macos_smb_scenario


def test_mac_smb_profile_has_native_operation_actors_and_no_transport_pid() -> None:
    profile = select_client_profile("macos", ["cifs-utils"], system_type="workstation")
    assert profile.os_category == "macos"
    assert profile.access_mode == profile.path_style == "mounted"
    assert profile.transport_attribution == "none"
    for operation, image in {
        "browse": "/bin/ls",
        "read": "/bin/cat",
        "create": "/usr/bin/tee",
        "update": "/usr/bin/tee",
        "copy": "/bin/cp",
        "move": "/bin/mv",
        "delete": "/bin/rm",
    }.items():
        actor = client_process_for_operation(profile, operation)
        assert actor is not None and actor.image == image
        assert actor.lifecycle == "operation"


def test_old_smb_profiles_remain_valid_and_mac_serving_remains_unavailable() -> None:
    data = load_smb_profiles().model_dump()
    data["client_defaults"].pop("macos")
    data["client_profiles"].pop("macos_smb_mount")
    assert SmbProfilesConfig.model_validate(data).schema_version == 1
    with pytest.raises(ValueError, match="macOS SMB serving"):
        select_server_profile("macos")
    with pytest.raises(ValueError, match="macOS SMB serving"):
        advertised_filesystem_default("macos", "xfs")


@pytest.mark.parametrize("server_platform", ["windows", "linux"])
def test_mac_mount_compilation_and_validation_preserve_server_ownership(
    scenarios_dir: Path, server_platform: str
) -> None:
    scenario = macos_smb_scenario(scenarios_dir, server_platform=server_platform)
    world = StorageWorldModel.compile(scenario)
    assert world.mappings[0].mount == "/Volumes/team"
    assert world.volumes[0].platform == server_platform
    assert world.manifest()["mappings"][0]["presentations"] == [
        {"platform": "macos", "type": "mount", "root": "/Volumes/team"}
    ]
    issues = ScenarioValidator(scenario).validate()
    errors = [item for item in issues if item.severity == "error"]
    assert not errors, errors
    assert not any("expects formats" in item.message for item in issues)


def test_mixed_posix_mount_audience_requires_existing_explicit_mount_field(
    scenarios_dir: Path,
) -> None:
    data = macos_smb_scenario(scenarios_dir, server_platform="linux").model_dump()
    mapping = data["environment"]["storage"]["mappings"][0]
    mapping["audience"]["systems"].append("FS-TEST")
    with pytest.raises(ValueError, match="explicit mount"):
        StorageWorldModel.compile(Scenario.model_validate(data))
    mapping["mount"] = "/shared/team"
    world = StorageWorldModel.compile(Scenario.model_validate(data))
    assert world.mappings[0].mount == "/shared/team"


@pytest.mark.parametrize("client_access", ["windows_native", "cifs_mount", "smbclient"])
def test_mac_cannot_inherit_another_platform_client_mode(
    scenarios_dir: Path, client_access: str
) -> None:
    data = macos_smb_scenario(scenarios_dir).model_dump()
    data["storyline"][0]["events"][0]["client_access"] = client_access
    errors = [
        item
        for item in ScenarioValidator(Scenario.model_validate(data)).validate()
        if item.severity == "error"
    ]
    assert any("macOS SMB clients require" in item.message for item in errors)
