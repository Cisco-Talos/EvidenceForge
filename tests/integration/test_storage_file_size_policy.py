# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Automatic storage size policy owns metadata without overriding explicit truth."""

import random
import statistics
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from evidenceforge.composition.compiler import build_management_effective_config
from evidenceforge.config.provider import effective_config_scope
from evidenceforge.generation.activity.storage_file_sizes import StorageFileSizePolicy
from evidenceforge.generation.storage_world import (
    StorageWorldModel,
    _load_catalog_config,
    _StorageWorldCompiler,
)
from evidenceforge.models.scenario import Scenario
from evidenceforge.utils import load_yaml
from evidenceforge.validation.configuration import ValidationResult, _validate_storage_catalog


def _scenario(scenarios_dir: Path) -> Scenario:
    return Scenario.model_validate(load_yaml(scenarios_dir / "minimal.yaml"))


def _samples(compiler: _StorageWorldCompiler, extension: str, preset: str) -> list[int]:
    rng = random.Random(273)
    return [compiler._file_size(rng, extension, preset) for _ in range(500)]


def test_default_policy_gives_configuration_files_small_nonconstant_support(
    scenarios_dir: Path,
) -> None:
    compiler = _StorageWorldCompiler(_scenario(scenarios_dir))
    ini = _samples(compiler, ".ini", "dc_policy")
    assert 0 < min(ini) < max(ini) <= 65536
    assert statistics.median(ini) < 8192
    for suffix in [".xml", ".pol", ".ps1", ".bat"]:
        assert max(_samples(compiler, suffix, "dc_policy")) <= 1048576
    assert ini == _samples(compiler, ".INI", "dc_policy")


def test_purpose_does_not_make_scripts_packages_or_logs_backup_archives(
    scenarios_dir: Path,
) -> None:
    compiler = _StorageWorldCompiler(_scenario(scenarios_dir))
    script = _samples(compiler, ".ps1", "software")
    package = _samples(compiler, ".exe", "software")
    log = _samples(compiler, ".log", "backup")
    archive = _samples(compiler, ".zip", "backup")
    assert statistics.median(script) < statistics.median(package) / 100
    assert statistics.median(log) < statistics.median(archive) / 100
    assert _samples(compiler, ".ps1", "software") == script


def test_route_specificity_and_custom_catalog_fallback() -> None:
    policy = StorageFileSizePolicy.model_validate(_load_catalog_config()["file_size_policy"])
    assert policy.profile_for(extension=".ZIP", preset="backup") == policy.profiles["backup"]
    assert (
        policy.profile_for(extension=".zip", preset="custom:unknown") == policy.profiles["package"]
    )
    assert (
        policy.profile_for(extension=".unlisted", preset="software") == policy.profiles["package"]
    )
    assert (
        policy.profile_for(extension=".unlisted", preset="custom:unknown")
        == policy.profiles[policy.default_profile]
    )


@pytest.mark.parametrize("mutation", ["null", "reversed", "boolean", "unknown", "suffix", "extra"])
def test_config_validation_rejects_invalid_size_policy(mutation: str) -> None:
    catalog = deepcopy(_load_catalog_config())
    policy = catalog["file_size_policy"]
    if mutation == "null":
        catalog["file_size_policy"] = None
    elif mutation == "reversed":
        policy["profiles"]["ini"].update(minimum_bytes=100, maximum_bytes=99)
    elif mutation == "boolean":
        policy["profiles"]["ini"]["minimum_bytes"] = True
    elif mutation == "unknown":
        policy["extension_profiles"][".ini"] = "missing-profile"
    elif mutation == "suffix":
        policy["extension_profiles"][".INI"] = "ini"
    else:
        policy["extra_field"] = "typo"
    result = ValidationResult()
    _validate_storage_catalog(result, catalog)
    assert result.errors
    assert any("file_size_policy" in issue.message for issue in result.errors)


def test_frozen_legacy_snapshot_keeps_exact_old_draws_and_restores_current_policy(
    scenarios_dir: Path,
    tmp_path: Path,
) -> None:
    current = build_management_effective_config(tmp_path)
    packaged = deepcopy(current.packaged_defaults)
    packaged["activity/storage_catalog.yaml"].pop("file_size_policy")
    legacy = current.model_copy(update={"packaged_defaults": packaged})
    cases = [
        (".txt", "backup", 7.0, 9.2),
        (".ps1", "software", 5.3, 8.2),
        (".ini", "dc_policy", 3.0, 7.1),
        (".zip", "custom", 5.3, 8.2),
        (".vhdx", "custom", 7.0, 9.2),
    ]
    with effective_config_scope(legacy, refresh_legacy_globals=False):
        compiler = _StorageWorldCompiler(_scenario(scenarios_dir))
        assert compiler._file_size_policy is None
        for suffix, preset, low, high in cases:
            actual, historical = random.Random(91), random.Random(91)
            assert [compiler._file_size(actual, suffix, preset) for _ in range(20)] == [
                int(10 ** historical.uniform(low, high)) for _ in range(20)
            ]
            assert actual.getstate() == historical.getstate()
    with effective_config_scope(current, refresh_legacy_globals=False):
        assert (
            max(_samples(_StorageWorldCompiler(_scenario(scenarios_dir)), ".ini", "dc_policy"))
            <= 65536
        )


def test_explicit_oversized_policy_seed_stays_authoritative_and_repeatable(
    scenarios_dir: Path,
) -> None:
    data: dict[str, Any] = load_yaml(scenarios_dir / "minimal.yaml")
    data["environment"]["systems"].append(
        {
            "hostname": "FS-01",
            "ip": "10.0.0.20",
            "os": "Windows Server 2022",
            "type": "server",
        }
    )
    data["environment"]["storage"] = {
        "population": "small",
        "servers": [
            {
                "system": "FS-01",
                "presets": [],
                "volumes": [{"id": "data", "mount": "D:\\"}],
                "shares": [
                    {
                        "id": "policies",
                        "name": "Policies",
                        "volume": "data",
                        "preset": "dc_policy",
                        "seed_files": [
                            {
                                "ref": "large-config",
                                "path": "Policies\\custom.ini",
                                "size_bytes": 16777216,
                            }
                        ],
                    }
                ],
            }
        ],
    }
    scenario = Scenario.model_validate(data)
    first, second = StorageWorldModel.compile(scenario), StorageWorldModel.compile(scenario)
    seeded = first.select("FS-01.policies", file_ref="large-config")[0]
    assert seeded.size_bytes == 16777216
    assert first.files_by_id == second.files_by_id
    automatic = [file for file in first.share("FS-01.policies").files if file.seed_ref is None]
    assert automatic
    assert all(file.size_bytes <= 1048576 for file in automatic)
