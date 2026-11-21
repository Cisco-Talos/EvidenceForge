# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT
"""Purpose-aware policy configuration remains optional in immutable snapshots."""

from copy import deepcopy
from pathlib import Path

import pytest

from evidenceforge.composition.compiler import build_management_effective_config
from evidenceforge.config.provider import effective_config_scope
from evidenceforge.generation.storage_world import StorageWorldModel, _load_catalog_config
from evidenceforge.validation.configuration import ValidationResult, _validate_storage_catalog
from tests.integration.test_storage_policy_repository import policy_scenario


def test_legacy_absence_and_disabled_policy_preserve_identical_world(
    scenarios_dir: Path, tmp_path: Path
) -> None:
    current = build_management_effective_config(tmp_path)
    scenario = policy_scenario(scenarios_dir)
    packaged = deepcopy(current.packaged_defaults)
    packaged["activity/storage_catalog.yaml"].pop("policy_repository")
    legacy = current.model_copy(update={"packaged_defaults": packaged})
    with effective_config_scope(legacy, refresh_legacy_globals=False):
        old = StorageWorldModel.compile(scenario).manifest()
        assert StorageWorldModel.compile(scenario).share("DC-1.sysvol").root == "SYSVOL"
    packaged = deepcopy(current.packaged_defaults)
    packaged["activity/storage_catalog.yaml"]["policy_repository"]["enabled"] = False
    disabled = current.model_copy(update={"packaged_defaults": packaged})
    with effective_config_scope(disabled, refresh_legacy_globals=False):
        assert StorageWorldModel.compile(scenario).manifest() == old
    with effective_config_scope(current, refresh_legacy_globals=False):
        assert StorageWorldModel.compile(scenario).share("DC-1.sysvol").root == "SYSVOL\\sysvol"


@pytest.mark.parametrize("mutation", ["null", "empty", "typo", "escape", "boolean"])
def test_malformed_repository_policy_has_named_validation_issue(mutation: str) -> None:
    catalog = deepcopy(_load_catalog_config())
    if mutation == "null":
        catalog["policy_repository"] = None
    elif mutation == "empty":
        catalog["policy_repository"] = {}
    elif mutation == "typo":
        catalog["policy_repository"]["unknown"] = 1
    elif mutation == "escape":
        catalog["policy_repository"]["sysvol_files"][0]["path"] = "..\\bad.ini"
    else:
        catalog["policy_repository"]["gpo_count_maximum"] = True
    result = ValidationResult()
    _validate_storage_catalog(result, catalog)
    assert any("policy_repository" in issue.message for issue in result.errors)
