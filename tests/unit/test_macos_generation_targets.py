# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Authored targets require an active generation profile, regardless of outputs."""

from pathlib import Path

import pytest

from evidenceforge.generation.activity.macos_endpoint_security_profiles import (
    load_macos_endpoint_security_profiles,
)
from evidenceforge.generation.engine import GenerationEngine
from evidenceforge.models.exceptions import StateError
from evidenceforge.validation.schema import ScenarioValidator
from tests.unit.test_macos_installed_provisioning import _scenario


@pytest.mark.parametrize(
    "format_name", ["ecar", "zsh_history", "macos_unified_log", "macos_endpoint_security"]
)
@pytest.mark.parametrize("os_name", ["macOS 26", "macOS 26.1", "macOS 28", "Darwin 25", "macOS"])
def test_unsupported_mac_target_fails_independently_of_output(
    format_name: str, os_name: str
) -> None:
    scenario = _scenario()
    scenario.environment.systems[0].os = os_name
    scenario.output.logs = [{"format": format_name}]
    issues = ScenarioValidator(scenario).validate()
    findings = [issue for issue in issues if "Unsupported macOS generation target" in issue.message]
    assert len(findings) == 1
    assert findings[0].severity == "error"
    assert findings[0].field_path == "environment.systems.0.os"
    assert "macOS 27 arm64 workstation" in findings[0].suggestion


@pytest.mark.parametrize("os_name", ["macOS 27", "macOS 27.0", "macOS 27.1.2"])
def test_active_mac_target_passes_target_validation(os_name: str) -> None:
    scenario = _scenario()
    scenario.environment.systems[0].os = os_name
    issues = ScenarioValidator(scenario).validate()
    assert not [issue for issue in issues if "Unsupported macOS generation target" in issue.message]


def test_active_catalog_contains_only_mac27() -> None:
    catalog = load_macos_endpoint_security_profiles()
    assert catalog is not None
    assert [(profile.os_major, profile.architecture) for profile in catalog.profiles] == [
        (27, "arm64")
    ]


def test_supported_sibling_does_not_make_a_retired_mac_target_valid() -> None:
    scenario = _scenario(two_macs=True)
    scenario.environment.systems[0].os = "macOS 26"
    scenario.output.logs = [{"format": "macos_endpoint_security"}]
    findings = [
        issue
        for issue in ScenarioValidator(scenario).validate()
        if "Unsupported macOS generation target" in issue.message
    ]
    assert len(findings) == 1
    assert findings[0].field_path == "environment.systems.0.os"


@pytest.mark.parametrize("format_name", ["ecar", "macos_endpoint_security"])
def test_engine_rejects_retired_target_before_process_activation(
    tmp_path: Path, format_name: str
) -> None:
    scenario = _scenario()
    scenario.environment.systems[0].os = "macOS 26"
    scenario.output.logs = [{"format": format_name}]
    engine = GenerationEngine(scenario, tmp_path)
    with pytest.raises(StateError, match="Unsupported macOS generation target"):
        engine._initialize()
    assert not engine.state_manager.get_processes_on_system("MAC-01")
