# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Native source data follows existing overlay and immutable provider contracts."""

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from evidenceforge.composition.compiler import build_management_effective_config
from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import overlay_project_root_scope
from evidenceforge.config.provider import effective_config_scope
from evidenceforge.config.schemas import MacosUnifiedLogProfilesConfig
from evidenceforge.generation.activity.macos_unified_log_profiles import (
    load_macos_unified_log_profiles,
    workspace_request_callsite,
)
from evidenceforge.validation.configuration import validate_config

_SUBPATH = "activity/macos_unified_log_profiles.yaml"


def _document() -> dict:
    return yaml.safe_load(
        (get_activity_directory() / "macos_unified_log_profiles.yaml").read_text()
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("format_string_offset", 2**31),
        ("format_string_offset", True),
        ("program_counter", 3),
        ("program_counter", -4),
        ("program_counter", 2**32),
        ("message_type", "Notice"),
        ("has_rules", 1),
        ("message", "bad\x00"),
        ("subsystem", ""),
        ("collector_enabled", True),
    ],
)
def test_native_profile_rejects_invalid_or_unimplemented_values(field: str, value: object) -> None:
    data = _document()
    data["workspace_request"][field] = value
    with pytest.raises(ValidationError):
        MacosUnifiedLogProfilesConfig.model_validate(data)


@pytest.mark.parametrize("value", [0, -1, True, "125", 2**32])
def test_native_profile_requires_explicit_typed_timebase(value: object) -> None:
    data = _document()
    data["mach_timebase"]["numerator"] = value
    with pytest.raises(ValidationError):
        MacosUnifiedLogProfilesConfig.model_validate(data)


def test_native_profile_deep_overlay_and_nested_provider_restore(tmp_path: Path) -> None:
    defaults = build_management_effective_config(tmp_path)
    path = tmp_path / ".eforge" / "config" / _SUBPATH
    path.parent.mkdir(parents=True)
    path.write_text("workspace_request:\n  program_counter: 69632\n", encoding="utf-8")
    selected = build_management_effective_config(tmp_path)
    with effective_config_scope(selected):
        profile = load_macos_unified_log_profiles()
        assert workspace_request_callsite().program_counter == 69632
        assert profile.workspace_request.format_string_offset == 131072
        with effective_config_scope(defaults):
            assert workspace_request_callsite().program_counter == 65536
        assert load_macos_unified_log_profiles() is profile
    # A later disk edit cannot change the already resolved run's values.
    path.write_text("workspace_request:\n  program_counter: 73728\n", encoding="utf-8")
    with effective_config_scope(selected):
        assert workspace_request_callsite().program_counter == 69632


def test_validate_config_reports_native_profile_errors_through_existing_diagnostics(
    tmp_path: Path,
) -> None:
    path = tmp_path / ".eforge" / "config" / _SUBPATH
    path.parent.mkdir(parents=True)
    path.write_text("workspace_request:\n  program_counter: 3\n", encoding="utf-8")
    config = build_management_effective_config(tmp_path)
    with overlay_project_root_scope(tmp_path), effective_config_scope(config):
        result = validate_config()
    assert any(
        issue.file == "macos_unified_log_profiles.yaml" and "program_counter" in issue.message
        for issue in result.errors
    )


def test_old_inputs_need_no_native_profile_fields(tmp_path: Path) -> None:
    config = build_management_effective_config(tmp_path)
    with effective_config_scope(config):
        profile = load_macos_unified_log_profiles()
        assert profile.profile == "macos27-workspace-entry-v1"
        assert profile.mach_timebase.numerator == 125
        assert profile.mach_timebase.denominator == 3
        assert workspace_request_callsite().trace_id & 255 == 4
    assert not (tmp_path / ".eforge").exists()
