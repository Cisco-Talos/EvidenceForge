# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Mac activity overlays use the same partial-merge and frozen-run semantics."""

from pathlib import Path

from evidenceforge.composition.compiler import build_management_effective_config
from evidenceforge.config.overlay import overlay_project_root_scope
from evidenceforge.config.provider import effective_config_scope
from evidenceforge.generation.activity.spawn_rules import get_parent_config
from evidenceforge.validation.configuration import validate_config


def test_mac_spawn_overlay_is_valid_frozen_and_preserves_other_platforms(tmp_path: Path) -> None:
    defaults = build_management_effective_config(tmp_path)
    with effective_config_scope(defaults):
        windows = get_parent_config("windows", "explorer.exe")
        linux = get_parent_config("linux", "bash")
        terminal = get_parent_config("macos", "Terminal")
    path = tmp_path / ".eforge/config/activity/spawn_rules.yaml"
    path.parent.mkdir(parents=True)
    path.write_text("macos:\n  Terminal:\n    lifetime: short\n")
    selected = build_management_effective_config(tmp_path)
    with overlay_project_root_scope(tmp_path), effective_config_scope(selected):
        assert not validate_config().errors
        assert get_parent_config("macos", "Terminal") == terminal | {"lifetime": "short"}
        assert get_parent_config("windows", "explorer.exe") == windows
        assert get_parent_config("linux", "bash") == linux
        with effective_config_scope(defaults):
            assert get_parent_config("macos", "Terminal") == terminal
        assert get_parent_config("macos", "Terminal")["lifetime"] == "short"
    path.write_text("macos:\n  Terminal:\n    lifetime: long\n")
    with effective_config_scope(selected):
        assert get_parent_config("macos", "Terminal")["lifetime"] == "short"


def test_misspelled_mac_spawn_platform_remains_a_validation_error(tmp_path: Path) -> None:
    path = tmp_path / ".eforge/config/activity/spawn_rules.yaml"
    path.parent.mkdir(parents=True)
    path.write_text("macoss:\n  Terminal:\n    lifetime: short\n")
    with overlay_project_root_scope(tmp_path):
        result = validate_config()
    assert any("macoss" in issue.message for issue in result.errors)
