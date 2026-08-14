# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused contracts for project-overlay discovery, merging, and validation."""

import random
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from evidenceforge.cli.validate_config import (
    ValidationResult,
    _validate_tls_issuer_overrides,
    validate_config,
)
from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import overlay_project_root_scope
from evidenceforge.config.overlay_registry import (
    CONFIG_OVERLAY_FAMILIES,
    config_family_inventory,
)
from evidenceforge.generation.activity.rsat_tools import _merge_rsat
from evidenceforge.generation.activity.tls_issuers import _merge_tls_issuers, pick_issuer


def test_overlay_registry_covers_every_packaged_activity_family() -> None:
    packaged = {f"activity/{path.name}" for path in get_activity_directory().glob("*.yaml")}

    assert set(CONFIG_OVERLAY_FAMILIES) == packaged | {"personas/*.yaml"}


def test_overlay_registry_is_immutable_and_inventory_returns_copies() -> None:
    with pytest.raises(TypeError):
        CONFIG_OVERLAY_FAMILIES["activity/new.yaml"] = CONFIG_OVERLAY_FAMILIES[
            "activity/dns_registry.yaml"
        ]

    inventory = config_family_inventory()
    inventory["activity/dns_registry.yaml"]["summary"] = "changed"

    assert config_family_inventory()["activity/dns_registry.yaml"]["summary"] != "changed"


def test_rsat_overlay_merges_matching_tool_by_id() -> None:
    defaults = {
        "tools": [
            {
                "id": "aduc",
                "snap_in": "dsa.msc",
                "command_line": "mmc.exe dsa.msc",
                "target_ports": [{"port": 389, "service": "ldap"}],
                "weight": 10,
            }
        ]
    }

    merged = _merge_rsat(defaults, {"tools": [{"id": "aduc", "weight": 25}]})

    assert merged["tools"] == [
        {
            "id": "aduc",
            "snap_in": "dsa.msc",
            "command_line": "mmc.exe dsa.msc",
            "target_ports": [{"port": 389, "service": "ldap"}],
            "weight": 25,
        }
    ]


def test_tls_overlay_merges_and_runtime_uses_domain_ca_override(monkeypatch) -> None:
    defaults = {
        "issuers": [
            {
                "name": "Default CA",
                "weight": 100,
                "validity_days_min": 90,
                "validity_days_max": 397,
                "not_before_max_days": 30,
                "key_types": [{"type": "rsa", "length": 2048, "weight": 100}],
            },
            {
                "name": "Project CA",
                "weight": 0,
                "validity_days_min": 90,
                "validity_days_max": 397,
                "not_before_max_days": 30,
                "key_types": [{"type": "rsa", "length": 2048, "weight": 100}],
            },
        ],
        "domain_ca_overrides": {"*.internal": "Default CA"},
    }
    merged = _merge_tls_issuers(
        defaults,
        {
            "domain_ca_overrides": {
                "*.internal": "Project CA",
                "*.corp.example": "Project CA",
            }
        },
    )
    monkeypatch.setattr(
        "evidenceforge.generation.activity.tls_issuers.load_tls_issuers",
        lambda: merged,
    )

    assert merged["domain_ca_overrides"] == {
        "*.internal": "Project CA",
        "*.corp.example": "Project CA",
    }
    assert pick_issuer(random.Random(7), "files.corp.example")["name"] == "Project CA"


def test_tls_override_validation_rejects_unknown_issuer() -> None:
    result = ValidationResult()

    _validate_tls_issuer_overrides(
        result,
        {
            "issuers": [{"name": "Known CA"}],
            "domain_ca_overrides": {"*.corp.example": "Typo CA"},
        },
    )

    assert [issue.message for issue in result.errors] == [
        "domain_ca_overrides['*.corp.example'] references unknown issuer 'Typo CA'"
    ]


def test_validate_config_rejects_top_level_replace_marker(tmp_path: Path) -> None:
    overlay = tmp_path / ".eforge" / "config" / "activity"
    overlay.mkdir(parents=True)
    (overlay / "dns_registry.yaml").write_text("_replace: true\n", encoding="utf-8")

    with overlay_project_root_scope(tmp_path):
        result = validate_config()

    assert any(
        issue.file == "overlay/activity/dns_registry.yaml"
        and 'Unexpected top-level key "_replace"' in issue.message
        for issue in result.errors
    )


@pytest.mark.parametrize(
    ("content", "expected_message"),
    [
        ("domains: [\n", "YAML parse error"),
        ("domains: {}\n", 'Field "domains" should be a list'),
    ],
)
def test_validate_config_preflights_bad_dns_before_merged_scope(
    tmp_path: Path,
    content: str,
    expected_message: str,
) -> None:
    overlay = tmp_path / ".eforge" / "config" / "activity"
    overlay.mkdir(parents=True)
    (overlay / "dns_registry.yaml").write_text(content, encoding="utf-8")
    scope_entered = False

    @contextmanager
    def merged_scope() -> Iterator[None]:
        nonlocal scope_entered
        scope_entered = True
        yield

    with overlay_project_root_scope(tmp_path):
        result = validate_config(merged_scope_factory=merged_scope)

    assert scope_entered is False
    assert result.files_checked == 1
    assert any(
        issue.file == "overlay/activity/dns_registry.yaml" and expected_message in issue.message
        for issue in result.errors
    )
