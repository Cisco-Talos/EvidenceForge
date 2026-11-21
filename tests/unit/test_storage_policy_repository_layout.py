# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT
"""Repository roles bind GUID folders, linked file names and finite populations."""

from copy import deepcopy
from typing import Any
from unittest.mock import Mock

import pytest
from pydantic import ValidationError

from evidenceforge.generation.activity import storage_policy_repository as policy
from evidenceforge.utils.rng import generation_seed_scope


def layout_data() -> dict[str, Any]:
    return {
        "enabled": True,
        "sysvol_root": "SYSVOL\\sysvol",
        "netlogon_root": "SYSVOL\\sysvol\\{domain}\\scripts",
        "gpo_count_minimum": 3,
        "gpo_count_maximum": 6,
        "default_gpo_ids": ["{31B2F340-016D-11D2-945F-00C04FB984F9}"],
        "sysvol_files": [
            {
                "path": "GPT.INI",
                "mime_type": "text/plain",
                "minimum_bytes": 24,
                "maximum_bytes": 128,
                "presence_probability": 1.0,
            },
            {
                "path": "Machine\\Registry.pol",
                "mime_type": "application/octet-stream",
                "minimum_bytes": 128,
                "maximum_bytes": 4096,
                "presence_probability": 0.7,
            },
        ],
        "netlogon_files": [
            {
                "path": "Logon\\Map-Drives.ps1",
                "mime_type": "text/plain",
                "minimum_bytes": 512,
                "maximum_bytes": 4096,
                "presence_probability": 1.0,
            }
        ],
    }


def test_domain_population_is_stable_and_every_modeled_gpo_has_bookkeeping() -> None:
    layout = policy.PolicyRepositoryLayout.model_validate(layout_data())
    with generation_seed_scope(82):
        first = policy.policy_repository_files(
            layout, role="sysvol", domain="EXAMPLE.TEST", scope="study"
        )
        assert first == policy.policy_repository_files(
            layout, role="sysvol", domain="example.test.", scope="study"
        )
        groups = {file.path.split("\\")[2] for file in first}
        assert 3 <= len(groups) <= 6
        assert all(
            any(file.path == f"example.test\\Policies\\{group}\\GPT.INI" for file in first)
            for group in groups
        )
        assert len({file.path.casefold() for file in first}) == len(first)
        assert first != policy.policy_repository_files(
            layout, role="sysvol", domain="different.test", scope="study"
        )
        assert layout.root("netlogon", "example.test") == "SYSVOL\\sysvol\\example.test\\scripts"
        scripts = policy.policy_repository_files(
            layout, role="netlogon", domain="example.test", scope="study"
        )
        assert [file.path for file in scripts] == ["Logon\\Map-Drives.ps1"]


@pytest.mark.parametrize(
    "mutation",
    [
        "null",
        "extra",
        "boolean_count",
        "reverse",
        "duplicate_guid",
        "duplicate_file",
        "optional_gpt",
        "missing_gpt",
        "empty_scripts",
        "nan",
        "boolean_probability",
        "bad_root",
        "escape",
        "absolute",
        "field_path",
    ],
)
def test_malformed_layout_rejects_before_any_catalog_is_compiled(mutation: str) -> None:
    data = deepcopy(layout_data())
    if mutation == "null":
        data = None
    elif mutation == "extra":
        data["typo"] = 1
    elif mutation == "boolean_count":
        data["gpo_count_minimum"] = True
    elif mutation == "reverse":
        data["gpo_count_maximum"] = 2
    elif mutation == "duplicate_guid":
        data["default_gpo_ids"] *= 2
    elif mutation == "duplicate_file":
        data["netlogon_files"] *= 2
    elif mutation == "optional_gpt":
        data["sysvol_files"][0]["presence_probability"] = 0.5
    elif mutation == "missing_gpt":
        data["sysvol_files"][0]["path"] = "Other.ini"
    elif mutation == "empty_scripts":
        data["netlogon_files"] = []
    elif mutation == "nan":
        data["sysvol_files"][0]["presence_probability"] = float("nan")
    elif mutation == "boolean_probability":
        data["sysvol_files"][0]["presence_probability"] = True
    elif mutation == "bad_root":
        data["netlogon_root"] = "SYSVOL\\{domain.__class__}"
    elif mutation == "escape":
        data["sysvol_files"][0]["path"] = "..\\escape.ini"
    elif mutation == "absolute":
        data["sysvol_files"][0]["path"] = "C:\\escape.ini"
    else:
        data["sysvol_files"][0]["path"] = "{domain}\\GPT.INI"
    with pytest.raises(ValidationError):
        policy.PolicyRepositoryLayout.model_validate(data)


def test_guid_collision_fails_in_bounded_work_instead_of_retrying(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    layout = policy.PolicyRepositoryLayout.model_validate(layout_data())
    rng = Mock()
    rng.randint.return_value = 4
    rng.getrandbits.return_value = 0
    monkeypatch.setattr(policy.random, "Random", Mock(return_value=rng))
    with pytest.raises(ValueError, match="identifier collision"):
        policy.policy_repository_files(layout, role="sysvol", domain="example.test", scope="test")
    assert rng.getrandbits.call_count == 3


@pytest.mark.parametrize("domain", ["../escape", "a\\b", "a:b", "bad..domain", "a" * 64 + ".test"])
def test_invalid_domain_cannot_become_a_path_component(domain: str) -> None:
    with pytest.raises(ValueError, match="explicit DNS domain"):
        policy.repository_domain(domain)
