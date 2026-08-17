# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for additive Scenario 2.0 deployment overrides."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from evidenceforge.models.scenario import Environment, HostDeploymentOverride, System


def _environment(**updates: object) -> Environment:
    data: dict[str, object] = {
        "description": "Deployment override model test",
        "users": [
            {
                "username": "analyst",
                "full_name": "Case Analyst",
                "email": "analyst@example.test",
            }
        ],
        "systems": [
            {
                "hostname": "WS-01",
                "ip": "10.0.0.10",
                "os": "Windows 11",
                "type": "workstation",
            }
        ],
    }
    data.update(updates)
    return Environment.model_validate(data)


def test_deployment_fields_have_behavior_preserving_defaults() -> None:
    system = System(
        hostname="WS-01",
        ip="10.0.0.10",
        os="Windows 11",
        type="workstation",
    )
    environment = _environment()

    assert system.os_build is None
    assert system.architecture is None
    assert environment.deployment_overrides == []


def test_exact_deployment_overrides_normalize_and_preserve_empty_replacements() -> None:
    environment = _environment(
        systems=[
            {
                "hostname": "WS-01",
                "ip": "10.0.0.10",
                "os": "Windows 11",
                "os_build": " 10.0.22631.3880 ",
                "architecture": "x64",
                "type": "workstation",
            }
        ],
        deployment_overrides=[
            {
                "system": "WS-01",
                "applications": [],
                "services": [" print-spooler "],
                "tasks": [],
                "modules": [r"C:\Windows\System32\spoolss.dll"],
                "cohorts": [" pilot-ring "],
                "user_applications": [{"user": "analyst", "applications": []}],
            }
        ],
    )

    assert environment.systems[0].os_build == "10.0.22631.3880"
    override = environment.deployment_overrides[0]
    assert override.applications == []
    assert override.services == ["print-spooler"]
    assert override.tasks == []
    assert override.modules == [r"C:\Windows\System32\spoolss.dll"]
    assert override.cohorts == ["pilot-ring"]
    assert override.user_applications is not None
    assert override.user_applications[0].applications == []


@pytest.mark.parametrize(
    "updates, match",
    [
        (
            {
                "deployment_overrides": [
                    {"system": "WS-01", "applications": []},
                    {"system": "ws-01", "applications": ["chrome"]},
                ]
            },
            "systems must be unique",
        ),
        (
            {"deployment_overrides": [{"system": "UNKNOWN", "applications": []}]},
            "unknown systems",
        ),
        (
            {
                "deployment_overrides": [
                    {
                        "system": "WS-01",
                        "user_applications": [{"user": "nobody", "applications": []}],
                    }
                ]
            },
            "unknown user application assignments",
        ),
    ],
)
def test_environment_rejects_ambiguous_or_unknown_deployment_targets(
    updates: dict[str, object],
    match: str,
) -> None:
    with pytest.raises(ValidationError, match=match):
        _environment(**updates)


@pytest.mark.parametrize(
    "payload, match",
    [
        ({"system": "WS-01"}, "at least one patch field"),
        ({"system": "WS-01", "applications": ["web*"]}, "exact IDs"),
        ({"system": "WS-01", "services": ["svc?"]}, "exact names"),
        (
            {
                "system": "WS-01",
                "user_applications": [
                    {"user": "analyst", "applications": []},
                    {"user": "ANALYST", "applications": ["chrome"]},
                ],
            },
            "users must be unique",
        ),
    ],
)
def test_deployment_override_rejects_patterns_empty_patches_and_duplicate_users(
    payload: dict[str, object],
    match: str,
) -> None:
    with pytest.raises(ValidationError, match=match):
        HostDeploymentOverride.model_validate(payload)


def test_environment_json_schema_exposes_deployment_override_contract() -> None:
    schema = Environment.model_json_schema()
    deployment_schema = schema["properties"]["deployment_overrides"]
    assert deployment_schema["items"]["$ref"].endswith("/HostDeploymentOverride")
    assert schema["$defs"]["HostDeploymentOverride"]["additionalProperties"] is False
