# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for additive Scenario 2.0 deployment and observation overrides."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from evidenceforge.composition.compiler import _merge_registered
from evidenceforge.models.scenario import (
    Environment,
    HostDeploymentOverride,
    SourceObservationOverride,
    System,
)


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


def test_observation_override_defaults_and_normalizes_exact_patch() -> None:
    environment = _environment(
        observation_overrides=[
            {
                "source_instance": "SYSMON:WS-01",
                "system": "WS-01",
                "family": "sysmon",
                "capabilities": ["process", "file", "coherent_actor"],
                "missingness": 0.01,
                "format_missingness": {"windows_event_sysmon": 0.02},
                "optional_fields": [],
                "windows": [
                    {
                        "start": "2026-08-16T13:00:00-04:00",
                        "end": "2026-08-16T14:00:00-04:00",
                    },
                    {
                        "start": "2026-08-16T12:00:00-04:00",
                        "end": "2026-08-16T13:00:00-04:00",
                    },
                ],
                "batching": {
                    "enabled": True,
                    "interval_us": 5_000_000,
                    "max_records": 500,
                },
            }
        ]
    )

    observation = environment.observation_overrides[0]
    assert observation.source_instance == "sysmon:ws-01"
    assert observation.optional_fields == []
    assert observation.windows is not None
    assert [window.start.isoformat() for window in observation.windows] == [
        "2026-08-16T16:00:00+00:00",
        "2026-08-16T17:00:00+00:00",
    ]

    default_environment = _environment()
    assert default_environment.observation_overrides == []
    with pytest.raises(ValidationError, match="frozen"):
        observation.enabled = False


def test_observation_override_rejects_invalid_exact_targets() -> None:
    invalid_updates = [
        (
            {
                "observation_overrides": [
                    {"source_instance": "sysmon:ws-01", "enabled": True},
                    {"source_instance": "SYSMON:WS-01", "enabled": False},
                ]
            },
            "source_instance values must be unique",
        ),
        (
            {
                "observation_overrides": [
                    {
                        "source_instance": "sysmon:ws-01",
                        "system": "MISSING",
                        "enabled": True,
                    }
                ]
            },
            "unknown system guards",
        ),
        (
            {"observation_overrides": [{"source_instance": "sysmon:missing", "enabled": True}]},
            "unknown source instances",
        ),
        (
            {
                "observation_overrides": [
                    {
                        "source_instance": "sysmon:ws-01",
                        "family": "ecar",
                        "enabled": True,
                    }
                ]
            },
            "identity guards do not match",
        ),
    ]

    for updates, message in invalid_updates:
        with pytest.raises(ValidationError, match=message):
            _environment(**updates)


def test_observation_override_model_and_schema_are_strict() -> None:
    invalid_patches = [
        ({"source_instance": "sysmon:*", "enabled": True}, "must use exact"),
        (
            {
                "source_instance": "sysmon:ws-01",
                "family": "sysmon",
                "format_missingness": {"zeek_conn": 0.1},
            },
            "do not belong to sysmon",
        ),
        (
            {
                "source_instance": "sysmon:ws-01",
                "batching": {"enabled": True, "interval_us": 0},
            },
            "positive interval_us",
        ),
        (
            {
                "source_instance": "sysmon:ws-01",
                "windows": [
                    {
                        "start": "2026-08-16T12:00:00Z",
                        "end": "2026-08-16T14:00:00Z",
                    },
                    {
                        "start": "2026-08-16T13:00:00Z",
                        "end": "2026-08-16T15:00:00Z",
                    },
                ],
            },
            "must not overlap",
        ),
        (
            {"source_instance": "sysmon:ws-01", "enabled": True, "unknown": 1},
            "Extra inputs are not permitted",
        ),
    ]

    for payload, message in invalid_patches:
        with pytest.raises(ValidationError, match=message):
            SourceObservationOverride.model_validate(payload)

    schema = Environment.model_json_schema(mode="validation")
    assert schema["properties"]["observation_overrides"]["items"]["$ref"].endswith(
        "/SourceObservationOverride"
    )
    assert schema["$defs"]["SourceObservationOverride"]["additionalProperties"] is False


def test_composition_merges_exact_observation_override_fields() -> None:
    lower = {
        "environment": {
            "observation_overrides": [
                {
                    "source_instance": "sysmon:ws-01",
                    "capabilities": ["process", "file"],
                    "optional_fields": ["CommandLine"],
                }
            ]
        }
    }
    higher = {
        "environment": {
            "observation_overrides": [
                {
                    "source_instance": "SYSMON:WS-01",
                    "capabilities": [],
                    "missingness": 0.02,
                }
            ]
        }
    }

    merged = _merge_registered(lower, higher)

    assert merged["environment"]["observation_overrides"] == [
        {
            "source_instance": "SYSMON:WS-01",
            "capabilities": [],
            "optional_fields": ["CommandLine"],
            "missingness": 0.02,
        }
    ]
