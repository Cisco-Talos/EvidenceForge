# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Validation notes storyline executables that generation must implicitly create."""

from typing import Any

from evidenceforge.models.scenario import Scenario
from evidenceforge.validation.schema import ScenarioValidator


def _scenario(steps: list[dict[str, Any]]) -> Scenario:
    return Scenario.model_validate(
        {
            "version": "1.0",
            "name": "implied-executable",
            "description": "Validation fixture",
            "generation_seed": 1,
            "environment": {
                "description": "One host",
                "users": [
                    {
                        "username": "alex",
                        "full_name": "Alex Example",
                        "email": "alex@example.test",
                        "primary_system": "APP",
                    }
                ],
                "systems": [
                    {"hostname": "APP", "ip": "10.88.0.20", "os": "Ubuntu 22.04", "type": "server"}
                ],
            },
            "time_window": {"start": "2026-10-20T10:00:00Z", "duration": "10m"},
            "baseline_activity": {"description": "b", "intensity": "low", "variation": "low"},
            "storyline": steps,
            "output": {"logs": [{"format": "ecar"}], "destination": "./out"},
        }
    )


def _step(step_id: str, minute: int, image: str, command: str) -> dict[str, Any]:
    return {
        "id": step_id,
        "time": f"+{minute}m",
        "actor": "alex",
        "system": "APP",
        "activity": step_id,
        "events": [{"type": "process", "process_name": image, "command_line": command}],
    }


def _implied_notes(scenario: Scenario) -> list[tuple[str, str]]:
    validator = ScenarioValidator(scenario)
    validator.validate()
    return [
        (issue.severity, issue.field_path)
        for issue in validator.issues
        if "implied creation" in issue.message
    ]


def test_validation_notes_only_undelivered_uninstalled_executables() -> None:
    scenario = _scenario(
        [
            _step("download", 1, "/usr/bin/curl", "curl -o /tmp/a https://x.example.test/a"),
            _step("run-downloaded", 2, "/tmp/a", "/tmp/a"),
            _step("run-undelivered", 3, "/tmp/b", "/tmp/b"),
            _step("run-again", 4, "/tmp/b", "/tmp/b --once"),
            _step("run-installed", 5, "/usr/bin/id", "id"),
        ]
    )
    assert _implied_notes(scenario) == [("info", "storyline.2.events.0")]
