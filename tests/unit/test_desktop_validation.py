"""Readable validation results shown by the desktop app."""

from __future__ import annotations

import json

from evidenceforge.desktop.validation import format_validation_output


def test_validation_summary_shows_scenario_and_resource_context() -> None:
    payload = {
        "valid": True,
        "status": "valid",
        "issues": [],
        "scenario": {
            "name": "sample",
            "users": 2,
            "systems": 3,
            "storyline_events": 4,
            "output_formats": ["windows", "zeek"],
        },
        "resource_forecast": {
            "memory": {"expected_bytes": 128 * 1024 * 1024},
            "final_output": {"expected_bytes": 2 * 1024 * 1024},
        },
    }

    rendered = format_validation_output(json.dumps(payload), "", 0)

    assert "VALID · sample" in rendered
    assert "2 users · 3 systems · 4 storyline events" in rendered
    assert "Formats: windows, zeek" in rendered
    assert "peak memory ~128.0 MiB" in rendered
    assert "No validation issues found." in rendered


def test_validation_summary_shows_issue_and_suggested_fix() -> None:
    payload = {
        "valid": False,
        "status": "invalid",
        "issues": [
            {
                "severity": "error",
                "field_path": "environment.systems.0.hostname",
                "message": "System hostname is missing",
                "suggestion": "Set a hostname on the first system",
            }
        ],
    }

    rendered = format_validation_output(json.dumps(payload), "", 2)

    assert "VALIDATION FAILED" in rendered
    assert "ERROR · environment.systems.0.hostname" in rendered
    assert "System hostname is missing" in rendered
    assert "Suggested fix: Set a hostname on the first system" in rendered


def test_validation_summary_uses_singular_counts() -> None:
    payload = {
        "valid": True,
        "status": "valid",
        "issues": [],
        "scenario": {"users": 1, "systems": 1, "storyline_events": 1},
    }

    rendered = format_validation_output(json.dumps(payload), "", 0)

    assert "1 user · 1 system · 1 storyline event" in rendered
