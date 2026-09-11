# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Focused scenario-schema CLI contracts."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import ValidationError
from typer.testing import CliRunner

from evidenceforge.cli.commands import _validation_json_payload, app
from evidenceforge.cli.schema import (
    resolve_schema_contract,
    schema_contract_payload,
    schema_selectors,
)


def test_every_focused_schema_example_validates() -> None:
    """Every advertised selector has an executable installed-version example."""

    selectors = schema_selectors()
    assert "environment.network_identities" in selectors
    assert "environment.service_accounts" in selectors
    assert "event.email_read" in selectors
    assert "event.rdp_session" in selectors

    for selector in selectors:
        contract = resolve_schema_contract(selector)
        assert contract is not None
        payload = schema_contract_payload(contract)
        assert payload["selector"] == selector
        assert payload["example"] is not None
        assert payload["json_schema"]


def test_schema_cli_reports_exact_network_identity_contract() -> None:
    """Network identity discovery exposes required fields and forbids invented aliases."""

    result = CliRunner().invoke(app, ["schema", "environment.network_identities", "--json"])

    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["fields"]["id"]["required"] is True
    assert set(payload["fields"]) == {"id", "hosts", "ips", "tags", "dns"}
    assert payload["example"]["hosts"] == ["partner.example.com"]
    assert "name" not in payload["fields"]
    assert "ip" not in payload["fields"]


def test_schema_cli_reports_scalar_service_accounts() -> None:
    """Service-account discovery makes the scalar list shape unambiguous."""

    result = CliRunner().invoke(app, ["schema", "environment.service_accounts", "--json"])

    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["json_schema"]["type"] == "array"
    assert payload["json_schema"]["items"]["type"] == "string"
    assert payload["example"] == ["svc-backup", "svc-monitoring"]


def test_email_read_schema_defines_numeric_seconds() -> None:
    """The focused contract distinguishes numeric seconds from duration strings."""

    result = CliRunner().invoke(app, ["schema", "event.email_read", "--json"])

    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    duration = payload["fields"]["duration"]
    assert duration["variants"][0]["type"] == "number"
    assert duration["variants"][0]["exclusiveMinimum"] == 0.0
    assert "numeric seconds" in duration["description"]
    assert payload["example"]["duration"] == 45.0

    contract = resolve_schema_contract("event.email_read")
    assert contract is not None
    try:
        contract.adapter.validate_python({"type": "email_read", "duration": "45s"})
    except ValidationError as exc:
        assert "valid number" in str(exc)
    else:
        raise AssertionError("duration strings must not validate for email_read")


def test_validate_email_read_string_duration_points_to_focused_contract(tmp_path: Path) -> None:
    """The authored-file diagnostic explains the invalid unit shape and exact schema query."""

    scenario = tmp_path / "scenario.yaml"
    scenario.write_text(
        """
version: "1.0"
name: invalid-email-duration
description: Reject duration strings for email reads
environment:
  description: Minimal environment
  users:
    - username: analyst
      full_name: Alex Analyst
      email: analyst@corp.invalid
      primary_system: WS-01
  systems:
    - hostname: WS-01
      ip: 10.0.1.10
      os: Windows 11
      type: workstation
time_window: {start: "2026-08-26T13:00:00Z", duration: 1h}
baseline_activity:
  description: Minimal baseline
  intensity: low
  variation: low
storyline:
  - id: read-email
    time: +10m
    actor: analyst
    system: WS-01
    activity: Read a message
    events:
      - type: email_read
        duration: 45s
output: {logs: [{format: windows}], destination: ./output}
""",
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["validate", str(scenario), "--json"])

    assert result.exit_code == 2, result.stdout
    payload = json.loads(result.stdout)
    issue = next(issue for issue in payload["issues"] if issue["field_path"].endswith("duration"))
    assert "valid number" in issue["message"]
    assert "eforge schema event.email_read --json" in issue["suggestion"]


def test_schema_cli_rejects_unknown_selector_with_inventory() -> None:
    """Unknown focused queries fail as input errors and advertise exact alternatives."""

    result = CliRunner().invoke(app, ["schema", "event.unknown", "--json"])

    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["valid"] is False
    assert "event.email_read" in payload["error"]


def test_validate_groups_network_identity_shape_errors(tmp_path: Path) -> None:
    """One malformed object produces one exact focused-contract diagnostic."""

    scenario = tmp_path / "scenario.yaml"
    scenario.write_text(
        """
version: "1.0"
name: grouped-shape-error
description: Group repeated Pydantic object errors
environment:
  description: Minimal environment
  users:
    - username: analyst
      full_name: Alex Analyst
      email: analyst@corp.invalid
      primary_system: WS-01
  systems:
    - hostname: WS-01
      ip: 10.0.1.10
      os: Windows 11
      type: workstation
  network_identities:
    - name: Partner Portal
      description: External service
      hostname: partner.example.com
      ip: 203.0.113.60
time_window: {start: "2026-08-26T13:00:00Z", duration: 1h}
baseline_activity:
  description: Minimal baseline
  intensity: low
  variation: low
output: {logs: [{format: windows}], destination: ./output}
""",
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["validate", str(scenario), "--json"])

    assert result.exit_code == 2, result.stdout
    payload = json.loads(result.stdout)
    shape_issues = [
        issue for issue in payload["issues"] if issue["code"] == "scenario.schema.object_shape"
    ]
    assert len(shape_issues) == 1
    issue = shape_issues[0]
    assert issue["field_path"] == "environment.network_identities.0"
    assert "missing required fields: id" in issue["message"]
    assert "unsupported fields: description, hostname, ip, name" in issue["message"]
    assert "eforge schema environment.network_identities --json" in issue["suggestion"]


def test_invalid_payload_headline_selects_first_error_not_warning(tmp_path: Path) -> None:
    """Warnings preceding blockers never become the top-level error headline."""

    common = {
        "code": "scenario.semantic",
        "field_path": "environment.network.sensors",
        "suggestion": None,
        "source": {"kind": "input", "path": str(tmp_path / "scenario.yaml")},
        "provenance": {"origin_kind": "input-fallback"},
    }
    payload = _validation_json_payload(
        scenario_file=tmp_path / "scenario.yaml",
        input_kind="scenario-2.0",
        project_root=tmp_path,
        issues=[
            {**common, "severity": "warning", "message": "Optional firewall warning"},
            {
                **common,
                "severity": "error",
                "field_path": "output.logs",
                "message": "Blocking sensor error",
            },
        ],
    )

    assert payload["valid"] is False
    assert payload["error"] == "Blocking sensor error"
