# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""CLI contracts for Scenario 2.0 pack discovery, authoring, and resolution."""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from typer.testing import CliRunner

from evidenceforge.cli.commands import app
from evidenceforge.composition.packs import CATALOG_FILES

runner = CliRunner()
_NORTHSTAR = Path("tests/fixtures/scenarios/northstar-health-pack.yaml").resolve()


def test_pack_inventory_show_and_validation_have_stable_json() -> None:
    """Inspection commands expose exact identities, exports, dependencies, and digests."""

    listed = runner.invoke(app, ["pack", "list", "--json"])
    shown = runner.invoke(
        app,
        ["pack", "show", "package:industry:healthcare@1.0.0", "--json"],
    )
    validated = runner.invoke(
        app,
        ["pack", "validate", "package:organization:northstar-health@1.0.0", "--json"],
    )

    assert listed.exit_code == 0
    assert {pack["name"] for pack in json.loads(listed.stdout)["packs"]} >= {
        "finance",
        "healthcare",
        "technology",
        "northstar-health",
    }
    shown_payload = json.loads(shown.stdout)
    assert shown.exit_code == 0
    assert shown_payload["exports"]["persona_catalog"] == ["healthcare:clinical_coordinator"]
    validation_payload = json.loads(validated.stdout)
    assert validated.exit_code == 0
    assert validation_payload["valid"] is True
    assert validation_payload["dependencies"][0]["name"] == "healthcare"


def test_pack_init_and_copy_are_complete_and_non_overwriting(tmp_path: Path) -> None:
    """Skeletons and forks land only in the project repository and preserve copy metadata."""

    initialized = runner.invoke(
        app,
        [
            "pack",
            "init",
            "organization",
            "example-org",
            "--version",
            "1.0.0",
            "--project-root",
            str(tmp_path),
        ],
    )
    root = tmp_path / ".eforge" / "packs" / "organization" / "example-org" / "1.0.0"

    assert initialized.exit_code == 0
    assert all((root / relative).is_file() for _name, relative, _model in CATALOG_FILES)
    assert (root / "model" / "environment.yaml").is_file()
    assert (root / "model" / "baseline_activity.yaml").is_file()
    duplicate = runner.invoke(
        app,
        [
            "pack",
            "init",
            "organization",
            "example-org",
            "--version",
            "1.0.0",
            "--project-root",
            str(tmp_path),
        ],
    )
    assert duplicate.exit_code != 0

    copied = runner.invoke(
        app,
        [
            "pack",
            "copy",
            "package:industry:healthcare@1.0.0",
            "--name",
            "tailored-healthcare",
            "--version",
            "1.1.0",
            "--project-root",
            str(tmp_path),
        ],
    )
    copied_root = tmp_path / ".eforge" / "packs" / "industry" / "tailored-healthcare" / "1.1.0"
    manifest = yaml.safe_load((copied_root / "pack.yaml").read_text(encoding="utf-8"))

    assert copied.exit_code == 0
    assert manifest["name"] == "tailored-healthcare"
    assert manifest["version"] == "1.1.0"
    assert "copied_from" not in manifest
    assert "package:industry:healthcare@1.0.0" in (copied_root / "COPY_PROVENANCE.md").read_text(
        encoding="utf-8"
    )


def test_resolve_explanation_is_portable_and_non_overwriting(tmp_path: Path) -> None:
    """Resolve emits stable JSON/provenance and protects a different existing destination."""

    output = tmp_path / "resolved.yaml"
    result = runner.invoke(
        app,
        [
            "resolve",
            str(_NORTHSTAR),
            "--output",
            str(output),
            "--explain-composition",
            "--json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["valid"] is True
    assert [pack["name"] for pack in payload["selected_packs"]] == [
        "healthcare",
        "northstar-health",
    ]
    composition = payload["composition"]
    assert composition["scenario_source_count"] == 1
    assert composition["selected_pack_count"] == 2
    assert composition["source_count"] == 1
    assert composition["source_count_scope"] == "scenario-source-graph"
    assert composition["field_origins"]
    assert all(not origin.startswith("/") for origin in composition["field_origins"].values())
    assert composition["organization_model_origins"]["environment.domain"] == (
        "model/environment.yaml"
    )
    assert composition["organization_model_origins"]["baseline_activity.intensity"] == (
        "model/baseline_activity.yaml"
    )
    assert all(
        not origin.startswith("/") for origin in composition["organization_model_origins"].values()
    )
    output.write_text("different\n", encoding="utf-8")
    refused = runner.invoke(
        app,
        ["resolve", str(_NORTHSTAR), "--output", str(output), "--json"],
    )
    assert refused.exit_code != 0
    assert json.loads(refused.stdout)["valid"] is False


def test_resolve_explanation_reports_concrete_layer_replacements(tmp_path: Path) -> None:
    """Explain output names actual scenario and project-overlay winners over pack data."""

    scenario_document = yaml.safe_load(_NORTHSTAR.read_text(encoding="utf-8"))
    scenario_document["environment"] = {"domain": "scenario-winner.example"}
    scenario_path = tmp_path / "scenario.yaml"
    scenario_path.write_text(
        yaml.safe_dump(scenario_document, sort_keys=False),
        encoding="utf-8",
    )
    overlay_root = tmp_path / ".eforge" / "config" / "activity"
    overlay_root.mkdir(parents=True)
    (overlay_root / "dns_registry.yaml").write_text(
        yaml.safe_dump(
            {
                "domains": [
                    {
                        "domain": "claims.healthcare.example",
                        "ips": ["203.0.113.44"],
                        "tags": ["healthcare"],
                        "_replace": True,
                    }
                ]
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "resolve",
            str(scenario_path),
            "--output",
            str(tmp_path / "resolved.yaml"),
            "--project-root",
            str(tmp_path),
            "--explain-composition",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.stdout
    decisions = json.loads(result.stdout)["composition"]["merge_decisions"]
    assert {
        "path": "environment.domain",
        "action": "replace",
        "lower_layer": "package:organization:northstar-health@1.0.0",
        "higher_layer": "scenario",
        "winner": "scenario",
    } in decisions
    assert {
        "path": "activity/dns_registry.yaml:domains[claims.healthcare.example]",
        "action": "replace",
        "lower_layer": "pack-adapter",
        "higher_layer": "project-overlay:activity/dns_registry.yaml",
        "winner": "project-overlay",
    } in decisions


def test_resolve_invalid_oob_host_keeps_json_error_contract(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "resolve",
            str(_NORTHSTAR),
            "--output",
            str(tmp_path / "resolved.yaml"),
            "--oob-host",
            "com",
            "--json",
        ],
    )

    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["valid"] is False
    assert "--oob-host 'com' must be a concrete registrable domain" in payload["error"]
