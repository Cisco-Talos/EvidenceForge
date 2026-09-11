# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""CLI contracts for Scenario 2.0 pack discovery, authoring, and resolution."""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from typer.testing import CliRunner

from evidenceforge.cli.commands import app
from evidenceforge.composition.compiler import resolve_management_project_root
from evidenceforge.composition.packs import CATALOG_FILES

runner = CliRunner()
_NORTHSTAR = Path("tests/fixtures/scenarios/northstar-health-pack.yaml").resolve()
_NORTHSTAR_LINUX = Path("tests/fixtures/scenarios/northstar-health-linux-pack.yaml").resolve()


def test_pack_inventory_show_and_validation_have_stable_json() -> None:
    """Inspection commands expose exact identities, exports, dependencies, and digests."""

    listed = runner.invoke(app, ["pack", "list", "--json"])
    shown = runner.invoke(
        app,
        ["pack", "show", "package:evidenceforge:industry:healthcare@1.0.0", "--json"],
    )
    validated = runner.invoke(
        app,
        ["pack", "validate", "package:evidenceforge:organization:northstar-health@1.0.0", "--json"],
    )

    assert listed.exit_code == 0
    assert {pack["name"] for pack in json.loads(listed.stdout)["packs"]} >= {
        "finance",
        "healthcare",
        "technology",
        "northstar-health",
        "metrolink-specialty-care",
    }
    shown_payload = json.loads(shown.stdout)
    assert shown.exit_code == 0
    assert shown_payload["exports"]["persona_catalog"] == [
        "evidenceforge/healthcare:clinical_coordinator"
    ]
    assert shown_payload["model_contributions"] == {
        "baseline_activity_fields": [],
        "environment_fields": [],
    }
    validation_payload = json.loads(validated.stdout)
    assert validated.exit_code == 0
    assert validation_payload["valid"] is True
    assert validation_payload["dependencies"][0]["name"] == "healthcare"


def test_pack_release_build_inspect_and_import_have_stable_json(tmp_path: Path) -> None:
    """Release CLI commands expose a validated immutable closure without project resolution."""

    archive = tmp_path / "metrolink.efpack"
    built = runner.invoke(
        app,
        [
            "pack",
            "build",
            "package:evidenceforge:organization:metrolink-specialty-care@1.0.0",
            "--output",
            str(archive),
            "--json",
        ],
    )
    inspected = runner.invoke(app, ["pack", "inspect", str(archive), "--json"])
    imported = runner.invoke(
        app,
        [
            "pack",
            "import",
            str(archive),
            "--scope",
            "project",
            "--accept-publisher",
            "evidenceforge",
            "--project-root",
            str(tmp_path),
            "--json",
        ],
    )

    assert built.exit_code == 0, built.stdout
    built_payload = json.loads(built.stdout)
    assert built_payload["built"] is True
    assert built_payload["root"]["name"] == "metrolink-specialty-care"
    assert len(built_payload["members"]) == 2
    assert inspected.exit_code == 0, inspected.stdout
    assert json.loads(inspected.stdout)["valid"] is True
    assert imported.exit_code == 0, imported.stdout
    imported_payload = json.loads(imported.stdout)
    assert imported_payload["imported"] is True
    assert imported_payload["scope"] == "project"


def test_organization_show_distinguishes_model_fields_from_catalog_exports() -> None:
    """Empty organization catalogs cannot be mistaken for an empty concrete model."""

    shown = runner.invoke(
        app,
        ["pack", "show", "package:evidenceforge:organization:northstar-health@1.0.0", "--json"],
    )

    assert shown.exit_code == 0, shown.stdout
    payload = json.loads(shown.stdout)
    assert payload["exports"]["storage_catalog"] == []
    assert payload["model_contributions"]["environment_fields"] == [
        "description",
        "domain",
        "email",
        "groups",
        "network",
        "storage",
        "systems",
        "timezone",
        "users",
    ]
    assert payload["model_contributions"]["baseline_activity_fields"] == [
        "description",
        "intensity",
        "suspicious_noise",
        "variation",
    ]


def test_package_packs_work_from_empty_directory_without_eforge(
    tmp_path: Path, monkeypatch
) -> None:
    """The working directory is a valid root even when no project repository exists."""

    monkeypatch.chdir(tmp_path)
    assert not (tmp_path / ".eforge").exists()
    assert resolve_management_project_root() == tmp_path.resolve()

    listed = runner.invoke(app, ["pack", "list", "--json"])

    assert listed.exit_code == 0, listed.stdout
    payload = json.loads(listed.stdout)
    assert any(
        pack["source"] == "package" and pack["name"] == "northstar-health"
        for pack in payload["packs"]
    )
    assert not (tmp_path / ".eforge").exists()


def test_publisher_cli_set_show_force_and_clear_have_stable_json(tmp_path: Path) -> None:
    """Publisher commands expose exact scope and require force for replacement."""

    first = runner.invoke(
        app,
        [
            "pack",
            "publisher",
            "set",
            "first-publisher",
            "--display-name",
            "First Publisher",
            "--scope",
            "project",
            "--project-root",
            str(tmp_path),
            "--json",
        ],
    )
    shown = runner.invoke(
        app,
        ["pack", "publisher", "show", "--project-root", str(tmp_path), "--json"],
    )
    refused = runner.invoke(
        app,
        [
            "pack",
            "publisher",
            "set",
            "second-publisher",
            "--display-name",
            "Second Publisher",
            "--scope",
            "project",
            "--project-root",
            str(tmp_path),
            "--json",
        ],
    )
    cleared = runner.invoke(
        app,
        [
            "pack",
            "publisher",
            "clear",
            "--scope",
            "project",
            "--project-root",
            str(tmp_path),
            "--json",
        ],
    )

    assert first.exit_code == 0
    assert json.loads(first.stdout)["publisher"] == "first-publisher"
    assert shown.exit_code == 0
    assert json.loads(shown.stdout) == {
        "configured": True,
        "publisher": "first-publisher",
        "publisher_display_name": "First Publisher",
        "scope": "project",
    }
    assert refused.exit_code != 0
    assert "--force" in json.loads(refused.stdout)["error"]
    assert cleared.exit_code == 0
    assert json.loads(cleared.stdout)["cleared"] is True


def test_northstar_linux_pack_has_exact_dependency_and_indexed_digest() -> None:
    """Northstar 1.1 is additive, pinned, and independently digest-verified."""

    validated = runner.invoke(
        app,
        ["pack", "validate", "package:evidenceforge:organization:northstar-health@1.1.0", "--json"],
    )

    assert validated.exit_code == 0, validated.stdout
    payload = json.loads(validated.stdout)
    assert payload["valid"] is True
    assert payload["pack"]["version"] == "1.1.0"
    assert payload["pack"]["digest"] == (
        "2b5c2142e4eae824e8a4463c914c6916661ed92817e3c9d7fd1be4d2cf891db1"
    )
    assert payload["dependencies"] == [
        {
            "digest": "91f369c55113c940a9a907282b53fcc5629c54d3b91b79a869814cbcb7b82220",
            "location": "package:evidenceforge:industry:healthcare@1.0.0",
            "name": "healthcare",
            "publisher": "evidenceforge",
            "source": "package",
            "type": "industry",
            "version": "1.0.0",
        }
    ]


def test_northstar_linux_fixture_resolves_exact_new_pack(tmp_path: Path) -> None:
    """The Linux SMB consumer selects 1.1 without mutating the 1.0 fixture."""

    result = runner.invoke(
        app,
        [
            "resolve",
            str(_NORTHSTAR_LINUX),
            "--output",
            str(tmp_path / "resolved.yaml"),
            "--json",
        ],
    )

    assert result.exit_code == 0, result.stdout
    selected = json.loads(result.stdout)["selected_packs"]
    assert [(pack["name"], pack["version"]) for pack in selected] == [
        ("healthcare", "1.0.0"),
        ("northstar-health", "1.1.0"),
    ]


def test_northstar_is_a_small_routine_validation_consumer() -> None:
    """Northstar stays in the documented small tier without a generation run."""

    result = runner.invoke(app, ["validate", str(_NORTHSTAR_LINUX), "--json"])

    assert result.exit_code == 0, result.stdout
    scenario = json.loads(result.stdout)["scenario"]
    assert 5 <= scenario["users"] <= 10
    assert 7 <= scenario["systems"] <= 15


def test_pack_init_and_copy_are_complete_and_non_overwriting(tmp_path: Path) -> None:
    """Skeletons and forks land only in the project repository and preserve copy metadata."""

    configured = runner.invoke(
        app,
        [
            "pack",
            "publisher",
            "set",
            "test-publisher",
            "--display-name",
            "Test Publisher",
            "--scope",
            "project",
            "--project-root",
            str(tmp_path),
        ],
    )
    assert configured.exit_code == 0, configured.stdout
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
    root = (
        tmp_path / ".eforge" / "packs" / "test-publisher" / "organization" / "example-org" / "1.0.0"
    )

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
            "package:evidenceforge:industry:healthcare@1.0.0",
            "--name",
            "tailored-healthcare",
            "--version",
            "1.1.0",
            "--project-root",
            str(tmp_path),
        ],
    )
    copied_root = (
        tmp_path
        / ".eforge"
        / "packs"
        / "test-publisher"
        / "industry"
        / "tailored-healthcare"
        / "1.1.0"
    )
    manifest = yaml.safe_load((copied_root / "pack.yaml").read_text(encoding="utf-8"))

    assert copied.exit_code == 0
    assert manifest["name"] == "tailored-healthcare"
    assert manifest["publisher"] == "test-publisher"
    assert manifest["version"] == "1.1.0"
    assert "copied_from" not in manifest
    assert "package:evidenceforge:industry:healthcare@1.0.0" in (
        copied_root / "COPY_PROVENANCE.md"
    ).read_text(encoding="utf-8")


def test_pack_lock_previews_then_atomically_applies_exact_dependency(tmp_path: Path) -> None:
    """Lock refresh previews changes and mutates only the lock when explicitly applied."""

    configured = runner.invoke(
        app,
        [
            "pack",
            "publisher",
            "set",
            "test-publisher",
            "--display-name",
            "Test Publisher",
            "--scope",
            "project",
            "--project-root",
            str(tmp_path),
        ],
    )
    assert configured.exit_code == 0, configured.stdout
    copied = runner.invoke(
        app,
        [
            "pack",
            "copy",
            "package:evidenceforge:organization:metrolink-specialty-care@1.0.0",
            "--name",
            "locked-care",
            "--version",
            "1.0.0",
            "--project-root",
            str(tmp_path),
        ],
    )
    assert copied.exit_code == 0, copied.stdout
    root = (
        tmp_path / ".eforge" / "packs" / "test-publisher" / "organization" / "locked-care" / "1.0.0"
    )
    lock_path = root / "pack.lock.yaml"
    lock = yaml.safe_load(lock_path.read_text(encoding="utf-8"))
    lock["dependencies"][0]["digest"] = "0" * 64
    lock_path.write_text(yaml.safe_dump(lock, sort_keys=False), encoding="utf-8")
    manifest_before = (root / "pack.yaml").read_bytes()
    reference = "project:test-publisher:organization:locked-care@1.0.0"

    preview = runner.invoke(
        app,
        ["pack", "lock", reference, "--project-root", str(tmp_path), "--json"],
    )
    assert preview.exit_code == 0, preview.stdout
    preview_payload = json.loads(preview.stdout)
    assert preview_payload["applied"] is False
    assert preview_payload["changed"] is True
    assert (
        yaml.safe_load(lock_path.read_text(encoding="utf-8"))["dependencies"][0]["digest"]
        == "0" * 64
    )

    applied = runner.invoke(
        app,
        ["pack", "lock", reference, "--apply", "--project-root", str(tmp_path), "--json"],
    )
    assert applied.exit_code == 0, applied.stdout
    assert json.loads(applied.stdout)["applied"] is True
    assert (root / "pack.yaml").read_bytes() == manifest_before
    assert (
        yaml.safe_load(lock_path.read_text(encoding="utf-8"))["dependencies"][0]["digest"]
        == "91f369c55113c940a9a907282b53fcc5629c54d3b91b79a869814cbcb7b82220"
    )


def test_old_pack_cli_reference_is_rejected_immediately() -> None:
    """The pre-release unqualified CLI syntax has no compatibility alias."""

    result = runner.invoke(
        app,
        ["pack", "show", "package:industry:healthcare@1.0.0", "--json"],
    )

    assert result.exit_code != 0
    assert "source:publisher:type:name@version" in json.loads(result.stdout)["error"]


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
        "lower_layer": "package:evidenceforge:organization:northstar-health@1.0.0",
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
