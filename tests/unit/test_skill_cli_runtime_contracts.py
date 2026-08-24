# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Machine-readable CLI contracts used by EvidenceForge authoring skills."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from evidenceforge.cli.commands import (
    EXIT_INPUT_ERROR,
    EXIT_SCHEMA_VALIDATION,
    app,
)
from evidenceforge.cli.info import gather_info, list_fields, resolve_field
from evidenceforge.composition import compile_scenario
from evidenceforge.composition.artifacts import (
    build_resolved_document,
    serialize_resolved_document,
)
from evidenceforge.config.provider import effective_config_scope

runner = CliRunner()
_MINIMAL = Path("tests/fixtures/scenarios/minimal.yaml").resolve()
_NORTHSTAR = Path("tests/fixtures/scenarios/northstar-health-pack.yaml").resolve()


def _write_included_persona_error(tmp_path: Path) -> tuple[Path, Path]:
    environment = tmp_path / "environment.yaml"
    environment.write_text(
        """
environment:
  description: Included environment
  users:
    - username: test_user
      full_name: Test User
      email: test.user@example.com
      primary_system: TEST-01
      persona: missing_persona
      enabled: true
  systems:
    - hostname: TEST-01
      ip: 10.0.0.1
      os: Windows 10
      type: workstation
""",
        encoding="utf-8",
    )
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text(
        """
includes: [environment.yaml]
version: "1.0"
name: source-aware-validation
description: Source-aware validation fixture
time_window:
  start: "2024-01-15T10:00:00Z"
  duration: "1h"
baseline_activity:
  description: Minimal baseline
  intensity: low
  variation: low
output:
  logs: [{format: windows}]
  destination: ./output
  compression: false
""",
        encoding="utf-8",
    )
    return scenario, environment


def test_validate_json_success_has_stable_bounded_envelope() -> None:
    result = runner.invoke(app, ["validate", str(_NORTHSTAR), "--json", "--show-storage"])

    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "1.0"
    assert payload["valid"] is True
    assert payload["status"] in {"valid", "valid_with_warnings"}
    assert payload["input"]["kind"] == "scenario-2.0"
    assert payload["severity_counts"] == {"error": 0, "warning": 0, "info": 0}
    assert payload["scenario"]["name"] == "northstar-health-baseline"
    assert [pack["name"] for pack in payload["composition"]["selected_packs"]] == [
        "healthcare",
        "northstar-health",
    ]
    assert isinstance(payload["resource_forecast"], dict)
    assert payload["storage"]["available"] is True
    assert payload["storage"]["shares"]


def test_validate_json_reports_actual_declaring_include_file(tmp_path: Path) -> None:
    scenario, environment = _write_included_persona_error(tmp_path)

    result = runner.invoke(app, ["validate", str(scenario), "--json"])

    assert result.exit_code == EXIT_SCHEMA_VALIDATION
    payload = json.loads(result.stdout)
    issue = next(item for item in payload["issues"] if item["field_path"].endswith("persona"))
    assert issue["source"] == {"kind": "authored-file", "path": str(environment.resolve())}
    assert issue["provenance"]["origin_kind"] == "authored-field"
    assert issue["suggestion"]
    assert payload["suggestions"]

    resolved_content = serialize_resolved_document(
        build_resolved_document(compile_scenario(scenario))
    )
    assert str(tmp_path).encode() not in resolved_content
    assert b"diagnostic_field_origins" not in resolved_content


def test_validate_json_reports_schema_error_declaring_include_file(tmp_path: Path) -> None:
    scenario, environment = _write_included_persona_error(tmp_path)
    environment.write_text(
        environment.read_text(encoding="utf-8").replace(
            "type: workstation",
            "type: unsupported-system-type",
        ),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["validate", str(scenario), "--json"])

    assert result.exit_code == EXIT_SCHEMA_VALIDATION
    payload = json.loads(result.stdout)
    issue = next(item for item in payload["issues"] if item["field_path"].endswith("type"))
    assert payload["input"]["kind"] == "scenario-1.0"
    assert issue["source"] == {"kind": "authored-file", "path": str(environment.resolve())}
    assert issue["provenance"]["origin_kind"] == "authored-field"
    assert issue["suggestion"]


def test_validate_json_reports_v2_schema_error_declaring_include_file(tmp_path: Path) -> None:
    scenario, environment = _write_included_persona_error(tmp_path)
    scenario.write_text(
        scenario.read_text(encoding="utf-8").replace(
            'version: "1.0"',
            'scenario_version: "2.0"',
        ),
        encoding="utf-8",
    )
    environment.write_text(
        environment.read_text(encoding="utf-8").replace(
            "type: workstation",
            "type: unsupported-system-type",
        ),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["validate", str(scenario), "--json"])

    assert result.exit_code == EXIT_SCHEMA_VALIDATION
    payload = json.loads(result.stdout)
    issue = next(item for item in payload["issues"] if item["field_path"].endswith("type"))
    assert payload["input"]["kind"] == "scenario-2.0"
    assert issue["source"] == {"kind": "authored-file", "path": str(environment.resolve())}


def test_validate_json_resolved_corruption_has_non_editing_guidance(tmp_path: Path) -> None:
    compiled = compile_scenario(_MINIMAL)
    resolved = tmp_path / "RESOLVED_SCENARIO.yaml"
    content = serialize_resolved_document(build_resolved_document(compiled))
    resolved.write_bytes(content.replace(b"editable: false", b"editable: true"))

    result = runner.invoke(app, ["validate", str(resolved), "--json"])

    assert result.exit_code == EXIT_SCHEMA_VALIDATION
    payload = json.loads(result.stdout)
    assert payload["input"]["kind"] == "resolved"
    suggestion = payload["issues"][0]["suggestion"]
    assert suggestion.startswith("Regenerate this authoritative artifact")
    assert "Edit this field" not in suggestion


def test_validate_json_missing_file_is_exit_one_and_valid_json(tmp_path: Path) -> None:
    missing = tmp_path / "missing.yaml"

    result = runner.invoke(app, ["validate", str(missing), "--json"])

    assert result.exit_code == EXIT_INPUT_ERROR
    payload = json.loads(result.stdout)
    assert payload["valid"] is False
    assert payload["input"]["kind"] == "missing"
    assert payload["issues"][0]["code"] == "input.not_found"
    assert payload["severity_counts"] == {"error": 1, "warning": 0, "info": 0}


def test_generate_missing_scenario_is_exit_one(tmp_path: Path) -> None:
    missing = tmp_path / "missing.yaml"

    result = runner.invoke(app, ["generate", str(missing)])

    assert result.exit_code == EXIT_INPUT_ERROR
    assert "Scenario file not found or unreadable" in result.stdout


def test_resolve_missing_scenario_is_exit_one_and_valid_json(tmp_path: Path) -> None:
    missing = tmp_path / "missing.yaml"

    result = runner.invoke(
        app,
        ["resolve", str(missing), "--output", str(tmp_path / "resolved.yaml"), "--json"],
    )

    assert result.exit_code == EXIT_INPUT_ERROR
    assert "scenario file not found or unreadable" in json.loads(result.stdout)["error"]


def test_eval_missing_paths_are_exit_one(tmp_path: Path) -> None:
    missing_output = tmp_path / "missing-output"
    missing_scenario = tmp_path / "missing-scenario.yaml"

    output_result = runner.invoke(app, ["eval", str(missing_output), "--format", "json"])
    scenario_result = runner.invoke(
        app,
        ["eval", str(tmp_path), "--scenario", str(missing_scenario), "--format", "json"],
    )

    assert output_result.exit_code == EXIT_INPUT_ERROR
    assert "output directory not found or unreadable" in json.loads(output_result.stdout)["error"]
    assert scenario_result.exit_code == EXIT_INPUT_ERROR
    assert "scenario file not found or unreadable" in json.loads(scenario_result.stdout)["error"]


def test_eval_rejects_unknown_output_format(tmp_path: Path) -> None:
    result = runner.invoke(app, ["eval", str(tmp_path), "--format", "jsno"])

    assert result.exit_code == EXIT_INPUT_ERROR
    assert "Unsupported report format" in result.stdout


def test_info_json_honors_project_root_and_derives_event_schemas(tmp_path: Path) -> None:
    overlay = tmp_path / ".eforge" / "config"
    overlay.mkdir(parents=True)

    overlay_result = runner.invoke(
        app,
        ["info", "overlay.path", "--project-root", str(tmp_path), "--json"],
    )
    version_result = runner.invoke(app, ["info", "version", "--json"])
    types_result = runner.invoke(app, ["info", "storyline_event_types", "--json"])
    schema_result = runner.invoke(app, ["info", "storyline_event_schemas.process", "--json"])

    assert overlay_result.exit_code == 0
    assert json.loads(overlay_result.stdout) == str(overlay)
    assert isinstance(json.loads(version_result.stdout), str)
    assert "process_access" in json.loads(types_result.stdout)
    schema = json.loads(schema_result.stdout)
    assert schema["properties"]["type"]["const"] == "process"
    assert schema["required"] == ["process_name"]
    assert {"process_ref", "parent_ref"} <= set(schema["properties"])


def test_info_config_family_inventory_is_authoring_grade() -> None:
    result = runner.invoke(app, ["info", "config_families", "--json"])

    assert result.exit_code == 0, result.stdout
    families = json.loads(result.stdout)
    dns = families["activity/dns_registry.yaml"]
    assert dns["ownership"] == "project-only"
    assert dns["merge_mode"]
    assert dns["validation"] == "eforge validate-config"
    assert dns["reference"].endswith("config-dns-network.md")


def test_info_advertised_fields_round_trip() -> None:
    data = gather_info()

    for field, _description in list_fields(data):
        if field.startswith("storyline_event_schemas."):
            field_data = gather_info(field=field)
            assert resolve_field(field_data, field) is not None, field
        else:
            assert resolve_field(data, field) is not None, field


def test_info_inventory_isolated_between_project_roots(tmp_path: Path) -> None:
    roots = [tmp_path / "a", tmp_path / "b"]
    for index, root in enumerate(roots):
        activity = root / ".eforge" / "config" / "activity"
        activity.mkdir(parents=True)
        (activity / "dns_registry.yaml").write_text(
            f'valid_tags:\n  root_{index}: "Project {index}"\n',
            encoding="utf-8",
        )
        (activity / "application_catalog.yaml").write_text(
            f"""schema_version: 2
default_deployment:
  kind: legacy_static
applications:
  - id: root_{index}_app
    display_name: Root {index} App
    platforms:
      linux:
        image_path: /opt/root_{index}_app/bin/root_{index}_app
    categories: [user_app]
    personas: [default]
""",
            encoding="utf-8",
        )

    for root, expected, absent in (
        (roots[0], "root_0", "root_1"),
        (roots[1], "root_1", "root_0"),
        (roots[1], "root_1", "root_0"),
        (roots[0], "root_0", "root_1"),
    ):
        info = gather_info(project_root=root)
        assert expected in info["dns_tags"]
        assert absent not in info["dns_tags"]
        assert f"{expected}_app" in info["application_ids"]
        assert f"{absent}_app" not in info["application_ids"]


def test_effective_config_scope_can_skip_refresh_and_restore_caches() -> None:
    from evidenceforge.generation.activity import dns_registry

    compiled = compile_scenario(_MINIMAL)
    original = dns_registry._CACHED_DATA
    sentinel = {"sentinel": True}
    dns_registry._CACHED_DATA = sentinel
    try:
        with patch("evidenceforge.config.provider._refresh_legacy_registry_globals") as refresh:
            with effective_config_scope(
                compiled.effective_config,
                refresh_legacy_globals=False,
            ):
                assert dns_registry._CACHED_DATA is None
                dns_registry._CACHED_DATA = {"inside": True}

        refresh.assert_not_called()
        assert dns_registry._CACHED_DATA is sentinel
    finally:
        dns_registry._CACHED_DATA = original


def test_validate_config_project_root_and_json_contract(tmp_path: Path) -> None:
    retired = tmp_path / ".eforge" / "config" / "activity" / "smb_file_transfers.yaml"
    retired.parent.mkdir(parents=True)
    retired.write_text("{}\n", encoding="utf-8")

    result = runner.invoke(
        app,
        ["validate-config", "--project-root", str(tmp_path), "--json"],
    )

    assert result.exit_code == EXIT_SCHEMA_VALIDATION, result.stdout
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "1.0"
    assert payload["valid"] is False
    assert payload["project_root"] == str(tmp_path.resolve())
    assert payload["severity_counts"]["error"] >= 1
    assert any("smb_file_transfers.yaml" in issue["file"] for issue in payload["issues"])


def test_validate_config_json_preserves_structured_yaml_parse_errors(tmp_path: Path) -> None:
    broken = tmp_path / ".eforge" / "config" / "activity" / "dns_registry.yaml"
    broken.parent.mkdir(parents=True)
    broken.write_text("domains: [\n", encoding="utf-8")

    result = runner.invoke(
        app,
        ["validate-config", "--project-root", str(tmp_path), "--json"],
    )

    assert result.exit_code == EXIT_SCHEMA_VALIDATION, result.stdout
    payload = json.loads(result.stdout)
    assert payload["valid"] is False
    issue = next(item for item in payload["issues"] if item["file"].endswith("dns_registry.yaml"))
    assert issue["severity"] == "error"
    assert "YAML parse error" in issue["message"]


def test_resolve_json_can_explain_without_writing() -> None:
    result = runner.invoke(
        app,
        [
            "resolve",
            str(_NORTHSTAR),
            "--explain-composition",
            "--include-effective-scenario",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.stdout
    payload = json.loads(result.stdout)
    assert payload["valid"] is True
    assert payload["written"] is False
    assert payload["output"] is None
    assert payload["composition"]["merge_rules"]
    assert payload["effective_scenario"]["environment"]["domain"] == "northstarhealth.lab"


def test_resolve_still_requires_output_for_normal_operation() -> None:
    result = runner.invoke(app, ["resolve", str(_MINIMAL), "--json"])

    assert result.exit_code == EXIT_INPUT_ERROR
    assert "--output is required" in json.loads(result.stdout)["error"]


def test_resolve_effective_scenario_is_restricted_to_json_explain(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "resolve",
            str(_MINIMAL),
            "--output",
            str(tmp_path / "resolved.yaml"),
            "--include-effective-scenario",
            "--json",
        ],
    )

    assert result.exit_code == EXIT_INPUT_ERROR
    assert "requires --explain-composition --json" in json.loads(result.stdout)["error"]
    assert not (tmp_path / "resolved.yaml").exists()


def test_generate_refuses_resolved_input_bundle_as_its_output_root(tmp_path: Path) -> None:
    compiled = compile_scenario(_MINIMAL)
    resolved = tmp_path / "RESOLVED_SCENARIO.yaml"
    resolved.write_bytes(serialize_resolved_document(build_resolved_document(compiled)))

    with patch("evidenceforge.cli.commands.GenerationEngine") as engine:
        result = runner.invoke(app, ["generate", str(resolved), "--force"])

    assert result.exit_code == EXIT_INPUT_ERROR
    assert "cannot be replayed" in result.stdout
    assert "distinct bundle root" in result.stdout
    engine.assert_not_called()


def test_validate_resolved_input_bypasses_project_discovery(tmp_path: Path) -> None:
    compiled = compile_scenario(_MINIMAL)
    resolved = tmp_path / "RESOLVED_SCENARIO.yaml"
    resolved.write_bytes(serialize_resolved_document(build_resolved_document(compiled)))

    with patch(
        "evidenceforge.composition.compiler.resolve_project_root",
        side_effect=AssertionError("resolved input must not discover a project root"),
    ):
        result = runner.invoke(app, ["validate", str(resolved), "--json"])

    assert result.exit_code == 0, result.stdout
    assert json.loads(result.stdout)["composition"]["project_root"] is None
