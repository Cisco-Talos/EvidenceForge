# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Current-working-directory project-root contracts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from evidenceforge.cli.commands import EXIT_SCHEMA_VALIDATION, app
from evidenceforge.composition.compiler import (
    resolve_management_project_root,
    resolve_project_root,
)

runner = CliRunner()
_NORTHSTAR = Path("tests/fixtures/scenarios/northstar-health-pack.yaml").resolve()


def test_implicit_project_root_is_current_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Scenario and management resolution share the process working directory."""

    working_directory = tmp_path / "work"
    scenario_directory = tmp_path / "scenario-project"
    working_directory.mkdir()
    scenario_directory.mkdir()
    scenario = scenario_directory / "scenario.yaml"
    scenario.write_text("name: placeholder\n", encoding="utf-8")
    monkeypatch.chdir(working_directory)

    assert resolve_project_root(scenario) == working_directory.resolve()
    assert resolve_management_project_root() == working_directory.resolve()


def test_implicit_project_root_ignores_ancestor_eforge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A parent overlay cannot leak into a child working directory."""

    (tmp_path / ".eforge").mkdir()
    working_directory = tmp_path / "nested" / "work"
    working_directory.mkdir(parents=True)
    scenario = tmp_path / "scenario.yaml"
    scenario.write_text("name: placeholder\n", encoding="utf-8")
    monkeypatch.chdir(working_directory)

    assert resolve_project_root(scenario) == working_directory.resolve()
    assert resolve_management_project_root() == working_directory.resolve()


def test_explicit_project_root_always_wins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The supported override is independent of scenario and working-directory paths."""

    working_directory = tmp_path / "work"
    explicit = tmp_path / "selected"
    working_directory.mkdir()
    explicit.mkdir()
    monkeypatch.chdir(working_directory)

    assert resolve_project_root(tmp_path / "elsewhere" / "scenario.yaml", explicit) == explicit
    assert resolve_management_project_root(explicit) == explicit


def test_missing_input_json_reports_current_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Early validation diagnostics use cwd rather than the missing scenario's directory."""

    working_directory = tmp_path / "work"
    working_directory.mkdir()
    missing = tmp_path / "elsewhere" / "missing.yaml"
    monkeypatch.chdir(working_directory)

    result = runner.invoke(app, ["validate", str(missing), "--json"])

    assert result.exit_code != 0
    payload = json.loads(result.stdout)
    assert payload["issues"][0]["code"] == "input.not_found"
    assert payload["composition"]["project_root"] == str(working_directory.resolve())


def test_no_flag_cli_commands_use_only_current_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pack and config inspection do not inherit a parent project."""

    parent = tmp_path / "project"
    child = parent / "empty-work"
    child.mkdir(parents=True)
    copied = runner.invoke(
        app,
        [
            "pack",
            "copy",
            "package:organization:northstar-health@1.0.0",
            "--name",
            "parent-only-org",
            "--version",
            "1.0.0",
            "--project-root",
            str(parent),
            "--json",
        ],
    )
    assert copied.exit_code == 0, copied.stdout

    monkeypatch.chdir(child)
    listed = runner.invoke(app, ["pack", "list", "--json"])
    overlay = runner.invoke(app, ["info", "overlay.path", "--json"])
    validated = runner.invoke(app, ["validate-config", "--json"])

    assert listed.exit_code == 0, listed.stdout
    assert "parent-only-org" not in {pack["name"] for pack in json.loads(listed.stdout)["packs"]}
    assert json.loads(overlay.stdout) == str(child / ".eforge" / "config")
    assert validated.exit_code == 0, validated.stdout
    assert json.loads(validated.stdout)["project_root"] == str(child.resolve())

    monkeypatch.chdir(parent)
    local = runner.invoke(app, ["pack", "list", "--json"])
    assert local.exit_code == 0, local.stdout
    assert "parent-only-org" in {pack["name"] for pack in json.loads(local.stdout)["packs"]}


def test_project_pack_requires_explicit_override_when_scenario_is_elsewhere(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A scenario path cannot implicitly select a neighboring project pack."""

    project = tmp_path / "project"
    working_directory = tmp_path / "work"
    project.mkdir()
    working_directory.mkdir()
    copied = runner.invoke(
        app,
        [
            "pack",
            "copy",
            "package:organization:northstar-health@1.0.0",
            "--name",
            "explicit-org",
            "--version",
            "1.0.0",
            "--project-root",
            str(project),
            "--json",
        ],
    )
    assert copied.exit_code == 0, copied.stdout

    scenario = project / "scenario.yaml"
    scenario.write_text(
        _NORTHSTAR.read_text(encoding="utf-8")
        .replace("source: package", "source: project")
        .replace("name: northstar-health", "name: explicit-org", 1),
        encoding="utf-8",
    )
    monkeypatch.chdir(working_directory)

    implicit = runner.invoke(app, ["validate", str(scenario), "--json"])
    explicit = runner.invoke(
        app,
        ["validate", str(scenario), "--project-root", str(project), "--json"],
    )

    assert implicit.exit_code == EXIT_SCHEMA_VALIDATION
    assert "project organization pack explicit-org@1.0.0 was not found" in implicit.stdout
    assert explicit.exit_code == 0, explicit.stdout
    assert json.loads(explicit.stdout)["composition"]["project_root"] == str(project.resolve())
