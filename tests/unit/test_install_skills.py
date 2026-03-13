"""Unit tests for eforge install-skills command."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from evidenceforge.cli.commands import EXIT_SUCCESS, app
from evidenceforge.cli.install_skills import install_skills

runner = CliRunner()

EXPECTED_SKILL_FILES = {"scenario.md", "generate.md", "validate.md"}
EXPECTED_PERSONA_COUNT = 15
EXPECTED_REFERENCE = "references/scenario-reference.md"


class TestInstallSkills:
    """Tests for install_skills() function."""

    def test_creates_directory_structure(self, tmp_path):
        """install_skills creates eforge/, eforge/references/, and eforge/personas/."""
        install_skills(tmp_path)

        eforge_dir = tmp_path / "eforge"
        assert eforge_dir.is_dir()
        assert (eforge_dir / "references").is_dir()
        assert (eforge_dir / "personas").is_dir()

    def test_copies_all_skill_files(self, tmp_path):
        """All three skill markdown files are installed."""
        install_skills(tmp_path)

        eforge_dir = tmp_path / "eforge"
        for skill_file in EXPECTED_SKILL_FILES:
            assert (eforge_dir / skill_file).is_file(), f"Missing skill: {skill_file}"

    def test_copies_reference_doc(self, tmp_path):
        """scenario-reference.md is copied to references/."""
        install_skills(tmp_path)

        ref = tmp_path / "eforge" / EXPECTED_REFERENCE
        assert ref.is_file()
        content = ref.read_text()
        assert len(content) > 100, "Reference doc appears empty or truncated"

    def test_copies_all_personas(self, tmp_path):
        """All 15 persona YAML files are installed."""
        install_skills(tmp_path)

        personas_dir = tmp_path / "eforge" / "personas"
        yaml_files = list(personas_dir.glob("*.yaml"))
        assert len(yaml_files) == EXPECTED_PERSONA_COUNT, (
            f"Expected {EXPECTED_PERSONA_COUNT} personas, got {len(yaml_files)}: "
            f"{[f.name for f in yaml_files]}"
        )

    def test_scenario_has_relative_paths(self, tmp_path):
        """Installed scenario.md references relative paths, not project paths."""
        install_skills(tmp_path)

        scenario = (tmp_path / "eforge" / "scenario.md").read_text()
        assert "references/scenario-reference.md" in scenario
        assert "docs/scenario-reference.md" not in scenario

    def test_idempotent(self, tmp_path):
        """Running install twice succeeds without error."""
        installed1, removed1 = install_skills(tmp_path)
        installed2, removed2 = install_skills(tmp_path)

        assert len(installed1) == len(installed2)
        assert removed2 == []  # No stale files on second run

    def test_removes_stale_files(self, tmp_path):
        """Files from a previous install that are no longer in the manifest get removed."""
        install_skills(tmp_path)

        # Simulate a stale file from a previous version
        stale_file = tmp_path / "eforge" / "old-skill.md"
        stale_file.write_text("this skill was removed")

        stale_persona = tmp_path / "eforge" / "personas" / "obsolete.yaml"
        stale_persona.write_text("name: obsolete")

        _, removed = install_skills(tmp_path)

        assert "old-skill.md" in removed
        assert "personas/obsolete.yaml" in removed
        assert not stale_file.exists()
        assert not stale_persona.exists()

    def test_stale_removal_does_not_touch_outside_eforge(self, tmp_path):
        """Stale file cleanup only affects eforge/ directory."""
        install_skills(tmp_path)

        # Create a file outside eforge/ in the target dir
        outside_file = tmp_path / "unrelated.md"
        outside_file.write_text("not a skill")

        install_skills(tmp_path)

        assert outside_file.exists(), "File outside eforge/ should not be touched"

    def test_returns_installed_and_removed_lists(self, tmp_path):
        """install_skills returns lists of installed and removed files."""
        installed, removed = install_skills(tmp_path)

        assert len(installed) > 0
        assert "scenario.md" in installed
        assert "generate.md" in installed
        assert "validate.md" in installed
        assert EXPECTED_REFERENCE in installed
        assert any(f.startswith("personas/") for f in installed)
        assert isinstance(removed, list)


class TestInstallSkillsCli:
    """Tests for the CLI command integration."""

    def test_install_skills_project_default(self, tmp_path, monkeypatch):
        """eforge install-skills copies files to .claude/commands/ in cwd."""
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["install-skills"])

        assert result.exit_code == EXIT_SUCCESS, f"Output: {result.stdout}"
        assert (tmp_path / ".claude" / "commands" / "eforge" / "scenario.md").is_file()
        assert (tmp_path / ".claude" / "commands" / "eforge" / "generate.md").is_file()
        assert (tmp_path / ".claude" / "commands" / "eforge" / "validate.md").is_file()

    def test_install_skills_global(self, tmp_path, monkeypatch):
        """eforge install-skills --global copies files to ~/.claude/commands/."""
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

        result = runner.invoke(app, ["install-skills", "--global"])

        assert result.exit_code == EXIT_SUCCESS, f"Output: {result.stdout}"
        assert (tmp_path / ".claude" / "commands" / "eforge" / "scenario.md").is_file()

    def test_install_skills_shows_file_list(self, tmp_path, monkeypatch):
        """Command output lists installed files."""
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["install-skills"])

        assert "scenario.md" in result.stdout
        assert "generate.md" in result.stdout
        assert "validate.md" in result.stdout
        assert "installed" in result.stdout.lower() or "Installed" in result.stdout
