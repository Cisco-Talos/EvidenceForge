# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""Unit tests for eforge install-skills command."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from evidenceforge.cli.commands import EXIT_SUCCESS, app
from evidenceforge.cli.install_skills import install_skills

runner = CliRunner()

# Minimum expected files — auto-discovery may find more, but these must exist.
EXPECTED_SKILL_FILES = {"scenario.md", "generate.md", "validate.md", "evaluate.md", "config.md"}
EXPECTED_REFERENCES_MIN = {
    "references/scenario-reference.md",
    "references/evidence-formats.md",
}


class TestInstallSkills:
    """Tests for install_skills() function."""

    def test_creates_directory_structure(self, tmp_path):
        """install_skills creates eforge/ and eforge/references/."""
        install_skills(tmp_path)

        eforge_dir = tmp_path / "eforge"
        assert eforge_dir.is_dir()
        assert (eforge_dir / "references").is_dir()

    def test_copies_all_skill_files(self, tmp_path):
        """All three skill markdown files are installed."""
        install_skills(tmp_path)

        eforge_dir = tmp_path / "eforge"
        for skill_file in EXPECTED_SKILL_FILES:
            assert (eforge_dir / skill_file).is_file(), f"Missing skill: {skill_file}"

    def test_copies_reference_docs(self, tmp_path):
        """Reference docs are copied to references/."""
        install_skills(tmp_path)

        for ref_path in EXPECTED_REFERENCES_MIN:
            ref = tmp_path / "eforge" / ref_path
            assert ref.is_file(), f"Missing reference: {ref_path}"
            content = ref.read_text()
            assert len(content) > 100, f"Reference doc appears empty or truncated: {ref_path}"

        # Auto-discovery should find all .md files in references/
        refs_dir = tmp_path / "eforge" / "references"
        all_refs = list(refs_dir.glob("*.md"))
        assert len(all_refs) >= len(EXPECTED_REFERENCES_MIN), (
            f"Expected at least {len(EXPECTED_REFERENCES_MIN)} references, got {len(all_refs)}"
        )

    def test_no_persona_files_installed(self, tmp_path):
        """Persona YAMLs are NOT installed (skills use eforge info instead)."""
        install_skills(tmp_path)

        personas_dir = tmp_path / "eforge" / "personas"
        assert not personas_dir.exists(), (
            "personas/ should not be installed — skills use eforge info"
        )

    def test_scenario_uses_subskill_references(self, tmp_path):
        """Installed scenario.md uses sub-skill invocation, not file paths."""
        install_skills(tmp_path)

        scenario = (tmp_path / "eforge" / "scenario.md").read_text()
        assert "/eforge:references:scenario-reference" in scenario
        assert "references/scenario-reference.md" not in scenario

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

        _, removed = install_skills(tmp_path)

        assert "old-skill.md" in removed
        assert not stale_file.exists()

    def test_stale_removal_does_not_touch_outside_eforge(self, tmp_path):
        """Stale file cleanup only affects eforge/ directory."""
        install_skills(tmp_path)

        # Create a file outside eforge/ in the target dir
        outside_file = tmp_path / "unrelated.md"
        outside_file.write_text("not a skill")

        install_skills(tmp_path)

        assert outside_file.exists(), "File outside eforge/ should not be touched"

    def test_rejects_symlinked_eforge_directory(self, tmp_path):
        """install_skills rejects a symlinked eforge/ directory."""
        victim_dir = tmp_path / "victim"
        victim_dir.mkdir()
        (tmp_path / "eforge").symlink_to(victim_dir, target_is_directory=True)

        with pytest.raises(PermissionError, match="symlinked directory"):
            install_skills(tmp_path)

    def test_returns_installed_and_removed_lists(self, tmp_path):
        """install_skills returns lists of installed and removed files."""
        installed, removed = install_skills(tmp_path)

        assert len(installed) > 0
        for skill in EXPECTED_SKILL_FILES:
            assert skill in installed, f"Missing skill in installed list: {skill}"
        for ref in EXPECTED_REFERENCES_MIN:
            assert ref in installed, f"Missing reference in installed list: {ref}"
        assert not any(f.startswith("personas/") for f in installed), (
            "Personas should not be installed"
        )
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
        assert (tmp_path / ".claude" / "commands" / "eforge" / "config.md").is_file()

    def test_install_skills_global(self, tmp_path, monkeypatch):
        """eforge install-skills --global copies files to ~/.claude/commands/."""
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

        result = runner.invoke(app, ["install-skills", "--global"])

        assert result.exit_code == EXIT_SUCCESS, f"Output: {result.stdout}"
        assert (tmp_path / ".claude" / "commands" / "eforge" / "scenario.md").is_file()
        assert (tmp_path / ".claude" / "commands" / "eforge" / "config.md").is_file()

    def test_install_skills_shows_file_list(self, tmp_path, monkeypatch):
        """Command output lists installed files."""
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["install-skills"])

        assert "scenario.md" in result.stdout
        assert "generate.md" in result.stdout
        assert "validate.md" in result.stdout
        assert "config.md" in result.stdout
        assert "installed" in result.stdout.lower() or "Installed" in result.stdout

    def test_install_skills_rejects_symlink_target(self, tmp_path, monkeypatch):
        """CLI returns input error when eforge target is a symlink."""
        monkeypatch.chdir(tmp_path)
        commands_dir = tmp_path / ".claude" / "commands"
        commands_dir.mkdir(parents=True)
        (commands_dir / "eforge").symlink_to(tmp_path / "victim", target_is_directory=True)

        result = runner.invoke(app, ["install-skills"])

        assert result.exit_code == 1
        assert "symlinked directory" in result.stdout
