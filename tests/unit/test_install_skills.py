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
import yaml
from typer.testing import CliRunner

from evidenceforge.cli.commands import EXIT_SUCCESS, app
from evidenceforge.cli.install_skills import install_codex_skills, install_skills

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

    def test_claude_install_preserves_source_frontmatter(self, tmp_path):
        """Claude command installs preserve Claude-only source frontmatter."""
        install_skills(tmp_path)

        scenario = (tmp_path / "eforge" / "scenario.md").read_text()
        assert "\nlicense: Copyright (c) 2026 Cisco Systems, Inc. and its affiliates;" in scenario

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

        with pytest.raises(PermissionError, match="symlinked path"):
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


class TestInstallCodexSkills:
    """Tests for Codex skill installation."""

    def test_creates_codex_skill_directories(self, tmp_path):
        """install_codex_skills creates one skill directory per command."""
        install_codex_skills(tmp_path)

        for name in EXPECTED_SKILL_FILES:
            command_name = name.removesuffix(".md")
            assert (tmp_path / f"eforge-{command_name}" / "SKILL.md").is_file()

    def test_codex_frontmatter_remains_valid(self, tmp_path):
        """Installed Codex SKILL.md frontmatter is valid and Codex-only."""
        install_codex_skills(tmp_path)

        for skill_file in EXPECTED_SKILL_FILES:
            command_name = skill_file.removesuffix(".md")
            skill = (tmp_path / f"eforge-{command_name}" / "SKILL.md").read_text()
            assert skill.startswith("---\n")
            frontmatter = skill.split("---\n", 2)[1]
            parsed = yaml.safe_load(frontmatter)
            assert set(parsed) == {"name", "description"}
            assert parsed["name"] == f"eforge-{command_name}"
            assert parsed["description"]

    def test_codex_frontmatter_removes_claude_license(self, tmp_path):
        """Codex SKILL.md files drop Claude-only license frontmatter fields."""
        install_codex_skills(tmp_path)

        for skill_file in EXPECTED_SKILL_FILES:
            command_name = skill_file.removesuffix(".md")
            skill = (tmp_path / f"eforge-{command_name}" / "SKILL.md").read_text()
            frontmatter = skill.split("---\n", 2)[1]
            assert "license:" not in frontmatter

    def test_codex_references_are_bundled(self, tmp_path):
        """Reference docs are copied beside each Codex skill."""
        install_codex_skills(tmp_path)

        for ref_path in EXPECTED_REFERENCES_MIN:
            ref = tmp_path / "eforge-scenario" / ref_path
            assert ref.is_file(), f"Missing reference: {ref_path}"
            assert len(ref.read_text()) > 100

    def test_codex_references_are_limited_per_skill(self, tmp_path):
        """Codex skills only receive the references they need."""
        install_codex_skills(tmp_path)

        assert (tmp_path / "eforge-config" / "references" / "config-personas.md").is_file()
        assert not (tmp_path / "eforge-scenario" / "references" / "config-personas.md").exists()
        assert not (tmp_path / "eforge-validate" / "references" / "evidence-formats.md").exists()

    def test_codex_install_prunes_no_longer_needed_references(self, tmp_path):
        """Codex reinstall removes references left by older all-reference installs."""
        old_ref = tmp_path / "eforge-scenario" / "references" / "config-personas.md"
        old_ref.parent.mkdir(parents=True)
        old_ref.write_text("old duplicated reference")

        _, removed = install_codex_skills(tmp_path)

        assert "eforge-scenario/references/config-personas.md" in removed
        assert not old_ref.exists()

    def test_codex_rewrites_claude_reference_invocations(self, tmp_path):
        """Codex skills use local reference paths instead of Claude sub-skill syntax."""
        install_codex_skills(tmp_path)

        skill = (tmp_path / "eforge-scenario" / "SKILL.md").read_text()
        assert "/eforge:references:scenario-reference" not in skill
        assert "`references/scenario-reference.md`" in skill

    def test_codex_preserves_user_managed_eforge_skills(self, tmp_path):
        """Codex install does not remove sibling eforge-* skills it does not own."""
        assess_dir = tmp_path / "eforge-assess"
        assess_dir.mkdir()
        sentinel = assess_dir / "sentinel.txt"
        sentinel.write_text("keep me")
        (assess_dir / "SKILL.md").write_text(
            "---\nname: eforge-assess\ndescription: User managed skill\n---\n"
        )

        _, removed = install_codex_skills(tmp_path)

        assert "eforge-assess" not in removed
        assert sentinel.read_text() == "keep me"
        assert (assess_dir / "SKILL.md").is_file()

    def test_codex_rejects_symlinked_skill_directory(self, tmp_path):
        """install_codex_skills rejects a symlinked target skill directory."""
        victim_dir = tmp_path / "victim"
        victim_dir.mkdir()
        (tmp_path / "eforge-scenario").symlink_to(victim_dir, target_is_directory=True)

        with pytest.raises(PermissionError, match="symlinked path"):
            install_codex_skills(tmp_path)


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

    def test_install_skills_claude_global_with_agent(self, tmp_path, monkeypatch):
        """eforge install-skills --agent claude --global keeps Claude global behavior."""
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

        result = runner.invoke(app, ["install-skills", "--agent", "claude", "--global"])

        assert result.exit_code == EXIT_SUCCESS, f"Output: {result.stdout}"
        assert (tmp_path / ".claude" / "commands" / "eforge" / "scenario.md").is_file()
        assert "/eforge scenario" in result.stdout

    def test_install_skills_codex(self, tmp_path, monkeypatch):
        """eforge install-skills --agent codex copies files to ~/.codex/skills/."""
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

        result = runner.invoke(app, ["install-skills", "--agent", "codex"])

        assert result.exit_code == EXIT_SUCCESS, f"Output: {result.stdout}"
        assert (tmp_path / ".codex" / "skills" / "eforge-scenario" / "SKILL.md").is_file()
        assert (tmp_path / ".codex" / "skills" / "eforge-config" / "SKILL.md").is_file()
        assert "eforge-scenario" in result.stdout

    def test_install_skills_codex_rejects_global(self, tmp_path, monkeypatch):
        """--global is invalid for Codex installs."""
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

        result = runner.invoke(app, ["install-skills", "--agent", "codex", "--global"])

        assert result.exit_code == 1
        assert "--global is only valid for Claude installs" in result.stdout
        assert not (tmp_path / ".codex" / "skills").exists()

    def test_install_skills_rejects_unknown_agent(self, tmp_path, monkeypatch):
        """Unknown agents return an input error."""
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["install-skills", "--agent", "other"])

        assert result.exit_code == 1
        assert "Unknown agent" in result.stdout

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
        assert "symlinked path" in result.stdout
