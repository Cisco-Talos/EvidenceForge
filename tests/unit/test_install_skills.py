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
from evidenceforge.cli.install_skills import (
    find_evidenceforge_chatgpt_skills,
    install_chatgpt_skills,
    install_codex_skills,
    install_skills,
)

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

    def test_installed_config_skill_mentions_identity_pools(self, tmp_path):
        """Installed config skill and references document generated identity pools."""
        install_skills(tmp_path)

        config_skill = (tmp_path / "eforge" / "config.md").read_text()
        config_ref = (tmp_path / "eforge" / "references" / "config-dns-network.md").read_text()
        validation_ref = (tmp_path / "eforge" / "references" / "config-validation.md").read_text()

        assert "identity_pools" in config_skill
        assert "external_actor_profiles.yaml" in config_ref
        assert "command_parameter_pools.yaml" in validation_ref

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


class TestInstallChatGPTSkills:
    """Tests for ChatGPT skill installation."""

    def test_creates_chatgpt_skill_directories(self, tmp_path):
        """install_chatgpt_skills creates one skill directory per command."""
        install_chatgpt_skills(tmp_path)

        for name in EXPECTED_SKILL_FILES:
            command_name = name.removesuffix(".md")
            assert (tmp_path / f"eforge-{command_name}" / "SKILL.md").is_file()

    def test_chatgpt_frontmatter_remains_valid(self, tmp_path):
        """Installed ChatGPT SKILL.md frontmatter is valid and minimal."""
        install_chatgpt_skills(tmp_path)

        for skill_file in EXPECTED_SKILL_FILES:
            command_name = skill_file.removesuffix(".md")
            skill = (tmp_path / f"eforge-{command_name}" / "SKILL.md").read_text()
            assert skill.startswith("---\n")
            frontmatter = skill.split("---\n", 2)[1]
            parsed = yaml.safe_load(frontmatter)
            assert set(parsed) == {"name", "description"}
            assert parsed["name"] == f"eforge-{command_name}"
            assert parsed["description"]

    def test_chatgpt_frontmatter_removes_claude_license(self, tmp_path):
        """ChatGPT SKILL.md files drop Claude-only license frontmatter fields."""
        install_chatgpt_skills(tmp_path)

        for skill_file in EXPECTED_SKILL_FILES:
            command_name = skill_file.removesuffix(".md")
            skill = (tmp_path / f"eforge-{command_name}" / "SKILL.md").read_text()
            frontmatter = skill.split("---\n", 2)[1]
            assert "license:" not in frontmatter

    def test_chatgpt_references_are_bundled(self, tmp_path):
        """Reference docs are copied beside each ChatGPT skill."""
        install_chatgpt_skills(tmp_path)

        for ref_path in EXPECTED_REFERENCES_MIN:
            ref = tmp_path / "eforge-scenario" / ref_path
            assert ref.is_file(), f"Missing reference: {ref_path}"
            assert len(ref.read_text()) > 100

    def test_chatgpt_config_skill_mentions_identity_pools(self, tmp_path):
        """Installed ChatGPT config skill includes identity-pool references."""
        install_chatgpt_skills(tmp_path)

        config_skill = (tmp_path / "eforge-config" / "SKILL.md").read_text()
        config_ref = (
            tmp_path / "eforge-config" / "references" / "config-dns-network.md"
        ).read_text()

        assert "identity_pools" in config_skill
        assert "mail_public_identities.yaml" in config_ref

    def test_chatgpt_references_are_limited_per_skill(self, tmp_path):
        """ChatGPT skills only receive the references they need."""
        install_chatgpt_skills(tmp_path)

        assert (tmp_path / "eforge-config" / "references" / "config-personas.md").is_file()
        assert not (tmp_path / "eforge-scenario" / "references" / "config-personas.md").exists()
        assert not (tmp_path / "eforge-validate" / "references" / "evidence-formats.md").exists()

    def test_chatgpt_install_prunes_no_longer_needed_references(self, tmp_path):
        """ChatGPT reinstall removes references left by older all-reference installs."""
        old_ref = tmp_path / "eforge-scenario" / "references" / "config-personas.md"
        old_ref.parent.mkdir(parents=True)
        old_ref.write_text("old duplicated reference")

        _, removed = install_chatgpt_skills(tmp_path)

        assert "eforge-scenario/references/config-personas.md" in removed
        assert not old_ref.exists()

    def test_chatgpt_rewrites_claude_reference_invocations(self, tmp_path):
        """ChatGPT skills use local reference paths instead of Claude sub-skill syntax."""
        install_chatgpt_skills(tmp_path)

        skill = (tmp_path / "eforge-scenario" / "SKILL.md").read_text()
        assert "/eforge:references:scenario-reference" not in skill
        assert "`references/scenario-reference.md`" in skill

    def test_chatgpt_preserves_user_managed_eforge_skills(self, tmp_path):
        """ChatGPT install preserves sibling eforge-* skills it does not own."""
        assess_dir = tmp_path / "eforge-assess"
        assess_dir.mkdir()
        sentinel = assess_dir / "sentinel.txt"
        sentinel.write_text("keep me")
        (assess_dir / "SKILL.md").write_text(
            "---\nname: eforge-assess\ndescription: User managed skill\n---\n"
        )

        _, removed = install_chatgpt_skills(tmp_path)

        assert "eforge-assess" not in removed
        assert sentinel.read_text() == "keep me"
        assert (assess_dir / "SKILL.md").is_file()

    def test_chatgpt_rejects_symlinked_skill_directory(self, tmp_path):
        """install_chatgpt_skills rejects a symlinked target skill directory."""
        victim_dir = tmp_path / "victim"
        victim_dir.mkdir()
        (tmp_path / "eforge-scenario").symlink_to(victim_dir, target_is_directory=True)

        with pytest.raises(PermissionError, match="symlinked path"):
            install_chatgpt_skills(tmp_path)

    def test_chatgpt_rejects_symlinked_skill_file(self, tmp_path):
        """install_chatgpt_skills rejects a symlinked SKILL.md destination file."""
        victim_file = tmp_path / "victim.txt"
        victim_file.write_text("do not overwrite")
        skill_dir = tmp_path / "eforge-scenario"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").symlink_to(victim_file)

        with pytest.raises(PermissionError, match="symlinked path"):
            install_chatgpt_skills(tmp_path)

        assert victim_file.read_text() == "do not overwrite"

    def test_chatgpt_rejects_symlinked_reference_directory(self, tmp_path):
        """install_chatgpt_skills rejects nested symlinked reference directories."""
        outside_refs = tmp_path / "outside_refs"
        outside_refs.mkdir()
        skill_dir = tmp_path / "eforge-scenario"
        skill_dir.mkdir()
        (skill_dir / "references").symlink_to(outside_refs, target_is_directory=True)

        with pytest.raises(PermissionError, match="symlinked path"):
            install_chatgpt_skills(tmp_path)

        assert list(outside_refs.iterdir()) == []

    def test_legacy_codex_function_is_compatibility_alias(self, tmp_path):
        """The legacy installer function still creates ChatGPT-compatible skills."""
        install_codex_skills(tmp_path)

        assert (tmp_path / "eforge-scenario" / "SKILL.md").is_file()

    def test_finds_only_installer_owned_chatgpt_skills(self, tmp_path):
        """Legacy detection ignores unrelated and user-managed skill directories."""
        install_chatgpt_skills(tmp_path)
        unrelated_dir = tmp_path / "unrelated"
        unrelated_dir.mkdir()
        (unrelated_dir / "SKILL.md").write_text(
            "---\nname: unrelated\ndescription: Another skill\n---\n"
        )
        assess_dir = tmp_path / "eforge-assess"
        assess_dir.mkdir()
        (assess_dir / "SKILL.md").write_text(
            "---\nname: eforge-assess\ndescription: User managed skill\n---\n"
        )

        found = find_evidenceforge_chatgpt_skills(tmp_path)

        assert {path.name for path in found} == {
            "eforge-config",
            "eforge-evaluate",
            "eforge-generate",
            "eforge-scenario",
            "eforge-validate",
        }


class TestInstallSkillsCli:
    """Tests for the CLI command integration."""

    def test_install_skills_project_default(self, tmp_path, monkeypatch):
        """The default project install creates Claude and ChatGPT skill trees."""
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["install-skills"])

        assert result.exit_code == EXIT_SUCCESS, f"Output: {result.stdout}"
        assert (tmp_path / ".claude" / "commands" / "eforge" / "scenario.md").is_file()
        assert (tmp_path / ".agents" / "skills" / "eforge-scenario" / "SKILL.md").is_file()

    def test_install_skills_global(self, tmp_path, monkeypatch):
        """The default global install creates both user-wide skill trees."""
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

        result = runner.invoke(app, ["install-skills", "--global"])

        assert result.exit_code == EXIT_SUCCESS, f"Output: {result.stdout}"
        assert (tmp_path / ".claude" / "commands" / "eforge" / "scenario.md").is_file()
        assert (tmp_path / ".agents" / "skills" / "eforge-scenario" / "SKILL.md").is_file()

    def test_install_skills_explicit_all(self, tmp_path, monkeypatch):
        """--agent all installs each canonical agent exactly once."""
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["install-skills", "--agent", "all"])

        assert result.exit_code == EXIT_SUCCESS, f"Output: {result.stdout}"
        assert (tmp_path / ".claude" / "commands" / "eforge" / "scenario.md").is_file()
        assert (tmp_path / ".agents" / "skills" / "eforge-scenario" / "SKILL.md").is_file()
        assert result.stdout.count("Installing EvidenceForge skills for chatgpt") == 1

    def test_install_skills_claude_global_with_agent(self, tmp_path, monkeypatch):
        """eforge install-skills --agent claude --global keeps Claude global behavior."""
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

        result = runner.invoke(app, ["install-skills", "--agent", "claude", "--global"])

        assert result.exit_code == EXIT_SUCCESS, f"Output: {result.stdout}"
        assert (tmp_path / ".claude" / "commands" / "eforge" / "scenario.md").is_file()
        assert not (tmp_path / ".agents").exists()
        assert "/eforge scenario" in result.stdout

    def test_install_skills_chatgpt_project(self, tmp_path, monkeypatch):
        """--agent chatgpt installs project skills under .agents/skills."""
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["install-skills", "--agent", "chatgpt"])

        assert result.exit_code == EXIT_SUCCESS, f"Output: {result.stdout}"
        assert (tmp_path / ".agents" / "skills" / "eforge-scenario" / "SKILL.md").is_file()
        assert not (tmp_path / ".claude").exists()
        assert "eforge-scenario" in result.stdout

    @pytest.mark.parametrize("agent", ["chatgpt", "codex"])
    def test_install_skills_chatgpt_global(self, tmp_path, monkeypatch, agent):
        """ChatGPT and its Codex alias install globally under .agents/skills."""
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

        result = runner.invoke(app, ["install-skills", "--agent", agent, "--global"])

        assert result.exit_code == EXIT_SUCCESS, f"Output: {result.stdout}"
        assert (tmp_path / ".agents" / "skills" / "eforge-scenario" / "SKILL.md").is_file()
        assert not (tmp_path / ".codex" / "skills").exists()

    def test_install_skills_codex_project_alias(self, tmp_path, monkeypatch):
        """The Codex alias uses the ChatGPT project destination."""
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["install-skills", "--agent", "codex"])

        assert result.exit_code == EXIT_SUCCESS, f"Output: {result.stdout}"
        assert (tmp_path / ".agents" / "skills" / "eforge-config" / "SKILL.md").is_file()
        assert "Installing EvidenceForge skills for chatgpt" in result.stdout

    def test_install_skills_rejects_unknown_agent(self, tmp_path, monkeypatch):
        """Unknown agents fail before creating any skill destinations."""
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["install-skills", "--agent", "other"])

        assert result.exit_code == 1
        assert "Unknown agent" in result.stdout
        assert not (tmp_path / ".claude").exists()
        assert not (tmp_path / ".agents").exists()

    def test_install_skills_shows_file_list(self, tmp_path, monkeypatch):
        """Command output lists installed files."""
        monkeypatch.chdir(tmp_path)

        result = runner.invoke(app, ["install-skills"])

        assert "scenario.md" in result.stdout
        assert "generate.md" in result.stdout
        assert "validate.md" in result.stdout
        assert "config.md" in result.stdout
        assert "installed" in result.stdout.lower() or "Installed" in result.stdout

    def test_install_skills_all_continues_after_one_failure(self, tmp_path, monkeypatch):
        """A failed target does not prevent later selected agents from installing."""
        monkeypatch.chdir(tmp_path)
        commands_dir = tmp_path / ".claude" / "commands"
        commands_dir.mkdir(parents=True)
        (commands_dir / "eforge").symlink_to(tmp_path / "victim", target_is_directory=True)

        result = runner.invoke(app, ["install-skills"])

        assert result.exit_code == 1
        assert "symlinked path" in result.stdout
        assert "Skill installation completed with errors" in result.stdout
        assert (tmp_path / ".agents" / "skills" / "eforge-scenario" / "SKILL.md").is_file()

    def test_global_chatgpt_warns_about_preserved_legacy_skills(self, tmp_path, monkeypatch):
        """Global ChatGPT installs warn about legacy skills without changing them."""
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        legacy_dir = tmp_path / ".codex" / "skills"
        install_chatgpt_skills(legacy_dir)
        sentinel = legacy_dir / "eforge-scenario" / "legacy-sentinel.txt"
        sentinel.write_text("preserve me")

        result = runner.invoke(app, ["install-skills", "--agent", "chatgpt", "--global"])

        assert result.exit_code == EXIT_SUCCESS, f"Output: {result.stdout}"
        assert "Legacy EvidenceForge skills" in result.stdout
        # Rich may wrap the long temporary home path at the slash depending on
        # the pytest worker suffix; normalize line wrapping before matching.
        assert ".codex/skills" in result.stdout.replace("\n", "")
        assert "These legacy files were not modified" in result.stdout
        assert sentinel.read_text() == "preserve me"
