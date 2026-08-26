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

import re
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from evidenceforge.cli.commands import EXIT_SUCCESS, app
from evidenceforge.cli.install_skills import (
    _CHATGPT_COMMAND_REWRITES,
    _CHATGPT_REFERENCES_BY_SKILL,
    CHATGPT_SKILL_NAMES,
    find_evidenceforge_chatgpt_skills,
    install_chatgpt_skills,
    install_codex_skills,
    install_skills,
)

runner = CliRunner()
REPOSITORY_ROOT = Path(__file__).parents[2]
CANONICAL_COMMAND_ROOT = REPOSITORY_ROOT / "commands" / "eforge"

EXPECTED_SKILL_FILES = {
    "config.md",
    "evaluate.md",
    "generate.md",
    "industry-pack.md",
    "organization-pack.md",
    "pack.md",
    "scenario.md",
    "validate.md",
}
EXPECTED_REFERENCE_FILES = {
    str(path.relative_to(CANONICAL_COMMAND_ROOT))
    for path in (CANONICAL_COMMAND_ROOT / "references").glob("*.md")
}
EVIDENCE_REFERENCES = {
    "references/evidence-endpoint-linux.md",
    "references/evidence-network-ids.md",
    "references/evidence-web-email.md",
    "references/evidence-windows.md",
    "references/generation-bundle-targets.md",
}
EXPECTED_CHATGPT_REFERENCES = {
    "config": {
        "references/config-apps-processes.md",
        "references/config-dependency-graph.md",
        "references/config-dns-network.md",
        "references/config-host-activity.md",
        "references/config-ids.md",
        "references/config-personas.md",
        "references/config-validation.md",
    },
    "evaluate": EVIDENCE_REFERENCES,
    "generate": EVIDENCE_REFERENCES,
    "industry-pack": {
        "references/pack-reference.md",
        "references/scenario-reference.md",
    },
    "organization-pack": {
        "references/pack-reference.md",
        "references/scenario-reference.md",
    },
    "pack": {"references/pack-reference.md"},
    "scenario": EVIDENCE_REFERENCES
    | {
        "references/scenario-briefing.md",
        "references/scenario-core.md",
        "references/scenario-email.md",
        "references/scenario-environment.md",
        "references/scenario-http.md",
        "references/scenario-pack-consumption.md",
        "references/scenario-payloads.md",
        "references/scenario-smb.md",
        "references/scenario-storyline.md",
    },
    "validate": {
        "references/validation-safety.md",
        "references/validation-storage.md",
    },
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
        """All canonical skill markdown files are installed."""
        install_skills(tmp_path)

        eforge_dir = tmp_path / "eforge"
        for skill_file in EXPECTED_SKILL_FILES:
            assert (eforge_dir / skill_file).is_file(), f"Missing skill: {skill_file}"

    def test_copies_reference_docs(self, tmp_path):
        """Reference docs are copied to references/."""
        install_skills(tmp_path)

        for ref_path in EXPECTED_REFERENCE_FILES:
            ref = tmp_path / "eforge" / ref_path
            assert ref.is_file(), f"Missing reference: {ref_path}"
            content = ref.read_text()
            assert len(content) > 100, f"Reference doc appears empty or truncated: {ref_path}"

        # Auto-discovery should find all .md files in references/
        refs_dir = tmp_path / "eforge" / "references"
        all_refs = list(refs_dir.glob("*.md"))
        assert {f"references/{path.name}" for path in all_refs} == EXPECTED_REFERENCE_FILES

    def test_long_reference_docs_have_navigation(self):
        """References over 100 lines expose their scope before detailed content."""

        for reference in sorted((CANONICAL_COMMAND_ROOT / "references").glob("*.md")):
            text = reference.read_text(encoding="utf-8")
            if len(text.splitlines()) > 100:
                assert "contents" in text[:2_500].lower(), reference.name

    def test_bundled_contract_references_match_user_documentation(self):
        """Canonical skill references cannot silently drift from public contracts."""
        reference_pairs = (
            (
                REPOSITORY_ROOT / "docs" / "reference" / "scenario-reference.md",
                CANONICAL_COMMAND_ROOT / "references" / "scenario-reference.md",
            ),
        )

        for public_reference, skill_reference in reference_pairs:
            assert skill_reference.read_bytes() == public_reference.read_bytes()

    def test_focused_evidence_references_track_bundle_and_smtp_contracts(self):
        """Focused references retain the generated bundle and SMTP contracts."""
        bundle_reference = (
            CANONICAL_COMMAND_ROOT / "references" / "generation-bundle-targets.md"
        ).read_text(encoding="utf-8")
        email_reference = (
            CANONICAL_COMMAND_ROOT / "references" / "evidence-web-email.md"
        ).read_text(encoding="utf-8")

        for sidecar in (
            "COLLECTION_PROFILE.json",
            "STORAGE_MANIFEST.json",
            "RESOLVED_SCENARIO.yaml",
            "GENERATION_MANIFEST.json",
        ):
            assert sidecar in bundle_reference
        assert "SMTP" in email_reference
        assert "No SMTP log" not in email_reference

    def test_installed_skills_include_cross_platform_smb_contract(self, tmp_path):
        """Installed guidance retains Linux client, Samba, and manifest-v2 semantics."""

        install_skills(tmp_path)
        root = tmp_path / "eforge"
        scenario_reference = (root / "references" / "scenario-smb.md").read_text()
        bundle_reference = (root / "references" / "generation-bundle-targets.md").read_text()
        endpoint_reference = (root / "references" / "evidence-endpoint-linux.md").read_text()
        network_reference = (root / "references" / "evidence-network-ids.md").read_text()
        windows_reference = (root / "references" / "evidence-windows.md").read_text()
        host_config_reference = (root / "references" / "config-host-activity.md").read_text()
        validation_reference = (root / "references" / "config-validation.md").read_text()

        assert "client_access" in scenario_reference
        assert "smb_principal" in scenario_reference
        assert "/mnt/<mapping-id>" in scenario_reference
        assert "schema version 2" in bundle_reference
        assert "mounted CIFS" in endpoint_reference
        assert "Samba" in endpoint_reference
        assert "wire-advertised" in network_reference
        assert "never fabricate Windows" in windows_reference
        assert "smb_profiles.yaml" in host_config_reference
        assert "linux_cifs_mount" in host_config_reference
        assert "per-transport `smbd`" in host_config_reference
        assert "source_path" in host_config_reference
        assert "transfer" in host_config_reference
        assert "source_path" in validation_reference
        assert "`transfer` requires" in validation_reference

    def test_installed_generate_skill_retains_lifecycle_diagnostics_and_linux_contract(
        self,
        tmp_path,
    ):
        """Generated ChatGPT skills include the compact defect rule and focused evidence detail."""

        install_chatgpt_skills(tmp_path)
        generate = (tmp_path / "eforge-generate" / "SKILL.md").read_text(encoding="utf-8")
        endpoint = (
            tmp_path / "eforge-generate" / "references" / "evidence-endpoint-linux.md"
        ).read_text(encoding="utf-8")

        assert "Lifecycle/channel/continuation invariant failures are generator defects" in generate
        assert "do not rewrite scenario timing to mask them" in generate
        assert "retirement remains provable after the shared channel tombstone expires" in endpoint
        assert "`sleep 30`, `sleep 30.5`, and `sleep .5`" in endpoint
        assert "1,425 ms release" in endpoint

    def test_chatgpt_manifest_covers_every_canonical_command(self):
        """Every canonical top-level command has an explicit ChatGPT install mapping."""
        repository = Path(__file__).parents[2]
        source_names = {path.stem for path in (repository / "commands" / "eforge").glob("*.md")}

        assert set(CHATGPT_SKILL_NAMES) == source_names
        assert set(_CHATGPT_REFERENCES_BY_SKILL) == source_names

    def test_chatgpt_reference_manifest_matches_direct_command_invocations(self):
        """Each command bundles every directly invoked reference and no others."""
        claude_pattern = re.compile(r"/eforge:references:([a-z0-9-]+)")
        local_pattern = re.compile(r"`(references/[a-z0-9-]+\.md)`")

        for source in sorted(CANONICAL_COMMAND_ROOT.glob("*.md")):
            content = source.read_text(encoding="utf-8")
            invoked = {f"references/{name}.md" for name in claude_pattern.findall(content)}
            invoked.update(local_pattern.findall(content))
            assert invoked == set(_CHATGPT_REFERENCES_BY_SKILL[source.stem]), source.name

    def test_chatgpt_pack_command_rewrite_mappings_are_complete(self):
        """Pack-to-pack routing has ChatGPT-compatible command rewrites."""
        assert _CHATGPT_COMMAND_REWRITES["/eforge pack"] == "the `eforge-pack` skill"
        assert _CHATGPT_COMMAND_REWRITES["/eforge industry-pack"] == (
            "the `eforge-industry-pack` skill"
        )
        assert _CHATGPT_COMMAND_REWRITES["/eforge organization-pack"] == (
            "the `eforge-organization-pack` skill"
        )

    def test_chatgpt_rewrites_do_not_create_nested_inline_code(self, tmp_path):
        """Generated skills consume canonical invocation backticks exactly once."""

        install_chatgpt_skills(tmp_path)

        for markdown in tmp_path.rglob("*.md"):
            content = markdown.read_text(encoding="utf-8")
            assert "`the `eforge-" not in content, markdown
            assert "``references/" not in content, markdown
        pack_skill = (tmp_path / "eforge-pack" / "SKILL.md").read_text(encoding="utf-8")
        assert "Use the `eforge-industry-pack` skill" in pack_skill
        assert "Read `references/pack-reference.md`" in pack_skill

    def test_no_persona_files_installed(self, tmp_path):
        """Persona YAMLs are NOT installed (skills use eforge info instead)."""
        install_skills(tmp_path)

        personas_dir = tmp_path / "eforge" / "personas"
        assert not personas_dir.exists(), (
            "personas/ should not be installed — skills use eforge info"
        )

    def test_canonical_commands_have_valid_minimal_frontmatter(self, tmp_path):
        """Every canonical command and Claude copy has only name and description metadata."""
        install_skills(tmp_path)

        for source in sorted(CANONICAL_COMMAND_ROOT.glob("*.md")):
            canonical = source.read_text(encoding="utf-8")
            installed = (tmp_path / "eforge" / source.name).read_text(encoding="utf-8")
            assert installed == canonical
            assert canonical.startswith("---\n")
            frontmatter = canonical.split("---\n", 2)[1]
            parsed = yaml.safe_load(frontmatter)
            assert set(parsed) == {"name", "description"}
            assert parsed["name"] == f"eforge-{source.stem}"
            assert parsed["description"]

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
        for ref in EXPECTED_REFERENCE_FILES:
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

    def test_chatgpt_references_are_bundled(self, tmp_path):
        """Reference docs are copied beside each ChatGPT skill."""
        install_chatgpt_skills(tmp_path)

        for ref_path in EXPECTED_CHATGPT_REFERENCES["scenario"]:
            ref = tmp_path / "eforge-scenario" / ref_path
            assert ref.is_file(), f"Missing reference: {ref_path}"
            assert len(ref.read_text()) > 100

    def test_chatgpt_reference_bundle_matches_each_skill_contract(self, tmp_path):
        """Each ChatGPT skill receives exactly the references required by its workflow."""
        install_chatgpt_skills(tmp_path)

        for skill_name, expected in EXPECTED_CHATGPT_REFERENCES.items():
            references_dir = tmp_path / f"eforge-{skill_name}" / "references"
            actual = {
                str(path.relative_to(references_dir.parent))
                for path in references_dir.rglob("*.md")
            }
            assert actual == expected, skill_name

    def test_chatgpt_reference_bundles_exclude_large_or_unrelated_contracts(self):
        """Focused skills exclude exhaustive and engine-owned references from their context."""
        scenario_refs = set(_CHATGPT_REFERENCES_BY_SKILL["scenario"])
        assert scenario_refs == EXPECTED_CHATGPT_REFERENCES["scenario"]
        assert (
            not {
                "references/pack-reference.md",
                "references/scenario-authoring.md",
                "references/scenario-reference.md",
            }
            & scenario_refs
        )

        assert set(_CHATGPT_REFERENCES_BY_SKILL["evaluate"]) == EVIDENCE_REFERENCES
        assert set(_CHATGPT_REFERENCES_BY_SKILL["generate"]) == EVIDENCE_REFERENCES
        assert set(_CHATGPT_REFERENCES_BY_SKILL["validate"]) == {
            "references/validation-safety.md",
            "references/validation-storage.md",
        }
        assert not {
            "references/config-evaluation.md",
            "references/config-formats.md",
        } & set(_CHATGPT_REFERENCES_BY_SKILL["config"])
        assert all(
            "references/evidence-formats.md" not in references
            for references in _CHATGPT_REFERENCES_BY_SKILL.values()
        )

    def test_chatgpt_core_skill_bodies_stay_within_context_budget(self, tmp_path):
        """Frequently used core skill bodies remain concise enough for small chat contexts."""
        install_chatgpt_skills(tmp_path)

        for skill_name in ("config", "evaluate", "generate", "scenario", "validate"):
            skill = (tmp_path / f"eforge-{skill_name}" / "SKILL.md").read_text()
            assert len(skill.split()) <= 1_500, skill_name

    def test_core_skills_prefer_the_checkout_cli_during_development(self):
        """Development skills cannot silently exercise an older globally installed CLI."""

        for skill_name in ("config", "evaluate", "generate", "scenario", "validate"):
            skill = (CANONICAL_COMMAND_ROOT / f"{skill_name}.md").read_text(encoding="utf-8")
            assert "In an EvidenceForge source checkout, use `uv run eforge`" in skill, skill_name
            assert "Outside a source checkout, use the installed `eforge` command" in skill, (
                skill_name
            )

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

        for skill_name, references in EXPECTED_CHATGPT_REFERENCES.items():
            skill = (tmp_path / f"eforge-{skill_name}" / "SKILL.md").read_text()
            for reference in references:
                invocation = f"/eforge:references:{Path(reference).stem}"
                assert invocation not in skill
                assert f"`{reference}`" in skill

    def test_chatgpt_skills_do_not_retain_claude_invocations(self, tmp_path):
        """Generated frontmatter, bodies, and references contain no Claude invocation syntax."""
        install_chatgpt_skills(tmp_path)

        claude_invocations = set(_CHATGPT_COMMAND_REWRITES)
        for skill_file in tmp_path.glob("eforge-*/**/*.md"):
            content = skill_file.read_text(encoding="utf-8")
            for invocation in claude_invocations:
                assert invocation not in content, f"{skill_file}: {invocation}"
            assert "/eforge" not in content, skill_file
            assert re.search(r"(?<![\w-])eforge:", content) is None, skill_file

    def test_chatgpt_inline_reference_paths_resolve(self, tmp_path):
        """Every rewritten inline reference invocation resolves within its skill bundle."""
        install_chatgpt_skills(tmp_path)
        reference_pattern = re.compile(r"`(references/[a-z0-9-]+\.md)`")

        for skill_dir in tmp_path.glob("eforge-*"):
            for markdown in skill_dir.rglob("*.md"):
                content = markdown.read_text(encoding="utf-8")
                for target in reference_pattern.findall(content):
                    assert (skill_dir / target).is_file(), f"{markdown}: missing {target}"

    def test_chatgpt_skill_local_markdown_links_resolve(self, tmp_path):
        """Every relative Markdown-document link in a generated skill resolves locally."""
        install_chatgpt_skills(tmp_path)
        link_pattern = re.compile(r"\[[^]]+\]\(([^)]+)\)")

        for markdown in tmp_path.glob("eforge-*/**/*.md"):
            content = markdown.read_text(encoding="utf-8")
            for raw_target in link_pattern.findall(content):
                target = raw_target.split("#", 1)[0]
                if not target or "://" in target or target.startswith("mailto:"):
                    continue
                if not target.endswith(".md"):
                    continue
                linked_path = markdown.parent / target
                assert linked_path.is_file(), f"{markdown}: missing local link {raw_target}"

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
            "eforge-industry-pack",
            "eforge-organization-pack",
            "eforge-pack",
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
        assert (tmp_path / ".claude" / "commands" / "eforge" / "pack.md").is_file()
        assert (tmp_path / ".agents" / "skills" / "eforge-scenario" / "SKILL.md").is_file()
        assert (tmp_path / ".agents" / "skills" / "eforge-organization-pack" / "SKILL.md").is_file()

    def test_install_skills_global(self, tmp_path, monkeypatch):
        """The default global install creates both user-wide skill trees."""
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

        result = runner.invoke(app, ["install-skills", "--global"])

        assert result.exit_code == EXIT_SUCCESS, f"Output: {result.stdout}"
        assert (tmp_path / ".claude" / "commands" / "eforge" / "scenario.md").is_file()
        assert (tmp_path / ".agents" / "skills" / "eforge-scenario" / "SKILL.md").is_file()
        assert (tmp_path / ".agents" / "skills" / "eforge-industry-pack" / "SKILL.md").is_file()

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
        assert (tmp_path / ".agents" / "skills" / "eforge-pack" / "SKILL.md").is_file()
        assert not (tmp_path / ".claude").exists()
        assert "eforge-scenario" in result.stdout
        assert "eforge-industry-pack" in result.stdout

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
        assert (tmp_path / ".agents" / "skills" / "eforge-organization-pack" / "SKILL.md").is_file()
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
        assert "pack.md" in result.stdout
        assert "industry-pack.md" in result.stdout
        assert "organization-pack.md" in result.stdout
        assert "/eforge pack" in result.stdout
        assert "eforge-industry-pack" in result.stdout
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
