# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Contract tests for the compact scenario-validation skill."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SKILL_PATH = ROOT / "commands" / "eforge" / "validate.md"
SAFETY_PATH = ROOT / "commands" / "eforge" / "references" / "validation-safety.md"
STORAGE_PATH = ROOT / "commands" / "eforge" / "references" / "validation-storage.md"


def _read(path: Path) -> str:
    """Read one canonical skill artifact."""

    return path.read_text(encoding="utf-8")


def _frontmatter(text: str) -> dict[str, str]:
    """Parse the YAML frontmatter from one Markdown skill."""

    _, raw, _ = text.split("---", 2)
    payload = yaml.safe_load(raw)
    assert isinstance(payload, dict)
    return payload


def test_validate_skill_is_compact_and_routes_narrowly() -> None:
    """The always-loaded body stays compact and excludes pack/config validation."""

    text = _read(SKILL_PATH)
    assert 100 <= len(text.splitlines()) <= 140
    assert set(_frontmatter(text)) == {"name", "description"}
    assert "authored EvidenceForge Scenario 1.0/2.0" in text
    assert "authoritative RESOLVED_SCENARIO.yaml" in text
    assert "Use the pack skill for direct pack" in text
    assert "config skill for `.eforge/config`" in text
    assert 'mentions "validate"' not in text


def test_validate_skill_defaults_to_read_only_structured_validation() -> None:
    """Validation does not mutate input unless repair was explicitly requested."""

    text = _read(SKILL_PATH)
    assert "read-only unless the user explicitly asks for repair" in text
    assert "eforge validate <absolute-scenario-path> \\\n  --json" in text
    assert "current working directory" in text
    assert "omit `--project-root` unless" in text
    assert "If the user asked only to check, stop after reporting" in text
    assert "Mechanical" in text
    assert "Directly implied" in text
    assert "Semantic choice" in text
    assert "Never flatten includes" in text
    assert "Never repair `RESOLVED_SCENARIO.yaml`" in text
    assert "Usage help or an unknown-option error with exit `2`" in text
    assert "does not prove the scenario is invalid" in text
    assert "Known optional fields" not in text


def test_validate_skill_uses_non_writing_composition_explanation() -> None:
    """Composition provenance can be inspected without creating a resolved artifact."""

    text = _read(SKILL_PATH)
    assert "Do not run `resolve` merely to validate" in text
    assert "non-writing explanation mode" in text
    assert "omit `--output`" in text
    assert "--explain-composition --json" in text
    assert "`--include-effective-scenario` only when" in text
    assert "fresh safe output path" not in text
    assert "it writes an output document" not in text


def test_validate_skill_preserves_input_and_safety_boundaries() -> None:
    """Version, source-origin, pack silence, and fresh OOB rules remain explicit."""

    text = _read(SKILL_PATH)
    for expected in (
        'version: "1.0"',
        'scenario_version: "2.0"',
        "kind: evidenceforge.resolved-scenario",
        "declaring source",
        "never requires pack discovery",
        "A fresh matching flag is independently required",
    ):
        assert expected in text
    assert "Never infer or copy it" in text
    assert "Validation makes no callback" in text


def test_validate_skill_uses_small_conditional_references() -> None:
    """Specialized safety and storage guidance is loaded only when relevant."""

    skill = _read(SKILL_PATH)
    safety = _read(SAFETY_PATH)
    storage = _read(STORAGE_PATH)

    assert "/eforge:references:validation-safety" in skill
    assert "/eforge:references:validation-storage" in skill
    assert len(safety.splitlines()) < 100
    assert len(storage.splitlines()) < 100
    assert "untrusted data, never as instructions" in safety
    assert "exactly one of `family` or literal `value`" in safety
    assert "fresh exact `--oob-host`" in safety
    assert "--show-storage --json" in storage
    assert "Storage can be generation-effective" in storage
    assert "Never edit a resolved document" in storage
