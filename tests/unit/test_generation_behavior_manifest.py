"""Contracts for behavior-aware checkpoint compatibility metadata."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError
from scripts.check_generation_behavior import require_revision_for_surface_change

from evidenceforge.generation.checkpoints import behavior
from evidenceforge.generation.checkpoints.behavior import (
    GenerationBehaviorManifest,
    behavior_fingerprint_components,
    classify_behavior_change,
    generation_behavior_surface_digest,
    load_generation_behavior_manifest,
)


def _manifest(*impacts: str) -> GenerationBehaviorManifest:
    return GenerationBehaviorManifest.model_validate(
        {
            "schema_version": "1.0",
            "current_revision": len(impacts),
            "history_start_revision": 1,
            "behavior_surface_sha256": "a" * 64,
            "changes": [
                {
                    "revision": index,
                    "id": f"change-{index}",
                    "impact": impact,
                    "domains": [f"domain-{index}"],
                    "formats": [f"format-{index}"],
                    "summary": f"Change {index}",
                }
                for index, impact in enumerate(impacts, start=1)
            ],
        }
    )


def test_packaged_behavior_manifest_matches_generation_surface() -> None:
    manifest = load_generation_behavior_manifest()

    assert manifest.behavior_surface_sha256 == generation_behavior_surface_digest()


def test_different_build_at_same_valid_revision_has_no_declared_change() -> None:
    result = classify_behavior_change(
        same_build=False,
        stored_components=behavior_fingerprint_components(),
    )

    assert result.change == "none-declared"


def test_same_revision_with_conflicting_surface_is_unknown() -> None:
    stored = behavior_fingerprint_components()
    stored["behavior_surface_sha256"] = "f" * 64

    result = classify_behavior_change(same_build=False, stored_components=stored)

    assert result.change == "unknown"


@pytest.mark.parametrize(
    "changes",
    (
        [],
        [
            {
                "revision": 2,
                "id": "gap",
                "impact": "none",
                "summary": "gap",
            }
        ],
        [
            {
                "revision": 1,
                "id": "duplicate",
                "impact": "none",
                "summary": "one",
            },
            {
                "revision": 2,
                "id": "duplicate",
                "impact": "localized",
                "summary": "two",
            },
        ],
    ),
)
def test_behavior_manifest_rejects_missing_gap_or_duplicate_ids(
    changes: list[dict[str, object]],
) -> None:
    with pytest.raises(ValidationError):
        GenerationBehaviorManifest.model_validate(
            {
                "schema_version": "1.0",
                "current_revision": 2,
                "history_start_revision": 1,
                "behavior_surface_sha256": "a" * 64,
                "changes": changes,
            }
        )


def test_behavior_manifest_allows_multiple_unique_changes_in_one_revision() -> None:
    manifest = GenerationBehaviorManifest.model_validate(
        {
            "schema_version": "1.0",
            "current_revision": 1,
            "history_start_revision": 1,
            "behavior_surface_sha256": "a" * 64,
            "changes": [
                {
                    "revision": 1,
                    "id": "first-domain",
                    "impact": "localized",
                    "summary": "First domain",
                },
                {
                    "revision": 1,
                    "id": "second-domain",
                    "impact": "none",
                    "summary": "Second domain",
                },
            ],
        }
    )

    assert len(manifest.changes) == 2


@pytest.mark.parametrize(
    ("impacts", "expected"),
    (
        (("none", "none"), "localized"),
        (("none", "localized"), "localized"),
        (("localized", "material"), "material"),
    ),
)
def test_behavior_change_aggregates_highest_intervening_severity(
    monkeypatch: pytest.MonkeyPatch,
    impacts: tuple[str, ...],
    expected: str,
) -> None:
    manifest = _manifest(*impacts)
    monkeypatch.setattr(behavior, "load_generation_behavior_manifest", lambda: manifest)

    result = classify_behavior_change(
        same_build=False,
        stored_components={
            "behavior_manifest_schema": "1.0",
            "behavior_revision": 1,
            "behavior_history_start_revision": 1,
            "behavior_history_sha256": behavior._history_digest(
                tuple(change for change in manifest.changes if change.revision <= 1)
            ),
            "behavior_surface_sha256": "c" * 64,
        },
    )

    assert result.change == expected
    assert result.change_ids == tuple(
        f"change-{revision}" for revision in range(2, len(impacts) + 1)
    )
    assert result.domains == tuple(f"domain-{revision}" for revision in range(2, len(impacts) + 1))
    assert result.summaries == tuple(
        f"Change {revision}" for revision in range(2, len(impacts) + 1)
    )


def test_behavior_change_rejects_conflicting_retained_history(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        behavior,
        "load_generation_behavior_manifest",
        lambda: _manifest("none", "localized"),
    )

    result = classify_behavior_change(
        same_build=False,
        stored_components={
            "behavior_manifest_schema": "1.0",
            "behavior_revision": 1,
            "behavior_history_start_revision": 1,
            "behavior_history_sha256": "b" * 64,
            "behavior_surface_sha256": "c" * 64,
        },
    )

    assert result.change == "unknown"
    assert result.reason == "checkpoint behavior history does not match the retained lineage"


@pytest.mark.parametrize(
    "stored",
    (
        {},
        {"behavior_manifest_schema": "1.0", "behavior_revision": 9},
        {
            "behavior_manifest_schema": "1.0",
            "behavior_revision": 1,
            "behavior_history_start_revision": 0,
        },
    ),
)
def test_behavior_change_is_unknown_for_legacy_downgrade_or_missing_history(
    monkeypatch: pytest.MonkeyPatch,
    stored: dict[str, object],
) -> None:
    monkeypatch.setattr(
        behavior,
        "load_generation_behavior_manifest",
        lambda: _manifest("none", "localized"),
    )

    components = {
        "behavior_history_sha256": "b" * 64,
        "behavior_surface_sha256": "c" * 64,
        **stored,
    }

    assert classify_behavior_change(same_build=False, stored_components=components).change == (
        "unknown"
    )


def test_behavior_surface_digest_changes_when_covered_file_changes(tmp_path: Path) -> None:
    package = tmp_path / "evidenceforge"
    generation = package / "generation"
    generation.mkdir(parents=True)
    source = generation / "generator.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    original = generation_behavior_surface_digest(package)

    source.write_text("VALUE = 2\n", encoding="utf-8")

    assert generation_behavior_surface_digest(package) != original


@pytest.mark.parametrize(
    "utility",
    ("ids.py", "rng.py", "time.py", "timing.py", "ua_template.py", "windows_ids.py"),
)
def test_behavior_surface_covers_deterministic_output_utilities(
    tmp_path: Path,
    utility: str,
) -> None:
    package = tmp_path / "evidenceforge"
    utilities = package / "utils"
    utilities.mkdir(parents=True)
    source = utilities / utility
    source.write_text("VALUE = 1\n", encoding="utf-8")
    original = generation_behavior_surface_digest(package)

    source.write_text("VALUE = 2\n", encoding="utf-8")

    assert generation_behavior_surface_digest(package) != original


def test_checkpoint_control_markers_are_excluded_from_behavior_surface(tmp_path: Path) -> None:
    package = tmp_path / "evidenceforge"
    generation = package / "generation"
    generation.mkdir(parents=True)
    source = generation / "generator.py"
    source.write_text(
        "VALUE = 1\n"
        "# behavior-surface: checkpoint-control-start\n"
        "CONTROL = 1\n"
        "# behavior-surface: checkpoint-control-end\n",
        encoding="utf-8",
    )
    original = generation_behavior_surface_digest(package)

    source.write_text(
        "VALUE = 1\n"
        "# behavior-surface: checkpoint-control-start\n"
        "CONTROL = 2\n"
        "# behavior-surface: checkpoint-control-end\n",
        encoding="utf-8",
    )

    assert generation_behavior_surface_digest(package) == original


def test_ci_requires_new_revision_when_behavior_surface_changes() -> None:
    with pytest.raises(SystemExit, match="without a new manifest revision"):
        require_revision_for_surface_change(
            prior_revision=7,
            prior_digest="a" * 64,
            current_revision=7,
            current_digest="b" * 64,
        )

    require_revision_for_surface_change(
        prior_revision=7,
        prior_digest="a" * 64,
        current_revision=8,
        current_digest="b" * 64,
    )
