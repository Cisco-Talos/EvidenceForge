"""Tests for generated output equivalence helpers."""

import json
from pathlib import Path

from tests.support.output_equivalence import compare_generated_outputs


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_compare_generated_outputs_reports_byte_identical(tmp_path: Path):
    """Matching event artifacts should pass both comparison levels."""
    before = tmp_path / "before"
    after = tmp_path / "after"
    _write(before / "data" / "webapp02" / "web_access.log", "a\nb\n")
    _write(after / "data" / "webapp02" / "web_access.log", "a\nb\n")
    _write(before / "generation.log", "slow before\n")
    _write(after / "generation.log", "fast after\n")

    result = compare_generated_outputs(before, after)

    assert result.byte_identical
    assert result.normalized_multiset_identical
    assert result.same_events


def test_compare_generated_outputs_accepts_reordered_text_records(tmp_path: Path):
    """The required event gate should pass when only line order changes."""
    before = tmp_path / "before"
    after = tmp_path / "after"
    _write(before / "data" / "proxy01" / "proxy_access.log", "a\nb\na\n")
    _write(after / "data" / "proxy01" / "proxy_access.log", "b\na\na\n")

    result = compare_generated_outputs(before, after)

    assert not result.byte_identical
    assert result.normalized_multiset_identical
    assert result.same_events


def test_compare_generated_outputs_normalizes_root_paths_in_json(tmp_path: Path):
    """Machine-readable artifacts should ignore destination-root path differences."""
    before = tmp_path / "before"
    after = tmp_path / "after"
    before_payload = {"events": [{"artifact": str(before / "data" / "x.log")}]}
    after_payload = {"events": [{"artifact": str(after / "data" / "x.log")}]}
    _write(before / "GROUND_TRUTH.json", json.dumps(before_payload))
    _write(after / "GROUND_TRUTH.json", json.dumps(after_payload))

    result = compare_generated_outputs(before, after)

    assert not result.byte_identical
    assert result.normalized_multiset_identical
    assert result.same_events


def test_compare_generated_outputs_reports_changed_event_counts(tmp_path: Path):
    """Duplicate record counts are part of the same-events contract."""
    before = tmp_path / "before"
    after = tmp_path / "after"
    _write(before / "data" / "webapp02" / "web_access.log", "a\na\n")
    _write(after / "data" / "webapp02" / "web_access.log", "a\n")

    result = compare_generated_outputs(before, after)

    assert not result.normalized_multiset_identical
    assert not result.same_events
    assert result.normalized_differences == ("data/webapp02/web_access.log",)
