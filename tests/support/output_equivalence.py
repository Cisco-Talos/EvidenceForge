"""Helpers for comparing generated EvidenceForge output bundles."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_IGNORED_NAMES = {
    "generation.log",
    "GROUND_TRUTH.md",
    "scenario.yaml",
}
_INCLUDED_ROOT_NAMES = {
    "GROUND_TRUTH.json",
    "OBSERVATION_MANIFEST.json",
}


@dataclass(frozen=True)
class OutputEquivalenceResult:
    """Comparison result for two generated output bundles."""

    byte_identical: bool
    normalized_multiset_identical: bool
    missing_from_after: tuple[str, ...]
    extra_in_after: tuple[str, ...]
    byte_differences: tuple[str, ...]
    normalized_differences: tuple[str, ...]

    @property
    def same_events(self) -> bool:
        """Return whether the generated event artifacts are equivalent."""
        return (
            not self.missing_from_after
            and not self.extra_in_after
            and self.normalized_multiset_identical
        )


def compare_generated_outputs(before: Path, after: Path) -> OutputEquivalenceResult:
    """Compare two generated output roots for byte and normalized event equivalence."""
    before = before.resolve()
    after = after.resolve()
    before_artifacts = _event_artifacts(before)
    after_artifacts = _event_artifacts(after)

    missing = tuple(sorted(str(path) for path in before_artifacts.keys() - after_artifacts.keys()))
    extra = tuple(sorted(str(path) for path in after_artifacts.keys() - before_artifacts.keys()))
    shared_paths = sorted(before_artifacts.keys() & after_artifacts.keys())

    byte_differences = []
    normalized_differences = []
    for relative_path in shared_paths:
        before_path = before_artifacts[relative_path]
        after_path = after_artifacts[relative_path]
        if before_path.read_bytes() != after_path.read_bytes():
            byte_differences.append(str(relative_path))
        if _normalized_record_multiset(before_path, before) != _normalized_record_multiset(
            after_path, after
        ):
            normalized_differences.append(str(relative_path))

    return OutputEquivalenceResult(
        byte_identical=not missing and not extra and not byte_differences,
        normalized_multiset_identical=not missing and not extra and not normalized_differences,
        missing_from_after=missing,
        extra_in_after=extra,
        byte_differences=tuple(byte_differences),
        normalized_differences=tuple(normalized_differences),
    )


def _event_artifacts(root: Path) -> dict[Path, Path]:
    artifacts: dict[Path, Path] = {}
    data_dir = root / "data"
    if data_dir.exists():
        for path in data_dir.rglob("*"):
            if path.is_file() and path.name not in _IGNORED_NAMES:
                artifacts[path.relative_to(root)] = path
    for name in _INCLUDED_ROOT_NAMES:
        path = root / name
        if path.is_file():
            artifacts[path.relative_to(root)] = path
    return artifacts


def _normalized_record_multiset(path: Path, root: Path) -> Counter[str]:
    if path.suffix == ".json" and path.parent == root:
        return Counter({_normalize_json_artifact(path, root): 1})
    records = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return Counter(_normalize_text_record(record, root) for record in records)


def _normalize_json_artifact(path: Path, root: Path) -> str:
    payload = json.loads(path.read_text(encoding="utf-8"))
    normalized = _normalize_json_value(payload, root)
    return json.dumps(normalized, sort_keys=True, separators=(",", ":"))


def _normalize_json_value(value: Any, root: Path) -> Any:
    if isinstance(value, dict):
        return {key: _normalize_json_value(item, root) for key, item in value.items()}
    if isinstance(value, list):
        return [_normalize_json_value(item, root) for item in value]
    if isinstance(value, str):
        return _normalize_text_record(value, root)
    return value


def _normalize_text_record(record: str, root: Path) -> str:
    return record.replace(str(root), "<OUTPUT_ROOT>")
