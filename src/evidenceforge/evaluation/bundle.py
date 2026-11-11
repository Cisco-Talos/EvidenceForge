"""Streaming authoritative bundle verification for standalone evaluation."""

from __future__ import annotations

import hashlib
import re
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from evidenceforge.composition.artifacts import (
    GENERATION_MANIFEST_FILENAME,
    RESOLVED_SCENARIO_FILENAME,
)
from evidenceforge.composition.models import GenerationManifestDocument
from evidenceforge.composition.sidecars import SIDECAR_REGISTRY
from evidenceforge.evaluation.filesystem import directory_entries
from evidenceforge.evaluation.json_stream import JsonStreamReader
from evidenceforge.evaluation.storage import (
    EvaluationWorkspace,
    bounded_map,
    bounded_sorted,
    evaluation_workspace,
)
from evidenceforge.events.ground_truth import GroundTruthDocument
from evidenceforge.events.ground_truth_occurrence import read_ground_truth_occurrences
from evidenceforge.models.exceptions import EvaluationError, SchemaValidationError
from evidenceforge.utils.host_paths import logical_path


def _manifest(path: Path, files: Any) -> dict[str, Any]:
    header: dict[str, Any] = {}
    seen: set[str] = set()
    with path.open(encoding="utf-8") as stream:
        reader = JsonStreamReader(stream)
        reader.expect("{")
        if reader.peek() != "}":
            while True:
                key = reader.value()
                if not isinstance(key, str) or key in seen:
                    raise ValueError("Manifest keys must be unique strings")
                seen.add(key)
                reader.expect(":")
                if key == "files":
                    for relative, digest in reader.object_items():
                        if (
                            not relative
                            or Path(relative).is_absolute()
                            or ".." in Path(relative).parts
                        ):
                            raise ValueError(f"Manifest contains unsafe file path: {relative!r}")
                        if (
                            not isinstance(digest, str)
                            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                        ):
                            raise ValueError(f"Manifest contains invalid file hash: {relative!r}")
                        files[relative] = digest
                    header[key] = {}
                else:
                    header[key] = reader.value()
                if reader.peek() == "}":
                    break
                reader.expect(",")
        reader.expect("}")
        if reader.peek():
            raise ValueError("Unexpected content after generation manifest")
    return GenerationManifestDocument.model_validate(header).model_dump(mode="json")


def _owned_files(path: Path, directory: bool) -> Iterator[Path]:
    if path.is_symlink():
        raise SchemaValidationError(f"generated bundle contains a symlink: {path}")
    if not path.exists():
        return
    if path.is_file():
        yield path
    elif directory:
        for child in directory_entries(path):
            yield from _owned_files(child, True)


def verify_evaluation_bundle(
    output_root: Path,
    *,
    memory_budget_bytes: int = 256 * 1024 * 1024,
    scratch_dir: Path | None = None,
) -> dict[str, Any]:
    """Verify every authoritative byte without retaining the complete file inventory.

    Returns validated run metadata. The ``files`` mapping is consumed during verification and
    returned empty; callers needing an exported inventory should use the composition API.
    """
    manifest_path = output_root / GENERATION_MANIFEST_FILENAME
    resolved = output_root / RESOLVED_SCENARIO_FILENAME
    if not manifest_path.is_file() or not resolved.is_file():
        raise FileNotFoundError("authoritative generation artifacts are not present")
    workspace = EvaluationWorkspace(memory_budget_bytes, scratch_dir)
    try:
        with evaluation_workspace(workspace):
            expected = bounded_map()
            try:
                manifest = _manifest(manifest_path, expected)
            except (ValidationError, ValueError, UnicodeError) as exc:
                raise SchemaValidationError(f"invalid generation manifest: {exc}") from exc
            with resolved.open("rb") as stream:
                actual_resolved_hash = hashlib.file_digest(stream, "sha256").hexdigest()
            if manifest["resolved_file_sha256"] != actual_resolved_hash:
                raise SchemaValidationError(
                    "resolved scenario file hash does not match generation manifest"
                )
            if RESOLVED_SCENARIO_FILENAME not in expected:
                raise SchemaValidationError(
                    "generation manifest does not hash the resolved scenario"
                )
            changed: list[str] = []
            unexpected: list[str] = []
            changed_count = unexpected_count = 0
            for spec in SIDECAR_REGISTRY.specs:
                if spec.relative_path == GENERATION_MANIFEST_FILENAME:
                    continue
                for path in _owned_files(output_root / spec.relative_path, spec.directory):
                    relative = logical_path(path.relative_to(output_root))
                    wanted = expected.pop(relative, None)
                    if wanted is None:
                        unexpected_count += 1
                        if len(unexpected) < 20:
                            unexpected.append(relative)
                    else:
                        with path.open("rb") as stream:
                            actual = hashlib.file_digest(stream, "sha256").hexdigest()
                        if actual != wanted:
                            changed_count += 1
                            if len(changed) < 20:
                                changed.append(relative)
            if expected or changed_count or unexpected_count:
                from itertools import islice

                missing = list(islice(bounded_sorted(expected), 20))
                raise SchemaValidationError(
                    "generation bundle hash verification failed: "
                    f"missing={missing} ({len(expected)} total), changed={sorted(changed)} "
                    f"({changed_count} total), unexpected={sorted(unexpected)} ({unexpected_count} total)"
                )
            ground_truth_path = output_root / "GROUND_TRUTH.json"
            if ground_truth_path.is_file():
                try:
                    document = GroundTruthDocument.model_validate_json(
                        ground_truth_path.read_text(encoding="utf-8")
                    )
                except (ValidationError, ValueError) as exc:
                    raise SchemaValidationError(f"invalid ground truth document: {exc}") from exc
                if document.schema_version >= 4:
                    if document.event_stream is None:
                        raise SchemaValidationError(
                            "schema-v4 ground truth requires its occurrence sidecar"
                        )
                    if document.schema_version == 5 and (
                        document.event_stream.schema_version != 2
                        or document.expectation_contract is None
                    ):
                        raise SchemaValidationError(
                            "schema-v5 ground truth requires its source expectation contract and schema-2 stream"
                        )
                    try:
                        for _ in read_ground_truth_occurrences(output_root, document.event_stream):
                            pass
                    except (OSError, ValueError) as exc:
                        raise SchemaValidationError(
                            f"invalid canonical occurrence sidecar: {exc}"
                        ) from exc
                effects = (
                    document.effect_reconciliation.model_dump(mode="json")
                    if document.effect_reconciliation
                    else None
                )
                if manifest.get("effect_reconciliation") != effects:
                    raise SchemaValidationError(
                        "generation manifest and ground truth effect reconciliation disagree"
                    )
            return manifest
    except sqlite3.Error as exc:
        raise EvaluationError(
            "Evaluation scratch storage failed; check free space and directory access"
        ) from exc
    finally:
        workspace.close()
