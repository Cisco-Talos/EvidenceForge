"""High-level generated-data inspection without reading log records or a Studio index."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

from evidenceforge.artifacts.lifecycle import ArtifactError
from evidenceforge.composition.models import GenerationManifestDocument
from evidenceforge.evaluation.parsers import discover_log_files


class BundleProperties(BaseModel):
    """Captured run provenance and aggregate data inventory, never a host inventory."""

    path: Path
    size_bytes: int
    data_bytes: int
    data_files: int
    complete: bool
    scenario: str | None = None
    created_at: str | None = None
    evidenceforge_version: str | None = None
    generation_seed: int | None = None
    output_target: str | None = None
    formats: list[str] = Field(default_factory=list, description="Captured output selections.")
    log_types: list[str] = Field(
        default_factory=list,
        description="Concrete types recognized from generated-data filenames, without reading records.",
    )
    unrecognized_data_files: int = Field(default=0, ge=0)
    selected_packs: list[dict[str, Any]] = Field(default_factory=list)
    artifact: dict[str, Any] = Field(default_factory=dict)
    overrides: dict[str, Any] = Field(default_factory=dict)
    compiled_sha256: str | None = None
    resolved_file_sha256: str | None = None
    findings: list[str] = Field(default_factory=list)
    model_config = ConfigDict(extra="forbid")


def inspect_bundle_properties(root: Path) -> BundleProperties:
    """Inspect file types and sizes; retain manifest selections separately from present types."""
    if root.is_symlink() or not root.is_dir():
        raise ArtifactError("bundle directory is unavailable")
    result = BundleProperties(path=root, size_bytes=0, data_bytes=0, data_files=0, complete=False)
    counted_data_paths: set[Path] = set()
    for directory, children, names in os.walk(root, followlinks=False):
        children[:] = [name for name in children if not (Path(directory) / name).is_symlink()]
        for name in names:
            path = Path(directory) / name
            if path.is_symlink() or not path.is_file():
                continue
            size = path.stat().st_size
            result.size_bytes += size
            if path.relative_to(root).parts[0] == "data":
                result.data_bytes += size
                result.data_files += 1
                counted_data_paths.add(path)
    data_root = root / "data"
    if data_root.is_dir() and not data_root.is_symlink():
        discovered = discover_log_files(data_root)
        # Discovery also includes out-of-data artifacts used by evaluation. This view only
        # describes the regular log files whose sizes were counted above.
        recognized: set[Path] = set()
        for log_type, paths in discovered.items():
            data_paths = counted_data_paths.intersection(paths)
            if data_paths:
                result.log_types.append(log_type)
                recognized.update(data_paths)
        result.unrecognized_data_files = result.data_files - len(recognized)
    manifest_path = root / "GENERATION_MANIFEST.json"
    if manifest_path.is_file() and not manifest_path.is_symlink():
        if manifest_path.stat().st_size > 8 * 1024**2:
            raise ArtifactError("generation manifest exceeds the inspection limit")
        manifest = GenerationManifestDocument.model_validate_json(manifest_path.read_bytes())
        result.complete = True
        for field in (
            "scenario",
            "created_at",
            "evidenceforge_version",
            "generation_seed",
            "output_target",
            "formats",
            "overrides",
            "compiled_sha256",
            "resolved_file_sha256",
        ):
            setattr(result, field, getattr(manifest, field))
        result.selected_packs = [pack.model_dump(mode="json") for pack in manifest.selected_packs]
        resolved = root / "RESOLVED_SCENARIO.yaml"
        if (
            resolved.is_file()
            and not resolved.is_symlink()
            and resolved.stat().st_size <= 64 * 1024**2
        ):
            content = resolved.read_bytes()
            if hashlib.sha256(content).hexdigest() != manifest.resolved_file_sha256:
                result.findings.append(
                    "Captured scenario has changed; its authored identity cannot be verified."
                )
                return result
            try:
                data = yaml.safe_load(content)
            except yaml.YAMLError as exc:
                raise ArtifactError("captured scenario YAML is malformed") from exc
            if isinstance(data, dict) and isinstance(data.get("provenance"), dict):
                artifact = data["provenance"].get("artifact")
                if isinstance(artifact, dict):
                    result.artifact = artifact
    else:
        result.findings.append(
            "No completion manifest is available; data size is the current partial output."
        )
    return result
