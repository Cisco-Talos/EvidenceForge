"""Bounded display identity from immutable generation inputs, without reading log data."""

from __future__ import annotations

import hashlib
import logging
from functools import lru_cache
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict

from evidenceforge.composition.models import GenerationManifestDocument

logger = logging.getLogger(__name__)


class CapturedScenario(BaseModel):
    """The authored identity captured by one run, independent of later catalog changes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    display_name: str | None = None
    publisher: str | None = None
    version: str | None = None
    draft_id: str | None = None
    status: Literal["draft", "published", "legacy", "unknown"] = "unknown"


def _stamp(path: Path, limit: int) -> tuple[int, int, int, int]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Captured source is not a regular file")
    info = path.stat()
    if info.st_size > limit:
        raise ValueError("Captured source exceeds the inspection limit")
    return info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_ino


@lru_cache(maxsize=256)
def _read_source(
    path: Path, expected: str, stamp: tuple[int, int, int, int]
) -> CapturedScenario | None:
    try:
        content = path.read_bytes()
        if len(content) > 64 * 1024**2 or hashlib.sha256(content).hexdigest() != expected:
            return None
        document = yaml.safe_load(content)
        if not isinstance(document, dict) or not isinstance(document.get("scenario"), dict):
            return None
        scenario = document["scenario"]
        provenance = document.get("provenance", {})
        artifact = provenance.get("artifact") if isinstance(provenance, dict) else None
        if isinstance(artifact, dict) and artifact.get("kind") == "scenario":
            return CapturedScenario(
                name=artifact["name"],
                display_name=artifact.get("display_name"),
                publisher=artifact.get("publisher"),
                version=artifact.get("version"),
                draft_id=artifact.get("draft_id"),
                status=artifact.get("status", "unknown"),
            )
        return CapturedScenario(name=scenario["name"], status="legacy")
    except (OSError, ValueError, KeyError, yaml.YAMLError) as error:
        logger.debug("Cannot inspect captured source (%s)", type(error).__name__)
        return None


@lru_cache(maxsize=256)
def _read_manifest(
    path: Path, expected: str | None, stamp: tuple[int, int, int, int]
) -> GenerationManifestDocument | None:
    try:
        content = path.read_bytes()
        if len(content) > 8 * 1024**2:
            return None
        if expected and hashlib.sha256(content).hexdigest() != expected:
            return None
        return GenerationManifestDocument.model_validate_json(content)
    except (OSError, ValueError) as error:
        logger.debug("Cannot inspect captured manifest (%s)", type(error).__name__)
        return None


def captured_scenario(
    root: Path,
    snapshot: Path | None = None,
    snapshot_sha256: str | None = None,
    *,
    manifest_sha256: str | None = None,
) -> CapturedScenario | None:
    """Use a verified queued input or completion manifest; never inspect a mutable source."""
    if snapshot is not None and snapshot_sha256:
        try:
            source = _read_source(snapshot, snapshot_sha256, _stamp(snapshot, 64 * 1024**2))
            if source is not None:
                return source
        except (OSError, ValueError):
            pass
    manifest_path = root / "GENERATION_MANIFEST.json"
    try:
        manifest = _read_manifest(
            manifest_path, manifest_sha256, _stamp(manifest_path, 8 * 1024**2)
        )
        if manifest is None:
            return None
        resolved = root / "RESOLVED_SCENARIO.yaml"
        source = _read_source(
            resolved, manifest.resolved_file_sha256, _stamp(resolved, 64 * 1024**2)
        )
        return source or CapturedScenario(name=manifest.scenario)
    except (OSError, ValueError):
        return None
