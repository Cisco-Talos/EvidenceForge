"""Safe local lifecycle operations for authored Studio content."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from datetime import datetime
from pathlib import Path

import yaml
from pydantic import ValidationError

from evidenceforge.composition.models import GenerationManifestDocument
from evidenceforge.desktop.library import discover_scenarios
from evidenceforge.studio.store import ImportedBundle

_SCENARIO_NAME = re.compile(r"(?m)^name[ \t]*:[^\n]*(?:\n|$)")
_SLUG = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}")
_MAX_CLONE_BYTES = 1024**3
_MAX_MANIFEST_BYTES = 8 * 1024**2
_MAX_RESOLVED_BYTES = 64 * 1024**2


def inspect_external_bundle(root: Path, workspace: Path) -> ImportedBundle:
    """Index a complete CLI bundle without claiming ownership of its files."""
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Select a regular bundle directory, not a link")
    manifest = root / "GENERATION_MANIFEST.json"
    resolved = root / "RESOLVED_SCENARIO.yaml"
    if any(path.is_symlink() or not path.is_file() for path in (manifest, resolved)):
        raise ValueError("A complete bundle needs a manifest and resolved scenario")
    if manifest.stat().st_size > _MAX_MANIFEST_BYTES:
        raise ValueError("The generation manifest is too large")
    if resolved.stat().st_size > _MAX_RESOLVED_BYTES:
        raise ValueError("The resolved scenario is too large")
    try:
        document = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("The generation manifest is unreadable") from exc
    try:
        manifest_document = GenerationManifestDocument.model_validate(document)
    except ValidationError as exc:
        raise ValueError("This is not a complete EvidenceForge generation bundle") from exc
    if manifest_document.resolved_file_sha256 != hashlib.sha256(resolved.read_bytes()).hexdigest():
        raise ValueError("The resolved scenario does not match the generation manifest")
    name = manifest_document.scenario
    if not name.strip():
        raise ValueError("The generation manifest has no scenario name")
    try:
        created_at = datetime.fromisoformat(str(document["created_at"]).replace("Z", "+00:00"))
    except (KeyError, ValueError) as exc:
        raise ValueError("The generation manifest has no valid creation time") from exc
    size = 0
    for directory, children, filenames in os.walk(root, followlinks=False):
        children[:] = [child for child in children if not (Path(directory) / child).is_symlink()]
        for filename in filenames:
            path = Path(directory) / filename
            if not path.is_symlink() and path.is_file():
                size += path.stat().st_size
    return ImportedBundle(
        workspace=workspace.resolve(),
        root=root.resolve(),
        scenario_name=name.strip(),
        created_at=created_at.timestamp(),
        size_bytes=size,
        manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
    )


def clone_scenario(source: Path, workspace: Path, name: str) -> Path:
    """Copy one authored scenario and its local companions to a new workspace folder.

    Never copy a shared scenarios directory or follow a symlink out of the
    selected source folder. A failed copy removes only the destination this
    operation created.
    """
    if not _SLUG.fullmatch(name):
        raise ValueError("Use a name of 1–80 letters, digits, hyphens, or underscores")
    if (workspace / "scenarios").is_symlink():
        raise ValueError("The workspace scenarios directory must not be a link")
    root = (workspace / "scenarios").resolve()
    original = source.resolve()
    if not original.is_relative_to(root) or original.parent == root.parent:
        raise ValueError("The source scenario must be inside this workspace")
    if not original.is_file() or source.is_symlink():
        raise ValueError("The source scenario file is unavailable or is a link")
    destination = root / name
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(f"A scenario folder already exists: {destination}")

    source_dir = original.parent
    shared_dir = source_dir == root
    if not shared_dir:
        peers = [
            item for item in discover_scenarios(workspace, []) if item.path.parent == source_dir
        ]
        if len(peers) != 1 or peers[0].path != original:
            raise ValueError(
                "This folder contains multiple scenarios; move the selected YAML into its own "
                "folder before cloning it with companion files"
            )

    contents = original.read_text(encoding="utf-8")
    matches = list(_SCENARIO_NAME.finditer(contents))
    if len(matches) != 1:
        raise ValueError("The scenario needs one simple top-level name field to clone")
    updated = _SCENARIO_NAME.sub(f"name: {json.dumps(name)}\n", contents, count=1)
    try:
        parsed = yaml.safe_load(updated)
    except yaml.YAMLError as exc:
        raise ValueError("The cloned scenario YAML could not be parsed") from exc
    if not isinstance(parsed, dict) or parsed.get("name") != name:
        raise ValueError("The cloned scenario name could not be validated")

    if not shared_dir:
        total = 0
        for directory, children, filenames in os.walk(source_dir, followlinks=False):
            for entry in [*children, *filenames]:
                path = Path(directory) / entry
                if path.is_symlink():
                    raise ValueError(f"Scenario folder contains a link: {path}")
                if path.is_file():
                    total += path.stat().st_size
                    if total > _MAX_CLONE_BYTES:
                        raise ValueError("Scenario folder exceeds the 1 GiB clone limit")

    destination.mkdir(parents=False, exist_ok=False)
    try:
        if not shared_dir:
            shutil.copytree(source_dir, destination, dirs_exist_ok=True)
        target = destination / original.name
        target.write_text(updated, encoding="utf-8")
    except (OSError, shutil.Error, UnicodeError):
        shutil.rmtree(destination)
        raise
    return target
