"""Safe local lifecycle operations for authored Studio content."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from datetime import datetime
from pathlib import Path

import yaml
from pydantic import ValidationError

from evidenceforge.composition.models import GenerationManifestDocument
from evidenceforge.desktop.library import discover_scenarios
from evidenceforge.naming import storage_name, validate_name
from evidenceforge.studio.store import ImportedBundle

_SCENARIO_NAME = re.compile(r"(?m)^name[ \t]*:[^\n]*(?:\n|$)")
_MAX_CLONE_BYTES = 1024**3
_MAX_MANIFEST_BYTES = 8 * 1024**2
_MAX_RESOLVED_BYTES = 64 * 1024**2


def rename_scenario(source: Path, name: str, expected_sha256: str) -> None:
    """Change only the authored name, retaining formatting and the source path.

    Reject stale edits and YAML aliases whose replacement would change other
    authored values. Replace the file atomically so indexing never sees a
    partially written scenario.
    """
    validate_name(name, "scenario")
    if source.is_symlink() or not source.is_file():
        raise ValueError("The authored scenario must be a regular file, not a link")
    if source.stat().st_size > _MAX_MANIFEST_BYTES:
        raise ValueError("This scenario exceeds the 8 MiB name-edit limit")
    contents = source.read_bytes()
    if hashlib.sha256(contents).hexdigest() != expected_sha256:
        raise FileExistsError("The scenario changed. Refresh it before renaming")
    text = contents.decode("utf-8")
    try:
        document = yaml.compose(text)
        original = yaml.safe_load(text)
        if not isinstance(document, yaml.MappingNode) or not isinstance(original, dict):
            raise ValueError("The scenario must be a YAML mapping")
        names = [
            (key, value)
            for key, value in document.value
            if isinstance(key, yaml.ScalarNode) and key.value == "name"
        ]
        if len(names) != 1:
            raise ValueError("The scenario needs exactly one top-level name field")
        key, value = names[0]
        if not isinstance(value, yaml.ScalarNode) or value.start_mark.index < key.end_mark.index:
            raise ValueError("Edit the scenario name directly in YAML to replace its alias")
        replacement = json.dumps(name)
        if value.style in {"|", ">"}:
            replacement += "\r\n" if "\r\n" in text else "\n"
        updated = text[: value.start_mark.index] + replacement + text[value.end_mark.index :]
        parsed = yaml.safe_load(updated)
        if parsed != {**original, "name": name}:
            raise ValueError("Renaming this YAML would change other fields; edit it directly")
    except yaml.YAMLError as exc:
        raise ValueError(
            "The scenario YAML could not be parsed; repair it before renaming"
        ) from exc

    from evidenceforge.artifacts.lifecycle import assert_mutable

    assert_mutable(source)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".eforge-name-", dir=source.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(updated.encode("utf-8"))
            output.flush()
            os.fsync(output.fileno())
        temporary.chmod(source.stat().st_mode & 0o777)
        if (
            source.is_symlink()
            or hashlib.sha256(source.read_bytes()).hexdigest() != expected_sha256
        ):
            raise FileExistsError("The scenario changed. Refresh it before renaming")
        temporary.replace(source)
    finally:
        temporary.unlink(missing_ok=True)


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
    from evidenceforge.artifacts.lifecycle import create_draft
    from evidenceforge.schema import identify_document
    from evidenceforge.utils import load_scenario_source_graph

    contract = identify_document(load_scenario_source_graph(source).data)
    if contract.lifecycle is not None:
        return create_draft(source, project_root=workspace, name=name)
    validate_name(name, "scenario")
    if (workspace / "scenarios").is_symlink():
        raise ValueError("The workspace scenarios directory must not be a link")
    root = (workspace / "scenarios").resolve()
    original = source.resolve()
    if not original.is_relative_to(root) or original.parent == root.parent:
        raise ValueError("The source scenario must be inside this workspace")
    if not original.is_file() or source.is_symlink():
        raise ValueError("The source scenario file is unavailable or is a link")
    destination = root / storage_name(name)
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
