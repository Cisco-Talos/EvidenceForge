"""Safe local lifecycle operations for authored Studio content."""

from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path

import yaml

from evidenceforge.desktop.library import discover_scenarios

_SCENARIO_NAME = re.compile(r"(?m)^name[ \t]*:[^\n]*(?:\n|$)")
_SLUG = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}")
_MAX_CLONE_BYTES = 1024**3


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
