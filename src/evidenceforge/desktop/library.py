"""File-backed catalog for the local desktop workspace."""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict


class LibraryItem(BaseModel):
    """A scenario or pack discovered from an authored YAML file."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    path: Path
    name: str
    description: str = ""
    kind: str = "scenario"
    version: str = ""
    users: int = 0
    systems: int = 0
    events: int = 0


_yaml_cache: dict[tuple[Path, int, int], dict[str, object] | None] = {}


def _read_yaml_file(path: Path, size: int) -> dict[str, object] | None:
    if size > 2_000_000:
        return None
    with path.open(encoding="utf-8") as stream:
        data = yaml.safe_load(stream)
    return data if isinstance(data, dict) else None


def _read_yaml(path: Path) -> dict[str, object] | None:
    stat = path.stat()
    key = (path, stat.st_mtime_ns, stat.st_size)
    if key not in _yaml_cache:
        if len(_yaml_cache) >= 128:
            _yaml_cache.clear()
        _yaml_cache[key] = _read_yaml_file(path, stat.st_size)
    return _yaml_cache[key]


def _count(value: object) -> int:
    return len(value) if isinstance(value, list) else 0


def _scenario_item(path: Path) -> LibraryItem | None:
    try:
        data = _read_yaml(path)
    except (OSError, UnicodeError, yaml.YAMLError):
        return None
    if not data or "name" not in data or "version" not in data or "environment" not in data:
        return None
    environment = data.get("environment")
    environment = environment if isinstance(environment, dict) else {}
    storyline = data.get("storyline")
    if isinstance(storyline, dict):
        events = storyline.get("events")
    else:
        events = storyline
    return LibraryItem(
        path=path.resolve(),
        name=str(data["name"]),
        description=str(data.get("description") or "").strip(),
        version=str(data["version"]),
        users=_count(environment.get("users")),
        systems=_count(environment.get("systems")),
        events=_count(events),
    )


def discover_scenarios(workspace: Path, imported_paths: list[Path]) -> list[LibraryItem]:
    """Find authored scenarios without traversing generated bundles."""
    roots = [workspace / "scenarios"]
    paths: set[Path] = {path.expanduser().resolve() for path in imported_paths}
    for root in roots:
        if not root.is_dir():
            continue
        for directory, children, filenames in os.walk(root):
            children[:] = [
                child
                for child in children
                if child not in {"data", "runs", "blind-test", ".git", ".eforge-generation"}
            ]
            for filename in filenames:
                if filename.endswith((".yaml", ".yml")):
                    paths.add(Path(directory, filename).resolve())
    items = [item for path in sorted(paths) if path.is_file() if (item := _scenario_item(path))]
    return sorted(items, key=lambda item: item.name.casefold())


def discover_packs(workspace: Path, kind: str) -> list[LibraryItem]:
    """Find bundled and workspace industry or organization packs."""
    bundled = Path(__file__).resolve().parents[1] / "config" / "packs"
    roots = [bundled, workspace / ".eforge" / "packs"]
    items: list[LibraryItem] = []
    for root in roots:
        if not root.is_dir():
            continue
        for path in root.rglob("pack.yaml"):
            try:
                data = _read_yaml(path)
            except (OSError, UnicodeError, yaml.YAMLError):
                continue
            if not data or data.get("type") != kind:
                continue
            items.append(
                LibraryItem(
                    path=path.resolve(),
                    name=str(data.get("name", path.parent.name)),
                    description=str(data.get("description") or "").strip(),
                    kind=kind,
                    version=str(data.get("version", "")),
                )
            )
    return sorted(items, key=lambda item: (item.name.casefold(), item.version))
