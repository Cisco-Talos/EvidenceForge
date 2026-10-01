"""File-backed catalog for the local desktop workspace."""

from __future__ import annotations

import os
import shlex
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

from evidenceforge.models.exceptions import ConfigurationError
from evidenceforge.utils import load_scenario_source_graph


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
    modified_at: float = 0.0
    search_text: str = Field(default="", repr=False, exclude=True)
    search_folded: str = Field(default="", repr=False, exclude=True)


_yaml_cache: dict[tuple[Path, int, int], dict[str, object] | None] = {}
_text_cache: dict[tuple[Path, int, int], str] = {}


def _read_yaml_file(path: Path, size: int) -> dict[str, object] | None:
    if size > 16 * 1024**2:
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


def _scenario_text(path: Path) -> tuple[str, float]:
    stat = path.stat()
    key = (path, stat.st_mtime_ns, stat.st_size)
    if key not in _text_cache:
        if len(_text_cache) >= 128:
            _text_cache.clear()
        _text_cache[key] = path.read_text(encoding="utf-8")
    return _text_cache[key], stat.st_mtime


def _scenario_item(path: Path) -> LibraryItem | None:
    try:
        data = _read_yaml(path)
    except (OSError, UnicodeError, yaml.YAMLError):
        return None
    if not data:
        return None
    if "includes" in data or "include" in data:
        try:
            data = load_scenario_source_graph(path).data
        except (ConfigurationError, OSError, ValueError):
            # Keep a repairable root visible; dependency health explains missing inputs.
            pass
    if (
        "name" not in data
        or ("version" not in data and "scenario_version" not in data)
        or not any(key in data for key in ("environment", "composition", "includes", "include"))
    ):
        return None
    try:
        search_text, modified_at = _scenario_text(path)
    except (OSError, UnicodeError):
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
        version=str(data.get("scenario_version", data.get("version", ""))),
        users=_count(environment.get("users")),
        systems=_count(environment.get("systems")),
        events=_count(events),
        modified_at=modified_at,
        search_text=search_text,
        search_folded=search_text.casefold(),
    )


def _search_terms(query: str) -> list[str]:
    try:
        return shlex.split(query.casefold())
    except ValueError:
        return query.casefold().split()


def matches_search(item: LibraryItem, query: str) -> bool:
    """Match every term against title, description, or authored YAML content."""
    terms = _search_terms(query)
    fields = {
        "name": item.name.casefold(),
        "description": item.description.casefold(),
        "yaml": item.search_folded or item.search_text.casefold(),
    }
    for term in terms:
        scope, separator, value = term.partition(":")
        if separator and scope in fields:
            if value not in fields[scope]:
                return False
        elif not any(term in field for field in fields.values()):
            return False
    return True


def search_snippet(item: LibraryItem, query: str) -> str:
    """Return one short, source-labeled excerpt explaining a search match."""
    if not query.strip():
        return ""
    fallback = ""
    for term in _search_terms(query):
        scope, separator, value = term.partition(":")
        wanted = value if separator and scope in {"name", "description", "yaml"} else term
        fields = (
            [
                (
                    scope,
                    {"name": item.name, "description": item.description, "yaml": item.search_text}[
                        scope
                    ],
                )
            ]
            if separator and scope in {"name", "description", "yaml"}
            else [
                ("name", item.name),
                ("description", item.description),
                ("yaml", item.search_text),
            ]
        )
        if not wanted:
            continue
        for field, text in fields:
            if wanted not in text.casefold():
                continue
            if field == "yaml":
                for number, line in enumerate(text.splitlines(), start=1):
                    if wanted in line.casefold():
                        return f"YAML line {number} · {_short_excerpt(line.strip(), wanted)}"
            snippet = f"{field.title()} · {_short_excerpt(text, wanted)}"
            if separator and scope in {"name", "description", "yaml"}:
                return snippet
            if not fallback:
                fallback = snippet
            break
    return fallback


def _short_excerpt(text: str, term: str) -> str:
    normalized = " ".join(text.split())
    if len(normalized) <= 90:
        return normalized
    position = normalized.casefold().find(term)
    start = max(0, position - 28)
    end = min(len(normalized), start + 90)
    prefix = "…" if start else ""
    suffix = "…" if end < len(normalized) else ""
    return f"{prefix}{normalized[start:end]}{suffix}"


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
                if child
                not in {"data", "runs", "blind-test", ".git", ".eforge-generation", ".sources"}
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
                    modified_at=path.stat().st_mtime,
                )
            )
    return sorted(items, key=lambda item: (item.name.casefold(), item.version))
