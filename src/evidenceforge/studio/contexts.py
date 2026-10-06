"""Portable configuration files for Studio project/scenario assignments."""

from __future__ import annotations

import hashlib
import os
import shlex
import shutil
import tempfile
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

from evidenceforge.config.context import (
    ConfigurationContext,
    OverlayReference,
    SelectedContext,
    select_context,
)
from evidenceforge.models.exceptions import ConfigurationError
from evidenceforge.studio.store import Project


class ContextFile(BaseModel):
    """One safe relative file shown in the configuration viewer."""

    model_config = ConfigDict(extra="forbid")
    path: str
    size: int = Field(ge=0)


class ConfigurationScope(BaseModel):
    """One explicitly selected or available editable overlay scope."""

    model_config = ConfigDict(extra="forbid")
    id: str
    name: str
    root: Path
    enabled: bool
    files: list[ContextFile] = Field(default_factory=list)
    truncated: bool = False


class ConfigurationState(BaseModel):
    """Current portable selection and its reproducible CLI invocation."""

    model_config = ConfigDict(extra="forbid")
    context_path: Path | None = None
    cli_command: str
    scopes: list[ConfigurationScope]


class CapturedOverlay(BaseModel):
    """Bounded source bytes for a reviewed, independently copied overlay."""

    model_config = ConfigDict(extra="forbid")
    name: str
    root: Path
    files: dict[str, bytes]


def capture_overlays(selection: SelectedContext) -> list[CapturedOverlay]:
    """Capture base and ordered layers without following links or copying engine policy."""
    roots = [
        OverlayReference(name="Source workspace", path=selection.project_root / ".eforge/config"),
        *selection.overlays,
    ]
    captured: list[CapturedOverlay] = []
    total = 0
    for index, reference in enumerate(roots):
        if not reference.path.exists() and index == 0:
            continue
        if any(part.is_symlink() for part in (reference.path, *reference.path.parents)):
            raise ValueError("Configuration cannot contain symbolic links")
        files: dict[str, bytes] = {}
        for path in sorted(reference.path.rglob("*")):
            if path.is_symlink():
                raise ValueError("Configuration cannot contain symbolic links")
            if not path.is_file() or path.suffix != ".yaml":
                continue
            total += path.stat().st_size
            if total > 64 * 1024**2 or len(files) >= 500:
                raise ValueError(
                    "Configuration exceeds the 64 MiB or 500 files per layer copy limit"
                )
            files[path.relative_to(reference.path).as_posix()] = path.read_bytes()
        captured.append(CapturedOverlay(name=reference.name, root=reference.path, files=files))
    return captured


def export_configuration(source: Path, workspace: Path) -> dict[str, bytes]:
    """Create a portable authored/ selection; resolved run inputs remain authoritative."""
    selection = select_context(workspace, context_path(source, workspace))
    captured = capture_overlays(selection)
    if not captured and selection.path is None:
        return {}
    files: dict[str, bytes] = {}
    layers: list[OverlayReference] = []
    base = workspace / ".eforge/config"
    for index, layer in enumerate(captured):
        if layer.root == base:
            relative = Path(".eforge/config")
        else:
            relative = Path("configuration/layers") / str(index)
            layers.append(OverlayReference(name=layer.name, path=Path("layers") / str(index)))
        files[relative.as_posix() + "/"] = b""
        files.update(
            {(relative / path).as_posix(): content for path, content in layer.files.items()}
        )
    document = ConfigurationContext(project_root=Path(".."), overlays=layers)
    files["configuration/context.yaml"] = yaml.safe_dump(
        document.model_dump(mode="json"), sort_keys=False
    ).encode()
    return files


def _source_key(source: Path, workspace: Path) -> str:
    resolved = source.resolve()
    identity = (
        resolved.relative_to(workspace.resolve())
        if resolved.is_relative_to(workspace.resolve())
        else resolved
    )
    return hashlib.sha256(os.fsencode(identity)).hexdigest()[:24]


def scenario_context_path(source: Path, workspace: Path) -> Path:
    """Locate Studio's explicit file for this source; the CLI never discovers it implicitly."""
    return workspace / ".eforge" / "contexts" / f"{_source_key(source, workspace)}.yaml"


def scenario_overlay_root(source: Path, workspace: Path) -> Path:
    """Keep scenario-scoped config independent of shared scenario source directories."""
    return workspace / ".eforge" / "scenarios" / _source_key(source, workspace) / "config"


def project_overlay_root(project: Project) -> Path:
    """Use a stable project identity so a display rename cannot redirect configuration."""
    return project.workspace / ".eforge" / "projects" / project.id / "config"


def context_arguments(source: Path, workspace: Path) -> list[str]:
    """Return exactly the public CLI selection used by every Studio operation."""
    path = scenario_context_path(source, workspace)
    if path.exists() or path.is_symlink():
        return ["--context", str(path)]
    return ["--project-root", str(workspace)]


def context_path(source: Path, workspace: Path) -> Path | None:
    """Return an explicitly bound file, including a broken link so it cannot silently fallback."""
    arguments = context_arguments(source, workspace)
    return Path(arguments[1]) if arguments[0] == "--context" else None


def safe_scope_files(root: Path) -> tuple[list[ContextFile], bool]:
    """List bounded YAML without following any directory or file links."""
    if any(part.is_symlink() for part in (root, *root.parents)):
        raise ValueError("Configuration paths must not be symbolic links")
    files: list[ContextFile] = []
    if root.is_dir():
        for path in sorted(root.rglob("*.yaml")):
            if any(part.is_symlink() for part in (path, *path.parents)) or not path.is_file():
                continue
            if len(files) == 500:
                return files, True
            files.append(
                ContextFile(path=path.relative_to(root).as_posix(), size=path.stat().st_size)
            )
    return files, False


def configuration_state(
    source: Path, workspace: Path, project: Project | None = None
) -> ConfigurationState:
    """Read file-owned selection; SQLite supplies only the available project display identity."""
    selected_path = context_path(source, workspace)
    selection = select_context(workspace, selected_path)
    selected = {layer.path for layer in selection.overlays}
    scopes = [
        ConfigurationScope(
            id="workspace", name="Workspace", root=workspace / ".eforge/config", enabled=True
        )
    ]
    if project is not None:
        root = project_overlay_root(project)
        scopes.append(
            ConfigurationScope(
                id="project", name=f"Project · {project.name}", root=root, enabled=root in selected
            )
        )
    own = scenario_overlay_root(source, workspace)
    scopes.append(
        ConfigurationScope(id="scenario", name="Scenario", root=own, enabled=own in selected)
    )
    known = {scope.root for scope in scopes}
    for index, layer in enumerate(selection.overlays):
        if layer.path not in known:
            scopes.append(
                ConfigurationScope(
                    id=f"extra-{index}", name=layer.name, root=layer.path, enabled=True
                )
            )
    # Show active layers in their actual application order, followed by available
    # disabled scopes. In particular, imported layers precede private scenario config.
    by_root = {scope.root: scope for scope in scopes[1:]}
    scopes = [
        scopes[0],
        *(by_root[layer.path] for layer in selection.overlays),
        *(scope for scope in scopes[1:] if not scope.enabled),
    ]
    for scope in scopes:
        if not scope.root.resolve().is_relative_to(workspace.resolve()):
            raise ValueError(
                "Studio configuration viewers require paths inside the active workspace"
            )
        scope.files, scope.truncated = safe_scope_files(scope.root)
    command = shlex.join(["eforge", "generate", str(source), *context_arguments(source, workspace)])
    return ConfigurationState(context_path=selected_path, cli_command=command, scopes=scopes)


def _atomic_write(path: Path, text: str) -> None:
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("Configuration paths must not be symbolic links")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=".context-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def configure_scenario(
    source: Path, workspace: Path, project: Project | None, *, scenario_enabled: bool | None = None
) -> Path | None:
    """Save the selected layers as ordinary, independently usable context YAML."""
    target = scenario_context_path(source, workspace)
    previous = select_context(workspace, context_path(source, workspace))
    own = scenario_overlay_root(source, workspace)
    enabled = (
        (own in {layer.path for layer in previous.overlays})
        if scenario_enabled is None
        else scenario_enabled
    )
    retained = [
        layer
        for layer in previous.overlays
        if layer.path != own and not layer.path.is_relative_to(workspace / ".eforge/projects")
    ]
    layers: list[OverlayReference] = []
    if project is not None and project.overlay_enabled:
        root = project_overlay_root(project)
        if any(part.is_symlink() for part in (root, *root.parents)):
            raise ValueError("Project configuration cannot be a symbolic link")
        root.mkdir(parents=True, exist_ok=True)
        layers.append(OverlayReference(name=f"Project: {project.name}"[:80], path=root))
    layers.extend(retained)
    if enabled:
        if any(part.is_symlink() for part in (own, *own.parents)):
            raise ValueError("Scenario configuration cannot be a symbolic link")
        own.mkdir(parents=True, exist_ok=True)
        layers.append(OverlayReference(name="Scenario", path=own))
    if not layers:
        if target.is_symlink():
            raise ValueError("Context file cannot be a symbolic link")
        target.unlink(missing_ok=True)
        return None
    document = ConfigurationContext(
        project_root=Path(os.path.relpath(workspace, target.parent)),
        overlays=[
            layer.model_copy(update={"path": Path(os.path.relpath(layer.path, target.parent))})
            for layer in layers
        ],
    )
    _atomic_write(target, yaml.safe_dump(document.model_dump(mode="json"), sort_keys=False))
    return target


def copy_scenario_configuration(
    source: Path, destination: Path, workspace: Path, project: Project | None
) -> None:
    """Clone private scenario patches; project config remains shared through its named selection."""
    original = scenario_overlay_root(source, workspace)
    target = scenario_overlay_root(destination, workspace)
    selected = select_context(workspace, context_path(source, workspace))
    enabled = original in {layer.path for layer in selected.overlays}
    if original.exists() or original.is_symlink():
        safe_scope_files(original)
        if any(path.is_symlink() for path in original.rglob("*")):
            raise ValueError("Scenario configuration cannot contain symbolic links")
        shutil.copytree(original, target)
    # Keep explicit manual layers in addition to the private clone and shared project layer.
    other = [
        layer
        for layer in selected.overlays
        if layer.path != original and not layer.path.is_relative_to(workspace / ".eforge/projects")
    ]
    if other:
        path = scenario_context_path(destination, workspace)
        document = ConfigurationContext(project_root=workspace, overlays=other)
        _atomic_write(path, yaml.safe_dump(document.model_dump(mode="json"), sort_keys=False))
    configure_scenario(destination, workspace, project, scenario_enabled=enabled)


def configure_project_scenarios(
    sources: list[Path], workspace: Path, project: Project | None
) -> None:
    """Update selections together, restoring their previous bytes if any write fails."""
    paths = [scenario_context_path(source, workspace) for source in sources]
    if any(any(part.is_symlink() for part in (path, *path.parents)) for path in paths):
        raise ValueError("Configuration context paths cannot be symbolic links")
    backups = {
        scenario_context_path(source, workspace): scenario_context_path(
            source, workspace
        ).read_bytes()
        if scenario_context_path(source, workspace).is_file()
        else None
        for source in sources
    }
    try:
        for source in sources:
            configure_scenario(source, workspace, project)
    except (OSError, ValueError, ConfigurationError):
        for path, content in backups.items():
            if content is None:
                path.unlink(missing_ok=True)
            else:
                _atomic_write(path, content.decode("utf-8"))
        raise
