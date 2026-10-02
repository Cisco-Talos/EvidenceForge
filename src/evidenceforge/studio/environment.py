"""Read-only environment inspection through the deterministic CLI contract."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from evidenceforge.composition.models import SelectedPack
from evidenceforge.desktop.jobs import _eforge_command
from evidenceforge.studio.settings import StudioSettings, controller_settings


class OverlayFile(BaseModel):
    """One regular overlay file beneath the selected workspace."""

    model_config = ConfigDict(extra="forbid")
    path: str
    size: int = Field(ge=0)


class EnvironmentReport(BaseModel):
    """Effective scenario and source declarations reported by eforge resolve."""

    model_config = ConfigDict(extra="forbid")
    source_sha256: str
    project_root: Path
    valid: bool = False
    error: str = ""
    compiled_sha256: str | None = None
    authored_kind: str = ""
    selected_packs: list[SelectedPack] = Field(default_factory=list)
    effective_scenario: dict[str, Any] = Field(default_factory=dict)
    field_origins: dict[str, str] = Field(default_factory=dict)
    organization_model_origins: dict[str, str] = Field(default_factory=dict)
    catalog_origins: dict[str, str] = Field(default_factory=dict)
    catalog_field_origins: dict[str, str] = Field(default_factory=dict)
    merge_decisions: list[dict[str, str]] = Field(default_factory=list)
    overlay_root: Path
    overlay_files: list[OverlayFile] = Field(default_factory=list)
    overlays_truncated: bool = False


def overlay_files(workspace: Path) -> tuple[Path, list[OverlayFile], bool]:
    """List bounded overlay files without following directory or file links."""
    root = workspace / ".eforge" / "config"
    if any(part.is_symlink() for part in (root, *root.parents)):
        raise ValueError("Workspace overlays must not be symbolic links")
    files: list[OverlayFile] = []
    if root.is_dir():
        for path in sorted(root.rglob("*")):
            if path.suffix.lower() not in {".yaml", ".yml"} or not path.is_file():
                continue
            if any(part.is_symlink() for part in (path, *path.parents)):
                continue
            if len(files) == 500:
                return root, files, True
            files.append(
                OverlayFile(path=path.relative_to(root).as_posix(), size=path.stat().st_size)
            )
    return root, files, False


def overlay_fingerprint(workspace: Path) -> str:
    """Hash overlay names and bytes with bounded memory, including files beyond the UI list."""
    root = workspace / ".eforge" / "config"
    if any(part.is_symlink() for part in (root, *root.parents)):
        raise ValueError("Workspace overlays must not be symbolic links")
    entries: list[tuple[str, str]] = []
    if root.is_dir():
        for path in sorted(root.rglob("*")):
            if path.suffix.lower() not in {".yaml", ".yml"} or not path.is_file():
                continue
            if any(part.is_symlink() for part in (path, *path.parents)):
                raise ValueError("Workspace overlays must not be symbolic links")
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                while chunk := stream.read(65536):
                    digest.update(chunk)
            entries.append((path.relative_to(root).as_posix(), digest.hexdigest()))
    return hashlib.sha256(json.dumps(entries).encode()).hexdigest()


def inspect_environment(
    settings: StudioSettings, source: Path, workspace: Path
) -> EnvironmentReport:
    """Resolve in a fresh process so pack and overlay edits cannot leave cached values."""
    root, files, truncated = overlay_files(workspace)
    if source.is_symlink() or not source.is_file() or source.stat().st_size > 8 * 1024**2:
        raise ValueError("Choose a regular scenario YAML file smaller than 8 MiB")
    report = EnvironmentReport(
        source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        project_root=workspace,
        overlay_root=root,
        overlay_files=files,
        overlays_truncated=truncated,
    )
    try:
        completed = subprocess.run(
            [
                *_eforge_command(controller_settings(settings)),
                "resolve",
                str(source),
                "--project-root",
                str(workspace),
                "--explain-composition",
                "--include-effective-scenario",
                "--json",
            ],
            cwd=workspace,
            capture_output=True,
            text=True,
            check=False,
            timeout=180,
        )
        payload = json.loads(completed.stdout)
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        report.error = f"Environment inspection could not finish: {exc}"
        return report
    if not isinstance(payload, dict) or completed.returncode or payload.get("valid") is not True:
        report.error = (
            str(payload.get("error", "Composition could not be resolved"))
            if isinstance(payload, dict)
            else "The CLI returned an invalid composition report"
        )
        return report
    composition = payload.get("composition", {})
    if not isinstance(composition, dict):
        report.error = (
            "The CLI returned invalid composition details. Refresh after checking eforge."
        )
        return report
    try:
        return EnvironmentReport.model_validate(
            {
                **report.model_dump(),
                "valid": True,
                "compiled_sha256": payload.get("compiled_sha256"),
                "authored_kind": composition.get("authored_kind", ""),
                "selected_packs": payload.get("selected_packs", []),
                "effective_scenario": payload.get("effective_scenario", {}),
                **{
                    name: composition.get(name, {} if name != "merge_decisions" else [])
                    for name in (
                        "field_origins",
                        "organization_model_origins",
                        "catalog_origins",
                        "catalog_field_origins",
                        "merge_decisions",
                    )
                },
            }
        )
    except ValidationError:
        report.error = (
            "The CLI returned invalid composition details. Refresh after checking eforge."
        )
        return report
