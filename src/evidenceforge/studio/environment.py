"""Read-only environment inspection through the deterministic CLI contract."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, JsonValue, PrivateAttr, ValidationError

from evidenceforge.composition.models import SelectedPack
from evidenceforge.desktop.jobs import _eforge_command
from evidenceforge.models.exceptions import ConfigurationError
from evidenceforge.studio.contexts import ConfigurationState, configuration_state, context_arguments
from evidenceforge.studio.settings import StudioSettings, controller_settings
from evidenceforge.studio.store import Project


class OverlayFile(BaseModel):
    """One regular overlay file beneath the selected workspace."""

    model_config = ConfigDict(extra="forbid")
    path: str
    size: int = Field(ge=0)


class SourceDeclaration(BaseModel):
    """One input value and its exact captured declaring YAML."""

    model_config = ConfigDict(extra="forbid")
    path: str
    layer: Literal["Scenario", "Organization", "Pack catalog"]
    source: str
    source_key: str | None = None
    source_size: int = Field(default=0, ge=0)
    line: int | None = Field(default=None, ge=1, description="One-based declaring YAML line")
    value: JsonValue = None
    value_found: bool = False


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
    declarations: list[SourceDeclaration] = Field(default_factory=list)
    configuration: ConfigurationState | None = None
    overlay_root: Path
    overlay_files: list[OverlayFile] = Field(default_factory=list)
    overlays_truncated: bool = False
    _declaration_contents: dict[str, str] = PrivateAttr(default_factory=dict)

    def declaration_content(self, key: str) -> str | None:
        """Return only YAML belonging to an inspected declaration."""
        return self._declaration_contents.get(key)


def _value_at_path(document: Any, path: str) -> tuple[bool, Any]:
    """Read list indices and mapping keys, preserving keys that contain dots."""
    if not path:
        return True, document
    if isinstance(document, dict):
        for key, value in document.items():
            name = str(key)
            if path == name:
                return True, value
            if path.startswith(name + "."):
                found, result = _value_at_path(value, path[len(name) + 1 :])
                if found:
                    return found, result
    if isinstance(document, list):
        index, _, remainder = path.partition(".")
        if index.isdecimal() and int(index) < len(document):
            return _value_at_path(document[int(index)], remainder)
    return False, None


def _line_at_path(node: yaml.Node | None, path: str) -> int | None:
    """Locate a declaration structurally, including repeated values and dotted keys."""
    if node is None:
        return None
    if not path:
        return node.start_mark.line + 1
    if isinstance(node, yaml.MappingNode):
        # SafeLoader flattens merge keys; the last occurrence owns an overridden key.
        entries: dict[str, tuple[yaml.ScalarNode, yaml.Node]] = {}
        for key, value in node.value:
            if not isinstance(key, yaml.ScalarNode):
                continue
            name = (
                key.value if key.tag == "tag:yaml.org,2002:str" else str(yaml.safe_load(key.value))
            )
            entries[name] = key, value
        # Match constructed mapping iteration, including ambiguous dotted-key prefixes.
        for name, (key, value) in entries.items():
            if path == name:
                return key.start_mark.line + 1
            if path.startswith(name + "."):
                line = _line_at_path(value, path[len(name) + 1 :])
                if line is not None:
                    return line
    if isinstance(node, yaml.SequenceNode):
        index, _, remainder = path.partition(".")
        if index.isdecimal() and int(index) < len(node.value):
            return _line_at_path(node.value[int(index)], remainder)
    return None


def _declaration_document(content: str) -> tuple[Any, yaml.Node | None]:
    """Retain SafeLoader's source marks alongside the exact constructed input values."""
    loader = yaml.SafeLoader(content)
    try:
        node = loader.get_single_node()
        return (loader.construct_document(node) if node is not None else None), node
    finally:
        loader.dispose()


def _populate_declarations(report: EnvironmentReport, captured: dict[str, str]) -> None:
    """Use captured source bytes rather than guessing effective values after overrides."""
    parsed: dict[str, tuple[Any, yaml.Node | None]] = {}
    groups = (
        ("Scenario", report.field_origins),
        ("Organization", report.organization_model_origins),
        ("Pack catalog", report.catalog_field_origins),
    )
    for layer, origins in groups:
        for path, source in origins.items():
            key = source
            lookup_path = path
            if layer != "Scenario":
                parts = path.split(".", 2)
                owner = (
                    parts[1].split(":", 1)[0]
                    if layer == "Pack catalog" and len(parts) > 1
                    else None
                )
                pack = next(
                    (
                        pack
                        for pack in report.selected_packs
                        if (
                            pack.type == "organization"
                            if layer == "Organization"
                            else f"{pack.publisher}/{pack.name}" == owner
                        )
                    ),
                    None,
                )
                if pack is not None:
                    key = f"packs/{pack.publisher}/{pack.type}/{pack.name}/{pack.version}/{source}"
                if layer == "Pack catalog" and len(parts) > 1:
                    parts[1] = parts[1].split(":", 1)[-1]
                    lookup_path = ".".join(parts)
            content = captured.get(key)
            found, value = False, None
            line = None
            if content is not None:
                if key not in parsed:
                    parsed[key] = _declaration_document(content)
                document, node = parsed[key]
                found, value = _value_at_path(document, lookup_path)
                line = _line_at_path(node, lookup_path) if found else None
                report._declaration_contents[key] = content
            report.declarations.append(
                SourceDeclaration(
                    path=path,
                    layer=layer,
                    source=re.sub(r"^sources/[0-9a-f]{16}-", "", key),
                    source_key=key if content is not None else None,
                    source_size=len(content.encode("utf-8")) if content is not None else 0,
                    line=line,
                    value=json.loads(json.dumps(value, default=str)),
                    value_found=found,
                )
            )


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
    settings: StudioSettings, source: Path, workspace: Path, project: Project | None = None
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
        report.configuration = configuration_state(source, workspace, project)
        completed = subprocess.run(
            [
                *_eforge_command(controller_settings(settings)),
                "resolve",
                str(source),
                *context_arguments(source, workspace),
                "--explain-composition",
                "--include-effective-scenario",
                "--include-declaration-sources",
                "--json",
            ],
            cwd=workspace,
            capture_output=True,
            text=True,
            check=False,
            timeout=180,
        )
        payload = json.loads(completed.stdout)
    except (
        OSError,
        ValueError,
        ConfigurationError,
        subprocess.TimeoutExpired,
        json.JSONDecodeError,
    ) as exc:
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
        inspected = EnvironmentReport.model_validate(
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
        captured = payload.get("declaration_sources", {})
        if not isinstance(captured, dict) or any(
            not isinstance(key, str) or not isinstance(content, str)
            for key, content in captured.items()
        ):
            raise ValueError("The CLI returned invalid declaration sources")
        _populate_declarations(inspected, captured)
        return inspected
    except (ValidationError, ValueError, yaml.YAMLError):
        report.error = (
            "The CLI returned invalid composition details. Refresh after checking eforge."
        )
        return report
