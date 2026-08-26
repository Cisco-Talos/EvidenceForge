# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Pack repository authoring and inspection commands."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, NoReturn

import typer
from rich.console import Console
from rich.table import Table

from evidenceforge.composition.compiler import resolve_management_project_root
from evidenceforge.composition.models import PackReference, PackType
from evidenceforge.composition.packs import LoadedPack, PackRepository, parse_pack_cli_reference
from evidenceforge.composition.releases import (
    build_efpack,
    hydrate_release,
    import_efpack,
    validate_efpack,
)
from evidenceforge.models.exceptions import PackError

pack_app = typer.Typer(help="Create, inspect, copy, and validate scenario packs.")
console = Console()


def _repository(project_root: Path | None) -> PackRepository:
    """Build the explicitly project-scoped repository for one command."""

    return PackRepository(resolve_management_project_root(project_root))


def _pack_payload(pack: LoadedPack) -> dict[str, Any]:
    """Return stable machine-readable pack metadata."""

    return {
        "source": pack.source,
        "publisher": pack.manifest.publisher,
        "publisher_display_name": pack.manifest.publisher_display_name,
        "type": pack.manifest.type,
        "name": pack.manifest.name,
        "version": pack.manifest.version,
        "description": pack.manifest.description,
        "requires_evidenceforge": pack.manifest.requires_evidenceforge,
        "digest": pack.digest,
        "location": str(pack.root),
        "industry_dependencies": [
            dependency.model_dump(mode="json") for dependency in pack.manifest.industry_dependencies
        ],
        "locked_dependencies": [
            dependency.model_dump(mode="json") for dependency in pack.lock.dependencies
        ],
        "exports": {catalog: sorted(entries) for catalog, entries in pack.catalogs.items()},
        "model_contributions": {
            "environment_fields": sorted(pack.environment),
            "baseline_activity_fields": sorted(pack.baseline_activity),
        },
    }


def _emit_json(payload: dict[str, Any]) -> None:
    """Emit one stable JSON result without Rich formatting."""

    typer.echo(json.dumps(payload, indent=2, sort_keys=True))


def _fail(
    exc: Exception,
    *,
    json_output: bool,
    json_payload: dict[str, Any],
    text_label: str = "Error",
    exit_code: int = 1,
) -> NoReturn:
    """Render a command failure through exactly one text or JSON channel."""

    if json_output:
        _emit_json({**json_payload, "error": str(exc)})
    else:
        console.print(f"[bold red]{text_label}:[/bold red] {exc}", style="red")
    raise typer.Exit(exit_code) from exc


@pack_app.command("list")
def list_packs(
    json_output: bool = typer.Option(False, "--json", help="Emit stable JSON."),
    project_root: Path | None = typer.Option(
        None,
        "--project-root",
        help="Override the current working directory for optional .eforge/config and .eforge/packs.",
    ),
) -> None:
    """List packaged and project-local packs."""

    try:
        packs = _repository(project_root).list()
    except PackError as exc:
        _fail(exc, json_output=json_output, json_payload={"packs": []})
    payload = [_pack_payload(pack) for pack in packs]
    if json_output:
        _emit_json({"packs": payload})
        return
    table = Table("Source", "Type", "Name", "Version", "Digest")
    for pack in payload:
        table.add_row(
            pack["source"],
            pack["type"],
            pack["name"],
            pack["version"],
            pack["digest"][:12],
        )
    console.print(table)


def _resolve_cli_pack(value: str, project_root: Path | None):
    """Parse and resolve a pack CLI reference."""

    reference, pack_type = parse_pack_cli_reference(value)
    if pack_type is None:
        raise PackError("pack type could not be determined")
    return _repository(project_root).resolve(
        reference,
        expected_type=pack_type,
        declaring_file=Path.cwd() / "pack-command.yaml",
    )


@pack_app.command("show")
def show_pack(
    reference: str = typer.Argument(..., help="source:type:name@version or pack path"),
    json_output: bool = typer.Option(False, "--json", help="Emit stable JSON."),
    project_root: Path | None = typer.Option(
        None,
        "--project-root",
        help="Override the current working directory for optional .eforge/config and .eforge/packs.",
    ),
) -> None:
    """Show a pack's manifest, dependencies, exports, and digest."""

    try:
        payload = _pack_payload(_resolve_cli_pack(reference, project_root))
    except (PackError, ValueError) as exc:
        _fail(exc, json_output=json_output, json_payload={"valid": False})
    if json_output:
        _emit_json(payload)
        return
    console.print(f"[bold]{payload['type']}:{payload['name']}@{payload['version']}[/bold]")
    console.print(payload["description"])
    console.print(f"Source: {payload['source']}")
    console.print(f"Requires EvidenceForge: {payload['requires_evidenceforge']}")
    console.print(f"Digest: {payload['digest']}")
    for catalog, names in payload["exports"].items():
        console.print(f"  {catalog}: {', '.join(names) if names else '(empty)'}")
    model = payload["model_contributions"]
    if model["environment_fields"] or model["baseline_activity_fields"]:
        console.print("Organization model:")
        console.print("  environment fields: " + ", ".join(model["environment_fields"]))
        console.print("  baseline activity fields: " + ", ".join(model["baseline_activity_fields"]))


@pack_app.command("validate")
def validate_pack(
    reference: str = typer.Argument(..., help="source:type:name@version or pack path"),
    json_output: bool = typer.Option(False, "--json", help="Emit stable JSON."),
    project_root: Path | None = typer.Option(
        None,
        "--project-root",
        help="Override the current working directory for optional .eforge/config and .eforge/packs.",
    ),
) -> None:
    """Validate pack schema, containment, identity, dependencies, and digest."""

    try:
        repository = _repository(project_root)
        pack = _resolve_cli_pack(reference, project_root)
        dependencies = repository.validate_semantics(pack)
        payload = {
            "valid": True,
            "pack": _pack_payload(pack),
            "dependencies": [
                dependency.selected().model_dump(mode="json") for dependency in dependencies
            ],
        }
    except (PackError, ValueError) as exc:
        _fail(
            exc,
            json_output=json_output,
            json_payload={"valid": False},
            text_label="Invalid pack",
            exit_code=2,
        )
    if json_output:
        _emit_json(payload)
    else:
        console.print(
            f"[green]✓[/green] Valid {pack.manifest.type} pack "
            f"{pack.manifest.name}@{pack.manifest.version}"
        )


@pack_app.command("init")
def init_pack(
    pack_type: PackType = typer.Argument(..., help="industry or organization"),
    name: str = typer.Argument(...),
    version: str = typer.Option(..., "--version"),
    json_output: bool = typer.Option(False, "--json", help="Emit stable JSON."),
    project_root: Path | None = typer.Option(
        None,
        "--project-root",
        help="Override the current working directory for optional .eforge/config and .eforge/packs.",
    ),
) -> None:
    """Create a complete project-local pack skeleton."""

    try:
        repository = _repository(project_root)
        destination = repository.create_skeleton(pack_type, name, version)
        pack = repository.resolve(
            PackReference(source="project", name=name, version=version),
            expected_type=pack_type,
        )
    except (PackError, ValueError) as exc:
        _fail(exc, json_output=json_output, json_payload={"created": False})
    if json_output:
        _emit_json({"created": True, "pack": _pack_payload(pack)})
        return
    console.print(f"[green]✓[/green] Created {destination}")


@pack_app.command("copy")
def copy_pack(
    reference: str = typer.Argument(..., help="source:type:name@version or pack path"),
    name: str = typer.Option(..., "--name"),
    version: str = typer.Option(..., "--version"),
    json_output: bool = typer.Option(False, "--json", help="Emit stable JSON."),
    project_root: Path | None = typer.Option(
        None,
        "--project-root",
        help="Override the current working directory for optional .eforge/config and .eforge/packs.",
    ),
) -> None:
    """Copy a validated pack into the project repository with a new identity."""

    try:
        repository = _repository(project_root)
        source_pack = _resolve_cli_pack(reference, project_root)
        destination = repository.copy(source_pack, name=name, version=version)
        copied_pack = repository.resolve(
            PackReference(source="project", name=name, version=version),
            expected_type=source_pack.manifest.type,
        )
    except (PackError, ValueError) as exc:
        _fail(exc, json_output=json_output, json_payload={"copied": False})
    if json_output:
        _emit_json(
            {
                "copied": True,
                "source_pack": _pack_payload(source_pack),
                "pack": _pack_payload(copied_pack),
            }
        )
        return
    console.print(f"[green]✓[/green] Copied pack to {destination}")


@pack_app.command("build")
def build_pack(
    reference: str = typer.Argument(..., help="source:type:name@version or pack path"),
    output: Path = typer.Option(..., "--output", help="Destination .efpack file."),
    json_output: bool = typer.Option(False, "--json", help="Emit stable JSON."),
    project_root: Path | None = typer.Option(None, "--project-root"),
) -> None:
    """Build a validated root-pack and dependency-closure .efpack archive."""

    try:
        repository = _repository(project_root)
        payload = build_efpack(repository, _resolve_cli_pack(reference, project_root), output)
    except (PackError, ValueError) as exc:
        _fail(exc, json_output=json_output, json_payload={"built": False})
    if json_output:
        _emit_json({"built": True, **payload})
    else:
        console.print(f"[green]✓[/green] Built {payload['path']}")


@pack_app.command("inspect")
def inspect_pack_release(
    archive: Path = typer.Argument(..., help=".efpack archive"),
    json_output: bool = typer.Option(False, "--json", help="Emit stable JSON."),
) -> None:
    """Validate an .efpack without modifying a library."""

    try:
        payload = validate_efpack(archive)
    except PackError as exc:
        _fail(exc, json_output=json_output, json_payload={"valid": False}, exit_code=2)
    result = {"valid": True, "root": payload.root, "members": list(payload.members)}
    if json_output:
        _emit_json(result)
    else:
        console.print(
            f"[green]✓[/green] Valid .efpack for {payload.root['publisher']}/{payload.root['name']}"
        )


@pack_app.command("import")
def import_pack_release(
    archive: Path = typer.Argument(..., help=".efpack archive"),
    scope: str = typer.Option("project", "--scope", help="project or user immutable library"),
    json_output: bool = typer.Option(False, "--json", help="Emit stable JSON."),
    project_root: Path | None = typer.Option(None, "--project-root"),
) -> None:
    """Validate then import an immutable .efpack closure."""

    if scope not in {"project", "user"}:
        _fail(
            PackError("scope must be project or user"),
            json_output=json_output,
            json_payload={"imported": False},
        )
    try:
        payload = import_efpack(
            archive,
            scope=scope,  # type: ignore[arg-type]
            project_root=resolve_management_project_root(project_root),
        )
    except (PackError, ValueError) as exc:
        _fail(exc, json_output=json_output, json_payload={"imported": False})
    if json_output:
        _emit_json({"imported": True, **payload})
    else:
        console.print(
            f"[green]✓[/green] Imported {len(payload['members'])} release(s) into {scope}"
        )


@pack_app.command("hydrate")
def hydrate_pack_release(
    release: str = typer.Argument(..., help="publisher:type:name@version from the user library"),
    json_output: bool = typer.Option(False, "--json", help="Emit stable JSON."),
    project_root: Path | None = typer.Option(None, "--project-root"),
) -> None:
    """Explicitly materialize a user-library release for one project."""

    try:
        payload = hydrate_release(release, resolve_management_project_root(project_root))
    except PackError as exc:
        _fail(exc, json_output=json_output, json_payload={"hydrated": False})
    if json_output:
        _emit_json(payload)
    else:
        console.print(f"[green]✓[/green] Hydrated {release}")
