# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Pack repository authoring and inspection commands."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from evidenceforge.composition.compiler import resolve_management_project_root
from evidenceforge.composition.models import PackType
from evidenceforge.composition.packs import PackRepository, parse_pack_cli_reference
from evidenceforge.models.exceptions import PackError

pack_app = typer.Typer(help="Create, inspect, copy, and validate scenario packs.")
console = Console()


def _repository(project_root: Path | None) -> PackRepository:
    """Build the explicitly project-scoped repository for one command."""

    return PackRepository(resolve_management_project_root(project_root))


def _pack_payload(pack: object) -> dict:
    """Return stable machine-readable pack metadata."""

    return {
        "source": pack.source,
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
        "exports": {catalog: sorted(entries) for catalog, entries in pack.catalogs.items()},
    }


@pack_app.command("list")
def list_packs(
    json_output: bool = typer.Option(False, "--json", help="Emit stable JSON."),
    project_root: Path | None = typer.Option(None, "--project-root"),
) -> None:
    """List packaged and project-local packs."""

    try:
        packs = _repository(project_root).list()
    except PackError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}", style="red")
        raise typer.Exit(1) from exc
    payload = [_pack_payload(pack) for pack in packs]
    if json_output:
        print(json.dumps({"packs": payload}, indent=2, sort_keys=True))
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
    project_root: Path | None = typer.Option(None, "--project-root"),
) -> None:
    """Show a pack's manifest, dependencies, exports, and digest."""

    try:
        payload = _pack_payload(_resolve_cli_pack(reference, project_root))
    except (PackError, ValueError) as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}", style="red")
        raise typer.Exit(1) from exc
    if json_output:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    console.print(f"[bold]{payload['type']}:{payload['name']}@{payload['version']}[/bold]")
    console.print(payload["description"])
    console.print(f"Source: {payload['source']}")
    console.print(f"Requires EvidenceForge: {payload['requires_evidenceforge']}")
    console.print(f"Digest: {payload['digest']}")
    for catalog, names in payload["exports"].items():
        console.print(f"  {catalog}: {', '.join(names) if names else '(empty)'}")


@pack_app.command("validate")
def validate_pack(
    reference: str = typer.Argument(..., help="source:type:name@version or pack path"),
    json_output: bool = typer.Option(False, "--json", help="Emit stable JSON."),
    project_root: Path | None = typer.Option(None, "--project-root"),
) -> None:
    """Validate pack schema, containment, identity, dependencies, and digest."""

    try:
        repository = _repository(project_root)
        pack = _resolve_cli_pack(reference, project_root)
        dependencies = []
        for dependency in pack.manifest.industry_dependencies:
            resolved = repository.resolve(
                dependency,
                expected_type="industry",
                declaring_file=pack.root / "pack.yaml",
            )
            dependencies.append(resolved.selected().model_dump(mode="json"))
        payload = {"valid": True, "pack": _pack_payload(pack), "dependencies": dependencies}
    except (PackError, ValueError) as exc:
        if json_output:
            print(json.dumps({"valid": False, "error": str(exc)}, indent=2, sort_keys=True))
        else:
            console.print(f"[bold red]Invalid pack:[/bold red] {exc}", style="red")
        raise typer.Exit(2) from exc
    if json_output:
        print(json.dumps(payload, indent=2, sort_keys=True))
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
    project_root: Path | None = typer.Option(None, "--project-root"),
) -> None:
    """Create a complete project-local pack skeleton."""

    try:
        destination = _repository(project_root).create_skeleton(pack_type, name, version)
    except (PackError, ValueError) as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}", style="red")
        raise typer.Exit(1) from exc
    console.print(f"[green]✓[/green] Created {destination}")


@pack_app.command("copy")
def copy_pack(
    reference: str = typer.Argument(..., help="source:type:name@version or pack path"),
    name: str = typer.Option(..., "--name"),
    version: str = typer.Option(..., "--version"),
    project_root: Path | None = typer.Option(None, "--project-root"),
) -> None:
    """Copy a validated pack into the project repository with a new identity."""

    try:
        repository = _repository(project_root)
        source_pack = _resolve_cli_pack(reference, project_root)
        destination = repository.copy(source_pack, name=name, version=version)
    except (PackError, ValueError) as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}", style="red")
        raise typer.Exit(1) from exc
    console.print(f"[green]✓[/green] Copied pack to {destination}")
