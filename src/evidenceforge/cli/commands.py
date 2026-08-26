# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""CLI commands for EvidenceForge log generator.

This module implements the command-line interface using Typer.
Provides commands for initialization, log generation, and validation.
"""

import json
import logging
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

import click
import typer
import yaml
from pydantic import ValidationError
from rich import box
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table
from rich.text import Text

from evidenceforge import __version__
from evidenceforge.cli.pack_commands import pack_app
from evidenceforge.composition import CompiledScenario, compile_scenario, with_runtime_scenario
from evidenceforge.composition.artifacts import (
    GENERATION_MANIFEST_FILENAME,
    RESOLVED_SCENARIO_FILENAME,
    build_resolved_document,
    serialize_resolved_document,
    verify_generation_bundle,
    write_generation_manifest,
    write_resolved_scenario,
)
from evidenceforge.composition.sidecars import SIDECAR_REGISTRY
from evidenceforge.generation import GenerationEngine
from evidenceforge.generation.resource_forecast import ResourceForecast, build_resource_forecast
from evidenceforge.generation.workload import estimate_workload
from evidenceforge.models.exceptions import (
    EvidenceForgeError,
    PackError,
    ScenarioIncludeError,
    SchemaValidationError,
)
from evidenceforge.models.scenario import Scenario
from evidenceforge.output_targets import (
    OUTPUT_TARGET_FILENAME,
    normalize_output_target,
    write_output_target_marker,
)

if TYPE_CHECKING:
    from evidenceforge.generation.storage_world import StorageWorldModel
    from evidenceforge.validation.schema import ScenarioValidator, ValidationIssue


class AbbreviatedGroup(typer.core.TyperGroup):
    """Typer Group that resolves unique command prefixes.

    Allows 'eforge v' instead of 'eforge validate', 'eforge g' instead
    of 'eforge generate', etc. Exact matches always win. Ambiguous
    prefixes produce a clear error listing the matching commands.
    """

    def resolve_command(self, ctx: click.Context, args: list[str]) -> tuple:
        cmd_name = args[0] if args else None
        if cmd_name is not None:
            # Exact match takes priority
            if cmd_name in self.commands:
                return super().resolve_command(ctx, args)
            # Find all commands that start with the prefix
            matches = [name for name in self.commands if name.startswith(cmd_name)]
            if len(matches) == 1:
                args[0] = matches[0]
            elif len(matches) > 1:
                ctx.fail(f"Ambiguous command '{cmd_name}': could be {', '.join(sorted(matches))}")
        return super().resolve_command(ctx, args)


# Initialize Typer app and Rich console


def _generation_progress(console: Console) -> Progress:
    """Build the long-running generation progress display."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=False,
        speed_estimate_period=15 * 60,
    )


app = typer.Typer(
    name="eforge",
    help="EvidenceForge - Generate realistic synthetic security logs for threat hunting training",
    add_completion=False,
    cls=AbbreviatedGroup,
    context_settings={"help_option_names": ["-h", "--help"]},
)
app.add_typer(pack_app, name="pack")
console = Console()

_STORAGE_SAMPLE_SIZE = 3


def _storage_table(*columns: tuple[str, str]) -> Table:
    """Build a consistent wrapping table for exact storage diagnostics."""
    table = Table(box=box.ROUNDED, header_style="bold cyan", pad_edge=False)
    for heading, justify in columns:
        table.add_column(heading, justify=justify, overflow="fold")
    return table


def _print_compiled_storage(storage_world: "StorageWorldModel") -> None:
    """Render author-facing diagnostics for a compiled storage world."""
    console.print("\n[bold]Compiled storage topology[/bold]")
    if not storage_world.volumes and not storage_world.file_sets:
        console.print("[dim]No host file sets, storage volumes, or SMB shares were compiled.[/dim]")
        return

    if storage_world.file_sets:
        console.print("\n[bold]Host file sets[/bold]")
        file_sets_table = _storage_table(
            ("File set", "left"),
            ("System / root", "left"),
            ("Preset / population", "left"),
            ("Files", "right"),
            ("Export", "left"),
        )
        for file_set in storage_world.file_sets:
            file_sets_table.add_row(
                Text(file_set.id),
                Text(f"{file_set.system} / {file_set.root}"),
                Text(f"{file_set.preset} / {file_set.population}"),
                str(len(file_set.files)),
                Text(file_set.backing_share or "local only"),
            )
        console.print(file_sets_table)

    if not storage_world.volumes:
        return

    console.print("\n[bold]Volumes[/bold]")
    volumes_table = _storage_table(
        ("Volume", "left"),
        ("Mount", "left"),
        ("Platform / backing FS", "left"),
        ("Label", "left"),
        ("Shares", "right"),
    )
    for volume in storage_world.volumes:
        volume_ref = f"{volume.system}.{volume.id}"
        share_count = sum(
            share.system.casefold() == volume.system.casefold()
            and share.volume.casefold() == volume.id.casefold()
            for share in storage_world.shares
        )
        volumes_table.add_row(
            Text(volume_ref),
            Text(volume.mount),
            Text(f"{volume.platform} / {volume.filesystem}"),
            Text(volume.label),
            str(share_count),
        )
    console.print(volumes_table)

    console.print("\n[bold]Shares[/bold]")
    console.print("[bold cyan]Locations[/bold cyan]")
    share_locations_table = _storage_table(
        ("Share", "left"),
        ("UNC root", "left"),
        ("Server root", "left"),
        ("Volume", "left"),
    )
    for share in storage_world.shares:
        share_locations_table.add_row(
            Text(share.ref),
            Text(storage_world.unc_path(share)),
            Text(storage_world.server_local_path(share, "")),
            Text(f"{share.system}.{share.volume}"),
        )
    console.print(share_locations_table)

    console.print("[bold cyan]Policy and catalog[/bold cyan]")
    share_policy_table = _storage_table(
        ("Share", "left"),
        ("Preset", "left"),
        ("Population", "left"),
        ("Activity", "left"),
        ("Files", "right"),
        ("Audit", "left"),
        ("Encryption", "left"),
    )
    for share in storage_world.shares:
        share_policy_table.add_row(
            Text(share.ref),
            Text(share.preset),
            Text(share.population),
            Text(share.activity),
            str(len(share.files)),
            Text(share.audit),
            Text(share.encryption),
        )
    console.print(share_policy_table)

    console.print("[bold cyan]SMB filesystem views[/bold cyan]")
    filesystem_views_table = _storage_table(
        ("Share", "left"),
        ("Provider", "left"),
        ("Backing FS", "left"),
        ("SMB native FS", "left"),
    )
    for share in storage_world.shares:
        volume = storage_world.volumes_by_ref[f"{share.system}.{share.volume}".casefold()]
        filesystem_views_table.add_row(
            Text(share.ref),
            Text("samba" if volume.platform == "linux" else "windows"),
            Text(volume.filesystem),
            Text(share.smb_native_filesystem),
        )
    console.print(filesystem_views_table)

    console.print("\n[bold]Effective access[/bold]")
    data_access_table = _storage_table(
        ("Share", "left"),
        ("Read", "left"),
        ("Modify", "left"),
    )
    for share in storage_world.shares:
        data_access_table.add_row(
            Text(share.ref),
            Text(", ".join(sorted(share.access.read, key=str.casefold)) or "-"),
            Text(", ".join(sorted(share.access.modify, key=str.casefold)) or "-"),
        )
    console.print(data_access_table)

    console.print("[bold cyan]Administration and denies[/bold cyan]")
    administrative_access_table = _storage_table(
        ("Share", "left"),
        ("Admin", "left"),
        ("Deny", "left"),
    )
    for share in storage_world.shares:
        administrative_access_table.add_row(
            Text(share.ref),
            Text(", ".join(sorted(share.access.admin, key=str.casefold)) or "-"),
            Text(", ".join(sorted(share.access.deny, key=str.casefold)) or "-"),
        )
    console.print(administrative_access_table)

    console.print("\n[bold]Bounded catalog samples[/bold]")
    for share in storage_world.shares:
        if not share.files:
            continue
        console.print(f"[bold cyan]{share.ref}[/bold cyan] [dim]({len(share.files)} files)[/dim]")
        samples_table = _storage_table(
            ("Kind", "left"),
            ("Path", "left"),
            ("Size", "right"),
        )
        metadata_table = _storage_table(
            ("Kind", "left"),
            ("MIME", "left"),
            ("Tags", "left"),
        )
        seed_files = [file for file in share.files if file.seed_ref]
        generated_files = [file for file in share.files if not file.seed_ref]
        samples = (*seed_files, *generated_files)[:_STORAGE_SAMPLE_SIZE]
        for file in samples:
            sample_kind = f"seed {file.seed_ref}" if file.seed_ref else "generated"
            tags = ", ".join(file.tags) or "-"
            samples_table.add_row(
                Text(sample_kind),
                Text(file.path),
                f"{file.size_bytes} bytes",
            )
            metadata_table.add_row(
                Text(sample_kind),
                Text(file.mime_type),
                Text(tags),
            )
        console.print(samples_table)
        console.print(metadata_table)
    console.print(
        f"[dim]Showing up to {_STORAGE_SAMPLE_SIZE} catalog entries per share; "
        "generated file and directory IDs remain internal.[/dim]"
    )

    if storage_world.mappings:
        console.print("\n[bold]Mappings[/bold]")
        mapping_locations_table = _storage_table(
            ("Mapping", "left"),
            ("Share", "left"),
            ("Drive", "left"),
            ("Mount", "left"),
        )
        mapping_policy_table = _storage_table(
            ("Mapping", "left"),
            ("Credentials", "left"),
            ("Principal", "left"),
            ("Lifecycle", "left"),
            ("Effective audience", "left"),
        )
        for mapping in storage_world.mappings:
            audience = ", ".join(sorted(mapping.users, key=str.casefold)) or "all allowed users"
            if mapping.systems:
                systems = ", ".join(sorted(mapping.systems, key=str.casefold))
                audience = f"{audience} on {systems}"
            mapping_locations_table.add_row(
                Text(mapping.id),
                Text(mapping.share),
                Text(mapping.drive or "-"),
                Text(mapping.mount or "-"),
            )
            mapping_policy_table.add_row(
                Text(mapping.id),
                Text(mapping.credential_mode),
                Text(mapping.principal or "-"),
                Text(mapping.lifecycle),
                Text(audience),
            )
        console.print(mapping_locations_table)
        console.print(mapping_policy_table)


def _format_capacity(value: int) -> str:
    """Format a byte count using compact binary units."""
    amount = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if amount < 1024 or unit == "PiB":
            return f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{amount:.1f} PiB"


def _display_resource_forecast(forecast: ResourceForecast) -> None:
    """Print an informational forecast followed immediately by pressure warnings."""
    memory = forecast.memory
    final_output = forecast.final_output
    disk = forecast.disk
    resources = forecast.snapshot
    console.print("\n[bold blue]Resource forecast[/bold blue]")
    console.print(
        "  Projected peak memory: "
        f"{_format_capacity(memory.lower_bytes)}–{_format_capacity(memory.upper_bytes)} "
        f"(expected {_format_capacity(memory.expected_bytes)})"
    )
    console.print(
        "  Available memory + swap: "
        f"{_format_capacity(resources.available_memory_bytes)} + "
        f"{_format_capacity(resources.free_swap_bytes)} "
        f"(installed/limited RAM {_format_capacity(resources.total_memory_bytes)})"
    )
    console.print(
        "  Projected final output: "
        f"{_format_capacity(final_output.lower_bytes)}–"
        f"{_format_capacity(final_output.upper_bytes)} "
        f"(expected {_format_capacity(final_output.expected_bytes)})"
    )
    console.print(
        "  Projected peak working disk: "
        f"{_format_capacity(disk.lower_bytes)}–{_format_capacity(disk.upper_bytes)} "
        f"(expected {_format_capacity(disk.expected_bytes)})"
    )
    console.print(
        f"  Available disk: {_format_capacity(resources.free_disk_bytes)} on {resources.disk_path}"
    )
    console.print(
        f"  Forecast model: v{forecast.calibration_version}, {forecast.calibration_label}",
        style="dim",
    )

    styles = {"low": "yellow", "medium": "dark_orange", "high": "bold red"}
    for pressure in forecast.pressures:
        console.print(
            f"[{styles[pressure.level]}]{pressure.level.upper()} resource warning: "
            f"projected {pressure.resource} use is {pressure.ratio:.0%} of the "
            f"forecast's usable {pressure.resource} capacity; generation will continue."
            f"[/{styles[pressure.level]}]"
        )


def _forecast_for_cli(
    scenario: Scenario,
    *,
    scenario_root: Path,
    destination: Path,
) -> ResourceForecast | None:
    """Build and display a forecast without masking owning validation errors."""
    forecast, error = _build_resource_forecast_for_cli(
        scenario,
        scenario_root=scenario_root,
        destination=destination,
    )
    if error is not None:
        console.print("\n[bold blue]Resource forecast[/bold blue]")
        console.print(f"  Unavailable until scenario resource errors are resolved: {error}")
        return None
    assert forecast is not None
    _display_resource_forecast(forecast)
    return forecast


def _build_resource_forecast_for_cli(
    scenario: Scenario,
    *,
    scenario_root: Path,
    destination: Path,
) -> tuple[ResourceForecast | None, str | None]:
    """Build a forecast for text or JSON callers without writing console output."""

    try:
        estimate = estimate_workload(scenario, scenario_root=scenario_root)
        forecast = build_resource_forecast(scenario, estimate, destination)
    except (EvidenceForgeError, OSError, ValueError, yaml.YAMLError) as exc:
        return None, str(exc)
    return forecast, None


# Exit codes (per TODO.md specification)
EXIT_SUCCESS = 0
EXIT_INPUT_ERROR = 1
EXIT_SCHEMA_VALIDATION = 2
EXIT_ABORTED = 3
EXIT_GENERATION_ERROR = 21
EXIT_EVAL_ERROR = 22
EXIT_SIGINT = 130


def setup_logging(verbose: bool = False, debug: bool = False) -> None:
    """Configure logging with Rich handler.

    Args:
        verbose: Enable INFO level logging if True
        debug: Enable DEBUG level logging if True (takes precedence over verbose)
    """
    if debug:
        level = logging.DEBUG
    elif verbose:
        level = logging.INFO
    else:
        level = logging.WARNING

    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(console=console, rich_tracebacks=True)],
    )


def _normalize_oob_hosts(
    oob_host: list[str],
    *,
    json_output: bool = False,
) -> tuple[str, ...]:
    """Normalize/validate operator-supplied --oob-host values for fail-fast CLI UX.

    Delegates the actual contract to ``adversarial_payload.normalize_oob_host`` — the single
    source of truth, which is ALSO enforced at the safety boundary (``check_payload_safety``)
    so a broad value (a bare TLD/public suffix that would allowlist a whole namespace via the
    suffix match) can never reach the allowlist regardless of caller. A value must be a concrete
    registrable domain (e.g. example.com, oast.fun, or a subdomain of one) or an IP literal.
    Shared by `generate` and `validate`. Prints a friendly error and raises
    typer.Exit(EXIT_INPUT_ERROR) on a bad value.
    """
    from evidenceforge.generation.adversarial_payload import AdversarialPayloadSafetyError

    try:
        return _normalize_oob_host_values(oob_host)
    except AdversarialPayloadSafetyError as exc:
        if json_output:
            print(json.dumps({"valid": False, "error": str(exc)}, indent=2, sort_keys=True))
        else:
            console.print(f"[bold red]Error:[/bold red] {exc}", style="red")
        raise typer.Exit(EXIT_INPUT_ERROR) from exc


def _normalize_oob_host_values(oob_host: list[str]) -> tuple[str, ...]:
    """Normalize OOB hosts while leaving presentation and exit handling to the caller."""

    from evidenceforge.generation.adversarial_payload import normalize_oob_host

    normalized = [normalize_oob_host(raw) for raw in oob_host if raw.strip()]
    return tuple(dict.fromkeys(normalized))


def _scenario_summary(scenario: Scenario) -> dict[str, Any]:
    """Return the bounded scenario summary used by machine-readable validation."""

    network = scenario.environment.network
    return {
        "name": scenario.name,
        "version": scenario.version,
        "description": scenario.description,
        "generation_seed": scenario.generation_seed,
        "users": len(scenario.environment.users),
        "systems": len(scenario.environment.systems),
        "personas": len(scenario.personas or []),
        "storyline_events": len(scenario.storyline or []),
        "red_herrings": len(scenario.red_herrings or []),
        "network": {
            "segments": len(network.segments) if network else 0,
            "sensors": len(network.sensors) if network else 0,
        },
        "output_formats": sorted(
            str(entry["format"])
            for entry in scenario.output.logs
            if isinstance(entry, dict) and "format" in entry
        ),
    }


def _field_origin_payload(
    compiled: CompiledScenario,
    field_path: str,
    scenario_file: Path,
) -> tuple[dict[str, str], dict[str, Any]]:
    """Resolve the closest portable authored or organization-pack field origin."""

    normalized = field_path.replace("[", ".").replace("]", "")
    diagnostic_match = _closest_diagnostic_origin(
        compiled.diagnostic_field_origins,
        normalized,
    )
    if diagnostic_match is not None:
        origin, declaring_field = diagnostic_match
        provenance: dict[str, Any] = {
            "origin_kind": "authored-field",
            "field_path": declaring_field,
        }
        authored_origins = compiled.provenance.get("field_origins", {})
        if isinstance(authored_origins, dict):
            portable_origin = authored_origins.get(declaring_field)
            if isinstance(portable_origin, str):
                provenance["portable_source"] = portable_origin
        return (
            {"kind": "authored-file", "path": str(origin)},
            provenance,
        )

    candidates: list[str] = []
    current = normalized
    while current:
        candidates.append(current)
        current = current.rpartition(".")[0]

    authored_origins = compiled.provenance.get("field_origins", {})
    if isinstance(authored_origins, dict):
        for candidate in candidates:
            origin = authored_origins.get(candidate)
            if isinstance(origin, str):
                return (
                    {"kind": "scenario-source", "path": origin},
                    {"origin_kind": "authored-field", "field_path": candidate},
                )

    organization_origins = compiled.provenance.get("organization_model_origins", {})
    if isinstance(organization_origins, dict):
        organization = next(
            (pack for pack in reversed(compiled.selected_packs) if pack.type == "organization"),
            None,
        )
        for candidate in candidates:
            origin = organization_origins.get(candidate)
            if isinstance(origin, str):
                provenance: dict[str, Any] = {
                    "origin_kind": "organization-pack",
                    "field_path": candidate,
                    "relative_path": origin,
                }
                if organization is not None:
                    provenance["pack"] = organization.model_dump(mode="json")
                return (
                    {"kind": "pack-source", "path": origin},
                    provenance,
                )

    return (
        {"kind": "input", "path": str(scenario_file)},
        {"origin_kind": "input-fallback"},
    )


def _closest_diagnostic_origin(
    origins: dict[str, Path],
    field_path: str,
) -> tuple[Path, str] | None:
    """Find the nearest exact, parent, or unambiguous child declaring file."""

    candidate = field_path
    while candidate:
        exact = origins.get(candidate)
        if exact is not None:
            return exact, candidate
        descendants = {
            source for path, source in origins.items() if path.startswith(f"{candidate}.")
        }
        if len(descendants) == 1:
            return next(iter(descendants)), candidate
        candidate = candidate.rpartition(".")[0]
    return None


def _validation_issue_payload(
    issue: "ValidationIssue",
    compiled: CompiledScenario,
    scenario_file: Path,
) -> dict[str, Any]:
    """Serialize one semantic issue with best-effort portable source provenance."""

    source, provenance = _field_origin_payload(compiled, issue.field_path, scenario_file)
    return {
        "code": "scenario.semantic",
        "severity": issue.severity,
        "field_path": issue.field_path,
        "message": issue.message,
        "suggestion": issue.suggestion,
        "source": source,
        "provenance": provenance,
    }


def _schema_error_guidance(field_path: str, message: str) -> tuple[str, str]:
    """Return a precise authored path and repair for known cross-field schema invariants."""

    normalized = message.casefold()
    if "batched smb destinations cannot use one explicit file path" in normalized:
        return (
            f"{field_path}.destination.path",
            "Move the directory prefix to destination.directory, or remove batch for one exact "
            "destination file.",
        )
    if "batched smb client sources require environment.storage.file_sets" in normalized:
        return (
            f"{field_path}.source.path",
            "Declare the bounded files under environment.storage.file_sets and reference its ID "
            "with source.file_set, or remove batch for one exact client path.",
        )
    if "storage share backing_file_set owns its catalog" in normalized:
        return (
            f"{field_path}.backing_file_set",
            "Let the backing file set own preset, population, and seed_files; omit those fields "
            "from the share.",
        )
    return field_path, "Edit this field in its declaring source to match the scenario schema."


def _focused_schema_selector(field_path: str) -> str | None:
    """Map one authored diagnostic path to the narrowest public schema selector."""

    prefixes = (
        ("environment.network_identities.", "environment.network_identities"),
        ("environment.service_accounts.", "environment.service_accounts"),
        ("environment.network.segments.", "environment.network.segments"),
        ("environment.network.sensors.", "environment.network.sensors"),
        ("environment.storage.", "environment.storage"),
        ("environment.email.", "environment.email"),
        ("environment.proxy.", "environment.proxy"),
        ("environment.users.", "environment.users"),
        ("environment.systems.", "environment.systems"),
        ("time_window.", "time_window"),
        ("baseline_activity.", "baseline_activity"),
        ("output.", "output"),
    )
    for prefix, selector in prefixes:
        if field_path.startswith(prefix):
            return selector

    parts = field_path.split(".")
    if parts and parts[0] in {"storyline", "red_herrings"} and "events" in parts:
        event_index = parts.index("events")
        if len(parts) > event_index + 2:
            return f"event.{parts[event_index + 2]}"
    return None


def _group_object_shape_issues(issues: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse sibling missing/extra errors into one actionable object-shape issue."""

    from evidenceforge.cli.schema import resolve_schema_contract, schema_contract_payload

    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    ungrouped: list[dict[str, Any]] = []
    for issue in issues:
        if issue["code"] not in {
            "scenario.schema.missing",
            "scenario.schema.extra_forbidden",
        }:
            ungrouped.append(issue)
            continue
        parent, separator, _field = issue["field_path"].rpartition(".")
        selector = _focused_schema_selector(issue["field_path"])
        if not separator or selector is None:
            ungrouped.append(issue)
            continue
        source_path = str(issue.get("source", {}).get("path", ""))
        grouped.setdefault((parent, selector, source_path), []).append(issue)

    collapsed: list[dict[str, Any]] = []
    for (parent, selector, _source_path), siblings in grouped.items():
        if len(siblings) == 1:
            collapsed.append(siblings[0])
            continue

        missing = sorted(
            issue["field_path"].rpartition(".")[2]
            for issue in siblings
            if issue["code"] == "scenario.schema.missing"
        )
        unsupported = sorted(
            issue["field_path"].rpartition(".")[2]
            for issue in siblings
            if issue["code"] == "scenario.schema.extra_forbidden"
        )
        details: list[str] = []
        if missing:
            details.append("missing required fields: " + ", ".join(missing))
        if unsupported:
            details.append("unsupported fields: " + ", ".join(unsupported))

        contract = resolve_schema_contract(selector)
        allowed = (
            sorted(schema_contract_payload(contract)["fields"]) if contract is not None else []
        )
        first = siblings[0]
        collapsed.append(
            {
                **first,
                "code": "scenario.schema.object_shape",
                "field_path": parent,
                "message": f"Object does not match {selector}: " + "; ".join(details),
                "suggestion": (
                    ("Use only these fields: " + ", ".join(allowed) + ". ") if allowed else ""
                )
                + f"Inspect the exact installed contract with `eforge schema {selector} --json`.",
                "provenance": {
                    **first.get("provenance", {}),
                    "field_path": parent,
                },
            }
        )

    return sorted(
        [*ungrouped, *collapsed],
        key=lambda issue: (str(issue.get("field_path", "")), str(issue.get("code", ""))),
    )


def _exception_issue_payloads(exc: Exception, scenario_file: Path) -> list[dict[str, Any]]:
    """Convert a compilation failure and any chained Pydantic details into issues."""

    raw_origins = getattr(exc, "diagnostic_field_origins", {})
    diagnostic_origins = (
        raw_origins
        if isinstance(raw_origins, dict)
        and all(
            isinstance(key, str) and isinstance(value, Path) for key, value in raw_origins.items()
        )
        else {}
    )
    raw_prefix = getattr(exc, "diagnostic_path_prefix", None)
    path_prefix = raw_prefix if isinstance(raw_prefix, str) and raw_prefix else None
    diagnostic_editable = getattr(exc, "diagnostic_editable", True) is not False
    diagnostic_kind = getattr(exc, "diagnostic_input_kind", "unknown")
    resolved_guidance = (
        "Regenerate this authoritative artifact from authored input, or restore an identical "
        "untampered copy."
    )
    cause: BaseException | None = exc
    while cause is not None:
        if isinstance(cause, ValidationError):
            issues: list[dict[str, Any]] = []
            for error in cause.errors():
                error_path = ".".join(str(part) for part in error["loc"])
                field_path = ".".join(part for part in (path_prefix, error_path) if part) or "$"
                field_path, authored_suggestion = _schema_error_guidance(
                    field_path,
                    error["msg"],
                )
                selector = _focused_schema_selector(field_path)
                if diagnostic_editable and selector is not None:
                    authored_suggestion += (
                        " Inspect the exact installed contract with "
                        f"`eforge schema {selector} --json`."
                    )
                origin = _closest_diagnostic_origin(diagnostic_origins, field_path)
                source: dict[str, str]
                provenance: dict[str, Any]
                if origin is not None:
                    source_path, declaring_field = origin
                    source = {"kind": "authored-file", "path": str(source_path)}
                    provenance = {
                        "origin_kind": "authored-field",
                        "field_path": declaring_field,
                    }
                else:
                    source = {"kind": "input", "path": str(scenario_file)}
                    provenance = {"origin_kind": "input-fallback"}
                issues.append(
                    {
                        "code": f"scenario.schema.{error['type']}",
                        "severity": "error",
                        "field_path": field_path,
                        "message": error["msg"],
                        "suggestion": (
                            authored_suggestion if diagnostic_editable else resolved_guidance
                        ),
                        "source": source,
                        "provenance": provenance,
                    }
                )
            if diagnostic_editable:
                return _group_object_shape_issues(issues)
            return issues
        cause = cause.__cause__

    if isinstance(exc, ScenarioIncludeError):
        code, field_path = "scenario.include", "includes"
    elif isinstance(exc, PackError):
        code, field_path = "scenario.pack", "composition"
    elif isinstance(exc, SchemaValidationError):
        code, field_path = "scenario.schema", "$"
    elif isinstance(exc, FileNotFoundError):
        code, field_path = "input.not_found", "$"
    else:
        code, field_path = "input.invalid", "$"
    suggestion = resolved_guidance if diagnostic_kind == "resolved" else None
    return [
        {
            "code": code,
            "severity": "error",
            "field_path": field_path,
            "message": str(exc),
            "suggestion": suggestion,
            "source": {"kind": "input", "path": str(scenario_file)},
            "provenance": {"origin_kind": "input-fallback"},
        }
    ]


def _validation_json_payload(
    *,
    scenario_file: Path,
    input_kind: str,
    project_root: Path | None,
    issues: list[dict[str, Any]],
    scenario: dict[str, Any] | None = None,
    selected_packs: list[dict[str, Any]] | None = None,
    resource_forecast: dict[str, Any] | None = None,
    storage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the stable Scenario validation JSON envelope."""

    counts = {
        severity: sum(issue.get("severity") == severity for issue in issues)
        for severity in ("error", "warning", "info")
    }
    valid = counts["error"] == 0
    status = "invalid" if not valid else "valid_with_warnings" if counts["warning"] else "valid"
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "valid": valid,
        "status": status,
        "input": {"path": str(scenario_file), "kind": input_kind},
        "severity_counts": counts,
        "issues": issues,
        "suggestions": [
            {
                "field_path": issue["field_path"],
                "message": issue["suggestion"],
                "source": issue["source"],
            }
            for issue in issues
            if issue.get("suggestion")
        ],
        "scenario": scenario,
        "composition": {
            "project_root": str(project_root) if project_root is not None else None,
            "selected_packs": selected_packs or [],
        },
        "resource_forecast": resource_forecast,
    }
    if storage is not None:
        payload["storage"] = storage
    if not valid and issues:
        first_error = next(issue for issue in issues if issue.get("severity") == "error")
        payload["error"] = first_error["message"]
    return payload


def _validate_compiled_scenario(
    compiled: CompiledScenario,
    oob_hosts: tuple[str, ...],
    scenario_root: Path,
    *,
    allow_large_workload: bool = False,
) -> tuple["ScenarioValidator", list["ValidationIssue"]]:
    """Run cross-reference validation inside the compilation's config scope."""

    from evidenceforge.config.provider import effective_config_scope
    from evidenceforge.validation import ScenarioValidator

    if not isinstance(compiled, CompiledScenario):
        raise TypeError("compiled must be a CompiledScenario")
    with effective_config_scope(compiled.effective_config):
        validator = ScenarioValidator(
            compiled.scenario,
            oob_hosts=oob_hosts,
            scenario_root=scenario_root,
            allow_large_workload=allow_large_workload,
        )
        return validator, validator.validate()


@app.command()
def generate(
    scenario_file: Path = typer.Argument(
        ...,
        help="Path to scenario YAML file",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Output bundle root (default: directory containing the scenario)",
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Enable verbose (INFO level) logging"
    ),
    debug: bool = typer.Option(False, "--debug", "-d", help="Enable debug (DEBUG level) logging"),
    force: bool = typer.Option(
        False, "--force", "-f", help="Overwrite existing output without prompting"
    ),
    formats: str | None = typer.Option(
        None,
        "--formats",
        "-F",
        help="Comma-separated format filter (e.g., 'zeek_conn,zeek_dns' or 'zeek'). "
        "Only generates formats present in both this list and the scenario. "
        "Supports group names (zeek, windows). See 'eforge info format_groups'.",
    ),
    target: str = typer.Option(
        "default",
        "--target",
        help="Output rendering target: default, sof-elk, or splunk",
    ),
    oob_host: list[str] = typer.Option(
        [],
        "--oob-host",
        help="LIVE CALLBACK (out-of-band) testing: register an operator-controlled host "
        "(e.g. a Burp Collaborator / interactsh / sinkhole domain) for adversarial_payload "
        "events. The payload's canary is replaced with this host so a vulnerable target "
        "actually calls back to YOU. Must be a concrete registrable domain (e.g. oast.fun) "
        "or an IP literal. Repeatable. Passing it is the explicit opt-in: only use against "
        "systems you are authorized to test. Off by default (payloads use the inert, "
        "non-resolving canary).",
    ),
    seed: int | None = typer.Option(
        None,
        "--seed",
        min=0,
        max=2**64 - 1,
        help="Override scenario generation_seed for this deterministic run.",
    ),
    project_root: Path | None = typer.Option(
        None,
        "--project-root",
        help="Override the current working directory for optional .eforge/config and .eforge/packs.",
    ),
    allow_large_workload: bool = typer.Option(
        False,
        "--allow-large-workload",
        hidden=True,
    ),
) -> None:
    """Generate synthetic security logs from a scenario file.

    Validates the scenario schema, initializes the generation engine,
    and produces coordinated logs across multiple formats.

    Exit codes:
    - 0: Success
    - 1: Input error (file not found, invalid path)
    - 2: Schema validation error
    - 21: Generation error
    - 130: Interrupted (Ctrl+C)
    """
    if not scenario_file.is_file() or not os.access(scenario_file, os.R_OK):
        console.print(
            f"[bold red]Error:[/bold red] Scenario file not found or unreadable: {scenario_file}",
            style="red",
        )
        raise typer.Exit(EXIT_INPUT_ERROR)

    setup_logging(verbose, debug)
    logger = logging.getLogger(__name__)
    try:
        output_target = normalize_output_target(target)
    except ValueError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}", style="red")
        raise typer.Exit(EXIT_INPUT_ERROR) from exc

    # Live-callback (OOB) opt-in for adversarial_payload events. Off by default; passing
    # --oob-host IS the explicit opt-in, and only the explicitly-registered host(s) become
    # allowlisted, so a payload can never silently point anywhere else. Normalize + validate
    # at the boundary (fail fast) via the shared helper that generate and validate share.
    oob_hosts: tuple[str, ...] = _normalize_oob_hosts(oob_host)

    console.print("[bold blue]EvidenceForge Log Generator[/bold blue]")
    console.print(f"Scenario: {scenario_file}")
    console.print(f"Output target: {output_target.value}")
    if oob_hosts:
        console.print(
            "[bold red]⚠ LIVE CALLBACK MODE[/bold red] — adversarial_payload events will "
            f"point at {', '.join(oob_hosts)} instead of the inert canary. A VULNERABLE "
            "TARGET WILL CALL BACK to these host(s). Only use against systems you are "
            "authorized to test.",
            style="red",
        )

    # Load and validate scenario
    try:
        console.print("\n[bold]Loading scenario...[/bold]")
        compiled = compile_scenario(
            scenario_file,
            project_root=project_root,
            generation_seed=seed,
        )
        scenario = compiled.scenario
        console.print(f"[green]✓[/green] Loaded scenario: {scenario.name}")
        console.print(f"  Description: {scenario.description}")
        console.print(f"  Users: {len(scenario.environment.users)}")
        console.print(f"  Systems: {len(scenario.environment.systems)}")
        if scenario.storyline:
            console.print(f"  Storyline events: {len(scenario.storyline)}")

        # Cross-reference validation (Phase 1.9)
        console.print("\n[bold]Validating cross-references...[/bold]")
        validator, issues = _validate_compiled_scenario(
            compiled,
            oob_hosts,
            scenario_file.parent,
        )

        if issues:
            counts = {
                severity: sum(issue.severity == severity for issue in issues)
                for severity in ("error", "warning", "info")
            }
            headline_color = "red" if counts["error"] else "yellow" if counts["warning"] else "cyan"
            console.print(
                f"\n[{headline_color}]Found {len(issues)} validation issue(s):[/{headline_color}]"
            )
            for issue in issues:
                if issue.severity == "error":
                    color, icon = "red", "✗"
                elif issue.severity == "warning":
                    color, icon = "yellow", "!"
                else:
                    color, icon = "cyan", "ℹ"
                console.print(f"  [{color}]{icon} {issue.field_path}[/{color}]")
                from rich.text import Text

                console.print(Text(f"    {issue.message}", style=color))
                if issue.suggestion:
                    # Wrap in Text() (like the message above) so bracketed tokens
                    # such as "roles: [web_server]" are not parsed as Rich markup.
                    console.print(Text(f"    💡 {issue.suggestion}", style="dim"))

            if validator.has_errors():
                console.print(
                    "\n[bold red]Validation failed with errors. Cannot proceed with generation.[/bold red]"
                )
                raise typer.Exit(EXIT_SCHEMA_VALIDATION)
            if counts["warning"]:
                console.print("\n[yellow]Warnings found but proceeding with generation...[/yellow]")
            else:
                console.print(
                    "\n[cyan]Informational findings only; proceeding with generation...[/cyan]"
                )
        else:
            console.print("[green]✓[/green] All cross-references valid")

    except typer.Exit:
        # Re-raise typer.Exit to preserve exit codes
        raise

    except FileNotFoundError:
        console.print(
            f"[bold red]Error:[/bold red] Scenario file not found: {scenario_file}", style="red"
        )
        raise typer.Exit(EXIT_INPUT_ERROR)

    except ScenarioIncludeError as e:
        console.print("[bold red]Error:[/bold red] Scenario include validation failed", style="red")
        console.print(f"  • {e}", style="red")
        raise typer.Exit(EXIT_SCHEMA_VALIDATION)

    except (PackError, SchemaValidationError) as e:
        console.print(f"[bold red]Error:[/bold red] Scenario compilation failed: {e}", style="red")
        raise typer.Exit(EXIT_SCHEMA_VALIDATION)

    except ValidationError as e:
        console.print("[bold red]Error:[/bold red] Schema validation failed", style="red")
        console.print("\nValidation errors:")
        for error in e.errors():
            field = " -> ".join(str(loc) for loc in error["loc"])
            console.print(f"  • {field}: {error['msg']}", style="red")
        raise typer.Exit(EXIT_SCHEMA_VALIDATION)
    except EvidenceForgeError as e:
        console.print(f"[bold red]Error:[/bold red] {e}", style="red")
        raise typer.Exit(EXIT_SCHEMA_VALIDATION)

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] Failed to load scenario: {e}", style="red")
        if verbose or debug:
            console.print_exception()
        raise typer.Exit(EXIT_INPUT_ERROR)

    # Determine output directory
    scenario_dir = scenario_file.parent
    if output:
        # Explicit --output flag: logs in data/ subdirectory, ground truth at root
        data_dir = output / "data"
        ground_truth_dir = output
    else:
        # Default: derive from scenario file location
        # scenarios/<name>/scenario.yaml → data goes to scenarios/<name>/data/
        data_dir = scenario_dir / "data"
        ground_truth_dir = scenario_dir
    if (
        compiled.authored_kind == "resolved"
        and ground_truth_dir.resolve() == scenario_file.resolve().parent
    ):
        console.print(
            "[bold red]Error:[/bold red] A resolved scenario cannot be replayed into "
            "the directory that contains the authoritative input. Choose a distinct "
            "bundle root with --output.",
            style="red",
        )
        raise typer.Exit(EXIT_INPUT_ERROR)
    artifacts_dir = ground_truth_dir / "artifacts"

    from evidenceforge.events.artifacts_manifest import ARTIFACTS_MANIFEST_FILENAME
    from evidenceforge.events.collection_profile import COLLECTION_PROFILE_FILENAME
    from evidenceforge.events.ground_truth import GROUND_TRUTH_JSON_FILENAME
    from evidenceforge.events.observation_manifest import OBSERVATION_MANIFEST_FILENAME

    # Apply --formats filter (intersection with scenario output.logs)
    if formats:
        from evidenceforge.events.dispatcher import expand_formats

        requested = expand_formats([f.strip() for f in formats.split(",")])
        scenario_formats = expand_formats(
            {log["format"] for log in scenario.output.logs if "format" in log}
        )
        filtered = requested & scenario_formats

        if requested - scenario_formats:
            missing = sorted(requested - scenario_formats)
            console.print(f"[yellow]Warning: formats not in scenario: {missing}[/yellow]")

        if not filtered:
            console.print(
                "[bold red]Error:[/bold red] No formats match both --formats and scenario output.logs"
            )
            raise typer.Exit(EXIT_INPUT_ERROR)

        scenario.output.logs = [{"format": fmt} for fmt in sorted(filtered)]
        compiled = with_runtime_scenario(compiled, scenario)
        console.print(f"[dim]Format filter: generating {sorted(filtered)}[/dim]")

    from evidenceforge.config.provider import effective_config_scope

    with effective_config_scope(compiled.effective_config):
        resource_forecast = _forecast_for_cli(
            scenario,
            scenario_root=scenario_dir,
            destination=ground_truth_dir,
        )
    if resource_forecast is None:
        raise typer.Exit(EXIT_SCHEMA_VALIDATION)

    console.print(f"\n[bold]Data directory:[/bold] {data_dir}")
    console.print(f"[bold]Ground truth:[/bold] {ground_truth_dir / 'GROUND_TRUTH.md'}")

    # Check for existing generated output (data/ and generated sidecars only).
    # ENVIRONMENT.md is authored by /eforge scenario, not the engine — never touch it.
    try:
        SIDECAR_REGISTRY.reject_symlinks(ground_truth_dir)
    except PermissionError as e:
        console.print(f"[bold red]Error:[/bold red] {e}", style="red")
        raise typer.Exit(EXIT_INPUT_ERROR)
    existing = [
        f"  {spec.relative_path} ({ground_truth_dir / spec.relative_path})"
        for spec in SIDECAR_REGISTRY.existing(ground_truth_dir)
    ]

    has_existing = bool(existing)
    if has_existing:
        console.print("\n[yellow]Existing output found:[/yellow]")
        for item in existing:
            console.print(item)

        if formats:
            console.print(
                "[yellow]Warning: --formats replaces the entire data/ directory. "
                "Previously generated formats not in the filter will be deleted.[/yellow]"
            )

        if not force:
            try:
                typer.confirm("\nOverwrite existing output?", abort=True)
            except typer.Abort:
                console.print("[dim]Aborted.[/dim]")
                raise typer.Exit(EXIT_ABORTED)

    # Stage generation into a temp directory when overwriting, so that a
    # mid-run failure doesn't destroy the previous good output.
    staging_dir = None
    gen_data_dir = data_dir
    gen_gt_dir = ground_truth_dir
    gen_artifacts_dir = artifacts_dir
    if has_existing:
        staging_dir = Path(tempfile.mkdtemp(prefix=".eforge_staging_", dir=ground_truth_dir))
        gen_data_dir = staging_dir / "data"
        gen_gt_dir = staging_dir
        gen_artifacts_dir = staging_dir / "artifacts"

    # Generate logs
    try:
        console.print("\n[bold]Starting log generation...[/bold]")

        # Create progress display with Rich
        with _generation_progress(console) as progress:
            # Progress tracking state
            phase_task = progress.add_task("Initializing...", total=None)
            hour_task = None
            storyline_task = None

            # Progress callback closure
            def progress_callback(event_type: str, data: dict) -> None:
                nonlocal phase_task, hour_task, storyline_task

                if event_type == "phase_start":
                    progress.update(phase_task, description=data["description"])

                elif event_type == "phase_end":
                    if data["phase"] == "baseline" and hour_task is not None:
                        progress.update(hour_task, completed=progress.tasks[hour_task].total)
                    elif data["phase"] == "storyline" and storyline_task is not None:
                        progress.update(
                            storyline_task, completed=progress.tasks[storyline_task].total
                        )

                elif event_type == "hour_progress":
                    if hour_task is None:
                        hour_task = progress.add_task(
                            "Processing hours...", total=data["total_hours"]
                        )
                    progress.update(
                        hour_task,
                        completed=data["hour"],
                        description=f"Hour {data['hour']}/{data['total_hours']}",
                    )

                elif event_type == "storyline_progress":
                    if storyline_task is None:
                        storyline_task = progress.add_task(
                            "Storyline events...", total=data["total_events"]
                        )
                    progress.update(
                        storyline_task,
                        completed=data["event_num"],
                        description=f"Event {data['event_num']}/{data['total_events']}: {data['actor']} on {data['system']}",
                    )

            # Generate logs with progress reporting
            engine = GenerationEngine(
                scenario=scenario,
                output_dir=gen_data_dir,
                progress_callback=progress_callback,
                ground_truth_dir=gen_gt_dir,
                artifact_dir=gen_artifacts_dir,
                scenario_root=scenario_dir,
                output_target=output_target,
                oob_hosts=oob_hosts,
                generation_seed=seed,
                allow_large_workload=allow_large_workload,
                resource_forecast=resource_forecast,
                compiled_scenario=compiled,
            )
            engine.generate()
            write_output_target_marker(gen_gt_dir, output_target)
            if not (gen_gt_dir / RESOLVED_SCENARIO_FILENAME).exists():
                write_resolved_scenario(compiled, gen_gt_dir)
            write_generation_manifest(
                compiled,
                gen_gt_dir,
                output_target=output_target.value,
                formats=[
                    str(log["format"])
                    for log in scenario.output.logs
                    if isinstance(log, dict) and "format" in log
                ],
                oob_hosts=oob_hosts,
                overrides={
                    "formats": formats,
                    "generation_seed": seed,
                },
            )

        # Transactional swap: backup old → install new → cleanup backup.
        # If any step fails (including KeyboardInterrupt), old output is
        # restored from backup. data/ and generated sidecars are always kept
        # as a matched set — partial preservation is never valid.
        if staging_dir:
            try:
                SIDECAR_REGISTRY.replace(staging_dir, ground_truth_dir)
            finally:
                shutil.rmtree(staging_dir, ignore_errors=True)

            console.print("[dim]Replaced previous output[/dim]")

        console.print("\n[bold green]✓ Generation complete![/bold green]")
        console.print("\nGenerated files:")
        console.print(f"  Scenario directory: {ground_truth_dir}")

        # List files in scenario root (GROUND_TRUTH.md + machine-readable sidecars)
        if ground_truth_dir.exists():
            for file in sorted(ground_truth_dir.iterdir()):
                if file.is_file() and file.name in {
                    "GROUND_TRUTH.md",
                    GROUND_TRUTH_JSON_FILENAME,
                    OBSERVATION_MANIFEST_FILENAME,
                    ARTIFACTS_MANIFEST_FILENAME,
                    COLLECTION_PROFILE_FILENAME,
                    "STORAGE_MANIFEST.json",
                    OUTPUT_TARGET_FILENAME,
                    RESOLVED_SCENARIO_FILENAME,
                    GENERATION_MANIFEST_FILENAME,
                }:
                    size = file.stat().st_size
                    size_str = f"{size:,} bytes" if size < 1024 else f"{size / 1024:.1f} KB"
                    console.print(f"  • {file.name} ({size_str})")

        # List generated log files in data/
        if data_dir.exists():
            console.print(f"  Data: {data_dir}")
            for file in sorted(data_dir.iterdir()):
                if file.is_file():
                    size = file.stat().st_size
                    size_str = f"{size:,} bytes" if size < 1024 else f"{size / 1024:.1f} KB"
                    console.print(f"    • {file.name} ({size_str})")

        if artifacts_dir.exists():
            console.print(f"  Artifacts: {artifacts_dir}")
            for file in sorted(artifacts_dir.rglob("*")):
                if file.is_file():
                    size = file.stat().st_size
                    size_str = f"{size:,} bytes" if size < 1024 else f"{size / 1024:.1f} KB"
                    console.print(f"    • {file.relative_to(artifacts_dir)} ({size_str})")

        # Success - exit normally
        return

    except KeyboardInterrupt:
        if staging_dir and staging_dir.exists():
            shutil.rmtree(staging_dir, ignore_errors=True)
            console.print("[dim]Cleaned up staging directory; previous output preserved[/dim]")
        console.print("\n[bold yellow]Interrupted by user (Ctrl+C)[/bold yellow]")
        logger.info("Generation interrupted by user")
        raise typer.Exit(EXIT_SIGINT)

    except Exception as e:
        if staging_dir and staging_dir.exists():
            shutil.rmtree(staging_dir, ignore_errors=True)
            console.print("[dim]Cleaned up staging directory; previous output preserved[/dim]")
        console.print(f"\n[bold red]Error:[/bold red] Generation failed: {e}", style="red")
        if verbose or debug:
            console.print_exception()
        logger.exception("Generation failed")
        raise typer.Exit(EXIT_GENERATION_ERROR)


@app.command("resolve")
def resolve_cmd(
    scenario_file: Path = typer.Argument(
        ...,
        help="Authored or authoritative scenario YAML.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help=("Resolved YAML output file. Optional only with --explain-composition --json."),
    ),
    json_output: bool = typer.Option(False, "--json", help="Emit stable JSON diagnostics."),
    explain_composition: bool = typer.Option(
        False,
        "--explain-composition",
        help="Report selected packs, precedence, and catalog field origins.",
    ),
    include_effective_scenario: bool = typer.Option(
        False,
        "--include-effective-scenario",
        help="Include the compiled effective scenario in JSON composition explanations.",
    ),
    project_root: Path | None = typer.Option(
        None,
        "--project-root",
        help="Override the current working directory for optional .eforge/config and .eforge/packs.",
    ),
    oob_host: list[str] = typer.Option(
        [],
        "--oob-host",
        help="Fresh literal OOB authorization, matching validate/generate semantics.",
    ),
) -> None:
    """Compile a scenario into a self-contained authoritative YAML document."""

    if not scenario_file.is_file() or not os.access(scenario_file, os.R_OK):
        message = f"scenario file not found or unreadable: {scenario_file}"
        if json_output:
            print(json.dumps({"valid": False, "error": message}, indent=2, sort_keys=True))
        else:
            console.print(f"[bold red]Error:[/bold red] {message}", style="red")
        raise typer.Exit(EXIT_INPUT_ERROR)

    if include_effective_scenario and not (explain_composition and json_output):
        message = "--include-effective-scenario requires --explain-composition --json"
        if json_output:
            print(json.dumps({"valid": False, "error": message}, indent=2, sort_keys=True))
        else:
            console.print(f"[bold red]Error:[/bold red] {message}", style="red")
        raise typer.Exit(EXIT_INPUT_ERROR)
    if output is None and not (explain_composition and json_output):
        message = "--output is required unless using --explain-composition --json"
        if json_output:
            print(json.dumps({"valid": False, "error": message}, indent=2, sort_keys=True))
        else:
            console.print(f"[bold red]Error:[/bold red] {message}", style="red")
        raise typer.Exit(EXIT_INPUT_ERROR)

    oob_hosts = _normalize_oob_hosts(oob_host, json_output=json_output)
    try:
        compiled = compile_scenario(scenario_file, project_root=project_root)
        validator, issues = _validate_compiled_scenario(
            compiled,
            oob_hosts,
            scenario_file.parent,
        )
        if validator.has_errors():
            messages = "; ".join(
                f"{issue.field_path}: {issue.message}"
                for issue in issues
                if issue.severity == "error"
            )
            raise SchemaValidationError(messages)
        if output is not None:
            content = serialize_resolved_document(build_resolved_document(compiled))
            if output.is_symlink():
                raise PermissionError(
                    f"refusing to write resolved scenario through symlink: {output}"
                )
            if output.exists():
                if output.read_bytes() != content:
                    raise FileExistsError(
                        f"resolved output already exists with different content: {output}"
                    )
            else:
                output.parent.mkdir(parents=True, exist_ok=True)
                temporary = output.with_name(f".{output.name}.tmp-{os.getpid()}")
                temporary.write_bytes(content)
                temporary.replace(output)
    except (EvidenceForgeError, OSError, ValidationError) as exc:
        if json_output:
            print(json.dumps({"valid": False, "error": str(exc)}, indent=2, sort_keys=True))
        else:
            console.print(f"[bold red]Error:[/bold red] {exc}", style="red")
        raise typer.Exit(EXIT_SCHEMA_VALIDATION) from exc

    payload = {
        "valid": True,
        "output": str(output) if output is not None else None,
        "written": output is not None,
        "compiled_sha256": compiled.digests.get("compiled_sha256"),
        "selected_packs": [pack.model_dump(mode="json") for pack in compiled.selected_packs],
    }
    if explain_composition:
        payload["composition"] = compiled.provenance
    if include_effective_scenario:
        payload["effective_scenario"] = compiled.scenario.model_dump(mode="json")
    if json_output:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        assert output is not None
        console.print(f"[green]✓[/green] Wrote authoritative scenario: {output}")
        if explain_composition:
            console.print_json(json.dumps(compiled.provenance, sort_keys=True))


@app.command()
def validate(
    scenario_file: Path = typer.Argument(
        ...,
        help="Path to scenario YAML file",
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    oob_host: list[str] = typer.Option(
        [],
        "--oob-host",
        help="Allowlist an operator-controlled out-of-band host (concrete registrable "
        "domain or IP literal) when validating a scenario whose adversarial_payload uses a "
        "literal `value:` pointing at that host — parity with `generate --oob-host`, so "
        "'validate before generate' stays reliable for live-callback scenarios. Validation "
        "only: no callback is ever made. Repeatable.",
    ),
    allow_large_workload: bool = typer.Option(
        False,
        "--allow-large-workload",
        hidden=True,
    ),
    show_storage: bool = typer.Option(
        False,
        "--show-storage",
        help=(
            "Show compiled Windows/Linux SMB volumes, share roots/scales/access, mappings, "
            "and bounded catalog samples."
        ),
    ),
    project_root: Path | None = typer.Option(
        None,
        "--project-root",
        help="Override the current working directory for optional .eforge/config and .eforge/packs.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit a stable machine-readable validation envelope.",
    ),
) -> None:
    """Validate a scenario file for schema correctness and cross-reference integrity.

    Checks YAML structure, Pydantic schema compliance, and internal consistency
    (user/system/persona references, network topology, etc.) without generating logs.

    Exit codes:
    - 0: Validation passed
    - 1: YAML parse error, file I/O error, or invalid --oob-host
    - 2: Schema validation or cross-reference error
    """
    from evidenceforge.composition.compiler import resolve_project_root

    fallback_project_root = (
        project_root.resolve() if project_root is not None else Path.cwd().resolve()
    )
    if not scenario_file.is_file():
        exc = FileNotFoundError(f"scenario file not found: {scenario_file}")
        if json_output:
            payload = _validation_json_payload(
                scenario_file=scenario_file,
                input_kind="missing",
                project_root=fallback_project_root,
                issues=_exception_issue_payloads(exc, scenario_file),
            )
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            console.print(f"[bold red]Error:[/bold red] {exc}", style="red")
        raise typer.Exit(EXIT_INPUT_ERROR)

    if not json_output:
        console.print("[bold blue]EvidenceForge Scenario Validator[/bold blue]")
        console.print(f"Scenario: {scenario_file}\n")

    try:
        oob_hosts = (
            _normalize_oob_host_values(oob_host) if json_output else _normalize_oob_hosts(oob_host)
        )
    except ValueError as exc:
        payload = _validation_json_payload(
            scenario_file=scenario_file,
            input_kind="unknown",
            project_root=fallback_project_root,
            issues=_exception_issue_payloads(exc, scenario_file),
        )
        print(json.dumps(payload, indent=2, sort_keys=True))
        raise typer.Exit(EXIT_INPUT_ERROR) from exc

    try:
        compiled = compile_scenario(scenario_file, project_root=project_root)
        scenario = compiled.scenario
    except (ScenarioIncludeError, PackError, SchemaValidationError, ValidationError) as exc:
        if json_output:
            diagnostic_kind = getattr(exc, "diagnostic_input_kind", "unknown")
            input_kind = diagnostic_kind if isinstance(diagnostic_kind, str) else "unknown"
            payload = _validation_json_payload(
                scenario_file=scenario_file,
                input_kind=input_kind,
                project_root=fallback_project_root,
                issues=_exception_issue_payloads(exc, scenario_file),
            )
            print(json.dumps(payload, indent=2, sort_keys=True))
        elif isinstance(exc, ScenarioIncludeError):
            console.print("[bold red]Scenario include validation failed:[/bold red]")
            console.print(f"  [red]✗ {exc}[/red]")
        else:
            console.print("[bold red]Scenario compilation failed:[/bold red]")
            console.print(f"  [red]✗ {exc}[/red]")
        raise typer.Exit(EXIT_SCHEMA_VALIDATION) from exc
    except (OSError, yaml.YAMLError, UnicodeError) as exc:
        if json_output:
            payload = _validation_json_payload(
                scenario_file=scenario_file,
                input_kind="unknown",
                project_root=fallback_project_root,
                issues=_exception_issue_payloads(exc, scenario_file),
            )
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            console.print(f"[bold red]Error:[/bold red] Failed to parse YAML: {exc}", style="red")
        raise typer.Exit(EXIT_INPUT_ERROR) from exc

    resolved_project_root = (
        None
        if compiled.authored_kind == "resolved"
        else resolve_project_root(scenario_file, project_root)
    )
    if not json_output:
        console.print(f"[green]✓[/green] Schema valid: {scenario.name}")
        console.print(f"  Users: {len(scenario.environment.users)}")
        console.print(f"  Systems: {len(scenario.environment.systems)}")
        if scenario.personas:
            console.print(f"  Personas: {len(scenario.personas)}")
        if scenario.storyline:
            console.print(f"  Storyline events: {len(scenario.storyline)}")
        if scenario.environment.network:
            segments = len(scenario.environment.network.segments)
            sensors = len(scenario.environment.network.sensors)
            console.print(f"  Network: {segments} segments, {sensors} sensors")
        console.print("\n[bold]Validating cross-references...[/bold]")

    validator, issues = _validate_compiled_scenario(
        compiled,
        oob_hosts,
        scenario_file.parent,
        allow_large_workload=allow_large_workload,
    )

    from evidenceforge.config.provider import effective_config_scope

    storage_has_errors = any(
        issue.severity == "error" and issue.field_path.startswith("environment.storage")
        for issue in issues
    )
    storage_world = None
    if show_storage and not storage_has_errors:
        from evidenceforge.generation.storage_world import StorageWorldModel

        with effective_config_scope(compiled.effective_config):
            storage_world = StorageWorldModel.compile(scenario)
        if not json_output:
            _print_compiled_storage(storage_world)

    with effective_config_scope(compiled.effective_config):
        if json_output:
            forecast, forecast_error = _build_resource_forecast_for_cli(
                scenario,
                scenario_root=scenario_file.parent,
                destination=scenario_file.parent,
            )
        else:
            forecast = _forecast_for_cli(
                scenario,
                scenario_root=scenario_file.parent,
                destination=scenario_file.parent,
            )
            forecast_error = None

    if json_output:
        issue_payloads = [
            _validation_issue_payload(issue, compiled, scenario_file) for issue in issues
        ]
        forecast_payload: dict[str, Any]
        if forecast is not None:
            forecast_payload = {"available": True, **forecast.model_dump(mode="json")}
        else:
            forecast_payload = {"available": False, "error": forecast_error}
        storage_payload: dict[str, Any] | None = None
        if show_storage:
            if storage_world is None:
                storage_payload = {
                    "available": False,
                    "error": "unavailable until storage validation errors are resolved",
                }
            else:
                storage_payload = {
                    "available": True,
                    **storage_world.manifest(sample_size=_STORAGE_SAMPLE_SIZE),
                }
        payload = _validation_json_payload(
            scenario_file=scenario_file,
            input_kind=compiled.authored_kind,
            project_root=resolved_project_root,
            issues=issue_payloads,
            scenario=_scenario_summary(scenario),
            selected_packs=[pack.model_dump(mode="json") for pack in compiled.selected_packs],
            resource_forecast=forecast_payload,
            storage=storage_payload,
        )
        print(json.dumps(payload, indent=2, sort_keys=True))
        if validator.has_errors():
            raise typer.Exit(EXIT_SCHEMA_VALIDATION)
        return

    if issues:
        counts = {
            severity: sum(issue.severity == severity for issue in issues)
            for severity in ("error", "warning", "info")
        }
        headline_color = "red" if counts["error"] else "yellow" if counts["warning"] else "cyan"
        console.print(
            f"\n[{headline_color}]Found {len(issues)} validation issue(s):[/{headline_color}]"
        )
        for issue in issues:
            if issue.severity == "error":
                color, icon = "red", "✗"
            elif issue.severity == "warning":
                color, icon = "yellow", "!"
            else:
                color, icon = "cyan", "ℹ"
            console.print(f"  [{color}]{icon} {issue.field_path}[/{color}]")
            console.print(Text(f"    {issue.message}", style=color))
            if issue.suggestion:
                console.print(Text(f"    💡 {issue.suggestion}", style="dim"))

        if validator.has_errors():
            console.print("\n[bold red]Validation failed with errors.[/bold red]")
            raise typer.Exit(EXIT_SCHEMA_VALIDATION)
        if counts["warning"]:
            console.print("\n[yellow]Warnings found but scenario is valid.[/yellow]")
        else:
            console.print("\n[cyan]Informational findings only; scenario is valid.[/cyan]")
    else:
        console.print("[green]✓[/green] All cross-references valid")

    console.print("\n[bold green]✓ Scenario is valid.[/bold green]")


@app.command("eval")
def eval_cmd(
    output_dir: Path = typer.Argument(
        ...,
        help="Directory containing generated log files",
    ),
    scenario_file: Path | None = typer.Option(
        None,
        "--scenario",
        "-s",
        help="Optional authored scenario for comparison; required for legacy bundles.",
    ),
    output_format: str = typer.Option(
        "text",
        "--format",
        "-f",
        help="Report format: text or json",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show detailed sub-scores and sample failures",
    ),
    real_parsers: bool = typer.Option(
        False,
        "--real-parsers",
        help="[Reserved] Evaluate using real downstream parser binaries (not yet implemented).",
        is_flag=True,
    ),
    allow_large_evaluation: bool = typer.Option(
        False,
        "--allow-large-evaluation",
        help="Trusted override for evaluator corpus byte/file/record-count limits.",
    ),
    allow_scenario_mismatch: bool = typer.Option(
        False,
        "--allow-scenario-mismatch",
        help="Evaluate the authoritative bundle despite an authored-scenario digest mismatch.",
    ),
) -> None:
    """Evaluate a generated dataset for quality across four pillars.

    Reads generated log files and the original scenario, runs deterministic
    and statistical quality checks, and produces a quality report.

    Exit codes:
    - 0: Evaluation completed (check report for pass/fail)
    - 1: Input error (file not found, invalid path)
    - 2: Schema validation error in scenario
    - 22: Evaluation engine error
    """
    if output_format not in {"text", "json"}:
        console.print(
            f"[bold red]Error:[/bold red] Unsupported report format {output_format!r}; "
            "choose 'text' or 'json'.",
            style="red",
        )
        raise typer.Exit(EXIT_INPUT_ERROR)
    if not output_dir.is_dir() or not os.access(output_dir, os.R_OK):
        message = f"output directory not found or unreadable: {output_dir}"
        if output_format == "json":
            print(json.dumps({"valid": False, "error": message}, indent=2, sort_keys=True))
        else:
            console.print(f"[bold red]Error:[/bold red] {message}", style="red")
        raise typer.Exit(EXIT_INPUT_ERROR)
    if scenario_file is not None and (
        not scenario_file.is_file() or not os.access(scenario_file, os.R_OK)
    ):
        message = f"scenario file not found or unreadable: {scenario_file}"
        if output_format == "json":
            print(json.dumps({"valid": False, "error": message}, indent=2, sort_keys=True))
        else:
            console.print(f"[bold red]Error:[/bold red] {message}", style="red")
        raise typer.Exit(EXIT_INPUT_ERROR)

    if real_parsers:
        console.print("[yellow]--real-parsers: real parser backend not yet implemented.[/yellow]")
        return

    setup_logging(verbose)

    # Use stderr for status messages in JSON mode to keep stdout clean
    status_console = Console(stderr=True) if output_format == "json" else console

    status_console.print("[bold blue]EvidenceForge Data Quality Evaluation[/bold blue]")
    status_console.print(f"Output directory: {output_dir}")
    if scenario_file is not None:
        status_console.print(f"Scenario comparison: {scenario_file}")

    evaluation_output_dir = output_dir
    try:
        if (output_dir / GENERATION_MANIFEST_FILENAME).is_file():
            bundle_root = output_dir
        elif (
            output_dir.name == "data"
            and (output_dir.parent / GENERATION_MANIFEST_FILENAME).is_file()
        ):
            bundle_root = output_dir.parent
        else:
            bundle_root = None

        if bundle_root is not None:
            manifest = verify_generation_bundle(bundle_root)
            bundle_compiled = compile_scenario(bundle_root / RESOLVED_SCENARIO_FILENAME)
            if manifest.get("compiled_sha256") != bundle_compiled.digests.get("compiled_sha256"):
                raise SchemaValidationError(
                    "generation manifest compiled digest does not match resolved scenario"
                )
            scenario = bundle_compiled.scenario
            effective_config = bundle_compiled.effective_config
            if output_dir == bundle_root and (bundle_root / "data").is_dir():
                evaluation_output_dir = bundle_root / "data"
            status_console.print(f"[green]✓[/green] Verified authoritative bundle: {scenario.name}")
            if scenario_file is not None:
                candidate = compile_scenario(
                    scenario_file,
                    generation_seed=int(manifest["generation_seed"]),
                )
                candidate_scenario = candidate.scenario.model_copy(deep=True)
                candidate_scenario.output.logs = [
                    {"format": value} for value in manifest.get("formats", [])
                ]
                candidate = with_runtime_scenario(candidate, candidate_scenario)
                if candidate.digests.get("compiled_sha256") != manifest.get("compiled_sha256"):
                    if not allow_scenario_mismatch:
                        raise SchemaValidationError(
                            "authored scenario does not match the authoritative generation bundle; "
                            "use --allow-scenario-mismatch to evaluate the bundle anyway"
                        )
                    status_console.print(
                        "[yellow]Authored scenario mismatch accepted; evaluation uses the "
                        "bundle's resolved scenario.[/yellow]"
                    )
        else:
            if scenario_file is None:
                raise FileNotFoundError(
                    "legacy bundle has no authoritative artifacts; pass --scenario"
                )
            legacy_compiled = compile_scenario(scenario_file)
            scenario = legacy_compiled.scenario
            effective_config = legacy_compiled.effective_config
            status_console.print(f"[green]✓[/green] Loaded legacy scenario: {scenario.name}")
    except ScenarioIncludeError as e:
        status_console.print(
            "[bold red]Error:[/bold red] Scenario include validation failed",
            style="red",
        )
        status_console.print(f"  • {e}", style="red")
        raise typer.Exit(EXIT_SCHEMA_VALIDATION)
    except ValidationError as e:
        status_console.print(
            "[bold red]Error:[/bold red] Scenario schema validation failed",
            style="red",
        )
        for error in e.errors():
            field = " -> ".join(str(loc) for loc in error["loc"])
            status_console.print(f"  • {field}: {error['msg']}", style="red")
        raise typer.Exit(EXIT_SCHEMA_VALIDATION)
    except EvidenceForgeError as e:
        status_console.print(f"[bold red]Error:[/bold red] {e}", style="red")
        raise typer.Exit(EXIT_SCHEMA_VALIDATION)
    except (OSError, UnicodeError, yaml.YAMLError, ValueError) as e:
        status_console.print(
            f"[bold red]Error:[/bold red] Failed to load scenario: {e}",
            style="red",
        )
        raise typer.Exit(EXIT_INPUT_ERROR)

    # Run evaluation
    try:
        from evidenceforge.evaluation.engine import EvaluationEngine
        from evidenceforge.evaluation.report import format_json_report, format_text_report

        status_console.print()

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=status_console,
            transient=False,
        ) as progress:
            overall_task = progress.add_task("Evaluating...", total=None)
            detail_task: int | None = None

            def eval_progress(event_type: str, data: dict) -> None:
                nonlocal detail_task

                if event_type == "phase_start" and data["phase"] == "parsing":
                    progress.update(overall_task, description="Parsing log files...")

                elif event_type == "parsing_format":
                    fmt = data["format"]
                    step, total = data["step"], data["total"]
                    if detail_task is None:
                        detail_task = progress.add_task(f"Parsing {fmt}", total=total)
                    progress.update(
                        detail_task,
                        completed=step,
                        description=f"Parsing {fmt} ({step}/{total})",
                    )

                elif event_type == "phase_done" and data["phase"] == "parsing":
                    if detail_task is not None:
                        progress.update(
                            detail_task,
                            completed=progress.tasks[detail_task].total,
                            description=f"Parsed {data['total_records']:,} records from {data['sources']} sources",
                        )
                        detail_task = None

                elif event_type == "phase_start" and data["phase"] == "scoring":
                    progress.update(
                        overall_task,
                        total=data["total_dimensions"],
                        completed=0,
                        description="Scoring dimensions...",
                    )

                elif event_type == "dimension_start":
                    name = data["name"]
                    progress.update(
                        overall_task,
                        description=f"Dim {data['number']}: {name}",
                    )

                elif event_type == "sub_score_start":
                    name = data["name"]
                    step, total = data["step"], data["total"]
                    if detail_task is None:
                        detail_task = progress.add_task(name, total=total)
                    else:
                        progress.update(detail_task, total=total)
                    progress.update(
                        detail_task,
                        completed=step - 1,
                        description=f"{name}",
                    )

                elif event_type == "sub_score_done":
                    score_val = data.get("score")
                    name = data["name"]
                    if detail_task is not None:
                        score_str = f"{score_val:.0f}/100" if score_val is not None else "N/A"
                        progress.update(
                            detail_task,
                            advance=1,
                            description=f"{name}: {score_str}",
                        )

                elif event_type == "dimension_done":
                    progress.update(overall_task, advance=1)
                    if detail_task is not None:
                        progress.remove_task(detail_task)
                        detail_task = None

            engine = EvaluationEngine(
                output_dir=evaluation_output_dir,
                scenario=scenario,
                verbose=verbose,
                progress_callback=eval_progress,
                allow_large_evaluation=allow_large_evaluation,
                effective_config=effective_config,
            )
            report = engine.run()

        # Output report
        if output_format == "json":
            print(format_json_report(report))
        else:
            format_text_report(report, console, verbose=verbose)

    except KeyboardInterrupt:
        status_console.print("\n[bold yellow]Interrupted by user (Ctrl+C)[/bold yellow]")
        raise typer.Exit(EXIT_SIGINT)
    except Exception as e:
        status_console.print(
            f"\n[bold red]Error:[/bold red] Evaluation failed: {e}",
            style="red",
        )
        if verbose:
            status_console.print_exception()
        raise typer.Exit(EXIT_EVAL_ERROR)


@app.command("install-skills")
def install_skills_cmd(
    agent: str = typer.Option(
        "all",
        "--agent",
        help="Agent to install skills for: all, claude, chatgpt, or codex (alias)",
    ),
    global_install: bool = typer.Option(
        False,
        "--global",
        help="Install to each selected agent user directory",
    ),
) -> None:
    """Install EvidenceForge skills for supported agent workflows.

    By default, installs skills for Claude Code and ChatGPT in the current
    project. Use --global to install to each selected agent user directory.
    The codex agent name remains available as an alias for chatgpt.

    Existing installations are updated: new files are copied, changed files
    are overwritten, and stale files from previous versions are removed.
    """
    from evidenceforge.cli.install_skills import (
        find_evidenceforge_chatgpt_skills,
        install_chatgpt_skills,
        install_skills,
    )

    requested_agent = agent.lower()
    valid_agents = {"all", "claude", "chatgpt", "codex"}
    if requested_agent not in valid_agents:
        console.print(
            f"[bold red]Error:[/bold red] Unknown agent {agent!r}. "
            "Use all, claude, chatgpt, or codex.",
            style="red",
        )
        raise typer.Exit(EXIT_INPUT_ERROR)

    if requested_agent == "all":
        selected_agents = ("claude", "chatgpt")
    elif requested_agent == "codex":
        selected_agents = ("chatgpt",)
    else:
        selected_agents = (requested_agent,)

    scope = "global" if global_install else "project"
    failures: list[tuple[str, str]] = []
    successful_agents: set[str] = set()

    for index, normalized_agent in enumerate(selected_agents):
        if index:
            console.print()

        if normalized_agent == "claude":
            target_dir = (
                Path.home() / ".claude" / "commands"
                if global_install
                else Path.cwd() / ".claude" / "commands"
            )
        else:
            target_dir = (
                Path.home() / ".agents" / "skills"
                if global_install
                else Path.cwd() / ".agents" / "skills"
            )

        console.print(
            f"[bold blue]Installing EvidenceForge skills for "
            f"{normalized_agent} ({scope})[/bold blue]"
        )
        console.print(f"Target: {target_dir}\n")

        try:
            if normalized_agent == "claude":
                installed, removed = install_skills(target_dir)
            else:
                installed, removed = install_chatgpt_skills(target_dir)
        except (FileNotFoundError, PermissionError) as error:
            console.print(f"[bold red]Error:[/bold red] {error}", style="red")
            failures.append((normalized_agent, str(error)))
            continue

        successful_agents.add(normalized_agent)
        if installed:
            console.print(f"[green]✓[/green] Installed {len(installed)} files:")
            for installed_file in installed:
                if normalized_agent == "claude":
                    console.print(f"  eforge/{installed_file}")
                else:
                    console.print(f"  {installed_file}")

        if removed:
            console.print(f"\n[yellow]Removed {len(removed)} stale files:[/yellow]")
            for removed_file in removed:
                if normalized_agent == "claude":
                    console.print(f"  eforge/{removed_file}", style="dim")
                else:
                    console.print(f"  {removed_file}", style="dim")

        if normalized_agent == "claude":
            installed_dir = target_dir / "eforge"
            console.print(f"\n[bold green]✓ Skills installed to {installed_dir}[/bold green]")
            console.print(
                "Use /eforge scenario, /eforge generate, /eforge validate, "
                "/eforge evaluate, or /eforge config."
            )
            console.print(
                "Manage packs with /eforge pack; author them with /eforge industry-pack "
                "or /eforge organization-pack."
            )
        else:
            console.print(f"\n[bold green]✓ Skills installed to {target_dir}[/bold green]")
            console.print(
                "Use the eforge-scenario, eforge-generate, eforge-validate, "
                "eforge-evaluate, or eforge-config skills."
            )
            console.print(
                "Manage packs with eforge-pack; author them with eforge-industry-pack "
                "or eforge-organization-pack."
            )

    if global_install and "chatgpt" in successful_agents:
        legacy_dir = Path.home() / ".codex" / "skills"
        legacy_skills = find_evidenceforge_chatgpt_skills(legacy_dir)
        if legacy_skills:
            console.print(
                "\n[bold yellow]Warning:[/bold yellow] Legacy EvidenceForge skills "
                f"also exist under {legacy_dir} and may appear as duplicates:"
            )
            for legacy_skill in legacy_skills:
                console.print(f"  {legacy_skill}", style="dim")
            console.print(
                "These legacy files were not modified. Remove them manually after "
                "confirming the new installation works."
            )

    if failures:
        console.print("\n[bold red]Skill installation completed with errors:[/bold red]")
        for failed_agent, message in failures:
            console.print(f"  {failed_agent}: {message}", style="red")
        raise typer.Exit(EXIT_INPUT_ERROR)


@app.command()
def info(
    field: str | None = typer.Argument(
        None, help="Dot-path to a specific field (e.g., paths.activity, overlay.exists, personas)"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON for machine parsing"),
    list_fields_flag: bool = typer.Option(
        False, "--fields", help="List all valid dot-path field names"
    ),
    project_root: Path | None = typer.Option(
        None,
        "--project-root",
        help="Override the current working directory for optional .eforge/config and .eforge/packs.",
    ),
) -> None:
    """Show EvidenceForge installation info: version, config paths, available data.

    Displays version, install type, config file paths, and inventories of
    available personas, formats, DNS tags, application IDs, and system roles.
    Use --json for machine-readable output (used by Claude Code skills).

    Optionally pass a dot-path field to get just that value:

        eforge info paths.activity

        eforge info overlay.exists

        eforge info personas
    """
    from evidenceforge.cli.info import (
        format_human_readable,
        format_ids_signature_inventory,
        format_json,
        gather_info,
        list_fields,
        resolve_field,
    )

    if project_root is not None and not project_root.is_dir():
        message = f"project root is not a directory: {project_root}"
        if json_output:
            print(json.dumps({"valid": False, "error": message}, indent=2, sort_keys=True))
        else:
            console.print(f"[bold red]Error:[/bold red] {message}", style="red")
        raise typer.Exit(EXIT_INPUT_ERROR)

    try:
        data = gather_info(field=field, project_root=project_root)
    except (EvidenceForgeError, OSError, UnicodeError, yaml.YAMLError, ValueError) as e:
        if json_output:
            print(
                json.dumps(
                    {"valid": False, "error": f"Failed to gather info: {e}"},
                    indent=2,
                    sort_keys=True,
                )
            )
        else:
            console.print(f"[bold red]Error:[/bold red] Failed to gather info: {e}", style="red")
        raise typer.Exit(EXIT_INPUT_ERROR) from e

    if list_fields_flag and field:
        message = (
            "Cannot use --fields with a field argument. Use 'eforge info --fields' "
            "to list fields, or 'eforge info <field>' to get a value."
        )
        if json_output:
            print(json.dumps({"valid": False, "error": message}, indent=2, sort_keys=True))
        else:
            console.print(f"[bold red]Error:[/bold red] {message}", style="red")
        raise typer.Exit(EXIT_INPUT_ERROR)

    if list_fields_flag:
        fields = list_fields(data)
        if json_output:
            print(json.dumps({name: desc for name, desc in fields}, indent=2, sort_keys=True))
        else:
            max_name = max(len(name) for name, _ in fields)
            for name, desc in fields:
                if desc:
                    print(f"{name:<{max_name}}  {desc}")
                else:
                    print(name)
    elif field:
        value = resolve_field(data, field)
        if value is None:
            if json_output:
                print(
                    json.dumps(
                        {"valid": False, "error": f"Unknown field: {field}"},
                        indent=2,
                        sort_keys=True,
                    )
                )
            else:
                console.print(f"[bold red]Error:[/bold red] Unknown field: {field}", style="red")
            raise typer.Exit(EXIT_INPUT_ERROR)
        if json_output:
            print(json.dumps(value, indent=2, sort_keys=True))
        elif field == "ids_signatures":
            print(format_ids_signature_inventory(value))
        elif isinstance(value, list):
            print("\n".join(str(v) for v in value))
        elif isinstance(value, dict):
            print(json.dumps(value))
        else:
            print(value)
    elif json_output:
        # JSON goes to stdout without Rich formatting
        print(format_json(data))
    else:
        console.print(format_human_readable(data))


@app.command("schema")
def scenario_schema(
    selector: str = typer.Argument(
        ...,
        help=(
            "Focused authored-schema selector, such as environment.network_identities "
            "or event.email_read."
        ),
    ),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON for machine parsing"),
) -> None:
    """Show one focused installed-version scenario authoring contract."""

    from evidenceforge.cli.schema import (
        resolve_schema_contract,
        schema_contract_payload,
        schema_selectors,
    )

    contract = resolve_schema_contract(selector)
    if contract is None:
        message = f"Unknown schema selector: {selector}. Known selectors: " + ", ".join(
            schema_selectors()
        )
        if json_output:
            print(json.dumps({"valid": False, "error": message}, indent=2, sort_keys=True))
        else:
            console.print(f"[bold red]Error:[/bold red] {message}", style="red")
        raise typer.Exit(EXIT_INPUT_ERROR)

    payload = schema_contract_payload(contract)
    if json_output:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return

    console.print(f"[bold blue]EvidenceForge Scenario Schema[/bold blue]: {contract.selector}")
    console.print_json(data=payload)


@app.command("validate-config")
def validate_config_cmd(
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
    project_root: Path | None = typer.Option(
        None,
        "--project-root",
        help="Override the current working directory for optional .eforge/config.",
    ),
) -> None:
    """Validate config files for integrity and cross-reference consistency.

    Runs integrity checks across config YAML files (activity, personas, formats,
    evaluation) including project overlay customizations. Reports errors,
    warnings, and info items.

    Exit codes:
    - 0: All checks passed (may include warnings/info)
    - 2: Errors found
    """
    from evidenceforge.cli.validate_config import validate_config
    from evidenceforge.composition.compiler import (
        build_management_effective_config,
        resolve_management_project_root,
    )
    from evidenceforge.config.overlay import overlay_project_root_scope
    from evidenceforge.config.provider import effective_config_scope

    status_console = Console(stderr=True) if json_output else console
    status_console.print("[bold blue]EvidenceForge Config Validator[/bold blue]")

    if project_root is not None and not project_root.is_dir():
        message = f"project root is not a directory: {project_root}"
        if json_output:
            print(json.dumps({"valid": False, "error": message}, indent=2, sort_keys=True))
        else:
            status_console.print(f"[bold red]Error:[/bold red] {message}", style="red")
        raise typer.Exit(EXIT_INPUT_ERROR)
    resolved_project_root = resolve_management_project_root(project_root)

    try:
        with overlay_project_root_scope(resolved_project_root):
            result = validate_config(
                merged_scope_factory=lambda: effective_config_scope(
                    build_management_effective_config(resolved_project_root),
                    refresh_legacy_globals=False,
                )
            )
    except (EvidenceForgeError, OSError, UnicodeError, yaml.YAMLError, ValueError) as e:
        if json_output:
            print(
                json.dumps(
                    {
                        "valid": False,
                        "status": "error",
                        "project_root": str(resolved_project_root),
                        "error": f"Validation failed: {e}",
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
        else:
            status_console.print(f"[bold red]Error:[/bold red] Validation failed: {e}", style="red")
        raise typer.Exit(EXIT_INPUT_ERROR) from e

    if json_output:
        severity_counts = {
            "error": len(result.errors),
            "warning": len(result.warnings),
            "info": len(result.infos),
        }
        output = {
            "schema_version": "1.0",
            "valid": not result.errors,
            "status": "invalid"
            if result.errors
            else "valid_with_warnings"
            if result.warnings
            else "valid",
            "project_root": str(resolved_project_root),
            "files_checked": result.files_checked,
            "severity_counts": severity_counts,
            "issues": [
                {
                    "severity": issue.severity.lower(),
                    "file": issue.file,
                    "message": issue.message,
                }
                for issue in result.issues
            ],
            "errors": [{"file": i.file, "message": i.message} for i in result.errors],
            "warnings": [{"file": i.file, "message": i.message} for i in result.warnings],
            "info": [{"file": i.file, "message": i.message} for i in result.infos],
        }
        # JSON mode: only JSON on stdout, exit non-zero on errors
        print(json.dumps(output, indent=2, sort_keys=True))
        if result.errors:
            raise typer.Exit(EXIT_SCHEMA_VALIDATION)
    else:
        if result.errors:
            status_console.print("\n[bold red]ERRORS (must fix):[/bold red]")
            for issue in result.errors:
                status_console.print(f"  [red]{issue.file}:[/red] {issue.message}")

        if result.warnings:
            status_console.print(
                "\n[bold yellow]WARNINGS (may degrade output quality):[/bold yellow]"
            )
            for issue in result.warnings:
                status_console.print(f"  [yellow]{issue.file}:[/yellow] {issue.message}")

        if result.infos:
            status_console.print("\n[bold cyan]INFO (suggestions):[/bold cyan]")
            for issue in result.infos:
                status_console.print(f"  [cyan]{issue.file}:[/cyan] {issue.message}")

        total_e = len(result.errors)
        total_w = len(result.warnings)
        total_i = len(result.infos)
        status_console.print(
            f"\n{total_e} errors, {total_w} warnings, {total_i} info items across {result.files_checked} files checked."
        )

        if result.errors:
            raise typer.Exit(EXIT_SCHEMA_VALIDATION)

        if not result.issues:
            status_console.print(
                f"\n[bold green]All config files validated successfully. No issues found across {result.files_checked} files.[/bold green]"
            )


@app.command()
def version() -> None:
    """Show version information."""
    console.print(f"EvidenceForge v{__version__}")
    console.print("Synthetic security log generator for threat hunting training")


def main() -> None:
    """Main CLI entry point."""
    try:
        app()
    except Exception as e:
        console.print(f"[bold red]Fatal error:[/bold red] {e}", style="red")
        sys.exit(EXIT_GENERATION_ERROR)


if __name__ == "__main__":
    main()
